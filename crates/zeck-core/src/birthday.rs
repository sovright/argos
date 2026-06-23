use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};
use tonic::transport::Channel;
use uuid::Uuid;
use zcash_client_backend::{
    data_api::AccountBirthday,
    proto::service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, Empty, GetAddressUtxosArg,
    },
};

use crate::{
    derivation::{derive_accounts, legacy_transparent_account_key, mnemonic_seed},
    error::{ZeckError, ZeckResult},
    lightwalletd::{
        probe_lightwalletd_endpoints, validate_lightwalletd_network,
        validated_lightwalletd_endpoints,
    },
    models::{BirthdayDetectResult, RuntimeScanConfig, ZeckNetwork},
    scan::{import_probe_account, run_wallet_sync},
    workspace::{consensus_network, RecoveryWorkspace},
};

const SAPLING_ACTIVATION_HEIGHT: u32 = 419_200;
const SAPLING_ACTIVATION_DATE: CalendarDate = CalendarDate {
    year: 2018,
    month: 10,
    day: 28,
};
/// Pre-Blossom block target was 150 s.  Used by the offline fallback only.
const PRE_BLOSSOM_BLOCK_SECONDS: i64 = 150;
/// Post-Blossom (and current) block target is 75 s.
const POST_BLOSSOM_BLOCK_SECONDS: i64 = 75;
/// Mainnet Blossom activation: block 653,600 ≈ 2019-12-11.
const BLOSSOM_ACTIVATION_HEIGHT: u32 = 653_600;
const BLOSSOM_ACTIVATION_DATE: CalendarDate = CalendarDate {
    year: 2019,
    month: 12,
    day: 11,
};
const DAY_SECONDS: i64 = 86_400;
/// Safety margin (~1 week at 75 s/block) subtracted from any date-derived
/// birthday so we err on the side of over-scanning rather than missing notes.
const DATE_SAFETY_BUFFER_BLOCKS: u32 = 8_064;

/// Approximate blocks per year at 75 s/block.
const PROBE_YEAR_STEP: u32 = 420_480;
/// Wall-clock limit per shielded probe window (seconds).
const PROBE_TIMEOUT_SECS: u64 = 45;
/// Safety margin subtracted from the detected transparent activity height.
const BIRTHDAY_BUFFER_BLOCKS: u32 = 10_000;
/// Number of accounts (and their transparent addresses) to check for transparent activity.
const PROBE_ACCOUNT_COUNT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CalendarDate {
    year: i32,
    month: u8,
    day: u8,
}

/// Offline piecewise estimator: 150 s/block from Sapling activation through
/// Blossom (block 653,600), then 75 s/block thereafter.  Used as the fallback
/// when lightwalletd is unreachable, and as the round-trip helper below.
pub fn estimate_birthday_from_date_offline(date: &str) -> ZeckResult<u32> {
    let parsed = CalendarDate::parse(date)?;
    if parsed <= SAPLING_ACTIVATION_DATE {
        return Ok(SAPLING_ACTIVATION_HEIGHT);
    }

    if parsed <= BLOSSOM_ACTIVATION_DATE {
        let seconds = parsed
            .days_since_unix_epoch()
            .saturating_sub(SAPLING_ACTIVATION_DATE.days_since_unix_epoch())
            .saturating_mul(DAY_SECONDS);
        let blocks = (seconds / PRE_BLOSSOM_BLOCK_SECONDS).max(0) as u32;
        return Ok(SAPLING_ACTIVATION_HEIGHT.saturating_add(blocks));
    }

    let seconds = parsed
        .days_since_unix_epoch()
        .saturating_sub(BLOSSOM_ACTIVATION_DATE.days_since_unix_epoch())
        .saturating_mul(DAY_SECONDS);
    let blocks = (seconds / POST_BLOSSOM_BLOCK_SECONDS).max(0) as u32;
    Ok(BLOSSOM_ACTIVATION_HEIGHT.saturating_add(blocks))
}

/// Estimate a wallet birthday from a date by binary-searching lightwalletd for
/// the first block whose timestamp meets-or-exceeds the target.  Falls back to
/// the offline piecewise heuristic if any RPC fails.
///
/// A safety margin of ~1 week (`DATE_SAFETY_BUFFER_BLOCKS`) is subtracted so
/// we err toward over-scanning rather than missing notes.
pub async fn estimate_birthday_from_date(
    date: &str,
    lightwalletd_url: &str,
) -> ZeckResult<u32> {
    let parsed = CalendarDate::parse(date)?;
    if parsed <= SAPLING_ACTIVATION_DATE {
        return Ok(SAPLING_ACTIVATION_HEIGHT);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let target_unix = parsed
        .days_since_unix_epoch()
        .saturating_mul(DAY_SECONDS);

    let probed = match probe_lightwalletd_endpoints(lightwalletd_url).await {
        Ok(probe) => probe,
        Err(_) => return estimate_birthday_from_date_offline(date),
    };
    let (mut client, _endpoint, chain_info) = probed;

    let chain_tip = match u32::try_from(chain_info.block_height) {
        Ok(h) => h,
        Err(_) => return estimate_birthday_from_date_offline(date),
    };
    let sapling_floor = u32::try_from(chain_info.sapling_activation_height)
        .unwrap_or(SAPLING_ACTIVATION_HEIGHT);

    let tip_time = match fetch_block_time(&mut client, chain_tip).await {
        Ok(t) => t,
        Err(_) => return estimate_birthday_from_date_offline(date),
    };
    if target_unix >= tip_time {
        return Ok(chain_tip
            .saturating_sub(DATE_SAFETY_BUFFER_BLOCKS)
            .max(sapling_floor));
    }

    let mut lo = sapling_floor;
    let mut hi = chain_tip;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mid_time = match fetch_block_time(&mut client, mid).await {
            Ok(t) => t,
            Err(_) => return estimate_birthday_from_date_offline(date),
        };
        if mid_time < target_unix {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    Ok(lo.saturating_sub(DATE_SAFETY_BUFFER_BLOCKS).max(sapling_floor))
}

/// Inverse of the offline estimator: given a block height, return the
/// approximate calendar date as `YYYY-MM-DD`.
pub fn estimate_date_from_height_offline(height: u32) -> String {
    let (anchor_date, anchor_height, block_seconds) = if height <= BLOSSOM_ACTIVATION_HEIGHT {
        (
            SAPLING_ACTIVATION_DATE,
            SAPLING_ACTIVATION_HEIGHT,
            PRE_BLOSSOM_BLOCK_SECONDS,
        )
    } else {
        (
            BLOSSOM_ACTIVATION_DATE,
            BLOSSOM_ACTIVATION_HEIGHT,
            POST_BLOSSOM_BLOCK_SECONDS,
        )
    };

    let delta_blocks = i64::from(height.saturating_sub(anchor_height));
    let delta_days = (delta_blocks * block_seconds) / DAY_SECONDS;
    let absolute_days = anchor_date
        .days_since_unix_epoch()
        .saturating_add(delta_days);
    CalendarDate::from_days_since_unix_epoch(absolute_days).format()
}

/// Caution appended to an auto-detected birthday that was derived from
/// server-reported history (transparent UTXOs or shielded-window probes).
///
/// Auto-detection trusts the lightwalletd server: a hostile server can withhold
/// early history, pushing the detected birthday later than the wallet's true
/// age, so every note received before that point falls outside the scan and the
/// user is shown an empty (or incomplete) result. Making the detected birthday
/// — with its approximate calendar date on mainnet — and this caution explicit
/// lets a late detection be noticed and corrected rather than failing silently
/// (audit Issue C). The date is omitted on testnet, where the mainnet-calibrated
/// offline estimator does not apply.
fn late_birthday_caution(birthday: u32, network: ZeckNetwork) -> String {
    let date_hint = match network {
        ZeckNetwork::Mainnet => {
            format!(" (around {})", estimate_date_from_height_offline(birthday))
        }
        ZeckNetwork::Testnet => String::new(),
    };
    format!(
        "Argos will scan only from block {birthday}{date_hint} forward, so any notes \
         received before it will not be found. If this wallet is older than that — for \
         example if the lightwalletd server returned incomplete early history — set an \
         earlier birthday and rescan."
    )
}

async fn fetch_block_time(
    client: &mut CompactTxStreamerClient<Channel>,
    height: u32,
) -> ZeckResult<i64> {
    let block = client
        .get_block(BlockId {
            height: u64::from(height),
            hash: vec![],
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    Ok(i64::from(block.time))
}

impl CalendarDate {
    fn parse(input: &str) -> ZeckResult<Self> {
        let mut parts = input.split('-');
        let year = parts
            .next()
            .ok_or_else(|| ZeckError::InvalidDate("expected YYYY-MM-DD".to_owned()))?
            .parse::<i32>()
            .map_err(|_| ZeckError::InvalidDate("invalid year".to_owned()))?;
        let month = parts
            .next()
            .ok_or_else(|| ZeckError::InvalidDate("expected YYYY-MM-DD".to_owned()))?
            .parse::<u8>()
            .map_err(|_| ZeckError::InvalidDate("invalid month".to_owned()))?;
        let day = parts
            .next()
            .ok_or_else(|| ZeckError::InvalidDate("expected YYYY-MM-DD".to_owned()))?
            .parse::<u8>()
            .map_err(|_| ZeckError::InvalidDate("invalid day".to_owned()))?;
        if parts.next().is_some() {
            return Err(ZeckError::InvalidDate("expected YYYY-MM-DD".to_owned()));
        }
        let date = Self { year, month, day };
        date.validate()?;
        Ok(date)
    }

    fn validate(self) -> ZeckResult<()> {
        if !(1..=12).contains(&self.month) {
            return Err(ZeckError::InvalidDate(
                "month must be 1 through 12".to_owned(),
            ));
        }
        let max_day = days_in_month(self.year, self.month);
        if self.day == 0 || self.day > max_day {
            return Err(ZeckError::InvalidDate(format!(
                "day must be 1 through {max_day}"
            )));
        }
        Ok(())
    }

    fn days_since_unix_epoch(self) -> i64 {
        let year = i64::from(self.year) - if self.month <= 2 { 1 } else { 0 };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let month = i64::from(self.month);
        let day = i64::from(self.day);
        let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

        era * 146_097 + day_of_era - 719_468
    }

    /// Inverse of [`days_since_unix_epoch`] using Howard Hinnant's
    /// civil_from_days algorithm.
    fn from_days_since_unix_epoch(days: i64) -> Self {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let day_of_era = z - era * 146_097;
        let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524
            - day_of_era / 146_096)
            / 365;
        let year = year_of_era + era * 400;
        let day_of_year =
            day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let mp = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let calendar_year = year + i64::from(month <= 2);
        Self {
            year: calendar_year as i32,
            month: month as u8,
            day: day as u8,
        }
    }

    fn format(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        // CalendarDate::validate has already rejected month outside 1..=12.
        _ => unreachable!("month {month} should have been rejected by validate()"),
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Probe the blockchain to find the earliest block height where account-0 shows
/// any activity (transparent UTXOs or shielded note decryptions).
///
/// Phase 1: Calls `GetAddressUtxos` for the first `PROBE_ACCOUNT_COUNT` account
/// transparent addresses — instant, O(1) per address.
///
/// Phase 2: For each year-interval probe point (activation, +1yr, +2yr, …),
/// creates a temporary workspace, imports account-0 with that birthday, and runs
/// a time-limited compact-block sync (≤45 s).  Returns as soon as activity is
/// found, setting the birthday to the previous probe year for safety.
///
/// Falls back to Sapling activation if nothing is found anywhere.
pub async fn detect_birthday<F>(
    seed_phrase: &SecretString,
    network: ZeckNetwork,
    lightwalletd_url: &str,
    on_progress: F,
) -> ZeckResult<BirthdayDetectResult>
where
    F: Fn(&str) + Send,
{
    let _ = rustls::crypto::ring::default_provider().install_default();

    on_progress("Connecting to lightwalletd…");
    let (mut client, primary_endpoint, chain_info) =
        probe_lightwalletd_endpoints(lightwalletd_url).await?;
    let chain_tip = u32::try_from(chain_info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let sapling_floor = u32::try_from(chain_info.sapling_activation_height)
        .unwrap_or(SAPLING_ACTIVATION_HEIGHT)
        .saturating_add(1);

    // ── Phase 1: transparent probe ────────────────────────────────────────────
    // Cross-check the earliest transparent UTXO across ALL configured endpoints
    // and take the minimum, so a single hostile server cannot hide early history
    // by withholding UTXOs and pushing the detected birthday later (audit Issue C
    // follow-up). Any honest endpoint that reports earlier activity lowers the
    // birthday.
    on_progress("Checking transparent address history across endpoints (instant)…");
    let earliest = earliest_transparent_across_endpoints(
        lightwalletd_url,
        &mut client,
        &primary_endpoint,
        seed_phrase,
        network,
        &on_progress,
    )
    .await;
    if let Some(earliest) = earliest {
        let birthday = earliest
            .saturating_sub(BIRTHDAY_BUFFER_BLOCKS)
            .max(sapling_floor);
        on_progress(&format!(
            "Transparent activity found at block {earliest}. Birthday → {birthday}."
        ));
        return Ok(BirthdayDetectResult {
            birthday,
            method: "transparent".to_owned(),
            message: format!(
                "Transparent activity detected at block {earliest}. \
                 Birthday set {BIRTHDAY_BUFFER_BLOCKS} blocks earlier to {birthday}. {}",
                late_birthday_caution(birthday, network)
            ),
        });
    }

    // ── Phase 2: stepped shielded probe ──────────────────────────────────────
    on_progress("No transparent history found. Probing shielded history by year…");
    let seed = mnemonic_seed(seed_phrase)?;
    let transparent_account = legacy_transparent_account_key(seed_phrase, network)?;
    let probe_keys = ShieldedProbeKeys {
        seed_phrase,
        seed: seed.expose_secret(),
        transparent_account: &transparent_account,
        sapling_floor,
    };

    // Build probe points: sapling_floor, +1yr, +2yr, … stop when too close to tip.
    let probe_heights: Vec<u32> = (0u32..)
        .map(|i| sapling_floor.saturating_add(PROBE_YEAR_STEP.saturating_mul(i)))
        .take_while(|&h| h.saturating_add(5_000) < chain_tip)
        .collect();

    for (i, &probe_height) in probe_heights.iter().enumerate() {
        let year_label = 2018usize.saturating_add(i);
        on_progress(&format!(
            "Probing ~{year_label} window (block {probe_height})…"
        ));

        let found = probe_shielded_window(
            &mut client,
            lightwalletd_url,
            &probe_keys,
            network,
            probe_height,
        )
        .await
        .unwrap_or(false);

        if found {
            // Set birthday to the PREVIOUS probe year so we don't miss any
            // notes from the window before the first detected activity.
            let birthday = if i == 0 {
                sapling_floor
            } else {
                probe_heights[i - 1]
            };
            on_progress(&format!(
                "Shielded activity detected near block {probe_height}. Birthday → {birthday}."
            ));
            return Ok(BirthdayDetectResult {
                birthday,
                method: "shielded_probe".to_owned(),
                message: format!(
                    "Shielded activity detected near year ~{year_label} \
                     (block {probe_height}). Birthday set to {birthday}. {}",
                    late_birthday_caution(birthday, network)
                ),
            });
        }
    }

    on_progress("No activity found in any probe window. Using Sapling activation.");
    Ok(BirthdayDetectResult {
        birthday: sapling_floor,
        method: "no_activity".to_owned(),
        message: format!(
            "No activity found in any probe window. \
             Using Sapling activation ({sapling_floor}) for a complete scan. \
             If you expected to recover funds, the lightwalletd server may have \
             returned incomplete history — retry against a server you trust."
        ),
    })
}

/// Combine two "earliest transparent activity" observations, taking the earlier
/// (minimum) of the two when both are present. A `None` from one endpoint never
/// raises the floor, so a hostile server that withholds early UTXOs cannot push
/// the detected birthday later than what an honest endpoint reports (audit
/// Issue C follow-up).
fn combine_earliest(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, b) => b,
    }
}

/// Probe the earliest transparent UTXO height across every configured
/// lightwalletd endpoint and return the minimum.
///
/// The already-connected `primary_client` (at `primary_endpoint`) is probed
/// first; every other configured endpoint is connected to and probed
/// independently, and unreachable secondaries are skipped best-effort. Taking
/// the minimum across endpoints means a single hostile server cannot hide early
/// history by withholding UTXOs (audit Issue C follow-up).
async fn earliest_transparent_across_endpoints<F>(
    lightwalletd_url: &str,
    primary_client: &mut CompactTxStreamerClient<Channel>,
    primary_endpoint: &str,
    seed_phrase: &SecretString,
    network: ZeckNetwork,
    on_progress: &F,
) -> Option<u32>
where
    F: Fn(&str),
{
    let mut earliest = probe_transparent(primary_client, seed_phrase, network)
        .await
        .ok()
        .flatten();

    let endpoints = validated_lightwalletd_endpoints(lightwalletd_url).unwrap_or_default();
    for endpoint in endpoints.iter().filter(|e| e.as_str() != primary_endpoint) {
        match CompactTxStreamerClient::connect(endpoint.clone()).await {
            Ok(mut client) => {
                // Validate the secondary's network before trusting its UTXO
                // heights, so a wrong-chain endpoint cannot influence the
                // detected birthday (audit Issue C follow-up review).
                let network_ok = match client.get_lightd_info(Empty {}).await {
                    Ok(info) => validate_lightwalletd_network(network, &info.into_inner()).is_ok(),
                    Err(_) => false,
                };
                if !network_ok {
                    on_progress(&format!(
                        "Secondary endpoint {endpoint} failed network validation for birthday cross-check (skipping)."
                    ));
                    continue;
                }
                let observed = probe_transparent(&mut client, seed_phrase, network)
                    .await
                    .ok()
                    .flatten();
                if let Some(h) = observed {
                    if earliest.is_none_or(|e| h < e) {
                        on_progress(&format!(
                            "Endpoint {endpoint} reported earlier transparent activity at block {h}; lowering birthday."
                        ));
                    }
                }
                earliest = combine_earliest(earliest, observed);
            }
            Err(err) => {
                on_progress(&format!(
                    "Secondary endpoint {endpoint} unreachable for birthday cross-check (skipping): {err}"
                ));
            }
        }
    }

    earliest
}

/// Call `GetAddressUtxos` for the first `PROBE_ACCOUNT_COUNT` accounts (both
/// external and internal transparent addresses).  Returns the earliest UTXO
/// block height, or `None` if no UTXOs exist or the RPC is unavailable.
async fn probe_transparent(
    client: &mut CompactTxStreamerClient<Channel>,
    seed_phrase: &SecretString,
    network: ZeckNetwork,
) -> ZeckResult<Option<u32>> {
    let accounts = derive_accounts(seed_phrase, network, PROBE_ACCOUNT_COUNT)?;
    let addresses: Vec<String> = accounts
        .iter()
        .flat_map(|a| {
            [
                a.transparent_receive_address.clone(),
                a.transparent_change_address.clone(),
            ]
        })
        .collect();

    let reply = client
        .get_address_utxos(GetAddressUtxosArg {
            addresses,
            start_height: 0,
            max_entries: 1_000,
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();

    let earliest = reply
        .address_utxos
        .iter()
        .filter_map(|utxo| u32::try_from(utxo.height).ok())
        .filter(|&h| h > 0)
        .min();

    Ok(earliest)
}

struct ShieldedProbeKeys<'a> {
    seed_phrase: &'a SecretString,
    seed: &'a [u8; 64],
    transparent_account: &'a zcash_transparent::keys::AccountPrivKey,
    sapling_floor: u32,
}

/// Create a temporary workspace at `probe_height`, import account-0, run a
/// time-limited compact-block sync (≤`PROBE_TIMEOUT_SECS` seconds), then check
/// whether any notes were written to the wallet DB.  Cleans up the temp
/// directory before returning.
async fn probe_shielded_window(
    client: &mut CompactTxStreamerClient<Channel>,
    lightwalletd_url: &str,
    keys: &ShieldedProbeKeys<'_>,
    network: ZeckNetwork,
    probe_height: u32,
) -> ZeckResult<bool> {
    let seed_phrase = keys.seed_phrase;
    let seed = keys.seed;
    let transparent_account = keys.transparent_account;
    let sapling_floor = keys.sapling_floor;
    let probe_dir = std::env::temp_dir().join(format!("zeck_probe_{}", Uuid::new_v4()));
    let effective_height = probe_height.max(sapling_floor.saturating_add(1));

    let probe_config = RuntimeScanConfig {
        seed_phrase: SecretString::new(seed_phrase.expose_secret().to_owned()),
        birthday: effective_height,
        num_accounts: Some(1),
        gap_limit: 1,
        lightwalletd_url: lightwalletd_url.to_owned(),
        data_dir: probe_dir.clone(),
        network,
        label: String::new(),
    };

    let workspace = RecoveryWorkspace::from_runtime(&probe_config)?;
    workspace.initialize(network, seed)?;

    let treestate = client
        .get_tree_state(BlockId {
            height: u64::from(effective_height.saturating_sub(1)),
            hash: vec![],
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();

    let account_birthday = AccountBirthday::from_treestate(treestate, None).map_err(|_| {
        ZeckError::Wallet("constructing probe account birthday from treestate".to_owned())
    })?;

    import_probe_account(&workspace, network, seed, &account_birthday, transparent_account)?;

    let net = consensus_network(network);
    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
        run_wallet_sync(&workspace, &net, client),
    )
    .await
    .is_err();

    if timed_out {
        // Reconnect so the next probe starts with a clean channel.
        if let Ok((new_client, _, _)) = probe_lightwalletd_endpoints(lightwalletd_url).await {
            *client = new_client;
        }
    }

    let has_activity = check_probe_activity(workspace.wallet_db_path()).unwrap_or(false);
    let _ = std::fs::remove_dir_all(&probe_dir);
    Ok(has_activity)
}

fn check_probe_activity(wallet_db_path: &std::path::Path) -> ZeckResult<bool> {
    let conn = Connection::open_with_flags(
        wallet_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| {
        ZeckError::Storage(format!("opening probe wallet for activity check: {err}"))
    })?;

    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sapling_received_notes)
          OR EXISTS(SELECT 1 FROM orchard_received_notes)
          OR EXISTS(SELECT 1 FROM transparent_received_outputs)",
        [],
        |row| row.get(0),
    )
    .map_err(|err| ZeckError::Wallet(format!("checking probe activity: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_birthday_caution_warns_and_dates_on_mainnet() {
        let note = late_birthday_caution(SAPLING_ACTIVATION_HEIGHT + 1_000_000, ZeckNetwork::Mainnet);
        // Tells the user to rescan with an earlier birthday...
        assert!(note.contains("rescan"));
        assert!(note.contains("earlier"));
        // ...and anchors the detected height to an approximate calendar date.
        assert!(note.contains("around 20"));
    }

    #[test]
    fn combine_earliest_takes_minimum_and_never_raised_by_none() {
        use super::combine_earliest;
        assert_eq!(combine_earliest(Some(900_000), Some(500_000)), Some(500_000));
        assert_eq!(combine_earliest(Some(500_000), Some(900_000)), Some(500_000));
        // A withholding or unreachable endpoint (None) must never raise the floor.
        assert_eq!(combine_earliest(Some(500_000), None), Some(500_000));
        assert_eq!(combine_earliest(None, Some(500_000)), Some(500_000));
        assert_eq!(combine_earliest(None, None), None);
    }

    #[test]
    fn late_birthday_caution_omits_date_on_testnet() {
        let note = late_birthday_caution(1_000_000, ZeckNetwork::Testnet);
        assert!(note.contains("rescan"));
        // The mainnet-calibrated estimator must not emit a (wrong) testnet date.
        assert!(!note.contains("around 20"));
    }

    #[test]
    fn sapling_activation_date_returns_activation_height() {
        let h = estimate_birthday_from_date_offline("2018-10-28").unwrap();
        assert_eq!(h, SAPLING_ACTIVATION_HEIGHT);
    }

    #[test]
    fn pre_sapling_date_clamps_to_activation_height() {
        let h = estimate_birthday_from_date_offline("2016-01-01").unwrap();
        assert_eq!(h, SAPLING_ACTIVATION_HEIGHT);
    }

    #[test]
    fn one_year_after_sapling_uses_pre_blossom_block_time() {
        // 1 year ≈ 365 days * 86400s / 150s = ~210k blocks, NOT 420k.
        let h = estimate_birthday_from_date_offline("2019-10-28").unwrap();
        let expected_min = SAPLING_ACTIVATION_HEIGHT + 195_000;
        let expected_max = SAPLING_ACTIVATION_HEIGHT + 220_000;
        assert!(
            h >= expected_min && h <= expected_max,
            "height {h} outside [{expected_min}, {expected_max}]"
        );
    }

    #[test]
    fn blossom_activation_date_lands_near_blossom_height() {
        let h = estimate_birthday_from_date_offline("2019-12-11").unwrap();
        assert!(
            (h as i64 - BLOSSOM_ACTIVATION_HEIGHT as i64).abs() < 5_000,
            "height {h} too far from blossom height {BLOSSOM_ACTIVATION_HEIGHT}"
        );
    }

    #[test]
    fn one_year_after_blossom_uses_post_blossom_block_time() {
        let h = estimate_birthday_from_date_offline("2020-12-11").unwrap();
        let expected_min = BLOSSOM_ACTIVATION_HEIGHT + 410_000;
        let expected_max = BLOSSOM_ACTIVATION_HEIGHT + 430_000;
        assert!(
            h >= expected_min && h <= expected_max,
            "height {h} outside [{expected_min}, {expected_max}]"
        );
    }

    #[test]
    fn invalid_date_format_is_rejected() {
        assert!(estimate_birthday_from_date_offline("28-10-2018").is_err());
        assert!(estimate_birthday_from_date_offline("2018/10/28").is_err());
        assert!(estimate_birthday_from_date_offline("not-a-date").is_err());
        assert!(estimate_birthday_from_date_offline("").is_err());
    }

    #[test]
    fn future_date_produces_height_above_current_chain() {
        let h = estimate_birthday_from_date_offline("2030-01-01").unwrap();
        assert!(h > 2_000_000, "expected large height, got {h}");
    }

    #[test]
    fn leap_year_february_29_is_handled() {
        let h = estimate_birthday_from_date_offline("2020-02-29").unwrap();
        assert!(
            h > SAPLING_ACTIVATION_HEIGHT,
            "expected height above activation"
        );
    }

    #[test]
    fn date_parser_rejects_invalid_calendar_dates() {
        assert!(CalendarDate::parse("2024-02-30").is_err());
        assert!(CalendarDate::parse("2024-13-01").is_err());
        assert!(CalendarDate::parse("2025-04-31").is_err());
    }

    #[test]
    fn date_height_round_trip_is_close() {
        for date in ["2019-06-01", "2020-01-01", "2022-07-15", "2024-03-01"] {
            let h = estimate_birthday_from_date_offline(date).unwrap();
            let back = estimate_date_from_height_offline(h);
            let parsed_in = CalendarDate::parse(date).unwrap();
            let parsed_out = CalendarDate::parse(&back).unwrap();
            let drift =
                (parsed_in.days_since_unix_epoch() - parsed_out.days_since_unix_epoch()).abs();
            assert!(drift <= 1, "round-trip drift {drift} days for {date} -> {back}");
        }
    }

    #[test]
    fn date_from_height_at_activation() {
        assert_eq!(
            estimate_date_from_height_offline(SAPLING_ACTIVATION_HEIGHT),
            "2018-10-28"
        );
        // Just past Blossom we anchor exactly to its date.
        assert!(
            estimate_date_from_height_offline(BLOSSOM_ACTIVATION_HEIGHT + 1)
                .starts_with("2019-12-")
        );
    }

    #[test]
    fn calendar_date_round_trip_via_days_since_epoch() {
        for (y, m, d) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2018, 10, 28),
            (2024, 12, 31),
        ] {
            let cd = CalendarDate { year: y, month: m, day: d };
            let back = CalendarDate::from_days_since_unix_epoch(cd.days_since_unix_epoch());
            assert_eq!(back, cd, "round trip failed for {y}-{m}-{d}");
        }
    }
}
