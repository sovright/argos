use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use tonic::transport::Channel;
use uuid::Uuid;
use zcash_client_backend::{
    data_api::AccountBirthday,
    proto::service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, Empty, GetAddressUtxosArg,
    },
};

use argos_wallet_import::keys::ImportedKeys;

use crate::{
    derivation::{derive_accounts, legacy_transparent_account_key, mnemonic_seed},
    error::{ZeckError, ZeckResult},
    imported::{imported_transparent_keys, ImportedTransparentKey},
    key_source::SeedKeySource,
    lightwalletd::{
        probe_lightwalletd_endpoints, probe_lightwalletd_endpoints_with_retry,
        validate_lightwalletd_network, validated_lightwalletd_endpoints,
    },
    models::{BirthdayDetectResult, RuntimeScanConfig, ZeckNetwork},
    scan::{import_probe_account, run_wallet_sync},
    transparent_recovery::fetch_transparent_utxos,
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
/// Post-Blossom and pre-NU7 block target is 75 s.
const POST_BLOSSOM_BLOCK_SECONDS: i64 = 75;
/// NU7 reduces the target to 25 seconds at its network-specific height.
const POST_NU7_BLOCK_SECONDS: i64 = 25;
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
const SECONDARY_PROBE_TIMEOUT_SECS: u64 = 5;
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

/// Consensus spacing at a known height. This never infers activation from a
/// calendar date, including when a local regtest schedule is installed.
fn birthday_block_seconds(network: ZeckNetwork, height: u32) -> i64 {
    if crate::nu7::activation_height(network).is_some_and(|activation| height >= activation) {
        POST_NU7_BLOCK_SECONDS
    } else if height
        >= match network {
            ZeckNetwork::Mainnet => BLOSSOM_ACTIVATION_HEIGHT,
            ZeckNetwork::Testnet => 584_000,
        }
    {
        POST_BLOSSOM_BLOCK_SECONDS
    } else {
        PRE_BLOSSOM_BLOCK_SECONDS
    }
}

/// Preserve the historical margin, and at least its one-week duration when
/// the target spacing falls to 25 seconds. This is a dating margin, not a
/// transaction-confirmation or finality threshold.
fn date_safety_buffer_blocks(network: ZeckNetwork, height: u32) -> u32 {
    DATE_SAFETY_BUFFER_BLOCKS.max(
        u32::try_from(7 * DAY_SECONDS / birthday_block_seconds(network, height))
            .unwrap_or(DATE_SAFETY_BUFFER_BLOCKS),
    )
}

/// Conservative mainnet offline estimate. Historical 150/75-second anchors
/// are retained. An offline clock cannot establish when NU7 actually mined,
/// so dates beyond that historical extrapolation stop before activation
/// rather than guessing a calendar date for the 25-second transition.
pub fn estimate_birthday_from_date_offline(date: &str) -> ZeckResult<u32> {
    estimate_birthday_from_date_offline_for_network(date, ZeckNetwork::Mainnet)
}

/// Network-aware offline fallback. Testnet has no reliable calendar anchors
/// because its production includes stalls and minimum-difficulty bursts;
/// scanning from Sapling activation is safer than inventing a later birthday.
pub fn estimate_birthday_from_date_offline_for_network(
    date: &str,
    network: ZeckNetwork,
) -> ZeckResult<u32> {
    let parsed = CalendarDate::parse(date)?;
    if network == ZeckNetwork::Testnet {
        return Ok(280_000);
    }
    if parsed <= SAPLING_ACTIVATION_DATE {
        return Ok(SAPLING_ACTIVATION_HEIGHT);
    }
    let (anchor_date, anchor_height, seconds_per_block) = if parsed <= BLOSSOM_ACTIVATION_DATE {
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
    let seconds = parsed
        .days_since_unix_epoch()
        .saturating_sub(anchor_date.days_since_unix_epoch())
        .saturating_mul(DAY_SECONDS);
    let blocks = u32::try_from((seconds / seconds_per_block).max(0)).unwrap_or(u32::MAX);
    let mut height = anchor_height.saturating_add(blocks);
    let target_time = parsed.days_since_unix_epoch().saturating_mul(DAY_SECONDS);
    // Recent dates also use the observed mainnet anchors and their existing
    // four-week dating margin. The display estimator's synthetic continuity
    // date for NU7 can precede its actual mined timestamp; it must never
    // advance a scan past history that the conservative anchors still cover.
    if target_time >= MAINNET_HEIGHT_ANCHORS[MAINNET_HEIGHT_ANCHORS.len() - 1].1 {
        if let Some(conservative) = height_at_or_before_time(network, target_time) {
            height = height.min(conservative);
        }
    }
    Ok(
        crate::nu7::activation_height(network).map_or(height, |activation| {
            height.min(activation.saturating_sub(1))
        }),
    )
}

/// Estimate a wallet birthday from a date by binary-searching lightwalletd for
/// the first block whose timestamp meets-or-exceeds the target.  Falls back to
/// the offline piecewise heuristic if any RPC fails.
///
/// A safety margin of ~1 week (`DATE_SAFETY_BUFFER_BLOCKS`) is subtracted so
/// we err toward over-scanning rather than missing notes.
pub async fn estimate_birthday_from_date(date: &str, lightwalletd_url: &str) -> ZeckResult<u32> {
    estimate_birthday_from_date_for_network(date, lightwalletd_url, ZeckNetwork::Mainnet).await
}

/// Estimate against the selected network's live block timestamps. The
/// binary search naturally spans NU7's spacing transition without assigning
/// the upgrade a speculative calendar date.
pub async fn estimate_birthday_from_date_for_network(
    date: &str,
    lightwalletd_url: &str,
    network: ZeckNetwork,
) -> ZeckResult<u32> {
    let parsed = CalendarDate::parse(date)?;
    let network_floor = match network {
        ZeckNetwork::Mainnet => SAPLING_ACTIVATION_HEIGHT,
        ZeckNetwork::Testnet => 280_000,
    };
    if parsed <= SAPLING_ACTIVATION_DATE {
        return Ok(network_floor);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let target_unix = parsed.days_since_unix_epoch().saturating_mul(DAY_SECONDS);

    let probed = match probe_lightwalletd_endpoints(lightwalletd_url).await {
        Ok(probe) => probe,
        Err(_) => return estimate_birthday_from_date_offline_for_network(date, network),
    };
    let (mut client, _endpoint, chain_info) = probed;
    validate_lightwalletd_network(network, &chain_info)?;

    let chain_tip = match u32::try_from(chain_info.block_height) {
        Ok(h) => h,
        Err(_) => return estimate_birthday_from_date_offline_for_network(date, network),
    };
    let sapling_floor =
        u32::try_from(chain_info.sapling_activation_height).unwrap_or(network_floor);

    let tip_time = match fetch_block_time(&mut client, chain_tip).await {
        Ok(t) => t,
        Err(_) => return estimate_birthday_from_date_offline_for_network(date, network),
    };
    if target_unix >= tip_time {
        return Ok(chain_tip
            .saturating_sub(date_safety_buffer_blocks(network, chain_tip))
            .max(sapling_floor));
    }

    let mut lo = sapling_floor;
    let mut hi = chain_tip;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mid_time = match fetch_block_time(&mut client, mid).await {
            Ok(t) => t,
            Err(_) => return estimate_birthday_from_date_offline_for_network(date, network),
        };
        if mid_time < target_unix {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    Ok(lo
        .saturating_sub(date_safety_buffer_blocks(network, lo))
        .max(sapling_floor))
}

/// Display-only piecewise estimate: historical 150/75-second targets, then
/// 25 seconds from the assigned mainnet NU7 height. The derived continuity
/// anchor is not an observed activation timestamp and is never inverted to
/// determine a post-NU7 scan birthday.
///
/// Below Sapling activation it counts back from Sapling at the same 150 s
/// target, floored at the mainnet genesis date: a wallet.dat birthday can be
/// pre-Sapling, and a date stuck at 2018 beside it would misstate its age.
pub fn estimate_date_from_height_offline(height: u32) -> String {
    let seconds = if height <= BLOSSOM_ACTIVATION_HEIGHT {
        SAPLING_ACTIVATION_DATE.days_since_unix_epoch() * DAY_SECONDS
            + (i64::from(height) - i64::from(SAPLING_ACTIVATION_HEIGHT)) * PRE_BLOSSOM_BLOCK_SECONDS
    } else {
        let pre_nu7_height = crate::nu7::activation_height(ZeckNetwork::Mainnet)
            .map_or(height, |activation| height.min(activation));
        let post_nu7_blocks = height.saturating_sub(pre_nu7_height);
        BLOSSOM_ACTIVATION_DATE.days_since_unix_epoch() * DAY_SECONDS
            + (i64::from(pre_nu7_height) - i64::from(BLOSSOM_ACTIVATION_HEIGHT))
                * POST_BLOSSOM_BLOCK_SECONDS
            + i64::from(post_nu7_blocks) * birthday_block_seconds(ZeckNetwork::Mainnet, height)
    };
    // This date is an approximate display hint, never evidence that NU7
    // activated on a particular date or permission to skip unscanned blocks.
    let absolute_days = seconds
        .div_euclid(DAY_SECONDS)
        .max(MAINNET_GENESIS_DATE.days_since_unix_epoch());
    CalendarDate::from_days_since_unix_epoch(absolute_days).format()
}

/// The day the mainnet genesis block was mined; no height is dated earlier.
const MAINNET_GENESIS_DATE: CalendarDate = CalendarDate {
    year: 2016,
    month: 10,
    day: 28,
};

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

// ── Wallet-file birthday ─────────────────────────────────────────────────────
//
// A zcashd `wallet.dat` records when each key was created. That reaches back
// past Sapling activation, which matters for Sprout: the full-block Sprout
// scan can skip trial decryption for every block mined before the wallet's
// Sprout keys existed. The rule throughout is that an early height only
// costs time and a late one loses funds, so every conversion here rounds
// toward the start of the chain.

pub use argos_wallet_import::zcashd::UNKNOWN_CREATE_TIME_AT_OR_BEFORE;

/// Mainnet `(height, unix time)` points the time conversion interpolates
/// between. Heights are the network-upgrade activation heights
/// (`zcash_protocol::consensus::MAIN_NETWORK`), plus block 1 — genesis's own
/// timestamp is about eight hours before the chain actually started, so
/// block 1 is the true start. Each time is that block's header timestamp
/// (checked against a block explorer, 2026-10-21) plus one day.
///
/// The extra day is deliberate. A later anchor time lowers the estimate on
/// both sides of it, so an anchor that errs late can only make a bound
/// earlier, and the day absorbs any error in the source. The heights are
/// protocol constants; only the times are observational.
const MAINNET_HEIGHT_ANCHORS: [(u32, i64); 6] = [
    // Block 1: 2016-10-28 16:19:56 UTC.
    (1, 1_477_671_596 + DAY_SECONDS),
    // Sapling: 2018-10-29 02:15:37 UTC.
    (419_200, 1_540_779_337 + DAY_SECONDS),
    // Blossom: 2019-12-11 21:50:05 UTC. Block target 150 s -> 75 s.
    (653_600, 1_576_101_005 + DAY_SECONDS),
    // Canopy: 2020-11-18 12:34:16 UTC.
    (1_046_400, 1_605_702_856 + DAY_SECONDS),
    // NU5: 2022-05-31 17:50:05 UTC.
    (1_687_104, 1_654_019_405 + DAY_SECONDS),
    // NU6: 2024-11-23 11:02:59 UTC.
    (2_726_400, 1_732_359_779 + DAY_SECONDS),
];

/// Block spacing assumed past the last anchor. The target is 75 s, but the
/// chain has averaged about 75.4 s since Blossom; extrapolating at the
/// target would run ahead of the real chain by roughly half a percent of the
/// elapsed time — more than the margin within a few years. 77 s stays behind
/// unless the chain runs more than 2% fast for years, which its difficulty
/// adjustment does not allow.
const EXTRAPOLATION_BLOCK_SECONDS: i64 = 77;

/// Subtracted from a creation time before it is converted. Covers a wrong
/// clock on the machine that created the key, uneven block production
/// between anchors, and the mining delay before a first payment confirms.
/// Four weeks: with nothing sampled between the anchors, the interpolation
/// alone can only be trusted to within about two, and missing a note costs
/// far more than four weeks of blocks of extra trial decryption.
const CREATION_TIME_MARGIN_SECS: i64 = 28 * DAY_SECONDS;

/// Seconds since the Unix epoch on this computer's clock.
///
/// The only clock read in this module. The dating functions take `now` as a
/// parameter instead, so tests can fix it and nothing about a birthday
/// depends on when a test happens to run.
pub fn unix_time_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The highest mainnet height that is certainly no later than the chain at
/// `unix_time`, less a four-week margin. Clamped to at least 1.
///
/// Interpolates between [`MAINNET_HEIGHT_ANCHORS`] and extrapolates past the
/// last at [`EXTRAPOLATION_BLOCK_SECONDS`], rounding down throughout. Keeping
/// this deliberately slow extrapolation after NU7 can only lower the bound
/// relative to the new 25-second target; no upgrade timestamp is guessed.
/// Pure; no network.
///
/// `None` on testnet. Testnet's block production has been irregular —
/// stalls and minimum-difficulty bursts — so no anchor table there could be
/// trusted to stay below the chain, and a height that might be late is worse
/// than none.
pub fn height_at_or_before_time(network: ZeckNetwork, unix_time: i64) -> Option<u32> {
    if network != ZeckNetwork::Mainnet {
        return None;
    }
    let t = i128::from(unix_time) - i128::from(CREATION_TIME_MARGIN_SECS);
    let anchors = MAINNET_HEIGHT_ANCHORS;
    let (first_height, first_time) = anchors[0];
    if t <= i128::from(first_time) {
        return Some(first_height.max(1));
    }

    let height: i128 = match anchors.windows(2).find(|pair| t < i128::from(pair[1].1)) {
        Some(pair) => {
            let (h0, t0) = (i128::from(pair[0].0), i128::from(pair[0].1));
            let (h1, t1) = (i128::from(pair[1].0), i128::from(pair[1].1));
            // Integer division rounds toward zero, and every term is
            // non-negative here, so this rounds down.
            h0 + (t - t0) * (h1 - h0) / (t1 - t0)
        }
        None => {
            let (h, at) = anchors[anchors.len() - 1];
            i128::from(h) + (t - i128::from(at)) / i128::from(EXTRAPOLATION_BLOCK_SECONDS)
        }
    };
    Some(u32::try_from(height.max(1)).unwrap_or(u32::MAX))
}

/// Where a wallet file's birthday came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletBirthdaySource {
    /// Every key in the file has a recorded creation time; the birthday is a
    /// lower bound derived from the earliest.
    WalletMetadata,
    /// The file could not date every key, so the birthday comes from the
    /// earliest *unspent* transparent output the chain reports for the
    /// file's transparent keys. An upper bound on the keys' age, not a lower
    /// one: funds received and spent before it, or held only in shielded
    /// pools, can be older.
    TransparentUtxos,
    /// Nothing to go on. Scan from the start of each pool.
    None,
}

/// What a wallet file says about where to start scanning.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalletFileBirthday {
    /// The birthday to show and fill in. May be below Sapling activation:
    /// a Sapling sync start must still be clamped to at least activation by
    /// the caller. `None` with [`WalletBirthdaySource::None`].
    pub height: Option<u32>,
    pub source: WalletBirthdaySource,
    /// Keys in the file with no usable creation time.
    pub keys_without_time: usize,
    /// One user-facing paragraph: the height, where it came from, and what
    /// to do if the wallet is older.
    pub message: String,
    /// Height below which the Sprout full-block scan may skip trial
    /// decryption. Derived only from the creation times of the Sprout keys
    /// being scanned, and only when every one of them has one — see
    /// [`sprout_skip_height`]. Independent of `height` and `source`: never
    /// taken from transparent outputs or Sapling metadata.
    pub sprout_skip_height: Option<u32>,
    /// Why there is or is not a skip, for the user: a skip can hide notes if
    /// the file's times are wrong, so it is always stated, never silent.
    pub sprout_skip_reason: String,
}

/// A key's creation time if it can be trusted at `now`.
///
/// A time later than this computer's clock was written by a machine whose
/// clock was wrong, and the true birth could be any time before it. Treated
/// as no time, so it can only make a scan start earlier.
fn trusted_time(created_at: Option<i64>, now: i64) -> Option<i64> {
    created_at.filter(|&t| t <= now)
}

/// Whether a key records a creation time `trusted_time` throws away.
fn is_future(created_at: Option<i64>, now: i64) -> bool {
    created_at.is_some_and(|t| t > now)
}

/// The height below which the Sprout scan of `keys`' Sprout keys plus
/// `extra_sprout_keys` may skip trial decryption.
///
/// `Some` only when every key to be scanned has a creation time from this
/// file: one key of unknown age could have received a note at any height.
/// An extra key (from a key file or pasted text) counts as dated only if it
/// is one of the file's own dated keys. Never uses transparent or Sapling
/// times — a Sprout key can be older than every other key in the wallet.
/// A time later than `now` counts as no time (see [`trusted_time`]).
pub fn sprout_skip_height(
    keys: &ImportedKeys,
    extra_sprout_keys: &[[u8; 32]],
    network: ZeckNetwork,
    now: i64,
) -> Option<u32> {
    let dated = |a_sk: &[u8; 32]| -> Option<i64> {
        let mut matching = keys
            .sprout
            .iter()
            .filter(|k| k.a_sk.expose_secret() == a_sk)
            .peekable();
        matching.peek()?;
        // A key stored twice with different metadata takes the most
        // cautious reading: any record without a time means no time.
        matching
            .map(|k| trusted_time(k.created_at, now))
            .min()
            .flatten()
    };
    let mut earliest: Option<i64> = None;
    let scanned = keys
        .sprout
        .iter()
        .map(|k| *k.a_sk.expose_secret())
        .chain(extra_sprout_keys.iter().copied());
    let mut any = false;
    for a_sk in scanned {
        any = true;
        let time = dated(&a_sk)?;
        earliest = Some(earliest.map_or(time, |e| e.min(time)));
    }
    if !any {
        return None;
    }
    height_at_or_before_time(network, earliest?)
}

/// The birthday a wallet file gives on its own, with no network.
///
/// `extra_sprout_keys` are Sprout keys that will be scanned alongside the
/// file's (a `--sprout-key-file`, the GUI paste box); they affect only the
/// Sprout skip. `keys_added_outside_file` counts the keys in `keys` that did
/// not come from the file (Sapling keys merged in from a key file or the
/// paste box, which never carry a time), so the message can say where the
/// undated keys came from. `now` is the current Unix time: a creation time
/// later than it counts as no time.
pub fn wallet_file_birthday_from_metadata(
    keys: &ImportedKeys,
    extra_sprout_keys: &[[u8; 32]],
    network: ZeckNetwork,
    keys_added_outside_file: usize,
    now: i64,
) -> WalletFileBirthday {
    let recorded: Vec<Option<i64>> = all_created_at(keys).collect();
    let times: Vec<Option<i64>> = recorded.iter().map(|&t| trusted_time(t, now)).collect();
    let total = times.len();
    let keys_without_time = times.iter().filter(|t| t.is_none()).count();
    let future = recorded.iter().filter(|&&t| is_future(t, now)).count();

    let sprout_skip = sprout_skip_height(keys, extra_sprout_keys, network, now);
    let sprout_skip_reason = sprout_skip_reason(keys, extra_sprout_keys, network, sprout_skip, now);

    let earliest = times.iter().copied().min().flatten();
    let dated_height = earliest.and_then(|t| height_at_or_before_time(network, t));

    let (height, source, message) = match dated_height {
        Some(height) if total > 0 && keys_without_time == 0 => (
            Some(height),
            WalletBirthdaySource::WalletMetadata,
            format!(
                "The wallet file records its oldest key as created on {}. Argos will start \
                 from block {height}, {margin} days before that and rounded down. This is \
                 the file's own claim, from the clock of the computer that created the \
                 key: if the wallet is older, enter an earlier birthday.",
                date_of_unix_time(earliest.unwrap_or_default()),
                margin = CREATION_TIME_MARGIN_SECS / DAY_SECONDS,
            ),
        ),
        _ => (None, WalletBirthdaySource::None, {
            let why = if network != ZeckNetwork::Mainnet {
                "Creation times are only converted to heights on mainnet".to_owned()
            } else if total == 0 {
                "The wallet file holds no keys to date".to_owned()
            } else {
                format!(
                    "{}, so the keys cannot all be dated",
                    describe_undated(total, keys_without_time, future, keys_added_outside_file)
                )
            };
            format!("{why}. Argos will scan from the start of each pool.")
        }),
    };

    WalletFileBirthday {
        height,
        source,
        keys_without_time,
        message,
        sprout_skip_height: sprout_skip,
        sprout_skip_reason,
    }
}

/// Every key's recorded creation time, in no particular order.
fn all_created_at(keys: &ImportedKeys) -> impl Iterator<Item = Option<i64>> + '_ {
    keys.transparent
        .iter()
        .map(|k| k.created_at)
        .chain(keys.sapling.iter().map(|k| k.created_at))
        .chain(keys.sprout.iter().map(|k| k.created_at))
}

/// Which keys are undated and why, as the start of a sentence.
///
/// `total` and `undated` count every key in the set, including the
/// `outside` ones added from a key file or the paste box. Those always lack
/// a time, so they are named for what they are rather than counted as the
/// file's, and zcashd is blamed only for keys that are in the file.
fn describe_undated(total: usize, undated: usize, future: usize, outside: usize) -> String {
    let outside = outside.min(undated);
    let file_total = total.saturating_sub(outside);
    let file_undated = undated - outside;
    let added =
        format!("{outside} key(s) added from a key file or paste box carry no creation time");
    if file_undated == 0 {
        return added;
    }
    let file_part = if future == 0 {
        format!(
            "{file_undated} of {file_total} keys in the wallet file have no recorded creation \
             time (zcashd does not record one for imported keys)"
        )
    } else if future == file_undated {
        format!(
            "{file_undated} of {file_total} keys in the wallet file have no usable creation \
             time ({future} record one later than this computer's clock, which cannot be right)"
        )
    } else {
        format!(
            "{file_undated} of {file_total} keys in the wallet file have no usable creation \
             time ({future} record one later than this computer's clock, and zcashd does not \
             record one for imported keys)"
        )
    };
    if outside == 0 {
        file_part
    } else {
        format!("{file_part}, and {added}")
    }
}

fn sprout_skip_reason(
    keys: &ImportedKeys,
    extra_sprout_keys: &[[u8; 32]],
    network: ZeckNetwork,
    skip: Option<u32>,
    now: i64,
) -> String {
    if let Some(height) = skip {
        return format!(
            "The Sprout scan will still walk every block from 1, but will not try to \
             decrypt notes in blocks below {height}: the wallet file records every Sprout \
             key being scanned as created after that. If the file's times are wrong, notes \
             below that block will not be found — turn the skip off, or enter an earlier \
             birthday, to scan every block."
        );
    }
    let reason = if keys.sprout.is_empty() && extra_sprout_keys.is_empty() {
        "there are no Sprout keys to scan"
    } else if network != ZeckNetwork::Mainnet {
        "creation times are only converted to heights on mainnet"
    } else if keys.sprout.iter().any(|k| is_future(k.created_at, now)) {
        "at least one Sprout key being scanned records a creation time later than this \
         computer's clock, which cannot be right"
    } else {
        "at least one Sprout key being scanned has no recorded creation time"
    };
    format!("The Sprout scan will try to decrypt every block, because {reason}.")
}

/// The bound a Sprout scan decrypts from, and the one line that says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SproutDecryptPlan {
    /// `None` decrypts every block.
    pub decrypt_from: Option<u32>,
    pub line: String,
}

/// Combine the wallet file's Sprout skip with what the user asked for.
///
/// `skip` and `skip_reason` come from [`wallet_file_birthday_from_metadata`]
/// for the keys being scanned. A birthday the user gave can only lower the
/// bound, never raise it or create one: the skip is allowed to exist only
/// because every scanned key is dated, and a typed height is no evidence of
/// that. A floor of 0 or 1 therefore means every block. Shared by both
/// surfaces so they make the same decision and say it the same way; each
/// appends its own words for how to turn the skip off.
pub fn plan_sprout_decrypt(
    skip: Option<u32>,
    skip_reason: &str,
    birthday_floor: Option<u32>,
    decrypt_every_block: bool,
) -> SproutDecryptPlan {
    let every = |why: &str| SproutDecryptPlan {
        decrypt_from: None,
        line: format!("Trial decryption will cover every block from 1: {why}."),
    };
    let Some(skip) = skip else {
        return SproutDecryptPlan {
            decrypt_from: None,
            line: skip_reason.to_owned(),
        };
    };
    if decrypt_every_block {
        return every("the birthday skip was turned off");
    }
    match birthday_floor {
        Some(floor) if floor <= 1 => every("the birthday given is block 1 or earlier"),
        Some(floor) if floor < skip => SproutDecryptPlan {
            decrypt_from: Some(floor),
            line: format!(
                "Trial decryption starts at block {floor}, the birthday given, rather than \
                 block {skip}, which the wallet file's Sprout key creation times would allow. \
                 The walk itself still starts at block 1."
            ),
        },
        _ => SproutDecryptPlan {
            decrypt_from: Some(skip),
            line: format!(
                "Trial decryption starts at block {skip} (about {date}), because the wallet \
                 file's creation times put every Sprout key being scanned after then. The walk \
                 itself still starts at block 1, but a note paid to these keys below block \
                 {skip} would not be found.",
                date = estimate_date_from_height_offline(skip),
            ),
        },
    }
}

/// Whether the chain should be asked: the file could not date every key,
/// it holds transparent keys whose outputs the chain can report, and every
/// Sapling key is dated.
///
/// For imported keys the birthday drives only the Sapling scan: transparent
/// funds are found by `GetAddressUtxos` whatever it says. An undated Sapling
/// key (`z_importkey`'d into the file, or added from a key file or the paste
/// box) could hold notes from any height after activation, and a transparent
/// output says nothing about when they arrived -- the same reason the Sprout
/// skip never uses one. So that case gets no birthday at all.
pub fn needs_chain_fallback(offline: &WalletFileBirthday, keys: &ImportedKeys, now: i64) -> bool {
    offline.source == WalletBirthdaySource::None
        && !keys.transparent.is_empty()
        && !has_undated_sapling_key(keys, now)
}

/// Whether any Sapling key lacks a creation time that can be trusted at
/// `now`.
fn has_undated_sapling_key(keys: &ImportedKeys, now: i64) -> bool {
    keys.sapling
        .iter()
        .any(|k| trusted_time(k.created_at, now).is_none())
}

/// Appended to the birthday message when an undated Sapling key rules out
/// the chain fallback.
const UNDATED_SAPLING_NO_FALLBACK: &str = "A Sapling key with no creation time could have \
     received notes at any height, and transparent outputs cannot date it, so the chain was \
     not used for a birthday: Sapling will be scanned from Sapling activation.";

/// Fold the chain's earliest unspent transparent output into a birthday the
/// file could not give.
///
/// The output height is an upper bound on the keys' age, so it is lowered by
/// [`BIRTHDAY_BUFFER_BLOCKS`] and further by any dated key's own bound, with
/// no Sapling floor. The Sprout skip is left exactly as it was: an unspent
/// transparent output says nothing about when a Sprout note arrived.
fn apply_utxo_fallback(
    offline: WalletFileBirthday,
    keys: &ImportedKeys,
    network: ZeckNetwork,
    earliest_utxo: Option<u32>,
    keys_added_outside_file: usize,
    now: i64,
) -> WalletFileBirthday {
    if has_undated_sapling_key(keys, now) {
        return WalletFileBirthday {
            message: format!("{} {UNDATED_SAPLING_NO_FALLBACK}", offline.message),
            ..offline
        };
    }
    let Some(earliest_utxo) = earliest_utxo else {
        return WalletFileBirthday {
            message: format!(
                "{} The chain reports no unspent transparent outputs for this file's \
                 transparent keys either.",
                offline.message
            ),
            ..offline
        };
    };
    let from_chain = earliest_utxo.saturating_sub(BIRTHDAY_BUFFER_BLOCKS).max(1);
    let dated_min = all_created_at(keys)
        .filter_map(|t| trusted_time(t, now))
        .filter_map(|t| height_at_or_before_time(network, t))
        .min();
    let recorded: Vec<Option<i64>> = all_created_at(keys).collect();
    let future = recorded.iter().filter(|&&t| is_future(t, now)).count();
    let undated = describe_undated(
        recorded.len(),
        offline.keys_without_time,
        future,
        keys_added_outside_file,
    );
    let height = dated_min.map_or(from_chain, |d| d.min(from_chain));
    WalletFileBirthday {
        height: Some(height),
        source: WalletBirthdaySource::TransparentUtxos,
        message: format!(
            "{undated}, so the birthday comes from the chain: the earliest unspent \
             transparent output for this file's keys is at block {earliest_utxo}, and Argos \
             will start from block {height}. That is an upper bound, not the wallet's age — \
             funds received and later spent, or held only in shielded pools, can be older. \
             If the wallet is older, enter an earlier birthday."
        ),
        ..offline
    }
}

/// [`wallet_file_birthday_from_metadata`], then — only if the file cannot
/// date every key — the earliest unspent transparent output across every
/// configured lightwalletd endpoint, for every transparent key in the file.
///
/// A failed or unreachable chain check leaves the offline answer in place
/// and says so; it never fails the call, because "no birthday" is always a
/// safe answer.
pub async fn detect_wallet_file_birthday<F>(
    keys: &ImportedKeys,
    extra_sprout_keys: &[[u8; 32]],
    network: ZeckNetwork,
    keys_added_outside_file: usize,
    now: i64,
    lightwalletd_url: Option<&str>,
    on_progress: F,
) -> WalletFileBirthday
where
    F: Fn(&str) + Send,
{
    let offline = wallet_file_birthday_from_metadata(
        keys,
        extra_sprout_keys,
        network,
        keys_added_outside_file,
        now,
    );
    let Some(url) = lightwalletd_url else {
        return offline;
    };
    if offline.source == WalletBirthdaySource::None && has_undated_sapling_key(keys, now) {
        return WalletFileBirthday {
            message: format!("{} {UNDATED_SAPLING_NO_FALLBACK}", offline.message),
            ..offline
        };
    }
    if !needs_chain_fallback(&offline, keys, now) {
        return offline;
    }
    let transparent = match imported_transparent_keys(keys) {
        Ok(keys) => keys,
        Err(err) => {
            return WalletFileBirthday {
                message: format!("{} The chain was not checked: {err}.", offline.message),
                ..offline
            }
        }
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    on_progress("Checking the wallet file's transparent addresses on chain…");
    let (mut client, primary_endpoint, _) = match probe_lightwalletd_endpoints_with_retry(url).await
    {
        Ok(probe) => probe,
        Err(err) => {
            return WalletFileBirthday {
                message: format!("{} The chain could not be checked: {err}.", offline.message),
                ..offline
            }
        }
    };
    let earliest = earliest_imported_utxo_across_endpoints(
        url,
        &mut client,
        &primary_endpoint,
        &transparent,
        network,
        &on_progress,
    )
    .await;
    apply_utxo_fallback(
        offline,
        keys,
        network,
        earliest,
        keys_added_outside_file,
        now,
    )
}

/// Earliest confirmed UTXO height for `keys`, the minimum across every
/// configured endpoint for the same reason as the seed path: one server
/// withholding history must not push the birthday later.
async fn earliest_imported_utxo_across_endpoints<F>(
    lightwalletd_url: &str,
    primary_client: &mut CompactTxStreamerClient<Channel>,
    primary_endpoint: &str,
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
    on_progress: &F,
) -> Option<u32>
where
    F: Fn(&str),
{
    let earliest_of = |utxos: Vec<crate::transparent_recovery::TransparentUtxo>| {
        utxos
            .iter()
            .filter_map(|u| u32::try_from(u.height).ok())
            .filter(|&h| h > 0)
            .min()
    };
    let mut earliest = fetch_transparent_utxos(primary_client, keys, network)
        .await
        .ok()
        .and_then(earliest_of);

    let endpoints = validated_lightwalletd_endpoints(lightwalletd_url).unwrap_or_default();
    for endpoint in endpoints.iter().filter(|e| e.as_str() != primary_endpoint) {
        let mut client = match connect_validated_secondary(endpoint, network).await {
            Ok(client) => client,
            Err(notice) => {
                on_progress(&notice);
                continue;
            }
        };
        let observed = match tokio::time::timeout(
            std::time::Duration::from_secs(SECONDARY_PROBE_TIMEOUT_SECS),
            fetch_transparent_utxos(&mut client, keys, network),
        )
        .await
        {
            Ok(result) => result.ok().and_then(earliest_of),
            Err(_) => {
                on_progress(&format!(
                    "Secondary endpoint {endpoint} timed out for birthday cross-check (skipping)."
                ));
                None
            }
        };
        earliest = combine_earliest(earliest, observed);
    }
    earliest
}

/// Connect to a secondary endpoint and check it serves `network`, or say
/// why it is being skipped. A wrong-chain endpoint must not influence a
/// birthday (audit Issue C follow-up review).
async fn connect_validated_secondary(
    endpoint: &str,
    network: ZeckNetwork,
) -> Result<CompactTxStreamerClient<Channel>, String> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(SECONDARY_PROBE_TIMEOUT_SECS),
        CompactTxStreamerClient::connect(endpoint.to_owned()),
    )
    .await
    {
        Ok(Ok(mut client)) => {
            let network_ok = match tokio::time::timeout(
                std::time::Duration::from_secs(SECONDARY_PROBE_TIMEOUT_SECS),
                client.get_lightd_info(Empty {}),
            )
            .await
            {
                Ok(Ok(info)) => validate_lightwalletd_network(network, &info.into_inner()).is_ok(),
                Ok(Err(_)) | Err(_) => false,
            };
            if network_ok {
                Ok(client)
            } else {
                Err(format!(
                    "Secondary endpoint {endpoint} failed network validation for birthday cross-check (skipping)."
                ))
            }
        }
        Ok(Err(err)) => Err(format!(
            "Secondary endpoint {endpoint} unreachable for birthday cross-check (skipping): {err}"
        )),
        Err(_) => Err(format!(
            "Secondary endpoint {endpoint} timed out connecting for birthday cross-check (skipping)."
        )),
    }
}

fn date_of_unix_time(unix_time: i64) -> String {
    CalendarDate::from_days_since_unix_epoch(unix_time.div_euclid(DAY_SECONDS)).format()
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
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
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

    crate::private_fs::cleanup_stale_ephemeral_probes(&std::env::temp_dir()).map_err(|err| {
        ZeckError::Storage(format!(
            "finishing an authenticated stale birthday probe cleanup: {err}"
        ))
    })?;

    on_progress("Connecting to lightwalletd…");
    let (mut client, primary_endpoint, chain_info) =
        probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
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
        .await?;

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
        let mut client = match connect_validated_secondary(endpoint, network).await {
            Ok(client) => client,
            Err(notice) => {
                on_progress(&notice);
                continue;
            }
        };
        let observed = match tokio::time::timeout(
            std::time::Duration::from_secs(SECONDARY_PROBE_TIMEOUT_SECS),
            probe_transparent(&mut client, seed_phrase, network),
        )
        .await
        {
            Ok(result) => result.ok().flatten(),
            Err(_) => {
                on_progress(&format!(
                    "Secondary endpoint {endpoint} timed out for birthday cross-check (skipping)."
                ));
                None
            }
        };
        if let Some(h) = observed {
            if earliest.is_none_or(|e| h < e) {
                on_progress(&format!(
                    "Endpoint {endpoint} reported earlier transparent activity at block {h}; lowering birthday."
                ));
            }
        }
        earliest = combine_earliest(earliest, observed);
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

#[derive(Debug)]
struct ProbeWorkspaceAuthority {
    private_root: std::path::PathBuf,
    root: std::path::PathBuf,
    database: std::path::PathBuf,
}

/// RAII guard that retires a probe's private authority before removing its
/// temporary directory.
///
/// The probe workspace imports a viewing key into a throwaway `wallet.sqlite`.
/// Cleanup pins and removes the exact private root, durably syncs that removal,
/// and only then retires its per-probe Windows authority. The outer UUID
/// container is removed only after the secret-bearing root is gone.
struct ProbeDirGuard {
    path: std::path::PathBuf,
    workspace: Option<ProbeWorkspaceAuthority>,
    registration: Option<crate::private_fs::EphemeralProbeRegistration>,
    authority_retired: bool,
    cleaned: bool,
}

impl ProbeDirGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            workspace: None,
            registration: None,
            authority_retired: false,
            cleaned: false,
        }
    }

    fn arm(&mut self, workspace: &RecoveryWorkspace) {
        self.workspace = Some(ProbeWorkspaceAuthority {
            private_root: workspace.private_root().to_owned(),
            root: workspace.root().to_owned(),
            database: workspace.wallet_db_path().to_owned(),
        });
    }

    fn register(&mut self, registration: crate::private_fs::EphemeralProbeRegistration) {
        self.registration = Some(registration);
    }

    fn cleanup(&mut self) -> std::io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        if !self.authority_retired {
            if let Some(workspace) = self.workspace.as_ref() {
                let registration = self.registration.take().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "ephemeral probe cleanup has no live registration",
                    )
                })?;
                crate::private_fs::begin_ephemeral_probe_cleanup(
                    registration,
                    &workspace.private_root,
                    &workspace.root,
                    &workspace.database,
                )?
                .remove_exact_private_root_and_retire()?;
            }
            self.authority_retired = true;
        }

        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for ProbeDirGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Create a temporary workspace at `probe_height`, import account-0, run a
/// time-limited compact-block sync (≤`PROBE_TIMEOUT_SECS` seconds), then check
/// whether any notes were written to the wallet DB.  A `ProbeDirGuard` removes
/// the temporary directory on every exit path (success, error, or unwind).
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
    // Guard ensures the probe directory (and its viewing-key-bearing wallet DB)
    // is removed on every exit path, not just the success path below.
    let mut probe_dir_guard = ProbeDirGuard::new(probe_dir.clone());
    let effective_height = probe_height.max(sapling_floor.saturating_add(1));

    let probe_config = RuntimeScanConfig {
        key_source: Arc::new(SeedKeySource::new(SecretString::new(
            seed_phrase.expose_secret().to_owned(),
        ))),
        birthday: effective_height,
        num_accounts: Some(1),
        gap_limit: 1,
        transparent_scan: None,
        lightwalletd_url: lightwalletd_url.to_owned(),
        confirmation_sources: Vec::new(),
        data_dir: probe_dir.clone(),
        network,
        label: String::new(),
    };

    let workspace = RecoveryWorkspace::from_runtime(&probe_config)?;
    probe_dir_guard.arm(&workspace);
    let registration = match crate::private_fs::prepare_ephemeral_probe_workspace(
        workspace.private_root(),
        workspace.root(),
        workspace.wallet_db_path(),
    ) {
        Ok(registration) => registration,
        Err(err) => {
            let primary = ZeckError::Storage(format!(
                "preparing authenticated birthday probe workspace {}: {err}",
                workspace.root().display()
            ));
            return finish_probe_cleanup(Err(primary), &mut probe_dir_guard, &probe_dir);
        }
    };
    probe_dir_guard.register(registration);
    let probe_result = async {
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

        import_probe_account(
            &workspace,
            network,
            seed,
            &account_birthday,
            transparent_account,
        )?;

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

        check_probe_activity(workspace.wallet_db_path())
    }
    .await;
    drop(workspace);
    finish_probe_cleanup(probe_result, &mut probe_dir_guard, &probe_dir)
}

fn finish_probe_cleanup<T>(
    probe_result: ZeckResult<T>,
    guard: &mut ProbeDirGuard,
    probe_dir: &std::path::Path,
) -> ZeckResult<T> {
    match guard.cleanup() {
        Ok(()) => probe_result,
        Err(cleanup_error) => {
            let primary = match probe_result {
                Ok(_) => String::new(),
                Err(error) => format!("probe failed first: {error}; "),
            };
            Err(ZeckError::Storage(format!(
                "{primary}retiring birthday probe workspace {} also failed: {cleanup_error}; authenticated stale cleanup will retry before the next probe",
                probe_dir.display()
            )))
        }
    }
}

fn check_probe_activity(wallet_db_path: &std::path::Path) -> ZeckResult<bool> {
    let conn =
        crate::workspace::open_wallet_connection_read_only(wallet_db_path).map_err(|err| {
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

    fn armed_probe_guard(container: &std::path::Path) -> (ProbeDirGuard, std::path::PathBuf) {
        let probe_dir = container.join(format!("zeck_probe_{}", Uuid::new_v4()));
        crate::private_fs::create_private_dir_all(&probe_dir).unwrap();
        let private_root = probe_dir.join("mainnet/workspace-test");
        let root = private_root.join("birthday-1/auto-gap-1");
        let database = root.join("wallet.sqlite");
        let registration =
            crate::private_fs::prepare_ephemeral_probe_workspace(&private_root, &root, &database)
                .unwrap();
        let mut guard = ProbeDirGuard::new(probe_dir.clone());
        guard.workspace = Some(ProbeWorkspaceAuthority {
            private_root,
            root,
            database,
        });
        guard.registration = Some(registration);
        (guard, probe_dir)
    }

    #[test]
    fn unarmed_probe_guard_removes_private_container() {
        let container = tempfile::tempdir().unwrap();
        let probe_dir = container
            .path()
            .join(format!("zeck_probe_{}", Uuid::new_v4()));
        crate::private_fs::create_private_dir_all(&probe_dir).unwrap();

        drop(ProbeDirGuard::new(probe_dir.clone()));

        assert!(!probe_dir.exists());
    }

    #[test]
    fn probe_activity_check_errors_are_not_treated_as_no_activity() {
        let container = tempfile::tempdir().unwrap();
        let missing = container.path().join("missing-wallet.sqlite");

        assert!(check_probe_activity(&missing).is_err());
    }

    #[test]
    fn probe_guard_retires_active_authority_before_removing_container() {
        let container = tempfile::tempdir().unwrap();
        let (mut guard, probe_dir) = armed_probe_guard(container.path());
        let private_root = guard.workspace.as_ref().unwrap().private_root.clone();

        guard.cleanup().unwrap();

        assert!(!private_root.exists());
        assert!(!probe_dir.exists());
        guard.cleanup().unwrap();
    }

    #[test]
    fn probe_guard_cleans_active_authority_during_unwind() {
        let container = tempfile::tempdir().unwrap();
        let probe_dir = std::cell::RefCell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (guard, path) = armed_probe_guard(container.path());
            *probe_dir.borrow_mut() = Some(path);
            let _guard = guard;
            panic!("exercise ephemeral probe cleanup during unwind");
        }));

        assert!(result.is_err());
        assert!(!probe_dir.borrow().as_ref().unwrap().exists());
    }

    #[test]
    fn authenticated_stale_probe_cleanup_recovers_crash_after_marker_before_secret() {
        let container = tempfile::tempdir().unwrap();
        let (mut guard, probe_dir) = armed_probe_guard(container.path());
        let private_root = guard.workspace.as_ref().unwrap().private_root.clone();
        drop(guard.registration.take());

        crate::private_fs::cleanup_stale_ephemeral_probes(container.path()).unwrap();

        assert!(!private_root.exists());
        guard.authority_retired = true;
        guard.cleanup().unwrap();
        assert!(!probe_dir.exists());
    }

    #[test]
    fn authenticated_stale_probe_cleanup_recovers_crash_after_secret_write() {
        let container = tempfile::tempdir().unwrap();
        let (mut guard, probe_dir) = armed_probe_guard(container.path());
        let workspace = guard.workspace.as_ref().unwrap();
        let private_root = workspace.private_root.clone();
        let database = workspace.database.clone();
        std::fs::write(&database, b"seed-derived probe state").unwrap();
        drop(guard.registration.take());

        crate::private_fs::cleanup_stale_ephemeral_probes(container.path()).unwrap();

        assert!(!database.exists());
        assert!(!private_root.exists());
        guard.authority_retired = true;
        guard.cleanup().unwrap();
        assert!(!probe_dir.exists());
    }

    #[test]
    fn stale_probe_scan_skips_registered_live_probe() {
        let container = tempfile::tempdir().unwrap();
        let (mut guard, _) = armed_probe_guard(container.path());
        let private_root = guard.workspace.as_ref().unwrap().private_root.clone();

        crate::private_fs::cleanup_stale_ephemeral_probes(container.path()).unwrap();

        assert!(private_root.exists());
        guard.cleanup().unwrap();
    }

    #[test]
    fn late_birthday_caution_warns_and_dates_on_mainnet() {
        let note =
            late_birthday_caution(SAPLING_ACTIVATION_HEIGHT + 1_000_000, ZeckNetwork::Mainnet);
        // Tells the user to rescan with an earlier birthday...
        assert!(note.contains("rescan"));
        assert!(note.contains("earlier"));
        // ...and anchors the detected height to an approximate calendar date.
        assert!(note.contains("around 20"));
    }

    #[test]
    fn combine_earliest_takes_minimum_and_never_raised_by_none() {
        use super::combine_earliest;
        assert_eq!(
            combine_earliest(Some(900_000), Some(500_000)),
            Some(500_000)
        );
        assert_eq!(
            combine_earliest(Some(500_000), Some(900_000)),
            Some(500_000)
        );
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
    fn nu7_birthday_spacing_follows_network_height_not_calendar_date() {
        for network in [ZeckNetwork::Mainnet, ZeckNetwork::Testnet] {
            let activation = crate::nu7::activation_height(network).unwrap();
            assert_eq!(birthday_block_seconds(network, activation - 1), 75);
            assert_eq!(birthday_block_seconds(network, activation), 25);
            assert_eq!(birthday_block_seconds(network, activation + 1), 25);
        }
        assert_eq!(birthday_block_seconds(ZeckNetwork::Mainnet, 500_000), 150);
        assert_eq!(birthday_block_seconds(ZeckNetwork::Mainnet, 1_000_000), 75);
    }

    #[test]
    fn nu7_height_date_segment_uses_twenty_five_seconds_and_preserves_history() {
        let activation = crate::nu7::activation_height(ZeckNetwork::Mainnet).unwrap();
        let day = |height| {
            CalendarDate::parse(&estimate_date_from_height_offline(height))
                .unwrap()
                .days_since_unix_epoch()
        };
        assert_eq!(day(activation) - day(activation - 1_152), 1);
        assert_eq!(day(activation + 3_456) - day(activation), 1);
        assert_eq!(day(activation + 6_912) - day(activation), 2);
        assert_eq!(estimate_date_from_height_offline(419_200), "2018-10-28");
        assert!(CalendarDate::parse(&estimate_date_from_height_offline(u32::MAX)).is_ok());
    }

    #[test]
    fn birthday_margin_keeps_a_week_at_nu7_without_changing_finality_thresholds() {
        for network in [ZeckNetwork::Mainnet, ZeckNetwork::Testnet] {
            let activation = crate::nu7::activation_height(network).unwrap();
            assert_eq!(date_safety_buffer_blocks(network, activation - 1), 8_064);
            assert_eq!(date_safety_buffer_blocks(network, activation), 24_192);
            assert_eq!(date_safety_buffer_blocks(network, activation + 1), 24_192);
        }
        assert_eq!(date_safety_buffer_blocks(ZeckNetwork::Mainnet, 1), 8_064);
        assert_eq!(birthday_block_seconds(ZeckNetwork::Testnet, 583_999), 150);
        assert_eq!(birthday_block_seconds(ZeckNetwork::Testnet, 584_000), 75);
    }

    #[test]
    fn recent_offline_dates_stay_below_the_observed_anchor_bound() {
        let activation = crate::nu7::activation_height(ZeckNetwork::Mainnet).unwrap();
        for height in [activation - 1, activation, activation + 3_456] {
            let date = estimate_date_from_height_offline(height);
            let timestamp =
                CalendarDate::parse(&date).unwrap().days_since_unix_epoch() * DAY_SECONDS;
            let conservative = height_at_or_before_time(ZeckNetwork::Mainnet, timestamp).unwrap();
            assert!(estimate_birthday_from_date_offline(&date).unwrap() <= conservative);
        }
    }

    #[test]
    fn offline_dates_never_guess_when_nu7_activated() {
        let activation = crate::nu7::activation_height(ZeckNetwork::Mainnet).unwrap();
        for date in ["2030-01-01", "9999-12-31", "2147483647-12-31"] {
            assert_eq!(
                estimate_birthday_from_date_offline(date).unwrap(),
                activation - 1
            );
        }
        // Testnet has no reliable calendar anchor; the pool floor is safe.
        assert_eq!(
            estimate_birthday_from_date_offline_for_network("2030-01-01", ZeckNetwork::Testnet)
                .unwrap(),
            280_000
        );
        assert!(
            estimate_birthday_from_date_offline_for_network("invalid", ZeckNetwork::Testnet)
                .is_err()
        );
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
            assert!(
                drift <= 1,
                "round-trip drift {drift} days for {date} -> {back}"
            );
        }
    }

    /// A wallet.dat birthday can now be below Sapling activation, and the
    /// date shown beside it must move with it rather than stick at 2018.
    #[test]
    fn pre_sapling_heights_get_pre_sapling_dates() {
        let one = estimate_date_from_height_offline(1);
        assert!(one.starts_with("2016-1"), "block 1 -> {one}");
        assert!(one.as_str() >= "2016-10-28", "never before genesis: {one}");
        let zero = estimate_date_from_height_offline(0);
        assert!(
            zero.starts_with("2016-10-") && zero.as_str() >= "2016-10-28",
            "{zero}"
        );
        // Block 200,000 was mined in late 2017.
        let mid = estimate_date_from_height_offline(200_000);
        assert!(mid.starts_with("2017-"), "block 200000 -> {mid}");
        let dates: Vec<String> = [1, 100_000, 300_000, 419_199, 419_200]
            .into_iter()
            .map(estimate_date_from_height_offline)
            .collect();
        assert!(dates.windows(2).all(|w| w[0] <= w[1]), "{dates:?}");
    }

    #[test]
    fn the_decrypt_plan_follows_the_skip_and_only_lowers_it() {
        let reason = "The Sprout scan will try to decrypt every block, because x.";
        // No skip: decrypt everything, whatever birthday is given, and say why.
        let plan = plan_sprout_decrypt(None, reason, Some(900_000), false);
        assert_eq!(plan.decrypt_from, None);
        assert_eq!(plan.line, reason);

        let plan = plan_sprout_decrypt(Some(500_000), reason, None, false);
        assert_eq!(plan.decrypt_from, Some(500_000));
        assert!(plan.line.contains("500000"), "{}", plan.line);
        assert!(plan.line.contains("creation times"), "{}", plan.line);

        // A later birthday never raises the bound above the file's.
        let plan = plan_sprout_decrypt(Some(500_000), reason, Some(900_000), false);
        assert_eq!(plan.decrypt_from, Some(500_000));

        // A lower one wins, and the line says it was the birthday.
        let plan = plan_sprout_decrypt(Some(500_000), reason, Some(300_000), false);
        assert_eq!(plan.decrypt_from, Some(300_000));
        assert!(plan.line.contains("300000"), "{}", plan.line);
        assert!(plan.line.contains("birthday"), "{}", plan.line);

        for floor in [0, 1] {
            let plan = plan_sprout_decrypt(Some(500_000), reason, Some(floor), false);
            assert_eq!(plan.decrypt_from, None, "birthday {floor}");
            assert!(plan.line.contains("every block"), "{}", plan.line);
        }

        // Turned off: nothing is skipped.
        let plan = plan_sprout_decrypt(Some(500_000), reason, None, true);
        assert_eq!(plan.decrypt_from, None);
        assert!(plan.line.contains("every block"), "{}", plan.line);
        assert!(plan.line.contains("turned off"), "{}", plan.line);
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
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2018, 10, 28), (2024, 12, 31)] {
            let cd = CalendarDate {
                year: y,
                month: m,
                day: d,
            };
            let back = CalendarDate::from_days_since_unix_epoch(cd.days_since_unix_epoch());
            assert_eq!(back, cd, "round trip failed for {y}-{m}-{d}");
        }
    }

    // ── wallet-file birthday ─────────────────────────────────────────────────

    use argos_wallet_import::keys::{Provenance, SaplingKey, SproutKey, TransparentKey};
    use secrecy::Secret;

    /// Mainnet blocks observed at the time of writing (block explorer,
    /// 2026-10-21): the anchors, blocks between them — the Sprout era before
    /// Canopy is where a skip can apply, and interpolation is only safe if
    /// the chain never fell behind a segment's average by more than the
    /// margin — and two past the last anchor, so the extrapolation is
    /// checked against real history too.
    const OBSERVED_MAINNET: [(u32, i64); 17] = [
        (1, 1_477_671_596),
        (20_000, 1_480_600_460),
        (100_000, 1_492_666_694),
        (200_000, 1_507_729_833),
        // Overwinter activation.
        (347_500, 1_529_977_051),
        (500_000, 1_552_955_406),
        (600_000, 1_568_024_995),
        (800_000, 1_587_134_100),
        (900_000, 1_594_669_980),
        (419_200, 1_540_779_337),
        (653_600, 1_576_101_005),
        (1_046_400, 1_605_702_856),
        (1_687_104, 1_654_019_405),
        (2_726_400, 1_732_359_779),
        (3_000_000, 1_752_983_473),
        (3_525_079, 1_792_551_157),
        // Before any anchor: genesis's own timestamp.
        (1, 1_477_641_360),
    ];

    #[test]
    fn observed_blocks_map_at_or_below_their_true_height() {
        for (height, time) in OBSERVED_MAINNET {
            let bound = height_at_or_before_time(ZeckNetwork::Mainnet, time).unwrap();
            assert!(
                bound <= height,
                "time {time}: bound {bound} > true {height}"
            );
            // Not so conservative as to be useless. The 77 s extrapolation
            // falls about 2.6% further behind each year past NU6 (about 29
            // days by late 2026) on top of the 28-day margin and the anchors'
            // extra day, so this allows 60 days.
            let sixty_days_of_blocks = 60 * DAY_SECONDS as u32 / 75;
            assert!(
                height.saturating_sub(bound) <= sixty_days_of_blocks,
                "time {time}: bound {bound} is far below {height}"
            );
        }
    }

    #[test]
    fn the_conversion_is_monotonic_and_never_below_one() {
        let mut last = 0;
        let mut time = UNKNOWN_CREATE_TIME_AT_OR_BEFORE - 30 * DAY_SECONDS;
        while time < 2_100_000_000 {
            let h = height_at_or_before_time(ZeckNetwork::Mainnet, time).unwrap();
            assert!(h >= 1);
            assert!(h >= last, "not monotonic at {time}: {h} < {last}");
            last = h;
            time += 3 * 3_600 + 17;
        }
        for time in [i64::MIN, -1, 0, 1, UNKNOWN_CREATE_TIME_AT_OR_BEFORE] {
            assert_eq!(
                height_at_or_before_time(ZeckNetwork::Mainnet, time),
                Some(1)
            );
        }
        assert!(height_at_or_before_time(ZeckNetwork::Mainnet, i64::MAX).is_some());
    }

    /// The two choices that keep the bound below the chain: a margin of at
    /// least four weeks, and an extrapolation slower than the 75 s target,
    /// because the chain has run about 0.5% slow since Blossom.
    ///
    /// Four weeks, not two (Kristi's #4 on #260): before Canopy the bound
    /// sat only about 15 days of blocks below the true height, so safety
    /// rested on the margin alone, and the anchor times come from an
    /// explorer with nothing sampled between the 17 observed points. Two more
    /// weeks of trial decryption is cheap next to a missed note.
    #[test]
    fn the_margin_and_extrapolation_err_early() {
        const { assert!(CREATION_TIME_MARGIN_SECS >= 28 * DAY_SECONDS) };
        const { assert!(EXTRAPOLATION_BLOCK_SECONDS > POST_BLOSSOM_BLOCK_SECONDS) };
        for (height, time) in MAINNET_HEIGHT_ANCHORS {
            let at_anchor = height_at_or_before_time(ZeckNetwork::Mainnet, time).unwrap();
            // Block 1 is the floor, so only later anchors can sit below.
            assert!(
                at_anchor < height || height == 1,
                "the margin must apply at anchor {height}"
            );
        }
    }

    #[test]
    fn testnet_times_are_refused() {
        assert_eq!(
            height_at_or_before_time(ZeckNetwork::Testnet, 1_700_000_000),
            None
        );
    }

    fn t_key(byte: u8, created_at: Option<i64>) -> TransparentKey {
        TransparentKey {
            secret: Secret::new([byte; 32]),
            provenance: Provenance::HdDerived,
            created_at,
        }
    }

    fn s_key(created_at: Option<i64>) -> SaplingKey {
        SaplingKey {
            extsk: Secret::new(vec![0x33; 169]),
            provenance: Provenance::HdDerived,
            created_at,
        }
    }

    fn z_key(byte: u8, created_at: Option<i64>) -> SproutKey {
        SproutKey {
            a_sk: Secret::new([byte; 32]),
            address: [byte; 64],
            provenance: Provenance::Standalone,
            created_at,
        }
    }

    const T_2017: i64 = 1_500_000_000; // 2017-07-14
    const T_2018: i64 = 1_530_000_000; // 2018-06-26
    const T_2019: i64 = 1_560_000_000; // 2019-06-08
    /// The clock every test runs at, fixed so no test depends on today.
    const NOW: i64 = 1_800_000_000; // 2027-01-15

    fn mainnet_bound(time: i64) -> u32 {
        height_at_or_before_time(ZeckNetwork::Mainnet, time).unwrap()
    }

    #[test]
    fn complete_metadata_gives_a_pre_sapling_birthday() {
        let keys = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018)), t_key(2, Some(T_2019))],
            sapling: vec![s_key(Some(T_2019))],
            sprout: vec![z_key(9, Some(T_2017))],
            ..ImportedKeys::default()
        };
        let b = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert_eq!(b.source, WalletBirthdaySource::WalletMetadata);
        assert_eq!(b.height, Some(mainnet_bound(T_2017)));
        assert!(
            b.height.unwrap() < SAPLING_ACTIVATION_HEIGHT,
            "no Sapling floor"
        );
        assert_eq!(b.keys_without_time, 0);
        assert_eq!(b.sprout_skip_height, Some(mainnet_bound(T_2017)));
        assert!(
            b.message.contains(&b.height.unwrap().to_string()),
            "{}",
            b.message
        );
    }

    /// One key of unknown age could be older than every dated one, so a
    /// birthday from the dated ones alone could be late.
    #[test]
    fn one_undated_key_means_no_metadata_birthday() {
        let keys = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018)), t_key(2, None)],
            sprout: vec![z_key(9, Some(T_2019))],
            ..ImportedKeys::default()
        };
        let b = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert_eq!(b.source, WalletBirthdaySource::None);
        assert_eq!(b.height, None);
        assert_eq!(b.keys_without_time, 1);
        assert!(b.message.contains("1 of 3"), "{}", b.message);
        // The Sprout skip depends on the Sprout keys only.
        assert_eq!(b.sprout_skip_height, Some(mainnet_bound(T_2019)));
    }

    /// The skip is about Sprout notes, so it comes from the Sprout keys'
    /// times only — an older transparent key does not lower it, and a
    /// younger one does not raise it.
    #[test]
    fn the_sprout_skip_uses_sprout_metadata_only() {
        let keys = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2017))],
            sapling: vec![s_key(Some(T_2017))],
            sprout: vec![z_key(8, Some(T_2019)), z_key(9, Some(T_2018))],
            ..ImportedKeys::default()
        };
        assert_eq!(
            sprout_skip_height(&keys, &[], ZeckNetwork::Mainnet, NOW),
            Some(mainnet_bound(T_2018))
        );
    }

    #[test]
    fn any_sprout_key_without_a_time_disables_the_skip() {
        let keys = ImportedKeys {
            sprout: vec![z_key(8, Some(T_2019)), z_key(9, None)],
            ..ImportedKeys::default()
        };
        assert_eq!(
            sprout_skip_height(&keys, &[], ZeckNetwork::Mainnet, NOW),
            None
        );
        let none = ImportedKeys::default();
        assert_eq!(
            sprout_skip_height(&none, &[], ZeckNetwork::Mainnet, NOW),
            None
        );
    }

    /// A key supplied alongside the file (`--sprout-key-file`, the GUI paste
    /// box) has no metadata of its own, so scanning it rules out any skip —
    /// unless it is one of the file's own dated keys.
    #[test]
    fn an_extra_sprout_key_from_outside_the_file_disables_the_skip() {
        let keys = ImportedKeys {
            sprout: vec![z_key(8, Some(T_2019))],
            ..ImportedKeys::default()
        };
        assert_eq!(
            sprout_skip_height(&keys, &[[0x77; 32]], ZeckNetwork::Mainnet, NOW),
            None
        );
        assert_eq!(
            sprout_skip_height(&keys, &[[8; 32]], ZeckNetwork::Mainnet, NOW),
            Some(mainnet_bound(T_2019))
        );
        // And with no file keys at all, only extras: nothing to date them by.
        assert_eq!(
            sprout_skip_height(
                &ImportedKeys::default(),
                &[[8; 32]],
                ZeckNetwork::Mainnet,
                NOW
            ),
            None
        );
        let b =
            wallet_file_birthday_from_metadata(&keys, &[[0x77; 32]], ZeckNetwork::Mainnet, 0, NOW);
        assert_eq!(b.sprout_skip_height, None);
        assert!(
            b.sprout_skip_reason.contains("no recorded creation time"),
            "{}",
            b.sprout_skip_reason
        );
    }

    #[test]
    fn testnet_wallets_get_neither_a_birthday_nor_a_skip() {
        let keys = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018))],
            sprout: vec![z_key(9, Some(T_2018))],
            ..ImportedKeys::default()
        };
        let b = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Testnet, 0, NOW);
        assert_eq!(b.source, WalletBirthdaySource::None);
        assert_eq!(b.height, None);
        assert_eq!(b.sprout_skip_height, None);
    }

    /// The chain fallback is the earliest *unspent* output: an upper bound
    /// on the keys' age. It fills the birthday only when the file could not,
    /// never lands above a dated key's own bound, has no Sapling floor, and
    /// never touches the Sprout skip.
    #[test]
    fn the_utxo_fallback_is_labelled_and_never_drives_the_skip() {
        let keys = ImportedKeys {
            transparent: vec![t_key(1, None), t_key(2, Some(T_2019))],
            sprout: vec![z_key(9, Some(T_2019))],
            ..ImportedKeys::default()
        };
        let offline = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Mainnet, 0, NOW);
        let skip = offline.sprout_skip_height;
        assert!(skip.is_some());

        let b = apply_utxo_fallback(
            offline.clone(),
            &keys,
            ZeckNetwork::Mainnet,
            Some(300_000),
            0,
            NOW,
        );
        assert_eq!(b.source, WalletBirthdaySource::TransparentUtxos);
        assert_eq!(b.height, Some(300_000 - BIRTHDAY_BUFFER_BLOCKS));
        assert_eq!(b.sprout_skip_height, skip);
        assert!(b.message.contains("upper bound"), "{}", b.message);

        // A dated key older than the output pulls the birthday down to it.
        let late = apply_utxo_fallback(
            offline.clone(),
            &keys,
            ZeckNetwork::Mainnet,
            Some(3_000_000),
            0,
            NOW,
        );
        assert_eq!(late.height, Some(mainnet_bound(T_2019)));

        // Clamped at block 1, not at Sapling activation.
        let early = apply_utxo_fallback(
            offline.clone(),
            &keys,
            ZeckNetwork::Mainnet,
            Some(5_000),
            0,
            NOW,
        );
        assert_eq!(early.height, Some(1));

        // Nothing found on chain: still no birthday.
        let none = apply_utxo_fallback(offline.clone(), &keys, ZeckNetwork::Mainnet, None, 0, NOW);
        assert_eq!(none.source, WalletBirthdaySource::None);
        assert_eq!(none.height, None);
    }

    /// A creation time later than this computer's clock cannot be a real
    /// birth: it comes from a machine whose clock was wrong. Trusted, it
    /// would push the Sprout skip past every real note. So it counts as
    /// undated, for the skip and for the birthday shown, while a time at
    /// exactly `now` is still accepted.
    #[test]
    fn a_creation_time_later_than_now_is_undated() {
        let future = NOW + 1;
        let keys = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018))],
            sprout: vec![z_key(8, Some(T_2019)), z_key(9, Some(future))],
            ..ImportedKeys::default()
        };
        assert_eq!(
            sprout_skip_height(&keys, &[], ZeckNetwork::Mainnet, NOW),
            None
        );
        let b = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert_eq!(b.sprout_skip_height, None);
        assert!(
            b.sprout_skip_reason
                .contains("later than this computer's clock"),
            "{}",
            b.sprout_skip_reason
        );
        assert_eq!(b.source, WalletBirthdaySource::None);
        assert_eq!(b.height, None);
        assert_eq!(b.keys_without_time, 1);
        assert!(
            b.message.contains("later than this computer's clock"),
            "{}",
            b.message
        );

        // The same file read with a clock past that time dates normally.
        let later = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Mainnet, 0, future);
        assert_eq!(later.source, WalletBirthdaySource::WalletMetadata);
        assert_eq!(later.sprout_skip_height, Some(mainnet_bound(T_2019)));

        // A future time never lowers or raises the chain fallback either:
        // only the honest dated key can pull it down.
        let only_future = ImportedKeys {
            transparent: vec![t_key(1, None), t_key(2, Some(future))],
            ..ImportedKeys::default()
        };
        let offline =
            wallet_file_birthday_from_metadata(&only_future, &[], ZeckNetwork::Mainnet, 0, NOW);
        let b = apply_utxo_fallback(
            offline,
            &only_future,
            ZeckNetwork::Mainnet,
            Some(3_000_000),
            0,
            NOW,
        );
        assert_eq!(b.height, Some(3_000_000 - BIRTHDAY_BUFFER_BLOCKS));
    }

    /// Keys supplied beside the file (a --sapling-key-file, the GUI paste
    /// box) carry no time. The message must say so in those words, not
    /// claim they are in the file or blame zcashd for them.
    #[test]
    fn the_message_names_where_undated_keys_came_from() {
        // File-only: one of the file's three keys is undated.
        let file_only = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018)), t_key(2, None)],
            sapling: vec![s_key(Some(T_2019))],
            ..ImportedKeys::default()
        };
        let b = wallet_file_birthday_from_metadata(&file_only, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert!(
            b.message.contains("1 of 3 keys in the wallet file"),
            "{}",
            b.message
        );
        assert!(b.message.contains("zcashd"), "{}", b.message);
        assert!(
            !b.message.contains("key file or paste box"),
            "{}",
            b.message
        );

        // Extra-only: every file key is dated; two keys were added.
        let extra_only = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018))],
            sapling: vec![s_key(Some(T_2019)), s_key(None), s_key(None)],
            ..ImportedKeys::default()
        };
        let b = wallet_file_birthday_from_metadata(&extra_only, &[], ZeckNetwork::Mainnet, 2, NOW);
        assert_eq!(b.source, WalletBirthdaySource::None);
        assert!(
            b.message
                .contains("2 key(s) added from a key file or paste box carry no creation time"),
            "{}",
            b.message
        );
        assert!(
            !b.message.contains("in the wallet file have"),
            "{}",
            b.message
        );
        assert!(!b.message.contains("zcashd"), "{}", b.message);
        let fallback =
            apply_utxo_fallback(b, &extra_only, ZeckNetwork::Mainnet, Some(300_000), 2, NOW);
        assert!(
            fallback.message.contains("key file or paste box"),
            "{}",
            fallback.message
        );
        assert!(
            !fallback.message.contains("of the wallet file's keys"),
            "{}",
            fallback.message
        );

        // Both: one of the file's two keys is undated, and one was added.
        let both = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2018)), t_key(2, None)],
            sapling: vec![s_key(None)],
            ..ImportedKeys::default()
        };
        let b = wallet_file_birthday_from_metadata(&both, &[], ZeckNetwork::Mainnet, 1, NOW);
        assert!(
            b.message.contains("1 of 2 keys in the wallet file"),
            "{}",
            b.message
        );
        assert!(
            b.message
                .contains("1 key(s) added from a key file or paste box"),
            "{}",
            b.message
        );
    }

    /// Kristi's #1 on #260. For imported keys the birthday drives only the
    /// Sapling scan (transparent funds are found by `GetAddressUtxos`
    /// whatever it says), so a transparent output must never decide where
    /// Sapling starts. An undated Sapling key — `z_importkey`'d into the
    /// file (zcashd stores time 1), or pasted beside it — could hold notes
    /// from any height after activation: no birthday, and no chain check.
    #[test]
    fn an_undated_sapling_key_blocks_the_utxo_fallback() {
        // From the file: an undated Sapling key beside a dated t-key whose
        // only unspent output is recent.
        let file = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2019)), t_key(2, None)],
            sapling: vec![s_key(None)],
            ..ImportedKeys::default()
        };
        // Pasted: every file key is dated; the Sapling key came from outside.
        let pasted = ImportedKeys {
            transparent: vec![t_key(1, None)],
            sapling: vec![s_key(Some(T_2019)), s_key(None)],
            ..ImportedKeys::default()
        };
        // A future time counts as undated too.
        let future = ImportedKeys {
            transparent: vec![t_key(1, None)],
            sapling: vec![s_key(Some(NOW + 1))],
            ..ImportedKeys::default()
        };
        for (name, keys, outside) in [
            ("file", &file, 0),
            ("pasted", &pasted, 1),
            ("future", &future, 0),
        ] {
            let offline =
                wallet_file_birthday_from_metadata(keys, &[], ZeckNetwork::Mainnet, outside, NOW);
            assert_eq!(offline.source, WalletBirthdaySource::None, "{name}");
            assert!(!needs_chain_fallback(&offline, keys, NOW), "{name}");
            let b = apply_utxo_fallback(
                offline.clone(),
                keys,
                ZeckNetwork::Mainnet,
                Some(2_500_000),
                outside,
                NOW,
            );
            assert_eq!(b.source, WalletBirthdaySource::None, "{name}");
            assert_eq!(b.height, None, "{name}");
            assert_eq!(b.sprout_skip_height, offline.sprout_skip_height, "{name}");
            assert!(
                b.message.contains("Sapling activation"),
                "{name}: {}",
                b.message
            );
        }

        // Every Sapling key dated, an undated t-key: the fallback still runs.
        let dated_sapling = ImportedKeys {
            transparent: vec![t_key(1, None)],
            sapling: vec![s_key(Some(T_2019))],
            ..ImportedKeys::default()
        };
        let offline =
            wallet_file_birthday_from_metadata(&dated_sapling, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert!(needs_chain_fallback(&offline, &dated_sapling, NOW));
        let b = apply_utxo_fallback(
            offline,
            &dated_sapling,
            ZeckNetwork::Mainnet,
            Some(3_000_000),
            0,
            NOW,
        );
        assert_eq!(b.source, WalletBirthdaySource::TransparentUtxos);
        assert_eq!(b.height, Some(mainnet_bound(T_2019)));
    }

    #[test]
    fn complete_metadata_is_not_overridden_by_the_chain() {
        let keys = ImportedKeys {
            transparent: vec![t_key(1, Some(T_2019))],
            ..ImportedKeys::default()
        };
        let offline = wallet_file_birthday_from_metadata(&keys, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert!(!needs_chain_fallback(&offline, &keys, NOW));
        let undated = ImportedKeys {
            transparent: vec![t_key(1, None)],
            ..ImportedKeys::default()
        };
        let offline =
            wallet_file_birthday_from_metadata(&undated, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert!(needs_chain_fallback(&offline, &undated, NOW));
        // No transparent keys: nothing to ask the chain about.
        let sapling_only = ImportedKeys {
            sapling: vec![s_key(None)],
            ..ImportedKeys::default()
        };
        let offline =
            wallet_file_birthday_from_metadata(&sapling_only, &[], ZeckNetwork::Mainnet, 0, NOW);
        assert!(!needs_chain_fallback(&offline, &sapling_only, NOW));
    }
}
