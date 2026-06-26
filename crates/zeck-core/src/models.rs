use std::path::PathBuf;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZeckNetwork {
    #[default]
    Mainnet,
    Testnet,
}

impl ZeckNetwork {
    pub fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 133,
            Self::Testnet => 1,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressScope {
    External,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub encoded: String,
    pub is_unified: bool,
    pub has_orchard: bool,
    pub has_sapling: bool,
    pub has_transparent: bool,
    pub destination_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedTransparentAddress {
    pub index: u32,
    pub scope: AddressScope,
    pub path: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedAccount {
    pub index: u32,
    pub sapling_path: String,
    pub orchard_path: String,
    pub transparent_receive_path: String,
    pub transparent_change_path: String,
    pub sapling_address: String,
    pub unified_address: String,
    pub transparent_receive_address: String,
    pub transparent_change_address: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeScanConfig {
    pub seed_phrase: SecretString,
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
    pub lightwalletd_url: String,
    pub data_dir: PathBuf,
    pub network: ZeckNetwork,
    /// User-facing label written to `session.json` so the launch-time
    /// "resume an unfinished scan" UI can identify this scan without the
    /// seed. Empty string is allowed and treated as "(unlabeled scan)".
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
    pub lightwalletd_url: String,
    pub data_dir: PathBuf,
    pub network: ZeckNetwork,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHandle {
    pub id: String,
}

impl ScanHandle {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for ScanHandle {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Idle,
    ValidatingSeed,
    DerivingKeys,
    ProbingLightwalletd,
    ScanningTransparent,
    ScanningShielded,
    Complete,
    Cancelled,
    Error,
}

impl ScanPhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled | Self::Error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBalancePreview {
    pub account_index: u32,
    pub sapling_address: String,
    pub unified_address: String,
    pub transparent_receive_address: String,
    pub transparent_change_address: String,
    pub transparent_utxo_count: u32,
    pub sapling_zatoshis: u64,
    pub orchard_zatoshis: u64,
    pub transparent_zatoshis: u64,
    pub total_zatoshis: u64,
    /// Whether this account has any historical note activity (received notes,
    /// including spent ones). Used instead of current balance for gap-limit
    /// decisions so that accounts that received and fully spent funds are still
    /// detected as active.
    pub has_activity: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LightwalletdProbe {
    pub endpoint: String,
    pub vendor: Option<String>,
    pub chain_name: Option<String>,
    pub latest_block_height: Option<u64>,
    pub sapling_activation_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_zatoshis: u64,
    pub authoritative_balances: bool,
    pub note: String,
    pub workspace_dir: String,
}

/// A funded position discovered on a derived account during scanning.
/// Emitted as soon as a refresh tick observes a new non-zero balance for an
/// (account, pool) pair, so users see "Found X ZEC on account N" without
/// waiting for the scan to complete. The list is append-only across the
/// scan; once a discovery is appended it stays put even if the balance
/// later drops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiscovery {
    pub account_index: u32,
    pub pool: DiscoveryPool,
    pub zatoshis: u64,
    /// Block height of the most recent refresh tick that produced this
    /// discovery — useful for "found at block 3,289,541" UX.
    pub at_block_height: u64,
    /// User-facing address for the pool: the unified address for orchard,
    /// the sapling z-addr for sapling, the transparent receive t-addr for
    /// transparent.
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryPool {
    Transparent,
    Sapling,
    Orchard,
}

impl DiscoveryPool {
    pub fn label(self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::Sapling => "sapling",
            Self::Orchard => "orchard",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub handle: ScanHandle,
    pub phase: ScanPhase,
    pub blocks_scanned: u64,
    pub blocks_total: u64,
    /// Absolute Zcash chain height the wallet workspace has scanned up to,
    /// or `None` before the first authoritative refresh. Use this (not
    /// `blocks_scanned`, which is a delta from `effective_birthday`) when
    /// mapping scan progress to calendar era or mined-block context.
    #[serde(default)]
    pub synced_to_height: Option<u64>,
    pub elapsed_seconds: Option<u64>,
    pub estimated_remaining_seconds: Option<u64>,
    pub accounts: Vec<AccountBalancePreview>,
    /// Append-only log of (account, pool) discoveries observed during the
    /// scan. Consumers render new entries as incremental "found X" toasts
    /// without waiting for the scan to finish.
    #[serde(default)]
    pub discoveries: Vec<ScanDiscovery>,
    pub summary: Option<ScanSummary>,
    pub server: Option<LightwalletdProbe>,
    pub message: Option<String>,
    pub error: Option<String>,
    /// Populated by the progress poller when it observes wall-clock jumps
    /// inconsistent with monotonic time — a strong signal the machine
    /// suspended. Sticky for the rest of the scan; updated in place when
    /// additional sleeps are detected so the UI can render "machine slept
    /// N times, total Xh lost".
    #[serde(default)]
    pub sleep_event: Option<SleepEvent>,
    /// True while the wallet sync cursor is inside the sandblasting era
    /// (mid-2022 → late 2023, mainnet only). Toggled per poll tick — the
    /// banner appears while traversing the slow zone and disappears once
    /// the cursor passes through.
    #[serde(default)]
    pub in_sandblasting_zone: bool,
}

/// Snapshot of all detected sleep gaps during the current scan. The poller
/// rewrites this struct in place each time it observes a new gap; consumers
/// render the latest values plus the running totals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleepEvent {
    /// Wall-clock at the last awake tick before the most recent sleep, as
    /// seconds since the Unix epoch. Frontends format to local time.
    pub slept_at_unix: u64,
    /// Wall-clock at the first post-sleep tick, seconds since the Unix epoch.
    pub resumed_at_unix: u64,
    /// Length of the most recent sleep gap, in seconds.
    pub last_sleep_seconds: u64,
    /// Sum of all detected sleep gaps so far this scan.
    pub total_lost_seconds: u64,
    /// Number of distinct sleeps observed.
    pub event_count: u32,
}

/// Mainnet block heights bracketing the sandblasting attack window.
///
/// Sources: Protos (mid-June 2022 onset), CoinDesk (zcashd 5.5.0 / ZIP 317
/// release on 2023-04-28 began mitigation), Electric Coin Company (declared
/// exit from emergency mode on 2023-11-01). Heights mapped via Blockchair.
///
/// The bounds are intentionally rounded to ~100k blocks. The attack was a
/// sustained traffic pattern, not a discrete event, and miner adoption of
/// ZIP 317 fees took months — so single-block precision would be misleading.
pub const SANDBLASTING_START_HEIGHT: u32 = 1_700_000;
/// 2023-11-01 was height 2,282,264; padded by ~7 days so wallets within a
/// week of the all-clear still see the banner — chain density doesn't drop
/// on the exact block.
pub const SANDBLASTING_END_HEIGHT: u32 = 2_290_000;

/// Whether the given mainnet height is inside the sandblasting attack
/// window. Returns `false` for testnet (the attack was mainnet-only).
pub fn in_sandblasting_zone(height: u32, network: ZeckNetwork) -> bool {
    matches!(network, ZeckNetwork::Mainnet)
        && (SANDBLASTING_START_HEIGHT..=SANDBLASTING_END_HEIGHT).contains(&height)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepRequest {
    pub destination: String,
    pub memo: Option<String>,
    /// Maximum total fee in zatoshis across all sweep transactions. If actual
    /// fees exceed this the sweep is aborted with `MaxFeeExceeded`. `None`
    /// means no limit — use only when the caller has already reviewed the
    /// proposal fee and explicitly accepted it.
    pub max_fee_zatoshis: Option<u64>,
    /// Fraction of each account's send amount to donate (e.g. 0.10). `None`
    /// skips the donation entirely. Validated to 0.0..1.0.
    #[serde(default)]
    pub donation_rate: Option<f64>,
    /// Optional email placed in the donation memo for an off-chain receipt.
    #[serde(default)]
    pub donor_email: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposedTxKind {
    ShieldTransparent,
    SweepShielded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedTx {
    pub kind: ProposedTxKind,
    pub source_account: u32,
    pub destination: String,
    pub gross_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub net_zatoshis: u64,
    /// Portion of `net_zatoshis` routed to the donation address (0 if none).
    #[serde(default)]
    pub donation_zatoshis: u64,
    pub note: String,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedSweepAccount {
    pub account_index: u32,
    pub gross_zatoshis: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepProposal {
    pub transactions: Vec<ProposedTx>,
    pub skipped_accounts: Vec<SkippedSweepAccount>,
    pub total_send_zatoshis: u64,
    pub total_fee_zatoshis: u64,
    pub net_received_zatoshis: u64,
    /// Sum of `donation_zatoshis` across all transactions.
    #[serde(default)]
    pub total_donation_zatoshis: u64,
    pub dry_run_default: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BirthdayDetectResult {
    pub birthday: u32,
    /// "transparent" | "shielded_probe" | "no_activity"
    pub method: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBroadcastResult {
    pub source_account: u32,
    pub txid: Option<String>,
    pub status: String,
    pub detail: String,
    pub confirmed_height: Option<u32>,
}

/// Outcome of an `execute_sweep`, reported even when the sweep aborts partway.
///
/// A multi-account sweep broadcasts transactions one account at a time. If a
/// later account fails after an earlier one has already been broadcast, the
/// earlier transactions are on-chain and irreversible. `transactions` always
/// lists every transaction that was broadcast — on full success and on a
/// partial abort alike — so the caller never loses the record of funds that
/// have already moved (audit Issue E).
///
/// `error` is `None` on full success and `Some(message)` when the sweep
/// aborted after broadcasting the transactions in `transactions`. A failure
/// *before any* transaction is broadcast is reported as an `Err` from
/// `execute_sweep` instead, so an empty `transactions` with `error: Some` is
/// never produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepOutcome {
    pub transactions: Vec<TxBroadcastResult>,
    /// Accounts that held a balance but moved nothing because every spendable
    /// note was below the ZIP-317 fee floor (only dust UTXOs, or funds outside
    /// the shieldable receivers). The sweep skipped them and continued with the
    /// other accounts rather than aborting; surfaced so a skip is visible to the
    /// user, mirroring the dry-run proposal's `skipped_accounts`.
    #[serde(default)]
    pub skipped_accounts: Vec<SkippedSweepAccount>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandblasting_zone_brackets_attack_window_on_mainnet() {
        assert!(!in_sandblasting_zone(SANDBLASTING_START_HEIGHT - 1, ZeckNetwork::Mainnet));
        assert!(in_sandblasting_zone(SANDBLASTING_START_HEIGHT, ZeckNetwork::Mainnet));
        assert!(in_sandblasting_zone(2_000_000, ZeckNetwork::Mainnet));
        assert!(in_sandblasting_zone(SANDBLASTING_END_HEIGHT, ZeckNetwork::Mainnet));
        assert!(!in_sandblasting_zone(SANDBLASTING_END_HEIGHT + 1, ZeckNetwork::Mainnet));
    }

    #[test]
    fn sandblasting_zone_is_mainnet_only() {
        // Testnet had no comparable spam attack — banner must not surface
        // for testnet sweeps even though heights overlap.
        assert!(!in_sandblasting_zone(2_000_000, ZeckNetwork::Testnet));
    }
}
