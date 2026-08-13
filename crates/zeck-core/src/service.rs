use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Instant};

use secrecy::SecretString;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Duration,
};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions,
            input_selection::{GreedyInputSelector, LockedInputPolicy, SpendPolicy},
            propose_send_max_transfer, propose_shielding, propose_transfer, ConfirmationsPolicy,
            SpendingKeys,
        },
        CoinbaseFilter, MaxSpendMode, TransactionStatus, WalletRead, WalletWrite,
    },
    fees::{standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule},
    proto::service::{
        compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction, TxFilter,
    },
    wallet::OvkPolicy,
};
// The crate re-export is deprecated in favor of the standalone `zip321` crate,
// but that crate is not a direct dependency; the re-export resolves to the
// identical `zip321` 0.7.0 already in the dependency tree. If the re-export is
// removed upstream, or if zip321 is needed in more than this one site, add
// `zip321` as a direct dependency — currently reused transitively to avoid
// growing the dependency tree.
#[allow(deprecated)]
use zcash_client_backend::zip321;
use zcash_client_sqlite::{util::SystemClock, AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::{
    fees::zip317::{MARGINAL_FEE, MINIMUM_FEE},
    TxId,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis, ShieldedPool};

use crate::{
    address::validate_destination_address,
    derivation::{legacy_transparent_account_key_from_seed, legacy_transparent_secret_key},
    error::{ZeckError, ZeckResult},
    key_source::{KeySource, SeedKeySource},
    lightwalletd::{
        connect_lightwalletd_endpoints_with_retry, validate_lightwalletd_network,
        validated_lightwalletd_endpoints,
    },
    models::{
        ProposedTx, ProposedTxKind, RuntimeScanConfig, ScanConfig, ScanHandle, ScanPhase,
        ScanProgress, SkippedSweepAccount, SweepOutcome, SweepProposal, SweepRequest,
        TxBroadcastResult,
    },
    scan::{
        refresh_scan_progress, run_recovery_scan, run_wallet_sync_with_retry, ScanTaskState,
        SharedScanTaskState, TrackedAccount,
    },
    workspace::{consensus_network, open_wallet_db, RecoveryWorkspace},
};

const RECOVERY_MEMO_DEFAULT: &str = "Argos recovery";
const SESSION_RETENTION_SECS: u64 = 300;
/// After a shielding tx is broadcast, how long to wait for it to mine so its
/// shielded note becomes spendable by the following send-max. zcash_client_backend
/// forbids spending transparent funds straight to an external address, so a
/// shield→sweep is necessarily two transactions and the second can't build on an
/// unconfirmed/unmined note — without this wait the send-max finds nothing and
/// strands the just-shielded funds. ~10 min covers several mainnet blocks.
#[cfg(not(feature = "argos-network"))]
const SHIELD_CONFIRM_TIMEOUT_SECS: u64 = 600;
/// Short timeout under the regtest harness (which doesn't auto-mine) so a
/// shield→sweep test fails fast instead of hanging for the production timeout.
#[cfg(feature = "argos-network")]
const SHIELD_CONFIRM_TIMEOUT_SECS: u64 = 30;
/// Delay between re-sync polls while waiting for the shield to confirm.
const SHIELD_CONFIRM_POLL_SECS: u64 = 10;
/// Maximum iterations for the donation-split fee-convergence loop. The extra
/// donation output adds at most one ZIP-317 marginal action, so convergence is
/// expected within 2 iterations; 4 leaves headroom.
const MAX_FEE_CONVERGENCE_ITERS: usize = 8;

/// ZIP-317 conventional fee floor in zatoshis: `marginal_fee (5000) *
/// grace_actions (2)`. A shielded send can never cost less than this, so it is
/// a safe lower bound to reserve for the send-max step that always follows a
/// shielding step in the per-account sweep. Reserving it lets a foreseeable
/// `MaxFeeExceeded` abort *before* the shielding transaction is broadcast,
/// rather than after it is already mined and its fee unrecoverable (audit
/// Issue E).
const MIN_SHIELDED_SEND_FEE_ZATOSHIS: u64 = 10_000;

/// Whether a balance is worth sweeping: it must *strictly exceed* the ZIP-317
/// fee floor. At or below the floor, the shielding/sweep transaction's fee would
/// consume the entire balance, so building it fails ("Insufficient funds:
/// required 10000 zatoshis, but only 0 were available").
///
/// `build_sweep_proposal` (the dry run) already skips such accounts; this is the
/// same predicate, used to gate the shielding and send-max steps in
/// `execute_sweep_for_session` so execution applies the identical dust-skip and
/// never hard-fails the whole sweep on an account the dry run quietly skipped.
fn balance_covers_sweep_fee(zatoshis: u64) -> bool {
    zatoshis > MIN_SHIELDED_SEND_FEE_ZATOSHIS
}

/// Whether a proposal-build error reflects "insufficient funds" — the input
/// selector found no spendable value that clears the ZIP-317 fee floor.
///
/// `balance_covers_sweep_fee` gates on an account's *summed* balance, but a
/// proposal can still come up empty: the value may be many sub-threshold dust
/// UTXOs the selector won't pick, or transparent funds at addresses outside the
/// two shieldable receivers. Such an account is simply unsweepable, so the
/// sweep must *skip* it (and continue with the other accounts) instead of
/// aborting the whole multi-account sweep on a `?`. Matched on the error text
/// because the underlying `zcash_client_backend` proposal error is a deep
/// generic type with no stable typed variant to match here; a false match only
/// downgrades a fatal abort to a skip (recorded), never the reverse.
pub(crate) fn is_insufficient_funds_error(message: &str) -> bool {
    message.to_ascii_lowercase().contains("insufficient funds")
}

/// The donation recipient used during sweep *execution* on a given network.
///
/// Mainnet uses the baked-in [`crate::donation::DONATION_ADDRESS`]; testnet
/// disables the donation feature (empty string). Under the dev/test-only
/// `argos-network` feature ONLY, the testnet branch honors
/// `ARGOS_TEST_DONATION_ADDRESS` so the regtest harness can drive the
/// donation-split path end-to-end with a regtest UA (the baked mainnet address
/// can't be used on regtest). Production builds compile that override out — same
/// rationale as the rest of the `argos-network` escape hatch — so testnet
/// donation stays off in released binaries.
fn execution_donation_address(network: crate::models::ZeckNetwork) -> String {
    match network {
        crate::models::ZeckNetwork::Mainnet => crate::donation::DONATION_ADDRESS.to_owned(),
        crate::models::ZeckNetwork::Testnet => {
            #[cfg(feature = "argos-network")]
            {
                std::env::var("ARGOS_TEST_DONATION_ADDRESS").unwrap_or_default()
            }
            #[cfg(not(feature = "argos-network"))]
            {
                String::new()
            }
        }
    }
}

/// The concrete wallet database type used throughout the execution path.
type SweepWalletDb =
    WalletDb<rusqlite::Connection, crate::workspace::ArgosParams, SystemClock, rand_core::OsRng>;
const CONFIRMATION_POLL_INTERVAL_SECS: u64 = 5;
const CONFIRMATION_POLL_ATTEMPTS: u32 = 24;
const SECONDARY_CONFIRMATION_TIMEOUT_SECS: u64 = 5;

struct ScanSession {
    state: SharedScanTaskState,
    runtime: RuntimeScanConfig,
    started_at: Instant,
    task: Mutex<Option<JoinHandle<()>>>,
    workspace_root: std::path::PathBuf,
}

type SharedScanSession = Arc<ScanSession>;

#[derive(Clone, Default)]
pub struct RecoveryService {
    sessions: Arc<RwLock<HashMap<String, SharedScanSession>>>,
}

impl RecoveryService {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start_scan(
        &self,
        config: ScanConfig,
        seed_phrase: SecretString,
    ) -> ZeckResult<ScanHandle> {
        self.start_scan_from_key_source(config, Arc::new(SeedKeySource::new(seed_phrase)))
            .await
    }

    /// Start a scan from any key source — a seed phrase, or keys read out
    /// of a legacy wallet file.
    pub async fn start_scan_from_key_source(
        &self,
        config: ScanConfig,
        key_source: Arc<dyn KeySource>,
    ) -> ZeckResult<ScanHandle> {
        validate_scan_config(&config)?;

        let handle = ScanHandle::new();
        let state = Arc::new(tokio::sync::Mutex::new(ScanTaskState::new(handle.clone())));
        let runtime = RuntimeScanConfig {
            key_source,
            birthday: config.birthday,
            num_accounts: config.num_accounts,
            gap_limit: config.gap_limit,
            lightwalletd_url: config.lightwalletd_url,
            data_dir: config.data_dir,
            network: config.network,
            label: config.label,
        };

        let workspace_root = RecoveryWorkspace::from_runtime(&runtime)?.root().to_owned();

        // Cancel any existing session targeting the same workspace to prevent
        // concurrent SQLite writers from locking each other out.
        let conflicting: Vec<ScanHandle> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, session)| session.workspace_root == workspace_root)
                .map(|(id, _)| ScanHandle { id: id.clone() })
                .collect()
        };
        for conflicting_handle in conflicting {
            let _ = self.cancel_scan(&conflicting_handle).await;
        }

        let session = Arc::new(ScanSession {
            state: state.clone(),
            runtime: runtime.clone(),
            started_at: Instant::now(),
            task: Mutex::new(None),
            workspace_root,
        });

        self.sessions
            .write()
            .await
            .insert(handle.id.clone(), session.clone());

        let sessions = self.sessions.clone();
        let handle_id = handle.id.clone();
        let task = tokio::spawn(async move {
            // Acquire a power-management guard so the OS doesn't put the
            // machine to sleep mid-scan. Held for the entire scan task; the
            // Drop impl releases on completion, error, panic, or task abort.
            // Soft-fail: if the guard can't be acquired we still scan, the
            // user just has to keep the machine awake themselves.
            let _awake = match keepawake::Builder::default()
                .idle(true)
                .sleep(true)
                .reason("Argos recovery scan")
                .app_name("Argos")
                .app_reverse_domain("org.argos.app")
                .create()
            {
                Ok(guard) => Some(guard),
                Err(err) => {
                    tracing::warn!(
                        "keepawake guard unavailable; scan may pause if the machine sleeps: {err}"
                    );
                    None
                }
            };
            run_recovery_scan(state.clone(), runtime).await;
            drop(_awake);
            // Keep completed sessions alive so the user can proceed to sweep
            // at their own pace. Only clean up cancelled/error sessions after
            // a short delay so they don't accumulate.
            let phase = state.lock().await.progress.phase;
            if phase != ScanPhase::Complete {
                spawn_session_cleanup(sessions, handle_id);
            }
        });
        *session.task.lock().await = Some(task);

        Ok(handle)
    }

    pub async fn get_scan_progress(&self, handle: &ScanHandle) -> ZeckResult<ScanProgress> {
        let session = self.session(handle).await?;
        let mut progress = session.state.lock().await.progress.clone();
        let session_elapsed = session.started_at.elapsed().as_secs();
        // Use scan-phase elapsed (set by ProgressPoller from when scanning began) for
        // the rate calculation so pre-scan phases don't dilute the blocks/sec estimate.
        let scan_elapsed = progress.elapsed_seconds.unwrap_or(session_elapsed);
        progress.elapsed_seconds = Some(session_elapsed);
        progress.estimated_remaining_seconds = estimate_remaining_seconds(&progress, scan_elapsed);
        Ok(progress)
    }

    pub async fn cancel_scan(&self, handle: &ScanHandle) -> ZeckResult<()> {
        let session = self.session(handle).await?;

        {
            let state = session.state.lock().await;
            // Never cancel an already-complete scan: the phase would flip to
            // Cancelled and any still-alive pump loop would emit scan-complete
            // with Cancelled, corrupting the UI for the user's sweep workflow.
            if state.progress.phase == ScanPhase::Complete {
                return Ok(());
            }
            state
                .cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        {
            let mut state = session.state.lock().await;
            state.progress.phase = ScanPhase::Cancelled;
            state.progress.message = Some("Recovery scan cancelled.".to_owned());
        }
        if let Some(task) = session.task.lock().await.take() {
            task.abort();
        }
        // spawn_session_cleanup is intentionally omitted here: aborting the
        // task prevents the scan from completing naturally, so the cleanup
        // that was scheduled in start_scan will not fire.  We schedule a
        // fresh one to ensure the session is eventually removed.
        if self.sessions.read().await.contains_key(&handle.id) {
            spawn_session_cleanup(self.sessions.clone(), handle.id.clone());
        }
        Ok(())
    }

    pub async fn propose_sweep(
        &self,
        handle: &ScanHandle,
        request: SweepRequest,
    ) -> ZeckResult<SweepProposal> {
        let session = self.session(handle).await?;
        let progress = session.state.lock().await.progress.clone();
        if progress.phase != ScanPhase::Complete {
            return Err(ZeckError::ScanNotReady(format!(
                "current phase is {:?}",
                progress.phase
            )));
        }

        // Confirm the workspace this proposal describes is still there and
        // still readable, before quoting a number derived from it.
        //
        // The balances below come from the in-memory scan state, not from
        // disk, so without this check a deleted or permission-stripped
        // workspace produces a confident, fully-priced proposal — and the
        // proposal's own warning tells the user it came from the persisted
        // wallet. Executing it would then fail, after the user has already
        // been shown an amount. For a recovery tool a confidently wrong
        // balance is a worse failure than a clean error.
        //
        // `from_runtime` only computes paths; it creates nothing. But opening
        // the database is not enough on its own: `open_wallet_db` uses
        // `Connection::open`, which recreates an empty `wallet.sqlite` when the
        // file has been deleted but its directory survives — masking the very
        // loss this guards against. So require a readable wallet summary too; a
        // missing or freshly-recreated database yields `None` here and fails
        // loudly, matching what the execute path already demands.
        let workspace = RecoveryWorkspace::from_runtime(&session.runtime)?;
        let wallet_db = open_wallet_db(
            workspace.wallet_db_path(),
            consensus_network(session.runtime.network),
        )
        .map_err(|err| {
            ZeckError::Wallet(format!(
                "the recovery workspace backing this scan is no longer readable, so its \
                 balances cannot be trusted: {err}"
            ))
        })?;
        wallet_db
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .map_err(|err| {
                ZeckError::Wallet(format!(
                    "the recovery workspace backing this scan is no longer readable, so its \
                     balances cannot be trusted: {err}"
                ))
            })?
            .ok_or_else(|| {
                ZeckError::Wallet(
                    "the recovery workspace backing this scan no longer contains a wallet, \
                     so its balances cannot be trusted"
                        .to_owned(),
                )
            })?;

        build_sweep_proposal(
            &progress,
            request,
            session.runtime.network,
            crate::donation::DONATION_ADDRESS,
        )
    }

    pub async fn execute_sweep(
        &self,
        handle: &ScanHandle,
        request: SweepRequest,
    ) -> ZeckResult<SweepOutcome> {
        self.execute_sweep_inner(handle, request, None).await
    }

    /// Test-only sweep entrypoint that inserts a fixed pause between
    /// per-account broadcasts. Exists so R-S29 (`argos-sweep-helper`) can
    /// SIGKILL the subprocess deterministically in the gap between two
    /// broadcasts; production builds compile this method out so the
    /// pause-duration field is unreachable from any released binary.
    #[cfg(feature = "argos-network")]
    pub async fn execute_sweep_with_test_pause(
        &self,
        handle: &ScanHandle,
        request: SweepRequest,
        pause_between_broadcasts: std::time::Duration,
    ) -> ZeckResult<SweepOutcome> {
        self.execute_sweep_inner(handle, request, Some(pause_between_broadcasts))
            .await
    }

    async fn execute_sweep_inner(
        &self,
        handle: &ScanHandle,
        request: SweepRequest,
        pause_between_broadcasts: Option<std::time::Duration>,
    ) -> ZeckResult<SweepOutcome> {
        let session = self.session(handle).await?;
        let progress = session.state.lock().await.progress.clone();
        if progress.phase != ScanPhase::Complete {
            return Err(ZeckError::ScanNotReady(format!(
                "current phase is {:?}",
                progress.phase
            )));
        }

        // An imported wallet with no HD seed cannot go through the sweep
        // below, which derives a UnifiedSpendingKey per account. Route it
        // here rather than in a front-end so the CLI and the GUI cannot
        // diverge on which key sources are spendable — the branch belongs
        // wherever `execute_sweep` is the shared surface.
        if session.runtime.key_source.wallet_seed()?.is_none() {
            if let Some(keys) = session.runtime.key_source.imported_keys() {
                return sweep_imported_session(&session.runtime, keys, &request).await;
            }
        }

        let _ = build_sweep_proposal(
            &progress,
            request.clone(),
            session.runtime.network,
            crate::donation::DONATION_ADDRESS,
        )?;
        execute_sweep_for_session(session, request, pause_between_broadcasts).await
    }

    /// Recursively delete the on-disk recovery workspace for a completed scan
    /// and drop the session. Used by the GUI's post-recovery "Delete workspace"
    /// action (threat-model T-L3).
    ///
    /// Returns the path that was deleted. Refuses to act on an in-flight scan
    /// — call `cancel_scan` first if the user truly wants to discard mid-run.
    ///
    /// Caveat: on modern SSDs `remove_dir_all` is not a cryptographic wipe;
    /// the filesystem and SSD controller may retain blocks until the cells
    /// are overwritten or TRIM'd. UI callers should surface this honestly.
    pub async fn delete_workspace(&self, handle: &ScanHandle) -> ZeckResult<std::path::PathBuf> {
        let session = self.session(handle).await?;

        // Refuse mid-scan to avoid tearing the SQLite write-ahead state out
        // from under the running task. Callers can cancel first if they really
        // mean it.
        {
            let state = session.state.lock().await;
            let phase = state.progress.phase;
            if !matches!(
                phase,
                ScanPhase::Complete | ScanPhase::Cancelled | ScanPhase::Error
            ) {
                return Err(ZeckError::ScanNotReady(format!(
                    "cannot delete workspace while scan is {phase:?}; cancel first",
                )));
            }
        }

        // Drop any lingering task handle so the SQLite files aren't held open.
        if let Some(task) = session.task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }

        let workspace_root = session.workspace_root.clone();

        // Remove the session from the registry before touching disk so a
        // concurrent caller cannot operate on the now-doomed workspace.
        self.sessions.write().await.remove(&handle.id);

        if workspace_root.exists() {
            std::fs::remove_dir_all(&workspace_root).map_err(|err| {
                ZeckError::Storage(format!(
                    "deleting workspace {}: {err}",
                    workspace_root.display()
                ))
            })?;
        }

        Ok(workspace_root)
    }

    async fn session(&self, handle: &ScanHandle) -> ZeckResult<SharedScanSession> {
        self.sessions
            .read()
            .await
            .get(&handle.id)
            .cloned()
            .ok_or(ZeckError::UnknownScanHandle)
    }
}

fn validate_scan_config(config: &ScanConfig) -> ZeckResult<()> {
    if config.gap_limit == 0 {
        return Err(ZeckError::InvalidConfig(
            "gap limit must be at least 1".to_owned(),
        ));
    }
    if config.gap_limit > 500 {
        return Err(ZeckError::InvalidConfig(
            "gap limit must not exceed 500".to_owned(),
        ));
    }
    if matches!(config.num_accounts, Some(0)) {
        return Err(ZeckError::InvalidConfig(
            "num_accounts must be at least 1".to_owned(),
        ));
    }
    if let Some(num_accounts) = config.num_accounts {
        if num_accounts > 500 {
            return Err(ZeckError::InvalidConfig(
                "num_accounts must not exceed 500".to_owned(),
            ));
        }
    }
    validated_lightwalletd_endpoints(&config.lightwalletd_url)?;

    Ok(())
}

fn spawn_session_cleanup(
    sessions: Arc<RwLock<HashMap<String, SharedScanSession>>>,
    handle_id: String,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(SESSION_RETENTION_SECS)).await;
        sessions.write().await.remove(&handle_id);
    });
}

fn build_sweep_proposal(
    progress: &ScanProgress,
    request: SweepRequest,
    network: crate::models::ZeckNetwork,
    donation_address: &str,
) -> ZeckResult<SweepProposal> {
    let destination = validate_destination_address(&request.destination, network)?;
    let memo = normalized_memo_text(request.memo.as_deref())?;
    let minimum_fee_zatoshis = u64::from(MINIMUM_FEE);

    // Testnet forces the donation feature off.
    let effective_donation_address = if matches!(network, crate::models::ZeckNetwork::Testnet) {
        ""
    } else {
        donation_address
    };

    crate::donation::validate_donation_rate(request.donation_rate)?;
    crate::donation::validate_donor_email(request.donor_email.as_deref())?;

    let mut transactions = Vec::new();
    let mut skipped_accounts = Vec::new();
    let mut total_fee_zatoshis = 0u64;
    let mut total_send_zatoshis = 0u64;
    let mut net_received_zatoshis = 0u64;
    let mut total_donation_zatoshis = 0u64;

    for account in progress
        .accounts
        .iter()
        .filter(|account| account.total_zatoshis > 0)
    {
        let shielded_existing = account
            .sapling_zatoshis
            .checked_add(account.orchard_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("shielded balance overflowed the supported range".to_owned())
            })?;
        let mut shielded_available = shielded_existing;

        if account.transparent_zatoshis > 0 {
            if account.transparent_zatoshis <= minimum_fee_zatoshis {
                skipped_accounts.push(SkippedSweepAccount {
                    account_index: account.account_index,
                    gross_zatoshis: account.transparent_zatoshis,
                    reason: format!(
                        "Transparent balance is too small to cover the ZIP 317 shielding fee floor of {minimum_fee_zatoshis} zats."
                    ),
                });
            } else {
                let shielding_fee_zatoshis = minimum_fee_zatoshis;
                let shielded_after_step_one = account.transparent_zatoshis - shielding_fee_zatoshis;
                shielded_available = shielded_available
                    .checked_add(shielded_after_step_one)
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "sweep proposal overflowed the supported range".to_owned(),
                        )
                    })?;
                total_send_zatoshis = total_send_zatoshis
                    .checked_add(account.transparent_zatoshis)
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "sweep proposal overflowed the supported range".to_owned(),
                        )
                    })?;
                total_fee_zatoshis = total_fee_zatoshis
                    .checked_add(shielding_fee_zatoshis)
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "sweep proposal overflowed the supported range".to_owned(),
                        )
                    })?;

                transactions.push(ProposedTx {
                    kind: ProposedTxKind::ShieldTransparent,
                    source_account: account.account_index,
                    destination: account.unified_address.clone(),
                    gross_zatoshis: account.transparent_zatoshis,
                    fee_zatoshis: shielding_fee_zatoshis,
                    net_zatoshis: shielded_after_step_one,
                    donation_zatoshis: 0,
                    note: format!(
                        "Estimated shielding step for {} transparent UTXOs before the external sweep.",
                        account.transparent_utxo_count
                    ),
                    memo: None,
                });
            }
        }

        if shielded_available == 0 {
            continue;
        }
        if shielded_available <= minimum_fee_zatoshis {
            skipped_accounts.push(SkippedSweepAccount {
                account_index: account.account_index,
                gross_zatoshis: shielded_available,
                reason: format!(
                    "Shielded balance is too small to cover the ZIP 317 sweep fee floor of {minimum_fee_zatoshis} zats."
                ),
            });
            continue;
        }

        let sweep_fee_zatoshis = minimum_fee_zatoshis;
        let net_received_for_account = shielded_available - sweep_fee_zatoshis;
        total_send_zatoshis = total_send_zatoshis
            .checked_add(shielded_available)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;
        total_fee_zatoshis = total_fee_zatoshis
            .checked_add(sweep_fee_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;
        net_received_zatoshis = net_received_zatoshis
            .checked_add(net_received_for_account)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;

        let donation_zatoshis = crate::donation::donation_for_send_amount(
            effective_donation_address,
            request.donation_rate,
            net_received_for_account,
        );
        total_donation_zatoshis = total_donation_zatoshis
            .checked_add(donation_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;

        transactions.push(ProposedTx {
            kind: ProposedTxKind::SweepShielded,
            source_account: account.account_index,
            destination: destination.encoded.clone(),
            gross_zatoshis: shielded_available,
            fee_zatoshis: sweep_fee_zatoshis,
            net_zatoshis: net_received_for_account,
            donation_zatoshis,
            note: if shielded_existing > 0 && account.transparent_zatoshis > 0 {
                "Estimated external recovery sweep after shielding the transparent portion and combining it with existing shielded funds."
                    .to_owned()
            } else if shielded_existing > 0 {
                "Estimated external recovery sweep for shielded funds already tracked in this account."
                    .to_owned()
            } else {
                "Estimated external recovery sweep after shielding completes.".to_owned()
            },
            memo: Some(memo.clone()),
        });
    }

    if let Some(max_fee_zatoshis) = request.max_fee_zatoshis {
        if total_fee_zatoshis > max_fee_zatoshis {
            return Err(ZeckError::MaxFeeExceeded(format!(
                "estimated fee {total_fee_zatoshis} zats exceeds limit {max_fee_zatoshis} zats"
            )));
        }
    }

    let warning = if net_received_zatoshis > 0 {
        "This dry-run proposal uses the balances from the completed scan, checked against the recovery workspace on disk. Argos estimates any required shielding first, then a final sweep to the destination Unified Address."
            .to_owned()
    } else if !skipped_accounts.is_empty() {
        "Balances were detected, but every discovered account was skipped because the ZIP 317 fee floor would consume the recoverable value."
            .to_owned()
    } else {
        "No spendable balances were found in the completed scan.".to_owned()
    };

    Ok(SweepProposal {
        transactions,
        skipped_accounts,
        total_send_zatoshis,
        total_fee_zatoshis,
        net_received_zatoshis,
        total_donation_zatoshis,
        dry_run_default: true,
        warning: Some(warning),
    })
}

async fn execute_sweep_for_session(
    session: SharedScanSession,
    request: SweepRequest,
    // Test-only knob threaded through from `execute_sweep_with_test_pause`.
    // Production callers pass None and the per-account loop runs at full
    // speed. Threaded as `Option<Duration>` rather than gated behind cfg so
    // the function signature stays stable across feature configurations.
    pause_between_broadcasts: Option<std::time::Duration>,
) -> ZeckResult<SweepOutcome> {
    let destination = validate_destination_address(&request.destination, session.runtime.network)?;
    let memo_text = normalized_memo_text(request.memo.as_deref())?;
    let memo_bytes = Some(
        MemoBytes::from_bytes(memo_text.as_bytes())
            .map_err(|err| ZeckError::InvalidMemo(err.to_string()))?,
    );

    crate::donation::validate_donation_rate(request.donation_rate)?;
    crate::donation::validate_donor_email(request.donor_email.as_deref())?;

    let (runtime, workspace, tracked_accounts, progress) = {
        let guard = session.state.lock().await;
        let workspace = guard
            .workspace
            .clone()
            .ok_or_else(|| ZeckError::ScanNotReady("wallet workspace is unavailable".to_owned()))?;
        (
            session.runtime.clone(),
            workspace,
            guard.tracked_accounts.clone(),
            guard.progress.clone(),
        )
    };

    // A scan cannot have reached this point without a seed — `run_recovery_scan_inner`
    // rejects a seedless key source before it derives anything — so this is a
    // consistency check rather than a user-facing path.
    let seed = runtime.key_source.wallet_seed()?.ok_or_else(|| {
        ZeckError::InvalidConfig(format!(
            "cannot sweep {}: standalone keys with no HD seed are not yet spendable",
            runtime.key_source.describe()
        ))
    })?;
    let transparent_account = legacy_transparent_account_key_from_seed(runtime.network, &seed)?;
    let network = consensus_network(runtime.network);
    let destination_address =
        ZcashAddress::try_from_encoded(&destination.encoded).map_err(|err| {
            ZeckError::InvalidAddress(format!(
                "failed to decode destination Unified Address: {err}"
            ))
        })?;
    let prover = LocalTxProver::bundled();
    let mut total_fee_zatoshis = 0u64;
    // Sum of the donation outputs actually broadcast (0 when a per-account
    // donation was below the floor or its split fell back). Reported on the
    // outcome so the completion screen shows the true donated total rather than
    // the proposal's estimate.
    let mut total_donation_zatoshis = 0u64;
    let mut results = Vec::new();
    // Accounts that held a balance but moved nothing (all spendable value below
    // the ZIP-317 fee floor). Collected so the completion screen can show the
    // skip instead of it being silent.
    let mut skipped_accounts: Vec<SkippedSweepAccount> = Vec::new();

    // Testnet kill-switch: forces the donation feature off (except under the
    // dev/test-only `argos-network` feature; see `execution_donation_address`).
    let effective_donation_address = execution_donation_address(runtime.network);
    let donation_memo = Some(
        MemoBytes::from_bytes(
            crate::donation::donation_memo_body(request.donor_email.as_deref()).as_bytes(),
        )
        .map_err(|err| ZeckError::InvalidMemo(err.to_string()))?,
    );

    let preferred_endpoint = progress
        .server
        .as_ref()
        .map(|server| server.endpoint.as_str());
    let (mut client, primary_endpoint) =
        connect_lightwalletd_endpoints_with_retry(&runtime.lightwalletd_url, preferred_endpoint)
            .await?;
    let lightwalletd_info = client
        .get_lightd_info(zcash_client_backend::proto::service::Empty {})
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    validate_lightwalletd_network(runtime.network, &lightwalletd_info)?;

    run_wallet_sync_with_retry(
        &workspace,
        &network,
        runtime.network,
        &mut client,
        &runtime.lightwalletd_url,
        &session.state,
    )
    .await?;
    refresh_scan_progress(
        &session.state,
        &workspace,
        runtime.network,
        runtime.birthday.min(chain_tip_height(&mut client).await?),
    )
    .await?;

    // The per-account loop broadcasts transactions one account at a time. Run
    // it inside a block whose `?` failures are *caught* rather than propagated,
    // so a mid-sequence abort still surfaces the records of every transaction
    // already broadcast (audit Issue E) instead of discarding `results`.
    let sweep_result: ZeckResult<()> = async {
        for tracked_account in tracked_accounts {
            let account_total = account_total_zatoshis(
                &workspace,
                runtime.network,
                tracked_account.wallet_account_id,
            )?;
            if account_total == 0 {
                continue;
            }
            // Set once a shielding tx is broadcast for this account, so a later
            // skip path doesn't mislabel an account that already moved funds.
            let mut account_shielded = false;
            // Set when an account HAS transparent funds above the fee floor but
            // `propose_shielding` couldn't select any (unconfirmed / unsupported
            // address), so the skip reason reflects "couldn't shield real funds"
            // rather than the misleading "balance too small".
            let mut transparent_unshieldable = false;

            let zip32_index =
                zip32::AccountId::try_from(tracked_account.derived.index).map_err(|_| {
                    ZeckError::InvalidConfig(format!(
                        "account index {} is out of range",
                        tracked_account.derived.index
                    ))
                })?;
            let usk = UnifiedSpendingKey::from_seed(&network, &seed, zip32_index)
                .map_err(|err| {
                    ZeckError::Wallet(format!(
                        "deriving account {}: {err}",
                        tracked_account.derived.index
                    ))
                })?;

            let transparent_balance =
                account_transparent_zatoshis(&workspace, runtime.network, &tracked_account)?;
            // Only shield a transparent balance that exceeds the fee floor; a
            // sub-floor (dust) balance can't cover the shielding fee and would
            // hard-fail `propose_shielding`. The dry-run proposal skips it, so
            // execution must too (otherwise the whole sweep aborts). The dust is
            // left unshielded, exactly as the proposal excludes it.
            if balance_covers_sweep_fee(transparent_balance) {
                let shielded_fee = {
                    let mut ctx = SweepStepCtx {
                        workspace: &workspace,
                        network: runtime.network,
                        client: &mut client,
                        prover: &prover,
                        results: &mut results,
                        prior_fee_zatoshis: total_fee_zatoshis,
                        max_fee_zatoshis: request.max_fee_zatoshis,
                        donation_address: effective_donation_address.as_str(),
                        donation_rate: request.donation_rate,
                        donation_memo: donation_memo.clone(),
                        lightwalletd_url: runtime.lightwalletd_url.as_str(),
                        primary_endpoint: primary_endpoint.as_str(),
                    };
                    execute_shielding_step(&mut ctx, &tracked_account, &transparent_account, &usk)
                        .await?
                };
                // `None` => the account's transparent balance isn't shieldable
                // (only dust UTXOs, or funds outside the two receivers); leave it
                // unshielded and fall through to sweep any existing shielded
                // balance instead of aborting the whole sweep.
                if let Some(fee) = shielded_fee {
                    account_shielded = true;
                    // Step already enforced the cap against (prior + step fee)
                    // before broadcast; recompute here purely to advance the
                    // running total for the next step.
                    total_fee_zatoshis = checked_fee_total(total_fee_zatoshis, fee)?;

                    // The shield was just broadcast (pending in the mempool). It
                    // MUST mine before the send-max can spend the resulting
                    // shielded note — zcash_client_backend won't send transparent
                    // funds straight to an external address, so this is two txs
                    // and the second can't build on an unconfirmed note. Skip a
                    // shield that outright failed; otherwise wait for it to
                    // confirm. A timeout leaves the funds shielded (re-running
                    // the sweep picks them up) and moves on without aborting.
                    if last_account_broadcast_failed(&results, tracked_account.derived.index) {
                        continue;
                    }
                    let shielded_before = shielded_spendable_zatoshis(
                        &workspace,
                        runtime.network,
                        &tracked_account,
                    )?;
                    if !wait_for_shielded_funds_to_confirm(
                        &workspace,
                        &network,
                        runtime.network,
                        &mut client,
                        &runtime.lightwalletd_url,
                        &session.state,
                        &tracked_account,
                        shielded_before,
                    )
                    .await?
                    {
                        continue;
                    }
                    refresh_scan_progress(
                        &session.state,
                        &workspace,
                        runtime.network,
                        runtime.birthday.min(chain_tip_height(&mut client).await?),
                    )
                    .await?;
                } else {
                    // Shielding returned None: the account has transparent funds
                    // above the fee floor that propose_shielding couldn't select.
                    transparent_unshieldable = true;
                }
            }

            // The shielded balance must cover the send-max fee, or the transfer
            // proposal fails the same way. Re-query the (post-shield) spendable
            // shielded balance — total minus any unshielded remainder — and skip
            // the account if it is at or below the fee floor, matching the dry
            // run's shielded-dust skip.
            let shielded_spendable =
                shielded_spendable_zatoshis(&workspace, runtime.network, &tracked_account)?;
            if !balance_covers_sweep_fee(shielded_spendable) {
                if !account_shielded {
                    let reason = if transparent_unshieldable {
                        "Transparent funds could not be swept: no spendable UTXOs were available to \
                         shield (they may be unconfirmed, or held at an address Argos cannot spend \
                         from). Check the address on a block explorer and retry once it has \
                         confirmations."
                            .to_owned()
                    } else {
                        format!(
                            "Balance is too small to cover the ZIP 317 sweep fee floor of {MIN_SHIELDED_SEND_FEE_ZATOSHIS} zats."
                        )
                    };
                    skipped_accounts.push(SkippedSweepAccount {
                        account_index: tracked_account.derived.index,
                        gross_zatoshis: account_total,
                        reason,
                    });
                }
                continue;
            }

            let send_max_fee = {
                let mut ctx = SweepStepCtx {
                    workspace: &workspace,
                    network: runtime.network,
                    client: &mut client,
                    prover: &prover,
                    results: &mut results,
                    prior_fee_zatoshis: total_fee_zatoshis,
                    max_fee_zatoshis: request.max_fee_zatoshis,
                    donation_address: effective_donation_address.as_str(),
                    donation_rate: request.donation_rate,
                    donation_memo: donation_memo.clone(),
                    lightwalletd_url: runtime.lightwalletd_url.as_str(),
                    primary_endpoint: primary_endpoint.as_str(),
                };
                execute_send_max_step(
                    &mut ctx,
                    &tracked_account,
                    &usk,
                    &destination_address,
                    memo_bytes.clone(),
                )
                .await?
            };
            // `None` => no selectable shielded value for this account; skip it
            // rather than aborting the whole sweep.
            let Some((fee, account_donation)) = send_max_fee else {
                if !account_shielded {
                    skipped_accounts.push(SkippedSweepAccount {
                        account_index: tracked_account.derived.index,
                        gross_zatoshis: account_total,
                        reason: format!(
                            "No spendable balance cleared the ZIP 317 fee floor of {MIN_SHIELDED_SEND_FEE_ZATOSHIS} zats."
                        ),
                    });
                }
                continue;
            };
            // Step already enforced the cap against (prior + step fee) before broadcast;
            // recompute here purely to advance the running total for the next account.
            total_fee_zatoshis = checked_fee_total(total_fee_zatoshis, fee)?;
            total_donation_zatoshis =
                total_donation_zatoshis.checked_add(account_donation).ok_or_else(|| {
                    ZeckError::Internal("donation total overflowed the supported range".to_owned())
                })?;

            // R-S29 hook: pause between per-account broadcasts so the test parent
            // can SIGKILL the helper subprocess deterministically in the gap. The
            // pause is unconditional; in production this is always None.
            if let Some(d) = pause_between_broadcasts {
                tokio::time::sleep(d).await;
            }
        }
        Ok(())
    }
    .await;

    assemble_sweep_outcome(
        results,
        skipped_accounts,
        total_donation_zatoshis,
        sweep_result,
    )
}

/// Fold the accumulated broadcast records and the loop's terminal status into a
/// [`SweepOutcome`].
///
/// - Full success (`Ok(())`) → `Ok` with no error.
/// - Aborted *after* broadcasting at least one transaction → `Ok` carrying the
///   partial records plus the error message, so the caller never loses the
///   record of funds already on-chain (audit Issue E).
/// - Aborted *before* any broadcast (empty `results`) → propagate the `Err`, so
///   "no transaction was sent" remains a faithful report.
///
/// `skipped_accounts` records accounts that held a balance but moved nothing
/// (every spendable note below the ZIP-317 fee floor); it rides along on the
/// `Ok` outcomes so the UI can surface the skip.
fn assemble_sweep_outcome(
    results: Vec<TxBroadcastResult>,
    skipped_accounts: Vec<SkippedSweepAccount>,
    total_donation_zatoshis: u64,
    sweep_result: ZeckResult<()>,
) -> ZeckResult<SweepOutcome> {
    match sweep_result {
        Ok(()) => Ok(SweepOutcome {
            transactions: results,
            skipped_accounts,
            total_donation_zatoshis,
            error: None,
        }),
        Err(err) => {
            if results.is_empty() {
                Err(err)
            } else {
                Ok(SweepOutcome {
                    transactions: results,
                    skipped_accounts,
                    total_donation_zatoshis,
                    error: Some(err.to_string()),
                })
            }
        }
    }
}

struct SweepStepCtx<'a> {
    workspace: &'a RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    client: &'a mut CompactTxStreamerClient<tonic::transport::Channel>,
    prover: &'a LocalTxProver,
    results: &'a mut Vec<TxBroadcastResult>,
    prior_fee_zatoshis: u64,
    max_fee_zatoshis: Option<u64>,
    donation_address: &'a str,
    donation_rate: Option<f64>,
    donation_memo: Option<MemoBytes>,
    // For the best-effort confirmation cross-check (audit Issue B follow-up):
    // the full configured endpoint list and the endpoint this sweep is using,
    // so a second distinct endpoint can be picked to verify confirmations.
    lightwalletd_url: &'a str,
    primary_endpoint: &'a str,
}

/// The change strategy used for every Argos proposal: ZIP-317 fees, no change
/// memo, Orchard as the fallback change pool, default dust handling. Extracted
/// so the shielding step and the donation-split step cannot drift apart.
fn standard_zip317_change_strategy<I>() -> SingleOutputChangeStrategy<I> {
    SingleOutputChangeStrategy::<I>::new(
        StandardFeeRule::Zip317,
        None,
        // Fallback change pool only. From Ironwood (NU6.3) activation the turnstile
        // forbids value entering the Orchard pool, and the change strategy coerces this
        // fallback to Ironwood for those transactions; below activation it still means
        // Orchard, as before.
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    )
}

async fn execute_shielding_step(
    ctx: &mut SweepStepCtx<'_>,
    tracked_account: &TrackedAccount,
    transparent_account: &zcash_transparent::keys::AccountPrivKey,
    usk: &UnifiedSpendingKey,
) -> ZeckResult<Option<u64>> {
    let mut wallet_db = open_wallet_db(
        ctx.workspace.wallet_db_path(),
        consensus_network(ctx.network),
    )?;
    let input_selector = GreedyInputSelector::<_>::new();
    let change_strategy = standard_zip317_change_strategy();

    let proposal = match propose_shielding::<_, _, _, _, Infallible>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        &input_selector,
        &change_strategy,
        Zatoshis::ZERO,
        &tracked_account.transparent_receivers,
        tracked_account.wallet_account_id,
        ConfirmationsPolicy::MIN,
        CoinbaseFilter::AllTransparentOutputs,
        // Argos is a single-process recovery tool with no concurrent proposals, so it
        // takes no advisory input locks.
        None,
    ) {
        Ok(proposal) => proposal,
        Err(err) => {
            let message = format!("building shielding proposal: {err}");
            if is_insufficient_funds_error(&message) {
                // No selectable transparent UTXOs (unconfirmed at the required
                // confirmations, dust, or held outside the two shieldable
                // receivers). Leave this account's transparent unshielded and let
                // the caller fall through to sweep any existing shielded balance.
                // Logged because the account's summary balance can read non-zero
                // while the proposal selects nothing — a recovery shortfall worth
                // seeing (the error carries the available/required amounts).
                tracing::warn!(
                    "account {}: transparent funds not shieldable — {message}",
                    tracked_account.derived.index,
                );
                return Ok(None);
            }
            return Err(ZeckError::TransactionBuild(message));
        }
    };
    let fee_zatoshis = proposal_fee_zatoshis(&proposal)?;
    let fee_through_shield = checked_fee_total(ctx.prior_fee_zatoshis, fee_zatoshis)?;
    enforce_max_fee(fee_through_shield, ctx.max_fee_zatoshis)?;
    // A shielding step is always followed by a send-max step for the same
    // account. Reserve the ZIP-317 minimum for that step so a foreseeable
    // `MaxFeeExceeded` aborts here, before this shielding transaction is
    // broadcast — otherwise the shield can be mined and its fee stranded only
    // for the subsequent send-max to blow the cap (audit Issue E).
    enforce_max_fee(
        checked_fee_total(fee_through_shield, MIN_SHIELDED_SEND_FEE_ZATOSHIS)?,
        ctx.max_fee_zatoshis,
    )?;

    let mut standalone_keys = HashMap::new();
    standalone_keys.insert(
        tracked_account.transparent_receivers[0],
        vec![legacy_transparent_secret_key(
            transparent_account,
            crate::models::AddressScope::External,
            tracked_account.derived.index,
        )?],
    );
    standalone_keys.insert(
        tracked_account.transparent_receivers[1],
        vec![legacy_transparent_secret_key(
            transparent_account,
            crate::models::AddressScope::Internal,
            tracked_account.derived.index,
        )?],
    );
    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        ctx.prover,
        ctx.prover,
        &SpendingKeys::new(usk.clone(), standalone_keys),
        OvkPolicy::Sender,
        &proposal,
        // No explicit expiry override; keep the library's default expiry.
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating shielding transaction: {err}")))?;

    broadcast_transactions(
        &mut wallet_db,
        ctx.client,
        tracked_account.derived.index,
        txids.into_iter().collect(),
        "shielding",
        ctx.results,
        ctx.lightwalletd_url,
        ctx.primary_endpoint,
        ctx.network,
    )
    .await?;

    Ok(Some(fee_zatoshis))
}

/// Build a two-output proposal that splits the full account balance between a
/// donation output and the user's destination, converging on the ZIP-317 fee so
/// that no change output remains.
///
/// Returns `Some(proposal)` once the candidate fee matches the proposal's
/// computed fee, or `None` if convergence (or a positive user remainder) could
/// not be achieved — in which case the caller falls back to the donation-free
/// Reduce a donation-split build result to a concrete `Proposal`, falling
/// back to the donation-free `max_proposal` on both `Ok(None)` (the
/// helper's intentional fallback signal) and `Err(_)` (any unexpected
/// failure constructing the split). Logged on `Err` so a regression is
/// observable in production logs rather than silent.
///
/// Extracted from the inline match in `execute_send_max_step` so the
/// three-way branch is unit-testable without a wallet DB.
fn donation_proposal_or_fallback<P>(
    split_result: ZeckResult<Option<P>>,
    max_proposal: P,
    donation: u64,
    account_index: u32,
) -> (P, u64) {
    match split_result {
        // Split built: the donation output carries `donation` zatoshis.
        Ok(Some(proposal)) => (proposal, donation),
        // Fell back to the donation-free sweep: nothing was actually donated.
        Ok(None) => (max_proposal, 0),
        Err(err) => {
            tracing::warn!(
                "donation split proposal failed for account {account_index}: {err}; \
                 falling back to donation-free sweep for this account",
            );
            (max_proposal, 0)
        }
    }
}

/// send-max sweep. This is a pure extraction of the inline two-pass logic; the
/// checked arithmetic, convergence loop, and fallback semantics are unchanged.
#[allow(clippy::too_many_arguments)]
fn build_donation_split_proposal(
    wallet_db: &mut SweepWalletDb,
    network: crate::models::ZeckNetwork,
    account_id: AccountUuid,
    destination_address: &ZcashAddress,
    memo_bytes: Option<MemoBytes>,
    donation_zcash_address: &ZcashAddress,
    donation_memo: Option<MemoBytes>,
    send_amount: u64,
    send_max_fee: u64,
    donation: u64,
) -> ZeckResult<Option<zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>>> {
    let total_spendable = send_amount.checked_add(send_max_fee).ok_or_else(|| {
        ZeckError::Internal("send amount plus fee overflowed the supported range".to_owned())
    })?;
    // Iterative fee convergence: two fixed payments summing to
    // (total_spendable - fee) drive change to zero once the candidate fee
    // matches the proposal's computed fee. Seed from the send-max fee PLUS one
    // ZIP-317 marginal action: the extra donation output costs exactly that, so
    // iteration 1 already has enough fee budget and `propose_transfer` doesn't
    // fail with insufficient funds before the loop can adjust. (Seeding from the
    // bare single-output send-max fee under-budgets the donation output and was
    // the bug that made every donation silently fall back to a donation-free
    // sweep.)
    let mut candidate_fee = send_max_fee.saturating_add(u64::from(MARGINAL_FEE));
    for _ in 0..MAX_FEE_CONVERGENCE_ITERS {
        let remainder = total_spendable
            .checked_sub(donation)
            .and_then(|v| v.checked_sub(candidate_fee));
        let remainder = match remainder {
            Some(r) if r > 0 => r,
            _ => break,
        };
        let request = zip321::TransactionRequest::new(vec![
            zip321::Payment::new(
                donation_zcash_address.clone(),
                Some(Zatoshis::from_u64(donation).map_err(|err| {
                    ZeckError::TransactionBuild(format!("donation amount out of range: {err}"))
                })?),
                donation_memo.clone(),
                None,
                None,
                vec![],
            )
            .map_err(|err| {
                ZeckError::TransactionBuild(format!("invalid donation payment: {err}"))
            })?,
            zip321::Payment::new(
                destination_address.clone(),
                Some(Zatoshis::from_u64(remainder).map_err(|err| {
                    ZeckError::TransactionBuild(format!("destination amount out of range: {err}"))
                })?),
                memo_bytes.clone(),
                None,
                None,
                vec![],
            )
            .map_err(|err| {
                ZeckError::TransactionBuild(format!(
                    "invalid destination payment in donation split: {err}"
                ))
            })?,
        ])
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("building donation transfer request: {err}"))
        })?;
        let input_selector = GreedyInputSelector::<_>::new();
        let change_strategy = standard_zip317_change_strategy();
        match propose_transfer::<_, _, _, _, Infallible>(
            wallet_db,
            &consensus_network(network),
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            // This split runs after shielding, so it spends shielded value only —
            // matching the pre-0.24 behaviour, where `propose_transfer` had no policy
            // argument and drew on the shielded pools alone. Ironwood is included for
            // the same reason it is in the sweep proposal: post-NU6.3 value can live
            // there.
            &SpendPolicy::shielded_pools([
                ShieldedPool::Sapling,
                ShieldedPool::Orchard,
                ShieldedPool::Ironwood,
            ]),
            // No advisory input locks; no transaction-version override, so the library
            // selects the version required at the target height (V6 from Ironwood
            // activation onward).
            None,
            None,
        ) {
            Ok(proposal) => {
                let fee = proposal_fee_zatoshis(&proposal)?;
                if fee == candidate_fee {
                    return Ok(Some(proposal));
                }
                candidate_fee = fee;
            }
            // The seed candidate fee is the *single-output* send-max fee, which
            // under-budgets the extra donation output — so the first proposal
            // fails with "insufficient funds" before the fee can converge. Raise
            // the candidate by one ZIP-317 marginal action and retry rather than
            // aborting the donation. THIS is the bug that made the donation split
            // silently fall back to a donation-free sweep on every sweep; the
            // path was never exercised end-to-end (all tests pass donation_rate
            // = None / use string stand-ins).
            Err(err) if is_insufficient_funds_error(&err.to_string()) => {
                candidate_fee = candidate_fee
                    .checked_add(u64::from(MARGINAL_FEE))
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "donation fee convergence overflowed the supported range".to_owned(),
                        )
                    })?;
            }
            Err(err) => {
                return Err(ZeckError::TransactionBuild(format!(
                    "building donation sweep proposal: {err}"
                )));
            }
        }
    }
    tracing::warn!(
        "donation split did not converge within {MAX_FEE_CONVERGENCE_ITERS} iterations; \
         falling back to a donation-free sweep for this account",
    );
    Ok(None)
}

async fn execute_send_max_step(
    ctx: &mut SweepStepCtx<'_>,
    tracked_account: &TrackedAccount,
    usk: &UnifiedSpendingKey,
    destination_address: &ZcashAddress,
    memo_bytes: Option<MemoBytes>,
) -> ZeckResult<Option<(u64, u64)>> {
    let mut wallet_db = open_wallet_db(
        ctx.workspace.wallet_db_path(),
        consensus_network(ctx.network),
    )?;

    // Pass 1 — measure the full-account send-max proposal (build only, no broadcast).
    let max_proposal = match propose_send_max_transfer::<_, _, _, Infallible>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        tracked_account.wallet_account_id,
        // Argos sweeps an account empty, so every shielded pool a recovered wallet can
        // hold value in must be spendable. Ironwood joins the list at NU6.3: funds
        // landing there after activation would otherwise be left behind by a sweep that
        // reported success.
        &[
            ShieldedPool::Sapling,
            ShieldedPool::Orchard,
            ShieldedPool::Ironwood,
        ],
        &StandardFeeRule::Zip317,
        destination_address.clone(),
        memo_bytes.clone(),
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::MIN,
        // Argos takes no advisory input locks; never draw on another holder's.
        &LockedInputPolicy::Exclude,
        None,
    ) {
        Ok(proposal) => proposal,
        Err(err) => {
            let message = format!("building sweep proposal: {err}");
            if is_insufficient_funds_error(&message) {
                // No selectable shielded value clears the fee floor (dust
                // notes, or nothing spendable at the required confirmations).
                // Skip this account rather than aborting the whole sweep.
                return Ok(None);
            }
            return Err(ZeckError::TransactionBuild(message));
        }
    };
    let send_max_fee = proposal_fee_zatoshis(&max_proposal)?;
    // Send-max is single-step with exactly one payment; read the amount destined
    // for the user (the full account spendable equals send_amount + send_max_fee).
    let send_amount: u64 = max_proposal
        .steps()
        .first()
        .transaction_request()
        .payments()
        .values()
        .next()
        .and_then(|payment| payment.amount())
        .map(u64::from)
        .ok_or_else(|| {
            ZeckError::TransactionBuild(
                "send-max proposal contained no payment output amount".to_owned(),
            )
        })?;

    let donation = crate::donation::donation_for_send_amount(
        ctx.donation_address,
        ctx.donation_rate,
        send_amount,
    );

    // `donation_zatoshis` is the amount *actually* placed in a donation output:
    // the requested `donation` when the split proposal is used, or 0 when there
    // is no donation or the split fell back to the donation-free sweep. Returned
    // so the caller can report the true donated total (the proposal figure is
    // only an estimate).
    let (proposal, donation_zatoshis) = if donation == 0 {
        // No donation output: behavior is unchanged from the single-pass sweep.
        (max_proposal, 0)
    } else {
        let donation_zcash_address =
            ZcashAddress::try_from_encoded(ctx.donation_address).map_err(|err| {
                ZeckError::InvalidAddress(format!("failed to decode donation address: {err}"))
            })?;
        // On non-convergence (or a non-positive user remainder) fall back to the
        // donation-free send-max sweep. The `Err` case is treated identically
        // to `Ok(None)`: anything that prevents us from constructing the
        // donation split (zip321 validation, unexpected proposal error,
        // future regressions) must not lose the user their sweep. Donation is
        // best-effort; the user's recovery is not.
        let split_result = build_donation_split_proposal(
            &mut wallet_db,
            ctx.network,
            tracked_account.wallet_account_id,
            destination_address,
            memo_bytes.clone(),
            &donation_zcash_address,
            ctx.donation_memo.clone(),
            send_amount,
            send_max_fee,
            donation,
        );
        donation_proposal_or_fallback(
            split_result,
            max_proposal,
            donation,
            tracked_account.derived.index,
        )
    };

    // Diagnostic (amounts only, no key material): makes a donation shortfall
    // observable — `donation` is what the rate/threshold asked for, while
    // `donation_zatoshis` is what was actually placed in an output (0 => the
    // split fell back).
    tracing::info!(
        "account {} donation — send_amount={} requested={} placed={}",
        tracked_account.derived.index,
        send_amount,
        donation,
        donation_zatoshis,
    );

    let fee_zatoshis = proposal_fee_zatoshis(&proposal)?;
    enforce_max_fee(
        checked_fee_total(ctx.prior_fee_zatoshis, fee_zatoshis)?,
        ctx.max_fee_zatoshis,
    )?;

    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        ctx.prover,
        ctx.prover,
        &SpendingKeys::from_unified_spending_key(usk.clone()),
        OvkPolicy::Sender,
        &proposal,
        // No explicit expiry override; keep the library's default expiry.
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating sweep transaction: {err}")))?;

    broadcast_transactions(
        &mut wallet_db,
        ctx.client,
        tracked_account.derived.index,
        txids.into_iter().collect(),
        "sweep",
        ctx.results,
        ctx.lightwalletd_url,
        ctx.primary_endpoint,
        ctx.network,
    )
    .await?;

    Ok(Some((fee_zatoshis, donation_zatoshis)))
}

#[allow(clippy::too_many_arguments)]
async fn broadcast_transactions(
    wallet_db: &mut WalletDb<
        rusqlite::Connection,
        crate::workspace::ArgosParams,
        SystemClock,
        rand_core::OsRng,
    >,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    account_index: u32,
    txids: Vec<TxId>,
    label: &str,
    results: &mut Vec<TxBroadcastResult>,
    lightwalletd_url: &str,
    primary_endpoint: &str,
    network: crate::models::ZeckNetwork,
) -> ZeckResult<()> {
    for txid in txids {
        let tx = wallet_db
            .get_transaction(txid)
            .map_err(|err| ZeckError::Wallet(format!("loading {label} transaction {txid}: {err}")))?
            .ok_or_else(|| {
                ZeckError::Wallet(format!(
                    "wallet did not persist the {label} transaction {txid}"
                ))
            })?;

        let mut tx_bytes = Vec::new();
        tx.write(&mut tx_bytes).map_err(|err| {
            ZeckError::TransactionBuild(format!("serializing transaction {txid}: {err}"))
        })?;

        let response = client
            .send_transaction(RawTransaction {
                data: tx_bytes,
                height: 0,
            })
            .await
            .map_err(|err| ZeckError::Broadcast(err.to_string()))?
            .into_inner();
        if response.error_code != 0 {
            let reason = if response.error_message.is_empty() {
                format!("error code {}", response.error_code)
            } else {
                response.error_message.clone()
            };
            return Err(ZeckError::Broadcast(format!(
                "{label} transaction {txid} was rejected: {reason}"
            )));
        }

        // The transaction is on the network now. Record it immediately as
        // pending so the record survives even if confirmation polling fails
        // below (audit Issue E); `execute_sweep` surfaces it either way. The
        // entry is then updated in place once polling resolves.
        let result_index = results.len();
        results.push(TxBroadcastResult {
            source_account: account_index,
            txid: Some(txid.to_string()),
            status: "pending".to_owned(),
            detail: format!("{label} transaction broadcast; awaiting confirmation"),
            confirmed_height: None,
        });

        let (status, detail, confirmed_height) =
            wait_for_confirmation(wallet_db, client, txid, label).await?;
        // Cross-check a "confirmed" status against a second configured endpoint
        // before presenting it as final, so a single hostile server cannot fake
        // a confirmation (audit Issue B follow-up). Best-effort: never fails the
        // sweep, only annotates the detail with the independent result.
        let detail = if status == "confirmed" {
            match cross_verify_mined(lightwalletd_url, primary_endpoint, network, txid).await {
                Some(true) => format!(
                    "{detail} A second configured endpoint also reported this transaction as mined."
                ),
                Some(false) => format!(
                    "{detail} NOTE: a second configured endpoint did not report this transaction as \
                     mined yet. This is most often benign propagation lag right after broadcast, but \
                     if it persists, verify the transaction on a block explorer before treating the \
                     recovery as final."
                ),
                None => detail,
            }
        } else {
            detail
        };
        let entry = &mut results[result_index];
        entry.status = status;
        entry.detail = detail;
        entry.confirmed_height = confirmed_height;
    }

    Ok(())
}

/// Best-effort cross-check of a confirmation against a second configured
/// lightwalletd endpoint (audit Issue B follow-up).
///
/// Returns `Some(true)` if a distinct second endpoint also reports `txid`
/// mined, `Some(false)` if it reports the transaction as not in the main chain,
/// and `None` if there is no distinct second endpoint or it could not be
/// reached/queried. This never errors: a confirmation that cannot be
/// independently checked falls back to the single-server attestation already
/// disclosed to the user, rather than failing the sweep.
async fn cross_verify_mined(
    lightwalletd_url: &str,
    primary_endpoint: &str,
    network: crate::models::ZeckNetwork,
    txid: TxId,
) -> Option<bool> {
    let secondary = validated_lightwalletd_endpoints(lightwalletd_url)
        .ok()?
        .into_iter()
        .find(|endpoint| is_distinct_lightwalletd_endpoint(endpoint, primary_endpoint))?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(SECONDARY_CONFIRMATION_TIMEOUT_SECS),
        CompactTxStreamerClient::connect(secondary),
    )
    .await
    .ok()?
    .ok()?;
    // Validate the secondary's network (chain name + Sapling activation height)
    // before trusting its answer, so a wrong-chain endpoint cannot produce a
    // misleading confirmation result (audit Issue B follow-up review).
    let info = tokio::time::timeout(
        Duration::from_secs(SECONDARY_CONFIRMATION_TIMEOUT_SECS),
        client.get_lightd_info(zcash_client_backend::proto::service::Empty {}),
    )
    .await
    .ok()?
    .ok()?
    .into_inner();
    validate_lightwalletd_network(network, &info).ok()?;
    let response = tokio::time::timeout(
        Duration::from_secs(SECONDARY_CONFIRMATION_TIMEOUT_SECS),
        client.get_transaction(TxFilter {
            block: None,
            index: 0,
            hash: txid.as_ref().to_vec(),
        }),
    )
    .await
    .ok()?
    .ok()?
    .into_inner();
    // Mined iff the height is a real block height: 0 means mempool/not found and
    // u64::MAX means reorged out. A `Some(false)` can also reflect benign
    // propagation lag on a healthy second endpoint, which is why the caller only
    // warns (never blocks) on it.
    Some(response.height != 0 && response.height != u64::MAX)
}

fn is_distinct_lightwalletd_endpoint(candidate: &str, primary: &str) -> bool {
    normalized_endpoint_authority(candidate) != normalized_endpoint_authority(primary)
}

fn normalized_endpoint_authority(endpoint: &str) -> String {
    let Ok(url) = url::Url::parse(endpoint) else {
        return endpoint.trim().trim_end_matches('/').to_ascii_lowercase();
    };
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url
        .host_str()
        .map(|host| host.to_ascii_lowercase())
        .unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{scheme}://{host}:{port}")
}

async fn wait_for_confirmation(
    wallet_db: &mut WalletDb<
        rusqlite::Connection,
        crate::workspace::ArgosParams,
        SystemClock,
        rand_core::OsRng,
    >,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    txid: TxId,
    label: &str,
) -> ZeckResult<(String, String, Option<u32>)> {
    for _ in 0..CONFIRMATION_POLL_ATTEMPTS {
        match client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid.as_ref().to_vec(),
            })
            .await
        {
            Ok(response) => {
                let tx = response.into_inner();
                if tx.height == 0 {
                    wallet_db
                        .set_transaction_status(txid, TransactionStatus::NotInMainChain)
                        .map_err(|err| {
                            ZeckError::Wallet(format!(
                                "marking pending transaction {txid} in wallet db: {err}"
                            ))
                        })?;
                } else if tx.height == u64::MAX {
                    wallet_db
                        .set_transaction_status(txid, TransactionStatus::NotInMainChain)
                        .map_err(|err| {
                            ZeckError::Wallet(format!(
                                "marking reorged transaction {txid} in wallet db: {err}"
                            ))
                        })?;
                } else {
                    let mined_height = u32::try_from(tx.height).map_err(|_| {
                        ZeckError::Broadcast(format!(
                            "{label} transaction {txid} returned an invalid mined height"
                        ))
                    })?;
                    wallet_db
                        .set_transaction_status(
                            txid,
                            TransactionStatus::Mined(BlockHeight::from_u32(mined_height)),
                        )
                        .map_err(|err| {
                            ZeckError::Wallet(format!(
                                "marking mined transaction {txid} in wallet db: {err}"
                            ))
                        })?;
                    // The mined height is reported by the single connected
                    // lightwalletd server and trusted verbatim. A hostile
                    // server can return a success code without relaying the
                    // transaction and then answer the confirmation poll with a
                    // fabricated height. Theft is not possible (signatures
                    // commit to the user's own outputs), but a recovery tool
                    // must not let the user treat a single server's word as
                    // final. Make the attestation explicit (audit Issue B).
                    return Ok((
                        "confirmed".to_owned(),
                        format!(
                            "{label} transaction reported mined at height {mined_height} by the \
                             connected lightwalletd server. This confirmation is attested by a \
                             single server — verify it against a block explorer or a second node \
                             before treating the recovery as final."
                        ),
                        Some(mined_height),
                    ));
                }
            }
            Err(_) => {
                wallet_db
                    .set_transaction_status(txid, TransactionStatus::NotInMainChain)
                    .map_err(|err| {
                        ZeckError::Wallet(format!(
                            "marking pending transaction {txid} in wallet db: {err}"
                        ))
                    })?;
            }
        }

        tokio::time::sleep(Duration::from_secs(CONFIRMATION_POLL_INTERVAL_SECS)).await;
    }

    Ok((
        "pending".to_owned(),
        format!(
            "{label} transaction broadcast successfully, but confirmation was not observed during the wait window."
        ),
        None,
    ))
}

async fn chain_tip_height(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
) -> ZeckResult<u32> {
    let info = client
        .get_lightd_info(zcash_client_backend::proto::service::Empty {})
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))
}

fn account_total_zatoshis(
    workspace: &RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    account_id: zcash_client_sqlite::AccountUuid,
) -> ZeckResult<u64> {
    let wallet_db = open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;
    let summary = wallet_db
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .map_err(|err| ZeckError::Wallet(format!("loading wallet summary: {err}")))?
        .ok_or_else(|| ZeckError::Wallet("wallet summary is unavailable".to_owned()))?;
    Ok(summary
        .account_balances()
        .get(&account_id)
        .map(|balance| u64::from(balance.total()))
        .unwrap_or(0))
}

fn account_transparent_zatoshis(
    workspace: &RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    tracked_account: &TrackedAccount,
) -> ZeckResult<u64> {
    let wallet_db = open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;
    let summary = wallet_db
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .map_err(|err| ZeckError::Wallet(format!("loading wallet summary: {err}")))?
        .ok_or_else(|| ZeckError::Wallet("wallet summary is unavailable".to_owned()))?;
    Ok(summary
        .account_balances()
        .get(&tracked_account.wallet_account_id)
        .map(|balance| u64::from(balance.unshielded_balance().total()))
        .unwrap_or(0))
}

fn proposal_fee_zatoshis<NoteRef>(
    proposal: &zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>,
) -> ZeckResult<u64> {
    proposal.steps().iter().try_fold(0u64, |sum, step| {
        sum.checked_add(u64::from(step.balance().fee_required()))
            .ok_or_else(|| {
                ZeckError::Internal("fee total overflowed the supported range".to_owned())
            })
    })
}

fn checked_fee_total(prior_fee_zatoshis: u64, next_fee_zatoshis: u64) -> ZeckResult<u64> {
    prior_fee_zatoshis
        .checked_add(next_fee_zatoshis)
        .ok_or_else(|| ZeckError::Internal("fee total overflowed the supported range".to_owned()))
}

fn enforce_max_fee(total_fee_zatoshis: u64, max_fee_zatoshis: Option<u64>) -> ZeckResult<()> {
    if let Some(max_fee_zatoshis) = max_fee_zatoshis {
        if total_fee_zatoshis > max_fee_zatoshis {
            return Err(ZeckError::MaxFeeExceeded(format!(
                "actual fee {total_fee_zatoshis} zats exceeds limit {max_fee_zatoshis} zats"
            )));
        }
    }

    Ok(())
}

/// Whether the most recent broadcast for `account_index` outright failed (vs
/// merely pending in the mempool). A failed shield is skipped immediately rather
/// than waited on.
fn last_account_broadcast_failed(results: &[TxBroadcastResult], account_index: u32) -> bool {
    results
        .iter()
        .rev()
        .find(|result| result.source_account == account_index)
        .map(|result| result.status == "failed")
        .unwrap_or(false)
}

/// Spendable shielded balance for an account = total spendable minus the
/// unshielded (transparent) portion.
fn shielded_spendable_zatoshis(
    workspace: &RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    tracked_account: &TrackedAccount,
) -> ZeckResult<u64> {
    let total = account_total_zatoshis(workspace, network, tracked_account.wallet_account_id)?;
    let transparent = account_transparent_zatoshis(workspace, network, tracked_account)?;
    Ok(total.saturating_sub(transparent))
}

/// Wait for a just-broadcast shielding tx to mine so its shielded note becomes
/// spendable by the following send-max. Polls (re-sync + balance check) until
/// the account's spendable shielded balance rises above `shielded_before` —
/// meaning the shield was mined, scanned, and is spendable — or until the
/// timeout. Returns `Ok(true)` once confirmed, `Ok(false)` on timeout (the
/// caller leaves the funds shielded and continues without aborting the sweep).
#[allow(clippy::too_many_arguments)]
async fn wait_for_shielded_funds_to_confirm(
    workspace: &RecoveryWorkspace,
    network: &crate::workspace::ArgosParams,
    zeck_network: crate::models::ZeckNetwork,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    lightwalletd_url: &str,
    state: &SharedScanTaskState,
    tracked_account: &TrackedAccount,
    shielded_before: u64,
) -> ZeckResult<bool> {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(SHIELD_CONFIRM_TIMEOUT_SECS);
    loop {
        {
            let mut guard = state.lock().await;
            guard.progress.message = Some(
                "Waiting for the shielding transaction to confirm before sweeping…".to_owned(),
            );
        }
        run_wallet_sync_with_retry(
            workspace,
            network,
            zeck_network,
            client,
            lightwalletd_url,
            state,
        )
        .await?;
        if shielded_spendable_zatoshis(workspace, zeck_network, tracked_account)? > shielded_before
        {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(std::time::Duration::from_secs(SHIELD_CONFIRM_POLL_SECS)).await;
    }
}

fn normalized_memo_text(memo: Option<&str>) -> ZeckResult<String> {
    let value = memo
        .map(str::trim)
        .filter(|memo| !memo.is_empty())
        .unwrap_or(RECOVERY_MEMO_DEFAULT);

    MemoBytes::from_bytes(value.as_bytes())
        .map_err(|err| ZeckError::InvalidMemo(err.to_string()))?;
    Ok(value.to_owned())
}

fn estimate_remaining_seconds(progress: &ScanProgress, elapsed_seconds: u64) -> Option<u64> {
    if progress.blocks_total == 0 {
        return None;
    }
    if progress.blocks_scanned >= progress.blocks_total {
        return Some(0);
    }
    if progress.blocks_scanned < 100 || elapsed_seconds < 5 {
        return None;
    }

    let remaining_blocks = progress
        .blocks_total
        .saturating_sub(progress.blocks_scanned);
    Some(
        remaining_blocks
            .saturating_mul(elapsed_seconds)
            .checked_div(progress.blocks_scanned)
            .unwrap_or(0),
    )
}

/// Adapt an imported-wallet sweep to the shared `SweepOutcome`.
///
/// An imported wallet moves its two pools in two transactions, so both are
/// reported as separate entries. A pool that held nothing appears as a
/// skipped account rather than being omitted: a pool silently missing from
/// the report is indistinguishable from one that was never attempted.
async fn sweep_imported_session(
    runtime: &RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    request: &SweepRequest,
) -> ZeckResult<SweepOutcome> {
    let outcome = crate::imported_sweep::sweep_imported_wallet(
        runtime,
        keys,
        &request.destination,
        request.max_fee_zatoshis,
    )
    .await?;

    let mut transactions = Vec::new();
    let mut skipped_accounts = Vec::new();

    // One entry per Sapling account that moved, so a wallet holding several
    // Sapling keys reports every transaction rather than only the first.
    for (index, txid) in outcome.sapling_txids.iter().enumerate() {
        transactions.push(TxBroadcastResult {
            source_account: index as u32,
            txid: Some(txid.clone()),
            status: "broadcast".to_owned(),
            detail: "Sapling notes from the imported wallet".to_owned(),
            confirmed_height: None,
        });
    }
    if outcome.sapling_txids.is_empty() {
        skipped_accounts.push(SkippedSweepAccount {
            account_index: 0,
            reason: "the imported wallet holds no spendable Sapling notes".to_owned(),
            gross_zatoshis: 0,
        });
    }

    match outcome.transparent_txid {
        Some(txid) => transactions.push(TxBroadcastResult {
            source_account: 0,
            txid: Some(txid),
            status: "broadcast".to_owned(),
            detail: format!(
                "transparent UTXOs from the imported wallet ({} zatoshis, {} fee)",
                outcome.transparent_zatoshis, outcome.transparent_fee_zatoshis
            ),
            confirmed_height: None,
        }),
        None => skipped_accounts.push(SkippedSweepAccount {
            account_index: 0,
            reason: "the imported wallet holds no spendable transparent funds".to_owned(),
            gross_zatoshis: 0,
        }),
    }

    Ok(SweepOutcome {
        transactions,
        skipped_accounts,
        // Donations are not split out of an imported sweep: the Sapling
        // path builds a single-step send-max proposal, which has no room
        // for a second output.
        total_donation_zatoshis: 0,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{build_sweep_proposal, is_distinct_lightwalletd_endpoint};
    use crate::{
        derive_accounts,
        error::ZeckError,
        models::{
            AccountBalancePreview, ProposedTxKind, ScanHandle, ScanPhase, ScanProgress,
            SweepRequest, ZeckNetwork,
        },
    };

    #[test]
    fn equivalent_lightwalletd_urls_are_not_distinct_confirmation_sources() {
        assert!(!is_distinct_lightwalletd_endpoint(
            "https://zec.rocks",
            "https://zec.rocks:443/"
        ));
        assert!(is_distinct_lightwalletd_endpoint(
            "https://na.zec.rocks:443",
            "https://zec.rocks:443"
        ));
    }

    fn derived_destination() -> String {
        derive_accounts(
            &SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
            ZeckNetwork::Mainnet,
            1,
        )
        .expect("derived account")[0]
            .unified_address
            .clone()
    }

    fn derived_destination_testnet() -> String {
        derive_accounts(
            &SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
            ZeckNetwork::Testnet,
            1,
        )
        .expect("derived account")[0]
            .unified_address
            .clone()
    }

    fn progress_with_account(account: AccountBalancePreview) -> ScanProgress {
        ScanProgress {
            handle: ScanHandle::new(),
            phase: ScanPhase::Complete,
            blocks_scanned: 1,
            blocks_total: 1,
            synced_to_height: None,
            elapsed_seconds: None,
            estimated_remaining_seconds: None,
            accounts: vec![account],
            discoveries: vec![],
            summary: None,
            server: None,
            message: None,
            error: None,
            sleep_event: None,
            in_sandblasting_zone: false,
            gap_extension: None,
        }
    }

    const DONATION_TEST_UA: &str = "u1nvgt6yr35mhc9wdf4wckvl38476vqy96dx3cwkfdwy4jet9300l5v8l2yg27ql7w9qwm0lf8kncnj9nus4mgete06j3cu3mhrqvstg6swvdya6xgzwhh6a9xxdhxkavvvmztqeuaurjtqfk3dzetuzgnu0zjvmdpe8ehvj53sy6yhzxj";

    #[test]
    fn proposal_splits_donation_out_of_shielded_send_on_mainnet() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 3_000_000,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 3_000_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: Some("donor@example.com".to_owned()),
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap();

        let sweep = proposal
            .transactions
            .iter()
            .find(|t| t.kind == crate::models::ProposedTxKind::SweepShielded)
            .unwrap();
        assert!(sweep.donation_zatoshis > 0);
        assert_eq!(proposal.total_donation_zatoshis, sweep.donation_zatoshis);
        // estimate invariant unchanged
        assert_eq!(
            sweep.net_zatoshis + sweep.fee_zatoshis,
            sweep.gross_zatoshis
        );
        // donation is strictly less than the amount being sent
        assert!(sweep.donation_zatoshis < sweep.net_zatoshis);
    }

    #[test]
    fn proposal_skips_donation_on_testnet() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 3_000_000,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 3_000_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination_testnet(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: None,
            },
            ZeckNetwork::Testnet,
            DONATION_TEST_UA,
        )
        .unwrap();
        assert_eq!(proposal.total_donation_zatoshis, 0);
    }

    #[test]
    fn proposal_separates_shielding_from_shielded_sweeping() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 1,
                sapling_zatoshis: 40_000,
                orchard_zatoshis: 0,
                transparent_zatoshis: 30_000,
                total_zatoshis: 70_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: Some("recovery".to_owned()),
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .expect("proposal should build");

        assert_eq!(proposal.transactions.len(), 2);
        assert_eq!(
            proposal.transactions[0].kind,
            crate::models::ProposedTxKind::ShieldTransparent
        );
        assert_eq!(proposal.transactions[0].gross_zatoshis, 30_000);
        assert_eq!(proposal.transactions[1].gross_zatoshis, 60_000);
    }

    #[test]
    fn proposal_rejects_max_fee_below_estimate() {
        let err = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 1,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 50_000,
                total_zatoshis: 50_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: Some(15_000),
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .expect_err("proposal should fail");

        assert!(matches!(err, ZeckError::MaxFeeExceeded(_)));
    }

    #[test]
    fn actual_fee_guard_rejects_before_transaction_creation() {
        use super::{checked_fee_total, enforce_max_fee};
        let total_fee = checked_fee_total(10_000, 10_000).expect("fee total should fit");
        let err = enforce_max_fee(total_fee, Some(15_000)).expect_err("fee cap should fail");

        assert!(matches!(err, ZeckError::MaxFeeExceeded(_)));
    }

    #[test]
    fn actual_fee_guard_detects_overflow() {
        use super::checked_fee_total;
        let err = checked_fee_total(u64::MAX, 1).expect_err("fee total should overflow");

        assert!(matches!(err, ZeckError::Internal(_)));
    }

    fn sample_broadcast_result(account: u32) -> crate::models::TxBroadcastResult {
        crate::models::TxBroadcastResult {
            source_account: account,
            txid: Some(format!("tx-{account}")),
            status: "confirmed".to_owned(),
            detail: "mined".to_owned(),
            confirmed_height: Some(1_000_000),
        }
    }

    #[test]
    fn sweep_outcome_full_success_carries_no_error() {
        use super::assemble_sweep_outcome;
        let outcome =
            assemble_sweep_outcome(vec![sample_broadcast_result(0)], Vec::new(), 25_000, Ok(()))
                .expect("Ok");
        assert!(outcome.error.is_none());
        assert_eq!(outcome.transactions.len(), 1);
        assert!(outcome.skipped_accounts.is_empty());
        assert_eq!(outcome.total_donation_zatoshis, 25_000);
    }

    #[test]
    fn sweep_outcome_partial_failure_preserves_records_and_error() {
        use super::assemble_sweep_outcome;
        let outcome = assemble_sweep_outcome(
            vec![sample_broadcast_result(0), sample_broadcast_result(1)],
            vec![crate::models::SkippedSweepAccount {
                account_index: 7,
                gross_zatoshis: 9_000,
                reason: "dust".to_owned(),
            }],
            0,
            Err(ZeckError::Broadcast("account 2 rejected".to_owned())),
        )
        .expect("a partial failure with broadcast records is reported as Ok, not lost");
        assert_eq!(outcome.transactions.len(), 2);
        // Skipped accounts ride along on the partial-success outcome.
        assert_eq!(outcome.skipped_accounts.len(), 1);
        assert_eq!(outcome.skipped_accounts[0].account_index, 7);
        let message = outcome
            .error
            .expect("a partial failure carries the underlying error message");
        assert!(message.contains("account 2 rejected"));
    }

    #[test]
    fn sweep_outcome_failure_before_any_broadcast_propagates_err() {
        use super::assemble_sweep_outcome;
        let err = assemble_sweep_outcome(
            Vec::new(),
            Vec::new(),
            0,
            Err(ZeckError::Broadcast("first account rejected".to_owned())),
        )
        .expect_err("a failure before any broadcast must stay an Err");
        assert!(matches!(err, ZeckError::Broadcast(_)));
    }

    #[test]
    fn shield_step_reserves_send_max_floor_before_broadcast() {
        use super::{checked_fee_total, enforce_max_fee, MIN_SHIELDED_SEND_FEE_ZATOSHIS};
        // A shield fee of 8000 zats fits a 10000-zat cap on its own...
        let shield_total = checked_fee_total(0, 8_000).expect("fits");
        assert!(enforce_max_fee(shield_total, Some(10_000)).is_ok());
        // ...but once the mandatory send-max floor is reserved, the combined
        // total exceeds the cap and must abort before the shield is broadcast.
        let reserved =
            checked_fee_total(shield_total, MIN_SHIELDED_SEND_FEE_ZATOSHIS).expect("fits");
        assert!(matches!(
            enforce_max_fee(reserved, Some(10_000)),
            Err(ZeckError::MaxFeeExceeded(_))
        ));
    }

    #[test]
    fn balance_at_or_below_fee_floor_is_not_sweepable() {
        use super::{balance_covers_sweep_fee, MIN_SHIELDED_SEND_FEE_ZATOSHIS};
        // A balance at or below the ZIP-317 fee floor cannot be swept — the fee
        // would consume it all, hard-failing the shielding/send proposal. This
        // predicate is what gates both execution steps so they skip such dust
        // exactly as `build_sweep_proposal` does (instead of erroring the sweep).
        assert!(!balance_covers_sweep_fee(0));
        assert!(!balance_covers_sweep_fee(
            MIN_SHIELDED_SEND_FEE_ZATOSHIS - 1
        ));
        assert!(!balance_covers_sweep_fee(MIN_SHIELDED_SEND_FEE_ZATOSHIS)); // == floor: fee eats it all
        assert!(balance_covers_sweep_fee(MIN_SHIELDED_SEND_FEE_ZATOSHIS + 1));
    }

    #[test]
    fn insufficient_funds_proposal_errors_are_detected_for_skip() {
        use super::is_insufficient_funds_error;
        // The exact zcash_client_backend phrasing the sweep must treat as
        // "this account is unsweepable, skip it" rather than a fatal sweep abort
        // — this is the case `balance_covers_sweep_fee` (summed balance) misses
        // when the value is dust UTXOs or outside the shieldable receivers.
        assert!(is_insufficient_funds_error(
            "building shielding proposal: Change output generation failed: \
             Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were available"
        ));
        assert!(is_insufficient_funds_error(
            "building sweep proposal: Insufficient funds: required 10000, but only 5000 were available"
        ));
        // Unrelated build failures MUST still abort (not be silently skipped).
        assert!(!is_insufficient_funds_error(
            "building shielding proposal: network validation failed"
        ));
        assert!(!is_insufficient_funds_error(
            "creating shielding transaction: prover initialization failed"
        ));
    }

    #[test]
    fn execution_dust_floor_matches_proposal_minimum_fee() {
        use super::MIN_SHIELDED_SEND_FEE_ZATOSHIS;
        use zcash_primitives::transaction::fees::zip317::MINIMUM_FEE;
        // The execution-side dust floor MUST equal the proposal's ZIP-317
        // `minimum_fee_zatoshis`, or the dry run and the actual sweep would
        // disagree on which accounts to skip — the divergence this fix closes.
        assert_eq!(MIN_SHIELDED_SEND_FEE_ZATOSHIS, u64::from(MINIMUM_FEE));
    }

    #[test]
    fn proposal_skips_dusty_transparent_only_accounts() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 1,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 5_000,
                total_zatoshis: 5_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .expect("proposal should build");

        assert!(proposal.transactions.is_empty());
        assert_eq!(proposal.skipped_accounts.len(), 1);
    }

    #[test]
    fn memo_with_ascii_is_accepted() {
        use super::normalized_memo_text;
        let result = normalized_memo_text(Some("Argos recovery"));
        assert!(result.is_ok());
    }

    #[test]
    fn memo_with_emoji_is_accepted_when_short_enough() {
        use super::normalized_memo_text;
        // emoji are 4 bytes each — a handful should still fit within the 512-byte limit
        let result = normalized_memo_text(Some("🎉 recovery 🎉"));
        assert!(result.is_ok());
    }

    #[test]
    fn memo_exceeding_512_bytes_is_rejected() {
        use super::normalized_memo_text;
        // each '🎉' is 4 bytes; 129 of them = 516 bytes, over the 512-byte memo limit
        let long_memo = "🎉".repeat(129);
        let result = normalized_memo_text(Some(&long_memo));
        assert!(result.is_err(), "expected InvalidMemo for oversized memo");
    }

    #[test]
    fn empty_memo_falls_back_to_default() {
        use super::{normalized_memo_text, RECOVERY_MEMO_DEFAULT};
        let result = normalized_memo_text(Some("   ")).unwrap();
        assert_eq!(result, RECOVERY_MEMO_DEFAULT);
    }

    // ─── Donation Err-fallback (Kristi review #1) ─────────────────────────────
    //
    // The three-way branch in execute_send_max_step's donation handling lives
    // in `donation_proposal_or_fallback`. Tests below use a String stand-in
    // for the Proposal type to exercise all three arms without a wallet DB.

    #[test]
    fn donation_fallback_ok_some_returns_split() {
        // Split built → its proposal AND the requested donation amount.
        let got = super::donation_proposal_or_fallback::<&str>(
            Ok(Some("donation-split")),
            "donation-free-max",
            5_000,
            0,
        );
        assert_eq!(got, ("donation-split", 5_000));
    }

    #[test]
    fn donation_fallback_ok_none_returns_max() {
        // Fell back → donation-free proposal AND zero actual donation.
        let got =
            super::donation_proposal_or_fallback::<&str>(Ok(None), "donation-free-max", 5_000, 0);
        assert_eq!(got, ("donation-free-max", 0));
    }

    #[test]
    fn donation_fallback_err_returns_max() {
        // The critical safety property: an Err must NOT propagate. The user's
        // sweep proceeds donation-free. Pre-fix, an Err here aborted the
        // entire sweep — see PR #66 review (Kristi, 2026-05-28). The actual
        // donation is reported as 0 so the outcome doesn't over-count.
        let got = super::donation_proposal_or_fallback::<&str>(
            Err(ZeckError::TransactionBuild(
                "synthetic regression".to_owned(),
            )),
            "donation-free-max",
            5_000,
            42,
        );
        assert_eq!(got, ("donation-free-max", 0));
    }

    // ─── Multi-account proposal donation logic ────────────────────────────────

    fn progress_with_accounts(accounts: Vec<AccountBalancePreview>) -> ScanProgress {
        ScanProgress {
            handle: ScanHandle::new(),
            phase: ScanPhase::Complete,
            blocks_scanned: 1,
            blocks_total: 1,
            synced_to_height: None,
            elapsed_seconds: None,
            estimated_remaining_seconds: None,
            accounts,
            discoveries: vec![],
            summary: None,
            server: None,
            message: None,
            error: None,
            sleep_event: None,
            in_sandblasting_zone: false,
            gap_extension: None,
        }
    }

    /// Helper to build a shielded-only account preview with a chosen Sapling
    /// balance. The index lets each account in a multi-account scenario be
    /// distinguishable in the proposal output.
    fn shielded_account(index: u32, sapling_zatoshis: u64) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: index,
            sapling_address: String::new(),
            unified_address: derived_destination(),
            transparent_receive_address: String::new(),
            transparent_change_address: String::new(),
            transparent_utxo_count: 0,
            sapling_zatoshis,
            orchard_zatoshis: 0,
            transparent_zatoshis: 0,
            total_zatoshis: sapling_zatoshis,
            has_activity: sapling_zatoshis > 0,
            status: String::new(),
        }
    }

    #[test]
    fn proposal_only_above_threshold_accounts_contribute_donation() {
        // Three accounts. Account 0 is large (donation included); account 1
        // is right at the threshold boundary (included); account 2 is below
        // threshold (skipped from donation, swept normally). Total donation
        // is the sum of accounts 0 and 1, not just one of them and not all.
        let proposal = build_sweep_proposal(
            &progress_with_accounts(vec![
                shielded_account(0, 5_000_000), // 10% = 500k, well above MIN
                shielded_account(1, 1_010_000), // net ≈ 1_000_000 → 10% = 100k = MIN
                shielded_account(2, 500_000),   // 10% ≈ 49.9k, below MIN → no donation
            ]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap();
        let sweeps: Vec<_> = proposal
            .transactions
            .iter()
            .filter(|t| t.kind == ProposedTxKind::SweepShielded)
            .collect();
        assert_eq!(sweeps.len(), 3, "every account produces a sweep tx");
        // Account 0 and 1 above threshold; account 2 below.
        assert!(sweeps[0].donation_zatoshis > 0);
        assert!(sweeps[1].donation_zatoshis > 0);
        assert_eq!(sweeps[2].donation_zatoshis, 0);
        // Total matches the per-tx sum.
        let summed: u64 = sweeps.iter().map(|s| s.donation_zatoshis).sum();
        assert_eq!(proposal.total_donation_zatoshis, summed);
        // Fund-safety invariant: per-tx, gross == net + fee (donation is part
        // of net in the estimate).
        for s in &sweeps {
            assert_eq!(s.net_zatoshis + s.fee_zatoshis, s.gross_zatoshis);
            assert!(
                s.donation_zatoshis < s.net_zatoshis,
                "donation must remain strictly below net so user receives positive remainder"
            );
        }
    }

    #[test]
    fn proposal_donation_rate_zero_produces_no_donation_across_accounts() {
        // donation_rate Some(0.0) is treated as "skip" by the helper. The
        // total donation must be 0 regardless of how many accounts exist.
        let proposal = build_sweep_proposal(
            &progress_with_accounts(vec![
                shielded_account(0, 10_000_000),
                shielded_account(1, 20_000_000),
                shielded_account(2, 5_000_000),
            ]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.0),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap();
        assert_eq!(proposal.total_donation_zatoshis, 0);
        for s in proposal
            .transactions
            .iter()
            .filter(|t| t.kind == ProposedTxKind::SweepShielded)
        {
            assert_eq!(s.donation_zatoshis, 0);
        }
    }

    #[test]
    fn proposal_no_donation_when_donation_address_empty() {
        // The feature off-switch: an empty DONATION_ADDRESS constant must
        // suppress every donation output regardless of rate or account size.
        // (Production passes `crate::donation::DONATION_ADDRESS`; the test
        // injects "" to simulate the dormant state.)
        let proposal = build_sweep_proposal(
            &progress_with_accounts(vec![
                shielded_account(0, 100_000_000), // 1 ZEC
                shielded_account(1, 50_000_000),  // 0.5 ZEC
            ]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: Some("donor@example.com".to_owned()),
            },
            ZeckNetwork::Mainnet,
            "", // address blanked
        )
        .unwrap();
        assert_eq!(proposal.total_donation_zatoshis, 0);
    }

    #[test]
    fn proposal_rejects_invalid_donation_rate() {
        let err = build_sweep_proposal(
            &progress_with_accounts(vec![shielded_account(0, 5_000_000)]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(1.5),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap_err();
        match err {
            ZeckError::InvalidConfig(msg) => {
                assert!(msg.contains("donation rate"), "got: {msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn proposal_rejects_invalid_donor_email() {
        let err = build_sweep_proposal(
            &progress_with_accounts(vec![shielded_account(0, 5_000_000)]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: Some("notanemail".to_owned()),
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap_err();
        assert!(matches!(err, ZeckError::InvalidConfig(_)));
    }
}
