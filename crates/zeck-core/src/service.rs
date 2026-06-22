use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Instant};

use secrecy::{ExposeSecret, SecretString};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Duration,
};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions, input_selection::GreedyInputSelector,
            propose_send_max_transfer, propose_shielding, propose_transfer, ConfirmationsPolicy,
            SpendingKeys,
        },
        MaxSpendMode, TransactionStatus, TransparentOutputFilter, WalletRead, WalletWrite,
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
use zcash_primitives::transaction::{fees::zip317::MINIMUM_FEE, TxId};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis, ShieldedProtocol};

use crate::{
    address::validate_destination_address,
    derivation::{legacy_transparent_account_key, legacy_transparent_secret_key, mnemonic_seed},
    error::{ZeckError, ZeckResult},
    lightwalletd::{
        connect_lightwalletd_endpoints, validate_lightwalletd_network,
        validated_lightwalletd_endpoints,
    },
    models::{
        ProposedTx, ProposedTxKind, RuntimeScanConfig, ScanConfig, ScanHandle, ScanPhase,
        ScanProgress, SkippedSweepAccount, SweepProposal, SweepRequest, TxBroadcastResult,
    },
    scan::{
        refresh_scan_progress, run_recovery_scan, run_wallet_sync, ScanTaskState,
        SharedScanTaskState, TrackedAccount,
    },
    workspace::{consensus_network, open_wallet_db, RecoveryWorkspace},
};

const RECOVERY_MEMO_DEFAULT: &str = "Argos recovery";
const SESSION_RETENTION_SECS: u64 = 300;
/// Maximum iterations for the donation-split fee-convergence loop. The extra
/// donation output adds at most one ZIP-317 marginal action, so convergence is
/// expected within 2 iterations; 4 leaves headroom.
const MAX_FEE_CONVERGENCE_ITERS: usize = 4;

/// The concrete wallet database type used throughout the execution path.
type SweepWalletDb = WalletDb<
    rusqlite::Connection,
    zcash_protocol::consensus::Network,
    SystemClock,
    rand_core::OsRng,
>;
const CONFIRMATION_POLL_INTERVAL_SECS: u64 = 5;
const CONFIRMATION_POLL_ATTEMPTS: u32 = 24;

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
        validate_scan_config(&config)?;

        let handle = ScanHandle::new();
        let state = Arc::new(tokio::sync::Mutex::new(ScanTaskState::new(handle.clone())));
        let runtime = RuntimeScanConfig {
            seed_phrase,
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
    ) -> ZeckResult<Vec<TxBroadcastResult>> {
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
    ) -> ZeckResult<Vec<TxBroadcastResult>> {
        self.execute_sweep_inner(handle, request, Some(pause_between_broadcasts))
            .await
    }

    async fn execute_sweep_inner(
        &self,
        handle: &ScanHandle,
        request: SweepRequest,
        pause_between_broadcasts: Option<std::time::Duration>,
    ) -> ZeckResult<Vec<TxBroadcastResult>> {
        let session = self.session(handle).await?;
        let progress = session.state.lock().await.progress.clone();
        if progress.phase != ScanPhase::Complete {
            return Err(ZeckError::ScanNotReady(format!(
                "current phase is {:?}",
                progress.phase
            )));
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
    let destination = validate_destination_address(&request.destination)?;
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
                "estimated fee {} zats exceeds limit {} zats",
                total_fee_zatoshis, max_fee_zatoshis
            )));
        }
    }

    let warning = if net_received_zatoshis > 0 {
        "This dry-run proposal uses the authoritative scan balances from the persisted wallet workspace. Argos estimates any required shielding first, then a final sweep to the destination Unified Address."
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
) -> ZeckResult<Vec<TxBroadcastResult>> {
    let destination = validate_destination_address(&request.destination)?;
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

    let seed = mnemonic_seed(&runtime.seed_phrase)?;
    let transparent_account =
        legacy_transparent_account_key(&runtime.seed_phrase, runtime.network)?;
    let network = consensus_network(runtime.network);
    let destination_address =
        ZcashAddress::try_from_encoded(&destination.encoded).map_err(|err| {
            ZeckError::InvalidAddress(format!(
                "failed to decode destination Unified Address: {err}"
            ))
        })?;
    let prover = LocalTxProver::bundled();
    let mut total_fee_zatoshis = 0u64;
    let mut results = Vec::new();

    // Testnet kill-switch: forces the donation feature off.
    let effective_donation_address =
        if matches!(runtime.network, crate::models::ZeckNetwork::Testnet) {
            ""
        } else {
            crate::donation::DONATION_ADDRESS
        };
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
    let (mut client, _) =
        connect_lightwalletd_endpoints(&runtime.lightwalletd_url, preferred_endpoint).await?;
    let lightwalletd_info = client
        .get_lightd_info(zcash_client_backend::proto::service::Empty {})
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    validate_lightwalletd_network(runtime.network, &lightwalletd_info)?;

    run_wallet_sync(&workspace, &network, &mut client).await?;
    refresh_scan_progress(
        &session.state,
        &workspace,
        runtime.network,
        runtime.birthday.min(chain_tip_height(&mut client).await?),
    )
    .await?;

    for tracked_account in tracked_accounts {
        if account_total_zatoshis(
            &workspace,
            runtime.network,
            tracked_account.wallet_account_id,
        )? == 0
        {
            continue;
        }

        let zip32_index =
            zip32::AccountId::try_from(tracked_account.derived.index).map_err(|_| {
                ZeckError::InvalidConfig(format!(
                    "account index {} is out of range",
                    tracked_account.derived.index
                ))
            })?;
        let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), zip32_index).map_err(|err| {
            ZeckError::Wallet(format!(
                "deriving account {}: {err}",
                tracked_account.derived.index
            ))
        })?;

        let transparent_balance =
            account_transparent_zatoshis(&workspace, runtime.network, &tracked_account)?;
        if transparent_balance > 0 {
            let fee = {
                let mut ctx = SweepStepCtx {
                    workspace: &workspace,
                    network: runtime.network,
                    client: &mut client,
                    prover: &prover,
                    results: &mut results,
                    prior_fee_zatoshis: total_fee_zatoshis,
                    max_fee_zatoshis: request.max_fee_zatoshis,
                    donation_address: effective_donation_address,
                    donation_rate: request.donation_rate,
                    donation_memo: donation_memo.clone(),
                };
                execute_shielding_step(
                    &mut ctx,
                    &tracked_account,
                    &transparent_account,
                    &usk,
                )
                .await?
            };
            // Step already enforced the cap against (prior + step fee) before broadcast;
            // recompute here purely to advance the running total for the next step.
            total_fee_zatoshis = checked_fee_total(total_fee_zatoshis, fee)?;

            if !last_account_confirmed(&results, tracked_account.derived.index) {
                continue;
            }

            run_wallet_sync(&workspace, &network, &mut client).await?;
            refresh_scan_progress(
                &session.state,
                &workspace,
                runtime.network,
                runtime.birthday.min(chain_tip_height(&mut client).await?),
            )
            .await?;
        }

        let fee = {
            let mut ctx = SweepStepCtx {
                workspace: &workspace,
                network: runtime.network,
                client: &mut client,
                prover: &prover,
                results: &mut results,
                prior_fee_zatoshis: total_fee_zatoshis,
                max_fee_zatoshis: request.max_fee_zatoshis,
                donation_address: effective_donation_address,
                donation_rate: request.donation_rate,
                donation_memo: donation_memo.clone(),
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
        // Step already enforced the cap against (prior + step fee) before broadcast;
        // recompute here purely to advance the running total for the next account.
        total_fee_zatoshis = checked_fee_total(total_fee_zatoshis, fee)?;

        // R-S29 hook: pause between per-account broadcasts so the test parent
        // can SIGKILL the helper subprocess deterministically in the gap. The
        // pause is unconditional; in production this is always None.
        if let Some(d) = pause_between_broadcasts {
            tokio::time::sleep(d).await;
        }
    }

    Ok(results)
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
}

/// The change strategy used for every Argos proposal: ZIP-317 fees, no change
/// memo, Orchard as the fallback change pool, default dust handling. Extracted
/// so the shielding step and the donation-split step cannot drift apart.
fn standard_zip317_change_strategy<I>() -> SingleOutputChangeStrategy<I> {
    SingleOutputChangeStrategy::<I>::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedProtocol::Orchard,
        DustOutputPolicy::default(),
    )
}

async fn execute_shielding_step(
    ctx: &mut SweepStepCtx<'_>,
    tracked_account: &TrackedAccount,
    transparent_account: &zcash_transparent::keys::AccountPrivKey,
    usk: &UnifiedSpendingKey,
) -> ZeckResult<u64> {
    let mut wallet_db =
        open_wallet_db(ctx.workspace.wallet_db_path(), consensus_network(ctx.network))?;
    let input_selector = GreedyInputSelector::<_>::new();
    let change_strategy = standard_zip317_change_strategy();

    let proposal = propose_shielding::<_, _, _, _, Infallible>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        &input_selector,
        &change_strategy,
        Zatoshis::ZERO,
        &tracked_account.transparent_receivers,
        tracked_account.wallet_account_id,
        ConfirmationsPolicy::MIN,
        TransparentOutputFilter::All,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("building shielding proposal: {err}")))?;
    let fee_zatoshis = proposal_fee_zatoshis(&proposal)?;
    enforce_max_fee(
        checked_fee_total(ctx.prior_fee_zatoshis, fee_zatoshis)?,
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
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating shielding transaction: {err}")))?;

    broadcast_transactions(
        &mut wallet_db,
        ctx.client,
        tracked_account.derived.index,
        txids.into_iter().collect(),
        "shielding",
        ctx.results,
    )
    .await?;

    Ok(fee_zatoshis)
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
    account_index: u32,
) -> P {
    match split_result {
        Ok(Some(proposal)) => proposal,
        Ok(None) => max_proposal,
        Err(err) => {
            tracing::warn!(
                "donation split proposal failed for account {account_index}: {err}; \
                 falling back to donation-free sweep for this account",
            );
            max_proposal
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
    // matches the proposal's computed fee. The extra output adds at most one
    // ZIP-317 marginal action, so this converges in <=2 iterations.
    let mut candidate_fee = send_max_fee;
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
        let proposal = propose_transfer::<_, _, _, _, Infallible>(
            wallet_db,
            &consensus_network(network),
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("building donation sweep proposal: {err}"))
        })?;
        let fee = proposal_fee_zatoshis(&proposal)?;
        if fee == candidate_fee {
            return Ok(Some(proposal));
        }
        candidate_fee = fee;
    }
    Ok(None)
}

async fn execute_send_max_step(
    ctx: &mut SweepStepCtx<'_>,
    tracked_account: &TrackedAccount,
    usk: &UnifiedSpendingKey,
    destination_address: &ZcashAddress,
    memo_bytes: Option<MemoBytes>,
) -> ZeckResult<u64> {
    let mut wallet_db =
        open_wallet_db(ctx.workspace.wallet_db_path(), consensus_network(ctx.network))?;

    // Pass 1 — measure the full-account send-max proposal (build only, no broadcast).
    let max_proposal = propose_send_max_transfer::<_, _, _, Infallible>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        tracked_account.wallet_account_id,
        &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard],
        &StandardFeeRule::Zip317,
        destination_address.clone(),
        memo_bytes.clone(),
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::MIN,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("building sweep proposal: {err}")))?;
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

    let donation =
        crate::donation::donation_for_send_amount(ctx.donation_address, ctx.donation_rate, send_amount);

    let proposal = if donation == 0 {
        // No donation output: behavior is unchanged from the single-pass sweep.
        max_proposal
    } else {
        let donation_zcash_address = ZcashAddress::try_from_encoded(ctx.donation_address)
            .map_err(|err| {
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
            tracked_account.derived.index,
        )
    };

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
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating sweep transaction: {err}")))?;

    broadcast_transactions(
        &mut wallet_db,
        ctx.client,
        tracked_account.derived.index,
        txids.into_iter().collect(),
        "sweep",
        ctx.results,
    )
    .await?;

    Ok(fee_zatoshis)
}

async fn broadcast_transactions(
    wallet_db: &mut WalletDb<
        rusqlite::Connection,
        zcash_protocol::consensus::Network,
        SystemClock,
        rand_core::OsRng,
    >,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    account_index: u32,
    txids: Vec<TxId>,
    label: &str,
    results: &mut Vec<TxBroadcastResult>,
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

        let (status, detail, confirmed_height) =
            wait_for_confirmation(wallet_db, client, txid, label).await?;
        results.push(TxBroadcastResult {
            source_account: account_index,
            txid: Some(txid.to_string()),
            status,
            detail,
            confirmed_height,
        });
    }

    Ok(())
}

async fn wait_for_confirmation(
    wallet_db: &mut WalletDb<
        rusqlite::Connection,
        zcash_protocol::consensus::Network,
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
                    return Ok((
                        "confirmed".to_owned(),
                        format!("{label} transaction mined at height {mined_height}."),
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
                "actual fee {} zats exceeds limit {} zats",
                total_fee_zatoshis, max_fee_zatoshis
            )));
        }
    }

    Ok(())
}

fn last_account_confirmed(results: &[TxBroadcastResult], account_index: u32) -> bool {
    results
        .iter()
        .rev()
        .find(|result| result.source_account == account_index)
        .map(|result| result.status == "confirmed")
        .unwrap_or(true)
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

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::build_sweep_proposal;
    use crate::{
        derive_accounts,
        error::ZeckError,
        models::{
            AccountBalancePreview, ProposedTxKind, ScanHandle, ScanPhase, ScanProgress,
            SweepRequest, ZeckNetwork,
        },
    };

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
        assert_eq!(sweep.net_zatoshis + sweep.fee_zatoshis, sweep.gross_zatoshis);
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
                destination: derived_destination(),
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
        let got = super::donation_proposal_or_fallback::<&str>(
            Ok(Some("donation-split")),
            "donation-free-max",
            0,
        );
        assert_eq!(got, "donation-split");
    }

    #[test]
    fn donation_fallback_ok_none_returns_max() {
        let got = super::donation_proposal_or_fallback::<&str>(
            Ok(None),
            "donation-free-max",
            0,
        );
        assert_eq!(got, "donation-free-max");
    }

    #[test]
    fn donation_fallback_err_returns_max() {
        // The critical safety property: an Err must NOT propagate. The user's
        // sweep proceeds donation-free. Pre-fix, an Err here aborted the
        // entire sweep — see PR #66 review (Kristi, 2026-05-28).
        let got = super::donation_proposal_or_fallback::<&str>(
            Err(ZeckError::TransactionBuild("synthetic regression".to_owned())),
            "donation-free-max",
            42,
        );
        assert_eq!(got, "donation-free-max");
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
            assert!(s.donation_zatoshis < s.net_zatoshis,
                "donation must remain strictly below net so user receives positive remainder");
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
