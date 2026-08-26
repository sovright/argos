use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::crypto::ring::default_provider;
use secrecy::SecretVec;
use tokio::sync::Mutex;
use tonic::{
    body::Body as TonicBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::warn;
use zcash_client_backend::{
    data_api::{
        chain::{error::Error as ChainError, BlockCache, BlockSource},
        scanning::ScanRange,
        wallet::{input_selection::LockFilter, ConfirmationsPolicy},
        Account as _, AccountBirthday, CoinbaseFilter, InputSource, WalletRead, WalletWrite,
        Zip32Derivation,
    },
    proto::{
        compact_formats::CompactBlock,
        service::{
            compact_tx_streamer_client::CompactTxStreamerClient, BlockId, Empty,
            GetAddressUtxosArg, LightdInfo,
        },
    },
    sync,
};
use zcash_client_sqlite::AccountUuid;
use zcash_protocol::consensus::BlockHeight;
use zcash_transparent::address::TransparentAddress;
use zip32::{fingerprint::SeedFingerprint, AccountId};

use crate::{
    derivation::{
        derive_accounts_from_seed, legacy_transparent_account_key_from_seed,
        legacy_transparent_pubkey,
    },
    error::{ZeckError, ZeckResult},
    lightwalletd::{
        build_probe, describe_lightwalletd_endpoints, validate_lightwalletd_network,
        validated_lightwalletd_endpoints,
    },
    models::{
        in_sandblasting_zone, AccountBalancePreview, AddressScope, DerivedAccount, DiscoveryPool,
        GapExtension, LightwalletdProbe, RuntimeScanConfig, ScanDiscovery, ScanHandle, ScanPhase,
        ScanProgress, ScanSummary, SleepEvent,
    },
    workspace::{
        consensus_network, mark_session_completed, open_wallet_db, touch_session_last_run,
        write_session_metadata, RecoveryWorkspace, SessionMetadata,
    },
};

/// Best-effort wall-clock for sidecar timestamps. Returns 0 if the system
/// clock is set before the Unix epoch (the sidecar is not security-relevant
/// and a wrong timestamp is not worth surfacing as an error to the user).
fn now_epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const MAX_ACCOUNT_SCAN_COUNT: u32 = 500;
const SYNC_BATCH_SIZE: u32 = 1_000;

#[derive(Debug)]
enum CacheError {
    MissingBlock(BlockHeight),
    Corrupted(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBlock(height) => write!(f, "missing compact block at height {height}"),
            Self::Corrupted(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for CacheError {}

/// In-memory block cache that holds at most one scan batch (~1,000 blocks).
/// `sync::run` deletes each range immediately after scanning, so no more than
/// one batch is ever live. This eliminates all cache.sqlite I/O: the protobuf
/// encode/decode cycles, fsyncs, and incremental-vacuum work that the
/// `SqliteBlockCache` predecessor required.
struct MemoryBlockCache(StdMutex<std::collections::BTreeMap<u32, CompactBlock>>);

impl MemoryBlockCache {
    fn new() -> Self {
        Self(StdMutex::new(std::collections::BTreeMap::new()))
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, std::collections::BTreeMap<u32, CompactBlock>>, CacheError>
    {
        self.0
            .lock()
            .map_err(|_| CacheError::Corrupted("block cache mutex was poisoned".to_owned()))
    }
}

impl BlockSource for MemoryBlockCache {
    type Error = CacheError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_row: F,
    ) -> Result<(), ChainError<DbErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<DbErrT, Self::Error>>,
    {
        fn to_chain_error<DbErrT>(err: CacheError) -> ChainError<DbErrT, CacheError> {
            ChainError::BlockSource(err)
        }

        let start_height = from_height.map_or(0u32, u32::from);
        let row_limit = limit.unwrap_or(usize::MAX);
        let guard = self.lock().map_err(to_chain_error)?;

        let mut expected = from_height;
        for (&height, block) in guard.range(start_height..).take(row_limit) {
            let height = BlockHeight::from_u32(height);
            if let Some(expected_height) = expected {
                if height != expected_height {
                    return Err(to_chain_error(CacheError::MissingBlock(expected_height)));
                }
            }
            with_row(block.clone())?;
            expected = expected.map(|h| h + 1);
        }

        if let Some(expected_height) = expected {
            if expected_height == from_height.unwrap_or(BlockHeight::from_u32(start_height)) {
                return Err(to_chain_error(CacheError::MissingBlock(expected_height)));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemoryBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let (start_height, end_height) = range
            .map(|r| {
                (
                    u32::from(r.block_range().start),
                    u32::from(r.block_range().end),
                )
            })
            .unwrap_or((0, u32::MAX));
        Ok(self
            .lock()?
            .range(start_height..end_height)
            .next_back()
            .map(|(&height, _)| BlockHeight::from_u32(height)))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let start = range.block_range().start;
        let end = range.block_range().end;
        let guard = self.lock()?;
        let mut blocks = Vec::new();
        let mut expected = start;
        for (&height, block) in guard.range(u32::from(start)..u32::from(end)) {
            let height = BlockHeight::from_u32(height);
            if height != expected {
                if blocks.is_empty() {
                    return Err(CacheError::MissingBlock(expected));
                }
                break;
            }
            blocks.push(block.clone());
            expected = expected + 1;
        }
        Ok(blocks)
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut guard = self.lock()?;
        for block in compact_blocks {
            guard.insert(u32::from(block.height()), block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let start = u32::from(range.block_range().start);
        let end = u32::from(range.block_range().end);
        let mut guard = self.lock()?;
        // `BTreeMap` has no remove-range; `split_off` twice removes
        // `[start, end)` without visiting unrelated entries.
        let mut tail = guard.split_off(&start);
        let keep = tail.split_off(&end);
        guard.extend(keep);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TrackedAccount {
    pub wallet_account_id: AccountUuid,
    pub derived: DerivedAccount,
    pub transparent_receivers: Vec<TransparentAddress>,
}

#[derive(Debug)]
pub struct ScanTaskState {
    pub progress: ScanProgress,
    pub cancelled: Arc<AtomicBool>,
    pub workspace: Option<RecoveryWorkspace>,
    pub tracked_accounts: Vec<TrackedAccount>,
}

impl ScanTaskState {
    pub fn new(handle: ScanHandle) -> Self {
        Self {
            progress: ScanProgress {
                handle,
                phase: ScanPhase::Idle,
                blocks_scanned: 0,
                blocks_total: 0,
                synced_to_height: None,
                elapsed_seconds: None,
                estimated_remaining_seconds: None,
                accounts: vec![],
                discoveries: vec![],
                summary: None,
                server: None,
                message: None,
                error: None,
                sleep_event: None,
                in_sandblasting_zone: false,
                gap_extension: None,
            },
            cancelled: Arc::new(AtomicBool::new(false)),
            workspace: None,
            tracked_accounts: vec![],
        }
    }
}

pub type SharedScanTaskState = Arc<Mutex<ScanTaskState>>;

struct ProgressPoller {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl ProgressPoller {
    fn start(
        workspace: RecoveryWorkspace,
        network: crate::models::ZeckNetwork,
        state: SharedScanTaskState,
        effective_birthday: u32,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let task = tokio::spawn(async move {
            let scan_started = std::time::Instant::now();
            // Sleep detection: each tick records (Instant, SystemTime). If
            // wall-clock advances much more than the monotonic delta between
            // two consecutive ticks, the OS almost certainly suspended us.
            // Threshold of 30s avoids false positives from scheduler hiccups
            // while still catching the shortest realistic suspend.
            const SLEEP_DETECTION_THRESHOLD: std::time::Duration =
                std::time::Duration::from_secs(30);
            let mut last_tick: Option<(std::time::Instant, std::time::SystemTime)> = None;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let now_mono = std::time::Instant::now();
                let now_wall = std::time::SystemTime::now();
                // The sleep gap is what wall-clock advanced *beyond* the
                // monotonic delta — i.e. the time the process was paused.
                let sleep_gap = match last_tick {
                    Some((prev_mono, prev_wall)) => {
                        let mono_delta = now_mono.saturating_duration_since(prev_mono);
                        let wall_delta = now_wall
                            .duration_since(prev_wall)
                            .unwrap_or(std::time::Duration::ZERO);
                        let gap = wall_delta.saturating_sub(mono_delta);
                        if gap >= SLEEP_DETECTION_THRESHOLD {
                            Some((prev_wall, gap))
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                last_tick = Some((now_mono, now_wall));

                let scanned_height = if let Ok(db) =
                    open_wallet_db(workspace.wallet_db_path(), consensus_network(network))
                {
                    db.get_wallet_summary(ConfirmationsPolicy::MIN)
                        .ok()
                        .flatten()
                        .map(|s| u32::from(s.fully_scanned_height()))
                } else {
                    None
                };

                let mut guard = state.lock().await;
                if let Some(scanned_height) = scanned_height {
                    guard.progress.blocks_scanned = block_delta(scanned_height, effective_birthday);
                    guard.progress.synced_to_height = Some(u64::from(scanned_height));
                    // Store scan-phase elapsed so get_scan_progress can compute an
                    // accurate rate that excludes pre-scan phases (seed validation,
                    // key derivation, lightwalletd probing).
                    guard.progress.elapsed_seconds = Some(scan_started.elapsed().as_secs());
                    guard.progress.in_sandblasting_zone =
                        in_sandblasting_zone(scanned_height, network);
                }
                if let Some((slept_at, gap)) = sleep_gap {
                    let last_seconds = gap.as_secs();
                    let slept_at_unix = slept_at
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let resumed_at_unix = now_wall
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let event = guard.progress.sleep_event.get_or_insert(SleepEvent {
                        slept_at_unix,
                        resumed_at_unix,
                        last_sleep_seconds: 0,
                        total_lost_seconds: 0,
                        event_count: 0,
                    });
                    event.slept_at_unix = slept_at_unix;
                    event.resumed_at_unix = resumed_at_unix;
                    event.last_sleep_seconds = last_seconds;
                    event.total_lost_seconds =
                        event.total_lost_seconds.saturating_add(last_seconds);
                    event.event_count = event.event_count.saturating_add(1);
                }
            }
        });
        Self { stop, task }
    }

    async fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.task.await;
    }
}

pub async fn run_recovery_scan(state: SharedScanTaskState, config: RuntimeScanConfig) {
    match run_recovery_scan_inner(state.clone(), config).await {
        Ok(()) | Err(ZeckError::Cancelled) => {}
        Err(err) => {
            let mut guard = state.lock().await;
            guard.progress.phase = ScanPhase::Error;
            guard.progress.error = Some(err.to_string());
            guard.progress.message = Some(if guard.progress.accounts.is_empty() {
                "Recovery scan failed before any legacy addresses were derived.".to_owned()
            } else if guard.progress.server.is_none() {
                "Legacy addresses were derived locally, but lightwalletd probing failed before shielded recovery could begin."
                    .to_owned()
            } else {
                "Partial results are shown below, but the recovery scan ended before the wallet workspace finished syncing."
                    .to_owned()
            });
        }
    }
}

async fn run_recovery_scan_inner(
    state: SharedScanTaskState,
    config: RuntimeScanConfig,
) -> ZeckResult<()> {
    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ValidatingSeed;
        guard.progress.message = Some(format!(
            "Validating keys from {}.",
            config.key_source.describe()
        ));
    }

    // Every account slot the HD scanner walks is derived from a seed. A
    // key source without one is scanned by `run_imported_scan` instead,
    // which registers the wallet file's own keys as accounts.
    //
    // A source with neither a seed nor importable keys is refused rather
    // than scanned as zero accounts: a successful-but-empty scan is the
    // failure mode a user recovering real funds would most easily mistake
    // for an answer.
    let seed = match config.key_source.wallet_seed()? {
        Some(seed) => seed,
        None => {
            let keys = config.key_source.imported_keys().ok_or_else(|| {
                ZeckError::InvalidConfig(format!(
                    "{} has no HD seed and no importable keys, so there is nothing to scan.",
                    config.key_source.describe()
                ))
            })?;
            // This branch used to refuse with a message naming the
            // transparent-only path — which only the CLI implemented, at its
            // own front end. The GUI handed the same wallet straight here and
            // showed the user that refusal, telling them their recoverable
            // funds were unrecoverable. A transparent-only `wallet.dat` is the
            // most common legacy zcashd shape, so that was the default
            // experience for it.
            //
            // Scope, stated honestly: this fixes the GUI. The CLI still
            // dispatches transparent-only at its own front end
            // (`main.rs`, `is_transparent_only`) and returns through
            // `print_transparent_report`, so it never reaches this match. The
            // *predicate* is shared — both sides classify through
            // `classify_recovery_route` — but the scan invocation is not, and
            // the two produce different observable output. Routing the CLI
            // through here would change what it prints, so it is a deliberate
            // follow-up rather than something this branch quietly did.
            match crate::key_source::classify_recovery_route(keys) {
                crate::key_source::RecoveryRoute::TransparentOnly => {
                    return run_transparent_only_scan(state, &config, keys).await;
                }
                crate::key_source::RecoveryRoute::Nothing => {
                    return Err(ZeckError::InvalidConfig(format!(
                        "{} contains no transparent or Sapling keys, so there is nothing \
                         to scan.",
                        config.key_source.describe()
                    )));
                }
                // A mnemonic would have produced a seed above, so `Hd` is
                // unreachable here; `ImportedAccounts` falls through.
                _ => {}
            }
            return run_imported_scan(state, &config, keys).await;
        }
    };
    let workspace = RecoveryWorkspace::from_runtime(&config)?;
    workspace.initialize(config.network, &seed)?;
    let transparent_account = legacy_transparent_account_key_from_seed(config.network, &seed)?;

    // Sidecar v1: written once we have a workspace on disk and before any
    // long-running probe/sync work. `target_height` is unknown until the
    // lightwalletd probe succeeds, so it starts as `None` and is filled in
    // below. An interrupted scan that never reached the probe still surfaces
    // in the launch-time list, just without progress numbers.
    let session_label = if config.label.trim().is_empty() {
        "(unlabeled scan)".to_owned()
    } else {
        config.label.clone()
    };
    if let Err(err) = write_session_metadata(
        workspace.root(),
        &SessionMetadata::new_in_progress(
            session_label.clone(),
            config.network,
            config.birthday,
            None,
            now_epoch_seconds(),
        ),
    ) {
        warn!("failed to write initial session sidecar (continuing): {err}");
    }

    {
        let mut guard = state.lock().await;
        guard.workspace = Some(workspace.clone());
    }

    let max_accounts = resolve_max_account_count(&config)?;
    let mut imported_accounts = 0u32;
    let mut target_accounts = initial_batch_size(&config, max_accounts);
    let mut gap_extension_pass = 0u32;
    let network = consensus_network(config.network);
    let initial_accounts = derive_accounts_from_seed(&seed, config.network, target_accounts)?;

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::DerivingKeys;
        guard.progress.message = Some(format!(
            "Derived {target_accounts} ZecWallet Lite-compatible account slots locally. Checking lightwalletd next."
        ));
    }
    initialize_accounts(&state, &initial_accounts).await;

    let configured_endpoints = describe_lightwalletd_endpoints(&config.lightwalletd_url);

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ProbingLightwalletd;
        guard.progress.message = Some(format!(
            "Connecting to {configured_endpoints} and checking chain metadata.",
        ));
    }

    let _ = default_provider().install_default();
    let (mut client, endpoint, response) =
        probe_valid_lightwalletd_endpoints(&config.lightwalletd_url, config.network).await?;
    let chain_tip_height = u32::try_from(response.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let probe: LightwalletdProbe = build_probe(endpoint, &response);
    // Clamp birthday to sapling_activation_height + 1 so we never request a
    // pre-Sapling treestate (block 419199 and earlier have no Sapling tree).
    let sapling_floor = u32::try_from(response.sapling_activation_height)
        .unwrap_or(419_201)
        .saturating_add(1);
    let effective_birthday = config.birthday.max(sapling_floor).min(chain_tip_height);
    let birthday_treestate = client
        .get_tree_state(BlockId {
            height: u64::from(effective_birthday.saturating_sub(1)),
            hash: vec![],
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    let account_birthday = AccountBirthday::from_treestate(
        birthday_treestate,
        Some(BlockHeight::from_u32(chain_tip_height)),
    )
    .map_err(|_| ZeckError::Wallet("constructing account birthday from treestate".to_owned()))?;

    {
        let mut guard = state.lock().await;
        guard.progress.server = Some(probe);
        guard.progress.blocks_total = block_delta(chain_tip_height, effective_birthday);
    }

    // Update the sidecar with the chain tip we just observed so the resume
    // UI can show "scanned X / Y" instead of "scanned X / ?". Best-effort.
    if let Err(err) = write_session_metadata(
        workspace.root(),
        &SessionMetadata::new_in_progress(
            session_label.clone(),
            config.network,
            config.birthday,
            Some(chain_tip_height),
            now_epoch_seconds(),
        ),
    ) {
        warn!("failed to update session sidecar with target height (continuing): {err}");
    }

    while imported_accounts < target_accounts {
        check_cancelled(&state).await?;

        {
            let mut guard = state.lock().await;
            guard.progress.phase = ScanPhase::DerivingKeys;
            guard.progress.message = Some(format!(
                "Preparing legacy account slots 0 through {}.",
                target_accounts.saturating_sub(1)
            ));
        }

        let derived_accounts = derive_accounts_from_seed(&seed, config.network, target_accounts)?;
        initialize_accounts(&state, &derived_accounts).await;

        // Fast transparent-only probe over the newly-added slice for this
        // iteration. lightwalletd's GetAddressUtxos answers in milliseconds
        // and surfaces preliminary t-addr balances long before the shielded
        // sync finishes. Probing per gap-extension iteration (rather than
        // only the first batch) means a funded account that only appears
        // after gap extension still gets the early-discovery UX.
        //
        // Safety: the probe dedupes its discovery pushes against the
        // existing log, and we slice to only the newly-derived range, so
        // repeated calls don't produce duplicate events. Failures are
        // non-fatal — the shielded scan below is authoritative.
        let new_slice_start = usize::try_from(imported_accounts)
            .map_err(|_| ZeckError::Internal("account index overflowed usize".to_owned()))?;
        let new_slice_end = usize::try_from(target_accounts)
            .map_err(|_| ZeckError::Internal("account index overflowed usize".to_owned()))?;
        let new_accounts = &derived_accounts[new_slice_start..new_slice_end];
        if let Err(err) =
            run_transparent_quick_probe(&state, &mut client, new_accounts, chain_tip_height).await
        {
            warn!("transparent quick probe failed (continuing with shielded scan): {err}");
        }

        import_accounts(
            &workspace,
            config.network,
            &seed,
            &account_birthday,
            &transparent_account,
            &derived_accounts[usize::try_from(imported_accounts)
                .map_err(|_| ZeckError::Internal("account index overflowed usize".to_owned()))?
                ..usize::try_from(target_accounts).map_err(|_| {
                    ZeckError::Internal("account index overflowed usize".to_owned())
                })?],
            &state,
        )
        .await?;
        imported_accounts = target_accounts;

        {
            let mut guard = state.lock().await;
            guard.progress.phase = ScanPhase::ScanningShielded;
            guard.progress.message = Some(format!(
                "Syncing compact blocks and transparent UTXOs for {imported_accounts} imported legacy account slots."
            ));
        }

        let poller = ProgressPoller::start(
            workspace.clone(),
            config.network,
            state.clone(),
            effective_birthday,
        );
        let sync_result = run_wallet_sync_with_retry(
            &workspace,
            &network,
            config.network,
            &mut client,
            &config.lightwalletd_url,
            &state,
        )
        .await;
        poller.stop().await;
        sync_result?;
        refresh_scan_progress(&state, &workspace, config.network, effective_birthday).await?;

        if config.num_accounts.is_some() || imported_accounts == max_accounts {
            break;
        }

        let should_stop = {
            let guard = state.lock().await;
            trailing_gap_limit_reached(&guard.progress.accounts, config.gap_limit)
        };
        if should_stop {
            break;
        }

        // Funds were found near the trailing edge, so widen the search and
        // scan the chain again for the new accounts. Publish a descriptor of
        // the widening before the next pass resets the block counter, so the
        // UI can explain the restart rather than let it read as a fault.
        let new_target = (target_accounts + config.gap_limit).min(max_accounts);
        gap_extension_pass += 1;
        {
            let mut guard = state.lock().await;
            let extension = describe_gap_extension(
                &guard.progress.accounts,
                target_accounts,
                new_target,
                gap_extension_pass,
            );
            guard.progress.gap_extension = extension;
        }
        target_accounts = new_target;
    }

    finish_scan(&state, &workspace).await
}

/// Publish the terminal state of a completed scan.
///
/// Shared by the HD and imported paths so the two cannot drift on what a
/// finished scan looks like — the summary, the total, and the sidecar flip
/// that stops the resume list from re-offering this workspace.
async fn finish_scan(state: &SharedScanTaskState, workspace: &RecoveryWorkspace) -> ZeckResult<()> {
    let (workspace_dir, total_zatoshis) = {
        let guard = state.lock().await;
        let total = guard
            .progress
            .accounts
            .iter()
            .try_fold(0u64, |sum, account| {
                sum.checked_add(account.total_zatoshis).ok_or_else(|| {
                    ZeckError::Internal("recovery total overflowed the supported range".to_owned())
                })
            })?;
        let workspace_dir = guard
            .workspace
            .as_ref()
            .map(|workspace| workspace.root().display().to_string())
            .unwrap_or_default();
        (workspace_dir, total)
    };

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::Complete;
        guard.progress.summary = Some(ScanSummary {
            total_zatoshis,
            authoritative_balances: true,
            note: if total_zatoshis > 0 {
                "Compact-block recovery finished. Transparent, Sapling, and Orchard balances now come from the persisted wallet workspace and are ready for sweep planning."
                    .to_owned()
            } else {
                "Compact-block recovery finished, but no spendable funds were found in the scanned legacy account range."
                    .to_owned()
            },
            workspace_dir,
        });
        guard.progress.message = Some(
            "Recovery scan finished. Review the authoritative per-account balances and continue to the sweep step when you are ready."
                .to_owned(),
        );
    }

    // Flip the sidecar to `completed: true` so the launch-time resume list
    // stops surfacing this workspace. Best-effort: a failure here doesn't
    // affect the scan outcome, only the next launch's UI.
    if let Err(err) = mark_session_completed(workspace.root(), now_epoch_seconds()) {
        warn!("failed to mark session sidecar completed (continuing): {err}");
    }

    Ok(())
}

fn resolve_max_account_count(config: &RuntimeScanConfig) -> ZeckResult<u32> {
    match config.num_accounts {
        Some(0) => Err(ZeckError::InvalidConfig(
            "num_accounts must be at least 1".to_owned(),
        )),
        Some(count) if count > MAX_ACCOUNT_SCAN_COUNT => Err(ZeckError::InvalidConfig(format!(
            "num_accounts must not exceed {MAX_ACCOUNT_SCAN_COUNT}"
        ))),
        Some(count) => Ok(count),
        None => Ok(MAX_ACCOUNT_SCAN_COUNT),
    }
}

fn initial_batch_size(config: &RuntimeScanConfig, max_accounts: u32) -> u32 {
    config
        .num_accounts
        .unwrap_or(config.gap_limit.min(max_accounts))
}

async fn initialize_accounts(state: &SharedScanTaskState, accounts: &[DerivedAccount]) {
    let mut guard = state.lock().await;
    let existing = std::mem::take(&mut guard.progress.accounts);
    guard.progress.accounts = merge_account_previews(existing, accounts);
}

/// Build the account snapshot for a (re-)derived account set, preserving any
/// already-populated rows instead of clobbering them back to zero previews.
///
/// The gap-limit loop re-derives the *full* account set on every extension
/// iteration and re-invokes [`initialize_accounts`] over all of it. A naive
/// rebuild would blank every account already refreshed in a prior batch back
/// to a zero-balance "Waiting for sync" preview — and, because the authoritative
/// refresh only runs *after* the next (potentially multi-hour) shielded batch
/// completes, the account table would show `0.00` for those accounts the whole
/// time. That contradicts the append-only discovery banner, which correctly and
/// permanently reports the funds found in the earlier batch.
///
/// Merging by `account_index` keeps the earlier authoritative balances (and
/// status) visible while seeding fresh zero previews only for genuinely-new
/// indices. Rows follow the freshly-derived account order; any preview whose
/// index is no longer in the derived set is dropped.
fn merge_account_previews(
    existing: Vec<AccountBalancePreview>,
    accounts: &[DerivedAccount],
) -> Vec<AccountBalancePreview> {
    let mut existing: std::collections::HashMap<u32, AccountBalancePreview> = existing
        .into_iter()
        .map(|preview| (preview.account_index, preview))
        .collect();
    accounts
        .iter()
        .map(|account| {
            existing
                .remove(&account.index)
                .unwrap_or_else(|| build_account_preview(account))
        })
        .collect()
}

fn build_account_preview(account: &DerivedAccount) -> AccountBalancePreview {
    AccountBalancePreview {
        account_index: account.index,
        sapling_address: account.sapling_address.clone(),
        unified_address: account.unified_address.clone(),
        transparent_receive_address: account.transparent_receive_address.clone(),
        transparent_change_address: account.transparent_change_address.clone(),
        transparent_utxo_count: 0,
        sapling_zatoshis: 0,
        orchard_zatoshis: 0,
        transparent_zatoshis: 0,
        total_zatoshis: 0,
        has_activity: false,
        status: "Derived locally. Waiting for wallet workspace sync.".to_owned(),
    }
}

/// Create the workspace and record the session, before any network work.
///
/// The counterpart to `finish_scan`, which was factored out "so the two
/// cannot drift" while the matching preamble never was — so each new scan
/// route re-derived it, and `run_transparent_only_scan` re-derived it wrong:
/// it created the workspace *after* the network call and never wrote the
/// in-progress sidecar, so an interrupted or failed transparent-only scan
/// left nothing behind and never appeared in the resume list.
///
/// Ordering is the point. The sidecar is written before the probe, with
/// `target_height` still unknown, so a scan that dies at the network is still
/// listed rather than vanishing.
async fn begin_scan_session(
    state: &SharedScanTaskState,
    config: &RuntimeScanConfig,
) -> ZeckResult<RecoveryWorkspace> {
    let workspace = RecoveryWorkspace::from_runtime(config)?;
    workspace.initialize_from_source(config.network, config.key_source.as_ref())?;
    {
        let mut guard = state.lock().await;
        guard.workspace = Some(workspace.clone());
    }

    let session_label = if config.label.trim().is_empty() {
        "(unlabeled scan)".to_owned()
    } else {
        config.label.clone()
    };
    if let Err(err) = write_session_metadata(
        workspace.root(),
        &SessionMetadata::new_in_progress(
            session_label,
            config.network,
            config.birthday,
            None,
            now_epoch_seconds(),
        ),
    ) {
        warn!("failed to write initial session sidecar (continuing): {err}");
    }

    Ok(workspace)
}

/// Scan a wallet file whose keys have no HD seed behind them.
///
/// Deliberately not the HD loop: there are no account slots to enumerate
/// and no gap to extend. The key set is fixed and fully known the moment
/// the file is parsed, so every account is registered once and the chain
/// is scanned once.
///
/// Transparent keys are covered here too, without a second pass: they are
/// attached to the first account as standalone receivers, so
/// `zcash_client_sqlite` scans them alongside the shielded notes.
async fn run_imported_scan(
    state: SharedScanTaskState,
    config: &RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
) -> ZeckResult<()> {
    use crate::imported::{
        imported_account_display, imported_transparent_keys, register_imported_accounts,
    };

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::DerivingKeys;
        guard.progress.message = Some(format!(
            "Preparing {} imported Sapling account(s) and {} transparent key(s).",
            keys.sapling.len(),
            keys.transparent.len()
        ));
    }

    let workspace = begin_scan_session(&state, config).await?;
    let session_label = if config.label.trim().is_empty() {
        "(unlabeled scan)".to_owned()
    } else {
        config.label.clone()
    };

    let network = consensus_network(config.network);
    let configured_endpoints = describe_lightwalletd_endpoints(&config.lightwalletd_url);
    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ProbingLightwalletd;
        guard.progress.message = Some(format!(
            "Connecting to {configured_endpoints} and checking chain metadata."
        ));
    }

    let _ = default_provider().install_default();
    let (mut client, endpoint, response) =
        probe_valid_lightwalletd_endpoints(&config.lightwalletd_url, config.network).await?;
    let chain_tip_height = u32::try_from(response.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let probe: LightwalletdProbe = build_probe(endpoint, &response);
    let sapling_floor = u32::try_from(response.sapling_activation_height)
        .unwrap_or(419_201)
        .saturating_add(1);
    let effective_birthday = config.birthday.max(sapling_floor).min(chain_tip_height);
    let birthday_treestate = client
        .get_tree_state(BlockId {
            height: u64::from(effective_birthday.saturating_sub(1)),
            hash: vec![],
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    let account_birthday = AccountBirthday::from_treestate(
        birthday_treestate,
        Some(BlockHeight::from_u32(chain_tip_height)),
    )
    .map_err(|_| ZeckError::Wallet("constructing account birthday from treestate".to_owned()))?;

    {
        let mut guard = state.lock().await;
        guard.progress.server = Some(probe);
        guard.progress.blocks_total = block_delta(chain_tip_height, effective_birthday);
    }
    if let Err(err) = write_session_metadata(
        workspace.root(),
        &SessionMetadata::new_in_progress(
            session_label,
            config.network,
            config.birthday,
            Some(chain_tip_height),
            now_epoch_seconds(),
        ),
    ) {
        warn!("failed to update session sidecar with target height (continuing): {err}");
    }

    check_cancelled(&state).await?;

    // Register accounts, then describe them for the progress UI. Both are
    // driven off the same returned list, so what is scanned and what is
    // displayed cannot disagree.
    let registered = {
        let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), network)?;
        register_imported_accounts(&mut wallet_db, keys, &account_birthday)?
    };
    let resolved_transparent = imported_transparent_keys(keys)?;

    let mut displays = Vec::with_capacity(registered.len());
    let mut tracked = Vec::with_capacity(registered.len());
    for (position, account) in registered.iter().enumerate() {
        let index = u32::try_from(position)
            .map_err(|_| ZeckError::Internal("imported account index overflowed u32".to_owned()))?;
        let Some(extsk) = account.sapling_extsk.as_ref() else {
            continue;
        };
        let display = imported_account_display(
            index,
            extsk,
            account.transparent_addresses.first(),
            config.network,
        )?;
        displays.push(display.clone());
        tracked.push(TrackedAccount {
            wallet_account_id: account.wallet_account_id,
            derived: display,
            transparent_receivers: account.transparent_addresses.clone(),
        });
    }

    initialize_accounts(&state, &displays).await;
    {
        let mut guard = state.lock().await;
        guard.tracked_accounts.extend(tracked);
    }

    // Fast transparent answer before the shielded sync, exactly as the HD
    // path does — an imported wallet's transparent balance should not wait
    // on a full chain scan.
    if !resolved_transparent.is_empty() {
        if let Err(err) =
            run_imported_transparent_probe(&state, &mut client, &resolved_transparent, config).await
        {
            warn!("transparent quick probe failed (continuing with shielded scan): {err}");
        }
    }

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ScanningShielded;
        guard.progress.message = Some(format!(
            "Syncing compact blocks for {} imported account(s).",
            displays.len()
        ));
    }

    let poller = ProgressPoller::start(
        workspace.clone(),
        config.network,
        state.clone(),
        effective_birthday,
    );
    let sync_result = run_wallet_sync_with_retry(
        &workspace,
        &network,
        config.network,
        &mut client,
        &config.lightwalletd_url,
        &state,
    )
    .await;
    poller.stop().await;
    sync_result?;
    refresh_scan_progress(&state, &workspace, config.network, effective_birthday).await?;

    finish_scan(&state, &workspace).await
}

/// Preliminary transparent balances for an imported wallet.
///
/// Separate from `run_transparent_quick_probe`, which keys results by HD
/// account index. Every imported transparent key hangs off account 0, so
/// this folds the whole set into that one account.
/// Scan a wallet that has transparent keys and nothing else.
///
/// No workspace sync and no wallet database: ZIP-316 forbids a
/// transparent-only unified container, so there is no account to anchor and
/// nothing for the shielded scanner to walk. `GetAddressUtxos` answers the
/// whole question directly, which is also why this returns in seconds rather
/// than hours.
///
/// Reached by the GUI. The CLI has its own transparent-only dispatch in
/// `main.rs` and does not call this — the two share `classify_recovery_route`
/// but not the scan itself, so their output differs. Consolidating them means
/// changing what the CLI prints, which is a separate change; until then this
/// is one of two implementations, not the only one.
async fn run_transparent_only_scan(
    state: SharedScanTaskState,
    config: &RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
) -> ZeckResult<()> {
    let transparent = crate::imported::imported_transparent_keys(keys)?;

    // Before the network call, not after: a scan that dies at the endpoint
    // must still leave a session behind. This path used to create the
    // workspace only on success, so a failed transparent-only scan vanished.
    let workspace = begin_scan_session(&state, config).await?;

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ScanningTransparent;
        guard.progress.message = Some(format!(
            "Checking {} transparent address(es). This wallet has no shielded keys, so no \
             block scan is needed.",
            transparent.len()
        ));
    }

    let report = crate::transparent_recovery::scan_transparent_only(
        &transparent,
        config.network,
        &config.lightwalletd_url,
    )
    .await?;

    {
        let mut guard = state.lock().await;
        guard.progress.synced_to_height = Some(u64::from(report.chain_tip_height));

        // One preview row, because there is exactly one thing to report: this
        // key set's transparent total. The shielded fields stay zero and the
        // addresses stay empty rather than being filled with something
        // plausible — a wallet with no Sapling key has no Sapling address, and
        // inventing one would misrepresent what was searched.
        guard.progress.accounts = vec![crate::models::AccountBalancePreview {
            account_index: 0,
            sapling_address: String::new(),
            unified_address: String::new(),
            transparent_receive_address: report
                .funded
                .first()
                .map(|f| f.address.clone())
                .unwrap_or_default(),
            transparent_change_address: String::new(),
            transparent_utxo_count: report
                .funded
                .iter()
                .fold(0u32, |acc, f| acc.saturating_add(f.utxo_count)),
            sapling_zatoshis: 0,
            orchard_zatoshis: 0,
            transparent_zatoshis: report.total_zatoshis,
            total_zatoshis: report.total_zatoshis,
            has_activity: report.total_zatoshis > 0,
            status: format!(
                "{} transparent address(es) checked, {} funded",
                report.addresses_checked,
                report.funded.len()
            ),
        }];

        // Appended, never replaced: the pump loops in the CLI and Tauri emit
        // only the tail of this vector on each tick.
        for funded in &report.funded {
            guard.progress.discoveries.push(crate::models::ScanDiscovery {
                account_index: 0,
                pool: crate::models::DiscoveryPool::Transparent,
                zatoshis: funded.zatoshis,
                at_block_height: u64::from(report.chain_tip_height),
                address: funded.address.clone(),
            });
        }
    }

    finish_scan(&state, &workspace).await
}

async fn run_imported_transparent_probe(
    state: &SharedScanTaskState,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    keys: &[crate::imported::ImportedTransparentKey],
    config: &RuntimeScanConfig,
) -> ZeckResult<()> {
    use crate::transparent_recovery::fetch_transparent_utxos;

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ScanningTransparent;
        guard.progress.message = Some(format!(
            "Quick-checking {} imported transparent address(es)…",
            keys.len()
        ));
    }

    let utxos = fetch_transparent_utxos(client, keys, config.network).await?;
    if utxos.is_empty() {
        return Ok(());
    }

    let total = utxos.iter().fold(0u64, |acc, u| {
        acc.saturating_add(u64::from(u.txout.value()))
    });
    let count = u32::try_from(utxos.len()).unwrap_or(u32::MAX);

    let mut guard = state.lock().await;
    if let Some(account) = guard.progress.accounts.first_mut() {
        account.transparent_zatoshis = total;
        account.transparent_utxo_count = count;
        account.total_zatoshis = account
            .total_zatoshis
            .max(total.saturating_add(account.sapling_zatoshis))
            .max(total);
        account.has_activity = account.has_activity || total > 0;
    }
    Ok(())
}

async fn import_accounts(
    workspace: &RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    seed: &[u8; 64],
    birthday: &AccountBirthday,
    transparent_account: &zcash_transparent::keys::AccountPrivKey,
    accounts: &[DerivedAccount],
    state: &SharedScanTaskState,
) -> ZeckResult<()> {
    if accounts.is_empty() {
        return Ok(());
    }

    let seed_fingerprint = SeedFingerprint::from_seed(seed).ok_or_else(|| {
        ZeckError::Internal("mnemonic seed length is out of the ZIP 32 range".to_owned())
    })?;
    let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;

    let mut tracked_accounts = Vec::with_capacity(accounts.len());

    for account in accounts {
        let zip32_index = AccountId::try_from(account.index).map_err(|_| {
            ZeckError::InvalidConfig(format!("account index {} is out of range", account.index))
        })?;
        let derivation = Zip32Derivation::new(seed_fingerprint, zip32_index);
        let wallet_account_id = if let Some(existing) =
            wallet_db.get_derived_account(&derivation).map_err(|err| {
                ZeckError::Wallet(format!("loading derived account {}: {err}", account.index))
            })? {
            existing.id()
        } else {
            wallet_db
                .import_account_hd(
                    &format!("zwl_account_{}", account.index),
                    &SecretVec::new(seed.to_vec()),
                    zip32_index,
                    birthday,
                    Some("Argos ZecWallet Lite recovery"),
                )
                .map_err(|err| {
                    ZeckError::Wallet(format!("importing account {}: {err}", account.index))
                })?
                .0
                .id()
        };

        let external_pubkey =
            legacy_transparent_pubkey(transparent_account, AddressScope::External, account.index)?;
        let internal_pubkey =
            legacy_transparent_pubkey(transparent_account, AddressScope::Internal, account.index)?;
        let external_address = TransparentAddress::from_pubkey(&external_pubkey);
        let internal_address = TransparentAddress::from_pubkey(&internal_pubkey);
        let existing_receivers = wallet_db
            .get_transparent_receivers(wallet_account_id, true, true)
            .map_err(|err| {
                ZeckError::Wallet(format!(
                    "loading transparent receivers for account {}: {err}",
                    account.index
                ))
            })?;

        if !existing_receivers.contains_key(&external_address) {
            wallet_db
                .import_standalone_transparent_pubkey(wallet_account_id, external_pubkey)
                .map_err(|err| {
                    ZeckError::Wallet(format!(
                        "importing external transparent receiver for account {}: {err}",
                        account.index
                    ))
                })?;
        }
        if !existing_receivers.contains_key(&internal_address) {
            wallet_db
                .import_standalone_transparent_pubkey(wallet_account_id, internal_pubkey)
                .map_err(|err| {
                    ZeckError::Wallet(format!(
                        "importing internal transparent receiver for account {}: {err}",
                        account.index
                    ))
                })?;
        }

        tracked_accounts.push(TrackedAccount {
            wallet_account_id,
            derived: account.clone(),
            transparent_receivers: vec![external_address, internal_address],
        });
    }

    let mut guard = state.lock().await;
    guard.tracked_accounts.extend(tracked_accounts);
    Ok(())
}

const MAX_SYNC_RETRIES: u32 = 10;
const SYNC_RETRY_DELAY_SECS: u64 = 5;
/// Attempts for the initial lightwalletd probe (before the sync stream starts),
/// so a transient DNS/network blip at startup doesn't fail a recovery before it
/// begins. Reuses `SYNC_RETRY_DELAY_SECS` between attempts.
const INITIAL_PROBE_ATTEMPTS: u32 = 4;

/// Stall watchdog: how long we wait without seeing `synced_to_height` advance
/// before giving up on the current batch. 60 s comfortably exceeds:
///
///   - librustzcash's default ~100-block batch boundary (committed in one tick
///     even under the R-N13 300 ms/block latency profile = 30 s per batch),
///   - the R-N14 32 KB/s throttle's per-batch budget,
///   - the regtest harness's typical mid-scan ProgressPoller refresh cycle.
///
/// Every bound above is a *latency* bound, which is why this budget does not
/// hold inside the sandblasting window — see
/// [`SANDBLASTING_STALL_TIMEOUT_SECS`].
const STALL_TIMEOUT_SECS: u64 = 60;

/// Stall budget inside the sandblasting window
/// ([`SANDBLASTING_START_HEIGHT`]..=[`SANDBLASTING_END_HEIGHT`]).
///
/// Those blocks are packed with shielded outputs, so a batch there is bound by
/// local trial-decryption CPU rather than by network latency, and can run for
/// many minutes on ordinary hardware. [`STALL_TIMEOUT_SECS`] was calibrated
/// against the wrong bottleneck for this range.
///
/// Applying the normal budget here is not merely impatient, it is a livelock:
/// the retry restarts the batch from the last committed height, so a batch
/// needing longer than the budget is killed at the same point on every
/// attempt, the retry budget drains, and the scan can never cross the era.
/// A wallet with a pre-2023 birthday must cross it to be recovered at all.
const SANDBLASTING_STALL_TIMEOUT_SECS: u64 = 900;

/// How often the watchdog polls `synced_to_height`. 5 s keeps the cost
/// negligible and gives the watchdog 12 ticks before tripping.
const STALL_CHECK_INTERVAL_SECS: u64 = 5;

/// Returns a [`ZeckError`] when `synced_to_height` has not advanced for the
/// applicable budget. The returned future *only* resolves on stall — used
/// inside `tokio::select!` against the actual sync future.
///
/// The budget is [`STALL_TIMEOUT_SECS`], widened to
/// [`SANDBLASTING_STALL_TIMEOUT_SECS`] while the scan is inside the
/// sandblasting window. `progress.in_sandblasting_zone` is already maintained
/// by the [`ProgressPoller`] from the live scan height, so the budget tracks
/// the scan into and back out of the era on its own.
///
/// State lives entirely on the local stack: each call gets a fresh
/// `last_height` baseline. When the retry loop in
/// `run_wallet_sync_with_retry` reopens a connection, a new watchdog is
/// started, so a progress event on the previous attempt doesn't paper over
/// a stall on the next.
///
/// The error deliberately claims nothing about the network. All this watchdog
/// observes is that a batch stopped committing; a hung stream and a dense
/// block range are indistinguishable from here. It is classified as retryable
/// via the `"scan stalled"` token in
/// [`crate::lightwalletd::is_transient_network_error`] rather than by
/// impersonating a transport error.
async fn stall_watchdog(state: &SharedScanTaskState) -> ZeckError {
    let mut last_height: Option<u64> = None;
    let mut stalled_secs: u64 = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(STALL_CHECK_INTERVAL_SECS)).await;
        let (current, in_sandblasting_zone) = {
            let guard = state.lock().await;
            (
                guard.progress.synced_to_height,
                guard.progress.in_sandblasting_zone,
            )
        };
        let budget_secs = if in_sandblasting_zone {
            SANDBLASTING_STALL_TIMEOUT_SECS
        } else {
            STALL_TIMEOUT_SECS
        };
        match (last_height, current) {
            // First observation of a height: just record it. We do not count
            // the pre-progress phase (probing/connecting) toward the stall
            // budget — sync begins when the first block lands.
            (None, Some(h)) => {
                last_height = Some(h);
                stalled_secs = 0;
            }
            // Advancing — reset the counter.
            (Some(prev), Some(curr)) if curr != prev => {
                last_height = Some(curr);
                stalled_secs = 0;
            }
            // No advance (either still None, or stuck at the same height).
            _ => {
                stalled_secs = stalled_secs.saturating_add(STALL_CHECK_INTERVAL_SECS);
                if stalled_secs >= budget_secs {
                    let context = if in_sandblasting_zone {
                        " (scanning the 2022–2023 sandblasting range, where blocks are \
                          dense and batches are slow)"
                    } else {
                        ""
                    };
                    return ZeckError::ScanStalled(format!(
                        "no block committed for {budget_secs}s{context}; reconnecting"
                    ));
                }
            }
        }
    }
}

/// Runs `run_wallet_sync` under a stall watchdog. Returns whichever future
/// completes first:
///   - sync's `Ok(())` / sync's `Err(...)` — natural outcome
///   - watchdog's `Err(...)` — stall detected; passed to the retry loop
///
/// `biased` polling ensures the sync future is given a chance on every
/// wake-up before the watchdog is checked, so an in-flight sync completion
/// never loses to a coincidentally-tripping watchdog.
async fn run_wallet_sync_with_stall_watchdog(
    workspace: &RecoveryWorkspace,
    network: &crate::workspace::ArgosParams,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    state: &SharedScanTaskState,
) -> ZeckResult<()> {
    tokio::select! {
        biased;
        result = run_wallet_sync(workspace, network, client) => result,
        err = stall_watchdog(state) => Err(err),
    }
}

/// Decides the retry budget to carry into the next attempt after a transient
/// failure. Returns 0 (a full reset) when `synced_to_height` has advanced since
/// the previous failure — an isolated stall that recovered must not count
/// toward the lifetime cap on a multi-hour scan. Otherwise the accumulated
/// `attempts` is preserved so that only *consecutive* failures with no forward
/// progress exhaust `MAX_SYNC_RETRIES` (issue #174).
fn retry_budget_after_failure(
    attempts: u32,
    last_failure_height: Option<u64>,
    current_height: Option<u64>,
) -> u32 {
    match (last_failure_height, current_height) {
        (Some(prev), Some(curr)) if curr > prev => 0,
        _ => attempts,
    }
}

/// Runs `run_wallet_sync`, reconnecting to lightwalletd on transient transport
/// errors.  Each reconnection attempt tries all configured endpoints in order.
/// Permanent errors (wallet database corruption, etc.) are returned immediately.
pub(crate) async fn run_wallet_sync_with_retry(
    workspace: &RecoveryWorkspace,
    network: &crate::workspace::ArgosParams,
    zeck_network: crate::models::ZeckNetwork,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    lightwalletd_url: &str,
    state: &SharedScanTaskState,
) -> ZeckResult<()> {
    let mut attempts = 0u32;
    // Height observed at the most recent transient failure. Forward progress
    // past this between failures resets the retry budget (issue #174).
    let mut last_failure_height: Option<u64> = None;
    loop {
        match run_wallet_sync_with_stall_watchdog(workspace, network, client, state).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                let msg = err.to_string();
                // Transport/stream drops AND DNS-resolution failures are
                // transient and worth reconnecting on (shared classifier so the
                // mid-sync and startup paths agree on what is retryable).
                let is_transient = crate::lightwalletd::is_transient_network_error(&msg);

                if !is_transient {
                    return Err(err);
                }

                // Reset the retry budget when the sync advanced since the last
                // failure: on a long scan against a loaded public endpoint,
                // isolated stalls that each recover must not accumulate toward
                // MAX_SYNC_RETRIES. Only consecutive no-progress failures (a
                // genuinely hung server) exhaust the budget.
                let current_height = state.lock().await.progress.synced_to_height;
                attempts =
                    retry_budget_after_failure(attempts, last_failure_height, current_height);
                last_failure_height = current_height;

                if attempts >= MAX_SYNC_RETRIES {
                    return Err(err);
                }

                attempts += 1;
                warn!(
                    "lightwalletd connection dropped (attempt {attempts}/{MAX_SYNC_RETRIES}), reconnecting in {SYNC_RETRY_DELAY_SECS}s: {msg}"
                );

                // Touch the sidecar so the launch-time list shows a fresh
                // "last run" timestamp on each reconnect — useful for users
                // who interrupt a long-running scan and want to confirm
                // it's the one they were running today.
                if let Err(err) = touch_session_last_run(workspace.root(), now_epoch_seconds()) {
                    warn!("failed to touch session sidecar (continuing): {err}");
                }

                {
                    let mut guard = state.lock().await;
                    guard.progress.message = Some(format!(
                        "Connection dropped — reconnecting (attempt {attempts}/{MAX_SYNC_RETRIES})…"
                    ));
                }

                tokio::time::sleep(std::time::Duration::from_secs(SYNC_RETRY_DELAY_SECS)).await;

                match probe_valid_lightwalletd_endpoints(lightwalletd_url, zeck_network).await {
                    Ok((new_client, endpoint, info)) => {
                        *client = new_client;
                        let mut guard = state.lock().await;
                        guard.progress.message =
                            Some(format!("Reconnected to {endpoint}, resuming sync…"));
                        // Pass the real `LightdInfo` so the displayed server
                        // identity reflects the endpoint actually in use rather
                        // than a zeroed default (audit Issue I).
                        guard.progress.server =
                            Some(crate::lightwalletd::build_probe(endpoint, &info));
                    }
                    Err(reconnect_err) => {
                        warn!("reconnect failed: {reconnect_err}");
                        // try again next iteration
                    }
                }
            }
        }
    }
}

async fn probe_valid_lightwalletd_endpoints(
    raw: &str,
    network: crate::models::ZeckNetwork,
) -> ZeckResult<(
    CompactTxStreamerClient<tonic::transport::Channel>,
    String,
    LightdInfo,
)> {
    // Bounded retry for the initial probe: a transient DNS/network blip at
    // startup must not fail a recovery before it begins. The mid-sync reconnect
    // loop only triggers on a drop *mid-stream*, so a clean connection failure
    // here would otherwise never be retried. Only retry transient errors — a
    // wrong-chain / validation failure won't get better by waiting.
    let mut attempt = 1u32;
    loop {
        match probe_valid_lightwalletd_endpoints_once(raw, network).await {
            Ok(ready) => return Ok(ready),
            Err(err) => {
                if attempt < INITIAL_PROBE_ATTEMPTS
                    && crate::lightwalletd::is_transient_network_error(&err.to_string())
                {
                    warn!(
                        "initial lightwalletd probe failed (attempt {attempt}/{INITIAL_PROBE_ATTEMPTS}), retrying in {SYNC_RETRY_DELAY_SECS}s: {err}"
                    );
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(SYNC_RETRY_DELAY_SECS)).await;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

async fn probe_valid_lightwalletd_endpoints_once(
    raw: &str,
    network: crate::models::ZeckNetwork,
) -> ZeckResult<(
    CompactTxStreamerClient<tonic::transport::Channel>,
    String,
    LightdInfo,
)> {
    let endpoints = validated_lightwalletd_endpoints(raw)?;
    let mut errors = Vec::new();

    for endpoint in endpoints {
        match CompactTxStreamerClient::connect(endpoint.clone()).await {
            Ok(mut client) => match client.get_lightd_info(Empty {}).await {
                Ok(response) => {
                    let info = response.into_inner();
                    match validate_lightwalletd_network(network, &info) {
                        Ok(()) => return Ok((client, endpoint, info)),
                        Err(err) => {
                            errors.push(format!("{endpoint}: network validation failed: {err}"));
                        }
                    }
                }
                Err(err) => errors.push(format!("{endpoint}: {err}")),
            },
            Err(err) => errors.push(format!("{endpoint}: {err}")),
        }
    }

    Err(ZeckError::Lightwalletd(format!(
        "no configured lightwalletd endpoint passed network validation: {}",
        errors.join(" | ")
    )))
}

pub(crate) async fn run_wallet_sync<ChT>(
    workspace: &RecoveryWorkspace,
    network: &crate::workspace::ArgosParams,
    client: &mut CompactTxStreamerClient<ChT>,
) -> ZeckResult<()>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    let cache = MemoryBlockCache::new();
    let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), *network)?;

    sync::run(client, network, &cache, &mut wallet_db, SYNC_BATCH_SIZE)
        .await
        .map_err(|err| ZeckError::Wallet(format!("synchronizing wallet workspace: {err}")))?;

    Ok(())
}

pub(crate) async fn refresh_scan_progress(
    state: &SharedScanTaskState,
    workspace: &RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    effective_birthday: u32,
) -> ZeckResult<()> {
    let tracked_accounts = {
        let guard = state.lock().await;
        guard.tracked_accounts.clone()
    };

    let wallet_db = open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;

    let summary = wallet_db
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .map_err(|err| ZeckError::Wallet(format!("loading wallet summary: {err}")))?
        .ok_or_else(|| ZeckError::Wallet("wallet summary is unavailable after sync".to_owned()))?;

    // Open a read-only connection to check historical note activity (including
    // spent notes) per account.  The WalletRead API only exposes current
    // balances, so accounts that received and fully spent funds would appear
    // inactive.  Querying the raw sqlite tables lets us detect any note that was
    // ever received, which is the correct signal for gap-limit decisions.
    let raw_conn = Connection::open_with_flags(
        workspace.wallet_db_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| {
        ZeckError::Storage(format!("opening wallet database for activity check: {err}"))
    })?;
    raw_conn
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|err| {
            ZeckError::Storage(format!("setting busy_timeout on wallet database: {err}"))
        })?;

    let target_height = (summary.chain_tip_height() + 1).into();
    let mut account_rows = Vec::with_capacity(tracked_accounts.len());
    let mut total_zatoshis = 0u64;

    for tracked in tracked_accounts {
        let balance = summary.account_balances().get(&tracked.wallet_account_id);
        let sapling_zatoshis = balance
            .map(|value| u64::from(value.sapling_balance().total()))
            .unwrap_or(0);
        let orchard_zatoshis = balance
            .map(|value| u64::from(value.orchard_balance().total()))
            .unwrap_or(0);
        let transparent_zatoshis = balance
            .map(|value| u64::from(value.unshielded_balance().total()))
            .unwrap_or(0);
        let total_account_zatoshis = balance.map(|value| u64::from(value.total())).unwrap_or(0);
        total_zatoshis = total_zatoshis
            .checked_add(total_account_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("recovery total overflowed the supported range".to_owned())
            })?;

        let transparent_utxo_count =
            tracked
                .transparent_receivers
                .iter()
                .try_fold(0usize, |sum, address| {
                    let outputs = wallet_db
                        .get_spendable_transparent_outputs(
                            address,
                            target_height,
                            ConfirmationsPolicy::MIN,
                            CoinbaseFilter::AllTransparentOutputs,
                            // Reporting path, not a selection path: this count feeds the
                            // recovery total shown to the user, so it must reflect
                            // everything the wallet holds. Argos never takes output locks,
                            // but `Unfiltered` is the upstream-sanctioned choice for
                            // retrieval and keeps the total from silently under-reporting
                            // if a lock ever appears.
                            LockFilter::Unfiltered,
                        )
                        .map_err(|err| {
                            ZeckError::Wallet(format!(
                                "loading transparent outputs for account {}: {err}",
                                tracked.derived.index
                            ))
                        })?;
                    sum.checked_add(outputs.len()).ok_or_else(|| {
                        ZeckError::Internal(
                            "transparent UTXO count overflowed the supported range".to_owned(),
                        )
                    })
                })?;

        let has_activity = account_has_note_activity(&raw_conn, &tracked.wallet_account_id)
            .map_err(|err| {
                ZeckError::Wallet(format!(
                    "checking note activity for account {}: {err}",
                    tracked.derived.index
                ))
            })?;

        account_rows.push(AccountBalancePreview {
            account_index: tracked.derived.index,
            sapling_address: tracked.derived.sapling_address.clone(),
            unified_address: tracked.derived.unified_address.clone(),
            transparent_receive_address: tracked.derived.transparent_receive_address.clone(),
            transparent_change_address: tracked.derived.transparent_change_address.clone(),
            transparent_utxo_count: u32::try_from(transparent_utxo_count).map_err(|_| {
                ZeckError::Internal("transparent UTXO count overflowed u32".to_owned())
            })?,
            sapling_zatoshis,
            orchard_zatoshis,
            transparent_zatoshis,
            total_zatoshis: total_account_zatoshis,
            has_activity,
            status: build_account_status(
                sapling_zatoshis,
                orchard_zatoshis,
                transparent_zatoshis,
                transparent_utxo_count,
                has_activity,
            ),
        });
    }

    let mut guard = state.lock().await;
    let scanned_height = u64::from(u32::from(summary.fully_scanned_height()));
    append_new_discoveries(
        &mut guard.progress.discoveries,
        &account_rows,
        scanned_height,
    );
    guard.progress.accounts = account_rows;
    guard.progress.blocks_total =
        block_delta(summary.chain_tip_height().into(), effective_birthday);
    guard.progress.blocks_scanned =
        block_delta(summary.fully_scanned_height().into(), effective_birthday);
    guard.progress.synced_to_height = Some(u64::from(u32::from(summary.fully_scanned_height())));
    guard.progress.summary = Some(ScanSummary {
        total_zatoshis,
        authoritative_balances: true,
        note: format!(
            "Wallet workspace synced through height {} and is tracking {} imported legacy account slots.",
            u32::from(summary.fully_scanned_height()),
            guard.progress.accounts.len()
        ),
        workspace_dir: workspace.root().display().to_string(),
    });
    guard.progress.message = Some(format!(
        "Wallet workspace synced through height {}. Review the account table below for authoritative balances.",
        u32::from(summary.fully_scanned_height())
    ));

    Ok(())
}

/// Fast transparent-balance probe issued before the shielded compact-block
/// scan begins. Batches every receive + change address from the supplied
/// slice into a single `GetAddressUtxos` call to lightwalletd, then
/// surfaces non-zero balances as preliminary discoveries.
///
/// Safe to call multiple times during a scan (e.g. once per gap-limit
/// extension): every discovery push is deduped against the existing
/// `progress.discoveries` log, so probing an already-probed account is
/// a no-op rather than a duplicate emission. Pass only the new account
/// slice each iteration to avoid wasted gRPC traffic.
///
/// Side effects on the shared state:
/// - Sets `phase = ScanningTransparent` while the probe is in flight.
/// - Updates `progress.accounts[i].transparent_zatoshis` and
///   `transparent_utxo_count` for any matched account so the subsequent
///   shielded refresh observes the same number authoritatively.
/// - Pushes a `ScanDiscovery::Transparent` per *newly-funded* account
///   with `at_block_height = chain_tip_height`.
async fn run_transparent_quick_probe(
    state: &SharedScanTaskState,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    accounts: &[DerivedAccount],
    chain_tip_height: u32,
) -> ZeckResult<()> {
    use std::collections::{HashMap, HashSet};

    if accounts.is_empty() {
        return Ok(());
    }

    {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::ScanningTransparent;
        guard.progress.message = Some(format!(
            "Quick-checking transparent balances for {} accounts via lightwalletd…",
            accounts.len()
        ));
    }

    // Build the address batch — receive + change for every account in the
    // supplied slice. Track account ownership so we can fold UTXO results
    // back into per-account preliminary balances.
    let mut address_to_account: HashMap<String, u32> = HashMap::new();
    let mut addresses: Vec<String> = Vec::with_capacity(accounts.len() * 2);
    for account in accounts {
        for addr in [
            &account.transparent_receive_address,
            &account.transparent_change_address,
        ] {
            if !addr.is_empty() && !address_to_account.contains_key(addr) {
                address_to_account.insert(addr.clone(), account.index);
                addresses.push(addr.clone());
            }
        }
    }
    if addresses.is_empty() {
        return Ok(());
    }

    let reply = client
        .get_address_utxos(GetAddressUtxosArg {
            addresses,
            start_height: 0,
            max_entries: 0,
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();

    // Aggregate UTXO value per account. A negative value_zat from
    // lightwalletd is misbehaving-server data — log it loudly and skip
    // the entry rather than silently coercing to 0, which would mask
    // the bug from the user.
    let mut sums: HashMap<u32, (u64, u32)> = HashMap::new();
    for utxo in &reply.address_utxos {
        let Some(&account_index) = address_to_account.get(&utxo.address) else {
            continue;
        };
        let value = match u64::try_from(utxo.value_zat) {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    "lightwalletd returned negative value_zat={} for address {} \
                     (account {}); skipping entry",
                    utxo.value_zat, utxo.address, account_index
                );
                continue;
            }
        };
        let entry = sums.entry(account_index).or_insert((0u64, 0u32));
        entry.0 = entry.0.saturating_add(value);
        entry.1 = entry.1.saturating_add(1);
    }

    if sums.is_empty() {
        return Ok(());
    }

    let mut guard = state.lock().await;
    let chain_tip = u64::from(chain_tip_height);

    // Preliminary balance write into the in-memory snapshot. This
    // intentionally clobbers existing preliminary values — a re-probe
    // on the same account should reflect the latest lightwalletd
    // numbers, not the previous tick's.
    for account in &mut guard.progress.accounts {
        if let Some(&(zatoshis, utxo_count)) = sums.get(&account.account_index) {
            if zatoshis == 0 {
                continue;
            }
            account.transparent_zatoshis = zatoshis;
            account.transparent_utxo_count = utxo_count;
            account.total_zatoshis = account
                .sapling_zatoshis
                .saturating_add(account.orchard_zatoshis)
                .saturating_add(zatoshis);
            account.has_activity = true;
            account.status = format!(
                "Preliminary: {utxo_count} transparent UTXOs / {zatoshis} zats (shielded scan still pending)."
            );
        }
    }

    // Discovery push deduped against the existing log so safe to call
    // the probe multiple times per scan (gap-extension iterations).
    let already_discovered: HashSet<(u32, DiscoveryPool)> = guard
        .progress
        .discoveries
        .iter()
        .map(|d| (d.account_index, d.pool))
        .collect();
    for (account_index, (zatoshis, _)) in sums {
        if zatoshis == 0 {
            continue;
        }
        if already_discovered.contains(&(account_index, DiscoveryPool::Transparent)) {
            continue;
        }
        let address = guard
            .progress
            .accounts
            .iter()
            .find(|a| a.account_index == account_index)
            .map(|a| a.transparent_receive_address.clone())
            .unwrap_or_default();
        guard.progress.discoveries.push(ScanDiscovery {
            account_index,
            pool: DiscoveryPool::Transparent,
            zatoshis,
            at_block_height: chain_tip,
            address,
        });
    }
    guard.progress.message = Some(
        "Transparent quick-check complete. Continuing with shielded compact-block scan…".to_owned(),
    );

    Ok(())
}

/// Walk the new account snapshot, append a `ScanDiscovery` to `discoveries`
/// for every (account, pool) pair that newly has a non-zero balance compared
/// to the previous snapshot. Append-only: discoveries already in the log are
/// never modified or removed, even if the corresponding balance later falls
/// to zero (so users can see "yes, this seed had funds" even if the wallet
/// was already swept).
/// Dedupe `(account, pool)` discoveries against the existing append-only
/// `discoveries` log rather than against the previous account snapshot.
///
/// The previous-snapshot approach was unsound: the gap-limit loop calls
/// `initialize_accounts` between batches, which replaces `progress.accounts`
/// with fresh zero-balance previews. Diffing against that zeroed snapshot
/// causes already-known discoveries to be re-emitted on every gap-extension
/// pass, and likewise causes the transparent quick probe's preliminary
/// values to be re-emitted by the first authoritative refresh.
///
/// The append-only log is the authoritative source of "has this
/// `(account, pool)` been surfaced to the user yet?", so dedupe against it.
fn append_new_discoveries(
    discoveries: &mut Vec<crate::models::ScanDiscovery>,
    current: &[AccountBalancePreview],
    at_block_height: u64,
) {
    use crate::models::{DiscoveryPool, ScanDiscovery};

    let mut seen: std::collections::HashSet<(u32, DiscoveryPool)> = discoveries
        .iter()
        .map(|d| (d.account_index, d.pool))
        .collect();

    let mut try_append = |discoveries: &mut Vec<ScanDiscovery>,
                          account_index: u32,
                          pool: DiscoveryPool,
                          zatoshis: u64,
                          address: String| {
        if zatoshis == 0 {
            return;
        }
        if !seen.insert((account_index, pool)) {
            return;
        }
        discoveries.push(ScanDiscovery {
            account_index,
            pool,
            zatoshis,
            at_block_height,
            address,
        });
    };

    for account in current {
        try_append(
            discoveries,
            account.account_index,
            DiscoveryPool::Transparent,
            account.transparent_zatoshis,
            account.transparent_receive_address.clone(),
        );
        try_append(
            discoveries,
            account.account_index,
            DiscoveryPool::Sapling,
            account.sapling_zatoshis,
            account.sapling_address.clone(),
        );
        try_append(
            discoveries,
            account.account_index,
            DiscoveryPool::Orchard,
            account.orchard_zatoshis,
            account.unified_address.clone(),
        );
    }
}

fn build_account_status(
    sapling_zatoshis: u64,
    orchard_zatoshis: u64,
    transparent_zatoshis: u64,
    transparent_utxo_count: usize,
    has_activity: bool,
) -> String {
    let total = sapling_zatoshis + orchard_zatoshis + transparent_zatoshis;
    if total == 0 {
        return if has_activity {
            "Previously active (all funds spent).".to_owned()
        } else {
            "No funds found for this derived account.".to_owned()
        };
    }

    let mut parts = Vec::new();
    if transparent_zatoshis > 0 {
        parts.push(format!(
            "{transparent_utxo_count} transparent UTXOs / {transparent_zatoshis} zats"
        ));
    }
    if sapling_zatoshis > 0 {
        parts.push(format!("Sapling {sapling_zatoshis} zats"));
    }
    if orchard_zatoshis > 0 {
        parts.push(format!("Orchard {orchard_zatoshis} zats"));
    }

    format!("Found {}.", parts.join(", "))
}

/// Highest account index with note activity, or `None` if none are active.
///
/// Uses `has_activity` (not balance) to match [`trailing_gap_limit_reached`]:
/// an account that received and fully spent funds still keeps the search
/// alive, so it is still the trigger for a widening.
fn highest_active_account_index(accounts: &[AccountBalancePreview]) -> Option<u32> {
    accounts
        .iter()
        .filter(|account| account.has_activity)
        .map(|account| account.account_index)
        .max()
}

/// Builds the [`GapExtension`] descriptor for a widening from `previous_target`
/// to `new_target` accounts, or `None` if nothing in `accounts` is active (in
/// which case the caller would not be extending). `pass` is the 1-based count
/// of widenings so far this scan.
///
/// `accounts_to` is the last *newly-added* index, `new_target - 1`, so the
/// range `[accounts_from, accounts_to]` names exactly the accounts whose
/// blocks the upcoming pass will scan.
fn describe_gap_extension(
    accounts: &[AccountBalancePreview],
    previous_target: u32,
    new_target: u32,
    pass: u32,
) -> Option<GapExtension> {
    let trigger_account_index = highest_active_account_index(accounts)?;
    Some(GapExtension {
        pass,
        accounts_from: previous_target,
        accounts_to: new_target.saturating_sub(1),
        trigger_account_index,
    })
}

fn trailing_gap_limit_reached(accounts: &[AccountBalancePreview], gap_limit: u32) -> bool {
    let gap = usize::try_from(gap_limit).unwrap_or(usize::MAX);
    if accounts.len() < gap {
        return false;
    }

    accounts
        .iter()
        .rev()
        .take(gap)
        .all(|account| !account.has_activity)
}

/// Returns `true` if the wallet database contains any received notes (Sapling,
/// Orchard, or transparent) for the given account, regardless of whether those
/// notes have been spent.  This is the correct activity signal for gap-limit
/// decisions: an account that received and fully spent its funds is still
/// evidence that higher account indices may also be in use.
fn account_has_note_activity(
    conn: &Connection,
    account_uuid: &AccountUuid,
) -> Result<bool, rusqlite::Error> {
    let uuid_bytes = account_uuid.expose_uuid().into_bytes();
    // Resolve the internal integer id once to avoid repeating the subquery and
    // to sidestep potential issues if uuid is not unique-constrained.
    let account_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM accounts WHERE uuid = ?1",
            params![uuid_bytes.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let account_id = match account_id {
        Some(id) => id,
        None => return Ok(false),
    };
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sapling_received_notes WHERE account_id = ?1)
             OR EXISTS(SELECT 1 FROM orchard_received_notes WHERE account_id = ?1)
             OR EXISTS(SELECT 1 FROM transparent_received_outputs WHERE account_id = ?1)",
        params![account_id],
        |row| row.get(0),
    )
}

/// Imports account-0 into a probe workspace without requiring a `SharedScanTaskState`.
/// Used by `birthday::probe_shielded_window` to set up a fresh temporary workspace
/// before running a time-limited sync to detect shielded activity.
pub(crate) fn import_probe_account(
    workspace: &RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    seed: &[u8; 64],
    birthday: &AccountBirthday,
    transparent_account: &zcash_transparent::keys::AccountPrivKey,
) -> ZeckResult<()> {
    let seed_fingerprint = SeedFingerprint::from_seed(seed).ok_or_else(|| {
        ZeckError::Internal("mnemonic seed length is out of the ZIP 32 range".to_owned())
    })?;
    let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;

    let zip32_index = AccountId::ZERO;
    let derivation = Zip32Derivation::new(seed_fingerprint, zip32_index);

    if wallet_db
        .get_derived_account(&derivation)
        .map_err(|err| ZeckError::Wallet(format!("checking probe account: {err}")))?
        .is_none()
    {
        wallet_db
            .import_account_hd(
                "probe_account_0",
                &SecretVec::new(seed.to_vec()),
                zip32_index,
                birthday,
                None,
            )
            .map_err(|err| ZeckError::Wallet(format!("importing probe account: {err}")))?;
    }

    let wallet_account_id = wallet_db
        .get_derived_account(&derivation)
        .map_err(|err| ZeckError::Wallet(format!("loading probe account after import: {err}")))?
        .ok_or_else(|| ZeckError::Wallet("probe account missing after import".to_owned()))?
        .id();

    let external_pubkey =
        legacy_transparent_pubkey(transparent_account, AddressScope::External, 0)?;
    let existing_receivers = wallet_db
        .get_transparent_receivers(wallet_account_id, true, true)
        .map_err(|err| ZeckError::Wallet(format!("loading probe transparent receivers: {err}")))?;
    let external_address = TransparentAddress::from_pubkey(&external_pubkey);

    if !existing_receivers.contains_key(&external_address) {
        wallet_db
            .import_standalone_transparent_pubkey(wallet_account_id, external_pubkey)
            .map_err(|err| {
                ZeckError::Wallet(format!("importing probe transparent receiver: {err}"))
            })?;
    }

    Ok(())
}

fn block_delta(height: u32, birthday: u32) -> u64 {
    u64::from(height.saturating_sub(birthday).saturating_add(1))
}

async fn check_cancelled(state: &SharedScanTaskState) -> ZeckResult<()> {
    let cancelled = {
        let guard = state.lock().await;
        guard.cancelled.load(Ordering::SeqCst)
    };

    if cancelled {
        let mut guard = state.lock().await;
        guard.progress.phase = ScanPhase::Cancelled;
        guard.progress.message = Some("Recovery scan cancelled.".to_owned());
        warn!("scan {} cancelled", guard.progress.handle.id);
        return Err(ZeckError::Cancelled);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secrecy::SecretString;

    use crate::key_source::SeedKeySource;

    use super::{
        append_new_discoveries, build_account_status, describe_gap_extension,
        highest_active_account_index, merge_account_previews, resolve_max_account_count,
        trailing_gap_limit_reached,
    };
    use crate::models::{
        AccountBalancePreview, DerivedAccount, DiscoveryPool, RuntimeScanConfig, ScanDiscovery,
        ZeckNetwork,
    };

    /// Minimal preview carrying only the fields the gap-limit logic reads.
    fn preview(account_index: u32, has_activity: bool) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index,
            sapling_address: String::new(),
            unified_address: String::new(),
            transparent_receive_address: String::new(),
            transparent_change_address: String::new(),
            transparent_utxo_count: 0,
            sapling_zatoshis: 0,
            orchard_zatoshis: 0,
            transparent_zatoshis: 0,
            total_zatoshis: 0,
            has_activity,
            status: String::new(),
        }
    }

    #[test]
    fn highest_active_account_index_is_the_trailing_trigger() {
        // Activity at index 0 and 3; the extension trigger is the *latest*.
        let accounts = vec![
            preview(0, true),
            preview(1, false),
            preview(2, false),
            preview(3, true),
            preview(4, false),
        ];
        assert_eq!(highest_active_account_index(&accounts), Some(3));
    }

    #[test]
    fn highest_active_account_index_is_none_when_no_activity() {
        let accounts = vec![preview(0, false), preview(1, false)];
        assert_eq!(highest_active_account_index(&accounts), None);
    }

    #[test]
    fn describe_gap_extension_reports_new_range_and_trigger() {
        // 20 accounts searched, activity at index 18, widening to 40.
        let mut accounts: Vec<_> = (0..20).map(|i| preview(i, false)).collect();
        accounts[18].has_activity = true;

        let ext = describe_gap_extension(&accounts, 20, 40, 1)
            .expect("activity present, so an extension is described");
        assert_eq!(ext.pass, 1);
        assert_eq!(ext.accounts_from, 20);
        assert_eq!(ext.accounts_to, 39);
        assert_eq!(ext.trigger_account_index, 18);
    }

    #[test]
    fn describe_gap_extension_is_none_without_a_trigger() {
        let accounts: Vec<_> = (0..20).map(|i| preview(i, false)).collect();
        assert!(describe_gap_extension(&accounts, 20, 40, 1).is_none());
    }

    fn config(num_accounts: Option<u32>) -> RuntimeScanConfig {
        RuntimeScanConfig {
            key_source: Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ))),
            birthday: 419_200,
            num_accounts,
            gap_limit: 20,
            lightwalletd_url: "https://example.com".to_owned(),
            data_dir: std::path::PathBuf::from("zeck_data"),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        }
    }

    #[test]
    fn account_limit_defaults_to_ceiling_for_gap_limit_mode() {
        let count = resolve_max_account_count(&config(None)).expect("default account count");
        assert_eq!(count, 500);
    }

    #[test]
    fn account_limit_rejects_zero() {
        let err = resolve_max_account_count(&config(Some(0))).expect_err("zero should fail");
        assert!(err.to_string().contains("at least 1"));
    }

    #[test]
    fn account_status_mentions_shielded_and_transparent_funds() {
        let status = build_account_status(42_000, 84_000, 21_000, 2, true);
        assert!(status.contains("Sapling"));
        assert!(status.contains("Orchard"));
        assert!(status.contains("transparent"));
    }

    #[test]
    fn account_status_shows_previously_active_for_spent_account() {
        let status = build_account_status(0, 0, 0, 0, true);
        assert!(status.contains("Previously active"));
    }

    #[test]
    fn account_status_shows_no_funds_for_inactive_account() {
        let status = build_account_status(0, 0, 0, 0, false);
        assert!(status.contains("No funds found"));
    }

    #[test]
    fn gap_limit_only_triggers_on_trailing_inactive_accounts() {
        let accounts = vec![
            AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 1,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 1,
                has_activity: true,
                status: "found".to_owned(),
            },
            AccountBalancePreview {
                account_index: 1,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 0,
                has_activity: false,
                status: "empty".to_owned(),
            },
            AccountBalancePreview {
                account_index: 2,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 0,
                has_activity: false,
                status: "empty".to_owned(),
            },
        ];

        assert!(trailing_gap_limit_reached(&accounts, 2));
        assert!(!trailing_gap_limit_reached(&accounts, 3));
    }

    #[test]
    fn gap_limit_does_not_trigger_when_spent_account_in_trailing_window() {
        // Account 1 has zero balance but historical activity (received and spent).
        // The gap limit should NOT trigger because account 1 is still "active".
        let accounts = vec![
            AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 1,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 1,
                has_activity: true,
                status: "found".to_owned(),
            },
            AccountBalancePreview {
                account_index: 1,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 0,
                has_activity: true, // spent account -- still active
                status: "previously active".to_owned(),
            },
            AccountBalancePreview {
                account_index: 2,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 0,
                has_activity: false,
                status: "empty".to_owned(),
            },
        ];

        // With gap_limit=2, the trailing 2 accounts are [1, 2].
        // Account 1 has_activity=true, so the gap limit should NOT fire.
        assert!(!trailing_gap_limit_reached(&accounts, 2));
    }

    #[test]
    fn gap_limit_boundary_with_spent_account_at_edge() {
        // Layout: [active, empty, spent] with gap_limit=2.
        // Trailing window = [empty, spent]. The spent account has activity,
        // so the gap limit should NOT fire.
        let accounts = vec![
            AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 100,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 100,
                has_activity: true,
                status: "found".to_owned(),
            },
            AccountBalancePreview {
                account_index: 1,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 0,
                has_activity: false,
                status: "empty".to_owned(),
            },
            AccountBalancePreview {
                account_index: 2,
                sapling_address: "zs".to_owned(),
                unified_address: "u".to_owned(),
                transparent_receive_address: "t1".to_owned(),
                transparent_change_address: "t2".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 0,
                has_activity: true, // spent account at boundary
                status: "previously active".to_owned(),
            },
        ];

        // Trailing 2 = [empty, spent]. Spent has activity, so gap limit does NOT fire.
        assert!(!trailing_gap_limit_reached(&accounts, 2));
        // But with gap_limit=1, trailing 1 = [spent], which has activity -- still no trigger.
        assert!(!trailing_gap_limit_reached(&accounts, 1));
    }

    fn empty_account(index: u32) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: index,
            sapling_address: "zs".to_owned(),
            unified_address: "u".to_owned(),
            transparent_receive_address: "t1".to_owned(),
            transparent_change_address: "t2".to_owned(),
            transparent_utxo_count: 0,
            sapling_zatoshis: 0,
            orchard_zatoshis: 0,
            transparent_zatoshis: 0,
            total_zatoshis: 0,
            has_activity: false,
            status: "empty".to_owned(),
        }
    }

    fn active_account(index: u32) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: index,
            sapling_zatoshis: 1,
            total_zatoshis: 1,
            has_activity: true,
            status: "found".to_owned(),
            ..empty_account(index)
        }
    }

    #[test]
    fn gap_limit_1_triggers_on_single_trailing_empty_account() {
        // [active, empty] with gap_limit=1 → trailing window is [empty] → fires
        let accounts = vec![active_account(0), empty_account(1)];
        assert!(trailing_gap_limit_reached(&accounts, 1));
    }

    #[test]
    fn gap_limit_1_does_not_trigger_on_active_tail() {
        // [empty, active] with gap_limit=1 → trailing window is [active] → no fire
        let accounts = vec![empty_account(0), active_account(1)];
        assert!(!trailing_gap_limit_reached(&accounts, 1));
    }

    #[test]
    fn gap_limit_triggers_only_when_all_trailing_accounts_inactive() {
        // [active, empty, empty] with gap_limit=2 → both trailing are inactive → fires
        let accounts = vec![active_account(0), empty_account(1), empty_account(2)];
        assert!(trailing_gap_limit_reached(&accounts, 2));
        // with gap_limit=1 → only last is empty → also fires
        assert!(trailing_gap_limit_reached(&accounts, 1));
        // with gap_limit=3 → window covers all 3, first has activity → no fire
        assert!(!trailing_gap_limit_reached(&accounts, 3));
    }

    #[test]
    fn gap_limit_larger_than_account_count_never_triggers() {
        let accounts = vec![empty_account(0), empty_account(1)];
        // gap_limit=5 > 2 accounts → window is entire list; but since there are
        // fewer accounts than the gap_limit, scanning has not yet had enough room
        // to confirm absence — should not fire.
        assert!(!trailing_gap_limit_reached(&accounts, 5));
    }

    fn account_with(
        index: u32,
        sapling: u64,
        orchard: u64,
        transparent: u64,
    ) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: index,
            sapling_zatoshis: sapling,
            orchard_zatoshis: orchard,
            transparent_zatoshis: transparent,
            total_zatoshis: sapling + orchard + transparent,
            has_activity: sapling + orchard + transparent > 0,
            ..empty_account(index)
        }
    }

    #[test]
    fn first_observation_emits_one_discovery_per_funded_pool() {
        let mut log = Vec::new();
        let new_snapshot = vec![account_with(0, 100, 200, 300)];
        append_new_discoveries(&mut log, &new_snapshot, 3_280_500);
        assert_eq!(log.len(), 3);
        let pools: Vec<DiscoveryPool> = log.iter().map(|d| d.pool).collect();
        assert!(pools.contains(&DiscoveryPool::Transparent));
        assert!(pools.contains(&DiscoveryPool::Sapling));
        assert!(pools.contains(&DiscoveryPool::Orchard));
        for d in &log {
            assert_eq!(d.account_index, 0);
            assert_eq!(d.at_block_height, 3_280_500);
            assert!(d.zatoshis > 0);
        }
    }

    #[test]
    fn empty_accounts_emit_no_discoveries() {
        let mut log = Vec::new();
        let snapshot = vec![empty_account(0), empty_account(1)];
        append_new_discoveries(&mut log, &snapshot, 100);
        assert!(log.is_empty());
    }

    #[test]
    fn second_call_with_same_funded_account_does_not_re_emit() {
        // First call discovers sapling. Second call (e.g. another refresh
        // tick) must not re-emit the same (account, pool) discovery.
        let mut log = Vec::new();
        let snapshot = vec![account_with(0, 100, 0, 0)];
        append_new_discoveries(&mut log, &snapshot, 100);
        assert_eq!(log.len(), 1);
        append_new_discoveries(&mut log, &snapshot, 200);
        assert_eq!(log.len(), 1, "duplicate discovery must not be appended");
    }

    #[test]
    fn newly_funded_pool_on_existing_account_emits_one_discovery() {
        // Account 0 already has sapling discovered; second call shows
        // orchard funds appearing on the same account.
        let mut log = Vec::new();
        let first = vec![account_with(0, 100, 0, 0)];
        let second = vec![account_with(0, 100, 50, 0)];
        append_new_discoveries(&mut log, &first, 100);
        append_new_discoveries(&mut log, &second, 200);
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].pool, DiscoveryPool::Orchard);
        assert_eq!(log[1].zatoshis, 50);
    }

    #[test]
    fn balance_dropping_to_zero_does_not_remove_existing_discovery() {
        // First tick discovers Sapling 100; second tick shows it spent.
        // The existing discovery must remain (append-only).
        let mut log = vec![ScanDiscovery {
            account_index: 0,
            pool: DiscoveryPool::Sapling,
            zatoshis: 100,
            at_block_height: 50,
            address: "zs".to_owned(),
        }];
        let next = vec![account_with(0, 0, 0, 0)];
        append_new_discoveries(&mut log, &next, 75);
        assert_eq!(log.len(), 1, "previous discovery must be preserved");
        assert_eq!(log[0].zatoshis, 100, "stored zatoshis must not be mutated");
    }

    #[test]
    fn newly_appearing_account_emits_for_each_funded_pool() {
        // Gap-limit extension can introduce new accounts between calls.
        let mut log = Vec::new();
        let first = vec![account_with(0, 100, 0, 0)];
        let second = vec![account_with(0, 100, 0, 0), account_with(7, 0, 50, 0)];
        append_new_discoveries(&mut log, &first, 100);
        append_new_discoveries(&mut log, &second, 200);
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].account_index, 7);
        assert_eq!(log[1].pool, DiscoveryPool::Orchard);
    }

    #[test]
    fn initialize_accounts_zeroing_does_not_cause_duplicate_emission() {
        // Regression test for the gap-limit-extension bug. The real scan
        // loop calls initialize_accounts() between batches, which zeros
        // the in-memory snapshot. The dedup logic must not re-emit the
        // same (account, pool) just because the snapshot was wiped and
        // refilled.
        //
        // Scenario:
        //   1. Authoritative refresh observes account 0 with 500 sapling.
        //   2. Loop extends gap range; initialize_accounts wipes snapshot
        //      to zeros (this is what previous logic compared against).
        //   3. Next refresh observes account 0 still with 500 sapling
        //      (it didn't disappear from WalletDb).
        // Expected: only one Sapling discovery for account 0 in the log.
        let mut log = Vec::new();
        let funded = vec![account_with(0, 500, 0, 0)];
        append_new_discoveries(&mut log, &funded, 100);
        assert_eq!(log.len(), 1);
        // Step 2: snapshot was zeroed by initialize_accounts. Step 3:
        // refresh sees the same funded account again. Old logic would
        // see prev=0, current=500, and re-emit. New logic dedupes
        // against the existing discovery log.
        append_new_discoveries(&mut log, &funded, 200);
        assert_eq!(
            log.len(),
            1,
            "gap-limit extension must not produce duplicate discoveries"
        );
    }

    #[test]
    fn transparent_quick_probe_followed_by_authoritative_refresh_dedupes() {
        // Regression test for PR #13's invariant. The transparent quick
        // probe pushes ScanDiscovery::Transparent directly. The first
        // authoritative refresh then calls append_new_discoveries with
        // a snapshot that may or may not have transparent_zatoshis set.
        // Either way, the existing discovery in the log must dedupe it.
        let mut log = vec![ScanDiscovery {
            account_index: 0,
            pool: DiscoveryPool::Transparent,
            zatoshis: 500_000,
            at_block_height: 3_280_500,
            address: "t1".to_owned(),
        }];
        // Refresh sees the same balance authoritatively; must not duplicate.
        let snapshot = vec![account_with(0, 0, 0, 500_000)];
        append_new_discoveries(&mut log, &snapshot, 3_281_000);
        assert_eq!(
            log.len(),
            1,
            "authoritative refresh must not re-emit a probe discovery"
        );
    }

    fn derived_account(index: u32) -> DerivedAccount {
        DerivedAccount {
            index,
            sapling_path: String::new(),
            orchard_path: String::new(),
            transparent_receive_path: String::new(),
            transparent_change_path: String::new(),
            sapling_address: "zs".to_owned(),
            unified_address: "u".to_owned(),
            transparent_receive_address: "t1".to_owned(),
            transparent_change_address: "t2".to_owned(),
        }
    }

    #[test]
    fn gap_extension_reinit_preserves_already_refreshed_balances() {
        // Regression for the discovery-banner vs account-table discrepancy.
        // On each gap-extension iteration the scan loop re-derives the full
        // account set and calls initialize_accounts over all of it. Accounts
        // already refreshed in a prior batch (with authoritative balances and
        // a sticky discovery banner) must not be blanked back to zero
        // "Waiting for sync" previews for the entire duration of the next
        // (long) shielded batch — otherwise the table contradicts the banner.
        let refreshed = vec![account_with(0, 12_645_600, 0, 0)];
        let derived = vec![derived_account(0), derived_account(1)];

        let merged = merge_account_previews(refreshed, &derived);

        assert_eq!(merged.len(), 2);
        // Account 0 keeps its authoritative sapling balance and status.
        assert_eq!(merged[0].account_index, 0);
        assert_eq!(merged[0].sapling_zatoshis, 12_645_600);
        assert!(merged[0].has_activity);
        // The genuinely-new account 1 gets a fresh zero preview.
        assert_eq!(merged[1].account_index, 1);
        assert_eq!(merged[1].sapling_zatoshis, 0);
        assert!(merged[1].status.contains("Waiting for"));
    }

    #[test]
    fn merge_account_previews_orders_by_derived_set_not_prior_snapshot() {
        // The returned rows must follow the freshly-derived account order,
        // and a preview whose index is no longer in the derived set is dropped.
        let stale = vec![account_with(5, 1, 0, 0), account_with(0, 2, 0, 0)];
        let derived = vec![derived_account(0), derived_account(1), derived_account(2)];

        let merged = merge_account_previews(stale, &derived);

        let indices: Vec<u32> = merged.iter().map(|a| a.account_index).collect();
        assert_eq!(indices, vec![0, 1, 2]);
        assert_eq!(merged[0].sapling_zatoshis, 2, "account 0 balance preserved");
    }

    /// Cancel-then-resume workspace persistence tests.
    ///
    /// These tests exercise the invariants that:
    ///   1. `import_accounts` leaves a persistent SQLite wallet DB on disk
    ///      (matching what happens when a scan task is `abort()`-ed mid-flight).
    ///   2. A second scan started with the same `RuntimeScanConfig` resolves to
    ///      the same workspace directory and does not duplicate already-imported
    ///      accounts.
    ///   3. `scan_cached_blocks` advances `fully_scanned_height` in the wallet DB,
    ///      that the cursor survives a workspace handle drop + reopen, and that
    ///      `suggest_scan_ranges` on the reopened wallet starts strictly above the
    ///      preserved cursor — i.e. a resume scan skips already-scanned blocks
    ///      instead of restarting from the birthday.
    ///
    /// (3) covers the end-to-end resume contract directly at the
    /// `zcash_client_backend::data_api::chain::scan_cached_blocks` layer rather
    /// than going through `run_wallet_sync_with_retry`, which would require a
    /// mock tonic `CompactTxStreamer` gRPC server. The cursor advancement and
    /// persistence behaviour we want to pin is the same in either case — it
    /// lives in the wallet DB, not the gRPC client — so testing one layer down
    /// gets us the same coverage with no new infrastructure.
    mod cancel_resume {
        use std::sync::Arc;

        use secrecy::{ExposeSecret, SecretString};
        use tokio::sync::Mutex;
        use zcash_client_backend::{
            data_api::{
                chain::{scan_cached_blocks, ChainState},
                wallet::ConfirmationsPolicy,
                AccountBirthday, WalletCommitmentTrees, WalletRead, WalletWrite,
            },
            proto::compact_formats::{ChainMetadata, CompactBlock},
        };
        use zcash_client_sqlite::{util::SystemClock, WalletDb};
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::consensus::BlockHeight;

        use super::super::{import_accounts, MemoryBlockCache, ScanTaskState};
        use crate::{
            derivation::{derive_accounts, legacy_transparent_account_key, mnemonic_seed},
            key_source::SeedKeySource,
            models::{RuntimeScanConfig, ScanHandle, ZeckNetwork},
            workspace::{consensus_network, RecoveryWorkspace},
        };

        const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon abandon abandon art";

        fn test_seed_phrase() -> SecretString {
            SecretString::new(TEST_SEED.to_owned())
        }

        /// A zcashd `wallet.dat` holds flat, individually-stored keys with
        /// no HD seed behind them. The scanner walks HD-derived account
        /// slots, so it has nothing to enumerate for such a source — and
        /// the dangerous outcome is not an error but a *successful* scan
        /// that finds nothing, which a user recovering real funds would
        /// read as "my money is gone".
        ///
        /// Pinned here because the refusal is the only thing standing
        /// between that user and a false negative. It fires before any
        /// network or filesystem work, so this test needs neither.
        #[tokio::test]
        async fn a_seedless_key_source_is_refused_rather_than_scanned_as_empty() {
            use crate::key_source::{ImportedKeySource, KeySource};
            // Genuinely empty: no seed, no keys of any kind. A
            // transparent-only wallet is *not* this case — it has a real
            // recovery route (see the test below), and treating it as a
            // refusal is the bug that dead-ended the GUI.
            let keys = argos_wallet_import::ImportedKeys::default();
            let source = ImportedKeySource::new(keys);
            // Non-vacuous: if this source ever grows a seed, the assertion
            // below would pass for the wrong reason.
            assert!(
                source.wallet_seed().expect("wallet_seed").is_none(),
                "fixture must be genuinely seedless or this test proves nothing"
            );

            let tempdir = tempfile::tempdir().expect("temp dir");
            let mut config = test_config(tempdir.path().to_owned());
            config.key_source = Arc::new(source);

            let state = Arc::new(Mutex::new(ScanTaskState::new(ScanHandle::new())));
            let err = super::super::run_recovery_scan_inner(state, config)
                .await
                .expect_err("a key source with nothing in it must not scan successfully");

            let rendered = err.to_string();
            assert!(
                rendered.contains("nothing to scan"),
                "the refusal must say why, got: {rendered}"
            );
        }

        /// A transparent-only wallet must be routed, not refused.
        ///
        /// This is the most common legacy zcashd shape. Core used to refuse
        /// it with a message naming a transparent-only path that only the CLI
        /// implemented, at its own front end — so the GUI handed the same file
        /// here and told the user their recoverable funds were unrecoverable.
        ///
        /// The scan itself needs a node, so what is pinned is the routing
        /// decision: it must not come back as the `InvalidConfig` refusal.
        /// Reaching the network and failing there is a pass — that is past the
        /// point where the old code gave up.
        #[tokio::test]
        async fn a_transparent_only_wallet_is_routed_rather_than_refused() {
            use argos_wallet_import::keys::{Provenance, TransparentKey};
            use secrecy::Secret;

            let mut keys = argos_wallet_import::ImportedKeys::default();
            keys.transparent.push(TransparentKey {
                secret: Secret::new([0x42; 32]),
                provenance: Provenance::Standalone,
            });
            assert_eq!(
                crate::key_source::classify_recovery_route(&keys),
                crate::key_source::RecoveryRoute::TransparentOnly,
                "fixture must classify as transparent-only or this test proves nothing"
            );

            let source = crate::key_source::ImportedKeySource::new(keys);
            let tempdir = tempfile::tempdir().expect("temp dir");
            let mut config = test_config(tempdir.path().to_owned());
            config.key_source = Arc::new(source);
            // Unroutable on purpose: the routing decision happens before any
            // connection, so this fails at the network rather than at config.
            config.lightwalletd_url = "https://127.0.0.1:1".to_owned();

            let state = Arc::new(Mutex::new(ScanTaskState::new(ScanHandle::new())));
            let data_dir = config.data_dir.clone();
            let result = super::super::run_recovery_scan_inner(state, config).await;

            if let Err(err) = result {
                assert!(
                    !matches!(err, crate::error::ZeckError::InvalidConfig(_)),
                    "a transparent-only wallet must be routed to the transparent path, \
                     not refused as unscannable; got: {err}"
                );
            }

            // And it must leave a session behind. This path used to build the
            // workspace only after the network call succeeded, so a scan that
            // failed at the endpoint vanished entirely — no sidecar, nothing
            // in the resume list, the user with no record that it ran. The
            // endpoint here is unroutable, so this is exactly that case.
            let sidecars: Vec<_> = walkdir(&data_dir)
                .into_iter()
                .filter(|p| p.file_name().is_some_and(|n| n == "session.json"))
                .collect();
            assert!(
                !sidecars.is_empty(),
                "a failed transparent-only scan must still record a session under \
                 {}, or it disappears from the resume list",
                data_dir.display()
            );
        }

        /// Minimal recursive file listing; the workspace path contains
        /// hashes that the test has no business reconstructing.
        fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
            let mut out = Vec::new();
            let Ok(entries) = std::fs::read_dir(root) else {
                return out;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walkdir(&path));
                } else {
                    out.push(path);
                }
            }
            out
        }

        fn test_config(data_dir: std::path::PathBuf) -> RuntimeScanConfig {
            RuntimeScanConfig {
                key_source: Arc::new(SeedKeySource::new(test_seed_phrase())),
                birthday: 419_200,
                num_accounts: Some(2),
                gap_limit: 5,
                lightwalletd_url: "https://example.invalid:443".to_owned(),
                data_dir,
                network: ZeckNetwork::Mainnet,
                label: String::new(),
            }
        }

        fn test_birthday() -> AccountBirthday {
            // Sapling activation is at 419200; the prior chain state is block 419199.
            // ChainState::empty sets empty commitment trees — valid for a scan
            // that doesn't need real note data (account-import idempotency tests).
            AccountBirthday::from_parts(
                ChainState::empty(BlockHeight::from_u32(419_199), BlockHash([0u8; 32])),
                None,
            )
        }

        #[tokio::test]
        async fn wallet_db_persists_after_workspace_handle_is_dropped() {
            let tempdir = tempfile::tempdir().expect("temp dir");
            let config = test_config(tempdir.path().to_owned());
            let workspace = RecoveryWorkspace::from_runtime(&config).expect("workspace");
            let seed = mnemonic_seed(&test_seed_phrase()).expect("seed");
            workspace
                .initialize(config.network, seed.expose_secret())
                .expect("workspace.initialize");
            let transparent_account =
                legacy_transparent_account_key(&test_seed_phrase(), config.network)
                    .expect("transparent account key");
            let accounts =
                derive_accounts(&test_seed_phrase(), config.network, 2).expect("accounts");
            let state = Arc::new(Mutex::new(ScanTaskState::new(ScanHandle::new())));

            import_accounts(
                &workspace,
                config.network,
                seed.expose_secret(),
                &test_birthday(),
                &transparent_account,
                &accounts,
                &state,
            )
            .await
            .expect("import_accounts should succeed");

            let db_path = workspace.wallet_db_path().to_owned();
            // Simulated abort: drop all in-memory state.
            drop(workspace);
            drop(state);

            assert!(
                db_path.exists(),
                "wallet DB must persist on disk after the workspace handle is dropped (resume contract)"
            );
        }

        #[tokio::test]
        async fn resume_reuses_same_workspace_and_does_not_duplicate_accounts() {
            let tempdir = tempfile::tempdir().expect("temp dir");
            let config = test_config(tempdir.path().to_owned());
            let seed = mnemonic_seed(&test_seed_phrase()).expect("seed");
            let transparent_account =
                legacy_transparent_account_key(&test_seed_phrase(), config.network)
                    .expect("transparent account key");
            let accounts =
                derive_accounts(&test_seed_phrase(), config.network, 2).expect("accounts");
            let state = Arc::new(Mutex::new(ScanTaskState::new(ScanHandle::new())));

            // ── First scan pass: import 2 accounts then simulate abort ──────────
            let workspace1 = RecoveryWorkspace::from_runtime(&config).expect("workspace");
            workspace1
                .initialize(config.network, seed.expose_secret())
                .expect("workspace.initialize");
            import_accounts(
                &workspace1,
                config.network,
                seed.expose_secret(),
                &test_birthday(),
                &transparent_account,
                &accounts,
                &state,
            )
            .await
            .expect("first import_accounts should succeed");

            let root1 = workspace1.root().to_owned();
            let db_path = workspace1.wallet_db_path().to_owned();
            drop(workspace1);

            // ── Resume: same config must resolve to the same workspace ───────────
            let workspace2 = RecoveryWorkspace::from_runtime(&config).expect("workspace (resume)");
            assert_eq!(
                workspace2.root(),
                root1,
                "resume must reuse the same workspace directory"
            );
            workspace2
                .initialize(config.network, seed.expose_secret())
                .expect("workspace2.initialize");

            // Re-importing the same accounts must be idempotent.
            import_accounts(
                &workspace2,
                config.network,
                seed.expose_secret(),
                &test_birthday(),
                &transparent_account,
                &accounts,
                &state,
            )
            .await
            .expect("resume import_accounts should succeed");

            // Open the DB and verify account count is still 2, not 4.
            let wallet_db = WalletDb::for_path(
                db_path,
                consensus_network(config.network),
                SystemClock,
                rand_core::OsRng,
            )
            .expect("WalletDb::for_path should succeed");

            let account_ids = wallet_db
                .get_account_ids()
                .expect("get_account_ids should succeed");
            assert_eq!(
                account_ids.len(),
                2,
                "re-importing the same 2 accounts must yield exactly 2 in the DB (not 4)"
            );
        }

        /// Builds an empty (no transactions) `CompactBlock` at the given height
        /// with the given prev-block hash. Tree sizes are unchanged from the
        /// previous block — appropriate for a block with no shielded outputs.
        fn empty_compact_block(
            height: u64,
            prev_hash: [u8; 32],
            sapling_tree_size: u32,
            orchard_tree_size: u32,
        ) -> CompactBlock {
            // Hash needs to be unique within a chain but is not validated for
            // PoW or merkle-root correctness by the scanner. A simple
            // height-derived hash is enough to keep the chain linkage
            // unambiguous for tests with a single-block chain.
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&height.to_le_bytes());
            CompactBlock {
                height,
                hash: hash.to_vec(),
                prev_hash: prev_hash.to_vec(),
                time: 0,
                header: vec![],
                vtx: vec![],
                chain_metadata: Some(ChainMetadata {
                    sapling_commitment_tree_size: sapling_tree_size,
                    orchard_commitment_tree_size: orchard_tree_size,
                    // These fixtures model blocks below Ironwood activation, so the
                    // Ironwood tree has not started growing yet.
                    ironwood_commitment_tree_size: 0,
                }),
            }
        }

        /// End-to-end resume contract test:
        ///   1. Import accounts into a fresh workspace.
        ///   2. Prime the wallet's view of subtree roots + chain tip, then call
        ///      `scan_cached_blocks` on a single empty block at birthday+1.
        ///   3. Verify `fully_scanned_height` advanced to the scanned height.
        ///   4. Drop all in-memory state (simulated cancel/abort).
        ///   5. Re-open the workspace with the same config and re-open the DB.
        ///   6. Verify the persisted `fully_scanned_height` matches step 3.
        ///   7. Bump the chain tip and check `suggest_scan_ranges` only returns
        ///      ranges starting strictly above the previous cursor — i.e. a
        ///      resume scan would skip the already-scanned block instead of
        ///      restarting from the birthday.
        #[tokio::test]
        async fn scan_advances_cursor_and_resume_skips_already_scanned_blocks() {
            let tempdir = tempfile::tempdir().expect("temp dir");
            let config = test_config(tempdir.path().to_owned());
            let seed = mnemonic_seed(&test_seed_phrase()).expect("seed");
            let transparent_account =
                legacy_transparent_account_key(&test_seed_phrase(), config.network)
                    .expect("transparent account key");
            let accounts =
                derive_accounts(&test_seed_phrase(), config.network, 1).expect("accounts");
            let state = Arc::new(Mutex::new(ScanTaskState::new(ScanHandle::new())));

            let network = consensus_network(config.network);
            // Birthday is 419_200 (Sapling activation). The block prior is
            // 419_199 with empty Sapling/Orchard frontiers.
            let birthday_height: u32 = 419_200;
            let scan_height = BlockHeight::from_u32(birthday_height);
            let chain_state_before_scan = ChainState::empty(
                BlockHeight::from_u32(birthday_height - 1),
                BlockHash([0u8; 32]),
            );

            // ─── Initial scan: import + scan one empty block ─────────────────
            let workspace1 = RecoveryWorkspace::from_runtime(&config).expect("workspace");
            workspace1
                .initialize(config.network, seed.expose_secret())
                .expect("workspace.initialize");
            import_accounts(
                &workspace1,
                config.network,
                seed.expose_secret(),
                &test_birthday(),
                &transparent_account,
                &accounts,
                &state,
            )
            .await
            .expect("import_accounts should succeed");

            let wallet_db_path = workspace1.wallet_db_path().to_owned();

            {
                let cache = MemoryBlockCache::new();
                let mut wallet_db =
                    WalletDb::for_path(&wallet_db_path, network, SystemClock, rand_core::OsRng)
                        .expect("wallet_db");

                // Prime the wallet's commitment-tree state and chain tip — the
                // same calls that `zcash_client_backend::sync` issues before
                // its first `scan_cached_blocks` invocation.
                wallet_db
                    .put_sapling_subtree_roots(0, &[])
                    .expect("put_sapling_subtree_roots");
                wallet_db
                    .put_orchard_subtree_roots(0, &[])
                    .expect("put_orchard_subtree_roots");
                wallet_db
                    .update_chain_tip(scan_height)
                    .expect("update_chain_tip");

                let block = empty_compact_block(scan_height.into(), [0u8; 32], 0, 0);
                <MemoryBlockCache as super::super::BlockCache>::insert(&cache, vec![block])
                    .await
                    .expect("cache insert");

                scan_cached_blocks(
                    &network,
                    &cache,
                    &mut wallet_db,
                    scan_height,
                    &chain_state_before_scan,
                    1,
                )
                .expect("scan_cached_blocks");

                let summary = wallet_db
                    .get_wallet_summary(ConfirmationsPolicy::MIN)
                    .expect("get_wallet_summary")
                    .expect("wallet summary present after scan");
                assert_eq!(
                    summary.fully_scanned_height(),
                    scan_height,
                    "fully_scanned_height must advance to the scanned block"
                );
            }
            // Simulated cancel: every in-memory handle dropped.
            drop(workspace1);

            // ─── Resume: same config must reuse the on-disk wallet DB ────────
            let workspace2 = RecoveryWorkspace::from_runtime(&config).expect("workspace (resume)");
            workspace2
                .initialize(config.network, seed.expose_secret())
                .expect("workspace2.initialize");
            assert_eq!(
                workspace2.wallet_db_path(),
                wallet_db_path,
                "resume must resolve to the same wallet DB path"
            );

            let mut wallet_db = WalletDb::for_path(
                workspace2.wallet_db_path(),
                network,
                SystemClock,
                rand_core::OsRng,
            )
            .expect("wallet_db reopen");

            let summary = wallet_db
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .expect("get_wallet_summary on reopen")
                .expect("wallet summary present after reopen");
            assert_eq!(
                summary.fully_scanned_height(),
                scan_height,
                "fully_scanned_height must be preserved across cancel/resume"
            );

            // Advance the wallet's view of the chain tip to mimic discovering
            // new blocks during the resume. The next suggested scan range must
            // start strictly above the preserved cursor, proving a resume
            // would not re-scan the already-scanned block.
            let resumed_tip = BlockHeight::from_u32(birthday_height + 100);
            wallet_db
                .update_chain_tip(resumed_tip)
                .expect("update_chain_tip on resume");

            let ranges = wallet_db
                .suggest_scan_ranges()
                .expect("suggest_scan_ranges on resume");
            assert!(
                !ranges.is_empty(),
                "with a chain tip above the cursor, resume should suggest at least one scan range"
            );
            for range in &ranges {
                let start = u32::from(range.block_range().start);
                assert!(
                    start > u32::from(scan_height),
                    "resume scan range must start above the preserved fully_scanned_height \
                     ({}); got {} for range {:?}",
                    u32::from(scan_height),
                    start,
                    range,
                );
            }
        }
    }

    /// Pins the `BlockSource`/`BlockCache` semantics of `MemoryBlockCache`
    /// that `zcash_client_backend::sync::run` and `scan_cached_blocks` rely on.
    mod memory_block_cache {
        use zcash_client_backend::{
            data_api::{
                chain::{error::Error as ChainError, BlockCache, BlockSource},
                scanning::{ScanPriority, ScanRange},
            },
            proto::compact_formats::CompactBlock,
        };
        use zcash_protocol::consensus::BlockHeight;

        use super::super::{CacheError, MemoryBlockCache};

        fn test_block(height: u32) -> CompactBlock {
            CompactBlock {
                height: u64::from(height),
                ..Default::default()
            }
        }

        fn scan_range(start: u32, end: u32) -> ScanRange {
            ScanRange::from_parts(
                BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
                ScanPriority::Historic,
            )
        }

        fn collect_heights(
            cache: &MemoryBlockCache,
            from_height: Option<u32>,
            limit: Option<usize>,
        ) -> Result<Vec<u32>, ChainError<std::convert::Infallible, CacheError>> {
            let mut heights = Vec::new();
            cache.with_blocks(from_height.map(BlockHeight::from_u32), limit, |block| {
                heights.push(u32::from(block.height()));
                Ok(())
            })?;
            Ok(heights)
        }

        #[tokio::test]
        async fn insert_then_with_blocks_yields_contiguous_ascending_blocks() {
            let cache = MemoryBlockCache::new();
            cache
                .insert(vec![test_block(102), test_block(100), test_block(101)])
                .await
                .expect("insert");
            let heights =
                collect_heights(&cache, Some(100), None).expect("with_blocks over full range");
            assert_eq!(heights, vec![100, 101, 102]);
        }

        #[tokio::test]
        async fn with_blocks_respects_limit() {
            let cache = MemoryBlockCache::new();
            cache
                .insert((100..110).map(test_block).collect())
                .await
                .expect("insert");
            let heights = collect_heights(&cache, Some(100), Some(3)).expect("limited iteration");
            assert_eq!(heights, vec![100, 101, 102]);
        }

        #[tokio::test]
        async fn with_blocks_errors_on_gap() {
            let cache = MemoryBlockCache::new();
            cache
                .insert(vec![test_block(100), test_block(102)])
                .await
                .expect("insert");
            let err = collect_heights(&cache, Some(100), None)
                .expect_err("gap at 101 must surface as an error");
            assert!(
                matches!(
                    err,
                    ChainError::BlockSource(CacheError::MissingBlock(height))
                        if height == BlockHeight::from_u32(101)
                ),
                "expected MissingBlock(101), got {err:?}"
            );
        }

        #[tokio::test]
        async fn with_blocks_errors_when_start_height_is_absent() {
            let cache = MemoryBlockCache::new();
            cache.insert(vec![test_block(200)]).await.expect("insert");
            let err = collect_heights(&cache, Some(100), None)
                .expect_err("absent start height must surface as an error");
            assert!(
                matches!(
                    err,
                    ChainError::BlockSource(CacheError::MissingBlock(height))
                        if height == BlockHeight::from_u32(100)
                ),
                "expected MissingBlock(100), got {err:?}"
            );
        }

        #[tokio::test]
        async fn read_returns_contiguous_prefix_of_range() {
            let cache = MemoryBlockCache::new();
            cache
                .insert(vec![test_block(100), test_block(101)])
                .await
                .expect("insert");
            let blocks = cache.read(&scan_range(100, 105)).await.expect("read");
            let heights: Vec<u32> = blocks.iter().map(|b| u32::from(b.height())).collect();
            assert_eq!(heights, vec![100, 101]);
        }

        #[tokio::test]
        async fn read_errors_when_range_start_is_missing() {
            let cache = MemoryBlockCache::new();
            cache.insert(vec![test_block(101)]).await.expect("insert");
            let err = cache
                .read(&scan_range(100, 102))
                .await
                .expect_err("missing range start must error");
            assert!(
                matches!(err, CacheError::MissingBlock(height)
                    if height == BlockHeight::from_u32(100)),
                "expected MissingBlock(100), got {err:?}"
            );
        }

        #[tokio::test]
        async fn get_tip_height_scopes_to_range() {
            let cache = MemoryBlockCache::new();
            cache
                .insert(vec![test_block(100), test_block(101), test_block(500)])
                .await
                .expect("insert");
            let overall = cache.get_tip_height(None).expect("tip overall");
            assert_eq!(overall, Some(BlockHeight::from_u32(500)));
            let range = scan_range(100, 200);
            let scoped = cache.get_tip_height(Some(&range)).expect("tip scoped");
            assert_eq!(scoped, Some(BlockHeight::from_u32(101)));
            let empty_range = scan_range(600, 700);
            let empty = cache
                .get_tip_height(Some(&empty_range))
                .expect("tip of empty range");
            assert_eq!(empty, None);
        }

        #[tokio::test]
        async fn delete_removes_exactly_the_range() {
            let cache = MemoryBlockCache::new();
            cache
                .insert((100..106).map(test_block).collect())
                .await
                .expect("insert");
            cache
                .delete(scan_range(102, 104))
                .await
                .expect("delete range");
            assert_eq!(
                collect_heights(&cache, Some(100), Some(2)).expect("prefix survives"),
                vec![100, 101]
            );
            assert_eq!(
                collect_heights(&cache, Some(104), None).expect("suffix survives"),
                vec![104, 105]
            );
            let err = collect_heights(&cache, Some(102), Some(1))
                .expect_err("deleted heights must read as missing");
            assert!(matches!(
                err,
                ChainError::BlockSource(CacheError::MissingBlock(_))
            ));
        }
    }

    // ─── stall watchdog (covers R-N15 production behaviour) ──────────────
    //
    // These tests run under tokio's paused-time clock so the 60 s threshold
    // doesn't burn wall-clock. We construct a `SharedScanTaskState` by hand
    // (without spinning up a real scan), mutate `progress.synced_to_height`
    // from a sibling task to simulate ProgressPoller's behaviour, and
    // observe whether the watchdog tripped or not.
    mod stall_watchdog_tests {
        use std::sync::Arc;
        use std::time::Duration;

        use tokio::sync::Mutex;

        use super::super::{
            stall_watchdog, ScanTaskState, SharedScanTaskState, SANDBLASTING_STALL_TIMEOUT_SECS,
            STALL_CHECK_INTERVAL_SECS, STALL_TIMEOUT_SECS,
        };
        use crate::ScanHandle;

        fn empty_state() -> SharedScanTaskState {
            Arc::new(Mutex::new(ScanTaskState::new(ScanHandle::new())))
        }

        async fn set_height(state: &SharedScanTaskState, h: u64) {
            state.lock().await.progress.synced_to_height = Some(h);
        }

        async fn set_sandblasting(state: &SharedScanTaskState, value: bool) {
            state.lock().await.progress.in_sandblasting_zone = value;
        }

        /// Inside the sandblasting window a batch is bound by local
        /// trial-decryption CPU, not by network latency, and routinely runs
        /// past the normal budget. Tripping there is a livelock: the retry
        /// restarts the same batch, which is killed at the same point, so the
        /// scan can never cross the era.
        #[tokio::test(start_paused = true)]
        async fn does_not_fire_at_the_normal_budget_inside_the_sandblasting_zone() {
            let state = empty_state();
            set_height(&state, 2_000_000).await;
            set_sandblasting(&state, true).await;

            let watchdog = {
                let state = state.clone();
                tokio::spawn(async move { stall_watchdog(&state).await })
            };

            tokio::time::advance(Duration::from_secs(
                STALL_TIMEOUT_SECS * 4 + STALL_CHECK_INTERVAL_SECS,
            ))
            .await;
            tokio::task::yield_now().await;

            assert!(
                !watchdog.is_finished(),
                "watchdog tripped at the normal budget inside the sandblasting zone"
            );
            watchdog.abort();
        }

        /// The extended budget is still a budget — a genuinely hung stream in
        /// the zone must eventually surface rather than hang forever.
        #[tokio::test(start_paused = true)]
        async fn fires_at_the_extended_budget_inside_the_sandblasting_zone() {
            let state = empty_state();
            set_height(&state, 2_000_000).await;
            set_sandblasting(&state, true).await;

            let watchdog = {
                let state = state.clone();
                tokio::spawn(async move { stall_watchdog(&state).await })
            };

            tokio::time::advance(Duration::from_secs(
                SANDBLASTING_STALL_TIMEOUT_SECS + STALL_CHECK_INTERVAL_SECS,
            ))
            .await;
            tokio::task::yield_now().await;

            assert!(
                watchdog.await.expect("watchdog task did not panic").to_string().contains("scan stalled"),
                "watchdog must still trip at the extended budget"
            );
        }

        /// The watchdog observes only that a batch has not committed. It has
        /// no evidence about the network, so it must not invent any — a
        /// fabricated transport error sends users chasing servers for what is
        /// usually local scanning cost.
        #[tokio::test(start_paused = true)]
        async fn stall_error_does_not_fabricate_a_network_failure() {
            let state = empty_state();
            set_height(&state, 100).await;

            let watchdog = {
                let state = state.clone();
                tokio::spawn(async move { stall_watchdog(&state).await })
            };

            tokio::time::advance(Duration::from_secs(
                STALL_TIMEOUT_SECS + STALL_CHECK_INTERVAL_SECS,
            ))
            .await;
            tokio::task::yield_now().await;

            let msg = watchdog.await.expect("watchdog task did not panic").to_string();
            assert!(msg.contains("scan stalled"), "got: {msg}");
            for lie in [
                "h2 protocol error",
                "hung stream",
                "lightwalletd probe failed",
            ] {
                assert!(
                    !msg.contains(lie),
                    "stall error must not claim {lie:?} — nothing observed the network; got: {msg}"
                );
            }
        }

        /// Dropping the fabricated "h2 protocol error" marker must not cost
        /// the stall its place in the retry loop.
        #[test]
        fn stall_error_is_still_classified_as_retryable() {
            assert!(crate::lightwalletd::is_transient_network_error(
                "scan stalled: no block committed for 60s"
            ));
        }

        #[tokio::test(start_paused = true)]
        async fn fires_after_threshold_when_height_never_advances() {
            let state = empty_state();
            set_height(&state, 100).await;

            // Spawn the watchdog; it must trip within the threshold + one
            // poll interval of paused-time advancement.
            let watchdog = {
                let state = state.clone();
                tokio::spawn(async move { stall_watchdog(&state).await })
            };

            // Advance paused time by STALL_TIMEOUT + one full check interval
            // to give the loop body time to observe the final stalled tick.
            tokio::time::advance(Duration::from_secs(
                STALL_TIMEOUT_SECS + STALL_CHECK_INTERVAL_SECS,
            ))
            .await;
            tokio::task::yield_now().await;

            let err = watchdog.await.expect("watchdog task did not panic");
            let msg = err.to_string();
            assert!(
                msg.contains("scan stalled"),
                "watchdog error must include the stall marker; got: {msg}"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn does_not_fire_when_height_advances_each_tick() {
            let state = empty_state();
            set_height(&state, 0).await;

            let watchdog = {
                let state = state.clone();
                tokio::spawn(async move { stall_watchdog(&state).await })
            };

            // Make the height advance every STALL_CHECK_INTERVAL_SECS for
            // twice the trip threshold. The watchdog should never fire.
            let ticks_to_run = (STALL_TIMEOUT_SECS / STALL_CHECK_INTERVAL_SECS) * 2 + 4;
            for tick in 1..=ticks_to_run {
                tokio::time::advance(Duration::from_secs(STALL_CHECK_INTERVAL_SECS)).await;
                tokio::task::yield_now().await;
                set_height(&state, tick).await;
            }

            // Watchdog must still be awaiting — it returns *only* on stall.
            assert!(
                !watchdog.is_finished(),
                "watchdog tripped while height was advancing every tick"
            );
            watchdog.abort();
        }

        #[tokio::test(start_paused = true)]
        async fn resets_on_resumed_progress_after_partial_stall() {
            let state = empty_state();
            set_height(&state, 50).await;

            let watchdog = {
                let state = state.clone();
                tokio::spawn(async move { stall_watchdog(&state).await })
            };

            // Stall for half the threshold, then resume advancing.
            let half_ticks = (STALL_TIMEOUT_SECS / STALL_CHECK_INTERVAL_SECS) / 2;
            for _ in 0..half_ticks {
                tokio::time::advance(Duration::from_secs(STALL_CHECK_INTERVAL_SECS)).await;
                tokio::task::yield_now().await;
            }

            // Resume advancement for past the original threshold.
            let resumed_ticks = (STALL_TIMEOUT_SECS / STALL_CHECK_INTERVAL_SECS) + 4;
            for tick in 1..=resumed_ticks {
                tokio::time::advance(Duration::from_secs(STALL_CHECK_INTERVAL_SECS)).await;
                tokio::task::yield_now().await;
                set_height(&state, 50 + tick).await;
            }

            assert!(
                !watchdog.is_finished(),
                "watchdog tripped after stall was resolved by resumed progress"
            );
            watchdog.abort();
        }
    }

    // ─── retry-budget reset (issue #174) ─────────────────────────────────
    //
    // The retry loop in `run_wallet_sync_with_retry` must bound *consecutive*
    // failures with no forward progress, not the lifetime total. These tests
    // exercise the pure decision helper directly.
    mod retry_budget_tests {
        use super::super::{retry_budget_after_failure, MAX_SYNC_RETRIES};

        #[test]
        fn resets_when_height_advanced_since_last_failure() {
            // 9 consecutive stalls, then the sync advanced before the next
            // failure — the intervening stall recovered, so the budget resets.
            assert_eq!(
                retry_budget_after_failure(9, Some(1_000), Some(1_500)),
                0
            );
        }

        #[test]
        fn preserves_budget_when_stuck_at_same_height() {
            // No forward progress between the two failures — budget carries.
            assert_eq!(
                retry_budget_after_failure(5, Some(1_000), Some(1_000)),
                5
            );
        }

        #[test]
        fn preserves_budget_on_first_failure_before_any_progress() {
            // No prior failure height and no progress yet: nothing to reset.
            assert_eq!(retry_budget_after_failure(0, None, None), 0);
            assert_eq!(retry_budget_after_failure(3, None, Some(1_000)), 3);
        }

        #[test]
        fn a_scan_that_makes_progress_between_stalls_never_exhausts_budget() {
            // Simulate many isolated stalls, each preceded by real progress.
            // Without the reset this would blow past MAX_SYNC_RETRIES; with it,
            // the budget never climbs above 1.
            let mut attempts = 0u32;
            let mut last_failure_height: Option<u64> = None;
            for i in 0..(MAX_SYNC_RETRIES as u64 * 5) {
                let current = Some(1_000 + i * 100); // advanced every time
                attempts = retry_budget_after_failure(attempts, last_failure_height, current);
                assert!(
                    attempts < MAX_SYNC_RETRIES,
                    "budget exhausted despite forward progress between stalls"
                );
                last_failure_height = current;
                attempts += 1;
            }
        }

        #[test]
        fn consecutive_stalls_with_no_progress_still_exhaust_budget() {
            // A genuinely hung server (no progress) must still hit the cap.
            let mut attempts = 0u32;
            let mut last_failure_height: Option<u64> = None;
            let mut bailed = false;
            for _ in 0..(MAX_SYNC_RETRIES + 5) {
                let current = Some(2_000); // stuck forever
                attempts = retry_budget_after_failure(attempts, last_failure_height, current);
                if attempts >= MAX_SYNC_RETRIES {
                    bailed = true;
                    break;
                }
                last_failure_height = current;
                attempts += 1;
            }
            assert!(bailed, "hung server never hit the retry cap");
        }
    }
}
