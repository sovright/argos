use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use rustls::crypto::ring::default_provider;
use secrecy::{ExposeSecret, SecretVec};
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
        wallet::ConfirmationsPolicy,
        Account as _, AccountBirthday, InputSource, TransparentOutputFilter, WalletRead,
        WalletWrite, Zip32Derivation,
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
        derive_accounts, legacy_transparent_account_key, legacy_transparent_pubkey, mnemonic_seed,
    },
    error::{ZeckError, ZeckResult},
    lightwalletd::{
        build_probe, describe_lightwalletd_endpoints, validate_lightwalletd_network,
        validated_lightwalletd_endpoints,
    },
    models::{
        in_sandblasting_zone, AccountBalancePreview, AddressScope, DerivedAccount, DiscoveryPool,
        LightwalletdProbe, RuntimeScanConfig, ScanDiscovery, ScanHandle, ScanPhase, ScanProgress,
        ScanSummary, SleepEvent,
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
        guard.progress.message = Some("Validating BIP-39 seed phrase.".to_owned());
    }

    let seed = mnemonic_seed(&config.seed_phrase)?;
    let workspace = RecoveryWorkspace::from_runtime(&config)?;
    workspace.initialize(config.network, seed.expose_secret())?;
    let transparent_account = legacy_transparent_account_key(&config.seed_phrase, config.network)?;

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
    let network = consensus_network(config.network);
    let initial_accounts = derive_accounts(&config.seed_phrase, config.network, target_accounts)?;

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

        let derived_accounts =
            derive_accounts(&config.seed_phrase, config.network, target_accounts)?;
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
            seed.expose_secret(),
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

        target_accounts = (target_accounts + config.gap_limit).min(max_accounts);
    }

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
    guard.progress.accounts = accounts.iter().map(build_account_preview).collect();
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
    network: &zcash_protocol::consensus::Network,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    state: &SharedScanTaskState,
) -> ZeckResult<()> {
    tokio::select! {
        biased;
        result = run_wallet_sync(workspace, network, client) => result,
        err = stall_watchdog(state) => Err(err),
    }
}

/// Runs `run_wallet_sync`, reconnecting to lightwalletd on transient transport
/// errors.  Each reconnection attempt tries all configured endpoints in order.
/// Permanent errors (wallet database corruption, etc.) are returned immediately.
pub(crate) async fn run_wallet_sync_with_retry(
    workspace: &RecoveryWorkspace,
    network: &zcash_protocol::consensus::Network,
    zeck_network: crate::models::ZeckNetwork,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    lightwalletd_url: &str,
    state: &SharedScanTaskState,
) -> ZeckResult<()> {
    let mut attempts = 0u32;
    loop {
        match run_wallet_sync_with_stall_watchdog(workspace, network, client, state).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                let msg = err.to_string();
                // Transport/stream drops AND DNS-resolution failures are
                // transient and worth reconnecting on (shared classifier so the
                // mid-sync and startup paths agree on what is retryable).
                let is_transient = crate::lightwalletd::is_transient_network_error(&msg);

                if !is_transient || attempts >= MAX_SYNC_RETRIES {
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
    network: &zcash_protocol::consensus::Network,
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
                            TransparentOutputFilter::All,
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
    use secrecy::SecretString;

    use super::{
        append_new_discoveries, build_account_status, resolve_max_account_count,
        trailing_gap_limit_reached,
    };
    use crate::models::{
        AccountBalancePreview, DiscoveryPool, RuntimeScanConfig, ScanDiscovery, ZeckNetwork,
    };

    fn config(num_accounts: Option<u32>) -> RuntimeScanConfig {
        RuntimeScanConfig {
            seed_phrase: SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
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
            models::{RuntimeScanConfig, ScanHandle, ZeckNetwork},
            workspace::{consensus_network, RecoveryWorkspace},
        };

        const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon abandon abandon art";

        fn test_config(data_dir: std::path::PathBuf) -> RuntimeScanConfig {
            RuntimeScanConfig {
                seed_phrase: SecretString::new(TEST_SEED.to_owned()),
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
            let seed = mnemonic_seed(&config.seed_phrase).expect("seed");
            workspace
                .initialize(config.network, seed.expose_secret())
                .expect("workspace.initialize");
            let transparent_account =
                legacy_transparent_account_key(&config.seed_phrase, config.network)
                    .expect("transparent account key");
            let accounts =
                derive_accounts(&config.seed_phrase, config.network, 2).expect("accounts");
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
            let seed = mnemonic_seed(&config.seed_phrase).expect("seed");
            let transparent_account =
                legacy_transparent_account_key(&config.seed_phrase, config.network)
                    .expect("transparent account key");
            let accounts =
                derive_accounts(&config.seed_phrase, config.network, 2).expect("accounts");
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
                proto_version: 1,
                height,
                hash: hash.to_vec(),
                prev_hash: prev_hash.to_vec(),
                time: 0,
                header: vec![],
                vtx: vec![],
                chain_metadata: Some(ChainMetadata {
                    sapling_commitment_tree_size: sapling_tree_size,
                    orchard_commitment_tree_size: orchard_tree_size,
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
            let seed = mnemonic_seed(&config.seed_phrase).expect("seed");
            let transparent_account =
                legacy_transparent_account_key(&config.seed_phrase, config.network)
                    .expect("transparent account key");
            let accounts =
                derive_accounts(&config.seed_phrase, config.network, 1).expect("accounts");
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
}
