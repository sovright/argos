//! Reviewed Sprout intent: what the user reviewed is what executes.
//!
//! **Key retention.** A scan session keeps its decoded Sprout spending keys,
//! and a reviewed proposal keeps the notes it will spend (`SpendableSproutNote`
//! carries the raw `a_sk`), in this process's memory only. Nothing here is
//! written to disk; the one spend-capable file remains the scan checkpoint,
//! which `sprout_scan_run` writes at `0600`. Execution used to re-read and
//! re-decrypt the wallet file, or re-collect the panel's keys, from form
//! fields at click time. That let execution diverge from the review (a
//! different file, passphrase, key box, network or server than the one the
//! user approved). Holding the reviewed material binds execution to the
//! review; wallet-backed execution reopens the file only to verify its
//! backend-held snapshot identity before any network or proving work, at the cost
//! of keeping keys resident for a bounded time:
//!
//! - a proposal lives at most [`PROPOSAL_TTL`], is swept on every store
//!   access, and is dropped on execute (one-shot) or explicit release;
//! - a running scan lives until it finishes or is explicitly released. A
//!   completed or failed scan lives at most [`SCAN_SECRET_TTL`], long enough
//!   to review a result without retaining abandoned keys for the process life.
//! - at most [`MAX_SCAN_SESSIONS`] scans and [`MAX_PROPOSALS`] proposals.
//!
//! Scan-key buffers are wiped when their final owner drops. The store and its
//! worker share that owner so cancellation cannot wipe keys while the worker
//! is still using them.
//!
//! This is process-memory hygiene, not process isolation. Rust may copy fixed
//! arrays through registers or stack temporaries, and zeroization cannot
//! protect swap, core dumps, DMA, or a process that is already compromised.

use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use argos_core::{sprout_recovery::SpendableSproutNote, sprout_sweep::SweepJournal, ZeckNetwork};
use secrecy::zeroize::Zeroize;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::commands::{SproutScanReport, SproutSweepResult};

pub const MAX_SCAN_SESSIONS: usize = 16;
pub const MAX_PROPOSALS: usize = 32;
pub const MAX_IN_FLIGHT_CHECKPOINTS: usize = 16;
pub const MAX_WALLET_REVIEWS: usize = 16;
pub const WALLET_REVIEW_TTL: Duration = Duration::from_secs(30 * 60);
/// Completed and failed scans retain their keys only for the review window.
pub const SCAN_SECRET_TTL: Duration = Duration::from_secs(30 * 60);
/// How long a reviewed Sprout proposal stays executable. Long enough to read
/// the review and tick the box; short enough that spending keys held for it
/// do not linger behind a review the user walked away from.
pub const PROPOSAL_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SproutScanHandle(pub String);

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SproutProposalId(pub String);

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletReviewId(pub String);

/// Backend-owned authority for the exact file object and bytes inspected.
/// It deliberately exposes neither the digest nor object identity to IPC.
#[derive(PartialEq, Eq)]
pub struct ReviewedWalletSource {
    review_id: WalletReviewId,
    path: PathBuf,
    identity: Arc<argos_core::wallet_file::WalletFileIdentity>,
}

impl ReviewedWalletSource {
    pub fn verify(&self) -> Result<argos_core::wallet_file::WalletFileSnapshot, String> {
        argos_core::wallet_file::verify_wallet_snapshot(&self.path, &self.identity)
            .map_err(|err| err.to_string())
    }
}

struct StoredWalletReview {
    source: Arc<ReviewedWalletSource>,
    created: Instant,
}

struct WalletReviewInner {
    reviews: HashMap<WalletReviewId, StoredWalletReview>,
    ttl: Duration,
}

impl Default for WalletReviewInner {
    fn default() -> Self {
        Self {
            reviews: HashMap::new(),
            ttl: WALLET_REVIEW_TTL,
        }
    }
}

#[derive(Clone, Default)]
pub struct WalletReviewRegistry(Arc<Mutex<WalletReviewInner>>);

impl WalletReviewRegistry {
    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(WalletReviewInner {
            ttl,
            ..WalletReviewInner::default()
        })))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, WalletReviewInner>, String> {
        self.0
            .lock()
            .map_err(|_| "wallet review registry unavailable".to_owned())
    }

    fn sweep_expired(inner: &mut WalletReviewInner) {
        let now = Instant::now();
        let ttl = inner.ttl;
        inner
            .reviews
            .retain(|_, stored| now.saturating_duration_since(stored.created) < ttl);
    }

    pub fn register(
        &self,
        path: PathBuf,
        identity: Arc<argos_core::wallet_file::WalletFileIdentity>,
    ) -> Result<WalletReviewId, String> {
        let mut inner = self.lock()?;
        Self::sweep_expired(&mut inner);
        if inner.reviews.len() >= MAX_WALLET_REVIEWS {
            return Err(
                "too many wallet reviews; inspect the file again after an older review expires"
                    .into(),
            );
        }
        let review_id = loop {
            let candidate = WalletReviewId(Uuid::new_v4().to_string());
            if !inner.reviews.contains_key(&candidate) {
                break candidate;
            }
        };
        let source = Arc::new(ReviewedWalletSource {
            review_id: review_id.clone(),
            path,
            identity,
        });
        inner.reviews.insert(
            review_id.clone(),
            StoredWalletReview {
                source,
                created: Instant::now(),
            },
        );
        Ok(review_id)
    }

    pub fn resolve(&self, id: &WalletReviewId) -> Result<Arc<ReviewedWalletSource>, String> {
        let mut inner = self.lock()?;
        Self::sweep_expired(&mut inner);
        inner
            .reviews
            .get(id)
            .map(|stored| Arc::clone(&stored.source))
            .ok_or_else(|| "unknown or expired wallet review; inspect the wallet again".to_owned())
    }

    pub fn verify(
        &self,
        id: &WalletReviewId,
    ) -> Result<
        (
            Arc<ReviewedWalletSource>,
            argos_core::wallet_file::WalletFileSnapshot,
        ),
        String,
    > {
        let source = self.resolve(id)?;
        self.verify_source(&source)
            .map(|snapshot| (source, snapshot))
    }

    pub fn verify_source(
        &self,
        source: &Arc<ReviewedWalletSource>,
    ) -> Result<argos_core::wallet_file::WalletFileSnapshot, String> {
        match source.verify() {
            Ok(snapshot) => Ok(snapshot),
            Err(err) => {
                if let Ok(mut inner) = self.lock() {
                    let is_matching = inner
                        .reviews
                        .get(&source.review_id)
                        .is_some_and(|stored| Arc::ptr_eq(&stored.source, source));
                    if is_matching {
                        inner.reviews.remove(&source.review_id);
                    }
                }
                Err(err)
            }
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SproutScanStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Serialize)]
pub struct SproutScanSnapshot {
    pub handle: SproutScanHandle,
    pub status: SproutScanStatus,
    pub report: Option<SproutScanReport>,
    pub error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SproutScanProgressEvent {
    pub handle: SproutScanHandle,
    pub height: u32,
    pub target: u32,
    pub notes_found: usize,
    pub joinsplits_seen: u64,
    pub peer_wait: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct SproutSweepPreviewData {
    pub notes: usize,
    pub gross_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub net_zatoshis: u64,
    pub active: Vec<SproutSweepResult>,
    pub mined: Vec<SproutSweepResult>,
}

#[derive(Serialize)]
pub struct ReviewedSproutSweep {
    pub proposal_id: SproutProposalId,
    #[serde(flatten)]
    pub plan: SproutSweepPreviewData,
    pub params_present: bool,
    pub params_path: String,
    pub lands_in_sapling: String,
    /// NU7's Sprout spending deadline, shown before the user commits.
    pub nu7_warning: String,
    /// Shown with the review, e.g. Sprout keys dropped as forged.
    pub warnings: Vec<String>,
    /// The verdict from verifying a saved scan for this review, which may
    /// differ from the earlier inspection if the checkpoint or chain changed.
    pub scan_warning: Option<String>,
}

/// Where a proposal's notes came from. A wallet proposal holds both the
/// reviewed notes and an Arc to the backend-owned file snapshot identity.
/// The registry may expire while the proposal remains live; execute still
/// re-verifies the exact source before it touches the network or prover.
#[derive(PartialEq, Eq)]
pub enum SproutIntentSource {
    Wallet(Arc<ReviewedWalletSource>),
    Scan(SproutScanHandle),
}

pub struct SproutSweepIntent {
    pub source: SproutIntentSource,
    pub notes: Vec<SpendableSproutNote>,
    pub destination: String,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    pub journal: SweepJournal,
    pub wallet_checkpoint: Option<WalletCheckpointAuthority>,
    pub checkpoint_authority: Option<argos_core::sprout_sweep::ScanCheckpointAuthority>,
    pub _checkpoint_reservation: Option<CheckpointReservation>,
    /// Set when the catch-up scan behind a scan-derived proposal could not
    /// confirm the chain tip; it leads the sweep report's warnings.
    pub tip_warning: Option<String>,
    /// A wallet proposal's verdict from verifying its saved scan against
    /// live headers at review time (#272). It ends the sweep report's
    /// warnings and is appended to a sweep error. Execution also re-verifies
    /// canonical spends before it uses the reviewed notes.
    pub chain_notice: Option<String>,
    /// Set when the scan panel's peer field was malformed at review time.
    /// The review degrades to a warning, but execution refuses the proposal.
    pub peer_error: Option<String>,
}

pub struct WalletCheckpointAuthority {
    pub data_dir: PathBuf,
    pub keys: SecretSproutKeys,
    pub peers: Vec<String>,
}

/// A single zeroizing owner for decoded Sprout spending keys.
///
/// This type deliberately provides only immutable borrowed access and has no
/// `Clone`, `Debug`, serialization, or owned-plaintext getter. Long-running
/// scans share it through `Arc`, so the final owner is the one that wipes it.
pub struct SecretSproutKeys {
    keys: Vec<[u8; 32]>,
    #[cfg(test)]
    drop_probe: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl SecretSproutKeys {
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        Self {
            keys,
            #[cfg(test)]
            drop_probe: None,
        }
    }

    pub fn as_slice(&self) -> &[[u8; 32]] {
        &self.keys
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[cfg(test)]
    fn with_drop_probe(keys: Vec<[u8; 32]>, probe: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            keys,
            drop_probe: Some(probe),
        }
    }
}

impl From<Vec<[u8; 32]>> for SecretSproutKeys {
    fn from(keys: Vec<[u8; 32]>) -> Self {
        Self::new(keys)
    }
}

impl Drop for SecretSproutKeys {
    fn drop(&mut self) {
        self.keys.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            debug_assert!(self
                .keys
                .iter()
                .all(|key| key.iter().all(|byte| *byte == 0)));
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

pub struct ScanMaterial {
    pub keys: Arc<SecretSproutKeys>,
    pub key_fingerprint: String,
    pub checkpoint: PathBuf,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    pub peers: Vec<String>,
}

struct SproutScanSession {
    keys: Arc<SecretSproutKeys>,
    key_fingerprint: String,
    checkpoint: PathBuf,
    network: ZeckNetwork,
    lightwalletd_url: String,
    confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    peers: Vec<String>,
    status: SproutScanStatus,
    report: Option<SproutScanReport>,
    error: Option<String>,
    finished_at: Option<Instant>,
    /// Stops the scan worker. Dropping its future also drops the checkpoint
    /// reservation it owns, so a released scan frees its checkpoint at once.
    /// The checkpoint is saved atomically every few hundred blocks, so an
    /// abort costs at most that much progress, and a later scan of the same
    /// keys resumes from it.
    worker: Option<ScanWorker>,
    catchup: Option<ScanCatchupControl>,
}

#[derive(Clone)]
struct ScanCatchupControl {
    id: Uuid,
    cancellation: ScanCancellation,
    completion: ScanWorkerCompletion,
}

struct ScanCancellationInner {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

#[derive(Clone)]
struct ScanCancellation(Arc<ScanCancellationInner>);

impl ScanCancellation {
    fn new() -> Self {
        Self(Arc::new(ScanCancellationInner {
            cancelled: std::sync::atomic::AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }))
    }

    fn cancel(&self) {
        self.0
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.0.notify.notify_one();
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.0.notify.notified();
            if self.0.cancelled.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// RAII authority for one in-flight scan catch-up. Releasing or expiring the
/// scan signals cancellation, and release waits for this lease to drop so the
/// catch-up's `ScanMaterial` key owner cannot outlive the release response.
pub struct ScanCatchupLease {
    store: Weak<Mutex<StoreInner>>,
    handle: SproutScanHandle,
    id: Uuid,
    cancellation: ScanCancellation,
    completion_guard: Option<ScanWorkerCompletionGuard>,
}

impl ScanCatchupLease {
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }
}

impl Drop for ScanCatchupLease {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            let mut inner = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(scan) = inner.scans.get_mut(&self.handle) {
                if scan
                    .catchup
                    .as_ref()
                    .is_some_and(|active| active.id == self.id)
                {
                    scan.catchup = None;
                }
            }
        }
        drop(self.completion_guard.take());
    }
}

struct ScanWorker {
    abort: tokio::task::AbortHandle,
    completion: ScanWorkerCompletion,
}

struct ScanWorkerCompletionInner {
    finished: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

/// Lets cancellation wait until the worker future has dropped every key
/// owner. The completion guard belongs to the supervisor that awaits the
/// abortable scan task; its `Drop` covers success, error, panic and abort.
#[derive(Clone)]
pub struct ScanWorkerCompletion(Arc<ScanWorkerCompletionInner>);

impl ScanWorkerCompletion {
    pub fn new() -> Self {
        Self(Arc::new(ScanWorkerCompletionInner {
            finished: std::sync::atomic::AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }))
    }

    pub fn guard(&self) -> ScanWorkerCompletionGuard {
        ScanWorkerCompletionGuard(Some(Arc::clone(&self.0)))
    }

    async fn wait(&self) {
        loop {
            let notified = self.0.notify.notified();
            if self.0.finished.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

impl Default for ScanWorkerCompletion {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ScanWorkerCompletionGuard(Option<Arc<ScanWorkerCompletionInner>>);

impl Drop for ScanWorkerCompletionGuard {
    fn drop(&mut self) {
        if let Some(completion) = self.0.take() {
            completion
                .finished
                .store(true, std::sync::atomic::Ordering::Release);
            completion.notify.notify_one();
        }
    }
}

struct StoredProposal {
    intent: SproutSweepIntent,
    created: Instant,
}

struct StoreInner {
    scans: HashMap<SproutScanHandle, SproutScanSession>,
    proposals: HashMap<SproutProposalId, StoredProposal>,
    checkpoint_reservations: Arc<Mutex<HashSet<PathBuf>>>,
    proposal_ttl: Duration,
    scan_ttl: Duration,
}

impl Default for StoreInner {
    fn default() -> Self {
        Self {
            scans: HashMap::new(),
            proposals: HashMap::new(),
            checkpoint_reservations: Arc::new(Mutex::new(HashSet::new())),
            proposal_ttl: PROPOSAL_TTL,
            scan_ttl: SCAN_SECRET_TTL,
        }
    }
}

impl StoreInner {
    /// Drop every proposal and finished scan past its TTL. Both maps change
    /// under this mutex, so a scan can never disappear while a proposal tied
    /// to its key material remains executable.
    fn sweep_expired(&mut self) {
        let now = Instant::now();
        let proposal_ttl = self.proposal_ttl;
        self.proposals
            .retain(|_, stored| now.saturating_duration_since(stored.created) < proposal_ttl);

        let scan_ttl = self.scan_ttl;
        let expired_scans = self
            .scans
            .iter()
            .filter_map(|(handle, scan)| {
                scan.finished_at
                    .filter(|finished| now.saturating_duration_since(*finished) >= scan_ttl)
                    .map(|_| handle.clone())
            })
            .collect::<HashSet<_>>();
        if expired_scans.is_empty() {
            return;
        }
        for handle in &expired_scans {
            if let Some(catchup) = self
                .scans
                .get(handle)
                .and_then(|scan| scan.catchup.as_ref())
            {
                catchup.cancellation.cancel();
            }
        }
        self.proposals.retain(|_, stored| {
            !matches!(
                &stored.intent.source,
                SproutIntentSource::Scan(handle) if expired_scans.contains(handle)
            )
        });
        self.scans
            .retain(|handle, _| !expired_scans.contains(handle));
    }

    fn lock(
        store: &Arc<Mutex<StoreInner>>,
    ) -> Result<std::sync::MutexGuard<'_, StoreInner>, String> {
        let mut inner = store
            .lock()
            .map_err(|_| "Sprout review store unavailable".to_owned())?;
        inner.sweep_expired();
        Ok(inner)
    }
}

/// A scan or catch-up owns this reservation until its future finishes or is
/// dropped. The guard also releases on unwinding; it never exposes keys.
pub struct CheckpointReservation {
    reservations: Arc<Mutex<HashSet<PathBuf>>>,
    identity: PathBuf,
}

impl Drop for CheckpointReservation {
    fn drop(&mut self) {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reservations.remove(&self.identity);
    }
}

fn checkpoint_identity(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| format!("resolving checkpoint location: {err}"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or("invalid Sprout checkpoint directory")?;
    let filename = absolute
        .file_name()
        .ok_or("invalid Sprout checkpoint path")?;
    let mut resolved = PathBuf::new();
    // Resolve each existing prefix before applying a later `..`. Lexically
    // removing `link/..` first is wrong when `link` points into another tree.
    // Once a component does not exist, keep it in the path so reservations
    // also work before the scanner creates its data directory or checkpoint.
    for component in parent.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                let candidate = resolved.join(name);
                match candidate.canonicalize() {
                    Ok(canonical) => resolved = canonical,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => resolved = candidate,
                    Err(err) => {
                        return Err(format!("resolving Sprout checkpoint directory: {err}"))
                    }
                }
            }
            root_or_prefix => resolved.push(root_or_prefix.as_os_str()),
        }
    }
    Ok(resolved.join(filename))
}

#[derive(Default)]
pub struct ReviewedIntentStore(Arc<Mutex<StoreInner>>);

impl Clone for ReviewedIntentStore {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl ReviewedIntentStore {
    fn schedule_expiry_sweep(&self, after: Duration) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // Synchronous callers (principally unit tests) still sweep on
            // every access. Production commands always run in Tokio.
            return;
        };
        let store = Arc::clone(&self.0);
        runtime.spawn(async move {
            tokio::time::sleep(after).await;
            drop(StoreInner::lock(&store));
        });
    }

    #[cfg(test)]
    pub fn with_proposal_ttl(proposal_ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(StoreInner {
            proposal_ttl,
            ..StoreInner::default()
        })))
    }

    #[cfg(test)]
    pub fn with_retention(proposal_ttl: Duration, scan_ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(StoreInner {
            proposal_ttl,
            scan_ttl,
            ..StoreInner::default()
        })))
    }

    #[cfg(test)]
    pub fn proposal_count(&self) -> usize {
        StoreInner::lock(&self.0).map_or(0, |inner| inner.proposals.len())
    }

    pub fn reserve_checkpoint(&self, checkpoint: &Path) -> Result<CheckpointReservation, String> {
        let identity = checkpoint_identity(checkpoint)?;
        let reservations = StoreInner::lock(&self.0)?.checkpoint_reservations.clone();
        let mut held = reservations
            .lock()
            .map_err(|_| "Sprout checkpoint reservation store unavailable".to_owned())?;
        if held.contains(&identity) {
            return Err("a Sprout scan or catch-up is already using this checkpoint".into());
        }
        if held.len() >= MAX_IN_FLIGHT_CHECKPOINTS {
            return Err("too many Sprout scans or catch-ups are running".into());
        }
        held.insert(identity.clone());
        drop(held);
        Ok(CheckpointReservation {
            reservations,
            identity,
        })
    }

    pub fn ensure_scan_proposal_capacity(&self, handle: &SproutScanHandle) -> Result<(), String> {
        let inner = StoreInner::lock(&self.0)?;
        let scan = inner
            .scans
            .get(handle)
            .ok_or("unknown or released Sprout scan")?;
        if !matches!(scan.status, SproutScanStatus::Completed) {
            return Err("wait for the Sprout scan to complete".into());
        }
        if inner.proposals.len() >= MAX_PROPOSALS {
            return Err("too many Sprout proposals; release an old proposal first".into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_scan(
        &self,
        keys: impl Into<SecretSproutKeys>,
        key_fingerprint: String,
        checkpoint: PathBuf,
        network: ZeckNetwork,
        lightwalletd_url: String,
        confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
        peers: Vec<String>,
    ) -> Result<SproutScanHandle, String> {
        let mut inner = StoreInner::lock(&self.0)?;
        if inner.scans.len() >= MAX_SCAN_SESSIONS {
            return Err("too many Sprout scans; release an old scan first".into());
        }
        let handle = SproutScanHandle(Uuid::new_v4().to_string());
        inner.scans.insert(
            handle.clone(),
            SproutScanSession {
                keys: Arc::new(keys.into()),
                key_fingerprint,
                checkpoint,
                network,
                lightwalletd_url,
                confirmation_sources,
                peers,
                status: SproutScanStatus::Running,
                report: None,
                error: None,
                finished_at: None,
                worker: None,
                catchup: None,
            },
        );
        Ok(handle)
    }

    pub fn scan_material(&self, handle: &SproutScanHandle) -> Result<ScanMaterial, String> {
        let inner = StoreInner::lock(&self.0)?;
        let scan = inner
            .scans
            .get(handle)
            .ok_or("unknown or released Sprout scan")?;
        Ok(ScanMaterial {
            keys: Arc::clone(&scan.keys),
            key_fingerprint: scan.key_fingerprint.clone(),
            checkpoint: scan.checkpoint.clone(),
            network: scan.network,
            lightwalletd_url: scan.lightwalletd_url.clone(),
            confirmation_sources: scan.confirmation_sources.clone(),
            peers: scan.peers.clone(),
        })
    }

    pub fn register_catchup(&self, handle: &SproutScanHandle) -> Result<ScanCatchupLease, String> {
        let mut inner = StoreInner::lock(&self.0)?;
        let scan = inner
            .scans
            .get_mut(handle)
            .ok_or("unknown or released Sprout scan")?;
        if !matches!(scan.status, SproutScanStatus::Completed) {
            return Err("wait for the Sprout scan to complete".into());
        }
        if scan.catchup.is_some() {
            return Err("a catch-up for this Sprout scan is already running".into());
        }
        let id = Uuid::new_v4();
        let cancellation = ScanCancellation::new();
        let completion = ScanWorkerCompletion::new();
        scan.catchup = Some(ScanCatchupControl {
            id,
            cancellation: cancellation.clone(),
            completion: completion.clone(),
        });
        Ok(ScanCatchupLease {
            store: Arc::downgrade(&self.0),
            handle: handle.clone(),
            id,
            cancellation,
            completion_guard: Some(completion.guard()),
        })
    }

    pub fn snapshot(&self, handle: &SproutScanHandle) -> Result<SproutScanSnapshot, String> {
        let inner = StoreInner::lock(&self.0)?;
        let scan = inner
            .scans
            .get(handle)
            .ok_or("unknown or released Sprout scan")?;
        Ok(SproutScanSnapshot {
            handle: handle.clone(),
            status: scan.status.clone(),
            report: scan.report.clone(),
            error: scan.error.clone(),
        })
    }

    /// Hand the store the scan worker's abort handle. A scan released before
    /// this lands is already gone, so its worker is stopped here instead.
    pub fn attach_worker(
        &self,
        handle: &SproutScanHandle,
        abort: tokio::task::AbortHandle,
        completion: ScanWorkerCompletion,
    ) {
        let worker = ScanWorker { abort, completion };
        let orphaned = match StoreInner::lock(&self.0) {
            Ok(mut inner) => match inner.scans.get_mut(handle) {
                Some(scan) => {
                    if matches!(scan.status, SproutScanStatus::Running) {
                        scan.worker = Some(worker);
                    }
                    None
                }
                None => Some(worker),
            },
            Err(_) => Some(worker),
        };
        // Outside the lock: the worker's reservation takes it when dropped.
        if let Some(worker) = orphaned {
            worker.abort.abort();
        }
    }

    pub fn finish_scan(&self, handle: &SproutScanHandle, result: Result<SproutScanReport, String>) {
        let mut finished_ttl = None;
        if let Ok(mut inner) = StoreInner::lock(&self.0) {
            // A released scan was removed; its late result has nowhere to go.
            if let Some(scan) = inner.scans.get_mut(handle) {
                scan.worker = None;
                match result {
                    Ok(report) => {
                        scan.status = SproutScanStatus::Completed;
                        scan.report = Some(report);
                    }
                    Err(error) => {
                        scan.status = SproutScanStatus::Failed;
                        scan.error = Some(error);
                    }
                }
                scan.finished_at = Some(Instant::now());
                finished_ttl = Some(inner.scan_ttl);
            }
        }
        if let Some(ttl) = finished_ttl {
            self.schedule_expiry_sweep(ttl);
        }
    }

    pub async fn release_scan(&self, handle: &SproutScanHandle) -> Result<(), String> {
        let scan = {
            let mut inner = StoreInner::lock(&self.0)?;
            let scan = inner
                .scans
                .remove(handle)
                .ok_or("unknown or released Sprout scan")?;
            inner.proposals.retain(|_, stored| {
                !matches!(&stored.intent.source, SproutIntentSource::Scan(source) if source == handle)
            });
            scan
        };
        // Running or not, the session and its keys go now. A running worker
        // is aborted, which drops its checkpoint reservation with it, so the
        // same scan can be started again at once rather than after it ends.
        // Outside the lock, which that reservation's drop takes.
        if let Some(worker) = &scan.worker {
            worker.abort.abort();
        }
        if let Some(catchup) = &scan.catchup {
            catchup.cancellation.cancel();
        }
        if let Some(worker) = &scan.worker {
            worker.completion.wait().await;
        }
        if let Some(catchup) = &scan.catchup {
            catchup.completion.wait().await;
        }
        drop(scan);
        Ok(())
    }

    pub fn insert_proposal(
        &self,
        intent: SproutSweepIntent,
        plan: SproutSweepPreviewData,
    ) -> Result<ReviewedSproutSweep, String> {
        let params_path = argos_core::sprout_sweep::default_params_path();
        let params_present = params_path.exists();
        let params_path = params_path.display().to_string();
        let mut inner = StoreInner::lock(&self.0)?;
        if inner.proposals.len() >= MAX_PROPOSALS {
            return Err("too many Sprout proposals; release an old proposal first".into());
        }
        if let SproutIntentSource::Scan(handle) = &intent.source {
            let scan = inner
                .scans
                .get(handle)
                .ok_or("unknown or released Sprout scan")?;
            if !matches!(scan.status, SproutScanStatus::Completed) {
                return Err("Sprout scan has not completed".into());
            }
        }
        let nu7_warning = argos_core::sprout_sweep::nu7_recovery_warning(intent.network);
        let proposal_id = SproutProposalId(Uuid::new_v4().to_string());
        inner.proposals.insert(
            proposal_id.clone(),
            StoredProposal {
                intent,
                created: Instant::now(),
            },
        );
        let proposal_ttl = inner.proposal_ttl;
        drop(inner);
        self.schedule_expiry_sweep(proposal_ttl);
        Ok(ReviewedSproutSweep {
            proposal_id,
            plan,
            params_present,
            params_path,
            lands_in_sapling: argos_core::sprout_sweep::SPROUT_LANDS_IN_SAPLING.to_owned(),
            nu7_warning,
            warnings: Vec::new(),
            scan_warning: None,
        })
    }

    pub fn take_proposal(&self, id: &SproutProposalId) -> Result<SproutSweepIntent, String> {
        let mut inner = StoreInner::lock(&self.0)?;
        let intent = inner
            .proposals
            .remove(id)
            .ok_or("unknown or already used Sprout proposal")?
            .intent;
        if let SproutIntentSource::Scan(handle) = &intent.source {
            if !inner.scans.contains_key(handle) {
                return Err("Sprout scan was released".into());
            }
        }
        Ok(intent)
    }

    pub fn take_wallet_proposal(&self, id: &SproutProposalId) -> Result<SproutSweepIntent, String> {
        {
            let inner = StoreInner::lock(&self.0)?;
            let intent = inner
                .proposals
                .get(id)
                .ok_or("unknown or already used Sprout proposal")?;
            if !matches!(intent.intent.source, SproutIntentSource::Wallet(_)) {
                return Err("proposal belongs to a scan-derived sweep".into());
            }
        }
        self.take_proposal(id)
    }

    pub fn take_scan_proposal(&self, id: &SproutProposalId) -> Result<SproutSweepIntent, String> {
        {
            let inner = StoreInner::lock(&self.0)?;
            let intent = inner
                .proposals
                .get(id)
                .ok_or("unknown or already used Sprout proposal")?;
            if !matches!(intent.intent.source, SproutIntentSource::Scan(_)) {
                return Err("proposal belongs to a wallet-derived sweep".into());
            }
        }
        self.take_proposal(id)
    }

    pub fn release_proposal(&self, id: &SproutProposalId) -> Result<(), String> {
        let mut inner = StoreInner::lock(&self.0)?;
        inner
            .proposals
            .remove(id)
            .ok_or("unknown or already used Sprout proposal")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_core::ZeckNetwork;
    use std::path::PathBuf;

    fn journal(marker: u8) -> SweepJournal {
        SweepJournal::for_keys(
            &std::env::temp_dir().join(format!("argos-reviewed-journal-{}", Uuid::new_v4())),
            &[[marker; 32]],
            ZeckNetwork::Mainnet,
        )
    }

    fn wallet_source(marker: u8) -> Arc<ReviewedWalletSource> {
        let registry = WalletReviewRegistry::default();
        let dir = std::env::temp_dir().join(format!("argos-wallet-source-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        std::fs::write(&path, [marker]).unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let id = registry
            .register(path, Arc::new(snapshot.identity().clone()))
            .unwrap();
        registry.resolve(&id).unwrap()
    }

    fn scan(store: &ReviewedIntentStore, marker: u8) -> SproutScanHandle {
        store
            .insert_scan(
                vec![[marker; 32]],
                format!("fingerprint-{marker}"),
                PathBuf::from(format!("/tmp/scan-{marker}")),
                ZeckNetwork::Mainnet,
                format!("https://node-{marker}"),
                Vec::new(),
                vec![format!("peer-{marker}:8233")],
            )
            .inspect(|handle| {
                store.finish_scan(
                    handle,
                    Ok(SproutScanReport {
                        blocks_scanned: 1,
                        joinsplits_seen: 2,
                        notes_found: 1,
                        spent_notes: 0,
                        total_zatoshis: 100_000,
                        has_lifecycle_status: false,
                        tip_warning: None,
                        decrypt_from_height: None,
                        decrypt_line: String::new(),
                    }),
                );
            })
            .unwrap()
    }

    fn proposal(
        store: &ReviewedIntentStore,
        source: SproutIntentSource,
        destination: &str,
    ) -> SproutProposalId {
        let endpoint = match &source {
            SproutIntentSource::Scan(handle) => {
                store.scan_material(handle).unwrap().lightwalletd_url
            }
            SproutIntentSource::Wallet(_) => "https://node-a".to_owned(),
        };
        store
            .insert_proposal(
                SproutSweepIntent {
                    source,
                    notes: Vec::new(),
                    destination: destination.to_owned(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: endpoint,
                    confirmation_sources: Vec::new(),
                    journal: journal(1),
                    wallet_checkpoint: None,
                    checkpoint_authority: None,
                    _checkpoint_reservation: None,
                    tip_warning: None,
                    chain_notice: None,
                    peer_error: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000,
                    active: Vec::new(),
                    mined: Vec::new(),
                },
            )
            .unwrap()
            .proposal_id
    }

    #[test]
    fn sprout_intent_preserves_source_destination_and_network() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        let intent = store.take_proposal(&id).unwrap();
        assert!(matches!(intent.source, SproutIntentSource::Scan(actual) if actual == handle));
        assert_eq!(intent.destination, "zs-reviewed");
        assert_eq!(intent.network, ZeckNetwork::Mainnet);
    }

    #[test]
    fn sprout_intent_is_one_shot() {
        let store = ReviewedIntentStore::default();
        let id = proposal(
            &store,
            SproutIntentSource::Wallet(wallet_source(1)),
            "zs-reviewed",
        );
        assert!(store.take_proposal(&id).is_ok());
        assert!(store.take_proposal(&id).is_err());
    }

    #[test]
    fn wrong_execution_route_cannot_consume_a_proposal() {
        let store = ReviewedIntentStore::default();
        let id = proposal(
            &store,
            SproutIntentSource::Wallet(wallet_source(2)),
            "zs-reviewed",
        );
        assert!(store.take_scan_proposal(&id).is_err());
        assert!(store.take_wallet_proposal(&id).is_ok());
    }

    #[test]
    fn overlapping_wallet_reviews_remain_until_explicit_release() {
        let store = ReviewedIntentStore::default();
        // B finishes first; older A returns later. A must not evict the ID
        // already displayed for B, and B remains one-shot executable.
        let b = proposal(&store, SproutIntentSource::Wallet(wallet_source(3)), "zs-B");
        let a = proposal(&store, SproutIntentSource::Wallet(wallet_source(4)), "zs-A");
        assert_eq!(store.take_wallet_proposal(&b).unwrap().destination, "zs-B");
        assert!(store.take_wallet_proposal(&b).is_err());
        store.release_proposal(&a).unwrap();
        assert_eq!(
            store.take_proposal(&a).err().unwrap(),
            "unknown or already used Sprout proposal"
        );
    }

    #[test]
    fn a_scan_handle_is_required_to_propose_a_scan_sweep() {
        let store = ReviewedIntentStore::default();
        let absent = SproutScanHandle("absent".into());
        assert!(store.scan_material(&absent).is_err());
        assert!(store
            .insert_proposal(
                SproutSweepIntent {
                    source: SproutIntentSource::Scan(absent),
                    notes: Vec::new(),
                    destination: "zs-reviewed".into(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: "https://node-a".into(),
                    confirmation_sources: Vec::new(),
                    journal: journal(2),
                    wallet_checkpoint: None,
                    checkpoint_authority: None,
                    _checkpoint_reservation: None,
                    tip_warning: None,
                    chain_notice: None,
                    peer_error: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000,
                    active: Vec::new(),
                    mined: Vec::new(),
                }
            )
            .is_err());
    }

    #[tokio::test]
    async fn scan_a_result_cannot_be_swept_under_scan_b() {
        let store = ReviewedIntentStore::default();
        let a = scan(&store, 1);
        let b = scan(&store, 2);
        let id = proposal(&store, SproutIntentSource::Scan(a.clone()), "zs-reviewed");
        assert_ne!(
            store.scan_material(&a).unwrap().key_fingerprint,
            store.scan_material(&b).unwrap().key_fingerprint
        );
        store.release_scan(&a).await.unwrap();
        assert!(store.take_proposal(&id).is_err());
        assert!(store.scan_material(&b).is_ok());
    }

    #[test]
    fn sprout_review_store_is_bounded() {
        let store = ReviewedIntentStore::default();
        for i in 0..MAX_SCAN_SESSIONS {
            scan(&store, i as u8);
        }
        assert!(store
            .insert_scan(
                vec![[99; 32]],
                "overflow".into(),
                PathBuf::from("/tmp/overflow"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new()
            )
            .is_err());
        for _ in 0..MAX_PROPOSALS {
            proposal(
                &store,
                SproutIntentSource::Wallet(wallet_source(5)),
                "zs-reviewed",
            );
        }
        assert!(store
            .insert_proposal(
                SproutSweepIntent {
                    source: SproutIntentSource::Wallet(wallet_source(6)),
                    notes: Vec::new(),
                    destination: "zs-reviewed".into(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: "https://node".into(),
                    confirmation_sources: Vec::new(),
                    journal: journal(3),
                    wallet_checkpoint: None,
                    checkpoint_authority: None,
                    _checkpoint_reservation: None,
                    tip_warning: None,
                    chain_notice: None,
                    peer_error: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000,
                    active: Vec::new(),
                    mined: Vec::new(),
                }
            )
            .is_err());
    }

    /// Finding 10: a released scan is gone, running or not, so it never
    /// holds a slot that a new scan needs.
    #[tokio::test]
    async fn released_running_scans_do_not_count_toward_the_limit() {
        let store = ReviewedIntentStore::default();
        for i in 0..MAX_SCAN_SESSIONS {
            let handle = store
                .insert_scan(
                    vec![[i as u8; 32]],
                    format!("fingerprint-{i}"),
                    PathBuf::from(format!("/tmp/scan-{i}")),
                    ZeckNetwork::Mainnet,
                    "https://node".into(),
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap();
            store.release_scan(&handle).await.unwrap();
            assert!(store.snapshot(&handle).is_err());
        }
        assert!(store
            .insert_scan(
                vec![[99; 32]],
                "replacement".into(),
                PathBuf::from("/tmp/replacement"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new()
            )
            .is_ok());
    }

    /// Finding 3: releasing a running scan stops its worker, so the
    /// checkpoint reservation the worker owns is freed at once and the same
    /// scan can be started again, instead of failing for hours.
    #[tokio::test]
    async fn releasing_a_running_scan_aborts_its_worker_and_frees_its_checkpoint() {
        let store = ReviewedIntentStore::default();
        let checkpoint = std::env::temp_dir()
            .join(format!("argos-abort-{}", Uuid::new_v4()))
            .join("scan.checkpoint");
        let handle = store
            .insert_scan(
                vec![[3; 32]],
                "fingerprint-3".into(),
                checkpoint.clone(),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        let reservation = store.reserve_checkpoint(&checkpoint).unwrap();
        let completion = ScanWorkerCompletion::new();
        let completion_guard = completion.guard();
        let worker = tokio::spawn(async move {
            let _completion_guard = completion_guard;
            let _reservation = reservation;
            std::future::pending::<()>().await;
        });
        store.attach_worker(&handle, worker.abort_handle(), completion);
        store.release_scan(&handle).await.unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("release stops the worker promptly");
        assert!(joined.is_err_and(|err| err.is_cancelled()));
        assert!(store.reserve_checkpoint(&checkpoint).is_ok());
        assert!(store.snapshot(&handle).is_err());
    }

    #[tokio::test]
    async fn release_waits_for_worker_drop_before_reporting_keys_gone() {
        let store = ReviewedIntentStore::default();
        let handle = store
            .insert_scan(
                vec![[40; 32]],
                "fingerprint-40".into(),
                PathBuf::from("/tmp/scan-40"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let mut inner = StoreInner::lock(&store.0).unwrap();
            inner.scans.get_mut(&handle).unwrap().keys = Arc::new(
                SecretSproutKeys::with_drop_probe(vec![[40; 32]], Arc::clone(&probe)),
            );
        }
        let material = store.scan_material(&handle).unwrap();
        let completion = ScanWorkerCompletion::new();
        let completion_guard = completion.guard();
        let worker = tokio::spawn(async move {
            let _completion_guard = completion_guard;
            let _material = material;
            std::future::pending::<()>().await;
        });
        store.attach_worker(&handle, worker.abort_handle(), completion);

        store.release_scan(&handle).await.unwrap();

        assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
        assert!(worker.await.is_err_and(|err| err.is_cancelled()));
    }

    #[tokio::test]
    async fn release_cancels_catchup_and_waits_for_its_final_key_owner() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 41);
        let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let mut inner = StoreInner::lock(&store.0).unwrap();
            inner.scans.get_mut(&handle).unwrap().keys = Arc::new(
                SecretSproutKeys::with_drop_probe(vec![[41; 32]], Arc::clone(&probe)),
            );
        }
        let catchup = store.register_catchup(&handle).unwrap();
        let material = store.scan_material(&handle).unwrap();
        let task = tokio::spawn(async move {
            let _material = material;
            tokio::select! {
                () = catchup.cancelled() => true,
                () = std::future::pending::<()>() => false,
            }
        });

        store.release_scan(&handle).await.unwrap();

        assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
        assert!(task.await.unwrap(), "catch-up observed cancellation");
    }

    /// A release that lands before the worker is attached still stops it.
    #[tokio::test]
    async fn a_worker_attached_after_release_is_aborted() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 4);
        // `scan` completes the session; make a running one instead.
        store.release_scan(&handle).await.unwrap();
        let handle = store
            .insert_scan(
                vec![[5; 32]],
                "fingerprint-5".into(),
                PathBuf::from("/tmp/scan-5"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        store.release_scan(&handle).await.unwrap();
        let completion = ScanWorkerCompletion::new();
        let completion_guard = completion.guard();
        let worker = tokio::spawn(async move {
            let _completion_guard = completion_guard;
            std::future::pending::<()>().await;
        });
        store.attach_worker(&handle, worker.abort_handle(), completion);
        let joined = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("a late-attached worker is stopped");
        assert!(joined.is_err_and(|err| err.is_cancelled()));
    }

    #[tokio::test]
    async fn a_late_worker_result_cannot_recreate_a_released_scan() {
        let store = ReviewedIntentStore::default();
        let handle = store
            .insert_scan(
                vec![[6; 32]],
                "fingerprint-6".into(),
                PathBuf::from("/tmp/scan-6"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        store.release_scan(&handle).await.unwrap();

        store.finish_scan(&handle, Err("late failure".into()));

        assert!(store.snapshot(&handle).is_err());
    }

    /// Finding 5: a reviewed proposal holds raw Sprout spending keys in its
    /// notes, so it does not outlive its review window.
    #[test]
    fn sprout_proposals_expire() {
        let store = ReviewedIntentStore::with_proposal_ttl(std::time::Duration::ZERO);
        let id = proposal(
            &store,
            SproutIntentSource::Wallet(wallet_source(7)),
            "zs-reviewed",
        );
        assert_eq!(
            store.take_wallet_proposal(&id).err().unwrap(),
            "unknown or already used Sprout proposal"
        );
        assert_eq!(store.proposal_count(), 0, "expired proposals are dropped");

        let store = ReviewedIntentStore::default();
        let id = proposal(
            &store,
            SproutIntentSource::Wallet(wallet_source(8)),
            "zs-reviewed",
        );
        assert!(store.take_wallet_proposal(&id).is_ok());
        assert_eq!(PROPOSAL_TTL, std::time::Duration::from_secs(15 * 60));
    }

    #[test]
    fn completed_and_failed_scans_expire_but_running_scans_do_not() {
        let store =
            ReviewedIntentStore::with_retention(Duration::from_secs(15 * 60), Duration::ZERO);
        let completed = scan(&store, 31);
        let failed = store
            .insert_scan(
                vec![[32; 32]],
                "fingerprint-32".into(),
                PathBuf::from("/tmp/scan-32"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        store.finish_scan(&failed, Err("peer failure".into()));
        let running = store
            .insert_scan(
                vec![[33; 32]],
                "fingerprint-33".into(),
                PathBuf::from("/tmp/scan-33"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();

        assert!(store.snapshot(&completed).is_err());
        assert!(store.snapshot(&failed).is_err());
        assert!(matches!(
            store.snapshot(&running).unwrap().status,
            SproutScanStatus::Running
        ));
    }

    #[test]
    fn scan_expiry_atomically_evicts_its_proposals() {
        let store = ReviewedIntentStore::with_retention(
            Duration::from_secs(15 * 60),
            Duration::from_millis(20),
        );
        let handle = scan(&store, 34);
        let proposal_id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        std::thread::sleep(Duration::from_millis(50));

        assert!(store.snapshot(&handle).is_err());
        assert!(store.take_scan_proposal(&proposal_id).is_err());
    }

    #[tokio::test]
    async fn finished_scan_keys_are_wiped_at_ttl_without_another_store_access() {
        let store = ReviewedIntentStore::with_retention(
            Duration::from_secs(15 * 60),
            Duration::from_millis(20),
        );
        let handle = store
            .insert_scan(
                vec![[35; 32]],
                "fingerprint-35".into(),
                PathBuf::from("/tmp/scan-35"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let mut inner = StoreInner::lock(&store.0).unwrap();
            inner.scans.get_mut(&handle).unwrap().keys = Arc::new(
                SecretSproutKeys::with_drop_probe(vec![[35; 32]], Arc::clone(&probe)),
            );
        }
        store.finish_scan(&handle, Err("peer failure".into()));

        tokio::time::sleep(Duration::from_millis(60)).await;

        assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn scan_keys_zeroize_only_after_the_last_owner_drops() {
        let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keys = Arc::new(SecretSproutKeys::with_drop_probe(
            vec![[0x5a; 32]],
            Arc::clone(&probe),
        ));
        let clone = Arc::clone(&keys);

        drop(keys);
        assert!(!probe.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(clone.as_slice(), &[[0x5a; 32]]);
        drop(clone);
        assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Expired proposals free their slots for new reviews.
    #[test]
    fn expired_proposals_do_not_fill_the_store() {
        let store = ReviewedIntentStore::with_proposal_ttl(std::time::Duration::ZERO);
        for _ in 0..MAX_PROPOSALS + 1 {
            proposal(
                &store,
                SproutIntentSource::Wallet(wallet_source(9)),
                "zs-reviewed",
            );
        }
    }

    #[test]
    fn checkpoint_reservation_rejects_overlapping_scan_and_catchup() {
        let store = ReviewedIntentStore::default();
        let checkpoint = PathBuf::from("/tmp/argos-reservation-a.checkpoint");
        let running_scan = store.reserve_checkpoint(&checkpoint).unwrap();
        assert!(store.reserve_checkpoint(&checkpoint).is_err());
        drop(running_scan);
        assert!(store.reserve_checkpoint(&checkpoint).is_ok());
    }

    #[test]
    fn scan_proposal_holds_checkpoint_reservation_through_execution_take() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 21);
        let checkpoint = store.scan_material(&handle).unwrap().checkpoint;
        let reservation = store.reserve_checkpoint(&checkpoint).unwrap();
        let review = store
            .insert_proposal(
                SproutSweepIntent {
                    source: SproutIntentSource::Scan(handle),
                    notes: Vec::new(),
                    destination: "zs-reviewed".into(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: "https://node-21".into(),
                    confirmation_sources: Vec::new(),
                    journal: journal(21),
                    wallet_checkpoint: None,
                    checkpoint_authority: None,
                    _checkpoint_reservation: Some(reservation),
                    tip_warning: None,
                    chain_notice: None,
                    peer_error: None,
                },
                SproutSweepPreviewData {
                    notes: 0,
                    gross_zatoshis: 0,
                    fee_zatoshis: 0,
                    net_zatoshis: 0,
                    active: Vec::new(),
                    mined: Vec::new(),
                },
            )
            .unwrap();
        assert!(store.reserve_checkpoint(&checkpoint).is_err());
        let executing = store.take_scan_proposal(&review.proposal_id).unwrap();
        assert!(store.reserve_checkpoint(&checkpoint).is_err());
        drop(executing);
        assert!(store.reserve_checkpoint(&checkpoint).is_ok());
    }

    #[test]
    fn checkpoint_reservation_normalizes_path_aliases() {
        let store = ReviewedIntentStore::default();
        let checkpoint = PathBuf::from("/tmp/argos-reservation-b.checkpoint");
        let _running = store.reserve_checkpoint(&checkpoint).unwrap();
        assert!(store
            .reserve_checkpoint(&PathBuf::from("/tmp/./argos-reservation-b.checkpoint"))
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_reservation_resolves_symlinked_parent_before_file_exists() {
        let root = std::env::temp_dir().join(format!("argos-reservation-link-{}", Uuid::new_v4()));
        let real = root.join("real");
        let alias = root.join("alias");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let store = ReviewedIntentStore::default();
        let _reservation = store
            .reserve_checkpoint(&real.join("scan.checkpoint"))
            .unwrap();
        assert!(store
            .reserve_checkpoint(&alias.join("scan.checkpoint"))
            .is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_reservation_resolves_symlink_before_parent_of_missing_directory() {
        let root =
            std::env::temp_dir().join(format!("argos-reservation-dotdot-{}", Uuid::new_v4()));
        let real = root.join("real");
        let nested = real.join("sub");
        let link = root.join("link");
        std::fs::create_dir_all(&nested).unwrap();
        std::os::unix::fs::symlink(&nested, &link).unwrap();
        let store = ReviewedIntentStore::default();
        let expected = real.join("new/scan.checkpoint");
        let alias = link.join("../new/scan.checkpoint");
        assert!(!expected.exists());
        let _reservation = store.reserve_checkpoint(&expected).unwrap();
        assert!(
            store.reserve_checkpoint(&alias).is_err(),
            "link/../new and real/new resolve to the same future checkpoint"
        );
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn checkpoint_reservations_bound_work_before_proposals_exist() {
        let store = ReviewedIntentStore::default();
        let reservations: Vec<_> = (0..MAX_IN_FLIGHT_CHECKPOINTS)
            .map(|i| {
                store
                    .reserve_checkpoint(&PathBuf::from(format!(
                        "/tmp/argos-reservation-{i}.checkpoint"
                    )))
                    .unwrap()
            })
            .collect();
        assert!(store
            .reserve_checkpoint(&PathBuf::from("/tmp/argos-reservation-overflow.checkpoint"))
            .is_err());
        drop(reservations);
        assert!(store
            .reserve_checkpoint(&PathBuf::from("/tmp/argos-reservation-overflow.checkpoint"))
            .is_ok());
    }

    #[test]
    fn checkpoint_reservation_releases_on_unwind() {
        let store = ReviewedIntentStore::default();
        let checkpoint = PathBuf::from("/tmp/argos-reservation-panic.checkpoint");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _reservation = store.reserve_checkpoint(&checkpoint).unwrap();
            panic!("worker stopped");
        }));
        assert!(result.is_err());
        assert!(store.reserve_checkpoint(&checkpoint).is_ok());
    }

    #[tokio::test]
    async fn release_drops_scan_and_proposal_authority() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        store.release_scan(&handle).await.unwrap();
        assert!(store.snapshot(&handle).is_err());
        assert!(store.take_proposal(&id).is_err());
        let wallet = proposal(
            &store,
            SproutIntentSource::Wallet(wallet_source(10)),
            "zs-reviewed",
        );
        store.release_proposal(&wallet).unwrap();
        assert!(store.take_proposal(&wallet).is_err());
    }

    #[test]
    fn sprout_progress_is_tagged_with_its_handle() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let value = serde_json::to_value(SproutScanProgressEvent {
            handle: handle.clone(),
            height: 50,
            target: 100,
            notes_found: 1,
            joinsplits_seen: 2,
            peer_wait: None,
        })
        .unwrap();
        assert_eq!(value["handle"], handle.0);
        assert_eq!(value["height"], 50);
    }

    fn reviewed_wallet(
        registry: &WalletReviewRegistry,
        bytes: &[u8],
    ) -> (PathBuf, PathBuf, WalletReviewId) {
        let dir = std::env::temp_dir().join(format!("argos-wallet-review-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        std::fs::write(&path, bytes).unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let id = registry
            .register(path.clone(), Arc::new(snapshot.identity().clone()))
            .unwrap();
        (dir, path, id)
    }

    #[test]
    fn stale_or_unknown_review_id_is_rejected() {
        let registry = WalletReviewRegistry::with_ttl(Duration::ZERO);
        let (dir, _path, id) = reviewed_wallet(&registry, b"wallet");
        assert!(registry.verify(&id).is_err());
        assert!(registry
            .verify(&WalletReviewId("unknown".to_owned()))
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_wallet_revokes_matching_review_id() {
        let registry = WalletReviewRegistry::default();
        let (dir, path, id) = reviewed_wallet(&registry, b"wallet-A");
        std::fs::write(&path, b"wallet-B").unwrap();
        assert!(registry.verify(&id).is_err());
        assert!(registry.verify(&id).is_err(), "the rejected ID was revoked");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retained_source_mismatch_revokes_matching_review_id() {
        let registry = WalletReviewRegistry::default();
        let (dir, path, id) = reviewed_wallet(&registry, b"wallet-A");
        let source = registry.resolve(&id).unwrap();
        std::fs::write(&path, b"wallet-B").unwrap();
        assert!(registry.verify_source(&source).is_err());
        assert!(
            registry.resolve(&id).is_err(),
            "the rejected ID was revoked"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn registry_expiry_does_not_kill_a_reviewed_proposal() {
        let registry = WalletReviewRegistry::with_ttl(Duration::from_millis(5));
        let (dir, _path, id) = reviewed_wallet(&registry, b"wallet");
        let source = registry.resolve(&id).unwrap();
        let store = ReviewedIntentStore::default();
        let proposal_id = proposal(
            &store,
            SproutIntentSource::Wallet(Arc::clone(&source)),
            "zs-reviewed",
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(registry.resolve(&id).is_err(), "registry entry expired");
        let intent = store.take_wallet_proposal(&proposal_id).unwrap();
        let SproutIntentSource::Wallet(retained) = intent.source else {
            panic!("wallet proposal source changed")
        };
        assert!(
            retained.verify().is_ok(),
            "proposal retains reviewed source"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wallet_review_registry_is_bounded() {
        let registry = WalletReviewRegistry::default();
        let mut roots = Vec::new();
        for marker in 0..MAX_WALLET_REVIEWS {
            let reviewed = reviewed_wallet(&registry, &[marker as u8]);
            roots.push(reviewed);
        }
        let dir = std::env::temp_dir().join(format!("argos-wallet-review-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("overflow.dat");
        std::fs::write(&path, b"overflow").unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        assert!(registry
            .register(path, Arc::new(snapshot.identity().clone()))
            .is_err());
        for (dir, _, _) in roots {
            std::fs::remove_dir_all(dir).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
