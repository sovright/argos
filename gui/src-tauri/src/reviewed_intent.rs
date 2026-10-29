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
//! Held key buffers are wiped on drop: a scan session and a wallet proposal's
//! execute-time verification keys use [`SecretSproutKeys`], while
//! `SpendableSproutNote` zeroizes its `a_sk` and note secrets in its own
//! `Drop`. The store and a running worker share a scan's owner, so cancellation
//! cannot wipe keys while the worker is still using them.
//!
//! This is best-effort process-memory hygiene, not process isolation. Copies
//! made earlier (decoding buffers, a `Vec` reallocation, registers, stack
//! temporaries, and wallet-import types that are not all zeroizing) are not
//! reached, and zeroization cannot protect swap, core dumps, DMA, or an
//! already-compromised process.

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

    /// Release a finished or abandoned inspection without disturbing other
    /// reviews of the same wallet. Repeated cleanup and expired IDs are harmless.
    pub fn release(&self, id: &WalletReviewId) -> Result<(), String> {
        let mut inner = self.lock()?;
        Self::sweep_expired(&mut inner);
        inner.reviews.remove(id);
        Ok(())
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
    /// True only after the command validates a fresh pre-NU7 chain height.
    pub allow_new_spends: bool,
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
    /// Permission derived from this exact review, never from a later UI status.
    /// Absence or elapsed freshness narrows execution to observation only.
    pub spend_authorized_until: Option<Instant>,
    pub source: SproutIntentSource,
    pub notes: Vec<SpendableSproutNote>,
    pub destination: String,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    pub journal: SweepJournal,
    /// Execute-time authority for re-verifying a wallet proposal's saved scan
    /// through the peers used at review. The current verdict replaces the
    /// review-time verdict, and its keys are wiped when the proposal drops.
    pub wallet_checkpoint: Option<WalletCheckpointAuthority>,
    pub checkpoint_authority: Option<argos_core::sprout_sweep::ScanCheckpointAuthority>,
    pub _checkpoint_reservation: Option<CheckpointReservation>,
    /// Set when the catch-up scan behind a scan-derived proposal could not
    /// confirm the chain tip; it leads the sweep report's warnings.
    pub tip_warning: Option<String>,
    /// Set when the scan panel's peer field was malformed at review time.
    /// The review degrades to a warning, but execution refuses the proposal.
    pub peer_error: Option<String>,
}

impl SproutSweepIntent {
    pub fn allows_new_spends(&self) -> bool {
        self.spend_authorized_until
            .is_some_and(|until| Instant::now() < until)
    }

    pub fn restrict_to_observation_only(&mut self) {
        self.spend_authorized_until = None;
    }
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

/// Decided once while the original wallet metadata is available. Retrying
/// changes peers only and never recomputes a birthday from cleared inputs.
#[derive(Clone, Default)]
pub struct ScanDecryptPlan {
    pub decrypt_from: Option<u32>,
    pub decrypt_line: String,
}

pub struct ScanMaterial {
    pub keys: Arc<SecretSproutKeys>,
    pub key_fingerprint: String,
    pub checkpoint: PathBuf,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    pub peers: Vec<String>,
    pub decrypt_plan: ScanDecryptPlan,
}

struct SproutScanSession {
    keys: Arc<SecretSproutKeys>,
    key_fingerprint: String,
    checkpoint: PathBuf,
    network: ZeckNetwork,
    lightwalletd_url: String,
    confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    peers: Vec<String>,
    decrypt_plan: ScanDecryptPlan,
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

#[derive(Clone)]
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
            tokio::pin!(notified);
            notified.as_mut().enable();
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
            completion.notify.notify_waiters();
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
        let scan = inner.scans.get(handle).ok_or(
            "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
        )?;
        if !matches!(scan.status, SproutScanStatus::Completed) {
            return Err("wait for the Sprout scan to complete".into());
        }
        if inner.proposals.len() >= MAX_PROPOSALS {
            return Err("too many Sprout proposals; release an old proposal first".into());
        }
        Ok(())
    }

    #[cfg(test)]
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
        self.insert_scan_with_plan(
            keys,
            key_fingerprint,
            checkpoint,
            network,
            lightwalletd_url,
            confirmation_sources,
            peers,
            ScanDecryptPlan::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_scan_with_plan(
        &self,
        keys: impl Into<SecretSproutKeys>,
        key_fingerprint: String,
        checkpoint: PathBuf,
        network: ZeckNetwork,
        lightwalletd_url: String,
        confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
        peers: Vec<String>,
        decrypt_plan: ScanDecryptPlan,
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
                decrypt_plan,
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
        let scan = inner.scans.get(handle).ok_or(
            "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
        )?;
        Ok(ScanMaterial {
            keys: Arc::clone(&scan.keys),
            key_fingerprint: scan.key_fingerprint.clone(),
            checkpoint: scan.checkpoint.clone(),
            network: scan.network,
            lightwalletd_url: scan.lightwalletd_url.clone(),
            confirmation_sources: scan.confirmation_sources.clone(),
            peers: scan.peers.clone(),
            decrypt_plan: scan.decrypt_plan.clone(),
        })
    }

    pub fn register_catchup(&self, handle: &SproutScanHandle) -> Result<ScanCatchupLease, String> {
        let mut inner = StoreInner::lock(&self.0)?;
        let scan = inner.scans.get_mut(handle).ok_or(
            "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
        )?;
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
        let scan = inner.scans.get(handle).ok_or(
            "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
        )?;
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
                        None
                    } else {
                        Some(worker)
                    }
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
                if !matches!(scan.status, SproutScanStatus::Running) {
                    return;
                }
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

    /// Stop work and revoke derived spending authority while retaining the
    /// backend key source. Controls stay in the session until their futures
    /// drop, so cancellation of this command cannot detach a live worker.
    pub async fn pause_scan(&self, handle: &SproutScanHandle) -> Result<(), String> {
        let (worker, catchup, expiry) = {
            let mut inner = StoreInner::lock(&self.0)?;
            let scan_ttl = inner.scan_ttl;
            let scan = inner.scans.get_mut(handle).ok_or(
                "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
            )?;
            scan.status = SproutScanStatus::Failed;
            scan.report = None;
            scan.error = Some("Sprout scan paused; retry to resume with its retained keys".into());
            let expiry = if scan.finished_at.is_none() {
                scan.finished_at = Some(Instant::now());
                Some(scan_ttl)
            } else {
                None
            };
            let controls = (scan.worker.clone(), scan.catchup.clone(), expiry);
            inner.proposals.retain(|_, stored| {
                !matches!(&stored.intent.source, SproutIntentSource::Scan(source) if source == handle)
            });
            controls
        };
        if let Some(expiry) = expiry {
            self.schedule_expiry_sweep(expiry);
        }
        if let Some(worker) = &worker {
            worker.abort.abort();
        }
        if let Some(catchup) = &catchup {
            catchup.cancellation.cancel();
        }
        if let Some(worker) = worker {
            worker.completion.wait().await;
        }
        if let Some(catchup) = catchup {
            catchup.completion.wait().await;
        }
        Ok(())
    }

    /// Atomically consume a stopped session without allocating an additional
    /// capacity slot. The caller owns the checkpoint reservation first; all
    /// fallible validation happens before this replacement.
    pub fn replace_scan_for_retry(
        &self,
        handle: &SproutScanHandle,
        peers: Vec<String>,
    ) -> Result<SproutScanHandle, String> {
        let mut inner = StoreInner::lock(&self.0)?;
        let scan = inner.scans.get(handle).ok_or(
            "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
        )?;
        if matches!(scan.status, SproutScanStatus::Running)
            || scan.worker.as_ref().is_some_and(|worker| {
                !worker
                    .completion
                    .0
                    .finished
                    .load(std::sync::atomic::Ordering::Acquire)
            })
            || scan.catchup.is_some()
        {
            return Err("pause the Sprout scan before retrying".into());
        }
        let mut scan = inner
            .scans
            .remove(handle)
            .expect("session checked under lock");
        inner.proposals.retain(|_, stored| {
            !matches!(&stored.intent.source, SproutIntentSource::Scan(source) if source == handle)
        });
        scan.peers = peers;
        scan.status = SproutScanStatus::Running;
        scan.report = None;
        scan.error = None;
        scan.finished_at = None;
        scan.worker = None;
        scan.catchup = None;
        let replacement = SproutScanHandle(Uuid::new_v4().to_string());
        inner.scans.insert(replacement.clone(), scan);
        Ok(replacement)
    }

    pub async fn release_scan(&self, handle: &SproutScanHandle) -> Result<(), String> {
        let scan = {
            let mut inner = StoreInner::lock(&self.0)?;
            let scan = inner.scans.remove(handle).ok_or(
                "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
            )?;
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
            let scan = inner.scans.get(handle).ok_or(
                "unknown, expired or released Sprout scan; reopen the wallet or re-enter its keys",
            )?;
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
            allow_new_spends: false,
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

    /// Bind the server-derived permission to the exact one-shot proposal.
    /// Call only after querying availability for its retained network/endpoints.
    pub fn bind_spending_availability(
        &self,
        id: &SproutProposalId,
        status: &argos_core::nu7::SproutAvailability,
    ) -> Result<(), String> {
        let mut inner = StoreInner::lock(&self.0)?;
        let stored = inner
            .proposals
            .get_mut(id)
            .ok_or("unknown or already used Sprout proposal")?;
        stored.intent.spend_authorized_until = status
            .allows_new_spends()
            .then(|| Instant::now() + Duration::from_secs(60));
        Ok(())
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
                    spend_authorized_until: None,
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
    fn sprout_spending_permission_is_bound_to_review_and_can_only_be_narrowed() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(&store, SproutIntentSource::Scan(handle), "zs-reviewed");
        let unknown = argos_core::nu7::SproutAvailability::unknown(ZeckNetwork::Mainnet, "offline");
        store.bind_spending_availability(&id, &unknown).unwrap();
        let intent = store.take_proposal(&id).unwrap();
        assert!(!intent.allows_new_spends());
        // A later healthy status query cannot widen an already consumed review.
        let healthy = argos_core::nu7::SproutAvailability::at_tip(
            ZeckNetwork::Mainnet,
            argos_core::nu7::MAINNET_ACTIVATION_HEIGHT - 100,
        );
        assert!(store.bind_spending_availability(&id, &healthy).is_err());

        let handle = scan(&store, 2);
        let id = proposal(&store, SproutIntentSource::Scan(handle), "zs-reviewed");
        store.bind_spending_availability(&id, &healthy).unwrap();
        let mut intent = store.take_proposal(&id).unwrap();
        assert!(intent.allows_new_spends());
        intent.restrict_to_observation_only();
        assert!(!intent.allows_new_spends());
    }

    #[test]
    fn old_sprout_review_cannot_authorize_new_spending() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(&store, SproutIntentSource::Scan(handle), "zs-reviewed");
        let healthy = argos_core::nu7::SproutAvailability::at_tip(
            ZeckNetwork::Mainnet,
            argos_core::nu7::MAINNET_ACTIVATION_HEIGHT - 100,
        );
        store.bind_spending_availability(&id, &healthy).unwrap();
        let mut intent = store.take_proposal(&id).unwrap();
        intent.spend_authorized_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!intent.allows_new_spends());
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
                    spend_authorized_until: None,
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
                    spend_authorized_until: None,
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

    #[tokio::test]
    async fn pause_retains_keys_invalidates_proposals_and_does_not_renew_expiry() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 91);
        let id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        let keys = store.scan_material(&handle).unwrap().keys;
        let first_finished = StoreInner::lock(&store.0).unwrap().scans[&handle].finished_at;
        store.pause_scan(&handle).await.unwrap();
        store.pause_scan(&handle).await.unwrap();
        let retained = store.scan_material(&handle).unwrap();
        assert!(Arc::ptr_eq(&keys, &retained.keys));
        assert!(store.take_scan_proposal(&id).is_err());
        assert!(store.snapshot(&handle).unwrap().report.is_none());
        assert!(matches!(
            store.snapshot(&handle).unwrap().status,
            SproutScanStatus::Failed
        ));
        assert_eq!(
            StoreInner::lock(&store.0).unwrap().scans[&handle].finished_at,
            first_finished
        );
    }

    #[tokio::test]
    async fn retry_retains_same_keys_and_original_plan_after_wallet_review_expiry() {
        let registry = WalletReviewRegistry::default();
        let (dir, _path, review) = reviewed_wallet(&registry, b"reviewed wallet snapshot");
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 92);
        let proposal = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        {
            let mut inner = StoreInner::lock(&store.0).unwrap();
            let session = inner.scans.get_mut(&handle).unwrap();
            session.decrypt_plan = ScanDecryptPlan {
                decrypt_from: Some(123_456),
                decrypt_line: "immutable wallet birthday bound".into(),
            };
            session.confirmation_sources = vec![argos_core::ConfirmationEndpoint {
                operator_id: "original-operator".into(),
                endpoint: "https://original-source.invalid".into(),
            }];
        }
        let original = store.scan_material(&handle).unwrap();
        registry.lock().unwrap().ttl = Duration::ZERO;
        assert!(registry.verify(&review).is_err());
        store.pause_scan(&handle).await.unwrap();
        let replacement = store
            .replace_scan_for_retry(&handle, vec!["new-peer:8233".into()])
            .unwrap();
        let retried = store.scan_material(&replacement).unwrap();
        assert!(Arc::ptr_eq(&original.keys, &retried.keys));
        assert_eq!(retried.keys.as_slice(), &[[92; 32]]);
        assert_eq!(retried.network, original.network);
        assert_eq!(retried.checkpoint, original.checkpoint);
        assert_eq!(retried.key_fingerprint, original.key_fingerprint);
        assert_eq!(retried.lightwalletd_url, original.lightwalletd_url);
        assert_eq!(
            retried.confirmation_sources[0].operator_id,
            "original-operator"
        );
        assert_eq!(
            retried.confirmation_sources[0].endpoint,
            "https://original-source.invalid"
        );
        assert_eq!(retried.decrypt_plan.decrypt_from, Some(123_456));
        assert_eq!(
            retried.decrypt_plan.decrypt_line,
            "immutable wallet birthday bound"
        );
        assert_eq!(retried.peers, vec!["new-peer:8233"]);
        assert_ne!(replacement.0, handle.0);
        assert!(store.snapshot(&handle).is_err());
        assert!(store.take_scan_proposal(&proposal).is_err());
        store.finish_scan(&handle, Err("stale result".into()));
        assert!(matches!(
            store.snapshot(&replacement).unwrap().status,
            SproutScanStatus::Running
        ));
        assert!(
            store
                .replace_scan_for_retry(&replacement, Vec::new())
                .is_err(),
            "running session cannot rotate without stopping its worker"
        );
        store.release_scan(&replacement).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn pause_expiry_wipes_keys_without_access_and_repeated_pause_does_not_renew() {
        let scan_ttl = Duration::from_secs(60);
        let store = ReviewedIntentStore::with_retention(Duration::from_secs(900), scan_ttl);
        let handle = scan(&store, 93);
        let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_finished = {
            let mut inner = store.0.lock().unwrap();
            let scan = inner.scans.get_mut(&handle).unwrap();
            scan.keys = Arc::new(SecretSproutKeys::with_drop_probe(
                vec![[93; 32]],
                probe.clone(),
            ));
            scan.finished_at
        };
        store.pause_scan(&handle).await.unwrap();
        store.pause_scan(&handle).await.unwrap();
        {
            let mut inner = store.0.lock().unwrap();
            let scan = inner.scans.get_mut(&handle).unwrap();
            assert_eq!(
                scan.finished_at, first_finished,
                "pause must not renew retention"
            );
            // Simulate the retention timer firing without depending on a
            // narrow sleep window or triggering a sweep through a store API.
            scan.finished_at = Some(Instant::now() - 2 * scan_ttl);
        }
        store.schedule_expiry_sweep(Duration::ZERO);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !probe.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background expiry wipes the retained keys without store access");
        assert!(store.snapshot(&handle).is_err());
    }

    #[tokio::test]
    async fn pause_cancels_catchup_and_retains_only_the_session_key_owner() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 94);
        let material = store.scan_material(&handle).unwrap();
        let weak_keys = Arc::downgrade(&material.keys);
        let catchup = store.register_catchup(&handle).unwrap();
        let reservation = store.reserve_checkpoint(&material.checkpoint).unwrap();
        let task = tokio::spawn(async move {
            let _material = material;
            let _reservation = reservation;
            catchup.cancelled().await;
        });
        store.pause_scan(&handle).await.unwrap();
        task.await.unwrap();
        assert_eq!(
            weak_keys.strong_count(),
            1,
            "only retained backend source remains"
        );
        let retained = store.scan_material(&handle).unwrap();
        assert!(store.reserve_checkpoint(&retained.checkpoint).is_ok());
        assert!(store.register_catchup(&handle).is_err());
        drop(retained);
        store.release_scan(&handle).await.unwrap();
        assert!(weak_keys.upgrade().is_none());
    }

    #[tokio::test]
    async fn retry_reuses_capacity_and_release_zeroizes_the_final_retained_owner() {
        let store = ReviewedIntentStore::default();
        let handles = (0..MAX_SCAN_SESSIONS)
            .map(|marker| scan(&store, marker as u8))
            .collect::<Vec<_>>();
        let handle = &handles[0];
        let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let mut inner = StoreInner::lock(&store.0).unwrap();
            inner.scans.get_mut(handle).unwrap().keys = Arc::new(
                SecretSproutKeys::with_drop_probe(vec![[0; 32]], probe.clone()),
            );
        }
        store.pause_scan(handle).await.unwrap();
        let replacement = store
            .replace_scan_for_retry(handle, vec!["replacement:8233".into()])
            .unwrap();
        assert_eq!(
            StoreInner::lock(&store.0).unwrap().scans.len(),
            MAX_SCAN_SESSIONS
        );
        assert!(!probe.load(std::sync::atomic::Ordering::SeqCst));
        store.release_scan(&replacement).await.unwrap();
        assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            StoreInner::lock(&store.0).unwrap().scans.len(),
            MAX_SCAN_SESSIONS - 1
        );
    }

    #[tokio::test]
    async fn concurrent_pauses_both_wait_for_worker_completion() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 95);
        let completion = ScanWorkerCompletion::new();
        let guard = completion.guard();
        let task = tokio::spawn(std::future::pending::<()>());
        // An independent supervisor holds completion open until both pause
        // callers have registered. They must all wake when the guard drops.
        StoreInner::lock(&store.0)
            .unwrap()
            .scans
            .get_mut(&handle)
            .unwrap()
            .worker = Some(ScanWorker {
            abort: task.abort_handle(),
            completion,
        });
        let release_guard = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            drop(guard);
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            let (first, second) =
                tokio::join!(store.pause_scan(&handle), store.pause_scan(&handle));
            first.unwrap();
            second.unwrap();
        })
        .await
        .expect("every pause waiter wakes when the worker drops");
        release_guard.await.unwrap();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn terminal_scan_results_do_not_extend_retention() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 90);
        let first_finished = StoreInner::lock(&store.0).unwrap().scans[&handle].finished_at;
        store.finish_scan(&handle, Err("late aborted worker".into()));
        let inner = StoreInner::lock(&store.0).unwrap();
        let session = &inner.scans[&handle];
        assert_eq!(
            session.finished_at, first_finished,
            "late completion must not renew retention"
        );
        assert!(matches!(session.status, SproutScanStatus::Completed));
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
                    spend_authorized_until: None,
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
    fn wallet_review_release_revokes_only_the_requested_capability() {
        let registry = WalletReviewRegistry::default();
        let (dir, path, released) = reviewed_wallet(&registry, b"wallet");
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let retained = registry
            .register(path, Arc::new(snapshot.identity().clone()))
            .unwrap();
        let source = registry.resolve(&released).unwrap();
        let weak = Arc::downgrade(&source);
        drop(source);

        registry.release(&released).unwrap();

        assert!(registry.resolve(&released).is_err());
        assert!(
            weak.upgrade().is_none(),
            "released registry owner was dropped"
        );
        assert!(registry.verify(&retained).is_ok());
        registry.release(&released).unwrap();
        assert!(registry.verify(&retained).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wallet_review_release_accepts_expired_and_unissued_ids() {
        let registry = WalletReviewRegistry::with_ttl(Duration::ZERO);
        let (dir, _path, id) = reviewed_wallet(&registry, b"wallet");
        registry.release(&id).unwrap();
        registry
            .release(&WalletReviewId("unissued".to_owned()))
            .unwrap();
        assert!(registry.resolve(&id).is_err());
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
            .register(path.clone(), Arc::new(snapshot.identity().clone()))
            .is_err());
        registry.release(&roots[0].2).unwrap();
        assert!(
            registry
                .register(path, Arc::new(snapshot.identity().clone()))
                .is_ok(),
            "explicit release reclaims registry capacity"
        );
        for (dir, _, _) in roots {
            std::fs::remove_dir_all(dir).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
