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
//! user approved) and re-opened the decrypt window on every click. Holding
//! the reviewed material instead binds execution to the review, at the cost
//! of keeping keys resident for a bounded time:
//!
//! - a proposal lives at most [`PROPOSAL_TTL`], is swept on every store
//!   access, and is dropped on execute (one-shot) or explicit release;
//! - a scan session lives until it is released (new scan, source change,
//!   Start over) or the app exits. A completed one must outlive the TTL: its
//!   sweep is often reviewed long after an hours-long scan finishes.
//! - at most [`MAX_SCAN_SESSIONS`] scans and [`MAX_PROPOSALS`] proposals.
//!
//! Held material is wiped on drop with `zeroize`: a scan session's keys sit
//! in `Zeroizing`, wiped when the last `Arc` (the session's, or a running
//! worker's) goes, and `SpendableSproutNote` zeroizes its `a_sk` and note
//! secrets in its own `Drop`, so an expired, released or executed proposal
//! leaves no key behind in freed memory. This is best effort, not a
//! guarantee: copies made earlier (decoding buffers, a `Vec` reallocation,
//! the wallet-import types, which are not all zeroizing) are not reached.

use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use argos_core::{sprout_recovery::SpendableSproutNote, sprout_sweep::SweepJournal, ZeckNetwork};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::SproutScanReport;

pub const MAX_SCAN_SESSIONS: usize = 16;
pub const MAX_PROPOSALS: usize = 32;
pub const MAX_IN_FLIGHT_CHECKPOINTS: usize = 16;
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
}

/// Where a proposal's notes came from. A wallet proposal carries no file
/// identity: its notes and their spending keys are held in the intent, so
/// execution never re-reads the file and there is nothing to compare.
#[derive(PartialEq, Eq)]
pub enum SproutIntentSource {
    Wallet,
    Scan(SproutScanHandle),
}

pub struct SproutSweepIntent {
    pub source: SproutIntentSource,
    pub notes: Vec<SpendableSproutNote>,
    pub destination: String,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub journal: Option<SweepJournal>,
    /// Set when the catch-up scan behind a scan-derived proposal could not
    /// confirm the chain tip; it leads the sweep report's warnings.
    pub tip_warning: Option<String>,
}

pub struct ScanMaterial {
    pub keys: Arc<Zeroizing<Vec<[u8; 32]>>>,
    pub key_fingerprint: String,
    pub checkpoint: PathBuf,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub peers: Vec<String>,
}

struct SproutScanSession {
    keys: Arc<Zeroizing<Vec<[u8; 32]>>>,
    key_fingerprint: String,
    checkpoint: PathBuf,
    network: ZeckNetwork,
    lightwalletd_url: String,
    peers: Vec<String>,
    status: SproutScanStatus,
    report: Option<SproutScanReport>,
    error: Option<String>,
    /// Stops the scan worker. Dropping its future also drops the checkpoint
    /// reservation it owns, so a released scan frees its checkpoint at once.
    /// The checkpoint is saved atomically every few hundred blocks, so an
    /// abort costs at most that much progress, and a later scan of the same
    /// keys resumes from it.
    worker: Option<tokio::task::AbortHandle>,
}

struct StoredProposal {
    intent: SproutSweepIntent,
    created: Instant,
}

struct StoreInner {
    scans: HashMap<SproutScanHandle, SproutScanSession>,
    proposals: HashMap<SproutProposalId, StoredProposal>,
    in_flight_checkpoints: HashSet<PathBuf>,
    proposal_ttl: Duration,
}

impl Default for StoreInner {
    fn default() -> Self {
        Self {
            scans: HashMap::new(),
            proposals: HashMap::new(),
            in_flight_checkpoints: HashSet::new(),
            proposal_ttl: PROPOSAL_TTL,
        }
    }
}

impl StoreInner {
    /// Drop every proposal past its TTL. Called on each store access, so an
    /// abandoned review's keys go with the next interaction.
    fn sweep_expired(&mut self) {
        let ttl = self.proposal_ttl;
        let now = Instant::now();
        self.proposals
            .retain(|_, stored| now.saturating_duration_since(stored.created) < ttl);
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
    inner: Arc<Mutex<StoreInner>>,
    identity: PathBuf,
}

impl Drop for CheckpointReservation {
    fn drop(&mut self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.in_flight_checkpoints.remove(&self.identity);
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
    #[cfg(test)]
    pub fn with_proposal_ttl(proposal_ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(StoreInner {
            proposal_ttl,
            ..StoreInner::default()
        })))
    }

    #[cfg(test)]
    pub fn proposal_count(&self) -> usize {
        StoreInner::lock(&self.0).map_or(0, |inner| inner.proposals.len())
    }

    pub fn reserve_checkpoint(&self, checkpoint: &Path) -> Result<CheckpointReservation, String> {
        let identity = checkpoint_identity(checkpoint)?;
        let mut inner = StoreInner::lock(&self.0)?;
        if inner.in_flight_checkpoints.contains(&identity) {
            return Err("a Sprout scan or catch-up is already using this checkpoint".into());
        }
        if inner.in_flight_checkpoints.len() >= MAX_IN_FLIGHT_CHECKPOINTS {
            return Err("too many Sprout scans or catch-ups are running".into());
        }
        inner.in_flight_checkpoints.insert(identity.clone());
        Ok(CheckpointReservation {
            inner: Arc::clone(&self.0),
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

    pub fn insert_scan(
        &self,
        keys: Vec<[u8; 32]>,
        key_fingerprint: String,
        checkpoint: PathBuf,
        network: ZeckNetwork,
        lightwalletd_url: String,
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
                keys: Arc::new(Zeroizing::new(keys)),
                key_fingerprint,
                checkpoint,
                network,
                lightwalletd_url,
                peers,
                status: SproutScanStatus::Running,
                report: None,
                error: None,
                worker: None,
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
            peers: scan.peers.clone(),
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
    pub fn attach_worker(&self, handle: &SproutScanHandle, worker: tokio::task::AbortHandle) {
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
            worker.abort();
        }
    }

    pub fn finish_scan(&self, handle: &SproutScanHandle, result: Result<SproutScanReport, String>) {
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
            }
        }
    }

    pub fn release_scan(&self, handle: &SproutScanHandle) -> Result<(), String> {
        let mut inner = StoreInner::lock(&self.0)?;
        let scan = inner
            .scans
            .remove(handle)
            .ok_or("unknown or released Sprout scan")?;
        inner.proposals.retain(|_, stored| {
            !matches!(&stored.intent.source, SproutIntentSource::Scan(source) if source == handle)
        });
        drop(inner);
        // Running or not, the session and its keys go now. A running worker
        // is aborted, which drops its checkpoint reservation with it, so the
        // same scan can be started again at once rather than after it ends.
        // Outside the lock, which that reservation's drop takes.
        if let Some(worker) = scan.worker {
            worker.abort();
        }
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
        Ok(ReviewedSproutSweep {
            proposal_id,
            plan,
            params_present,
            params_path,
            lands_in_sapling: argos_core::sprout_sweep::SPROUT_LANDS_IN_SAPLING.to_owned(),
            nu7_warning,
            warnings: Vec::new(),
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
            if !matches!(intent.intent.source, SproutIntentSource::Wallet) {
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

    fn scan(store: &ReviewedIntentStore, marker: u8) -> SproutScanHandle {
        store
            .insert_scan(
                vec![[marker; 32]],
                format!("fingerprint-{marker}"),
                PathBuf::from(format!("/tmp/scan-{marker}")),
                ZeckNetwork::Mainnet,
                format!("https://node-{marker}"),
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
            SproutIntentSource::Wallet => "https://node-a".to_owned(),
        };
        store
            .insert_proposal(
                SproutSweepIntent {
                    source,
                    notes: Vec::new(),
                    destination: destination.to_owned(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: endpoint,
                    journal: None,
                    tip_warning: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000,
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
        let id = proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
        assert!(store.take_proposal(&id).is_ok());
        assert!(store.take_proposal(&id).is_err());
    }

    #[test]
    fn wrong_execution_route_cannot_consume_a_proposal() {
        let store = ReviewedIntentStore::default();
        let id = proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
        assert!(store.take_scan_proposal(&id).is_err());
        assert!(store.take_wallet_proposal(&id).is_ok());
    }

    #[test]
    fn overlapping_wallet_reviews_remain_until_explicit_release() {
        let store = ReviewedIntentStore::default();
        // B finishes first; older A returns later. A must not evict the ID
        // already displayed for B, and B remains one-shot executable.
        let b = proposal(&store, SproutIntentSource::Wallet, "zs-B");
        let a = proposal(&store, SproutIntentSource::Wallet, "zs-A");
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
                    journal: None,
                    tip_warning: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000
                }
            )
            .is_err());
    }

    #[test]
    fn scan_a_result_cannot_be_swept_under_scan_b() {
        let store = ReviewedIntentStore::default();
        let a = scan(&store, 1);
        let b = scan(&store, 2);
        let id = proposal(&store, SproutIntentSource::Scan(a.clone()), "zs-reviewed");
        assert_ne!(
            store.scan_material(&a).unwrap().key_fingerprint,
            store.scan_material(&b).unwrap().key_fingerprint
        );
        store.release_scan(&a).unwrap();
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
                Vec::new()
            )
            .is_err());
        for _ in 0..MAX_PROPOSALS {
            proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
        }
        assert!(store
            .insert_proposal(
                SproutSweepIntent {
                    source: SproutIntentSource::Wallet,
                    notes: Vec::new(),
                    destination: "zs-reviewed".into(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: "https://node".into(),
                    journal: None,
                    tip_warning: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000
                }
            )
            .is_err());
    }

    /// Finding 10: a released scan is gone, running or not, so it never
    /// holds a slot that a new scan needs.
    #[test]
    fn released_running_scans_do_not_count_toward_the_limit() {
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
                )
                .unwrap();
            store.release_scan(&handle).unwrap();
            assert!(store.snapshot(&handle).is_err());
        }
        assert!(store
            .insert_scan(
                vec![[99; 32]],
                "replacement".into(),
                PathBuf::from("/tmp/replacement"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
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
            )
            .unwrap();
        let reservation = store.reserve_checkpoint(&checkpoint).unwrap();
        let worker = tokio::spawn(async move {
            let _reservation = reservation;
            std::future::pending::<()>().await;
        });
        store.attach_worker(&handle, worker.abort_handle());
        store.release_scan(&handle).unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("release stops the worker promptly");
        assert!(joined.is_err_and(|err| err.is_cancelled()));
        assert!(store.reserve_checkpoint(&checkpoint).is_ok());
        assert!(store.snapshot(&handle).is_err());
    }

    /// A scan session's keys are held in `Zeroizing`, and the session is
    /// their only owner once its worker is gone: releasing it leaves the
    /// last `Arc` here, and dropping that wipes the keys. Wiping is what
    /// `Zeroizing`'s `Drop` does; it is called directly so the zeros can be
    /// observed.
    #[test]
    fn released_scan_keys_are_held_in_a_wiping_wrapper() {
        use zeroize::Zeroize;
        let store = ReviewedIntentStore::default();
        let handle = store
            .insert_scan(
                vec![[0xab; 32], [0xcd; 32]],
                "fingerprint-z".into(),
                PathBuf::from("/tmp/scan-z"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
            )
            .unwrap();
        let material = store.scan_material(&handle).unwrap();
        store.release_scan(&handle).unwrap();
        let mut keys: Zeroizing<Vec<[u8; 32]>> =
            Arc::try_unwrap(material.keys).expect("the released session kept no copy");
        assert_eq!(keys.len(), 2);
        keys.zeroize();
        assert!(keys.is_empty(), "wiped and cleared");
    }

    /// A release that lands before the worker is attached still stops it.
    #[tokio::test]
    async fn a_worker_attached_after_release_is_aborted() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 4);
        // `scan` completes the session; make a running one instead.
        store.release_scan(&handle).unwrap();
        let handle = store
            .insert_scan(
                vec![[5; 32]],
                "fingerprint-5".into(),
                PathBuf::from("/tmp/scan-5"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
            )
            .unwrap();
        store.release_scan(&handle).unwrap();
        let worker = tokio::spawn(std::future::pending::<()>());
        store.attach_worker(&handle, worker.abort_handle());
        let joined = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("a late-attached worker is stopped");
        assert!(joined.is_err_and(|err| err.is_cancelled()));
    }

    /// Finding 5: a reviewed proposal holds raw Sprout spending keys in its
    /// notes, so it does not outlive its review window.
    #[test]
    fn sprout_proposals_expire() {
        let store = ReviewedIntentStore::with_proposal_ttl(std::time::Duration::ZERO);
        let id = proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
        assert_eq!(
            store.take_wallet_proposal(&id).err().unwrap(),
            "unknown or already used Sprout proposal"
        );
        assert_eq!(store.proposal_count(), 0, "expired proposals are dropped");

        let store = ReviewedIntentStore::default();
        let id = proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
        assert!(store.take_wallet_proposal(&id).is_ok());
        assert_eq!(PROPOSAL_TTL, std::time::Duration::from_secs(15 * 60));
    }

    /// Expired proposals free their slots for new reviews.
    #[test]
    fn expired_proposals_do_not_fill_the_store() {
        let store = ReviewedIntentStore::with_proposal_ttl(std::time::Duration::ZERO);
        for _ in 0..MAX_PROPOSALS + 1 {
            proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
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

    #[test]
    fn release_drops_scan_and_proposal_authority() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        store.release_scan(&handle).unwrap();
        assert!(store.snapshot(&handle).is_err());
        assert!(store.take_proposal(&id).is_err());
        let wallet = proposal(&store, SproutIntentSource::Wallet, "zs-reviewed");
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
}
