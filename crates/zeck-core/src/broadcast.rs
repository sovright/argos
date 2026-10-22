use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    fs::OpenOptions,
    io::{Cursor, Seek, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction, SendResponse,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;

use crate::{
    error::{ZeckError, ZeckResult},
    models::{canonical_confirmation_operator_id, normalized_confirmation_authority},
    private_fs::{open_private_file, NamespaceLease, PrivateOpenMode, RetainedNamespaceChild},
    workspace::append_private_file,
};

pub use crate::models::TxLifecycleState;

pub const BROADCAST_LOG_SCHEMA_VERSION: u32 = 1;
pub const BROADCAST_LOG_FILE_NAME: &str = "broadcasts-v1.jsonl";
const LEGACY_IMPORT_MANIFEST_V1_FILE_NAME: &str = "legacy-imports-v1.json";
const LEGACY_IMPORT_MANIFEST_FILE_NAME: &str = "legacy-imports-v2.jsonl";

#[derive(Default, Serialize, Deserialize)]
struct LegacyImportManifest {
    /// Canonical source path to the exact bytes imported from that source.
    sources: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct LegacyImportRecord {
    source: String,
    digest: String,
}

/// The lock lives beside the workspace, so renaming or deleting that
/// workspace cannot unlink the lock inode while a submitter holds it.
fn broadcast_lock_path(path: &Path) -> ZeckResult<PathBuf> {
    let workspace = path.parent().ok_or_else(|| {
        ZeckError::Storage(format!("broadcast log {} has no workspace", path.display()))
    })?;
    let parent = workspace.parent().ok_or_else(|| {
        ZeckError::Storage(format!("workspace {} has no parent", workspace.display()))
    })?;
    let name = workspace
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ZeckError::Storage(format!(
                "workspace {} has no valid name",
                workspace.display()
            ))
        })?;
    let log_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ZeckError::Storage(format!(
                "broadcast log {} has no valid name",
                path.display()
            ))
        })?;
    Ok(parent.join(format!("{name}.{log_name}.lock.sqlite")))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxObservationState {
    /// An independent pair of operators agree on the block and height.
    Mined,
    /// Block evidence from one operator only, with no source disagreeing.
    MinedSingleSource,
    PresentUnmined,
    Absent,
    Reorged,
    Contested,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointTxEvidence {
    pub operator_id: String,
    pub endpoint: String,
    pub tip_height: Option<u32>,
    pub reported_height: Option<u32>,
    pub block_hash: Option<Vec<u8>>,
    pub tx_in_block: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxObservation {
    pub state: TxObservationState,
    pub mined_height: Option<u32>,
    pub expiry_height: Option<u32>,
    pub primary_tip: Option<u32>,
    pub secondary_tip: Option<u32>,
    pub evidence: Vec<EndpointTxEvidence>,
}

/// Blocks past a transaction's expiry height before one source's report of
/// absence (from chain and mempool) is enough to mark it Expired.
///
/// An expired transaction can never be mined. A server that lies about the
/// absence can therefore at worst lead the user to rebuild a transaction
/// that spends the same inputs, and consensus rejects whichever of the two
/// arrives second; the destination is fixed by the reviewed request, so no
/// value can be redirected. The margin absorbs ordinary tip skew and a short
/// reorg around the expiry height, which is why a single configured source
/// suffices.
pub const EXPIRY_MARGIN_BLOCKS: u32 = 20;

/// Confirmations a corroborated (independent-pair) Mined transaction needs
/// before Argos tells the user the source keys may be discarded.
pub const MIN_DISCARD_CONFIRMATIONS: u32 = 10;

fn independent_evidence_sources(a: &EndpointTxEvidence, b: &EndpointTxEvidence) -> bool {
    let a_operator = canonical_confirmation_operator_id(&a.operator_id, &a.endpoint);
    let b_operator = canonical_confirmation_operator_id(&b.operator_id, &b.endpoint);
    if a_operator.is_empty() || b_operator.is_empty() || a_operator == b_operator {
        return false;
    }
    let (Some(a_authority), Some(b_authority)) = (
        normalized_confirmation_authority(&a.endpoint),
        normalized_confirmation_authority(&b.endpoint),
    ) else {
        return false;
    };
    a_authority != b_authority
}

fn has_independent_pair(evidence: &[&EndpointTxEvidence]) -> bool {
    evidence.iter().enumerate().any(|(index, first)| {
        evidence
            .iter()
            .skip(index + 1)
            .any(|second| independent_evidence_sources(first, second))
    })
}

impl TxObservation {
    /// Corroborated mining: an independent pair agree, and the evidence
    /// re-derives the same state and height.
    pub fn has_canonical_mined_evidence(&self) -> bool {
        self.state == TxObservationState::Mined && self.rederives_own_state()
    }

    /// Mining reported by one operator only. Resolved for continuing a
    /// recovery, never for telling the user to discard the source keys.
    pub fn has_single_source_mined_evidence(&self) -> bool {
        self.state == TxObservationState::MinedSingleSource && self.rederives_own_state()
    }

    pub fn state_is_mined(&self) -> bool {
        matches!(
            self.state,
            TxObservationState::Mined | TxObservationState::MinedSingleSource
        )
    }

    fn rederives_own_state(&self) -> bool {
        let recomputed = observe_transaction(self.evidence.clone(), self.expiry_height);
        self.mined_height.is_some()
            && recomputed.state == self.state
            && recomputed.mined_height == self.mined_height
    }

    /// Confirmations of a mined transaction according to the least advanced
    /// source that reported its block.
    pub fn confirmations(&self) -> Option<u32> {
        let height = self.mined_height?;
        self.evidence
            .iter()
            .filter(|item| item.tx_in_block && item.reported_height == Some(height))
            .filter_map(|item| item.tip_height)
            .map(|tip| tip.saturating_sub(height).saturating_add(1))
            .min()
    }

    /// Corroborated, and deep enough that a reorg is no longer a practical
    /// concern. Only this permits a "safe to discard the source" message.
    pub fn is_safe_to_discard(&self) -> bool {
        self.has_canonical_mined_evidence()
            && self
                .confirmations()
                .is_some_and(|depth| depth >= MIN_DISCARD_CONFIRMATIONS)
    }

    /// Any configured source reporting the transaction absent from chain and
    /// mempool at a tip strictly above `expiry_height + EXPIRY_MARGIN_BLOCKS`,
    /// with no source reporting it present. See [`EXPIRY_MARGIN_BLOCKS`] for
    /// why one source suffices. An expiry height of zero means the
    /// transaction never expires.
    pub fn is_expired(&self) -> bool {
        if self.state != TxObservationState::Absent || self.mined_height.is_some() {
            return false;
        }
        let Some(expiry_height) = self.expiry_height.filter(|height| *height != 0) else {
            return false;
        };
        if self.evidence.iter().any(|item| {
            item.tx_in_block || item.reported_height.is_some() || item.block_hash.is_some()
        }) {
            return false;
        }
        let threshold = expiry_height.saturating_add(EXPIRY_MARGIN_BLOCKS);
        self.evidence.iter().any(|item| {
            normalized_confirmation_authority(&item.endpoint).is_some()
                && item.tip_height.is_some_and(|tip| tip > threshold)
        })
    }
}

/// Reduce independently labelled lightwalletd observations. A missing height
/// with a known tip means the transaction was absent; a missing tip means the
/// source could not give usable evidence. `u32::MAX` is reserved for the
/// lightwalletd `u64::MAX` orphaned-transaction sentinel.
pub fn observe_transaction(
    evidence: Vec<EndpointTxEvidence>,
    expiry_height: Option<u32>,
) -> TxObservation {
    let evidence = evidence
        .into_iter()
        .map(|mut item| {
            item.operator_id =
                canonical_confirmation_operator_id(&item.operator_id, &item.endpoint);
            item
        })
        .collect::<Vec<_>>();
    let primary_tip = evidence.first().and_then(|item| item.tip_height);
    let secondary_tip = evidence.get(1).and_then(|item| item.tip_height);
    let mut claims: Vec<&EndpointTxEvidence> = Vec::new();
    let mut reported_heights = HashSet::new();
    let mut absent_sources = Vec::new();
    let mut any_absent = false;
    let mut present_unmined = false;
    let mut reorged = false;
    let mut contested = false;
    let mut claimed_height = false;
    for item in &evidence {
        match item.reported_height {
            Some(u32::MAX) => reorged = true,
            Some(0) => present_unmined = true,
            Some(height) => {
                claimed_height = true;
                reported_heights.insert(height);
                if item
                    .block_hash
                    .as_deref()
                    .is_some_and(|hash| hash.len() == 32)
                {
                    if item.tx_in_block {
                        if normalized_confirmation_authority(&item.endpoint).is_some() {
                            claims.push(item);
                        }
                    } else {
                        contested = true;
                    }
                }
            }
            None if item.tip_height.is_some() => {
                any_absent = true;
                if normalized_confirmation_authority(&item.endpoint).is_some() {
                    absent_sources.push(item);
                }
            }
            None => {}
        }
    }
    if let Some(first) = claims.first() {
        if claims.iter().any(|other| {
            other.reported_height != first.reported_height || other.block_hash != first.block_hash
        }) || present_unmined
            || any_absent
        {
            contested = true;
        }
    }
    if reported_heights.len() > 1 {
        contested = true;
    }
    // One source's orphan sentinel against sources that still place the
    // transaction in a block is a disagreement, not a positive reorg.
    if reorged && !claims.is_empty() {
        contested = true;
    }
    let (state, mined_height) = if contested {
        (TxObservationState::Contested, None)
    } else if reorged {
        (TxObservationState::Reorged, None)
    } else if has_independent_pair(&claims) {
        (
            TxObservationState::Mined,
            claims.first().and_then(|item| item.reported_height),
        )
    } else if !claims.is_empty() {
        (
            TxObservationState::MinedSingleSource,
            claims.first().and_then(|item| item.reported_height),
        )
    } else if claimed_height {
        (TxObservationState::Unavailable, None)
    } else if present_unmined {
        (TxObservationState::PresentUnmined, None)
    } else if !absent_sources.is_empty() {
        (TxObservationState::Absent, None)
    } else {
        (TxObservationState::Unavailable, None)
    };
    TxObservation {
        state,
        mined_height,
        expiry_height,
        primary_tip,
        secondary_tip,
        evidence,
    }
}

#[async_trait]
pub trait TxObserver {
    async fn observe(
        &mut self,
        network: crate::models::ZeckNetwork,
        txid: TxId,
        expiry_height: Option<u32>,
    ) -> ZeckResult<TxObservation>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubmissionDisposition {
    Accepted,
    AmbiguousTransport,
    AlreadyKnown,
    RetryableRejection { code: i32, reason: String },
    DeterministicRejection { code: i32, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTransaction {
    pub txid: TxId,
    pub raw_tx: Vec<u8>,
    pub fee_zatoshis: u64,
    pub expiry_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedTransaction {
    pub prepared: PreparedTransaction,
    pub state: TxLifecycleState,
    pub last_submission: Option<SubmissionDisposition>,
    pub observation: Option<TxObservation>,
}

pub trait BroadcastStore {
    fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()>;
    fn transition(
        &mut self,
        txid: TxId,
        state: TxLifecycleState,
        submission: Option<&SubmissionDisposition>,
        observation: Option<&TxObservation>,
    ) -> ZeckResult<()>;
    fn latest(&self, txid: TxId) -> Option<PersistedTransaction>;
}

/// A single raw transaction submission. The caller owns the durable record.
#[async_trait]
pub trait TxSubmitter {
    async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status>;
}

pub struct LightwalletdSubmitter<'a> {
    pub client: &'a mut CompactTxStreamerClient<Channel>,
}

#[async_trait]
impl TxSubmitter for LightwalletdSubmitter<'_> {
    async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
        self.client
            .send_transaction(RawTransaction {
                data: raw,
                height: 0,
            })
            .await
            .map(tonic::Response::into_inner)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSubmissionResult {
    pub txid: TxId,
    pub state: TxLifecycleState,
    pub fee_zatoshis: u64,
    pub disposition: SubmissionDisposition,
    /// The pre-I/O Unknown was synced, but the post-I/O status could not be.
    pub persistence_warning: Option<String>,
}

impl TxSubmissionResult {
    /// A later sweep leg cannot advance until this exact transaction is reconciled.
    pub fn blocks_followup_submission(&self) -> bool {
        self.state == TxLifecycleState::SubmissionUnknown
            || (self.state == TxLifecycleState::Pending
                && matches!(
                    self.disposition,
                    SubmissionDisposition::RetryableRejection { .. }
                ))
    }
}

/// Recognize only stable, specific node reasons. Any unfamiliar response stays
/// ambiguous; response codes alone are not proof of consensus invalidity.
pub fn classify_send_response(response: &SendResponse) -> SubmissionDisposition {
    if response.error_code == 0 {
        return SubmissionDisposition::Accepted;
    }
    let reason = response.error_message.trim().to_owned();
    let normalized = reason.to_ascii_lowercase();
    if [
        "already in mempool",
        "already known",
        "already have transaction",
        "already in block chain",
        "already in blockchain",
        "txn-already-known",
        "txn-already-in-mempool",
        "txn-already-in-chain",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
    {
        return SubmissionDisposition::AlreadyKnown;
    }
    if [
        "mempool full",
        "mempool is full",
        "mempool min fee",
        "mempool minimum fee",
        "mempool minimum",
        "mempool fee",
        "min relay fee",
        "minrelaytxfee",
        "insufficient fee",
        "too many unconfirmed",
        "mempool eviction",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || (["non-final", "nonfinal"]
            .iter()
            .any(|needle| normalized.contains(needle))
            && !normalized.contains("expired"))
    {
        return SubmissionDisposition::RetryableRejection {
            code: response.error_code,
            reason,
        };
    }
    if [
        "invalid proof",
        "invalid signature",
        "bad signature",
        "wrong consensus branch",
        "wrong branch id",
        "confirmed conflicting spend",
        "malformed transaction",
        "deserialize transaction",
        "transaction decode failed",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
    {
        return SubmissionDisposition::DeterministicRejection {
            code: response.error_code,
            reason,
        };
    }
    SubmissionDisposition::AmbiguousTransport
}

pub(crate) fn txid_from_raw(raw_tx: &[u8]) -> ZeckResult<TxId> {
    let mut cursor = Cursor::new(raw_tx);
    // V5/V6 carry their branch in the header. For older transactions the
    // branch supplied here does not affect the serialized transaction ID.
    let parsed = Transaction::read(&mut cursor, BranchId::Nu5).map_err(|err| {
        ZeckError::TransactionBuild(format!("cannot parse persisted transaction: {err}"))
    })?;
    if cursor.position() != raw_tx.len() as u64 {
        return Err(ZeckError::TransactionBuild(
            "persisted transaction has trailing bytes".into(),
        ));
    }
    Ok(parsed.txid())
}

pub async fn submit_prepared_transaction<S, N>(
    store: &mut S,
    network: &mut N,
    tx: PreparedTransaction,
    deadline: Duration,
) -> ZeckResult<TxSubmissionResult>
where
    S: BroadcastStore,
    N: TxSubmitter,
{
    store.persist_prepared(&tx)?;
    resubmit_prepared_transaction(store, network, &tx, deadline).await
}

pub async fn resubmit_prepared_transaction<S, N>(
    store: &mut S,
    network: &mut N,
    tx: &PreparedTransaction,
    deadline: Duration,
) -> ZeckResult<TxSubmissionResult>
where
    S: BroadcastStore,
    N: TxSubmitter,
{
    let persisted = store.latest(tx.txid).ok_or_else(|| {
        ZeckError::Storage(format!("transaction {} is not durably prepared", tx.txid))
    })?;
    if persisted.prepared != *tx {
        return Err(ZeckError::Storage(format!(
            "prepared transaction {} differs from durable record",
            tx.txid
        )));
    }
    if !matches!(
        persisted.state,
        TxLifecycleState::NotSubmitted
            | TxLifecycleState::SubmissionUnknown
            | TxLifecycleState::Pending
    ) || persisted.observation.as_ref().is_some_and(|observation| {
        observation.expiry_height == persisted.prepared.expiry_height && observation.is_expired()
    }) {
        return Err(ZeckError::Broadcast(format!(
            "transaction {} is not eligible for resubmission",
            tx.txid
        )));
    }
    if txid_from_raw(&persisted.prepared.raw_tx)? != persisted.prepared.txid {
        return Err(ZeckError::Storage(format!(
            "persisted raw transaction does not match txid {}",
            tx.txid
        )));
    }
    // The transition is synced by BroadcastStore before any network I/O.
    store.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)?;
    let disposition = match tokio::time::timeout(
        deadline.min(Duration::from_secs(30)),
        network.send_raw(persisted.prepared.raw_tx.clone()),
    )
    .await
    {
        Ok(Ok(response)) => classify_send_response(&response),
        Ok(Err(_)) | Err(_) => SubmissionDisposition::AmbiguousTransport,
    };
    let state = match disposition {
        SubmissionDisposition::Accepted => TxLifecycleState::Pending,
        // A definite consensus rejection resolves the record: a new review may
        // start, and these bytes are never resent automatically. A primary
        // that forwards the bytes and then fabricates the rejection can at
        // worst cause a rebuilt transaction that conflicts on the same inputs
        // and is rejected by consensus; the destination is fixed.
        SubmissionDisposition::DeterministicRejection { .. }
            if rejection_can_be_definitive(&persisted) =>
        {
            TxLifecycleState::Rejected
        }
        SubmissionDisposition::DeterministicRejection { .. } => TxLifecycleState::SubmissionUnknown,
        SubmissionDisposition::AmbiguousTransport
        | SubmissionDisposition::AlreadyKnown
        | SubmissionDisposition::RetryableRejection { .. } => {
            // A lost reply or an inconclusive refusal stays blocking until an
            // observation resolves whether the transaction reached the network.
            TxLifecycleState::SubmissionUnknown
        }
    };
    let persistence_warning = store
        .transition(tx.txid, state, Some(&disposition), None)
        .err()
        .map(|err| format!("post-submission status could not be persisted ({err}); reconcile the durable pre-submission Unknown for {}", tx.txid));
    Ok(TxSubmissionResult {
        txid: tx.txid,
        state: if persistence_warning.is_some() {
            TxLifecycleState::SubmissionUnknown
        } else {
            state
        },
        fee_zatoshis: tx.fee_zatoshis,
        disposition,
        persistence_warning,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BroadcastLogEvent {
    Prepared {
        schema_version: u32,
        txid: [u8; 32],
        raw_tx: String,
        fee_zatoshis: u64,
        expiry_height: Option<u32>,
    },
    StateChanged {
        schema_version: u32,
        txid: [u8; 32],
        state: TxLifecycleState,
        submission: Option<SubmissionDisposition>,
        observation: Option<TxObservation>,
        /// Written by submitters that treat a deterministic node rejection as
        /// final. Older journal entries lack it and replay a Rejected record
        /// conservatively as SubmissionUnknown.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        definitive_rejection: bool,
    },
}

impl BroadcastLogEvent {
    fn txid(&self) -> TxId {
        match self {
            Self::Prepared { txid, .. } | Self::StateChanged { txid, .. } => {
                TxId::from_bytes(*txid)
            }
        }
    }
}

fn ordered_event_lines(bytes: &[u8]) -> ZeckResult<Vec<(TxId, Vec<u8>)>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err(ZeckError::Storage(
            "incomplete broadcast log during legacy import".to_owned(),
        ));
    }
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(|line| {
            let event: BroadcastLogEvent = serde_json::from_slice(line).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid broadcast event during legacy import: {err}"
                ))
            })?;
            Ok((event.txid(), line.to_vec()))
        })
        .collect()
}

fn event_lines_by_txid(bytes: &[u8]) -> ZeckResult<HashMap<TxId, Vec<Vec<u8>>>> {
    let mut grouped: HashMap<TxId, Vec<Vec<u8>>> = HashMap::new();
    for (txid, line) in ordered_event_lines(bytes)? {
        grouped.entry(txid).or_default().push(line);
    }
    Ok(grouped)
}

pub struct DurableBroadcastLog {
    path: PathBuf,
    latest: HashMap<TxId, PersistedTransaction>,
    write_failed: bool,
    // SQLite owns an OS file lock, released by Drop or process death. The
    // sidecar never stores transaction data and cannot leave a stale lock.
    _process_lock: Option<rusqlite::Connection>,
    // The network registry is opened through the NetworkOperationGuard's
    // retained namespace authority. Every registry and import-manifest read
    // or replacement is then relative to that exact directory handle.
    namespace: Option<NamespaceLease>,
    compatibility_lock: Option<RetainedNamespaceChild>,
    // A network registry keeps every legacy source locked until the caller's
    // entire scan, review, submission, reconciliation, or deletion ends.
    // Otherwise an older binary can append to a local journal just after its
    // one-time import (or after an absent-JSONL sidecar was overlooked).
    held_legacy_sources: Vec<DurableBroadcastLog>,
}

/// Keeps old workspace/standalone journal locks alive while a route reopens
/// the network registry for its individual submissions.
pub(crate) struct LegacyBroadcastGuards {
    _held: Vec<DurableBroadcastLog>,
}

impl DurableBroadcastLog {
    /// Any unresolved submission must be reconciled before a fresh review or
    /// execution can start. Mined (by any operator), Expired, and Rejected
    /// records are resolved.
    pub fn blocking_submission(&self) -> Option<TxId> {
        self.latest.iter().find_map(|(txid, persisted)| {
            (persisted.state == TxLifecycleState::SubmissionUnknown
                || persisted.state == TxLifecycleState::Pending)
                .then_some(*txid)
        })
    }

    /// Within one reviewed execution, later legs spend disjoint reviewed
    /// inputs, so an earlier leg that was accepted (Pending) does not stop
    /// them. Only an outcome that is not yet known -- a lost reply, or a
    /// retryable refusal -- blocks the next submission.
    pub fn blocking_next_leg(&self) -> Option<TxId> {
        self.latest.iter().find_map(|(txid, persisted)| {
            (persisted.state == TxLifecycleState::SubmissionUnknown
                || (persisted.state == TxLifecycleState::Pending
                    && matches!(
                        persisted.last_submission,
                        Some(SubmissionDisposition::RetryableRejection { .. })
                    )))
            .then_some(*txid)
        })
    }

    /// Prepared bytes that never reached a submission attempt (a crash
    /// between persisting and sending).
    pub fn has_not_submitted(&self) -> bool {
        self.latest
            .values()
            .any(|record| record.state == TxLifecycleState::NotSubmitted)
    }

    pub fn has_unresolved_history(&self) -> bool {
        self.blocking_submission().is_some()
            || self
                .latest
                .values()
                .any(|record| record.state == TxLifecycleState::NotSubmitted)
    }

    pub fn contains_mined_txid(&self, txid: &str) -> bool {
        self.mined_record_by_txid(txid).is_some()
    }

    pub fn mined_record_by_txid(&self, txid: &str) -> Option<PersistedTransaction> {
        self.latest
            .values()
            .find(|record| {
                record.state == TxLifecycleState::Mined
                    && record.prepared.txid.to_string() == txid
                    && record
                        .observation
                        .as_ref()
                        .is_some_and(TxObservation::has_canonical_mined_evidence)
            })
            .cloned()
    }

    pub fn mined_records(&self) -> Vec<PersistedTransaction> {
        self.records()
            .into_iter()
            .filter(|record| {
                record.state == TxLifecycleState::Mined
                    && record
                        .observation
                        .as_ref()
                        .is_some_and(TxObservation::has_canonical_mined_evidence)
            })
            .collect()
    }

    /// A deterministic snapshot for observing every historical transaction.
    pub fn records(&self) -> Vec<PersistedTransaction> {
        let mut records = self.latest.values().cloned().collect::<Vec<_>>();
        records.sort_by_key(|record| record.prepared.txid.to_string());
        records
    }

    pub fn open(path: impl AsRef<Path>) -> ZeckResult<Self> {
        let path = path.as_ref().to_path_buf();
        let lock_path = broadcast_lock_path(&path)?;
        drop(
            open_private_file(&lock_path, PrivateOpenMode::Append).map_err(|err| {
                ZeckError::Storage(format!(
                    "opening broadcast lock {}: {err}",
                    lock_path.display()
                ))
            })?,
        );
        let process_lock = rusqlite::Connection::open(&lock_path).map_err(|err| {
            ZeckError::Storage(format!(
                "opening broadcast lock {}: {err}",
                lock_path.display()
            ))
        })?;
        process_lock
            .busy_timeout(Duration::ZERO)
            .map_err(|err| ZeckError::Storage(format!("setting broadcast lock timeout: {err}")))?;
        process_lock
            .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
            .map_err(|err| {
                ZeckError::Storage(format!("broadcast log {} is in use: {err}", path.display()))
            })?;
        let mut log = Self {
            path,
            latest: HashMap::new(),
            write_failed: false,
            _process_lock: Some(process_lock),
            namespace: None,
            compatibility_lock: None,
            held_legacy_sources: Vec::new(),
        };
        log.replay_from_disk()?;
        Ok(log)
    }

    pub(crate) fn open_in_namespace(
        path: impl AsRef<Path>,
        namespace: &NamespaceLease,
        compatibility_lock_path: &Path,
    ) -> ZeckResult<Self> {
        let path = path.as_ref().to_path_buf();
        namespace.require_child(&path).map_err(|err| {
            ZeckError::Storage(format!(
                "broadcast registry {} is outside the retained namespace: {err}",
                path.display()
            ))
        })?;
        namespace.verify_current().map_err(|err| {
            ZeckError::Storage(format!(
                "broadcast registry namespace changed before open: {err}"
            ))
        })?;
        let mut log = Self {
            path,
            latest: HashMap::new(),
            write_failed: false,
            _process_lock: None,
            namespace: Some(namespace.try_clone_authority().map_err(|err| {
                ZeckError::Storage(format!("retaining broadcast registry namespace: {err}"))
            })?),
            compatibility_lock: Some(namespace.retain_child(compatibility_lock_path).map_err(
                |err| ZeckError::Storage(format!("retaining workspace compatibility lock: {err}")),
            )?),
            held_legacy_sources: Vec::new(),
        };
        log.replay_from_disk()?;
        log.verify_namespace()?;
        Ok(log)
    }

    fn verify_namespace(&self) -> ZeckResult<()> {
        if let Some(namespace) = &self.namespace {
            namespace.verify_current().map_err(|err| {
                ZeckError::Storage(format!("broadcast registry namespace was replaced: {err}"))
            })?;
            if let Some(lock) = &self.compatibility_lock {
                lock.verify_current().map_err(|err| {
                    ZeckError::Storage(format!(
                        "workspace compatibility lock was replaced while held: {err}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    fn read_path(&self, path: &Path) -> ZeckResult<Option<Vec<u8>>> {
        self.verify_namespace()?;
        let result = if let Some(namespace) = &self.namespace {
            namespace.read_child(path)
        } else {
            fs::read(path)
        };
        let value = match result {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => Err(ZeckError::Storage(format!(
                "reading {}: {err}",
                path.display()
            )))?,
        };
        self.verify_namespace()?;
        Ok(value)
    }

    fn append_line_to_path(&self, path: &Path, line: &[u8]) -> ZeckResult<()> {
        self.verify_namespace()?;
        if let Some(namespace) = &self.namespace {
            let current = match namespace.read_child_version(path) {
                Ok((bytes, object_id)) => Some((bytes, object_id)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(ZeckError::Storage(format!(
                        "reading {} before append: {err}",
                        path.display()
                    )))
                }
            };
            let expected = current
                .as_ref()
                .map(|(bytes, object_id)| (object_id, bytes.as_slice()));
            let mut suffix = line.to_vec();
            suffix.push(b'\n');
            namespace
                .append_child_if_unchanged(path, expected, &suffix)
                .map_err(|err| {
                    ZeckError::Storage(format!("appending {}: {err}", path.display()))
                })?;
            self.verify_namespace()
        } else {
            append_private_file(path, line)
        }
    }

    /// Lock a legacy source even when its JSONL does not exist yet. If bytes
    /// exist, import them while still holding that exact source lock. A
    /// missing manifest after a crash is safe to recover because each source
    /// transaction must be an exact event prefix of the network registry.
    pub(crate) fn hold_legacy_source(&mut self, source_path: &Path) -> ZeckResult<()> {
        self.hold_legacy_source_before_lock(source_path, || {})
    }

    fn hold_legacy_source_before_lock<F: FnOnce()>(
        &mut self,
        source_path: &Path,
        before_lock: F,
    ) -> ZeckResult<()> {
        if self.write_failed {
            return Err(ZeckError::Storage(format!(
                "broadcast log {} needs reopening after a failed write",
                self.path.display()
            )));
        }
        let source_path = source_path.to_path_buf();
        if source_path == self.path {
            return Err(ZeckError::Storage(
                "cannot import broadcast log into itself".to_owned(),
            ));
        }
        let source = if let Some(index) = self
            .held_legacy_sources
            .iter()
            .position(|source| source.path == source_path)
        {
            self.held_legacy_sources.swap_remove(index)
        } else {
            before_lock();
            Self::open(&source_path)?
        };
        // Inspect only after acquiring the exact source sidecar. An older
        // writer could create its first JSONL between a pre-lock absent stat
        // and this acquisition; that newly persisted Unknown must be imported.
        let present = match fs::symlink_metadata(&source_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
            Ok(_) => {
                return Err(ZeckError::Storage(format!(
                    "legacy broadcast log {} must be a regular file",
                    source_path.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                return Err(ZeckError::Storage(format!(
                    "inspecting legacy log {}: {err}",
                    source_path.display()
                )));
            }
        };
        let result = if present {
            self.import_locked_legacy_log(&source_path, &source)
        } else {
            Ok(())
        };
        self.held_legacy_sources.push(source);
        result
    }

    /// Copy an existing legacy journal into this locked network registry.
    /// Kept for in-crate callers and fixture tests; the source remains locked.
    pub(crate) fn import_legacy_log(&mut self, source_path: &Path) -> ZeckResult<()> {
        if !source_path.is_file() {
            return Err(ZeckError::Storage(format!(
                "legacy broadcast log {} is missing",
                source_path.display()
            )));
        }
        self.hold_legacy_source(source_path)
    }

    pub(crate) fn into_legacy_source_guards(mut self) -> LegacyBroadcastGuards {
        let held = std::mem::take(&mut self.held_legacy_sources);
        LegacyBroadcastGuards { _held: held }
    }

    fn import_locked_legacy_log(
        &mut self,
        source_path: &Path,
        source: &DurableBroadcastLog,
    ) -> ZeckResult<()> {
        let source_bytes = source.read_path(source_path)?.ok_or_else(|| {
            ZeckError::Storage(format!(
                "legacy broadcast log {} is missing",
                source_path.display()
            ))
        })?;
        let source_digest = format!("{:x}", Sha256::digest(&source_bytes));
        let registry_parent = self
            .path
            .parent()
            .ok_or_else(|| ZeckError::Storage("broadcast registry has no directory".to_owned()))?;
        let legacy_manifest_path = registry_parent.join(LEGACY_IMPORT_MANIFEST_V1_FILE_NAME);
        let manifest_path = registry_parent.join(LEGACY_IMPORT_MANIFEST_FILE_NAME);
        let legacy_manifest: LegacyImportManifest = match self.read_path(&legacy_manifest_path)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid legacy import manifest {}: {err}",
                    legacy_manifest_path.display()
                ))
            })?,
            None => LegacyImportManifest::default(),
        };
        let mut imported_sources = legacy_manifest.sources;
        if let Some(bytes) = self.read_path(&manifest_path)? {
            if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                return Err(ZeckError::Storage(format!(
                    "incomplete legacy import manifest {}",
                    manifest_path.display()
                )));
            }
            for line in bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let record: LegacyImportRecord = serde_json::from_slice(line).map_err(|err| {
                    ZeckError::Storage(format!(
                        "invalid legacy import record {}: {err}",
                        manifest_path.display()
                    ))
                })?;
                match imported_sources.get(&record.source) {
                    Some(previous) if previous != &record.digest => {
                        return Err(ZeckError::Storage(format!(
                            "conflicting legacy import records for {}",
                            record.source
                        )))
                    }
                    Some(_) => {}
                    None => {
                        imported_sources.insert(record.source, record.digest);
                    }
                }
            }
        }
        let source_key = source_path.to_string_lossy().into_owned();
        if let Some(previous_digest) = imported_sources.get(&source_key) {
            if previous_digest != &source_digest {
                return Err(ZeckError::Storage(format!(
                    "legacy broadcast log {} changed after import",
                    source_path.display()
                )));
            }
        }

        let registry_bytes = self.read_path(&self.path)?.unwrap_or_default();
        let source_events = event_lines_by_txid(&source_bytes)?;
        let registry_events = event_lines_by_txid(&registry_bytes)?;
        for (txid, source_lines) in &source_events {
            if let Some(registry_lines) = registry_events.get(txid) {
                if !registry_lines.starts_with(source_lines)
                    && !source_lines.starts_with(registry_lines)
                {
                    return Err(ZeckError::Storage(format!(
                        "conflicting legacy broadcast history for {txid} in {}",
                        source_path.display()
                    )));
                }
                if source.latest(*txid).is_none() || self.latest(*txid).is_none() {
                    return Err(ZeckError::Storage(format!(
                        "missing broadcast history for {txid} during legacy import"
                    )));
                }
            }
        }
        let mut seen_by_txid = HashMap::<TxId, usize>::new();
        let mut appended = false;
        for (txid, line) in ordered_event_lines(&source_bytes)? {
            let seen = seen_by_txid.entry(txid).or_default();
            let existing = registry_events.get(&txid).map_or(0, Vec::len);
            if *seen >= existing {
                if let Err(err) = self.append_line_to_path(&self.path, &line) {
                    self.write_failed = true;
                    return Err(err);
                }
                appended = true;
            }
            *seen += 1;
        }
        if appended {
            if let Err(err) = self.replay_from_disk() {
                self.write_failed = true;
                return Err(err);
            }
        }
        if !imported_sources.contains_key(&source_key) {
            let bytes = serde_json::to_vec(&LegacyImportRecord {
                source: source_key,
                digest: source_digest,
            })
            .map_err(|err| {
                ZeckError::Serialization(format!("serializing legacy import record: {err}"))
            })?;
            self.append_line_to_path(&manifest_path, &bytes)?;
        }
        self.verify_namespace()?;
        Ok(())
    }

    fn replay_from_disk(&mut self) -> ZeckResult<()> {
        self.latest.clear();
        let path = self.path.clone();
        let bytes = self.read_path(&path)?.unwrap_or_default();
        let bytes = self.repair_unterminated_tail(bytes)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let complete_bytes = &bytes[..bytes.len() - 1];
        for (index, line) in complete_bytes.split(|byte| *byte == b'\n').enumerate() {
            let value: serde_json::Value = serde_json::from_slice(line).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid broadcast log event {} in {}: {err}",
                    index + 1,
                    path.display()
                ))
            })?;
            let version = value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64);
            if version != Some(u64::from(BROADCAST_LOG_SCHEMA_VERSION)) {
                return Err(ZeckError::Storage(format!(
                    "unsupported broadcast log schema {:?} at event {} in {}",
                    version,
                    index + 1,
                    path.display()
                )));
            }
            let event: BroadcastLogEvent = serde_json::from_value(value).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid broadcast log event {} in {}: {err}",
                    index + 1,
                    path.display()
                ))
            })?;
            self.apply_event(event, true)?;
        }
        Ok(())
    }

    /// A crash can leave the final event without its newline. Events are
    /// appended as one buffer and acknowledged only after a sync, so:
    ///
    /// - a final fragment that does not parse as an event was never
    ///   acknowledged; standalone logs truncate it away so the earlier synced
    ///   state stands. Namespace-held logs refuse it until the namespace can
    ///   perform an exact replacement transition;
    /// - a final event that parses was fully written; its newline is added so
    ///   the next append starts on a clean line.
    ///
    /// Any unparseable line before the last still refuses the journal.
    /// Runs only under the exclusive journal lock held by `open`.
    fn repair_unterminated_tail(&mut self, mut bytes: Vec<u8>) -> ZeckResult<Vec<u8>> {
        if bytes.is_empty() || bytes.ends_with(b"\n") {
            return Ok(bytes);
        }
        let tail_start = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let complete = serde_json::from_slice::<BroadcastLogEvent>(&bytes[tail_start..]).is_ok();
        if let Some(namespace) = &self.namespace {
            if !complete {
                return Err(ZeckError::Storage(format!(
                    "incomplete broadcast log at {}: the retained private namespace cannot discard a torn final event without an exact replacement transition",
                    self.path.display()
                )));
            }
            let (current, object_id) = namespace.read_child_version(&self.path).map_err(|err| {
                ZeckError::Storage(format!(
                    "reading {} before tail repair: {err}",
                    self.path.display()
                ))
            })?;
            if current != bytes {
                return Err(ZeckError::Storage(format!(
                    "broadcast log {} changed before tail repair",
                    self.path.display()
                )));
            }
            namespace
                .append_child_if_unchanged(&self.path, Some((&object_id, &current)), b"\n")
                .map_err(|err| {
                    ZeckError::Storage(format!(
                        "terminating final event in {}: {err}",
                        self.path.display()
                    ))
                })?;
            self.verify_namespace()?;
            bytes.push(b'\n');
            return Ok(bytes);
        }
        let file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|err| {
                ZeckError::Storage(format!("opening {} for repair: {err}", self.path.display()))
            })?;
        let repaired = if complete {
            let mut file = file;
            file.seek(std::io::SeekFrom::End(0))
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all())
                .map_err(|err| {
                    ZeckError::Storage(format!(
                        "terminating final event in {}: {err}",
                        self.path.display()
                    ))
                })?;
            bytes.push(b'\n');
            bytes
        } else {
            file.set_len(tail_start as u64)
                .and_then(|_| file.sync_all())
                .map_err(|err| {
                    ZeckError::Storage(format!(
                        "dropping torn final event in {}: {err}",
                        self.path.display()
                    ))
                })?;
            bytes.truncate(tail_start);
            bytes
        };
        Ok(repaired)
    }

    fn append_event(&mut self, event: BroadcastLogEvent) -> ZeckResult<()> {
        self.verify_namespace()?;
        if self.write_failed {
            return Err(ZeckError::Storage(format!(
                "broadcast log {} needs reopening after a failed write",
                self.path.display()
            )));
        }
        self.validate_new_event(&event)?;
        let bytes = serde_json::to_vec(&event).map_err(|err| {
            ZeckError::Serialization(format!("serializing broadcast log event: {err}"))
        })?;
        let write_result = if let Some(namespace) = &self.namespace {
            let current = match namespace.read_child_version(&self.path) {
                Ok((bytes, object_id)) => Some((bytes, object_id)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(ZeckError::Storage(format!(
                        "reading {} before append: {err}",
                        self.path.display()
                    )))
                }
            };
            let mut suffix = bytes;
            suffix.push(b'\n');
            let expected = current
                .as_ref()
                .map(|(bytes, object_id)| (object_id, bytes.as_slice()));
            namespace
                .append_child_if_unchanged(&self.path, expected, &suffix)
                .map_err(|err| {
                    ZeckError::Storage(format!("appending {}: {err}", self.path.display()))
                })
        } else {
            append_private_file(&self.path, &bytes)
        };
        if let Err(err) = write_result {
            self.write_failed = true;
            return Err(err);
        }
        self.verify_namespace()?;
        let applied = self.apply_event(event, false);
        if applied.is_err() {
            self.write_failed = true;
        }
        applied
    }

    fn validate_new_event(&self, event: &BroadcastLogEvent) -> ZeckResult<()> {
        match event {
            BroadcastLogEvent::Prepared {
                txid,
                raw_tx,
                fee_zatoshis,
                expiry_height,
                ..
            } => {
                let txid = TxId::from_bytes(*txid);
                let prepared = PreparedTransaction {
                    txid,
                    raw_tx: STANDARD.decode(raw_tx).map_err(|err| {
                        ZeckError::Storage(format!("invalid base64 transaction for {txid}: {err}"))
                    })?,
                    fee_zatoshis: *fee_zatoshis,
                    expiry_height: *expiry_height,
                };
                if self
                    .latest
                    .get(&txid)
                    .is_some_and(|existing| existing.prepared != prepared)
                {
                    return Err(ZeckError::Storage(format!(
                        "conflicting prepared transaction for {txid}"
                    )));
                }
                Ok(())
            }
            BroadcastLogEvent::StateChanged {
                txid,
                state,
                submission,
                observation,
                ..
            } => {
                let txid = TxId::from_bytes(*txid);
                let existing = self.latest.get(&txid).ok_or_else(|| {
                    ZeckError::Storage(format!(
                        "state transition without prepared transaction for {txid}"
                    ))
                })?;
                validate_transition(
                    existing,
                    *state,
                    submission.as_ref(),
                    observation.as_ref(),
                    false,
                )
            }
        }
    }

    fn apply_event(&mut self, event: BroadcastLogEvent, legacy_replay: bool) -> ZeckResult<()> {
        match event {
            BroadcastLogEvent::Prepared {
                txid,
                raw_tx,
                fee_zatoshis,
                expiry_height,
                ..
            } => {
                let txid = TxId::from_bytes(txid);
                let raw_tx = STANDARD.decode(raw_tx).map_err(|err| {
                    ZeckError::Storage(format!("invalid base64 transaction for {txid}: {err}"))
                })?;
                let prepared = PreparedTransaction {
                    txid,
                    raw_tx,
                    fee_zatoshis,
                    expiry_height,
                };
                match self.latest.get(&txid) {
                    Some(existing) if existing.prepared != prepared => Err(ZeckError::Storage(
                        format!("conflicting prepared transaction for {txid}"),
                    )),
                    Some(_) => Ok(()),
                    None => {
                        self.latest.insert(
                            txid,
                            PersistedTransaction {
                                prepared,
                                state: TxLifecycleState::NotSubmitted,
                                last_submission: None,
                                observation: None,
                            },
                        );
                        Ok(())
                    }
                }
            }
            BroadcastLogEvent::StateChanged {
                txid,
                state,
                submission,
                observation,
                definitive_rejection,
                ..
            } => {
                let txid = TxId::from_bytes(txid);
                let existing = self.latest.get(&txid).ok_or_else(|| {
                    ZeckError::Storage(format!(
                        "state transition without prepared transaction for {txid}"
                    ))
                })?;
                validate_transition(
                    existing,
                    state,
                    submission.as_ref(),
                    observation.as_ref(),
                    legacy_replay,
                )?;
                let existing = self.latest.get_mut(&txid).expect("checked above");
                existing.state = if legacy_replay
                    && !definitive_rejection
                    && state == TxLifecycleState::Rejected
                    && matches!(
                        submission.as_ref(),
                        Some(SubmissionDisposition::DeterministicRejection { .. })
                    ) {
                    TxLifecycleState::SubmissionUnknown
                } else {
                    state
                };
                if let Some(submission) = submission {
                    existing.last_submission = Some(submission);
                }
                if let Some(observation) = observation {
                    existing.observation = Some(observation);
                }
                Ok(())
            }
        }
    }
}

/// A rejection is final only for bytes that no earlier reply or observation
/// ever placed on the network. Once a node accepted them, or a source saw
/// them, a later rejection (for example of a resend) proves nothing.
fn rejection_can_be_definitive(existing: &PersistedTransaction) -> bool {
    !matches!(
        existing.last_submission,
        Some(SubmissionDisposition::Accepted | SubmissionDisposition::AlreadyKnown)
    ) && !existing.observation.as_ref().is_some_and(|item| {
        matches!(
            item.state,
            TxObservationState::Mined
                | TxObservationState::MinedSingleSource
                | TxObservationState::PresentUnmined
        )
    })
}

pub(crate) fn validate_transition(
    existing: &PersistedTransaction,
    state: TxLifecycleState,
    submission: Option<&SubmissionDisposition>,
    observation: Option<&TxObservation>,
    legacy_replay: bool,
) -> ZeckResult<()> {
    let supported = match state {
        TxLifecycleState::NotSubmitted => {
            existing.state == TxLifecycleState::NotSubmitted
                && existing.last_submission.is_none()
                && existing.observation.is_none()
                && submission.is_none()
                && observation.is_none()
        }
        TxLifecycleState::SubmissionUnknown => {
            !matches!(
                existing.state,
                TxLifecycleState::Mined
                    | TxLifecycleState::MinedSingleSource
                    | TxLifecycleState::Rejected
                    | TxLifecycleState::Expired
            ) && observation.is_none()
                && matches!(
                    submission,
                    None | Some(SubmissionDisposition::AmbiguousTransport)
                        | Some(SubmissionDisposition::AlreadyKnown)
                        | Some(SubmissionDisposition::RetryableRejection { .. })
                        | Some(SubmissionDisposition::DeterministicRejection { .. })
                )
        }
        TxLifecycleState::Pending => {
            let effective_observation = observation.or(existing.observation.as_ref());
            let positive_presence = effective_observation.is_some_and(|item| {
                item.state == TxObservationState::PresentUnmined
                    && observe_transaction(item.evidence.clone(), item.expiry_height).state
                        == TxObservationState::PresentUnmined
                    && item.evidence.iter().any(|source| {
                        source.reported_height == Some(0)
                            && normalized_confirmation_authority(&source.endpoint).is_some()
                    })
            });
            let already_pending_nonfinal = existing.state == TxLifecycleState::Pending
                && matches!(
                    effective_observation.map(|item| &item.state),
                    None | Some(
                        TxObservationState::PresentUnmined
                            | TxObservationState::Absent
                            | TxObservationState::Reorged
                            | TxObservationState::Contested
                            | TxObservationState::Unavailable
                    )
                );
            // Only a positive observation demotes a mined record: a reorg
            // sentinel or absence from a source, or the transaction seen back
            // in a mempool. A timeout (Unavailable) or a disagreement
            // (Contested) leaves it mined.
            let mined_reorg = existing.state.is_mined()
                && (matches!(
                    observation.map(|item| &item.state),
                    Some(TxObservationState::Reorged | TxObservationState::Absent)
                ) || (positive_presence
                    && matches!(
                        observation.map(|item| &item.state),
                        Some(TxObservationState::PresentUnmined)
                    )));
            // An earlier acceptance cannot resolve a later Unknown recorded
            // before an exact-byte resend whose outcome has not arrived.
            let accepted = matches!(submission, Some(SubmissionDisposition::Accepted));
            let legacy_nonfinal = legacy_replay
                && matches!(
                    effective_observation.map(|item| &item.state),
                    Some(
                        TxObservationState::PresentUnmined
                            | TxObservationState::Absent
                            | TxObservationState::Reorged
                            | TxObservationState::Contested
                            | TxObservationState::Unavailable
                    )
                );
            // Schema-v1 submitters wrote a retryable response as Pending even
            // without transaction-presence evidence. Preserve replay of that
            // historical identity, but never authorize a new Pending append.
            let legacy_retryable = legacy_replay
                && matches!(
                    submission.or(existing.last_submission.as_ref()),
                    Some(SubmissionDisposition::RetryableRejection { .. })
                );
            (positive_presence
                || accepted
                || already_pending_nonfinal
                || mined_reorg
                || legacy_nonfinal
                || legacy_retryable)
                && !effective_observation.is_some_and(|item| {
                    item.expiry_height == existing.prepared.expiry_height && item.is_expired()
                })
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && !matches!(
                    effective_observation.map(|item| &item.state),
                    Some(TxObservationState::Mined | TxObservationState::MinedSingleSource)
                )
                && (!existing.state.is_mined() || mined_reorg)
                && !matches!(
                    existing.state,
                    TxLifecycleState::Rejected | TxLifecycleState::Expired
                )
        }
        TxLifecycleState::Mined => {
            observation
                .or(existing.observation.as_ref())
                .is_some_and(TxObservation::has_canonical_mined_evidence)
                && !matches!(
                    existing.state,
                    TxLifecycleState::Rejected | TxLifecycleState::Expired
                )
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
        }
        TxLifecycleState::MinedSingleSource => {
            observation
                .or(existing.observation.as_ref())
                .is_some_and(TxObservation::has_single_source_mined_evidence)
                && !matches!(
                    existing.state,
                    TxLifecycleState::Mined
                        | TxLifecycleState::Rejected
                        | TxLifecycleState::Expired
                )
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
        }
        TxLifecycleState::Rejected if !legacy_replay => {
            // Only the reply to the submission that just went out, and only
            // when nothing ever showed the bytes reaching the network.
            existing.state == TxLifecycleState::SubmissionUnknown
                && matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && observation.is_none()
                && rejection_can_be_definitive(existing)
        }
        TxLifecycleState::Rejected => {
            legacy_replay
                && matches!(
                    submission.or(existing.last_submission.as_ref()),
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && !matches!(
                    existing.state,
                    TxLifecycleState::Mined
                        | TxLifecycleState::MinedSingleSource
                        | TxLifecycleState::Expired
                )
                && !matches!(
                    observation
                        .or(existing.observation.as_ref())
                        .map(|item| &item.state),
                    Some(TxObservationState::Mined | TxObservationState::MinedSingleSource)
                )
        }
        TxLifecycleState::Expired => {
            let effective_observation = observation.or(existing.observation.as_ref());
            effective_observation.is_some_and(|item| {
                item.expiry_height == existing.prepared.expiry_height && item.is_expired()
            }) && existing.state != TxLifecycleState::Rejected
        }
    };
    if supported {
        Ok(())
    } else {
        Err(ZeckError::Storage(format!(
            "unsupported broadcast state {:?} for {} without matching durable evidence",
            state, existing.prepared.txid
        )))
    }
}

impl BroadcastStore for DurableBroadcastLog {
    fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()> {
        if self.write_failed {
            return Err(ZeckError::Storage(format!(
                "broadcast log {} needs reopening after a failed write",
                self.path.display()
            )));
        }
        if let Some(existing) = self.latest.get(&tx.txid) {
            if existing.prepared == *tx {
                let expected = existing.clone();
                if let Err(err) = self.replay_from_disk() {
                    self.write_failed = true;
                    return Err(err);
                }
                return if self.latest(tx.txid).as_ref() == Some(&expected) {
                    Ok(())
                } else {
                    self.write_failed = true;
                    Err(ZeckError::Storage(format!(
                        "prepared transaction {} is missing or changed in {}",
                        tx.txid,
                        self.path.display()
                    )))
                };
            }
            return Err(ZeckError::Storage(format!(
                "conflicting prepared transaction for {}",
                tx.txid
            )));
        }
        self.append_event(BroadcastLogEvent::Prepared {
            schema_version: BROADCAST_LOG_SCHEMA_VERSION,
            txid: tx.txid.into(),
            raw_tx: STANDARD.encode(&tx.raw_tx),
            fee_zatoshis: tx.fee_zatoshis,
            expiry_height: tx.expiry_height,
        })
    }

    fn transition(
        &mut self,
        txid: TxId,
        state: TxLifecycleState,
        submission: Option<&SubmissionDisposition>,
        observation: Option<&TxObservation>,
    ) -> ZeckResult<()> {
        let existing = self.latest.get(&txid).ok_or_else(|| {
            ZeckError::Storage(format!(
                "state transition without prepared transaction for {txid}"
            ))
        })?;
        validate_transition(existing, state, submission, observation, false)?;
        self.append_event(BroadcastLogEvent::StateChanged {
            schema_version: BROADCAST_LOG_SCHEMA_VERSION,
            txid: txid.into(),
            state,
            submission: submission.cloned(),
            observation: observation.cloned(),
            definitive_rejection: state == TxLifecycleState::Rejected,
        })
    }

    fn latest(&self, txid: TxId) -> Option<PersistedTransaction> {
        self.latest.get(&txid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use zcash_client_backend::proto::service::SendResponse;
    use zcash_primitives::transaction::Authorized;
    use zcash_primitives::transaction::TxId;
    use zcash_primitives::transaction::{TransactionData, TxVersion};
    use zcash_protocol::consensus::{BlockHeight, BranchId};

    #[test]
    fn retryable_disposition_blocks_followup_only_while_pending() {
        let txid = fixture().txid;
        let retryable = SubmissionDisposition::RetryableRejection {
            code: 1,
            reason: "mempool full".to_owned(),
        };
        let pending = TxSubmissionResult {
            txid,
            state: TxLifecycleState::Pending,
            fee_zatoshis: 10_000,
            disposition: retryable.clone(),
            persistence_warning: None,
        };
        assert!(pending.blocks_followup_submission());
        let rejected = TxSubmissionResult {
            state: TxLifecycleState::Rejected,
            disposition: retryable,
            ..pending
        };
        assert!(!rejected.blocks_followup_submission());
    }

    #[test]
    fn durable_log_identifies_submissions_that_block_new_sweep_legs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(log.blocking_submission(), None);
        log.persist_prepared(&tx).unwrap();
        log.transition(
            tx.txid,
            TxLifecycleState::SubmissionUnknown,
            Some(&SubmissionDisposition::AmbiguousTransport),
            None,
        )
        .unwrap();
        assert_eq!(log.blocking_submission(), Some(tx.txid));
        drop(log);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(reopened.blocking_submission(), Some(tx.txid));
    }

    #[test]
    fn accepted_pending_reopen_blocks_a_new_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            tx.txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        drop(log);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(reopened.blocking_submission(), Some(tx.txid));
        assert_eq!(reopened.latest(tx.txid).unwrap().prepared.raw_tx, tx.raw_tx);
    }

    #[test]
    fn no_presence_evidence_cannot_clear_unknown_submission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        for state in [
            TxObservationState::Absent,
            TxObservationState::Unavailable,
            TxObservationState::Contested,
        ] {
            let observation = TxObservation {
                state,
                mined_height: None,
                expiry_height: tx.expiry_height,
                primary_tip: Some(1),
                secondary_tip: Some(1),
                evidence: vec![],
            };
            assert!(log
                .transition(tx.txid, TxLifecycleState::Pending, None, Some(&observation))
                .is_err());
            assert_eq!(
                log.latest(tx.txid).unwrap().state,
                TxLifecycleState::SubmissionUnknown
            );
        }
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .blocking_submission(),
            Some(tx.txid)
        );
    }

    #[test]
    fn prior_acceptance_does_not_clear_a_later_unknown_submission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(
            tx.txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let absent = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: tx.expiry_height,
            primary_tip: Some(1),
            secondary_tip: Some(1),
            evidence: vec![],
        };
        assert!(log
            .transition(tx.txid, TxLifecycleState::Pending, None, Some(&absent))
            .is_err());
        assert_eq!(
            log.latest(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[test]
    fn legacy_unknown_to_absent_pending_log_reopens_and_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(log);
        let event = BroadcastLogEvent::StateChanged {
            schema_version: BROADCAST_LOG_SCHEMA_VERSION,
            txid: tx.txid.into(),
            state: TxLifecycleState::Pending,
            submission: None,
            definitive_rejection: false,
            observation: Some(TxObservation {
                state: TxObservationState::Absent,
                mined_height: None,
                expiry_height: tx.expiry_height,
                primary_tip: Some(1),
                secondary_tip: Some(1),
                evidence: vec![],
            }),
        };
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        drop(file);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(
            reopened.latest(tx.txid).unwrap().state,
            TxLifecycleState::Pending
        );
        assert_eq!(reopened.blocking_submission(), Some(tx.txid));
    }

    #[test]
    fn legacy_retryable_pending_reopens_but_new_retryable_pending_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let txid_bytes: [u8; 32] = tx.txid.into();
        // Schema-v1 production wrote this exact three-event chain after a
        // retryable send response. Write the JSONL directly: the new writer
        // must never create the final event, but reopen must preserve it.
        let legacy_events = [
            serde_json::json!({
                "kind": "prepared",
                "schema_version": 1,
                "txid": txid_bytes,
                "raw_tx": STANDARD.encode(&tx.raw_tx),
                "fee_zatoshis": tx.fee_zatoshis,
                "expiry_height": tx.expiry_height,
            }),
            serde_json::json!({
                "kind": "state_changed",
                "schema_version": 1,
                "txid": txid_bytes,
                "state": "submission_unknown",
                "submission": null,
                "observation": null,
            }),
            serde_json::json!({
                "kind": "state_changed",
                "schema_version": 1,
                "txid": txid_bytes,
                "state": "pending",
                "submission": {"kind": "retryable_rejection", "code": -26, "reason": "mempool full"},
                "observation": null,
            }),
        ];
        let bytes = legacy_events
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&path, bytes.as_bytes()).unwrap();
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        let saved = reopened.latest(tx.txid).unwrap();
        assert_eq!(saved.state, TxLifecycleState::Pending);
        assert_eq!(saved.prepared.raw_tx, tx.raw_tx);
        assert!(matches!(
            saved.last_submission,
            Some(SubmissionDisposition::RetryableRejection { .. })
        ));
        assert_eq!(reopened.blocking_submission(), Some(tx.txid));
        assert_eq!(fs::read(&path).unwrap(), bytes.as_bytes());

        let fresh_path = dir.path().join("fresh.jsonl");
        let mut fresh = DurableBroadcastLog::open(&fresh_path).unwrap();
        fresh.persist_prepared(&tx).unwrap();
        fresh
            .transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let before = fs::read(&fresh_path).unwrap();
        assert!(fresh
            .transition(
                tx.txid,
                TxLifecycleState::Pending,
                Some(&SubmissionDisposition::RetryableRejection {
                    code: -26,
                    reason: "mempool full".to_owned(),
                }),
                None,
            )
            .is_err());
        assert_eq!(fs::read(&fresh_path).unwrap(), before);
        drop(fresh);
        let fresh_reopened = DurableBroadcastLog::open(&fresh_path).unwrap();
        assert_eq!(
            fresh_reopened.latest(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
        assert_eq!(fresh_reopened.blocking_submission(), Some(tx.txid));
    }

    #[test]
    fn legacy_post_io_rejected_replays_as_unknown_and_new_rejected_is_final() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let txid_bytes: [u8; 32] = tx.txid.into();
        let legacy_events = [
            serde_json::json!({
                "kind": "prepared", "schema_version": 1, "txid": txid_bytes,
                "raw_tx": STANDARD.encode(&tx.raw_tx),
                "fee_zatoshis": tx.fee_zatoshis,
                "expiry_height": tx.expiry_height,
            }),
            serde_json::json!({
                "kind": "state_changed", "schema_version": 1, "txid": txid_bytes,
                "state": "submission_unknown", "submission": null, "observation": null,
            }),
            serde_json::json!({
                "kind": "state_changed", "schema_version": 1, "txid": txid_bytes,
                "state": "rejected",
                "submission": {"kind": "deterministic_rejection", "code": -26, "reason": "invalid proof"},
                "observation": null,
            }),
        ];
        let bytes = legacy_events
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&path, bytes.as_bytes()).unwrap();
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        let record = reopened.latest(tx.txid).unwrap();
        assert_eq!(record.state, TxLifecycleState::SubmissionUnknown);
        assert_eq!(record.prepared.raw_tx, tx.raw_tx);
        assert!(matches!(
            record.last_submission,
            Some(SubmissionDisposition::DeterministicRejection { .. })
        ));
        assert_eq!(reopened.blocking_submission(), Some(tx.txid));
        assert_eq!(fs::read(&path).unwrap(), bytes.as_bytes());

        let fresh_path = dir.path().join("fresh-rejection.jsonl");
        let mut fresh = DurableBroadcastLog::open(&fresh_path).unwrap();
        fresh.persist_prepared(&tx).unwrap();
        fresh
            .transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        fresh
            .transition(
                tx.txid,
                TxLifecycleState::Rejected,
                Some(&SubmissionDisposition::DeterministicRejection {
                    code: -26,
                    reason: "invalid proof".to_owned(),
                }),
                None,
            )
            .unwrap();
        assert_eq!(fresh.blocking_submission(), None);
        assert!(!fresh.has_unresolved_history());
        drop(fresh);
        // Written by the current submitter, so replay keeps it final rather
        // than demoting it like the legacy entry above.
        let fresh_reopened = DurableBroadcastLog::open(&fresh_path).unwrap();
        assert_eq!(
            fresh_reopened.latest(tx.txid).unwrap().state,
            TxLifecycleState::Rejected
        );
        assert!(!fresh_reopened.has_unresolved_history());
    }

    #[test]
    fn rejection_after_acceptance_is_not_final() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("accepted.jsonl")).unwrap();
        let tx = fixture();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            tx.txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        assert!(log
            .transition(
                tx.txid,
                TxLifecycleState::Rejected,
                Some(&SubmissionDisposition::DeterministicRejection {
                    code: -26,
                    reason: "invalid proof".to_owned(),
                }),
                None,
            )
            .is_err());
    }

    #[test]
    fn legacy_import_preserves_bytes_and_ignores_unchanged_source_after_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let old_root = dir.path().join("workspace-old");
        let registry_root = dir.path().join(".broadcast-registry");
        fs::create_dir_all(&old_root).unwrap();
        fs::create_dir_all(&registry_root).unwrap();
        let old_path = old_root.join(BROADCAST_LOG_FILE_NAME);
        let registry_path = registry_root.join(BROADCAST_LOG_FILE_NAME);
        let tx = fixture();
        let mut old = DurableBroadcastLog::open(&old_path).unwrap();
        old.persist_prepared(&tx).unwrap();
        old.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(old);
        let old_bytes = fs::read(&old_path).unwrap();

        let mut registry = DurableBroadcastLog::open(&registry_path).unwrap();
        registry.import_legacy_log(&old_path).unwrap();
        assert_eq!(fs::read(&registry_path).unwrap(), old_bytes);
        assert_eq!(registry.blocking_submission(), Some(tx.txid));
        assert_eq!(registry.latest(tx.txid).unwrap().prepared.raw_tx, tx.raw_tx);

        registry
            .transition(
                tx.txid,
                TxLifecycleState::Pending,
                Some(&SubmissionDisposition::Accepted),
                None,
            )
            .unwrap();
        let advanced = fs::read(&registry_path).unwrap();
        registry.import_legacy_log(&old_path).unwrap();
        assert_eq!(fs::read(&registry_path).unwrap(), advanced);
        assert_eq!(
            registry.latest(tx.txid).unwrap().state,
            TxLifecycleState::Pending
        );

        // A crash can land after the append-only registry merge but before
        // its manifest entry. The exact source prefix still proves import.
        let manifest = registry_root.join(LEGACY_IMPORT_MANIFEST_FILE_NAME);
        fs::remove_file(&manifest).unwrap();
        registry.import_legacy_log(&old_path).unwrap();
        assert_eq!(fs::read(&registry_path).unwrap(), advanced);
        assert!(manifest.exists());

        drop(registry);
        let mut old = DurableBroadcastLog::open(&old_path).unwrap();
        old.transition(
            tx.txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        drop(old);
        let mut registry = DurableBroadcastLog::open(&registry_path).unwrap();
        assert!(registry.import_legacy_log(&old_path).is_err());
        assert_eq!(fs::read(&registry_path).unwrap(), advanced);
    }

    #[test]
    fn legacy_import_resumes_an_append_only_partial_transaction_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let old_root = dir.path().join("workspace-old");
        let registry_root = dir.path().join(".broadcast-registry");
        fs::create_dir_all(&old_root).unwrap();
        fs::create_dir_all(&registry_root).unwrap();
        let old_path = old_root.join(BROADCAST_LOG_FILE_NAME);
        let registry_path = registry_root.join(BROADCAST_LOG_FILE_NAME);
        let tx = fixture();
        let mut old = DurableBroadcastLog::open(&old_path).unwrap();
        old.persist_prepared(&tx).unwrap();
        old.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(old);
        let source = fs::read(&old_path).unwrap();
        let first_line_end = source.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        crate::private_fs::write_private_file(&registry_path, &source[..first_line_end]).unwrap();

        let mut registry = DurableBroadcastLog::open(&registry_path).unwrap();
        registry.import_legacy_log(&old_path).unwrap();
        assert_eq!(fs::read(&registry_path).unwrap(), source);
        assert_eq!(
            registry.latest(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[test]
    fn imported_legacy_journal_lock_survives_until_registry_drop() {
        let dir = tempfile::tempdir().unwrap();
        let old_root = dir.path().join("workspace-old");
        let registry_root = dir.path().join(".broadcast-registry");
        fs::create_dir_all(&old_root).unwrap();
        fs::create_dir_all(&registry_root).unwrap();
        let old_path = old_root.join(BROADCAST_LOG_FILE_NAME);
        let registry_path = registry_root.join(BROADCAST_LOG_FILE_NAME);
        let tx = fixture();
        let mut old = DurableBroadcastLog::open(&old_path).unwrap();
        old.persist_prepared(&tx).unwrap();
        drop(old);

        let mut registry = DurableBroadcastLog::open(&registry_path).unwrap();
        registry.import_legacy_log(&old_path).unwrap();
        assert_eq!(registry.latest(tx.txid).unwrap().prepared.raw_tx, tx.raw_tx);
        let attempt = DurableBroadcastLog::open(&old_path)
            .err()
            .expect("older signer must not reopen its source while registry operates");
        assert!(attempt.to_string().contains("in use"), "{attempt}");
        let guards = registry.into_legacy_source_guards();
        let attempt = DurableBroadcastLog::open(&old_path)
            .err()
            .expect("per-leg registry reopening must not release the old source lock");
        assert!(attempt.to_string().contains("in use"), "{attempt}");
        drop(guards);
        DurableBroadcastLog::open(&old_path).unwrap();
    }

    #[test]
    fn jsonl_created_after_absent_hint_is_imported_under_source_lock() {
        let dir = tempfile::tempdir().unwrap();
        let old_root = dir.path().join("workspace-old");
        let registry_root = dir.path().join(".broadcast-registry");
        fs::create_dir_all(&old_root).unwrap();
        fs::create_dir_all(&registry_root).unwrap();
        let old_path = old_root.join(BROADCAST_LOG_FILE_NAME);
        let registry_path = registry_root.join(BROADCAST_LOG_FILE_NAME);
        let tx = fixture();
        assert!(!old_path.exists());

        let mut registry = DurableBroadcastLog::open(&registry_path).unwrap();
        registry
            .hold_legacy_source_before_lock(&old_path, || {
                // Deterministically occupy the gap where a pre-lock absence
                // check would have been stale in the older implementation.
                let mut old = DurableBroadcastLog::open(&old_path).unwrap();
                old.persist_prepared(&tx).unwrap();
                old.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
                    .unwrap();
            })
            .unwrap();
        assert_eq!(registry.blocking_submission(), Some(tx.txid));
        assert_eq!(registry.latest(tx.txid).unwrap().prepared.raw_tx, tx.raw_tx);
        assert!(DurableBroadcastLog::open(&old_path).is_err());
    }

    #[test]
    fn invalid_new_state_event_does_not_poison_durable_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let before = fs::read(&path).unwrap();
        let invalid = BroadcastLogEvent::StateChanged {
            schema_version: BROADCAST_LOG_SCHEMA_VERSION,
            txid: tx.txid.into(),
            state: TxLifecycleState::Pending,
            submission: None,
            definitive_rejection: false,
            observation: Some(TxObservation {
                state: TxObservationState::Unavailable,
                mined_height: None,
                expiry_height: tx.expiry_height,
                primary_tip: None,
                secondary_tip: None,
                evidence: vec![],
            }),
        };
        assert!(log.append_event(invalid).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .blocking_submission(),
            Some(tx.txid)
        );
    }

    #[test]
    fn positive_unmined_presence_can_reconcile_unknown_without_mining_claim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let forged = TxObservation {
            state: TxObservationState::PresentUnmined,
            mined_height: None,
            expiry_height: tx.expiry_height,
            primary_tip: Some(99),
            secondary_tip: None,
            evidence: vec![],
        };
        assert!(log
            .transition(tx.txid, TxLifecycleState::Pending, None, Some(&forged))
            .is_err());
        let witnessed = observe_transaction(
            vec![EndpointTxEvidence {
                operator_id: "one".to_owned(),
                endpoint: "https://one.example".to_owned(),
                tip_height: Some(99),
                reported_height: Some(0),
                block_hash: None,
                tx_in_block: false,
            }],
            tx.expiry_height,
        );
        assert_eq!(witnessed.state, TxObservationState::PresentUnmined);
        log.transition(tx.txid, TxLifecycleState::Pending, None, Some(&witnessed))
            .unwrap();
        drop(log);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(reopened.blocking_submission(), Some(tx.txid));
        assert_eq!(
            reopened.latest(tx.txid).unwrap().state,
            TxLifecycleState::Pending
        );
    }

    #[derive(Default, Clone)]
    struct RecordingStore(Arc<Mutex<Option<PersistedTransaction>>>);

    impl BroadcastStore for RecordingStore {
        fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()> {
            let mut latest = self.0.lock().unwrap();
            if latest.is_some() {
                return Err(ZeckError::Storage("already prepared".into()));
            }
            *latest = Some(PersistedTransaction {
                prepared: tx.clone(),
                state: TxLifecycleState::NotSubmitted,
                last_submission: None,
                observation: None,
            });
            Ok(())
        }
        fn transition(
            &mut self,
            txid: TxId,
            state: TxLifecycleState,
            submission: Option<&SubmissionDisposition>,
            observation: Option<&TxObservation>,
        ) -> ZeckResult<()> {
            let mut latest = self.0.lock().unwrap();
            let existing = latest
                .as_mut()
                .ok_or_else(|| ZeckError::Storage("not prepared".into()))?;
            if existing.prepared.txid != txid {
                return Err(ZeckError::Storage("wrong txid".into()));
            }
            existing.state = state;
            if let Some(submission) = submission {
                existing.last_submission = Some(submission.clone());
            }
            if let Some(observation) = observation {
                existing.observation = Some(observation.clone());
            }
            Ok(())
        }
        fn latest(&self, txid: TxId) -> Option<PersistedTransaction> {
            self.0
                .lock()
                .unwrap()
                .as_ref()
                .filter(|record| record.prepared.txid == txid)
                .cloned()
        }
    }

    enum Script {
        Response(i32, &'static str),
        Transport,
        Stall,
    }
    struct ScriptedSubmitter {
        store: RecordingStore,
        script: Script,
        calls: usize,
        sent: Vec<Vec<u8>>,
    }
    #[async_trait::async_trait]
    impl TxSubmitter for ScriptedSubmitter {
        async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
            assert_eq!(
                self.store.0.lock().unwrap().as_ref().unwrap().state,
                TxLifecycleState::SubmissionUnknown
            );
            self.calls += 1;
            self.sent.push(raw);
            match self.script {
                Script::Response(code, reason) => Ok(SendResponse {
                    error_code: code,
                    error_message: reason.into(),
                }),
                Script::Transport => Err(tonic::Status::unavailable("connection lost")),
                Script::Stall => std::future::pending().await,
            }
        }
    }
    fn fixture() -> PreparedTransaction {
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(100),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let mut raw_tx = Vec::new();
        tx.write(&mut raw_tx).unwrap();
        PreparedTransaction {
            txid: tx.txid(),
            raw_tx,
            fee_zatoshis: 12_345,
            expiry_height: Some(100),
        }
    }
    fn network(store: &RecordingStore, script: Script) -> ScriptedSubmitter {
        ScriptedSubmitter {
            store: store.clone(),
            script,
            calls: 0,
            sent: Vec::new(),
        }
    }

    #[tokio::test]
    async fn submission_state_is_unknown_before_network_io() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(&store, Script::Response(0, ""));
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx.clone(), Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::Pending);
        assert_eq!(node.sent, vec![tx.raw_tx]);
    }
    #[tokio::test]
    async fn transport_failure_preserves_txid_raw_bytes_and_unknown_state() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(&store, Script::Transport);
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx.clone(), Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(
            result.disposition,
            SubmissionDisposition::AmbiguousTransport
        );
        assert_eq!(store.latest(tx.txid).unwrap().prepared, tx);
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
    }
    #[tokio::test(start_paused = true)]
    async fn submission_timeout_is_unknown_not_rejected() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(&store, Script::Stall);
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
        assert_eq!(
            result.disposition,
            SubmissionDisposition::AmbiguousTransport
        );
    }

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_bounds_a_stalled_submission() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(&store, Script::Stall);
        let start = tokio::time::Instant::now();
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_millis(25))
                .await
                .unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(25));
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
        assert_eq!(
            result.disposition,
            SubmissionDisposition::AmbiguousTransport
        );
    }

    #[tokio::test]
    async fn mined_and_expired_transactions_are_not_resubmitted() {
        for state in [TxLifecycleState::Mined, TxLifecycleState::Expired] {
            let tx = fixture();
            let mut store = RecordingStore::default();
            store.persist_prepared(&tx).unwrap();
            store.transition(tx.txid, state, None, None).unwrap();
            let mut node = network(&store, Script::Response(0, ""));
            assert!(resubmit_prepared_transaction(
                &mut store,
                &mut node,
                &tx,
                Duration::from_secs(1),
            )
            .await
            .is_err());
            assert_eq!(node.calls, 0, "{state:?} must not reach network I/O");
        }
    }
    #[tokio::test]
    async fn deterministic_rejection_is_resolved_without_resend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let mut store = DurableBroadcastLog::open(&path).unwrap();
        let tx = fixture();
        struct RejectingSubmitter {
            sent: Vec<Vec<u8>>,
        }
        #[async_trait::async_trait]
        impl TxSubmitter for RejectingSubmitter {
            async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
                self.sent.push(raw);
                Ok(SendResponse {
                    error_code: -26,
                    error_message: "invalid proof".to_owned(),
                })
            }
        }
        let mut node = RejectingSubmitter { sent: vec![] };
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx.clone(), Duration::from_secs(30))
                .await
                .unwrap();
        // Exactly one send: no automatic resend after a definite rejection.
        assert_eq!(node.sent, vec![tx.raw_tx.clone()]);
        assert_eq!(result.state, TxLifecycleState::Rejected);
        assert!(matches!(
            result.disposition,
            SubmissionDisposition::DeterministicRejection { .. }
        ));
        assert!(!result.blocks_followup_submission());
        assert!(!result.state.fee_is_at_risk());
        assert_eq!(result.fee_zatoshis, tx.fee_zatoshis);
        // Resolved: a fresh review may start.
        assert_eq!(store.blocking_submission(), None);
        assert!(!store.has_unresolved_history());
        // And the stored bytes are never eligible for an explicit resend.
        assert!(
            resubmit_prepared_transaction(&mut store, &mut node, &tx, Duration::from_secs(1))
                .await
                .is_err()
        );
        assert_eq!(node.sent.len(), 1);
        drop(store);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        let saved = reopened.latest(tx.txid).unwrap();
        assert_eq!(saved.prepared.raw_tx, tx.raw_tx);
        assert_eq!(saved.state, TxLifecycleState::Rejected);
        assert!(!reopened.has_unresolved_history());
    }
    #[tokio::test]
    async fn duplicate_response_remains_unknown_until_observed() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(
            &store,
            Script::Response(-27, "transaction already in mempool"),
        );
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
        assert_eq!(result.disposition, SubmissionDisposition::AlreadyKnown);
    }
    #[tokio::test]
    async fn retryable_policy_rejection_remains_unknown_and_exact_byte_eligible() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(&store, Script::Response(-26, "mempool full"));
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
        assert_eq!(
            store.latest(result.txid).unwrap().prepared.raw_tx,
            fixture().raw_tx
        );
        assert!(matches!(
            result.disposition,
            SubmissionDisposition::RetryableRejection { .. }
        ));
    }
    #[tokio::test]
    async fn deterministic_rejection_cannot_be_resubmitted() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        store.persist_prepared(&tx).unwrap();
        store
            .transition(
                tx.txid,
                TxLifecycleState::Rejected,
                Some(&SubmissionDisposition::DeterministicRejection {
                    code: -26,
                    reason: "invalid proof".into(),
                }),
                None,
            )
            .unwrap();
        let mut node = network(&store, Script::Response(0, ""));
        assert!(
            resubmit_prepared_transaction(&mut store, &mut node, &tx, Duration::from_secs(30))
                .await
                .is_err()
        );
        assert_eq!(node.calls, 0);
    }
    #[tokio::test]
    async fn resubmit_uses_exact_persisted_bytes() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        store.persist_prepared(&tx).unwrap();
        let mut node = network(&store, Script::Response(0, ""));
        let result =
            resubmit_prepared_transaction(&mut store, &mut node, &tx, Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::Pending);
        assert_eq!(node.sent, vec![tx.raw_tx]);
    }
    #[tokio::test]
    async fn resubmit_refuses_raw_txid_mismatch() {
        let mut store = RecordingStore::default();
        let mut tx = fixture();
        tx.txid = TxId::from_bytes([42; 32]);
        store.persist_prepared(&tx).unwrap();
        let mut node = network(&store, Script::Response(0, ""));
        assert!(
            resubmit_prepared_transaction(&mut store, &mut node, &tx, Duration::from_secs(30))
                .await
                .is_err()
        );
        assert_eq!(node.calls, 0);
    }

    #[test]
    fn unknown_node_refusal_is_ambiguous() {
        let response = SendResponse {
            error_code: -26,
            error_message: "unfamiliar policy response".into(),
        };
        assert_eq!(
            classify_send_response(&response),
            SubmissionDisposition::AmbiguousTransport
        );
        let expired = SendResponse {
            error_code: -26,
            error_message: "non-final expired transaction".into(),
        };
        assert_eq!(
            classify_send_response(&expired),
            SubmissionDisposition::AmbiguousTransport
        );
        let spent = SendResponse {
            error_code: -26,
            error_message: "bad-txns-inputs-spent".into(),
        };
        assert_eq!(
            classify_send_response(&spent),
            SubmissionDisposition::AmbiguousTransport
        );
    }

    #[tokio::test]
    async fn failed_unknown_transition_prevents_network_io() {
        struct FailingStore(RecordingStore);
        impl BroadcastStore for FailingStore {
            fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()> {
                self.0.persist_prepared(tx)
            }
            fn transition(
                &mut self,
                _: TxId,
                _: TxLifecycleState,
                _: Option<&SubmissionDisposition>,
                _: Option<&TxObservation>,
            ) -> ZeckResult<()> {
                Err(ZeckError::Storage("sync failed".into()))
            }
            fn latest(&self, txid: TxId) -> Option<PersistedTransaction> {
                self.0.latest(txid)
            }
        }
        let tx = fixture();
        let recording = RecordingStore::default();
        let mut store = FailingStore(recording.clone());
        let mut node = network(&recording, Script::Response(0, ""));
        assert!(submit_prepared_transaction(
            &mut store,
            &mut node,
            tx.clone(),
            Duration::from_secs(30)
        )
        .await
        .is_err());
        assert_eq!(node.calls, 0);
        assert_eq!(
            recording.latest(tx.txid).unwrap().state,
            TxLifecycleState::NotSubmitted
        );
    }

    #[tokio::test]
    async fn failed_final_transition_returns_known_unknown_after_accepted_response() {
        struct FinalTransitionFails(RecordingStore);
        impl BroadcastStore for FinalTransitionFails {
            fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()> {
                self.0.persist_prepared(tx)
            }
            fn transition(
                &mut self,
                txid: TxId,
                state: TxLifecycleState,
                submission: Option<&SubmissionDisposition>,
                observation: Option<&TxObservation>,
            ) -> ZeckResult<()> {
                if submission.is_some() {
                    return Err(ZeckError::Storage("final sync failed".into()));
                }
                self.0.transition(txid, state, submission, observation)
            }
            fn latest(&self, txid: TxId) -> Option<PersistedTransaction> {
                self.0.latest(txid)
            }
        }
        let tx = fixture();
        let recording = RecordingStore::default();
        let mut store = FinalTransitionFails(recording.clone());
        let mut node = network(&recording, Script::Response(0, ""));
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx.clone(), Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(node.calls, 1);
        assert_eq!(result.txid, tx.txid);
        assert_eq!(result.fee_zatoshis, tx.fee_zatoshis);
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
        assert!(result.blocks_followup_submission());
        assert!(result
            .persistence_warning
            .as_deref()
            .unwrap()
            .contains("final sync failed"));
        assert_eq!(
            recording.latest(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[tokio::test]
    async fn failed_final_transition_returns_known_unknown_after_transport_failure() {
        struct FinalTransitionFails(RecordingStore);
        impl BroadcastStore for FinalTransitionFails {
            fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()> {
                self.0.persist_prepared(tx)
            }
            fn transition(
                &mut self,
                txid: TxId,
                state: TxLifecycleState,
                submission: Option<&SubmissionDisposition>,
                observation: Option<&TxObservation>,
            ) -> ZeckResult<()> {
                if submission.is_some() {
                    return Err(ZeckError::Storage("final sync failed".into()));
                }
                self.0.transition(txid, state, submission, observation)
            }
            fn latest(&self, txid: TxId) -> Option<PersistedTransaction> {
                self.0.latest(txid)
            }
        }
        let tx = fixture();
        let recording = RecordingStore::default();
        let mut store = FinalTransitionFails(recording.clone());
        let mut node = network(&recording, Script::Transport);
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx.clone(), Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(node.calls, 1);
        assert_eq!(result.txid, tx.txid);
        assert_eq!(result.fee_zatoshis, tx.fee_zatoshis);
        assert_eq!(result.state, TxLifecycleState::SubmissionUnknown);
        assert!(result.persistence_warning.is_some());
        assert_eq!(
            recording.latest(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[test]
    fn durable_log_excludes_second_opener_until_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let first = DurableBroadcastLog::open(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock_path = broadcast_lock_path(&path).unwrap();
            assert_eq!(
                fs::metadata(lock_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(DurableBroadcastLog::open(&path).is_err());
        drop(first);
        assert!(DurableBroadcastLog::open(&path).is_ok());
    }

    #[test]
    fn lock_survives_workspace_rename_and_recreation() {
        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let path = workspace.join(BROADCAST_LOG_FILE_NAME);
        let held = DurableBroadcastLog::open(&path).unwrap();
        let tombstone = parent.path().join("workspace-deleting");
        fs::rename(&workspace, &tombstone).unwrap();
        fs::create_dir(&workspace).unwrap();
        assert!(DurableBroadcastLog::open(&path).is_err());
        drop(held);
        assert!(DurableBroadcastLog::open(&path).is_ok());
    }

    struct ChildReaper(Option<std::process::Child>);

    impl ChildReaper {
        fn new(child: std::process::Child) -> Self {
            Self(Some(child))
        }

        fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
            self.0.as_mut().expect("child still owned").try_wait()
        }

        fn kill_and_wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            let child = self.0.as_mut().expect("child still owned");
            child.kill()?;
            let status = child.wait()?;
            self.0 = None;
            Ok(status)
        }
    }

    impl Drop for ChildReaper {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn process_lock_releases_after_forced_child_exit() {
        const CHILD_ENV: &str = "ARGOS_TEST_BROADCAST_LOCK_CHILD_PATH";
        const READY_ENV: &str = "ARGOS_TEST_BROADCAST_LOCK_READY_PATH";
        if let Some(path) = std::env::var_os(CHILD_ENV) {
            let _held = DurableBroadcastLog::open(path).unwrap();
            let ready = std::env::var_os(READY_ENV).expect("child ready path");
            std::fs::write(ready, b"locked").unwrap();
            std::thread::sleep(Duration::from_secs(60));
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let ready = dir.path().join("child-ready");
        let mut child = ChildReaper::new(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "broadcast::tests::process_lock_releases_after_forced_child_exit",
                    "--nocapture",
                ])
                .env(CHILD_ENV, &path)
                .env(READY_ENV, &ready)
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if std::time::Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                panic!("child never acquired lock");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            DurableBroadcastLog::open(&path).is_err(),
            "child must hold the lock"
        );
        child.kill_and_wait().unwrap();
        assert!(
            DurableBroadcastLog::open(&path).is_ok(),
            "OS must release lock on child death"
        );
    }

    #[test]
    fn lifecycle_states_serialize_to_the_public_contract() {
        assert_eq!(
            serde_json::to_string(&TxLifecycleState::SubmissionUnknown).unwrap(),
            "\"submission_unknown\""
        );
        assert_eq!(
            serde_json::to_string(&TxLifecycleState::NotSubmitted).unwrap(),
            "\"not_submitted\""
        );
    }

    #[test]
    fn lifecycle_states_display_the_public_status_token() {
        assert_eq!(TxLifecycleState::Mined.to_string(), "mined");
    }

    #[test]
    fn broadcast_log_round_trips_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([7; 32]);
        let prepared = PreparedTransaction {
            txid,
            raw_tx: vec![0, 1, 127, 128, 255],
            fee_zatoshis: 12_345,
            expiry_height: Some(2_200_000),
        };
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&prepared).unwrap();
        log.transition(
            txid,
            TxLifecycleState::SubmissionUnknown,
            Some(&SubmissionDisposition::AmbiguousTransport),
            None,
        )
        .unwrap();
        drop(log);

        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(
            reopened.latest(txid),
            Some(PersistedTransaction {
                prepared,
                state: TxLifecycleState::SubmissionUnknown,
                last_submission: Some(SubmissionDisposition::AmbiguousTransport),
                observation: None,
            })
        );
    }

    #[test]
    fn truncated_final_event_does_not_upgrade_the_last_synced_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([9; 32]);
        let prepared = PreparedTransaction {
            txid,
            raw_tx: vec![0, 42, 255],
            fee_zatoshis: 10_000,
            expiry_height: Some(500),
        };
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&prepared).unwrap();
        assert_eq!(
            log.latest(txid).unwrap().state,
            TxLifecycleState::NotSubmitted
        );
        drop(log);

        let synced = fs::read(&path).unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"kind":"state_changed""#)
            .unwrap();
        file.sync_all().unwrap();

        // A torn, unparseable final fragment was never acknowledged: it is
        // dropped instead of refusing the journal forever, and it cannot
        // upgrade the last synced state.
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(
            log.latest(txid).unwrap().state,
            TxLifecycleState::NotSubmitted
        );
        assert_eq!(fs::read(&path).unwrap(), synced);
        // Later appends land on a clean line boundary.
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .latest(txid)
                .unwrap()
                .state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[test]
    fn complete_final_event_without_newline_is_kept_and_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(log);
        let mut bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(&path, &bytes).unwrap();

        let mut log = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(
            log.latest(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
        log.transition(
            tx.txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .latest(tx.txid)
                .unwrap()
                .state,
            TxLifecycleState::Pending
        );
    }

    #[test]
    fn corrupt_middle_line_still_refuses_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = fixture();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        drop(log);
        let mut bytes = b"{not json}\n".to_vec();
        bytes.extend(fs::read(&path).unwrap());
        fs::write(&path, &bytes).unwrap();
        assert!(DurableBroadcastLog::open(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn rejects_unsupported_schema_without_changing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let bytes = br#"{"kind":"prepared","schema_version":2,"txid":[0],"raw_tx":"AA==","fee_zatoshis":1,"expiry_height":null}
"#;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            DurableBroadcastLog::open(&path),
            Err(crate::ZeckError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn rejects_transition_without_a_prepared_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        assert!(matches!(
            log.transition(
                TxId::from_bytes([1; 32]),
                TxLifecycleState::Pending,
                None,
                None
            ),
            Err(crate::ZeckError::Storage(_))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn rejects_conflicting_prepared_bytes_without_appending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([3; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        let prepared = PreparedTransaction {
            txid,
            raw_tx: vec![1, 2, 3],
            fee_zatoshis: 10_000,
            expiry_height: None,
        };
        log.persist_prepared(&prepared).unwrap();
        let before = fs::read(&path).unwrap();
        let mut conflicting = prepared.clone();
        conflicting.raw_tx.push(4);
        assert!(matches!(
            log.persist_prepared(&conflicting),
            Err(crate::ZeckError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(log.latest(txid).unwrap().prepared, prepared);
    }

    #[test]
    fn failed_append_poisoning_blocks_idempotent_prepare() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([4; 32]);
        let prepared = PreparedTransaction {
            txid,
            raw_tx: vec![42],
            fee_zatoshis: 10_000,
            expiry_height: None,
        };
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&prepared).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None),
            Err(crate::ZeckError::Storage(_))
        ));
        assert!(matches!(
            log.persist_prepared(&prepared),
            Err(crate::ZeckError::Storage(_))
        ));
    }

    #[test]
    fn certainty_bearing_states_require_matching_evidence_before_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([10; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![10],
            fee_zatoshis: 1,
            expiry_height: Some(100),
        })
        .unwrap();
        let before = fs::read(&path).unwrap();
        for state in [
            TxLifecycleState::Pending,
            TxLifecycleState::Mined,
            TxLifecycleState::Rejected,
            TxLifecycleState::Expired,
        ] {
            assert!(matches!(
                log.transition(txid, state, None, None),
                Err(crate::ZeckError::Storage(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), before);
            assert_eq!(
                log.latest(txid).unwrap().state,
                TxLifecycleState::NotSubmitted
            );
        }
        assert!(matches!(
            log.transition(
                txid,
                TxLifecycleState::SubmissionUnknown,
                Some(&SubmissionDisposition::Accepted),
                None
            ),
            Err(crate::ZeckError::Storage(_))
        ));
    }

    #[test]
    fn existing_evidence_supports_only_compatible_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([11; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![11],
            fee_zatoshis: 1,
            expiry_height: Some(100),
        })
        .unwrap();
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        log.transition(txid, TxLifecycleState::Pending, None, None)
            .unwrap();

        let mined = TxObservation {
            state: TxObservationState::Mined,
            mined_height: Some(90),
            expiry_height: Some(100),
            primary_tip: Some(90),
            secondary_tip: Some(90),
            evidence: vec![
                confirmation_evidence("one", Some(90), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(90), Some(&[1; 32]), true),
            ],
        };
        log.transition(txid, TxLifecycleState::Mined, None, Some(&mined))
            .unwrap();
        log.transition(txid, TxLifecycleState::Mined, None, None)
            .unwrap();
        assert_eq!(
            log.mined_record_by_txid(&txid.to_string())
                .unwrap()
                .prepared
                .txid,
            txid
        );
        assert_eq!(log.mined_records().len(), 1);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            log.transition(txid, TxLifecycleState::Pending, None, None),
            Err(crate::ZeckError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        let reorged = TxObservation {
            state: TxObservationState::Reorged,
            ..mined
        };
        log.transition(txid, TxLifecycleState::Pending, None, Some(&reorged))
            .unwrap();
        assert!(log.mined_record_by_txid(&txid.to_string()).is_none());
        assert!(log.mined_records().is_empty());
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .latest(txid)
                .unwrap()
                .state,
            TxLifecycleState::Pending
        );
    }

    #[test]
    fn expiry_needs_one_absent_source_beyond_the_expiry_margin() {
        let absent = |operator_id: &str, tip_height, tx_in_block| EndpointTxEvidence {
            operator_id: operator_id.to_owned(),
            endpoint: format!("https://{operator_id}.example"),
            tip_height: Some(tip_height),
            reported_height: None,
            block_hash: None,
            tx_in_block,
        };
        let margin_tip = 100 + EXPIRY_MARGIN_BLOCKS;
        let mut observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(100),
            primary_tip: Some(margin_tip),
            secondary_tip: None,
            evidence: vec![absent("one", margin_tip, false)],
        };
        // At the margin is not past it.
        assert!(!observation.is_expired());
        // One configured source past the margin suffices.
        observation.evidence[0].tip_height = Some(margin_tip + 1);
        assert!(observation.is_expired());
        // Unlabelled (custom primary) sources count as configured sources.
        observation.evidence[0].operator_id = String::new();
        assert!(observation.is_expired());
        // Any presence claim defeats expiry.
        observation.evidence[0].tx_in_block = true;
        assert!(!observation.is_expired());
        observation.evidence[0].tx_in_block = false;
        // An unusable endpoint is not a source.
        observation.evidence[0].endpoint.clear();
        assert!(!observation.is_expired());
    }

    #[test]
    fn zero_expiry_height_never_expires() {
        let observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(0),
            primary_tip: Some(u32::MAX),
            secondary_tip: Some(u32::MAX),
            evidence: ["one", "two"]
                .into_iter()
                .map(|id| EndpointTxEvidence {
                    operator_id: id.to_owned(),
                    endpoint: format!("https://{id}.example"),
                    tip_height: Some(u32::MAX),
                    reported_height: None,
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
        };
        assert_eq!(
            observe_transaction(observation.evidence.clone(), Some(0)).state,
            TxObservationState::Absent
        );
        assert!(!observation.is_expired());
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("never.jsonl")).unwrap();
        let txid = TxId::from_bytes([77; 32]);
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![77],
            fee_zatoshis: 10_000,
            expiry_height: Some(0),
        })
        .unwrap();
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        assert!(log
            .transition(txid, TxLifecycleState::Expired, None, Some(&observation))
            .is_err());
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &observation).unwrap(),
            TxLifecycleState::SubmissionUnknown
        );
        assert_eq!(log.blocking_submission(), Some(txid));
    }

    fn confirmation_evidence(
        operator_id: &str,
        reported_height: Option<u32>,
        block_hash: Option<&[u8]>,
        tx_in_block: bool,
    ) -> EndpointTxEvidence {
        EndpointTxEvidence {
            operator_id: operator_id.to_owned(),
            endpoint: format!("https://{operator_id}.example"),
            tip_height: Some(120),
            reported_height,
            block_hash: block_hash.map(<[u8]>::to_vec),
            tx_in_block,
        }
    }

    #[test]
    fn one_reported_height_is_single_source_not_canonical_mined() {
        let observation = observe_transaction(
            vec![confirmation_evidence(
                "one",
                Some(100),
                Some(&[1; 32]),
                true,
            )],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::MinedSingleSource);
        assert_eq!(observation.mined_height, Some(100));
        assert!(observation.has_single_source_mined_evidence());
        assert!(!observation.has_canonical_mined_evidence());
        assert!(!observation.is_safe_to_discard());
    }

    #[test]
    fn one_orphan_sentinel_against_an_agreeing_pair_is_contested() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("three", Some(u32::MAX), None, false),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Contested);
    }

    #[test]
    fn safe_to_discard_needs_corroboration_and_depth() {
        let at_tip = |operator: &str, tip: u32| {
            let mut item = confirmation_evidence(operator, Some(100), Some(&[1; 32]), true);
            item.tip_height = Some(tip);
            item
        };
        let shallow = observe_transaction(
            vec![
                // A block at height 100 seen from tip 100 has one confirmation.
                at_tip("one", 100 + MIN_DISCARD_CONFIRMATIONS - 2),
                at_tip("two", 140),
            ],
            Some(130),
        );
        assert!(shallow.has_canonical_mined_evidence());
        assert_eq!(shallow.confirmations(), Some(MIN_DISCARD_CONFIRMATIONS - 1));
        assert!(!shallow.is_safe_to_discard());
        let deep = observe_transaction(
            vec![
                at_tip("one", 100 + MIN_DISCARD_CONFIRMATIONS - 1),
                at_tip("two", 140),
            ],
            Some(130),
        );
        assert!(deep.is_safe_to_discard());
        let single = observe_transaction(vec![at_tip("one", 200)], Some(130));
        assert!(!single.is_safe_to_discard());
    }

    #[test]
    fn durable_log_rejects_a_mined_label_without_canonical_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([44; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![44],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        let forged = TxObservation {
            state: TxObservationState::Mined,
            mined_height: Some(100),
            expiry_height: Some(130),
            primary_tip: Some(120),
            secondary_tip: None,
            evidence: vec![confirmation_evidence(
                "one",
                Some(100),
                Some(&[1; 32]),
                true,
            )],
        };
        assert!(log
            .transition(txid, TxLifecycleState::Mined, None, Some(&forged))
            .is_err());
    }

    #[test]
    fn same_operator_sources_are_not_independent() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("zec.rocks", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("zec.rocks", Some(100), Some(&[1; 32]), true),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::MinedSingleSource);
    }

    #[test]
    fn operator_label_capitalization_cannot_finalize_mined_or_expired() {
        let evidence =
            |operator_id: &str, endpoint: &str, reported_height: Option<u32>, tx_in_block: bool| {
                EndpointTxEvidence {
                    operator_id: operator_id.to_owned(),
                    endpoint: endpoint.to_owned(),
                    tip_height: Some(140),
                    reported_height,
                    block_hash: tx_in_block.then(|| vec![3; 32]),
                    tx_in_block,
                }
            };
        let mined = observe_transaction(
            vec![
                evidence("OperatorA", "https://one.example", Some(120), true),
                evidence("operatora", "https://two.example", Some(120), true),
            ],
            Some(130),
        );
        assert_ne!(mined.state, TxObservationState::Mined);
        assert!(!mined.has_canonical_mined_evidence());
        let absent = observe_transaction(
            vec![
                evidence("OperatorA", "https://one.example", None, false),
                evidence("operatora", "https://two.example", None, false),
            ],
            Some(130),
        );
        assert!(!absent.is_expired());
    }

    #[test]
    fn matching_height_without_txid_in_block_is_contested() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[1; 32]), false),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Contested);
    }

    #[test]
    fn different_block_hashes_are_contested() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[2; 32]), true),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Contested);
    }

    #[test]
    fn secondary_absence_keeps_transaction_pending() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", None, None, false),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Contested);
        assert_eq!(observation.mined_height, None);
    }

    #[test]
    fn unlabeled_absence_prevents_mined_status() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("", None, None, false),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Contested);
    }

    #[test]
    fn matching_independent_evidence_returns_mined() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[1; 32]), true),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Mined);
        assert_eq!(observation.mined_height, Some(100));
    }

    #[test]
    fn review_trimmed_operator_ids_are_one_mining_source() {
        let mut second = confirmation_evidence(" one ", Some(100), Some(&[1; 32]), true);
        second.endpoint = "https://other.example".to_owned();
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                second,
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::MinedSingleSource);
    }

    #[test]
    fn review_trimmed_operator_ids_are_one_expiry_source() {
        let mut second = confirmation_evidence(" one ", None, None, false);
        second.endpoint = "https://other.example".to_owned();
        let evidence = vec![confirmation_evidence("one", None, None, false), second];
        // Both tips sit exactly at expiry + margin: absent, not yet expired.
        let observation = observe_transaction(evidence, Some(120 - EXPIRY_MARGIN_BLOCKS));
        assert_eq!(observation.state, TxObservationState::Absent);
        assert!(!observation.is_expired());
    }

    #[test]
    fn review_reported_height_disagreement_contests_even_without_block() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("three", Some(101), None, false),
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Contested);
        let mut unavailable = confirmation_evidence("three", None, None, false);
        unavailable.tip_height = None;
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                confirmation_evidence("two", Some(100), Some(&[1; 32]), true),
                unavailable,
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Mined);
    }

    #[test]
    fn review_short_block_hashes_cannot_confirm() {
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1, 2]), true),
                confirmation_evidence("two", Some(100), Some(&[1, 2]), true),
            ],
            Some(130),
        );
        assert_ne!(observation.state, TxObservationState::Mined);
    }

    #[test]
    fn review_missing_endpoint_cannot_finalize_mining_or_expiry() {
        let mut invalid_mined = confirmation_evidence("two", Some(100), Some(&[1; 32]), true);
        invalid_mined.endpoint.clear();
        let mined = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                invalid_mined,
            ],
            Some(130),
        );
        assert_ne!(mined.state, TxObservationState::Mined);
        let mut invalid_absent = confirmation_evidence("two", None, None, false);
        invalid_absent.endpoint.clear();
        let absent = observe_transaction(vec![invalid_absent], Some(10));
        assert_ne!(absent.state, TxObservationState::Absent);
        let forged = TxObservation {
            state: TxObservationState::Absent,
            ..absent
        };
        assert!(!forged.is_expired());
    }

    #[test]
    fn review_zero_port_endpoint_cannot_finalize_mining() {
        let mut invalid = confirmation_evidence("two", Some(100), Some(&[1; 32]), true);
        invalid.endpoint = "https://two.example:0".to_owned();
        let observation = observe_transaction(
            vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                invalid,
            ],
            Some(130),
        );
        assert_ne!(observation.state, TxObservationState::Mined);
    }

    #[test]
    fn review_durable_log_rejects_mined_same_authority_relabel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([45; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![45],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        let mut second = confirmation_evidence("two", Some(100), Some(&[1; 32]), true);
        second.endpoint = "https://ONE.example:443/".to_owned();
        let observation = TxObservation {
            state: TxObservationState::Mined,
            mined_height: Some(100),
            expiry_height: Some(130),
            primary_tip: Some(120),
            secondary_tip: Some(120),
            evidence: vec![
                confirmation_evidence("one", Some(100), Some(&[1; 32]), true),
                second,
            ],
        };
        assert!(log
            .transition(txid, TxLifecycleState::Mined, None, Some(&observation))
            .is_err());
    }

    #[test]
    fn review_durable_log_rejects_expired_same_authority_relabel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([46; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![46],
            fee_zatoshis: 10_000,
            expiry_height: Some(100),
        })
        .unwrap();
        let mut second = confirmation_evidence("two", None, None, false);
        second.endpoint = "https://ONE.example:443/".to_owned();
        let observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(100),
            primary_tip: Some(120),
            secondary_tip: Some(120),
            evidence: vec![confirmation_evidence("one", None, None, false), second],
        };
        assert!(log
            .transition(txid, TxLifecycleState::Expired, None, Some(&observation))
            .is_err());
    }

    #[test]
    fn review_durable_log_rejects_mined_builtin_operator_relabel() {
        let dir = tempfile::tempdir().unwrap();
        let txid = TxId::from_bytes([47; 32]);
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![47],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        let mut first = confirmation_evidence("one", Some(100), Some(&[1; 32]), true);
        first.endpoint = "https://zec.rocks:443".to_owned();
        let mut second = confirmation_evidence("two", Some(100), Some(&[1; 32]), true);
        second.endpoint = "https://na.zec.rocks:443".to_owned();
        let observation = TxObservation {
            state: TxObservationState::Mined,
            mined_height: Some(100),
            expiry_height: Some(130),
            primary_tip: Some(120),
            secondary_tip: Some(120),
            evidence: vec![first, second],
        };
        let reduced = observe_transaction(observation.evidence.clone(), observation.expiry_height);
        assert_ne!(reduced.state, TxObservationState::Mined);
        assert!(reduced
            .evidence
            .iter()
            .all(|item| item.operator_id == "zec.rocks"));
        assert!(log
            .transition(txid, TxLifecycleState::Mined, None, Some(&observation))
            .is_err());
    }

    #[test]
    fn review_durable_log_rejects_expired_builtin_operator_relabel_with_trailing_dots() {
        let dir = tempfile::tempdir().unwrap();
        let txid = TxId::from_bytes([48; 32]);
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![48],
            fee_zatoshis: 10_000,
            expiry_height: Some(100),
        })
        .unwrap();
        let mut first = confirmation_evidence("one", None, None, false);
        first.endpoint = "https://zec.rocks.:443".to_owned();
        let mut second = confirmation_evidence("two", None, None, false);
        second.endpoint = "https://na.zec.rocks.:443".to_owned();
        let observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(100),
            primary_tip: Some(120),
            secondary_tip: Some(120),
            evidence: vec![first, second],
        };
        // Tips at exactly expiry + margin are not past it.
        assert!(!observation.is_expired());
        let reduced = observe_transaction(observation.evidence.clone(), observation.expiry_height);
        assert_eq!(reduced.state, TxObservationState::Absent);
        assert!(reduced
            .evidence
            .iter()
            .all(|item| item.operator_id == "zec.rocks"));
        assert!(log
            .transition(txid, TxLifecycleState::Expired, None, Some(&observation))
            .is_err());
    }

    #[test]
    fn u64_max_is_reorged() {
        let observation = observe_transaction(
            vec![confirmation_evidence("one", Some(u32::MAX), None, false)],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Reorged);
    }

    #[tokio::test]
    async fn unexpired_absence_remains_pending_and_resubmittable() {
        let mut observation = observe_transaction(
            vec![
                confirmation_evidence("one", None, None, false),
                confirmation_evidence("two", None, None, false),
            ],
            Some(100),
        );
        for item in &mut observation.evidence {
            item.tip_height = Some(99);
        }
        assert_eq!(observation.state, TxObservationState::Absent);
        assert!(!observation.is_expired());
        let tx = fixture();
        let mut store = RecordingStore::default();
        store.persist_prepared(&tx).unwrap();
        store
            .transition(tx.txid, TxLifecycleState::Pending, None, Some(&observation))
            .unwrap();
        let mut submitter = ScriptedSubmitter {
            store: store.clone(),
            script: Script::Response(0, ""),
            calls: 0,
            sent: Vec::new(),
        };
        let result =
            resubmit_prepared_transaction(&mut store, &mut submitter, &tx, Duration::from_secs(1))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::Pending);
        assert_eq!(submitter.sent, vec![tx.raw_tx]);
    }

    #[test]
    fn expired_transition_requires_canonical_evidence_for_prepared_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([12; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![12],
            fee_zatoshis: 1,
            expiry_height: Some(100),
        })
        .unwrap();
        let evidence = ["one", "two"]
            .into_iter()
            .map(|id| EndpointTxEvidence {
                operator_id: id.to_owned(),
                endpoint: format!("https://{id}.example"),
                tip_height: Some(101 + EXPIRY_MARGIN_BLOCKS),
                reported_height: None,
                block_hash: None,
                tx_in_block: false,
            })
            .collect();
        let mut observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(99),
            primary_tip: Some(101 + EXPIRY_MARGIN_BLOCKS),
            secondary_tip: Some(101 + EXPIRY_MARGIN_BLOCKS),
            evidence,
        };
        assert!(matches!(
            log.transition(txid, TxLifecycleState::Expired, None, Some(&observation)),
            Err(crate::ZeckError::Storage(_))
        ));
        observation.expiry_height = Some(100);
        assert!(matches!(
            log.transition(txid, TxLifecycleState::Pending, None, Some(&observation)),
            Err(crate::ZeckError::Storage(_))
        ));
        log.transition(txid, TxLifecycleState::Expired, None, Some(&observation))
            .unwrap();
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .latest(txid)
                .unwrap()
                .state,
            TxLifecycleState::Expired
        );
    }

    #[test]
    fn replay_rejects_unjustified_mined_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([13; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![13],
            fee_zatoshis: 1,
            expiry_height: None,
        })
        .unwrap();
        drop(log);
        let event = serde_json::json!({
            "kind": "state_changed", "schema_version": 1, "txid": vec![13; 32],
            "state": "mined", "submission": null, "observation": null
        });
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "{event}").unwrap();
        file.sync_all().unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            DurableBroadcastLog::open(&path),
            Err(crate::ZeckError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn identical_prepare_rejects_deleted_durable_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = TxId::from_bytes([14; 32]);
        let prepared = PreparedTransaction {
            txid,
            raw_tx: vec![14],
            fee_zatoshis: 1,
            expiry_height: None,
        };
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&prepared).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            log.persist_prepared(&prepared),
            Err(crate::ZeckError::Storage(_))
        ));
        assert!(
            matches!(
                log.persist_prepared(&prepared),
                Err(crate::ZeckError::Storage(_))
            ),
            "a missing durable record poisons this open log"
        );
    }
}
