use std::{
    collections::{HashMap, HashSet},
    fs,
    fs::OpenOptions,
    io::Cursor,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction, SendResponse,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;

use crate::{
    error::{ZeckError, ZeckResult},
    models::{canonical_confirmation_operator_id, normalized_confirmation_authority},
    workspace::append_private_file,
};

pub use crate::models::TxLifecycleState;

pub const BROADCAST_LOG_SCHEMA_VERSION: u32 = 1;
pub const BROADCAST_LOG_FILE_NAME: &str = "broadcasts-v1.jsonl";

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
    Mined,
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
    pub fn has_canonical_mined_evidence(&self) -> bool {
        self.state == TxObservationState::Mined
            && self.mined_height.is_some()
            && observe_transaction(self.evidence.clone(), self.expiry_height).mined_height
                == self.mined_height
    }

    /// Expiry needs independent absence after the transaction's expiry height.
    pub fn is_expired(&self) -> bool {
        if self.state != TxObservationState::Absent || self.mined_height.is_some() {
            return false;
        }
        let Some(expiry_height) = self.expiry_height else {
            return false;
        };
        if self.evidence.iter().any(|item| {
            item.tx_in_block || item.reported_height.is_some() || item.block_hash.is_some()
        }) {
            return false;
        }
        let absent_after_expiry = self
            .evidence
            .iter()
            .filter(|item| {
                !item.operator_id.trim().is_empty()
                    && item.tip_height.is_some_and(|tip| tip > expiry_height)
            })
            .collect::<Vec<_>>();
        has_independent_pair(&absent_after_expiry)
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
    let (state, mined_height) = if contested {
        (TxObservationState::Contested, None)
    } else if reorged {
        (TxObservationState::Reorged, None)
    } else if has_independent_pair(&claims) {
        (
            TxObservationState::Mined,
            claims.first().and_then(|item| item.reported_height),
        )
    } else if claimed_height {
        (TxObservationState::Unavailable, None)
    } else if present_unmined {
        (TxObservationState::PresentUnmined, None)
    } else if has_independent_pair(&absent_sources) {
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

fn txid_from_raw(raw_tx: &[u8]) -> ZeckResult<TxId> {
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
    }) || matches!(
        persisted.last_submission,
        Some(SubmissionDisposition::DeterministicRejection { .. })
    ) {
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
        network.send_raw(persisted.prepared.raw_tx),
    )
    .await
    {
        Ok(Ok(response)) => classify_send_response(&response),
        Ok(Err(_)) | Err(_) => SubmissionDisposition::AmbiguousTransport,
    };
    let state = match disposition {
        SubmissionDisposition::Accepted => TxLifecycleState::Pending,
        SubmissionDisposition::DeterministicRejection { .. } => TxLifecycleState::Rejected,
        SubmissionDisposition::AmbiguousTransport
        | SubmissionDisposition::AlreadyKnown
        | SubmissionDisposition::RetryableRejection { .. } => TxLifecycleState::SubmissionUnknown,
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
    },
}

pub struct DurableBroadcastLog {
    path: PathBuf,
    latest: HashMap<TxId, PersistedTransaction>,
    write_failed: bool,
    // SQLite owns an OS file lock, released by Drop or process death. The
    // sidecar never stores transaction data and cannot leave a stale lock.
    _process_lock: rusqlite::Connection,
}

impl DurableBroadcastLog {
    /// Any unresolved submission must be reconciled before a fresh sweep can
    /// construct or submit another transaction.
    pub fn blocking_submission(&self) -> Option<TxId> {
        self.latest.iter().find_map(|(txid, persisted)| {
            (persisted.state == TxLifecycleState::SubmissionUnknown
                || persisted.state == TxLifecycleState::Pending)
                .then_some(*txid)
        })
    }

    pub fn has_unresolved_history(&self) -> bool {
        self.blocking_submission().is_some()
            || self
                .latest
                .values()
                .any(|record| record.state == TxLifecycleState::NotSubmitted)
    }

    pub fn contains_mined_txid(&self, txid: &str) -> bool {
        self.latest.values().any(|record| {
            record.state == TxLifecycleState::Mined
                && record.prepared.txid.to_string() == txid
                && record
                    .observation
                    .as_ref()
                    .is_some_and(TxObservation::has_canonical_mined_evidence)
        })
    }

    pub fn open(path: impl AsRef<Path>) -> ZeckResult<Self> {
        let path = path.as_ref().to_path_buf();
        let lock_path = broadcast_lock_path(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            options.open(&lock_path).map_err(|err| {
                ZeckError::Storage(format!(
                    "opening broadcast lock {}: {err}",
                    lock_path.display()
                ))
            })?;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
                ZeckError::Storage(format!(
                    "securing broadcast lock {}: {err}",
                    lock_path.display()
                ))
            })?;
        }
        #[cfg(not(unix))]
        options.open(&lock_path).map_err(|err| {
            ZeckError::Storage(format!(
                "opening broadcast lock {}: {err}",
                lock_path.display()
            ))
        })?;
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
            _process_lock: process_lock,
        };
        log.replay_from_disk()?;
        Ok(log)
    }

    fn replay_from_disk(&mut self) -> ZeckResult<()> {
        self.latest.clear();
        let path = self.path.clone();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => {
                return Err(ZeckError::Storage(format!(
                    "reading {}: {err}",
                    path.display()
                )))
            }
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(ZeckError::Storage(format!(
                "incomplete broadcast log at {}: final event has no newline",
                path.display()
            )));
        }
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

    fn append_event(&mut self, event: BroadcastLogEvent) -> ZeckResult<()> {
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
        if let Err(err) = append_private_file(&self.path, &bytes) {
            self.write_failed = true;
            return Err(err);
        }
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
                existing.state = state;
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

fn validate_transition(
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
                TxLifecycleState::Mined | TxLifecycleState::Rejected | TxLifecycleState::Expired
            ) && observation.is_none()
                && matches!(
                    submission,
                    None | Some(SubmissionDisposition::AmbiguousTransport)
                        | Some(SubmissionDisposition::AlreadyKnown)
                        | Some(SubmissionDisposition::RetryableRejection { .. })
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
            let mined_reorg = existing.state == TxLifecycleState::Mined
                && matches!(
                    observation.map(|item| &item.state),
                    Some(
                        TxObservationState::Reorged
                            | TxObservationState::Contested
                            | TxObservationState::Absent
                    )
                );
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
            (positive_presence
                || accepted
                || already_pending_nonfinal
                || mined_reorg
                || legacy_nonfinal)
                && !effective_observation.is_some_and(|item| {
                    item.expiry_height == existing.prepared.expiry_height && item.is_expired()
                })
                && !matches!(
                    submission,
                    Some(SubmissionDisposition::DeterministicRejection { .. })
                )
                && !matches!(
                    effective_observation.map(|item| &item.state),
                    Some(TxObservationState::Mined)
                )
                && (existing.state != TxLifecycleState::Mined
                    || matches!(
                        observation.map(|item| &item.state),
                        Some(
                            TxObservationState::Reorged
                                | TxObservationState::Contested
                                | TxObservationState::Absent
                        )
                    ))
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
        TxLifecycleState::Rejected => {
            matches!(
                submission.or(existing.last_submission.as_ref()),
                Some(SubmissionDisposition::DeterministicRejection { .. })
            ) && !matches!(
                existing.state,
                TxLifecycleState::Mined | TxLifecycleState::Expired
            ) && !matches!(
                observation
                    .or(existing.observation.as_ref())
                    .map(|item| &item.state),
                Some(TxObservationState::Mined)
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
    async fn deterministic_node_refusal_is_rejected() {
        let mut store = RecordingStore::default();
        let tx = fixture();
        let mut node = network(&store, Script::Response(-26, "invalid proof"));
        let result =
            submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
                .await
                .unwrap();
        assert_eq!(result.state, TxLifecycleState::Rejected);
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

        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"kind":"state_changed""#)
            .unwrap();
        file.sync_all().unwrap();
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            DurableBroadcastLog::open(&path),
            Err(crate::ZeckError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
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
    fn expiry_needs_two_distinct_absent_operators_beyond_stored_height() {
        let absent = |operator_id: &str, tip_height, tx_in_block| EndpointTxEvidence {
            operator_id: operator_id.to_owned(),
            endpoint: format!("https://{operator_id}.example"),
            tip_height: Some(tip_height),
            reported_height: None,
            block_hash: None,
            tx_in_block,
        };
        let mut observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(100),
            primary_tip: Some(101),
            secondary_tip: Some(101),
            evidence: vec![absent("one", 101, false), absent("one", 101, false)],
        };
        assert!(!observation.is_expired());
        observation.evidence[1].operator_id = "two".to_owned();
        observation.evidence[1].endpoint = "https://two.example".to_owned();
        observation.evidence[1].tip_height = Some(100);
        assert!(!observation.is_expired());
        observation.evidence[1].tip_height = Some(101);
        assert!(observation.is_expired());
        observation.evidence[1].tx_in_block = true;
        assert!(!observation.is_expired());
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
    fn one_reported_height_is_not_canonical_mined() {
        let observation = observe_transaction(
            vec![confirmation_evidence(
                "one",
                Some(100),
                Some(&[1; 32]),
                true,
            )],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Unavailable);
        assert_eq!(observation.mined_height, None);
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
        assert_eq!(observation.state, TxObservationState::Unavailable);
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
        assert_eq!(observation.state, TxObservationState::Unavailable);
    }

    #[test]
    fn review_trimmed_operator_ids_are_one_expiry_source() {
        let mut second = confirmation_evidence(" one ", None, None, false);
        second.endpoint = "https://other.example".to_owned();
        let evidence = vec![confirmation_evidence("one", None, None, false), second];
        let observation = observe_transaction(evidence.clone(), Some(100));
        assert_ne!(observation.state, TxObservationState::Absent);
        let forged = TxObservation {
            state: TxObservationState::Absent,
            evidence,
            ..observation
        };
        assert!(!forged.is_expired());
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
        let absent = observe_transaction(
            vec![
                confirmation_evidence("one", None, None, false),
                invalid_absent,
            ],
            Some(100),
        );
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
        assert!(!observation.is_expired());
        let reduced = observe_transaction(observation.evidence.clone(), observation.expiry_height);
        assert_ne!(reduced.state, TxObservationState::Absent);
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
                tip_height: Some(101),
                reported_height: None,
                block_hash: None,
                tx_in_block: false,
            })
            .collect();
        let mut observation = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(99),
            primary_tip: Some(101),
            secondary_tip: Some(101),
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
