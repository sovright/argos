use std::{io::Cursor, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction, SendResponse,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId};

use super::{lifecycle::rejection_can_be_definitive, TxLifecycleState, TxObservation};
use crate::{
    error::{ZeckError, ZeckResult},
    models::ZeckNetwork,
    workspace::consensus_network,
};

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
pub trait TxSubmitter: Send {
    async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status>;

    /// Fresh evidence from the endpoint that will receive an explicit retry.
    /// Ordinary submitters cannot silently authorize old bytes with an unknown
    /// height; adapters supporting retry must validate the requested network.
    async fn validated_tip(&mut self, _network: ZeckNetwork) -> ZeckResult<u32> {
        Err(ZeckError::Broadcast(
            "cannot establish a fresh network-validated tip for retry; keep the stored transaction bytes and reconcile their status before replanning".into(),
        ))
    }
}

pub struct LightwalletdSubmitter<'a> {
    pub client: &'a mut CompactTxStreamerClient<Channel>,
}

#[async_trait]
impl TxSubmitter for LightwalletdSubmitter<'_> {
    async fn validated_tip(&mut self, network: ZeckNetwork) -> ZeckResult<u32> {
        crate::nu7::validated_tip_from_client(self.client, network).await
    }

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

/// Check the exact persisted transaction against the candidate next block.
/// V5/V6 retain their format across upgrades, but their encoded branch binds
/// their signatures. Reading old bytes with a new fallback branch cannot
/// change that encoded authority. This check neither mutates nor rebuilds them.
pub(crate) fn validate_retry_at_tip(
    raw_tx: &[u8],
    network: ZeckNetwork,
    tip: u32,
) -> ZeckResult<()> {
    let next_height = tip.checked_add(1).filter(|_| tip > 0).ok_or_else(|| {
        ZeckError::Broadcast("cannot establish a supported next-block height for retry; keep the stored transaction bytes and reconcile their status before replanning".into())
    })?;
    let branch = BranchId::for_height(
        &consensus_network(network),
        BlockHeight::from_u32(next_height),
    );
    let mut cursor = Cursor::new(raw_tx);
    let transaction = Transaction::read(&mut cursor, branch).map_err(|err| {
        ZeckError::TransactionBuild(format!(
            "cannot parse persisted transaction for retry: {err}"
        ))
    })?;
    if cursor.position() != raw_tx.len() as u64 {
        return Err(ZeckError::TransactionBuild(
            "persisted transaction has trailing bytes".into(),
        ));
    }
    crate::nu7::validate_transaction_for_tip(network, tip, &transaction).map_err(|err| {
        ZeckError::Broadcast(format!(
            "stored transaction cannot be retried ({err}); keep its exact bytes and reconcile its status before replanning"
        ))
    })
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
