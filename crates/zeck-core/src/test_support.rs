//! Fixtures shared by unit tests in several modules.

use async_trait::async_trait;
use zcash_client_backend::proto::service::SendResponse;
use zcash_primitives::transaction::{Authorized, TransactionData, TxId, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::{
    broadcast::{
        BroadcastStore, PersistedTransaction, PreparedTransaction, SubmissionDisposition,
        TxObservation, TxSubmitter,
    },
    error::{ZeckError, ZeckResult},
    models::TxLifecycleState,
};

/// A valid, empty V5 transaction expiring at `expiry_height`. Its txid is
/// determined by the expiry height alone; the fee is bookkeeping only.
pub(crate) fn empty_v5_prepared(expiry_height: u32, fee_zatoshis: u64) -> PreparedTransaction {
    let tx = TransactionData::<Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        0,
        BlockHeight::from_u32(expiry_height),
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
        fee_zatoshis,
        expiry_height: Some(expiry_height),
    }
}

/// A node that accepts every submission and keeps the bytes it was sent.
#[derive(Default)]
pub(crate) struct AcceptingSubmitter(pub(crate) Vec<Vec<u8>>);

#[async_trait]
impl TxSubmitter for AcceptingSubmitter {
    async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
        self.0.push(raw);
        Ok(SendResponse {
            error_code: 0,
            error_message: String::new(),
        })
    }
}

/// A node whose reply is always lost after the bytes were sent.
pub(crate) struct LostReplySubmitter;

#[async_trait]
impl TxSubmitter for LostReplySubmitter {
    async fn send_raw(&mut self, _raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
        Err(tonic::Status::unavailable("GoAway"))
    }
}

/// Wraps a store and fails every transition that records a submission
/// outcome (the post-I/O write) with "final sync failed".
pub(crate) struct FinalTransitionFails<S>(pub(crate) S);

impl<S: BroadcastStore> BroadcastStore for FinalTransitionFails<S> {
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
