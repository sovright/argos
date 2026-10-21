//! Observe durable sweep submissions without constructing another transaction.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

use crate::{
    broadcast::{
        resubmit_prepared_transaction, BroadcastStore, DurableBroadcastLog, SubmissionDisposition,
        TxObservation, TxObservationState, TxObserver, TxSubmitter,
    },
    error::{ZeckError, ZeckResult},
    models::{TxLifecycleState, ZeckNetwork},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciledTransaction {
    pub txid: String,
    pub status: TxLifecycleState,
    pub fee_zatoshis: u64,
    pub confirmed_height: Option<u32>,
    pub detail: String,
}

/// Append only conclusions supported by the current observation. An absent
/// transaction before expiry is not evidence that an uncertain send failed.
pub fn record_observation(
    store: &mut impl BroadcastStore,
    txid: TxId,
    observation: &TxObservation,
) -> ZeckResult<TxLifecycleState> {
    let previous = store
        .latest(txid)
        .ok_or_else(|| ZeckError::Storage(format!("missing prepared transaction {txid}")))?
        .state;
    if matches!(
        previous,
        TxLifecycleState::Rejected | TxLifecycleState::Expired
    ) {
        return Ok(previous);
    }
    let next = if observation.state == TxObservationState::Mined {
        TxLifecycleState::Mined
    } else if observation.is_expired() {
        TxLifecycleState::Expired
    } else if matches!(
        previous,
        TxLifecycleState::NotSubmitted | TxLifecycleState::SubmissionUnknown
    ) && observation.state != TxObservationState::PresentUnmined
    {
        return Ok(previous);
    } else {
        TxLifecycleState::Pending
    };
    store.transition(txid, next, None, Some(observation))?;
    Ok(next)
}

/// One bounded observation of the exact transaction already in the journal.
/// No signing or submission occurs here.
pub async fn observe_reconciled_transaction<S: BroadcastStore, O: TxObserver>(
    store: &mut S,
    observer: &mut O,
    network: ZeckNetwork,
    txid: TxId,
) -> ZeckResult<ReconciledTransaction> {
    let persisted = store
        .latest(txid)
        .ok_or_else(|| ZeckError::Storage(format!("missing prepared transaction {txid}")))?;
    let observation = observer
        .observe(network, txid, persisted.prepared.expiry_height)
        .await?;
    let status = record_observation(store, txid, &observation)?;
    let confirmed_height = (status == TxLifecycleState::Mined)
        .then_some(observation.mined_height)
        .flatten()
        .or_else(|| {
            (status == TxLifecycleState::Mined)
                .then(|| {
                    persisted
                        .observation
                        .as_ref()
                        .and_then(|item| item.mined_height)
                })
                .flatten()
        });
    let detail = match status {
        TxLifecycleState::Mined => format!(
            "Transaction canonically mined at height {} with independent matching block evidence.",
            confirmed_height.ok_or_else(|| {
                ZeckError::Storage(format!("mined transaction {txid} has no canonical height"))
            })?
        ),
        TxLifecycleState::Expired => {
            "Transaction expired with independent absence beyond its expiry height.".to_owned()
        }
        TxLifecycleState::SubmissionUnknown | TxLifecycleState::NotSubmitted => format!(
            "Observation {:?} does not resolve whether the stored transaction reached the network; keep the source wallet.",
            observation.state
        ),
        TxLifecycleState::Pending => format!(
            "Transaction remains pending (observed {:?}); independent mining evidence is not yet available.",
            observation.state
        ),
        TxLifecycleState::Rejected => "Transaction was deterministically rejected.".to_owned(),
    };
    Ok(ReconciledTransaction {
        txid: txid.to_string(),
        status,
        fee_zatoshis: persisted.prepared.fee_zatoshis,
        confirmed_height,
        detail,
    })
}

/// Observe every latest lifecycle record in a durable journal. This includes
/// older Pending or Unknown transactions that a single blocking-tx lookup
/// would miss, and returns a deterministic txid-ordered snapshot for callers.
pub async fn observe_all_reconciled_transactions<O: TxObserver>(
    log: &mut DurableBroadcastLog,
    observer: &mut O,
    network: ZeckNetwork,
) -> ZeckResult<Vec<ReconciledTransaction>> {
    let txids = log
        .records()
        .into_iter()
        .map(|record| record.prepared.txid)
        .collect::<Vec<_>>();
    let mut results = Vec::with_capacity(txids.len());
    for txid in txids {
        results.push(observe_reconciled_transaction(log, observer, network, txid).await?);
    }
    Ok(results)
}

/// A separate user-authorized retry of Unknown or crash-left Prepared bytes.
/// The caller supplies only a txid; raw bytes come exclusively from the
/// durable record after a fresh observation.
pub async fn retry_unknown_transaction<O: TxObserver, N: TxSubmitter>(
    log: &mut DurableBroadcastLog,
    observer: &mut O,
    submitter: &mut N,
    network: ZeckNetwork,
    txid: TxId,
    deadline: Duration,
) -> ZeckResult<ReconciledTransaction> {
    let observed = observe_reconciled_transaction(log, observer, network, txid).await?;
    if !matches!(
        observed.status,
        TxLifecycleState::SubmissionUnknown | TxLifecycleState::NotSubmitted
    ) {
        return Err(ZeckError::Broadcast(format!(
            "transaction {txid} is {:?}, so its stored bytes are not eligible for explicit retry",
            observed.status
        )));
    }
    let stored = log
        .latest(txid)
        .ok_or_else(|| ZeckError::Storage(format!("missing prepared transaction {txid}")))?
        .prepared;
    let submitted = resubmit_prepared_transaction(log, submitter, &stored, deadline).await?;
    Ok(ReconciledTransaction {
        txid: txid.to_string(),
        status: submitted.state,
        fee_zatoshis: stored.fee_zatoshis,
        confirmed_height: None,
        detail: match submitted.disposition {
            SubmissionDisposition::Accepted =>
                "Exact stored transaction accepted; awaiting independent confirmation.".to_owned(),
            other => format!(
                "Exact stored transaction retry returned {other:?}; confirmation remains unresolved."
            ),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, time::Duration};

    use async_trait::async_trait;
    use zcash_client_backend::proto::service::SendResponse;
    use zcash_primitives::transaction::{Authorized, TransactionData, TxId, TxVersion};
    use zcash_protocol::consensus::{BlockHeight, BranchId};

    use crate::{
        broadcast::{
            observe_transaction, BroadcastStore, DurableBroadcastLog, EndpointTxEvidence,
            PreparedTransaction, SubmissionDisposition, TxObservation, TxObservationState,
            TxObserver, TxSubmitter,
        },
        models::{TxLifecycleState, ZeckNetwork},
        ZeckResult,
    };

    struct ScriptedObserver(VecDeque<TxObservation>);

    #[async_trait]
    impl TxObserver for ScriptedObserver {
        async fn observe(
            &mut self,
            network: ZeckNetwork,
            _txid: TxId,
            _expiry_height: Option<u32>,
        ) -> ZeckResult<TxObservation> {
            assert_eq!(network, ZeckNetwork::Testnet);
            Ok(self
                .0
                .pop_front()
                .expect("one scripted observation per call"))
        }
    }

    fn evidence(operator: &str, height: Option<u32>, in_block: bool) -> EndpointTxEvidence {
        EndpointTxEvidence {
            operator_id: operator.to_owned(),
            endpoint: format!("https://{operator}.example:443"),
            tip_height: Some(122),
            reported_height: height,
            block_hash: in_block.then(|| vec![8; 32]),
            tx_in_block: in_block,
        }
    }

    fn prepared_with_expiry(expiry: u32) -> PreparedTransaction {
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(expiry),
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
            fee_zatoshis: 10_000,
            expiry_height: Some(expiry),
        }
    }

    fn prepared() -> PreparedTransaction {
        prepared_with_expiry(200)
    }

    #[tokio::test]
    async fn pending_needs_two_matching_block_claims_before_it_mines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = prepared();
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
        let contested = observe_transaction(
            vec![
                evidence("one", Some(120), true),
                evidence("two", Some(121), true),
            ],
            tx.expiry_height,
        );
        let mined = observe_transaction(
            vec![
                evidence("one", Some(120), true),
                evidence("two", Some(120), true),
            ],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([contested, mined]));
        let first = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(first.status, TxLifecycleState::Pending);
        assert_eq!(first.confirmed_height, None);
        assert_eq!(log.blocking_submission(), Some(tx.txid));
        let second = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(second.status, TxLifecycleState::Mined);
        assert_eq!(second.confirmed_height, Some(120));
        drop(log);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(
            reopened.latest(tx.txid).unwrap().state,
            TxLifecycleState::Mined
        );
        assert_eq!(reopened.blocking_submission(), None);
    }

    #[tokio::test]
    async fn observes_every_latest_record_instead_of_only_one_blocker() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let first = prepared_with_expiry(200);
        let second = prepared_with_expiry(201);
        for tx in [&first, &second] {
            log.persist_prepared(tx).unwrap();
            log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
            log.transition(
                tx.txid,
                TxLifecycleState::Pending,
                Some(&SubmissionDisposition::Accepted),
                None,
            )
            .unwrap();
        }
        let observations = log
            .records()
            .into_iter()
            .map(|record| {
                observe_transaction(
                    vec![
                        evidence("one", Some(120), true),
                        evidence("two", Some(120), true),
                    ],
                    record.prepared.expiry_height,
                )
            })
            .collect();
        let mut observer = ScriptedObserver(observations);
        let rows = super::observe_all_reconciled_transactions(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.status == TxLifecycleState::Mined));
        assert_ne!(rows[0].txid, rows[1].txid);
        assert_eq!(log.blocking_submission(), None);
    }

    #[tokio::test]
    async fn mined_transaction_seen_unmined_again_blocks_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let mined = observe_transaction(
            vec![
                evidence("one", Some(120), true),
                evidence("two", Some(120), true),
            ],
            tx.expiry_height,
        );
        log.transition(tx.txid, TxLifecycleState::Mined, None, Some(&mined))
            .unwrap();
        let unmined = observe_transaction(
            vec![
                evidence("one", Some(0), false),
                evidence("two", Some(0), false),
            ],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([unmined]));
        let result = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(result.status, TxLifecycleState::Pending);
        assert_eq!(result.confirmed_height, None);
        assert_eq!(log.blocking_submission(), Some(tx.txid));
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

    #[tokio::test]
    async fn mined_transaction_with_unavailable_fresh_evidence_blocks_completion() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let mined = observe_transaction(
            vec![
                evidence("one", Some(120), true),
                evidence("two", Some(120), true),
            ],
            tx.expiry_height,
        );
        log.transition(tx.txid, TxLifecycleState::Mined, None, Some(&mined))
            .unwrap();
        let unavailable = observe_transaction(vec![], tx.expiry_height);
        assert_eq!(
            unavailable.state,
            crate::broadcast::TxObservationState::Unavailable
        );
        let mut observer = ScriptedObserver(VecDeque::from([unavailable]));
        let result = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(result.status, TxLifecycleState::Pending);
        assert_eq!(result.confirmed_height, None);
        assert_eq!(log.blocking_submission(), Some(tx.txid));
    }

    #[tokio::test]
    async fn absence_keeps_unknown_blocking_without_submitting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let absent = observe_transaction(
            vec![evidence("one", None, false), evidence("two", None, false)],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([absent]));
        let result = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(result.status, TxLifecycleState::SubmissionUnknown);
        assert_eq!(result.confirmed_height, None);
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .blocking_submission(),
            Some(tx.txid)
        );
    }

    #[test]
    fn unknown_requires_positive_presence_to_become_pending() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        for state in [
            TxObservationState::Absent,
            TxObservationState::Reorged,
            TxObservationState::Contested,
            TxObservationState::Unavailable,
        ] {
            let observation = TxObservation {
                state,
                mined_height: None,
                expiry_height: tx.expiry_height,
                primary_tip: Some(120),
                secondary_tip: Some(120),
                evidence: vec![],
            };
            assert_eq!(
                super::record_observation(&mut log, tx.txid, &observation).unwrap(),
                TxLifecycleState::SubmissionUnknown
            );
            assert_eq!(log.blocking_submission(), Some(tx.txid));
        }
        let present = observe_transaction(
            vec![
                evidence("one", Some(0), false),
                evidence("two", Some(0), false),
            ],
            tx.expiry_height,
        );
        assert_eq!(present.state, TxObservationState::PresentUnmined);
        assert_eq!(
            super::record_observation(&mut log, tx.txid, &present).unwrap(),
            TxLifecycleState::Pending
        );
    }

    #[derive(Default)]
    struct CapturingSubmitter(Vec<Vec<u8>>);

    #[async_trait]
    impl TxSubmitter for CapturingSubmitter {
        async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
            self.0.push(raw);
            Ok(SendResponse {
                error_code: 0,
                error_message: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn explicit_unknown_retry_sends_only_the_stored_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let absent = observe_transaction(
            vec![evidence("one", None, false), evidence("two", None, false)],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([absent]));
        let mut submitter = CapturingSubmitter::default();
        let result = super::retry_unknown_transaction(
            &mut log,
            &mut observer,
            &mut submitter,
            ZeckNetwork::Testnet,
            tx.txid,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(submitter.0, vec![tx.raw_tx]);
        assert_eq!(result.status, TxLifecycleState::Pending);
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

    #[tokio::test]
    async fn explicit_retry_refuses_send_after_fresh_presence_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let present = observe_transaction(
            vec![
                evidence("one", Some(0), false),
                evidence("two", Some(0), false),
            ],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([present]));
        let mut submitter = CapturingSubmitter::default();
        let result = super::retry_unknown_transaction(
            &mut log,
            &mut observer,
            &mut submitter,
            ZeckNetwork::Testnet,
            tx.txid,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
        assert!(submitter.0.is_empty());
        assert_eq!(
            log.latest(tx.txid).unwrap().state,
            TxLifecycleState::Pending
        );
    }

    #[tokio::test]
    async fn prepared_before_submission_crash_retries_only_stored_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&tx).unwrap();
        let absent = observe_transaction(
            vec![evidence("one", None, false), evidence("two", None, false)],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([absent]));
        let mut submitter = CapturingSubmitter::default();
        let result = super::retry_unknown_transaction(
            &mut log,
            &mut observer,
            &mut submitter,
            ZeckNetwork::Testnet,
            tx.txid,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(submitter.0, vec![tx.raw_tx]);
        assert_eq!(result.status, TxLifecycleState::Pending);
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
}
