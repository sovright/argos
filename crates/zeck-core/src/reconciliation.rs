//! Observe durable sweep submissions without constructing another transaction.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

use crate::{
    broadcast::{
        observe_transaction, resubmit_prepared_transaction, BroadcastStore, DurableBroadcastLog,
        SubmissionDisposition, TxObservation, TxObservationState, TxObserver, TxSubmitter,
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
    /// See `TxBroadcastResult::safe_to_discard`.
    #[serde(default)]
    pub safe_to_discard: bool,
}

/// The one place an observation becomes a lifecycle state, shared by
/// post-submission polling, explicit reconciliation, and deletion checks.
///
/// - Rejected and Expired are final.
/// - Independent-pair block evidence gives Mined; one operator's block
///   evidence gives MinedSingleSource (and never downgrades Mined).
/// - Absence past expiry plus margin gives Expired (see
///   `broadcast::EXPIRY_MARGIN_BLOCKS`).
/// - A mined record is demoted to Pending only by a positive reorg, absence,
///   or mempool observation; Unavailable and Contested leave it mined.
/// - An absent transaction before expiry is not evidence that an uncertain
///   send failed, so NotSubmitted / SubmissionUnknown need positive presence.
/// - A Pending record observed as still pending appends nothing.
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
    let next = if observation.has_canonical_mined_evidence() {
        TxLifecycleState::Mined
    } else if observation.has_single_source_mined_evidence() {
        if previous == TxLifecycleState::Mined {
            return Ok(previous);
        }
        TxLifecycleState::MinedSingleSource
    } else if observation.is_expired() {
        TxLifecycleState::Expired
    } else if previous.is_mined() {
        match observation.state {
            TxObservationState::Reorged
            | TxObservationState::Absent
            | TxObservationState::PresentUnmined => TxLifecycleState::Pending,
            _ => return Ok(previous),
        }
    } else if matches!(
        previous,
        TxLifecycleState::NotSubmitted | TxLifecycleState::SubmissionUnknown
    ) && observation.state != TxObservationState::PresentUnmined
    {
        return Ok(previous);
    } else {
        TxLifecycleState::Pending
    };
    if previous == TxLifecycleState::Pending && next == TxLifecycleState::Pending {
        return Ok(previous);
    }
    store.transition(txid, next, None, Some(observation))?;
    Ok(next)
}

/// User-facing explanation of a lifecycle state after an observation.
pub(crate) fn lifecycle_detail(
    status: TxLifecycleState,
    observation_state: &TxObservationState,
    confirmed_height: Option<u32>,
    safe_to_discard: bool,
) -> String {
    let height = confirmed_height
        .map(|height| height.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    match status {
        TxLifecycleState::Mined if safe_to_discard => format!(
            "Transaction mined at height {height} with matching block evidence from independent operators, at least {} confirmations deep.",
            crate::broadcast::MIN_DISCARD_CONFIRMATIONS
        ),
        TxLifecycleState::Mined => format!(
            "Transaction mined at height {height} with matching block evidence from independent operators. Keep the source until it is {} confirmations deep.",
            crate::broadcast::MIN_DISCARD_CONFIRMATIONS
        ),
        TxLifecycleState::MinedSingleSource => format!(
            "Transaction mined at height {height} according to a single confirmation operator. The recovery can continue, but keep the source keys or wallet file until an independent source confirms."
        ),
        TxLifecycleState::Expired => {
            "Transaction expired: reported absent from chain and mempool past its expiry height.".to_owned()
        }
        TxLifecycleState::SubmissionUnknown | TxLifecycleState::NotSubmitted => format!(
            "Observation {observation_state:?} does not resolve whether the stored transaction reached the network; keep the source wallet."
        ),
        TxLifecycleState::Pending => format!(
            "Transaction remains pending (observed {observation_state:?}); mining evidence is not yet available."
        ),
        TxLifecycleState::Rejected => {
            "Transaction was deterministically rejected; a new review may rebuild it.".to_owned()
        }
    }
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
    reconcile_with_observation(store, txid, observation)
}

fn reconcile_with_observation<S: BroadcastStore>(
    store: &mut S,
    txid: TxId,
    observation: TxObservation,
) -> ZeckResult<ReconciledTransaction> {
    let status = record_observation(store, txid, &observation)?;
    let persisted = store
        .latest(txid)
        .ok_or_else(|| ZeckError::Storage(format!("missing prepared transaction {txid}")))?;
    // A mined record kept through an Unavailable observation reports the
    // evidence it was mined on.
    let evidence = if status.is_mined() && !observation.state_is_mined() {
        persisted.observation.clone()
    } else {
        Some(observation.clone())
    };
    let confirmed_height = status
        .is_mined()
        .then(|| evidence.as_ref().and_then(|item| item.mined_height))
        .flatten();
    if status.is_mined() && confirmed_height.is_none() {
        return Err(ZeckError::Storage(format!(
            "mined transaction {txid} has no canonical height"
        )));
    }
    let safe_to_discard = status == TxLifecycleState::Mined
        && evidence
            .as_ref()
            .is_some_and(TxObservation::is_safe_to_discard);
    Ok(ReconciledTransaction {
        txid: txid.to_string(),
        status,
        fee_zatoshis: persisted.prepared.fee_zatoshis,
        confirmed_height,
        detail: lifecycle_detail(
            status,
            &observation.state,
            confirmed_height,
            safe_to_discard,
        ),
        safe_to_discard,
    })
}

/// Observe every latest lifecycle record in a durable journal. This includes
/// older Pending or Unknown transactions that a single blocking-tx lookup
/// would miss, and returns a deterministic txid-ordered snapshot for callers.
/// An observer failure for one transaction is recorded as Unavailable for it
/// and does not stop the others from being observed.
pub async fn observe_all_reconciled_transactions<O: TxObserver>(
    log: &mut DurableBroadcastLog,
    observer: &mut O,
    network: ZeckNetwork,
) -> ZeckResult<Vec<ReconciledTransaction>> {
    let records = log.records();
    let mut results = Vec::with_capacity(records.len());
    for record in records {
        let txid = record.prepared.txid;
        let observation = match observer
            .observe(network, txid, record.prepared.expiry_height)
            .await
        {
            Ok(observation) => observation,
            Err(err) => {
                let mut row = reconcile_with_observation(
                    log,
                    txid,
                    observe_transaction(Vec::new(), record.prepared.expiry_height),
                )?;
                row.detail = format!("{} Observation failed: {err}", row.detail);
                results.push(row);
                continue;
            }
        };
        results.push(reconcile_with_observation(log, txid, observation)?);
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
        safe_to_discard: false,
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
    use zcash_primitives::transaction::TxId;

    use crate::{
        broadcast::{
            observe_transaction, BroadcastStore, DurableBroadcastLog, EndpointTxEvidence,
            PreparedTransaction, SubmissionDisposition, TxObservation, TxObservationState,
            TxObserver,
        },
        models::{TxLifecycleState, ZeckNetwork},
        test_support::{AcceptingSubmitter, LostReplySubmitter},
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
        crate::test_support::empty_v5_prepared(expiry, 10_000)
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
    async fn unavailable_evidence_does_not_demote_a_mined_transaction() {
        for corroborated in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let tx = prepared();
            let path = dir.path().join("broadcasts-v1.jsonl");
            let mut log = DurableBroadcastLog::open(&path).unwrap();
            log.persist_prepared(&tx).unwrap();
            log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
            let sources = if corroborated {
                vec![
                    evidence("one", Some(120), true),
                    evidence("two", Some(120), true),
                ]
            } else {
                vec![evidence("one", Some(120), true)]
            };
            let mined = observe_transaction(sources, tx.expiry_height);
            let expected = if corroborated {
                TxLifecycleState::Mined
            } else {
                TxLifecycleState::MinedSingleSource
            };
            assert_eq!(
                super::record_observation(&mut log, tx.txid, &mined).unwrap(),
                expected
            );
            let events_before = std::fs::read(&path).unwrap();
            // A timeout, and a disagreement, are not positive reorg evidence.
            let unavailable = observe_transaction(vec![], tx.expiry_height);
            assert_eq!(unavailable.state, TxObservationState::Unavailable);
            let contested = observe_transaction(
                vec![
                    evidence("one", Some(120), true),
                    evidence("two", Some(121), true),
                ],
                tx.expiry_height,
            );
            assert_eq!(contested.state, TxObservationState::Contested);
            let mut observer = ScriptedObserver(VecDeque::from([unavailable, contested]));
            for _ in 0..2 {
                let result = super::observe_reconciled_transaction(
                    &mut log,
                    &mut observer,
                    ZeckNetwork::Testnet,
                    tx.txid,
                )
                .await
                .unwrap();
                assert_eq!(result.status, expected);
                assert_eq!(result.confirmed_height, Some(120));
                assert_eq!(log.blocking_submission(), None);
            }
            assert_eq!(std::fs::read(&path).unwrap(), events_before);
        }
    }

    #[test]
    fn single_source_mining_never_downgrades_corroborated_mining() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        log.persist_prepared(&tx).unwrap();
        log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        let single = observe_transaction(vec![evidence("one", Some(120), true)], tx.expiry_height);
        let pair = observe_transaction(
            vec![
                evidence("one", Some(120), true),
                evidence("two", Some(120), true),
            ],
            tx.expiry_height,
        );
        assert_eq!(
            super::record_observation(&mut log, tx.txid, &single).unwrap(),
            TxLifecycleState::MinedSingleSource
        );
        assert_eq!(
            super::record_observation(&mut log, tx.txid, &pair).unwrap(),
            TxLifecycleState::Mined
        );
        assert_eq!(
            super::record_observation(&mut log, tx.txid, &single).unwrap(),
            TxLifecycleState::Mined
        );
    }

    #[test]
    fn pending_observed_still_pending_appends_nothing() {
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
        let before = std::fs::read(&path).unwrap();
        for observation in [
            observe_transaction(vec![], tx.expiry_height),
            observe_transaction(
                vec![
                    evidence("one", Some(0), false),
                    evidence("two", Some(0), false),
                ],
                tx.expiry_height,
            ),
        ] {
            assert_eq!(
                super::record_observation(&mut log, tx.txid, &observation).unwrap(),
                TxLifecycleState::Pending
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    struct FailingFirstObserver {
        calls: usize,
        inner: ScriptedObserver,
    }

    #[async_trait]
    impl TxObserver for FailingFirstObserver {
        async fn observe(
            &mut self,
            network: ZeckNetwork,
            txid: TxId,
            expiry_height: Option<u32>,
        ) -> ZeckResult<TxObservation> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(crate::ZeckError::Lightwalletd("timed out".to_owned()));
            }
            self.inner.observe(network, txid, expiry_height).await
        }
    }

    #[tokio::test]
    async fn one_observer_failure_does_not_stop_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let first = prepared_with_expiry(200);
        let second = prepared_with_expiry(201);
        for tx in [&first, &second] {
            log.persist_prepared(tx).unwrap();
            log.transition(tx.txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
        }
        let mined = observe_transaction(
            vec![
                evidence("one", Some(120), true),
                evidence("two", Some(120), true),
            ],
            Some(201),
        );
        let mut observer = FailingFirstObserver {
            calls: 0,
            inner: ScriptedObserver(VecDeque::from([mined])),
        };
        let rows = super::observe_all_reconciled_transactions(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
        )
        .await
        .unwrap();
        assert_eq!(observer.calls, 2);
        assert_eq!(rows.len(), 2);
        let failed = rows
            .iter()
            .find(|row| row.status == TxLifecycleState::SubmissionUnknown)
            .expect("the failed observation is reported as unresolved");
        assert!(failed.detail.contains("timed out"), "{}", failed.detail);
        assert!(rows.iter().any(|row| row.status == TxLifecycleState::Mined));
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

    /// The default configuration: zec.rocks and na.zec.rocks, one operator.
    fn default_operator_evidence(
        endpoint: &str,
        tip: u32,
        reported_height: Option<u32>,
    ) -> EndpointTxEvidence {
        EndpointTxEvidence {
            operator_id: "zec.rocks".to_owned(),
            endpoint: endpoint.to_owned(),
            tip_height: Some(tip),
            reported_height,
            block_hash: reported_height.map(|_| vec![9; 32]),
            tx_in_block: reported_height.is_some(),
        }
    }

    #[tokio::test]
    async fn default_operator_mining_resolves_review_but_not_discard() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let mut node = AcceptingSubmitter::default();
        let submitted = crate::broadcast::submit_prepared_transaction(
            &mut log,
            &mut node,
            tx.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(submitted.state, TxLifecycleState::Pending);
        assert!(log.has_unresolved_history());
        let mined = observe_transaction(
            vec![
                default_operator_evidence("https://zec.rocks:443", 150, Some(120)),
                default_operator_evidence("https://na.zec.rocks:443", 150, Some(120)),
            ],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([mined]));
        let row = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(row.status, TxLifecycleState::MinedSingleSource);
        assert_eq!(row.confirmed_height, Some(120));
        // A new review may start ...
        assert!(!log.has_unresolved_history());
        assert_eq!(log.blocking_submission(), None);
        // ... but nothing says the source may be discarded, however deep.
        assert!(!row.safe_to_discard);
        assert!(log.mined_records().is_empty());
        assert!(row.detail.contains("independent source"), "{}", row.detail);
    }

    #[tokio::test]
    async fn lost_reply_then_absence_past_expiry_margin_expires() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared_with_expiry(200);
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let submitted = crate::broadcast::submit_prepared_transaction(
            &mut log,
            &mut LostReplySubmitter,
            tx.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(submitted.state, TxLifecycleState::SubmissionUnknown);
        assert!(log.has_unresolved_history());
        let margin = crate::broadcast::EXPIRY_MARGIN_BLOCKS;
        let at_margin = observe_transaction(
            vec![default_operator_evidence(
                "https://zec.rocks:443",
                200 + margin,
                None,
            )],
            tx.expiry_height,
        );
        let past_margin = observe_transaction(
            vec![default_operator_evidence(
                "https://zec.rocks:443",
                201 + margin,
                None,
            )],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([at_margin, past_margin]));
        let first = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(first.status, TxLifecycleState::SubmissionUnknown);
        assert!(log.has_unresolved_history());
        let second = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(second.status, TxLifecycleState::Expired);
        assert!(!log.has_unresolved_history());
    }

    #[tokio::test]
    async fn lost_reply_then_single_operator_mining_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepared();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        crate::broadcast::submit_prepared_transaction(
            &mut log,
            &mut LostReplySubmitter,
            tx.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let mined = observe_transaction(
            vec![default_operator_evidence(
                "https://zec.rocks:443",
                130,
                Some(121),
            )],
            tx.expiry_height,
        );
        let mut observer = ScriptedObserver(VecDeque::from([mined]));
        let row = super::observe_reconciled_transaction(
            &mut log,
            &mut observer,
            ZeckNetwork::Testnet,
            tx.txid,
        )
        .await
        .unwrap();
        assert_eq!(row.status, TxLifecycleState::MinedSingleSource);
        assert!(!log.has_unresolved_history());
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
        let mut submitter = AcceptingSubmitter::default();
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
        let mut submitter = AcceptingSubmitter::default();
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
        let mut submitter = AcceptingSubmitter::default();
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
