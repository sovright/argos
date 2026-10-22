use super::log::{broadcast_lock_path, BroadcastLogEvent};
use super::*;
use crate::error::{ZeckError, ZeckResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
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
    let result = submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
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
    let result = submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_millis(25))
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
        assert!(
            resubmit_prepared_transaction(&mut store, &mut node, &tx, Duration::from_secs(1),)
                .await
                .is_err()
        );
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
    let result = submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
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
    let result = submit_prepared_transaction(&mut store, &mut node, tx, Duration::from_secs(30))
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
    let result = resubmit_prepared_transaction(&mut store, &mut node, &tx, Duration::from_secs(30))
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
