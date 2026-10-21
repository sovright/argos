use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

use crate::{
    error::{ZeckError, ZeckResult},
    workspace::append_private_file,
};

pub use crate::models::TxLifecycleState;

pub const BROADCAST_LOG_SCHEMA_VERSION: u32 = 1;
pub const BROADCAST_LOG_FILE_NAME: &str = "broadcasts-v1.jsonl";

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

impl TxObservation {
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
        self.evidence
            .iter()
            .filter(|item| {
                !item.operator_id.trim().is_empty()
                    && item.tip_height.is_some_and(|tip| tip > expiry_height)
            })
            .map(|item| item.operator_id.as_str())
            .collect::<HashSet<_>>()
            .len()
            >= 2
    }
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
}

impl DurableBroadcastLog {
    pub fn open(path: impl AsRef<Path>) -> ZeckResult<Self> {
        let path = path.as_ref().to_path_buf();
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
        let mut log = Self {
            path,
            latest: HashMap::new(),
            write_failed: false,
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(ZeckError::Storage(format!(
                "incomplete broadcast log at {}: final event has no newline",
                log.path.display()
            )));
        }
        if bytes.is_empty() {
            return Ok(log);
        }
        let complete_bytes = &bytes[..bytes.len() - 1];
        for (index, line) in complete_bytes.split(|byte| *byte == b'\n').enumerate() {
            let value: serde_json::Value = serde_json::from_slice(line).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid broadcast log event {} in {}: {err}",
                    index + 1,
                    log.path.display()
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
                    log.path.display()
                )));
            }
            let event: BroadcastLogEvent = serde_json::from_value(value).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid broadcast log event {} in {}: {err}",
                    index + 1,
                    log.path.display()
                ))
            })?;
            log.apply_event(event)?;
        }
        Ok(log)
    }

    fn append_event(&mut self, event: BroadcastLogEvent) -> ZeckResult<()> {
        if self.write_failed {
            return Err(ZeckError::Storage(format!(
                "broadcast log {} needs reopening after a failed write",
                self.path.display()
            )));
        }
        let bytes = serde_json::to_vec(&event).map_err(|err| {
            ZeckError::Serialization(format!("serializing broadcast log event: {err}"))
        })?;
        if let Err(err) = append_private_file(&self.path, &bytes) {
            self.write_failed = true;
            return Err(err);
        }
        self.apply_event(event)
    }

    fn apply_event(&mut self, event: BroadcastLogEvent) -> ZeckResult<()> {
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
                validate_transition(existing, state, submission.as_ref(), observation.as_ref())?;
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
                )
        }
        TxLifecycleState::Pending => {
            let effective_observation = observation.or(existing.observation.as_ref());
            let effective_submission = submission.or(existing.last_submission.as_ref());
            let non_final_observation = matches!(
                effective_observation.map(|item| &item.state),
                Some(
                    TxObservationState::PresentUnmined
                        | TxObservationState::Absent
                        | TxObservationState::Reorged
                        | TxObservationState::Contested
                        | TxObservationState::Unavailable
                )
            );
            let accepted_or_retryable = matches!(
                effective_submission,
                Some(
                    SubmissionDisposition::Accepted
                        | SubmissionDisposition::RetryableRejection { .. }
                )
            );
            (non_final_observation || accepted_or_retryable)
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
            matches!(
                observation
                    .or(existing.observation.as_ref())
                    .map(|item| &item.state),
                Some(TxObservationState::Mined)
            ) && !matches!(
                existing.state,
                TxLifecycleState::Rejected | TxLifecycleState::Expired
            ) && !matches!(
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
                let replayed = Self::open(&self.path)?;
                return if replayed.latest(tx.txid).as_ref() == Some(existing) {
                    Ok(())
                } else {
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
        validate_transition(existing, state, submission, observation)?;
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
    use std::{fs, io::Write};
    use zcash_primitives::transaction::TxId;

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
            evidence: vec![],
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
        observation.evidence[1].tip_height = Some(100);
        assert!(!observation.is_expired());
        observation.evidence[1].tip_height = Some(101);
        assert!(observation.is_expired());
        observation.evidence[1].tx_in_block = true;
        assert!(!observation.is_expired());
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
    }
}
