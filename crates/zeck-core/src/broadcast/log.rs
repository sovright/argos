use std::{
    collections::HashMap,
    fs,
    fs::OpenOptions,
    io::{Seek, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

use super::{
    lifecycle::validate_transition, BroadcastStore, PersistedTransaction, PreparedTransaction,
    SubmissionDisposition, TxLifecycleState, TxObservation,
};
use crate::{
    error::{ZeckError, ZeckResult},
    workspace::append_private_file,
};

pub const BROADCAST_LOG_SCHEMA_VERSION: u32 = 1;
pub const BROADCAST_LOG_FILE_NAME: &str = "broadcasts-v1.jsonl";

/// The lock lives beside the workspace, so renaming or deleting that
/// workspace cannot unlink the lock inode while a submitter holds it.
pub(super) fn broadcast_lock_path(path: &Path) -> ZeckResult<PathBuf> {
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum BroadcastLogEvent {
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

pub struct DurableBroadcastLog {
    path: PathBuf,
    latest: HashMap<TxId, PersistedTransaction>,
    write_failed: bool,
    // SQLite owns an OS file lock, released by Drop or process death. The
    // sidecar never stores transaction data and cannot leave a stale lock.
    _process_lock: rusqlite::Connection,
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
    ///   acknowledged; it is truncated away (the earlier synced state stands);
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

    pub(super) fn append_event(&mut self, event: BroadcastLogEvent) -> ZeckResult<()> {
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
