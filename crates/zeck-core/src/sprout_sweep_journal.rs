//! Durable, versioned Sprout sweep transactions, keyed by note and source.
//!
//! # What is on disk
//!
//! `sprout-sweep-<fingerprint>.journal` in the data directory: a header
//! (version, network, full key-set fingerprint), then one JSON record per
//! event -- each note's outpoint and swept value, each transaction's exact
//! signed bytes, fee and expiry, and its lifecycle transitions with the
//! observations behind them.
//!
//! It holds no spending key (`a_sk`) and no note plaintext, so it cannot
//! spend anything; the scan checkpoint is the spend-capable file. It is
//! still linkable: the signed bytes reveal each note's nullifier and the
//! destination's encrypted output, tying the wallet's Sprout notes to their
//! sweep transactions.
//!
//! The journal is created through the private artifact container before its
//! first byte is written. Every append verifies the retained namespace, exact
//! object identity, lineage anchor, and artifact generation. Legacy journals
//! without that v4 lineage boundary are preserved unchanged and refused until
//! explicitly reconciled.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::Cursor,
    path::{Path, PathBuf},
    time::Duration,
};

use argos_wallet_import::keys::JsOutPoint;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;

use crate::{
    broadcast::{
        txid_from_raw, validate_transition, BroadcastStore, PersistedTransaction,
        PreparedTransaction, SubmissionDisposition, TxLifecycleState, TxObservation,
    },
    error::{ZeckError, ZeckResult},
    models::ZeckNetwork,
    private_fs::{NamespaceLease, PrivateObjectId},
    sprout_scan::SPROUT_REORG_WINDOW,
    sprout_scan_run::{full_key_set_fingerprint, key_set_fingerprint, CheckpointGeneration},
};

pub const SPROUT_SWEEP_JOURNAL_VERSION: u32 = 4;
pub const SPROUT_EXPIRY_DELTA: u32 = 40;
pub type SproutNoteId = ([u8; 32], u64, u8);

#[cfg(test)]
static FAIL_AFTER_CHECKPOINT_DISCARD: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

#[cfg(test)]
pub(crate) fn fail_after_checkpoint_discard(path: &Path) {
    FAIL_AFTER_CHECKPOINT_DISCARD
        .lock()
        .unwrap()
        .insert(path.to_path_buf());
}

pub fn note_id(outpoint: &JsOutPoint) -> SproutNoteId {
    (outpoint.txid, outpoint.js_index, outpoint.output_index)
}

fn outpoint(id: SproutNoteId) -> JsOutPoint {
    JsOutPoint {
        txid: id.0,
        js_index: id.1,
        output_index: id.2,
    }
}

fn journal_error(message: impl Into<String>) -> ZeckError {
    ZeckError::Storage(message.into())
}

/// The lock inode is stable across the v1-to-v2 rename. Both the temporary
/// legacy writer and v2 journal take this same SQLite process lock.
pub(crate) fn with_sweep_journal_lock<T>(
    path: &Path,
    namespace: Option<&NamespaceLease>,
    operation: impl FnOnce(&NamespaceLease) -> ZeckResult<T>,
) -> ZeckResult<T> {
    let parent = path
        .parent()
        .ok_or_else(|| journal_error("Sprout journal lock has no parent"))?;
    let sqlite_path = parent.join(".journal.lock.sqlite");
    let authority_path = parent.join(".journal.lock");
    let owned_namespace;
    let namespace = if let Some(namespace) = namespace {
        if namespace.parent_path() != parent {
            return Err(journal_error(format!(
                "sweep journal {} is not bound to its retained namespace",
                path.display()
            )));
        }
        namespace
    } else {
        owned_namespace = crate::private_fs::NamespaceLease::acquire(parent, &authority_path)
            .map_err(|err| {
                journal_error(format!(
                    "opening sweep journal namespace {}: {err}",
                    parent.display()
                ))
            })?;
        &owned_namespace
    };
    namespace
        .verify_current()
        .map_err(|err| journal_error(format!("verifying sweep journal namespace: {err}")))?;
    let child_lock = if namespace.lock_path() == authority_path {
        None
    } else {
        Some(
            namespace
                .acquire_child_lock(&authority_path)
                .map_err(|err| {
                    journal_error(format!(
                        "locking sweep journal sidecar {}: {err}",
                        authority_path.display()
                    ))
                })?,
        )
    };
    let sqlite_child = namespace
        .open_or_create_retained_child(&sqlite_path)
        .map_err(|err| {
            journal_error(format!(
                "retaining sweep journal compatibility lock {}: {err}",
                sqlite_path.display()
            ))
        })?;
    let connection = rusqlite::Connection::open_with_flags(
        &sqlite_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .map_err(|err| {
        journal_error(format!(
            "opening sweep journal lock {}: {err}",
            sqlite_path.display()
        ))
    })?;
    sqlite_child.verify_current().map_err(|err| {
        journal_error(format!(
            "sweep journal compatibility lock changed while opening: {err}"
        ))
    })?;
    connection
        .busy_timeout(Duration::from_secs(10))
        .map_err(|err| journal_error(format!("setting sweep journal lock timeout: {err}")))?;
    connection
        .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
        .map_err(|err| {
            journal_error(format!("sweep journal {} is in use: {err}", path.display()))
        })?;
    sqlite_child.verify_current().map_err(|err| {
        journal_error(format!(
            "sweep journal compatibility lock changed while locking: {err}"
        ))
    })?;
    namespace.verify_current().map_err(|err| {
        journal_error(format!(
            "sweep journal namespace changed while locking: {err}"
        ))
    })?;
    if let Some(child_lock) = child_lock.as_ref() {
        child_lock.verify_current().map_err(|err| {
            journal_error(format!(
                "sweep journal sidecar changed while locking: {err}"
            ))
        })?;
    }
    let result = operation(namespace);
    let verified = namespace.verify_current().map_err(|err| {
        journal_error(format!(
            "sweep journal namespace changed during operation: {err}"
        ))
    });
    let child_verified = child_lock
        .as_ref()
        .map(|child_lock| {
            child_lock.verify_current().map_err(|err| {
                journal_error(format!(
                    "sweep journal sidecar changed during operation: {err}"
                ))
            })
        })
        .transpose();
    let sqlite_verified = sqlite_child.verify_current().map_err(|err| {
        journal_error(format!(
            "sweep journal compatibility lock changed during operation: {err}"
        ))
    });
    drop(connection);
    match result {
        Err(err) => Err(err),
        Ok(value) => verified
            .and(child_verified.map(|_| ()))
            .and(sqlite_verified)
            .map(|()| value),
    }
}

fn validate_prepared(tx: &PreparedTransaction) -> ZeckResult<()> {
    if txid_from_raw(&tx.raw_tx)? != tx.txid {
        return Err(journal_error(format!(
            "raw transaction does not match {}",
            tx.txid
        )));
    }
    let parsed = Transaction::read(&mut Cursor::new(&tx.raw_tx), BranchId::Nu5)
        .map_err(|err| journal_error(format!("cannot decode journal transaction expiry: {err}")))?;
    let encoded_expiry = u32::from(parsed.expiry_height());
    if tx.expiry_height != Some(encoded_expiry) {
        return Err(journal_error(format!(
            "journal expiry {:?} does not match transaction expiry {encoded_expiry}",
            tx.expiry_height
        )));
    }
    Ok(())
}

fn decode_txid(text: &str) -> ZeckResult<TxId> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(journal_error("invalid journal transaction ID"));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().rev().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| journal_error("invalid journal transaction ID"))?;
    }
    Ok(TxId::from_bytes(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JournalPreparedTransaction {
    txid: String,
    raw_tx_base64: String,
    fee_zatoshis: u64,
    expiry_height: Option<u32>,
}

impl JournalPreparedTransaction {
    fn from_prepared(tx: &PreparedTransaction) -> ZeckResult<Self> {
        validate_prepared(tx)?;
        Ok(Self {
            txid: tx.txid.to_string(),
            raw_tx_base64: STANDARD.encode(&tx.raw_tx),
            fee_zatoshis: tx.fee_zatoshis,
            expiry_height: tx.expiry_height,
        })
    }

    fn into_prepared(self) -> ZeckResult<PreparedTransaction> {
        let txid = decode_txid(&self.txid)?;
        let raw_tx = STANDARD
            .decode(self.raw_tx_base64)
            .map_err(|err| journal_error(format!("invalid journal raw transaction: {err}")))?;
        let tx = PreparedTransaction {
            txid,
            raw_tx,
            fee_zatoshis: self.fee_zatoshis,
            expiry_height: self.expiry_height,
        };
        validate_prepared(&tx)?;
        Ok(tx)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum SproutJournalRecord {
    Header {
        version: u32,
        network: ZeckNetwork,
        source_fingerprint: String,
        authority_anchor: [u8; 16],
        artifact_generation: [u8; 16],
    },
    Prepared {
        note_id: SproutNoteId,
        value_zatoshis: u64,
        transaction: JournalPreparedTransaction,
    },
    Transition {
        txid: String,
        state: TxLifecycleState,
        submission: Option<SubmissionDisposition>,
        observation: Option<TxObservation>,
    },
    /// Narrows cleanup authority without replacing the known lifecycle fact.
    CleanupEvidenceInvalidated {
        txid: String,
    },
    LegacyAccepted {
        note_id: SproutNoteId,
        txid: String,
    },
    LegacyExpiryBound {
        txid: String,
        verified_tip: u32,
        expiry_bound: u32,
    },
    CheckpointManifest {
        source_fingerprint: String,
        generation: CheckpointGeneration,
        note_ids: BTreeSet<SproutNoteId>,
    },
    CheckpointDiscardStarted {
        source_fingerprint: String,
        generation: CheckpointGeneration,
        reorg_window: u32,
    },
    CheckpointDiscarded {
        source_fingerprint: String,
        generation: CheckpointGeneration,
    },
    CheckpointTombstone {
        source_fingerprint: String,
        generation: CheckpointGeneration,
        reorg_window: u32,
        note_id: SproutNoteId,
        value_zatoshis: u64,
        transaction: JournalPreparedTransaction,
        state: TxLifecycleState,
        last_submission: Option<SubmissionDisposition>,
        observations: Vec<TxObservation>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointManifest {
    pub source_fingerprint: String,
    pub generation: CheckpointGeneration,
    pub note_ids: BTreeSet<SproutNoteId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointCleanupEligibility {
    Eligible { mined_txids: Vec<String> },
    Retain { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointCleanupResult {
    Removed,
    AlreadyAbsent,
    Retain { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SproutJournalEntry {
    pub outpoint: JsOutPoint,
    pub source_fingerprint: String,
    pub transaction: Option<PreparedTransaction>,
    pub legacy_txid: Option<TxId>,
    pub value_zatoshis: Option<u64>,
    pub state: TxLifecycleState,
    pub last_submission: Option<SubmissionDisposition>,
    pub observation: Option<TxObservation>,
    /// Observations in the current uninterrupted cleanup-evidence run. An
    /// invalidation clears this run, while earlier records remain on disk.
    pub observations: Vec<TxObservation>,
    pub legacy_expiry_bound: Option<u32>,
}

impl SproutJournalEntry {
    /// A mature observation becomes redundant only after the same canonical
    /// block has been durably observed in two mature reconciliation rounds.
    /// Record maturity regressions too, so old evidence cannot bridge them.
    pub(crate) fn mined_observation_is_redundant(&self, observation: &TxObservation) -> bool {
        let signature = mature_mined_signature(observation);
        if signature.is_none() {
            return self
                .observation
                .as_ref()
                .and_then(mature_mined_signature)
                .is_none();
        }
        let mut latest = self.observations.iter().rev();
        latest.next().and_then(mature_mined_signature) == signature
            && latest.next().and_then(mature_mined_signature) == signature
    }

    pub fn txid(&self) -> TxId {
        self.transaction
            .as_ref()
            .map(|tx| tx.txid)
            .or(self.legacy_txid)
            .expect("journal entry has transaction identity")
    }
}

#[derive(Debug, Clone, Default)]
pub struct SproutJournalSnapshot {
    by_note: HashMap<SproutNoteId, SproutJournalEntry>,
    by_txid: HashMap<TxId, SproutNoteId>,
    seen_transactions: HashMap<TxId, (SproutNoteId, u64, PreparedTransaction)>,
    order: Vec<SproutNoteId>,
    checkpoint_manifests: HashMap<CheckpointGeneration, CheckpointManifest>,
    discard_started: HashSet<CheckpointGeneration>,
    discarded_checkpoints: HashSet<CheckpointGeneration>,
    /// Expired or rejected transactions a later plan replaced, in the order
    /// they were replaced. Kept so the old txid stays visible to the user;
    /// never indexed by txid, so no transition can reach them.
    superseded: Vec<SproutJournalEntry>,
}

impl SproutJournalSnapshot {
    pub fn entry_for_note(&self, outpoint: &JsOutPoint) -> Option<&SproutJournalEntry> {
        self.by_note.get(&note_id(outpoint))
    }

    pub fn entry_for_txid(&self, txid: TxId) -> Option<&SproutJournalEntry> {
        self.by_txid.get(&txid).and_then(|id| self.by_note.get(id))
    }

    pub fn entries(&self) -> impl Iterator<Item = &SproutJournalEntry> {
        self.order.iter().filter_map(|id| self.by_note.get(id))
    }

    pub fn entries_in_journal_order(&self) -> impl Iterator<Item = &SproutJournalEntry> {
        self.entries()
    }

    /// Transactions replaced by a later plan for the same note. Their state
    /// is final (Expired or Rejected) and their value is never counted.
    pub fn superseded_entries(&self) -> impl Iterator<Item = &SproutJournalEntry> {
        self.superseded.iter()
    }

    pub fn ready_for_new_plan(&self, outpoint: &JsOutPoint) -> bool {
        let id = note_id(outpoint);
        if self
            .checkpoint_manifests
            .iter()
            .any(|(generation, manifest)| {
                self.discarded_checkpoints.contains(generation) && manifest.note_ids.contains(&id)
            })
        {
            return false;
        }
        self.ready_for_new_plan_with_restored_source(outpoint)
    }

    /// A caller holding the recovered spendable note is itself proof that
    /// source authority was restored after checkpoint cleanup. The journal
    /// alone deliberately cannot make this decision after a reorg.
    pub fn ready_for_new_plan_with_restored_source(&self, outpoint: &JsOutPoint) -> bool {
        self.entry_for_note(outpoint).is_none_or(|entry| {
            matches!(
                entry.state,
                TxLifecycleState::Expired | TxLifecycleState::Rejected
            )
        })
    }

    pub fn all_mined_for<'a>(&self, outpoints: impl IntoIterator<Item = &'a JsOutPoint>) -> bool {
        outpoints.into_iter().all(|outpoint| {
            self.entry_for_note(outpoint).is_some_and(|entry| {
                entry.state == TxLifecycleState::Mined
                    && entry
                        .observation
                        .as_ref()
                        .is_some_and(TxObservation::has_canonical_mined_evidence)
            })
        })
    }

    pub fn checkpoint_manifest(
        &self,
        generation: &CheckpointGeneration,
    ) -> Option<&CheckpointManifest> {
        self.checkpoint_manifests.get(generation)
    }

    pub fn checkpoint_was_discarded(&self, generation: &CheckpointGeneration) -> bool {
        self.discarded_checkpoints.contains(generation)
    }

    /// A spend-capable checkpoint is discarded only after two separate
    /// reconciliation rounds each carry a mature, independently administered
    /// canonical mined pair for every source note. This deliberately exceeds
    /// ordinary "mined" display semantics: the first sighting never deletes
    /// the only recovery material.
    pub fn checkpoint_cleanup_eligibility(
        &self,
        source_fingerprint: &str,
        generation: &CheckpointGeneration,
        current_source_notes: &BTreeSet<SproutNoteId>,
    ) -> CheckpointCleanupEligibility {
        let retain = |reason: &str| CheckpointCleanupEligibility::Retain {
            reason: reason.to_owned(),
        };
        let Some(manifest) = self.checkpoint_manifests.get(generation) else {
            return retain("the exact checkpoint generation has no durable manifest");
        };
        if manifest.source_fingerprint != source_fingerprint {
            return retain("the checkpoint manifest belongs to another key source");
        }
        if manifest.note_ids.is_empty() {
            return retain("the checkpoint manifest is empty");
        }
        if current_source_notes != &manifest.note_ids {
            return retain("the current checkpoint notes differ from its durable manifest");
        }
        let mut txids = Vec::with_capacity(manifest.note_ids.len());
        for id in &manifest.note_ids {
            let Some(entry) = self.by_note.get(id) else {
                return retain("a manifested checkpoint note has no journal entry");
            };
            if entry.source_fingerprint != source_fingerprint
                || entry.state != TxLifecycleState::Mined
            {
                return retain("a manifested checkpoint note is not currently mined");
            }
            if entry.transaction.is_none() {
                return retain(
                    "a legacy acceptance has no prepared transaction and cannot authorize cleanup",
                );
            }
            let newest = entry
                .observations
                .iter()
                .rev()
                .take(2)
                .map(mature_mined_signature)
                .collect::<Option<Vec<_>>>();
            if newest
                .as_ref()
                .is_none_or(|rounds| rounds.len() != 2 || rounds[0] != rounds[1])
            {
                return retain(
                    "canonical mining has not survived two mature reconciliation rounds",
                );
            }
            txids.push(entry.txid().to_string());
        }
        txids.sort();
        txids.dedup();
        CheckpointCleanupEligibility::Eligible { mined_txids: txids }
    }

    fn apply(&mut self, record: SproutJournalRecord, fingerprint: &str) -> ZeckResult<()> {
        match record {
            SproutJournalRecord::Header { .. } => Err(journal_error("unexpected journal header")),
            SproutJournalRecord::Prepared {
                note_id,
                value_zatoshis,
                transaction,
            } => {
                let tx = transaction.into_prepared()?;
                if let Some((seen_note, seen_value, seen_tx)) = self.seen_transactions.get(&tx.txid)
                {
                    if *seen_note != note_id || *seen_value != value_zatoshis || seen_tx != &tx {
                        return Err(journal_error(format!(
                            "immutable metadata changed for transaction {}",
                            tx.txid
                        )));
                    }
                    return if self
                        .by_note
                        .get(&note_id)
                        .is_some_and(|entry| entry.transaction.as_ref() == Some(&tx))
                    {
                        Ok(())
                    } else {
                        Err(journal_error(
                            "superseded transaction cannot be prepared again",
                        ))
                    };
                }
                if self
                    .by_txid
                    .get(&tx.txid)
                    .is_some_and(|existing| *existing != note_id)
                {
                    return Err(journal_error(format!(
                        "transaction {} claims a second note",
                        tx.txid
                    )));
                }
                if let Some(existing) = self.by_note.get(&note_id) {
                    if !matches!(
                        existing.state,
                        TxLifecycleState::Expired | TxLifecycleState::Rejected
                    ) {
                        return Err(journal_error(
                            "conflicting prepared transaction for active note",
                        ));
                    }
                    let replaced = existing.clone();
                    self.by_txid.remove(&replaced.txid());
                    self.order.retain(|existing| *existing != note_id);
                    self.superseded.push(replaced);
                }
                self.seen_transactions
                    .insert(tx.txid, (note_id, value_zatoshis, tx.clone()));
                self.by_txid.insert(tx.txid, note_id);
                self.order.push(note_id);
                self.by_note.insert(
                    note_id,
                    SproutJournalEntry {
                        outpoint: outpoint(note_id),
                        source_fingerprint: fingerprint.to_owned(),
                        transaction: Some(tx),
                        legacy_txid: None,
                        value_zatoshis: Some(value_zatoshis),
                        state: TxLifecycleState::NotSubmitted,
                        last_submission: None,
                        observation: None,
                        observations: Vec::new(),
                        legacy_expiry_bound: None,
                    },
                );
                Ok(())
            }
            SproutJournalRecord::Transition {
                txid,
                state,
                submission,
                observation,
            } => {
                let txid = decode_txid(&txid)?;
                let id = *self
                    .by_txid
                    .get(&txid)
                    .ok_or_else(|| journal_error("transition before preparation"))?;
                let entry = self.by_note.get_mut(&id).expect("indexed note exists");
                if let Some(prepared) = entry.transaction.as_ref() {
                    let persisted = PersistedTransaction {
                        prepared: prepared.clone(),
                        state: entry.state,
                        last_submission: entry.last_submission.clone(),
                        observation: entry.observation.clone(),
                    };
                    validate_transition(
                        &persisted,
                        state,
                        submission.as_ref(),
                        observation.as_ref(),
                        false,
                    )?;
                } else {
                    // A v1 acceptance has no raw bytes or expiry. It follows
                    // the same evidence policy as a v2 record: corroborated
                    // mining for Mined, one operator for MinedSingleSource,
                    // absence past the derived expiry bound for Expired, and
                    // only a positive reorg, absence, or mempool sighting
                    // demotes a mined record back to Pending.
                    use crate::broadcast::TxObservationState as Seen;
                    let seen = observation.as_ref().map(|o| &o.state);
                    let final_state = matches!(
                        entry.state,
                        TxLifecycleState::Expired | TxLifecycleState::Rejected
                    );
                    match state {
                        TxLifecycleState::SubmissionUnknown if !entry.state.is_mined() => {}
                        TxLifecycleState::Mined
                            if !final_state
                                && observation
                                    .as_ref()
                                    .is_some_and(TxObservation::has_canonical_mined_evidence) => {}
                        TxLifecycleState::MinedSingleSource
                            if !final_state
                                && entry.state != TxLifecycleState::Mined
                                && observation.as_ref().is_some_and(
                                    TxObservation::has_single_source_mined_evidence,
                                ) => {}
                        TxLifecycleState::Expired
                            if observation.as_ref().is_some_and(TxObservation::is_expired)
                                && entry.legacy_expiry_bound.is_some_and(|bound| {
                                    observation.as_ref().and_then(|o| o.expiry_height)
                                        == Some(bound)
                                }) => {}
                        TxLifecycleState::Pending
                            if !final_state
                                && if entry.state.is_mined() {
                                    matches!(
                                        seen,
                                        Some(Seen::Reorged | Seen::Absent | Seen::PresentUnmined)
                                    )
                                } else {
                                    !matches!(seen, Some(Seen::Mined | Seen::MinedSingleSource))
                                } => {}
                        _ => {
                            return Err(journal_error(
                                "legacy transaction lacks evidence for transition",
                            ))
                        }
                    }
                }
                entry.state = state;
                if let Some(submission) = submission {
                    entry.last_submission = Some(submission);
                }
                if let Some(observation) = observation {
                    entry.observations.push(observation.clone());
                    entry.observation = Some(observation);
                }
                Ok(())
            }
            SproutJournalRecord::CleanupEvidenceInvalidated { txid } => {
                let txid = decode_txid(&txid)?;
                let id = self.by_txid.get(&txid).ok_or_else(|| {
                    journal_error("cleanup evidence invalidation before preparation")
                })?;
                let entry = self.by_note.get_mut(id).expect("indexed note exists");
                if entry.state != TxLifecycleState::Mined {
                    return Err(journal_error(
                        "cleanup evidence invalidation requires a recorded mined fact",
                    ));
                }
                // Keep lifecycle, displayed canonical evidence and exact retry
                // bytes. Only the authority to discard recovery material resets.
                entry.observations.clear();
                Ok(())
            }
            SproutJournalRecord::LegacyAccepted { note_id, txid } => {
                let txid = decode_txid(&txid)?;
                if self
                    .by_txid
                    .get(&txid)
                    .is_some_and(|existing| *existing != note_id)
                {
                    return Err(journal_error("legacy transaction claims a second note"));
                }
                if let Some(existing) = self.by_note.get(&note_id) {
                    return if existing.legacy_txid == Some(txid) {
                        Ok(())
                    } else {
                        Err(journal_error("conflicting legacy transaction for note"))
                    };
                }
                self.by_txid.insert(txid, note_id);
                self.order.push(note_id);
                self.by_note.insert(
                    note_id,
                    SproutJournalEntry {
                        outpoint: outpoint(note_id),
                        source_fingerprint: fingerprint.to_owned(),
                        transaction: None,
                        legacy_txid: Some(txid),
                        value_zatoshis: None,
                        // v1 recorded only that a node accepted the bytes:
                        // in flight, never final, and not a reason to stop
                        // the other notes.
                        state: TxLifecycleState::Pending,
                        last_submission: None,
                        observation: None,
                        observations: Vec::new(),
                        legacy_expiry_bound: None,
                    },
                );
                Ok(())
            }
            SproutJournalRecord::LegacyExpiryBound {
                txid,
                verified_tip,
                expiry_bound,
            } => {
                let txid = decode_txid(&txid)?;
                let id = *self
                    .by_txid
                    .get(&txid)
                    .ok_or_else(|| journal_error("expiry bound without legacy entry"))?;
                let entry = self.by_note.get_mut(&id).expect("indexed note exists");
                if entry.transaction.is_some()
                    || verified_tip.checked_add(SPROUT_EXPIRY_DELTA) != Some(expiry_bound)
                    || entry
                        .legacy_expiry_bound
                        .is_some_and(|old| old != expiry_bound)
                {
                    return Err(journal_error("invalid legacy expiry bound"));
                }
                entry.legacy_expiry_bound = Some(expiry_bound);
                Ok(())
            }
            SproutJournalRecord::CheckpointManifest {
                source_fingerprint,
                generation,
                note_ids,
            } => {
                if source_fingerprint != fingerprint || note_ids.is_empty() {
                    return Err(journal_error(
                        "checkpoint manifest is empty or belongs to another source",
                    ));
                }
                let manifest = self
                    .checkpoint_manifests
                    .entry(generation.clone())
                    .or_insert_with(|| CheckpointManifest {
                        source_fingerprint: source_fingerprint.clone(),
                        generation,
                        note_ids: BTreeSet::new(),
                    });
                if manifest.source_fingerprint != source_fingerprint {
                    return Err(journal_error("checkpoint manifest identity changed"));
                }
                // Records are monotonic: a later proposal may discover more
                // notes, but can never remove an earlier source member.
                manifest.note_ids.extend(note_ids);
                Ok(())
            }
            SproutJournalRecord::CheckpointDiscardStarted {
                source_fingerprint,
                generation,
                reorg_window,
            } => {
                if source_fingerprint != fingerprint
                    || !self.checkpoint_manifests.contains_key(&generation)
                    || reorg_window != u32::try_from(SPROUT_REORG_WINDOW).unwrap_or(u32::MAX)
                {
                    return Err(journal_error("checkpoint discard marker has no manifest"));
                }
                self.discard_started.insert(generation);
                Ok(())
            }
            SproutJournalRecord::CheckpointDiscarded {
                source_fingerprint,
                generation,
            } => {
                if source_fingerprint != fingerprint || !self.discard_started.contains(&generation)
                {
                    return Err(journal_error(
                        "checkpoint discard completion has no synced start marker",
                    ));
                }
                self.discarded_checkpoints.insert(generation);
                Ok(())
            }
            SproutJournalRecord::CheckpointTombstone {
                source_fingerprint,
                generation,
                reorg_window,
                note_id,
                value_zatoshis,
                transaction,
                state,
                last_submission,
                observations,
            } => {
                let window = u32::try_from(SPROUT_REORG_WINDOW)
                    .map_err(|_| journal_error("Sprout reorg window does not fit u32"))?;
                if source_fingerprint != fingerprint
                    || reorg_window != window
                    || state != TxLifecycleState::Mined
                    || !self.discard_started.contains(&generation)
                    || !self
                        .checkpoint_manifests
                        .get(&generation)
                        .is_some_and(|manifest| manifest.note_ids.contains(&note_id))
                {
                    return Err(journal_error("invalid checkpoint tombstone authority"));
                }
                let newest = observations
                    .iter()
                    .rev()
                    .take(2)
                    .map(mature_mined_signature)
                    .collect::<Option<Vec<_>>>();
                if newest
                    .as_ref()
                    .is_none_or(|rounds| rounds.len() != 2 || rounds[0] != rounds[1])
                {
                    return Err(journal_error("checkpoint tombstone is not mature"));
                }
                let tx = transaction.into_prepared()?;
                if self
                    .by_txid
                    .get(&tx.txid)
                    .is_some_and(|existing| *existing != note_id)
                {
                    return Err(journal_error(
                        "checkpoint tombstone conflicts with journal state",
                    ));
                }
                if let Some(existing) = self.by_note.get(&note_id) {
                    if existing.source_fingerprint != source_fingerprint
                        || existing.transaction.as_ref() != Some(&tx)
                        || existing.value_zatoshis != Some(value_zatoshis)
                        || existing.state != state
                        || existing.last_submission != last_submission
                        || existing.observations != observations
                    {
                        return Err(journal_error(
                            "checkpoint tombstone conflicts with journal state",
                        ));
                    }
                    return Ok(());
                }
                self.seen_transactions
                    .insert(tx.txid, (note_id, value_zatoshis, tx.clone()));
                self.by_txid.insert(tx.txid, note_id);
                self.order.push(note_id);
                self.by_note.insert(
                    note_id,
                    SproutJournalEntry {
                        outpoint: outpoint(note_id),
                        source_fingerprint,
                        transaction: Some(tx),
                        legacy_txid: None,
                        value_zatoshis: Some(value_zatoshis),
                        state,
                        last_submission,
                        observation: observations.last().cloned(),
                        observations,
                        legacy_expiry_bound: None,
                    },
                );
                Ok(())
            }
        }
    }
}

fn mature_mined_signature(observation: &TxObservation) -> Option<(u32, Vec<u8>)> {
    if !observation.has_canonical_mined_evidence() {
        return None;
    }
    let height = observation.mined_height?;
    let mature_tip = height.checked_add(u32::try_from(SPROUT_REORG_WINDOW).ok()?)?;
    let claims = observation
        .evidence
        .iter()
        .filter(|item| {
            item.tx_in_block
                && item.reported_height == Some(height)
                && item.tip_height.is_some_and(|tip| tip >= mature_tip)
                && item
                    .block_hash
                    .as_ref()
                    .is_some_and(|hash| hash.len() == 32)
        })
        .collect::<Vec<_>>();
    for (index, first) in claims.iter().enumerate() {
        for second in claims.iter().skip(index + 1) {
            let first_operator = crate::models::canonical_confirmation_operator_id(
                &first.operator_id,
                &first.endpoint,
            );
            let second_operator = crate::models::canonical_confirmation_operator_id(
                &second.operator_id,
                &second.endpoint,
            );
            let independent = !first_operator.is_empty()
                && !second_operator.is_empty()
                && first_operator != second_operator
                && crate::models::normalized_confirmation_authority(&first.endpoint).is_some()
                && crate::models::normalized_confirmation_authority(&second.endpoint).is_some()
                && crate::models::normalized_confirmation_authority(&first.endpoint)
                    != crate::models::normalized_confirmation_authority(&second.endpoint);
            if independent && first.block_hash == second.block_hash {
                return Some((height, first.block_hash.clone()?));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct JournalNoteContext {
    pub outpoint: JsOutPoint,
    pub value_zatoshis: u64,
}

/// Extract only syntactically valid transaction IDs from known legacy record
/// shapes. These are investigation leads, never authenticated spend history.
fn legacy_recorded_txids(bytes: &[u8]) -> Option<BTreeSet<String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut txids = BTreeSet::new();
    for line in text.lines() {
        let candidate = if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
            match record.get("record").and_then(serde_json::Value::as_str) {
                Some("prepared" | "checkpoint_tombstone") => record
                    .get("transaction")
                    .and_then(|transaction| transaction.get("txid"))
                    .and_then(serde_json::Value::as_str),
                Some(
                    "transition"
                    | "legacy_accepted"
                    | "legacy_expiry_bound"
                    | "cleanup_evidence_invalidated",
                ) => record.get("txid").and_then(serde_json::Value::as_str),
                _ => None,
            }
            .map(str::to_owned)
        } else {
            let fields = line.split_whitespace().take(3).collect::<Vec<_>>();
            if fields.len() != 2 {
                continue;
            }
            let note = fields[0].split(':').take(4).collect::<Vec<_>>();
            if note.len() != 3
                || decode_txid(note[0]).is_err()
                || note[1].parse::<u64>().is_err()
                || !matches!(note[2].parse::<u8>(), Ok(0 | 1))
            {
                continue;
            }
            Some(fields[1].to_owned())
        };
        if let Some(txid) = candidate.and_then(|candidate| decode_txid(&candidate).ok()) {
            txids.insert(txid.to_string());
        }
    }
    Some(txids)
}

#[derive(Debug)]
pub struct SweepJournal {
    data_dir: PathBuf,
    path: PathBuf,
    root: PathBuf,
    purpose: Vec<u8>,
    network: ZeckNetwork,
    source_fingerprint: String,
    retained_root: Option<std::sync::Weak<crate::private_fs::PrivateArtifactRootLease>>,
    retained_namespace: Option<std::sync::Weak<crate::private_fs::NamespaceLease>>,
}

impl SweepJournal {
    pub fn for_keys(data_dir: &Path, spending_keys: &[[u8; 32]], network: ZeckNetwork) -> Self {
        let short = key_set_fingerprint(spending_keys);
        let source_fingerprint = full_key_set_fingerprint(spending_keys);
        let purpose =
            crate::private_fs::private_artifact_purpose(network.label(), &source_fingerprint);
        let root = crate::private_fs::private_artifact_root_path(data_dir, &purpose);
        Self {
            data_dir: data_dir.to_path_buf(),
            path: root.join(format!("sprout-sweep-{short}.journal")),
            root,
            purpose,
            network,
            source_fingerprint,
            retained_root: None,
            retained_namespace: None,
        }
    }

    fn artifact_access(&self) -> ZeckResult<crate::private_fs::PrivateArtifactAccess> {
        let retained = self
            .retained_root
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .zip(
                self.retained_namespace
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade),
            );
        self.reject_direct_legacy_journals(retained.as_ref().map(|(root, _)| root.as_ref()))?;
        let access = match retained {
            Some((root, namespace)) => {
                crate::private_fs::PrivateArtifactAccess::acquire_from_retained_root(
                    root,
                    &namespace,
                    &self.purpose,
                    crate::private_fs::PrivateArtifactDomain::Journal,
                    &self.path,
                )
            }
            None => crate::private_fs::PrivateArtifactAccess::acquire(
                &self.root,
                &self.purpose,
                crate::private_fs::PrivateArtifactDomain::Journal,
                &self.path,
            ),
        };
        access.map_err(|error| {
            journal_error(format!("opening private Sprout journal authority: {error}"))
        })
    }

    fn artifact_access_bound_to_checkpoint(
        &self,
        lease: &crate::sprout_scan_run::CheckpointLease,
    ) -> ZeckResult<crate::private_fs::PrivateArtifactAccess> {
        let root = lease.clone_artifact_root();
        let namespace = lease.clone_namespace();
        self.reject_direct_legacy_journals(Some(&root))?;
        crate::private_fs::PrivateArtifactAccess::acquire_from_retained_root(
            root,
            &namespace,
            &self.purpose,
            crate::private_fs::PrivateArtifactDomain::Journal,
            &self.path,
        )
        .map_err(|error| {
            journal_error(format!(
                "opening checkpoint-bound private Sprout journal authority: {error}"
            ))
        })
    }

    fn reject_direct_legacy_journals(
        &self,
        retained_root: Option<&crate::private_fs::PrivateArtifactRootLease>,
    ) -> ZeckResult<()> {
        let names = match retained_root {
            Some(root) => root.publication_parent_child_names(),
            None => crate::private_fs::private_data_dir_child_names(&self.data_dir),
        }
        .map_err(|err| {
            journal_error(format!(
                "cannot verify the data directory for legacy Sprout journals {}: {err}",
                self.data_dir.display()
            ))
        })?;
        let mut names = names;
        names.sort();
        let mut diagnostics = Vec::new();
        for name in names {
            let text = name.to_string_lossy();
            if text.starts_with("sprout-sweep-") && text.ends_with(".journal") {
                let path = self.data_dir.join(name);
                // Legacy contents have no create-time authority. Read only a
                // bounded, pinned, no-follow private file for diagnostics; no
                // bytes enter the lifecycle snapshot or submission path.
                const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024 * 1024;
                let diagnostic = match crate::private_fs::read_direct_legacy_journal_diagnostic(
                    &self.data_dir,
                    retained_root,
                    &path,
                    MAX_DIAGNOSTIC_BYTES,
                ) {
                    Ok(bytes) => match legacy_recorded_txids(&bytes) {
                        Some(txids) if !txids.is_empty() => format!(
                            "read-only diagnostic, syntactically valid recorded txids (untrusted): {}",
                            txids.into_iter().collect::<Vec<_>>().join(", ")
                        ),
                        _ => "read-only diagnostic found no valid recorded txids; manual inspection of the original history is required".to_owned(),
                    },
                    Err(error) => format!(
                        "read-only diagnostic unavailable: {error}; inspect the original history manually without following links or substituting another file"
                    ),
                };
                diagnostics.push(format!("{}: {diagnostic}", path.display()));
            }
        }
        if diagnostics.is_empty() {
            return Ok(());
        }
        Err(journal_error(format!(
            "legacy direct Sprout journal history lacks create-time authority and blocks sweeping; files preserved unchanged. {}. IDs are untrusted and may be incomplete. Independently reconcile every txid and all ambiguous history; not-found alone is not settlement. After every possible spend is independently settled, preserve a private backup, move the listed journals outside this data directory, and rescan the original wallet or keys before sweeping",
            diagnostics.join("; ")
        )))
    }

    pub(crate) fn bind_checkpoint_namespace(
        &mut self,
        lease: &crate::sprout_scan_run::CheckpointLease,
    ) -> ZeckResult<()> {
        let namespace = lease.clone_namespace();
        let root = lease.clone_artifact_root();
        let parent = self
            .path
            .parent()
            .ok_or_else(|| journal_error("Sprout journal has no data directory"))?;
        if namespace.parent_path() != parent {
            return Err(journal_error(
                "checkpoint authority does not bind the sweep journal namespace",
            ));
        }
        self.retained_root = Some(std::sync::Arc::downgrade(&root));
        self.retained_namespace = Some(std::sync::Arc::downgrade(&namespace));
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    fn header(
        &self,
        authority_anchor: [u8; 16],
        artifact_generation: [u8; 16],
    ) -> SproutJournalRecord {
        SproutJournalRecord::Header {
            version: SPROUT_SWEEP_JOURNAL_VERSION,
            network: self.network,
            source_fingerprint: self.source_fingerprint.clone(),
            authority_anchor,
            artifact_generation,
        }
    }

    pub fn load_or_migrate(&self) -> ZeckResult<SproutJournalSnapshot> {
        let access = self.artifact_access()?;
        with_sweep_journal_lock(&self.path, Some(access.namespace()), |namespace| {
            self.load_or_migrate_unlocked(namespace, &access)
        })
    }

    /// Load this key set's journal and reject any sibling journal that also
    /// claims a note protected by this invocation. The process-wide network
    /// operation guard serializes current Argos writers; each sibling's own
    /// journal lock serializes its read with older per-journal writers.
    /// Binaries predating the network guard cannot be made to honor it, so a
    /// later execution repeats this check immediately before reconciliation.
    pub fn load_scoped_snapshot(
        &self,
        invocation_outpoints: &[JsOutPoint],
    ) -> ZeckResult<SproutJournalSnapshot> {
        let access = self.artifact_access()?;
        let snapshot =
            with_sweep_journal_lock(&self.path, Some(access.namespace()), |namespace| {
                self.load_or_migrate_unlocked(namespace, &access)
            })?;
        let mut protected = invocation_outpoints
            .iter()
            .map(note_id)
            .collect::<HashSet<_>>();
        protected.extend(snapshot.entries().map(|entry| note_id(&entry.outpoint)));
        drop(access);
        self.reject_overlapping_siblings(&protected)?;
        Ok(snapshot)
    }

    fn reject_overlapping_siblings(&self, protected: &HashSet<SproutNoteId>) -> ZeckResult<()> {
        let retained_root = self
            .retained_root
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        self.reject_direct_legacy_journals(retained_root.as_deref())?;
        let roots = match retained_root {
            Some(root) => root.discover_sibling_roots(),
            None => crate::private_fs::discover_private_artifact_roots_except(
                &self.data_dir,
                Some(&self.root),
            ),
        }
        .map_err(|err| journal_error(format!("discovering private Sprout journals: {err}")))?;
        for root in roots {
            let mut journal_child = None;
            for name in root.child_names().map_err(|err| {
                journal_error(format!(
                    "reading private artifact root {}: {err}",
                    root.path().display()
                ))
            })? {
                let path = root.path().join(name);
                let Some(short) = sibling_journal_short_name(&path)? else {
                    continue;
                };
                if journal_child.replace((path, short)).is_some() {
                    return Err(journal_error(format!(
                        "private artifact root {} contains multiple Sprout journals",
                        root.path().display()
                    )));
                }
            }
            let Some((path, short)) = journal_child else {
                continue;
            };
            let sibling_purpose = root.purpose().to_vec();
            let access = crate::private_fs::PrivateArtifactAccess::acquire_from_verified_root(
                root,
                &sibling_purpose,
                crate::private_fs::PrivateArtifactDomain::Journal,
                &path,
            )
            .map_err(|err| {
                journal_error(format!(
                    "cannot authenticate sibling Sprout journal {}: {err}",
                    path.display()
                ))
            })?;
            let (network, sibling) =
                with_sweep_journal_lock(&path, Some(access.namespace()), |_| {
                    inspect_authorized_sibling_journal(&access, &path, &short)
                })
                .map_err(|err| {
                    journal_error(format!(
                        "cannot safely inspect sibling Sprout journal {}: {err}",
                        path.display()
                    ))
                })?;
            if network.is_some_and(|network| network != self.network) {
                continue;
            }
            let overlapping_outpoint = sibling
                .entries()
                .find(|entry| protected.contains(&note_id(&entry.outpoint)))
                .map(|entry| entry.outpoint);
            if let Some(overlapping_outpoint) = overlapping_outpoint {
                let id = note_id(&overlapping_outpoint);
                let txid =
                    id.0.iter()
                        .rev()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                return Err(journal_error(format!(
                    "Sprout journal overlap for {txid}:{}:{} between {} and {}. Preserve the original key set and data dir; recover or reconcile that journal identity before sweeping.",
                    id.1,
                    id.2,
                    self.path.display(),
                    path.display()
                )));
            }
        }
        Ok(())
    }

    fn load_or_migrate_unlocked(
        &self,
        namespace: &NamespaceLease,
        access: &crate::private_fs::PrivateArtifactAccess,
    ) -> ZeckResult<SproutJournalSnapshot> {
        let (bytes, object_id) = match access.read_optional_child_version() {
            Ok(Some(version)) => version,
            Ok(None) => return Ok(SproutJournalSnapshot::default()),
            Err(err) => {
                return Err(journal_error(format!(
                    "reading {}: {err}",
                    self.path.display()
                )))
            }
        };
        if bytes.is_empty() {
            return Ok(SproutJournalSnapshot::default());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| journal_error("journal is not UTF-8"))?;
        let first = text.lines().next().unwrap_or_default();
        if !first.starts_with('{') {
            return Err(journal_error(
                "legacy journal content has no mandatory v4 lineage boundary; preserve it unchanged for explicit reconciliation",
            ));
        }
        let (authority_anchor, state) = access
            .current_authority()
            .map_err(|err| journal_error(format!("reading journal lineage authority: {err}")))?
            .ok_or_else(|| journal_error("journal lineage authority is missing"))?;
        let artifact_generation = match state {
            crate::private_fs::PrivateArtifactState::Active { generation, object }
                if object == object_id =>
            {
                generation
            }
            _ => {
                return Err(journal_error(
                    "journal lineage authority is not active for its exact object",
                ))
            }
        };
        self.load_v2(
            namespace,
            &object_id,
            &bytes,
            authority_anchor,
            artifact_generation,
        )
    }

    fn load_v2(
        &self,
        namespace: &NamespaceLease,
        object_id: &PrivateObjectId,
        bytes: &[u8],
        expected_anchor: [u8; 16],
        expected_generation: [u8; 16],
    ) -> ZeckResult<SproutJournalSnapshot> {
        let mut complete = bytes.split(|byte| *byte == b'\n');
        let header = complete
            .next()
            .ok_or_else(|| journal_error("missing journal header"))?;
        if !bytes.contains(&b'\n') {
            return Err(journal_error("unterminated journal header"));
        }
        match serde_json::from_slice::<SproutJournalRecord>(header)
            .map_err(|err| journal_error(format!("invalid journal header: {err}")))?
        {
            SproutJournalRecord::Header {
                version,
                network,
                source_fingerprint,
                authority_anchor,
                artifact_generation,
            } if version == SPROUT_SWEEP_JOURNAL_VERSION
                && network == self.network
                && source_fingerprint == self.source_fingerprint
                && authority_anchor == expected_anchor
                && artifact_generation == expected_generation => {}
            _ => {
                return Err(journal_error(
                    "journal version, network, or source fingerprint mismatch",
                ))
            }
        }
        let mut snapshot = SproutJournalSnapshot::default();
        let mut remaining = complete.peekable();
        while let Some(line) = remaining.next() {
            if remaining.peek().is_none() && !bytes.ends_with(b"\n") {
                break;
            }
            if line.is_empty() {
                if remaining.peek().is_none() {
                    break;
                }
                return Err(journal_error("empty complete journal record"));
            }
            let record = serde_json::from_slice(line).map_err(|err| {
                journal_error(format!("malformed complete journal record: {err}"))
            })?;
            snapshot.apply(record, &self.source_fingerprint)?;
        }
        if !bytes.ends_with(b"\n") {
            let _ = (namespace, object_id);
            return Err(journal_error(
                "journal has an incomplete trailing record; preserve it for review",
            ));
        }
        Ok(snapshot)
    }

    fn append_unlocked(
        &self,
        _namespace: &NamespaceLease,
        access: &crate::private_fs::PrivateArtifactAccess,
        record: &SproutJournalRecord,
    ) -> ZeckResult<()> {
        let version = access
            .read_optional_child_version()
            .map_err(|err| journal_error(format!("opening journal: {err}")))?;
        let write_header = version.as_ref().is_none_or(|(bytes, _)| bytes.is_empty());
        access
            .append_child_if_unchanged_with_lineage(
                version.as_ref().map(|(bytes, id)| (id, bytes.as_slice())),
                |authority_anchor, artifact_generation| {
                    let mut suffix = Vec::new();
                    if write_header {
                        serde_json::to_writer(
                            &mut suffix,
                            &self.header(authority_anchor, artifact_generation),
                        )
                        .map_err(std::io::Error::other)?;
                        suffix.push(b'\n');
                    }
                    serde_json::to_writer(&mut suffix, record).map_err(std::io::Error::other)?;
                    suffix.push(b'\n');
                    Ok(suffix)
                },
            )
            .map_err(|err| journal_error(format!("syncing journal event: {err}")))
    }

    pub fn scoped_store<'a>(
        &'a self,
        note: JournalNoteContext,
        snapshot: &'a mut SproutJournalSnapshot,
    ) -> SproutBroadcastStore<'a> {
        SproutBroadcastStore {
            journal: self,
            note,
            snapshot,
        }
    }

    fn mutate(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        record: SproutJournalRecord,
    ) -> ZeckResult<()> {
        let access = self.artifact_access()?;
        with_sweep_journal_lock(&self.path, Some(access.namespace()), |namespace| {
            let mut durable = self.load_or_migrate_unlocked(namespace, &access)?;
            *snapshot = durable.clone();
            // Decide under the journal lock using fresh durable state, so a
            // stale caller cannot skip invalidating newly appended evidence.
            let redundant_invalidation = match &record {
                SproutJournalRecord::CleanupEvidenceInvalidated { txid } => durable
                    .entry_for_txid(decode_txid(txid)?)
                    .is_some_and(|entry| entry.observations.is_empty()),
                _ => false,
            };
            durable.apply(record.clone(), &self.source_fingerprint)?;
            if !redundant_invalidation {
                self.append_unlocked(namespace, &access, &record)?;
            }
            *snapshot = durable;
            Ok(())
        })
    }

    /// Durably interrupt cleanup eligibility while preserving the known mined
    /// lifecycle fact. Repeating an already-invalidated round does not append.
    pub(crate) fn invalidate_cleanup_evidence(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        txid: TxId,
    ) -> ZeckResult<()> {
        self.mutate(
            snapshot,
            SproutJournalRecord::CleanupEvidenceInvalidated {
                txid: txid.to_string(),
            },
        )
    }

    pub fn append_transition(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        txid: TxId,
        state: TxLifecycleState,
        submission: Option<&SubmissionDisposition>,
        observation: Option<&TxObservation>,
    ) -> ZeckResult<()> {
        self.mutate(
            snapshot,
            SproutJournalRecord::Transition {
                txid: txid.to_string(),
                state,
                submission: submission.cloned(),
                observation: observation.cloned(),
            },
        )
    }

    pub fn append_legacy_expiry_bound(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        txid: TxId,
        verified_tip: u32,
        expiry_bound: u32,
    ) -> ZeckResult<()> {
        self.mutate(
            snapshot,
            SproutJournalRecord::LegacyExpiryBound {
                txid: txid.to_string(),
                verified_tip,
                expiry_bound,
            },
        )
    }

    pub fn record_checkpoint_manifest<'a>(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        generation: &CheckpointGeneration,
        notes: impl IntoIterator<Item = &'a JsOutPoint>,
    ) -> ZeckResult<()> {
        self.record_checkpoint_manifest_ids(
            snapshot,
            generation,
            notes.into_iter().map(note_id).collect(),
        )
    }

    pub fn record_checkpoint_manifest_ids(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        generation: &CheckpointGeneration,
        note_ids: BTreeSet<SproutNoteId>,
    ) -> ZeckResult<()> {
        if note_ids.is_empty() {
            return Err(journal_error("checkpoint manifest cannot be empty"));
        }
        self.mutate(
            snapshot,
            SproutJournalRecord::CheckpointManifest {
                source_fingerprint: self.source_fingerprint.clone(),
                generation: generation.clone(),
                note_ids,
            },
        )
    }

    fn compact_unlocked(
        &self,
        namespace: &NamespaceLease,
        access: &crate::private_fs::PrivateArtifactAccess,
        snapshot: &SproutJournalSnapshot,
        generation: &CheckpointGeneration,
    ) -> ZeckResult<()> {
        let manifest = snapshot
            .checkpoint_manifests
            .get(generation)
            .ok_or_else(|| journal_error("checkpoint has no manifest during compaction"))?;
        let reorg_window = u32::try_from(SPROUT_REORG_WINDOW)
            .map_err(|_| journal_error("Sprout reorg window does not fit u32"))?;
        for note_id in &manifest.note_ids {
            let entry = snapshot
                .by_note
                .get(note_id)
                .ok_or_else(|| journal_error("manifest entry disappeared during compaction"))?;
            let transaction = entry
                .transaction
                .as_ref()
                .ok_or_else(|| journal_error("legacy entry cannot become a tombstone"))?;
            let tombstone = SproutJournalRecord::CheckpointTombstone {
                source_fingerprint: self.source_fingerprint.clone(),
                generation: generation.clone(),
                reorg_window,
                note_id: *note_id,
                value_zatoshis: entry
                    .value_zatoshis
                    .ok_or_else(|| journal_error("tombstone has no source value"))?,
                transaction: JournalPreparedTransaction::from_prepared(transaction)?,
                state: entry.state,
                last_submission: entry.last_submission.clone(),
                observations: entry.observations.clone(),
            };
            self.append_unlocked(namespace, access, &tombstone)?;
        }
        Ok(())
    }

    pub fn finalize_checkpoint_cleanup(
        &self,
        lease: &crate::sprout_scan_run::CheckpointLease,
        generation: &CheckpointGeneration,
        checkpoint: &Path,
    ) -> ZeckResult<CheckpointCleanupResult> {
        let access = self.artifact_access_bound_to_checkpoint(lease)?;
        with_sweep_journal_lock(&self.path, Some(access.namespace()), |namespace| {
            lease.verify_for(checkpoint)?;
            let mut snapshot = self.load_or_migrate_unlocked(namespace, &access)?;
            match lease.generation_if_present(checkpoint)? {
                Some(current) if &current != generation => {
                    return Ok(CheckpointCleanupResult::Retain {
                        reason: "the checkpoint generation changed after review".into(),
                    });
                }
                Some(_) => {}
                None if snapshot.discard_started.contains(generation) => {}
                None => {
                    return Err(journal_error(
                        "checkpoint disappeared before cleanup was authorized",
                    ));
                }
            }
            let current_source_notes = snapshot
                .entries()
                .map(|entry| note_id(&entry.outpoint))
                .collect::<BTreeSet<_>>();
            match snapshot.checkpoint_cleanup_eligibility(
                &self.source_fingerprint,
                generation,
                &current_source_notes,
            ) {
                CheckpointCleanupEligibility::Retain { reason } => {
                    return Ok(CheckpointCleanupResult::Retain { reason });
                }
                CheckpointCleanupEligibility::Eligible { .. } => {}
            }
            if !snapshot.discard_started.contains(generation) {
                let marker = SproutJournalRecord::CheckpointDiscardStarted {
                    source_fingerprint: self.source_fingerprint.clone(),
                    generation: generation.clone(),
                    reorg_window: u32::try_from(SPROUT_REORG_WINDOW)
                        .map_err(|_| journal_error("Sprout reorg window does not fit u32"))?,
                };
                snapshot.apply(marker.clone(), &self.source_fingerprint)?;
                self.append_unlocked(namespace, &access, &marker)?;
            }
            self.compact_unlocked(namespace, &access, &snapshot, generation)?;
            let discarded = crate::sprout_scan_run::discard_checkpoint_generation_while_leased(
                lease, checkpoint, generation,
            )?;
            #[cfg(test)]
            if FAIL_AFTER_CHECKPOINT_DISCARD
                .lock()
                .unwrap()
                .remove(checkpoint)
            {
                return Err(journal_error(
                    "injected crash after checkpoint discard before completion",
                ));
            }
            if !snapshot.discarded_checkpoints.contains(generation) {
                let completed = SproutJournalRecord::CheckpointDiscarded {
                    source_fingerprint: self.source_fingerprint.clone(),
                    generation: generation.clone(),
                };
                snapshot.apply(completed.clone(), &self.source_fingerprint)?;
                self.append_unlocked(namespace, &access, &completed)?;
            }
            Ok(match discarded {
                crate::sprout_scan_run::CheckpointDiscard::Removed => {
                    CheckpointCleanupResult::Removed
                }
                crate::sprout_scan_run::CheckpointDiscard::AlreadyAbsent => {
                    CheckpointCleanupResult::AlreadyAbsent
                }
            })
        })
    }

    pub fn resume_checkpoint_cleanup(
        &self,
        lease: &crate::sprout_scan_run::CheckpointLease,
        checkpoint: &Path,
    ) -> ZeckResult<Option<CheckpointCleanupResult>> {
        let access = self.artifact_access_bound_to_checkpoint(lease)?;
        with_sweep_journal_lock(&self.path, Some(access.namespace()), |namespace| {
            lease.verify_for(checkpoint)?;
            let mut snapshot = self.load_or_migrate_unlocked(namespace, &access)?;
            let pending = snapshot
                .discard_started
                .iter()
                .filter(|generation| !snapshot.discarded_checkpoints.contains(*generation))
                .cloned()
                .collect::<Vec<_>>();
            if pending.is_empty() {
                return Ok(None);
            }
            if pending.len() != 1 {
                return Err(journal_error(
                    "multiple interrupted checkpoint discards require manual review",
                ));
            }
            let generation = &pending[0];
            if !snapshot.checkpoint_manifests.contains_key(generation) {
                return Err(journal_error("discard marker has no checkpoint manifest"));
            }
            if lease.restore_interrupted_retirement(checkpoint)? {
                return Ok(Some(CheckpointCleanupResult::Retain {
                    reason: "the exact checkpoint retirement was restored after restart; fresh reconciliation and review are required before cleanup".into(),
                }));
            }
            let current_generation = lease.generation_if_present(checkpoint)?;
            if current_generation.as_ref() == Some(generation) {
                return Ok(Some(CheckpointCleanupResult::Retain {
                    reason: "the exact checkpoint generation survived restart; fresh reconciliation and review are required before cleanup".into(),
                }));
            }
            let replacement_present = current_generation.is_some();
            let current_source_notes = snapshot
                .entries()
                .map(|entry| note_id(&entry.outpoint))
                .collect::<BTreeSet<_>>();
            match snapshot.checkpoint_cleanup_eligibility(
                &self.source_fingerprint,
                generation,
                &current_source_notes,
            ) {
                CheckpointCleanupEligibility::Retain { reason } => {
                    return Ok(Some(CheckpointCleanupResult::Retain { reason }));
                }
                CheckpointCleanupEligibility::Eligible { .. } => {}
            }
            self.compact_unlocked(namespace, &access, &snapshot, generation)?;
            if replacement_present {
                let completed = SproutJournalRecord::CheckpointDiscarded {
                    source_fingerprint: self.source_fingerprint.clone(),
                    generation: generation.clone(),
                };
                snapshot.apply(completed.clone(), &self.source_fingerprint)?;
                self.append_unlocked(namespace, &access, &completed)?;
                return Ok(Some(CheckpointCleanupResult::Retain {
                    reason: "a replacement checkpoint generation was preserved".into(),
                }));
            }
            let discarded = crate::sprout_scan_run::discard_checkpoint_generation_while_leased(
                lease, checkpoint, generation,
            )?;
            let completed = SproutJournalRecord::CheckpointDiscarded {
                source_fingerprint: self.source_fingerprint.clone(),
                generation: generation.clone(),
            };
            snapshot.apply(completed.clone(), &self.source_fingerprint)?;
            self.append_unlocked(namespace, &access, &completed)?;
            Ok(Some(match discarded {
                crate::sprout_scan_run::CheckpointDiscard::Removed => {
                    CheckpointCleanupResult::Removed
                }
                crate::sprout_scan_run::CheckpointDiscard::AlreadyAbsent => {
                    CheckpointCleanupResult::AlreadyAbsent
                }
            }))
        })
    }
}

fn sibling_journal_short_name(path: &Path) -> ZeckResult<Option<String>> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(journal_error(format!(
            "sibling journal path is not UTF-8: {}",
            path.display()
        )));
    };
    let Some(short) = name
        .strip_prefix("sprout-sweep-")
        .and_then(|name| name.strip_suffix(".journal"))
    else {
        return Ok(None);
    };
    if short.len() != 16
        || !short
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(journal_error(format!(
            "invalid sibling Sprout journal filename {}",
            path.display()
        )));
    }
    Ok(Some(short.to_owned()))
}

fn inspect_authorized_sibling_journal(
    access: &crate::private_fs::PrivateArtifactAccess,
    path: &Path,
    filename_short: &str,
) -> ZeckResult<(Option<ZeckNetwork>, SproutJournalSnapshot)> {
    let (bytes, object_id) = access
        .read_optional_child_version()
        .map_err(|err| journal_error(format!("reading {}: {err}", path.display())))?
        .ok_or_else(|| journal_error("enumerated sibling journal is absent from its authority"))?;
    let (authority_anchor, state) = access
        .current_authority()
        .map_err(|err| journal_error(format!("reading sibling journal authority: {err}")))?
        .ok_or_else(|| journal_error("sibling journal authority is missing"))?;
    let artifact_generation = match state {
        crate::private_fs::PrivateArtifactState::Active { generation, object }
            if object == object_id =>
        {
            generation
        }
        _ => {
            return Err(journal_error(
                "sibling journal authority is not active for its exact object",
            ))
        }
    };
    inspect_sibling_journal_bytes(
        &bytes,
        filename_short,
        authority_anchor,
        artifact_generation,
    )
}

fn inspect_sibling_journal_bytes(
    bytes: &[u8],
    filename_short: &str,
    expected_anchor: [u8; 16],
    expected_generation: [u8; 16],
) -> ZeckResult<(Option<ZeckNetwork>, SproutJournalSnapshot)> {
    if bytes.is_empty() {
        return Err(journal_error("empty sibling journal"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| journal_error("sibling journal is not UTF-8"))?;
    if !text.lines().next().unwrap_or_default().starts_with('{') {
        return Err(journal_error(
            "legacy sibling journal has no mandatory v4 lineage boundary",
        ));
    }
    inspect_v2_sibling(bytes, filename_short, expected_anchor, expected_generation)
}

fn inspect_v2_sibling(
    bytes: &[u8],
    filename_short: &str,
    expected_anchor: [u8; 16],
    expected_generation: [u8; 16],
) -> ZeckResult<(Option<ZeckNetwork>, SproutJournalSnapshot)> {
    if !bytes.contains(&b'\n') {
        return Err(journal_error("unterminated sibling journal header"));
    }
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let header = lines
        .next()
        .ok_or_else(|| journal_error("missing sibling journal header"))?;
    let (network, fingerprint) = match serde_json::from_slice::<SproutJournalRecord>(header)
        .map_err(|err| journal_error(format!("invalid sibling journal header: {err}")))?
    {
        SproutJournalRecord::Header {
            version: SPROUT_SWEEP_JOURNAL_VERSION,
            network,
            source_fingerprint,
            authority_anchor,
            artifact_generation,
        } if authority_anchor == expected_anchor && artifact_generation == expected_generation => {
            (network, source_fingerprint)
        }
        _ => return Err(journal_error("unsupported sibling journal header")),
    };
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !fingerprint.starts_with(filename_short)
    {
        return Err(journal_error(
            "sibling journal fingerprint does not match its filename",
        ));
    }

    let mut snapshot = SproutJournalSnapshot::default();
    let mut remaining = lines.peekable();
    while let Some(line) = remaining.next() {
        if remaining.peek().is_none() && !bytes.ends_with(b"\n") {
            break;
        }
        if line.is_empty() {
            if remaining.peek().is_none() {
                break;
            }
            return Err(journal_error("empty complete sibling journal record"));
        }
        let record = serde_json::from_slice(line).map_err(|err| {
            journal_error(format!("malformed complete sibling journal record: {err}"))
        })?;
        snapshot.apply(record, &fingerprint)?;
    }
    Ok((Some(network), snapshot))
}

pub struct SproutBroadcastStore<'a> {
    journal: &'a SweepJournal,
    note: JournalNoteContext,
    snapshot: &'a mut SproutJournalSnapshot,
}

impl BroadcastStore for SproutBroadcastStore<'_> {
    fn persist_prepared(&mut self, tx: &PreparedTransaction) -> ZeckResult<()> {
        let record = SproutJournalRecord::Prepared {
            note_id: note_id(&self.note.outpoint),
            value_zatoshis: self.note.value_zatoshis,
            transaction: JournalPreparedTransaction::from_prepared(tx)?,
        };
        self.journal.mutate(self.snapshot, record)
    }

    fn transition(
        &mut self,
        txid: TxId,
        state: TxLifecycleState,
        submission: Option<&SubmissionDisposition>,
        observation: Option<&TxObservation>,
    ) -> ZeckResult<()> {
        self.journal
            .append_transition(self.snapshot, txid, state, submission, observation)
    }

    fn latest(&self, txid: TxId) -> Option<PersistedTransaction> {
        let entry = self.snapshot.entry_for_txid(txid)?;
        Some(PersistedTransaction {
            prepared: entry.transaction.clone()?,
            state: entry.state,
            last_submission: entry.last_submission.clone(),
            observation: entry.observation.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broadcast::BroadcastStore;
    use std::io::Write;
    use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
    use zcash_protocol::consensus::{BlockHeight, BranchId};

    fn fixture() -> PreparedTransaction {
        fixture_with_lock_time(0)
    }

    fn fixture_with_lock_time(lock_time: u32) -> PreparedTransaction {
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            lock_time,
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

    fn confirmed_absence(expiry_height: u32) -> TxObservation {
        use crate::broadcast::{EndpointTxEvidence, TxObservationState};
        let confirmed_tip = expiry_height
            .saturating_add(crate::broadcast::EXPIRY_MARGIN_BLOCKS)
            .saturating_add(1);
        TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(expiry_height),
            primary_tip: Some(confirmed_tip),
            secondary_tip: Some(confirmed_tip),
            evidence: ["a", "b"]
                .into_iter()
                .map(|label| EndpointTxEvidence {
                    operator_id: label.to_owned(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(confirmed_tip),
                    reported_height: None,
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
        }
    }

    fn outpoint() -> JsOutPoint {
        JsOutPoint {
            txid: [0x42; 32],
            js_index: 3,
            output_index: 1,
        }
    }

    fn context() -> JournalNoteContext {
        JournalNoteContext {
            outpoint: outpoint(),
            value_zatoshis: 1_000_000,
        }
    }

    fn context_for(outpoint: JsOutPoint) -> JournalNoteContext {
        JournalNoteContext {
            outpoint,
            value_zatoshis: 1_000_000,
        }
    }

    fn artifact_data_dir(outer: &Path) -> PathBuf {
        // An absent intermediate exercises production private-directory creation;
        // elevated Windows runners can assign the raw temp root to Administrators.
        outer.join("publication").join("artifact-data")
    }

    fn journal(outer: &std::path::Path) -> SweepJournal {
        SweepJournal::for_keys(
            &artifact_data_dir(outer),
            &[[0x42; 32]],
            ZeckNetwork::Mainnet,
        )
    }

    #[test]
    fn exact_mode_legacy_direct_journal_is_refused_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        journal.load_or_migrate().unwrap();
        let legacy = journal.data_dir().join(format!(
            "sprout-sweep-{}.journal",
            key_set_fingerprint(&[[0x42; 32]])
        ));
        crate::private_fs::write_private_file(&legacy, b"legacy secret\n").unwrap();

        let error = journal
            .load_or_migrate()
            .expect_err("unmarked direct journal must fail closed");

        assert!(error.to_string().contains("legacy direct Sprout journal"));
        assert_eq!(std::fs::read(&legacy).unwrap(), b"legacy secret\n");
        assert!(!journal.path().exists());
        assert!(journal.root.exists());
    }

    #[test]
    fn direct_legacy_refusal_lists_txids_and_safe_manual_reconciliation_steps() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        journal.load_or_migrate().unwrap();
        let legacy = journal
            .data_dir()
            .join("sprout-sweep-deadbeefdeadbeef.journal");
        let v1_txid = "ab".repeat(32);
        let json_txid = "cd".repeat(32);
        let bytes = format!(
            "{}:0:1 {v1_txid}\n{{\"record\":\"prepared\",\"transaction\":{{\"txid\":\"{json_txid}\",\"raw_tx\":\"private-linkable-bytes\"}}}}\n{{\"record\":\"transition\",\"txid\":\"{json_txid}\"}}\n{{\"record\":\"transition\",\"txid\":\"not-a-txid\"}}\nunrecognized history\n",
            "ef".repeat(32)
        );
        crate::private_fs::write_private_file(&legacy, bytes.as_bytes()).unwrap();
        let sibling = journal
            .data_dir()
            .join("sprout-sweep-feedfeedfeedfeed.journal");
        let sibling_txid = "12".repeat(32);
        let sibling_bytes = format!("{}:1:0 {sibling_txid}\n", "34".repeat(32));
        crate::private_fs::write_private_file(&sibling, sibling_bytes.as_bytes()).unwrap();

        let error = journal.load_or_migrate().unwrap_err().to_string();

        assert!(error.contains(&sibling_txid), "{error}");
        assert!(error.contains(&v1_txid), "{error}");
        assert!(error.contains(&json_txid), "{error}");
        assert_eq!(error.matches(&json_txid).count(), 1, "{error}");
        assert!(!error.contains("private-linkable-bytes"));
        assert!(!error.contains("not-a-txid"));
        assert!(error.contains("untrusted"), "{error}");
        assert!(error.contains("independently"), "{error}");
        assert!(error.contains("move"), "{error}");
        assert!(error.contains("ambiguous"), "{error}");
        assert_eq!(std::fs::read(&legacy).unwrap(), bytes.as_bytes());
        assert_eq!(std::fs::read(&sibling).unwrap(), sibling_bytes.as_bytes());
        assert!(!journal.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn direct_legacy_diagnostics_do_not_follow_symlinks_or_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        journal.load_or_migrate().unwrap();
        let target = journal.data_dir().join("not-journal");
        let txid = "aa".repeat(32);
        let bytes = format!("{}:0:0 {txid}\n", "bb".repeat(32));
        crate::private_fs::write_private_file(&target, bytes.as_bytes()).unwrap();
        let legacy = journal
            .data_dir()
            .join("sprout-sweep-deadbeefdeadbeef.journal");
        for hardlink in [false, true] {
            if hardlink {
                std::fs::hard_link(&target, &legacy).unwrap();
            } else {
                std::os::unix::fs::symlink(&target, &legacy).unwrap();
            }
            let error = journal.load_or_migrate().unwrap_err().to_string();
            assert!(error.contains("legacy direct Sprout journal"), "{error}");
            assert!(error.contains("diagnostic"), "{error}");
            assert!(
                !error.contains(&txid),
                "must not read a linked replacement: {error}"
            );
            assert_eq!(std::fs::read(&target).unwrap(), bytes.as_bytes());
            std::fs::remove_file(&legacy).unwrap();
        }
    }

    fn checkpoint_generation(_dir: &Path, label: &[u8]) -> CheckpointGeneration {
        use sha2::Digest as _;

        let digest: [u8; 32] = sha2::Sha256::digest(label).into();
        let mut lineage_anchor = [0u8; 16];
        lineage_anchor.copy_from_slice(&digest[..16]);
        let mut artifact_generation = [0u8; 16];
        artifact_generation.copy_from_slice(&digest[16..]);
        CheckpointGeneration {
            lineage_anchor,
            artifact_generation,
            len: label.len() as u64,
            sha256: digest,
            object: crate::private_fs::PrivateObjectId::Unix {
                device: u64::from_le_bytes(digest[..8].try_into().unwrap()),
                inode: u64::from_le_bytes(digest[8..16].try_into().unwrap()),
            },
        }
    }

    fn authoritative_checkpoint(outer: &Path) -> (PathBuf, CheckpointGeneration) {
        let keys = [[0x42; 32]];
        let scanner = crate::sprout_scan::SproutScanner::new(&keys);
        let path = crate::sprout_scan_run::checkpoint_path_for_network(
            &artifact_data_dir(outer),
            &keys,
            crate::p2p::wire::P2pNetwork::Mainnet,
        );
        crate::sprout_scan_run::save_checkpoint(
            &scanner,
            crate::p2p::wire::P2pNetwork::Mainnet,
            &path,
        )
        .unwrap();
        let generation = crate::sprout_scan_run::checkpoint_generation(&path).unwrap();
        (path, generation)
    }

    fn mined_observation(height: u32, depth: u32, hash: u8) -> TxObservation {
        crate::broadcast::observe_transaction(
            ["first", "second"]
                .into_iter()
                .map(|label| crate::broadcast::EndpointTxEvidence {
                    operator_id: label.to_owned(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(height.checked_add(depth).unwrap()),
                    reported_height: Some(height),
                    block_hash: Some(vec![hash; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(100),
        )
    }

    #[test]
    fn cleanup_evidence_invalidation_records_decode_without_demoting_mined_history() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, 100, 0x11);
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Mined,
                Some(&SubmissionDisposition::Accepted),
                Some(&mature),
            )
            .unwrap();
        let original = std::fs::read(journal.path()).unwrap();
        let invalidation = format!(
            "{{\"record\":\"cleanup_evidence_invalidated\",\"txid\":\"{}\"}}\n",
            transaction.txid
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(journal.path())
            .unwrap();
        // Replay repeated durable markers to pin decoder idempotency.
        file.write_all(invalidation.as_bytes()).unwrap();
        file.write_all(invalidation.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let restored = journal.load_or_migrate().unwrap();
        let entry = restored.entry_for_txid(transaction.txid).unwrap();
        assert!(entry.observations.is_empty());
        assert_eq!(entry.state, TxLifecycleState::Mined);
        assert_eq!(entry.observation.as_ref(), Some(&mature));
        assert_eq!(entry.transaction.as_ref(), Some(&transaction));
        assert_eq!(entry.last_submission, Some(SubmissionDisposition::Accepted));
        assert!(!restored.ready_for_new_plan(&context().outpoint));
        assert!(std::fs::read(journal.path())
            .unwrap()
            .starts_with(&original));
    }

    #[test]
    fn cleanup_evidence_invalidation_refuses_unknown_or_unmined_transactions() {
        use std::io::Write as _;
        for unknown_txid in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let journal = journal(dir.path());
            let mut snapshot = journal.load_or_migrate().unwrap();
            let transaction = fixture();
            journal
                .scoped_store(context(), &mut snapshot)
                .persist_prepared(&transaction)
                .unwrap();
            let txid = if unknown_txid {
                TxId::from_bytes([0xff; 32])
            } else {
                transaction.txid
            };
            let invalidation =
                format!("{{\"record\":\"cleanup_evidence_invalidated\",\"txid\":\"{txid}\"}}\n");
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(journal.path())
                .unwrap();
            file.write_all(invalidation.as_bytes()).unwrap();
            drop(file);
            let error = journal.load_or_migrate().unwrap_err().to_string();
            assert!(
                error.contains(if unknown_txid {
                    "invalidation before preparation"
                } else {
                    "invalidation requires a recorded mined fact"
                }),
                "{error}"
            );
        }
    }

    #[test]
    fn checkpoint_cleanup_requires_two_mature_canonical_rounds() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
        let current = BTreeSet::from([note_id(&outpoint())]);
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Mined,
                None,
                Some(&mature),
            )
            .unwrap();
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &current
            ),
            CheckpointCleanupEligibility::Retain { .. }
        ));
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Mined,
                None,
                Some(&mature),
            )
            .unwrap();
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &current
            ),
            CheckpointCleanupEligibility::Eligible { .. }
        ));
        let shallow_fork = mined_observation(2, SPROUT_REORG_WINDOW as u32 - 1, 0x22);
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Mined,
                None,
                Some(&shallow_fork),
            )
            .unwrap();
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &current
            ),
            CheckpointCleanupEligibility::Retain { .. }
        ));
    }

    #[test]
    fn checkpoint_cleanup_rejects_shallow_generation_mismatch_and_extra_note() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
        let current = BTreeSet::from([note_id(&outpoint())]);
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let shallow = mined_observation(1, SPROUT_REORG_WINDOW as u32 - 1, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    None,
                    Some(&shallow),
                )
                .unwrap();
        }
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &current
            ),
            CheckpointCleanupEligibility::Retain { .. }
        ));

        let mut replaced = generation.clone();
        replaced.artifact_generation[0] ^= 1;
        assert_ne!(generation, replaced);
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &replaced,
                &current
            ),
            CheckpointCleanupEligibility::Retain { .. }
        ));

        let mut extra = current.clone();
        extra.insert(([0x99; 32], 1, 0));
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &extra
            ),
            CheckpointCleanupEligibility::Retain { .. }
        ));
    }

    #[test]
    fn mixed_or_reorged_manifest_never_authorizes_checkpoint_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
        let current = BTreeSet::from([note_id(&outpoint())]);
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    Some(&SubmissionDisposition::Accepted),
                    Some(&mature),
                )
                .unwrap();
        }
        let assert_retained = |candidate: &SproutJournalSnapshot| {
            assert!(matches!(
                candidate.checkpoint_cleanup_eligibility(
                    journal.source_fingerprint(),
                    &generation,
                    &current
                ),
                CheckpointCleanupEligibility::Retain { .. }
            ));
        };

        let mut missing = snapshot.clone();
        missing.by_note.remove(&note_id(&outpoint()));
        assert_retained(&missing);
        for state in [
            TxLifecycleState::NotSubmitted,
            TxLifecycleState::Pending,
            TxLifecycleState::SubmissionUnknown,
            TxLifecycleState::Expired,
            TxLifecycleState::Rejected,
        ] {
            let mut candidate = snapshot.clone();
            candidate
                .by_note
                .get_mut(&note_id(&outpoint()))
                .unwrap()
                .state = state;
            assert_retained(&candidate);
        }
        let mut single_source = snapshot.clone();
        single_source
            .by_note
            .get_mut(&note_id(&outpoint()))
            .unwrap()
            .observations
            .last_mut()
            .unwrap()
            .evidence
            .truncate(1);
        assert_retained(&single_source);
        let mut contested = snapshot.clone();
        contested
            .by_note
            .get_mut(&note_id(&outpoint()))
            .unwrap()
            .observations
            .last_mut()
            .unwrap()
            .evidence[1]
            .block_hash = Some(vec![0x22; 32]);
        assert_retained(&contested);
        let mut reorged = snapshot;
        let entry = reorged.by_note.get_mut(&note_id(&outpoint())).unwrap();
        entry.state = TxLifecycleState::Pending;
        entry.observations.push(TxObservation {
            state: crate::broadcast::TxObservationState::Reorged,
            mined_height: None,
            expiry_height: transaction.expiry_height,
            primary_tip: Some(200),
            secondary_tip: Some(200),
            evidence: Vec::new(),
        });
        assert_retained(&reorged);
    }

    #[test]
    fn checkpoint_manifest_union_keeps_nonadjacent_source_positions() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
        let first = JsOutPoint {
            txid: [0x31; 32],
            js_index: 1,
            output_index: 0,
        };
        let third = JsOutPoint {
            txid: [0x33; 32],
            js_index: 3,
            output_index: 1,
        };
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&first])
            .unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&third])
            .unwrap();
        let restored = journal.load_or_migrate().unwrap();
        assert_eq!(
            restored.checkpoint_manifest(&generation).unwrap().note_ids,
            BTreeSet::from([note_id(&first), note_id(&third)])
        );
    }

    #[test]
    fn cleanup_failure_is_visible_and_keeps_the_mined_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let (checkpoint, generation) = authoritative_checkpoint(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    Some(&SubmissionDisposition::Accepted),
                    Some(&mature),
                )
                .unwrap();
        }
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        crate::sprout_scan_run::fail_checkpoint_discard(&checkpoint);
        let err = journal
            .finalize_checkpoint_cleanup(&lease, &generation, &checkpoint)
            .expect_err("a deletion error must be surfaced")
            .to_string();
        assert!(
            err.contains("injected checkpoint deletion failure"),
            "{err}"
        );
        assert!(checkpoint.exists());
        drop(lease);
        let restored = journal.load_or_migrate().unwrap();
        let entry = restored.entry_for_note(&outpoint()).unwrap();
        assert_eq!(entry.transaction.as_ref(), Some(&transaction));
        assert_eq!(entry.value_zatoshis, Some(context().value_zatoshis));
        assert_eq!(entry.last_submission, Some(SubmissionDisposition::Accepted));
        assert_eq!(entry.observations.len(), 2);
        assert!(restored.discard_started.contains(&generation));
        assert!(!restored.discarded_checkpoints.contains(&generation));
        let records = std::fs::read_to_string(journal.path()).unwrap();
        assert_eq!(
            records
                .matches("\"record\":\"checkpoint_tombstone\"")
                .count(),
            1
        );
        assert!(records.contains("\"record\":\"prepared\""));
        assert!(records.contains("\"record\":\"transition\""));

        let reorg = TxObservation {
            state: crate::broadcast::TxObservationState::Reorged,
            mined_height: None,
            expiry_height: transaction.expiry_height,
            primary_tip: Some(50),
            secondary_tip: Some(50),
            evidence: ["first", "second"]
                .into_iter()
                .map(|label| crate::broadcast::EndpointTxEvidence {
                    operator_id: label.into(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(50),
                    reported_height: Some(u32::MAX),
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
        };
        let mut restored = restored;
        journal
            .append_transition(
                &mut restored,
                transaction.txid,
                TxLifecycleState::Pending,
                None,
                Some(&reorg),
            )
            .unwrap();
        journal
            .append_transition(
                &mut restored,
                transaction.txid,
                TxLifecycleState::Expired,
                None,
                Some(&confirmed_absence(100)),
            )
            .unwrap();
        assert!(restored.ready_for_new_plan(&outpoint()));
    }

    #[test]
    fn cleanup_restart_never_deletes_a_surviving_generation_from_stale_observations() {
        let dir = tempfile::tempdir().unwrap();
        let (checkpoint, generation) = authoritative_checkpoint(dir.path());
        let original = std::fs::read(&checkpoint).unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    Some(&SubmissionDisposition::Accepted),
                    Some(&mature),
                )
                .unwrap();
        }

        // Crash after the durable start marker but before the checkpoint is
        // quarantined. The chain may reorg during arbitrary downtime, so the
        // pre-crash observations cannot authorize deletion after restart.
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        crate::sprout_scan_run::fail_checkpoint_discard(&checkpoint);
        journal
            .finalize_checkpoint_cleanup(&lease, &generation, &checkpoint)
            .expect_err("the injected pre-quarantine crash must interrupt cleanup");
        drop(lease);

        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        let result = journal
            .resume_checkpoint_cleanup(&lease, &checkpoint)
            .unwrap();
        assert!(matches!(
            result,
            Some(CheckpointCleanupResult::Retain { ref reason })
                if reason.contains("fresh reconciliation")
        ));
        assert_eq!(std::fs::read(&checkpoint).unwrap(), original);
        assert_eq!(lease.generation(&checkpoint).unwrap(), generation);
        drop(lease);

        let restored = journal.load_or_migrate().unwrap();
        assert!(restored.discard_started.contains(&generation));
        assert!(!restored.discarded_checkpoints.contains(&generation));
    }

    #[test]
    fn cleanup_restart_after_unlink_commits_an_idempotent_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let (checkpoint, generation) = authoritative_checkpoint(dir.path());
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    Some(&SubmissionDisposition::Accepted),
                    Some(&mature),
                )
                .unwrap();
        }
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        fail_after_checkpoint_discard(&checkpoint);
        journal
            .finalize_checkpoint_cleanup(&lease, &generation, &checkpoint)
            .expect_err("the injected crash must happen after durable retirement");
        assert!(!checkpoint.exists());
        drop(lease);
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();

        assert_eq!(
            journal
                .resume_checkpoint_cleanup(&lease, &checkpoint)
                .unwrap(),
            Some(CheckpointCleanupResult::AlreadyAbsent)
        );
        drop(lease);
        let restored = journal.load_or_migrate().unwrap();
        assert!(restored.discarded_checkpoints.contains(&generation));
        assert_eq!(
            restored
                .entry_for_note(&outpoint())
                .unwrap()
                .transaction
                .as_ref(),
            Some(&transaction)
        );
    }

    #[test]
    fn cleanup_restart_completes_old_generation_without_deleting_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let (checkpoint, generation) = authoritative_checkpoint(dir.path());
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    Some(&SubmissionDisposition::Accepted),
                    Some(&mature),
                )
                .unwrap();
        }
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        fail_after_checkpoint_discard(&checkpoint);
        journal
            .finalize_checkpoint_cleanup(&lease, &generation, &checkpoint)
            .expect_err("the injected crash must leave retired authority before completion");
        drop(lease);

        let (replacement_path, replacement_generation) = authoritative_checkpoint(dir.path());
        assert_eq!(replacement_path, checkpoint);
        assert_ne!(replacement_generation, generation);
        let replacement = std::fs::read(&checkpoint).unwrap();
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();

        let result = journal
            .resume_checkpoint_cleanup(&lease, &checkpoint)
            .unwrap();
        assert!(matches!(
            result,
            Some(CheckpointCleanupResult::Retain { ref reason })
                if reason.contains("replacement checkpoint")
        ));
        assert_eq!(std::fs::read(&checkpoint).unwrap(), replacement);
        assert_eq!(
            lease.generation(&checkpoint).unwrap(),
            replacement_generation
        );
        drop(lease);
        let restored = journal.load_or_migrate().unwrap();
        assert!(restored.discarded_checkpoints.contains(&generation));
        assert!(journal
            .resume_checkpoint_cleanup(
                &crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap(),
                &checkpoint,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_post_cleanup_reorg_never_makes_the_discarded_source_ready() {
        let dir = tempfile::tempdir().unwrap();
        let (checkpoint, generation) = authoritative_checkpoint(dir.path());
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let transaction = fixture();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();
        let mature = mined_observation(1, SPROUT_REORG_WINDOW as u32, 0x11);
        for _ in 0..2 {
            journal
                .append_transition(
                    &mut snapshot,
                    transaction.txid,
                    TxLifecycleState::Mined,
                    None,
                    Some(&mature),
                )
                .unwrap();
        }
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        assert_eq!(
            journal
                .finalize_checkpoint_cleanup(&lease, &generation, &checkpoint)
                .unwrap(),
            CheckpointCleanupResult::Removed
        );
        drop(lease);
        let reorg = TxObservation {
            state: crate::broadcast::TxObservationState::Reorged,
            mined_height: None,
            expiry_height: transaction.expiry_height,
            primary_tip: Some(50),
            secondary_tip: Some(50),
            evidence: ["first", "second"]
                .into_iter()
                .map(|label| crate::broadcast::EndpointTxEvidence {
                    operator_id: label.into(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(50),
                    reported_height: Some(u32::MAX),
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
        };
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Pending,
                None,
                Some(&reorg),
            )
            .unwrap();
        assert!(!snapshot.ready_for_new_plan(&outpoint()));

        let (restored_path, restored_generation) = authoritative_checkpoint(dir.path());
        assert_eq!(restored_path, checkpoint);
        journal
            .record_checkpoint_manifest(&mut snapshot, &restored_generation, [&outpoint()])
            .unwrap();
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Expired,
                None,
                Some(&confirmed_absence(100)),
            )
            .unwrap();
        assert!(
            snapshot.ready_for_new_plan_with_restored_source(&outpoint()),
            "a newly manifested checkpoint restores the source authority"
        );
    }

    #[test]
    fn v4_prepared_record_round_trips_every_safety_field() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let tx = fixture();
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&tx)
            .unwrap();
        let restored = journal.load_or_migrate().unwrap();
        let entry = restored.entry_for_note(&outpoint()).unwrap();
        assert_eq!(entry.outpoint, outpoint());
        assert_eq!(
            entry.source_fingerprint,
            full_key_set_fingerprint(&[[0x42; 32]])
        );
        assert_eq!(entry.value_zatoshis, Some(1_000_000));
        assert_eq!(entry.transaction.as_ref(), Some(&tx));
        assert_eq!(entry.state, TxLifecycleState::NotSubmitted);
        assert_eq!(
            restored.entry_for_txid(tx.txid).unwrap().outpoint,
            outpoint()
        );
        let first_line = std::fs::read_to_string(journal.path()).unwrap();
        let header: serde_json::Value =
            serde_json::from_str(first_line.lines().next().unwrap()).unwrap();
        assert_eq!(header["version"], 4);
        assert_eq!(header["network"], "mainnet");
        assert_eq!(
            header["source_fingerprint"],
            full_key_set_fingerprint(&[[0x42; 32]])
        );
        assert_eq!(header["authority_anchor"].as_array().unwrap().len(), 16);
        assert_eq!(header["artifact_generation"].as_array().unwrap().len(), 16);
    }

    #[test]
    fn authenticated_root_rejects_v2_and_v3_without_rewriting_history() {
        for old_version in [2, 3] {
            let dir = tempfile::tempdir().unwrap();
            let journal = journal(dir.path());
            let mut snapshot = journal.load_or_migrate().unwrap();
            journal
                .scoped_store(context(), &mut snapshot)
                .persist_prepared(&fixture())
                .unwrap();
            let mut lines = std::fs::read_to_string(journal.path())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut header = serde_json::from_str::<serde_json::Value>(&lines[0]).unwrap();
            header["version"] = old_version.into();
            lines[0] = serde_json::to_string(&header).unwrap();
            let legacy = lines.join("\n") + "\n";
            std::fs::write(journal.path(), legacy.as_bytes()).unwrap();

            let error = journal
                .load_or_migrate()
                .expect_err("old formats inside a new authenticated root are invalid")
                .to_string();

            assert!(error.contains("mismatch"), "{error}");
            assert_eq!(std::fs::read(journal.path()).unwrap(), legacy.as_bytes());
        }
    }

    #[test]
    fn wrong_network_or_full_fingerprint_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        let other = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x43; 32]],
            ZeckNetwork::Mainnet,
        );
        let mut other_snapshot = other.load_or_migrate().unwrap();
        other
            .scoped_store(
                context_for(JsOutPoint {
                    txid: [0x99; 32],
                    js_index: 0,
                    output_index: 0,
                }),
                &mut other_snapshot,
            )
            .persist_prepared(&fixture())
            .unwrap();
        let replay = std::fs::read(journal.path()).unwrap();
        std::fs::write(other.path(), replay).unwrap();

        let error = other
            .load_or_migrate()
            .expect_err("journal bytes cannot be replayed under another root authority")
            .to_string();
        assert!(
            error.contains("lineage") || error.contains("mismatch"),
            "{error}"
        );
    }

    #[test]
    fn scoped_load_strictly_validates_sibling_header_and_raw_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let current = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x43; 32]],
            ZeckNetwork::Mainnet,
        );
        let sibling = journal(dir.path());
        let mut snapshot = sibling.load_or_migrate().unwrap();
        sibling
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();

        let mut records = std::fs::read_to_string(sibling.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        records[1]["transaction"]["raw_tx_base64"] = serde_json::Value::String("AA==".into());
        let corrupted = records
            .into_iter()
            .map(|record| serde_json::to_string(&record).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(sibling.path(), corrupted).unwrap();
        let err = current
            .load_scoped_snapshot(&[outpoint()])
            .expect_err("every sibling raw transaction must be reduced and verified")
            .to_string();
        assert!(err.contains("transaction") || err.contains("raw"), "{err}");
    }

    #[test]
    fn scoped_load_ignores_only_a_fully_valid_other_network_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        let sibling = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x43; 32]],
            ZeckNetwork::Testnet,
        );
        let mut snapshot = sibling.load_or_migrate().unwrap();
        sibling
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        current
            .load_scoped_snapshot(&[outpoint()])
            .expect("a valid other-network sibling cannot claim this network's note");
    }

    #[test]
    fn scoped_load_rejects_an_overlapping_authorized_key_set_root() {
        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        let sibling = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x43; 32]],
            ZeckNetwork::Mainnet,
        );
        let mut snapshot = sibling.load_or_migrate().unwrap();
        sibling
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();

        let error = current
            .load_scoped_snapshot(&[outpoint()])
            .expect_err("another authenticated key-set history for the note must block sweeping")
            .to_string();

        assert!(error.contains("Sprout journal overlap"), "{error}");
        assert!(error.contains(&sibling.path().display().to_string()));
    }

    #[test]
    fn scoped_load_accepts_a_nonoverlapping_authorized_key_set_root() {
        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        let sibling = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x43; 32]],
            ZeckNetwork::Mainnet,
        );
        let different = JsOutPoint {
            txid: [0x99; 32],
            js_index: 2,
            output_index: 0,
        };
        let mut snapshot = sibling.load_or_migrate().unwrap();
        sibling
            .scoped_store(context_for(different), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();

        current
            .load_scoped_snapshot(&[outpoint()])
            .expect("authenticated histories for distinct notes may coexist");
    }

    #[test]
    fn scoped_load_rejects_a_tampered_private_root_before_reading_its_journal() {
        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        let sibling = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x43; 32]],
            ZeckNetwork::Mainnet,
        );
        sibling.load_or_migrate().unwrap();
        std::fs::write(
            sibling
                .root
                .join(crate::private_fs::PRIVATE_ARTIFACT_ROOT_MARKER),
            b"tampered marker",
        )
        .unwrap();

        let error = current
            .load_scoped_snapshot(&[])
            .expect_err("an unauthenticated sibling root must fail closed")
            .to_string();

        assert!(
            error.contains("authenticated marker") || error.contains("invalid"),
            "{error}"
        );
    }

    #[test]
    fn every_direct_legacy_journal_blocks_even_for_another_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        current.load_or_migrate().unwrap();
        let legacy = current
            .data_dir()
            .join("sprout-sweep-deadbeefdeadbeef.journal");
        crate::private_fs::write_private_file(&legacy, b"possibly broadcast history\n").unwrap();

        let error = current
            .load_scoped_snapshot(&[])
            .expect_err("an unreconciled direct sibling history must block every key set")
            .to_string();

        assert!(error.contains("legacy direct Sprout journal"), "{error}");
        assert_eq!(
            std::fs::read(&legacy).unwrap(),
            b"possibly broadcast history\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scoped_load_rejects_a_symlinked_sibling() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        current.load_or_migrate().unwrap();
        let target = current.data_dir().join("outside");
        std::fs::write(&target, b"not a journal\n").unwrap();
        let sibling = current
            .data_dir()
            .join("sprout-sweep-deadbeefdeadbeef.journal");
        symlink(&target, &sibling).unwrap();
        let err = current
            .load_scoped_snapshot(&[])
            .expect_err("sibling symlinks fail closed")
            .to_string();
        assert!(
            err.contains("legacy direct Sprout journal")
                && err.contains(&sibling.display().to_string())
        );
    }

    #[test]
    fn raw_transaction_must_hash_to_the_recorded_txid() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        let valid = fixture();
        let mut wrong = valid.clone();
        wrong.txid = TxId::from_bytes([0x99; 32]);
        assert!(journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&wrong)
            .is_err());
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&valid)
            .unwrap();
        let text = std::fs::read_to_string(journal.path()).unwrap();
        std::fs::write(
            journal.path(),
            text.replace(&valid.txid.to_string(), &wrong.txid.to_string()),
        )
        .unwrap();
        assert!(journal.load_or_migrate().is_err());
    }

    #[test]
    fn all_mined_for_requires_stored_canonical_observation() {
        use crate::broadcast::{EndpointTxEvidence, TxObservationState};

        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let transaction = fixture();
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&transaction)
            .unwrap();

        snapshot
            .by_note
            .get_mut(&note_id(&outpoint()))
            .unwrap()
            .state = TxLifecycleState::Mined;
        assert!(!snapshot.all_mined_for([&outpoint()]));

        let block_hash = vec![0x11; 32];
        snapshot
            .by_note
            .get_mut(&note_id(&outpoint()))
            .unwrap()
            .observation = Some(TxObservation {
            state: TxObservationState::Mined,
            mined_height: Some(90),
            expiry_height: transaction.expiry_height,
            primary_tip: Some(100),
            secondary_tip: Some(100),
            evidence: ["a", "b"]
                .into_iter()
                .map(|label| EndpointTxEvidence {
                    operator_id: label.to_owned(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(100),
                    reported_height: Some(90),
                    block_hash: Some(block_hash.clone()),
                    tx_in_block: true,
                })
                .collect(),
        });
        assert!(snapshot.all_mined_for([&outpoint()]));
    }

    #[test]
    fn malformed_complete_line_blocks_broadcast() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(journal.path())
            .unwrap();
        file.write_all(b"not a record\n").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let before = std::fs::read(journal.path()).unwrap();
        assert!(journal.load_or_migrate().is_err());
        assert_eq!(std::fs::read(journal.path()).unwrap(), before);
    }

    #[test]
    fn torn_final_v4_transition_fails_closed_without_rewriting_history() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let tx = fixture();
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&tx)
            .unwrap();
        journal
            .append_transition(
                &mut snapshot,
                tx.txid,
                TxLifecycleState::SubmissionUnknown,
                None,
                None,
            )
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(journal.path())
            .unwrap();
        file.write_all(b"{\"record\":\"transition\",\"state\":\"mined\"")
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        let before = std::fs::read(journal.path()).unwrap();
        let err = journal.load_or_migrate().unwrap_err().to_string();
        assert!(err.contains("incomplete trailing record"), "{err}");
        assert_eq!(std::fs::read(journal.path()).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn journal_is_created_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        let mode = std::fs::metadata(journal.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn expired_note_replacement_does_not_alias_the_old_txid() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let first = fixture();
        let second = fixture_with_lock_time(1);
        assert_ne!(first.txid, second.txid);
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&first)
            .unwrap();
        let absence = confirmed_absence(first.expiry_height.unwrap());
        journal
            .append_transition(
                &mut snapshot,
                first.txid,
                TxLifecycleState::Expired,
                None,
                Some(&absence),
            )
            .unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&second)
            .unwrap();
        assert!(snapshot.entry_for_txid(first.txid).is_none());
        assert_eq!(
            snapshot.entry_for_txid(second.txid).unwrap().state,
            TxLifecycleState::NotSubmitted
        );
        assert!(journal
            .append_transition(
                &mut snapshot,
                first.txid,
                TxLifecycleState::Pending,
                Some(&SubmissionDisposition::Accepted),
                None
            )
            .is_err());
    }

    #[test]
    fn independently_loaded_handles_cannot_prepare_competing_transactions_for_one_note() {
        let dir = tempfile::tempdir().unwrap();
        let first_handle = journal(dir.path());
        let second_handle = journal(dir.path());
        let mut first_snapshot = first_handle.load_or_migrate().unwrap();
        let mut stale_snapshot = second_handle.load_or_migrate().unwrap();
        let first = fixture();
        let competing = fixture_with_lock_time(1);
        first_handle
            .scoped_store(context(), &mut first_snapshot)
            .persist_prepared(&first)
            .unwrap();
        assert!(second_handle
            .scoped_store(context(), &mut stale_snapshot)
            .persist_prepared(&competing)
            .is_err());
        let durable = first_handle.load_or_migrate().unwrap();
        assert_eq!(
            durable
                .entry_for_note(&outpoint())
                .unwrap()
                .transaction
                .as_ref(),
            Some(&first)
        );
    }

    #[test]
    fn stale_transition_cannot_append_invalid_history() {
        let dir = tempfile::tempdir().unwrap();
        let first_handle = journal(dir.path());
        let second_handle = journal(dir.path());
        let tx = fixture();
        let mut first_snapshot = first_handle.load_or_migrate().unwrap();
        first_handle
            .scoped_store(context(), &mut first_snapshot)
            .persist_prepared(&tx)
            .unwrap();
        let mut stale_snapshot = second_handle.load_or_migrate().unwrap();
        first_handle
            .append_transition(
                &mut first_snapshot,
                tx.txid,
                TxLifecycleState::SubmissionUnknown,
                None,
                None,
            )
            .unwrap();
        assert!(second_handle
            .append_transition(
                &mut stale_snapshot,
                tx.txid,
                TxLifecycleState::NotSubmitted,
                None,
                None
            )
            .is_err());
        assert_eq!(
            first_handle
                .load_or_migrate()
                .unwrap()
                .entry_for_txid(tx.txid)
                .unwrap()
                .state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[test]
    fn separate_connection_lock_blocks_load_and_append() {
        use std::sync::mpsc;
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let mut initial = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut initial)
            .persist_prepared(&fixture())
            .unwrap();
        let lock_path = journal.root.join(".journal.lock.sqlite");
        let connection = rusqlite::Connection::open(&lock_path).unwrap();
        connection
            .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
            .unwrap();
        let (sender, receiver) = mpsc::channel();
        let other = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x42; 32]],
            ZeckNetwork::Mainnet,
        );
        let worker =
            std::thread::spawn(move || sender.send(other.load_or_migrate().is_ok()).unwrap());
        assert!(receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        connection.execute_batch("COMMIT").unwrap();
        assert!(receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap());
        worker.join().unwrap();
        let tx = fixture_with_lock_time(1);
        let mut snapshot = journal.load_or_migrate().unwrap();
        let another_note = JournalNoteContext {
            outpoint: JsOutPoint {
                txid: [0x43; 32],
                js_index: 2,
                output_index: 0,
            },
            value_zatoshis: 2_000_000,
        };
        connection
            .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
            .unwrap();
        let (sender, receiver) = mpsc::channel();
        let other = SweepJournal::for_keys(
            &artifact_data_dir(dir.path()),
            &[[0x42; 32]],
            ZeckNetwork::Mainnet,
        );
        let worker = std::thread::spawn(move || {
            sender
                .send(
                    other
                        .scoped_store(another_note, &mut snapshot)
                        .persist_prepared(&tx)
                        .is_ok(),
                )
                .unwrap();
        });
        assert!(receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        connection.execute_batch("COMMIT").unwrap();
        assert!(receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap());
        worker.join().unwrap();
        assert_eq!(journal.load_or_migrate().unwrap().entries().count(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn windows_journal_authority_denies_sidecar_replacement_and_second_writer() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let access = journal.artifact_access().unwrap();
        let authority = access.namespace().lock_path().to_path_buf();
        let displaced = authority.with_extension("displaced-lock");

        with_sweep_journal_lock(journal.path(), Some(access.namespace()), |_| {
            assert!(std::fs::rename(&authority, &displaced).is_err());
            let second = with_sweep_journal_lock(journal.path(), None, |_| Ok(()))
                .expect_err("a second journal authority must be refused");
            assert!(second.to_string().contains("namespace"), "{second}");
            Ok(())
        })
        .unwrap();
        assert!(authority.exists());
        assert!(!displaced.exists());
    }

    #[test]
    fn terminal_note_cannot_reuse_same_txid_with_changed_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let first = fixture();
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&first)
            .unwrap();
        journal
            .append_transition(
                &mut snapshot,
                first.txid,
                TxLifecycleState::Expired,
                None,
                Some(&confirmed_absence(100)),
            )
            .unwrap();
        let mut changed = first.clone();
        changed.fee_zatoshis += 1;
        assert!(journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&changed)
            .is_err());
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .entry_for_txid(first.txid)
                .unwrap()
                .transaction
                .as_ref(),
            Some(&first)
        );
    }

    #[test]
    fn encoded_transaction_expiry_must_match_prepared_metadata_on_write_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let valid = fixture();
        let mut snapshot = journal.load_or_migrate().unwrap();
        let mut forged = valid.clone();
        forged.expiry_height = Some(1);
        assert!(journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&forged)
            .is_err());
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&valid)
            .unwrap();
        let text = std::fs::read_to_string(journal.path()).unwrap();
        std::fs::write(
            journal.path(),
            text.replace("\"expiry_height\":100", "\"expiry_height\":1"),
        )
        .unwrap();
        assert!(journal.load_or_migrate().is_err());
    }
}
