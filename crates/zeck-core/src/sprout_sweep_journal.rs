//! Durable, versioned Sprout sweep transactions, keyed by note and source.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::File,
    io::{Cursor, Read, Seek},
    path::{Path, PathBuf},
    time::Duration,
};

use argos_wallet_import::keys::JsOutPoint;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;
use zeroize::Zeroizing;

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

pub const SPROUT_SWEEP_JOURNAL_VERSION: u32 = 3;
pub const SPROUT_EXPIRY_DELTA: u32 = 40;
pub type SproutNoteId = ([u8; 32], u64, u8);

#[cfg(test)]
static FAIL_AFTER_CHECKPOINT_DISCARD: std::sync::Mutex<Option<PathBuf>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn fail_after_checkpoint_discard(path: &Path) {
    *FAIL_AFTER_CHECKPOINT_DISCARD.lock().unwrap() = Some(path.to_path_buf());
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

fn checkpoint_discard_prefix(path: &Path) -> ZeckResult<String> {
    let name = path
        .file_name()
        .ok_or_else(|| journal_error("checkpoint path has no file name"))?;
    Ok(format!(
        ".argos-checkpoint-discard-{:x}-",
        Sha256::digest(name.as_encoded_bytes())
    ))
}

fn checkpoint_discard_quarantines(
    namespace: &NamespaceLease,
    checkpoint: &Path,
) -> ZeckResult<Vec<PathBuf>> {
    let prefix = checkpoint_discard_prefix(checkpoint)?;
    Ok(namespace
        .child_names()
        .map_err(|err| journal_error(format!("reading checkpoint quarantine names: {err}")))?
        .into_iter()
        .filter(|name| {
            name.to_str()
                .and_then(|name| name.strip_prefix(&prefix))
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        })
        .map(|name| namespace.parent_path().join(name))
        .collect())
}

fn hash_checkpoint_handle(file: &File, path: &Path) -> ZeckResult<(u64, [u8; 32])> {
    let mut reader = file;
    reader
        .rewind()
        .map_err(|err| journal_error(format!("seeking checkpoint {}: {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; 64 * 1024]);
    let mut len = 0u64;
    loop {
        let read = reader.read(&mut *buffer).map_err(|err| {
            journal_error(format!("reading checkpoint {}: {err}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        len = len
            .checked_add(read as u64)
            .ok_or_else(|| journal_error("checkpoint length overflow"))?;
        hasher.update(&buffer[..read]);
    }
    Ok((len, hasher.finalize().into()))
}

fn retained_quarantine_generation(
    namespace: &NamespaceLease,
    path: &Path,
) -> ZeckResult<(File, CheckpointGeneration)> {
    namespace
        .require_child(path)
        .and_then(|()| namespace.verify_current())
        .map_err(|err| journal_error(format!("verifying checkpoint quarantine: {err}")))?;
    let file = crate::private_fs::open_child_file_for_removal(namespace.parent(), path).map_err(
        |err| {
            journal_error(format!(
                "opening checkpoint quarantine {}: {err}",
                path.display()
            ))
        },
    )?;
    let before = file.metadata().map_err(|err| {
        journal_error(format!(
            "inspecting checkpoint quarantine {}: {err}",
            path.display()
        ))
    })?;
    if !before.is_file() {
        return Err(journal_error(format!(
            "checkpoint quarantine {} is not a regular file",
            path.display()
        )));
    }
    let before_object = crate::private_fs::private_object_id(&file).map_err(|err| {
        journal_error(format!(
            "reading checkpoint quarantine identity {}: {err}",
            path.display()
        ))
    })?;
    let (len, sha256) = hash_checkpoint_handle(&file, path)?;
    let (verified_len, verified_sha256) = hash_checkpoint_handle(&file, path)?;
    let after = file.metadata().map_err(|err| {
        journal_error(format!(
            "rechecking checkpoint quarantine {}: {err}",
            path.display()
        ))
    })?;
    let after_object = crate::private_fs::private_object_id(&file).map_err(|err| {
        journal_error(format!(
            "rechecking checkpoint quarantine identity {}: {err}",
            path.display()
        ))
    })?;
    namespace.verify_current().map_err(|err| {
        journal_error(format!("rechecking checkpoint quarantine namespace: {err}"))
    })?;
    if before.len() != after.len()
        || before.len() != len
        || len != verified_len
        || sha256 != verified_sha256
        || before_object != after_object
    {
        return Err(journal_error(format!(
            "checkpoint quarantine {} changed while it was reviewed",
            path.display()
        )));
    }
    Ok((
        file,
        CheckpointGeneration {
            len,
            sha256,
            object: after_object,
        },
    ))
}

/// The lock inode is stable across the v1-to-v2 rename. Both the temporary
/// legacy writer and v2 journal take this same SQLite process lock.
pub(crate) fn with_sweep_journal_lock<T>(
    path: &Path,
    namespace: Option<&NamespaceLease>,
    operation: impl FnOnce(&NamespaceLease) -> ZeckResult<T>,
) -> ZeckResult<T> {
    let mut sqlite_name = path.as_os_str().to_os_string();
    sqlite_name.push(".lock.sqlite");
    let sqlite_path = PathBuf::from(sqlite_name);
    let mut authority_name = path.as_os_str().to_os_string();
    authority_name.push(".lock");
    let authority_path = PathBuf::from(authority_name);
    let parent = path
        .parent()
        .ok_or_else(|| journal_error("Sprout journal lock has no parent"))?;
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
    /// Every independently reduced reconciliation observation, retained so a
    /// first mined sighting can never erase the checkpoint by itself.
    pub observations: Vec<TxObservation>,
    pub legacy_expiry_bound: Option<u32>,
}

impl SproutJournalEntry {
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
                    self.by_txid.remove(&existing.txid());
                    self.order.retain(|existing| *existing != note_id);
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
                    // A v1 acceptance has no raw bytes or expiry; it cannot be
                    // declared final without independently corroborated evidence.
                    match state {
                        TxLifecycleState::SubmissionUnknown => {}
                        TxLifecycleState::Mined
                            if observation
                                .as_ref()
                                .is_some_and(TxObservation::has_canonical_mined_evidence) => {}
                        TxLifecycleState::Expired
                            if observation.as_ref().is_some_and(TxObservation::is_expired)
                                && entry.legacy_expiry_bound.is_some_and(|bound| {
                                    observation.as_ref().and_then(|o| o.expiry_height)
                                        == Some(bound)
                                }) => {}
                        TxLifecycleState::Pending
                            if observation.as_ref().is_some_and(|o| {
                                o.state == crate::broadcast::TxObservationState::PresentUnmined
                            }) => {}
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
                        state: TxLifecycleState::SubmissionUnknown,
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

#[derive(Debug)]
pub struct SweepJournal {
    path: PathBuf,
    network: ZeckNetwork,
    source_fingerprint: String,
    namespace: Option<std::sync::Weak<crate::private_fs::NamespaceLease>>,
}

impl SweepJournal {
    pub fn for_keys(data_dir: &Path, spending_keys: &[[u8; 32]], network: ZeckNetwork) -> Self {
        let short = key_set_fingerprint(spending_keys);
        Self {
            path: data_dir.join(format!("sprout-sweep-{short}.journal")),
            network,
            source_fingerprint: full_key_set_fingerprint(spending_keys),
            namespace: None,
        }
    }

    pub(crate) fn bind_checkpoint_namespace(
        &mut self,
        lease: &crate::sprout_scan_run::CheckpointLease,
    ) -> ZeckResult<()> {
        let namespace = lease.clone_namespace();
        let parent = self
            .path
            .parent()
            .ok_or_else(|| journal_error("Sprout journal has no data directory"))?;
        if namespace.parent_path() != parent {
            return Err(journal_error(
                "checkpoint authority does not bind the sweep journal namespace",
            ));
        }
        self.namespace = Some(std::sync::Arc::downgrade(&namespace));
        Ok(())
    }

    fn bound_namespace(
        &self,
    ) -> ZeckResult<Option<std::sync::Arc<crate::private_fs::NamespaceLease>>> {
        Ok(self.namespace.as_ref().and_then(std::sync::Weak::upgrade))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    fn header(&self) -> SproutJournalRecord {
        SproutJournalRecord::Header {
            version: SPROUT_SWEEP_JOURNAL_VERSION,
            network: self.network,
            source_fingerprint: self.source_fingerprint.clone(),
        }
    }

    pub fn load_or_migrate(&self) -> ZeckResult<SproutJournalSnapshot> {
        let namespace = self.bound_namespace()?;
        with_sweep_journal_lock(&self.path, namespace.as_deref(), |namespace| {
            self.load_or_migrate_unlocked(namespace)
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
        let namespace = self.bound_namespace()?;
        with_sweep_journal_lock(&self.path, namespace.as_deref(), |namespace| {
            let snapshot = self.load_or_migrate_unlocked(namespace)?;
            let mut protected = invocation_outpoints
                .iter()
                .map(note_id)
                .collect::<HashSet<_>>();
            protected.extend(snapshot.entries().map(|entry| note_id(&entry.outpoint)));
            self.reject_overlapping_siblings(namespace, &protected)?;
            Ok(snapshot)
        })
    }

    fn reject_overlapping_siblings(
        &self,
        namespace: &NamespaceLease,
        protected: &HashSet<SproutNoteId>,
    ) -> ZeckResult<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| journal_error("Sprout journal has no data directory"))?;
        let mut siblings = namespace
            .child_names()
            .map_err(|err| journal_error(format!("reading {}: {err}", parent.display())))?
            .into_iter()
            .map(|name| parent.join(name))
            .collect::<Vec<_>>();
        siblings.sort();

        for path in siblings {
            if path == self.path {
                continue;
            }
            let Some(short) = sibling_journal_short_name(&path)? else {
                continue;
            };
            let (network, sibling) = with_sweep_journal_lock(&path, Some(namespace), |namespace| {
                inspect_sibling_journal(namespace, &path, &short)
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
    ) -> ZeckResult<SproutJournalSnapshot> {
        let (bytes, object_id) = match namespace.read_child_version(&self.path) {
            Ok(version) => version,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SproutJournalSnapshot::default())
            }
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
        if first.starts_with('{') {
            self.load_v2(namespace, &object_id, &bytes)
        } else {
            self.migrate_v1(namespace, &object_id, text)
        }
    }

    fn load_v2(
        &self,
        namespace: &NamespaceLease,
        object_id: &PrivateObjectId,
        bytes: &[u8],
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
            } if matches!(version, 2 | SPROUT_SWEEP_JOURNAL_VERSION)
                && network == self.network
                && source_fingerprint == self.source_fingerprint => {}
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

    fn migrate_v1(
        &self,
        namespace: &NamespaceLease,
        object_id: &PrivateObjectId,
        text: &str,
    ) -> ZeckResult<SproutJournalSnapshot> {
        if !text.ends_with('\n') {
            return Err(journal_error("unterminated legacy journal record"));
        }
        let mut snapshot = SproutJournalSnapshot::default();
        let mut upgraded = false;
        for line in text.lines() {
            if upgraded {
                let record = serde_json::from_str::<SproutJournalRecord>(line).map_err(|err| {
                    journal_error(format!("malformed upgraded journal record: {err}"))
                })?;
                snapshot.apply(record, &self.source_fingerprint)?;
                continue;
            }
            if line.starts_with('{') {
                match serde_json::from_str::<SproutJournalRecord>(line).map_err(|err| {
                    journal_error(format!("invalid legacy upgrade delimiter: {err}"))
                })? {
                    SproutJournalRecord::Header {
                        version: SPROUT_SWEEP_JOURNAL_VERSION,
                        network,
                        source_fingerprint,
                    } if network == self.network
                        && source_fingerprint == self.source_fingerprint =>
                    {
                        upgraded = true;
                        continue;
                    }
                    _ => return Err(journal_error("invalid legacy upgrade delimiter")),
                }
            }
            let (note_text, txid) = line
                .split_once(' ')
                .ok_or_else(|| journal_error("malformed legacy journal line"))?;
            if txid.contains(' ') {
                return Err(journal_error("malformed legacy journal line"));
            }
            let mut parts = note_text.split(':');
            let tx = parts
                .next()
                .ok_or_else(|| journal_error("missing legacy note ID"))?;
            let js = parts
                .next()
                .ok_or_else(|| journal_error("missing legacy JoinSplit index"))?
                .parse::<u64>()
                .map_err(|_| journal_error("invalid legacy JoinSplit index"))?;
            let output = parts
                .next()
                .ok_or_else(|| journal_error("missing legacy output index"))?
                .parse::<u8>()
                .map_err(|_| journal_error("invalid legacy output index"))?;
            if parts.next().is_some() || output > 1 {
                return Err(journal_error("malformed legacy outpoint"));
            }
            let id = (decode_txid(tx)?.into(), js, output);
            let txid = decode_txid(txid)?.to_string();
            let record = SproutJournalRecord::LegacyAccepted { note_id: id, txid };
            snapshot.apply(record, &self.source_fingerprint)?;
        }
        if !upgraded {
            let mut delimiter = Vec::new();
            serde_json::to_writer(&mut delimiter, &self.header())
                .map_err(|err| journal_error(format!("encoding legacy upgrade: {err}")))?;
            delimiter.push(b'\n');
            namespace
                .append_child_if_unchanged(
                    &self.path,
                    Some((object_id, text.as_bytes())),
                    &delimiter,
                )
                .map_err(|err| journal_error(format!("syncing legacy upgrade: {err}")))?;
        }
        Ok(snapshot)
    }

    fn append_unlocked(
        &self,
        namespace: &NamespaceLease,
        record: &SproutJournalRecord,
    ) -> ZeckResult<()> {
        let mut version = match namespace.read_child_version(&self.path) {
            Ok((bytes, id)) => Some((bytes, id)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(journal_error(format!("opening journal: {err}"))),
        };
        let mut suffix = Vec::new();
        if version.as_ref().is_none_or(|(bytes, _)| bytes.is_empty()) {
            serde_json::to_writer(&mut suffix, &self.header())
                .map_err(|err| journal_error(format!("writing journal header: {err}")))?;
            suffix.push(b'\n');
        }
        serde_json::to_writer(&mut suffix, record)
            .map_err(|err| journal_error(format!("writing journal event: {err}")))?;
        suffix.push(b'\n');
        namespace
            .append_child_if_unchanged(
                &self.path,
                version.as_mut().map(|(bytes, id)| (&*id, bytes.as_slice())),
                &suffix,
            )
            .map_err(|err| journal_error(format!("syncing journal event: {err}")))
    }

    fn upgrade_header_unlocked(&self, namespace: &NamespaceLease) -> ZeckResult<()> {
        // Both v2 headers and append-upgraded v1 journals remain physically
        // unchanged. Their loaders already validated the durable prefix, and
        // new v3 records make older readers fail closed without a rewrite.
        let _ = namespace;
        Ok(())
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
        let namespace = self.bound_namespace()?;
        with_sweep_journal_lock(&self.path, namespace.as_deref(), |namespace| {
            // The caller may have loaded before another process wrote.
            // Replay under the lock; only this current durable state can
            // authorize the next event.
            let mut durable = self.load_or_migrate_unlocked(namespace)?;
            *snapshot = durable.clone();
            durable.apply(record.clone(), &self.source_fingerprint)?;
            self.upgrade_header_unlocked(namespace)?;
            self.append_unlocked(namespace, &record)?;
            *snapshot = durable;
            Ok(())
        })
    }

    pub fn append_transition(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        txid: TxId,
        state: TxLifecycleState,
        submission: Option<&SubmissionDisposition>,
        observation: Option<&TxObservation>,
    ) -> ZeckResult<()> {
        let record = SproutJournalRecord::Transition {
            txid: txid.to_string(),
            state,
            submission: submission.cloned(),
            observation: observation.cloned(),
        };
        self.mutate(snapshot, record)
    }

    pub fn append_legacy_expiry_bound(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        txid: TxId,
        verified_tip: u32,
        expiry_bound: u32,
    ) -> ZeckResult<()> {
        let record = SproutJournalRecord::LegacyExpiryBound {
            txid: txid.to_string(),
            verified_tip,
            expiry_bound,
        };
        self.mutate(snapshot, record)
    }

    /// Durably bind an exact checkpoint object to every note it may recreate.
    /// Repeated records only add members; they can never shrink a manifest.
    pub fn record_checkpoint_manifest<'a>(
        &self,
        snapshot: &mut SproutJournalSnapshot,
        generation: &CheckpointGeneration,
        notes: impl IntoIterator<Item = &'a JsOutPoint>,
    ) -> ZeckResult<()> {
        let note_ids = notes.into_iter().map(note_id).collect::<BTreeSet<_>>();
        self.record_checkpoint_manifest_ids(snapshot, generation, note_ids)
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
            self.append_unlocked(namespace, &tombstone)?;
        }
        Ok(())
    }

    /// Make the final decision, marker, compaction and deletion one journal
    /// critical section. The caller additionally holds the network guard and
    /// checkpoint lease, giving a single lock order for all cleanup paths.
    pub fn finalize_checkpoint_cleanup(
        &self,
        lease: &crate::sprout_scan_run::CheckpointLease,
        generation: &CheckpointGeneration,
        checkpoint: &Path,
    ) -> ZeckResult<CheckpointCleanupResult> {
        let namespace = lease.clone_namespace();
        with_sweep_journal_lock(&self.path, Some(&namespace), |namespace| {
            lease.verify_for(checkpoint)?;
            let mut snapshot = self.load_or_migrate_unlocked(namespace)?;
            match lease.generation_if_present(checkpoint)? {
                Some(current) if &current != generation => {
                    return Ok(CheckpointCleanupResult::Retain {
                        reason: "the checkpoint generation changed after review".into(),
                    })
                }
                Some(_) => {}
                None if snapshot.discard_started.contains(generation) => {
                    // A crash may have happened after unlink but before the
                    // completion marker. The synced start marker and exact
                    // generation authorize only idempotent finalization.
                }
                None => {
                    return Err(journal_error(
                        "checkpoint disappeared before cleanup was authorized",
                    ))
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
                    return Ok(CheckpointCleanupResult::Retain { reason })
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
                self.append_unlocked(namespace, &marker)?;
            }
            self.compact_unlocked(namespace, &snapshot, generation)?;
            let discarded = crate::sprout_scan_run::discard_checkpoint_generation_while_leased(
                lease, checkpoint, generation,
            )?;
            #[cfg(test)]
            if FAIL_AFTER_CHECKPOINT_DISCARD
                .lock()
                .unwrap()
                .take_if(|failing| failing == checkpoint)
                .is_some()
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
                self.append_unlocked(namespace, &completed)?;
            }
            match discarded {
                crate::sprout_scan_run::CheckpointDiscard::Removed => {
                    Ok(CheckpointCleanupResult::Removed)
                }
                crate::sprout_scan_run::CheckpointDiscard::AlreadyAbsent => {
                    Ok(CheckpointCleanupResult::AlreadyAbsent)
                }
            }
        })
    }

    /// Reconcile cleanup that already crossed the durable discard marker.
    /// A surviving canonical generation is retained, and an exact deletion
    /// quarantine is restored: observations recorded before arbitrary
    /// downtime never authorize a restart-time deletion. Completion is
    /// idempotent only after the manifested generation is already absent from
    /// both the canonical path and every deletion quarantine.
    pub fn resume_checkpoint_cleanup(
        &self,
        lease: &crate::sprout_scan_run::CheckpointLease,
        checkpoint: &Path,
    ) -> ZeckResult<Option<CheckpointCleanupResult>> {
        let namespace = lease.clone_namespace();
        with_sweep_journal_lock(&self.path, Some(&namespace), |namespace| {
            lease.verify_for(checkpoint)?;
            let mut snapshot = self.load_or_migrate_unlocked(namespace)?;
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
            let current_generation = lease.generation_if_present(checkpoint)?;
            if current_generation.as_ref() == Some(generation) {
                return Ok(Some(CheckpointCleanupResult::Retain {
                    reason: "the exact checkpoint generation survived restart; fresh reconciliation and review are required before cleanup".into(),
                }));
            }
            let replacement_present = current_generation.is_some();
            let quarantine_paths = checkpoint_discard_quarantines(namespace, checkpoint)?;
            let mut matching_quarantine = None;
            let mut unexpected_quarantine = false;
            for quarantine in quarantine_paths {
                let (file, current) = retained_quarantine_generation(namespace, &quarantine)?;
                if &current == generation {
                    if matching_quarantine.is_some() {
                        return Ok(Some(CheckpointCleanupResult::Retain {
                            reason: "multiple exact checkpoint deletion quarantines survived restart; all were preserved for manual review".into(),
                        }));
                    }
                    matching_quarantine = Some((quarantine, file, current));
                } else {
                    unexpected_quarantine = true;
                }
            }
            if let Some((quarantine, file, current)) = matching_quarantine {
                if replacement_present {
                    return Ok(Some(CheckpointCleanupResult::Retain {
                        reason: "a replacement checkpoint and the old exact deletion quarantine both survived restart; both were preserved for manual review".into(),
                    }));
                }
                namespace
                    .rename_open_child(&quarantine, checkpoint, &file, &current.object)
                    .and_then(|()| namespace.sync_parent())
                    .map_err(|err| {
                        journal_error(format!(
                            "restoring exact checkpoint quarantine {}: {err}",
                            quarantine.display()
                        ))
                    })?;
                return Ok(Some(CheckpointCleanupResult::Retain {
                    reason: "the exact checkpoint deletion quarantine was restored after restart; fresh reconciliation and review are required before cleanup".into(),
                }));
            }
            if unexpected_quarantine {
                return Ok(Some(CheckpointCleanupResult::Retain {
                    reason: "an unexpected checkpoint deletion quarantine survived restart and was preserved for manual review".into(),
                }));
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
                    return Ok(Some(CheckpointCleanupResult::Retain { reason }))
                }
                CheckpointCleanupEligibility::Eligible { .. } => {}
            }
            self.compact_unlocked(namespace, &snapshot, generation)?;
            if replacement_present {
                // The old generation crossed its durable discard boundary,
                // but a new source was restored before restart recovery. Mark
                // the old cleanup complete without touching the replacement.
                let completed = SproutJournalRecord::CheckpointDiscarded {
                    source_fingerprint: self.source_fingerprint.clone(),
                    generation: generation.clone(),
                };
                snapshot.apply(completed.clone(), &self.source_fingerprint)?;
                self.append_unlocked(namespace, &completed)?;
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
            self.append_unlocked(namespace, &completed)?;
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

fn inspect_sibling_journal(
    namespace: &NamespaceLease,
    path: &Path,
    filename_short: &str,
) -> ZeckResult<(Option<ZeckNetwork>, SproutJournalSnapshot)> {
    let bytes = namespace.read_child(path).map_err(|err| {
        journal_error(format!(
            "refusing symlink or irregular sibling journal {}: {err}",
            path.display()
        ))
    })?;
    if bytes.is_empty() {
        return Err(journal_error("empty sibling journal"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| journal_error("sibling journal is not UTF-8"))?;
    if text.lines().next().unwrap_or_default().starts_with('{') {
        inspect_v2_sibling(&bytes, filename_short)
    } else {
        inspect_v1_sibling(text, filename_short).map(|snapshot| (None, snapshot))
    }
}

fn inspect_v2_sibling(
    bytes: &[u8],
    filename_short: &str,
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
            version: 2 | SPROUT_SWEEP_JOURNAL_VERSION,
            network,
            source_fingerprint,
        } => (network, source_fingerprint),
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

fn inspect_v1_sibling(text: &str, filename_short: &str) -> ZeckResult<SproutJournalSnapshot> {
    if !text.ends_with('\n') {
        return Err(journal_error("unterminated legacy sibling journal record"));
    }
    let fingerprint = format!("legacy:{filename_short}");
    let mut snapshot = SproutJournalSnapshot::default();
    for line in text.lines() {
        let (note_text, txid) = line
            .split_once(' ')
            .ok_or_else(|| journal_error("malformed legacy sibling journal line"))?;
        if txid.contains(' ') {
            return Err(journal_error("malformed legacy sibling journal line"));
        }
        let mut parts = note_text.split(':');
        let tx = parts
            .next()
            .ok_or_else(|| journal_error("missing legacy sibling note ID"))?;
        let js = parts
            .next()
            .ok_or_else(|| journal_error("missing legacy sibling JoinSplit index"))?
            .parse::<u64>()
            .map_err(|_| journal_error("invalid legacy sibling JoinSplit index"))?;
        let output = parts
            .next()
            .ok_or_else(|| journal_error("missing legacy sibling output index"))?
            .parse::<u8>()
            .map_err(|_| journal_error("invalid legacy sibling output index"))?;
        if parts.next().is_some() || output > 1 {
            return Err(journal_error("malformed legacy sibling outpoint"));
        }
        snapshot.apply(
            SproutJournalRecord::LegacyAccepted {
                note_id: (decode_txid(tx)?.into(), js, output),
                txid: decode_txid(txid)?.to_string(),
            },
            &fingerprint,
        )?;
    }
    Ok(snapshot)
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
        TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: Some(expiry_height),
            primary_tip: Some(expiry_height + 1),
            secondary_tip: Some(expiry_height + 1),
            evidence: ["a", "b"]
                .into_iter()
                .map(|label| EndpointTxEvidence {
                    operator_id: label.to_owned(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(expiry_height + 1),
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

    fn journal(dir: &std::path::Path) -> SweepJournal {
        SweepJournal::for_keys(dir, &[[0x42; 32]], ZeckNetwork::Mainnet)
    }

    fn write_private_fixture(path: &Path, bytes: impl AsRef<[u8]>) {
        crate::private_fs::write_private_file(path, bytes.as_ref()).unwrap();
    }

    fn legacy_line(sweep_txid: &str) -> String {
        format!("{}:3:1 {sweep_txid}\n", "42".repeat(32))
    }

    fn checkpoint_generation(dir: &Path, label: &[u8]) -> CheckpointGeneration {
        let path = dir.join("scan.checkpoint");
        crate::private_fs::write_private_file(&path, label).unwrap();
        crate::sprout_scan_run::checkpoint_generation(&path).unwrap()
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

        let path = dir.path().join("scan.checkpoint");
        let replacement = dir.path().join("replacement");
        crate::private_fs::write_private_file(&replacement, b"checkpoint-a").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let replaced = crate::sprout_scan_run::checkpoint_generation(&path).unwrap();
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
    fn v2_journal_loads_without_inventing_a_checkpoint_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        let text = std::fs::read_to_string(journal.path()).unwrap();
        std::fs::write(
            journal.path(),
            text.replacen("\"version\":3", "\"version\":2", 1),
        )
        .unwrap();
        let snapshot = journal.load_or_migrate().unwrap();
        assert!(snapshot.checkpoint_manifest(&generation).is_none());
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &BTreeSet::from([note_id(&outpoint())])
            ),
            CheckpointCleanupEligibility::Retain { .. }
        ));

        let mut snapshot = snapshot;
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
            .unwrap();
        let text = std::fs::read_to_string(journal.path()).unwrap();
        let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .checkpoint_manifest(&generation)
                .unwrap()
                .note_ids,
            BTreeSet::from([note_id(&outpoint())])
        );
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
    fn legacy_v1_acceptance_never_authorizes_checkpoint_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let transaction = fixture();
        crate::private_fs::write_private_file(
            journal.path(),
            legacy_line(&transaction.txid.to_string()).as_bytes(),
        )
        .unwrap();
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &generation, [&outpoint()])
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
        assert!(matches!(
            snapshot.checkpoint_cleanup_eligibility(
                journal.source_fingerprint(),
                &generation,
                &BTreeSet::from([note_id(&outpoint())])
            ),
            CheckpointCleanupEligibility::Retain { reason }
                if reason.contains("legacy acceptance")
        ));
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
        let generation = checkpoint_generation(dir.path(), b"checkpoint-a");
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
        let checkpoint = dir.path().join("scan.checkpoint");
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
        let checkpoint = dir.path().join("scan.checkpoint");
        crate::private_fs::write_private_file(&checkpoint, b"checkpoint-a").unwrap();
        let original = std::fs::read(&checkpoint).unwrap();
        let generation = crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
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
    fn cleanup_restart_restores_a_surviving_exact_quarantine() {
        use sha2::Digest as _;

        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("scan.checkpoint");
        crate::private_fs::write_private_file(&checkpoint, b"checkpoint-a").unwrap();
        let original = std::fs::read(&checkpoint).unwrap();
        let generation = crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
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
        journal
            .mutate(
                &mut snapshot,
                SproutJournalRecord::CheckpointDiscardStarted {
                    source_fingerprint: journal.source_fingerprint().to_owned(),
                    generation: generation.clone(),
                    reorg_window: SPROUT_REORG_WINDOW as u32,
                },
            )
            .unwrap();

        // Simulate a crash after the exact checkpoint was renamed into its
        // deletion quarantine but before that retained handle was unlinked.
        let name = checkpoint.file_name().unwrap();
        let prefix = format!(
            ".argos-checkpoint-discard-{:x}-",
            sha2::Sha256::digest(name.as_encoded_bytes())
        );
        let quarantine = dir.path().join(format!("{prefix}{}", uuid::Uuid::new_v4()));
        std::fs::rename(&checkpoint, &quarantine).unwrap();

        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        let result = journal
            .resume_checkpoint_cleanup(&lease, &checkpoint)
            .unwrap();
        assert!(matches!(
            result,
            Some(CheckpointCleanupResult::Retain { ref reason })
                if reason.contains("restored") && reason.contains("fresh reconciliation")
        ));
        assert_eq!(std::fs::read(&checkpoint).unwrap(), original);
        assert_eq!(lease.generation(&checkpoint).unwrap(), generation);
        assert!(!quarantine.exists());
        drop(lease);

        let restored = journal.load_or_migrate().unwrap();
        assert!(restored.discard_started.contains(&generation));
        assert!(!restored.discarded_checkpoints.contains(&generation));
    }

    #[test]
    fn cleanup_restart_preserves_replacement_and_old_exact_quarantine() {
        use sha2::Digest as _;

        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("scan.checkpoint");
        crate::private_fs::write_private_file(&checkpoint, b"checkpoint-a").unwrap();
        let old_generation = crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
        let journal = journal(dir.path());
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .record_checkpoint_manifest(&mut snapshot, &old_generation, [&outpoint()])
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
        journal
            .mutate(
                &mut snapshot,
                SproutJournalRecord::CheckpointDiscardStarted {
                    source_fingerprint: journal.source_fingerprint().to_owned(),
                    generation: old_generation.clone(),
                    reorg_window: SPROUT_REORG_WINDOW as u32,
                },
            )
            .unwrap();

        let name = checkpoint.file_name().unwrap();
        let prefix = format!(
            ".argos-checkpoint-discard-{:x}-",
            sha2::Sha256::digest(name.as_encoded_bytes())
        );
        let quarantine = dir.path().join(format!("{prefix}{}", uuid::Uuid::new_v4()));
        std::fs::rename(&checkpoint, &quarantine).unwrap();
        crate::private_fs::write_private_file(&checkpoint, b"replacement checkpoint").unwrap();

        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();
        let result = journal
            .resume_checkpoint_cleanup(&lease, &checkpoint)
            .unwrap();
        assert!(matches!(
            result,
            Some(CheckpointCleanupResult::Retain { ref reason })
                if reason.contains("replacement") && reason.contains("quarantine")
        ));
        assert_eq!(
            std::fs::read(&checkpoint).unwrap(),
            b"replacement checkpoint"
        );
        assert_eq!(std::fs::read(&quarantine).unwrap(), b"checkpoint-a");
        drop(lease);

        let restored = journal.load_or_migrate().unwrap();
        assert!(restored.discard_started.contains(&old_generation));
        assert!(!restored.discarded_checkpoints.contains(&old_generation));
    }

    #[test]
    fn cleanup_restart_after_unlink_commits_an_idempotent_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("scan.checkpoint");
        crate::private_fs::write_private_file(&checkpoint, b"checkpoint-a").unwrap();
        let generation = crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
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
        journal
            .mutate(
                &mut snapshot,
                SproutJournalRecord::CheckpointDiscardStarted {
                    source_fingerprint: journal.source_fingerprint().to_owned(),
                    generation: generation.clone(),
                    reorg_window: SPROUT_REORG_WINDOW as u32,
                },
            )
            .unwrap();
        std::fs::remove_file(&checkpoint).unwrap();
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();

        assert_eq!(
            journal
                .finalize_checkpoint_cleanup(&lease, &generation, &checkpoint)
                .unwrap(),
            CheckpointCleanupResult::AlreadyAbsent
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
        let checkpoint = dir.path().join("scan.checkpoint");
        crate::private_fs::write_private_file(&checkpoint, b"checkpoint-a").unwrap();
        let generation = crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
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
        journal
            .mutate(
                &mut snapshot,
                SproutJournalRecord::CheckpointDiscardStarted {
                    source_fingerprint: journal.source_fingerprint().to_owned(),
                    generation: generation.clone(),
                    reorg_window: SPROUT_REORG_WINDOW as u32,
                },
            )
            .unwrap();
        crate::private_fs::write_private_file(&checkpoint, b"replacement checkpoint source")
            .unwrap();
        let lease = crate::sprout_scan_run::CheckpointLease::acquire(&checkpoint).unwrap();

        let result = journal
            .resume_checkpoint_cleanup(&lease, &checkpoint)
            .unwrap();
        assert!(matches!(
            result,
            Some(CheckpointCleanupResult::Retain { ref reason })
                if reason.contains("replacement checkpoint")
        ));
        assert_eq!(
            std::fs::read(&checkpoint).unwrap(),
            b"replacement checkpoint source"
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
        let checkpoint = dir.path().join("scan.checkpoint");
        crate::private_fs::write_private_file(&checkpoint, b"checkpoint-a").unwrap();
        let generation = crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
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

        crate::private_fs::write_private_file(&checkpoint, b"restored checkpoint source").unwrap();
        let restored_generation =
            crate::sprout_scan_run::checkpoint_generation(&checkpoint).unwrap();
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
    fn v2_prepared_record_round_trips_every_safety_field() {
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
        assert_eq!(header["version"], 3);
        assert_eq!(header["network"], "mainnet");
        assert_eq!(
            header["source_fingerprint"],
            full_key_set_fingerprint(&[[0x42; 32]])
        );
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
        assert!(
            SweepJournal::for_keys(dir.path(), &[[0x42; 32]], ZeckNetwork::Testnet)
                .load_or_migrate()
                .is_err()
        );
        let other = SweepJournal::for_keys(dir.path(), &[[0x43; 32]], ZeckNetwork::Mainnet);
        std::fs::copy(journal.path(), other.path()).unwrap();
        assert!(other.load_or_migrate().is_err());
    }

    #[test]
    fn scoped_load_strictly_validates_sibling_header_and_raw_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let current = SweepJournal::for_keys(dir.path(), &[[0x43; 32]], ZeckNetwork::Mainnet);
        let sibling = journal(dir.path());
        let mut snapshot = sibling.load_or_migrate().unwrap();
        sibling
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();

        let mismatched = dir.path().join("sprout-sweep-deadbeefdeadbeef.journal");
        std::fs::rename(sibling.path(), &mismatched).unwrap();
        let err = current
            .load_scoped_snapshot(&[outpoint()])
            .expect_err("filename must authenticate the full fingerprint")
            .to_string();
        assert!(
            err.contains("fingerprint") && err.contains("filename"),
            "{err}"
        );

        std::fs::rename(&mismatched, sibling.path()).unwrap();
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
        let sibling = SweepJournal::for_keys(dir.path(), &[[0x43; 32]], ZeckNetwork::Testnet);
        let mut snapshot = sibling.load_or_migrate().unwrap();
        sibling
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        current
            .load_scoped_snapshot(&[outpoint()])
            .expect("a valid other-network sibling cannot claim this network's note");
    }

    #[cfg(unix)]
    #[test]
    fn scoped_load_rejects_a_symlinked_sibling() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let current = journal(dir.path());
        let target = dir.path().join("outside");
        std::fs::write(&target, b"not a journal\n").unwrap();
        let sibling = dir.path().join("sprout-sweep-deadbeefdeadbeef.journal");
        symlink(&target, &sibling).unwrap();
        let err = current
            .load_scoped_snapshot(&[])
            .expect_err("sibling symlinks fail closed")
            .to_string();
        assert!(err.contains("symlink") && err.contains(&sibling.display().to_string()));
    }

    #[test]
    fn store_refuses_to_append_to_an_existing_journal_with_another_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mainnet = journal(dir.path());
        let mut snapshot = mainnet.load_or_migrate().unwrap();
        mainnet
            .scoped_store(context(), &mut snapshot)
            .persist_prepared(&fixture())
            .unwrap();
        let testnet = SweepJournal::for_keys(dir.path(), &[[0x42; 32]], ZeckNetwork::Testnet);
        let original = std::fs::read(testnet.path()).unwrap();
        let mut empty = SproutJournalSnapshot::default();
        assert!(testnet
            .scoped_store(context(), &mut empty)
            .persist_prepared(&fixture())
            .is_err());
        assert_eq!(std::fs::read(testnet.path()).unwrap(), original);
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
    fn v1_accepted_entry_migrates_to_submission_unknown_not_mined() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let txid = fixture().txid;
        write_private_fixture(journal.path(), legacy_line(&txid.to_string()));
        let snapshot = journal.load_or_migrate().unwrap();
        let entry = snapshot.entry_for_note(&outpoint()).unwrap();
        assert_eq!(entry.legacy_txid, Some(txid));
        assert!(entry.transaction.is_none());
        assert_eq!(entry.state, TxLifecycleState::SubmissionUnknown);
        assert!(!snapshot.all_mined_for([&outpoint()]));
        let upgraded = std::fs::read_to_string(journal.path()).unwrap();
        assert!(upgraded.starts_with(&legacy_line(&txid.to_string())));
        assert!(upgraded.contains("{\"record\":\"header\""));
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
    fn v1_accepted_entry_waits_for_a_conservative_expiry_horizon() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        write_private_fixture(journal.path(), legacy_line(&fixture().txid.to_string()));
        let snapshot = journal.load_or_migrate().unwrap();
        let entry = snapshot.entry_for_note(&outpoint()).unwrap();
        assert_eq!(entry.state, TxLifecycleState::SubmissionUnknown);
        assert_eq!(entry.legacy_expiry_bound, None);
        assert!(!snapshot.ready_for_new_plan(&outpoint()));
    }

    #[test]
    fn duplicate_identical_v1_lines_coalesce_but_conflicting_txids_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let txid = fixture().txid.to_string();
        let line = legacy_line(&txid);
        write_private_fixture(journal.path(), format!("{line}{line}"));
        assert_eq!(journal.load_or_migrate().unwrap().entries().count(), 1);
        let conflict = TxId::from_bytes([0x55; 32]).to_string();
        write_private_fixture(journal.path(), format!("{line}{}", legacy_line(&conflict)));
        assert!(journal.load_or_migrate().is_err());
    }

    #[test]
    fn invalid_v1_migration_leaves_original_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let original = format!(
            "{}{}",
            legacy_line(&fixture().txid.to_string()),
            legacy_line(&TxId::from_bytes([0x55; 32]).to_string())
        );
        write_private_fixture(journal.path(), &original);
        assert!(journal.load_or_migrate().is_err());
        assert_eq!(std::fs::read_to_string(journal.path()).unwrap(), original);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn v1_migration_rejects_a_world_readable_file_without_repairing_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let original = legacy_line(&fixture().txid.to_string());
        write_private_fixture(journal.path(), &original);
        std::fs::set_permissions(journal.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let original_id =
            crate::private_fs::private_object_id(&std::fs::File::open(journal.path()).unwrap())
                .unwrap();
        let error = journal.load_or_migrate().unwrap_err().to_string();
        assert!(error.contains("mode 600"), "{error}");
        assert_eq!(std::fs::read_to_string(journal.path()).unwrap(), original);
        assert_eq!(
            crate::private_fs::private_object_id(&std::fs::File::open(journal.path()).unwrap())
                .unwrap(),
            original_id
        );
        let mode = std::fs::metadata(journal.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn malformed_complete_line_blocks_broadcast() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        write_private_fixture(
            journal.path(),
            format!("{}not a record\n", legacy_line(&fixture().txid.to_string())),
        );
        assert!(journal.load_or_migrate().is_err());
    }

    #[test]
    fn torn_final_v2_transition_fails_closed_without_rewriting_history() {
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
        use crate::broadcast::{EndpointTxEvidence, TxObservationState};
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
        let absence = TxObservation {
            state: TxObservationState::Absent,
            mined_height: None,
            expiry_height: first.expiry_height,
            primary_tip: Some(101),
            secondary_tip: Some(101),
            evidence: ["a", "b"]
                .into_iter()
                .map(|label| EndpointTxEvidence {
                    operator_id: label.to_owned(),
                    endpoint: format!("https://{label}.example"),
                    tip_height: Some(101),
                    reported_height: None,
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
        };
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
    fn separate_connection_lock_blocks_migration_and_append() {
        use std::sync::mpsc;
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        write_private_fixture(journal.path(), legacy_line(&fixture().txid.to_string()));
        let lock_path =
            std::path::PathBuf::from(format!("{}.lock.sqlite", journal.path().display()));
        crate::private_fs::write_private_file(&lock_path, b"").unwrap();
        let connection = rusqlite::Connection::open(&lock_path).unwrap();
        connection
            .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
            .unwrap();
        let (sender, receiver) = mpsc::channel();
        let other = SweepJournal::for_keys(dir.path(), &[[0x42; 32]], ZeckNetwork::Mainnet);
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
        let other = SweepJournal::for_keys(dir.path(), &[[0x42; 32]], ZeckNetwork::Mainnet);
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
        let mut authority_name = journal.path().as_os_str().to_os_string();
        authority_name.push(".lock");
        let authority = PathBuf::from(authority_name);
        let displaced = authority.with_extension("displaced-lock");

        with_sweep_journal_lock(journal.path(), None, |_| {
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

    #[test]
    fn legacy_expiry_bound_must_be_exactly_the_protocol_window() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let txid = fixture().txid;
        write_private_fixture(journal.path(), legacy_line(&txid.to_string()));
        let mut snapshot = journal.load_or_migrate().unwrap();
        assert!(journal
            .append_legacy_expiry_bound(&mut snapshot, txid, 100, 101)
            .is_err());
        assert_eq!(
            snapshot.entry_for_txid(txid).unwrap().legacy_expiry_bound,
            None
        );
        journal
            .append_legacy_expiry_bound(&mut snapshot, txid, 100, 140)
            .unwrap();
        assert_eq!(
            snapshot.entry_for_txid(txid).unwrap().legacy_expiry_bound,
            Some(140)
        );
    }

    #[test]
    fn legacy_upgrade_is_append_only_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let original = legacy_line(&fixture().txid.to_string());
        write_private_fixture(journal.path(), &original);
        let original_id =
            crate::private_fs::private_object_id(&std::fs::File::open(journal.path()).unwrap())
                .unwrap();
        let snapshot = journal.load_or_migrate().unwrap();
        assert_eq!(snapshot.entries().count(), 1);
        let upgraded = std::fs::read_to_string(journal.path()).unwrap();
        assert!(upgraded.starts_with(&original));
        assert_eq!(upgraded.matches("\"record\":\"header\"").count(), 1);
        assert_eq!(
            crate::private_fs::private_object_id(&std::fs::File::open(journal.path()).unwrap())
                .unwrap(),
            original_id
        );
        assert_eq!(journal.load_or_migrate().unwrap().entries().count(), 1);
    }
}
