//! Durable, versioned Sprout sweep transactions, keyed by note and source.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Cursor, Write},
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
    private_fs::{open_private_file, PrivateOpenMode},
    sprout_scan_run::{full_key_set_fingerprint, key_set_fingerprint},
};

pub const SPROUT_SWEEP_JOURNAL_VERSION: u32 = 2;
pub const SPROUT_EXPIRY_DELTA: u32 = 40;
pub type SproutNoteId = ([u8; 32], u64, u8);

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
    operation: impl FnOnce() -> ZeckResult<T>,
) -> ZeckResult<T> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock.sqlite");
    let lock_path = PathBuf::from(name);
    drop(
        open_private_file(&lock_path, PrivateOpenMode::Append).map_err(|err| {
            journal_error(format!(
                "opening sweep journal lock {}: {err}",
                lock_path.display()
            ))
        })?,
    );
    let connection = rusqlite::Connection::open(&lock_path).map_err(|err| {
        journal_error(format!(
            "opening sweep journal lock {}: {err}",
            lock_path.display()
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
    let result = operation();
    drop(connection);
    result
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
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct JournalNoteContext {
    pub outpoint: JsOutPoint,
    pub value_zatoshis: u64,
}

#[derive(Debug, Clone)]
pub struct SweepJournal {
    path: PathBuf,
    network: ZeckNetwork,
    source_fingerprint: String,
}

impl SweepJournal {
    pub fn for_keys(data_dir: &Path, spending_keys: &[[u8; 32]], network: ZeckNetwork) -> Self {
        let short = key_set_fingerprint(spending_keys);
        Self {
            path: data_dir.join(format!("sprout-sweep-{short}.journal")),
            network,
            source_fingerprint: full_key_set_fingerprint(spending_keys),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn header(&self) -> SproutJournalRecord {
        SproutJournalRecord::Header {
            version: SPROUT_SWEEP_JOURNAL_VERSION,
            network: self.network,
            source_fingerprint: self.source_fingerprint.clone(),
        }
    }

    pub fn load_or_migrate(&self) -> ZeckResult<SproutJournalSnapshot> {
        with_sweep_journal_lock(&self.path, || self.load_or_migrate_unlocked())
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
        let snapshot = self.load_or_migrate()?;
        let mut protected = invocation_outpoints
            .iter()
            .map(note_id)
            .collect::<HashSet<_>>();
        protected.extend(snapshot.entries().map(|entry| note_id(&entry.outpoint)));
        self.reject_overlapping_siblings(&protected)?;
        Ok(snapshot)
    }

    fn reject_overlapping_siblings(&self, protected: &HashSet<SproutNoteId>) -> ZeckResult<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| journal_error("Sprout journal has no data directory"))?;
        let mut siblings = fs::read_dir(parent)
            .map_err(|err| journal_error(format!("reading {}: {err}", parent.display())))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|err| journal_error(format!("reading {}: {err}", parent.display())))
            })
            .collect::<ZeckResult<Vec<_>>>()?;
        siblings.sort();

        for path in siblings {
            if path == self.path {
                continue;
            }
            let Some(short) = sibling_journal_short_name(&path)? else {
                continue;
            };
            let metadata = fs::symlink_metadata(&path).map_err(|err| {
                journal_error(format!(
                    "inspecting sibling journal {}: {err}",
                    path.display()
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(journal_error(format!(
                    "sibling Sprout journal {} is a symlink or irregular file; preserve the original key set and data dir and inspect it before sweeping",
                    path.display()
                )));
            }
            let (network, sibling) =
                with_sweep_journal_lock(&path, || inspect_sibling_journal(&path, &short)).map_err(
                    |err| {
                        journal_error(format!(
                            "cannot safely inspect sibling Sprout journal {}: {err}",
                            path.display()
                        ))
                    },
                )?;
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

    fn load_or_migrate_unlocked(&self) -> ZeckResult<SproutJournalSnapshot> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
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
            self.load_v2(&bytes)
        } else {
            self.migrate_v1(text)
        }
    }

    fn load_v2(&self, bytes: &[u8]) -> ZeckResult<SproutJournalSnapshot> {
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
            } if version == SPROUT_SWEEP_JOURNAL_VERSION
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
            // A synced event always ends in a newline. Remove only the
            // trailing unsynced bytes, so a later append cannot turn them
            // into a malformed complete record or invent a transition.
            let complete_len = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .expect("header was terminated")
                + 1;
            let file = open_private_file(&self.path, PrivateOpenMode::Append)
                .map_err(|err| journal_error(format!("opening torn journal: {err}")))?;
            file.set_len(complete_len as u64)
                .and_then(|_| file.sync_all())
                .map_err(|err| journal_error(format!("repairing torn journal: {err}")))?;
        }
        Ok(snapshot)
    }

    fn migrate_v1(&self, text: &str) -> ZeckResult<SproutJournalSnapshot> {
        if !text.ends_with('\n') {
            return Err(journal_error("unterminated legacy journal record"));
        }
        let mut snapshot = SproutJournalSnapshot::default();
        let mut records = vec![self.header()];
        for line in text.lines() {
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
            snapshot.apply(record.clone(), &self.source_fingerprint)?;
            if !records.iter().any(|item| matches!(item, SproutJournalRecord::LegacyAccepted { note_id, .. } if *note_id == id)) {
                records.push(record);
            }
        }
        let mut data = Vec::new();
        for record in records {
            serde_json::to_writer(&mut data, &record)
                .map_err(|err| journal_error(format!("encoding journal: {err}")))?;
            data.push(b'\n');
        }
        self.atomic_replace_if_unchanged(text.as_bytes(), &data)?;
        Ok(snapshot)
    }

    fn atomic_replace_if_unchanged(&self, expected: &[u8], bytes: &[u8]) -> ZeckResult<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| journal_error("journal has no parent"))?;
        let temporary = parent.join(format!(".sprout-sweep-migrate-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = open_private_file(&temporary, PrivateOpenMode::CreateNew)
                .map_err(|err| journal_error(format!("creating migration file: {err}")))?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|err| journal_error(format!("syncing migration file: {err}")))?;
            if fs::read(&self.path)
                .map_err(|err| journal_error(format!("rechecking legacy journal: {err}")))?
                != expected
            {
                return Err(journal_error(
                    "legacy journal changed during migration; retry after preserving the source",
                ));
            }
            fs::rename(&temporary, &self.path)
                .map_err(|err| journal_error(format!("replacing journal: {err}")))?;
            fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|err| journal_error(format!("syncing journal directory: {err}")))
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn append_unlocked(&self, record: &SproutJournalRecord) -> ZeckResult<()> {
        let missing = !self.path.exists();
        let mut file = open_private_file(&self.path, PrivateOpenMode::Append)
            .map_err(|err| journal_error(format!("opening journal: {err}")))?;
        if missing
            || file
                .metadata()
                .map_err(|err| journal_error(format!("journal metadata: {err}")))?
                .len()
                == 0
        {
            serde_json::to_writer(&mut file, &self.header())
                .map_err(|err| journal_error(format!("writing journal header: {err}")))?;
            file.write_all(b"\n")
                .and_then(|_| file.flush())
                .and_then(|_| file.sync_all())
                .map_err(|err| journal_error(format!("syncing journal header: {err}")))?;
            fs::File::open(self.path.parent().expect("journal path has parent"))
                .and_then(|dir| dir.sync_all())
                .map_err(|err| journal_error(format!("syncing journal directory: {err}")))?;
        }
        serde_json::to_writer(&mut file, record)
            .map_err(|err| journal_error(format!("writing journal event: {err}")))?;
        file.write_all(b"\n")
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
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
        with_sweep_journal_lock(&self.path, || {
            // The caller may have loaded before another process wrote.
            // Replay under the lock; only this current durable state can
            // authorize the next event.
            let mut durable = self.load_or_migrate_unlocked()?;
            *snapshot = durable.clone();
            durable.apply(record.clone(), &self.source_fingerprint)?;
            self.append_unlocked(&record)?;
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
    path: &Path,
    filename_short: &str,
) -> ZeckResult<(Option<ZeckNetwork>, SproutJournalSnapshot)> {
    let bytes = fs::read(path)
        .map_err(|err| journal_error(format!("reading {}: {err}", path.display())))?;
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
            version,
            network,
            source_fingerprint,
        } if version == SPROUT_SWEEP_JOURNAL_VERSION => (network, source_fingerprint),
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

    fn legacy_line(sweep_txid: &str) -> String {
        format!("{}:3:1 {sweep_txid}\n", "42".repeat(32))
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
        assert_eq!(header["version"], 2);
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
        std::fs::write(journal.path(), legacy_line(&txid.to_string())).unwrap();
        let snapshot = journal.load_or_migrate().unwrap();
        let entry = snapshot.entry_for_note(&outpoint()).unwrap();
        assert_eq!(entry.legacy_txid, Some(txid));
        assert!(entry.transaction.is_none());
        assert_eq!(entry.state, TxLifecycleState::SubmissionUnknown);
        assert!(!snapshot.all_mined_for([&outpoint()]));
        assert!(std::fs::read_to_string(journal.path())
            .unwrap()
            .starts_with("{\"record\":\"header\""));
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
        std::fs::write(journal.path(), legacy_line(&fixture().txid.to_string())).unwrap();
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
        std::fs::write(journal.path(), format!("{line}{line}")).unwrap();
        assert_eq!(journal.load_or_migrate().unwrap().entries().count(), 1);
        let conflict = TxId::from_bytes([0x55; 32]).to_string();
        std::fs::write(journal.path(), format!("{line}{}", legacy_line(&conflict))).unwrap();
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
        std::fs::write(journal.path(), &original).unwrap();
        assert!(journal.load_or_migrate().is_err());
        assert_eq!(std::fs::read_to_string(journal.path()).unwrap(), original);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn v1_migration_replaces_a_world_readable_file_with_private_v2() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        std::fs::write(journal.path(), legacy_line(&fixture().txid.to_string())).unwrap();
        std::fs::set_permissions(journal.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        journal.load_or_migrate().unwrap();
        let mode = std::fs::metadata(journal.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        let lock_path =
            std::path::PathBuf::from(format!("{}.lock.sqlite", journal.path().display()));
        let lock_mode = std::fs::metadata(lock_path).unwrap().permissions().mode();
        assert_eq!(lock_mode & 0o777, 0o600);
    }

    #[test]
    fn malformed_complete_line_blocks_broadcast() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        std::fs::write(
            journal.path(),
            format!("{}not a record\n", legacy_line(&fixture().txid.to_string())),
        )
        .unwrap();
        assert!(journal.load_or_migrate().is_err());
    }

    #[test]
    fn torn_final_v2_transition_falls_back_to_the_previous_safe_state() {
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
        let restored = journal.load_or_migrate().unwrap();
        assert_eq!(
            restored.entry_for_txid(tx.txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
        let mut restored = restored;
        journal
            .append_transition(
                &mut restored,
                tx.txid,
                TxLifecycleState::Pending,
                Some(&SubmissionDisposition::Accepted),
                None,
            )
            .unwrap();
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .entry_for_txid(tx.txid)
                .unwrap()
                .state,
            TxLifecycleState::Pending
        );
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
        std::fs::write(journal.path(), legacy_line(&fixture().txid.to_string())).unwrap();
        let lock_path =
            std::path::PathBuf::from(format!("{}.lock.sqlite", journal.path().display()));
        let connection = rusqlite::Connection::open(&lock_path).unwrap();
        connection
            .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
            .unwrap();
        let (sender, receiver) = mpsc::channel();
        let other = journal.clone();
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
        let other = journal.clone();
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
        std::fs::write(journal.path(), legacy_line(&txid.to_string())).unwrap();
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
    fn migration_rechecks_original_bytes_before_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let journal = journal(dir.path());
        let original = legacy_line(&fixture().txid.to_string());
        let appended = legacy_line(&TxId::from_bytes([0x55; 32]).to_string());
        std::fs::write(journal.path(), &original).unwrap();
        std::fs::write(journal.path(), format!("{original}{appended}")).unwrap();
        assert!(journal
            .atomic_replace_if_unchanged(original.as_bytes(), b"replacement\n")
            .is_err());
        assert_eq!(
            std::fs::read_to_string(journal.path()).unwrap(),
            format!("{original}{appended}")
        );
    }
}
