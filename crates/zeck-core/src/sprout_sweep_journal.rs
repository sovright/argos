//! Durable, versioned Sprout sweep transactions, keyed by note and source.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use argos_wallet_import::keys::JsOutPoint;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

use crate::{
    broadcast::{
        txid_from_raw, validate_transition, BroadcastStore, PersistedTransaction,
        PreparedTransaction, SubmissionDisposition, TxLifecycleState, TxObservation,
    },
    error::{ZeckError, ZeckResult},
    models::ZeckNetwork,
    sprout_scan_run::{full_key_set_fingerprint, key_set_fingerprint},
};

pub const SPROUT_SWEEP_JOURNAL_VERSION: u32 = 2;
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
        if txid_from_raw(&tx.raw_tx)? != tx.txid {
            return Err(journal_error(format!(
                "raw transaction does not match {}",
                tx.txid
            )));
        }
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
        if txid_from_raw(&raw_tx)? != txid {
            return Err(journal_error(format!(
                "raw transaction does not match {txid}"
            )));
        }
        Ok(PreparedTransaction {
            txid,
            raw_tx,
            fee_zatoshis: self.fee_zatoshis,
            expiry_height: self.expiry_height,
        })
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
}

impl SproutJournalSnapshot {
    pub fn entry_for_note(&self, outpoint: &JsOutPoint) -> Option<&SproutJournalEntry> {
        self.by_note.get(&note_id(outpoint))
    }

    pub fn entry_for_txid(&self, txid: TxId) -> Option<&SproutJournalEntry> {
        self.by_txid.get(&txid).and_then(|id| self.by_note.get(id))
    }

    pub fn entries(&self) -> impl Iterator<Item = &SproutJournalEntry> {
        self.by_note.values()
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
            self.entry_for_note(outpoint)
                .is_some_and(|entry| entry.state == TxLifecycleState::Mined)
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
                    if existing.transaction.as_ref() == Some(&tx)
                        && existing.value_zatoshis == Some(value_zatoshis)
                    {
                        return Ok(());
                    }
                    if !matches!(
                        existing.state,
                        TxLifecycleState::Expired | TxLifecycleState::Rejected
                    ) {
                        return Err(journal_error(
                            "conflicting prepared transaction for active note",
                        ));
                    }
                    self.by_txid.remove(&existing.txid());
                }
                self.by_txid.insert(tx.txid, note_id);
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
                    || verified_tip >= expiry_bound
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
            let file = OpenOptions::new()
                .write(true)
                .open(&self.path)
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
        self.atomic_replace(&data)?;
        Ok(snapshot)
    }

    fn atomic_replace(&self, bytes: &[u8]) -> ZeckResult<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| journal_error("journal has no parent"))?;
        let temporary = parent.join(format!(".sprout-sweep-migrate-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .map_err(|err| journal_error(format!("creating migration file: {err}")))?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|err| journal_error(format!("syncing migration file: {err}")))?;
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

    fn append(&self, record: &SproutJournalRecord) -> ZeckResult<()> {
        let missing = !self.path.exists();
        if !missing {
            // A caller may have retained an old snapshot or opened the same
            // short-name path under another network. Check the disk identity
            // and reducer before adding any bytes to an existing file.
            self.load_or_migrate()?;
        }
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
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
        let mut next = snapshot.clone();
        next.apply(record.clone(), &self.source_fingerprint)?;
        self.append(&record)?;
        *snapshot = next;
        Ok(())
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
        let mut next = snapshot.clone();
        next.apply(record.clone(), &self.source_fingerprint)?;
        self.append(&record)?;
        *snapshot = next;
        Ok(())
    }
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
        let mut next = self.snapshot.clone();
        next.apply(record.clone(), &self.journal.source_fingerprint)?;
        self.journal.append(&record)?;
        *self.snapshot = next;
        Ok(())
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
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
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
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
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
}
