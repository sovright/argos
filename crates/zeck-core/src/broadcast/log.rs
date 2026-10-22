use std::{
    collections::{BTreeMap, HashMap},
    fs,
    fs::OpenOptions,
    io::{Seek, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::TxId;

use super::{
    lifecycle::validate_transition, BroadcastStore, PersistedTransaction, PreparedTransaction,
    SubmissionDisposition, TxLifecycleState, TxObservation,
};
use crate::{
    error::{ZeckError, ZeckResult},
    private_fs::{open_private_file, NamespaceLease, PrivateOpenMode, RetainedNamespaceChild},
    workspace::append_private_file,
};

pub const BROADCAST_LOG_SCHEMA_VERSION: u32 = 1;
pub const BROADCAST_LOG_FILE_NAME: &str = "broadcasts-v1.jsonl";
pub(super) const LEGACY_IMPORT_MANIFEST_V1_FILE_NAME: &str = "legacy-imports-v1.json";
pub(super) const LEGACY_IMPORT_MANIFEST_FILE_NAME: &str = "legacy-imports-v2.jsonl";

#[derive(Default, Serialize, Deserialize)]
struct LegacyImportManifest {
    /// Canonical source path to the exact bytes imported from that source.
    sources: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct LegacyImportRecord {
    source: String,
    digest: String,
}

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

impl BroadcastLogEvent {
    fn txid(&self) -> TxId {
        match self {
            Self::Prepared { txid, .. } | Self::StateChanged { txid, .. } => {
                TxId::from_bytes(*txid)
            }
        }
    }
}

fn ordered_event_lines(bytes: &[u8]) -> ZeckResult<Vec<(TxId, Vec<u8>)>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err(ZeckError::Storage(
            "incomplete broadcast log during legacy import".to_owned(),
        ));
    }
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(|line| {
            let event: BroadcastLogEvent = serde_json::from_slice(line).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid broadcast event during legacy import: {err}"
                ))
            })?;
            Ok((event.txid(), line.to_vec()))
        })
        .collect()
}

fn event_lines_by_txid(bytes: &[u8]) -> ZeckResult<HashMap<TxId, Vec<Vec<u8>>>> {
    let mut grouped: HashMap<TxId, Vec<Vec<u8>>> = HashMap::new();
    for (txid, line) in ordered_event_lines(bytes)? {
        grouped.entry(txid).or_default().push(line);
    }
    Ok(grouped)
}

pub struct DurableBroadcastLog {
    path: PathBuf,
    latest: HashMap<TxId, PersistedTransaction>,
    write_failed: bool,
    // SQLite owns an OS file lock, released by Drop or process death. The
    // sidecar never stores transaction data and cannot leave a stale lock.
    _process_lock: Option<rusqlite::Connection>,
    // The network registry is opened through the NetworkOperationGuard's
    // retained namespace authority. Every registry and import-manifest read
    // or replacement is then relative to that exact directory handle.
    namespace: Option<NamespaceLease>,
    compatibility_lock: Option<RetainedNamespaceChild>,
    // A network registry keeps every legacy source locked until the caller's
    // entire scan, review, submission, reconciliation, or deletion ends.
    // Otherwise an older binary can append to a local journal just after its
    // one-time import (or after an absent-JSONL sidecar was overlooked).
    held_legacy_sources: Vec<DurableBroadcastLog>,
}

/// Keeps old workspace/standalone journal locks alive while a route reopens
/// the network registry for its individual submissions.
pub(crate) struct LegacyBroadcastGuards {
    _held: Vec<DurableBroadcastLog>,
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
        drop(
            open_private_file(&lock_path, PrivateOpenMode::Append).map_err(|err| {
                ZeckError::Storage(format!(
                    "opening broadcast lock {}: {err}",
                    lock_path.display()
                ))
            })?,
        );
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
            _process_lock: Some(process_lock),
            namespace: None,
            compatibility_lock: None,
            held_legacy_sources: Vec::new(),
        };
        log.replay_from_disk()?;
        Ok(log)
    }

    pub(crate) fn open_in_namespace(
        path: impl AsRef<Path>,
        namespace: &NamespaceLease,
        compatibility_lock: &RetainedNamespaceChild,
    ) -> ZeckResult<Self> {
        let path = path.as_ref().to_path_buf();
        namespace.require_child(&path).map_err(|err| {
            ZeckError::Storage(format!(
                "broadcast registry {} is outside the retained namespace: {err}",
                path.display()
            ))
        })?;
        namespace.verify_current().map_err(|err| {
            ZeckError::Storage(format!(
                "broadcast registry namespace changed before open: {err}"
            ))
        })?;
        let mut log = Self {
            path,
            latest: HashMap::new(),
            write_failed: false,
            _process_lock: None,
            namespace: Some(namespace.try_clone_authority().map_err(|err| {
                ZeckError::Storage(format!("retaining broadcast registry namespace: {err}"))
            })?),
            compatibility_lock: Some(namespace.clone_retained_child(compatibility_lock).map_err(
                |err| ZeckError::Storage(format!("retaining workspace compatibility lock: {err}")),
            )?),
            held_legacy_sources: Vec::new(),
        };
        log.replay_from_disk()?;
        log.verify_namespace()?;
        Ok(log)
    }

    fn verify_namespace(&self) -> ZeckResult<()> {
        if let Some(namespace) = &self.namespace {
            namespace.verify_current().map_err(|err| {
                ZeckError::Storage(format!("broadcast registry namespace was replaced: {err}"))
            })?;
            if let Some(lock) = &self.compatibility_lock {
                lock.verify_current().map_err(|err| {
                    ZeckError::Storage(format!(
                        "workspace compatibility lock was replaced while held: {err}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    fn read_path(&self, path: &Path) -> ZeckResult<Option<Vec<u8>>> {
        self.verify_namespace()?;
        let result = if let Some(namespace) = &self.namespace {
            namespace.read_child(path)
        } else {
            fs::read(path)
        };
        let value = match result {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => Err(ZeckError::Storage(format!(
                "reading {}: {err}",
                path.display()
            )))?,
        };
        self.verify_namespace()?;
        Ok(value)
    }

    fn append_line_to_path(&self, path: &Path, line: &[u8]) -> ZeckResult<()> {
        self.verify_namespace()?;
        if let Some(namespace) = &self.namespace {
            let current = match namespace.read_child_version(path) {
                Ok((bytes, object_id)) => Some((bytes, object_id)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(ZeckError::Storage(format!(
                        "reading {} before append: {err}",
                        path.display()
                    )))
                }
            };
            let expected = current
                .as_ref()
                .map(|(bytes, object_id)| (object_id, bytes.as_slice()));
            let mut suffix = line.to_vec();
            suffix.push(b'\n');
            namespace
                .append_child_if_unchanged(path, expected, &suffix)
                .map_err(|err| {
                    ZeckError::Storage(format!("appending {}: {err}", path.display()))
                })?;
            self.verify_namespace()
        } else {
            append_private_file(path, line)
        }
    }

    /// Lock a legacy source even when its JSONL does not exist yet. If bytes
    /// exist, import them while still holding that exact source lock. A
    /// missing manifest after a crash is safe to recover because each source
    /// transaction must be an exact event prefix of the network registry.
    pub(crate) fn hold_legacy_source(&mut self, source_path: &Path) -> ZeckResult<()> {
        self.hold_legacy_source_before_lock(source_path, || {})
    }

    pub(super) fn hold_legacy_source_before_lock<F: FnOnce()>(
        &mut self,
        source_path: &Path,
        before_lock: F,
    ) -> ZeckResult<()> {
        if self.write_failed {
            return Err(ZeckError::Storage(format!(
                "broadcast log {} needs reopening after a failed write",
                self.path.display()
            )));
        }
        let source_path = source_path.to_path_buf();
        if source_path == self.path {
            return Err(ZeckError::Storage(
                "cannot import broadcast log into itself".to_owned(),
            ));
        }
        let source = if let Some(index) = self
            .held_legacy_sources
            .iter()
            .position(|source| source.path == source_path)
        {
            self.held_legacy_sources.swap_remove(index)
        } else {
            before_lock();
            Self::open(&source_path)?
        };
        // Inspect only after acquiring the exact source sidecar. An older
        // writer could create its first JSONL between a pre-lock absent stat
        // and this acquisition; that newly persisted Unknown must be imported.
        let present = match fs::symlink_metadata(&source_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
            Ok(_) => {
                return Err(ZeckError::Storage(format!(
                    "legacy broadcast log {} must be a regular file",
                    source_path.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                return Err(ZeckError::Storage(format!(
                    "inspecting legacy log {}: {err}",
                    source_path.display()
                )));
            }
        };
        let result = if present {
            self.import_locked_legacy_log(&source_path, &source)
        } else {
            Ok(())
        };
        self.held_legacy_sources.push(source);
        result
    }

    /// Copy an existing legacy journal into this locked network registry.
    /// Kept for in-crate callers and fixture tests; the source remains locked.
    pub(crate) fn import_legacy_log(&mut self, source_path: &Path) -> ZeckResult<()> {
        if !source_path.is_file() {
            return Err(ZeckError::Storage(format!(
                "legacy broadcast log {} is missing",
                source_path.display()
            )));
        }
        self.hold_legacy_source(source_path)
    }

    pub(crate) fn into_legacy_source_guards(mut self) -> LegacyBroadcastGuards {
        let held = std::mem::take(&mut self.held_legacy_sources);
        LegacyBroadcastGuards { _held: held }
    }

    fn import_locked_legacy_log(
        &mut self,
        source_path: &Path,
        source: &DurableBroadcastLog,
    ) -> ZeckResult<()> {
        let source_bytes = source.read_path(source_path)?.ok_or_else(|| {
            ZeckError::Storage(format!(
                "legacy broadcast log {} is missing",
                source_path.display()
            ))
        })?;
        let source_digest = format!("{:x}", Sha256::digest(&source_bytes));
        let registry_parent = self
            .path
            .parent()
            .ok_or_else(|| ZeckError::Storage("broadcast registry has no directory".to_owned()))?;
        let legacy_manifest_path = registry_parent.join(LEGACY_IMPORT_MANIFEST_V1_FILE_NAME);
        let manifest_path = registry_parent.join(LEGACY_IMPORT_MANIFEST_FILE_NAME);
        let legacy_manifest: LegacyImportManifest = match self.read_path(&legacy_manifest_path)? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
                ZeckError::Storage(format!(
                    "invalid legacy import manifest {}: {err}",
                    legacy_manifest_path.display()
                ))
            })?,
            None => LegacyImportManifest::default(),
        };
        let mut imported_sources = legacy_manifest.sources;
        if let Some(bytes) = self.read_path(&manifest_path)? {
            if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                return Err(ZeckError::Storage(format!(
                    "incomplete legacy import manifest {}",
                    manifest_path.display()
                )));
            }
            for line in bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let record: LegacyImportRecord = serde_json::from_slice(line).map_err(|err| {
                    ZeckError::Storage(format!(
                        "invalid legacy import record {}: {err}",
                        manifest_path.display()
                    ))
                })?;
                match imported_sources.get(&record.source) {
                    Some(previous) if previous != &record.digest => {
                        return Err(ZeckError::Storage(format!(
                            "conflicting legacy import records for {}",
                            record.source
                        )))
                    }
                    Some(_) => {}
                    None => {
                        imported_sources.insert(record.source, record.digest);
                    }
                }
            }
        }
        let source_key = source_path.to_string_lossy().into_owned();
        if let Some(previous_digest) = imported_sources.get(&source_key) {
            if previous_digest != &source_digest {
                return Err(ZeckError::Storage(format!(
                    "legacy broadcast log {} changed after import",
                    source_path.display()
                )));
            }
        }

        let registry_bytes = self.read_path(&self.path)?.unwrap_or_default();
        let source_events = event_lines_by_txid(&source_bytes)?;
        let registry_events = event_lines_by_txid(&registry_bytes)?;
        for (txid, source_lines) in &source_events {
            if let Some(registry_lines) = registry_events.get(txid) {
                if !registry_lines.starts_with(source_lines)
                    && !source_lines.starts_with(registry_lines)
                {
                    return Err(ZeckError::Storage(format!(
                        "conflicting legacy broadcast history for {txid} in {}",
                        source_path.display()
                    )));
                }
                if source.latest(*txid).is_none() || self.latest(*txid).is_none() {
                    return Err(ZeckError::Storage(format!(
                        "missing broadcast history for {txid} during legacy import"
                    )));
                }
            }
        }
        let mut seen_by_txid = HashMap::<TxId, usize>::new();
        let mut appended = false;
        for (txid, line) in ordered_event_lines(&source_bytes)? {
            let seen = seen_by_txid.entry(txid).or_default();
            let existing = registry_events.get(&txid).map_or(0, Vec::len);
            if *seen >= existing {
                if let Err(err) = self.append_line_to_path(&self.path, &line) {
                    self.write_failed = true;
                    return Err(err);
                }
                appended = true;
            }
            *seen += 1;
        }
        if appended {
            if let Err(err) = self.replay_from_disk() {
                self.write_failed = true;
                return Err(err);
            }
        }
        if !imported_sources.contains_key(&source_key) {
            let bytes = serde_json::to_vec(&LegacyImportRecord {
                source: source_key,
                digest: source_digest,
            })
            .map_err(|err| {
                ZeckError::Serialization(format!("serializing legacy import record: {err}"))
            })?;
            self.append_line_to_path(&manifest_path, &bytes)?;
        }
        self.verify_namespace()?;
        Ok(())
    }

    fn replay_from_disk(&mut self) -> ZeckResult<()> {
        self.latest.clear();
        let path = self.path.clone();
        let bytes = self.read_path(&path)?.unwrap_or_default();
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
    ///   acknowledged; standalone logs truncate it away so the earlier synced
    ///   state stands. Namespace-held logs refuse it until the namespace can
    ///   perform an exact replacement transition;
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
        if let Some(namespace) = &self.namespace {
            if !complete {
                return Err(ZeckError::Storage(format!(
                    "incomplete broadcast log at {}: the retained private namespace cannot discard a torn final event without an exact replacement transition",
                    self.path.display()
                )));
            }
            let (current, object_id) = namespace.read_child_version(&self.path).map_err(|err| {
                ZeckError::Storage(format!(
                    "reading {} before tail repair: {err}",
                    self.path.display()
                ))
            })?;
            if current != bytes {
                return Err(ZeckError::Storage(format!(
                    "broadcast log {} changed before tail repair",
                    self.path.display()
                )));
            }
            namespace
                .append_child_if_unchanged(&self.path, Some((&object_id, &current)), b"\n")
                .map_err(|err| {
                    ZeckError::Storage(format!(
                        "terminating final event in {}: {err}",
                        self.path.display()
                    ))
                })?;
            self.verify_namespace()?;
            bytes.push(b'\n');
            return Ok(bytes);
        }
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
        self.verify_namespace()?;
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
        let write_result = if let Some(namespace) = &self.namespace {
            let current = match namespace.read_child_version(&self.path) {
                Ok((bytes, object_id)) => Some((bytes, object_id)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(ZeckError::Storage(format!(
                        "reading {} before append: {err}",
                        self.path.display()
                    )))
                }
            };
            let mut suffix = bytes;
            suffix.push(b'\n');
            let expected = current
                .as_ref()
                .map(|(bytes, object_id)| (object_id, bytes.as_slice()));
            namespace
                .append_child_if_unchanged(&self.path, expected, &suffix)
                .map_err(|err| {
                    ZeckError::Storage(format!("appending {}: {err}", self.path.display()))
                })
        } else {
            append_private_file(&self.path, &bytes)
        };
        if let Err(err) = write_result {
            self.write_failed = true;
            return Err(err);
        }
        self.verify_namespace()?;
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
