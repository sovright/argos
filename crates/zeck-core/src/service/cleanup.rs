//! Workspace deletion and the durable cleanup marker that makes an
//! interrupted deletion recoverable after a restart.

use super::*;

pub(super) fn cleanup_marker_path(root: &std::path::Path) -> ZeckResult<std::path::PathBuf> {
    let name = root.file_name().ok_or_else(|| {
        ZeckError::Storage(format!(
            "workspace {} has no final component",
            root.display()
        ))
    })?;
    let mut marker = name.to_os_string();
    marker.push(".cleanup-pending.json");
    Ok(root.with_file_name(marker))
}

pub(super) fn refuse_interrupted_cleanup(root: &std::path::Path) -> ZeckResult<()> {
    let marker = cleanup_marker_path(root)?;
    if marker.exists() {
        return Err(ZeckError::ScanNotReady(format!(
            "workspace cleanup is incomplete; inspect {} before using this wallet",
            marker.display()
        )));
    }
    // Older partial deletions may have left a tombstone without a marker.
    // A fresh scan must not create a new empty journal beside that history.
    if let Some(parent) = root.parent() {
        let prefix = format!(
            "{}.deleting-",
            root.file_name().unwrap_or_default().to_string_lossy()
        );
        match std::fs::read_dir(parent) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(|err| {
                        ZeckError::Storage(format!(
                            "reading workspace parent {}: {err}",
                            parent.display()
                        ))
                    })?;
                    if entry.file_name().to_string_lossy().starts_with(&prefix) {
                        return Err(ZeckError::ScanNotReady(format!(
                            "workspace cleanup is incomplete; inspect {} before using this wallet",
                            entry.path().display()
                        )));
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(ZeckError::Storage(format!(
                    "reading workspace parent {}: {err}",
                    parent.display()
                )));
            }
        }
    }
    Ok(())
}

fn create_cleanup_marker(
    root: &std::path::Path,
    tombstone: &std::path::Path,
    broadcast_log: &DurableBroadcastLog,
    outcome: Option<&SweepOutcome>,
) -> ZeckResult<()> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let records = broadcast_log.records();
    let mut receipts = Vec::new();
    // A workspace deleted without a sweep has no receipts to bind.
    for transaction in outcome.map_or(&[][..], |outcome| &outcome.transactions[..]) {
        let txid = transaction.txid.as_deref().ok_or_else(|| {
            ZeckError::Storage("cannot mark cleanup without a durable transaction ID".to_owned())
        })?;
        let record = records
            .iter()
            .find(|record| record.prepared.txid.to_string() == txid)
            .ok_or_else(|| ZeckError::Storage(format!("cleanup receipt {txid} is missing")))?;
        receipts.push(serde_json::json!({
            "txid": txid,
            "raw_sha256": format!("{:x}", Sha256::digest(&record.prepared.raw_tx)),
        }));
    }
    let path = cleanup_marker_path(root)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|err| {
        ZeckError::Storage(format!("creating cleanup marker {}: {err}", path.display()))
    })?;
    let payload = serde_json::json!({
        "workspace": root,
        "tombstone": tombstone,
        "receipts": receipts,
    });
    file.write_all(payload.to_string().as_bytes())
        .map_err(|err| {
            ZeckError::Storage(format!("writing cleanup marker {}: {err}", path.display()))
        })?;
    file.sync_all().map_err(|err| {
        ZeckError::Storage(format!("syncing cleanup marker {}: {err}", path.display()))
    })?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "syncing cleanup marker parent {}: {err}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

/// Resolve a crash between renaming and removing a workspace. This restores
/// the old journal for inspection, but never resurrects the old GUI approval:
/// the caller must start a fresh scan and review before another deletion.
pub(super) fn recover_interrupted_cleanup(
    root: &std::path::Path,
    operation_lock: &NetworkOperationGuard,
) -> ZeckResult<()> {
    use sha2::{Digest, Sha256};

    let marker = cleanup_marker_path(root)?;
    if !marker.exists() {
        return refuse_interrupted_cleanup(root);
    }
    let manual = |why: &str| {
        ZeckError::ScanNotReady(format!(
            "workspace cleanup requires manual recovery at {}: {why}",
            marker.display()
        ))
    };
    let bytes = std::fs::read(&marker).map_err(|_| manual("cannot read cleanup marker"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| manual("invalid cleanup marker"))?;
    if payload.get("workspace").and_then(|value| value.as_str()) != root.to_str() {
        return Err(manual(&format!(
            "workspace identity does not match (marker {:?}, current {})",
            payload.get("workspace"),
            root.display()
        )));
    }
    let tombstone = payload
        .get("tombstone")
        .and_then(|value| value.as_str())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| manual("missing tombstone path"))?;
    let expected_prefix = format!(
        "{}.deleting-",
        root.file_name().unwrap_or_default().to_string_lossy()
    );
    if tombstone.parent() != root.parent()
        || !tombstone
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(&expected_prefix))
    {
        return Err(manual("tombstone path does not match workspace"));
    }
    let receipts = payload
        .get("receipts")
        .and_then(|value| value.as_array())
        .ok_or_else(|| manual("missing durable receipt list"))?;
    let expected = receipts
        .iter()
        .map(|receipt| {
            let txid = receipt
                .get("txid")
                .and_then(|value| value.as_str())
                .ok_or_else(|| manual("invalid receipt transaction ID"))?;
            let digest = receipt
                .get("raw_sha256")
                .and_then(|value| value.as_str())
                .ok_or_else(|| manual("invalid receipt digest"))?;
            Ok((txid.to_owned(), digest.to_owned()))
        })
        .collect::<ZeckResult<Vec<_>>>()?;
    if root.exists() && tombstone.exists() {
        return Err(manual("both original workspace and tombstone exist"));
    }
    if !root.exists() {
        if !tombstone.is_dir() || tombstone.is_symlink() {
            return Err(manual("surviving tombstone is missing or unsafe"));
        }
        std::fs::rename(&tombstone, root)
            .map_err(|_| manual("cannot restore surviving tombstone"))?;
    }
    if !root.is_dir() || root.is_symlink() {
        return Err(manual("surviving workspace is missing or unsafe"));
    }
    let registry = operation_lock
        .open_broadcast_log()
        .map_err(|_| manual("the network registry cannot be opened"))?;
    let registry_records = registry.records();
    for (txid, digest) in expected {
        let Some(receipt) = registry_records
            .iter()
            .find(|record| record.prepared.txid.to_string() == txid)
        else {
            return Err(manual("registry receipt is missing"));
        };
        if format!("{:x}", Sha256::digest(&receipt.prepared.raw_tx)) != digest {
            return Err(manual("registry raw transaction changed"));
        }
    }
    drop(registry);
    clear_cleanup_marker(root)?;
    refuse_interrupted_cleanup(root)
}

fn clear_cleanup_marker(root: &std::path::Path) -> ZeckResult<()> {
    let path = cleanup_marker_path(root)?;
    std::fs::remove_file(&path).map_err(|err| {
        ZeckError::Storage(format!("clearing cleanup marker {}: {err}", path.display()))
    })?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "syncing cleanup marker parent {}: {err}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

impl RecoveryService {
    /// Recursively delete the on-disk recovery workspace for a completed scan
    /// and drop the session. Used by the GUI's post-recovery "Delete workspace"
    /// action (threat-model T-L3).
    ///
    /// Returns the path that was deleted. Refuses to act on an in-flight scan
    /// — call `cancel_scan` first if the user truly wants to discard mid-run.
    ///
    /// Caveat: on modern SSDs `remove_dir_all` is not a cryptographic wipe;
    /// the filesystem and SSD controller may retain blocks until the cells
    /// are overwritten or TRIM'd. UI callers should surface this honestly.
    pub async fn delete_workspace(&self, handle: &ScanHandle) -> ZeckResult<std::path::PathBuf> {
        let session = self.session(handle).await?;
        let mut observer = LightwalletdTxObserver::new(
            &session.runtime.lightwalletd_url,
            &session.runtime.confirmation_sources,
        )?;
        self.delete_workspace_with_observer(handle, &mut observer)
            .await
    }

    pub(super) async fn delete_workspace_with_observer<O: TxObserver>(
        &self,
        handle: &ScanHandle,
        observer: &mut O,
    ) -> ZeckResult<std::path::PathBuf> {
        let session = self.session(handle).await?;
        let _workspace_guard = self
            .workspace_gate(&session.workspace_root)
            .try_lock_owned()
            .map_err(|_| {
                ZeckError::ScanNotReady(
                    "cannot delete workspace while a scan or sweep is active".to_owned(),
                )
            })?;
        let _operation_lock =
            NetworkOperationGuard::acquire(&session.runtime.data_dir, session.runtime.network)?;
        if !self
            .sessions
            .read()
            .await
            .get(&handle.id)
            .is_some_and(|current| Arc::ptr_eq(current, &session))
        {
            return Err(ZeckError::UnknownScanHandle);
        }
        let cleanup_retry = self
            .cleanup_retry
            .lock()
            .await
            .get(&session.workspace_root)
            .cloned();
        if cleanup_retry.is_none() {
            refuse_interrupted_cleanup(&session.workspace_root)?;
        }
        if let Some(remaining) = cleanup_retry {
            // Restore a surviving tombstone before inspecting any persisted
            // state. `RecoveryWorkspace` paths then refer to the actual
            // wallet and journal, rather than a fresh empty original path.
            if remaining != session.workspace_root {
                if session.workspace_root.exists() {
                    return Err(ZeckError::Storage(format!(
                        "cannot retry deletion while both {} and {} exist",
                        session.workspace_root.display(),
                        remaining.display()
                    )));
                }
                std::fs::rename(&remaining, &session.workspace_root).map_err(|err| {
                    ZeckError::Storage(format!(
                        "restoring workspace {} for deletion retry: {err}",
                        remaining.display()
                    ))
                })?;
                self.cleanup_retry.lock().await.insert(
                    session.workspace_root.clone(),
                    session.workspace_root.clone(),
                );
            } else if !remaining.exists() {
                return Err(ZeckError::Storage(format!(
                    "cannot retry deletion because workspace {} is missing",
                    remaining.display()
                )));
            }
        }

        // Refuse mid-scan to avoid tearing the SQLite write-ahead state out
        // from under the running task. Callers can cancel first if they really
        // mean it. A finished scan -- complete, cancelled or failed -- may be
        // deleted with or without a sweep: spend authority lives in the
        // source keys, not in this workspace.
        {
            let state = session.state.lock().await;
            let phase = state.progress.phase;
            if !matches!(
                phase,
                ScanPhase::Complete | ScanPhase::Cancelled | ScanPhase::Error
            ) {
                return Err(ZeckError::ScanNotReady(format!(
                    "cannot delete workspace while scan is {phase:?}; cancel first",
                )));
            }
        }

        // The network registry lives outside the workspace, so it survives
        // deletion and is authoritative for every workspace on this network.
        let mut broadcast_log = _operation_lock.open_broadcast_log()?;
        // The only refusal: a broadcast whose outcome is not yet resolved.
        // Observe each once first, so a transaction that has since mined (by
        // any operator), expired, or been rejected does not block. An
        // observation failure leaves the record as it was. The registry is
        // network-wide, so this conservatively includes broadcasts from
        // other workspaces on the same network.
        for record in broadcast_log.records() {
            if record.state.is_resolved() {
                continue;
            }
            let txid = record.prepared.txid;
            let observed = observer
                .observe(session.runtime.network, txid, record.prepared.expiry_height)
                .await
                .unwrap_or_else(|_| {
                    crate::broadcast::observe_transaction(Vec::new(), record.prepared.expiry_height)
                });
            crate::reconciliation::record_observation(&mut broadcast_log, txid, &observed)?;
        }
        if let Some(record) = broadcast_log
            .records()
            .into_iter()
            .find(|record| !record.state.is_resolved())
        {
            return Err(ZeckError::Broadcast(format!(
                "cannot delete workspace: transaction {} is {}; reconcile it first",
                record.prepared.txid, record.state
            )));
        }
        let outcome = self
            .last_sweep_outcomes
            .lock()
            .await
            .get(&handle.id)
            .cloned();

        // Drop any lingering task handle so the SQLite files aren't held open.
        if let Some(task) = session.task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }

        let workspace_root = session.workspace_root.clone();
        if workspace_root.exists() {
            let tombstone = workspace_root.with_file_name(format!(
                "{}.deleting-{}",
                workspace_root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("workspace"),
                uuid::Uuid::new_v4(),
            ));
            if !cleanup_marker_path(&workspace_root)?.exists() {
                create_cleanup_marker(
                    &workspace_root,
                    &tombstone,
                    &broadcast_log,
                    outcome.as_ref(),
                )?;
            }
            if let Err(err) = std::fs::rename(&workspace_root, &tombstone) {
                self.cleanup_retry
                    .lock()
                    .await
                    .insert(workspace_root.clone(), workspace_root.clone());
                return Err(ZeckError::Storage(format!(
                    "renaming workspace {} for deletion: {err}",
                    workspace_root.display()
                )));
            }
            if let Err(err) = std::fs::remove_dir_all(&tombstone) {
                let remaining = if std::fs::rename(&tombstone, &workspace_root).is_ok() {
                    workspace_root.clone()
                } else {
                    tombstone.clone()
                };
                self.cleanup_retry
                    .lock()
                    .await
                    .insert(workspace_root.clone(), remaining);
                return Err(ZeckError::Storage(format!(
                    "deleting workspace {}: {err}; cleanup can be retried",
                    tombstone.display()
                )));
            }
        }

        if cleanup_marker_path(&workspace_root)?.exists() {
            if let Err(err) = clear_cleanup_marker(&workspace_root) {
                self.cleanup_retry
                    .lock()
                    .await
                    .insert(workspace_root.clone(), workspace_root.clone());
                return Err(err);
            }
        }

        self.sessions.write().await.remove(&handle.id);
        self.reconciliation_rescan_required
            .lock()
            .await
            .remove(&handle.id);
        self.last_sweep_outcomes.lock().await.remove(&handle.id);
        self.cleanup_retry.lock().await.remove(&workspace_root);

        Ok(workspace_root)
    }
}
