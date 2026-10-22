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

const WORKSPACE_CLEANUP_LOCK_FILE: &str = ".workspace-cleanup.lock";

pub(super) struct WorkspaceCleanupAuthority {
    namespace: crate::private_fs::NamespaceLease,
}

impl WorkspaceCleanupAuthority {
    pub(super) fn acquire(root: &std::path::Path) -> ZeckResult<Self> {
        let parent = root.parent().ok_or_else(|| {
            ZeckError::Storage(format!("workspace {} has no parent", root.display()))
        })?;
        let lock = parent.join(WORKSPACE_CLEANUP_LOCK_FILE);
        let namespace =
            crate::private_fs::NamespaceLease::acquire(parent, &lock).map_err(|err| {
                ZeckError::ScanNotReady(format!(
                    "workspace cleanup namespace {} is in use: {err}",
                    parent.display()
                ))
            })?;
        namespace.require_child(root).map_err(|err| {
            ZeckError::Storage(format!(
                "invalid workspace cleanup path {}: {err}",
                root.display()
            ))
        })?;
        Ok(Self { namespace })
    }

    pub(super) fn exists(&self, path: &std::path::Path) -> ZeckResult<bool> {
        self.namespace.child_exists(path).map_err(|err| {
            ZeckError::Storage(format!("checking cleanup object {}: {err}", path.display()))
        })
    }

    pub(super) fn unexpected_tombstone_exists(
        &self,
        root: &std::path::Path,
        expected: &std::path::Path,
    ) -> ZeckResult<bool> {
        let prefix = format!(
            "{}.deleting-",
            root.file_name().unwrap_or_default().to_string_lossy()
        );
        let expected_name = expected.file_name();
        self.namespace
            .child_names()
            .map(|names| {
                names.into_iter().any(|name| {
                    name.to_string_lossy().starts_with(&prefix)
                        && Some(name.as_os_str()) != expected_name
                })
            })
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "enumerating cleanup tombstones for {}: {err}",
                    root.display()
                ))
            })
    }

    pub(super) fn retain_workspace(
        &self,
        root: &std::path::Path,
        database: &std::path::Path,
    ) -> ZeckResult<crate::private_fs::RetainedWorkspaceDirectory> {
        crate::private_fs::retain_private_workspace_for_cleanup(&self.namespace, root, database)
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "retaining workspace {} for exact cleanup: {err}",
                    root.display()
                ))
            })
    }

    pub(super) fn rename_retained_workspace(
        &self,
        from: &std::path::Path,
        to: &std::path::Path,
        retained: &crate::private_fs::RetainedWorkspaceDirectory,
    ) -> ZeckResult<()> {
        self.namespace
            .rename_retained_workspace_directory(from, to, retained)
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "renaming retained cleanup directory {} to {}: {err}",
                    from.display(),
                    to.display()
                ))
            })
    }

    pub(super) fn remove_retained_workspace_all(
        &self,
        path: &std::path::Path,
        retained: &crate::private_fs::RetainedWorkspaceDirectory,
    ) -> ZeckResult<()> {
        self.namespace
            .remove_retained_workspace_directory_all(path, retained)
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "deleting retained cleanup directory {}: {err}",
                    path.display()
                ))
            })
    }

    pub(super) fn read_marker(&self, path: &std::path::Path) -> ZeckResult<Vec<u8>> {
        let protected = self
            .namespace
            .read_child_bounded(path, 64 * 1024)
            .map_err(|err| {
                ZeckError::Storage(format!("reading cleanup marker {}: {err}", path.display()))
            })?;
        crate::private_fs::unprotect_cleanup_marker(&protected).map_err(|err| {
            ZeckError::Storage(format!(
                "authenticating cleanup marker {}: {err}",
                path.display()
            ))
        })
    }

    pub(super) fn create_marker(&self, path: &std::path::Path, payload: &[u8]) -> ZeckResult<()> {
        let protected = crate::private_fs::protect_cleanup_marker(payload).map_err(|err| {
            ZeckError::Storage(format!(
                "protecting cleanup marker {}: {err}",
                path.display()
            ))
        })?;
        self.namespace
            .append_child_if_unchanged(path, None, &protected)
            .map_err(|err| {
                ZeckError::Storage(format!("creating cleanup marker {}: {err}", path.display()))
            })
    }

    pub(super) fn remove_marker(&self, path: &std::path::Path) -> ZeckResult<()> {
        self.namespace.remove_child_exact(path).map_err(|err| {
            ZeckError::Storage(format!("clearing cleanup marker {}: {err}", path.display()))
        })
    }
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

struct CleanupMarkerEvidence<'a> {
    broadcast_log: &'a DurableBroadcastLog,
    outcome: Option<&'a SweepOutcome>,
    local_journal_exists: bool,
}

fn create_cleanup_marker(
    authority: &WorkspaceCleanupAuthority,
    root: &std::path::Path,
    tombstone: &std::path::Path,
    cleanup_id: uuid::Uuid,
    lineage: &crate::private_fs::PrivateWorkspaceCleanupBinding,
    evidence: CleanupMarkerEvidence<'_>,
) -> ZeckResult<()> {
    use sha2::{Digest, Sha256};

    let records = evidence.broadcast_log.records();
    let mut receipts = Vec::new();
    // A workspace deleted without a sweep has no receipts to bind.
    for transaction in evidence
        .outcome
        .map_or(&[][..], |outcome| &outcome.transactions[..])
    {
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
    let payload = serde_json::json!({
        "workspace": root,
        "tombstone": tombstone,
        "cleanup_id": cleanup_id,
        "lineage": lineage,
        "receipts": receipts,
        "local_journal_exists": evidence.local_journal_exists,
    });
    authority.create_marker(&path, payload.to_string().as_bytes())
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
    let parent = root
        .parent()
        .ok_or_else(|| ZeckError::Storage(format!("workspace {} has no parent", root.display())))?;
    // A marker and its tombstone are direct siblings of the workspace. If
    // that parent has never existed, there is no cleanup generation to
    // recover. Do not create the wallet-specific hierarchy merely to check.
    if !parent.exists() {
        return Ok(());
    }
    operation_lock.verify()?;
    let authority = WorkspaceCleanupAuthority::acquire(root)?;
    operation_lock.verify()?;
    if !authority.exists(&marker)? {
        return refuse_interrupted_cleanup(root);
    }
    let manual = |why: &str| {
        ZeckError::ScanNotReady(format!(
            "workspace cleanup requires manual recovery at {}: {why}",
            marker.display()
        ))
    };
    let bytes = authority
        .read_marker(&marker)
        .map_err(|_| manual("cannot read cleanup marker"))?;
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
    let cleanup_id = payload
        .get("cleanup_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| manual("missing cleanup generation"))?
        .parse::<uuid::Uuid>()
        .map_err(|_| manual("invalid cleanup generation"))?;
    let lineage: crate::private_fs::PrivateWorkspaceCleanupBinding = serde_json::from_value(
        payload
            .get("lineage")
            .cloned()
            .ok_or_else(|| manual("missing cleanup lineage binding"))?,
    )
    .map_err(|_| manual("invalid cleanup lineage binding"))?;
    let receipts = payload
        .get("receipts")
        .and_then(|value| value.as_array())
        .ok_or_else(|| manual("missing durable receipt list"))?;
    let local_journal_exists = payload
        .get("local_journal_exists")
        .and_then(|value| value.as_bool())
        .ok_or_else(|| manual("missing journal location"))?;
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
    let root_exists = authority
        .exists(root)
        .map_err(|_| manual("cannot inspect workspace"))?;
    let tombstone_exists = authority
        .exists(&tombstone)
        .map_err(|_| manual("cannot inspect tombstone"))?;
    if authority
        .unexpected_tombstone_exists(root, &tombstone)
        .map_err(|_| manual("cannot verify the cleanup tombstone set"))?
    {
        return Err(manual("an unexpected cleanup tombstone object exists"));
    }
    if root_exists && tombstone_exists {
        return Err(manual("both original workspace and tombstone exist"));
    }
    let private_root = root
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| manual("workspace layout has no private root"))?;
    let database = root.join("wallet.sqlite");
    if !root_exists && !tombstone_exists {
        crate::private_fs::verify_completed_private_workspace_cleanup(
            private_root,
            &database,
            cleanup_id.into_bytes(),
            &lineage,
        )
        .map_err(|_| manual("completed deletion does not match durable cleanup authority"))?;
        clear_cleanup_marker(&authority, root)?;
        return Ok(());
    }
    let surviving = if root_exists { root } else { &tombstone };
    let surviving_database = surviving.join("wallet.sqlite");
    let retained = authority
        .retain_workspace(surviving, &surviving_database)
        .map_err(|_| manual("cannot retain the exact surviving workspace"))?;
    if retained.id() != &lineage.workspace {
        return Err(manual(
            "surviving workspace identity does not match the cleanup marker",
        ));
    }
    if !root_exists {
        authority
            .rename_retained_workspace(&tombstone, root, &retained)
            .map_err(|_| manual("cannot restore surviving tombstone"))?;
    }
    crate::private_fs::verify_surviving_private_workspace_cleanup(
        private_root,
        &retained,
        &database,
        &lineage,
    )
    .map_err(|_| manual("surviving workspace does not match its exact cleanup binding"))?;
    if !root.is_dir() || root.is_symlink() {
        return Err(manual("surviving workspace is missing or unsafe"));
    }
    let local_path = root.join(crate::broadcast::BROADCAST_LOG_FILE_NAME);
    if local_journal_exists && (!local_path.is_file() || local_path.is_symlink()) {
        return Err(manual("surviving workspace journal is missing or unsafe"));
    }
    let registry = operation_lock
        .open_broadcast_log_for(&local_path)
        .map_err(|_| manual("surviving journal cannot be imported into the registry"))?;
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
    // The registry owns and replays the exact surviving local source lock.
    // Newer outcome receipts live only in the global registry and need not
    // also appear in an older imported prefix.
    drop(registry);
    crate::private_fs::reconcile_private_workspace_cleanup(
        private_root,
        &retained,
        &database,
        cleanup_id.into_bytes(),
        &lineage,
    )
    .map_err(|_| manual("surviving workspace does not match durable cleanup authority"))?;
    clear_cleanup_marker(&authority, root)?;
    refuse_interrupted_cleanup(root)
}

fn clear_cleanup_marker(
    authority: &WorkspaceCleanupAuthority,
    root: &std::path::Path,
) -> ZeckResult<()> {
    let path = cleanup_marker_path(root)?;
    authority.remove_marker(&path)
}

fn read_cleanup_plan(
    authority: &WorkspaceCleanupAuthority,
    root: &std::path::Path,
) -> ZeckResult<(
    std::path::PathBuf,
    uuid::Uuid,
    crate::private_fs::PrivateWorkspaceCleanupBinding,
)> {
    let marker = cleanup_marker_path(root)?;
    let bytes = authority.read_marker(&marker)?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
        ZeckError::Storage(format!("reading cleanup plan {}: {err}", marker.display()))
    })?;
    if payload.get("workspace").and_then(|value| value.as_str()) != root.to_str() {
        return Err(ZeckError::Storage(format!(
            "cleanup plan {} names a different workspace",
            marker.display()
        )));
    }
    let tombstone = payload
        .get("tombstone")
        .and_then(|value| value.as_str())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| ZeckError::Storage("cleanup plan has no tombstone path".to_owned()))?;
    let cleanup_id = payload
        .get("cleanup_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ZeckError::Storage("cleanup plan has no cleanup generation".to_owned()))?
        .parse::<uuid::Uuid>()
        .map_err(|err| ZeckError::Storage(format!("invalid cleanup generation: {err}")))?;
    let lineage = serde_json::from_value(
        payload
            .get("lineage")
            .cloned()
            .ok_or_else(|| ZeckError::Storage("cleanup plan has no lineage binding".to_owned()))?,
    )
    .map_err(|err| ZeckError::Storage(format!("invalid cleanup lineage binding: {err}")))?;
    Ok((tombstone, cleanup_id, lineage))
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
        _operation_lock.verify()?;
        if !self
            .sessions
            .read()
            .await
            .get(&handle.id)
            .is_some_and(|current| Arc::ptr_eq(current, session.shared()))
        {
            return Err(ZeckError::UnknownScanHandle);
        }
        let cleanup_retry = self
            .cleanup_retry
            .lock()
            .await
            .get(&session.workspace_root)
            .cloned();
        if cleanup_retry.is_some() {
            // Never reuse the pre-cleanup GUI review after a failed rename or
            // recursive removal. Reconcile the DPAPI marker, exact retained
            // object identities, and durable Revoked state before any journal
            // is parsed, then require a fresh scan and fresh canonicality
            // evidence before deletion can be proposed again.
            recover_interrupted_cleanup(&session.workspace_root, &_operation_lock)?;
            session.reviewed_sweeps.lock().await.entries.clear();
            self.sessions.write().await.remove(&handle.id);
            self.reconciliation_rescan_required
                .lock()
                .await
                .remove(&handle.id);
            self.last_sweep_outcomes.lock().await.remove(&handle.id);
            self.cleanup_retry
                .lock()
                .await
                .remove(&session.workspace_root);
            return Err(ZeckError::ScanNotReady(
                "workspace cleanup was recovered; run and review a fresh scan before deleting it"
                    .to_owned(),
            ));
        }
        refuse_interrupted_cleanup(&session.workspace_root)?;
        let cleanup_authority = WorkspaceCleanupAuthority::acquire(&session.workspace_root)?;

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

        let workspace = RecoveryWorkspace::from_runtime(&session.runtime)?;
        // Import and inspect the surviving workspace journal after a retry
        // restored its actual path. The network registry (outside the
        // workspace, so it survives deletion) is authoritative for all
        // aliases; the local journal is also checked so a changed source
        // cannot be silently ignored.
        let local_path = workspace.broadcast_log_path();
        let local_journal_exists = local_path.exists();
        let mut broadcast_log = _operation_lock.open_broadcast_log_for(&local_path)?;
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
        if cleanup_authority.exists(&workspace_root)? {
            let workspace_private_root = workspace_root
                .parent()
                .and_then(std::path::Path::parent)
                .ok_or_else(|| {
                    ZeckError::Storage(format!(
                        "workspace {} has no private-root ancestor",
                        workspace_root.display()
                    ))
                })?;
            let workspace_database = workspace_root.join("wallet.sqlite");
            // Pin the exact reviewed workspace before publishing cleanup
            // intent. On Windows this atomically removes the cached SQLite
            // authority and marks the object cleanup-held, so no same-process
            // opener can reauthorize a replacement between revocation and
            // rename.
            let retained_workspace =
                cleanup_authority.retain_workspace(&workspace_root, &workspace_database)?;
            let lineage = crate::private_fs::inspect_private_workspace_cleanup_binding(
                workspace_private_root,
                &retained_workspace,
                &workspace_database,
            )
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "binding exact workspace lineage for {}: {err}",
                    workspace_root.display()
                ))
            })?;
            let marker_path = cleanup_marker_path(&workspace_root)?;
            let (tombstone, cleanup_id, marker_lineage) =
                if cleanup_authority.exists(&marker_path)? {
                    read_cleanup_plan(&cleanup_authority, &workspace_root)?
                } else {
                    let cleanup_id = uuid::Uuid::new_v4();
                    let tombstone = workspace_root.with_file_name(format!(
                        "{}.deleting-{cleanup_id}",
                        workspace_root
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("workspace"),
                    ));
                    create_cleanup_marker(
                        &cleanup_authority,
                        &workspace_root,
                        &tombstone,
                        cleanup_id,
                        &lineage,
                        CleanupMarkerEvidence {
                            broadcast_log: &broadcast_log,
                            outcome: outcome.as_ref(),
                            local_journal_exists,
                        },
                    )?;
                    (tombstone, cleanup_id, lineage.clone())
                };
            if marker_lineage != lineage {
                return Err(ZeckError::Storage(
                    "cleanup marker no longer matches the exact workspace objects".to_owned(),
                ));
            }
            crate::private_fs::revoke_private_workspace_lineage(
                workspace_private_root,
                &retained_workspace,
                &workspace_database,
                cleanup_id.into_bytes(),
                &lineage,
            )
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "revoking private workspace lineage for {}: {err}",
                    workspace_root.display()
                ))
            })?;
            if let Err(err) = cleanup_authority.rename_retained_workspace(
                &workspace_root,
                &tombstone,
                &retained_workspace,
            ) {
                self.cleanup_retry
                    .lock()
                    .await
                    .insert(workspace_root.clone(), workspace_root.clone());
                return Err(ZeckError::Storage(format!(
                    "renaming workspace {} for deletion: {err}",
                    workspace_root.display()
                )));
            }
            // Opening the global registry imports and retains the legacy
            // workspace-local journal so its receipts can be authenticated
            // above. Keep that lock until the reviewed workspace has been
            // revoked and renamed, then release the self-held SQLite source
            // before recursive removal: Windows correctly refuses to remove
            // an open SQLite child. The network operation lock and retained
            // directory handle continue to pin the registry and exact object.
            drop(broadcast_log);
            if let Err(err) =
                cleanup_authority.remove_retained_workspace_all(&tombstone, &retained_workspace)
            {
                let remaining = if cleanup_authority
                    .rename_retained_workspace(&tombstone, &workspace_root, &retained_workspace)
                    .is_ok()
                {
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

        if cleanup_authority.exists(&cleanup_marker_path(&workspace_root)?)? {
            if let Err(err) = clear_cleanup_marker(&cleanup_authority, &workspace_root) {
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
