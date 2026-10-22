//! Fail-closed filesystem primitives for spend-capable recovery artifacts.

use sha2::Digest as _;
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PrivateObjectId {
    Unix { device: u64, inode: u64 },
    Windows { volume_serial: u32, file_index: u64 },
}

pub(crate) const PRIVATE_ROOT_LINEAGE_FILE_NAME: &str = ".argos-private-root-v1";
pub(crate) const PRIVATE_ARTIFACT_ROOT_MARKER: &str = ".argos-private-artifact-root-v1";
pub(crate) const PRIVATE_ARTIFACT_BOUND_NAMES: [&str; 5] = [
    ".checkpoint.authority-v1",
    ".checkpoint.lease.sqlite",
    ".journal.authority-v1",
    ".journal.lock",
    ".journal.lock.sqlite",
];

const PRIVATE_ROOT_LINEAGE_SCHEMA_VERSION: u32 = 1;
const PRIVATE_SQLITE_LINEAGE_SCHEMA_VERSION: u32 = 1;
const PRIVATE_ROOT_STAGING_TAG: &str = ".argos-staging-";
const EPHEMERAL_PROBE_CLEANUP_SCHEMA_VERSION: u32 = 1;
const EPHEMERAL_PROBE_CLEANUP_MARKER_SUFFIX: &str = ".argos-ephemeral-cleanup-v1";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PrivateRootLineageRecord {
    schema_version: u32,
    publication_parent: PrivateObjectId,
    private_root: PrivateObjectId,
    marker: PrivateObjectId,
    context: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PrivateArtifactRootRecord {
    schema_version: u32,
    publication_parent: PrivateObjectId,
    private_root: PrivateObjectId,
    marker: PrivateObjectId,
    purpose: Vec<u8>,
    context: Vec<u8>,
    bound_objects: std::collections::BTreeMap<String, PrivateObjectId>,
    #[cfg(windows)]
    anchor_id: [u8; 16],
    #[cfg(windows)]
    generation: [u8; 16],
}

/// Retained proof that a per-key recovery-artifact namespace was privately
/// staged and published without replacing any pre-existing path. All mutable
/// artifacts are children of this exact directory; its authority and lock
/// files were created before publication and are bound by the root marker.
#[derive(Debug)]
pub(crate) struct PrivateArtifactRootLease {
    publication_parent: File,
    root: File,
    path: std::path::PathBuf,
    id: PrivateObjectId,
    publication_parent_id: PrivateObjectId,
    marker_id: PrivateObjectId,
    context: Vec<u8>,
    bound_objects: std::collections::BTreeMap<String, PrivateObjectId>,
}

impl PrivateArtifactRootLease {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn try_clone_authority(&self) -> io::Result<Self> {
        self.verify_retained_current()?;
        Ok(Self {
            publication_parent: self.publication_parent.try_clone()?,
            root: self.root.try_clone()?,
            path: self.path.clone(),
            id: self.id.clone(),
            publication_parent_id: self.publication_parent_id.clone(),
            marker_id: self.marker_id.clone(),
            context: self.context.clone(),
            bound_objects: self.bound_objects.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn bound_object_ids(&self) -> &std::collections::BTreeMap<String, PrivateObjectId> {
        &self.bound_objects
    }

    pub(crate) fn purpose(&self) -> &[u8] {
        &self.context
    }

    pub(crate) fn child_names(&self) -> io::Result<Vec<OsString>> {
        self.verify_retained_current()?;
        parent_child_names(&self.root, &self.path)
    }

    pub(crate) fn publication_parent_child_names(&self) -> io::Result<Vec<OsString>> {
        self.verify_retained_current()?;
        let parent_path = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "artifact root has no parent")
        })?;
        parent_child_names(&self.publication_parent, parent_path)
    }

    pub(crate) fn discover_sibling_roots(&self) -> io::Result<Vec<PrivateArtifactRootLease>> {
        self.verify_retained_current()?;
        let parent_path = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "artifact root has no parent")
        })?;
        discover_private_artifact_roots_from_parent(
            parent_path,
            &self.publication_parent,
            Some(&self.path),
        )
    }

    pub(crate) fn verify_current(&self) -> io::Result<()> {
        let root = open_child_directory_for_identity(&self.publication_parent, &self.path)?;
        validate_private_directory_handle(&root)?;
        let current = verify_private_artifact_root_from_handles(
            &self.path,
            &self.context,
            self.publication_parent.try_clone()?,
            root,
        )?;
        if current.id != self.id
            || current.publication_parent_id != self.publication_parent_id
            || current.marker_id != self.marker_id
            || current.bound_objects != self.bound_objects
        {
            return Err(invalid_lineage(
                "private artifact namespace changed after authority was retained",
            ));
        }
        Ok(())
    }

    fn verify_retained_current(&self) -> io::Result<()> {
        if private_object_id(&self.publication_parent)? != self.publication_parent_id
            || private_object_id(&self.root)? != self.id
        {
            return Err(invalid_lineage(
                "retained private artifact root handles changed identity",
            ));
        }
        #[cfg(unix)]
        {
            let current_parent = open_publication_parent(self.path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "artifact root has no parent")
            })?)?;
            if private_object_id(&current_parent)? != self.publication_parent_id {
                return Err(invalid_lineage(
                    "private artifact publication parent path was replaced",
                ));
            }
            let current_root = open_private_directory_lease(&self.path)?;
            if private_object_id(&current_root)? != self.id {
                return Err(invalid_lineage("private artifact root path was replaced"));
            }
        }
        let marker = open_child_file_for_bound_identity(
            &self.root,
            &self.path.join(PRIVATE_ARTIFACT_ROOT_MARKER),
        )?;
        if private_object_id(&marker)? != self.marker_id {
            return Err(invalid_lineage("private artifact root marker was replaced"));
        }
        for (name, expected) in &self.bound_objects {
            let child = open_child_file_for_bound_identity(&self.root, &self.path.join(name))?;
            if private_object_id(&child)? != *expected {
                return Err(invalid_lineage(format!(
                    "private artifact root bound object {name} was replaced"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn namespace(&self, lock_name: &str) -> io::Result<NamespaceLease> {
        let expected = self.bound_objects.get(lock_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown artifact namespace lock",
            )
        })?;
        // Cold preflight uses exclusive opens for every bound object. Do it
        // before retaining the domain lock: Windows correctly rejects a new
        // share=0 open once the read/write lock handle is live.
        self.verify_current()?;
        let lease = NamespaceLease::acquire(&self.path, &self.path.join(lock_name))?;
        if &lease.lock_id != expected {
            return Err(invalid_lineage(
                "private artifact namespace lock does not match its create-time identity",
            ));
        }
        if lease.parent_id != self.id {
            return Err(invalid_lineage(
                "private artifact namespace root changed while its lock was acquired",
            ));
        }
        Ok(lease)
    }

    fn namespace_from_verified_root(&self, lock_name: &str) -> io::Result<NamespaceLease> {
        let expected = self.bound_objects.get(lock_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown artifact namespace lock",
            )
        })?;
        self.verify_retained_current()?;
        for (name, bound_id) in &self.bound_objects {
            let child = open_child_file_for_authority(&self.root, &self.path.join(name))?;
            if private_object_id(&child)? != *bound_id {
                return Err(invalid_lineage(format!(
                    "private artifact root bound object {name} changed after discovery"
                )));
            }
        }
        let lease = NamespaceLease::acquire(&self.path, &self.path.join(lock_name))?;
        if &lease.lock_id != expected || lease.parent_id != self.id {
            return Err(invalid_lineage(
                "private artifact namespace changed while its discovered root was retained",
            ));
        }
        Ok(lease)
    }

    fn namespace_from_retained(
        &self,
        held_namespace: &NamespaceLease,
        lock_name: &str,
    ) -> io::Result<NamespaceLease> {
        let expected = self.bound_objects.get(lock_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown artifact namespace lock",
            )
        })?;
        self.verify_retained_current()?;
        held_namespace.verify_current()?;
        if held_namespace.parent_id != self.id {
            return Err(invalid_lineage(
                "retained namespace does not belong to the artifact root",
            ));
        }
        // Cold-check only the target domain lock. Other domains may already
        // retain their own bound lock handles.
        drop(open_child_file_for_authority(
            &self.root,
            &self.path.join(lock_name),
        )?);
        let lease = held_namespace.acquire_sibling_lock(&self.path.join(lock_name))?;
        if &lease.lock_id != expected || lease.parent_id != self.id {
            return Err(invalid_lineage(
                "private artifact target-domain lock changed during acquisition",
            ));
        }
        Ok(lease)
    }
}

pub(crate) fn private_data_dir_child_names(data_dir: &Path) -> io::Result<Vec<OsString>> {
    let container = ensure_private_artifact_container(data_dir)?;
    container.child_names()
}

pub(crate) fn discover_private_artifact_roots(
    data_dir: &Path,
) -> io::Result<Vec<PrivateArtifactRootLease>> {
    discover_private_artifact_roots_except(data_dir, None)
}

pub(crate) fn discover_private_artifact_roots_except(
    data_dir: &Path,
    excluded: Option<&Path>,
) -> io::Result<Vec<PrivateArtifactRootLease>> {
    let container = ensure_private_artifact_container(data_dir)?;
    discover_private_artifact_roots_from_parent(data_dir, &container.root, excluded)
}

fn discover_private_artifact_roots_from_parent(
    data_dir: &Path,
    parent: &File,
    excluded: Option<&Path>,
) -> io::Result<Vec<PrivateArtifactRootLease>> {
    let mut names = parent_child_names(parent, data_dir)?;
    names.sort();
    let mut roots = Vec::new();
    for name in names {
        let Some(text) = name.to_str() else { continue };
        let Some(digest) = text.strip_prefix(".argos-private-artifacts-") else {
            continue;
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_lineage(format!(
                "malformed private artifact root candidate {text}"
            )));
        }
        let path = data_dir.join(&name);
        if excluded == Some(path.as_path()) {
            continue;
        }
        let initial = open_child_directory_for_identity(parent, &path).map_err(|error| {
            invalid_lineage(format!(
                "private artifact root candidate {} is untrusted: {error}",
                path.display()
            ))
        })?;
        validate_private_directory_handle(&initial)?;
        let initial_id = private_object_id(&initial)?;
        let marker = path.join(PRIVATE_ARTIFACT_ROOT_MARKER);
        let (bytes, _) = read_private_lineage_child_bytes(&initial, &marker).map_err(|error| {
            invalid_lineage(format!(
                "private artifact root candidate {} has no authenticated marker: {error}",
                path.display()
            ))
        })?;
        let record: PrivateArtifactRootRecord =
            decode_lineage_record(LineageRecordKind::ArtifactRoot, &bytes)?;
        if private_artifact_root_path(data_dir, &record.purpose) != path {
            return Err(invalid_lineage(format!(
                "private artifact root candidate {} does not match its authenticated purpose",
                path.display()
            )));
        }
        let verified = verify_private_artifact_root_from_handles(
            &path,
            &record.purpose,
            parent.try_clone()?,
            initial,
        )?;
        if verified.id != initial_id {
            return Err(invalid_lineage(format!(
                "private artifact root candidate {} changed during discovery",
                path.display()
            )));
        }
        roots.push(verified);
    }
    Ok(roots)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PrivateArtifactDomain {
    Checkpoint,
    Journal,
}

impl PrivateArtifactDomain {
    fn label(self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::Journal => "journal",
        }
    }

    fn authority_name(self) -> &'static str {
        match self {
            Self::Checkpoint => ".checkpoint.authority-v1",
            Self::Journal => ".journal.authority-v1",
        }
    }

    fn lock_name(self) -> &'static str {
        match self {
            Self::Checkpoint => ".checkpoint.lease.sqlite",
            Self::Journal => ".journal.lock",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PrivateArtifactState {
    Pending {
        generation: [u8; 16],
        candidate: String,
        old: Option<PrivateObjectId>,
    },
    Created {
        generation: [u8; 16],
        candidate: String,
        object: PrivateObjectId,
        old: Option<PrivateObjectId>,
    },
    Replacing {
        generation: [u8; 16],
        candidate: String,
        object: PrivateObjectId,
        len: u64,
        sha256: [u8; 32],
        old: Option<PrivateObjectId>,
    },
    Active {
        generation: [u8; 16],
        object: PrivateObjectId,
    },
    Retiring {
        generation: [u8; 16],
        object: PrivateObjectId,
        cleanup_id: [u8; 16],
        quarantine: Option<(String, PrivateObjectId)>,
    },
    Retired {
        generation: [u8; 16],
        cleanup_id: [u8; 16],
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PrivateArtifactAuthorityRecord {
    schema_version: u32,
    sequence: u64,
    anchor_id: [u8; 16],
    context_hash: [u8; 32],
    purpose_hash: [u8; 32],
    domain: PrivateArtifactDomain,
    state: PrivateArtifactState,
}

/// A retained, serialized view of one artifact domain inside an exact
/// create-time-proven root. The namespace lock and root lease live for the
/// entire read, append, replacement, or cleanup operation.
#[derive(Debug)]
pub(crate) struct PrivateArtifactAccess {
    root: std::sync::Arc<PrivateArtifactRootLease>,
    namespace: NamespaceLease,
    artifact: std::path::PathBuf,
    authority: std::path::PathBuf,
    domain: PrivateArtifactDomain,
    context_hash: [u8; 32],
    purpose_hash: [u8; 32],
}

impl PrivateArtifactAccess {
    pub(crate) fn acquire_existing(
        root_path: &Path,
        domain: PrivateArtifactDomain,
        artifact: &Path,
    ) -> io::Result<Self> {
        Self::acquire_existing_with_observer(root_path, domain, artifact, || Ok(()))
    }

    fn acquire_existing_with_observer(
        root_path: &Path,
        domain: PrivateArtifactDomain,
        artifact: &Path,
        after_marker_read: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Self> {
        let parent = root_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private artifact root has no parent",
            )
        })?;
        let container = ensure_private_artifact_container(parent)?;
        let root = open_child_directory_for_identity(&container.root, root_path)?;
        validate_private_directory_handle(&root)?;
        let initial_id = private_object_id(&root)?;
        let marker = root_path.join(PRIVATE_ARTIFACT_ROOT_MARKER);
        let (bytes, _) = read_private_lineage_child_bytes(&root, &marker)?;
        let record: PrivateArtifactRootRecord =
            decode_lineage_record(LineageRecordKind::ArtifactRoot, &bytes)?;
        if private_artifact_root_path(parent, &record.purpose) != root_path {
            return Err(invalid_lineage(
                "private artifact root name does not match its authenticated purpose",
            ));
        }
        after_marker_read()?;
        let verified = verify_private_artifact_root_from_handles(
            root_path,
            &record.purpose,
            container.root.try_clone()?,
            open_child_directory_for_identity(&container.root, root_path)?,
        )?;
        if verified.id != initial_id {
            return Err(invalid_lineage(
                "private artifact root changed while its existing authority was acquired",
            ));
        }
        Self::from_root(
            std::sync::Arc::new(verified),
            &record.purpose,
            domain,
            artifact,
            None,
        )
    }

    pub(crate) fn acquire(
        root_path: &Path,
        purpose: &[u8],
        domain: PrivateArtifactDomain,
        artifact: &Path,
    ) -> io::Result<Self> {
        if artifact.parent() != Some(root_path) || artifact.file_name().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private artifact must be a direct child of its authority root",
            ));
        }
        let root = std::sync::Arc::new(ensure_private_artifact_root(root_path, purpose)?);
        Self::from_root(root, purpose, domain, artifact, None)
    }

    pub(crate) fn acquire_from_retained_root(
        root: std::sync::Arc<PrivateArtifactRootLease>,
        held_namespace: &NamespaceLease,
        purpose: &[u8],
        domain: PrivateArtifactDomain,
        artifact: &Path,
    ) -> io::Result<Self> {
        if root.path != artifact.parent().unwrap_or_else(|| Path::new(""))
            || root.context != purpose
            || artifact.file_name().is_none()
        {
            return Err(invalid_lineage(
                "retained artifact root does not match the requested purpose and child",
            ));
        }
        Self::from_root(root, purpose, domain, artifact, Some(held_namespace))
    }

    pub(crate) fn acquire_from_verified_root(
        root: PrivateArtifactRootLease,
        purpose: &[u8],
        domain: PrivateArtifactDomain,
        artifact: &Path,
    ) -> io::Result<Self> {
        if root.path != artifact.parent().unwrap_or_else(|| Path::new(""))
            || root.context != purpose
            || artifact.file_name().is_none()
        {
            return Err(invalid_lineage(
                "verified artifact root does not match the requested purpose and child",
            ));
        }
        let root = std::sync::Arc::new(root);
        let namespace = root.namespace_from_verified_root(domain.lock_name())?;
        Self::from_root_and_namespace(root, namespace, purpose, domain, artifact)
    }

    fn from_root(
        root: std::sync::Arc<PrivateArtifactRootLease>,
        purpose: &[u8],
        domain: PrivateArtifactDomain,
        artifact: &Path,
        held_namespace: Option<&NamespaceLease>,
    ) -> io::Result<Self> {
        let namespace = match held_namespace {
            Some(namespace) => root.namespace_from_retained(namespace, domain.lock_name())?,
            None => root.namespace(domain.lock_name())?,
        };
        Self::from_root_and_namespace(root, namespace, purpose, domain, artifact)
    }

    fn from_root_and_namespace(
        root: std::sync::Arc<PrivateArtifactRootLease>,
        namespace: NamespaceLease,
        purpose: &[u8],
        domain: PrivateArtifactDomain,
        artifact: &Path,
    ) -> io::Result<Self> {
        let root_path = root.path.as_path();
        let authority = root_path.join(domain.authority_name());
        let context_hash =
            sha2::Sha256::digest(private_artifact_root_context(root_path, purpose)?).into();
        let mut purpose_bytes = b"argos/private-artifact-purpose/v1".to_vec();
        purpose_bytes.extend_from_slice(domain.label().as_bytes());
        purpose_bytes.extend_from_slice(purpose);
        append_lineage_context_component(
            &mut purpose_bytes,
            artifact.file_name().expect("artifact has a name"),
        );
        let purpose_hash = sha2::Sha256::digest(purpose_bytes).into();
        let access = Self {
            root,
            namespace,
            artifact: artifact.to_path_buf(),
            authority,
            domain,
            context_hash,
            purpose_hash,
        };
        access.verify_authority_object()?;
        let _ = access.current_record()?;
        Ok(access)
    }

    pub(crate) fn root_lease(&self) -> std::sync::Arc<PrivateArtifactRootLease> {
        std::sync::Arc::clone(&self.root)
    }

    fn verify_authority_object(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        let expected = self
            .root
            .bound_objects
            .get(self.domain.authority_name())
            .expect("artifact root binds every authority object");
        let file = open_child_file_for_authority(self.namespace.parent(), &self.authority)?;
        if private_object_id(&file)? != *expected {
            return Err(invalid_lineage(
                "private artifact authority log was replaced",
            ));
        }
        Ok(())
    }

    fn authority_records(&self) -> io::Result<Vec<PrivateArtifactAuthorityRecord>> {
        self.verify_authority_object()?;
        const SLOT_BYTES: usize = 4096;
        const HEADER_BYTES: usize = 8 + 4 + 8 + 4;
        const DIGEST_BYTES: usize = 32;
        const MAGIC: &[u8; 8] = b"ARGOAUT1";
        let bytes = self
            .namespace
            .read_child_bounded(&self.authority, SLOT_BYTES * 2)?;
        let mut records = Vec::new();
        for index in 0..2 {
            let start = index * SLOT_BYTES;
            if bytes.len() < start + SLOT_BYTES {
                continue;
            }
            let slot = &bytes[start..start + SLOT_BYTES];
            if &slot[..8] != MAGIC {
                continue;
            }
            let version = u32::from_le_bytes(slot[8..12].try_into().unwrap());
            let sequence = u64::from_le_bytes(slot[12..20].try_into().unwrap());
            let length = u32::from_le_bytes(slot[20..24].try_into().unwrap()) as usize;
            if version != 1 || length > SLOT_BYTES - HEADER_BYTES - DIGEST_BYTES {
                continue;
            }
            let payload = &slot[HEADER_BYTES..HEADER_BYTES + length];
            let digest_offset = SLOT_BYTES - DIGEST_BYTES;
            let stored_digest: [u8; 32] = slot[digest_offset..].try_into().unwrap();
            if <[u8; 32]>::from(sha2::Sha256::digest(payload)) != stored_digest {
                continue;
            }
            let record: PrivateArtifactAuthorityRecord = match serde_json::from_slice(payload) {
                Ok(record) => record,
                Err(_) => continue,
            };
            if record.schema_version != 1
                || record.sequence != sequence
                || record.context_hash != self.context_hash
                || record.purpose_hash != self.purpose_hash
                || record.domain != self.domain
            {
                continue;
            }
            records.push(record);
        }
        records.sort_by_key(|record| record.sequence);
        if records.len() == 2 && records[0].anchor_id != records[1].anchor_id {
            return Err(invalid_lineage(
                "artifact authority slots disagree on their permanent anchor",
            ));
        }
        Ok(records)
    }

    fn current_record(&self) -> io::Result<Option<PrivateArtifactAuthorityRecord>> {
        Ok(self.authority_records()?.pop())
    }

    pub(crate) fn current_state(&self) -> io::Result<Option<PrivateArtifactState>> {
        Ok(self.current_record()?.map(|record| record.state))
    }

    pub(crate) fn current_authority(&self) -> io::Result<Option<([u8; 16], PrivateArtifactState)>> {
        Ok(self
            .current_record()?
            .map(|record| (record.anchor_id, record.state)))
    }

    pub(crate) fn namespace(&self) -> &NamespaceLease {
        &self.namespace
    }

    pub(crate) fn artifact_path(&self) -> &Path {
        &self.artifact
    }

    pub(crate) fn read_optional_child_version(
        &self,
    ) -> io::Result<Option<(Vec<u8>, PrivateObjectId)>> {
        match self.current_record()? {
            None => {
                if self.namespace.child_exists(&self.artifact)? {
                    Err(invalid_lineage(
                        "existing private artifact predates create-time authority; preserved unchanged",
                    ))
                } else {
                    Ok(None)
                }
            }
            Some(PrivateArtifactAuthorityRecord {
                state: PrivateArtifactState::Active { object, .. },
                ..
            }) => {
                let (bytes, actual) = self.namespace.read_child_version(&self.artifact)?;
                if actual != object {
                    return Err(invalid_lineage(
                        "private artifact path does not name its active exact object",
                    ));
                }
                self.verify_authority_object()?;
                Ok(Some((bytes, actual)))
            }
            Some(record) => Err(invalid_lineage(format!(
                "{} artifact authority is interrupted in state {:?}; preserved unchanged",
                self.domain.label(),
                record.state
            ))),
        }
    }

    fn append_state(&self, state: PrivateArtifactState) -> io::Result<()> {
        const SLOT_BYTES: usize = 4096;
        const HEADER_BYTES: usize = 8 + 4 + 8 + 4;
        const DIGEST_BYTES: usize = 32;
        let records = self.authority_records()?;
        let current = records.last();
        let anchor_id = current.map_or_else(
            || uuid::Uuid::new_v4().into_bytes(),
            |record| record.anchor_id,
        );
        let sequence = current.map_or(0, |record| record.sequence + 1);
        let record = PrivateArtifactAuthorityRecord {
            schema_version: 1,
            sequence,
            anchor_id,
            context_hash: self.context_hash,
            purpose_hash: self.purpose_hash,
            domain: self.domain,
            state,
        };
        let payload = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if payload.len() > SLOT_BYTES - HEADER_BYTES - DIGEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private artifact authority state exceeds its fixed slot",
            ));
        }
        let mut slot = vec![0u8; SLOT_BYTES];
        slot[..8].copy_from_slice(b"ARGOAUT1");
        slot[8..12].copy_from_slice(&1u32.to_le_bytes());
        slot[12..20].copy_from_slice(&sequence.to_le_bytes());
        slot[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        slot[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(&payload);
        let digest_offset = SLOT_BYTES - DIGEST_BYTES;
        slot[digest_offset..].copy_from_slice(&sha2::Sha256::digest(&payload));
        let mut file = open_child_file_for_lock(self.namespace.parent(), &self.authority)?;
        let id = private_object_id(&file)?;
        let expected = self
            .root
            .bound_objects
            .get(self.domain.authority_name())
            .expect("artifact root binds every authority object");
        if &id != expected {
            return Err(invalid_lineage(
                "private artifact authority changed before durable transition",
            ));
        }
        file.seek(SeekFrom::Start((sequence as usize % 2 * SLOT_BYTES) as u64))?;
        file.write_all(&slot)?;
        file.flush()?;
        file.sync_all()?;
        // Windows authority verification uses a cold share=0 reopen. Release
        // the compatible read/write state handle before that preflight.
        drop(file);
        self.verify_authority_object()
    }

    fn active_generation_and_id(&self) -> io::Result<([u8; 16], PrivateObjectId)> {
        match self.current_state()? {
            Some(PrivateArtifactState::Active { generation, object }) => {
                Ok((generation, object))
            }
            Some(state) => Err(invalid_lineage(format!(
                "{} artifact authority is interrupted in state {state:?}; preserve it for explicit recovery",
                self.domain.label()
            ))),
            None => Err(invalid_lineage(format!(
                "{} artifact has no create-time authority",
                self.domain.label()
            ))),
        }
    }

    #[cfg(test)]
    pub(crate) fn read_child_version(&self) -> io::Result<(Vec<u8>, PrivateObjectId)> {
        let (_, expected) = self.active_generation_and_id()?;
        let (bytes, actual) = self.namespace.read_child_version(&self.artifact)?;
        if actual != expected {
            return Err(invalid_lineage(
                "private artifact path does not name its active exact object",
            ));
        }
        self.verify_authority_object()?;
        Ok((bytes, actual))
    }

    pub(crate) fn open_active_child(
        &self,
    ) -> io::Result<Option<(File, [u8; 16], PrivateObjectId)>> {
        match self.current_state()? {
            None => {
                if self.namespace.child_exists(&self.artifact)? {
                    Err(invalid_lineage(
                        "existing private artifact predates create-time authority; preserved unchanged",
                    ))
                } else {
                    Ok(None)
                }
            }
            Some(PrivateArtifactState::Active { generation, object }) => {
                let file = open_child_file_for_removal(self.namespace.parent(), &self.artifact)?;
                if private_object_id(&file)? != object {
                    return Err(invalid_lineage(
                        "private artifact path does not name its active exact object",
                    ));
                }
                self.verify_authority_object()?;
                Ok(Some((file, generation, object)))
            }
            Some(PrivateArtifactState::Replacing {
                generation,
                candidate,
                object,
                len,
                sha256,
                old,
            }) => {
                self.finish_replacing(
                    generation,
                    &candidate,
                    &object,
                    len,
                    &sha256,
                    old.as_ref(),
                )?;
                self.open_active_child()
            }
            Some(PrivateArtifactState::Retired { .. }) => {
                if self.namespace.child_exists(&self.artifact)? {
                    Err(invalid_lineage(
                        "retired artifact authority still has a canonical object",
                    ))
                } else {
                    Ok(None)
                }
            }
            Some(state) => Err(invalid_lineage(format!(
                "{} artifact authority is interrupted in state {state:?}; preserve it for explicit recovery",
                self.domain.label()
            ))),
        }
    }

    #[cfg(test)]
    pub(crate) fn append_child_if_unchanged(
        &self,
        expected: Option<(&PrivateObjectId, &[u8])>,
        suffix: &[u8],
    ) -> io::Result<()> {
        self.append_child_if_unchanged_with_observer(expected, suffix, |_, _| Ok(()))
    }

    pub(crate) fn append_child_if_unchanged_with_lineage(
        &self,
        expected: Option<(&PrivateObjectId, &[u8])>,
        build_suffix: impl FnOnce([u8; 16], [u8; 16]) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        match self.current_record()? {
            None => {
                if self.namespace.child_exists(&self.artifact)? {
                    return Err(invalid_lineage(
                        "existing private artifact predates create-time authority; preserved unchanged",
                    ));
                }
                if expected.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "expected private artifact is absent",
                    ));
                }
                let generation = uuid::Uuid::new_v4().into_bytes();
                let candidate = self
                    .artifact
                    .file_name()
                    .expect("artifact has a name")
                    .to_string_lossy()
                    .into_owned();
                self.append_state(PrivateArtifactState::Pending {
                    generation,
                    candidate: candidate.clone(),
                    old: None,
                })?;
                let mut file =
                    create_child_file_read_append(self.namespace.parent(), &self.artifact)?;
                file.sync_all()?;
                self.namespace.sync_parent()?;
                let object = private_object_id(&file)?;
                self.append_state(PrivateArtifactState::Created {
                    generation,
                    candidate,
                    object: object.clone(),
                    old: None,
                })?;
                let (anchor, state) = self.current_authority()?.ok_or_else(|| {
                    invalid_lineage("new artifact authority disappeared before its first byte")
                })?;
                if !matches!(state, PrivateArtifactState::Created { generation: current, object: ref current_object, .. }
                    if current == generation && current_object == &object)
                {
                    return Err(invalid_lineage(
                        "new artifact authority changed before its first byte",
                    ));
                }
                let suffix = build_suffix(anchor, generation)?;
                file.write_all(&suffix)?;
                file.flush()?;
                file.sync_all()?;
                if private_object_id(&file)? != object {
                    return Err(invalid_lineage(
                        "private artifact changed during its first write",
                    ));
                }
                self.append_state(PrivateArtifactState::Active { generation, object })?;
                self.verify_authority_object()
            }
            Some(PrivateArtifactAuthorityRecord {
                anchor_id,
                state: PrivateArtifactState::Active { generation, object },
                ..
            }) => {
                let (current, actual) = self.namespace.read_child_version(&self.artifact)?;
                if actual != object {
                    return Err(invalid_lineage(
                        "private artifact was replaced before append",
                    ));
                }
                match expected {
                    Some((expected_id, expected_bytes))
                        if *expected_id == actual && expected_bytes == current => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "private artifact changed before append",
                        ))
                    }
                }
                let suffix = build_suffix(anchor_id, generation)?;
                self.namespace.append_child_if_unchanged(
                    &self.artifact,
                    Some((&actual, &current)),
                    &suffix,
                )?;
                self.verify_authority_object()
            }
            Some(record) => Err(invalid_lineage(format!(
                "{} artifact authority is interrupted in state {:?}; preserved unchanged",
                self.domain.label(),
                record.state
            ))),
        }
    }

    fn finish_replacing(
        &self,
        generation: [u8; 16],
        candidate: &str,
        object: &PrivateObjectId,
        len: u64,
        sha256: &[u8; 32],
        old: Option<&PrivateObjectId>,
    ) -> io::Result<()> {
        let candidate_path = self.root.path.join(candidate);
        if let Ok((current, canonical_id)) = self.namespace.read_child_version(&self.artifact) {
            if canonical_id == *object
                && current.len() as u64 == len
                && <[u8; 32]>::from(sha2::Sha256::digest(&current)) == *sha256
            {
                self.append_state(PrivateArtifactState::Active {
                    generation,
                    object: object.clone(),
                })?;
                return Ok(());
            }
            if old != Some(&canonical_id) {
                return Err(invalid_lineage(
                    "canonical private artifact does not match the replacing generation",
                ));
            }
        }
        let (candidate_bytes, candidate_id) = self.namespace.read_child_version(&candidate_path)?;
        if candidate_id != *object
            || candidate_bytes.len() as u64 != len
            || <[u8; 32]>::from(sha2::Sha256::digest(&candidate_bytes)) != *sha256
        {
            return Err(invalid_lineage(
                "private artifact replacement candidate does not match durable authority",
            ));
        }
        if let Some(old) = old {
            match open_child_file_for_removal(self.namespace.parent(), &self.artifact) {
                Ok(file) => {
                    if private_object_id(&file)? != *old {
                        return Err(invalid_lineage(
                            "private artifact changed before exact replacement",
                        ));
                    }
                    self.namespace
                        .remove_open_child(&self.artifact, &file, old)?;
                    self.namespace.sync_parent()?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let candidate_file = open_child_file_for_removal(self.namespace.parent(), &candidate_path)?;
        if private_object_id(&candidate_file)? != *object {
            return Err(invalid_lineage(
                "private artifact replacement candidate changed before publication",
            ));
        }
        self.namespace.rename_open_child(
            &candidate_path,
            &self.artifact,
            &candidate_file,
            object,
        )?;
        self.append_state(PrivateArtifactState::Active {
            generation,
            object: object.clone(),
        })
    }

    pub(crate) fn replace_child(&self, bytes: &[u8]) -> io::Result<()> {
        let current = self.current_state()?;
        if let Some(PrivateArtifactState::Replacing {
            generation,
            candidate,
            object,
            len,
            sha256,
            old,
        }) = current.clone()
        {
            self.finish_replacing(generation, &candidate, &object, len, &sha256, old.as_ref())?;
        }
        let old = match self.current_state()? {
            None => None,
            Some(PrivateArtifactState::Active { object, .. }) => Some(object),
            // A caller that owns the normal checkpoint-save path is the
            // explicit start of a new scan generation after retirement.
            Some(PrivateArtifactState::Retired { .. }) => None,
            Some(state) => {
                return Err(invalid_lineage(format!(
                "{} artifact replacement is interrupted in state {state:?}; preserved unchanged",
                self.domain.label()
            )))
            }
        };
        if old.is_none() && self.namespace.child_exists(&self.artifact)? {
            return Err(invalid_lineage(
                "existing private artifact predates create-time authority; preserved unchanged",
            ));
        }
        let generation = uuid::Uuid::new_v4().into_bytes();
        let candidate = format!(
            ".{}.candidate-{}",
            self.artifact
                .file_name()
                .expect("artifact has a name")
                .to_string_lossy(),
            uuid::Uuid::new_v4()
        );
        self.append_state(PrivateArtifactState::Pending {
            generation,
            candidate: candidate.clone(),
            old: old.clone(),
        })?;
        let candidate_path = self.root.path.join(&candidate);
        let mut file = create_child_file_read_append(self.namespace.parent(), &candidate_path)?;
        file.sync_all()?;
        self.namespace.sync_parent()?;
        let object = private_object_id(&file)?;
        self.append_state(PrivateArtifactState::Created {
            generation,
            candidate: candidate.clone(),
            object: object.clone(),
            old: old.clone(),
        })?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        if private_object_id(&file)? != object || file.metadata()?.len() != bytes.len() as u64 {
            return Err(invalid_lineage(
                "private artifact replacement changed during write",
            ));
        }
        drop(file);
        let len = bytes.len() as u64;
        let sha256 = sha2::Sha256::digest(bytes).into();
        self.append_state(PrivateArtifactState::Replacing {
            generation,
            candidate: candidate.clone(),
            object: object.clone(),
            len,
            sha256,
            old: old.clone(),
        })?;
        self.finish_replacing(generation, &candidate, &object, len, &sha256, old.as_ref())
    }

    /// Move the exact active checkpoint into a deterministic quarantine and
    /// durably bind that name and object identity before any deletion. The
    /// caller must already have persisted its journal discard boundary.
    pub(crate) fn quarantine_active_child(
        &self,
        expected: &PrivateObjectId,
        cleanup_id: [u8; 16],
    ) -> io::Result<(std::path::PathBuf, File, [u8; 16])> {
        if self.domain != PrivateArtifactDomain::Checkpoint {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only checkpoints may enter artifact retirement",
            ));
        }
        let (generation, object) = self.active_generation_and_id()?;
        if &object != expected {
            return Err(invalid_lineage(
                "checkpoint authority does not match the reviewed object",
            ));
        }
        let quarantine_name = format!(
            ".checkpoint-retiring-{}",
            uuid::Uuid::from_bytes(cleanup_id)
        );
        let quarantine = self.root.path.join(&quarantine_name);
        if self.namespace.child_exists(&quarantine)? {
            return Err(invalid_lineage(
                "checkpoint retirement quarantine already exists",
            ));
        }
        // Persist the exact planned quarantine before the rename. Because the
        // rename preserves object identity, this one record describes both
        // sides of the only crash window.
        self.append_state(PrivateArtifactState::Retiring {
            generation,
            object: object.clone(),
            cleanup_id,
            quarantine: Some((quarantine_name, object.clone())),
        })?;
        let file = open_child_file_for_removal(self.namespace.parent(), &self.artifact)?;
        if private_object_id(&file)? != object {
            return Err(invalid_lineage(
                "checkpoint changed after retirement authority was persisted",
            ));
        }
        self.namespace
            .rename_open_child(&self.artifact, &quarantine, &file, &object)?;
        self.namespace.sync_parent()?;
        self.verify_authority_object()?;
        Ok((quarantine, file, generation))
    }

    pub(crate) fn finish_retiring_child(
        &self,
        quarantine: &Path,
        file: &File,
        expected: &PrivateObjectId,
        cleanup_id: [u8; 16],
    ) -> io::Result<()> {
        let generation = match self.current_state()? {
            Some(PrivateArtifactState::Retiring {
                generation,
                object,
                cleanup_id: recorded_cleanup,
                quarantine: Some((name, quarantine_id)),
            }) if object == *expected
                && quarantine_id == *expected
                && recorded_cleanup == cleanup_id
                && quarantine.file_name() == Some(std::ffi::OsStr::new(&name)) =>
            {
                generation
            }
            Some(state) => {
                return Err(invalid_lineage(format!(
                    "checkpoint retirement state does not authorize deletion: {state:?}"
                )))
            }
            None => return Err(invalid_lineage("checkpoint has no retirement authority")),
        };
        self.namespace
            .remove_open_child(quarantine, file, expected)?;
        self.namespace.sync_parent()?;
        self.append_state(PrivateArtifactState::Retired {
            generation,
            cleanup_id,
        })
    }

    /// Restore a surviving exact quarantine after a crash. Stored network
    /// observations do not authorize deletion after arbitrary downtime.
    pub(crate) fn restore_retiring_child(&self) -> io::Result<bool> {
        let (generation, object, quarantine_name) = match self.current_state()? {
            Some(PrivateArtifactState::Retiring {
                generation,
                object,
                quarantine: Some((name, quarantine_id)),
                ..
            }) if object == quarantine_id => (generation, object, name),
            Some(PrivateArtifactState::Retiring { .. }) => {
                return Err(invalid_lineage(
                    "checkpoint retirement has no exact quarantine binding",
                ))
            }
            _ => return Ok(false),
        };
        let quarantine = self.root.path.join(quarantine_name);
        let canonical = open_child_file_for_removal(self.namespace.parent(), &self.artifact);
        let quarantined = open_child_file_for_removal(self.namespace.parent(), &quarantine);
        match (canonical, quarantined) {
            (Ok(file), Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                if private_object_id(&file)? != object {
                    return Err(invalid_lineage(
                        "surviving checkpoint does not match retirement authority",
                    ));
                }
            }
            (Err(error), Ok(file)) if error.kind() == io::ErrorKind::NotFound => {
                if private_object_id(&file)? != object {
                    return Err(invalid_lineage(
                        "checkpoint quarantine does not match retirement authority",
                    ));
                }
                self.namespace
                    .rename_open_child(&quarantine, &self.artifact, &file, &object)?;
                self.namespace.sync_parent()?;
            }
            (Ok(_), Ok(_)) => {
                return Err(invalid_lineage(
                    "canonical checkpoint and retirement quarantine both exist",
                ))
            }
            (Err(left), Err(right))
                if left.kind() == io::ErrorKind::NotFound
                    && right.kind() == io::ErrorKind::NotFound =>
            {
                return Err(invalid_lineage(
                    "retiring checkpoint and its exact quarantine are both absent",
                ))
            }
            (Err(error), _) | (_, Err(error)) => return Err(error),
        }
        self.append_state(PrivateArtifactState::Active { generation, object })?;
        Ok(true)
    }

    #[cfg(test)]
    fn append_child_if_unchanged_with_observer(
        &self,
        expected: Option<(&PrivateObjectId, &[u8])>,
        suffix: &[u8],
        after_created: impl FnOnce(&File, &PrivateObjectId) -> io::Result<()>,
    ) -> io::Result<()> {
        match self.current_record()? {
            None => {
                if self.namespace.child_exists(&self.artifact)? {
                    return Err(invalid_lineage(
                        "existing private artifact predates create-time authority; preserved unchanged",
                    ));
                }
                if expected.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "expected private artifact is absent",
                    ));
                }
                let generation = uuid::Uuid::new_v4().into_bytes();
                let candidate = self
                    .artifact
                    .file_name()
                    .expect("artifact has a name")
                    .to_string_lossy()
                    .into_owned();
                self.append_state(PrivateArtifactState::Pending {
                    generation,
                    candidate: candidate.clone(),
                    old: None,
                })?;
                let mut file =
                    create_child_file_read_append(self.namespace.parent(), &self.artifact)?;
                file.sync_all()?;
                self.namespace.sync_parent()?;
                let object = private_object_id(&file)?;
                self.append_state(PrivateArtifactState::Created {
                    generation,
                    candidate,
                    object: object.clone(),
                    old: None,
                })?;
                after_created(&file, &object)?;
                file.write_all(suffix)?;
                file.flush()?;
                file.sync_all()?;
                if private_object_id(&file)? != object {
                    return Err(invalid_lineage(
                        "private artifact changed during its first write",
                    ));
                }
                self.append_state(PrivateArtifactState::Active { generation, object })?;
                self.verify_authority_object()
            }
            Some(PrivateArtifactAuthorityRecord {
                state: PrivateArtifactState::Active { object, .. },
                ..
            }) => {
                let (current, actual) = self.namespace.read_child_version(&self.artifact)?;
                if actual != object {
                    return Err(invalid_lineage(
                        "private artifact was replaced before append",
                    ));
                }
                match expected {
                    Some((expected_id, expected_bytes))
                        if *expected_id == actual && expected_bytes == current => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "private artifact changed before append",
                        ))
                    }
                }
                self.namespace.append_child_if_unchanged(
                    &self.artifact,
                    Some((&actual, &current)),
                    suffix,
                )?;
                self.verify_authority_object()
            }
            Some(record) => Err(invalid_lineage(format!(
                "{} artifact authority is interrupted in state {:?}; preserved unchanged",
                self.domain.label(),
                record.state
            ))),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PrivateSqliteLineageRecord {
    schema_version: u32,
    private_root: PrivateObjectId,
    parent: PrivateObjectId,
    database: PrivateObjectId,
    marker: PrivateObjectId,
    context: Vec<u8>,
    #[cfg(windows)]
    generation: [u8; 16],
    #[cfg(windows)]
    anchor_id: [u8; 16],
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EphemeralProbeCleanupRecord {
    schema_version: u32,
    private_root: std::path::PathBuf,
    database: std::path::PathBuf,
    binding: PrivateWorkspaceCleanupBinding,
    marker: PrivateObjectId,
}

#[derive(Clone, Copy)]
enum LineageRecordKind {
    Root,
    Sqlite,
    ArtifactRoot,
    #[cfg(windows)]
    CleanupMarker,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WindowsLineageObjects {
    publication_parent: PrivateObjectId,
    private_root: PrivateObjectId,
    root_marker: PrivateObjectId,
    sqlite_parent: PrivateObjectId,
    database: PrivateObjectId,
    sqlite_marker: PrivateObjectId,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum WindowsLineageState {
    Pending {
        generation: [u8; 16],
    },
    Active {
        generation: [u8; 16],
        objects: WindowsLineageObjects,
    },
    Revoked {
        retired_generation: [u8; 16],
        cleanup_id: [u8; 16],
        objects: WindowsLineageObjects,
    },
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WindowsLineageAuthorityRecord {
    schema_version: u32,
    context_hash: [u8; 32],
    anchor_id: [u8; 16],
    state: WindowsLineageState,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WindowsArtifactRootObjects {
    publication_parent: PrivateObjectId,
    private_root: PrivateObjectId,
    marker: PrivateObjectId,
    bound_objects: std::collections::BTreeMap<String, PrivateObjectId>,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum WindowsArtifactRootState {
    Pending {
        generation: [u8; 16],
    },
    Active {
        generation: [u8; 16],
        objects: WindowsArtifactRootObjects,
    },
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WindowsArtifactRootAuthorityRecord {
    schema_version: u32,
    context_hash: [u8; 32],
    anchor_id: [u8; 16],
    state: WindowsArtifactRootState,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TrustedSqliteIdentity {
    canonical_path: std::path::PathBuf,
    publication_parent: PrivateObjectId,
    private_root: PrivateObjectId,
    parent: PrivateObjectId,
    database: PrivateObjectId,
    marker: PrivateObjectId,
    anchor_id: [u8; 16],
    generation: [u8; 16],
}

#[cfg(windows)]
#[derive(Debug)]
struct TrustedSqliteAuthority {
    identity: TrustedSqliteIdentity,
    _root: File,
    _parent: File,
    database: File,
    marker: File,
}

#[cfg(windows)]
#[derive(Debug, Default)]
struct TrustedSqliteRegistry {
    authorities: std::collections::HashMap<std::path::PathBuf, TrustedSqliteAuthority>,
    cleanup_held: std::collections::HashSet<std::path::PathBuf>,
}

/// An exact workspace-leaf handle retained across cleanup marker creation,
/// Windows lineage revocation, rename, and recursive removal.
#[derive(Debug)]
pub(crate) struct RetainedWorkspaceDirectory {
    directory: File,
    id: PrivateObjectId,
    cleanup_hold: Option<SqliteCleanupHold>,
}

/// Exact authority for removing a throwaway shielded-probe workspace. The
/// registry remains Active until the exact private root has been removed and
/// its publication parent synced; only then is the per-probe authority retired.
#[derive(Debug)]
pub(crate) struct EphemeralProbeCleanup {
    publication_parent: File,
    publication_parent_path: std::path::PathBuf,
    private_root: std::path::PathBuf,
    private_root_directory: File,
    private_root_id: PrivateObjectId,
    marker_path: std::path::PathBuf,
    marker_id: PrivateObjectId,
    #[cfg(windows)]
    database: std::path::PathBuf,
    binding: PrivateWorkspaceCleanupBinding,
    cleanup_hold: Option<SqliteCleanupHold>,
    _registration: EphemeralProbeRegistration,
}

/// A process-held, exact private file lock proving that an authenticated probe
/// marker belongs to a live probe and must be skipped by stale recovery.
#[derive(Debug)]
pub(crate) struct EphemeralProbeRegistration {
    file: File,
    id: PrivateObjectId,
    path: std::path::PathBuf,
}

#[derive(Debug)]
struct SqliteCleanupHold {
    #[cfg(windows)]
    registry_key: std::path::PathBuf,
    #[cfg(windows)]
    _open_guard: PrivateSqliteOpenGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PrivateWorkspaceCleanupBinding {
    pub(crate) publication_parent: PrivateObjectId,
    pub(crate) private_root: PrivateObjectId,
    pub(crate) root_marker: PrivateObjectId,
    pub(crate) workspace: PrivateObjectId,
    pub(crate) database: PrivateObjectId,
    pub(crate) database_marker: PrivateObjectId,
    pub(crate) anchor_id: Option<[u8; 16]>,
    pub(crate) generation: Option<[u8; 16]>,
}

impl RetainedWorkspaceDirectory {
    pub(crate) fn id(&self) -> &PrivateObjectId {
        &self.id
    }
}

#[derive(Debug)]
pub(crate) struct PrivateSqliteOpenGuard {
    #[cfg(windows)]
    key: std::path::PathBuf,
}

#[cfg(windows)]
fn sqlite_open_gates() -> &'static (
    std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    std::sync::Condvar,
) {
    static GATES: std::sync::OnceLock<(
        std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
        std::sync::Condvar,
    )> = std::sync::OnceLock::new();
    GATES.get_or_init(|| {
        (
            std::sync::Mutex::new(std::collections::HashSet::new()),
            std::sync::Condvar::new(),
        )
    })
}

pub(crate) fn lock_private_sqlite_open(path: &Path) -> io::Result<PrivateSqliteOpenGuard> {
    #[cfg(windows)]
    {
        let key = fs::canonicalize(path)?;
        let (mutex, changed) = sqlite_open_gates();
        let mut held = mutex
            .lock()
            .map_err(|_| io::Error::other("private SQLite open gate is poisoned"))?;
        while held.contains(&key) {
            held = changed
                .wait(held)
                .map_err(|_| io::Error::other("private SQLite open gate is poisoned"))?;
        }
        held.insert(key.clone());
        Ok(PrivateSqliteOpenGuard { key })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(PrivateSqliteOpenGuard {})
    }
}

#[cfg(windows)]
impl Drop for PrivateSqliteOpenGuard {
    fn drop(&mut self) {
        let (mutex, changed) = sqlite_open_gates();
        if let Ok(mut held) = mutex.lock() {
            held.remove(&self.key);
            changed.notify_all();
        }
    }
}

#[cfg(windows)]
impl Drop for SqliteCleanupHold {
    fn drop(&mut self) {
        if let Ok(mut registry) = trusted_sqlite_authorities().lock() {
            registry.cleanup_held.remove(&self.registry_key);
        }
    }
}

/// Retained proof that a wallet-private root was created by the private-first
/// policy. Existing unmarked roots are never blessed in place.
#[derive(Debug)]
pub(crate) struct PrivateRootLineageLease {
    root: File,
    path: std::path::PathBuf,
    context_path: std::path::PathBuf,
    id: PrivateObjectId,
    publication_parent_id: PrivateObjectId,
    root_marker_id: PrivateObjectId,
}

impl PrivateRootLineageLease {
    pub(crate) fn id(&self) -> &PrivateObjectId {
        &self.id
    }

    pub(crate) fn verify_current(&self) -> io::Result<()> {
        if private_object_id(&self.root)? != self.id {
            return Err(invalid_lineage("retained private workspace root changed"));
        }
        let parent_path = self.path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private workspace root has no parent",
            )
        })?;
        let parent = open_publication_parent(parent_path)?;
        if private_object_id(&parent)? != self.publication_parent_id {
            return Err(invalid_lineage(
                "workspace publication parent changed after lineage verification",
            ));
        }
        #[cfg(unix)]
        {
            let current = unix_private::open_directory(&self.path)?;
            unix_private::verify_private_directory(&current)?;
            if private_object_id(&current)? != self.id {
                return Err(invalid_lineage(
                    "private workspace root path no longer names the retained object",
                ));
            }
        }
        Ok(())
    }

    fn contextualize(&self, path: &Path) -> io::Result<std::path::PathBuf> {
        let relative = path.strip_prefix(&self.path).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private lineage child is outside its retained root",
            )
        })?;
        Ok(self.context_path.join(relative))
    }
}

pub(crate) fn private_object_id(file: &File) -> io::Result<PrivateObjectId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata()?;
        Ok(PrivateObjectId::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION},
        };
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(PrivateObjectId::Windows {
            volume_serial: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private object identity is unsupported on this platform",
        ))
    }
}

/// Stable authority over a private pathname namespace. The parent and lock
/// objects remain open and identity-checked for the entire operation.
#[derive(Debug)]
pub(crate) struct NamespaceLease {
    parent: File,
    parent_path: std::path::PathBuf,
    parent_id: PrivateObjectId,
    lock_file: File,
    lock_path: std::path::PathBuf,
    lock_id: PrivateObjectId,
}

#[derive(Debug)]
pub(crate) struct NamespaceChildLock<'a> {
    namespace: &'a NamespaceLease,
    file: File,
    path: std::path::PathBuf,
    id: PrivateObjectId,
}

#[derive(Debug)]
pub(crate) struct RetainedNamespaceChild {
    namespace: NamespaceLease,
    file: File,
    path: std::path::PathBuf,
    id: PrivateObjectId,
}

impl NamespaceLease {
    pub(crate) fn acquire(parent_path: &Path, lock_path: &Path) -> io::Result<Self> {
        require_direct_child(parent_path, lock_path)?;
        let parent = open_parent_lease_handle(parent_path)?;
        lock_parent_namespace(&parent)?;
        let parent_id = private_object_id(&parent)?;
        let lock_file = open_child_file_for_lock(&parent, lock_path)?;
        parent.sync_all()?;
        lock_exclusive(&lock_file)?;
        let lock_id = private_object_id(&lock_file)?;
        let lease = Self {
            parent,
            parent_path: parent_path.to_path_buf(),
            parent_id,
            lock_file,
            lock_path: lock_path.to_path_buf(),
            lock_id,
        };
        lease.verify_current()?;
        Ok(lease)
    }

    fn acquire_sibling_lock(&self, lock_path: &Path) -> io::Result<Self> {
        require_direct_child(&self.parent_path, lock_path)?;
        self.verify_current()?;
        let parent = self.parent.try_clone()?;
        let lock_file = open_child_file_for_lock(&parent, lock_path)?;
        lock_exclusive(&lock_file)?;
        let lock_id = private_object_id(&lock_file)?;
        let lease = Self {
            parent,
            parent_path: self.parent_path.clone(),
            parent_id: self.parent_id.clone(),
            lock_file,
            lock_path: lock_path.to_path_buf(),
            lock_id,
        };
        lease.verify_current()?;
        Ok(lease)
    }

    pub(crate) fn verify_current(&self) -> io::Result<()> {
        if private_object_id(&self.parent)? != self.parent_id
            || private_object_id(&self.lock_file)? != self.lock_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained private namespace object changed",
            ));
        }
        let current_parent = open_parent_identity_handle(&self.parent_path)?;
        if private_object_id(&current_parent)? != self.parent_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private namespace parent was replaced while held",
            ));
        }
        let current_lock = open_identity_file(&self.lock_path)?;
        if private_object_id(&current_lock)? != self.lock_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private namespace lock was replaced while held",
            ));
        }
        let current_parent = open_parent_identity_handle(&self.parent_path)?;
        if private_object_id(&current_parent)? != self.parent_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private namespace parent changed while the lock was rechecked",
            ));
        }
        Ok(())
    }

    pub(crate) fn parent(&self) -> &File {
        &self.parent
    }

    pub(crate) fn parent_path(&self) -> &Path {
        &self.parent_path
    }

    pub(crate) fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub(crate) fn sync_parent(&self) -> io::Result<()> {
        self.parent.sync_all()
    }

    pub(crate) fn require_child(&self, path: &Path) -> io::Result<()> {
        require_direct_child(&self.parent_path, path)
    }

    pub(crate) fn read_child(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.read_child_version(path).map(|(bytes, _)| bytes)
    }

    pub(crate) fn read_child_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.require_child(path)?;
        self.verify_current()?;
        let file = open_child_file_for_authority(&self.parent, path)?;
        let mut bytes = Vec::new();
        file.take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private metadata exceeds its maximum size",
            ));
        }
        self.verify_current()?;
        Ok(bytes)
    }

    pub(crate) fn read_child_version(&self, path: &Path) -> io::Result<(Vec<u8>, PrivateObjectId)> {
        self.require_child(path)?;
        self.verify_current()?;
        let mut file = open_child_file_for_authority(&self.parent, path)?;
        let identity = private_object_id(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        self.verify_current()?;
        Ok((bytes, identity))
    }

    pub(crate) fn append_child_if_unchanged(
        &self,
        path: &Path,
        expected: Option<(&PrivateObjectId, &[u8])>,
        suffix: &[u8],
    ) -> io::Result<()> {
        self.append_child_if_unchanged_with_observer(path, expected, suffix, || Ok(()))
    }

    fn append_child_if_unchanged_with_observer(
        &self,
        path: &Path,
        expected: Option<(&PrivateObjectId, &[u8])>,
        suffix: &[u8],
        after_verify: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.require_child(path)?;
        self.verify_current()?;
        after_verify()?;
        let created = expected.is_none();
        let mut file = match open_child_file_read_append(&self.parent, path) {
            Ok(file) => file,
            Err(err) if created && err.kind() == io::ErrorKind::NotFound => {
                create_child_file_read_append(&self.parent, path)?
            }
            Err(err) => return Err(err),
        };
        let object_id = private_object_id(&file)?;
        let mut current = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut current)?;
        match expected {
            Some((expected_id, expected_bytes))
                if expected_id == &object_id && expected_bytes == current => {}
            None if current.is_empty() => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private child changed before append",
                ))
            }
        }
        file.write_all(suffix)?;
        file.flush()?;
        file.sync_all()?;
        #[cfg(unix)]
        let final_id = private_object_id(&open_child_file(&self.parent, path)?)?;
        #[cfg(windows)]
        let final_id = private_object_id(&file)?;
        if final_id != object_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private child path changed during append",
            ));
        }
        if created {
            self.parent.sync_all()?;
        }
        self.verify_current()
    }

    pub(crate) fn child_names(&self) -> io::Result<Vec<OsString>> {
        self.verify_current()?;
        let names = parent_child_names(&self.parent, &self.parent_path)?;
        self.verify_current()?;
        Ok(names)
    }

    pub(crate) fn child_exists(&self, path: &Path) -> io::Result<bool> {
        self.require_child(path)?;
        let name = path.file_name().expect("direct children have a file name");
        Ok(self
            .child_names()?
            .iter()
            .any(|candidate| candidate == name))
    }

    pub(crate) fn remove_child_exact(&self, path: &Path) -> io::Result<()> {
        self.require_child(path)?;
        self.verify_current()?;
        let file = open_child_file_for_removal(&self.parent, path)?;
        let expected = private_object_id(&file)?;
        self.remove_open_child(path, &file, &expected)?;
        self.parent.sync_all()?;
        self.verify_current()
    }

    pub(crate) fn remove_open_child(
        &self,
        path: &Path,
        file: &File,
        expected_id: &PrivateObjectId,
    ) -> io::Result<()> {
        self.require_child(path)?;
        self.verify_current()?;
        remove_open_child_file(&self.parent, path, file, expected_id)?;
        self.verify_current()
    }

    pub(crate) fn rename_open_child(
        &self,
        from: &Path,
        to: &Path,
        file: &File,
        expected_id: &PrivateObjectId,
    ) -> io::Result<()> {
        self.require_child(from)?;
        self.require_child(to)?;
        self.verify_current()?;
        if private_object_id(file)? != *expected_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained private child changed before rename",
            ));
        }
        rename_open_child_file(&self.parent, from, to, file, expected_id)?;
        self.parent.sync_all()?;
        #[cfg(unix)]
        {
            let current = open_child_file_for_identity(&self.parent, to)?;
            if private_object_id(&current)? != *expected_id {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private child destination changed after rename",
                ));
            }
        }
        #[cfg(windows)]
        if private_object_id(file)? != *expected_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained private child changed after rename",
            ));
        }
        self.verify_current()
    }

    pub(crate) fn rename_retained_workspace_directory(
        &self,
        from: &Path,
        to: &Path,
        retained: &RetainedWorkspaceDirectory,
    ) -> io::Result<()> {
        self.require_child(from)?;
        self.require_child(to)?;
        self.verify_current()?;
        verify_open_child_directory(&self.parent, from, &retained.directory, &retained.id)?;
        rename_open_child_directory(&self.parent, from, to, &retained.directory)?;
        self.parent.sync_all()?;
        verify_open_child_directory(&self.parent, to, &retained.directory, &retained.id)?;
        self.verify_current()
    }

    #[cfg(test)]
    fn rename_child_directory_with_observer(
        &self,
        from: &Path,
        to: &Path,
        after_open: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.require_child(from)?;
        self.require_child(to)?;
        self.verify_current()?;
        let directory = open_child_directory_for_mutation(&self.parent, from)?;
        let expected = private_object_id(&directory)?;
        after_open()?;
        self.verify_current()?;
        verify_open_child_directory(&self.parent, from, &directory, &expected)?;
        rename_open_child_directory(&self.parent, from, to, &directory)?;
        self.parent.sync_all()?;
        verify_open_child_directory(&self.parent, to, &directory, &expected)?;
        self.verify_current()
    }

    #[cfg(test)]
    pub(crate) fn remove_child_directory_all(&self, path: &Path) -> io::Result<()> {
        self.remove_child_directory_all_with_observer(path, || Ok(()))
    }

    pub(crate) fn remove_retained_workspace_directory_all(
        &self,
        path: &Path,
        retained: &RetainedWorkspaceDirectory,
    ) -> io::Result<()> {
        self.require_child(path)?;
        self.verify_current()?;
        verify_open_child_directory(&self.parent, path, &retained.directory, &retained.id)?;
        remove_open_directory_contents(&retained.directory)?;
        retained.directory.sync_all()?;
        verify_open_child_directory(&self.parent, path, &retained.directory, &retained.id)?;
        remove_open_child_directory(&self.parent, path, &retained.directory, &retained.id)?;
        self.parent.sync_all()?;
        self.verify_current()
    }

    #[cfg(test)]
    fn remove_child_directory_all_with_observer(
        &self,
        path: &Path,
        after_open: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.require_child(path)?;
        self.verify_current()?;
        let directory = open_child_directory_for_mutation(&self.parent, path)?;
        let expected = private_object_id(&directory)?;
        after_open()?;
        self.verify_current()?;
        verify_open_child_directory(&self.parent, path, &directory, &expected)?;
        remove_open_directory_contents(&directory)?;
        directory.sync_all()?;
        verify_open_child_directory(&self.parent, path, &directory, &expected)?;
        remove_open_child_directory(&self.parent, path, &directory, &expected)?;
        self.parent.sync_all()?;
        self.verify_current()
    }

    pub(crate) fn acquire_child_lock(&self, path: &Path) -> io::Result<NamespaceChildLock<'_>> {
        self.require_child(path)?;
        self.verify_current()?;
        let file = open_child_file_for_lock(&self.parent, path)?;
        lock_exclusive(&file)?;
        let id = private_object_id(&file)?;
        let child = NamespaceChildLock {
            namespace: self,
            file,
            path: path.to_path_buf(),
            id,
        };
        child.verify_current()?;
        Ok(child)
    }

    pub(crate) fn retain_child(&self, path: &Path) -> io::Result<RetainedNamespaceChild> {
        self.require_child(path)?;
        self.verify_current()?;
        let file = open_child_file_for_authority(&self.parent, path)?;
        let id = private_object_id(&file)?;
        let child = RetainedNamespaceChild {
            namespace: self.try_clone_authority()?,
            file,
            path: path.to_path_buf(),
            id,
        };
        child.verify_current()?;
        Ok(child)
    }

    pub(crate) fn open_or_create_retained_child(
        &self,
        path: &Path,
    ) -> io::Result<RetainedNamespaceChild> {
        self.require_child(path)?;
        self.verify_current()?;
        let file = open_child_file_for_lock(&self.parent, path)?;
        self.parent.sync_all()?;
        let id = private_object_id(&file)?;
        let child = RetainedNamespaceChild {
            namespace: self.try_clone_authority()?,
            file,
            path: path.to_path_buf(),
            id,
        };
        child.verify_current()?;
        Ok(child)
    }

    pub(crate) fn try_clone_authority(&self) -> io::Result<Self> {
        Ok(Self {
            parent: self.parent.try_clone()?,
            parent_path: self.parent_path.clone(),
            parent_id: self.parent_id.clone(),
            lock_file: self.lock_file.try_clone()?,
            lock_path: self.lock_path.clone(),
            lock_id: self.lock_id.clone(),
        })
    }
}

pub(crate) fn open_child_file_for_authority(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_file(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_file_exclusive(parent, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private authority reads are unsupported on this platform",
        ))
    }
}

fn open_child_file_for_bound_identity(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_file(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_file_for_identity(parent, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private bound-object identity reads are unsupported on this platform",
        ))
    }
}

#[cfg(unix)]
fn open_child_file_for_identity(parent: &File, path: &Path) -> io::Result<File> {
    unix_private::open_child_file(parent, path)
}

fn rename_open_child_file(
    parent: &File,
    from: &Path,
    to: &Path,
    file: &File,
    expected_id: &PrivateObjectId,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        let current = unix_private::open_child_file(parent, from)?;
        if private_object_id(&current)? != *expected_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private child path changed before rename",
            ));
        }
        let _ = file;
        unix_private::rename_child_file(parent, from, to)
    }
    #[cfg(windows)]
    {
        let _ = (from, expected_id);
        windows_acl::move_file(file, parent, to, false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, from, to, file, expected_id);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exact private child rename is unsupported on this platform",
        ))
    }
}

pub(crate) fn open_child_file_for_removal(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_file(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_for_mutation(parent, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exact private child removal is unsupported on this platform",
        ))
    }
}

impl NamespaceChildLock<'_> {
    pub(crate) fn verify_current(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        if private_object_id(&self.file)? != self.id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained namespace child lock changed",
            ));
        }
        let current = open_child_file(self.namespace.parent(), &self.path)?;
        if private_object_id(&current)? != self.id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "namespace child lock path was replaced while held",
            ));
        }
        self.namespace.verify_current()
    }
}

impl RetainedNamespaceChild {
    pub(crate) fn verify_current(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        if private_object_id(&self.file)? != self.id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained namespace child changed",
            ));
        }
        #[cfg(unix)]
        let current = open_child_file(self.namespace.parent(), &self.path)?;
        #[cfg(windows)]
        let current =
            windows_acl::open_child_file_for_identity(self.namespace.parent(), &self.path)?;
        if private_object_id(&current)? != self.id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retained namespace child path was replaced",
            ));
        }
        self.namespace.verify_current()
    }
}

fn require_direct_child(parent: &Path, child: &Path) -> io::Result<()> {
    if child.parent() == Some(parent) && child.file_name().is_some() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "private namespace child {} is not directly inside {}",
            child.display(),
            parent.display()
        ),
    ))
}

fn open_identity_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let file = options.open(path)?;
        validate_private_file(&file)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        windows_acl::open_file_for_identity(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private file identity is unsupported on this platform",
        ))
    }
}

#[cfg(unix)]
fn lock_parent_namespace(file: &File) -> io::Result<()> {
    lock_exclusive(file)
}

#[cfg(windows)]
fn lock_parent_namespace(_file: &File) -> io::Result<()> {
    // The directory handle denies FILE_SHARE_DELETE, which pins its name.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn lock_parent_namespace(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private namespace locks are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let mut overlapped = OVERLAPPED::default();
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } != 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_exclusive(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private namespace locks are unsupported on this platform",
    ))
}

/// How [`open_private_file`] may change the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateOpenMode {
    /// Tighten an existing object before truncating it.
    Truncate,
    /// Tighten an existing object before appending to it.
    Append,
    /// Open without truncation for an operating-system lock. On Windows this
    /// grants the read/write access required by `LockFileEx` and deliberately
    /// denies delete sharing so the locked pathname cannot be replaced.
    ReadWriteLock,
    /// Open without truncation for an exact-object append, with read access
    /// so the caller can compare the retained bytes before writing.
    ReadWriteAppend,
    /// Refuse an existing target. Useful for atomic-replacement temporaries.
    CreateNew,
}

/// Create the path privately, or verify that an existing leaf is already private.
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        harden_private_directory(path)
    }
    #[cfg(windows)]
    {
        windows_acl::create_dir_all(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private filesystem permissions are unsupported on this platform",
        ))
    }
}

fn create_private_identity_record(
    parent: &File,
    path: &Path,
    build: impl FnOnce(&PrivateObjectId) -> io::Result<Vec<u8>>,
) -> io::Result<PrivateObjectId> {
    let mut file = create_child_file_read_append(parent, path)?;
    let id = private_object_id(&file)?;
    let result = (|| {
        let bytes = build(&id)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        parent.sync_all()
    })();
    if let Err(error) = result {
        drop(file);
        let _ = remove_child_file(parent, path);
        return Err(error);
    }
    Ok(id)
}

fn append_lineage_context_component(bytes: &mut Vec<u8>, value: &std::ffi::OsStr) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        let encoded = value.encode_wide().collect::<Vec<_>>();
        bytes.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        for unit in encoded {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let encoded = value.as_bytes();
        bytes.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        bytes.extend_from_slice(encoded);
    }
}

fn private_root_lineage_context(private_root: &Path) -> io::Result<Vec<u8>> {
    let parent = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private workspace root has no parent",
        )
    })?;
    let canonical_parent = fs::canonicalize(parent)?;
    let root_name = private_root.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private workspace root has no name",
        )
    })?;
    let mut context = b"argos/private-root-lineage/context/v1".to_vec();
    append_lineage_context_component(&mut context, canonical_parent.as_os_str());
    append_lineage_context_component(&mut context, root_name);
    Ok(context)
}

fn private_artifact_root_context(private_root: &Path, purpose: &[u8]) -> io::Result<Vec<u8>> {
    let parent = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private artifact root has no parent",
        )
    })?;
    let canonical_parent = fs::canonicalize(parent)?;
    let root_name = private_root.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private artifact root has no name",
        )
    })?;
    let mut context = b"argos/private-artifact-root/context/v1".to_vec();
    append_lineage_context_component(&mut context, canonical_parent.as_os_str());
    append_lineage_context_component(&mut context, root_name);
    context.extend_from_slice(&(purpose.len() as u64).to_le_bytes());
    context.extend_from_slice(purpose);
    Ok(context)
}

pub(crate) fn private_artifact_root_path(data_dir: &Path, purpose: &[u8]) -> std::path::PathBuf {
    let mut input = b"argos/private-artifact-root-name/v1".to_vec();
    input.extend_from_slice(&(purpose.len() as u64).to_le_bytes());
    input.extend_from_slice(purpose);
    let digest = sha2::Sha256::digest(input);
    let mut name = String::from(".argos-private-artifacts-");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    data_dir.join(name)
}

fn private_artifact_container_purpose() -> &'static [u8] {
    b"argos/private-artifact-container/v1"
}

pub(crate) fn private_artifact_purpose(network: &str, full_fingerprint: &str) -> Vec<u8> {
    let mut purpose = b"argos/sprout-private-artifacts/v1".to_vec();
    append_lineage_context_component(&mut purpose, std::ffi::OsStr::new(network));
    append_lineage_context_component(&mut purpose, std::ffi::OsStr::new(full_fingerprint));
    purpose
}

fn sqlite_lineage_context(root: &PrivateRootLineageLease, database: &Path) -> io::Result<Vec<u8>> {
    let expected_database = root.contextualize(database)?;
    sqlite_lineage_context_paths(&root.context_path, &expected_database)
}

fn sqlite_lineage_context_paths(private_root: &Path, database: &Path) -> io::Result<Vec<u8>> {
    let relative = database
        .strip_prefix(private_root)
        .map_err(io::Error::other)?;
    let mut context = private_root_lineage_context(private_root)?;
    context.extend_from_slice(b"argos/private-sqlite-lineage/context/v1");
    append_lineage_context_component(&mut context, relative.as_os_str());
    Ok(context)
}

#[cfg(windows)]
fn require_windows_authority_header(
    authority: &WindowsLineageAuthorityRecord,
    context_hash: &[u8; 32],
    anchor_id: &[u8; 16],
) -> io::Result<()> {
    if authority.schema_version != 1
        || authority.context_hash != *context_hash
        || authority.anchor_id != *anchor_id
    {
        return Err(invalid_lineage(
            "Windows private lineage registry authority does not match this workspace",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn prepare_windows_lineage_creation(context: &[u8]) -> io::Result<([u8; 16], [u8; 16])> {
    let context_hash = windows_lineage::context_hash(context);
    let authority = windows_lineage::read_authority(&context_hash)?;
    match authority {
        None => {
            let anchor_id = uuid::Uuid::new_v4().into_bytes();
            let generation = uuid::Uuid::new_v4().into_bytes();
            windows_lineage::write_authority(
                &context_hash,
                &WindowsLineageAuthorityRecord {
                    schema_version: 1,
                    context_hash,
                    anchor_id,
                    state: WindowsLineageState::Pending { generation },
                },
            )?;
            Ok((anchor_id, generation))
        }
        Some(authority) => match authority.state {
            WindowsLineageState::Pending { generation } => {
                require_windows_authority_header(
                    &authority,
                    &context_hash,
                    &authority.anchor_id,
                )?;
                Ok((authority.anchor_id, generation))
            }
            WindowsLineageState::Revoked { .. } => Err(invalid_lineage(
                "Windows private lineage authority is revoked; start an explicitly confirmed new recovery after cleanup completes",
            )),
            WindowsLineageState::Active { .. } => Err(invalid_lineage(
                "Windows private lineage authority is active but the workspace root is absent; manual recovery is required",
            )),
        },
    }
}

#[cfg(windows)]
fn activate_or_verify_windows_sqlite_authority(
    context: &[u8],
    record: &PrivateSqliteLineageRecord,
    objects: WindowsLineageObjects,
) -> io::Result<()> {
    let context_hash = windows_lineage::context_hash(context);
    let _guard = windows_lineage::lock(&context_hash)?;
    let mut authority = windows_lineage::read_authority(&context_hash)?
        .ok_or_else(|| invalid_lineage("Windows private lineage registry authority is missing"))?;
    require_windows_authority_header(&authority, &context_hash, &record.anchor_id)?;
    if record.context != context {
        return Err(invalid_lineage(
            "Windows SQLite marker generation does not match the private root authority",
        ));
    }
    match &authority.state {
        WindowsLineageState::Pending { generation } if generation == &record.generation => {
            authority.state = WindowsLineageState::Active {
                generation: *generation,
                objects,
            };
            windows_lineage::write_authority(&context_hash, &authority)?;
        }
        WindowsLineageState::Active {
            generation,
            objects: expected,
        } if generation == &record.generation && expected == &objects => {}
        WindowsLineageState::Revoked { .. } => {
            return Err(invalid_lineage(
                "Windows private lineage authority was revoked before workspace cleanup",
            ));
        }
        _ => {
            return Err(invalid_lineage(
                "Windows private lineage authority does not match the exact SQLite objects",
            ));
        }
    }
    Ok(())
}

fn encode_lineage_record<T: serde::Serialize>(
    kind: LineageRecordKind,
    record: &T,
) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    #[cfg(windows)]
    {
        use zeroize::Zeroize as _;
        let protected = windows_lineage::protect(kind, &bytes);
        bytes.zeroize();
        protected
    }
    #[cfg(not(windows))]
    {
        let _ = kind;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn decode_lineage_record<T: serde::de::DeserializeOwned>(
    kind: LineageRecordKind,
    bytes: &[u8],
) -> io::Result<T> {
    #[cfg(windows)]
    let plaintext = windows_lineage::unprotect(kind, bytes)?;
    #[cfg(not(windows))]
    let plaintext = {
        let _ = kind;
        bytes
    };
    #[cfg(windows)]
    let plaintext = plaintext.as_slice();
    serde_json::from_slice(plaintext)
        .map_err(|error| invalid_lineage(format!("private lineage record is invalid: {error}")))
}

pub(crate) fn protect_cleanup_marker(bytes: &[u8]) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        windows_lineage::protect(LineageRecordKind::CleanupMarker, bytes)
    }
    #[cfg(not(windows))]
    {
        Ok(bytes.to_vec())
    }
}

pub(crate) fn unprotect_cleanup_marker(bytes: &[u8]) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        windows_lineage::unprotect(LineageRecordKind::CleanupMarker, bytes)
            .map(|plaintext| plaintext.to_vec())
    }
    #[cfg(not(windows))]
    {
        Ok(bytes.to_vec())
    }
}

fn encode_ephemeral_probe_cleanup_record(
    record: &EphemeralProbeCleanupRecord,
) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    return encode_lineage_record(LineageRecordKind::CleanupMarker, record);
    #[cfg(not(windows))]
    {
        let mut bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn decode_ephemeral_probe_cleanup_record(bytes: &[u8]) -> io::Result<EphemeralProbeCleanupRecord> {
    #[cfg(windows)]
    return decode_lineage_record(LineageRecordKind::CleanupMarker, bytes);
    #[cfg(not(windows))]
    serde_json::from_slice(bytes).map_err(|error| {
        invalid_lineage(format!(
            "ephemeral probe cleanup marker is invalid: {error}"
        ))
    })
}

fn read_private_child_bytes(parent: &File, path: &Path) -> io::Result<(Vec<u8>, PrivateObjectId)> {
    let mut file = open_child_file_for_authority(parent, path)?;
    let id = private_object_id(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok((bytes, id))
}

fn read_private_lineage_child_bytes(
    parent: &File,
    path: &Path,
) -> io::Result<(Vec<u8>, PrivateObjectId)> {
    #[cfg(unix)]
    let mut file = unix_private::open_child_file(parent, path)?;
    #[cfg(windows)]
    let mut file = windows_acl::open_child_file(parent, path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private lineage reads are unsupported on this platform",
    ));
    let id = private_object_id(&file)?;
    const MAX_LINEAGE_RECORD_BYTES: u64 = 64 * 1024;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_LINEAGE_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LINEAGE_RECORD_BYTES {
        return Err(invalid_lineage(
            "private lineage record exceeds the bounded metadata size",
        ));
    }
    Ok((bytes, id))
}

pub(crate) fn read_private_child_file(parent: &File, path: &Path) -> io::Result<Vec<u8>> {
    read_private_child_bytes(parent, path).map(|(bytes, _)| bytes)
}

fn invalid_lineage(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn open_publication_parent(path: &Path) -> io::Result<File> {
    let parent = open_parent_lease_handle(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = parent.metadata()?;
        let mode = metadata.mode() & 0o7777;
        if metadata.uid() != unsafe { libc::geteuid() } || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(invalid_lineage(
                "workspace publication parent must be current-user-owned and not non-sticky group/world writable",
            ));
        }
        unix_private::verify_no_extended_directory_acl(&parent)?;
    }
    #[cfg(windows)]
    windows_acl::verify_publication_parent(&parent)?;
    Ok(parent)
}

pub(crate) fn verify_private_workspace_lineage(
    private_root: &Path,
) -> io::Result<PrivateRootLineageLease> {
    let publication_parent_path = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private workspace root has no parent",
        )
    })?;
    let publication_parent = open_publication_parent(publication_parent_path)?;
    let publication_parent_id = private_object_id(&publication_parent)?;
    let root = open_private_directory_lease(private_root)?;
    let id = private_object_id(&root)?;
    let marker = private_root.join(PRIVATE_ROOT_LINEAGE_FILE_NAME);
    let (bytes, marker_id) = read_private_lineage_child_bytes(&root, &marker).map_err(|error| {
        invalid_lineage(format!(
            "private workspace root {} has no valid create-time lineage marker: {error}; replace the legacy root while Argos is stopped",
            private_root.display()
        ))
    })?;
    let record: PrivateRootLineageRecord = decode_lineage_record(LineageRecordKind::Root, &bytes)
        .map_err(|error| {
        invalid_lineage(format!(
            "private workspace root {} has an invalid lineage marker: {error}",
            private_root.display()
        ))
    })?;
    let context = private_root_lineage_context(private_root)?;
    if record.schema_version != PRIVATE_ROOT_LINEAGE_SCHEMA_VERSION
        || record.publication_parent != publication_parent_id
        || record.private_root != id
        || record.marker != marker_id
        || record.context != context
    {
        return Err(invalid_lineage(format!(
            "private workspace root {} lineage does not match the exact directory object",
            private_root.display()
        )));
    }
    Ok(PrivateRootLineageLease {
        root,
        path: private_root.to_path_buf(),
        context_path: private_root.to_path_buf(),
        id,
        publication_parent_id,
        root_marker_id: marker_id,
    })
}

#[cfg(windows)]
fn prepare_windows_artifact_root_creation(context: &[u8]) -> io::Result<([u8; 16], [u8; 16])> {
    let context_hash = windows_lineage::context_hash(context);
    match windows_lineage::read_artifact_authority(&context_hash)? {
        None => {
            let anchor_id = uuid::Uuid::new_v4().into_bytes();
            let generation = uuid::Uuid::new_v4().into_bytes();
            windows_lineage::write_artifact_authority(
                &context_hash,
                &WindowsArtifactRootAuthorityRecord {
                    schema_version: 1,
                    context_hash,
                    anchor_id,
                    state: WindowsArtifactRootState::Pending { generation },
                },
            )?;
            Ok((anchor_id, generation))
        }
        Some(authority) if authority.schema_version != 1 || authority.context_hash != context_hash => {
            Err(invalid_lineage(
                "Windows artifact-root authority does not match its canonical context",
            ))
        }
        Some(WindowsArtifactRootAuthorityRecord {
            anchor_id,
            state: WindowsArtifactRootState::Pending { generation },
            ..
        }) => Ok((anchor_id, generation)),
        Some(WindowsArtifactRootAuthorityRecord {
            state: WindowsArtifactRootState::Active { .. },
            ..
        }) => Err(invalid_lineage(
            "Windows artifact-root authority is active but its exact root is absent; manual recovery is required",
        )),
    }
}

#[cfg(windows)]
fn activate_or_verify_windows_artifact_root(
    context: &[u8],
    record: &PrivateArtifactRootRecord,
    objects: WindowsArtifactRootObjects,
) -> io::Result<()> {
    let context_hash = windows_lineage::context_hash(context);
    let mut authority = windows_lineage::read_artifact_authority(&context_hash)?
        .ok_or_else(|| invalid_lineage("Windows artifact-root registry authority is missing"))?;
    if authority.schema_version != 1
        || authority.context_hash != context_hash
        || authority.anchor_id != record.anchor_id
    {
        return Err(invalid_lineage(
            "Windows artifact-root registry authority does not match its marker",
        ));
    }
    match &authority.state {
        WindowsArtifactRootState::Pending { generation } if generation == &record.generation => {
            authority.state = WindowsArtifactRootState::Active {
                generation: *generation,
                objects,
            };
            windows_lineage::write_artifact_authority(&context_hash, &authority)
        }
        WindowsArtifactRootState::Active {
            generation,
            objects: expected,
        } if generation == &record.generation && expected == &objects => Ok(()),
        _ => Err(invalid_lineage(
            "Windows artifact-root authority does not match the exact published objects",
        )),
    }
}

fn verify_private_artifact_root(
    private_root: &Path,
    purpose: &[u8],
) -> io::Result<PrivateArtifactRootLease> {
    let publication_parent_path = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private artifact root has no parent",
        )
    })?;
    let publication_parent = open_publication_parent(publication_parent_path)?;
    let root = open_child_directory_for_identity(&publication_parent, private_root)?;
    validate_private_directory_handle(&root)?;
    verify_private_artifact_root_from_handles(private_root, purpose, publication_parent, root)
}

fn verify_private_artifact_root_from_handles(
    private_root: &Path,
    purpose: &[u8],
    publication_parent: File,
    root: File,
) -> io::Result<PrivateArtifactRootLease> {
    let context = private_artifact_root_context(private_root, purpose)?;
    #[cfg(windows)]
    let _artifact_guard = {
        let context_hash = windows_lineage::context_hash(&context);
        windows_lineage::artifact_lock(&context_hash)?
    };
    let publication_parent_id = private_object_id(&publication_parent)?;
    validate_private_directory_handle(&root)?;
    let id = private_object_id(&root)?;
    let marker_path = private_root.join(PRIVATE_ARTIFACT_ROOT_MARKER);
    let (bytes, marker_id) = read_private_lineage_child_bytes(&root, &marker_path).map_err(|error| {
        invalid_lineage(format!(
            "private artifact root {} has no valid create-time lineage marker: {error}; preserve the legacy artifacts and start a fresh scan",
            private_root.display()
        ))
    })?;
    let record: PrivateArtifactRootRecord =
        decode_lineage_record(LineageRecordKind::ArtifactRoot, &bytes).map_err(|error| {
            invalid_lineage(format!(
                "private artifact root {} has an invalid lineage marker: {error}",
                private_root.display()
            ))
        })?;
    if record.schema_version != 1
        || record.publication_parent != publication_parent_id
        || record.private_root != id
        || record.marker != marker_id
        || record.purpose != purpose
        || record.context != context
        || record.bound_objects.len() != PRIVATE_ARTIFACT_BOUND_NAMES.len()
    {
        return Err(invalid_lineage(format!(
            "private artifact root {} lineage does not match its exact context and directory",
            private_root.display()
        )));
    }
    for name in PRIVATE_ARTIFACT_BOUND_NAMES {
        let expected = record.bound_objects.get(name).ok_or_else(|| {
            invalid_lineage(format!(
                "private artifact root {} is missing bound object {name}",
                private_root.display()
            ))
        })?;
        let child = open_child_file_for_authority(&root, &private_root.join(name))?;
        if private_object_id(&child)? != *expected {
            return Err(invalid_lineage(format!(
                "private artifact root {} bound object {name} was replaced",
                private_root.display()
            )));
        }
    }
    #[cfg(windows)]
    activate_or_verify_windows_artifact_root(
        &context,
        &record,
        WindowsArtifactRootObjects {
            publication_parent: publication_parent_id.clone(),
            private_root: id.clone(),
            marker: marker_id.clone(),
            bound_objects: record.bound_objects.clone(),
        },
    )?;
    Ok(PrivateArtifactRootLease {
        publication_parent,
        root,
        path: private_root.to_path_buf(),
        id,
        publication_parent_id,
        marker_id,
        context: purpose.to_vec(),
        bound_objects: record.bound_objects,
    })
}

/// Establish or verify a create-time-proven per-key artifact namespace.
/// Existing directories are never repaired or retroactively marked trusted.
fn ensure_private_artifact_root_raw(
    private_root: &Path,
    purpose: &[u8],
) -> io::Result<PrivateArtifactRootLease> {
    ensure_private_artifact_root_with_parent(private_root, purpose, None)
}

fn ensure_private_artifact_root_with_parent(
    private_root: &Path,
    purpose: &[u8],
    retained_parent: Option<&File>,
) -> io::Result<PrivateArtifactRootLease> {
    match fs::symlink_metadata(private_root) {
        Ok(_) => match retained_parent {
            Some(parent) => {
                let root = open_child_directory_for_identity(parent, private_root)?;
                validate_private_directory_handle(&root)?;
                verify_private_artifact_root_from_handles(
                    private_root,
                    purpose,
                    parent.try_clone()?,
                    root,
                )
            }
            None => verify_private_artifact_root(private_root, purpose),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let publication_parent_path = private_root.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private artifact root has no parent",
                )
            })?;
            if retained_parent.is_none() {
                fs::create_dir_all(publication_parent_path)?;
            }
            let context = private_artifact_root_context(private_root, purpose)?;
            #[cfg(windows)]
            let _artifact_guard = {
                let context_hash = windows_lineage::context_hash(&context);
                windows_lineage::artifact_lock(&context_hash)?
            };
            // Serialize the absent check with the permanent Windows
            // authority. A concurrent publisher that won before the mutex
            // must be verified, never treated as a fresh root.
            if fs::symlink_metadata(private_root).is_ok() {
                return match retained_parent {
                    Some(parent) => {
                        let root = open_child_directory_for_identity(parent, private_root)?;
                        validate_private_directory_handle(&root)?;
                        verify_private_artifact_root_from_handles(
                            private_root,
                            purpose,
                            parent.try_clone()?,
                            root,
                        )
                    }
                    None => verify_private_artifact_root(private_root, purpose),
                };
            }
            #[cfg(windows)]
            let (artifact_anchor_id, artifact_generation) =
                prepare_windows_artifact_root_creation(&context)?;
            let publication_parent = match retained_parent {
                Some(parent) => parent.try_clone()?,
                None => open_publication_parent(publication_parent_path)?,
            };
            let publication_parent_id = private_object_id(&publication_parent)?;
            let destination_name = private_root.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private artifact root has no name",
                )
            })?;
            if child_names_set(&publication_parent, publication_parent_path)?
                .contains(destination_name)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private artifact root appeared before publication; retry",
                ));
            }
            let staging_name = format!(
                ".{}-staging-{}",
                destination_name.to_string_lossy(),
                uuid::Uuid::new_v4()
            );
            let staging_root = publication_parent_path.join(staging_name);
            create_private_dir_all(&staging_root)?;
            let staging = open_child_directory_for_mutation(&publication_parent, &staging_root)?;
            let staging_id = private_object_id(&staging)?;
            let mut bound_objects = std::collections::BTreeMap::new();
            for name in PRIVATE_ARTIFACT_BOUND_NAMES {
                let child_path = staging_root.join(name);
                let child = create_child_file_read_append(&staging, &child_path)?;
                child.sync_all()?;
                bound_objects.insert(name.to_owned(), private_object_id(&child)?);
            }
            create_private_identity_record(
                &staging,
                &staging_root.join(PRIVATE_ARTIFACT_ROOT_MARKER),
                |marker_id| {
                    encode_lineage_record(
                        LineageRecordKind::ArtifactRoot,
                        &PrivateArtifactRootRecord {
                            schema_version: 1,
                            publication_parent: publication_parent_id.clone(),
                            private_root: staging_id.clone(),
                            marker: marker_id.clone(),
                            purpose: purpose.to_vec(),
                            context,
                            bound_objects,
                            #[cfg(windows)]
                            anchor_id: artifact_anchor_id,
                            #[cfg(windows)]
                            generation: artifact_generation,
                        },
                    )
                },
            )?;
            staging.sync_all()?;
            rename_open_child_directory(
                &publication_parent,
                &staging_root,
                private_root,
                &staging,
            )?;
            publication_parent.sync_all()?;
            let published = open_child_directory_for_identity(&publication_parent, private_root)?;
            validate_private_directory_handle(&published)?;
            let verified = verify_private_artifact_root_from_handles(
                private_root,
                purpose,
                publication_parent,
                published,
            )?;
            if verified.id != staging_id {
                return Err(invalid_lineage(
                    "private artifact root changed during no-replace publication",
                ));
            }
            Ok(verified)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_private_artifact_container(
    data_dir: &Path,
) -> io::Result<PrivateArtifactRootLease> {
    ensure_private_artifact_root_raw(data_dir, private_artifact_container_purpose()).map_err(
        |error| {
            if matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData)
            {
                invalid_lineage(format!(
                    "artifact data directory {} has no authenticated create-time container authority: {error}. Preserve and explicitly reconcile every historical Sprout journal before selecting a fresh authority location",
                    data_dir.display()
                ))
            } else {
                error
            }
        },
    )
}

pub(crate) fn ensure_private_artifact_root(
    private_root: &Path,
    purpose: &[u8],
) -> io::Result<PrivateArtifactRootLease> {
    let data_dir = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private artifact root has no data directory",
        )
    })?;
    let container = ensure_private_artifact_container(data_dir)?;
    ensure_private_artifact_root_with_parent(private_root, purpose, Some(&container.root))
}

fn sqlite_lineage_path(database: &Path) -> io::Result<std::path::PathBuf> {
    let name = database.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SQLite database has no file name",
        )
    })?;
    let mut marker = name.to_os_string();
    marker.push(".argos-private-v1");
    Ok(database.with_file_name(marker))
}

fn sqlite_sidecar_paths(database: &Path) -> [std::path::PathBuf; 3] {
    ["-journal", "-wal", "-shm"].map(|suffix| {
        let mut sidecar = database.as_os_str().to_owned();
        sidecar.push(suffix);
        std::path::PathBuf::from(sidecar)
    })
}

fn child_names_set(
    parent: &File,
    parent_path: &Path,
) -> io::Result<std::collections::HashSet<OsString>> {
    Ok(parent_child_names(parent, parent_path)?
        .into_iter()
        .collect())
}

fn ensure_private_sqlite_lineage(
    root: &PrivateRootLineageLease,
    parent: &File,
    parent_path: &Path,
    database: &Path,
) -> io::Result<()> {
    let marker = sqlite_lineage_path(database)?;
    let database_name = database.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SQLite database has no file name",
        )
    })?;
    let marker_name = marker
        .file_name()
        .expect("marker is a sibling of the database");
    let names = child_names_set(parent, parent_path)?;
    let database_exists = names.contains(database_name);
    let marker_exists = names.contains(marker_name);

    if !database_exists {
        let sidecar_exists = sqlite_sidecar_paths(database)
            .iter()
            .filter_map(|path| path.file_name())
            .any(|name| names.contains(name));
        if marker_exists || sidecar_exists {
            return Err(invalid_lineage(format!(
                "private SQLite lineage for {} is incomplete; archive and recreate this workspace while Argos is stopped",
                database.display()
            )));
        }
        let context = sqlite_lineage_context(root, database)?;
        #[cfg(windows)]
        let context_hash = windows_lineage::context_hash(&context);
        #[cfg(windows)]
        let _lineage_guard = windows_lineage::lock(&context_hash)?;
        #[cfg(windows)]
        let (anchor_id, generation) = prepare_windows_lineage_creation(&context)?;
        let database_file = create_child_file_read_append(parent, database)?;
        database_file.sync_all()?;
        let database_id = private_object_id(&database_file)?;
        let parent_id = private_object_id(parent)?;
        create_private_identity_record(parent, &marker, |marker_id| {
            let record = PrivateSqliteLineageRecord {
                schema_version: PRIVATE_SQLITE_LINEAGE_SCHEMA_VERSION,
                private_root: root.id.clone(),
                parent: parent_id,
                database: database_id,
                marker: marker_id.clone(),
                context,
                #[cfg(windows)]
                generation,
                #[cfg(windows)]
                anchor_id,
            };
            encode_lineage_record(LineageRecordKind::Sqlite, &record)
        })?;
        parent.sync_all()?;
        return Ok(());
    }
    if !marker_exists {
        return Err(invalid_lineage(format!(
            "existing SQLite database {} predates create-time lineage; archive and recreate this workspace while Argos is stopped",
            database.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn reserve_windows_sqlite_creation_before_leaf(
    root: &PrivateRootLineageLease,
    leaf: &Path,
    database: &Path,
) -> io::Result<()> {
    let context = sqlite_lineage_context(root, database)?;
    let context_hash = windows_lineage::context_hash(&context);
    let _guard = windows_lineage::lock(&context_hash)?;
    let authority = windows_lineage::read_authority(&context_hash)?;
    let leaf_exists = match fs::symlink_metadata(leaf) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    match authority {
        None if leaf_exists => Err(invalid_lineage(
            "existing workspace leaf has no Windows private lineage authority",
        )),
        None => {
            let _ = prepare_windows_lineage_creation(&context)?;
            Ok(())
        }
        Some(authority) => {
            require_windows_authority_header(&authority, &context_hash, &authority.anchor_id)?;
            match authority.state {
                WindowsLineageState::Pending { .. } => Ok(()),
                WindowsLineageState::Active { .. } if leaf_exists => Ok(()),
                WindowsLineageState::Active { .. } => Err(invalid_lineage(
                    "active Windows private lineage workspace is missing; manual recovery is required",
                )),
                WindowsLineageState::Revoked { .. } => Err(invalid_lineage(
                    "Windows private lineage is revoked; cleanup reconciliation is required before recreation",
                )),
            }
        }
    }
}

fn initialize_staged_private_root(
    staging_root: &Path,
    staging_leaf: &Path,
    staging_database: &Path,
    context_root: &Path,
    publication_parent_id: &PrivateObjectId,
) -> io::Result<PrivateObjectId> {
    create_private_dir_all(staging_leaf)?;
    let root = open_private_directory_lease(staging_root)?;
    let root_id = private_object_id(&root)?;
    let marker = staging_root.join(PRIVATE_ROOT_LINEAGE_FILE_NAME);
    let context = private_root_lineage_context(context_root)?;
    let root_marker_id = create_private_identity_record(&root, &marker, |marker_id| {
        let record = PrivateRootLineageRecord {
            schema_version: PRIVATE_ROOT_LINEAGE_SCHEMA_VERSION,
            publication_parent: publication_parent_id.clone(),
            private_root: root_id.clone(),
            marker: marker_id.clone(),
            context,
        };
        encode_lineage_record(LineageRecordKind::Root, &record)
    })?;
    #[cfg(not(windows))]
    let _ = &root_marker_id;
    let lineage = PrivateRootLineageLease {
        root,
        path: staging_root.to_path_buf(),
        context_path: context_root.to_path_buf(),
        id: root_id.clone(),
        publication_parent_id: publication_parent_id.clone(),
        root_marker_id,
    };
    let leaf = open_private_directory_lease(staging_leaf)?;
    ensure_private_sqlite_lineage(&lineage, &leaf, staging_leaf, staging_database)?;
    leaf.sync_all()?;
    lineage.root.sync_all()?;
    Ok(root_id)
}

/// Publish a fresh wallet-private root with its empty database and lineage
/// fully synced, or require an existing root to carry exact create-time
/// lineage. A failed staging or publish attempt never blesses the final path.
fn ensure_private_workspace_lineage_impl(
    private_root: &Path,
    leaf: &Path,
    database: &Path,
    activate_sqlite: bool,
) -> io::Result<PrivateRootLineageLease> {
    if !leaf.starts_with(private_root) || database.parent() != Some(leaf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private workspace database must be a direct child beneath its private root",
        ));
    }
    match fs::symlink_metadata(private_root) {
        Ok(_) => {
            let lineage = verify_private_workspace_lineage(private_root)?;
            #[cfg(windows)]
            reserve_windows_sqlite_creation_before_leaf(&lineage, leaf, database)?;
            create_private_dir_all(leaf)?;
            let leaf_handle = open_private_sqlite_parent(leaf)?;
            ensure_private_sqlite_lineage(&lineage, &leaf_handle, leaf, database)?;
            if activate_sqlite {
                ensure_private_sqlite_file(&lineage, &leaf_handle, leaf, database)?;
            }
            Ok(lineage)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let publish_parent = private_root.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private root has no parent")
            })?;
            fs::create_dir_all(publish_parent)?;
            #[cfg(windows)]
            let sqlite_context = sqlite_lineage_context_paths(private_root, database)?;
            #[cfg(windows)]
            let context_hash = windows_lineage::context_hash(&sqlite_context);
            #[cfg(windows)]
            let _lineage_guard = windows_lineage::lock(&context_hash)?;
            let publication_parent = open_publication_parent(publish_parent)?;
            let publication_parent_id = private_object_id(&publication_parent)?;
            let names = child_names_set(&publication_parent, publish_parent)?;
            if names.contains(private_root.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private root has no file name")
            })?) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "private workspace root appeared during staged publication; retry",
                ));
            }
            #[cfg(windows)]
            let _reserved_generation = prepare_windows_lineage_creation(&sqlite_context)?;
            let destination_name = private_root.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private root has no file name")
            })?;
            let staging_name = format!(
                ".{}{}{}",
                destination_name.to_string_lossy(),
                PRIVATE_ROOT_STAGING_TAG,
                uuid::Uuid::new_v4()
            );
            let staging_root = publish_parent.join(staging_name);
            let leaf_relative = leaf.strip_prefix(private_root).map_err(io::Error::other)?;
            let database_relative = database
                .strip_prefix(private_root)
                .map_err(io::Error::other)?;
            let staging_leaf = staging_root.join(leaf_relative);
            let staging_database = staging_root.join(database_relative);
            let staged_id = initialize_staged_private_root(
                &staging_root,
                &staging_leaf,
                &staging_database,
                private_root,
                &publication_parent_id,
            )?;
            let staging = open_child_directory_for_mutation(&publication_parent, &staging_root)?;
            if private_object_id(&staging)? != staged_id {
                return Err(invalid_lineage(
                    "private staging root changed before publication",
                ));
            }
            rename_open_child_directory(
                &publication_parent,
                &staging_root,
                private_root,
                &staging,
            )?;
            publication_parent.sync_all()?;
            let current_parent = open_publication_parent(publish_parent)?;
            if private_object_id(&current_parent)? != publication_parent_id {
                return Err(invalid_lineage(
                    "workspace publication parent changed during publication",
                ));
            }
            let verified = verify_private_workspace_lineage(private_root)?;
            if verified.id != staged_id {
                return Err(invalid_lineage(
                    "private workspace root changed during staged publication",
                ));
            }
            let leaf_handle = open_private_sqlite_parent(leaf)?;
            ensure_private_sqlite_lineage(&verified, &leaf_handle, leaf, database)?;
            if activate_sqlite {
                ensure_private_sqlite_file(&verified, &leaf_handle, leaf, database)?;
            }
            Ok(verified)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_private_workspace_lineage(
    private_root: &Path,
    leaf: &Path,
    database: &Path,
) -> io::Result<PrivateRootLineageLease> {
    ensure_private_workspace_lineage_impl(private_root, leaf, database, true)
}

/// Verify that a private directory has the exact required access controls.
pub fn harden_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let directory = unix_private::open_directory(path)?;
        unix_private::verify_private_directory(&directory)
    }
    #[cfg(windows)]
    {
        windows_acl::harden_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private filesystem permissions are unsupported on this platform",
    ))
}

/// Verify that an already-open object has the exact required access controls.
///
/// Reused objects are never repaired in place: changing a mode or DACL cannot
/// revoke a stale handle held by another process. Creation establishes private
/// access before bytes are written, then this function verifies it.
pub fn harden_private_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::verify_private_file(file)
    }
    #[cfg(windows)]
    {
        windows_acl::harden(file, false)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private filesystem permissions are unsupported on this platform",
    ))
}

fn options_for(mode: PrivateOpenMode, create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(create_new);
    if matches!(
        mode,
        PrivateOpenMode::ReadWriteLock | PrivateOpenMode::ReadWriteAppend
    ) {
        options.read(true);
    }
    if matches!(
        mode,
        PrivateOpenMode::Append | PrivateOpenMode::ReadWriteAppend
    ) {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_APPEND_DATA, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };
        let data_access = match mode {
            PrivateOpenMode::Append => FILE_APPEND_DATA,
            PrivateOpenMode::ReadWriteLock | PrivateOpenMode::ReadWriteAppend => {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE
            }
            PrivateOpenMode::Truncate | PrivateOpenMode::CreateNew => FILE_GENERIC_WRITE,
        };
        options.access_mode(data_access | READ_CONTROL);
        if matches!(
            mode,
            PrivateOpenMode::ReadWriteLock | PrivateOpenMode::ReadWriteAppend
        ) {
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}

fn create_new_private_file(path: &Path, mode: PrivateOpenMode) -> io::Result<File> {
    #[cfg(windows)]
    {
        windows_acl::create_file(path, mode)
    }
    #[cfg(not(windows))]
    {
        options_for(mode, true).open(path)
    }
}

fn open_private_file_with(
    path: &Path,
    mode: PrivateOpenMode,
    harden: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<File> {
    let (file, created) = match create_new_private_file(path, mode) {
        Ok(file) => (file, true),
        Err(err)
            if err.kind() == io::ErrorKind::AlreadyExists && mode != PrivateOpenMode::CreateNew =>
        {
            #[cfg(windows)]
            let file = windows_acl::open_existing_private_file(path, mode)?;
            #[cfg(not(windows))]
            let file = options_for(mode, false).open(path)?;
            (file, false)
        }
        Err(err) => return Err(err),
    };

    if let Err(err) = validate_private_file(&file).and_then(|_| harden(&file)) {
        drop(file);
        if created {
            let _ = fs::remove_file(path);
        }
        return Err(err);
    }
    // Never request truncation in OpenOptions: reused files must pass exact
    // access-control verification before their old contents are destroyed.
    if mode == PrivateOpenMode::Truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

fn validate_private_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        if file.metadata()?.file_type().is_file() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file must be a regular file",
            ))
        }
    }
    #[cfg(windows)]
    {
        windows_acl::validate_private_file(file)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private filesystem permissions are unsupported on this platform",
    ))
}

/// Create a file with private access, or exact-verify a reused file before use.
pub fn open_private_file(path: &Path, mode: PrivateOpenMode) -> io::Result<File> {
    open_private_file_with(path, mode, harden_private_file)
}

fn open_sqlite_file_shared(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    return unix_private::open_child_file(parent, path);
    #[cfg(windows)]
    return windows_acl::open_child_file_for_identity(parent, path);
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private SQLite verification is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn trusted_sqlite_authorities() -> &'static std::sync::Mutex<TrustedSqliteRegistry> {
    static AUTHORITIES: std::sync::OnceLock<std::sync::Mutex<TrustedSqliteRegistry>> =
        std::sync::OnceLock::new();
    AUTHORITIES.get_or_init(|| std::sync::Mutex::new(TrustedSqliteRegistry::default()))
}

/// Revalidate the create-time root/database lineage before SQLite can parse a
/// byte. On Windows the first open of each exact object in this process uses a
/// share-zero preflight; later writer/progress connections are allowed only for
/// the same revalidated root, parent, database, and marker identities.
pub(crate) fn ensure_private_sqlite_file(
    root: &PrivateRootLineageLease,
    parent: &File,
    parent_path: &Path,
    path: &Path,
) -> io::Result<()> {
    if path.parent() != Some(parent_path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private SQLite database must be a direct child of its retained parent",
        ));
    }
    root.verify_current()?;
    let parent_id = private_object_id(parent)?;
    let marker_path = sqlite_lineage_path(path)?;
    let (marker_bytes, marker_id) = read_private_lineage_child_bytes(parent, &marker_path)?;
    let record: PrivateSqliteLineageRecord =
        decode_lineage_record(LineageRecordKind::Sqlite, &marker_bytes).map_err(|error| {
            invalid_lineage(format!(
                "private SQLite lineage marker {} is invalid: {error}",
                marker_path.display()
            ))
        })?;
    let database = open_sqlite_file_shared(parent, path)?;
    let database_id = private_object_id(&database)?;
    let context = sqlite_lineage_context(root, path)?;
    if record.schema_version != PRIVATE_SQLITE_LINEAGE_SCHEMA_VERSION
        || record.private_root != *root.id()
        || record.parent != parent_id
        || record.database != database_id
        || record.marker != marker_id
        || record.context != context
    {
        return Err(invalid_lineage(format!(
            "private SQLite lineage for {} does not match the exact filesystem objects",
            path.display()
        )));
    }
    #[cfg(windows)]
    activate_or_verify_windows_sqlite_authority(
        &context,
        &record,
        WindowsLineageObjects {
            publication_parent: root.publication_parent_id.clone(),
            private_root: root.id.clone(),
            root_marker: root.root_marker_id.clone(),
            sqlite_parent: parent_id.clone(),
            database: database_id.clone(),
            sqlite_marker: marker_id.clone(),
        },
    )?;
    drop(database);

    #[cfg(windows)]
    {
        let canonical_path = fs::canonicalize(path)?;
        let identity = TrustedSqliteIdentity {
            canonical_path: canonical_path.clone(),
            publication_parent: root.publication_parent_id.clone(),
            private_root: root.id().clone(),
            parent: parent_id,
            database: database_id,
            marker: marker_id,
            anchor_id: record.anchor_id,
            generation: record.generation,
        };
        let mut trusted = trusted_sqlite_authorities()
            .lock()
            .map_err(|_| io::Error::other("private SQLite authority registry is poisoned"))?;
        if trusted.cleanup_held.contains(&canonical_path) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "private SQLite workspace cleanup is in progress",
            ));
        }
        if let Some(authority) = trusted.authorities.get(&canonical_path) {
            if authority.identity != identity
                || private_object_id(&authority._root)? != identity.private_root
                || private_object_id(&authority._parent)? != identity.parent
                || private_object_id(&authority.database)? != identity.database
                || private_object_id(&authority.marker)? != identity.marker
            {
                return Err(invalid_lineage(
                    "cached private SQLite authority no longer matches the exact objects",
                ));
            }
        } else {
            let exclusive = windows_acl::open_child_file_exclusive(parent, path)?;
            if private_object_id(&exclusive)? != identity.database {
                return Err(invalid_lineage(
                    "private SQLite database changed during exclusive preflight",
                ));
            }
            drop(exclusive);
            let retained_root = windows_acl::open_directory_for_authority(&root.path)?;
            if private_object_id(&retained_root)? != identity.private_root {
                return Err(invalid_lineage(
                    "private workspace root changed before authority retention",
                ));
            }
            let retained_parent = windows_acl::open_directory_for_cleanup_authority(parent_path)?;
            if private_object_id(&retained_parent)? != identity.parent {
                return Err(invalid_lineage(
                    "private SQLite parent changed before authority retention",
                ));
            }
            let database = windows_acl::open_child_file_for_retained_authority(parent, path)?;
            let marker = windows_acl::open_child_file_for_retained_authority(parent, &marker_path)?;
            let authority = TrustedSqliteAuthority {
                identity,
                _root: retained_root,
                _parent: retained_parent,
                database,
                marker,
            };
            trusted.authorities.insert(canonical_path, authority);
        }
    }
    #[cfg(not(windows))]
    let _ = marker_id;
    root.verify_current()?;
    Ok(())
}

/// Atomically remove the process-local SQLite authority from general use and
/// retain the exact workspace directory handle that authority reviewed. The
/// registry marks the database cleanup-held before releasing its mutex, so a
/// concurrent same-process opener cannot repopulate authority before rename.
pub(crate) fn retain_private_workspace_for_cleanup(
    namespace: &NamespaceLease,
    leaf: &Path,
    database: &Path,
) -> io::Result<RetainedWorkspaceDirectory> {
    namespace.require_child(leaf)?;
    if database.parent() != Some(leaf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cleanup database must be a direct child of the workspace",
        ));
    }
    namespace.verify_current()?;

    #[cfg(windows)]
    {
        let open_guard = lock_private_sqlite_open(database)?;
        let registry_key = fs::canonicalize(database)?;
        let authority = {
            let mut registry = trusted_sqlite_authorities()
                .lock()
                .map_err(|_| io::Error::other("private SQLite authority registry is poisoned"))?;
            if !registry.cleanup_held.insert(registry_key.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "private SQLite workspace cleanup is already in progress",
                ));
            }
            registry.authorities.remove(&registry_key)
        };

        let result = (|| {
            let (directory, id) = if let Some(authority) = authority {
                if authority.identity.canonical_path != registry_key {
                    return Err(invalid_lineage(
                        "cached private SQLite authority has a different path",
                    ));
                }
                let id = authority.identity.parent.clone();
                let TrustedSqliteAuthority {
                    _parent: directory,
                    _root,
                    database,
                    marker,
                    ..
                } = authority;
                drop((_root, database, marker));
                (directory, id)
            } else {
                let directory = open_child_directory_for_mutation(namespace.parent(), leaf)?;
                let id = private_object_id(&directory)?;
                (directory, id)
            };
            verify_open_child_directory(namespace.parent(), leaf, &directory, &id)?;
            namespace.verify_current()?;
            Ok(RetainedWorkspaceDirectory {
                directory,
                id,
                cleanup_hold: Some(SqliteCleanupHold {
                    registry_key: registry_key.clone(),
                    _open_guard: open_guard,
                }),
            })
        })();
        if result.is_err() {
            if let Ok(mut registry) = trusted_sqlite_authorities().lock() {
                registry.cleanup_held.remove(&registry_key);
            }
        }
        return result;
    }

    #[cfg(unix)]
    {
        let directory = open_child_directory_for_mutation(namespace.parent(), leaf)?;
        unix_private::verify_private_directory(&directory)?;
        let id = private_object_id(&directory)?;
        verify_open_child_directory(namespace.parent(), leaf, &directory, &id)?;
        namespace.verify_current()?;
        Ok(RetainedWorkspaceDirectory {
            directory,
            id,
            cleanup_hold: None,
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (namespace, leaf, database);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "retained private workspace cleanup is unsupported on this platform",
        ))
    }
}

fn ephemeral_probe_cleanup_marker_path(private_root: &Path) -> io::Result<std::path::PathBuf> {
    let parent = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe private root has no publication parent",
        )
    })?;
    let root_name = private_root.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe private root has no name",
        )
    })?;
    let mut marker_name = OsString::from(".");
    marker_name.push(root_name);
    marker_name.push(EPHEMERAL_PROBE_CLEANUP_MARKER_SUFFIX);
    Ok(parent.join(marker_name))
}

fn ephemeral_probe_registration_path(private_root: &Path) -> io::Result<std::path::PathBuf> {
    let marker = ephemeral_probe_cleanup_marker_path(private_root)?;
    let mut name = marker
        .file_name()
        .expect("cleanup markers always have a name")
        .to_os_string();
    name.push(".lock");
    Ok(marker.with_file_name(name))
}

impl EphemeralProbeRegistration {
    fn acquire(private_root: &Path) -> io::Result<Self> {
        let parent_path = private_root.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ephemeral probe private root has no publication parent",
            )
        })?;
        let parent = open_publication_parent(parent_path)?;
        let path = ephemeral_probe_registration_path(private_root)?;
        let file = open_child_file_for_lock(&parent, &path)?;
        let id = private_object_id(&file)?;
        lock_exclusive(&file)?;
        parent.sync_all()?;
        Ok(Self { file, id, path })
    }

    fn verify(&self, private_root: &Path) -> io::Result<()> {
        if self.path != ephemeral_probe_registration_path(private_root)?
            || private_object_id(&self.file)? != self.id
        {
            return Err(invalid_lineage("ephemeral probe live registration changed"));
        }
        Ok(())
    }
}

fn ephemeral_probe_lock_is_contended(error: &io::Error) -> bool {
    #[cfg(unix)]
    return error
        .raw_os_error()
        .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK);
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
        return matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_LOCK_VIOLATION as i32
                    || code == ERROR_SHARING_VIOLATION as i32
        );
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

#[cfg(windows)]
fn hold_stale_ephemeral_probe_sqlite(database: &Path) -> io::Result<Option<SqliteCleanupHold>> {
    let registry_key = match fs::canonicalize(database) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let open_guard = lock_private_sqlite_open(database)?;
    let authority = {
        let mut registry = trusted_sqlite_authorities()
            .lock()
            .map_err(|_| io::Error::other("private SQLite authority registry is poisoned"))?;
        if !registry.cleanup_held.insert(registry_key.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "private SQLite workspace cleanup is already in progress",
            ));
        }
        registry.authorities.remove(&registry_key)
    };
    drop(authority);
    Ok(Some(SqliteCleanupHold {
        registry_key,
        _open_guard: open_guard,
    }))
}

fn validate_ephemeral_probe_cleanup_record(
    record: &EphemeralProbeCleanupRecord,
    marker_id: &PrivateObjectId,
    private_root: &Path,
    database: &Path,
    binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<()> {
    if record.schema_version != EPHEMERAL_PROBE_CLEANUP_SCHEMA_VERSION
        || &record.marker != marker_id
        || record.private_root != private_root
        || record.database != database
        || &record.binding != binding
    {
        return Err(invalid_lineage(
            "ephemeral probe cleanup marker does not match the exact workspace objects",
        ));
    }
    Ok(())
}

fn publish_ephemeral_probe_cleanup_marker(
    publication_parent: &File,
    private_root: &Path,
    database: &Path,
    binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<(std::path::PathBuf, PrivateObjectId)> {
    let marker_path = ephemeral_probe_cleanup_marker_path(private_root)?;
    let marker_id =
        match create_private_identity_record(publication_parent, &marker_path, |marker_id| {
            encode_ephemeral_probe_cleanup_record(&EphemeralProbeCleanupRecord {
                schema_version: EPHEMERAL_PROBE_CLEANUP_SCHEMA_VERSION,
                private_root: private_root.to_path_buf(),
                database: database.to_path_buf(),
                binding: binding.clone(),
                marker: marker_id.clone(),
            })
        }) {
            Ok(id) => id,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let (bytes, id) =
                    read_private_lineage_child_bytes(publication_parent, &marker_path)?;
                let record = decode_ephemeral_probe_cleanup_record(&bytes)?;
                validate_ephemeral_probe_cleanup_record(
                    &record,
                    &id,
                    private_root,
                    database,
                    binding,
                )?;
                id
            }
            Err(error) => return Err(error),
        };
    publication_parent.sync_all()?;
    Ok((marker_path, marker_id))
}

/// Establish empty private lineage and durably publish authenticated cleanup
/// authority before a probe writes seed-derived material to SQLite.
pub(crate) fn prepare_ephemeral_probe_workspace(
    private_root: &Path,
    leaf: &Path,
    database: &Path,
) -> io::Result<EphemeralProbeRegistration> {
    let publication_parent_path = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe private root has no publication parent",
        )
    })?;
    fs::create_dir_all(publication_parent_path)?;
    let registration = EphemeralProbeRegistration::acquire(private_root)?;
    ensure_private_workspace_lineage_impl(private_root, leaf, database, false)?;
    let directory = open_private_sqlite_parent(leaf)?;
    let id = private_object_id(&directory)?;
    let retained = RetainedWorkspaceDirectory {
        directory,
        id,
        cleanup_hold: None,
    };
    let binding = inspect_prepared_ephemeral_probe_binding(private_root, &retained, database)?;
    let publication_parent = open_publication_parent(publication_parent_path)?;
    if private_object_id(&publication_parent)? != binding.publication_parent {
        return Err(invalid_lineage(
            "ephemeral probe publication parent changed before marker publication",
        ));
    }
    publish_ephemeral_probe_cleanup_marker(&publication_parent, private_root, database, &binding)?;
    Ok(registration)
}

/// Begin exact cleanup of a throwaway probe workspace. This publishes a
/// private, authenticated cleanup marker before releasing the retained SQLite
/// leaf handles. The returned token keeps same-process SQLite opens blocked
/// until cleanup either finishes or fails.
pub(crate) fn begin_ephemeral_probe_cleanup(
    registration: EphemeralProbeRegistration,
    private_root: &Path,
    leaf: &Path,
    database: &Path,
) -> io::Result<EphemeralProbeCleanup> {
    registration.verify(private_root)?;
    if !leaf.starts_with(private_root) || database.parent() != Some(leaf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe database must be a direct child beneath its private root",
        ));
    }
    let namespace_parent = leaf.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe workspace has no namespace parent",
        )
    })?;
    let namespace = NamespaceLease::acquire(
        namespace_parent,
        &namespace_parent.join(".argos-ephemeral-probe-cleanup.lock"),
    )?;
    let retained_leaf = retain_private_workspace_for_cleanup(&namespace, leaf, database)?;
    let binding =
        inspect_private_workspace_cleanup_binding(private_root, &retained_leaf, database)?;

    let publication_parent_path = private_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe private root has no publication parent",
        )
    })?;
    let publication_parent = open_publication_parent(publication_parent_path)?;
    if private_object_id(&publication_parent)? != binding.publication_parent {
        return Err(invalid_lineage(
            "ephemeral probe publication parent changed before cleanup",
        ));
    }
    let private_root_directory =
        open_child_directory_for_mutation(&publication_parent, private_root)?;
    let private_root_id = private_object_id(&private_root_directory)?;
    if private_root_id != binding.private_root {
        return Err(invalid_lineage(
            "ephemeral probe private root changed before cleanup",
        ));
    }

    let (marker_path, marker_id) = publish_ephemeral_probe_cleanup_marker(
        &publication_parent,
        private_root,
        database,
        &binding,
    )?;
    let RetainedWorkspaceDirectory {
        directory,
        id: _,
        cleanup_hold,
    } = retained_leaf;
    drop(directory);

    Ok(EphemeralProbeCleanup {
        publication_parent,
        publication_parent_path: publication_parent_path.to_path_buf(),
        private_root: private_root.to_path_buf(),
        private_root_directory,
        private_root_id,
        marker_path,
        marker_id,
        #[cfg(windows)]
        database: database.to_path_buf(),
        binding,
        cleanup_hold,
        _registration: registration,
    })
}

impl EphemeralProbeCleanup {
    /// Remove the exact private root, durably publish its absence, and only
    /// then retire the exact Windows per-probe registry authority.
    pub(crate) fn remove_exact_private_root_and_retire(mut self) -> io::Result<()> {
        if private_object_id(&self.publication_parent)? != self.binding.publication_parent
            || private_object_id(&self.private_root_directory)? != self.private_root_id
            || self.private_root_id != self.binding.private_root
        {
            return Err(invalid_lineage(
                "ephemeral probe cleanup authority no longer matches its retained objects",
            ));
        }
        verify_open_child_directory(
            &self.publication_parent,
            &self.private_root,
            &self.private_root_directory,
            &self.private_root_id,
        )?;

        #[cfg(windows)]
        let (context_hash, _lineage_guard) = verify_active_ephemeral_probe_authority(
            &self.private_root,
            &self.database,
            &self.binding,
        )?;

        remove_open_directory_contents(&self.private_root_directory)?;
        self.private_root_directory.sync_all()?;
        remove_open_child_directory(
            &self.publication_parent,
            &self.private_root,
            &self.private_root_directory,
            &self.private_root_id,
        )?;
        self.publication_parent.sync_all()?;
        if parent_child_names(&self.publication_parent, &self.publication_parent_path)?
            .iter()
            .any(|name| Some(name.as_os_str()) == self.private_root.file_name())
        {
            return Err(invalid_lineage(
                "ephemeral probe private root still exists after exact cleanup",
            ));
        }

        #[cfg(windows)]
        windows_lineage::delete_authority(&context_hash)?;

        remove_ephemeral_probe_cleanup_marker(
            &self.publication_parent,
            &self.marker_path,
            &self.marker_id,
        )?;
        self.cleanup_hold.take();
        Ok(())
    }
}

fn read_ephemeral_probe_cleanup_marker(
    marker_path: &Path,
) -> io::Result<(
    File,
    std::path::PathBuf,
    PrivateObjectId,
    EphemeralProbeCleanupRecord,
)> {
    let parent_path = marker_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe cleanup marker has no parent",
        )
    })?;
    let parent = open_publication_parent(parent_path)?;
    let (bytes, marker_id) = read_private_lineage_child_bytes(&parent, marker_path)?;
    let record = decode_ephemeral_probe_cleanup_record(&bytes)?;
    if record.schema_version != EPHEMERAL_PROBE_CLEANUP_SCHEMA_VERSION
        || record.marker != marker_id
        || record.private_root.parent() != Some(parent_path)
        || ephemeral_probe_cleanup_marker_path(&record.private_root)? != marker_path
        || record.database.parent().is_none()
        || !record.database.starts_with(&record.private_root)
        || record.binding.publication_parent != private_object_id(&parent)?
        || record.binding.private_root == record.binding.workspace
    {
        return Err(invalid_lineage(
            "ephemeral probe cleanup marker has invalid path or object bindings",
        ));
    }
    Ok((parent, parent_path.to_path_buf(), marker_id, record))
}

#[cfg(windows)]
fn verify_active_ephemeral_probe_authority(
    private_root: &Path,
    database: &Path,
    binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<([u8; 32], windows_acl::LineageMutex)> {
    let context = sqlite_lineage_context_paths(private_root, database)?;
    let context_hash = windows_lineage::context_hash(&context);
    let guard = windows_lineage::lock(&context_hash)?;
    let authority = windows_lineage::read_authority(&context_hash)?
        .ok_or_else(|| invalid_lineage("ephemeral probe Windows lineage authority is missing"))?;
    let anchor_id = binding
        .anchor_id
        .ok_or_else(|| invalid_lineage("ephemeral probe binding has no anchor"))?;
    let generation = binding
        .generation
        .ok_or_else(|| invalid_lineage("ephemeral probe binding has no generation"))?;
    require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
    match authority.state {
        WindowsLineageState::Active {
            generation: current,
            objects,
        } if current == generation && objects == windows_objects_from_cleanup_binding(binding) => {}
        _ => {
            return Err(invalid_lineage(
                "ephemeral probe cleanup requires the exact Active authority",
            ));
        }
    }
    Ok((context_hash, guard))
}

#[cfg(windows)]
fn verify_stale_ephemeral_probe_authority(
    private_root: &Path,
    database: &Path,
    binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<([u8; 32], windows_acl::LineageMutex)> {
    let context = sqlite_lineage_context_paths(private_root, database)?;
    let context_hash = windows_lineage::context_hash(&context);
    let guard = windows_lineage::lock(&context_hash)?;
    let authority = windows_lineage::read_authority(&context_hash)?
        .ok_or_else(|| invalid_lineage("ephemeral probe Windows lineage authority is missing"))?;
    let anchor_id = binding
        .anchor_id
        .ok_or_else(|| invalid_lineage("ephemeral probe binding has no anchor"))?;
    let generation = binding
        .generation
        .ok_or_else(|| invalid_lineage("ephemeral probe binding has no generation"))?;
    require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
    match authority.state {
        WindowsLineageState::Pending {
            generation: current,
        } if current == generation => {}
        WindowsLineageState::Active {
            generation: current,
            objects,
        } if current == generation && objects == windows_objects_from_cleanup_binding(binding) => {}
        _ => {
            return Err(invalid_lineage(
                "stale ephemeral probe marker does not match Pending or Active authority",
            ));
        }
    }
    Ok((context_hash, guard))
}

fn remove_ephemeral_probe_cleanup_marker(
    publication_parent: &File,
    marker_path: &Path,
    marker_id: &PrivateObjectId,
) -> io::Result<()> {
    let marker = open_child_file_for_removal(publication_parent, marker_path)?;
    if private_object_id(&marker)? != *marker_id {
        return Err(invalid_lineage(
            "ephemeral probe cleanup marker changed before retirement",
        ));
    }
    remove_open_child_file(publication_parent, marker_path, &marker, marker_id)?;
    publication_parent.sync_all()
}

/// Resume an authenticated ephemeral-probe cleanup marker left by a crash.
/// A marker is only authority for the exact root and registry objects it binds;
/// candidate names alone never authorize filesystem mutation.
pub(crate) fn cleanup_stale_ephemeral_probe_marker(marker_path: &Path) -> io::Result<()> {
    let (publication_parent, publication_parent_path, marker_id, record) =
        read_ephemeral_probe_cleanup_marker(marker_path)?;
    let _registration = match EphemeralProbeRegistration::acquire(&record.private_root) {
        Ok(registration) => registration,
        Err(error) if ephemeral_probe_lock_is_contended(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    let _cleanup_hold = hold_stale_ephemeral_probe_sqlite(&record.database)?;
    let root_name = record.private_root.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ephemeral probe private root has no name",
        )
    })?;
    let root_exists = parent_child_names(&publication_parent, &publication_parent_path)?
        .iter()
        .any(|name| name == root_name);

    #[cfg(windows)]
    let (context_hash, _lineage_guard, retire_authority) = if root_exists {
        let (context_hash, guard) = verify_stale_ephemeral_probe_authority(
            &record.private_root,
            &record.database,
            &record.binding,
        )?;
        (context_hash, guard, true)
    } else {
        let context = sqlite_lineage_context_paths(&record.private_root, &record.database)?;
        let context_hash = windows_lineage::context_hash(&context);
        let guard = windows_lineage::lock(&context_hash)?;
        let authority = windows_lineage::read_authority(&context_hash)?;
        let retire = match authority {
            None => false,
            Some(authority) => {
                let anchor_id = record
                    .binding
                    .anchor_id
                    .ok_or_else(|| invalid_lineage("ephemeral probe binding has no anchor"))?;
                let generation = record
                    .binding
                    .generation
                    .ok_or_else(|| invalid_lineage("ephemeral probe binding has no generation"))?;
                require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
                match authority.state {
                    WindowsLineageState::Pending {
                        generation: current,
                    } if current == generation => true,
                    WindowsLineageState::Active {
                        generation: current,
                        objects,
                    } if current == generation
                        && objects == windows_objects_from_cleanup_binding(&record.binding) =>
                    {
                        true
                    }
                    _ => {
                        return Err(invalid_lineage(
                            "stale ephemeral probe marker does not match its Windows authority",
                        ));
                    }
                }
            }
        };
        (context_hash, guard, retire)
    };

    if root_exists {
        let private_root_directory =
            open_child_directory_for_mutation(&publication_parent, &record.private_root)?;
        let private_root_id = private_object_id(&private_root_directory)?;
        if private_root_id != record.binding.private_root {
            return Err(invalid_lineage(
                "stale ephemeral probe marker names a different private root object",
            ));
        }
        remove_open_directory_contents(&private_root_directory)?;
        private_root_directory.sync_all()?;
        remove_open_child_directory(
            &publication_parent,
            &record.private_root,
            &private_root_directory,
            &private_root_id,
        )?;
        publication_parent.sync_all()?;
    }
    if parent_child_names(&publication_parent, &publication_parent_path)?
        .iter()
        .any(|name| name == root_name)
    {
        return Err(invalid_lineage(
            "stale ephemeral probe private root still exists after exact cleanup",
        ));
    }

    #[cfg(windows)]
    if retire_authority {
        windows_lineage::delete_authority(&context_hash)?;
    }
    remove_ephemeral_probe_cleanup_marker(&publication_parent, marker_path, &marker_id)
}

fn ephemeral_probe_container_owned_by_current_user(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = fs::symlink_metadata(path)?;
        Ok(metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() })
    }
    #[cfg(windows)]
    return windows_acl::directory_owned_by_current_user(path);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(false)
    }
}

/// Find authenticated probe cleanup markers beneath UUID probe containers and
/// finish them before starting another probe. Containers without a marker are
/// left untouched, including any concurrently active probe.
pub(crate) fn cleanup_stale_ephemeral_probes(temp_parent: &Path) -> io::Result<()> {
    for container in fs::read_dir(temp_parent)? {
        let container = container?;
        let name = container.file_name();
        let Some(candidate) = name
            .to_str()
            .and_then(|name| name.strip_prefix("zeck_probe_"))
        else {
            continue;
        };
        let Ok(uuid) = uuid::Uuid::parse_str(candidate) else {
            continue;
        };
        if uuid.hyphenated().to_string() != candidate {
            continue;
        }
        match ephemeral_probe_container_owned_by_current_user(&container.path()) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(error) => return Err(error),
        }
        let metadata = container.file_type()?;
        if !metadata.is_dir() || metadata.is_symlink() {
            continue;
        }
        for network_dir in fs::read_dir(container.path())? {
            let network_dir = network_dir?;
            let metadata = network_dir.file_type()?;
            if !metadata.is_dir() || metadata.is_symlink() {
                continue;
            }
            for marker in fs::read_dir(network_dir.path())? {
                let marker = marker?;
                let name = marker.file_name();
                if name
                    .to_string_lossy()
                    .ends_with(EPHEMERAL_PROBE_CLEANUP_MARKER_SUFFIX)
                {
                    cleanup_stale_ephemeral_probe_marker(&marker.path())?;
                }
            }
        }
    }
    Ok(())
}

/// Authorize a new recovery generation only after an earlier, durably revoked
/// leaf has been fully removed. Ordinary workspace open never performs this
/// transition.
#[cfg(windows)]
fn verify_workspace_absent_for_recreation(leaf: &Path, database: &Path) -> io::Result<()> {
    match fs::symlink_metadata(leaf) {
        Ok(_) => {
            return Err(invalid_lineage(
                "workspace leaf already exists; missing or revoked authority cannot bless it",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for path in std::iter::once(database.to_path_buf())
        .chain(std::iter::once(sqlite_lineage_path(database)?))
        .chain(sqlite_sidecar_paths(database))
    {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(invalid_lineage(format!(
                    "revoked workspace artifact {} still exists",
                    path.display()
                )));
            }
            Err(error) => return Err(error),
        }
    }
    let cleanup_parent = leaf.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "workspace leaf has no parent")
    })?;
    match open_private_directory_lease(cleanup_parent) {
        Ok(parent) => {
            let names = child_names_set(&parent, cleanup_parent)?;
            let leaf_name = leaf.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "workspace leaf has no name")
            })?;
            let marker = {
                let mut marker = leaf_name.to_os_string();
                marker.push(".cleanup-pending.json");
                marker
            };
            let tombstone_prefix = format!("{}.deleting-", leaf_name.to_string_lossy());
            if names.contains(&marker)
                || names
                    .iter()
                    .any(|name| name.to_string_lossy().starts_with(&tombstone_prefix))
            {
                return Err(invalid_lineage(
                    "workspace cleanup marker or tombstone still exists; cleanup must finish before a new recovery",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

pub(crate) fn authorize_private_workspace_recreation(
    private_root: &Path,
    leaf: &Path,
    database: &Path,
) -> io::Result<()> {
    #[cfg(windows)]
    {
        if !private_root.exists() {
            return Ok(());
        }
        let root = verify_private_workspace_lineage(private_root)?;
        let context = sqlite_lineage_context(&root, database)?;
        let context_hash = windows_lineage::context_hash(&context);
        let _guard = windows_lineage::lock(&context_hash)?;
        let Some(mut authority) = windows_lineage::read_authority(&context_hash)? else {
            verify_workspace_absent_for_recreation(leaf, database)?;
            let _ = prepare_windows_lineage_creation(&context)?;
            return Ok(());
        };
        require_windows_authority_header(&authority, &context_hash, &authority.anchor_id)?;
        let revoked_objects = match &authority.state {
            WindowsLineageState::Revoked { objects, .. } => objects,
            WindowsLineageState::Pending { .. } => return Ok(()),
            WindowsLineageState::Active { .. } => {
                return match fs::symlink_metadata(leaf) {
                    Ok(_) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Err(invalid_lineage(
                        "active Windows private lineage workspace is missing; manual recovery is required",
                    )),
                    Err(error) => Err(error),
                };
            }
        };
        if revoked_objects.publication_parent != root.publication_parent_id
            || revoked_objects.private_root != root.id
            || revoked_objects.root_marker != root.root_marker_id
        {
            return Err(invalid_lineage(
                "revoked Windows lineage does not match the retained private root",
            ));
        }
        verify_workspace_absent_for_recreation(leaf, database)?;
        let generation = uuid::Uuid::new_v4().into_bytes();
        authority.state = WindowsLineageState::Pending { generation };
        windows_lineage::write_authority(&context_hash, &authority)?;
    }
    #[cfg(not(windows))]
    let _ = (private_root, leaf, database);
    Ok(())
}

/// Durably revoke a Windows leaf/DB generation before its retained directory
/// handle is renamed for cleanup. Repeating the same cleanup ID is idempotent.
fn inspect_private_workspace_cleanup_binding_filesystem(
    private_root: &Path,
    retained_leaf: &RetainedWorkspaceDirectory,
    database: &Path,
) -> io::Result<PrivateWorkspaceCleanupBinding> {
    let root = verify_private_workspace_lineage(private_root)?;
    if database.parent().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private SQLite database has no workspace parent",
        ));
    }
    #[cfg(unix)]
    unix_private::verify_private_directory(&retained_leaf.directory)?;
    #[cfg(windows)]
    windows_acl::validate_private_directory(&retained_leaf.directory)?;
    if private_object_id(&retained_leaf.directory)? != retained_leaf.id {
        return Err(invalid_lineage(
            "retained workspace changed before cleanup binding inspection",
        ));
    }
    let marker_path = sqlite_lineage_path(database)?;
    let (marker_bytes, marker_id) =
        read_private_lineage_child_bytes(&retained_leaf.directory, &marker_path)?;
    let record: PrivateSqliteLineageRecord =
        decode_lineage_record(LineageRecordKind::Sqlite, &marker_bytes)?;
    let database_file = open_sqlite_file_shared(&retained_leaf.directory, database)?;
    let database_id = private_object_id(&database_file)?;
    let context = sqlite_lineage_context(&root, database)?;
    if record.schema_version != PRIVATE_SQLITE_LINEAGE_SCHEMA_VERSION
        || record.private_root != root.id
        || record.parent != retained_leaf.id
        || record.database != database_id
        || record.marker != marker_id
        || record.context != context
    {
        return Err(invalid_lineage(
            "cleanup binding does not match the exact private workspace objects",
        ));
    }

    let binding = PrivateWorkspaceCleanupBinding {
        publication_parent: root.publication_parent_id.clone(),
        private_root: root.id.clone(),
        root_marker: root.root_marker_id.clone(),
        workspace: retained_leaf.id.clone(),
        database: database_id,
        database_marker: marker_id,
        #[cfg(windows)]
        anchor_id: Some(record.anchor_id),
        #[cfg(not(windows))]
        anchor_id: None,
        #[cfg(windows)]
        generation: Some(record.generation),
        #[cfg(not(windows))]
        generation: None,
    };

    let _ = context;
    Ok(binding)
}

fn inspect_prepared_ephemeral_probe_binding(
    private_root: &Path,
    retained_leaf: &RetainedWorkspaceDirectory,
    database: &Path,
) -> io::Result<PrivateWorkspaceCleanupBinding> {
    let binding = inspect_private_workspace_cleanup_binding_filesystem(
        private_root,
        retained_leaf,
        database,
    )?;
    #[cfg(windows)]
    {
        let root = verify_private_workspace_lineage(private_root)?;
        let context = sqlite_lineage_context(&root, database)?;
        let context_hash = windows_lineage::context_hash(&context);
        let _guard = windows_lineage::lock(&context_hash)?;
        let authority = windows_lineage::read_authority(&context_hash)?.ok_or_else(|| {
            invalid_lineage("prepared ephemeral probe Windows authority is missing")
        })?;
        let anchor_id = binding
            .anchor_id
            .ok_or_else(|| invalid_lineage("prepared probe binding has no anchor"))?;
        let generation = binding
            .generation
            .ok_or_else(|| invalid_lineage("prepared probe binding has no generation"))?;
        require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
        match authority.state {
            WindowsLineageState::Pending {
                generation: current,
            } if current == generation => {}
            WindowsLineageState::Active {
                generation: current,
                objects,
            } if current == generation
                && objects == windows_objects_from_cleanup_binding(&binding) => {}
            _ => {
                return Err(invalid_lineage(
                    "prepared ephemeral probe authority is neither exact Pending nor Active",
                ));
            }
        }
    }
    Ok(binding)
}

#[cfg(windows)]
fn windows_objects_from_cleanup_binding(
    binding: &PrivateWorkspaceCleanupBinding,
) -> WindowsLineageObjects {
    WindowsLineageObjects {
        publication_parent: binding.publication_parent.clone(),
        private_root: binding.private_root.clone(),
        root_marker: binding.root_marker.clone(),
        sqlite_parent: binding.workspace.clone(),
        database: binding.database.clone(),
        sqlite_marker: binding.database_marker.clone(),
    }
}

pub(crate) fn inspect_private_workspace_cleanup_binding(
    private_root: &Path,
    retained_leaf: &RetainedWorkspaceDirectory,
    database: &Path,
) -> io::Result<PrivateWorkspaceCleanupBinding> {
    let binding = inspect_private_workspace_cleanup_binding_filesystem(
        private_root,
        retained_leaf,
        database,
    )?;
    #[cfg(windows)]
    {
        let root = verify_private_workspace_lineage(private_root)?;
        let context = sqlite_lineage_context(&root, database)?;
        let context_hash = windows_lineage::context_hash(&context);
        let _guard = windows_lineage::lock(&context_hash)?;
        let authority = windows_lineage::read_authority(&context_hash)?.ok_or_else(|| {
            invalid_lineage("Windows private lineage registry authority is missing")
        })?;
        let anchor_id = binding
            .anchor_id
            .ok_or_else(|| invalid_lineage("cleanup binding has no Windows anchor"))?;
        let generation = binding
            .generation
            .ok_or_else(|| invalid_lineage("cleanup binding has no Windows generation"))?;
        require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
        match authority.state {
            WindowsLineageState::Active {
                generation: current,
                objects,
            } if current == generation
                && objects == windows_objects_from_cleanup_binding(&binding) => {}
            _ => {
                return Err(invalid_lineage(
                    "Windows private lineage is not Active for the exact cleanup objects",
                ));
            }
        }
    }
    Ok(binding)
}

pub(crate) fn revoke_private_workspace_lineage(
    private_root: &Path,
    retained_leaf: &RetainedWorkspaceDirectory,
    database: &Path,
    cleanup_id: [u8; 16],
    expected_binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<()> {
    #[cfg(windows)]
    {
        let current_binding = inspect_private_workspace_cleanup_binding_filesystem(
            private_root,
            retained_leaf,
            database,
        )?;
        if &current_binding != expected_binding {
            return Err(invalid_lineage(
                "private workspace changed after cleanup marker publication",
            ));
        }
        let root = verify_private_workspace_lineage(private_root)?;
        windows_acl::validate_private_directory(&retained_leaf.directory)?;
        let parent = &retained_leaf.directory;
        let marker_path = sqlite_lineage_path(database)?;
        let (marker_bytes, marker_id) = read_private_lineage_child_bytes(parent, &marker_path)?;
        let record: PrivateSqliteLineageRecord =
            decode_lineage_record(LineageRecordKind::Sqlite, &marker_bytes)?;
        let database_file = open_sqlite_file_shared(parent, database)?;
        let context = sqlite_lineage_context(&root, database)?;
        let objects = WindowsLineageObjects {
            publication_parent: root.publication_parent_id.clone(),
            private_root: root.id.clone(),
            root_marker: root.root_marker_id.clone(),
            sqlite_parent: private_object_id(parent)?,
            database: private_object_id(&database_file)?,
            sqlite_marker: marker_id,
        };
        if record.schema_version != PRIVATE_SQLITE_LINEAGE_SCHEMA_VERSION
            || record.private_root != root.id
            || record.parent != objects.sqlite_parent
            || record.database != objects.database
            || record.marker != objects.sqlite_marker
            || record.context != context
        {
            return Err(invalid_lineage(
                "cannot revoke a SQLite lineage that does not match the exact workspace objects",
            ));
        }
        let context_hash = windows_lineage::context_hash(&context);
        let _guard = windows_lineage::lock(&context_hash)?;
        let mut authority = windows_lineage::read_authority(&context_hash)?.ok_or_else(|| {
            invalid_lineage("Windows private lineage registry authority is missing")
        })?;
        require_windows_authority_header(&authority, &context_hash, &record.anchor_id)?;
        match &authority.state {
            WindowsLineageState::Active {
                generation,
                objects: expected,
            } if generation == &record.generation && expected == &objects => {
                authority.state = WindowsLineageState::Revoked {
                    retired_generation: record.generation,
                    cleanup_id,
                    objects,
                };
                windows_lineage::write_authority(&context_hash, &authority)?;
            }
            WindowsLineageState::Revoked {
                retired_generation,
                cleanup_id: expected_cleanup,
                objects: expected,
            } if retired_generation == &record.generation
                && expected_cleanup == &cleanup_id
                && expected == &objects => {}
            _ => {
                return Err(invalid_lineage(
                    "Windows private lineage authority cannot be revoked from its current state",
                ));
            }
        }
    }
    #[cfg(not(windows))]
    {
        let current_binding =
            inspect_private_workspace_cleanup_binding(private_root, retained_leaf, database)?;
        if &current_binding != expected_binding {
            return Err(invalid_lineage(
                "private workspace changed after cleanup marker publication",
            ));
        }
        let _ = cleanup_id;
    }
    Ok(())
}

/// Reconcile a crash-stopped cleanup whose exact workspace survived. The
/// marker's cleanup ID and complete object binding must match the durable
/// Revoked record before the same generation can return to Active.
pub(crate) fn reconcile_private_workspace_cleanup(
    private_root: &Path,
    retained_leaf: &RetainedWorkspaceDirectory,
    database: &Path,
    cleanup_id: [u8; 16],
    expected_binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<()> {
    let current = inspect_private_workspace_cleanup_binding_filesystem(
        private_root,
        retained_leaf,
        database,
    )?;
    if &current != expected_binding {
        return Err(invalid_lineage(
            "surviving cleanup workspace does not match its exact marker binding",
        ));
    }
    #[cfg(windows)]
    {
        let root = verify_private_workspace_lineage(private_root)?;
        let context = sqlite_lineage_context(&root, database)?;
        let context_hash = windows_lineage::context_hash(&context);
        let _guard = windows_lineage::lock(&context_hash)?;
        let mut authority = windows_lineage::read_authority(&context_hash)?.ok_or_else(|| {
            invalid_lineage("Windows private lineage registry authority is missing")
        })?;
        let anchor_id = expected_binding
            .anchor_id
            .ok_or_else(|| invalid_lineage("cleanup binding has no Windows anchor"))?;
        let generation = expected_binding
            .generation
            .ok_or_else(|| invalid_lineage("cleanup binding has no Windows generation"))?;
        let objects = windows_objects_from_cleanup_binding(expected_binding);
        require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
        match &authority.state {
            WindowsLineageState::Active {
                generation: current,
                objects: current_objects,
            } if current == &generation && current_objects == &objects => {}
            WindowsLineageState::Revoked {
                retired_generation,
                cleanup_id: current_cleanup,
                objects: current_objects,
            } if retired_generation == &generation
                && current_cleanup == &cleanup_id
                && current_objects == &objects =>
            {
                authority.state = WindowsLineageState::Active {
                    generation,
                    objects,
                };
                windows_lineage::write_authority(&context_hash, &authority)?;
            }
            _ => {
                return Err(invalid_lineage(
                    "cleanup marker does not match the Active or Revoked Windows authority",
                ));
            }
        }
    }
    #[cfg(not(windows))]
    let _ = cleanup_id;
    Ok(())
}

pub(crate) fn verify_surviving_private_workspace_cleanup(
    private_root: &Path,
    retained_leaf: &RetainedWorkspaceDirectory,
    database: &Path,
    expected_binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<()> {
    let current = inspect_private_workspace_cleanup_binding_filesystem(
        private_root,
        retained_leaf,
        database,
    )?;
    if &current != expected_binding {
        return Err(invalid_lineage(
            "surviving cleanup workspace does not match its exact marker binding",
        ));
    }
    Ok(())
}

/// Verify the terminal crash state where the exact workspace was fully
/// removed after durable revocation but before its cleanup marker was cleared.
pub(crate) fn verify_completed_private_workspace_cleanup(
    private_root: &Path,
    database: &Path,
    cleanup_id: [u8; 16],
    expected_binding: &PrivateWorkspaceCleanupBinding,
) -> io::Result<()> {
    #[cfg(windows)]
    {
        let root = verify_private_workspace_lineage(private_root)?;
        let context = sqlite_lineage_context(&root, database)?;
        let context_hash = windows_lineage::context_hash(&context);
        let _guard = windows_lineage::lock(&context_hash)?;
        let authority = windows_lineage::read_authority(&context_hash)?.ok_or_else(|| {
            invalid_lineage("Windows private lineage registry authority is missing")
        })?;
        let anchor_id = expected_binding
            .anchor_id
            .ok_or_else(|| invalid_lineage("cleanup binding has no Windows anchor"))?;
        let generation = expected_binding
            .generation
            .ok_or_else(|| invalid_lineage("cleanup binding has no Windows generation"))?;
        require_windows_authority_header(&authority, &context_hash, &anchor_id)?;
        match authority.state {
            WindowsLineageState::Revoked {
                retired_generation,
                cleanup_id: current_cleanup,
                objects,
            } if retired_generation == generation
                && current_cleanup == cleanup_id
                && objects == windows_objects_from_cleanup_binding(expected_binding) => {}
            _ => {
                return Err(invalid_lineage(
                    "completed cleanup does not match its durable Revoked authority",
                ));
            }
        }
    }
    #[cfg(not(windows))]
    let _ = (private_root, database, cleanup_id, expected_binding);
    Ok(())
}

#[cfg(all(test, windows))]
fn forget_sqlite_authority_for_test(path: &Path) {
    if let Ok(canonical) = fs::canonicalize(path) {
        let mut registry = trusted_sqlite_authorities().lock().unwrap();
        registry.authorities.remove(&canonical);
        registry.cleanup_held.remove(&canonical);
    }
}

/// Replace a private file in place after applying permissions to its handle.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_private_file(path, PrivateOpenMode::Truncate)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

/// Atomically replace `path` using a create-new private sibling.
pub fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_private_file_atomic_with_observer(path, bytes, |_| Ok(()))
}

pub(crate) fn write_private_file_atomic_in_parent(
    parent: &File,
    path: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::write_atomic_in_parent(parent, path, bytes, |_| Ok(()))
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            write_private_file_atomic_windows_in_parent(parent, path, bytes, |_| Ok(()))
        }
        #[cfg(not(windows))]
        {
            let _ = parent;
            write_private_file_atomic(path, bytes)
        }
    }
}

/// Remove destination-scoped atomic staging left by a crashed writer once it
/// is old enough that it cannot belong to an active write. The caller must
/// serialize cleanup with every writer for `path`; age alone cannot prove a
/// paused writer is inactive.
#[cfg(all(test, unix))]
pub(crate) fn remove_stale_private_file_staging(
    path: &Path,
    minimum_age: std::time::Duration,
) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unix_private::cleanup_staging(path, Some(minimum_age))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, minimum_age);
        Ok(false)
    }
}

#[cfg(all(test, unix))]
pub(crate) fn discard_private_file_staging(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unix_private::cleanup_staging(path, None)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
    }
}

/// Remove one direct child through a retained parent directory handle.
pub(crate) fn remove_child_file(parent: &File, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::remove_child_file(parent, path)
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            let _ = parent;
            let file = windows_acl::open_child_for_mutation(parent, path)?;
            windows_acl::delete_open_file(&file)
        }
        #[cfg(not(windows))]
        {
            let _ = parent;
            fs::remove_file(path)
        }
    }
}

/// Rename direct children through a retained parent directory handle.
#[cfg(all(test, windows))]
pub(crate) fn rename_child_file(parent: &File, from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::rename_child_file(parent, from, to)
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            let file = windows_acl::open_child_for_mutation(parent, from)?;
            windows_acl::replace_file(&file, parent, to)
        }
        #[cfg(not(windows))]
        {
            let _ = parent;
            fs::rename(from, to)
        }
    }
}

fn open_child_directory_for_mutation(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_directory_for_mutation(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_directory_for_mutation(parent, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directory mutation is unsupported on this platform",
        ))
    }
}

fn verify_open_child_directory(
    parent: &File,
    path: &Path,
    directory: &File,
    expected: &PrivateObjectId,
) -> io::Result<()> {
    if &private_object_id(directory)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "retained private directory changed",
        ));
    }
    let current = open_child_directory_for_identity(parent, path)?;
    if private_object_id(&current)? != *expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private directory path changed before mutation",
        ));
    }
    Ok(())
}

fn open_child_directory_for_identity(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_directory_for_mutation(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_directory_for_identity(parent, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directory identity is unsupported on this platform",
        ))
    }
}

fn rename_open_child_directory(
    parent: &File,
    from: &Path,
    to: &Path,
    directory: &File,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        let _ = directory;
        unix_private::rename_child_directory_noreplace(parent, from, to)
    }
    #[cfg(windows)]
    {
        let _ = from;
        windows_acl::move_file(directory, parent, to, false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, from, to, directory);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directory rename is unsupported on this platform",
        ))
    }
}

fn remove_open_directory_contents(directory: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::remove_open_directory_contents(directory)
    }
    #[cfg(windows)]
    {
        windows_acl::remove_open_directory_contents(directory)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = directory;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private recursive directory removal is unsupported on this platform",
        ))
    }
}

fn remove_open_child_directory(
    parent: &File,
    path: &Path,
    directory: &File,
    expected: &PrivateObjectId,
) -> io::Result<()> {
    if &private_object_id(directory)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "retained private directory changed before deletion",
        ));
    }
    #[cfg(unix)]
    {
        verify_open_child_directory(parent, path, directory, expected)?;
        unix_private::remove_child_directory(parent, path)
    }
    #[cfg(windows)]
    {
        let _ = (parent, path);
        windows_acl::delete_open_file(directory)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exact private directory deletion is unsupported on this platform",
        ))
    }
}

fn remove_open_child_file(
    parent: &File,
    path: &Path,
    file: &File,
    expected_id: &PrivateObjectId,
) -> io::Result<()> {
    if &private_object_id(file)? != expected_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "retained private child changed before deletion",
        ));
    }
    #[cfg(windows)]
    {
        let _ = (parent, path);
        windows_acl::delete_open_file(file)
    }
    #[cfg(unix)]
    {
        let current = open_child_file(parent, path)?;
        if private_object_id(&current)? != *expected_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private child path changed before deletion",
            ));
        }
        unix_private::remove_child_file(parent, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exact private child deletion is unsupported on this platform",
        ))
    }
}

pub(crate) fn open_child_file(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_file(parent, path)
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            windows_acl::open_child_file(parent, path)
        }
        #[cfg(not(windows))]
        {
            let _ = parent;
            File::open(path)
        }
    }
}

fn open_child_file_read_append(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_file_read_append(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_private(parent, path, PrivateOpenMode::ReadWriteAppend)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private child append is unsupported on this platform",
        ))
    }
}

fn create_child_file_read_append(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::create_child_file_read_append(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::create_child_private(parent, path, PrivateOpenMode::ReadWriteAppend)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private child creation is unsupported on this platform",
        ))
    }
}

fn open_child_file_for_lock(parent: &File, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_child_file_for_lock(parent, path)
    }
    #[cfg(windows)]
    {
        windows_acl::open_child_private(parent, path, PrivateOpenMode::ReadWriteLock)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private child locks are unsupported on this platform",
        ))
    }
}

pub(crate) fn parent_child_names(parent: &File, parent_path: &Path) -> io::Result<Vec<OsString>> {
    #[cfg(unix)]
    {
        let _ = parent_path;
        unix_private::directory_names(parent)
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            windows_acl::child_names(parent, parent_path)
        }
        #[cfg(not(windows))]
        {
            let _ = parent;
            let mut names = fs::read_dir(parent_path)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<io::Result<Vec<_>>>()?;
            names.sort();
            Ok(names)
        }
    }
}

fn write_private_file_atomic_with_observer(
    path: &Path,
    bytes: &[u8],
    before_replace: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::write_atomic(path, bytes, before_replace)
    }
    #[cfg(windows)]
    {
        write_private_file_atomic_windows(path, bytes, before_replace)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, bytes, before_replace);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic private replacement is unsupported on this platform",
        ))
    }
}

#[cfg(windows)]
fn write_private_file_atomic_windows(
    path: &Path,
    bytes: &[u8],
    before_replace: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_sync = open_parent_lease_handle(parent)?;
    write_private_file_atomic_windows_in_parent(&parent_sync, path, bytes, before_replace)
}

#[cfg(windows)]
fn write_private_file_atomic_windows_in_parent(
    parent: &File,
    path: &Path,
    bytes: &[u8],
    before_replace: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let temporary = private_temporary(path);
    let mut file =
        windows_acl::create_child_private(parent, &temporary, PrivateOpenMode::CreateNew)?;
    let mut replaced = false;
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        parent.sync_all()?;
        before_replace(&temporary)?;
        windows_acl::replace_file(&file, parent, path)?;
        replaced = true;
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() && !replaced {
        #[cfg(windows)]
        let _ = windows_acl::delete_open_file(&file);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
    }
    drop(file);
    result
}

pub(crate) fn open_parent_sync_handle(parent: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_directory(parent)
    }
    #[cfg(windows)]
    {
        windows_acl::open_directory_for_sync(parent)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory synchronization is unsupported on this platform",
    ))
}

pub(crate) fn open_parent_lease_handle(parent: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_directory(parent)
    }
    #[cfg(windows)]
    {
        windows_acl::open_directory_for_lease(parent)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory leases are unsupported on this platform",
    ))
}

/// Retain a directory handle that prevents Windows pathname replacement and
/// verify that the directory is already private. Unix retains the exact
/// directory object; same-user namespace replacement remains outside the
/// documented trust boundary.
pub(crate) fn open_private_directory_lease(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    let directory = open_parent_lease_handle(path)?;
    #[cfg(windows)]
    let directory = windows_acl::open_directory_for_authority(path)?;
    #[cfg(unix)]
    unix_private::verify_private_directory(&directory)?;
    #[cfg(windows)]
    windows_acl::harden(&directory, true)?;
    Ok(directory)
}

fn validate_private_directory_handle(directory: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_private::verify_private_directory(directory)
    }
    #[cfg(windows)]
    {
        windows_acl::validate_private_directory(directory)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = directory;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directory validation is unsupported on this platform",
        ))
    }
}

/// Open an exact-private SQLite parent without requesting delete authority and
/// while sharing delete. Windows keeps a separate retained delete-capable
/// authority handle in the process registry; transient writer/progress opens
/// must coexist with that handle.
pub(crate) fn open_private_sqlite_parent(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        let directory = unix_private::open_directory(path)?;
        unix_private::verify_private_directory(&directory)?;
        Ok(directory)
    }
    #[cfg(windows)]
    {
        windows_acl::open_directory_for_sqlite(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private SQLite directories are unsupported on this platform",
        ))
    }
}

/// Verify an existing sensitive child through its already verified parent.
pub(crate) fn verify_private_child_file(parent: &File, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return unix_private::verify_child_private_file(parent, path);
    #[cfg(windows)]
    return windows_acl::verify_child_private_file_shared(parent, path);
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private child verification is unsupported on this platform",
    ))
}

/// Normalize a child proven absent before a trusted library created it while
/// `parent` stayed retained and exact-private. This narrow creation exception
/// must never be used to repair an object that existed before the operation.
pub(crate) fn secure_new_private_child_file(parent: &File, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return unix_private::secure_new_child_private_file(parent, path);
    #[cfg(windows)]
    return windows_acl::secure_new_child_private_file(parent, path);
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private child creation hardening is unsupported on this platform",
    ))
}

fn open_parent_identity_handle(parent: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        unix_private::open_directory(parent)
    }
    #[cfg(windows)]
    {
        windows_acl::open_directory_for_identity(parent)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory identity is unsupported on this platform",
    ))
}

/// Durably record directory-entry removals or renames for a private artifact.
pub fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    open_parent_sync_handle(parent)?.sync_all()
}

#[cfg(windows)]
fn private_temporary(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private");
    path.with_file_name(format!("{name}.{}.tmp", uuid::Uuid::new_v4()))
}

#[cfg(unix)]
mod unix_private {
    use super::{harden_private_file, validate_private_file};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::{CStr, CString, OsStr, OsString},
        fs::{self, File},
        io::{self, Write},
        os::unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, PermissionsExt},
            io::{AsRawFd, FromRawFd, RawFd},
        },
        path::{Path, PathBuf},
    };

    const ARTIFACT_NAME: &str = "artifact";
    const CLEANUP_DIRECTORY_NAME: &str = ".argos-private-cleanup";

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
    }

    fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(target_os = "macos")]
    mod macos_acl {
        use std::ffi::c_void;

        pub(super) const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
        pub(super) const ACL_FIRST_ENTRY: i32 = 0;

        unsafe extern "C" {
            pub(super) fn acl_init(count: i32) -> *mut c_void;
            pub(super) fn acl_free(object: *mut c_void) -> i32;
            pub(super) fn acl_set_fd_np(fd: i32, acl: *mut c_void, acl_type: i32) -> i32;
            pub(super) fn acl_get_fd_np(fd: i32, acl_type: i32) -> *mut c_void;
            pub(super) fn acl_get_entry(
                acl: *mut c_void,
                entry_id: i32,
                entry: *mut *mut c_void,
            ) -> i32;
        }
    }

    fn c_string(value: &OsStr, description: &str) -> io::Result<CString> {
        CString::new(value.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("private {description} contains a NUL character"),
            )
        })
    }

    fn last_error() -> io::Error {
        io::Error::last_os_error()
    }

    #[cfg(target_os = "macos")]
    pub(super) fn verify_no_extended_acl(file: &File) -> io::Result<()> {
        let acl =
            unsafe { macos_acl::acl_get_fd_np(file.as_raw_fd(), macos_acl::ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = last_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let mut entry = std::ptr::null_mut();
        let result =
            unsafe { macos_acl::acl_get_entry(acl, macos_acl::ACL_FIRST_ENTRY, &mut entry) };
        unsafe {
            macos_acl::acl_free(acl);
        }
        match result {
            0 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object retained an extended macOS ACL",
            )),
            _ => Err(last_error()),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn verify_no_extended_acl(file: &File) -> io::Result<()> {
        verify_absent_posix_acl_xattr(file, b"system.posix_acl_access\0", "access")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    pub(super) fn verify_no_extended_acl(_file: &File) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private ACL verification is unsupported on this Unix platform",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn verify_absent_posix_acl_xattr(
        file: &File,
        name: &'static [u8],
        description: &str,
    ) -> io::Result<()> {
        debug_assert_eq!(name.last(), Some(&0));
        let size = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr().cast(),
                std::ptr::null_mut(),
                0,
            )
        };
        if size >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private object retained a POSIX {description} ACL"),
            ));
        }
        let error = last_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENODATA) | Some(libc::EOPNOTSUPP)
        ) {
            Ok(())
        } else {
            Err(error)
        }
    }

    pub(super) fn verify_no_extended_directory_acl(directory: &File) -> io::Result<()> {
        verify_no_extended_acl(directory)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        verify_absent_posix_acl_xattr(directory, b"system.posix_acl_default\0", "default")?;
        Ok(())
    }

    fn verify_private_access(file: &File, expected_mode: u32, description: &str) -> io::Result<()> {
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != expected_mode
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private {description} must be owned by the current user with mode {expected_mode:o}"
                ),
            ));
        }
        verify_no_extended_acl(file)
    }

    pub(super) fn verify_private_file(file: &File) -> io::Result<()> {
        verify_private_access(file, 0o600, "file")
    }

    pub(super) fn verify_private_directory(directory: &File) -> io::Result<()> {
        verify_private_access(directory, 0o700, "directory")?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        verify_absent_posix_acl_xattr(directory, b"system.posix_acl_default\0", "default")?;
        Ok(())
    }

    fn open_child_file_for_verification(parent: &File, path: &Path) -> io::Result<File> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
            })?,
            "private child name",
        )?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file(&file)?;
        Ok(file)
    }

    pub(super) fn verify_child_private_file(parent: &File, path: &Path) -> io::Result<()> {
        verify_private_file(&open_child_file_for_verification(parent, path)?)
    }

    #[cfg(target_os = "macos")]
    fn remove_extended_acl_from_new(file: &File) -> io::Result<()> {
        let acl = unsafe { macos_acl::acl_init(1) };
        if acl.is_null() {
            return Err(last_error());
        }
        let result = unsafe {
            macos_acl::acl_set_fd_np(file.as_raw_fd(), acl, macos_acl::ACL_TYPE_EXTENDED)
        };
        unsafe {
            macos_acl::acl_free(acl);
        }
        if result == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn remove_extended_acl_from_new(file: &File) -> io::Result<()> {
        let result = unsafe {
            libc::fremovexattr(
                file.as_raw_fd(),
                b"system.posix_acl_access\0".as_ptr().cast(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = last_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENODATA) | Some(libc::EOPNOTSUPP)
        ) {
            Ok(())
        } else {
            Err(error)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    fn remove_extended_acl_from_new(_file: &File) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private ACL creation hardening is unsupported on this Unix platform",
        ))
    }

    pub(super) fn secure_new_child_private_file(parent: &File, path: &Path) -> io::Result<()> {
        let file = open_child_file_for_verification(parent, path)?;
        if verify_private_file(&file).is_ok() {
            return Ok(());
        }
        if file.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "new private child is not owned by the current user",
            ));
        }
        remove_extended_acl_from_new(&file)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        verify_private_file(&file)
    }

    pub(super) fn open_directory(path: &Path) -> io::Result<File> {
        let path = c_string(path.as_os_str(), "directory path")?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private parent must be a directory",
            ));
        }
        Ok(directory)
    }

    fn staging_prefix(path: &Path) -> io::Result<String> {
        let destination = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private file has no name")
        })?;
        let digest = Sha256::digest(destination.as_bytes());
        Ok(format!(".argos-private-{digest:x}-"))
    }

    fn create_staging_directory(
        parent: &File,
        prefix: &str,
    ) -> io::Result<(File, CString, PathBuf, FileIdentity)> {
        for _ in 0..16 {
            let name = format!("{prefix}{}", uuid::Uuid::new_v4());
            let c_name = c_string(OsStr::new(&name), "staging name")?;
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) };
            if created != 0 {
                let err = last_error();
                if err.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(err);
            }
            let descriptor = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(last_error());
            }
            let directory = unsafe { File::from_raw_fd(descriptor) };
            let metadata = directory.metadata()?;
            if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private staging directory was substituted during creation",
                ));
            }
            verify_private_directory(&directory)?;
            let metadata = directory.metadata()?;
            return Ok((
                directory,
                c_name,
                PathBuf::from(name),
                file_identity(&metadata),
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique private staging directory",
        ))
    }

    fn create_artifact(directory: RawFd) -> io::Result<File> {
        let name = c_string(OsStr::new(ARTIFACT_NAME), "artifact name")?;
        let descriptor = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file(&file)?;
        harden_private_file(&file)?;
        Ok(file)
    }

    fn unlink_artifact(directory: RawFd) {
        if let Ok(name) = c_string(OsStr::new(ARTIFACT_NAME), "artifact name") {
            unsafe {
                libc::unlinkat(directory, name.as_ptr(), 0);
            }
        }
    }

    #[allow(clippy::unnecessary_cast)] // libc field aliases differ across Unix targets.
    fn entry_identity(parent: RawFd, name: &CString) -> io::Result<FileIdentity> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::zeroed();
        if unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(last_error());
        }
        let status = unsafe { status.assume_init() };
        Ok(FileIdentity {
            device: status.st_dev as u64,
            inode: status.st_ino as u64,
        })
    }

    fn open_owned_directory(parent: RawFd, name: &CString) -> io::Result<File> {
        let descriptor = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory is not owned by the current user",
            ));
        }
        verify_private_directory(&directory)?;
        Ok(directory)
    }

    fn open_staging_directory(parent: RawFd, name: &CString) -> io::Result<File> {
        let directory = open_owned_directory(parent, name)?;
        verify_private_directory(&directory)?;
        Ok(directory)
    }

    fn open_cleanup_directory(parent: &File) -> io::Result<File> {
        let name = c_string(OsStr::new(CLEANUP_DIRECTORY_NAME), "cleanup directory name")?;
        let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
        if !created {
            let error = last_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
            return open_staging_directory(parent.as_raw_fd(), &name);
        }
        let directory = open_owned_directory(parent.as_raw_fd(), &name)?;
        verify_private_directory(&directory)?;
        Ok(directory)
    }

    fn remove_staging_entry_with_observer(
        parent: &File,
        name: &CString,
        expected: FileIdentity,
        before_move: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<bool> {
        let cleanup = open_cleanup_directory(parent)?;
        let quarantine = c_string(
            OsStr::new(&format!("entry-{}", uuid::Uuid::new_v4())),
            "cleanup entry name",
        )?;
        before_move()?;
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                name.as_ptr(),
                cleanup.as_raw_fd(),
                quarantine.as_ptr(),
            )
        } != 0
        {
            let error = last_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(error)
            };
        }
        cleanup.sync_all()?;
        parent.sync_all()?;
        if entry_identity(cleanup.as_raw_fd(), &quarantine)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private staging directory changed before cleanup",
            ));
        }
        if unsafe { libc::unlinkat(cleanup.as_raw_fd(), quarantine.as_ptr(), libc::AT_REMOVEDIR) }
            != 0
        {
            return Err(last_error());
        }
        cleanup.sync_all()?;
        Ok(true)
    }

    fn remove_staging_entry(
        parent: &File,
        name: &CString,
        expected: FileIdentity,
    ) -> io::Result<bool> {
        remove_staging_entry_with_observer(parent, name, expected, || Ok(()))
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    struct DirectoryStream(*mut libc::DIR);

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "dragonfly"))]
    fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__errno_location() }
    }

    #[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
    fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__errno() }
    }

    #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
    fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__error() }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub(super) fn directory_names(directory: &File) -> io::Result<Vec<OsString>> {
        // `dup` shares the directory stream offset with later enumerations
        // through this retained handle. Open `.` relative to the pinned
        // directory so every pass starts at the first entry.
        let dot = c_string(OsStr::new("."), "directory entry")?;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            unsafe {
                libc::close(descriptor);
            }
            return Err(last_error());
        }
        let stream = DirectoryStream(stream);
        let mut names = Vec::new();
        loop {
            unsafe {
                *errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = last_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error);
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        names.sort();
        Ok(names)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    pub(super) fn directory_names(_directory: &File) -> io::Result<Vec<OsString>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private staging enumeration is unsupported on this Unix target",
        ))
    }

    #[cfg(test)]
    fn open_staged_artifact(directory: RawFd) -> io::Result<Option<File>> {
        let artifact = c_string(OsStr::new(ARTIFACT_NAME), "artifact name")?;
        let descriptor = unsafe {
            libc::openat(
                directory,
                artifact.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            let err = last_error();
            return if err.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(err)
            };
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        validate_private_file(&file)?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staged private artifact is not owner-only",
            ));
        }
        verify_no_extended_acl(&file)?;
        Ok(Some(file))
    }

    #[cfg(test)]
    fn cleanup_candidate(parent: &File, name: &OsStr, staging: File) -> io::Result<bool> {
        let name = c_string(name, "staging name")?;
        let staging_identity = file_identity(&staging.metadata()?);
        if let Some(artifact_file) = open_staged_artifact(staging.as_raw_fd())? {
            let artifact = c_string(OsStr::new(ARTIFACT_NAME), "artifact name")?;
            let expected = file_identity(&artifact_file.metadata()?);
            if entry_identity(staging.as_raw_fd(), &artifact)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "staged private artifact changed before cleanup",
                ));
            }
            if unsafe { libc::unlinkat(staging.as_raw_fd(), artifact.as_ptr(), 0) } != 0 {
                return Err(last_error());
            }
            staging.sync_all()?;
        }
        drop(staging);
        remove_staging_entry(parent, &name, staging_identity)
    }

    #[cfg(test)]
    pub(super) fn cleanup_staging(
        path: &Path,
        minimum_age: Option<std::time::Duration>,
    ) -> io::Result<bool> {
        cleanup_staging_with_observer(path, minimum_age, || Ok(()))
    }

    #[cfg(test)]
    fn cleanup_staging_with_observer(
        path: &Path,
        minimum_age: Option<std::time::Duration>,
        after_parent_open: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<bool> {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = open_directory(parent_path)?;
        after_parent_open()?;
        cleanup_staging_in_parent(&parent, path, minimum_age)
    }

    #[cfg(test)]
    fn cleanup_staging_in_parent(
        parent: &File,
        path: &Path,
        minimum_age: Option<std::time::Duration>,
    ) -> io::Result<bool> {
        let prefix = staging_prefix(path)?;
        let now = std::time::SystemTime::now();
        let mut removed = false;
        let mut errors = Vec::new();
        for name in directory_names(parent)? {
            let Some(name_text) = name.to_str() else {
                continue;
            };
            let Some(id) = name_text.strip_prefix(&prefix) else {
                continue;
            };
            if uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            let candidate_name = c_string(&name, "staging name")?;
            let candidate = match open_staging_directory(parent.as_raw_fd(), &candidate_name) {
                Ok(candidate) => candidate,
                Err(error) => {
                    errors.push(format!("{}: {error}", name.to_string_lossy()));
                    continue;
                }
            };
            let old_enough = match minimum_age {
                None => true,
                Some(minimum) => match candidate
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .and_then(|modified| {
                        now.duration_since(modified)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    }) {
                    Ok(age) => age >= minimum,
                    Err(error) => {
                        errors.push(format!("{}: {error}", name.to_string_lossy()));
                        continue;
                    }
                },
            };
            if !old_enough {
                continue;
            }
            match cleanup_candidate(parent, &name, candidate) {
                Ok(candidate_removed) => removed |= candidate_removed,
                Err(error) => errors.push(format!("{}: {error}", name.to_string_lossy())),
            }
        }
        if removed {
            if let Err(error) = parent.sync_all() {
                errors.push(format!("syncing private staging parent: {error}"));
            }
        }
        if !errors.is_empty() {
            return Err(io::Error::other(format!(
                "private staging cleanup was incomplete: {}",
                errors.join("; ")
            )));
        }
        Ok(removed)
    }

    pub(super) fn open_child_directory_for_mutation(
        parent: &File,
        path: &Path,
    ) -> io::Result<File> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private directory has no name")
            })?,
            "private directory name",
        )?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory is not owned by the current user",
            ));
        }
        Ok(directory)
    }

    fn open_recursive_entry(parent: &File, name: &OsStr) -> io::Result<(File, bool, FileIdentity)> {
        let name = c_string(name, "private directory entry")?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let entry = unsafe { File::from_raw_fd(descriptor) };
        let metadata = entry.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory entry is not owned by the current user",
            ));
        }
        let is_directory = metadata.is_dir();
        if !is_directory && !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private recursive deletion refuses symlinks and special files",
            ));
        }
        if is_directory {
            verify_private_directory(&entry)?;
        } else {
            verify_private_file(&entry)?;
        }
        let identity = file_identity(&metadata);
        if entry_identity(parent.as_raw_fd(), &name)? != identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory entry changed while it was opened",
            ));
        }
        Ok((entry, is_directory, identity))
    }

    pub(super) fn remove_open_directory_contents(directory: &File) -> io::Result<()> {
        let names = directory_names(directory)?;
        for name in names {
            let c_name = c_string(&name, "private directory entry")?;
            let (entry, is_directory, expected) = open_recursive_entry(directory, &name)?;
            if is_directory {
                remove_open_directory_contents(&entry)?;
                entry.sync_all()?;
            }
            if entry_identity(directory.as_raw_fd(), &c_name)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private directory entry changed before deletion",
                ));
            }
            let flags = if is_directory { libc::AT_REMOVEDIR } else { 0 };
            if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name.as_ptr(), flags) } != 0 {
                return Err(last_error());
            }
            directory.sync_all()?;
        }
        if !directory_names(directory)?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "private directory changed during recursive deletion",
            ));
        }
        Ok(())
    }

    pub(super) fn rename_child_directory_noreplace(
        parent: &File,
        from: &Path,
        to: &Path,
    ) -> io::Result<()> {
        let from = c_string(
            from.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private source has no name")
            })?,
            "private source name",
        )?;
        let to = c_string(
            to.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private destination has no name",
                )
            })?,
            "private destination name",
        )?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let result = unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_vendor = "apple")]
        let result = unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        let result = {
            match entry_identity(parent.as_raw_fd(), &to) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "private destination already exists",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            unsafe {
                libc::renameat(
                    parent.as_raw_fd(),
                    from.as_ptr(),
                    parent.as_raw_fd(),
                    to.as_ptr(),
                )
            }
        };
        if result == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    pub(super) fn remove_child_directory(parent: &File, path: &Path) -> io::Result<()> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private directory has no name")
            })?,
            "private directory name",
        )?;
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    pub(super) fn remove_child_file(parent: &File, path: &Path) -> io::Result<()> {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
        })?;
        let name = c_string(name, "private child name")?;
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    pub(super) fn rename_child_file(parent: &File, from: &Path, to: &Path) -> io::Result<()> {
        let from = c_string(
            from.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private source has no name")
            })?,
            "private source name",
        )?;
        let to = c_string(
            to.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private destination has no name",
                )
            })?,
            "private destination name",
        )?;
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    pub(super) fn open_child_file(parent: &File, path: &Path) -> io::Result<File> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
            })?,
            "private child name",
        )?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file(&file)?;
        verify_private_file(&file)?;
        Ok(file)
    }

    pub(super) fn open_child_file_read_append(parent: &File, path: &Path) -> io::Result<File> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
            })?,
            "private child name",
        )?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_APPEND
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file(&file)?;
        harden_private_file(&file)?;
        Ok(file)
    }

    pub(super) fn create_child_file_read_append(parent: &File, path: &Path) -> io::Result<File> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
            })?,
            "private child name",
        )?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_APPEND
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        if let Err(error) = validate_private_file(&file).and_then(|_| harden_private_file(&file)) {
            if let Ok(metadata) = file.metadata() {
                let expected = file_identity(&metadata);
                if entry_identity(parent.as_raw_fd(), &name).is_ok_and(|actual| actual == expected)
                {
                    unsafe {
                        libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
                    }
                }
            }
            return Err(error);
        }
        Ok(file)
    }

    pub(super) fn open_child_file_for_lock(parent: &File, path: &Path) -> io::Result<File> {
        let name = c_string(
            path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
            })?,
            "private child name",
        )?;
        let mut created = true;
        let mut descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 && last_error().kind() == io::ErrorKind::AlreadyExists {
            created = false;
            descriptor = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
        }
        if descriptor < 0 {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        if let Err(error) = validate_private_file(&file).and_then(|_| harden_private_file(&file)) {
            if created {
                if let Ok(metadata) = file.metadata() {
                    let expected = file_identity(&metadata);
                    if entry_identity(parent.as_raw_fd(), &name)
                        .is_ok_and(|actual| actual == expected)
                    {
                        unsafe {
                            libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
                        }
                    }
                }
            }
            return Err(error);
        }
        Ok(file)
    }

    pub(super) fn write_atomic(
        path: &Path,
        bytes: &[u8],
        before_replace: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = open_directory(parent_path)?;
        write_atomic_in_parent(&parent, path, bytes, before_replace)
    }

    pub(super) fn write_atomic_in_parent(
        parent: &File,
        path: &Path,
        bytes: &[u8],
        before_replace: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let destination = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private file has no name")
        })?;
        let destination = c_string(destination, "destination name")?;
        let artifact = c_string(OsStr::new(ARTIFACT_NAME), "artifact name")?;
        parent.sync_all()?;
        let prefix = staging_prefix(path)?;
        let (staging, staging_name, staging_relative, staging_identity) =
            create_staging_directory(parent, &prefix)?;
        let exposed = parent_path.join(staging_relative);
        let mut file = match create_artifact(staging.as_raw_fd()) {
            Ok(file) => file,
            Err(err) => {
                let _ = remove_staging_entry(parent, &staging_name, staging_identity);
                return Err(err);
            }
        };
        let mut replaced = false;
        let result = (|| {
            file.write_all(bytes)?;
            file.flush()?;
            file.sync_all()?;
            staging.sync_all()?;
            before_replace(&exposed)?;
            if unsafe {
                libc::renameat(
                    staging.as_raw_fd(),
                    artifact.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                )
            } != 0
            {
                return Err(last_error());
            }
            replaced = true;
            staging.sync_all()?;
            parent.sync_all()
        })();
        if result.is_err() && !replaced {
            unlink_artifact(staging.as_raw_fd());
        }
        drop(file);
        drop(staging);
        let _ = remove_staging_entry(parent, &staging_name, staging_identity);
        result
    }

    #[cfg(test)]
    pub(super) fn abandon_staged_write(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = open_directory(parent_path)?;
        let prefix = staging_prefix(path)?;
        let (staging, _, relative, _) = create_staging_directory(&parent, &prefix)?;
        let mut artifact = create_artifact(staging.as_raw_fd())?;
        artifact.write_all(bytes)?;
        artifact.sync_all()?;
        staging.sync_all()?;
        Ok(parent_path.join(relative))
    }

    #[cfg(test)]
    mod race_tests {
        use super::*;
        use std::{cell::RefCell, os::unix::fs::MetadataExt};

        #[test]
        fn final_cleanup_never_unlinks_an_object_swapped_after_identity_check() {
            let tmp = tempfile::tempdir().unwrap();
            let parent = open_directory(tmp.path()).unwrap();
            let name = c_string(OsStr::new("stage"), "staging name").unwrap();
            fs::create_dir(tmp.path().join("stage")).unwrap();
            fs::set_permissions(tmp.path().join("stage"), fs::Permissions::from_mode(0o700))
                .unwrap();
            let staging = open_staging_directory(parent.as_raw_fd(), &name).unwrap();
            let expected = file_identity(&staging.metadata().unwrap());
            let moved = tmp.path().join("moved-stage");
            let decoy_handle = RefCell::new(None);

            let error = remove_staging_entry_with_observer(&parent, &name, expected, || {
                fs::rename(tmp.path().join("stage"), &moved)?;
                fs::create_dir(tmp.path().join("stage"))?;
                fs::set_permissions(tmp.path().join("stage"), fs::Permissions::from_mode(0o700))?;
                *decoy_handle.borrow_mut() = Some(open_directory(&tmp.path().join("stage"))?);
                Ok(())
            })
            .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(moved.is_dir());
            assert!(
                decoy_handle
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .nlink()
                    > 0,
                "the substituted directory was deleted"
            );
        }

        #[test]
        fn cleanup_enumerates_the_pinned_parent_after_a_path_swap() {
            let tmp = tempfile::tempdir().unwrap();
            let parent_path = tmp.path().join("parent");
            fs::create_dir(&parent_path).unwrap();
            let checkpoint = parent_path.join("wallet.checkpoint");
            let staging = abandon_staged_write(&checkpoint, b"spend-capable").unwrap();
            let staging_name = staging.file_name().unwrap().to_owned();
            let moved_parent = tmp.path().join("moved-parent");

            assert!(cleanup_staging_with_observer(
                &checkpoint,
                Some(std::time::Duration::ZERO),
                || {
                    fs::rename(&parent_path, &moved_parent)?;
                    fs::create_dir(&parent_path)?;
                    Ok(())
                },
            )
            .unwrap());
            assert!(!moved_parent.join(staging_name).exists());
        }

        #[test]
        fn cleanup_continues_after_a_hostile_candidate() {
            let tmp = tempfile::tempdir().unwrap();
            let checkpoint = tmp.path().join("wallet.checkpoint");
            let first = abandon_staged_write(&checkpoint, b"first").unwrap();
            let second = abandon_staged_write(&checkpoint, b"second").unwrap();
            let (hostile, removable) = if first.file_name() < second.file_name() {
                (first, second)
            } else {
                (second, first)
            };
            fs::set_permissions(&hostile, fs::Permissions::from_mode(0o777)).unwrap();

            assert!(cleanup_staging(&checkpoint, Some(std::time::Duration::ZERO)).is_err());
            assert!(hostile.exists());
            assert!(
                !removable.exists(),
                "one hostile candidate prevented cleanup of another secret"
            );
        }

        #[test]
        fn cleanup_directory_collision_is_never_hardened_in_place() {
            let tmp = tempfile::tempdir().unwrap();
            let collision = tmp.path().join(CLEANUP_DIRECTORY_NAME);
            fs::create_dir(&collision).unwrap();
            fs::set_permissions(&collision, fs::Permissions::from_mode(0o750)).unwrap();
            fs::write(collision.join("owner-data"), b"must survive").unwrap();
            let parent = open_directory(tmp.path()).unwrap();

            let error = open_cleanup_directory(&parent).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(collision.metadata().unwrap().mode() & 0o777, 0o750);
            assert_eq!(
                fs::read(collision.join("owner-data")).unwrap(),
                b"must survive"
            );
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn cleanup_directory_collision_keeps_its_existing_acl() {
            use std::process::Command;

            let tmp = tempfile::tempdir().unwrap();
            let collision = tmp.path().join(CLEANUP_DIRECTORY_NAME);
            fs::create_dir(&collision).unwrap();
            fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
            let parent = open_directory(tmp.path()).unwrap();
            let name =
                c_string(OsStr::new(CLEANUP_DIRECTORY_NAME), "cleanup directory name").unwrap();
            let collision_handle = open_owned_directory(parent.as_raw_fd(), &name).unwrap();
            assert!(Command::new("chmod")
                .arg("+a")
                .arg("everyone allow read,search,list")
                .arg(&collision)
                .status()
                .unwrap()
                .success());
            assert!(verify_no_extended_acl(&collision_handle).is_err());

            assert!(open_cleanup_directory(&parent).is_err());
            assert!(
                verify_no_extended_acl(&collision_handle).is_err(),
                "collision ACL was changed before cleanup failed"
            );
        }
    }
}

#[cfg(windows)]
mod windows_lineage {
    use super::{
        LineageRecordKind, WindowsArtifactRootAuthorityRecord, WindowsLineageAuthorityRecord,
    };
    use sha2::{Digest as _, Sha256};
    use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt as _, ptr, slice};
    use windows_sys::Win32::{
        Foundation::{
            LocalFree, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
        },
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
        System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegFlushKey, RegOpenKeyExW,
            RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
            KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY, REG_OPTION_NON_VOLATILE,
        },
    };
    use zeroize::{Zeroize as _, Zeroizing};

    const PRIVATE_ROOT_ENTROPY: &[u8] = b"argos/private-root-lineage/dpapi/v1";
    const PRIVATE_SQLITE_ENTROPY: &[u8] = b"argos/private-sqlite-lineage/dpapi/v1";
    const PRIVATE_ARTIFACT_ROOT_ENTROPY: &[u8] = b"argos/private-artifact-root/dpapi/v1";
    const CLEANUP_MARKER_ENTROPY: &[u8] = b"argos/workspace-cleanup-marker/dpapi/v1";
    const REGISTRY_AUTHORITY_ENTROPY: &[u8] = b"argos/private-lineage-registry/dpapi/v1";
    const REGISTRY_KEY: &str = "Software\\Argos\\WalletRescue\\PrivateRootAuthority\\v1";
    const ARTIFACT_REGISTRY_AUTHORITY_ENTROPY: &[u8] =
        b"argos/private-artifact-authority/registry/dpapi/v1";
    const ARTIFACT_REGISTRY_KEY: &str =
        "Software\\Argos\\WalletRescue\\PrivateArtifactAuthority\\v1";
    const MAX_REGISTRY_AUTHORITY_BYTES: u32 = 64 * 1024;

    struct LocalBlob {
        blob: CRYPT_INTEGER_BLOB,
        secret: bool,
    }

    impl LocalBlob {
        fn new(secret: bool) -> Self {
            Self {
                blob: CRYPT_INTEGER_BLOB {
                    cbData: 0,
                    pbData: ptr::null_mut(),
                },
                secret,
            }
        }

        fn to_vec(&self) -> io::Result<Vec<u8>> {
            if self.blob.cbData == 0 {
                return Ok(Vec::new());
            }
            if self.blob.pbData.is_null() {
                return Err(io::Error::other("DPAPI returned a null output buffer"));
            }
            Ok(unsafe {
                slice::from_raw_parts(self.blob.pbData, self.blob.cbData as usize).to_vec()
            })
        }
    }

    impl Drop for LocalBlob {
        fn drop(&mut self) {
            if self.blob.pbData.is_null() {
                return;
            }
            if self.secret && self.blob.cbData != 0 {
                unsafe {
                    slice::from_raw_parts_mut(self.blob.pbData, self.blob.cbData as usize)
                        .zeroize();
                }
            }
            unsafe {
                LocalFree(self.blob.pbData.cast());
            }
        }
    }

    fn entropy(kind: LineageRecordKind) -> &'static [u8] {
        match kind {
            LineageRecordKind::Root => PRIVATE_ROOT_ENTROPY,
            LineageRecordKind::Sqlite => PRIVATE_SQLITE_ENTROPY,
            LineageRecordKind::ArtifactRoot => PRIVATE_ARTIFACT_ROOT_ENTROPY,
            LineageRecordKind::CleanupMarker => CLEANUP_MARKER_ENTROPY,
        }
    }

    fn registry_entropy(context_hash: &[u8; 32]) -> Vec<u8> {
        let mut entropy = REGISTRY_AUTHORITY_ENTROPY.to_vec();
        entropy.extend_from_slice(context_hash);
        entropy
    }

    fn artifact_registry_entropy(context_hash: &[u8; 32]) -> Vec<u8> {
        let mut entropy = ARTIFACT_REGISTRY_AUTHORITY_ENTROPY.to_vec();
        entropy.extend_from_slice(context_hash);
        entropy
    }

    fn input_blob(bytes: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "DPAPI input is too large")
            })?,
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    fn protect_with_entropy(plaintext: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
        let input = input_blob(plaintext)?;
        let entropy = input_blob(entropy)?;
        let mut output = LocalBlob::new(false);
        if unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.blob,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        output.to_vec()
    }

    pub(super) fn protect(kind: LineageRecordKind, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        protect_with_entropy(plaintext, entropy(kind))
    }

    fn unprotect_with_entropy(ciphertext: &[u8], entropy: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let input = input_blob(ciphertext)?;
        let entropy = input_blob(entropy)?;
        let mut output = LocalBlob::new(true);
        if unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.blob,
            )
        } == 0
        {
            return Err(super::invalid_lineage(format!(
                "Windows DPAPI rejected private lineage authority: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Zeroizing::new(output.to_vec()?))
    }

    pub(super) fn unprotect(
        kind: LineageRecordKind,
        ciphertext: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        unprotect_with_entropy(ciphertext, entropy(kind))
    }

    struct RegKey(HKEY);

    impl Drop for RegKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    pub(super) fn context_hash(context: &[u8]) -> [u8; 32] {
        Sha256::digest(context).into()
    }

    fn value_name(context_hash: &[u8; 32]) -> String {
        let mut name = String::from("w-");
        for byte in context_hash {
            use std::fmt::Write as _;
            write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
        }
        name
    }

    fn artifact_value_name(context_hash: &[u8; 32]) -> String {
        let mut name = String::from("a-");
        for byte in context_hash {
            use std::fmt::Write as _;
            write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
        }
        name
    }

    pub(super) fn mutex_name(context_hash: &[u8; 32]) -> String {
        format!(
            "Global\\ArgosWalletRescue-Lineage-{}",
            value_name(context_hash)
        )
    }

    pub(super) fn lock(context_hash: &[u8; 32]) -> io::Result<super::windows_acl::LineageMutex> {
        let name = mutex_name(context_hash);
        super::windows_acl::acquire_lineage_mutex(&name)
    }

    pub(super) fn artifact_lock(
        context_hash: &[u8; 32],
    ) -> io::Result<super::windows_acl::LineageMutex> {
        let name = format!(
            "Global\\ArgosWalletRescue-PrivateArtifact-{}",
            artifact_value_name(context_hash)
        );
        super::windows_acl::acquire_lineage_mutex(&name)
    }

    fn open_registry_key(write: bool) -> io::Result<Option<RegKey>> {
        open_registry_key_at(REGISTRY_KEY, write)
    }

    fn open_registry_key_at(path: &str, write: bool) -> io::Result<Option<RegKey>> {
        let subkey = wide(path);
        let mut key = ptr::null_mut();
        let access = KEY_QUERY_VALUE | KEY_WOW64_64KEY | if write { KEY_SET_VALUE } else { 0 };
        let status = if write {
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    access,
                    ptr::null(),
                    &mut key,
                    ptr::null_mut(),
                )
            }
        } else {
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut key) }
        };
        if !write && matches!(status, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Some(RegKey(key)))
    }

    pub(super) fn read_artifact_authority(
        context_hash: &[u8; 32],
    ) -> io::Result<Option<WindowsArtifactRootAuthorityRecord>> {
        let Some(key) = open_registry_key_at(ARTIFACT_REGISTRY_KEY, false)? else {
            return Ok(None);
        };
        let name = wide(&artifact_value_name(context_hash));
        let mut value_type = 0;
        let mut length = 0;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut value_type,
                ptr::null_mut(),
                &mut length,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if value_type != REG_BINARY || length == 0 || length > MAX_REGISTRY_AUTHORITY_BYTES {
            return Err(super::invalid_lineage(
                "Windows artifact-root registry authority has an invalid type or size",
            ));
        }
        for _ in 0..2 {
            let mut bytes = vec![0u8; length as usize];
            let mut actual = length;
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    ptr::null(),
                    &mut value_type,
                    bytes.as_mut_ptr(),
                    &mut actual,
                )
            };
            if status == ERROR_MORE_DATA && actual <= MAX_REGISTRY_AUTHORITY_BYTES {
                length = actual;
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            bytes.truncate(actual as usize);
            let entropy = artifact_registry_entropy(context_hash);
            let plaintext = unprotect_with_entropy(&bytes, &entropy)?;
            let record = serde_json::from_slice(&plaintext).map_err(|error| {
                super::invalid_lineage(format!(
                    "Windows artifact-root registry authority is invalid: {error}"
                ))
            })?;
            return Ok(Some(record));
        }
        Err(super::invalid_lineage(
            "Windows artifact-root registry authority changed during bounded read",
        ))
    }

    pub(super) fn write_artifact_authority(
        context_hash: &[u8; 32],
        record: &WindowsArtifactRootAuthorityRecord,
    ) -> io::Result<()> {
        let mut plaintext = serde_json::to_vec(record).map_err(io::Error::other)?;
        let entropy = artifact_registry_entropy(context_hash);
        let protected = protect_with_entropy(&plaintext, &entropy);
        plaintext.zeroize();
        let protected = protected?;
        let key = open_registry_key_at(ARTIFACT_REGISTRY_KEY, true)?
            .expect("write opens or creates the artifact registry key");
        let name = wide(&artifact_value_name(context_hash));
        let length = u32::try_from(protected.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact authority is too large",
            )
        })?;
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_BINARY,
                protected.as_ptr(),
                length,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let status = unsafe { RegFlushKey(key.0) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub(super) fn read_authority(
        context_hash: &[u8; 32],
    ) -> io::Result<Option<WindowsLineageAuthorityRecord>> {
        let Some(key) = open_registry_key(false)? else {
            return Ok(None);
        };
        let name = wide(&value_name(context_hash));
        let mut value_type = 0;
        let mut length = 0;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut value_type,
                ptr::null_mut(),
                &mut length,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if value_type != REG_BINARY || length == 0 || length > MAX_REGISTRY_AUTHORITY_BYTES {
            return Err(super::invalid_lineage(
                "Windows private lineage registry authority has an invalid type or size",
            ));
        }
        for _ in 0..2 {
            let mut bytes = vec![0u8; length as usize];
            let mut actual = length;
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    ptr::null(),
                    &mut value_type,
                    bytes.as_mut_ptr(),
                    &mut actual,
                )
            };
            if status == ERROR_MORE_DATA && actual <= MAX_REGISTRY_AUTHORITY_BYTES {
                length = actual;
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            bytes.truncate(actual as usize);
            let entropy = registry_entropy(context_hash);
            let plaintext = unprotect_with_entropy(&bytes, &entropy)?;
            let record = serde_json::from_slice(&plaintext).map_err(|error| {
                super::invalid_lineage(format!(
                    "Windows private lineage registry authority is invalid: {error}"
                ))
            })?;
            return Ok(Some(record));
        }
        Err(super::invalid_lineage(
            "Windows private lineage registry authority changed during bounded read",
        ))
    }

    pub(super) fn write_authority(
        context_hash: &[u8; 32],
        record: &WindowsLineageAuthorityRecord,
    ) -> io::Result<()> {
        let mut plaintext = serde_json::to_vec(record).map_err(io::Error::other)?;
        let entropy = registry_entropy(context_hash);
        let protected = protect_with_entropy(&plaintext, &entropy);
        plaintext.zeroize();
        let protected = protected?;
        let key = open_registry_key(true)?.expect("write opens or creates the registry key");
        let name = wide(&value_name(context_hash));
        let length = u32::try_from(protected.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry authority is too large",
            )
        })?;
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_BINARY,
                protected.as_ptr(),
                length,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let status = unsafe { RegFlushKey(key.0) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub(super) fn delete_authority(context_hash: &[u8; 32]) -> io::Result<()> {
        let key = open_registry_key(true)?.expect("write opens or creates the registry key");
        let name = wide(&value_name(context_hash));
        let status = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let status = unsafe { RegFlushKey(key.0) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows_acl {
    use std::{
        ffi::OsStr,
        io, mem,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Path, PathBuf},
        ptr,
    };

    use windows_sys::Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FileDirectoryInformation, NtCreateFile, NtQueryDirectoryFile, FILE_CREATE,
            FILE_DIRECTORY_FILE, FILE_DIRECTORY_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        },
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL,
            GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
            STATUS_BUFFER_OVERFLOW, STATUS_NO_MORE_FILES, UNICODE_STRING, WAIT_ABANDONED,
            WAIT_OBJECT_0,
        },
        Security::{
            AclSizeInformation, AddAccessAllowedAceEx,
            Authorization::{
                GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
            },
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetLengthSid,
            GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
            InitializeSecurityDescriptor, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
            SetSecurityDescriptorOwner, TokenUser, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL,
            ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
            SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, FileDispositionInfo, FileRenameInfo,
            GetFileInformationByHandle, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            CREATE_NEW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS,
            FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_DISPOSITION_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
            SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
        },
        System::Threading::{
            CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
            INFINITE,
        },
    };

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) struct LineageMutex(OwnedHandle);

    impl Drop for LineageMutex {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.0 .0);
            }
        }
    }

    pub(super) fn acquire_lineage_mutex(name: &str) -> io::Result<LineageMutex> {
        let mut wide_name = OsStr::new(name).encode_wide().collect::<Vec<_>>();
        if wide_name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private lineage mutex name contains a NUL character",
            ));
        }
        wide_name.push(0);
        let security = PrivateSecurity::new(false)?;
        let handle = unsafe { CreateMutexW(security.attributes(), 0, wide_name.as_ptr()) };
        if handle.is_null() {
            return Err(last_error());
        }
        let handle = OwnedHandle(handle);
        verify_handle(
            handle.0,
            SE_KERNEL_OBJECT,
            false,
            security.user_sid,
            security.system_sid,
        )?;
        match unsafe { WaitForSingleObject(handle.0, INFINITE) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(LineageMutex(handle)),
            _ => Err(last_error()),
        }
    }

    fn last_error() -> io::Error {
        io::Error::last_os_error()
    }

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut encoded = OsStr::new(path).encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private path contains a NUL character",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn nt_error(status: i32) -> io::Error {
        let code = unsafe { windows_sys::Win32::Foundation::RtlNtStatusToDosError(status) };
        io::Error::from_raw_os_error(code as i32)
    }

    fn relative_name(path: &Path) -> io::Result<Vec<u16>> {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private child has no name")
        })?;
        let encoded = name.encode_wide().collect::<Vec<_>>();
        if encoded.is_empty() || encoded.len() > usize::from(u16::MAX) / 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private child name is empty or too long",
            ));
        }
        Ok(encoded)
    }

    fn nt_open_child(
        parent: &std::fs::File,
        path: &Path,
        desired_access: u32,
        share_access: u32,
        disposition: u32,
        security_descriptor: *const core::ffi::c_void,
    ) -> io::Result<std::fs::File> {
        nt_open_child_with_options(
            parent,
            path,
            desired_access,
            share_access,
            disposition,
            security_descriptor,
            FILE_NON_DIRECTORY_FILE,
        )
    }

    fn nt_open_child_with_options(
        parent: &std::fs::File,
        path: &Path,
        desired_access: u32,
        share_access: u32,
        disposition: u32,
        security_descriptor: *const core::ffi::c_void,
        type_options: u32,
    ) -> io::Result<std::fs::File> {
        let mut name = relative_name(path)?;
        let unicode = UNICODE_STRING {
            Length: u16::try_from(name.len() * mem::size_of::<u16>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private child name is too long",
                )
            })?,
            MaximumLength: u16::try_from(name.len() * mem::size_of::<u16>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private child name is too long",
                )
            })?,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle() as HANDLE,
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: security_descriptor.cast(),
            SecurityQualityOfService: ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle = INVALID_HANDLE_VALUE;
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                share_access,
                disposition,
                type_options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status < 0 {
            return Err(nt_error(status));
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "NtCreateFile succeeded without returning a child handle",
            ));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }

    pub(super) fn open_child_file(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let file = nt_open_child(
            parent,
            path,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            ptr::null(),
        )?;
        validate_private_file(&file)?;
        PrivateSecurity::new(false)?.verify(&file)?;
        Ok(file)
    }

    pub(super) fn open_child_file_exclusive(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let file = nt_open_child(parent, path, FILE_GENERIC_READ, 0, FILE_OPEN, ptr::null())?;
        validate_private_file(&file)?;
        PrivateSecurity::new(false)?.verify(&file)?;
        Ok(file)
    }

    pub(super) fn open_child_file_for_identity(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let file = nt_open_child(
            parent,
            path,
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            ptr::null(),
        )?;
        validate_private_file(&file)?;
        PrivateSecurity::new(false)?.verify(&file)?;
        Ok(file)
    }

    pub(super) fn open_child_file_for_retained_authority(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let file = nt_open_child(
            parent,
            path,
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            ptr::null(),
        )?;
        validate_private_file(&file)?;
        PrivateSecurity::new(false)?.verify(&file)?;
        Ok(file)
    }

    pub(super) fn verify_child_private_file_shared(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<()> {
        drop(open_child_file_for_identity(parent, path)?);
        Ok(())
    }

    pub(super) fn secure_new_child_private_file(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<()> {
        let file = nt_open_child(
            parent,
            path,
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            ptr::null(),
        )?;
        validate_private_file(&file)?;
        let security = PrivateSecurity::new(false)?;
        if security.verify(&file).is_ok() {
            return Ok(());
        }
        secure_new_child_dacl(&file, &security)
    }

    pub(super) fn open_child_private(
        parent: &std::fs::File,
        path: &Path,
        mode: super::PrivateOpenMode,
    ) -> io::Result<std::fs::File> {
        open_or_create_child_private(parent, path, mode, false)
    }

    pub(super) fn create_child_private(
        parent: &std::fs::File,
        path: &Path,
        mode: super::PrivateOpenMode,
    ) -> io::Result<std::fs::File> {
        open_or_create_child_private(parent, path, mode, true)
    }

    pub(super) fn child_names(
        parent: &std::fs::File,
        _parent_path: &Path,
    ) -> io::Result<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        let mut restart = true;
        loop {
            let mut buffer = vec![0u64; 8192];
            let mut status_block = IO_STATUS_BLOCK::default();
            let status = unsafe {
                NtQueryDirectoryFile(
                    parent.as_raw_handle() as HANDLE,
                    ptr::null_mut(),
                    None,
                    ptr::null(),
                    &mut status_block,
                    buffer.as_mut_ptr().cast(),
                    u32::try_from(buffer.len() * mem::size_of::<u64>()).unwrap(),
                    FileDirectoryInformation,
                    false,
                    ptr::null(),
                    restart,
                )
            };
            if status == STATUS_NO_MORE_FILES {
                break;
            }
            if status < 0 && status != STATUS_BUFFER_OVERFLOW {
                return Err(nt_error(status));
            }
            let available = status_block.Information;
            if available == 0 {
                break;
            }
            let mut offset = 0usize;
            loop {
                if offset + mem::size_of::<FILE_DIRECTORY_INFORMATION>() > available {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Windows directory enumeration record",
                    ));
                }
                let entry = unsafe {
                    &*buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_DIRECTORY_INFORMATION>()
                };
                let units = usize::try_from(entry.FileNameLength).unwrap() / mem::size_of::<u16>();
                let value = unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), units) };
                if value != [b'.' as u16] && value != [b'.' as u16, b'.' as u16] {
                    names.push(std::ffi::OsString::from_wide(value));
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                offset = offset
                    .checked_add(entry.NextEntryOffset as usize)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "overflow in Windows directory enumeration",
                        )
                    })?;
                if offset >= available {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows directory enumeration escaped its buffer",
                    ));
                }
            }
            restart = false;
        }
        names.sort();
        Ok(names)
    }

    fn file_information(file: &std::fs::File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) }
            == 0
        {
            return Err(last_error());
        }
        Ok(information)
    }

    fn validate_recursive_entry(file: &std::fs::File) -> io::Result<bool> {
        let information = file_information(file)?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private recursive deletion refuses reparse points",
            ));
        }
        Ok(information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0)
    }

    pub(super) fn open_child_directory_for_mutation(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let directory = nt_open_child_with_options(
            parent,
            path,
            DELETE | FILE_GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            ptr::null(),
            FILE_DIRECTORY_FILE,
        )?;
        if !validate_recursive_entry(&directory)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private workspace entry is not a directory",
            ));
        }
        PrivateSecurity::new(true)?.verify(&directory)?;
        Ok(directory)
    }

    pub(super) fn open_child_directory_for_identity(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let directory = nt_open_child_with_options(
            parent,
            path,
            READ_CONTROL | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            ptr::null(),
            FILE_DIRECTORY_FILE,
        )?;
        if !validate_recursive_entry(&directory)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private workspace entry is not a directory",
            ));
        }
        PrivateSecurity::new(true)?.verify(&directory)?;
        Ok(directory)
    }

    fn open_recursive_entry(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<(std::fs::File, bool)> {
        let entry = nt_open_child_with_options(
            parent,
            path,
            DELETE | FILE_GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            ptr::null(),
            0,
        )?;
        let is_directory = validate_recursive_entry(&entry)?;
        PrivateSecurity::new(is_directory)?.verify(&entry)?;
        Ok((entry, is_directory))
    }

    fn reopen_recursive_entry_for_identity(
        parent: &std::fs::File,
        path: &Path,
        is_directory: bool,
    ) -> io::Result<std::fs::File> {
        let entry = nt_open_child_with_options(
            parent,
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            ptr::null(),
            if is_directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            },
        )?;
        if validate_recursive_entry(&entry)? != is_directory {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private directory entry type changed before deletion",
            ));
        }
        PrivateSecurity::new(is_directory)?.verify(&entry)?;
        Ok(entry)
    }

    pub(super) fn remove_open_directory_contents(directory: &std::fs::File) -> io::Result<()> {
        let names = child_names(directory, Path::new("."))?;
        for name in names {
            let path = PathBuf::from(&name);
            let (entry, is_directory) = open_recursive_entry(directory, &path)?;
            let expected = super::private_object_id(&entry)?;
            if is_directory {
                remove_open_directory_contents(&entry)?;
                entry.sync_all()?;
            }
            let current = reopen_recursive_entry_for_identity(directory, &path, is_directory)?;
            if super::private_object_id(&current)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private directory entry changed before deletion",
                ));
            }
            delete_open_file(&entry)?;
            drop(current);
            drop(entry);
            directory.sync_all()?;
        }
        if !child_names(directory, Path::new("."))?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "private directory changed during recursive deletion",
            ));
        }
        Ok(())
    }

    struct PrivateSecurity {
        _token_user: Vec<usize>,
        _system: Vec<usize>,
        _acl: Vec<usize>,
        descriptor: Box<SECURITY_DESCRIPTOR>,
        attributes: SECURITY_ATTRIBUTES,
        user_sid: PSID,
        system_sid: PSID,
        directory: bool,
    }

    impl PrivateSecurity {
        fn new(directory: bool) -> io::Result<Self> {
            unsafe {
                let (token_user, user_sid) = current_user_sid()?;
                let (system, system_sid) = local_system_sid()?;
                let flags = expected_flags(directory);
                let ace_base = mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>();
                let acl_len = mem::size_of::<ACL>()
                    + ace_base * 2
                    + GetLengthSid(user_sid) as usize
                    + GetLengthSid(system_sid) as usize;
                let mut acl = vec![0usize; acl_len.div_ceil(mem::size_of::<usize>())];
                let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
                if InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) == 0 {
                    return Err(last_error());
                }
                for sid in [user_sid, system_sid] {
                    if AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, FILE_ALL_ACCESS, sid)
                        == 0
                    {
                        return Err(last_error());
                    }
                }

                let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
                if InitializeSecurityDescriptor(
                    (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                ) == 0
                {
                    return Err(last_error());
                }
                if SetSecurityDescriptorDacl(
                    (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    1,
                    acl_ptr,
                    0,
                ) == 0
                    || SetSecurityDescriptorControl(
                        (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                        SE_DACL_PROTECTED,
                        SE_DACL_PROTECTED,
                    ) == 0
                    || SetSecurityDescriptorOwner(
                        (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                        user_sid,
                        0,
                    ) == 0
                {
                    return Err(last_error());
                }
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    bInheritHandle: 0,
                };
                Ok(Self {
                    _token_user: token_user,
                    _system: system,
                    _acl: acl,
                    descriptor,
                    attributes,
                    user_sid,
                    system_sid,
                    directory,
                })
            }
        }

        fn attributes(&self) -> *const SECURITY_ATTRIBUTES {
            &self.attributes
        }

        fn verify(&self, file: &std::fs::File) -> io::Result<()> {
            let _keep_descriptor_alive = &self.descriptor;
            verify(file, self.directory, self.user_sid, self.system_sid)
        }
    }

    unsafe fn current_user_sid() -> io::Result<(Vec<usize>, PSID)> {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error());
        }
        let token = OwnedHandle(token);
        let mut token_len = 0;
        let first = GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut token_len);
        if first != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        {
            return Err(last_error());
        }
        let mut token_buffer = vec![0usize; (token_len as usize).div_ceil(mem::size_of::<usize>())];
        if GetTokenInformation(
            token.0,
            TokenUser,
            token_buffer.as_mut_ptr().cast(),
            token_len,
            &mut token_len,
        ) == 0
        {
            return Err(last_error());
        }
        let user_sid = (*(token_buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        Ok((token_buffer, user_sid))
    }

    unsafe fn local_system_sid() -> io::Result<(Vec<usize>, PSID)> {
        let mut bytes =
            vec![0usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(mem::size_of::<usize>())];
        let mut len = SECURITY_MAX_SID_SIZE;
        let sid: PSID = bytes.as_mut_ptr().cast();
        if CreateWellKnownSid(WinLocalSystemSid, ptr::null_mut(), sid, &mut len) == 0 {
            return Err(last_error());
        }
        Ok((bytes, sid))
    }

    fn expected_flags(directory: bool) -> u32 {
        if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        }
    }

    pub(super) fn harden(file: &std::fs::File, directory: bool) -> io::Result<()> {
        let security = PrivateSecurity::new(directory)?;
        security.verify(file)
    }

    #[cfg(test)]
    pub(super) fn verify_for_expected_owner_test(
        file: &std::fs::File,
        directory: bool,
        expected_owner: PSID,
    ) -> io::Result<()> {
        let security = PrivateSecurity::new(directory)?;
        verify(file, directory, expected_owner, security.system_sid)
    }

    pub(super) fn require_current_owner_sid(owner_sid: PSID, user_sid: PSID) -> io::Result<()> {
        if owner_sid.is_null() || unsafe { EqualSid(owner_sid, user_sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object is not owned by the current user",
            ));
        }
        Ok(())
    }

    struct OwnedLocalDescriptor(*mut core::ffi::c_void);
    impl Drop for OwnedLocalDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    fn verify_owner(file: &std::fs::File, user_sid: PSID) -> io::Result<()> {
        unsafe {
            let mut owner = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let status = GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let _descriptor = OwnedLocalDescriptor(descriptor);
            require_current_owner_sid(owner, user_sid)
        }
    }

    pub(super) fn directory_owned_by_current_user(path: &Path) -> io::Result<bool> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        if !validate_recursive_entry(&directory)? {
            return Ok(false);
        }
        let security = PrivateSecurity::new(true)?;
        match verify_owner(&directory, security.user_sid) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn verify_publication_parent(directory: &std::fs::File) -> io::Result<()> {
        unsafe {
            let security = PrivateSecurity::new(true)?;
            let mut owner = ptr::null_mut();
            let mut dacl = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let status = GetSecurityInfo(
                directory.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let _descriptor = OwnedLocalDescriptor(descriptor);
            require_current_owner_sid(owner, security.user_sid)?;
            if dacl.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "workspace publication parent DACL is absent",
                ));
            }
            let mut info = ACL_SIZE_INFORMATION::default();
            if GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == 0
            {
                return Err(last_error());
            }
            let dangerous = FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_DELETE_CHILD
                | FILE_GENERIC_WRITE
                | GENERIC_WRITE
                | GENERIC_ALL
                | DELETE
                | WRITE_DAC
                | WRITE_OWNER;
            for index in 0..info.AceCount {
                let mut raw = ptr::null_mut();
                if GetAce(dacl, index, &mut raw) == 0 {
                    return Err(last_error());
                }
                let ace = &*(raw.cast::<ACCESS_ALLOWED_ACE>());
                if ace.Header.AceType == ACCESS_DENIED_ACE_TYPE {
                    continue;
                }
                if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "workspace publication parent contains an unsupported ACE type",
                    ));
                }
                let sid: PSID = (&ace.SidStart as *const u32).cast_mut().cast();
                if EqualSid(sid, security.user_sid) == 0
                    && EqualSid(sid, security.system_sid) == 0
                    && ace.Mask & dangerous != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "workspace publication parent grants create/delete authority to a non-owner",
                    ));
                }
            }
            Ok(())
        }
    }

    fn secure_new_child_dacl(file: &std::fs::File, security: &PrivateSecurity) -> io::Result<()> {
        // This mutation is permitted only for a child proven absent before a
        // trusted library created it under a retained exact-private parent.
        // Owner verification prevents the exception from taking over a
        // substituted foreign-owned object.
        verify_owner(file, security.user_sid)?;
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                security._acl.as_ptr().cast(),
                ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        security.verify(file)
    }

    fn verify(
        file: &std::fs::File,
        directory: bool,
        user_sid: PSID,
        system_sid: PSID,
    ) -> io::Result<()> {
        verify_handle(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            directory,
            user_sid,
            system_sid,
        )
    }

    fn verify_handle(
        handle: HANDLE,
        object_type: SE_OBJECT_TYPE,
        directory: bool,
        user_sid: PSID,
        system_sid: PSID,
    ) -> io::Result<()> {
        unsafe {
            let mut owner = ptr::null_mut();
            let mut dacl = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let status = GetSecurityInfo(
                handle,
                object_type,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let _descriptor = OwnedLocalDescriptor(descriptor);
            require_current_owner_sid(owner, user_sid)?;
            if dacl.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private DACL is absent",
                ));
            }
            let mut control = 0;
            let mut revision = 0;
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private DACL is not protected",
                ));
            }
            let mut info = ACL_SIZE_INFORMATION::default();
            if GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == 0
                || info.AceCount != 2
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private DACL must contain exactly two ACEs",
                ));
            }
            let mut saw_user = false;
            let mut saw_system = false;
            for index in 0..info.AceCount {
                let mut raw = ptr::null_mut();
                if GetAce(dacl, index, &mut raw) == 0 {
                    return Err(last_error());
                }
                let ace = &*(raw.cast::<ACCESS_ALLOWED_ACE>());
                let sid: PSID = (&ace.SidStart as *const u32).cast_mut().cast();
                if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || u32::from(ace.Header.AceFlags) != expected_flags(directory)
                    || ace.Mask != FILE_ALL_ACCESS
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private DACL contains an unexpected ACE",
                    ));
                }
                if EqualSid(sid, user_sid) != 0 {
                    if saw_user {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "duplicate owner ACE",
                        ));
                    }
                    saw_user = true;
                } else if EqualSid(sid, system_sid) != 0 {
                    if saw_system {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "duplicate LocalSystem ACE",
                        ));
                    }
                    saw_system = true;
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private DACL grants an unexpected principal",
                    ));
                }
            }
            if !saw_user || !saw_system {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private DACL is missing owner or LocalSystem",
                ));
            }
            Ok(())
        }
    }

    pub(super) fn create_file(
        path: &Path,
        mode: super::PrivateOpenMode,
    ) -> io::Result<std::fs::File> {
        create_file_with_observer(path, mode, |_| Ok(()))
    }

    fn open_or_create_child_private(
        parent: &std::fs::File,
        path: &Path,
        mode: super::PrivateOpenMode,
        create_only: bool,
    ) -> io::Result<std::fs::File> {
        let security = PrivateSecurity::new(false)?;
        let access = match mode {
            super::PrivateOpenMode::Append => FILE_APPEND_DATA,
            super::PrivateOpenMode::ReadWriteLock | super::PrivateOpenMode::ReadWriteAppend => {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE
            }
            super::PrivateOpenMode::Truncate | super::PrivateOpenMode::CreateNew => {
                FILE_GENERIC_WRITE
            }
        } | DELETE
            | READ_CONTROL;
        let share = if matches!(
            mode,
            super::PrivateOpenMode::ReadWriteLock | super::PrivateOpenMode::ReadWriteAppend
        ) {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        };
        let descriptor = security.attributes.lpSecurityDescriptor.cast_const();
        let (file, created) =
            match nt_open_child(parent, path, access, share, FILE_CREATE, descriptor) {
                Ok(file) => (file, true),
                Err(err)
                    if err.kind() == io::ErrorKind::AlreadyExists
                        && !create_only
                        && mode != super::PrivateOpenMode::CreateNew =>
                {
                    let exclusive = nt_open_child(parent, path, access, 0, FILE_OPEN, ptr::null())?;
                    validate_private_file(&exclusive)?;
                    security.verify(&exclusive)?;
                    if mode == super::PrivateOpenMode::ReadWriteLock {
                        drop(exclusive);
                        let shared =
                            nt_open_child(parent, path, access, share, FILE_OPEN, ptr::null())?;
                        security.verify(&shared)?;
                        (shared, false)
                    } else {
                        (exclusive, false)
                    }
                }
                Err(err) => return Err(err),
            };
        let secured = validate_private_file(&file).and_then(|_| {
            if created {
                security.verify(&file)
            } else {
                security.verify(&file)
            }
        });
        if let Err(err) = secured {
            if created {
                let _ = delete_open_file(&file);
            }
            return Err(err);
        }
        if mode == super::PrivateOpenMode::Truncate {
            file.set_len(0)?;
        }
        Ok(file)
    }

    pub(super) fn create_file_with_observer(
        path: &Path,
        mode: super::PrivateOpenMode,
        observer: impl FnOnce(&std::fs::File) -> io::Result<()>,
    ) -> io::Result<std::fs::File> {
        let security = PrivateSecurity::new(false)?;
        let path_buf = path.to_path_buf();
        let path = wide(path)?;
        let access = match mode {
            super::PrivateOpenMode::Append => FILE_APPEND_DATA,
            super::PrivateOpenMode::ReadWriteLock | super::PrivateOpenMode::ReadWriteAppend => {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE
            }
            super::PrivateOpenMode::Truncate | super::PrivateOpenMode::CreateNew => {
                FILE_GENERIC_WRITE
            }
        };
        let share = if matches!(
            mode,
            super::PrivateOpenMode::ReadWriteLock | super::PrivateOpenMode::ReadWriteAppend
        ) {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        };
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access | DELETE | READ_CONTROL,
                share,
                security.attributes(),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle) };
        if let Err(err) = observer(&file).and_then(|_| security.verify(&file)) {
            drop(file);
            let _ = std::fs::remove_file(path_buf);
            return Err(err);
        }
        Ok(file)
    }

    pub(super) fn open_existing_private_file(
        path: &Path,
        mode: super::PrivateOpenMode,
    ) -> io::Result<std::fs::File> {
        let mut exclusive_options = super::options_for(mode, false);
        exclusive_options.share_mode(0);
        let exclusive = exclusive_options.open(path)?;
        validate_private_file(&exclusive)?;
        let security = PrivateSecurity::new(false)?;
        security.verify(&exclusive)?;
        if mode == super::PrivateOpenMode::ReadWriteLock {
            drop(exclusive);
            let shared = super::options_for(mode, false).open(path)?;
            validate_private_file(&shared)?;
            security.verify(&shared)?;
            Ok(shared)
        } else {
            Ok(exclusive)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        volume: u32,
        index_high: u32,
        index_low: u32,
    }

    pub(super) fn validate_private_file(file: &std::fs::File) -> io::Result<()> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) }
            == 0
        {
            return Err(last_error());
        }
        if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file must be a regular non-reparse file",
            ));
        }
        Ok(())
    }

    pub(super) fn replace_file(
        file: &std::fs::File,
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<()> {
        move_file(file, parent, path, true)
    }

    pub(super) fn move_file(
        file: &std::fs::File,
        parent: &std::fs::File,
        path: &Path,
        replace: bool,
    ) -> io::Result<()> {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private file has no name")
        })?;
        let name = name.encode_wide().collect::<Vec<_>>();
        let header_len = mem::offset_of!(FILE_RENAME_INFO, FileName);
        let buffer_len = header_len + name.len() * mem::size_of::<u16>();
        let mut buffer = vec![0usize; buffer_len.div_ceil(mem::size_of::<usize>())];
        let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*rename).Anonymous.ReplaceIfExists = replace;
            (*rename).RootDirectory = parent.as_raw_handle() as HANDLE;
            (*rename).FileNameLength = (name.len() * mem::size_of::<u16>()) as u32;
            ptr::copy_nonoverlapping(name.as_ptr(), (*rename).FileName.as_mut_ptr(), name.len());
            if SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileRenameInfo,
                rename.cast(),
                buffer_len as u32,
            ) == 0
            {
                return Err(last_error());
            }
        }
        Ok(())
    }

    pub(super) fn delete_open_file(file: &std::fs::File) -> io::Result<()> {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn open_child_for_mutation(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let file = nt_open_child(
            parent,
            path,
            DELETE | FILE_GENERIC_READ | READ_CONTROL,
            0,
            FILE_OPEN,
            ptr::null(),
        )?;
        validate_private_file(&file)?;
        PrivateSecurity::new(false)?.verify(&file)?;
        Ok(file)
    }

    pub(super) fn open_file_for_identity(path: &Path) -> io::Result<std::fs::File> {
        let path = wide(path)?;
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle) };
        validate_private_file(&file)?;
        Ok(file)
    }

    fn directory_identity(directory: &std::fs::File) -> io::Result<FileIdentity> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe {
            GetFileInformationByHandle(directory.as_raw_handle() as HANDLE, &mut information)
        } == 0
        {
            return Err(last_error());
        }
        if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory must be a non-reparse directory",
            ));
        }
        Ok(FileIdentity {
            volume: information.dwVolumeSerialNumber,
            index_high: information.nFileIndexHigh,
            index_low: information.nFileIndexLow,
        })
    }

    fn ensure_same_directory(
        expected: FileIdentity,
        actual: &std::fs::File,
        description: &str,
    ) -> io::Result<()> {
        if directory_identity(actual)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private directory {description} changed during creation"),
            ));
        }
        Ok(())
    }

    fn create_directory(path: &Path) -> io::Result<()> {
        create_directory_with_observer(path, |_| Ok(()))
    }

    pub(super) fn create_directory_with_observer(
        path: &Path,
        observer: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory has no parent",
            )
        })?;
        let pinned_parent = open_directory(parent, READ_CONTROL)?;
        let parent_identity = directory_identity(&pinned_parent)?;
        let security = PrivateSecurity::new(true)?;
        let path_wide = wide(path)?;
        if unsafe { CreateDirectoryW(path_wide.as_ptr(), security.attributes()) } == 0 {
            return Err(last_error());
        }
        observer(path)?;
        let current_parent = open_directory(parent, READ_CONTROL)?;
        ensure_same_directory(parent_identity, &current_parent, "parent")?;
        let directory = open_directory(path, READ_CONTROL)?;
        let directory_identity = directory_identity(&directory)?;
        security.verify(&directory)?;
        let current_directory = open_directory(path, READ_CONTROL)?;
        ensure_same_directory(directory_identity, &current_directory, "path")
    }

    pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
        create_dir_all_with_before_create(path, |_| Ok(()))
    }

    pub(super) fn create_dir_all_with_before_create(
        path: &Path,
        mut before_create: impl FnMut(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut missing = Vec::<PathBuf>::new();
        let mut cursor = path.as_path();
        while !cursor.exists() {
            missing.push(cursor.to_path_buf());
            cursor = cursor.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private directory has no existing ancestor",
                )
            })?;
        }
        if missing.is_empty() {
            return harden_directory(&path);
        }
        for directory in missing.iter().rev() {
            before_create(directory)?;
            // A path that appears after the missing-component walk belongs
            // to a racing process. Never accept or harden that object: its
            // creator can retain a handle with broader rights.
            create_directory(directory)?;
        }
        Ok(())
    }

    fn open_directory(path: &Path, access: u32) -> io::Result<std::fs::File> {
        open_directory_with_share(
            path,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
    }

    fn open_directory_with_share(
        path: &Path,
        access: u32,
        share: u32,
    ) -> io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(access | FILE_READ_ATTRIBUTES)
            .share_mode(share)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        directory_identity(&directory)?;
        Ok(directory)
    }

    pub(super) fn harden_directory(path: &Path) -> io::Result<()> {
        let directory = open_directory_with_share(path, READ_CONTROL, 0)?;
        harden(&directory, true)
    }

    #[cfg(test)]
    pub(super) fn verify_current(file: &std::fs::File, directory: bool) -> io::Result<()> {
        PrivateSecurity::new(directory)?.verify(file)
    }

    pub(super) fn validate_private_directory(file: &std::fs::File) -> io::Result<()> {
        directory_identity(file)?;
        PrivateSecurity::new(true)?.verify(file)
    }

    pub(super) fn open_directory_for_sync(path: &Path) -> io::Result<std::fs::File> {
        open_directory(path, FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL)
    }

    pub(super) fn open_directory_for_authority(path: &Path) -> io::Result<std::fs::File> {
        let directory = open_directory_with_share(
            path,
            READ_CONTROL | FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        harden(&directory, true)?;
        Ok(directory)
    }

    pub(super) fn open_directory_for_cleanup_authority(path: &Path) -> io::Result<std::fs::File> {
        let directory = open_directory_with_share(
            path,
            DELETE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        harden(&directory, true)?;
        Ok(directory)
    }

    pub(super) fn open_directory_for_sqlite(path: &Path) -> io::Result<std::fs::File> {
        let directory = open_directory_with_share(
            path,
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        harden(&directory, true)?;
        Ok(directory)
    }

    pub(super) fn open_directory_for_lease(path: &Path) -> io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        directory_identity(&directory)?;
        Ok(directory)
    }

    pub(super) fn open_directory_for_identity(path: &Path) -> io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        directory_identity(&directory)?;
        Ok(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_absent_artifact_data_dir_is_published_as_authenticated_container() {
        let outer = tempfile::tempdir().unwrap();
        let data_dir = outer.path().join("artifact-data");

        let first = ensure_private_artifact_container(&data_dir).unwrap();
        let first_id = first.id.clone();
        assert_eq!(first.context, private_artifact_container_purpose());
        assert!(data_dir.join(PRIVATE_ARTIFACT_ROOT_MARKER).is_file());
        drop(first);

        let reopened = ensure_private_artifact_container(&data_dir).unwrap();
        assert_eq!(reopened.id, first_id);
        assert!(reopened.child_names().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_authenticated_container_and_root_reopen_and_enumerate() {
        let outer = tempfile::tempdir().unwrap();
        let data_dir = outer.path().join("artifact-data");
        let container = ensure_private_artifact_container(&data_dir).unwrap();
        assert!(container
            .child_names()
            .unwrap()
            .iter()
            .any(|name| { name == std::ffi::OsStr::new(PRIVATE_ARTIFACT_ROOT_MARKER) }));
        drop(container);

        let purpose = b"mainnet\0native-windows-enumeration";
        let root = private_artifact_root_path(&data_dir, purpose);
        ensure_private_artifact_root(&root, purpose).unwrap();
        let names = private_data_dir_child_names(&data_dir).unwrap();
        assert!(names.iter().any(|name| root.file_name() == Some(name)));

        let reopened = ensure_private_artifact_root(&root, purpose).unwrap();
        reopened.verify_current().unwrap();
        assert_eq!(
            reopened.child_names().unwrap().len(),
            PRIVATE_ARTIFACT_BOUND_NAMES.len() + 1
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_artifact_container_recovers_pending_before_publish() {
        let outer = tempfile::tempdir().unwrap();
        let data_dir = outer.path().join("artifact-data");
        let context =
            private_artifact_root_context(&data_dir, private_artifact_container_purpose()).unwrap();
        prepare_windows_artifact_root_creation(&context).unwrap();
        assert!(!data_dir.exists());

        let container = ensure_private_artifact_container(&data_dir).unwrap();

        container.verify_current().unwrap();
        assert!(data_dir.join(PRIVATE_ARTIFACT_ROOT_MARKER).is_file());
    }

    #[cfg(windows)]
    #[test]
    fn windows_artifact_container_registry_prevents_rollback_or_remint() {
        let outer = tempfile::tempdir().unwrap();
        let data_dir = outer.path().join("artifact-data");
        let parked = outer.path().join("parked-artifact-data");
        ensure_private_artifact_container(&data_dir).unwrap();
        fs::rename(&data_dir, &parked).unwrap();

        let missing = ensure_private_artifact_container(&data_dir)
            .expect_err("an Active container authority must forbid reminting a missing path");
        assert_eq!(missing.kind(), io::ErrorKind::PermissionDenied);

        create_private_dir_all(&data_dir).unwrap();
        let decoy = ensure_private_artifact_container(&data_dir)
            .expect_err("an unmarked decoy cannot supersede the Active container");
        assert_eq!(decoy.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir(&data_dir).unwrap();
        fs::rename(&parked, &data_dir).unwrap();
        ensure_private_artifact_container(&data_dir).unwrap();
    }

    #[test]
    fn preexisting_unmarked_artifact_data_dir_is_refused_unchanged() {
        let outer = tempfile::tempdir().unwrap();
        let data_dir = outer.path().join("existing-data");
        create_private_dir_all(&data_dir).unwrap();
        write_private_file(
            &data_dir.join("sprout-sweep-deadbeefdeadbeef.journal"),
            b"historical broadcast state",
        )
        .unwrap();

        let error = ensure_private_artifact_container(&data_dir)
            .expect_err("an unproven existing data dir must require reconciliation");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("explicitly reconcile"));
        assert_eq!(
            fs::read(data_dir.join("sprout-sweep-deadbeefdeadbeef.journal")).unwrap(),
            b"historical broadcast state"
        );
        assert!(!data_dir.join(PRIVATE_ARTIFACT_ROOT_MARKER).exists());
    }

    #[test]
    fn fresh_private_artifact_root_binds_every_precreated_authority_object() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer
            .path()
            .join("artifact-data/.argos-private-artifacts-mainnet-deadbeef");
        let context = b"mainnet\0full-fingerprint\0artifact-root";

        let first = ensure_private_artifact_root(&root, context).unwrap();
        let ids = first.bound_object_ids().clone();
        drop(first);
        let reopened = ensure_private_artifact_root(&root, context).unwrap();

        assert_eq!(reopened.bound_object_ids(), &ids);
        for name in PRIVATE_ARTIFACT_BOUND_NAMES {
            assert!(root.join(name).is_file(), "missing {name}");
        }
    }

    #[test]
    fn unmarked_private_artifact_root_is_refused_without_mutation() {
        let outer = tempfile::tempdir().unwrap();
        let data_dir = outer.path().join("artifact-data");
        ensure_private_artifact_container(&data_dir).unwrap();
        let root = data_dir.join(".argos-private-artifacts-mainnet-deadbeef");
        create_private_dir_all(&root).unwrap();
        write_private_file(&root.join("checkpoint"), b"legacy secret").unwrap();

        let error = ensure_private_artifact_root(&root, b"context")
            .expect_err("an unmarked existing artifact root must remain legacy");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(root.join("checkpoint")).unwrap(), b"legacy secret");
        assert!(!root.join(PRIVATE_ARTIFACT_ROOT_MARKER).exists());
    }

    #[test]
    fn private_artifact_root_context_replay_is_refused() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer
            .path()
            .join("artifact-data/.argos-private-artifacts-mainnet-deadbeef");
        ensure_private_artifact_root(&root, b"mainnet\0fingerprint-a").unwrap();

        let error = ensure_private_artifact_root(&root, b"testnet\0fingerprint-a")
            .expect_err("network context replay must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn existing_artifact_acquire_rejects_root_swapped_after_marker_read() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = b"mainnet\0full-fingerprint";
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), purpose);
        let parked = outer.path().join("parked-private-root");
        let artifact = root.join("checkpoint");
        ensure_private_artifact_root(&root, purpose).unwrap();

        let error = PrivateArtifactAccess::acquire_existing_with_observer(
            &root,
            PrivateArtifactDomain::Checkpoint,
            &artifact,
            || {
                fs::rename(&root, &parked)?;
                ensure_private_artifact_root(&root, purpose)?;
                Ok(())
            },
        )
        .expect_err("marker observation must remain bound to the retained root identity");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn artifact_root_name_is_opaque_and_context_specific() {
        let data_dir = Path::new("wallet-data");
        let fingerprint = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mainnet = [b"mainnet\0".as_slice(), fingerprint].concat();
        let testnet = [b"testnet\0".as_slice(), fingerprint].concat();

        let first = private_artifact_root_path(data_dir, &mainnet);
        let same = private_artifact_root_path(data_dir, &mainnet);
        let other = private_artifact_root_path(data_dir, &testnet);

        assert_eq!(first, same);
        assert_ne!(first, other);
        let name = first.file_name().unwrap().to_string_lossy();
        assert!(!name.contains("0123456789abcdef"));
        assert!(!name.contains("mainnet"));
    }

    #[test]
    fn artifact_authority_is_durable_before_the_first_secret_byte() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer
            .path()
            .join("artifact-data/.argos-private-artifacts-mainnet-deadbeef");
        let artifact = root.join("journal");
        let purpose = b"mainnet\0full-fingerprint";
        let access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Journal,
            &artifact,
        )
        .unwrap();

        access
            .append_child_if_unchanged_with_observer(None, b"secret\n", |file, expected| {
                assert_eq!(file.metadata()?.len(), 0);
                assert_eq!(private_object_id(file)?, *expected);
                let state = access.current_state()?.expect("authority is recorded");
                assert!(matches!(state, PrivateArtifactState::Created { object, .. } if object == *expected));
                Ok(())
            })
            .unwrap();

        assert_eq!(fs::read(&artifact).unwrap(), b"secret\n");
        assert!(matches!(
            access.current_state().unwrap(),
            Some(PrivateArtifactState::Active { .. })
        ));
    }

    #[test]
    fn existing_unbound_artifact_is_refused_without_read_or_mutation() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer
            .path()
            .join("artifact-data/.argos-private-artifacts-mainnet-deadbeef");
        let purpose = b"mainnet\0full-fingerprint";
        ensure_private_artifact_root(&root, purpose).unwrap();
        let artifact = root.join("journal");
        write_private_file(&artifact, b"unbound legacy secret").unwrap();

        let access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Journal,
            &artifact,
        )
        .unwrap();
        let error = access
            .read_child_version()
            .expect_err("unbound exact-private child must be refused");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&artifact).unwrap(), b"unbound legacy secret");
    }

    #[test]
    fn artifact_replacement_records_exact_generation_before_publication() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = b"mainnet\0full-fingerprint";
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), purpose);
        let artifact = root.join("checkpoint");
        let access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Checkpoint,
            &artifact,
        )
        .unwrap();

        access.replace_child(b"first checkpoint").unwrap();
        let first = access.current_state().unwrap().unwrap();
        access.replace_child(b"second checkpoint").unwrap();
        let second = access.current_state().unwrap().unwrap();

        assert_eq!(fs::read(&artifact).unwrap(), b"second checkpoint");
        assert!(matches!((&first, &second),
            (PrivateArtifactState::Active { generation: a, object: ao },
             PrivateArtifactState::Active { generation: b, object: bo })
            if a != b && ao != bo));
    }

    #[cfg(windows)]
    #[test]
    fn windows_artifact_domains_cold_verify_before_retaining_their_bound_locks() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = format!("mainnet\0{}", uuid::Uuid::new_v4()).into_bytes();
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), &purpose);
        let checkpoint = root.join("checkpoint");
        let journal = root.join("journal");

        for _ in 0..2 {
            let checkpoint_access = PrivateArtifactAccess::acquire(
                &root,
                &purpose,
                PrivateArtifactDomain::Checkpoint,
                &checkpoint,
            )
            .unwrap();
            drop(checkpoint_access);
            let journal_access = PrivateArtifactAccess::acquire(
                &root,
                &purpose,
                PrivateArtifactDomain::Journal,
                &journal,
            )
            .unwrap();
            drop(journal_access);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_artifact_registry_prevents_root_rollback_or_remint() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = format!("mainnet\0{}", uuid::Uuid::new_v4()).into_bytes();
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), &purpose);
        let parked = outer.path().join("parked-root");
        ensure_private_artifact_root(&root, &purpose).unwrap();
        fs::rename(&root, &parked).unwrap();

        let error = ensure_private_artifact_root(&root, &purpose)
            .expect_err("an Active off-filesystem authority must forbid reminting a missing root");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        create_private_dir_all(&root).unwrap();
        let error = ensure_private_artifact_root(&root, &purpose)
            .expect_err("an unmarked replacement cannot supersede the Active exact root");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir(&root).unwrap();
        fs::rename(&parked, &root).unwrap();
        ensure_private_artifact_root(&root, &purpose).unwrap();
    }

    #[test]
    fn artifact_authority_stays_bounded_across_full_chain_checkpoint_cadence() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = b"mainnet\0full-fingerprint";
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), purpose);
        let artifact = root.join("checkpoint");
        let access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Checkpoint,
            &artifact,
        )
        .unwrap();

        for index in 0..10_000u64 {
            let mut generation = [0u8; 16];
            generation[..8].copy_from_slice(&index.to_le_bytes());
            access
                .append_state(PrivateArtifactState::Pending {
                    generation,
                    candidate: format!("candidate-{index}"),
                    old: None,
                })
                .unwrap();
        }

        assert_eq!(fs::metadata(&access.authority).unwrap().len(), 8192);
        assert_eq!(access.current_record().unwrap().unwrap().sequence, 9_999);
    }

    #[test]
    fn torn_newest_authority_slot_falls_back_to_previous_durable_state() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = b"mainnet\0full-fingerprint";
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), purpose);
        let artifact = root.join("checkpoint");
        let access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Checkpoint,
            &artifact,
        )
        .unwrap();
        access
            .append_state(PrivateArtifactState::Pending {
                generation: [1; 16],
                candidate: "first".into(),
                old: None,
            })
            .unwrap();
        access
            .append_state(PrivateArtifactState::Pending {
                generation: [2; 16],
                candidate: "second".into(),
                old: None,
            })
            .unwrap();

        let newest = access.current_record().unwrap().unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&access.authority)
            .unwrap();
        let corrupt_at = newest.sequence % 2 * 4096 + 4095;
        file.seek(SeekFrom::Start(corrupt_at)).unwrap();
        file.write_all(&[0x7f]).unwrap();
        file.sync_all().unwrap();

        let recovered = access.current_record().unwrap().unwrap();
        assert_eq!(recovered.sequence + 1, newest.sequence);
        assert!(matches!(
            recovered.state,
            PrivateArtifactState::Pending { generation, .. } if generation == [1; 16]
        ));
    }

    #[test]
    fn checkpoint_retirement_restores_after_restart_and_retires_before_reuse() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = b"mainnet\0full-fingerprint";
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), purpose);
        let artifact = root.join("checkpoint");
        let access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Checkpoint,
            &artifact,
        )
        .unwrap();
        access.replace_child(b"reviewed checkpoint").unwrap();
        let (_, expected) = access.active_generation_and_id().unwrap();

        let first_cleanup = uuid::Uuid::new_v4().into_bytes();
        let (quarantine, file, _) = access
            .quarantine_active_child(&expected, first_cleanup)
            .unwrap();
        drop(file);
        assert!(!artifact.exists());
        assert!(quarantine.exists());
        drop(access);

        let resumed = PrivateArtifactAccess::acquire_existing(
            &root,
            PrivateArtifactDomain::Checkpoint,
            &artifact,
        )
        .unwrap();
        assert!(resumed.restore_retiring_child().unwrap());
        assert_eq!(fs::read(&artifact).unwrap(), b"reviewed checkpoint");

        let second_cleanup = uuid::Uuid::new_v4().into_bytes();
        let (quarantine, file, _) = resumed
            .quarantine_active_child(&expected, second_cleanup)
            .unwrap();
        resumed
            .finish_retiring_child(&quarantine, &file, &expected, second_cleanup)
            .unwrap();
        assert!(!artifact.exists());
        assert!(!quarantine.exists());
        assert!(matches!(
            resumed.current_state().unwrap(),
            Some(PrivateArtifactState::Retired { cleanup_id, .. }) if cleanup_id == second_cleanup
        ));

        resumed.replace_child(b"new explicit scan").unwrap();
        assert_eq!(fs::read(&artifact).unwrap(), b"new explicit scan");
    }

    #[test]
    fn retained_root_allows_checkpoint_and_journal_domains_to_coexist() {
        let outer = tempfile::tempdir().unwrap();
        let purpose = b"mainnet\0full-fingerprint";
        let root = private_artifact_root_path(&outer.path().join("artifact-data"), purpose);
        let checkpoint = root.join("checkpoint");
        let journal = root.join("journal");
        let checkpoint_access = PrivateArtifactAccess::acquire(
            &root,
            purpose,
            PrivateArtifactDomain::Checkpoint,
            &checkpoint,
        )
        .unwrap();
        checkpoint_access.replace_child(b"first").unwrap();

        let journal_access = PrivateArtifactAccess::acquire_from_retained_root(
            checkpoint_access.root_lease(),
            checkpoint_access.namespace(),
            purpose,
            PrivateArtifactDomain::Journal,
            &journal,
        )
        .unwrap();
        journal_access
            .append_child_if_unchanged(None, b"header\n")
            .unwrap();
        checkpoint_access.replace_child(b"second").unwrap();

        assert_eq!(fs::read(checkpoint).unwrap(), b"second");
        assert_eq!(fs::read(journal).unwrap(), b"header\n");
    }

    #[test]
    fn stale_probe_scan_ignores_noncanonical_candidate_names() {
        let temp = tempfile::tempdir().unwrap();
        for name in [
            "zeck_probe_not-a-uuid",
            "zeck_probe_550E8400-E29B-41D4-A716-446655440000",
            "zeck_probe_550e8400e29b41d4a716446655440000",
        ] {
            let candidate = temp.path().join(name);
            fs::create_dir(&candidate).unwrap();
            fs::write(candidate.join("must-survive"), b"untrusted candidate").unwrap();
        }

        cleanup_stale_ephemeral_probes(temp.path()).unwrap();

        for entry in fs::read_dir(temp.path()).unwrap() {
            assert!(entry.unwrap().path().join("must-survive").exists());
        }
    }

    #[test]
    fn existing_private_root_without_lineage_is_refused_without_minting_a_marker() {
        let outer = tempfile::tempdir().unwrap();
        let private_root = outer.path().join("workspace-private-root");
        let leaf = private_root.join("birthday-1/scope");
        let database = leaf.join("wallet.sqlite");
        create_private_dir_all(&leaf).unwrap();

        let error = ensure_private_workspace_lineage(&private_root, &leaf, &database)
            .expect_err("an existing unmarked private root must be treated as legacy");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!private_root.join(PRIVATE_ROOT_LINEAGE_FILE_NAME).exists());
        assert!(leaf.is_dir());
    }

    #[test]
    fn fresh_private_root_gets_create_only_identity_lineage() {
        let outer = tempfile::tempdir().unwrap();
        let private_root = outer.path().join("workspace-private-root");
        let leaf = private_root.join("birthday-1/scope");
        let database = leaf.join("wallet.sqlite");

        ensure_private_workspace_lineage(&private_root, &leaf, &database).unwrap();
        let first = verify_private_workspace_lineage(&private_root).unwrap();
        ensure_private_workspace_lineage(&private_root, &leaf, &database).unwrap();
        let second = verify_private_workspace_lineage(&private_root).unwrap();

        assert_eq!(first.id(), second.id());
        assert!(leaf.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn first_append_after_parent_swap_never_writes_the_replacement_namespace() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("active");
        fs::create_dir(&parent).unwrap();
        let child = parent.join("journal");
        let lock = parent.join("journal.lock");
        let lease = NamespaceLease::acquire(&parent, &lock).unwrap();
        let displaced = root.path().join("displaced");

        let error = lease
            .append_child_if_unchanged_with_observer(&child, None, b"secret\n", || {
                fs::rename(&parent, &displaced)?;
                fs::create_dir(&parent)?;
                fs::write(parent.join("sentinel"), b"replacement tree")?;
                Ok(())
            })
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read(parent.join("sentinel")).unwrap(),
            b"replacement tree"
        );
        assert!(!child.exists());
        assert_eq!(fs::read(displaced.join("journal")).unwrap(), b"secret\n");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_directory_rename_refuses_parent_replacement_without_touching_either_tree() {
        let outer = tempfile::tempdir().unwrap();
        let parent = outer.path().join("network");
        fs::create_dir(&parent).unwrap();
        let workspace = parent.join("wallet");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("secret"), b"original").unwrap();
        let lease = NamespaceLease::acquire(&parent, &parent.join("cleanup.lock")).unwrap();
        let detached = outer.path().join("detached-network");
        let tombstone = parent.join("wallet.deleting-test");

        let error = lease
            .rename_child_directory_with_observer(&workspace, &tombstone, || {
                fs::rename(&parent, &detached)?;
                fs::create_dir(&parent)?;
                fs::create_dir(parent.join("wallet"))?;
                fs::write(parent.join("wallet/sentinel"), b"replacement")?;
                Ok(())
            })
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read(parent.join("wallet/sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            fs::read(detached.join("wallet/secret")).unwrap(),
            b"original"
        );
        assert!(!parent.join("wallet.deleting-test").exists());
        assert!(!detached.join("wallet.deleting-test").exists());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_directory_rename_refuses_substituted_child() {
        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("wallet");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("secret"), b"original").unwrap();
        let displaced = parent.path().join("displaced-wallet");
        let tombstone = parent.path().join("wallet.deleting-test");
        let lease =
            NamespaceLease::acquire(parent.path(), &parent.path().join("cleanup.lock")).unwrap();

        let error = lease
            .rename_child_directory_with_observer(&workspace, &tombstone, || {
                fs::rename(&workspace, &displaced)?;
                fs::create_dir(&workspace)?;
                fs::write(workspace.join("sentinel"), b"replacement")?;
                Ok(())
            })
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read(workspace.join("sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(fs::read(displaced.join("secret")).unwrap(), b"original");
        assert!(!tombstone.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recursive_workspace_removal_refuses_substituted_tombstone() {
        let parent = tempfile::tempdir().unwrap();
        let tombstone = parent.path().join("wallet.deleting-test");
        create_private_dir_all(&tombstone).unwrap();
        fs::create_dir(tombstone.join("nested")).unwrap();
        fs::write(tombstone.join("nested/secret"), b"original").unwrap();
        let displaced = parent.path().join("displaced-tombstone");
        let lease =
            NamespaceLease::acquire(parent.path(), &parent.path().join("cleanup.lock")).unwrap();

        let error = lease
            .remove_child_directory_all_with_observer(&tombstone, || {
                fs::rename(&tombstone, &displaced)?;
                fs::create_dir(&tombstone)?;
                fs::write(tombstone.join("sentinel"), b"replacement")?;
                Ok(())
            })
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read(tombstone.join("sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            fs::read(displaced.join("nested/secret")).unwrap(),
            b"original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_workspace_removal_refuses_symlinks_without_touching_the_target() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let tombstone = parent.path().join("wallet.deleting-test");
        fs::create_dir(&tombstone).unwrap();
        let target = parent.path().join("outside-secret");
        fs::write(&target, b"must survive").unwrap();
        symlink(&target, tombstone.join("link")).unwrap();
        let lease =
            NamespaceLease::acquire(parent.path(), &parent.path().join("cleanup.lock")).unwrap();

        let error = lease
            .remove_child_directory_all(&tombstone)
            .expect_err("recursive deletion must refuse symlinks");
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ) || error.kind() == io::ErrorKind::PermissionDenied,
            "{error}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"must survive");
        assert!(tombstone.join("link").exists());
    }

    #[test]
    fn recursive_workspace_removal_deletes_only_the_retained_tree() {
        let parent = tempfile::tempdir().unwrap();
        let tombstone = parent.path().join("wallet.deleting-test");
        create_private_dir_all(&tombstone.join("nested")).unwrap();
        write_private_file(&tombstone.join("nested/secret"), b"delete me").unwrap();
        let sibling = parent.path().join("sibling");
        fs::create_dir(&sibling).unwrap();
        fs::write(sibling.join("sentinel"), b"must survive").unwrap();
        let lease =
            NamespaceLease::acquire(parent.path(), &parent.path().join("cleanup.lock")).unwrap();

        lease.remove_child_directory_all(&tombstone).unwrap();

        assert!(!tombstone.exists());
        assert_eq!(fs::read(sibling.join("sentinel")).unwrap(), b"must survive");
    }

    #[cfg(windows)]
    #[test]
    fn windows_workspace_cleanup_uses_retained_directory_handles() {
        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("wallet");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join("nested")).unwrap();
        fs::write(workspace.join("nested/secret"), b"delete me").unwrap();
        let tombstone = parent.path().join("wallet.deleting-test");
        let lease =
            NamespaceLease::acquire(parent.path(), &parent.path().join("cleanup.lock")).unwrap();

        lease
            .rename_child_directory_with_observer(&workspace, &tombstone, || {
                assert!(fs::rename(&workspace, parent.path().join("stolen")).is_err());
                Ok(())
            })
            .unwrap();
        lease
            .remove_child_directory_all_with_observer(&tombstone, || {
                assert!(fs::rename(&tombstone, parent.path().join("stolen")).is_err());
                Ok(())
            })
            .unwrap();

        assert!(!workspace.exists());
        assert!(!tombstone.exists());
    }

    #[test]
    fn hardening_failure_occurs_before_truncate_or_write() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing-secret");
        fs::write(&path, b"must survive").unwrap();
        let err = open_private_file_with(&path, PrivateOpenMode::Truncate, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected ACL failure",
            ))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), b"must survive");
    }

    #[cfg(unix)]
    #[test]
    fn reused_private_file_refuses_a_symlink_before_truncate() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("wallet.dat");
        let link = tmp.path().join("report.json");
        fs::write(&target, b"must survive").unwrap();
        symlink(&target, &link).unwrap();
        assert!(open_private_file(&link, PrivateOpenMode::Truncate).is_err());
        assert_eq!(fs::read(target).unwrap(), b"must survive");
    }

    #[cfg(unix)]
    #[test]
    fn reused_private_file_rejects_insecure_mode_before_truncate() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("checkpoint");
        fs::write(&path, b"must survive").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = open_private_file(&path, PrivateOpenMode::Truncate)
            .expect_err("insecure reused file must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), b"must survive");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn reused_private_directory_rejects_insecure_mode_without_repair() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("workspace");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        let error =
            create_private_dir_all(&path).expect_err("insecure reused directory must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn authority_reads_and_retains_reject_permissive_sensitive_children() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let outer = tempfile::tempdir().unwrap();
        let parent = outer.path().join("private");
        create_private_dir_all(&parent).unwrap();
        let lease = NamespaceLease::acquire(&parent, &parent.join("authority.lock")).unwrap();

        for name in ["journal", "checkpoint", "registry"] {
            let path = parent.join(name);
            fs::write(&path, b"attacker-controlled").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

            assert_eq!(
                lease.read_child(&path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                lease.retain_child(&path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(fs::read(&path).unwrap(), b"attacker-controlled");
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o644);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn set_posix_acl_xattr(file: &File, name: &[u8], entries: &[(u16, u16, u32)]) {
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in entries {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        assert_eq!(name.last(), Some(&0));
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr().cast(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            },
            0,
            "setting POSIX ACL xattr: {}",
            io::Error::last_os_error()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_reused_private_file_rejects_posix_access_acl() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("checkpoint");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        set_posix_acl_xattr(
            &file,
            b"system.posix_acl_access\0",
            &[
                (0x01, 0x06, u32::MAX),
                (0x02, 0x04, unsafe { libc::geteuid() }.saturating_add(1)),
                (0x04, 0, u32::MAX),
                (0x10, 0x04, u32::MAX),
                (0x20, 0, u32::MAX),
            ],
        );
        drop(file);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = open_private_file(&path, PrivateOpenMode::Append)
            .expect_err("POSIX access ACL must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_reused_private_directory_rejects_posix_default_acl() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("workspace");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(&path).unwrap();
        set_posix_acl_xattr(
            &directory,
            b"system.posix_acl_default\0",
            &[
                (0x01, 0x07, u32::MAX),
                (0x04, 0, u32::MAX),
                (0x10, 0, u32::MAX),
                (0x20, 0, u32::MAX),
            ],
        );
        drop(directory);

        let error = create_private_dir_all(&path).expect_err("POSIX default ACL must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_publication_parent_rejects_posix_acl_before_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = File::open(tmp.path()).unwrap();
        set_posix_acl_xattr(
            &parent,
            b"system.posix_acl_access\0",
            &[
                (0x01, 0x07, u32::MAX),
                (0x04, 0, u32::MAX),
                (0x10, 0, u32::MAX),
                (0x20, 0, u32::MAX),
            ],
        );
        let private_root = tmp.path().join("workspace-private-root");
        let leaf = private_root.join("birthday-1/scope");
        let database = leaf.join("wallet.sqlite");

        let error = ensure_private_workspace_lineage(&private_root, &leaf, &database)
            .expect_err("publication parent ACL must fail before staging");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!private_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_survives_exposed_entry_substitution() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let path = tmp.path().join("checkpoint");
        let moved = tmp.path().join("moved-private-entry");
        write_private_file_atomic_with_observer(&path, b"verified secret", |exposed| {
            assert!(exposed.is_dir(), "the exposed entry must contain no secret");
            fs::rename(exposed, &moved)?;
            fs::create_dir(exposed)?;
            fs::write(exposed.join("artifact"), b"attacker replacement")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"verified secret");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_cleanup_does_not_remove_a_substituted_empty_directory() {
        use std::{
            cell::RefCell,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };

        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let path = tmp.path().join("checkpoint");
        let moved = tmp.path().join("moved-private-entry");
        let decoy = RefCell::new(None);
        write_private_file_atomic_with_observer(&path, b"verified secret", |exposed| {
            fs::rename(exposed, &moved)?;
            fs::create_dir(exposed)?;
            *decoy.borrow_mut() = Some(File::open(exposed)?);
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"verified secret");
        assert!(
            decoy.borrow().as_ref().unwrap().metadata().unwrap().nlink() > 0,
            "cleanup deleted an attacker-substituted staging object"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_cleanup_removes_crash_left_secret_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("wallet-a.checkpoint");
        let staging = super::unix_private::abandon_staged_write(&path, b"spend-capable").unwrap();
        assert_eq!(
            fs::read(staging.join("artifact")).unwrap(),
            b"spend-capable"
        );

        assert!(remove_stale_private_file_staging(&path, std::time::Duration::ZERO).unwrap());
        assert!(!staging.exists());
    }

    #[cfg(unix)]
    #[test]
    fn discard_cleanup_is_scoped_to_one_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("wallet-a.checkpoint");
        let second = tmp.path().join("wallet-b.checkpoint");
        let first_staging =
            super::unix_private::abandon_staged_write(&first, b"first secret").unwrap();
        let second_staging =
            super::unix_private::abandon_staged_write(&second, b"second secret").unwrap();

        assert!(discard_private_file_staging(&first).unwrap());
        assert!(!first_staging.exists());
        assert!(second_staging.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn atomic_private_objects_reject_inherited_macos_acls_before_use() {
        use std::process::Command;

        fn has_extended_acl(path: &Path) -> bool {
            let output = Command::new("ls").arg("-lde").arg(path).output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .skip(1)
                .any(|line| line.trim_start().starts_with("0:"))
        }

        let tmp = tempfile::tempdir().unwrap();
        let status = Command::new("chmod")
            .arg("+a")
            .arg(
                "everyone allow list,search,add_file,add_subdirectory,delete_child,\
                 file_inherit,directory_inherit",
            )
            .arg(tmp.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(has_extended_acl(tmp.path()));

        let path = tmp.path().join("checkpoint");
        let error = write_private_file_atomic(&path, b"spend-capable")
            .expect_err("an inherited ACL must fail before secret bytes are written");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.exists());
        assert!(
            fs::read_dir(tmp.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| entry.file_name() != "artifact"),
            "no secret artifact was created under an insecure inherited ACL"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_verifier_rejects_an_inherited_entry() {
        use std::{os::unix::fs::PermissionsExt, process::Command};

        let tmp = tempfile::tempdir().unwrap();
        assert!(Command::new("chmod")
            .arg("+a")
            .arg(
                "everyone allow list,search,add_file,add_subdirectory,delete_child,\
                 file_inherit,directory_inherit",
            )
            .arg(tmp.path())
            .status()
            .unwrap()
            .success());
        let child = tmp.path().join("child");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        let child = File::open(child).unwrap();

        assert!(super::unix_private::verify_no_extended_acl(&child).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_publication_parent_rejects_extended_acl_before_staging() {
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap();
        assert!(Command::new("chmod")
            .arg("+a")
            .arg("everyone allow list,search,add_file,add_subdirectory,delete_child")
            .arg(tmp.path())
            .status()
            .unwrap()
            .success());
        let private_root = tmp.path().join("workspace-private-root");
        let leaf = private_root.join("birthday-1/scope");
        let database = leaf.join("wallet.sqlite");

        let error = ensure_private_workspace_lineage(&private_root, &leaf, &database)
            .expect_err("publication parent ACL must fail before staging");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!private_root.exists());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::{
        mem,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SHARING_VIOLATION,
            ERROR_SUCCESS, HANDLE,
        },
        Security::{
            AclSizeInformation, AddAccessAllowedAceEx,
            Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetLengthSid,
            GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, TokenUser,
            WinBuiltinUsersSid, WinLocalSystemSid, WinWorldSid, ACCESS_ALLOWED_ACE, ACL,
            ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSID, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateSymbolicLinkW, FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE, WRITE_DAC,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    unsafe fn token_user() -> (Vec<usize>, PSID) {
        let mut token = ptr::null_mut();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
            0
        );
        let token = Token(token);
        let mut len = 0;
        assert_eq!(
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len),
            0
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(ERROR_INSUFFICIENT_BUFFER as i32)
        );
        let mut bytes = vec![0usize; (len as usize).div_ceil(mem::size_of::<usize>())];
        assert_ne!(
            GetTokenInformation(token.0, TokenUser, bytes.as_mut_ptr().cast(), len, &mut len),
            0
        );
        let sid = (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        (bytes, sid)
    }

    unsafe fn well_known(kind: i32) -> (Vec<usize>, PSID) {
        let mut bytes =
            vec![0usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(mem::size_of::<usize>())];
        let mut len = SECURITY_MAX_SID_SIZE;
        let sid = bytes.as_mut_ptr().cast();
        assert_ne!(CreateWellKnownSid(kind, ptr::null_mut(), sid, &mut len), 0);
        (bytes, sid)
    }

    unsafe fn set_world_access(file: &File, directory: bool) {
        let (_world_bytes, world) = well_known(WinWorldSid);
        let ace_base = mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>();
        let len = mem::size_of::<ACL>() + ace_base + GetLengthSid(world) as usize;
        let mut bytes = vec![0usize; len.div_ceil(mem::size_of::<usize>())];
        let acl = bytes.as_mut_ptr().cast::<ACL>();
        assert_ne!(InitializeAcl(acl, len as u32, ACL_REVISION), 0);
        let flags = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        assert_ne!(
            AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FILE_ALL_ACCESS, world),
            0
        );
        assert_eq!(
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            ),
            ERROR_SUCCESS
        );
    }

    unsafe fn assert_private_acl(file: &File, directory: bool) {
        let (_user_bytes, user) = token_user();
        let (_system_bytes, system) = well_known(WinLocalSystemSid);
        let (_world_bytes, world) = well_known(WinWorldSid);
        let (_users_bytes, users) = well_known(WinBuiltinUsersSid);
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        assert_eq!(
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            ),
            ERROR_SUCCESS
        );
        assert_ne!(owner, ptr::null_mut());
        assert_ne!(
            EqualSid(owner, user),
            0,
            "private object owner must be the current token user"
        );
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0, "DACL must be protected");
        let mut info = ACL_SIZE_INFORMATION::default();
        assert_ne!(
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ),
            0
        );
        assert_eq!(info.AceCount, 2, "only owner and LocalSystem may have ACEs");
        let mut saw_user = false;
        let mut saw_system = false;
        for index in 0..info.AceCount {
            let mut raw = ptr::null_mut();
            assert_ne!(GetAce(dacl, index, &mut raw), 0);
            let ace = &*(raw.cast::<ACCESS_ALLOWED_ACE>());
            assert_eq!(ace.Header.AceType, ACCESS_ALLOWED_ACE_TYPE);
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            if EqualSid(sid, user) != 0 {
                assert!(!saw_user, "owner must have exactly one ACE");
                saw_user = true;
            } else if EqualSid(sid, system) != 0 {
                assert!(!saw_system, "LocalSystem must have exactly one ACE");
                saw_system = true;
            } else {
                panic!("unexpected SID in private DACL");
            }
            assert_eq!(EqualSid(sid, world), 0);
            assert_eq!(EqualSid(sid, users), 0);
            assert_eq!(ace.Mask, FILE_ALL_ACCESS);
            assert_eq!(
                u32::from(ace.Header.AceFlags),
                if directory {
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                } else {
                    0
                }
            );
        }
        assert!(saw_user && saw_system);
        LocalFree(descriptor);
    }

    unsafe fn assert_world_access_is_still_present(file: &File) {
        let (_world_bytes, world) = well_known(WinWorldSid);
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        assert_eq!(
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            ),
            ERROR_SUCCESS
        );
        let mut info = ACL_SIZE_INFORMATION::default();
        assert_ne!(
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ),
            0
        );
        let mut found = false;
        for index in 0..info.AceCount {
            let mut raw = ptr::null_mut();
            assert_ne!(GetAce(dacl, index, &mut raw), 0);
            let ace = &*(raw.cast::<ACCESS_ALLOWED_ACE>());
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            found |= EqualSid(sid, world) != 0;
        }
        assert!(found, "reuse verification must not rewrite the DACL");
        LocalFree(descriptor);
    }

    #[test]
    fn windows_owner_verifier_rejects_a_foreign_owner_sid() {
        let (_user_bytes, user) = unsafe { token_user() };
        let (_system_bytes, system) = unsafe { well_known(WinLocalSystemSid) };
        let error = super::windows_acl::require_current_owner_sid(system, user)
            .expect_err("a foreign owner must not be accepted as a private object");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        super::windows_acl::require_current_owner_sid(user, user).unwrap();
    }

    #[test]
    fn windows_foreign_owner_verification_never_repairs_the_dacl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("foreign-owned-secret");
        fs::write(&path, b"must survive").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&file, false) };
        let (_system_bytes, system) = unsafe { well_known(WinLocalSystemSid) };

        let error = super::windows_acl::verify_for_expected_owner_test(&file, false, system)
            .expect_err("foreign ownership must fail without DACL repair or truncation");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), b"must survive");
        unsafe { assert_world_access_is_still_present(&file) };
    }

    #[test]
    fn windows_reuse_refuses_permissive_file_with_security_only_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("preopened-secret");
        fs::write(&path, b"must survive").unwrap();
        let attacker = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&attacker, false) };

        let error = open_private_file(&path, PrivateOpenMode::Truncate)
            .expect_err("a permissive reused file must fail before truncation");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert_eq!(fs::read(&path).unwrap(), b"must survive");
        unsafe { assert_world_access_is_still_present(&attacker) };
        drop(attacker);

        assert!(open_private_file(&path, PrivateOpenMode::Truncate).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"must survive");
    }

    #[test]
    fn windows_relative_reuse_refuses_permissive_child_with_security_only_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_path = tmp.path().join("private");
        create_private_dir_all(&parent_path).unwrap();
        let parent = super::windows_acl::open_directory_for_lease(&parent_path).unwrap();
        let path = parent_path.join("journal");
        fs::write(&path, b"must survive").unwrap();
        let attacker = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&attacker, false) };

        let error =
            super::windows_acl::open_child_private(&parent, &path, PrivateOpenMode::Truncate)
                .expect_err("relative reused child must verify its existing DACL");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert_eq!(fs::read(&path).unwrap(), b"must survive");
        unsafe { assert_world_access_is_still_present(&attacker) };
    }

    #[test]
    fn windows_authority_reads_and_retains_reject_permissive_sensitive_children() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_path = tmp.path().join("private");
        create_private_dir_all(&parent_path).unwrap();
        let lease =
            NamespaceLease::acquire(&parent_path, &parent_path.join("authority.lock")).unwrap();

        for name in ["journal", "checkpoint", "registry"] {
            let path = parent_path.join(name);
            fs::write(&path, b"attacker-controlled").unwrap();
            let file = OpenOptions::new()
                .read(true)
                .access_mode(READ_CONTROL | WRITE_DAC)
                .open(&path)
                .unwrap();
            unsafe { set_world_access(&file, false) };

            assert_eq!(
                lease.read_child(&path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                lease.retain_child(&path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(fs::read(&path).unwrap(), b"attacker-controlled");
            unsafe { assert_world_access_is_still_present(&file) };
        }
    }

    #[test]
    fn windows_authority_reads_refuse_preheld_data_handles() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_path = tmp.path().join("private");
        create_private_dir_all(&parent_path).unwrap();
        let lease =
            NamespaceLease::acquire(&parent_path, &parent_path.join("authority.lock")).unwrap();
        let path = parent_path.join("journal");
        write_private_file(&path, b"exact-private").unwrap();
        let held = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();

        for error in [
            lease.read_child(&path).unwrap_err(),
            lease.retain_child(&path).unwrap_err(),
        ] {
            assert_eq!(
                error.raw_os_error(),
                Some(ERROR_SHARING_VIOLATION as i32),
                "{error}"
            );
        }
        assert_eq!(fs::read(&path).unwrap(), b"exact-private");
        drop(held);
        assert_eq!(lease.read_child(&path).unwrap(), b"exact-private");
        let retained = lease.retain_child(&path).unwrap();
        retained.verify_current().unwrap();
    }

    #[test]
    fn windows_checkpoint_generation_refuses_a_permissive_dacl() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("private");
        create_private_dir_all(&parent).unwrap();
        let path = parent.join("scan.checkpoint");
        write_private_file(&path, b"spending-key checkpoint").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&file, false) };

        let error = crate::sprout_scan_run::checkpoint_generation(&path)
            .expect_err("a permissive checkpoint must be rejected before its bytes are read");

        assert!(
            error.to_string().contains("opening checkpoint child"),
            "{error}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"spending-key checkpoint");
        unsafe { assert_world_access_is_still_present(&file) };
    }

    #[test]
    fn windows_private_directory_authority_retains_no_delete_share() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sqlite-parent");
        create_private_dir_all(&path).unwrap();
        let authority = open_private_directory_lease(&path).unwrap();
        open_private_directory_lease(&path).unwrap();
        assert!(fs::rename(&path, tmp.path().join("replaced")).is_err());
        drop(authority);
    }

    #[test]
    fn windows_sqlite_preflight_refuses_a_preheld_data_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let private_root = tmp.path().join("workspace-private-root");
        let parent_path = private_root.join("birthday-1/scope");
        let path = parent_path.join("wallet.sqlite");
        let root = ensure_private_workspace_lineage(&private_root, &parent_path, &path).unwrap();
        forget_sqlite_authority_for_test(&path);
        let held = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        let parent = open_private_sqlite_parent(&parent_path).unwrap();

        let error = ensure_private_sqlite_file(&root, &parent, &parent_path, &path)
            .expect_err("a preheld data handle must block SQLite preflight");
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32),
            "{error}"
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        drop(held);
        ensure_private_sqlite_file(&root, &parent, &parent_path, &path).unwrap();
    }

    #[test]
    fn windows_existing_private_root_reserves_pending_before_a_second_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let private_root = tmp.path().join("workspace-private-root");
        let first_leaf = private_root.join("birthday-1/scope-a");
        let first_database = first_leaf.join("wallet.sqlite");
        ensure_private_workspace_lineage(&private_root, &first_leaf, &first_database).unwrap();

        let second_leaf = private_root.join("birthday-2/scope-b");
        let second_database = second_leaf.join("wallet.sqlite");
        ensure_private_workspace_lineage(&private_root, &second_leaf, &second_database).unwrap();

        assert!(first_database.is_file());
        assert!(second_database.is_file());
        let root = verify_private_workspace_lineage(&private_root).unwrap();
        let parent = open_private_sqlite_parent(&second_leaf).unwrap();
        ensure_private_sqlite_file(&root, &parent, &second_leaf, &second_database).unwrap();
    }

    #[test]
    fn windows_lineage_decoder_refuses_plaintext_json() {
        let error = decode_lineage_record::<PrivateRootLineageRecord>(
            LineageRecordKind::Root,
            br#"{"schema_version":1}"#,
        )
        .expect_err("Windows lineage must never accept an unauthenticated JSON fallback");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn windows_lineage_mutex_uses_global_private_hashed_name() {
        let plaintext = format!(
            r"C:\Users\Argos\private-workspace\{}\mainnet",
            uuid::Uuid::new_v4()
        );
        let context_hash = super::windows_lineage::context_hash(plaintext.as_bytes());
        let name = super::windows_lineage::mutex_name(&context_hash);

        assert!(name.starts_with("Global\\ArgosWalletRescue-Lineage-w-"));
        assert!(!name.contains(&plaintext));
        assert_eq!(
            name.len(),
            "Global\\ArgosWalletRescue-Lineage-w-".len() + 64
        );

        // Acquisition also verifies that an existing object has the exact
        // protected current-user plus LocalSystem DACL before trusting it.
        let _guard = super::windows_lineage::lock(&context_hash).unwrap();
    }

    #[test]
    fn windows_reused_read_append_keeps_exclusive_handle_through_write() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_path = tmp.path().join("private");
        create_private_dir_all(&parent_path).unwrap();
        let path = parent_path.join("journal");
        write_private_file(&path, b"before").unwrap();
        let held = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();

        let error = open_private_file(&path, PrivateOpenMode::ReadWriteAppend)
            .expect_err("preheld data handle must block exact journal append");
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32),
            "{error}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"before");
        drop(held);

        let mut journal = open_private_file(&path, PrivateOpenMode::ReadWriteAppend).unwrap();
        journal.write_all(b"-after").unwrap();
        journal.sync_all().unwrap();
        drop(journal);
        assert_eq!(fs::read(&path).unwrap(), b"before-after");
    }

    #[test]
    fn windows_recursive_cleanup_refuses_permissive_nested_child() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_path = tmp.path().join("private");
        let tombstone = parent_path.join("workspace.deleting");
        create_private_dir_all(&tombstone).unwrap();
        let child = tombstone.join("checkpoint");
        write_private_file(&child, b"must survive").unwrap();
        let child_handle = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .open(&child)
            .unwrap();
        unsafe { set_world_access(&child_handle, false) };
        let parent = super::windows_acl::open_directory_for_lease(&parent_path).unwrap();
        let tombstone_handle =
            super::windows_acl::open_child_directory_for_mutation(&parent, &tombstone).unwrap();

        let error = super::windows_acl::remove_open_directory_contents(&tombstone_handle)
            .expect_err("permissive nested child must stop recursive cleanup");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&child).unwrap(), b"must survive");
        unsafe { assert_world_access_is_still_present(&child_handle) };
        assert!(tombstone.exists());
    }

    #[test]
    fn windows_reuse_refuses_permissive_directory_with_security_only_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("preopened-directory");
        fs::create_dir(&path).unwrap();
        let attacker = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&attacker, true) };

        let error = create_private_dir_all(&path)
            .expect_err("a permissive reused directory must fail without DACL repair");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        unsafe { assert_world_access_is_still_present(&attacker) };
        drop(attacker);

        assert!(create_private_dir_all(&path).is_err());
    }

    #[test]
    fn windows_reused_permissive_objects_fail_closed_without_repair() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        fs::create_dir(&dir).unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        unsafe { set_world_access(&directory, true) };

        let path = dir.join("secret");
        fs::write(&path, b"old").unwrap();
        let permissive = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&permissive, false) };
        drop(permissive);

        let directory_error =
            create_private_dir_all(&dir).expect_err("permissive reused directory must fail closed");
        let file_error = open_private_file(&path, PrivateOpenMode::Append)
            .expect_err("permissive reused file must fail closed");

        assert_eq!(directory_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(file_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), b"old");
        unsafe {
            assert_world_access_is_still_present(&directory);
            let file = OpenOptions::new()
                .read(true)
                .access_mode(READ_CONTROL)
                .open(&path)
                .unwrap();
            assert_world_access_is_still_present(&file);
        }
    }

    #[test]
    fn windows_creation_is_private_before_first_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("new-private");
        create_private_dir_all(&dir).unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        unsafe { assert_private_acl(&directory, true) };
        let path = dir.join("checkpoint.tmp");
        let mut file = super::windows_acl::create_file_with_observer(
            &path,
            PrivateOpenMode::Truncate,
            |created| {
                assert_eq!(
                    created.metadata()?.len(),
                    0,
                    "observer runs before any secret byte"
                );
                unsafe { assert_private_acl(created, false) };
                Ok(())
            },
        )
        .unwrap();
        file.write_all(b"spend-capable checkpoint").unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::read(path).unwrap(), b"spend-capable checkpoint");
    }

    #[test]
    fn windows_creation_verification_failure_precedes_secret_write() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("must-not-survive");
        let err = super::windows_acl::create_file_with_observer(
            &path,
            PrivateOpenMode::Truncate,
            |created| {
                assert_eq!(created.metadata()?.len(), 0);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected creation-time ACL verification failure",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.exists(), "failed private creation must leave no file");
    }

    #[test]
    fn windows_atomic_replace_syncs_private_parent_and_preserves_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        create_private_dir_all(&dir).unwrap();
        let path = dir.join("journal.jsonl");
        write_private_file_atomic(&path, b"first").unwrap();
        write_private_file_atomic(&path, b"replacement").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        unsafe { assert_private_acl(&file, false) };
    }

    #[test]
    fn windows_atomic_replace_renames_the_verified_handle_after_name_swap() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        create_private_dir_all(&dir).unwrap();
        let path = dir.join("checkpoint");
        let swapped_name = std::cell::RefCell::new(None);
        write_private_file_atomic_with_observer(&path, b"verified secret", |temporary| {
            let moved = dir.join("moved-verified-temp");
            fs::rename(temporary, &moved)?;
            fs::write(temporary, b"attacker replacement")?;
            *swapped_name.borrow_mut() = Some(temporary.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"verified secret");
        assert_eq!(
            fs::read(swapped_name.into_inner().unwrap()).unwrap(),
            b"attacker replacement"
        );
    }

    #[test]
    fn windows_namespace_child_operations_stay_rooted_during_ancestor_rename_attempts() {
        let tmp = tempfile::tempdir().unwrap();
        let ancestor = tmp.path().join("authority");
        let parent = ancestor.join("private");
        create_private_dir_all(&parent).unwrap();
        let child = parent.join("journal");
        let renamed = parent.join("renamed-journal");
        let lock = parent.join("journal.lock");
        let lease = NamespaceLease::acquire(&parent, &lock).unwrap();
        let detached = tmp.path().join("detached-authority");

        assert!(
            fs::rename(&ancestor, &detached).is_err(),
            "an open retained parent must prevent an ancestor namespace rename on Windows"
        );
        lease
            .append_child_if_unchanged(&child, None, b"first")
            .unwrap();
        let (bytes, id) = lease.read_child_version(&child).unwrap();
        lease
            .append_child_if_unchanged(&child, Some((&id, &bytes)), b"-second")
            .unwrap();
        assert!(lease
            .child_names()
            .unwrap()
            .contains(&child.file_name().unwrap().to_owned()));

        write_private_file_atomic_windows_in_parent(lease.parent(), &child, b"atomic", |_| {
            assert!(fs::rename(&ancestor, &detached).is_err());
            Ok(())
        })
        .unwrap();
        rename_child_file(lease.parent(), &child, &renamed).unwrap();
        let opened = open_child_file(lease.parent(), &renamed).unwrap();
        let opened_id = private_object_id(&opened).unwrap();
        remove_open_child_file(lease.parent(), &renamed, &opened, &opened_id).unwrap();

        assert!(!renamed.exists());
        assert!(!detached.exists());
    }

    #[test]
    fn windows_namespace_append_create_and_reuse_keep_retained_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("private");
        create_private_dir_all(&parent).unwrap();
        let child = parent.join("journal");
        let lease = NamespaceLease::acquire(&parent, &parent.join("journal.lock")).unwrap();

        lease
            .append_child_if_unchanged(&child, None, b"created")
            .unwrap();
        let (bytes, id) = lease.read_child_version(&child).unwrap();
        assert_eq!(bytes, b"created");
        lease
            .append_child_if_unchanged(&child, Some((&id, &bytes)), b"-reused")
            .unwrap();

        assert_eq!(lease.read_child(&child).unwrap(), b"created-reused");
    }

    #[test]
    fn windows_relative_primitives_never_touch_a_recreated_ancestor_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let ancestor = tmp.path().join("authority");
        let parent = ancestor.join("private");
        create_private_dir_all(&parent).unwrap();
        let retained = open_parent_sync_handle(&parent).unwrap();
        let detached_ancestor = tmp.path().join("detached-authority");
        fs::rename(&ancestor, &detached_ancestor).unwrap();
        create_private_dir_all(&parent).unwrap();

        let replacement_sentinel = parent.join("sentinel");
        fs::write(&replacement_sentinel, b"replacement tree").unwrap();
        let child = parent.join("journal");
        let mut created = super::windows_acl::create_child_private(
            &retained,
            &child,
            PrivateOpenMode::ReadWriteAppend,
        )
        .unwrap();
        created.write_all(b"created").unwrap();
        created.sync_all().unwrap();
        drop(created);
        let mut existing = super::windows_acl::open_child_private(
            &retained,
            &child,
            PrivateOpenMode::ReadWriteAppend,
        )
        .unwrap();
        existing.write_all(b"-appended").unwrap();
        existing.sync_all().unwrap();
        drop(existing);
        assert!(parent_child_names(&retained, &parent)
            .unwrap()
            .contains(&child.file_name().unwrap().to_owned()));

        let truncated = parent.join("truncate-target");
        {
            let mut original = super::windows_acl::create_child_private(
                &retained,
                &truncated,
                PrivateOpenMode::ReadWriteAppend,
            )
            .unwrap();
            original.write_all(b"old bytes").unwrap();
        }
        fs::write(&truncated, b"replacement sentinel").unwrap();
        let mut truncated_handle = super::windows_acl::open_child_private(
            &retained,
            &truncated,
            PrivateOpenMode::Truncate,
        )
        .unwrap();
        truncated_handle.write_all(b"detached replacement").unwrap();
        truncated_handle.sync_all().unwrap();

        let atomic = parent.join("atomic-target");
        fs::write(&atomic, b"replacement atomic sentinel").unwrap();
        write_private_file_atomic_windows_in_parent(&retained, &atomic, b"detached atomic", |_| {
            assert_eq!(fs::read(&replacement_sentinel)?, b"replacement tree");
            Ok(())
        })
        .unwrap();

        let source = parent.join("source");
        let renamed = parent.join("renamed");
        let mut source_handle = super::windows_acl::create_child_private(
            &retained,
            &source,
            PrivateOpenMode::ReadWriteAppend,
        )
        .unwrap();
        source_handle.write_all(b"rename then delete").unwrap();
        drop(source_handle);
        rename_child_file(&retained, &source, &renamed).unwrap();
        let opened = open_child_file(&retained, &renamed).unwrap();
        let opened_id = private_object_id(&opened).unwrap();
        remove_open_child_file(&retained, &renamed, &opened, &opened_id).unwrap();

        let detached_parent = detached_ancestor.join("private");
        assert_eq!(
            fs::read(detached_parent.join("journal")).unwrap(),
            b"created-appended"
        );
        assert_eq!(
            fs::read(detached_parent.join("truncate-target")).unwrap(),
            b"detached replacement"
        );
        assert_eq!(
            fs::read(detached_parent.join("atomic-target")).unwrap(),
            b"detached atomic"
        );
        assert!(!detached_parent.join("renamed").exists());
        assert_eq!(
            fs::read(&replacement_sentinel).unwrap(),
            b"replacement tree"
        );
        assert_eq!(fs::read(&truncated).unwrap(), b"replacement sentinel");
        assert_eq!(fs::read(&atomic).unwrap(), b"replacement atomic sentinel");
        assert!(!child.exists());
        assert!(!source.exists());
        assert!(!renamed.exists());
    }

    #[test]
    fn windows_reused_private_file_refuses_a_symlink_before_truncate() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("wallet.dat");
        let link = tmp.path().join("report.json");
        fs::write(&target, b"must survive").unwrap();
        let wide = |path: &Path| {
            use std::os::windows::ffi::OsStrExt;
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        };
        let link_wide = wide(&link);
        let target_wide = wide(&target);
        let created = unsafe {
            CreateSymbolicLinkW(
                link_wide.as_ptr(),
                target_wide.as_ptr(),
                SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            )
        };
        if !created {
            let err = io::Error::last_os_error();
            if err.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD as i32)
            {
                return;
            }
            panic!("creating test symlink: {err}");
        }
        assert!(open_private_file(&link, PrivateOpenMode::Truncate).is_err());
        assert_eq!(fs::read(target).unwrap(), b"must survive");
    }

    #[test]
    fn windows_directory_creation_collision_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("colliding-private");
        let err = super::windows_acl::create_dir_all_with_before_create(&path, |candidate| {
            fs::create_dir(candidate)?;
            let directory = OpenOptions::new()
                .read(true)
                .access_mode(READ_CONTROL | WRITE_DAC)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(candidate)?;
            unsafe { set_world_access(&directory, true) };
            Ok(())
        })
        .unwrap_err();
        assert!(
            err.raw_os_error()
                .map(|code| code as u32)
                .is_some_and(|code| {
                    code == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS
                        || code == windows_sys::Win32::Foundation::ERROR_FILE_EXISTS
                }),
            "unexpected collision error: {err}"
        );
        let directory = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        assert!(
            super::windows_acl::verify_current(&directory, true).is_err(),
            "a raced-in directory must not be accepted or hardened"
        );
    }

    #[test]
    fn windows_directory_creation_detects_parent_substitution_before_hardening() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        let moved_parent = tmp.path().join("moved-parent");
        create_private_dir_all(&parent).unwrap();
        let path = parent.join("private");
        let err = super::windows_acl::create_directory_with_observer(&path, |_| {
            fs::rename(&parent, &moved_parent)?;
            fs::create_dir(&parent)?;
            fs::create_dir(&path)?;
            let replacement = OpenOptions::new()
                .read(true)
                .access_mode(READ_CONTROL | WRITE_DAC)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(&path)?;
            unsafe { set_world_access(&replacement, true) };
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let replacement = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        assert!(
            super::windows_acl::verify_current(&replacement, true).is_err(),
            "the substituted directory must not be hardened"
        );
    }

    #[test]
    fn windows_verifier_rejects_a_broad_same_handle_dacl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("permissive");
        fs::write(&path, b"secret").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        unsafe { set_world_access(&file, false) };
        assert!(super::windows_acl::verify_current(&file, false).is_err());
        let error = harden_private_file(&file)
            .expect_err("verification must not repair a broad reused DACL");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        unsafe { assert_world_access_is_still_present(&file) };
    }
}
