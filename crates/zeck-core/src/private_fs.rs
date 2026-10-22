//! Fail-closed filesystem primitives for spend-capable recovery artifacts.

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

    pub(crate) fn read_child_version(&self, path: &Path) -> io::Result<(Vec<u8>, PrivateObjectId)> {
        self.require_child(path)?;
        self.verify_current()?;
        let mut file = open_child_file(&self.parent, path)?;
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
        let current_path = open_child_file(&self.parent, path)?;
        if private_object_id(&current_path)? != object_id {
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

    pub(crate) fn rename_child_directory(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.rename_child_directory_with_observer(from, to, || Ok(()))
    }

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

    pub(crate) fn remove_child_directory_all(&self, path: &Path) -> io::Result<()> {
        self.remove_child_directory_all_with_observer(path, || Ok(()))
    }

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
        let file = open_child_file(&self.parent, path)?;
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

fn open_child_file_for_removal(parent: &File, path: &Path) -> io::Result<File> {
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
        let current = open_child_file(self.namespace.parent(), &self.path)?;
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

/// Create `path` and tighten the leaf directory before it is used.
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

/// Remove inherited/broad access from an existing private directory.
pub fn harden_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = unix_private::open_directory(path)?;
        unix_private::remove_extended_acl(&directory)?;
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        unix_private::verify_no_extended_acl(&directory)
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

/// Tighten the object addressed by an already-open handle.
pub fn harden_private_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        unix_private::remove_extended_acl(file)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        unix_private::verify_no_extended_acl(file)
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
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
        };
        let data_access = match mode {
            PrivateOpenMode::Append => FILE_APPEND_DATA,
            PrivateOpenMode::ReadWriteLock | PrivateOpenMode::ReadWriteAppend => {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE
            }
            PrivateOpenMode::Truncate | PrivateOpenMode::CreateNew => FILE_GENERIC_WRITE,
        };
        options.access_mode(data_access | READ_CONTROL | WRITE_DAC);
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
            (options_for(mode, false).open(path)?, false)
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
    // Never request truncation in OpenOptions: reused files must be hardened
    // successfully before their old contents are destroyed.
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

/// Open a private file, establishing its ACL/mode before truncation or writes.
pub fn open_private_file(path: &Path, mode: PrivateOpenMode) -> io::Result<File> {
    open_private_file_with(path, mode, harden_private_file)
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
#[cfg(test)]
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

pub(crate) fn remove_stale_private_file_staging_in_parent(
    parent: &File,
    path: &Path,
    minimum_age: std::time::Duration,
) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unix_private::cleanup_staging_in_parent(parent, path, Some(minimum_age))
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, path, minimum_age);
        Ok(false)
    }
}

#[cfg(test)]
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

/// Remove destination-scoped staging through a parent handle retained by the
/// caller's namespace lease. On Unix this never follows a replaced parent
/// pathname; Windows pins the namespace with a non-delete-shared lock file.
pub(crate) fn discard_private_file_staging_in_parent(
    parent: &File,
    path: &Path,
) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unix_private::cleanup_staging_in_parent(parent, path, None)
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, path);
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
    pub(super) fn remove_extended_acl(file: &File) -> io::Result<()> {
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

    #[cfg(not(target_os = "macos"))]
    pub(super) fn remove_extended_acl(_file: &File) -> io::Result<()> {
        Ok(())
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

    #[cfg(not(target_os = "macos"))]
    pub(super) fn verify_no_extended_acl(_file: &File) -> io::Result<()> {
        Ok(())
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
            remove_extended_acl(&directory)?;
            directory.set_permissions(fs::Permissions::from_mode(0o700))?;
            let metadata = directory.metadata()?;
            if metadata.mode() & 0o777 != 0o700 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private staging directory permissions were not established",
                ));
            }
            verify_no_extended_acl(&directory)?;
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
        Ok(directory)
    }

    fn open_staging_directory(parent: RawFd, name: &CString) -> io::Result<File> {
        let directory = open_owned_directory(parent, name)?;
        if directory.metadata()?.mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private staging directory is not owner-only",
            ));
        }
        verify_no_extended_acl(&directory)?;
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
        remove_extended_acl(&directory)?;
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        if directory.metadata()?.mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private cleanup directory permissions were not established",
            ));
        }
        verify_no_extended_acl(&directory)?;
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

    pub(super) fn cleanup_staging_in_parent(
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
        validate_private_file(&file)?;
        harden_private_file(&file)?;
        Ok(file)
    }

    pub(super) fn open_child_file_for_lock(parent: &File, path: &Path) -> io::Result<File> {
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
                    | libc::O_CREAT
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
            assert!(Command::new("chmod")
                .arg("+a")
                .arg("everyone allow read,search,list")
                .arg(&collision)
                .status()
                .unwrap()
                .success());
            let parent = open_directory(tmp.path()).unwrap();
            let name =
                c_string(OsStr::new(CLEANUP_DIRECTORY_NAME), "cleanup directory name").unwrap();
            let collision_handle = open_owned_directory(parent.as_raw_fd(), &name).unwrap();
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
            CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
            INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, STATUS_BUFFER_OVERFLOW,
            STATUS_NO_MORE_FILES, UNICODE_STRING,
        },
        Security::{
            AclSizeInformation, AddAccessAllowedAceEx,
            Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetLengthSid,
            GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
            InitializeSecurityDescriptor, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
            TokenUser, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
            ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
            SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, FileDispositionInfo, FileRenameInfo,
            GetFileInformationByHandle, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            CREATE_NEW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
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
        Ok(file)
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
        Ok(directory)
    }

    pub(super) fn open_child_directory_for_identity(
        parent: &std::fs::File,
        path: &Path,
    ) -> io::Result<std::fs::File> {
        let directory = nt_open_child_with_options(
            parent,
            path,
            FILE_READ_ATTRIBUTES,
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
        unsafe {
            let status = SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                security._acl.as_ptr().cast(),
                ptr::null(),
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        security.verify(file)
    }

    fn verify(
        file: &std::fs::File,
        directory: bool,
        user_sid: PSID,
        system_sid: PSID,
    ) -> io::Result<()> {
        unsafe {
            let mut dacl = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            let status = GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            struct Descriptor(*mut core::ffi::c_void);
            impl Drop for Descriptor {
                fn drop(&mut self) {
                    unsafe { LocalFree(self.0) };
                }
            }
            let _descriptor = Descriptor(descriptor);
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
            | READ_CONTROL
            | WRITE_DAC;
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
                    (
                        nt_open_child(parent, path, access, share, FILE_OPEN, ptr::null())?,
                        false,
                    )
                }
                Err(err) => return Err(err),
            };
        let secured = validate_private_file(&file).and_then(|_| {
            if created {
                security.verify(&file)
            } else {
                super::harden_private_file(&file)
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
                access | DELETE | READ_CONTROL | WRITE_DAC,
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
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            ptr::null(),
        )?;
        validate_private_file(&file)?;
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
        let directory = open_directory(path, READ_CONTROL | WRITE_DAC)?;
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
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(access | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        directory_identity(&directory)?;
        Ok(directory)
    }

    pub(super) fn harden_directory(path: &Path) -> io::Result<()> {
        let directory = open_directory(path, READ_CONTROL | WRITE_DAC)?;
        harden(&directory, true)
    }

    #[cfg(test)]
    pub(super) fn verify_current(file: &std::fs::File, directory: bool) -> io::Result<()> {
        PrivateSecurity::new(directory)?.verify(file)
    }

    pub(super) fn open_directory_for_sync(path: &Path) -> io::Result<std::fs::File> {
        open_directory(
            path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        )
    }

    pub(super) fn open_directory_for_lease(path: &Path) -> io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC)
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
        fs::create_dir(&tombstone).unwrap();
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
        fs::create_dir(&tombstone).unwrap();
        fs::create_dir(tombstone.join("nested")).unwrap();
        fs::write(tombstone.join("nested/secret"), b"delete me").unwrap();
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
    fn atomic_private_objects_drop_inherited_macos_acls_before_use() {
        use std::{cell::RefCell, process::Command};

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
        let staging_path = RefCell::new(None);
        write_private_file_atomic_with_observer(&path, b"spend-capable", |staging| {
            *staging_path.borrow_mut() = Some(staging.to_path_buf());
            assert!(
                !has_extended_acl(staging),
                "the staging directory retained an inherited macOS ACL"
            );
            assert!(
                !has_extended_acl(&staging.join("artifact")),
                "the staged artifact retained an inherited macOS ACL"
            );
            Ok(())
        })
        .unwrap();
        assert!(!has_extended_acl(&path));
        assert!(
            !staging_path.borrow().as_ref().unwrap().exists(),
            "the private staging directory was not cleaned up"
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
        Foundation::{CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE},
        Security::{
            AclSizeInformation, AddAccessAllowedAceEx,
            Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetLengthSid,
            GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, TokenUser,
            WinBuiltinUsersSid, WinLocalSystemSid, WinWorldSid, ACCESS_ALLOWED_ACE, ACL,
            ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE,
            SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateSymbolicLinkW, FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, READ_CONTROL, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            WRITE_DAC,
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

    #[test]
    fn windows_reused_private_objects_have_only_owner_and_system_access() {
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

        create_private_dir_all(&dir).unwrap();
        drop(open_private_file(&path, PrivateOpenMode::Append).unwrap());

        let directory = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
            .open(&path)
            .unwrap();
        unsafe {
            assert_private_acl(&directory, true);
            assert_private_acl(&file, false);
        }
    }

    #[test]
    fn windows_creation_is_private_before_first_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("new-private");
        create_private_dir_all(&dir).unwrap();
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
        harden_private_file(&file).unwrap();
        super::windows_acl::verify_current(&file, false).unwrap();
    }
}
