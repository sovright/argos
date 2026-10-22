//! Fail-closed filesystem primitives for spend-capable recovery artifacts.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

/// How [`open_private_file`] may change the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateOpenMode {
    /// Tighten an existing object before truncating it.
    Truncate,
    /// Tighten an existing object before appending to it.
    Append,
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
    if mode == PrivateOpenMode::Append {
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
            FILE_APPEND_DATA, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, READ_CONTROL,
            WRITE_DAC,
        };
        let data_access = if mode == PrivateOpenMode::Append {
            FILE_APPEND_DATA
        } else {
            FILE_GENERIC_WRITE
        };
        options
            .access_mode(data_access | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}

fn create_new_private_file(path: &Path, mode: PrivateOpenMode) -> io::Result<File> {
    #[cfg(windows)]
    {
        windows_acl::create_file(path, mode == PrivateOpenMode::Append)
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

/// Remove destination-scoped atomic staging left by a crashed writer once it
/// is old enough that it cannot belong to an active write. The caller must
/// serialize cleanup with every writer for `path`; age alone cannot prove a
/// paused writer is inactive.
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

/// Remove every safe, destination-scoped atomic staging directory for `path`.
/// Callers must serialize this with writers for the same destination.
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
    let temporary = private_temporary(path);
    let mut file = open_private_file(&temporary, PrivateOpenMode::CreateNew)?;
    let mut replaced = false;
    let result = (|| {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        // Preflight the platform-specific directory handle before changing
        // the name. A bad Windows directory open must not turn a completed
        // replacement into a reported failure.
        let parent_sync = open_parent_sync_handle(parent)?;
        parent_sync.sync_all()?;
        before_replace(&temporary)?;
        windows_acl::replace_file(&file, &parent_sync, path)?;
        replaced = true;
        parent_sync.sync_all()?;
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

fn open_parent_sync_handle(parent: &Path) -> io::Result<File> {
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
            0 => Ok(()),
            value if value > 0 => Err(io::Error::new(
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

    fn open_staging_directory(parent: RawFd, name: &CString) -> io::Result<File> {
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
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
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
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = last_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let directory = open_staging_directory(parent.as_raw_fd(), &name)?;
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

    struct DirectoryStream(*mut libc::DIR);

    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__errno_location() }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__error() }
    }

    fn directory_names(directory: &File) -> io::Result<Vec<OsString>> {
        let descriptor = unsafe { libc::dup(directory.as_raw_fd()) };
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
            #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                target_os = "ios"
            ))]
            unsafe {
                *errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                #[cfg(any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "ios"
                ))]
                {
                    let error = last_error();
                    if error.raw_os_error() != Some(0) {
                        return Err(error);
                    }
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

    pub(super) fn cleanup_staging(
        path: &Path,
        minimum_age: Option<std::time::Duration>,
    ) -> io::Result<bool> {
        cleanup_staging_with_observer(path, minimum_age, || Ok(()))
    }

    fn cleanup_staging_with_observer(
        path: &Path,
        minimum_age: Option<std::time::Duration>,
        after_parent_open: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<bool> {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let prefix = staging_prefix(path)?;
        let parent = open_directory(parent_path)?;
        after_parent_open()?;
        let now = std::time::SystemTime::now();
        let mut removed = false;
        let mut errors = Vec::new();
        for name in directory_names(&parent)? {
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
            match cleanup_candidate(&parent, &name, candidate) {
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

    pub(super) fn write_atomic(
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
        let parent = open_directory(parent_path)?;
        parent.sync_all()?;
        let prefix = staging_prefix(path)?;
        let (staging, staging_name, staging_relative, staging_identity) =
            create_staging_directory(&parent, &prefix)?;
        let exposed = parent_path.join(staging_relative);
        let mut file = match create_artifact(staging.as_raw_fd()) {
            Ok(file) => file,
            Err(err) => {
                let _ = remove_staging_entry(&parent, &staging_name, staging_identity);
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
        let _ = remove_staging_entry(&parent, &staging_name, staging_identity);
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
    }
}

#[cfg(windows)]
mod windows_acl {
    use std::{
        ffi::OsStr,
        io, mem,
        os::windows::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Path, PathBuf},
        ptr,
    };

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
            INVALID_HANDLE_VALUE,
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
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
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

    pub(super) fn create_file(path: &Path, append: bool) -> io::Result<std::fs::File> {
        create_file_with_observer(path, append, |_| Ok(()))
    }

    pub(super) fn create_file_with_observer(
        path: &Path,
        append: bool,
        observer: impl FnOnce(&std::fs::File) -> io::Result<()>,
    ) -> io::Result<std::fs::File> {
        let security = PrivateSecurity::new(false)?;
        let path_buf = path.to_path_buf();
        let path = wide(path)?;
        let access = if append {
            FILE_APPEND_DATA
        } else {
            FILE_GENERIC_WRITE
        };
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                access | DELETE | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "private file has no name")
        })?;
        let name = name.encode_wide().collect::<Vec<_>>();
        let header_len = mem::offset_of!(FILE_RENAME_INFO, FileName);
        let buffer_len = header_len + name.len() * mem::size_of::<u16>();
        let mut buffer = vec![0usize; buffer_len.div_ceil(mem::size_of::<usize>())];
        let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*rename).Anonymous.ReplaceIfExists = true;
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

    pub(super) fn verify_current(file: &std::fs::File, directory: bool) -> io::Result<()> {
        PrivateSecurity::new(directory)?.verify(file)
    }

    pub(super) fn open_directory_for_sync(path: &Path) -> io::Result<std::fs::File> {
        open_directory(
            path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        write_private_file_atomic_with_observer(&path, b"spend-capable", |staging| {
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
        let mut file = super::windows_acl::create_file_with_observer(&path, false, |created| {
            assert_eq!(
                created.metadata()?.len(),
                0,
                "observer runs before any secret byte"
            );
            unsafe { assert_private_acl(created, false) };
            Ok(())
        })
        .unwrap();
        file.write_all(b"spend-capable checkpoint").unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::read(path).unwrap(), b"spend-capable checkpoint");
    }

    #[test]
    fn windows_creation_verification_failure_precedes_secret_write() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("must-not-survive");
        let err = super::windows_acl::create_file_with_observer(&path, false, |created| {
            assert_eq!(created.metadata()?.len(), 0);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected creation-time ACL verification failure",
            ))
        })
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
