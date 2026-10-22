//! Fail-closed filesystem primitives for spend-capable recovery artifacts.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
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
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
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
        file.set_permissions(fs::Permissions::from_mode(0o600))
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
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_APPEND_DATA, FILE_GENERIC_WRITE, READ_CONTROL, WRITE_DAC,
        };
        let data_access = if mode == PrivateOpenMode::Append {
            FILE_APPEND_DATA
        } else {
            FILE_GENERIC_WRITE
        };
        options.access_mode(data_access | READ_CONTROL | WRITE_DAC);
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

    if let Err(err) = harden(&file) {
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
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let temporary = private_temporary(path);
    let result = (|| {
        let mut file = open_private_file(&temporary, PrivateOpenMode::CreateNew)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        // Preflight the platform-specific directory handle before changing
        // the name. A bad Windows directory open must not turn a completed
        // replacement into a reported failure.
        let parent_sync = open_parent_sync_handle(parent)?;
        parent_sync.sync_all()?;
        // The create-new handle was already hardened and verified. Windows
        // creation grants FILE_SHARE_DELETE, so keep that exact verified
        // object open across the rename instead of reopening by path.
        fs::rename(&temporary, path)?;
        parent_sync.sync_all()?;
        drop(file);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn open_parent_sync_handle(parent: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        File::open(parent)
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

fn private_temporary(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private");
    path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()))
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
            CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS,
            ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
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
            CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ALL_ACCESS, FILE_APPEND_DATA,
            FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
            WRITE_DAC,
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
                access | READ_CONTROL | WRITE_DAC,
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

    fn create_directory(path: &Path) -> io::Result<()> {
        let security = PrivateSecurity::new(true)?;
        let path_wide = wide(path)?;
        if unsafe { CreateDirectoryW(path_wide.as_ptr(), security.attributes()) } == 0 {
            return Err(last_error());
        }
        let directory = open_directory(path, READ_CONTROL | WRITE_DAC)?;
        security.verify(&directory)
    }

    pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
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
        for directory in missing.iter().rev() {
            match create_directory(directory) {
                Ok(()) => {}
                Err(err)
                    if err
                        .raw_os_error()
                        .map(|code| code as u32)
                        .is_some_and(|code| {
                            code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS
                        }) =>
                {
                    harden_directory(directory)?;
                }
                Err(err) => return Err(err),
            }
        }
        harden_directory(&path)
    }

    fn open_directory(path: &Path, access: u32) -> io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(access)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        options.open(path)
    }

    pub(super) fn harden_directory(path: &Path) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory must not be a symlink or non-directory",
            ));
        }
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
            FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            READ_CONTROL, WRITE_DAC,
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
