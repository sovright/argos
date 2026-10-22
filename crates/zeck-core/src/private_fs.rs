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
    }
    #[cfg(windows)]
    fs::create_dir_all(path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private filesystem permissions are unsupported on this platform",
    ));
    harden_private_directory(path)
}

/// Remove inherited/broad access from an existing private directory.
pub fn harden_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL, WRITE_DAC,
        };
        let directory = OpenOptions::new()
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        return windows_acl::harden(&directory, true);
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
        return file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    return windows_acl::harden(file, false);
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

fn open_private_file_with(
    path: &Path,
    mode: PrivateOpenMode,
    harden: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<File> {
    let (file, created) = match options_for(mode, true).open(path) {
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
        drop(file);
        fs::rename(&temporary, path)?;
        let final_file = options_for(PrivateOpenMode::Append, false).open(path)?;
        harden_private_file(&final_file)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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
    use std::{io, mem, os::windows::io::AsRawHandle, ptr};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE},
        Security::{
            AddAccessAllowedAceEx,
            Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, GetLengthSid, GetTokenInformation, InitializeAcl, TokenUser,
            WinLocalSystemSid, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE,
            TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn last_error() -> io::Error {
        io::Error::last_os_error()
    }

    pub(super) fn harden(file: &std::fs::File, directory: bool) -> io::Result<()> {
        unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(last_error());
            }
            let token = OwnedHandle(token);
            let mut token_len = 0;
            let first = GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut token_len);
            if first != 0
                || io::Error::last_os_error().raw_os_error()
                    != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            {
                return Err(last_error());
            }
            let mut token_buffer =
                vec![0usize; (token_len as usize).div_ceil(mem::size_of::<usize>())];
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

            let mut system_buffer =
                vec![0usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(mem::size_of::<usize>())];
            let mut system_len = SECURITY_MAX_SID_SIZE;
            let system_sid: PSID = system_buffer.as_mut_ptr().cast();
            if CreateWellKnownSid(
                WinLocalSystemSid,
                ptr::null_mut(),
                system_sid,
                &mut system_len,
            ) == 0
            {
                return Err(last_error());
            }

            let ace_base = mem::size_of::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>()
                - mem::size_of::<u32>();
            let acl_len = mem::size_of::<ACL>()
                + ace_base * 2
                + GetLengthSid(user_sid) as usize
                + GetLengthSid(system_sid) as usize;
            let mut acl_buffer = vec![0usize; acl_len.div_ceil(mem::size_of::<usize>())];
            let acl = acl_buffer.as_mut_ptr().cast::<ACL>();
            if InitializeAcl(acl, acl_len as u32, ACL_REVISION) == 0 {
                return Err(last_error());
            }
            let flags = if directory {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                0
            };
            for sid in [user_sid, system_sid] {
                if AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FILE_ALL_ACCESS, sid) == 0 {
                    return Err(last_error());
                }
            }
            let status = SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            Ok(())
        }
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
        for index in 0..info.AceCount {
            let mut raw = ptr::null_mut();
            assert_ne!(GetAce(dacl, index, &mut raw), 0);
            let ace = &*(raw.cast::<ACCESS_ALLOWED_ACE>());
            assert_eq!(ace.Header.AceType, ACCESS_ALLOWED_ACE_TYPE);
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            assert!(EqualSid(sid, user) != 0 || EqualSid(sid, system) != 0);
            assert_eq!(EqualSid(sid, world), 0);
            assert_eq!(EqualSid(sid, users), 0);
            if directory {
                assert_eq!(
                    u32::from(ace.Header.AceFlags) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                );
            }
        }
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
}
