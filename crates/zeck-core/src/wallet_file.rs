//! Read-only wallet loading shared by desktop and CLI imports.

use secrecy::Zeroize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    ops::Deref,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;

/// Stable identity for the opened wallet object. Fields stay private so IPC
/// callers cannot manufacture authority from a path, digest, or inode.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletFileIdentity {
    len: u64,
    sha256: [u8; 32],
    object: FileObjectId,
}

#[derive(Clone, PartialEq, Eq)]
pub enum FileObjectId {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { volume_serial: u32, file_index: u64 },
}

/// Bytes and identity captured from the same open file handle. Deliberately
/// has no Debug, Clone, or Serialize implementation.
pub struct WalletFileSnapshot {
    bytes: WalletFileBytes,
    identity: WalletFileIdentity,
}

impl WalletFileSnapshot {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn identity(&self) -> &WalletFileIdentity {
        &self.identity
    }

    pub fn into_bytes(self) -> WalletFileBytes {
        self.bytes
    }
}

/// Raw wallet bytes may contain plaintext spending keys. Keep them in one
/// allocation and scrub that allocation on success and on read errors.
/// Deliberately has no Debug or Clone implementation.
pub struct WalletFileBytes(Vec<u8>);

impl Deref for WalletFileBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for WalletFileBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn read_wallet_file(path: impl AsRef<Path>) -> io::Result<WalletFileBytes> {
    read_wallet_snapshot(path).map(WalletFileSnapshot::into_bytes)
}

pub fn read_wallet_snapshot(path: impl AsRef<Path>) -> io::Result<WalletFileSnapshot> {
    let path = path.as_ref();
    // Check before opening so a selected FIFO does not block waiting for a writer.
    require_regular(&fs::metadata(path)?)?;
    let file = File::open(path)?;
    // Check the opened handle too, in case the path changed before open.
    let before = file.metadata()?;
    require_regular(&before)?;
    let before_object = file_object_id(&before)?;
    let bytes = read_sized(&file, before.len())?;
    let after = file.metadata()?;
    require_regular(&after)?;
    let after_object = file_object_id(&after)?;
    if before.len() != after.len() || before_object != after_object {
        return Err(wallet_changed_while_reading());
    }
    let sha256 = Sha256::digest(&*bytes);
    Ok(WalletFileSnapshot {
        identity: WalletFileIdentity {
            len: after.len(),
            sha256: sha256.into(),
            object: after_object,
        },
        bytes,
    })
}

pub fn verify_wallet_snapshot(
    path: impl AsRef<Path>,
    expected: &WalletFileIdentity,
) -> io::Result<WalletFileSnapshot> {
    let snapshot = read_wallet_snapshot(path).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("wallet changed since review; inspect it again: {err}"),
        )
    })?;
    // Always perform each comparison before deciding. This keeps the logical
    // comparison order independent of which identity field changed.
    let same_len = snapshot.identity.len == expected.len;
    let same_digest = snapshot.identity.sha256 == expected.sha256;
    let same_object = snapshot.identity.object == expected.object;
    if !(same_len & same_digest & same_object) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet changed since review; inspect it again",
        ));
    }
    Ok(snapshot)
}

fn wallet_changed_while_reading() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "wallet changed while reading; retry with a stable backup",
    )
}

#[cfg(unix)]
fn file_object_id(metadata: &fs::Metadata) -> io::Result<FileObjectId> {
    Ok(FileObjectId::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn file_object_id(metadata: &fs::Metadata) -> io::Result<FileObjectId> {
    Ok(FileObjectId::Windows {
        volume_serial: metadata
            .volume_serial_number()
            .ok_or_else(|| io::Error::other("wallet volume identity is unavailable"))?,
        file_index: metadata
            .file_index()
            .ok_or_else(|| io::Error::other("wallet file identity is unavailable"))?,
    })
}

#[cfg(not(any(unix, windows)))]
fn file_object_id(_metadata: &fs::Metadata) -> io::Result<FileObjectId> {
    Err(io::Error::other(
        "wallet object identity is unsupported on this platform",
    ))
}

fn require_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wallet must be a regular file",
        ));
    }
    Ok(())
}

fn read_sized(mut reader: impl Read, size: u64) -> io::Result<WalletFileBytes> {
    let size = usize::try_from(size)
        .map_err(|_| io::Error::other("wallet is too large for this platform"))?;
    let mut bytes = WalletFileBytes(Vec::new());
    bytes
        .0
        .try_reserve_exact(size)
        .map_err(|_| io::Error::other("not enough memory to read this wallet"))?;
    bytes.0.resize(size, 0);
    reader.read_exact(&mut bytes.0)?;
    // Never grow a secret-bearing buffer: reallocation would leave an
    // unscrubbed copy behind. Ask for a stable backup if the file grows.
    let mut extra = [0u8; 1];
    let result = reader.read(&mut extra);
    extra.zeroize();
    if result? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet changed while reading; retry with a stable backup",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_regular_files_without_modification() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"synthetic wallet").unwrap();
        assert_eq!(
            &*read_wallet_file(file.path()).unwrap(),
            b"synthetic wallet"
        );
    }

    #[test]
    fn accepts_regular_wallet_larger_than_the_removed_ceiling() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let len = 256 * 1024 * 1024 + 1;
        file.as_file().set_len(len).unwrap();
        assert_eq!(read_wallet_file(file.path()).unwrap().len() as u64, len);
    }

    #[test]
    fn rejects_growth_without_returning_a_truncated_wallet() {
        assert!(read_sized(std::io::Cursor::new(b"12345"), 4).is_err());
    }

    #[test]
    fn rejects_shrinking_file_and_preserves_read_errors() {
        let result = read_sized(std::io::Cursor::new(b"123"), 4);
        assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reads_empty_file() {
        assert!(read_sized(std::io::empty(), 0).unwrap().is_empty());
    }

    #[test]
    fn rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_wallet_file(dir.path()).is_err());
    }

    #[test]
    fn same_length_mutation_requires_new_wallet_review() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"wallet-A").unwrap();
        let reviewed = read_wallet_snapshot(file.path()).unwrap();
        std::fs::write(file.path(), b"wallet-B").unwrap();

        let err = verify_wallet_snapshot(file.path(), reviewed.identity())
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("wallet changed since review"));
    }

    #[cfg(unix)]
    #[test]
    fn identical_bytes_in_replaced_inode_require_new_wallet_review() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        std::fs::write(&path, b"identical wallet bytes").unwrap();
        let reviewed = read_wallet_snapshot(&path).unwrap();
        let replacement = dir.path().join("replacement.dat");
        std::fs::write(&replacement, b"identical wallet bytes").unwrap();
        std::fs::rename(replacement, &path).unwrap();

        let err = verify_wallet_snapshot(&path, reviewed.identity())
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("wallet changed since review"));
    }

    #[test]
    fn growth_or_shrink_during_read_is_rejected() {
        assert!(read_sized(std::io::Cursor::new(b"12345"), 4).is_err());
        let result = read_sized(std::io::Cursor::new(b"123"), 4);
        assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn wallet_snapshot_still_accepts_files_over_256_mib() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let len = 256 * 1024 * 1024 + 1;
        file.as_file().set_len(len).unwrap();
        assert_eq!(
            read_wallet_snapshot(file.path()).unwrap().bytes().len() as u64,
            len
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_device_without_reading_it() {
        assert!(read_wallet_file("/dev/zero").is_err());
    }
}
