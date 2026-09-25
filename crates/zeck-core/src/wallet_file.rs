//! Read-only wallet loading shared by desktop and CLI imports.

use secrecy::Zeroize;
use std::{
    fs::{self, File},
    io::{self, Read},
    ops::Deref,
    path::Path,
};

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
    let path = path.as_ref();
    // Check before opening so a selected FIFO does not block waiting for a writer.
    require_regular(&fs::metadata(path)?)?;
    let file = File::open(path)?;
    // Check the opened handle too, in case the path changed before open.
    let metadata = file.metadata()?;
    require_regular(&metadata)?;
    read_sized(file, metadata.len())
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

    #[cfg(unix)]
    #[test]
    fn rejects_device_without_reading_it() {
        assert!(read_wallet_file("/dev/zero").is_err());
    }
}
