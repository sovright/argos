//! Bounded reads of untrusted wallet files, shared by desktop and CLI imports.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

/// Limit the raw wallet allocation before parsing. Larger backups must be
/// handled separately rather than risking exhaustion of the recovery process.
pub const MAX_WALLET_FILE_BYTES: u64 = 256 * 1024 * 1024;

pub fn read_wallet_file(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wallet must be a regular file",
        ));
    }
    if metadata.len() > MAX_WALLET_FILE_BYTES {
        return Err(too_large(MAX_WALLET_FILE_BYTES));
    }
    // Metadata alone is insufficient: the file can grow after this check.
    read_limited(file, MAX_WALLET_FILE_BYTES)
}

fn too_large(limit: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("wallet file exceeds the {limit}-byte safety limit"),
    )
}

fn read_limited(reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(too_large(limit));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_regular_files_and_rejects_oversized_sparse_files() {
        let path = std::env::temp_dir().join(format!(
            "argos-wallet-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Remove the synthetic file even if an assertion fails.
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let _cleanup = Cleanup(path.clone());
        std::io::Write::write_all(&mut file, b"synthetic wallet").unwrap();
        assert_eq!(read_wallet_file(&path).unwrap(), b"synthetic wallet");
        file.set_len(MAX_WALLET_FILE_BYTES + 1).unwrap();
        assert_eq!(
            read_wallet_file(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn accepts_bytes_up_to_the_limit_without_modification() {
        for bytes in [b"".as_slice(), b"wallet", b"12345678"] {
            assert_eq!(read_limited(Cursor::new(bytes), 8).unwrap(), bytes);
        }
    }

    #[test]
    fn rejects_oversized_input_instead_of_returning_truncated_wallet() {
        let error = read_limited(Cursor::new(b"123456789"), 8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stops_reading_after_the_limit_even_if_input_keeps_growing() {
        let mut reader = Cursor::new(vec![0; 1024]);
        assert!(read_limited(&mut reader, 8).is_err());
        assert_eq!(reader.position(), 9);
    }

    #[test]
    fn preserves_read_failures() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "fixture"))
            }
        }
        assert_eq!(
            read_limited(Broken, 8).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
