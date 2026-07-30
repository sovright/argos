use crate::error::ImportError;

/// Berkeley DB btree magic. Stable across BDB versions; the *page* format
/// is what differs, and zcashd uses BDB 6.2.
const BDB_BTREE_MAGIC: u32 = 0x0005_3162;

/// Offset of the magic within the BDB metadata page.
const BDB_MAGIC_OFFSET: usize = 12;

/// ZecWallet Lite files begin with a u64 little-endian version. Anything
/// at or below this is a plausible ZWL version; real files are far lower.
/// Used only to reject obvious junk, since ZWL has no magic number.
const ZWL_MAX_PLAUSIBLE_VERSION: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletFormat {
    Zcashd,
    ZecwalletLite,
}

/// Identify a wallet file from its leading bytes.
///
/// Checks BDB first because it has a real magic number. ZecWallet Lite has
/// none, so it is inferred from a plausible leading version word — which
/// means a corrupt zcashd file could in principle be misread as ZWL. The
/// ZWL parser rejects it immediately in that case.
pub fn sniff(bytes: &[u8]) -> Result<WalletFormat, ImportError> {
    if let Some(magic) = bytes.get(BDB_MAGIC_OFFSET..BDB_MAGIC_OFFSET + 4) {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(magic);
        // BDB writes the metadata page in host byte order, so a wallet
        // written on a big-endian machine is still valid. Accept both.
        if u32::from_le_bytes(buf) == BDB_BTREE_MAGIC || u32::from_be_bytes(buf) == BDB_BTREE_MAGIC
        {
            return Ok(WalletFormat::Zcashd);
        }
    }

    if let Some(head) = bytes.get(0..8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(head);
        if u64::from_le_bytes(buf) <= ZWL_MAX_PLAUSIBLE_VERSION {
            return Ok(WalletFormat::ZecwalletLite);
        }
    }

    Err(ImportError::UnrecognizedFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Berkeley DB btree magic 0x00053162, little-endian at offset 12.
    fn bdb_header() -> Vec<u8> {
        let mut v = vec![0u8; 4096];
        v[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        v
    }

    #[test]
    fn detects_zcashd_from_bdb_magic() {
        assert_eq!(sniff(&bdb_header()).unwrap(), WalletFormat::Zcashd);
    }

    #[test]
    fn detects_bdb_magic_in_big_endian() {
        let mut v = vec![0u8; 4096];
        v[12..16].copy_from_slice(&0x0005_3162u32.to_be_bytes());
        assert_eq!(sniff(&v).unwrap(), WalletFormat::Zcashd);
    }

    #[test]
    fn rejects_a_file_that_is_neither() {
        let junk = vec![0xAAu8; 4096];
        assert_eq!(sniff(&junk).unwrap_err(), ImportError::UnrecognizedFormat);
    }

    #[test]
    fn rejects_a_file_too_short_to_have_a_header() {
        assert_eq!(
            sniff(&[0u8; 4]).unwrap_err(),
            ImportError::UnrecognizedFormat
        );
    }

    #[test]
    fn real_golden_fixtures_are_detected_as_zcashd() {
        for name in [
            "sprout-plaintext",
            "sprout-encrypted",
            "modern-plaintext",
            "modern-encrypted",
        ] {
            let path = format!("tests/fixtures/{name}.dat");
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(sniff(&bytes).unwrap(), WalletFormat::Zcashd, "{name}");
        }
    }
}
