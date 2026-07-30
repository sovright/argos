use crate::error::ImportError;

/// Berkeley DB btree magic. Stable across BDB versions; the *page* format
/// is what differs, and zcashd uses BDB 6.2.
const BDB_BTREE_MAGIC: u32 = 0x0005_3162;

/// Offset of the magic within the BDB metadata page.
const BDB_MAGIC_OFFSET: usize = 12;

/// ZecWallet Lite files begin with a u64 little-endian version. Anything
/// at or below this is a plausible ZWL version; real files are far lower
/// (the true ceiling is 31, enforced by the ZWL parser itself). Used only
/// to reject obvious junk, since ZWL has no magic number.
const ZWL_MAX_PLAUSIBLE_VERSION: u64 = 1_000;

/// Shortest input that could be any wallet file. Below this we cannot even
/// read a BDB metadata header, so claiming a format would be guesswork.
const MIN_PLAUSIBLE_WALLET_LEN: usize = 16;

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
    // Too short to hold even a BDB header. Without this, an 8-to-15-byte
    // file skips the magic check entirely and falls through to the ZWL
    // heuristic, which would classify any such file with small leading
    // bytes as a wallet.
    if bytes.len() < MIN_PLAUSIBLE_WALLET_LEN {
        return Err(ImportError::UnrecognizedFormat);
    }

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
        let version = u64::from_le_bytes(buf);
        // Version 0 is excluded deliberately. A zcashd wallet whose BDB
        // magic is damaged still carries a Berkeley DB LSN in bytes 0..8,
        // and an unlogged database can hold LSN {0,0} — which reads here
        // as version 0. Classifying that as ZecWallet Lite would tell a
        // user with a corrupted zcashd wallet that they have a different
        // format entirely, sending them down the wrong recovery path. No
        // real ZWL wallet carries version 0.
        //
        // The committed zcashd fixtures carry LSN {0,1}, which reads as
        // 4294967296 and is already excluded by the upper bound.
        if (1..=ZWL_MAX_PLAUSIBLE_VERSION).contains(&version) {
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
    fn rejects_the_gap_between_a_zwl_version_word_and_a_bdb_header() {
        // 8..15 bytes is long enough to read a ZWL version word but too
        // short to reach the BDB magic at offset 12..16. Without a minimum
        // length these fell through and were claimed as ZecWallet Lite.
        for len in 8..MIN_PLAUSIBLE_WALLET_LEN {
            assert_eq!(
                sniff(&vec![0u8; len]).unwrap_err(),
                ImportError::UnrecognizedFormat,
                "a {len}-byte file must not be claimed as any wallet format"
            );
        }
    }

    #[test]
    fn a_damaged_zcashd_wallet_is_not_claimed_as_zecwallet_lite() {
        // A zcashd wallet with a destroyed BDB magic must report
        // "unrecognized", not "ZecWallet Lite" — telling someone with a
        // corrupted wallet that they have a different format sends them
        // down the wrong recovery path.
        //
        // LSN {0,0} is the case that matters: bytes 0..8 all zero read as
        // version 0, which the ZWL branch must not accept.
        let mut damaged = vec![0u8; 4096];
        damaged[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            sniff(&damaged).unwrap_err(),
            ImportError::UnrecognizedFormat
        );
    }

    #[test]
    fn still_detects_a_plausible_zecwallet_lite_version() {
        // The version-0 exclusion must not break real ZWL detection. The
        // true ceiling is 31; the ZWL parser enforces that, not the sniffer.
        for version in [1u64, 25, 31] {
            let mut v = vec![0u8; 4096];
            v[0..8].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                sniff(&v).unwrap(),
                WalletFormat::ZecwalletLite,
                "version {version} should sniff as ZecWallet Lite"
            );
        }
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
