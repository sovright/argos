//! zcashd wallet record decoding.
//!
//! Record keys are Bitcoin-style serialized pairs: a CompactSize-prefixed
//! type string followed by type-specific key material.

/// A record key split into its type string and the bytes that follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    pub record_type: String,
    pub rest: Vec<u8>,
}

/// Read a Bitcoin CompactSize integer. Returns `(value, bytes_consumed)`.
///
/// Returns `None` rather than panicking on truncated input — this parses
/// attacker-controlled bytes.
pub fn compact_size(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    match first {
        0..=0xfc => Some((u64::from(first), 1)),
        0xfd => {
            let s = bytes.get(1..3)?;
            let mut b = [0u8; 2];
            b.copy_from_slice(s);
            Some((u64::from(u16::from_le_bytes(b)), 3))
        }
        0xfe => {
            let s = bytes.get(1..5)?;
            let mut b = [0u8; 4];
            b.copy_from_slice(s);
            Some((u64::from(u32::from_le_bytes(b)), 5))
        }
        _ => {
            let s = bytes.get(1..9)?;
            let mut b = [0u8; 8];
            b.copy_from_slice(s);
            Some((u64::from_le_bytes(b), 9))
        }
    }
}

/// Longest zcashd record type string; anything longer is not a record key.
const MAX_RECORD_TYPE_LEN: u64 = 32;

/// Split a raw record key into its type string and remainder.
pub fn parse_record_key(bytes: &[u8]) -> Option<RecordKey> {
    let (len, consumed) = compact_size(bytes)?;
    if len > MAX_RECORD_TYPE_LEN {
        return None;
    }
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    let name = bytes.get(consumed..end)?;
    let record_type = std::str::from_utf8(name).ok()?.to_owned();
    let rest = bytes.get(end..)?.to_vec();
    Some(RecordKey { record_type, rest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_reads_single_byte() {
        assert_eq!(compact_size(&[0x04]), Some((4, 1)));
    }

    #[test]
    fn compact_size_reads_two_byte_form() {
        assert_eq!(compact_size(&[0xfd, 0x01, 0x02]), Some((0x0201, 3)));
    }

    #[test]
    fn compact_size_rejects_truncated_input() {
        assert_eq!(compact_size(&[0xfd, 0x01]), None);
        assert_eq!(compact_size(&[]), None);
    }

    #[test]
    fn parses_a_zkey_record_key() {
        // CompactSize(4) "zkey" then a 64-byte Sprout payment address.
        let mut raw = vec![0x04];
        raw.extend_from_slice(b"zkey");
        raw.extend_from_slice(&[0xAB; 64]);
        let parsed = parse_record_key(&raw).unwrap();
        assert_eq!(parsed.record_type, "zkey");
        assert_eq!(parsed.rest.len(), 64);
    }

    #[test]
    fn returns_none_for_a_length_that_exceeds_the_buffer() {
        let raw = vec![0x40, b'z', b'k']; // claims 64 bytes, has 2
        assert!(parse_record_key(&raw).is_none());
    }

    #[test]
    fn golden_sprout_wallet_record_types_include_zkey_and_key() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let types: std::collections::BTreeSet<String> = pairs
            .iter()
            .filter_map(|(k, _)| parse_record_key(k))
            .map(|r| r.record_type)
            .collect();
        assert!(types.contains("zkey"), "types found: {types:?}");
        assert!(types.contains("key"), "types found: {types:?}");
    }

    #[test]
    fn golden_encrypted_sprout_wallet_has_czkey_and_mkey() {
        let bytes = std::fs::read("tests/fixtures/sprout-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let types: std::collections::BTreeSet<String> = pairs
            .iter()
            .filter_map(|(k, _)| parse_record_key(k))
            .map(|r| r.record_type)
            .collect();
        // walletdb.cpp:125 writes czkey and erases the plaintext zkey.
        assert!(types.contains("czkey"), "types found: {types:?}");
        assert!(types.contains("mkey"), "types found: {types:?}");
        assert!(!types.contains("zkey"), "plaintext zkey should be erased");
    }
}
