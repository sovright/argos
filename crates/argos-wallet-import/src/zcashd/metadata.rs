//! Key creation times from zcashd's `CKeyMetadata` records.
//!
//! zcashd writes one metadata record beside every key it holds:
//!
//! | record        | record key                                | describes        |
//! |---------------|-------------------------------------------|------------------|
//! | `keymeta`     | `CPubKey` (CompactSize(len) \|\| pubkey)  | `key` / `ckey`   |
//! | `zkeymeta`    | `SproutPaymentAddress` (64 bytes)         | `zkey` / `czkey` |
//! | `sapzkeymeta` | `SaplingIncomingViewingKey` (32 bytes)    | `sapzkey` / `csapzkey` |
//!
//! Each record key's remainder is byte-for-byte the remainder of the key
//! record it describes (verified against the golden fixtures), so the two are
//! joined on that remainder. The value is
//! `int32 nVersion; int64 nCreateTime;` and, from `VERSION_WITH_HDDATA` (10),
//! `string hdKeypath; uint256 seedFp` (`src/wallet/walletdb.h`).
//!
//! These records are never encrypted, even in an encrypted wallet: only the
//! secret half of a key is. So one index serves both collectors.
//!
//! The time is used to decide where a scan may start, and a time later than
//! the key's real age would hide notes from that scan. Anything that does not
//! parse cleanly therefore yields no time at all rather than a best guess.

use std::collections::HashMap;

use crate::{error::ImportDiagnostic, zcashd::records::compact_size};

/// Times at or before this are not creation times. zcashd writes
/// `nCreateTime = 1` for a key whose birth it does not know
/// (`importprivkey`, `z_importkey`), and 0 appears in the same role. The
/// bound is the mainnet genesis block's timestamp (2016-10-28): no Zcash key
/// can be older than the chain, so every such value means "unknown".
pub const UNKNOWN_CREATE_TIME_AT_OR_BEFORE: i64 = 1_477_641_360;

/// Times after this are treated as corrupt. A creation time centuries out is
/// not a clock error; accepting it would put a scan's start past the chain
/// tip. 2100-01-01T00:00:00Z.
const LATEST_PLAUSIBLE_CREATE_TIME: i64 = 4_102_444_800;

/// `CKeyMetadata::VERSION_WITH_HDDATA`: from this version on the value also
/// carries an HD keypath and a seed fingerprint.
const VERSION_WITH_HDDATA: i32 = 10;

/// The three metadata record types and the key records each describes.
const METADATA_RECORDS: [&str; 3] = ["keymeta", "zkeymeta", "sapzkeymeta"];

/// Which pool a metadata record describes. Kept distinct so a Sapling ivk and
/// a Sprout address that happened to share bytes could not be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataKind {
    Transparent,
    Sprout,
    Sapling,
}

impl MetadataKind {
    fn of_record(record_type: &str) -> Option<Self> {
        match record_type {
            "keymeta" => Some(Self::Transparent),
            "zkeymeta" => Some(Self::Sprout),
            "sapzkeymeta" => Some(Self::Sapling),
            _ => None,
        }
    }
}

/// Creation times, keyed by pool and the record-key remainder that names
/// the key.
#[derive(Debug, Default)]
pub struct KeyMetadataIndex {
    times: HashMap<(MetadataKind, Vec<u8>), i64>,
}

impl KeyMetadataIndex {
    /// Index every metadata record in `pairs`.
    ///
    /// A record that does not parse is reported through `diagnostics` and
    /// left out, so its key ends up with no creation time. Records whose time
    /// zcashd itself marks as unknown are left out silently: that is the
    /// normal state of an imported key, not damage to the file.
    pub fn build(
        pairs: &[(Vec<u8>, Vec<u8>)],
        mut diagnostics: Option<&mut Vec<ImportDiagnostic>>,
    ) -> Self {
        let mut index = Self::default();
        for (raw_key, value) in pairs {
            let Some(rec) = crate::zcashd::records::parse_record_key(raw_key) else {
                continue;
            };
            let Some(kind) = MetadataKind::of_record(&rec.record_type) else {
                continue;
            };
            match parse_create_time(value) {
                Ok(Some(time)) => {
                    index.times.insert((kind, rec.rest), time);
                }
                Ok(None) => {}
                Err(reason) => {
                    if let Some(diagnostics) = diagnostics.as_deref_mut() {
                        diagnostics.push(ImportDiagnostic::UnreadableKeyMetadata {
                            record_type: rec.record_type,
                            reason: reason.to_owned(),
                        });
                    }
                }
            }
        }
        index
    }

    /// The creation time recorded for the key whose record-key remainder is
    /// `identifier`, if one is known.
    pub fn created_at(&self, kind: MetadataKind, identifier: &[u8]) -> Option<i64> {
        self.times.get(&(kind, identifier.to_vec())).copied()
    }
}

/// Whether `record_type` is one of the metadata records read here.
pub fn is_metadata_record(record_type: &str) -> bool {
    METADATA_RECORDS.contains(&record_type)
}

/// Read `nCreateTime` from a `CKeyMetadata` value.
///
/// `Ok(None)` for zcashd's own "unknown" marker; `Err` for a value that is
/// not a well-formed `CKeyMetadata`. Trailing bytes are allowed, as zcashd's
/// deserializer allows them, so a later version that appends fields still
/// reads.
fn parse_create_time(value: &[u8]) -> Result<Option<i64>, &'static str> {
    let version = value
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_le_bytes)
        .ok_or("value is too short for a version")?;
    if version < 1 {
        return Err("version is not positive");
    }
    let time = value
        .get(4..12)
        .and_then(|b| b.try_into().ok())
        .map(i64::from_le_bytes)
        .ok_or("value is too short for a creation time")?;

    if version >= VERSION_WITH_HDDATA {
        // Not used, but required to be present: a value cut short here is a
        // damaged record, and a damaged record's time is not trusted either.
        let rest = value.get(12..).ok_or("HD data is missing")?;
        let (len, consumed) = compact_size(rest).ok_or("HD keypath length is missing")?;
        let path_end = usize::try_from(len)
            .ok()
            .and_then(|len| consumed.checked_add(len))
            .ok_or("HD keypath length overflows")?;
        let fp_end = path_end
            .checked_add(32)
            .ok_or("HD keypath length overflows")?;
        rest.get(path_end..fp_end)
            .ok_or("HD keypath or seed fingerprint is truncated")?;
    }

    if time <= UNKNOWN_CREATE_TIME_AT_OR_BEFORE {
        return Ok(None);
    }
    if time > LATEST_PLAUSIBLE_CREATE_TIME {
        return Err("creation time is implausibly far in the future");
    }
    Ok(Some(time))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `CKeyMetadata` value as zcashd writes it at version 10.
    fn metadata_v10(time: i64, keypath: &str) -> Vec<u8> {
        let mut v = 10i32.to_le_bytes().to_vec();
        v.extend_from_slice(&time.to_le_bytes());
        v.push(keypath.len() as u8);
        v.extend_from_slice(keypath.as_bytes());
        v.extend_from_slice(&[0x5A; 32]);
        v
    }

    fn record(kind: &str, key_rest: &[u8], value: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut k = vec![kind.len() as u8];
        k.extend_from_slice(kind.as_bytes());
        k.extend_from_slice(key_rest);
        (k, value)
    }

    #[test]
    fn a_well_formed_record_yields_its_time() {
        assert_eq!(
            parse_create_time(&metadata_v10(1_785_406_081, "m/32'/1'/0'")),
            Ok(Some(1_785_406_081))
        );
        // Version 1 carries only the version and the time.
        let mut v1 = 1i32.to_le_bytes().to_vec();
        v1.extend_from_slice(&1_600_000_000i64.to_le_bytes());
        assert_eq!(parse_create_time(&v1), Ok(Some(1_600_000_000)));
    }

    /// zcashd's `z_importkey` / `importprivkey` write `nCreateTime = 1`. That
    /// is "unknown", and must come back as no time — never as 1970, which a
    /// caller could read as "scan from the start" today but which is not a
    /// fact about the key, and never as a diagnostic, because nothing is
    /// wrong with the file.
    #[test]
    fn zcashds_unknown_marker_is_no_time_and_no_diagnostic() {
        for time in [0, 1, UNKNOWN_CREATE_TIME_AT_OR_BEFORE, -5] {
            assert_eq!(
                parse_create_time(&metadata_v10(time, "")),
                Ok(None),
                "{time}"
            );
        }
        assert_eq!(
            parse_create_time(&metadata_v10(UNKNOWN_CREATE_TIME_AT_OR_BEFORE + 1, "")),
            Ok(Some(UNKNOWN_CREATE_TIME_AT_OR_BEFORE + 1))
        );

        let mut diagnostics = Vec::new();
        let index = KeyMetadataIndex::build(
            &[record("zkeymeta", &[0xAB; 64], metadata_v10(1, ""))],
            Some(&mut diagnostics),
        );
        assert_eq!(index.created_at(MetadataKind::Sprout, &[0xAB; 64]), None);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn a_truncated_record_is_no_time_and_a_diagnostic() {
        let whole = metadata_v10(1_785_406_081, "m/32'/1'/0'");
        // Every proper prefix is damaged: short of the version, short of the
        // time, or short of the HD data that version 10 promises.
        for cut in 0..whole.len() {
            assert!(
                parse_create_time(&whole[..cut]).is_err(),
                "a {cut}-byte prefix must not parse"
            );
        }

        let mut diagnostics = Vec::new();
        let index = KeyMetadataIndex::build(
            &[record("sapzkeymeta", &[0x11; 32], whole[..20].to_vec())],
            Some(&mut diagnostics),
        );
        assert_eq!(index.created_at(MetadataKind::Sapling, &[0x11; 32]), None);
        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(
            &diagnostics[0],
            ImportDiagnostic::UnreadableKeyMetadata { record_type, .. } if record_type == "sapzkeymeta"
        ));
    }

    #[test]
    fn garbage_is_refused_not_guessed() {
        let mut bad_version = metadata_v10(1_785_406_081, "");
        bad_version[..4].copy_from_slice(&0i32.to_le_bytes());
        assert!(parse_create_time(&bad_version).is_err());

        // A keypath length that runs past the end.
        let mut long_path = 10i32.to_le_bytes().to_vec();
        long_path.extend_from_slice(&1_785_406_081i64.to_le_bytes());
        long_path.push(0xFF);
        long_path.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_create_time(&long_path).is_err());

        assert!(parse_create_time(&metadata_v10(LATEST_PLAUSIBLE_CREATE_TIME + 1, "")).is_err());
        assert!(parse_create_time(&metadata_v10(i64::MAX, "")).is_err());
    }

    #[test]
    fn trailing_bytes_are_allowed() {
        let mut v = metadata_v10(1_785_406_081, "m/0");
        v.extend_from_slice(&[0xEE; 7]);
        assert_eq!(parse_create_time(&v), Ok(Some(1_785_406_081)));
    }

    /// A Sapling ivk and the first bytes of something else must not collide:
    /// lookups are per pool.
    #[test]
    fn lookups_are_per_pool_and_exact() {
        let index = KeyMetadataIndex::build(
            &[
                record("sapzkeymeta", &[0x22; 32], metadata_v10(1_700_000_000, "")),
                record("keymeta", &[0x22; 32], metadata_v10(1_700_000_500, "")),
            ],
            None,
        );
        assert_eq!(
            index.created_at(MetadataKind::Sapling, &[0x22; 32]),
            Some(1_700_000_000)
        );
        assert_eq!(
            index.created_at(MetadataKind::Transparent, &[0x22; 32]),
            Some(1_700_000_500)
        );
        assert_eq!(index.created_at(MetadataKind::Sprout, &[0x22; 32]), None);
        assert_eq!(index.created_at(MetadataKind::Sapling, &[0x22; 31]), None);
    }
}
