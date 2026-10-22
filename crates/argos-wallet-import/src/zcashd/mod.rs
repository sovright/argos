//! zcashd wallet.dat record layer.

pub mod crypto;
pub mod encrypted;
pub mod metadata;
pub mod plaintext;
pub mod records;
pub mod seed;
pub mod sprout;

pub use crypto::{
    classify_encryption, derive_master_key, find_mkey, EncryptionMetadata, MasterKey, MkeyRecord,
};
pub use encrypted::collect_encrypted;
pub use metadata::{KeyMetadataIndex, MetadataKind, UNKNOWN_CREATE_TIME_AT_OR_BEFORE};
pub use plaintext::collect_plaintext;
pub use records::{compact_size, parse_record_key, RecordKey};
pub use sprout::collect_sprout_notes;

use std::collections::HashSet;

use secrecy::SecretString;

use crate::{
    bdb,
    error::{ImportDiagnostic, ImportError},
    keys::ImportedKeys,
};

/// Whether the wallet needs a passphrase. Reject damaged encryption metadata
/// before prompting, so a missing `mkey` cannot masquerade as plaintext.
pub fn needs_passphrase(bytes: &[u8]) -> Result<bool, ImportError> {
    let walk = bdb::walk(bytes)?;
    match classify_encryption(&walk.records) {
        EncryptionMetadata::Unencrypted => Ok(false),
        EncryptionMetadata::Encrypted(_) => Ok(true),
        EncryptionMetadata::Damaged { reason } => {
            Err(ImportError::DamagedEncryptionMetadata(reason))
        }
    }
}

/// Parse a zcashd `wallet.dat` into normalized key material.
///
/// Decryption happens here, once, before any caller touches the network:
/// a wallet needing a passphrase fails fast and locally.
pub fn import_zcashd(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let walk = bdb::walk(bytes)?;
    let walk_diagnostics = walk.diagnostics;
    let pairs = Records(walk.records);
    let master = match classify_encryption(&pairs) {
        EncryptionMetadata::Damaged { reason } => {
            return Err(ImportError::DamagedEncryptionMetadata(reason));
        }
        // Encrypted wallet: without a passphrase the encrypted records are
        // unreachable, and reporting partial plaintext results would let a
        // user believe they had recovered everything.
        EncryptionMetadata::Encrypted(mkey) => Some(derive_master_key(
            passphrase.ok_or(ImportError::WrongPassphrase)?,
            &mkey,
        )?),
        EncryptionMetadata::Unencrypted => None,
    };
    let mut out = import_records(&pairs, master.as_ref());
    out.diagnostics.splice(0..0, walk_diagnostics);

    let absence_already_explained = out.diagnostics.iter().any(|diagnostic| match diagnostic {
        ImportDiagnostic::UnrecoveredSeed { .. }
        | ImportDiagnostic::UnscannedSeedAccounts { .. }
        | ImportDiagnostic::MissingDerivedKeys { .. } => true,
        ImportDiagnostic::UnparseableRecord { record_type, .. }
        | ImportDiagnostic::DecryptionFailed { record_type, .. }
        | ImportDiagnostic::PublicIdentifierMismatch { record_type, .. }
        | ImportDiagnostic::LockedKey { record_type, .. } => matches!(
            record_type.as_str(),
            "key" | "zkey" | "sapzkey" | "ckey" | "czkey" | "csapzkey"
        ),
        _ => false,
    });
    if out.is_empty() && !absence_already_explained {
        out.diagnostics
            .push(ImportDiagnostic::MissingSpendAuthority {
                format: "Berkeley DB",
            });
    }

    Ok(out)
}

/// Every pass over the walked records. `master` is `Some` exactly when the
/// wallet is encrypted.
fn import_records(pairs: &[(Vec<u8>, Vec<u8>)], master: Option<&MasterKey>) -> ImportedKeys {
    let mut out = ImportedKeys::default();
    let mut recovered = collect_plaintext(pairs, &mut out);
    collect_sprout_notes(pairs, &mut out);
    if let Some(master) = master {
        recovered.extend(collect_encrypted(pairs, master, &mut out));
    }
    // Last: coverage is judged by key identity — a derived key counts only
    // if its metadata names this seed *and* the passes above actually
    // recovered it. A key record that merely exists but could not be read
    // or decrypted is not a key the user has.
    seed::assess_seed(pairs, master, &recovered, &mut out);
    out
}

/// The keys a collector actually recovered, named by the remainder of
/// their record key after the type: the serialized public key for
/// `key`/`ckey`, the incoming viewing key for `sapzkey`/`csapzkey`. Those
/// are byte-for-byte the keys of the matching `keymeta`/`sapzkeymeta`
/// records, which is how seed coverage joins the two.
#[derive(Default)]
pub struct RecoveredKeyIds {
    pub(crate) transparent: HashSet<Vec<u8>>,
    pub(crate) sapling: HashSet<Vec<u8>>,
}

impl RecoveredKeyIds {
    pub(crate) fn extend(&mut self, other: Self) {
        self.transparent.extend(other.transparent);
        self.sapling.extend(other.sapling);
    }
}

/// The walked records, scrubbed when dropped — on every exit, including the
/// early one for a missing passphrase.
///
/// They hold the plaintext `mnemonicphrase` (which zcashd v6.20.0 leaves in
/// place even after `encryptwallet`) and, for an unencrypted wallet, every
/// raw key. The parsed keys the caller keeps are wrapped in `Secret`; these
/// copies were otherwise left in freed heap for the life of the process.
struct Records(Vec<(Vec<u8>, Vec<u8>)>);

impl std::ops::Deref for Records {
    type Target = [(Vec<u8>, Vec<u8>)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        use secrecy::Zeroize;
        for (key, value) in &mut self.0 {
            key.zeroize();
            value.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ImportDiagnostic;
    use secrecy::SecretString;

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap()
    }

    fn mkey_record(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        bdb::walk(bytes)
            .unwrap()
            .records
            .into_iter()
            .find(|(key, _)| parse_record_key(key).is_some_and(|r| r.record_type == "mkey"))
            .expect("golden encrypted wallet has an mkey")
    }

    fn replace_unique(bytes: &mut [u8], original: &[u8], replacement: &[u8]) {
        assert_eq!(original.len(), replacement.len());
        let offsets: Vec<_> = bytes
            .windows(original.len())
            .enumerate()
            .filter_map(|(index, window)| (window == original).then_some(index))
            .collect();
        assert_eq!(offsets.len(), 1, "fixture record must occur exactly once");
        bytes[offsets[0]..offsets[0] + original.len()].copy_from_slice(replacement);
    }

    fn assert_damaged_encryption(bytes: &[u8]) {
        let err = import_zcashd(bytes, None).unwrap_err();
        let ImportError::DamagedEncryptionMetadata(reason) = &err else {
            panic!("expected damaged encryption metadata, got {err}");
        };
        assert!(reason.contains("mkey"), "reason must name mkey");
        assert!(
            reason.contains("encrypted records"),
            "reason must name encrypted records"
        );
        assert!(err.to_string().contains("Keep the original wallet file"));
    }

    #[test]
    fn encrypted_records_with_truncated_mkey_are_damaged_not_plaintext() {
        let mut bytes = read("modern-encrypted");
        let (_, value) = mkey_record(&bytes);
        let mut malformed = value.clone();
        malformed[0] = 0xfc; // impossible ciphertext length within this record
        replace_unique(&mut bytes, &value, &malformed);
        assert_damaged_encryption(&bytes);
    }

    #[test]
    fn encrypted_records_without_mkey_are_damaged_not_plaintext() {
        let mut bytes = read("modern-encrypted");
        let (key, _) = mkey_record(&bytes);
        let mut renamed = key.clone();
        renamed[1..5].copy_from_slice(b"xkey");
        replace_unique(&mut bytes, &key, &renamed);
        assert_damaged_encryption(&bytes);
    }

    #[test]
    fn encrypted_seed_record_without_mkey_is_damaged() {
        let pairs = bdb::walk(&read("modern-encrypted")).unwrap().records;
        let seed = pairs
            .into_iter()
            .find(|(key, _)| {
                parse_record_key(key).is_some_and(|r| {
                    matches!(r.record_type.as_str(), "chdseed" | "cmnemonicphrase")
                })
            })
            .expect("golden fixture has encrypted seed");
        let classification = crate::zcashd::crypto::classify_encryption(&[seed]);
        assert!(matches!(
            classification,
            crate::zcashd::crypto::EncryptionMetadata::Damaged { .. }
        ));
    }

    #[test]
    fn unsupported_mkey_kdf_is_damaged_metadata() {
        let pairs = bdb::walk(&read("modern-encrypted")).unwrap().records;
        let mut mkey = pairs
            .into_iter()
            .find(|(key, _)| parse_record_key(key).is_some_and(|r| r.record_type == "mkey"))
            .unwrap();
        let value = &mut mkey.1;
        let (key_len, key_offset) = compact_size(value).unwrap();
        let salt_offset = key_offset + key_len as usize;
        let method_offset = salt_offset + 1 + 8;
        value[method_offset..method_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            crate::zcashd::crypto::classify_encryption(&[mkey]),
            crate::zcashd::crypto::EncryptionMetadata::Damaged { .. }
        ));
    }

    #[test]
    fn malformed_mkey_ciphertext_shape_is_damaged_metadata() {
        let pairs = bdb::walk(&read("modern-encrypted")).unwrap().records;
        let mut mkey = pairs
            .into_iter()
            .find(|(key, _)| parse_record_key(key).is_some_and(|r| r.record_type == "mkey"))
            .unwrap();
        // Keep the serialized record well formed, but shrink the AES-CBC
        // ciphertext from the fixture's 48 bytes to an impossible 32 bytes.
        mkey.1.drain(33..49);
        mkey.1[0] = 32;
        assert!(matches!(
            crate::zcashd::crypto::classify_encryption(&[mkey]),
            crate::zcashd::crypto::EncryptionMetadata::Damaged { .. }
        ));
    }

    #[test]
    fn plaintext_wallet_without_encrypted_records_is_unencrypted() {
        let pairs = bdb::walk(&read("modern-plaintext")).unwrap().records;
        assert!(matches!(
            crate::zcashd::crypto::classify_encryption(&pairs),
            crate::zcashd::crypto::EncryptionMetadata::Unencrypted
        ));
    }

    #[test]
    fn needs_passphrase_propagates_damaged_encryption_metadata() {
        let mut bytes = read("modern-encrypted");
        let (key, _) = mkey_record(&bytes);
        let mut renamed = key.clone();
        renamed[1..5].copy_from_slice(b"xkey");
        replace_unique(&mut bytes, &key, &renamed);
        assert!(matches!(
            needs_passphrase(&bytes),
            Err(ImportError::DamagedEncryptionMetadata(_))
        ));
    }

    #[test]
    fn valid_empty_bdb_cannot_claim_complete_recovery() {
        let mut bytes = vec![0u8; 1024];
        bytes[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&512u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[88..92].copy_from_slice(&1u32.to_le_bytes());
        bytes[512 + 25] = bdb::PAGE_TYPE_LBTREE;

        let keys = import_zcashd(&bytes, None).expect("valid empty btree must parse");
        assert!(keys.is_empty());
        assert!(keys.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            crate::error::ImportDiagnostic::MissingSpendAuthority {
                format: "Berkeley DB"
            }
        )));
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn recognized_zcashd_without_spend_authority_is_key_material_missing() {
        // One valid BDB leaf containing only a zcashd `version` metadata
        // record. The container and record parse cleanly but have no keys.
        let mut bytes = vec![0u8; 1024];
        bytes[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&512u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[88..92].copy_from_slice(&1u32.to_le_bytes());
        let page = 512;
        bytes[page + 20..page + 22].copy_from_slice(&2u16.to_le_bytes());
        bytes[page + 25] = bdb::PAGE_TYPE_LBTREE;
        let key = b"\x07version";
        let value = 1u32.to_le_bytes();
        for (slot, offset, data) in [(0, 40u16, key.as_slice()), (1, 60, value.as_slice())] {
            let index = page + 26 + slot * 2;
            bytes[index..index + 2].copy_from_slice(&offset.to_le_bytes());
            let start = page + usize::from(offset);
            bytes[start..start + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
            bytes[start + 2] = 1; // BDB key/data leaf entry
            bytes[start + 3..start + 3 + data.len()].copy_from_slice(data);
        }

        let walk = bdb::walk(&bytes).expect("metadata-only BDB must parse");
        assert_eq!(walk.records.len(), 1);
        assert_eq!(
            parse_record_key(&walk.records[0].0).unwrap().record_type,
            "version"
        );
        assert!(walk.diagnostics.is_empty());

        let keys = import_zcashd(&bytes, None).unwrap();
        assert!(keys.is_empty());
        assert!(keys.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            ImportDiagnostic::MissingSpendAuthority {
                format: "Berkeley DB"
            }
        )));
        assert_eq!(
            keys.coverage(),
            crate::keys::ImportCoverage::KeyMaterialMissing
        );
    }

    #[test]
    fn unrelated_malformed_record_does_not_hide_missing_spend_authority() {
        // Valid metadata plus a record key that cannot identify any key
        // type. Its parse diagnostic says nothing about spending authority.
        let mut bytes = vec![0u8; 1024];
        bytes[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&512u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[88..92].copy_from_slice(&1u32.to_le_bytes());
        let page = 512;
        bytes[page + 20..page + 22].copy_from_slice(&4u16.to_le_bytes());
        bytes[page + 25] = bdb::PAGE_TYPE_LBTREE;
        let version = 1u32.to_le_bytes();
        for (slot, offset, data) in [
            (0, 40u16, b"\x07version".as_slice()),
            (1, 60, version.as_slice()),
            (2, 80, b"\xff".as_slice()),
            (3, 100, b"unrelated".as_slice()),
        ] {
            let index = page + 26 + slot * 2;
            bytes[index..index + 2].copy_from_slice(&offset.to_le_bytes());
            let start = page + usize::from(offset);
            bytes[start..start + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
            bytes[start + 2] = 1;
            bytes[start + 3..start + 3 + data.len()].copy_from_slice(data);
        }

        let keys = import_zcashd(&bytes, None).unwrap();
        assert!(keys.is_empty());
        assert!(keys.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            ImportDiagnostic::UnparseableRecord { record_type, .. }
                if record_type == "<unparseable>"
        )));
        assert!(keys.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            ImportDiagnostic::MissingSpendAuthority {
                format: "Berkeley DB"
            }
        )));
        assert_eq!(
            keys.coverage(),
            crate::keys::ImportCoverage::KeyMaterialMissing
        );
    }

    #[test]
    fn seed_only_wallet_keeps_its_specific_coverage_without_missing_authority() {
        // A structurally valid BDB leaf with only an unrecovered plaintext
        // HD seed. This specific warning already explains absent spend keys.
        let mut bytes = vec![0u8; 1024];
        bytes[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&512u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[88..92].copy_from_slice(&1u32.to_le_bytes());
        let page = 512;
        bytes[page + 20..page + 22].copy_from_slice(&2u16.to_le_bytes());
        bytes[page + 25] = bdb::PAGE_TYPE_LBTREE;
        let key = b"\x06hdseed";
        let value = [0x42u8; 32];
        for (slot, offset, data) in [(0, 40u16, key.as_slice()), (1, 60, value.as_slice())] {
            let index = page + 26 + slot * 2;
            bytes[index..index + 2].copy_from_slice(&offset.to_le_bytes());
            let start = page + usize::from(offset);
            bytes[start..start + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
            bytes[start + 2] = 1;
            bytes[start + 3..start + 3 + data.len()].copy_from_slice(data);
        }

        let keys = import_zcashd(&bytes, None).unwrap();
        assert!(keys.is_empty());
        assert!(keys
            .diagnostics
            .iter()
            .any(ImportDiagnostic::is_unrecovered_seed));
        assert!(!keys.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            ImportDiagnostic::MissingSpendAuthority { .. }
        )));
        assert_eq!(
            keys.coverage(),
            crate::keys::ImportCoverage::SeedNotRecovered
        );
    }

    /// The record key, after its type, of the first key whose metadata
    /// names a legacy-account keypath containing `branch`.
    fn derived_key_id(pairs: &[(Vec<u8>, Vec<u8>)], branch: &str) -> Vec<u8> {
        pairs
            .iter()
            .find_map(|(k, v)| {
                let r = parse_record_key(k)?;
                (r.record_type == "keymeta" && String::from_utf8_lossy(v).contains(branch))
                    .then_some(r.rest)
            })
            .expect("a derived key")
    }

    /// Cut the value of the `record_type` record whose key is `id` to `len`
    /// bytes: the record is still there, its key is not readable.
    fn truncate_record(pairs: &mut [(Vec<u8>, Vec<u8>)], record_type: &str, id: &[u8], len: usize) {
        let mut hit = 0;
        for (k, v) in pairs.iter_mut() {
            if parse_record_key(k).is_some_and(|r| r.record_type == record_type && r.rest == id) {
                v.truncate(len);
                hit += 1;
            }
        }
        assert_eq!(hit, 1, "exactly one {record_type} record is damaged");
    }

    fn assert_not_claimed_complete(keys: &ImportedKeys, pool: &str) {
        assert!(keys.seed_verified, "{:?}", keys.diagnostics);
        let note = keys
            .verified_seed_note()
            .expect("a verified seed has a note");
        assert!(
            !note.contains("every key it derived is read"),
            "an unread derived key must withdraw the claim, got: {note}"
        );
        assert!(keys.coverage().may_hide_funds(), "{:?}", keys.coverage());
        assert!(
            keys.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::MissingDerivedKeys { pool: p, expected, found }
                    if p.contains(pool) && *found + 1 == *expected
            )),
            "the unread key must not count as present: {:?}",
            keys.diagnostics
        );
    }

    /// Review round 3 on #230, finding 1. A derived key whose record merely
    /// existed counted as present, so a legacy external `key` record cut
    /// short — unreadable, its key not recovered — still read as "verified —
    /// every key it derived is read from this file".
    #[test]
    fn an_unreadable_derived_key_withdraws_the_verified_claim() {
        let mut pairs = bdb::walk(&read("modern-plaintext")).unwrap().records;
        let id = derived_key_id(&pairs, "/2147483647'/0/");
        truncate_record(&mut pairs, "key", &id, 10);
        let keys = import_records(&pairs, None);
        assert!(
            keys.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::UnparseableRecord { record_type, .. } if record_type == "key"
            )),
            "{:?}",
            keys.diagnostics
        );
        assert_not_claimed_complete(&keys, "external");
    }

    /// An unreadable `keymeta` costs its key only a creation time, so by
    /// itself it grades Complete and is not a seed finding. But it can no
    /// longer vouch for a derived key, and that shortfall is graded where it
    /// belongs: as a missing derived key, not by the metadata diagnostic.
    #[test]
    fn unreadable_metadata_on_a_derived_key_is_graded_by_the_seed_check() {
        let mut pairs = bdb::walk(&read("modern-plaintext")).unwrap().records;
        let id = derived_key_id(&pairs, "/2147483647'/1/");
        truncate_record(&mut pairs, "keymeta", &id, 20);
        let keys = import_records(&pairs, None);
        let unreadable: Vec<_> = keys
            .diagnostics
            .iter()
            .filter(|d| matches!(d, ImportDiagnostic::UnreadableKeyMetadata { .. }))
            .collect();
        assert_eq!(unreadable.len(), 1, "reported once: {:?}", keys.diagnostics);
        assert!(!unreadable[0].is_about_seed());
        assert_eq!(
            crate::keys::ImportCoverage::of(unreadable[0]),
            crate::keys::ImportCoverage::Complete
        );
        assert_not_claimed_complete(&keys, "change");
        assert_eq!(
            keys.coverage(),
            crate::keys::ImportCoverage::DerivedKeysMissing
        );
    }

    /// The same through decryption: a change `ckey` whose ciphertext is cut
    /// short does not decrypt. (Flipping a ciphertext byte would not do —
    /// CBC decrypts it to 32 bytes of garbage with no diagnostic.)
    #[test]
    fn an_undecryptable_derived_key_withdraws_the_verified_claim() {
        let mut pairs = bdb::walk(&read("modern-encrypted")).unwrap().records;
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let master = derive_master_key(&pass, &find_mkey(&pairs).unwrap()).unwrap();
        let id = derived_key_id(&pairs, "/2147483647'/1/");
        truncate_record(&mut pairs, "ckey", &id, 5);
        let keys = import_records(&pairs, Some(&master));
        assert!(
            keys.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::DecryptionFailed { record_type, .. } if record_type == "ckey"
            )),
            "{:?}",
            keys.diagnostics
        );
        assert_not_claimed_complete(&keys, "change");
    }

    #[test]
    fn detects_which_wallets_need_a_passphrase() {
        assert!(needs_passphrase(&read("modern-encrypted")).unwrap());
        assert!(needs_passphrase(&read("sprout-encrypted")).unwrap());
        assert!(!needs_passphrase(&read("modern-plaintext")).unwrap());
        assert!(!needs_passphrase(&read("sprout-plaintext")).unwrap());
    }

    #[test]
    fn imports_a_plaintext_wallet_without_a_passphrase() {
        let keys = import_zcashd(&read("sprout-plaintext"), None).unwrap();
        assert!(!keys.sprout.is_empty());
        assert!(!keys.is_empty());
    }

    #[test]
    fn refuses_an_encrypted_wallet_without_a_passphrase() {
        let err = import_zcashd(&read("sprout-encrypted"), None).unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn imports_an_encrypted_sprout_wallet_end_to_end() {
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let keys = import_zcashd(&read("sprout-encrypted"), Some(&pass)).unwrap();
        assert!(!keys.sprout.is_empty(), "no Sprout keys recovered");
        assert!(keys.total_keys() > 0);
    }

    /// zcashd 5.0+ keeps its HD seed in `mnemonicphrase` (plaintext) or
    /// `cmnemonicphrase` (encrypted). Every golden wallet's seed must decode,
    /// match the fingerprint zcashd stored it under, and — because none of
    /// them ever created a unified account and every legacy key the seed
    /// derived is stored — leave the import complete rather than warned.
    #[test]
    fn a_zcashd_5_wallets_seed_is_verified_and_its_coverage_is_complete() {
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        for (name, passphrase) in [
            ("modern-plaintext", None),
            ("sprout-plaintext", None),
            ("modern-encrypted", Some(&pass)),
            ("sprout-encrypted", Some(&pass)),
        ] {
            let keys = import_zcashd(&read(name), passphrase).unwrap();
            assert!(keys.seed_verified, "{name}: seed was not verified");
            assert!(
                keys.diagnostics.is_empty(),
                "{name}: unexpected diagnostics {:?}",
                keys.diagnostics
            );
            assert_eq!(
                keys.coverage(),
                crate::keys::ImportCoverage::Complete,
                "{name}"
            );
            // Verified is not "used for derivation": routing a zcashd wallet
            // down the HD path would drop every key it stores under the
            // legacy account, which the HD scan never enumerates.
            assert!(keys.mnemonic.is_none(), "{name}: mnemonic must stay unset");
        }
    }

    #[test]
    fn a_truncated_wallet_recovers_what_it_can() {
        match import_zcashd(&read("sprout-plaintext-truncated"), None) {
            Ok(keys) => {
                // Partial recovery: either keys or diagnostics, never a
                // silent empty success.
                assert!(!keys.is_empty() || !keys.diagnostics.is_empty());
            }
            Err(ImportError::UnwalkableBtree(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
