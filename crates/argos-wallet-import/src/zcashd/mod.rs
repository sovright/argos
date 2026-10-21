//! zcashd wallet.dat record layer.

pub mod crypto;
pub mod encrypted;
pub mod metadata;
pub mod plaintext;
pub mod records;
pub mod seed;
pub mod sprout;

pub use crypto::{derive_master_key, find_mkey, MasterKey, MkeyRecord};
pub use encrypted::collect_encrypted;
pub use metadata::{KeyMetadataIndex, MetadataKind, UNKNOWN_CREATE_TIME_AT_OR_BEFORE};
pub use plaintext::collect_plaintext;
pub use records::{compact_size, parse_record_key, RecordKey};
pub use sprout::collect_sprout_notes;

use std::collections::HashSet;

use secrecy::SecretString;

use crate::{bdb, error::ImportError, keys::ImportedKeys};

/// True when the wallet carries an `mkey` record and therefore needs a
/// passphrase. Checked before prompting so we never ask for a passphrase
/// the wallet does not use.
pub fn needs_passphrase(bytes: &[u8]) -> bool {
    bdb::walk(bytes)
        .map(|pairs| find_mkey(&pairs).is_some())
        .unwrap_or(false)
}

/// Parse a zcashd `wallet.dat` into normalized key material.
///
/// Decryption happens here, once, before any caller touches the network:
/// a wallet needing a passphrase fails fast and locally.
pub fn import_zcashd(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let pairs = Records(bdb::walk(bytes)?);
    let master = match find_mkey(&pairs) {
        // Encrypted wallet: without a passphrase the encrypted records are
        // unreachable, and reporting partial plaintext results would let a
        // user believe they had recovered everything.
        Some(mkey) => Some(derive_master_key(
            passphrase.ok_or(ImportError::WrongPassphrase)?,
            &mkey,
        )?),
        None => None,
    };
    Ok(import_records(&pairs, master.as_ref()))
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
        let mut pairs = bdb::walk(&read("modern-plaintext")).unwrap();
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

    /// The same through decryption: a change `ckey` whose ciphertext is cut
    /// short does not decrypt. (Flipping a ciphertext byte would not do —
    /// CBC decrypts it to 32 bytes of garbage with no diagnostic.)
    #[test]
    fn an_undecryptable_derived_key_withdraws_the_verified_claim() {
        let mut pairs = bdb::walk(&read("modern-encrypted")).unwrap();
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
        assert!(needs_passphrase(&read("modern-encrypted")));
        assert!(needs_passphrase(&read("sprout-encrypted")));
        assert!(!needs_passphrase(&read("modern-plaintext")));
        assert!(!needs_passphrase(&read("sprout-plaintext")));
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
