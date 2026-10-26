//! Prove that a recovered transparent secret key really controls the
//! public key it was stored under.
//!
//! This mirrors `tests/sprout_key_is_genuine.rs`. AES-CBC only XORs the IV
//! into ciphertext block 0, and a `ckey` ciphertext is 48 bytes (a 32-byte
//! secret plus PKCS#7 padding), so a wrong IV corrupts the recovered secret
//! but decryption still succeeds and still returns 32 non-zero bytes —
//! `Result::Ok` proves nothing about correctness. The only real oracle is
//! whether the recovered secret's public key matches the public key the
//! record was filed under, exactly as zcashd's own `DecryptKey` checks via
//! `key.VerifyPubKey(vchPubKey)`.

use argos_wallet_import::{
    bdb,
    keys::{ImportCoverage, ImportedKeys},
    zcashd, ImportDiagnostic,
};
use secp256k1::{PublicKey, SecretKey};
use secrecy::{ExposeSecret, SecretString};

const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

fn load(fixture: &str) -> Vec<argos_wallet_import::bdb::RawRecord> {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat"))
        .unwrap_or_else(|e| panic!("fixture {fixture}: {e}"));
    bdb::walk(&bytes)
        .unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
        .records
}

/// The raw (unprefixed) serialized public key stored in a `record_type`
/// record's key, in the order those records appear in `pairs`. This walks
/// the wallet file independently of `collect_encrypted`/`collect_plaintext`
/// so it is a genuine external check, not a restatement of the code under
/// test.
fn stored_pubkeys(
    pairs: &[argos_wallet_import::bdb::RawRecord],
    record_type: &str,
) -> Vec<Vec<u8>> {
    pairs
        .iter()
        .filter_map(|record| {
            let rec = zcashd::parse_record_key(&record.key)?;
            if rec.record_type != record_type {
                return None;
            }
            let (len, consumed) = zcashd::compact_size(&rec.rest)?;
            let end = consumed.checked_add(usize::try_from(len).ok()?)?;
            rec.rest.get(consumed..end).map(<[u8]>::to_vec)
        })
        .collect()
}

fn derive_pubkey(secret: &[u8; 32]) -> [u8; 33] {
    let sk =
        SecretKey::from_secret_bytes(*secret).expect("recovered secret must be a valid scalar");
    PublicKey::from_secret_key(&sk).serialize()
}

fn assert_keys_control_their_pubkeys(
    keys: &ImportedKeys,
    stored: &[Vec<u8>],
    expected_count: usize,
    what: &str,
) {
    assert_eq!(
        keys.transparent.len(),
        expected_count,
        "{what}: expected {expected_count} recovered transparent keys"
    );
    assert_eq!(
        stored.len(),
        expected_count,
        "{what}: expected {expected_count} stored public keys in the wallet file"
    );

    let mut verified = 0;
    for (key, stored_pubkey) in keys.transparent.iter().zip(stored) {
        let derived = derive_pubkey(key.secret.expose_secret());
        assert_eq!(
            derived.as_slice(),
            stored_pubkey.as_slice(),
            "{what}: recovered secret does not derive the public key it is stored under. \
             The key is well-formed but controls nothing."
        );
        verified += 1;
    }
    assert_eq!(verified, expected_count);
}

#[test]
fn a_decrypted_ckey_controls_its_stored_pubkey() {
    // The one that matters: this is the bug. 103 recovered secrets, 0 of
    // which matched their stored public keys before the IV fix.
    let pairs = load("modern-encrypted");
    let mkey = zcashd::find_mkey(&pairs).expect("encrypted wallet must carry an mkey");
    let master =
        zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
            .expect("fixture passphrase must derive the master key");

    let mut keys = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut keys);

    let stored = stored_pubkeys(&pairs, "ckey");
    assert_keys_control_their_pubkeys(&keys, &stored, 103, "ckey");
}

#[test]
fn a_plaintext_key_controls_its_stored_pubkey() {
    let pairs = load("sprout-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&pairs, &mut keys);

    let stored = stored_pubkeys(&pairs, "key");
    assert_keys_control_their_pubkeys(&keys, &stored, 103, "key");
}

#[test]
fn the_derivation_rejects_a_wrong_key() {
    // Guards against the check itself being vacuous: if derive_pubkey
    // returned a constant, or the comparison always succeeded, this would
    // fail to catch it.
    let pairs = load("sprout-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&pairs, &mut keys);
    let key = keys
        .transparent
        .first()
        .expect("fixture has a transparent key");

    let mut tampered = *key.secret.expose_secret();
    tampered[31] ^= 0x01;

    assert_ne!(
        derive_pubkey(&tampered),
        derive_pubkey(key.secret.expose_secret()),
        "flipping one bit of the secret must change the derived public key"
    );
}

fn assert_one_rejected(before: &ImportedKeys, after: &ImportedKeys, kind: &str) {
    assert_eq!(after.transparent.len() + 1, before.transparent.len());
    for (actual, expected) in after
        .transparent
        .iter()
        .zip(before.transparent.iter().skip(1))
    {
        assert_eq!(
            actual.secret.expose_secret(),
            expected.secret.expose_secret()
        );
    }
    assert_ne!(after.coverage(), ImportCoverage::Complete);
    let mismatches: Vec<_> = after
        .diagnostics
        .iter()
        .filter(|d| {
            matches!(d,
        ImportDiagnostic::PublicIdentifierMismatch { record_type, identifier: "public key" }
        if record_type == kind)
        })
        .collect();
    assert_eq!(mismatches.len(), 1);
    let message = mismatches[0].to_string();
    assert!(!message.contains(&hex_pubkey(
        &stored_pubkeys(&load("sprout-plaintext"), "key")[0]
    )));
}

fn hex_pubkey(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn mutate_first_pubkey(pairs: &mut [argos_wallet_import::bdb::RawRecord], kind: &str) {
    let record = pairs
        .iter_mut()
        .find(|record| zcashd::parse_record_key(&record.key).is_some_and(|r| r.record_type == kind))
        .unwrap();
    let raw_key = &mut record.key;
    let rest_start = 1 + kind.len();
    let (len, prefix) = zcashd::compact_size(&raw_key[rest_start..]).unwrap();
    assert!(len == 33 || len == 65);
    raw_key[rest_start + prefix + len as usize - 1] ^= 1;
}

#[test]
fn mutated_plaintext_pubkey_rejects_secret() {
    let mut pairs = load("sprout-plaintext");
    let mut before = ImportedKeys::default();
    zcashd::collect_plaintext(&pairs, &mut before);
    mutate_first_pubkey(&mut pairs, "key");
    let mut after = ImportedKeys::default();
    zcashd::collect_plaintext(&pairs, &mut after);
    assert_one_rejected(&before, &after, "key");
}

#[test]
fn mutated_ckey_pubkey_rejects_secret() {
    let mut pairs = load("modern-encrypted");
    let mkey = zcashd::find_mkey(&pairs).unwrap();
    let master =
        zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
            .unwrap();
    let mut before = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut before);
    mutate_first_pubkey(&mut pairs, "ckey");
    let mut after = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut after);
    assert_one_rejected(&before, &after, "ckey");
}
