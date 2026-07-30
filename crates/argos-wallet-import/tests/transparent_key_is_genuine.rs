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

use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use secrecy::{ExposeSecret, SecretString};

const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

fn load(fixture: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat"))
        .unwrap_or_else(|e| panic!("fixture {fixture}: {e}"));
    bdb::walk(&bytes).unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
}

/// The raw (unprefixed) serialized public key stored in a `record_type`
/// record's key, in the order those records appear in `pairs`. This walks
/// the wallet file independently of `collect_encrypted`/`collect_plaintext`
/// so it is a genuine external check, not a restatement of the code under
/// test.
fn stored_pubkeys(pairs: &[(Vec<u8>, Vec<u8>)], record_type: &str) -> Vec<Vec<u8>> {
    pairs
        .iter()
        .filter_map(|(raw_key, _)| {
            let rec = zcashd::parse_record_key(raw_key)?;
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
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret).expect("recovered secret must be a valid scalar");
    PublicKey::from_secret_key(&secp, &sk).serialize()
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
