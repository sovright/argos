#![cfg(feature = "sprout")]
//! Prove that the Sprout derivation chain produces the address the wallet
//! stored it under — both halves of it.
//!
//! `argos-wallet-import`'s `sprout_key_is_genuine.rs` closes this loop on
//! `a_pk`. That leaves `sk_enc` — and therefore `pk_enc`, and therefore every
//! note decryption — unchecked, because nothing downstream of it had been
//! written yet.
//!
//! A Sprout payment address is `a_pk || pk_enc`, and both halves derive from
//! `a_sk`. zcashd keyed each record by that address, so the file is an
//! external oracle: a wrong `sk_enc`, or a missing Curve25519 clamp, yields a
//! `pk_enc` that does not match bytes we did not write.
//!
//! This matters more than the usual round-trip test. No fixture holds a
//! funded Sprout note (zcashd refuses inbound Sprout transfers regardless of
//! Canopy height — see `tests/regtest/fixtures/README.md`), so decryption
//! cannot be tested end to end against real data. The derivation check is the
//! strongest evidence available that the key material feeding
//! `decrypt_note` is right.

use argos_core::sprout;
use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use secrecy::ExposeSecret;

fn load(fixture: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let path = format!(
        "{}/../argos-wallet-import/tests/fixtures/{fixture}.dat",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"));
    bdb::walk(&bytes).unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
}

fn assert_derivation_matches(keys: &ImportedKeys, what: &str) {
    assert!(
        !keys.sprout.is_empty(),
        "{what}: expected at least one Sprout key to validate"
    );

    for key in &keys.sprout {
        let a_sk = key.a_sk.expose_secret();

        let stored_a_pk: [u8; 32] = key.address[..32].try_into().expect("address is 64 bytes");
        let stored_pk_enc: [u8; 32] = key.address[32..].try_into().expect("address is 64 bytes");

        assert_eq!(
            sprout::a_pk(a_sk),
            stored_a_pk,
            "{what}: derived a_pk does not match the address this key is stored under"
        );

        // The half that had never been checked. If the Curve25519 clamp in
        // `sk_enc` is missing or wrong, this is where it shows up — and it
        // would otherwise show up as every note decryption silently failing
        // its AEAD tag, which looks identical to "no notes for this key".
        assert_eq!(
            sprout::pk_enc(a_sk),
            stored_pk_enc,
            "{what}: derived pk_enc does not match the address this key is stored under. \
             Note decryption with this key would fail against every ciphertext."
        );
    }
}

#[test]
fn a_plaintext_sprout_key_derives_its_full_address() {
    let records = load("sprout-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&records, &mut keys);
    assert_derivation_matches(&keys, "zkey");
}

#[test]
fn a_ciphertext_that_is_not_ours_is_rejected_cleanly() {
    // Decryption is tried against every key for every note, so "not mine" is
    // the common path and must be an ordinary result rather than an error a
    // user sees.
    let err = sprout::decrypt_note(&[7u8; 32], &[9u8; 32], &[0u8; 601], &[0u8; 32], 0)
        .expect_err("random bytes must not decrypt");
    assert_eq!(err, sprout::SproutNoteError::NotForThisKey);
}

#[test]
fn a_wrong_length_ciphertext_is_reported_as_such() {
    let err = sprout::decrypt_note(&[7u8; 32], &[9u8; 32], &[0u8; 600], &[0u8; 32], 0)
        .expect_err("a short ciphertext is malformed, not merely unreadable");
    assert_eq!(err, sprout::SproutNoteError::CiphertextLength(600));
}
