//! Prove that a recovered Sprout spending key really controls the address
//! it was stored under.
//!
//! This crate's parser has always been unconditional, so every Argos build
//! decrypts `czkey` records — the only
//! implementation in the ecosystem that does (Zallet drops Sprout keys during
//! migration, `zewif-zcashd` returns an explicit error for them). These
//! assertions are the only specification that decryption has. Gating them
//! would ship it, in the default build, with nothing checking it.
//!
//! It needs no Sprout support to run: it re-derives `a_pk` from `a_sk` with
//! `sha2::compress256` directly rather than calling `argos_core::sprout`,
//! which is what makes it an independent check rather than a restatement.
//!
//! Every other test in this crate shows that 32 bytes came out of the right
//! position in the file. That is not the same as showing they are the right
//! 32 bytes. This branch has already produced, twice, a well-formed key that
//! was silently wrong — once from a mis-sliced DER header, once from a value
//! decoder that read a length prefix that was not there.
//!
//! `czkey` makes that risk acute: no other software decrypts these records,
//! so there is no implementation to differential-test against. The only
//! external oracle available is the wallet file itself. Each Sprout record is
//! keyed by its 64-byte payment address, `a_pk || pk_enc`, and `a_pk` is
//! derived from `a_sk`. Re-deriving it and comparing closes the loop:
//!
//!     a_pk == PRF^addr_{a_sk}(0)
//!
//! If that holds for a key recovered by decrypting `czkey`, the decryption is
//! correct. If it does not, we recovered something plausible and wrong.

use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use secrecy::{ExposeSecret, SecretString};
use sha2::compress256;
use sha2::digest::generic_array::GenericArray;

const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

/// SHA-256 initial state, per FIPS 180-4.
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The bare SHA-256 compression function over one 512-bit block — *not*
/// SHA-256 itself. Zcash's `SHA256Compress` deliberately omits padding and
/// the length suffix, so this must not be replaced with `Sha256::digest`.
fn sha256_compress(block: &[u8; 64]) -> [u8; 32] {
    let mut state = SHA256_IV;
    compress256(&mut state, &[*GenericArray::from_slice(block)]);
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// `PRF^addr_{a_sk}(t)`, following `PRF` in `zcash/zcash` `src/zcash/prf.cpp`.
///
/// The block is `a_sk || t_as_uint256`, with the top four bits of the first
/// byte cleared and replaced by the tag `1100`. `a_sk` is a 252-bit value
/// stored in 32 bytes, which is why those four bits are free to carry the tag.
fn prf_addr(a_sk: &[u8; 32], t: u8) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(a_sk);
    block[0] &= 0x0F;
    block[0] |= 0b1100_0000;
    block[32] = t;
    sha256_compress(&block)
}

fn a_pk_from(a_sk: &[u8; 32]) -> [u8; 32] {
    prf_addr(a_sk, 0)
}

fn load(fixture: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat"))
        .unwrap_or_else(|e| panic!("fixture {fixture}: {e}"));
    bdb::walk(&bytes).unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
}

fn assert_keys_control_their_addresses(keys: &ImportedKeys, what: &str) {
    assert!(
        !keys.sprout.is_empty(),
        "{what}: expected at least one Sprout key to validate"
    );

    for key in &keys.sprout {
        let derived = a_pk_from(key.a_sk.expose_secret());
        let stored: [u8; 32] = key.address[..32]
            .try_into()
            .expect("a payment address is 64 bytes");

        assert_eq!(
            derived, stored,
            "{what}: recovered a_sk does not derive the a_pk it is stored under. \
             The key is well-formed but controls a different address."
        );
    }
}

#[test]
fn a_plaintext_zkey_controls_its_stored_address() {
    let records = load("sprout-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&records, &mut keys);
    assert_keys_control_their_addresses(&keys, "zkey");
}

#[test]
fn a_decrypted_czkey_controls_its_stored_address() {
    // The one that matters. No other software decrypts czkey, so this
    // derivation is the only external check that exists on the result.
    let records = load("sprout-encrypted");
    let mkey = zcashd::find_mkey(&records).expect("encrypted wallet must carry an mkey");
    let master =
        zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
            .expect("fixture passphrase must derive the master key");

    let mut keys = ImportedKeys::default();
    zcashd::collect_encrypted(&records, &master, &mut keys);
    assert_keys_control_their_addresses(&keys, "czkey");
}

#[test]
fn the_derivation_rejects_a_wrong_key() {
    // Guards against the check itself being vacuous: if a_pk_from returned a
    // constant, or the comparison always succeeded, this would fail.
    let records = load("sprout-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&records, &mut keys);
    let key = keys.sprout.first().expect("fixture has a Sprout key");

    let mut tampered = *key.a_sk.expose_secret();
    tampered[31] ^= 0x01;

    assert_ne!(
        a_pk_from(&tampered),
        a_pk_from(key.a_sk.expose_secret()),
        "flipping one bit of a_sk must change the derived a_pk"
    );
}
