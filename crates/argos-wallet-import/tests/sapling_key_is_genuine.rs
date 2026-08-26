//! Prove that a recovered Sapling extended spending key really controls the
//! viewing key it was stored under.
//!
//! The third of this crate's genuineness tests, after
//! `sprout_key_is_genuine.rs` and `transparent_key_is_genuine.rs`. Sapling
//! was the pool that had none — which is exactly the gap that let a
//! `csapzkey` of any length through the parser: the encrypted path pushed
//! whatever `decrypt` returned, and nothing downstream of it in this crate
//! ever asked whether those bytes were a key.
//!
//! Deliberately NOT feature-gated, for the same reason the other two are
//! not: a test follows the code it covers, and `collect_plaintext` /
//! `collect_encrypted` are unconditional. A default Argos build parses these
//! records, so a default `cargo test` must check them.
//!
//! `Ok` from AES-CBC proves nothing here. AES-CBC XORs the IV into
//! ciphertext block 0 only, and PKCS#7 unpadding accepts any final block
//! whose last byte happens to be a plausible pad length, so a wrong IV, a
//! truncated ciphertext, or crafted bytes all still decrypt "successfully"
//! into something wrong-but-plausible. zcashd's own
//! `DecryptSaplingSpendingKey` (`src/wallet/crypter.cpp`) therefore does two
//! things after decrypting, and this file checks both:
//!
//! ```text
//!     if (vchSecret.size() != ZIP32_XSK_SIZE)      // 169; zip32.h
//!         return false;
//!     ...
//!     return sk.expsk.full_viewing_key() == extfvk.fvk;
//! ```
//!
//! The second is the real oracle. An extended spending key's `expsk`
//! (`ask || nsk || ovk`) determines its full viewing key
//! `(ak, nk, ovk) = (SpendAuthGenerator·ask, ProofGenerationKeyGenerator·nsk,
//! ovk)`, and a `csapzkey` record stores that full viewing key *in the
//! clear*, in the same value, ahead of the ciphertext. Re-deriving it from
//! the decrypted key and comparing closes the loop with material the wallet
//! file supplied independently of the ciphertext. It also validates the IV:
//! the IV is `BLAKE2b-256("ZcashSaplingFVFP", ak || nk || ovk)` over exactly
//! those bytes, so a key that re-derives them is a key decrypted under the
//! right IV.
//!
//! For the plaintext `sapzkey` path there is no `extfvk` in the value, but
//! zcashd keys the record by the incoming viewing key —
//! `Write(std::make_pair(std::string("sapzkey"), ivk), key)`
//! (`src/wallet/walletdb.cpp`) — and `ivk = CRH^ivk(ak, nk)` is derived from
//! the same viewing key. So the record key is the oracle there.
//!
//! The re-derivation uses `sapling-crypto`, a crate this parser does not
//! depend on and never calls, so the comparison is against an independent
//! implementation rather than a restatement of the code under test — the
//! same arrangement `transparent_key_is_genuine.rs` has with `secp256k1`.

use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use sapling_crypto::zip32::ExtendedSpendingKey;
use secrecy::{ExposeSecret, SecretString};

const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

/// `ZIP32_XSK_SIZE` in zcashd's `src/zcash/address/zip32.h`.
const EXTSK_LEN: usize = 169;
/// `ZIP32_XFVK_SIZE`, the same size but a different structure. A `csapzkey`
/// value is `extfvk || CompactSize(n) || ciphertext`.
const EXTFVK_LEN: usize = 169;
/// Offset of the embedded `fvk` (`ak || nk || ovk`) within a serialized
/// extended full viewing key: depth(1) + parentFVKTag(4) + childIndex(4) +
/// chaincode(32).
const FVK_OFFSET: usize = 41;
const FVK_LEN: usize = 96;

fn load(fixture: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat"))
        .unwrap_or_else(|e| panic!("fixture {fixture}: {e}"));
    bdb::walk(&bytes).unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
}

/// Parse a recovered 169-byte extended spending key and return the
/// `(ak || nk || ovk)` and `ivk` its `expsk` determines.
fn viewing_key_from(extsk_bytes: &[u8]) -> ([u8; FVK_LEN], [u8; 32]) {
    let extsk = ExtendedSpendingKey::from_bytes(extsk_bytes)
        .unwrap_or_else(|e| panic!("recovered key is not a valid ZIP-32 extsk: {e:?}"));
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk();
    (fvk.to_bytes(), fvk.vk.ivk().to_repr())
}

/// The record-key remainders, in file order, for one record type. Walks the
/// records independently of `collect_*` so this is a genuine external check.
/// For both `sapzkey` and `csapzkey` this remainder is the 32-byte incoming
/// viewing key (zcashd `walletdb.cpp`).
fn stored_ivks(pairs: &[(Vec<u8>, Vec<u8>)], record_type: &str) -> Vec<[u8; 32]> {
    pairs
        .iter()
        .filter_map(|(raw_key, _)| {
            let rec = zcashd::parse_record_key(raw_key)?;
            if rec.record_type != record_type {
                return None;
            }
            rec.rest.get(..32)?.try_into().ok()
        })
        .collect()
}

/// The plaintext `extfvk.fvk` bytes carried in each `csapzkey` value, in
/// file order.
fn stored_fvks(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<[u8; FVK_LEN]> {
    pairs
        .iter()
        .filter_map(|(raw_key, value)| {
            let rec = zcashd::parse_record_key(raw_key)?;
            if rec.record_type != "csapzkey" {
                return None;
            }
            assert!(
                value.len() > EXTFVK_LEN,
                "a csapzkey value must carry a 169-byte extfvk plus a ciphertext"
            );
            value.get(FVK_OFFSET..FVK_OFFSET + FVK_LEN)?.try_into().ok()
        })
        .collect()
}

#[test]
fn a_decrypted_csapzkey_controls_its_stored_viewing_key() {
    // The one that matters. This is the record type M1 was about: before the
    // length check, a ciphertext that unpadded to anything at all became a
    // SaplingKey, and no assertion in this crate looked at it again.
    let pairs = load("modern-encrypted");
    let mkey = zcashd::find_mkey(&pairs).expect("encrypted wallet must carry an mkey");
    let master =
        zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
            .expect("fixture passphrase must derive the master key");

    let mut keys = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut keys);

    let stored_fvk = stored_fvks(&pairs);
    let stored_ivk = stored_ivks(&pairs, "csapzkey");
    assert!(
        !keys.sapling.is_empty(),
        "the encrypted fixture must yield at least one Sapling key"
    );
    assert_eq!(
        keys.sapling.len(),
        stored_fvk.len(),
        "every csapzkey record in the file must produce exactly one key"
    );
    assert_eq!(stored_ivk.len(), stored_fvk.len());

    for ((key, want_fvk), want_ivk) in keys.sapling.iter().zip(&stored_fvk).zip(&stored_ivk) {
        let bytes = key.extsk.expose_secret();
        assert_eq!(
            bytes.len(),
            EXTSK_LEN,
            "a recovered extsk must be exactly {EXTSK_LEN} bytes"
        );

        let (derived_fvk, derived_ivk) = viewing_key_from(bytes);
        assert_eq!(
            &derived_fvk, want_fvk,
            "recovered extsk does not derive the full viewing key stored \
             beside it in the same csapzkey record. The key is well-formed \
             but controls a different account."
        );
        assert_eq!(
            &derived_ivk, want_ivk,
            "recovered extsk does not derive the incoming viewing key the \
             record is filed under"
        );
    }
}

#[test]
fn a_plaintext_sapzkey_controls_its_stored_viewing_key() {
    let pairs = load("modern-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&pairs, &mut keys);

    let stored_ivk = stored_ivks(&pairs, "sapzkey");
    assert!(
        !keys.sapling.is_empty(),
        "the plaintext fixture must yield at least one Sapling key"
    );
    assert_eq!(
        keys.sapling.len(),
        stored_ivk.len(),
        "every sapzkey record in the file must produce exactly one key"
    );

    for (key, want_ivk) in keys.sapling.iter().zip(&stored_ivk) {
        let bytes = key.extsk.expose_secret();
        assert_eq!(bytes.len(), EXTSK_LEN);
        let (_, derived_ivk) = viewing_key_from(bytes);
        assert_eq!(
            &derived_ivk, want_ivk,
            "recovered extsk does not derive the incoming viewing key it is \
             stored under. The key is well-formed but controls a different \
             account."
        );
    }
}

/// Re-encrypt `plaintext` exactly as zcashd would have written a `csapzkey`
/// ciphertext: AES-256-CBC under the wallet master key, with PKCS#7 padding
/// and the IV zcashd derives for this record —
/// `BLAKE2b-256("ZcashSaplingFVFP", ak || nk || ovk)` truncated to 16 bytes.
///
/// This is what makes the wrong-length case testable at all. Simply
/// truncating a real ciphertext is not enough: PKCS#7 then rejects the final
/// block, the parser reports a plain decryption failure, and the test passes
/// whether or not the length check exists. Only a ciphertext that decrypts
/// *cleanly* to a wrong length distinguishes the two.
fn encrypt_under(master: &zcashd::MasterKey, fvk: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashSaplingFVFP")
        .hash(fvk);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&digest.as_bytes()[..16]);

    let key: [u8; 32] = *master.expose_secret();
    cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

#[test]
fn a_csapzkey_that_decrypts_to_the_wrong_length_is_rejected_not_kept() {
    // M1 itself, and the reason a length check is not redundant with PKCS#7.
    // AES-CBC unpadding only checks the final block's padding bytes; it says
    // nothing about how long the message is. A ciphertext encrypted under
    // the right key and IV over 168 bytes decrypts perfectly and yields 168
    // bytes — which is not a ZIP-32 extended spending key. Before the fix
    // those 168 bytes became a `SaplingKey` and the failure surfaced much
    // later, inside `argos-core`, far from the record that caused it.
    //
    // The plaintext used here is the record's own genuine key with its last
    // byte removed: everything about it is real except the length, so
    // nothing but a length check can reject it.
    let mut pairs = load("modern-encrypted");
    let mkey = zcashd::find_mkey(&pairs).expect("encrypted wallet must carry an mkey");
    let master =
        zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
            .expect("fixture passphrase must derive the master key");

    let mut baseline = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut baseline);
    let full_count = baseline.sapling.len();
    assert!(full_count > 0, "fixture must have csapzkey records to maul");
    let mut short_key = baseline.sapling[0].extsk.expose_secret().clone();
    assert_eq!(short_key.len(), EXTSK_LEN);
    short_key.pop();

    // Rewrite the first csapzkey record's ciphertext, fixing up its
    // CompactSize length so the record still parses.
    let mut mauled = 0usize;
    for (raw_key, value) in pairs.iter_mut() {
        let is_csapzkey = zcashd::parse_record_key(raw_key)
            .map(|r| r.record_type == "csapzkey")
            .unwrap_or(false);
        if !is_csapzkey {
            continue;
        }
        let fvk = value[FVK_OFFSET..FVK_OFFSET + FVK_LEN].to_vec();
        let ct = encrypt_under(&master, &fvk, &short_key);
        assert!(ct.len() < 0xFD, "ciphertext needs a one-byte CompactSize");
        value.truncate(EXTFVK_LEN);
        value.push(ct.len() as u8);
        value.extend_from_slice(&ct);
        mauled += 1;
        break;
    }
    assert_eq!(mauled, 1, "exactly one record must have been rewritten");

    let mut out = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut out);

    for key in &out.sapling {
        assert_eq!(
            key.extsk.expose_secret().len(),
            EXTSK_LEN,
            "a plaintext that decrypted cleanly to the wrong length was kept \
             as a Sapling key"
        );
    }
    assert_eq!(
        out.sapling.len(),
        full_count - 1,
        "the rewritten record must not still produce a key, and no other \
         record may be affected"
    );
    assert!(
        out.diagnostics
            .iter()
            .any(|d| d.to_string().contains("csapzkey")),
        "the rejected record must be reported, not silently dropped: {:?}",
        out.diagnostics
    );
}

#[test]
fn the_derivation_rejects_a_wrong_key() {
    // Guards against the check itself being vacuous: if viewing_key_from
    // returned a constant, or the comparison always succeeded, this would
    // fail to catch it.
    let pairs = load("modern-plaintext");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&pairs, &mut keys);
    let key = keys.sapling.first().expect("fixture has a Sapling key");

    let good = key.extsk.expose_secret().clone();
    let mut tampered = good.clone();
    // Flip a bit inside `ask` (extsk[41..73]), which feeds ak.
    tampered[41] ^= 0x01;

    assert_ne!(
        viewing_key_from(&tampered).0,
        viewing_key_from(&good).0,
        "flipping one bit of ask must change the derived full viewing key"
    );
}
