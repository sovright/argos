//! An encrypted zcashd `ckey` filed under an uncompressed (65-byte) public key.
//!
//! zcashd stores an `importprivkey` of an uncompressed WIF under its 65-byte
//! public key, and the coins sit at the P2PKH address of that key. Argos keeps
//! only the 32-byte secret and derives, scans and spends compressed P2PKH
//! addresses (`imported_transparent_keys` in argos-core), so a kept key would
//! be scanned at an address that never held its coins while the import still
//! read as complete. The key must be refused loudly instead, as the plaintext
//! path already refuses an uncompressed `key` record.
//!
//! The key is secret key 1, whose public key is the secp256k1 generator: a
//! public test vector, so no key material here belongs to anyone.

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use argos_wallet_import::{
    bdb,
    keys::{ImportCoverage, ImportedKeys},
    zcashd, ImportDiagnostic,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

const SECRET_ONE: [u8; 32] = {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    secret
};

/// Secret key 1's public key in compressed form.
const COMPRESSED_ONE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Secret key 1's public key in uncompressed form.
const UNCOMPRESSED_ONE: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                                483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

fn hex(text: &str) -> Vec<u8> {
    let compact: String = text.split_whitespace().collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).expect("constant is hex"))
        .collect()
}

fn load(fixture: &str) -> Vec<bdb::RawRecord> {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat"))
        .unwrap_or_else(|e| panic!("fixture {fixture}: {e}"));
    bdb::walk(&bytes)
        .unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
        .records
}

fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let len = u8::try_from(bytes.len()).expect("every field here is under 253 bytes");
    assert!(len < 0xfd, "a one-byte CompactSize covers every field here");
    let mut out = vec![len];
    out.extend_from_slice(bytes);
    out
}

/// Import the encrypted fixture as is, and again with its first `ckey`
/// replaced by secret key 1 filed under `public_key` and encrypted the way
/// zcashd does it: IV = SHA256d(raw public key)[..16], AES-256-CBC.
fn import_with_ckey_for_secret_one(public_key: &[u8]) -> (ImportedKeys, ImportedKeys) {
    let pairs = load("modern-encrypted");
    let mkey = zcashd::find_mkey(&pairs).expect("the encrypted fixture carries an mkey");
    let master =
        zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
            .expect("the fixture passphrase derives the master key");

    let mut before = ImportedKeys::default();
    zcashd::collect_encrypted(&pairs, &master, &mut before);

    let mut mutated = load("modern-encrypted");
    let slot = mutated
        .iter()
        .position(|record| {
            zcashd::parse_record_key(&record.key).is_some_and(|rec| rec.record_type == "ckey")
        })
        .expect("the fixture holds a ckey record");

    let digest = Sha256::digest(Sha256::digest(public_key));
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&digest[..16]);
    let key: [u8; 32] = *master.expose_secret();
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(&SECRET_ONE);

    let mut record_key = length_prefixed(b"ckey");
    record_key.extend_from_slice(&length_prefixed(public_key));
    mutated[slot] = bdb::RawRecord::new(record_key, length_prefixed(&ciphertext));

    let mut after = ImportedKeys::default();
    zcashd::collect_encrypted(&mutated, &master, &mut after);

    // Guard: the rewritten record decrypts cleanly, so whatever happens to it
    // below is the importer's decision, not a broken test.
    assert!(
        !after
            .diagnostics
            .iter()
            .any(|d| matches!(d, ImportDiagnostic::DecryptionFailed { .. })),
        "the rewritten ckey must decrypt under its public key"
    );
    (before, after)
}

fn holds_secret_one(keys: &ImportedKeys) -> bool {
    keys.transparent
        .iter()
        .any(|key| *key.secret.expose_secret() == SECRET_ONE)
}

fn ckey_refusals(keys: &ImportedKeys) -> usize {
    keys.diagnostics
        .iter()
        .filter(|d| {
            matches!(d, ImportDiagnostic::UnparseableRecord { record_type, .. }
                if record_type == "ckey")
        })
        .count()
}

#[test]
fn an_uncompressed_ckey_is_refused_and_lowers_coverage() {
    let (before, after) = import_with_ckey_for_secret_one(&hex(UNCOMPRESSED_ONE));

    // The fixture alone imports complete, so any coverage lost below is the
    // refusal's doing and not something the fixture already carried.
    assert_eq!(before.coverage(), ImportCoverage::Complete);
    assert!(
        !holds_secret_one(&after),
        "an uncompressed ckey must not be kept: Argos would scan its compressed address, \
         which never held its coins"
    );
    assert_eq!(
        after.transparent.len() + 1,
        before.transparent.len(),
        "only the rewritten key is missing"
    );
    assert_eq!(ckey_refusals(&before), 0);
    assert_eq!(
        ckey_refusals(&after),
        1,
        "the refusal must be reported, not silent"
    );
    assert!(
        after.coverage() >= ImportCoverage::KeysUnread && after.coverage().may_hide_funds(),
        "a refused key must keep the import from reading as complete"
    );
    let uncompressed = UNCOMPRESSED_ONE.split_whitespace().collect::<String>();
    for diagnostic in &after.diagnostics {
        assert!(
            !diagnostic.to_string().contains(&uncompressed),
            "diagnostics must not echo key material"
        );
    }
}

#[test]
fn a_compressed_ckey_for_the_same_secret_is_still_kept() {
    let (before, after) = import_with_ckey_for_secret_one(&hex(COMPRESSED_ONE));

    assert!(holds_secret_one(&after));
    assert_eq!(after.transparent.len(), before.transparent.len());
    assert_eq!(ckey_refusals(&after), 0);
    assert_eq!(after.coverage(), before.coverage());
}
