//! zcashd transparent keys filed under an uncompressed (65-byte) public key.
//!
//! zcashd stores an `importprivkey` of an uncompressed WIF under its 65-byte
//! public key, and the coins sit at the P2PKH address of those 65 bytes. The
//! same secret's compressed address is a different address that never held
//! them. So the import must keep each key together with the form it was filed
//! in, and must not let the import read as complete while Argos cannot sweep
//! the uncompressed form.
//!
//! Every key here is secret key 1, whose public key is the secp256k1
//! generator: a public test vector, so no key material belongs to anyone.

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use argos_wallet_import::{
    bdb,
    keys::{ImportCoverage, ImportedKeys, PubkeyForm},
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

/// The DER around the secret in zcashd's `ec_seckey_export_der` (`key.cpp`,
/// zcash/zcash master 558f686599586f55def3db86955d74d3be44605e), copied from
/// the source's byte arrays. A compressed blob is `begin || secret || middle
/// || 33-byte pubkey` (214 bytes); an uncompressed one is the same with the
/// longer arrays and the 65-byte pubkey (279 bytes).
///
/// These records are built from that source, not written by a zcashd node.
/// They show that the parser and the source agree; only a node-written
/// wallet.dat (the regtest acceptance case) shows the parser agrees with
/// zcashd itself.
const DER_BEGIN_COMPRESSED: &str = "3081d30201010420";
const DER_MIDDLE_COMPRESSED: &str =
    "a08185308182020101302c06072a8648ce3d0101022100ffffffffffffffff\
     fffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704210279be667ef9dcbbac55a06\
     295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af4\
     8a03bbfd25e8cd0364141020101a124032200";
const DER_BEGIN_UNCOMPRESSED: &str = "308201130201010420";
const DER_MIDDLE_UNCOMPRESSED: &str =
    "a081a53081a2020101302c06072a8648ce3d0101022100ffffffffffffffff\
     fffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06\
     295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a6855419\
     9c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101\
     a144034200";

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

/// Bitcoin's CompactSize, as zcashd serializes vector lengths.
fn compact_size(len: usize) -> Vec<u8> {
    match len {
        0..=0xfc => vec![u8::try_from(len).expect("fits")],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&u16::try_from(len).expect("fits").to_le_bytes());
            out
        }
        _ => panic!("no field here is that long"),
    }
}

fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = compact_size(bytes.len());
    out.extend_from_slice(bytes);
    out
}

fn record_key(record_type: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut key = length_prefixed(record_type);
    key.extend_from_slice(&length_prefixed(public_key));
    key
}

/// The first `count` record indices of `record_type`, in file order.
fn slots(records: &[bdb::RawRecord], record_type: &str, count: usize) -> Vec<usize> {
    let found: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| {
            zcashd::parse_record_key(&record.key).is_some_and(|rec| rec.record_type == record_type)
        })
        .map(|(index, _)| index)
        .take(count)
        .collect();
    assert_eq!(
        found.len(),
        count,
        "the fixture holds {count} {record_type} record(s)"
    );
    found
}

fn master_key(records: &[bdb::RawRecord]) -> zcashd::MasterKey {
    let mkey = zcashd::find_mkey(records).expect("the encrypted fixture carries an mkey");
    zcashd::derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
        .expect("the fixture passphrase derives the master key")
}

/// Import the encrypted fixture as is, and again with its first ckeys
/// replaced by secret key 1 filed under each of `public_keys`, encrypted the
/// way zcashd does it: IV = SHA256d(raw public key)[..16], AES-256-CBC.
fn encrypted_with_secret_one_under(public_keys: &[&[u8]]) -> (ImportedKeys, ImportedKeys) {
    let records = load("modern-encrypted");
    let master = master_key(&records);

    let mut before = ImportedKeys::default();
    zcashd::collect_encrypted(&records, &master, &mut before);

    let mut mutated = load("modern-encrypted");
    for (slot, public_key) in slots(&mutated, "ckey", public_keys.len())
        .into_iter()
        .zip(public_keys)
    {
        let digest = Sha256::digest(Sha256::digest(public_key));
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&digest[..16]);
        let key: [u8; 32] = *master.expose_secret();
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&SECRET_ONE);
        mutated[slot] = bdb::RawRecord::new(
            record_key(b"ckey", public_key),
            length_prefixed(&ciphertext),
        );
    }

    let mut after = ImportedKeys::default();
    zcashd::collect_encrypted(&mutated, &master, &mut after);
    // Guard: every rewritten record decrypts cleanly, so whatever happens to
    // it is the importer's decision, not a broken test.
    assert!(
        !after
            .diagnostics
            .iter()
            .any(|d| matches!(d, ImportDiagnostic::DecryptionFailed { .. })),
        "every rewritten ckey must decrypt under its public key"
    );
    (before, after)
}

/// A plaintext `key` record for secret key 1, as zcashd's `WriteKey` lays it
/// out: key `"key" || pubkey`, value `CompactSize || DER || SHA256d(pubkey ||
/// DER)`.
fn plaintext_record(public_key: &[u8], der: &[u8]) -> bdb::RawRecord {
    let mut hashed = public_key.to_vec();
    hashed.extend_from_slice(der);
    let mut value = length_prefixed(der);
    value.extend_from_slice(&Sha256::digest(Sha256::digest(&hashed)));
    bdb::RawRecord::new(record_key(b"key", public_key), value)
}

fn der(begin: &str, middle: &str, public_key: &str) -> Vec<u8> {
    let mut der = hex(begin);
    der.extend_from_slice(&SECRET_ONE);
    der.extend_from_slice(&hex(middle));
    der.extend_from_slice(&hex(public_key));
    der
}

fn compressed_der() -> Vec<u8> {
    let der = der(DER_BEGIN_COMPRESSED, DER_MIDDLE_COMPRESSED, COMPRESSED_ONE);
    assert_eq!(der.len(), 214, "zcashd's CKey::COMPRESSED_PRIVATE_KEY_SIZE");
    der
}

fn uncompressed_der() -> Vec<u8> {
    let der = der(
        DER_BEGIN_UNCOMPRESSED,
        DER_MIDDLE_UNCOMPRESSED,
        UNCOMPRESSED_ONE,
    );
    assert_eq!(der.len(), 279, "zcashd's CKey::PRIVATE_KEY_SIZE");
    der
}

/// Import the plaintext fixture as is, and again with its first `key` records
/// replaced by `replacements`.
fn plaintext_with(replacements: Vec<bdb::RawRecord>) -> (ImportedKeys, ImportedKeys) {
    let records = load("modern-plaintext");
    let mut before = ImportedKeys::default();
    zcashd::collect_plaintext(&records, &mut before);

    let mut mutated = load("modern-plaintext");
    for (slot, record) in slots(&mutated, "key", replacements.len())
        .into_iter()
        .zip(replacements)
    {
        mutated[slot] = record;
    }
    let mut after = ImportedKeys::default();
    zcashd::collect_plaintext(&mutated, &mut after);
    (before, after)
}

fn forms_of_secret_one(keys: &ImportedKeys) -> Vec<PubkeyForm> {
    keys.transparent
        .iter()
        .filter(|key| *key.secret.expose_secret() == SECRET_ONE)
        .map(|key| key.pubkey_form)
        .collect()
}

fn count(keys: &ImportedKeys, wanted: impl Fn(&ImportDiagnostic) -> bool) -> usize {
    keys.diagnostics.iter().filter(|d| wanted(d)).count()
}

fn unswept_uncompressed(record: &'static str) -> impl Fn(&ImportDiagnostic) -> bool {
    move |d| {
        matches!(d, ImportDiagnostic::UnrecoveredStandaloneKey { record_type, pool }
            if record_type == record && *pool == "uncompressed transparent")
    }
}

fn unparseable(record: &'static str) -> impl Fn(&ImportDiagnostic) -> bool {
    move |d| {
        matches!(d, ImportDiagnostic::UnparseableRecord { record_type, .. }
            if record_type == record)
    }
}

/// The keys the fixture carried besides the rewritten slots are untouched and
/// still compressed.
fn assert_rest_compressed(before: &ImportedKeys, after: &ImportedKeys, rewritten: usize) {
    assert_eq!(
        after.transparent.len(),
        before.transparent.len(),
        "one key per record, none lost"
    );
    let others = after
        .transparent
        .iter()
        .filter(|key| *key.secret.expose_secret() != SECRET_ONE)
        .count();
    assert_eq!(others, before.transparent.len() - rewritten);
    assert!(after
        .transparent
        .iter()
        .filter(|key| *key.secret.expose_secret() != SECRET_ONE)
        .all(|key| key.pubkey_form == PubkeyForm::Compressed));
}

fn assert_no_key_material_in(keys: &ImportedKeys) {
    let uncompressed = UNCOMPRESSED_ONE.split_whitespace().collect::<String>();
    let secret = hex_string(&SECRET_ONE);
    for diagnostic in &keys.diagnostics {
        let text = diagnostic.to_string();
        assert!(
            !text.contains(&uncompressed),
            "diagnostics must not echo the public key"
        );
        assert!(
            !text.contains(&secret),
            "diagnostics must not echo the secret"
        );
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn an_uncompressed_ckey_is_kept_in_its_form_and_the_import_stays_incomplete() {
    let (before, after) = encrypted_with_secret_one_under(&[&hex(UNCOMPRESSED_ONE)]);

    // The fixture alone imports complete, so any coverage lost below is the
    // uncompressed key's doing and not something the fixture already carried.
    assert_eq!(before.coverage(), ImportCoverage::Complete);
    assert_eq!(
        forms_of_secret_one(&after),
        vec![PubkeyForm::Uncompressed],
        "the key is kept, with the form its public key was filed in"
    );
    assert_rest_compressed(&before, &after, 1);
    assert_eq!(
        count(&after, unswept_uncompressed("ckey")),
        1,
        "reported, not silent"
    );
    assert_eq!(
        count(&after, unparseable("ckey")),
        0,
        "the record parsed; it is not refused"
    );
    assert_eq!(after.coverage(), ImportCoverage::KeyMaterialMissing);
    assert!(
        after.coverage().may_hide_funds(),
        "while Argos cannot sweep the key, the import must not read as complete"
    );
    assert_no_key_material_in(&after);
}

#[test]
fn a_compressed_ckey_for_the_same_secret_stays_compressed_and_complete() {
    let (before, after) = encrypted_with_secret_one_under(&[&hex(COMPRESSED_ONE)]);

    assert_eq!(forms_of_secret_one(&after), vec![PubkeyForm::Compressed]);
    assert_rest_compressed(&before, &after, 1);
    assert_eq!(count(&after, unswept_uncompressed("ckey")), 0);
    assert_eq!(after.coverage(), before.coverage());
}

#[test]
fn both_forms_of_one_secret_are_two_keys() {
    // A wallet that imported the same secret both ways holds two keys, at
    // two addresses. Neither may stand in for the other.
    let (before, after) =
        encrypted_with_secret_one_under(&[&hex(COMPRESSED_ONE), &hex(UNCOMPRESSED_ONE)]);

    let mut forms = forms_of_secret_one(&after);
    forms.sort_by_key(|form| *form == PubkeyForm::Uncompressed);
    assert_eq!(
        forms,
        vec![PubkeyForm::Compressed, PubkeyForm::Uncompressed]
    );
    assert_rest_compressed(&before, &after, 2);
    assert_eq!(
        count(&after, unswept_uncompressed("ckey")),
        1,
        "only the uncompressed one"
    );
}

#[test]
fn an_uncompressed_plaintext_key_is_kept_in_its_form_and_the_import_stays_incomplete() {
    let (before, after) = plaintext_with(vec![plaintext_record(
        &hex(UNCOMPRESSED_ONE),
        &uncompressed_der(),
    )]);

    assert_eq!(before.coverage(), ImportCoverage::Complete);
    assert_eq!(forms_of_secret_one(&after), vec![PubkeyForm::Uncompressed]);
    assert_rest_compressed(&before, &after, 1);
    assert_eq!(count(&after, unswept_uncompressed("key")), 1);
    assert_eq!(count(&after, unparseable("key")), 0);
    assert_eq!(after.coverage(), ImportCoverage::KeyMaterialMissing);
    assert_no_key_material_in(&after);
}

#[test]
fn a_compressed_plaintext_key_built_from_zcashd_source_stays_compressed() {
    // The compressed layout built from the same source the uncompressed one
    // comes from, so the uncompressed test above rests on a source the
    // fixtures already confirm for the compressed form.
    let (before, after) = plaintext_with(vec![plaintext_record(
        &hex(COMPRESSED_ONE),
        &compressed_der(),
    )]);

    assert_eq!(forms_of_secret_one(&after), vec![PubkeyForm::Compressed]);
    assert_rest_compressed(&before, &after, 1);
    assert_eq!(after.coverage(), before.coverage());
}

#[test]
fn a_plaintext_key_whose_der_and_public_key_disagree_on_form_is_refused() {
    // zcashd writes both from one `fCompressed`. A record that disagrees with
    // itself cannot say which address holds the coins.
    for (public_key, der) in [
        (hex(COMPRESSED_ONE), uncompressed_der()),
        (hex(UNCOMPRESSED_ONE), compressed_der()),
    ] {
        let (_, after) = plaintext_with(vec![plaintext_record(&public_key, &der)]);
        assert!(
            forms_of_secret_one(&after).is_empty(),
            "the key is not kept"
        );
        assert_eq!(count(&after, unparseable("key")), 1);
        assert!(after.coverage().may_hide_funds());
    }
}

#[test]
fn an_uncompressed_der_of_the_wrong_length_is_refused() {
    // The header announces 0x0113 bytes; a blob of any other length is not
    // the shape zcashd writes, and no slice is taken from it.
    for der in [
        uncompressed_der()[..278].to_vec(),
        [uncompressed_der(), vec![0]].concat(),
    ] {
        let (_, after) = plaintext_with(vec![plaintext_record(&hex(UNCOMPRESSED_ONE), &der)]);
        assert!(forms_of_secret_one(&after).is_empty());
        assert_eq!(count(&after, unparseable("key")), 1);
    }
}

#[test]
fn every_key_in_the_fixtures_reads_as_compressed() {
    // zcashd generates compressed keys only; none of the fixtures imported an
    // uncompressed WIF. Their keys must keep reading the way they always did.
    for (fixture, passphrase) in [
        ("modern-plaintext", None),
        ("sprout-plaintext", None),
        ("modern-encrypted", Some(FIXTURE_PASSPHRASE)),
        ("sprout-encrypted", Some(FIXTURE_PASSPHRASE)),
    ] {
        let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat")).expect("fixture");
        let passphrase = passphrase.map(|p| SecretString::new(p.to_owned()));
        let keys = argos_wallet_import::import_wallet_file(&bytes, passphrase.as_ref())
            .unwrap_or_else(|e| panic!("{fixture}: {e}"));
        assert!(
            !keys.transparent.is_empty(),
            "{fixture} holds transparent keys"
        );
        assert!(
            keys.transparent
                .iter()
                .all(|key| key.pubkey_form == PubkeyForm::Compressed),
            "{fixture}: every key is compressed"
        );
        assert_eq!(count(&keys, unswept_uncompressed("key")), 0, "{fixture}");
        assert_eq!(count(&keys, unswept_uncompressed("ckey")), 0, "{fixture}");
    }
}
