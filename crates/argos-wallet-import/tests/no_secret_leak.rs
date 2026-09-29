//! Key material must never reach a `Debug` rendering.
//!
//! This crate exists to handle other people's Zcash spending keys. A single
//! `tracing::debug!`, `dbg!`, `unwrap` panic message, or `{:?}` in an error
//! path is enough to write one to a log file or a crash report, and a
//! recovered Sprout key is unrecoverable once disclosed.
//!
//! The guard is easy to lose: swapping a `Secret<T>` field for a plain
//! `Vec<u8>`, or adding `#[derive(Debug)]` to a struct that grows a key
//! field later, both reintroduce the leak with no compiler complaint. These
//! tests fail loudly if that happens.

use argos_wallet_import::keys::{ImportedKeys, Provenance, SaplingKey, SproutKey, TransparentKey};
use argos_wallet_import::zcashd::{derive_master_key, MkeyRecord};
use argos_wallet_import::ImportDiagnostic;
use secrecy::{Secret, SecretString};

/// Distinctive byte patterns, so a leak is unambiguous in the rendered
/// output rather than something that might coincidentally appear.
const TRANSPARENT_MARKER: u8 = 0xAB;
const SPROUT_MARKER: u8 = 0xCD;
const SAPLING_MARKER: u8 = 0xEF;

/// Passphrase every encrypted golden fixture was created with.
const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

/// Assert that a rendered string does not contain `marker`'s bytes.
///
/// **Precondition: the secret being checked must be a uniform fill of
/// `marker`.** The decimal arm looks for the marker repeated adjacently,
/// which is what a byte array renders as, and would not catch a single
/// stray byte surrounded by different ones. Every call site here fills a
/// buffer with one repeated marker, so that holds — but do not reuse this
/// helper for a non-uniform payload without strengthening it.
fn assert_no_marker(rendered: &str, marker: u8, what: &str) {
    let hex_lower = format!("{marker:02x}");
    let hex_upper = format!("{marker:02X}");
    let decimal = marker.to_string();

    assert!(
        !rendered.contains(&hex_lower) && !rendered.contains(&hex_upper),
        "{what} secret bytes leaked into Debug output as hex: {rendered}"
    );
    // A derived Debug on a byte array renders decimal, not hex, so check
    // both representations.
    assert!(
        !rendered.contains(&format!("{decimal}, {decimal}")),
        "{what} secret bytes leaked into Debug output as decimals: {rendered}"
    );
}

#[test]
fn transparent_key_debug_is_redacted() {
    let k = TransparentKey {
        secret: Secret::new([TRANSPARENT_MARKER; 32]),
        provenance: Provenance::HdDerived,
    };
    let rendered = format!("{k:?}");
    assert_no_marker(&rendered, TRANSPARENT_MARKER, "transparent");
    assert!(
        rendered.contains("REDACTED") || rendered.contains("redacted"),
        "expected an explicit redaction marker, got: {rendered}"
    );
}

#[test]
fn sprout_key_debug_is_redacted() {
    // The spending key must be redacted. The payment address is public and
    // may legitimately appear — it is what the user needs to identify the
    // funds.
    let k = SproutKey {
        a_sk: Secret::new([SPROUT_MARKER; 32]),
        address: [0x11; 64],
        provenance: Provenance::Standalone,
    };
    let rendered = format!("{k:?}");
    assert_no_marker(&rendered, SPROUT_MARKER, "sprout a_sk");
}

#[test]
fn sapling_key_debug_is_redacted() {
    // 169 bytes: the real serialized extended spending key length.
    let k = SaplingKey {
        extsk: Secret::new(vec![SAPLING_MARKER; 169]),
        provenance: Provenance::Standalone,
    };
    let rendered = format!("{k:?}");
    assert_no_marker(&rendered, SAPLING_MARKER, "sapling extsk");
}

#[test]
fn master_key_debug_is_redacted() {
    // The master key unlocks every encrypted record in the wallet — every
    // transparent key, every Sapling key, and the encrypted Sprout keys
    // this project exists to recover. Leaking it is strictly worse than
    // leaking any single key, and it now has a public `expose_secret`
    // accessor, so the type is a live rendering path.
    // Derive from a real zcashd-encrypted wallet rather than a synthetic
    // record. A hand-built mkey does not survive PKCS#7 unpadding, so a
    // conditional `if let Ok(..)` here would silently assert nothing —
    // the test would pass while proving nothing at all.
    let bytes = std::fs::read("tests/fixtures/modern-encrypted.dat")
        .expect("modern-encrypted.dat fixture must exist");
    let records = argos_wallet_import::bdb::walk(&bytes).expect("fixture must walk");
    let mkey: MkeyRecord = argos_wallet_import::zcashd::find_mkey(&records)
        .expect("encrypted wallet must have an mkey");

    let master = derive_master_key(&SecretString::new(FIXTURE_PASSPHRASE.to_owned()), &mkey)
        .expect("the fixture passphrase must derive a master key");

    let rendered = format!("{master:?}");
    let secret_rendered = format!("{:?}", master.expose_secret());

    assert!(
        !rendered.contains(&secret_rendered),
        "master key bytes leaked into Debug output: {rendered}"
    );
    assert!(
        rendered.contains("REDACTED") || rendered.contains("redacted"),
        "expected an explicit redaction marker, got: {rendered}"
    );
}

#[test]
fn an_imported_key_set_does_not_leak_through_debug() {
    // The aggregate is what a caller is most likely to log, so it gets its
    // own guard rather than relying on the per-key impls above.
    let mut keys = ImportedKeys::default();
    keys.transparent.push(TransparentKey {
        secret: Secret::new([TRANSPARENT_MARKER; 32]),
        provenance: Provenance::HdDerived,
    });
    keys.sprout.push(SproutKey {
        a_sk: Secret::new([SPROUT_MARKER; 32]),
        address: [0x11; 64],
        provenance: Provenance::Standalone,
    });
    keys.sapling.push(SaplingKey {
        extsk: Secret::new(vec![SAPLING_MARKER; 169]),
        provenance: Provenance::Standalone,
    });

    // ImportedKeys has its own manual Debug impl (Result::unwrap_err needs
    // Ok: Debug), so the aggregate is a live rendering path in its own
    // right — and it is the one a caller is most likely to log. Assert it
    // rather than relying on a comment that it only prints counts.
    let aggregate = format!("{keys:?}");
    assert_no_marker(&aggregate, TRANSPARENT_MARKER, "transparent (aggregate)");
    assert_no_marker(&aggregate, SPROUT_MARKER, "sprout a_sk (aggregate)");
    assert_no_marker(&aggregate, SAPLING_MARKER, "sapling extsk (aggregate)");
    assert!(
        aggregate.contains('1'),
        "aggregate Debug should still report counts, got: {aggregate}"
    );

    // And each element individually, in case the aggregate is later changed
    // to delegate to them.
    for k in &keys.transparent {
        assert_no_marker(&format!("{k:?}"), TRANSPARENT_MARKER, "transparent");
    }
    for k in &keys.sprout {
        assert_no_marker(&format!("{k:?}"), SPROUT_MARKER, "sprout a_sk");
    }
    for k in &keys.sapling {
        assert_no_marker(&format!("{k:?}"), SAPLING_MARKER, "sapling extsk");
    }
}

#[test]
fn recovered_mnemonic_does_not_leak_through_debug() {
    // A decrypted ZWL wallet's recovered seed is a BIP-39 phrase, not a
    // uniform byte fill, so `assert_no_marker`'s hex/decimal check doesn't
    // apply here — this checks for the literal phrase text instead.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                   abandon abandon about";

    let keys = ImportedKeys {
        mnemonic: Some(SecretString::new(phrase.to_owned())),
        ..ImportedKeys::default()
    };

    let rendered = format!("{keys:?}");
    assert!(
        !rendered.contains(phrase),
        "mnemonic phrase leaked into Debug output: {rendered}"
    );
    assert!(
        rendered.contains("mnemonic"),
        "expected an explicit (redacted) mnemonic field, got: {rendered}"
    );

    // Non-vacuous: prove the phrase text would actually appear if
    // `ImportedKeys`'s Debug impl ever rendered this field naively (e.g.
    // a derive, or delegating to `SecretString`'s inner value directly),
    // so the negative assertion above is not trivially satisfied.
    let naively_rendered = format!("{phrase:?}");
    assert!(
        naively_rendered.contains(phrase),
        "sanity check: a plain Debug of the phrase must contain the phrase itself, or this \
         test proves nothing"
    );
}

/// Each zcashd 5.x golden fixture, whether it is encrypted, and the first
/// four words of its BIP-39 phrase. Four adjacent words cannot turn up in a
/// rendering by coincidence, so finding them means the phrase leaked.
const SEED_FIXTURES: [(&str, bool, &str); 4] = [
    ("modern-plaintext", false, "almost elegant report wrist"),
    ("modern-encrypted", true, "salmon gown still zoo"),
    ("sprout-plaintext", false, "walk protect ticket novel"),
    ("sprout-encrypted", true, "arch evolve memory trophy"),
];

fn import_fixture(bytes: &[u8], encrypted: bool) -> ImportedKeys {
    let pass = SecretString::new(FIXTURE_PASSPHRASE.to_owned());
    argos_wallet_import::zcashd::import_zcashd(bytes, encrypted.then_some(&pass))
        .expect("golden fixture must import")
}

/// Every rendering of an import result a caller could log or show.
fn renderings(keys: &ImportedKeys) -> Vec<(String, String)> {
    let mut out = vec![
        ("ImportedKeys Debug".to_owned(), format!("{keys:?}")),
        ("mnemonic Debug".to_owned(), format!("{:?}", keys.mnemonic)),
    ];
    for (i, d) in keys.diagnostics.iter().enumerate() {
        out.push((format!("diagnostic {i} Display"), d.to_string()));
        out.push((format!("diagnostic {i} Debug"), format!("{d:?}")));
    }
    out
}

fn assert_no_phrase(keys: &ImportedKeys, marker: &str, name: &str) {
    for (what, rendered) in renderings(keys) {
        assert!(
            !rendered.contains(marker),
            "{name}: the seed phrase leaked into the {what}: {rendered}"
        );
    }
}

/// Non-vacuous: the phrase really is in the file, so its absence from the
/// renderings is the import withholding it rather than never having seen it.
fn assert_fixture_holds(bytes: &[u8], marker: &str, name: &str) {
    assert!(
        bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
        "{name}: the fixture no longer holds its phrase in plaintext, so the leak \
         checks against it prove nothing"
    );
}

#[test]
fn a_verified_zcashd_seed_does_not_leak_through_any_rendering() {
    // zcashd 5.x wallets carry a BIP-39 phrase. `import_zcashd` reads it
    // only to verify the stored keys, then drops it; nothing it returns may
    // carry the words — not the aggregate, not a diagnostic, not `mnemonic`.
    for (name, encrypted, marker) in SEED_FIXTURES {
        let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
        assert_fixture_holds(&bytes, marker, name);
        let keys = import_fixture(&bytes, encrypted);
        assert!(keys.seed_verified, "{name}: the fixture seed should verify");
        assert_no_phrase(&keys, marker, name);
    }
}

/// Replace the single occurrence of `needle` in `bytes` with `with`,
/// failing rather than guessing if it is absent or ambiguous.
fn replace_once(bytes: &mut [u8], needle: &[u8], with: &[u8]) {
    assert_eq!(needle.len(), with.len());
    let hits: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "needle must occur exactly once in the fixture"
    );
    bytes[hits[0]..hits[0] + needle.len()].copy_from_slice(with);
}

fn unrecovered_seed(keys: &ImportedKeys) -> Vec<&ImportDiagnostic> {
    keys.diagnostics
        .iter()
        .filter(|d| matches!(d, ImportDiagnostic::UnrecoveredSeed { .. }))
        .collect()
}

#[test]
fn a_seed_whose_chain_fails_does_not_leak_through_its_diagnostic() {
    // The phrase decodes and matches its fingerprint, but the
    // `mnemonichdchain` record names a different seed. The fingerprint also
    // keys the `mnemonicphrase` record and sits in every keymeta value, so
    // flip it only inside the chain: locate the chain's whole 61-byte value,
    // which occurs exactly once in the file.
    let (name, _, marker) = SEED_FIXTURES[0];
    let mut bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
    let chain = argos_wallet_import::bdb::walk(&bytes)
        .unwrap()
        .into_iter()
        .find(|(k, _)| {
            argos_wallet_import::zcashd::parse_record_key(k)
                .is_some_and(|r| r.record_type == "mnemonichdchain")
        })
        .map(|(_, v)| v)
        .expect("the fixture has a mnemonichdchain record");
    let mut tampered = chain.clone();
    tampered[4] ^= 1; // first byte of the chain's seed fingerprint
    replace_once(&mut bytes, &chain, &tampered);

    let keys = import_fixture(&bytes, false);
    assert!(!keys.seed_verified);
    assert!(
        matches!(unrecovered_seed(&keys).as_slice(),
            [ImportDiagnostic::UnrecoveredSeed { record_type, .. }]
            if record_type == "mnemonichdchain"),
        "expected one mnemonichdchain UnrecoveredSeed, got: {:?}",
        keys.diagnostics
    );
    assert_no_phrase(&keys, marker, name);
}

#[test]
fn a_phrase_that_fails_to_decode_does_not_leak_through_its_diagnostic() {
    // The failure most tempted to quote the phrase: a word outside the
    // BIP-39 list. bip0039's error names the offending word, so a reason
    // built from it would carry phrase text. Mangle the fifth word so the
    // four-word marker stays intact, and look for the mangled word too.
    let (name, _, marker) = SEED_FIXTURES[0];
    let mut bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
    replace_once(&mut bytes, b"wrist cloth recall", b"wrist clotj recall");

    let keys = import_fixture(&bytes, false);
    assert!(!keys.seed_verified);
    assert!(
        matches!(unrecovered_seed(&keys).as_slice(),
            [ImportDiagnostic::UnrecoveredSeed { record_type, .. }]
            if record_type == "mnemonicphrase"),
        "expected one mnemonicphrase UnrecoveredSeed, got: {:?}",
        keys.diagnostics
    );
    assert_no_phrase(&keys, marker, name);
    assert_no_phrase(&keys, "clotj", name);
}
