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
