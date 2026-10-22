//! Prove that each recovered key carries the creation time zcashd stored for
//! *that* key, read from the golden fixtures.
//!
//! zcashd keeps a `CKeyMetadata` record beside every key: `keymeta` keyed by
//! the public key, `zkeymeta` by the Sprout payment address, `sapzkeymeta` by
//! the Sapling incoming viewing key. A creation time attached to the wrong
//! key is worse than none — it can move a scan's start past a note — so the
//! lookup here does not trust the parser's own matching. It re-derives each
//! key's public identifier with an independent implementation (`secp256k1`
//! for the pubkey, `sapling-crypto` for the ivk; the Sprout address is the
//! record's own key) and reads the time straight from the metadata record
//! stored under that identifier.

use std::collections::HashMap;

use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use sapling_crypto::zip32::ExtendedSpendingKey;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use secrecy::{ExposeSecret, SecretString};

const FIXTURE_PASSPHRASE: &str = "argos-test-passphrase";

/// The fixtures were generated in mid-2026 (see
/// `tests/regtest/fixtures/README.md`). Anything outside this window means
/// the time was read from the wrong offset.
const PLAUSIBLE_FROM: i64 = 1_767_225_600; // 2026-01-01
const PLAUSIBLE_TO: i64 = 1_798_761_600; // 2027-01-01

fn load(fixture: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat"))
        .unwrap_or_else(|e| panic!("fixture {fixture}: {e}"));
    bdb::walk(&bytes)
        .unwrap_or_else(|e| panic!("walking {fixture}: {e}"))
        .records
}

fn import(fixture: &str) -> ImportedKeys {
    let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat")).unwrap();
    let pass = SecretString::new(FIXTURE_PASSPHRASE.to_owned());
    zcashd::import_zcashd(&bytes, Some(&pass)).unwrap()
}

/// Every metadata record of one type, keyed by its record-key remainder,
/// with `nCreateTime` read directly from bytes 4..12 of the value.
fn stored_times(pairs: &[(Vec<u8>, Vec<u8>)], record_type: &str) -> HashMap<Vec<u8>, i64> {
    pairs
        .iter()
        .filter_map(|(raw_key, value)| {
            let rec = zcashd::parse_record_key(raw_key)?;
            (rec.record_type == record_type).then(|| {
                (
                    rec.rest,
                    i64::from_le_bytes(value[4..12].try_into().unwrap()),
                )
            })
        })
        .collect()
}

fn pubkey_record_key(secret: &[u8; 32]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(secret).unwrap());
    // `CPubKey` serializes as CompactSize(33) || compressed pubkey.
    let mut key = vec![33u8];
    key.extend_from_slice(&pubkey.serialize());
    key
}

fn ivk_of(extsk: &[u8]) -> Vec<u8> {
    let extsk = ExtendedSpendingKey::from_bytes(extsk).unwrap();
    extsk
        .to_diversifiable_full_viewing_key()
        .fvk()
        .vk
        .ivk()
        .to_repr()
        .to_vec()
}

#[test]
fn every_fixture_key_carries_the_time_stored_for_it() {
    for fixture in [
        "sprout-plaintext",
        "sprout-encrypted",
        "modern-plaintext",
        "modern-encrypted",
    ] {
        let pairs = load(fixture);
        let keys = import(fixture);

        let keymeta = stored_times(&pairs, "keymeta");
        assert!(!keys.transparent.is_empty(), "{fixture}");
        for key in &keys.transparent {
            let want = keymeta[&pubkey_record_key(key.secret.expose_secret())];
            assert_eq!(key.created_at, Some(want), "{fixture}: transparent");
            assert!(
                (PLAUSIBLE_FROM..PLAUSIBLE_TO).contains(&want),
                "{fixture}: {want}"
            );
        }

        let sapzkeymeta = stored_times(&pairs, "sapzkeymeta");
        assert!(!keys.sapling.is_empty(), "{fixture}");
        for key in &keys.sapling {
            let want = sapzkeymeta[&ivk_of(key.extsk.expose_secret())];
            assert_eq!(key.created_at, Some(want), "{fixture}: sapling");
            assert!(
                (PLAUSIBLE_FROM..PLAUSIBLE_TO).contains(&want),
                "{fixture}: {want}"
            );
        }

        let zkeymeta = stored_times(&pairs, "zkeymeta");
        for key in &keys.sprout {
            let want = zkeymeta[key.address.as_slice()];
            assert_eq!(key.created_at, Some(want), "{fixture}: sprout");
            assert!(
                (PLAUSIBLE_FROM..PLAUSIBLE_TO).contains(&want),
                "{fixture}: {want}"
            );
        }
        assert_eq!(
            keys.sprout.len(),
            usize::from(fixture.starts_with("sprout")),
            "{fixture}"
        );

        // Reading metadata must not cost the wallet any coverage, and none of
        // these well-formed records may be reported as unreadable.
        assert!(
            keys.diagnostics.iter().all(|d| !matches!(
                d,
                argos_wallet_import::ImportDiagnostic::UnreadableKeyMetadata { .. }
            )),
            "{fixture}: {:?}",
            keys.diagnostics
        );
    }
}
