//! The claim behind a zcashd 5.x wallet reading as completely recovered.
//!
//! `argos-wallet-import` verifies the seed and trusts zcashd's
//! `mnemonichdchain` counters to say every key the seed derived is stored.
//! This re-derives those keys with independent implementations
//! (`sapling-crypto`, `zcash_transparent`) and checks the golden wallets
//! store exactly them — as many as the chain's counters say, no more, no
//! fewer — under the legacy account `0x7FFFFFFF`, the account the HD scan
//! never enumerates, which is why the seed is verified rather than scanned.

use argos_wallet_import::{bdb, zcashd::import_zcashd, zcashd::parse_record_key};
use bip0039::{English, Mnemonic};
use secrecy::{ExposeSecret, SecretString};
use zcash_protocol::consensus::TEST_NETWORK;
use zcash_transparent::keys::{AccountPrivKey, NonHardenedChildIndex};
use zip32::{AccountId, ChildIndex};

const LEGACY_ACCOUNT: u32 = 0x7FFF_FFFF;
/// The fixtures are regtest wallets, which use the testnet coin type.
const COIN_TYPE: u32 = 1;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("../argos-wallet-import/tests/fixtures/{name}.dat")).unwrap()
}

/// The value of the wallet's `record_type` record, read straight from the
/// file rather than through the code under test.
fn record(bytes: &[u8], record_type: &str) -> Option<Vec<u8>> {
    bdb::walk(bytes)
        .unwrap()
        .into_iter()
        .find(|(k, _)| parse_record_key(k).is_some_and(|r| r.record_type == record_type))
        .map(|(_, v)| v)
}

/// Read the phrase from the plaintext record rather than through the code
/// under test, which deliberately never exposes it.
fn seed_of(name: &str, bytes: &[u8]) -> [u8; 64] {
    let value = record(bytes, "mnemonicphrase")
        .unwrap_or_else(|| panic!("{name}: no plaintext mnemonicphrase record"));
    // u32 language, then a one-byte CompactSize (every phrase is < 253 bytes).
    let phrase = std::str::from_utf8(&value[5..]).unwrap();
    Mnemonic::<English>::from_phrase(phrase)
        .unwrap()
        .to_seed("")
}

/// The chain's legacy-account counters.
struct Counters {
    t_external: u32,
    t_internal: u32,
    sapling: u32,
}

/// Layout: u32 version | fp(32) | i64 create_time | u32 account_counter |
/// u32 legacy_t_external | u32 legacy_t_internal | u32 legacy_sapling | bool.
fn counters_of(name: &str, bytes: &[u8]) -> Counters {
    let value = record(bytes, "mnemonichdchain")
        .unwrap_or_else(|| panic!("{name}: no mnemonichdchain record"));
    assert_eq!(value.len(), 61, "{name}: unexpected mnemonichdchain length");
    let u32_at = |at: usize| u32::from_le_bytes(value[at..at + 4].try_into().unwrap());
    Counters {
        t_external: u32_at(48),
        t_internal: u32_at(52),
        sapling: u32_at(56),
    }
}

#[test]
fn every_stored_key_is_a_legacy_account_derivation_of_the_seed() {
    let pass = SecretString::new("argos-test-passphrase".to_owned());
    for (name, passphrase) in [
        ("modern-plaintext", None),
        ("sprout-plaintext", None),
        ("modern-encrypted", Some(&pass)),
        ("sprout-encrypted", Some(&pass)),
    ] {
        let bytes = fixture(name);
        if passphrase.is_some() {
            // This test derives from the phrase, and reads an encrypted
            // wallet's phrase through the plaintext copy zcashd v6.20.0's
            // `encryptwallet` leaves beside `cmnemonicphrase`. The day a
            // regenerated fixture stops carrying that copy, fail here by
            // name rather than in an unwrap below: this test would then
            // need to decrypt the seed itself. The decryption path is
            // covered separately by
            // `the_encrypted_seed_verifies_without_its_plaintext_copy` in
            // `argos-wallet-import`'s seed.rs.
            assert!(
                record(&bytes, "cmnemonicphrase").is_some(),
                "{name}: an encrypted fixture should carry cmnemonicphrase"
            );
            assert!(
                record(&bytes, "mnemonicphrase").is_some(),
                "{name}: zcashd no longer leaves a plaintext mnemonicphrase beside \
                 cmnemonicphrase, so this test must decrypt the seed instead"
            );
        }
        let seed = seed_of(name, &bytes);
        let counters = counters_of(name, &bytes);
        let keys = import_zcashd(&bytes, passphrase).unwrap();
        assert!(keys.seed_verified, "{name}");

        // Exact sorted-set equality against the chain's legacySapling
        // counter: a missing, extra, or duplicated key all fail. Compared
        // with `assert!` rather than `assert_eq!` so a failure does not
        // print spending keys.
        let master = sapling_crypto::zip32::ExtendedSpendingKey::master(&seed);
        let mut derived_sapling: Vec<Vec<u8>> = (0..counters.sapling)
            .map(|i| {
                let path = [32, COIN_TYPE, LEGACY_ACCOUNT, i].map(ChildIndex::hardened);
                sapling_crypto::zip32::ExtendedSpendingKey::from_path(&master, &path)
                    .to_bytes()
                    .to_vec()
            })
            .collect();
        let mut stored_sapling: Vec<Vec<u8>> = keys
            .sapling
            .iter()
            .map(|k| k.extsk.expose_secret().clone())
            .collect();
        derived_sapling.sort();
        stored_sapling.sort();
        assert!(
            stored_sapling == derived_sapling,
            "{name}: the {} stored Sapling keys are not exactly \
             m/32'/{COIN_TYPE}'/{LEGACY_ACCOUNT:#x}'/i' for i in 0..{} (legacySapling)",
            stored_sapling.len(),
            counters.sapling
        );

        let account = AccountPrivKey::from_seed(
            &TEST_NETWORK,
            &seed,
            AccountId::try_from(LEGACY_ACCOUNT).unwrap(),
        )
        .unwrap();
        let child = |i| NonHardenedChildIndex::from_index(i).unwrap();
        let mut derived_transparent: Vec<[u8; 32]> = (0..counters.t_external)
            .map(|i| {
                account
                    .derive_external_secret_key(child(i))
                    .unwrap()
                    .secret_bytes()
            })
            .collect();
        derived_transparent.extend((0..counters.t_internal).map(|i| {
            account
                .derive_internal_secret_key(child(i))
                .unwrap()
                .secret_bytes()
        }));
        let mut stored: Vec<[u8; 32]> = keys
            .transparent
            .iter()
            .map(|k| *k.secret.expose_secret())
            .collect();
        stored.sort();
        derived_transparent.sort();
        assert!(
            stored == derived_transparent,
            "{name}: the {} stored transparent keys are not exactly the chain's legacy \
             derivations ({} external + {} internal)",
            stored.len(),
            counters.t_external,
            counters.t_internal
        );

        // And none at the ZIP-32 account 0 the HD scan would start from.
        let hd_zero = sapling_crypto::zip32::ExtendedSpendingKey::from_path(
            &master,
            &[32, COIN_TYPE, 0].map(ChildIndex::hardened),
        );
        assert!(!keys
            .sapling
            .iter()
            .any(|k| k.extsk.expose_secret() == &hd_zero.to_bytes().to_vec()));
    }
}
