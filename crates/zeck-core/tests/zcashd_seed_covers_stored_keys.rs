//! The claim behind a zcashd 5.x wallet reading as completely recovered.
//!
//! `argos-wallet-import` verifies the seed and trusts zcashd's
//! `mnemonichdchain` counters to say every key the seed derived is stored.
//! This re-derives those keys with independent implementations
//! (`sapling-crypto`, `zcash_transparent`) and checks the golden wallets
//! really do store exactly them, under the legacy account `0x7FFFFFFF` —
//! the account the HD scan never enumerates, which is why the seed is
//! verified rather than scanned.

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

/// Read the phrase straight from the record rather than through the code
/// under test, which deliberately never exposes it.
fn seed_of(bytes: &[u8]) -> [u8; 64] {
    let value = bdb::walk(bytes)
        .unwrap()
        .into_iter()
        .find(|(k, _)| parse_record_key(k).unwrap().record_type == "mnemonicphrase")
        .map(|(_, v)| v)
        .unwrap();
    // u32 language, then a one-byte CompactSize (every phrase is < 253 bytes).
    let phrase = std::str::from_utf8(&value[5..]).unwrap();
    Mnemonic::<English>::from_phrase(phrase)
        .unwrap()
        .to_seed("")
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
        let seed = seed_of(&bytes);
        let keys = import_zcashd(&bytes, passphrase).unwrap();
        assert!(keys.seed_verified, "{name}");

        let master = sapling_crypto::zip32::ExtendedSpendingKey::master(&seed);
        let derived_sapling: Vec<Vec<u8>> = (0..keys.sapling.len() as u32)
            .map(|i| {
                let path = [32, COIN_TYPE, LEGACY_ACCOUNT, i].map(ChildIndex::hardened);
                sapling_crypto::zip32::ExtendedSpendingKey::from_path(&master, &path)
                    .to_bytes()
                    .to_vec()
            })
            .collect();
        for key in &keys.sapling {
            assert!(
                derived_sapling.contains(key.extsk.expose_secret()),
                "{name}: a stored Sapling key is not m/32'/{COIN_TYPE}'/{LEGACY_ACCOUNT:#x}'/i'"
            );
        }

        let account = AccountPrivKey::from_seed(
            &TEST_NETWORK,
            &seed,
            AccountId::try_from(LEGACY_ACCOUNT).unwrap(),
        )
        .unwrap();
        // The chain's counters for these wallets: 2 external, 101 internal.
        let child = |i| NonHardenedChildIndex::from_index(i).unwrap();
        let mut derived_transparent: Vec<[u8; 32]> = (0..2)
            .map(|i| {
                account
                    .derive_external_secret_key(child(i))
                    .unwrap()
                    .secret_bytes()
            })
            .collect();
        derived_transparent.extend((0..101).map(|i| {
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
        assert_eq!(
            stored, derived_transparent,
            "{name}: stored transparent keys are not exactly the chain's legacy derivations"
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
