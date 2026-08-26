//! A transparent key owned by the transparent-only sweep test alone.
//!
//! The transparent-only test cannot borrow a key from the golden wallet
//! fixture. `sweep_imported_wallet` sweeps *both* pools, so the imported
//! Sapling test — which now routes through `execute_sweep` — drains every
//! fixture transparent UTXO as a side effect. Whichever test ran second
//! would find an empty address.
//!
//! Nor can the test generate a key at runtime: the regtest block subsidy is
//! worthless by the height these tests run at (ZIP-212 enforcement forces
//! them past 32,257, where the subsidy has decayed to nothing), so an
//! address `setup.sh` did not fund near genesis cannot be funded later.
//!
//! So the key is a fixed constant shared by the funder and the test. It is
//! also a better fit for what the test claims to cover: a transparent-*only*
//! wallet. The fixture holds Sapling keys, so borrowing one of its
//! transparent keys only ever simulated that case.
//!
//! Not a secret: this key exists to hold worthless regtest coins.
pub const STANDALONE_TRANSPARENT_SECRET: [u8; 32] = [0x11; 32];

/// Derive the standalone key through the same path the importer uses, so
/// the funder and the test cannot disagree about the address.
pub fn standalone_transparent_key() -> argos_core::imported::ImportedTransparentKey {
    use zcash_transparent::address::TransparentAddress;

    let secp = secp256k1::Secp256k1::signing_only();
    let secret = secp256k1::SecretKey::from_slice(&STANDALONE_TRANSPARENT_SECRET)
        .expect("the standalone test key is a valid secp256k1 scalar");
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    argos_core::imported::ImportedTransparentKey {
        secret,
        address: TransparentAddress::from_pubkey(&pubkey),
    }
}
