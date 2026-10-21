//! Bind recovered spending authority to the public identifier stored beside it.
//! Failed comparisons return no key material or attacker-controlled text.

use sapling_crypto::zip32::ExtendedSpendingKey;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{compress256, digest::generic_array::GenericArray};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zcash_address::ZcashAddress;
use zcash_protocol::consensus::NetworkType;
use zcash_transparent::address::TransparentAddress;

use crate::keys::EmbeddedNetwork;

pub(crate) fn transparent_matches_pubkey(secret: &[u8; 32], stored: &[u8]) -> bool {
    let Ok(sk) = SecretKey::from_slice(secret) else {
        return false;
    };
    let derived = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    match stored.len() {
        33 => derived.serialize().as_slice() == stored,
        65 => derived.serialize_uncompressed().as_slice() == stored,
        _ => false,
    }
}

pub(crate) fn transparent_matches_address(
    secret: &[u8; 32],
    stored: &str,
) -> Result<EmbeddedNetwork, ()> {
    let sk = SecretKey::from_slice(secret).map_err(|_| ())?;
    let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let expected = TransparentAddress::from_pubkey(&pubkey);
    let (network, address): (NetworkType, TransparentAddress) =
        ZcashAddress::try_from_encoded(stored)
            .map_err(|_| ())?
            .convert()
            .map_err(|_| ())?;
    if address != expected {
        return Err(());
    }
    Ok(match network {
        NetworkType::Main => EmbeddedNetwork::Mainnet,
        NetworkType::Test => EmbeddedNetwork::Testnet,
        NetworkType::Regtest => EmbeddedNetwork::Regtest,
    })
}

pub(crate) fn sapling_matches_ivk(extsk: &[u8], stored: &[u8]) -> bool {
    let Ok(extsk) = ExtendedSpendingKey::from_bytes(extsk) else {
        return false;
    };
    extsk
        .to_diversifiable_full_viewing_key()
        .fvk()
        .vk
        .ivk()
        .to_repr()
        .as_slice()
        == stored
}

pub(crate) fn sapling_matches_extfvk(extsk: &[u8], stored: &[u8]) -> bool {
    let Ok(extsk) = ExtendedSpendingKey::from_bytes(extsk) else {
        return false;
    };
    let mut derived = [0u8; 169];
    #[allow(deprecated)]
    let result = extsk.to_extended_full_viewing_key().write(&mut derived[..]);
    result.is_ok() && derived.as_slice() == stored
}

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

fn prf_addr(a_sk: &[u8; 32], tag: u8) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(a_sk);
    block[0] = (block[0] & 0x0f) | 0xc0;
    block[32] = tag;
    let mut state = SHA256_IV;
    compress256(&mut state, &[*GenericArray::from_slice(&block)]);
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn sprout_address_from_spending_key(a_sk: &[u8; 32]) -> [u8; 64] {
    let mut address = [0u8; 64];
    address[..32].copy_from_slice(&prf_addr(a_sk, 0));
    let mut sk_enc = prf_addr(a_sk, 1);
    sk_enc[0] &= 248;
    sk_enc[31] &= 127;
    sk_enc[31] |= 64;
    let pk_enc = X25519PublicKey::from(&StaticSecret::from(sk_enc));
    address[32..].copy_from_slice(pk_enc.as_bytes());
    address
}
