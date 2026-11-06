//! Bind recovered spending authority to the public identifier stored beside it.
//! Failed comparisons return no key material or attacker-controlled text.

use sapling_crypto::zip32::ExtendedSpendingKey;
use secp256k1::{PublicKey, SecretKey};
use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;
use zcash_transparent::address::TransparentAddress;

use crate::{keys::EmbeddedNetwork, secret_bytes::SecretArray};

// Keep wallet provenance restricted to the legacy transparent address formats.
// NU7 moved address conversion out of zcash_transparent; do not accept a
// unified or transparent-source-only address as an equivalent stored identity.
struct LegacyTransparentAddress(TransparentAddress);

impl TryFromAddress for LegacyTransparentAddress {
    type Error = std::convert::Infallible;

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self(TransparentAddress::PublicKeyHash(data)))
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self(TransparentAddress::ScriptHash(data)))
    }
}

pub(crate) fn transparent_matches_pubkey(secret: &[u8; 32], stored: &[u8]) -> bool {
    let Ok(sk) = SecretKey::from_secret_bytes(*secret) else {
        return false;
    };
    let derived = PublicKey::from_secret_key(&sk);
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
    let sk = SecretKey::from_secret_bytes(*secret).map_err(|_| ())?;
    let pubkey = PublicKey::from_secret_key(&sk);
    let expected = TransparentAddress::from_pubkey(&pubkey);
    let (network, address): (NetworkType, LegacyTransparentAddress) =
        ZcashAddress::try_from_encoded(stored)
            .map_err(|_| ())?
            .convert()
            .map_err(|_| ())?;
    if address.0 != expected {
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

pub(crate) fn retain_transparent_secret(
    secret: SecretArray<32>,
    public_key: &[u8],
) -> Option<secrecy::Secret<[u8; 32]>> {
    transparent_matches_pubkey(secret.as_array(), public_key).then(|| secret.into_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn mismatched_fixed_secrets_drop_zeroizing_owners() {
        let transparent_dropped = Arc::new(AtomicBool::new(false));
        let transparent = crate::secret_bytes::SecretArray::with_drop_probe(
            [0xA5; 32],
            Arc::clone(&transparent_dropped),
        );
        assert!(retain_transparent_secret(transparent, &[0u8; 33]).is_none());
        assert!(transparent_dropped.load(Ordering::SeqCst));
    }
}
