//! Reading zcashd's text encoding for Sapling extended spending keys.
//!
//! A user may hold a Sapling spending key as a `secret-extended-key-main1…`
//! string — from `z_exportkey`, from `zcashd-wallet-tool`, or from a paper
//! backup — with no `wallet.dat` at all. That string is the whole of what
//! they have, so decoding it correctly is the entire difference between a
//! recovery and a dead end. This is the same situation `sprout_key` handles
//! for Sprout.
//!
//! # Why this needs no golden-constant caveat
//!
//! `sprout_key` pins zcashd's base58 version bytes by hand and documents that
//! mainnet has no oracle in this repo. Sapling has no such problem: the
//! human-readable parts come from `zcash_protocol::constants`, which is the
//! same source librustzcash, zcashd, and every other wallet encode against.
//! The test below still pins the literal strings, so an upstream rename
//! cannot silently move Argos off the prefix users actually hold.

use zcash_keys::encoding::{decode_extended_spending_key, AddressCodec};
use zcash_keys::keys::sapling::ExtendedSpendingKey;
use zcash_protocol::constants;

use crate::{
    error::{ZeckError, ZeckResult},
    models::ZeckNetwork,
};

/// The bech32 human-readable part for a spending key on this network.
fn spending_key_hrp(network: ZeckNetwork) -> &'static str {
    match network {
        ZeckNetwork::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        ZeckNetwork::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
    }
}

/// The bech32 human-readable part for a *viewing* key on this network.
///
/// Not accepted as input — used only to recognise one and say why it is not
/// enough.
fn viewing_key_hrp(network: ZeckNetwork) -> &'static str {
    match network {
        ZeckNetwork::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        ZeckNetwork::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
    }
}

fn other_network(network: ZeckNetwork) -> ZeckNetwork {
    match network {
        ZeckNetwork::Mainnet => ZeckNetwork::Testnet,
        ZeckNetwork::Testnet => ZeckNetwork::Mainnet,
    }
}

/// Decode a bech32 Sapling extended spending key.
///
/// Every rejection names what the user must do next: a correct key for the
/// other network says so, a Sprout key is redirected to the Sprout route, and
/// a viewing key is told why viewing is not spending. "Invalid key" sends a
/// user hunting for a different backup when the one in their hand is fine.
pub fn decode_sapling_spending_key(
    s: &str,
    network: ZeckNetwork,
) -> ZeckResult<ExtendedSpendingKey> {
    let trimmed = s.trim();

    if let Ok(key) = decode_extended_spending_key(spending_key_hrp(network), trimmed) {
        return Ok(key);
    }

    let other = other_network(network);
    if decode_extended_spending_key(spending_key_hrp(other), trimmed).is_ok() {
        return Err(ZeckError::Import(format!(
            "this is a {} Sapling spending key, but Argos is set to {}. \
             Re-run against {} to use it.",
            other.label(),
            network.label(),
            other.label(),
        )));
    }

    // zcashd renders Sprout spending keys as base58 `SK…` (mainnet) / `ST…`
    // (testnet). Someone holding two paper backups will mix them up.
    if trimmed.starts_with("SK") || trimmed.starts_with("ST") {
        return Err(ZeckError::Import(
            "that looks like a Sprout spending key, not a Sapling one. \
             Pass it with --sprout-key-file instead (GUI: the Sprout scan panel)."
                .to_owned(),
        ));
    }

    if trimmed.starts_with(viewing_key_hrp(network)) || trimmed.starts_with(viewing_key_hrp(other))
    {
        return Err(ZeckError::Import(
            "that is a Sapling full viewing key. It can show a balance but \
             cannot move it — Argos needs the spending key \
             (`secret-extended-key-…`) to sweep funds."
                .to_owned(),
        ));
    }

    Err(ZeckError::Import(format!(
        "not a Sapling extended spending key: expected a string beginning \
         `{}1…`. Check for a truncated copy — the checksum rejects a partial key.",
        spending_key_hrp(network),
    )))
}

/// The default Sapling address a key controls, for showing a user which key
/// they just pasted.
///
/// Shown instead of the key itself: an address is safe to display, log, and
/// compare against a block explorer or a paper backup, and the key is not.
pub fn default_sapling_address(extsk: &ExtendedSpendingKey, network: ZeckNetwork) -> String {
    let params = crate::workspace::consensus_network(network);
    let (_, address) = extsk.to_diversifiable_full_viewing_key().default_address();
    address.encode(&params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_keys::encoding::encode_extended_spending_key;
    use zcash_protocol::constants;

    /// The prefixes users actually type, pinned against ZIP-32 §5.6.3.1.
    /// An upstream rename must break a test, not a recovery.
    #[test]
    fn the_human_readable_prefixes_are_the_ones_zip32_defines() {
        assert_eq!(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "secret-extended-key-main"
        );
        assert_eq!(
            constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "secret-extended-key-test"
        );
    }

    fn a_key() -> ExtendedSpendingKey {
        sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32])
    }

    #[test]
    fn a_mainnet_key_round_trips_and_yields_its_address() {
        let extsk = a_key();
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &extsk,
        );
        assert!(
            encoded.starts_with("secret-extended-key-main1"),
            "encoded key should carry the prefix users recognise, got: {}",
            &encoded[..30.min(encoded.len())]
        );

        let decoded = decode_sapling_spending_key(&encoded, ZeckNetwork::Mainnet)
            .expect("a well-formed mainnet key must decode");
        assert_eq!(decoded.to_bytes(), extsk.to_bytes());

        let address = default_sapling_address(&decoded, ZeckNetwork::Mainnet);
        assert!(
            address.starts_with("zs1"),
            "mainnet Sapling address should start with zs1, got {address}"
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let padded = format!("  {encoded}\t");
        assert!(decode_sapling_spending_key(&padded, ZeckNetwork::Mainnet).is_ok());
    }

    /// The message must name the real problem. A user holding a correct key
    /// for the other network is not helped by "malformed".
    #[test]
    fn a_testnet_key_on_mainnet_names_the_network() {
        let encoded = encode_extended_spending_key(
            constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let err = decode_sapling_spending_key(&encoded, ZeckNetwork::Mainnet)
            .expect_err("a testnet key must not decode as mainnet")
            .to_string();
        assert!(
            err.contains("testnet"),
            "the message should name the key's real network, got: {err}"
        );
    }

    #[test]
    fn a_mainnet_key_on_testnet_names_the_network() {
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let err = decode_sapling_spending_key(&encoded, ZeckNetwork::Testnet)
            .expect_err("a mainnet key must not decode as testnet")
            .to_string();
        assert!(
            err.contains("mainnet"),
            "the message should name the key's real network, got: {err}"
        );
    }

    /// The exact inverse of `sprout_key`'s
    /// `a_sapling_key_is_not_accepted_as_sprout`. Someone with two paper
    /// backups will mix them up eventually.
    #[test]
    fn a_sprout_key_is_not_accepted_as_sapling_and_points_at_the_right_flag() {
        let sprout = "SKxt8pwrQipUL5KgZUcBAqyLj9R1YwMuRRR7rRRRRRRRRRRRRRRR";
        let err = decode_sapling_spending_key(sprout, ZeckNetwork::Mainnet)
            .expect_err("a Sprout key must not decode as Sapling")
            .to_string();
        assert!(
            err.contains("Sprout") && err.contains("--sprout-key-file"),
            "the message should redirect to the Sprout route, got: {err}"
        );
    }

    /// A viewing key can show a balance but cannot move it. Accepting one
    /// would surface funds the user then cannot sweep.
    ///
    /// `to_extended_full_viewing_key` is deprecated in favour of
    /// `to_diversifiable_full_viewing_key`, but `encode_extended_full_viewing_key`
    /// (below) still takes the old `ExtendedFullViewingKey` type -- it is the
    /// only way to construct the bech32 string this test needs to reject.
    #[test]
    #[allow(deprecated)]
    fn a_viewing_key_is_rejected_as_not_spendable() {
        let extfvk = a_key().to_extended_full_viewing_key();
        let encoded = zcash_keys::encoding::encode_extended_full_viewing_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        );
        let err = decode_sapling_spending_key(&encoded, ZeckNetwork::Mainnet)
            .expect_err("a viewing key must not be accepted as a spending key")
            .to_string();
        assert!(
            err.contains("viewing key") && err.contains("spending key"),
            "the message should explain why a viewing key is not enough, got: {err}"
        );
    }

    #[test]
    fn junk_and_empty_input_are_rejected() {
        for bad in ["", "   ", "not a key", "secret-extended-key-main1", "zs1"] {
            assert!(
                decode_sapling_spending_key(bad, ZeckNetwork::Mainnet).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// A single mistyped character must fail, not silently decode to a
    /// different key. This is what the bech32 checksum is for.
    #[test]
    fn a_single_character_typo_is_caught_by_the_checksum() {
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let typo: String = chars.into_iter().collect();
        assert!(
            decode_sapling_spending_key(&typo, ZeckNetwork::Mainnet).is_err(),
            "a one-character typo must not decode"
        );
    }
}
