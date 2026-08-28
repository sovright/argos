use std::str::FromStr;

use zcash_address::unified::{self, Encoding};
use zcash_address::ZcashAddress;
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::PoolType;

use crate::{
    error::{ZeckError, ZeckResult},
    models::{AddressInfo, ZeckNetwork},
};

fn network_type(network: ZeckNetwork) -> NetworkType {
    match network {
        ZeckNetwork::Mainnet => NetworkType::Main,
        ZeckNetwork::Testnet => NetworkType::Test,
    }
}

fn network_type_label(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => "mainnet",
        NetworkType::Test => "testnet",
        NetworkType::Regtest => "regtest",
    }
}

/// Validates a sweep destination against the scan's network.
///
/// The destination must be a Unified Address with an Orchard or Sapling
/// receiver, and its network (recovered from the UA's network-unique HRP) must
/// match the scan's network. Mismatches are rejected up front with
/// [`ZeckError::WrongNetwork`] rather than surfacing later as an opaque
/// proposal-construction error.
pub fn validate_destination_address(
    address: &str,
    network: ZeckNetwork,
) -> ZeckResult<AddressInfo> {
    let parsed = ZcashAddress::from_str(address)
        .or_else(|_| ZcashAddress::try_from_encoded(address))
        .map_err(|err| ZeckError::InvalidAddress(err.to_string()))?;

    let has_orchard = parsed.can_receive_as(PoolType::ORCHARD);
    let has_sapling = parsed.can_receive_as(PoolType::SAPLING);
    let has_transparent = parsed.can_receive_as(PoolType::TRANSPARENT);

    // `unified::Address::decode` recovers the address's network from its HRP.
    // UA HRPs are network-unique, so this also correctly rejects regtest
    // addresses on a mainnet or testnet scan.
    let decoded = unified::Address::decode(address);
    let is_unified = decoded.is_ok();

    if !is_unified {
        return Err(ZeckError::DestinationMustBeUnified);
    }

    let (address_net, _) = decoded.expect("is_unified implies decode succeeded");
    let expected_net = network_type(network);

    // The regtest harness derives destinations under regtest parameters, so
    // they carry the `uregtest` HRP while the scan's network is testnet.
    // Accept that pairing only when regtest consensus parameters have actually
    // been installed in this process — a deliberate local act, not something
    // an address or a server can assert — and only in `argos-network` builds.
    // A released binary still rejects every regtest address outright.
    #[cfg(feature = "argos-network")]
    let regtest_harness_destination = expected_net == NetworkType::Test
        && address_net == NetworkType::Regtest
        && crate::workspace::regtest_consensus_params_installed();
    #[cfg(not(feature = "argos-network"))]
    let regtest_harness_destination = false;

    if address_net != expected_net && !regtest_harness_destination {
        return Err(ZeckError::WrongNetwork {
            expected: network_type_label(expected_net).to_owned(),
            actual: network_type_label(address_net).to_owned(),
        });
    }

    let destination_ok = has_orchard || has_sapling;

    if !destination_ok {
        return Err(ZeckError::UnsupportedDestination);
    }

    Ok(AddressInfo {
        encoded: address.to_owned(),
        is_unified,
        has_orchard,
        has_sapling,
        has_transparent,
        destination_ok,
    })
}

/// The Sapling receiver of a destination address, if it has one.
///
/// Absent and malformed are different problems with different fixes and must
/// not be reported identically: "this address can never receive shielded
/// value" sends the user for a different address, "these bytes do not decode"
/// sends them to re-copy the one they have.
pub enum SaplingReceiver {
    /// The receiver, and whether it came from a unified address rather than a
    /// bare Sapling one.
    Found(sapling_crypto::PaymentAddress, bool),
    Malformed,
    Absent,
}

/// Why a destination could not be read at all.
pub enum ReceiverLookupError {
    NotAnAddress(String),
    IncorrectNetwork { expected: String, actual: String },
    Unsupported(String),
}

/// Walk a destination address for its Sapling receiver.
///
/// The `TryFromAddress` machinery below existed twice — once in
/// `sprout_sweep` and once in `transparent_recovery` — as ~85 near-identical
/// lines each, and the same review finding had to be applied to both. Only
/// the walk is shared: the two callers map the result onto deliberately
/// different error vocabularies (one typed, one explanatory), each pinned by
/// its own tests, so folding those together would silently change one
/// surface's behaviour.
pub fn find_sapling_receiver(
    destination: &str,
    network: crate::ZeckNetwork,
) -> Result<SaplingReceiver, ReceiverLookupError> {
    use zcash_address::{
        unified::{Container, Receiver},
        ConversionError, TryFromAddress, ZcashAddress,
    };
    use zcash_protocol::consensus::NetworkType;

    let parsed = ZcashAddress::try_from_encoded(destination)
        .map_err(|err| ReceiverLookupError::NotAnAddress(err.to_string()))?;

    struct Found(SaplingReceiver);
    impl TryFromAddress for Found {
        type Error = &'static str;

        fn try_from_sapling(
            _net: NetworkType,
            data: [u8; 43],
        ) -> Result<Self, ConversionError<Self::Error>> {
            Ok(Found(
                sapling_crypto::PaymentAddress::from_bytes(&data)
                    .map(|a| SaplingReceiver::Found(a, false))
                    .unwrap_or(SaplingReceiver::Malformed),
            ))
        }

        fn try_from_unified(
            _net: NetworkType,
            ua: zcash_address::unified::Address,
        ) -> Result<Self, ConversionError<Self::Error>> {
            for receiver in ua.items() {
                if let Receiver::Sapling(data) = receiver {
                    return Ok(Found(
                        sapling_crypto::PaymentAddress::from_bytes(&data)
                            .map(|a| SaplingReceiver::Found(a, true))
                            .unwrap_or(SaplingReceiver::Malformed),
                    ));
                }
            }
            Ok(Found(SaplingReceiver::Absent))
        }
    }

    let want = network_type(network);
    let retry = parsed.clone();
    parsed
        .convert_if_network::<Found>(want)
        .map(|found| found.0)
        .map_err(|err| match err {
            ConversionError::IncorrectNetwork { expected, actual } => {
                // `convert_if_network` checks the network before the address
                // kind, so a transparent address on the wrong network reports
                // as a network mismatch. Both are true, but only one is
                // fixable: no t-address can receive shielded value on any
                // network, and blaming the network setting sends the user to
                // correct the one thing that is not wrong. Re-run against the
                // address's own network to find out which it really is.
                match retry.convert_if_network::<Found>(actual) {
                    Err(ConversionError::Unsupported(err)) => {
                        ReceiverLookupError::Unsupported(err.to_string())
                    }
                    _ => ReceiverLookupError::IncorrectNetwork {
                        expected: format!("{expected:?}"),
                        actual: format!("{actual:?}"),
                    },
                }
            }
            other => ReceiverLookupError::Unsupported(other.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real mainnet unified address with Orchard + Sapling receivers derived from the
    // BIP-39 all-"abandon" test vector (account 0, produced by argos show-keys).
    const UA_ORCHARD_SAPLING: &str =
        "u1nvgt6yr35mhc9wdf4wckvl38476vqy96dx3cwkfdwy4jet9300l5v8l2yg27ql7w9qwm0lf8kncnj9nus4mgete06j3cu3mhrqvstg6swvdya6xgzwhh6a9xxdhxkavvvmztqeuaurjtqfk3dzetuzgnu0zjvmdpe8ehvj53sy6yhzxj";

    // BIP-39 all-"abandon" test vector (no real funds). Used to derive a
    // testnet UA on the fly so the network-mismatch test does not depend on a
    // hard-coded testnet encoding.
    const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn valid_unified_address_accepted() {
        let info = validate_destination_address(UA_ORCHARD_SAPLING, ZeckNetwork::Mainnet).unwrap();
        assert!(info.is_unified);
        assert!(info.has_orchard);
        assert!(info.has_sapling);
        assert!(info.destination_ok);
        assert!(!info.has_transparent);
    }

    #[test]
    fn transparent_address_rejected() {
        // t1 address — not a unified address at all
        let err = validate_destination_address(
            "t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F",
            ZeckNetwork::Mainnet,
        )
        .unwrap_err();
        assert!(
            matches!(err, ZeckError::DestinationMustBeUnified),
            "got {err:?}"
        );
    }

    #[test]
    fn sapling_address_rejected() {
        // zs1 address — valid Zcash address but not unified
        let err = validate_destination_address(
            "zs16uhd4mux24se6wkm74vld0ec63d4dxt3d7m80l5xytreplkkllrrf9c7fj859mhp8tkcq9hxfvj",
            ZeckNetwork::Mainnet,
        )
        .unwrap_err();
        assert!(
            matches!(err, ZeckError::DestinationMustBeUnified),
            "got {err:?}"
        );
    }

    #[test]
    fn garbage_string_rejected() {
        let err = validate_destination_address("not-an-address", ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");
    }

    #[test]
    fn empty_string_rejected() {
        let err = validate_destination_address("", ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");
    }

    // ─── Address resilience (R-A6..R-A9) ──────────────────────────────────────
    //
    // Coverage gaps named in docs/superpowers/test-plans/recovery-resilience.md.
    // None of these inputs are valid destinations; the validator must reject
    // each without panicking and without ambiguous error variants.

    #[test]
    fn very_long_random_string_rejected_without_panic() {
        // R-A6: defends against pathological clipboard / form input. 100 KB
        // of `u` characters is structurally not a unified address but starts
        // with the expected prefix — the decoder must reject rather than
        // hang on a giant Bech32m payload.
        let huge = "u".to_owned() + &"q".repeat(100_000);
        let err = validate_destination_address(&huge, ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");
    }

    #[test]
    fn upper_case_unified_address_rejected() {
        // R-A7: Bech32m is case-sensitive (case-mixing within the payload is
        // explicitly disallowed). Upper-casing a valid UA must not round-trip
        // back to the same address.
        let upper = UA_ORCHARD_SAPLING.to_ascii_uppercase();
        // Skip if the test UA happens to already be uppercase (impossible for
        // a `u1…` prefix, defensive).
        assert!(upper.starts_with("U1"));
        let err = validate_destination_address(&upper, ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");
    }

    #[test]
    fn unified_address_with_embedded_whitespace_rejected() {
        // R-A8: a space in the middle of a UA is an immediate Bech32m
        // violation. Embedded NUL too — both should reject before any
        // partial parse.
        let with_space = format!(
            "{}{}{}",
            &UA_ORCHARD_SAPLING[..40],
            " ",
            &UA_ORCHARD_SAPLING[40..]
        );
        let err = validate_destination_address(&with_space, ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");

        let with_nul = format!(
            "{}{}{}",
            &UA_ORCHARD_SAPLING[..40],
            "\x00",
            &UA_ORCHARD_SAPLING[40..]
        );
        let err = validate_destination_address(&with_nul, ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");
    }

    #[test]
    fn zip321_payment_uri_rejected_as_destination() {
        // R-A9: `zcash:u1…` is a payment URI, not a destination address.
        // Argos's sweep destination field expects a bare address; the URI
        // form must be rejected so users aren't surprised by their entire
        // ZIP-321 URI (including amount/memo parameters) being silently
        // accepted and partially parsed.
        let uri = format!("zcash:{UA_ORCHARD_SAPLING}");
        let err = validate_destination_address(&uri, ZeckNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidAddress(_)), "got {err:?}");
    }

    // ─── Audit Suggestion 1: destination network validation ───────────────────

    fn testnet_unified_address() -> String {
        let seed = secrecy::SecretString::new(TEST_SEED.to_owned());
        let accounts = crate::derivation::derive_accounts(&seed, ZeckNetwork::Testnet, 1)
            .expect("derive testnet account 0");
        accounts[0].unified_address.clone()
    }

    #[test]
    fn matching_network_unified_address_accepted() {
        // Same testnet UA validated against a testnet scan must pass.
        let ua = testnet_unified_address();
        let info = validate_destination_address(&ua, ZeckNetwork::Testnet).unwrap();
        assert!(info.destination_ok, "got {info:?}");
    }

    #[test]
    fn testnet_address_rejected_on_mainnet_scan() {
        // A testnet UA on a mainnet scan must be rejected up front with
        // WrongNetwork, not surface later as an opaque proposal error.
        let ua = testnet_unified_address();
        let err = validate_destination_address(&ua, ZeckNetwork::Mainnet).unwrap_err();
        match err {
            ZeckError::WrongNetwork { expected, actual } => {
                assert_eq!(expected, "mainnet");
                assert_eq!(actual, "testnet");
            }
            other => panic!("expected WrongNetwork, got {other:?}"),
        }
    }

    #[test]
    fn mainnet_address_rejected_on_testnet_scan() {
        let err =
            validate_destination_address(UA_ORCHARD_SAPLING, ZeckNetwork::Testnet).unwrap_err();
        match err {
            ZeckError::WrongNetwork { expected, actual } => {
                assert_eq!(expected, "testnet");
                assert_eq!(actual, "mainnet");
            }
            other => panic!("expected WrongNetwork, got {other:?}"),
        }
    }
}
