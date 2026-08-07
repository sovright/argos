//! Reading and writing zcashd's text encodings for Sprout.
//!
//! A user may hold a Sprout spending key as a `SK…` string from
//! `z_exportkey` or a paper backup, with no `wallet.dat` at all. That string
//! is the whole of what they have, so decoding it correctly is the entire
//! difference between a recovery and a dead end.
//!
//! Sprout address encoding is here too, because it is the only way to show a
//! user an address they can recognise. A Sprout address is 64 raw bytes with
//! no text form of its own inside a wallet file, so Argos previously printed
//! hex — which nobody can match against a paper backup or a block explorer.
//!
//! # Where the constants come from
//!
//! Not from memory. The testnet/regtest pair was produced by a running
//! `zcashd` and is preserved as the golden fixture in this module's tests:
//! decoding the key must derive exactly the address zcashd reported for it.
//! That is the same self-validating shape as
//! `argos-wallet-import`'s `sprout_key_is_genuine`.
//!
//! The mainnet pair cannot be measured here — generating a Sprout address
//! requires a Canopy-inactive chain, and mainnet passed Canopy in 2020. It is
//! instead pinned by the rendering it must produce: a 32-byte payload under
//! the key prefix has to encode to `SK…`, and a 64-byte payload under the
//! address prefix to `zc…`. Those tests fail if either constant is wrong.

use crate::{
    error::{ZeckError, ZeckResult},
    p2p::wire::sha256d,
    sprout::SproutPaymentAddress,
    ZeckNetwork,
};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// `zcSpendingKey` version bytes.
const MAINNET_SPENDING_KEY: [u8; 2] = [0xAB, 0x36];
const TESTNET_SPENDING_KEY: [u8; 2] = [0xAC, 0x08];

/// `zcPaymentAddress` version bytes.
const MAINNET_PAYMENT_ADDRESS: [u8; 2] = [0x16, 0x9A];
const TESTNET_PAYMENT_ADDRESS: [u8; 2] = [0x16, 0xB6];

fn spending_key_prefix(network: ZeckNetwork) -> [u8; 2] {
    match network {
        ZeckNetwork::Mainnet => MAINNET_SPENDING_KEY,
        ZeckNetwork::Testnet => TESTNET_SPENDING_KEY,
    }
}

fn payment_address_prefix(network: ZeckNetwork) -> [u8; 2] {
    match network {
        ZeckNetwork::Mainnet => MAINNET_PAYMENT_ADDRESS,
        ZeckNetwork::Testnet => TESTNET_PAYMENT_ADDRESS,
    }
}

/// Base58 decode. No bignum dependency: the payloads are at most 70 bytes,
/// so long multiplication over a byte buffer is both sufficient and easier
/// to audit than pulling in an arbitrary-precision crate.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    let mut out = vec![0u8; s.len()];
    for ch in s.bytes() {
        let mut carry = ALPHABET.iter().position(|c| *c == ch)? as u32;
        for byte in out.iter_mut().rev() {
            carry += 58 * u32::from(*byte);
            *byte = (carry % 256) as u8;
            carry /= 256;
        }
        if carry != 0 {
            return None;
        }
    }

    // Leading '1's encode leading zero bytes; everything before the first
    // significant byte of the buffer is padding from the fixed-size scratch.
    let leading_zeros = s.bytes().take_while(|c| *c == b'1').count();
    let first_significant = out.iter().position(|b| *b != 0).unwrap_or(out.len());
    let mut result = vec![0u8; leading_zeros];
    result.extend_from_slice(out.get(first_significant..)?);
    Some(result)
}

fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::new();
    for _ in bytes.iter().take_while(|b| **b == 0) {
        out.push('1');
    }
    for digit in digits.iter().rev() {
        out.push(char::from(ALPHABET[*digit as usize]));
    }
    if out.is_empty() {
        out.push('1');
    }
    out
}

/// Strip and verify a base58check envelope, returning the body.
///
/// The checksum is what turns a mistyped key into an error rather than a
/// silently wrong one — which for a recovery tool means a wrong address
/// derived, no notes found, and no indication why.
fn base58check_decode(s: &str) -> Option<Vec<u8>> {
    let raw = base58_decode(s.trim())?;
    if raw.len() < 5 {
        return None;
    }
    let (body, checksum) = raw.split_at(raw.len() - 4);
    if sha256d(body).get(..4)? != checksum {
        return None;
    }
    Some(body.to_vec())
}

fn base58check_encode(prefix: [u8; 2], payload: &[u8]) -> String {
    let mut body = prefix.to_vec();
    body.extend_from_slice(payload);
    let checksum = sha256d(&body);
    body.extend_from_slice(&checksum[..4]);
    base58_encode(&body)
}

/// Decode a `SK…` (mainnet) or `ST…` (testnet/regtest) Sprout spending key.
pub fn decode_sprout_spending_key(encoded: &str, network: ZeckNetwork) -> ZeckResult<[u8; 32]> {
    let want = spending_key_prefix(network);

    let body = base58check_decode(encoded).ok_or_else(|| {
        ZeckError::InvalidAddress(
            "this is not a valid Sprout spending key: the text is malformed or its \
             checksum does not match, which usually means a typo or a truncated copy"
                .to_owned(),
        )
    })?;

    let (prefix, payload) = body.split_at(body.len().min(2));
    if prefix != want {
        // Naming the other network is the useful part: pasting a testnet key
        // while set to mainnet is a far more common mistake than a corrupt
        // key, and "invalid key" would send someone hunting for a typo.
        let other = match network {
            ZeckNetwork::Mainnet => TESTNET_SPENDING_KEY,
            ZeckNetwork::Testnet => MAINNET_SPENDING_KEY,
        };
        if prefix == other {
            return Err(ZeckError::InvalidAddress(format!(
                "this is a Sprout spending key for the other network. Re-run with the \
                 matching --network, or check you pasted the right key. (expected prefix \
                 {want:02x?}, found {prefix:02x?})"
            )));
        }
        return Err(ZeckError::InvalidAddress(format!(
            "this is not a Sprout spending key (expected prefix {want:02x?}, found \
             {prefix:02x?}). Sapling and Orchard keys are not Sprout keys and cannot be \
             used here."
        )));
    }

    payload.try_into().map_err(|_| {
        ZeckError::InvalidAddress(format!(
            "a Sprout spending key carries 32 bytes; this one has {}",
            payload.len()
        ))
    })
}

/// Encode a spending key back to its `SK…`/`ST…` form.
///
/// Present so the decoder can be tested against its own inverse and against
/// zcashd's output at the same time; a decoder checked only against itself
/// proves nothing about the encoding.
pub fn encode_sprout_spending_key(a_sk: &[u8; 32], network: ZeckNetwork) -> String {
    base58check_encode(spending_key_prefix(network), a_sk)
}

/// Encode a Sprout payment address as `zc…`/`zt…`.
///
/// A Sprout address is 64 raw bytes inside a wallet file with no text form,
/// so this is the only way to show a user something they can match against a
/// paper backup or a block explorer.
pub fn encode_sprout_address(address: &SproutPaymentAddress, network: ZeckNetwork) -> String {
    base58check_encode(payment_address_prefix(network), &address.to_bytes())
}

/// Decode a `zc…`/`zt…` Sprout payment address.
pub fn decode_sprout_address(
    encoded: &str,
    network: ZeckNetwork,
) -> ZeckResult<SproutPaymentAddress> {
    let want = payment_address_prefix(network);
    let body = base58check_decode(encoded).ok_or_else(|| {
        ZeckError::InvalidAddress("this is not a valid Sprout address".to_owned())
    })?;

    let (prefix, payload) = body.split_at(body.len().min(2));
    if prefix != want {
        return Err(ZeckError::InvalidAddress(format!(
            "this is not a Sprout address for this network (expected prefix {want:02x?}, \
             found {prefix:02x?})"
        )));
    }
    let bytes: [u8; 64] = payload.try_into().map_err(|_| {
        ZeckError::InvalidAddress(format!(
            "a Sprout address carries 64 bytes; this one has {}",
            payload.len()
        ))
    })?;
    Ok(SproutPaymentAddress::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produced by a running `zcashd` v6.20.0 on the `sprout` regtest chain,
    /// which is the only place a Sprout address can still be generated
    /// (zcashd refuses once Canopy activates, and that chain holds it out of
    /// reach). Preserved verbatim: this is our only sample of zcashd's
    /// encoder output, and it cannot be regenerated without that chain.
    const ZCASHD_KEY: &str = "ST129rwUWwN4XHUTZ2SQc3CvX5UzMSEFfgbdF8qRotfps5C48tzF";
    const ZCASHD_ADDR: &str = "ztRrojTh1CpSSLikYq8bFoAJbeLfaHCHafhRbmvQVrp8emRoyUHrF6D4rE5ELeeckoUvNUF1psGSVaMZUEPgFwK9aJiq1sx";

    /// The test that matters. Decoding zcashd's key must derive exactly the
    /// address zcashd filed it under — checking the decoder against a real
    /// encoder *and* against the key derivation at once. A decoder verified
    /// only against our own encoder would pass with both sides wrong.
    #[test]
    fn zcashds_key_derives_zcashds_address() {
        let a_sk = decode_sprout_spending_key(ZCASHD_KEY, ZeckNetwork::Testnet)
            .expect("zcashd's own key must decode");

        let derived = SproutPaymentAddress::from_spending_key(&a_sk);
        let encoded = encode_sprout_address(&derived, ZeckNetwork::Testnet);

        assert_eq!(
            encoded, ZCASHD_ADDR,
            "the key zcashd exported must derive the address zcashd reported for it"
        );
    }

    #[test]
    fn zcashds_address_round_trips() {
        let addr = decode_sprout_address(ZCASHD_ADDR, ZeckNetwork::Testnet).expect("decode");
        assert_eq!(
            encode_sprout_address(&addr, ZeckNetwork::Testnet),
            ZCASHD_ADDR
        );
    }

    #[test]
    fn a_spending_key_round_trips_through_our_own_encoder() {
        let a_sk = decode_sprout_spending_key(ZCASHD_KEY, ZeckNetwork::Testnet).unwrap();
        assert_eq!(
            encode_sprout_spending_key(&a_sk, ZeckNetwork::Testnet),
            ZCASHD_KEY
        );
    }

    /// Mainnet cannot be measured — generating a Sprout address needs a
    /// Canopy-inactive chain and mainnet passed Canopy in 2020 — so the
    /// constants are pinned by the rendering they must produce. Both fail if
    /// either version byte is wrong.
    #[test]
    fn mainnet_prefixes_render_as_sk_and_zc() {
        let key = encode_sprout_spending_key(&[0x01; 32], ZeckNetwork::Mainnet);
        assert!(
            key.starts_with("SK"),
            "a mainnet Sprout spending key renders as SK…, got {key}"
        );

        let addr = encode_sprout_address(
            &SproutPaymentAddress::from_bytes([0x01; 64]),
            ZeckNetwork::Mainnet,
        );
        assert!(
            addr.starts_with("zc"),
            "a mainnet Sprout address renders as zc…, got {addr}"
        );
    }

    #[test]
    fn testnet_prefixes_render_as_st_and_zt() {
        assert!(encode_sprout_spending_key(&[0x01; 32], ZeckNetwork::Testnet).starts_with("ST"));
        assert!(encode_sprout_address(
            &SproutPaymentAddress::from_bytes([0x01; 64]),
            ZeckNetwork::Testnet
        )
        .starts_with("zt"));
    }

    /// A mistyped key must fail, not decode to a different key. Silently
    /// accepting one would derive a wrong address, find no notes, and give
    /// no indication why.
    #[test]
    fn a_single_character_typo_is_rejected() {
        let mut chars: Vec<char> = ZCASHD_KEY.chars().collect();
        // Swap two adjacent characters — a checksum-detectable edit that
        // keeps the length and alphabet valid.
        chars.swap(10, 11);
        let typo: String = chars.into_iter().collect();
        assert_ne!(typo, ZCASHD_KEY);

        assert!(
            decode_sprout_spending_key(&typo, ZeckNetwork::Testnet).is_err(),
            "a transposition must fail the checksum rather than decode"
        );
    }

    /// The most likely real mistake, and it deserves its own message rather
    /// than "invalid key".
    #[test]
    fn a_key_for_the_other_network_says_so() {
        let err = match decode_sprout_spending_key(ZCASHD_KEY, ZeckNetwork::Mainnet) {
            Ok(_) => panic!("a testnet key must not decode as mainnet"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("other network"),
            "the message should name the real problem, got: {err}"
        );
    }

    #[test]
    fn junk_and_empty_input_are_rejected() {
        for bad in ["", "   ", "not a key", "0OIl", "SK"] {
            assert!(
                decode_sprout_spending_key(bad, ZeckNetwork::Mainnet).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// A Sapling key is the thing a confused user is most likely to paste.
    #[test]
    fn a_sapling_key_is_not_accepted_as_sprout() {
        let sapling = "secret-extended-key-main1qw508d6qejxtdg4y5r3zarvary0c5xw7k";
        assert!(decode_sprout_spending_key(sapling, ZeckNetwork::Mainnet).is_err());
    }

    #[test]
    fn base58_round_trips_including_leading_zeros() {
        for case in [
            vec![0u8],
            vec![0, 0, 1, 2, 3],
            vec![0xFF; 32],
            (0u8..=255).collect::<Vec<u8>>(),
        ] {
            let encoded = base58_encode(&case);
            assert_eq!(
                base58_decode(&encoded).expect("must decode"),
                case,
                "round trip failed for {case:02x?}"
            );
        }
    }
}
