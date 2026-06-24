use bip0039::{English, Error as Bip39Error, Language, Mnemonic};
use secrecy::{ExposeSecret, Secret, SecretString};
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
use zcash_keys::{encoding::AddressCodec, keys::sapling};
use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};
use zcash_transparent::keys::{
    AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope,
};
use zip32::AccountId;

use crate::{
    error::{ZeckError, ZeckResult},
    models::{AddressScope, DerivedAccount, ZeckNetwork},
};

pub fn validate_mnemonic_words(words: &[String]) -> ZeckResult<()> {
    let phrase = normalize_words(words)?;
    let _ = Mnemonic::<English>::from_phrase(&phrase)
        .map_err(|err| redact_mnemonic_error(&err, &phrase))?;
    Ok(())
}

pub fn derive_accounts(
    seed_phrase: &SecretString,
    network: ZeckNetwork,
    account_count: u32,
) -> ZeckResult<Vec<DerivedAccount>> {
    let seed = mnemonic_seed(seed_phrase)?;
    let transparent_account =
        legacy_transparent_account_key_from_seed(network, seed.expose_secret())?;

    let external_ivk = transparent_account
        .to_account_pubkey()
        .derive_external_ivk()
        .map_err(|err| ZeckError::Internal(err.to_string()))?;
    let internal_ivk = transparent_account
        .to_account_pubkey()
        .derive_internal_ivk()
        .map_err(|err| ZeckError::Internal(err.to_string()))?;

    (0..account_count)
        .map(|index| {
            derive_account(
                index,
                network,
                seed.expose_secret(),
                &external_ivk,
                &internal_ivk,
            )
        })
        .collect()
}

pub(crate) fn mnemonic_seed(seed_phrase: &SecretString) -> ZeckResult<Secret<[u8; 64]>> {
    let mnemonic = Mnemonic::<English>::from_phrase(seed_phrase.expose_secret())
        .map_err(|err| redact_mnemonic_error(&err, seed_phrase.expose_secret()))?;
    Ok(Secret::new(mnemonic.to_seed("")))
}

pub(crate) fn legacy_transparent_account_key(
    seed_phrase: &SecretString,
    network: ZeckNetwork,
) -> ZeckResult<AccountPrivKey> {
    let seed = mnemonic_seed(seed_phrase)?;
    legacy_transparent_account_key_from_seed(network, seed.expose_secret())
}

pub(crate) fn legacy_transparent_pubkey(
    transparent_account: &AccountPrivKey,
    scope: AddressScope,
    index: u32,
) -> ZeckResult<secp256k1::PublicKey> {
    let child_index = transparent_child_index(index)?;
    transparent_account
        .to_account_pubkey()
        .derive_address_pubkey(scope.into(), child_index)
        .map_err(|err| ZeckError::Internal(err.to_string()))
}

pub(crate) fn legacy_transparent_secret_key(
    transparent_account: &AccountPrivKey,
    scope: AddressScope,
    index: u32,
) -> ZeckResult<secp256k1::SecretKey> {
    let child_index = transparent_child_index(index)?;
    transparent_account
        .derive_secret_key(scope.into(), child_index)
        .map_err(|err| ZeckError::Internal(err.to_string()))
}

fn derive_account(
    index: u32,
    network: ZeckNetwork,
    seed: &[u8; 64],
    external_ivk: &zcash_transparent::keys::ExternalIvk,
    internal_ivk: &zcash_transparent::keys::InternalIvk,
) -> ZeckResult<DerivedAccount> {
    let zip32_index = AccountId::try_from(index)
        .map_err(|_| ZeckError::InvalidConfig(format!("account index {index} is out of range")))?;

    let sapling_extsk = sapling::spending_key(seed, network.coin_type(), zip32_index);
    let sapling_address = sapling_extsk
        .to_diversifiable_full_viewing_key()
        .default_address()
        .1;

    let orchard_sk =
        orchard::keys::SpendingKey::from_zip32_seed(seed, network.coin_type(), zip32_index)
            .map_err(|err| ZeckError::Internal(err.to_string()))?;
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_address = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    let unified = UnifiedAddress::try_from_items(vec![
        Receiver::Orchard(orchard_address.to_raw_address_bytes()),
        Receiver::Sapling(sapling_address.to_bytes()),
    ])
    .map_err(|err| ZeckError::Internal(err.to_string()))?;

    let child_index = NonHardenedChildIndex::from_index(index).ok_or_else(|| {
        ZeckError::InvalidConfig(format!("transparent index {index} is out of range"))
    })?;

    let transparent_receive = external_ivk
        .derive_address(child_index)
        .map_err(|err| ZeckError::Internal(err.to_string()))?;
    let transparent_change = internal_ivk
        .derive_address(child_index)
        .map_err(|err| ZeckError::Internal(err.to_string()))?;

    let sapling_encoded = match network {
        ZeckNetwork::Mainnet => sapling_address.encode(&MAIN_NETWORK),
        ZeckNetwork::Testnet => sapling_address.encode(&TEST_NETWORK),
    };
    let unified_encoded = unified.encode(&match network {
        ZeckNetwork::Mainnet => zcash_protocol::consensus::NetworkType::Main,
        ZeckNetwork::Testnet => zcash_protocol::consensus::NetworkType::Test,
    });
    let transparent_receive_encoded = match network {
        ZeckNetwork::Mainnet => transparent_receive.encode(&MAIN_NETWORK),
        ZeckNetwork::Testnet => transparent_receive.encode(&TEST_NETWORK),
    };
    let transparent_change_encoded = match network {
        ZeckNetwork::Mainnet => transparent_change.encode(&MAIN_NETWORK),
        ZeckNetwork::Testnet => transparent_change.encode(&TEST_NETWORK),
    };

    Ok(DerivedAccount {
        index,
        sapling_path: format!("m_Sapling / 32' / {}' / {}'", network.coin_type(), index),
        orchard_path: format!("m_Orchard / 32' / {}' / {}'", network.coin_type(), index),
        transparent_receive_path: transparent_path(
            AddressScope::External,
            index,
            network.coin_type(),
        ),
        transparent_change_path: transparent_path(
            AddressScope::Internal,
            index,
            network.coin_type(),
        ),
        sapling_address: sapling_encoded,
        unified_address: unified_encoded,
        transparent_receive_address: transparent_receive_encoded,
        transparent_change_address: transparent_change_encoded,
    })
}

fn transparent_path(scope: AddressScope, index: u32, coin_type: u32) -> String {
    let scope_number = match scope {
        AddressScope::External => 0,
        AddressScope::Internal => 1,
    };

    format!("m / 44' / {coin_type}' / 0' / {scope_number} / {index}")
}

fn legacy_transparent_account_key_from_seed(
    network: ZeckNetwork,
    seed: &[u8; 64],
) -> ZeckResult<AccountPrivKey> {
    match network {
        ZeckNetwork::Mainnet => AccountPrivKey::from_seed(&MAIN_NETWORK, seed, AccountId::ZERO),
        ZeckNetwork::Testnet => AccountPrivKey::from_seed(&TEST_NETWORK, seed, AccountId::ZERO),
    }
    .map_err(|err| ZeckError::Internal(err.to_string()))
}

fn transparent_child_index(index: u32) -> ZeckResult<NonHardenedChildIndex> {
    NonHardenedChildIndex::from_index(index).ok_or_else(|| {
        ZeckError::InvalidConfig(format!("transparent index {index} is out of range"))
    })
}

/// Convert a `bip0039` validation error into a `ZeckError::InvalidMnemonic`
/// without ever leaking the literal seed word.
///
/// Audit Suggestion 6 (Least Authority): the `bip0039` `UnknownWord` Display
/// embeds the offending word verbatim. Because a typo is often only a single
/// edit away from the intended BIP-39 word, that string can leak partial seed
/// material through screenshots or pasted logs. For `UnknownWord` we therefore
/// report only the 1-based position of the first offending word, derived by
/// locating it in the caller's phrase, and never the word itself. All other
/// `bip0039` variants carry no secret material and are forwarded as-is.
fn redact_mnemonic_error(err: &Bip39Error, phrase: &str) -> ZeckError {
    match err {
        Bip39Error::UnknownWord(_) => {
            let position = phrase
                .split_whitespace()
                .position(|word| English::index_of(word).is_none())
                .map(|index| index + 1);
            let message = match position {
                Some(position) => {
                    format!("word {position} is not in the BIP-39 wordlist")
                }
                None => "mnemonic contains a word that is not in the BIP-39 wordlist".to_owned(),
            };
            ZeckError::InvalidMnemonic(message)
        }
        other => ZeckError::InvalidMnemonic(other.to_string()),
    }
}

fn normalize_words(words: &[String]) -> ZeckResult<String> {
    if words.len() != 24 {
        return Err(ZeckError::InvalidMnemonic(format!(
            "expected 24 words, got {}",
            words.len()
        )));
    }

    Ok(words
        .iter()
        .map(|word| word.trim())
        .collect::<Vec<_>>()
        .join(" "))
}

impl From<AddressScope> for TransparentKeyScope {
    fn from(value: AddressScope) -> Self {
        match value {
            AddressScope::External => TransparentKeyScope::EXTERNAL,
            AddressScope::Internal => TransparentKeyScope::INTERNAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    // Standard BIP-39 test vector: 24× "abandon" + "art"
    const TEST_SEED: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    fn test_seed() -> SecretString {
        SecretString::new(TEST_SEED.to_owned())
    }

    #[test]
    fn valid_24_word_seed_validates() {
        let words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        assert!(validate_mnemonic_words(&words).is_ok());
    }

    #[test]
    fn wrong_word_count_rejected() {
        let words: Vec<String> = TEST_SEED
            .split_whitespace()
            .take(23)
            .map(str::to_owned)
            .collect();
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn non_bip39_word_rejected() {
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        words[0] = "zzzznotaword".to_owned();
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    // Audit Suggestion 6 (Least Authority): an unknown seed word must never be
    // echoed back in the error message, because a typo is usually a single edit
    // away from the real BIP-39 word and leaks partial seed material. Only the
    // 1-based position of the offending word may appear.
    #[test]
    fn unknown_word_error_reports_index_not_word() {
        // A near-miss typo: "abandom" is one edit from the valid word "abandon".
        let offending_word = "abandom";
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        words[6] = offending_word.to_owned(); // 7th word (1-based position 7)

        let err = validate_mnemonic_words(&words).unwrap_err();
        let ZeckError::InvalidMnemonic(message) = &err else {
            panic!("expected InvalidMnemonic, got {err:?}");
        };

        assert!(
            !message.contains(offending_word),
            "error message leaked the literal seed word: {message:?}"
        );
        assert!(
            message.contains("word 7"),
            "error message should report the 1-based position: {message:?}"
        );
    }

    // The same redaction must hold on the seed-derivation path, not just the
    // standalone validator, so no entry point leaks the literal word.
    #[test]
    fn mnemonic_seed_unknown_word_error_redacted() {
        let offending_word = "abandom";
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        words[0] = offending_word.to_owned();
        let phrase = SecretString::new(words.join(" "));

        let err = mnemonic_seed(&phrase).unwrap_err();
        let ZeckError::InvalidMnemonic(message) = &err else {
            panic!("expected InvalidMnemonic, got {err:?}");
        };

        assert!(
            !message.contains(offending_word),
            "error message leaked the literal seed word: {message:?}"
        );
        assert!(
            message.contains("word 1"),
            "error message should report the 1-based position: {message:?}"
        );
    }

    #[test]
    fn words_with_whitespace_padding_validated() {
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        words[0] = "  abandon  ".to_owned(); // leading/trailing spaces
        assert!(validate_mnemonic_words(&words).is_ok());
    }

    // ─── Seed resilience (R-D5..R-D10) ────────────────────────────────────────
    //
    // Coverage gaps named in docs/superpowers/test-plans/recovery-resilience.md.
    // These exercise inputs a careless or hostile UI / CLI invocation might
    // hand to `validate_mnemonic_words`. None of them should panic; all must
    // produce a clean `ZeckError::InvalidMnemonic`.

    #[test]
    fn empty_seed_rejected() {
        // R-D5: an empty Vec is "zero words", far from the required 24.
        let err = validate_mnemonic_words(&[]).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn whitespace_only_words_rejected() {
        // R-D6: "  " entries normalise to empty strings, which are not BIP-39
        // words. Counts as a non-BIP-39 input, not as "0 words" — the
        // validator's downstream check should still reject it cleanly.
        let words: Vec<String> = vec!["   ".to_owned(); 24];
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn embedded_control_characters_rejected() {
        // R-D7: control characters inside a word are not BIP-39 wordlist
        // members. Should reject cleanly (no panic from utf-8 boundary
        // issues or from the bip0039 crate).
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        words[0] = "aband\x00on".to_owned(); // NUL inside the word
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");

        words[0] = "aband\non".to_owned(); // LF inside the word
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn very_long_single_word_rejected_without_panic() {
        // R-D8: defends the validator against absurd inputs from a faulty
        // form / CLI argument. 1 MB of letters in one slot must not crash
        // or hang.
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        words[0] = "a".repeat(1_000_000);
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn valid_words_but_broken_checksum_rejected() {
        // R-D9: 24 BIP-39 wordlist members are a syntactically valid set,
        // but the BIP-39 entropy+checksum constraint isn't met for an
        // arbitrary sequence. The validator must rely on the bip0039 crate's
        // full validation, not just the wordlist membership check.
        //
        // Constructed by replacing the LAST word (which carries the checksum
        // bits) with a different valid wordlist member, breaking the
        // checksum but keeping all entries in the wordlist.
        let mut words: Vec<String> = TEST_SEED.split_whitespace().map(str::to_owned).collect();
        assert_eq!(words.last().map(String::as_str), Some("art"));
        words[23] = "ability".to_owned(); // also in the wordlist; different bits
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn unicode_garbage_rejected_without_panic() {
        // R-D10: emoji and other multi-byte unicode aren't BIP-39 wordlist
        // members. Cleanly rejected, no utf-8 indexing bugs.
        let words: Vec<String> = (0..24).map(|i| format!("🎉{i}")).collect();
        let err = validate_mnemonic_words(&words).unwrap_err();
        assert!(matches!(err, ZeckError::InvalidMnemonic(_)), "got {err:?}");
    }

    #[test]
    fn derive_accounts_mainnet_produces_expected_account_0_addresses() {
        let accounts = derive_accounts(&test_seed(), ZeckNetwork::Mainnet, 1).unwrap();
        assert_eq!(accounts.len(), 1);
        let acc = &accounts[0];

        // Verify the known values produced by `argos show-keys` with this seed
        assert_eq!(
            acc.unified_address,
            "u1nvgt6yr35mhc9wdf4wckvl38476vqy96dx3cwkfdwy4jet9300l5v8l2yg27ql7w9qwm0lf8kncnj9nus4mgete06j3cu3mhrqvstg6swvdya6xgzwhh6a9xxdhxkavvvmztqeuaurjtqfk3dzetuzgnu0zjvmdpe8ehvj53sy6yhzxj"
        );
        assert_eq!(
            acc.sapling_address,
            "zs16uhd4mux24se6wkm74vld0ec63d4dxt3d7m80l5xytreplkkllrrf9c7fj859mhp8tkcq9hxfvj"
        );
        assert_eq!(acc.transparent_receive_address, "t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F");
        assert_eq!(acc.transparent_change_address, "t1eFjJFc6eRbhVLeDwsAkjTQoUid6LHi631");
        assert_eq!(acc.index, 0);
    }

    #[test]
    fn derive_accounts_produces_distinct_addresses_per_account() {
        let accounts = derive_accounts(&test_seed(), ZeckNetwork::Mainnet, 3).unwrap();
        assert_eq!(accounts.len(), 3);

        // All unified addresses must be different
        let uas: Vec<_> = accounts.iter().map(|a| &a.unified_address).collect();
        assert_ne!(uas[0], uas[1]);
        assert_ne!(uas[1], uas[2]);

        // All transparent receive addresses must be different
        let tras: Vec<_> = accounts.iter().map(|a| &a.transparent_receive_address).collect();
        assert_ne!(tras[0], tras[1]);
        assert_ne!(tras[1], tras[2]);
    }

    #[test]
    fn derive_accounts_mainnet_and_testnet_addresses_differ() {
        let mainnet = derive_accounts(&test_seed(), ZeckNetwork::Mainnet, 1).unwrap();
        let testnet = derive_accounts(&test_seed(), ZeckNetwork::Testnet, 1).unwrap();

        assert_ne!(mainnet[0].unified_address, testnet[0].unified_address);
        assert_ne!(mainnet[0].sapling_address, testnet[0].sapling_address);
        assert_ne!(
            mainnet[0].transparent_receive_address,
            testnet[0].transparent_receive_address
        );
    }

    #[test]
    fn derive_zero_accounts_returns_empty_vec() {
        let accounts = derive_accounts(&test_seed(), ZeckNetwork::Mainnet, 0).unwrap();
        assert!(accounts.is_empty());
    }

    #[test]
    fn derive_accounts_path_strings_are_correct() {
        let accounts = derive_accounts(&test_seed(), ZeckNetwork::Mainnet, 1).unwrap();
        let acc = &accounts[0];
        assert_eq!(acc.sapling_path, "m_Sapling / 32' / 133' / 0'");
        assert_eq!(acc.transparent_receive_path, "m / 44' / 133' / 0' / 0 / 0");
        assert_eq!(acc.transparent_change_path, "m / 44' / 133' / 0' / 1 / 0");
    }
}
