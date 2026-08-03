//! Registering keys from a legacy wallet file as spendable wallet accounts.
//!
//! A zcashd wallet holds keys individually rather than deriving them from a
//! seed, so none of them fit the HD account model the seed path uses. They
//! are instead registered with [`WalletWrite::import_account_ufvk`] under
//! [`AccountPurpose::Spending`] with **no ZIP-32 derivation** — an account
//! the wallet knows is spendable but cannot re-derive.
//!
//! Such an account cannot be spent through `create_proposed_transactions`,
//! which resolves its account by looking up a `UnifiedSpendingKey`'s UFVK
//! and takes Sapling spend authority solely from that key. The PCZT path
//! is account-id driven and accepts raw per-pool keys, which is what makes
//! this work at all; see `docs/` for the full argument.

use argos_wallet_import::ImportedKeys;
use rand_core::OsRng;
use secrecy::ExposeSecret;
use zcash_address::unified::{Encoding, Fvk, Ufvk};
use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, AccountPurpose, WalletRead, WalletWrite,
};
use zcash_client_sqlite::{util::SystemClock, AccountUuid, WalletDb};
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{sapling::ExtendedSpendingKey, UnifiedAddressRequest, UnifiedFullViewingKey};
use zcash_transparent::address::TransparentAddress;

use crate::{
    error::{ZeckError, ZeckResult},
    models::{DerivedAccount, ZeckNetwork},
    workspace::ArgosParams,
};

/// The concrete wallet database Argos opens everywhere.
pub type ArgosWalletDb = WalletDb<rusqlite::Connection, ArgosParams, SystemClock, OsRng>;

/// Serialized length of a Sapling extended spending key.
const EXTSK_LEN: usize = 169;

/// Parse a serialized Sapling extended spending key as recovered from a
/// wallet file.
pub fn parse_sapling_extsk(bytes: &[u8]) -> ZeckResult<ExtendedSpendingKey> {
    if bytes.len() != EXTSK_LEN {
        return Err(ZeckError::Import(format!(
            "Sapling extended spending key is {} bytes, expected {EXTSK_LEN}",
            bytes.len()
        )));
    }
    ExtendedSpendingKey::from_bytes(bytes)
        .map_err(|err| ZeckError::Import(format!("malformed Sapling spending key: {err:?}")))
}

/// Build a Sapling-only unified full viewing key for an imported key.
///
/// `UnifiedFullViewingKey::new` is gated behind `test-dependencies`
/// upstream, so this goes through the supported route: assemble a ZIP-316
/// container with `zcash_address::unified` and parse it. That is also the
/// only route that keeps this working in a release build.
pub fn sapling_ufvk(extsk: &ExtendedSpendingKey) -> ZeckResult<UnifiedFullViewingKey> {
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let ufvk = Ufvk::try_from_items(vec![Fvk::Sapling(dfvk.to_bytes())]).map_err(|err| {
        ZeckError::Import(format!("assembling a Sapling-only UFVK failed: {err}"))
    })?;
    UnifiedFullViewingKey::parse(&ufvk)
        .map_err(|err| ZeckError::Import(format!("parsing the assembled UFVK failed: {err}")))
}

/// Display metadata for an imported account, shaped like the HD scanner's
/// `DerivedAccount` so the whole progress and reporting pipeline works on
/// imported wallets without change.
///
/// The path fields say "imported" rather than carrying a ZIP-32 path,
/// because there is none: these keys were stored individually. Showing a
/// plausible-looking path would invite someone to re-derive the key from a
/// seed that does not exist.
pub fn imported_account_display(
    index: u32,
    extsk: &ExtendedSpendingKey,
    transparent: Option<&TransparentAddress>,
    network: ZeckNetwork,
) -> ZeckResult<DerivedAccount> {
    let params = crate::workspace::consensus_network(network);
    let (_, sapling_address) = extsk
        .to_diversifiable_full_viewing_key()
        .default_address();

    let ufvk = sapling_ufvk(extsk)?;
    let unified_address = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|err| ZeckError::Import(format!("deriving a unified address: {err}")))?
        .0
        .encode(&params);

    let transparent_encoded = transparent
        .map(|addr| encode_transparent_address(addr, network))
        .unwrap_or_default();

    Ok(DerivedAccount {
        index,
        sapling_path: IMPORTED_PATH.to_owned(),
        orchard_path: NO_ORCHARD.to_owned(),
        transparent_receive_path: IMPORTED_PATH.to_owned(),
        transparent_change_path: IMPORTED_PATH.to_owned(),
        sapling_address: sapling_address.encode(&params),
        unified_address,
        // The same address in both slots: an imported wallet has no
        // external/internal scope distinction, and leaving one blank would
        // read as "we did not look there".
        transparent_receive_address: transparent_encoded.clone(),
        transparent_change_address: transparent_encoded,
    })
}

/// Shown where an HD account would show a derivation path.
const IMPORTED_PATH: &str = "imported (no derivation path)";
/// A zcashd wallet predates Orchard, so an imported account never has one.
const NO_ORCHARD: &str = "n/a (imported wallet has no Orchard key)";

/// A transparent key recovered from a wallet file, resolved to the address
/// it controls.
///
/// Pairing them is what makes the rest of the transparent path possible:
/// lightwalletd is queried by address, and the builder signs by key, so
/// every step needs both halves together.
pub struct ImportedTransparentKey {
    pub secret: secp256k1::SecretKey,
    pub address: TransparentAddress,
}

impl std::fmt::Debug for ImportedTransparentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The address is public; the secret is not, and this type exists
        // precisely to carry one next to the other.
        f.debug_struct("ImportedTransparentKey")
            .field("secret", &"<redacted>")
            .field("address", &self.address)
            .finish()
    }
}

/// Resolve every transparent key in a wallet file to its address.
///
/// Order follows the file, and duplicates are preserved: two records
/// yielding the same address is a fact about the wallet worth surfacing
/// rather than silently collapsing.
pub fn imported_transparent_keys(keys: &ImportedKeys) -> ZeckResult<Vec<ImportedTransparentKey>> {
    let secp = secp256k1::Secp256k1::signing_only();
    keys.transparent
        .iter()
        .map(|key| {
            let secret = secp256k1::SecretKey::from_slice(key.secret.expose_secret())
                .map_err(|err| ZeckError::Import(format!("malformed transparent key: {err}")))?;
            let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
            Ok(ImportedTransparentKey {
                secret,
                address: TransparentAddress::from_pubkey(&pubkey),
            })
        })
        .collect()
}

/// Encode a transparent address for display on `network`.
///
/// Goes through `consensus_network` rather than matching on `ZeckNetwork`
/// directly so that a regtest harness — which installs its own parameters
/// process-wide — gets regtest's Base58 prefix. Matching here would emit a
/// testnet-prefixed address that the regtest node rejects and that
/// lightwalletd would never match a UTXO against. Identical to the direct
/// match for mainnet and testnet.
pub fn encode_transparent_address(address: &TransparentAddress, network: ZeckNetwork) -> String {
    address.encode(&crate::workspace::consensus_network(network))
}

/// An imported wallet account, as registered in the wallet database.
///
/// Holds the Sapling spending key alongside the account id because the
/// PCZT signing path needs the raw key later; the wallet database stores
/// only the viewing key.
pub struct ImportedWalletAccount {
    pub wallet_account_id: AccountUuid,
    /// `None` for the account that exists solely to anchor transparent
    /// keys (see `register_imported_accounts`).
    pub sapling_extsk: Option<ExtendedSpendingKey>,
    pub transparent_addresses: Vec<TransparentAddress>,
}

impl std::fmt::Debug for ImportedWalletAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedWalletAccount")
            .field("wallet_account_id", &self.wallet_account_id)
            .field("has_sapling_extsk", &self.sapling_extsk.is_some())
            .field("transparent_addresses", &self.transparent_addresses.len())
            .finish()
    }
}

/// Register every importable key from a wallet file as a wallet account.
///
/// One account per Sapling key, because a UFVK carries exactly one Sapling
/// component. Transparent keys are standalone pubkeys rather than an
/// account-level extended key, so they cannot form a UFVK component of
/// their own; they are attached as standalone receivers to the first
/// account instead. Which account they hang from does not affect
/// spendability — the signing key is supplied per-input — but it does
/// determine which account reports their balance.
///
/// Returns an error when the wallet has transparent keys but no shielded
/// keys: ZIP-316 forbids a transparent-only unified container, so there is
/// no UFVK to anchor an account to. That is an upstream limitation
/// (zcash/librustzcash#2582), not something Argos can work around here.
///
/// Idempotent: re-registering an already-imported key reuses its account,
/// so a resumed scan does not duplicate accounts.
pub fn register_imported_accounts(
    wallet_db: &mut ArgosWalletDb,
    keys: &ImportedKeys,
    birthday: &AccountBirthday,
) -> ZeckResult<Vec<ImportedWalletAccount>> {
    if keys.sapling.is_empty() {
        if keys.transparent.is_empty() {
            return Err(ZeckError::Import(
                "this wallet file contains no transparent or Sapling keys to scan".to_owned(),
            ));
        }
        return Err(ZeckError::Import(
            "this wallet file has only transparent keys. A unified viewing key must \
             contain at least one shielded component (ZIP-316), so there is no account \
             to attach them to. Transparent-only wallet import is not yet supported."
                .to_owned(),
        ));
    }

    let mut accounts = Vec::with_capacity(keys.sapling.len());
    for (index, key) in keys.sapling.iter().enumerate() {
        let extsk = parse_sapling_extsk(key.extsk.expose_secret())?;
        let ufvk = sapling_ufvk(&extsk)?;

        let wallet_account_id = match wallet_db
            .get_account_for_ufvk(&ufvk)
            .map_err(|err| ZeckError::Wallet(format!("looking up imported account: {err}")))?
        {
            Some(existing) => existing.id(),
            None => wallet_db
                .import_account_ufvk(
                    &format!("imported_sapling_{index}"),
                    &ufvk,
                    birthday,
                    // The wallet has the spending key; it simply cannot be
                    // re-derived from a seed, which is what `None` says.
                    AccountPurpose::Spending { derivation: None },
                    Some("Argos wallet file import"),
                )
                .map_err(|err| {
                    ZeckError::Wallet(format!("importing Sapling account {index}: {err}"))
                })?
                .id(),
        };

        accounts.push(ImportedWalletAccount {
            wallet_account_id,
            sapling_extsk: Some(extsk),
            transparent_addresses: Vec::new(),
        });
    }

    // Attach every transparent key to the first account.
    let Some(anchor) = accounts.first_mut() else {
        return Err(ZeckError::Internal(
            "no imported account was created despite a non-empty Sapling key set".to_owned(),
        ));
    };

    let secp = secp256k1::Secp256k1::signing_only();
    let existing = wallet_db
        .get_transparent_receivers(anchor.wallet_account_id, true, true)
        .map_err(|err| ZeckError::Wallet(format!("loading transparent receivers: {err}")))?;

    for imported in imported_transparent_keys(keys)? {
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &imported.secret);
        let address = imported.address;

        if !existing.contains_key(&address) {
            wallet_db
                .import_standalone_transparent_pubkey(anchor.wallet_account_id, pubkey)
                .map_err(|err| {
                    ZeckError::Wallet(format!("importing transparent receiver: {err}"))
                })?;
        }
        anchor.transparent_addresses.push(address);
    }

    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real Sapling key, recovered by our own parser from a wallet file a
    /// real zcashd wrote.
    ///
    /// Using the golden fixture rather than a synthetic key is the point:
    /// a hand-built extsk would prove only that this module is
    /// self-consistent, whereas the failure that actually matters is
    /// "the bytes our BDB parser hands us are not what `sapling-crypto`
    /// expects". Only a real recovered key can catch that.
    fn fixture_sapling_extsk() -> ExtendedSpendingKey {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
        ))
        .expect("golden fixture must exist");
        let keys = argos_wallet_import::import_wallet_file(&bytes, None)
            .expect("the plaintext fixture must import");
        let key = keys
            .sapling
            .first()
            .expect("the fixture must contain a Sapling key");
        parse_sapling_extsk(key.extsk.expose_secret())
            .expect("a recovered Sapling key must parse as an extended spending key")
    }

    #[test]
    fn a_recovered_sapling_key_parses_as_an_extended_spending_key() {
        // Non-vacuous on its own: `fixture_sapling_extsk` panics with a
        // specific message at whichever step fails, so this test names the
        // parser/consumer boundary rather than folding it into the UFVK
        // test below.
        let extsk = fixture_sapling_extsk();
        assert_eq!(
            extsk.to_bytes().len(),
            EXTSK_LEN,
            "round-tripping must preserve the serialized length"
        );
    }

    #[test]
    fn a_recovered_sapling_key_becomes_a_unified_full_viewing_key() {
        let extsk = fixture_sapling_extsk();
        let ufvk = sapling_ufvk(&extsk).expect("a Sapling-only UFVK must be constructible");

        // The UFVK must carry the *same* Sapling key we put in. If it
        // carried a different one the wallet would scan for notes
        // belonging to a key nobody holds and report an empty account —
        // the silent false negative this whole feature exists to avoid.
        let recovered = ufvk
            .sapling()
            .expect("the UFVK must have a Sapling component");
        assert_eq!(
            recovered.to_bytes(),
            extsk.to_diversifiable_full_viewing_key().to_bytes(),
            "the UFVK's Sapling key must match the imported spending key"
        );

        // And no other pool is claimed: asserting absence stops a future
        // change from quietly attaching an unrelated transparent or
        // Orchard component that the imported wallet never had.
        assert!(
            ufvk.orchard().is_none(),
            "an imported Sapling key must not claim an Orchard component"
        );
        assert!(
            ufvk.transparent().is_none(),
            "an imported Sapling key must not claim a transparent component"
        );
    }

    /// The addresses printed by `inspect-wallet` are the only thing a
    /// user with a transparent-only wallet can act on unaided — they take
    /// them to a block explorer. A wrong address sends them looking at
    /// somebody else's funds, so the derivation is pinned against the
    /// same ground truth the parser tests use: the address zcashd itself
    /// stored the key under.
    #[test]
    fn a_recovered_transparent_key_resolves_to_the_address_zcashd_stored_it_under() {
        use argos_wallet_import::bdb;
        use argos_wallet_import::zcashd::records::parse_record_key;

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
        );
        let bytes = std::fs::read(path).expect("golden fixture must exist");
        let keys =
            argos_wallet_import::import_wallet_file(&bytes, None).expect("fixture must import");
        let resolved = imported_transparent_keys(&keys).expect("keys must resolve");

        // Ground truth: every "key" record's remainder is the serialized
        // pubkey the wallet filed that secret under.
        let records = bdb::walk(&bytes).expect("fixture must walk");
        let mut stored: std::collections::HashSet<TransparentAddress> =
            std::collections::HashSet::new();
        for (raw_key, _) in &records {
            let Some(rec) = parse_record_key(raw_key) else {
                continue;
            };
            if rec.record_type != "key" {
                continue;
            }
            // CompactSize-prefixed pubkey.
            let Some((len, off)) = argos_wallet_import::zcashd::records::compact_size(&rec.rest)
            else {
                continue;
            };
            let end = off + len as usize;
            let Some(pubkey_bytes) = rec.rest.get(off..end) else {
                continue;
            };
            if let Ok(pubkey) = secp256k1::PublicKey::from_slice(pubkey_bytes) {
                stored.insert(TransparentAddress::from_pubkey(&pubkey));
            }
        }

        assert!(
            !stored.is_empty(),
            "the fixture must contain transparent key records, or this proves nothing"
        );
        for imported in &resolved {
            assert!(
                stored.contains(&imported.address),
                "derived address {:?} was not stored in the wallet",
                imported.address
            );
        }
        assert_eq!(
            resolved.len(),
            keys.transparent.len(),
            "every recovered key must resolve to an address"
        );
    }

    #[test]
    fn an_encoded_mainnet_address_looks_like_a_t_address() {
        let keys = {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
            );
            let bytes = std::fs::read(path).expect("fixture");
            argos_wallet_import::import_wallet_file(&bytes, None).expect("import")
        };
        let resolved = imported_transparent_keys(&keys).expect("resolve");
        let encoded =
            encode_transparent_address(&resolved[0].address, crate::models::ZeckNetwork::Mainnet);
        assert!(
            encoded.starts_with("t1"),
            "a mainnet P2PKH address must start with t1, got: {encoded}"
        );
        // Testnet must differ, or the network parameter is being ignored
        // and every address we print for a testnet wallet is wrong.
        let testnet =
            encode_transparent_address(&resolved[0].address, crate::models::ZeckNetwork::Testnet);
        assert_ne!(encoded, testnet, "network must affect the encoding");
    }

    #[test]
    fn a_wrong_length_key_is_rejected_rather_than_truncated() {
        // Silently accepting a short key would produce a valid-looking
        // UFVK for the wrong wallet.
        let err = parse_sapling_extsk(&[0u8; 100]).unwrap_err();
        assert!(
            err.to_string().contains("169"),
            "the error must name the expected length, got: {err}"
        );
    }

    /// The constraint that bounds what Argos can offer: ZIP-316 forbids a
    /// unified container holding only transparent items
    /// (`zcash_address/src/kind/unified.rs`, `try_from_items`). A zcashd
    /// wallet with transparent keys and no shielded keys therefore has no
    /// UFVK, so it cannot be given an account at all.
    ///
    /// Pinned as a test so that if upstream ever relaxes it, this fails and
    /// tells us the transparent-only path just became possible — rather
    /// than the limitation quietly outliving its cause.
    #[test]
    fn a_transparent_only_container_is_still_rejected_upstream() {
        let items: Vec<Fvk> = vec![Fvk::P2pkh([0u8; 65])];
        assert!(
            Ufvk::try_from_items(items).is_err(),
            "ZIP-316 must still forbid a transparent-only UFVK; if this now \
             succeeds, transparent-only wallet import is unblocked"
        );
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::{
        models::ZeckNetwork,
        workspace::{consensus_network, open_wallet_db},
    };
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_client_sqlite::wallet::init::init_wallet_db;
    use zcash_protocol::consensus::BlockHeight;

    fn fixture_keys(name: &str) -> ImportedKeys {
        let path = format!(
            "{}/../argos-wallet-import/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(path).expect("golden fixture must exist");
        argos_wallet_import::import_wallet_file(&bytes, None).expect("fixture must import")
    }

    fn birthday() -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(
                BlockHeight::from_u32(419_199),
                zcash_primitives::block::BlockHash([0u8; 32]),
            ),
            None,
        )
    }

    /// Open a wallet DB initialized with **no seed**, which is the whole
    /// point: an imported wallet has none, and `init_wallet_db` must
    /// accept that for any of this to be reachable in production.
    fn seedless_wallet_db(dir: &std::path::Path) -> ArgosWalletDb {
        let path = dir.join("wallet.sqlite");
        let mut db = open_wallet_db(&path, consensus_network(ZeckNetwork::Mainnet))
            .expect("wallet db should open");
        init_wallet_db(&mut db, None).expect("a seedless wallet db must initialize");
        db
    }

    #[test]
    fn registering_a_wallet_file_creates_a_spendable_account_with_no_derivation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = seedless_wallet_db(dir.path());
        let keys = fixture_keys("sprout-plaintext.dat");

        let accounts =
            register_imported_accounts(&mut db, &keys, &birthday()).expect("registration");

        assert_eq!(
            accounts.len(),
            keys.sapling.len(),
            "one account per imported Sapling key"
        );

        // The account must be recorded as *spending*, not view-only.
        // Getting this wrong would let a scan report a balance the user
        // could never move, which is worse than refusing outright.
        let account = db
            .get_account(accounts[0].wallet_account_id)
            .expect("account lookup")
            .expect("the account must exist");
        assert!(
            matches!(
                account.source(),
                zcash_client_backend::data_api::AccountSource::Imported {
                    purpose: AccountPurpose::Spending { derivation: None },
                    ..
                }
            ),
            "expected an imported spending account with no derivation, got {:?}",
            account.source()
        );
    }

    #[test]
    fn every_transparent_key_in_the_file_becomes_a_tracked_receiver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = seedless_wallet_db(dir.path());
        let keys = fixture_keys("sprout-plaintext.dat");
        assert!(
            keys.transparent.len() > 1,
            "fixture must have several transparent keys or this proves little"
        );

        let accounts =
            register_imported_accounts(&mut db, &keys, &birthday()).expect("registration");

        let receivers = db
            .get_transparent_receivers(accounts[0].wallet_account_id, true, true)
            .expect("receivers");

        // Every recovered key must be watched. A key that is imported but
        // not tracked is a silent partial scan: the user is told their
        // wallet is empty because we never looked at that address.
        for address in &accounts[0].transparent_addresses {
            assert!(
                receivers.contains_key(address),
                "imported transparent address {address:?} is not a tracked receiver"
            );
        }
        assert_eq!(
            accounts[0].transparent_addresses.len(),
            keys.transparent.len(),
            "every transparent key in the file must be registered"
        );
    }

    #[test]
    fn re_registering_the_same_wallet_reuses_its_accounts() {
        // The resume path re-runs registration on every scan start. If it
        // created a second account each time, a resumed scan would rescan
        // from scratch and double-count balances.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = seedless_wallet_db(dir.path());
        let keys = fixture_keys("sprout-plaintext.dat");

        let first = register_imported_accounts(&mut db, &keys, &birthday()).expect("first");
        let second = register_imported_accounts(&mut db, &keys, &birthday()).expect("second");

        assert_eq!(
            first
                .iter()
                .map(|a| a.wallet_account_id)
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|a| a.wallet_account_id)
                .collect::<Vec<_>>(),
            "re-registration must reuse the same accounts"
        );
    }

    #[test]
    fn a_transparent_only_wallet_is_refused_with_an_explanation() {
        use argos_wallet_import::keys::{Provenance, TransparentKey};
        use secrecy::Secret;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = seedless_wallet_db(dir.path());

        let keys = ImportedKeys {
            transparent: vec![TransparentKey {
                secret: Secret::new([0x42; 32]),
                provenance: Provenance::Standalone,
            }],
            ..Default::default()
        };

        let err = register_imported_accounts(&mut db, &keys, &birthday())
            .expect_err("a transparent-only wallet has no UFVK to anchor an account to");
        assert!(
            err.to_string().contains("shielded"),
            "the refusal must explain the ZIP-316 constraint, got: {err}"
        );
    }
}
