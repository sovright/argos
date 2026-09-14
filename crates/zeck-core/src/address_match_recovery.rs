//! Converts a public address-discovery match into the least-authority key
//! source needed by the existing recovery pipeline.

use std::sync::Arc;

use argos_wallet_import::keys::TransparentKey;
use argos_wallet_import::{ImportedKeys, Provenance, SaplingKey};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zcash_address::unified::Encoding;
use zip32::AccountId;

use crate::{
    derivation::{legacy_transparent_secret_key_for_account, transparent_address_from_seed},
    error::{ZeckError, ZeckResult},
    imported::encode_transparent_address,
    key_source::{ImportedKeySource, KeySource, KeySourceFingerprint},
    models::{AddressScope, DiscoveryPool, ZeckNetwork},
};

/// Public coordinates retained with a recovery session. This contains enough
/// information to re-derive and verify the same match after seed re-entry, but
/// contains no seed, passphrase, or private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchCoordinates {
    pub pool: DiscoveryPool,
    pub account: u32,
    pub scope: AddressScope,
    pub index: u32,
    pub network: ZeckNetwork,
    pub address: String,
    pub path: String,
}

/// Build a spend-capable source for exactly the matched address/account.
///
/// `seed` is already the BIP-39 PBKDF output, including any optional,
/// case-sensitive BIP-39 passphrase. Recovery must re-enter the exact seed
/// phrase and passphrase used during discovery. The passphrase is separate
/// from a wallet-file encryption password; neither secret is retained in the
/// serializable match descriptor or echoed in errors.
pub fn prepare_match_recovery(
    seed: &[u8; 64],
    network: ZeckNetwork,
    coordinates: MatchCoordinates,
) -> ZeckResult<Arc<dyn KeySource>> {
    if coordinates.network != network {
        return Err(ZeckError::InvalidConfig(format!(
            "matched address is for {}, but recovery selected {}",
            coordinates.network.label(),
            network.label()
        )));
    }

    match coordinates.pool {
        DiscoveryPool::Transparent => {
            let secret = legacy_transparent_secret_key_for_account(
                network,
                seed,
                coordinates.account,
                coordinates.scope,
                coordinates.index,
            )?;
            let derived = transparent_address_from_seed(
                network,
                seed,
                coordinates.account,
                coordinates.scope,
                coordinates.index,
            )?;
            let encoded = encode_transparent_address(&derived, network);
            verify_public_match(&coordinates, &encoded)?;
            let mut keys = ImportedKeys::default();
            keys.transparent.push(TransparentKey {
                secret: Secret::new(secret.secret_bytes()),
                provenance: Provenance::HdDerived,
            });
            Ok(Arc::new(MatchedImportedKeySource::new(keys, coordinates)))
        }
        DiscoveryPool::Sapling => {
            let account = AccountId::try_from(coordinates.account).map_err(|_| {
                ZeckError::InvalidConfig(format!(
                    "account index {} is out of range",
                    coordinates.account
                ))
            })?;
            let extsk = zcash_keys::keys::sapling::spending_key(seed, network.coin_type(), account);
            let dfvk = match coordinates.scope {
                AddressScope::External => extsk.to_diversifiable_full_viewing_key(),
                AddressScope::Internal => {
                    extsk.derive_internal().to_diversifiable_full_viewing_key()
                }
            };
            let address = dfvk.address(coordinates.index.into()).ok_or_else(|| {
                ZeckError::InvalidConfig("saved Sapling diversifier index is invalid".to_owned())
            })?;
            use zcash_keys::encoding::AddressCodec;
            let encoded = match network {
                ZeckNetwork::Mainnet => address.encode(&zcash_protocol::consensus::MAIN_NETWORK),
                ZeckNetwork::Testnet => address.encode(&zcash_protocol::consensus::TEST_NETWORK),
            };
            verify_public_match(&coordinates, &encoded)?;
            let mut keys = ImportedKeys::default();
            keys.sapling.push(SaplingKey {
                extsk: Secret::new(extsk.to_bytes().to_vec()),
                provenance: Provenance::HdDerived,
            });
            Ok(Arc::new(MatchedImportedKeySource::new(keys, coordinates)))
        }
        DiscoveryPool::Orchard => {
            let account = AccountId::try_from(coordinates.account).map_err(|_| {
                ZeckError::InvalidConfig(format!(
                    "account index {} is out of range",
                    coordinates.account
                ))
            })?;
            let sk =
                orchard::keys::SpendingKey::from_zip32_seed(seed, network.coin_type(), account)
                    .map_err(|err| ZeckError::Internal(err.to_string()))?;
            let scope = match coordinates.scope {
                AddressScope::External => orchard::keys::Scope::External,
                AddressScope::Internal => orchard::keys::Scope::Internal,
            };
            let address =
                orchard::keys::FullViewingKey::from(&sk).address_at(coordinates.index, scope);
            let encoded = zcash_address::unified::Address::try_from_items(vec![
                zcash_address::unified::Receiver::Orchard(address.to_raw_address_bytes()),
            ])
            .map_err(|err| ZeckError::Internal(err.to_string()))?
            .encode(&match network {
                ZeckNetwork::Mainnet => zcash_protocol::consensus::NetworkType::Main,
                ZeckNetwork::Testnet => zcash_protocol::consensus::NetworkType::Test,
            });
            verify_public_match(&coordinates, &encoded)?;
            Ok(Arc::new(MatchedSeedKeySource::new(*seed, coordinates)))
        }
    }
}

fn verify_public_match(coordinates: &MatchCoordinates, derived: &str) -> ZeckResult<()> {
    if coordinates.address != derived {
        return Err(ZeckError::InvalidConfig(
            "the re-entered seed phrase and case-sensitive BIP-39 passphrase do not derive the matched address at the saved path; check both exactly (the wallet-file password is separate)".to_owned(),
        ));
    }
    Ok(())
}

struct MatchedImportedKeySource {
    inner: ImportedKeySource,
    coordinates: MatchCoordinates,
}

impl MatchedImportedKeySource {
    fn new(keys: ImportedKeys, coordinates: MatchCoordinates) -> Self {
        Self {
            inner: ImportedKeySource::new(keys),
            coordinates,
        }
    }
}

impl KeySource for MatchedImportedKeySource {
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        self.inner.fingerprint()
    }
    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        Ok(None)
    }
    fn workspace_path_component(&self) -> ZeckResult<String> {
        self.inner.workspace_path_component()
    }
    fn describe(&self) -> String {
        format!("matched {} address", self.coordinates.pool.label())
    }
    fn imported_keys(&self) -> Option<&ImportedKeys> {
        self.inner.imported_keys()
    }
    fn match_coordinates(&self) -> Option<&MatchCoordinates> {
        Some(&self.coordinates)
    }
}

struct MatchedSeedKeySource {
    seed: Secret<[u8; 64]>,
    coordinates: MatchCoordinates,
}

impl MatchedSeedKeySource {
    fn new(seed: [u8; 64], coordinates: MatchCoordinates) -> Self {
        Self {
            seed: Secret::new(seed),
            coordinates,
        }
    }
}

impl KeySource for MatchedSeedKeySource {
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        let mut h = Sha256::new();
        h.update(b"argos-matched-seed-fingerprint-v1");
        h.update(self.seed.expose_secret());
        h.update(self.coordinates.account.to_le_bytes());
        Ok(KeySourceFingerprint::from_bytes(h.finalize().into()))
    }
    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        Ok(Some(*self.seed.expose_secret()))
    }
    fn workspace_path_component(&self) -> ZeckResult<String> {
        Ok(format!("matched-orchard-{}", self.fingerprint()?.to_hex()))
    }
    fn describe(&self) -> String {
        format!("matched Orchard account {}", self.coordinates.account)
    }
    fn match_coordinates(&self) -> Option<&MatchCoordinates> {
        Some(&self.coordinates)
    }
    fn exact_hd_account(&self) -> Option<u32> {
        Some(self.coordinates.account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{read_session_metadata, write_session_metadata, SessionMetadata};

    const SEED: [u8; 64] = [7; 64];

    #[test]
    fn transparent_match_imports_only_the_exact_private_key() {
        let address = transparent_address_from_seed(
            ZeckNetwork::Testnet,
            &SEED,
            3,
            AddressScope::Internal,
            19,
        )
        .unwrap();
        let coordinates = MatchCoordinates {
            pool: DiscoveryPool::Transparent,
            account: 3,
            scope: AddressScope::Internal,
            index: 19,
            network: ZeckNetwork::Testnet,
            address: encode_transparent_address(&address, ZeckNetwork::Testnet),
            path: "m / 44' / 1' / 3' / 1 / 19".to_owned(),
        };
        let source = prepare_match_recovery(&SEED, ZeckNetwork::Testnet, coordinates).unwrap();
        let keys = source.imported_keys().unwrap();
        assert_eq!(keys.transparent.len(), 1);
        assert!(keys.sapling.is_empty());
        let wanted = legacy_transparent_secret_key_for_account(
            ZeckNetwork::Testnet,
            &SEED,
            3,
            AddressScope::Internal,
            19,
        )
        .unwrap();
        assert_eq!(
            keys.transparent[0].secret.expose_secret(),
            &wanted.secret_bytes()
        );
        assert_eq!(source.match_coordinates().unwrap().index, 19);
        assert_eq!(
            source.match_coordinates().unwrap().scope,
            AddressScope::Internal
        );
    }

    #[test]
    fn orchard_match_targets_only_its_exact_account() {
        let account = AccountId::try_from(511).unwrap();
        let sk = orchard::keys::SpendingKey::from_zip32_seed(&SEED, 1, account).unwrap();
        let address = orchard::keys::FullViewingKey::from(&sk)
            .address_at(23u32, orchard::keys::Scope::External);
        let encoded = zcash_address::unified::Address::try_from_items(vec![
            zcash_address::unified::Receiver::Orchard(address.to_raw_address_bytes()),
        ])
        .unwrap()
        .encode(&zcash_protocol::consensus::NetworkType::Test);
        let source = prepare_match_recovery(
            &SEED,
            ZeckNetwork::Testnet,
            MatchCoordinates {
                pool: DiscoveryPool::Orchard,
                account: 511,
                scope: AddressScope::External,
                index: 23,
                network: ZeckNetwork::Testnet,
                address: encoded,
                path: "m_Orchard / 32' / 1' / 511' / 23".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(source.exact_hd_account(), Some(511));
        assert_eq!(source.wallet_seed().unwrap(), Some(SEED));
    }

    #[test]
    fn sapling_internal_handoff_rederives_exact_scope_and_index() {
        let account = AccountId::try_from(4).unwrap();
        let extsk = zcash_keys::keys::sapling::spending_key(&SEED, 133, account);
        let (index, address) = (1u32..1000)
            .find_map(|index| {
                extsk
                    .derive_internal()
                    .to_diversifiable_full_viewing_key()
                    .address(index.into())
                    .map(|address| (index, address))
            })
            .expect("a valid nonzero Sapling diversifier in bounded test range");
        use zcash_keys::encoding::AddressCodec;
        let encoded = address.encode(&zcash_protocol::consensus::MAIN_NETWORK);
        let source = prepare_match_recovery(
            &SEED,
            ZeckNetwork::Mainnet,
            MatchCoordinates {
                pool: DiscoveryPool::Sapling,
                account: 4,
                scope: AddressScope::Internal,
                index,
                network: ZeckNetwork::Mainnet,
                address: encoded,
                path: format!("m_Sapling / 32' / 133' / 4' / {index} (internal)"),
            },
        )
        .unwrap();
        assert_eq!(source.imported_keys().unwrap().sapling.len(), 1);
        assert_eq!(source.match_coordinates().unwrap().index, index);
    }

    #[test]
    fn changed_passphrase_seed_cannot_reconstruct_saved_match() {
        let address = transparent_address_from_seed(
            ZeckNetwork::Mainnet,
            &SEED,
            0,
            AddressScope::External,
            2,
        )
        .unwrap();
        let coordinates = MatchCoordinates {
            pool: DiscoveryPool::Transparent,
            account: 0,
            scope: AddressScope::External,
            index: 2,
            network: ZeckNetwork::Mainnet,
            address: encode_transparent_address(&address, ZeckNetwork::Mainnet),
            path: "m / 44' / 133' / 0' / 0 / 2".to_owned(),
        };
        let changed_passphrase_seed = [8u8; 64];
        let err = match prepare_match_recovery(
            &changed_passphrase_seed,
            ZeckNetwork::Mainnet,
            coordinates,
        ) {
            Ok(_) => panic!("different raw seed must not resume the saved match"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("seed phrase and case-sensitive BIP-39 passphrase"));
        assert!(message.contains("check both exactly"));
        assert!(message.contains("wallet-file password is separate"));
        assert!(!message.contains("8"));
    }

    #[test]
    fn session_round_trip_retains_coordinates_without_seed() {
        let dir = tempfile::tempdir().unwrap();
        let coordinates = MatchCoordinates {
            pool: DiscoveryPool::Sapling,
            account: 8,
            scope: AddressScope::External,
            index: 4,
            network: ZeckNetwork::Mainnet,
            address: "zs-public".to_owned(),
            path: "m_Sapling / 32' / 133' / 8' / 4".to_owned(),
        };
        let meta =
            SessionMetadata::new_in_progress("match".to_owned(), ZeckNetwork::Mainnet, 1, None, 2)
                .with_match_coordinates(Some(coordinates.clone()));
        write_session_metadata(dir.path(), &meta).unwrap();
        assert_eq!(
            read_session_metadata(dir.path())
                .unwrap()
                .unwrap()
                .match_coordinates,
            Some(coordinates)
        );
        let json = std::fs::read_to_string(dir.path().join("session.json")).unwrap();
        assert!(!json.contains("seed"));
        assert!(!json.contains("passphrase"));
    }

    #[test]
    fn resume_workspace_accepts_same_match_and_rejects_other_coordinates() {
        use crate::models::RuntimeScanConfig;
        use crate::workspace::{verify_key_source_for_workspace, RecoveryWorkspace};

        let coordinates = |index| {
            let address = transparent_address_from_seed(
                ZeckNetwork::Testnet,
                &SEED,
                2,
                AddressScope::External,
                index,
            )
            .unwrap();
            MatchCoordinates {
                pool: DiscoveryPool::Transparent,
                account: 2,
                scope: AddressScope::External,
                index,
                network: ZeckNetwork::Testnet,
                address: encode_transparent_address(&address, ZeckNetwork::Testnet),
                path: format!("m / 44' / 1' / 2' / 0 / {index}"),
            }
        };
        let source = prepare_match_recovery(&SEED, ZeckNetwork::Testnet, coordinates(7)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let runtime = RuntimeScanConfig {
            key_source: source.clone(),
            birthday: 1,
            num_accounts: Some(1),
            gap_limit: 1,
            lightwalletd_url: "https://example.invalid".to_owned(),
            data_dir: temp.path().to_owned(),
            network: ZeckNetwork::Testnet,
            label: "match".to_owned(),
        };
        let workspace = RecoveryWorkspace::from_runtime(&runtime).unwrap();
        verify_key_source_for_workspace(workspace.root(), source.as_ref()).unwrap();

        let other = prepare_match_recovery(&SEED, ZeckNetwork::Testnet, coordinates(8)).unwrap();
        assert!(verify_key_source_for_workspace(workspace.root(), other.as_ref()).is_err());
    }
}
