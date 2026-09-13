//! Receiver-level matching for ZIP-32 Sapling and Orchard addresses.
use crate::{
    error::{ZeckError, ZeckResult},
    models::{AddressScope, DiscoveryPool, ZeckNetwork},
};
use std::collections::BTreeSet;
use zcash_address::unified::{Address as UnifiedAddress, Container, Encoding, Receiver};
use zcash_keys::{encoding::AddressCodec, keys::sapling};
use zcash_protocol::consensus::{NetworkConstants, NetworkType, MAIN_NETWORK, TEST_NETWORK};
use zip32::AccountId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShieldedReceiver {
    Sapling([u8; 43]),
    Orchard([u8; 43]),
}

/// Shielded receivers extracted from a target. Transparent-only targets are valid and empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetReceivers {
    receivers: BTreeSet<ShieldedReceiver>,
}
impl TargetReceivers {
    pub fn parse(target: &str, network: ZeckNetwork) -> ZeckResult<Self> {
        let mut receivers = BTreeSet::new();
        if let Ok((actual, ua)) = UnifiedAddress::decode(target) {
            if actual != net(network) {
                return Err(ZeckError::WrongNetwork {
                    expected: network.label().into(),
                    actual: format!("{actual:?}").to_lowercase(),
                });
            }
            for receiver in ua.items() {
                match receiver {
                    Receiver::Sapling(bytes) => {
                        receivers.insert(ShieldedReceiver::Sapling(bytes));
                    }
                    Receiver::Orchard(bytes) => {
                        receivers.insert(ShieldedReceiver::Orchard(bytes));
                    }
                    _ => {}
                }
            }
            return Ok(Self { receivers });
        }
        let address = match network {
            ZeckNetwork::Mainnet => zcash_keys::encoding::decode_payment_address(
                MAIN_NETWORK.hrp_sapling_payment_address(),
                target,
            ),
            ZeckNetwork::Testnet => zcash_keys::encoding::decode_payment_address(
                TEST_NETWORK.hrp_sapling_payment_address(),
                target,
            ),
        };
        match address {
            Ok(address) => {
                receivers.insert(ShieldedReceiver::Sapling(address.to_bytes()));
                Ok(Self { receivers })
            }
            Err(_) => Ok(Self { receivers }),
        }
    }
    pub fn has_shielded(&self) -> bool {
        !self.receivers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedReceiver {
    pub pool: DiscoveryPool,
    pub address: String,
    pub path: String,
}

/// Account-scoped key cache, reused across every requested address index.
pub struct AccountMatcher {
    network: ZeckNetwork,
    account: u32,
    sapling_fvk: sapling_crypto::zip32::DiversifiableFullViewingKey,
    orchard_fvk: orchard::keys::FullViewingKey,
}
impl AccountMatcher {
    pub fn new(seed: &[u8; 64], network: ZeckNetwork, account: u32) -> ZeckResult<Self> {
        let id = AccountId::try_from(account).map_err(|_| {
            ZeckError::InvalidConfig(format!("account index {account} is out of range"))
        })?;
        let sapling_sk = sapling::spending_key(seed, network.coin_type(), id);
        let orchard_sk = orchard::keys::SpendingKey::from_zip32_seed(seed, network.coin_type(), id)
            .map_err(|e| ZeckError::Internal(e.to_string()))?;
        Ok(Self {
            network,
            account,
            sapling_fvk: sapling_sk.to_diversifiable_full_viewing_key(),
            orchard_fvk: orchard::keys::FullViewingKey::from(&orchard_sk),
        })
    }
    pub fn matches(
        &self,
        target: &TargetReceivers,
        scope: AddressScope,
        index: u32,
    ) -> ZeckResult<Vec<MatchedReceiver>> {
        let mut out = Vec::new();
        // The upstream API does not expose Sapling's internal diversifier key.
        // Never test an external address while labeling it internal.
        if matches!(scope, AddressScope::External) {
            if let Some(address) = self.sapling_fvk.to_external_ivk().address_at(index) {
                if target
                    .receivers
                    .contains(&ShieldedReceiver::Sapling(address.to_bytes()))
                {
                    let encoded = match self.network {
                        ZeckNetwork::Mainnet => address.encode(&MAIN_NETWORK),
                        ZeckNetwork::Testnet => address.encode(&TEST_NETWORK),
                    };
                    out.push(MatchedReceiver {
                        pool: DiscoveryPool::Sapling,
                        address: encoded,
                        path: format!(
                            "m_Sapling / 32' / {}' / {}' / {index}",
                            self.network.coin_type(),
                            self.account
                        ),
                    });
                }
            }
        }
        let os = match scope {
            AddressScope::External => orchard::keys::Scope::External,
            AddressScope::Internal => orchard::keys::Scope::Internal,
        };
        let address = self.orchard_fvk.address_at(index, os);
        if target
            .receivers
            .contains(&ShieldedReceiver::Orchard(address.to_raw_address_bytes()))
        {
            let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(
                address.to_raw_address_bytes(),
            )])
            .map_err(|e| ZeckError::Internal(e.to_string()))?;
            out.push(MatchedReceiver {
                pool: DiscoveryPool::Orchard,
                address: ua.encode(&net(self.network)),
                path: format!(
                    "m_Orchard / 32' / {}' / {}' / {index} ({scope:?})",
                    self.network.coin_type(),
                    self.account
                ),
            });
        }
        Ok(out)
    }
}
fn net(network: ZeckNetwork) -> NetworkType {
    match network {
        ZeckNetwork::Mainnet => NetworkType::Main,
        ZeckNetwork::Testnet => NetworkType::Test,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn orchard_internal_scope_matches_only_internal_target() {
        let m = AccountMatcher::new(&[7u8; 64], ZeckNetwork::Mainnet, 0).unwrap();
        let external = m
            .orchard_fvk
            .address_at(7u32, orchard::keys::Scope::External);
        let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(
            external.to_raw_address_bytes(),
        )])
        .unwrap();
        let target =
            TargetReceivers::parse(&ua.encode(&NetworkType::Main), ZeckNetwork::Mainnet).unwrap();
        assert!(m
            .matches(&target, AddressScope::Internal, 7)
            .unwrap()
            .is_empty());
        let internal = m
            .orchard_fvk
            .address_at(7u32, orchard::keys::Scope::Internal);
        let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(
            internal.to_raw_address_bytes(),
        )])
        .unwrap();
        let target =
            TargetReceivers::parse(&ua.encode(&NetworkType::Main), ZeckNetwork::Mainnet).unwrap();
        assert_eq!(
            m.matches(&target, AddressScope::Internal, 7).unwrap().len(),
            1
        );
    }
    #[test]
    fn mixed_target_matches_only_owned_pool() {
        let m = AccountMatcher::new(&[8u8; 64], ZeckNetwork::Mainnet, 0).unwrap();
        let other = AccountMatcher::new(&[99u8; 64], ZeckNetwork::Mainnet, 0).unwrap();
        let orchard = other
            .orchard_fvk
            .address_at(3u32, orchard::keys::Scope::External);
        let (index, sapling) = (1u32..1000)
            .find_map(|i| {
                m.sapling_fvk
                    .to_external_ivk()
                    .address_at(i)
                    .map(|address| (i, address))
            })
            .unwrap();
        let ua = UnifiedAddress::try_from_items(vec![
            Receiver::Orchard(orchard.to_raw_address_bytes()),
            Receiver::Sapling(sapling.to_bytes()),
        ])
        .unwrap();
        let target =
            TargetReceivers::parse(&ua.encode(&NetworkType::Main), ZeckNetwork::Mainnet).unwrap();
        let found = m.matches(&target, AddressScope::External, index).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pool, DiscoveryPool::Sapling);
    }
    #[test]
    fn sapling_nonzero_matches_and_invalid_index_does_not_advance() {
        let m = AccountMatcher::new(&[10u8; 64], ZeckNetwork::Mainnet, 0).unwrap();
        let ivk = m.sapling_fvk.to_external_ivk();
        let invalid = (1u32..1000).find(|i| ivk.address_at(*i).is_none()).unwrap();
        let (valid, sapling) = (invalid + 1..1000)
            .find_map(|i| ivk.address_at(i).map(|address| (i, address)))
            .unwrap();
        let ua =
            UnifiedAddress::try_from_items(vec![Receiver::Sapling(sapling.to_bytes())]).unwrap();
        let target =
            TargetReceivers::parse(&ua.encode(&NetworkType::Main), ZeckNetwork::Mainnet).unwrap();
        assert_eq!(
            m.matches(&target, AddressScope::External, valid)
                .unwrap()
                .len(),
            1
        );
        assert!(m
            .matches(&target, AddressScope::Internal, valid)
            .unwrap()
            .is_empty());
        // The target is the first valid address after this invalid index.
        // A matcher using find_address would incorrectly return it here.
        assert!(m
            .matches(&target, AddressScope::External, invalid)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn wrong_network_is_rejected() {
        let m = AccountMatcher::new(&[9u8; 64], ZeckNetwork::Mainnet, 0).unwrap();
        let a = m
            .orchard_fvk
            .address_at(0u32, orchard::keys::Scope::External);
        let ua = UnifiedAddress::try_from_items(vec![Receiver::Orchard(a.to_raw_address_bytes())])
            .unwrap();
        assert!(matches!(
            TargetReceivers::parse(&ua.encode(&NetworkType::Main), ZeckNetwork::Testnet),
            Err(ZeckError::WrongNetwork { .. })
        ));
    }
}
