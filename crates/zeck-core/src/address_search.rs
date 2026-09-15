//! Bounded, cancellable offline address matching. No wallet or network access.
use crate::address_search_shielded::{AccountMatcher, TargetReceivers};
use crate::{AddressScope, DiscoveryPool, ZeckError, ZeckNetwork, ZeckResult};
use bip0039::{English, Mnemonic};
use secrecy::{ExposeSecret, Secret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use zcash_keys::address::Address;
use zcash_transparent::{
    address::TransparentAddress,
    keys::{AccountPrivKey, NonHardenedChildIndex},
};
use zip32::AccountId;

const MAX_WORK: u64 = 10_000_000;
const MAX_MATCHES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchProfile {
    ZecwalletLite,
    Bip44,
}

// Secret-bearing input never implements Serialize, Clone or Debug.
pub struct CandidateSeed {
    pub label: String,
    pub seed: SecretString,
    pub passphrase: SecretString,
}
pub struct SearchRequest {
    pub target: String,
    pub network: ZeckNetwork,
    pub seeds: Vec<CandidateSeed>,
    pub profile: SearchProfile,
    pub account_start: u32,
    pub account_count: u32,
    pub index_start: u32,
    pub index_count: u32,
    pub include_change: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct AddressMatch {
    pub id: String,
    pub seed_label: String,
    pub seed_index: usize,
    pub address: String,
    pub pool: DiscoveryPool,
    pub path: String,
    pub account: u32,
    pub scope: AddressScope,
    pub index: u32,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStatus {
    Running,
    Complete,
    Cancelled,
    Error,
}
#[derive(Clone, Debug, Serialize)]
pub struct SearchSnapshot {
    pub id: String,
    pub target: String,
    pub network: ZeckNetwork,
    pub profile: SearchProfile,
    pub status: SearchStatus,
    pub checked: u64,
    pub total: u64,
    pub matches: Vec<AddressMatch>,
    pub error: Option<String>,
}
struct RetainedMatch {
    public: AddressMatch,
    seed: Arc<Secret<[u8; 64]>>,
}
struct SearchJob {
    snapshot: Mutex<SearchSnapshot>,
    matches: Mutex<Vec<RetainedMatch>>,
    cancelled: AtomicBool,
}
#[derive(Clone, Default)]
pub struct AddressSearchService {
    current: Arc<Mutex<Option<Arc<SearchJob>>>>,
}

fn invalid(message: &str) -> ZeckError {
    ZeckError::InvalidConfig(message.to_owned())
}
fn end(start: u32, count: u32) -> ZeckResult<u32> {
    start
        .checked_add(count)
        .filter(|end| count > 0 && *end <= (1 << 31))
        .ok_or_else(|| invalid("range must be nonempty and within 0–2147483647"))
}

/// Converts BIP39 mnemonic + optional passphrase to seed bytes. Error text never
/// echoes either input. The passphrase is processed by bip0039's NFKD handling.
pub fn candidate_seed(
    phrase: &SecretString,
    passphrase: &SecretString,
) -> ZeckResult<Secret<[u8; 64]>> {
    let normalized = SecretString::new(
        phrase
            .expose_secret()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
    );
    let mnemonic = Mnemonic::<English>::from_phrase(normalized.expose_secret())
        .map_err(|_| invalid("invalid BIP-39 seed phrase"))?;
    Ok(Secret::new(mnemonic.to_seed(passphrase.expose_secret())))
}

impl AddressSearchService {
    pub fn start(&self, request: SearchRequest) -> ZeckResult<String> {
        if request.target.len() > 4096 {
            return Err(invalid("target address is too long"));
        }
        let params = crate::workspace::consensus_network(request.network);
        let address = Address::decode(&params, request.target.trim())
            .ok_or_else(|| invalid("target address is invalid or belongs to another network"))?;
        let transparent = match &address {
            Address::Transparent(TransparentAddress::PublicKeyHash(hash)) => Some(TransparentAddress::PublicKeyHash(*hash)),
            Address::Unified(ua) => ua.transparent().copied().filter(|a| matches!(a, TransparentAddress::PublicKeyHash(_))),
            Address::Sapling(_) => None,
            _ => return Err(invalid("this address type requires an imported script/key or is not supported by seed matching")),
        };
        let shielded = TargetReceivers::parse(request.target.trim(), request.network)?;
        if transparent.is_none() && !shielded.has_shielded() {
            return Err(invalid("target has no supported receivers"));
        }
        if request.seeds.is_empty() || request.seeds.len() > 64 {
            return Err(invalid("provide 1–64 candidate seeds"));
        }
        end(request.account_start, request.account_count)?;
        end(request.index_start, request.index_count)?;
        if matches!(request.profile, SearchProfile::ZecwalletLite)
            && transparent.is_some()
            && (request.account_start != 0 || request.account_count != 1)
        {
            return Err(invalid("ZecWallet Lite transparent matching uses account 0; choose advanced BIP44 to search other accounts"));
        }
        let scopes = if request.include_change { 2u64 } else { 1 };
        let total = (request.seeds.len() as u64)
            .checked_mul(u64::from(request.account_count))
            .and_then(|n| n.checked_mul(u64::from(request.index_count)))
            .and_then(|n| n.checked_mul(scopes))
            .filter(|n| *n <= MAX_WORK)
            .ok_or_else(|| {
                invalid(
                    "search exceeds 10000000 derivation candidates; split it into smaller ranges",
                )
            })?;
        // Validate before registration; PBKDF2 runs on the worker, not the UI task.
        for (i, candidate) in request.seeds.iter().enumerate() {
            if candidate.label.chars().count() > 80
                || candidate.seed.expose_secret().len() > 4096
                || candidate.passphrase.expose_secret().len() > 1024
            {
                return Err(invalid("candidate label, seed, or passphrase is too long"));
            }
            let normalized = SecretString::new(
                candidate
                    .seed
                    .expose_secret()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase(),
            );
            Mnemonic::<English>::from_phrase(normalized.expose_secret())
                .map_err(|_| invalid(&format!("Seed {}: invalid BIP-39 phrase", i + 1)))?;
        }
        let mut current = self.current.lock().unwrap();
        if current.is_some() {
            return Err(invalid(
                "release the existing address search before starting another",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let job = Arc::new(SearchJob {
            snapshot: Mutex::new(SearchSnapshot {
                id: id.clone(),
                target: request.target.trim().to_owned(),
                network: request.network,
                profile: request.profile,
                status: SearchStatus::Running,
                checked: 0,
                total,
                matches: vec![],
                error: None,
            }),
            matches: Mutex::new(vec![]),
            cancelled: AtomicBool::new(false),
        });
        *current = Some(job.clone());
        std::thread::Builder::new()
            .name("argos-address-search".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_search(&job, request, transparent, shielded)
                }));
                let mut snapshot = job.snapshot.lock().unwrap();
                match result {
                    Ok(Ok(())) if job.cancelled.load(Ordering::Relaxed) => {
                        snapshot.status = SearchStatus::Cancelled
                    }
                    Ok(Ok(())) => snapshot.status = SearchStatus::Complete,
                    Ok(Err(err)) => {
                        snapshot.status = SearchStatus::Error;
                        snapshot.error = Some(err.to_string());
                    }
                    Err(_) => {
                        snapshot.status = SearchStatus::Error;
                        snapshot.error = Some("address search could not finish".to_owned());
                    }
                }
            })
            .map_err(|_| {
                *current = None;
                invalid("could not start address search")
            })?;
        Ok(id)
    }
    fn job(&self, id: &str) -> ZeckResult<Arc<SearchJob>> {
        self.current
            .lock()
            .unwrap()
            .as_ref()
            .filter(|job| job.snapshot.lock().unwrap().id == id)
            .cloned()
            .ok_or_else(|| invalid("address search is no longer available"))
    }
    pub fn snapshot(&self, id: &str) -> ZeckResult<SearchSnapshot> {
        Ok(self.job(id)?.snapshot.lock().unwrap().clone())
    }
    pub fn cancel(&self, id: &str) -> ZeckResult<()> {
        self.job(id)?.cancelled.store(true, Ordering::Relaxed);
        Ok(())
    }
    pub fn release(&self, id: &str) -> ZeckResult<()> {
        let mut current = self.current.lock().unwrap();
        let job = current
            .as_ref()
            .filter(|j| j.snapshot.lock().unwrap().id == id)
            .ok_or_else(|| invalid("address search is no longer available"))?;
        job.cancelled.store(true, Ordering::Relaxed);
        // Retain registration until the worker stops so repeated close/start
        // cannot create unbounded detached derivation threads.
        if matches!(job.snapshot.lock().unwrap().status, SearchStatus::Running) {
            return Err(invalid(
                "search is cancelling; wait for it to stop before releasing",
            ));
        }
        *current = None;
        Ok(())
    }
    pub fn matched_seed(
        &self,
        id: &str,
        match_id: &str,
    ) -> ZeckResult<(AddressMatch, Arc<Secret<[u8; 64]>>)> {
        let job = self.job(id)?;
        let matches = job.matches.lock().unwrap();
        let found = matches
            .iter()
            .find(|m| m.public.id == match_id)
            .ok_or_else(|| invalid("address match is no longer available"))?;
        Ok((found.public.clone(), found.seed.clone()))
    }
}
fn record(job: &SearchJob, public: AddressMatch, seed: &Arc<Secret<[u8; 64]>>) -> ZeckResult<()> {
    let mut matches = job.matches.lock().unwrap();
    if matches.len() >= MAX_MATCHES {
        return Err(invalid("match limit reached; narrow the search range"));
    }
    matches.push(RetainedMatch {
        public: public.clone(),
        seed: seed.clone(),
    });
    job.snapshot.lock().unwrap().matches.push(public);
    Ok(())
}
fn run_search(
    job: &SearchJob,
    request: SearchRequest,
    transparent: Option<TransparentAddress>,
    shielded: TargetReceivers,
) -> ZeckResult<()> {
    let params = crate::workspace::consensus_network(request.network);
    let mut checked = 0;
    for (seed_index, candidate) in request.seeds.into_iter().enumerate() {
        if job.cancelled.load(Ordering::Relaxed) {
            break;
        }
        let seed = Arc::new(candidate_seed(&candidate.seed, &candidate.passphrase)?);
        let label = if candidate.label.trim().is_empty() {
            format!("Seed {}", seed_index + 1)
        } else {
            candidate.label.trim().to_owned()
        };
        drop(candidate);
        for account in request.account_start..request.account_start + request.account_count {
            if job.cancelled.load(Ordering::Relaxed) {
                break;
            }
            let key = if transparent.is_some() {
                Some(
                    AccountPrivKey::from_seed(
                        &params,
                        seed.expose_secret(),
                        AccountId::try_from(account).map_err(|_| invalid("invalid account"))?,
                    )
                    .map_err(|_| invalid("could not derive transparent account"))?
                    .to_account_pubkey(),
                )
            } else {
                None
            };
            let matcher = if shielded.has_shielded() {
                Some(AccountMatcher::new(
                    seed.expose_secret(),
                    request.network,
                    account,
                )?)
            } else {
                None
            };
            for scope_number in 0..if request.include_change { 2 } else { 1 } {
                let scope = if scope_number == 0 {
                    AddressScope::External
                } else {
                    AddressScope::Internal
                };
                for index in request.index_start..request.index_start + request.index_count {
                    if job.cancelled.load(Ordering::Relaxed) {
                        job.snapshot.lock().unwrap().checked = checked;
                        return Ok(());
                    }
                    if let (Some(key), Some(target)) = (&key, transparent) {
                        let pubkey = key
                            .derive_address_pubkey(
                                scope.into(),
                                NonHardenedChildIndex::from_index(index).unwrap(),
                            )
                            .map_err(|_| invalid("could not derive transparent address"))?;
                        let derived = TransparentAddress::from_pubkey(&pubkey);
                        if derived == target {
                            record(
                                job,
                                AddressMatch {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    seed_label: label.clone(),
                                    seed_index,
                                    address: crate::imported::encode_transparent_address(
                                        &derived,
                                        request.network,
                                    ),
                                    pool: DiscoveryPool::Transparent,
                                    path: format!(
                                        "m/44'/{}'/{account}'/{scope_number}/{index}",
                                        request.network.coin_type()
                                    ),
                                    account,
                                    scope,
                                    index,
                                },
                                &seed,
                            )?;
                        }
                    }
                    if let Some(matcher) = &matcher {
                        for found in matcher.matches(&shielded, scope, index)? {
                            record(
                                job,
                                AddressMatch {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    seed_label: label.clone(),
                                    seed_index,
                                    address: found.address,
                                    pool: found.pool,
                                    path: found.path,
                                    account,
                                    scope,
                                    index,
                                },
                                &seed,
                            )?;
                        }
                    }
                    checked += 1;
                    if checked % 128 == 0 {
                        job.snapshot.lock().unwrap().checked = checked;
                    }
                }
            }
        }
    }
    job.snapshot.lock().unwrap().checked = checked;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // Public BIP39 test vector, never a funded wallet.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn request(target: String) -> SearchRequest {
        SearchRequest {
            target,
            network: ZeckNetwork::Mainnet,
            seeds: vec![CandidateSeed {
                label: "test vector".into(),
                seed: SecretString::new(PHRASE.into()),
                passphrase: SecretString::new("TREZOR".into()),
            }],
            profile: SearchProfile::Bip44,
            account_start: 3,
            account_count: 1,
            index_start: 0,
            index_count: 130,
            include_change: true,
        }
    }
    fn target(account: u32, index: u32, scope: AddressScope) -> String {
        let seed = candidate_seed(
            &SecretString::new(PHRASE.into()),
            &SecretString::new("TREZOR".into()),
        )
        .unwrap();
        let params = crate::workspace::consensus_network(ZeckNetwork::Mainnet);
        let key = AccountPrivKey::from_seed(
            &params,
            seed.expose_secret(),
            AccountId::try_from(account).unwrap(),
        )
        .unwrap();
        // Derive through the private-key path to independently check public-key search.
        let sk = key
            .derive_secret_key(
                scope.into(),
                NonHardenedChildIndex::from_index(index).unwrap(),
            )
            .unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        crate::imported::encode_transparent_address(
            &TransparentAddress::from_pubkey(&pk),
            ZeckNetwork::Mainnet,
        )
    }
    fn terminal(service: &AddressSearchService, id: &str) -> SearchSnapshot {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let snapshot = service.snapshot(id).unwrap();
            if !matches!(snapshot.status, SearchStatus::Running) {
                return snapshot;
            }
            assert!(Instant::now() < deadline, "address search timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn finds_nonzero_account_change_index_beyond_gap_and_rehydrates_exact_key() {
        let service = AddressSearchService::default();
        let target = target(3, 127, AddressScope::Internal);
        let mut input = request(target.clone());
        input.seeds[0].seed = SecretString::new(PHRASE.to_ascii_uppercase());
        input.seeds.insert(
            0,
            CandidateSeed {
                label: "wrong passphrase".into(),
                seed: SecretString::new(PHRASE.into()),
                passphrase: SecretString::new("".into()),
            },
        );
        let id = service.start(input).unwrap();
        let result = terminal(&service, &id);
        assert!(
            matches!(result.status, SearchStatus::Complete),
            "{:?}",
            result.error
        );
        assert_eq!(result.checked, 520);
        assert_eq!(result.matches.len(), 1);
        let found = &result.matches[0];
        assert_eq!((found.seed_index, found.account, found.index), (1, 3, 127));
        assert_eq!(found.scope, AddressScope::Internal);
        assert_eq!(found.address, target);
        assert_eq!(found.path, "m/44'/133'/3'/1/127");
        let (public, seed) = service.matched_seed(&id, &found.id).unwrap();
        let coordinates = crate::MatchCoordinates {
            pool: public.pool,
            account: public.account,
            scope: public.scope,
            index: public.index,
            network: ZeckNetwork::Mainnet,
            address: public.address,
            path: public.path,
        };
        let source = crate::prepare_match_recovery(
            seed.expose_secret(),
            ZeckNetwork::Mainnet,
            coordinates.clone(),
        )
        .unwrap();
        assert_eq!(source.match_coordinates(), Some(&coordinates));
        let imported = source
            .imported_keys()
            .expect("transparent match uses imported route");
        assert_eq!(imported.transparent.len(), 1);
        let expected = crate::derivation::legacy_transparent_secret_key_for_account(
            ZeckNetwork::Mainnet,
            seed.expose_secret(),
            found.account,
            found.scope,
            found.index,
        )
        .unwrap();
        assert_eq!(
            imported.transparent[0].secret.expose_secret(),
            &expected.secret_bytes(),
            "the retained match must hand the existing signer its exact nonzero-index key"
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(PHRASE));
        assert!(!serialized.contains("TREZOR"));
        service.release(&id).unwrap();
        assert!(service.matched_seed(&id, &found.id).is_err());
    }

    #[test]
    fn one_handoff_does_not_consume_a_second_match() {
        let service = AddressSearchService::default();
        let wanted = target(3, 127, AddressScope::Internal);
        let mut input = request(wanted);
        input.seeds.push(CandidateSeed {
            label: "same recovery material, second candidate".into(),
            seed: SecretString::new(PHRASE.into()),
            passphrase: SecretString::new("TREZOR".into()),
        });
        let id = service.start(input).unwrap();
        let result = terminal(&service, &id);
        assert_eq!(result.matches.len(), 2);

        let first = &result.matches[0];
        let second = &result.matches[1];
        let (first_public, first_seed) = service.matched_seed(&id, &first.id).unwrap();
        let first_source = crate::prepare_match_recovery(
            first_seed.expose_secret(),
            ZeckNetwork::Mainnet,
            crate::MatchCoordinates {
                pool: first_public.pool,
                account: first_public.account,
                scope: first_public.scope,
                index: first_public.index,
                network: ZeckNetwork::Mainnet,
                address: first_public.address,
                path: first_public.path,
            },
        )
        .unwrap();
        drop(first_source);

        assert!(service.matched_seed(&id, &second.id).is_ok());
        assert!(service.snapshot(&id).is_ok());
        service.release(&id).unwrap();
        assert!(service.matched_seed(&id, &second.id).is_err());
    }
    #[test]
    fn zecwallet_lite_finds_receive_index_997_without_account_expansion() {
        let service = AddressSearchService::default();
        let mut input = request(target(0, 997, AddressScope::External));
        input.profile = SearchProfile::ZecwalletLite;
        input.account_start = 0;
        input.account_count = 1;
        input.index_count = 1000;
        input.include_change = false;
        let id = service.start(input).unwrap();
        let result = terminal(&service, &id);
        assert!(matches!(result.status, SearchStatus::Complete));
        assert_eq!(result.checked, 1000);
        assert_eq!(result.matches.len(), 1);
        let found = &result.matches[0];
        assert_eq!(found.account, 0);
        assert_eq!(found.scope, AddressScope::External);
        assert_eq!(found.index, 997);
        assert_eq!(found.path, "m/44'/133'/0'/0/997");
        service.release(&id).unwrap();
    }

    #[test]
    fn cancellation_holds_registration_until_worker_stops() {
        let service = AddressSearchService::default();
        let target = target(3, 127, AddressScope::Internal);
        let mut input = request(target.clone());
        input.index_count = 1_000_000;
        let id = service.start(input).unwrap();
        assert!(service.start(request(target.clone())).is_err());
        assert!(service.cancel("wrong-id").is_err());
        service.cancel(&id).unwrap();
        assert!(matches!(
            terminal(&service, &id).status,
            SearchStatus::Cancelled
        ));
        service.release(&id).unwrap();
        assert!(service.snapshot(&id).is_err());
        let next = service.start(request(target)).unwrap();
        terminal(&service, &next);
        service.release(&next).unwrap();
    }
    #[test]
    fn invalid_inputs_do_not_register_jobs_or_echo_secrets() {
        let service = AddressSearchService::default();
        let address = target(3, 127, AddressScope::Internal);
        let mut input = request(address.clone());
        input.seeds = (0..65)
            .map(|_| CandidateSeed {
                label: String::new(),
                seed: SecretString::new(PHRASE.into()),
                passphrase: SecretString::new(String::new()),
            })
            .collect();
        assert!(service.start(input).is_err());
        let mut input = request(address.clone());
        input.network = ZeckNetwork::Testnet;
        assert!(service.start(input).is_err());
        let mut input = request(address.clone());
        input.index_start = 1 << 31;
        assert!(service.start(input).is_err());
        let mut input = request(address.clone());
        input.index_count = 0;
        assert!(service.start(input).is_err());
        let mut input = request(address.clone());
        input.account_count = 100_000;
        assert!(service.start(input).is_err());
        let mut input = request(address.clone());
        input.profile = SearchProfile::ZecwalletLite;
        assert!(service.start(input).is_err());
        let mut input = request(address.clone());
        input.seeds[0].seed = SecretString::new("do-not-echo-this-invalid-secret".into());
        let error = service.start(input).unwrap_err().to_string();
        assert!(!error.contains("do-not-echo"));
        let script = crate::imported::encode_transparent_address(
            &TransparentAddress::ScriptHash([1; 20]),
            ZeckNetwork::Mainnet,
        );
        assert!(service.start(request(script)).is_err());
        let id = service.start(request(address)).unwrap();
        terminal(&service, &id);
        service.release(&id).unwrap();
    }
}
