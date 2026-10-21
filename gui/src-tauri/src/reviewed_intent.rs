use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use argos_core::{sprout_recovery::SpendableSproutNote, sprout_sweep::SweepJournal, ZeckNetwork};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::commands::SproutScanReport;

pub const MAX_SCAN_SESSIONS: usize = 16;
pub const MAX_PROPOSALS: usize = 32;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SproutScanHandle(pub String);

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SproutProposalId(pub String);

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SproutScanStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Serialize)]
pub struct SproutScanSnapshot {
    pub handle: SproutScanHandle,
    pub status: SproutScanStatus,
    pub report: Option<SproutScanReport>,
    pub error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SproutScanProgressEvent {
    pub handle: SproutScanHandle,
    pub height: u32,
    pub target: u32,
    pub notes_found: usize,
    pub joinsplits_seen: u64,
    pub peer_wait: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct SproutSweepPreviewData {
    pub notes: usize,
    pub gross_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub net_zatoshis: u64,
}

#[derive(Serialize)]
pub struct ReviewedSproutSweep {
    pub proposal_id: SproutProposalId,
    #[serde(flatten)]
    pub plan: SproutSweepPreviewData,
    pub params_present: bool,
    pub params_path: String,
    pub lands_in_sapling: String,
}

#[derive(PartialEq, Eq)]
pub enum SproutIntentSource {
    Wallet(String),
    Scan(SproutScanHandle),
}

pub struct SproutSweepIntent {
    pub source: SproutIntentSource,
    pub notes: Vec<SpendableSproutNote>,
    pub destination: String,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub journal: Option<SweepJournal>,
}

pub struct ScanMaterial {
    pub keys: Arc<Vec<[u8; 32]>>,
    pub key_fingerprint: String,
    pub checkpoint: PathBuf,
    pub network: ZeckNetwork,
    pub lightwalletd_url: String,
    pub peers: Vec<String>,
}

struct SproutScanSession {
    keys: Arc<Vec<[u8; 32]>>,
    key_fingerprint: String,
    checkpoint: PathBuf,
    network: ZeckNetwork,
    lightwalletd_url: String,
    peers: Vec<String>,
    status: SproutScanStatus,
    report: Option<SproutScanReport>,
    error: Option<String>,
    released: bool,
}

#[derive(Default)]
struct StoreInner {
    scans: HashMap<SproutScanHandle, SproutScanSession>,
    proposals: HashMap<SproutProposalId, SproutSweepIntent>,
}

#[derive(Default)]
pub struct ReviewedIntentStore(Arc<Mutex<StoreInner>>);

impl Clone for ReviewedIntentStore {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl ReviewedIntentStore {
    pub fn insert_scan(
        &self,
        keys: Vec<[u8; 32]>,
        key_fingerprint: String,
        checkpoint: PathBuf,
        network: ZeckNetwork,
        lightwalletd_url: String,
        peers: Vec<String>,
    ) -> Result<SproutScanHandle, String> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        if inner.scans.len() >= MAX_SCAN_SESSIONS {
            return Err("too many Sprout scans; release an old scan first".into());
        }
        let handle = SproutScanHandle(Uuid::new_v4().to_string());
        inner.scans.insert(
            handle.clone(),
            SproutScanSession {
                keys: Arc::new(keys),
                key_fingerprint,
                checkpoint,
                network,
                lightwalletd_url,
                peers,
                status: SproutScanStatus::Running,
                report: None,
                error: None,
                released: false,
            },
        );
        Ok(handle)
    }

    pub fn scan_material(&self, handle: &SproutScanHandle) -> Result<ScanMaterial, String> {
        let inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        let scan = inner
            .scans
            .get(handle)
            .ok_or("unknown or released Sprout scan")?;
        if scan.released {
            return Err("unknown or released Sprout scan".into());
        }
        Ok(ScanMaterial {
            keys: Arc::clone(&scan.keys),
            key_fingerprint: scan.key_fingerprint.clone(),
            checkpoint: scan.checkpoint.clone(),
            network: scan.network,
            lightwalletd_url: scan.lightwalletd_url.clone(),
            peers: scan.peers.clone(),
        })
    }

    pub fn snapshot(&self, handle: &SproutScanHandle) -> Result<SproutScanSnapshot, String> {
        let inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        let scan = inner
            .scans
            .get(handle)
            .ok_or("unknown or released Sprout scan")?;
        if scan.released {
            return Err("unknown or released Sprout scan".into());
        }
        Ok(SproutScanSnapshot {
            handle: handle.clone(),
            status: scan.status.clone(),
            report: scan.report.clone(),
            error: scan.error.clone(),
        })
    }

    pub fn finish_scan(&self, handle: &SproutScanHandle, result: Result<SproutScanReport, String>) {
        if let Ok(mut inner) = self.0.lock() {
            if inner.scans.get(handle).is_some_and(|scan| scan.released) {
                inner.scans.remove(handle);
                return;
            }
            if let Some(scan) = inner.scans.get_mut(handle) {
                match result {
                    Ok(report) => {
                        scan.status = SproutScanStatus::Completed;
                        scan.report = Some(report);
                    }
                    Err(error) => {
                        scan.status = SproutScanStatus::Failed;
                        scan.error = Some(error);
                    }
                }
            }
        }
    }

    pub fn release_scan(&self, handle: &SproutScanHandle) -> Result<(), String> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        let scan = inner
            .scans
            .get_mut(handle)
            .ok_or("unknown or released Sprout scan")?;
        if scan.released {
            return Err("unknown or released Sprout scan".into());
        }
        if matches!(scan.status, SproutScanStatus::Running) {
            scan.released = true;
        } else {
            inner.scans.remove(handle);
        }
        inner.proposals.retain(|_, intent| !matches!(&intent.source, SproutIntentSource::Scan(source) if source == handle));
        Ok(())
    }

    pub fn insert_proposal(
        &self,
        intent: SproutSweepIntent,
        plan: SproutSweepPreviewData,
    ) -> Result<ReviewedSproutSweep, String> {
        let params_path = argos_core::sprout_sweep::default_params_path();
        let params_present = params_path.exists();
        let params_path = params_path.display().to_string();
        let mut inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        inner.proposals.retain(|_, old| old.source != intent.source);
        if inner.proposals.len() >= MAX_PROPOSALS {
            return Err("too many Sprout proposals; release an old proposal first".into());
        }
        if let SproutIntentSource::Scan(handle) = &intent.source {
            let scan = inner
                .scans
                .get(handle)
                .ok_or("unknown or released Sprout scan")?;
            if !matches!(scan.status, SproutScanStatus::Completed) {
                return Err("Sprout scan has not completed".into());
            }
            if scan.network != intent.network || scan.lightwalletd_url != intent.lightwalletd_url {
                return Err("Sprout proposal source changed".into());
            }
        }
        let proposal_id = SproutProposalId(Uuid::new_v4().to_string());
        inner.proposals.insert(proposal_id.clone(), intent);
        Ok(ReviewedSproutSweep {
            proposal_id,
            plan,
            params_present,
            params_path,
            lands_in_sapling: argos_core::sprout_sweep::SPROUT_LANDS_IN_SAPLING.to_owned(),
        })
    }

    pub fn take_proposal(&self, id: &SproutProposalId) -> Result<SproutSweepIntent, String> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        let intent = inner
            .proposals
            .remove(id)
            .ok_or("unknown or already used Sprout proposal")?;
        if let SproutIntentSource::Scan(handle) = &intent.source {
            if !inner.scans.contains_key(handle) {
                return Err("Sprout scan was released".into());
            }
        }
        Ok(intent)
    }

    pub fn take_wallet_proposal(&self, id: &SproutProposalId) -> Result<SproutSweepIntent, String> {
        {
            let inner = self
                .0
                .lock()
                .map_err(|_| "Sprout review store unavailable")?;
            let intent = inner
                .proposals
                .get(id)
                .ok_or("unknown or already used Sprout proposal")?;
            if !matches!(intent.source, SproutIntentSource::Wallet(_)) {
                return Err("proposal belongs to a scan-derived sweep".into());
            }
        }
        self.take_proposal(id)
    }

    pub fn take_scan_proposal(&self, id: &SproutProposalId) -> Result<SproutSweepIntent, String> {
        {
            let inner = self
                .0
                .lock()
                .map_err(|_| "Sprout review store unavailable")?;
            let intent = inner
                .proposals
                .get(id)
                .ok_or("unknown or already used Sprout proposal")?;
            if !matches!(intent.source, SproutIntentSource::Scan(_)) {
                return Err("proposal belongs to a wallet-derived sweep".into());
            }
        }
        self.take_proposal(id)
    }

    pub fn release_proposal(&self, id: &SproutProposalId) -> Result<(), String> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| "Sprout review store unavailable")?;
        inner
            .proposals
            .remove(id)
            .ok_or("unknown or already used Sprout proposal")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_core::ZeckNetwork;
    use std::path::PathBuf;

    fn scan(store: &ReviewedIntentStore, marker: u8) -> SproutScanHandle {
        store
            .insert_scan(
                vec![[marker; 32]],
                format!("fingerprint-{marker}"),
                PathBuf::from(format!("/tmp/scan-{marker}")),
                ZeckNetwork::Mainnet,
                format!("https://node-{marker}"),
                vec![format!("peer-{marker}:8233")],
            )
            .inspect(|handle| {
                store.finish_scan(
                    handle,
                    Ok(SproutScanReport {
                        blocks_scanned: 1,
                        joinsplits_seen: 2,
                        notes_found: 1,
                        spent_notes: 0,
                        total_zatoshis: 100_000,
                        tip_warning: None,
                    }),
                );
            })
            .unwrap()
    }

    fn proposal(
        store: &ReviewedIntentStore,
        source: SproutIntentSource,
        destination: &str,
    ) -> SproutProposalId {
        let endpoint = match &source {
            SproutIntentSource::Scan(handle) => {
                store.scan_material(handle).unwrap().lightwalletd_url
            }
            SproutIntentSource::Wallet(_) => "https://node-a".to_owned(),
        };
        store
            .insert_proposal(
                SproutSweepIntent {
                    source,
                    notes: Vec::new(),
                    destination: destination.to_owned(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: endpoint,
                    journal: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000,
                },
            )
            .unwrap()
            .proposal_id
    }

    #[test]
    fn sprout_intent_preserves_source_destination_and_network() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        let intent = store.take_proposal(&id).unwrap();
        assert!(matches!(intent.source, SproutIntentSource::Scan(actual) if actual == handle));
        assert_eq!(intent.destination, "zs-reviewed");
        assert_eq!(intent.network, ZeckNetwork::Mainnet);
    }

    #[test]
    fn sprout_intent_is_one_shot() {
        let store = ReviewedIntentStore::default();
        let id = proposal(
            &store,
            SproutIntentSource::Wallet("wallet-a".into()),
            "zs-reviewed",
        );
        assert!(store.take_proposal(&id).is_ok());
        assert!(store.take_proposal(&id).is_err());
    }

    #[test]
    fn wrong_execution_route_cannot_consume_a_proposal() {
        let store = ReviewedIntentStore::default();
        let id = proposal(
            &store,
            SproutIntentSource::Wallet("wallet-a".into()),
            "zs-reviewed",
        );
        assert!(store.take_scan_proposal(&id).is_err());
        assert!(store.take_wallet_proposal(&id).is_ok());
    }

    #[test]
    fn newer_review_revokes_the_same_source() {
        let store = ReviewedIntentStore::default();
        let first = proposal(
            &store,
            SproutIntentSource::Wallet("wallet-a".into()),
            "zs-first",
        );
        let second = proposal(
            &store,
            SproutIntentSource::Wallet("wallet-a".into()),
            "zs-second",
        );
        assert!(store.take_proposal(&first).is_err());
        assert_eq!(
            store.take_proposal(&second).unwrap().destination,
            "zs-second"
        );
    }

    #[test]
    fn a_scan_handle_is_required_to_propose_a_scan_sweep() {
        let store = ReviewedIntentStore::default();
        let absent = SproutScanHandle("absent".into());
        assert!(store.scan_material(&absent).is_err());
        assert!(store
            .insert_proposal(
                SproutSweepIntent {
                    source: SproutIntentSource::Scan(absent),
                    notes: Vec::new(),
                    destination: "zs-reviewed".into(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: "https://node-a".into(),
                    journal: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000
                }
            )
            .is_err());
    }

    #[test]
    fn scan_a_result_cannot_be_swept_under_scan_b() {
        let store = ReviewedIntentStore::default();
        let a = scan(&store, 1);
        let b = scan(&store, 2);
        let id = proposal(&store, SproutIntentSource::Scan(a.clone()), "zs-reviewed");
        assert_ne!(
            store.scan_material(&a).unwrap().key_fingerprint,
            store.scan_material(&b).unwrap().key_fingerprint
        );
        store.release_scan(&a).unwrap();
        assert!(store.take_proposal(&id).is_err());
        assert!(store.scan_material(&b).is_ok());
    }

    #[test]
    fn sprout_review_store_is_bounded() {
        let store = ReviewedIntentStore::default();
        for i in 0..MAX_SCAN_SESSIONS {
            scan(&store, i as u8);
        }
        assert!(store
            .insert_scan(
                vec![[99; 32]],
                "overflow".into(),
                PathBuf::from("/tmp/overflow"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new()
            )
            .is_err());
        for i in 0..MAX_PROPOSALS {
            proposal(
                &store,
                SproutIntentSource::Wallet(format!("wallet-{i}")),
                "zs-reviewed",
            );
        }
        assert!(store
            .insert_proposal(
                SproutSweepIntent {
                    source: SproutIntentSource::Wallet("overflow".into()),
                    notes: Vec::new(),
                    destination: "zs-reviewed".into(),
                    network: ZeckNetwork::Mainnet,
                    lightwalletd_url: "https://node".into(),
                    journal: None,
                },
                SproutSweepPreviewData {
                    notes: 1,
                    gross_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    net_zatoshis: 90_000
                }
            )
            .is_err());
    }

    #[test]
    fn released_running_scans_still_count_until_they_stop() {
        let store = ReviewedIntentStore::default();
        let mut handles = Vec::new();
        for i in 0..MAX_SCAN_SESSIONS {
            let handle = store
                .insert_scan(
                    vec![[i as u8; 32]],
                    format!("fingerprint-{i}"),
                    PathBuf::from(format!("/tmp/scan-{i}")),
                    ZeckNetwork::Mainnet,
                    "https://node".into(),
                    Vec::new(),
                )
                .unwrap();
            store.release_scan(&handle).unwrap();
            assert!(store.snapshot(&handle).is_err());
            handles.push(handle);
        }
        assert!(store
            .insert_scan(
                vec![[99; 32]],
                "overflow".into(),
                PathBuf::from("/tmp/overflow"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new()
            )
            .is_err());
        store.finish_scan(&handles[0], Err("stopped".into()));
        assert!(store
            .insert_scan(
                vec![[99; 32]],
                "replacement".into(),
                PathBuf::from("/tmp/replacement"),
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new()
            )
            .is_ok());
    }

    #[test]
    fn release_drops_scan_and_proposal_authority() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let id = proposal(
            &store,
            SproutIntentSource::Scan(handle.clone()),
            "zs-reviewed",
        );
        store.release_scan(&handle).unwrap();
        assert!(store.snapshot(&handle).is_err());
        assert!(store.take_proposal(&id).is_err());
        let wallet = proposal(
            &store,
            SproutIntentSource::Wallet("wallet-a".into()),
            "zs-reviewed",
        );
        store.release_proposal(&wallet).unwrap();
        assert!(store.take_proposal(&wallet).is_err());
    }

    #[test]
    fn sprout_progress_is_tagged_with_its_handle() {
        let store = ReviewedIntentStore::default();
        let handle = scan(&store, 1);
        let value = serde_json::to_value(SproutScanProgressEvent {
            handle: handle.clone(),
            height: 50,
            target: 100,
            notes_found: 1,
            joinsplits_seen: 2,
            peer_wait: None,
        })
        .unwrap();
        assert_eq!(value["handle"], handle.0);
        assert_eq!(value["height"], 50);
    }
}
