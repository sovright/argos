//! NU7 activation and fresh, network-validated Sprout spending availability.
//!
//! This is an RPC evidence check, not independent consensus verification. The
//! spending coordinator repeats it before proving and before submitting bytes.
use std::time::Duration;

use serde::Serialize;
use tonic::transport::Channel;
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec, Empty, LightdInfo,
    },
};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};

use crate::{
    error::{ZeckError, ZeckResult},
    lightwalletd::{confirmation_endpoints, validate_lightwalletd_network},
    models::{ConfirmationEndpoint, ZeckNetwork},
    workspace::consensus_network,
};

pub const MAINNET_ACTIVATION_HEIGHT: u32 = 3_543_405;
pub const TESTNET_ACTIVATION_HEIGHT: u32 = 4_465_026;
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TIP_AGE: u64 = 30 * 60;
const MAX_FUTURE_TIME: u64 = 5 * 60;

pub fn activation_height(network: ZeckNetwork) -> Option<u32> {
    consensus_network(network)
        .activation_height(NetworkUpgrade::Nu7)
        .map(u32::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SproutAvailabilityState {
    BeforeActivation,
    Activated,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct SproutAvailability {
    pub state: SproutAvailabilityState,
    pub activation_height: u32,
    pub tip_height: Option<u32>,
    pub warning: String,
    pub allow_new_spends: bool,
}
impl SproutAvailability {
    pub fn allows_new_spends(&self) -> bool {
        self.allow_new_spends
    }

    pub fn unknown(network: ZeckNetwork, reason: impl std::fmt::Display) -> Self {
        Self { state: SproutAvailabilityState::Unknown, activation_height: activation_height(network).unwrap_or(0), tip_height: None, warning: format!("Cannot establish a fresh NU7 chain height: {reason}. New Sprout spending is disabled; keep your keys and recovery files."), allow_new_spends: false }
    }

    pub fn at_tip(network: ZeckNetwork, tip: u32) -> Self {
        let activation = activation_height(network);
        let activated = activation.is_some_and(|a| tip >= a);
        let allowed = activation.is_none_or(|a| tip.checked_add(1).is_some_and(|next| next < a));
        let warning = match activation {
            Some(a) if activated => format!("NU7 is active at height {a}. Sprout transactions cannot be mined under current rules. Historical inspection and transaction status remain available; retain your keys and recovery files."),
            Some(a) if !allowed => format!("The next block is NU7 activation height {a}; new Sprout transactions can no longer be mined. Historical inspection and transaction status remain available."),
            Some(a) => format!("Sprout spending ends at NU7 height {a}; the last valid mining height is {}. Current tip: {tip}. Inclusion before the deadline is not guaranteed.", a - 1),
            None => "No NU7 activation is configured on this local network.".to_owned(),
        };
        Self {
            state: if activated {
                SproutAvailabilityState::Activated
            } else {
                SproutAvailabilityState::BeforeActivation
            },
            activation_height: activation.unwrap_or(0),
            tip_height: Some(tip),
            warning,
            allow_new_spends: allowed,
        }
    }
}

fn evidence_error(message: impl Into<String>) -> ZeckError {
    ZeckError::Lightwalletd(message.into())
}

fn validate_tip_evidence(
    network: ZeckNetwork,
    info: &LightdInfo,
    latest: &BlockId,
    block: &CompactBlock,
    now: u64,
) -> ZeckResult<u32> {
    validate_lightwalletd_network(network, info)?;
    let height = u32::try_from(latest.height)
        .map_err(|_| evidence_error("tip height exceeds supported range"))?;
    if height == 0
        || block.height != latest.height
        || block.hash.len() != 32
        || latest.hash.len() != 32
        || block.hash != latest.hash
    {
        return Err(evidence_error("tip block height or hash is inconsistent"));
    }
    let branch = u32::from_str_radix(info.consensus_branch_id.trim().trim_start_matches("0x"), 16)
        .map_err(|_| evidence_error("missing or invalid server consensus branch"))?;
    let expected: u32 =
        BranchId::for_height(&consensus_network(network), BlockHeight::from_u32(height)).into();
    if branch != expected {
        return Err(evidence_error(
            "server consensus branch does not match tip height",
        ));
    }
    if info.block_height.abs_diff(latest.height) > 12 {
        return Err(evidence_error("server metadata and chain tip disagree"));
    }
    // Explicit process-local regtest setup permits artificially mined timestamps.
    #[cfg(feature = "argos-network")]
    let local_clock = matches!(network, ZeckNetwork::Testnet)
        && crate::workspace::regtest_consensus_params_installed();
    #[cfg(not(feature = "argos-network"))]
    let local_clock = false;
    let timestamp = u64::from(block.time);
    if !local_clock
        && (timestamp == 0
            || now.saturating_sub(timestamp) > MAX_TIP_AGE
            || timestamp.saturating_sub(now) > MAX_FUTURE_TIME)
    {
        return Err(evidence_error("tip timestamp is stale or in the future"));
    }
    Ok(height)
}

/// Check already-signed bytes against the next inclusion block after a freshly
/// validated tip. Never rebuild or rewrite a transaction to cross an upgrade.
pub(crate) fn validate_transaction_for_tip(
    network: ZeckNetwork,
    tip: u32,
    tx: &zcash_primitives::transaction::Transaction,
) -> ZeckResult<()> {
    let candidate = tip.checked_add(1).filter(|_| tip > 0).ok_or_else(|| {
        ZeckError::Broadcast("transaction submission requires a usable fresh chain tip".to_owned())
    })?;
    let params = consensus_network(network);
    let height = BlockHeight::from_u32(candidate);
    let branch = BranchId::for_height(&params, height);
    if !tx.version().valid_in_branch(branch) {
        return Err(ZeckError::Broadcast(format!(
            "signed transaction version is invalid for the next block's consensus branch {branch:?}; nothing was submitted"
        )));
    }
    if tx.consensus_branch_id() != branch {
        return Err(ZeckError::Broadcast(format!(
            "consensus branch changed after transaction construction: signed {:?}, next block {branch:?}; nothing was submitted",
            tx.consensus_branch_id()
        )));
    }
    let expiry = u32::from(tx.expiry_height());
    if expiry != 0 && tip >= expiry {
        return Err(ZeckError::Broadcast(format!(
            "signed transaction expired at height {expiry}; nothing was submitted"
        )));
    }
    crate::nu7_limits::validate_transaction(&params, height, tx)
}

/// Bounded check on the existing connection used for a Sprout operation.
pub async fn validated_tip_from_client(
    client: &mut CompactTxStreamerClient<Channel>,
    network: ZeckNetwork,
) -> ZeckResult<u32> {
    tokio::time::timeout(QUERY_TIMEOUT, async {
        let info = client
            .get_lightd_info(Empty {})
            .await
            .map_err(|e| evidence_error(e.to_string()))?
            .into_inner();
        validate_lightwalletd_network(network, &info)?;
        let latest = client
            .get_latest_block(ChainSpec {})
            .await
            .map_err(|e| evidence_error(e.to_string()))?
            .into_inner();
        let block = client
            .get_block(BlockId {
                height: latest.height,
                hash: vec![],
            })
            .await
            .map_err(|e| evidence_error(e.to_string()))?
            .into_inner();
        let now = u64::try_from(crate::unix_time_now())
            .map_err(|_| evidence_error("system clock is before the Unix epoch"))?;
        validate_tip_evidence(network, &info, &latest, &block, now)
    })
    .await
    .map_err(|_| evidence_error("fresh tip query timed out"))?
}

/// Query all configured authorities concurrently. A fresh activated observation
/// wins; conflicting preactivation heights fail closed. Failed sources are
/// disclosed, rather than silently treated as independent agreement.
pub async fn query_sprout_availability(
    network: ZeckNetwork,
    urls: &str,
    confirmations: &[ConfirmationEndpoint],
) -> SproutAvailability {
    let endpoints = match confirmation_endpoints(urls, confirmations) {
        Ok(e) if !e.is_empty() && e.len() <= 16 => e,
        Ok(_) => {
            return SproutAvailability::unknown(
                network,
                "configure between one and sixteen endpoints",
            )
        }
        Err(e) => return SproutAvailability::unknown(network, e),
    };
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in endpoints {
        tasks.spawn(async move {
            tokio::time::timeout(QUERY_TIMEOUT, async {
                let mut client = CompactTxStreamerClient::connect(endpoint.endpoint)
                    .await
                    .map_err(|e| evidence_error(e.to_string()))?;
                validated_tip_from_client(&mut client, network).await
            })
            .await
            .map_err(|_| evidence_error("endpoint query timed out"))?
        });
    }
    let mut heights = Vec::new();
    let mut failures = 0;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(h)) => heights.push(h),
            _ => failures += 1,
        }
    }
    let Some(&max) = heights.iter().max() else {
        return SproutAvailability::unknown(
            network,
            "no configured endpoint supplied usable evidence",
        );
    };
    if activation_height(network).is_none_or(|a| max < a)
        && heights.iter().any(|h| max.abs_diff(*h) > 12)
    {
        return SproutAvailability::unknown(
            network,
            "configured endpoints disagree on the chain height",
        );
    }
    let mut status = SproutAvailability::at_tip(network, max);
    if failures > 0 {
        status.warning.push_str(&format!(
            " {failures} configured endpoint(s) did not supply usable fresh evidence."
        ));
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_schedule_matches_sdk() {
        assert_eq!(
            activation_height(ZeckNetwork::Mainnet),
            Some(MAINNET_ACTIVATION_HEIGHT)
        );
        assert_eq!(
            activation_height(ZeckNetwork::Testnet),
            Some(TESTNET_ACTIVATION_HEIGHT)
        );
    }
    #[test]
    fn spending_requires_a_valid_next_block() {
        for network in [ZeckNetwork::Mainnet, ZeckNetwork::Testnet] {
            let a = activation_height(network).unwrap();
            assert!(SproutAvailability::at_tip(network, a - 2).allows_new_spends());
            let deadline = SproutAvailability::at_tip(network, a - 1);
            assert_eq!(deadline.state, SproutAvailabilityState::BeforeActivation);
            assert!(!deadline.allows_new_spends());
            assert_eq!(
                SproutAvailability::at_tip(network, a).state,
                SproutAvailabilityState::Activated
            );
            assert!(!SproutAvailability::at_tip(network, a).allows_new_spends());
            assert!(!SproutAvailability::unknown(network, "offline").allows_new_spends());
        }
    }
    fn signed_fixture(
        branch: BranchId,
        version: zcash_primitives::transaction::TxVersion,
        expiry: u32,
    ) -> zcash_primitives::transaction::Transaction {
        use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
        if version == TxVersion::V6 {
            TransactionData::<Authorized>::from_parts_v6(
                branch,
                0,
                BlockHeight::from_u32(expiry),
                None,
                None,
                None,
                None,
            )
            .freeze()
            .unwrap()
        } else {
            TransactionData::<Authorized>::from_parts(
                version,
                branch,
                0,
                BlockHeight::from_u32(expiry),
                None,
                None,
                None,
                None,
            )
            .freeze()
            .unwrap()
        }
    }

    #[test]
    fn signed_branch_must_still_match_after_proving_on_both_networks() {
        use zcash_primitives::transaction::TxVersion;
        for network in [ZeckNetwork::Mainnet, ZeckNetwork::Testnet] {
            let activation = activation_height(network).unwrap();
            for version in [TxVersion::V5, TxVersion::V6] {
                let tx = signed_fixture(BranchId::Nu6_3, version, activation + 120);
                let mut before = vec![];
                tx.write(&mut before).unwrap();
                assert!(validate_transaction_for_tip(network, activation - 2, &tx).is_ok());
                for tip in [activation - 1, activation, activation + 1] {
                    assert!(validate_transaction_for_tip(network, tip, &tx)
                        .unwrap_err()
                        .to_string()
                        .contains("branch"));
                }
                let mut after = vec![];
                tx.write(&mut after).unwrap();
                assert_eq!(
                    before, after,
                    "rejecting an obsolete branch preserves the signed evidence"
                );
                let current = signed_fixture(BranchId::Nu7, version, activation + 120);
                assert!(validate_transaction_for_tip(network, activation - 1, &current).is_ok());
                assert!(validate_transaction_for_tip(network, activation, &current).is_ok());
                assert!(validate_transaction_for_tip(network, activation + 1, &current).is_ok());
                assert!(
                    validate_transaction_for_tip(network, activation - 2, &current).is_err(),
                    "a reorg across activation also invalidates a new-branch signature"
                );
            }
            let legacy = signed_fixture(BranchId::Nu6_3, TxVersion::V4, activation + 120);
            assert!(validate_transaction_for_tip(network, activation - 1, &legacy).is_err());
        }
    }

    #[test]
    fn signed_expiry_and_unknown_tips_fail_before_submission() {
        use zcash_primitives::transaction::TxVersion;
        let activation = MAINNET_ACTIVATION_HEIGHT;
        let tx = signed_fixture(BranchId::Nu7, TxVersion::V6, activation + 5);
        assert!(validate_transaction_for_tip(ZeckNetwork::Mainnet, activation + 4, &tx).is_ok());
        assert!(
            validate_transaction_for_tip(ZeckNetwork::Mainnet, activation + 5, &tx)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert!(validate_transaction_for_tip(ZeckNetwork::Mainnet, 0, &tx).is_err());
        assert!(validate_transaction_for_tip(ZeckNetwork::Mainnet, u32::MAX, &tx).is_err());
        let no_expiry = signed_fixture(BranchId::Nu7, TxVersion::V6, 0);
        assert!(
            validate_transaction_for_tip(ZeckNetwork::Mainnet, activation + 5, &no_expiry).is_ok()
        );
    }

    fn fixture() -> (LightdInfo, BlockId, CompactBlock, u64) {
        let height = MAINNET_ACTIVATION_HEIGHT - 10;
        let now = 1_800_000_000;
        let branch: u32 = BranchId::for_height(
            &consensus_network(ZeckNetwork::Mainnet),
            BlockHeight::from_u32(height),
        )
        .into();
        (
            LightdInfo {
                chain_name: "main".into(),
                sapling_activation_height: 419_200,
                consensus_branch_id: format!("{branch:08x}"),
                block_height: u64::from(height),
                ..Default::default()
            },
            BlockId {
                height: u64::from(height),
                hash: vec![7; 32],
            },
            CompactBlock {
                height: u64::from(height),
                hash: vec![7; 32],
                time: now as u32,
                ..Default::default()
            },
            now,
        )
    }
    #[test]
    fn fresh_tip_rejects_stale_wrong_network_branch_and_hash() {
        let (info, latest, block, now) = fixture();
        assert!(validate_tip_evidence(ZeckNetwork::Mainnet, &info, &latest, &block, now).is_ok());
        assert!(validate_tip_evidence(
            ZeckNetwork::Mainnet,
            &info,
            &latest,
            &block,
            now + MAX_TIP_AGE + 1
        )
        .is_err());
        assert!(validate_tip_evidence(ZeckNetwork::Testnet, &info, &latest, &block, now).is_err());
        let mut bad = info.clone();
        bad.consensus_branch_id = "ffffffff".into();
        assert!(validate_tip_evidence(ZeckNetwork::Mainnet, &bad, &latest, &block, now).is_err());
        let mut bad = block.clone();
        bad.hash[0] ^= 1;
        assert!(validate_tip_evidence(ZeckNetwork::Mainnet, &info, &latest, &bad, now).is_err());
        let mut bad = block;
        bad.time = (now + MAX_FUTURE_TIME + 1) as u32;
        assert!(validate_tip_evidence(ZeckNetwork::Mainnet, &info, &latest, &bad, now).is_err());
    }
}
