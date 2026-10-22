use std::collections::HashSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::TxId;

use crate::{
    error::ZeckResult,
    models::{canonical_confirmation_operator_id, normalized_confirmation_authority},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxObservationState {
    /// An independent pair of operators agree on the block and height.
    Mined,
    /// Block evidence from one operator only, with no source disagreeing.
    MinedSingleSource,
    PresentUnmined,
    Absent,
    Reorged,
    Contested,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointTxEvidence {
    pub operator_id: String,
    pub endpoint: String,
    pub tip_height: Option<u32>,
    pub reported_height: Option<u32>,
    pub block_hash: Option<Vec<u8>>,
    pub tx_in_block: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxObservation {
    pub state: TxObservationState,
    pub mined_height: Option<u32>,
    pub expiry_height: Option<u32>,
    pub primary_tip: Option<u32>,
    pub secondary_tip: Option<u32>,
    pub evidence: Vec<EndpointTxEvidence>,
}

/// Blocks past a transaction's expiry height before one source's report of
/// absence (from chain and mempool) is enough to mark it Expired.
///
/// An expired transaction can never be mined. A server that lies about the
/// absence can therefore at worst lead the user to rebuild a transaction
/// that spends the same inputs, and consensus rejects whichever of the two
/// arrives second; the destination is fixed by the reviewed request, so no
/// value can be redirected. The margin absorbs ordinary tip skew and a short
/// reorg around the expiry height, which is why a single configured source
/// suffices.
pub const EXPIRY_MARGIN_BLOCKS: u32 = 20;

/// Confirmations a corroborated (independent-pair) Mined transaction needs
/// before Argos tells the user the source keys may be discarded.
pub const MIN_DISCARD_CONFIRMATIONS: u32 = 10;

fn independent_evidence_sources(a: &EndpointTxEvidence, b: &EndpointTxEvidence) -> bool {
    let a_operator = canonical_confirmation_operator_id(&a.operator_id, &a.endpoint);
    let b_operator = canonical_confirmation_operator_id(&b.operator_id, &b.endpoint);
    if a_operator.is_empty() || b_operator.is_empty() || a_operator == b_operator {
        return false;
    }
    let (Some(a_authority), Some(b_authority)) = (
        normalized_confirmation_authority(&a.endpoint),
        normalized_confirmation_authority(&b.endpoint),
    ) else {
        return false;
    };
    a_authority != b_authority
}

fn has_independent_pair(evidence: &[&EndpointTxEvidence]) -> bool {
    evidence.iter().enumerate().any(|(index, first)| {
        evidence
            .iter()
            .skip(index + 1)
            .any(|second| independent_evidence_sources(first, second))
    })
}

impl TxObservation {
    /// Corroborated mining: an independent pair agree, and the evidence
    /// re-derives the same state and height.
    pub fn has_canonical_mined_evidence(&self) -> bool {
        self.state == TxObservationState::Mined && self.rederives_own_state()
    }

    /// Mining reported by one operator only. Resolved for continuing a
    /// recovery, never for telling the user to discard the source keys.
    pub fn has_single_source_mined_evidence(&self) -> bool {
        self.state == TxObservationState::MinedSingleSource && self.rederives_own_state()
    }

    pub fn state_is_mined(&self) -> bool {
        matches!(
            self.state,
            TxObservationState::Mined | TxObservationState::MinedSingleSource
        )
    }

    fn rederives_own_state(&self) -> bool {
        let recomputed = observe_transaction(self.evidence.clone(), self.expiry_height);
        self.mined_height.is_some()
            && recomputed.state == self.state
            && recomputed.mined_height == self.mined_height
    }

    /// Confirmations of a mined transaction according to the least advanced
    /// source that reported its block.
    pub fn confirmations(&self) -> Option<u32> {
        let height = self.mined_height?;
        self.evidence
            .iter()
            .filter(|item| item.tx_in_block && item.reported_height == Some(height))
            .filter_map(|item| item.tip_height)
            .map(|tip| tip.saturating_sub(height).saturating_add(1))
            .min()
    }

    /// Corroborated, and deep enough that a reorg is no longer a practical
    /// concern. Only this permits a "safe to discard the source" message.
    pub fn is_safe_to_discard(&self) -> bool {
        self.has_canonical_mined_evidence()
            && self
                .confirmations()
                .is_some_and(|depth| depth >= MIN_DISCARD_CONFIRMATIONS)
    }

    /// Any configured source reporting the transaction absent from chain and
    /// mempool at a tip strictly above `expiry_height + EXPIRY_MARGIN_BLOCKS`,
    /// with no source reporting it present. See [`EXPIRY_MARGIN_BLOCKS`] for
    /// why one source suffices. An expiry height of zero means the
    /// transaction never expires.
    pub fn is_expired(&self) -> bool {
        if self.state != TxObservationState::Absent || self.mined_height.is_some() {
            return false;
        }
        let Some(expiry_height) = self.expiry_height.filter(|height| *height != 0) else {
            return false;
        };
        if self.evidence.iter().any(|item| {
            item.tx_in_block || item.reported_height.is_some() || item.block_hash.is_some()
        }) {
            return false;
        }
        let threshold = expiry_height.saturating_add(EXPIRY_MARGIN_BLOCKS);
        self.evidence.iter().any(|item| {
            normalized_confirmation_authority(&item.endpoint).is_some()
                && item.tip_height.is_some_and(|tip| tip > threshold)
        })
    }
}

/// Reduce independently labelled lightwalletd observations. A missing height
/// with a known tip means the transaction was absent; a missing tip means the
/// source could not give usable evidence. `u32::MAX` is reserved for the
/// lightwalletd `u64::MAX` orphaned-transaction sentinel.
pub fn observe_transaction(
    evidence: Vec<EndpointTxEvidence>,
    expiry_height: Option<u32>,
) -> TxObservation {
    let evidence = evidence
        .into_iter()
        .map(|mut item| {
            item.operator_id =
                canonical_confirmation_operator_id(&item.operator_id, &item.endpoint);
            item
        })
        .collect::<Vec<_>>();
    let primary_tip = evidence.first().and_then(|item| item.tip_height);
    let secondary_tip = evidence.get(1).and_then(|item| item.tip_height);
    let mut claims: Vec<&EndpointTxEvidence> = Vec::new();
    let mut reported_heights = HashSet::new();
    let mut absent_sources = Vec::new();
    let mut any_absent = false;
    let mut present_unmined = false;
    let mut reorged = false;
    let mut contested = false;
    let mut claimed_height = false;
    for item in &evidence {
        match item.reported_height {
            Some(u32::MAX) => reorged = true,
            Some(0) => present_unmined = true,
            Some(height) => {
                claimed_height = true;
                reported_heights.insert(height);
                if item
                    .block_hash
                    .as_deref()
                    .is_some_and(|hash| hash.len() == 32)
                {
                    if item.tx_in_block {
                        if normalized_confirmation_authority(&item.endpoint).is_some() {
                            claims.push(item);
                        }
                    } else {
                        contested = true;
                    }
                }
            }
            None if item.tip_height.is_some() => {
                any_absent = true;
                if normalized_confirmation_authority(&item.endpoint).is_some() {
                    absent_sources.push(item);
                }
            }
            None => {}
        }
    }
    if let Some(first) = claims.first() {
        if claims.iter().any(|other| {
            other.reported_height != first.reported_height || other.block_hash != first.block_hash
        }) || present_unmined
            || any_absent
        {
            contested = true;
        }
    }
    if reported_heights.len() > 1 {
        contested = true;
    }
    // One source's orphan sentinel against sources that still place the
    // transaction in a block is a disagreement, not a positive reorg.
    if reorged && !claims.is_empty() {
        contested = true;
    }
    let (state, mined_height) = if contested {
        (TxObservationState::Contested, None)
    } else if reorged {
        (TxObservationState::Reorged, None)
    } else if has_independent_pair(&claims) {
        (
            TxObservationState::Mined,
            claims.first().and_then(|item| item.reported_height),
        )
    } else if !claims.is_empty() {
        (
            TxObservationState::MinedSingleSource,
            claims.first().and_then(|item| item.reported_height),
        )
    } else if claimed_height {
        (TxObservationState::Unavailable, None)
    } else if present_unmined {
        (TxObservationState::PresentUnmined, None)
    } else if !absent_sources.is_empty() {
        (TxObservationState::Absent, None)
    } else {
        (TxObservationState::Unavailable, None)
    };
    TxObservation {
        state,
        mined_height,
        expiry_height,
        primary_tip,
        secondary_tip,
        evidence,
    }
}

#[async_trait]
pub trait TxObserver {
    async fn observe(
        &mut self,
        network: crate::models::ZeckNetwork,
        txid: TxId,
        expiry_height: Option<u32>,
    ) -> ZeckResult<TxObservation>;
}
