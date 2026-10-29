//! ZIP 218 transaction limits and lossless batching of recovery proposals.
//!
//! The consensus limits apply to blocks; a transaction must fit by itself.
//! Counts include builder padding, and transparent inputs do not consume this budget.
use nonempty::NonEmpty;
#[allow(deprecated)]
use zcash_client_backend::zip321;
use zcash_client_backend::{
    fees::{StandardFeeRule, TransactionBalance},
    proposal::{Proposal, ShieldedInputs, Step},
};
use zcash_primitives::transaction::{
    builder::BundlePadding, components::orchard::bundle_version_for_branch, fees::FeeRule,
    Transaction,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters},
    value::Zatoshis,
    PoolType,
};

use crate::error::{ZeckError, ZeckResult};

pub const SAPLING_IO_LIMIT: usize = 300;
pub const ORCHARD_ACTION_LIMIT: usize = 330;
pub const GLOBAL_SHIELDED_LIMIT: usize = 330;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ShieldedCounts {
    pub sapling_spends: usize,
    pub sapling_outputs: usize,
    pub orchard: usize,
    pub ironwood: usize,
    pub joinsplits: usize,
}

impl ShieldedCounts {
    fn validate(self) -> ZeckResult<()> {
        let sapling = self.sapling_spends.checked_add(self.sapling_outputs);
        let total = sapling
            .and_then(|n| n.checked_add(self.orchard))
            .and_then(|n| n.checked_add(self.ironwood))
            .and_then(|n| {
                self.joinsplits
                    .checked_mul(2)
                    .and_then(|j| n.checked_add(j))
            });
        if sapling.is_none_or(|n| n > SAPLING_IO_LIMIT)
            || self.orchard > ORCHARD_ACTION_LIMIT
            || self.ironwood > ORCHARD_ACTION_LIMIT
            || self.joinsplits != 0
            || total.is_none_or(|n| n > GLOBAL_SHIELDED_LIMIT)
        {
            return Err(ZeckError::TransactionBuild(format!(
                "transaction exceeds the NU7 ZIP 218 shielded budget: {self:?}"
            )));
        }
        Ok(())
    }
}

fn build_error(error: impl std::fmt::Display) -> ZeckError {
    ZeckError::TransactionBuild(format!("planning bounded recovery: {error}"))
}

fn counts<P: Parameters, N>(
    params: &P,
    height: BlockHeight,
    step: &Step<N>,
) -> ZeckResult<ShieldedCounts> {
    let spends = step.input_count_in_pool(PoolType::SAPLING);
    let outputs =
        step.output_count_in_pool(PoolType::SAPLING) + step.change_count_in_pool(PoolType::SAPLING);
    let sapling = sapling_crypto::builder::BundleType::DEFAULT;
    let branch = BranchId::for_height(params, height);
    let orchard = bundle_version_for_branch(branch, orchard::ValuePool::Orchard)
        .map(|version| step.orchard_action_count(BundlePadding::DEFAULT, version))
        .transpose()
        .map_err(build_error)?
        .unwrap_or(0);
    let ironwood = bundle_version_for_branch(branch, orchard::ValuePool::Ironwood)
        .map(|version| step.ironwood_action_count(step.ironwood_bundle_padding(), version))
        .transpose()
        .map_err(build_error)?
        .unwrap_or(0);
    Ok(ShieldedCounts {
        sapling_spends: sapling.num_spends(spends).map_err(build_error)?,
        sapling_outputs: sapling.num_outputs(spends, outputs).map_err(build_error)?,
        orchard,
        ironwood,
        joinsplits: 0,
    })
}

pub(crate) fn validate_proposal<P: Parameters, N>(
    params: &P,
    proposal: &Proposal<StandardFeeRule, N>,
) -> ZeckResult<()> {
    let height = BlockHeight::from(proposal.min_target_height());
    if params.is_nu_active(NetworkUpgrade::Nu7, height) {
        for step in proposal.steps() {
            counts(params, height, step)?.validate()?;
        }
    }
    Ok(())
}

/// Validate actual serialized bundle sizes, independently of proposal estimates.
pub(crate) fn validate_transaction<P: Parameters>(
    params: &P,
    target_height: BlockHeight,
    tx: &Transaction,
) -> ZeckResult<()> {
    if !params.is_nu_active(NetworkUpgrade::Nu7, target_height) {
        return Ok(());
    }
    ShieldedCounts {
        sapling_spends: tx.sapling_bundle().map_or(0, |b| b.shielded_spends().len()),
        sapling_outputs: tx
            .sapling_bundle()
            .map_or(0, |b| b.shielded_outputs().len()),
        orchard: tx.orchard_bundle().map_or(0, |b| b.actions().len()),
        ironwood: tx.ironwood_bundle().map_or(0, |b| b.actions().len()),
        joinsplits: tx.sprout_bundle().map_or(0, |b| b.joinsplits.len()),
    }
    .validate()
}

/// Materialize one independent step for a PCZT builder (which accepts one step).
/// Refuse chained proposals, whose references cannot survive extraction.
pub(crate) fn independent_step<N: Clone>(
    proposal: &Proposal<StandardFeeRule, N>,
    index: usize,
) -> ZeckResult<Proposal<StandardFeeRule, N>> {
    let step = proposal
        .steps()
        .get(index)
        .ok_or_else(|| build_error("missing recovery batch"))?;
    if !step.prior_step_inputs().is_empty() {
        return Err(build_error(
            "recovery batch depends on an earlier transaction",
        ));
    }
    Proposal::multi_step(
        *proposal.fee_rule(),
        proposal.min_target_height(),
        proposal.confirmations_policy(),
        NonEmpty::singleton(step.clone()),
    )
    .map(|p| p.with_proposed_version(proposal.proposed_version()))
    .map_err(build_error)
}

/// Split a send-max proposal into disjoint, independently spendable transactions.
/// Every selected note is retained. The quoted fee is the sum of all batch fees.
/// Splitting is only required at NU7, and never imposes a transparent-input cap.
/// Send-max has no change; an optional donation is apportioned from the reduced
/// net amount after the additional transaction fees, preserving its fraction.
pub(crate) fn bound_send_max<P: Parameters, N: Clone>(
    params: &P,
    proposal: Proposal<StandardFeeRule, N>,
) -> ZeckResult<Proposal<StandardFeeRule, N>> {
    let height = BlockHeight::from(proposal.min_target_height());
    if !params.is_nu_active(NetworkUpgrade::Nu7, height)
        || validate_proposal(params, &proposal).is_ok()
    {
        return Ok(proposal);
    }
    let original = proposal.steps().first();
    if proposal.steps().len() != 1
        || !original.transparent_inputs().is_empty()
        || !original.prior_step_inputs().is_empty()
        || !original.balance().proposed_change().is_empty()
        || original.transaction_request().payments().is_empty()
        || original.transaction_request().payments().len() > 2
    {
        return Err(build_error(
            "oversized recovery proposal is not an independent send-max",
        ));
    }
    let notes = original
        .shielded_inputs()
        .ok_or_else(|| build_error("send-max has no selected notes"))?
        .notes();
    // A batch with 298 notes plus the mandatory two Sapling outputs fits the
    // Sapling budget. Other pools' padded outputs still fit the global budget.
    // Balance batch lengths to avoid leaving an uneconomic one-note tail.
    let batch_count = notes.len().div_ceil(SAPLING_IO_LIMIT - 2);
    let batch_size = notes.len() / batch_count;
    let larger_batches = notes.len() % batch_count;
    let payments: Vec<_> = original.transaction_request().payments().values().collect();
    let original_net: u64 = payments.iter().try_fold(0u64, |sum, p| {
        sum.checked_add(u64::from(
            p.amount()
                .ok_or_else(|| build_error("payment has no amount"))?,
        ))
        .ok_or_else(|| build_error("payment amount overflow"))
    })?;
    if original_net == 0 {
        return Err(build_error("send-max payment amount is zero"));
    }
    // Distribute fee-paying value, not just note counts. Contiguous chunks
    // can strand near-marginal notes in a batch with no value for output
    // padding even when the complete wallet can pay every batch's fees.
    // Stable value ordering and index tie-breaks make review deterministic.
    let mut notes: Vec<_> = notes.iter().cloned().collect();
    notes.sort_by_key(|note| std::cmp::Reverse(u64::from(note.note().value())));
    let mut batches = vec![Vec::new(); batch_count];
    let mut available = std::collections::BinaryHeap::new();
    for index in 0..batch_count {
        available.push(std::cmp::Reverse((0u64, 0usize, index)));
    }
    for note in notes {
        let std::cmp::Reverse((surplus, count, index)) = available
            .pop()
            .expect("batch capacity covers every selected note");
        let surplus = surplus
            .checked_add(u64::from(note.note().value()).saturating_sub(5_000))
            .ok_or_else(|| build_error("batch fee-paying value overflow"))?;
        batches[index].push(note);
        let capacity = batch_size + usize::from(index < larger_batches);
        if count + 1 < capacity {
            available.push(std::cmp::Reverse((surplus, count + 1, index)));
        }
    }
    let mut steps = Vec::new();
    for chunk in batches {
        let inputs =
            ShieldedInputs::from_parts(NonEmpty::from_vec(chunk.clone()).expect("nonempty chunk"));
        let gross: u64 = chunk.iter().try_fold(0u64, |sum, n| {
            sum.checked_add(u64::from(n.note().value()))
                .ok_or_else(|| build_error("input value overflow"))
        })?;
        // A balanced candidate preserves the recipient/pool structure, letting
        // the SDK count version-specific padding before computing the real fee.
        let make_step = |fee: Zatoshis| -> ZeckResult<Step<N>> {
            let net = gross
                .checked_sub(u64::from(fee))
                .filter(|n| *n > 0)
                .ok_or_else(|| build_error("recovery batch does not cover its ZIP 317 fee"))?;
            let mut remaining = net;
            let mut batch_payments = Vec::new();
            for (i, payment) in payments.iter().enumerate() {
                let amount = if i + 1 == payments.len() {
                    remaining
                } else {
                    ((u128::from(net)
                        * u128::from(u64::from(payment.amount().expect("checked amount"))))
                        / u128::from(original_net)) as u64
                };
                remaining -= amount;
                batch_payments.push(
                    zip321::Payment::new(
                        payment.recipient_address().clone(),
                        Some(Zatoshis::from_u64(amount).map_err(build_error)?),
                        payment.memo().cloned(),
                        payment.label().cloned(),
                        payment.message().cloned(),
                        payment.other_params().to_vec(),
                    )
                    .map_err(build_error)?,
                );
            }
            Step::from_parts(
                &[],
                zip321::TransactionRequest::new(batch_payments).map_err(build_error)?,
                original.payment_pools().clone(),
                vec![],
                Some(inputs.clone()),
                original.anchor_height(),
                vec![],
                TransactionBalance::new(vec![], fee).map_err(build_error)?,
                false,
                params.is_nu_active(NetworkUpgrade::Nu6_3, height),
            )
            .map_err(build_error)
        };
        let candidate = make_step(Zatoshis::ZERO)?;
        let count = counts(params, height, &candidate)?;
        count.validate()?;
        let fee = proposal
            .fee_rule()
            .fee_required(
                params,
                height,
                [],
                [],
                count.sapling_spends,
                count.sapling_outputs,
                count.orchard,
                count.ironwood,
            )
            .map_err(build_error)?;
        steps.push(make_step(fee)?);
    }
    let bounded = Proposal::multi_step(
        *proposal.fee_rule(),
        proposal.min_target_height(),
        proposal.confirmations_policy(),
        NonEmpty::from_vec(steps).expect("selected notes"),
    )
    .map_err(build_error)?
    .with_proposed_version(proposal.proposed_version());
    validate_proposal(params, &bounded)?;
    Ok(bounded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sapling_proposal(note_count: usize, height: BlockHeight) -> Proposal<StandardFeeRule, u32> {
        sapling_values_proposal(&vec![100_000; note_count], height, None)
    }

    fn sapling_values_proposal(
        values: &[u64],
        height: BlockHeight,
        destination: Option<zcash_address::ZcashAddress>,
    ) -> Proposal<StandardFeeRule, u32> {
        let note_count = values.len();
        use zcash_client_backend::{
            data_api::wallet::ConfirmationsPolicy,
            wallet::{Note, ReceivedNote},
        };
        let key = sapling_crypto::zip32::ExtendedSpendingKey::master(&[7; 32]).unwrap();
        let (_, address) = key.default_address();
        let recipient = zcash_address::ZcashAddress::try_from_encoded(
            &zcash_keys::encoding::encode_payment_address(
                zcash_address::constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                &address,
            ),
        )
        .unwrap();
        let recipient = destination.unwrap_or(recipient);
        let output_pool = if recipient.can_receive_as(PoolType::ORCHARD) {
            PoolType::IRONWOOD
        } else {
            PoolType::SAPLING
        };
        let notes: Vec<_> = (0..note_count)
            .map(|i| {
                ReceivedNote::from_parts(
                    i as u32,
                    zcash_primitives::transaction::TxId::from_bytes([9; 32]),
                    i as u16,
                    Note::Sapling(sapling_crypto::Note::from_parts(
                        address,
                        sapling_crypto::value::NoteValue::from_raw(values[i]),
                        sapling_crypto::Rseed::AfterZip212([3; 32]),
                    )),
                    zip32::Scope::External,
                    (i as u64).into(),
                    Some(height - 10),
                    None,
                )
            })
            .collect();
        let fee = 5_000
            * (note_count.max(2) as u64
                + if output_pool == PoolType::IRONWOOD {
                    2
                } else {
                    0
                });
        let request = zip321::TransactionRequest::new(vec![zip321::Payment::new(
            recipient,
            Some(Zatoshis::from_u64(values.iter().sum::<u64>() - fee).unwrap()),
            Some(zcash_protocol::memo::MemoBytes::empty()),
            None,
            None,
            vec![],
        )
        .unwrap()])
        .unwrap();
        Proposal::single_step(
            request,
            [(0, output_pool)].into(),
            vec![],
            Some(ShieldedInputs::from_parts(
                NonEmpty::from_vec(notes).unwrap(),
            )),
            height - 3,
            TransactionBalance::new(vec![], Zatoshis::from_u64(fee).unwrap()).unwrap(),
            StandardFeeRule::Zip317,
            height.into(),
            ConfirmationsPolicy::MIN,
            false,
            true,
        )
        .unwrap()
    }

    #[test]
    fn large_recovery_retains_every_input_and_prices_every_batch() {
        let params = zcash_protocol::consensus::MAIN_NETWORK;
        let height = params.activation_height(NetworkUpgrade::Nu7).unwrap();
        let proposal = sapling_proposal(901, height);
        assert!(validate_proposal(&params, &proposal).is_err());
        let bounded = bound_send_max(&params, proposal).unwrap();
        assert_eq!(bounded.steps().len(), 4);
        validate_proposal(&params, &bounded).unwrap();
        let mut ids: Vec<_> = bounded
            .steps()
            .iter()
            .flat_map(|s| {
                s.shielded_inputs()
                    .unwrap()
                    .notes()
                    .iter()
                    .map(|n| *n.internal_note_id())
            })
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, (0..901).collect::<Vec<_>>());
        let mut total = 0u64;
        for (index, step) in bounded.steps().iter().enumerate() {
            let independent = independent_step(&bounded, index).unwrap();
            assert_eq!(independent.steps().len(), 1);
            let fee = u64::from(step.balance().fee_required());
            assert_eq!(
                fee,
                step.shielded_inputs().unwrap().notes().len() as u64 * 5_000
            );
            let payment = step.transaction_request().payments().get(&0).unwrap();
            assert!(payment.memo().is_some());
            total += u64::from(payment.amount().unwrap()) + fee;
        }
        assert_eq!(total, 901 * 100_000);
    }

    #[test]
    fn batching_distributes_value_to_pay_cross_pool_output_padding() {
        let params = zcash_protocol::consensus::MAIN_NETWORK;
        let height = params.activation_height(NetworkUpgrade::Nu7).unwrap();
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &params,
            &[11; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let recipient = usk
            .to_unified_full_viewing_key()
            .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .0;
        let recipient =
            zcash_address::ZcashAddress::try_from_encoded(&recipient.encode(&params)).unwrap();
        let mut values = vec![5_001; 299];
        values[0] = 100_000;
        values[1] = 100_000;
        let proposal = sapling_values_proposal(&values, height, Some(recipient));
        let bounded = bound_send_max(&params, proposal).unwrap();
        assert_eq!(bounded.steps().len(), 2);
        let mut accounted = 0;
        for step in bounded.steps() {
            assert_eq!(
                step.shielded_inputs()
                    .unwrap()
                    .notes()
                    .iter()
                    .filter(|n| u64::from(n.note().value()) == 100_000)
                    .count(),
                1
            );
            assert_eq!(step.payment_pools()[&0], PoolType::IRONWOOD);
            accounted += u64::from(step.transaction_request().payments()[&0].amount().unwrap())
                + u64::from(step.balance().fee_required());
        }
        assert_eq!(accounted, values.iter().sum::<u64>());
    }

    #[test]
    fn bounded_batches_preserve_donation_and_recipient_memos() {
        let params = zcash_protocol::consensus::MAIN_NETWORK;
        let height = params.activation_height(NetworkUpgrade::Nu7).unwrap();
        let template = sapling_proposal(901, height);
        let step = template.steps().first();
        let payment = step.transaction_request().payments().get(&0).unwrap();
        let net = u64::from(payment.amount().unwrap());
        let donation = net / 10;
        let make_payment = |amount| {
            zip321::Payment::new(
                payment.recipient_address().clone(),
                Some(Zatoshis::from_u64(amount).unwrap()),
                payment.memo().cloned(),
                None,
                None,
                vec![],
            )
            .unwrap()
        };
        let original = Proposal::single_step(
            zip321::TransactionRequest::new(vec![
                make_payment(donation),
                make_payment(net - donation),
            ])
            .unwrap(),
            [(0, PoolType::SAPLING), (1, PoolType::SAPLING)].into(),
            vec![],
            step.shielded_inputs().cloned(),
            step.anchor_height().unwrap(),
            step.balance().clone(),
            StandardFeeRule::Zip317,
            height.into(),
            template.confirmations_policy(),
            false,
            true,
        )
        .unwrap();
        let bounded = bound_send_max(&params, original).unwrap();
        let mut donated = 0;
        let mut delivered = 0;
        for step in bounded.steps() {
            let payments = step.transaction_request().payments();
            donated += u64::from(payments[&0].amount().unwrap());
            delivered += u64::from(payments[&1].amount().unwrap());
            assert_eq!(payments[&1].memo(), payment.memo());
            assert_eq!(
                payments[&1].recipient_address(),
                payment.recipient_address()
            );
        }
        assert_eq!(donated, donation);
        assert_eq!(
            donated + delivered + crate::service::proposal_fee_zatoshis(&bounded).unwrap(),
            901 * 100_000
        );
    }

    #[test]
    fn activation_boundary_changes_batching_without_dropping_notes() {
        let params = zcash_protocol::consensus::MAIN_NETWORK;
        let activation = params.activation_height(NetworkUpgrade::Nu7).unwrap();
        assert_eq!(
            bound_send_max(&params, sapling_proposal(299, activation - 1))
                .unwrap()
                .steps()
                .len(),
            1
        );
        assert_eq!(
            bound_send_max(&params, sapling_proposal(298, activation))
                .unwrap()
                .steps()
                .len(),
            1
        );
        assert_eq!(
            bound_send_max(&params, sapling_proposal(299, activation))
                .unwrap()
                .steps()
                .len(),
            2
        );
    }

    #[test]
    fn pool_and_combined_boundaries_include_padding() {
        assert!(ShieldedCounts {
            sapling_spends: 298,
            sapling_outputs: 2,
            ..Default::default()
        }
        .validate()
        .is_ok());
        assert!(ShieldedCounts {
            sapling_spends: 299,
            sapling_outputs: 2,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ShieldedCounts {
            orchard: 330,
            ..Default::default()
        }
        .validate()
        .is_ok());
        assert!(ShieldedCounts {
            orchard: 331,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ShieldedCounts {
            sapling_spends: 298,
            sapling_outputs: 2,
            orchard: 30,
            ..Default::default()
        }
        .validate()
        .is_ok());
        assert!(ShieldedCounts {
            sapling_spends: 298,
            sapling_outputs: 2,
            orchard: 31,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ShieldedCounts {
            orchard: 200,
            ironwood: 200,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ShieldedCounts {
            joinsplits: 1,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ShieldedCounts {
            sapling_spends: usize::MAX,
            sapling_outputs: 2,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
