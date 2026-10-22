//! Spending Sapling notes held by an imported wallet account.
//!
//! The ordinary sweep path cannot do this. `create_proposed_transactions`
//! resolves its account by looking up a [`UnifiedSpendingKey`]'s UFVK and
//! takes Sapling spend authority solely from that key
//! (`zcash_client_backend::data_api::wallet`), and a standalone `sapzkey`
//! recovered from a zcashd `wallet.dat` can form neither: it has no ZIP-32
//! derivation and no seed behind it.
//!
//! The PCZT roles have no such constraint. `create_pczt_from_proposal` is
//! driven by an account id rather than a spending key, and every use it
//! makes of the account's derivation is conditional — so an account created
//! with `AccountPurpose::Spending { derivation: None }` is supported. The
//! one thing that conditionality costs us is the Sapling key path, which
//! that function only populates when a derivation exists; without it the
//! Prover has no proof generation key. `LowLevelSigner::sign_sapling_with`
//! is the way to supply it, and is why the ordinary `Updater` is not
//! enough here.
//!
//! [`UnifiedSpendingKey`]: zcash_keys::keys::UnifiedSpendingKey
//!
//! Unreviewed sweep entrypoints are not part of the public API:
//!
//! ```compile_fail
//! use argos_core::imported_sweep::{sweep_imported_wallet, sweep_imported_filtered_wallet};
//! ```

// `low_level_signer::Signer` and `signer::Signer` are different roles with
// the same name; alias so which one is in use is never ambiguous.
use pczt::roles::{
    low_level_signer::Signer as LowLevelSigner, prover::Prover, signer::Signer,
    tx_extractor::TransactionExtractor,
};
use sapling_crypto as sapling;
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            input_selection::LockedInputPolicy, propose_send_max_transfer, ConfirmationsPolicy,
        },
        MaxSpendMode,
    },
    fees::StandardFeeRule,
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId};
use zcash_keys::keys::sapling::ExtendedSpendingKey;
use zcash_primitives::transaction::{builder::BundlePadding, Transaction};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::ShieldedPool;

use crate::error::{ZeckError, ZeckResult};
use crate::{
    broadcast::{
        submit_prepared_transaction, DurableBroadcastLog, LightwalletdSubmitter,
        PreparedTransaction, TxSubmissionResult,
    },
    models::{TxBroadcastResult, TxLifecycleState},
};

/// Builder inputs supplied by the service's validated post-sync plan.
#[derive(Clone, Default)]
pub(crate) struct ImportedExecutionPlan {
    pub sapling: std::collections::HashMap<
        AccountUuid,
        zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>,
    >,
    pub transparent: Option<(
        Vec<crate::transparent_recovery::TransparentUtxo>,
        crate::transparent_recovery::TransparentSweepPlan,
        u32,
    )>,
}

/// Errors from the proof-generation-key step.
///
/// `sign_sapling_with` requires the closure's error to absorb its own parse
/// failure, and the update itself fails differently, so the two are carried
/// together rather than flattened into a string at the point of failure.
#[derive(Debug)]
enum ProofKeyError {
    // Carried for its Debug rendering in the error message; never matched on.
    Parse(#[allow(dead_code)] pczt::sapling::ParseError),
    Update(#[allow(dead_code)] sapling::pczt::UpdaterError),
    MissingRecipient,
    UnknownRecipientScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaplingSpendScope {
    External,
    Internal,
}

fn classify_spend_scope(
    extsk: &ExtendedSpendingKey,
    recipient: Option<&sapling::PaymentAddress>,
) -> Result<SaplingSpendScope, ProofKeyError> {
    let recipient = recipient.ok_or(ProofKeyError::MissingRecipient)?;
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    // Compare recipients directly: sapling-crypto 0.7.0's decrypt_diversifier
    // checks the external key in its internal branch.
    if dfvk.diversified_address(*recipient.diversifier()).as_ref() == Some(recipient) {
        Ok(SaplingSpendScope::External)
    } else if dfvk
        .diversified_change_address(*recipient.diversifier())
        .as_ref()
        == Some(recipient)
    {
        Ok(SaplingSpendScope::Internal)
    } else {
        Err(ProofKeyError::UnknownRecipientScope)
    }
}

impl From<pczt::sapling::ParseError> for ProofKeyError {
    fn from(err: pczt::sapling::ParseError) -> Self {
        Self::Parse(err)
    }
}

/// Build, prove, sign, and extract a transaction spending every Sapling
/// note in an imported account.
///
/// Restricted to the Sapling pool deliberately, and not only because that
/// is all an imported zcashd wallet can hold: `create_pczt_from_proposal`
/// accepts single-step proposals only, and a multi-pool sweep is
/// multi-step. Transparent funds on the same account are recovered through
/// `transparent_recovery`, which needs no proposal at all.
///
/// Does not broadcast. The caller decides that, so a dry run and a real
/// sweep cannot diverge in how the transaction was built.
///
/// `max_fee_zatoshis` is the user's `--max-fee`, a cap on the whole sweep;
/// `prior_fee_zatoshis` is what this sweep's earlier transactions already
/// paid, and each gate checks the two together. It is enforced twice and
/// never after broadcast: once against the proposal, before any proving
/// work, and once against the fee actually encoded in the extracted
/// transaction. The second is the one that matters — the first is the
/// planner's own arithmetic restated, whereas the second reads what was
/// built.
pub(crate) fn propose_imported_sapling_sweep<P>(
    wallet_db: &mut crate::imported::ArgosWalletDb,
    params: &P,
    account_id: AccountUuid,
    destination: &ZcashAddress,
) -> ZeckResult<zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
{
    propose_send_max_transfer::<_, _, _, std::convert::Infallible>(
        wallet_db,
        params,
        account_id,
        &[ShieldedPool::Sapling],
        &StandardFeeRule::Zip317,
        destination.clone(),
        None,
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::MIN,
        &LockedInputPolicy::Exclude,
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("proposing the Sapling sweep: {err}")))
}

#[allow(clippy::too_many_arguments)]
pub fn build_imported_sapling_sweep<P>(
    wallet_db: &mut crate::imported::ArgosWalletDb,
    params: &P,
    account_id: AccountUuid,
    extsk: &ExtendedSpendingKey,
    destination: &ZcashAddress,
    prover: &LocalTxProver,
    max_fee_zatoshis: Option<u64>,
    prior_fee_zatoshis: u64,
) -> ZeckResult<Transaction>
where
    P: zcash_protocol::consensus::Parameters + Clone,
{
    build_imported_sapling_sweep_reviewed(
        wallet_db,
        params,
        account_id,
        extsk,
        destination,
        prover,
        max_fee_zatoshis,
        prior_fee_zatoshis,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_imported_sapling_sweep_reviewed<P>(
    wallet_db: &mut crate::imported::ArgosWalletDb,
    params: &P,
    account_id: AccountUuid,
    extsk: &ExtendedSpendingKey,
    destination: &ZcashAddress,
    prover: &LocalTxProver,
    max_fee_zatoshis: Option<u64>,
    prior_fee_zatoshis: u64,
    reviewed_fee_zatoshis: Option<u64>,
    planned_proposal: Option<
        &zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>,
    >,
) -> ZeckResult<Transaction>
where
    P: zcash_protocol::consensus::Parameters + Clone,
{
    // Cheapest possible refusal: a cap this low can never be met by any
    // Sapling sweep, whatever this account holds.
    enforce_sapling_fee_floor(max_fee_zatoshis)?;

    // The extractor verifies the proofs it just had made, so the verifying
    // keys come from the same parameters that produced them rather than
    // being passed in alongside and risking a mismatch.
    let (spend_vk, output_vk) = prover.verifying_keys();
    let proposal = if let Some(planned) = planned_proposal {
        planned.clone()
    } else {
        propose_imported_sapling_sweep(wallet_db, params, account_id, destination)?
    };

    // First gate, before proving parameters are put to work.
    let planned_fee_zatoshis = crate::service::proposal_fee_zatoshis(&proposal)?;
    if let Some(reviewed) = reviewed_fee_zatoshis {
        if reviewed != planned_fee_zatoshis {
            return Err(ZeckError::FeeQuoteChanged {
                reviewed,
                current: planned_fee_zatoshis,
            });
        }
    }
    enforce_cumulative_fee(prior_fee_zatoshis, planned_fee_zatoshis, max_fee_zatoshis)?;

    let pczt = zcash_client_backend::data_api::wallet::create_pczt_from_proposal::<
        _,
        _,
        std::convert::Infallible,
        _,
        std::convert::Infallible,
        _,
    >(
        wallet_db,
        params,
        account_id,
        OvkPolicy::Discard,
        &proposal,
        None,
        BundlePadding::DEFAULT,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating the PCZT: {err}")))?;

    // Supply the proof generation key the account's missing ZIP-32
    // derivation would otherwise have provided. Internal notes use the
    // account's derived internal nsk (ask is unchanged), so classify every PCZT recipient
    // through the DFVK and fail closed if it is missing or foreign.
    let internal_extsk = extsk.derive_internal();
    let mut spend_scopes = Vec::new();
    let pczt = LowLevelSigner::new(pczt)
        .sign_sapling_with(|_, bundle, _| {
            spend_scopes = bundle
                .spends()
                .iter()
                .map(|spend| classify_spend_scope(extsk, spend.recipient().as_ref()))
                .collect::<Result<Vec<_>, _>>()?;
            let proof_keys: Vec<_> = spend_scopes
                .iter()
                .map(|scope| match scope {
                    SaplingSpendScope::External => extsk.expsk.proof_generation_key(),
                    SaplingSpendScope::Internal => internal_extsk.expsk.proof_generation_key(),
                })
                .collect();
            bundle
                .update_with(|mut updater| {
                    for (index, pgk) in proof_keys.into_iter().enumerate() {
                        updater.update_spend_with(index, |mut spend| {
                            spend.set_proof_generation_key(pgk)
                        })?;
                    }
                    Ok(())
                })
                .map_err(ProofKeyError::Update)
        })
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("supplying the proof generation key: {err:?}"))
        })?
        .finish();

    // The proposal spends only Sapling, but the PCZT still carries padded
    // Orchard and Ironwood bundles — `BundlePadding::DEFAULT` fills them
    // with dummy actions, and on a chain past NU6.3 the Ironwood bundle
    // exists too. Every bundle present needs a proof or the extractor
    // fails with `MissingProof`, so ask the Prover what it needs rather
    // than assuming a Sapling-only spend implies a Sapling-only proof.
    let mut prover_role = Prover::new(pczt);
    if prover_role.requires_sapling_proofs() {
        prover_role = prover_role
            .create_sapling_proofs(prover, prover)
            .map_err(|err| {
                ZeckError::TransactionBuild(format!("proving the Sapling bundle: {err:?}"))
            })?;
    }
    let needs_orchard = prover_role.requires_orchard_proof();
    let needs_ironwood = prover_role.requires_ironwood_proof();

    // The Orchard and Ironwood bundles use different circuit versions, but
    // `TransactionExtractor` verifies both against a single Orchard
    // verifying key. A transaction carrying both would therefore need one
    // key to verify two circuits, which is not possible — refuse rather
    // than pick one and produce a transaction that fails verification for
    // a reason the caller cannot see. A Sapling-only proposal should never
    // produce both.
    if needs_orchard && needs_ironwood {
        return Err(ZeckError::TransactionBuild(
            "this sweep produced both an Orchard and an Ironwood bundle, which the PCZT \
             extractor cannot verify with a single verifying key"
                .to_owned(),
        ));
    }

    let circuit_version = if needs_ironwood {
        Some(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    } else if needs_orchard {
        Some(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2)
    } else {
        None
    };

    if let Some(version) = circuit_version {
        // Building this is expensive, so only when a bundle needs it.
        let orchard_pk = orchard::circuit::ProvingKey::build(version);
        prover_role = if needs_ironwood {
            prover_role
                .create_ironwood_proof(&orchard_pk)
                .map_err(|err| {
                    ZeckError::TransactionBuild(format!("proving the Ironwood bundle: {err:?}"))
                })?
        } else {
            prover_role
                .create_orchard_proof(&orchard_pk)
                .map_err(|err| {
                    ZeckError::TransactionBuild(format!("proving the Orchard bundle: {err:?}"))
                })?
        };
    }
    let pczt = prover_role.finish();

    // Count before `Signer::new` consumes the PCZT.
    let spend_count = pczt.sapling().spends().len();
    let mut signer = Signer::new(pczt)
        .map_err(|err| ZeckError::TransactionBuild(format!("preparing the signer: {err:?}")))?;
    for index in 0..spend_count {
        let ask = match spend_scopes.get(index) {
            Some(SaplingSpendScope::External) => &extsk.expsk.ask,
            Some(SaplingSpendScope::Internal) => &internal_extsk.expsk.ask,
            None => {
                return Err(ZeckError::TransactionBuild(format!(
                    "Sapling spend {index} has no verified recipient scope"
                )));
            }
        };
        signer.sign_sapling(index, ask).map_err(|err| {
            ZeckError::TransactionBuild(format!("signing Sapling spend {index}: {err:?}"))
        })?;
    }
    let pczt = signer.finish();

    // Must match the circuit the proof above was made with.
    let orchard_vk = orchard::circuit::VerifyingKey::build(
        circuit_version.unwrap_or(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2),
    );
    let tx = TransactionExtractor::new(pczt)
        .with_sapling(&spend_vk, &output_vk)
        .with_orchard(&orchard_vk)
        .extract()
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("extracting the signed transaction: {err:?}"))
        })?;

    // Second gate, on the fee the built transaction actually pays.
    //
    // `fee_paid` sums every bundle's value balance, so the ZIP-317 output
    // padding that bills one Sapling output as `MIN_SHIELDED_OUTPUTS` is
    // counted as it was built rather than as it was assumed — this is the
    // trap `BundleType::num_outputs` exists to avoid, sidestepped entirely
    // by measuring instead of predicting. Cross-checking it against the
    // proposal mirrors `transparent_recovery`, which refuses to sign when
    // its plan and the builder's `get_fee` disagree: two independent
    // computations of one number, and a mismatch means one is wrong.
    let actual_fee_zatoshis = transaction_fee_zatoshis(&tx)?;
    if actual_fee_zatoshis != planned_fee_zatoshis {
        return Err(ZeckError::Internal(format!(
            "the proposed fee {planned_fee_zatoshis} does not match the built transaction's \
             fee {actual_fee_zatoshis}; refusing to broadcast"
        )));
    }
    enforce_cumulative_fee(prior_fee_zatoshis, actual_fee_zatoshis, max_fee_zatoshis)?;

    Ok(tx)
}

/// `--max-fee` is a cap on the whole sweep, as on the HD route: refuse a
/// transaction whose fee would take what the sweep has paid so far over it.
/// Checking each transaction against the full cap on its own let a wallet
/// with several Sapling keys pay several times what the user set.
pub(crate) fn enforce_cumulative_fee(
    prior_fee_zatoshis: u64,
    next_fee_zatoshis: u64,
    max_fee_zatoshis: Option<u64>,
) -> ZeckResult<()> {
    let total = crate::service::checked_fee_total(prior_fee_zatoshis, next_fee_zatoshis)?;
    match max_fee_zatoshis {
        Some(cap) if total > cap => Err(ZeckError::MaxFeeExceeded(format!(
            "the next transaction's fee is {next_fee_zatoshis} zats and this sweep has \
             already paid {prior_fee_zatoshis}, so the total {total} would exceed the \
             {cap}-zat cap"
        ))),
        _ => Ok(()),
    }
}

/// Refuse a fee cap no Sapling sweep could ever satisfy.
///
/// A ZIP-317 shielded send costs at least the conventional fee floor, so a
/// cap below it is unsatisfiable regardless of what the account holds.
/// Checking it first turns a guaranteed failure into an immediate one,
/// before a wallet database is opened or proving parameters are loaded.
fn enforce_sapling_fee_floor(max_fee_zatoshis: Option<u64>) -> ZeckResult<()> {
    if let Some(max_fee_zatoshis) = max_fee_zatoshis {
        if max_fee_zatoshis < crate::service::MIN_SHIELDED_SEND_FEE_ZATOSHIS {
            return Err(ZeckError::MaxFeeExceeded(format!(
                "a Sapling sweep cannot cost less than the ZIP 317 fee floor of {} zats, \
                 so the requested limit of {max_fee_zatoshis} zats can never be met",
                crate::service::MIN_SHIELDED_SEND_FEE_ZATOSHIS
            )));
        }
    }
    Ok(())
}

/// The fee a built sweep transaction actually pays.
///
/// Read off the transaction rather than recomputed, so it cannot restate
/// the planner's assumptions back at it.
fn transaction_fee_zatoshis(tx: &Transaction) -> ZeckResult<u64> {
    // `fee_paid` needs the value of every transparent input, which only the
    // chain knows. This sweep spends Sapling notes exclusively, so there
    // should be no transparent bundle at all; if one appears, the fee is
    // unverifiable and the transaction must not be broadcast rather than be
    // waved through on an assumed value.
    if tx.transparent_bundle().is_some() {
        return Err(ZeckError::Internal(
            "the imported Sapling sweep produced a transparent bundle, whose fee cannot be \
             verified without the values of the outputs it spends; refusing to broadcast"
                .to_owned(),
        ));
    }

    let fee = tx
        .fee_paid::<zcash_protocol::value::BalanceError, _>(|_| Ok(None))
        .map_err(|err| ZeckError::Internal(format!("computing the built sweep's fee: {err:?}")))?
        .ok_or_else(|| {
            ZeckError::Internal(
                "the built sweep's fee could not be determined; refusing to broadcast".to_owned(),
            )
        })?;
    Ok(u64::from(fee))
}

/// What an imported-wallet sweep submitted or attempted to submit.
///
/// Both pools are reported separately and either may be `None`. A wallet
/// can hold Sapling notes, transparent UTXOs, both, or (after a previous
/// sweep) neither, and collapsing that into one number would hide a pool
/// that silently moved nothing.
#[derive(Debug, Clone, Default)]
pub struct ImportedSweepOutcome {
    /// One record per Sapling account with a prepared transaction, followed
    /// by the transparent record when that leg runs.
    ///
    /// A `Vec`, not an `Option`: an imported wallet has one account per
    /// Sapling key, each with its own notes, and each sweeps separately.
    /// Reporting only one would under-report what moved.
    pub transactions: Vec<TxBroadcastResult>,
    pub sapling_transaction_count: usize,
    /// Display ID used when registered Sapling accounts held only dust/zero.
    pub sapling_empty_display_index: Option<u32>,
    /// The Sapling leg ran to completion, so no Sapling records means
    /// "nothing was spendable" rather than "we stopped before finding out".
    /// Without this the caller cannot tell a genuinely empty pool from one
    /// whose sweep aborted, and would report the first as the second.
    pub sapling_leg_completed: bool,
    pub transparent_display_index: Option<u32>,
    pub transparent_transaction_recorded: bool,
    /// An uncertain or retryable submission bars every later leg.
    pub followup_blocked: bool,
    /// As `sapling_leg_completed`, for the transparent pool.
    pub transparent_leg_completed: bool,
}

fn record_sapling_submission(
    outcome: &mut ImportedSweepOutcome,
    display_index: u32,
    submission: &TxSubmissionResult,
) -> ZeckResult<bool> {
    let mut detail = match &submission.disposition {
        crate::broadcast::SubmissionDisposition::Accepted => {
            "Sapling transaction accepted; awaiting confirmation".to_owned()
        }
        other => format!("Sapling submission: {other:?}"),
    };
    if let Some(warning) = &submission.persistence_warning {
        detail.push_str(&format!(" Persistence warning: {warning}"));
    }
    outcome.transactions.push(TxBroadcastResult {
        source_account: display_index,
        txid: Some(submission.txid.to_string()),
        status: submission.state,
        fee_zatoshis: submission.fee_zatoshis,
        detail,
        confirmed_height: None,
        safe_to_discard: false,
    });
    outcome.sapling_transaction_count += 1;
    outcome.followup_blocked |= submission.blocks_followup_submission();
    crate::service::at_risk_fee_total(&outcome.transactions)?;
    Ok(outcome.followup_blocked)
}

/// What the standalone transparent follow-up needs besides its keys.
struct TransparentFollowup<'a> {
    runtime: &'a crate::models::RuntimeScanConfig,
    destination: &'a str,
    max_fee_zatoshis: Option<u64>,
    reviewed_fee_zatoshis: Option<u64>,
    planned: Option<&'a ImportedExecutionPlan>,
    /// The account row the transparent result is shown under, if any.
    display_index: Option<u32>,
}

/// Sweep `keys` through the account-free transparent path and record the
/// result. An uncertain or retryable submission blocks any later leg; a node
/// rejection ends the sweep. Nothing is sent when there are no keys or the
/// reviewed plan had no transparent leg.
async fn submit_transparent_followup(
    log: &mut DurableBroadcastLog,
    keys: &[crate::imported::ImportedTransparentKey],
    outcome: &mut ImportedSweepOutcome,
    followup: &TransparentFollowup<'_>,
) -> ZeckResult<()> {
    let planned = followup.planned;
    if keys.is_empty() || planned.is_some_and(|plan| plan.transparent.is_none()) {
        return Ok(());
    }
    let Some(swept) = crate::transparent_recovery::sweep_transparent_only_reviewed(
        log,
        keys,
        followup.runtime.network,
        &followup.runtime.lightwalletd_url,
        followup.destination,
        followup.max_fee_zatoshis,
        crate::service::at_risk_fee_total(&outcome.transactions)?,
        followup.reviewed_fee_zatoshis,
        planned.and_then(|plan| {
            plan.transparent
                .as_ref()
                .map(|(utxos, cost, height)| (utxos.as_slice(), cost, *height))
        }),
    )
    .await?
    else {
        return Ok(());
    };
    let blocked = matches!(
        swept.disposition,
        crate::broadcast::SubmissionDisposition::RetryableRejection { .. }
    ) || swept.transaction.status == TxLifecycleState::SubmissionUnknown;
    let rejected = swept.transaction.status == TxLifecycleState::Rejected;
    outcome.transactions.push(TxBroadcastResult {
        source_account: followup.display_index.unwrap_or(0),
        ..swept.transaction
    });
    outcome.transparent_transaction_recorded = true;
    outcome.transparent_display_index = followup.display_index;
    if blocked {
        outcome.followup_blocked = true;
        return Err(ZeckError::Broadcast("transparent submission may already have reached the network; reconcile its txid before retrying".to_owned()));
    }
    if rejected {
        return Err(ZeckError::Broadcast(
            "the node rejected the transparent sweep transaction".to_owned(),
        ));
    }
    Ok(())
}

async fn run_transparent_followup<F, Fut>(allowed: bool, submit: F) -> ZeckResult<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ZeckResult<()>>,
{
    if !allowed {
        return Err(ZeckError::Broadcast("a Sapling transaction may already have reached the network; reconcile its txid before retrying any sweep leg".to_owned()));
    }
    submit().await
}

#[async_trait::async_trait]
trait SaplingAccountRunner {
    async fn build_and_submit(
        &mut self,
        account: &crate::imported::ImportedWalletAccount,
        prior_fee_zatoshis: u64,
    ) -> ZeckResult<Option<TxSubmissionResult>>;
}

/// This loop is the production coordinator: once an uncertain submission is
/// recorded, no later account runner is invoked.
async fn run_sapling_accounts<R: SaplingAccountRunner>(
    accounts: &[(u32, crate::imported::ImportedWalletAccount)],
    outcome: &mut ImportedSweepOutcome,
    runner: &mut R,
) -> ZeckResult<()> {
    for (display_index, account) in accounts {
        let prior_fee = crate::service::at_risk_fee_total(&outcome.transactions)?;
        let Some(submission) = runner.build_and_submit(account, prior_fee).await? else {
            continue;
        };
        if record_sapling_submission(outcome, *display_index, &submission)? {
            return Err(ZeckError::Broadcast(format!(
                "Sapling transaction {} may already have reached the network or was retryably refused; reconcile it before any further sweep",
                submission.txid,
            )));
        }
        if submission.state == TxLifecycleState::Rejected {
            return Err(ZeckError::Broadcast(format!(
                "the node rejected Sapling transaction {}: {:?}",
                submission.txid, submission.disposition,
            )));
        }
    }
    Ok(())
}

struct RealSaplingAccountRunner<'a> {
    runtime: &'a crate::models::RuntimeScanConfig,
    workspace: &'a crate::workspace::RecoveryWorkspace,
    params: crate::workspace::ArgosParams,
    recipient: &'a ZcashAddress,
    prover: &'a LocalTxProver,
    max_fee_zatoshis: Option<u64>,
    reviewed_sapling_fees: Option<&'a std::collections::HashMap<AccountUuid, u64>>,
    planned: Option<&'a ImportedExecutionPlan>,
    broadcast_log: &'a mut DurableBroadcastLog,
}

#[async_trait::async_trait]
impl SaplingAccountRunner for RealSaplingAccountRunner<'_> {
    async fn build_and_submit(
        &mut self,
        account: &crate::imported::ImportedWalletAccount,
        prior_fee_zatoshis: u64,
    ) -> ZeckResult<Option<TxSubmissionResult>> {
        let Some(extsk) = account.sapling_extsk.as_ref() else {
            return Ok(None);
        };
        if self
            .planned
            .is_some_and(|plan| !plan.sapling.contains_key(&account.wallet_account_id))
        {
            return Ok(None);
        }
        let built = {
            let mut wallet_db =
                crate::workspace::open_wallet_db(self.workspace.wallet_db_path(), self.params)?;
            extsk.with_parsed(|parsed| {
                build_imported_sapling_sweep_reviewed(
                    &mut wallet_db,
                    &self.params,
                    account.wallet_account_id,
                    parsed,
                    self.recipient,
                    self.prover,
                    self.max_fee_zatoshis,
                    prior_fee_zatoshis,
                    self.reviewed_sapling_fees
                        .map(|fees| fees.get(&account.wallet_account_id).copied().unwrap_or(0)),
                    if let Some(plan) = self.planned {
                        plan.sapling.get(&account.wallet_account_id)
                    } else {
                        None
                    },
                )
            })
        };
        let tx = match built {
            Ok(tx) => tx,
            Err(err) if crate::service::is_insufficient_funds_error(&err.to_string()) => {
                return Ok(None)
            }
            Err(err) => return Err(err),
        };
        let mut raw = Vec::new();
        tx.write(&mut raw).map_err(|err| {
            ZeckError::TransactionBuild(format!("serializing the Sapling sweep: {err}"))
        })?;
        let prepared = PreparedTransaction {
            txid: tx.txid(),
            raw_tx: raw,
            fee_zatoshis: transaction_fee_zatoshis(&tx)?,
            expiry_height: Some(u32::from(tx.expiry_height())),
        };
        let (mut client, _endpoint) =
            crate::lightwalletd::connect_lightwalletd_endpoints_with_retry(
                &self.runtime.lightwalletd_url,
                None,
            )
            .await?;
        submit_prepared_transaction(
            self.broadcast_log,
            &mut LightwalletdSubmitter {
                client: &mut client,
            },
            prepared,
            std::time::Duration::from_secs(30),
        )
        .await
        .map(Some)
    }
}

fn open_imported_broadcast_log(
    registry_lease: &crate::service::NetworkRegistryLease,
) -> ZeckResult<DurableBroadcastLog> {
    registry_lease.verify()?;
    let log = registry_lease.reopen_broadcast_log()?;
    registry_lease.verify()?;
    // The execution-start gate already refused unresolved history from any
    // earlier review. Here only an unknown outcome blocks: a leg of this same
    // execution that was accepted (Pending) spends disjoint reviewed inputs.
    if let Some(txid) = log.blocking_next_leg() {
        return Err(ZeckError::Broadcast(format!(
            "transaction {txid} may already have reached the network or was retryably refused; reconcile its durable record before starting another sweep leg"
        )));
    }
    if log.has_not_submitted() {
        return Err(ZeckError::Broadcast(
            "cannot start another sweep leg with unresolved prepared transaction history"
                .to_owned(),
        ));
    }
    Ok(log)
}

/// Sweep everything an imported wallet holds to `destination`.
///
/// Separate transactions: the Sapling notes go through the PCZT path,
/// and the transparent UTXOs through `transparent_recovery`, which drives
/// the builder directly. They cannot be combined —
/// `create_pczt_from_proposal` accepts only single-step proposals and a
/// two-pool sweep is two steps.
///
/// A pool with nothing in it is skipped rather than failing the sweep, and
/// a failure in one pool does not discard its result: the caller is told
/// what may have moved. The workspace must already have been scanned, or the
/// wallet database holds no notes to spend.
///
/// Returns the outcome *and* the terminal status side by side, rather than
/// folding a failure into `Err` and dropping the outcome with it. Each
/// Sapling account is submitted separately, so by the time anything can
/// fail there may already be transactions on-chain; an `Err` return would
/// take their txids with it and show the user a total failure for a sweep
/// that may have moved real funds. This is the same split the HD sweep path
/// makes for the same reason (audit Issue E); the caller folds the two back
/// together with `assemble_sweep_outcome`.
#[cfg(test)]
async fn sweep_imported_wallet(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
) -> (ImportedSweepOutcome, ZeckResult<()>) {
    let operation_guard =
        match crate::service::NetworkOperationGuard::acquire(&runtime.data_dir, runtime.network) {
            Ok(guard) => guard,
            Err(err) => return (ImportedSweepOutcome::default(), Err(err)),
        };
    let registry_lease = match operation_guard.registry_lease() {
        Ok(lease) => lease,
        Err(err) => return (ImportedSweepOutcome::default(), Err(err)),
    };
    sweep_imported_wallet_reviewed(
        runtime,
        keys,
        destination,
        max_fee_zatoshis,
        ImportedSweepReview {
            sapling_fees: None,
            transparent_fee: None,
            plan: None,
            registry_lease: &registry_lease,
        },
    )
    .await
}

pub(crate) struct ImportedSweepReview<'a> {
    pub(crate) sapling_fees: Option<&'a std::collections::HashMap<AccountUuid, u64>>,
    pub(crate) transparent_fee: Option<u64>,
    pub(crate) plan: Option<&'a ImportedExecutionPlan>,
    pub(crate) registry_lease: &'a crate::service::NetworkRegistryLease,
}

pub(crate) async fn sweep_imported_wallet_reviewed(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    review: ImportedSweepReview<'_>,
) -> (ImportedSweepOutcome, ZeckResult<()>) {
    let mut outcome = ImportedSweepOutcome::default();
    let result = sweep_imported_wallet_into(
        runtime,
        keys,
        destination,
        max_fee_zatoshis,
        &mut outcome,
        review,
    )
    .await;
    (outcome, result)
}

/// Spend only the standalone identities registered by a mixed scan. The
/// account IDs come from that scan; re-registering the original imported set
/// would reintroduce HD-overlapping keys and duplicate spend authority.
#[cfg(test)]
async fn sweep_imported_filtered_wallet(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    sapling_accounts: &[(u32, AccountUuid, usize)],
    transparent_indices: &[usize],
    transparent_display_index: Option<u32>,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
) -> (ImportedSweepOutcome, ZeckResult<()>) {
    let operation_guard =
        match crate::service::NetworkOperationGuard::acquire(&runtime.data_dir, runtime.network) {
            Ok(guard) => guard,
            Err(err) => return (ImportedSweepOutcome::default(), Err(err)),
        };
    let registry_lease = match operation_guard.registry_lease() {
        Ok(lease) => lease,
        Err(err) => return (ImportedSweepOutcome::default(), Err(err)),
    };
    sweep_imported_filtered_wallet_reviewed(
        runtime,
        keys,
        sapling_accounts,
        transparent_indices,
        transparent_display_index,
        destination,
        max_fee_zatoshis,
        None,
        None,
        None,
        &registry_lease,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sweep_imported_filtered_wallet_reviewed(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    sapling_accounts: &[(u32, AccountUuid, usize)],
    transparent_indices: &[usize],
    transparent_display_index: Option<u32>,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    reviewed_sapling_fees: Option<&std::collections::HashMap<AccountUuid, u64>>,
    reviewed_transparent_fee: Option<u64>,
    planned: Option<&ImportedExecutionPlan>,
    registry_lease: &crate::service::NetworkRegistryLease,
) -> (ImportedSweepOutcome, ZeckResult<()>) {
    let mut outcome = ImportedSweepOutcome {
        sapling_empty_display_index: sapling_accounts.first().map(|account| account.0),
        ..Default::default()
    };
    let result = async {
        let mut log = open_imported_broadcast_log(registry_lease)?;
        sweep_imported_sapling_leg(
            runtime,
            keys,
            destination,
            max_fee_zatoshis,
            &mut outcome,
            Some(sapling_accounts),
            &mut log,
            reviewed_sapling_fees,
            planned,
        )
        .await?;
        outcome.sapling_leg_completed = true;
        if !outcome.followup_blocked
            && !transparent_indices.is_empty()
            && planned.is_none_or(|plan| plan.transparent.is_some())
        {
            let all_keys = crate::imported::imported_transparent_keys(keys)?;
            let mut available = all_keys.into_iter().map(Some).collect::<Vec<_>>();
            let selected = transparent_indices
                .iter()
                .map(|index| {
                    available
                        .get_mut(*index)
                        .and_then(Option::take)
                        .ok_or_else(|| {
                            ZeckError::Wallet(format!(
                                "standalone transparent key {index} is missing"
                            ))
                        })
                })
                .collect::<ZeckResult<Vec<_>>>()?;
            submit_transparent_followup(
                &mut log,
                &selected,
                &mut outcome,
                &TransparentFollowup {
                    runtime,
                    destination,
                    max_fee_zatoshis,
                    reviewed_fee_zatoshis: reviewed_transparent_fee,
                    planned,
                    display_index: transparent_display_index,
                },
            )
            .await?;
        }
        outcome.transparent_leg_completed = true;
        Ok(())
    }
    .await;
    (outcome, result)
}

/// The body of [`sweep_imported_wallet`], writing into an outcome the caller
/// owns.
///
/// Split out so `?` stays usable throughout: every early return lands in the
/// caller's `ZeckResult<()>` while whatever was already recorded in
/// `outcome` survives, which is precisely the property a mid-loop
/// `return Err` destroyed.
async fn sweep_imported_wallet_into(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    outcome: &mut ImportedSweepOutcome,
    review: ImportedSweepReview<'_>,
) -> ZeckResult<()> {
    use crate::imported::imported_transparent_keys;
    let ImportedSweepReview {
        sapling_fees: reviewed_sapling_fees,
        transparent_fee: reviewed_transparent_fee,
        plan: planned,
        registry_lease,
    } = review;
    let mut log = open_imported_broadcast_log(registry_lease)?;

    // Sapling first. A definite failure may leave the independent transparent
    // pool spendable, but an uncertain or retryable submission blocks it.
    let sapling_result = sweep_imported_sapling_leg(
        runtime,
        keys,
        destination,
        max_fee_zatoshis,
        outcome,
        None,
        &mut log,
        reviewed_sapling_fees,
        planned,
    )
    .await;
    outcome.sapling_leg_completed = sapling_result.is_ok();

    // Transparent, through the path that needs no account at all.
    let transparent_result = run_transparent_followup(!outcome.followup_blocked, || async {
        let transparent = imported_transparent_keys(keys)?;
        submit_transparent_followup(
            &mut log,
            &transparent,
            outcome,
            &TransparentFollowup {
                runtime,
                destination,
                max_fee_zatoshis,
                reviewed_fee_zatoshis: reviewed_transparent_fee,
                planned,
                display_index: None,
            },
        )
        .await
    })
    .await;
    outcome.transparent_leg_completed = transparent_result.is_ok();

    // When both legs failed the Sapling one is returned: it is the pool that
    // broadcasts per account, so it is the failure that can leave funds
    // half-moved, and it is the one whose `ZeckError` variant the caller
    // acts on (`MaxFeeExceeded` in particular). Merging the two into a
    // single string would flatten that variant into `Internal` and cost the
    // caller the distinction, so the transparent reason is logged instead of
    // concatenated — `transparent_leg_completed` already tells the caller it
    // was attempted and did not finish.
    match (sapling_result, transparent_result) {
        (Ok(()), transparent) => transparent,
        (Err(sapling), Ok(())) => Err(sapling),
        (Err(sapling), Err(transparent)) => {
            tracing::warn!("the transparent sweep also failed: {transparent}");
            Err(sapling)
        }
    }
}

/// Sweep every imported Sapling account, one transaction at a time.
///
/// Writes each submission into `outcome` as it happens, so an abort part-way
/// through still leaves the caller holding the known txid, fee, and state.
#[allow(clippy::too_many_arguments)]
async fn sweep_imported_sapling_leg(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    outcome: &mut ImportedSweepOutcome,
    registered_accounts: Option<&[(u32, AccountUuid, usize)]>,
    broadcast_log: &mut DurableBroadcastLog,
    reviewed_sapling_fees: Option<&std::collections::HashMap<AccountUuid, u64>>,
    planned: Option<&ImportedExecutionPlan>,
) -> ZeckResult<()> {
    use crate::imported::register_imported_accounts;
    use crate::workspace::{consensus_network, open_wallet_db, RecoveryWorkspace};
    use zcash_client_backend::data_api::{chain::ChainState, AccountBirthday};
    use zcash_proofs::prover::LocalTxProver;

    let params = consensus_network(runtime.network);

    if registered_accounts.is_some_and(|accounts| accounts.is_empty()) {
        return Ok(());
    }

    // Every account, not just the first. `register_imported_accounts` creates
    // one account per Sapling key and `run_imported_scan` reports a balance
    // for each, so sweeping only `keys.sapling.first()` showed the user a full
    // balance and moved one key's notes, with the shortfall reported nowhere.
    // A zcashd wallet accumulates a `sapzkey` record per `z_getnewaddress`,
    // so multiple keys is the ordinary case, not an exotic one.
    // Registration only happens on the route that has accounts. It must not
    // be hoisted above this check: `register_imported_accounts` refuses a
    // transparent-only key set outright (ZIP-316 gives it no UFVK to anchor
    // to), so running it unconditionally aborts the whole sweep before
    // reaching the transparent path below — which needs no account at all.
    // The scan already routes on `classify_recovery_route`; this is the same
    // decision on the sweep side.
    if registered_accounts.is_none()
        && !matches!(
            crate::key_source::classify_recovery_route(keys),
            crate::key_source::RecoveryRoute::ImportedAccounts
        )
    {
        // No Sapling keys at all, so the leg is complete and empty rather
        // than skipped.
        return Ok(());
    }

    // Refuse an unsatisfiable fee cap here as well as inside
    // `build_imported_sapling_sweep`, so the refusal costs neither a wallet
    // database nor the ~725 MB of proving parameters below. The check
    // inside the builder is the load-bearing one; this is the same
    // conclusion reached sooner.
    enforce_sapling_fee_floor(max_fee_zatoshis)?;

    let workspace = RecoveryWorkspace::from_runtime(runtime)?;
    let accounts = if let Some(registered) = registered_accounts {
        registered
            .iter()
            .map(|&(display_index, wallet_account_id, key_index)| {
                let key = keys.sapling.get(key_index).ok_or_else(|| {
                    ZeckError::Wallet(format!("standalone Sapling key {key_index} is missing"))
                })?;
                let extsk = crate::imported::ImportedSaplingSpendingKey::from_serialized(
                    secrecy::ExposeSecret::expose_secret(&key.extsk),
                )?;
                Ok((
                    display_index,
                    crate::imported::ImportedWalletAccount {
                        wallet_account_id,
                        sapling_extsk: Some(extsk),
                        transparent_addresses: Vec::new(),
                    },
                ))
            })
            .collect::<ZeckResult<Vec<_>>>()?
    } else {
        let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), params)?;
        // Re-registration is idempotent and returns the accounts the
        // scan already created.
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                zcash_protocol::consensus::BlockHeight::from_u32(runtime.birthday),
                zcash_primitives::block::BlockHash([0u8; 32]),
            ),
            None,
        );
        unique_registered_accounts(register_imported_accounts(&mut wallet_db, keys, &birthday)?)?
            .into_iter()
            .enumerate()
            .map(|(index, account)| (index as u32, account))
            .collect()
    };

    if accounts.is_empty() {
        return Err(ZeckError::Internal(
            "no imported account to sweep from".to_owned(),
        ));
    }
    // Every reviewed Sapling leg must map to an account this executor will
    // visit; otherwise it would be silently dropped. Fail before signing.
    if let Some(plan) = planned {
        if let Some(missing) = plan.sapling.keys().find(|reviewed| {
            !accounts
                .iter()
                .any(|(_, account)| account.wallet_account_id == **reviewed)
        }) {
            return Err(ZeckError::StaleSweepProposal(format!(
                "reviewed imported Sapling leg for account {missing:?} cannot be executed; nothing was signed"
            )));
        }
    }

    let recipient = ZcashAddress::try_from_encoded(destination)
        .map_err(|err| ZeckError::InvalidAddress(format!("could not decode destination: {err}")))?;

    // Loaded once for all accounts: the bundled Sapling parameters are
    // ~725 MB, and loading them per key would dominate the sweep.
    let prover = LocalTxProver::bundled();

    let mut runner = RealSaplingAccountRunner {
        runtime,
        workspace: &workspace,
        params,
        recipient: &recipient,
        prover: &prover,
        max_fee_zatoshis,
        reviewed_sapling_fees,
        planned,
        broadcast_log,
    };
    run_sapling_accounts(&accounts, outcome, &mut runner).await
}

/// A wallet file may contain repeated records for one Sapling key. Registration
/// reuses its UUID; the executor must visit that UUID only once.
fn unique_registered_accounts(
    accounts: Vec<crate::imported::ImportedWalletAccount>,
) -> ZeckResult<Vec<crate::imported::ImportedWalletAccount>> {
    let mut seen = std::collections::HashMap::new();
    let mut unique = Vec::with_capacity(accounts.len());
    for account in accounts {
        let identity = account
            .sapling_extsk
            .as_ref()
            .map(crate::imported::ImportedSaplingSpendingKey::full_viewing_key_identity)
            .transpose()?;
        if let Some(previous) = seen.get(&account.wallet_account_id) {
            if previous != &identity {
                return Err(ZeckError::Wallet(
                    "one registered Sapling account has conflicting key identities".to_owned(),
                ));
            }
            continue;
        }
        seen.insert(account.wallet_account_id, identity);
        unique.push(account);
    }
    Ok(unique)
}

#[cfg(test)]
mod fee_cap_tests {
    use super::*;

    /// The imported-Sapling leg compares the fee captured at review with the
    /// proposal it is about to build, before the PCZT is created.
    #[test]
    fn imported_leg_compares_reviewed_fee_with_the_planned_proposal() {
        let tempdir = tempfile::tempdir().unwrap();
        let key_source: std::sync::Arc<dyn crate::key_source::KeySource> =
            std::sync::Arc::new(crate::key_source::SeedKeySource::new(
                secrecy::SecretString::new(
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        .to_owned(),
                ),
            ));
        let runtime = crate::models::RuntimeScanConfig {
            key_source: key_source.clone(),
            birthday: 419_200,
            num_accounts: Some(1),
            gap_limit: 1,
            transparent_scan: None,
            lightwalletd_url: "http://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: tempdir.path().to_owned(),
            network: crate::models::ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let workspace = crate::workspace::RecoveryWorkspace::from_runtime(&runtime).unwrap();
        workspace
            .initialize_from_source(runtime.network, key_source.as_ref())
            .unwrap();
        let params = crate::workspace::consensus_network(runtime.network);
        let mut wallet_db =
            crate::workspace::open_wallet_db(workspace.wallet_db_path(), params).unwrap();
        let extsk = ExtendedSpendingKey::master(&[1; 32]);
        let (_, address) = extsk.default_address();
        let destination =
            ZcashAddress::try_from_encoded(&zcash_keys::encoding::encode_payment_address(
                zcash_protocol::constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                &address,
            ))
            .unwrap();
        let planned = crate::service::leg_fee_pin_tests::offline_proposal::<ReceivedNoteId>(15_000);
        let prover = LocalTxProver::bundled();
        let result = build_imported_sapling_sweep_reviewed(
            &mut wallet_db,
            &params,
            AccountUuid::default(),
            &extsk,
            &destination,
            &prover,
            None,
            0,
            Some(10_000),
            Some(&planned),
        );
        assert!(
            matches!(
                result,
                Err(ZeckError::FeeQuoteChanged {
                    reviewed: 10_000,
                    current: 15_000
                })
            ),
            "{:?}",
            result.map(|tx| tx.txid())
        );
    }

    #[tokio::test]
    async fn filtered_transparent_only_route_skips_sapling_registration_and_reaches_t_key() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = crate::models::RuntimeScanConfig {
            key_source: std::sync::Arc::new(crate::key_source::ImportedKeySource::new(
                argos_wallet_import::ImportedKeys::default(),
            )),
            birthday: 419_200,
            num_accounts: Some(1),
            gap_limit: 1,
            transparent_scan: None,
            lightwalletd_url: "http://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: tempdir.path().join("recovery-data"),
            network: crate::models::ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let (outcome, result) = sweep_imported_filtered_wallet(
            &runtime,
            &argos_wallet_import::ImportedKeys::default(),
            &[],
            &[0],
            Some(5),
            "unused-destination",
            Some(1),
        )
        .await;
        let error = result.expect_err("the missing transparent key should be detected");
        assert!(
            error.to_string().contains("standalone transparent key 0"),
            "{error}"
        );
        assert!(outcome.sapling_leg_completed);
        assert!(outcome.transactions.is_empty());
    }

    #[tokio::test]
    async fn filtered_sapling_leg_uses_the_scan_key_index_before_any_network_call() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = crate::models::RuntimeScanConfig {
            key_source: std::sync::Arc::new(crate::key_source::ImportedKeySource::new(
                argos_wallet_import::ImportedKeys::default(),
            )),
            birthday: 419_200,
            num_accounts: Some(1),
            gap_limit: 1,
            transparent_scan: None,
            lightwalletd_url: "http://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: tempdir.path().join("recovery-data"),
            network: crate::models::ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let (outcome, result) = sweep_imported_filtered_wallet(
            &runtime,
            &argos_wallet_import::ImportedKeys::default(),
            &[(7, AccountUuid::default(), 3)],
            &[],
            None,
            "unused-destination",
            None,
        )
        .await;
        let error = result.expect_err("the scan's key index must resolve to a real key");
        assert!(
            error.to_string().contains("standalone Sapling key 3"),
            "{error}"
        );
        assert_eq!(outcome.sapling_empty_display_index, Some(7));
        assert!(outcome.transactions.is_empty());
    }

    /// `--max-fee` must reach the imported-Sapling leg.
    ///
    /// It was honoured on the transparent leg and on the HD sweep, but
    /// `build_imported_sapling_sweep` never received it, so a user who
    /// capped their fee had that cap silently voided on the one leg that
    /// spends shielded notes.
    ///
    /// Driven through the public `sweep_imported_wallet` rather than a
    /// helper, so it fails if the cap is threaded no further than the
    /// signature. It uses a real Sapling key from the golden fixture — the
    /// route is chosen by `classify_recovery_route`, and a key set without
    /// one never enters this leg at all.
    ///
    /// Asserted positively on `MaxFeeExceeded`. Without the cap plumbed
    /// through, this wallet reaches a database with no notes and an
    /// unroutable endpoint, and fails as something else entirely; "returned
    /// an error" would be satisfied by either.
    #[tokio::test]
    async fn a_fee_cap_below_the_zip317_floor_refuses_the_sapling_sweep() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
        ))
        .expect("golden fixture must exist");
        let make_keys = || {
            argos_wallet_import::import_wallet_file(&bytes, None)
                .expect("the plaintext fixture must import")
        };
        let keys = make_keys();
        assert!(
            !keys.sapling.is_empty(),
            "the fixture must hold a Sapling key or this test never enters the Sapling leg"
        );
        assert_eq!(
            crate::key_source::classify_recovery_route(&keys),
            crate::key_source::RecoveryRoute::ImportedAccounts,
            "fixture must take the imported-account route or this test proves nothing"
        );

        let tempdir = tempfile::tempdir().expect("temp dir");
        let runtime = crate::models::RuntimeScanConfig {
            key_source: std::sync::Arc::new(crate::key_source::ImportedKeySource::new(make_keys())),
            birthday: 419_200,
            num_accounts: Some(1),
            gap_limit: 5,
            transparent_scan: None,
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: tempdir.path().join("recovery-data"),
            network: crate::models::ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let destination = {
            use zcash_address::unified::{Address, Encoding, Receiver};
            let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x7u8; 32]);
            let (_, payment_address) = extsk.default_address();
            Address::try_from_items(vec![Receiver::Sapling(payment_address.to_bytes())])
                .expect("a Sapling-only unified address is valid under ZIP 316")
                .encode(&zcash_protocol::consensus::NetworkType::Main)
        };

        // One zatoshi under the ZIP-317 conventional floor: unsatisfiable by
        // any Sapling sweep, whatever the wallet holds.
        let cap = crate::service::MIN_SHIELDED_SEND_FEE_ZATOSHIS - 1;
        let (outcome, result) =
            sweep_imported_wallet(&runtime, &keys, &destination, Some(cap)).await;

        let err = result.expect_err("a cap below the ZIP 317 floor must refuse the sweep");
        assert!(
            matches!(err, ZeckError::MaxFeeExceeded(_)),
            "the refusal must be the fee cap, not something the sweep tripped over on the \
             way past it. Got: {err:?}"
        );
        assert!(
            err.to_string().contains(&cap.to_string()),
            "the refusal must name the limit that was not met. Got: {err}"
        );
        assert!(
            outcome.transactions.is_empty(),
            "the refusal must come before any broadcast"
        );
        assert!(
            !outcome.sapling_leg_completed,
            "a refused Sapling leg must not be reported as having run to completion"
        );

        // The fixture also holds transparent keys, so this doubles as proof
        // that a failed Sapling leg does not skip the transparent one: the
        // transparent sweep was attempted and failed on the unroutable
        // endpoint, which it can only have done by running.
        assert!(
            !keys.transparent.is_empty(),
            "the fixture must hold transparent keys or the assertion below is vacuous"
        );
        assert!(
            !outcome.transparent_leg_completed,
            "the transparent leg must still be attempted after the Sapling leg errored"
        );
    }

    /// The floor check must not refuse a cap a sweep could actually meet.
    ///
    /// The other direction of the same gate: without this, "refuse
    /// everything" would pass the test above.
    #[test]
    fn a_cap_at_or_above_the_floor_is_not_refused_outright() {
        assert!(enforce_sapling_fee_floor(None).is_ok());
        assert!(
            enforce_sapling_fee_floor(Some(crate::service::MIN_SHIELDED_SEND_FEE_ZATOSHIS)).is_ok()
        );
        assert!(matches!(
            enforce_sapling_fee_floor(Some(crate::service::MIN_SHIELDED_SEND_FEE_ZATOSHIS - 1)),
            Err(ZeckError::MaxFeeExceeded(_))
        ));
    }
}

#[cfg(test)]
mod registered_account_dedup_tests {
    use super::*;

    #[test]
    fn duplicate_registered_sapling_uuid_is_swept_once() {
        let extsk = || {
            let parsed = sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32]);
            crate::imported::ImportedSaplingSpendingKey::from_serialized(&parsed.to_bytes())
                .expect("fixture key")
        };
        let make_account = || crate::imported::ImportedWalletAccount {
            wallet_account_id: AccountUuid::default(),
            sapling_extsk: Some(extsk()),
            transparent_addresses: Vec::new(),
        };
        let unique = super::unique_registered_accounts(vec![make_account(), make_account()])
            .expect("the same key may appear in more than one wallet record");
        assert_eq!(unique.len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broadcast::{SubmissionDisposition, TxSubmissionResult};
    use crate::models::TxLifecycleState;
    use zcash_primitives::transaction::TxId;

    struct CountingRunner {
        first: TxSubmissionResult,
        builds: usize,
        submissions: usize,
    }

    #[async_trait::async_trait]
    impl SaplingAccountRunner for CountingRunner {
        async fn build_and_submit(
            &mut self,
            _: &crate::imported::ImportedWalletAccount,
            _: u64,
        ) -> ZeckResult<Option<TxSubmissionResult>> {
            self.builds += 1;
            self.submissions += 1;
            Ok(Some(self.first.clone()))
        }
    }

    async fn assert_first_submission_stops_coordinator(first: TxSubmissionResult) {
        let account = || crate::imported::ImportedWalletAccount {
            wallet_account_id: AccountUuid::default(),
            sapling_extsk: None,
            transparent_addresses: Vec::new(),
        };
        let accounts = vec![(0, account()), (1, account())];
        let mut runner = CountingRunner {
            first,
            builds: 0,
            submissions: 0,
        };
        let mut outcome = ImportedSweepOutcome::default();
        assert!(run_sapling_accounts(&accounts, &mut outcome, &mut runner)
            .await
            .is_err());
        assert_eq!(runner.builds, 1, "second Sapling builder was called");
        assert_eq!(runner.submissions, 1, "second Sapling submitter was called");
        assert_eq!(outcome.transactions.len(), 1);
        let transparent_calls = std::cell::Cell::new(0);
        let result = run_transparent_followup(!outcome.followup_blocked, || async {
            transparent_calls.set(transparent_calls.get() + 1);
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            transparent_calls.get(),
            0,
            "transparent submitter was called"
        );
    }

    fn unknown() -> TxSubmissionResult {
        TxSubmissionResult {
            txid: TxId::from_bytes([7; 32]),
            state: TxLifecycleState::SubmissionUnknown,
            fee_zatoshis: 10_000,
            disposition: SubmissionDisposition::AmbiguousTransport,
            persistence_warning: None,
        }
    }

    #[tokio::test]
    async fn unknown_sapling_submission_stops_remaining_sapling_accounts() {
        let mut outcome = ImportedSweepOutcome::default();
        let stop = record_sapling_submission(&mut outcome, 3, &unknown()).unwrap();
        assert!(
            stop,
            "the next Sapling account must not be built or submitted"
        );
        assert_eq!(outcome.transactions.len(), 1);
        assert_eq!(outcome.transactions[0].source_account, 3);
        assert_eq!(
            outcome.transactions[0].status,
            TxLifecycleState::SubmissionUnknown
        );
        assert_eq!(outcome.transactions[0].fee_zatoshis, 10_000);
    }

    #[tokio::test]
    async fn unknown_first_submission_leaves_second_builder_and_transparent_submitter_untouched() {
        assert_first_submission_stops_coordinator(unknown()).await;
    }

    #[tokio::test]
    async fn retryable_first_submission_leaves_second_builder_and_transparent_submitter_untouched()
    {
        let mut retryable = unknown();
        retryable.state = TxLifecycleState::Pending;
        retryable.disposition = SubmissionDisposition::RetryableRejection {
            code: -26,
            reason: "mempool full".to_owned(),
        };
        assert_first_submission_stops_coordinator(retryable).await;
    }

    #[test]
    fn sapling_record_includes_post_io_persistence_warning() {
        let mut submission = unknown();
        submission.persistence_warning = Some("final sync failed".to_owned());
        let mut outcome = ImportedSweepOutcome::default();
        record_sapling_submission(&mut outcome, 0, &submission).unwrap();
        assert!(outcome.transactions[0].detail.contains("final sync failed"));
    }

    #[tokio::test]
    async fn unknown_sapling_submission_stops_transparent_leg() {
        let mut outcome = ImportedSweepOutcome::default();
        record_sapling_submission(&mut outcome, 3, &unknown()).unwrap();
        assert!(outcome.followup_blocked);
    }
}

#[cfg(test)]
mod sapling_scope_tests {
    use super::*;

    #[test]
    fn classifies_external_and_internal_note_authority() {
        let extsk = ExtendedSpendingKey::master(&[7u8; 32]);
        let external = extsk.default_address().1;
        let internal_extsk = extsk.derive_internal();
        let internal = internal_extsk.default_address().1;

        assert_eq!(
            classify_spend_scope(&extsk, Some(&external)).unwrap(),
            SaplingSpendScope::External
        );
        assert_eq!(
            classify_spend_scope(&extsk, Some(&internal)).unwrap(),
            SaplingSpendScope::Internal
        );
        assert_ne!(
            extsk.expsk.proof_generation_key().nsk,
            internal_extsk.expsk.proof_generation_key().nsk,
            "internal Sapling notes require the internal nsk proof authority"
        );
        assert_eq!(
            extsk.expsk.ask.to_bytes(),
            internal_extsk.expsk.ask.to_bytes(),
            "Sapling internal derivation preserves ask while changing nsk"
        );
    }

    #[test]
    fn missing_or_foreign_recipient_fails_closed() {
        let extsk = ExtendedSpendingKey::master(&[7u8; 32]);
        let stranger = ExtendedSpendingKey::master(&[8u8; 32]).default_address().1;
        assert!(matches!(
            classify_spend_scope(&extsk, None),
            Err(ProofKeyError::MissingRecipient)
        ));
        assert!(matches!(
            classify_spend_scope(&extsk, Some(&stranger)),
            Err(ProofKeyError::UnknownRecipientScope)
        ));
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;

    /// A transparent-only wallet must reach the transparent sweep.
    ///
    /// `register_imported_accounts` refuses a transparent-only key set
    /// outright — ZIP-316 gives it no UFVK to anchor an account to — so
    /// calling it unconditionally aborts the entire sweep before the
    /// transparent path, which needs no account at all. That is exactly what
    /// happened when registration was hoisted out of the Sapling guard to fix
    /// the multi-key bug: the scan could show a transparent balance the sweep
    /// then refused to move, which is the scan/sweep asymmetry this work set
    /// out to close, moved one step downstream.
    ///
    /// Pinned by routing rather than by outcome, because the sweep itself
    /// needs a node. The endpoint is unroutable on purpose: failing at the
    /// network proves the routing decision was made correctly first, since the
    /// registration refusal happens before any connection is attempted.
    #[tokio::test]
    async fn a_transparent_only_wallet_is_not_refused_at_registration() {
        use argos_wallet_import::keys::{Provenance, TransparentKey};
        use secrecy::Secret;

        let make_keys = || {
            let mut keys = argos_wallet_import::ImportedKeys::default();
            keys.transparent.push(TransparentKey {
                secret: Secret::new([0x42; 32]),
                provenance: Provenance::Standalone,
                created_at: None,
            });
            keys
        };
        let keys = make_keys();
        assert_eq!(
            crate::key_source::classify_recovery_route(&keys),
            crate::key_source::RecoveryRoute::TransparentOnly,
            "fixture must classify as transparent-only or this test proves nothing"
        );

        let tempdir = tempfile::tempdir().expect("temp dir");
        let runtime = crate::models::RuntimeScanConfig {
            key_source: std::sync::Arc::new(crate::key_source::ImportedKeySource::new(make_keys())),
            birthday: 419_200,
            num_accounts: Some(1),
            gap_limit: 5,
            transparent_scan: None,
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: tempdir.path().join("recovery-data"),
            network: crate::models::ZeckNetwork::Mainnet,
            label: String::new(),
        };

        // A real destination, derived rather than typed. The first version of
        // this test used a placeholder string, which the sweep rejects during
        // address validation long before it reaches registration — so it
        // passed even with the bug reintroduced. It has to get past the
        // address gate to test anything at all.
        let destination = {
            use zcash_address::unified::{Address, Encoding, Receiver};
            let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x7u8; 32]);
            let (_, payment_address) = extsk.default_address();
            Address::try_from_items(vec![Receiver::Sapling(payment_address.to_bytes())])
                .expect("a Sapling-only unified address is valid under ZIP 316")
                .encode(&zcash_protocol::consensus::NetworkType::Main)
        };

        let err = sweep_imported_wallet(&runtime, &keys, &destination, None)
            .await
            .1
            .err()
            .map(|err| err.to_string());

        // Asserted positively, on the one signal that actually separates the
        // two paths: routed correctly, the sweep reaches lightwalletd and
        // fails on the unroutable endpoint. Taking the account path instead,
        // it dies earlier trying to open a wallet database that a
        // transparent-only sweep never creates.
        //
        // Two earlier versions of this assertion passed against the bug. The
        // first used a placeholder destination, rejected during address
        // validation before routing was reached. The second asserted the
        // absence of the ZIP-316 refusal text — but the account path fails at
        // `open_wallet_db` before registration is even called, so that string
        // never appeared either way. A negative assertion is satisfied by
        // every failure that is not the one named; only a positive one pins
        // the path actually taken.
        let rendered = err.expect("an unroutable endpoint must produce an error");
        assert!(
            rendered.contains("lightwalletd"),
            "a transparent-only wallet must be routed to the transparent sweep, which \
             reaches the network; an error from anywhere earlier means it took the \
             account path and was refused before it got there. Got: {rendered}"
        );
    }
}

#[cfg(test)]
mod cumulative_fee_tests {
    use super::*;

    /// `--max-fee` caps the whole sweep. Each account's transaction used to
    /// be checked against the full cap on its own, so four accounts at 60%
    /// of the cap each paid 240% of it with no error.
    #[test]
    fn each_account_is_checked_against_what_the_sweep_has_already_paid() {
        let cap = Some(10_000);
        assert!(enforce_cumulative_fee(0, 6_000, cap).is_ok());
        let err = enforce_cumulative_fee(6_000, 6_000, cap)
            .expect_err("a second 6,000 fee takes the sweep to 12,000, over 10,000");
        assert!(matches!(err, ZeckError::MaxFeeExceeded(_)), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("already paid 6000"), "{text}");
        assert!(
            enforce_cumulative_fee(6_000, 4_000, cap).is_ok(),
            "exactly at the cap"
        );
        assert!(
            enforce_cumulative_fee(u64::MAX, 1, None).is_err(),
            "overflow is refused"
        );
    }
}
