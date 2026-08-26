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
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::sapling::ExtendedSpendingKey;
use zcash_primitives::transaction::{builder::BundlePadding, Transaction};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::ShieldedPool;

use crate::error::{ZeckError, ZeckResult};

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
/// `max_fee_zatoshis` is the user's `--max-fee`. It is enforced twice and
/// never after broadcast: once against the proposal, before any proving
/// work, and once against the fee actually encoded in the extracted
/// transaction. The second is the one that matters — the first is the
/// planner's own arithmetic restated, whereas the second reads what was
/// built.
#[allow(clippy::too_many_arguments)]
pub fn build_imported_sapling_sweep<P>(
    wallet_db: &mut crate::imported::ArgosWalletDb,
    params: &P,
    account_id: AccountUuid,
    extsk: &ExtendedSpendingKey,
    destination: &ZcashAddress,
    prover: &LocalTxProver,
    max_fee_zatoshis: Option<u64>,
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
    let proposal = propose_send_max_transfer::<_, _, _, std::convert::Infallible>(
        wallet_db,
        params,
        account_id,
        &[ShieldedPool::Sapling],
        &StandardFeeRule::Zip317,
        destination.clone(),
        None,
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::MIN,
        // Argos takes no advisory input locks; never draw on another
        // holder's.
        &LockedInputPolicy::Exclude,
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("proposing the Sapling sweep: {err}")))?;

    // First gate, before ~725 MB of proving parameters are put to work and
    // long before anything could be broadcast. Same helper the HD sweep
    // path uses, so the two cannot drift on what "over the cap" means.
    let planned_fee_zatoshis = crate::service::proposal_fee_zatoshis(&proposal)?;
    crate::service::enforce_max_fee(planned_fee_zatoshis, max_fee_zatoshis)?;

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
        // The imported wallet must not be able to decrypt its own outgoing
        // output afterwards, and there is no meaningful account OVK here.
        OvkPolicy::Discard,
        &proposal,
        None,
        BundlePadding::DEFAULT,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating the PCZT: {err}")))?;

    // Supply the proof generation key the account's missing ZIP-32
    // derivation would otherwise have provided. Every spend in this bundle
    // belongs to the one imported key, because the proposal was restricted
    // to this account's Sapling pool.
    let pgk = extsk.expsk.proof_generation_key();
    let pczt = LowLevelSigner::new(pczt)
        .sign_sapling_with(|_, bundle, _| {
            let spends = bundle.spends().len();
            bundle
                .update_with(|mut updater| {
                    for index in 0..spends {
                        updater.update_spend_with(index, |mut spend| {
                            spend.set_proof_generation_key(pgk.clone())
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
        signer
            .sign_sapling(index, &extsk.expsk.ask)
            .map_err(|err| {
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
    crate::service::enforce_max_fee(actual_fee_zatoshis, max_fee_zatoshis)?;

    Ok(tx)
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

/// What an imported-wallet sweep moved.
///
/// Both pools are reported separately and either may be `None`. A wallet
/// can hold Sapling notes, transparent UTXOs, both, or (after a previous
/// sweep) neither, and collapsing that into one number would hide a pool
/// that silently moved nothing.
#[derive(Debug, Clone, Default)]
pub struct ImportedSweepOutcome {
    /// One transaction per Sapling account that had something to move.
    ///
    /// A `Vec`, not an `Option`: an imported wallet has one account per
    /// Sapling key, each with its own notes, and each sweeps separately.
    /// Reporting only one would under-report what moved.
    pub sapling_txids: Vec<String>,
    /// The Sapling leg ran to completion, so an empty `sapling_txids` means
    /// "nothing was spendable" rather than "we stopped before finding out".
    /// Without this the caller cannot tell a genuinely empty pool from one
    /// whose sweep aborted, and would report the first as the second.
    pub sapling_leg_completed: bool,
    pub transparent_txid: Option<String>,
    pub transparent_zatoshis: u64,
    pub transparent_fee_zatoshis: u64,
    /// As `sapling_leg_completed`, for the transparent pool.
    pub transparent_leg_completed: bool,
}

/// Sweep everything an imported wallet holds to `destination`.
///
/// Two transactions, not one: the Sapling notes go through the PCZT path,
/// and the transparent UTXOs through `transparent_recovery`, which drives
/// the builder directly. They cannot be combined —
/// `create_pczt_from_proposal` accepts only single-step proposals and a
/// two-pool sweep is two steps.
///
/// A pool with nothing in it is skipped rather than failing the sweep, and
/// a failure in one pool does not discard the other's result: the caller is
/// told what did move. The workspace must already have been scanned, or the
/// wallet database holds no notes to spend.
///
/// Returns the outcome *and* the terminal status side by side, rather than
/// folding a failure into `Err` and dropping the outcome with it. Each
/// Sapling account is broadcast separately, so by the time anything can
/// fail there may already be transactions on-chain; an `Err` return would
/// take their txids with it and show the user a total failure for a sweep
/// that moved real funds — and a retry would then find those notes already
/// spent and appear to do nothing. This is the same split the HD sweep path
/// makes for the same reason (audit Issue E); the caller folds the two back
/// together with `assemble_sweep_outcome`.
pub async fn sweep_imported_wallet(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
) -> (ImportedSweepOutcome, ZeckResult<()>) {
    let mut outcome = ImportedSweepOutcome::default();
    let result =
        sweep_imported_wallet_into(runtime, keys, destination, max_fee_zatoshis, &mut outcome)
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
) -> ZeckResult<()> {
    use crate::imported::imported_transparent_keys;

    // Sapling first: it is usually where the value is, and a failure here
    // must not stop the transparent sweep from being attempted — so its
    // result is held rather than propagated, and the transparent leg runs
    // either way. Whatever the Sapling leg already broadcast is in
    // `outcome` by then and stays there.
    let sapling_result =
        sweep_imported_sapling_leg(runtime, keys, destination, max_fee_zatoshis, outcome).await;
    outcome.sapling_leg_completed = sapling_result.is_ok();

    // Transparent, through the path that needs no account at all.
    let transparent_result = async {
        let transparent = imported_transparent_keys(keys)?;
        if !transparent.is_empty() {
            if let Some(swept) = crate::transparent_recovery::sweep_transparent_only(
                &transparent,
                runtime.network,
                &runtime.lightwalletd_url,
                destination,
                max_fee_zatoshis,
            )
            .await?
            {
                outcome.transparent_txid = Some(swept.txid);
                outcome.transparent_zatoshis = swept.plan.output_zatoshis;
                outcome.transparent_fee_zatoshis = swept.plan.fee_zatoshis;
            }
        }
        Ok(())
    }
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
/// Writes each broadcast txid into `outcome` as it happens, so an abort
/// part-way through still leaves the caller holding the record of what is
/// already on-chain.
async fn sweep_imported_sapling_leg(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    outcome: &mut ImportedSweepOutcome,
) -> ZeckResult<()> {
    use crate::imported::register_imported_accounts;
    use crate::workspace::{consensus_network, open_wallet_db, RecoveryWorkspace};
    use zcash_client_backend::data_api::{chain::ChainState, AccountBirthday};
    use zcash_client_backend::proto::service::RawTransaction;
    use zcash_proofs::prover::LocalTxProver;

    let params = consensus_network(runtime.network);

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
    if !matches!(
        crate::key_source::classify_recovery_route(keys),
        crate::key_source::RecoveryRoute::ImportedAccounts
    ) {
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
    let accounts = {
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
        register_imported_accounts(&mut wallet_db, keys, &birthday)?
    };

    if accounts.is_empty() {
        return Err(ZeckError::Internal(
            "no imported account to sweep from".to_owned(),
        ));
    }

    let recipient = ZcashAddress::try_from_encoded(destination)
        .map_err(|err| ZeckError::InvalidAddress(format!("could not decode destination: {err}")))?;

    // Loaded once for all accounts: the bundled Sapling parameters are
    // ~725 MB, and loading them per key would dominate the sweep.
    let prover = LocalTxProver::bundled();

    for account in &accounts {
        // Every account created from a Sapling key carries its key; the
        // `None` case is the transparent-anchor account, which has no
        // Sapling notes of its own to move.
        let Some(extsk) = account.sapling_extsk.as_ref() else {
            continue;
        };

        let built = {
            let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), params)?;
            build_imported_sapling_sweep(
                &mut wallet_db,
                &params,
                account.wallet_account_id,
                extsk,
                &recipient,
                &prover,
                max_fee_zatoshis,
            )
        };

        match built {
            Ok(tx) => {
                // Every failure between here and the push below aborts the
                // remaining accounts, but `outcome` is the caller's, so the
                // txids of the accounts already broadcast are kept. Stopping
                // rather than continuing is deliberate: a serialization
                // failure or a node rejection is far more likely to be
                // systemic than account-specific, and a retry costs the user
                // nothing — the accounts already swept hold no selectable
                // notes on the second run and are skipped as such.
                let mut raw = Vec::new();
                tx.write(&mut raw).map_err(|err| {
                    ZeckError::TransactionBuild(format!("serializing the Sapling sweep: {err}"))
                })?;
                let (mut client, _endpoint) =
                    crate::lightwalletd::connect_lightwalletd_endpoints_with_retry(
                        &runtime.lightwalletd_url,
                        None,
                    )
                    .await?;
                let response = client
                    .send_transaction(RawTransaction {
                        data: raw,
                        height: 0,
                    })
                    .await
                    .map_err(|err| ZeckError::Broadcast(err.to_string()))?
                    .into_inner();
                if response.error_code != 0 {
                    return Err(ZeckError::Broadcast(format!(
                        "the node rejected the Sapling sweep: {}",
                        response.error_message
                    )));
                }
                outcome.sapling_txids.push(tx.txid().to_string());
            }
            Err(err) => {
                // "Nothing selectable" is the ordinary shape of an account
                // whose Sapling pool is empty or all dust; it must not
                // abort the remaining accounts or the transparent sweep.
                //
                // One shared classifier, in `service`, which is the only
                // one with tests. The local copy here was a second, looser
                // definition of the same predicate.
                if !crate::service::is_insufficient_funds_error(&err.to_string()) {
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod fee_cap_tests {
    use super::*;

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
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            data_dir: tempdir.path().to_owned(),
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
            outcome.sapling_txids.is_empty(),
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
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            data_dir: tempdir.path().to_owned(),
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
