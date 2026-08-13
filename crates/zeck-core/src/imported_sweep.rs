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
#[allow(clippy::too_many_arguments)]
pub fn build_imported_sapling_sweep<P>(
    wallet_db: &mut crate::imported::ArgosWalletDb,
    params: &P,
    account_id: AccountUuid,
    extsk: &ExtendedSpendingKey,
    destination: &ZcashAddress,
    prover: &LocalTxProver,
) -> ZeckResult<Transaction>
where
    P: zcash_protocol::consensus::Parameters + Clone,
{
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
    TransactionExtractor::new(pczt)
        .with_sapling(&spend_vk, &output_vk)
        .with_orchard(&orchard_vk)
        .extract()
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("extracting the signed transaction: {err:?}"))
        })
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
    /// Accounts whose Sapling pool was empty or all dust. Counted so the
    /// caller can distinguish "nothing to sweep" from "swept nothing".
    pub sapling_accounts_with_nothing_to_sweep: usize,
    pub transparent_txid: Option<String>,
    pub transparent_zatoshis: u64,
    pub transparent_fee_zatoshis: u64,
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
pub async fn sweep_imported_wallet(
    runtime: &crate::models::RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
) -> ZeckResult<ImportedSweepOutcome> {
    use crate::imported::{imported_transparent_keys, register_imported_accounts};
    use crate::workspace::{consensus_network, open_wallet_db, RecoveryWorkspace};
    use zcash_client_backend::data_api::{chain::ChainState, AccountBirthday};
    use zcash_client_backend::proto::service::RawTransaction;
    use zcash_proofs::prover::LocalTxProver;

    let mut outcome = ImportedSweepOutcome::default();
    let params = consensus_network(runtime.network);
    let workspace = RecoveryWorkspace::from_runtime(runtime)?;

    // Sapling first: it is usually where the value is, and a failure here
    // should not stop the transparent sweep from being attempted.
    //
    // Every account, not just the first. `register_imported_accounts` creates
    // one account per Sapling key and `run_imported_scan` reports a balance
    // for each, so sweeping only `keys.sapling.first()` showed the user a full
    // balance and moved one key's notes, with the shortfall reported nowhere.
    // A zcashd wallet accumulates a `sapzkey` record per `z_getnewaddress`,
    // so multiple keys is the ordinary case, not an exotic one.
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

    if !keys.sapling.is_empty() {
        if accounts.is_empty() {
            return Err(ZeckError::Internal(
                "no imported account to sweep from".to_owned(),
            ));
        }

        let recipient = ZcashAddress::try_from_encoded(destination).map_err(|err| {
            ZeckError::InvalidAddress(format!("could not decode destination: {err}"))
        })?;

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
                )
            };

            match built {
                Ok(tx) => {
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
                    // Lowercased before matching: the backend spells this
                    // "Insufficient funds" in some variants, which a
                    // case-sensitive `contains("insufficient")` misses — and a
                    // miss here abandons every later account along with this
                    // one.
                    let message = err.to_string().to_ascii_lowercase();
                    if !message.contains("insufficientfunds") && !message.contains("insufficient") {
                        return Err(err);
                    }
                    outcome.sapling_accounts_with_nothing_to_sweep += 1;
                }
            }
        }
    }

    // Transparent, through the path that needs no account at all.
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

    Ok(outcome)
}
