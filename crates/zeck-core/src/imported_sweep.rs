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
use zcash_proofs::prover::LocalTxProver;
use zcash_keys::keys::sapling::ExtendedSpendingKey;
use zcash_primitives::transaction::{builder::BundlePadding, Transaction};
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

    let pczt = Prover::new(pczt)
        .create_sapling_proofs(prover, prover)
        .map_err(|err| ZeckError::TransactionBuild(format!("proving the Sapling bundle: {err:?}")))?
        .finish();

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

    TransactionExtractor::new(pczt)
        .with_sapling(&spend_vk, &output_vk)
        .extract()
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("extracting the signed transaction: {err:?}"))
        })
}
