use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex as StdMutex},
    time::Instant,
};

use prost::Message;
use secrecy::SecretString;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Duration,
};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions,
            input_selection::{GreedyInputSelector, LockedInputPolicy, SpendPolicy},
            propose_send_max_transfer, propose_shielding, propose_transfer, ConfirmationsPolicy,
            SpendingKeys,
        },
        CoinbaseFilter, MaxSpendMode, TransactionStatus, WalletRead, WalletWrite,
    },
    fees::{standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule},
    proto::service::compact_tx_streamer_client::CompactTxStreamerClient,
    wallet::OvkPolicy,
};
// The crate re-export is deprecated in favor of the standalone `zip321` crate,
// but that crate is not a direct dependency; the re-export resolves to the
// identical `zip321` 0.7.0 already in the dependency tree. If the re-export is
// removed upstream, or if zip321 is needed in more than this one site, add
// `zip321` as a direct dependency — currently reused transitively to avoid
// growing the dependency tree.
#[allow(deprecated)]
use zcash_client_backend::zip321;
use zcash_client_sqlite::{util::SystemClock, AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::keys::UnifiedSpendingKey;
#[cfg(test)]
use zcash_primitives::transaction::fees::zip317::MINIMUM_FEE;
use zcash_primitives::transaction::{fees::zip317::MARGINAL_FEE, TxId};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis, ShieldedPool};

use crate::{
    address::validate_destination_address,
    broadcast::{
        submit_prepared_transaction, BroadcastStore, DurableBroadcastLog, LightwalletdSubmitter,
        PreparedTransaction, TxObservationState, TxObserver,
    },
    derivation::{legacy_transparent_account_key_from_seed, legacy_transparent_secret_key},
    error::{ZeckError, ZeckResult},
    key_source::{KeySource, KeySourceFingerprint, SeedKeySource},
    lightwalletd::{
        connect_lightwalletd_endpoints_with_retry, validate_lightwalletd_network,
        validated_lightwalletd_endpoints, LightwalletdTxObserver,
    },
    models::{
        ConfirmationEndpoint, ProposedTx, ProposedTxKind, ReviewedSweepProposal, RuntimeScanConfig,
        ScanConfig, ScanHandle, ScanPhase, ScanProgress, SkippedSweepAccount, SweepOutcome,
        SweepProposal, SweepProposalId, SweepRequest, TxBroadcastResult, TxLifecycleState,
    },
    scan::{
        refresh_scan_progress, run_recovery_scan, run_wallet_sync_with_retry,
        validate_wallet_output_identities, ScanTaskState, SharedScanTaskState, TrackedAccount,
        TrackedSpendAuthority,
    },
    workspace::{consensus_network, open_wallet_db, RecoveryWorkspace},
};

mod cleanup;
mod confirmation;

#[cfg(test)]
use cleanup::cleanup_marker_path;
use cleanup::{recover_interrupted_cleanup, refuse_interrupted_cleanup};
use confirmation::{broadcast_transactions, chain_tip_height};
#[cfg(test)]
use confirmation::{
    is_distinct_lightwalletd_endpoint, submit_and_confirm_batch, wait_for_confirmation,
    ConfirmationResult,
};

const RECOVERY_MEMO_DEFAULT: &str = "Argos recovery";
const SESSION_RETENTION_SECS: u64 = 300;
/// Maximum iterations for the donation-split fee-convergence loop. The extra
/// donation output adds at most one ZIP-317 marginal action, so convergence is
/// expected within 2 iterations; 4 leaves headroom.
const MAX_FEE_CONVERGENCE_ITERS: usize = 8;

/// ZIP-317 conventional fee floor in zatoshis: `marginal_fee (5000) *
/// grace_actions (2)`. A shielded send can never cost less than this, so it is
/// a safe early dust refusal. Actual reviewed fees come from the built
/// proposal, including every selected ZIP-317 action.
pub(crate) const MIN_SHIELDED_SEND_FEE_ZATOSHIS: u64 = 10_000;

/// Whether a balance is worth sweeping: it must *strictly exceed* the ZIP-317
/// fee floor. At or below the floor, the shielding/sweep transaction's fee would
/// consume the entire balance, so building it fails ("Insufficient funds:
/// required 10000 zatoshis, but only 0 were available").
///
/// This predicate avoids asking the builder to spend value beneath the lower
/// bound; the final quote still comes from the builder's selected action set.
fn balance_covers_sweep_fee(zatoshis: u64) -> bool {
    zatoshis > MIN_SHIELDED_SEND_FEE_ZATOSHIS
}

/// Whether a proposal-build error reflects "insufficient funds" — the input
/// selector found no spendable value that clears the ZIP-317 fee floor.
///
/// `balance_covers_sweep_fee` gates on an account's *summed* balance, but a
/// proposal can still come up empty: the value may be many sub-threshold dust
/// UTXOs the selector won't pick, or transparent funds at addresses outside the
/// two shieldable receivers. Such an account is simply unsweepable, so the
/// sweep must *skip* it (and continue with the other accounts) instead of
/// aborting the whole multi-account sweep on a `?`. Matched on the error text
/// because the underlying `zcash_client_backend` proposal error is a deep
/// generic type with no stable typed variant to match here; a false match only
/// downgrades a fatal abort to a skip (recorded), never the reverse.
pub(crate) fn is_insufficient_funds_error(message: &str) -> bool {
    message.to_ascii_lowercase().contains("insufficient funds")
}

/// The donation recipient used during sweep *execution* on a given network.
///
/// Mainnet uses the baked-in [`crate::donation::DONATION_ADDRESS`]; testnet
/// disables the donation feature (empty string). Under the dev/test-only
/// `argos-network` feature ONLY, the testnet branch honors
/// `ARGOS_TEST_DONATION_ADDRESS` so the regtest harness can drive the
/// donation-split path end-to-end with a regtest UA (the baked mainnet address
/// can't be used on regtest). Production builds compile that override out — same
/// rationale as the rest of the `argos-network` escape hatch — so testnet
/// donation stays off in released binaries.
fn execution_donation_address(network: crate::models::ZeckNetwork) -> String {
    match network {
        crate::models::ZeckNetwork::Mainnet => crate::donation::DONATION_ADDRESS.to_owned(),
        crate::models::ZeckNetwork::Testnet => {
            #[cfg(feature = "argos-network")]
            {
                std::env::var("ARGOS_TEST_DONATION_ADDRESS").unwrap_or_default()
            }
            #[cfg(not(feature = "argos-network"))]
            {
                String::new()
            }
        }
    }
}

/// The concrete wallet database type used throughout the execution path.
type SweepWalletDb =
    WalletDb<rusqlite::Connection, crate::workspace::ArgosParams, SystemClock, rand_core::OsRng>;
type HdSweepProposal = zcash_client_backend::proposal::Proposal<StandardFeeRule, Infallible>;
type ImportedSweepProposal =
    zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>;
const CONFIRMATION_POLL_INTERVAL_SECS: u64 = 5;
const CONFIRMATION_POLL_ATTEMPTS: u32 = 24;
const MAX_REVIEWED_SWEEPS: usize = 16;

/// The proposal that was priced is also the proposal given to the signer.
/// A post-sync plan is rebuilt and compared with the reviewed input identity
/// before any leg is allowed to construct or broadcast a transaction.
enum ExactSweepLeg {
    HdShield {
        account_index: u32,
        proposal: HdSweepProposal,
    },
    HdSend {
        account_index: u32,
        proposal: ImportedSweepProposal,
        donation_zatoshis: u64,
    },
    ImportedSapling {
        account_index: u32,
        account_id: AccountUuid,
        proposal: ImportedSweepProposal,
    },
    DirectTransparent {
        account_index: u32,
        utxos: Vec<crate::transparent_recovery::TransparentUtxo>,
        plan: crate::transparent_recovery::TransparentSweepPlan,
        target_height: u32,
        version: u32,
    },
}

/// Fee authority follows the signing route, not the public display row:
/// a mixed direct sweep and HD send can share both display account and kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ExactFeeKey {
    HdShield(u32),
    HdSend(u32),
    ImportedSapling(AccountUuid),
    DirectTransparent,
}

#[derive(Clone)]
struct ExactLegFees(HashMap<ExactFeeKey, u64>);

impl ExactLegFees {
    fn from_pairs(pairs: impl IntoIterator<Item = (ExactFeeKey, u64)>) -> ZeckResult<Self> {
        let mut fees = HashMap::new();
        for (key, fee) in pairs {
            if fees.insert(key, fee).is_some() {
                return Err(ZeckError::StaleSweepProposal(format!(
                    "duplicate validated sweep fee for {key:?}"
                )));
            }
        }
        Ok(Self(fees))
    }

    fn from_legs(legs: &[ExactSweepLeg]) -> ZeckResult<Self> {
        Self::from_pairs(
            legs.iter()
                .map(|leg| {
                    Ok(match leg {
                        ExactSweepLeg::HdShield {
                            account_index,
                            proposal,
                        } => (
                            ExactFeeKey::HdShield(*account_index),
                            proposal_fee_zatoshis(proposal)?,
                        ),
                        ExactSweepLeg::HdSend {
                            account_index,
                            proposal,
                            ..
                        } => (
                            ExactFeeKey::HdSend(*account_index),
                            proposal_fee_zatoshis(proposal)?,
                        ),
                        ExactSweepLeg::ImportedSapling {
                            account_id,
                            proposal,
                            ..
                        } => (
                            ExactFeeKey::ImportedSapling(*account_id),
                            proposal_fee_zatoshis(proposal)?,
                        ),
                        ExactSweepLeg::DirectTransparent { plan, .. } => {
                            (ExactFeeKey::DirectTransparent, plan.fee_zatoshis)
                        }
                    })
                })
                .collect::<ZeckResult<Vec<_>>>()?,
        )
    }

    fn require(&self, key: ExactFeeKey) -> ZeckResult<u64> {
        self.0.get(&key).copied().ok_or_else(|| {
            ZeckError::StaleSweepProposal(format!("validated sweep fee is missing for {key:?}"))
        })
    }

    fn imported_sapling_map(&self) -> HashMap<AccountUuid, u64> {
        self.0
            .iter()
            .filter_map(|(key, fee)| match key {
                ExactFeeKey::ImportedSapling(account_id) => Some((*account_id, *fee)),
                _ => None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalLegKind {
    HdShield,
    HdSend,
    ImportedSapling,
    DirectTransparent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalLegInputs {
    kind: CanonicalLegKind,
    account_index: u32,
    /// Builder proposal: selected inputs, output pools, amounts, fees, change,
    /// and version. Tip/anchor heights are normalized; direct sweeps encode
    /// their exact UTXO slice and output plan.
    backend_plan: Vec<u8>,
}

struct ExactSweepPlan {
    quote: SweepProposal,
    legs: Vec<ExactSweepLeg>,
    direct_account_index: Option<u32>,
    network: crate::models::ZeckNetwork,
}

impl ExactSweepPlan {
    fn canonical_inputs(&self) -> Vec<CanonicalLegInputs> {
        self.legs
            .iter()
            .map(|leg| {
                let (kind, account_index, backend_plan) = match leg {
                    ExactSweepLeg::HdShield {
                        account_index,
                        proposal,
                    } => (
                        CanonicalLegKind::HdShield,
                        *account_index,
                        canonical_proposal(proposal, self.network),
                    ),
                    ExactSweepLeg::HdSend {
                        account_index,
                        proposal,
                        ..
                    } => (
                        CanonicalLegKind::HdSend,
                        *account_index,
                        canonical_proposal(proposal, self.network),
                    ),
                    ExactSweepLeg::ImportedSapling {
                        account_index,
                        proposal,
                        ..
                    } => (
                        CanonicalLegKind::ImportedSapling,
                        *account_index,
                        canonical_proposal(proposal, self.network),
                    ),
                    ExactSweepLeg::DirectTransparent {
                        account_index,
                        utxos,
                        plan,
                        version,
                        ..
                    } => (
                        CanonicalLegKind::DirectTransparent,
                        *account_index,
                        canonical_direct_plan(utxos, plan, *version),
                    ),
                };
                CanonicalLegInputs {
                    kind,
                    account_index,
                    backend_plan,
                }
            })
            .collect()
    }
}

fn canonical_proposal<NoteRef: std::fmt::Debug>(
    proposal: &zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>,
    network: crate::models::ZeckNetwork,
) -> Vec<u8> {
    let encoded = canonical_proposal_proto(
        zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(proposal),
    );
    let mut bytes = Vec::with_capacity(encoded.len() + 64);
    bytes.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&encoded);
    let version = proposal.proposed_version().unwrap_or_else(|| {
        let branch = zcash_protocol::consensus::BranchId::for_height(
            &consensus_network(network),
            BlockHeight::from_u32(proposal.min_target_height().into()),
        );
        zcash_primitives::transaction::TxVersion::suggested_for_branch(branch)
    });
    bytes.extend_from_slice(&version.header().to_le_bytes());
    // The public protobuf intentionally omits the wallet's local note ID and
    // transparent script/owner. Bind those too: they are consumed by signing.
    bytes.extend_from_slice(&(proposal.steps().len() as u64).to_le_bytes());
    for step in proposal.steps().iter() {
        let mut local_inputs = Vec::new();
        for input in step.transparent_inputs() {
            let mut identity = vec![0];
            identity.extend_from_slice(input.outpoint().hash());
            identity.extend_from_slice(&input.outpoint().n().to_le_bytes());
            input
                .txout()
                .write(&mut identity)
                .expect("serializing TxOut into Vec cannot fail");
            identity.extend_from_slice(&crate::transparent_recovery::transparent_address_identity(
                input.recipient_address(),
            ));
            local_inputs.push(identity);
        }
        for input in step
            .shielded_inputs()
            .iter()
            .flat_map(|shielded| shielded.notes().iter())
        {
            local_inputs.push(canonical_shielded_note_identity(
                input.txid().as_ref(),
                input.output_index(),
                shielded_pool_tag(input.note().pool()),
                u64::from(input.note().value()),
                input.internal_note_id(),
            ));
        }
        local_inputs.sort();
        bytes.extend_from_slice(&(local_inputs.len() as u64).to_le_bytes());
        for identity in local_inputs {
            bytes.extend_from_slice(&(identity.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&identity);
        }
    }
    bytes
}

/// A stable tag for a shielded pool in canonical identities.
fn shielded_pool_tag(pool: ShieldedPool) -> u8 {
    match pool {
        ShieldedPool::Sapling => 0,
        ShieldedPool::Orchard => 1,
        ShieldedPool::Ironwood => 2,
    }
}

fn canonical_shielded_note_identity<NoteRef: std::fmt::Debug>(
    txid: &[u8],
    output_index: u16,
    pool: u8,
    value: u64,
    local_id: &NoteRef,
) -> Vec<u8> {
    let mut identity = vec![1];
    identity.extend_from_slice(&(txid.len() as u64).to_le_bytes());
    identity.extend_from_slice(txid);
    identity.extend_from_slice(&output_index.to_le_bytes());
    identity.push(pool);
    identity.extend_from_slice(&value.to_le_bytes());
    // The wallet-local note ID (zcash_client_sqlite's ReceivedNoteId) is an
    // opaque upstream type with no byte accessor, so its Debug text is the
    // only available encoding. The note is already pinned by txid, output
    // index, pool, and value above; this only binds the local row too.
    let local_id = format!("{local_id:?}");
    identity.extend_from_slice(&(local_id.len() as u64).to_le_bytes());
    identity.extend_from_slice(local_id.as_bytes());
    identity
}

fn canonical_proposal_proto(
    mut proposal: zcash_client_backend::proto::proposal::Proposal,
) -> Vec<u8> {
    // A normal tip advance changes these fields without changing the user's
    // reviewed transaction or selected coins. Execution signs the fresh
    // post-sync proposal, so retain its current anchor but ignore the height
    // drift when comparing review authority.
    proposal.min_target_height = 0;
    for step in &mut proposal.steps {
        step.anchor_height = 0;
    }
    proposal.encode_to_vec()
}

fn canonical_direct_plan(
    utxos: &[crate::transparent_recovery::TransparentUtxo],
    plan: &crate::transparent_recovery::TransparentSweepPlan,
    version: u32,
) -> Vec<u8> {
    let mut inputs = utxos
        .iter()
        .map(canonical_transparent_input)
        .collect::<Vec<_>>();
    inputs.sort();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    for input in inputs {
        bytes.extend_from_slice(&(input.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&input);
    }
    bytes.extend_from_slice(&plan.total_input_zatoshis.to_le_bytes());
    bytes.extend_from_slice(&plan.fee_zatoshis.to_le_bytes());
    bytes.extend_from_slice(&plan.output_zatoshis.to_le_bytes());
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes
}

fn canonical_transparent_input(utxo: &crate::transparent_recovery::TransparentUtxo) -> Vec<u8> {
    let mut bytes = utxo.outpoint.hash().to_vec();
    bytes.extend_from_slice(&utxo.outpoint.n().to_le_bytes());
    utxo.txout
        .write(&mut bytes)
        .expect("serializing a TxOut into Vec cannot fail");
    bytes.extend_from_slice(&crate::transparent_recovery::transparent_address_identity(
        &utxo.address,
    ));
    bytes
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SweepAccountSnapshot {
    account_index: u32,
    sapling_zatoshis: u64,
    orchard_zatoshis: u64,
    transparent_zatoshis: u64,
    transparent_utxo_count: u32,
    total_zatoshis: u64,
}

/// Only values that change spend authority belong here. Progress text and
/// timing can change between review and execution without changing balances.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SweepBalanceSnapshot {
    scan_handle: String,
    source_fingerprint: KeySourceFingerprint,
    network: crate::models::ZeckNetwork,
    workspace_root: std::path::PathBuf,
    synced_to_height: Option<u64>,
    accounts: Vec<SweepAccountSnapshot>,
    total_zatoshis: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedAuthoritySnapshot {
    account_index: u32,
    wallet_account_id: AccountUuid,
    spend_authority: TrackedSpendAuthority,
    transparent_receivers: Vec<zcash_transparent::address::TransparentAddress>,
    standalone_transparent_receivers: Vec<zcash_transparent::address::TransparentAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SweepAuthoritySnapshot {
    tracked: Vec<TrackedAuthoritySnapshot>,
    standalone_sapling_indices: Vec<usize>,
    standalone_transparent_indices: Vec<usize>,
    standalone_transparent_balances: Vec<(u32, crate::scan::StandaloneTransparentBalance)>,
}

impl SweepAuthoritySnapshot {
    fn capture(state: &ScanTaskState) -> Self {
        let mut tracked = state
            .tracked_accounts
            .iter()
            .map(|account| {
                let mut transparent_receivers = account.transparent_receivers.clone();
                transparent_receivers.sort_unstable();
                let mut standalone_transparent_receivers =
                    account.standalone_transparent_receivers.clone();
                standalone_transparent_receivers.sort_unstable();
                TrackedAuthoritySnapshot {
                    account_index: account.derived.index,
                    wallet_account_id: account.wallet_account_id,
                    spend_authority: account.spend_authority,
                    transparent_receivers,
                    standalone_transparent_receivers,
                }
            })
            .collect::<Vec<_>>();
        tracked.sort_by_key(|account| account.account_index);
        let mut standalone_transparent_balances = state
            .standalone_transparent_balances
            .iter()
            .map(|(&index, &balance)| (index, balance))
            .collect::<Vec<_>>();
        standalone_transparent_balances.sort_by_key(|(index, _)| *index);
        Self {
            tracked,
            standalone_sapling_indices: state.standalone_sapling_indices.clone(),
            standalone_transparent_indices: state.standalone_transparent_indices.clone(),
            standalone_transparent_balances,
        }
    }
}

impl SweepBalanceSnapshot {
    fn capture(session: &ScanSession, progress: &ScanProgress) -> Self {
        let mut accounts: Vec<_> = progress
            .accounts
            .iter()
            .map(|account| SweepAccountSnapshot {
                account_index: account.account_index,
                sapling_zatoshis: account.sapling_zatoshis,
                orchard_zatoshis: account.orchard_zatoshis,
                transparent_zatoshis: account.transparent_zatoshis,
                transparent_utxo_count: account.transparent_utxo_count,
                total_zatoshis: account.total_zatoshis,
            })
            .collect();
        accounts.sort_by_key(|account| account.account_index);
        Self {
            scan_handle: progress.handle.id.clone(),
            source_fingerprint: session.source_fingerprint,
            network: session.runtime.network,
            workspace_root: session.workspace_root.clone(),
            synced_to_height: progress.synced_to_height,
            accounts,
            total_zatoshis: progress
                .summary
                .as_ref()
                .map(|summary| summary.total_zatoshis),
        }
    }
}

struct ReviewedSweepIntent {
    request: SweepRequest,
    snapshot: SweepBalanceSnapshot,
    /// Spend authority and standalone partition the quote was built from.
    /// `None` only for intents built in unit tests that check balances
    /// alone; [`issue_reviewed_proposal`] and execution refuse it.
    authority: Option<SweepAuthoritySnapshot>,
    quoted_transactions: Vec<ProposedTx>,
    quoted_proposal: Option<SweepProposal>,
    quoted_inputs: Vec<CanonicalLegInputs>,
    /// Total fee of the quote the user reviewed. Set only by binding the
    /// service's own quote; no caller input reaches it.
    reviewed_fee_zatoshis: Option<u64>,
    /// Per-leg fees of the plan the user reviewed, captured at propose time.
    /// Execution compares each leg it actually builds against these, never
    /// against a fee recomputed from the execute-time plan.
    reviewed_leg_fees: Option<ExactLegFees>,
}

impl ReviewedSweepIntent {
    fn capture(request: SweepRequest, session: &ScanSession, progress: &ScanProgress) -> Self {
        Self {
            request,
            snapshot: SweepBalanceSnapshot::capture(session, progress),
            authority: None,
            quoted_transactions: Vec::new(),
            quoted_proposal: None,
            quoted_inputs: Vec::new(),
            reviewed_fee_zatoshis: None,
            reviewed_leg_fees: None,
        }
    }

    #[cfg(test)]
    fn capture_reviewed(
        request: SweepRequest,
        proposal: &SweepProposal,
        session: &ScanSession,
        progress: &ScanProgress,
    ) -> Self {
        let mut intent = Self::capture(request, session, progress);
        intent.bind_quote(proposal);
        intent
    }

    fn bind_quote(&mut self, proposal: &SweepProposal) {
        self.reviewed_fee_zatoshis = Some(proposal.total_fee_zatoshis);
        self.request
            .max_fee_zatoshis
            .get_or_insert(proposal.total_fee_zatoshis);
        self.quoted_transactions = proposal.transactions.clone();
        self.quoted_proposal = Some(proposal.clone());
    }

    fn require_current_fee(&self, current_fee_zatoshis: u64) -> ZeckResult<()> {
        let reviewed = self
            .reviewed_fee_zatoshis
            .ok_or_else(|| ZeckError::StaleSweepProposal("reviewed fee is missing".to_owned()))?;
        if reviewed != current_fee_zatoshis {
            return Err(ZeckError::FeeQuoteChanged {
                reviewed,
                current: current_fee_zatoshis,
            });
        }
        Ok(())
    }

    fn require_current_quote(&self, current: &SweepProposal) -> ZeckResult<()> {
        self.require_current_fee(current.total_fee_zatoshis)?;
        if self.quoted_proposal.as_ref() != Some(current) {
            return Err(ZeckError::StaleSweepProposal(
                "sweep quote changed after review".to_owned(),
            ));
        }
        Ok(())
    }

    fn bind_plan(&mut self, plan: &ExactSweepPlan) -> ZeckResult<()> {
        self.bind_quote(&plan.quote);
        self.quoted_inputs = plan.canonical_inputs();
        self.reviewed_leg_fees = Some(ExactLegFees::from_legs(&plan.legs)?);
        Ok(())
    }

    /// Authorize the execute-time plan: it must be the reviewed plan (a fee
    /// difference is reported as FeeQuoteChanged), and only then is the fee
    /// ceiling applied, so a changed fee never surfaces as MaxFeeExceeded.
    /// Returns the reviewed per-leg fees for the leg executors.
    fn authorize_current_plan(&self, current: &ExactSweepPlan) -> ZeckResult<ExactLegFees> {
        self.require_current_plan(current)?;
        enforce_max_fee(
            current.quote.total_fee_zatoshis,
            self.request.max_fee_zatoshis,
        )?;
        let reviewed = self.reviewed_leg_fees.clone().ok_or_else(|| {
            ZeckError::StaleSweepProposal("reviewed per-leg fees are missing".to_owned())
        })?;
        let current_keys = ExactLegFees::from_legs(&current.legs)?
            .0
            .into_keys()
            .collect::<HashSet<_>>();
        if reviewed.0.keys().copied().collect::<HashSet<_>>() != current_keys {
            return Err(ZeckError::StaleSweepProposal(
                "the executable legs no longer match the reviewed legs".to_owned(),
            ));
        }
        Ok(reviewed)
    }

    fn require_current_plan(&self, current: &ExactSweepPlan) -> ZeckResult<()> {
        self.require_current_quote(&current.quote)?;
        if self.quoted_inputs != current.canonical_inputs() {
            return Err(ZeckError::StaleSweepProposal(
                "selected sweep inputs changed after review".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_current_authority(&self, state: &ScanTaskState) -> ZeckResult<()> {
        if self.authority.as_ref() != Some(&SweepAuthoritySnapshot::capture(state)) {
            return Err(ZeckError::StaleSweepProposal(
                "scan spend authority or standalone balance changed".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn capture_from_state(
        request: SweepRequest,
        proposal: &SweepProposal,
        session: &ScanSession,
        state: &ScanTaskState,
    ) -> Self {
        let mut intent = Self::capture(request, session, &state.progress);
        intent.bind_quote(proposal);
        intent.authority = Some(SweepAuthoritySnapshot::capture(state));
        intent
    }

    /// Whether the scan this intent was reviewed against still stands: the
    /// scan is complete and every balance, height, network, workspace and
    /// source identity in the snapshot is unchanged. The session object
    /// itself is immutable, so its handle and key source are not re-checked
    /// here; a different session shows up as a different snapshot.
    fn validate_state(&self, session: &ScanSession, progress: &ScanProgress) -> ZeckResult<()> {
        if progress.phase != ScanPhase::Complete {
            return Err(ZeckError::StaleSweepProposal(
                "scan is no longer complete".to_owned(),
            ));
        }
        if self.snapshot != SweepBalanceSnapshot::capture(session, progress) {
            return Err(ZeckError::StaleSweepProposal(
                "source, scan, workspace, or balance changed".to_owned(),
            ));
        }
        Ok(())
    }

    /// [`Self::validate_state`] plus the spend-authority partition: which
    /// accounts sign through the seed and which through a standalone key,
    /// and the standalone transparent balances. The total can stay the same
    /// while the split moves, and the split decides who signs what.
    fn validate_scan_state(&self, session: &ScanSession, state: &ScanTaskState) -> ZeckResult<()> {
        self.validate_state(session, &state.progress)?;
        self.require_current_authority(state)
    }
}

#[cfg(test)]
tokio::task_local! {
    /// Runs inside `propose_sweep` after the quote is built and before its id
    /// is issued. Task-local so parallel tests cannot see each other's hook.
    static PROPOSE_AFTER_BUILD: Box<dyn Fn(&ScanSession) + Send + Sync>;
    /// Replaces the lightwalletd tip and UTXO lookup in
    /// `attach_direct_sweep_leg`, so offline tests reach the review checks
    /// that follow it instead of a network error.
    static DIRECT_LEG_CHAIN: (u32, Vec<crate::transparent_recovery::TransparentUtxo>);
}

#[cfg(any(test, feature = "argos-network"))]
tokio::task_local! {
    /// A fixed pause between per-account broadcasts. Set only by
    /// `execute_sweep_with_test_pause`, so the R-S29 crash test
    /// (`argos-sweep-helper`) can SIGKILL in the gap deterministically.
    static PAUSE_BETWEEN_BROADCASTS: std::time::Duration;
}

/// A no-op in released builds; inside `PAUSE_BETWEEN_BROADCASTS.scope` it
/// sleeps for the scoped duration.
async fn pause_between_broadcasts() {
    #[cfg(any(test, feature = "argos-network"))]
    if let Ok(pause) = PAUSE_BETWEEN_BROADCASTS.try_with(|pause| *pause) {
        tokio::time::sleep(pause).await;
    }
}

/// Store a reviewed intent and issue its id, but only if `current` scan state
/// still matches the state it was reviewed against. Proposal construction
/// can read a wallet and take time; a progress refresh during that work must
/// invalidate the quote before it is issued. The only way an id is stored.
async fn issue_reviewed_proposal(
    session: &ScanSession,
    intent: ReviewedSweepIntent,
    current: &ScanTaskState,
) -> ZeckResult<SweepProposalId> {
    intent.validate_scan_state(session, current)?;
    let proposal_id = SweepProposalId(uuid::Uuid::new_v4().to_string());
    session
        .reviewed_sweeps
        .lock()
        .await
        .insert(proposal_id.clone(), intent);
    Ok(proposal_id)
}

#[derive(Default)]
struct ReviewedSweepStore {
    entries: VecDeque<(SweepProposalId, ReviewedSweepIntent)>,
}

impl ReviewedSweepStore {
    fn insert(&mut self, id: SweepProposalId, intent: ReviewedSweepIntent) {
        if self.entries.len() == MAX_REVIEWED_SWEEPS {
            self.entries.pop_front();
        }
        self.entries.push_back((id, intent));
    }

    fn take(&mut self, id: &SweepProposalId) -> ZeckResult<ReviewedSweepIntent> {
        let index = self
            .entries
            .iter()
            .position(|(stored_id, _)| stored_id == id)
            .ok_or(ZeckError::UnknownSweepProposal)?;
        Ok(self
            .entries
            .remove(index)
            .expect("position came from entries")
            .1)
    }
}

struct ScanSession {
    source_fingerprint: KeySourceFingerprint,
    state: SharedScanTaskState,
    runtime: RuntimeScanConfig,
    started_at: Instant,
    task: Mutex<Option<JoinHandle<()>>>,
    workspace_root: std::path::PathBuf,
    reviewed_sweeps: Mutex<ReviewedSweepStore>,
}

type SharedScanSession = Arc<ScanSession>;

#[derive(Clone, Default)]
pub struct RecoveryService {
    sessions: Arc<RwLock<HashMap<String, SharedScanSession>>>,
    workspace_gates: Arc<StdMutex<HashMap<std::path::PathBuf, Arc<Mutex<()>>>>>,
    last_sweep_outcomes: Arc<Mutex<HashMap<String, SweepOutcome>>>,
    cleanup_retry: Arc<Mutex<HashMap<std::path::PathBuf, std::path::PathBuf>>>,
    reconciliation_rescan_required: Arc<Mutex<HashSet<String>>>,
}

fn journal_states_changed(
    previous_states: &HashMap<String, TxLifecycleState>,
    log: &DurableBroadcastLog,
) -> bool {
    log.records()
        .iter()
        .any(|record| previous_states.get(&record.prepared.txid.to_string()) != Some(&record.state))
}

/// Resolve aliases in the existing parent even before a scan creates its
/// workspace, so all handles for one on-disk wallet share a single gate.
fn canonical_workspace_identity(root: &std::path::Path) -> ZeckResult<std::path::PathBuf> {
    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|err| ZeckError::Storage(format!("finding current directory: {err}")))?
            .join(root)
    };
    let mut candidate = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match candidate.canonicalize() {
            Ok(mut canonical) => {
                for component in missing.into_iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let component = candidate.file_name().ok_or_else(|| {
                    ZeckError::Storage(format!("cannot resolve workspace {}", root.display()))
                })?;
                missing.push(component.to_owned());
                candidate = candidate.parent().ok_or_else(|| {
                    ZeckError::Storage(format!("cannot resolve workspace {}", root.display()))
                })?;
            }
            Err(err) => {
                return Err(ZeckError::Storage(format!(
                    "resolving workspace {}: {err}",
                    root.display()
                )));
            }
        }
    }
}

/// Stable, cross-process exclusion for every workspace operation. It is
/// separate from the broadcast journal lock because a sweep opens that lock
/// after syncing and must not recursively acquire the same SQLite lock.
pub struct NetworkOperationGuard {
    _connection: rusqlite::Connection,
    data_dir: std::path::PathBuf,
    network: crate::models::ZeckNetwork,
}

impl NetworkOperationGuard {
    pub fn acquire(
        data_dir: &std::path::Path,
        network: crate::models::ZeckNetwork,
    ) -> ZeckResult<Self> {
        let data_dir = canonical_workspace_identity(data_dir)?;
        let network_root = network_registry_root(&data_dir, network)?;
        std::fs::create_dir_all(&network_root).map_err(|err| {
            ZeckError::Storage(format!(
                "creating network registry {}: {err}",
                network_root.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&network_root, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| {
                    ZeckError::Storage(format!(
                        "securing network registry {}: {err}",
                        network_root.display()
                    ))
                })?;
        }
        let path = network_root.join(".workspace-operations.sqlite");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path).map_err(|err| {
            ZeckError::Storage(format!("opening workspace lock {}: {err}", path.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |err| {
                    ZeckError::Storage(format!("securing workspace lock {}: {err}", path.display()))
                },
            )?;
        }
        let connection = rusqlite::Connection::open(&path).map_err(|err| {
            ZeckError::Storage(format!("opening workspace lock {}: {err}", path.display()))
        })?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|err| ZeckError::Storage(format!("setting workspace lock timeout: {err}")))?;
        connection
            .execute_batch("BEGIN EXCLUSIVE TRANSACTION")
            .map_err(|err| {
                ZeckError::ScanNotReady(format!(
                    "network registry {} is in use by another process: {err}",
                    network_root.display()
                ))
            })?;
        Ok(Self {
            _connection: connection,
            data_dir,
            network,
        })
    }

    pub fn broadcast_log_path(&self) -> ZeckResult<std::path::PathBuf> {
        network_broadcast_log_path(&self.data_dir, self.network)
    }

    /// Open the network registry. The caller already holds the network-wide
    /// operation lock, so no other Argos operation can append concurrently.
    pub fn open_broadcast_log(&self) -> ZeckResult<DurableBroadcastLog> {
        DurableBroadcastLog::open(self.broadcast_log_path()?)
    }
}

fn network_registry_root(
    data_dir: &std::path::Path,
    network: crate::models::ZeckNetwork,
) -> ZeckResult<std::path::PathBuf> {
    Ok(canonical_workspace_identity(data_dir)?
        .join(network.label())
        .join(".broadcast-registry"))
}

pub fn network_broadcast_log_path(
    data_dir: &std::path::Path,
    network: crate::models::ZeckNetwork,
) -> ZeckResult<std::path::PathBuf> {
    Ok(network_registry_root(data_dir, network)?.join(crate::broadcast::BROADCAST_LOG_FILE_NAME))
}

impl RecoveryService {
    pub fn new() -> Self {
        Self::default()
    }

    fn workspace_gate(&self, root: &std::path::Path) -> Arc<Mutex<()>> {
        self.workspace_gates
            .lock()
            .expect("workspace gate registry lock poisoned")
            .entry(root.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn start_scan(
        &self,
        config: ScanConfig,
        seed_phrase: SecretString,
    ) -> ZeckResult<ScanHandle> {
        self.start_scan_from_key_source(config, Arc::new(SeedKeySource::new(seed_phrase)))
            .await
    }

    /// Start a scan from any key source — a seed phrase, or keys read out
    /// of a legacy wallet file.
    pub async fn start_scan_from_key_source(
        &self,
        config: ScanConfig,
        key_source: Arc<dyn KeySource>,
    ) -> ZeckResult<ScanHandle> {
        validate_scan_config(&config)?;

        // Imported sources and exact matched-account sources define their own
        // key set. An unrelated broad BIP-44 range must never be applied to
        // either route, including when resuming a reused frontend config.
        let transparent_scan =
            if key_source.wallet_seed()?.is_none() || key_source.exact_hd_account().is_some() {
                None
            } else {
                config.transparent_scan
            };

        let handle = ScanHandle::new();
        let state = Arc::new(tokio::sync::Mutex::new(ScanTaskState::new(handle.clone())));
        let runtime = RuntimeScanConfig {
            key_source,
            birthday: config.birthday,
            num_accounts: config.num_accounts,
            gap_limit: config.gap_limit,
            transparent_scan,
            lightwalletd_url: config.lightwalletd_url,
            confirmation_sources: config.confirmation_sources,
            data_dir: config.data_dir,
            network: config.network,
            label: config.label,
        };

        let workspace = RecoveryWorkspace::from_runtime(&runtime)?;
        let workspace_root = canonical_workspace_identity(workspace.root())?;
        let source_fingerprint = runtime.key_source.fingerprint()?;
        if self
            .cleanup_retry
            .lock()
            .await
            .contains_key(&workspace_root)
        {
            return Err(ZeckError::ScanNotReady(
                "workspace removal was interrupted; retry cleanup before scanning".to_owned(),
            ));
        }
        let scan_guard = self
            .workspace_gate(&workspace_root)
            .try_lock_owned()
            .map_err(|_| {
                ZeckError::ScanNotReady("workspace is in use by a scan or sweep".to_owned())
            })?;
        let operation_lock = NetworkOperationGuard::acquire(&runtime.data_dir, runtime.network)?;
        recover_interrupted_cleanup(&workspace_root, &operation_lock)?;
        // Refuse to start on a registry that cannot be replayed.
        drop(operation_lock.open_broadcast_log()?);

        // Cancel any existing session targeting the same workspace to prevent
        // concurrent SQLite writers from locking each other out.
        let conflicting: Vec<ScanHandle> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, session)| session.workspace_root == workspace_root)
                .map(|(id, _)| ScanHandle { id: id.clone() })
                .collect()
        };
        for conflicting_handle in conflicting {
            let _ = self.cancel_scan(&conflicting_handle).await;
            self.sessions.write().await.remove(&conflicting_handle.id);
            self.reconciliation_rescan_required
                .lock()
                .await
                .remove(&conflicting_handle.id);
        }

        let session = Arc::new(ScanSession {
            source_fingerprint,
            state: state.clone(),
            runtime: runtime.clone(),
            started_at: Instant::now(),
            task: Mutex::new(None),
            workspace_root,
            reviewed_sweeps: Mutex::new(ReviewedSweepStore::default()),
        });

        self.sessions
            .write()
            .await
            .insert(handle.id.clone(), session.clone());

        let sessions = self.sessions.clone();
        let reconciliation_rescan_required = self.reconciliation_rescan_required.clone();
        let handle_id = handle.id.clone();
        let task = tokio::spawn(async move {
            let _workspace_guard = scan_guard;
            let _operation_lock = operation_lock;
            // Acquire a power-management guard so the OS doesn't put the
            // machine to sleep mid-scan. Held for the entire scan task; the
            // Drop impl releases on completion, error, panic, or task abort.
            // Soft-fail: if the guard can't be acquired we still scan, the
            // user just has to keep the machine awake themselves.
            let _awake = match keepawake::Builder::default()
                .idle(true)
                .sleep(true)
                .reason("Argos recovery scan")
                .app_name("Argos")
                .app_reverse_domain("org.argos.app")
                .create()
            {
                Ok(guard) => Some(guard),
                Err(err) => {
                    tracing::warn!(
                        "keepawake guard unavailable; scan may pause if the machine sleeps: {err}"
                    );
                    None
                }
            };
            run_recovery_scan(state.clone(), runtime).await;
            drop(_awake);
            // Keep completed sessions alive so the user can proceed to sweep
            // at their own pace. Only clean up cancelled/error sessions after
            // a short delay so they don't accumulate.
            let phase = state.lock().await.progress.phase;
            if phase != ScanPhase::Complete {
                spawn_session_cleanup(sessions, reconciliation_rescan_required, handle_id);
            }
        });
        *session.task.lock().await = Some(task);

        Ok(handle)
    }

    pub async fn get_scan_progress(&self, handle: &ScanHandle) -> ZeckResult<ScanProgress> {
        let session = self.session(handle).await?;
        let mut progress = session.state.lock().await.progress.clone();
        let session_elapsed = session.started_at.elapsed().as_secs();
        // Use scan-phase elapsed (set by ProgressPoller from when scanning began) for
        // the rate calculation so pre-scan phases don't dilute the blocks/sec estimate.
        let scan_elapsed = progress.elapsed_seconds.unwrap_or(session_elapsed);
        progress.elapsed_seconds = Some(session_elapsed);
        progress.estimated_remaining_seconds = estimate_remaining_seconds(&progress, scan_elapsed);
        Ok(progress)
    }

    pub async fn cancel_scan(&self, handle: &ScanHandle) -> ZeckResult<()> {
        let session = self.session(handle).await?;

        {
            let state = session.state.lock().await;
            // Never cancel an already-complete scan: the phase would flip to
            // Cancelled and any still-alive pump loop would emit scan-complete
            // with Cancelled, corrupting the UI for the user's sweep workflow.
            if state.progress.phase == ScanPhase::Complete {
                return Ok(());
            }
            state
                .cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        {
            let mut state = session.state.lock().await;
            state.progress.phase = ScanPhase::Cancelled;
            state.progress.message = Some("Recovery scan cancelled.".to_owned());
        }
        if let Some(task) = session.task.lock().await.take() {
            task.abort();
            // The operation lock lives in the scan task. Wait for abort to
            // release it before a new service can inspect or recover this
            // workspace after cancellation.
            let _ = task.await;
        }
        // spawn_session_cleanup is intentionally omitted here: aborting the
        // task prevents the scan from completing naturally, so the cleanup
        // that was scheduled in start_scan will not fire.  We schedule a
        // fresh one to ensure the session is eventually removed.
        if self.sessions.read().await.contains_key(&handle.id) {
            spawn_session_cleanup(
                self.sessions.clone(),
                self.reconciliation_rescan_required.clone(),
                handle.id.clone(),
            );
        }
        Ok(())
    }

    pub async fn propose_sweep(
        &self,
        handle: &ScanHandle,
        request: SweepRequest,
    ) -> ZeckResult<ReviewedSweepProposal> {
        let session = self.session(handle).await?;
        let _workspace_guard = self
            .workspace_gate(&session.workspace_root)
            .lock_owned()
            .await;
        let _operation_lock =
            NetworkOperationGuard::acquire(&session.runtime.data_dir, session.runtime.network)?;
        refuse_interrupted_cleanup(&session.workspace_root)?;
        let global_log = _operation_lock.open_broadcast_log()?;
        if global_log.has_unresolved_history() {
            return Err(ZeckError::Broadcast(
                "cannot review a new sweep while the network registry has unresolved prepared transaction history".to_owned(),
            ));
        }
        if self
            .reconciliation_rescan_required
            .lock()
            .await
            .contains(&handle.id)
        {
            return Err(ZeckError::StaleSweepProposal(
                "transaction status changed after this scan; start a fresh scan and review a new sweep quote"
                    .to_owned(),
            ));
        }
        if self
            .cleanup_retry
            .lock()
            .await
            .contains_key(&session.workspace_root)
        {
            return Err(ZeckError::ScanNotReady(
                "workspace deletion is incomplete".to_owned(),
            ));
        }
        let (
            progress,
            tracked_accounts,
            standalone_transparent_balances,
            standalone_transparent_indices,
            authority,
        ) = {
            let state = session.state.lock().await;
            (
                state.progress.clone(),
                state.tracked_accounts.clone(),
                state.standalone_transparent_balances.clone(),
                state.standalone_transparent_indices.clone(),
                SweepAuthoritySnapshot::capture(&state),
            )
        };
        if progress.phase != ScanPhase::Complete {
            return Err(ZeckError::ScanNotReady(format!(
                "current phase is {:?}",
                progress.phase
            )));
        }

        // Confirm the workspace this proposal describes is still there and
        // still readable, before quoting a number derived from it.
        //
        // The balances below come from the in-memory scan state, not from
        // disk, so without this check a deleted or permission-stripped
        // workspace produces a confident, fully-priced proposal — and the
        // proposal's own warning tells the user it came from the persisted
        // wallet. Executing it would then fail, after the user has already
        // been shown an amount. For a recovery tool a confidently wrong
        // balance is a worse failure than a clean error.
        //
        // `from_runtime` only computes paths; it creates nothing. But opening
        // the database is not enough on its own: `open_wallet_db` uses
        // `Connection::open`, which recreates an empty `wallet.sqlite` when the
        // file has been deleted but its directory survives — masking the very
        // loss this guards against. So require a readable wallet summary too; a
        // missing or freshly-recreated database yields `None` here and fails
        // loudly, matching what the execute path already demands.
        //
        // Not on the transparent-only route. It never creates an account, so
        // its database is empty by design, and the guard refused every such
        // sweep (1.2.0 through 1.5.2) while the scan above it showed the
        // funds. Its balance never came from that database, and the sweep
        // re-reads every UTXO from the chain before signing.
        if !is_transparent_only_route(session.runtime.key_source.as_ref())? {
            let workspace = RecoveryWorkspace::from_runtime(&session.runtime)?;
            validate_wallet_output_identities(&workspace)?;
            let wallet_db = open_wallet_db(
                workspace.wallet_db_path(),
                consensus_network(session.runtime.network),
            )
            .map_err(|err| {
                ZeckError::Wallet(format!(
                    "the recovery workspace backing this scan is no longer readable, so its \
                     balances cannot be trusted: {err}"
                ))
            })?;
            wallet_db
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .map_err(|err| {
                    ZeckError::Wallet(format!(
                        "the recovery workspace backing this scan is no longer readable, so \
                         its balances cannot be trusted: {err}"
                    ))
                })?
                .ok_or_else(|| {
                    ZeckError::Wallet(
                        "the recovery workspace backing this scan no longer contains a \
                         wallet, so its balances cannot be trusted"
                            .to_owned(),
                    )
                })?;
        }

        refuse_memo_for_key_source(session.runtime.key_source.as_ref(), request.memo.as_deref())?;
        let workspace = RecoveryWorkspace::from_runtime(&session.runtime)?;
        let mut plan = build_exact_sweep_proposal(
            &progress,
            &tracked_accounts,
            &standalone_transparent_balances,
            &request,
            session.runtime.network,
            &workspace,
        )?;
        attach_direct_sweep_leg(&mut plan, &session.runtime, &standalone_transparent_indices)
            .await?;
        enforce_max_fee(plan.quote.total_fee_zatoshis, request.max_fee_zatoshis)?;
        let mut intent = ReviewedSweepIntent::capture(request, &session, &progress);
        intent.bind_plan(&plan)?;
        intent.authority = Some(authority);
        // Test seam: lets a test move progress between the build above and
        // the issue below, which is the window the re-check exists for.
        #[cfg(test)]
        let _ = PROPOSE_AFTER_BUILD.try_with(|hook| hook(&session));
        let confirmation_notice = crate::lightwalletd::single_operator_notice(
            &session.runtime.lightwalletd_url,
            &session.runtime.confirmation_sources,
        )?
        .map(str::to_owned);
        let state = session.state.lock().await;
        let proposal_id = issue_reviewed_proposal(&session, intent, &state).await?;
        let mut proposal = plan.quote;
        proposal.confirmation_notice = confirmation_notice;
        Ok(ReviewedSweepProposal {
            proposal_id,
            proposal,
        })
    }

    pub async fn execute_sweep(
        &self,
        handle: &ScanHandle,
        proposal_id: &SweepProposalId,
    ) -> ZeckResult<SweepOutcome> {
        self.execute_sweep_inner(handle, proposal_id).await
    }

    /// Refresh every historical broadcast receipt for an active recovery
    /// session. A fresh proposal remains a separate review step after this.
    pub async fn reconcile_sweep(
        &self,
        handle: &ScanHandle,
    ) -> ZeckResult<Vec<crate::reconciliation::ReconciledTransaction>> {
        let session = self.session(handle).await?;
        let mut observer = LightwalletdTxObserver::new(
            &session.runtime.lightwalletd_url,
            &session.runtime.confirmation_sources,
        )?;
        self.reconcile_sweep_with_observer(handle, &mut observer)
            .await
    }

    async fn reconcile_sweep_with_observer<O: TxObserver>(
        &self,
        handle: &ScanHandle,
        observer: &mut O,
    ) -> ZeckResult<Vec<crate::reconciliation::ReconciledTransaction>> {
        let session = self.session(handle).await?;
        let _workspace_guard = self
            .workspace_gate(&session.workspace_root)
            .lock_owned()
            .await;
        let operation_guard =
            NetworkOperationGuard::acquire(&session.runtime.data_dir, session.runtime.network)?;
        refuse_interrupted_cleanup(&session.workspace_root)?;
        let mut log = operation_guard.open_broadcast_log()?;
        let previous_states = log
            .records()
            .into_iter()
            .map(|record| (record.prepared.txid.to_string(), record.state))
            .collect::<HashMap<_, _>>();
        let observed = crate::reconciliation::observe_all_reconciled_transactions(
            &mut log,
            observer,
            session.runtime.network,
        )
        .await;
        // Earlier records may have been durably updated before a later
        // observer failed. Invalidate old quotes even on an error return.
        let changed = journal_states_changed(&previous_states, &log);
        self.invalidate_if_journal_changed(handle, &session, changed)
            .await;
        let reconciled = observed?;
        if let Some(outcome) = self.last_sweep_outcomes.lock().await.get_mut(&handle.id) {
            for transaction in &mut outcome.transactions {
                if let Some(updated) = reconciled
                    .iter()
                    .find(|updated| transaction.txid.as_deref() == Some(updated.txid.as_str()))
                {
                    transaction.status = updated.status;
                    transaction.confirmed_height = updated.confirmed_height;
                    transaction.detail = updated.detail.clone();
                    transaction.safe_to_discard = updated.safe_to_discard;
                }
            }
        }
        Ok(reconciled)
    }

    async fn invalidate_if_journal_changed(
        &self,
        handle: &ScanHandle,
        session: &SharedScanSession,
        changed: bool,
    ) {
        if changed {
            session.reviewed_sweeps.lock().await.entries.clear();
            self.reconciliation_rescan_required
                .lock()
                .await
                .insert(handle.id.clone());
        }
    }

    /// Explicitly retry only the exact raw transaction stored for an
    /// unresolved Unknown or NotSubmitted receipt, after observing it again.
    /// The caller supplies no bytes or new transaction parameters.
    pub async fn retry_unknown_sweep(
        &self,
        handle: &ScanHandle,
        txid: &str,
    ) -> ZeckResult<crate::reconciliation::ReconciledTransaction> {
        let session = self.session(handle).await?;
        let mut observer = LightwalletdTxObserver::new(
            &session.runtime.lightwalletd_url,
            &session.runtime.confirmation_sources,
        )?;
        let (mut client, _, info) = crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(
            &session.runtime.lightwalletd_url,
        )
        .await?;
        validate_lightwalletd_network(session.runtime.network, &info)?;
        let mut submitter = LightwalletdSubmitter {
            client: &mut client,
        };
        self.retry_unknown_sweep_with_clients(handle, txid, &mut observer, &mut submitter)
            .await
    }

    async fn retry_unknown_sweep_with_clients<O: TxObserver, N: crate::broadcast::TxSubmitter>(
        &self,
        handle: &ScanHandle,
        txid: &str,
        observer: &mut O,
        submitter: &mut N,
    ) -> ZeckResult<crate::reconciliation::ReconciledTransaction> {
        let session = self.session(handle).await?;
        let _workspace_guard = self
            .workspace_gate(&session.workspace_root)
            .lock_owned()
            .await;
        let operation_guard =
            NetworkOperationGuard::acquire(&session.runtime.data_dir, session.runtime.network)?;
        refuse_interrupted_cleanup(&session.workspace_root)?;
        let mut log = operation_guard.open_broadcast_log()?;
        let previous_states = log
            .records()
            .into_iter()
            .map(|record| (record.prepared.txid.to_string(), record.state))
            .collect::<HashMap<_, _>>();
        let stored_txid = log
            .records()
            .into_iter()
            .find(|record| record.prepared.txid.to_string() == txid)
            .map(|record| record.prepared.txid)
            .ok_or_else(|| ZeckError::Storage(format!("unknown stored transaction {txid}")))?;
        let retried = crate::reconciliation::retry_unknown_transaction(
            &mut log,
            observer,
            submitter,
            session.runtime.network,
            stored_txid,
            Duration::from_secs(30),
        )
        .await;
        // Observation can resolve the receipt before retry becomes eligible;
        // even an error return must invalidate quotes from the old scan.
        let changed = journal_states_changed(&previous_states, &log);
        self.invalidate_if_journal_changed(handle, &session, changed)
            .await;
        retried
    }

    /// Test-only sweep entrypoint that inserts a fixed pause between
    /// per-account broadcasts. Exists so R-S29 (`argos-sweep-helper`) can
    /// SIGKILL the subprocess deterministically in the gap between two
    /// broadcasts; production builds compile this method and the hook out.
    #[cfg(feature = "argos-network")]
    pub async fn execute_sweep_with_test_pause(
        &self,
        handle: &ScanHandle,
        proposal_id: &SweepProposalId,
        pause_between_broadcasts: std::time::Duration,
    ) -> ZeckResult<SweepOutcome> {
        PAUSE_BETWEEN_BROADCASTS
            .scope(
                pause_between_broadcasts,
                self.execute_sweep_inner(handle, proposal_id),
            )
            .await
    }

    async fn execute_sweep_inner(
        &self,
        handle: &ScanHandle,
        proposal_id: &SweepProposalId,
    ) -> ZeckResult<SweepOutcome> {
        let session = self.session(handle).await?;
        let _workspace_guard = self
            .workspace_gate(&session.workspace_root)
            .lock_owned()
            .await;
        let _operation_lock =
            NetworkOperationGuard::acquire(&session.runtime.data_dir, session.runtime.network)?;
        refuse_interrupted_cleanup(&session.workspace_root)?;
        let global_log = _operation_lock.open_broadcast_log()?;
        if global_log.has_unresolved_history() {
            return Err(ZeckError::Broadcast(
                "cannot start a new sweep while the network registry has unresolved prepared transaction history".to_owned(),
            ));
        }
        // Per-leg signers reopen the registry under the held operation lock.
        drop(global_log);
        if self
            .reconciliation_rescan_required
            .lock()
            .await
            .contains(&handle.id)
        {
            return Err(ZeckError::StaleSweepProposal(
                "transaction status changed after this scan; start a fresh scan and review a new sweep quote"
                    .to_owned(),
            ));
        }
        if !self
            .sessions
            .read()
            .await
            .get(&handle.id)
            .is_some_and(|current| Arc::ptr_eq(current, &session))
        {
            return Err(ZeckError::UnknownScanHandle);
        }
        if self
            .cleanup_retry
            .lock()
            .await
            .contains_key(&session.workspace_root)
        {
            return Err(ZeckError::ScanNotReady(
                "workspace removal was interrupted; retry cleanup before sweeping".to_owned(),
            ));
        }
        let outcome = self.execute_sweep_locked(session, proposal_id).await;
        if let Ok(ref completed) = outcome {
            self.last_sweep_outcomes
                .lock()
                .await
                .insert(handle.id.clone(), completed.clone());
        }
        outcome
    }

    async fn execute_sweep_locked(
        &self,
        session: SharedScanSession,
        proposal_id: &SweepProposalId,
    ) -> ZeckResult<SweepOutcome> {
        // The token is consumed while holding only the in-memory store lock.
        // No wallet, proving, or network operation runs under this lock.
        let intent = session.reviewed_sweeps.lock().await.take(proposal_id)?;
        let (
            progress,
            tracked_accounts,
            standalone_transparent_balances,
            standalone_sapling_indices,
            standalone_transparent_indices,
        ) = {
            let state = session.state.lock().await;
            intent.validate_scan_state(&session, &state)?;
            (
                state.progress.clone(),
                state.tracked_accounts.clone(),
                state.standalone_transparent_balances.clone(),
                state.standalone_sapling_indices.clone(),
                state.standalone_transparent_indices.clone(),
            )
        };
        let has_standalone_keys =
            !standalone_sapling_indices.is_empty() || !standalone_transparent_indices.is_empty();
        let workspace = RecoveryWorkspace::from_runtime(&session.runtime)?;
        if !is_transparent_only_route(session.runtime.key_source.as_ref())? {
            validate_wallet_output_identities(&workspace)?;
        }
        if standalone_transparent_balances
            .values()
            .any(|balance| balance.zatoshis > 0)
        {
            crate::transparent_recovery::sapling_receiver(
                &intent.request.destination,
                session.runtime.network,
            )?;
        }
        if session.runtime.key_source.wallet_seed()?.is_some()
            && session.state.lock().await.workspace.is_none()
        {
            return Err(ZeckError::ScanNotReady(
                "wallet workspace is unavailable".to_owned(),
            ));
        }
        // Refresh the wallet before the final plan comparison. Signing must
        // consume this same post-sync plan, never a later input selection.
        let (
            progress,
            tracked_accounts,
            standalone_transparent_balances,
            _standalone_sapling_indices,
            standalone_transparent_indices,
        ) = if !is_transparent_only_route(session.runtime.key_source.as_ref())? {
            let preferred = progress
                .server
                .as_ref()
                .map(|server| server.endpoint.as_str());
            let (mut client, _endpoint) = connect_lightwalletd_endpoints_with_retry(
                &session.runtime.lightwalletd_url,
                preferred,
            )
            .await?;
            let info = client
                .get_lightd_info(zcash_client_backend::proto::service::Empty {})
                .await
                .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
                .into_inner();
            validate_lightwalletd_network(session.runtime.network, &info)?;
            run_wallet_sync_with_retry(
                &workspace,
                &consensus_network(session.runtime.network),
                session.runtime.network,
                &mut client,
                &session.runtime.lightwalletd_url,
                &session.state,
            )
            .await?;
            refresh_scan_progress(
                &session.state,
                &workspace,
                session.runtime.network,
                session
                    .runtime
                    .birthday
                    .min(chain_tip_height(&mut client).await?),
            )
            .await?;
            let state = session.state.lock().await;
            intent.require_current_authority(&state)?;
            (
                state.progress.clone(),
                state.tracked_accounts.clone(),
                state.standalone_transparent_balances.clone(),
                state.standalone_sapling_indices.clone(),
                state.standalone_transparent_indices.clone(),
            )
        } else {
            (
                progress,
                tracked_accounts,
                standalone_transparent_balances,
                standalone_sapling_indices,
                standalone_transparent_indices,
            )
        };
        let mut current_plan = build_exact_sweep_proposal(
            &progress,
            &tracked_accounts,
            &standalone_transparent_balances,
            &intent.request,
            session.runtime.network,
            &workspace,
        )?;
        attach_direct_sweep_leg(
            &mut current_plan,
            &session.runtime,
            &standalone_transparent_indices,
        )
        .await?;
        let exact_fees = intent.authorize_current_plan(&current_plan)?;
        hd_leg_plan(&current_plan.legs, &tracked_accounts)?;
        let quoted_transactions = intent.quoted_transactions;
        let quoted_skipped = intent
            .quoted_proposal
            .as_ref()
            .map(|quote| quote.skipped_accounts.clone())
            .unwrap_or_default();
        let backend_legs = current_plan.legs;
        let request = intent.request;

        // An imported wallet with no HD seed cannot go through the sweep
        // below, which derives a UnifiedSpendingKey per account. Route it
        // here rather than in a front-end so the CLI and the GUI cannot
        // diverge on which key sources are spendable — the branch belongs
        // wherever `execute_sweep` is the shared surface.
        // Refused at the same level as in `propose_sweep`, not inside the
        // imported-keys branch: a seedless source that does not override
        // `imported_keys` would otherwise be refused at propose and accepted
        // here.
        refuse_memo_for_key_source(session.runtime.key_source.as_ref(), request.memo.as_deref())?;
        if session.runtime.key_source.wallet_seed()?.is_none() {
            if let Some(keys) = session.runtime.key_source.imported_keys() {
                // Before the Sapling legs broadcast, not after: the
                // transparent leg is last and is the only one that needs a
                // Sapling receiver.
                crate::transparent_recovery::refuse_destination_the_transparent_leg_cannot_reach(
                    keys,
                    &request.destination,
                    session.runtime.network,
                )?;
                return sweep_imported_session(
                    &session.runtime,
                    keys,
                    &request,
                    &backend_legs,
                    &exact_fees,
                )
                .await;
            }
        }

        if has_standalone_keys {
            let keys =
                session.runtime.key_source.imported_keys().ok_or_else(|| {
                    ZeckError::Wallet("mixed scan lost its imported keys".to_owned())
                })?;
            let (hd_indices, _imported_indices, imported_accounts) =
                partition_mixed_spend_authorities(&tracked_accounts)?;
            // The exact proposal above checked every leg before submission.
            // The proposal creates a direct leg only for a positive scanned
            // standalone balance. An imported key with no UTXOs must not
            // require a Sapling receiver or enter the direct executor.
            let has_direct_leg = backend_legs
                .iter()
                .any(|leg| matches!(leg, ExactSweepLeg::DirectTransparent { .. }));
            if has_direct_leg {
                crate::transparent_recovery::sapling_receiver(
                    &request.destination,
                    session.runtime.network,
                )?;
            }
            // The scan stores standalone balances by display account, not
            // individual key. When that aggregate is empty, skip every key;
            // otherwise let the executor resolve its selected keys' UTXOs.
            let transparent_indices_to_sweep: &[usize] = if has_direct_leg {
                &standalone_transparent_indices
            } else {
                &[]
            };
            let transparent_display_index = standalone_transparent_balances
                .iter()
                .filter(|(_, balance)| balance.utxo_count > 0)
                .map(|(&index, _)| index)
                .min();
            let imported_plan = imported_execution_plan(&backend_legs);
            let reviewed_sapling_fees = exact_fees.imported_sapling_map();
            let reviewed_transparent_fee = has_direct_leg
                .then(|| exact_fees.require(ExactFeeKey::DirectTransparent))
                .transpose()?;
            let (imported, imported_result) =
                crate::imported_sweep::sweep_imported_filtered_wallet_reviewed(
                    &session.runtime,
                    keys,
                    &imported_accounts,
                    transparent_indices_to_sweep,
                    transparent_display_index,
                    &request.destination,
                    request.max_fee_zatoshis,
                    Some(&reviewed_sapling_fees),
                    reviewed_transparent_fee,
                    Some(&imported_plan),
                )
                .await;
            let imported_fee = at_risk_fee_total(&imported.transactions)?;
            let imported_outcome = assemble_imported_sweep_outcome_for_legs(
                imported,
                imported_result,
                !imported_accounts.is_empty(),
                has_direct_leg,
            )?;
            if imported_outcome.error.is_some() || hd_indices.is_empty() {
                return Ok(imported_outcome);
            }
            let hd_outcome = execute_sweep_for_session(
                session,
                request,
                imported_fee,
                quoted_transactions,
                quoted_skipped,
                backend_legs,
                tracked_accounts,
                exact_fees,
            )
            .await;
            return merge_combined_sweep_outcomes(imported_outcome, hd_outcome);
        }

        execute_sweep_for_session(
            session,
            request,
            0,
            quoted_transactions,
            quoted_skipped,
            backend_legs,
            tracked_accounts,
            exact_fees,
        )
        .await
    }

    async fn session(&self, handle: &ScanHandle) -> ZeckResult<SharedScanSession> {
        self.sessions
            .read()
            .await
            .get(&handle.id)
            .cloned()
            .ok_or(ZeckError::UnknownScanHandle)
    }
}

fn merge_combined_sweep_outcomes(
    mut imported: SweepOutcome,
    hd: ZeckResult<SweepOutcome>,
) -> ZeckResult<SweepOutcome> {
    match hd {
        Ok(mut hd) => {
            imported.transactions.append(&mut hd.transactions);
            imported.skipped_accounts.append(&mut hd.skipped_accounts);
            imported.total_donation_zatoshis = hd.total_donation_zatoshis;
            imported.follow_up_review_required |= hd.follow_up_review_required;
            imported.error = hd.error;
            // Only the HD leg can carry a donation, so its note is the
            // sweep's note.
            imported.donation_note = hd.donation_note;
            Ok(imported)
        }
        Err(err) if !imported.transactions.is_empty() => {
            imported.error = Some(err.to_string());
            imported.donation_note = None;
            Ok(imported)
        }
        Err(err) => Err(err),
    }
}

fn validate_scan_config(config: &ScanConfig) -> ZeckResult<()> {
    if let Some(transparent_scan) = &config.transparent_scan {
        transparent_scan.validate()?;
    }
    if config.gap_limit == 0 {
        return Err(ZeckError::InvalidConfig(
            "gap limit must be at least 1".to_owned(),
        ));
    }
    if config.gap_limit > 500 {
        return Err(ZeckError::InvalidConfig(
            "gap limit must not exceed 500".to_owned(),
        ));
    }
    if matches!(config.num_accounts, Some(0)) {
        return Err(ZeckError::InvalidConfig(
            "num_accounts must be at least 1".to_owned(),
        ));
    }
    if let Some(num_accounts) = config.num_accounts {
        if num_accounts > 500 {
            return Err(ZeckError::InvalidConfig(
                "num_accounts must not exceed 500".to_owned(),
            ));
        }
    }
    validated_lightwalletd_endpoints(&config.lightwalletd_url)?;
    crate::lightwalletd::confirmation_endpoints(
        &config.lightwalletd_url,
        &config.confirmation_sources,
    )?;

    Ok(())
}

fn spawn_session_cleanup(
    sessions: Arc<RwLock<HashMap<String, SharedScanSession>>>,
    reconciliation_rescan_required: Arc<Mutex<HashSet<String>>>,
    handle_id: String,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(SESSION_RETENTION_SECS)).await;
        sessions.write().await.remove(&handle_id);
        reconciliation_rescan_required
            .lock()
            .await
            .remove(&handle_id);
    });
}

#[cfg(test)]
fn build_sweep_proposal(
    progress: &ScanProgress,
    request: SweepRequest,
    network: crate::models::ZeckNetwork,
    donation_address: &str,
) -> ZeckResult<SweepProposal> {
    let destination = validate_destination_address(&request.destination, network)?;
    let memo = normalized_memo_text(request.memo.as_deref())?;
    let minimum_fee_zatoshis = u64::from(MINIMUM_FEE);

    // Testnet forces the donation feature off.
    let effective_donation_address = if matches!(network, crate::models::ZeckNetwork::Testnet) {
        ""
    } else {
        donation_address
    };

    crate::donation::validate_donation_rate(request.donation_rate)?;
    crate::donation::validate_donor_email(request.donor_email.as_deref())?;

    let mut transactions = Vec::new();
    let mut skipped_accounts = Vec::new();
    let mut total_fee_zatoshis = 0u64;
    let mut total_send_zatoshis = 0u64;
    let mut net_received_zatoshis = 0u64;
    let mut total_donation_zatoshis = 0u64;
    let mut follow_up_review_required = false;

    for account in progress
        .accounts
        .iter()
        .filter(|account| account.total_zatoshis > 0)
    {
        let shielded_existing = account
            .sapling_zatoshis
            .checked_add(account.orchard_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("shielded balance overflowed the supported range".to_owned())
            })?;
        let shielded_available = shielded_existing;

        if account.transparent_zatoshis > 0 {
            // ZIP 317 charges at least two logical actions, and each P2PKH
            // input is one action. Large input sets may be split across
            // several shielding transactions by the selector; this is the
            // aggregate input-action estimate, while execution enforces each
            // proposal's exact fee against the user's cap before broadcast.
            let shielding_fee_zatoshis = u64::from(MARGINAL_FEE)
                .checked_mul(u64::from(account.transparent_utxo_count).max(2))
                .ok_or_else(|| {
                    ZeckError::Internal("shielding fee estimate overflowed u64".to_owned())
                })?;
            if account.transparent_zatoshis <= shielding_fee_zatoshis {
                skipped_accounts.push(SkippedSweepAccount {
                    account_index: account.account_index,
                    gross_zatoshis: account.transparent_zatoshis,
                    reason: format!(
                        "Transparent balance is too small to cover the estimated ZIP 317 shielding fee of {shielding_fee_zatoshis} zats."
                    ),
                });
            } else {
                let shielded_after_step_one = account.transparent_zatoshis - shielding_fee_zatoshis;
                total_send_zatoshis = total_send_zatoshis
                    .checked_add(account.transparent_zatoshis)
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "sweep proposal overflowed the supported range".to_owned(),
                        )
                    })?;
                total_fee_zatoshis = total_fee_zatoshis
                    .checked_add(shielding_fee_zatoshis)
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "sweep proposal overflowed the supported range".to_owned(),
                        )
                    })?;

                transactions.push(ProposedTx {
                    kind: ProposedTxKind::ShieldTransparent,
                    leg_kind: crate::models::ProposedLegKind::Wallet,
                    source_account: account.account_index,
                    destination: account.unified_address.clone(),
                    gross_zatoshis: account.transparent_zatoshis,
                    fee_zatoshis: shielding_fee_zatoshis,
                    net_zatoshis: shielded_after_step_one,
                    donation_zatoshis: 0,
                    note: format!(
                        "Estimated shielding of {} transparent UTXOs before the external sweep; large input sets may require multiple transactions.",
                        account.transparent_utxo_count
                    ),
                    memo: None,
                });
                follow_up_review_required = true;
                // The future shielded send depends on a mined, witnessed output.
                // It receives a new proposal ID after a fresh scan.
                continue;
            }
        }

        if shielded_available == 0 {
            continue;
        }
        if shielded_available <= minimum_fee_zatoshis {
            skipped_accounts.push(SkippedSweepAccount {
                account_index: account.account_index,
                gross_zatoshis: shielded_available,
                reason: format!(
                    "Shielded balance is too small to cover the ZIP 317 sweep fee floor of {minimum_fee_zatoshis} zats."
                ),
            });
            continue;
        }

        let sweep_fee_zatoshis = minimum_fee_zatoshis;
        let net_received_for_account = shielded_available - sweep_fee_zatoshis;
        total_send_zatoshis = total_send_zatoshis
            .checked_add(shielded_available)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;
        total_fee_zatoshis = total_fee_zatoshis
            .checked_add(sweep_fee_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;
        net_received_zatoshis = net_received_zatoshis
            .checked_add(net_received_for_account)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;

        let donation_zatoshis = crate::donation::donation_for_send_amount(
            effective_donation_address,
            request.donation_rate,
            net_received_for_account,
        );
        total_donation_zatoshis = total_donation_zatoshis
            .checked_add(donation_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
            })?;

        transactions.push(ProposedTx {
            kind: ProposedTxKind::SweepShielded,
            leg_kind: crate::models::ProposedLegKind::Wallet,
            source_account: account.account_index,
            destination: destination.encoded.clone(),
            gross_zatoshis: shielded_available,
            fee_zatoshis: sweep_fee_zatoshis,
            net_zatoshis: net_received_for_account,
            donation_zatoshis,
            note: if shielded_existing > 0 && account.transparent_zatoshis > 0 {
                "Estimated external recovery sweep after shielding the transparent portion and combining it with existing shielded funds."
                    .to_owned()
            } else if shielded_existing > 0 {
                "Estimated external recovery sweep for shielded funds already tracked in this account."
                    .to_owned()
            } else {
                "Estimated external recovery sweep after shielding completes.".to_owned()
            },
            memo: Some(memo.clone()),
        });
    }

    if let Some(max_fee_zatoshis) = request.max_fee_zatoshis {
        if total_fee_zatoshis > max_fee_zatoshis {
            return Err(ZeckError::MaxFeeExceeded(format!(
                "estimated fee {total_fee_zatoshis} zats exceeds limit {max_fee_zatoshis} zats"
            )));
        }
    }

    let warning = if follow_up_review_required {
        "This proposal covers the transparent shielding stage only. After it mines, rescan and review a new proposal for the shielded send."
            .to_owned()
    } else if net_received_zatoshis > 0 {
        "This dry-run proposal uses the balances from the completed scan, checked against the recovery workspace on disk. Argos estimates any required shielding first, then a final sweep to the destination Unified Address."
            .to_owned()
    } else if !skipped_accounts.is_empty() {
        "Balances were detected, but every discovered account was skipped because the ZIP 317 fee floor would consume the recoverable value."
            .to_owned()
    } else {
        "No spendable balances were found in the completed scan.".to_owned()
    };

    Ok(SweepProposal {
        transactions,
        skipped_accounts,
        total_send_zatoshis,
        total_fee_zatoshis,
        net_received_zatoshis,
        total_donation_zatoshis,
        dry_run_default: true,
        warning: Some(warning),
        donation_note: None,
        follow_up_review_required,
        confirmation_notice: None,
    })
}

/// Build the review from the same wallet proposals that execution will sign.
/// Each HD account with transparent funds quotes only its shielding stage.
#[allow(clippy::too_many_arguments)]
fn build_exact_sweep_proposal(
    progress: &ScanProgress,
    tracked_accounts: &[TrackedAccount],
    standalone_transparent: &HashMap<u32, crate::scan::StandaloneTransparentBalance>,
    request: &SweepRequest,
    network: crate::models::ZeckNetwork,
    workspace: &RecoveryWorkspace,
) -> ZeckResult<ExactSweepPlan> {
    let destination = validate_destination_address(&request.destination, network)?;
    let destination_address = ZcashAddress::try_from_encoded(&destination.encoded)
        .map_err(|err| ZeckError::InvalidAddress(err.to_string()))?;
    let memo_text = normalized_memo_text(request.memo.as_deref())?;
    let memo_bytes = Some(
        MemoBytes::from_bytes(memo_text.as_bytes())
            .map_err(|err| ZeckError::InvalidMemo(err.to_string()))?,
    );
    crate::donation::validate_donation_rate(request.donation_rate)?;
    crate::donation::validate_donor_email(request.donor_email.as_deref())?;
    let donation_address = execution_donation_address(network);
    if standalone_transparent
        .values()
        .any(|balance| balance.zatoshis > 0)
    {
        crate::transparent_recovery::sapling_receiver(&destination.encoded, network)?;
    }
    let donation_memo = Some(
        MemoBytes::from_bytes(
            crate::donation::donation_memo_body(request.donor_email.as_deref()).as_bytes(),
        )
        .map_err(|err| ZeckError::InvalidMemo(err.to_string()))?,
    );
    let mut transactions = Vec::new();
    let mut legs = Vec::new();
    let mut skipped_accounts = Vec::new();
    let mut follow_up_review_required = false;
    let mut has_hd_leg = false;
    let mut direct_account_index = None;

    for tracked in tracked_accounts {
        let row = progress
            .accounts
            .iter()
            .find(|row| row.account_index == tracked.derived.index)
            .ok_or_else(|| {
                ZeckError::Wallet(format!(
                    "recovery account {} is absent from scan",
                    tracked.derived.index
                ))
            })?;
        match tracked.spend_authority {
            TrackedSpendAuthority::Hd { .. } => {
                has_hd_leg = true;
                let standalone = standalone_transparent
                    .get(&row.account_index)
                    .copied()
                    .unwrap_or_default();
                let transparent = row
                    .transparent_zatoshis
                    .checked_sub(standalone.zatoshis)
                    .ok_or_else(|| {
                        ZeckError::Wallet(
                            "standalone transparent balance exceeds HD account balance".to_owned(),
                        )
                    })?;
                if balance_covers_sweep_fee(transparent) {
                    let mut db =
                        open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;
                    if let Some(proposal) = propose_hd_shielding(&mut db, network, tracked)? {
                        let fee = proposal_fee_zatoshis(&proposal)?;
                        let gross = proposal
                            .steps()
                            .iter()
                            .flat_map(|step| step.transparent_inputs())
                            .try_fold(0u64, |sum, input| {
                                sum.checked_add(u64::from(input.txout().value()))
                                    .ok_or_else(|| {
                                        ZeckError::Internal(
                                            "shielding input total overflowed".to_owned(),
                                        )
                                    })
                            })?;
                        let net = gross.checked_sub(fee).ok_or_else(|| {
                            ZeckError::TransactionBuild(
                                "shielding fee exceeds selected inputs".to_owned(),
                            )
                        })?;
                        transactions.push(ProposedTx {
                            kind: ProposedTxKind::ShieldTransparent,
                            leg_kind: crate::models::ProposedLegKind::Wallet,
                            source_account: row.account_index,
                            destination: row.unified_address.clone(),
                            gross_zatoshis: gross,
                            fee_zatoshis: fee,
                            net_zatoshis: net,
                            donation_zatoshis: 0,
                            note: "Shielding stage only. Rescan after mining and review a new send proposal.".to_owned(),
                            memo: None,
                        });
                        legs.push(ExactSweepLeg::HdShield {
                            account_index: row.account_index,
                            proposal,
                        });
                        follow_up_review_required = true;
                        continue;
                    }
                }
                if !hd_has_shielded_balance(row)? {
                    if row.total_zatoshis > 0 {
                        skipped_accounts.push(SkippedSweepAccount {
                            account_index: row.account_index,
                            gross_zatoshis: row.total_zatoshis,
                            reason: "No spendable shielded notes or shieldable transparent UTXOs were available.".to_owned(),
                        });
                    }
                    continue;
                }
                let mut db =
                    open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;
                if let Some((proposal, donation)) = propose_hd_send_max(
                    &mut db,
                    network,
                    tracked.wallet_account_id,
                    row.account_index,
                    &destination_address,
                    memo_bytes.clone(),
                    &donation_address,
                    request.donation_rate,
                    donation_memo.clone(),
                )? {
                    let fee = proposal_fee_zatoshis(&proposal)?;
                    let net = proposal_payment_total(&proposal)?;
                    let gross = checked_fee_total(net, fee)?;
                    transactions.push(ProposedTx {
                        kind: ProposedTxKind::SweepShielded,
                        leg_kind: crate::models::ProposedLegKind::Wallet,
                        source_account: row.account_index,
                        destination: destination.encoded.clone(),
                        gross_zatoshis: gross,
                        fee_zatoshis: fee,
                        net_zatoshis: net,
                        donation_zatoshis: donation,
                        note: "Exact ZIP-317 send-max proposal from spendable shielded notes."
                            .to_owned(),
                        memo: Some(memo_text.clone()),
                    });
                    legs.push(ExactSweepLeg::HdSend {
                        account_index: row.account_index,
                        proposal,
                        donation_zatoshis: donation,
                    });
                } else {
                    skipped_accounts.push(SkippedSweepAccount {
                        account_index: row.account_index,
                        gross_zatoshis: row.total_zatoshis,
                        reason: "No selectable shielded value cleared the ZIP-317 fee.".to_owned(),
                    });
                }
            }
            TrackedSpendAuthority::ImportedSapling {
                wallet_account_id, ..
            } => {
                if row.sapling_zatoshis == 0 {
                    continue;
                }
                let mut db =
                    open_wallet_db(workspace.wallet_db_path(), consensus_network(network))?;
                let proposal = match crate::imported_sweep::propose_imported_sapling_sweep(
                    &mut db,
                    &consensus_network(network),
                    wallet_account_id,
                    &destination_address,
                ) {
                    Ok(proposal) => proposal,
                    Err(err) if is_insufficient_funds_error(&err.to_string()) => {
                        skipped_accounts.push(SkippedSweepAccount {
                            account_index: row.account_index,
                            gross_zatoshis: row.sapling_zatoshis,
                            reason: "No selectable imported Sapling value cleared the ZIP-317 fee."
                                .to_owned(),
                        });
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                let fee = proposal_fee_zatoshis(&proposal)?;
                let net = proposal_payment_total(&proposal)?;
                let gross = checked_fee_total(net, fee)?;
                transactions.push(ProposedTx {
                    kind: ProposedTxKind::SweepShielded,
                    leg_kind: crate::models::ProposedLegKind::Wallet,
                    source_account: row.account_index,
                    destination: destination.encoded.clone(),
                    gross_zatoshis: gross,
                    fee_zatoshis: fee,
                    net_zatoshis: net,
                    donation_zatoshis: 0,
                    note: "Exact ZIP-317 imported Sapling proposal.".to_owned(),
                    memo: None,
                });
                legs.push(ExactSweepLeg::ImportedSapling {
                    account_index: row.account_index,
                    account_id: wallet_account_id,
                    proposal,
                });
            }
        }
    }

    // Transparent-only scans have no wallet account or UUID. Their scan row
    // is the authoritative snapshot and the executor re-fetches every UTXO.
    let fallback_transparent = (tracked_accounts.is_empty() && standalone_transparent.is_empty())
        .then(|| {
            progress
                .accounts
                .iter()
                .fold((0u64, 0usize), |(amount, inputs), row| {
                    (
                        amount.saturating_add(row.transparent_zatoshis),
                        inputs.saturating_add(row.transparent_utxo_count as usize),
                    )
                })
        });
    let standalone_total = standalone_transparent
        .values()
        .try_fold(0u64, |sum, balance| {
            sum.checked_add(balance.zatoshis).ok_or_else(|| {
                ZeckError::Internal("standalone transparent balance overflowed".to_owned())
            })
        })?;
    let standalone_inputs = standalone_transparent
        .values()
        .try_fold(0usize, |sum, balance| {
            sum.checked_add(balance.utxo_count as usize)
                .ok_or_else(|| ZeckError::Internal("standalone input count overflowed".to_owned()))
        })?;
    let (standalone_total, standalone_inputs) =
        fallback_transparent.unwrap_or((standalone_total, standalone_inputs));
    if standalone_total > 0 {
        crate::transparent_recovery::sapling_receiver(&destination.encoded, network)?;
        let fee = crate::transparent_recovery::transparent_sweep_fee(network, standalone_inputs)?;
        let account_index = standalone_transparent.keys().copied().min().unwrap_or(0);
        if let Some(net) = standalone_total.checked_sub(fee).filter(|net| *net > 0) {
            direct_account_index = Some(account_index);
            transactions.push(ProposedTx {
                kind: ProposedTxKind::SweepShielded,
                leg_kind: crate::models::ProposedLegKind::DirectTransparent,
                source_account: account_index,
                destination: destination.encoded.clone(),
                gross_zatoshis: standalone_total,
                fee_zatoshis: fee,
                net_zatoshis: net,
                donation_zatoshis: 0,
                note: format!("Direct sweep of {standalone_inputs} standalone transparent UTXOs."),
                memo: None,
            });
        } else {
            skipped_accounts.push(SkippedSweepAccount {
                account_index,
                gross_zatoshis: standalone_total,
                reason: format!("Transparent balance cannot cover its {fee}-zat ZIP-317 fee."),
            });
        }
    }
    // The fee ceiling is applied by the caller: at review on this quote, and
    // at execution only after the plan matched the reviewed one.
    let total_fee_zatoshis = transactions
        .iter()
        .try_fold(0u64, |sum, tx| checked_fee_total(sum, tx.fee_zatoshis))?;
    let total_send_zatoshis = transactions
        .iter()
        .try_fold(0u64, |sum, tx| checked_fee_total(sum, tx.gross_zatoshis))?;
    let net_received_zatoshis = transactions
        .iter()
        .filter(|tx| tx.kind == ProposedTxKind::SweepShielded)
        .try_fold(0u64, |sum, tx| {
            let received = tx
                .net_zatoshis
                .checked_sub(tx.donation_zatoshis)
                .ok_or_else(|| {
                    ZeckError::Internal("donation exceeds proposed output".to_owned())
                })?;
            checked_fee_total(sum, received)
        })?;
    let total_donation_zatoshis = transactions
        .iter()
        .try_fold(0u64, |sum, tx| checked_fee_total(sum, tx.donation_zatoshis))?;
    let imported_indices = tracked_accounts
        .iter()
        .filter_map(|account| {
            matches!(
                account.spend_authority,
                TrackedSpendAuthority::ImportedSapling { .. }
            )
            .then_some(account.derived.index)
        })
        .collect::<std::collections::HashSet<_>>();
    order_quoted_transactions(&mut transactions, &imported_indices);
    legs.sort_by_key(exact_leg_execution_rank);
    Ok(ExactSweepPlan {
        quote: SweepProposal {
            transactions,
            skipped_accounts,
            total_send_zatoshis,
            total_fee_zatoshis,
            net_received_zatoshis,
            total_donation_zatoshis,
            dry_run_default: true,
            warning: Some(if follow_up_review_required {
                "This proposal covers shielding only for HD accounts with transparent funds. After mining, rescan and review the send-max stage.".to_owned()
            } else {
                "This proposal prices the spendable wallet inputs with the transaction builders used for execution.".to_owned()
            }),
            donation_note: (!has_hd_leg).then(|| SEEDLESS_DONATION_NOTE.to_owned()),
            follow_up_review_required,
            confirmation_notice: None,
        },
        legs,
        direct_account_index,
        network,
    })
}

async fn attach_direct_sweep_leg(
    plan: &mut ExactSweepPlan,
    runtime: &RuntimeScanConfig,
    standalone_indices: &[usize],
) -> ZeckResult<()> {
    let Some(account_index) = plan.direct_account_index else {
        return Ok(());
    };
    let imported = runtime.key_source.imported_keys().ok_or_else(|| {
        ZeckError::StaleSweepProposal("direct sweep keys are no longer available".to_owned())
    })?;
    let all_keys = crate::imported::imported_transparent_keys(imported)?;
    let selected = if standalone_indices.is_empty() {
        all_keys
    } else {
        standalone_indices
            .iter()
            .map(|&index| {
                all_keys
                    .get(index)
                    .map(|key| crate::imported::ImportedTransparentKey {
                        secret: key.secret,
                        address: key.address,
                    })
                    .ok_or_else(|| {
                        ZeckError::StaleSweepProposal(format!(
                            "direct sweep key {index} is no longer available"
                        ))
                    })
            })
            .collect::<ZeckResult<Vec<_>>>()?
    };
    #[cfg(test)]
    let fixture = DIRECT_LEG_CHAIN.try_with(Clone::clone).ok();
    #[cfg(not(test))]
    let fixture: Option<(u32, Vec<crate::transparent_recovery::TransparentUtxo>)> = None;
    let (tip, mut utxos) = if let Some(fixture) = fixture {
        fixture
    } else {
        let (mut client, _endpoint, info) =
            crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(&runtime.lightwalletd_url)
                .await?;
        validate_lightwalletd_network(runtime.network, &info)?;
        let tip = u32::try_from(info.block_height)
            .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
        let utxos = crate::transparent_recovery::fetch_transparent_utxos(
            &mut client,
            &selected,
            runtime.network,
        )
        .await?;
        (tip, utxos)
    };
    utxos.sort_by_cached_key(canonical_transparent_input);
    let params = consensus_network(runtime.network);
    let Some(direct_plan) = crate::transparent_recovery::plan_sweep(
        &params,
        BlockHeight::from_u32(tip.saturating_add(1)),
        &utxos,
    )?
    else {
        return Err(ZeckError::StaleSweepProposal(
            "direct sweep inputs disappeared".to_owned(),
        ));
    };
    let quoted = direct_leg_quote(&plan.quote.transactions, account_index)?;
    if quoted.gross_zatoshis != direct_plan.total_input_zatoshis
        || quoted.fee_zatoshis != direct_plan.fee_zatoshis
        || quoted.net_zatoshis != direct_plan.output_zatoshis
        || direct_plan.input_count != utxos.len()
    {
        return Err(ZeckError::StaleSweepProposal(
            "direct sweep UTXOs no longer match the reviewed amount and fee".to_owned(),
        ));
    }
    let version = zcash_primitives::transaction::TxVersion::suggested_for_branch(
        zcash_protocol::consensus::BranchId::for_height(
            &params,
            BlockHeight::from_u32(tip.saturating_add(1)),
        ),
    )
    .header();
    plan.legs.push(ExactSweepLeg::DirectTransparent {
        account_index,
        utxos,
        plan: direct_plan,
        target_height: tip.saturating_add(1),
        version,
    });
    plan.legs.sort_by_key(exact_leg_execution_rank);
    Ok(())
}

/// Imported Sapling sends run first, then the standalone transparent
/// follow-up, then HD accounts. The review displays that same order.
fn order_quoted_transactions(
    transactions: &mut [ProposedTx],
    imported_indices: &std::collections::HashSet<u32>,
) {
    transactions.sort_by_key(|tx| match tx.leg_kind {
        crate::models::ProposedLegKind::DirectTransparent => 1,
        crate::models::ProposedLegKind::Wallet if imported_indices.contains(&tx.source_account) => {
            0
        }
        crate::models::ProposedLegKind::Wallet => 2,
    });
}

/// The quoted direct transparent leg for `account_index`.
fn direct_leg_quote(transactions: &[ProposedTx], account_index: u32) -> ZeckResult<&ProposedTx> {
    transactions
        .iter()
        .find(|tx| {
            tx.source_account == account_index
                && tx.leg_kind == crate::models::ProposedLegKind::DirectTransparent
        })
        .ok_or_else(|| ZeckError::StaleSweepProposal("direct sweep quote disappeared".to_owned()))
}

fn exact_leg_execution_rank(leg: &ExactSweepLeg) -> u8 {
    match leg {
        ExactSweepLeg::ImportedSapling { .. } => 0,
        ExactSweepLeg::DirectTransparent { .. } => 1,
        ExactSweepLeg::HdShield { .. } | ExactSweepLeg::HdSend { .. } => 2,
    }
}

fn proposal_payment_total<NoteRef>(
    proposal: &zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>,
) -> ZeckResult<u64> {
    proposal
        .steps()
        .iter()
        .flat_map(|step| step.transaction_request().payments().values())
        .try_fold(0u64, |sum, payment| {
            let amount = payment.amount().ok_or_else(|| {
                ZeckError::TransactionBuild("proposal payment has no amount".to_owned())
            })?;
            checked_fee_total(sum, u64::from(amount))
        })
}

/// Refuse a memo on a sweep that has no seed phrase behind it.
///
/// Only the HD sweep attaches a memo. The imported-key, transparent-only and
/// matched-address sweeps send none, and a memo dropped silently can lose an
/// exchange deposit — so the request is refused, not quietly trimmed.
///
/// A blank memo is not refused because the user has asked for nothing: it is
/// what the memo field holds when left empty. (On the HD route a blank memo
/// is replaced by the default `RECOVERY_MEMO_DEFAULT` in
/// `normalized_memo_text`; a seedless sweep sends none at all.)
pub fn refuse_memo_without_seed(memo: Option<&str>) -> ZeckResult<()> {
    if memo.is_some_and(|memo| !memo.trim().is_empty()) {
        // Worded for the sweep, not the wallet: a matched-address recovery
        // takes this route although its user has just typed a seed phrase.
        return Err(ZeckError::InvalidMemo(
            "a memo can be attached only to a full recovery from a seed phrase. This recovery \
             sweeps individual keys (an imported wallet, standalone keys, or a single \
             matched address), and that sweep sends no memo. Remove the memo, or send \
             from the destination wallet afterwards if the recipient needs one."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Whether this key source scans through `run_transparent_only_scan`, which
/// creates no account and so leaves nothing in the wallet database.
///
/// Asked through `classify_recovery_route`, the predicate the scan routes on,
/// so the scan and `propose_sweep` cannot disagree about which wallets take it.
fn is_transparent_only_route(source: &dyn KeySource) -> ZeckResult<bool> {
    if source.wallet_seed()?.is_some() {
        return Ok(false);
    }
    Ok(source.imported_keys().is_some_and(|keys| {
        crate::key_source::classify_recovery_route(keys)
            == crate::key_source::RecoveryRoute::TransparentOnly
    }))
}

/// [`refuse_memo_without_seed`], asked of the key source that will be swept.
///
/// The one predicate for "can this sweep carry a memo": the GUI asks it
/// before scanning, `propose_sweep` and `execute_sweep` ask it again.
pub fn refuse_memo_for_key_source(source: &dyn KeySource, memo: Option<&str>) -> ZeckResult<()> {
    if source.wallet_seed()?.is_some() {
        return Ok(());
    }
    refuse_memo_without_seed(memo)
}

/// Why a seedless sweep shows no donation, for both surfaces to show in
/// place of the fee-threshold explanation, which is false for this route.
pub const SEEDLESS_DONATION_NOTE: &str = "This sweep sends no donation: only a full recovery \
     from a seed phrase can include one, so your full balance goes to your address.";

/// The proposal for a sweep with no seed phrase behind it.
///
/// Such a sweep sends neither a memo nor a donation, so the preview shows
/// neither: a dry run that promises what the sweep will not deliver is worse
/// than no dry run.
#[cfg(test)]
fn build_seedless_sweep_proposal(
    progress: &ScanProgress,
    request: SweepRequest,
    network: crate::models::ZeckNetwork,
) -> ZeckResult<SweepProposal> {
    refuse_memo_without_seed(request.memo.as_deref())?;

    // Modelled on what `sweep_imported_wallet` actually sends, not on the HD
    // sweep. Each imported Sapling account is swept in its own send-max
    // transaction, which is the HD model's final step, so that estimate is
    // reused for the shielded balance alone. Transparent funds go to the
    // destination in one direct transaction (`transparent_recovery`); the HD
    // model instead shielded them to the recovered wallet first, showing a
    // hop that never happens and charging two fees for it.
    let mut shielded_only = progress.clone();
    let mut transparent_zatoshis = 0u64;
    let mut transparent_utxos = 0usize;
    let mut transparent_account = None;
    for account in &mut shielded_only.accounts {
        if account.transparent_zatoshis > 0 {
            transparent_account.get_or_insert(account.account_index);
        }
        transparent_zatoshis = transparent_zatoshis
            .checked_add(account.transparent_zatoshis)
            .ok_or_else(|| {
                ZeckError::Internal("transparent balance overflowed the supported range".to_owned())
            })?;
        transparent_utxos += account.transparent_utxo_count as usize;
        account.total_zatoshis = account
            .total_zatoshis
            .saturating_sub(account.transparent_zatoshis);
        account.transparent_zatoshis = 0;
        account.transparent_utxo_count = 0;
    }

    let max_fee_zatoshis = request.max_fee_zatoshis;
    let destination = validate_destination_address(&request.destination, network)?.encoded;
    let mut proposal = build_sweep_proposal(&shielded_only, request, network, "")?;
    for tx in &mut proposal.transactions {
        tx.memo = None;
    }

    if let Some(account_index) = transparent_account {
        // Refused in the preview too: its transparent transaction needs a
        // Sapling receiver the address may not have.
        crate::transparent_recovery::sapling_receiver(&destination, network)?;
        let fee_zatoshis =
            crate::transparent_recovery::transparent_sweep_fee(network, transparent_utxos)?;
        if transparent_zatoshis <= fee_zatoshis {
            proposal.skipped_accounts.push(SkippedSweepAccount {
                account_index,
                gross_zatoshis: transparent_zatoshis,
                reason: format!(
                    "Transparent balance is too small to cover the {fee_zatoshis}-zat network fee to move it."
                ),
            });
        } else {
            let net_zatoshis = transparent_zatoshis - fee_zatoshis;
            let add = |total: u64, value: u64| {
                total.checked_add(value).ok_or_else(|| {
                    ZeckError::Internal("sweep proposal overflowed the supported range".to_owned())
                })
            };
            proposal.total_send_zatoshis = add(proposal.total_send_zatoshis, transparent_zatoshis)?;
            proposal.total_fee_zatoshis = add(proposal.total_fee_zatoshis, fee_zatoshis)?;
            proposal.net_received_zatoshis = add(proposal.net_received_zatoshis, net_zatoshis)?;
            proposal.transactions.push(ProposedTx {
                kind: ProposedTxKind::SweepShielded,
                leg_kind: crate::models::ProposedLegKind::DirectTransparent,
                source_account: account_index,
                destination,
                gross_zatoshis: transparent_zatoshis,
                fee_zatoshis,
                net_zatoshis,
                donation_zatoshis: 0,
                note: format!(
                    "Estimated sweep of {transparent_utxos} transparent UTXO(s) straight to your \
                     destination's Sapling receiver, in one transaction."
                ),
                memo: None,
            });
        }
        // `build_sweep_proposal` checked the cap before this transaction
        // existed; check the whole sweep again now that it does.
        enforce_max_fee(proposal.total_fee_zatoshis, max_fee_zatoshis).map_err(|_| {
            ZeckError::MaxFeeExceeded(format!(
                "estimated fee {} zats exceeds limit {} zats",
                proposal.total_fee_zatoshis,
                max_fee_zatoshis.unwrap_or_default()
            ))
        })?;
    }

    if proposal.net_received_zatoshis > 0 {
        proposal.warning = Some(
            "This dry-run proposal uses the balances from the completed scan. A wallet without \
             a seed phrase is swept one imported Sapling key per transaction, and its \
             transparent funds in one more, each straight to your destination."
                .to_owned(),
        );
    }
    proposal.donation_note = Some(SEEDLESS_DONATION_NOTE.to_owned());
    Ok(proposal)
}

/// Quote HD and standalone keys as one recovery, keeping the independent
/// signing routes and applying the fee cap to their combined cost.
#[cfg(test)]
fn build_combined_sweep_proposal(
    progress: &ScanProgress,
    request: SweepRequest,
    network: crate::models::ZeckNetwork,
    hd_indices: &[u32],
    imported_indices: &[u32],
    standalone_transparent: &HashMap<u32, crate::scan::StandaloneTransparentBalance>,
) -> ZeckResult<SweepProposal> {
    let mut hd_progress = progress.clone();
    hd_progress.accounts.clear();
    let mut imported_progress = hd_progress.clone();
    let mut seen = std::collections::HashSet::new();

    for row in &progress.accounts {
        if !seen.insert(row.account_index) {
            return Err(ZeckError::Wallet(format!(
                "duplicate recovery account index {}",
                row.account_index
            )));
        }
        let standalone = standalone_transparent
            .get(&row.account_index)
            .copied()
            .unwrap_or_default();
        if hd_indices.contains(&row.account_index) {
            let mut hd_row = row.clone();
            hd_row.transparent_zatoshis = hd_row
                .transparent_zatoshis
                .checked_sub(standalone.zatoshis)
                .ok_or_else(|| {
                    ZeckError::Wallet(
                        "standalone transparent balance exceeds account balance".to_owned(),
                    )
                })?;
            hd_row.transparent_utxo_count = hd_row
                .transparent_utxo_count
                .checked_sub(standalone.utxo_count)
                .ok_or_else(|| {
                    ZeckError::Wallet(
                        "standalone transparent inputs exceed account inputs".to_owned(),
                    )
                })?;
            hd_row.total_zatoshis = hd_row
                .total_zatoshis
                .checked_sub(standalone.zatoshis)
                .ok_or_else(|| {
                    ZeckError::Wallet(
                        "standalone transparent balance exceeds account total".to_owned(),
                    )
                })?;
            hd_progress.accounts.push(hd_row);
            if standalone.zatoshis > 0 {
                let mut direct_row = row.clone();
                direct_row.sapling_zatoshis = 0;
                direct_row.orchard_zatoshis = 0;
                direct_row.transparent_zatoshis = standalone.zatoshis;
                direct_row.transparent_utxo_count = standalone.utxo_count;
                direct_row.total_zatoshis = standalone.zatoshis;
                imported_progress.accounts.push(direct_row);
            }
        } else if imported_indices.contains(&row.account_index) {
            imported_progress.accounts.push(row.clone());
        } else if row.total_zatoshis > 0 {
            return Err(ZeckError::Wallet(format!(
                "recovery account {} has no spend authority",
                row.account_index
            )));
        }
    }
    if standalone_transparent
        .keys()
        .any(|index| !seen.contains(index))
    {
        return Err(ZeckError::Wallet(
            "standalone transparent balance has no recovery account".to_owned(),
        ));
    }

    let mut unbounded = request.clone();
    unbounded.max_fee_zatoshis = None;
    let mut hd = build_sweep_proposal(
        &hd_progress,
        unbounded.clone(),
        network,
        crate::donation::DONATION_ADDRESS,
    )?;
    unbounded.memo = None;
    unbounded.donation_rate = None;
    unbounded.donor_email = None;
    let imported = build_seedless_sweep_proposal(&imported_progress, unbounded, network)?;
    let add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or_else(|| ZeckError::Internal("combined sweep proposal overflowed".to_owned()))
    };
    hd.total_send_zatoshis = add(hd.total_send_zatoshis, imported.total_send_zatoshis)?;
    hd.total_fee_zatoshis = add(hd.total_fee_zatoshis, imported.total_fee_zatoshis)?;
    hd.net_received_zatoshis = add(hd.net_received_zatoshis, imported.net_received_zatoshis)?;
    hd.total_donation_zatoshis = add(hd.total_donation_zatoshis, imported.total_donation_zatoshis)?;
    enforce_max_fee(hd.total_fee_zatoshis, request.max_fee_zatoshis)?;
    hd.transactions.extend(imported.transactions);
    hd.skipped_accounts.extend(imported.skipped_accounts);
    hd.warning = Some("This proposal combines mnemonic-derived and standalone keys. Memo and donation apply only to mnemonic-derived transactions; standalone Sapling and transparent sweeps carry neither.".to_owned());
    Ok(hd)
}

type MixedAuthorityPartition = (Vec<u32>, Vec<u32>, Vec<(u32, AccountUuid, usize)>);

fn partition_mixed_spend_authorities(
    tracked_accounts: &[TrackedAccount],
) -> ZeckResult<MixedAuthorityPartition> {
    let mut hd_indices = Vec::new();
    let mut imported_indices = Vec::new();
    let mut imported_accounts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for tracked in tracked_accounts {
        if !seen.insert(tracked.derived.index) {
            return Err(ZeckError::Wallet(format!(
                "duplicate recovery account index {}",
                tracked.derived.index
            )));
        }
        match tracked.spend_authority {
            TrackedSpendAuthority::Hd { .. } => hd_indices.push(tracked.derived.index),
            TrackedSpendAuthority::ImportedSapling {
                key_index,
                wallet_account_id,
            } => {
                if wallet_account_id != tracked.wallet_account_id {
                    return Err(ZeckError::Wallet(
                        "imported signing account differs from scan account".to_owned(),
                    ));
                }
                imported_indices.push(tracked.derived.index);
                imported_accounts.push((tracked.derived.index, wallet_account_id, key_index));
            }
        }
    }
    Ok((hd_indices, imported_indices, imported_accounts))
}

#[allow(clippy::too_many_arguments)]
async fn execute_sweep_for_session(
    session: SharedScanSession,
    request: SweepRequest,
    initial_fee_zatoshis: u64,
    quoted_transactions: Vec<ProposedTx>,
    quoted_skipped: Vec<SkippedSweepAccount>,
    backend_legs: Vec<ExactSweepLeg>,
    tracked_accounts: Vec<TrackedAccount>,
    exact_fees: ExactLegFees,
) -> ZeckResult<SweepOutcome> {
    let (runtime, workspace, progress) = {
        let guard = session.state.lock().await;
        let workspace = guard
            .workspace
            .clone()
            .ok_or_else(|| ZeckError::ScanNotReady("wallet workspace is unavailable".to_owned()))?;
        (session.runtime.clone(), workspace, guard.progress.clone())
    };
    let mut broadcast_log = DurableBroadcastLog::open(network_broadcast_log_path(
        &runtime.data_dir,
        runtime.network,
    )?)?;
    // The execution-start gate refused unresolved history from earlier
    // reviews. Imported legs of this same execution may already be Pending;
    // only an unknown outcome stops the HD legs.
    if let Some(txid) = broadcast_log.blocking_next_leg() {
        return Err(ZeckError::Broadcast(format!(
            "transaction {txid} may already have reached the network or was retryably refused; reconcile its durable record before starting another sweep leg"
        )));
    }

    // A scan cannot have reached this point without a seed — `run_recovery_scan_inner`
    // rejects a seedless key source before it derives anything — so this is a
    // consistency check rather than a user-facing path.
    let seed = runtime.key_source.wallet_seed()?.ok_or_else(|| {
        ZeckError::InvalidConfig(format!(
            "cannot sweep {}: standalone keys with no HD seed are not yet spendable",
            runtime.key_source.describe()
        ))
    })?;
    let transparent_account = legacy_transparent_account_key_from_seed(runtime.network, &seed)?;
    let network = consensus_network(runtime.network);
    let prover = LocalTxProver::bundled();
    // Sum of the donation outputs actually broadcast (0 when a per-account
    // donation was below the floor or its split fell back). Reported on the
    // outcome so the completion screen shows the true donated total rather than
    // the proposal's estimate.
    let mut total_donation_zatoshis = 0u64;
    let mut follow_up_review_required = false;
    let mut results = Vec::new();
    // Accounts that held a balance but moved nothing (all spendable value below
    // the ZIP-317 fee floor). Collected so the completion screen can show the
    // skip instead of it being silent.
    let mut skipped_accounts: Vec<SkippedSweepAccount> = Vec::new();

    let preferred_endpoint = progress
        .server
        .as_ref()
        .map(|server| server.endpoint.as_str());
    let (mut client, _primary_endpoint) =
        connect_lightwalletd_endpoints_with_retry(&runtime.lightwalletd_url, preferred_endpoint)
            .await?;
    let lightwalletd_info = client
        .get_lightd_info(zcash_client_backend::proto::service::Empty {})
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    validate_lightwalletd_network(runtime.network, &lightwalletd_info)?;

    // The final sync, balance refresh, and complete plan comparison ran in
    // execute_sweep_locked. A second sync here could change selected inputs
    // after the review gate, so every builder below uses that validated plan.

    // Walk the validated reviewed legs, not the tracked accounts: a leg the
    // user reviewed can never be silently skipped. `hd_leg_plan` already
    // refused (before anything was signed) a leg with no executable account.
    let hd_legs = hd_leg_plan(&backend_legs, &tracked_accounts)?;
    // Accounts the review itself skipped are reported as reviewed.
    skipped_accounts.extend(quoted_skipped.into_iter().filter(|skipped| {
        tracked_accounts.iter().any(|account| {
            account.derived.index == skipped.account_index
                && matches!(account.spend_authority, TrackedSpendAuthority::Hd { .. })
        })
    }));

    // The legs broadcast one at a time. Run them inside a block whose `?`
    // failures are *caught* rather than propagated, so a mid-sequence abort
    // still surfaces the records of every transaction already broadcast
    // (audit Issue E) instead of discarding `results`.
    let sweep_result: ZeckResult<()> = async {
        for (position, (tracked_account, zip32_index, leg)) in hd_legs.into_iter().enumerate() {
            if position > 0 {
                // R-S29 hook: a no-op outside execute_sweep_with_test_pause.
                pause_between_broadcasts().await;
            }
            let usk =
                UnifiedSpendingKey::from_seed(&network, &seed, zip32_index).map_err(|err| {
                    ZeckError::Wallet(format!(
                        "deriving account {}: {err}",
                        tracked_account.derived.index
                    ))
                })?;
            let prior_fee_zatoshis =
                checked_fee_total(initial_fee_zatoshis, at_risk_fee_total(&results)?)?;
            match leg {
                ExactSweepLeg::HdShield {
                    account_index,
                    proposal,
                } => {
                    let mut ctx = SweepStepCtx {
                        workspace: &workspace,
                        network: runtime.network,
                        client: &mut client,
                        prover: &prover,
                        results: &mut results,
                        broadcast_log: &mut broadcast_log,
                        prior_fee_zatoshis,
                        max_fee_zatoshis: request.max_fee_zatoshis,
                        reviewed_fee_zatoshis: exact_fees
                            .require(ExactFeeKey::HdShield(*account_index))?,
                        lightwalletd_url: runtime.lightwalletd_url.as_str(),
                        confirmation_sources: &runtime.confirmation_sources,
                    };
                    execute_shielding_step(
                        &mut ctx,
                        tracked_account,
                        &transparent_account,
                        &usk,
                        proposal,
                    )
                    .await?;
                    // The shielded output is not spendable until it has mined
                    // and acquired a witness. A new scan and proposal must
                    // authorize the later send-max transaction.
                    follow_up_review_required = true;
                }
                ExactSweepLeg::HdSend {
                    account_index,
                    proposal,
                    donation_zatoshis,
                } => {
                    let mut ctx = SweepStepCtx {
                        workspace: &workspace,
                        network: runtime.network,
                        client: &mut client,
                        prover: &prover,
                        results: &mut results,
                        broadcast_log: &mut broadcast_log,
                        prior_fee_zatoshis,
                        max_fee_zatoshis: request.max_fee_zatoshis,
                        reviewed_fee_zatoshis: exact_fees
                            .require(ExactFeeKey::HdSend(*account_index))?,
                        lightwalletd_url: runtime.lightwalletd_url.as_str(),
                        confirmation_sources: &runtime.confirmation_sources,
                    };
                    let (_fee, account_donation) = execute_send_max_step(
                        &mut ctx,
                        tracked_account,
                        &usk,
                        proposal,
                        *donation_zatoshis,
                    )
                    .await?;
                    total_donation_zatoshis = total_donation_zatoshis
                        .checked_add(account_donation)
                        .ok_or_else(|| {
                            ZeckError::Internal(
                                "donation total overflowed the supported range".to_owned(),
                            )
                        })?;
                }
                _ => unreachable!("hd_leg_plan returns only HD legs"),
            }
        }
        Ok(())
    }
    .await;

    assemble_sweep_outcome(
        results,
        skipped_accounts,
        total_donation_zatoshis,
        sweep_result,
    )
    .map(|mut outcome| {
        outcome.follow_up_review_required = follow_up_review_required;
        apply_recorded_shield_follow_up(&mut outcome, &quoted_transactions);
        outcome
    })
}

/// Pair every reviewed HD leg with the HD account that signs it, in the
/// reviewed order. Refuses -- before anything is signed -- a leg whose account
/// is missing, is not HD, or has an out-of-range ZIP-32 index.
fn hd_leg_plan<'a>(
    legs: &'a [ExactSweepLeg],
    tracked_accounts: &'a [TrackedAccount],
) -> ZeckResult<Vec<(&'a TrackedAccount, zip32::AccountId, &'a ExactSweepLeg)>> {
    legs.iter()
        .filter_map(|leg| match leg {
            ExactSweepLeg::HdShield { account_index, .. }
            | ExactSweepLeg::HdSend { account_index, .. } => Some((*account_index, leg)),
            _ => None,
        })
        .map(|(account_index, leg)| {
            let tracked = tracked_accounts
                .iter()
                .find(|account| account.derived.index == account_index)
                .ok_or_else(|| {
                    ZeckError::StaleSweepProposal(format!(
                        "reviewed leg for account {account_index} has no scanned account; nothing was signed"
                    ))
                })?;
            let TrackedSpendAuthority::Hd { zip32_index } = tracked.spend_authority else {
                return Err(ZeckError::StaleSweepProposal(format!(
                    "reviewed HD leg for account {account_index} is not signed by the seed; nothing was signed"
                )));
            };
            let zip32_index = zip32::AccountId::try_from(zip32_index).map_err(|_| {
                ZeckError::InvalidConfig(format!(
                    "account index {account_index} is out of range; nothing was signed"
                ))
            })?;
            Ok((tracked, zip32_index, leg))
        })
        .collect()
}

fn hd_has_shielded_balance(row: &crate::models::AccountBalancePreview) -> ZeckResult<bool> {
    row.total_zatoshis
        .checked_sub(row.transparent_zatoshis)
        .map(|shielded| shielded > 0)
        .ok_or_else(|| {
            ZeckError::Wallet(format!(
                "account {} transparent balance exceeds its total",
                row.account_index
            ))
        })
}

fn apply_recorded_shield_follow_up(outcome: &mut SweepOutcome, quote: &[ProposedTx]) {
    outcome.follow_up_review_required |= outcome.transactions.iter().any(|result| {
        result.txid.is_some()
            && result.status.fee_is_at_risk()
            && quote.iter().any(|tx| {
                tx.kind == ProposedTxKind::ShieldTransparent
                    && tx.source_account == result.source_account
            })
    });
}

/// Fold the accumulated broadcast records and the loop's terminal status into a
/// [`SweepOutcome`].
///
/// - Full success (`Ok(())`) → `Ok` with no error.
/// - Aborted after recording at least one submission → `Ok` carrying the
///   records plus the error message, including an uncertain first submission.
/// - Aborted before any submission (empty `results`) → propagate the `Err`.
///
/// `skipped_accounts` records accounts that held a balance but moved nothing
/// (every spendable note below the ZIP-317 fee floor); it rides along on the
/// `Ok` outcomes so the UI can surface the skip.
fn assemble_sweep_outcome(
    results: Vec<TxBroadcastResult>,
    skipped_accounts: Vec<SkippedSweepAccount>,
    total_donation_zatoshis: u64,
    sweep_result: ZeckResult<()>,
) -> ZeckResult<SweepOutcome> {
    match sweep_result {
        Ok(()) => Ok(SweepOutcome {
            transactions: results,
            skipped_accounts,
            total_donation_zatoshis,
            error: None,
            donation_note: None,
            follow_up_review_required: false,
        }),
        Err(err) => {
            if results.is_empty() {
                Err(err)
            } else {
                let uncertain = results
                    .iter()
                    .any(|tx| tx.status == TxLifecycleState::SubmissionUnknown);
                let error = if uncertain {
                    format!("{err}. A transaction may already have reached the network; reconcile its txid before retrying or discarding the source wallet.")
                } else {
                    err.to_string()
                };
                Ok(SweepOutcome {
                    transactions: results,
                    skipped_accounts,
                    total_donation_zatoshis,
                    error: Some(error),
                    donation_note: None,
                    follow_up_review_required: false,
                })
            }
        }
    }
}

struct SweepStepCtx<'a> {
    workspace: &'a RecoveryWorkspace,
    network: crate::models::ZeckNetwork,
    client: &'a mut CompactTxStreamerClient<tonic::transport::Channel>,
    prover: &'a LocalTxProver,
    results: &'a mut Vec<TxBroadcastResult>,
    broadcast_log: &'a mut DurableBroadcastLog,
    prior_fee_zatoshis: u64,
    max_fee_zatoshis: Option<u64>,
    reviewed_fee_zatoshis: u64,
    lightwalletd_url: &'a str,
    confirmation_sources: &'a [ConfirmationEndpoint],
}

/// The change strategy used for every Argos proposal: ZIP-317 fees, no change
/// memo, Orchard as the fallback change pool, default dust handling. Extracted
/// so the shielding step and the donation-split step cannot drift apart.
fn standard_zip317_change_strategy<I>() -> SingleOutputChangeStrategy<I> {
    SingleOutputChangeStrategy::<I>::new(
        StandardFeeRule::Zip317,
        None,
        // Fallback change pool only. From Ironwood (NU6.3) activation the turnstile
        // forbids value entering the Orchard pool, and the change strategy coerces this
        // fallback to Ironwood for those transactions; below activation it still means
        // Orchard, as before.
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    )
}

fn propose_hd_shielding(
    wallet_db: &mut SweepWalletDb,
    network: crate::models::ZeckNetwork,
    tracked_account: &TrackedAccount,
) -> ZeckResult<Option<zcash_client_backend::proposal::Proposal<StandardFeeRule, Infallible>>> {
    let input_selector = GreedyInputSelector::<_>::new();
    let change_strategy = standard_zip317_change_strategy();
    match propose_shielding::<_, _, _, _, Infallible>(
        wallet_db,
        &consensus_network(network),
        &input_selector,
        &change_strategy,
        Zatoshis::ZERO,
        &tracked_account.transparent_receivers,
        tracked_account.wallet_account_id,
        ConfirmationsPolicy::MIN,
        CoinbaseFilter::AllTransparentOutputs,
        None,
    ) {
        Ok(proposal) => Ok(Some(proposal)),
        Err(err) => {
            let message = format!("building shielding proposal: {err}");
            if is_insufficient_funds_error(&message) {
                tracing::warn!(
                    "account {}: transparent funds not shieldable — {message}",
                    tracked_account.derived.index,
                );
                Ok(None)
            } else {
                Err(ZeckError::TransactionBuild(message))
            }
        }
    }
}

async fn execute_shielding_step(
    ctx: &mut SweepStepCtx<'_>,
    tracked_account: &TrackedAccount,
    transparent_account: &zcash_transparent::keys::AccountPrivKey,
    usk: &UnifiedSpendingKey,
    proposal: &HdSweepProposal,
) -> ZeckResult<u64> {
    let mut wallet_db = open_wallet_db(
        ctx.workspace.wallet_db_path(),
        consensus_network(ctx.network),
    )?;
    let fee_zatoshis = proposal_fee_zatoshis(proposal)?;
    require_fee_matches(ctx.reviewed_fee_zatoshis, fee_zatoshis)?;
    let fee_through_shield = checked_fee_total(ctx.prior_fee_zatoshis, fee_zatoshis)?;
    enforce_max_fee(fee_through_shield, ctx.max_fee_zatoshis)?;

    let standalone_keys =
        standalone_transparent_signing_keys(tracked_account, transparent_account)?;
    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        ctx.prover,
        ctx.prover,
        &SpendingKeys::new(usk.clone(), standalone_keys),
        OvkPolicy::Sender,
        proposal,
        // No explicit expiry override; keep the library's default expiry.
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating shielding transaction: {err}")))?;

    broadcast_transactions(
        ctx,
        &mut wallet_db,
        tracked_account.derived.index,
        txids.into_iter().collect(),
        "shielding",
        fee_zatoshis,
    )
    .await?;

    Ok(fee_zatoshis)
}

fn standalone_transparent_signing_keys(
    tracked_account: &TrackedAccount,
    transparent_account: &zcash_transparent::keys::AccountPrivKey,
) -> ZeckResult<HashMap<zcash_transparent::address::TransparentAddress, Vec<secp256k1::SecretKey>>>
{
    let mut keys = HashMap::new();
    for coordinate in &tracked_account.transparent_key_coordinates {
        keys.entry(coordinate.address)
            .or_insert_with(Vec::new)
            .push(legacy_transparent_secret_key(
                transparent_account,
                coordinate.scope,
                coordinate.index,
            )?);
    }
    Ok(keys)
}

/// Build a two-output proposal that splits the full account balance between a
/// donation output and the user's destination, converging on the ZIP-317 fee so
/// that no change output remains.
///
/// Returns `Some(proposal)` once the candidate fee matches the proposal's
/// computed fee, or `None` if convergence (or a positive user remainder) could
/// not be achieved — in which case the caller falls back to the donation-free
/// Reduce a donation-split build result to a concrete `Proposal`, falling
/// back to the donation-free `max_proposal` on both `Ok(None)` (the
/// helper's intentional fallback signal) and `Err(_)` (any unexpected
/// failure constructing the split). Logged on `Err` so a regression is
/// observable in production logs rather than silent.
///
/// Extracted from the inline match in `execute_send_max_step` so the
/// three-way branch is unit-testable without a wallet DB.
fn donation_proposal_or_fallback<P>(
    split_result: ZeckResult<Option<P>>,
    max_proposal: P,
    donation: u64,
    account_index: u32,
) -> (P, u64) {
    match split_result {
        // Split built: the donation output carries `donation` zatoshis.
        Ok(Some(proposal)) => (proposal, donation),
        // Fell back to the donation-free sweep: nothing was actually donated.
        Ok(None) => (max_proposal, 0),
        Err(err) => {
            tracing::warn!(
                "donation split proposal failed for account {account_index}: {err}; \
                 falling back to donation-free sweep for this account",
            );
            (max_proposal, 0)
        }
    }
}

/// send-max sweep. This is a pure extraction of the inline two-pass logic; the
/// checked arithmetic, convergence loop, and fallback semantics are unchanged.
#[allow(clippy::too_many_arguments)]
fn build_donation_split_proposal(
    wallet_db: &mut SweepWalletDb,
    network: crate::models::ZeckNetwork,
    account_id: AccountUuid,
    destination_address: &ZcashAddress,
    memo_bytes: Option<MemoBytes>,
    donation_zcash_address: &ZcashAddress,
    donation_memo: Option<MemoBytes>,
    send_amount: u64,
    send_max_fee: u64,
    donation: u64,
) -> ZeckResult<Option<zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>>> {
    let total_spendable = send_amount.checked_add(send_max_fee).ok_or_else(|| {
        ZeckError::Internal("send amount plus fee overflowed the supported range".to_owned())
    })?;
    // Iterative fee convergence: two fixed payments summing to
    // (total_spendable - fee) drive change to zero once the candidate fee
    // matches the proposal's computed fee. Seed from the send-max fee PLUS one
    // ZIP-317 marginal action: the extra donation output costs exactly that, so
    // iteration 1 already has enough fee budget and `propose_transfer` doesn't
    // fail with insufficient funds before the loop can adjust. (Seeding from the
    // bare single-output send-max fee under-budgets the donation output and was
    // the bug that made every donation silently fall back to a donation-free
    // sweep.)
    let mut candidate_fee = send_max_fee.saturating_add(u64::from(MARGINAL_FEE));
    for _ in 0..MAX_FEE_CONVERGENCE_ITERS {
        let remainder = total_spendable
            .checked_sub(donation)
            .and_then(|v| v.checked_sub(candidate_fee));
        let remainder = match remainder {
            Some(r) if r > 0 => r,
            _ => break,
        };
        let request = zip321::TransactionRequest::new(vec![
            zip321::Payment::new(
                donation_zcash_address.clone(),
                Some(Zatoshis::from_u64(donation).map_err(|err| {
                    ZeckError::TransactionBuild(format!("donation amount out of range: {err}"))
                })?),
                donation_memo.clone(),
                None,
                None,
                vec![],
            )
            .map_err(|err| {
                ZeckError::TransactionBuild(format!("invalid donation payment: {err}"))
            })?,
            zip321::Payment::new(
                destination_address.clone(),
                Some(Zatoshis::from_u64(remainder).map_err(|err| {
                    ZeckError::TransactionBuild(format!("destination amount out of range: {err}"))
                })?),
                memo_bytes.clone(),
                None,
                None,
                vec![],
            )
            .map_err(|err| {
                ZeckError::TransactionBuild(format!(
                    "invalid destination payment in donation split: {err}"
                ))
            })?,
        ])
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("building donation transfer request: {err}"))
        })?;
        let input_selector = GreedyInputSelector::<_>::new();
        let change_strategy = standard_zip317_change_strategy();
        match propose_transfer::<_, _, _, _, Infallible>(
            wallet_db,
            &consensus_network(network),
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            // This split runs after shielding, so it spends shielded value only —
            // matching the pre-0.24 behaviour, where `propose_transfer` had no policy
            // argument and drew on the shielded pools alone. Ironwood is included for
            // the same reason it is in the sweep proposal: post-NU6.3 value can live
            // there.
            &SpendPolicy::shielded_pools([
                ShieldedPool::Sapling,
                ShieldedPool::Orchard,
                ShieldedPool::Ironwood,
            ]),
            // No advisory input locks; no transaction-version override, so the library
            // selects the version required at the target height (V6 from Ironwood
            // activation onward).
            None,
            None,
        ) {
            Ok(proposal) => {
                let fee = proposal_fee_zatoshis(&proposal)?;
                if fee == candidate_fee {
                    return Ok(Some(proposal));
                }
                candidate_fee = fee;
            }
            // The seed candidate fee is the *single-output* send-max fee, which
            // under-budgets the extra donation output — so the first proposal
            // fails with "insufficient funds" before the fee can converge. Raise
            // the candidate by one ZIP-317 marginal action and retry rather than
            // aborting the donation. THIS is the bug that made the donation split
            // silently fall back to a donation-free sweep on every sweep; the
            // path was never exercised end-to-end (all tests pass donation_rate
            // = None / use string stand-ins).
            Err(err) if is_insufficient_funds_error(&err.to_string()) => {
                candidate_fee = candidate_fee
                    .checked_add(u64::from(MARGINAL_FEE))
                    .ok_or_else(|| {
                        ZeckError::Internal(
                            "donation fee convergence overflowed the supported range".to_owned(),
                        )
                    })?;
            }
            Err(err) => {
                return Err(ZeckError::TransactionBuild(format!(
                    "building donation sweep proposal: {err}"
                )));
            }
        }
    }
    tracing::warn!(
        "donation split did not converge within {MAX_FEE_CONVERGENCE_ITERS} iterations; \
         falling back to a donation-free sweep for this account",
    );
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn propose_hd_send_max(
    wallet_db: &mut SweepWalletDb,
    network: crate::models::ZeckNetwork,
    account_id: AccountUuid,
    account_index: u32,
    destination_address: &ZcashAddress,
    memo_bytes: Option<MemoBytes>,
    donation_address: &str,
    donation_rate: Option<f64>,
    donation_memo: Option<MemoBytes>,
) -> ZeckResult<
    Option<(
        zcash_client_backend::proposal::Proposal<StandardFeeRule, ReceivedNoteId>,
        u64,
    )>,
> {
    // Pass 1 — measure the full-account send-max proposal (build only, no broadcast).
    let max_proposal = match propose_send_max_transfer::<_, _, _, Infallible>(
        wallet_db,
        &consensus_network(network),
        account_id,
        // Argos sweeps an account empty, so every shielded pool a recovered wallet can
        // hold value in must be spendable. Ironwood joins the list at NU6.3: funds
        // landing there after activation would otherwise be left behind by a sweep that
        // reported success.
        &[
            ShieldedPool::Sapling,
            ShieldedPool::Orchard,
            ShieldedPool::Ironwood,
        ],
        &StandardFeeRule::Zip317,
        destination_address.clone(),
        memo_bytes.clone(),
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::MIN,
        // Argos takes no advisory input locks; never draw on another holder's.
        &LockedInputPolicy::Exclude,
        None,
    ) {
        Ok(proposal) => proposal,
        Err(err) => {
            let message = format!("building sweep proposal: {err}");
            if is_insufficient_funds_error(&message) {
                // No selectable shielded value clears the fee floor (dust
                // notes, or nothing spendable at the required confirmations).
                // Skip this account rather than aborting the whole sweep.
                return Ok(None);
            }
            return Err(ZeckError::TransactionBuild(message));
        }
    };
    let send_max_fee = proposal_fee_zatoshis(&max_proposal)?;
    // Send-max is single-step with exactly one payment; read the amount destined
    // for the user (the full account spendable equals send_amount + send_max_fee).
    let send_amount: u64 = max_proposal
        .steps()
        .first()
        .transaction_request()
        .payments()
        .values()
        .next()
        .and_then(|payment| payment.amount())
        .map(u64::from)
        .ok_or_else(|| {
            ZeckError::TransactionBuild(
                "send-max proposal contained no payment output amount".to_owned(),
            )
        })?;

    let donation =
        crate::donation::donation_for_send_amount(donation_address, donation_rate, send_amount);

    // `donation_zatoshis` is the amount *actually* placed in a donation output:
    // the requested `donation` when the split proposal is used, or 0 when there
    // is no donation or the split fell back to the donation-free sweep. Returned
    // so the caller can report the true donated total (the proposal figure is
    // only an estimate).
    let (proposal, donation_zatoshis) = if donation == 0 {
        // No donation output: behavior is unchanged from the single-pass sweep.
        (max_proposal, 0)
    } else {
        let donation_zcash_address =
            ZcashAddress::try_from_encoded(donation_address).map_err(|err| {
                ZeckError::InvalidAddress(format!("failed to decode donation address: {err}"))
            })?;
        // On non-convergence (or a non-positive user remainder) fall back to the
        // donation-free send-max sweep. The `Err` case is treated identically
        // to `Ok(None)`: anything that prevents us from constructing the
        // donation split (zip321 validation, unexpected proposal error,
        // future regressions) must not lose the user their sweep. Donation is
        // best-effort; the user's recovery is not.
        let split_result = build_donation_split_proposal(
            wallet_db,
            network,
            account_id,
            destination_address,
            memo_bytes.clone(),
            &donation_zcash_address,
            donation_memo.clone(),
            send_amount,
            send_max_fee,
            donation,
        );
        donation_proposal_or_fallback(split_result, max_proposal, donation, account_index)
    };

    Ok(Some((proposal, donation_zatoshis)))
}

async fn execute_send_max_step(
    ctx: &mut SweepStepCtx<'_>,
    tracked_account: &TrackedAccount,
    usk: &UnifiedSpendingKey,
    proposal: &ImportedSweepProposal,
    donation_zatoshis: u64,
) -> ZeckResult<(u64, u64)> {
    let mut wallet_db = open_wallet_db(
        ctx.workspace.wallet_db_path(),
        consensus_network(ctx.network),
    )?;

    let fee_zatoshis = proposal_fee_zatoshis(proposal)?;
    require_fee_matches(ctx.reviewed_fee_zatoshis, fee_zatoshis)?;
    enforce_max_fee(
        checked_fee_total(ctx.prior_fee_zatoshis, fee_zatoshis)?,
        ctx.max_fee_zatoshis,
    )?;

    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
        &mut wallet_db,
        &consensus_network(ctx.network),
        ctx.prover,
        ctx.prover,
        &SpendingKeys::from_unified_spending_key(usk.clone()),
        OvkPolicy::Sender,
        proposal,
        // No explicit expiry override; keep the library's default expiry.
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("creating sweep transaction: {err}")))?;

    broadcast_transactions(
        ctx,
        &mut wallet_db,
        tracked_account.derived.index,
        txids.into_iter().collect(),
        "sweep",
        fee_zatoshis,
    )
    .await?;

    Ok((fee_zatoshis, donation_zatoshis))
}

pub(crate) fn proposal_fee_zatoshis<NoteRef>(
    proposal: &zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>,
) -> ZeckResult<u64> {
    proposal.steps().iter().try_fold(0u64, |sum, step| {
        sum.checked_add(u64::from(step.balance().fee_required()))
            .ok_or_else(|| {
                ZeckError::Internal("fee total overflowed the supported range".to_owned())
            })
    })
}

pub(crate) fn checked_fee_total(
    prior_fee_zatoshis: u64,
    next_fee_zatoshis: u64,
) -> ZeckResult<u64> {
    prior_fee_zatoshis
        .checked_add(next_fee_zatoshis)
        .ok_or_else(|| ZeckError::Internal("fee total overflowed the supported range".to_owned()))
}

fn require_fee_matches(reviewed: u64, current: u64) -> ZeckResult<()> {
    if reviewed == current {
        Ok(())
    } else {
        Err(ZeckError::FeeQuoteChanged { reviewed, current })
    }
}

fn require_persisted_batch_fee(
    reviewed: u64,
    fees: impl IntoIterator<Item = u64>,
) -> ZeckResult<()> {
    let current = fees.into_iter().try_fold(0u64, checked_fee_total)?;
    require_fee_matches(reviewed, current)
}

pub(crate) fn at_risk_fee_total(results: &[TxBroadcastResult]) -> ZeckResult<u64> {
    results
        .iter()
        .filter(|result| result.status.fee_is_at_risk())
        .try_fold(0, |sum, result| checked_fee_total(sum, result.fee_zatoshis))
}

pub(crate) fn enforce_max_fee(
    total_fee_zatoshis: u64,
    max_fee_zatoshis: Option<u64>,
) -> ZeckResult<()> {
    if let Some(max_fee_zatoshis) = max_fee_zatoshis {
        if total_fee_zatoshis > max_fee_zatoshis {
            return Err(ZeckError::MaxFeeExceeded(format!(
                "actual fee {total_fee_zatoshis} zats exceeds limit {max_fee_zatoshis} zats"
            )));
        }
    }

    Ok(())
}

fn normalized_memo_text(memo: Option<&str>) -> ZeckResult<String> {
    let value = memo
        .map(str::trim)
        .filter(|memo| !memo.is_empty())
        .unwrap_or(RECOVERY_MEMO_DEFAULT);

    MemoBytes::from_bytes(value.as_bytes())
        .map_err(|err| ZeckError::InvalidMemo(err.to_string()))?;
    Ok(value.to_owned())
}

fn estimate_remaining_seconds(progress: &ScanProgress, elapsed_seconds: u64) -> Option<u64> {
    if progress.blocks_total == 0 {
        return None;
    }
    if progress.blocks_scanned >= progress.blocks_total {
        return Some(0);
    }
    if progress.blocks_scanned < 100 || elapsed_seconds < 5 {
        return None;
    }

    let remaining_blocks = progress
        .blocks_total
        .saturating_sub(progress.blocks_scanned);
    Some(
        remaining_blocks
            .saturating_mul(elapsed_seconds)
            .checked_div(progress.blocks_scanned)
            .unwrap_or(0),
    )
}

/// Adapt an imported-wallet sweep to the shared `SweepOutcome`.
///
/// An imported wallet moves its two pools in two transactions, so both are
/// reported as separate entries. A pool that held nothing appears as a
/// skipped account rather than being omitted: a pool silently missing from
/// the report is indistinguishable from one that was never attempted.
///
/// The sweep's terminal status is folded in through `assemble_sweep_outcome`
/// rather than propagated with `?`, exactly as the HD path does. An imported
/// wallet broadcasts one transaction per Sapling account, so a failure on
/// the third account arrives with two transactions already on-chain;
/// returning `Err` there would drop their txids and report a total failure
/// for a sweep that moved real funds (audit Issue E, second occurrence).
async fn sweep_imported_session(
    runtime: &RuntimeScanConfig,
    keys: &argos_wallet_import::ImportedKeys,
    request: &SweepRequest,
    backend_legs: &[ExactSweepLeg],
    exact_fees: &ExactLegFees,
) -> ZeckResult<SweepOutcome> {
    let reviewed_sapling_fees = exact_fees.imported_sapling_map();
    let reviewed_transparent_fee = exact_fees.0.get(&ExactFeeKey::DirectTransparent).copied();
    let imported_plan = imported_execution_plan(backend_legs);
    let (outcome, sweep_result) = crate::imported_sweep::sweep_imported_wallet_reviewed(
        runtime,
        keys,
        &request.destination,
        request.max_fee_zatoshis,
        Some(&reviewed_sapling_fees),
        reviewed_transparent_fee,
        Some(&imported_plan),
    )
    .await;

    assemble_imported_sweep_outcome(outcome, sweep_result)
}

fn imported_execution_plan(legs: &[ExactSweepLeg]) -> crate::imported_sweep::ImportedExecutionPlan {
    let mut plan = crate::imported_sweep::ImportedExecutionPlan::default();
    for leg in legs {
        match leg {
            ExactSweepLeg::ImportedSapling {
                account_id,
                proposal,
                ..
            } => {
                plan.sapling.insert(*account_id, proposal.clone());
            }
            ExactSweepLeg::DirectTransparent {
                utxos,
                plan: cost,
                target_height,
                ..
            } => {
                plan.transparent = Some((utxos.clone(), cost.clone(), *target_height));
            }
            _ => {}
        }
    }
    plan
}

/// Fold an imported-wallet sweep's records and terminal status into a
/// [`SweepOutcome`].
///
/// Separated from the sweep itself so the partial-failure path — records
/// kept, error surfaced — is exercisable without a node. It is the only
/// route from an [`ImportedSweepOutcome`] to a `SweepOutcome`; there is no
/// second one to drift from it.
///
/// [`ImportedSweepOutcome`]: crate::imported_sweep::ImportedSweepOutcome
fn assemble_imported_sweep_outcome(
    outcome: crate::imported_sweep::ImportedSweepOutcome,
    sweep_result: ZeckResult<()>,
) -> ZeckResult<SweepOutcome> {
    assemble_imported_sweep_outcome_for_legs(outcome, sweep_result, true, true)
}

fn assemble_imported_sweep_outcome_for_legs(
    outcome: crate::imported_sweep::ImportedSweepOutcome,
    sweep_result: ZeckResult<()>,
    sapling_expected: bool,
    transparent_expected: bool,
) -> ZeckResult<SweepOutcome> {
    let transactions = outcome.transactions;
    let mut skipped_accounts = Vec::new();
    // Only claimed when the leg actually ran to the end. A leg that aborted
    // has not established that the pool is empty, and reporting "holds no
    // spendable Sapling notes" for a pool whose sweep failed would tell the
    // user the opposite of what happened.
    if sapling_expected && outcome.sapling_transaction_count == 0 && outcome.sapling_leg_completed {
        skipped_accounts.push(SkippedSweepAccount {
            account_index: outcome.sapling_empty_display_index.unwrap_or(0),
            reason: "the imported wallet holds no spendable Sapling notes".to_owned(),
            gross_zatoshis: 0,
        });
    }

    if transparent_expected
        && !outcome.transparent_transaction_recorded
        && outcome.transparent_leg_completed
    {
        skipped_accounts.push(SkippedSweepAccount {
            account_index: outcome.transparent_display_index.unwrap_or(0),
            reason: "the imported wallet holds no spendable transparent funds".to_owned(),
            gross_zatoshis: 0,
        });
    }

    assemble_sweep_outcome(
        transactions,
        skipped_accounts,
        // Donations are not split out of an imported sweep: the Sapling
        // path builds a single-step send-max proposal, which has no room
        // for a second output.
        0,
        sweep_result,
    )
    .map(|mut assembled| {
        assembled.donation_note = Some(SEEDLESS_DONATION_NOTE.to_owned());
        assembled
    })
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};

    use super::{
        build_seedless_sweep_proposal, build_sweep_proposal, is_distinct_lightwalletd_endpoint,
        standalone_transparent_signing_keys, ReviewedSweepIntent, ReviewedSweepStore, ScanSession,
        SweepBalanceSnapshot, MAX_REVIEWED_SWEEPS,
    };
    use crate::{
        broadcast::{
            observe_transaction, BroadcastStore, DurableBroadcastLog, EndpointTxEvidence,
            PreparedTransaction, SubmissionDisposition, TxObservation, TxObservationState,
        },
        derivation::{
            legacy_transparent_account_key, mnemonic_seed, transparent_address_from_seed,
        },
        derive_accounts,
        error::ZeckError,
        key_source::SeedKeySource,
        models::{
            AccountBalancePreview, AddressScope, ProposedTxKind, RuntimeScanConfig, ScanHandle,
            ScanPhase, ScanProgress, ScanSummary, SweepProposalId, SweepRequest, TxLifecycleState,
            ZeckNetwork,
        },
        scan::{ScanTaskState, TrackedAccount, TrackedTransparentKey},
    };
    use std::{path::PathBuf, sync::Arc, time::Instant};
    use tokio::sync::Mutex;

    struct FixedConfirmationObserver(TxObservation);

    #[async_trait::async_trait]
    impl crate::broadcast::TxObserver for FixedConfirmationObserver {
        async fn observe(
            &mut self,
            _network: ZeckNetwork,
            _txid: zcash_primitives::transaction::TxId,
            _expiry_height: Option<u32>,
        ) -> crate::error::ZeckResult<TxObservation> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn confirmation_one_source_is_mined_single_source_in_durable_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = zcash_primitives::transaction::TxId::from_bytes([42; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![42],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(
            txid,
            crate::models::TxLifecycleState::SubmissionUnknown,
            None,
            None,
        )
        .unwrap();
        log.transition(
            txid,
            crate::models::TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        let observation = observe_transaction(
            vec![EndpointTxEvidence {
                operator_id: "one".to_owned(),
                endpoint: "https://one.example".to_owned(),
                tip_height: Some(120),
                reported_height: Some(100),
                block_hash: Some(vec![1; 32]),
                tx_in_block: true,
            }],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::MinedSingleSource);
        let state =
            crate::reconciliation::record_observation(&mut log, txid, &observation).unwrap();
        assert_eq!(state, crate::models::TxLifecycleState::MinedSingleSource);
        drop(log);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(
            reopened.latest(txid).unwrap().observation,
            Some(observation)
        );
        assert_eq!(
            reopened.latest(txid).unwrap().state,
            crate::models::TxLifecycleState::MinedSingleSource
        );
        // Resolved for a new review, but never counted as corroborated.
        assert!(!reopened.has_unresolved_history());
        assert!(reopened.mined_records().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_confirmation_poll_returns_persisted_unknown_state() {
        for observation in [
            observe_transaction(vec![], Some(130)),
            observe_transaction(
                ["one", "two"]
                    .into_iter()
                    .map(|operator| EndpointTxEvidence {
                        operator_id: operator.to_owned(),
                        endpoint: format!("https://{operator}.example"),
                        tip_height: Some(120),
                        reported_height: None,
                        block_hash: None,
                        tx_in_block: false,
                    })
                    .collect(),
                Some(130),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("broadcasts-v1.jsonl");
            let txid = zcash_primitives::transaction::TxId::from_bytes([53; 32]);
            let mut log = DurableBroadcastLog::open(&path).unwrap();
            log.persist_prepared(&PreparedTransaction {
                txid,
                raw_tx: vec![53],
                fee_zatoshis: 10_000,
                expiry_height: Some(130),
            })
            .unwrap();
            log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
            let mut observer = FixedConfirmationObserver(observation);
            let mut never_mined =
                |_: zcash_primitives::transaction::TxId, _: u32| -> crate::ZeckResult<()> {
                    panic!("an unresolved poll must not mark anything mined")
                };
            let super::ConfirmationResult {
                state: reported,
                detail,
                confirmed_height: height,
                ..
            } = super::wait_for_confirmation(
                &mut never_mined,
                &mut log,
                &mut observer,
                ZeckNetwork::Testnet,
                txid,
                Some(130),
                "test",
            )
            .await
            .unwrap();
            assert_eq!(
                log.latest(txid).unwrap().state,
                TxLifecycleState::SubmissionUnknown
            );
            assert_eq!(reported, TxLifecycleState::SubmissionUnknown);
            assert!(detail.contains("unknown"));
            assert_eq!(height, None);
        }
    }

    #[test]
    fn confirmation_absence_only_expires_past_the_margin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = zcash_primitives::transaction::TxId::from_bytes([43; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![43],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(
            txid,
            crate::models::TxLifecycleState::SubmissionUnknown,
            None,
            None,
        )
        .unwrap();
        log.transition(
            txid,
            crate::models::TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        let evidence = |operator: &str, tip| EndpointTxEvidence {
            operator_id: operator.to_owned(),
            endpoint: format!("https://{operator}.example"),
            tip_height: Some(tip),
            reported_height: None,
            block_hash: None,
            tx_in_block: false,
        };
        let margin = crate::broadcast::EXPIRY_MARGIN_BLOCKS;
        let pending = observe_transaction(vec![evidence("one", 130 + margin)], Some(130));
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &pending).unwrap(),
            crate::models::TxLifecycleState::Pending
        );
        // One configured source past expiry + margin is enough.
        let expired = observe_transaction(vec![evidence("one", 131 + margin)], Some(130));
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &expired).unwrap(),
            crate::models::TxLifecycleState::Expired
        );
    }

    #[test]
    fn formerly_mined_transaction_seen_in_mempool_returns_to_pending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = zcash_primitives::transaction::TxId::from_bytes([45; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![45],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(
            txid,
            crate::models::TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        let mined = observe_transaction(
            ["one", "two"]
                .into_iter()
                .map(|operator| EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(120),
                    reported_height: Some(120),
                    block_hash: Some(vec![7; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(130),
        );
        assert_eq!(mined.state, TxObservationState::Mined);
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &mined).unwrap(),
            crate::models::TxLifecycleState::Mined
        );
        let mempool = observe_transaction(
            ["one", "two"]
                .into_iter()
                .map(|operator| EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(121),
                    reported_height: Some(0),
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
            Some(130),
        );
        assert_eq!(mempool.state, TxObservationState::PresentUnmined);
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &mempool).unwrap(),
            crate::models::TxLifecycleState::Pending
        );
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &mined).unwrap(),
            crate::models::TxLifecycleState::Mined
        );
        // A timeout is not reorg evidence: the record stays Mined.
        let unavailable = observe_transaction(vec![], Some(130));
        assert_eq!(unavailable.state, TxObservationState::Unavailable);
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &unavailable).unwrap(),
            crate::models::TxLifecycleState::Mined
        );
        drop(log);
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(reopened.blocking_submission(), None);
        assert_eq!(reopened.latest(txid).unwrap().observation, Some(mined));
    }

    #[test]
    fn unknown_submission_stays_unknown_after_unexpired_absence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let txid = zcash_primitives::transaction::TxId::from_bytes([44; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![44],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(
            txid,
            crate::models::TxLifecycleState::SubmissionUnknown,
            None,
            None,
        )
        .unwrap();
        let observation = observe_transaction(
            vec![
                EndpointTxEvidence {
                    operator_id: "one".into(),
                    endpoint: "https://one.example".into(),
                    tip_height: Some(129),
                    reported_height: None,
                    block_hash: None,
                    tx_in_block: false,
                },
                EndpointTxEvidence {
                    operator_id: "two".into(),
                    endpoint: "https://two.example".into(),
                    tip_height: Some(129),
                    reported_height: None,
                    block_hash: None,
                    tx_in_block: false,
                },
            ],
            Some(130),
        );
        assert_eq!(observation.state, TxObservationState::Absent);
        assert_eq!(
            crate::reconciliation::record_observation(&mut log, txid, &observation).unwrap(),
            crate::models::TxLifecycleState::SubmissionUnknown
        );
        drop(log);
        assert_eq!(
            DurableBroadcastLog::open(&path)
                .unwrap()
                .blocking_submission(),
            Some(txid)
        );
    }

    fn reviewed_session(handle: ScanHandle, phrase: &str) -> ScanSession {
        let state = Arc::new(Mutex::new(ScanTaskState::new(handle)));
        let source = Arc::new(SeedKeySource::new(SecretString::new(phrase.to_owned())));
        let source_fingerprint =
            crate::key_source::KeySource::fingerprint(source.as_ref()).unwrap();
        ScanSession {
            source_fingerprint,
            state,
            runtime: RuntimeScanConfig {
                key_source: source,
                birthday: 1,
                num_accounts: Some(1),
                gap_limit: 1,
                transparent_scan: None,
                lightwalletd_url: "https://example.invalid".to_owned(),
                confirmation_sources: Vec::new(),
                data_dir: PathBuf::from("/tmp/argos-reviewed-intent-test"),
                network: ZeckNetwork::Mainnet,
                label: String::new(),
            },
            started_at: Instant::now(),
            task: Mutex::new(None),
            workspace_root: PathBuf::from("/tmp/argos-reviewed-intent-test/workspace"),
            reviewed_sweeps: Mutex::new(ReviewedSweepStore::default()),
        }
    }

    fn reviewed_progress(handle: ScanHandle) -> ScanProgress {
        let mut progress = progress_with_account(AccountBalancePreview {
            account_index: 2,
            sapling_address: "zs-test".to_owned(),
            unified_address: "u-test".to_owned(),
            transparent_receive_address: "t-recv".to_owned(),
            transparent_change_address: "t-change".to_owned(),
            transparent_utxo_count: 3,
            sapling_zatoshis: 40_000,
            orchard_zatoshis: 30_000,
            transparent_zatoshis: 20_000,
            total_zatoshis: 90_000,
            has_activity: true,
            status: "ok".to_owned(),
        });
        progress.handle = handle;
        progress.synced_to_height = Some(100);
        progress.summary = Some(ScanSummary {
            total_zatoshis: 90_000,
            authoritative_balances: true,
            note: String::new(),
            workspace_dir: String::new(),
        });
        progress
    }

    fn reviewed_proposal() -> crate::models::SweepProposal {
        crate::models::SweepProposal {
            transactions: Vec::new(),
            donation_note: None,
            skipped_accounts: Vec::new(),
            total_send_zatoshis: 90_000,
            total_fee_zatoshis: 10_000,
            net_received_zatoshis: 80_000,
            total_donation_zatoshis: 0,
            dry_run_default: false,
            warning: None,
            follow_up_review_required: false,
            confirmation_notice: None,
        }
    }

    fn reviewed_request() -> SweepRequest {
        SweepRequest {
            destination: "u-reviewed".to_owned(),
            memo: Some("reviewed memo".to_owned()),
            max_fee_zatoshis: Some(20_000),
            donation_rate: Some(0.10),
            donor_email: Some("reviewed@example.com".to_owned()),
        }
    }

    #[test]
    fn reviewed_intent_preserves_the_exact_request() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let id = SweepProposalId("reviewed".to_owned());
        let mut store = ReviewedSweepStore::default();
        store.insert(
            id.clone(),
            ReviewedSweepIntent::capture_reviewed(
                reviewed_request(),
                &reviewed_proposal(),
                &session,
                &progress,
            ),
        );
        let mut changed_live_request = reviewed_request();
        changed_live_request.destination = "u-other".to_owned();
        changed_live_request.memo = None;
        changed_live_request.max_fee_zatoshis = Some(1);
        changed_live_request.donation_rate = Some(0.99);
        changed_live_request.donor_email = None;
        let stored = store.take(&id).unwrap();
        assert_eq!(stored.request.destination, "u-reviewed");
        assert_eq!(stored.request.memo.as_deref(), Some("reviewed memo"));
        assert_eq!(stored.request.max_fee_zatoshis, Some(20_000));
        assert_eq!(stored.request.donation_rate, Some(0.10));
        assert_eq!(
            stored.request.donor_email.as_deref(),
            Some("reviewed@example.com")
        );
        assert_ne!(stored.request.destination, changed_live_request.destination);
        assert_ne!(
            stored.request.donation_rate,
            changed_live_request.donation_rate
        );
    }

    #[test]
    fn caller_supplied_reviewed_fee_never_enters_one_shot_intent() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        // A frontend that still sends the old field cannot seed the fee the
        // service compares execution against: the request has no such field.
        let mut json = serde_json::to_value(reviewed_request()).unwrap();
        json["reviewed_fee_zatoshis"] = serde_json::json!(1);
        let request: SweepRequest = serde_json::from_value(json).unwrap();
        assert!(serde_json::to_value(&request)
            .unwrap()
            .get("reviewed_fee_zatoshis")
            .is_none());
        let intent = ReviewedSweepIntent::capture(request, &session, &progress);
        assert_eq!(intent.reviewed_fee_zatoshis, None);
    }

    #[test]
    fn blank_max_fee_defaults_to_exact_reviewed_total() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut request = reviewed_request();
        request.max_fee_zatoshis = None;
        let mut intent = ReviewedSweepIntent::capture(request, &session, &progress);
        let quote = super::SweepProposal {
            transactions: vec![],
            donation_note: None,
            skipped_accounts: vec![],
            total_send_zatoshis: 0,
            total_fee_zatoshis: 25_000,
            net_received_zatoshis: 0,
            total_donation_zatoshis: 0,
            dry_run_default: true,
            warning: None,
            follow_up_review_required: false,
            confirmation_notice: None,
        };
        intent.bind_quote(&quote);
        assert_eq!(intent.reviewed_fee_zatoshis, Some(25_000));
        assert_eq!(intent.request.max_fee_zatoshis, Some(25_000));
    }

    #[test]
    fn changed_execution_fee_requires_requote_before_submission() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut intent = ReviewedSweepIntent::capture(reviewed_request(), &session, &progress);
        intent.reviewed_fee_zatoshis = Some(25_000);
        let id = SweepProposalId("fee-review".to_owned());
        let mut store = ReviewedSweepStore::default();
        store.insert(id.clone(), intent);
        let consumed = store.take(&id).unwrap();
        assert!(matches!(
            consumed.require_current_fee(20_000),
            Err(ZeckError::FeeQuoteChanged {
                reviewed: 25_000,
                current: 20_000
            })
        ));
        assert!(matches!(
            store.take(&id),
            Err(ZeckError::UnknownSweepProposal)
        ));
        assert!(matches!(
            super::require_fee_matches(25_000, 20_000),
            Err(ZeckError::FeeQuoteChanged { .. })
        ));
    }

    fn reviewed_tx(account: u32, kind: ProposedTxKind, fee: u64) -> super::ProposedTx {
        super::ProposedTx {
            kind,
            leg_kind: crate::models::ProposedLegKind::Wallet,
            source_account: account,
            destination: format!("destination-{account}"),
            gross_zatoshis: 100_000,
            fee_zatoshis: fee,
            net_zatoshis: 100_000 - fee,
            donation_zatoshis: 0,
            note: String::new(),
            memo: None,
        }
    }

    #[test]
    fn canonical_pool_identity_is_an_explicit_tag() {
        use zcash_protocol::ShieldedPool;
        assert_eq!(
            [
                ShieldedPool::Sapling,
                ShieldedPool::Orchard,
                ShieldedPool::Ironwood
            ]
            .map(super::shielded_pool_tag),
            [0, 1, 2]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn broadcast_pause_applies_only_inside_its_scope() {
        let start = tokio::time::Instant::now();
        super::pause_between_broadcasts().await;
        assert_eq!(
            start.elapsed(),
            std::time::Duration::ZERO,
            "production has no pause"
        );
        super::PAUSE_BETWEEN_BROADCASTS
            .scope(
                std::time::Duration::from_secs(5),
                super::pause_between_broadcasts(),
            )
            .await;
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(5));
    }

    #[test]
    fn direct_leg_is_identified_by_its_kind_not_its_note_text() {
        use crate::models::ProposedLegKind;

        // A wallet leg whose display text happens to read like a direct
        // sweep must not be ordered or matched as one.
        let mut wallet = reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000);
        wallet.note = "Direct sweep of 3 standalone transparent UTXOs.".to_owned();
        let mut direct = reviewed_tx(0, ProposedTxKind::SweepShielded, 15_000);
        direct.leg_kind = ProposedLegKind::DirectTransparent;
        let mut imported = reviewed_tx(4, ProposedTxKind::SweepShielded, 20_000);
        imported.note = "Direct sweep of nothing.".to_owned();

        let mut transactions = vec![wallet, direct, imported];
        super::order_quoted_transactions(&mut transactions, &[4].into_iter().collect());
        assert_eq!(
            transactions
                .iter()
                .map(|tx| (tx.source_account, tx.leg_kind, tx.fee_zatoshis))
                .collect::<Vec<_>>(),
            vec![
                (4, ProposedLegKind::Wallet, 20_000),
                (0, ProposedLegKind::DirectTransparent, 15_000),
                (0, ProposedLegKind::Wallet, 10_000),
            ]
        );
        assert_eq!(
            super::direct_leg_quote(&transactions, 0)
                .unwrap()
                .fee_zatoshis,
            15_000
        );
        assert!(super::direct_leg_quote(&transactions, 4).is_err());
    }

    fn reviewed_quote(transactions: Vec<super::ProposedTx>) -> super::SweepProposal {
        let total_fee_zatoshis = transactions.iter().map(|tx| tx.fee_zatoshis).sum();
        super::SweepProposal {
            transactions,
            donation_note: None,
            skipped_accounts: vec![],
            total_send_zatoshis: 200_000,
            total_fee_zatoshis,
            net_received_zatoshis: 200_000 - total_fee_zatoshis,
            total_donation_zatoshis: 0,
            dry_run_default: true,
            warning: None,
            follow_up_review_required: false,
            confirmation_notice: None,
        }
    }

    #[test]
    fn equal_total_redistributed_leg_fees_reject_before_route_invocation() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut intent = ReviewedSweepIntent::capture(reviewed_request(), &session, &progress);
        let reviewed = reviewed_quote(vec![
            reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000),
            reviewed_tx(1, ProposedTxKind::SweepShielded, 20_000),
        ]);
        let current = reviewed_quote(vec![
            reviewed_tx(0, ProposedTxKind::SweepShielded, 20_000),
            reviewed_tx(1, ProposedTxKind::SweepShielded, 10_000),
        ]);
        assert_eq!(reviewed.total_fee_zatoshis, current.total_fee_zatoshis);
        intent.bind_quote(&reviewed);
        let mut route_called = false;
        let result = intent.require_current_quote(&current).map(|_| {
            route_called = true;
        });
        assert!(matches!(result, Err(ZeckError::StaleSweepProposal(_))));
        assert!(!route_called);
        let reordered = reviewed_quote(vec![
            reviewed_tx(1, ProposedTxKind::SweepShielded, 20_000),
            reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000),
        ]);
        assert!(matches!(
            intent.require_current_quote(&reordered),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        let mut changed_destination = reviewed_quote(vec![
            reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000),
            reviewed_tx(1, ProposedTxKind::SweepShielded, 20_000),
        ]);
        changed_destination.transactions[0].destination = "different".to_owned();
        assert!(matches!(
            intent.require_current_quote(&changed_destination),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn mixed_later_leg_amount_change_rejects_before_any_route() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut intent = ReviewedSweepIntent::capture(reviewed_request(), &session, &progress);
        let reviewed = reviewed_quote(vec![
            reviewed_tx(0, ProposedTxKind::ShieldTransparent, 10_000),
            reviewed_tx(1, ProposedTxKind::SweepShielded, 10_000),
        ]);
        let mut current = reviewed.clone();
        current.transactions[1].gross_zatoshis += 5_000;
        current.transactions[1].net_zatoshis += 5_000;
        assert_eq!(reviewed.total_fee_zatoshis, current.total_fee_zatoshis);
        intent.bind_quote(&reviewed);
        let mut first_route_called = false;
        let mut second_route_called = false;
        let result = intent.require_current_quote(&current).map(|_| {
            first_route_called = true;
            second_route_called = true;
        });
        assert!(matches!(result, Err(ZeckError::StaleSweepProposal(_))));
        assert!(!first_route_called);
        assert!(!second_route_called);
    }

    #[test]
    fn changed_skipped_balance_invalidates_an_unchanged_transaction_quote() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut intent = ReviewedSweepIntent::capture(reviewed_request(), &session, &progress);
        let reviewed = reviewed_quote(vec![reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000)]);
        intent.bind_quote(&reviewed);
        let mut current = reviewed;
        current.skipped_accounts.push(super::SkippedSweepAccount {
            account_index: 1,
            gross_zatoshis: 42_000,
            reason: "became unspendable".to_owned(),
        });
        assert!(matches!(
            intent.require_current_quote(&current),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn public_sweep_kind_does_not_merge_distinct_signing_routes() {
        let direct = super::CanonicalLegInputs {
            kind: super::CanonicalLegKind::DirectTransparent,
            account_index: 0,
            backend_plan: vec![1, 2, 3],
        };
        let imported = super::CanonicalLegInputs {
            kind: super::CanonicalLegKind::ImportedSapling,
            account_index: 0,
            backend_plan: vec![1, 2, 3],
        };
        assert_ne!(direct, imported);
    }

    #[test]
    fn mixed_same_display_account_keeps_direct_and_hd_fees_distinct_after_direct_submission() {
        let quote = reviewed_quote(vec![
            reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000),
            reviewed_tx(0, ProposedTxKind::SweepShielded, 15_000),
        ]);
        let fees = super::ExactLegFees::from_pairs([
            (super::ExactFeeKey::DirectTransparent, 10_000),
            (super::ExactFeeKey::HdSend(0), 15_000),
        ])
        .unwrap();

        // The public rows share an account and kind, and the direct leg runs
        // first. The HD builder must still get its own reviewed fee.
        assert_eq!(
            quote.transactions[0].source_account,
            quote.transactions[1].source_account
        );
        assert_eq!(quote.transactions[0].kind, quote.transactions[1].kind);
        let direct_fee = fees.require(super::ExactFeeKey::DirectTransparent).unwrap();
        let hd_fee = fees.require(super::ExactFeeKey::HdSend(0)).unwrap();
        assert_eq!((direct_fee, hd_fee), (10_000, 15_000));
        assert!(super::require_fee_matches(hd_fee, 15_000).is_ok());
        let cumulative = super::checked_fee_total(direct_fee, hd_fee).unwrap();
        assert!(super::enforce_max_fee(cumulative, Some(25_000)).is_ok());
    }

    #[test]
    fn same_fee_changed_direct_outpoint_requires_new_review() {
        use crate::transparent_recovery::{
            tests_support::{addr, utxo},
            TransparentSweepPlan,
        };
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut intent = ReviewedSweepIntent::capture(reviewed_request(), &session, &progress);
        let quote = reviewed_quote(vec![reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000)]);
        let cost = TransparentSweepPlan {
            input_count: 1,
            total_input_zatoshis: 100_000,
            fee_zatoshis: 10_000,
            output_zatoshis: 90_000,
        };
        let reviewed = super::ExactSweepPlan {
            quote: quote.clone(),
            legs: vec![super::ExactSweepLeg::DirectTransparent {
                account_index: 0,
                utxos: vec![utxo(addr(3), 100_000, 1)],
                plan: cost.clone(),
                target_height: 2_000_000,
                version: zcash_primitives::transaction::TxVersion::V5.header(),
            }],
            direct_account_index: Some(0),
            network: ZeckNetwork::Mainnet,
        };
        intent.bind_plan(&reviewed).unwrap();
        let current = super::ExactSweepPlan {
            quote,
            legs: vec![super::ExactSweepLeg::DirectTransparent {
                account_index: 0,
                utxos: vec![utxo(addr(3), 100_000, 2)],
                plan: cost,
                target_height: 2_000_001,
                version: zcash_primitives::transaction::TxVersion::V5.header(),
            }],
            direct_account_index: Some(0),
            network: ZeckNetwork::Mainnet,
        };
        assert!(matches!(
            intent.require_current_plan(&current),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn same_fee_changed_direct_output_requires_new_review() {
        use crate::transparent_recovery::{
            tests_support::{addr, utxo},
            TransparentSweepPlan,
        };
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut intent = ReviewedSweepIntent::capture(reviewed_request(), &session, &progress);
        let quote = reviewed_quote(vec![reviewed_tx(0, ProposedTxKind::SweepShielded, 10_000)]);
        let selected = vec![utxo(addr(3), 100_000, 1)];
        let reviewed = super::ExactSweepPlan {
            quote: quote.clone(),
            legs: vec![super::ExactSweepLeg::DirectTransparent {
                account_index: 0,
                utxos: selected.clone(),
                plan: TransparentSweepPlan {
                    input_count: 1,
                    total_input_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    output_zatoshis: 90_000,
                },
                target_height: 2_000_000,
                version: zcash_primitives::transaction::TxVersion::V5.header(),
            }],
            direct_account_index: Some(0),
            network: ZeckNetwork::Mainnet,
        };
        intent.bind_plan(&reviewed).unwrap();
        let current = super::ExactSweepPlan {
            quote,
            legs: vec![super::ExactSweepLeg::DirectTransparent {
                account_index: 0,
                utxos: selected,
                plan: TransparentSweepPlan {
                    input_count: 1,
                    total_input_zatoshis: 100_000,
                    fee_zatoshis: 10_000,
                    output_zatoshis: 80_000,
                },
                target_height: 2_000_001,
                version: zcash_primitives::transaction::TxVersion::V5.header(),
            }],
            direct_account_index: Some(0),
            network: ZeckNetwork::Mainnet,
        };
        assert!(matches!(
            intent.require_current_plan(&current),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn backend_identity_ignores_tip_height_but_binds_same_fee_note_and_output() {
        use zcash_client_backend::proto::proposal::{
            proposed_input, Proposal, ProposalStep, ProposedInput, ReceivedOutput, ValuePool,
        };
        let mut reviewed = Proposal {
            min_target_height: 100,
            steps: vec![ProposalStep {
                anchor_height: 99,
                transaction_request: "zcash:recipient?amount=0.0009".to_owned(),
                inputs: vec![ProposedInput {
                    value: Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                        txid: vec![1; 32],
                        value_pool: ValuePool::Sapling.into(),
                        index: 0,
                        value: 100_000,
                    })),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let identity = super::canonical_proposal_proto(reviewed.clone());
        reviewed.min_target_height = 101;
        reviewed.steps[0].anchor_height = 100;
        assert_eq!(identity, super::canonical_proposal_proto(reviewed.clone()));
        reviewed.steps[0].inputs[0].value =
            Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                txid: vec![2; 32],
                value_pool: ValuePool::Sapling.into(),
                index: 0,
                value: 100_000,
            }));
        assert_ne!(identity, super::canonical_proposal_proto(reviewed.clone()));
        reviewed.steps[0].inputs[0].value =
            Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                txid: vec![1; 32],
                value_pool: ValuePool::Sapling.into(),
                index: 0,
                value: 100_000,
            }));
        reviewed.steps[0].transaction_request = "zcash:other-recipient?amount=0.0009".to_owned();
        assert_ne!(identity, super::canonical_proposal_proto(reviewed));
    }

    #[test]
    fn shielded_local_id_stays_paired_with_its_chain_output() {
        let a = super::canonical_shielded_note_identity(&[1; 32], 0, 0, 50_000, &"local-a");
        let b = super::canonical_shielded_note_identity(&[2; 32], 0, 0, 50_000, &"local-b");
        let swapped_a = super::canonical_shielded_note_identity(&[1; 32], 0, 0, 50_000, &"local-b");
        let swapped_b = super::canonical_shielded_note_identity(&[2; 32], 0, 0, 50_000, &"local-a");
        let mut reviewed = vec![a, b];
        let mut changed = vec![swapped_a, swapped_b];
        reviewed.sort();
        changed.sort();
        assert_ne!(reviewed, changed);
    }

    #[test]
    fn ironwood_only_preview_enters_real_hd_proposal_path() {
        let mut row = reviewed_progress(ScanHandle::new()).accounts.remove(0);
        row.sapling_zatoshis = 0;
        row.orchard_zatoshis = 0;
        row.transparent_zatoshis = 0;
        row.total_zatoshis = 100_000;
        assert!(super::hd_has_shielded_balance(&row).unwrap());
        row.total_zatoshis = 0;
        assert!(!super::hd_has_shielded_balance(&row).unwrap());
    }

    #[test]
    fn recorded_shielding_submission_retains_follow_up_after_late_error() {
        let quote = reviewed_quote(vec![reviewed_tx(
            2,
            ProposedTxKind::ShieldTransparent,
            10_000,
        )]);
        let mut result = sample_broadcast_result(2);
        result.status = crate::models::TxLifecycleState::SubmissionUnknown;
        result.confirmed_height = None;
        let mut outcome = super::assemble_sweep_outcome(
            vec![result],
            vec![],
            0,
            Err(ZeckError::Wallet("confirmation status failed".to_owned())),
        )
        .expect("recorded submission must survive the later error");
        super::apply_recorded_shield_follow_up(&mut outcome, &quote.transactions);
        assert!(outcome.follow_up_review_required);
        assert_eq!(outcome.transactions.len(), 1);
        assert!(outcome.error.is_some());
        let mut rejected = sample_broadcast_result(2);
        rejected.status = crate::models::TxLifecycleState::Rejected;
        let mut rejected_outcome = super::assemble_sweep_outcome(
            vec![rejected],
            vec![],
            0,
            Err(ZeckError::Broadcast("definite rejection".to_owned())),
        )
        .unwrap();
        super::apply_recorded_shield_follow_up(&mut rejected_outcome, &quote.transactions);
        assert!(!rejected_outcome.follow_up_review_required);
        let mut other_account = super::assemble_sweep_outcome(
            vec![sample_broadcast_result(9)],
            vec![],
            0,
            Err(ZeckError::Wallet("unrelated error".to_owned())),
        )
        .unwrap();
        super::apply_recorded_shield_follow_up(&mut other_account, &quote.transactions);
        assert!(!other_account.follow_up_review_required);
    }

    #[test]
    fn built_batch_fee_must_match_reviewed_proposal_before_submission() {
        assert!(matches!(
            super::require_persisted_batch_fee(25_000, [10_000, 10_000]),
            Err(ZeckError::FeeQuoteChanged {
                reviewed: 25_000,
                current: 20_000
            })
        ));
        assert!(super::require_persisted_batch_fee(25_000, [10_000, 15_000]).is_ok());
    }

    #[test]
    fn imported_multi_action_quote_matches_zip317_transparent_plan() {
        use crate::transparent_recovery::{
            plan_sweep,
            tests_support::{addr, utxo},
        };
        use zcash_protocol::consensus::BlockHeight;
        let inputs = (1..=5)
            .map(|index| utxo(addr(7), 100_000, index))
            .collect::<Vec<_>>();
        let plan = plan_sweep(
            &zcash_protocol::consensus::MAIN_NETWORK,
            BlockHeight::from_u32(3_000_000),
            &inputs,
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.fee_zatoshis, 35_000);

        let handle = ScanHandle::new();
        let session = reviewed_session(handle, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let workspace =
            crate::workspace::RecoveryWorkspace::from_runtime(&session.runtime).unwrap();
        let progress = progress_with_account(AccountBalancePreview {
            account_index: 0,
            sapling_address: String::new(),
            unified_address: String::new(),
            transparent_receive_address: String::new(),
            transparent_change_address: String::new(),
            transparent_utxo_count: 5,
            sapling_zatoshis: 0,
            orchard_zatoshis: 0,
            transparent_zatoshis: 500_000,
            total_zatoshis: 500_000,
            has_activity: true,
            status: String::new(),
        });
        let quote = super::build_exact_sweep_proposal(
            &progress,
            &[],
            &std::collections::HashMap::from([(
                0,
                crate::scan::StandaloneTransparentBalance {
                    zatoshis: 500_000,
                    utxo_count: 5,
                },
            )]),
            &SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            &workspace,
        )
        .unwrap();
        assert_eq!(quote.quote.total_fee_zatoshis, plan.fee_zatoshis);
        assert_eq!(quote.quote.transactions.len(), 1);
    }

    #[test]
    fn reviewed_intent_is_bound_to_its_scan_session() {
        let handle_a = ScanHandle::new();
        let session_a = reviewed_session(handle_a.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress_a = reviewed_progress(handle_a);
        let handle_b = ScanHandle::new();
        let session_b = reviewed_session(handle_b.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress_b = reviewed_progress(handle_b);
        let id = SweepProposalId("a".to_owned());
        let mut store_a = ReviewedSweepStore::default();
        let mut store_b = ReviewedSweepStore::default();
        store_a.insert(
            id.clone(),
            ReviewedSweepIntent::capture_reviewed(
                reviewed_request(),
                &reviewed_proposal(),
                &session_a,
                &progress_a,
            ),
        );
        assert!(matches!(
            store_b.take(&id),
            Err(ZeckError::UnknownSweepProposal)
        ));
        let intent = store_a.take(&id).unwrap();
        assert!(matches!(
            intent.validate_state(&session_b, &progress_b),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn reviewed_intent_is_one_shot() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let id = SweepProposalId("one".to_owned());
        let mut store = ReviewedSweepStore::default();
        store.insert(
            id.clone(),
            ReviewedSweepIntent::capture_reviewed(
                reviewed_request(),
                &reviewed_proposal(),
                &session,
                &progress,
            ),
        );
        assert!(store.take(&id).is_ok());
        assert!(matches!(
            store.take(&id),
            Err(ZeckError::UnknownSweepProposal)
        ));
    }

    #[test]
    fn same_total_changed_standalone_partition_invalidates_review() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let mut state = ScanTaskState::new(handle.clone());
        state.progress = reviewed_progress(handle);
        state.standalone_transparent_indices = vec![0];
        state.standalone_transparent_balances.insert(
            2,
            crate::scan::StandaloneTransparentBalance {
                zatoshis: 10_000,
                utxo_count: 1,
            },
        );
        let mut derived = derive_accounts(
            &SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned()),
            ZeckNetwork::Mainnet,
            1,
        )
        .unwrap()
        .remove(0);
        derived.index = 2;
        state.tracked_accounts.push(TrackedAccount {
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            derived,
            transparent_receivers: vec![
                zcash_transparent::address::TransparentAddress::PublicKeyHash([1; 20]),
            ],
            spend_authority: crate::scan::TrackedSpendAuthority::Hd { zip32_index: 0 },
            standalone_transparent_receivers: vec![
                zcash_transparent::address::TransparentAddress::PublicKeyHash([2; 20]),
            ],
            transparent_key_coordinates: Vec::new(),
        });
        let intent = ReviewedSweepIntent::capture_from_state(
            reviewed_request(),
            &reviewed_proposal(),
            &session,
            &state,
        );
        assert!(intent.validate_scan_state(&session, &state).is_ok());

        state
            .standalone_transparent_balances
            .get_mut(&2)
            .unwrap()
            .zatoshis = 20_000;
        assert!(matches!(
            intent.validate_scan_state(&session, &state),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        state
            .standalone_transparent_balances
            .get_mut(&2)
            .unwrap()
            .zatoshis = 10_000;
        state.standalone_transparent_indices = vec![1];
        assert!(matches!(
            intent.validate_scan_state(&session, &state),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        state.standalone_transparent_indices = vec![0];
        state.standalone_sapling_indices = vec![3];
        assert!(matches!(
            intent.validate_scan_state(&session, &state),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        state.standalone_sapling_indices.clear();
        state.tracked_accounts[0].standalone_transparent_receivers[0] =
            zcash_transparent::address::TransparentAddress::PublicKeyHash([3; 20]);
        assert!(matches!(
            intent.validate_scan_state(&session, &state),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        assert!(matches!(
            intent.require_current_authority(&state),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn changed_balance_snapshot_requires_a_new_proposal() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let intent = ReviewedSweepIntent::capture_reviewed(
            reviewed_request(),
            &reviewed_proposal(),
            &session,
            &progress,
        );
        assert!(intent.validate_state(&session, &progress).is_ok());
        let mut volatile = progress.clone();
        volatile.elapsed_seconds = Some(999);
        volatile.message = Some("later".to_owned());
        assert!(intent.validate_state(&session, &volatile).is_ok());
        for changed in 0..8 {
            let mut p = progress.clone();
            match changed {
                0 => p.synced_to_height = Some(101),
                1 => p.accounts[0].account_index += 1,
                2 => p.accounts[0].sapling_zatoshis += 1,
                3 => p.accounts[0].orchard_zatoshis += 1,
                4 => p.accounts[0].transparent_zatoshis += 1,
                5 => p.accounts[0].transparent_utxo_count += 1,
                6 => p.accounts[0].total_zatoshis += 1,
                _ => p.summary.as_mut().unwrap().total_zatoshis += 1,
            }
            assert!(
                matches!(
                    intent.validate_state(&session, &p),
                    Err(ZeckError::StaleSweepProposal(_))
                ),
                "changed field {changed}"
            );
        }
        let mut other_network = reviewed_session(progress.handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        other_network.runtime.network = ZeckNetwork::Testnet;
        assert!(matches!(
            intent.validate_state(&other_network, &progress),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        other_network.runtime.network = ZeckNetwork::Mainnet;
        other_network.workspace_root = PathBuf::from("/tmp/other-workspace");
        assert!(matches!(
            intent.validate_state(&other_network, &progress),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        let other_source = reviewed_session(
            progress.handle.clone(),
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        );
        assert!(matches!(
            intent.validate_state(&other_source, &progress),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        assert_ne!(
            SweepBalanceSnapshot::capture(&session, &progress),
            SweepBalanceSnapshot::capture(&other_source, &progress)
        );
    }

    #[test]
    fn reviewed_intent_store_is_bounded() {
        let handle = ScanHandle::new();
        let session = reviewed_session(handle.clone(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let progress = reviewed_progress(handle);
        let mut store = ReviewedSweepStore::default();
        for n in 0..=MAX_REVIEWED_SWEEPS {
            store.insert(
                SweepProposalId(n.to_string()),
                ReviewedSweepIntent::capture_reviewed(
                    reviewed_request(),
                    &reviewed_proposal(),
                    &session,
                    &progress,
                ),
            );
        }
        assert!(matches!(
            store.take(&SweepProposalId("0".to_owned())),
            Err(ZeckError::UnknownSweepProposal)
        ));
        for n in 1..=MAX_REVIEWED_SWEEPS {
            assert!(
                store.take(&SweepProposalId(n.to_string())).is_ok(),
                "entry {n}"
            );
        }
    }

    #[test]
    fn transparent_range_signer_map_controls_every_coordinate() {
        let phrase = SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
        );
        let seed = mnemonic_seed(&phrase).unwrap();
        let account_key = legacy_transparent_account_key(&phrase, ZeckNetwork::Mainnet).unwrap();
        let derived = derive_accounts(&phrase, ZeckNetwork::Mainnet, 1)
            .unwrap()
            .remove(0);
        let mut coordinates = Vec::new();
        for index in [997, 998] {
            for scope in [AddressScope::External, AddressScope::Internal] {
                coordinates.push(TrackedTransparentKey {
                    address: transparent_address_from_seed(
                        ZeckNetwork::Mainnet,
                        seed.expose_secret(),
                        0,
                        scope,
                        index,
                    )
                    .unwrap(),
                    scope,
                    index,
                });
            }
        }
        let tracked = TrackedAccount {
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            derived,
            transparent_receivers: coordinates.iter().map(|key| key.address).collect(),
            spend_authority: crate::scan::TrackedSpendAuthority::Hd { zip32_index: 0 },
            standalone_transparent_receivers: Vec::new(),
            transparent_key_coordinates: coordinates.clone(),
        };
        let signer_map = standalone_transparent_signing_keys(&tracked, &account_key).unwrap();
        assert_eq!(signer_map.len(), coordinates.len());
        let secp = secp256k1::Secp256k1::signing_only();
        for coordinate in coordinates {
            let secrets = signer_map
                .get(&coordinate.address)
                .expect("coordinate signer");
            assert_eq!(secrets.len(), 1);
            let public = secp256k1::PublicKey::from_secret_key(&secp, &secrets[0]);
            assert_eq!(
                zcash_transparent::address::TransparentAddress::from_pubkey(&public),
                coordinate.address
            );
        }
    }

    #[test]
    fn equivalent_lightwalletd_urls_are_not_distinct_confirmation_sources() {
        assert!(!is_distinct_lightwalletd_endpoint(
            "https://zec.rocks",
            "https://zec.rocks:443/"
        ));
        assert!(is_distinct_lightwalletd_endpoint(
            "https://na.zec.rocks:443",
            "https://zec.rocks:443"
        ));
    }

    fn derived_destination() -> String {
        derive_accounts(
            &SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
            ZeckNetwork::Mainnet,
            1,
        )
        .expect("derived account")[0]
            .unified_address
            .clone()
    }

    fn derived_destination_testnet() -> String {
        derive_accounts(
            &SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    .to_owned(),
            ),
            ZeckNetwork::Testnet,
            1,
        )
        .expect("derived account")[0]
            .unified_address
            .clone()
    }

    fn progress_with_account(account: AccountBalancePreview) -> ScanProgress {
        ScanProgress {
            handle: ScanHandle::new(),
            phase: ScanPhase::Complete,
            blocks_scanned: 1,
            blocks_total: 1,
            synced_to_height: None,
            elapsed_seconds: None,
            estimated_remaining_seconds: None,
            accounts: vec![account],
            discoveries: vec![],
            summary: None,
            server: None,
            message: None,
            error: None,
            sleep_event: None,
            in_sandblasting_zone: false,
            gap_extension: None,
        }
    }

    const DONATION_TEST_UA: &str = "u1nvgt6yr35mhc9wdf4wckvl38476vqy96dx3cwkfdwy4jet9300l5v8l2yg27ql7w9qwm0lf8kncnj9nus4mgete06j3cu3mhrqvstg6swvdya6xgzwhh6a9xxdhxkavvvmztqeuaurjtqfk3dzetuzgnu0zjvmdpe8ehvj53sy6yhzxj";

    #[test]
    fn transparent_shielding_requires_post_mining_send_review() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 3,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 100_000,
                total_zatoshis: 100_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .unwrap();
        assert_eq!(
            proposal.transactions.len(),
            1,
            "future send-max needs a new review"
        );
        assert_eq!(
            proposal.transactions[0].kind,
            ProposedTxKind::ShieldTransparent
        );
        assert_eq!(
            proposal.total_fee_zatoshis,
            proposal.transactions[0].fee_zatoshis
        );
    }

    #[test]
    fn proposal_splits_donation_out_of_shielded_send_on_mainnet() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 3_000_000,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 3_000_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: Some("donor@example.com".to_owned()),
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap();

        let sweep = proposal
            .transactions
            .iter()
            .find(|t| t.kind == crate::models::ProposedTxKind::SweepShielded)
            .unwrap();
        assert!(sweep.donation_zatoshis > 0);
        assert_eq!(proposal.total_donation_zatoshis, sweep.donation_zatoshis);
        // estimate invariant unchanged
        assert_eq!(
            sweep.net_zatoshis + sweep.fee_zatoshis,
            sweep.gross_zatoshis
        );
        // donation is strictly less than the amount being sent
        assert!(sweep.donation_zatoshis < sweep.net_zatoshis);
    }

    fn seedless_test_account() -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: 0,
            sapling_address: "zs-test".to_owned(),
            unified_address: "u-test".to_owned(),
            transparent_receive_address: "t-recv".to_owned(),
            transparent_change_address: "t-change".to_owned(),
            transparent_utxo_count: 0,
            sapling_zatoshis: 3_000_000,
            orchard_zatoshis: 0,
            transparent_zatoshis: 0,
            total_zatoshis: 3_000_000,
            has_activity: true,
            status: "ok".to_owned(),
        }
    }

    /// The positive half of the memo rules. Every other memo test is a
    /// refusal, so nothing failed if the seed-phrase route stopped carrying
    /// the user's memo — or stopped writing the default when none is given,
    /// which is why `--memo` help now names it.
    #[test]
    fn a_seed_route_sweep_carries_the_memo_or_the_default() {
        let request = |memo: Option<&str>| SweepRequest {
            destination: derived_destination(),
            memo: memo.map(str::to_owned),
            max_fee_zatoshis: None,
            donation_rate: None,
            donor_email: None,
        };
        let given = build_sweep_proposal(
            &progress_with_account(seedless_test_account()),
            request(Some("exchange deposit 8821")),
            ZeckNetwork::Mainnet,
            "",
        )
        .unwrap();
        assert!(!given.transactions.is_empty());
        for tx in &given.transactions {
            assert_eq!(tx.memo.as_deref(), Some("exchange deposit 8821"), "{tx:?}");
        }

        for absent in [None, Some("   ")] {
            let default = build_sweep_proposal(
                &progress_with_account(seedless_test_account()),
                request(absent),
                ZeckNetwork::Mainnet,
                "",
            )
            .unwrap();
            for tx in &default.transactions {
                assert_eq!(
                    tx.memo.as_deref(),
                    Some(super::RECOVERY_MEMO_DEFAULT),
                    "{tx:?}"
                );
            }
        }
    }

    /// Transparent funds in a seedless wallet go to the destination in one
    /// transaction (`transparent_recovery`), never shielded to the
    /// recovered wallet first. The preview used the HD model — a shield to
    /// the account's own address, then a sweep — so it showed a hop that
    /// never happens and charged two fees, which could refuse a sweep whose
    /// real fee was under `--max-fee`.
    #[test]
    fn seedless_transparent_funds_are_previewed_as_one_direct_sweep() {
        let mut account = seedless_test_account();
        account.sapling_zatoshis = 0;
        account.transparent_zatoshis = 5_000_000;
        account.transparent_utxo_count = 3;
        account.total_zatoshis = 5_000_000;
        let real_fee = crate::transparent_recovery::transparent_sweep_fee(ZeckNetwork::Mainnet, 3)
            .expect("fee");

        let proposal = build_seedless_sweep_proposal(
            &progress_with_account(account),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                // Room for the one real transaction, not for a shield plus
                // a sweep on top of it.
                max_fee_zatoshis: Some(real_fee),
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
        )
        .expect("the real fee is within the cap");

        assert_eq!(
            proposal.transactions.len(),
            1,
            "{:?}",
            proposal.transactions
        );
        let tx = &proposal.transactions[0];
        assert!(
            !matches!(tx.kind, ProposedTxKind::ShieldTransparent),
            "{tx:?}"
        );
        assert_eq!(
            tx.destination,
            derived_destination(),
            "straight to the destination"
        );
        assert_eq!(tx.fee_zatoshis, real_fee);
        assert_eq!(tx.net_zatoshis, 5_000_000 - real_fee);
        assert_eq!(proposal.total_fee_zatoshis, real_fee);
    }

    #[test]
    fn a_seedless_preview_still_refuses_a_cap_below_the_real_fee() {
        let mut account = seedless_test_account();
        account.transparent_zatoshis = 5_000_000;
        account.transparent_utxo_count = 3;
        account.total_zatoshis = 8_000_000;
        let err = build_seedless_sweep_proposal(
            &progress_with_account(account),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: Some(1),
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
        )
        .expect_err("no sweep fits a 1-zat cap");
        assert!(matches!(err, ZeckError::MaxFeeExceeded(_)), "{err:?}");
    }

    /// A wallet with no seed phrase sweeps through the imported-key path,
    /// which sends neither a memo nor a donation. The preview is where a
    /// careful user checks before committing, so it must not show either.
    #[test]
    fn seedless_proposal_shows_no_memo_and_no_donation() {
        let proposal = build_seedless_sweep_proposal(
            &progress_with_account(seedless_test_account()),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
        )
        .unwrap();

        assert!(!proposal.transactions.is_empty());
        for tx in &proposal.transactions {
            assert_eq!(tx.memo, None, "{tx:?}");
            assert_eq!(tx.donation_zatoshis, 0, "{tx:?}");
        }
        assert_eq!(proposal.total_donation_zatoshis, 0);
    }

    /// A dropped memo can lose an exchange deposit, so a memo the seedless
    /// sweep cannot deliver is refused rather than discarded.
    #[test]
    fn seedless_proposal_refuses_a_memo() {
        let err = build_seedless_sweep_proposal(
            &progress_with_account(seedless_test_account()),
            SweepRequest {
                destination: derived_destination(),
                memo: Some("exchange deposit 12345".to_owned()),
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
        )
        .unwrap_err();

        assert!(matches!(err, ZeckError::InvalidMemo(_)), "{err:?}");
        assert!(err.to_string().contains("seed phrase"), "{err}");
    }

    /// The GUI selects a 10% donation by default, and a seedless sweep can
    /// send none. Without being told why, its preview said the donation
    /// "may be included or skipped depending on the fee" and its complete
    /// screen blamed the 0.001 ZEC minimum — both false for this route.
    #[test]
    fn seedless_proposal_says_why_no_donation_is_sent() {
        let proposal = build_seedless_sweep_proposal(
            &progress_with_account(seedless_test_account()),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        let note = proposal
            .donation_note
            .expect("a seedless proposal says why");
        assert!(note.contains("seed phrase"), "{note}");
        assert!(
            !note.contains("minimum"),
            "not a fee-threshold story: {note}"
        );
    }

    #[test]
    fn an_imported_sweep_outcome_says_why_no_donation_was_sent() {
        let outcome = crate::service::assemble_imported_sweep_outcome(
            crate::imported_sweep::ImportedSweepOutcome {
                transactions: vec![sample_imported_result(0, "txid", "Sapling")],
                sapling_transaction_count: 1,
                sapling_leg_completed: true,
                transparent_leg_completed: true,
                ..Default::default()
            },
            Ok(()),
        )
        .unwrap();
        assert_eq!(outcome.total_donation_zatoshis, 0);
        assert!(outcome.donation_note.is_some());
    }

    #[test]
    fn seedless_proposal_treats_a_blank_memo_as_none() {
        build_seedless_sweep_proposal(
            &progress_with_account(seedless_test_account()),
            SweepRequest {
                destination: derived_destination(),
                memo: Some("   ".to_owned()),
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
        )
        .unwrap();
    }

    #[test]
    fn proposal_skips_donation_on_testnet() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 3_000_000,
                orchard_zatoshis: 0,
                transparent_zatoshis: 0,
                total_zatoshis: 3_000_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination_testnet(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: None,
            },
            ZeckNetwork::Testnet,
            DONATION_TEST_UA,
        )
        .unwrap();
        assert_eq!(proposal.total_donation_zatoshis, 0);
    }

    #[test]
    fn proposal_separates_shielding_from_shielded_sweeping() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 1,
                sapling_zatoshis: 40_000,
                orchard_zatoshis: 0,
                transparent_zatoshis: 30_000,
                total_zatoshis: 70_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: Some("recovery".to_owned()),
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .expect("proposal should build");

        assert_eq!(proposal.transactions.len(), 1);
        assert_eq!(
            proposal.transactions[0].kind,
            crate::models::ProposedTxKind::ShieldTransparent
        );
        assert_eq!(proposal.transactions[0].gross_zatoshis, 30_000);
        assert!(proposal.follow_up_review_required);
    }

    #[test]
    fn proposal_rejects_max_fee_below_estimate() {
        let err = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 1,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 50_000,
                total_zatoshis: 50_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: Some(9_999),
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .expect_err("proposal should fail");

        assert!(matches!(err, ZeckError::MaxFeeExceeded(_)));
    }

    #[test]
    fn actual_fee_guard_rejects_before_transaction_creation() {
        use super::{checked_fee_total, enforce_max_fee};
        let total_fee = checked_fee_total(10_000, 10_000).expect("fee total should fit");
        let err = enforce_max_fee(total_fee, Some(15_000)).expect_err("fee cap should fail");

        assert!(matches!(err, ZeckError::MaxFeeExceeded(_)));
    }

    #[test]
    fn actual_fee_guard_detects_overflow() {
        use super::checked_fee_total;
        let err = checked_fee_total(u64::MAX, 1).expect_err("fee total should overflow");

        assert!(matches!(err, ZeckError::Internal(_)));
    }

    fn sample_broadcast_result(account: u32) -> crate::models::TxBroadcastResult {
        crate::models::TxBroadcastResult {
            source_account: account,
            txid: Some(format!("tx-{account}")),
            status: crate::models::TxLifecycleState::Mined,
            fee_zatoshis: 0,
            detail: "mined".to_owned(),
            confirmed_height: Some(1_000_000),
            safe_to_discard: false,
        }
    }

    fn sample_imported_result(
        account: u32,
        txid: &str,
        detail: &str,
    ) -> crate::models::TxBroadcastResult {
        crate::models::TxBroadcastResult {
            source_account: account,
            txid: Some(txid.to_owned()),
            status: crate::models::TxLifecycleState::Pending,
            fee_zatoshis: 10_000,
            detail: detail.to_owned(),
            confirmed_height: None,
            safe_to_discard: false,
        }
    }

    #[test]
    fn sweep_outcome_full_success_carries_no_error() {
        use super::assemble_sweep_outcome;
        let outcome =
            assemble_sweep_outcome(vec![sample_broadcast_result(0)], Vec::new(), 25_000, Ok(()))
                .expect("Ok");
        assert!(outcome.error.is_none());
        assert_eq!(outcome.transactions.len(), 1);
        assert!(outcome.skipped_accounts.is_empty());
        assert_eq!(outcome.total_donation_zatoshis, 25_000);
    }

    #[test]
    fn sweep_outcome_partial_failure_preserves_records_and_error() {
        use super::assemble_sweep_outcome;
        let outcome = assemble_sweep_outcome(
            vec![sample_broadcast_result(0), sample_broadcast_result(1)],
            vec![crate::models::SkippedSweepAccount {
                account_index: 7,
                gross_zatoshis: 9_000,
                reason: "dust".to_owned(),
            }],
            0,
            Err(ZeckError::Broadcast("account 2 rejected".to_owned())),
        )
        .expect("a partial failure with broadcast records is reported as Ok, not lost");
        assert_eq!(outcome.transactions.len(), 2);
        // Skipped accounts ride along on the partial-success outcome.
        assert_eq!(outcome.skipped_accounts.len(), 1);
        assert_eq!(outcome.skipped_accounts[0].account_index, 7);
        let message = outcome
            .error
            .expect("a partial failure carries the underlying error message");
        assert!(message.contains("account 2 rejected"));
    }

    #[test]
    fn unknown_first_transaction_is_returned_even_without_prior_success() {
        use super::assemble_sweep_outcome;
        use crate::models::TxLifecycleState;

        let mut unknown = sample_broadcast_result(0);
        unknown.txid = Some("known-before-submit".to_owned());
        unknown.status = TxLifecycleState::SubmissionUnknown;
        unknown.fee_zatoshis = 10_000;
        unknown.confirmed_height = None;
        let outcome = assemble_sweep_outcome(
            vec![unknown],
            Vec::new(),
            0,
            Err(ZeckError::Broadcast("transport closed".to_owned())),
        )
        .expect("an ambiguous first submission must return its durable identity");
        assert_eq!(outcome.transactions.len(), 1);
        assert_eq!(
            outcome.transactions[0].txid.as_deref(),
            Some("known-before-submit")
        );
        assert_eq!(outcome.transactions[0].fee_zatoshis, 10_000);
        let error = outcome.error.expect("uncertainty must remain visible");
        assert!(
            error.contains("may already have reached the network"),
            "{error}"
        );
        assert!(error.contains("reconcil"), "{error}");
    }

    #[test]
    fn unknown_submission_fee_counts_against_total_cap() {
        let mut unknown = sample_broadcast_result(0);
        unknown.status = crate::models::TxLifecycleState::SubmissionUnknown;
        unknown.fee_zatoshis = 10_000;
        let prior = super::at_risk_fee_total(&[unknown]).unwrap();
        assert_eq!(prior, 10_000);
        assert!(matches!(
            super::enforce_max_fee(
                super::checked_fee_total(prior, 20_000).unwrap(),
                Some(20_000)
            ),
            Err(ZeckError::MaxFeeExceeded(_))
        ));
    }

    #[test]
    fn rejected_submission_does_not_consume_fee_cap() {
        let mut rejected = sample_broadcast_result(0);
        rejected.status = crate::models::TxLifecycleState::Rejected;
        rejected.fee_zatoshis = 10_000;
        assert_eq!(super::at_risk_fee_total(&[rejected]).unwrap(), 0);
    }

    /// An imported sweep that broadcast some accounts and then failed must
    /// report the transactions it already sent, with the failure attached.
    ///
    /// This is audit Issue E in its second location. An imported zcashd
    /// wallet ordinarily holds several `sapzkey` records, so the multi-account
    /// loop is the common case, not an exotic one; each account is built and
    /// broadcast separately. Aborting the sweep with `Err` on account 3 threw
    /// away the txids of accounts 0-2 along with the outcome that held them,
    /// so the user was told the whole sweep failed while real funds had moved
    /// — and a retry found those notes already spent and appeared to do
    /// nothing.
    ///
    /// Asserted positively on the txids themselves and on the error text. An
    /// assertion that the result is merely `Ok` would be satisfied by an
    /// outcome carrying no transactions at all, which is the bug.
    #[test]
    fn imported_sweep_partial_failure_preserves_broadcast_txids_and_error() {
        use super::assemble_imported_sweep_outcome;
        use crate::imported_sweep::ImportedSweepOutcome;

        let outcome = assemble_imported_sweep_outcome(
            ImportedSweepOutcome {
                transactions: vec![
                    sample_imported_result(0, "txid-account-0", "Sapling"),
                    sample_imported_result(1, "txid-account-1", "Sapling"),
                ],
                sapling_transaction_count: 2,
                // The leg aborted on account 2, so it never established that
                // the pool was empty.
                sapling_leg_completed: false,
                transparent_leg_completed: true,
                ..Default::default()
            },
            Err(ZeckError::Broadcast(
                "the node rejected the Sapling sweep: account 2".to_owned(),
            )),
        )
        .expect("a partial imported sweep must report what it broadcast, not collapse to Err");

        let reported: Vec<_> = outcome
            .transactions
            .iter()
            .filter_map(|tx| tx.txid.clone())
            .collect();
        assert_eq!(
            reported,
            vec!["txid-account-0".to_owned(), "txid-account-1".to_owned()],
            "both already-broadcast Sapling transactions must survive the later failure"
        );

        let message = outcome
            .error
            .expect("a partial imported sweep carries the failure that stopped it");
        assert!(
            message.contains("account 2"),
            "the terminal error must name what failed. Got: {message}"
        );

        // The aborted Sapling leg must not be reported as an empty pool: only
        // the transparent leg, which did run to the end, is skipped.
        assert_eq!(outcome.skipped_accounts.len(), 1);
        assert!(
            outcome.skipped_accounts[0].reason.contains("transparent"),
            "an aborted Sapling leg must not claim the pool was empty. Got: {}",
            outcome.skipped_accounts[0].reason
        );
    }

    #[test]
    fn imported_sweep_uses_registered_display_indices_after_filtering() {
        let outcome = super::assemble_imported_sweep_outcome(
            crate::imported_sweep::ImportedSweepOutcome {
                transactions: vec![sample_imported_result(7, "imported-tx", "Sapling")],
                sapling_transaction_count: 1,
                sapling_leg_completed: true,
                transparent_leg_completed: true,
                ..Default::default()
            },
            Ok(()),
        )
        .expect("filtered imported sweep should report its broadcast");
        assert_eq!(outcome.transactions[0].source_account, 7);
    }

    #[test]
    fn transparent_only_mixed_outcome_reports_its_display_id_without_fake_sapling_skip() {
        let outcome = super::assemble_imported_sweep_outcome_for_legs(
            crate::imported_sweep::ImportedSweepOutcome {
                sapling_leg_completed: true,
                transparent_leg_completed: true,
                transactions: vec![sample_imported_result(5, "transparent-tx", "direct")],
                transparent_transaction_recorded: true,
                transparent_display_index: Some(5),
                ..Default::default()
            },
            Ok(()),
            false,
            true,
        )
        .unwrap();
        assert_eq!(outcome.transactions[0].source_account, 5);
        assert!(outcome.transactions[0].detail.contains("direct"));
        assert!(outcome.skipped_accounts.is_empty());
    }

    #[test]
    fn filtered_transparent_empty_leg_skip_uses_its_display_id() {
        let outcome = super::assemble_imported_sweep_outcome_for_legs(
            crate::imported_sweep::ImportedSweepOutcome {
                sapling_leg_completed: true,
                transparent_leg_completed: true,
                transparent_display_index: Some(5),
                ..Default::default()
            },
            Ok(()),
            false,
            true,
        )
        .unwrap();
        assert_eq!(outcome.skipped_accounts.len(), 1);
        assert_eq!(outcome.skipped_accounts[0].account_index, 5);
    }

    /// Review nit on #275: the HD leg's donation note (why a donation was
    /// or was not placed) used to be dropped when the legs were merged.
    #[test]
    fn mixed_outcome_keeps_the_hd_legs_donation_note() {
        let leg = |txid: &str, note: Option<&str>| crate::models::SweepOutcome {
            transactions: vec![crate::models::TxBroadcastResult {
                source_account: 0,
                txid: Some(txid.into()),
                status: crate::models::TxLifecycleState::Pending,
                fee_zatoshis: 0,
                detail: String::new(),
                confirmed_height: None,
                safe_to_discard: false,
            }],
            skipped_accounts: Vec::new(),
            total_donation_zatoshis: 0,
            error: None,
            donation_note: note.map(str::to_owned),
            follow_up_review_required: false,
        };
        let merged = super::merge_combined_sweep_outcomes(
            leg("imported-tx", None),
            Ok(leg("hd-tx", Some("donation below the floor"))),
        )
        .unwrap();
        assert_eq!(merged.transactions.len(), 2);
        assert_eq!(
            merged.donation_note.as_deref(),
            Some("donation below the floor")
        );
    }

    #[test]
    fn mixed_hd_failure_keeps_imported_broadcast_receipt() {
        let imported = crate::models::SweepOutcome {
            transactions: vec![crate::models::TxBroadcastResult {
                source_account: 7,
                txid: Some("imported-tx".into()),
                status: crate::models::TxLifecycleState::Pending,
                fee_zatoshis: 0,
                detail: "imported Sapling".into(),
                confirmed_height: None,
                safe_to_discard: false,
            }],
            skipped_accounts: Vec::new(),
            total_donation_zatoshis: 0,
            error: None,
            donation_note: None,
            follow_up_review_required: false,
        };
        let merged = super::merge_combined_sweep_outcomes(
            imported,
            Err(ZeckError::Broadcast("HD node rejection".into())),
        )
        .expect("a broadcast imported tx must survive HD failure");
        assert_eq!(merged.transactions[0].txid.as_deref(), Some("imported-tx"));
        assert!(merged
            .error
            .as_deref()
            .unwrap()
            .contains("HD node rejection"));
    }

    /// The same fold, with nothing broadcast, must stay a hard failure.
    ///
    /// The partial-failure allowance exists only to stop on-chain
    /// transactions being forgotten. With none, "the sweep failed" is the
    /// truthful report and must not be softened into a success carrying an
    /// error field the caller may not read.
    #[test]
    fn imported_sweep_failure_before_any_broadcast_stays_an_err() {
        use super::assemble_imported_sweep_outcome;
        use crate::imported_sweep::ImportedSweepOutcome;

        let err = assemble_imported_sweep_outcome(
            ImportedSweepOutcome::default(),
            Err(ZeckError::Broadcast("account 0 rejected".to_owned())),
        )
        .expect_err("a failure with nothing broadcast must remain an Err");
        assert!(matches!(err, ZeckError::Broadcast(_)));
    }

    #[test]
    fn sweep_outcome_failure_before_any_broadcast_propagates_err() {
        use super::assemble_sweep_outcome;
        let err = assemble_sweep_outcome(
            Vec::new(),
            Vec::new(),
            0,
            Err(ZeckError::Broadcast("first account rejected".to_owned())),
        )
        .expect_err("a failure before any broadcast must stay an Err");
        assert!(matches!(err, ZeckError::Broadcast(_)));
    }

    #[test]
    fn balance_at_or_below_fee_floor_is_not_sweepable() {
        use super::{balance_covers_sweep_fee, MIN_SHIELDED_SEND_FEE_ZATOSHIS};
        // A balance at or below the ZIP-317 fee floor cannot be swept — the fee
        // would consume it all, hard-failing the shielding/send proposal. This
        // predicate is what gates both execution steps so they skip such dust
        // exactly as `build_sweep_proposal` does (instead of erroring the sweep).
        assert!(!balance_covers_sweep_fee(0));
        assert!(!balance_covers_sweep_fee(
            MIN_SHIELDED_SEND_FEE_ZATOSHIS - 1
        ));
        assert!(!balance_covers_sweep_fee(MIN_SHIELDED_SEND_FEE_ZATOSHIS)); // == floor: fee eats it all
        assert!(balance_covers_sweep_fee(MIN_SHIELDED_SEND_FEE_ZATOSHIS + 1));
    }

    #[test]
    fn insufficient_funds_proposal_errors_are_detected_for_skip() {
        use super::is_insufficient_funds_error;
        // The exact zcash_client_backend phrasing the sweep must treat as
        // "this account is unsweepable, skip it" rather than a fatal sweep abort
        // — this is the case `balance_covers_sweep_fee` (summed balance) misses
        // when the value is dust UTXOs or outside the shieldable receivers.
        assert!(is_insufficient_funds_error(
            "building shielding proposal: Change output generation failed: \
             Insufficient funds: required 10000 zatoshis, but only 0 zatoshis were available"
        ));
        assert!(is_insufficient_funds_error(
            "building sweep proposal: Insufficient funds: required 10000, but only 5000 were available"
        ));
        // Unrelated build failures MUST still abort (not be silently skipped).
        assert!(!is_insufficient_funds_error(
            "building shielding proposal: network validation failed"
        ));
        assert!(!is_insufficient_funds_error(
            "creating shielding transaction: prover initialization failed"
        ));
    }

    #[test]
    fn execution_dust_floor_matches_proposal_minimum_fee() {
        use super::MIN_SHIELDED_SEND_FEE_ZATOSHIS;
        use zcash_primitives::transaction::fees::zip317::MINIMUM_FEE;
        // The execution-side dust floor MUST equal the proposal's ZIP-317
        // `minimum_fee_zatoshis`, or the dry run and the actual sweep would
        // disagree on which accounts to skip — the divergence this fix closes.
        assert_eq!(MIN_SHIELDED_SEND_FEE_ZATOSHIS, u64::from(MINIMUM_FEE));
    }

    #[test]
    fn proposal_skips_dusty_transparent_only_accounts() {
        let proposal = build_sweep_proposal(
            &progress_with_account(AccountBalancePreview {
                account_index: 0,
                sapling_address: "zs-test".to_owned(),
                unified_address: "u-test".to_owned(),
                transparent_receive_address: "t-recv".to_owned(),
                transparent_change_address: "t-change".to_owned(),
                transparent_utxo_count: 1,
                sapling_zatoshis: 0,
                orchard_zatoshis: 0,
                transparent_zatoshis: 5_000,
                total_zatoshis: 5_000,
                has_activity: true,
                status: "ok".to_owned(),
            }),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            "",
        )
        .expect("proposal should build");

        assert!(proposal.transactions.is_empty());
        assert_eq!(proposal.skipped_accounts.len(), 1);
    }

    #[test]
    fn memo_with_ascii_is_accepted() {
        use super::normalized_memo_text;
        let result = normalized_memo_text(Some("Argos recovery"));
        assert!(result.is_ok());
    }

    #[test]
    fn memo_with_emoji_is_accepted_when_short_enough() {
        use super::normalized_memo_text;
        // emoji are 4 bytes each — a handful should still fit within the 512-byte limit
        let result = normalized_memo_text(Some("🎉 recovery 🎉"));
        assert!(result.is_ok());
    }

    #[test]
    fn memo_exceeding_512_bytes_is_rejected() {
        use super::normalized_memo_text;
        // each '🎉' is 4 bytes; 129 of them = 516 bytes, over the 512-byte memo limit
        let long_memo = "🎉".repeat(129);
        let result = normalized_memo_text(Some(&long_memo));
        assert!(result.is_err(), "expected InvalidMemo for oversized memo");
    }

    #[test]
    fn empty_memo_falls_back_to_default() {
        use super::{normalized_memo_text, RECOVERY_MEMO_DEFAULT};
        let result = normalized_memo_text(Some("   ")).unwrap();
        assert_eq!(result, RECOVERY_MEMO_DEFAULT);
    }

    // ─── Donation Err-fallback (Kristi review #1) ─────────────────────────────
    //
    // The three-way branch in execute_send_max_step's donation handling lives
    // in `donation_proposal_or_fallback`. Tests below use a String stand-in
    // for the Proposal type to exercise all three arms without a wallet DB.

    #[test]
    fn donation_fallback_ok_some_returns_split() {
        // Split built → its proposal AND the requested donation amount.
        let got = super::donation_proposal_or_fallback::<&str>(
            Ok(Some("donation-split")),
            "donation-free-max",
            5_000,
            0,
        );
        assert_eq!(got, ("donation-split", 5_000));
    }

    #[test]
    fn donation_fallback_ok_none_returns_max() {
        // Fell back → donation-free proposal AND zero actual donation.
        let got =
            super::donation_proposal_or_fallback::<&str>(Ok(None), "donation-free-max", 5_000, 0);
        assert_eq!(got, ("donation-free-max", 0));
    }

    #[test]
    fn donation_fallback_err_returns_max() {
        // The critical safety property: an Err must NOT propagate. The user's
        // sweep proceeds donation-free. Pre-fix, an Err here aborted the
        // entire sweep — see PR #66 review (Kristi, 2026-05-28). The actual
        // donation is reported as 0 so the outcome doesn't over-count.
        let got = super::donation_proposal_or_fallback::<&str>(
            Err(ZeckError::TransactionBuild(
                "synthetic regression".to_owned(),
            )),
            "donation-free-max",
            5_000,
            42,
        );
        assert_eq!(got, ("donation-free-max", 0));
    }

    // ─── Multi-account proposal donation logic ────────────────────────────────

    fn progress_with_accounts(accounts: Vec<AccountBalancePreview>) -> ScanProgress {
        ScanProgress {
            handle: ScanHandle::new(),
            phase: ScanPhase::Complete,
            blocks_scanned: 1,
            blocks_total: 1,
            synced_to_height: None,
            elapsed_seconds: None,
            estimated_remaining_seconds: None,
            accounts,
            discoveries: vec![],
            summary: None,
            server: None,
            message: None,
            error: None,
            sleep_event: None,
            in_sandblasting_zone: false,
            gap_extension: None,
        }
    }

    /// Helper to build a shielded-only account preview with a chosen Sapling
    /// balance. The index lets each account in a multi-account scenario be
    /// distinguishable in the proposal output.
    fn shielded_account(index: u32, sapling_zatoshis: u64) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: index,
            sapling_address: String::new(),
            unified_address: derived_destination(),
            transparent_receive_address: String::new(),
            transparent_change_address: String::new(),
            transparent_utxo_count: 0,
            sapling_zatoshis,
            orchard_zatoshis: 0,
            transparent_zatoshis: 0,
            total_zatoshis: sapling_zatoshis,
            has_activity: sapling_zatoshis > 0,
            status: String::new(),
        }
    }

    #[test]
    fn mixed_proposal_routes_each_asset_once_and_scopes_memo_to_hd() {
        let mut hd = shielded_account(0, 100_000);
        hd.transparent_zatoshis = 200_000;
        hd.transparent_utxo_count = 2;
        hd.total_zatoshis = 300_000;
        let progress = progress_with_accounts(vec![hd, shielded_account(1, 300_000)]);
        let standalone = std::collections::HashMap::from([(
            0,
            crate::scan::StandaloneTransparentBalance {
                zatoshis: 100_000,
                utxo_count: 1,
            },
        )]);
        let proposal = super::build_combined_sweep_proposal(
            &progress,
            SweepRequest {
                destination: derived_destination_testnet(),
                memo: Some("recovered".into()),
                max_fee_zatoshis: Some(45_000),
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Testnet,
            &[0],
            &[1],
            &standalone,
        )
        .expect("all three assets should fit the combined cap");
        assert_eq!(proposal.transactions.len(), 3);
        assert_eq!(proposal.total_fee_zatoshis, 35_000);
        assert_eq!(proposal.net_received_zatoshis, 375_000);
        assert_eq!(
            proposal
                .transactions
                .iter()
                .filter(|tx| tx.memo.is_some())
                .count(),
            0
        );
        assert_eq!(
            proposal
                .transactions
                .iter()
                .filter(|tx| tx.source_account == 1)
                .count(),
            1
        );
        assert!(proposal
            .transactions
            .iter()
            .any(|tx| tx.note.contains("straight to your")));
    }

    #[test]
    fn mixed_proposal_applies_fee_cap_after_all_legs() {
        let progress = progress_with_accounts(vec![
            shielded_account(0, 100_000),
            shielded_account(1, 100_000),
        ]);
        let error = super::build_combined_sweep_proposal(
            &progress,
            SweepRequest {
                destination: derived_destination_testnet(),
                memo: None,
                max_fee_zatoshis: Some(15_000),
                donation_rate: None,
                donor_email: None,
            },
            ZeckNetwork::Testnet,
            &[0],
            &[1],
            &std::collections::HashMap::new(),
        )
        .expect_err("two individually affordable legs cost 20,000 together");
        assert!(matches!(error, crate::error::ZeckError::MaxFeeExceeded(_)));
    }

    fn orchard_only_destination() -> String {
        use zcash_address::unified::{Address, Encoding, Receiver};
        let sk = orchard::keys::SpendingKey::from_bytes([7u8; 32]).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let address = fvk.address_at(0u32, orchard::keys::Scope::External);
        Address::try_from_items(vec![Receiver::Orchard(address.to_raw_address_bytes())])
            .unwrap()
            .encode(&zcash_protocol::consensus::NetworkType::Main)
    }

    #[tokio::test]
    async fn empty_standalone_transparent_key_does_not_block_orchard_hd_execution() {
        use crate::key_source::ImportedKeySource;
        use argos_wallet_import::{keys::TransparentKey, ImportedKeys, Provenance};
        use secrecy::Secret;

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = ImportedKeys {
            mnemonic: Some(SecretString::new(phrase.to_owned())),
            transparent: vec![TransparentKey {
                secret: Secret::new([0x42; 32]),
                provenance: Provenance::Standalone,
                created_at: None,
            }],
            ..Default::default()
        };
        let handle = ScanHandle::new();
        let mut session = reviewed_session(handle.clone(), phrase);
        session.runtime.key_source = Arc::new(ImportedKeySource::new(keys));
        session.source_fingerprint = session.runtime.key_source.fingerprint().unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        session.runtime.data_dir = tempdir.path().to_owned();
        let workspace =
            crate::workspace::RecoveryWorkspace::from_runtime(&session.runtime).unwrap();
        workspace
            .initialize_from_source(session.runtime.network, session.runtime.key_source.as_ref())
            .unwrap();
        session.workspace_root = workspace.root().to_owned();
        let derived = derive_accounts(
            &SecretString::new(phrase.to_owned()),
            ZeckNetwork::Mainnet,
            1,
        )
        .unwrap()
        .remove(0);
        let mut state = session.state.lock().await;
        state.progress = progress_with_accounts(vec![shielded_account(0, 100_000)]);
        state.progress.handle = handle.clone();
        state.standalone_transparent_indices = vec![0];
        state.standalone_transparent_balances.insert(
            0,
            crate::scan::StandaloneTransparentBalance {
                zatoshis: 0,
                utxo_count: 0,
            },
        );
        state.tracked_accounts.push(TrackedAccount {
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            derived,
            transparent_receivers: Vec::new(),
            spend_authority: crate::scan::TrackedSpendAuthority::Hd { zip32_index: 0 },
            standalone_transparent_receivers: Vec::new(),
            transparent_key_coordinates: Vec::new(),
        });
        let request = SweepRequest {
            destination: orchard_only_destination(),
            memo: None,
            max_fee_zatoshis: None,
            donation_rate: None,
            donor_email: None,
        };
        let proposal = super::build_combined_sweep_proposal(
            &state.progress,
            request.clone(),
            ZeckNetwork::Mainnet,
            &[0],
            &[],
            &state.standalone_transparent_balances,
        )
        .expect("the funded HD leg can propose to Orchard only");
        assert_eq!(proposal.transactions.len(), 1);
        let intent =
            ReviewedSweepIntent::capture_from_state(request.clone(), &proposal, &session, &state);
        drop(state);
        let proposal_id = SweepProposalId("orchard-hd-empty-direct".to_owned());
        session
            .reviewed_sweeps
            .lock()
            .await
            .insert(proposal_id.clone(), intent);
        let service = super::RecoveryService::new();
        service
            .sessions
            .write()
            .await
            .insert(handle.id.clone(), Arc::new(session));

        // There are no actual wallet notes in this fixture. Execution must
        // reach the HD wallet path rather than refusing the empty direct leg.
        let error = service
            .execute_sweep(&handle, &proposal_id)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("wallet workspace is unavailable"),
            "empty direct leg wrongly blocked HD execution: {error}"
        );

        // A discovered standalone UTXO changes the route: the same
        // destination must be refused before the imported executor starts.
        let session = service.session(&handle).await.unwrap();
        let mut state = session.state.lock().await;
        state.standalone_transparent_balances.insert(
            0,
            crate::scan::StandaloneTransparentBalance {
                zatoshis: 100_000,
                utxo_count: 1,
            },
        );
        state.progress.accounts[0].transparent_zatoshis = 100_000;
        state.progress.accounts[0].transparent_utxo_count = 1;
        state.progress.accounts[0].total_zatoshis = 200_000;
        let quoted = super::build_combined_sweep_proposal(
            &state.progress,
            request.clone(),
            ZeckNetwork::Mainnet,
            &[0],
            &[],
            &state.standalone_transparent_balances,
        );
        assert!(
            quoted.is_err(),
            "funded direct leg cannot quote Orchard only"
        );
        let intent = ReviewedSweepIntent::capture_from_state(request, &proposal, &session, &state);
        drop(state);
        let funded_id = SweepProposalId("orchard-hd-funded-direct".to_owned());
        session
            .reviewed_sweeps
            .lock()
            .await
            .insert(funded_id.clone(), intent);
        let error = service
            .execute_sweep(&handle, &funded_id)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("destination must include an Orchard or Sapling receiver"),
            "funded direct leg was not refused before execution: {error}"
        );
    }

    #[test]
    fn mixed_execution_partition_keeps_imported_signer_out_of_hd_leg() {
        let phrase = SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned());
        let mut derived = derive_accounts(&phrase, ZeckNetwork::Testnet, 1)
            .unwrap()
            .remove(0);
        let hd = TrackedAccount {
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            derived: derived.clone(),
            transparent_receivers: Vec::new(),
            spend_authority: crate::scan::TrackedSpendAuthority::Hd { zip32_index: 0 },
            standalone_transparent_receivers: Vec::new(),
            transparent_key_coordinates: Vec::new(),
        };
        derived.index = 7;
        let imported = TrackedAccount {
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            derived,
            transparent_receivers: Vec::new(),
            spend_authority: crate::scan::TrackedSpendAuthority::ImportedSapling {
                key_index: 3,
                wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            },
            standalone_transparent_receivers: Vec::new(),
            transparent_key_coordinates: Vec::new(),
        };
        let (hd_ids, imported_ids, signers) =
            super::partition_mixed_spend_authorities(&[hd, imported]).unwrap();
        assert_eq!(hd_ids, vec![0]);
        assert_eq!(imported_ids, vec![7]);
        assert_eq!(
            signers,
            vec![(7, zcash_client_sqlite::AccountUuid::default(), 3)]
        );
    }

    #[test]
    fn proposal_only_above_threshold_accounts_contribute_donation() {
        // Three accounts. Account 0 is large (donation included); account 1
        // is right at the threshold boundary (included); account 2 is below
        // threshold (skipped from donation, swept normally). Total donation
        // is the sum of accounts 0 and 1, not just one of them and not all.
        let proposal = build_sweep_proposal(
            &progress_with_accounts(vec![
                shielded_account(0, 5_000_000), // 10% = 500k, well above MIN
                shielded_account(1, 1_010_000), // net ≈ 1_000_000 → 10% = 100k = MIN
                shielded_account(2, 500_000),   // 10% ≈ 49.9k, below MIN → no donation
            ]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap();
        let sweeps: Vec<_> = proposal
            .transactions
            .iter()
            .filter(|t| t.kind == ProposedTxKind::SweepShielded)
            .collect();
        assert_eq!(sweeps.len(), 3, "every account produces a sweep tx");
        // Account 0 and 1 above threshold; account 2 below.
        assert!(sweeps[0].donation_zatoshis > 0);
        assert!(sweeps[1].donation_zatoshis > 0);
        assert_eq!(sweeps[2].donation_zatoshis, 0);
        // Total matches the per-tx sum.
        let summed: u64 = sweeps.iter().map(|s| s.donation_zatoshis).sum();
        assert_eq!(proposal.total_donation_zatoshis, summed);
        // Fund-safety invariant: per-tx, gross == net + fee (donation is part
        // of net in the estimate).
        for s in &sweeps {
            assert_eq!(s.net_zatoshis + s.fee_zatoshis, s.gross_zatoshis);
            assert!(
                s.donation_zatoshis < s.net_zatoshis,
                "donation must remain strictly below net so user receives positive remainder"
            );
        }
    }

    #[test]
    fn proposal_donation_rate_zero_produces_no_donation_across_accounts() {
        // donation_rate Some(0.0) is treated as "skip" by the helper. The
        // total donation must be 0 regardless of how many accounts exist.
        let proposal = build_sweep_proposal(
            &progress_with_accounts(vec![
                shielded_account(0, 10_000_000),
                shielded_account(1, 20_000_000),
                shielded_account(2, 5_000_000),
            ]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.0),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap();
        assert_eq!(proposal.total_donation_zatoshis, 0);
        for s in proposal
            .transactions
            .iter()
            .filter(|t| t.kind == ProposedTxKind::SweepShielded)
        {
            assert_eq!(s.donation_zatoshis, 0);
        }
    }

    #[test]
    fn proposal_no_donation_when_donation_address_empty() {
        // The feature off-switch: an empty DONATION_ADDRESS constant must
        // suppress every donation output regardless of rate or account size.
        // (Production passes `crate::donation::DONATION_ADDRESS`; the test
        // injects "" to simulate the dormant state.)
        let proposal = build_sweep_proposal(
            &progress_with_accounts(vec![
                shielded_account(0, 100_000_000), // 1 ZEC
                shielded_account(1, 50_000_000),  // 0.5 ZEC
            ]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: Some("donor@example.com".to_owned()),
            },
            ZeckNetwork::Mainnet,
            "", // address blanked
        )
        .unwrap();
        assert_eq!(proposal.total_donation_zatoshis, 0);
    }

    #[test]
    fn proposal_rejects_invalid_donation_rate() {
        let err = build_sweep_proposal(
            &progress_with_accounts(vec![shielded_account(0, 5_000_000)]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(1.5),
                donor_email: None,
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap_err();
        match err {
            ZeckError::InvalidConfig(msg) => {
                assert!(msg.contains("donation rate"), "got: {msg}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn proposal_rejects_invalid_donor_email() {
        let err = build_sweep_proposal(
            &progress_with_accounts(vec![shielded_account(0, 5_000_000)]),
            SweepRequest {
                destination: derived_destination(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: Some(0.10),
                donor_email: Some("notanemail".to_owned()),
            },
            ZeckNetwork::Mainnet,
            DONATION_TEST_UA,
        )
        .unwrap_err();
        assert!(matches!(err, ZeckError::InvalidConfig(_)));
    }
}

#[cfg(test)]
mod memo_refusal_tests {
    use super::*;
    use crate::key_source::{ImportedKeySource, SeedKeySource};
    use secrecy::SecretString;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon art";

    /// One predicate for "can this sweep carry a memo", asked of the key
    /// source: the GUI asks it before scanning, and propose and execute ask
    /// it again, so the three cannot disagree.
    #[test]
    fn only_a_seed_source_may_carry_a_memo() {
        let seeded = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let seedless = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());

        assert!(refuse_memo_for_key_source(&seeded, Some("exchange deposit 8821")).is_ok());
        assert!(refuse_memo_for_key_source(&seedless, None).is_ok());
        assert!(
            refuse_memo_for_key_source(&seedless, Some("   ")).is_ok(),
            "blank is no memo"
        );

        let err = refuse_memo_for_key_source(&seedless, Some("exchange deposit 8821"))
            .expect_err("a seedless sweep sends no memo");
        let text = err.to_string();
        // Worded for the sweep, not the wallet: a matched-address recovery
        // is seedless here although its user has just typed a seed phrase.
        assert!(!text.contains("has no seed phrase"), "{text}");
        assert!(text.contains("sends no memo"), "{text}");
    }
}

#[cfg(all(test, feature = "argos-network"))]
#[path = "../tests/common/fake_lightwalletd.rs"]
mod deletion_fake_lightwalletd;

#[cfg(test)]
mod propose_workspace_guard_tests {
    use super::*;
    use crate::broadcast::{
        observe_transaction, EndpointTxEvidence, SubmissionDisposition, TxObservation,
    };
    use crate::key_source::{ImportedKeySource, SeedKeySource};
    use crate::models::{AccountBalancePreview, ZeckNetwork};
    use crate::scan::ScanTaskState;
    use argos_wallet_import::keys::{Provenance, TransparentKey};
    use secrecy::Secret;

    #[cfg(unix)]
    #[test]
    fn workspace_identity_collapses_aliases_before_the_directory_exists() {
        let tempdir = tempfile::tempdir().unwrap();
        let real = tempdir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = tempdir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert_eq!(
            canonical_workspace_identity(&real.join("new/workspace")).unwrap(),
            canonical_workspace_identity(&alias.join("new/workspace")).unwrap(),
        );
    }

    fn destination() -> String {
        crate::derive_accounts(
            &SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about"
                    .to_owned(),
            ),
            ZeckNetwork::Mainnet,
            1,
        )
        .expect("derived account")[0]
            .unified_address
            .clone()
    }

    fn request() -> SweepRequest {
        SweepRequest {
            destination: destination(),
            memo: None,
            max_fee_zatoshis: None,
            donation_rate: None,
            donor_email: None,
        }
    }

    /// A completed session, built the way `begin_scan_session` leaves the
    /// workspace: initialized, with no account registered in it.
    async fn completed_session(
        data_dir: &std::path::Path,
        key_source: Arc<dyn KeySource>,
        account: AccountBalancePreview,
    ) -> (RecoveryService, ScanHandle) {
        let runtime = RuntimeScanConfig {
            key_source,
            birthday: 1_528_061,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: data_dir.to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        completed_session_from_runtime(runtime, account).await
    }

    async fn completed_session_from_runtime(
        runtime: RuntimeScanConfig,
        account: AccountBalancePreview,
    ) -> (RecoveryService, ScanHandle) {
        let workspace = RecoveryWorkspace::from_runtime(&runtime).expect("workspace paths");
        workspace
            .initialize_from_source(runtime.network, runtime.key_source.as_ref())
            .expect("workspace initializes");

        let handle = ScanHandle::new();
        let mut task_state = ScanTaskState::new(handle.clone());
        task_state.progress.phase = ScanPhase::Complete;
        task_state.progress.accounts = vec![account];
        task_state.workspace = Some(workspace.clone());

        let service = RecoveryService::new();
        let source_fingerprint = runtime
            .key_source
            .fingerprint()
            .expect("source fingerprint");
        service.sessions.write().await.insert(
            handle.id.clone(),
            Arc::new(ScanSession {
                source_fingerprint,
                state: Arc::new(Mutex::new(task_state)),
                runtime,
                started_at: Instant::now(),
                task: Mutex::new(None),
                workspace_root: workspace.root().to_owned(),
                reviewed_sweeps: Mutex::new(ReviewedSweepStore::default()),
            }),
        );
        (service, handle)
    }

    #[tokio::test]
    async fn reconciled_old_scan_cannot_issue_another_sweep_quote() {
        let dir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            dir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about"
                    .to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        service
            .reconciliation_rescan_required
            .lock()
            .await
            .insert(handle.id.clone());
        let err = service.propose_sweep(&handle, request()).await.unwrap_err();
        assert!(err.to_string().contains("fresh scan"), "{err}");
        let err = service
            .execute_sweep(&handle, &SweepProposalId("old-review".to_owned()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("fresh scan"), "{err}");
    }

    struct OneMinedThenObserverError(usize);

    #[async_trait::async_trait]
    impl TxObserver for OneMinedThenObserverError {
        async fn observe(
            &mut self,
            _network: ZeckNetwork,
            _txid: TxId,
            _expiry_height: Option<u32>,
        ) -> ZeckResult<TxObservation> {
            self.0 += 1;
            if self.0 == 1 {
                Ok(mined_deletion_observation())
            } else {
                Err(ZeckError::Lightwalletd(
                    "second observation failed".to_owned(),
                ))
            }
        }
    }

    #[tokio::test]
    async fn partial_reconciliation_failure_still_invalidates_old_review() {
        let dir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            dir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about"
                    .to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let registry_path = {
            let guard = NetworkOperationGuard::acquire(dir.path(), ZeckNetwork::Mainnet).unwrap();
            let path = guard.broadcast_log_path().unwrap();
            let mut log = guard.open_broadcast_log().unwrap();
            for byte in [84, 85] {
                let txid = TxId::from_bytes([byte; 32]);
                log.persist_prepared(&PreparedTransaction {
                    txid,
                    raw_tx: vec![byte],
                    fee_zatoshis: 10_000,
                    expiry_height: Some(130),
                })
                .unwrap();
                log.transition(
                    txid,
                    TxLifecycleState::Pending,
                    Some(&SubmissionDisposition::Accepted),
                    None,
                )
                .unwrap();
            }
            path
        };
        let mut observer = OneMinedThenObserverError(0);
        // One observer failure is reported on its row, not as an error that
        // hides the rows already observed.
        let rows = service
            .reconcile_sweep_with_observer(&handle, &mut observer)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|row| row.detail.contains("second observation failed")));
        let mut log = DurableBroadcastLog::open(&registry_path).unwrap();
        let records = log.records();
        assert_eq!(records[0].state, TxLifecycleState::Mined);
        assert_eq!(records[1].state, TxLifecycleState::Pending);
        log.transition(
            records[1].prepared.txid,
            TxLifecycleState::Mined,
            None,
            Some(&mined_deletion_observation()),
        )
        .unwrap();
        drop(log);
        let err = service.propose_sweep(&handle, request()).await.unwrap_err();
        assert!(err.to_string().contains("fresh scan"), "{err}");
    }

    struct NeverSubmit;

    #[async_trait::async_trait]
    impl crate::broadcast::TxSubmitter for NeverSubmit {
        async fn send_raw(
            &mut self,
            _raw: Vec<u8>,
        ) -> Result<zcash_client_backend::proto::service::SendResponse, tonic::Status> {
            panic!("mined transaction must never be resubmitted")
        }
    }

    #[tokio::test]
    async fn retry_that_observes_mining_refuses_send_and_invalidates_old_review() {
        let dir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            dir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about"
                    .to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let txid = TxId::from_bytes([86; 32]);
        {
            let guard = NetworkOperationGuard::acquire(dir.path(), ZeckNetwork::Mainnet).unwrap();
            let mut log = guard.open_broadcast_log().unwrap();
            log.persist_prepared(&PreparedTransaction {
                txid,
                raw_tx: vec![86],
                fee_zatoshis: 10_000,
                expiry_height: Some(130),
            })
            .unwrap();
            log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
        }
        let mut observer = FixedDeletionObserver(mined_deletion_observation());
        let err = service
            .retry_unknown_sweep_with_clients(
                &handle,
                &txid.to_string(),
                &mut observer,
                &mut NeverSubmit,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not eligible"), "{err}");
        let guard = NetworkOperationGuard::acquire(dir.path(), ZeckNetwork::Mainnet).unwrap();
        assert_eq!(
            guard
                .open_broadcast_log()
                .unwrap()
                .latest(txid)
                .unwrap()
                .state,
            TxLifecycleState::Mined
        );
        drop(guard);
        let err = service.propose_sweep(&handle, request()).await.unwrap_err();
        assert!(err.to_string().contains("fresh scan"), "{err}");
    }

    fn transparent_account(zatoshis: u64) -> AccountBalancePreview {
        AccountBalancePreview {
            account_index: 0,
            sapling_address: String::new(),
            unified_address: String::new(),
            transparent_receive_address: String::new(),
            transparent_change_address: String::new(),
            transparent_utxo_count: 1,
            sapling_zatoshis: 0,
            orchard_zatoshis: 0,
            transparent_zatoshis: zatoshis,
            total_zatoshis: zatoshis,
            has_activity: true,
            status: "204 transparent address(es) checked, 1 funded".to_owned(),
        }
    }

    /// A transparent-only `wallet.dat` scanned in the GUI must reach a sweep
    /// proposal.
    ///
    /// That route never builds an account — ZIP-316 gives a transparent-only
    /// key set no UFVK to anchor one to — so its `wallet.sqlite` is empty by
    /// design, not because it was lost. The workspace guard read that as a
    /// deleted workspace and refused every such sweep with "no longer
    /// contains a wallet", from 1.2.0 through 1.5.2, while the scan above it
    /// showed the funds. The balance is not taken from that database, and the
    /// sweep re-reads every UTXO from the chain before signing, so there is
    /// nothing for the guard to protect here.
    #[tokio::test]
    async fn a_transparent_only_scan_can_price_a_sweep_without_wallet_db() {
        let mut keys = argos_wallet_import::ImportedKeys::default();
        keys.transparent.push(TransparentKey {
            secret: Secret::new([0x42; 32]),
            provenance: Provenance::Standalone,
            created_at: None,
        });
        assert_eq!(
            crate::key_source::classify_recovery_route(&keys),
            crate::key_source::RecoveryRoute::TransparentOnly,
            "fixture must classify as transparent-only or this test proves nothing"
        );

        let tempdir = tempfile::tempdir().expect("temp dir");
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(ImportedKeySource::new(keys)),
            transparent_account(2_099_979_000),
        )
        .await;

        // This offline fixture has no lightwalletd UTXO endpoint. The public
        // review also fetches exact UTXOs before issuing its token; exercise
        // the local pricing/database boundary here.
        let session = service.session(&handle).await.unwrap();
        let state = session.state.lock().await;
        let workspace = RecoveryWorkspace::from_runtime(&session.runtime).unwrap();
        let proposal = super::build_exact_sweep_proposal(
            &state.progress,
            &state.tracked_accounts,
            &state.standalone_transparent_balances,
            &request(),
            session.runtime.network,
            &workspace,
        )
        .expect("a transparent-only scan must be priceable without a wallet database");
        assert_eq!(
            proposal.quote.transactions.len(),
            1,
            "{:?}",
            proposal.quote.transactions
        );
        assert_eq!(proposal.quote.transactions[0].gross_zatoshis, 2_099_979_000);
    }

    fn transparent_only_source() -> Arc<dyn KeySource> {
        let mut keys = argos_wallet_import::ImportedKeys::default();
        keys.transparent.push(TransparentKey {
            secret: Secret::new([0x42; 32]),
            provenance: Provenance::Standalone,
            created_at: None,
        });
        Arc::new(ImportedKeySource::new(keys))
    }

    /// The execute-time stale check, at its call site. A balance that moved
    /// after review must refuse the reviewed proposal before any wallet,
    /// proving or network work: the session's endpoint is unroutable, so if
    /// the check were skipped this would fail with a connection error (or
    /// hit the timeout), never `StaleSweepProposal`.
    #[tokio::test]
    async fn execute_refuses_a_proposal_whose_balance_changed_after_review() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let (service, handle) = completed_session(
            tempdir.path(),
            transparent_only_source(),
            transparent_account(2_099_979_000),
        )
        .await;
        let session = service.session(&handle).await.expect("session");
        let state = session.state.lock().await;
        let proposal =
            build_seedless_sweep_proposal(&state.progress, request(), session.runtime.network)
                .expect("reviewable");
        let intent =
            ReviewedSweepIntent::capture_from_state(request(), &proposal, &session, &state);
        drop(state);
        let proposal_id = SweepProposalId("stale-balance-at-execute".to_owned());
        session
            .reviewed_sweeps
            .lock()
            .await
            .insert(proposal_id.clone(), intent);
        session.state.lock().await.progress.accounts[0].sapling_zatoshis += 1;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            service.execute_sweep(&handle, &proposal_id),
        )
        .await
        .expect("a stale proposal is refused before any network call");
        assert!(
            matches!(result, Err(ZeckError::StaleSweepProposal(_))),
            "got: {result:?}"
        );
        // One-shot: the refused proposal is consumed, not left to retry.
        assert!(matches!(
            service.execute_sweep(&handle, &proposal_id).await,
            Err(ZeckError::UnknownSweepProposal)
        ));
    }

    /// The propose-time re-check: progress that moved while the proposal was
    /// being built must not be issued an id. `issue_reviewed_proposal` is the
    /// only path that stores one, so `propose_sweep` cannot skip the check.
    #[tokio::test]
    async fn a_proposal_is_not_issued_when_progress_moved_while_it_was_built() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let (service, handle) = completed_session(
            tempdir.path(),
            transparent_only_source(),
            transparent_account(2_099_979_000),
        )
        .await;
        let session = service.session(&handle).await.expect("session");
        let mut state = session.state.lock().await;
        let progress = state.progress.clone();
        let proposal = build_seedless_sweep_proposal(&progress, request(), ZeckNetwork::Mainnet)
            .expect("buildable");
        let intent =
            ReviewedSweepIntent::capture_from_state(request(), &proposal, &session, &state);

        state.progress.accounts[0].sapling_zatoshis += 1;
        assert!(matches!(
            issue_reviewed_proposal(&session, intent, &state).await,
            Err(ZeckError::StaleSweepProposal(_))
        ));
        assert!(
            session.reviewed_sweeps.lock().await.entries.is_empty(),
            "a refused proposal must not be stored"
        );

        state.progress = progress;
        let intent =
            ReviewedSweepIntent::capture_from_state(request(), &proposal, &session, &state);
        let id = issue_reviewed_proposal(&session, intent, &state)
            .await
            .expect("unchanged progress issues an id");
        drop(state);
        assert!(session.reviewed_sweeps.lock().await.take(&id).is_ok());
    }

    /// The product must complete a recovery with only the defaults: review
    /// does not require a second confirmation operator, it says that
    /// confirmation will rest on one.
    #[tokio::test]
    async fn review_under_a_single_operator_carries_the_notice() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let (service, handle) = completed_session(
            tempdir.path(),
            transparent_only_source(),
            transparent_account(2_099_979_000),
        )
        .await;
        let chain = (
            3_000_000,
            vec![crate::transparent_recovery::tests_support::utxo(
                crate::transparent_recovery::tests_support::addr(0x42),
                2_099_979_000,
                7,
            )],
        );
        let reviewed = DIRECT_LEG_CHAIN
            .scope(chain, service.propose_sweep(&handle, request()))
            .await
            .expect("a single-operator configuration can review a sweep");
        assert_eq!(
            reviewed.proposal.confirmation_notice.as_deref(),
            Some(crate::lightwalletd::SINGLE_OPERATOR_NOTICE)
        );
    }

    /// The same re-check at its call site: `propose_sweep` must compare the
    /// intent with the progress current at issue time, not the snapshot the
    /// quote was built from. Progress is moved between build and issue; a
    /// call site passing the stale snapshot would issue an id here.
    #[tokio::test]
    async fn propose_refuses_when_progress_moves_between_build_and_issue() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let (service, handle) = completed_session(
            tempdir.path(),
            transparent_only_source(),
            transparent_account(2_099_979_000),
        )
        .await;
        let hook: Box<dyn Fn(&ScanSession) + Send + Sync> = Box::new(|session| {
            session
                .state
                .try_lock()
                .expect("nothing else holds the scan state")
                .progress
                .accounts[0]
                .sapling_zatoshis += 1;
        });
        // Offline chain for the direct transparent leg: one UTXO matching the
        // scanned balance, so the quote builds and the issue-time re-check is
        // what refuses it -- quickly, with no lightwalletd probe.
        let chain = (
            3_000_000,
            vec![crate::transparent_recovery::tests_support::utxo(
                crate::transparent_recovery::tests_support::addr(0x42),
                2_099_979_000,
                7,
            )],
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            DIRECT_LEG_CHAIN.scope(
                chain,
                PROPOSE_AFTER_BUILD.scope(hook, service.propose_sweep(&handle, request())),
            ),
        )
        .await
        .expect("the stale check needs no network");
        assert!(
            matches!(result, Err(ZeckError::StaleSweepProposal(_))),
            "got: {result:?}"
        );
        let session = service.session(&handle).await.expect("session");
        assert!(
            session.reviewed_sweeps.lock().await.entries.is_empty(),
            "a refused proposal must not be stored"
        );
    }

    /// The other half: the guard still refuses a route whose balances do come
    /// from the wallet database, when that database holds no wallet. The
    /// transparent-only exemption must not widen into skipping the check.
    #[tokio::test]
    async fn an_hd_scan_with_an_empty_workspace_is_still_refused() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let mut account = transparent_account(0);
        account.sapling_zatoshis = 5_000_000;
        account.total_zatoshis = 5_000_000;
        account.transparent_utxo_count = 0;
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about"
                    .to_owned(),
            ))),
            account,
        )
        .await;

        let err = service
            .propose_sweep(&handle, request())
            .await
            .expect_err("an HD scan with no wallet in its workspace must not be quoted");
        assert!(
            err.to_string().contains("no longer contains a wallet"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn delete_workspace_refuses_an_external_broadcast_lock_holder() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let session = service.session(&handle).await.unwrap();
        let path = registry_log_path(&session.workspace_root);
        let lock = DurableBroadcastLog::open(&path).unwrap();
        let error = service
            .delete_workspace(&handle)
            .await
            .expect_err("active cross-process journal lock must block deletion");
        assert!(
            error.to_string().contains("broadcast")
                || error.to_string().contains("use")
                || error.to_string().contains("locked"),
            "{error}"
        );
        assert!(session.workspace_root.exists());
        assert!(service.session(&handle).await.is_ok());
        drop(lock);
    }

    fn mined_outcome(txid: String) -> SweepOutcome {
        SweepOutcome {
            transactions: vec![TxBroadcastResult {
                source_account: 0,
                txid: Some(txid),
                status: TxLifecycleState::Mined,
                fee_zatoshis: 10_000,
                detail: "canonical mining evidence".to_owned(),
                confirmed_height: Some(120),
                safe_to_discard: false,
            }],
            donation_note: None,
            skipped_accounts: vec![],
            total_donation_zatoshis: 0,
            error: None,
            follow_up_review_required: false,
        }
    }

    struct FixedDeletionObserver(TxObservation);

    #[async_trait::async_trait]
    impl TxObserver for FixedDeletionObserver {
        async fn observe(
            &mut self,
            _network: ZeckNetwork,
            _txid: TxId,
            _expiry_height: Option<u32>,
        ) -> ZeckResult<TxObservation> {
            Ok(self.0.clone())
        }
    }

    fn mined_deletion_observation() -> TxObservation {
        crate::broadcast::observe_transaction(
            ["one", "two"]
                .into_iter()
                .map(|operator| crate::broadcast::EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(120),
                    reported_height: Some(120),
                    block_hash: Some(vec![1; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(130),
        )
    }

    /// The network registry a workspace (or its tombstone) shares.
    fn registry_log_path(workspace_root: &std::path::Path) -> std::path::PathBuf {
        let network_root = workspace_root
            .ancestors()
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name == "mainnet" || name == "testnet")
            })
            .expect("workspace lives under a network directory");
        let path = network_root
            .join(".broadcast-registry")
            .join(crate::broadcast::BROADCAST_LOG_FILE_NAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    fn seed_source() -> Arc<dyn KeySource> {
        Arc::new(SeedKeySource::new(SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
        )))
    }

    /// Baseline eligibility: a Complete, Cancelled or Error scan may be
    /// deleted with or without a sweep outcome, and with tracked shielded
    /// accounts -- the source keys, not the workspace, hold spend authority.
    #[tokio::test]
    async fn finished_scans_delete_without_a_sweep_outcome() {
        for phase in [ScanPhase::Complete, ScanPhase::Cancelled, ScanPhase::Error] {
            let tempdir = tempfile::tempdir().unwrap();
            let (service, handle) =
                completed_session(tempdir.path(), seed_source(), transparent_account(5_000)).await;
            let session = service.session(&handle).await.unwrap();
            session.state.lock().await.progress.phase = phase;
            let root = session.workspace_root.clone();
            drop(session);
            let deleted = service
                .delete_workspace_with_observer(
                    &handle,
                    &mut FixedDeletionObserver(observe_transaction(vec![], None)),
                )
                .await
                .unwrap_or_else(|err| panic!("{phase:?}: {err}"));
            assert_eq!(deleted, root);
            assert!(!root.exists(), "{phase:?}");
        }
    }

    #[tokio::test]
    async fn unresolved_broadcast_blocks_deletion_until_observed_resolved() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) =
            completed_session(tempdir.path(), seed_source(), transparent_account(0)).await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let txid = TxId::from_bytes([91; 32]);
        let registry_path = {
            let guard =
                NetworkOperationGuard::acquire(tempdir.path(), ZeckNetwork::Mainnet).unwrap();
            let path = guard.broadcast_log_path().unwrap();
            let mut log = guard.open_broadcast_log().unwrap();
            log.persist_prepared(&PreparedTransaction {
                txid,
                raw_tx: vec![91],
                fee_zatoshis: 10_000,
                expiry_height: Some(130),
            })
            .unwrap();
            log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
            path
        };
        // Still unresolved after a fresh observation: refused.
        let err = service
            .delete_workspace_with_observer(
                &handle,
                &mut FixedDeletionObserver(observe_transaction(vec![], Some(130))),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&txid.to_string()), "{err}");
        assert!(root.exists());
        // One operator reports it mined: resolved, so deletion proceeds.
        let single = observe_transaction(
            vec![EndpointTxEvidence {
                operator_id: "zec.rocks".to_owned(),
                endpoint: "https://zec.rocks:443".to_owned(),
                tip_height: Some(125),
                reported_height: Some(120),
                block_hash: Some(vec![1; 32]),
                tx_in_block: true,
            }],
            Some(130),
        );
        service
            .delete_workspace_with_observer(&handle, &mut FixedDeletionObserver(single))
            .await
            .unwrap();
        assert!(!root.exists());
        // The network registry outlives the workspace.
        assert!(registry_path.is_file());
        let reopened = DurableBroadcastLog::open(&registry_path).unwrap();
        assert_eq!(
            reopened.latest(txid).unwrap().state,
            TxLifecycleState::MinedSingleSource
        );
    }

    async fn completed_mined_session(
        data_dir: &std::path::Path,
    ) -> (RecoveryService, ScanHandle, std::path::PathBuf, TxId) {
        let (service, handle) = completed_session(
            data_dir,
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let txid = TxId::from_bytes([84; 32]);
        let mut log = DurableBroadcastLog::open(registry_log_path(&root)).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![84, 85],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        let observation = crate::broadcast::observe_transaction(
            ["one", "two"]
                .into_iter()
                .map(|operator| crate::broadcast::EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(120),
                    reported_height: Some(120),
                    block_hash: Some(vec![1; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(130),
        );
        log.transition(txid, TxLifecycleState::Mined, None, Some(&observation))
            .unwrap();
        drop(log);
        service
            .last_sweep_outcomes
            .lock()
            .await
            .insert(handle.id.clone(), mined_outcome(txid.to_string()));
        (service, handle, root, txid)
    }

    #[tokio::test]
    async fn retry_rechecks_restored_root_journal_before_removing() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, _) = completed_mined_session(tempdir.path()).await;
        service
            .cleanup_retry
            .lock()
            .await
            .insert(root.clone(), root.clone());
        let added_txid = TxId::from_bytes([85; 32]);
        let raw = vec![85, 86, 87];
        let path = registry_log_path(&root);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid: added_txid,
            raw_tx: raw.clone(),
            fee_zatoshis: 10_000,
            expiry_height: Some(140),
        })
        .unwrap();
        log.transition(added_txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(log);

        assert!(service.delete_workspace(&handle).await.is_err());
        assert!(root.exists());
        assert!(service.session(&handle).await.is_ok());
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        assert_eq!(reopened.latest(added_txid).unwrap().prepared.raw_tx, raw);
        assert_eq!(
            reopened.latest(added_txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[tokio::test]
    async fn retry_rechecks_surviving_tombstone_journal_before_removing() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, _) = completed_mined_session(tempdir.path()).await;
        let tombstone = root.with_file_name("remaining.deleting-test");
        std::fs::rename(&root, &tombstone).unwrap();
        service
            .cleanup_retry
            .lock()
            .await
            .insert(root.clone(), tombstone.clone());
        let path = registry_log_path(&tombstone);
        let added_txid = TxId::from_bytes([86; 32]);
        let raw = vec![86, 87, 88];
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid: added_txid,
            raw_tx: raw.clone(),
            fee_zatoshis: 10_000,
            expiry_height: Some(140),
        })
        .unwrap();
        log.transition(added_txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        drop(log);

        assert!(service.delete_workspace(&handle).await.is_err());
        assert!(
            root.exists(),
            "the surviving tombstone must be restored for validation"
        );
        let reopened = DurableBroadcastLog::open(registry_log_path(&root)).unwrap();
        assert_eq!(reopened.latest(added_txid).unwrap().prepared.raw_tx, raw);
        assert_eq!(
            reopened.latest(added_txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[tokio::test]
    async fn durable_cleanup_marker_refuses_new_scan_after_service_restart() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, txid) = completed_mined_session(tempdir.path()).await;
        let session = service.session(&handle).await.unwrap();
        let runtime = session.runtime.clone();
        let marker = root.with_file_name(format!(
            "{}.cleanup-pending.json",
            root.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&marker, b"pending cleanup").unwrap();

        let restarted = RecoveryService::new();
        let result = restarted
            .start_scan_from_key_source(
                ScanConfig {
                    birthday: runtime.birthday,
                    num_accounts: runtime.num_accounts,
                    gap_limit: runtime.gap_limit,
                    transparent_scan: runtime.transparent_scan,
                    lightwalletd_url: runtime.lightwalletd_url.clone(),
                    confirmation_sources: runtime.confirmation_sources.clone(),
                    data_dir: runtime.data_dir.clone(),
                    network: runtime.network,
                    label: runtime.label.clone(),
                },
                runtime.key_source.clone(),
            )
            .await;
        if let Ok(ref started) = result {
            restarted.cancel_scan(started).await.unwrap();
        }
        assert!(
            result.is_err(),
            "a durable deletion marker must survive process restart"
        );
        let log = DurableBroadcastLog::open(registry_log_path(&root)).unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![84, 85]);
    }

    #[tokio::test]
    async fn restart_restores_tombstone_and_a_new_scan_may_delete_it() {
        use sha2::{Digest, Sha256};

        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, txid) = completed_mined_session(tempdir.path()).await;
        let root = root.canonicalize().unwrap();
        let runtime = service.session(&handle).await.unwrap().runtime.clone();
        let tombstone = root.with_file_name(format!(
            "{}.deleting-restart",
            root.file_name().unwrap().to_string_lossy()
        ));
        let marker = super::cleanup_marker_path(&root).unwrap();
        std::fs::write(
            &marker,
            serde_json::json!({
                "workspace": root,
                "tombstone": tombstone,
                "receipts": [{
                    "txid": txid.to_string(),
                    "raw_sha256": format!("{:x}", Sha256::digest([84, 85])),
                }],
            })
            .to_string(),
        )
        .unwrap();
        std::fs::rename(&root, &tombstone).unwrap();

        let restarted = RecoveryService::new();
        let started = restarted
            .start_scan_from_key_source(
                ScanConfig {
                    birthday: runtime.birthday,
                    num_accounts: runtime.num_accounts,
                    gap_limit: runtime.gap_limit,
                    transparent_scan: runtime.transparent_scan,
                    lightwalletd_url: runtime.lightwalletd_url.clone(),
                    confirmation_sources: runtime.confirmation_sources.clone(),
                    data_dir: runtime.data_dir.clone(),
                    network: runtime.network,
                    label: runtime.label.clone(),
                },
                runtime.key_source.clone(),
            )
            .await
            .expect("a verified tombstone should be recoverable for a fresh scan");
        assert!(root.exists());
        assert!(!tombstone.exists());
        assert!(!marker.exists());
        assert!(restarted
            .last_sweep_outcomes
            .lock()
            .await
            .get(&started.id)
            .is_none());
        restarted.cancel_scan(&started).await.unwrap();
        let guard =
            super::NetworkOperationGuard::acquire(&runtime.data_dir, runtime.network).unwrap();
        let log = guard.open_broadcast_log().unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![84, 85]);
        drop(log);
        drop(guard);
        restarted
            .session(&started)
            .await
            .unwrap()
            .state
            .lock()
            .await
            .progress
            .phase = ScanPhase::Complete;
        // The fresh scan carries no old outcome; with every broadcast
        // resolved, it may be deleted, and the registry receipt survives.
        restarted
            .delete_workspace_with_observer(
                &started,
                &mut FixedDeletionObserver(mined_deletion_observation()),
            )
            .await
            .unwrap();
        assert!(!root.exists());
        let guard =
            super::NetworkOperationGuard::acquire(&runtime.data_dir, runtime.network).unwrap();
        let log = guard.open_broadcast_log().unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![84, 85]);
    }

    #[tokio::test]
    async fn restart_without_registry_receipt_requires_manual_recovery() {
        use sha2::{Digest, Sha256};

        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, _) = completed_mined_session(tempdir.path()).await;
        let root = root.canonicalize().unwrap();
        let runtime = service.session(&handle).await.unwrap().runtime.clone();
        let tombstone = root.with_file_name(format!(
            "{}.deleting-restart-missing",
            root.file_name().unwrap().to_string_lossy()
        ));
        // The marker binds a receipt the registry never recorded.
        let missing = TxId::from_bytes([0xEE; 32]);
        let marker = super::cleanup_marker_path(&root).unwrap();
        std::fs::write(
            &marker,
            serde_json::json!({
                "workspace": root,
                "tombstone": tombstone,
                "receipts": [{
                    "txid": missing.to_string(),
                    "raw_sha256": format!("{:x}", Sha256::digest([84, 85])),
                }],
            })
            .to_string(),
        )
        .unwrap();
        std::fs::rename(&root, &tombstone).unwrap();

        let restarted = RecoveryService::new();
        let error = restarted
            .start_scan_from_key_source(
                ScanConfig {
                    birthday: runtime.birthday,
                    num_accounts: runtime.num_accounts,
                    gap_limit: runtime.gap_limit,
                    transparent_scan: runtime.transparent_scan,
                    lightwalletd_url: runtime.lightwalletd_url.clone(),
                    confirmation_sources: runtime.confirmation_sources.clone(),
                    data_dir: runtime.data_dir.clone(),
                    network: runtime.network,
                    label: runtime.label.clone(),
                },
                runtime.key_source.clone(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("manual recovery"), "{error}");
        assert!(
            root.exists(),
            "surviving tombstone remains available for inspection"
        );
        assert!(marker.exists());
    }

    #[tokio::test]
    async fn another_service_cannot_delete_while_scan_owns_workspace() {
        let tempdir = tempfile::tempdir().unwrap();
        let (deleter, handle, root, txid) = completed_mined_session(tempdir.path()).await;
        let runtime = deleter.session(&handle).await.unwrap().runtime.clone();
        let scanner = RecoveryService::new();
        let scanning = scanner
            .start_scan_from_key_source(
                ScanConfig {
                    birthday: runtime.birthday,
                    num_accounts: runtime.num_accounts,
                    gap_limit: runtime.gap_limit,
                    transparent_scan: runtime.transparent_scan,
                    lightwalletd_url: runtime.lightwalletd_url.clone(),
                    confirmation_sources: runtime.confirmation_sources.clone(),
                    data_dir: runtime.data_dir.clone(),
                    network: runtime.network,
                    label: runtime.label.clone(),
                },
                runtime.key_source.clone(),
            )
            .await
            .unwrap();
        let result = deleter.delete_workspace(&handle).await;
        assert!(
            result.is_err(),
            "the other service's live scan must exclude deletion"
        );
        assert!(root.exists());
        scanner.cancel_scan(&scanning).await.unwrap();
        let log = DurableBroadcastLog::open(registry_log_path(&root)).unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![84, 85]);
    }

    #[tokio::test]
    async fn different_birthday_scan_excludes_deletion_in_same_network_registry() {
        let tempdir = tempfile::tempdir().unwrap();
        let (deleter, handle, root, txid) = completed_mined_session(tempdir.path()).await;
        let runtime = deleter.session(&handle).await.unwrap().runtime.clone();
        let scanner = RecoveryService::new();
        let scanning = scanner
            .start_scan_from_key_source(
                ScanConfig {
                    birthday: runtime.birthday + 1,
                    num_accounts: runtime.num_accounts,
                    gap_limit: runtime.gap_limit,
                    transparent_scan: runtime.transparent_scan,
                    lightwalletd_url: runtime.lightwalletd_url.clone(),
                    confirmation_sources: runtime.confirmation_sources.clone(),
                    data_dir: runtime.data_dir.clone(),
                    network: runtime.network,
                    label: runtime.label.clone(),
                },
                runtime.key_source.clone(),
            )
            .await
            .unwrap();
        let result = deleter.delete_workspace(&handle).await;
        assert!(
            result.is_err(),
            "another scan scope must share the network operation lock"
        );
        assert!(root.exists());
        scanner.cancel_scan(&scanning).await.unwrap();
        let log = DurableBroadcastLog::open(registry_log_path(&root)).unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![84, 85]);
    }

    #[tokio::test]
    async fn resolved_mined_receipt_deletes_without_a_fresh_observation() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, txid) = completed_mined_session(tempdir.path()).await;
        // The session's lightwalletd is unroutable: a resolved receipt must
        // not need it.
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            service.delete_workspace(&handle),
        )
        .await
        .expect("no network call for a resolved receipt")
        .unwrap();
        assert!(!root.exists());
        let registry_path =
            super::network_broadcast_log_path(tempdir.path(), ZeckNetwork::Mainnet).unwrap();
        let log = DurableBroadcastLog::open(registry_path).unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![84, 85]);
        assert_eq!(log.latest(txid).unwrap().state, TxLifecycleState::Mined);
    }

    #[tokio::test]
    async fn deletion_observes_unresolved_receipts_omitted_from_gui_outcome() {
        struct PerTransactionObserver {
            seen: Vec<TxId>,
        }
        #[async_trait::async_trait]
        impl TxObserver for PerTransactionObserver {
            async fn observe(
                &mut self,
                _network: ZeckNetwork,
                txid: TxId,
                _expiry_height: Option<u32>,
            ) -> ZeckResult<TxObservation> {
                self.seen.push(txid);
                Ok(crate::broadcast::observe_transaction(
                    vec![crate::broadcast::EndpointTxEvidence {
                        operator_id: "one".to_owned(),
                        endpoint: "https://one.example".to_owned(),
                        tip_height: Some(121),
                        reported_height: Some(0),
                        block_hash: None,
                        tx_in_block: false,
                    }],
                    Some(130),
                ))
            }
        }

        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, original) = completed_mined_session(tempdir.path()).await;
        let extra = TxId::from_bytes([97; 32]);
        let path = registry_log_path(&root);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid: extra,
            raw_tx: vec![97, 98],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(extra, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            extra,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        drop(log);

        let mut observer = PerTransactionObserver { seen: Vec::new() };
        let err = service
            .delete_workspace_with_observer(&handle, &mut observer)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&extra.to_string()), "{err}");
        // Only the unresolved receipt is observed; the mined one is resolved.
        assert_eq!(observer.seen, vec![extra]);
        assert!(root.exists());
        let registry_path =
            super::network_broadcast_log_path(tempdir.path(), ZeckNetwork::Mainnet).unwrap();
        let registry = DurableBroadcastLog::open(registry_path).unwrap();
        assert_eq!(
            registry.latest(original).unwrap().state,
            TxLifecycleState::Mined
        );
        assert_eq!(
            registry.latest(extra).unwrap().state,
            TxLifecycleState::Pending
        );
    }

    #[tokio::test]
    async fn deletion_accepts_new_canonical_mining_evidence_before_removal() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle, root, _) = completed_mined_session(tempdir.path()).await;
        let deleted = service
            .delete_workspace_with_observer(
                &handle,
                &mut FixedDeletionObserver(mined_deletion_observation()),
            )
            .await
            .unwrap();
        assert_eq!(deleted, root);
        assert!(!root.exists());
    }

    #[cfg(feature = "argos-network")]
    #[tokio::test]
    async fn transparent_funds_reported_elsewhere_do_not_pin_a_resolved_workspace() {
        use super::deletion_fake_lightwalletd::FakeLightwalletd;
        use crate::models::ConfirmationEndpoint;
        use zcash_client_backend::proto::service::GetAddressUtxosReply;

        let mut keys = argos_wallet_import::ImportedKeys::default();
        keys.transparent.push(TransparentKey {
            secret: Secret::new([0x42; 32]),
            provenance: Provenance::Standalone,
            created_at: None,
        });
        let address = crate::imported::encode_transparent_address(
            &crate::imported::imported_transparent_keys(&keys).unwrap()[0].address,
            ZeckNetwork::Testnet,
        );
        let primary = FakeLightwalletd::builder()
            .chain_name("test")
            .sapling_activation_height(280_000)
            .block_height(3_500_000)
            .scripted_address_utxos(vec![])
            .build()
            .await
            .unwrap();
        let secondary = FakeLightwalletd::builder()
            .chain_name("test")
            .sapling_activation_height(280_000)
            .block_height(3_500_000)
            .scripted_address_utxos(vec![GetAddressUtxosReply {
                address,
                txid: vec![0x44; 32],
                index: 0,
                script: Vec::new(),
                value_zat: 250_000,
                height: 3_500_000,
            }])
            .build()
            .await
            .unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let runtime = RuntimeScanConfig {
            key_source: Arc::new(ImportedKeySource::new(keys)),
            birthday: 1_000_000,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: primary.url.clone(),
            confirmation_sources: vec![
                ConfirmationEndpoint {
                    operator_id: "primary".to_owned(),
                    endpoint: primary.url.clone(),
                },
                ConfirmationEndpoint {
                    operator_id: "secondary".to_owned(),
                    endpoint: secondary.url.clone(),
                },
            ],
            data_dir: tempdir.path().to_owned(),
            network: ZeckNetwork::Testnet,
            label: "two source deletion".to_owned(),
        };
        let (service, handle) =
            completed_session_from_runtime(runtime, transparent_account(0)).await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let txid = TxId::from_bytes([91; 32]);
        let path = registry_log_path(&root);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![91, 92],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        log.transition(
            txid,
            TxLifecycleState::Mined,
            None,
            Some(&mined_deletion_observation()),
        )
        .unwrap();
        drop(log);
        service
            .last_sweep_outcomes
            .lock()
            .await
            .insert(handle.id.clone(), mined_outcome(txid.to_string()));

        // Standalone transparent funds that a secondary still reports stay
        // spendable from the source wallet file, not from this workspace.
        // With every broadcast resolved, deletion proceeds; the registry
        // keeps the receipt.
        service
            .delete_workspace_with_observer(
                &handle,
                &mut FixedDeletionObserver(mined_deletion_observation()),
            )
            .await
            .unwrap();
        assert!(!root.exists());
        let registry_path =
            super::network_broadcast_log_path(tempdir.path(), ZeckNetwork::Testnet).unwrap();
        let log = DurableBroadcastLog::open(registry_path).unwrap();
        assert_eq!(log.latest(txid).unwrap().prepared.raw_tx, vec![91, 92]);
        drop((primary, secondary));
    }

    #[tokio::test]
    async fn gui_mined_result_without_matching_durable_history_cannot_delete() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        service
            .last_sweep_outcomes
            .lock()
            .await
            .insert(handle.id.clone(), mined_outcome("unrecorded-tx".to_owned()));
        assert!(service.delete_workspace(&handle).await.is_err());
        assert!(service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .exists());
    }

    #[tokio::test]
    async fn active_workspace_operation_refuses_delete_without_waiting() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let _operation = service.workspace_gate(&root).lock_owned().await;
        assert!(service.delete_workspace(&handle).await.is_err());
        assert!(root.exists());
    }

    #[tokio::test]
    async fn durable_unknown_and_raw_transaction_survive_refused_concurrent_delete() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let path = registry_log_path(&root);
        let txid = TxId::from_bytes([71; 32]);
        let raw = vec![71, 72, 73];
        let (unknown_written, unknown_seen) = tokio::sync::oneshot::channel();
        let resume = Arc::new(tokio::sync::Notify::new());
        let service_for_sweep = service.clone();
        let root_for_sweep = root.clone();
        let path_for_sweep = path.clone();
        let raw_for_sweep = raw.clone();
        let resume_sweep = resume.clone();
        let sweep = tokio::spawn(async move {
            // This is the same workspace guard held by execute_sweep_inner.
            // Pause at the exact durable pre-submission boundary.
            let _guard = service_for_sweep
                .workspace_gate(&root_for_sweep)
                .lock_owned()
                .await;
            let mut log = DurableBroadcastLog::open(&path_for_sweep).unwrap();
            log.persist_prepared(&PreparedTransaction {
                txid,
                raw_tx: raw_for_sweep,
                fee_zatoshis: 10_000,
                expiry_height: Some(130),
            })
            .unwrap();
            log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
                .unwrap();
            unknown_written.send(()).unwrap();
            resume_sweep.notified().await;
        });
        unknown_seen.await.unwrap();
        let service_for_delete = service.clone();
        let handle_for_delete = handle.clone();
        let refusal = tokio::spawn(async move {
            service_for_delete
                .delete_workspace(&handle_for_delete)
                .await
        })
        .await
        .unwrap();
        assert!(refusal.is_err());
        assert!(root.exists());
        resume.notify_one();
        sweep.await.unwrap();
        assert!(service.delete_workspace(&handle).await.is_err());
        let reopened = DurableBroadcastLog::open(&path).unwrap();
        let persisted = reopened.latest(txid).unwrap();
        assert_eq!(persisted.prepared.raw_tx, raw);
        assert_eq!(persisted.state, TxLifecycleState::SubmissionUnknown);
    }

    #[tokio::test]
    async fn deletion_requires_resolved_history_not_a_clean_outcome() {
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let path = registry_log_path(&root);
        let txid = TxId::from_bytes([72; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![72],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        drop(log);
        service
            .last_sweep_outcomes
            .lock()
            .await
            .insert(handle.id.clone(), mined_outcome(txid.to_string()));
        assert!(
            service.delete_workspace(&handle).await.is_err(),
            "GUI result cannot override pending history"
        );
        let registry_path =
            super::network_broadcast_log_path(tempdir.path(), ZeckNetwork::Mainnet).unwrap();
        let mut log = DurableBroadcastLog::open(&registry_path).unwrap();
        let observation = crate::broadcast::observe_transaction(
            ["one", "two"]
                .into_iter()
                .map(|operator| crate::broadcast::EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(120),
                    reported_height: Some(120),
                    block_hash: Some(vec![1; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(130),
        );
        log.transition(txid, TxLifecycleState::Mined, None, Some(&observation))
            .unwrap();
        drop(log);
        service
            .last_sweep_outcomes
            .lock()
            .await
            .get_mut(&handle.id)
            .unwrap()
            .skipped_accounts
            .push(crate::models::SkippedSweepAccount {
                account_index: 1,
                gross_zatoshis: 1,
                reason: "remaining".to_owned(),
            });
        // A skipped balance stays spendable from the source keys; it does not
        // pin the workspace once every broadcast is resolved.
        let deleted = service
            .delete_workspace_with_observer(
                &handle,
                &mut FixedDeletionObserver(mined_deletion_observation()),
            )
            .await
            .unwrap();
        assert_eq!(deleted, root);
        assert!(!root.exists());
        assert!(service.session(&handle).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_workspace_removal_restores_retryable_session_path() {
        use std::os::unix::fs::PermissionsExt;
        let tempdir = tempfile::tempdir().unwrap();
        let (service, handle) = completed_session(
            tempdir.path(),
            Arc::new(SeedKeySource::new(SecretString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
            ))),
            transparent_account(0),
        )
        .await;
        let root = service
            .session(&handle)
            .await
            .unwrap()
            .workspace_root
            .clone();
        let path = registry_log_path(&root);
        let txid = TxId::from_bytes([73; 32]);
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![73],
            fee_zatoshis: 10_000,
            expiry_height: Some(130),
        })
        .unwrap();
        log.transition(txid, TxLifecycleState::SubmissionUnknown, None, None)
            .unwrap();
        log.transition(
            txid,
            TxLifecycleState::Pending,
            Some(&SubmissionDisposition::Accepted),
            None,
        )
        .unwrap();
        let observation = crate::broadcast::observe_transaction(
            ["one", "two"]
                .into_iter()
                .map(|operator| crate::broadcast::EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(120),
                    reported_height: Some(120),
                    block_hash: Some(vec![1; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(130),
        );
        log.transition(txid, TxLifecycleState::Mined, None, Some(&observation))
            .unwrap();
        drop(log);
        service
            .last_sweep_outcomes
            .lock()
            .await
            .insert(handle.id.clone(), mined_outcome(txid.to_string()));
        let locked = root.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("keep"), b"secret").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = service
            .delete_workspace_with_observer(
                &handle,
                &mut FixedDeletionObserver(mined_deletion_observation()),
            )
            .await;
        let tombstone = std::fs::read_dir(root.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&format!(
                        "{}.deleting-",
                        root.file_name().unwrap().to_string_lossy()
                    ))
            });
        let locked_after = if root.exists() {
            root.join("locked")
        } else {
            tombstone.as_ref().unwrap().join("locked")
        };
        std::fs::set_permissions(&locked_after, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert!(
            root.exists(),
            "failed removal must restore the original path for retry"
        );
        assert!(service.session(&handle).await.is_ok());
        assert!(root.join("locked/keep").exists());
        assert!(service
            .delete_workspace_with_observer(
                &handle,
                &mut FixedDeletionObserver(mined_deletion_observation()),
            )
            .await
            .is_ok());
    }
}

/// Each per-leg reviewed-fee check compares the fee captured at review with
/// the leg actually about to be built, and each is pinned here: removing the
/// check changes the error these tests see.
#[cfg(test)]
pub(crate) mod leg_fee_pin_tests {
    use super::*;
    use crate::models::ZeckNetwork;
    use std::collections::BTreeMap;
    use zcash_client_backend::{
        fees::{ChangeValue, TransactionBalance},
        proposal::Proposal,
        wallet::WalletTransparentOutput,
        zip321::TransactionRequest,
    };
    use zcash_transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
    };

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A structurally valid one-input shielding proposal with the given fee,
    /// built offline. Only the fee and change differ between two calls, so
    /// two proposals can share every local input identity.
    pub(crate) fn offline_proposal<N>(fee: u64) -> Proposal<StandardFeeRule, N> {
        let address = TransparentAddress::PublicKeyHash([7; 20]);
        let txout = TxOut::new(Zatoshis::const_from_u64(100_000), address.script().into());
        let input = WalletTransparentOutput::<()>::from_parts(
            OutPoint::new([3; 32], 0),
            txout,
            Some(BlockHeight::from_u32(1)),
            None,
            None,
            None,
        )
        .expect("P2PKH output");
        let balance = TransactionBalance::new(
            vec![ChangeValue::sapling(
                Zatoshis::from_u64(100_000 - fee).unwrap(),
                None,
            )],
            Zatoshis::from_u64(fee).unwrap(),
        )
        .unwrap();
        Proposal::single_step(
            TransactionRequest::empty(),
            BTreeMap::new(),
            vec![input],
            None,
            BlockHeight::from_u32(1),
            balance,
            StandardFeeRule::Zip317,
            BlockHeight::from_u32(2).into(),
            ConfirmationsPolicy::MIN,
            true,
            false,
        )
        .expect("offline proposal")
    }

    fn hd_account() -> TrackedAccount {
        let derived = crate::derive_accounts(
            &secrecy::SecretString::new(PHRASE.to_owned()),
            ZeckNetwork::Mainnet,
            1,
        )
        .unwrap()
        .remove(0);
        TrackedAccount {
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
            derived,
            transparent_receivers: Vec::new(),
            spend_authority: TrackedSpendAuthority::Hd { zip32_index: 0 },
            standalone_transparent_receivers: Vec::new(),
            transparent_key_coordinates: Vec::new(),
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        workspace: RecoveryWorkspace,
        log: DurableBroadcastLog,
        seed: [u8; 64],
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let key_source: Arc<dyn KeySource> = Arc::new(SeedKeySource::new(
            secrecy::SecretString::new(PHRASE.to_owned()),
        ));
        let runtime = RuntimeScanConfig {
            key_source: key_source.clone(),
            birthday: 1_000_000,
            num_accounts: Some(1),
            gap_limit: 1,
            transparent_scan: None,
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let workspace = RecoveryWorkspace::from_runtime(&runtime).unwrap();
        workspace
            .initialize_from_source(runtime.network, key_source.as_ref())
            .unwrap();
        let log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let seed = key_source.wallet_seed().unwrap().unwrap();
        Fixture {
            _dir: dir,
            workspace,
            log,
            seed,
        }
    }

    fn offline_client() -> CompactTxStreamerClient<tonic::transport::Channel> {
        CompactTxStreamerClient::new(
            tonic::transport::Channel::from_static("http://127.0.0.1:1").connect_lazy(),
        )
    }

    #[tokio::test]
    async fn shield_leg_compares_reviewed_fee_before_the_cap() {
        let mut fx = fixture();
        let proposal = offline_proposal::<Infallible>(15_000);
        let mut client = offline_client();
        let prover = LocalTxProver::bundled();
        let mut results = Vec::new();
        let tracked = hd_account();
        let network = consensus_network(ZeckNetwork::Mainnet);
        let usk =
            UnifiedSpendingKey::from_seed(&network, &fx.seed, zip32::AccountId::ZERO).unwrap();
        let transparent_account =
            legacy_transparent_account_key_from_seed(ZeckNetwork::Mainnet, &fx.seed).unwrap();
        let mut ctx = SweepStepCtx {
            workspace: &fx.workspace,
            network: ZeckNetwork::Mainnet,
            client: &mut client,
            prover: &prover,
            results: &mut results,
            broadcast_log: &mut fx.log,
            prior_fee_zatoshis: 0,
            // Below the built fee: the cap must not mask a changed fee.
            max_fee_zatoshis: Some(1),
            reviewed_fee_zatoshis: 10_000,
            lightwalletd_url: "https://127.0.0.1:1",
            confirmation_sources: &[],
        };
        let result =
            execute_shielding_step(&mut ctx, &tracked, &transparent_account, &usk, &proposal).await;
        assert!(
            matches!(
                result,
                Err(ZeckError::FeeQuoteChanged {
                    reviewed: 10_000,
                    current: 15_000
                })
            ),
            "{result:?}"
        );
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn send_leg_compares_reviewed_fee_before_the_cap() {
        let mut fx = fixture();
        let proposal = offline_proposal::<zcash_client_sqlite::ReceivedNoteId>(15_000);
        let mut client = offline_client();
        let prover = LocalTxProver::bundled();
        let mut results = Vec::new();
        let tracked = hd_account();
        let network = consensus_network(ZeckNetwork::Mainnet);
        let usk =
            UnifiedSpendingKey::from_seed(&network, &fx.seed, zip32::AccountId::ZERO).unwrap();
        let mut ctx = SweepStepCtx {
            workspace: &fx.workspace,
            network: ZeckNetwork::Mainnet,
            client: &mut client,
            prover: &prover,
            results: &mut results,
            broadcast_log: &mut fx.log,
            prior_fee_zatoshis: 0,
            max_fee_zatoshis: Some(1),
            reviewed_fee_zatoshis: 10_000,
            lightwalletd_url: "https://127.0.0.1:1",
            confirmation_sources: &[],
        };
        let result = execute_send_max_step(&mut ctx, &tracked, &usk, &proposal, 0).await;
        assert!(
            matches!(
                result,
                Err(ZeckError::FeeQuoteChanged {
                    reviewed: 10_000,
                    current: 15_000
                })
            ),
            "{result:?}"
        );
        assert!(results.is_empty());
    }

    fn plan_with_leg_fee(fee: u64) -> ExactSweepPlan {
        let proposal = offline_proposal::<Infallible>(fee);
        let quote = SweepProposal {
            transactions: vec![ProposedTx {
                kind: ProposedTxKind::ShieldTransparent,
                leg_kind: crate::models::ProposedLegKind::Wallet,
                source_account: 0,
                destination: "u-test".to_owned(),
                gross_zatoshis: 100_000,
                fee_zatoshis: fee,
                net_zatoshis: 100_000 - fee,
                donation_zatoshis: 0,
                note: String::new(),
                memo: None,
            }],
            donation_note: None,
            skipped_accounts: Vec::new(),
            total_send_zatoshis: 100_000,
            total_fee_zatoshis: fee,
            net_received_zatoshis: 0,
            total_donation_zatoshis: 0,
            dry_run_default: true,
            warning: None,
            follow_up_review_required: true,
            confirmation_notice: None,
        };
        ExactSweepPlan {
            quote,
            legs: vec![ExactSweepLeg::HdShield {
                account_index: 0,
                proposal,
            }],
            direct_account_index: None,
            network: ZeckNetwork::Mainnet,
        }
    }

    fn intent_for(plan: &ExactSweepPlan) -> ReviewedSweepIntent {
        let fx_dir = tempfile::tempdir().unwrap();
        let key_source: Arc<dyn KeySource> = Arc::new(SeedKeySource::new(
            secrecy::SecretString::new(PHRASE.to_owned()),
        ));
        let runtime = RuntimeScanConfig {
            key_source: key_source.clone(),
            birthday: 1_000_000,
            num_accounts: Some(1),
            gap_limit: 1,
            transparent_scan: None,
            lightwalletd_url: "https://127.0.0.1:1".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: fx_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let handle = crate::models::ScanHandle::new();
        let session = ScanSession {
            source_fingerprint: key_source.fingerprint().unwrap(),
            state: Arc::new(Mutex::new(crate::scan::ScanTaskState::new(handle.clone()))),
            workspace_root: fx_dir.path().to_owned(),
            runtime,
            started_at: Instant::now(),
            task: Mutex::new(None),
            reviewed_sweeps: Mutex::new(ReviewedSweepStore::default()),
        };
        let progress = ScanProgress {
            ..crate::scan::ScanTaskState::new(handle).progress
        };
        let mut intent = ReviewedSweepIntent::capture(
            SweepRequest {
                destination: "u-test".to_owned(),
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
            &session,
            &progress,
        );
        intent.bind_plan(plan).unwrap();
        intent
    }

    #[test]
    fn executed_fee_change_is_fee_quote_changed_not_max_fee_exceeded() {
        let reviewed = plan_with_leg_fee(10_000);
        let intent = intent_for(&reviewed);
        // A blank cap was bound to the reviewed total, so a higher executed
        // fee would also exceed the cap; the fee change must be reported.
        assert_eq!(intent.request.max_fee_zatoshis, Some(10_000));
        let current = plan_with_leg_fee(15_000);
        assert!(matches!(
            intent.authorize_current_plan(&current),
            Err(ZeckError::FeeQuoteChanged {
                reviewed: 10_000,
                current: 15_000
            })
        ));
        // The same plan authorizes, returning the fees captured at review.
        let fees = intent.authorize_current_plan(&reviewed).unwrap();
        assert_eq!(fees.require(ExactFeeKey::HdShield(0)).unwrap(), 10_000);
    }

    #[test]
    fn reviewed_leg_fees_come_from_the_reviewed_plan() {
        let intent = intent_for(&plan_with_leg_fee(10_000));
        let fees = intent.reviewed_leg_fees.as_ref().unwrap();
        assert_eq!(fees.require(ExactFeeKey::HdShield(0)).unwrap(), 10_000);
        assert!(fees.require(ExactFeeKey::HdSend(0)).is_err());
    }

    #[test]
    fn canonical_identity_binds_the_protobuf_proposal() {
        // Same single transparent input, same version; only the fee and the
        // change value (carried by the protobuf proposal) differ.
        let a = offline_proposal::<Infallible>(10_000);
        let b = offline_proposal::<Infallible>(15_000);
        assert_ne!(
            canonical_proposal(&a, ZeckNetwork::Mainnet),
            canonical_proposal(&b, ZeckNetwork::Mainnet)
        );
        assert_eq!(
            canonical_proposal(&a, ZeckNetwork::Mainnet),
            canonical_proposal(
                &offline_proposal::<Infallible>(10_000),
                ZeckNetwork::Mainnet
            )
        );
    }

    #[test]
    fn a_reviewed_leg_without_an_executable_account_fails_closed() {
        let plan = plan_with_leg_fee(10_000);
        assert!(hd_leg_plan(&plan.legs, &[hd_account()]).is_ok());
        assert!(matches!(
            hd_leg_plan(&plan.legs, &[]),
            Err(ZeckError::StaleSweepProposal(message)) if message.contains("nothing was signed")
        ));
        let mut imported = hd_account();
        imported.spend_authority = TrackedSpendAuthority::ImportedSapling {
            key_index: 0,
            wallet_account_id: zcash_client_sqlite::AccountUuid::default(),
        };
        assert!(matches!(
            hd_leg_plan(&plan.legs, &[imported]),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }
}

/// Leg-to-leg gating through the real submission and confirmation loop,
/// against a scripted node and observer. Wallet-backed construction of the
/// legs is covered by the regtest suite; these pin the broadcast policy.
#[cfg(test)]
mod leg_gating_tests {
    use super::*;
    use crate::broadcast::{EndpointTxEvidence, TxObservation, TxSubmitter};
    use crate::models::ZeckNetwork;
    use zcash_client_backend::proto::service::SendResponse;
    use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
    use zcash_protocol::consensus::BranchId;

    fn prepared(expiry: u32) -> PreparedTransaction {
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(expiry),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let mut raw_tx = Vec::new();
        tx.write(&mut raw_tx).unwrap();
        PreparedTransaction {
            txid: tx.txid(),
            raw_tx,
            fee_zatoshis: 10_000,
            expiry_height: Some(expiry),
        }
    }

    #[derive(Default)]
    struct Node {
        sent: Vec<Vec<u8>>,
        lose_reply_for: Option<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl TxSubmitter for Node {
        async fn send_raw(&mut self, raw: Vec<u8>) -> Result<SendResponse, tonic::Status> {
            self.sent.push(raw.clone());
            if self.lose_reply_for.as_ref() == Some(&raw) {
                return Err(tonic::Status::unavailable("GoAway"));
            }
            Ok(SendResponse {
                error_code: 0,
                error_message: String::new(),
            })
        }
    }

    /// The default configuration: zec.rocks and na.zec.rocks, one operator.
    fn default_operator_mined(height: u32) -> TxObservation {
        crate::broadcast::observe_transaction(
            ["https://zec.rocks:443", "https://na.zec.rocks:443"]
                .into_iter()
                .map(|endpoint| EndpointTxEvidence {
                    operator_id: "zec.rocks".to_owned(),
                    endpoint: endpoint.to_owned(),
                    tip_height: Some(height + 2),
                    reported_height: Some(height),
                    block_hash: Some(vec![5; 32]),
                    tx_in_block: true,
                })
                .collect(),
            Some(500),
        )
    }

    /// Observes each txid with the scripted result, Unavailable otherwise.
    struct Observer(HashMap<TxId, TxObservation>);

    #[async_trait::async_trait]
    impl TxObserver for Observer {
        async fn observe(
            &mut self,
            _network: ZeckNetwork,
            txid: TxId,
            expiry_height: Option<u32>,
        ) -> ZeckResult<TxObservation> {
            Ok(self
                .0
                .get(&txid)
                .cloned()
                .unwrap_or_else(|| crate::broadcast::observe_transaction(vec![], expiry_height)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn second_account_broadcasts_while_the_first_is_still_pending() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let (first, second) = (prepared(300), prepared(301));
        let mut node = Node::default();
        let mut observer = Observer(HashMap::new());
        let mut results = Vec::new();
        let mut mined = Vec::new();
        let mut mark = |txid: TxId, height: u32| {
            mined.push((txid, height));
            Ok(())
        };
        submit_and_confirm_batch(
            vec![first.clone()],
            0,
            "sweep",
            &mut results,
            &mut log,
            &mut node,
            &mut observer,
            ZeckNetwork::Mainnet,
            &mut mark,
        )
        .await
        .unwrap();
        assert_eq!(results[0].status, TxLifecycleState::Pending);
        submit_and_confirm_batch(
            vec![second.clone()],
            1,
            "sweep",
            &mut results,
            &mut log,
            &mut node,
            &mut observer,
            ZeckNetwork::Mainnet,
            &mut mark,
        )
        .await
        .expect("an accepted earlier leg does not block a later one");
        assert_eq!(node.sent, vec![first.raw_tx, second.raw_tx]);
        assert_eq!(
            results
                .iter()
                .map(|row| row.source_account)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(mined.is_empty());
        // Both remain unresolved for a NEW review.
        assert!(log.has_unresolved_history());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_reply_blocks_the_next_leg() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let (first, second) = (prepared(300), prepared(301));
        let mut node = Node {
            lose_reply_for: Some(first.raw_tx.clone()),
            ..Node::default()
        };
        let mut observer = Observer(HashMap::new());
        let mut results = Vec::new();
        let mut mark = |_: TxId, _: u32| Ok(());
        assert!(submit_and_confirm_batch(
            vec![first.clone()],
            0,
            "sweep",
            &mut results,
            &mut log,
            &mut node,
            &mut observer,
            ZeckNetwork::Mainnet,
            &mut mark,
        )
        .await
        .is_err());
        assert_eq!(results[0].status, TxLifecycleState::SubmissionUnknown);
        assert!(submit_and_confirm_batch(
            vec![second],
            1,
            "sweep",
            &mut results,
            &mut log,
            &mut node,
            &mut observer,
            ZeckNetwork::Mainnet,
            &mut mark,
        )
        .await
        .is_err());
        assert_eq!(node.sent, vec![first.raw_tx]);
    }

    #[tokio::test(start_paused = true)]
    async fn shield_then_send_completes_under_the_default_single_operator() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap();
        let (shield, send) = (prepared(300), prepared(301));
        let mut node = Node::default();
        let mut observer = Observer(HashMap::from([
            (shield.txid, default_operator_mined(120)),
            (send.txid, default_operator_mined(125)),
        ]));
        let mut results = Vec::new();
        let mut mined = Vec::new();
        let mut mark = |txid: TxId, height: u32| {
            mined.push((txid, height));
            Ok(())
        };
        submit_and_confirm_batch(
            vec![shield.clone()],
            0,
            "shielding",
            &mut results,
            &mut log,
            &mut node,
            &mut observer,
            ZeckNetwork::Mainnet,
            &mut mark,
        )
        .await
        .unwrap();
        assert_eq!(results[0].status, TxLifecycleState::MinedSingleSource);
        // The execution-start gate for the follow-up review now passes.
        assert!(!log.has_unresolved_history());
        submit_and_confirm_batch(
            vec![send.clone()],
            0,
            "sweep",
            &mut results,
            &mut log,
            &mut node,
            &mut observer,
            ZeckNetwork::Mainnet,
            &mut mark,
        )
        .await
        .unwrap();
        assert_eq!(results[1].status, TxLifecycleState::MinedSingleSource);
        assert_eq!(mined, vec![(shield.txid, 120), (send.txid, 125)]);
        assert!(results.iter().all(|row| !row.safe_to_discard));
        assert!(!log.has_unresolved_history());
        assert_eq!(node.sent, vec![shield.raw_tx, send.raw_tx]);
    }
}

/// ZIP-317 fee fidelity without a funded chain: the fee the proposal path
/// quotes (Argos's own change strategy, and the transparent planner) equals
/// the fee of the transaction the builder actually produces, including the
/// padded single-output case (one Sapling output is billed as two, per
/// `BundleType::num_outputs`). The wallet-backed equivalents
/// (`multi_note_shielded_quote_uses_real_zip317_fee` and friends) need the
/// funded regtest harness and are `#[ignore]`d.
#[cfg(test)]
mod zip317_fee_fidelity_tests {
    use super::*;
    use crate::models::ZeckNetwork;
    use rand_core::OsRng;
    use sapling_crypto as sapling;
    use zcash_client_backend::fees::{ChangeStrategy, ChangeValue};
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, BundlePadding},
        fees::zip317::FeeRule,
    };
    use zcash_protocol::{
        consensus::{NetworkUpgrade, Parameters},
        memo::MemoBytes,
    };

    struct Spend(u32, Zatoshis);

    impl zcash_client_backend::fees::sapling::InputView<u32> for Spend {
        fn note_id(&self) -> &u32 {
            &self.0
        }
        fn value(&self) -> Zatoshis {
            self.1
        }
    }

    fn zip317(logical_actions: usize) -> u64 {
        5_000 * (logical_actions.max(2) as u64)
    }

    /// Quote through the production change strategy, then build the same
    /// shape and read the fee the built transaction pays.
    fn quote_and_build(note_values: &[u64]) -> (u64, u64) {
        let network = consensus_network(ZeckNetwork::Mainnet);
        let height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 10_000;
        let total: u64 = note_values.iter().sum();
        let spends = note_values
            .iter()
            .enumerate()
            .map(|(index, value)| Spend(index as u32, Zatoshis::from_u64(*value).unwrap()))
            .collect::<Vec<_>>();
        // Send-max shape: the payment is total - fee, and no change remains.
        let expected_outputs = sapling::builder::BundleType::DEFAULT
            .num_outputs(spends.len(), 1)
            .unwrap();
        let fee_guess = zip317(spends.len().max(expected_outputs));
        let payment = [Zatoshis::from_u64(total - fee_guess).unwrap()];
        // The production change strategy used for every Argos proposal.
        let strategy = standard_zip317_change_strategy::<SweepWalletDb>();
        let balance = strategy
            .compute_balance::<_, u32>(
                &network,
                height.into(),
                &[] as &[Infallible],
                &[] as &[zcash_transparent::bundle::TxOut],
                &(
                    sapling::builder::BundleType::DEFAULT,
                    &spends[..],
                    &payment[..],
                ),
                &zcash_client_backend::fees::orchard::EmptyBundleView,
                &zcash_client_backend::fees::orchard::EmptyBundleView,
                None,
                &(),
            )
            .expect("change strategy prices the sweep");
        assert!(
            balance
                .proposed_change()
                .iter()
                .all(|change: &ChangeValue| change.value() == Zatoshis::ZERO),
            "a send-max quote leaves no change"
        );
        let quoted = u64::from(balance.fee_required());

        // Build the same transaction for real.
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[7; 32]);
        let (_, address) = extsk.default_address();
        let fvk = extsk.to_diversifiable_full_viewing_key().fvk().clone();
        let notes = note_values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                sapling::Note::from_parts(
                    address,
                    sapling::value::NoteValue::from_raw(*value),
                    sapling::Rseed::AfterZip212([index as u8 + 1; 32]),
                )
            })
            .collect::<Vec<_>>();
        let mut tree = sapling::CommitmentTree::empty();
        let mut witnesses: Vec<sapling::IncrementalWitness> = Vec::new();
        for note in &notes {
            let node = sapling::Node::from_cmu(&note.cmu());
            tree.append(node).unwrap();
            for witness in &mut witnesses {
                witness.append(node).unwrap();
            }
            witnesses.push(sapling::IncrementalWitness::from_tree(tree.clone()).unwrap());
        }
        let anchor = sapling::Anchor::from(tree.root());
        let mut builder = Builder::new(
            network,
            height,
            BuildConfig::Standard {
                sapling_anchor: Some(anchor),
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        for (note, witness) in notes.iter().zip(&witnesses) {
            builder
                .add_sapling_spend::<Infallible>(fvk.clone(), note.clone(), witness.path().unwrap())
                .unwrap();
        }
        builder
            .add_sapling_output::<Infallible>(None, address, payment[0], MemoBytes::empty())
            .unwrap();
        let prover = LocalTxProver::bundled();
        let built = builder
            .build(
                &zcash_transparent::builder::TransparentSigningSet::new(),
                &[extsk],
                &[],
                OsRng,
                &prover,
                &prover,
                &FeeRule::standard(),
            )
            .expect("the quoted shape builds");
        let tx = built.transaction();
        let paid = tx
            .sapling_bundle()
            .map(|bundle| bundle.value_balance().as_fee_paid())
            .expect("a Sapling bundle");
        (quoted, paid)
    }

    trait FeePaid {
        fn as_fee_paid(&self) -> u64;
    }

    impl FeePaid for zcash_protocol::value::ZatBalance {
        fn as_fee_paid(&self) -> u64 {
            u64::try_from(i64::from(*self)).expect("spends exceed outputs by the fee")
        }
    }

    #[test]
    fn multi_note_shielded_quote_equals_built_fee() {
        // Three spends, one output (padded to two): three logical actions,
        // above the two-action floor that a single-note estimate would use.
        let (quoted, paid) = quote_and_build(&[100_000, 200_000, 300_000]);
        assert_eq!(quoted, zip317(3));
        assert_eq!(paid, quoted);
    }

    #[test]
    fn padded_single_output_quote_equals_built_fee() {
        // One spend and one output: the output pads to two, so two actions.
        assert_eq!(
            sapling::builder::BundleType::DEFAULT
                .num_outputs(1, 1)
                .unwrap(),
            2
        );
        let (quoted, paid) = quote_and_build(&[500_000]);
        assert_eq!(quoted, zip317(2));
        assert_eq!(paid, quoted);
    }

    #[test]
    fn transparent_sweep_plan_equals_built_fee() {
        use crate::transparent_recovery::tests_support::utxo;
        let network = consensus_network(ZeckNetwork::Mainnet);
        let height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 10_000;
        let secret = secp256k1::SecretKey::from_slice(&[0x24; 32]).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        let address = zcash_transparent::address::TransparentAddress::from_pubkey(&public);
        let key = crate::imported::ImportedTransparentKey { secret, address };
        let recipient = sapling::zip32::ExtendedSpendingKey::master(&[9; 32])
            .default_address()
            .1;
        let prover = LocalTxProver::bundled();
        for inputs in [1usize, 2, 5] {
            let utxos = (0..inputs)
                .map(|index| utxo(address, 1_000_000, index as u8 + 1))
                .collect::<Vec<_>>();
            let plan = crate::transparent_recovery::plan_sweep(&network, height, &utxos)
                .unwrap()
                .unwrap();
            // n P2PKH inputs + one Sapling output padded to two.
            assert_eq!(plan.fee_zatoshis, zip317(inputs + 2), "{inputs} inputs");
            assert_eq!(
                plan.fee_zatoshis,
                crate::transparent_recovery::transparent_sweep_fee(ZeckNetwork::Mainnet, inputs)
                    .unwrap()
            );
            let tx = crate::transparent_recovery::build_sweep_transaction(
                &network,
                height,
                &utxos,
                std::slice::from_ref(&key),
                &plan,
                recipient,
                &prover,
                &prover,
            )
            .unwrap();
            let input_total = 1_000_000 * inputs as u64;
            let into_sapling =
                u64::try_from(-i64::from(*tx.sapling_bundle().unwrap().value_balance())).unwrap();
            assert_eq!(
                input_total - into_sapling,
                plan.fee_zatoshis,
                "{inputs} inputs"
            );
        }
    }
}
