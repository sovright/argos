//! Moving recovered Sprout notes to a modern address.
//!
//! # The shape of a Sprout sweep
//!
//! Sprout cannot pay Sapling. A JoinSplit's outputs are Sprout notes, so
//! value leaves the pool through `vpub_new` into the transparent value pool,
//! and a Sapling output in the *same transaction* consumes it. Splitting
//! those across two transactions would leave the value sitting in the
//! transparent pool, spendable by whoever mines next.
//!
//! # Why this needs no scan
//!
//! A `wallet.dat` that zcashd ever synced holds a cached witness per note,
//! and consensus accepts a historical Sprout anchor — proven against a node
//! in `sprout_stale_anchor`, where a spend against a root the chain had
//! already moved past was accepted and mined. So the witness in the file is
//! usable as-is, however old, and the full-block scan is only needed for a
//! wallet holding a bare spending key with no note data at all.
//!
//! # The proving parameters
//!
//! Sprout proving needs `sprout-groth16.params`, ~725 MB, which is not
//! bundled. It is verified by digest before use: `Parameters::read` does not
//! validate the points it reads, so a corrupt or substituted file would
//! otherwise produce proofs that fail only at broadcast, after the work.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::{
    broadcast::{
        resubmit_prepared_transaction, submit_prepared_transaction, PreparedTransaction,
        SubmissionDisposition, TxLifecycleState, TxObservation, TxObservationState, TxObserver,
        TxSubmitter,
    },
    error::{ZeckError, ZeckResult},
    sprout::{self, SproutNotePlaintext},
    sprout_recovery::SpendableSproutNote,
    sprout_spend,
    sprout_sweep_journal::{note_id, JournalNoteContext},
    sprout_witness,
};

pub use crate::sprout_sweep_journal::{SproutJournalEntry, SproutJournalSnapshot, SweepJournal};

/// ZIP 317 charges 5,000 zatoshi per logical action.
const ZAT_PER_ACTION: u64 = 5_000;

/// A Sprout sweep's logical actions: two per JoinSplit, plus two for the
/// Sapling side.
///
/// The Sapling figure is two rather than one because `BundleType::DEFAULT`
/// pads outputs to `MIN_SHIELDED_OUTPUTS` — a single output is billed as
/// two. Asking the bundle type rather than counting outputs is the only way
/// to get this right; assuming one output costs one action underpays and the
/// transaction is simply not relayed.
const ACTIONS_PER_SWEEP: u64 = 2 + 2;

/// The fee for a one-JoinSplit Sprout sweep.
pub const SPROUT_SWEEP_FEE: u64 = ACTIONS_PER_SWEEP * ZAT_PER_ACTION;

/// Where the NU7 deadline stands on mainnet, as text.
///
/// The date is the ecosystem's announced target, not a consensus constant:
/// the height is proposed in zcash/zips#1405 and is not yet in ZIP 259.
/// Do not state a height here until that PR merges.
const MAINNET_NU7_SCHEDULE: &str = "Mainnet activation is targeted for about November 5, \
     2026; the final height is not yet assigned (proposed in zcash/zips#1405).";

/// Kept last in a message, with no punctuation after it, so a copied link
/// does not pick up a trailing full stop.
const MAINNET_NU7_TIMELINE: &str =
    "NU7 timeline: https://forum.zcashcommunity.com/t/nu7-timeline/57655";

const TESTNET_NU7_SCHEDULE: &str = "The testnet NU7 activation height is 4,465,026.";

/// Testnet NU7 activation height (ZIP 259). The pinned `zcash_protocol`
/// carries it only behind `zcash_unstable = "nu7"`, so it is stated here.
const TESTNET_NU7_ACTIVATION_HEIGHT: u32 = 4_465_026;

/// The height at which NU7 activates on `network`, when one is assigned.
///
/// Mainnet has no assigned height yet (see [`MAINNET_NU7_SCHEDULE`]), so it
/// has no hard guard: the warnings carry the deadline instead. A local
/// regtest chain under the dev-only `argos-network` feature never activates
/// NU7.
pub fn nu7_activation_height(network: crate::ZeckNetwork) -> Option<u32> {
    #[cfg(feature = "argos-network")]
    if crate::workspace::regtest_consensus_params_installed() {
        return None;
    }
    match network {
        crate::ZeckNetwork::Mainnet => None,
        crate::ZeckNetwork::Testnet => Some(TESTNET_NU7_ACTIVATION_HEIGHT),
    }
}

/// `1234567` as `1,234,567`.
fn group_thousands(value: u32) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// The NU7 spending deadline, shared by every Sprout recovery interface.
///
/// This is guidance, not a consensus activation check.
pub fn nu7_recovery_warning(network: crate::ZeckNetwork) -> String {
    let rules = "NU7 disables all version 4 transactions, the only format that can spend \
                 Sprout funds. Funds remaining in Sprout at activation become unspendable \
                 under NU7 rules.";
    match network {
        crate::ZeckNetwork::Mainnet => format!(
            "URGENT: {rules} {MAINNET_NU7_SCHEDULE} Start recovery promptly: recovery \
             transactions must be mined before activation; broadcast alone is not enough. \
             Full-block scans and proving can take substantial time. Check \
             https://zips.z.cash/zip-0259 for the assigned mainnet activation height and \
             upgrade status. {MAINNET_NU7_TIMELINE}"
        ),
        crate::ZeckNetwork::Testnet => format!(
            "{rules} {TESTNET_NU7_SCHEDULE} At or after this height you cannot spend \
             Sprout funds. Recovery transactions needed to be mined before activation; \
             broadcast alone is not enough. Check https://zips.z.cash/zip-0259 for the \
             current upgrade status."
        ),
    }
}

/// The NU7 deadline after a Sprout sweep has broadcast at least one
/// transaction. "Start recovery promptly" no longer fits: the remaining risk
/// is a broadcast transaction that is not mined before activation.
pub fn nu7_broadcast_warning(network: crate::ZeckNetwork) -> String {
    let schedule = match network {
        crate::ZeckNetwork::Mainnet => format!("{MAINNET_NU7_SCHEDULE} {MAINNET_NU7_TIMELINE}"),
        crate::ZeckNetwork::Testnet => TESTNET_NU7_SCHEDULE.to_owned(),
    };
    format!(
        "Your Sprout recovery transaction was broadcast, but it must be mined before NU7 \
         activation; confirm it is mined by checking its txid in a block explorer. A \
         version 4 transaction still unmined at activation can never be mined. {schedule}"
    )
}

/// Where to find the Sprout proving parameters.
///
/// Checks `ARGOS_SPROUT_PARAMS` first, then the conventional zcashd location,
/// so a user who already runs a node does not download 725 MB again.
pub fn default_params_path() -> PathBuf {
    if let Ok(path) = std::env::var("ARGOS_SPROUT_PARAMS") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home)
        .join(".zcash-params")
        .join("sprout-groth16.params")
}

/// What a sweep would do, before it is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SproutSweepPlan {
    pub notes: usize,
    pub gross_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub net_zatoshis: u64,
}

/// Plan a sweep of `notes`.
///
/// Each note is swept in its own transaction: a JoinSplit takes at most two
/// inputs, and batching them would mean pairing notes whose witnesses may
/// have different anchors. One note per transaction keeps every anchor
/// exactly the one its own witness produced.
pub fn plan_sweep(notes: &[SpendableSproutNote]) -> ZeckResult<SproutSweepPlan> {
    let candidates = notes.iter().collect::<Vec<_>>();
    plan_sweep_candidates(&candidates)?.ok_or_else(|| {
        ZeckError::TransactionBuild(format!(
            "no Sprout note is worth more than the {SPROUT_SWEEP_FEE} zatoshi fee needed \
             to move it"
        ))
    })
}

/// Plan only the ready notes that execution can actually submit. Journal
/// previews use this same function so dust never inflates their count or fee.
pub fn plan_sweep_candidates(
    notes: &[&SpendableSproutNote],
) -> ZeckResult<Option<SproutSweepPlan>> {
    let spendable = notes
        .iter()
        .copied()
        .filter(|note| note.note.value > SPROUT_SWEEP_FEE)
        .collect::<Vec<_>>();
    if spendable.is_empty() {
        return Ok(None);
    }

    // Saturating: every value came from the wallet file, checked only
    // against commitments from the same file, so a crafted one can sum past
    // `u64::MAX` — and release builds do not check overflow.
    let gross = spendable
        .iter()
        .fold(0u64, |sum, n| sum.saturating_add(n.note.value));
    let fee = SPROUT_SWEEP_FEE.saturating_mul(spendable.len() as u64);

    Ok(Some(SproutSweepPlan {
        notes: spendable.len(),
        gross_zatoshis: gross,
        fee_zatoshis: fee,
        net_zatoshis: gross.saturating_sub(fee),
    }))
}

/// One built, signed sweep transaction.
pub struct BuiltSproutSweep {
    pub txid: String,
    pub raw: Vec<u8>,
    pub value_swept: u64,
}

/// Load and verify the Sprout proving parameters.
pub fn load_params(path: &Path) -> ZeckResult<bellman::groth16::Parameters<bls12_381::Bls12>> {
    if !path.exists() {
        return Err(ZeckError::TransactionBuild(format!(
            "the Sprout proving parameters are not at {}. Download them with:\n  \
             curl -o {} https://download.z.cash/downloads/sprout-groth16.params\n  \
             (about 725 MB; set ARGOS_SPROUT_PARAMS to use a different location)",
            path.display(),
            path.display()
        )));
    }
    sprout_spend::load_sprout_proving_key(path)
}

/// Build and sign a sweep of one note into a Sapling address.
///
/// The anchor comes from the note's own cached witness rather than from the
/// chain tip. That is the point: the witness is whatever the wallet last
/// recorded, and consensus accepts the historical root it produces.
#[allow(clippy::too_many_arguments)]
pub fn build_sweep_for_note(
    note: &SpendableSproutNote,
    destination: sapling_crypto::PaymentAddress,
    branch_id: BranchId,
    expiry_height: BlockHeight,
    proving_key: &bellman::groth16::Parameters<bls12_381::Bls12>,
    sapling_prover: &zcash_proofs::prover::LocalTxProver,
    memo: [u8; 512],
    mut rng: impl rand_core::RngCore + rand_core::CryptoRng + Clone,
) -> ZeckResult<BuiltSproutSweep> {
    if note.note.value <= SPROUT_SWEEP_FEE {
        return Err(ZeckError::TransactionBuild(format!(
            "this note holds {} zatoshi, which does not cover the {SPROUT_SWEEP_FEE} \
             zatoshi fee",
            note.note.value
        )));
    }
    let to_sapling = note.note.value - SPROUT_SWEEP_FEE;

    // The anchor and path were resolved when the note was recovered, from
    // whichever source it came from — a wallet's cached witness or a scan
    // that rebuilt one. Both produce the same two values here, so the
    // sweeper no longer has to know which.
    let anchor = note.anchor;
    let witness_path = note.witness_path.clone();

    let signing_key = sprout_spend::JoinSplitSigningKey::from_bytes(random_bytes(&mut rng));

    // The second input is a dummy: a JoinSplit always has two, and a
    // zero-value note with a dummy path is how the spec says to fill one.
    let inputs = [
        sprout_spend::JoinSplitInput {
            note: note.note.clone(),
            a_sk: note.a_sk,
            witness_path,
        },
        sprout_spend::JoinSplitInput {
            note: SproutNotePlaintext {
                value: 0,
                rho: random_bytes(&mut rng),
                r: random_bytes(&mut rng),
                memo: [0u8; 512],
            },
            a_sk: note.a_sk,
            witness_path: sprout_witness::dummy_path().to_vec(),
        },
    ];

    // Both outputs are zero: the whole note leaves through vpub_new. Paying
    // the change back into Sprout would be pointless — the pool is closed to
    // new value and the user is trying to leave it.
    let outputs = [
        sprout_spend::JoinSplitOutput {
            recipient: note.address,
            value: 0,
        },
        sprout_spend::JoinSplitOutput {
            recipient: note.address,
            value: 0,
        },
    ];

    // Every field drawn from one CSPRNG, independently — including each
    // output's `rcm`, which §4.7.1 requires be sampled rather than derived.
    let randomness = sprout_spend::JoinSplitRandomness::sample(&mut rng);

    let fields = sprout_spend::compute_joinsplit_fields(
        &inputs,
        &outputs,
        0,
        note.note.value,
        anchor,
        &signing_key.verification_key(),
        &randomness,
    )?;

    let proof = sprout_spend::prove_joinsplit(&fields, &inputs, &outputs, proving_key)?;
    let js = sprout_spend::build_js_description(&fields, &proof)?;

    let mut builder = sapling_crypto::builder::Builder::new(
        // Enforcement is decided by the caller's branch id in practice; a
        // sweep targets the tip, where ZIP 212 is long since active.
        sapling_crypto::note_encryption::Zip212Enforcement::On,
        sapling_crypto::builder::BundleType::DEFAULT,
        sapling_crypto::Anchor::empty_tree(),
    );
    builder
        .add_output(
            None,
            destination,
            sapling_crypto::value::NoteValue::from_raw(to_sapling),
            memo,
        )
        .map_err(|err| {
            ZeckError::TransactionBuild(format!("adding the Sapling output: {err:?}"))
        })?;
    let (bundle, _) = builder
        .build::<zcash_proofs::prover::LocalTxProver, zcash_proofs::prover::LocalTxProver, _, zcash_protocol::value::ZatBalance>(
            &[],
            &mut rng,
        )
        .map_err(|err| ZeckError::TransactionBuild(format!("building the Sapling bundle: {err:?}")))?
        .ok_or_else(|| {
            ZeckError::TransactionBuild("the Sapling bundle has no output".to_owned())
        })?;

    // Cross-check the fee against the transaction actually assembled,
    // before signing. SPROUT_SWEEP_FEE is a constant derived from an
    // expected shape; this reads the built bundle's real output count and
    // refuses to sign if it no longer matches -- a second real output, a
    // transparent leg, a different BundleType would all change it, and the
    // failure is silent: underpay and the node never relays it, overpay and
    // the difference is burned.
    //
    // This is an internal-consistency check, not an independent oracle. The
    // transparent sweep recomputes from the builder's own get_fee over the
    // zcash_primitives ZIP-317 rule; that rule does not model JoinSplits, so
    // there is no library oracle for the Sprout leg. The JoinSplit's "2
    // logical actions" is a hand-modelled assumption the constant also
    // embeds, so both sides share it: this catches output-shape drift, not
    // that assumption being wrong -- which stays unverified until a real
    // mainnet sweep exercises it.
    let sapling_outputs = bundle.shielded_outputs().len() as u64;
    // ZIP 317 charges max(spends, outputs) for the Sapling side; there are
    // no Sapling spends in a Sprout sweep, so it is the output count.
    let expected_actions = 2 + sapling_outputs;
    let expected_fee = expected_actions * ZAT_PER_ACTION;
    if expected_fee != SPROUT_SWEEP_FEE {
        return Err(ZeckError::TransactionBuild(format!(
            "this sweep would pay {SPROUT_SWEEP_FEE} zatoshi but the transaction as \
             assembled needs {expected_fee} ({expected_actions} logical actions: one \
             JoinSplit plus {sapling_outputs} Sapling output(s)). Refusing to sign rather \
             than broadcast a transaction that would be rejected or overpay."
        )));
    }

    let tx = sprout_spend::build_and_sign_v4_sprout_to_sapling(
        branch_id,
        expiry_height,
        vec![js],
        bundle,
        sapling_prover,
        &signing_key,
        rng,
    )?;

    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|err| ZeckError::TransactionBuild(format!("serializing the sweep: {err}")))?;

    Ok(BuiltSproutSweep {
        txid: tx.txid().to_string(),
        raw,
        value_swept: to_sapling,
    })
}

/// One persisted Sprout transaction and its current lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SproutSweepTransaction {
    pub txid: String,
    pub value_zatoshis: Option<u64>,
    pub state: TxLifecycleState,
    pub mined_height: Option<u32>,
    /// An expired or rejected transaction a later plan for the same note
    /// replaced. Listed so its txid is not lost; it needs no action.
    pub superseded: bool,
}

/// One note the network refused to let the sweep spend.
#[derive(Debug, Clone)]
pub struct RejectedSweep {
    pub outpoint: argos_wallet_import::keys::JsOutPoint,
    pub value: u64,
    pub kind: Refusal,
    pub source: NoteSource,
    pub reason: String,
}

impl RejectedSweep {
    /// One line: which note, how much, and what the node said.
    pub fn summary(&self) -> String {
        let txid: String = self
            .outpoint
            .txid
            .iter()
            .rev()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "note {txid}:{}:{} ({}) was refused: {}",
            self.outpoint.js_index,
            self.outpoint.output_index,
            zec(self.value),
            self.reason
        )
    }
}

impl std::fmt::Display for RejectedSweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}. Nothing moved and no fee was paid. {}",
            self.summary(),
            self.kind.explanation(self.source)
        )
    }
}

impl Refusal {
    /// What a refusal of this kind means for a note from `source`, and what
    /// to do about it. Shared by every note refused the same way, so a
    /// surface can say it once per kind rather than once per note.
    pub fn explanation(self, source: NoteSource) -> &'static str {
        match (self, source) {
            (Refusal::Spent, NoteSource::WalletFile) => {
                "The network says it is already spent, though this wallet file shows it \
                 unspent — most likely it was spent from another copy of this wallet. The \
                 full-block scan (`argos scan-sprout --wallet-file …`, or Scan for Sprout notes \
                 in the app) confirms that from the chain, and a sweep run after it skips \
                 every note the scan saw spent."
            }
            (Refusal::Spent, NoteSource::Scan) => {
                "The network says it is already spent. The scan saw it unspent up to the \
                 height it reached, so it was spent since the scan."
            }
            (Refusal::PendingSpend, _) => {
                "Another transaction in the node's mempool already spends it — most often \
                 this sweep's own earlier transaction, still waiting to be mined. If so it \
                 will confirm on its own; if it never does, running the sweep again retries \
                 the note."
            }
            (Refusal::UnknownAnchor, NoteSource::WalletFile) => {
                "The node does not recognise the tree root this note's cached witness proves \
                 against, so the witness in the wallet file is stale or damaged. The full-block \
                 scan builds a fresh one from the chain."
            }
            (Refusal::UnknownAnchor, NoteSource::Scan) => {
                "The node does not recognise the root of the witness the scan built. Running \
                 the scan again from its checkpoint rebuilds it against the current chain."
            }
            (Refusal::Evicted, _) => {
                "The node dropped this transaction under its mempool limits. It says nothing \
                 about the note, which is unspent as far as is known; running the sweep again \
                 retries it."
            }
            (Refusal::AlreadyAccepted | Refusal::Expired | Refusal::Other, _) => {
                "This is not a refusal the sweep carries past; it is recorded here only as \
                 the node's own words."
            }
        }
    }
}

/// Zatoshis as ZEC, matching the CLI's `format_zec`.
fn zec(zatoshis: u64) -> String {
    let (whole, frac) = (zatoshis / 100_000_000, zatoshis % 100_000_000);
    if frac == 0 {
        format!("{whole} ZEC")
    } else {
        format!("{whole}.{frac:08} ZEC")
    }
}

/// The result of sweeping every recoverable note.
#[derive(Debug, Clone, Default)]
pub struct SproutSweepOutcome {
    pub transactions: Vec<SproutSweepTransaction>,
    pub mined_zatoshis: u64,
    pub pending_zatoshis: u64,
    pub unknown_zatoshis: u64,
    /// Notes that were skipped, and why. Reported rather than dropped: a
    /// user who sees a smaller total than expected needs to know which notes
    /// did not move.
    pub skipped: Vec<String>,
    /// Notes the network refused, and what it said. The sweep carries on
    /// past these: a refused transaction moved nothing, each note is its own
    /// transaction, and the usual cause — the note was spent from another
    /// copy of the wallet, which the file cannot know — says nothing about
    /// the notes after it.
    pub rejected: Vec<RejectedSweep>,
    /// Things worth saying that did not stop anything, such as a broadcast
    /// that could not be written to the sweep journal.
    pub warnings: Vec<String>,
    /// What went wrong, when something did.
    ///
    /// Carried in a successful-looking outcome rather than returned as an
    /// error, because by the time a later note fails the earlier ones are
    /// already broadcast and irreversible. Returning `Err` would discard
    /// their txids, and a user whose funds have moved would be told nothing
    /// moved — then re-run, re-prove for minutes, and hit double-spend
    /// rejections that read as "my funds are gone". The HD sweep learned
    /// this as audit Issue E; this path is the same shape.
    pub error: Option<String>,
    /// True only when every journal transaction was observed during this
    /// invocation as corroborated Mined at least
    /// [`crate::broadcast::MIN_DISCARD_CONFIRMATIONS`] deep. Nothing else may
    /// tell the operator the source material can be discarded.
    pub fresh_all_mined: bool,
}

/// Which receiver a destination resolved to.
///
/// Reported so the surfaces can tell the user where the funds will actually
/// land. Someone who pastes a Unified Address reasonably expects the value to
/// arrive in its best pool; for a Sprout sweep it always arrives in the
/// Sapling one, and that must be said rather than discovered on a block
/// explorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationKind {
    /// A bare `zs1…` Sapling address.
    BareSapling,
    /// The Sapling receiver of a Unified Address.
    SaplingReceiverOfUnified,
}

/// Why a Sprout sweep cannot land in Orchard, in the user's terms.
///
/// Not an implementation limit and not worth hedging about: Sprout
/// JoinSplits exist only in v4 transactions and Orchard actions only in v5,
/// so no single transaction can hold both. Reaching Orchard is necessarily a
/// second transaction, and since Argos never holds the intermediate key, that
/// second hop belongs to the user's own wallet.
pub const SPROUT_LANDS_IN_SAPLING: &str =
    "Sprout funds can only be moved into the Sapling pool. A Sprout JoinSplit \
     exists only in a version 4 transaction and Orchard only in version 5, so \
     no single transaction can reach Orchard. The funds arrive in the Sapling \
     receiver of the address you gave, under your own keys — to finish moving \
     them to Orchard, shield them from within your own wallet afterwards.";

/// Parse a destination that can receive Sapling value.
///
/// A Unified Address is accepted only when it carries a Sapling receiver.
/// Sprout value crosses the transparent pool and must be consumed by a
/// Sapling output in the same transaction, so an Orchard-only or
/// transparent-only destination cannot receive it — and sending there would
/// leave the value in the transparent pool for whoever mines next.
pub fn parse_sapling_destination(
    destination: &str,
    network: crate::ZeckNetwork,
) -> ZeckResult<sapling_crypto::PaymentAddress> {
    parse_sapling_destination_kind(destination, network).map(|(addr, _)| addr)
}

/// As [`parse_sapling_destination`], but also reporting which receiver was
/// used.
pub fn parse_sapling_destination_kind(
    destination: &str,
    network: crate::ZeckNetwork,
) -> ZeckResult<(sapling_crypto::PaymentAddress, DestinationKind)> {
    // Shares the receiver walk with `transparent_recovery` via
    // `address::find_sapling_receiver`; the two used to carry ~85
    // near-identical lines each and the same review finding had to be applied
    // twice. The error vocabularies stay separate on purpose: this path
    // explains *why* Sprout needs a Sapling output, which is the thing users
    // get wrong, while the transparent path returns typed variants its tests
    // match on. Merging those would have silently changed one of them.
    use crate::address::{find_sapling_receiver, ReceiverLookupError, SaplingReceiver};

    match find_sapling_receiver(destination, network) {
        Ok(SaplingReceiver::Found(address, from_unified)) => Ok((
            address,
            if from_unified {
                DestinationKind::SaplingReceiverOfUnified
            } else {
                DestinationKind::BareSapling
            },
        )),
        Ok(SaplingReceiver::Malformed) => Err(ZeckError::MalformedReceiver(format!(
            "{destination} carries a Sapling receiver whose bytes do not decode. The \
             address is damaged rather than the wrong kind — re-copy it from your wallet \
             rather than looking for a different one."
        ))),
        Ok(SaplingReceiver::Absent) | Err(ReceiverLookupError::Unsupported(_)) => {
            Err(ZeckError::InvalidAddress(format!(
                "{destination} has no Sapling receiver. Sprout value leaves the pool \
                 through the transparent pool and must be consumed by a Sapling output in \
                 the same transaction, so a transparent-only or Orchard-only destination \
                 cannot receive it."
            )))
        }
        Err(ReceiverLookupError::IncorrectNetwork { expected, actual }) => {
            Err(ZeckError::InvalidAddress(format!(
                "{destination} is a {actual} address, but this is a {expected} sweep. \
                 Check the --network setting, or paste the address for this network."
            )))
        }
        Err(ReceiverLookupError::NotAnAddress(err)) => Err(ZeckError::InvalidAddress(format!(
            "{destination} is not a Zcash address: {err}"
        ))),
    }
}

/// The consensus branch in force at `height`.
///
/// Routed through [`crate::workspace::consensus_network`] rather than matching
/// on `MAIN_NETWORK`/`TEST_NETWORK` directly. Under the dev-only
/// `argos-network` feature the regtest `LocalNetwork` has its own activation
/// heights, and a direct match silently hands it testnet branch IDs — the same
/// trap `encode_transparent_address` hit, where the symptom is a signature the
/// node rejects rather than anything visible locally.
pub fn branch_id_for_height(network: crate::ZeckNetwork, height: u32) -> BranchId {
    let params = crate::workspace::consensus_network(network);
    BranchId::for_height(&params, BlockHeight::from_u32(height))
}

/// Where the notes being swept came from. It decides what a refusal means,
/// and so what the user is told to do about it: a note from the wallet file
/// was judged unspent by the file's own history, one from the scan by the
/// chain up to where the scan reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoteSource {
    #[default]
    WalletFile,
    Scan,
}

/// Everything about a sweep beyond what to sweep and where to send it.
#[derive(Clone, Copy)]
pub struct SweepOptions<'a> {
    pub source: NoteSource,
    /// Mandatory durable lifecycle journal.
    pub journal: &'a SweepJournal,
    /// Independently administered observers used to corroborate mined or
    /// expired state. The submission endpoint is added separately and can
    /// never corroborate itself.
    pub confirmation_sources: &'a [crate::models::ConfirmationEndpoint],
}

/// What the sweep needs from the network: the tip, and a way to broadcast.
/// lightwalletd in production; a script in tests, so the loop's decisions —
/// which refusals it carries on past, which stop it — are exercised rather
/// than only described.
pub(crate) trait SweepNode: TxSubmitter {
    async fn tip(&mut self) -> Result<u32, String>;
}

struct Lightwalletd(
    zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<
        tonic::transport::Channel,
    >,
);

impl SweepNode for Lightwalletd {
    async fn tip(&mut self) -> Result<u32, String> {
        use zcash_client_backend::proto::service::ChainSpec;
        self.0
            .get_latest_block(ChainSpec {})
            .await
            .map_err(|err| err.to_string())
            .and_then(|r| tip_from_height(r.into_inner().height))
    }
}

#[async_trait::async_trait]
impl TxSubmitter for Lightwalletd {
    async fn send_raw(
        &mut self,
        raw: Vec<u8>,
    ) -> Result<zcash_client_backend::proto::service::SendResponse, tonic::Status> {
        use zcash_client_backend::proto::service::RawTransaction;
        self.0
            .send_transaction(RawTransaction {
                data: raw,
                height: 0,
            })
            .await
            .map(tonic::Response::into_inner)
    }
}

/// What a refusal says about the note, read from the node's reject reason.
///
/// lightwalletd passes the node's RPC error through unchanged, and the code
/// is too coarse to act on — zcashd's `-26` covers both "this note is spent"
/// and "this transaction is too big", and Zebra reports every verifier
/// failure under one legacy code. So the reason text decides. The strings are
/// zcashd's `ShieldedReqRejectReason` and `AcceptToMemoryPool` reasons and
/// Zebra's `ValidateContextError` / mempool rejection messages, checked
/// against their source. Anything unrecognised is treated as being about the
/// node, which stops the sweep: carrying on past a refusal costs a proving
/// run, so only a refusal known to be about this note alone is carried past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The note's nullifier is already on chain or in the mempool.
    Spent,
    /// The node does not know the tree root the note's witness proves
    /// against — the witness, not the note, is the problem.
    UnknownAnchor,
    /// The node already holds this exact transaction — in its mempool or
    /// its chain. Not a refusal at all: the funds moved.
    AlreadyAccepted,
    /// Another transaction in the mempool already spends this note — most
    /// often this sweep's own earlier transaction, still waiting to be mined.
    PendingSpend,
    /// The node dropped this transaction under its mempool limits (ZIP-401).
    /// About this one transaction; a later run retries it.
    Evicted,
    /// The transaction's expiry height had passed by the time it arrived.
    Expired,
    /// Anything else: the node's state, or the transaction as a whole.
    Other,
}

/// zcashd's `RPC_CLIENT_IN_INITIAL_DOWNLOAD` and `RPC_IN_WARMUP`: the node
/// cannot judge any transaction yet. Decided by code alone, before any
/// message is read — whatever it says, every note would meet the same answer.
const NODE_NOT_READY: [i32; 2] = [-10, -28];

pub fn classify_refusal(code: i32, reason: &str) -> Refusal {
    if NODE_NOT_READY.contains(&code) {
        return Refusal::Other;
    }
    let r = reason.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| r.contains(n));
    if any(&[
        "txn-already-in-mempool",
        "txn-already-known",
        "transaction already in block chain",
        "transaction already exists in mempool",
        "transaction was committed to the best chain",
    ]) {
        Refusal::AlreadyAccepted
    } else if any(&["zip-401 denial of service limits"]) {
        Refusal::Evicted
    } else if any(&["already spent some of its inputs"]) {
        Refusal::PendingSpend
    } else if any(&[
        "bad-txns-sprout-duplicate-nullifier",
        "sprout double-spend",
        "nullifiers were revealed",
    ]) {
        Refusal::Spent
    } else if any(&["bad-txns-sprout-unknown-anchor", "unknown sprout anchor"]) {
        Refusal::UnknownAnchor
    } else if any(&[
        "tx-expiring-soon",
        "tx-overwinter-expired",
        "reached transaction expiry height",
    ]) {
        Refusal::Expired
    } else {
        Refusal::Other
    }
}

/// How many blocks after the tip read just before building a note its
/// transaction may still be mined. Read per note, so a long sweep never
/// builds against a tip that has moved on.
const EXPIRY_DELTA: u32 = crate::sprout_sweep_journal::SPROUT_EXPIRY_DELTA;

/// The highest expiry height consensus accepts: zcashd refuses
/// `nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD` (500,000,000), and Zebra's
/// `Height::MAX_EXPIRY_HEIGHT` is 499,999,999.
const MAX_EXPIRY_HEIGHT: u32 = 499_999_999;

/// A server-reported chain height as a tip the sweep can build against:
/// converted without truncation, and low enough that `tip + EXPIRY_DELTA` is
/// still a valid expiry. Anything else is not a real Zcash chain, and is
/// refused before a proving run is spent on it.
pub(crate) fn tip_from_height(height: u64) -> Result<u32, String> {
    u32::try_from(height)
        .ok()
        .filter(|tip| {
            tip.checked_add(EXPIRY_DELTA)
                .is_some_and(|expiry| expiry <= MAX_EXPIRY_HEIGHT)
        })
        .ok_or_else(|| format!("implausible chain tip {height}"))
}

/// Unknown-anchor refusals in a row, with nothing yet accepted, after which
/// the sweep stops.
///
/// An unknown anchor is normally about one note's witness. But a server that
/// knows no Sprout anchor at all -- pruned, on a fork, on another chain --
/// answers that way for every note, and each answer costs a proving run.
/// Until something has been accepted there is no evidence the server can
/// judge Sprout anchors, so a short run of these stops it and names the
/// server. Spent-note refusals never count: those are genuinely per note, and
/// the sweep tries every one.
const UNKNOWN_ANCHOR_BREAKER: usize = 3;

/// Passes submissions through and keeps the node's last reply.
///
/// The shared broadcast classifier only knows reasons that mean the same
/// thing for every kind of transaction, so it leaves Sprout's per-note
/// refusals (a spent nullifier, an unknown anchor) as an unknown outcome.
/// The Sprout loop reads the reply itself, so one bad note is recorded as
/// rejected instead of stopping every note after it.
struct RecordingSubmitter<'a, N> {
    inner: &'a mut N,
    last_reply: Option<zcash_client_backend::proto::service::SendResponse>,
}

#[async_trait::async_trait]
impl<N: TxSubmitter + Send> TxSubmitter for RecordingSubmitter<'_, N> {
    async fn send_raw(
        &mut self,
        raw: Vec<u8>,
    ) -> Result<zcash_client_backend::proto::service::SendResponse, tonic::Status> {
        self.last_reply = None;
        let reply = self.inner.send_raw(raw).await;
        if let Ok(response) = &reply {
            self.last_reply = Some(response.clone());
        }
        reply
    }
}

/// A node reply that refuses this one note and says nothing about the rest.
fn per_note_refusal(
    reply: &zcash_client_backend::proto::service::SendResponse,
) -> Option<(Refusal, String)> {
    if reply.error_code == 0 {
        return None;
    }
    let reason = if reply.error_message.trim().is_empty() {
        format!("error code {}", reply.error_code)
    } else {
        reply.error_message.trim().to_owned()
    };
    match classify_refusal(reply.error_code, &reason) {
        kind @ (Refusal::Spent
        | Refusal::UnknownAnchor
        | Refusal::PendingSpend
        | Refusal::Evicted) => Some((kind, reason)),
        Refusal::AlreadyAccepted | Refusal::Expired | Refusal::Other => None,
    }
}

pub struct SproutSweepInventory<'a> {
    pub ready: Vec<&'a SpendableSproutNote>,
    pub active: Vec<SproutJournalEntry>,
    pub mined: Vec<SproutJournalEntry>,
    terminal: Vec<SproutJournalEntry>,
}

impl SproutSweepInventory<'_> {
    /// Describe durable journal state without turning a broadcast into a
    /// completed move. Values migrated from the v1 journal remain unknown
    /// rather than entering arithmetic as zero.
    pub fn accounting_lines(&self) -> Vec<String> {
        const KEEP_SOURCE: &str = "Keep the original wallet or Sprout key and the scan checkpoint.";
        let amount = |entry: &SproutJournalEntry| match entry.value_zatoshis {
            Some(value) => zec(value),
            None => "amount unknown".to_owned(),
        };
        let mut lines = Vec::new();
        for entry in &self.active {
            let txid = entry.txid();
            match entry.state {
                TxLifecycleState::Pending => lines.push(format!(
                    "Sprout transaction {txid}: broadcast but not mined ({}). {KEEP_SOURCE}",
                    amount(entry)
                )),
                TxLifecycleState::NotSubmitted | TxLifecycleState::SubmissionUnknown => {
                    lines.push(format!(
                        "Sprout transaction {txid}: submission status unknown ({}); it may or \
                         may not have reached the network, so later work stopped. {KEEP_SOURCE}",
                        amount(entry)
                    ));
                }
                // MinedSingleSource lands here: one operator's report lets
                // later notes continue but is not final. Mined without
                // canonical evidence would too, should a producer emit it.
                _ => lines.push(format!(
                    "Sprout transaction {txid}: current status is not independently final \
                     ({}). {KEEP_SOURCE}",
                    amount(entry)
                )),
            }
        }
        for entry in &self.mined {
            let height = entry
                .observation
                .as_ref()
                .and_then(|observation| observation.mined_height)
                .expect("mined inventory requires canonical height evidence");
            lines.push(format!(
                "Sprout transaction {}: canonically confirmed at height {height} ({}). {KEEP_SOURCE}",
                entry.txid(),
                amount(entry)
            ));
        }
        for entry in &self.terminal {
            match entry.state {
                TxLifecycleState::Expired => lines.push(format!(
                    "Sprout transaction {}: the old transaction can no longer mine and the \
                     note is ready for a new plan. {KEEP_SOURCE}",
                    entry.txid()
                )),
                TxLifecycleState::Rejected => lines.push(format!(
                    "Sprout transaction {} was rejected: nothing is counted as moved, note \
                     material is retained, and the existing refusal classification determines \
                     whether a later run may retry. {KEEP_SOURCE}",
                    entry.txid()
                )),
                _ => {}
            }
        }
        lines
    }
}

pub fn classify_sprout_notes<'a>(
    notes: &'a [SpendableSproutNote],
    journal: &SproutJournalSnapshot,
) -> SproutSweepInventory<'a> {
    let mut inventory = SproutSweepInventory {
        ready: Vec::new(),
        active: Vec::new(),
        mined: Vec::new(),
        terminal: Vec::new(),
    };
    for note in notes {
        match journal.entry_for_note(&note.outpoint) {
            None => inventory.ready.push(note),
            Some(entry)
                if matches!(
                    entry.state,
                    TxLifecycleState::Expired | TxLifecycleState::Rejected
                ) =>
            {
                inventory.ready.push(note);
                inventory.terminal.push(entry.clone());
            }
            Some(entry)
                if entry.state == TxLifecycleState::Mined
                    && entry.observation.as_ref().is_some_and(
                        crate::broadcast::TxObservation::has_canonical_mined_evidence,
                    ) =>
            {
                inventory.mined.push(entry.clone())
            }
            Some(entry) => inventory.active.push(entry.clone()),
        }
    }
    inventory
}

pub struct SproutReconciliation {
    pub snapshot: SproutJournalSnapshot,
    pub transactions: Vec<SproutSweepTransaction>,
    pub stop_reason: Option<String>,
    /// Transactions this pass observed as corroborated Mined at least
    /// `MIN_DISCARD_CONFIRMATIONS` deep. An observer error, a single
    /// operator, or a shallow block leaves a transaction out.
    pub fresh_safe_to_discard: HashSet<TxId>,
}

fn transaction_summary(entry: &SproutJournalEntry, superseded: bool) -> SproutSweepTransaction {
    SproutSweepTransaction {
        superseded,
        txid: entry.txid().to_string(),
        value_zatoshis: entry.value_zatoshis,
        state: entry.state,
        mined_height: (entry.state == TxLifecycleState::Mined)
            .then(|| {
                entry
                    .observation
                    .as_ref()
                    .and_then(|item| item.mined_height)
            })
            .flatten(),
    }
}

fn transaction_summaries(snapshot: &SproutJournalSnapshot) -> Vec<SproutSweepTransaction> {
    snapshot
        .superseded_entries()
        .map(|entry| transaction_summary(entry, true))
        .chain(
            snapshot
                .entries_in_journal_order()
                .map(|entry| transaction_summary(entry, false)),
        )
        .collect()
}

/// The tip a v1 entry's expiry bound is derived from.
///
/// The highest tip an independent pair agrees on when there is one;
/// otherwise the first configured source reporting absence -- the primary,
/// in the default single-operator setup. One source suffices for the same
/// reason it suffices for expiry (see `EXPIRY_MARGIN_BLOCKS`): a source
/// that lies low can at worst cause a rebuild that conflicts with the old
/// transaction on the same nullifier, and consensus rejects whichever
/// arrives second. A tip too high to be a real chain is never used, so a
/// lying source cannot push the bound out of reach.
fn reliable_observed_tip(observation: &TxObservation) -> Option<u32> {
    let reduced = crate::broadcast::observe_transaction(
        observation.evidence.clone(),
        observation.expiry_height,
    );
    if reduced.state != TxObservationState::Absent {
        return None;
    }
    highest_corroborated_absent_tip(&reduced)
        .or_else(|| {
            reduced
                .evidence
                .iter()
                .find(|item| {
                    is_absent_evidence(item)
                        && crate::models::normalized_confirmation_authority(&item.endpoint)
                            .is_some()
                })
                .and_then(|item| item.tip_height)
        })
        .filter(|tip| tip_from_height(u64::from(*tip)).is_ok())
}

fn independently_administered_absence(
    first: &crate::broadcast::EndpointTxEvidence,
    second: &crate::broadcast::EndpointTxEvidence,
) -> bool {
    let first_operator =
        crate::models::canonical_confirmation_operator_id(&first.operator_id, &first.endpoint);
    let second_operator =
        crate::models::canonical_confirmation_operator_id(&second.operator_id, &second.endpoint);
    if first_operator.is_empty() || second_operator.is_empty() || first_operator == second_operator
    {
        return false;
    }
    let (Some(first_authority), Some(second_authority)) = (
        crate::models::normalized_confirmation_authority(&first.endpoint),
        crate::models::normalized_confirmation_authority(&second.endpoint),
    ) else {
        return false;
    };
    first_authority != second_authority
}

fn is_absent_evidence(item: &crate::broadcast::EndpointTxEvidence) -> bool {
    item.tip_height.is_some()
        && item.reported_height.is_none()
        && item.block_hash.is_none()
        && !item.tx_in_block
}

fn highest_corroborated_absent_tip(observation: &TxObservation) -> Option<u32> {
    let absent = observation
        .evidence
        .iter()
        .filter(|item| is_absent_evidence(item))
        .collect::<Vec<_>>();
    let mut highest = None;
    for (index, first) in absent.iter().enumerate() {
        for second in absent.iter().skip(index + 1) {
            if independently_administered_absence(first, second) {
                let corroborated = first.tip_height?.min(second.tip_height?);
                highest = Some(highest.map_or(corroborated, |tip: u32| tip.max(corroborated)));
            }
        }
    }
    highest
}

fn expired_absence_from_reorg(
    observation: &TxObservation,
    expiry_height: u32,
) -> Option<TxObservation> {
    if observation.state != TxObservationState::Reorged {
        return None;
    }
    let absence = crate::broadcast::observe_transaction(
        observation
            .evidence
            .iter()
            .filter(|item| is_absent_evidence(item))
            .cloned()
            .collect(),
        Some(expiry_height),
    );
    absence.is_expired().then_some(absence)
}

fn valid_for_exact_retry(observation: &TxObservation, expiry: u32) -> bool {
    let reduced = crate::broadcast::observe_transaction(
        observation.evidence.clone(),
        observation.expiry_height,
    );
    reduced.state == observation.state
        && matches!(
            observation.state,
            TxObservationState::Absent | TxObservationState::Reorged
        )
        && observation
            .evidence
            .iter()
            .filter_map(|item| item.tip_height)
            .all(|tip| tip <= expiry)
        && observation
            .evidence
            .iter()
            .any(|item| item.tip_height.is_some())
}

/// A transition to the record's current state whose observation reports
/// the same thing as the stored one. Appending it would only record a newer
/// tip, and doing so on every pass grows the journal without bound.
fn repeats_record(
    entry: &SproutJournalEntry,
    state: TxLifecycleState,
    observation: &TxObservation,
) -> bool {
    entry.state == state
        && entry.observation.as_ref().is_some_and(|stored| {
            stored.state == observation.state && stored.mined_height == observation.mined_height
        })
}

pub(crate) async fn reconcile_sprout_journal<S: TxSubmitter, O: TxObserver>(
    journal: &SweepJournal,
    mut snapshot: SproutJournalSnapshot,
    submitter: &mut S,
    observer: &mut O,
    network: crate::ZeckNetwork,
) -> ZeckResult<SproutReconciliation> {
    let entries = snapshot
        .entries_in_journal_order()
        .cloned()
        .collect::<Vec<_>>();
    let mut retries = Vec::new();
    let mut unresolved_unknown = false;
    let mut unknown_observation_errors = Vec::new();
    let mut fresh_safe_to_discard = HashSet::new();

    for entry in entries {
        if entry.state == TxLifecycleState::NotSubmitted {
            if let Some(transaction) = entry.transaction.clone() {
                let value_zatoshis = entry.value_zatoshis.ok_or_else(|| {
                    ZeckError::Storage(format!(
                        "Sprout transaction {} has no recorded value",
                        transaction.txid
                    ))
                })?;
                retries.push((entry.outpoint, value_zatoshis, transaction));
            } else {
                unresolved_unknown = true;
            }
            continue;
        }
        if !matches!(
            entry.state,
            TxLifecycleState::SubmissionUnknown
                | TxLifecycleState::Pending
                | TxLifecycleState::Mined
                | TxLifecycleState::MinedSingleSource
        ) {
            continue;
        }
        let expiry = entry
            .transaction
            .as_ref()
            .and_then(|transaction| transaction.expiry_height)
            .or(entry.legacy_expiry_bound);
        let observation = match observer.observe(network, entry.txid(), expiry).await {
            Ok(observation) => observation,
            Err(err) => {
                if entry.state == TxLifecycleState::SubmissionUnknown {
                    unknown_observation_errors.push(format!("{}: {err}", entry.txid()));
                    unresolved_unknown = true;
                }
                continue;
            }
        };

        if observation.has_canonical_mined_evidence() {
            if !repeats_record(&entry, TxLifecycleState::Mined, &observation) {
                journal.append_transition(
                    &mut snapshot,
                    entry.txid(),
                    TxLifecycleState::Mined,
                    None,
                    Some(&observation),
                )?;
            }
            // Only corroborated and deep enough may ever tell the operator
            // the source is no longer needed.
            if observation.is_safe_to_discard() {
                fresh_safe_to_discard.insert(entry.txid());
            }
            continue;
        }
        if observation.has_single_source_mined_evidence() {
            // Preserve a previously corroborated result. Otherwise record
            // the one-operator result so later legs may continue without
            // presenting it as independent finality to the operator.
            if entry.state != TxLifecycleState::Mined
                && !repeats_record(&entry, TxLifecycleState::MinedSingleSource, &observation)
            {
                journal.append_transition(
                    &mut snapshot,
                    entry.txid(),
                    TxLifecycleState::MinedSingleSource,
                    None,
                    Some(&observation),
                )?;
            }
            continue;
        }
        if observation.state == TxObservationState::PresentUnmined {
            if !repeats_record(&entry, TxLifecycleState::Pending, &observation) {
                journal.append_transition(
                    &mut snapshot,
                    entry.txid(),
                    TxLifecycleState::Pending,
                    None,
                    Some(&observation),
                )?;
            }
            continue;
        }
        if observation.is_expired() {
            journal.append_transition(
                &mut snapshot,
                entry.txid(),
                TxLifecycleState::Expired,
                None,
                Some(&observation),
            )?;
            continue;
        }
        if let Some(expired_absence) =
            expiry.and_then(|expiry_height| expired_absence_from_reorg(&observation, expiry_height))
        {
            journal.append_transition(
                &mut snapshot,
                entry.txid(),
                TxLifecycleState::Expired,
                None,
                Some(&expired_absence),
            )?;
            continue;
        }

        let Some(transaction) = entry.transaction.clone() else {
            if entry.state.is_mined()
                && matches!(
                    observation.state,
                    TxObservationState::Absent | TxObservationState::Reorged
                )
            {
                journal.append_transition(
                    &mut snapshot,
                    entry.txid(),
                    TxLifecycleState::Pending,
                    None,
                    Some(&observation),
                )?;
            }
            if entry.legacy_expiry_bound.is_none() {
                if let Some(verified_tip) = reliable_observed_tip(&observation) {
                    let expiry_bound = verified_tip.checked_add(EXPIRY_DELTA).ok_or_else(|| {
                        ZeckError::Storage("legacy expiry horizon overflow".into())
                    })?;
                    journal.append_legacy_expiry_bound(
                        &mut snapshot,
                        entry.txid(),
                        verified_tip,
                        expiry_bound,
                    )?;
                }
            }
            // Without raw bytes there is nothing to resend. A v1 entry is
            // Pending and leaves the other notes free; only a genuinely
            // unknown submission stops them.
            if entry.state == TxLifecycleState::SubmissionUnknown {
                unresolved_unknown = true;
            }
            continue;
        };
        let expiry = transaction.expiry_height.ok_or_else(|| {
            ZeckError::Storage(format!(
                "Sprout transaction {} has no expiry",
                transaction.txid
            ))
        })?;
        let mined_was_displaced = entry.state.is_mined()
            && matches!(
                observation.state,
                TxObservationState::Absent | TxObservationState::Reorged
            );
        if mined_was_displaced {
            journal.append_transition(
                &mut snapshot,
                entry.txid(),
                TxLifecycleState::Pending,
                None,
                Some(&observation),
            )?;
        }
        if valid_for_exact_retry(&observation, expiry) {
            let value_zatoshis = entry.value_zatoshis.ok_or_else(|| {
                ZeckError::Storage(format!(
                    "Sprout transaction {} has no recorded value",
                    transaction.txid
                ))
            })?;
            if entry.state != TxLifecycleState::SubmissionUnknown
                && !mined_was_displaced
                && !repeats_record(&entry, TxLifecycleState::Pending, &observation)
            {
                journal.append_transition(
                    &mut snapshot,
                    entry.txid(),
                    TxLifecycleState::Pending,
                    None,
                    Some(&observation),
                )?;
            }
            retries.push((entry.outpoint, value_zatoshis, transaction));
        } else {
            if entry.state == TxLifecycleState::Pending
                && !repeats_record(&entry, TxLifecycleState::Pending, &observation)
            {
                journal.append_transition(
                    &mut snapshot,
                    entry.txid(),
                    TxLifecycleState::Pending,
                    None,
                    Some(&observation),
                )?;
            }
            if entry.state == TxLifecycleState::SubmissionUnknown {
                unresolved_unknown = true;
            }
        }
    }

    let mut stop_reason = if unresolved_unknown {
        let detail = if unknown_observation_errors.is_empty() {
            String::new()
        } else {
            format!(" ({})", unknown_observation_errors.join(", "))
        };
        Some(format!("a Sprout submission remains unknown{detail}; later broadcasts are stopped until independent reconciliation resolves it"))
    } else {
        None
    };

    if stop_reason.is_none() {
        for (outpoint, value_zatoshis, transaction) in retries {
            // Observation can take long enough for an older Argos process
            // that ignores the network operation guard to create a sibling
            // journal. Narrow that compatibility race immediately before
            // the exact saved bytes leave this process.
            journal.load_scoped_snapshot(&[outpoint])?;
            let result = {
                let mut store = journal.scoped_store(
                    JournalNoteContext {
                        outpoint,
                        value_zatoshis,
                    },
                    &mut snapshot,
                );
                resubmit_prepared_transaction(
                    &mut store,
                    submitter,
                    &transaction,
                    Duration::from_secs(30),
                )
                .await?
            };
            if let Some(warning) = result.persistence_warning {
                stop_reason = Some(warning);
                break;
            }
            if result.blocks_followup_submission() {
                stop_reason = Some(format!(
                    "Sprout transaction {} remains {}; later broadcasts are stopped",
                    result.txid, result.state
                ));
                break;
            }
        }
    }

    Ok(SproutReconciliation {
        transactions: transaction_summaries(&snapshot),
        snapshot,
        stop_reason,
        fresh_safe_to_discard,
    })
}

async fn with_sprout_operation_guard<T>(
    data_dir: &Path,
    network: crate::ZeckNetwork,
    operation: impl std::future::Future<Output = ZeckResult<T>>,
) -> ZeckResult<T> {
    let _operation_guard = crate::service::NetworkOperationGuard::acquire(data_dir, network)?;
    operation.await
}

/// Prove and broadcast a sweep of every recoverable note.
///
/// One transaction per note, because a JoinSplit takes two inputs and
/// batching would mean pairing notes whose cached witnesses may carry
/// different anchors. Each is broadcast as it is built rather than at the
/// end: proving takes minutes per note, and a failure on note five should
/// not discard the four that already succeeded.
pub async fn sweep_sprout_notes(
    notes: &[SpendableSproutNote],
    network: crate::ZeckNetwork,
    lightwalletd_url: &str,
    destination: &str,
    params_path: &Path,
    options: SweepOptions<'_>,
    progress: impl FnMut(String),
) -> ZeckResult<SproutSweepOutcome> {
    let (sapling_dest, _) = parse_sapling_destination_kind(destination, network)?;

    let data_dir = options
        .journal
        .path()
        .parent()
        .ok_or_else(|| ZeckError::Storage("Sprout journal has no data directory".into()))?;
    with_sprout_operation_guard(
        data_dir,
        network,
        sweep_sprout_notes_guarded(
            notes,
            network,
            lightwalletd_url,
            sapling_dest,
            params_path,
            options,
            progress,
        ),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sweep_sprout_notes_guarded(
    notes: &[SpendableSproutNote],
    network: crate::ZeckNetwork,
    lightwalletd_url: &str,
    sapling_dest: sapling_crypto::PaymentAddress,
    params_path: &Path,
    options: SweepOptions<'_>,
    progress: impl FnMut(String),
) -> ZeckResult<SproutSweepOutcome> {
    // Migration and identity validation must finish before any network I/O or
    // proving work. `run_sweep` reloads while the outer operation guard held
    // by `with_sprout_operation_guard` remains live.
    let outpoints = notes.iter().map(|note| note.outpoint).collect::<Vec<_>>();
    options.journal.load_scoped_snapshot(&outpoints)?;

    // Every other fund-moving path checks that lightwalletd serves the chain
    // the keys belong to. Without it, the mainnet default under
    // `--network testnet` would build against the wrong tip and branch id.
    //
    // The prober the scan uses, which moves past an endpoint on the wrong
    // chain to the next one, so a comma-separated list is honoured here as
    // it is everywhere else. And before the proving parameters: a wrong
    // server should be reported in seconds, not after ~725 MB is read.
    let (client, _endpoint, _info) =
        crate::scan::probe_valid_lightwalletd_endpoints(lightwalletd_url, network).await?;

    let sapling_prover = zcash_proofs::prover::LocalTxProver::bundled();

    let mut node = Lightwalletd(client);
    let mut observer = crate::lightwalletd::LightwalletdTxObserver::new(
        lightwalletd_url,
        options.confirmation_sources,
    )?;
    let mut proving_key = None;
    let outcome = run_sweep(
        notes,
        &mut node,
        &mut observer,
        network,
        |note: &SpendableSproutNote, expiry: BlockHeight, branch_id: BranchId| {
            if proving_key.is_none() {
                proving_key = Some(load_params(params_path)?);
            }
            build_sweep_for_note(
                note,
                sapling_dest,
                branch_id,
                expiry,
                proving_key.as_ref().expect("proving key initialized"),
                &sapling_prover,
                [0u8; 512],
                rand_core::OsRng,
            )
        },
        options.source,
        options.journal,
        progress,
    )
    .await;
    Ok(outcome)
}

/// A note as a user can find it again: its place in this sweep, from one,
/// and its outpoint.
fn note_label(index: usize, total: usize, note: &SpendableSproutNote) -> String {
    let txid: String = note
        .outpoint
        .txid
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "note {} of {total} ({txid}:{}:{})",
        index + 1,
        note.outpoint.js_index,
        note.outpoint.output_index
    )
}

/// The sweep's decisions, separated from lightwalletd and the prover.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_sweep(
    notes: &[SpendableSproutNote],
    node: &mut (impl SweepNode + Send),
    observer: &mut impl TxObserver,
    network: crate::ZeckNetwork,
    mut build: impl FnMut(&SpendableSproutNote, BlockHeight, BranchId) -> ZeckResult<BuiltSproutSweep>,
    source: NoteSource,
    journal: &SweepJournal,
    mut progress: impl FnMut(String),
) -> SproutSweepOutcome {
    let mut outcome = SproutSweepOutcome::default();
    let total = notes.len();
    let outpoints = notes.iter().map(|note| note.outpoint).collect::<Vec<_>>();
    let snapshot = match journal.load_scoped_snapshot(&outpoints) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            outcome.error = Some(format!(
                "{err}. Nothing was sent because the Sprout lifecycle journal could not be opened."
            ));
            return outcome;
        }
    };

    let reconciliation =
        match reconcile_sprout_journal(journal, snapshot, node, observer, network).await {
            Ok(reconciliation) => reconciliation,
            Err(err) => {
                outcome.error = Some(format!(
                    "Sprout reconciliation failed before any new proof or broadcast: {err}"
                ));
                if let Ok(snapshot) = journal.load_scoped_snapshot(&outpoints) {
                    refresh_outcome(&mut outcome, &snapshot, notes, &HashSet::new());
                }
                return outcome;
            }
        };
    let mut snapshot = reconciliation.snapshot;
    if let Some(reason) = reconciliation.stop_reason {
        outcome.error = Some(reason);
        refresh_outcome(
            &mut outcome,
            &snapshot,
            notes,
            &reconciliation.fresh_safe_to_discard,
        );
        return outcome;
    }

    let fresh_safe_to_discard = reconciliation.fresh_safe_to_discard;
    let ready_ids = classify_sprout_notes(notes, &snapshot)
        .ready
        .into_iter()
        .map(|note| note_id(&note.outpoint))
        .collect::<HashSet<_>>();

    let mut server_has_accepted = false;
    let mut unknown_anchor_run = 0usize;
    for (index, note) in notes.iter().enumerate() {
        let label = note_label(index, total, note);
        if !ready_ids.contains(&note_id(&note.outpoint)) {
            continue;
        }
        if note.note.value <= SPROUT_SWEEP_FEE {
            outcome.skipped.push(format!(
                "{label}: holds {} zatoshi, below the {SPROUT_SWEEP_FEE} zatoshi fee",
                note.note.value
            ));
            continue;
        }
        // Re-checked immediately before a proving run that takes minutes.
        // Proving an inconsistent note only yields a transaction consensus
        // rejects, after all the work.
        if !note_is_consistent(note) {
            outcome
                .skipped
                .push(format!("{label}: does not match its own commitment"));
            continue;
        }

        // Read for every note, not once: at minutes per proof, a single
        // expiry height goes stale within the first twenty notes of a large
        // sweep, and every note after that is refused as expired.
        let tip = match node.tip().await {
            Ok(tip) => tip,
            Err(err) => {
                outcome.error = Some(format!(
                    "could not read the chain tip before {label} ({err}). Nothing was sent \
                     for it; notes swept before it are listed above."
                ));
                break;
            }
        };
        // A height within the expiry delta of `u32::MAX` is no real chain;
        // building against it would wrap the expiry and pick a branch id
        // from nonsense.
        let Ok(tip) = tip_from_height(u64::from(tip)) else {
            outcome.error = Some(format!(
                "the server reported an implausible chain tip ({tip}) before {label}. Nothing \
                 was sent for it; check the lightwalletd server."
            ));
            break;
        };
        // A Sprout spend is a version 4 transaction, and NU7 disables
        // version 4 outright. A transaction built for a block at or past
        // activation can never be mined, so refuse before a proving run.
        if let Some(activation) = nu7_activation_height(network) {
            if tip.saturating_add(1) >= activation {
                outcome.error = Some(format!(
                    "the next block ({}) is at or past NU7 activation at height {} on {}. NU7 \
                     disables version 4 transactions, the only format that can spend Sprout, \
                     so Sprout funds cannot move after activation. Nothing was built or sent \
                     for {label}.",
                    group_thousands(tip.saturating_add(1)),
                    group_thousands(activation),
                    network.label(),
                ));
                break;
            }
        }
        let branch_id = branch_id_for_height(network, tip);
        let expiry = BlockHeight::from_u32(tip + EXPIRY_DELTA);

        progress(format!("proving {label}"));
        let built = match build(note, expiry, branch_id) {
            Ok(built) => built,
            // Not skipped: the build failures that come after proving — the
            // fee cross-check, the Sapling output, the bundle — are about the
            // destination and the transaction shape, not this note, so every
            // remaining note would pay a proving run to fail the same way.
            // Note-specific problems (a bad witness, a value below the fee)
            // are caught before this point, without proving.
            Err(err) => {
                outcome.error = Some(format!(
                    "{label} could not be built: {err}. Nothing was sent for it. The sweep \
                     stopped rather than prove the remaining notes into the same failure; \
                     notes swept before it are listed above."
                ));
                break;
            }
        };

        let txid = match crate::broadcast::txid_from_raw(&built.raw) {
            Ok(txid) if txid.to_string() == built.txid => txid,
            Ok(txid) => {
                outcome.error = Some(format!(
                    "{label} was built with transaction ID {} but its bytes hash to {txid}; nothing was sent",
                    built.txid
                ));
                break;
            }
            Err(err) => {
                outcome.error = Some(format!("{label} produced invalid transaction bytes: {err}"));
                break;
            }
        };
        let transaction = PreparedTransaction {
            txid,
            raw_tx: built.raw,
            fee_zatoshis: SPROUT_SWEEP_FEE,
            expiry_height: Some(u32::from(expiry)),
        };
        // Proving may take minutes. Repeat the complete sibling inspection
        // after it and immediately before durable prepare/send, protecting
        // this note even though it is not yet present in the target journal.
        if let Err(err) = journal.load_scoped_snapshot(&[note.outpoint]) {
            outcome.error = Some(format!(
                "Sprout journal scope changed before {label} could be broadcast: {err}. Nothing was sent for it."
            ));
            break;
        }
        let mut recorder = RecordingSubmitter {
            inner: &mut *node,
            last_reply: None,
        };
        let result = {
            let mut store = journal.scoped_store(
                JournalNoteContext {
                    outpoint: note.outpoint,
                    value_zatoshis: built.value_swept,
                },
                &mut snapshot,
            );
            submit_prepared_transaction(
                &mut store,
                &mut recorder,
                transaction,
                Duration::from_secs(30),
            )
            .await
        };
        let last_reply = recorder.last_reply.take();
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                outcome.error = Some(format!(
                    "{label} could not be durably prepared for submission: {err}. No later note was built."
                ));
                break;
            }
        };
        progress(format!(
            "broadcast {label} as {} ({})",
            result.txid, result.state
        ));
        if let Some(warning) = result.persistence_warning {
            outcome.warnings.push(warning.clone());
            outcome.error = Some(warning);
            break;
        }
        if result.state == TxLifecycleState::Pending {
            server_has_accepted = true;
            unknown_anchor_run = 0;
        }
        // A refusal about this note alone: the node did not take these bytes
        // and said why in terms of the note. Record the note as rejected and
        // carry on; only a lost or unfamiliar reply stays unknown and stops.
        let refusal = (result.state == TxLifecycleState::SubmissionUnknown)
            .then(|| last_reply.as_ref().and_then(per_note_refusal))
            .flatten();
        if let Some((kind, reason)) = refusal {
            let code = last_reply.as_ref().map_or(0, |reply| reply.error_code);
            let disposition = SubmissionDisposition::DeterministicRejection {
                code,
                reason: reason.clone(),
            };
            if let Err(err) = journal.append_transition(
                &mut snapshot,
                result.txid,
                TxLifecycleState::Rejected,
                Some(&disposition),
                None,
            ) {
                outcome.error = Some(format!(
                    "{label} was refused ({reason}), but the refusal could not be recorded:                      {err}. It stays unknown; no later Sprout note was built or broadcast."
                ));
                break;
            }
            progress(format!("{label} was refused: {reason}"));
            outcome.rejected.push(RejectedSweep {
                outpoint: note.outpoint,
                value: note.note.value,
                kind,
                source,
                reason,
            });
            unknown_anchor_run = match kind {
                Refusal::UnknownAnchor => unknown_anchor_run + 1,
                _ => 0,
            };
            if !server_has_accepted && unknown_anchor_run >= UNKNOWN_ANCHOR_BREAKER {
                outcome.error = Some(format!(
                    "the server refused {unknown_anchor_run} notes in a row because it does \
                     not recognise their witnesses' tree roots, and has accepted none in this \
                     sweep. That points at the lightwalletd server (pruned, on a fork, or on \
                     another chain) rather than the notes. The sweep stopped rather than prove \
                     every remaining note into the same answer; try another lightwalletd server."
                ));
                break;
            }
            continue;
        }
        if result.blocks_followup_submission() {
            outcome.error = Some(format!(
                "{} remains {}; no later Sprout note was built or broadcast",
                result.txid, result.state
            ));
            break;
        }
    }

    refresh_outcome(&mut outcome, &snapshot, notes, &fresh_safe_to_discard);
    outcome
}

fn refresh_outcome(
    outcome: &mut SproutSweepOutcome,
    snapshot: &SproutJournalSnapshot,
    notes: &[SpendableSproutNote],
    fresh_safe_to_discard: &HashSet<TxId>,
) {
    outcome.transactions = transaction_summaries(snapshot);
    outcome.mined_zatoshis = 0;
    outcome.pending_zatoshis = 0;
    outcome.unknown_zatoshis = 0;
    for transaction in &outcome.transactions {
        let Some(value) = transaction.value_zatoshis else {
            continue;
        };
        match transaction.state {
            TxLifecycleState::Mined => {
                outcome.mined_zatoshis = outcome.mined_zatoshis.saturating_add(value)
            }
            // One confirmation operator is not independent mining evidence;
            // keep the value in flight until a second authority agrees.
            TxLifecycleState::Pending | TxLifecycleState::MinedSingleSource => {
                outcome.pending_zatoshis = outcome.pending_zatoshis.saturating_add(value)
            }
            TxLifecycleState::NotSubmitted | TxLifecycleState::SubmissionUnknown => {
                outcome.unknown_zatoshis = outcome.unknown_zatoshis.saturating_add(value)
            }
            TxLifecycleState::Expired | TxLifecycleState::Rejected => {}
        }
    }
    // Completion is a wallet-journal verdict, not merely a verdict over the
    // notes recovered by this invocation. An orphaned journal entry still
    // identifies a transaction whose value may be in flight, so it must be
    // freshly observed alongside every other transaction before a caller may
    // tell the operator that the original recovery material is no longer
    // needed.
    let journal_entries = snapshot.entries().collect::<Vec<_>>();
    let no_ready_notes = classify_sprout_notes(notes, snapshot).ready.is_empty();
    outcome.fresh_all_mined = !journal_entries.is_empty()
        && journal_entries.iter().all(|entry| {
            entry.state == TxLifecycleState::Mined && fresh_safe_to_discard.contains(&entry.txid())
        })
        && no_ready_notes
        && outcome.error.is_none()
        && outcome.skipped.is_empty()
        && outcome.rejected.is_empty();
}

fn random_bytes(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> [u8; 32] {
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    out
}

/// Verify a note's plaintext really is what its commitment commits to.
///
/// Already checked when the note was recovered, but re-checked immediately
/// before a 725 MB proving run: proving a note that does not match wastes
/// minutes to produce a transaction consensus rejects.
pub fn note_is_consistent(note: &SpendableSproutNote) -> bool {
    sprout::note_commitment(
        note.address.a_pk(),
        note.note.value,
        &note.note.rho,
        &note.note.r,
    ) == note.commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprout::SproutPaymentAddress;
    use argos_wallet_import::keys::JsOutPoint;

    /// PR #263 review item 1: the mainnet warning must give the targeted
    /// date and say the height is not yet assigned, or a user facing a
    /// days-long scan cannot judge how urgent this is.
    #[test]
    fn mainnet_nu7_warning_gives_the_target_date_and_unassigned_height() {
        let text = nu7_recovery_warning(crate::ZeckNetwork::Mainnet);
        assert!(text.starts_with("URGENT:"), "{text}");
        assert!(text.contains("all version 4 transactions"), "{text}");
        assert!(
            text.contains(
                "Mainnet activation is targeted for about November 5, 2026; the final \
                 height is not yet assigned (proposed in zcash/zips#1405)"
            ),
            "{text}"
        );
        assert!(
            text.contains("https://forum.zcashcommunity.com/t/nu7-timeline/57655"),
            "{text}"
        );
        assert!(text.contains("mined before activation"), "{text}");
        assert!(text.contains("broadcast alone is not enough"), "{text}");
        assert!(text.contains("Start recovery promptly"), "{text}");
        assert!(text.contains("https://zips.z.cash/zip-0259"), "{text}");
        // No height may be stated as fact until zcash/zips#1405 merges.
        assert!(!text.contains("3,543,405") && !text.contains("3543405"));
        // A copied link must not pick up trailing punctuation.
        assert!(text.ends_with("/t/nu7-timeline/57655"), "{text}");
        assert!(nu7_broadcast_warning(crate::ZeckNetwork::Mainnet).ends_with("/57655"));
    }

    #[test]
    fn testnet_nu7_warning_states_the_assigned_height_without_urgency() {
        let text = nu7_recovery_warning(crate::ZeckNetwork::Testnet);
        assert!(text.contains("4,465,026"), "{text}");
        assert!(!text.contains("URGENT"), "{text}");
        assert!(!text.contains("Start recovery promptly"), "{text}");
        assert!(!text.contains("November 5"), "{text}");
    }

    /// PR #263 review item 3: once a sweep has broadcast, "start recovery
    /// promptly" is wrong advice; the remaining risk is that it is not mined.
    #[test]
    fn post_broadcast_nu7_warning_asks_to_confirm_mining_not_to_start() {
        for network in [crate::ZeckNetwork::Mainnet, crate::ZeckNetwork::Testnet] {
            let text = nu7_broadcast_warning(network);
            assert!(text.contains("broadcast"), "{text}");
            assert!(text.contains("must be mined before"), "{text}");
            assert!(text.contains("confirm"), "{text}");
            assert!(!text.contains("URGENT"), "{text}");
            assert!(!text.contains("Start recovery promptly"), "{text}");
        }
        assert!(nu7_broadcast_warning(crate::ZeckNetwork::Mainnet).contains("November 5, 2026"));
        assert!(nu7_broadcast_warning(crate::ZeckNetwork::Testnet).contains("4,465,026"));
    }

    #[test]
    fn readme_does_not_treat_a_primary_rejection_as_terminal_evidence() {
        let readme = include_str!("../../../README.md");
        assert!(!readme.contains(
            "deterministically rejected follows a separate terminal path back to a new plan"
        ));
        assert!(!readme
            .contains("an eligible deterministic rejection can return separately to a new plan"));
        assert!(readme.contains("SubmissionUnknown") || readme.contains("submission unknown"));
        assert!(readme.contains("independent"));
        assert!(readme.contains("older Argos") && readme.contains("concurrently"));
        // The single-operator policy: one source's absence past expiry plus
        // the margin is enough to replace a transaction.
        assert!(!readme.contains("only after independent sources corroborate absence"));
        assert!(!readme.contains("requires independently corroborated absence"));
        // What the journal holds, stated honestly.
        assert!(readme.contains("no spending keys and no note plaintexts"));
        assert!(readme.contains("not atomically replaced"));
        // Nothing deletes the checkpoint for the user.
        assert!(readme.contains("does not delete the checkpoint"));
    }

    /// Kristi's F5 on #239: the plan printed before confirmation must not
    /// wrap. Two notes near half of `u64::MAX` saturate rather than show a
    /// tiny gross.
    #[test]
    fn the_plan_saturates_instead_of_wrapping() {
        let plan = plan_sweep(&[note(u64::MAX / 2 + 1), note(u64::MAX / 2 + 1)]).unwrap();
        assert_eq!(plan.gross_zatoshis, u64::MAX);
        assert!(plan.net_zatoshis > u64::MAX / 2);
    }

    fn note(value: u64) -> SpendableSproutNote {
        let a_sk = [0x42u8; 32];
        let address = SproutPaymentAddress::from_spending_key(&a_sk);
        let rho = [0x11u8; 32];
        let r = [0x22u8; 32];
        SpendableSproutNote {
            note: SproutNotePlaintext {
                value,
                rho,
                r,
                memo: [0u8; 512],
            },
            a_sk,
            address,
            commitment: sprout::note_commitment(address.a_pk(), value, &rho, &r),
            anchor: [0u8; 32],
            witness_path: vec![0u8; crate::sprout_witness::WITNESS_PATH_SIZE],
            outpoint: JsOutPoint {
                txid: [0u8; 32],
                js_index: 0,
                output_index: 0,
            },
        }
    }

    /// The fee must count four actions, not three. A Sapling bundle pads to
    /// MIN_SHIELDED_OUTPUTS, so the single output is billed as two, and
    /// underpaying means the transaction is never relayed — a failure that
    /// looks like a network problem rather than a fee problem.
    #[test]
    fn the_fee_accounts_for_saplings_padded_output() {
        // This used to assert SPROUT_SWEEP_FEE == 20_000 and
        // ACTIONS_PER_SWEEP == 4, both of which restate their own
        // definitions and cannot fail. Raised in review of #189.
        //
        // What actually needs pinning is the padding: BundleType::DEFAULT
        // raises a single requested output to MIN_SHIELDED_OUTPUTS, so one
        // output is billed as two. Ask the bundle type rather than assume,
        // which is what the constant's own doc says to do.
        let padded = sapling_crypto::builder::BundleType::DEFAULT
            .num_outputs(0, 1)
            .expect("a one-output bundle is valid");
        assert_eq!(
            padded, 2,
            "a single Sapling output is padded to MIN_SHIELDED_OUTPUTS and billed as two"
        );

        let actions = 2 + padded as u64;
        assert_eq!(
            actions * ZAT_PER_ACTION,
            SPROUT_SWEEP_FEE,
            "the constant must equal what ZIP 317 charges for the shape this sweep \
             actually builds, not merely equal itself"
        );
    }

    #[test]
    fn a_plan_sums_value_and_fees_per_note() {
        let plan = plan_sweep(&[note(1_000_000), note(2_000_000)]).expect("plan");
        assert_eq!(plan.notes, 2);
        assert_eq!(plan.gross_zatoshis, 3_000_000);
        assert_eq!(plan.fee_zatoshis, 2 * SPROUT_SWEEP_FEE);
        assert_eq!(plan.net_zatoshis, 3_000_000 - 2 * SPROUT_SWEEP_FEE);
    }

    /// Dust must be excluded rather than swept at a loss.
    #[test]
    fn notes_worth_less_than_the_fee_are_left_out() {
        let plan = plan_sweep(&[note(1_000_000), note(100)]).expect("plan");
        assert_eq!(plan.notes, 1, "the dust note cannot pay its own fee");
        assert_eq!(plan.gross_zatoshis, 1_000_000);
    }

    #[test]
    fn a_wallet_of_only_dust_is_refused_with_a_reason() {
        let err = plan_sweep(&[note(10), note(SPROUT_SWEEP_FEE)])
            .expect_err("nothing here can pay its own fee");
        assert!(
            err.to_string().contains("fee"),
            "the message must say why: {err}"
        );
    }

    /// Exactly the fee is not enough — it would leave a zero-value output.
    #[test]
    fn a_note_worth_exactly_the_fee_is_not_swept() {
        assert!(plan_sweep(&[note(SPROUT_SWEEP_FEE)]).is_err());
        assert!(plan_sweep(&[note(SPROUT_SWEEP_FEE + 1)]).is_ok());
    }

    /// The explanation must name the actual constraint, not gesture at one.
    /// A user who pastes a unified address and gets Sapling deserves to know
    /// it is a transaction-version limit and that a second hop is theirs.
    #[test]
    fn the_pool_explanation_names_the_constraint_and_the_next_step() {
        let text = SPROUT_LANDS_IN_SAPLING;
        assert!(text.contains("Sapling"));
        assert!(text.contains("Orchard"));
        assert!(
            text.contains("version 4") && text.contains("version 5"),
            "the reason is a transaction-version constraint and should say so"
        );
        assert!(
            text.contains("your own"),
            "the second hop belongs to the user's wallet and must be stated"
        );
    }

    /// A bare Sapling address and a unified address must be told apart, or
    /// the surfaces cannot explain where the funds landed.
    #[test]
    fn the_destination_kind_distinguishes_bare_sapling_from_unified() {
        assert_ne!(
            DestinationKind::BareSapling,
            DestinationKind::SaplingReceiverOfUnified
        );
    }

    /// The server is checked before ~725 MB of proving parameters are read,
    /// so a wrong `--lightwalletd-url` is reported in seconds, not minutes.
    #[tokio::test]
    async fn the_server_is_checked_before_the_parameters_are_loaded() {
        let data_dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(data_dir.path());
        let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32]);
        let destination =
            crate::sapling_key::default_sapling_address(&extsk, crate::ZeckNetwork::Mainnet);
        let err = sweep_sprout_notes(
            &[note(1_000_000)],
            crate::ZeckNetwork::Mainnet,
            "nonono",
            &destination,
            Path::new("/nonexistent/sprout-groth16.params"),
            SweepOptions {
                source: NoteSource::WalletFile,
                journal: &journal,
                confirmation_sources: &[],
            },
            |_| {},
        )
        .await
        .expect_err("neither the server nor the parameters are usable");
        let text = err.to_string();
        assert!(
            !text.contains("proving parameters"),
            "the server must be refused first: {text}"
        );
    }

    #[tokio::test]
    async fn public_sweep_fails_before_network_work_when_operation_guard_is_held() {
        let data_dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(data_dir.path());
        let guard = crate::service::NetworkOperationGuard::acquire(
            data_dir.path(),
            crate::ZeckNetwork::Mainnet,
        )
        .unwrap();
        let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32]);
        let destination =
            crate::sapling_key::default_sapling_address(&extsk, crate::ZeckNetwork::Mainnet);

        let err = sweep_sprout_notes(
            &[note(1_000_000)],
            crate::ZeckNetwork::Mainnet,
            "nonono",
            &destination,
            Path::new("/nonexistent/sprout-groth16.params"),
            SweepOptions {
                source: NoteSource::WalletFile,
                journal: &journal,
                confirmation_sources: &[],
            },
            |_| {},
        )
        .await
        .expect_err("the held operation guard must stop the sweep before network work");
        assert!(matches!(err, ZeckError::ScanNotReady(_)), "{err}");

        drop(guard);
        let released = crate::service::NetworkOperationGuard::acquire(
            data_dir.path(),
            crate::ZeckNetwork::Mainnet,
        );
        assert!(
            released.is_ok(),
            "failed acquisition must not retain the lock"
        );
    }

    /// Orchard-only and transparent destinations must be refused with the
    /// reason, since sending there would strand the value in the transparent
    /// pool for whoever mines next.
    #[test]
    fn each_bad_destination_is_refused_for_its_own_reason() {
        // This asserted `!err.is_empty()`, which every error message
        // satisfies — the same defect raised in review of #187 and repeated
        // here. A transparent address and a typo are different mistakes and
        // the user has to be told which one they made.
        // A real mainnet t-address. The fabricated one this used to carry
        // was not a valid address at all, so it was rejected as unparseable
        // rather than for lacking a Sapling receiver — and the old
        // `!err.is_empty()` assertion accepted that without complaint.
        let transparent = match parse_sapling_destination(
            "t1UE73p3WKJRqjMTyFqRKXieX9FkWTNvZhm",
            crate::ZeckNetwork::Mainnet,
        ) {
            Ok(_) => panic!("a transparent address cannot receive Sprout value"),
            Err(err) => err.to_string(),
        };
        assert!(
            transparent.contains("Sapling receiver") && !transparent.contains("this network"),
            "a mainnet t-address is valid on mainnet — it must be refused for what it \
             cannot receive, not blamed on the network setting; got: {transparent}"
        );

        let garbage = match parse_sapling_destination("not-an-address", crate::ZeckNetwork::Mainnet)
        {
            Ok(_) => panic!("garbage is not an address"),
            Err(err) => err.to_string(),
        };
        assert!(
            garbage.contains("not a Zcash address"),
            "unparseable input must be named as such rather than reported as a missing \
             receiver, which would send someone hunting for the wrong problem; got: {garbage}"
        );
    }

    #[test]
    fn a_recovered_note_is_self_consistent() {
        assert!(note_is_consistent(&note(500)));

        let mut tampered = note(500);
        tampered.note.value = 501;
        assert!(
            !note_is_consistent(&tampered),
            "a value that does not match the commitment must be caught before proving"
        );
    }

    #[test]
    fn the_params_path_honours_the_override() {
        // SAFETY: single-threaded test process; no other thread reads the
        // environment concurrently.
        unsafe { std::env::set_var("ARGOS_SPROUT_PARAMS", "/tmp/custom.params") };
        assert_eq!(default_params_path(), PathBuf::from("/tmp/custom.params"));
        unsafe { std::env::remove_var("ARGOS_SPROUT_PARAMS") };
        assert!(default_params_path().ends_with("sprout-groth16.params"));
    }

    #[test]
    fn a_missing_params_file_explains_how_to_get_it() {
        // `Parameters` has no Debug, so the error is matched out by hand
        // rather than via expect_err.
        let text = match load_params(Path::new("/nonexistent/sprout.params")) {
            Ok(_) => panic!("a missing file must fail"),
            Err(err) => err.to_string(),
        };
        assert!(text.contains("download.z.cash"), "must say where to get it");
        assert!(text.contains("725 MB"), "must say how big it is");
    }

    type BeforeSend = Box<dyn FnMut(&[u8]) + Send>;

    struct LifecycleNode {
        tip: u32,
        tip_calls: usize,
        replies: std::collections::VecDeque<
            Result<zcash_client_backend::proto::service::SendResponse, tonic::Status>,
        >,
        sent: Vec<Vec<u8>>,
        before_send: Option<BeforeSend>,
    }

    impl LifecycleNode {
        fn accepted(tip: u32, count: usize) -> Self {
            Self {
                tip,
                tip_calls: 0,
                replies: (0..count)
                    .map(|_| {
                        Ok(zcash_client_backend::proto::service::SendResponse {
                            error_code: 0,
                            error_message: String::new(),
                        })
                    })
                    .collect(),
                sent: Vec::new(),
                before_send: None,
            }
        }

        fn reply(tip: u32, code: i32, message: &str) -> Self {
            Self {
                tip,
                tip_calls: 0,
                replies: [Ok(zcash_client_backend::proto::service::SendResponse {
                    error_code: code,
                    error_message: message.to_owned(),
                })]
                .into(),
                sent: Vec::new(),
                before_send: None,
            }
        }
    }

    impl SweepNode for LifecycleNode {
        async fn tip(&mut self) -> Result<u32, String> {
            self.tip_calls += 1;
            Ok(self.tip)
        }
    }

    #[async_trait::async_trait]
    impl crate::broadcast::TxSubmitter for LifecycleNode {
        async fn send_raw(
            &mut self,
            raw: Vec<u8>,
        ) -> Result<zcash_client_backend::proto::service::SendResponse, tonic::Status> {
            if let Some(before_send) = self.before_send.as_mut() {
                before_send(&raw);
            }
            self.sent.push(raw);
            self.replies.pop_front().expect("unexpected submission")
        }
    }

    #[derive(Default)]
    struct LifecycleObserver {
        observations: std::collections::VecDeque<(
            zcash_primitives::transaction::TxId,
            crate::broadcast::TxObservation,
        )>,
        observed: Vec<zcash_primitives::transaction::TxId>,
        shared_observed:
            Option<std::sync::Arc<std::sync::Mutex<Vec<zcash_primitives::transaction::TxId>>>>,
        before_observe: Option<Box<dyn FnMut() + Send>>,
        failing: Vec<zcash_primitives::transaction::TxId>,
    }

    impl LifecycleObserver {
        fn new(
            observations: impl IntoIterator<
                Item = (
                    zcash_primitives::transaction::TxId,
                    crate::broadcast::TxObservation,
                ),
            >,
        ) -> Self {
            Self {
                observations: observations.into_iter().collect(),
                observed: Vec::new(),
                shared_observed: None,
                before_observe: None,
                failing: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::broadcast::TxObserver for LifecycleObserver {
        async fn observe(
            &mut self,
            _network: crate::ZeckNetwork,
            txid: zcash_primitives::transaction::TxId,
            expiry_height: Option<u32>,
        ) -> ZeckResult<crate::broadcast::TxObservation> {
            if let Some(before_observe) = self.before_observe.as_mut() {
                before_observe();
            }
            self.observed.push(txid);
            if let Some(shared) = &self.shared_observed {
                shared.lock().unwrap().push(txid);
            }
            if self.failing.contains(&txid) {
                return Err(ZeckError::Broadcast("observer unreachable".into()));
            }
            let (expected, mut observation) = self
                .observations
                .pop_front()
                .expect("unexpected observation");
            assert_eq!(txid, expected);
            assert_eq!(expiry_height, observation.expiry_height);
            observation.expiry_height = expiry_height;
            Ok(observation)
        }
    }

    fn lifecycle_note(value: u64, id: u8) -> SpendableSproutNote {
        let mut result = note(value);
        result.outpoint.txid = [id; 32];
        result
    }

    fn fixture_transaction(seed: u32, expiry: u32) -> crate::broadcast::PreparedTransaction {
        use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
        let tx = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            seed,
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
        crate::broadcast::PreparedTransaction {
            txid: tx.txid(),
            raw_tx,
            fee_zatoshis: SPROUT_SWEEP_FEE,
            expiry_height: Some(expiry),
        }
    }

    fn endpoint(
        operator: &str,
        tip: u32,
        reported_height: Option<u32>,
        tx_in_block: bool,
    ) -> crate::broadcast::EndpointTxEvidence {
        crate::broadcast::EndpointTxEvidence {
            operator_id: operator.to_owned(),
            endpoint: format!("https://{operator}.example"),
            tip_height: Some(tip),
            reported_height,
            block_hash: reported_height
                .filter(|height| *height != 0 && *height != u32::MAX)
                .map(|height| vec![height as u8; 32]),
            tx_in_block,
        }
    }

    fn absent(expiry: Option<u32>, tip: u32) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(
            vec![
                endpoint("alpha", tip, None, false),
                endpoint("bravo", tip, None, false),
            ],
            expiry,
        )
    }

    fn mined(expiry: Option<u32>, height: u32, tip: u32) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(
            vec![
                endpoint("alpha", tip, Some(height), true),
                endpoint("bravo", tip, Some(height), true),
            ],
            expiry,
        )
    }

    fn mined_by_one_source(
        expiry: Option<u32>,
        height: u32,
        tip: u32,
    ) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(
            vec![endpoint("alpha", tip, Some(height), true)],
            expiry,
        )
    }

    fn unavailable(expiry: Option<u32>, tip: u32) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(vec![endpoint("alpha", tip, None, false)], expiry)
    }

    fn unavailable_without_tip(expiry: Option<u32>) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(Vec::new(), expiry)
    }

    fn first_expired_tip(expiry: u32) -> u32 {
        expiry
            .saturating_add(crate::broadcast::EXPIRY_MARGIN_BLOCKS)
            .saturating_add(1)
    }

    fn contested(expiry: Option<u32>, height: u32, tip: u32) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(
            vec![
                endpoint("alpha", tip, Some(height), true),
                endpoint("bravo", tip, None, false),
            ],
            expiry,
        )
    }

    fn reorged(expiry: Option<u32>, tip: u32) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(
            vec![
                endpoint("alpha", tip, Some(u32::MAX), false),
                endpoint("bravo", tip, Some(u32::MAX), false),
            ],
            expiry,
        )
    }

    fn reorged_with_absent_sources(
        expiry: Option<u32>,
        tip: u32,
        absent_sources: usize,
    ) -> crate::broadcast::TxObservation {
        let mut evidence = vec![endpoint("primary", tip, Some(u32::MAX), false)];
        evidence.extend(
            ["alpha", "bravo"]
                .into_iter()
                .take(absent_sources)
                .map(|operator| endpoint(operator, tip, None, false)),
        );
        crate::broadcast::observe_transaction(evidence, expiry)
    }

    fn lifecycle_journal(dir: &Path) -> crate::sprout_sweep_journal::SweepJournal {
        crate::sprout_sweep_journal::SweepJournal::for_keys(
            dir,
            &[[0x42; 32]],
            crate::ZeckNetwork::Mainnet,
        )
    }

    fn seed_entry(
        journal: &crate::sprout_sweep_journal::SweepJournal,
        note: &SpendableSproutNote,
        tx: &crate::broadcast::PreparedTransaction,
        state: crate::broadcast::TxLifecycleState,
    ) {
        use crate::broadcast::{BroadcastStore, SubmissionDisposition, TxLifecycleState};
        let mut snapshot = journal.load_or_migrate().unwrap();
        journal
            .scoped_store(
                crate::sprout_sweep_journal::JournalNoteContext {
                    outpoint: note.outpoint,
                    value_zatoshis: note.note.value - SPROUT_SWEEP_FEE,
                },
                &mut snapshot,
            )
            .persist_prepared(tx)
            .unwrap();
        if state == TxLifecycleState::NotSubmitted {
            return;
        }
        journal
            .append_transition(
                &mut snapshot,
                tx.txid,
                TxLifecycleState::SubmissionUnknown,
                None,
                None,
            )
            .unwrap();
        if matches!(state, TxLifecycleState::Pending | TxLifecycleState::Mined) {
            journal
                .append_transition(
                    &mut snapshot,
                    tx.txid,
                    TxLifecycleState::Pending,
                    Some(&SubmissionDisposition::Accepted),
                    None,
                )
                .unwrap();
        }
        if state == TxLifecycleState::Mined {
            let observation = mined(tx.expiry_height, 90, 100);
            journal
                .append_transition(
                    &mut snapshot,
                    tx.txid,
                    TxLifecycleState::Mined,
                    None,
                    Some(&observation),
                )
                .unwrap();
        }
    }

    fn run_lifecycle(
        notes: &[SpendableSproutNote],
        node: &mut LifecycleNode,
        observer: &mut LifecycleObserver,
        journal: &crate::sprout_sweep_journal::SweepJournal,
        build_seed: u32,
    ) -> (SproutSweepOutcome, usize, Vec<Vec<u8>>) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut build_count = 0;
        let mut built_raw = Vec::new();
        let outcome = runtime.block_on(run_sweep(
            notes,
            node,
            observer,
            crate::ZeckNetwork::Mainnet,
            |note: &SpendableSproutNote, expiry: BlockHeight, _| {
                build_count += 1;
                let tx = fixture_transaction(build_seed + build_count as u32, expiry.into());
                built_raw.push(tx.raw_tx.clone());
                Ok(BuiltSproutSweep {
                    txid: tx.txid.to_string(),
                    raw: tx.raw_tx,
                    value_swept: note.note.value - SPROUT_SWEEP_FEE,
                })
            },
            NoteSource::WalletFile,
            journal,
            |_| {},
        ));
        (outcome, build_count, built_raw)
    }

    #[test]
    fn accepted_transaction_is_pending_not_swept() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [lifecycle_note(1_000_000, 1)];
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 10);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::Pending
        );
        assert_eq!(outcome.mined_zatoshis, 0);
        assert_eq!(outcome.pending_zatoshis, 1_000_000 - SPROUT_SWEEP_FEE);
    }

    #[test]
    fn single_source_mining_remains_pending_value_until_corroborated() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 71);
        let tx = fixture_transaction(710, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let mut node = LifecycleNode::accepted(150, 0);
        let observation = mined_by_one_source(tx.expiry_height, 110, 150);
        assert_eq!(
            observation.state,
            crate::broadcast::TxObservationState::MinedSingleSource
        );
        let mut observer = LifecycleObserver::new([(tx.txid, observation)]);

        let (outcome, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            711,
        );

        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::MinedSingleSource
        );
        assert_eq!(outcome.mined_zatoshis, 0);
        assert_eq!(outcome.pending_zatoshis, note.note.value - SPROUT_SWEEP_FEE);
        assert!(!outcome.fresh_all_mined);
    }

    #[test]
    fn prepared_record_is_durable_before_send_is_invoked() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let inspect = journal.clone();
        let notes = [lifecycle_note(1_000_000, 2)];
        let mut node = LifecycleNode::accepted(100, 1);
        node.before_send = Some(Box::new(move |raw| {
            let snapshot = inspect.load_or_migrate().unwrap();
            let entry = snapshot.entries().next().expect("prepared entry");
            assert_eq!(
                entry.state,
                crate::broadcast::TxLifecycleState::SubmissionUnknown
            );
            assert_eq!(entry.transaction.as_ref().unwrap().raw_tx, raw);
        }));
        let mut observer = LifecycleObserver::default();
        let (_, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 20);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
    }

    #[test]
    fn overlapping_sibling_key_sets_stop_before_network_proving_or_send() {
        use crate::broadcast::TxLifecycleState;

        for (current_keys, sibling_keys) in [
            (vec![[0x42; 32]], vec![[0x42; 32], [0x24; 32]]),
            (vec![[0x42; 32], [0x24; 32]], vec![[0x42; 32]]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let current = crate::sprout_sweep_journal::SweepJournal::for_keys(
                dir.path(),
                &current_keys,
                crate::ZeckNetwork::Mainnet,
            );
            let sibling = crate::sprout_sweep_journal::SweepJournal::for_keys(
                dir.path(),
                &sibling_keys,
                crate::ZeckNetwork::Mainnet,
            );
            let note = lifecycle_note(1_000_000, 201);
            seed_entry(
                &sibling,
                &note,
                &fixture_transaction(901, 140),
                TxLifecycleState::Pending,
            );

            let mut node = LifecycleNode::accepted(100, 1);
            let mut observer = LifecycleObserver::default();
            let (outcome, builds, _) =
                run_lifecycle(&[note], &mut node, &mut observer, &current, 902);

            let error = outcome.error.expect("overlapping journal must fail closed");
            assert!(error.contains("overlap"), "{error}");
            assert!(
                error.contains(&current.path().display().to_string()),
                "{error}"
            );
            assert!(
                error.contains(&sibling.path().display().to_string()),
                "{error}"
            );
            assert!(
                error.contains("original") && error.contains("data dir"),
                "{error}"
            );
            assert_eq!(node.tip_calls, 0, "network tip must not be queried");
            assert!(observer.observed.is_empty(), "observer must not run");
            assert_eq!(builds, 0, "prover/builder must not run");
            assert!(node.sent.is_empty(), "no transaction may be sent");
        }
    }

    #[test]
    fn malformed_sibling_journal_stops_before_network_proving_or_send() {
        let dir = tempfile::tempdir().unwrap();
        let current = lifecycle_journal(dir.path());
        let malformed = dir.path().join("sprout-sweep-deadbeefdeadbeef.journal");
        std::fs::write(&malformed, b"{not valid json}\n").unwrap();
        let note = lifecycle_note(1_000_000, 202);
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::default();

        let (outcome, builds, _) = run_lifecycle(&[note], &mut node, &mut observer, &current, 903);

        let error = outcome.error.expect("malformed sibling must fail closed");
        assert!(error.contains(&malformed.display().to_string()), "{error}");
        assert_eq!(node.tip_calls, 0);
        assert!(observer.observed.is_empty());
        assert_eq!(builds, 0);
        assert!(node.sent.is_empty());
    }

    #[test]
    fn legacy_sibling_overlap_is_inspected_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let current = lifecycle_journal(dir.path());
        let sibling = crate::sprout_sweep_journal::SweepJournal::for_keys(
            dir.path(),
            &[[0x42; 32], [0x24; 32]],
            crate::ZeckNetwork::Mainnet,
        );
        let legacy = format!("{}:0:0 {}\n", "cb".repeat(32), "33".repeat(32));
        std::fs::write(sibling.path(), legacy.as_bytes()).unwrap();
        let note = lifecycle_note(1_000_000, 0xcb);
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::default();

        let (outcome, builds, _) = run_lifecycle(&[note], &mut node, &mut observer, &current, 904);

        assert!(outcome
            .error
            .as_deref()
            .is_some_and(|error| error.contains("overlap")));
        assert_eq!(std::fs::read(sibling.path()).unwrap(), legacy.as_bytes());
        assert_eq!(node.tip_calls, 0);
        assert!(observer.observed.is_empty());
        assert_eq!(builds, 0);
        assert!(node.sent.is_empty());
    }

    #[test]
    fn sibling_created_during_proving_blocks_the_new_transaction_send() {
        let dir = tempfile::tempdir().unwrap();
        let current = lifecycle_journal(dir.path());
        let sibling = crate::sprout_sweep_journal::SweepJournal::for_keys(
            dir.path(),
            &[[0x42; 32], [0x24; 32]],
            crate::ZeckNetwork::Mainnet,
        );
        let note = lifecycle_note(1_000_000, 0xd1);
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut builds = 0;
        let outcome = runtime.block_on(run_sweep(
            &[note],
            &mut node,
            &mut observer,
            crate::ZeckNetwork::Mainnet,
            |note, expiry, _| {
                builds += 1;
                seed_entry(
                    &sibling,
                    note,
                    &fixture_transaction(905, expiry.into()),
                    crate::TxLifecycleState::Pending,
                );
                let tx = fixture_transaction(906, expiry.into());
                Ok(BuiltSproutSweep {
                    txid: tx.txid.to_string(),
                    raw: tx.raw_tx,
                    value_swept: note.note.value - SPROUT_SWEEP_FEE,
                })
            },
            NoteSource::WalletFile,
            &current,
            |_| {},
        ));
        assert_eq!(builds, 1);
        assert!(outcome
            .error
            .as_deref()
            .is_some_and(|error| error.contains("overlap")));
        assert!(
            node.sent.is_empty(),
            "the post-proof scope check must precede send"
        );
    }

    #[test]
    fn sibling_created_during_observation_blocks_exact_byte_retry() {
        let dir = tempfile::tempdir().unwrap();
        let current = lifecycle_journal(dir.path());
        let sibling = crate::sprout_sweep_journal::SweepJournal::for_keys(
            dir.path(),
            &[[0x42; 32], [0x24; 32]],
            crate::ZeckNetwork::Mainnet,
        );
        let note = lifecycle_note(1_000_000, 0xd2);
        let tx = fixture_transaction(907, 140);
        seed_entry(
            &current,
            &note,
            &tx,
            crate::TxLifecycleState::SubmissionUnknown,
        );
        let sibling_note = lifecycle_note(1_000_000, 0xd2);
        let mut observer = LifecycleObserver::new([(tx.txid, absent(tx.expiry_height, 100))]);
        observer.before_observe = Some(Box::new(move || {
            seed_entry(
                &sibling,
                &sibling_note,
                &fixture_transaction(908, 140),
                crate::TxLifecycleState::Pending,
            );
        }));
        let mut node = LifecycleNode::accepted(100, 1);

        let (outcome, builds, _) = run_lifecycle(&[note], &mut node, &mut observer, &current, 909);

        assert_eq!(builds, 0);
        assert!(outcome
            .error
            .as_deref()
            .is_some_and(|error| error.contains("overlap")));
        assert!(
            node.sent.is_empty(),
            "the post-observation scope check must precede retry"
        );
    }

    #[test]
    fn restart_after_prepared_sync_submits_the_same_raw_transaction_without_rebuilding() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 3);
        let tx = fixture_transaction(30, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::NotSubmitted,
        );
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::default();
        let (_, builds, raw) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 31);
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert_eq!(node.sent, vec![tx.raw_tx]);
    }

    #[test]
    fn transport_failure_records_unknown_and_stops_the_next_note() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [lifecycle_note(1_000_000, 4), lifecycle_note(2_000_000, 5)];
        let mut node = LifecycleNode {
            tip: 100,
            tip_calls: 0,
            replies: [Err(tonic::Status::unavailable("lost reply"))].into(),
            sent: Vec::new(),
            before_send: None,
        };
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 40);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::SubmissionUnknown
        );
        assert!(outcome.error.is_some());
    }

    #[test]
    fn pending_but_absent_transaction_is_rebroadcast_byte_for_byte_while_valid() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 6);
        let tx = fixture_transaction(50, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::new([(tx.txid, absent(Some(140), 120))]);
        let (_, builds, raw) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 51);
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert_eq!(node.sent, vec![tx.raw_tx]);
    }

    #[test]
    fn all_active_records_are_observed_before_exact_retries_in_journal_order() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [lifecycle_note(1_000_000, 22), lifecycle_note(2_000_000, 23)];
        let first = fixture_transaction(52, 140);
        let second = fixture_transaction(53, 140);
        seed_entry(
            &journal,
            &notes[0],
            &first,
            crate::broadcast::TxLifecycleState::Pending,
        );
        seed_entry(
            &journal,
            &notes[1],
            &second,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut observer = LifecycleObserver::new([
            (first.txid, absent(Some(140), 120)),
            (second.txid, absent(Some(140), 120)),
        ]);
        observer.shared_observed = Some(observed.clone());
        let mut node = LifecycleNode::accepted(120, 2);
        node.before_send = Some(Box::new(move |_| {
            assert_eq!(observed.lock().unwrap().len(), 2);
        }));
        let (_, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 54);
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert_eq!(node.sent, vec![first.raw_tx, second.raw_tx]);
    }

    #[tokio::test]
    async fn operation_guard_remains_held_through_observe_retry_build_and_send() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let pending_note = lifecycle_note(1_000_000, 31);
        let ready_note = lifecycle_note(1_100_000, 32);
        let pending = fixture_transaction(310, 140);
        seed_entry(
            &journal,
            &pending_note,
            &pending,
            crate::broadcast::TxLifecycleState::Pending,
        );

        let observe_path = dir.path().to_path_buf();
        let mut observer =
            LifecycleObserver::new([(pending.txid, absent(pending.expiry_height, 120))]);
        observer.before_observe = Some(Box::new(move || {
            assert!(crate::service::NetworkOperationGuard::acquire(
                &observe_path,
                crate::ZeckNetwork::Mainnet,
            )
            .is_err());
        }));

        let send_path = dir.path().to_path_buf();
        let mut node = LifecycleNode::accepted(120, 2);
        node.before_send = Some(Box::new(move |_| {
            assert!(crate::service::NetworkOperationGuard::acquire(
                &send_path,
                crate::ZeckNetwork::Mainnet,
            )
            .is_err());
        }));

        let build_path = dir.path().to_path_buf();
        let mut build_count = 0;
        let outcome = with_sprout_operation_guard(dir.path(), crate::ZeckNetwork::Mainnet, async {
            Ok(run_sweep(
                &[pending_note, ready_note],
                &mut node,
                &mut observer,
                crate::ZeckNetwork::Mainnet,
                |note: &SpendableSproutNote, expiry: BlockHeight, _| {
                    assert!(crate::service::NetworkOperationGuard::acquire(
                        &build_path,
                        crate::ZeckNetwork::Mainnet,
                    )
                    .is_err());
                    build_count += 1;
                    let tx = fixture_transaction(320, expiry.into());
                    Ok(BuiltSproutSweep {
                        txid: tx.txid.to_string(),
                        raw: tx.raw_tx,
                        value_swept: note.note.value - SPROUT_SWEEP_FEE,
                    })
                },
                NoteSource::WalletFile,
                &journal,
                |_| {},
            )
            .await)
        })
        .await
        .unwrap();

        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(build_count, 1);
        assert_eq!(node.sent.len(), 2, "one retry and one new submission");
        assert!(crate::service::NetworkOperationGuard::acquire(
            dir.path(),
            crate::ZeckNetwork::Mainnet,
        )
        .is_ok());
    }

    #[test]
    fn absence_at_expiry_height_does_not_release_the_note() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 7);
        let tx = fixture_transaction(60, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let mut node = LifecycleNode::accepted(140, 1);
        let mut observer = LifecycleObserver::new([(tx.txid, absent(Some(140), 140))]);
        let (_, builds, raw) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 61);
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert_eq!(node.sent, vec![tx.raw_tx]);
    }

    #[test]
    fn absence_past_expiry_returns_the_note_to_planning() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 8);
        let old = fixture_transaction(70, 140);
        seed_entry(
            &journal,
            &note,
            &old,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let expired_tip = first_expired_tip(140);
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let expired_absence = absent(Some(140), expired_tip);
        assert!(expired_absence.is_expired());
        let mut observer = LifecycleObserver::new([(old.txid, expired_absence)]);
        let (_, builds, raw) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 71);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert_ne!(node.sent[0], old.raw_tx);
    }

    #[test]
    fn evicted_transaction_is_rebroadcast_not_rebuilt_before_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 9);
        let later = lifecycle_note(2_000_000, 19);
        let tx = fixture_transaction(80, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let mut node = LifecycleNode::reply(120, -26, "mempool eviction");
        let mut observer = LifecycleObserver::new([(tx.txid, absent(Some(140), 120))]);
        let (_, builds, raw) =
            run_lifecycle(&[note, later], &mut node, &mut observer, &journal, 81);
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert_eq!(node.sent, vec![tx.raw_tx]);
    }

    #[test]
    fn deterministic_rejection_allows_the_next_reviewed_note() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [lifecycle_note(1_000_000, 20), lifecycle_note(2_000_000, 21)];
        let mut node = LifecycleNode::reply(120, -26, "invalid proof");
        node.replies
            .push_back(Ok(zcash_client_backend::proto::service::SendResponse {
                error_code: 0,
                error_message: String::new(),
            }));
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 82);
        assert_eq!(builds, 2);
        assert_eq!(node.sent, raw);
        assert_eq!(node.sent.len(), 2);
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::Rejected
        );
        assert_eq!(
            outcome.transactions[1].state,
            crate::broadcast::TxLifecycleState::Pending
        );
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
    }

    #[test]
    fn canonically_mined_transaction_is_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 10);
        let tx = fixture_transaction(90, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let mut node = LifecycleNode::accepted(120, 0);
        let mut observer = LifecycleObserver::new([(tx.txid, mined(Some(140), 110, 120))]);
        let expected_value = note.note.value - SPROUT_SWEEP_FEE;
        let (outcome, builds, raw) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 91);
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert!(node.sent.is_empty());
        assert_eq!(outcome.mined_zatoshis, expected_value);
        assert!(outcome.fresh_all_mined);
    }

    #[test]
    fn contested_or_single_endpoint_evidence_never_releases_the_note() {
        for (id, observation) in [
            (11, contested(Some(140), 110, 150)),
            (12, unavailable(Some(140), 150)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let journal = lifecycle_journal(dir.path());
            let note = lifecycle_note(1_000_000, id);
            let tx = fixture_transaction(100 + id as u32, 140);
            seed_entry(
                &journal,
                &note,
                &tx,
                crate::broadcast::TxLifecycleState::Pending,
            );
            let mut node = LifecycleNode::accepted(150, 0);
            let mut observer = LifecycleObserver::new([(tx.txid, observation)]);
            let outpoint = note.outpoint;
            let (_, builds, raw) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 110);
            assert_eq!(builds, 0);
            assert!(raw.is_empty());
            assert!(node.sent.is_empty());
            assert!(!journal
                .load_or_migrate()
                .unwrap()
                .ready_for_new_plan(&outpoint));
        }
    }

    #[test]
    fn reorged_out_mined_transaction_returns_to_pending_or_expired() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 13);
        let old = fixture_transaction(120, 140);
        seed_entry(
            &journal,
            &note,
            &old,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let mut node = LifecycleNode::accepted(120, 1);
        let mut observer = LifecycleObserver::new([(old.txid, reorged(Some(140), 120))]);
        let (_, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            121,
        );
        assert_eq!(builds, 0);
        assert!(raw.is_empty());
        assert_eq!(node.sent, vec![old.raw_tx.clone()]);

        let expired_tip = first_expired_tip(140);
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let mut observer = LifecycleObserver::new([(old.txid, absent(Some(140), expired_tip))]);
        let (outcome, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &journal, 122);
        assert_eq!(builds, 1, "{:?}", outcome.error);
        assert_eq!(node.sent, raw);
        assert_ne!(node.sent[0], old.raw_tx);
    }

    #[test]
    fn reorged_mined_transaction_expires_only_from_absence_past_the_margin() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 33);
        let old = fixture_transaction(330, 140);
        seed_entry(
            &journal,
            &note,
            &old,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let expired_tip = first_expired_tip(140);
        let observation = reorged_with_absent_sources(old.expiry_height, expired_tip, 1);
        assert_eq!(
            observation.state,
            crate::broadcast::TxObservationState::Reorged
        );
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let mut observer = LifecycleObserver::new([(old.txid, observation)]);

        let (_, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            331,
        );

        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert_ne!(node.sent[0], old.raw_tx);
        let durable = std::fs::read_to_string(journal.path()).unwrap();
        assert!(durable.contains(&old.txid.to_string()));
        assert!(durable.contains("\"state\":\"expired\""));

        let one_source_dir = tempfile::tempdir().unwrap();
        let one_source_journal = lifecycle_journal(one_source_dir.path());
        seed_entry(
            &one_source_journal,
            &note,
            &old,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let no_absence = reorged_with_absent_sources(old.expiry_height, expired_tip, 0);
        let mut node = LifecycleNode::accepted(expired_tip, 0);
        let mut observer = LifecycleObserver::new([(old.txid, no_absence)]);
        let (_, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &one_source_journal, 332);
        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        assert_eq!(
            one_source_journal
                .load_or_migrate()
                .unwrap()
                .entry_for_txid(old.txid)
                .unwrap()
                .state,
            crate::broadcast::TxLifecycleState::Pending
        );
    }

    #[test]
    fn stored_mined_entry_is_reobserved_before_fresh_all_mined() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 14);
        let tx = fixture_transaction(130, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let mut node = LifecycleNode::accepted(150, 0);
        let mut observer = LifecycleObserver::new([(tx.txid, unavailable(Some(140), 150))]);
        let (outcome, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            131,
        );
        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        assert!(!outcome.fresh_all_mined);

        let mut node = LifecycleNode::accepted(150, 0);
        let mut observer = LifecycleObserver::new([(tx.txid, mined(Some(140), 110, 150))]);
        let (outcome, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &journal, 132);
        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        assert!(outcome.fresh_all_mined);
    }

    #[test]
    fn orphan_stored_mined_entry_prevents_fresh_all_mined_when_observation_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let recovered_note = lifecycle_note(1_000_000, 60);
        let orphan_note = lifecycle_note(2_000_000, 61);
        let recovered_tx = fixture_transaction(600, 140);
        let orphan_tx = fixture_transaction(601, 140);
        seed_entry(
            &journal,
            &recovered_note,
            &recovered_tx,
            crate::broadcast::TxLifecycleState::Mined,
        );
        seed_entry(
            &journal,
            &orphan_note,
            &orphan_tx,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let mut node = LifecycleNode::accepted(150, 0);
        let mut observer = LifecycleObserver::new([
            (recovered_tx.txid, mined(Some(140), 110, 150)),
            (orphan_tx.txid, unavailable(Some(140), 150)),
        ]);

        let (outcome, builds, raw) = run_lifecycle(
            std::slice::from_ref(&recovered_note),
            &mut node,
            &mut observer,
            &journal,
            602,
        );

        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        assert_eq!(outcome.transactions.len(), 2);
        assert!(outcome
            .transactions
            .iter()
            .any(|transaction| transaction.txid == orphan_tx.txid.to_string()));
        assert!(
            !outcome.fresh_all_mined,
            "an unavailable orphan transaction makes the whole wallet journal nonfinal"
        );
    }

    #[test]
    fn stored_mined_contested_or_unavailable_is_not_downgraded() {
        for (offset, fresh_observation) in [
            unavailable_without_tip(Some(140)),
            contested(Some(140), 110, 150),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = tempfile::tempdir().unwrap();
            let journal = lifecycle_journal(dir.path());
            let note = lifecycle_note(1_000_000, 40 + offset as u8);
            let tx = fixture_transaction(400 + offset as u32, 140);
            seed_entry(
                &journal,
                &note,
                &tx,
                crate::broadcast::TxLifecycleState::Mined,
            );
            let mut node = LifecycleNode::accepted(150, 0);
            let mut observer = LifecycleObserver::new([(tx.txid, fresh_observation)]);

            let (outcome, builds, raw) = run_lifecycle(
                std::slice::from_ref(&note),
                &mut node,
                &mut observer,
                &journal,
                410 + offset as u32,
            );

            assert_eq!(builds, 0);
            assert!(raw.is_empty() && node.sent.is_empty());
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
            assert!(!outcome.fresh_all_mined);
            assert_eq!(outcome.mined_zatoshis, note.note.value - SPROUT_SWEEP_FEE);
            assert_eq!(outcome.pending_zatoshis, 0);
            assert_eq!(
                outcome.transactions[0].state,
                crate::broadcast::TxLifecycleState::Mined
            );
            assert_eq!(
                journal
                    .load_or_migrate()
                    .unwrap()
                    .entry_for_txid(tx.txid)
                    .unwrap()
                    .state,
                crate::broadcast::TxLifecycleState::Mined
            );
        }
    }

    #[test]
    fn legacy_unknown_without_raw_waits_a_conservative_expiry_window() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 15);
        let legacy_txid = zcash_primitives::transaction::TxId::from_bytes([0xab; 32]);
        let note_txid: String = note
            .outpoint
            .txid
            .iter()
            .rev()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        std::fs::write(
            journal.path(),
            format!(
                "{note_txid}:{}:{} {legacy_txid}\n",
                note.outpoint.js_index, note.outpoint.output_index
            ),
        )
        .unwrap();
        let mut node = LifecycleNode::accepted(100, 0);
        let mut observer = LifecycleObserver::new([(legacy_txid, absent(None, 100))]);
        let (outcome, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            140,
        );
        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        // A v1 entry is Pending: it waits without stopping the sweep.
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .entry_for_note(&note.outpoint)
                .unwrap()
                .legacy_expiry_bound,
            Some(140)
        );

        let mut node = LifecycleNode::accepted(140, 0);
        let mut observer = LifecycleObserver::new([(legacy_txid, absent(Some(140), 140))]);
        let (outcome, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            141,
        );
        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        // A v1 entry is Pending: it waits without stopping the sweep.
        assert!(outcome.error.is_none(), "{:?}", outcome.error);

        let expired_tip = first_expired_tip(140);
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let mut observer = LifecycleObserver::new([(legacy_txid, absent(Some(140), expired_tip))]);
        let (_, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &journal, expired_tip);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
    }

    #[test]
    fn legacy_expiry_bound_uses_the_highest_tip_corroborated_by_a_pair() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 34);
        let legacy_txid = zcash_primitives::transaction::TxId::from_bytes([0xbc; 32]);
        let note_txid: String = note
            .outpoint
            .txid
            .iter()
            .rev()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        std::fs::write(
            journal.path(),
            format!(
                "{note_txid}:{}:{} {legacy_txid}\n",
                note.outpoint.js_index, note.outpoint.output_index
            ),
        )
        .unwrap();
        let observation = crate::broadcast::observe_transaction(
            vec![
                endpoint("alpha", 100, None, false),
                endpoint("bravo", 100, None, false),
                endpoint("mallory-high", 4_000_000_000, None, false),
                endpoint("mallory-low", 1, None, false),
            ],
            None,
        );
        let mut node = LifecycleNode::accepted(100, 0);
        let mut observer = LifecycleObserver::new([(legacy_txid, observation)]);

        let (outcome, builds, raw) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            340,
        );

        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        // A v1 entry is Pending: it waits without stopping the sweep.
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .entry_for_note(&note.outpoint)
                .unwrap()
                .legacy_expiry_bound,
            Some(140)
        );
    }

    #[test]
    fn journal_write_failure_before_send_performs_no_network_io() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 16);
        let mut node = LifecycleNode::accepted(100, 0);
        let mut observer = LifecycleObserver::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut builds = 0;
        let mut raw = Vec::new();
        let path = journal.path().to_path_buf();
        let outcome = runtime.block_on(run_sweep(
            &[note],
            &mut node,
            &mut observer,
            crate::ZeckNetwork::Mainnet,
            |note: &SpendableSproutNote, expiry: BlockHeight, _| {
                builds += 1;
                let tx = fixture_transaction(151, expiry.into());
                raw.push(tx.raw_tx.clone());
                std::fs::create_dir(&path).unwrap();
                Ok(BuiltSproutSweep {
                    txid: tx.txid.to_string(),
                    raw: tx.raw_tx,
                    value_swept: note.note.value - SPROUT_SWEEP_FEE,
                })
            },
            NoteSource::WalletFile,
            &journal,
            |_| {},
        ));
        assert_eq!(builds, 1);
        assert_eq!(raw.len(), 1);
        assert!(node.sent.is_empty());
        assert!(outcome.error.is_some());
    }

    #[test]
    fn journal_transition_failure_after_send_stops_later_notes() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let corrupt = journal.path().to_path_buf();
        let notes = [lifecycle_note(1_000_000, 17), lifecycle_note(2_000_000, 18)];
        let mut node = LifecycleNode::accepted(100, 1);
        node.before_send = Some(Box::new(move |_| {
            std::fs::write(&corrupt, b"corrupt\n").unwrap();
        }));
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 160);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert!(outcome.error.is_some());
    }

    fn replies(tip: u32, replies: &[(i32, &str)]) -> LifecycleNode {
        LifecycleNode {
            tip,
            tip_calls: 0,
            replies: replies
                .iter()
                .map(|(code, message)| {
                    Ok(zcash_client_backend::proto::service::SendResponse {
                        error_code: *code,
                        error_message: (*message).to_owned(),
                    })
                })
                .collect(),
            sent: Vec::new(),
            before_send: None,
        }
    }

    #[test]
    fn a_note_refused_as_spent_is_rejected_and_the_next_note_is_still_swept() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [lifecycle_note(1_000_000, 90), lifecycle_note(2_000_000, 91)];
        let mut node = replies(
            120,
            &[(-26, "bad-txns-sprout-duplicate-nullifier"), (0, "")],
        );
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, raw) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 900);
        assert_eq!(builds, 2, "{:?}", outcome.error);
        assert_eq!(node.sent, raw);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(outcome.rejected.len(), 1);
        assert_eq!(outcome.rejected[0].kind, Refusal::Spent);
        assert_eq!(outcome.rejected[0].outpoint, notes[0].outpoint);
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::Rejected
        );
        assert_eq!(
            outcome.transactions[1].state,
            crate::broadcast::TxLifecycleState::Pending
        );
        assert_eq!(outcome.pending_zatoshis, 2_000_000 - SPROUT_SWEEP_FEE);
        assert!(!outcome.fresh_all_mined);
        let snapshot = journal.load_or_migrate().unwrap();
        assert!(snapshot.ready_for_new_plan(&notes[0].outpoint));
    }

    #[test]
    fn each_per_note_refusal_kind_is_recorded_and_carried_past() {
        for (id, message, kind) in [
            (92, "bad-txns-sprout-unknown-anchor", Refusal::UnknownAnchor),
            (
                93,
                "transaction already spent some of its inputs",
                Refusal::PendingSpend,
            ),
            (94, "zip-401 denial of service limits", Refusal::Evicted),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let journal = lifecycle_journal(dir.path());
            let notes = [
                lifecycle_note(1_000_000, id),
                lifecycle_note(2_000_000, id + 50),
            ];
            let mut node = replies(120, &[(-26, message), (0, "")]);
            let mut observer = LifecycleObserver::default();
            let (outcome, builds, _) =
                run_lifecycle(&notes, &mut node, &mut observer, &journal, 920 + id as u32);
            assert_eq!(builds, 2, "{message}: {:?}", outcome.error);
            assert!(outcome.error.is_none(), "{message}: {:?}", outcome.error);
            assert_eq!(outcome.rejected.len(), 1, "{message}");
            assert_eq!(outcome.rejected[0].kind, kind, "{message}");
            assert_eq!(outcome.rejected[0].reason, message);
        }
    }

    #[test]
    fn a_refusal_about_the_node_still_stops_the_sweep_as_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [lifecycle_note(1_000_000, 95), lifecycle_note(2_000_000, 96)];
        let mut node = replies(120, &[(-1, "something unfamiliar")]);
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, _) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 950);
        assert_eq!(builds, 1);
        assert!(outcome.error.is_some());
        assert!(outcome.rejected.is_empty());
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::SubmissionUnknown
        );
    }

    #[test]
    fn a_run_of_unknown_anchors_with_nothing_accepted_stops_and_names_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let notes = [
            lifecycle_note(1_000_000, 97),
            lifecycle_note(1_000_000, 98),
            lifecycle_note(1_000_000, 99),
            lifecycle_note(1_000_000, 100),
        ];
        let anchor = (-26, "bad-txns-sprout-unknown-anchor");
        let mut node = replies(120, &[anchor, anchor, anchor]);
        let mut observer = LifecycleObserver::default();
        let (outcome, builds, _) = run_lifecycle(&notes, &mut node, &mut observer, &journal, 970);
        assert_eq!(builds, UNKNOWN_ANCHOR_BREAKER);
        assert_eq!(outcome.rejected.len(), UNKNOWN_ANCHOR_BREAKER);
        assert!(outcome
            .error
            .as_deref()
            .is_some_and(|error| error.contains("lightwalletd server")));
    }

    fn one_operator_absent(expiry: Option<u32>, tip: u32) -> crate::broadcast::TxObservation {
        crate::broadcast::observe_transaction(vec![endpoint("primary", tip, None, false)], expiry)
    }

    fn write_legacy_line(
        journal: &crate::sprout_sweep_journal::SweepJournal,
        note: &SpendableSproutNote,
        legacy_txid: zcash_primitives::transaction::TxId,
    ) {
        let note_txid: String = note
            .outpoint
            .txid
            .iter()
            .rev()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        std::fs::write(
            journal.path(),
            format!(
                "{note_txid}:{}:{} {legacy_txid}\n",
                note.outpoint.js_index, note.outpoint.output_index
            ),
        )
        .unwrap();
    }

    #[test]
    fn default_single_operator_resolves_a_lost_reply_to_expired_and_replans() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 101);
        let old = fixture_transaction(1010, 140);
        seed_entry(
            &journal,
            &note,
            &old,
            crate::broadcast::TxLifecycleState::SubmissionUnknown,
        );

        // Inside the margin the one configured source cannot release it.
        let inside = 140 + crate::broadcast::EXPIRY_MARGIN_BLOCKS;
        let mut node = LifecycleNode::accepted(inside, 0);
        let mut observer =
            LifecycleObserver::new([(old.txid, one_operator_absent(Some(140), inside))]);
        let (outcome, builds, _) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            1011,
        );
        assert_eq!(builds, 0);
        assert!(node.sent.is_empty());
        assert!(outcome.error.is_some());

        let expired_tip = first_expired_tip(140);
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let mut observer =
            LifecycleObserver::new([(old.txid, one_operator_absent(Some(140), expired_tip))]);
        let (outcome, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &journal, 1012);
        assert_eq!(builds, 1, "{:?}", outcome.error);
        assert_eq!(node.sent, raw);
        assert_ne!(node.sent[0], old.raw_tx);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
    }

    #[test]
    fn one_operator_mining_resolves_without_stalling_or_offering_discard() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let mined_note = lifecycle_note(1_000_000, 102);
        let next_note = lifecycle_note(2_000_000, 103);
        let tx = fixture_transaction(1020, 140);
        seed_entry(
            &journal,
            &mined_note,
            &tx,
            crate::broadcast::TxLifecycleState::SubmissionUnknown,
        );
        let mut node = LifecycleNode::accepted(200, 1);
        let mut observer =
            LifecycleObserver::new([(tx.txid, mined_by_one_source(Some(140), 120, 200))]);
        let (outcome, builds, raw) = run_lifecycle(
            &[mined_note, next_note],
            &mut node,
            &mut observer,
            &journal,
            1021,
        );
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::MinedSingleSource
        );
        assert!(!outcome.fresh_all_mined);
    }

    #[test]
    fn a_v1_entry_under_one_operator_neither_blocks_other_notes_nor_waits_forever() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let legacy_note = lifecycle_note(1_000_000, 104);
        let other_note = lifecycle_note(2_000_000, 105);
        let legacy_txid = zcash_primitives::transaction::TxId::from_bytes([0xcd; 32]);
        write_legacy_line(&journal, &legacy_note, legacy_txid);

        // First pass: one source bounds the old expiry, and the other note
        // is swept rather than stopped behind it.
        let mut node = LifecycleNode::accepted(100, 1);
        let mut observer = LifecycleObserver::new([(legacy_txid, one_operator_absent(None, 100))]);
        let (outcome, builds, _) = run_lifecycle(
            &[lifecycle_note(1_000_000, 104), other_note],
            &mut node,
            &mut observer,
            &journal,
            1040,
        );
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(builds, 1);
        let bound = 100 + EXPIRY_DELTA;
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .entry_for_note(&legacy_note.outpoint)
                .unwrap()
                .legacy_expiry_bound,
            Some(bound)
        );

        // Past bound plus margin, the one source expires it and the note is
        // planned again.
        let expired_tip = first_expired_tip(bound);
        let other_txid = journal
            .load_or_migrate()
            .unwrap()
            .entries()
            .find(|entry| entry.outpoint != legacy_note.outpoint)
            .unwrap()
            .txid();
        let other_expiry = journal
            .load_or_migrate()
            .unwrap()
            .entry_for_txid(other_txid)
            .unwrap()
            .transaction
            .as_ref()
            .unwrap()
            .expiry_height;
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let mut observer = LifecycleObserver::new([
            (legacy_txid, one_operator_absent(Some(bound), expired_tip)),
            (
                other_txid,
                mined_by_one_source(other_expiry, 110, expired_tip),
            ),
        ]);
        let (outcome, builds, _) = run_lifecycle(
            std::slice::from_ref(&legacy_note),
            &mut node,
            &mut observer,
            &journal,
            1041,
        );
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(builds, 1);
    }

    #[test]
    fn a_v1_entry_mined_per_one_operator_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let legacy_note = lifecycle_note(1_000_000, 106);
        let legacy_txid = zcash_primitives::transaction::TxId::from_bytes([0xce; 32]);
        write_legacy_line(&journal, &legacy_note, legacy_txid);
        let mut node = LifecycleNode::accepted(200, 0);
        let mut observer =
            LifecycleObserver::new([(legacy_txid, mined_by_one_source(None, 120, 200))]);
        let (outcome, builds, _) = run_lifecycle(
            std::slice::from_ref(&legacy_note),
            &mut node,
            &mut observer,
            &journal,
            1060,
        );
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(builds, 0);
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::MinedSingleSource
        );
        assert!(!outcome.fresh_all_mined);
    }

    #[test]
    fn observer_error_for_a_stored_mined_entry_keeps_it_mined_but_never_final() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 107);
        let tx = fixture_transaction(1070, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let mut node = LifecycleNode::accepted(200, 0);
        let mut observer = LifecycleObserver::default();
        observer.failing.push(tx.txid);
        let (outcome, builds, _) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            1071,
        );
        assert_eq!(observer.observed, vec![tx.txid]);
        assert_eq!(builds, 0);
        assert!(node.sent.is_empty());
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::Mined
        );
        assert!(!outcome.fresh_all_mined);
    }

    #[test]
    fn corroborated_mining_below_the_discard_depth_is_not_final() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 108);
        let tx = fixture_transaction(1080, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let height = 110;
        let shallow_tip = height + crate::broadcast::MIN_DISCARD_CONFIRMATIONS - 2;
        let shallow = mined(Some(140), height, shallow_tip);
        assert!(shallow.has_canonical_mined_evidence());
        assert!(!shallow.is_safe_to_discard());
        let mut node = LifecycleNode::accepted(shallow_tip, 0);
        let mut observer = LifecycleObserver::new([(tx.txid, shallow)]);
        let expected = note.note.value - SPROUT_SWEEP_FEE;
        let (outcome, _, _) = run_lifecycle(
            std::slice::from_ref(&note),
            &mut node,
            &mut observer,
            &journal,
            1081,
        );
        assert_eq!(outcome.mined_zatoshis, expected);
        assert!(!outcome.fresh_all_mined);

        let deep_tip = height + crate::broadcast::MIN_DISCARD_CONFIRMATIONS - 1;
        let deep = mined(Some(140), height, deep_tip);
        assert!(deep.is_safe_to_discard());
        let mut node = LifecycleNode::accepted(deep_tip, 0);
        let mut observer = LifecycleObserver::new([(tx.txid, deep)]);
        let (outcome, _, _) = run_lifecycle(&[note], &mut node, &mut observer, &journal, 1082);
        assert!(outcome.fresh_all_mined, "{:?}", outcome.error);
    }

    #[test]
    fn a_replanned_note_keeps_its_expired_transaction_visible_as_superseded() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 109);
        let old = fixture_transaction(1090, 140);
        seed_entry(
            &journal,
            &note,
            &old,
            crate::broadcast::TxLifecycleState::Pending,
        );
        let expired_tip = first_expired_tip(140);
        let mut node = LifecycleNode::accepted(expired_tip, 1);
        let mut observer = LifecycleObserver::new([(old.txid, absent(Some(140), expired_tip))]);
        let (outcome, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &journal, 1091);
        assert_eq!(builds, 1);
        assert_eq!(node.sent, raw);
        assert_eq!(outcome.transactions.len(), 2, "{:?}", outcome.transactions);
        let old_summary = outcome
            .transactions
            .iter()
            .find(|transaction| transaction.txid == old.txid.to_string())
            .expect("the expired transaction stays visible");
        assert_eq!(
            old_summary.state,
            crate::broadcast::TxLifecycleState::Expired
        );
        assert!(old_summary.superseded);
        let new_summary = outcome
            .transactions
            .iter()
            .find(|transaction| transaction.txid != old.txid.to_string())
            .unwrap();
        assert_eq!(
            new_summary.state,
            crate::broadcast::TxLifecycleState::Pending
        );
        assert!(!new_summary.superseded);
        // The superseded value is not counted twice.
        assert_eq!(outcome.pending_zatoshis, 1_000_000 - SPROUT_SWEEP_FEE);
        // And it survives a reload.
        let reloaded = journal.load_or_migrate().unwrap();
        assert_eq!(transaction_summaries(&reloaded).len(), 2);
    }

    #[test]
    fn one_hostile_orphan_sentinel_against_an_agreeing_pair_is_contested_not_reorged() {
        let dir = tempfile::tempdir().unwrap();
        let journal = lifecycle_journal(dir.path());
        let note = lifecycle_note(1_000_000, 110);
        let tx = fixture_transaction(1100, 140);
        seed_entry(
            &journal,
            &note,
            &tx,
            crate::broadcast::TxLifecycleState::Mined,
        );
        let observation = crate::broadcast::observe_transaction(
            vec![
                endpoint("mallory", 150, Some(u32::MAX), false),
                endpoint("alpha", 150, Some(90), true),
                endpoint("bravo", 150, Some(90), true),
            ],
            Some(140),
        );
        assert_eq!(
            observation.state,
            crate::broadcast::TxObservationState::Contested
        );
        let mut node = LifecycleNode::accepted(150, 0);
        let mut observer = LifecycleObserver::new([(tx.txid, observation)]);
        let (outcome, builds, raw) =
            run_lifecycle(&[note], &mut node, &mut observer, &journal, 1101);
        assert_eq!(builds, 0);
        assert!(raw.is_empty() && node.sent.is_empty());
        assert_eq!(
            outcome.transactions[0].state,
            crate::broadcast::TxLifecycleState::Mined
        );
        assert!(!outcome.fresh_all_mined);
        assert_eq!(
            journal
                .load_or_migrate()
                .unwrap()
                .entry_for_txid(tx.txid)
                .unwrap()
                .state,
            crate::broadcast::TxLifecycleState::Mined
        );
    }

    fn run_on_testnet_at(tip: u32, id: u8) -> (SproutSweepOutcome, usize, usize) {
        let dir = tempfile::tempdir().unwrap();
        let journal = crate::sprout_sweep_journal::SweepJournal::for_keys(
            dir.path(),
            &[[0x42; 32]],
            crate::ZeckNetwork::Testnet,
        );
        let notes = [lifecycle_note(1_000_000, id)];
        let mut node = LifecycleNode::accepted(tip, 1);
        let mut observer = LifecycleObserver::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut builds = 0;
        let outcome = runtime.block_on(run_sweep(
            &notes,
            &mut node,
            &mut observer,
            crate::ZeckNetwork::Testnet,
            |note: &SpendableSproutNote, expiry: BlockHeight, _| {
                builds += 1;
                let tx = fixture_transaction(1200 + id as u32, expiry.into());
                Ok(BuiltSproutSweep {
                    txid: tx.txid.to_string(),
                    raw: tx.raw_tx,
                    value_swept: note.note.value - SPROUT_SWEEP_FEE,
                })
            },
            NoteSource::WalletFile,
            &journal,
            |_| {},
        ));
        let sent = node.sent.len();
        (outcome, builds, sent)
    }

    #[test]
    fn no_sprout_transaction_is_built_for_a_block_at_or_past_nu7() {
        let activation = nu7_activation_height(crate::ZeckNetwork::Testnet).unwrap();
        assert_eq!(activation, 4_465_026);
        assert!(TESTNET_NU7_SCHEDULE.contains(&group_thousands(activation)));
        assert_eq!(nu7_activation_height(crate::ZeckNetwork::Mainnet), None);

        // The next block is the last before activation: still buildable.
        let (outcome, builds, sent) = run_on_testnet_at(activation - 2, 111);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!((builds, sent), (1, 1));

        // The next block is the activation block: refused before proving.
        for (offset, tip) in [activation - 1, activation, activation + 1000]
            .into_iter()
            .enumerate()
        {
            let (outcome, builds, sent) = run_on_testnet_at(tip, 112 + offset as u8);
            assert_eq!((builds, sent), (0, 0), "tip {tip}");
            let error = outcome.error.expect("NU7 refusal");
            assert!(error.contains("NU7"), "{error}");
            assert!(
                error.contains("4,465,026") || error.contains("4465026"),
                "{error}"
            );
            assert!(error.contains("cannot"), "{error}");
        }
    }

    #[test]
    fn repeated_reconciles_with_nothing_new_do_not_grow_the_journal() {
        type Observe = fn(u32) -> crate::broadcast::TxObservation;
        let cases: [(&str, crate::broadcast::TxLifecycleState, Observe); 4] = [
            (
                "pending contested",
                crate::broadcast::TxLifecycleState::Pending,
                |tip| contested(Some(140), 110, tip),
            ),
            (
                "pending absent, not retryable",
                crate::broadcast::TxLifecycleState::Pending,
                |tip| absent(Some(140), tip),
            ),
            (
                "single-source mined",
                crate::broadcast::TxLifecycleState::Pending,
                |tip| mined_by_one_source(Some(140), 110, tip),
            ),
            (
                "corroborated mined",
                crate::broadcast::TxLifecycleState::Mined,
                |tip| mined(Some(140), 90, tip),
            ),
        ];
        for (offset, (name, seeded, observe)) in cases.into_iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let journal = lifecycle_journal(dir.path());
            let note = lifecycle_note(1_000_000, 130 + offset as u8);
            let tx = fixture_transaction(1300 + offset as u32, 140);
            seed_entry(&journal, &note, &tx, seeded);
            let lines = || {
                std::fs::read_to_string(journal.path())
                    .unwrap()
                    .lines()
                    .count()
            };

            let mut counts = Vec::new();
            for tip in [150, 151, 152] {
                let mut node = LifecycleNode::accepted(tip, 0);
                let mut observer = LifecycleObserver::new([(tx.txid, observe(tip))]);
                let (outcome, builds, _) = run_lifecycle(
                    std::slice::from_ref(&note),
                    &mut node,
                    &mut observer,
                    &journal,
                    1310,
                );
                assert_eq!(builds, 0, "{name}: {:?}", outcome.error);
                assert!(node.sent.is_empty(), "{name}");
                counts.push(lines());
            }
            assert_eq!(counts[0], counts[1], "{name}: {counts:?}");
            assert_eq!(counts[1], counts[2], "{name}: {counts:?}");
        }
    }
}
