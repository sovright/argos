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

use std::path::{Path, PathBuf};

use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::{
    error::{ZeckError, ZeckResult},
    sprout::{self, SproutNotePlaintext},
    sprout_recovery::SpendableSproutNote,
    sprout_spend, sprout_witness,
};

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
    let spendable: Vec<_> = notes
        .iter()
        .filter(|n| n.note.value > SPROUT_SWEEP_FEE)
        .collect();

    if spendable.is_empty() {
        return Err(ZeckError::TransactionBuild(format!(
            "no Sprout note is worth more than the {SPROUT_SWEEP_FEE} zatoshi fee needed \
             to move it"
        )));
    }

    // Saturating: every value came from the wallet file, checked only
    // against commitments from the same file, so a crafted one can sum past
    // `u64::MAX` — and release builds do not check overflow.
    let gross = spendable
        .iter()
        .fold(0u64, |sum, n| sum.saturating_add(n.note.value));
    let fee = SPROUT_SWEEP_FEE.saturating_mul(spendable.len() as u64);

    Ok(SproutSweepPlan {
        notes: spendable.len(),
        gross_zatoshis: gross,
        fee_zatoshis: fee,
        net_zatoshis: gross.saturating_sub(fee),
    })
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

/// One broadcast sweep.
#[derive(Debug, Clone)]
pub struct SentSweep {
    pub txid: String,
    pub value_swept: u64,
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

impl std::fmt::Display for RejectedSweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let txid: String = self
            .outpoint
            .txid
            .iter()
            .rev()
            .map(|b| format!("{b:02x}"))
            .collect();
        write!(
            f,
            "note {txid}:{}:{} ({} zatoshi) was refused ({}). Nothing moved and no fee was \
             paid. ",
            self.outpoint.js_index, self.outpoint.output_index, self.value, self.reason
        )?;
        match (self.kind, self.source) {
            (Refusal::UnknownAnchor, NoteSource::WalletFile) => write!(
                f,
                "The node does not recognise the tree root this note's cached witness proves \
                 against, so the witness in the wallet file is stale or damaged. The full-block \
                 scan builds a fresh one from the chain."
            ),
            (Refusal::UnknownAnchor, _) => write!(
                f,
                "The node does not recognise the root of the witness the scan built. Running \
                 the scan again from its checkpoint rebuilds it against the current chain."
            ),
            (_, NoteSource::WalletFile) => write!(
                f,
                "The network says it is already spent, though this wallet file shows it \
                 unspent — most likely it was spent from another copy of this wallet. The \
                 full-block scan (`argos scan-sprout --wallet-file …`, or Scan for Sprout notes \
                 in the app) confirms that from the chain."
            ),
            (_, _) => write!(
                f,
                "The network says it is already spent. The scan saw it unspent up to the \
                 height it reached, so it was spent since the scan — or an earlier sweep \
                 already sent it and it is waiting in the mempool."
            ),
        }
    }
}

/// Record a refused note. Only called for refusals about the note itself;
/// the sweep then carries on to the next.
fn record_rejection(
    outcome: &mut SproutSweepOutcome,
    note: &SpendableSproutNote,
    kind: Refusal,
    source: NoteSource,
    reason: String,
) {
    outcome.rejected.push(RejectedSweep {
        outpoint: note.outpoint,
        value: note.note.value,
        kind,
        source,
        reason,
    });
}

/// The result of sweeping every recoverable note.
#[derive(Debug, Clone, Default)]
pub struct SproutSweepOutcome {
    pub sent: Vec<SentSweep>,
    pub total_swept: u64,
    /// Which receiver the value landed in. Carried back so the surfaces can
    /// tell the user the funds are in the Sapling pool, and that reaching
    /// Orchard is a further hop from their own wallet.
    pub destination_kind: Option<DestinationKind>,
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
#[derive(Debug, Clone, Default)]
pub struct SweepOptions {
    pub source: NoteSource,
}

/// What the sweep needs from the network: the tip, and a way to broadcast.
/// lightwalletd in production; a script in tests, so the loop's decisions —
/// which refusals it carries on past, which stop it — are exercised rather
/// than only described.
pub(crate) trait SweepNode {
    async fn tip(&mut self) -> Result<u32, String>;
    /// `Ok((code, message))` is the node's answer, `code == 0` meaning it
    /// accepted the transaction and `message` then being its txid. `Err` is
    /// a transport failure, which says nothing about whether it landed.
    async fn send(&mut self, raw: Vec<u8>) -> Result<(i32, String), String>;
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
            .map(|r| r.into_inner().height as u32)
            .map_err(|err| err.to_string())
    }

    async fn send(&mut self, raw: Vec<u8>) -> Result<(i32, String), String> {
        use zcash_client_backend::proto::service::RawTransaction;
        self.0
            .send_transaction(RawTransaction {
                data: raw,
                height: 0,
            })
            .await
            .map(|r| {
                let r = r.into_inner();
                (r.error_code, r.error_message)
            })
            .map_err(|err| err.to_string())
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
        "bad-txns-sprout-duplicate-nullifier",
        "sprout double-spend",
        "already spent some of its inputs",
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
const EXPIRY_DELTA: u32 = 40;

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
    options: SweepOptions,
    progress: impl FnMut(String),
) -> ZeckResult<SproutSweepOutcome> {
    let (sapling_dest, destination_kind) = parse_sapling_destination_kind(destination, network)?;

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

    let proving_key = load_params(params_path)?;
    let sapling_prover = zcash_proofs::prover::LocalTxProver::bundled();

    let mut node = Lightwalletd(client);
    let mut outcome = run_sweep(
        notes,
        &mut node,
        network,
        |note: &SpendableSproutNote, expiry: BlockHeight, branch_id: BranchId| {
            build_sweep_for_note(
                note,
                sapling_dest,
                branch_id,
                expiry,
                &proving_key,
                &sapling_prover,
                [0u8; 512],
                rand_core::OsRng,
            )
        },
        options.source,
        progress,
    )
    .await;
    outcome.destination_kind = Some(destination_kind);
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
pub(crate) async fn run_sweep(
    notes: &[SpendableSproutNote],
    node: &mut impl SweepNode,
    network: crate::ZeckNetwork,
    mut build: impl FnMut(&SpendableSproutNote, BlockHeight, BranchId) -> ZeckResult<BuiltSproutSweep>,
    source: NoteSource,
    mut progress: impl FnMut(String),
) -> SproutSweepOutcome {
    let mut outcome = SproutSweepOutcome::default();
    let total = notes.len();

    for (index, note) in notes.iter().enumerate() {
        let label = note_label(index, total, note);
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
                return outcome;
            }
        };
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
                return outcome;
            }
        };

        let (code, message) = match node.send(built.raw).await {
            Ok(reply) => reply,
            Err(err) => {
                // A transport failure is not proof the node refused it: the
                // transaction may already be in the mempool. Say so, rather
                // than implying nothing happened.
                outcome.error = Some(format!(
                    "{label} could not be confirmed as sent ({err}). It may or may not have \
                     reached the network — check the destination before retrying, because \
                     re-sweeping an accepted note is rejected as a double spend."
                ));
                return outcome;
            }
        };
        if code != 0 {
            let reason = if message.is_empty() {
                format!("error code {code}")
            } else {
                message
            };
            progress(format!("{label} was refused: {reason}"));
            match classify_refusal(code, &reason) {
                kind @ (Refusal::Spent | Refusal::UnknownAnchor) => {
                    record_rejection(&mut outcome, note, kind, source, reason);
                    continue;
                }
                Refusal::Expired => {
                    outcome.error = Some(format!(
                        "{label} was refused as expired ({reason}). It was built to expire \
                         {EXPIRY_DELTA} blocks after the tip read just before building it, so \
                         either proving it took longer than that or the server's chain is \
                         behind. Nothing was sent for it. The sweep stopped rather than prove \
                         the remaining notes into the same refusal."
                    ));
                    return outcome;
                }
                Refusal::Other => {
                    outcome.error = Some(format!(
                        "the node refused {label} for a reason that is not about this note: \
                         {reason}. Nothing was sent for it. The sweep stopped rather than prove \
                         the remaining notes into the same refusal; notes swept before it are \
                         listed above."
                    ));
                    return outcome;
                }
            }
        }

        // Reported now, not only in the returned outcome: a sweep killed
        // partway must already have shown every txid it broadcast.
        progress(format!("swept {label} in {}", built.txid));
        outcome.total_swept = outcome.total_swept.saturating_add(built.value_swept);
        outcome.sent.push(SentSweep {
            txid: built.txid,
            value_swept: built.value_swept,
        });
    }

    outcome
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

    /// Kristi's F5 on #239: the plan printed before confirmation must not
    /// wrap. Two notes near half of `u64::MAX` saturate rather than show a
    /// tiny gross.
    #[test]
    fn the_plan_saturates_instead_of_wrapping() {
        let plan = plan_sweep(&[note(u64::MAX / 2 + 1), note(u64::MAX / 2 + 1)]).unwrap();
        assert_eq!(plan.gross_zatoshis, u64::MAX);
        assert!(plan.net_zatoshis > u64::MAX / 2);
    }

    /// Every note is tried: fifty refusals about the notes themselves, and
    /// every note is still built and sent.
    #[test]
    fn refusals_about_notes_never_stop_the_sweep() {
        let replies = (0..50)
            .map(|_| Ok((-26, "bad-txns-sprout-duplicate-nullifier")))
            .collect();
        let mut node = ScriptedNode::new(replies);
        let values: Vec<u64> = (0..50).map(|i| 1_000_000 + i).collect();
        let (outcome, expiries) = run(&notes(&values), &mut node, NoteSource::WalletFile);
        assert_eq!(expiries.len(), 50);
        assert_eq!(outcome.rejected.len(), 50);
        assert!(outcome.error.is_none());
    }

    /// A node that answers from a script: each `send` pops the next reply,
    /// and `tip` advances by `blocks_per_note` every time it is asked.
    struct ScriptedNode {
        tip: u32,
        blocks_per_note: u32,
        replies: std::collections::VecDeque<Result<(i32, String), String>>,
        sent: usize,
    }

    impl ScriptedNode {
        fn new(replies: Vec<Result<(i32, &str), &str>>) -> Self {
            Self {
                tip: 3_000_000,
                blocks_per_note: 25,
                replies: replies
                    .into_iter()
                    .map(|r| r.map(|(c, m)| (c, m.to_owned())).map_err(str::to_owned))
                    .collect(),
                sent: 0,
            }
        }
    }

    impl SweepNode for ScriptedNode {
        async fn tip(&mut self) -> Result<u32, String> {
            let tip = self.tip;
            self.tip += self.blocks_per_note;
            Ok(tip)
        }
        async fn send(&mut self, _raw: Vec<u8>) -> Result<(i32, String), String> {
            self.sent += 1;
            self.replies
                .pop_front()
                .expect("the script ran out: the sweep sent more than the test expected")
        }
    }

    /// Run the real loop against a scripted node and a builder that records
    /// the expiry height it was asked for instead of proving.
    fn run(
        notes: &[SpendableSproutNote],
        node: &mut ScriptedNode,
        source: NoteSource,
    ) -> (SproutSweepOutcome, Vec<u32>) {
        let mut expiries = Vec::new();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a test runtime");
        let outcome = runtime.block_on(run_sweep(
            notes,
            node,
            crate::ZeckNetwork::Mainnet,
            |note: &SpendableSproutNote, expiry: BlockHeight, _branch| {
                expiries.push(u32::from(expiry));
                Ok(BuiltSproutSweep {
                    txid: format!("sweep-of-{}", note.note.value),
                    raw: Vec::new(),
                    value_swept: note.note.value - SPROUT_SWEEP_FEE,
                })
            },
            source,
            |_| {},
        ));
        (outcome, expiries)
    }

    /// [`run`], with a builder that fails every note and the progress lines.
    fn run_failing_build(
        notes: &[SpendableSproutNote],
        node: &mut ScriptedNode,
    ) -> (SproutSweepOutcome, usize, Vec<String>) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut built = 0;
        let mut lines = Vec::new();
        let outcome = runtime.block_on(run_sweep(
            notes,
            node,
            crate::ZeckNetwork::Mainnet,
            |_: &SpendableSproutNote, _: BlockHeight, _| {
                built += 1;
                Err(ZeckError::TransactionBuild(
                    "the Sapling bundle has no output".into(),
                ))
            },
            NoteSource::WalletFile,
            |line| lines.push(line),
        ));
        (outcome, built, lines)
    }

    /// Kristi's round-4 finding 1 on #239: the build failures that come
    /// after proving are about the fee, the destination or the bundle, not
    /// the note — so carrying on proves every remaining note into the same
    /// failure. A build failure stops the sweep, and says so.
    #[test]
    fn a_build_failure_stops_the_sweep() {
        let mut node = ScriptedNode::new(vec![]);
        let (outcome, built, _) =
            run_failing_build(&notes(&[1_000_000, 2_000_000, 3_000_000]), &mut node);
        assert_eq!(built, 1, "no second proving run");
        let error = outcome
            .error
            .expect("the sweep did not finish, and must say so");
        assert!(error.contains("could not be built"), "{error}");
        assert!(outcome.skipped.is_empty());
    }

    /// Finding 7: an accepted broadcast is reported the moment it happens,
    /// so a sweep killed partway has already shown every txid it sent.
    #[test]
    fn every_broadcast_is_reported_as_it_happens() {
        let mut node = ScriptedNode::new(vec![Ok((0, "x")), Ok((0, "y"))]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut lines = Vec::new();
        runtime.block_on(run_sweep(
            &notes(&[1_000_000, 2_000_000]),
            &mut node,
            crate::ZeckNetwork::Mainnet,
            |note: &SpendableSproutNote, _: BlockHeight, _| {
                Ok(BuiltSproutSweep {
                    txid: format!("sweep-of-{}", note.note.value),
                    raw: Vec::new(),
                    value_swept: note.note.value - SPROUT_SWEEP_FEE,
                })
            },
            NoteSource::WalletFile,
            |line| lines.push(line),
        ));
        for txid in ["sweep-of-1000000", "sweep-of-2000000"] {
            assert!(
                lines.iter().any(|l| l.contains(txid)),
                "{txid} not reported: {lines:?}"
            );
        }
    }

    fn notes(values: &[u64]) -> Vec<SpendableSproutNote> {
        values.iter().map(|v| note(*v)).collect()
    }

    /// Kristi's F2 on #239: one expiry height for a sweep of hundreds of
    /// notes goes stale within the first twenty, after which every note is
    /// refused as expired and blamed on a spend. Each note is built against
    /// the tip as it is when that note is built.
    #[test]
    fn each_note_expires_relative_to_the_tip_when_it_is_built() {
        let mut node = ScriptedNode::new(vec![Ok((0, "a")), Ok((0, "b")), Ok((0, "c"))]);
        let (outcome, expiries) = run(
            &notes(&[1_000_000, 2_000_000, 3_000_000]),
            &mut node,
            NoteSource::WalletFile,
        );
        assert_eq!(outcome.sent.len(), 3);
        assert_eq!(expiries, vec![3_000_040, 3_000_065, 3_000_090]);
    }

    /// The headline behaviour, driven through the real loop: a note the
    /// network says is already spent is recorded and the next is tried.
    /// Both node implementations' wording, from their source.
    #[test]
    fn a_spent_note_is_recorded_and_the_next_one_is_still_swept() {
        for spent in [
            "bad-txns-sprout-duplicate-nullifier",
            "transaction did not pass consensus validation: sprout double-spend: duplicate nullifier: Nullifier(..)",
            "transaction rejected because another transaction in the mempool has already spent some of its inputs",
            "bad-txns-sprout-unknown-anchor",
            "unknown Sprout anchor: Root(..)",
        ] {
            let mut node = ScriptedNode::new(vec![Ok((-26, spent)), Ok((0, "ok"))]);
            let (outcome, _) = run(&notes(&[1_000_000, 2_000_000]), &mut node, NoteSource::WalletFile);
            assert_eq!(outcome.rejected.len(), 1, "{spent}");
            assert_eq!(outcome.sent.len(), 1, "{spent}: the next note must still be swept");
            assert!(outcome.error.is_none(), "{spent}");
        }
    }

    /// Kristi's F1 on #239: the node's own state is not a verdict on the
    /// note. Carrying on would prove every remaining note into the same
    /// refusal, so these stop, naming what the node said.
    #[test]
    fn a_refusal_about_the_node_stops_the_sweep() {
        for (code, message) in [
            (-10, "Zcash is downloading blocks..."),
            (-28, "Loading block index..."),
            (-26, "bad-txns-oversize"),
            (
                -25,
                "mempool is disabled since synchronization is behind the chain tip",
            ),
        ] {
            let mut node = ScriptedNode::new(vec![Ok((code, message))]);
            let (outcome, expiries) = run(
                &notes(&[1_000_000, 2_000_000]),
                &mut node,
                NoteSource::WalletFile,
            );
            assert_eq!(expiries.len(), 1, "{message}: no second note may be proved");
            assert!(
                outcome.rejected.is_empty(),
                "{message}: not a verdict on the note"
            );
            let error = outcome.error.expect("stopping must say why");
            assert!(error.contains(message), "{error}");
            assert!(!error.contains("another copy"), "{error}");
        }
    }

    /// `-10`/`-28` mean the node cannot judge anything yet. The code alone
    /// decides it, even if the message happens to read like a spend.
    #[test]
    fn a_node_that_is_not_ready_stops_the_sweep_whatever_it_says() {
        for code in [-10, -28] {
            assert_eq!(
                classify_refusal(code, "bad-txns-sprout-duplicate-nullifier"),
                Refusal::Other
            );
            let mut node =
                ScriptedNode::new(vec![Ok((code, "sprout double-spend: duplicate nullifier"))]);
            let (outcome, expiries) = run(
                &notes(&[1_000_000, 2_000_000]),
                &mut node,
                NoteSource::WalletFile,
            );
            assert_eq!(expiries.len(), 1, "code {code}: no second proving run");
            assert!(outcome.rejected.is_empty());
            assert!(outcome.error.is_some());
        }
    }

    #[test]
    fn an_expired_sweep_stops_and_says_so() {
        for message in [
            "tx-expiring-soon",
            "tx-overwinter-expired",
            "best chain tip has reached transaction expiry height",
        ] {
            let mut node = ScriptedNode::new(vec![Ok((-26, message))]);
            let (outcome, expiries) = run(
                &notes(&[1_000_000, 2_000_000]),
                &mut node,
                NoteSource::WalletFile,
            );
            assert_eq!(expiries.len(), 1, "{message}");
            let error = outcome.error.expect("stopping must say why");
            assert!(error.contains("expir"), "{error}");
            assert!(!error.contains("another copy"), "{error}");
        }
    }

    /// A transport failure cannot say whether the transaction landed.
    #[test]
    fn a_transport_failure_stops_the_sweep() {
        let mut node = ScriptedNode::new(vec![Err("connection reset")]);
        let (outcome, expiries) = run(
            &notes(&[1_000_000, 2_000_000]),
            &mut node,
            NoteSource::WalletFile,
        );
        assert_eq!(expiries.len(), 1);
        assert!(outcome
            .error
            .unwrap()
            .contains("may or may not have reached"));
    }

    /// Kristi's F6: the advice depends on where the notes came from. Notes
    /// from the chain scan must not be sent back to the chain scan.
    #[test]
    fn a_refused_note_is_explained_by_where_it_came_from() {
        let refused = |source| {
            let mut node =
                ScriptedNode::new(vec![Ok((-26, "bad-txns-sprout-duplicate-nullifier"))]);
            run(&notes(&[1_000_000]), &mut node, source).0.rejected[0].to_string()
        };
        let from_file = refused(NoteSource::WalletFile);
        assert!(from_file.contains("another copy"), "{from_file}");
        let from_scan = refused(NoteSource::Scan);
        assert!(!from_scan.contains("scan-sprout"), "{from_scan}");
        assert!(from_scan.contains("since the scan"), "{from_scan}");
    }

    /// Notes are numbered from one everywhere a user reads them, and name
    /// their outpoint (Kristi's F13).
    #[test]
    fn a_skipped_note_is_numbered_from_one_and_named() {
        let mut node = ScriptedNode::new(vec![Ok((0, "ok"))]);
        let (outcome, _) = run(
            &notes(&[1_000, 2_000_000]),
            &mut node,
            NoteSource::WalletFile,
        );
        assert!(
            outcome.skipped[0].starts_with("note 1 of 2 ("),
            "{}",
            outcome.skipped[0]
        );
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
        let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32]);
        let destination =
            crate::sapling_key::default_sapling_address(&extsk, crate::ZeckNetwork::Mainnet);
        let err = sweep_sprout_notes(
            &[note(1_000_000)],
            crate::ZeckNetwork::Mainnet,
            "nonono",
            &destination,
            Path::new("/nonexistent/sprout-groth16.params"),
            SweepOptions::default(),
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
}
