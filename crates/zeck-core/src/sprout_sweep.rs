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

    let gross: u64 = spendable.iter().map(|n| n.note.value).sum();
    let fee = SPROUT_SWEEP_FEE * spendable.len() as u64;

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

    let fields = sprout_spend::compute_joinsplit_fields(
        &inputs,
        &outputs,
        0,
        note.note.value,
        anchor,
        &signing_key.verification_key(),
        random_bytes(&mut rng),
        random_bytes(&mut rng),
        random_bytes(&mut rng),
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
    memo: [u8; 512],
    mut progress: impl FnMut(String),
) -> ZeckResult<SproutSweepOutcome> {
    use zcash_client_backend::proto::service::{ChainSpec, RawTransaction};

    let (sapling_dest, destination_kind) = parse_sapling_destination_kind(destination, network)?;
    let proving_key = load_params(params_path)?;
    let sapling_prover = zcash_proofs::prover::LocalTxProver::bundled();

    let (mut client, _endpoint) =
        crate::lightwalletd::connect_lightwalletd_endpoints_with_retry(lightwalletd_url, None)
            .await?;
    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(|err| ZeckError::Broadcast(format!("could not reach lightwalletd: {err}")))?
        .into_inner()
        .height as u32;
    let branch_id = branch_id_for_height(network, tip);

    let mut outcome = SproutSweepOutcome {
        destination_kind: Some(destination_kind),
        ..Default::default()
    };

    for (index, note) in notes.iter().enumerate() {
        if note.note.value <= SPROUT_SWEEP_FEE {
            outcome.skipped.push(format!(
                "note {index}: holds {} zatoshi, below the {SPROUT_SWEEP_FEE} zatoshi fee",
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
                .push(format!("note {index}: does not match its own commitment"));
            continue;
        }

        progress(format!("proving note {} of {}", index + 1, notes.len()));
        let built = match build_sweep_for_note(
            note,
            sapling_dest,
            branch_id,
            BlockHeight::from_u32(tip + 40),
            &proving_key,
            &sapling_prover,
            memo,
            rand_core::OsRng,
        ) {
            Ok(built) => built,
            Err(err) => {
                outcome.error = Some(format!("note {index} could not be built: {err}"));
                return Ok(outcome);
            }
        };

        let response = match client
            .send_transaction(RawTransaction {
                data: built.raw,
                height: 0,
            })
            .await
        {
            Ok(r) => r.into_inner(),
            Err(err) => {
                // A transport failure is not proof the node refused it: the
                // transaction may already be in the mempool. Say so, rather
                // than implying nothing happened.
                outcome.error = Some(format!(
                    "note {index} could not be confirmed as sent ({err}). It may or may \
                     not have reached the network — check the destination before retrying, \
                     because re-sweeping an accepted note is rejected as a double spend."
                ));
                return Ok(outcome);
            }
        };
        if response.error_code != 0 {
            outcome.error = Some(format!(
                "the node rejected the sweep of note {index}: {}",
                if response.error_message.is_empty() {
                    format!("error code {}", response.error_code)
                } else {
                    response.error_message
                }
            ));
            return Ok(outcome);
        }

        outcome.total_swept += built.value_swept;
        outcome.sent.push(SentSweep {
            txid: built.txid,
            value_swept: built.value_swept,
        });
    }

    Ok(outcome)
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
