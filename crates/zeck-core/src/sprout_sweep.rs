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

    // The cached blob is zcashd's `std::list<SproutWitness>`; the newest
    // entry is the one nearest the wallet's last sync.
    let witness =
        sprout_witness::IncrementalWitness::parse_cached(&note.witness).map_err(|err| {
            ZeckError::TransactionBuild(format!(
                "this note's cached witness could not be read ({err}). Without it the note's \
             position in the commitment tree is unknown and it cannot be spent without a \
             full-block rescan."
            ))
        })?;
    let anchor = witness.root();
    let witness_path = witness
        .encode_for_prover()
        .map_err(|err| ZeckError::TransactionBuild(format!("encoding the witness path: {err}")))?
        .to_vec();

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
    /// Notes that were skipped, and why. Reported rather than dropped: a
    /// user who sees a smaller total than expected needs to know which notes
    /// did not move.
    pub skipped: Vec<String>,
}

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
    use zcash_address::{
        unified::{Container, Receiver},
        ConversionError, TryFromAddress, ZcashAddress,
    };
    use zcash_protocol::consensus::NetworkType;

    let parsed = ZcashAddress::try_from_encoded(destination).map_err(|err| {
        ZeckError::InvalidAddress(format!("{destination} is not a Zcash address: {err}"))
    })?;

    struct Found(Option<sapling_crypto::PaymentAddress>);
    impl TryFromAddress for Found {
        type Error = &'static str;

        fn try_from_sapling(
            _net: NetworkType,
            data: [u8; 43],
        ) -> Result<Self, ConversionError<Self::Error>> {
            Ok(Found(sapling_crypto::PaymentAddress::from_bytes(&data)))
        }

        fn try_from_unified(
            _net: NetworkType,
            ua: zcash_address::unified::Address,
        ) -> Result<Self, ConversionError<Self::Error>> {
            for receiver in ua.items() {
                if let Receiver::Sapling(data) = receiver {
                    return Ok(Found(sapling_crypto::PaymentAddress::from_bytes(&data)));
                }
            }
            Ok(Found(None))
        }
    }

    let want = match network {
        crate::ZeckNetwork::Mainnet => NetworkType::Main,
        crate::ZeckNetwork::Testnet => NetworkType::Test,
    };
    let found: Found = parsed.convert_if_network(want).map_err(|err| {
        ZeckError::InvalidAddress(format!("{destination} is not valid on this network: {err}"))
    })?;

    found.0.ok_or_else(|| {
        ZeckError::InvalidAddress(format!(
            "{destination} has no Sapling receiver. Sprout value leaves the pool through \
             the transparent pool and must be consumed by a Sapling output in the same \
             transaction, so a transparent-only or Orchard-only destination cannot \
             receive it."
        ))
    })
}

/// The consensus branch in force at `height`.
pub fn branch_id_for_height(network: crate::ZeckNetwork, height: u32) -> BranchId {
    use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};
    let at = BlockHeight::from_u32(height);
    match network {
        crate::ZeckNetwork::Mainnet => BranchId::for_height(&MAIN_NETWORK, at),
        crate::ZeckNetwork::Testnet => BranchId::for_height(&TEST_NETWORK, at),
    }
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

    let sapling_dest = parse_sapling_destination(destination, network)?;
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

    let mut outcome = SproutSweepOutcome::default();

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
        let built = build_sweep_for_note(
            note,
            sapling_dest,
            branch_id,
            BlockHeight::from_u32(tip + 40),
            &proving_key,
            &sapling_prover,
            memo,
            rand_core::OsRng,
        )?;

        let response = client
            .send_transaction(RawTransaction {
                data: built.raw,
                height: 0,
            })
            .await
            .map_err(|err| ZeckError::Broadcast(err.to_string()))?
            .into_inner();
        if response.error_code != 0 {
            return Err(ZeckError::Broadcast(format!(
                "the node rejected the sweep of note {index}: {}",
                if response.error_message.is_empty() {
                    format!("error code {}", response.error_code)
                } else {
                    response.error_message
                }
            )));
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
            witness: Vec::new(),
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
        assert_eq!(SPROUT_SWEEP_FEE, 20_000);
        assert_eq!(ACTIONS_PER_SWEEP, 4);
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
