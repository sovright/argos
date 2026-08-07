//! Assembling a JoinSplit, and the V4 transaction that carries it.
//!
//! This is the layer `zcash_primitives` will not do for us. Its transaction
//! builder hardcodes `sprout_bundle: None`, and `JsDescription`'s fields are
//! `pub(crate)`, so a JoinSplit cannot be constructed through the ordinary
//! API. What *is* public is enough to do it by hand:
//!
//! * `JsDescription::read` — so a description can be serialized and parsed
//!   back in, which is the only way to populate those private fields.
//! * `sprout::Bundle`'s fields — all three are public.
//! * `TransactionData::from_parts`, which accepts a `sprout_bundle`.
//! * `sighash_v4::v4_signature_hash`.
//!
//! Same conclusion as the PCZT work reached for Sapling: the low-level
//! surfaces are open, only the convenience APIs refuse. No upstream change
//! is required.
//!
//! # Ordering
//!
//! The JoinSplit's fields are not independent, and getting the order wrong
//! produces a description that serializes cleanly and proves nothing:
//!
//! 1. Generate the ed25519 keypair. Its verification key is
//!    `joinsplit_pubkey`, which feeds `hSig`.
//! 2. Compute input nullifiers from each input's `a_sk` and `rho`.
//! 3. `hSig = h_sig(random_seed, nullifiers, joinsplit_pubkey)`.
//! 4. Derive each output's `rho` from `phi` and `hSig`; commit to it.
//! 5. MAC each input with `PRF^pk(a_sk, i, hSig)`.
//! 6. Encrypt both output notes under `hSig`.
//! 7. Prove.
//! 8. Assemble the transaction, take its v4 sighash with the signature
//!    field zeroed, and sign that.
//!
//! `hSig` depends on the signing key, and the signature covers a hash of the
//! whole transaction including the JoinSplit — the circularity is broken
//! only because the signature itself is excluded from the sighash.

use bellman::groth16::Parameters;
use bls12_381::Bls12;
use zcash_primitives::transaction::components::sprout as sprout_tx;
use zcash_primitives::transaction::sighash::SignableInput;
use zcash_primitives::transaction::sighash_v4::v4_signature_hash;
use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_transparent::bundle as transparent;

use crate::error::{ZeckError, ZeckResult};
use crate::sprout::{
    encrypt_note, epk_for, h_sig, note_commitment, prf_nf, prf_pk, prf_rho, SproutNotePlaintext,
    NOTE_CIPHERTEXT_LEN,
};
use crate::sprout_witness::WITNESS_PATH_SIZE;

/// Groth16 JoinSplit proof size: three compressed group elements.
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
/// A JoinSplit has exactly two inputs and two outputs, always. Unused slots
/// are zero-value dummies rather than absent.
pub const JS_INPUTS: usize = 2;
pub const JS_OUTPUTS: usize = 2;

/// One JoinSplit input: a note this wallet can spend, and the material
/// proving it is in the tree.
pub struct JoinSplitInput {
    pub note: SproutNotePlaintext,
    pub a_sk: [u8; 32],
    /// The 966-byte encoding from `sprout_witness::encode_for_prover`.
    pub witness_path: Vec<u8>,
}

/// One JoinSplit output: a Sprout note paid to someone.
///
/// Sprout can only pay Sprout. Reaching Sapling means routing value through
/// the transparent value pool with `vpub_new`, then having a Sapling output
/// in the same transaction consume it.
pub struct JoinSplitOutput {
    pub a_pk: [u8; 32],
    pub pk_enc: [u8; 32],
    pub value: u64,
}

/// Everything a JoinSplit description needs, computed but not yet proved.
///
/// Split out from proving so the assembly and its ordering can be tested
/// without `sprout-groth16.params`, which is ~700 MB and not bundled.
pub struct JoinSplitFields {
    pub vpub_old: u64,
    pub vpub_new: u64,
    pub anchor: [u8; 32],
    pub nullifiers: [[u8; 32]; JS_INPUTS],
    pub commitments: [[u8; 32]; JS_OUTPUTS],
    pub ephemeral_key: [u8; 32],
    pub random_seed: [u8; 32],
    pub macs: [[u8; 32]; JS_INPUTS],
    pub ciphertexts: [Vec<u8>; JS_OUTPUTS],
    /// Retained because `create_proof` needs it, and because it is the
    /// value `hSig` was computed over.
    pub h_sig: [u8; 32],
    /// The `phi` the output `rho` values were derived from.
    pub phi: [u8; 32],
}

/// Compute every field of a JoinSplit except the proof.
///
/// `phi` and `esk` are supplied rather than sampled internally so tests can
/// be deterministic. Production callers must pass fresh randomness: reusing
/// `esk` reuses an AEAD key under a fixed nonce, and reusing `phi` repeats
/// output `rho` values, which makes nullifiers collide.
#[allow(clippy::too_many_arguments)]
pub fn compute_joinsplit_fields(
    inputs: &[JoinSplitInput; JS_INPUTS],
    outputs: &[JoinSplitOutput; JS_OUTPUTS],
    vpub_old: u64,
    vpub_new: u64,
    anchor: [u8; 32],
    joinsplit_pubkey: &[u8; 32],
    phi: [u8; 32],
    esk: [u8; 32],
) -> ZeckResult<JoinSplitFields> {
    // Nullifiers first: hSig commits to them.
    let nullifiers = [
        prf_nf(&inputs[0].a_sk, &inputs[0].note.rho),
        prf_nf(&inputs[1].a_sk, &inputs[1].note.rho),
    ];

    let h_sig = h_sig(&phi, &nullifiers, joinsplit_pubkey);

    let macs = [
        prf_pk(&inputs[0].a_sk, 0, &h_sig),
        prf_pk(&inputs[1].a_sk, 1, &h_sig),
    ];

    // Each output's rho is derived, not chosen: it is what binds the output
    // to this JoinSplit and stops the same note being created twice.
    let mut commitments = [[0u8; 32]; JS_OUTPUTS];
    let mut ciphertexts: [Vec<u8>; JS_OUTPUTS] = [Vec::new(), Vec::new()];
    for i in 0..JS_OUTPUTS {
        let rho = prf_rho(&phi, i, &h_sig);
        // The output note's commitment randomness. Derived from phi and the
        // index so that a caller cannot accidentally reuse one across
        // outputs; the spec permits any randomness here.
        let r = prf_rho(&phi, i, &nullifiers[i]);
        commitments[i] = note_commitment(&outputs[i].a_pk, outputs[i].value, &rho, &r);

        let note = SproutNotePlaintext {
            value: outputs[i].value,
            rho,
            r,
            memo: [0u8; 512],
        };
        ciphertexts[i] = encrypt_note(&esk, &outputs[i].pk_enc, &h_sig, i as u8, &note.to_bytes())
            .map_err(|err| {
                ZeckError::TransactionBuild(format!("encrypting a Sprout output: {err}"))
            })?;
    }

    Ok(JoinSplitFields {
        vpub_old,
        vpub_new,
        anchor,
        nullifiers,
        commitments,
        ephemeral_key: epk_for(&esk),
        random_seed: phi,
        macs,
        ciphertexts,
        h_sig,
        phi,
    })
}

/// Serialize a JoinSplit description in the wire order `JsDescription::read`
/// expects, then parse it back.
///
/// The round trip through bytes is not gratuitous: `JsDescription`'s fields
/// are `pub(crate)`, so `read` is the only way to build one from outside
/// `zcash_primitives`.
pub fn build_js_description(
    fields: &JoinSplitFields,
    proof: &[u8; GROTH_PROOF_SIZE],
) -> ZeckResult<sprout_tx::JsDescription> {
    let mut bytes = Vec::with_capacity(1698);
    bytes.extend_from_slice(&fields.vpub_old.to_le_bytes());
    bytes.extend_from_slice(&fields.vpub_new.to_le_bytes());
    bytes.extend_from_slice(&fields.anchor);
    bytes.extend_from_slice(&fields.nullifiers[0]);
    bytes.extend_from_slice(&fields.nullifiers[1]);
    bytes.extend_from_slice(&fields.commitments[0]);
    bytes.extend_from_slice(&fields.commitments[1]);
    bytes.extend_from_slice(&fields.ephemeral_key);
    bytes.extend_from_slice(&fields.random_seed);
    bytes.extend_from_slice(&fields.macs[0]);
    bytes.extend_from_slice(&fields.macs[1]);
    bytes.extend_from_slice(proof);
    for ct in &fields.ciphertexts {
        if ct.len() != NOTE_CIPHERTEXT_LEN {
            return Err(ZeckError::TransactionBuild(format!(
                "a Sprout ciphertext is {} bytes, expected {NOTE_CIPHERTEXT_LEN}",
                ct.len()
            )));
        }
        bytes.extend_from_slice(ct);
    }

    // `use_groth = true`: a JoinSplit in a v4 transaction carries a Groth16
    // proof. PHGR13 belongs to pre-Sapling transaction versions, which this
    // never emits.
    sprout_tx::JsDescription::read(&bytes[..], true).map_err(|err| {
        ZeckError::TransactionBuild(format!(
            "re-reading the JoinSplit we just serialized: {err}"
        ))
    })
}

/// An ed25519 keypair for signing a JoinSplit.
///
/// `ed25519-zebra` rather than `ed25519-dalek`: Zcash consensus requires
/// ZIP 215 verification semantics, and the two libraries disagree about
/// edge-case signatures. This is the crate Zebra verifies with.
pub struct JoinSplitSigningKey {
    signing: ed25519_zebra::SigningKey,
}

impl JoinSplitSigningKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing: ed25519_zebra::SigningKey::from(bytes),
        }
    }

    /// The `joinsplit_pubkey` field, which `hSig` is computed over.
    pub fn verification_key(&self) -> [u8; 32] {
        ed25519_zebra::VerificationKey::from(&self.signing).into()
    }

    /// Sign the transaction's v4 sighash.
    pub fn sign(&self, sighash: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(sighash).into()
    }
}

/// Assemble a V4 transaction carrying a Sprout bundle, and sign it.
///
/// Sprout can only live in a V4 transaction: ZIP 225 rewrote the encoding
/// for V5 and dropped JoinSplits entirely. V4 remains consensus-valid, which
/// is what makes recovery possible at all.
///
/// The signature covers a sighash of the whole transaction, and the
/// transaction contains the signature — the circularity is broken by
/// computing the sighash with `joinsplit_sig` zeroed, exactly as zcashd
/// does.
pub fn build_and_sign_v4(
    consensus_branch_id: BranchId,
    expiry_height: BlockHeight,
    transparent_bundle: Option<transparent::Bundle<transparent::Authorized>>,
    joinsplits: Vec<sprout_tx::JsDescription>,
    key: &JoinSplitSigningKey,
) -> ZeckResult<Transaction> {
    if joinsplits.is_empty() {
        return Err(ZeckError::TransactionBuild(
            "a Sprout transaction needs at least one JoinSplit".to_owned(),
        ));
    }

    let unsigned = TransactionData::<Authorized>::from_parts(
        TxVersion::V4,
        consensus_branch_id,
        0,
        expiry_height,
        transparent_bundle.clone(),
        Some(sprout_tx::Bundle {
            joinsplits: joinsplits.clone(),
            joinsplit_pubkey: key.verification_key(),
            // Zeroed for the sighash. zcashd does the same: the signature
            // cannot commit to itself.
            joinsplit_sig: [0u8; 64],
        }),
        None,
        None,
    );

    let sighash = v4_signature_hash(&unsigned, &SignableInput::Shielded);
    let mut sighash_bytes = [0u8; 32];
    sighash_bytes.copy_from_slice(sighash.as_bytes());

    let signed = TransactionData::<Authorized>::from_parts(
        TxVersion::V4,
        consensus_branch_id,
        0,
        expiry_height,
        transparent_bundle,
        Some(sprout_tx::Bundle {
            joinsplits,
            joinsplit_pubkey: key.verification_key(),
            joinsplit_sig: key.sign(&sighash_bytes),
        }),
        None,
        None,
    );

    signed.freeze().map_err(|err| {
        ZeckError::TransactionBuild(format!("freezing the Sprout transaction: {err}"))
    })
}

/// Load the Sprout Groth16 proving key.
///
/// `zcash_proofs` exposes the *verifying* key through `load_parameters` but
/// not the proving key, so this reads the file directly.
///
/// The file is ~725 MB and is not bundled with Argos — `LocalTxProver::bundled`
/// covers Sapling only. `zcash_proofs::download_sprout_parameters` fetches it
/// and verifies a pinned BLAKE2b hash; the size is checked here first because
/// a truncated download otherwise surfaces as an opaque deserialization
/// failure several minutes in.
pub fn load_sprout_proving_key(path: &std::path::Path) -> ZeckResult<Parameters<Bls12>> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        ZeckError::InvalidConfig(format!(
            "cannot read the Sprout proving key at {}: {err}",
            path.display()
        ))
    })?;
    if metadata.len() != SPROUT_BYTES {
        return Err(ZeckError::InvalidConfig(format!(
            "the Sprout proving key at {} is {} bytes, expected {SPROUT_BYTES}.              A truncated or wrong file here fails later as an unreadable parameter set.",
            path.display(),
            metadata.len()
        )));
    }

    let file = std::fs::File::open(path)
        .map_err(|err| ZeckError::InvalidConfig(format!("opening the Sprout proving key: {err}")))?;
    // 1 MiB buffer: the file is large and read sequentially.
    let reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    // `checked = false` skips the point-validity pass, which costs minutes.
    // Safe here only because the file's hash was verified on download.
    Parameters::<Bls12>::read(reader, false).map_err(|err| {
        ZeckError::InvalidConfig(format!("parsing the Sprout proving key: {err}"))
    })
}

/// The expected size of `sprout-groth16.params`, from `zcash_proofs`.
pub const SPROUT_BYTES: u64 = 725_523_612;

/// Prove a JoinSplit.
///
/// Thin by design: everything expensive to get right is already computed in
/// `JoinSplitFields`, so the untestable-without-parameters part is confined
/// to this one call.
pub fn prove_joinsplit(
    fields: &JoinSplitFields,
    inputs: &[JoinSplitInput; JS_INPUTS],
    outputs: &[JoinSplitOutput; JS_OUTPUTS],
    proving_key: &Parameters<Bls12>,
) -> ZeckResult<[u8; GROTH_PROOF_SIZE]> {
    let mut auth = [[0u8; WITNESS_PATH_SIZE]; JS_INPUTS];
    for (i, input) in inputs.iter().enumerate() {
        if input.witness_path.len() != WITNESS_PATH_SIZE {
            return Err(ZeckError::TransactionBuild(format!(
                "input {i}'s witness path is {} bytes, expected {WITNESS_PATH_SIZE}",
                input.witness_path.len()
            )));
        }
        auth[i].copy_from_slice(&input.witness_path);
    }

    let proof = zcash_proofs::sprout::create_proof(
        fields.phi,
        fields.anchor,
        fields.h_sig,
        inputs[0].a_sk,
        inputs[0].note.value,
        inputs[0].note.rho,
        inputs[0].note.r,
        &auth[0],
        inputs[1].a_sk,
        inputs[1].note.value,
        inputs[1].note.rho,
        inputs[1].note.r,
        &auth[1],
        outputs[0].a_pk,
        outputs[0].value,
        prf_rho(&fields.phi, 0, &fields.nullifiers[0]),
        outputs[1].a_pk,
        outputs[1].value,
        prf_rho(&fields.phi, 1, &fields.nullifiers[1]),
        fields.vpub_old,
        fields.vpub_new,
        proving_key,
    );

    let mut bytes = [0u8; GROTH_PROOF_SIZE];
    proof
        .write(&mut bytes[..])
        .map_err(|err| ZeckError::TransactionBuild(format!("serializing the Sprout proof: {err}")))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprout::{a_pk, pk_enc};

    fn dummy_input(a_sk: [u8; 32], value: u64, rho: [u8; 32]) -> JoinSplitInput {
        JoinSplitInput {
            note: SproutNotePlaintext {
                value,
                rho,
                r: [1u8; 32],
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: vec![0u8; crate::sprout_witness::WITNESS_PATH_SIZE],
        }
    }

    fn fields_for_test() -> JoinSplitFields {
        let key = JoinSplitSigningKey::from_bytes([9u8; 32]);
        let recipient = [4u8; 32];
        let inputs = [
            dummy_input([3u8; 32], 50_000, [21u8; 32]),
            dummy_input([3u8; 32], 0, [22u8; 32]),
        ];
        let outputs = [
            JoinSplitOutput {
                a_pk: a_pk(&recipient),
                pk_enc: pk_enc(&recipient),
                value: 0,
            },
            JoinSplitOutput {
                a_pk: a_pk(&recipient),
                pk_enc: pk_enc(&recipient),
                value: 0,
            },
        ];
        compute_joinsplit_fields(
            &inputs,
            &outputs,
            0,
            50_000,
            [7u8; 32],
            &key.verification_key(),
            [11u8; 32],
            [13u8; 32],
        )
        .expect("fields")
    }

    /// The description must survive the byte round trip, since that is the
    /// only way to construct one.
    #[test]
    fn a_description_round_trips_through_serialization() {
        let fields = fields_for_test();
        let js = build_js_description(&fields, &[0u8; GROTH_PROOF_SIZE]).expect("build");

        assert_eq!(js.anchor(), &fields.anchor);
        assert_eq!(js.nullifiers(), &fields.nullifiers);
        assert_eq!(js.commitments(), &fields.commitments);
        assert_eq!(js.random_seed(), &fields.random_seed);
        assert_eq!(u64::try_from(i64::from(js.vpub_new())).unwrap(), 50_000);
    }

    /// The two inputs must produce different nullifiers even when they share
    /// a spending key — the rho is what distinguishes them. If this fails,
    /// a two-input JoinSplit double-spends one note.
    #[test]
    fn inputs_sharing_a_key_get_distinct_nullifiers() {
        let fields = fields_for_test();
        assert_ne!(fields.nullifiers[0], fields.nullifiers[1]);
        assert_ne!(fields.macs[0], fields.macs[1]);
    }

    /// hSig binds the signing key. A different key must give a different
    /// hSig, and therefore different MACs and ciphertext keys — that binding
    /// is what stops a JoinSplit being lifted into another transaction.
    #[test]
    fn h_sig_binds_the_joinsplit_signing_key() {
        let a = fields_for_test();

        let other = JoinSplitSigningKey::from_bytes([10u8; 32]);
        let recipient = [4u8; 32];
        let inputs = [
            dummy_input([3u8; 32], 50_000, [21u8; 32]),
            dummy_input([3u8; 32], 0, [22u8; 32]),
        ];
        let outputs = [
            JoinSplitOutput {
                a_pk: a_pk(&recipient),
                pk_enc: pk_enc(&recipient),
                value: 0,
            },
            JoinSplitOutput {
                a_pk: a_pk(&recipient),
                pk_enc: pk_enc(&recipient),
                value: 0,
            },
        ];
        let b = compute_joinsplit_fields(
            &inputs,
            &outputs,
            0,
            50_000,
            [7u8; 32],
            &other.verification_key(),
            [11u8; 32],
            [13u8; 32],
        )
        .expect("fields");

        assert_ne!(a.h_sig, b.h_sig);
        assert_ne!(a.macs, b.macs);
    }

    /// The recipient must be able to decrypt the output note the JoinSplit
    /// created for them — otherwise the value is provably burned.
    #[test]
    fn the_recipient_can_decrypt_their_output() {
        let recipient = [4u8; 32];
        let fields = fields_for_test();

        for i in 0..JS_OUTPUTS {
            let note = crate::sprout::decrypt_note(
                &recipient,
                &fields.ephemeral_key,
                &fields.ciphertexts[i],
                &fields.h_sig,
                i as u8,
            )
            .expect("the recipient must be able to read the note addressed to them");
            // And it must be the note the commitment was made over, or the
            // recipient holds a note they cannot spend.
            let expected = note_commitment(&a_pk(&recipient), note.value, &note.rho, &note.r);
            assert_eq!(expected, fields.commitments[i]);
        }
    }

    #[test]
    fn a_signature_verifies_against_the_published_key() {
        let key = JoinSplitSigningKey::from_bytes([9u8; 32]);
        let sighash = [42u8; 32];
        let sig = key.sign(&sighash);

        let vk = ed25519_zebra::VerificationKey::try_from(key.verification_key())
            .expect("the published key must be a valid ed25519 point");
        vk.verify(&ed25519_zebra::Signature::from(sig), &sighash)
            .expect("the signature must verify under the key the JoinSplit publishes");
    }

    /// The whole point: a V4 transaction that carries a JoinSplit, is
    /// signed, and re-serializes to the same bytes it was built from.
    ///
    /// zcash_primitives' builder cannot produce this — it hardcodes
    /// `sprout_bundle: None` — so this exercises the hand-assembled path
    /// end to end, short of the proof itself.
    #[test]
    fn a_v4_transaction_carries_a_signed_joinsplit() {
        let key = JoinSplitSigningKey::from_bytes([9u8; 32]);
        let fields = fields_for_test();
        let js = build_js_description(&fields, &[0u8; GROTH_PROOF_SIZE]).expect("build");

        let tx = build_and_sign_v4(
            BranchId::Nu5,
            BlockHeight::from_u32(2_000_000),
            None,
            vec![js],
            &key,
        )
        .expect("assemble and sign");

        let bundle = tx
            .sprout_bundle()
            .expect("the transaction must carry the Sprout bundle we put in it");
        assert_eq!(bundle.joinsplits.len(), 1);
        assert_eq!(bundle.joinsplit_pubkey, key.verification_key());
        assert_ne!(
            bundle.joinsplit_sig, [0u8; 64],
            "the signature must be filled in, not left zeroed from the sighash pass"
        );

        // The signature must verify against the sighash of the same
        // transaction with the signature zeroed — the property consensus
        // checks.
        let unsigned = TransactionData::<Authorized>::from_parts(
            TxVersion::V4,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(2_000_000),
            None,
            Some(sprout_tx::Bundle {
                joinsplits: bundle.joinsplits.clone(),
                joinsplit_pubkey: bundle.joinsplit_pubkey,
                joinsplit_sig: [0u8; 64],
            }),
            None,
            None,
        );
        let sighash = v4_signature_hash(&unsigned, &SignableInput::Shielded);
        let vk = ed25519_zebra::VerificationKey::try_from(bundle.joinsplit_pubkey)
            .expect("published key is valid");
        vk.verify(
            &ed25519_zebra::Signature::from(bundle.joinsplit_sig),
            sighash.as_bytes(),
        )
        .expect("the JoinSplit signature must verify over the zeroed-signature sighash");

        // And it must round-trip on the wire.
        let mut bytes = Vec::new();
        tx.write(&mut bytes).expect("serialize");
        let reparsed = Transaction::read(&bytes[..], BranchId::Nu5).expect("re-read");
        assert_eq!(
            reparsed.sprout_bundle().expect("bundle survives").joinsplit_sig,
            bundle.joinsplit_sig
        );
    }

    /// A missing parameter file must say so plainly. This is the most
    /// likely first-run failure: the file is ~725 MB and is not shipped.
    #[test]
    fn a_missing_proving_key_is_reported_clearly() {
        let Err(err) = load_sprout_proving_key(std::path::Path::new("/nonexistent/sprout.params"))
        else {
            panic!("a missing parameter file must fail");
        };
        assert!(
            format!("{err}").contains("Sprout proving key"),
            "the error must name what is missing, got: {err}"
        );
    }

    /// A truncated download is the second most likely failure, and it is
    /// worth catching on size rather than several minutes later as an
    /// unreadable parameter set.
    #[test]
    fn a_wrong_sized_proving_key_is_rejected_on_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sprout-groth16.params");
        std::fs::write(&path, b"not the real parameters").expect("write");
        let Err(err) = load_sprout_proving_key(&path) else {
            panic!("a short file must fail");
        };
        let msg = format!("{err}");
        assert!(msg.contains("expected"), "must state the expected size: {msg}");
    }

    #[test]
    fn a_transaction_with_no_joinsplits_is_refused() {
        let key = JoinSplitSigningKey::from_bytes([9u8; 32]);
        assert!(build_and_sign_v4(
            BranchId::Nu5,
            BlockHeight::from_u32(2_000_000),
            None,
            vec![],
            &key,
        )
        .is_err());
    }

    #[test]
    fn a_wrong_length_ciphertext_is_refused() {
        let mut fields = fields_for_test();
        fields.ciphertexts[0].truncate(600);
        assert!(build_js_description(&fields, &[0u8; GROTH_PROOF_SIZE]).is_err());
    }
}
