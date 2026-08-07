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
    SproutPaymentAddress, NOTE_CIPHERTEXT_LEN,
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
///
/// The recipient is a whole `SproutPaymentAddress` rather than a separate
/// `a_pk` and `pk_enc`. Taking them separately allowed a caller to commit to
/// one party and encrypt to another, which makes the output permanently
/// unspendable with nothing at broadcast time to show for it.
pub struct JoinSplitOutput {
    pub recipient: SproutPaymentAddress,
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
/// `phi`, `random_seed` and `esk` are supplied rather than sampled internally
/// so tests can be deterministic. Production callers must pass fresh
/// randomness for each.
///
/// **`phi` and `random_seed` must be independent.** `random_seed` is a
/// *public* JoinSplit field; `phi` is a *private* circuit witness. zcashd
/// samples them separately (`random_uint252` and `random_uint256`). Setting
/// `random_seed = phi` — which this originally did — publishes `phi`, and
/// since every output's `rho` is `PRF^rho_phi(i, hSig)`, that makes all
/// output `rho` values publicly computable. Combined with deriving `r` from
/// `phi`, it would make the commitment randomness public too, letting anyone
/// test candidate `a_pk` values against the commitments.
///
/// Only the low 252 bits of `phi` are used: the circuit takes it as a
/// 252-bit witness, and `PRF^rho` overwrites the top four bits with its tag.
#[allow(clippy::too_many_arguments)]
pub fn compute_joinsplit_fields(
    inputs: &[JoinSplitInput; JS_INPUTS],
    outputs: &[JoinSplitOutput; JS_OUTPUTS],
    vpub_old: u64,
    vpub_new: u64,
    anchor: [u8; 32],
    joinsplit_pubkey: &[u8; 32],
    phi: [u8; 32],
    random_seed: [u8; 32],
    esk: [u8; 32],
) -> ZeckResult<JoinSplitFields> {
    // Nullifiers first: hSig commits to them.
    let nullifiers = [
        prf_nf(&inputs[0].a_sk, &inputs[0].note.rho),
        prf_nf(&inputs[1].a_sk, &inputs[1].note.rho),
    ];

    // hSig is computed over the *public* random_seed, not over phi.
    let h_sig = h_sig(&random_seed, &nullifiers, joinsplit_pubkey);

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
        commitments[i] =
            note_commitment(outputs[i].recipient.a_pk(), outputs[i].value, &rho, &r);

        let note = SproutNotePlaintext {
            value: outputs[i].value,
            rho,
            r,
            memo: [0u8; 512],
        };
        ciphertexts[i] =
            encrypt_note(&esk, outputs[i].recipient.pk_enc(), &h_sig, i as u8, &note.to_bytes())
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
        random_seed,
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
/// covers Sapling only.
///
/// The size is checked first, because a truncated download otherwise surfaces
/// as an opaque deserialization failure minutes in. The BLAKE2b-512 digest is
/// then verified against the value pinned in `zcash_proofs`, streaming as the
/// parameters are read so the 725 MB is only traversed once.
///
/// That verification is not optional. Parsing uses `checked = false`, which
/// skips the point-validity pass — several minutes of work — and is only
/// defensible because the bytes are authenticated first. An earlier version
/// of this function asserted in a comment that the hash "was verified on
/// download" while doing no such check, which is precisely the kind of
/// assumption that survives review by being written down.
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
    let mut reader = HashingReader::new(reader);

    // `checked = false` skips the point-validity pass, which costs minutes.
    // Defensible only because the digest is verified below.
    let params = Parameters::<Bls12>::read(&mut reader, false).map_err(|err| {
        ZeckError::InvalidConfig(format!("parsing the Sprout proving key: {err}"))
    })?;

    // Drain whatever the parser did not consume before finalizing: the
    // digest is over the whole file, and `Parameters::read` stops as soon as
    // it has what it needs. Hashing only the consumed prefix produces a
    // mismatch against a perfectly good file — which is what happened the
    // first time this check was added. zcash_proofs drains the same way.
    std::io::copy(&mut reader, &mut std::io::sink()).map_err(|err| {
        ZeckError::InvalidConfig(format!("reading the Sprout proving key to its end: {err}"))
    })?;

    let digest = reader.finalize();
    if digest.as_bytes() != SPROUT_HASH {
        return Err(ZeckError::InvalidConfig(format!(
            "the Sprout proving key at {} does not match the expected digest.              Refusing to prove with unauthenticated parameters.",
            path.display()
        )));
    }
    Ok(params)
}

/// The expected size of `sprout-groth16.params`, from `zcash_proofs`.
pub const SPROUT_BYTES: u64 = 725_523_612;

/// The BLAKE2b-512 digest of `sprout-groth16.params`, from `zcash_proofs`.
/// Kept as bytes so the comparison cannot be fooled by hex casing.
const SPROUT_HASH: [u8; 64] = [
    0xe9, 0xb2, 0x38, 0x41, 0x1b, 0xd6, 0xc0, 0xec, 0x47, 0x91, 0xe9, 0xd0, 0x42, 0x45, 0xec, 0x35,
    0x0c, 0x9c, 0x57, 0x44, 0xf5, 0x61, 0x0d, 0xfc, 0xce, 0x43, 0x65, 0xd5, 0xca, 0x49, 0xdf, 0xef,
    0xd5, 0x05, 0x4e, 0x37, 0x18, 0x42, 0xb3, 0xf8, 0x8f, 0xa1, 0xb9, 0xd7, 0xe8, 0xe0, 0x75, 0x24,
    0x9b, 0x3e, 0xba, 0xbd, 0x16, 0x7f, 0xa8, 0xb0, 0xf3, 0x16, 0x12, 0x92, 0xd3, 0x6c, 0x18, 0x0a,
];

/// Streams the file through BLAKE2b while it is being parsed, so the 725 MB
/// is read once rather than twice.
struct HashingReader<R> {
    inner: R,
    state: blake2b_simd::State,
}

impl<R: std::io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            state: blake2b_simd::State::new(),
        }
    }

    fn finalize(self) -> blake2b_simd::Hash {
        self.state.finalize()
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.state.update(&buf[..n]);
        Ok(n)
    }
}

/// Load the Sprout verifying key from the same parameter file.
///
/// Consensus verifies JoinSplits with this; checking our own proof against
/// it is the only way to know the circuit accepts what we assembled, short
/// of a node doing it.
pub fn load_sprout_verifying_key(
    path: &std::path::Path,
) -> ZeckResult<bellman::groth16::PreparedVerifyingKey<Bls12>> {
    let params = load_sprout_proving_key(path)?;
    Ok(bellman::groth16::prepare_verifying_key(&params.vk))
}

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
        *outputs[0].recipient.a_pk(),
        outputs[0].value,
        prf_rho(&fields.phi, 0, &fields.nullifiers[0]),
        *outputs[1].recipient.a_pk(),
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

/// One transparent input funding a JoinSplit's `vpub_old`.
pub struct TransparentFunding {
    pub txid: [u8; 32],
    pub index: u32,
    pub value: u64,
    /// The `scriptPubKey` being spent, which is also the `scriptCode` for a
    /// P2PKH sighash.
    pub script_pubkey: Vec<u8>,
    pub secret: secp256k1::SecretKey,
}

/// Assemble a V4 transaction with transparent inputs feeding a JoinSplit,
/// and sign everything.
///
/// This is how value *enters* the Sprout pool, and the only route to a real
/// Sprout note on a chain that has never had one: a JoinSplit's zero-value
/// inputs skip the circuit's Merkle check, so no prior note or witness is
/// needed. It is how Sprout was funded before any Sprout note existed.
///
/// `zcash_primitives`' builder cannot express this — it emits no Sprout
/// bundle — so the transparent inputs are signed by hand here, the same way
/// the JoinSplit is.
///
/// No transparent outputs are produced: everything not claimed by
/// `vpub_old` is the fee. That also keeps the transaction valid if an input
/// ever happens to be coinbase, since consensus forbids a transaction
/// spending transparent coinbase from having transparent outputs.
pub fn build_and_sign_v4_shielding(
    consensus_branch_id: BranchId,
    expiry_height: BlockHeight,
    funding: &[TransparentFunding],
    joinsplits: Vec<sprout_tx::JsDescription>,
    key: &JoinSplitSigningKey,
) -> ZeckResult<Transaction> {
    use zcash_transparent::address::Script;
    use zcash_transparent::bundle::{Authorized as TAuthorized, OutPoint, TxIn};
    use zcash_transparent::sighash::SighashType;

    if funding.is_empty() {
        return Err(ZeckError::TransactionBuild(
            "a shielding transaction needs at least one transparent input".to_owned(),
        ));
    }

    let secp = secp256k1::Secp256k1::new();

    // Pass one: an unsigned bundle, so the sighash has the right shape. Each
    // script_sig is empty; the sighash for a given input substitutes that
    // input's script_code anyway.
    let build_bundle = |sigs: &[Vec<u8>]| zcash_transparent::bundle::Bundle::<TAuthorized> {
        vin: funding
            .iter()
            .enumerate()
            .map(|(i, f)| {
                TxIn::from_parts(
                    OutPoint::new(f.txid, f.index),
                    Script(zcash_script::script::Code(sigs.get(i).cloned().unwrap_or_default())),
                    0xFFFF_FFFF,
                )
            })
            .collect(),
        vout: Vec::new(),
        authorization: TAuthorized,
    };

    let sprout_bundle = |sig: [u8; 64]| sprout_tx::Bundle {
        joinsplits: joinsplits.clone(),
        joinsplit_pubkey: key.verification_key(),
        joinsplit_sig: sig,
    };

    let empty: Vec<Vec<u8>> = Vec::new();
    let unsigned = TransactionData::<Authorized>::from_parts(
        TxVersion::V4,
        consensus_branch_id,
        0,
        expiry_height,
        Some(build_bundle(&empty)),
        Some(sprout_bundle([0u8; 64])),
        None,
        None,
    );

    // Sign each transparent input over its own sighash.
    let mut script_sigs = Vec::with_capacity(funding.len());
    for (i, f) in funding.iter().enumerate() {
        let script = Script(zcash_script::script::Code(f.script_pubkey.clone()));
        let value = zcash_protocol::value::Zatoshis::from_u64(f.value).map_err(|err| {
            ZeckError::TransactionBuild(format!("input {i} value out of range: {err}"))
        })?;
        let signable = zcash_transparent::sighash::SignableInput::from_parts(
            unsigned
                .transparent_bundle()
                .expect("we just supplied a transparent bundle"),
            SighashType::ALL,
            i,
            &script,
            &script,
            value,
        )
        .map_err(|err| ZeckError::TransactionBuild(format!("signable input {i}: {err:?}")))?;

        let sighash = v4_signature_hash(&unsigned, &SignableInput::Transparent(signable));
        let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes())
            .map_err(|err| ZeckError::TransactionBuild(format!("sighash {i}: {err}")))?;
        let sig = secp.sign_ecdsa(&msg, &f.secret);

        // scriptSig = PUSH(der||SIGHASH_ALL) PUSH(pubkey)
        let mut der = sig.serialize_der().to_vec();
        der.push(SighashType::ALL.encode());
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &f.secret).serialize();

        let mut script_sig = Vec::with_capacity(der.len() + pubkey.len() + 2);
        script_sig.push(der.len() as u8);
        script_sig.extend_from_slice(&der);
        script_sig.push(pubkey.len() as u8);
        script_sig.extend_from_slice(&pubkey);
        script_sigs.push(script_sig);
    }

    // Pass two: the JoinSplit signature, over the transaction with the
    // transparent inputs now signed and joinsplit_sig still zeroed.
    let with_scripts = TransactionData::<Authorized>::from_parts(
        TxVersion::V4,
        consensus_branch_id,
        0,
        expiry_height,
        Some(build_bundle(&script_sigs)),
        Some(sprout_bundle([0u8; 64])),
        None,
        None,
    );
    let js_sighash = v4_signature_hash(&with_scripts, &SignableInput::Shielded);
    let mut js_bytes = [0u8; 32];
    js_bytes.copy_from_slice(js_sighash.as_bytes());

    let signed = TransactionData::<Authorized>::from_parts(
        TxVersion::V4,
        consensus_branch_id,
        0,
        expiry_height,
        Some(build_bundle(&script_sigs)),
        Some(sprout_bundle(key.sign(&js_bytes))),
        None,
        None,
    );

    signed.freeze().map_err(|err| {
        ZeckError::TransactionBuild(format!("freezing the shielding transaction: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprout::a_pk;

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
        let addr = SproutPaymentAddress::from_spending_key(&recipient);
        let outputs = [
            JoinSplitOutput { recipient: addr, value: 0 },
            JoinSplitOutput { recipient: addr, value: 0 },
        ];
        compute_joinsplit_fields(
            &inputs,
            &outputs,
            0,
            50_000,
            [7u8; 32],
            &key.verification_key(),
            [11u8; 32],
            [12u8; 32],
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
        let addr = SproutPaymentAddress::from_spending_key(&recipient);
        let outputs = [
            JoinSplitOutput { recipient: addr, value: 0 },
            JoinSplitOutput { recipient: addr, value: 0 },
        ];
        let b = compute_joinsplit_fields(
            &inputs,
            &outputs,
            0,
            50_000,
            [7u8; 32],
            &other.verification_key(),
            [11u8; 32],
            [12u8; 32],
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
