//! Prove a JoinSplit with the real Groth16 parameters, and verify it.
//!
//! This is the check the rest of the Sprout work could not make. Everything
//! else is self-consistency: my encryptor round-trips with my decryptor, my
//! path folds back to my root. A verifying proof is different, because the
//! circuit independently enforces almost everything the other modules
//! compute:
//!
//! * each nullifier is `PRF^nf(a_sk, rho)` for a note the prover holds
//! * each input note's commitment is in the tree at the claimed anchor,
//!   along the supplied authentication path
//! * each MAC is `PRF^pk(a_sk, i, hSig)`
//! * each output commitment is `NoteCommit^Sprout` over its note
//! * the value balance closes: inputs + vpub_old == outputs + vpub_new
//!
//! So if `verify_proof` returns true, the witness encoding, the PRF domain
//! tags, the note commitment (including the little-endian value that was
//! wrong the first time), and `hSig` are all correct — validated by the
//! consensus circuit rather than by me.
//!
//! Ignored by default: it needs `sprout-groth16.params` (~725 MB) and takes
//! minutes to load and prove.
//!
//!     cargo test -p argos-core --test sprout_proof_is_real -- --ignored

use argos_core::{sprout, sprout_spend, sprout_witness};
use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use secrecy::ExposeSecret;

fn params_path() -> std::path::PathBuf {
    std::env::var("ARGOS_SPROUT_PARAMS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME must be set");
            std::path::PathBuf::from(home)
                .join(".zcash-params")
                .join("sprout-groth16.params")
        })
}

fn recovered_sprout_key() -> [u8; 32] {
    let path = format!(
        "{}/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"));
    let records = bdb::walk(&bytes).expect("walk the wallet file");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&records, &mut keys);
    *keys
        .sprout
        .first()
        .expect("the fixture holds a Sprout key")
        .a_sk
        .expose_secret()
}

#[test]
#[ignore = "needs sprout-groth16.params (~725 MB); see the module docs"]
fn a_joinsplit_we_built_verifies_against_the_consensus_circuit() {
    let path = params_path();
    assert!(
        path.exists(),
        "expected the Sprout parameters at {}. Download with:\n  \
         curl -o {} https://download.z.cash/downloads/sprout-groth16.params",
        path.display(),
        path.display()
    );

    let proving_key =
        sprout_spend::load_sprout_proving_key(&path).expect("the parameters must load");

    // A real spending key, and a note placed in a tree with siblings so the
    // circuit's Merkle check has something to do.
    let a_sk = recovered_sprout_key();
    let a_pk = sprout::a_pk(&a_sk);
    let note = sprout::SproutNotePlaintext {
        value: 1_000_000,
        rho: [0x21; 32],
        r: [0x22; 32],
        memo: [0u8; 512],
    };
    let commitment = sprout::note_commitment(&a_pk, note.value, &note.rho, &note.r);

    let mut tree = sprout_witness::IncrementalMerkleTree::default();
    tree.append([0x01; 32]).expect("append");
    tree.append(commitment).expect("append the note to spend");
    let mut witness = sprout_witness::IncrementalWitness::from_tree(tree.clone());
    for i in 3..=6u8 {
        let mut leaf = [0u8; 32];
        leaf[0] = i;
        tree.append(leaf).expect("append");
        witness.append(leaf).expect("bring the witness forward");
    }
    let anchor = witness.root();
    let auth = witness.encode_for_prover().expect("encode the path");

    // The second input is a zero-value dummy. The circuit skips the Merkle
    // check for those, which is what lets a JoinSplit exist before any
    // Sprout note does.
    let key = sprout_spend::JoinSplitSigningKey::from_bytes([0x33; 32]);
    let inputs = [
        sprout_spend::JoinSplitInput {
            note: note.clone(),
            a_sk,
            witness_path: auth.to_vec(),
        },
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: [0x23; 32],
                r: [0x24; 32],
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: auth.to_vec(),
        },
    ];
    // One address object, so the committed and encrypted halves cannot
    // describe different owners.
    let recipient = sprout::SproutPaymentAddress::from_spending_key(&a_sk);
    let outputs = [
        sprout_spend::JoinSplitOutput { recipient, value: 0 },
        sprout_spend::JoinSplitOutput { recipient, value: 0 },
    ];

    // Everything leaves the Sprout pool: 1_000_000 in, 1_000_000 out through
    // vpub_new. The circuit enforces this balance.
    let fields = sprout_spend::compute_joinsplit_fields(
        &inputs,
        &outputs,
        0,
        note.value,
        anchor,
        &key.verification_key(),
        [0x44; 32],
        [0x66; 32],
        [0x55; 32],
    )
    .expect("compute the JoinSplit fields");

    let proof = sprout_spend::prove_joinsplit(&fields, &inputs, &outputs, &proving_key)
        .expect("the circuit must be satisfiable by the witness we assembled");

    let vk = sprout_spend::load_sprout_verifying_key(&path).expect("verifying key");
    assert!(
        zcash_proofs::sprout::verify_proof(
            &proof,
            &fields.anchor,
            &fields.h_sig,
            &fields.macs[0],
            &fields.macs[1],
            &fields.nullifiers[0],
            &fields.nullifiers[1],
            &fields.commitments[0],
            &fields.commitments[1],
            fields.vpub_old,
            fields.vpub_new,
            &vk,
        ),
        "the consensus circuit rejected a JoinSplit we built"
    );

    // And it must survive assembly into a transaction.
    let js = sprout_spend::build_js_description(&fields, &proof).expect("build the description");
    let tx = sprout_spend::build_and_sign_v4(
        zcash_protocol::consensus::BranchId::Nu5,
        zcash_protocol::consensus::BlockHeight::from_u32(2_500_000),
        None,
        vec![js],
        &key,
    )
    .expect("assemble and sign");
    assert!(tx.sprout_bundle().is_some());
}
