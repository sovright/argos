#![cfg(feature = "sprout")]
//! The Sprout spend pipeline, end to end, from a real wallet file.
//!
//! Every other Sprout test checks one stage. This runs the whole chain a
//! recovery actually performs:
//!
//!   wallet.dat → a_sk → note commitment → tree → witness → 966-byte path
//!              → JoinSplit fields → JsDescription → signed V4 transaction
//!
//! The spending key is the genuine one recovered from the golden fixture, so
//! the key material entering the pipeline is real rather than invented.
//!
//! # What is necessarily simulated
//!
//! The *note* is synthetic. No fixture holds a funded Sprout note: zcashd
//! refuses inbound Sprout transfers regardless of Canopy height, so one
//! cannot be manufactured (`tests/regtest/fixtures/README.md`). A real note
//! would arrive with its value, rho and r decrypted from a JoinSplit
//! ciphertext; here those are chosen, and the commitment is computed from
//! them exactly as it would be.
//!
//! The *proof* is a zero placeholder. Producing a real one needs
//! `sprout-groth16.params`, ~725 MB, which is not bundled and not fetched in
//! tests. Everything the proof commits to is computed and asserted here; the
//! proof itself is the one untested link.
//!
//! So this establishes that the pipeline is self-consistent and produces a
//! structurally valid signed transaction. It does not establish that a real
//! node would accept it — that needs the parameters and a funded note.

use argos_core::{sprout, sprout_spend, sprout_witness};
use argos_wallet_import::{bdb, keys::ImportedKeys, zcashd};
use secrecy::ExposeSecret;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId};

fn recovered_sprout_key() -> [u8; 32] {
    let path = format!(
        "{}/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"));
    let records = bdb::walk(&bytes).expect("walk the wallet file");
    let mut keys = ImportedKeys::default();
    zcashd::collect_plaintext(&records, &mut keys);
    let key = keys.sprout.first().expect("the fixture holds a Sprout key");
    *key.a_sk.expose_secret()
}

#[test]
fn a_recovered_sprout_key_produces_a_signed_v4_transaction() {
    let a_sk = recovered_sprout_key();
    let a_pk = sprout::a_pk(&a_sk);

    // The note this wallet is going to spend. Synthetic, for the reason in
    // the module docs — but its commitment is computed the real way, which
    // is what the tree and the proof would both bind to.
    let note = sprout::SproutNotePlaintext {
        value: 1_000_000,
        rho: [0x21; 32],
        r: [0x22; 32],
        memo: [0u8; 512],
    };
    let commitment = sprout::note_commitment(&a_pk, note.value, &note.rho, &note.r);

    // Put it in a tree with other commitments around it, so the witness has
    // real siblings rather than only empty roots.
    let mut tree = sprout_witness::IncrementalMerkleTree::default();
    tree.append([0x01; 32]).expect("append");
    tree.append(commitment)
        .expect("append the note we will spend");
    let mut witness = sprout_witness::IncrementalWitness::from_tree(tree.clone());
    for i in 3..=6u8 {
        let mut leaf = [0u8; 32];
        leaf[0] = i;
        tree.append(leaf).expect("append");
        witness.append(leaf).expect("bring the witness forward");
    }

    let anchor = witness.root();
    assert_eq!(anchor, tree.root(), "the witness must track its tree");

    let path = witness
        .encode_for_prover()
        .expect("the witness must encode for the prover");
    assert_eq!(path.len(), sprout_witness::WITNESS_PATH_SIZE);

    // The JoinSplit: one real input, one zero-value dummy, both outputs
    // zero-value, and the whole balance pushed out through vpub_new into the
    // transparent value pool. That is how Sprout value reaches Sapling — a
    // Sapling output in the same transaction consumes it.
    let key = sprout_spend::JoinSplitSigningKey::from_bytes([0x33; 32]);
    let inputs = [
        sprout_spend::JoinSplitInput {
            note: note.clone(),
            a_sk,
            witness_path: path.to_vec(),
        },
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: [0x23; 32],
                r: [0x24; 32],
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: path.to_vec(),
        },
    ];
    // One address object, so the committed and encrypted halves cannot
    // describe different owners.
    let recipient = sprout::SproutPaymentAddress::from_spending_key(&a_sk);
    let outputs = [
        sprout_spend::JoinSplitOutput {
            recipient,
            value: 0,
        },
        sprout_spend::JoinSplitOutput {
            recipient,
            value: 0,
        },
    ];

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

    assert_eq!(fields.anchor, anchor);
    assert_eq!(
        fields.vpub_new, note.value,
        "the note's whole value must leave the Sprout pool"
    );
    assert_eq!(
        fields.nullifiers[0],
        sprout::prf_nf(&a_sk, &note.rho),
        "the nullifier must be the one this note's rho produces"
    );

    // The dummy input must not share the real input's nullifier, or the
    // JoinSplit spends the same note twice.
    assert_ne!(fields.nullifiers[0], fields.nullifiers[1]);

    let js = sprout_spend::build_js_description(&fields, &[0u8; sprout_spend::GROTH_PROOF_SIZE])
        .expect("the description must round-trip through serialization");

    let tx = sprout_spend::build_and_sign_v4(
        BranchId::Nu5,
        BlockHeight::from_u32(2_500_000),
        None,
        vec![js],
        &key,
    )
    .expect("assemble and sign the transaction");

    // It must survive the wire, since that is what gets broadcast.
    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize");
    let reparsed = Transaction::read(&raw[..], BranchId::Nu5).expect("re-read what we wrote");

    let bundle = reparsed
        .sprout_bundle()
        .expect("the re-read transaction must still carry its JoinSplit");
    assert_eq!(bundle.joinsplits.len(), 1);
    assert_eq!(bundle.joinsplits[0].anchor(), &anchor);
    assert_eq!(bundle.joinsplits[0].nullifiers(), &fields.nullifiers);
    assert_eq!(bundle.joinsplit_pubkey, key.verification_key());
    assert_ne!(bundle.joinsplit_sig, [0u8; 64]);

    // And the wallet must be able to read back the change note it paid
    // itself, or the outputs are unspendable.
    for i in 0..2usize {
        let recovered = sprout::decrypt_note(
            &a_sk,
            &fields.ephemeral_key,
            &fields.ciphertexts[i],
            &fields.h_sig,
            i as u8,
        )
        .expect("the wallet must be able to decrypt its own output");
        assert_eq!(
            sprout::note_commitment(&a_pk, recovered.value, &recovered.rho, &recovered.r),
            fields.commitments[i],
            "the decrypted output must reproduce its commitment"
        );

        // The scanner does not call `decrypt_note`: it precomputes `pk_enc`
        // per key and the Diffie-Hellman agreement per JoinSplit, because
        // `decrypt_note` otherwise redoes a base-point scalar multiplication
        // on every trial decryption and that is the dominant cost of a
        // full-chain scan. Splitting a crypto function for speed is exactly
        // the change that silently stops finding notes — the scan would
        // report a clean pass over the whole chain and simply miss the funds,
        // indistinguishable from a wallet that never held any. So the fast
        // path is pinned against the wrapper here, on real ciphertext.
        let dhsecret = *x25519_dalek::StaticSecret::from(sprout::sk_enc(&a_sk))
            .diffie_hellman(&x25519_dalek::PublicKey::from(fields.ephemeral_key))
            .as_bytes();
        let fast = sprout::decrypt_note_with_agreement(
            &dhsecret,
            &fields.ephemeral_key,
            recipient.pk_enc(),
            &fields.ciphertexts[i],
            &fields.h_sig,
            i as u8,
        )
        .expect("the fast path must decrypt what the wrapper decrypts");
        assert_eq!(fast.value, recovered.value, "output {i}: value");
        assert_eq!(fast.rho, recovered.rho, "output {i}: rho");
        assert_eq!(fast.r, recovered.r, "output {i}: r");
    }
}
