//! Create a real Sprout note on a node, then spend it — and let consensus
//! judge both halves.
//!
//! This is the only test where an implementation other than mine decides
//! whether the transaction is valid. It checks what neither my own tests nor
//! the proving circuit can: transaction version and branch ID, the v4 sighash
//! across a transparent *and* a Sprout bundle, the transparent input
//! signatures, the JoinSplit signature under the published key, the anchor
//! being a root the chain knows, and the value balance across pools.
//!
//! # Why a separate chain, and why zcashd
//!
//! ZIP 211 disabled adding value to the Sprout pool from Canopy onward. The
//! main harness activates Canopy at height 1, so a shielding JoinSplit there
//! is rejected outright — "adding to the sprout pool is disabled after
//! Canopy" — and with no note there is nothing for the spend path to spend.
//!
//! So this runs against `zcashd-sprout`, which holds Canopy at 9,999,999.
//! zcashd rather than Zebra because Zebra refuses to mine below Canopy at all
//! ("does not support generating pre-Canopy block templates"), and because
//! zcashd has `sendtoaddress`, so a transparent output can be paid to a key
//! we hold.
//!
//! The tradeoff: zcashd cannot activate Ironwood, so this exercises Sprout
//! under pre-Canopy rules. JoinSplit validation does not change across the
//! later upgrades, and the alternative is not testing the spend path at all.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --features argos-network \
//!         --test sprout_consensus_roundtrip -- --ignored --nocapture

#![cfg(feature = "argos-network")]

use argos_core::{sprout, sprout_spend, sprout_witness};
use zcash_protocol::consensus::{BlockHeight, BranchId};

const RPC: &str = "http://127.0.0.1:18242";
/// ZIP 317's conventional fee for this shape, not the 10,000 floor.
///
/// Logical actions here: one transparent input, plus two per JoinSplit —
/// three in total, at 5,000 zatoshi each. Paying the floor instead gets the
/// transaction relayed nowhere: "tx unpaid action limit exceeded: 1 action(s)
/// exceeds limit of 0", which is mempool policy rather than a validity
/// failure and so says nothing about whether the transaction is correct.
const FEE: u64 = 15_000;

/// Minimal JSON-RPC over a raw socket, with the basic auth zcashd requires.
///
/// Deliberately not an HTTP client dependency: the harness already speaks
/// JSON-RPC this way, and one test does not justify pulling reqwest into a
/// wallet-recovery tool's dependency graph.
async fn rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let host_port = RPC.strip_prefix("http://").unwrap_or(RPC);
    let body = serde_json::json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
    let payload = serde_json::to_vec(&body).expect("serializable");
    let auth = base64::engine::general_purpose::STANDARD.encode("argos-regtest:argos-regtest");

    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .unwrap_or_else(|err| panic!("connecting to zcashd at {host_port}: {err}"));
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Basic {auth}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes()).await.expect("headers");
    stream.write_all(&payload).await.expect("body");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("response");
    let text = String::from_utf8_lossy(&raw);
    let json_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let parsed: serde_json::Value = serde_json::from_str(text[json_start..].trim())
        .unwrap_or_else(|err| panic!("zcashd {method} returned unparseable body: {err}\n{text}"));

    if let Some(error) = parsed.get("error") {
        if !error.is_null() {
            panic!("zcashd {method} failed: {error}");
        }
    }
    parsed
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// Fresh randomness per run.
///
/// Not decoration: a nullifier is `PRF^nf(a_sk, rho)`, so fixed dummy `rho`
/// values produce the same nullifiers on every run and the chain rejects the
/// second one with `bad-txns-sprout-duplicate-nullifier`. `compute_joinsplit_fields`
/// documents that production callers must pass fresh randomness; a test that
/// runs twice against one chain has the same requirement.
fn random32() -> [u8; 32] {
    use rand_core::RngCore;
    let mut out = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut out);
    out
}

fn params_path() -> std::path::PathBuf {
    std::env::var("ARGOS_SPROUT_PARAMS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").expect("HOME"))
                .join(".zcash-params")
                .join("sprout-groth16.params")
        })
}

/// The branch ID in force at the chain tip, so the transaction is signed for
/// the epoch it will be mined in.
async fn tip_branch_id() -> BranchId {
    let info = rpc("getblockchaininfo", serde_json::json!([])).await;
    let hex = info["consensus"]["nextblock"]
        .as_str()
        .expect("nextblock branch id");
    let raw = u32::from_str_radix(hex, 16).expect("branch id is hex");
    BranchId::try_from(raw).unwrap_or_else(|_| panic!("unknown branch id {hex}"))
}

#[tokio::test]
#[ignore = "requires the sprout profile and sprout-groth16.params; see the module docs"]
async fn a_sprout_note_can_be_created_and_spent_under_consensus() {
    let params = params_path();
    assert!(
        params.exists(),
        "need the Sprout parameters at {}",
        params.display()
    );
    let proving_key = sprout_spend::load_sprout_proving_key(&params).expect("proving key");

    let key = argos_core::imported::ImportedTransparentKey {
        secret: secp256k1::SecretKey::from_slice(&[0x11; 32]).expect("key"),
        address: {
            let secp = secp256k1::Secp256k1::signing_only();
            let pk = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&[0x11; 32]).expect("key"),
            );
            zcash_transparent::address::TransparentAddress::from_pubkey(&pk)
        },
    };

    // Fund it. zcashd's own wallet pays a key we hold; Zebra cannot do this.
    rpc("generate", serde_json::json!([120])).await;
    let addr = argos_core::imported::encode_transparent_address(
        &key.address,
        argos_core::ZeckNetwork::Testnet,
    );
    let txid = rpc("sendtoaddress", serde_json::json!([addr, 5.0]))
        .await
        .as_str()
        .expect("txid")
        .to_owned();
    rpc("generate", serde_json::json!([1])).await;

    let funding = rpc("getrawtransaction", serde_json::json!([txid, 1])).await;
    let vout = funding["vout"]
        .as_array()
        .expect("vout")
        .iter()
        .find(|v| {
            v["scriptPubKey"]["addresses"]
                .as_array()
                .map(|a| a.iter().any(|s| s.as_str() == Some(addr.as_str())))
                .unwrap_or(false)
        })
        .expect("an output paying our address");
    let value = (vout["value"].as_f64().expect("value") * 1e8).round() as u64;
    let index = vout["n"].as_u64().expect("n") as u32;
    let script = hex_to_bytes(
        vout["scriptPubKey"]["hex"]
            .as_str()
            .expect("scriptPubKey hex"),
    );
    let mut txid_bytes = hex_to_bytes(&txid);
    txid_bytes.reverse(); // RPC prints txids big-endian; the wire is little-endian.
    let txid_arr: [u8; 32] = txid_bytes.try_into().expect("32-byte txid");

    // ── Shield: transparent value in, a Sprout note out ───────────────────
    let a_sk = random32();
    let recipient = sprout::SproutPaymentAddress::from_spending_key(&a_sk);
    let shielded = value - FEE;

    let js_key = sprout_spend::JoinSplitSigningKey::from_bytes(random32());
    let dummy = sprout_witness::dummy_path().to_vec();
    let inputs = [
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: random32(),
                r: random32(),
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: dummy.clone(),
        },
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: random32(),
                r: random32(),
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: dummy,
        },
    ];
    let outputs = [
        sprout_spend::JoinSplitOutput {
            recipient,
            value: shielded,
        },
        sprout_spend::JoinSplitOutput {
            recipient,
            value: 0,
        },
    ];

    let fields = sprout_spend::compute_joinsplit_fields(
        &inputs,
        &outputs,
        shielded, // vpub_old: value entering the pool
        0,
        sprout_witness::empty_tree_root(),
        &js_key.verification_key(),
        random32(),
        random32(),
        random32(),
    )
    .expect("compute fields");

    let proof = sprout_spend::prove_joinsplit(&fields, &inputs, &outputs, &proving_key)
        .expect("prove the shielding JoinSplit");
    let js = sprout_spend::build_js_description(&fields, &proof).expect("build description");

    let height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .unwrap();
    let tx = sprout_spend::build_and_sign_v4_shielding(
        tip_branch_id().await,
        BlockHeight::from_u32(height as u32 + 40),
        &[sprout_spend::TransparentFunding {
            txid: txid_arr,
            index,
            value,
            script_pubkey: script,
            secret: key.secret,
        }],
        vec![js],
        &js_key,
    )
    .expect("assemble the shielding transaction");

    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize");
    let sent = rpc(
        "sendrawtransaction",
        serde_json::json!([bytes_to_hex(&raw)]),
    )
    .await;
    let shield_txid = sent
        .as_str()
        .expect("the node accepted the shielding transaction");
    eprintln!("[sprout] shielding accepted: {shield_txid}");

    rpc("generate", serde_json::json!([1])).await;
    let shield_height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .unwrap();
    let mined = rpc("getrawtransaction", serde_json::json!([shield_txid, 1])).await;
    assert!(
        mined["confirmations"].as_u64().unwrap_or(0) >= 1,
        "the shielding transaction did not mine"
    );

    eprintln!(
        "[sprout] note commitment {} is now in the chain's Sprout tree",
        bytes_to_hex(&fields.commitments[0])
    );

    // ── Spend: the Sprout note out, into a Sapling output ─────────────────
    //
    // This is the direction Argos exists for. Sprout cannot pay Sapling
    // directly — a JoinSplit's outputs are Sprout notes — so the value
    // leaves through vpub_new into the transparent value pool and a Sapling
    // output in the same transaction consumes it.

    // The note we are spending is the first output of the shielding
    // JoinSplit. Its rho and r are derived, not chosen, so they are
    // recomputed the same way the builder did.
    let spent = sprout::SproutNotePlaintext {
        value: shielded,
        rho: sprout::prf_rho(&fields.phi, 0, &fields.h_sig),
        r: sprout::prf_rho(&fields.phi, 0, &fields.nullifiers[0]),
        memo: [0u8; 512],
    };
    assert_eq!(
        sprout::note_commitment(recipient.a_pk(), spent.value, &spent.rho, &spent.r),
        fields.commitments[0],
        "the note we think we are spending must be the one that was committed"
    );

    // Rebuild the tree as the chain actually has it.
    //
    // Assuming an empty tree is wrong the moment anything else has ever
    // shielded — including an earlier run of this very test — and yields
    // `bad-txns-sprout-unknown-anchor`, which reads like a bug in the
    // witness code rather than a wrong starting point. `z_gettreestate`
    // returns the serialized tree, which is the structure the wallet parser
    // already reads.
    let before = rpc(
        "z_gettreestate",
        serde_json::json!([(shield_height - 1).to_string()]),
    )
    .await;
    let final_state = before["sprout"]["commitments"]["finalState"]
        .as_str()
        .expect("z_gettreestate returns the sprout tree");
    let mut tree = sprout_witness::IncrementalMerkleTree::parse(&hex_to_bytes(final_state))
        .expect("the chain's Sprout tree must parse");

    tree.append(fields.commitments[0]).expect("append note");
    let mut witness = sprout_witness::IncrementalWitness::from_tree(tree.clone());
    tree.append(fields.commitments[1]).expect("append sibling");
    witness
        .append(fields.commitments[1])
        .expect("witness forward");
    let anchor = witness.root();
    assert_eq!(anchor, tree.root(), "witness must track its tree");

    // Cross-check against the node: our reconstruction must equal the tree
    // the chain computed for the block our note landed in. This validates
    // the tree implementation against zcashd rather than against itself.
    let after = rpc(
        "z_gettreestate",
        serde_json::json!([shield_height.to_string()]),
    )
    .await;
    let chain_root = after["sprout"]["commitments"]["finalRoot"]
        .as_str()
        .expect("finalRoot");
    let mut chain_root_bytes = hex_to_bytes(chain_root);
    chain_root_bytes.reverse(); // RPC prints roots big-endian.
    assert_eq!(
        anchor.to_vec(),
        chain_root_bytes,
        "our Sprout tree does not match the one the chain computed"
    );

    // Four logical actions, not three: two for the JoinSplit, and two for
    // Sapling because BundleType::DEFAULT pads outputs to
    // MIN_SHIELDED_OUTPUTS. One output is billed as two — the same padding
    // that makes a "Sapling-only" PCZT still carry an Orchard bundle, and
    // the same trap the PCZT fee logic already had to account for.
    let spend_fee = 20_000u64;
    let to_sapling = spent.value - spend_fee;

    let spend_key = sprout_spend::JoinSplitSigningKey::from_bytes(random32());
    let spend_inputs = [
        sprout_spend::JoinSplitInput {
            note: spent.clone(),
            a_sk,
            witness_path: witness.encode_for_prover().expect("encode path").to_vec(),
        },
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: random32(),
                r: random32(),
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: sprout_witness::dummy_path().to_vec(),
        },
    ];
    let spend_outputs = [
        sprout_spend::JoinSplitOutput {
            recipient,
            value: 0,
        },
        sprout_spend::JoinSplitOutput {
            recipient,
            value: 0,
        },
    ];

    let spend_fields = sprout_spend::compute_joinsplit_fields(
        &spend_inputs,
        &spend_outputs,
        0,
        spent.value, // vpub_new: the whole note leaves the Sprout pool
        anchor,
        &spend_key.verification_key(),
        random32(),
        random32(),
        random32(),
    )
    .expect("compute spend fields");

    let spend_proof =
        sprout_spend::prove_joinsplit(&spend_fields, &spend_inputs, &spend_outputs, &proving_key)
            .expect("prove the spend JoinSplit");
    let spend_js =
        sprout_spend::build_js_description(&spend_fields, &spend_proof).expect("build description");

    // A Sapling output consuming what the JoinSplit released.
    let sapling_prover = zcash_proofs::prover::LocalTxProver::bundled();
    let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&random32());
    let (_, sapling_addr) = extsk.default_address();

    // No Sapling spends, so the anchor is unused — but the builder still
    // requires one. ZIP 212 enforcement is off because this chain is
    // pre-Canopy, which is the whole reason it exists.
    let mut sapling_builder = sapling_crypto::builder::Builder::new(
        sapling_crypto::note_encryption::Zip212Enforcement::Off,
        sapling_crypto::builder::BundleType::DEFAULT,
        sapling_crypto::Anchor::empty_tree(),
    );
    sapling_builder
        .add_output(
            None,
            sapling_addr,
            sapling_crypto::value::NoteValue::from_raw(to_sapling),
            [0u8; 512],
        )
        .expect("add the Sapling output");
    let (sapling_bundle, _meta) = sapling_builder
        .build::<zcash_proofs::prover::LocalTxProver, zcash_proofs::prover::LocalTxProver, _, zcash_protocol::value::ZatBalance>(
            &[],
            rand_core::OsRng,
        )
        .expect("build the Sapling bundle")
        .expect("the bundle must have an output");

    let spend_height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .unwrap();
    let spend_tx = sprout_spend::build_and_sign_v4_sprout_to_sapling(
        tip_branch_id().await,
        BlockHeight::from_u32(spend_height as u32 + 40),
        vec![spend_js],
        sapling_bundle,
        &sapling_prover,
        &spend_key,
        rand_core::OsRng,
    )
    .expect("assemble the Sprout-to-Sapling transaction");

    let mut spend_raw = Vec::new();
    spend_tx.write(&mut spend_raw).expect("serialize");
    let spend_sent = rpc(
        "sendrawtransaction",
        serde_json::json!([bytes_to_hex(&spend_raw)]),
    )
    .await;
    let spend_txid = spend_sent
        .as_str()
        .expect("the node accepted the Sprout-to-Sapling transaction");
    eprintln!("[sprout] SPEND accepted: {spend_txid}");

    rpc("generate", serde_json::json!([1])).await;
    let spend_mined = rpc("getrawtransaction", serde_json::json!([spend_txid, 1])).await;
    assert!(
        spend_mined["confirmations"].as_u64().unwrap_or(0) >= 1,
        "the Sprout-to-Sapling transaction did not mine"
    );
    eprintln!("[sprout] {to_sapling} zatoshi migrated from Sprout to Sapling under consensus");
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
