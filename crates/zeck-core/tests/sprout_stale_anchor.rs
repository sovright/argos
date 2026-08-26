//! Does consensus accept a *historical* Sprout anchor?
//!
//! # Why this is load-bearing
//!
//! Recovering Sprout funds from a `wallet.dat` uses the witness zcashd
//! cached when that wallet last synced — which may have been years ago. The
//! anchor it yields is the Sprout root as of that moment, not the current
//! one. If nodes only accepted a recent anchor, the entire cached-witness
//! path would be worthless, and the only route to those funds would be a
//! multi-hour full-block rescan to rebuild a current witness.
//!
//! The existing `sprout_consensus_roundtrip` test does not settle this. It
//! builds its anchor from `z_gettreestate` at the block its note landed in
//! and spends immediately, so the anchor is still current when the node sees
//! it. Every Sprout spend proven so far has used a fresh anchor.
//!
//! # How this tests it without a second shielding
//!
//! A JoinSplit has two outputs, so one shielding transaction creates two
//! real notes sharing one anchor. Spending the first is itself a JoinSplit,
//! whose own outputs append two more commitments and move the tree on. The
//! second note is then spent with its original, now-stale anchor — the exact
//! situation a years-old cached witness produces.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test sprout_stale_anchor -- --ignored --nocapture

use argos_core::{sprout, sprout_spend, sprout_witness};
use zcash_protocol::consensus::{BlockHeight, BranchId};

const RPC: &str = "http://127.0.0.1:18242";

/// ZIP 317: two logical actions per JoinSplit, plus two for the Sapling
/// bundle because `BundleType::DEFAULT` pads outputs to
/// `MIN_SHIELDED_OUTPUTS` — one output is billed as two.
const SPEND_FEE: u64 = 20_000;

/// One transparent input plus two per JoinSplit, at 5,000 each.
const SHIELD_FEE: u64 = 15_000;

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
    let start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    serde_json::from_str::<serde_json::Value>(text[start..].trim())
        .unwrap_or_else(|err| panic!("zcashd {method}: unparseable body: {err}\n{text}"))
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// Like `rpc`, but returns the error instead of discarding it.
///
/// The point of this test is *which* rejection a stale anchor produces, so
/// the error text cannot be thrown away.
async fn rpc_try(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let host_port = RPC.strip_prefix("http://").unwrap_or(RPC);
    let body = serde_json::json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
    let payload = serde_json::to_vec(&body).expect("serializable");
    let auth = base64::engine::general_purpose::STANDARD.encode("argos-regtest:argos-regtest");

    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .map_err(|e| e.to_string())?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Basic {auth}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let parsed: serde_json::Value =
        serde_json::from_str(text[start..].trim()).map_err(|e| e.to_string())?;

    if let Some(error) = parsed.get("error") {
        if !error.is_null() {
            return Err(error.to_string());
        }
    }
    Ok(parsed
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

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

async fn tip_branch_id() -> BranchId {
    let height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height");
    let info = rpc("getblockchaininfo", serde_json::json!([])).await;
    let _ = info;
    // This chain holds Canopy inactive, which is the only condition under
    // which Sprout can be funded at all (ZIP 211).
    let _ = height;
    BranchId::Heartwood
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Build and broadcast a Sprout->Sapling spend of `note` against `anchor`.
///
/// Returns the node's response so the caller can distinguish acceptance
/// from a specific rejection.
#[allow(clippy::too_many_arguments)]
async fn spend_note_with_anchor(
    note: &sprout::SproutNotePlaintext,
    a_sk: [u8; 32],
    recipient: sprout::SproutPaymentAddress,
    witness_path: Vec<u8>,
    anchor: [u8; 32],
    proving_key: &bellman::groth16::Parameters<bls12_381::Bls12>,
    label: &str,
) -> Result<String, String> {
    let to_sapling = note.value - SPEND_FEE;
    let spend_key = sprout_spend::JoinSplitSigningKey::from_bytes(random32());

    let inputs = [
        sprout_spend::JoinSplitInput {
            note: note.clone(),
            a_sk,
            witness_path,
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
        &spend_key.verification_key(),
        random32(),
        random32(),
        random32(),
    )
    .expect("compute spend fields");

    let proof = sprout_spend::prove_joinsplit(&fields, &inputs, &outputs, proving_key)
        .expect("prove the spend JoinSplit");
    let js = sprout_spend::build_js_description(&fields, &proof).expect("build description");

    let sapling_prover = zcash_proofs::prover::LocalTxProver::bundled();
    let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&random32());
    let (_, sapling_addr) = extsk.default_address();

    let mut builder = sapling_crypto::builder::Builder::new(
        sapling_crypto::note_encryption::Zip212Enforcement::Off,
        sapling_crypto::builder::BundleType::DEFAULT,
        sapling_crypto::Anchor::empty_tree(),
    );
    builder
        .add_output(
            None,
            sapling_addr,
            sapling_crypto::value::NoteValue::from_raw(to_sapling),
            [0u8; 512],
        )
        .expect("add the Sapling output");
    let (bundle, _) = builder
        .build::<zcash_proofs::prover::LocalTxProver, zcash_proofs::prover::LocalTxProver, _, zcash_protocol::value::ZatBalance>(
            &[],
            rand_core::OsRng,
        )
        .expect("build the Sapling bundle")
        .expect("the bundle must have an output");

    let height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height");
    let tx = sprout_spend::build_and_sign_v4_sprout_to_sapling(
        tip_branch_id().await,
        BlockHeight::from_u32(height as u32 + 40),
        vec![js],
        bundle,
        &sapling_prover,
        &spend_key,
        rand_core::OsRng,
    )
    .expect("assemble the Sprout-to-Sapling transaction");

    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize");
    eprintln!(
        "[stale-anchor] broadcasting {label} against anchor {}",
        bytes_to_hex(&anchor)
    );
    rpc_try(
        "sendrawtransaction",
        serde_json::json!([bytes_to_hex(&raw)]),
    )
    .await
    .map(|v| v.as_str().unwrap_or_default().to_owned())
}

#[tokio::test]
#[ignore = "requires the sprout profile and sprout-groth16.params; see the module docs"]
async fn a_historical_sprout_anchor_is_still_accepted() {
    let params = params_path();
    assert!(
        params.exists(),
        "need the Sprout parameters at {}",
        params.display()
    );
    let proving_key = sprout_spend::load_sprout_proving_key(&params).expect("proving key");

    let secret = secp256k1::SecretKey::from_slice(&[0x11; 32]).expect("key");
    let address = {
        let secp = secp256k1::Secp256k1::signing_only();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        zcash_transparent::address::TransparentAddress::from_pubkey(&pk)
    };

    rpc("generate", serde_json::json!([120])).await;
    let addr = argos_core::imported::encode_transparent_address(
        &address,
        argos_core::ZeckNetwork::Testnet,
    );
    let txid = rpc("sendtoaddress", serde_json::json!([addr, 5.0]))
        .await
        .as_str()
        .expect("txid")
        .to_owned();
    rpc("generate", serde_json::json!([1])).await;

    let funding = rpc("getrawtransaction", serde_json::json!([txid.clone(), 1])).await;
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
    let script = hex_to_bytes(vout["scriptPubKey"]["hex"].as_str().expect("hex"));
    let mut txid_bytes = hex_to_bytes(&txid);
    txid_bytes.reverse();
    let txid_arr: [u8; 32] = txid_bytes.try_into().expect("32-byte txid");

    // ── Shield into TWO real notes sharing one anchor ─────────────────────
    let a_sk = random32();
    let recipient = sprout::SproutPaymentAddress::from_spending_key(&a_sk);
    let shielded = value - SHIELD_FEE;
    // Split so both notes can each cover a spend fee on their own.
    let first_value = shielded / 2;
    let second_value = shielded - first_value;

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
            value: first_value,
        },
        sprout_spend::JoinSplitOutput {
            recipient,
            value: second_value,
        },
    ];

    let fields = sprout_spend::compute_joinsplit_fields(
        &inputs,
        &outputs,
        shielded,
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
        .expect("height");
    let tx = sprout_spend::build_and_sign_v4_shielding(
        tip_branch_id().await,
        BlockHeight::from_u32(height as u32 + 40),
        &[sprout_spend::TransparentFunding {
            txid: txid_arr,
            index,
            value,
            script_pubkey: script,
            secret,
        }],
        vec![js],
        &js_key,
    )
    .expect("assemble the shielding transaction");

    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize");
    let shield_txid = rpc(
        "sendrawtransaction",
        serde_json::json!([bytes_to_hex(&raw)]),
    )
    .await
    .as_str()
    .expect("the node accepted the shielding transaction")
    .to_owned();
    eprintln!("[stale-anchor] shielded two notes: {shield_txid}");

    rpc("generate", serde_json::json!([1])).await;
    let shield_height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height");

    // Recover both output notes, exactly as the builder derived them.
    let note_a = sprout::SproutNotePlaintext {
        value: first_value,
        rho: sprout::prf_rho(&fields.phi, 0, &fields.h_sig),
        r: sprout::prf_rho(&fields.phi, 0, &fields.nullifiers[0]),
        memo: [0u8; 512],
    };
    let note_b = sprout::SproutNotePlaintext {
        value: second_value,
        rho: sprout::prf_rho(&fields.phi, 1, &fields.h_sig),
        r: sprout::prf_rho(&fields.phi, 1, &fields.nullifiers[1]),
        memo: [0u8; 512],
    };
    assert_eq!(
        sprout::note_commitment(recipient.a_pk(), note_b.value, &note_b.rho, &note_b.r),
        fields.commitments[1],
        "the second note must be the one that was committed"
    );

    // Build both witnesses against the tree as of the shielding block. This
    // single anchor is what both spends will use.
    let before = rpc(
        "z_gettreestate",
        serde_json::json!([(shield_height - 1).to_string()]),
    )
    .await;
    let final_state = before["sprout"]["commitments"]["finalState"]
        .as_str()
        .expect("finalState");
    let mut tree = sprout_witness::IncrementalMerkleTree::parse(&hex_to_bytes(final_state))
        .expect("the chain's Sprout tree must parse");

    tree.append(fields.commitments[0]).expect("append note a");
    let mut witness_a = sprout_witness::IncrementalWitness::from_tree(tree.clone());
    tree.append(fields.commitments[1]).expect("append note b");
    witness_a.append(fields.commitments[1]).expect("advance a");
    let witness_b = sprout_witness::IncrementalWitness::from_tree(tree.clone());

    let anchor = tree.root();
    assert_eq!(witness_a.root(), anchor, "witness a must track its tree");
    assert_eq!(witness_b.root(), anchor, "witness b must track its tree");
    eprintln!(
        "[stale-anchor] both notes anchored at {} (height {shield_height})",
        bytes_to_hex(&anchor)
    );

    // ── Spend the first note. Its anchor is current. ──────────────────────
    let first = spend_note_with_anchor(
        &note_a,
        a_sk,
        recipient,
        witness_a.encode_for_prover().expect("encode a").to_vec(),
        anchor,
        &proving_key,
        "the first spend (anchor is current)",
    )
    .await
    .expect("a current anchor must be accepted");
    eprintln!("[stale-anchor] first spend accepted: {first}");

    rpc("generate", serde_json::json!([1])).await;

    // That spend's own JoinSplit outputs appended two more commitments, so
    // the chain's Sprout root has moved past the anchor above.
    let now = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height");
    let current = rpc("z_gettreestate", serde_json::json!([now.to_string()])).await;
    let mut current_root = hex_to_bytes(
        current["sprout"]["commitments"]["finalRoot"]
            .as_str()
            .expect("finalRoot"),
    );
    current_root.reverse();

    assert_ne!(
        current_root,
        anchor.to_vec(),
        "the tree must have moved on, or the second spend would not be testing a \
         stale anchor at all"
    );
    eprintln!(
        "[stale-anchor] chain root is now {} — the anchor above is history",
        bytes_to_hex(&current_root)
    );

    // ── Spend the second note against that now-historical anchor ──────────
    let second = spend_note_with_anchor(
        &note_b,
        a_sk,
        recipient,
        witness_b.encode_for_prover().expect("encode b").to_vec(),
        anchor,
        &proving_key,
        "the second spend (anchor is STALE)",
    )
    .await;

    match second {
        Ok(txid) => {
            eprintln!("[stale-anchor] STALE ANCHOR ACCEPTED: {txid}");
            rpc("generate", serde_json::json!([1])).await;
            let mined = rpc("getrawtransaction", serde_json::json!([txid, 1])).await;
            assert!(
                mined["confirmations"].as_u64().unwrap_or(0) >= 1,
                "the stale-anchor transaction was accepted but did not mine"
            );
            eprintln!(
                "[stale-anchor] confirmed. A cached wallet.dat witness is spendable \
                 without a rescan."
            );
        }
        Err(err) => panic!(
            "consensus rejected a historical Sprout anchor: {err}\n\
             This would mean the cached-witness recovery path cannot work, and every \
             wallet.dat Sprout recovery needs a full-block rescan to rebuild a current \
             witness."
        ),
    }
}
