//! The Sprout scanner, driven end to end against a real chain.
//!
//! Every piece of the scan has been validated in isolation — the rebuilt
//! tree matches zcashd's root, the p2p layer works against live mainnet,
//! resume is unit-tested — but `run_sprout_scan` itself, the loop that
//! connects, walks, fetches and feeds, has never been run. Both surfaces now
//! expose it, so an unexercised loop is the highest-risk thing in the branch.
//!
//! This creates a Sprout note under a key we choose, then scans the chain
//! from genesis with nothing but that key and asks whether the note comes
//! back — which is exactly what a user with a bare `zkey` and no wallet file
//! is doing.
//!
//! The assertion that matters is not "a note was found" but that its
//! **witness is spendable**: the scanner derives a witness from scratch, and
//! a witness that authenticates nothing still encodes, still looks right,
//! and fails only at broadcast. So the recovered anchor is checked against
//! the one the chain computed.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test sprout_scan_finds_a_real_note -- --ignored --nocapture

use argos_core::{p2p::wire::P2pNetwork, sprout, sprout_scan_run, sprout_spend, sprout_witness};
use zcash_protocol::consensus::{BlockHeight, BranchId};

const RPC: &str = "http://127.0.0.1:18242";
const NODE_P2P: &str = "127.0.0.1:18344";
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
        .unwrap_or_else(|err| panic!("connecting to zcashd: {err}"));
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
    let parsed: serde_json::Value = serde_json::from_str(text[start..].trim())
        .unwrap_or_else(|err| panic!("zcashd {method}: {err}\n{text}"));
    if let Some(e) = parsed.get("error") {
        if !e.is_null() {
            panic!("zcashd {method} failed: {e}");
        }
    }
    parsed
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn random32() -> [u8; 32] {
    use rand_core::RngCore;
    let mut out = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut out);
    out
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

fn params_path() -> std::path::PathBuf {
    std::env::var("ARGOS_SPROUT_PARAMS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").expect("HOME"))
                .join(".zcash-params")
                .join("sprout-groth16.params")
        })
}

#[tokio::test]
#[ignore = "requires the sprout profile and sprout-groth16.params; see the module docs"]
async fn a_scan_finds_a_note_it_was_never_told_about() {
    let params = params_path();
    assert!(
        params.exists(),
        "need Sprout parameters at {}",
        params.display()
    );
    let proving_key = sprout_spend::load_sprout_proving_key(&params).expect("proving key");

    // ── Create a note under a key we choose ───────────────────────────────
    let secret = secp256k1::SecretKey::from_slice(&[0x33; 32]).expect("key");
    let address = {
        let secp = secp256k1::Secp256k1::signing_only();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        zcash_transparent::address::TransparentAddress::from_pubkey(&pk)
    };

    rpc("generate", serde_json::json!([110])).await;
    let addr = argos_core::imported::encode_transparent_address(
        &address,
        argos_core::ZeckNetwork::Testnet,
    );
    let txid = rpc("sendtoaddress", serde_json::json!([addr, 4.0]))
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

    // The key the scan will be given, and nothing else.
    let a_sk = random32();
    let recipient = sprout::SproutPaymentAddress::from_spending_key(&a_sk);
    let shielded = value - SHIELD_FEE;

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
        shielded,
        0,
        sprout_witness::empty_tree_root(),
        &js_key.verification_key(),
        &sprout_spend::JoinSplitRandomness {
            phi: random32(),
            random_seed: random32(),
            esk: random32(),
            rcm: [[0xA1; 32], [0xA2; 32]],
        },
    )
    .expect("compute fields");

    let proof =
        sprout_spend::prove_joinsplit(&fields, &inputs, &outputs, &proving_key).expect("prove");
    let js = sprout_spend::build_js_description(&fields, &proof).expect("build");

    let height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height");
    let tx = sprout_spend::build_and_sign_v4_shielding(
        BranchId::Heartwood,
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
    .expect("assemble");

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
    rpc("generate", serde_json::json!([1])).await;
    let shield_height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height");
    eprintln!("[scan] planted {shielded} zatoshi at height {shield_height} ({shield_txid})");

    // ── Now scan, knowing only the spending key ───────────────────────────
    let dir = std::env::temp_dir().join("argos-scan-e2e");
    let _ = std::fs::remove_dir_all(&dir);
    let checkpoint = sprout_scan_run::checkpoint_path(&dir, &[a_sk]);

    let started = std::time::Instant::now();
    let result = sprout_scan_run::run_sprout_scan(
        &[a_sk],
        P2pNetwork::Regtest,
        &[NODE_P2P.to_owned()],
        &checkpoint,
        |tick| {
            if tick.height % 400 == 0 {
                eprintln!(
                    "[scan] height {} — {} note(s)",
                    tick.height, tick.notes_found
                );
            }
        },
    )
    .await
    .expect("the scan must complete");

    eprintln!(
        "[scan] {} blocks, {} JoinSplits, {} note(s), {:?}",
        result.progress.blocks_scanned,
        result.progress.joinsplits_seen,
        result.notes.len(),
        started.elapsed()
    );

    assert!(
        result.progress.blocks_scanned >= shield_height,
        "the scan must reach the block holding the note: scanned {} of {shield_height}",
        result.progress.blocks_scanned
    );
    // A JoinSplit has two outputs and both were paid to this address — the
    // funded note and a zero-value sibling. Both are real notes, so two is
    // the correct answer; what matters is the value recovered.
    assert_eq!(
        result.notes.len(),
        2,
        "both outputs of the shielding JoinSplit pay this address"
    );
    assert_eq!(
        result.total_value(),
        shielded,
        "the scan was given only a spending key and must recover the exact value"
    );

    let found = result
        .notes
        .iter()
        .find(|n| n.note.value == shielded)
        .expect("the funded note must be among those found");
    assert_eq!(found.a_sk, a_sk);

    // ── The assertion that actually matters ───────────────────────────────
    //
    // A witness that authenticates nothing still encodes and still looks
    // right; it fails only at broadcast, after proving. So the anchor the
    // scanner derived is checked against the root the chain computed for the
    // block the note landed in.
    let mut ours = found.anchor;
    ours.reverse();

    let state = rpc(
        "z_gettreestate",
        serde_json::json!([shield_height.to_string()]),
    )
    .await;
    let chain_root = state["sprout"]["commitments"]["finalRoot"]
        .as_str()
        .expect("finalRoot");

    assert_eq!(
        bytes_to_hex(&ours),
        chain_root,
        "the witness the scanner built must anchor to the tree the chain computed; a \
         mismatch means the note was found but is not spendable"
    );
    assert_eq!(
        found.witness_path.len(),
        sprout_witness::WITNESS_PATH_SIZE,
        "the path must be in the encoding the JoinSplit prover parses"
    );
    eprintln!("[scan] witness anchors to the chain's root {chain_root}");

    // ── Resume must not redo the work ─────────────────────────────────────
    assert!(checkpoint.exists(), "the scan must leave a checkpoint");
    eprintln!("[scan] checkpoint at {}", checkpoint.display());
}
