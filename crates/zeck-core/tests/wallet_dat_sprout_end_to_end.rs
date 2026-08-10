//! Whether a funded `wallet.dat` fixture can be manufactured at all.
//!
//! It cannot, and this records the evidence. The file is named for the
//! question, not for the sweep it was originally written to perform — an
//! earlier version was called `a_funded_wallet_dat_sweeps_from_file_to_
//! broadcast` while asserting the exact opposite, so anyone reading
//! `cargo test --list` would have concluded the file-to-broadcast seam was
//! closed. It is not, and by this test's own finding it cannot be closed
//! with a synthetic wallet.
//!
//! Every stage of this has been validated on its own — decryption, tree
//! reconstruction, stale anchors, the spend itself — but the seam from
//! *file* to *broadcast* never had. That seam is what a real user walks.
//!
//! # What was expected, and what happened
//!
//! `CLAUDE.md` has recorded since sub-spec 1 that no fixture holds a funded
//! Sprout note, on the grounds that ZIP 211 closes the pool from Canopy
//! onward. The late-Canopy `sprout` chain was expected to lift that: the
//! pool stays open, and `z_getnewaddress` lets zcashd hold a Sprout address
//! of its own, so it can be paid.
//!
//! It can be paid — consensus mines the transaction — and zcashd still
//! files no note record and no JoinSplit for it. The expectation was wrong
//! and the original note was right.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test wallet_dat_sprout_end_to_end -- --ignored --nocapture

use argos_core::{sprout, sprout_key, sprout_spend, sprout_witness};
use zcash_protocol::consensus::{BlockHeight, BranchId};

const RPC: &str = "http://127.0.0.1:18242";
const SHIELD_FEE: u64 = 15_000;
const CONTAINER: &str = "argos-zcashd-sprout";

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
async fn zcashd_records_no_inbound_sprout_note_so_no_funded_fixture_exists() {
    let params = params_path();
    assert!(
        params.exists(),
        "need Sprout parameters at {}",
        params.display()
    );
    let proving_key = sprout_spend::load_sprout_proving_key(&params).expect("proving key");

    // ── Give zcashd a Sprout address of its own, and pay it ───────────────
    let encoded = rpc("z_getnewaddress", serde_json::json!(["sprout"]))
        .await
        .as_str()
        .expect("zcashd must still be able to create a Sprout address")
        .to_owned();
    eprintln!("[e2e] zcashd owns {encoded}");

    // Decoded with Argos's own decoder — the address zcashd printed is the
    // only form it gives us, so reading it is part of the path under test.
    let recipient = sprout_key::decode_sprout_address(&encoded, argos_core::ZeckNetwork::Testnet)
        .expect("zcashd's address must decode");

    let secret = secp256k1::SecretKey::from_slice(&[0x55; 32]).expect("key");
    let t_address = {
        let secp = secp256k1::Secp256k1::signing_only();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        zcash_transparent::address::TransparentAddress::from_pubkey(&pk)
    };

    rpc("generate", serde_json::json!([110])).await;
    let addr = argos_core::imported::encode_transparent_address(
        &t_address,
        argos_core::ZeckNetwork::Testnet,
    );
    let txid = rpc("sendtoaddress", serde_json::json!([addr, 3.0]))
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

    let shielded = value - SHIELD_FEE;
    let js_key = sprout_spend::JoinSplitSigningKey::from_bytes(random32());
    let dummy = sprout_witness::dummy_path().to_vec();
    // The spending key here is irrelevant: the *inputs* are dummies, and the
    // outputs are paid to zcashd's address, not ours.
    let throwaway = random32();
    let inputs = [
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: random32(),
                r: random32(),
                memo: [0u8; 512],
            },
            a_sk: throwaway,
            witness_path: dummy.clone(),
        },
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: random32(),
                r: random32(),
                memo: [0u8; 512],
            },
            a_sk: throwaway,
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
        random32(),
        random32(),
        random32(),
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
    // Extra blocks so the wallet's cached witness advances past the note,
    // which is the state a real years-old wallet is in.
    rpc("generate", serde_json::json!([6])).await;
    eprintln!("[e2e] paid {shielded} zatoshi to zcashd's Sprout address ({shield_txid})");

    // ── Does zcashd actually record it? ───────────────────────────────────
    //
    // Nothing in this repo had ever shown that it does. If this fails, no
    // funded wallet.dat fixture is possible and the seam cannot be closed.
    // Checked through the wallet file rather than an RPC: z_getbalance is
    // deprecated-disabled, and the file's contents are the thing under test
    // in any case. If zcashd ignored the note, the import below finds
    // nothing and says so.

    // ── Take the wallet file ──────────────────────────────────────────────
    let out_dir = std::env::temp_dir().join("argos-walletdat-e2e");
    std::fs::create_dir_all(&out_dir).expect("temp dir");
    let wallet_path = out_dir.join("wallet.dat");
    let _ = std::fs::remove_file(&wallet_path);

    // `backupwallet` writes a consistent copy; reading the live file would
    // race Berkeley DB mid-write.
    // zcashd requires an alphanumeric backup filename.
    rpc("backupwallet", serde_json::json!(["argose2edat"])).await;
    let status = std::process::Command::new("docker")
        .args([
            "cp",
            &format!("{CONTAINER}:/srv/zcashd/.zcash/argose2edat"),
            wallet_path.to_str().expect("path"),
        ])
        .status()
        .expect("docker cp must run");
    assert!(
        status.success(),
        "copying the wallet file out of the container failed"
    );
    let bytes = std::fs::read(&wallet_path).expect("read the wallet file");
    eprintln!("[e2e] wallet.dat is {} bytes", bytes.len());

    // ── From here on, only the file ───────────────────────────────────────
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("the wallet file must import");
    eprintln!(
        "[e2e] imported {} Sprout key(s), {} note record(s), {} JoinSplit(s)",
        keys.sprout.len(),
        keys.sprout_notes.len(),
        keys.sprout_joinsplits.len()
    );

    // ── The finding, and why task 4 cannot be closed this way ────────────
    //
    // zcashd created the Sprout address, and consensus accepted a payment
    // into it — the transaction mined. But the wallet files no note record
    // and no JoinSplit for it: `sprout_notes` and `sprout_joinsplits` are
    // both empty, while the spending keys are all present.
    //
    // So zcashd v6.20.0 does not detect an inbound Sprout note built by
    // another party, even with Canopy inactive and the pool open. This is
    // the behaviour `CLAUDE.md` has recorded since sub-spec 1 — "zcashd
    // refuses all inbound Sprout transfers regardless of Canopy height" —
    // and it survives the late-Canopy chain, which was the one condition
    // thought to lift it.
    //
    // The consequence is that a funded `wallet.dat` fixture cannot be
    // manufactured, and the file-to-broadcast seam cannot be closed against
    // a synthetic wallet. It would need a real pre-Canopy wallet file.
    //
    // Asserted rather than described, so that if a future zcashd starts
    // recording these notes, this test fails and tells us the fixture has
    // become possible.
    assert!(
        !keys.sprout.is_empty(),
        "zcashd must at least hold the Sprout keys it generated"
    );
    assert!(
        keys.sprout_notes.is_empty() && keys.sprout_joinsplits.is_empty(),
        "zcashd recorded an inbound Sprout note ({} note record(s), {} JoinSplit(s)) — \
         if this fails, a funded wallet.dat fixture is now possible and the \
         file-to-broadcast seam can finally be closed",
        keys.sprout_notes.len(),
        keys.sprout_joinsplits.len()
    );
    eprintln!(
        "[e2e] zcashd holds {} Sprout key(s) but filed no note: a funded wallet.dat \
         fixture cannot be manufactured",
        keys.sprout.len()
    );
}
