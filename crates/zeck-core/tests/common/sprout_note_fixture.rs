//! A real Sprout JoinSplit fixture shared by the regtest scanner tests.
//! zcashd no longer creates inbound Sprout transfers itself, even on this
//! pre-Canopy regtest chain, so the tests build one consensus-valid proof.

use argos_core::{sprout, sprout_spend, sprout_witness};
use zcash_protocol::consensus::{BlockHeight, BranchId};

#[path = "sprout_wallet_sync.rs"]
mod sprout_wallet_sync;

const RPC: &str = "http://127.0.0.1:18242";
pub const NODE_P2P: &str = "127.0.0.1:18344";
const SHIELD_FEE: u64 = 15_000;

pub async fn rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
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

pub fn random32() -> [u8; 32] {
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

pub fn bytes_to_hex(b: &[u8]) -> String {
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

pub struct PlantedSproutNote {
    pub value: u64,
    pub height: u32,
    pub txid: String,
}

/// Fund a transparent output, prove a Sprout shielding JoinSplit, and
/// mine it. The returned block carries two real commitments.
pub async fn plant_sprout_note(a_sk: [u8; 32]) -> PlantedSproutNote {
    let params = params_path();
    assert!(
        params.exists(),
        "need Sprout parameters at {}",
        params.display()
    );
    let proving_key = sprout_spend::load_sprout_proving_key(&params).expect("proving key");

    let secret = secp256k1::SecretKey::from_secret_bytes([0x33; 32]).expect("key");
    let address = {
        let pk = secp256k1::PublicKey::from_secret_key(&secret);
        zcash_transparent::address::TransparentAddress::from_pubkey(&pk)
    };

    rpc("generate", serde_json::json!([110])).await;
    // `generate` can return before zcashd's wallet has indexed the newly
    // matured coinbase outputs. Sending immediately then races wallet sync
    // and intermittently reports "Insufficient funds" even though the chain
    // is already at the required height.
    sprout_wallet_sync::wait_for_spendable_balance(4.01, || {
        rpc("getbalance", serde_json::json!(["*", 1]))
    })
    .await;
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

    PlantedSproutNote {
        value: shielded,
        height: shield_height as u32,
        txid: shield_txid,
    }
}
