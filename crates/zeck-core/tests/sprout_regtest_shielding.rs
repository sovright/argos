#![cfg(feature = "sprout")]
//! Broadcast a real Sprout JoinSplit to a node and let consensus judge it.
//!
//! Everything else in the Sprout work is checked by me or by the proving
//! circuit. This is the only test where an independent implementation — a
//! Zebra node applying the full consensus rules — decides whether the
//! transaction is valid. It checks what the circuit cannot: transaction
//! version and branch ID, the v4 sighash over both bundles, the transparent
//! input signatures, the JoinSplit signature, the anchor being one the chain
//! actually knows, and the value balance across pools.
//!
//! It *shields*: transparent value in, a Sprout note out. That direction is
//! the only one available on a chain that has never held a Sprout note,
//! because a JoinSplit's zero-value inputs skip the circuit's Merkle check.
//! It is how Sprout was funded before any Sprout note existed, and it
//! produces the first real note — which a later test can then spend.
//!
//! Requires the regtest harness and the Sprout parameters:
//!
//!     cd tests/regtest && docker compose up -d && ./setup.sh
//!     export ARGOS_REGTEST_LIGHTWALLETD_URL=http://localhost:9067
//!     cargo test -p argos-core --features argos-network \
//!         --test sprout_regtest_shielding -- --ignored

#![cfg(feature = "argos-network")]

// This test uses a small part of the shared harness; the rest is used by
// other integration tests that compile the same module.
#[allow(dead_code)]
mod common;

use argos_core::{sprout, sprout_spend, sprout_witness, ZeckNetwork};
use common::regtest_harness::{zebra_rpc, RegtestHarness};
use zcash_protocol::consensus::{BlockHeight, BranchId};

/// ZIP 317's floor. The rest of the input becomes the fee; there are no
/// transparent outputs, so nothing is left over.
const FEE: u64 = 10_000;

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
#[ignore = "requires the regtest harness and sprout-groth16.params; see the module docs"]
async fn a_shielding_joinsplit_is_accepted_by_the_node() {
    let harness = RegtestHarness::require();
    let params = params_path();
    assert!(
        params.exists(),
        "expected the Sprout parameters at {}",
        params.display()
    );

    // Fund the standalone transparent key, which no other test sweeps.
    let key = common::standalone_transparent::standalone_transparent_key();
    let address =
        argos_core::imported::encode_transparent_address(&key.address, ZeckNetwork::Testnet);
    common::regtest_harness::fund_address(&address, 500_000_000).await;

    let (mut client, _endpoint) = argos_core::lightwalletd::connect_lightwalletd_endpoints(
        harness.lightwalletd_url(),
        None,
    )
    .await
    .expect("connect to lightwalletd");

    let utxos = argos_core::transparent_recovery::fetch_transparent_utxos(
        &mut client,
        std::slice::from_ref(&key),
        ZeckNetwork::Testnet,
    )
    .await
    .expect("fetch UTXOs");
    assert!(!utxos.is_empty(), "the funded address must have UTXOs");

    // One UTXO is enough, and keeps the transaction small.
    let utxo = utxos
        .iter()
        .find(|u| u64::from(u.txout.value()) > FEE)
        .expect("a UTXO larger than the fee");
    let shielded_value = u64::from(utxo.txout.value()) - FEE;

    // The note this JoinSplit creates, paid to the golden fixture's Sprout
    // address so a later spend test can use the real recovered key.
    let a_sk = [0x77u8; 32];
    let recipient = sprout::SproutPaymentAddress::from_spending_key(&a_sk);

    // Both inputs are zero-value dummies: the circuit skips the Merkle check
    // for those, which is what allows a JoinSplit on a chain with no Sprout
    // notes. The anchor must still be a root the chain knows, and on such a
    // chain that is the empty root.
    let anchor = sprout_witness::empty_tree_root();
    // Not an all-zeroes buffer: create_proof parses the path for every
    // input, including zero-value dummies whose Merkle check the circuit
    // skips, and asserts on its framing.
    let dummy_path = sprout_witness::dummy_path().to_vec();
    let js_key = sprout_spend::JoinSplitSigningKey::from_bytes([0x88; 32]);
    let inputs = [
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: [0x01; 32],
                r: [0x02; 32],
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: dummy_path.clone(),
        },
        sprout_spend::JoinSplitInput {
            note: sprout::SproutNotePlaintext {
                value: 0,
                rho: [0x03; 32],
                r: [0x04; 32],
                memo: [0u8; 512],
            },
            a_sk,
            witness_path: dummy_path,
        },
    ];
    let outputs = [
        sprout_spend::JoinSplitOutput {
            recipient,
            value: shielded_value,
        },
        sprout_spend::JoinSplitOutput {
            recipient,
            value: 0,
        },
    ];

    let fields = sprout_spend::compute_joinsplit_fields(
        &inputs,
        &outputs,
        shielded_value, // vpub_old: value entering the Sprout pool
        0,
        anchor,
        &js_key.verification_key(),
        [0x91; 32],
        [0x92; 32],
        [0x93; 32],
    )
    .expect("compute JoinSplit fields");

    let proving_key =
        sprout_spend::load_sprout_proving_key(&params).expect("load the proving key");
    let proof = sprout_spend::prove_joinsplit(&fields, &inputs, &outputs, &proving_key)
        .expect("prove the shielding JoinSplit");
    let js = sprout_spend::build_js_description(&fields, &proof).expect("build the description");

    let tip = zebra_rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("getblockcount");

    let tx = sprout_spend::build_and_sign_v4_shielding(
        BranchId::try_from(0x37a5_165b_u32).expect("Ironwood branch id"),
        BlockHeight::from_u32(tip as u32 + 40),
        &[sprout_spend::TransparentFunding {
            txid: *utxo.outpoint.txid().as_ref(),
            index: utxo.outpoint.n(),
            value: u64::from(utxo.txout.value()),
            script_pubkey: utxo.txout.script_pubkey().0 .0.clone(),
            secret: key.secret,
        }],
        vec![js],
        &js_key,
    )
    .expect("assemble and sign the shielding transaction");

    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize");

    // The moment of truth: an independent implementation decides.
    let response = client
        .send_transaction(zcash_client_backend::proto::service::RawTransaction {
            data: raw,
            height: 0,
        })
        .await
        .expect("send_transaction")
        .into_inner();
    assert_eq!(
        response.error_code, 0,
        "the node rejected our Sprout shielding transaction: {}",
        response.error_message
    );

    // And it must actually mine, not merely sit in the mempool.
    zebra_rpc("generate", serde_json::json!([1])).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let txid = tx.txid().to_string();
    let mined = zebra_rpc("getrawtransaction", serde_json::json!([txid, 1])).await;
    let confirmations = mined
        .get("confirmations")
        .and_then(|c| c.as_u64())
        .unwrap_or(0);
    assert!(
        confirmations >= 1,
        "the shielding transaction did not mine: {mined:?}"
    );

    eprintln!("[regtest] Sprout shielding accepted and mined: {txid}");
}
