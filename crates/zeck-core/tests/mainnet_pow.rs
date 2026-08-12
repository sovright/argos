//! Mainnet Equihash parameters, against real mainnet headers.
//!
//! `verify_header_pow` was validated against regtest, which uses Equihash
//! (48, 5). Mainnet uses (200, 9) — a different parameter set, a different
//! solution length, and a different code path through the verifier. The
//! byte offsets were the part most likely to be wrong and are already
//! proven, but the mainnet parameters themselves had never been exercised
//! against a header this project did not construct.
//!
//! That matters because a wrong parameter rejects *every* honest mainnet
//! header while looking exactly like a hostile network — the failure this
//! whole area is built to avoid, and one that would only appear once a real
//! user started a real scan.
//!
//! Needs a mainnet peer reachable at 127.0.0.1:18233. The sovright zebra
//! nodes are reachable over an IAP tunnel:
//!
//!     gcloud compute ssh zebra-us-central1-2 --zone=us-central1-a \
//!       --tunnel-through-iap --project=sovright-bedrock-mainnet \
//!       -- -N -L 18233:localhost:8233
//!
//!     cargo test -p argos-core --test mainnet_pow -- --ignored --nocapture

use argos_core::p2p::{peer::Peer, wire::{verify_header_pow, P2pNetwork}};

const NODE: &str = "127.0.0.1:18233";

#[tokio::test]
#[ignore = "needs a mainnet peer; see the module docs"]
async fn real_mainnet_headers_pass_equihash_200_9() {
    let mut peer = Peer::connect(NODE, P2pNetwork::Mainnet)
        .await
        .expect("a mainnet peer must accept us");
    println!("connected; peer height {}", peer.peer_height);

    // From genesis: these are the Sprout-era headers a scan actually walks.
    let headers = peer
        .get_headers(&[[0u8; 32]])
        .await
        .expect("getheaders must be answered");
    assert!(!headers.is_empty(), "a mainnet peer must return headers");

    for (i, header) in headers.iter().enumerate() {
        verify_header_pow(P2pNetwork::Mainnet, header).unwrap_or_else(|err| {
            panic!("real mainnet header {i} failed verification: {err}")
        });
    }
    println!(
        "{} real mainnet headers passed Equihash (200, 9) and difficulty",
        headers.len()
    );

    // Without this, a pass would only show the verifier accepts things.
    let mut tampered = headers[0].clone();
    let last = tampered.raw.len() - 1;
    tampered.raw[last] ^= 0xFF;
    assert!(
        verify_header_pow(P2pNetwork::Mainnet, &tampered).is_err(),
        "a corrupted mainnet Equihash solution must be rejected"
    );
    println!("a tampered mainnet solution was rejected");
}
