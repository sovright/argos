//! The p2p wire format, checked against a real zcashd rather than against
//! our own encoder.
//!
//! The unit tests in `p2p::wire` round-trip our encoder against our decoder,
//! which cannot catch a wrong network magic, a mis-ordered `version` field,
//! or a header layout that is self-consistent but not what the network
//! speaks. Only a node that did not come from us can catch those, and the
//! failure mode without this test is a silent stall against mainnet peers
//! with nothing to inspect.
//!
//! Runs against the `sprout` profile node, which is the one regtest chain
//! that can hold Sprout notes (ZIP 211 forbids funding the Sprout pool from
//! Canopy onward, and that chain holds Canopy inactive).
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test p2p_against_a_real_node -- --ignored

use argos_core::p2p::{peer::Peer, wire::P2pNetwork};

/// The published p2p port of the `sprout` profile node.
const NODE: &str = "127.0.0.1:18344";

/// The handshake is the whole wire format under test at once: wrong magic,
/// a bad header layout, or a malformed `version` all fail here, and all of
/// them are invisible to a round-trip test.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn the_handshake_succeeds_against_a_real_zcashd() {
    let peer = Peer::connect(NODE, P2pNetwork::Regtest)
        .await
        .expect("the handshake must complete against a real node");

    // The node reports its own chain height, so a nonzero value proves we
    // parsed its `version` rather than merely exchanged bytes.
    assert!(
        peer.peer_height > 0,
        "the node should report a nonzero height; got {}",
        peer.peer_height
    );
    println!("handshake ok; peer reports height {}", peer.peer_height);
}

/// Connecting with the wrong network's magic must fail, not half-work.
/// Getting this wrong on mainnet would mean scanning nothing while looking
/// like a connection problem.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn the_wrong_network_magic_is_rejected() {
    let result = Peer::connect(NODE, P2pNetwork::Mainnet).await;
    assert!(
        result.is_err(),
        "a regtest node must not complete a mainnet handshake"
    );
}

/// Headers and blocks, fetched for real. This is what the scanner is built
/// on: if `getheaders` framing or the Equihash-solution-aware header decoder
/// were wrong, it would surface here rather than mid-scan against mainnet.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn headers_and_blocks_come_back_from_a_real_node() {
    let mut peer = Peer::connect(NODE, P2pNetwork::Regtest)
        .await
        .expect("handshake");

    // Genesis-rooted locator: ask for what follows the start of the chain.
    let genesis = genesis_hash(&mut peer).await;
    let headers = peer
        .get_headers(&[genesis])
        .await
        .expect("getheaders must be answered");

    assert!(
        !headers.is_empty(),
        "a chain with blocks must return headers"
    );
    println!("got {} headers", headers.len());

    // The chain must actually link: each header's prev must be the one
    // before it. A decoder that mis-sized the Equihash solution would
    // still return plausible-looking hashes, and this is what catches it.
    for pair in headers.windows(2) {
        assert_eq!(
            pair[1].prev_hash, pair[0].hash,
            "decoded headers must form a chain"
        );
    }

    // Fetch the first few as full blocks.
    let wanted: Vec<[u8; 32]> = headers.iter().take(3).map(|h| h.hash).collect();
    let blocks = peer
        .get_blocks(&wanted)
        .await
        .expect("getdata must return blocks");

    assert_eq!(blocks.len(), wanted.len());
    for block in &blocks {
        // A Zcash block header is 140 bytes plus its solution; anything
        // shorter is not a block.
        assert!(
            block.len() > 140,
            "a block must be longer than its fixed header, got {}",
            block.len()
        );
    }
    println!(
        "fetched {} blocks, {} bytes total",
        blocks.len(),
        blocks.iter().map(|b| b.len()).sum::<usize>()
    );
}

/// Ask the node for the hash of block 1 via its RPC, to root the locator.
async fn genesis_hash(_peer: &mut Peer) -> [u8; 32] {
    // The genesis hash is whatever block 0 is; an all-zero locator makes the
    // peer send from the start of the chain, which is what we want and needs
    // no RPC round trip.
    [0u8; 32]
}
