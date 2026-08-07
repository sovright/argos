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

/// The peer pool, against a node we control.
///
/// Deliberately not tested against mainnet. Public seed nodes refuse the
/// overwhelming majority of inbound connections — measured at 38 of 38 across
/// repeated runs, with an identical close whether or not a `version` message
/// is sent, which places the refusal before the protocol rather than in it.
/// A test that depends on catching a free slot on a public node would be
/// flaky by construction, and polling for one hard enough to be reliable
/// would itself be abusive.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn the_pool_connects_to_an_explicitly_supplied_node() {
    use argos_core::p2p::pool::connect_to_any;

    let peer = connect_to_any(P2pNetwork::Regtest, &[NODE.to_owned()], 1)
        .await
        .expect("an explicitly supplied node must be used without any DNS seed");

    assert!(peer.peer_height > 0);
}

/// A supplied address that is not listening must fail with the diagnosis
/// that says so, rather than a bare connection error.
#[tokio::test]
#[ignore = "needs no node, but grouped with the other p2p checks"]
async fn an_unreachable_node_reports_a_refusal_not_a_crash() {
    use argos_core::p2p::pool::connect_to_any;

    // Port 1 on loopback: nothing listens there.
    let err = connect_to_any(P2pNetwork::Regtest, &["127.0.0.1:1".to_owned()], 1)
        .await
        .expect_err("nothing listens on port 1");

    let text = err.to_string();
    assert!(
        text.contains("refused"),
        "the failure should name a connection refusal, got: {text}"
    );
}

/// Extract JoinSplits from real blocks, off the wire, on a chain that
/// actually contains them.
///
/// This is the whole read path at once: p2p framing, block header walk,
/// upstream transaction parsing, and the `write`/re-read round trip that
/// recovers `ephemeral_key` and `ciphertexts` — the two fields
/// `zcash_primitives` exposes no accessor for. Every earlier test in this
/// file runs on blocks with no JoinSplits, so none of them exercise it.
///
/// The `sprout` chain is the only one that can carry Sprout notes: ZIP 211
/// forbids funding the pool from Canopy onward, and that chain holds Canopy
/// inactive.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn joinsplits_are_recovered_from_real_blocks() {
    use argos_core::p2p::block::joinsplits_in_block;
    use zcash_protocol::consensus::BranchId;

    let mut peer = Peer::connect(NODE, P2pNetwork::Regtest)
        .await
        .expect("handshake");

    // Walk the whole chain, pulling every block and scanning it.
    let mut locator = [0u8; 32];
    let mut found = Vec::new();
    let mut blocks_seen = 0usize;

    loop {
        let headers = peer.get_headers(&[locator]).await.expect("getheaders");
        if headers.is_empty() {
            break;
        }
        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        locator = *hashes.last().expect("non-empty");

        for block in peer.get_blocks(&hashes).await.expect("getdata") {
            blocks_seen += 1;
            let js = joinsplits_in_block(&block, BranchId::Canopy)
                .expect("a real block from a real node must parse");
            found.extend(js);
        }
    }

    println!("scanned {blocks_seen} blocks, found {} JoinSplits", found.len());
    assert!(
        !found.is_empty(),
        "the sprout chain holds JoinSplit transactions; none were found, so the \
         extraction path is not working"
    );

    for js in &found {
        // The fields with no upstream accessor are the reason this round
        // trip exists; if the re-read were misaligned they would be zero.
        assert_ne!(
            js.ephemeral_key, [0u8; 32],
            "ephemeral_key must be recovered, not left zero"
        );
        assert_ne!(
            js.joinsplit_pubkey, [0u8; 32],
            "the per-transaction pubkey must be backfilled"
        );
        for ct in &js.ciphertexts {
            assert_eq!(ct.len(), 601, "a Sprout note ciphertext is 601 bytes");
            assert!(
                ct.iter().any(|b| *b != 0),
                "a real ciphertext is not all zeros"
            );
        }
        // A JoinSplit always publishes two commitments, and at least one
        // must be a real note.
        assert!(
            js.commitments.iter().any(|c| *c != [0u8; 32]),
            "a real JoinSplit commits to at least one note"
        );
    }
}
