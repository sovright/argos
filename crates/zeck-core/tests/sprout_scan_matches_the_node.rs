//! The rebuilt Sprout commitment tree, checked against the node's own.
//!
//! Everything about a Sprout scan rests on one claim: that appending every
//! JoinSplit commitment from full blocks, in consensus order, reproduces the
//! tree the network actually maintains. If it does not, the scan still
//! "succeeds" — notes decrypt, witnesses encode, proofs generate — and the
//! transaction is rejected at broadcast for an unknown anchor, after the work
//! is done and with no local signal that anything was wrong.
//!
//! No unit test can catch that, because a self-consistent wrong tree is
//! indistinguishable from a right one without an independent implementation
//! to compare against. zcashd computes the same tree, publishes its root via
//! `z_gettreestate`, and did not get it from us.
//!
//! Runs against the `sprout` profile node, which is the only regtest chain
//! that can carry Sprout notes (ZIP 211 forbids funding the pool from Canopy
//! onward, and that chain holds Canopy inactive).
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test sprout_scan_matches_the_node -- --ignored

use argos_core::{
    p2p::{
        block::{joinsplits_in_block, BlockError},
        peer::Peer,
        wire::{read_compact_size, write_compact_size, P2pNetwork},
    },
    sprout_scan::SproutScanner,
};
use std::io::Cursor;
use zcash_primitives::{block::BlockHeader, transaction::Transaction};
use zcash_protocol::consensus::BranchId;

const NODE_P2P: &str = "127.0.0.1:18344";
const RPC: &str = "http://127.0.0.1:18242";

/// Minimal JSON-RPC over a raw socket, with the basic auth zcashd requires.
/// Matches the approach in `sprout_consensus_roundtrip`: no HTTP client
/// dependency for a handful of test calls.
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

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Split bytes from the node without using the block authentication under test.
/// Cursor offsets retain the original header and transaction serializations.
fn split_block(block: &[u8], branch_id: BranchId) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut cursor = Cursor::new(block);
    BlockHeader::read(&mut cursor).expect("node header parses");
    let header_end = cursor.position() as usize;
    let (count, count_len) = read_compact_size(&block[header_end..]).expect("transaction count");
    cursor.set_position((header_end + count_len) as u64);

    let mut transactions = Vec::new();
    for _ in 0..count {
        let start = cursor.position() as usize;
        Transaction::read(&mut cursor, branch_id).expect("node transaction parses");
        let end = cursor.position() as usize;
        transactions.push(block[start..end].to_vec());
    }
    assert_eq!(cursor.position() as usize, block.len(), "no trailing data");
    (block[..header_end].to_vec(), transactions)
}

/// A real node's header must reject any changed transaction vector, even when
/// every replacement transaction remains individually parseable.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn an_authentic_header_rejects_altered_transaction_vectors() {
    let branch_id = BranchId::Canopy;
    let mut peer = Peer::connect(NODE_P2P, P2pNetwork::Regtest)
        .await
        .expect("handshake");
    let mut locator = [0u8; 32];
    let (header, transactions) = 'chain: loop {
        let headers = peer.get_headers(&[locator]).await.expect("getheaders");
        assert!(
            !headers.is_empty(),
            "need a real block with two transactions"
        );
        let hashes: Vec<[u8; 32]> = headers.iter().map(|header| header.hash).collect();
        locator = *hashes.last().expect("non-empty");
        let fetched = peer.get_blocks(&hashes).await.expect("getdata");
        for hash in &hashes {
            let block = fetched.get(hash).expect("requested block returned");
            let parts = split_block(block, branch_id);
            if parts.1.len() >= 2 {
                break 'chain parts;
            }
        }
    };

    let assemble = |transactions: &[Vec<u8>]| {
        let mut block = header.clone();
        write_compact_size(&mut block, transactions.len() as u64);
        for transaction in transactions {
            block.extend_from_slice(transaction);
        }
        block
    };

    assert!(matches!(
        joinsplits_in_block(&assemble(&[]), branch_id),
        Err(BlockError::NoTransactions)
    ));
    assert!(matches!(
        joinsplits_in_block(
            &assemble(&transactions[..transactions.len() - 1]),
            branch_id
        ),
        Err(BlockError::MerkleRootMismatch)
    ));

    let mut replaced = transactions.clone();
    replaced[1] = transactions[0].clone();
    assert!(matches!(
        joinsplits_in_block(&assemble(&replaced), branch_id),
        Err(BlockError::MutatedMerkleTree | BlockError::MerkleRootMismatch)
    ));

    let mut reordered = transactions;
    reordered.swap(0, 1);
    assert!(matches!(
        joinsplits_in_block(&assemble(&reordered), branch_id),
        Err(BlockError::MerkleRootMismatch)
    ));
}

/// Scan every block on the chain over p2p and compare the resulting Sprout
/// root against `z_gettreestate`.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn the_rebuilt_tree_matches_the_nodes_sprout_root() {
    let height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("a height");
    println!("chain height {height}");

    let mut peer = Peer::connect(NODE_P2P, P2pNetwork::Regtest)
        .await
        .expect("handshake");

    // Scanning for no keys at all: this test is about the tree, not about
    // finding notes, and an empty key set still appends every commitment.
    let mut scanner = SproutScanner::new(&[]);

    let mut locator = [0u8; 32];
    let mut scanned = 0u64;
    while scanned < height {
        let headers = peer.get_headers(&[locator]).await.expect("getheaders");
        if headers.is_empty() {
            break;
        }
        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        locator = *hashes.last().expect("non-empty");

        let fetched = peer.get_blocks(&hashes).await.expect("getdata");
        for hash in &hashes {
            let block = fetched
                .get(hash)
                .expect("every requested block must come back");
            // Canopy is inactive on this chain, so every transaction that
            // can hold a JoinSplit parses under a pre-Canopy branch id.
            let joinsplits =
                joinsplits_in_block(block, BranchId::Canopy).expect("a real block must parse");
            scanner.scan_block(&joinsplits).expect("scan");
            scanned += 1;
            if scanned >= height {
                break;
            }
        }
    }

    let progress = scanner.progress();
    println!(
        "scanned {} blocks, {} JoinSplits, {} commitments",
        progress.blocks_scanned, progress.joinsplits_seen, progress.commitments_appended
    );
    assert!(
        progress.joinsplits_seen > 0,
        "this chain holds JoinSplits; finding none means the read path is broken \
         and the root comparison below would pass vacuously on an empty tree"
    );

    // The node's own Sprout root at the same height.
    let treestate = rpc("z_gettreestate", serde_json::json!([height.to_string()])).await;
    let node_root = treestate
        .get("sprout")
        .and_then(|s| s.get("commitments"))
        .and_then(|c| c.get("finalRoot"))
        .and_then(|r| r.as_str())
        .expect("z_gettreestate must report a Sprout finalRoot");

    // zcashd prints roots byte-reversed relative to the internal encoding,
    // as it does for block hashes.
    let mut ours = scanner.anchor();
    ours.reverse();

    println!("node  root {node_root}");
    println!("our   root {}", to_hex(&ours));

    assert_eq!(
        to_hex(&ours),
        node_root,
        "the rebuilt Sprout tree must match the node's. A mismatch means \
         commitments were appended in the wrong order or some were missed, and \
         every witness derived from this tree would be worthless."
    );

    // Sanity: the node's root really is the non-empty one, so this did not
    // pass by both sides being the empty tree.
    assert_ne!(
        from_hex(node_root),
        vec![0u8; 32],
        "an all-zero root would mean the comparison proved nothing"
    );
}
