//! A saved Sprout scan must follow a real zcashd reorg, including its cursor,
//! retained rollback history, completion flag, and commitment tree.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test sprout_scan_reorg -- --ignored --nocapture

use std::path::Path;

use argos_core::{
    p2p::wire::P2pNetwork,
    sprout_scan::{SproutScanCheckpoint, SproutScanner},
    sprout_scan_run::{run_sprout_scan, TipAnchor},
};

const RPC: &str = "http://127.0.0.1:18242";
const NODE_P2P: &str = "127.0.0.1:18344";
const KEY: [u8; 32] = [0x11; 32];

async fn rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let host_port = RPC.strip_prefix("http://").unwrap_or(RPC);
    let body = serde_json::json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
    let payload = serde_json::to_vec(&body).expect("serializable request");
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
    let start = text.find("\r\n\r\n").map(|i| i + 4).expect("HTTP headers");
    let parsed: serde_json::Value = serde_json::from_str(text[start..].trim())
        .unwrap_or_else(|err| panic!("zcashd {method} returned unparseable JSON: {err}\n{text}"));
    assert!(
        parsed.get("error").is_none_or(serde_json::Value::is_null),
        "zcashd {method} failed: {}",
        parsed["error"]
    );
    parsed.get("result").cloned().expect("RPC result")
}

fn wire_hash(display_hash: &str) -> [u8; 32] {
    assert_eq!(display_hash.len(), 64, "a block hash has 32 bytes");
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&display_hash[index * 2..index * 2 + 2], 16)
            .expect("hex block hash");
    }
    bytes.reverse();
    bytes
}

fn display_hash(mut wire_hash: [u8; 32]) -> String {
    wire_hash.reverse();
    wire_hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn saved_scanner(path: &Path) -> SproutScanner {
    let bytes = std::fs::read(path).expect("saved checkpoint");
    assert_eq!(&bytes[..2], &[0xA5, 3], "network-tagged regtest checkpoint");
    SproutScanner::resume(&SproutScanCheckpoint::from_bytes(bytes[2..].to_vec()))
        .expect("read saved scanner")
}

async fn tip() -> (u32, String) {
    let height = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("block count") as u32;
    let hash = rpc("getbestblockhash", serde_json::json!([]))
        .await
        .as_str()
        .expect("best block hash")
        .to_owned();
    (height, hash)
}

/// Invalidation three blocks deep must discard the old suffix, then resume
/// the same checkpoint to the replacement tip and its independently computed
/// Sprout root.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn sprout_checkpoint_rewinds_and_resumes_on_the_nodes_new_branch() {
    // Five fresh empty blocks make the fork depth independent of the node's
    // pre-existing chain and leave a retained common ancestor.
    rpc("generate", serde_json::json!([5])).await;
    let (old_height, old_tip) = tip().await;
    assert!(old_height >= 5);

    let dir = tempfile::tempdir().expect("private checkpoint directory");
    let checkpoint = dir.path().join("reorg.checkpoint");
    let peers = [NODE_P2P.to_owned()];
    let first = run_sprout_scan(
        &[KEY],
        P2pNetwork::Regtest,
        &peers,
        Some(TipAnchor {
            height: old_height,
            hash: wire_hash(&old_tip),
        }),
        &checkpoint,
        |_| {},
    )
    .await
    .expect("initial scan to old tip");
    let before = saved_scanner(&checkpoint);
    let old_cursor = before.cursor().expect("saved initial cursor");
    assert_eq!(old_cursor.last_height, old_height);
    assert_eq!(old_cursor.last_block_hash, wire_hash(&old_tip));
    assert!(before.is_complete(), "initial scan reached its tip");
    assert_eq!(before.anchor(), first.anchor, "saved initial anchor");

    let fork_height = old_height - 2; // This block and two successors are orphaned.
    let orphaned: Vec<[u8; 32]> = {
        let mut hashes = Vec::new();
        for height in fork_height..=old_height {
            let hash = rpc("getblockhash", serde_json::json!([height]))
                .await
                .as_str()
                .expect("old branch block hash")
                .to_owned();
            hashes.push(wire_hash(&hash));
        }
        hashes
    };
    rpc(
        "invalidateblock",
        serde_json::json!([display_hash(orphaned[0])]),
    )
    .await;
    rpc("generate", serde_json::json!([5])).await;
    let (new_height, new_tip) = tip().await;
    assert_eq!(
        new_height,
        old_height + 2,
        "replacement branch has five blocks"
    );
    assert_ne!(new_tip, old_tip, "zcashd switched branches");

    let resumed = run_sprout_scan(
        &[KEY],
        P2pNetwork::Regtest,
        &peers,
        Some(TipAnchor {
            height: new_height,
            hash: wire_hash(&new_tip),
        }),
        &checkpoint,
        |_| {},
    )
    .await
    .expect("resume checkpoint across reorg");
    let after = saved_scanner(&checkpoint);
    let final_cursor = after.cursor().expect("saved replacement cursor");
    assert_eq!(final_cursor.last_height, new_height);
    assert_eq!(final_cursor.last_block_hash, wire_hash(&new_tip));
    assert_eq!(display_hash(final_cursor.last_block_hash), new_tip);
    assert!(
        after.is_complete(),
        "completion is valid only at the replacement tip"
    );
    assert!(
        after
            .rollback_locators()
            .iter()
            .all(|locator| !orphaned.contains(&locator.last_block_hash)),
        "no orphan hash may survive in retained locators"
    );

    let tree = rpc(
        "z_gettreestate",
        serde_json::json!([new_height.to_string()]),
    )
    .await;
    let node_root = tree["sprout"]["commitments"]["finalRoot"]
        .as_str()
        .expect("node's Sprout finalRoot");
    assert_eq!(display_hash(resumed.anchor), node_root);
    assert_eq!(after.anchor(), resumed.anchor, "saved replacement anchor");
}
