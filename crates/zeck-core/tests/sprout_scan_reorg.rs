//! A saved Sprout scan must follow a real zcashd reorg, including its cursor,
//! retained rollback history, completion flag, and commitment tree.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test sprout_scan_reorg -- --ignored --nocapture

use std::path::Path;
use std::sync::{Arc, Mutex};

#[path = "common/sprout_note_fixture.rs"]
mod sprout_note_fixture;

use argos_core::{
    p2p::wire::P2pNetwork,
    sprout_scan::{SproutScanCheckpoint, SproutScanner},
    sprout_scan_run::{run_sprout_scan, TipAnchor},
};
use sprout_note_fixture::{plant_sprout_note, rpc, NODE_P2P};

const KEY: [u8; 32] = [0x11; 32];

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
    assert_eq!(
        bytes[2], 5,
        "current checkpoint layout, with rollback history"
    );
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

/// What the test changed on the shared node, so it can be put back whether
/// the test passes or panics, and other regtest tests do not depend on
/// running before this one.
#[derive(Default)]
struct NodeChanges {
    /// The block `invalidateblock` was called on (display hex).
    invalidated: Option<String>,
    /// The transaction deprioritised out of the replacement blocks.
    deprioritised: Option<String>,
}

/// Undo [`NodeChanges`]: clear the invalid flag (the replacement branch is
/// longer, so the node stays on it), give the held-back JoinSplit its
/// priority back, and mine it so the next test finds an empty mempool.
async fn restore_node(changes: NodeChanges) {
    if let Some(txid) = &changes.deprioritised {
        rpc(
            "prioritisetransaction",
            serde_json::json!([txid, 0, 1_000_000_000]),
        )
        .await;
    }
    if let Some(hash) = &changes.invalidated {
        rpc("reconsiderblock", serde_json::json!([hash])).await;
    }
    if changes.invalidated.is_some() || changes.deprioritised.is_some() {
        rpc("generate", serde_json::json!([1])).await;
    }
}

/// Invalidation three blocks deep must discard the old suffix, then resume
/// the same checkpoint to the replacement tip and its independently computed
/// Sprout root. The node is restored afterwards, pass or fail.
#[tokio::test]
#[ignore = "needs the regtest sprout node; see the module docs"]
async fn sprout_checkpoint_rewinds_and_resumes_on_the_nodes_new_branch() {
    let changes = Arc::new(Mutex::new(NodeChanges::default()));
    // Run on its own task so a panic is caught and the node still restored.
    let outcome = tokio::spawn(rewind_and_resume(changes.clone())).await;
    let changes = std::mem::take(&mut *changes.lock().unwrap_or_else(|e| e.into_inner()));
    restore_node(changes).await;
    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn rewind_and_resume(changes: Arc<Mutex<NodeChanges>>) {
    // The fixture mines 110 funding blocks, then a funding block and the
    // JoinSplit block. Two more empty blocks put its commitments exactly
    // three deep, with well over five fresh blocks in the recent suffix.
    let planted = plant_sprout_note(KEY).await;
    rpc("generate", serde_json::json!([2])).await;
    let (old_height, old_tip) = tip().await;
    assert_eq!(old_height, planted.height + 2);

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
    assert_eq!(
        first.total_value(),
        planted.value,
        "planted note was scanned"
    );

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
    changes.lock().unwrap().invalidated = Some(display_hash(orphaned[0]));
    // zcashd returns the invalidated JoinSplit to its mempool. Keep it out
    // of the replacement blocks so its commitments are genuinely orphaned.
    assert_eq!(
        rpc(
            "prioritisetransaction",
            serde_json::json!([planted.txid, 0, -1_000_000_000]),
        )
        .await,
        serde_json::json!(true),
        "deprioritise the orphaned JoinSplit for replacement mining"
    );
    changes.lock().unwrap().deprioritised = Some(planted.txid.clone());
    rpc("generate", serde_json::json!([5])).await;
    let (new_height, new_tip) = tip().await;
    assert_eq!(
        new_height,
        old_height + 2,
        "replacement branch has five blocks"
    );
    assert_ne!(new_tip, old_tip, "zcashd switched branches");
    for height in fork_height..=new_height {
        let hash = rpc("getblockhash", serde_json::json!([height])).await;
        let block = rpc("getblock", serde_json::json!([hash, 1])).await;
        assert!(
            !block["tx"]
                .as_array()
                .expect("replacement block transactions")
                .iter()
                .any(|txid| txid.as_str() == Some(planted.txid.as_str())),
            "the planted JoinSplit must not be mined on the replacement branch"
        );
    }
    let tree = rpc(
        "z_gettreestate",
        serde_json::json!([new_height.to_string()]),
    )
    .await;
    let node_root = tree["sprout"]["commitments"]["finalRoot"]
        .as_str()
        .expect("node's Sprout finalRoot");
    assert_ne!(
        display_hash(before.anchor()),
        node_root,
        "the invalidated suffix must change the Sprout root"
    );
    eprintln!(
        "[reorg] old Sprout root {}, replacement root {node_root}",
        display_hash(before.anchor())
    );

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

    assert_eq!(display_hash(resumed.anchor), node_root);
    assert_eq!(after.anchor(), resumed.anchor, "saved replacement anchor");

    // A second resume begins with an empty getheaders reply at the new tip.
    // The verifier must fetch the saved block again through its retained
    // predecessor and validate that overlap before preserving completion.
    let stable_bytes = std::fs::read(&checkpoint).expect("saved replacement checkpoint");
    let tip_only = run_sprout_scan(
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
    .expect("validate and resume a checkpoint already at the tip");
    assert_eq!(tip_only.anchor, resumed.anchor);
    assert_eq!(std::fs::read(&checkpoint).unwrap(), stable_bytes);
}
