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

#[path = "common/sprout_note_fixture.rs"]
mod sprout_note_fixture;

use argos_core::{p2p::wire::P2pNetwork, sprout_scan_run, sprout_witness};
use sprout_note_fixture::{bytes_to_hex, plant_sprout_note, random32, rpc, NODE_P2P};

#[tokio::test]
#[ignore = "requires the sprout profile and sprout-groth16.params; see the module docs"]
async fn a_scan_finds_a_note_it_was_never_told_about() {
    let a_sk = random32();
    let planted = plant_sprout_note(a_sk).await;
    let shielded = planted.value;
    let shield_height = u64::from(planted.height);
    let mined = rpc("getrawtransaction", serde_json::json!([planted.txid, 1])).await;
    assert_eq!(mined["height"].as_u64(), Some(shield_height));

    // ── Now scan, knowing only the spending key ───────────────────────────
    let dir = std::env::temp_dir().join("argos-scan-e2e");
    let _ = std::fs::remove_dir_all(&dir);
    let checkpoint = sprout_scan_run::checkpoint_path(&dir, &[a_sk]);

    let started = std::time::Instant::now();
    let result = sprout_scan_run::run_sprout_scan(
        &[a_sk],
        P2pNetwork::Regtest,
        &[NODE_P2P.to_owned()],
        None,
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
