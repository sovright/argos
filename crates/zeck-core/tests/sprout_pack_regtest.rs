//! The Sprout pack, built from a real node and scanned against a real chain.
//!
//! Plants a Sprout note, builds a pack from the node that ends partway up
//! the chain (after the note, so the note comes from the pack, and before
//! the tip, so the scan has to hand off to p2p), then checks that a scan
//! with the pack ends exactly where a scan without it does: same notes,
//! same anchor, same JoinSplit count.
//!
//!     cd tests/regtest && docker compose --profile sprout up -d zcashd-sprout
//!     cargo test -p argos-core --test sprout_pack_regtest -- --ignored --nocapture

#[path = "common/sprout_note_fixture.rs"]
mod sprout_note_fixture;

use argos_core::{
    p2p::wire::P2pNetwork,
    sprout_pack::{PackTrust, SproutPack},
    sprout_pack_build::{build_pack, PackBuildConfig},
    sprout_scan_run::{self, SproutScanOptions},
};
use sprout_note_fixture::{plant_sprout_note, random32, rpc, NODE_P2P};

#[tokio::test]
#[ignore = "requires the sprout profile and sprout-groth16.params; see the module docs"]
async fn a_pack_built_from_a_node_scans_like_the_chain() {
    let a_sk = random32();
    let planted = plant_sprout_note(a_sk).await;
    let tip = rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("height") as u32;
    assert!(tip > planted.height, "the note must be below the tip");
    eprintln!(
        "[pack] note planted by {} at height {}",
        planted.txid, planted.height
    );
    // Between the note and the tip: the note is read from the pack and the
    // remaining blocks from the node.
    let end_height = planted.height + (tip - planted.height) / 2;

    let parent = tempfile::tempdir().expect("tempdir");
    let pack_dir = parent.path().join("pack");
    let config = PackBuildConfig {
        network: P2pNetwork::Regtest,
        peers: vec![NODE_P2P.to_owned()],
        end_height,
        out_dir: pack_dir.clone(),
    };
    let built = build_pack(&config, |_| {}).await.expect("build");
    assert_eq!(built.manifest.end_height, end_height);
    assert!(built.manifest.total_joinsplits > 0);

    // A second build from the same node reproduces the manifest byte for byte.
    let again_dir = parent.path().join("pack-again");
    let again = build_pack(
        &PackBuildConfig {
            out_dir: again_dir,
            ..config.clone()
        },
        |_| {},
    )
    .await
    .expect("rebuild");
    assert_eq!(again.manifest_sha256, built.manifest_sha256);

    // The pack's tree root is the chain's.
    let state = rpc(
        "z_gettreestate",
        serde_json::json!([end_height.to_string()]),
    )
    .await;
    let mut root = built.manifest.sprout_root;
    root.reverse();
    assert_eq!(
        sprout_note_fixture::bytes_to_hex(&root),
        state["sprout"]["commitments"]["finalRoot"]
            .as_str()
            .expect("finalRoot")
    );

    let pack = SproutPack::open(&pack_dir, P2pNetwork::Regtest).expect("open");
    assert_eq!(pack.trust(), PackTrust::Unpinned);

    let with_pack_dir = parent.path().join("scan-with-pack");
    let with_pack = sprout_scan_run::run_sprout_scan_with_options(
        &[a_sk],
        P2pNetwork::Regtest,
        &[NODE_P2P.to_owned()],
        None,
        &sprout_scan_run::checkpoint_path_for_network(&with_pack_dir, &[a_sk], P2pNetwork::Regtest),
        SproutScanOptions {
            decrypt_from: None,
            pack: Some(&pack),
        },
        |_| {},
    )
    .await
    .expect("scan with pack");

    let without_dir = parent.path().join("scan-without");
    let without = sprout_scan_run::run_sprout_scan(
        &[a_sk],
        P2pNetwork::Regtest,
        &[NODE_P2P.to_owned()],
        None,
        &sprout_scan_run::checkpoint_path_for_network(&without_dir, &[a_sk], P2pNetwork::Regtest),
        |_| {},
    )
    .await
    .expect("scan without pack");

    assert_eq!(with_pack.progress, without.progress);
    assert_eq!(with_pack.notes.len(), without.notes.len());
    assert_eq!(with_pack.total_value(), planted.value);
    for (a, b) in with_pack.notes.iter().zip(&without.notes) {
        assert_eq!(a.anchor, b.anchor, "the pack must give the same witness");
        assert_eq!(a.outpoint, b.outpoint);
    }
}
