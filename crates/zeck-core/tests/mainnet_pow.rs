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

use argos_core::p2p::{
    peer::Peer,
    wire::{verify_header_pow, P2pNetwork},
};

const NODE: &str = "127.0.0.1:18233";

/// The sovright zebra nodes' public p2p addresses.
const SOVRIGHT_NODES: &[&str] = &[
    "136.115.98.175:8233",
    "34.80.219.125:8233",
    "34.182.139.187:8233",
    "34.91.248.94:8233",
];

/// Are the sovright nodes reachable as ordinary public peers?
///
/// If they are, an Argos user needs no tunnel and no node of their own:
/// these can be seeded directly, which is the difference between a scan
/// anyone can run and one only an operator can.
#[tokio::test]
#[ignore = "probes public infrastructure"]
async fn sovright_nodes_are_reachable_without_a_tunnel() {
    let mut reachable = 0;
    for node in SOVRIGHT_NODES {
        match Peer::connect(node, P2pNetwork::Mainnet).await {
            Ok(p) => {
                reachable += 1;
                println!("OK   {node}  height {}", p.peer_height);
            }
            Err(err) => println!("FAIL {node}  {err}"),
        }
    }
    println!("--- {reachable}/{} reachable", SOVRIGHT_NODES.len());
}

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
        verify_header_pow(P2pNetwork::Mainnet, header)
            .unwrap_or_else(|err| panic!("real mainnet header {i} failed verification: {err}"));
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

/// A bounded mainnet scan: the real read path, on the real chain.
///
/// Deliberately a few thousand blocks rather than the full 1,046,400. The
/// full range costs hours and adds only one property a short run does not
/// already establish — sustained multi-hour peer behaviour — which a single
/// run would not establish reliably anyway, since peer availability varies
/// by hour and by peer. Everything else the scan does, it does on block
/// five hundred exactly as on block five hundred thousand.
///
/// What this does exercise, all against mainnet rather than regtest: real
/// headers with real Equihash (200, 9), the difficulty check, block parsing
/// of real transactions, JoinSplit extraction, and commitment-tree building.
#[tokio::test]
#[ignore = "needs a mainnet peer; see the module docs"]
async fn a_bounded_mainnet_scan_reads_real_blocks() {
    use argos_core::{p2p::block::joinsplits_in_block, sprout_scan::SproutScanner};
    use zcash_protocol::consensus::BranchId;

    const TARGET: usize = 3_000;

    let mut peer = Peer::connect(NODE, P2pNetwork::Mainnet)
        .await
        .expect("a mainnet peer must accept us");

    let mut scanner = SproutScanner::new(&[[0x42u8; 32]]);
    let mut locator = [0u8; 32];
    let mut height = 0u32;
    let mut bytes = 0usize;
    let started = std::time::Instant::now();

    while (height as usize) < TARGET {
        let headers = peer.get_headers(&[locator]).await.expect("getheaders");
        if headers.is_empty() {
            break;
        }

        // Every header carries its own proof of work — the check the scan
        // itself now enforces.
        for header in &headers {
            verify_header_pow(P2pNetwork::Mainnet, header)
                .expect("a real mainnet header must verify");
        }

        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        locator = *hashes.last().expect("non-empty");
        let fetched = peer.get_blocks(&hashes).await.expect("getdata");

        for hash in &hashes {
            if (height as usize) >= TARGET {
                break;
            }
            let block = fetched.get(hash).expect("every requested block returns");
            bytes += block.len();
            height += 1;

            let joinsplits = joinsplits_in_block(block, BranchId::Sprout)
                .expect("a real mainnet block must parse");
            scanner
                .scan_block_at(&joinsplits, *hash, height)
                .expect("scan");
        }
    }

    let progress = scanner.progress();
    let secs = started.elapsed().as_secs_f64();
    println!(
        "scanned {} mainnet blocks, {} JoinSplits, {} commitments, {} bytes in {:.1}s",
        progress.blocks_scanned,
        progress.joinsplits_seen,
        progress.commitments_appended,
        bytes,
        secs
    );
    println!(
        "  {:.0} blocks/s — the full Sprout range would take {:.1} hours",
        progress.blocks_scanned as f64 / secs,
        (1_046_400.0 / (progress.blocks_scanned as f64 / secs)) / 3600.0
    );

    assert!(
        progress.blocks_scanned as usize >= TARGET,
        "the scan must reach its bound; got {}",
        progress.blocks_scanned
    );
    // Mainnet's first blocks predate any shielded activity, so finding no
    // JoinSplits here is correct — the assertion is that real blocks parsed
    // and the tree advanced in step with them.
    assert_eq!(
        progress.commitments_appended,
        progress.joinsplits_seen * 2,
        "each JoinSplit contributes exactly two commitments"
    );
}

/// Every checkpoint must match the real chain, checked directly.
///
/// A wrong checkpoint does not weaken security — it rejects the honest
/// chain outright, aborting every mainnet scan at that height. That failure
/// is invisible to a bounded scan (the earliest checkpoint is at 100,000)
/// and to unit tests, which can only confirm the constants parse. Only the
/// chain itself can say whether they are the right hashes.
#[tokio::test]
#[ignore = "needs a mainnet peer; see the module docs"]
async fn every_mainnet_checkpoint_matches_the_real_chain() {
    use argos_core::p2p::wire::checkpoint_at;

    // Heights with pinned hashes, walked to over p2p and compared.
    const PINNED: &[u32] = &[100_000, 200_000, 300_000, 419_200];

    let mut peer = Peer::connect(NODE, P2pNetwork::Mainnet)
        .await
        .expect("a mainnet peer must accept us");

    let mut locator = [0u8; 32];
    let mut height: u32 = 0;
    let mut checked = 0usize;
    let last = *PINNED.last().expect("non-empty");

    // `<=`, not `<`: the last pinned height must itself be processed. With
    // `<` the loop exits just before reaching it, and the final checkpoint
    // is silently never checked — which is exactly what this test caught in
    // its own first version.
    while height <= last {
        let headers = peer.get_headers(&[locator]).await.expect("getheaders");
        if headers.is_empty() {
            break;
        }
        locator = headers.last().expect("non-empty").hash;

        for header in &headers {
            // `height` is the height of this header: genesis is 0.
            if let Some(expected) = checkpoint_at(P2pNetwork::Mainnet, height) {
                assert_eq!(
                    header.hash, expected,
                    "checkpoint at height {height} does not match the real chain — every                      mainnet scan would abort here"
                );
                checked += 1;
                println!("  height {height} matches");
            }
            height += 1;
            if height > last {
                break;
            }
        }
    }

    assert_eq!(
        checked,
        PINNED.len(),
        "every pinned height must have been reached and checked"
    );
    println!("all {checked} mainnet checkpoints match the chain");
}
