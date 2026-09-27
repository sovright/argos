//! Why the Sprout scan runs to the chain tip, checked against mainnet itself.
//!
//! The scan used to stop at Canopy on the reading that ZIP 211 ended Sprout
//! there. It does not: ZIP 211 requires `vpub_old == 0`, which stops new
//! value *entering* Sprout, but a JoinSplit may still spend Sprout notes and
//! create new ones. These tests pin the facts that change rested on, and the
//! new pieces it relies on, to the real chain rather than to reasoning.
//!
//! They need the public mainnet p2p network (and, for the last, a mainnet
//! lightwalletd), so they are ignored by default:
//!
//!     cargo test -p argos-core --test sprout_scan_past_canopy -- --ignored --nocapture

use argos_core::p2p::{
    block::joinsplits_in_block,
    peer::Peer,
    pool::connect_to_any,
    wire::{checkpoint_at, verify_header_pow, P2pNetwork},
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

/// A mainnet peer, with a pause before every retry: peers refuse a second
/// connection from the same address for about two minutes, and hammering
/// them only exhausts the public pool (and the fallback nodes in it).
async fn peer(attempt: &mut u32) -> Peer {
    assert!(*attempt < 10, "could not keep a mainnet peer");
    if *attempt > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
    *attempt += 1;
    connect_to_any(P2pNetwork::Mainnet, &[], 6)
        .await
        .expect("a mainnet peer")
}

/// Walk `count` blocks after `locator`, returning each block with its hash.
async fn blocks_after(
    locator: [u8; 32],
    count: u32,
    visit: &mut impl FnMut(u32, &[u8; 32], &[u8]),
) {
    let mut attempt = 0;
    let mut p = peer(&mut attempt).await;
    let (mut locator, mut seen) = (locator, 0u32);
    while seen < count {
        let headers = match p.get_headers(&[locator]).await {
            Ok(h) if !h.is_empty() => h,
            _ => {
                p = peer(&mut attempt).await;
                continue;
            }
        };
        for h in &headers {
            verify_header_pow(P2pNetwork::Mainnet, h).expect("real headers verify");
        }
        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        let blocks = match p.get_blocks(&hashes).await {
            Ok(b) => b,
            Err(_) => {
                p = peer(&mut attempt).await;
                continue;
            }
        };
        assert_eq!(
            headers[0].prev_hash, locator,
            "the peer must continue from the block asked for"
        );
        locator = *hashes.last().expect("non-empty");
        for hash in &hashes {
            if seen >= count {
                return;
            }
            seen += 1;
            visit(seen, hash, &blocks[hash]);
        }
    }
}

/// The premise. If this ever found nothing, the Canopy bound would have been
/// harmless; it finds JoinSplits within the first twenty blocks.
#[tokio::test]
#[ignore = "needs the public mainnet p2p network"]
async fn sprout_joinsplits_continue_after_canopy() {
    let canopy = checkpoint_at(P2pNetwork::Mainnet, 1_046_400).expect("pinned");
    let mut joinsplits = 0usize;
    let mut first = None;
    blocks_after(canopy, 1_000, &mut |offset, _, block| {
        let found = joinsplits_in_block(block, BranchId::Canopy).expect("a real block parses");
        if !found.is_empty() {
            first.get_or_insert(1_046_400 + offset);
        }
        joinsplits += found.len();
    })
    .await;
    println!("{joinsplits} Sprout JoinSplits in the 1,000 blocks after Canopy; first at {first:?}");
    assert!(
        joinsplits > 0,
        "Sprout JoinSplits exist after Canopy — a scan that stops there misses them"
    );
}

/// The height a block claims for itself, from its coinbase (BIP 34).
fn coinbase_height(block: &[u8]) -> u32 {
    fn compact(b: &[u8]) -> (usize, usize) {
        match b[0] {
            0xfd => (u16::from_le_bytes([b[1], b[2]]) as usize, 3),
            0xfe => (u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as usize, 5),
            n => (n as usize, 1),
        }
    }
    // 140-byte fixed header, then the length-prefixed Equihash solution,
    // then the transaction count.
    let (solution, used) = compact(&block[140..]);
    let mut pos = 140 + used + solution;
    pos += compact(&block[pos..]).1;
    let coinbase = Transaction::read(&block[pos..], BranchId::Canopy).expect("coinbase parses");
    let script = &coinbase.transparent_bundle().expect("transparent").vin[0]
        .script_sig()
        .0
         .0;
    let len = script[0] as usize;
    let mut height = [0u8; 4];
    height[..len].copy_from_slice(&script[1..=len]);
    u32::from_le_bytes(height)
}

/// Every checkpoint past Canopy is the block at its height, and the chain
/// continues from it — including across the v5 transactions NU5 introduced,
/// which the scan must parse even though they never carry a JoinSplit.
///
/// Checked by hash rather than by walking from genesis: fetching the pinned
/// hash proves the block exists, its coinbase proves the height, and a
/// proof-of-work-valid chain continuing from it proves it is on the chain.
#[tokio::test]
#[ignore = "needs the public mainnet p2p network"]
async fn post_canopy_checkpoints_are_real() {
    for height in [1_687_104, 2_726_400, 3_146_400, 3_364_600, 3_428_143] {
        let hash = checkpoint_at(P2pNetwork::Mainnet, height).expect("pinned");
        let mut attempt = 0;
        let mut p = peer(&mut attempt).await;
        let block = loop {
            match p.get_blocks(&[hash]).await {
                Ok(mut found) => break found.remove(&hash).expect("the pinned block"),
                Err(_) => p = peer(&mut attempt).await,
            }
        };
        assert_eq!(
            coinbase_height(&block),
            height,
            "coinbase of the pin at {height}"
        );
        let mut parsed = 0;
        blocks_after(hash, 200, &mut |offset, _, b| {
            joinsplits_in_block(b, BranchId::Canopy)
                .unwrap_or_else(|err| panic!("block {} must parse: {err}", height + offset));
            parsed += 1;
        })
        .await;
        println!("checkpoint {height} is on the chain; {parsed} blocks after it parse");
    }
}

/// `TipAnchor` compares lightwalletd's `CompactBlock.hash` directly against
/// the peer's block hash, which is only right if lightwalletd sends it in
/// wire order. Checked against a pinned block, so a byte-order mistake
/// cannot reject every honest peer at the anchor.
#[tokio::test]
#[ignore = "needs a mainnet lightwalletd"]
async fn lightwalletd_block_hashes_are_in_wire_order() {
    use zcash_client_backend::proto::service::BlockId;

    let (mut client, endpoint) = argos_core::lightwalletd::connect_lightwalletd_endpoints(
        argos_core::lightwalletd::DEFAULT_MAINNET_LIGHTWALLETD,
        None,
    )
    .await
    .expect("a mainnet lightwalletd");
    let block = client
        .get_block(BlockId {
            height: 1_046_400,
            hash: vec![],
        })
        .await
        .expect("block 1,046,400")
        .into_inner();
    assert_eq!(
        block.hash.as_slice(),
        checkpoint_at(P2pNetwork::Mainnet, 1_046_400)
            .expect("pinned")
            .as_slice(),
        "{endpoint} must return block hashes in wire order"
    );

    let anchor = argos_core::sprout_scan_run::independent_tip_anchor(
        argos_core::ZeckNetwork::Mainnet,
        argos_core::lightwalletd::DEFAULT_MAINNET_LIGHTWALLETD,
    )
    .await
    .expect("an anchor");
    assert!(
        anchor.height > 3_428_143,
        "the anchor must sit past the last checkpoint"
    );
    println!("anchor at {} from {endpoint}", anchor.height);
}
