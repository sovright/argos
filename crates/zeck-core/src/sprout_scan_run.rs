//! Driving a Sprout scan from end to end.
//!
//! [`crate::sprout_scan::SproutScanner`] is a passive consumer: it takes one
//! block's JoinSplits at a time and knows nothing about where they came
//! from. This module is the part that connects to the network, walks the
//! chain, and keeps the scan alive across the hours it takes.
//!
//! # What makes this awkward
//!
//! Three properties of the p2p network, each measured rather than assumed,
//! shape the loop:
//!
//! - A peer serves one inbound connection per source IP per ~119 seconds, so
//!   a lost connection must be replaced by a *different* peer. Retrying the
//!   same one is guaranteed to fail and looks identical to a dead network.
//! - A `getdata` naming a whole header page is accepted and never answered,
//!   so block requests are batched small.
//! - Peers refuse the overwhelming majority of inbound connections outright,
//!   so finding one at all means racing many.
//!
//! # Checkpointing
//!
//! The scan saves after every batch. The commitment tree is not derivable
//! from anything cheaper than re-reading every block, so losing it means
//! starting a multi-hour download again — which is exactly what the cost
//! warning promises will not happen.

use std::path::{Path, PathBuf};

use crate::{
    error::{ZeckError, ZeckResult},
    p2p::{block::joinsplits_in_block, peer::Peer, pool::connect_to_any, wire::P2pNetwork},
    sprout_scan::{SproutScanCheckpoint, SproutScanResult, SproutScanner},
};
use zcash_protocol::consensus::BranchId;

/// How often to write a checkpoint, in blocks.
///
/// Every batch would be safest and every thousand cheapest. This is sized so
/// an interrupted scan loses at most a few seconds of work while the file is
/// rewritten rarely enough not to matter.
const CHECKPOINT_EVERY: u64 = 500;

/// Progress, reported often enough that a multi-hour run never looks stalled.
#[derive(Debug, Clone, Copy)]
pub struct ScanTick {
    pub height: u32,
    pub target: u32,
    pub notes_found: usize,
    pub joinsplits_seen: u64,
}

/// Where a scan's checkpoint lives for a given key set.
///
/// Keyed by a fingerprint of the spending keys, so scanning a different
/// wallet never resumes into the wrong tree — a checkpoint restored under
/// the wrong keys would hold a valid tree and find nothing, with no
/// indication why.
pub fn checkpoint_path(data_dir: &Path, spending_keys: &[[u8; 32]]) -> PathBuf {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    // Sorted, so key order does not change the identity of a scan.
    let mut sorted: Vec<_> = spending_keys.to_vec();
    sorted.sort_unstable();
    for key in &sorted {
        h.update(key);
    }
    let digest = h.finalize();
    let fingerprint: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    data_dir.join(format!("sprout-scan-{fingerprint}.checkpoint"))
}

/// Run a Sprout scan to completion, resuming from `checkpoint_file` if present.
///
/// `extra_peers` is tried before any DNS seed, so a caller with its own node
/// never depends on the public network.
pub async fn run_sprout_scan(
    spending_keys: &[[u8; 32]],
    network: P2pNetwork,
    extra_peers: &[String],
    checkpoint_file: &Path,
    mut progress: impl FnMut(ScanTick),
) -> ZeckResult<SproutScanResult> {
    if spending_keys.is_empty() {
        return Err(ZeckError::TransactionBuild(
            "a Sprout scan needs at least one spending key".to_owned(),
        ));
    }

    let target = network.sprout_scan_end();

    // Resume if we can. A checkpoint that will not load is reported rather
    // than silently discarded: starting a six-hour scan over because a file
    // was quietly ignored is worse than stopping to say so.
    let mut scanner = match std::fs::read(checkpoint_file) {
        Ok(bytes) => {
            let checkpoint = SproutScanCheckpoint::from_bytes(bytes);
            SproutScanner::resume(&checkpoint).map_err(|err| {
                ZeckError::TransactionBuild(format!(
                    "the scan checkpoint at {} could not be read ({err}). Delete it to \
                     start a fresh scan, or restore a good copy — it holds hours of work.",
                    checkpoint_file.display()
                ))
            })?
        }
        Err(_) => SproutScanner::new(spending_keys),
    };

    let mut locator = scanner
        .cursor()
        .map(|c| c.last_block_hash)
        // An all-zero locator asks the peer to start from genesis.
        .unwrap_or([0u8; 32]);
    let mut height = scanner.progress().last_height;
    let mut since_checkpoint = 0u64;

    let mut peer = connect_peer(network, extra_peers, &[]).await?;
    let mut exhausted: Vec<String> = Vec::new();

    while height < target {
        let headers = match peer.get_headers(&[locator]).await {
            Ok(h) if !h.is_empty() => h,
            // A clean end of chain.
            Ok(_) => break,
            Err(_) => {
                // The peer is gone. Reconnecting to it would be refused for
                // the next two minutes regardless, so take a different one.
                exhausted.push(String::new());
                peer = connect_peer(network, extra_peers, &exhausted).await?;
                continue;
            }
        };

        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        let blocks = match peer.get_blocks(&hashes).await {
            Ok(b) => b,
            Err(_) => {
                exhausted.push(String::new());
                peer = connect_peer(network, extra_peers, &exhausted).await?;
                continue;
            }
        };

        for (block, hash) in blocks.iter().zip(hashes.iter()) {
            if height >= target {
                break;
            }
            height += 1;

            // The branch id only affects how the transaction parses, and
            // every Sprout-bearing transaction predates Canopy.
            let joinsplits = joinsplits_in_block(block, BranchId::Canopy).map_err(|err| {
                ZeckError::TransactionBuild(format!("block at height {height}: {err}"))
            })?;

            scanner
                .scan_block_at(&joinsplits, *hash, height)
                .map_err(|err| {
                    ZeckError::TransactionBuild(format!("scanning height {height}: {err}"))
                })?;
            since_checkpoint += 1;
        }

        locator = *hashes.last().expect("non-empty");

        if since_checkpoint >= CHECKPOINT_EVERY {
            save_checkpoint(&scanner, checkpoint_file)?;
            since_checkpoint = 0;
        }

        let p = scanner.progress();
        progress(ScanTick {
            height,
            target,
            notes_found: p.notes_found,
            joinsplits_seen: p.joinsplits_seen,
        });
    }

    save_checkpoint(&scanner, checkpoint_file)?;

    scanner
        .finish()
        .map_err(|err| ZeckError::TransactionBuild(format!("finishing the scan: {err}")))
}

fn save_checkpoint(scanner: &SproutScanner, path: &Path) -> ZeckResult<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Written to a temporary file and renamed, so an interrupt during the
    // write cannot leave a half-written checkpoint where a good one was —
    // that would turn a recoverable pause into a restart from genesis.
    let tmp = path.with_extension("checkpoint.tmp");
    std::fs::write(&tmp, scanner.checkpoint().as_bytes()).map_err(|err| {
        ZeckError::TransactionBuild(format!("writing the scan checkpoint: {err}"))
    })?;
    std::fs::rename(&tmp, path).map_err(|err| {
        ZeckError::TransactionBuild(format!("replacing the scan checkpoint: {err}"))
    })?;
    Ok(())
}

async fn connect_peer(
    network: P2pNetwork,
    extra: &[String],
    _exhausted: &[String],
) -> ZeckResult<Peer> {
    connect_to_any(network, extra, 4)
        .await
        .map_err(|err| ZeckError::Broadcast(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two different key sets must never share a checkpoint. Resuming into
    /// the wrong tree would produce a valid-looking scan that finds nothing,
    /// with nothing to indicate why.
    #[test]
    fn checkpoint_paths_are_keyed_by_the_spending_keys() {
        let dir = Path::new("/tmp/argos");
        let a = checkpoint_path(dir, &[[0x11; 32]]);
        let b = checkpoint_path(dir, &[[0x22; 32]]);
        assert_ne!(a, b);
        assert!(a.to_string_lossy().contains("sprout-scan-"));
    }

    /// Key order is not part of a scan's identity: the same wallet listed in
    /// a different order must resume its own checkpoint, not start over.
    #[test]
    fn key_order_does_not_change_the_checkpoint_path() {
        let dir = Path::new("/tmp/argos");
        assert_eq!(
            checkpoint_path(dir, &[[0x11; 32], [0x22; 32]]),
            checkpoint_path(dir, &[[0x22; 32], [0x11; 32]])
        );
    }

    #[tokio::test]
    async fn a_scan_with_no_keys_is_refused() {
        let err = run_sprout_scan(
            &[],
            P2pNetwork::Regtest,
            &[],
            Path::new("/tmp/argos/none.checkpoint"),
            |_| {},
        )
        .await
        .expect_err("a scan needs keys");
        assert!(err.to_string().contains("at least one"));
    }

    /// A corrupt checkpoint must stop the scan with an explanation, not be
    /// silently discarded — six hours of work is worth a question.
    #[tokio::test]
    async fn a_corrupt_checkpoint_is_reported_not_discarded() {
        let dir = std::env::temp_dir().join("argos-scan-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corrupt.checkpoint");
        std::fs::write(&path, b"not a checkpoint").unwrap();

        let err = run_sprout_scan(&[[0x11; 32]], P2pNetwork::Regtest, &[], &path, |_| {})
            .await
            .expect_err("a corrupt checkpoint must not be ignored");
        let text = err.to_string();
        assert!(
            text.contains("could not be read") && text.contains("Delete it"),
            "the message must say what happened and what to do: {text}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
