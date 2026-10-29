//! Building a Sprout pack from a node the maintainer runs.
//!
//! The builder walks the chain from genesis to a fixed end height over p2p,
//! from the listed peers only, and writes each block's JoinSplits into
//! [`crate::sprout_pack`] chunks. It reuses the scan's fetcher, so every
//! block it writes has passed the same checks a scanned block passes: the
//! header's Equihash proof of work, linkage to the block before it, the
//! pinned checkpoint hashes, and the body's txid Merkle root.
//!
//! Peers-only is deliberate. A pack is meant to be a function of the chain,
//! reproduced by a second maintainer from a second node; a walk that drifted
//! onto a public peer after a dropped connection would make it a function of
//! whichever peer answered. Either zcashd or zebrad works, since both speak
//! the same p2p protocol on port 8233 (18233 on testnet).
//!
//! # Resuming
//!
//! A mainnet build reads the whole chain once and takes hours. Each chunk is
//! renamed into place only when complete, so a re-run reads the complete
//! chunks already on disk, continues from the last one's final block, and
//! rewrites anything after it.
//!
//! # The manifest is derived from the files
//!
//! When every chunk exists, the manifest is computed by reading the chunks
//! back from disk — hashes, counts and the Sprout tree root — not from what
//! the builder believes it wrote. What gets pinned is what is on disk.

use std::path::{Path, PathBuf};

use crate::{
    error::{ZeckError, ZeckResult},
    p2p::wire::P2pNetwork,
    sprout_pack::{
        chunk_count, chunk_range, scan_chunk_file, summarize_chunks, write_manifest, ChunkEntry,
        ChunkWriter, PackManifest, CHUNK_BLOCKS, PACK_MIN_DEPTH,
    },
    sprout_scan_run::{agrees_with_checkpoints, connect_peer_from, PageFetcher, PeerWait},
};

/// What to build.
#[derive(Debug, Clone)]
pub struct PackBuildConfig {
    pub network: P2pNetwork,
    /// The node(s) to read from, as `host:port`. Only these are dialled.
    pub peers: Vec<String>,
    /// The last height the pack covers.
    pub end_height: u32,
    /// Where chunks and the manifest are written.
    pub out_dir: PathBuf,
}

/// Progress, reported after each page and while waiting for a peer.
#[derive(Debug, Clone)]
pub enum PackBuildTick {
    /// Chunks already complete on disk from an earlier run were reused.
    Resumed { chunks: usize, next_height: u32 },
    /// Walking the chain: `height` is the last block written.
    Walking { height: u32, end_height: u32 },
    /// Waiting on the node.
    Waiting(PeerWait),
    /// Reading the finished chunks back to write the manifest.
    Summarizing { height: u32, end_height: u32 },
}

/// A finished pack.
#[derive(Debug, Clone)]
pub struct BuiltPack {
    pub manifest: PackManifest,
    pub manifest_sha256: [u8; 32],
}

fn build_error(message: impl Into<String>) -> ZeckError {
    ZeckError::InvalidConfig(format!("Sprout pack build: {}", message.into()))
}

/// How far below the node's tip the end height must be.
fn min_depth(network: P2pNetwork) -> u32 {
    // A regtest chain is whatever a test mined; it never reorganizes.
    if matches!(network, P2pNetwork::Regtest) {
        0
    } else {
        PACK_MIN_DEPTH
    }
}

/// The complete chunks already in `dir`, in order, stopping at the first
/// missing or unreadable one.
fn completed_chunks(dir: &Path, network: P2pNetwork, end_height: u32) -> Vec<ChunkEntry> {
    let mut done = Vec::new();
    for index in 0..chunk_count(end_height) {
        match scan_chunk_file(dir, index, network, end_height, |_| Ok(())) {
            Ok(entry) => done.push(entry),
            Err(_) => break,
        }
    }
    done
}

/// Build (or finish building) a pack.
pub async fn build_pack(
    config: &PackBuildConfig,
    mut progress: impl FnMut(PackBuildTick),
) -> ZeckResult<BuiltPack> {
    if config.peers.is_empty() {
        return Err(build_error(
            "name the node to read from with at least one peer (host:port)",
        ));
    }
    if config.end_height == 0 {
        return Err(build_error("the end height must be at least 1"));
    }
    let network = config.network;
    let end_height = config.end_height;
    let dir = config.out_dir.as_path();
    std::fs::create_dir_all(dir)
        .map_err(|err| build_error(format!("creating {}: {err}", dir.display())))?;

    let mut done = completed_chunks(dir, network, end_height);
    let total_chunks = chunk_count(end_height);
    if !done.is_empty() {
        progress(PackBuildTick::Resumed {
            chunks: done.len(),
            next_height: done.len() as u32 * CHUNK_BLOCKS + 1,
        });
    }

    if done.len() < total_chunks {
        walk(config, &mut done, &mut progress).await?;
    }

    let summary = summarize_chunks(dir, network, end_height, |height| {
        if height % 10_000 == 0 || height == end_height {
            progress(PackBuildTick::Summarizing { height, end_height });
        }
    })?;
    if summary.chunks != done {
        return Err(build_error(
            "the chunks on disk changed while the pack was being built",
        ));
    }
    let manifest = PackManifest {
        network,
        end_height,
        end_hash: summary
            .chunks
            .last()
            .map(|c| c.last_hash)
            .expect("at least one chunk"),
        sprout_root: summary.sprout_root,
        total_joinsplits: summary.total_joinsplits,
        chunks: summary.chunks,
    };
    let manifest_sha256 = write_manifest(dir, &manifest)?;
    Ok(BuiltPack {
        manifest,
        manifest_sha256,
    })
}

/// Fetch and write every chunk after those in `done`.
async fn walk(
    config: &PackBuildConfig,
    done: &mut Vec<ChunkEntry>,
    progress: &mut impl FnMut(PackBuildTick),
) -> ZeckResult<()> {
    let network = config.network;
    let end_height = config.end_height;
    let dir = config.out_dir.as_path();

    let locator = done.last().map_or([0u8; 32], |c| c.last_hash);
    let mut height = done.len() as u32 * CHUNK_BLOCKS + 1;

    let mut waits = Vec::new();
    let peer =
        connect_peer_from(network, &config.peers, &[], true, |wait| waits.push(wait)).await?;
    for wait in waits {
        progress(PackBuildTick::Waiting(wait));
    }
    let tip = peer.peer_height;
    let needed = end_height.saturating_add(min_depth(network));
    if tip < needed {
        return Err(build_error(format!(
            "{} reports its chain at height {tip}. A pack ending at {end_height} needs the \
             node at least {} blocks past it (height {needed}), so the pinned end can \
             never be reorganized away. Wait for the node to sync, or choose a lower end \
             height.",
            peer.dialled_as(),
            min_depth(network)
        )));
    }

    let (wait_tx, mut wait_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut fetcher = PageFetcher::for_listed_peers(
        peer,
        locator,
        height,
        end_height,
        network,
        config.peers.clone(),
        wait_tx,
    );

    let mut index = done.len();
    let (first, last) = chunk_range(index, end_height).expect("a chunk remains");
    let mut writer = ChunkWriter::create(dir, index, network, first, last)?;

    while height <= end_height {
        let page = fetcher.next_page().await;
        while let Ok(wait) = wait_rx.try_recv() {
            progress(PackBuildTick::Waiting(wait));
        }
        let Some(page) = page? else {
            continue;
        };
        if page.blocks.is_empty() {
            return Err(build_error(format!(
                "the node stopped serving blocks at height {height}, below the end \
                 height {end_height}"
            )));
        }
        fetcher.advance(page.blocks.len());
        for (hash, joinsplits) in &page.blocks {
            if height > end_height {
                break;
            }
            if !agrees_with_checkpoints(network, height, *hash) {
                return Err(build_error(format!(
                    "the block the node served at height {height} does not match the \
                     pinned checkpoint. The node is on a different chain; nothing past the \
                     last complete chunk was kept."
                )));
            }
            writer.push(height, hash, joinsplits)?;
            height += 1;
            if writer.is_full() {
                done.push(writer.finish()?);
                index += 1;
                match chunk_range(index, end_height) {
                    Some((first, last)) => {
                        writer = ChunkWriter::create(dir, index, network, first, last)?;
                    }
                    None => return Ok(()),
                }
            }
        }
        progress(PackBuildTick::Walking {
            height: height - 1,
            end_height,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprout_pack::test_support::write_pack;

    #[test]
    fn complete_chunks_on_disk_are_found_for_resume() {
        let dir = tempfile::tempdir().unwrap();
        write_pack(dir.path(), P2pNetwork::Regtest, 150_000);
        assert_eq!(
            completed_chunks(dir.path(), P2pNetwork::Regtest, 150_000).len(),
            2
        );
        // A partial file is not a chunk.
        std::fs::remove_file(dir.path().join(crate::sprout_pack::chunk_file_name(1))).unwrap();
        assert_eq!(
            completed_chunks(dir.path(), P2pNetwork::Regtest, 150_000).len(),
            1
        );
        // A different end height changes the last chunk's range, so the old
        // last chunk is rebuilt, but the full chunks before it are reused.
        assert_eq!(
            completed_chunks(dir.path(), P2pNetwork::Regtest, 120_000).len(),
            1
        );
    }

    #[tokio::test]
    async fn a_build_with_every_chunk_present_needs_no_node() {
        let dir = tempfile::tempdir().unwrap();
        let written = write_pack(dir.path(), P2pNetwork::Regtest, 300);
        std::fs::remove_file(dir.path().join(crate::sprout_pack::MANIFEST_FILE)).unwrap();
        let built = build_pack(
            &PackBuildConfig {
                network: P2pNetwork::Regtest,
                // Never dialled: nothing is missing.
                peers: vec!["127.0.0.1:1".to_owned()],
                end_height: 300,
                out_dir: dir.path().to_owned(),
            },
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(built.manifest, written);
        assert_eq!(built.manifest_sha256, written.sha256());
    }

    #[tokio::test]
    async fn a_build_needs_a_named_node() {
        let dir = tempfile::tempdir().unwrap();
        let err = build_pack(
            &PackBuildConfig {
                network: P2pNetwork::Mainnet,
                peers: Vec::new(),
                end_height: 10,
                out_dir: dir.path().to_owned(),
            },
            |_| {},
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("at least one peer"), "{err}");
    }
}
