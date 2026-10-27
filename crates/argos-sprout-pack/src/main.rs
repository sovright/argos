//! `argos-sprout-pack`: build and verify the Sprout pack a release ships.
//!
//! A maintainer tool, not part of the `argos` CLI or the desktop app. It
//! needs a fully synced zcashd or zebrad reachable over p2p and never sees a
//! key. See `docs/sprout-pack.md` for the release procedure.
//!
//!     argos-sprout-pack build --peer 127.0.0.1:8233 --end-height 3500000 --out pack/
//!     argos-sprout-pack verify pack/

use std::{path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use argos_core::{
    p2p::wire::P2pNetwork,
    sprout_pack::{pinned_entry_source, to_hex, PackTrust, SproutPack},
    sprout_pack_build::{build_pack, PackBuildConfig, PackBuildTick},
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "argos-sprout-pack",
    about = "Build and verify the Sprout pack that lets Argos users skip the full-chain p2p walk"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for P2pNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => P2pNetwork::Mainnet,
            Network::Testnet => P2pNetwork::Testnet,
            Network::Regtest => P2pNetwork::Regtest,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Walk the chain from your own node and write a pack.
    ///
    /// Only the nodes named with --peer are dialled, never DNS seeds or
    /// public peers. Every block is checked exactly as a scan checks it
    /// (proof of work, linkage, pinned checkpoints, Merkle root). Re-running
    /// with the same --out resumes after the last complete chunk.
    Build {
        #[arg(long, value_enum, default_value = "mainnet")]
        network: Network,
        /// Your node, as host:port (zcashd or zebrad; 8233 on mainnet,
        /// 18233 on testnet). Repeatable.
        #[arg(long, required = true)]
        peer: Vec<String>,
        /// The last height the pack covers. Must be at least 1,000 blocks
        /// below the node's tip, so it can never be reorganized away.
        #[arg(long)]
        end_height: u32,
        /// Directory for the chunks and manifest.
        #[arg(long)]
        out: PathBuf,
    },
    /// Re-read every chunk, check it against the manifest, and print the
    /// manifest hash to pin.
    Verify {
        #[arg(long, value_enum, default_value = "mainnet")]
        network: Network,
        /// The pack directory.
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Build {
            network,
            peer,
            end_height,
            out,
        } => build(network.into(), peer, end_height, out).await,
        Command::Verify { network, dir } => verify(network.into(), dir),
    }
}

async fn build(
    network: P2pNetwork,
    peers: Vec<String>,
    end_height: u32,
    out: PathBuf,
) -> Result<()> {
    let started = Instant::now();
    let mut last_report = Instant::now();
    let config = PackBuildConfig {
        network,
        peers,
        end_height,
        out_dir: out.clone(),
    };
    build_pack(&config, |tick| match tick {
        PackBuildTick::Resumed {
            chunks,
            next_height,
        } => eprintln!("Reusing {chunks} complete chunk(s); continuing from height {next_height}."),
        PackBuildTick::Waiting(wait) => eprintln!("  {wait}"),
        PackBuildTick::Walking { height, end_height } => {
            if last_report.elapsed().as_secs() >= 10 || height == end_height {
                last_report = Instant::now();
                eprintln!(
                    "  walking {height}/{end_height} ({:.1}%)  {:.0?} elapsed",
                    f64::from(height) / f64::from(end_height.max(1)) * 100.0,
                    started.elapsed()
                );
            }
        }
        PackBuildTick::Summarizing { height, end_height } => {
            eprintln!("  checking chunks {height}/{end_height}")
        }
    })
    .await
    .context("building the pack")?;
    println!("Pack written to {}", out.display());
    print_summary(&SproutPack::open_for_inspection(&out, network)?);
    Ok(())
}

fn verify(network: P2pNetwork, dir: PathBuf) -> Result<()> {
    let pack = SproutPack::open_for_inspection(&dir, network)
        .with_context(|| format!("opening {}", dir.display()))?;
    let end = pack.end_height();
    let mut last_report = Instant::now();
    pack.verify_all(|height| {
        if last_report.elapsed().as_secs() >= 10 {
            last_report = Instant::now();
            eprintln!("  checked {height}/{end}");
        }
    })
    .context("verifying the pack")?;
    println!("Every chunk matches the manifest, and the chunks rebuild its Sprout tree root.");
    print_summary(&pack);
    Ok(())
}

fn print_summary(pack: &SproutPack) {
    let manifest = pack.manifest();
    let mut end_hash = manifest.end_hash;
    // Explorers and RPCs print block hashes reversed relative to the wire.
    end_hash.reverse();
    let mut root = manifest.sprout_root;
    root.reverse();
    println!();
    println!("  manifest SHA-256   {}", to_hex(&pack.manifest_sha256()));
    println!("  end height         {}", manifest.end_height);
    println!("  end block hash     {}", to_hex(&end_hash));
    println!(
        "  Sprout tree root   {} (as z_gettreestate prints it)",
        to_hex(&root)
    );
    println!("  JoinSplits         {}", manifest.total_joinsplits);
    println!("  chunks             {}", manifest.chunks.len());
    println!(
        "  total size         {:.2} GB",
        manifest.total_bytes() as f64 / 1e9
    );
    println!(
        "  pinned             {}",
        match pack.trust() {
            PackTrust::Pinned => "yes, in this build of Argos",
            PackTrust::Unpinned => "no",
        }
    );
    if pack.trust() == PackTrust::Unpinned {
        println!();
        println!("Once a second maintainer has built the same manifest hash from another");
        println!("node, add this to PINNED_PACKS in crates/zeck-core/src/sprout_pack.rs:");
        println!();
        println!("{}", pinned_entry_source(manifest, &pack.manifest_sha256()));
    }
}
