//! `argos-sprout-pack`: build and verify the Sprout pack a release ships.
//!
//! A maintainer tool, not part of the `argos` CLI or the desktop app. It
//! needs a fully synced zcashd or zebrad reachable over p2p and never sees a
//! user's key. See `docs/sprout-pack.md` for the release procedure.
//!
//!     argos-sprout-pack build --peer 127.0.0.1:8233 --end-height 3500000 --out pack/
//!     argos-sprout-pack verify pack/
//!     argos-sprout-pack compare --peer 127.0.0.1:8233 --pack pack/ --work-dir cmp/

use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use argos_core::{
    p2p::wire::P2pNetwork,
    sprout_pack::{pinned_entry_source, to_hex, PackTrust, SproutPack},
    sprout_pack_build::{build_pack, PackBuildConfig, PackBuildTick},
    sprout_scan_run::{self, ScanTick, SproutScanOptions},
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
    /// Scan to the pack's end height twice, once over p2p and once from the
    /// pack, and diff the results (release procedure step 4).
    ///
    /// The pack scan runs first and reads only the pack; the p2p scan then
    /// walks the chain from --peer, which it tries first, and from the
    /// built-in peers a normal scan uses. Both stop at the pack's end height.
    /// Their running digests over every JoinSplit field, in chain order, must
    /// match, and so must the saved tree root, cursor, progress,
    /// spent-nullifier set and notes. Exits non-zero on any difference.
    ///
    /// --work-dir must be new or empty: both scans start from nothing, so a
    /// result can never come from an earlier pack or an earlier run.
    ///
    /// Scans with a fixed, published key that holds no funds: the scan needs
    /// a key to trial-decrypt with. The digest, not the key, is what covers
    /// the fields that decide whether a note is found.
    Compare {
        #[arg(long, value_enum, default_value = "mainnet")]
        network: Network,
        /// Your node, as host:port, tried before the built-in peers.
        /// Repeatable.
        #[arg(long, required = true)]
        peer: Vec<String>,
        /// The pack directory. On mainnet it must be pinned in this build.
        #[arg(long)]
        pack: PathBuf,
        /// Directory for the two scans' checkpoints. Must be new or empty.
        #[arg(long)]
        work_dir: PathBuf,
    },
}

/// The key `compare` scans with. Public on purpose: it holds no funds. The
/// top four bits are clear, as a Sprout spending key requires.
const COMPARE_KEY: [u8; 32] = [0x0a; 32];

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
        Command::Compare {
            network,
            peer,
            pack,
            work_dir,
        } => compare(network.into(), peer, pack, work_dir).await,
    }
}

async fn compare(
    network: P2pNetwork,
    peers: Vec<String>,
    pack_dir: PathBuf,
    work_dir: PathBuf,
) -> Result<()> {
    let pack = if network == P2pNetwork::Mainnet {
        SproutPack::open(&pack_dir, network)
    } else {
        SproutPack::open_for_inspection(&pack_dir, network)
    }
    .with_context(|| format!("opening {}", pack_dir.display()))?;
    let end_height = pack.end_height();
    let reused = std::fs::read_dir(&work_dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    anyhow::ensure!(
        !reused,
        "{} is not empty. Use a new --work-dir: both scans must start from nothing.",
        work_dir.display()
    );
    let keys = [COMPARE_KEY];
    let checkpoint = |name: &str| {
        sprout_scan_run::checkpoint_path_for_network(&work_dir.join(name), &keys, network)
    };
    let (over_p2p, from_pack) = (checkpoint("p2p"), checkpoint("pack"));

    // The pack scan first: it reads only local files and takes minutes, so
    // a problem with it shows before the long p2p scan rather than after.
    eprintln!("Scanning heights 1 to {end_height} from the pack.");
    let pack_digest = scan_to(network, &peers, &from_pack, Some(&pack), end_height).await?;
    eprintln!("Scanning heights 1 to {end_height} over p2p.");
    let p2p_digest = scan_to(network, &peers, &over_p2p, None, end_height).await?;

    let mut differences =
        sprout_scan_run::compare_saved_scans(&over_p2p, &from_pack, network, &keys)
            .context("comparing the two scans")?;
    if p2p_digest != pack_digest {
        differences.push(format!(
            "JoinSplit digest: {} over p2p vs {} from the pack",
            to_hex(&p2p_digest),
            to_hex(&pack_digest)
        ));
    }
    println!();
    println!("  pack manifest      {}", to_hex(&pack.manifest_sha256()));
    println!("  compared heights   1 to {end_height}");
    println!("  JoinSplit digest   {}", to_hex(&pack_digest));
    if differences.is_empty() {
        println!(
            "  result             identical: every JoinSplit field, tree root, cursor, \
             progress, spent nullifiers, notes"
        );
        Ok(())
    } else {
        for difference in &differences {
            println!("  DIFFERS            {difference}");
        }
        anyhow::bail!("the pack scan and the p2p scan differ")
    }
}

async fn scan_to(
    network: P2pNetwork,
    peers: &[String],
    checkpoint: &Path,
    pack: Option<&SproutPack>,
    end_height: u32,
) -> Result<[u8; 32]> {
    let started = Instant::now();
    let mut last_report = Instant::now();
    let result = sprout_scan_run::run_sprout_scan_with_options(
        &[COMPARE_KEY],
        network,
        peers,
        None,
        checkpoint,
        SproutScanOptions {
            decrypt_from: None,
            pack,
            stop_at: Some(end_height),
            digest_joinsplits: true,
        },
        |tick: ScanTick| {
            if let Some(wait) = tick.peer_wait {
                eprintln!("  {wait}");
            } else if last_report.elapsed().as_secs() >= 10 {
                last_report = Instant::now();
                eprintln!(
                    "  scanning {}/{end_height} ({:.1}%)  {} JoinSplits  {:.0?} elapsed",
                    tick.height,
                    f64::from(tick.height) / f64::from(end_height.max(1)) * 100.0,
                    tick.joinsplits_seen,
                    started.elapsed()
                );
            }
        },
    )
    .await
    .with_context(|| format!("scanning into {}", checkpoint.display()))?;
    anyhow::ensure!(
        result.progress.last_height == end_height,
        "the scan ended at height {}, not {end_height}",
        result.progress.last_height
    );
    eprintln!(
        "  done at {end_height}: {} JoinSplits, {:.0?}",
        result.progress.joinsplits_seen,
        started.elapsed()
    );
    result
        .joinsplit_digest
        .context("the scan returned no JoinSplit digest (it was rewound)")
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
