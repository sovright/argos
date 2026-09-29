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
//!   When *every* candidate refuses there is no different peer to move to, so
//!   the scan waits that window out and makes another pass, for a bounded
//!   time, rather than failing after one (`acquire_with_retry`).
//! - A `getdata` naming a whole header page is accepted and never answered,
//!   so block requests are batched small.
//! - Peers refuse the overwhelming majority of inbound connections outright,
//!   so finding one at all means racing many.
//!
//! # Chain validation
//!
//! Every header is checked for proof of work
//! (`p2p::wire::verify_header_pow`): the Equihash solution, and that the
//! hash meets the difficulty the header claims. A peer must therefore do
//! real work per header rather than linking cheap ones together, and the
//! checkpoints bound where a forgery could start at all.
//!
//! Validated against headers this project did not construct — 160 real ones
//! from a node, with a deliberately corrupted solution required to fail, so
//! a pass cannot mean the checker accepts everything. That check matters
//! because wrong byte offsets would reject every *honest* header while
//! looking exactly like a hostile network.
//!
//! # Why the difficulty adjustment is deliberately not validated
//!
//! Four checks compose into a complete pin on mainnet, and the adjustment
//! rule adds nothing on top of them:
//!
//! 1. the first page's `prev_hash` must equal the all-zero locator, so the
//!    walk provably starts at genesis;
//! 2. every header in a page links to its predecessor;
//! 3. every page links to the previous page's last hash;
//! 4. the pinned checkpoint hashes must match at fixed heights, and past the
//!    last of them the [`TipAnchor`] learned from lightwalletd must match
//!    at its height.
//!
//! Together those pin both ends of every segment. Forging blocks between
//! two pinned points requires the forged chain's last `prev_hash` to equal
//! the real block before the next one — which requires that real block,
//! which requires its real work. No block from genesis to the anchor can be
//! inserted, omitted or substituted without breaking a hash link to a
//! pinned point. The last hundred blocks, above the anchor, rest on the
//! peer; so does everything past the last checkpoint when no anchor could
//! be had, and the user is told so.
//!
//! Implementing ZIP 208's averaging window and damping would therefore buy
//! nothing here, while being easy to get subtly wrong — and a wrong
//! difficulty rule rejects the *honest* chain, which is the failure mode
//! this module works hardest to avoid. It would matter on testnet, where
//! nothing is pinned; testnet therefore retains a stronger peer-trust
//! residual than mainnet.
//!
//! Both parameter sets are now checked against headers this project did not
//! construct: regtest's (48, 5) and mainnet's (200, 9), each with a
//! deliberately corrupted solution required to fail, so neither pass can
//! mean the verifier simply accepts everything.
//!
//! The checkpoint file is likewise unauthenticated: it carries no MAC. A
//! resumed scan always continues to the tip, but an edited cursor still
//! skips the blocks it claims were read. It is checked against the requested
//! key set, which catches the accidental case of the wrong wallet, but not a
//! deliberately edited file. A checkpoint from another network fails on its
//! first page, because no peer on this network recognises its block cursor.
//!
//! The checkpoint is also read with no network contact at all:
//! [`lookup_chain_spends`] hands its nullifier set to the wallet-file path as
//! evidence that notes were spent. That consumer is stricter — the network
//! tag is required, the embedded key set must match, and whether the walk
//! reached the tip (`complete`) is reported, not assumed. A MAC would still
//! add nothing against an attacker: marking a note spent needs a checkpoint
//! holding the wallet's exact spending keys, and the note's nullifier needs
//! its `a_sk`, which the checkpoint stores in the clear. Whoever can forge
//! the evidence can already spend the note. The residual is accidental: a
//! stale or truncated file, which `complete` and `scanned_to` make visible.
//! See `docs/THREAT_MODEL.md` T-N7.
//!
//! # Checkpointing
//!
//! The scan saves after every batch. The commitment tree is not derivable
//! from anything cheaper than re-reading every block, so losing it means
//! starting a multi-hour download again — which is exactly what the cost
//! warning promises will not happen.

use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    error::{ZeckError, ZeckResult},
    p2p::{
        block::joinsplits_in_block,
        peer::{Peer, READ_TIMEOUT},
        pool::{connect_to_any_except, PoolError, PEER_RECONNECT_DELAY},
        wire::P2pNetwork,
    },
    sprout_scan::{ScanCursor, SproutScanCheckpoint, SproutScanResult, SproutScanner},
};
use zcash_protocol::consensus::BranchId;

/// The height of the first block a walk will scan.
///
/// Height 1 for a fresh scan, not genesis. `getheaders` returns the blocks
/// *after* the locator, so an all-zero locator yields the child of genesis:
/// the peer never serves genesis itself, and an earlier comment here claiming
/// otherwise ("the all-zero locator makes the peer include genesis") was
/// simply wrong. Confirmed directly against a node — the first header of a
/// fresh walk has genesis as its `prev_hash`.
///
/// Nothing is lost by starting at 1. A Zcash genesis block holds a single
/// coinbase transaction and therefore no JoinSplit, so it contributes no
/// Sprout commitment and cannot shift a tree position.
///
/// Getting this wrong is not a missing block, it is an off-by-one in every
/// later height: the checkpoints are keyed to true heights, so calling the
/// child of genesis "height 0" makes `checkpoint_at(419_200)` fire on the
/// block at 419,199 and abort the scan against the honest chain.
fn first_scan_height(cursor: Option<ScanCursor>) -> u32 {
    cursor.map_or(1, |c| c.last_height + 1)
}

/// How often to write a checkpoint, in blocks.
///
/// Every batch would be safest and every thousand cheapest. This is sized so
/// an interrupted scan loses at most a few seconds of work while the file is
/// rewritten rarely enough not to matter.
pub const CHECKPOINT_EVERY: u64 = 500;

/// How many peers may return nothing before the scan gives up.
///
/// Bounded rather than infinite so a network where no peer will serve the
/// Sprout range fails with an explanation instead of spinning forever.
const MAX_EMPTY_REPLIES: u32 = 8;

/// How long the scan keeps trying to find a peer before it gives up.
///
/// One pass over the candidates takes seconds, and used to be the whole
/// attempt. A user lost two days to that: all 34 candidates refused, every
/// time, while the fallback nodes were healthy and simply had every inbound
/// slot taken. Slots on a full node churn constantly, so the fix is to still
/// be asking when one frees — not to ask harder.
///
/// A quarter of an hour because the unit of retry is fixed from outside: no
/// address may be re-dialled within [`PEER_RECONNECT_DELAY`], so this buys
/// six to eight passes, each against freshly resolved seeds and a fresh state
/// of every node's slot table. Much shorter leaves two or three tries, which
/// is barely better than one. Much longer stops being persistence and becomes
/// a scan that says nothing is wrong to someone whose network is actually
/// blocking port 8233 — against a scan measured in hours, fifteen minutes is
/// what a person will leave running unattended and still come back to.
pub const PEER_ACQUISITION_BUDGET: Duration = Duration::from_secs(15 * 60);

/// How often a wait is re-announced while it runs.
///
/// Two minutes behind one unchanging line looks exactly like a hang, which is
/// the impression the retry exists to remove. Often enough to read as a
/// countdown, rarely enough that the CLI does not scroll.
const WAIT_NOTICE_INTERVAL: Duration = Duration::from_secs(30);

/// How many consecutive times seed resolution may fail before the scan stops.
///
/// A DNS failure is a different fault from a busy network and must not
/// inherit its patience. Nothing about it improves by waiting out a peer's
/// reconnect window, because no peer was dialled; and its usual cause — no
/// internet, or DNS blocked — is something the user has to fix, so holding it
/// behind fifteen minutes of "retrying" would hide the one message that tells
/// them so. It is not failed instantly either: hours into a scan, a laptop
/// waking or Wi-Fi re-associating produces exactly this error for a few
/// seconds, and that should not cost the run. Hence a few quick tries, and
/// then the DNS error itself, unchanged.
const SEED_RETRY_LIMIT: u32 = 3;

/// The pause between those tries. No reconnect window applies — a failed
/// resolution never reached a peer.
const SEED_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Why the scan is waiting for a peer rather than scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerWaitReason {
    /// Every candidate refused a connection slot. Routine on a busy network.
    AllPeersBusy,
    /// The DNS seeds would not resolve. Usually this machine's connection.
    SeedsUnresolved,
    /// A peer accepted the connection and then answered nothing for a full
    /// read timeout. zcashd does exactly this with `getheaders` while it is
    /// in initial block download, which is how a user pointing `--peer` at
    /// their own still-syncing node saw Argos reconnect every thirty seconds
    /// forever and print nothing. `peer` is named so a user with several
    /// custom peers knows which to check; `named_by_user` says whether it was
    /// one of theirs, because only then is there something to go and check.
    PeerSilent { peer: String, named_by_user: bool },
}

/// The scan is alive, has no peer, and is waiting before trying again.
///
/// Carried on [`ScanTick`] so it reaches the CLI and the GUI through the
/// progress callback they already listen to, rather than a second channel
/// each would have to learn about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerWait {
    pub reason: PeerWaitReason,
    /// The number of the attempt that follows this wait; the first is 1, so
    /// this is never below 2.
    pub next_attempt: u32,
    pub retry_in: Duration,
}

/// The wording lives here so both surfaces say the same thing.
impl std::fmt::Display for PeerWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.retry_in.as_secs();
        let attempt = self.next_attempt;
        match &self.reason {
            PeerWaitReason::AllPeersBusy => write!(
                f,
                "Every Zcash peer is busy, which is normal and passes. Retrying in \
                 {secs}s (attempt {attempt})."
            ),
            PeerWaitReason::SeedsUnresolved => write!(
                f,
                "Could not look up any Zcash peers (DNS). Check the internet connection. \
                 Retrying in {secs}s (attempt {attempt})."
            ),
            // Worded for both surfaces: the CLI's --peer and the GUI's
            // "Custom peers" box name the same thing.
            PeerWaitReason::PeerSilent {
                peer,
                named_by_user: true,
            } => write!(
                f,
                "{peer}, a Zcash node you chose, accepted a connection but sent nothing \
                 for {}s. A zcashd node in initial block download (still syncing, or with \
                 a newest block more than a day old) behaves like this; check it with \
                 `zcash-cli getblockchaininfo`. Skipping it for about {} minutes and trying \
                 another peer (attempt {attempt}).",
                READ_TIMEOUT.as_secs(),
                PEER_RECONNECT_DELAY.as_secs().div_ceil(60)
            ),
            PeerWaitReason::PeerSilent {
                peer,
                named_by_user: false,
            } => write!(
                f,
                "The Zcash peer {peer} accepted a connection but sent nothing for {}s. \
                 Skipping it for about {} minutes and trying another peer (attempt \
                 {attempt}).",
                READ_TIMEOUT.as_secs(),
                PEER_RECONNECT_DELAY.as_secs().div_ceil(60)
            ),
        }
    }
}

/// Progress, reported often enough that a multi-hour run never looks stalled.
#[derive(Debug, Clone)]
pub struct ScanTick {
    pub height: u32,
    /// The best-known chain tip, for display. The scan has no fixed end — it
    /// runs until a peer reports the tip — so this can grow as it goes.
    pub target: u32,
    pub notes_found: usize,
    pub joinsplits_seen: u64,
    /// Set when this tick reports a wait for a peer rather than blocks
    /// scanned. The other fields still hold the scan's position, so a surface
    /// that ignores this shows stale-but-true progress, never garbage.
    pub peer_wait: Option<PeerWait>,
}

/// Load a scan checkpoint for exactly these keys on exactly this network.
///
/// `Ok(None)` when there is no file. Shared by the scan's resume and by
/// [`chain_spends`], so the wallet-file path trusts a checkpoint under the
/// same rules the scan does and the two cannot drift.
fn load_checkpoint(
    checkpoint_file: &Path,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<Option<SproutScanner>> {
    let Some(bytes) = read_checkpoint_file(checkpoint_file)? else {
        return Ok(None);
    };
    // Checked after the scanner loads, so a corrupt file is still
    // reported as corrupt rather than as the wrong network.
    let (tag, body) = match bytes.as_slice() {
        [NETWORK_TAGGED, tag, body @ ..] => (Some(*tag), body.to_vec()),
        _ => (None, bytes),
    };
    let checkpoint = SproutScanCheckpoint::from_bytes(body);
    let resumed = SproutScanner::resume(&checkpoint).map_err(|err| {
        ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} could not be read ({err}). Delete it to \
             start a fresh scan, or restore a good copy — it holds hours of work.",
            checkpoint_file.display()
        ))
    })?;

    // The checkpoint must be for *these* keys. The default path is
    // fingerprinted by key set, but the path is a parameter, so a
    // handed or misplaced file would otherwise be resumed silently:
    // the scan would report results for whichever keys the file
    // holds while the caller believed it scanned the ones it passed,
    // hiding one wallet's funds and touching another's key material.
    let mut wanted: Vec<[u8; 32]> = spending_keys.to_vec();
    wanted.sort_unstable();
    wanted.dedup();
    if resumed.spending_keys() != wanted {
        return Err(ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} was made for a different set of spending \
             keys. Resuming it would report that wallet's results as though they \
             were yours. Point --data-dir somewhere else, or delete the file.",
            checkpoint_file.display()
        )));
    }

    let other_network = match tag {
        Some(tag) => tag != network_tag(network),
        None => legacy_scan_end(network).is_some_and(|end| resumed.progress().last_height >= end),
    };
    if other_network {
        return Err(ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} was made on a different network. Resuming \
             it here would report that chain's notes as this one's. Point \
             --data-dir somewhere else, or delete the file.",
            checkpoint_file.display()
        )));
    }
    Ok(Some(resumed))
}

/// Read a checkpoint file. `Ok(None)` only when there is no file: any other
/// failure — permissions, I/O, a directory in its place — is an error, so a
/// scan that ran for hours never reads as one that never ran.
fn read_checkpoint_file(path: &Path) -> ZeckResult<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(ZeckError::TransactionBuild(format!(
            "reading the scan checkpoint at {}: {err}",
            path.display()
        ))),
    }
}

/// What a scan checkpoint says about spends on chain, for the wallet-file
/// path to consult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEvidence {
    /// The checkpoint this came from, so the surfaces can say which.
    pub path: PathBuf,
    /// Every nullifier the scan saw, with the transaction that revealed it
    /// where recorded (checkpoints before version 2 did not).
    pub spent: std::collections::HashMap<[u8; 32], Option<[u8; 32]>>,
    /// The height of the last block the scan read.
    pub scanned_to: u32,
    /// Whether the scan ended at the chain tip. `false` for one that stopped
    /// early — a silent peer, an interrupt — whose coverage ends at
    /// `scanned_to` however complete its file looks.
    pub complete: bool,
}

/// The outcome of looking for a scan of a key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSpendsLookup {
    /// No checkpoint at `path`: no scan of exactly these keys has run in this
    /// data directory.
    NotFound {
        path: PathBuf,
    },
    /// A checkpoint exists but has not read a block yet.
    NothingScanned {
        path: PathBuf,
    },
    Found(ScanEvidence),
}

/// Look for a full-block scan of these keys and read what it saw.
///
/// The wallet-file path only knows the spends its own wallet recorded. A
/// scan knows every nullifier on chain up to where it reached, so a note
/// spent from another copy of the wallet — invisible to the file — shows up
/// here. Read from the checkpoint `scan-sprout` itself resumes, found by the
/// same key-set fingerprint (pass [`scan_key_set`], the set the scan used).
///
/// Stricter than resume. Resume re-reads the chain from its cursor, so a
/// wrong guess costs a refused page; this is a verdict with no network
/// contact, so it requires the network tag outright rather than inferring
/// the network from height, and it checks the key set embedded in the file,
/// not only its name. It reads only the spent set and cursor
/// ([`crate::sprout_scan::read_chain_evidence`]), never rebuilding the tree or
/// the witnesses a verdict does not need.
///
/// An unreadable, untagged, wrong-network or wrong-key checkpoint is an
/// error, never `NotFound`.
pub fn lookup_chain_spends(
    data_dir: &Path,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<ChainSpendsLookup> {
    let path = checkpoint_path(data_dir, spending_keys);
    let Some(bytes) = read_checkpoint_file(&path)? else {
        return Ok(ChainSpendsLookup::NotFound { path });
    };
    let [NETWORK_TAGGED, tag, body @ ..] = bytes.as_slice() else {
        return Err(ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} does not record its network, so its spends \
             cannot be trusted for this one. It was written by an older Argos; running \
             the scan again updates it.",
            path.display()
        )));
    };
    let evidence =
        crate::sprout_scan::read_chain_evidence(&SproutScanCheckpoint::from_bytes(body.to_vec()))
            .map_err(|err| {
            ZeckError::TransactionBuild(format!(
                "the scan checkpoint at {} could not be read ({err}).",
                path.display()
            ))
        })?;
    if evidence.spending_keys != scan_key_set(spending_keys, &[]) {
        return Err(ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} was made for a different set of spending keys, \
             so it says nothing about this wallet's notes.",
            path.display()
        )));
    }
    if *tag != network_tag(network) {
        return Err(ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} was made on a different network, so its spends \
             say nothing about this one's notes.",
            path.display()
        )));
    }
    Ok(match evidence.cursor {
        None => ChainSpendsLookup::NothingScanned { path },
        Some(cursor) => ChainSpendsLookup::Found(ScanEvidence {
            path,
            spent: evidence.spent,
            scanned_to: cursor.last_height,
            complete: evidence.complete,
        }),
    })
}

/// [`lookup_chain_spends`] reduced to the nullifier set, for callers that
/// need only the verdict. `Ok(None)` when no scan has read a block.
pub fn chain_spends(
    data_dir: &Path,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<Option<crate::sprout_recovery::ChainSpends>> {
    Ok(
        match lookup_chain_spends(data_dir, network, spending_keys)? {
            ChainSpendsLookup::Found(evidence) => Some(crate::sprout_recovery::ChainSpends {
                nullifiers: evidence.spent,
                scanned_to: evidence.scanned_to,
                complete: evidence.complete,
            }),
            ChainSpendsLookup::NotFound { .. } | ChainSpendsLookup::NothingScanned { .. } => None,
        },
    )
}

/// What a cached lookup found.
enum CachedLookup {
    Found(std::sync::Arc<crate::sprout_recovery::ChainSpends>, PathBuf),
    NotFound(PathBuf),
    NothingScanned(PathBuf),
}

/// Parsed scan evidence, kept until its file changes.
///
/// Opening a wallet in the GUI asks for the scan twice — inspection, then the
/// sweep preview — and a completed mainnet scan is a spent set of millions of
/// nullifiers. The second ask is served from here. Keyed by path and network
/// and validated by the file's size and modification time, so a resumed scan
/// rewriting the checkpoint is re-read, and a deleted one is not served.
#[derive(Default)]
pub struct ChainSpendsCache {
    entries: std::sync::Mutex<Vec<CacheEntry>>,
}

struct CacheEntry {
    path: PathBuf,
    network: u8,
    stamp: Stamp,
    spends: std::sync::Arc<crate::sprout_recovery::ChainSpends>,
}

/// What identifies one version of a checkpoint file without parsing it:
/// its size, its mtime, and its last bytes. The tail is where the cursor
/// and the completion byte live, so a re-save that changes only those — a
/// scan finishing, with no new nullifiers and so the same length — is seen
/// even where mtimes are too coarse to tell two saves apart.
type Stamp = (u64, Option<std::time::SystemTime>, Vec<u8>);

/// How much of a checkpoint's end goes into its [`Stamp`].
const STAMP_TAIL: u64 = 64;

fn stamp_of(path: &Path) -> Option<Stamp> {
    use std::io::{Read, Seek, SeekFrom};
    let meta = std::fs::metadata(path).ok()?;
    let mut file = std::fs::File::open(path).ok()?;
    file.seek(SeekFrom::Start(meta.len().saturating_sub(STAMP_TAIL)))
        .ok()?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).ok()?;
    Some((meta.len(), meta.modified().ok(), tail))
}

/// A few wallets' worth: the GUI works on one at a time.
const CACHE_ENTRIES: usize = 4;

impl ChainSpendsCache {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The scan evidence for exactly these keys, parsed at most once per
    /// version of the file. `Ok(None)` when there is none to use.
    pub fn load(
        &self,
        data_dir: &Path,
        network: P2pNetwork,
        spending_keys: &[[u8; 32]],
    ) -> ZeckResult<Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>> {
        Ok(match self.lookup(data_dir, network, spending_keys)? {
            CachedLookup::Found(spends, _) => Some(spends),
            CachedLookup::NotFound(_) | CachedLookup::NothingScanned(_) => None,
        })
    }

    fn lookup(
        &self,
        data_dir: &Path,
        network: P2pNetwork,
        spending_keys: &[[u8; 32]],
    ) -> ZeckResult<CachedLookup> {
        let path = checkpoint_path(data_dir, spending_keys);
        let tag = network_tag(network);
        let stamp = stamp_of(&path);
        if let Some(stamp) = &stamp {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(hit) = entries
                .iter()
                .find(|e| e.path == path && e.network == tag && &e.stamp == stamp)
            {
                return Ok(CachedLookup::Found(hit.spends.clone(), path));
            }
        }
        Ok(
            match lookup_chain_spends(data_dir, network, spending_keys)? {
                ChainSpendsLookup::Found(evidence) => {
                    let spends = std::sync::Arc::new(crate::sprout_recovery::ChainSpends {
                        nullifiers: evidence.spent,
                        scanned_to: evidence.scanned_to,
                        complete: evidence.complete,
                    });
                    if let Some(stamp) = stamp {
                        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                        entries.retain(|e| !(e.path == path && e.network == tag));
                        if entries.len() >= CACHE_ENTRIES {
                            entries.remove(0);
                        }
                        entries.push(CacheEntry {
                            path: path.clone(),
                            network: tag,
                            stamp,
                            spends: spends.clone(),
                        });
                    }
                    CachedLookup::Found(spends, evidence.path)
                }
                ChainSpendsLookup::NotFound { path } => CachedLookup::NotFound(path),
                ChainSpendsLookup::NothingScanned { path } => CachedLookup::NothingScanned(path),
            },
        )
    }
}

static CHAIN_SPENDS_CACHE: ChainSpendsCache = ChainSpendsCache::new();

/// How much of a checkpoint to read to find its key set: the header is a
/// version byte, a tree frontier of a few kilobytes, and the keys.
const HEADER_READ_LIMIT: u64 = 1 << 20;

/// Key sets of this network's checkpoints in `data_dir` that cover every one
/// of `wanted` and more. A scan run with keys typed in beside a wallet file's
/// is keyed by the larger set, so an exact lookup misses it.
///
/// Only supersets: a checkpoint that holds every one of the wallet's
/// spending keys can only have been made by someone who can already spend
/// the wallet's funds, which is what keeps a planted checkpoint
/// self-defeating. Untagged legacy checkpoints are not evidence, as before.
fn scans_covering(data_dir: &Path, network: P2pNetwork, wanted: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    use std::io::Read;
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let tag = network_tag(network);
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with("sprout-scan-") && name.ends_with(".checkpoint")) {
            continue;
        }
        let mut head = Vec::new();
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        if file.take(HEADER_READ_LIMIT).read_to_end(&mut head).is_err() {
            continue;
        }
        let [NETWORK_TAGGED, file_tag, body @ ..] = head.as_slice() else {
            continue;
        };
        if *file_tag != tag {
            continue;
        }
        let Ok(keys) = crate::sprout_scan::read_spending_keys(body) else {
            continue;
        };
        if keys.len() > wanted.len() && wanted.iter().all(|k| keys.binary_search(k).is_ok()) {
            found.push(keys);
        }
    }
    found
}

/// What a wallet file's surfaces need from the scan: its evidence, and a
/// sentence whenever the user should know something about it.
///
/// One helper for the CLI and the GUI, so both look for exactly the key set
/// the scan fingerprints (sorted and deduplicated, via [`scan_key_set`]) and
/// both explain themselves the same way. With no scan of exactly these keys,
/// a scan of a larger set that includes all of them is used instead. It never
/// fails: a checkpoint that cannot be used is reported in the notice, and the
/// wallet file's own record stands. Parsed evidence is cached until its file
/// changes ([`ChainSpendsCache`]).
pub fn chain_spends_for_wallet(
    data_dir: &Path,
    network: P2pNetwork,
    wallet_keys: &[[u8; 32]],
) -> (
    Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>,
    Option<String>,
) {
    let keys = scan_key_set(wallet_keys, &[]);
    if keys.is_empty() {
        return (None, None);
    }
    let stopped_early = |path: &Path, spends: &crate::sprout_recovery::ChainSpends| {
        (!spends.complete).then(|| {
            format!(
                "It stopped at height {} before reaching the chain tip ({}).",
                spends.scanned_to,
                path.display()
            )
        })
    };
    match CHAIN_SPENDS_CACHE.lookup(data_dir, network, &keys) {
        Ok(CachedLookup::Found(spends, path)) => {
            let notice = stopped_early(&path, &spends)
                .map(|s| format!("Using this wallet's full-block scan. {s}"));
            (Some(spends), notice)
        }
        Ok(CachedLookup::NotFound(path)) => {
            // A scan of more keys than the wallet holds, if one covers them
            // all: the most complete, then the furthest along.
            // A covering checkpoint that cannot be used is kept and
            // reported: hours of scan work must not read as absent.
            let mut unusable = Vec::new();
            let best = scans_covering(data_dir, network, &keys)
                .into_iter()
                .filter_map(
                    |wider| match CHAIN_SPENDS_CACHE.lookup(data_dir, network, &wider) {
                        Ok(CachedLookup::Found(spends, path)) => Some((spends, path, wider.len())),
                        Ok(_) => None,
                        Err(err) => {
                            unusable.push(format!(
                                "{} ({err})",
                                checkpoint_path(data_dir, &wider).display()
                            ));
                            None
                        }
                    },
                )
                .max_by_key(|(spends, _, _)| (spends.complete, spends.scanned_to));
            match best {
                Some((spends, path, width)) => {
                    let mut notice = format!(
                        "Using the full-block scan at {}, which scanned this wallet's Sprout \
                         keys together with {} other key(s).",
                        path.display(),
                        width - keys.len()
                    );
                    if let Some(s) = stopped_early(&path, &spends) {
                        notice = format!("{notice} {s}");
                    }
                    (Some(spends), Some(notice))
                }
                None if !unusable.is_empty() => (
                    None,
                    Some(format!(
                        "A full-block scan covering this wallet's Sprout keys was found but could \
                         not be used: {}. Spent status is the wallet file's own record.",
                        unusable.join("; ")
                    )),
                ),
                None => (
                    None,
                    Some(format!(
                        "No full-block scan of this wallet's Sprout keys was found (looked for \
                         {} and any scan covering these keys in {}), so spent status is the \
                         wallet file's own record.",
                        path.display(),
                        data_dir.display()
                    )),
                ),
            }
        }
        Ok(CachedLookup::NothingScanned(path)) => (
            None,
            Some(format!(
                "A full-block scan of these keys was started ({}) but has not read a block \
                 yet, so spent status is the wallet file's own record.",
                path.display()
            )),
        ),
        Err(err) => (
            None,
            Some(format!(
                "Not using the full-block scan checkpoint: {err} Spent status is the wallet \
                 file's own record."
            )),
        ),
    }
}

/// The exact key set a scan runs with: a wallet file's Sprout keys and any
/// supplied separately, sorted and deduplicated. The checkpoint is named by
/// this set, so a caller looking for a scan must build it the same way, or a
/// scan run with an extra `--sprout-key-file`, or over a wallet holding one
/// key twice, is never found.
pub fn scan_key_set(wallet_keys: &[[u8; 32]], extra_keys: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = wallet_keys.iter().chain(extra_keys).copied().collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Where a scan's checkpoint lives for a given key set.
///
/// Keyed by a fingerprint of the spending keys, so scanning a different
/// wallet never resumes into the wrong tree — a checkpoint restored under
/// the wrong keys would hold a valid tree and find nothing, with no
/// indication why.
pub fn checkpoint_path(data_dir: &Path, spending_keys: &[[u8; 32]]) -> PathBuf {
    let fingerprint = key_set_fingerprint(spending_keys);
    data_dir.join(format!("sprout-scan-{fingerprint}.checkpoint"))
}

/// A short, stable name for a set of Sprout spending keys: the first eight
/// bytes of SHA-256 over the sorted keys, so key order does not change it.
/// Names the scan checkpoint and the sweep journal alike, so both files for
/// one wallet sit side by side and never collide with another wallet's.
pub fn key_set_fingerprint(spending_keys: &[[u8; 32]]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    // Deduplicated as well as sorted: [A, A] is the scan of [A], and must
    // name the same file.
    for key in &scan_key_set(spending_keys, &[]) {
        h.update(key);
    }
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A block near the chain tip, learned from lightwalletd rather than from
/// the peer serving the scan.
///
/// The pinned checkpoints fix the chain up to the last of them. Past it,
/// nothing did: the difficulty adjustment is deliberately not validated, so
/// a hostile peer could serve a cheap fabricated tail and hide every later
/// spend, making a migrated note read as spendable. Requiring the scan's
/// block at this height to be *this* block pins that last stretch to a
/// second, independent source.
///
/// A resumed scan already past the anchor's height cannot check it — that
/// only happens when the previous run ended within the last hundred blocks —
/// and must still reach the anchor's height before it may stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TipAnchor {
    pub height: u32,
    /// Wire byte order — what lightwalletd's `CompactBlock.hash` carries,
    /// and what the checkpoints are compared in.
    pub hash: [u8; 32],
}

/// How far below lightwalletd's tip the anchor sits: past any reorg, so an
/// honest peer and an honest lightwalletd cannot disagree about it.
pub const TIP_ANCHOR_DEPTH: u32 = 100;

/// Ask lightwalletd for a [`TipAnchor`].
///
/// Refuses a server on the wrong network: an anchor from another chain would
/// reject every honest peer.
pub async fn independent_tip_anchor(
    network: crate::ZeckNetwork,
    lightwalletd_url: &str,
) -> ZeckResult<TipAnchor> {
    use zcash_client_backend::proto::service::BlockId;

    let (mut client, _endpoint, info) =
        crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
    crate::lightwalletd::validate_lightwalletd_network(network, &info)?;
    let tip = u32::try_from(info.block_height).map_err(|_| {
        ZeckError::Lightwalletd(format!("implausible chain height {}", info.block_height))
    })?;
    let height = tip.saturating_sub(TIP_ANCHOR_DEPTH);
    let block = client
        .get_block(BlockId {
            height: u64::from(height),
            hash: vec![],
        })
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    let hash = <[u8; 32]>::try_from(block.hash.as_slice()).map_err(|_| {
        ZeckError::Lightwalletd(format!(
            "lightwalletd returned a {}-byte block hash",
            block.hash.len()
        ))
    })?;
    Ok(TipAnchor { height, hash })
}

/// What to tell the user when no [`TipAnchor`] could be had, in the words
/// both surfaces show.
pub fn unconfirmed_tip_warning(network: P2pNetwork, reason: &str) -> String {
    format!(
        "Could not confirm the chain tip with lightwalletd ({reason}). The scan still \
         runs to the tip its peer reports, but blocks past height {} are then only as \
         trustworthy as that peer.",
        network.sprout_scan_minimum_tip()
    )
}

/// Run a Sprout scan to the chain tip, resuming from `checkpoint_file` if
/// present.
///
/// `extra_peers` are raced alongside the DNS seeds, first in line.
///
/// `tip_anchor` is a block learned independently of any peer — see
/// [`independent_tip_anchor`]. The scan must reach it, and the peer's block
/// at that height must be that block, exactly as for a pinned checkpoint.
/// Pass `None` when there is none: the network's minimum tip still applies,
/// but the stretch past the last pinned checkpoint is then only as
/// trustworthy as the peer.
///
/// A saved scan is never "finished": resuming one catches up from where it
/// stopped to the current tip, so a note spent since the last run is not
/// offered as spendable.
pub async fn run_sprout_scan(
    spending_keys: &[[u8; 32]],
    network: P2pNetwork,
    extra_peers: &[String],
    tip_anchor: Option<TipAnchor>,
    checkpoint_file: &Path,
    mut progress: impl FnMut(ScanTick),
) -> ZeckResult<SproutScanResult> {
    if spending_keys.is_empty() {
        return Err(ZeckError::TransactionBuild(
            "a Sprout scan needs at least one spending key".to_owned(),
        ));
    }

    // `fetched` counts blocks, so reaching the anchor's height means having
    // fetched one past it.
    let floor = tip_anchor
        .map_or(0, |anchor| anchor.height.saturating_add(1))
        .max(network.sprout_scan_minimum_tip());

    // Resume if we can. A checkpoint that will not load is reported rather
    // than silently discarded: starting a six-hour scan over because a file
    // was quietly ignored is worse than stopping to say so.
    let mut scanner = load_checkpoint(checkpoint_file, network, spending_keys)?
        .unwrap_or_else(|| SproutScanner::new(spending_keys));

    let cursor = scanner.cursor();
    // An all-zero locator asks the peer to start from genesis.
    let locator = cursor.map_or([0u8; 32], |c| c.last_block_hash);
    // `height` is the height of the *next* block to scan, and the block being
    // scanned is checkpointed and recorded at this value before it is
    // incremented. A fresh scan begins at genesis (height 0): the all-zero
    // locator makes the peer include genesis as `headers[0]`, so the first
    // block scanned is height 0, not 1. A resumed scan continues one past the
    // last block it recorded.
    let mut height = first_scan_height(cursor);
    let mut since_checkpoint = 0u64;

    // A wait is reported as a tick at the scan's current position, so the
    // surfaces hear about it through the callback they already have.
    let waiting_tick = |scanner: &SproutScanner, height: u32, wait: PeerWait| {
        let p = scanner.progress();
        ScanTick {
            height,
            target: floor.max(height),
            notes_found: p.notes_found,
            joinsplits_seen: p.joinsplits_seen,
            peer_wait: Some(wait),
        }
    };

    let peer = connect_peer(network, extra_peers, &[], |wait| {
        progress(waiting_tick(&scanner, height, wait));
    })
    .await?;
    // Only for display: the peer's own claim is a better guess at the tip
    // than the floor, and never below where the scan already is.
    let mut target = floor.max(peer.peer_height).max(height);

    // The fetcher below is a spawned task and cannot call `progress`, which
    // is neither `Send` nor its to share. Its waits come back over this and
    // are replayed into the callback by the consumer. Unbounded because a
    // notice is a few bytes sent a handful of times per wait, and because a
    // bounded send would have the fetcher's retry timing depend on how busy
    // the consumer is.
    let (wait_tx, mut wait_rx) = tokio::sync::mpsc::unbounded_channel::<PeerWait>();

    // Fetching runs one page ahead of scanning.
    //
    // The loop used to be strictly serial: headers, then blocks, then parse
    // and trial-decrypt, with the network idle for the whole CPU phase and
    // the CPU idle for the whole download. On a scan measured in hours that
    // wastes roughly half the wall clock.
    //
    // Only fetching and page *validation* move here. Height accounting,
    // checkpoint comparison, tree appends and note discovery all stay in the
    // consumer below, in the same order, so the invariant that every
    // commitment is appended exactly once and in chain order is preserved by
    // construction rather than by argument — this task cannot reorder or drop
    // a page, because it only ever sends whole validated pages in sequence.
    //
    // Capacity 1: at most one page sits between fetch and scan, and
    // `get_blocks` already bounds a page by `MAX_BLOCKS_BYTES`.
    // `Ok(None)` is the fetcher saying it reached the chain tip. The channel
    // closing without it means the fetcher died, and must not read as done:
    // a scan that stops early reports spent notes as spendable.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ZeckResult<Option<Page>>>(1);
    let mut fetcher = PageFetcher {
        peer,
        locator,
        empty_replies: 0,
        fetched: height,
        floor,
        network,
        peers: extra_peers.to_vec(),
        silent: Vec::new(),
        silence_exclusion: PEER_RECONNECT_DELAY,
        waits: wait_tx,
    };
    // Aborted when this future is dropped, not only when it finishes.
    // Dropping the scan is how it is cancelled, and a detached fetcher would
    // otherwise outlive the cancel by however long it had left to wait for a
    // peer — up to the whole acquisition budget, holding sockets open for a
    // scan nobody is running.
    let fetch_task = AbortOnDrop(tokio::spawn(async move {
        loop {
            match fetcher.next_page().await {
                Ok(None) => continue,
                // Empty page: the chain tip (see `PageFetcher::next_page`).
                Ok(Some(page)) if page.is_empty() => {
                    let _ = tx.send(Ok(None)).await;
                    return;
                }
                Ok(Some(page)) => {
                    fetcher.fetched += page.len() as u32;
                    if tx.send(Ok(Some(page))).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    let _ = tx.send(Err(err)).await;
                    return;
                }
            }
        }
    }));

    loop {
        // Waits first: a notice still queued when its page arrives is stale,
        // and replaying it before the page means the scanning tick below is
        // what is left on screen, not a wait that has already ended.
        let page = tokio::select! {
            biased;
            Some(wait) = wait_rx.recv() => {
                progress(waiting_tick(&scanner, height, wait));
                continue;
            }
            page = rx.recv() => page,
        };
        // Every early exit saves first. The messages say "progress is saved",
        // and between checkpoints (every CHECKPOINT_EVERY blocks) that was
        // untrue: a scan stopped by a silent peer at height 1 left no file.
        let Some(page) = page else {
            save_before_stopping(&scanner, network, checkpoint_file);
            return Err(ZeckError::Broadcast(format!(
                "the block download stopped unexpectedly at height {height}, before \
                 reaching the chain tip. Progress is saved; re-run to continue."
            )));
        };
        let page = match page {
            Ok(page) => page,
            Err(err) => {
                save_before_stopping(&scanner, network, checkpoint_file);
                return Err(err);
            }
        };
        let Some(page) = page else {
            break;
        };

        // Already in header order, and already complete: `next_page`
        // assembles the page in the order the headers came in and treats a
        // missing block as a hard error, because a short page still looks
        // well-formed and would land every later commitment at the wrong
        // position. Re-deriving a hash list and a lookup map here only undid
        // that work.
        for (hash, block) in &page {
            // A pinned block must be the block we were handed. This is what
            // makes a fabricated chain pointless: cheap forged headers link
            // to each other fine, but they cannot reproduce a real mainnet
            // hash at a real height without doing the work. Checked against
            // this block's own height, before the counter advances — the
            // checkpoints are keyed by true heights (genesis = 0).
            let expected = crate::p2p::wire::checkpoint_at(network, height).or(tip_anchor
                .filter(|anchor| anchor.height == height)
                .map(|anchor| anchor.hash));
            if let Some(expected) = expected {
                if *hash != expected {
                    return Err(ZeckError::Broadcast(format!(
                        "the chain this peer served does not match Zcash at height \
                         {height}. It is serving a different or fabricated chain, so the \
                         scan stops rather than search it. Re-run to pick another peer, \
                         or pass --peer with a node you trust."
                    )));
                }
            }

            // The branch id is only consulted for pre-v5 transactions, whose
            // encoding it does not change; v5 carries its own. Sprout
            // JoinSplits exist only in v2-v4, before and after Canopy alike.
            let joinsplits = joinsplits_in_block(block, BranchId::Canopy).map_err(|err| {
                ZeckError::TransactionBuild(format!("block at height {height}: {err}"))
            })?;

            scanner
                .scan_block_at(&joinsplits, *hash, height)
                .map_err(|err| {
                    ZeckError::TransactionBuild(format!("scanning height {height}: {err}"))
                })?;
            since_checkpoint += 1;
            height += 1;
        }

        if since_checkpoint >= CHECKPOINT_EVERY {
            save_checkpoint(&scanner, network, checkpoint_file)?;
            since_checkpoint = 0;
        }

        target = target.max(height);
        let p = scanner.progress();
        progress(ScanTick {
            height,
            target,
            notes_found: p.notes_found,
            joinsplits_seen: p.joinsplits_seen,
            peer_wait: None,
        });
    }

    // The fetcher has already returned after reporting the tip; dropping it
    // is only to be certain no connection outlives the scan.
    drop(fetch_task);

    // The only place a scan is marked complete: the loop leaves only on the
    // fetcher's tip signal (`Ok(None)`). Every early exit above saves
    // without it, so its checkpoint never reads as full coverage.
    scanner.mark_complete();
    save_checkpoint(&scanner, network, checkpoint_file)?;

    scanner
        .finish()
        .map_err(|err| ZeckError::TransactionBuild(format!("finishing the scan: {err}")))
}

/// One page of blocks, in chain order.
type Page = Vec<([u8; 32], Vec<u8>)>;

/// The producer half of the scan: everything needed to pull validated pages
/// from the network, and nothing about what is done with them.
///
/// Grouped into a struct because these were seven loose parameters — three of
/// them `&mut` out-params — carried through a function that needed an
/// `#[allow(clippy::too_many_arguments)]` to exist. They are one thing: the
/// fetcher's own state.
struct PageFetcher {
    peer: crate::p2p::peer::Peer,
    locator: [u8; 32],
    empty_replies: u32,
    /// How far the *fetcher* has read. Distinct from the consumer's `height`,
    /// which is the authority for checkpoints and tree positions.
    fetched: u32,
    /// Below this, an empty reply is not the tip. See `run_sprout_scan`.
    floor: u32,
    network: P2pNetwork,
    peers: Vec<String>,
    /// Peers that accepted a connection and then answered nothing, each with
    /// the time it may be dialled again. Such a peer handshakes fastest of
    /// all, so without this it wins every reconnect and is asked forever. Not
    /// permanent: one stall on the only node a user can reach must not cost
    /// them the rest of an hours-long scan.
    silent: Vec<(String, tokio::time::Instant)>,
    /// How long a silent peer is skipped. `PEER_RECONNECT_DELAY` outside
    /// tests: the node would refuse an earlier redial from this IP anyway.
    silence_exclusion: Duration,
    /// Where a wait for a peer is announced; see `run_sprout_scan`.
    waits: tokio::sync::mpsc::UnboundedSender<PeerWait>,
}

impl PageFetcher {
    /// Replace the peer, announcing any wait that takes.
    ///
    /// A failed send means the consumer has gone, and the page send that
    /// follows will notice that and end the task; nothing to do about it here.
    ///
    /// The current connection is closed first. Assigning the new peer would
    /// drop it only after the replacement had been dialled and handshaken, and
    /// a Zebra node — the fallback nodes are always candidates — drops a
    /// second connection from an IP it already has one from, so the scan
    /// would be refused by the very node it was using. If no replacement is
    /// found the closed peer is never used again: every caller ends the scan
    /// on this error.
    async fn reconnect(&mut self) -> ZeckResult<()> {
        self.peer.close().await;
        let waits = &self.waits;
        self.peer = connect_peer(self.network, &self.peers, &self.silent, |wait| {
            let _ = waits.send(wait);
        })
        .await?;
        Ok(())
    }

    /// Rotate to another peer, charging this failure against the budget.
    ///
    /// One implementation of the retry rule, which existed three times over,
    /// identical but for the message — the shape where one copy gets a fix and
    /// the others do not. Returns `Ok(None)` to mean "try again with the new
    /// peer"; the budget being exhausted is the error.
    ///
    /// Reconnecting to the same peer would be refused for the next two minutes
    /// regardless, so a rotation always takes a different one.
    async fn rotate(&mut self, exhausted: String) -> ZeckResult<Option<Page>> {
        self.reconnect().await?;
        self.empty_replies += 1;
        if self.empty_replies > MAX_EMPTY_REPLIES {
            return Err(ZeckError::Broadcast(exhausted));
        }
        Ok(None)
    }

    /// Handle a request that failed.
    ///
    /// Every failure is charged against the same budget as an empty reply,
    /// which resets only once a whole page has been delivered. It used to be
    /// free, and then reset after `getheaders` but before `getdata`, so a
    /// peer that answers headers and never delivers bodies — a node in
    /// initial block download — could keep the scan retrying forever.
    ///
    /// Only genuine silence (`PeerError::Silent`) is announced as such and
    /// skips the peer for a while. A peer that sent too much, or kept
    /// talking without answering, is working, and is rotated away from
    /// without being told it is in initial block download.
    async fn on_request_failure(
        &mut self,
        err: crate::p2p::peer::PeerError,
        height: u32,
    ) -> ZeckResult<Option<Page>> {
        if !matches!(err, crate::p2p::peer::PeerError::Silent { .. }) {
            let last = format!("{err}");
            return self
                .rotate(format!(
                    "{} attempts in a row to fetch blocks from height {height} failed; the \
                     most recent: {last}. Progress is saved; re-run to continue.",
                    self.empty_replies + 1
                ))
                .await;
        }
        let peer = self.peer.dialled_as().to_owned();
        let named_by_user = self.peers.contains(&peer);
        let until = tokio::time::Instant::now() + self.silence_exclusion;
        self.silent.retain(|(addr, _)| *addr != peer);
        self.silent.push((peer.clone(), until));
        self.empty_replies += 1;
        let _ = self.waits.send(PeerWait {
            reason: PeerWaitReason::PeerSilent {
                peer: peer.clone(),
                named_by_user,
            },
            next_attempt: self.empty_replies + 1,
            retry_in: Duration::ZERO,
        });
        if self.empty_replies > MAX_EMPTY_REPLIES {
            return Err(ZeckError::Broadcast(silence_explained(
                height,
                self.empty_replies,
                &peer,
                named_by_user,
            )));
        }
        match self.reconnect().await {
            Ok(()) => Ok(None),
            // The pool's own reason leads: it is what actually stopped the
            // scan, and may be this machine's connection rather than the peer.
            Err(err) => Err(ZeckError::Broadcast(format!(
                "no other Zcash peer could be reached from height {height}: {}. This \
                 began when {peer} stopped answering.{} Progress is saved; re-run to \
                 continue.",
                // The pool's sentence ends in its own full stop.
                err.to_string().trim_end_matches('.'),
                own_node_hint(named_by_user)
            ))),
        }
    }

    /// Fetch and validate one page of blocks.
    ///
    /// `Ok(None)` means "this peer was no good; a new one is connected, try
    /// again" — the caller loops. An empty page means the chain tip was
    /// reached (see `empty_reply_is_chain_tip`). Every check that decides
    /// whether a page may be scanned at all lives here: proof of work,
    /// continuity with the locator, and the internal linkage of the page.
    ///
    /// What deliberately does *not* live here is anything positional —
    /// checkpoint comparison and the tree append stay with the consumer, keyed
    /// on the true height, so this cannot affect where a commitment lands.
    async fn next_page(&mut self) -> ZeckResult<Option<Page>> {
        let height = self.fetched;

        let headers = match self.peer.get_headers(&[self.locator]).await {
            Ok(h) if !h.is_empty() => h,
            // Only the tip if every tip height we know of has been reached;
            // see `empty_reply_is_chain_tip` for why stopping short is the
            // worst failure here.
            Ok(_) => {
                if crate::p2p::wire::empty_reply_is_chain_tip(
                    height,
                    self.floor,
                    self.peer.peer_height,
                ) {
                    return Ok(Some(Vec::new()));
                }
                let floor = self.floor.max(self.peer.peer_height);
                return self
                    .rotate(format!(
                        "no peer would serve blocks past height {height}, but the chain \
                         reaches at least {floor}. The scan is incomplete and its results \
                         would be wrong, so it stops here rather than reporting a balance \
                         it cannot stand behind. Progress is saved; re-run to continue."
                    ))
                    .await;
            }
            Err(err) => return self.on_request_failure(err, height).await,
        };

        // An honest page is at most MAX_PAGE_BLOCKS; a hostile `headers` reply
        // can list thousands, and every one named here is a body fetched
        // into memory. The rest simply arrive on the next page.
        let mut headers = headers;
        headers.truncate(crate::p2p::peer::MAX_PAGE_BLOCKS);

        // Every header must carry its own proof of work. With the checkpoints
        // bounding where a forgery can start, this bounds how cheaply one can
        // be built in between: a peer must do real work per header, not merely
        // link cheap ones together.
        if headers
            .iter()
            .any(|h| crate::p2p::wire::verify_header_pow(self.network, h).is_err())
        {
            return self
                .rotate(format!(
                    "no peer would serve headers with valid proof of work from height \
                     {height}. The scan stops rather than walk a chain it cannot verify."
                ))
                .await;
        }

        // The peer must be continuing from exactly where we asked, and the
        // page must itself be a chain. A peer that does not recognise the
        // locator serves from genesis, which would re-append the whole prefix
        // into a tree that already contains it; a peer starting partway would
        // skip the blocks before it. Either silently shifts every later
        // commitment position.
        //
        // A fresh walk cannot check the first link, because there is nothing
        // to check it against: `getheaders` serves the blocks *after* the
        // locator, and an all-zero locator is not a block hash, so
        // `headers[0]` is the child of genesis and its `prev_hash` is the
        // genesis hash. Requiring it to equal the locator rejected every fresh
        // scan's first page.
        //
        // This is deliberately not the old `height > 0` guard, which skipped
        // the check whenever the counter happened to be zero and so accepted a
        // first page starting anywhere. The relaxation is tied to the locator
        // being the all-zero sentinel, true exactly once, on the first page of
        // a fresh walk.
        let fresh_walk = self.locator == [0u8; 32];
        let first_link_ok = fresh_walk || headers[0].prev_hash == self.locator;
        if !first_link_ok || !headers.windows(2).all(|w| w[1].prev_hash == w[0].hash) {
            // Charged against the same budget as an empty reply: a peer that
            // answers with an unusable page is no more useful than one that
            // answers with nothing, and without this the scan switches peers
            // forever rather than stopping with an explanation.
            return self
                .rotate(format!(
                    "no peer would serve a usable chain of blocks from height {height}. \
                     The scan is incomplete and its results would be wrong, so it stops \
                     here. Progress is saved; re-run to continue."
                ))
                .await;
        }
        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        let mut blocks = match self.peer.get_blocks(&hashes).await {
            Ok(b) => b,
            Err(err) => return self.on_request_failure(err, height).await,
        };

        // Assembled in header order, so the consumer receives the page already
        // in chain order and never has to trust the peer's reply order.
        //
        // A missing block is a hard error, not a gap. Filtering it out would
        // hand the consumer a shorter page that still looks well-formed, and
        // every commitment after it would land at the wrong position — the
        // scan would finish clean and the notes would be unspendable.
        let mut page: Page = Vec::with_capacity(hashes.len());
        for (offset, hash) in hashes.iter().enumerate() {
            let Some(block) = blocks.remove(hash) else {
                return Err(ZeckError::Broadcast(format!(
                    "a peer did not return the block at height {}. The scan cannot skip \
                     it without corrupting every later note, so it stops. Progress is \
                     saved; re-run to continue.",
                    height + offset as u32
                )));
            };
            page.push((*hash, block));
        }

        self.locator = *hashes.last().expect("non-empty");
        // Only here, with a whole page in hand: resetting any earlier let a
        // peer that answers `getheaders` but never `getdata` reset the budget
        // between every failure, so it never ran out.
        self.empty_replies = 0;
        Ok(Some(page))
    }
}

/// Why a scan stopped after its failure budget ran out, the last failure
/// being silence. Says only what is known: the count covers every kind of
/// failure, and only the most recent is known to have been silence.
fn silence_explained(height: u32, attempts: u32, peer: &str, named_by_user: bool) -> String {
    format!(
        "{attempts} attempts in a row to fetch blocks from height {height} failed; the most \
         recent, {peer}, accepted a connection and then sent nothing for {}s.{} Progress is \
         saved; re-run to continue.",
        READ_TIMEOUT.as_secs(),
        own_node_hint(named_by_user)
    )
}

/// The initial-block-download hint, offered only when the silent peer is one
/// the user chose: only then is there a node of theirs to go and check.
fn own_node_hint(named_by_user: bool) -> &'static str {
    if named_by_user {
        " If that is your own zcashd node, it may be in initial block download (still \
         syncing, or with a newest block more than a day old); check it with `zcash-cli \
         getblockchaininfo`, or leave it out to use public peers."
    } else {
        ""
    }
}

/// Write a checkpoint.
///
/// # This file is spend-capable
///
/// It holds raw Sprout spending keys and note plaintexts — everything needed
/// to move the funds. It is therefore created 0600 rather than left to the
/// umask, the same treatment the recovery report gets. Callers should say so
/// to the user before pointing them at the path, and delete it once the
/// funds are swept.
pub fn save_checkpoint(
    scanner: &SproutScanner,
    network: P2pNetwork,
    path: &Path,
) -> ZeckResult<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Written to a temporary file and renamed, so an interrupt during the
    // write cannot leave a half-written checkpoint where a good one was —
    // that would turn a recoverable pause into a restart from genesis.
    let tmp = path.with_extension("checkpoint.tmp");
    // Removed first: `mode(0600)` applies only to files this call *creates*,
    // so writing into a leftover 0644 temporary from an earlier version
    // would put spend-capable bytes in a world-readable inode and then
    // rename that inode into place.
    let _ = std::fs::remove_file(&tmp);
    let mut bytes = vec![NETWORK_TAGGED, network_tag(network)];
    bytes.extend_from_slice(scanner.checkpoint().as_bytes());
    write_private(&tmp, &bytes)?;
    std::fs::rename(&tmp, path).map_err(|err| {
        ZeckError::TransactionBuild(format!("replacing the scan checkpoint: {err}"))
    })?;
    Ok(())
}

/// Save on the way out of a failed scan, so the saved-progress claim in its
/// error holds. A failure to save is logged, not raised: the scan's own
/// error is the one the user needs to see.
fn save_before_stopping(scanner: &SproutScanner, network: P2pNetwork, path: &Path) {
    if let Err(err) = save_checkpoint(scanner, network, path) {
        tracing::warn!("could not save the Sprout scan checkpoint while stopping: {err}");
    }
}

/// Leads a checkpoint file that records its network, followed by that
/// network's tag and then the scanner's own bytes. Distinct from every
/// `SproutScanner` checkpoint version, so the two cannot be mistaken.
///
/// The scanner itself stays network-agnostic; the network is this module's
/// to know, so it is recorded here. Needed since the scan stopped having a
/// fixed end: a cursor from a longer chain used to be caught by exceeding
/// this network's range, and now could read as the tip of a shorter one.
const NETWORK_TAGGED: u8 = 0xA5;

fn network_tag(network: P2pNetwork) -> u8 {
    match network {
        P2pNetwork::Mainnet => 1,
        P2pNetwork::Testnet => 2,
        P2pNetwork::Regtest => 3,
    }
}

/// Where each network's scan used to stop. Every checkpoint without a
/// network tag was written by one of those scans, so its cursor cannot be
/// past this height on the network that wrote it.
const fn legacy_scan_end(network: P2pNetwork) -> Option<u32> {
    match network {
        P2pNetwork::Mainnet => Some(1_046_400),
        P2pNetwork::Testnet => Some(1_028_500),
        P2pNetwork::Regtest => None,
    }
}

/// Create at 0600 and write, so a spend-capable file is never briefly
/// world-readable between creation and a later chmod.
fn write_private(path: &Path, bytes: &[u8]) -> ZeckResult<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        ZeckError::TransactionBuild(format!("creating {}: {err}", path.display()))
    })?;
    file.write_all(bytes).map_err(|err| {
        ZeckError::TransactionBuild(format!("writing the scan checkpoint: {err}"))
    })?;
    Ok(())
}

/// Delete a checkpoint and its temporary sibling.
///
/// Called once the funds it describes have been swept: it holds spending
/// keys, and leaving it behind is a standing risk for no remaining benefit.
pub fn discard_checkpoint(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("checkpoint.tmp"));
}

/// Take a peer, racing candidates.
///
/// There is deliberately no "avoid the peer that just failed" list: an
/// earlier version carried one and never used it, which made the module's
/// claim about rotating away from a refusing peer fiction. `connect_to_any`
/// races a fresh batch each round, so a peer inside its 119-second window
/// simply loses the race rather than being excluded by name.
///
/// That holds *within* a pass. Across passes there is still no list, because
/// none is needed: when a whole pass is refused, [`acquire_with_retry`] waits
/// out the reconnect window before the next one, so by the time any address
/// is dialled again every peer has forgotten the last attempt. The window is
/// respected by the clock rather than by bookkeeping per address.
///
/// `on_wait` hears about each such wait, so the caller can show that the scan
/// is alive and waiting on purpose.
async fn connect_peer(
    network: P2pNetwork,
    extra: &[String],
    excluded: &[(String, tokio::time::Instant)],
    on_wait: impl FnMut(PeerWait),
) -> ZeckResult<Peer> {
    // Regtest gets no patience. Its only candidates are the addresses the
    // caller named, there is no public capacity to free up, and a refusal
    // means the node is down — which a test should learn at once, not after
    // a quarter of an hour.
    let budget = if matches!(network, P2pNetwork::Regtest) {
        Duration::ZERO
    } else {
        PEER_ACQUISITION_BUDGET
    };
    // `connect_to_any` resolves the seeds itself, so each pass re-resolves
    // them. That matters: the seeders rotate what they hand out, so a later
    // pass is not just the same refusals again but partly different peers.
    //
    // Exclusions are re-read on every pass, so a silent peer whose skip has
    // expired is back in the running during a long wait rather than only on
    // the next reconnect.
    acquire_with_retry(
        budget,
        || {
            let now = tokio::time::Instant::now();
            let active: Vec<String> = excluded
                .iter()
                .filter(|(_, until)| now < *until)
                .map(|(addr, _)| addr.clone())
                .collect();
            async move { connect_to_any_except(network, extra, &active, 4).await }
        },
        on_wait,
    )
    .await
    .map_err(ZeckError::from)
}

/// Keep making passes at the network until one yields a peer or `budget` is
/// spent.
///
/// Generic over the dial so the policy — which is all timing — can be tested
/// under a paused clock with no network, and over `T` for the same reason.
///
/// # The two retryable faults are not treated alike
///
/// *Every peer refused* is the routine one, and is retried for the whole
/// budget, one pass per [`PEER_RECONNECT_DELAY`]. Sooner would be worse than
/// useless: a peer drops a second connection from the same address inside
/// that window silently and before the handshake, so an eager retry is
/// guaranteed to fail and indistinguishable from a dead network. The wait
/// starts when the pass *ends*, so every address in it — first round or
/// last — has had at least the full window.
///
/// *No seed resolved* gets [`SEED_RETRY_LIMIT`] quick tries and then fails
/// as itself; see that constant for why. The count is of consecutive
/// failures, so a blip hours into a scan does not inherit strikes from one
/// hours earlier.
///
/// Anything else is returned untouched. The match is on the two variants
/// this policy understands with a catch-all beside them, so a fault added to
/// [`PoolError`] later fails fast by default rather than being silently
/// waited on.
///
/// # Cancellation
///
/// Nothing here outlives its caller: the waits are plain sleeps in this
/// future, so dropping it stops the retry mid-wait.
async fn acquire_with_retry<T, F, Fut>(
    budget: Duration,
    mut dial: F,
    mut on_wait: impl FnMut(PeerWait),
) -> Result<T, PoolError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, PoolError>>,
{
    let started = tokio::time::Instant::now();
    let mut next_attempt = 1u32;
    let mut seed_failures = 0u32;

    loop {
        let err = match dial().await {
            Ok(found) => return Ok(found),
            Err(err) => err,
        };
        next_attempt += 1;

        let (reason, delay) = match &err {
            // Only if the wait fits: a wait that ends past the budget would
            // make the bound a suggestion.
            PoolError::AllPeersRefused { .. }
                if started.elapsed() + PEER_RECONNECT_DELAY <= budget =>
            {
                seed_failures = 0;
                (PeerWaitReason::AllPeersBusy, PEER_RECONNECT_DELAY)
            }
            PoolError::NoSeedsResolved(_)
                if seed_failures + 1 < SEED_RETRY_LIMIT
                    && started.elapsed() + SEED_RETRY_DELAY <= budget =>
            {
                seed_failures += 1;
                (PeerWaitReason::SeedsUnresolved, SEED_RETRY_DELAY)
            }
            _ => return Err(err),
        };

        // Slept in slices so the wait can be re-announced as a countdown.
        let mut remaining = delay;
        while !remaining.is_zero() {
            on_wait(PeerWait {
                reason: reason.clone(),
                next_attempt,
                retry_in: remaining,
            });
            let slice = remaining.min(WAIT_NOTICE_INTERVAL);
            tokio::time::sleep(slice).await;
            remaining -= slice;
        }
    }
}

/// Aborts a spawned task when dropped.
///
/// A `JoinHandle` detaches on drop, which is the wrong default for a task
/// that only makes sense while its parent future is alive.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer that completes the handshake and then answers nothing — what
    /// a zcashd node in initial block download does with `getheaders`. It
    /// advertises a height well past anything a regtest scan would need, as
    /// the reporter's node did.
    async fn silent_peer() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer_handshake_only(stream));
            }
        });
        addr
    }

    /// Complete the handshake on `stream` and ignore everything after it,
    /// returning once the client has closed the connection.
    async fn answer_handshake_only(mut stream: tokio::net::TcpStream) {
        use crate::p2p::wire::{encode_message, encode_version};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut header = [0u8; 24];
        while stream.read_exact(&mut header).await.is_ok() {
            let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).await.is_err() {
                return;
            }
            if header[4..11] == *b"version" {
                let version = encode_version(170_160, "/MagicBean:6.20.0/", 3_500_000, 1, 0);
                let _ = stream
                    .write_all(&encode_message(P2pNetwork::Regtest, "version", &version))
                    .await;
                let _ = stream
                    .write_all(&encode_message(P2pNetwork::Regtest, "verack", &[]))
                    .await;
            }
            // Everything else, `getheaders` included, is ignored.
        }
    }

    /// A peer that notes, for each connection after the first, whether the
    /// one before it had already been closed when this one arrived — the
    /// fact Zebra's one-inbound-connection-per-IP rule turns on.
    ///
    /// "Already closed" allows a short grace for the close to be read, so the
    /// check measures the order of close and dial rather than which task the
    /// scheduler happened to run first. Without the fix the old connection
    /// stays open until the new handshake completes, which this peer holds
    /// back until the grace has expired, so no grace can hide the bug.
    async fn one_connection_per_ip_peer() -> (String, std::sync::Arc<std::sync::Mutex<Vec<bool>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            let mut previous: Option<tokio::sync::oneshot::Receiver<()>> = None;
            while let Ok((stream, _)) = listener.accept().await {
                if let Some(closed) = previous.take() {
                    let was_closed = tokio::time::timeout(Duration::from_millis(500), closed)
                        .await
                        .is_ok();
                    record.lock().unwrap().push(was_closed);
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                previous = Some(rx);
                tokio::spawn(async move {
                    answer_handshake_only(stream).await;
                    let _ = tx.send(());
                });
            }
        });
        (addr, seen)
    }

    /// The reported failure: "Every Zcash peer is busy" after every page.
    ///
    /// Zebra keeps one inbound connection per IP and drops a second one after
    /// the handshake. The Sovright fallback nodes are always candidates, so a
    /// replacement dialled while the current connection is still open is very
    /// likely to reach the node already in use, which then refuses it as a
    /// duplicate. The current connection must be closed before any dial.
    #[tokio::test]
    async fn reconnect_closes_the_current_connection_before_dialling() {
        let (addr, seen) = one_connection_per_ip_peer().await;
        let peers = vec![addr];
        let peer = connect_peer(P2pNetwork::Regtest, &peers, &[], |_| {})
            .await
            .unwrap();
        let (waits, _waits_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut fetcher = PageFetcher {
            peer,
            locator: [0; 32],
            empty_replies: 0,
            fetched: 0,
            floor: 0,
            network: P2pNetwork::Regtest,
            peers,
            silent: Vec::new(),
            silence_exclusion: PEER_RECONNECT_DELAY,
            waits,
        };

        fetcher.reconnect().await.unwrap();

        assert_eq!(
            *seen.lock().unwrap(),
            vec![true],
            "the old connection was still open when its replacement was dialled"
        );
    }

    /// The reported failure: Argos connected to the user's own node every
    /// thirty seconds, forever, printing nothing. A silent peer must be
    /// named in the progress, dropped, and — when nothing else is left —
    /// end the scan with an explanation rather than spin.
    #[tokio::test]
    async fn a_peer_that_never_answers_is_reported_and_not_asked_again() {
        let peer = silent_peer().await;
        // Per process: two `cargo test` runs on one machine must not delete
        // each other's checkpoint mid-run.
        let dir = std::env::temp_dir().join(format!(
            "argos-scan-silent-peer-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("silent.checkpoint");
        discard_checkpoint(&path);

        let mut notices = Vec::new();
        let outcome = tokio::time::timeout(
            READ_TIMEOUT * 3,
            run_sprout_scan(
                &[[0x11; 32]],
                P2pNetwork::Regtest,
                std::slice::from_ref(&peer),
                None,
                &path,
                |tick| {
                    if let Some(wait) = tick.peer_wait {
                        notices.push(wait);
                    }
                },
            ),
        )
        .await
        .expect("a silent peer must not stall the scan indefinitely");
        // The error says progress is saved, so a file must exist even
        // though the scan stopped before its first CHECKPOINT_EVERY blocks.
        let saved = path.exists();
        discard_checkpoint(&path);

        let err = outcome.expect_err("a scan whose only peer is silent cannot succeed");
        let text = err.to_string();
        assert!(text.contains("stopped answering"), "{text}");
        assert!(text.contains(&peer), "the silent peer is named: {text}");
        assert!(text.contains("initial block download"), "{text}");
        assert!(
            saved,
            "an aborted scan must leave the checkpoint it claims to"
        );
        assert!(
            notices.iter().any(|w| w.reason
                == PeerWaitReason::PeerSilent {
                    peer: peer.clone(),
                    named_by_user: true
                }),
            "the silence must reach the progress callback: {notices:?}"
        );
    }

    /// The budget must actually run out. With one candidate the scan ended
    /// through "no other peer", so the budget itself was never reached and
    /// setting it to u32::MAX failed no test. Ten silent peers exhaust it.
    #[tokio::test]
    async fn the_failure_budget_runs_out_across_silent_peers() {
        let mut peers = Vec::new();
        for _ in 0..(MAX_EMPTY_REPLIES + 2) {
            peers.push(silent_peer().await);
        }
        let dir =
            std::env::temp_dir().join(format!("argos-scan-budget-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("budget.checkpoint");
        discard_checkpoint(&path);

        let mut silences = 0u32;
        let outcome = tokio::time::timeout(
            READ_TIMEOUT * (MAX_EMPTY_REPLIES + 4),
            run_sprout_scan(
                &[[0x11; 32]],
                P2pNetwork::Regtest,
                &peers,
                None,
                &path,
                |tick| {
                    if matches!(
                        tick.peer_wait.map(|w| w.reason),
                        Some(PeerWaitReason::PeerSilent { .. })
                    ) {
                        silences += 1;
                    }
                },
            ),
        )
        .await
        .expect("the budget must end the scan");
        discard_checkpoint(&path);

        let text = outcome.expect_err("every peer is silent").to_string();
        assert_eq!(silences, MAX_EMPTY_REPLIES + 1, "{text}");
        assert!(
            text.contains(&format!("{} attempts in a row", MAX_EMPTY_REPLIES + 1)),
            "{text}"
        );
        // Only the last failure is known to be silence; the count is not
        // claimed to be N silent peers.
        assert!(text.contains("the most recent"), "{text}");
    }

    /// A silent peer is skipped for a while, not for the rest of the run:
    /// a user whose only reachable node stalls once must get it back.
    #[tokio::test]
    async fn a_silent_peer_is_dialled_again_once_its_skip_expires() {
        let peer = silent_peer().await;
        let peers = vec![peer.clone()];
        let now = tokio::time::Instant::now();

        let skipped = [(peer.clone(), now + Duration::from_secs(60))];
        assert!(
            connect_peer(P2pNetwork::Regtest, &peers, &skipped, |_| {})
                .await
                .is_err(),
            "while its skip lasts the peer is not dialled"
        );

        let expired = [(peer.clone(), now - Duration::from_millis(1))];
        connect_peer(P2pNetwork::Regtest, &peers, &expired, |_| {})
            .await
            .expect("an expired skip admits the peer again");
    }

    /// A peer that sent too much, or kept talking without answering, is
    /// working: it is rotated away from, but not skipped, and not reported
    /// as silent or in initial block download.
    #[tokio::test]
    async fn a_failure_that_is_not_silence_neither_skips_nor_blames_the_peer() {
        let peer = silent_peer().await;
        let peers = vec![peer.clone()];
        let first = connect_peer(P2pNetwork::Regtest, &peers, &[], |_| {})
            .await
            .unwrap();
        let (waits, mut waits_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut fetcher = PageFetcher {
            peer: first,
            locator: [0; 32],
            empty_replies: 0,
            fetched: 0,
            floor: 0,
            network: P2pNetwork::Regtest,
            peers,
            silent: Vec::new(),
            silence_exclusion: PEER_RECONNECT_DELAY,
            waits,
        };

        let outcome = fetcher
            .on_request_failure(crate::p2p::peer::PeerError::Oversized { mb: 400 }, 0)
            .await
            .expect("one failure is within the budget");
        assert!(outcome.is_none(), "rotate and try again");
        assert!(
            fetcher.silent.is_empty(),
            "not skipped: {:?}",
            fetcher.silent
        );
        assert_eq!(fetcher.empty_replies, 1, "but charged");
        assert!(waits_rx.try_recv().is_err(), "and not announced as silence");
    }

    #[test]
    fn a_silent_peer_notice_says_why_and_what_happens_next() {
        let named = PeerWait {
            reason: PeerWaitReason::PeerSilent {
                peer: "127.0.0.1:8233".to_owned(),
                named_by_user: true,
            },
            next_attempt: 2,
            retry_in: Duration::ZERO,
        }
        .to_string();
        // Names the node, and words it for both surfaces: the GUI has no
        // --peer flag, only a "Custom peers" box.
        assert!(named.contains("127.0.0.1:8233"), "{named}");
        assert!(!named.contains("--peer"), "{named}");
        assert!(named.contains("initial block download"), "{named}");
        assert!(named.contains("Skipping it for about"), "{named}");

        let public = PeerWait {
            reason: PeerWaitReason::PeerSilent {
                peer: "203.0.113.9:8233".to_owned(),
                named_by_user: false,
            },
            next_attempt: 2,
            retry_in: Duration::ZERO,
        }
        .to_string();
        assert!(public.contains("203.0.113.9:8233"), "{public}");
        assert!(!public.contains("initial block download"), "{public}");
    }

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

    /// Every block must be counted at its true height.
    ///
    /// The checkpoints are keyed by true block heights and the walk records a
    /// block at `height` before incrementing, so a counter that starts one off
    /// shifts every block and rejects the honest chain at the first checkpoint
    /// (419,200) — the failure this test exists to prevent, and it still does.
    ///
    /// It previously asserted 0, on the premise that a fresh walk scans
    /// genesis. It does not: `getheaders` serves the blocks *after* the
    /// locator, so an all-zero locator returns the child of genesis and the
    /// peer never sends genesis at all. Checked directly against a node. So
    /// the first block a fresh walk actually receives is height 1, and
    /// starting the counter at 0 mislabelled it — the same off-by-one this
    /// test guards against, in the other direction, and it made every fresh
    /// scan abort on its first page.
    ///
    /// No commitment is lost: a Zcash genesis block is a single coinbase
    /// transaction with no JoinSplit, so it contributes nothing to the tree.
    #[test]
    fn a_fresh_walk_counts_its_first_block_as_height_one() {
        assert_eq!(first_scan_height(None), 1);

        let just_below_the_first_checkpoint = ScanCursor {
            last_block_hash: [0xAB; 32],
            last_height: 419_199,
        };
        assert_eq!(
            first_scan_height(Some(just_below_the_first_checkpoint)),
            419_200
        );
    }

    fn all_refused() -> PoolError {
        PoolError::AllPeersRefused {
            tried: 34,
            refused: 34,
            timed_out: 0,
            other: 0,
            fallback_refused: 4,
        }
    }

    /// The failure this exists for: every candidate refused, the user's scan
    /// died after one pass lasting seconds, and the nodes were healthy the
    /// whole time — merely full. A later pass must be made, and no address
    /// may be re-dialled inside the window in which its refusal is
    /// guaranteed.
    ///
    /// Time is paused, so the two-minute waits cost nothing and the spacing
    /// can be asserted exactly rather than slept through.
    #[tokio::test(start_paused = true)]
    async fn a_refused_pass_is_retried_after_the_reconnect_window() {
        let mut dialled_at = Vec::new();
        let mut notices = Vec::new();
        let result = acquire_with_retry(
            PEER_ACQUISITION_BUDGET,
            || {
                dialled_at.push(tokio::time::Instant::now());
                let pass = dialled_at.len();
                async move {
                    if pass < 3 {
                        Err(all_refused())
                    } else {
                        Ok(pass)
                    }
                }
            },
            |wait| notices.push(wait),
        )
        .await;

        assert_eq!(result.expect("the third pass finds a peer"), 3);
        for pair in dialled_at.windows(2) {
            assert!(
                pair[1] - pair[0] >= PEER_RECONNECT_DELAY,
                "a pass {:?} after the last re-dials peers that must refuse",
                pair[1] - pair[0]
            );
        }
        assert!(notices
            .iter()
            .all(|w| w.reason == PeerWaitReason::AllPeersBusy));
        assert!(notices.iter().any(|w| w.next_attempt == 2));
        assert!(notices.iter().any(|w| w.next_attempt == 3));
    }

    /// Persistent, not infinite: a network that never answers must end in the
    /// refusal error, inside the budget, rather than spin for ever.
    #[tokio::test(start_paused = true)]
    async fn the_retry_gives_up_inside_its_budget() {
        let started = tokio::time::Instant::now();
        let mut passes = 0u32;
        let err = acquire_with_retry(
            PEER_ACQUISITION_BUDGET,
            || {
                passes += 1;
                async { Err::<(), _>(all_refused()) }
            },
            |_| {},
        )
        .await
        .expect_err("nothing ever answers");

        assert!(matches!(err, PoolError::AllPeersRefused { .. }));
        assert!(passes > 1, "one pass is the behaviour being replaced");
        assert!(
            started.elapsed() <= PEER_ACQUISITION_BUDGET,
            "gave up after {:?}, past the budget",
            started.elapsed()
        );
        // The bound is only meaningful if it leaves room for several windows.
        assert!(PEER_ACQUISITION_BUDGET >= PEER_RECONNECT_DELAY * 5);
    }

    /// A DNS failure is this machine's fault, not the network being busy.
    /// Sitting on it for a quarter of an hour would hide "you are offline"
    /// behind a message about busy peers, so it gets a few quick tries and
    /// then surfaces as itself.
    #[tokio::test(start_paused = true)]
    async fn a_dns_failure_is_retried_briefly_and_stays_a_dns_failure() {
        let started = tokio::time::Instant::now();
        let mut passes = 0u32;
        let mut notices = Vec::new();
        let err = acquire_with_retry(
            PEER_ACQUISITION_BUDGET,
            || {
                passes += 1;
                async { Err::<(), _>(PoolError::NoSeedsResolved("dns down".to_owned())) }
            },
            |wait| notices.push(wait),
        )
        .await
        .expect_err("DNS never comes back");

        assert!(matches!(err, PoolError::NoSeedsResolved(_)));
        assert_eq!(passes, SEED_RETRY_LIMIT);
        assert!(
            started.elapsed() < PEER_RECONNECT_DELAY,
            "a DNS fault must not be waited on like a busy network"
        );
        assert!(!notices.is_empty());
        assert!(notices
            .iter()
            .all(|w| w.reason == PeerWaitReason::SeedsUnresolved));
    }

    /// Two minutes of one unchanging line is indistinguishable from a hang,
    /// so a wait is reported as a countdown.
    #[tokio::test(start_paused = true)]
    async fn a_wait_is_reported_as_a_countdown() {
        let mut passes = 0u32;
        let mut notices = Vec::new();
        let _ = acquire_with_retry(
            PEER_ACQUISITION_BUDGET,
            || {
                passes += 1;
                let pass = passes;
                async move {
                    if pass == 1 {
                        Err(all_refused())
                    } else {
                        Ok(())
                    }
                }
            },
            |wait| notices.push(wait),
        )
        .await;

        assert!(notices.len() > 1, "one notice per wait is a frozen screen");
        assert_eq!(notices[0].retry_in, PEER_RECONNECT_DELAY);
        assert!(notices.windows(2).all(|w| w[1].retry_in < w[0].retry_in));
        assert!(notices.iter().all(|w| w.next_attempt == 2));
    }

    /// Regtest passes no budget: the only candidate is the node the caller
    /// named, and if that is down no amount of waiting frees a slot.
    #[tokio::test(start_paused = true)]
    async fn with_no_budget_a_refusal_fails_at_once() {
        let started = tokio::time::Instant::now();
        let mut passes = 0u32;
        let err = acquire_with_retry(
            Duration::ZERO,
            || {
                passes += 1;
                async { Err::<(), _>(all_refused()) }
            },
            |_| panic!("nothing to wait for, so nothing to announce"),
        )
        .await
        .expect_err("refused");
        assert!(matches!(err, PoolError::AllPeersRefused { .. }));
        assert_eq!(passes, 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// The wording both surfaces show. It has to say that Argos is waiting on
    /// purpose, for how long, and that this is not the first try.
    #[test]
    fn a_wait_notice_says_what_is_happening_and_for_how_long() {
        let text = PeerWait {
            reason: PeerWaitReason::AllPeersBusy,
            next_attempt: 2,
            retry_in: PEER_RECONNECT_DELAY,
        }
        .to_string();
        assert!(text.contains("busy"), "{text}");
        assert!(text.contains("119s"), "{text}");
        assert!(text.contains("attempt 2"), "{text}");

        let dns = PeerWait {
            reason: PeerWaitReason::SeedsUnresolved,
            next_attempt: 2,
            retry_in: SEED_RETRY_DELAY,
        }
        .to_string();
        assert!(dns.contains("DNS"), "{dns}");
        assert!(!dns.contains("busy"), "a DNS fault is not a busy network");
    }

    /// Dropping the scan is how it is cancelled — Ctrl-C in the CLI, quitting
    /// the app. The fetcher is a spawned task, which outlives a dropped
    /// future unless something aborts it; left alone it would now sit in a
    /// peer wait for up to the whole budget after the user had walked away.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_scan_stops_a_fetcher_that_is_waiting() {
        let alive = std::sync::Arc::new(());
        let held = alive.clone();
        let guard = AbortOnDrop(tokio::spawn(async move {
            let _held = held;
            tokio::time::sleep(PEER_ACQUISITION_BUDGET).await;
        }));
        tokio::task::yield_now().await;
        assert_eq!(std::sync::Arc::strong_count(&alive), 2);

        drop(guard);
        tokio::task::yield_now().await;
        assert_eq!(
            std::sync::Arc::strong_count(&alive),
            1,
            "the task must be gone, not sleeping out its wait"
        );
    }

    /// Kristi's #240 findings 1, 2 and 4: both surfaces look up the scan
    /// through one helper, keyed exactly as the scan fingerprints its keys,
    /// and it always says what it found — never an unexplained silence.
    #[test]
    fn a_wallets_scan_lookup_always_explains_itself() {
        let dir = std::env::temp_dir().join(format!("argos-lookup-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [[0x21; 32]];

        let (chain, notice) = chain_spends_for_wallet(&dir, P2pNetwork::Mainnet, &keys);
        assert!(chain.is_none());
        let notice = notice.expect("no scan must be said, with where it looked");
        assert!(notice.contains(&dir.display().to_string()), "{notice}");

        // A duplicated key in the wallet names the same checkpoint the scan
        // wrote for the deduplicated set.
        let mut scanner = SproutScanner::new(&keys);
        scanner.scan_block_at(&[], [0xCD; 32], 300_000).unwrap();
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &checkpoint_path(&dir, &keys)).unwrap();
        let (chain, notice) =
            chain_spends_for_wallet(&dir, P2pNetwork::Mainnet, &[keys[0], keys[0]]);
        let chain = chain.expect("the duplicate must not hide the scan");
        assert!(!chain.complete);
        assert!(notice.unwrap().contains("before reaching the chain tip"));

        // Unusable evidence is said, not swallowed.
        let (chain, notice) = chain_spends_for_wallet(&dir, P2pNetwork::Testnet, &keys);
        assert!(chain.is_none());
        assert!(notice.unwrap().contains("different network"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("argos-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_scan(dir: &Path, keys: &[[u8; 32]], height: u32, complete: bool) -> PathBuf {
        let mut scanner = SproutScanner::new(keys);
        scanner.scan_block_at(&[], [0xCD; 32], height).unwrap();
        if complete {
            scanner.mark_complete();
        }
        let path = checkpoint_path(dir, keys);
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &path).unwrap();
        path
    }

    /// Kristi's #240 finding 1, remaining half: a scan run with keys typed
    /// in beside the wallet file's is keyed by the larger set. The wallet's
    /// own lookup finds it, because it covers every one of the wallet's keys
    /// — and holding them is what keeps a planted checkpoint self-defeating.
    #[test]
    fn a_scan_of_more_keys_than_the_wallet_holds_is_found() {
        let dir = fresh_dir("superset");
        let (a, b, c) = ([0x31; 32], [0x32; 32], [0x33; 32]);
        write_scan(&dir, &[a, b], 3_000_000, true);

        let (chain, notice) = chain_spends_for_wallet(&dir, P2pNetwork::Mainnet, &[a]);
        let chain = chain.expect("a scan covering the wallet's keys must be used");
        assert_eq!(chain.scanned_to, 3_000_000);
        let notice = notice.expect("using a wider scan is said");
        assert!(notice.contains("together with 1 other key"), "{notice}");

        // Not a superset: the wallet holds a key the scan never looked for —
        // even though the scan looked for more keys than the wallet has.
        write_scan(&dir, &[a, b, [0x35; 32]], 3_000_000, true);
        let (chain, _) = chain_spends_for_wallet(&dir, P2pNetwork::Mainnet, &[a, c]);
        assert!(
            chain.is_none(),
            "a scan missing one of the wallet's keys proves nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #240 finding 9, remaining half: opening a wallet asks for the scan
    /// twice (inspection, then preview). The second is served from memory
    /// until the file changes.
    #[test]
    fn a_checkpoint_is_parsed_once_until_it_changes() {
        let dir = fresh_dir("cache");
        let keys = [[0x34; 32]];
        write_scan(&dir, &keys, 3_000_000, true);
        let cache = ChainSpendsCache::default();

        let first = cache
            .load(&dir, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .unwrap();
        let second = cache
            .load(&dir, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .unwrap();
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "the second read must be cached"
        );

        // A resumed scan rewrites the file: the cache must not serve the old one.
        let mut scanner = SproutScanner::new(&keys);
        scanner.scan_block_at(&[], [0xCD; 32], 3_000_000).unwrap();
        scanner
            .scan_block_at(&[joinsplit_revealing([0x77; 32])], [0xCE; 32], 3_000_001)
            .unwrap();
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &checkpoint_path(&dir, &keys)).unwrap();
        let third = cache
            .load(&dir, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&first, &third));
        assert_eq!(third.scanned_to, 3_000_001);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Kristi's round-6 finding 12: a finished scan re-saves its checkpoint
    /// with only the completion byte changed — the same length, and within
    /// one mtime tick. The cache must not keep serving "incomplete".
    #[test]
    fn the_cache_sees_a_rewrite_of_the_same_length() {
        let dir = fresh_dir("cache-same-len");
        let keys = [[0x36; 32]];
        let path = write_scan(&dir, &keys, 3_000_000, false);
        let cache = ChainSpendsCache::default();
        let before = cache
            .load(&dir, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .unwrap();
        assert!(!before.complete);
        let meta = std::fs::metadata(&path).unwrap();
        let (len, mtime) = (meta.len(), meta.modified().unwrap());

        write_scan(&dir, &keys, 3_000_000, true);
        // A filesystem with coarse timestamps gives both saves the same
        // mtime; model that directly rather than rely on this one's.
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "same length by design"
        );
        let after = cache
            .load(&dir, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .unwrap();
        assert!(after.complete, "the finished scan must be seen");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 11: a covering checkpoint that cannot be used is reported as
    /// such, not as "no scan found" — hours of scan work must not look absent.
    #[test]
    fn an_unusable_covering_scan_is_reported_not_hidden() {
        let dir = fresh_dir("covering-broken");
        let (a, b) = ([0x37; 32], [0x38; 32]);
        let path = write_scan(&dir, &[a, b], 3_000_000, true);
        // Damage the body, past the header the covering search reads.
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();

        let (chain, notice) = chain_spends_for_wallet(&dir, P2pNetwork::Mainnet, &[a]);
        assert!(chain.is_none());
        let notice = notice.unwrap();
        assert!(notice.contains("could not be used"), "{notice}");
        assert!(notice.contains(&path.display().to_string()), "{notice}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn joinsplit_revealing(nf: [u8; 32]) -> argos_wallet_import::keys::SproutJoinSplit {
        argos_wallet_import::keys::SproutJoinSplit {
            txid: [0x71; 32],
            js_index: 0,
            anchor: [0; 32],
            nullifiers: [nf, [0x72; 32]],
            commitments: [[0x73; 32], [0x74; 32]],
            ephemeral_key: [0x75; 32],
            random_seed: [0x76; 32],
            joinsplit_pubkey: [0x77; 32],
            ciphertexts: [vec![0; 601], vec![0; 601]],
        }
    }

    /// A directory for one test in one process, emptied before use and
    /// removed after. Two `cargo test` runs on one machine must not share
    /// or delete each other's files, and a crashed run must not leave one
    /// behind that fails the next run permanently.
    struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("argos-chain-evidence-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scanned(keys: &[[u8; 32]], nf: [u8; 32], height: u32) -> SproutScanner {
        let mut scanner = SproutScanner::new(keys);
        scanner
            .scan_block_at(&[joinsplit_revealing(nf)], [0xCD; 32], height)
            .expect("a block with one JoinSplit");
        scanner
    }

    fn found(lookup: ChainSpendsLookup) -> ScanEvidence {
        match lookup {
            ChainSpendsLookup::Found(evidence) => evidence,
            other => panic!("expected a scan, got {other:?}"),
        }
    }

    /// The wallet-file path asks the scan what the chain says about spends.
    /// It must read exactly the checkpoint `scan-sprout` would resume.
    #[test]
    fn chain_spends_reads_what_the_scan_saw_on_chain() {
        let dir = ScratchDir::new("reads");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(
            &scanned(&keys, [0x99; 32], 2_000_000),
            P2pNetwork::Mainnet,
            &path,
        )
        .unwrap();

        let chain = chain_spends(&dir.0, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .expect("a checkpoint exists for these keys");
        assert!(chain.nullifiers.contains_key(&[0x99; 32]));
        assert!(chain.nullifiers.contains_key(&[0x72; 32]));
        assert_eq!(chain.scanned_to, 2_000_000);
    }

    /// Kristi, #240 #10: the revealing txid is carried to the caller, so a
    /// chain-proven spend can be checked in an explorer.
    #[test]
    fn the_lookup_names_the_transaction_behind_each_spend() {
        let dir = ScratchDir::new("txid");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(&scanned(&keys, [0x99; 32], 5), P2pNetwork::Mainnet, &path).unwrap();

        let evidence = found(lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys).unwrap());
        assert_eq!(evidence.spent.get(&[0x99; 32]), Some(&Some([0x71; 32])));
        assert_eq!(evidence.path, path);
    }

    /// Kristi, #240 #2: no scan must be distinguishable from an unreadable
    /// one, and the caller must be able to say where it looked.
    #[test]
    fn no_scan_is_reported_with_where_it_looked() {
        let dir = ScratchDir::new("none");
        let keys = [[0x12; 32]];
        match lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys).unwrap() {
            ChainSpendsLookup::NotFound { path } => {
                assert_eq!(path, checkpoint_path(&dir.0, &keys))
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        assert!(chain_spends(&dir.0, P2pNetwork::Mainnet, &keys)
            .unwrap()
            .is_none());
    }

    /// A checkpoint that exists but cannot be read is an error, never "no
    /// scan": a six-hour scan must not silently read as never having run.
    #[test]
    fn an_unreadable_checkpoint_is_an_error_not_no_scan() {
        let dir = ScratchDir::new("unreadable");
        let keys = [[0x14; 32]];
        // A directory where the file should be: reading it fails, and not
        // with NotFound. Portable, unlike a permission bit root ignores.
        std::fs::create_dir_all(checkpoint_path(&dir.0, &keys)).unwrap();

        let err = lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys)
            .expect_err("an unreadable checkpoint must be reported");
        assert!(
            err.to_string().contains("reading the scan checkpoint"),
            "{err}"
        );
    }

    /// The same guard the scan's own resume applies: another chain's
    /// nullifiers would mark this chain's notes spent.
    #[test]
    fn chain_spends_from_another_network_are_refused() {
        let dir = ScratchDir::new("network");
        let keys = [[0x13; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(
            &scanned(&keys, [0x99; 32], 2_000_000),
            P2pNetwork::Mainnet,
            &path,
        )
        .unwrap();

        let err = chain_spends(&dir.0, P2pNetwork::Testnet, &keys)
            .expect_err("a mainnet scan must not answer for testnet");
        assert!(err.to_string().contains("different network"), "{err}");
    }

    /// Kristi, #240 #5: resume tolerates an untagged checkpoint by a height
    /// heuristic, because it re-reads the chain anyway. Evidence that marks
    /// notes spent with no network contact must not.
    #[test]
    fn an_untagged_checkpoint_is_not_chain_evidence() {
        let dir = ScratchDir::new("untagged");
        let keys = [[0x15; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        std::fs::write(&path, scanned(&keys, [0x99; 32], 5).checkpoint().as_bytes()).unwrap();

        let err = lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys)
            .expect_err("no network recorded, so no verdict");
        assert!(
            err.to_string().contains("does not record its network"),
            "{err}"
        );
    }

    /// Kristi, #240 #8: the embedded key set, not the file name, is what
    /// ties a checkpoint to a wallet. A file for keys A at keys B's path is
    /// refused.
    #[test]
    fn a_checkpoint_for_other_keys_is_refused_whatever_its_name() {
        let dir = ScratchDir::new("keyset");
        let (a, b) = ([[0x16; 32]], [[0x17; 32]]);
        save_checkpoint(
            &scanned(&a, [0x99; 32], 5),
            P2pNetwork::Mainnet,
            &checkpoint_path(&dir.0, &b),
        )
        .unwrap();

        let err = lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &b)
            .expect_err("keys A's scan must not answer for keys B");
        assert!(
            err.to_string().contains("different set of spending"),
            "{err}"
        );
    }

    /// Kristi, #240 #3: a scan that stopped early left a valid checkpoint
    /// that read as full coverage. The lookup says which it is.
    #[test]
    fn an_aborted_scan_is_found_but_not_complete() {
        let dir = ScratchDir::new("complete");
        let keys = [[0x18; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        let mut scanner = scanned(&keys, [0x99; 32], 300_000);
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &path).unwrap();
        let aborted = found(lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys).unwrap());
        assert!(!aborted.complete);
        assert_eq!(aborted.scanned_to, 300_000);

        scanner.mark_complete();
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &path).unwrap();
        let finished = found(lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys).unwrap());
        assert!(finished.complete);
    }

    /// Kristi, #240 #1: the scan dedups its keys, so [A, A] and [A] are one
    /// scan and must name one file.
    #[test]
    fn duplicated_keys_name_the_same_checkpoint() {
        let dir = std::path::Path::new("/x");
        let (a, b) = ([0x21; 32], [0x22; 32]);
        assert_eq!(checkpoint_path(dir, &[a, a]), checkpoint_path(dir, &[a]));
        assert_eq!(
            checkpoint_path(dir, &[b, a, a]),
            checkpoint_path(dir, &[a, b])
        );
        assert_ne!(checkpoint_path(dir, &[a]), checkpoint_path(dir, &[b]));
    }

    #[test]
    fn the_scan_key_set_merges_sorts_and_dedups() {
        let (a, b, c) = ([0x01; 32], [0x02; 32], [0x03; 32]);
        assert_eq!(scan_key_set(&[c, a, a], &[b, c]), vec![a, b, c]);
        assert_eq!(scan_key_set(&[], &[]), Vec::<[u8; 32]>::new());
    }

    /// A checkpoint records its network, so resuming one elsewhere is
    /// refused before any peer is asked — its cursor would otherwise read as
    /// the tip of a shorter chain and hand back the other network's notes.
    #[tokio::test]
    async fn a_checkpoint_from_another_network_is_refused() {
        let mut scanner = SproutScanner::new(&[[0x11; 32]]);
        scanner
            .scan_block_at(&[], [0xCD; 32], 2_000_000)
            .expect("an empty block");
        let dir = std::env::temp_dir().join("argos-scan-network-tag-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mainnet.checkpoint");
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &path).unwrap();

        let err = run_sprout_scan(&[[0x11; 32]], P2pNetwork::Testnet, &[], None, &path, |_| {})
            .await
            .expect_err("a mainnet checkpoint must not resume on testnet");
        discard_checkpoint(&path);
        assert!(err.to_string().contains("different network"), "{err}");
    }

    /// Checkpoints written before files recorded a network came from
    /// Canopy-bounded scans, so one past this network's Canopy height was
    /// made elsewhere — the rule that used to guard every resume.
    #[tokio::test]
    async fn an_untagged_checkpoint_past_this_networks_canopy_is_refused() {
        let mut scanner = SproutScanner::new(&[[0x11; 32]]);
        scanner
            .scan_block_at(&[], [0xCD; 32], 1_046_399)
            .expect("an empty block");
        let dir = std::env::temp_dir().join("argos-scan-legacy-network-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.checkpoint");
        std::fs::write(&path, scanner.checkpoint().as_bytes()).unwrap();

        let err = run_sprout_scan(&[[0x11; 32]], P2pNetwork::Testnet, &[], None, &path, |_| {})
            .await
            .expect_err("mainnet's Canopy height is past testnet's");
        discard_checkpoint(&path);
        assert!(err.to_string().contains("different network"), "{err}");
    }

    /// A scan saved at the old Canopy end is not finished. It used to be
    /// returned offline as a complete result, which is how a note migrated
    /// after Canopy came back as spendable. Resuming must go on to the tip,
    /// so it reaches for a peer instead of returning.
    #[tokio::test]
    async fn a_scan_saved_at_canopy_catches_up_instead_of_finishing() {
        let mut scanner = SproutScanner::new(&[[0x11; 32]]);
        scanner
            .scan_block_at(&[], [0xCD; 32], 1_046_399)
            .expect("an empty block");

        let dir = std::env::temp_dir().join("argos-scan-canopy-resume-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("canopy.checkpoint");
        // Written as every existing checkpoint was — before files recorded
        // their network — because those are the scans this must continue.
        std::fs::write(&path, scanner.checkpoint().as_bytes()).unwrap();

        // Nothing listens on the only peer offered, so a run that goes on
        // to fetch can only still be waiting for a connection — or fail
        // for want of one. What it must not do is hand back a result.
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            run_sprout_scan(
                &[[0x11; 32]],
                P2pNetwork::Mainnet,
                &["127.0.0.1:1".to_owned()],
                None,
                &path,
                |_| {},
            ),
        )
        .await;
        discard_checkpoint(&path);
        assert!(
            !matches!(outcome, Ok(Ok(_))),
            "a scan saved at Canopy must not be reported as complete"
        );
    }

    #[tokio::test]
    async fn a_scan_with_no_keys_is_refused() {
        let err = run_sprout_scan(
            &[],
            P2pNetwork::Regtest,
            &[],
            None,
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

        let err = run_sprout_scan(&[[0x11; 32]], P2pNetwork::Regtest, &[], None, &path, |_| {})
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
