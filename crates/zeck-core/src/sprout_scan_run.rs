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
//! A wallet-file lookup reconciles the saved cursor with a live peer before
//! using any cached nullifier as spend evidence. That consumer is stricter —
//! the network tag is required, the embedded key set must match, and whether
//! the walk reached the tip (`complete`) is reported, not assumed. A MAC would still
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
    fs,
    future::Future,
    io::{Read, Seek},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{ZeckError, ZeckResult},
    p2p::{
        block::joinsplits_in_block,
        peer::{Peer, READ_TIMEOUT},
        pool::{connect_to_any_except, PoolError, PEER_RECONNECT_DELAY},
        wire::P2pNetwork,
    },
    sprout_scan::{
        CheckpointError, ScanCursor, SproutScanCheckpoint, SproutScanResult, SproutScanner,
    },
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

/// Identity of the exact spend-capable checkpoint object reviewed by a
/// proposal. A path and digest alone do not detect an atomic replacement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointGeneration {
    pub len: u64,
    pub sha256: [u8; 32],
    pub object: CheckpointObjectId,
}

/// Cross-process lease for a checkpoint path.
///
/// The lock is taken on the exact private sidecar handle we opened and
/// hardened. We retain that handle, its object identity, and the parent
/// directory handle for the lease lifetime. Every authority-sensitive use
/// verifies that the path still names both retained objects, so replacing a
/// locked sidecar cannot create a second authority that the first one fails
/// to notice.
pub struct CheckpointLease {
    namespace: std::sync::Arc<crate::private_fs::NamespaceLease>,
    _not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

impl CheckpointLease {
    pub fn acquire(path: &Path) -> ZeckResult<Self> {
        let sidecar_path = checkpoint_lease_path(path);
        let parent_path = sidecar_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        ensure_checkpoint_parent(path)?;
        let namespace = crate::private_fs::NamespaceLease::acquire(&parent_path, &sidecar_path)
            .map_err(|err| {
                ZeckError::ScanNotReady(format!(
                    "checkpoint {} is in use by another recovery operation: {err}",
                    path.display()
                ))
            })?;
        let lease = Self {
            namespace: std::sync::Arc::new(namespace),
            _not_sync: std::marker::PhantomData,
        };
        lease.verify_for(path)?;
        Ok(lease)
    }

    pub(crate) fn verify_for(&self, path: &Path) -> ZeckResult<()> {
        if checkpoint_lease_path(path) != self.namespace.lock_path() {
            return Err(ZeckError::ScanNotReady(format!(
                "checkpoint lease does not authorize {}",
                path.display()
            )));
        }
        self.namespace.verify_current().map_err(|err| {
            ZeckError::ScanNotReady(format!(
                "checkpoint lease for {} was replaced while held: {err}",
                path.display()
            ))
        })
    }

    fn child_path(&self, path: &Path) -> ZeckResult<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if parent != self.namespace.parent_path() || path.file_name().is_none() {
            return Err(ZeckError::ScanNotReady(format!(
                "checkpoint lease does not authorize child {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn open_child(&self, path: &Path) -> ZeckResult<Option<fs::File>> {
        self.child_path(path)?;
        match crate::private_fs::open_child_file(self.namespace.parent(), path) {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(ZeckError::TransactionBuild(format!(
                "opening checkpoint child {}: {err}",
                path.display()
            ))),
        }
    }

    fn remove_child(&self, path: &Path) -> ZeckResult<bool> {
        self.child_path(path)?;
        match crate::private_fs::remove_child_file(self.namespace.parent(), path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(ZeckError::TransactionBuild(format!(
                "removing checkpoint child {}: {err}",
                path.display()
            ))),
        }
    }

    fn remove_open_child(
        &self,
        path: &Path,
        file: &fs::File,
        expected_id: &CheckpointObjectId,
    ) -> ZeckResult<()> {
        self.child_path(path)?;
        self.namespace
            .remove_open_child(path, file, expected_id)
            .map_err(|err| {
                ZeckError::TransactionBuild(format!(
                    "removing exact checkpoint child {}: {err}",
                    path.display()
                ))
            })
    }

    fn rename_child(&self, from: &Path, to: &Path) -> ZeckResult<()> {
        self.child_path(from)?;
        self.child_path(to)?;
        crate::private_fs::rename_child_file(self.namespace.parent(), from, to).map_err(|err| {
            ZeckError::TransactionBuild(format!(
                "renaming checkpoint child {} to {}: {err}",
                from.display(),
                to.display()
            ))
        })
    }

    fn child_names(&self) -> ZeckResult<Vec<std::ffi::OsString>> {
        crate::private_fs::parent_child_names(self.namespace.parent(), self.namespace.parent_path())
            .map_err(|err| {
                ZeckError::TransactionBuild(format!(
                    "reading checkpoint directory {}: {err}",
                    self.namespace.parent_path().display()
                ))
            })
    }

    fn sync_parent(&self) -> ZeckResult<()> {
        self.namespace.sync_parent().map_err(|err| {
            ZeckError::TransactionBuild(format!(
                "syncing checkpoint directory {}: {err}",
                self.namespace.parent_path().display()
            ))
        })
    }

    pub(crate) fn generation(&self, path: &Path) -> ZeckResult<CheckpointGeneration> {
        self.generation_if_present(path)?.ok_or_else(|| {
            ZeckError::ScanNotReady(format!("checkpoint {} is absent", path.display()))
        })
    }

    pub(crate) fn generation_if_present(
        &self,
        path: &Path,
    ) -> ZeckResult<Option<CheckpointGeneration>> {
        self.open_child(path)?
            .map(|file| checkpoint_generation_from_handle(&file, path))
            .transpose()
    }

    pub(crate) fn clone_namespace(&self) -> std::sync::Arc<crate::private_fs::NamespaceLease> {
        std::sync::Arc::clone(&self.namespace)
    }
}

fn checkpoint_lease_path(path: &Path) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(".lease.sqlite");
    PathBuf::from(sidecar)
}

fn ensure_checkpoint_parent(path: &Path) -> ZeckResult<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.exists() {
        if !parent.is_dir() {
            return Err(ZeckError::TransactionBuild(format!(
                "checkpoint parent {} is not a directory",
                parent.display()
            )));
        }
        return Ok(());
    }
    // A directory Argos creates for this checkpoint is private from birth.
    // Existing user-selected data directories are never chmodded here.
    crate::private_fs::create_private_dir_all(parent).map_err(|err| {
        ZeckError::TransactionBuild(format!(
            "creating private checkpoint directory {}: {err}",
            parent.display()
        ))
    })
}

pub use crate::private_fs::PrivateObjectId as CheckpointObjectId;

/// Capture length, contents and filesystem object identity from one open
/// checkpoint handle, rejecting a file that changes during the read.
pub fn checkpoint_generation(path: &Path) -> ZeckResult<CheckpointGeneration> {
    checkpoint_generation_with_post_read(path, || {})
}

fn checkpoint_generation_with_post_read(
    path: &Path,
    post_read: impl FnOnce(),
) -> ZeckResult<CheckpointGeneration> {
    let file = fs::File::open(path).map_err(|err| {
        ZeckError::TransactionBuild(format!("opening checkpoint {}: {err}", path.display()))
    })?;
    checkpoint_generation_from_handle_with_post_read(&file, path, post_read)
}

fn checkpoint_generation_from_handle(
    file: &fs::File,
    path: &Path,
) -> ZeckResult<CheckpointGeneration> {
    checkpoint_generation_from_handle_with_post_read(file, path, || {})
}

fn checkpoint_generation_from_handle_with_post_read(
    file: &fs::File,
    path: &Path,
    post_read: impl FnOnce(),
) -> ZeckResult<CheckpointGeneration> {
    let before = file.metadata().map_err(|err| {
        ZeckError::TransactionBuild(format!("inspecting checkpoint {}: {err}", path.display()))
    })?;
    if !before.is_file() {
        return Err(ZeckError::TransactionBuild(format!(
            "checkpoint {} is not a regular file",
            path.display()
        )));
    }
    let before_object = checkpoint_object_id(file, &before)?;
    let (len, digest) = hash_checkpoint_handle(file, path)?;
    post_read();
    let (verified_len, verified_digest) = hash_checkpoint_handle(file, path)?;
    let after = file.metadata().map_err(|err| {
        ZeckError::TransactionBuild(format!("rechecking checkpoint {}: {err}", path.display()))
    })?;
    let after_object = checkpoint_object_id(file, &after)?;
    if before.len() != after.len()
        || before.len() != len
        || len != verified_len
        || digest != verified_digest
        || before_object != after_object
    {
        return Err(ZeckError::TransactionBuild(format!(
            "checkpoint {} changed while it was reviewed",
            path.display()
        )));
    }
    Ok(CheckpointGeneration {
        len,
        sha256: digest,
        object: after_object,
    })
}

fn hash_checkpoint_handle(file: &fs::File, path: &Path) -> ZeckResult<(u64, [u8; 32])> {
    let mut reader = file;
    reader.rewind().map_err(|err| {
        ZeckError::TransactionBuild(format!("seeking checkpoint {}: {err}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            ZeckError::TransactionBuild(format!("reading checkpoint {}: {err}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        len = len
            .checked_add(read as u64)
            .ok_or_else(|| ZeckError::TransactionBuild("checkpoint length overflow".into()))?;
        hasher.update(&buffer[..read]);
    }
    Ok((len, hasher.finalize().into()))
}

fn checkpoint_object_id(
    file: &fs::File,
    _metadata: &fs::Metadata,
) -> ZeckResult<CheckpointObjectId> {
    crate::private_fs::private_object_id(file).map_err(|err| {
        ZeckError::TransactionBuild(format!("reading checkpoint object identity: {err}"))
    })
}

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

/// Wallet evidence must be checked promptly when opening or previewing a wallet.
const WALLET_EVIDENCE_BUDGET: Duration = Duration::from_secs(45);

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
    let _lease = CheckpointLease::acquire(checkpoint_file)?;
    load_checkpoint_while_leased(&_lease, checkpoint_file, network, spending_keys)
}

fn load_checkpoint_while_leased(
    lease: &CheckpointLease,
    checkpoint_file: &Path,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<Option<SproutScanner>> {
    lease.verify_for(checkpoint_file)?;
    remove_stale_temp_files_while_leased(lease, checkpoint_file)?;
    lease.verify_for(checkpoint_file)?;
    let Some(mut file) = lease.open_child(checkpoint_file)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|err| {
        ZeckError::TransactionBuild(format!(
            "reading the scan checkpoint at {}: {err}",
            checkpoint_file.display()
        ))
    })?;
    parse_checkpoint(checkpoint_file, bytes, network, spending_keys).map(Some)
}

/// The checks of [`load_checkpoint`], on bytes already read.
fn parse_checkpoint(
    checkpoint_file: &Path,
    bytes: Vec<u8>,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<SproutScanner> {
    // Checked after the scanner loads, so a corrupt file is still
    // reported as corrupt rather than as the wrong network.
    let (tag, body) = match bytes.as_slice() {
        [NETWORK_TAGGED, tag, body @ ..] => (Some(*tag), body.to_vec()),
        _ => (None, bytes),
    };
    let checkpoint = SproutScanCheckpoint::from_bytes(body);
    let resumed = SproutScanner::resume(&checkpoint).map_err(|err| match err {
        CheckpointError::UnauthenticatedLegacy => legacy_checkpoint_error(checkpoint_file),
        _ => ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} could not be read ({err}). Delete it to \
             start a fresh scan, or restore a good copy — it holds hours of work.",
            checkpoint_file.display()
        )),
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
    Ok(resumed)
}

fn legacy_checkpoint_error(path: &Path) -> ZeckError {
    ZeckError::TransactionBuild(format!(
        "the scan checkpoint at {} predates Sprout block-body authentication and cannot \
         be trusted for resume or spend evidence. Preserve this file and the original \
         spending-key source; start a fresh scan in a new data directory or move this \
         checkpoint aside first.",
        path.display()
    ))
}

/// A resumed scan asked to decrypt blocks its checkpoint walked past
/// without decrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptBoundConflict {
    /// The bound the checkpoint was scanned under.
    pub stored: u32,
    /// The bound now asked for; `None` is "decrypt every block".
    pub requested: Option<u32>,
    /// The last block the checkpoint walked.
    pub cursor_height: u32,
}

impl DecryptBoundConflict {
    fn into_error(self, checkpoint_file: &Path) -> ZeckError {
        let asked = match self.requested {
            Some(height) => format!("decryption from block {height}"),
            None => "decryption of every block".to_owned(),
        };
        ZeckError::TransactionBuild(format!(
            "the scan checkpoint at {} was saved by a scan that did not try to decrypt \
             notes below block {stored}, and has already walked to block {cursor}. This \
             scan asks for {asked}, so resuming would leave the blocks between unchecked \
             and miss any notes in them. Delete the checkpoint to scan from the start, or \
             run again with a birthday of block {stored} or later.",
            checkpoint_file.display(),
            stored = self.stored,
            cursor = self.cursor_height,
        ))
    }
}

/// The decrypt-from bound a scan continues under, given the bound its
/// checkpoint was scanned under, how far that checkpoint walked, and the
/// bound now requested.
///
/// A resumed scan must never silently change which blocks were decrypted.
/// Nothing walked yet: the request stands. A request at or above the stored
/// bound: the stored one is kept, since every block it covers was decrypted
/// anyway and it is the bound that truly applies. A request below it is
/// accepted only while the walk has not reached the requested bound —
/// otherwise blocks the request wants decrypted were already passed over.
pub fn reconcile_decrypt_from(
    stored: Option<u32>,
    cursor_height: Option<u32>,
    requested: Option<u32>,
) -> Result<Option<u32>, DecryptBoundConflict> {
    let Some(cursor_height) = cursor_height else {
        return Ok(requested);
    };
    let (stored_floor, requested_floor) = (stored.unwrap_or(0), requested.unwrap_or(0));
    if requested_floor >= stored_floor {
        return Ok(stored);
    }
    // Blocks 1..=cursor were walked; those in [requested, stored) were not
    // decrypted but the request needs them to be.
    if cursor_height < requested_floor.max(1) {
        return Ok(requested);
    }
    Err(DecryptBoundConflict {
        stored: stored_floor,
        requested,
        cursor_height,
    })
}

/// The decrypt-from bound a scan may apply, given a height the chain is
/// known to have reached.
///
/// A bound above the tip would decrypt nothing at all, and can only come
/// from creation times written by a machine whose clock ran ahead. Such a
/// bound is evidence of nothing, so it is dropped and every block is
/// decrypted. With no tip to compare against, the bound passes through:
/// the creation-time check against the current time
/// (`birthday::sprout_skip_height`) is then the only guard.
pub fn bound_within_tip(decrypt_from: Option<u32>, tip: Option<u32>) -> Option<u32> {
    match (decrypt_from, tip) {
        (Some(bound), Some(tip)) if bound > tip => None,
        _ => decrypt_from,
    }
}

/// What to tell the user when [`bound_within_tip`] drops the requested
/// skip for the tip the scan was given. The line printed before the scan
/// promised a skip, and must not be left standing. Asked of the same inputs
/// rather than inferred from the bound the scan reports, because a resume of
/// a scan that decrypted every block also reports no bound, for a different
/// reason.
pub fn dropped_bound_line(requested: Option<u32>, tip: Option<u32>) -> Option<String> {
    match (requested, bound_within_tip(requested, tip)) {
        (Some(bound), None) => Some(format!(
            "Trial decryption covered every block from 1: the requested start, block \
             {bound}, is above the chain tip lightwalletd reported, so the wallet file's \
             creation times cannot be right and were not used."
        )),
        _ => None,
    }
}

/// The decrypt-from bound the saved scan for `spending_keys` ran under, or
/// `None` when there is no checkpoint. `Some(None)` is a scan that
/// decrypted every block.
///
/// For a resume that must continue exactly as the scan ran — the sweep
/// after a scan — rather than re-deriving the bound from inputs that may
/// have changed since, which [`reconcile_decrypt_from`] would refuse. The
/// checkpoint is checked as a resume checks it: wrong keys or network is an
/// error.
pub fn saved_decrypt_from(
    checkpoint_file: &Path,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<Option<Option<u32>>> {
    Ok(load_checkpoint(checkpoint_file, network, spending_keys)?
        .map(|scanner| scanner.decrypt_from_height()))
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
struct ScanEvidence {
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
enum ChainSpendsLookup {
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
fn lookup_chain_spends(
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
             cannot be trusted for this one. Preserve the file and the original \
             spending-key source; start a fresh scan in a new data directory or \
             move this checkpoint aside first.",
            path.display()
        )));
    };
    let evidence =
        crate::sprout_scan::read_chain_evidence(&SproutScanCheckpoint::from_bytes(body.to_vec()))
            .map_err(|err| match err {
            CheckpointError::UnauthenticatedLegacy => legacy_checkpoint_error(&path),
            _ => ZeckError::TransactionBuild(format!(
                "the scan checkpoint at {} could not be read ({err}).",
                path.display()
            )),
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
#[cfg(test)]
fn chain_spends(
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

/// What a verified lookup found.
enum VerifiedLookup {
    Found(std::sync::Arc<crate::sprout_recovery::ChainSpends>, PathBuf),
    NotFound(PathBuf),
    NothingScanned(PathBuf),
}

/// Size, mtime and content digest of a checkpoint file: what proves the
/// file still holds the bytes that were parsed and verified. The digest
/// catches a same-length rewrite (a scan finishing changes one byte) on a
/// filesystem whose mtimes are too coarse to tell two saves apart.
type Stamp = (u64, Option<std::time::SystemTime>, [u8; 32]);

fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn stamp_of(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    let bytes = std::fs::read(path).ok()?;
    Some((bytes.len() as u64, meta.modified().ok(), digest(&bytes)))
}

/// [`load_checkpoint`] with the [`Stamp`] of the very bytes it parsed. The
/// metadata is read first, so a file replaced between the two reads shows
/// up as a changed mtime rather than slipping past.
fn load_checkpoint_stamped(
    checkpoint_file: &Path,
    network: P2pNetwork,
    spending_keys: &[[u8; 32]],
) -> ZeckResult<Option<(Stamp, SproutScanner)>> {
    let modified = std::fs::metadata(checkpoint_file)
        .ok()
        .and_then(|meta| meta.modified().ok());
    let Some(bytes) = read_checkpoint_file(checkpoint_file)? else {
        return Ok(None);
    };
    let stamp = (bytes.len() as u64, modified, digest(&bytes));
    let scanner = parse_checkpoint(checkpoint_file, bytes, network, spending_keys)?;
    Ok(Some((stamp, scanner)))
}

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

/// Select one checkpoint without exposing its parsed spends. Ranking a
/// covering scan still parses its evidence, but that transient map is dropped
/// here; only the selected file may later become wallet evidence.
fn select_wallet_checkpoint(
    data_dir: &Path,
    network: P2pNetwork,
    keys: &[[u8; 32]],
) -> Result<(Vec<[u8; 32]>, Option<usize>), String> {
    let path = checkpoint_path(data_dir, keys);
    match std::fs::metadata(&path) {
        Ok(_) => Ok((keys.to_vec(), None)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut unusable = Vec::new();
            let best = scans_covering(data_dir, network, keys)
                .into_iter()
                .filter_map(|wider| match lookup_chain_spends(data_dir, network, &wider) {
                    Ok(ChainSpendsLookup::Found(evidence)) => {
                        Some((evidence.complete, evidence.scanned_to, wider))
                    }
                    Ok(_) => None,
                    Err(err) => {
                        unusable.push(format!("{} ({err})", checkpoint_path(data_dir, &wider).display()));
                        None
                    }
                })
                .max_by_key(|(complete, height, _)| (*complete, *height));
            match best {
                Some((_, _, wider)) => {
                    let width = wider.len() - keys.len();
                    Ok((wider, Some(width)))
                }
                None if !unusable.is_empty() => Err(format!(
                    "A full-block scan covering this wallet's Sprout keys was found but could not be used: {}. Spent status is the wallet file's own record.",
                    unusable.join("; ")
                )),
                None => Err(format!(
                    "No full-block scan of this wallet's Sprout keys was found (looked for {} and any scan covering these keys in {}), so spent status is the wallet file's own record.",
                    path.display(), data_dir.display()
                )),
            }
        }
        Err(err) => Err(format!(
            "Not using the full-block scan checkpoint at {}: {err}. Spent status is the wallet file's own record.", path.display()
        )),
    }
}

/// Parse the selected checkpoint once, verify its cursor against live
/// headers, and return its spends only if the file still holds the bytes
/// that were parsed.
async fn verified_checkpoint_lookup<V: CursorVerifier>(
    data_dir: &Path,
    network: P2pNetwork,
    keys: &[[u8; 32]],
    verifier: &mut V,
) -> ZeckResult<VerifiedLookup> {
    verified_checkpoint_lookup_with(data_dir, network, keys, verifier, stamp_of, |_| {}).await
}

// The two callbacks let tests replace a checkpoint at the exact reconciliation
// boundary and model an unreadable file stamp without timing or permissions.
async fn verified_checkpoint_lookup_with<V: CursorVerifier>(
    data_dir: &Path,
    network: P2pNetwork,
    keys: &[[u8; 32]],
    verifier: &mut V,
    read_stamp: impl FnOnce(&Path) -> Option<Stamp> + Send + 'static,
    after_reconcile: impl FnOnce(&Path),
) -> ZeckResult<VerifiedLookup> {
    let path = checkpoint_path(data_dir, keys);
    // A completed mainnet scan is millions of nullifiers: read and parse it
    // once, off the async runtime.
    let loaded = {
        let (path, keys) = (path.clone(), keys.to_vec());
        tokio::task::spawn_blocking(move || load_checkpoint_stamped(&path, network, &keys))
            .await
            .map_err(|err| {
                ZeckError::TransactionBuild(format!("reading the scan checkpoint: {err}"))
            })??
    };
    let Some((stamp, mut scanner)) = loaded else {
        return Ok(VerifiedLookup::NotFound(path));
    };
    let Some(cursor) = scanner.cursor() else {
        return Ok(VerifiedLookup::NothingScanned(path));
    };
    // Wallet evidence does not own scanner progress. Reconcile only in
    // memory so a scan writer advancing during this await is never replaced
    // by a wallet lookup's older rewind or completion downgrade.
    reconcile_cursor_in_memory(&mut scanner, verifier, &path).await?;
    after_reconcile(&path);
    let after = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || read_stamp(&path))
            .await
            .ok()
            .flatten()
    };
    if after != Some(stamp) {
        return Err(ZeckError::ScanNotReady(format!(
            "the scan checkpoint at {} changed while it was being verified (or could not be re-read to confirm it had not); Argos will not use its spent-note evidence.",
            path.display()
        )));
    }
    let scanned_to = scanner.cursor().unwrap_or(cursor).last_height;
    Ok(VerifiedLookup::Found(
        std::sync::Arc::new(crate::sprout_recovery::ChainSpends {
            complete: scanner.is_complete(),
            scanned_to,
            nullifiers: scanner.into_spent_nullifiers(),
        }),
        path,
    ))
}

fn wallet_lookup_result(
    lookup: ZeckResult<VerifiedLookup>,
    wider_keys: Option<usize>,
) -> (
    Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>,
    Option<String>,
) {
    match lookup {
        Ok(VerifiedLookup::Found(spends, path)) => {
            let mut notice = wider_keys.map(|width| format!(
                "Using the full-block scan at {}, which scanned this wallet's Sprout keys together with {width} other key(s).", path.display()
            ));
            if !spends.complete {
                let suffix = format!("It stopped at height {} before reaching the chain tip ({}).", spends.scanned_to, path.display());
                notice = Some(match notice { Some(prefix) => format!("{prefix} {suffix}"), None => format!("Using this wallet's full-block scan. {suffix}") });
            }
            (Some(spends), notice)
        }
        Ok(VerifiedLookup::NotFound(path)) => (None, Some(format!(
            "The selected full-block scan at {} disappeared before verification, so spent status is the wallet file's own record.", path.display()
        ))),
        Ok(VerifiedLookup::NothingScanned(path)) => (None, Some(format!(
            "A full-block scan of these keys was started ({}) but has not read a block yet, so spent status is the wallet file's own record.", path.display()
        ))),
        Err(err) => (None, Some(format!(
            "Not using the full-block scan checkpoint: {err} Argos will not use its spent-note evidence. Spent status is the wallet file's own record."
        ))),
    }
}

/// What inspection says about a full-block scan of the wallet's keys,
/// without contacting the network.
///
/// A checkpoint's nullifiers may mark a wallet note spent only after its
/// cursor is verified against live headers (a reorg can orphan them), and
/// inspection makes no network contact. So this fails closed: it never
/// returns scan evidence, only a sentence naming the scan and saying it was
/// not used. A sweep verifies the same checkpoint with
/// [`chain_spends_for_wallet`] before relying on it. `None` when the wallet
/// has no Sprout keys.
pub fn wallet_scan_notice_offline(
    data_dir: &Path,
    network: P2pNetwork,
    wallet_keys: &[[u8; 32]],
) -> Option<String> {
    let keys = scan_key_set(wallet_keys, &[]);
    if keys.is_empty() {
        return None;
    }
    let (selected, wider_keys) = match select_wallet_checkpoint(data_dir, network, &keys) {
        Ok(selected) => selected,
        Err(notice) => return Some(notice),
    };
    let path = checkpoint_path(data_dir, &selected);
    let wider = wider_keys.map_or(String::new(), |width| {
        format!(" (it scanned this wallet's Sprout keys together with {width} other key(s))")
    });
    Some(format!(
        "A full-block scan of this wallet's Sprout keys exists at {}{wider}, but its spent-note evidence was not verified offline: a chain reorganization can orphan what it saw, and checking that needs live peers, which were not contacted. Spent status is the wallet file's own record. A sweep verifies the scan against live peers before using it.",
        path.display()
    ))
}

/// One pass over the candidate peers, with no waiting between passes: a
/// wallet sweep should learn at once that no peer is reachable, not after
/// the quarter of an hour a scan is given.
const WALLET_PEER_ACQUISITION_BUDGET: Duration = Duration::ZERO;

/// Wallet-file spend evidence for a sweep, returned only after a live cursor
/// check. `extra_peers` are the user's own peers, dialled first. Peer
/// acquisition is a single pass, and acquisition plus reconciliation share
/// one [`WALLET_EVIDENCE_BUDGET`] deadline. Never fails: evidence that
/// cannot be verified is reported in the notice and the wallet file's own
/// record stands.
pub async fn chain_spends_for_wallet(
    data_dir: &Path,
    network: P2pNetwork,
    wallet_keys: &[[u8; 32]],
    extra_peers: &[String],
) -> (
    Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>,
    Option<String>,
) {
    let keys = scan_key_set(wallet_keys, &[]);
    if keys.is_empty() {
        return (None, None);
    }
    let (selected, wider_keys) = match select_wallet_checkpoint(data_dir, network, &keys) {
        Ok(selected) => selected,
        Err(notice) => return (None, Some(notice)),
    };
    let path = checkpoint_path(data_dir, &selected);
    let result = tokio::time::timeout(WALLET_EVIDENCE_BUDGET, async {
        let mut waits = Vec::new();
        let mut peer = connect_peer_with_budget(
            network,
            extra_peers,
            &[],
            WALLET_PEER_ACQUISITION_BUDGET,
            |wait| waits.push(wait),
        )
        .await?;
        let mut verifier = NetworkCursorVerifier {
            peer: &mut peer,
            network,
            peers: extra_peers,
            floor: network.sprout_scan_minimum_tip(),
            tip_anchor: None,
            checkpoint_file: &path,
            waits: &mut waits,
        };
        verified_checkpoint_lookup(data_dir, network, &selected, &mut verifier).await
    })
    .await;
    match result {
        Ok(lookup) => wallet_lookup_result(lookup, wider_keys),
        Err(_) => wallet_lookup_result(
            Err(ZeckError::ScanNotReady(format!(
                "live verification of the scan checkpoint at {} timed out after {} seconds",
                path.display(),
                WALLET_EVIDENCE_BUDGET.as_secs()
            ))),
            wider_keys,
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
    full_key_set_fingerprint(spending_keys)[..16].to_owned()
}

/// Full digest bound into a sweep journal header, guarding even a collision
/// in the short fingerprint used by deployed checkpoint and journal names.
pub fn full_key_set_fingerprint(spending_keys: &[[u8; 32]]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    // Deduplicated as well as sorted: [A, A] is the scan of [A], and must
    // name the same file.
    for key in &scan_key_set(spending_keys, &[]) {
        h.update(key);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
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

/// A header-only check of the saved cursor. The seam lets reconciliation be
/// tested without a socket or fabricated proof of work.
#[async_trait::async_trait]
trait CursorVerifier {
    async fn continuation(&mut self, locators: &[ScanCursor]) -> ZeckResult<CanonicalContinuation>;
}

#[derive(Debug)]
enum CanonicalContinuation {
    Current { chain_has_more: bool },
    CommonAncestor(ScanCursor),
}

fn beyond_retained_window(locators: &[ScanCursor], checkpoint_file: &Path) -> ZeckError {
    let old = locators.first().map_or(0, |c| c.last_height);
    let oldest = locators.last().map_or(old, |c| c.last_height);
    ZeckError::ScanNotReady(format!(
        "the saved Sprout scan at {} ended at height {old}, but the live chain \
         has no common ancestor among its retained cursors (oldest retained \
         height {oldest}). Argos will not use its spent-note evidence. \
         Please keep the original wallet or key and start a safe full rescan.",
        checkpoint_file.display()
    ))
}

/// Reconcile the scanner in memory. Wallet inspection uses the result only
/// while the original checkpoint bytes remain unchanged; a scan run persists
/// it before consuming another page.
async fn reconcile_cursor_in_memory<V: CursorVerifier>(
    scanner: &mut SproutScanner,
    verifier: &mut V,
    checkpoint_file: &Path,
) -> ZeckResult<bool> {
    let locators = scanner.rollback_locators();
    if locators.is_empty() {
        return match scanner.cursor() {
            None => Ok(false),
            Some(cursor) => Err(ZeckError::ScanNotReady(format!(
                "the saved Sprout scan at {} ended at height {} without a \
                 verifiable block-hash cursor. Argos will not use its \
                 spent-note evidence. Please keep the original wallet or key \
                 and start a safe full rescan.",
                checkpoint_file.display(),
                cursor.last_height
            ))),
        };
    }
    match verifier.continuation(&locators).await? {
        CanonicalContinuation::Current {
            chain_has_more: false,
        } => Ok(false),
        CanonicalContinuation::Current {
            chain_has_more: true,
        } => {
            if scanner.is_complete() {
                scanner.mark_incomplete();
                Ok(true)
            } else {
                Ok(false)
            }
        }
        CanonicalContinuation::CommonAncestor(ancestor) => {
            scanner
                .rewind_to(ancestor.last_block_hash)
                .map_err(|err| match err {
                    crate::sprout_scan::RewindError::BeyondRetainedWindow => {
                        beyond_retained_window(&locators, checkpoint_file)
                    }
                    other => ZeckError::TransactionBuild(format!(
                        "the rollback history in {} is inconsistent ({other}); \
                         keep the original wallet or key and start a safe full rescan.",
                        checkpoint_file.display()
                    )),
                })?;
            Ok(true)
        }
    }
}

/// Persist the verified state before a scan consumes another page. Failed
/// reconciliation leaves the checkpoint untouched.
#[cfg(test)]
async fn reconcile_cursor<V: CursorVerifier>(
    scanner: &mut SproutScanner,
    verifier: &mut V,
    network: P2pNetwork,
    checkpoint_file: &Path,
) -> ZeckResult<()> {
    let lease = CheckpointLease::acquire(checkpoint_file)?;
    if reconcile_cursor_in_memory(scanner, verifier, checkpoint_file).await? {
        save_checkpoint_while_leased(&lease, scanner, network, checkpoint_file)?;
    }
    Ok(())
}

/// Owns only the header validation phase; the same peer is handed to the
/// page fetcher after reconciliation succeeds.
struct NetworkCursorVerifier<'a> {
    peer: &'a mut Peer,
    network: P2pNetwork,
    peers: &'a [String],
    floor: u32,
    tip_anchor: Option<TipAnchor>,
    checkpoint_file: &'a Path,
    waits: &'a mut Vec<PeerWait>,
}

#[async_trait::async_trait]
impl CursorVerifier for NetworkCursorVerifier<'_> {
    async fn continuation(&mut self, locators: &[ScanCursor]) -> ZeckResult<CanonicalContinuation> {
        let rules = PinRules {
            network: self.network,
            floor: self.floor,
            tip_anchor: self.tip_anchor,
        };
        let checkpoint_file = self.checkpoint_file;
        let mut dialer = NetworkDialer {
            network: self.network,
            peers: self.peers,
            waits: self.waits,
        };
        let mut peer = RotatingHeaderPeer {
            conn: self.peer,
            network: self.network,
            dialer: &mut dialer,
            excluded: Vec::new(),
        };
        verify_continuation(&mut peer, &rules, locators, checkpoint_file).await
    }
}

/// How many distinct peers must independently answer from before every
/// retained cursor before Argos concludes the fork is deeper than its
/// rollback window. One peer saying so may simply not know this branch, or
/// may be lying to force a costly rescan.
const BEYOND_WINDOW_QUORUM: usize = 3;

/// The independent pins a header must agree with: the network's fixed
/// checkpoints and, when one was learned, the lightwalletd [`TipAnchor`].
struct PinRules {
    network: P2pNetwork,
    floor: u32,
    tip_anchor: Option<TipAnchor>,
}

impl PinRules {
    /// True when no pin at `height` contradicts `hash`.
    fn agrees(&self, height: u32, hash: [u8; 32]) -> bool {
        crate::p2p::wire::checkpoint_at(self.network, height).is_none_or(|pin| pin == hash)
            && self
                .tip_anchor
                .filter(|anchor| anchor.height == height)
                .is_none_or(|anchor| anchor.hash == hash)
    }
}

/// A source of headers that can move on to another peer. The network
/// implementation validates proof of work, size and linkage before handing
/// headers over, so [`verify_continuation`] judges only what they say.
#[async_trait::async_trait]
trait HeaderPeer: Send {
    fn peer_height(&self) -> u32;
    fn peer_id(&self) -> String;
    /// Validated headers following `locators`, or why this peer's reply
    /// could not be used.
    async fn validated_headers(
        &mut self,
        locators: &[[u8; 32]],
    ) -> Result<Vec<crate::p2p::wire::BlockHeader>, String>;
    async fn next_peer(&mut self) -> ZeckResult<()>;
}

/// One live connection's header answers, validated for proof of work and
/// linkage. Separate from [`HeaderPeer`] so the rotation policy in
/// [`RotatingHeaderPeer`] can be tested without a network.
#[async_trait::async_trait]
trait HeaderConnection: Send {
    fn peer_height(&self) -> u32;
    fn dialled_as(&self) -> &str;
    async fn validated_headers(
        &mut self,
        network: P2pNetwork,
        locators: &[[u8; 32]],
    ) -> Result<Vec<crate::p2p::wire::BlockHeader>, String>;
    async fn close(&mut self);
}

#[async_trait::async_trait]
impl HeaderConnection for Peer {
    fn peer_height(&self) -> u32 {
        self.peer_height
    }

    fn dialled_as(&self) -> &str {
        Peer::dialled_as(self)
    }

    async fn validated_headers(
        &mut self,
        network: P2pNetwork,
        locators: &[[u8; 32]],
    ) -> Result<Vec<crate::p2p::wire::BlockHeader>, String> {
        let headers = self
            .get_headers(locators)
            .await
            .map_err(|err| err.to_string())?;
        let valid_work = headers.len() <= crate::p2p::peer::MAX_PAGE_BLOCKS
            && headers
                .iter()
                .all(|h| crate::p2p::wire::verify_header_pow(network, h).is_ok());
        let valid_links = headers
            .windows(2)
            .all(|pair| pair[1].prev_hash == pair[0].hash);
        if valid_work && valid_links {
            Ok(headers)
        } else {
            Err("peer returned invalid header work or linkage".to_owned())
        }
    }

    async fn close(&mut self) {
        Peer::close(self).await;
    }
}

/// Opens a new connection, skipping every address whose exclusion has not
/// yet expired.
#[async_trait::async_trait]
trait PeerDialer<C>: Send {
    async fn dial(&mut self, excluded: &[(String, tokio::time::Instant)]) -> ZeckResult<C>;
}

struct NetworkDialer<'a, 'b> {
    network: P2pNetwork,
    peers: &'a [String],
    waits: &'b mut Vec<PeerWait>,
}

#[async_trait::async_trait]
impl PeerDialer<Peer> for NetworkDialer<'_, '_> {
    async fn dial(&mut self, excluded: &[(String, tokio::time::Instant)]) -> ZeckResult<Peer> {
        let waits = &mut *self.waits;
        connect_peer(self.network, self.peers, excluded, |wait| waits.push(wait)).await
    }
}

/// A [`HeaderPeer`] over one connection at a time, moving to another when
/// asked.
///
/// [`verify_continuation`] rotates only away from a peer whose answer it
/// could not use — a fault, silence, or headers from before every retained
/// cursor — so the peer being left is excluded for [`PEER_RECONNECT_DELAY`],
/// whatever it did. Excluding only silent peers let a fast hostile peer win
/// every reconnection race and spend every attempt by itself.
struct RotatingHeaderPeer<'a, C, D> {
    conn: &'a mut C,
    network: P2pNetwork,
    dialer: &'a mut D,
    excluded: Vec<(String, tokio::time::Instant)>,
}

#[async_trait::async_trait]
impl<C, D> HeaderPeer for RotatingHeaderPeer<'_, C, D>
where
    C: HeaderConnection,
    D: PeerDialer<C>,
{
    fn peer_height(&self) -> u32 {
        self.conn.peer_height()
    }

    fn peer_id(&self) -> String {
        self.conn.dialled_as().to_owned()
    }

    async fn validated_headers(
        &mut self,
        locators: &[[u8; 32]],
    ) -> Result<Vec<crate::p2p::wire::BlockHeader>, String> {
        self.conn.validated_headers(self.network, locators).await
    }

    async fn next_peer(&mut self) -> ZeckResult<()> {
        self.excluded.push((
            self.conn.dialled_as().to_owned(),
            tokio::time::Instant::now() + PEER_RECONNECT_DELAY,
        ));
        self.conn.close().await;
        *self.conn = self.dialer.dial(&self.excluded).await?;
        Ok(())
    }
}

/// One peer's answer about the saved cursor.
enum PeerVerdict {
    Settled(CanonicalContinuation),
    /// This peer's answer cannot be used; another may do better.
    Fault(String),
    /// This peer's headers start before every retained cursor.
    BeyondWindow,
}

/// Ask one peer where the saved cursor stands.
async fn judge_peer<P: HeaderPeer + ?Sized>(
    peer: &mut P,
    rules: &PinRules,
    locators: &[ScanCursor],
    checkpoint_file: &Path,
) -> ZeckResult<PeerVerdict> {
    let saved = locators[0];
    let hashes: Vec<_> = locators.iter().map(|c| c.last_block_hash).collect();
    let headers = match peer.validated_headers(&hashes).await {
        Ok(headers) => headers,
        Err(failure) => return Ok(PeerVerdict::Fault(failure)),
    };
    if headers.is_empty() {
        if !crate::p2p::wire::empty_reply_is_chain_tip(
            first_scan_height(Some(saved)),
            rules.floor,
            peer.peer_height(),
        ) {
            return Ok(PeerVerdict::Fault(format!(
                "peer reported no headers after height {} despite a known tip of {}",
                saved.last_height,
                rules.floor.max(peer.peer_height())
            )));
        }
        // "Nothing after it" is only believable for a block the pins accept,
        // and only once a header fetched from a retained predecessor shows
        // the saved block is on this peer's active chain.
        if !rules.agrees(saved.last_height, saved.last_block_hash) {
            return Ok(PeerVerdict::Fault(format!(
                "peer called the saved cursor the tip, but it disagrees with a pinned block at height {}",
                saved.last_height
            )));
        }
        // Local, not the peer's fault: no other peer can supply history this
        // checkpoint does not retain.
        let Some(parent) = locators.get(1).copied() else {
            return Err(ZeckError::ScanNotReady(format!(
                "the peer returned no headers after the saved Sprout cursor at {}, and no retained predecessor can prove that cursor is on the current chain. Argos will not use its spent-note evidence; keep the original wallet or key and start a safe full rescan if needed.",
                checkpoint_file.display()
            )));
        };
        let probe = match peer.validated_headers(&[parent.last_block_hash]).await {
            Ok(probe) => probe,
            Err(failure) => return Ok(PeerVerdict::Fault(failure)),
        };
        let Some(first) = probe.first() else {
            return Ok(PeerVerdict::Fault(
                "peer supplied no validated header overlapping the saved Sprout cursor".to_owned(),
            ));
        };
        if first.prev_hash != parent.last_block_hash {
            return Ok(
                if locators
                    .iter()
                    .any(|c| c.last_block_hash == first.prev_hash)
                {
                    PeerVerdict::Fault(
                        "peer answered the tip probe from a block other than the one asked for"
                            .to_owned(),
                    )
                } else {
                    PeerVerdict::BeyondWindow
                },
            );
        }
        if !pins_agree(rules, parent, &probe) {
            return Ok(PeerVerdict::Fault(
                "peer returned a header that disagrees with a pinned block".to_owned(),
            ));
        }
        return Ok(PeerVerdict::Settled(
            if first.hash == saved.last_block_hash {
                // The saved block is on the active chain. Anything after it in
                // the probe arrived since the empty reply: an honest race, and
                // the scan simply has more to read.
                CanonicalContinuation::Current {
                    chain_has_more: probe.len() > 1,
                }
            } else {
                CanonicalContinuation::CommonAncestor(parent)
            },
        ));
    }
    // An answer from before every retained hash is a deep reorg, or a peer
    // that does not know this branch. No height can be assigned to it.
    let Some(ancestor) = locators
        .iter()
        .find(|c| c.last_block_hash == headers[0].prev_hash)
        .copied()
    else {
        return Ok(PeerVerdict::BeyondWindow);
    };
    if !pins_agree(rules, ancestor, &headers) {
        return Ok(PeerVerdict::Fault(
            "peer returned a header that disagrees with a pinned block".to_owned(),
        ));
    }
    Ok(PeerVerdict::Settled(if ancestor == saved {
        CanonicalContinuation::Current {
            chain_has_more: true,
        }
    } else {
        CanonicalContinuation::CommonAncestor(ancestor)
    }))
}

/// `ancestor` and every header after it agree with the pins at their heights.
fn pins_agree(
    rules: &PinRules,
    ancestor: ScanCursor,
    headers: &[crate::p2p::wire::BlockHeader],
) -> bool {
    rules.agrees(ancestor.last_height, ancestor.last_block_hash)
        && headers.iter().enumerate().all(|(offset, header)| {
            u32::try_from(offset)
                .ok()
                .and_then(|offset| ancestor.last_height.checked_add(1)?.checked_add(offset))
                .is_some_and(|height| rules.agrees(height, header.hash))
        })
}

/// Where the saved cursor stands on the live chain, asking peer after peer
/// until one gives a usable answer. A single peer cannot end verification
/// with a "rescan" verdict: an unusable answer only rotates to the next
/// peer, and the fork is declared deeper than the retained window only when
/// [`BEYOND_WINDOW_QUORUM`] distinct peers independently say so.
async fn verify_continuation<P: HeaderPeer + ?Sized>(
    peer: &mut P,
    rules: &PinRules,
    locators: &[ScanCursor],
    checkpoint_file: &Path,
) -> ZeckResult<CanonicalContinuation> {
    let mut failures = 0u32;
    let mut beyond: Vec<String> = Vec::new();
    loop {
        let failure = match judge_peer(peer, rules, locators, checkpoint_file).await? {
            PeerVerdict::Settled(continuation) => return Ok(continuation),
            PeerVerdict::Fault(failure) => failure,
            PeerVerdict::BeyondWindow => {
                let id = peer.peer_id();
                if !beyond.contains(&id) {
                    beyond.push(id);
                }
                if beyond.len() >= BEYOND_WINDOW_QUORUM {
                    return Err(beyond_retained_window(locators, checkpoint_file));
                }
                "peer served headers that start before every retained Sprout cursor".to_owned()
            }
        };
        failures += 1;
        if failures > MAX_EMPTY_REPLIES {
            return Err(ZeckError::Broadcast(format!(
                "{failures} attempts to verify the saved Sprout cursor failed; \
                 the most recent: {failure}. The checkpoint was left unchanged."
            )));
        }
        peer.next_peer().await.map_err(|err| {
            ZeckError::Broadcast(format!(
                "verifying the saved Sprout cursor failed ({failure}), and no other \
                 peer could be reached ({err}). The checkpoint was left unchanged."
            ))
        })?;
    }
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
    progress: impl FnMut(ScanTick),
) -> ZeckResult<SproutScanResult> {
    run_sprout_scan_with_decrypt_from(
        spending_keys,
        network,
        extra_peers,
        tip_anchor,
        checkpoint_file,
        None,
        progress,
    )
    .await
}

/// [`run_sprout_scan`], not trial-decrypting blocks below `decrypt_from`.
///
/// The walk is unchanged: it still starts at block 1 and appends every
/// commitment, so the tree, its root and every witness are exactly those of
/// an unbounded scan — only notes paid below the bound go unfound. The bound
/// must therefore come from evidence that the keys did not exist before it
/// (`birthday::sprout_skip_height`), and the bound actually used is returned
/// in [`SproutScanResult::decrypt_from_height`] for the caller to state.
///
/// The bound is saved in the checkpoint. A resume continues under it, or
/// fails with [`DecryptBoundConflict`]'s explanation when the request would
/// need blocks already walked to be decrypted — see
/// [`reconcile_decrypt_from`].
pub async fn run_sprout_scan_with_decrypt_from(
    spending_keys: &[[u8; 32]],
    network: P2pNetwork,
    extra_peers: &[String],
    tip_anchor: Option<TipAnchor>,
    checkpoint_file: &Path,
    decrypt_from: Option<u32>,
    mut progress: impl FnMut(ScanTick),
) -> ZeckResult<SproutScanResult> {
    if spending_keys.is_empty() {
        return Err(ZeckError::TransactionBuild(
            "a Sprout scan needs at least one spending key".to_owned(),
        ));
    }
    // Held across load, reconciliation and every atomic replacement. A
    // reviewed sweep proposal holds the same stable sidecar lock, so a scan
    // cannot replace the exact checkpoint while cleanup authority is live.
    let checkpoint_lease = CheckpointLease::acquire(checkpoint_file)?;

    // `fetched` counts blocks, so reaching the anchor's height means having
    // fetched one past it.
    let floor = tip_anchor
        .map_or(0, |anchor| anchor.height.saturating_add(1))
        .max(network.sprout_scan_minimum_tip());

    // lightwalletd's tip is the one height known to be on the chain before
    // any peer is reached. A requested bound above it is dropped here, before
    // the resume check, so a checkpoint that walked under such a bound is
    // refused rather than continued under it.
    let decrypt_from = bound_within_tip(decrypt_from, tip_anchor.map(|anchor| anchor.height));

    // Resume if we can. A checkpoint that will not load is reported rather
    // than silently discarded: starting a six-hour scan over because a file
    // was quietly ignored is worse than stopping to say so.
    let mut scanner = match load_checkpoint_while_leased(
        &checkpoint_lease,
        checkpoint_file,
        network,
        spending_keys,
    )? {
        Some(mut resumed) => {
            let bound = reconcile_decrypt_from(
                resumed.decrypt_from_height(),
                resumed.cursor().map(|c| c.last_height),
                decrypt_from,
            )
            .map_err(|conflict| conflict.into_error(checkpoint_file))?;
            resumed.set_decrypt_from(bound);
            resumed
        }
        None => SproutScanner::with_decrypt_from(spending_keys, decrypt_from),
    };

    let mut height = first_scan_height(scanner.cursor());

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

    let mut initial_waits = Vec::new();
    let mut peer = connect_peer(network, extra_peers, &[], |wait| initial_waits.push(wait)).await?;
    if scanner.cursor().is_some() {
        let mut verifier = NetworkCursorVerifier {
            peer: &mut peer,
            network,
            peers: extra_peers,
            floor,
            tip_anchor,
            checkpoint_file,
            waits: &mut initial_waits,
        };
        if reconcile_cursor_in_memory(&mut scanner, &mut verifier, checkpoint_file).await? {
            save_checkpoint_while_leased(&checkpoint_lease, &scanner, network, checkpoint_file)?;
        }
        height = first_scan_height(scanner.cursor());
    }
    for wait in initial_waits {
        progress(waiting_tick(&scanner, height, wait));
    }
    let locator = scanner.cursor().map_or([0u8; 32], |c| c.last_block_hash);
    let mut since_checkpoint = 0u64;
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
            scanner.mark_incomplete();
            save_before_stopping_while_leased(
                &checkpoint_lease,
                &scanner,
                network,
                checkpoint_file,
            );
            return Err(ZeckError::Broadcast(format!(
                "the block download stopped unexpectedly at height {height}, before \
                 reaching the chain tip. Progress is saved; re-run to continue."
            )));
        };
        let page = match page {
            Ok(page) => page,
            Err(err) => {
                scanner.mark_incomplete();
                save_before_stopping_while_leased(
                    &checkpoint_lease,
                    &scanner,
                    network,
                    checkpoint_file,
                );
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
        // position.
        since_checkpoint += consume_page_or_save_while_leased(
            &checkpoint_lease,
            &mut scanner,
            &page,
            network,
            tip_anchor,
            &mut height,
            checkpoint_file,
        )?;

        if since_checkpoint >= CHECKPOINT_EVERY {
            save_checkpoint_while_leased(&checkpoint_lease, &scanner, network, checkpoint_file)?;
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
    save_checkpoint_while_leased(&checkpoint_lease, &scanner, network, checkpoint_file)?;
    let generation = checkpoint_lease.generation(checkpoint_file)?;
    checkpoint_lease.verify_for(checkpoint_file)?;
    let mut result = scanner
        .finish()
        .map_err(|err| ZeckError::TransactionBuild(format!("finishing the scan: {err}")))?;
    result.checkpoint_generation = Some(generation);
    Ok(result)
}

/// One page of blocks, in chain order: each block's hash and the JoinSplits
/// of its authenticated body, with the first header's parent for the
/// consumer to compare against the last accepted scanner cursor.
struct Page {
    parent: [u8; 32],
    blocks: Vec<([u8; 32], Vec<argos_wallet_import::keys::SproutJoinSplit>)>,
}

impl Page {
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }
}

/// [`consume_page`], saving on the way out of a failure: the scanner is
/// marked incomplete and checkpointed, so the saved-progress claim in the
/// error holds and a re-run resumes rather than starting over.
#[cfg(test)]
fn consume_page_or_save(
    scanner: &mut SproutScanner,
    page: &Page,
    network: P2pNetwork,
    tip_anchor: Option<TipAnchor>,
    height: &mut u32,
    checkpoint_file: &Path,
) -> ZeckResult<u64> {
    let lease = CheckpointLease::acquire(checkpoint_file)?;
    consume_page_or_save_while_leased(
        &lease,
        scanner,
        page,
        network,
        tip_anchor,
        height,
        checkpoint_file,
    )
}

fn consume_page_or_save_while_leased(
    lease: &CheckpointLease,
    scanner: &mut SproutScanner,
    page: &Page,
    network: P2pNetwork,
    tip_anchor: Option<TipAnchor>,
    height: &mut u32,
    checkpoint_file: &Path,
) -> ZeckResult<u64> {
    consume_page(scanner, page, network, tip_anchor, height).inspect_err(|_| {
        scanner.mark_incomplete();
        save_before_stopping_while_leased(lease, scanner, network, checkpoint_file);
    })
}

/// Check one page, then scan it, advancing `height` past it.
///
/// A branch switch is rejected before a single body is used. On that error
/// the caller saves only the scanner state from the last consistent page;
/// the next invocation verifies that cursor against live headers again.
///
/// Every hash in the page is then checked against the pinned checkpoints and
/// the [`TipAnchor`] before any block of it is scanned. A pinned block must
/// be the block we were handed: cheap forged headers link to each other
/// fine, but they cannot reproduce a real mainnet hash at a real height
/// without doing the work. The checkpoints are keyed by true heights
/// (genesis = 0), so each block is checked at its own height.
///
/// On a mismatch the scan stops — fail closed — and the state the caller
/// saves ends at the last block of the previous page. Checking the whole
/// page up front is what makes that possible: no block of the mismatching
/// page, including those before the mismatch (they came from the same peer,
/// and the forgery may begin anywhere in the page), has reached the scanner.
fn consume_page(
    scanner: &mut SproutScanner,
    page: &Page,
    network: P2pNetwork,
    tip_anchor: Option<TipAnchor>,
    height: &mut u32,
) -> ZeckResult<u64> {
    if scanner
        .cursor()
        .is_some_and(|cursor| page.parent != cursor.last_block_hash)
    {
        return Err(ZeckError::ScanNotReady(format!(
            "a chain reorganization was detected before height {height}: the peer's \
             next blocks no longer follow the last block scanned. The scan is \
             incomplete and stopped without using them. Progress is saved. Re-run the \
             scan and it will verify its cursor, roll back to the common ancestor \
             and continue on the current chain."
        )));
    }
    let pins = PinRules {
        network,
        floor: 0,
        tip_anchor,
    };
    for (offset, (hash, _)) in page.blocks.iter().enumerate() {
        let at = *height + offset as u32;
        if !pins.agrees(at, *hash) {
            let saved = match scanner.cursor() {
                Some(cursor) => format!("Progress up to height {} is saved.", cursor.last_height),
                None => "Nothing had been scanned yet.".to_owned(),
            };
            return Err(ZeckError::Broadcast(format!(
                "the chain this peer served does not match Zcash at height {at}. It is \
                 serving a different or fabricated chain, so the scan stops rather than \
                 search it. {saved} Re-run to pick another peer, or pass --peer with a \
                 node you trust."
            )));
        }
    }
    let mut consumed = 0;
    for (hash, joinsplits) in &page.blocks {
        scanner
            .scan_block_at(joinsplits, *hash, *height)
            .map_err(|err| {
                ZeckError::TransactionBuild(format!("scanning height {height}: {err}"))
            })?;
        consumed += 1;
        *height += 1;
    }
    Ok(consumed)
}

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
    /// continuity with the locator, the internal linkage of the page, and
    /// each body's authentication against its header
    /// ([`Self::authenticate_page`]). A failure of any of them is charged to
    /// the serving peer and the page refetched from another.
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
                    return Ok(Some(Page {
                        parent: self.locator,
                        blocks: Vec::new(),
                    }));
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
        let blocks = match self.peer.get_blocks(&hashes).await {
            Ok(b) => b,
            Err(err) => return self.on_request_failure(err, height).await,
        };
        let parent = headers[0].prev_hash;
        self.authenticate_page(&hashes, parent, blocks, height)
            .await
    }

    /// Turn the bodies fetched for `hashes` into a page, or reject them.
    ///
    /// `hashes` come from headers that have already passed proof of work and
    /// linkage; `blocks` are what the peer sent for them, keyed by the hash
    /// recomputed from each block's own header bytes.
    async fn authenticate_page(
        &mut self,
        hashes: &[[u8; 32]],
        parent: [u8; 32],
        mut blocks: std::collections::HashMap<[u8; 32], Vec<u8>>,
        height: u32,
    ) -> ZeckResult<Option<Page>> {
        // Assembled in header order, so the consumer receives the page already
        // in chain order and never has to trust the peer's reply order.
        //
        // A missing block is a hard error, not a gap. Filtering it out would
        // hand the consumer a shorter page that still looks well-formed, and
        // every commitment after it would land at the wrong position — the
        // scan would finish clean and the notes would be unspendable.
        let mut page = Page {
            parent,
            blocks: Vec::with_capacity(hashes.len()),
        };
        for (offset, hash) in hashes.iter().enumerate() {
            let Some(block) = blocks.remove(hash) else {
                return Err(ZeckError::Broadcast(format!(
                    "a peer did not return the block at height {}. The scan cannot skip \
                     it without corrupting every later note, so it stops. Progress is \
                     saved; re-run to continue.",
                    height + offset as u32
                )));
            };
            // The body must be the one the authenticated header commits to:
            // every declared transaction parsed, nothing trailing, and the
            // txid Merkle root equal to the header's. A body that fails is
            // the serving peer's fault — the header and so the hash we asked
            // for are already proven — so it is handled like any other bad
            // reply: rotate, charge the budget, and fetch this same page
            // again from the next peer (the locator has not moved). Fail
            // closed: nothing reaches the consumer unless this returned `Ok`.
            //
            // The branch id is only consulted for pre-v5 transactions, whose
            // encoding it does not change; v5 carries its own. Sprout
            // JoinSplits exist only in v2-v4, before and after Canopy alike.
            let joinsplits = match joinsplits_in_block(&block, BranchId::Canopy) {
                Ok(joinsplits) => joinsplits,
                Err(err) => {
                    let at = height + offset as u32;
                    return self
                        .rotate(format!(
                            "{} attempts in a row to fetch blocks from height {height} failed; \
                             the most recent served a body for the block at height {at} that \
                             does not match its header ({err}). The scan never uses an \
                             unauthenticated block, so it stops here. Progress is saved; \
                             re-run to pick other peers, or pass --peer with a node you trust.",
                            self.empty_replies + 1
                        ))
                        .await;
                }
            };
            page.blocks.push((*hash, joinsplits));
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
    let _lease = CheckpointLease::acquire(path)?;
    save_checkpoint_while_leased(&_lease, scanner, network, path)
}

fn save_checkpoint_while_leased(
    lease: &CheckpointLease,
    scanner: &SproutScanner,
    network: P2pNetwork,
    path: &Path,
) -> ZeckResult<()> {
    lease.verify_for(path)?;
    ensure_checkpoint_parent(path)?;
    // Written to a private create-new sibling, synced, and renamed while a
    // platform-correct parent-directory handle stays open. An interrupt
    // cannot leave a half-written checkpoint where a good one was, and a
    // Windows directory is never opened as an ordinary file after mutation.
    remove_stale_temp_files_while_leased(lease, path)?;
    lease.verify_for(path)?;
    let mut bytes = vec![NETWORK_TAGGED, network_tag(network)];
    bytes.extend_from_slice(scanner.checkpoint().as_bytes());
    crate::private_fs::write_private_file_atomic_in_parent(lease.namespace.parent(), path, &bytes)
        .map_err(|err| ZeckError::TransactionBuild(format!("replacing the scan checkpoint: {err}")))
}

/// Save on the way out of a failed scan, so the saved-progress claim in its
/// error holds. A failure to save is logged, not raised: the scan's own
/// error is the one the user needs to see.
#[cfg(test)]
fn save_before_stopping(scanner: &SproutScanner, network: P2pNetwork, path: &Path) {
    let lease = match CheckpointLease::acquire(path) {
        Ok(lease) => lease,
        Err(err) => {
            tracing::warn!("could not reserve the Sprout scan checkpoint while stopping: {err}");
            return;
        }
    };
    save_before_stopping_while_leased(&lease, scanner, network, path);
}

fn save_before_stopping_while_leased(
    lease: &CheckpointLease,
    scanner: &SproutScanner,
    network: P2pNetwork,
    path: &Path,
) {
    if let Err(err) = save_checkpoint_while_leased(lease, scanner, network, path) {
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

/// Delete a checkpoint and any abandoned temporary siblings.
///
/// Called once the funds it describes have been swept: it holds spending
/// keys, and leaving it behind is a standing risk for no remaining benefit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointDiscard {
    Removed,
    AlreadyAbsent,
}

#[cfg(test)]
static FAIL_CHECKPOINT_DISCARD: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn fail_checkpoint_discard(path: &Path) {
    *FAIL_CHECKPOINT_DISCARD.lock().unwrap() = Some(path.to_path_buf());
}

pub fn discard_checkpoint(path: &Path) -> ZeckResult<CheckpointDiscard> {
    let lease = CheckpointLease::acquire(path)?;
    match checkpoint_generation(path) {
        Ok(generation) => discard_checkpoint_generation_while_leased(&lease, path, &generation),
        Err(_) if !path.exists() => {
            let removed = discard_checkpoint_temporaries(&lease, path)?;
            let quarantines = checkpoint_discard_quarantines(&lease, path)?;
            if !quarantines.is_empty() {
                return Err(ZeckError::ScanNotReady(format!(
                    "checkpoint {} is absent but exact deletion quarantine {} remains; retained it because no manifested generation authorized deletion",
                    path.display(),
                    quarantines[0].display()
                )));
            }
            lease.sync_parent()?;
            Ok(if removed {
                CheckpointDiscard::Removed
            } else {
                CheckpointDiscard::AlreadyAbsent
            })
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn discard_checkpoint_generation_while_leased(
    lease: &CheckpointLease,
    path: &Path,
    expected: &CheckpointGeneration,
) -> ZeckResult<CheckpointDiscard> {
    discard_checkpoint_generation_while_leased_with_observer(lease, path, expected, || {})
}

fn discard_checkpoint_temporaries(lease: &CheckpointLease, path: &Path) -> ZeckResult<bool> {
    #[cfg(test)]
    if FAIL_CHECKPOINT_DISCARD
        .lock()
        .unwrap()
        .take_if(|failing| failing == path)
        .is_some()
    {
        return Err(ZeckError::TransactionBuild(
            "injected checkpoint deletion failure".into(),
        ));
    }
    lease.verify_for(path)?;
    let mut removed =
        crate::private_fs::discard_private_file_staging_in_parent(lease.namespace.parent(), path)
            .map_err(|err| {
            ZeckError::TransactionBuild(format!(
                "removing checkpoint private staging for {}: {err}",
                path.display()
            ))
        })?;
    lease.verify_for(path)?;
    // Checkpoints written before unique temp names used this fixed sibling.
    let fixed = path.with_extension("checkpoint.tmp");
    removed |= lease.remove_child(&fixed)?;
    for temp in unique_temp_siblings_in_parent(lease, path)? {
        removed |= lease.remove_child(&temp)?;
    }
    lease.verify_for(path)?;
    Ok(removed)
}

fn discard_checkpoint_generation_while_leased_with_observer(
    lease: &CheckpointLease,
    path: &Path,
    expected: &CheckpointGeneration,
    after_generation_check: impl FnOnce(),
) -> ZeckResult<CheckpointDiscard> {
    discard_checkpoint_generation_while_leased_with_observers(
        lease,
        path,
        expected,
        after_generation_check,
        |_| {},
    )
}

fn discard_checkpoint_generation_while_leased_with_observers(
    lease: &CheckpointLease,
    path: &Path,
    expected: &CheckpointGeneration,
    after_generation_check: impl FnOnce(),
    before_quarantine_delete: impl FnOnce(&Path),
) -> ZeckResult<CheckpointDiscard> {
    lease.verify_for(path)?;
    let mut removed = discard_checkpoint_temporaries(lease, path)?;
    let (resumed_removed, unexpected_quarantines) =
        discard_matching_checkpoint_quarantines(lease, path, expected)?;
    removed |= resumed_removed;
    if let Some(unexpected) = unexpected_quarantines.first() {
        if resumed_removed {
            lease.sync_parent()?;
        }
        return Err(ZeckError::ScanNotReady(format!(
            "checkpoint deletion quarantine {} does not match the manifested generation; preserved it for review",
            unexpected.display()
        )));
    }
    let file = match lease.open_child(path)? {
        Some(file) => file,
        None => {
            lease.sync_parent()?;
            return Ok(if removed {
                CheckpointDiscard::Removed
            } else {
                CheckpointDiscard::AlreadyAbsent
            });
        }
    };
    let current = checkpoint_generation_from_handle(&file, path)?;
    if &current != expected {
        return Err(ZeckError::ScanNotReady(format!(
            "checkpoint {} changed immediately before deletion",
            path.display()
        )));
    }

    // The test seam is deliberately after the generation was captured from
    // the open handle. Exact-object removal below must remain safe even when
    // the path is replaced in this window.
    after_generation_check();
    lease.verify_for(path)?;
    let quarantine = checkpoint_discard_quarantine(path)?;
    lease.rename_child(path, &quarantine)?;
    lease.sync_parent()?;
    let moved_file = lease.open_child(&quarantine)?.ok_or_else(|| {
        ZeckError::ScanNotReady("checkpoint quarantine disappeared before verification".into())
    })?;
    let moved = checkpoint_generation_from_handle(&moved_file, &quarantine)?;
    if &moved != expected {
        restore_unexpected_checkpoint(lease, &quarantine, path)?;
        return Err(ZeckError::ScanNotReady(format!(
            "checkpoint {} was replaced at the deletion boundary; the replacement was preserved",
            path.display()
        )));
    }
    before_quarantine_delete(&quarantine);
    // Windows deletes the retained handle itself. Unix has no portable
    // unlink-by-handle primitive, so private_fs performs a final identity
    // recheck immediately before unlinkat. The namespace lease excludes all
    // cooperating writers; a hostile same-UID process can still race the
    // final open-to-unlink syscall gap, which is surfaced as a platform limit.
    lease.remove_open_child(&quarantine, &moved_file, &moved.object)?;
    removed = true;
    lease.sync_parent()?;
    Ok(if removed {
        CheckpointDiscard::Removed
    } else {
        CheckpointDiscard::AlreadyAbsent
    })
}

fn checkpoint_discard_prefix(path: &Path) -> ZeckResult<String> {
    let name = path
        .file_name()
        .ok_or_else(|| ZeckError::TransactionBuild("checkpoint path has no file name".into()))?;
    Ok(format!(
        ".argos-checkpoint-discard-{:x}-",
        Sha256::digest(name.as_encoded_bytes())
    ))
}

fn checkpoint_discard_quarantine(path: &Path) -> ZeckResult<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = checkpoint_discard_prefix(path)?;
    Ok(parent.join(format!("{prefix}{}", uuid::Uuid::new_v4())))
}

fn checkpoint_discard_quarantines(
    lease: &CheckpointLease,
    path: &Path,
) -> ZeckResult<Vec<PathBuf>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = checkpoint_discard_prefix(path)?;
    Ok(lease
        .child_names()?
        .into_iter()
        .filter(|name| {
            name.to_str()
                .and_then(|name| name.strip_prefix(&prefix))
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        })
        .map(|name| parent.join(name))
        .collect())
}

fn discard_matching_checkpoint_quarantines(
    lease: &CheckpointLease,
    path: &Path,
    expected: &CheckpointGeneration,
) -> ZeckResult<(bool, Vec<PathBuf>)> {
    let mut removed = false;
    let mut unexpected = Vec::new();
    for quarantine in checkpoint_discard_quarantines(lease, path)? {
        let file = lease
            .open_child(&quarantine)?
            .ok_or_else(|| ZeckError::ScanNotReady("checkpoint quarantine disappeared".into()))?;
        let current = checkpoint_generation_from_handle(&file, &quarantine)?;
        if &current != expected {
            unexpected.push(quarantine);
            continue;
        }
        lease.remove_open_child(&quarantine, &file, &current.object)?;
        removed = true;
    }
    Ok((removed, unexpected))
}

fn restore_unexpected_checkpoint(
    lease: &CheckpointLease,
    quarantine: &Path,
    path: &Path,
) -> ZeckResult<()> {
    match lease.rename_child(quarantine, path) {
        Ok(()) => lease.sync_parent(),
        Err(ZeckError::TransactionBuild(ref message)) if message.contains("exists") => {
            Err(ZeckError::ScanNotReady(format!(
                "a replacement checkpoint already exists at {}; preserved the raced object at {}",
                path.display(),
                quarantine.display()
            )))
        }
        Err(err) => Err(err),
    }
}

/// How old a unique temp sibling must be before it is taken for a crashed
/// writer's leftover. A save writes and renames within seconds; this is far
/// past that, so a concurrent scan's file in progress is never touched.
const STALE_TEMP_AGE: Duration = Duration::from_secs(10 * 60);

fn remove_stale_temp_files_while_leased(lease: &CheckpointLease, path: &Path) -> ZeckResult<()> {
    crate::private_fs::remove_stale_private_file_staging_in_parent(
        lease.namespace.parent(),
        path,
        STALE_TEMP_AGE,
    )
    .map_err(|err| {
        ZeckError::TransactionBuild(format!(
            "removing stale checkpoint staging for {}: {err}",
            path.display()
        ))
    })?;
    let now = std::time::SystemTime::now();
    for temp in unique_temp_siblings_in_parent(lease, path)? {
        let stale = lease
            .open_child(&temp)?
            .and_then(|file| file.metadata().ok())
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= STALE_TEMP_AGE);
        if stale {
            lease.remove_child(&temp)?;
        }
    }
    lease.sync_parent()
}

fn unique_temp_siblings_in_parent(
    lease: &CheckpointLease,
    path: &Path,
) -> ZeckResult<Vec<PathBuf>> {
    let temp_base = path.with_extension("checkpoint");
    let Some(name) = temp_base.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let prefix = format!("{name}.");
    Ok(lease
        .child_names()?
        .into_iter()
        .filter(|name| {
            name.to_str()
                .and_then(|name| name.strip_prefix(&prefix))
                .and_then(|name| name.strip_suffix(".tmp"))
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        })
        .map(|name| lease.namespace.parent_path().join(name))
        .collect())
}

/// Take a peer, racing candidates.
///
/// `excluded` names peers to skip until their timestamp passes. The cursor
/// verifier puts every peer it rotates away from on that list for
/// [`PEER_RECONNECT_DELAY`], whether the peer went silent, faulted, or
/// answered "beyond the retained window", so one fast hostile peer cannot win
/// every race and block verification. Within a pass, `connect_to_any` races a
/// fresh batch of the remaining addresses.
///
/// Across passes no further bookkeeping is needed: when a whole pass is
/// refused, [`acquire_with_retry`] waits out the reconnect window before the
/// next one, so by the time any address is dialled again every peer has
/// forgotten the last attempt.
///
/// `on_wait` hears about each such wait, so the caller can show that the scan
/// is alive and waiting on purpose.
async fn connect_peer(
    network: P2pNetwork,
    extra: &[String],
    excluded: &[(String, tokio::time::Instant)],
    on_wait: impl FnMut(PeerWait),
) -> ZeckResult<Peer> {
    connect_peer_with_budget(network, extra, excluded, PEER_ACQUISITION_BUDGET, on_wait).await
}

async fn connect_peer_with_budget(
    network: P2pNetwork,
    extra: &[String],
    excluded: &[(String, tokio::time::Instant)],
    requested_budget: Duration,
    on_wait: impl FnMut(PeerWait),
) -> ZeckResult<Peer> {
    // Regtest gets no patience. Its only candidates are the addresses the
    // caller named, there is no public capacity to free up, and a refusal
    // means the node is down — which a test should learn at once, not after
    // a quarter of an hour.
    let budget = if matches!(network, P2pNetwork::Regtest) {
        Duration::ZERO
    } else {
        requested_budget
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

    struct FakeCursorVerifier {
        response: Option<CanonicalContinuation>,
        seen: Vec<ScanCursor>,
    }

    #[async_trait::async_trait]
    impl CursorVerifier for FakeCursorVerifier {
        async fn continuation(
            &mut self,
            locators: &[ScanCursor],
        ) -> ZeckResult<CanonicalContinuation> {
            self.seen = locators.to_vec();
            self.response.take().ok_or_else(|| {
                ZeckError::ScanNotReady("live cursor verification is unavailable".to_owned())
            })
        }
    }

    /// A connection for [`RotatingHeaderPeer`]: a fixed script of answers,
    /// identified by the address it was dialled as.
    struct FakeConnection {
        id: String,
        replies: std::collections::VecDeque<Result<Vec<crate::p2p::wire::BlockHeader>, String>>,
    }

    #[async_trait::async_trait]
    impl HeaderConnection for FakeConnection {
        fn peer_height(&self) -> u32 {
            0
        }

        fn dialled_as(&self) -> &str {
            &self.id
        }

        async fn validated_headers(
            &mut self,
            _network: P2pNetwork,
            _locators: &[[u8; 32]],
        ) -> Result<Vec<crate::p2p::wire::BlockHeader>, String> {
            self.replies
                .pop_front()
                .unwrap_or_else(|| Err("script exhausted".to_owned()))
        }

        async fn close(&mut self) {}
    }

    /// A pool in which the hostile peer always wins the race: every dial
    /// returns the first candidate not currently excluded, hostile first.
    /// The hostile peer answers the same unusable thing every time it is
    /// asked, so only an exclusion lets the honest peer be reached.
    struct FastHostilePool {
        hostile: Result<Vec<crate::p2p::wire::BlockHeader>, String>,
        honest: Result<Vec<crate::p2p::wire::BlockHeader>, String>,
        dialled: Vec<String>,
    }

    impl FastHostilePool {
        fn connection(&self, id: &str) -> FakeConnection {
            let reply = if id == "hostile" {
                self.hostile.clone()
            } else {
                self.honest.clone()
            };
            FakeConnection {
                id: id.to_owned(),
                replies: std::iter::repeat_n(reply, 4).collect(),
            }
        }
    }

    #[async_trait::async_trait]
    impl PeerDialer<FakeConnection> for FastHostilePool {
        async fn dial(
            &mut self,
            excluded: &[(String, tokio::time::Instant)],
        ) -> ZeckResult<FakeConnection> {
            let now = tokio::time::Instant::now();
            let id = ["hostile", "honest"]
                .into_iter()
                .find(|id| !excluded.iter().any(|(a, until)| a == id && now < *until))
                .ok_or_else(|| ZeckError::Broadcast("every candidate is excluded".to_owned()))?;
            self.dialled.push(id.to_owned());
            Ok(self.connection(id))
        }
    }

    async fn verify_against_fast_hostile_peer(
        hostile: Result<Vec<crate::p2p::wire::BlockHeader>, String>,
    ) -> (ZeckResult<CanonicalContinuation>, Vec<String>) {
        let mut pool = FastHostilePool {
            hostile,
            honest: Ok(vec![hdr(4, 3)]),
            dialled: Vec::new(),
        };
        let mut conn = pool.connection("hostile");
        let mut peer = RotatingHeaderPeer {
            conn: &mut conn,
            network: P2pNetwork::Regtest,
            dialer: &mut pool,
            excluded: Vec::new(),
        };
        let result = verify_continuation(
            &mut peer,
            &regtest_rules(),
            &three_locators(),
            Path::new("unused.checkpoint"),
        )
        .await;
        (result, pool.dialled)
    }

    /// Review of #272, round 2: rotation excluded only silent peers, so a
    /// fast peer that had just faulted was dialled straight back and could
    /// exhaust every attempt on its own. Now the peer being rotated away
    /// from is skipped for `PEER_RECONNECT_DELAY`, whatever it did.
    #[tokio::test]
    async fn a_peer_that_faulted_is_not_redialled_before_an_honest_one() {
        let (result, dialled) =
            verify_against_fast_hostile_peer(Err("invalid header work".to_owned())).await;
        assert!(
            matches!(
                result,
                Ok(CanonicalContinuation::Current {
                    chain_has_more: true
                })
            ),
            "the honest peer settles it: {:?}",
            result.err()
        );
        assert_eq!(dialled, vec!["honest"]);
    }

    /// The same for a peer that answers from beyond the retained window: one
    /// such answer must not let it be asked again and again.
    #[tokio::test]
    async fn a_peer_that_answered_beyond_the_window_is_not_redialled() {
        let (result, dialled) = verify_against_fast_hostile_peer(Ok(vec![hdr(9, 8)])).await;
        assert!(
            matches!(
                result,
                Ok(CanonicalContinuation::Current {
                    chain_has_more: true
                })
            ),
            "the honest peer settles it: {:?}",
            result.err()
        );
        assert_eq!(dialled, vec!["honest"]);
    }

    /// A scripted sequence of peers for [`verify_continuation`]. Headers are
    /// handed over as already validated, which is what the network
    /// implementation guarantees before the judgment runs.
    struct ScriptedPeer {
        id: &'static str,
        height: u32,
        replies: std::collections::VecDeque<Result<Vec<crate::p2p::wire::BlockHeader>, String>>,
    }

    struct ScriptedPeers {
        current: ScriptedPeer,
        next: std::collections::VecDeque<ScriptedPeer>,
        asked: Vec<Vec<[u8; 32]>>,
        rotations: usize,
    }

    impl ScriptedPeers {
        fn new(mut peers: Vec<ScriptedPeer>) -> Self {
            let current = peers.remove(0);
            Self {
                current,
                next: peers.into(),
                asked: Vec::new(),
                rotations: 0,
            }
        }
    }

    #[async_trait::async_trait]
    impl HeaderPeer for ScriptedPeers {
        fn peer_height(&self) -> u32 {
            self.current.height
        }

        fn peer_id(&self) -> String {
            self.current.id.to_owned()
        }

        async fn validated_headers(
            &mut self,
            locators: &[[u8; 32]],
        ) -> Result<Vec<crate::p2p::wire::BlockHeader>, String> {
            self.asked.push(locators.to_vec());
            self.current
                .replies
                .pop_front()
                .unwrap_or_else(|| Err("script exhausted".to_owned()))
        }

        async fn next_peer(&mut self) -> ZeckResult<()> {
            self.rotations += 1;
            self.current = self
                .next
                .pop_front()
                .ok_or_else(|| ZeckError::Broadcast("no more scripted peers".to_owned()))?;
            Ok(())
        }
    }

    fn scripted(
        id: &'static str,
        replies: Vec<Result<Vec<crate::p2p::wire::BlockHeader>, String>>,
    ) -> ScriptedPeer {
        ScriptedPeer {
            id,
            height: 0,
            replies: replies.into(),
        }
    }

    fn hdr(hash: u8, prev: u8) -> crate::p2p::wire::BlockHeader {
        crate::p2p::wire::BlockHeader {
            hash: [hash; 32],
            prev_hash: [prev; 32],
            raw: Vec::new(),
        }
    }

    /// Newest first, as `rollback_locators` returns them: blocks 3, 2, 1
    /// with hashes equal to their heights.
    fn three_locators() -> Vec<ScanCursor> {
        (1..=3u8)
            .rev()
            .map(|h| ScanCursor {
                last_block_hash: [h; 32],
                last_height: u32::from(h),
            })
            .collect()
    }

    fn regtest_rules() -> PinRules {
        PinRules {
            network: P2pNetwork::Regtest,
            floor: 0,
            tip_anchor: None,
        }
    }

    #[tokio::test]
    async fn one_hostile_peer_then_an_honest_one_verifies_the_cursor() {
        let mut peers = ScriptedPeers::new(vec![
            // Headers that start before every retained cursor.
            scripted("hostile", vec![Ok(vec![hdr(0x99, 0x98)])]),
            scripted("honest", vec![Ok(vec![hdr(4, 3)])]),
        ]);
        let outcome = verify_continuation(
            &mut peers,
            &regtest_rules(),
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .expect("one hostile peer must not end verification");
        assert!(matches!(
            outcome,
            CanonicalContinuation::Current {
                chain_has_more: true
            }
        ));
        assert_eq!(peers.rotations, 1);
    }

    #[tokio::test]
    async fn beyond_the_window_needs_independent_peers_to_agree() {
        let mut peers = ScriptedPeers::new(vec![
            scripted("a", vec![Ok(vec![hdr(0x99, 0x98)])]),
            scripted("b", vec![Ok(vec![hdr(0x99, 0x98)])]),
            scripted("c", vec![Ok(vec![hdr(0x99, 0x98)])]),
        ]);
        let err = verify_continuation(
            &mut peers,
            &regtest_rules(),
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .expect_err("three independent peers agree");
        assert!(err.to_string().contains("safe full rescan"), "{err}");
        assert_eq!(peers.rotations, BEYOND_WINDOW_QUORUM - 1);
    }

    #[tokio::test]
    async fn one_peer_repeating_beyond_the_window_is_not_agreement() {
        let repeats = (0..=MAX_EMPTY_REPLIES)
            .map(|_| scripted("same", vec![Ok(vec![hdr(0x99, 0x98)])]))
            .collect();
        let mut peers = ScriptedPeers::new(repeats);
        let err = verify_continuation(
            &mut peers,
            &regtest_rules(),
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .expect_err("the budget runs out");
        let text = err.to_string();
        assert!(!text.contains("safe full rescan"), "{text}");
        assert!(text.contains("left unchanged"), "{text}");
    }

    #[tokio::test]
    async fn a_peer_that_cannot_back_its_empty_tip_reply_is_rotated_away() {
        let mut peers = ScriptedPeers::new(vec![
            // Claims the saved block is the tip, then cannot show it.
            scripted("hostile", vec![Ok(Vec::new()), Ok(Vec::new())]),
            scripted("honest", vec![Ok(vec![hdr(4, 3)])]),
        ]);
        let outcome = verify_continuation(
            &mut peers,
            &regtest_rules(),
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .expect("an unbacked tip reply is the peer's fault");
        assert!(matches!(
            outcome,
            CanonicalContinuation::Current {
                chain_has_more: true
            }
        ));
        assert_eq!(peers.rotations, 1);
    }

    #[tokio::test]
    async fn an_empty_reply_contradicting_a_pin_is_rotated_away() {
        let rules = PinRules {
            tip_anchor: Some(TipAnchor {
                height: 3,
                hash: [0x77; 32],
            }),
            ..regtest_rules()
        };
        let mut peers = ScriptedPeers::new(vec![
            scripted("hostile", vec![Ok(Vec::new())]),
            scripted("honest", vec![Ok(vec![hdr(0x77, 2)])]),
        ]);
        let outcome = verify_continuation(
            &mut peers,
            &rules,
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .expect("the pin decides against the peer, not the checkpoint");
        assert!(matches!(
            outcome,
            CanonicalContinuation::CommonAncestor(ScanCursor { last_height: 2, .. })
        ));
        assert_eq!(peers.rotations, 1);
    }

    /// The honest race: the tip reply was empty, a block arrived, and the
    /// probe from the parent now shows the saved block and its child.
    #[tokio::test]
    async fn a_block_arriving_between_tip_and_probe_is_not_a_contradiction() {
        let mut peers = ScriptedPeers::new(vec![scripted(
            "honest",
            vec![Ok(Vec::new()), Ok(vec![hdr(3, 2), hdr(4, 3)])],
        )]);
        let outcome = verify_continuation(
            &mut peers,
            &regtest_rules(),
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .expect("an honest race verifies");
        assert!(matches!(
            outcome,
            CanonicalContinuation::Current {
                chain_has_more: true
            }
        ));
        assert_eq!(peers.rotations, 0);
        assert_eq!(peers.asked[1], vec![[2; 32]], "probed from the parent");
    }

    #[tokio::test]
    async fn an_empty_reply_backed_by_the_probe_is_the_tip() {
        let mut peers = ScriptedPeers::new(vec![scripted(
            "honest",
            vec![Ok(Vec::new()), Ok(vec![hdr(3, 2)])],
        )]);
        let outcome = verify_continuation(
            &mut peers,
            &regtest_rules(),
            &three_locators(),
            Path::new("scan.checkpoint"),
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            CanonicalContinuation::Current {
                chain_has_more: false
            }
        ));
    }

    struct ConcurrentWriteVerifier {
        path: PathBuf,
        replacement: SproutScanner,
        response: CanonicalContinuation,
    }

    #[async_trait::async_trait]
    impl CursorVerifier for ConcurrentWriteVerifier {
        async fn continuation(
            &mut self,
            _locators: &[ScanCursor],
        ) -> ZeckResult<CanonicalContinuation> {
            save_checkpoint(&self.replacement, P2pNetwork::Regtest, &self.path)?;
            Ok(match self.response {
                CanonicalContinuation::Current { chain_has_more } => {
                    CanonicalContinuation::Current { chain_has_more }
                }
                CanonicalContinuation::CommonAncestor(ancestor) => {
                    CanonicalContinuation::CommonAncestor(ancestor)
                }
            })
        }
    }

    async fn empty_headers_peer(advertised_height: u32) -> Peer {
        use crate::p2p::wire::{encode_message, encode_version};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 24];
            while stream.read_exact(&mut header).await.is_ok() {
                let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() {
                    return;
                }
                if header[4..11] == *b"version" {
                    let version = encode_version(170_160, "/tip-test/", advertised_height, 1, 0);
                    stream
                        .write_all(&encode_message(P2pNetwork::Regtest, "version", &version))
                        .await
                        .unwrap();
                    stream
                        .write_all(&encode_message(P2pNetwork::Regtest, "verack", &[]))
                        .await
                        .unwrap();
                } else if header[4..14] == *b"getheaders" {
                    stream
                        .write_all(&encode_message(P2pNetwork::Regtest, "headers", &[0]))
                        .await
                        .unwrap();
                }
            }
        });
        Peer::connect(&addr, P2pNetwork::Regtest).await.unwrap()
    }

    fn reorg_scanner() -> SproutScanner {
        let mut scanner = SproutScanner::new(&[[0x11; 32]]);
        for height in 1..=3 {
            scanner
                .scan_block_at(
                    &[joinsplit_revealing([height as u8; 32])],
                    [height as u8; 32],
                    height,
                )
                .unwrap();
        }
        scanner.mark_complete();
        scanner
    }

    // Exercise the wallet evidence boundary with a deterministic chain view.
    // The production implementation will route this seam through reconciliation.
    async fn wallet_evidence_with_fake(
        dir: &Path,
        keys: &[[u8; 32]],
        verifier: &mut FakeCursorVerifier,
    ) -> (
        Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>,
        Option<String>,
    ) {
        wallet_evidence_with_fake_on(dir, P2pNetwork::Regtest, keys, verifier).await
    }

    async fn wallet_evidence_with_fake_on(
        dir: &Path,
        network: P2pNetwork,
        keys: &[[u8; 32]],
        verifier: &mut FakeCursorVerifier,
    ) -> (
        Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>,
        Option<String>,
    ) {
        let keys = scan_key_set(keys, &[]);
        let (selected, wider_keys) = match select_wallet_checkpoint(dir, network, &keys) {
            Ok(selected) => selected,
            Err(notice) => return (None, Some(notice)),
        };
        wallet_lookup_result(
            verified_checkpoint_lookup(dir, network, &selected, verifier).await,
            wider_keys,
        )
    }

    async fn wallet_evidence_with_current(
        dir: &Path,
        network: P2pNetwork,
        keys: &[[u8; 32]],
    ) -> (
        Option<std::sync::Arc<crate::sprout_recovery::ChainSpends>>,
        Option<String>,
    ) {
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::Current {
                chain_has_more: false,
            }),
            seen: Vec::new(),
        };
        wallet_evidence_with_fake_on(dir, network, keys, &mut verifier).await
    }

    /// Inspection makes no network contact. A checkpoint it cannot verify
    /// offline is named, and none of its nullifiers count as spends.
    #[test]
    fn offline_inspection_names_the_scan_but_never_uses_its_evidence() {
        let dir = ScratchDir::new("offline-notice");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        let notice = wallet_scan_notice_offline(&dir.0, P2pNetwork::Regtest, &keys)
            .expect("no scan is reported too");
        assert!(notice.contains("No full-block scan"), "{notice}");

        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let notice = wallet_scan_notice_offline(&dir.0, P2pNetwork::Regtest, &keys)
            .expect("an existing scan is reported");
        assert!(notice.contains(&path.display().to_string()), "{notice}");
        assert!(notice.contains("not verified offline"), "{notice}");
        assert!(
            notice.contains("Spent status is the wallet file's own record"),
            "{notice}"
        );
        assert!(wallet_scan_notice_offline(&dir.0, P2pNetwork::Regtest, &[]).is_none());
    }

    #[tokio::test]
    async fn cached_spends_are_not_returned_before_live_cursor_verification() {
        let dir = ScratchDir::new("evidence-unavailable");
        let keys = [[0x11; 32]];
        let scanner = reorg_scanner();
        save_checkpoint(
            &scanner,
            P2pNetwork::Regtest,
            &checkpoint_path(&dir.0, &keys),
        )
        .unwrap();
        let mut verifier = FakeCursorVerifier {
            response: None,
            seen: Vec::new(),
        };
        let (chain, notice) = wallet_evidence_with_fake(&dir.0, &keys, &mut verifier).await;
        assert!(
            chain.is_none(),
            "unverified checkpoint evidence must be refused"
        );
        assert!(notice.unwrap().contains("not use its spent-note evidence"));
    }

    #[tokio::test]
    async fn an_orphaned_nullifier_never_marks_a_wallet_note_spent() {
        let dir = ScratchDir::new("evidence-orphan");
        let keys = [[0x11; 32]];
        let scanner = reorg_scanner();
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let parent = ScanCursor {
            last_block_hash: [2; 32],
            last_height: 2,
        };
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::CommonAncestor(parent)),
            seen: Vec::new(),
        };
        let (chain, _) = wallet_evidence_with_fake(&dir.0, &keys, &mut verifier).await;
        let chain = chain.expect("the verified parent remains useful");
        assert!(!chain.nullifiers.contains_key(&[3; 32]));
        assert_eq!(chain.scanned_to, 2);
        assert!(!chain.complete);
        assert_eq!(
            load_checkpoint(&path, P2pNetwork::Regtest, &keys)
                .unwrap()
                .unwrap()
                .cursor(),
            Some(ScanCursor {
                last_block_hash: [3; 32],
                last_height: 3,
            }),
            "wallet inspection must not replace the scanner's checkpoint"
        );
    }

    #[tokio::test]
    async fn an_empty_peer_cannot_publish_an_orphaned_wallet_nullifier() {
        let dir = ScratchDir::new("empty-peer-orphan-nullifier");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut peer = empty_headers_peer(3).await;
        let mut waits = Vec::new();
        let mut verifier = NetworkCursorVerifier {
            peer: &mut peer,
            network: P2pNetwork::Regtest,
            peers: &[],
            floor: 0,
            tip_anchor: None,
            checkpoint_file: &path,
            waits: &mut waits,
        };
        let (chain, notice) = wallet_lookup_result(
            verified_checkpoint_lookup(&dir.0, P2pNetwork::Regtest, &keys, &mut verifier).await,
            None,
        );
        assert!(
            chain.is_none(),
            "an empty reply cannot certify the orphaned nullifier"
        );
        assert!(notice.unwrap().contains("not use its spent-note evidence"));
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[tokio::test]
    async fn wallet_verification_cannot_replace_a_newer_scanner_checkpoint() {
        let dir = ScratchDir::new("concurrent-scan-writer");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let mut replacement = reorg_scanner();
        replacement
            .scan_block_at(&[joinsplit_revealing([0xFA; 32])], [4; 32], 4)
            .unwrap();
        let expected = {
            let mut bytes = vec![NETWORK_TAGGED, network_tag(P2pNetwork::Regtest)];
            bytes.extend_from_slice(replacement.checkpoint().as_bytes());
            bytes
        };
        let mut verifier = ConcurrentWriteVerifier {
            path: path.clone(),
            replacement,
            response: CanonicalContinuation::CommonAncestor(ScanCursor {
                last_block_hash: [2; 32],
                last_height: 2,
            }),
        };
        let result =
            verified_checkpoint_lookup(&dir.0, P2pNetwork::Regtest, &keys, &mut verifier).await;
        assert!(
            result.is_err(),
            "the wallet must not adopt the concurrent writer's state"
        );
        assert_eq!(std::fs::read(&path).unwrap(), expected);
    }

    #[test]
    fn saving_a_checkpoint_does_not_touch_another_writers_temp_file() {
        let dir = ScratchDir::new("independent-temp-files");
        let path = checkpoint_path(&dir.0, &[[0x11; 32]]);
        let other_writer_tmp = path.with_extension("checkpoint.tmp");
        std::fs::write(&other_writer_tmp, b"writer in progress").unwrap();
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        assert_eq!(
            std::fs::read(other_writer_tmp).unwrap(),
            b"writer in progress"
        );
        assert_eq!(
            load_checkpoint(&path, P2pNetwork::Regtest, &[[0x11; 32]])
                .unwrap()
                .unwrap()
                .cursor()
                .unwrap()
                .last_height,
            3
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_checkpoint_replace_syncs_its_private_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private-checkpoints");
        crate::private_fs::create_private_dir_all(&dir).unwrap();
        let path = checkpoint_path(&dir, &[[0x11; 32]]);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let mut replacement = reorg_scanner();
        replacement
            .scan_block_at(&[joinsplit_revealing([0xFA; 32])], [4; 32], 4)
            .unwrap();
        save_checkpoint(&replacement, P2pNetwork::Regtest, &path).unwrap();
        assert_eq!(
            load_checkpoint(&path, P2pNetwork::Regtest, &[[0x11; 32]])
                .unwrap()
                .unwrap()
                .cursor()
                .unwrap()
                .last_height,
            4
        );
    }

    #[test]
    fn discarding_a_checkpoint_removes_abandoned_unique_temp_files() {
        let dir = ScratchDir::new("abandoned-unique-temp");
        let path = checkpoint_path(&dir.0, &[[0x11; 32]]);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let abandoned = path.with_extension(format!("checkpoint.{}.tmp", uuid::Uuid::new_v4()));
        std::fs::write(&abandoned, b"private partial checkpoint").unwrap();
        let unrelated = dir.0.join("unrelated.tmp");
        std::fs::write(&unrelated, b"keep").unwrap();
        discard_checkpoint(&path).unwrap();
        assert!(!path.exists());
        assert!(!abandoned.exists(), "a crash can leave private temp bytes");
        assert_eq!(std::fs::read(unrelated).unwrap(), b"keep");
    }

    #[test]
    fn checkpoint_lease_preserves_save_into_a_missing_private_parent() {
        let dir = ScratchDir::new("checkpoint-missing-parent");
        let path = checkpoint_path(&dir.0.join("new/private"), &[[0x11; 32]]);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        assert!(path.is_file());
        assert!(checkpoint_lease_path(&path).is_file());
    }

    #[test]
    fn checkpoint_generation_rejects_identical_byte_replacement() {
        let dir = ScratchDir::new("checkpoint-generation-replacement");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"same checkpoint bytes").unwrap();
        let first = checkpoint_generation(&path).unwrap();
        let replacement = dir.0.join("replacement");
        std::fs::write(&replacement, b"same checkpoint bytes").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let second = checkpoint_generation(&path).unwrap();
        assert_eq!(first.len, second.len);
        assert_eq!(first.sha256, second.sha256);
        assert_ne!(first.object, second.object);
    }

    #[test]
    fn checkpoint_generation_rejects_same_length_in_place_mutation_during_review() {
        let dir = ScratchDir::new("checkpoint-generation-in-place-race");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"first checkpoint bytes").unwrap();
        let err = checkpoint_generation_with_post_read(&path, || {
            std::fs::write(&path, b"other checkpoint bytes").unwrap();
        })
        .expect_err("an in-place mutation during the review must be rejected")
        .to_string();
        assert!(err.contains("changed while it was reviewed"), "{err}");
    }

    #[test]
    fn checkpoint_lease_serializes_replacement_and_cleanup_authority() {
        let dir = ScratchDir::new("checkpoint-lease");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"checkpoint").unwrap();
        let first = CheckpointLease::acquire(&path).unwrap();
        assert!(CheckpointLease::acquire(&path).is_err());
        assert!(save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"checkpoint");
        drop(first);
        CheckpointLease::acquire(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaced_lease_sidecar_revokes_old_cleanup_authority() {
        let dir = ScratchDir::new("checkpoint-lease-replaced-sidecar");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let old_generation = checkpoint_generation(&path).unwrap();
        let old = CheckpointLease::acquire(&path).unwrap();
        let sidecar = checkpoint_lease_path(&path);
        let displaced = dir.0.join("displaced-lease");
        std::fs::rename(&sidecar, &displaced).unwrap();

        assert!(
            CheckpointLease::acquire(&path).is_err(),
            "the retained parent namespace lock must reject a replacement sidecar"
        );
        let replacement = dir.0.join("replacement.checkpoint");
        std::fs::write(&replacement, b"newer checkpoint").unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let err = discard_checkpoint_generation_while_leased(&old, &path, &old_generation)
            .expect_err("the displaced lease must not delete a newer checkpoint")
            .to_string();
        assert!(err.contains("replaced while held"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"newer checkpoint");

        drop(old);
        let current = CheckpointLease::acquire(&path).unwrap();
        let current_generation = checkpoint_generation(&path).unwrap();
        assert_eq!(
            discard_checkpoint_generation_while_leased(&current, &path, &current_generation)
                .unwrap(),
            CheckpointDiscard::Removed
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_sidecar_cannot_start_a_writer_or_delete_its_staging() {
        use std::os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _};

        let dir = ScratchDir::new("checkpoint-sidecar-staging-race");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let old = CheckpointLease::acquire(&path).unwrap();
        let sidecar = checkpoint_lease_path(&path);
        std::fs::rename(&sidecar, dir.0.join("displaced-lease")).unwrap();

        assert!(CheckpointLease::acquire(&path).is_err());
        let digest = Sha256::digest(path.file_name().unwrap().as_bytes());
        let staging = dir.0.join(format!(
            ".argos-private-{digest:x}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = staging.join("artifact");
        std::fs::write(&artifact, b"newer spend-capable staging").unwrap();
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(discard_checkpoint_generation_while_leased(&old, &path, &generation).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"reviewed checkpoint");
        assert_eq!(
            std::fs::read(&artifact).unwrap(),
            b"newer spend-capable staging"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_parent_namespace_cannot_redirect_old_cleanup() {
        let root = ScratchDir::new("checkpoint-parent-replacement");
        let parent = root.0.join("active");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("scan.checkpoint");
        std::fs::write(&path, b"old checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let old = CheckpointLease::acquire(&path).unwrap();

        let displaced = root.0.join("displaced");
        std::fs::rename(&parent, &displaced).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(&path, b"new checkpoint").unwrap();
        let current = CheckpointLease::acquire(&path).unwrap();

        assert!(discard_checkpoint_generation_while_leased(&old, &path, &generation).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"new checkpoint");
        assert_eq!(
            std::fs::read(displaced.join("scan.checkpoint")).unwrap(),
            b"old checkpoint"
        );
        drop(current);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_and_generation_swap_at_final_delete_boundary_preserves_new_checkpoint() {
        let dir = ScratchDir::new("checkpoint-final-delete-race");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let old = CheckpointLease::acquire(&path).unwrap();
        let sidecar = checkpoint_lease_path(&path);
        let displaced = dir.0.join("displaced-lease");
        let replacement = dir.0.join("replacement.checkpoint");
        let mut replacement_lease_refused = false;

        let err = discard_checkpoint_generation_while_leased_with_observer(
            &old,
            &path,
            &generation,
            || {
                std::fs::rename(&sidecar, &displaced).unwrap();
                replacement_lease_refused = CheckpointLease::acquire(&path).is_err();
                std::fs::write(&replacement, b"newer checkpoint").unwrap();
                std::fs::rename(&replacement, &path).unwrap();
            },
        )
        .expect_err("the old authority must be revoked at the final deletion boundary")
        .to_string();
        assert!(err.contains("replaced while held"), "{err}");
        assert!(replacement_lease_refused);
        assert_eq!(std::fs::read(&path).unwrap(), b"newer checkpoint");

        drop(old);
        let current = CheckpointLease::acquire(&path).unwrap();
        let current_generation = checkpoint_generation(&path).unwrap();
        assert_eq!(
            discard_checkpoint_generation_while_leased(&current, &path, &current_generation)
                .unwrap(),
            CheckpointDiscard::Removed
        );
    }

    #[test]
    fn generation_swap_at_exact_delete_boundary_is_quarantined_and_restored() {
        let dir = ScratchDir::new("checkpoint-exact-delete-race");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let lease = CheckpointLease::acquire(&path).unwrap();
        let replacement = dir.0.join("replacement.checkpoint");

        let err = discard_checkpoint_generation_while_leased_with_observer(
            &lease,
            &path,
            &generation,
            || {
                std::fs::write(&replacement, b"newer checkpoint").unwrap();
                std::fs::rename(&replacement, &path).unwrap();
            },
        )
        .expect_err("exact-object deletion must reject the raced generation")
        .to_string();
        assert!(err.contains("replacement was preserved"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"newer checkpoint");
        assert!(checkpoint_discard_quarantines(&lease, &path)
            .unwrap()
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_swap_after_verification_preserves_the_sentinel() {
        let dir = ScratchDir::new("checkpoint-quarantine-delete-race");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let lease = CheckpointLease::acquire(&path).unwrap();
        let displaced = dir.0.join("verified-quarantine");

        let err = discard_checkpoint_generation_while_leased_with_observers(
            &lease,
            &path,
            &generation,
            || {},
            |quarantine| {
                std::fs::rename(quarantine, &displaced).unwrap();
                std::fs::write(quarantine, b"sentinel replacement").unwrap();
            },
        )
        .expect_err("the final identity check must reject a substituted quarantine")
        .to_string();

        assert!(err.contains("path changed before deletion"), "{err}");
        let quarantine = checkpoint_discard_quarantines(&lease, &path).unwrap();
        assert_eq!(quarantine.len(), 1);
        assert_eq!(
            std::fs::read(&quarantine[0]).unwrap(),
            b"sentinel replacement"
        );
        assert_eq!(std::fs::read(&displaced).unwrap(), b"reviewed checkpoint");
    }

    #[cfg(windows)]
    #[test]
    fn windows_checkpoint_quarantine_uses_exact_open_handle_rename_and_delete() {
        let dir = ScratchDir::new("checkpoint-windows-exact-delete");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let lease = CheckpointLease::acquire(&path).unwrap();
        let displaced = dir.0.join("must-not-move-open-quarantine");

        assert_eq!(
            discard_checkpoint_generation_while_leased_with_observers(
                &lease,
                &path,
                &generation,
                || {},
                |quarantine| {
                    assert!(
                        std::fs::rename(quarantine, &displaced).is_err(),
                        "the verified open quarantine must deny replacement before handle deletion"
                    );
                },
            )
            .unwrap(),
            CheckpointDiscard::Removed
        );
        assert!(!path.exists());
        assert!(!displaced.exists());
        assert!(checkpoint_discard_quarantines(&lease, &path)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn exact_delete_restart_removes_only_the_manifested_quarantine() {
        let dir = ScratchDir::new("checkpoint-exact-delete-restart");
        let path = dir.0.join("scan.checkpoint");
        std::fs::write(&path, b"reviewed checkpoint").unwrap();
        let generation = checkpoint_generation(&path).unwrap();
        let lease = CheckpointLease::acquire(&path).unwrap();
        let quarantine = checkpoint_discard_quarantine(&path).unwrap();
        std::fs::rename(&path, &quarantine).unwrap();
        let unrelated = checkpoint_discard_quarantine(&path).unwrap();
        std::fs::write(&unrelated, b"different generation").unwrap();

        let err = discard_checkpoint_generation_while_leased(&lease, &path, &generation)
            .expect_err("an unmanifested quarantine must block completion")
            .to_string();
        assert!(err.contains("does not match"), "{err}");
        assert!(!quarantine.exists());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"different generation");
        std::fs::remove_file(&unrelated).unwrap();
        assert_eq!(
            discard_checkpoint_generation_while_leased(&lease, &path, &generation).unwrap(),
            CheckpointDiscard::AlreadyAbsent
        );
    }

    #[cfg(unix)]
    #[test]
    fn held_lease_blocks_read_and_cleanup_of_a_paused_atomic_writer() {
        use std::os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _};

        let dir = ScratchDir::new("checkpoint-paused-writer");
        let path = checkpoint_path(&dir.0, &[[0x11; 32]]);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let writer_path = path.clone();
        let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        let writer = std::thread::spawn(move || {
            let _lease = CheckpointLease::acquire(&writer_path).unwrap();
            let destination = writer_path.file_name().unwrap();
            let digest = Sha256::digest(destination.as_bytes());
            let staging = writer_path.parent().unwrap().join(format!(
                ".argos-private-{digest:x}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir(&staging).unwrap();
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
            let artifact = staging.join("artifact");
            std::fs::write(&artifact, b"paused spend-capable checkpoint").unwrap();
            std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o600)).unwrap();
            paused_tx.send(staging.clone()).unwrap();
            resume_rx.recv().unwrap();
            staging
        });
        let staging = paused_rx.recv().unwrap();

        let read_err = saved_decrypt_from(&path, P2pNetwork::Regtest, &[[0x11; 32]])
            .expect_err("a read/cleanup entry must honor the live writer lease")
            .to_string();
        assert!(read_err.contains("in use"), "{read_err}");
        let discard_err = discard_checkpoint(&path)
            .expect_err("cleanup must not race the live writer")
            .to_string();
        assert!(discard_err.contains("in use"), "{discard_err}");
        assert!(path.exists());
        assert!(staging.join("artifact").exists());

        resume_tx.send(()).unwrap();
        let staging = writer.join().unwrap();
        assert_eq!(
            discard_checkpoint(&path).unwrap(),
            CheckpointDiscard::Removed
        );
        assert!(!path.exists());
        assert!(!staging.exists());
    }

    /// A crash between writing a unique temp file and renaming it leaves a
    /// spend-capable 0600 file behind. Saving and loading sweep away such
    /// leftovers once they are clearly abandoned, and never a temp file a
    /// concurrent writer may still be filling.
    #[test]
    fn stale_unique_temp_files_are_removed_and_fresh_ones_kept() {
        let dir = ScratchDir::new("stale-unique-temp");
        let path = checkpoint_path(&dir.0, &[[0x11; 32]]);
        let temp = |label: &str| {
            let tmp = path.with_extension(format!("checkpoint.{}.tmp", uuid::Uuid::new_v4()));
            std::fs::write(&tmp, label).unwrap();
            tmp
        };
        let age = |tmp: &Path| {
            std::fs::File::options()
                .write(true)
                .open(tmp)
                .unwrap()
                .set_modified(std::time::SystemTime::now() - STALE_TEMP_AGE * 2)
                .unwrap();
        };
        let stale = temp("crashed writer");
        age(&stale);
        let fresh = temp("writer in progress");
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        assert!(!stale.exists(), "an abandoned temp file is removed on save");
        assert!(fresh.exists(), "a concurrent writer's temp file is kept");

        let stale = temp("crashed writer");
        age(&stale);
        load_checkpoint(&path, P2pNetwork::Regtest, &[[0x11; 32]])
            .unwrap()
            .unwrap();
        assert!(!stale.exists(), "an abandoned temp file is removed on load");
        assert!(fresh.exists());
    }

    #[tokio::test]
    async fn every_lookup_revalidates_the_cursor() {
        let dir = ScratchDir::new("evidence-cache-reorg");
        let keys = [[0x11; 32]];
        save_checkpoint(
            &reorg_scanner(),
            P2pNetwork::Regtest,
            &checkpoint_path(&dir.0, &keys),
        )
        .unwrap();
        let mut current = FakeCursorVerifier {
            response: Some(CanonicalContinuation::Current {
                chain_has_more: false,
            }),
            seen: Vec::new(),
        };
        let (first, _) = wallet_evidence_with_fake(&dir.0, &keys, &mut current).await;
        assert!(first.unwrap().nullifiers.contains_key(&[3; 32]));
        let mut reorg = FakeCursorVerifier {
            response: Some(CanonicalContinuation::CommonAncestor(ScanCursor {
                last_block_hash: [2; 32],
                last_height: 2,
            })),
            seen: Vec::new(),
        };
        let (second, _) = wallet_evidence_with_fake(&dir.0, &keys, &mut reorg).await;
        assert!(!second.unwrap().nullifiers.contains_key(&[3; 32]));
        assert_eq!(reorg.seen[0].last_height, 3);
    }

    #[tokio::test]
    async fn replacement_after_rewind_cannot_supply_unverified_spends() {
        let dir = ScratchDir::new("evidence-replaced-after-rewind");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let mut replacement = reorg_scanner();
        replacement
            .scan_block_at(&[joinsplit_revealing([0xFA; 32])], [4; 32], 4)
            .unwrap();
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::CommonAncestor(ScanCursor {
                last_block_hash: [2; 32],
                last_height: 2,
            })),
            seen: Vec::new(),
        };
        let result = verified_checkpoint_lookup_with(
            &dir.0,
            P2pNetwork::Regtest,
            &keys,
            &mut verifier,
            stamp_of,
            |path| save_checkpoint(&replacement, P2pNetwork::Regtest, path).unwrap(),
        )
        .await;
        assert!(
            result.is_err(),
            "a replacement after reconciliation must not become wallet evidence"
        );
    }

    #[tokio::test]
    async fn unavailable_file_stamp_cannot_authorize_cached_spends() {
        let dir = ScratchDir::new("evidence-stamp-unavailable");
        let keys = [[0x11; 32]];
        save_checkpoint(
            &reorg_scanner(),
            P2pNetwork::Regtest,
            &checkpoint_path(&dir.0, &keys),
        )
        .unwrap();
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::Current {
                chain_has_more: false,
            }),
            seen: Vec::new(),
        };
        let result = verified_checkpoint_lookup_with(
            &dir.0,
            P2pNetwork::Regtest,
            &keys,
            &mut verifier,
            |_| None,
            |_| {},
        )
        .await;
        assert!(
            result.is_err(),
            "two unavailable stamps cannot prove checkpoint stability"
        );
    }

    #[tokio::test]
    async fn a_replaced_file_cannot_escape_through_a_stale_stamp_read() {
        let dir = ScratchDir::new("evidence-stale-stamp-read");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        save_checkpoint(&reorg_scanner(), P2pNetwork::Regtest, &path).unwrap();
        let old_stamp = stamp_of(&path).unwrap();
        let mut replacement = reorg_scanner();
        replacement
            .scan_block_at(&[joinsplit_revealing([0xFB; 32])], [4; 32], 4)
            .unwrap();
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::Current {
                chain_has_more: false,
            }),
            seen: Vec::new(),
        };
        let result = verified_checkpoint_lookup_with(
            &dir.0,
            P2pNetwork::Regtest,
            &keys,
            &mut verifier,
            move |_| Some(old_stamp),
            |path| save_checkpoint(&replacement, P2pNetwork::Regtest, path).unwrap(),
        )
        .await;
        // The evidence is built from the bytes parsed and verified, never
        // re-read: a stale stamp can at most return those, not the
        // replacement's nullifiers.
        let Ok(VerifiedLookup::Found(spends, _)) = result else {
            panic!("the verified bytes themselves are still evidence");
        };
        assert!(
            !spends.nullifiers.contains_key(&[0xFB; 32]),
            "a stale stamp read cannot license replacement nullifiers"
        );
        assert_eq!(spends.scanned_to, 3);
    }

    /// A pre-v5 checkpoint has no rollback history (v4) or no body
    /// authentication (v1-v3). It is refused before any live verification
    /// is attempted, and the file is left for the user to preserve.
    #[tokio::test]
    async fn a_legacy_checkpoint_is_refused_before_verification() {
        for legacy in [2u8, 4] {
            let dir = ScratchDir::new(&format!("evidence-legacy-v{legacy}"));
            let keys = [[0x11; 32]];
            let mut scanner = SproutScanner::new(&keys);
            scanner
                .scan_block_at(&[joinsplit_revealing([0xEE; 32])], [0xAA; 32], 7)
                .unwrap();
            let mut body = scanner.checkpoint().as_bytes().to_vec();
            body[0] = legacy;
            let path = checkpoint_path(&dir.0, &keys);
            let mut file = vec![NETWORK_TAGGED, network_tag(P2pNetwork::Regtest)];
            file.extend_from_slice(&body);
            std::fs::write(&path, &file).unwrap();
            let mut verifier = FakeCursorVerifier {
                response: Some(CanonicalContinuation::Current {
                    chain_has_more: false,
                }),
                seen: Vec::new(),
            };
            let (chain, notice) = wallet_evidence_with_fake(&dir.0, &keys, &mut verifier).await;
            assert!(chain.is_none(), "v{legacy} is never spend evidence");
            let notice = notice.unwrap();
            assert!(notice.contains("fresh scan"), "v{legacy}: {notice}");
            assert!(
                verifier.seen.is_empty(),
                "v{legacy}: refused before verification"
            );
            assert_eq!(std::fs::read(path).unwrap(), file);
        }
    }

    #[tokio::test]
    async fn a_ranked_covering_scan_is_refused_when_live_verification_fails() {
        let dir = ScratchDir::new("evidence-covering-unavailable");
        let wallet_key = [0x11; 32];
        let extra_key = [0x12; 32];
        let mut scanner = SproutScanner::new(&[wallet_key, extra_key]);
        scanner
            .scan_block_at(&[joinsplit_revealing([0xEF; 32])], [1; 32], 1)
            .unwrap();
        scanner.mark_complete();
        let path = checkpoint_path(&dir.0, &[wallet_key, extra_key]);
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let mut verifier = FakeCursorVerifier {
            response: None,
            seen: Vec::new(),
        };
        let (chain, notice) = wallet_evidence_with_fake(&dir.0, &[wallet_key], &mut verifier).await;
        assert!(
            chain.is_none(),
            "ranking a covering scan cannot publish its spent map"
        );
        assert!(notice.unwrap().contains("not use its spent-note evidence"));
        assert_eq!(verifier.seen[0].last_height, 1);
    }

    #[tokio::test]
    async fn resume_sends_retained_locators_newest_first() {
        let dir = ScratchDir::new("locator-order");
        let path = dir.0.join("scan.checkpoint");
        let mut scanner = reorg_scanner();
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::Current {
                chain_has_more: false,
            }),
            seen: Vec::new(),
        };
        reconcile_cursor(&mut scanner, &mut verifier, P2pNetwork::Regtest, &path)
            .await
            .unwrap();
        assert_eq!(
            verifier.seen,
            (1..=3)
                .rev()
                .map(|height| ScanCursor {
                    last_block_hash: [height as u8; 32],
                    last_height: height,
                })
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn an_empty_reply_without_overlap_cannot_certify_the_saved_tip() {
        let mut peer = empty_headers_peer(3).await;
        assert_eq!(peer.peer_height, 3);
        let mut waits = Vec::new();
        let mut verifier = NetworkCursorVerifier {
            peer: &mut peer,
            network: P2pNetwork::Regtest,
            peers: &[],
            floor: 4, // TipAnchor at 3 requires fetching through height 3.
            tip_anchor: Some(TipAnchor {
                height: 3,
                hash: [3; 32],
            }),
            checkpoint_file: Path::new("unused.checkpoint"),
            waits: &mut waits,
        };
        let saved = ScanCursor {
            last_height: 3,
            last_block_hash: [3; 32],
        };
        let err = verifier
            .continuation(&[saved])
            .await
            .expect_err("matching a pin still needs positive chain evidence");
        assert!(err.to_string().contains("not use its spent-note evidence"));
    }

    #[tokio::test]
    async fn a_conflicting_tip_anchor_rejects_an_empty_low_height_peer() {
        let mut peer = empty_headers_peer(3).await;
        let mut waits = Vec::new();
        let mut verifier = NetworkCursorVerifier {
            peer: &mut peer,
            network: P2pNetwork::Regtest,
            peers: &[],
            floor: 4,
            tip_anchor: Some(TipAnchor {
                height: 3,
                hash: [0xEE; 32],
            }),
            checkpoint_file: Path::new("unused.checkpoint"),
            waits: &mut waits,
        };
        let saved = ScanCursor {
            last_height: 3,
            last_block_hash: [3; 32],
        };
        let err = verifier
            .continuation(&[saved])
            .await
            .expect_err("the anchor contradicts the saved block at its height");
        assert!(err.to_string().contains("pinned block"));
    }

    #[tokio::test]
    async fn off_chain_cursor_rewinds_to_the_common_ancestor_before_fetching() {
        let dir = ScratchDir::new("reorg-rewind");
        let path = dir.0.join("scan.checkpoint");
        let mut scanner = reorg_scanner();
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let ancestor = ScanCursor {
            last_block_hash: [1; 32],
            last_height: 1,
        };
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::CommonAncestor(ancestor)),
            seen: Vec::new(),
        };
        reconcile_cursor(&mut scanner, &mut verifier, P2pNetwork::Regtest, &path)
            .await
            .unwrap();
        assert_eq!(scanner.cursor(), Some(ancestor));
        assert!(!scanner.is_complete());
        assert!(scanner.spent_nullifiers().contains_key(&[1; 32]));
        assert!(!scanner.spent_nullifiers().contains_key(&[2; 32]));
        assert!(!scanner.spent_nullifiers().contains_key(&[3; 32]));
        let saved = load_checkpoint(&path, P2pNetwork::Regtest, &[[0x11; 32]])
            .unwrap()
            .unwrap();
        assert_eq!(saved.cursor(), Some(ancestor));
        assert_eq!(saved.spent_nullifiers(), scanner.spent_nullifiers());
    }

    #[tokio::test]
    async fn canonical_extension_clears_the_complete_flag() {
        let dir = ScratchDir::new("reorg-extension");
        let path = dir.0.join("scan.checkpoint");
        let mut scanner = reorg_scanner();
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::Current {
                chain_has_more: true,
            }),
            seen: Vec::new(),
        };
        reconcile_cursor(&mut scanner, &mut verifier, P2pNetwork::Regtest, &path)
            .await
            .unwrap();
        assert!(!scanner.is_complete());
        let saved = load_checkpoint(&path, P2pNetwork::Regtest, &[[0x11; 32]])
            .unwrap()
            .unwrap();
        assert!(!saved.is_complete());
    }

    #[tokio::test]
    async fn deep_reorg_preserves_the_checkpoint_and_returns_incomplete() {
        let dir = ScratchDir::new("reorg-deep");
        let path = dir.0.join("scan.checkpoint");
        let mut scanner = reorg_scanner();
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut verifier = FakeCursorVerifier {
            response: Some(CanonicalContinuation::CommonAncestor(ScanCursor {
                last_block_hash: [0xaa; 32],
                last_height: 0,
            })),
            seen: Vec::new(),
        };
        let err = reconcile_cursor(&mut scanner, &mut verifier, P2pNetwork::Regtest, &path)
            .await
            .expect_err("the rollback window must bound reconciliation");
        let msg = err.to_string();
        for phrase in [
            "height 3",
            "height 1",
            "will not use its spent-note evidence",
            "keep the original wallet or key",
            "safe full rescan",
        ] {
            assert!(msg.contains(phrase), "missing {phrase:?}: {msg}");
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(scanner.cursor().unwrap().last_height, 3);
    }

    #[tokio::test]
    async fn unlocated_legacy_cursor_requires_rescan_without_inventing_ancestry() {
        let dir = ScratchDir::new("legacy-unlocated");
        let path = dir.0.join("scan.checkpoint");
        let mut scanner = SproutScanner::new(&[[0x11; 32]]);
        scanner.scan_block_at(&[], [0; 32], 7).unwrap();
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut verifier = FakeCursorVerifier {
            response: None,
            seen: Vec::new(),
        };
        let err = reconcile_cursor(&mut scanner, &mut verifier, P2pNetwork::Regtest, &path)
            .await
            .expect_err("an unlocated cursor cannot be mapped to a live branch");
        let msg = err.to_string();
        assert!(msg.contains("height 7"), "{msg}");
        assert!(msg.contains("safe full rescan"), "{msg}");
        assert!(verifier.seen.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn mid_fetch_reorg_stops_without_scanning_or_saving_a_mixed_page() {
        let dir = ScratchDir::new("reorg-mid-fetch");
        let path = dir.0.join("scan.checkpoint");
        let mut scanner = reorg_scanner();
        scanner.mark_incomplete();
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
        let original = std::fs::read(&path).unwrap();
        let page = Page {
            parent: [0xee; 32],
            blocks: vec![([4; 32], Vec::new())],
        };
        let mut height = 4;
        let err = consume_page(&mut scanner, &page, P2pNetwork::Regtest, None, &mut height)
            .expect_err("a page from the other branch must be refused");
        assert!(matches!(&err, ZeckError::ScanNotReady(_)));
        let text = err.to_string();
        assert!(text.contains("reorganization was detected"), "{text}");
        assert!(text.contains("Re-run"), "{text}");
        assert!(text.contains("common ancestor"), "{text}");
        save_before_stopping(&scanner, P2pNetwork::Regtest, &path);
        assert_eq!(scanner.cursor().unwrap().last_height, 3);
        assert_eq!(height, 4);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

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
        discard_checkpoint(&path).unwrap();

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
        discard_checkpoint(&path).unwrap();

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
        discard_checkpoint(&path).unwrap();

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
        discard_checkpoint(&path).unwrap();

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

    /// A peer that completes the handshake on its first connection only, and
    /// drops every later one before the handshake: once rotated away from,
    /// it cannot be chosen again, so the test knows which peer comes next.
    async fn one_connection_only_peer() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer_handshake_only(stream));
            }
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        addr
    }

    /// An honest block, and the same header over a substituted body: the
    /// header (and so the block hash the peer was asked for) is unchanged,
    /// only the transactions differ.
    fn honest_and_forged_block() -> ([u8; 32], Vec<u8>, Vec<u8>) {
        use crate::p2p::block::test_support::{legacy_test_transaction, test_block};
        let honest_tx = legacy_test_transaction(1);
        let forged_tx = legacy_test_transaction(2);
        let honest = test_block(std::slice::from_ref(&honest_tx));
        let mut forged = honest[..honest.len() - honest_tx.len()].to_vec();
        forged.extend_from_slice(&forged_tx);
        let hash = crate::p2p::block::block_hash(&honest).unwrap();
        assert_eq!(crate::p2p::block::block_hash(&forged).unwrap(), hash);
        (hash, honest, forged)
    }

    fn fetcher_on(peer: Peer, peers: Vec<String>) -> PageFetcher {
        let (waits, _rx) = tokio::sync::mpsc::unbounded_channel();
        PageFetcher {
            peer,
            locator: [7; 32],
            empty_replies: 0,
            fetched: 10,
            floor: 0,
            network: P2pNetwork::Regtest,
            peers,
            silent: Vec::new(),
            silence_exclusion: PEER_RECONNECT_DELAY,
            waits,
        }
    }

    /// Review of #265: a body that fails authentication used to abort the
    /// whole scan from the consumer, with no other peer tried. It is the
    /// serving peer's failure: rotate away, charge the budget, and fetch the
    /// same page again from the next peer — never scanning the forged body.
    #[tokio::test]
    async fn a_peer_serving_a_forged_body_is_rotated_away_and_the_page_refetched() {
        let bad = one_connection_only_peer().await;
        let good = silent_peer().await;
        let first = connect_peer(P2pNetwork::Regtest, std::slice::from_ref(&bad), &[], |_| {})
            .await
            .unwrap();
        let mut fetcher = fetcher_on(first, vec![bad.clone(), good.clone()]);
        let (hash, honest, forged) = honest_and_forged_block();

        let outcome = fetcher
            .authenticate_page(
                &[hash],
                [7; 32],
                std::collections::HashMap::from([(hash, forged)]),
                10,
            )
            .await
            .expect("one forged body is within the budget");
        assert!(outcome.is_none(), "the forged page is not handed on");
        assert_eq!(fetcher.peer.dialled_as(), good, "rotated to the other peer");
        assert_eq!(fetcher.empty_replies, 1, "charged against the budget");
        assert!(fetcher.silent.is_empty(), "a forged body is not silence");
        assert_eq!(fetcher.locator, [7; 32], "the same page is asked for again");

        let page = fetcher
            .authenticate_page(
                &[hash],
                [7; 32],
                std::collections::HashMap::from([(hash, honest)]),
                10,
            )
            .await
            .expect("the honest body authenticates")
            .expect("and is a page");
        assert_eq!(page.len(), 1);
        assert_eq!(page.parent, [7; 32]);
        assert_eq!(page.blocks[0].0, hash);
        assert!(
            page.blocks[0].1.is_empty(),
            "a coinbase-only block has no JoinSplits"
        );
        assert_eq!(fetcher.locator, hash, "the scan moves on past the page");
        assert_eq!(
            fetcher.empty_replies, 0,
            "a delivered page resets the budget"
        );
    }

    /// With no honest peer to be had, the budget still ends the scan, with
    /// an error saying what to do.
    #[tokio::test]
    async fn forged_bodies_from_every_peer_exhaust_the_budget() {
        let peer = silent_peer().await;
        let first = connect_peer(
            P2pNetwork::Regtest,
            std::slice::from_ref(&peer),
            &[],
            |_| {},
        )
        .await
        .unwrap();
        let mut fetcher = fetcher_on(first, vec![peer]);
        let (hash, _, forged) = honest_and_forged_block();

        let mut attempts = 0u32;
        let err = loop {
            attempts += 1;
            match fetcher
                .authenticate_page(
                    &[hash],
                    [7; 32],
                    std::collections::HashMap::from([(hash, forged.clone())]),
                    10,
                )
                .await
            {
                Ok(None) => continue,
                Ok(Some(_)) => panic!("a forged body must never be handed on"),
                Err(err) => break err,
            }
        };
        assert_eq!(attempts, MAX_EMPTY_REPLIES + 1);
        let text = err.to_string();
        assert!(text.contains("height 10"), "{text}");
        assert!(text.contains("--peer"), "{text}");
        assert!(text.contains("re-run"), "{text}");
        assert_eq!(fetcher.locator, [7; 32]);
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
    #[tokio::test]
    async fn a_wallets_scan_lookup_always_explains_itself() {
        let dir = std::env::temp_dir().join(format!("argos-lookup-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys = [[0x21; 32]];

        let (chain, notice) = wallet_evidence_with_current(&dir, P2pNetwork::Mainnet, &keys).await;
        assert!(chain.is_none());
        let notice = notice.expect("no scan must be said, with where it looked");
        assert!(notice.contains(&dir.display().to_string()), "{notice}");

        // A duplicated key in the wallet names the same checkpoint the scan
        // wrote for the deduplicated set.
        let mut scanner = SproutScanner::new(&keys);
        scanner.scan_block_at(&[], [0xCD; 32], 300_000).unwrap();
        save_checkpoint(&scanner, P2pNetwork::Mainnet, &checkpoint_path(&dir, &keys)).unwrap();
        let (chain, notice) =
            wallet_evidence_with_current(&dir, P2pNetwork::Mainnet, &[keys[0], keys[0]]).await;
        let chain = chain.expect("the duplicate must not hide the scan");
        assert!(!chain.complete);
        assert!(notice.unwrap().contains("before reaching the chain tip"));

        // Unusable evidence is said, not swallowed.
        let (chain, notice) = wallet_evidence_with_current(&dir, P2pNetwork::Testnet, &keys).await;
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
    #[tokio::test]
    async fn a_scan_of_more_keys_than_the_wallet_holds_is_found() {
        let dir = fresh_dir("superset");
        let (a, b, c) = ([0x31; 32], [0x32; 32], [0x33; 32]);
        write_scan(&dir, &[a, b], 3_000_000, true);

        let (chain, notice) = wallet_evidence_with_current(&dir, P2pNetwork::Mainnet, &[a]).await;
        let chain = chain.expect("a scan covering the wallet's keys must be used");
        assert_eq!(chain.scanned_to, 3_000_000);
        let notice = notice.expect("using a wider scan is said");
        assert!(notice.contains("together with 1 other key"), "{notice}");

        // Not a superset: the wallet holds a key the scan never looked for —
        // even though the scan looked for more keys than the wallet has.
        write_scan(&dir, &[a, b, [0x35; 32]], 3_000_000, true);
        let (chain, _) = wallet_evidence_with_current(&dir, P2pNetwork::Mainnet, &[a, c]).await;
        assert!(
            chain.is_none(),
            "a scan missing one of the wallet's keys proves nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_legacy_covering_scan_is_reported_but_not_used() {
        for legacy in [2u8, 3, 4] {
            let dir = ScratchDir::new(&format!("legacy-superset-v{legacy}"));
            let (a, b) = ([0x31; 32], [0x32; 32]);
            let path = write_scan(&dir.0, &[a, b], 3_000_000, true);
            let mut old_bytes = std::fs::read(&path).unwrap();
            old_bytes[2] = legacy;
            std::fs::write(&path, &old_bytes).unwrap();

            let (chain, notice) =
                wallet_evidence_with_current(&dir.0, P2pNetwork::Mainnet, &[a]).await;
            assert!(chain.is_none(), "v{legacy}");
            let notice = notice.expect("old covering scan must be reported");
            assert!(notice.contains("fresh scan"), "{notice}");
            assert!(notice.contains(&path.display().to_string()), "{notice}");
            assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
        }
    }

    /// Finding 11: a covering checkpoint that cannot be used is reported as
    /// such, not as "no scan found" — hours of scan work must not look absent.
    #[tokio::test]
    async fn an_unusable_covering_scan_is_reported_not_hidden() {
        let dir = fresh_dir("covering-broken");
        let (a, b) = ([0x37; 32], [0x38; 32]);
        let path = write_scan(&dir, &[a, b], 3_000_000, true);
        // Damage the body, past the header the covering search reads.
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();

        let (chain, notice) = wallet_evidence_with_current(&dir, P2pNetwork::Mainnet, &[a]).await;
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

    #[test]
    fn a_legacy_checkpoint_cannot_resume_a_scan() {
        // v3 matters most: it is the decrypt-from layout already on main,
        // written before bodies were authenticated.
        for legacy in [2u8, 3] {
            let dir = ScratchDir::new(&format!("legacy-resume-v{legacy}"));
            let keys = [[0x11; 32]];
            let path = checkpoint_path(&dir.0, &keys);
            save_checkpoint(&scanned(&keys, [0x99; 32], 5), P2pNetwork::Mainnet, &path).unwrap();
            let mut old_bytes = std::fs::read(&path).unwrap();
            old_bytes[2] = legacy;
            std::fs::write(&path, &old_bytes).unwrap();

            let err = match load_checkpoint(&path, P2pNetwork::Mainnet, &keys) {
                Err(err) => err,
                Ok(_) => panic!("v{legacy} state predates body authentication"),
            };
            assert!(err.to_string().contains("fresh scan"), "{err}");
            assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
        }
    }

    #[test]
    fn a_legacy_checkpoint_cannot_answer_wallet_file_spends() {
        for legacy in [2u8, 3] {
            let dir = ScratchDir::new(&format!("legacy-spends-v{legacy}"));
            let keys = [[0x11; 32]];
            let path = checkpoint_path(&dir.0, &keys);
            save_checkpoint(&scanned(&keys, [0x99; 32], 5), P2pNetwork::Mainnet, &path).unwrap();
            let mut old_bytes = std::fs::read(&path).unwrap();
            old_bytes[2] = legacy;
            std::fs::write(&path, &old_bytes).unwrap();

            let err = lookup_chain_spends(&dir.0, P2pNetwork::Mainnet, &keys)
                .expect_err("pre-v4 nullifiers predate body authentication");
            assert!(err.to_string().contains("fresh scan"), "{err}");
            assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
        }
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
        discard_checkpoint(&path).unwrap();
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
        discard_checkpoint(&path).unwrap();
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
        discard_checkpoint(&path).unwrap();
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

    // ── decrypt-from bound across a resume ───────────────────────────────────

    #[test]
    fn a_fresh_scan_takes_the_requested_bound() {
        assert_eq!(
            reconcile_decrypt_from(Some(50), None, Some(10)),
            Ok(Some(10))
        );
        assert_eq!(reconcile_decrypt_from(Some(50), None, None), Ok(None));
    }

    /// Asking for a later bound than the checkpoint was scanned under is
    /// safe — the earlier blocks were decrypted anyway — and keeps the
    /// checkpoint's, so the reported bound is the one actually used.
    #[test]
    fn a_resume_keeps_a_lower_stored_bound() {
        assert_eq!(
            reconcile_decrypt_from(Some(10), Some(500), Some(10)),
            Ok(Some(10))
        );
        assert_eq!(
            reconcile_decrypt_from(Some(10), Some(500), Some(90)),
            Ok(Some(10))
        );
        assert_eq!(reconcile_decrypt_from(None, Some(500), Some(90)), Ok(None));
    }

    /// Lowering the bound is only possible while the walk has not yet
    /// reached the new bound: past it, blocks the new bound wants decrypted
    /// were walked without decryption, and resuming would miss their notes.
    #[test]
    fn a_resume_refuses_a_lower_bound_it_has_already_passed() {
        assert_eq!(
            reconcile_decrypt_from(Some(100), Some(49), Some(50)),
            Ok(Some(50))
        );
        assert!(reconcile_decrypt_from(Some(100), Some(50), Some(50)).is_err());
        assert!(reconcile_decrypt_from(Some(100), Some(99), Some(50)).is_err());
        // Turning the skip off entirely, once any block has been walked.
        let conflict = reconcile_decrypt_from(Some(100), Some(1), None).unwrap_err();
        assert_eq!(conflict.stored, 100);
        assert_eq!(conflict.requested, None);
    }

    /// A bound above the tip lightwalletd reported would decrypt nothing at
    /// all. Such a bound can only come from wrong creation times, so it is
    /// dropped and every block is decrypted. With no tip to compare against
    /// the bound passes through; the creation-time check already ran.
    #[test]
    fn a_bound_above_the_known_tip_is_not_applied() {
        assert_eq!(bound_within_tip(Some(500), Some(400)), None);
        assert_eq!(bound_within_tip(Some(400), Some(400)), Some(400));
        assert_eq!(bound_within_tip(Some(300), Some(400)), Some(300));
        assert_eq!(bound_within_tip(Some(500), None), Some(500));
        assert_eq!(bound_within_tip(None, Some(400)), None);
    }

    #[test]
    fn a_dropped_skip_is_said_and_a_kept_one_is_not() {
        let line = dropped_bound_line(Some(500), Some(400)).expect("the skip was dropped");
        assert!(
            line.contains("every block") && line.contains("500"),
            "{line}"
        );
        assert_eq!(dropped_bound_line(Some(500), Some(500)), None);
        assert_eq!(dropped_bound_line(Some(500), None), None);
        assert_eq!(dropped_bound_line(None, Some(400)), None);
    }

    /// The sweep resumes under the bound the scan actually used, read from
    /// the checkpoint, so no later change to the form can make it conflict.
    #[test]
    fn the_saved_bound_is_read_back_for_the_same_keys_only() {
        let keys = [[0x13; 32]];
        let dir = fresh_dir("saved-decrypt-from");

        let missing = dir.join("missing.checkpoint");
        assert_eq!(
            saved_decrypt_from(&missing, P2pNetwork::Regtest, &keys).unwrap(),
            None
        );

        for (name, bound) in [("skip", Some(300)), ("every", None)] {
            let mut scanner = SproutScanner::with_decrypt_from(&keys, bound);
            scanner
                .scan_block_at(&[], [0xCF; 32], 400)
                .expect("an empty block");
            let path = dir.join(format!("{name}.checkpoint"));
            save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();
            assert_eq!(
                saved_decrypt_from(&path, P2pNetwork::Regtest, &keys).unwrap(),
                Some(bound),
                "{name}"
            );
            // Another key set's checkpoint is refused, not read.
            assert!(saved_decrypt_from(&path, P2pNetwork::Regtest, &[[0x14; 32]]).is_err());
            discard_checkpoint(&path).unwrap();
        }
    }

    #[tokio::test]
    async fn resuming_a_skipping_scan_without_the_skip_is_refused_before_any_peer() {
        let keys = [[0x12; 32]];
        let mut scanner = SproutScanner::with_decrypt_from(&keys, Some(300));
        scanner
            .scan_block_at(&[], [0xCE; 32], 400)
            .expect("an empty block");
        let dir = fresh_dir("decrypt-bound-resume");
        let path = dir.join("skip.checkpoint");
        save_checkpoint(&scanner, P2pNetwork::Regtest, &path).unwrap();

        let err = run_sprout_scan(&keys, P2pNetwork::Regtest, &[], None, &path, |_| {})
            .await
            .expect_err("blocks below 300 were never decrypted");
        let message = err.to_string();
        assert!(message.contains("300"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
        // The file is kept: it is still a valid scan under its own bound.
        assert!(path.exists());
        discard_checkpoint(&path).unwrap();
    }

    /// Review of #265, round 2: a hash mismatch against a pinned checkpoint
    /// or the [`TipAnchor`] used to return without saving, losing up to a
    /// page of work. It must still stop — fail closed — but first save what
    /// was consumed before the mismatching page, and none of that page.
    #[test]
    fn a_hash_mismatch_saves_progress_before_the_page_and_none_of_it() {
        let dir = ScratchDir::new("mismatch-save");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        let mut scanner = SproutScanner::new(&keys);
        let mut height = 1u32;

        // An anchor further up, so the first page is checked against nothing
        // and consumed. Nothing is saved yet: the page is under
        // CHECKPOINT_EVERY.
        let anchor = TipAnchor {
            height: 5,
            hash: [0xAA; 32],
        };
        let good = Page {
            parent: [0; 32],
            blocks: vec![
                ([1; 32], Vec::new()),
                ([2; 32], Vec::new()),
                ([3; 32], Vec::new()),
            ],
        };
        consume_page_or_save(
            &mut scanner,
            &good,
            P2pNetwork::Regtest,
            Some(anchor),
            &mut height,
            &path,
        )
        .expect("an unanchored page is consumed");
        assert_eq!(height, 4);
        assert!(!path.exists(), "no checkpoint is due yet");

        // The next page disagrees with the anchor at height 5. Height 4,
        // before it in the same page, is from the same peer and is not kept.
        let forged = Page {
            parent: [3; 32],
            blocks: vec![
                ([4; 32], Vec::new()),
                ([5; 32], Vec::new()),
                ([6; 32], Vec::new()),
            ],
        };
        let err = consume_page_or_save(
            &mut scanner,
            &forged,
            P2pNetwork::Regtest,
            Some(anchor),
            &mut height,
            &path,
        )
        .expect_err("a mismatch stops the scan");
        let text = err.to_string();
        assert!(text.contains("height 5"), "{text}");
        assert!(text.contains("Re-run"), "{text}");
        assert!(text.contains("--peer"), "{text}");
        assert!(text.contains("saved"), "{text}");
        assert_eq!(height, 4, "the scan does not advance into the forged page");

        let saved = load_checkpoint(&path, P2pNetwork::Regtest, &keys)
            .expect("the checkpoint loads")
            .expect("progress before the forged page was saved");
        let cursor = saved.cursor().expect("a cursor");
        assert_eq!(
            cursor.last_height, 3,
            "up to the last block before the page"
        );
        assert_eq!(cursor.last_block_hash, [3; 32]);
        assert!(
            !saved.is_complete(),
            "a stopped scan never reads as complete"
        );
    }

    /// A mismatch on the first page of a fresh scan has nothing before it to
    /// save, and must not claim "progress up to height 0".
    #[test]
    fn a_mismatch_on_the_first_page_does_not_claim_progress() {
        let dir = ScratchDir::new("mismatch-first-page");
        let keys = [[0x11; 32]];
        let path = checkpoint_path(&dir.0, &keys);
        let mut scanner = SproutScanner::new(&keys);
        let mut height = 1u32;
        let anchor = TipAnchor {
            height: 1,
            hash: [0xAA; 32],
        };
        let forged = Page {
            parent: [0; 32],
            blocks: vec![([1; 32], Vec::new())],
        };
        let text = consume_page_or_save(
            &mut scanner,
            &forged,
            P2pNetwork::Regtest,
            Some(anchor),
            &mut height,
            &path,
        )
        .expect_err("a mismatch stops the scan")
        .to_string();
        assert!(!text.contains("height 0"), "{text}");
        assert!(text.contains("Nothing had been scanned yet"), "{text}");
        assert!(text.contains("--peer"), "{text}");
        assert_eq!(height, 1);
    }
}
