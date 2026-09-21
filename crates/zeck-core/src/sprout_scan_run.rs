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
//! 4. four checkpoint hashes must match at fixed heights.
//!
//! Together those pin both ends of every segment. Forging blocks between
//! two checkpoints requires the forged chain's last `prev_hash` to equal the
//! real block before the next checkpoint — which requires that real block,
//! which requires its real work. No block from genesis to Canopy can be
//! inserted, omitted or substituted without breaking a hash link to a
//! pinned point.
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
//! The checkpoint file is likewise unauthenticated: it carries no MAC, and
//! its `last_height` alone decides whether the scan is finished. Editing
//! that one field to the target makes a scan "complete" instantly. It is
//! now checked against the requested key set and the network's range, which
//! catches the accidental cases, but not a deliberately edited file.
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
        peer::Peer,
        pool::{connect_to_any, PoolError, PEER_RECONNECT_DELAY},
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
const CHECKPOINT_EVERY: u64 = 500;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerWaitReason {
    /// Every candidate refused a connection slot. Routine on a busy network.
    AllPeersBusy,
    /// The DNS seeds would not resolve. Usually this machine's connection.
    SeedsUnresolved,
}

/// The scan is alive, has no peer, and is waiting before trying again.
///
/// Carried on [`ScanTick`] so it reaches the CLI and the GUI through the
/// progress callback they already listen to, rather than a second channel
/// each would have to learn about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        match self.reason {
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
        }
    }
}

/// Progress, reported often enough that a multi-hour run never looks stalled.
#[derive(Debug, Clone, Copy)]
pub struct ScanTick {
    pub height: u32,
    pub target: u32,
    pub notes_found: usize,
    pub joinsplits_seen: u64,
    /// Set when this tick reports a wait for a peer rather than blocks
    /// scanned. The other fields still hold the scan's position, so a surface
    /// that ignores this shows stale-but-true progress, never garbage.
    pub peer_wait: Option<PeerWait>,
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

    let bound = network.sprout_scan_bound();
    let target = bound.loop_limit();

    // Resume if we can. A checkpoint that will not load is reported rather
    // than silently discarded: starting a six-hour scan over because a file
    // was quietly ignored is worse than stopping to say so.
    let mut scanner = match std::fs::read(checkpoint_file) {
        Ok(bytes) => {
            let checkpoint = SproutScanCheckpoint::from_bytes(bytes);
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

            // And for this network. A completed mainnet checkpoint carries a
            // last_height past the testnet target, so resuming it under
            // testnet would skip the loop entirely and hand back mainnet
            // notes as a finished testnet scan.
            if resumed.progress().last_height > target {
                return Err(ZeckError::TransactionBuild(format!(
                    "the scan checkpoint at {} reaches height {}, past this network's \
                     Sprout range ({target}). It was almost certainly made on a different \
                     network.",
                    checkpoint_file.display(),
                    resumed.progress().last_height
                )));
            }
            resumed
        }
        Err(_) => SproutScanner::new(spending_keys),
    };

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

    // A scan that is already complete has nothing to fetch, so it must not
    // ask for a peer. The GUI's sweep re-runs a finished scan purely to get
    // its notes back; connecting first made that depend on a free slot it
    // never used, and now that acquisition is persistent it would have sat
    // out the whole budget before sweeping funds it already held.
    if height >= target {
        save_checkpoint(&scanner, checkpoint_file)?;
        return scanner
            .finish()
            .map_err(|err| ZeckError::TransactionBuild(format!("finishing the scan: {err}")));
    }

    // A wait is reported as a tick at the scan's current position, so the
    // surfaces hear about it through the callback they already have.
    let waiting_tick = |scanner: &SproutScanner, height: u32, wait: PeerWait| {
        let p = scanner.progress();
        ScanTick {
            height,
            target,
            notes_found: p.notes_found,
            joinsplits_seen: p.joinsplits_seen,
            peer_wait: Some(wait),
        }
    };

    let peer = connect_peer(network, extra_peers, &[], |wait| {
        progress(waiting_tick(&scanner, height, wait));
    })
    .await?;

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
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ZeckResult<Page>>(1);
    let mut fetcher = PageFetcher {
        peer,
        locator,
        empty_replies: 0,
        fetched: height,
        target,
        bound,
        network,
        peers: extra_peers.to_vec(),
        waits: wait_tx,
    };
    // Aborted when this future is dropped, not only when it finishes.
    // Dropping the scan is how it is cancelled, and a detached fetcher would
    // otherwise outlive the cancel by however long it had left to wait for a
    // peer — up to the whole acquisition budget, holding sockets open for a
    // scan nobody is running.
    let fetch_task = AbortOnDrop(tokio::spawn(async move {
        while fetcher.fetched < fetcher.target {
            match fetcher.next_page().await {
                Ok(None) => continue,
                // Empty page: the chain ended (see `PageFetcher::next_page`).
                // Dropping the sender ends the consumer's loop.
                Ok(Some(page)) if page.is_empty() => return,
                Ok(Some(page)) => {
                    fetcher.fetched += page.len() as u32;
                    if tx.send(Ok(page)).await.is_err() {
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

    while height < target {
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
        let Some(page) = page else {
            break;
        };
        let page = page?;

        // Already in header order, and already complete: `next_page`
        // assembles the page in the order the headers came in and treats a
        // missing block as a hard error, because a short page still looks
        // well-formed and would land every later commitment at the wrong
        // position. Re-deriving a hash list and a lookup map here only undid
        // that work.
        for (hash, block) in &page {
            if height >= target {
                break;
            }

            // A pinned block must be the block we were handed. This is what
            // makes a fabricated chain pointless: cheap forged headers link
            // to each other fine, but they cannot reproduce a real mainnet
            // hash at a real height without doing the work. Checked against
            // this block's own height, before the counter advances — the
            // checkpoints are keyed by true heights (genesis = 0).
            if let Some(expected) = crate::p2p::wire::checkpoint_at(network, height) {
                if *hash != expected {
                    return Err(ZeckError::Broadcast(format!(
                        "the chain this peer served does not match Zcash at height \
                         {height}. It is serving a different or fabricated chain, so the \
                         scan stops rather than search it. Re-run to pick another peer, \
                         or pass --peer with a node you trust."
                    )));
                }
            }

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
            height += 1;
        }

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
            peer_wait: None,
        });
    }

    // The consumer may finish before the fetcher (target reached mid-page).
    // Dropping the receiver already makes the next `send` fail and the task
    // return, but abort it explicitly so a peer connection is not held open
    // for however long the current request takes to time out.
    drop(fetch_task);

    save_checkpoint(&scanner, checkpoint_file)?;

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
    target: u32,
    bound: crate::p2p::wire::SproutScanBound,
    network: P2pNetwork,
    peers: Vec<String>,
    /// Where a wait for a peer is announced; see `run_sprout_scan`.
    waits: tokio::sync::mpsc::UnboundedSender<PeerWait>,
}

impl PageFetcher {
    /// Replace the peer, announcing any wait that takes.
    ///
    /// A failed send means the consumer has gone, and the page send that
    /// follows will notice that and end the task; nothing to do about it here.
    async fn reconnect(&mut self) -> ZeckResult<()> {
        let waits = &self.waits;
        self.peer = connect_peer(self.network, &self.peers, &[], |wait| {
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

    /// Fetch and validate one page of blocks.
    ///
    /// `Ok(None)` means "this peer was no good; a new one is connected, try
    /// again" — the caller loops. An empty page means the chain ended, which
    /// only happens when the scan has no fixed bound. Every check that decides
    /// whether a page may be scanned at all lives here: proof of work,
    /// continuity with the locator, and the internal linkage of the page.
    ///
    /// What deliberately does *not* live here is anything positional —
    /// checkpoint comparison and the tree append stay with the consumer, keyed
    /// on the true height, so this cannot affect where a commitment lands.
    async fn next_page(&mut self) -> ZeckResult<Option<Page>> {
        let height = self.fetched;
        let target = self.target;

        let headers = match self.peer.get_headers(&[self.locator]).await {
            Ok(h) if !h.is_empty() => h,
            // NOT a clean end of chain when the scan has a fixed bound.
            // `target` is then a pre-Canopy height every synced peer has, so
            // an empty reply below it means this peer cannot serve us —
            // under-synced, on another chain, or lying. Treating that as
            // completion is the worst failure here: a tree truncated at a
            // block boundary is a *genuine historical tree state*, so
            // witnesses still verify and spend, but nullifiers published after
            // the cut were never collected and a spent note gets offered as
            // spendable.
            //
            // Where there is no fixed bound, the chain tip is the only
            // possible ending and this reply is it. Matched on the variant
            // rather than on a sentinel height, so no `target` arriving at
            // `u32::MAX` by another route can disable the rule above.
            Ok(_) => {
                if self.bound.ends_at_chain_tip() {
                    return Ok(Some(Vec::new()));
                }
                return self
                    .rotate(format!(
                        "no peer would serve blocks past height {height} of {target}. The \
                         scan is incomplete and its results would be wrong, so it stops \
                         here rather than reporting a balance it cannot stand behind. \
                         Progress is saved; re-run to continue."
                    ))
                    .await;
            }
            Err(_) => {
                self.reconnect().await?;
                return Ok(None);
            }
        };

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
        self.empty_replies = 0;

        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash).collect();
        let mut blocks = match self.peer.get_blocks(&hashes).await {
            Ok(b) => b,
            Err(_) => {
                self.reconnect().await?;
                return Ok(None);
            }
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
        Ok(Some(page))
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
fn save_checkpoint(scanner: &SproutScanner, path: &Path) -> ZeckResult<()> {
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
    write_private(&tmp, scanner.checkpoint().as_bytes())?;
    std::fs::rename(&tmp, path).map_err(|err| {
        ZeckError::TransactionBuild(format!("replacing the scan checkpoint: {err}"))
    })?;
    Ok(())
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
    _prior: &[String],
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
    acquire_with_retry(budget, || connect_to_any(network, extra, 4), on_wait)
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
                reason,
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

    /// A finished checkpoint needs no peer. The GUI's sweep re-runs a
    /// completed scan to get its notes back; demanding a connection first
    /// made that depend on a free slot it never used, and with persistent
    /// retry would have made it wait out the budget for nothing.
    #[tokio::test]
    async fn a_finished_scan_does_not_need_a_peer() {
        let network = P2pNetwork::Testnet;
        let target = network.sprout_scan_bound().loop_limit();
        let mut scanner = SproutScanner::new(&[[0x11; 32]]);
        scanner
            .scan_block_at(&[], [0xCD; 32], target - 1)
            .expect("an empty block");

        let dir = std::env::temp_dir().join("argos-scan-finished-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("finished.checkpoint");
        save_checkpoint(&scanner, &path).unwrap();

        // The only peer offered is an address nothing listens on, and the
        // scan must still succeed: only a run that never dials can.
        let result = run_sprout_scan(
            &[[0x11; 32]],
            network,
            &["127.0.0.1:1".to_owned()],
            &path,
            |_| {},
        )
        .await;
        discard_checkpoint(&path);
        assert!(result.expect("finishes offline").notes.is_empty());
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
