//! Finding Sprout notes by rebuilding the commitment tree.
//!
//! This is the recovery path for a wallet that has a Sprout spending key and
//! nothing else — a bare `zkey` from a paper backup or a `z_exportkey`, or a
//! `wallet.dat` whose `z_importkey` ran without a rescan. There is no note
//! metadata to join against and no cached witness to reuse, so both have to
//! be reconstructed from the chain.
//!
//! # Why the whole tree
//!
//! A Sprout witness is a note's position in a commitment tree that spans
//! every JoinSplit ever made, network-wide. There is no way to compute one
//! note's path without having appended every commitment before it, in order.
//! That is why this cannot be a targeted lookup and has to be a sweep.
//!
//! ZIP 211 makes the sweep finite: nothing can be added to the Sprout pool
//! from Canopy onward, so the tree stops growing at a fixed height and the
//! range never expands.
//!
//! # Ordering is the whole correctness argument
//!
//! Commitments must be appended in exactly consensus order — both outputs of
//! each JoinSplit, each JoinSplit in transaction order, each transaction in
//! block order. A single misplaced append shifts every subsequent position,
//! and the resulting witness authenticates nothing. It fails at broadcast,
//! after proving, with no local signal that anything was wrong. So the
//! scanner appends every commitment it sees, including those from JoinSplits
//! it cannot decrypt — those notes belong to other people, and skipping them
//! would corrupt the tree for ours.
//!
//! # Spent notes
//!
//! A note found here may already have been spent. Its nullifier appears in
//! some later JoinSplit, so nullifiers are collected during the same pass and
//! matched at the end. Missing that check would mean offering the user a
//! balance they cannot move.

use std::collections::{HashMap, HashSet, VecDeque};

use argos_wallet_import::keys::{JsOutPoint, SproutJoinSplit};

use crate::{
    sprout::{self, SproutPaymentAddress},
    sprout_recovery::SpendableSproutNote,
    sprout_witness::{IncrementalMerkleTree, IncrementalWitness, WitnessError},
};

/// A key being scanned for, with its address precomputed.
struct ScanKey {
    a_sk: [u8; 32],
    address: SproutPaymentAddress,
    /// `sk_enc(a_sk)` as an x25519 secret, kept so the per-JoinSplit
    /// Diffie-Hellman agreement does not re-derive it on every attempt.
    enc_secret: x25519_dalek::StaticSecret,
}

impl ScanKey {
    fn new(a_sk: [u8; 32]) -> Self {
        Self {
            a_sk,
            address: SproutPaymentAddress::from_spending_key(&a_sk),
            enc_secret: x25519_dalek::StaticSecret::from(sprout::sk_enc(&a_sk)),
        }
    }

    /// The agreement for one JoinSplit's ephemeral key.
    ///
    /// Depends only on `(sk_enc, epk)`, so it is the same for both outputs —
    /// computed once per JoinSplit rather than once per output.
    fn agree(&self, epk: &[u8; 32]) -> [u8; 32] {
        *self
            .enc_secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*epk))
            .as_bytes()
    }
}

/// A note found mid-scan, whose witness is still being brought forward.
struct PendingNote {
    note: crate::sprout::SproutNotePlaintext,
    a_sk: [u8; 32],
    address: SproutPaymentAddress,
    commitment: [u8; 32],
    outpoint: JsOutPoint,
    nullifier: [u8; 32],
    witness: IncrementalWitness,
}

/// A decrypted note, before its witness exists.
///
/// Separate from `PendingNote` because the witness can only be taken once
/// the note's own commitment is in the tree, which happens after decryption.
struct DecryptedNote {
    note: crate::sprout::SproutNotePlaintext,
    a_sk: [u8; 32],
    address: SproutPaymentAddress,
    commitment: [u8; 32],
    outpoint: JsOutPoint,
    nullifier: [u8; 32],
}

/// Progress, for a scan that runs for hours.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SproutScanProgress {
    pub blocks_scanned: u64,
    pub joinsplits_seen: u64,
    pub commitments_appended: u64,
    pub notes_found: usize,
    /// Height of the last block fed in, so a resumed scan knows what to ask
    /// for next.
    pub last_height: u32,
}

/// Where the block walk had reached.
///
/// Without this a checkpoint restores a correct tree and has no idea which
/// block comes next — the tree cannot be advanced from an unknown position,
/// so "resume" would mean rescanning from genesis and re-appending
/// everything into a tree that already contains it. Stored as a hash, not
/// just a height, because the hash is what `getheaders` takes as a locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanCursor {
    pub last_block_hash: [u8; 32],
    pub last_height: u32,
}

pub const SPROUT_REORG_WINDOW: usize = 100;

struct BlockUndo {
    applied: ScanCursor,
    cursor_before: Option<ScanCursor>,
    tree_before: IncrementalMerkleTree,
    pending_len_before: usize,
    witnesses_before: Vec<IncrementalWitness>,
    spent_before: Vec<NullifierUndo>,
    progress_before: SproutScanProgress,
}

struct NullifierUndo {
    nullifier: [u8; 32],
    previous: Option<Option<[u8; 32]>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RewindError {
    #[error("the common ancestor is older than this checkpoint's retained rollback window")]
    BeyondRetainedWindow,
    #[error("the checkpoint rollback history is internally inconsistent")]
    CorruptHistory,
}

/// Scans blocks for notes belonging to a set of Sprout spending keys.
pub struct SproutScanner {
    keys: Vec<ScanKey>,
    tree: IncrementalMerkleTree,
    pending: Vec<PendingNote>,
    /// Every nullifier seen, to tell a live note from a spent one, with the
    /// transaction that revealed it. `None` only for nullifiers restored from
    /// a version-1 checkpoint, which did not record it.
    spent: HashMap<[u8; 32], Option<[u8; 32]>>,
    progress: SproutScanProgress,
    cursor: ScanCursor,
    /// The walk reached the chain tip at `cursor` — set by the scan runner
    /// when the fetcher reports the tip, cleared by any further block. A
    /// checkpoint left by a scan that stopped early reads `false`, so its
    /// cursor is never mistaken for full coverage.
    complete: bool,
    history: VecDeque<BlockUndo>,
    source_version: u8,
}

impl SproutScanner {
    pub fn new(spending_keys: &[[u8; 32]]) -> Self {
        Self {
            keys: spending_keys
                .iter()
                .map(|a_sk| ScanKey::new(*a_sk))
                .collect(),
            tree: IncrementalMerkleTree::default(),
            pending: Vec::new(),
            spent: HashMap::new(),
            progress: SproutScanProgress::default(),
            cursor: ScanCursor::default(),
            complete: false,
            history: VecDeque::new(),
            source_version: CHECKPOINT_VERSION,
        }
    }

    /// Where the walk has reached. `None` before any block is fed.
    pub fn cursor(&self) -> Option<ScanCursor> {
        (self.progress.blocks_scanned > 0).then_some(self.cursor)
    }

    /// Every nullifier the walk has seen on chain, with the transaction that
    /// revealed it where known. A note whose nullifier is here was spent at
    /// or below the cursor, whoever spent it.
    pub fn spent_nullifiers(&self) -> &HashMap<[u8; 32], Option<[u8; 32]>> {
        &self.spent
    }

    /// Record that the walk reached the chain tip at the current cursor.
    pub fn mark_complete(&mut self) {
        self.complete = true;
    }

    /// A scan stopped before the chain tip cannot supply complete evidence.
    pub fn mark_incomplete(&mut self) {
        self.complete = false;
    }

    /// Whether the walk ended at the chain tip rather than stopping early.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The keys this scanner is looking for, sorted and deduplicated.
    ///
    /// Exposed so a resumed checkpoint can be checked against the keys the
    /// caller actually asked about; the file path alone does not prove it.
    pub fn spending_keys(&self) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8; 32]> = self.keys.iter().map(|k| k.a_sk).collect();
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    pub fn progress(&self) -> SproutScanProgress {
        self.progress
    }

    /// Layout of the checkpoint this scanner was restored from.
    pub fn checkpoint_version(&self) -> u8 {
        self.source_version
    }

    /// The commitment tree root after everything appended so far.
    ///
    /// This is the anchor a spend built from this scan will use, so it is
    /// exposed for cross-checking against a node's `z_gettreestate`.
    pub fn anchor(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Feed one block's JoinSplits, in consensus order.
    pub fn scan_block(&mut self, joinsplits: &[SproutJoinSplit]) -> Result<(), WitnessError> {
        self.scan_block_at(joinsplits, [0u8; 32], 0)
    }

    /// Feed one block's JoinSplits, recording which block it was.
    ///
    /// The hash and height are what make a checkpoint resumable; a scan that
    /// does not record them can restore its tree but not continue the walk.
    pub fn scan_block_at(
        &mut self,
        joinsplits: &[SproutJoinSplit],
        block_hash: [u8; 32],
        height: u32,
    ) -> Result<(), WitnessError> {
        let located = height > 0 && block_hash != [0; 32];
        let prior = self.cursor();
        let contiguous = located
            && prior.is_some_and(|cursor| {
                cursor.last_height > 0
                    && cursor.last_block_hash != [0; 32]
                    && cursor.last_height.checked_add(1) == Some(height)
            });
        let applied = ScanCursor {
            last_block_hash: block_hash,
            last_height: height,
        };
        let mut seen_nullifiers = HashSet::new();
        let spent_before = joinsplits
            .iter()
            .flat_map(|js| js.nullifiers)
            .filter(|nf| seen_nullifiers.insert(*nf))
            .map(|nullifier| NullifierUndo {
                nullifier,
                previous: self.spent.get(&nullifier).copied(),
            })
            .collect();
        let cursor_before_raw = self.cursor;
        let undo = BlockUndo {
            applied,
            cursor_before: if contiguous { prior } else { None },
            tree_before: self.tree.clone(),
            pending_len_before: self.pending.len(),
            witnesses_before: self.pending.iter().map(|p| p.witness.clone()).collect(),
            spent_before,
            progress_before: self.progress,
        };
        let complete_before = self.complete;
        for js in joinsplits {
            if let Err(err) = self.scan_joinsplit(js) {
                self.restore_block(undo);
                self.cursor = cursor_before_raw;
                self.complete = complete_before;
                return Err(err);
            }
        }
        self.progress.blocks_scanned += 1;
        self.progress.last_height = height;
        // The tip has moved past wherever a previous run ended.
        self.complete = false;
        self.cursor = applied;
        if located {
            if !contiguous {
                self.history.clear();
            }
            self.history.push_back(undo);
            if self.history.len() > SPROUT_REORG_WINDOW {
                self.history.pop_front();
            }
        } else {
            // An unlocated helper call changes state but proves no chain
            // ancestry, so no earlier rollback frames can cross it.
            self.history.clear();
        }
        Ok(())
    }

    fn restore_block(&mut self, undo: BlockUndo) {
        self.tree = undo.tree_before;
        self.pending.truncate(undo.pending_len_before);
        for (pending, witness) in self.pending.iter_mut().zip(undo.witnesses_before) {
            pending.witness = witness;
        }
        for entry in undo.spent_before {
            match entry.previous {
                Some(previous) => {
                    self.spent.insert(entry.nullifier, previous);
                }
                None => {
                    self.spent.remove(&entry.nullifier);
                }
            }
        }
        self.progress = undo.progress_before;
        self.cursor = undo.cursor_before.unwrap_or_default();
    }

    /// Candidate ancestors in newest-first order, limited to actual block
    /// hashes. The oldest candidate is the cursor before the oldest undo.
    pub fn rollback_locators(&self) -> Vec<ScanCursor> {
        let Some(current) = self
            .cursor()
            .filter(|cursor| cursor.last_height > 0 && cursor.last_block_hash != [0; 32])
        else {
            return Vec::new();
        };
        let mut locators = vec![current];
        let mut expected = current;
        for frame in self.history.iter().rev() {
            if frame.applied != expected {
                break;
            }
            let Some(previous) = frame.cursor_before else {
                break;
            };
            locators.push(previous);
            expected = previous;
        }
        locators
    }

    /// Restore all state after a retained ancestor. Validate the whole
    /// suffix first so a corrupt in-memory history cannot partially rewind.
    pub fn rewind_to(&mut self, ancestor_hash: [u8; 32]) -> Result<u32, RewindError> {
        let current = self
            .cursor()
            .filter(|cursor| cursor.last_height > 0 && cursor.last_block_hash != [0; 32]);
        let Some(current) = current else {
            return Err(RewindError::BeyondRetainedWindow);
        };
        let mut expected = current;
        let mut pending_len = self.pending.len();
        let mut blocks = 0usize;
        if expected.last_block_hash != ancestor_hash {
            for frame in self.history.iter().rev() {
                if frame.applied != expected
                    || frame.witnesses_before.len() != frame.pending_len_before
                    || frame.pending_len_before > pending_len
                    || frame.cursor_before.is_some_and(|previous| {
                        previous.last_height.checked_add(1) != Some(frame.applied.last_height)
                    })
                {
                    return Err(RewindError::CorruptHistory);
                }
                pending_len = frame.pending_len_before;
                blocks += 1;
                let Some(previous) = frame.cursor_before else {
                    break;
                };
                expected = previous;
                if expected.last_block_hash == ancestor_hash {
                    break;
                }
            }
            if expected.last_block_hash != ancestor_hash {
                return Err(RewindError::BeyondRetainedWindow);
            }
        }
        for _ in 0..blocks {
            let frame = self.history.pop_back().expect("validated undo frame");
            self.restore_block(frame);
        }
        self.complete = false;
        Ok(blocks as u32)
    }

    fn scan_joinsplit(&mut self, js: &SproutJoinSplit) -> Result<(), WitnessError> {
        self.progress.joinsplits_seen += 1;

        // A JoinSplit's nullifiers spend earlier notes. Recorded before the
        // outputs, though order does not matter here, because the match
        // happens at the end.
        for nf in &js.nullifiers {
            self.spent.insert(*nf, Some(js.txid));
        }

        let h_sig = sprout::h_sig(&js.random_seed, &js.nullifiers, &js.joinsplit_pubkey);

        // One Diffie-Hellman per key for this JoinSplit, shared by both of its
        // outputs. Trial decryption is the dominant cost of a full-chain scan,
        // and the agreement is the expensive part of it.
        let agreements: Vec<[u8; 32]> = self
            .keys
            .iter()
            .map(|k| k.agree(&js.ephemeral_key))
            .collect();

        for (index, commitment) in js.commitments.iter().enumerate() {
            let found = self.try_decrypt(js, index, &h_sig, commitment, &agreements);

            // Every commitment is appended, decryptable or not. Skipping
            // other people's notes would shift every later position.
            self.tree.append(*commitment)?;
            self.progress.commitments_appended += 1;

            // Notes found earlier advance by this commitment. Done before
            // the new note is pushed, so a note is never fed its own
            // commitment twice.
            for pending in &mut self.pending {
                pending.witness.append(*commitment)?;
            }

            if let Some(found) = found {
                // Taken from the tree *after* its own commitment is
                // appended, matching zcashd, where a witness is obtained
                // from the tree that already contains the note. Building it
                // from the tree beforehand yields a witness over an empty
                // tree for the very first note.
                self.pending.push(PendingNote {
                    witness: IncrementalWitness::from_tree(self.tree.clone()),
                    note: found.note,
                    a_sk: found.a_sk,
                    address: found.address,
                    commitment: found.commitment,
                    outpoint: found.outpoint,
                    nullifier: found.nullifier,
                });
                self.progress.notes_found += 1;
            }
        }

        Ok(())
    }

    /// Trial-decrypt one JoinSplit output against every key.
    fn try_decrypt(
        &self,
        js: &SproutJoinSplit,
        index: usize,
        h_sig: &[u8; 32],
        commitment: &[u8; 32],
        agreements: &[[u8; 32]],
    ) -> Option<DecryptedNote> {
        let ciphertext = js.ciphertexts.get(index)?;

        for (key, dhsecret) in self.keys.iter().zip(agreements) {
            let Ok(note) = sprout::decrypt_note_with_agreement(
                dhsecret,
                &js.ephemeral_key,
                key.address.pk_enc(),
                ciphertext,
                h_sig,
                index as u8,
            ) else {
                continue;
            };

            // Authentication says the ciphertext was not tampered with. It
            // does not say the plaintext is the note this commitment
            // commits to, and only the latter makes it spendable.
            let derived =
                sprout::note_commitment(key.address.a_pk(), note.value, &note.rho, &note.r);
            if derived != *commitment {
                continue;
            }

            let nullifier = sprout::prf_nf(&key.a_sk, &note.rho);

            return Some(DecryptedNote {
                note,
                a_sk: key.a_sk,
                address: key.address,
                commitment: derived,
                outpoint: JsOutPoint {
                    txid: js.txid,
                    js_index: js.js_index,
                    output_index: index as u8,
                },
                nullifier,
            });
        }
        None
    }

    /// Finish the scan, returning only notes that are still unspent.
    ///
    /// Spent notes are dropped rather than reported as balance: their
    /// nullifiers were published on the same chain this scan just read, so
    /// offering them would promise funds that cannot move.
    pub fn finish(self) -> Result<SproutScanResult, WitnessError> {
        let mut notes = Vec::new();
        let mut spent_notes = 0usize;

        for pending in self.pending {
            if self.spent.contains_key(&pending.nullifier) {
                spent_notes += 1;
                continue;
            }
            notes.push(SpendableSproutNote {
                note: pending.note,
                a_sk: pending.a_sk,
                address: pending.address,
                commitment: pending.commitment,
                anchor: pending.witness.root(),
                witness_path: pending.witness.encode_for_prover()?.to_vec(),
                outpoint: pending.outpoint,
            });
        }

        Ok(SproutScanResult {
            notes,
            spent_notes,
            anchor: self.tree.root(),
            progress: self.progress,
        })
    }
}

/// What a completed scan found.
#[derive(Debug)]
pub struct SproutScanResult {
    /// Unspent notes, each with a witness encoded for the prover.
    pub notes: Vec<SpendableSproutNote>,
    /// Notes that were found but had already been spent.
    pub spent_notes: usize,
    /// The commitment tree root at the end of the scan.
    pub anchor: [u8; 32],
    pub progress: SproutScanProgress,
}

impl SproutScanResult {
    pub fn total_value(&self) -> u64 {
        self.notes.iter().map(|n| n.note.value).sum()
    }
}

/// A scan's full state, enough to resume exactly where it stopped.
///
/// The commitment tree is the reason this exists. It is not derivable from
/// anything cheaper: reconstructing it means re-reading every block from
/// genesis, which is the multi-hour, multi-gigabyte cost the whole scan is
/// trying not to repeat. In-flight witnesses are the same — a witness only
/// advances by seeing every subsequent commitment, so a lost witness cannot
/// be rebuilt without another full pass.
///
/// Nullifiers are kept too. A note found early may be spent by a JoinSplit
/// that has not been reached yet, so dropping the set across a resume would
/// report spent notes as spendable.
///
/// The format is a length-prefixed concatenation with a version byte, in the
/// same CompactSize style as everything else here. Deliberately not JSON: it
/// holds spending keys and note plaintexts, and a text format invites being
/// pasted into a bug report.
pub struct SproutScanCheckpoint {
    bytes: Vec<u8>,
}

/// Bumped when the layout changes, so a stale file is refused rather than
/// misread into a wrong tree — which would produce worthless witnesses with
/// no visible error.
///
/// Version 3 adds bounded reorg history after the version-2 completion byte.
/// Version 2 records the revealing txid with each nullifier and completion.
/// Version 1 is still read — a scan measured in hours must survive an upgrade
/// mid-way — with no txids and `complete = false`.
const CHECKPOINT_VERSION: u8 = 3;

/// The oldest layout still read.
const OLDEST_READABLE_VERSION: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("this checkpoint was written by a different version of Argos and cannot be resumed")]
    WrongVersion,
    #[error("the checkpoint file is corrupt or truncated")]
    Corrupt,
    #[error(transparent)]
    Witness(#[from] WitnessError),
}

impl SproutScanCheckpoint {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// What a checkpoint says about the chain, without the scan state needed to
/// continue it.
///
/// The spent set is all a caller asking "was this note spent?" needs. Reading
/// it through [`SproutScanner::resume`] rebuilds the commitment tree and
/// every pending witness only to discard them, then the caller clones the
/// set; on a completed mainnet scan that is the bulk of a large file, parsed
/// on every wallet open. [`read_chain_evidence`] walks past both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEvidence {
    /// Sorted and deduplicated, as [`SproutScanner::spending_keys`].
    pub spending_keys: Vec<[u8; 32]>,
    /// Every nullifier seen, with its revealing txid where recorded.
    pub spent: HashMap<[u8; 32], Option<[u8; 32]>>,
    /// Where the walk reached; `None` if it scanned nothing.
    pub cursor: Option<ScanCursor>,
    /// Whether the walk ended at the chain tip.
    pub complete: bool,
}

/// The key set a checkpoint was made for, read from its header alone.
///
/// Everything a caller needs to decide whether a checkpoint covers a wallet,
/// without parsing a spent set that runs to hundreds of megabytes. `bytes`
/// may be only a prefix of the checkpoint, as long as it reaches the keys.
pub fn read_spending_keys(bytes: &[u8]) -> Result<Vec<[u8; 32]>, CheckpointError> {
    let mut r = codec::Reader::new(bytes);
    read_version(&mut r)?;
    r.bytes().ok_or(CheckpointError::Corrupt)?; // tree
    let key_count = r.u64().ok_or(CheckpointError::Corrupt)?;
    let mut keys = Vec::new();
    for _ in 0..key_count {
        keys.push(r.array32().ok_or(CheckpointError::Corrupt)?);
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

/// Read a checkpoint's chain evidence. Validates the layout end to end —
/// version, every length, no trailing bytes — but does not parse the tree or
/// the witnesses, whose correctness no spent verdict depends on.
pub fn read_chain_evidence(
    checkpoint: &SproutScanCheckpoint,
) -> Result<ChainEvidence, CheckpointError> {
    let mut r = codec::Reader::new(checkpoint.as_bytes());
    let version = read_version(&mut r)?;
    r.bytes().ok_or(CheckpointError::Corrupt)?; // tree

    let key_count = r.u64().ok_or(CheckpointError::Corrupt)?;
    let mut spending_keys = Vec::new();
    for _ in 0..key_count {
        spending_keys.push(r.array32().ok_or(CheckpointError::Corrupt)?);
    }
    spending_keys.sort_unstable();
    spending_keys.dedup();

    let pending_count = r.u64().ok_or(CheckpointError::Corrupt)?;
    for _ in 0..pending_count {
        // a_sk, value, rho, r
        r.take(32 + 8 + 32 + 32).ok_or(CheckpointError::Corrupt)?;
        r.bytes().ok_or(CheckpointError::Corrupt)?; // memo
                                                    // commitment, nullifier, txid, js_index, output_index
        r.take(32 + 32 + 32 + 8 + 1)
            .ok_or(CheckpointError::Corrupt)?;
        r.bytes().ok_or(CheckpointError::Corrupt)?; // witness
    }

    let spent = read_spent(&mut r, version)?;
    let blocks_scanned = r.u64().ok_or(CheckpointError::Corrupt)?;
    r.take(8 * 4).ok_or(CheckpointError::Corrupt)?; // the rest of the progress
    let cursor = ScanCursor {
        last_block_hash: r.array32().ok_or(CheckpointError::Corrupt)?,
        last_height: u32::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?,
    };
    let complete = read_complete(&mut r, version)?;
    if version >= 3 {
        let _ = read_history(&mut r, cursor, false)?;
    }
    if r.pos != r.bytes.len() {
        return Err(CheckpointError::Corrupt);
    }

    Ok(ChainEvidence {
        spending_keys,
        spent,
        cursor: (blocks_scanned > 0).then_some(cursor),
        complete,
    })
}

fn read_version(r: &mut codec::Reader<'_>) -> Result<u8, CheckpointError> {
    match r.take(1).and_then(|v| v.first().copied()) {
        Some(v) if (OLDEST_READABLE_VERSION..=CHECKPOINT_VERSION).contains(&v) => Ok(v),
        Some(_) => Err(CheckpointError::WrongVersion),
        None => Err(CheckpointError::Corrupt),
    }
}

fn read_spent(
    r: &mut codec::Reader<'_>,
    version: u8,
) -> Result<HashMap<[u8; 32], Option<[u8; 32]>>, CheckpointError> {
    let count = r.u64().ok_or(CheckpointError::Corrupt)?;
    let mut spent = HashMap::new();
    for _ in 0..count {
        let nf = r.array32().ok_or(CheckpointError::Corrupt)?;
        let txid = if version >= 2 {
            match r.take(1).and_then(|b| b.first().copied()) {
                Some(0) => None,
                Some(1) => Some(r.array32().ok_or(CheckpointError::Corrupt)?),
                _ => return Err(CheckpointError::Corrupt),
            }
        } else {
            None
        };
        spent.insert(nf, txid);
    }
    Ok(spent)
}

fn read_complete(r: &mut codec::Reader<'_>, version: u8) -> Result<bool, CheckpointError> {
    if version < 2 {
        return Ok(false);
    }
    match r.take(1).and_then(|b| b.first().copied()) {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(CheckpointError::Corrupt),
    }
}

fn write_cursor(out: &mut Vec<u8>, cursor: ScanCursor) {
    out.extend_from_slice(&cursor.last_block_hash);
    codec::put_u64(out, u64::from(cursor.last_height));
}

fn read_cursor(r: &mut codec::Reader<'_>) -> Result<ScanCursor, CheckpointError> {
    Ok(ScanCursor {
        last_block_hash: r.array32().ok_or(CheckpointError::Corrupt)?,
        last_height: u32::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?,
    })
}

fn write_progress(out: &mut Vec<u8>, progress: SproutScanProgress) {
    for value in [
        progress.blocks_scanned,
        progress.joinsplits_seen,
        progress.commitments_appended,
        progress.notes_found as u64,
        u64::from(progress.last_height),
    ] {
        codec::put_u64(out, value);
    }
}

fn read_progress(r: &mut codec::Reader<'_>) -> Result<SproutScanProgress, CheckpointError> {
    Ok(SproutScanProgress {
        blocks_scanned: r.u64().ok_or(CheckpointError::Corrupt)?,
        joinsplits_seen: r.u64().ok_or(CheckpointError::Corrupt)?,
        commitments_appended: r.u64().ok_or(CheckpointError::Corrupt)?,
        notes_found: usize::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?,
        last_height: u32::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?,
    })
}

fn read_history(
    r: &mut codec::Reader<'_>,
    cursor: ScanCursor,
    parse_state: bool,
) -> Result<VecDeque<BlockUndo>, CheckpointError> {
    let count = usize::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
        .map_err(|_| CheckpointError::Corrupt)?;
    // Check before allocation or iteration. Every frame needs at least a
    // cursor, prior-cursor tag, tree length, three counts and five counters.
    if count > SPROUT_REORG_WINDOW || count > (r.bytes.len() - r.pos) / 113 {
        return Err(CheckpointError::Corrupt);
    }
    let mut history: VecDeque<BlockUndo> = VecDeque::new();
    for _ in 0..count {
        let applied = read_cursor(r)?;
        let cursor_before = match r.take(1).and_then(|b| b.first().copied()) {
            Some(0) => None,
            Some(1) => Some(read_cursor(r)?),
            _ => return Err(CheckpointError::Corrupt),
        };
        if let Some(previous) = cursor_before {
            if previous.last_height.checked_add(1) != Some(applied.last_height) {
                return Err(CheckpointError::Corrupt);
            }
        }
        if let Some(previous_frame) = history.back() {
            if cursor_before != Some(previous_frame.applied) {
                return Err(CheckpointError::Corrupt);
            }
        }
        let tree_bytes = r.bytes().ok_or(CheckpointError::Corrupt)?;
        let tree_before = if parse_state {
            IncrementalMerkleTree::parse(tree_bytes)?
        } else {
            IncrementalMerkleTree::default()
        };
        let pending_len_before = usize::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?;
        let witness_count = usize::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?;
        if witness_count != pending_len_before || witness_count > (r.bytes.len() - r.pos) / 8 {
            return Err(CheckpointError::Corrupt);
        }
        let mut witnesses_before = Vec::new();
        for _ in 0..witness_count {
            let bytes = r.bytes().ok_or(CheckpointError::Corrupt)?;
            if parse_state {
                witnesses_before.push(IncrementalWitness::parse_one(bytes)?);
            }
        }
        let spent_count = usize::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
            .map_err(|_| CheckpointError::Corrupt)?;
        if spent_count > (r.bytes.len() - r.pos) / 33 {
            return Err(CheckpointError::Corrupt);
        }
        let mut spent_before = Vec::new();
        let mut seen = HashSet::new();
        for _ in 0..spent_count {
            let nullifier = r.array32().ok_or(CheckpointError::Corrupt)?;
            if !seen.insert(nullifier) {
                return Err(CheckpointError::Corrupt);
            }
            let previous = match r.take(1).and_then(|b| b.first().copied()) {
                Some(0) => None,
                Some(1) => Some(None),
                Some(2) => Some(Some(r.array32().ok_or(CheckpointError::Corrupt)?)),
                _ => return Err(CheckpointError::Corrupt),
            };
            if parse_state {
                spent_before.push(NullifierUndo {
                    nullifier,
                    previous,
                });
            }
        }
        let progress_before = read_progress(r)?;
        history.push_back(BlockUndo {
            applied,
            cursor_before,
            tree_before,
            pending_len_before,
            witnesses_before,
            spent_before,
            progress_before,
        });
    }
    if history.back().is_some_and(|frame| frame.applied != cursor) {
        return Err(CheckpointError::Corrupt);
    }
    Ok(history)
}

/// Minimal writer/reader for the checkpoint encoding.
mod codec {
    pub fn put_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
        put_u64(out, b.len() as u64);
        out.extend_from_slice(b);
    }
    pub struct Reader<'a> {
        pub bytes: &'a [u8],
        pub pos: usize,
    }
    impl<'a> Reader<'a> {
        pub fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, pos: 0 }
        }
        pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let end = self.pos.checked_add(n)?;
            let s = self.bytes.get(self.pos..end)?;
            self.pos = end;
            Some(s)
        }
        pub fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        pub fn bytes(&mut self) -> Option<&'a [u8]> {
            let n = usize::try_from(self.u64()?).ok()?;
            self.take(n)
        }
        pub fn array32(&mut self) -> Option<[u8; 32]> {
            self.take(32)?.try_into().ok()
        }
    }
}

impl SproutScanner {
    /// Capture everything needed to resume.
    pub fn checkpoint(&self) -> SproutScanCheckpoint {
        self.encode(CHECKPOINT_VERSION)
    }

    /// Write the given layout. Only the current one is written outside
    /// tests; version 1 exists so its reader stays tested.
    fn encode(&self, version: u8) -> SproutScanCheckpoint {
        use codec::{put_bytes, put_u64};

        let mut out = vec![version];

        put_bytes(&mut out, &self.tree.to_bytes());

        put_u64(&mut out, self.keys.len() as u64);
        for key in &self.keys {
            out.extend_from_slice(&key.a_sk);
        }

        put_u64(&mut out, self.pending.len() as u64);
        for p in &self.pending {
            out.extend_from_slice(&p.a_sk);
            put_u64(&mut out, p.note.value);
            out.extend_from_slice(&p.note.rho);
            out.extend_from_slice(&p.note.r);
            put_bytes(&mut out, &p.note.memo);
            out.extend_from_slice(&p.commitment);
            out.extend_from_slice(&p.nullifier);
            out.extend_from_slice(&p.outpoint.txid);
            put_u64(&mut out, p.outpoint.js_index);
            out.push(p.outpoint.output_index);
            put_bytes(&mut out, &p.witness.to_bytes());
        }

        put_u64(&mut out, self.spent.len() as u64);
        // Sorted, so the same scan state always produces the same bytes: a
        // checkpoint that differed run to run would be impossible to compare
        // when diagnosing a resume bug.
        let mut spent: Vec<_> = self.spent.iter().collect();
        spent.sort_unstable();
        for (nf, txid) in spent {
            out.extend_from_slice(nf);
            if version >= 2 {
                match txid {
                    Some(txid) => {
                        out.push(1);
                        out.extend_from_slice(txid);
                    }
                    None => out.push(0),
                }
            }
        }

        put_u64(&mut out, self.progress.blocks_scanned);
        put_u64(&mut out, self.progress.joinsplits_seen);
        put_u64(&mut out, self.progress.commitments_appended);
        put_u64(&mut out, self.progress.notes_found as u64);
        put_u64(&mut out, u64::from(self.progress.last_height));
        out.extend_from_slice(&self.cursor.last_block_hash);
        put_u64(&mut out, u64::from(self.cursor.last_height));
        if version >= 2 {
            out.push(u8::from(self.complete));
        }
        if version >= 3 {
            put_u64(&mut out, self.history.len() as u64);
            for frame in &self.history {
                write_cursor(&mut out, frame.applied);
                match frame.cursor_before {
                    Some(cursor) => {
                        out.push(1);
                        write_cursor(&mut out, cursor);
                    }
                    None => out.push(0),
                }
                put_bytes(&mut out, &frame.tree_before.to_bytes());
                put_u64(&mut out, frame.pending_len_before as u64);
                put_u64(&mut out, frame.witnesses_before.len() as u64);
                for witness in &frame.witnesses_before {
                    put_bytes(&mut out, &witness.to_bytes());
                }
                put_u64(&mut out, frame.spent_before.len() as u64);
                for undo in &frame.spent_before {
                    out.extend_from_slice(&undo.nullifier);
                    match undo.previous {
                        None => out.push(0),
                        Some(None) => out.push(1),
                        Some(Some(txid)) => {
                            out.push(2);
                            out.extend_from_slice(&txid);
                        }
                    }
                }
                write_progress(&mut out, frame.progress_before);
            }
        }

        SproutScanCheckpoint { bytes: out }
    }

    /// Rebuild a scanner from a checkpoint.
    pub fn resume(checkpoint: &SproutScanCheckpoint) -> Result<Self, CheckpointError> {
        let mut r = codec::Reader::new(checkpoint.as_bytes());
        let version = read_version(&mut r)?;

        let tree = IncrementalMerkleTree::parse(r.bytes().ok_or(CheckpointError::Corrupt)?)?;

        let key_count = r.u64().ok_or(CheckpointError::Corrupt)?;
        let mut keys = Vec::new();
        for _ in 0..key_count {
            let a_sk = r.array32().ok_or(CheckpointError::Corrupt)?;
            keys.push(ScanKey::new(a_sk));
        }

        let pending_count = r.u64().ok_or(CheckpointError::Corrupt)?;
        let mut pending = Vec::new();
        for _ in 0..pending_count {
            let a_sk = r.array32().ok_or(CheckpointError::Corrupt)?;
            let value = r.u64().ok_or(CheckpointError::Corrupt)?;
            let rho = r.array32().ok_or(CheckpointError::Corrupt)?;
            let note_r = r.array32().ok_or(CheckpointError::Corrupt)?;
            let memo: [u8; 512] = r
                .bytes()
                .ok_or(CheckpointError::Corrupt)?
                .try_into()
                .map_err(|_| CheckpointError::Corrupt)?;
            let commitment = r.array32().ok_or(CheckpointError::Corrupt)?;
            let nullifier = r.array32().ok_or(CheckpointError::Corrupt)?;
            let txid = r.array32().ok_or(CheckpointError::Corrupt)?;
            let js_index = r.u64().ok_or(CheckpointError::Corrupt)?;
            let output_index = *r
                .take(1)
                .and_then(|b| b.first())
                .ok_or(CheckpointError::Corrupt)?;
            let witness =
                IncrementalWitness::parse_one(r.bytes().ok_or(CheckpointError::Corrupt)?)?;

            pending.push(PendingNote {
                note: crate::sprout::SproutNotePlaintext {
                    value,
                    rho,
                    r: note_r,
                    memo,
                },
                a_sk,
                address: SproutPaymentAddress::from_spending_key(&a_sk),
                commitment,
                outpoint: JsOutPoint {
                    txid,
                    js_index,
                    output_index,
                },
                nullifier,
                witness,
            });
        }

        let spent = read_spent(&mut r, version)?;

        let progress = SproutScanProgress {
            blocks_scanned: r.u64().ok_or(CheckpointError::Corrupt)?,
            joinsplits_seen: r.u64().ok_or(CheckpointError::Corrupt)?,
            commitments_appended: r.u64().ok_or(CheckpointError::Corrupt)?,
            notes_found: usize::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
                .map_err(|_| CheckpointError::Corrupt)?,
            last_height: u32::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
                .map_err(|_| CheckpointError::Corrupt)?,
        };
        let cursor = ScanCursor {
            last_block_hash: r.array32().ok_or(CheckpointError::Corrupt)?,
            last_height: u32::try_from(r.u64().ok_or(CheckpointError::Corrupt)?)
                .map_err(|_| CheckpointError::Corrupt)?,
        };

        let complete = read_complete(&mut r, version)?;

        let history = if version >= 3 {
            read_history(&mut r, cursor, true)?
        } else {
            VecDeque::new()
        };

        if r.pos != r.bytes.len() {
            return Err(CheckpointError::Corrupt);
        }

        Ok(Self {
            keys,
            tree,
            pending,
            spent,
            progress,
            cursor,
            complete,
            history,
            source_version: version,
        })
    }
}

/// Group JoinSplits by transaction, preserving order.
///
/// Only used for reporting; the scan itself consumes them in sequence.
pub fn joinsplits_by_transaction(joinsplits: &[SproutJoinSplit]) -> HashMap<[u8; 32], Vec<u64>> {
    let mut out: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
    for js in joinsplits {
        out.entry(js.txid).or_default().push(js.js_index);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprout::SproutNotePlaintext;

    #[test]
    fn orphaned_nullifier_is_removed_and_the_note_is_live_again() {
        let key = [0x42; 32];
        let (receipt, nullifier) = joinsplit_paying(&key, 1234, 0, 11);
        let (mut spend, _) = joinsplit_paying(&[0x77; 32], 1, 0, 12);
        spend.nullifiers[0] = nullifier;
        let mut scanner = SproutScanner::new(&[key]);
        scanner.scan_block_at(&[receipt], [1; 32], 1).unwrap();
        scanner.scan_block_at(&[spend], [2; 32], 2).unwrap();
        assert!(scanner.spent.contains_key(&nullifier));

        assert_eq!(scanner.rewind_to([1; 32]), Ok(1));
        assert!(!scanner.spent.contains_key(&nullifier));
        let result = scanner.finish().unwrap();
        assert_eq!(result.spent_notes, 0);
        assert_eq!(result.total_value(), 1234);
    }

    #[test]
    fn orphaned_received_note_is_removed_and_the_previous_anchor_is_restored() {
        let key = [0x42; 32];
        let mut scanner = SproutScanner::new(&[key]);
        scanner.scan_block_at(&[], [1; 32], 1).unwrap();
        let anchor_before = scanner.anchor();
        let (receipt, _) = joinsplit_paying(&key, 1234, 0, 13);
        scanner.scan_block_at(&[receipt], [2; 32], 2).unwrap();
        assert_ne!(scanner.anchor(), anchor_before);

        assert_eq!(scanner.rewind_to([1; 32]), Ok(1));
        assert_eq!(scanner.anchor(), anchor_before);
        assert!(scanner.finish().unwrap().notes.is_empty());
    }

    #[test]
    fn rewind_removes_a_received_and_spent_orphan_note_atomically() {
        let key = [0x42; 32];
        let mut scanner = SproutScanner::new(&[key]);
        let (original, _) = joinsplit_paying(&key, 42, 0, 14);
        scanner.scan_block_at(&[original], [1; 32], 1).unwrap();
        let expected = scanner.checkpoint().as_bytes().to_vec();
        let (receipt, nullifier) = joinsplit_paying(&key, 1234, 0, 15);
        let (mut spend, _) = joinsplit_paying(&[0x77; 32], 1, 0, 16);
        spend.nullifiers[0] = nullifier;
        scanner.scan_block_at(&[receipt], [2; 32], 2).unwrap();
        scanner.scan_block_at(&[spend], [3; 32], 3).unwrap();
        scanner.mark_complete();

        assert_eq!(scanner.rewind_to([1; 32]), Ok(2));
        assert_eq!(scanner.cursor().unwrap().last_block_hash, [1; 32]);
        assert!(!scanner.is_complete());
        // Completion is intentionally cleared by rewind; all other state is exact.
        assert_eq!(scanner.checkpoint().as_bytes(), expected);
        let result = scanner.finish().unwrap();
        assert_eq!(result.total_value(), 42);
        assert_eq!(result.spent_notes, 0);
    }

    #[test]
    fn failed_block_scan_is_atomic() {
        // A tree with one available leaf lets the first commitment through,
        // then the second fails after nullifiers and progress have changed.
        let mut almost_full = vec![1];
        almost_full.extend_from_slice(&[1; 32]);
        almost_full.push(0);
        almost_full.push((crate::sprout_witness::TREE_DEPTH - 1) as u8);
        for _ in 0..crate::sprout_witness::TREE_DEPTH - 1 {
            almost_full.push(1);
            almost_full.extend_from_slice(&[2; 32]);
        }
        let mut scanner = SproutScanner::new(&[[0x42; 32]]);
        scanner.scan_block_at(&[], [1; 32], 1).unwrap();
        scanner.tree = IncrementalMerkleTree::parse(&almost_full).unwrap();
        scanner.mark_complete();
        let before = scanner.checkpoint().as_bytes().to_vec();
        let (js, _) = joinsplit_paying(&[0x77; 32], 1, 0, 17);

        assert_eq!(
            scanner.scan_block_at(&[js], [2; 32], 2),
            Err(WitnessError::TreeFull)
        );
        assert_eq!(scanner.checkpoint().as_bytes(), before);
    }

    #[test]
    fn rollback_history_keeps_exactly_one_hundred_blocks() {
        let mut scanner = SproutScanner::new(&[]);
        for height in 1..=101u32 {
            scanner
                .scan_block_at(&[], [height as u8; 32], height)
                .unwrap();
        }
        assert_eq!(scanner.history.len(), SPROUT_REORG_WINDOW);
        let locators = scanner.rollback_locators();
        assert_eq!(locators.len(), 101);
        assert_eq!(locators[0].last_height, 101);
        assert_eq!(locators[100].last_height, 1);
    }

    #[test]
    fn ancestor_older_than_the_window_is_refused_without_mutation() {
        let mut scanner = SproutScanner::new(&[]);
        for height in 1..=102u32 {
            scanner
                .scan_block_at(&[], [height as u8; 32], height)
                .unwrap();
        }
        let before = scanner.checkpoint().as_bytes().to_vec();
        assert_eq!(
            scanner.rewind_to([1; 32]),
            Err(RewindError::BeyondRetainedWindow)
        );
        assert_eq!(scanner.checkpoint().as_bytes(), before);
    }

    #[test]
    fn checkpoint_v3_round_trips_reorg_history() {
        let key = [0x42; 32];
        let mut scanner = SproutScanner::new(&[key]);
        for height in 1..=3u32 {
            let (js, _) = joinsplit_paying(&key, 100 * u64::from(height), 0, height as u8);
            scanner
                .scan_block_at(&[js], [height as u8; 32], height)
                .unwrap();
        }
        scanner.mark_complete();
        let checkpoint = scanner.checkpoint();
        let resumed = SproutScanner::resume(&checkpoint).unwrap();
        assert_eq!(resumed.checkpoint_version(), 3);
        assert_eq!(resumed.history.len(), 3);
        assert_eq!(resumed.checkpoint().as_bytes(), checkpoint.as_bytes());
        assert_eq!(resumed.tree.to_bytes(), scanner.tree.to_bytes());
        assert_eq!(resumed.pending.len(), scanner.pending.len());
        for (actual, expected) in resumed.pending.iter().zip(&scanner.pending) {
            assert_eq!(actual.witness.to_bytes(), expected.witness.to_bytes());
        }
        assert_eq!(resumed.spent, scanner.spent);
        assert_eq!(resumed.progress(), scanner.progress());
        assert_eq!(resumed.cursor(), scanner.cursor());
        assert_eq!(resumed.is_complete(), scanner.is_complete());
    }

    #[test]
    fn hundred_frame_checkpoint_records_only_per_block_spent_undo() {
        let key = [0x42; 32];
        let mut scanner = SproutScanner::new(&[key]);
        let mut first_block = Vec::new();
        for seed in (10..100u8).step_by(3) {
            let recipient = if seed == 10 { key } else { [0x77; 32] };
            first_block.push(joinsplit_paying(&recipient, 100, 0, seed).0);
        }
        scanner.scan_block_at(&first_block, [1; 32], 1).unwrap();
        for height in 2..=100u32 {
            let joinsplits = match height {
                2 | 3 => vec![joinsplit_paying(&key, 100, 0, 100 + 3 * height as u8).0],
                _ => Vec::new(),
            };
            scanner
                .scan_block_at(&joinsplits, [height as u8; 32], height)
                .unwrap();
        }
        assert_eq!(scanner.history.len(), SPROUT_REORG_WINDOW);
        assert_eq!(scanner.pending.len(), 3);
        assert_eq!(scanner.spent.len(), 64);
        assert_eq!(scanner.history[0].spent_before.len(), 60);
        assert_eq!(scanner.history[1].spent_before.len(), 2);
        assert_eq!(scanner.history[2].spent_before.len(), 2);
        assert!(scanner
            .history
            .iter()
            .skip(3)
            .all(|f| f.spent_before.is_empty()));

        let v2_bytes = scanner.encode(2).as_bytes().len();
        let v3 = scanner.checkpoint();
        let v3_bytes = v3.as_bytes().len();
        // A frame contains its own tree/witness snapshots and only the
        // nullifiers changed in that block. Account for every encoded byte:
        // an added copy of the global spent map in any frame fails this.
        let frames_bytes: usize = scanner
            .history
            .iter()
            .map(|frame| {
                40 + 1
                    + usize::from(frame.cursor_before.is_some()) * 40
                    + 8
                    + frame.tree_before.to_bytes().len()
                    + 8
                    + 8
                    + frame
                        .witnesses_before
                        .iter()
                        .map(|w| 8 + w.to_bytes().len())
                        .sum::<usize>()
                    + 8
                    + frame
                        .spent_before
                        .iter()
                        .map(|undo| 33 + usize::from(matches!(undo.previous, Some(Some(_)))) * 32)
                        .sum::<usize>()
                    + 40
            })
            .sum();
        assert_eq!(v3_bytes, v2_bytes + 8 + frames_bytes);
        assert_eq!(SproutScanner::resume(&v3).unwrap().history.len(), 100);
        eprintln!("100-frame checkpoint with three pending notes and 64 spent nullifiers: v2-equivalent={v2_bytes} bytes, v3={v3_bytes} bytes");
    }

    #[test]
    fn v3_rejects_oversized_and_noncontiguous_history() {
        let mut scanner = SproutScanner::new(&[[0x42; 32]]);
        for height in 1..=2u32 {
            scanner
                .scan_block_at(&[], [height as u8; 32], height)
                .unwrap();
        }
        let offset = scanner.encode(2).as_bytes().len();
        let original = scanner.checkpoint().as_bytes().to_vec();

        let mut oversized = original.clone();
        oversized[offset..offset + 8].copy_from_slice(&101u64.to_le_bytes());
        assert!(matches!(
            SproutScanner::resume(&SproutScanCheckpoint::from_bytes(oversized)),
            Err(CheckpointError::Corrupt)
        ));

        // The first applied cursor no longer joins the second frame's prior cursor.
        let mut noncontiguous = original;
        noncontiguous[offset + 8 + 32..offset + 8 + 32 + 8].copy_from_slice(&3u64.to_le_bytes());
        assert!(matches!(
            SproutScanner::resume(&SproutScanCheckpoint::from_bytes(noncontiguous)),
            Err(CheckpointError::Corrupt)
        ));
    }

    #[test]
    fn v1_and_v2_resume_without_claiming_rollback_history() {
        let mut scanner = SproutScanner::new(&[[0x42; 32]]);
        scanner.scan_block_at(&[], [1; 32], 1).unwrap();
        for version in [1, 2] {
            let resumed = SproutScanner::resume(&scanner.encode(version)).unwrap();
            assert_eq!(resumed.checkpoint_version(), version);
            assert!(resumed.history.is_empty());
            assert_eq!(resumed.cursor(), scanner.cursor());
        }
    }

    /// Build a JoinSplit paying `value` to `a_sk` in output `index`, with
    /// the other output a real note to a stranger. Produced through the
    /// encryption path so the scanner faces genuine ciphertexts.
    fn joinsplit_paying(
        a_sk: &[u8; 32],
        value: u64,
        index: usize,
        seed: u8,
    ) -> (SproutJoinSplit, [u8; 32]) {
        let address = SproutPaymentAddress::from_spending_key(a_sk);
        let stranger = SproutPaymentAddress::from_spending_key(&[seed ^ 0xFF; 32]);

        let random_seed = [seed; 32];
        let nullifiers = [[seed.wrapping_add(1); 32], [seed.wrapping_add(2); 32]];
        let joinsplit_pubkey = [seed.wrapping_add(3); 32];
        let esk = [seed.wrapping_add(4); 32];
        let h_sig = sprout::h_sig(&random_seed, &nullifiers, &joinsplit_pubkey);

        let rho = [seed.wrapping_add(5); 32];
        let r = [seed.wrapping_add(6); 32];
        let ours = SproutNotePlaintext {
            value,
            rho,
            r,
            memo: [0u8; 512],
        };
        let theirs = SproutNotePlaintext {
            value: 7,
            rho: [seed.wrapping_add(7); 32],
            r: [seed.wrapping_add(8); 32],
            memo: [0u8; 512],
        };

        let epk = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(esk)).as_bytes();

        let mut ciphertexts = [Vec::new(), Vec::new()];
        let mut commitments = [[0u8; 32], [0u8; 32]];
        for i in 0..2 {
            let (note, addr) = if i == index {
                (&ours, &address)
            } else {
                (&theirs, &stranger)
            };
            ciphertexts[i] =
                sprout::encrypt_note(&esk, addr.pk_enc(), &h_sig, i as u8, &note.to_bytes())
                    .expect("encrypt");
            commitments[i] = sprout::note_commitment(addr.a_pk(), note.value, &note.rho, &note.r);
        }

        let nullifier_of_ours = sprout::prf_nf(a_sk, &rho);

        (
            SproutJoinSplit {
                txid: [seed; 32],
                js_index: 0,
                anchor: [0u8; 32],
                nullifiers,
                commitments,
                ephemeral_key: epk,
                random_seed,
                joinsplit_pubkey,
                ciphertexts,
            },
            nullifier_of_ours,
        )
    }

    #[test]
    fn a_note_paid_to_our_key_is_found() {
        let a_sk = [0x42u8; 32];
        let (js, _) = joinsplit_paying(&a_sk, 500_000, 0, 1);

        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block(&[js]).expect("scan");
        let result = scanner.finish().expect("finish");

        assert_eq!(result.notes.len(), 1);
        assert_eq!(result.notes[0].note.value, 500_000);
        assert_eq!(result.total_value(), 500_000);
        // Both outputs must have been appended, ours and the stranger's.
        assert_eq!(result.progress.commitments_appended, 2);
    }

    /// The note can be in either output slot; a scanner that only checked
    /// index 0 would silently miss half of all notes.
    #[test]
    fn a_note_in_the_second_output_is_found_too() {
        let a_sk = [0x42u8; 32];
        let (js, _) = joinsplit_paying(&a_sk, 900, 1, 2);

        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block(&[js]).expect("scan");
        let result = scanner.finish().expect("finish");

        assert_eq!(result.notes.len(), 1);
        assert_eq!(result.notes[0].outpoint.output_index, 1);
    }

    #[test]
    fn notes_belonging_to_others_are_not_returned() {
        let ours = [0x42u8; 32];
        let theirs = [0x99u8; 32];
        let (js, _) = joinsplit_paying(&theirs, 1_000, 0, 3);

        let mut scanner = SproutScanner::new(&[ours]);
        scanner.scan_block(&[js]).expect("scan");
        let result = scanner.finish().expect("finish");

        assert!(result.notes.is_empty());
        // But their commitments still went into the tree.
        assert_eq!(result.progress.commitments_appended, 2);
    }

    /// The ordering invariant, stated as a test: a scanner that skipped
    /// undecryptable commitments would compute a different anchor, and every
    /// witness derived from it would be wrong.
    #[test]
    fn other_peoples_commitments_still_advance_the_tree() {
        let ours = [0x42u8; 32];
        let theirs = [0x99u8; 32];

        let (strangers, _) = joinsplit_paying(&theirs, 1_000, 0, 4);
        let (mine, _) = joinsplit_paying(&ours, 2_000, 0, 5);

        // Scan with the stranger's JoinSplit first.
        let mut with = SproutScanner::new(&[ours]);
        with.scan_block(&[strangers, mine.clone()]).expect("scan");
        let anchor_with = with.anchor();

        // Scan with only ours, as a scanner that skipped foreign
        // commitments would effectively do.
        let mut without = SproutScanner::new(&[ours]);
        without.scan_block(&[mine]).expect("scan");

        assert_ne!(
            anchor_with,
            without.anchor(),
            "dropping other people's commitments must change the anchor — if it did \
             not, position would not depend on them and the invariant would be vacuous"
        );
    }

    /// A note whose nullifier appears later on the same chain has been
    /// spent, and must not be reported as recoverable balance.
    #[test]
    fn a_note_already_spent_is_not_offered() {
        let a_sk = [0x42u8; 32];
        let (js, nullifier) = joinsplit_paying(&a_sk, 1_234, 0, 6);

        // A later JoinSplit that spends it.
        let (mut spender, _) = joinsplit_paying(&[0x77u8; 32], 10, 0, 7);
        spender.nullifiers[0] = nullifier;

        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block(&[js, spender]).expect("scan");
        let result = scanner.finish().expect("finish");

        assert!(
            result.notes.is_empty(),
            "a spent note must not be reported as spendable"
        );
        assert_eq!(result.spent_notes, 1);
        assert_eq!(result.total_value(), 0);
    }

    /// The witness must be encoded in the 966-byte form the prover parses,
    /// or the note is found and still unspendable.
    #[test]
    fn a_found_note_carries_a_prover_ready_witness() {
        let a_sk = [0x42u8; 32];
        let (js, _) = joinsplit_paying(&a_sk, 42, 0, 8);

        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block(&[js]).expect("scan");
        let result = scanner.finish().expect("finish");

        assert_eq!(
            result.notes[0].witness_path.len(),
            crate::sprout_witness::WITNESS_PATH_SIZE,
            "the witness must be the prover's encoding"
        );
    }

    /// Several keys at once, which is the normal case for a wallet holding
    /// more than one Sprout address.
    #[test]
    fn every_supplied_key_is_scanned_for() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        let (a, _) = joinsplit_paying(&first, 100, 0, 9);
        let (b, _) = joinsplit_paying(&second, 200, 1, 10);

        let mut scanner = SproutScanner::new(&[first, second]);
        scanner.scan_block(&[a, b]).expect("scan");
        let result = scanner.finish().expect("finish");

        assert_eq!(result.notes.len(), 2);
        assert_eq!(result.total_value(), 300);
    }

    /// The property the whole feature rests on: stopping and resuming must
    /// produce exactly what an uninterrupted scan would. Anything less and
    /// the warning's promise that progress is saved is false.
    #[test]
    fn a_resumed_scan_matches_an_uninterrupted_one() {
        let a_sk = [0x42u8; 32];
        let (first, _) = joinsplit_paying(&a_sk, 1_000, 0, 20);
        let (second, _) = joinsplit_paying(&[0x99u8; 32], 500, 1, 21);
        let (third, _) = joinsplit_paying(&a_sk, 2_500, 1, 22);

        // Straight through.
        let mut whole = SproutScanner::new(&[a_sk]);
        whole
            .scan_block(&[first.clone(), second.clone()])
            .expect("scan");
        whole
            .scan_block(std::slice::from_ref(&third))
            .expect("scan");
        let expected_anchor = whole.anchor();
        let expected = whole.finish().expect("finish");

        // Interrupted after the first block, resumed for the second.
        let mut part = SproutScanner::new(&[a_sk]);
        part.scan_block(&[first, second]).expect("scan");
        let checkpoint = part.checkpoint();
        drop(part);

        let mut resumed = SproutScanner::resume(&checkpoint).expect("resume");
        resumed.scan_block(&[third]).expect("scan");
        let resumed_anchor = resumed.anchor();
        let actual = resumed.finish().expect("finish");

        assert_eq!(
            resumed_anchor, expected_anchor,
            "the commitment tree must survive a resume exactly; a different anchor \
             means every witness from here on is worthless"
        );
        assert_eq!(actual.notes.len(), expected.notes.len());
        assert_eq!(actual.total_value(), expected.total_value());
        assert_eq!(actual.total_value(), 3_500);

        // The witnesses must match too, not merely the count: a witness that
        // stopped advancing across the resume still encodes, and fails only
        // at broadcast.
        for (a, b) in actual.notes.iter().zip(expected.notes.iter()) {
            assert_eq!(
                a.witness_path, b.witness_path,
                "witnesses must survive the resume"
            );
            assert_eq!(a.anchor, b.anchor, "anchors must survive the resume");
            assert_eq!(a.commitment, b.commitment);
        }
    }

    /// A note found before the checkpoint, spent after it. The nullifier set
    /// has to cross the resume or the note is reported as spendable.
    #[test]
    fn a_note_spent_after_the_checkpoint_is_still_detected() {
        let a_sk = [0x42u8; 32];
        let (js, nullifier) = joinsplit_paying(&a_sk, 4_000, 0, 23);

        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block(&[js]).expect("scan");
        let checkpoint = scanner.checkpoint();

        let mut resumed = SproutScanner::resume(&checkpoint).expect("resume");
        let (mut spender, _) = joinsplit_paying(&[0x77u8; 32], 10, 0, 24);
        spender.nullifiers[0] = nullifier;
        resumed.scan_block(&[spender]).expect("scan");
        let result = resumed.finish().expect("finish");

        assert!(
            result.notes.is_empty(),
            "the note was spent after the checkpoint and must not be offered"
        );
        assert_eq!(result.spent_notes, 1);
    }

    /// The converse: a nullifier seen *before* the checkpoint must still be
    /// remembered afterwards, or a note found later is wrongly offered.
    #[test]
    fn nullifiers_seen_before_the_checkpoint_survive_it() {
        let a_sk = [0x42u8; 32];
        let (js, nullifier) = joinsplit_paying(&a_sk, 4_000, 0, 25);

        let mut scanner = SproutScanner::new(&[a_sk]);
        let (mut spender, _) = joinsplit_paying(&[0x77u8; 32], 10, 0, 26);
        spender.nullifiers[0] = nullifier;
        // Spend seen first, then the note itself — the checkpoint falls
        // between them.
        scanner.scan_block(&[spender]).expect("scan");
        let checkpoint = scanner.checkpoint();

        let mut resumed = SproutScanner::resume(&checkpoint).expect("resume");
        resumed.scan_block(&[js]).expect("scan");
        let result = resumed.finish().expect("finish");

        assert!(result.notes.is_empty());
        assert_eq!(result.spent_notes, 1);
    }

    #[test]
    fn a_checkpoint_round_trips_with_no_notes_found() {
        let mut scanner = SproutScanner::new(&[[0x42u8; 32]]);
        let (js, _) = joinsplit_paying(&[0x99u8; 32], 1, 0, 27);
        scanner.scan_block(&[js]).expect("scan");
        let anchor = scanner.anchor();

        let resumed =
            SproutScanner::resume(&scanner.checkpoint()).expect("an empty result must resume");
        assert_eq!(resumed.anchor(), anchor);
        assert_eq!(resumed.progress(), scanner.progress());
    }

    /// Checkpointing the same state twice must give identical bytes, or
    /// diagnosing a resume bug by comparing files is impossible. The
    /// nullifier set is a HashSet, whose iteration order is not stable.
    #[test]
    fn checkpoints_are_deterministic() {
        let a_sk = [0x42u8; 32];
        let mut scanner = SproutScanner::new(&[a_sk]);
        for seed in 30..40 {
            let (js, _) = joinsplit_paying(&a_sk, 100, 0, seed);
            scanner.scan_block(&[js]).expect("scan");
        }
        assert_eq!(
            scanner.checkpoint().as_bytes(),
            scanner.checkpoint().as_bytes(),
            "the nullifier set is unordered and must be sorted before writing"
        );
    }

    /// A checkpoint from a future layout must be refused. Misreading one
    /// would yield a wrong tree with no visible error, and worthless
    /// witnesses that only fail at broadcast.
    #[test]
    fn a_checkpoint_from_another_version_is_refused() {
        let scanner = SproutScanner::new(&[[0x42u8; 32]]);
        let mut bytes = scanner.checkpoint().as_bytes().to_vec();
        bytes[0] = CHECKPOINT_VERSION.wrapping_add(1);

        assert!(matches!(
            SproutScanner::resume(&SproutScanCheckpoint::from_bytes(bytes)),
            Err(CheckpointError::WrongVersion)
        ));
    }

    /// Truncation must be caught rather than silently producing a shorter
    /// tree, and so must trailing junk.
    #[test]
    fn a_corrupt_checkpoint_is_refused() {
        let a_sk = [0x42u8; 32];
        let mut scanner = SproutScanner::new(&[a_sk]);
        let (js, _) = joinsplit_paying(&a_sk, 100, 0, 41);
        scanner.scan_block(&[js]).expect("scan");
        let full = scanner.checkpoint().as_bytes().to_vec();

        for cut in [1, full.len() / 2, full.len() - 1] {
            assert!(
                SproutScanner::resume(&SproutScanCheckpoint::from_bytes(full[..cut].to_vec()))
                    .is_err(),
                "a checkpoint truncated to {cut} bytes must be refused"
            );
        }

        let mut extra = full;
        extra.push(0x00);
        assert!(
            matches!(
                SproutScanner::resume(&SproutScanCheckpoint::from_bytes(extra)),
                Err(CheckpointError::Corrupt)
            ),
            "trailing bytes mean the layout is not what we think it is"
        );
    }

    /// The defect this cursor exists to fix: without it a checkpoint
    /// restores a correct tree and has no idea which block comes next, so
    /// resuming would mean rescanning from genesis into a tree that already
    /// contains everything.
    #[test]
    fn the_block_cursor_survives_a_checkpoint() {
        let a_sk = [0x42u8; 32];
        let (js, _) = joinsplit_paying(&a_sk, 1_000, 0, 50);

        let mut scanner = SproutScanner::new(&[a_sk]);
        assert_eq!(scanner.cursor(), None, "no cursor before any block");

        scanner
            .scan_block_at(&[js], [0xAB; 32], 12_345)
            .expect("scan");

        let cursor = scanner.cursor().expect("a scanned block sets the cursor");
        assert_eq!(cursor.last_block_hash, [0xAB; 32]);
        assert_eq!(cursor.last_height, 12_345);

        let resumed = SproutScanner::resume(&scanner.checkpoint()).expect("resume");
        assert_eq!(
            resumed.cursor(),
            Some(cursor),
            "the walk position must survive, or the scan cannot continue"
        );
        assert_eq!(resumed.progress().last_height, 12_345);
    }

    /// Kristi, #240 #10: a chain-proven spend should name a txid the user
    /// can paste into an explorer, and the JoinSplit carries it.
    #[test]
    fn a_spend_seen_on_chain_records_the_transaction_that_revealed_it() {
        let a_sk = [0x42u8; 32];
        let (js, _) = joinsplit_paying(&a_sk, 1_000, 0, 60);
        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block_at(&[js], [0xAB; 32], 7).expect("scan");

        let spent = scanner.spent_nullifiers();
        assert_eq!(spent.get(&[61u8; 32]), Some(&Some([60u8; 32])));

        let resumed = SproutScanner::resume(&scanner.checkpoint()).expect("resume");
        assert_eq!(resumed.spent_nullifiers(), scanner.spent_nullifiers());
    }

    /// A real user has a version-1 checkpoint mid-scan. It must still load
    /// and resume: its nullifiers without txids, and not marked complete.
    #[test]
    fn a_version_1_checkpoint_still_resumes() {
        let a_sk = [0x42u8; 32];
        let (js, _) = joinsplit_paying(&a_sk, 1_000, 0, 70);
        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block_at(&[js], [0xAB; 32], 9).expect("scan");
        scanner.mark_complete();

        let v1 = scanner.encode(1);
        assert_eq!(v1.as_bytes()[0], 1);
        let resumed = SproutScanner::resume(&v1).expect("a v1 checkpoint resumes");
        assert_eq!(resumed.cursor(), scanner.cursor());
        assert_eq!(resumed.progress(), scanner.progress());
        assert!(
            !resumed.is_complete(),
            "v1 recorded no completion, so none is claimed"
        );
        assert_eq!(resumed.spent_nullifiers().get(&[71u8; 32]), Some(&None));
        assert_eq!(resumed.spent_nullifiers().len(), 2);

        let evidence = read_chain_evidence(&v1).expect("v1 reads as evidence");
        assert!(!evidence.complete);
        assert_eq!(evidence.spent.get(&[71u8; 32]), Some(&None));
    }

    /// Kristi, #240 #3: a scan that died early left a valid checkpoint
    /// indistinguishable from a finished one. Completion is recorded, and
    /// any further block clears it, because the tip has moved past it.
    #[test]
    fn completion_is_recorded_and_cleared_by_another_block() {
        let a_sk = [0x42u8; 32];
        let mut scanner = SproutScanner::new(&[a_sk]);
        scanner.scan_block_at(&[], [0xAB; 32], 1).expect("scan");
        assert!(!scanner.is_complete());
        scanner.mark_complete();

        let resumed = SproutScanner::resume(&scanner.checkpoint()).expect("resume");
        assert!(resumed.is_complete());
        assert!(read_chain_evidence(&scanner.checkpoint()).unwrap().complete);

        scanner.scan_block_at(&[], [0xAC; 32], 2).expect("scan");
        assert!(
            !scanner.is_complete(),
            "a later block means the walk is no longer at its end"
        );
    }

    /// Kristi, #240 #9: reading a checkpoint as chain evidence must not
    /// rebuild the tree and every witness, only to throw them away. It must
    /// still see exactly what a full resume sees.
    #[test]
    fn chain_evidence_matches_a_full_resume() {
        let a_sk = [0x42u8; 32];
        let mut scanner = SproutScanner::new(&[a_sk, a_sk]);
        for seed in 80..84 {
            let (js, _) = joinsplit_paying(&a_sk, 1_000, 0, seed);
            scanner
                .scan_block_at(&[js], [seed; 32], u32::from(seed))
                .expect("scan");
        }
        scanner.mark_complete();
        let checkpoint = scanner.checkpoint();

        let evidence = read_chain_evidence(&checkpoint).expect("evidence");
        let resumed = SproutScanner::resume(&checkpoint).expect("resume");
        assert_eq!(evidence.spending_keys, resumed.spending_keys());
        assert_eq!(
            evidence.spending_keys,
            vec![a_sk],
            "duplicate keys are one key"
        );
        assert_eq!(&evidence.spent, resumed.spent_nullifiers());
        assert_eq!(evidence.cursor, resumed.cursor());
        assert!(evidence.complete);

        let mut truncated = checkpoint.as_bytes().to_vec();
        truncated.pop();
        assert!(read_chain_evidence(&SproutScanCheckpoint::from_bytes(truncated)).is_err());
    }

    #[test]
    fn an_empty_scan_yields_the_empty_root() {
        let scanner = SproutScanner::new(&[[0x42u8; 32]]);
        assert_eq!(scanner.anchor(), crate::sprout_witness::empty_tree_root());
    }
}
