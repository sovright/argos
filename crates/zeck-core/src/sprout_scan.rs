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

use std::collections::{HashMap, HashSet};

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
}

/// Scans blocks for notes belonging to a set of Sprout spending keys.
pub struct SproutScanner {
    keys: Vec<ScanKey>,
    tree: IncrementalMerkleTree,
    pending: Vec<PendingNote>,
    /// Every nullifier seen, to tell a live note from a spent one.
    spent: HashSet<[u8; 32]>,
    progress: SproutScanProgress,
}

impl SproutScanner {
    pub fn new(spending_keys: &[[u8; 32]]) -> Self {
        Self {
            keys: spending_keys
                .iter()
                .map(|a_sk| ScanKey {
                    a_sk: *a_sk,
                    address: SproutPaymentAddress::from_spending_key(a_sk),
                })
                .collect(),
            tree: IncrementalMerkleTree::default(),
            pending: Vec::new(),
            spent: HashSet::new(),
            progress: SproutScanProgress::default(),
        }
    }

    pub fn progress(&self) -> SproutScanProgress {
        self.progress
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
        for js in joinsplits {
            self.scan_joinsplit(js)?;
        }
        self.progress.blocks_scanned += 1;
        Ok(())
    }

    fn scan_joinsplit(&mut self, js: &SproutJoinSplit) -> Result<(), WitnessError> {
        self.progress.joinsplits_seen += 1;

        // A JoinSplit's nullifiers spend earlier notes. Recorded before the
        // outputs, though order does not matter here, because the match
        // happens at the end.
        for nf in &js.nullifiers {
            self.spent.insert(*nf);
        }

        let h_sig = sprout::h_sig(&js.random_seed, &js.nullifiers, &js.joinsplit_pubkey);

        for (index, commitment) in js.commitments.iter().enumerate() {
            let found = self.try_decrypt(js, index, &h_sig, commitment);

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
    ) -> Option<DecryptedNote> {
        let ciphertext = js.ciphertexts.get(index)?;

        for key in &self.keys {
            let Ok(note) =
                sprout::decrypt_note(&key.a_sk, &js.ephemeral_key, ciphertext, h_sig, index as u8)
            else {
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
            if self.spent.contains(&pending.nullifier) {
                spent_notes += 1;
                continue;
            }
            notes.push(SpendableSproutNote {
                note: pending.note,
                a_sk: pending.a_sk,
                address: pending.address,
                commitment: pending.commitment,
                witness: pending.witness.encode_for_prover()?.to_vec(),
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
            result.notes[0].witness.len(),
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

    #[test]
    fn an_empty_scan_yields_the_empty_root() {
        let scanner = SproutScanner::new(&[[0x42u8; 32]]);
        assert_eq!(scanner.anchor(), crate::sprout_witness::empty_tree_root());
    }
}
