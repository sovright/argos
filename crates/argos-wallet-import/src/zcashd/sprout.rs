//! Preservation of Sprout note data and cached witnesses.
//!
//! zcashd caches an incremental witness per Sprout note inside the `tx`
//! records. Sub-spec 3's cost depends on whether those witnesses can be
//! brought forward rather than rebuilding the commitment tree from
//! genesis, so they are preserved verbatim here and left uninterpreted.
//!
//! # Locating approach
//!
//! The task brief's original approach scanned each `tx` record's raw
//! bytes for an ASCII `"sprout"` marker as a shortcut to
//! `mapSproutNoteData`. Checked against the golden `sprout-encrypted.dat`
//! fixture (which has three real `tx` records), that marker never
//! occurs — `mapSproutNoteData` is a CompactSize-prefixed map, like every
//! other wallet.dat structure, with no embedded text. The marker approach
//! would have been silently non-functional on real data, so this module
//! instead walks the serialized `CWalletTx` structurally, per
//! `zcash/zcash` `src/wallet/wallet.h` (`CWalletTx::SerializationOp`,
//! `JSOutPoint`, `SproutNoteData`) and
//! `src/zcash/IncrementalMerkleTree.hpp` (witness framing), stopping the
//! instant `mapSproutNoteData` has been read in full — nothing after it
//! (`vOrderForm`, `nTimeReceived`, `mapSaplingNoteData`, ...) is needed
//! here.
//!
//! The walk only ever measures byte boundaries (CompactSize counts,
//! `Option` discriminant bytes, fixed-width fields). The bytes of each
//! cached witness — the Merkle authentication path itself — are copied
//! verbatim into `SproutNoteData::witness` and never decoded.
//!
//! Only transaction versions 1-4 (pre-NU5/Orchard) are supported. NU5
//! rewrote the transaction encoding (ZIP 225); a `tx` record using it
//! cannot be walked with this structure and is treated as malformed and
//! skipped, per the partial-recovery principle, rather than guessed at.

use crate::{
    keys::{ImportedKeys, SproutNoteData},
    zcashd::records::{compact_size, parse_record_key},
};

/// A Sapling-carrying transaction (`nVersion == 4`) uses Groth16 proofs for
/// its JoinSplits; earlier versions use the older PHGR13 proof. zcashd
/// selects this the same way: `fOverwintered && nVersion >= 4`.
const SAPLING_TX_VERSION: u32 = 4;

/// `SpendDescription`: cv(32) + anchor(32) + nullifier(32) + rk(32) +
/// zkproof (Groth16, 192) + spendAuthSig(64).
const SPEND_DESCRIPTION_LEN: usize = 384;
/// `OutputDescription`: cv(32) + cmu(32) + ephemeralKey(32) +
/// encCiphertext(580) + outCiphertext(80) + zkproof (Groth16, 192).
const OUTPUT_DESCRIPTION_LEN: usize = 948;
/// Groth16 JoinSplit proof: three compressed group elements, 48+96+48.
const GROTH_PROOF_LEN: usize = 192;
/// PHGR13 JoinSplit proof, used by pre-Sapling transaction versions.
const PHGR_PROOF_LEN: usize = 296;
/// `ZC_NOTECIPHERTEXT_SIZE`: NOTEPLAINTEXT_SIZE(585) + AUTH_BYTES(16).
const NOTE_CIPHERTEXT_LEN: usize = 601;
/// Sum of every fixed-size `JSDescription` field except the proof and the
/// two ciphertexts: vpub_old(8) + vpub_new(8) + anchor(32) +
/// nullifiers(2*32) + commitments(2*32) + ephemeralKey(32) +
/// randomSeed(32) + macs(2*32).
const JSDESCRIPTION_BASE_LEN: usize = 304;

fn joinsplit_desc_len(use_groth: bool) -> usize {
    let proof_len = if use_groth {
        GROTH_PROOF_LEN
    } else {
        PHGR_PROOF_LEN
    };
    // 2 ciphertexts per JSDescription (ZC_NUM_JS_OUTPUTS).
    JSDESCRIPTION_BASE_LEN + proof_len + 2 * NOTE_CIPHERTEXT_LEN
}

/// A forward-only cursor over a `tx` record's value bytes. Every read is
/// bounds-checked; running past the end of `bytes` yields `None` rather
/// than panicking, since this walks attacker-controlled data.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn compact_size(&mut self) -> Option<u64> {
        let (value, consumed) = compact_size(self.bytes.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(consumed)?;
        Some(value)
    }
}

fn skip_var_bytes(c: &mut Cursor) -> Option<()> {
    let len = usize::try_from(c.compact_size()?).ok()?;
    c.skip(len)
}

fn skip_tx_in(c: &mut Cursor) -> Option<()> {
    c.skip(32)?; // prevout hash
    c.skip(4)?; // prevout index
    skip_var_bytes(c)?; // scriptSig
    c.skip(4) // sequence
}

fn skip_tx_out(c: &mut Cursor) -> Option<()> {
    c.skip(8)?; // value
    skip_var_bytes(c) // scriptPubKey
}

/// Walk past the serialized `CTransaction` body (`vin`, `vout`,
/// `lock_time`, the Sapling bundle, and `vJoinSplit`), leaving the cursor
/// positioned at the start of the `CMerkleTx` tail (`hashBlock`, ...).
///
/// Only versions 1-4 are understood; anything else (in particular NU5's
/// v5 encoding) returns `None`.
fn skip_transaction_body(c: &mut Cursor) -> Option<()> {
    let header = u32::from_le_bytes(c.take(4)?.try_into().ok()?);
    let overwintered = header & 0x8000_0000 != 0;
    let version = header & 0x7fff_ffff;

    if (!overwintered && version > 2) || (overwintered && !(3..=4).contains(&version)) {
        return None;
    }

    if overwintered {
        c.skip(4)?; // version group id
    }

    let n_vin = c.compact_size()?;
    for _ in 0..n_vin {
        skip_tx_in(c)?;
    }
    let n_vout = c.compact_size()?;
    for _ in 0..n_vout {
        skip_tx_out(c)?;
    }
    c.skip(4)?; // lock_time
    if overwintered {
        c.skip(4)?; // expiry_height
    }

    let mut have_sapling_actions = false;
    if version >= SAPLING_TX_VERSION {
        c.skip(8)?; // valueBalanceSapling
        let n_spend = usize::try_from(c.compact_size()?).ok()?;
        c.skip(n_spend.checked_mul(SPEND_DESCRIPTION_LEN)?)?;
        let n_out = usize::try_from(c.compact_size()?).ok()?;
        c.skip(n_out.checked_mul(OUTPUT_DESCRIPTION_LEN)?)?;
        have_sapling_actions = n_spend > 0 || n_out > 0;
    }

    if version >= 2 {
        let n_js = usize::try_from(c.compact_size()?).ok()?;
        if n_js > 0 {
            let use_groth = overwintered && version >= SAPLING_TX_VERSION;
            let js_len = joinsplit_desc_len(use_groth);
            c.skip(n_js.checked_mul(js_len)?)?;
            c.skip(32)?; // joinSplitPubKey
            c.skip(64)?; // joinSplitSig
        }
    }

    // `CTransaction::SerializationOp` (`zcash/zcash`
    // `src/primitives/transaction.h`): a Sapling-version transaction with
    // at least one Spend or Output description carries a 64-byte
    // `bindingSig` after the JoinSplit section.
    if version >= SAPLING_TX_VERSION && have_sapling_actions {
        c.skip(64)?; // bindingSig
    }
    Some(())
}

/// Walk past `CMerkleTx`'s own fields (`hashBlock`, `vMerkleBranch`,
/// `nIndex`), which follow the `CTransaction` body.
fn skip_merkle_tx_tail(c: &mut Cursor) -> Option<()> {
    c.skip(32)?; // hashBlock
    let n_branch = usize::try_from(c.compact_size()?).ok()?;
    c.skip(n_branch.checked_mul(32)?)?; // vMerkleBranch: Vec<uint256>
    c.skip(4) // nIndex
}

fn read_var_string(c: &mut Cursor) -> Option<()> {
    let len = usize::try_from(c.compact_size()?).ok()?;
    c.skip(len)
}

fn skip_optional_hash(c: &mut Cursor) -> Option<()> {
    let flag = *c.take(1)?.first()?;
    if flag != 0 {
        c.skip(32)?;
    }
    Some(())
}

fn read_optional_hash(c: &mut Cursor) -> Option<Option<[u8; 32]>> {
    let flag = *c.take(1)?.first()?;
    if flag == 0 {
        return Some(None);
    }
    let h: [u8; 32] = c.take(32)?.try_into().ok()?;
    Some(Some(h))
}

/// `IncrementalMerkleTree`: `left`, `right` (each `Option<uint256>`), and
/// `parents` (`Vec<Option<uint256>>`).
fn skip_merkle_tree(c: &mut Cursor) -> Option<()> {
    skip_optional_hash(c)?; // left
    skip_optional_hash(c)?; // right
    let n_parents = usize::try_from(c.compact_size()?).ok()?;
    for _ in 0..n_parents {
        skip_optional_hash(c)?;
    }
    Some(())
}

/// `SproutWitness` (an `IncrementalWitness`): its own `tree`, then
/// `filled` (`Vec<uint256>`, unlike `parents` these are *not* optional),
/// then an optional `cursor` tree.
fn skip_witness(c: &mut Cursor) -> Option<()> {
    skip_merkle_tree(c)?; // tree
    let n_filled = usize::try_from(c.compact_size()?).ok()?;
    c.skip(n_filled.checked_mul(32)?)?; // filled: Vec<uint256>
    let has_cursor = *c.take(1)?.first()?;
    if has_cursor != 0 {
        skip_merkle_tree(c)?; // cursor: Option<IncrementalMerkleTree>
    }
    Some(())
}

/// `std::list<SproutWitness>`, most-recent witness first.
fn skip_witness_list(c: &mut Cursor) -> Option<()> {
    let n = c.compact_size()?;
    for _ in 0..n {
        skip_witness(c)?;
    }
    Some(())
}

/// Parse one `tx` record's value, appending any Sprout notes it holds to
/// `out`. `None` means the record could not be walked structurally
/// (truncated, or an unsupported transaction version) — the caller treats
/// that as "skip this record", never as fatal.
fn extract_sprout_notes(value: &[u8], out: &mut ImportedKeys) -> Option<()> {
    let mut c = Cursor::new(value);
    skip_transaction_body(&mut c)?;
    skip_merkle_tx_tail(&mut c)?;

    // vUnused (formerly vtxPrev): always empty in every wallet this crate
    // has seen. A nonzero count means either an ancient wallet format
    // this module doesn't understand, or a misparse upstream of here —
    // either way, safer to bail than to keep reading at a wrong offset.
    let n_unused = c.compact_size()?;
    if n_unused != 0 {
        return None;
    }

    let n_map = c.compact_size()?; // mapValue: Map<String, String>
    for _ in 0..n_map {
        read_var_string(&mut c)?; // key
        read_var_string(&mut c)?; // value
    }

    let n_notes = c.compact_size()?; // mapSproutNoteData
    for _ in 0..n_notes {
        // JSOutPoint: hash(32) + js: uint64_t(8) + n: uint8_t(1). Not
        // needed to identify the note for preservation purposes; the
        // note's own address is enough.
        c.skip(32)?;
        c.skip(8)?;
        c.skip(1)?;

        let address: [u8; 64] = c.take(64)?.try_into().ok()?;
        let nullifier = read_optional_hash(&mut c)?;

        // The cached witness state: `witnesses` and `witnessHeight`.
        // `SproutNoteData::SerializationOp` in `zcash/zcash`
        // `src/wallet/wallet.h` reads exactly these two fields plus
        // `address`/`nullifier` above — `spentHeight` is declared
        // `(memory only)` immediately above `SerializationOp` and is never
        // part of it, so it is not read here either. Captured as one
        // opaque blob — this module walks just far enough to find its
        // boundaries and never decodes what is inside.
        let witness_start = c.pos;
        skip_witness_list(&mut c)?;
        c.skip(4)?; // witnessHeight: int32
        let witness_end = c.pos;
        let witness = c.bytes.get(witness_start..witness_end)?.to_vec();

        if address != [0u8; 64] {
            out.sprout_notes.push(SproutNoteData {
                address,
                nullifier,
                witness,
            });
        }
    }
    Some(())
}

/// Collect Sprout note data and cached witnesses from `tx` records.
///
/// Uninterpreted by design: sub-spec 1 preserves, sub-spec 3 decides
/// whether the witnesses are usable. A `tx` record that cannot be walked
/// is silently skipped — it must never abort recovery of notes from
/// records that parse cleanly.
pub fn collect_sprout_notes(pairs: &[(Vec<u8>, Vec<u8>)], out: &mut ImportedKeys) {
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };
        if rec.record_type != "tx" {
            continue;
        }
        let _ = extract_sprout_notes(value, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_note_data_from_the_golden_sprout_wallet() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mut out = ImportedKeys::default();
        collect_sprout_notes(&pairs, &mut out);
        // A freshly generated wallet may hold no notes; the contract is
        // that parsing does not fail and does not fabricate entries.
        for n in &out.sprout_notes {
            assert_ne!(n.address, [0u8; 64]);
        }
    }

    /// The encrypted golden wallet's three `tx` records are real,
    /// structurally valid Sapling-version coinbase transactions with no
    /// JoinSplits (verified by inspection: `vJoinSplit` count is 0 in
    /// each). `mapSproutNoteData` on a JoinSplit-free transaction is
    /// necessarily empty, so this fixture legitimately yields zero notes
    /// too — but unlike the plaintext fixture, these `tx` records are
    /// non-trivial (229 bytes of real transaction and wallet-metadata
    /// bytes each), so successfully walking all the way through them
    /// without hitting `None` is a real structural correctness check on
    /// the CTransaction/CMerkleTx/CWalletTx walk, not a vacuous pass.
    #[test]
    fn walks_every_real_tx_record_in_the_encrypted_golden_wallet_without_failing() {
        let bytes = std::fs::read("tests/fixtures/sprout-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mut tx_count = 0;
        let mut out = ImportedKeys::default();
        for (raw_key, value) in &pairs {
            let Some(rec) = parse_record_key(raw_key) else {
                continue;
            };
            if rec.record_type != "tx" {
                continue;
            }
            tx_count += 1;
            assert!(
                extract_sprout_notes(value, &mut out).is_some(),
                "a real tx record failed to parse structurally"
            );
        }
        assert_eq!(tx_count, 3, "expected the documented 3 tx records");
        assert!(
            out.sprout_notes.is_empty(),
            "these coinbase txs have no JoinSplits"
        );
    }

    /// Sub-spec 3 may be able to bring cached witnesses forward instead of
    /// indexing from genesis, so they must survive collection byte-exact.
    /// This builds a minimal but structurally valid `tx` record value —
    /// a version-1 (pre-JoinSplit) transaction with no inputs or outputs,
    /// two Sprout notes in `mapSproutNoteData` — and checks each captured
    /// witness blob against the exact bytes that were written into it.
    ///
    /// `SproutNoteData::SerializationOp` in `zcash/zcash`
    /// `src/wallet/wallet.h` reads exactly four fields — `address`,
    /// `nullifier`, `witnesses`, `witnessHeight` — with no `spentHeight`
    /// on disk (that field is declared `(memory only)` immediately above
    /// `SerializationOp` and is never part of it). A second note is
    /// included so a wrong field boundary on the first note would
    /// misalign the second rather than passing by coincidence.
    #[test]
    fn witness_bytes_survive_collection_unmodified() {
        let mut value = Vec::new();
        value.extend_from_slice(&1u32.to_le_bytes()); // header: version 1, not overwintered
        value.push(0x00); // n_vin = 0
        value.push(0x00); // n_vout = 0
        value.extend_from_slice(&0u32.to_le_bytes()); // lock_time
                                                      // version 1 has no vJoinSplit field at all.

        value.extend_from_slice(&[0xAA; 32]); // hashBlock
        value.push(0x00); // vMerkleBranch count = 0
        value.extend_from_slice(&0i32.to_le_bytes()); // nIndex

        value.push(0x00); // vUnused count = 0
        value.push(0x00); // mapValue count = 0

        value.push(0x02); // mapSproutNoteData count = 2

        // Note 1.
        value.extend_from_slice(&[0xBB; 32]); // JSOutPoint.hash
        value.extend_from_slice(&0u64.to_le_bytes()); // JSOutPoint.js
        value.push(0x00); // JSOutPoint.n
        value.extend_from_slice(&[0x77; 64]); // SproutNoteData.address
        value.push(0x00); // nullifier: None
                          // Cached witness state, captured verbatim as `witness`: an empty
                          // witness list, then witnessHeight. No spentHeight on disk.
        let witness_1: [u8; 5] = [
            0x00, // witnesses count = 0
            0xDE, 0xAD, 0xBE, 0xEF, // witnessHeight (opaque to this test)
        ];
        value.extend_from_slice(&witness_1);

        // Note 2: a single empty witness, and a present nullifier — both
        // exercise the offset differently from note 1 so a wrong boundary
        // on note 1 corrupts note 2 instead of happening to still align.
        value.extend_from_slice(&[0xCC; 32]); // JSOutPoint.hash
        value.extend_from_slice(&1u64.to_le_bytes()); // JSOutPoint.js
        value.push(0x01); // JSOutPoint.n
        value.extend_from_slice(&[0x88; 64]); // SproutNoteData.address
        value.push(0x01); // nullifier: Some
        value.extend_from_slice(&[0x99; 32]); // nullifier bytes
        let witness_2: [u8; 10] = [
            0x01, // witnesses count = 1
            0x00, 0x00, // tree.left = None, tree.right = None
            0x00, // tree.parents count = 0
            0x00, // witness.filled count = 0
            0x00, // witness.cursor = None
            0xFE, 0xED, 0xFA, 0xCE, // witnessHeight (opaque to this test)
        ];
        value.extend_from_slice(&witness_2);

        let mut key = vec![2u8];
        key.extend_from_slice(b"tx");

        let mut out = ImportedKeys::default();
        collect_sprout_notes(&[(key, value)], &mut out);

        assert_eq!(out.sprout_notes.len(), 2);
        assert_eq!(out.sprout_notes[0].address, [0x77; 64]);
        assert_eq!(out.sprout_notes[0].nullifier, None);
        assert_eq!(out.sprout_notes[0].witness, witness_1.to_vec());
        assert_eq!(out.sprout_notes[1].address, [0x88; 64]);
        assert_eq!(out.sprout_notes[1].nullifier, Some([0x99; 32]));
        assert_eq!(out.sprout_notes[1].witness, witness_2.to_vec());
    }

    /// Regression test for the missing Sapling `bindingSig` skip. A
    /// Sapling-version transaction with `n_out > 0` (i.e.
    /// `haveSaplingActions`) carries a 64-byte `bindingSig` after the
    /// JoinSplit section (`zcash/zcash` `src/primitives/transaction.h`,
    /// `CTransaction::SerializationOp`). No real fixture exercises this —
    /// the golden `sprout-encrypted.dat` transactions all have
    /// `n_spend = n_out = 0` — so this builds one with a single, non-empty
    /// `OutputDescription` and confirms the walk still lands on the
    /// correct byte boundaries for `CMerkleTx` and `mapSproutNoteData`
    /// afterward.
    #[test]
    fn skips_the_sapling_binding_sig_when_sapling_actions_are_present() {
        let mut value = Vec::new();
        value.extend_from_slice(&0x8000_0004u32.to_le_bytes()); // header: overwintered, version 4
        value.extend_from_slice(&[0x89, 0xBB, 0x09, 0x00]); // version group id (unchecked)
        value.push(0x00); // n_vin = 0
        value.push(0x00); // n_vout = 0
        value.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        value.extend_from_slice(&0u32.to_le_bytes()); // expiry_height

        value.extend_from_slice(&0i64.to_le_bytes()); // valueBalanceSapling
        value.push(0x00); // n_spend = 0
        value.push(0x01); // n_out = 1
        value.extend_from_slice(&[0xCC; OUTPUT_DESCRIPTION_LEN]); // one OutputDescription

        value.push(0x00); // n_js = 0 (no JoinSplits)

        value.extend_from_slice(&[0xEE; 64]); // bindingSig (present: n_out > 0)

        value.extend_from_slice(&[0xAA; 32]); // hashBlock
        value.push(0x00); // vMerkleBranch count = 0
        value.extend_from_slice(&0i32.to_le_bytes()); // nIndex

        value.push(0x00); // vUnused count = 0
        value.push(0x00); // mapValue count = 0

        value.push(0x01); // mapSproutNoteData count = 1
        value.extend_from_slice(&[0xBB; 32]); // JSOutPoint.hash
        value.extend_from_slice(&0u64.to_le_bytes()); // JSOutPoint.js
        value.push(0x00); // JSOutPoint.n
        value.extend_from_slice(&[0x77; 64]); // SproutNoteData.address
        value.push(0x00); // nullifier: None

        // Cached witness state: an empty witness list, then witnessHeight.
        // `SproutNoteData::SerializationOp` has no `spentHeight` field on
        // disk (that field is memory-only) — see Finding 2.
        let mut witness = vec![0x00u8]; // witnesses (SproutWitness list) count = 0
        witness.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // witnessHeight
        value.extend_from_slice(&witness);

        let mut key = vec![2u8];
        key.extend_from_slice(b"tx");

        let mut out = ImportedKeys::default();
        collect_sprout_notes(&[(key, value)], &mut out);

        assert_eq!(
            out.sprout_notes.len(),
            1,
            "the note after a non-empty Sapling bundle must still be found"
        );
        assert_eq!(out.sprout_notes[0].address, [0x77; 64]);
        assert_eq!(out.sprout_notes[0].witness, witness);
    }

    #[test]
    fn malformed_note_data_does_not_abort_collection() {
        let pairs = vec![(vec![2u8, b't', b'x'], vec![0x00])];
        let mut out = ImportedKeys::default();
        collect_sprout_notes(&pairs, &mut out);
        // No panic, no fatal error. Diagnostics may or may not be added.
        assert!(out.sprout_notes.is_empty());
    }
}
