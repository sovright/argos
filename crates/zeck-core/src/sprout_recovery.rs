//! Recover spendable Sprout notes from an imported zcashd wallet.
//!
//! # Why this step exists
//!
//! A Sprout note is spendable only if its `value`, `rho` and `r` are known,
//! and zcashd's wallet stores none of them. `CSproutNoteData` — the record
//! this crate's importer preserves as [`SproutNoteData`] — holds an address,
//! an optional nullifier, and a cached witness. Nothing more.
//!
//! Those three values live in the JoinSplit's note ciphertext, on-chain and
//! in the clear as far as the wallet file is concerned, readable only with
//! the Sprout spending key. So recovery is a join across three things the
//! importer produces separately:
//!
//!   1. [`SproutNoteData::outpoint`] says which JoinSplit output the note is,
//!   2. [`SproutJoinSplit`] carries that output's ciphertext and the public
//!      material `hSig` is computed from,
//!   3. [`SproutKey`] supplies the `a_sk` that decrypts it.
//!
//! # Trust posture
//!
//! Every input here came out of an attacker-supplied binary file, so no
//! single note's failure may abort the others: a note that will not decrypt,
//! or decrypts to something inconsistent, is reported and skipped. That is
//! the same partial-recovery principle the importer follows.
//!
//! # What the commitment check does and does not prove
//!
//! It proves the recovered plaintext is the note *this JoinSplit record
//! committed to*. It does **not** prove the JoinSplit is on-chain. Every
//! field used — the txid, the commitments, the ciphertext, the cached
//! witness — comes from the wallet file, and nothing here recomputes a
//! transaction id or consults an authenticated view of the chain.
//!
//! So a crafted `wallet.dat` can carry a fabricated note, a matching
//! fabricated JoinSplit under the outpoint it names, and a witness built
//! over that commitment, and this function will report it as spendable with
//! an attacker-chosen value. Consensus catches it — the anchor is not a root
//! any node recognises, so the sweep is rejected and no funds move — but the
//! user is shown a balance that does not exist until they try to spend it.
//!
//! Closing this needs chain provenance: the note's anchor checked against a
//! real Sprout root, which requires a node, or the full-block scan, which
//! derives everything from the chain and is immune to it. Treat a balance
//! reported from a wallet file alone as the file's claim, not a fact.
//!
//! The consistency check is not optional. `decrypt_note` authenticates the
//! ciphertext, but authentication alone does not establish that the
//! recovered plaintext is the note the commitment tree actually committed
//! to. Re-deriving the commitment from `(a_pk, value, rho, r)` and comparing
//! it against the JoinSplit's own `commitments[n]` is what makes a note
//! genuinely spendable rather than merely well-formed — a note that fails it
//! would produce a proof the network rejects, and the failure would surface
//! at broadcast with the fee already spent.

use std::collections::{HashMap, HashSet};

use argos_wallet_import::keys::{ImportedKeys, JsOutPoint, SproutJoinSplit, SproutNoteData};
use secrecy::ExposeSecret;

use crate::sprout::{self, SproutNotePlaintext, SproutPaymentAddress};

/// Hex for diagnostics. Inline rather than a dependency: this is the only
/// place in the crate that needs it, and it is four lines.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A Sprout note with everything needed to spend it.
pub struct SpendableSproutNote {
    pub note: SproutNotePlaintext,
    /// The spending key that unlocks it.
    pub a_sk: [u8; 32],
    pub address: SproutPaymentAddress,
    /// The note commitment, re-derived and checked against the JoinSplit's.
    pub commitment: [u8; 32],
    /// The commitment tree root this note's witness authenticates against.
    ///
    /// Resolved here rather than carried as a raw blob. A wallet supplies a
    /// cached zcashd witness and a scan builds one from the chain; those are
    /// different encodings, and a single `witness: Vec<u8>` field meant the
    /// sweeper had to guess which it held — it guessed "wallet", so scanned
    /// notes could be found and never spent.
    pub anchor: [u8; 32],
    /// The 966-byte authentication path the JoinSplit prover parses.
    pub witness_path: Vec<u8>,
    pub outpoint: JsOutPoint,
}

impl core::fmt::Debug for SpendableSproutNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `a_sk` and the note's `r`/`rho` are spending material.
        f.debug_struct("SpendableSproutNote")
            .field("outpoint", &self.outpoint)
            .field("value", &self.note.value)
            .field("commitment", &hex(&self.commitment))
            .field("anchor", &hex(&self.anchor))
            .finish_non_exhaustive()
    }
}

/// Why one note could not be recovered. Reported rather than returned as an
/// error, so one bad note never hides the good ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SproutRecoveryIssue {
    /// The note's outpoint names a JoinSplit that is not in the wallet.
    /// Normal for a wallet holding note metadata whose transaction was
    /// pruned, and fatal only for that note.
    MissingJoinSplit { outpoint: JsOutPoint },
    /// No spending key in the wallet matches the note's address. Expected
    /// for watch-only entries.
    NoSpendingKey { outpoint: JsOutPoint },
    /// `output_index` was not 0 or 1. A JoinSplit has exactly two outputs.
    OutputIndexOutOfRange { outpoint: JsOutPoint, index: u8 },
    /// The note decrypted, but its cached witness could not be read, so its
    /// position in the commitment tree is unknown and it cannot be spent
    /// without a rescan.
    UnreadableWitness {
        outpoint: JsOutPoint,
        reason: String,
    },
    /// The ciphertext did not authenticate under this key.
    Undecryptable {
        outpoint: JsOutPoint,
        reason: String,
    },
    /// It decrypted, but the recovered note does not reproduce the
    /// commitment the JoinSplit published. Proving from it would produce a
    /// transaction the network rejects.
    CommitmentMismatch {
        outpoint: JsOutPoint,
        expected: [u8; 32],
        derived: [u8; 32],
    },
}

impl std::fmt::Display for SproutRecoveryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = |o: &JsOutPoint| format!("{}:{}:{}", hex(&o.txid), o.js_index, o.output_index);
        match self {
            Self::MissingJoinSplit { outpoint } => write!(
                f,
                "note {}: the wallet has no JoinSplit for this outpoint",
                op(outpoint)
            ),
            Self::NoSpendingKey { outpoint } => write!(
                f,
                "note {}: no Sprout spending key in this wallet matches its address",
                op(outpoint)
            ),
            Self::OutputIndexOutOfRange { outpoint, index } => write!(
                f,
                "note {}: output index {index} is out of range (a JoinSplit has 2 outputs)",
                op(outpoint)
            ),
            Self::UnreadableWitness { outpoint, reason } => write!(
                f,
                "note {}: decrypted, but its cached witness could not be read ({reason}); \
                 it cannot be spent without a full-block rescan",
                op(outpoint)
            ),
            Self::Undecryptable { outpoint, reason } => {
                write!(f, "note {}: could not decrypt ({reason})", op(outpoint))
            }
            Self::CommitmentMismatch {
                outpoint,
                expected,
                derived,
            } => write!(
                f,
                "note {}: decrypted, but its commitment does not match the chain \
                 (expected {}, derived {}) — it is not spendable",
                op(outpoint),
                hex(expected),
                hex(derived)
            ),
        }
    }
}

/// A note this wallet received and later spent itself.
///
/// Kept apart from `issues`: nothing is wrong with it, and a long-lived
/// wallet has hundreds of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentSproutNote {
    pub outpoint: JsOutPoint,
    pub value: u64,
    /// The transaction, recorded as mined, whose JoinSplit spent it.
    pub spent_in: [u8; 32],
}

/// The outcome of scanning a wallet for spendable Sprout notes.
#[derive(Debug, Default)]
pub struct SproutRecovery {
    pub notes: Vec<SpendableSproutNote>,
    /// Notes spent by a transaction this same wallet recorded as mined.
    pub spent: Vec<SpentSproutNote>,
    /// Offered in `notes`, though a transaction the wallet never saw mined
    /// would spend them. If it was mined after all, the sweep is rejected.
    pub unconfirmed_spends: Vec<JsOutPoint>,
    /// Unspent notes worth no more than the fee to move one — mostly
    /// zcashd's zero-value change. Left out of `notes`, because the sweep
    /// skips them: each would cost a JoinSplit and move nothing.
    pub dust: Vec<JsOutPoint>,
    /// Transaction records the wallet file holds but Argos could not read.
    /// Notes they received are missing, and spends they made are unseen.
    pub unreadable_transactions: usize,
    pub issues: Vec<SproutRecoveryIssue>,
}

impl SproutRecovery {
    /// Saturating: every value here came from the wallet file, checked only
    /// against commitments from the same file, so a crafted one can sum past
    /// `u64::MAX`.
    pub fn total_value(&self) -> u64 {
        self.notes
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(n.note.value))
    }

    pub fn spent_value(&self) -> u64 {
        self.spent
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(n.value))
    }
}

/// The limit of reading spends from a wallet file, said where a user decides
/// whether to sweep. One copy, rendered by both surfaces.
pub const SPENT_STATUS_IS_THE_FILES: &str = "Spent status comes from this wallet file's own \
     history. A note spent from another copy of this wallet still appears here; the network \
     refuses it at sweep, and Argos skips it and carries on. The full-block scan \
     (`argos scan-sprout`, or Scan for Sprout notes in the app) reads spends from the chain \
     instead.";

impl SproutRecovery {
    /// Nothing to move, and nothing wrong: every note was spent by the
    /// wallet itself or is dust. Such a wallet must hear that, not the
    /// multi-day scan quote meant for keys without note data.
    pub fn nothing_left_to_sweep(&self) -> bool {
        self.notes.is_empty()
            && self.issues.is_empty()
            && self.unreadable_transactions == 0
            && !(self.spent.is_empty() && self.dust.is_empty())
    }

    /// Why the Sprout total is what it is, one sentence per line. Shared so
    /// the CLI and the GUI cannot describe one file differently.
    pub fn accounting_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.spent.is_empty() {
            lines.push(format!(
                "{} note(s), {} in all, were spent by transactions this wallet file records \
                 as mined. They are the wallet's history, not a balance, and are left out. \
                 (Argos 1.4.0 and earlier counted them as spendable; that total was wrong.)",
                self.spent.len(),
                zec(self.spent_value())
            ));
        }
        if !self.dust.is_empty() {
            lines.push(format!(
                "{} note(s) worth no more than the {} fee to move one are left out.",
                self.dust.len(),
                zec(crate::sprout_sweep::SPROUT_SWEEP_FEE)
            ));
        }
        if !self.unconfirmed_spends.is_empty() {
            lines.push(format!(
                "{} note(s) have a spend in this file that was never recorded as mined — it \
                 may have expired. They are offered; if a spend did land, the sweep skips it.",
                self.unconfirmed_spends.len()
            ));
        }
        lines
    }
}

/// Spent status comes from the nullifiers of the wallet's own transactions,
/// so a transaction record that could not be read hides the spends it holds.
/// Said beside the Sprout total, where it changes what the number means.
pub fn unreadable_transactions_warning(keys: &ImportedKeys) -> Option<String> {
    let unread = count_unreadable_transactions(keys);
    (unread > 0).then(|| {
        format!(
            "Warning: {unread} transaction record(s) in this file could not be read. Sprout \
             notes they received are not counted here, and a note one of them spent would \
             be counted as unspent — so this total can be wrong in either direction. The \
             full-block scan reads both from the chain. The sweep skips any note the network \
             says is already spent."
        )
    })
}

/// Zatoshis as ZEC, matching the CLI's `format_zec`.
fn zec(zatoshis: u64) -> String {
    let (whole, frac) = (zatoshis / 100_000_000, zatoshis % 100_000_000);
    if frac == 0 {
        format!("{whole} ZEC")
    } else {
        format!("{whole}.{frac:08} ZEC")
    }
}

/// A key that does not control the address it was filed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgedSproutKey {
    /// The address the wallet record was keyed by.
    pub stored_address: [u8; 64],
    /// The address the secret actually controls.
    pub derived_address: [u8; 64],
}

impl std::fmt::Display for ForgedSproutKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a Sprout key in this file does not control the address it is stored under              (stored {}, derived {}). It was skipped: spending with it would build a              transaction for someone else's note.",
            hex(&self.stored_address),
            hex(&self.derived_address)
        )
    }
}

/// Drop any Sprout key that does not control its own stored address.
///
/// zcashd files each Sprout key under the payment address it unlocks, and
/// `a_pk` is derived from `a_sk`, so re-deriving closes the loop. Until now
/// that check lived only in `argos-wallet-import`'s fixture tests — the
/// property was asserted against eight known-good files and enforced
/// nowhere, so a real wallet shaped slightly differently could import a
/// wrong key and report success. Raised in review of #189.
///
/// It lives here rather than at the point of parse because deriving `a_pk`
/// needs the Sprout PRF, and `argos-wallet-import` deliberately depends on
/// nothing — putting it there would mean duplicating crypto or inverting the
/// dependency.
///
/// Mismatches are skipped and reported rather than fatal, the same as every
/// other defect in a file the user was handed.
pub fn reject_forged_sprout_keys(keys: &mut ImportedKeys) -> Vec<ForgedSproutKey> {
    use secrecy::ExposeSecret;

    let mut rejected = Vec::new();
    keys.sprout.retain(|key| {
        let derived = SproutPaymentAddress::from_spending_key(key.a_sk.expose_secret()).to_bytes();
        if derived == key.address {
            true
        } else {
            rejected.push(ForgedSproutKey {
                stored_address: key.address,
                derived_address: derived,
            });
            false
        }
    });
    rejected
}

/// Decrypt every Sprout note the wallet holds a spending key for, and keep
/// the ones it has not spent.
///
/// zcashd keeps a `CSproutNoteData` for every note it ever received, spent
/// or not — `spentHeight` is memory-only and never written. Spent status is
/// therefore recomputed the way zcashd itself does it: a note is spent when
/// its nullifier, `PRF^nf(a_sk, rho)`, appears in a JoinSplit of a
/// transaction the wallet recorded as mined. Derived from the decrypted
/// `rho` rather than read from the record's cached nullifier, which may be
/// absent and, in a crafted file, could be anything.
///
/// A spend the wallet never saw mined — an expired `z_sendmany`, one never
/// relayed — does not count: treating it as spent would hide a live note
/// with no way back. The note is offered and listed in
/// `unconfirmed_spends`; if that spend did land, the network rejects the
/// sweep of it and the sweep moves on.
///
/// This only sees spends the wallet recorded. A note spent from another
/// copy of the wallet still reads as unspent here, with the same outcome at
/// sweep; only the full-block scan knows every nullifier on chain.
///
/// Never fails as a whole: notes that cannot be recovered are reported in
/// `issues`.
pub fn recover_spendable_sprout_notes(keys: &ImportedKeys) -> SproutRecovery {
    let ctx = RecoveryContext::new(keys);
    let mut out = SproutRecovery {
        unreadable_transactions: count_unreadable_transactions(keys),
        ..Default::default()
    };

    // One note per outpoint, judged by its best record. A file can carry the
    // same outpoint twice — `bdb::walk` re-emits a record reachable from two
    // roots — and the first copy may be the damaged one. Taking whichever
    // came first let a copy with a truncated witness or a foreign address
    // hide a good copy of a spendable note. Of two good copies, the one whose
    // witness zcashd updated later wins: both commit to the same note (the
    // commitment check binds value, rho and r), so only the witness can
    // differ, and the fresher one is the likelier to prove. With no good
    // copy, every distinct problem is kept — different causes, different
    // remedies.
    let mut order = Vec::new();
    let mut best: HashMap<OutpointKey, Judgement> = HashMap::new();
    for note_data in &keys.sprout_notes {
        let o = note_data.outpoint;
        let key = (o.txid, o.js_index, o.output_index);
        let height = cached_witness_height(&note_data.witness);
        let result = ctx.recover_one(note_data);
        match (best.get_mut(&key), result) {
            (None, result) => {
                order.push(key);
                best.insert(key, result.map(|r| (r, height)).map_err(|i| vec![i]));
            }
            (Some(slot @ Err(_)), Ok(r)) => *slot = Ok((r, height)),
            (Some(Err(issues)), Err(issue)) => {
                if !issues.contains(&issue) {
                    issues.push(issue);
                }
            }
            (
                Some(Ok((Recovered::Spendable { .. }, kept))),
                Ok(r @ Recovered::Spendable { .. }),
            ) if height > *kept => {
                best.insert(key, Ok((r, height)));
            }
            (Some(Ok(_)), _) => {}
        }
    }

    for key in order {
        match best.remove(&key) {
            Some(Ok((
                Recovered::Spendable {
                    note,
                    unconfirmed_spend,
                },
                _,
            ))) => {
                if unconfirmed_spend {
                    out.unconfirmed_spends.push(note.outpoint);
                }
                out.notes.push(*note);
            }
            Some(Ok((Recovered::Spent(spent), _))) => out.spent.push(spent),
            Some(Ok((Recovered::Dust(outpoint), _))) => out.dust.push(outpoint),
            Some(Err(issues)) => out.issues.extend(issues),
            None => {}
        }
    }
    out
}

/// A note's outpoint, as notes are deduplicated by it.
type OutpointKey = ([u8; 32], u64, u8);

/// The best a note's records have produced so far: a recovery and the
/// cached witness height it came with, or every distinct problem.
type Judgement = Result<(Recovered, i32), Vec<SproutRecoveryIssue>>;

/// zcashd's `witnessHeight`: the last four bytes of a cached witness blob,
/// the height the witness was last brought up to. `i32::MIN` when absent,
/// so a blob without one never outranks one with it.
fn cached_witness_height(blob: &[u8]) -> i32 {
    match blob.len().checked_sub(4).and_then(|at| blob.get(at..)) {
        Some(&[a, b, c, d]) => i32::from_le_bytes([a, b, c, d]),
        _ => i32::MIN,
    }
}

fn count_unreadable_transactions(keys: &ImportedKeys) -> usize {
    use argos_wallet_import::ImportDiagnostic;
    keys.diagnostics
        .iter()
        .filter(|d| {
            matches!(d, ImportDiagnostic::UnparseableRecord { record_type, .. } if record_type == "tx")
        })
        .count()
}

/// What one note record resolved to.
enum Recovered {
    Spendable {
        note: Box<SpendableSproutNote>,
        /// A JoinSplit the wallet never saw mined would spend it.
        unconfirmed_spend: bool,
    },
    Spent(SpentSproutNote),
    Dust(JsOutPoint),
}

/// Everything about the wallet one note's recovery consults.
struct RecoveryContext<'a> {
    by_outpoint: HashMap<([u8; 32], u64), &'a SproutJoinSplit>,
    keys_by_address: HashMap<[u8; 64], &'a [u8; 32]>,
    /// Nullifiers revealed by transactions the wallet recorded as mined,
    /// with the transaction that revealed each.
    spent_by: HashMap<[u8; 32], [u8; 32]>,
    /// Nullifiers revealed only by transactions it never saw mined.
    unconfirmed: HashSet<[u8; 32]>,
}

impl<'a> RecoveryContext<'a> {
    fn new(keys: &'a ImportedKeys) -> Self {
        let unmined: HashSet<[u8; 32]> = keys.sprout_unconfirmed_txids.iter().copied().collect();
        let mut spent_by = HashMap::new();
        let mut unconfirmed = HashSet::new();
        for js in &keys.sprout_joinsplits {
            for nf in js.nullifiers {
                if unmined.contains(&js.txid) {
                    unconfirmed.insert(nf);
                } else {
                    spent_by.entry(nf).or_insert(js.txid);
                }
            }
        }
        Self {
            by_outpoint: keys
                .sprout_joinsplits
                .iter()
                .map(|js| ((js.txid, js.js_index), js))
                .collect(),
            // Keyed by the full 64-byte address, never by `a_pk` alone: a_pk
            // and pk_enc must come from the same key, and matching on half of
            // the address would let a wallet holding two keys pair the wrong
            // halves.
            keys_by_address: keys
                .sprout
                .iter()
                .map(|k| (k.address, k.a_sk.expose_secret()))
                .collect(),
            spent_by,
            unconfirmed,
        }
    }

    fn recover_one(&self, note_data: &SproutNoteData) -> Result<Recovered, SproutRecoveryIssue> {
        let outpoint = note_data.outpoint;

        let js = self
            .by_outpoint
            .get(&(outpoint.txid, outpoint.js_index))
            .ok_or(SproutRecoveryIssue::MissingJoinSplit { outpoint })?;

        let index = outpoint.output_index;
        let ciphertext = js
            .ciphertexts
            .get(index as usize)
            .ok_or(SproutRecoveryIssue::OutputIndexOutOfRange { outpoint, index })?;

        let a_sk = self
            .keys_by_address
            .get(&note_data.address)
            .ok_or(SproutRecoveryIssue::NoSpendingKey { outpoint })?;

        let h_sig = sprout::h_sig(&js.random_seed, &js.nullifiers, &js.joinsplit_pubkey);
        let note = sprout::decrypt_note(a_sk, &js.ephemeral_key, ciphertext, &h_sig, index)
            .map_err(|err| SproutRecoveryIssue::Undecryptable {
                outpoint,
                reason: err.to_string(),
            })?;

        // Derive the address from the key rather than trusting the 64 bytes
        // stored beside the note: the commitment check below is only
        // meaningful if `a_pk` provably belongs to the key we are about to
        // spend with.
        let address = SproutPaymentAddress::from_spending_key(a_sk);
        let derived = sprout::note_commitment(address.a_pk(), note.value, &note.rho, &note.r);
        let expected = js.commitments[index as usize];
        if derived != expected {
            return Err(SproutRecoveryIssue::CommitmentMismatch {
                outpoint,
                expected,
                derived,
            });
        }

        // After the commitment check, so `rho` is bound to the commitment
        // before the nullifier derived from it decides anything.
        let nullifier = sprout::prf_nf(a_sk, &note.rho);
        if let Some(spent_in) = self.spent_by.get(&nullifier) {
            return Ok(Recovered::Spent(SpentSproutNote {
                outpoint,
                value: note.value,
                spent_in: *spent_in,
            }));
        }
        // Worth no more than the fee to move it: the sweep would skip it
        // anyway, so it is not counted as spendable.
        if note.value <= crate::sprout_sweep::SPROUT_SWEEP_FEE {
            return Ok(Recovered::Dust(outpoint));
        }

        // Resolved now, not at sweep time: a witness that cannot be read
        // makes the note unspendable, and saying so during recovery is far
        // better than after a 725 MB proving run.
        let unreadable =
            |err: crate::sprout_witness::WitnessError| SproutRecoveryIssue::UnreadableWitness {
                outpoint,
                reason: err.to_string(),
            };
        let witness = crate::sprout_witness::IncrementalWitness::parse_cached(&note_data.witness)
            .map_err(unreadable)?;
        let witness_path = witness.encode_for_prover().map_err(unreadable)?.to_vec();

        Ok(Recovered::Spendable {
            note: Box::new(SpendableSproutNote {
                note,
                a_sk: **a_sk,
                address,
                commitment: derived,
                anchor: witness.root(),
                witness_path,
                outpoint,
            }),
            unconfirmed_spend: self.unconfirmed.contains(&nullifier),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_wallet_import::keys::{Provenance, SproutKey, SproutNoteData};
    use secrecy::Secret;

    /// Build a wallet holding one real, self-consistent Sprout note: the
    /// ciphertext is produced by the encryption path, so decryption here is
    /// checked against a genuine encryption rather than a canned blob.
    fn wallet_with_one_note(value: u64) -> (ImportedKeys, [u8; 32]) {
        let a_sk = [0x42u8; 32];
        let address = SproutPaymentAddress::from_spending_key(&a_sk);
        let rho = [0x11u8; 32];
        let r = [0x22u8; 32];
        let random_seed = [0x33u8; 32];
        let nullifiers = [[0x44u8; 32], [0x55u8; 32]];
        let joinsplit_pubkey = [0x66u8; 32];
        let esk = [0x77u8; 32];

        let h_sig = sprout::h_sig(&random_seed, &nullifiers, &joinsplit_pubkey);
        let note = SproutNotePlaintext {
            value,
            rho,
            r,
            memo: [0u8; 512],
        };
        let ciphertext = sprout::encrypt_note(&esk, address.pk_enc(), &h_sig, 0, &note.to_bytes())
            .expect("encryption must succeed");
        // `epk` is the public half of `esk`, exactly as the encryption path
        // derives it; the JoinSplit publishes it so the recipient can
        // reconstruct the shared secret.
        let epk = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(esk)).as_bytes();

        let commitment = sprout::note_commitment(address.a_pk(), value, &rho, &r);

        let txid = [0x99u8; 32];
        let outpoint = JsOutPoint {
            txid,
            js_index: 0,
            output_index: 0,
        };

        let mut keys = ImportedKeys::default();
        keys.sprout.push(SproutKey {
            a_sk: Secret::new(a_sk),
            address: address.to_bytes(),
            provenance: Provenance::Standalone,
        });
        keys.sprout_joinsplits.push(SproutJoinSplit {
            txid,
            js_index: 0,
            anchor: [0u8; 32],
            nullifiers,
            commitments: [commitment, [0u8; 32]],
            ephemeral_key: epk,
            random_seed,
            joinsplit_pubkey,
            ciphertexts: [ciphertext, vec![0u8; 601]],
        });
        // A real cached witness blob, in zcashd's shape: a
        // `std::list<SproutWitness>` followed by `witnessHeight`. Recovery
        // parses this now rather than passing it along, so a placeholder
        // would no longer exercise the path.
        let mut tree = crate::sprout_witness::IncrementalMerkleTree::default();
        tree.append(commitment).expect("append the note");
        let witness = crate::sprout_witness::IncrementalWitness::from_tree(tree);
        let mut blob = vec![0x01u8]; // one witness in the list
        blob.extend_from_slice(&witness.to_bytes());
        blob.extend_from_slice(&0i32.to_le_bytes()); // witnessHeight

        keys.sprout_notes.push(SproutNoteData {
            address: address.to_bytes(),
            nullifier: None,
            witness: blob,
            outpoint,
        });

        (keys, a_sk)
    }

    /// A key filed under an address it does not control must be dropped,
    /// not used. Spending with it builds a transaction for someone else's
    /// note, which is why this is enforced rather than only asserted
    /// against fixtures.
    #[test]
    fn a_key_that_does_not_control_its_address_is_rejected() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        assert_eq!(keys.sprout.len(), 1);

        // A genuine key, refiled under a different address — exactly what a
        // corrupt or hostile wallet file looks like.
        let someone_else = SproutPaymentAddress::from_spending_key(&[0x99u8; 32]).to_bytes();
        keys.sprout[0].address = someone_else;

        let rejected = reject_forged_sprout_keys(&mut keys);

        assert_eq!(rejected.len(), 1, "the mismatch must be reported");
        assert_eq!(rejected[0].stored_address, someone_else);
        assert!(
            keys.sprout.is_empty(),
            "a key that does not control its address must not remain usable"
        );
        assert!(
            rejected[0].to_string().contains("someone else's note"),
            "the message must say what spending with it would do"
        );
    }

    #[test]
    fn genuine_keys_survive_the_check() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        assert!(reject_forged_sprout_keys(&mut keys).is_empty());
        assert_eq!(keys.sprout.len(), 1, "a genuine key must not be dropped");
    }

    #[test]
    fn recovers_a_notes_value_rho_and_r_from_its_ciphertext() {
        let (keys, a_sk) = wallet_with_one_note(123_456_789);
        let recovered = recover_spendable_sprout_notes(&keys);

        assert!(
            recovered.issues.is_empty(),
            "unexpected issues: {:?}",
            recovered.issues
        );
        assert_eq!(recovered.notes.len(), 1);

        let note = &recovered.notes[0];
        assert_eq!(note.note.value, 123_456_789);
        assert_eq!(note.note.rho, [0x11u8; 32]);
        assert_eq!(note.note.r, [0x22u8; 32]);
        assert_eq!(note.a_sk, a_sk);
        assert_eq!(
            note.witness_path.len(),
            crate::sprout_witness::WITNESS_PATH_SIZE
        );
        assert_eq!(recovered.total_value(), 123_456_789);
    }

    /// A JoinSplit elsewhere in the wallet that reveals `a_sk`'s nullifier
    /// for this note: the wallet's own record that the note was spent.
    fn spend_of(keys: &ImportedKeys, a_sk: &[u8; 32]) -> SproutJoinSplit {
        let mut spend = keys.sprout_joinsplits[0].clone();
        spend.txid = [0xAB; 32];
        spend.nullifiers = [[0x01; 32], sprout::prf_nf(a_sk, &[0x11u8; 32])];
        spend
    }

    /// The reported failure: a wallet with a long Sprout history showed
    /// 796,540 ZEC "spendable" — more than the Sprout pool holds — because
    /// every note it had ever received was offered, spent or not.
    #[test]
    fn a_note_the_wallet_spent_is_not_offered_as_spendable() {
        let (mut keys, a_sk) = wallet_with_one_note(1_000_000);
        let spend = spend_of(&keys, &a_sk);
        keys.sprout_joinsplits.push(spend);

        let recovered = recover_spendable_sprout_notes(&keys);

        assert!(
            recovered.notes.is_empty(),
            "a spent note must not be offered"
        );
        assert_eq!(recovered.total_value(), 0);
        assert_eq!(recovered.spent.len(), 1, "it must be counted as spent");
        assert_eq!(recovered.spent[0].value, 1_000_000);
        assert!(recovered.issues.is_empty(), "{:?}", recovered.issues);
    }

    /// The nullifier is derived from the key and the decrypted `rho`, never
    /// taken from the file's cached copy, which zcashd may leave unset and a
    /// crafted file could set to anything.
    #[test]
    fn spent_is_judged_by_the_derived_nullifier_not_the_cached_one() {
        let (mut keys, a_sk) = wallet_with_one_note(1_000_000);
        let spend = spend_of(&keys, &a_sk);
        keys.sprout_joinsplits.push(spend);
        keys.sprout_notes[0].nullifier = Some([0xEE; 32]);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert!(recovered.notes.is_empty());
        assert_eq!(recovered.spent.len(), 1);
    }

    #[test]
    fn an_unrelated_nullifier_does_not_mark_a_note_spent() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let mut other = keys.sprout_joinsplits[0].clone();
        other.txid = [0xAB; 32];
        other.nullifiers = [[0x01; 32], [0x02; 32]];
        keys.sprout_joinsplits.push(other);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.notes.len(), 1);
        assert!(recovered.spent.is_empty());
    }

    /// zcashd pays zero-value change back to the wallet. A note worth no
    /// more than the fee is skipped by the sweep, so offering it would quote
    /// a count and a total the sweep cannot honour.
    #[test]
    fn a_note_worth_no_more_than_the_fee_is_dust_not_spendable() {
        use crate::sprout_sweep::SPROUT_SWEEP_FEE;
        for value in [0, SPROUT_SWEEP_FEE] {
            let (keys, _) = wallet_with_one_note(value);
            let recovered = recover_spendable_sprout_notes(&keys);
            assert!(
                recovered.notes.is_empty(),
                "{value} zat must not be offered"
            );
            assert_eq!(recovered.dust.len(), 1, "{value} zat is dust");
            assert!(recovered.issues.is_empty(), "{:?}", recovered.issues);
        }
        let (keys, _) = wallet_with_one_note(SPROUT_SWEEP_FEE + 1);
        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(
            recovered.notes.len(),
            1,
            "one zatoshi over the fee is worth sweeping"
        );
        assert!(recovered.dust.is_empty());
    }

    /// Kristi's blocker on #239: zcashd keeps a transaction that expired
    /// unmined, so its nullifiers are not spends. Treating them as spends
    /// made a live note invisible, which is worse than the phantom balance.
    #[test]
    fn a_spend_the_wallet_never_saw_mined_does_not_hide_the_note() {
        let (mut keys, a_sk) = wallet_with_one_note(1_000_000);
        let spend = spend_of(&keys, &a_sk);
        keys.sprout_unconfirmed_txids.push(spend.txid);
        keys.sprout_joinsplits.push(spend);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.notes.len(), 1, "a live note must stay on offer");
        assert!(recovered.spent.is_empty());
        assert_eq!(
            recovered.unconfirmed_spends,
            vec![recovered.notes[0].outpoint],
            "and it must say an unconfirmed spend exists"
        );
    }

    #[test]
    fn a_spent_note_names_the_transaction_that_spent_it() {
        let (mut keys, a_sk) = wallet_with_one_note(1_000_000);
        let spend = spend_of(&keys, &a_sk);
        keys.sprout_joinsplits.push(spend);
        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.spent[0].spent_in, [0xAB; 32]);
    }

    /// The direction that would lose money: the file's cached nullifier
    /// matches a revealed one, but the note's real nullifier does not. The
    /// cached copy must never decide.
    #[test]
    fn a_cached_nullifier_matching_a_spend_does_not_mark_the_note_spent() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let mut other = keys.sprout_joinsplits[0].clone();
        other.txid = [0xAB; 32];
        other.nullifiers = [[0x01; 32], [0xEE; 32]];
        keys.sprout_joinsplits.push(other);
        keys.sprout_notes[0].nullifier = Some([0xEE; 32]);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.notes.len(), 1);
        assert!(recovered.spent.is_empty());
    }

    /// Kristi's probes on #239: a damaged copy of a record filed before the
    /// good copy of the same outpoint must not hide the good one. Before
    /// dedup existed both cases recovered the note; first-wins lost it.
    #[test]
    fn a_damaged_duplicate_does_not_hide_a_good_one() {
        type Spoil = fn(&mut SproutNoteData);
        let damage: [(&str, Spoil); 2] = [
            ("truncated witness", |n| n.witness.truncate(3)),
            ("foreign address", |n| n.address = [0x5A; 64]),
        ];
        for (what, spoil) in damage {
            let (mut keys, _) = wallet_with_one_note(1_000_000);
            let mut bad = keys.sprout_notes[0].clone();
            spoil(&mut bad);
            keys.sprout_notes.insert(0, bad);

            let recovered = recover_spendable_sprout_notes(&keys);
            assert_eq!(recovered.notes.len(), 1, "{what}: the good copy must win");
            assert!(
                recovered.issues.is_empty(),
                "{what}: {:?}",
                recovered.issues
            );
        }
    }

    #[test]
    fn a_duplicate_with_no_good_copy_is_reported_once() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        keys.sprout_notes[0].witness.truncate(3);
        let again = keys.sprout_notes[0].clone();
        keys.sprout_notes.push(again);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert!(recovered.notes.is_empty());
        assert_eq!(recovered.issues.len(), 1, "{:?}", recovered.issues);
    }

    /// A wallet that spent everything is told so, and is not sent to the
    /// multi-day scan; one with issues still is.
    #[test]
    fn a_fully_spent_wallet_has_nothing_left_and_says_why() {
        let (mut keys, a_sk) = wallet_with_one_note(1_000_000);
        let spend = spend_of(&keys, &a_sk);
        keys.sprout_joinsplits.push(spend);
        let recovered = recover_spendable_sprout_notes(&keys);
        assert!(recovered.nothing_left_to_sweep());
        let lines = recovered.accounting_lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("0.01000000 ZEC"), "{}", lines[0]);
        assert!(lines[0].contains("not a balance"), "{}", lines[0]);

        let (mut keys, _) = wallet_with_one_note(1_000_000);
        keys.sprout_notes[0].witness.truncate(3);
        assert!(!recover_spendable_sprout_notes(&keys).nothing_left_to_sweep());
    }

    #[test]
    fn an_unreadable_transaction_makes_the_total_uncertain_both_ways() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        assert!(unreadable_transactions_warning(&keys).is_none());
        keys.diagnostics
            .push(argos_wallet_import::ImportDiagnostic::UnparseableRecord {
                record_type: "tx".into(),
                reason: "x".into(),
            });
        let warning = unreadable_transactions_warning(&keys).unwrap();
        assert!(warning.contains("either direction"), "{warning}");
    }

    /// A cached witness blob in zcashd's shape: one witness, then the
    /// `witnessHeight` it was last updated at.
    fn witness_blob(commitment: [u8; 32], later: &[[u8; 32]], height: i32) -> Vec<u8> {
        let mut tree = crate::sprout_witness::IncrementalMerkleTree::default();
        tree.append(commitment).unwrap();
        let mut witness = crate::sprout_witness::IncrementalWitness::from_tree(tree);
        for cm in later {
            witness.append(*cm).unwrap();
        }
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&witness.to_bytes());
        blob.extend_from_slice(&height.to_le_bytes());
        blob
    }

    /// Kristi's F10 on #239: of two valid copies of one note, the one whose
    /// cached witness zcashd updated later wins, whichever came first.
    #[test]
    fn of_two_good_copies_the_fresher_witness_wins() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let cm = keys.sprout_joinsplits[0].commitments[0];
        let stale = witness_blob(cm, &[], 100);
        let fresh = witness_blob(cm, &[[0x31; 32], [0x32; 32]], 250);
        let fresh_root = crate::sprout_witness::IncrementalWitness::parse_cached(&fresh)
            .unwrap()
            .root();
        keys.sprout_notes[0].witness = fresh;
        let mut older = keys.sprout_notes[0].clone();
        older.witness = stale;
        keys.sprout_notes.insert(0, older);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.notes.len(), 1);
        assert_eq!(recovered.notes[0].anchor, fresh_root, "the stale copy won");
    }

    /// Kristi's F11: with no usable copy, each copy's distinct problem is
    /// reported, not just the first — different causes, different remedies.
    #[test]
    fn every_distinct_problem_with_an_unusable_note_is_reported() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let mut foreign = keys.sprout_notes[0].clone();
        foreign.address = [0x5A; 64];
        keys.sprout_notes[0].witness.truncate(3);
        keys.sprout_notes.push(foreign);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert!(recovered.notes.is_empty());
        assert_eq!(recovered.issues.len(), 2, "{:?}", recovered.issues);
        assert!(matches!(
            recovered.issues[0],
            SproutRecoveryIssue::UnreadableWitness { .. }
        ));
        assert!(matches!(
            recovered.issues[1],
            SproutRecoveryIssue::NoSpendingKey { .. }
        ));
    }

    /// Kristi's F4: an unread transaction may have received notes that were
    /// never counted, so "nothing left" cannot be claimed while any exist —
    /// that verdict withdraws the scan, the one thing that could correct it.
    #[test]
    fn nothing_is_left_only_when_every_transaction_was_read() {
        let (mut keys, a_sk) = wallet_with_one_note(1_000_000);
        let spend = spend_of(&keys, &a_sk);
        keys.sprout_joinsplits.push(spend);
        assert!(recover_spendable_sprout_notes(&keys).nothing_left_to_sweep());

        keys.diagnostics
            .push(argos_wallet_import::ImportDiagnostic::UnparseableRecord {
                record_type: "tx".into(),
                reason: "x".into(),
            });
        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.unreadable_transactions, 1);
        assert!(!recovered.nothing_left_to_sweep());
        let warning = unreadable_transactions_warning(&keys).unwrap();
        assert!(warning.contains("received"), "both directions: {warning}");
    }

    /// Values come from the file, so a crafted one can sum past `u64::MAX`.
    #[test]
    fn totals_saturate_rather_than_overflow() {
        let (keys, _) = wallet_with_one_note(u64::MAX / 2 + 1);
        let one = recover_spendable_sprout_notes(&keys);
        let mut twice = SproutRecovery::default();
        for n in one.notes {
            twice.notes.push(SpendableSproutNote { ..n });
        }
        let (keys, _) = wallet_with_one_note(u64::MAX / 2 + 1);
        twice
            .notes
            .extend(recover_spendable_sprout_notes(&keys).notes);
        assert_eq!(twice.total_value(), u64::MAX);
    }

    #[test]
    fn a_note_listed_twice_is_counted_once() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let again = keys.sprout_notes[0].clone();
        keys.sprout_notes.push(again);

        let recovered = recover_spendable_sprout_notes(&keys);
        assert_eq!(recovered.notes.len(), 1);
        assert_eq!(recovered.total_value(), 1_000_000);
    }

    /// The check that separates "decrypts" from "spendable". A note whose
    /// commitment does not match the chain must never reach the builder.
    #[test]
    fn a_note_whose_commitment_disagrees_is_rejected_not_returned() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        keys.sprout_joinsplits[0].commitments[0] = [0xFF; 32];

        let recovered = recover_spendable_sprout_notes(&keys);

        assert!(
            recovered.notes.is_empty(),
            "it must not be offered as spendable"
        );
        assert!(matches!(
            recovered.issues.as_slice(),
            [SproutRecoveryIssue::CommitmentMismatch { .. }]
        ));
    }

    #[test]
    fn a_note_with_no_matching_key_is_reported_not_dropped_silently() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        keys.sprout.clear();

        let recovered = recover_spendable_sprout_notes(&keys);

        assert!(recovered.notes.is_empty());
        assert!(matches!(
            recovered.issues.as_slice(),
            [SproutRecoveryIssue::NoSpendingKey { .. }]
        ));
    }

    #[test]
    fn a_note_whose_joinsplit_is_absent_is_reported() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        keys.sprout_joinsplits.clear();

        let recovered = recover_spendable_sprout_notes(&keys);

        assert!(recovered.notes.is_empty());
        assert!(matches!(
            recovered.issues.as_slice(),
            [SproutRecoveryIssue::MissingJoinSplit { .. }]
        ));
    }

    /// The wrong key must fail to authenticate rather than yield garbage
    /// that then fails the commitment check — the two failures are
    /// different bugs and should not be confused.
    #[test]
    fn the_wrong_spending_key_fails_to_decrypt() {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let wrong = [0x01u8; 32];
        // Keep the address the note is filed under, so the join still
        // matches and only the key is wrong.
        keys.sprout[0] = SproutKey {
            a_sk: Secret::new(wrong),
            address: keys.sprout_notes[0].address,
            provenance: Provenance::Standalone,
        };

        let recovered = recover_spendable_sprout_notes(&keys);

        assert!(recovered.notes.is_empty());
        assert!(
            matches!(
                recovered.issues.as_slice(),
                [SproutRecoveryIssue::Undecryptable { .. }]
            ),
            "expected an authentication failure, got {:?}",
            recovered.issues
        );
    }

    /// One unrecoverable note must not suppress a recoverable one.
    #[test]
    fn a_bad_note_does_not_hide_a_good_one() {
        let (mut keys, _) = wallet_with_one_note(5_000_000);
        let mut orphan = keys.sprout_notes[0].clone();
        orphan.outpoint.js_index = 99; // no such JoinSplit
        keys.sprout_notes.push(orphan);

        let recovered = recover_spendable_sprout_notes(&keys);

        assert_eq!(recovered.notes.len(), 1, "the good note still comes back");
        assert_eq!(recovered.total_value(), 5_000_000);
        assert_eq!(recovered.issues.len(), 1);
    }
}
