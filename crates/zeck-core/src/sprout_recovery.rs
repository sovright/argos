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

use std::collections::HashMap;

use argos_wallet_import::keys::{ImportedKeys, JsOutPoint, SproutJoinSplit};
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

/// The outcome of scanning a wallet for spendable Sprout notes.
#[derive(Debug, Default)]
pub struct SproutRecovery {
    pub notes: Vec<SpendableSproutNote>,
    pub issues: Vec<SproutRecoveryIssue>,
}

impl SproutRecovery {
    pub fn total_value(&self) -> u64 {
        self.notes.iter().map(|n| n.note.value).sum()
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

/// Decrypt every Sprout note the wallet holds a spending key for.
///
/// Never fails as a whole: notes that cannot be recovered are reported in
/// `issues`.
pub fn recover_spendable_sprout_notes(keys: &ImportedKeys) -> SproutRecovery {
    let by_outpoint: HashMap<([u8; 32], u64), &SproutJoinSplit> = keys
        .sprout_joinsplits
        .iter()
        .map(|js| ((js.txid, js.js_index), js))
        .collect();

    // Keyed by the full 64-byte address, never by `a_pk` alone: a_pk and
    // pk_enc must come from the same key, and matching on half of the
    // address would let a wallet holding two keys pair the wrong halves.
    let keys_by_address: HashMap<[u8; 64], &[u8; 32]> = keys
        .sprout
        .iter()
        .map(|k| (k.address, k.a_sk.expose_secret()))
        .collect();

    let mut out = SproutRecovery::default();

    for note_data in &keys.sprout_notes {
        let outpoint = note_data.outpoint;

        let Some(js) = by_outpoint.get(&(outpoint.txid, outpoint.js_index)) else {
            out.issues
                .push(SproutRecoveryIssue::MissingJoinSplit { outpoint });
            continue;
        };

        let index = outpoint.output_index;
        let Some(ciphertext) = js.ciphertexts.get(index as usize) else {
            out.issues
                .push(SproutRecoveryIssue::OutputIndexOutOfRange { outpoint, index });
            continue;
        };

        let Some(a_sk) = keys_by_address.get(&note_data.address) else {
            out.issues
                .push(SproutRecoveryIssue::NoSpendingKey { outpoint });
            continue;
        };

        let h_sig = sprout::h_sig(&js.random_seed, &js.nullifiers, &js.joinsplit_pubkey);
        let note = match sprout::decrypt_note(a_sk, &js.ephemeral_key, ciphertext, &h_sig, index) {
            Ok(note) => note,
            Err(err) => {
                out.issues.push(SproutRecoveryIssue::Undecryptable {
                    outpoint,
                    reason: err.to_string(),
                });
                continue;
            }
        };

        // Derive the address from the key rather than trusting the 64 bytes
        // stored beside the note: the commitment check below is only
        // meaningful if `a_pk` provably belongs to the key we are about to
        // spend with.
        let address = SproutPaymentAddress::from_spending_key(a_sk);
        let derived = sprout::note_commitment(address.a_pk(), note.value, &note.rho, &note.r);
        let expected = js.commitments[index as usize];
        if derived != expected {
            out.issues.push(SproutRecoveryIssue::CommitmentMismatch {
                outpoint,
                expected,
                derived,
            });
            continue;
        }

        // Resolved now, not at sweep time: a witness that cannot be read
        // makes the note unspendable, and saying so during recovery is far
        // better than after a 725 MB proving run.
        let witness =
            match crate::sprout_witness::IncrementalWitness::parse_cached(&note_data.witness) {
                Ok(w) => w,
                Err(err) => {
                    out.issues.push(SproutRecoveryIssue::UnreadableWitness {
                        outpoint,
                        reason: err.to_string(),
                    });
                    continue;
                }
            };
        let witness_path = match witness.encode_for_prover() {
            Ok(path) => path.to_vec(),
            Err(err) => {
                out.issues.push(SproutRecoveryIssue::UnreadableWitness {
                    outpoint,
                    reason: err.to_string(),
                });
                continue;
            }
        };

        out.notes.push(SpendableSproutNote {
            note,
            a_sk: **a_sk,
            address,
            commitment: derived,
            anchor: witness.root(),
            witness_path,
            outpoint,
        });
    }

    out
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
        let (mut keys, _) = wallet_with_one_note(1_000);
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
        let (mut keys, _) = wallet_with_one_note(1_000);
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

    /// The check that separates "decrypts" from "spendable". A note whose
    /// commitment does not match the chain must never reach the builder.
    #[test]
    fn a_note_whose_commitment_disagrees_is_rejected_not_returned() {
        let (mut keys, _) = wallet_with_one_note(1_000);
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
        let (mut keys, _) = wallet_with_one_note(1_000);
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
        let (mut keys, _) = wallet_with_one_note(1_000);
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
        let (mut keys, _) = wallet_with_one_note(1_000);
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
        let (mut keys, _) = wallet_with_one_note(5_000);
        let mut orphan = keys.sprout_notes[0].clone();
        orphan.outpoint.js_index = 99; // no such JoinSplit
        keys.sprout_notes.push(orphan);

        let recovered = recover_spendable_sprout_notes(&keys);

        assert_eq!(recovered.notes.len(), 1, "the good note still comes back");
        assert_eq!(recovered.total_value(), 5_000);
        assert_eq!(recovered.issues.len(), 1);
    }
}
