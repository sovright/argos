//! The normalized output of any wallet import.

use secrecy::{Secret, SecretString};

use crate::error::ImportDiagnostic;

/// Where a key came from. Surfaced to the user so they can tell
/// HD-derived keys from ones that exist only in the wallet file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Derived from the wallet's HD chain.
    HdDerived,
    /// Imported standalone (`z_importkey` / `importprivkey`), or supplied
    /// directly as a key string. Exists in no seed, so it is recoverable
    /// only from the wallet file or from the key text itself — never
    /// re-derivable.
    Standalone,
}

/// Deliberately no `#[derive(Debug, Clone)]` on any struct below that holds
/// a `Secret`. A derived `Debug` on a key-bearing struct is a standing risk
/// that a spending key ends up in a log line or a panic message, and this
/// crate exists to handle other people's spending keys. Where a caller
/// genuinely needs `Debug`, it gets a manual, redacted impl instead.
pub struct TransparentKey {
    pub secret: Secret<[u8; 32]>,
    pub provenance: Provenance,
}

impl std::fmt::Debug for TransparentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparentKey")
            .field("secret", &"<redacted>")
            .field("provenance", &self.provenance)
            .finish()
    }
}

pub struct SaplingKey {
    /// Raw extended spending key bytes, as stored by zcashd.
    pub extsk: Secret<Vec<u8>>,
    pub provenance: Provenance,
}

impl std::fmt::Debug for SaplingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaplingKey")
            .field("extsk", &"<redacted>")
            .field("provenance", &self.provenance)
            .finish()
    }
}

pub struct SproutKey {
    /// 32-byte Sprout spending key a_sk.
    pub a_sk: Secret<[u8; 32]>,
    /// 64-byte Sprout payment address this key unlocks.
    pub address: [u8; 64],
    pub provenance: Provenance,
}

impl std::fmt::Debug for SproutKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SproutKey")
            .field("a_sk", &"<redacted>")
            .field("address", &self.address)
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// A Sprout note and its cached witness, preserved verbatim from the
/// wallet file.
///
/// Sub-spec 3's cost depends on whether these cached witnesses can be
/// brought forward instead of indexing from genesis. Preserving them here
/// is nearly free; discarding them at this layer would be irreversible.
///
/// Holds no secret material — witnesses and addresses are public — so it
/// keeps the ordinary derives.
#[derive(Debug, Clone)]
pub struct SproutNoteData {
    pub address: [u8; 64],
    pub nullifier: Option<[u8; 32]>,
    /// Opaque serialized witness. Not interpreted in sub-spec 1.
    pub witness: Vec<u8>,
    /// Which JoinSplit output this note came out of.
    ///
    /// Preserved because it is the only link from a note to the ciphertext
    /// that carries its plaintext. The note records hold `value`, `rho` and
    /// `r` nowhere; those live in the JoinSplit's `ciphertexts[n]`, and
    /// nothing else in the wallet says which output of which JoinSplit a
    /// given note came from.
    pub outpoint: JsOutPoint,
}

/// zcashd's `JSOutPoint`: the transaction, the JoinSplit within it, and the
/// output within that JoinSplit (always 0 or 1 — `ZC_NUM_JS_OUTPUTS` is 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsOutPoint {
    pub txid: [u8; 32],
    pub js_index: u64,
    pub output_index: u8,
}

/// The public fields of one `JSDescription`, captured from a `tx` record.
///
/// Everything here is public consensus data — it is on-chain in the clear.
/// The note plaintexts inside `ciphertexts` are not readable without a
/// Sprout spending key, so this struct is not secret-bearing and keeps the
/// ordinary derives.
///
/// `proof` and `macs` are deliberately not captured: recovery re-proves
/// from scratch and never re-checks the original proof.
#[derive(Debug, Clone)]
pub struct SproutJoinSplit {
    pub txid: [u8; 32],
    pub js_index: u64,
    pub anchor: [u8; 32],
    pub nullifiers: [[u8; 32]; 2],
    pub commitments: [[u8; 32]; 2],
    pub ephemeral_key: [u8; 32],
    pub random_seed: [u8; 32],
    /// Per-transaction, not per-JoinSplit, but copied onto each one because
    /// `hSig` needs it alongside this JoinSplit's own `random_seed` and
    /// nullifiers, and carrying it here keeps that computation local.
    pub joinsplit_pubkey: [u8; 32],
    /// The two note ciphertexts, `ZC_NOTECIPHERTEXT_SIZE` (601) bytes each.
    pub ciphertexts: [Vec<u8>; 2],
}

/// No `Debug`/`Clone` derive: it holds `Vec<TransparentKey>` etc., which
/// carry `Secret`s. Add a manual redacted impl or a clone path if a caller
/// turns out to need one — not speculatively.
#[derive(Default)]
pub struct ImportedKeys {
    pub transparent: Vec<TransparentKey>,
    pub sapling: Vec<SaplingKey>,
    pub sprout: Vec<SproutKey>,
    pub sprout_notes: Vec<SproutNoteData>,
    /// Every JoinSplit in every `tx` record the wallet holds, indexed by
    /// `SproutNoteData::outpoint`. Kept flat rather than nested under the
    /// notes because one JoinSplit's `hSig` covers both of its outputs.
    pub sprout_joinsplits: Vec<SproutJoinSplit>,
    /// A recovered BIP-39 mnemonic, when the source wallet held a seed
    /// rather than (or in addition to) flat key material — currently only
    /// ZWL, whose HD keys are re-derived from this seed rather than stored
    /// individually. Deriving keys from it is `argos-core`'s job, not this
    /// crate's: see the module docs on `zwl` for why.
    pub mnemonic: Option<SecretString>,
    /// True when a zcashd 5.x seed decoded, matched the fingerprint zcashd
    /// stored it under, and matched the wallet's `mnemonichdchain`. It is
    /// *not* placed in `mnemonic`: zcashd stores its keys under the legacy
    /// account `0x7FFFFFFF`, which the HD scan never enumerates, so routing
    /// the wallet down the HD path would drop them. Verification is what
    /// lets the import say whether the stored keys are the whole story.
    pub seed_verified: bool,
    /// Everything we could not read. Never empty silently — always shown
    /// to the user with counts.
    pub diagnostics: Vec<ImportDiagnostic>,
}

impl ImportedKeys {
    /// A recovered mnemonic counts as non-empty even with zero flat keys:
    /// that is exactly what a decrypted ZWL wallet yields, since its
    /// HD-derived keys live only in the seed, not the file. See the
    /// `mnemonic` field's docs.
    pub fn is_empty(&self) -> bool {
        self.transparent.is_empty()
            && self.sapling.is_empty()
            && self.sprout.is_empty()
            && self.mnemonic.is_none()
    }

    pub fn total_keys(&self) -> usize {
        self.transparent.len() + self.sapling.len() + self.sprout.len()
    }

    /// The "Seed phrase" line for a verified zcashd seed, shared by the CLI
    /// and GUI. Claims the stored keys are complete only when the seed's own
    /// records say so.
    pub fn verified_seed_note(&self) -> Option<&'static str> {
        if !self.seed_verified {
            return None;
        }
        let another_seed = self
            .diagnostics
            .iter()
            .any(|d| matches!(d, ImportDiagnostic::UnrecoveredSeed { .. }));
        let seed_keys_missing = self.diagnostics.iter().any(|d| {
            matches!(
                d,
                ImportDiagnostic::UnscannedSeedAccounts { .. }
                    | ImportDiagnostic::MissingDerivedKeys { .. }
            )
        });
        // The completeness claim covers the whole file, so a second seed
        // Argos could not verify withdraws it as surely as a missing key.
        Some(if seed_keys_missing {
            "verified — but not every key it derived is in this file (see Recovery coverage)"
        } else if another_seed {
            "verified — but this file also holds a seed Argos could not verify (see Recovery \
             coverage)"
        } else {
            "verified — every key it derived is read from this file"
        })
    }

    /// How much of the file's key material this import is known to cover,
    /// graded by the worst diagnostic.
    pub fn coverage(&self) -> ImportCoverage {
        self.diagnostics
            .iter()
            .map(ImportCoverage::of)
            .max()
            .unwrap_or(ImportCoverage::Complete)
    }

    /// Every distinct way this import is incomplete, most severe first, in
    /// the words both surfaces show. `None` when complete.
    ///
    /// Not just the worst grade: two failure modes neither of which is worse
    /// than the other — unscanned unified accounts and an unreadable key
    /// record — call for different things, and saying only one hid the
    /// other.
    pub fn coverage_notice(&self) -> Option<String> {
        let mut grades: Vec<ImportCoverage> =
            self.diagnostics.iter().map(ImportCoverage::of).collect();
        grades.sort_unstable_by(|a, b| b.cmp(a));
        grades.dedup();
        let may_hide_funds = grades.iter().any(|g| g.may_hide_funds());
        let mut notices: Vec<&str> = grades
            .into_iter()
            .filter_map(ImportCoverage::notice)
            .collect();
        // Once, after every notice, rather than at the end of each: joining
        // two notices used to print the same call to action twice.
        if may_hide_funds {
            notices.push(KEEP_THE_FILE);
        }
        (!notices.is_empty()).then(|| notices.join(" "))
    }
}

/// What to do about any notice that may hide funds; appended once by
/// [`ImportedKeys::coverage_notice`].
const KEEP_THE_FILE: &str = "Keep the original wallet file.";

/// Graded, so a skipped record of an unrecognised type does not raise the
/// same alarm as a lost seed: a warning people learn to ignore is worse
/// than none. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImportCoverage {
    /// Every record that can hold a key was read.
    Complete,
    /// Complete as far as can be checked, beside a pre-5.0 seed whose
    /// individually stored keys have no counters to check them against.
    LegacySeedUnchecked,
    /// Only records of unrecognised types were skipped. They may hold
    /// nothing of value, but we cannot say so.
    UnknownRecordsSkipped,
    /// A record known to hold key material could not be read or decrypted.
    KeysUnread,
    /// The file's own seed chain says keys were derived that it does not
    /// hold — a truncated or damaged wallet. Not "unread": they are absent.
    DerivedKeysMissing,
    /// The seed is verified, but unified accounts derived from it hold
    /// keys the file does not store, so they are not scanned.
    SeedAccountsNotScanned,
    /// The wallet's HD seed could not be verified, so a whole key tree may
    /// be missing.
    SeedNotRecovered,
}

impl ImportCoverage {
    fn of(diagnostic: &ImportDiagnostic) -> Self {
        match diagnostic {
            ImportDiagnostic::UnrecoveredSeed { .. } => Self::SeedNotRecovered,
            ImportDiagnostic::UnscannedSeedAccounts { .. } => Self::SeedAccountsNotScanned,
            ImportDiagnostic::MissingDerivedKeys { .. } => Self::DerivedKeysMissing,
            ImportDiagnostic::UnparseableRecord { .. }
            | ImportDiagnostic::DecryptionFailed { .. } => Self::KeysUnread,
            ImportDiagnostic::UnknownRecord { .. } => Self::UnknownRecordsSkipped,
            ImportDiagnostic::UncheckedLegacySeed { .. } => Self::LegacySeedUnchecked,
        }
    }

    /// One user-facing sentence, shared by the CLI and GUI so the two
    /// cannot describe the same file differently. `None` when complete. The
    /// call to action is not part of it: [`ImportedKeys::coverage_notice`]
    /// adds it once.
    pub fn notice(self) -> Option<&'static str> {
        match self {
            Self::Complete => None,
            Self::LegacySeedUnchecked => Some(
                "This wallet also holds a pre-5.0 HD seed. zcashd stored every key it \
                 derived individually and those were read, but Argos cannot check that \
                 none is missing.",
            ),
            Self::UnknownRecordsSkipped => Some(
                "Some records of a type Argos does not recognise were skipped. They \
                 are listed with the other diagnostics; if any held keys, those keys \
                 exist only in the original wallet file.",
            ),
            Self::KeysUnread => Some(
                "Incomplete — some key records could not be read, so recovered keys \
                 and balances may be missing funds.",
            ),
            Self::DerivedKeysMissing => Some(
                "Incomplete — this wallet's own records say its seed derived keys that \
                 are not in this file, so balances may be missing funds.",
            ),
            Self::SeedAccountsNotScanned => Some(
                "Incomplete — this wallet created unified accounts from its seed \
                 (z_getnewaccount). Their keys are not stored in the file and Argos \
                 does not scan them, so balances may be missing funds.",
            ),
            Self::SeedNotRecovered => Some(
                "Incomplete — this file holds an HD seed that Argos could not verify. \
                 Keys derived from it are only covered if the file also stores them \
                 individually, so balances may be missing funds.",
            ),
        }
    }

    /// Whether the notice must follow the user to the totals and the
    /// delete-workspace screen, not just the import summary.
    pub fn may_hide_funds(self) -> bool {
        self >= Self::KeysUnread
    }
}

// Manual, redacted impl rather than `#[derive(Debug)]` — needed so
// `Result<ImportedKeys, _>::unwrap_err()` type-checks in tests, without
// risking key material reaching a log line or panic message. Field
// contents are counts only; no secret ever passes through this impl.
impl std::fmt::Debug for ImportedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedKeys")
            .field("transparent", &format!("<{} keys>", self.transparent.len()))
            .field("sapling", &format!("<{} keys>", self.sapling.len()))
            .field("sprout", &format!("<{} keys>", self.sprout.len()))
            .field(
                "sprout_notes",
                &format!("<{} notes>", self.sprout_notes.len()),
            )
            .field(
                "mnemonic",
                &if self.mnemonic.is_some() {
                    "<redacted>"
                } else {
                    "None"
                },
            )
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    fn with(diagnostics: Vec<ImportDiagnostic>) -> ImportedKeys {
        ImportedKeys {
            diagnostics,
            ..ImportedKeys::default()
        }
    }

    fn unknown() -> ImportDiagnostic {
        ImportDiagnostic::UnknownRecord {
            record_type: "cscript".to_owned(),
        }
    }

    #[test]
    fn coverage_is_graded_by_the_worst_diagnostic() {
        assert_eq!(with(vec![]).coverage(), ImportCoverage::Complete);
        assert_eq!(
            with(vec![unknown()]).coverage(),
            ImportCoverage::UnknownRecordsSkipped
        );
        let unread = ImportDiagnostic::UnparseableRecord {
            record_type: "key".to_owned(),
            reason: "truncated".to_owned(),
        };
        assert_eq!(
            with(vec![unknown(), unread.clone()]).coverage(),
            ImportCoverage::KeysUnread
        );
        let seed = ImportDiagnostic::UnrecoveredSeed {
            record_type: "hdseed".to_owned(),
            reason: "pre-5.0 seed".to_owned(),
        };
        assert_eq!(
            with(vec![seed, unread, unknown()]).coverage(),
            ImportCoverage::SeedNotRecovered
        );
    }

    #[test]
    fn a_verified_seed_claims_completeness_only_when_its_records_agree() {
        let mut keys = with(vec![unknown()]);
        assert_eq!(keys.verified_seed_note(), None);
        keys.seed_verified = true;
        assert!(keys
            .verified_seed_note()
            .unwrap()
            .contains("every key it derived"));
        keys.diagnostics
            .push(ImportDiagnostic::UnscannedSeedAccounts { accounts: 1 });
        assert!(keys.verified_seed_note().unwrap().contains("not every key"));
    }

    /// Two failure modes neither of which is worse than the other must both
    /// be said. Taking only the most severe hid "some key records could not
    /// be read" behind the unified-account sentence.
    #[test]
    fn every_distinct_failure_mode_is_reported() {
        let keys = with(vec![
            ImportDiagnostic::UnscannedSeedAccounts { accounts: 2 },
            ImportDiagnostic::UnparseableRecord {
                record_type: "key".to_owned(),
                reason: "truncated".to_owned(),
            },
        ]);
        let notice = keys.coverage_notice().expect("incomplete");
        assert!(notice.contains("unified accounts"), "{notice}");
        assert!(notice.contains("could not be read"), "{notice}");
    }

    /// Keys the seed derived that the file does not hold were never "read":
    /// their notice says what the file's own records show.
    #[test]
    fn missing_derived_keys_are_not_called_unread_records() {
        let keys = with(vec![ImportDiagnostic::MissingDerivedKeys {
            pool: "Sapling".to_owned(),
            expected: 2,
            found: 1,
        }]);
        assert_eq!(keys.coverage(), ImportCoverage::DerivedKeysMissing);
        let notice = keys.coverage_notice().unwrap();
        assert!(!notice.contains("could not be read"), "{notice}");
        assert!(keys.coverage().may_hide_funds());
    }

    /// A verified seed does not make the file complete when it also holds a
    /// seed Argos could not verify: the note must not say "every key".
    #[test]
    fn an_unverified_second_seed_withdraws_the_completeness_claim() {
        let mut keys = with(vec![ImportDiagnostic::UnrecoveredSeed {
            record_type: "mnemonicphrase".to_owned(),
            reason: "a second seed in this file, which Argos could not verify".to_owned(),
        }]);
        keys.seed_verified = true;
        let note = keys.verified_seed_note().unwrap();
        assert!(!note.contains("every key it derived is read"), "{note}");
    }

    /// Each notice used to end with the same call to action, so two failure
    /// modes printed it twice in one line.
    #[test]
    fn the_call_to_action_is_said_once() {
        let keys = with(vec![
            ImportDiagnostic::UnscannedSeedAccounts { accounts: 2 },
            ImportDiagnostic::UnparseableRecord {
                record_type: "key".to_owned(),
                reason: "truncated".to_owned(),
            },
        ]);
        let notice = keys.coverage_notice().unwrap();
        assert_eq!(
            notice.matches("Keep the original wallet file").count(),
            1,
            "{notice}"
        );
        assert!(
            notice.ends_with("Keep the original wallet file."),
            "{notice}"
        );
    }

    #[test]
    fn only_a_possible_loss_of_funds_is_carried_to_later_screens() {
        assert_eq!(ImportCoverage::Complete.notice(), None);
        assert!(!ImportCoverage::UnknownRecordsSkipped.may_hide_funds());
        assert!(ImportCoverage::KeysUnread.may_hide_funds());
        assert!(ImportCoverage::SeedAccountsNotScanned.may_hide_funds());
        assert!(ImportCoverage::SeedNotRecovered.may_hide_funds());
        // The seed notice must not be the generic one: it names the seed.
        let seed = ImportCoverage::SeedNotRecovered.notice().unwrap();
        assert!(seed.contains("HD seed"));
        assert_ne!(Some(seed), ImportCoverage::KeysUnread.notice());
    }
}
