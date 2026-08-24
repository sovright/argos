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
