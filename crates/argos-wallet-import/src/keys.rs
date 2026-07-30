//! The normalized output of any wallet import.

use secrecy::{zeroize::Zeroize, CloneableSecret, DebugSecret, Secret};

use crate::error::ImportDiagnostic;

/// Owns extended spending key bytes.
///
/// `secrecy` 0.8's `DebugSecret`/`CloneableSecret` blanket impls cover only
/// fixed-size arrays (up to 64 bytes) and `String` — not bare `Vec<u8>`, and
/// a serialized Sapling extsk is 169 bytes. This wrapper opts `Vec<u8>` into
/// both marker traits without deriving `Debug`, so the bytes can never leak
/// through an accidental `{:?}` on the wrapper itself.
#[derive(Clone)]
pub struct ExtSpendingKeyBytes(pub Vec<u8>);

impl Zeroize for ExtSpendingKeyBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl CloneableSecret for ExtSpendingKeyBytes {}
impl DebugSecret for ExtSpendingKeyBytes {}

/// Where a key came from. Surfaced to the user so they can tell
/// HD-derived keys from ones that exist only in the wallet file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Derived from the wallet's HD chain.
    HdDerived,
    /// Imported standalone (`z_importkey` / `importprivkey`). Exists in no
    /// seed — recoverable only from the wallet file.
    Standalone,
}

#[derive(Debug, Clone)]
pub struct TransparentKey {
    pub secret: Secret<[u8; 32]>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone)]
pub struct SaplingKey {
    /// Raw extended spending key bytes, as stored by zcashd.
    pub extsk: Secret<ExtSpendingKeyBytes>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone)]
pub struct SproutKey {
    /// 32-byte Sprout spending key a_sk.
    pub a_sk: Secret<[u8; 32]>,
    /// 64-byte Sprout payment address this key unlocks.
    pub address: [u8; 64],
    pub provenance: Provenance,
}

/// A Sprout note and its cached witness, preserved verbatim from the
/// wallet file.
///
/// Sub-spec 3's cost depends on whether these cached witnesses can be
/// brought forward instead of indexing from genesis. Preserving them here
/// is nearly free; discarding them at this layer would be irreversible.
#[derive(Debug, Clone)]
pub struct SproutNoteData {
    pub address: [u8; 64],
    pub nullifier: Option<[u8; 32]>,
    /// Opaque serialized witness. Not interpreted in sub-spec 1.
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ImportedKeys {
    pub transparent: Vec<TransparentKey>,
    pub sapling: Vec<SaplingKey>,
    pub sprout: Vec<SproutKey>,
    pub sprout_notes: Vec<SproutNoteData>,
    /// Everything we could not read. Never empty silently — always shown
    /// to the user with counts.
    pub diagnostics: Vec<ImportDiagnostic>,
}

impl ImportedKeys {
    pub fn is_empty(&self) -> bool {
        self.transparent.is_empty() && self.sapling.is_empty() && self.sprout.is_empty()
    }

    pub fn total_keys(&self) -> usize {
        self.transparent.len() + self.sapling.len() + self.sprout.len()
    }
}
