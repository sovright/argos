//! The normalized output of any wallet import.

use secrecy::Secret;

use crate::error::ImportDiagnostic;

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
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}
