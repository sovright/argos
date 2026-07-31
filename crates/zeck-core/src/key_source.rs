//! Where scan keys come from.
//!
//! The scanner and sweeper take a `&dyn KeySource` and no longer know
//! whether keys were HD-derived from a seed or read out of a wallet file.
//! This is the seam Sprout key sources plug into later.

use argos_wallet_import::ImportedKeys;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::{
    derivation::mnemonic_seed,
    error::{ZeckError, ZeckResult},
};

/// Domain separator so a fingerprint can never be confused with another
/// hash in the codebase.
const FINGERPRINT_DOMAIN: &[u8] = b"argos-key-source-fingerprint-v1";

/// Identifies a key set for workspace keying. Changing the keys must
/// change this, so a resume never reuses a workspace built from different
/// keys — the same invariant the seed fingerprint provided before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySourceFingerprint([u8; 32]);

impl KeySourceFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, for use in filesystem paths.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub trait KeySource: Send + Sync {
    /// Stable identifier for this key set.
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint>;

    /// The 64-byte seed used to initialize the wallet database, when one
    /// exists. Imported key sets have no seed.
    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>>;

    /// Short human-readable description for logs and the resume UI.
    /// Must never contain secret material.
    fn describe(&self) -> String;
}

/// Today's behaviour: keys derived from a BIP-39 mnemonic.
pub struct SeedKeySource {
    seed_phrase: SecretString,
}

impl SeedKeySource {
    pub fn new(seed_phrase: SecretString) -> Self {
        Self { seed_phrase }
    }

    pub fn seed_phrase(&self) -> &SecretString {
        &self.seed_phrase
    }
}

impl KeySource for SeedKeySource {
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        let seed = mnemonic_seed(&self.seed_phrase)?;
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        h.update(b"seed");
        h.update(seed.expose_secret());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Ok(KeySourceFingerprint(out))
    }

    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        let seed = mnemonic_seed(&self.seed_phrase)?;
        Ok(Some(*seed.expose_secret()))
    }

    fn describe(&self) -> String {
        "seed phrase".to_owned()
    }
}

/// Keys read out of a wallet file.
pub struct ImportedKeySource {
    keys: ImportedKeys,
}

impl ImportedKeySource {
    pub fn new(keys: ImportedKeys) -> Self {
        Self { keys }
    }

    pub fn keys(&self) -> &ImportedKeys {
        &self.keys
    }
}

impl KeySource for ImportedKeySource {
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        // Distinct label from the seed source, so the two can never
        // collide even on an empty key set.
        h.update(b"imported");

        // Hash public identifiers only — never secret material. Sprout
        // addresses and counts are enough to distinguish key sets.
        h.update((self.keys.transparent.len() as u64).to_le_bytes());
        h.update((self.keys.sapling.len() as u64).to_le_bytes());
        h.update((self.keys.sprout.len() as u64).to_le_bytes());
        for k in &self.keys.sprout {
            h.update(k.address);
        }
        for k in &self.keys.transparent {
            // Public-key-derived material is not available here, so bind
            // to a hash of the secret rather than the secret itself.
            let mut inner = Sha256::new();
            inner.update(b"argos-transparent-id-v1");
            inner.update(k.secret.expose_secret());
            h.update(inner.finalize());
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Ok(KeySourceFingerprint(out))
    }

    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        // Imported key sets have no seed. `zcash_client_sqlite`'s
        // init_wallet_db accepts None; callers must not fabricate one.
        Ok(None)
    }

    fn describe(&self) -> String {
        format!(
            "wallet file ({} transparent, {} sapling, {} sprout)",
            self.keys.transparent.len(),
            self.keys.sapling.len(),
            self.keys.sprout.len()
        )
    }
}

impl From<argos_wallet_import::ImportError> for ZeckError {
    fn from(err: argos_wallet_import::ImportError) -> Self {
        ZeckError::Import(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn the_same_seed_yields_the_same_fingerprint() {
        let a = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let b = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        assert_eq!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }

    #[test]
    fn a_different_seed_yields_a_different_fingerprint() {
        // The brief's original fixture swapped the last word ("art" ->
        // "amount"), but that invalidates the BIP-39 checksum rather than
        // yielding a second valid mnemonic — `mnemonic_seed` correctly
        // rejects it, so the test would fail on `unwrap()` regardless of
        // `KeySource`. Derive a second, genuinely valid 24-word phrase
        // from different entropy instead; the intent (different seed ->
        // different fingerprint) is unchanged.
        use bip0039::{English, Mnemonic};
        let other = Mnemonic::<English>::from_entropy(vec![0x01u8; 32])
            .unwrap()
            .into_phrase();

        let a = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let b = SeedKeySource::new(SecretString::new(other));
        assert_ne!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }

    #[test]
    fn a_seed_and_an_import_never_collide() {
        // The resume invariant depends on this: two different key sources
        // must never share a workspace.
        let seed = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let imported = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());
        assert_ne!(seed.fingerprint().unwrap(), imported.fingerprint().unwrap());
    }

    #[test]
    fn imported_fingerprint_changes_when_the_key_set_changes() {
        use argos_wallet_import::keys::{Provenance, TransparentKey};
        use secrecy::Secret;

        let empty = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());

        let mut keys = argos_wallet_import::ImportedKeys::default();
        keys.transparent.push(TransparentKey {
            secret: Secret::new([0x42; 32]),
            provenance: Provenance::Standalone,
        });
        let one = ImportedKeySource::new(keys);

        assert_ne!(empty.fingerprint().unwrap(), one.fingerprint().unwrap());
    }

    #[test]
    fn fingerprint_is_stable_across_calls() {
        let s = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        assert_eq!(s.fingerprint().unwrap(), s.fingerprint().unwrap());
    }
}
