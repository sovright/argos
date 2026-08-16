//! zcashd wallet.dat record layer.

pub mod crypto;
pub mod encrypted;
pub mod plaintext;
pub mod records;
pub mod sprout;

pub use crypto::{derive_master_key, find_mkey, MasterKey, MkeyRecord};
pub use encrypted::collect_encrypted;
pub use plaintext::collect_plaintext;
pub use records::{compact_size, parse_record_key, RecordKey};
pub use sprout::collect_sprout_notes;

use secrecy::SecretString;

use crate::{bdb, error::ImportError, keys::ImportedKeys};

/// True when the wallet carries an `mkey` record and therefore needs a
/// passphrase. Checked before prompting so we never ask for a passphrase
/// the wallet does not use.
pub fn needs_passphrase(bytes: &[u8]) -> bool {
    bdb::walk(bytes)
        .map(|pairs| find_mkey(&pairs).is_some())
        .unwrap_or(false)
}

/// Parse a zcashd `wallet.dat` into normalized key material.
///
/// Decryption happens here, once, before any caller touches the network:
/// a wallet needing a passphrase fails fast and locally.
pub fn import_zcashd(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let pairs = bdb::walk(bytes)?;
    let mut out = ImportedKeys::default();

    collect_plaintext(&pairs, &mut out);
    collect_sprout_notes(&pairs, &mut out);

    if let Some(mkey) = find_mkey(&pairs) {
        // Encrypted wallet: without a passphrase the encrypted records are
        // unreachable, and reporting partial plaintext results would let a
        // user believe they had recovered everything.
        let passphrase = passphrase.ok_or(ImportError::WrongPassphrase)?;
        let master = derive_master_key(passphrase, &mkey)?;
        collect_encrypted(&pairs, &master, &mut out);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap()
    }

    #[test]
    fn detects_which_wallets_need_a_passphrase() {
        assert!(needs_passphrase(&read("modern-encrypted")));
        assert!(needs_passphrase(&read("sprout-encrypted")));
        assert!(!needs_passphrase(&read("modern-plaintext")));
        assert!(!needs_passphrase(&read("sprout-plaintext")));
    }

    #[test]
    fn imports_a_plaintext_wallet_without_a_passphrase() {
        let keys = import_zcashd(&read("sprout-plaintext"), None).unwrap();
        assert!(!keys.sprout.is_empty());
        assert!(!keys.is_empty());
    }

    #[test]
    fn refuses_an_encrypted_wallet_without_a_passphrase() {
        let err = import_zcashd(&read("sprout-encrypted"), None).unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn imports_an_encrypted_sprout_wallet_end_to_end() {
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let keys = import_zcashd(&read("sprout-encrypted"), Some(&pass)).unwrap();
        assert!(!keys.sprout.is_empty(), "no Sprout keys recovered");
        assert!(keys.total_keys() > 0);
    }

    #[test]
    fn a_truncated_wallet_recovers_what_it_can() {
        match import_zcashd(&read("sprout-plaintext-truncated"), None) {
            Ok(keys) => {
                // Partial recovery: either keys or diagnostics, never a
                // silent empty success.
                assert!(!keys.is_empty() || !keys.diagnostics.is_empty());
            }
            Err(ImportError::UnwalkableBtree(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
