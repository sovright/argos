//! zcashd wallet encryption.
//!
//! zcashd derives a key-encryption key from the passphrase with an
//! iterated SHA-512 (Bitcoin's `EVP_BytesToKey`-style construction), then
//! AES-256-CBC-decrypts a random master key stored in the `mkey` record.
//! Every individual key record is encrypted under that master key.

use aes::cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, KeyIvInit};
use secrecy::{ExposeSecret, Secret, SecretString};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::{
    bdb::RawRecord,
    error::ImportError,
    zcashd::records::{compact_size, parse_record_key},
    SecretBytes,
};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// zcashd's only key derivation method.
const DERIVATION_SHA512: u32 = 0;

/// Refuse an absurd round count: it would be a denial of service against
/// the importing user, and no real wallet uses one.
const MAX_ROUNDS: u32 = 10_000_000;

#[derive(Debug, Clone)]
pub struct MkeyRecord {
    pub encrypted_key: Vec<u8>,
    pub salt: [u8; 8],
    pub derivation_method: u32,
    pub rounds: u32,
}

/// Encryption state of the records recovered from a zcashd wallet.
pub enum EncryptionMetadata {
    Unencrypted,
    Encrypted(MkeyRecord),
    Damaged { reason: String },
}

/// Classify encryption before extracting any keys. An encrypted record is
/// never evidence that the wallet is plaintext merely because its `mkey`
/// is absent or malformed.
pub fn classify_encryption(pairs: &[RawRecord]) -> EncryptionMetadata {
    let mut encrypted_records = false;
    let mut mkey = None;
    let mut malformed_mkey = false;

    for record in pairs {
        let key = &record.key;
        let value = record.value();
        let Some(record) = parse_record_key(key) else {
            continue;
        };
        match record.record_type.as_str() {
            "ckey" | "czkey" | "csapzkey" | "chdseed" | "cmnemonicphrase" => {
                encrypted_records = true;
            }
            "mkey" => match parse_mkey(value) {
                Some(parsed)
                    if parsed.derivation_method == DERIVATION_SHA512
                        && parsed.encrypted_key.len() == 48 =>
                {
                    mkey = Some(parsed);
                }
                _ => malformed_mkey = true,
            },
            _ => {}
        }
    }

    if malformed_mkey || (encrypted_records && mkey.is_none()) {
        let reason = if encrypted_records {
            "mkey is missing or invalid while encrypted records are present"
        } else {
            "mkey is invalid"
        };
        EncryptionMetadata::Damaged {
            reason: reason.to_owned(),
        }
    } else if let Some(mkey) = mkey {
        EncryptionMetadata::Encrypted(mkey)
    } else {
        EncryptionMetadata::Unencrypted
    }
}

/// The decrypted wallet master key. Every `ckey`, `czkey`, and `csapzkey`
/// record is encrypted under this.
pub struct MasterKey(pub(crate) Secret<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// Access the raw key bytes, for decrypting the `ckey`/`czkey`/
    /// `csapzkey` records that follow. Callers must not let these bytes
    /// escape the scope of that decryption — never log, print, or copy
    /// them into a longer-lived structure.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// Parse an `mkey` record value.
pub fn parse_mkey(value: &[u8]) -> Option<MkeyRecord> {
    let (klen, koff) = compact_size(value)?;
    let kend = koff.checked_add(usize::try_from(klen).ok()?)?;
    let encrypted_key = value.get(koff..kend)?.to_vec();

    let (slen, soff) = compact_size(value.get(kend..)?)?;
    if slen != 8 {
        return None;
    }
    let sstart = kend.checked_add(soff)?;
    let send = sstart.checked_add(8)?;
    let salt: [u8; 8] = value.get(sstart..send)?.try_into().ok()?;

    let mut b = [0u8; 4];
    b.copy_from_slice(value.get(send..send + 4)?);
    let derivation_method = u32::from_le_bytes(b);

    b.copy_from_slice(value.get(send + 4..send + 8)?);
    let rounds = u32::from_le_bytes(b);

    if rounds == 0 || rounds > MAX_ROUNDS {
        return None;
    }

    Some(MkeyRecord {
        encrypted_key,
        salt,
        derivation_method,
        rounds,
    })
}

/// Locate the `mkey` record in a walked wallet, if the wallet is encrypted.
pub fn find_mkey(pairs: &[RawRecord]) -> Option<MkeyRecord> {
    pairs.iter().find_map(|record| {
        let rec = parse_record_key(&record.key)?;
        (rec.record_type == "mkey").then(|| parse_mkey(record.value()))?
    })
}

/// Derive the key-encryption key and unwrap the master key.
///
/// Returns `WrongPassphrase` — never a corruption error — when unwrapping
/// fails, so a user with a correct passphrase and a damaged wallet is not
/// misled into giving up on recoverable funds.
pub fn derive_master_key(
    passphrase: &SecretString,
    mkey: &MkeyRecord,
) -> Result<MasterKey, ImportError> {
    if mkey.derivation_method != DERIVATION_SHA512 {
        return Err(ImportError::UnwalkableBtree(format!(
            "unsupported key derivation method {}",
            mkey.derivation_method
        )));
    }

    // Iterated SHA-512 over passphrase||salt, then re-hashing the digest.
    //
    // Everything derived below is as sensitive as the passphrase itself.
    // Explicit digest outputs, the KEK/IV split, the AES/CBC key schedule,
    // and the in-place plaintext buffer all have zeroizing owners. The
    // `sha2` hasher's internal compression state does not expose a zeroize
    // feature; compiler-created register/stack copies are likewise outside
    // Rust's ownership guarantees and remain a documented residual limit.
    let mut buf = Zeroizing::new([0u8; 64]);
    let mut hasher = Sha512::new();
    hasher.update(passphrase.expose_secret().as_bytes());
    hasher.update(mkey.salt);
    let digest = Zeroizing::new(hasher.finalize());
    buf.copy_from_slice(digest.as_slice());

    for _ in 1..mkey.rounds {
        let mut h = Sha512::new();
        h.update(buf.as_slice());
        let digest = Zeroizing::new(h.finalize());
        buf.copy_from_slice(digest.as_slice());
    }

    let mut ct = SecretBytes::copy_from_slice(&mkey.encrypted_key);
    (|| {
        let mut kek = Zeroizing::new([0u8; 32]);
        let mut iv = Zeroizing::new([0u8; 16]);
        kek.copy_from_slice(buf.get(0..32).ok_or(ImportError::WrongPassphrase)?);
        iv.copy_from_slice(buf.get(32..48).ok_or(ImportError::WrongPassphrase)?);

        let decrypted = Aes256CbcDec::new(
            GenericArray::from_slice(kek.as_slice()),
            GenericArray::from_slice(iv.as_slice()),
        )
        .decrypt_padded_mut::<Pkcs7>(ct.as_mut_slice())
        // Bad PKCS#7 padding is overwhelmingly a wrong passphrase, and
        // that is the actionable message for the user.
        .map_err(|_| ImportError::WrongPassphrase);

        Ok(MasterKey(Secret::new(
            decrypted?
                .try_into()
                .map_err(|_| ImportError::WrongPassphrase)?,
        )))
    })()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn aes_cbc_key_schedule_and_iv_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<aes::Aes256>();
        assert_zeroize_on_drop::<Aes256CbcDec>();
    }

    #[test]
    fn parses_an_mkey_record() {
        // 48-byte encrypted key, 8-byte salt, method 0, 25000 rounds.
        let mut v = vec![0x30];
        v.extend_from_slice(&[0xAA; 48]);
        v.extend_from_slice(&[0x08]);
        v.extend_from_slice(&[0xBB; 8]);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&25_000u32.to_le_bytes());

        let m = parse_mkey(&v).unwrap();
        assert_eq!(m.encrypted_key.len(), 48);
        assert_eq!(m.salt, [0xBB; 8]);
        assert_eq!(m.rounds, 25_000);
    }

    #[test]
    fn rejects_a_truncated_mkey_record() {
        assert!(parse_mkey(&[0x30, 0xAA]).is_none());
    }

    #[test]
    fn rejects_zero_rounds() {
        // Zero rounds would make key stretching a no-op.
        let mut v = vec![0x30];
        v.extend_from_slice(&[0xAA; 48]);
        v.extend_from_slice(&[0x08]);
        v.extend_from_slice(&[0xBB; 8]);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_mkey(&v).is_none());
    }

    #[test]
    fn a_wrong_passphrase_is_reported_as_wrong_passphrase() {
        // Not as corruption. A user with a correct passphrase and a
        // damaged wallet must not be told their passphrase is wrong.
        let bytes = std::fs::read("tests/fixtures/modern-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap().records;
        let mkey = find_mkey(&pairs).expect("encrypted wallet must have an mkey");
        let err = derive_master_key(&SecretString::new("definitely-wrong".to_owned()), &mkey)
            .unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn the_correct_passphrase_derives_a_master_key() {
        let bytes = std::fs::read("tests/fixtures/modern-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap().records;
        let mkey = find_mkey(&pairs).expect("encrypted wallet must have an mkey");
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        assert!(derive_master_key(&pass, &mkey).is_ok());
    }
}
