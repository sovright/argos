//! zcashd wallet encryption.
//!
//! zcashd derives a key-encryption key from the passphrase with an
//! iterated SHA-512 (Bitcoin's `EVP_BytesToKey`-style construction), then
//! AES-256-CBC-decrypts a random master key stored in the `mkey` record.
//! Every individual key record is encrypted under that master key.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use secrecy::{ExposeSecret, Secret, SecretString, Zeroize};
use sha2::{Digest, Sha512};

use crate::{
    error::ImportError,
    zcashd::records::{compact_size, parse_record_key},
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

/// The decrypted wallet master key. Every `ckey`, `czkey`, and `csapzkey`
/// record is encrypted under this.
#[derive(Clone)]
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
pub fn find_mkey(pairs: &[(Vec<u8>, Vec<u8>)]) -> Option<MkeyRecord> {
    pairs.iter().find_map(|(k, v)| {
        let rec = parse_record_key(k)?;
        (rec.record_type == "mkey").then(|| parse_mkey(v))?
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
    // Everything derived below is as sensitive as the passphrase itself:
    // `buf` *is* the key-encryption key and IV concatenated, and `ct`
    // becomes the plaintext master key in place. All three are scrubbed on
    // every exit path — including the error paths, which is why the fallible
    // steps are wrapped in a closure rather than returning with `?` directly.
    // `Zeroize` for `[u8; N]` and `Vec<u8>` is a volatile write the optimizer
    // may not elide; a plain assignment would be dead-store-eliminated.
    let mut buf = [0u8; 64];
    let mut hasher = Sha512::new();
    hasher.update(passphrase.expose_secret().as_bytes());
    hasher.update(mkey.salt);
    buf.copy_from_slice(&hasher.finalize());

    for _ in 1..mkey.rounds {
        let mut h = Sha512::new();
        h.update(buf);
        buf.copy_from_slice(&h.finalize());
    }

    let mut ct = mkey.encrypted_key.clone();
    let result = (|| {
        let mut kek = [0u8; 32];
        let mut iv = [0u8; 16];
        kek.copy_from_slice(buf.get(0..32).ok_or(ImportError::WrongPassphrase)?);
        iv.copy_from_slice(buf.get(32..48).ok_or(ImportError::WrongPassphrase)?);

        let decrypted = Aes256CbcDec::new(&kek.into(), &iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut ct)
            // Bad PKCS#7 padding is overwhelmingly a wrong passphrase, and
            // that is the actionable message for the user.
            .map_err(|_| ImportError::WrongPassphrase);

        // `kek`/`iv` were consumed by value into the cipher above, so these
        // are the copies left behind on this stack frame.
        kek.zeroize();
        iv.zeroize();

        let master: [u8; 32] = decrypted?
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or(ImportError::WrongPassphrase)?;

        Ok(MasterKey(Secret::new(master)))
    })();

    buf.zeroize();
    ct.zeroize();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

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
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mkey = find_mkey(&pairs).expect("encrypted wallet must have an mkey");
        let err = derive_master_key(&SecretString::new("definitely-wrong".to_owned()), &mkey)
            .unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn the_correct_passphrase_derives_a_master_key() {
        let bytes = std::fs::read("tests/fixtures/modern-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mkey = find_mkey(&pairs).expect("encrypted wallet must have an mkey");
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        assert!(derive_master_key(&pass, &mkey).is_ok());
    }
}
