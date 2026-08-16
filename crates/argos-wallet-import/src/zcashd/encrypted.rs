//! Decryption of encrypted zcashd key records.
//!
//! Each record's IV is the first 16 bytes of a 32-byte digest computed
//! from that record's own public identifier — which is why the master key
//! alone is enough to decrypt every record. zcashd (`crypter.cpp`,
//! `DecryptSecret`/`DecryptKey`/`DecryptSproutSpendingKey`/
//! `DecryptSaplingSpendingKey`) uses a *different* digest per record type:
//!
//! - `ckey`: `SHA256d(serialized pubkey)` (`CPubKey::GetHash`)
//! - `czkey`: `SHA256d(serialized Sprout payment address)`
//!   (`SproutPaymentAddress::GetHash`)
//! - `csapzkey`: `BLAKE2b-256("ZcashSaplingFVFP", ak || nk || ovk)`
//!   (`SaplingFullViewingKey::GetFingerprint`) — the fingerprint of the
//!   *full viewing key*, not a hash of the incoming viewing key that
//!   appears in the record key.
//!
//! `czkey` — encrypted Sprout spending keys — is handled here. Zallet
//! drops Sprout keys during migration and `zewif-zcashd` returns an error
//! for them, so this is the only implementation that exists.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use secrecy::{Secret, Zeroize};
use sha2::{Digest, Sha256};

use crate::{
    error::ImportDiagnostic,
    keys::{ImportedKeys, Provenance, SaplingKey, SproutKey, TransparentKey},
    zcashd::{
        crypto::MasterKey,
        records::{compact_size, parse_record_key},
    },
};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// zcashd's Sapling FVK fingerprint personalization (`Zcash.h`/`sapling.cpp`
/// `ZCASH_SAPLING_FVFP_PERSONALIZATION`): the 16-byte ASCII string
/// `"ZcashSaplingFVFP"`.
const SAPLING_FVFP_PERSONALIZATION: &[u8; 16] = b"ZcashSaplingFVFP";

/// First 16 bytes of a 32-byte digest, as zcashd's `WALLET_CRYPTO_IV_SIZE`
/// truncation of the `uint256` digest into an AES IV.
fn iv_from_digest(digest: &[u8; 32]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&digest[..16]);
    iv
}

/// IV identifier for `ckey`/`czkey`: double-SHA256 of the record's public
/// identifier (pubkey or Sprout payment address).
fn sha256d_iv(identifier: &[u8]) -> [u8; 16] {
    let first = Sha256::digest(identifier);
    let second = Sha256::digest(first);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&second);
    iv_from_digest(&digest)
}

/// IV identifier for `csapzkey`: the Sapling FVK fingerprint, i.e.
/// `BLAKE2b-256("ZcashSaplingFVFP", ak || nk || ovk)`.
fn sapling_fvfp_iv(fvk: &[u8]) -> [u8; 16] {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(SAPLING_FVFP_PERSONALIZATION)
        .hash(fvk);
    let mut d = [0u8; 32];
    d.copy_from_slice(digest.as_bytes());
    iv_from_digest(&d)
}

/// Decrypt one record under the wallet master key.
///
/// Two scratch buffers here hold key material for the length of the call:
/// `key`, a stack copy of the master key that unlocks every record in the
/// wallet, and `buf`, which `decrypt_padded_mut` turns into the plaintext
/// spending key in place. Both are scrubbed before returning, on the
/// failure path as well as the success path. The returned `Vec` is the
/// caller's to protect — callers wrap it in a `Secret`.
///
/// The IV is not secret: it is derived from a public record identifier.
fn decrypt(master: &MasterKey, iv: [u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let mut buf = ciphertext.to_vec();
    let mut key: [u8; 32] = *master.expose_secret();
    let plain = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()
        .map(<[u8]>::to_vec);
    key.zeroize();
    buf.zeroize();
    plain
}

fn read_length_prefixed(value: &[u8]) -> Option<(&[u8], usize)> {
    let (len, consumed) = compact_size(value)?;
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    Some((value.get(consumed..end)?, end))
}

/// Decrypt every encrypted key record under `master`.
///
/// A record that fails to decrypt is reported and skipped. One corrupt
/// record must never cost the user the keys beside it.
pub fn collect_encrypted(pairs: &[(Vec<u8>, Vec<u8>)], master: &MasterKey, out: &mut ImportedKeys) {
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };

        match rec.record_type.as_str() {
            // Key: "czkey" || SproutPaymentAddress (64 bytes)
            // Value: receiving key `rk` || encrypted a_sk.
            // See zcash walletdb.cpp:125 —
            //   Write(("czkey", addr), make_pair(rk, vchCryptedSecret)).
            // `rk` is `libzcash::ReceivingKey`, which subclasses `uint256`
            // (sprout.hpp:46) — a fixed-size type with NO CompactSize
            // prefix, unlike `vchCryptedSecret`, a `std::vector<uchar>`
            // which does get one. So the layout is 32 raw bytes, then a
            // length-prefixed ciphertext — not two length-prefixed fields.
            "czkey" => {
                let addr: Option<[u8; 64]> = rec.rest.get(..64).and_then(|s| s.try_into().ok());
                let Some(address) = addr else {
                    out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "czkey".to_owned(),
                        reason: "payment address is not 64 bytes".to_owned(),
                    });
                    continue;
                };

                // Skip the fixed-size 32-byte rk, then read the ciphertext.
                let ct = value
                    .get(32..)
                    .and_then(read_length_prefixed)
                    .map(|(ct, _)| ct);

                let Some(ct) = ct else {
                    out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "czkey".to_owned(),
                        reason: "value is not a (rk, ciphertext) pair".to_owned(),
                    });
                    continue;
                };

                match decrypt(master, sha256d_iv(&address), ct).and_then(|p| {
                    let s: [u8; 32] = p.get(..32)?.try_into().ok()?;
                    Some(s)
                }) {
                    Some(a_sk) => out.sprout.push(SproutKey {
                        a_sk: Secret::new(a_sk),
                        address,
                        provenance: Provenance::Standalone,
                    }),
                    None => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "czkey".to_owned(),
                        reason: "ciphertext did not decrypt to a 32-byte key".to_owned(),
                    }),
                }
            }

            // Key: "ckey" || serialized public key, where the serialized
            // public key is itself CompactSize(len) || raw pubkey bytes
            // (`CPubKey::Serialize`). zcashd derives the IV from
            // `vchPubKey.GetHash()` (`crypter.cpp` `DecryptKey`), and
            // `CPubKey::GetHash()` hashes only the raw pubkey — it does not
            // see the CompactSize length prefix (`pubkey.h`). So the IV
            // identifier is the raw pubkey, not the whole record-key
            // remainder.
            "ckey" => {
                let Some((pubkey, _)) = read_length_prefixed(&rec.rest) else {
                    out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "ckey".to_owned(),
                        reason: "record key is not a length-prefixed public key".to_owned(),
                    });
                    continue;
                };
                let iv = sha256d_iv(pubkey);
                match read_length_prefixed(value)
                    .and_then(|(ct, _)| decrypt(master, iv, ct))
                    .and_then(|p| {
                        let s: [u8; 32] = p.get(..32)?.try_into().ok()?;
                        Some(s)
                    }) {
                    Some(secret) => out.transparent.push(TransparentKey {
                        secret: Secret::new(secret),
                        provenance: Provenance::HdDerived,
                    }),
                    None => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "ckey".to_owned(),
                        reason: "ciphertext did not decrypt to a 32-byte key".to_owned(),
                    }),
                }
            }

            // Key: "csapzkey" || incoming viewing key.
            // Value: extfvk || encrypted extsk. `extfvk` is
            // `SaplingExtendedFullViewingKey` (zip32.h), a fixed-size
            // struct — depth(1) + parentFVKTag(4) + childIndex(4) +
            // chaincode(32) + fvk(ak+nk+ovk, 32 each = 96) + dk(32) = 169
            // bytes — with NO CompactSize prefix. `vchCryptedSecret` is a
            // `std::vector<uchar>` and does get one.
            //
            // The IV identifier is NOT the ivk in the record key: zcashd
            // (`crypter.cpp` `DecryptSaplingSpendingKey`) uses
            // `extfvk.fvk.GetFingerprint()`, the Sapling FVK fingerprint
            // over the embedded `fvk` (ak||nk||ovk) — offset 41..137 of
            // the 169-byte extfvk blob (depth 1 + parentFVKTag 4 +
            // childIndex 4 + chaincode 32 = 41 bytes precede it).
            "csapzkey" => {
                const EXTFVK_LEN: usize = 169;
                const FVK_OFFSET: usize = 41;
                const FVK_LEN: usize = 96;

                let fvk = value.get(FVK_OFFSET..FVK_OFFSET + FVK_LEN);
                let Some(fvk) = fvk else {
                    out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "csapzkey".to_owned(),
                        reason: "extfvk is truncated".to_owned(),
                    });
                    continue;
                };
                let iv = sapling_fvfp_iv(fvk);

                match value
                    .get(EXTFVK_LEN..)
                    .and_then(read_length_prefixed)
                    .and_then(|(ct, _)| decrypt(master, iv, ct))
                {
                    Some(extsk) => out.sapling.push(SaplingKey {
                        extsk: Secret::new(extsk),
                        provenance: Provenance::HdDerived,
                    }),
                    None => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "csapzkey".to_owned(),
                        reason: "ciphertext did not decrypt".to_owned(),
                    }),
                }
            }

            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, SecretString};

    #[allow(clippy::type_complexity)]
    fn unlock(fixture: &str) -> (Vec<(Vec<u8>, Vec<u8>)>, MasterKey) {
        let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat")).unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mkey = crate::zcashd::find_mkey(&pairs).expect("no mkey");
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let master = crate::zcashd::derive_master_key(&pass, &mkey).unwrap();
        (pairs, master)
    }

    #[test]
    fn decrypts_encrypted_sprout_spending_keys() {
        // The capability no other software has.
        let (pairs, master) = unlock("sprout-encrypted");
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        assert!(!out.sprout.is_empty(), "no czkey records were decrypted");
    }

    #[test]
    fn decrypted_sprout_key_matches_the_plaintext_wallet_shape() {
        let (pairs, master) = unlock("sprout-encrypted");
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        for k in &out.sprout {
            // a_sk is 32 bytes and must not be all zeros — an all-zero key
            // is the classic signature of decrypting into a zeroed buffer.
            assert_ne!(k.a_sk.expose_secret(), &[0u8; 32]);
            assert_ne!(k.address, [0u8; 64]);
        }
    }

    #[test]
    fn decrypts_encrypted_transparent_and_sapling_keys() {
        let (pairs, master) = unlock("modern-encrypted");
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        assert!(!out.transparent.is_empty(), "no ckey records decrypted");
        assert!(!out.sapling.is_empty(), "no csapzkey records decrypted");
    }

    #[test]
    fn a_record_that_fails_to_decrypt_is_reported_not_fatal() {
        let (mut pairs, master) = unlock("sprout-encrypted");
        // Corrupt one czkey value.
        for (k, v) in pairs.iter_mut() {
            if crate::zcashd::parse_record_key(k)
                .map(|r| r.record_type == "czkey")
                .unwrap_or(false)
            {
                v.iter_mut().for_each(|b| *b ^= 0xFF);
                break;
            }
        }
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        assert!(
            !out.diagnostics.is_empty(),
            "a failed decryption must be reported"
        );
    }
}
