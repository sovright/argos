//! ZecWallet Lite wallet file reader.
//!
//! Unlike zcashd, ZWL uses a custom length-prefixed serialization with no
//! magic number and no Berkeley DB involvement. The file opens with a
//! little-endian u64 `external_version`, followed by a `Keys` struct that
//! carries its own, separate version word.
//!
//! Layout confirmed against `zingolabs/zewif-zwl` (`src/zwl_parser.rs` and
//! `src/keys.rs`, default branch `master`):
//!
//! ```text
//! u64            external_version      (max known: 31, ZwlParser::serialized_version)
//! Keys:
//!   u64          keys version          (its own version word; max known: 22,
//!                                       Keys::serialized_version)
//!   u8           encrypted flag
//!   [u8; 48]     enc_seed              (encrypted seed when locked)
//!   Vector<u8>   nonce
//!   [u8; 32]     seed                  (plaintext seed; zero when locked)
//!   Vector<WalletOKey>  okeys          (only when keys version > 21)
//!   Vector<WalletZKey>  zkeys
//!   Vector<WalletTKey>  tkeys          (only when keys version > 20; older
//!                                      versions use a flat secret-key +
//!                                      address-string pair of vectors)
//! ... blocks, transactions, chain name, options, birthday, tree state,
//!     price info — ignored, this task only extracts key material.
//! ```
//!
//! `Vector`, `Optional`, and `CompactSize` above match
//! `zcash_encoding`'s encodings exactly (CompactSize count prefix for
//! `Vector`, a single 0/1 flag byte for `Optional`); this module
//! reimplements them directly rather than taking the dependency, the same
//! way `compact_size` in `zcashd::records` does for zcashd.
//!
//! Everything past the `encrypted` flag is parsed best-effort: a
//! truncated or unrecognized shape stops parsing and returns whatever key
//! material was already collected, rather than failing the whole import.
//! Only two conditions are hard errors: an unreadable/too-new
//! `external_version`, and an encrypted wallet with no passphrase or the
//! wrong one.
//!
//! ZWL never held Sprout keys, so nothing here contributes to sub-spec 3.
//!
//! ## Encrypted wallets: the seed, not the keys
//!
//! ZWL encrypts with a libsodium `secretbox` (XSalsa20-Poly1305), a
//! different primitive than zcashd's AES-256-CBC master key scheme this
//! crate already implements for `zcashd::crypto`. Confirmed against
//! `zingolabs/zewif-zwl`'s `src/keys.rs` (`master` branch, ~lines
//! 299-330):
//!
//! ```text
//! key   = double_sha256(passphrase)         // no salt, no work factor
//! nonce = self.nonce                        // 24 bytes, stored in the file
//! seed  = secretbox_open(enc_seed, nonce, key)
//! ```
//!
//! **The KDF is unsalted double-SHA-256 with no work factor.** That is
//! ZWL's design, not this crate's, but it means a ZWL passphrase is
//! brute-forceable at plain hashing speed — worth stating plainly since
//! this crate exists to handle wallets whose threat model includes that.
//!
//! A decrypted ZWL wallet does not yield a flat set of keys: ZWL stores no
//! per-key ciphertext for its HD-derived keys, only this one encrypted
//! seed, and re-derives every HD key from it on load. So decryption here
//! produces a BIP-39 mnemonic (`ImportedKeys::mnemonic`), not spending
//! keys — zip32/Sapling/Orchard re-derivation from that mnemonic belongs
//! in `argos-core`, which already does it for the unencrypted case, not in
//! this deliberately minimal, network-free leaf crate. Per-record
//! ciphertext on an individual locked `zkey`/`tkey` entry (`enc_key` +
//! its own `nonce`) is a separate, still-unimplemented scheme; those
//! entries keep surfacing as diagnostics exactly as before, since the
//! seed does not unlock them at this layer.
//!
//! **This is the least-validated code in the crate.** There is no real
//! ZWL wallet fixture to test against (unlike the zcashd path, which has
//! eight). The tests below are round-trips against hand-built byte
//! streams that follow the confirmed reference layout — they prove the
//! parser reads back what it was given, not that the layout matches every
//! real-world ZWL wallet on disk.

use bip0039::{English, Mnemonic};
use crypto_secretbox::{aead::Aead, KeyInit, Nonce as SecretboxNonce, XSalsa20Poly1305};
use secrecy::{ExposeSecret, Secret, SecretString};
use sha2::{Digest, Sha256};

use crate::{
    error::{ImportDiagnostic, ImportError},
    keys::{ImportedKeys, Provenance, SaplingKey, TransparentKey},
};

/// Highest `external_version` this parser understands, matching
/// `ZwlParser::serialized_version()` in zingolabs/zewif-zwl. Refusing a
/// newer file is safer than misreading it: a wrong parse yields wrong
/// keys silently, which is worse than a clear failure.
const MAX_SUPPORTED_VERSION: u64 = 31;

/// Highest `Keys`-internal version this parser understands, matching
/// `Keys::serialized_version()`. Distinct from `MAX_SUPPORTED_VERSION`:
/// the file version and the `Keys` struct's own version word are
/// unrelated numbers that happen to both exist in the same file.
const MAX_SUPPORTED_KEYS_VERSION: u64 = 22;

/// Below this `external_version`, `ZwlParser` calls `Keys::read_old`
/// instead of `Keys::read`: a materially different layout (per-field
/// gates keyed on `external_version` itself, no `Keys` version word, a
/// legacy Sapling extsk/extfvk vector pair). Not implemented — wallets
/// this old predate the app's stable releases, and nothing already
/// parsed is lost by stopping here.
const MIN_KEYS_READ_EXTERNAL_VERSION: u64 = 15;

/// Length of a raw serialized Sapling `ExtendedSpendingKey`: depth(1) +
/// parent_fvk_tag(4) + child_index(4) + chain_code(32) + expsk (ask+nsk+ovk,
/// 96) + dk(32) = 169. Matches the length already confirmed for zcashd's
/// `sapzkey` record in `zcashd::plaintext`.
const EXTSK_LEN: usize = 169;

/// `ExtendedFullViewingKey` has the identical shape with ak/nk/ovk in
/// place of ask/nsk/ovk, so it serializes to the same 169 bytes. Always
/// present in a `WalletZKey` (unlike `extsk`, it is not `Optional`); we
/// only need its length to skip over it.
const EXTFVK_LEN: usize = 169;

/// Orchard `FullViewingKey::to_bytes()` length (ak/nk/rivk, 32 bytes
/// each), from `zcash/orchard`'s `keys.rs`.
const ORCHARD_FVK_LEN: usize = 96;

const ENC_SEED_LEN: usize = 48;
const SEED_LEN: usize = 32;
const TRANSPARENT_SECRET_LEN: usize = 32;

/// XSalsa20-Poly1305 (libsodium `secretbox`) nonce length.
const NONCE_LEN: usize = 24;

fn unreadable(msg: impl Into<String>) -> ImportError {
    ImportError::UnwalkableBtree(msg.into())
}

/// Per-record ciphertext on an individual locked `zkey`/`tkey` entry
/// (`enc_key` + its own `nonce`) is a distinct, still-unimplemented
/// scheme from the whole-wallet `enc_seed` this module now decrypts — see
/// the module docs. These entries keep surfacing as diagnostics.
fn decryption_not_supported(record_type: &str) -> ImportDiagnostic {
    ImportDiagnostic::DecryptionFailed {
        record_type: record_type.to_owned(),
        reason: "ZecWallet Lite's per-key libsodium ciphertext is not supported by this build; \
                 this key is only recoverable from the wallet's decrypted seed, via HD \
                 re-derivation"
            .to_owned(),
    }
}

/// ZWL's key-derivation function: unsalted double-SHA-256 over the raw
/// passphrase bytes. See the module docs for why that is worth flagging.
fn double_sha256(passphrase: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(passphrase);
    Sha256::digest(first).into()
}

/// Decrypt `enc_seed` into raw BIP-39 entropy.
///
/// Returns `Err(())` on any failure — a malformed nonce or a Poly1305
/// authentication failure alike — leaving the caller to translate that
/// into `ImportError::WrongPassphrase`, since a wrong passphrase is the
/// overwhelmingly likely cause of either.
fn decrypt_seed(
    enc_seed: &[u8; ENC_SEED_LEN],
    nonce: &[u8],
    passphrase: &SecretString,
) -> Result<[u8; SEED_LEN], ()> {
    let nonce_bytes: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| ())?;
    let key_bytes = double_sha256(passphrase.expose_secret().as_bytes());

    let cipher = XSalsa20Poly1305::new(&key_bytes.into());
    let plaintext = cipher
        .decrypt(&SecretboxNonce::from(nonce_bytes), enc_seed.as_slice())
        .map_err(|_| ())?;

    plaintext.try_into().map_err(|_| ())
}

/// Minimal, bounds-checked cursor over attacker-controlled bytes.
///
/// Every read returns `None` on truncation or an unrecognized shape,
/// rather than panicking or guessing. Callers above the fixed `Keys`
/// header treat a `None` as "stop here, keep whatever was already
/// collected" — see the module-level partial-recovery note.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u32_le(&mut self) -> Option<u32> {
        let arr: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(arr))
    }

    fn u64_le(&mut self) -> Option<u64> {
        let arr: [u8; 8] = self.take(8)?.try_into().ok()?;
        Some(u64::from_le_bytes(arr))
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    /// Bitcoin-style CompactSize, the same encoding already implemented
    /// for zcashd record keys.
    fn compact_size(&mut self) -> Option<u64> {
        let (value, consumed) = crate::zcashd::records::compact_size(self.bytes.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(consumed)?;
        Some(value)
    }

    /// `zcash_encoding::Vector::read`: a CompactSize count, then that many
    /// elements decoded by `read`.
    fn vector<T>(&mut self, mut read: impl FnMut(&mut Self) -> Option<T>) -> Option<Vec<T>> {
        let count = self.compact_size()?;
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(read(self)?);
        }
        Some(out)
    }

    /// A `Vec<u8>` written as `Vector::write(w, bytes, |w, b| ...)`, i.e.
    /// CompactSize-prefixed.
    fn vector_bytes(&mut self) -> Option<Vec<u8>> {
        let count = self.compact_size()?;
        Some(self.take(usize::try_from(count).ok()?)?.to_vec())
    }

    /// `zcash_encoding::Optional::read`: a single flag byte (0 = absent,
    /// 1 = present), then the value if present. Any other flag byte value
    /// is non-canonical and treated as a parse failure.
    fn optional<T>(&mut self, read: impl FnOnce(&mut Self) -> Option<T>) -> Option<Option<T>> {
        match self.u8()? {
            0 => Some(None),
            1 => read(self).map(Some),
            _ => None,
        }
    }

    /// ZWL address strings (`WalletTKey::read`'s `address` field): a
    /// plain little-endian `u64` byte length, NOT CompactSize like
    /// `Vector`. The bytes are discarded — this crate does not retain
    /// addresses, only key material.
    fn skip_zwl_string(&mut self) -> Option<()> {
        let len = self.u64_le()?;
        self.skip(usize::try_from(len).ok()?)
    }
}

/// The fixed-shape prefix of `Keys::read`, up through the plaintext
/// `seed` slot.
struct KeysHeader {
    keys_version: u64,
    encrypted: bool,
    enc_seed: [u8; ENC_SEED_LEN],
    nonce: Vec<u8>,
}

fn read_keys_header(cur: &mut Cursor) -> Option<KeysHeader> {
    let keys_version = cur.u64_le()?;
    if keys_version > MAX_SUPPORTED_KEYS_VERSION {
        // An internal version this build has never seen: same risk as an
        // unrecognized external_version (wrong parse over silent
        // misread), but treated as a stop-here rather than a hard error,
        // since we cannot tell truncation apart from a genuinely newer
        // shape at this point without more information than we have.
        return None;
    }
    let encrypted = cur.u8()? > 0;
    let enc_seed = cur.array::<ENC_SEED_LEN>()?;
    let nonce = cur.vector_bytes()?;
    cur.skip(SEED_LEN)?;
    Some(KeysHeader {
        keys_version,
        encrypted,
        enc_seed,
        nonce,
    })
}

enum ZKeyEntry {
    /// A usable Sapling extended spending key.
    Recovered(SaplingKey),
    /// The spending key exists but was omitted from the file because the
    /// wallet was locked at write time. Recoverable only with a working
    /// decryption path, which this build does not yet have.
    Locked,
    /// A view-key-only entry (`WalletZKeyType::ImportedViewKey`, or an
    /// unrecognized key type). No spending key was ever present here —
    /// this is not a failure.
    NoSpendingKey,
}

/// Read one `WalletZKey`. Field order confirmed against `WalletZKey::read`
/// in `zingolabs/zewif-zwl`'s `src/walletzkey.rs`.
fn read_zkey(cur: &mut Cursor) -> Option<ZKeyEntry> {
    cur.u8()?; // per-record serialization version, not gated here
    let keytype = cur.u32_le()?;
    cur.u8()?; // locked flag: redundant with extsk's Optional presence below
    let extsk = cur.optional(|c| c.array::<EXTSK_LEN>())?;
    cur.skip(EXTFVK_LEN)?; // extfvk: always present, not retained
    cur.optional(|c| c.u32_le())?; // hdkey_num
    cur.optional(Cursor::vector_bytes)?; // enc_key
    cur.optional(Cursor::vector_bytes)?; // nonce

    let provenance = match keytype {
        0 => Provenance::HdDerived,                 // WalletZKeyType::HdKey
        1 => Provenance::Standalone,                // WalletZKeyType::ImportedSpendingKey
        2 => return Some(ZKeyEntry::NoSpendingKey), // ImportedViewKey
        // Unrecognized discriminant: continuing would mean guessing at a
        // shape we do not know, exactly the risk this crate refuses to
        // take elsewhere (see zcashd::plaintext's DER header check).
        _ => return None,
    };

    Some(match extsk {
        Some(bytes) => ZKeyEntry::Recovered(SaplingKey {
            extsk: Secret::new(bytes.to_vec()),
            provenance,
        }),
        None => ZKeyEntry::Locked,
    })
}

enum TKeyEntry {
    Recovered(TransparentKey),
    Locked,
}

/// Read one `WalletTKey` in the post-version-20 shape. Field order
/// confirmed against `WalletTKey::read` in `src/wallettkey.rs`.
fn read_tkey(cur: &mut Cursor) -> Option<TKeyEntry> {
    cur.u8()?; // per-record serialization version
    let keytype = cur.u32_le()?;
    cur.u8()?; // locked flag: redundant with key's Optional presence below
    let key = cur.optional(|c| c.array::<TRANSPARENT_SECRET_LEN>())?;
    cur.skip_zwl_string()?; // t-address, not retained
    cur.optional(|c| c.u32_le())?; // hdkey_num
    cur.optional(Cursor::vector_bytes)?; // enc_key
    cur.optional(Cursor::vector_bytes)?; // nonce

    let provenance = match keytype {
        0 => Provenance::HdDerived,  // WalletTKeyType::HdKey
        1 => Provenance::Standalone, // WalletTKeyType::ImportedKey
        _ => return None,
    };

    Some(match key {
        Some(secret) => TKeyEntry::Recovered(TransparentKey {
            secret: Secret::new(secret),
            provenance,
        }),
        None => TKeyEntry::Locked,
    })
}

/// Skip one `WalletOKey` (Orchard). `ImportedKeys` has no Orchard variant
/// yet, so this only needs to advance the cursor correctly to keep the
/// `zkeys`/`tkeys` vectors that follow aligned — nothing is extracted.
/// Field order confirmed against `WalletOKey::read` in
/// `src/walletokey.rs`.
fn skip_okey(cur: &mut Cursor) -> Option<()> {
    cur.u8()?; // per-record serialization version
    cur.u32_le()?; // keytype
    cur.u8()?; // locked flag
    cur.optional(|c| c.u32_le())?; // hdkey_num
    cur.skip(ORCHARD_FVK_LEN)?; // fvk: always present
    cur.optional(|c| c.array::<32>())?; // sk
    cur.optional(Cursor::vector_bytes)?; // enc_key
    cur.optional(Cursor::vector_bytes)?; // nonce
    Some(())
}

/// Read `okeys` (if the `Keys` version supports them), `zkeys`, and
/// `tkeys`, pushing recovered key material into `out`. Returns `None` on
/// the first truncated or unrecognized field; the caller treats that as
/// "stop here", not an error — whatever was pushed into `out` before that
/// point is kept.
fn read_key_vectors(cur: &mut Cursor, keys_version: u64, out: &mut ImportedKeys) -> Option<()> {
    if keys_version > 21 {
        let count = cur.compact_size()?;
        for _ in 0..count {
            skip_okey(cur)?;
        }
        // `ImportedKeys` has no Orchard variant yet, so these records are
        // dropped rather than recovered. Unlike a locked zkey/tkey (which
        // at least leaves a diagnostic per entry), a purely-Orchard wallet
        // would otherwise report `is_empty() == true` with an empty
        // diagnostics list — indistinguishable from a wallet that never
        // held funds. `keys.rs`'s contract is that diagnostics must never
        // be empty silently, so record what was skipped, without leaking
        // any key material.
        if count > 0 {
            out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                record_type: "zwl-okey".to_owned(),
                reason: format!(
                    "{count} Orchard key record(s) skipped: Orchard is not yet \
                     supported by this wallet-recovery tool"
                ),
            });
        }
    }

    let zkeys = cur.vector(|c| read_zkey(c))?;
    for entry in zkeys {
        match entry {
            ZKeyEntry::Recovered(k) => out.sapling.push(k),
            ZKeyEntry::Locked => out.diagnostics.push(decryption_not_supported("zwl-zkey")),
            ZKeyEntry::NoSpendingKey => {}
        }
    }

    if keys_version <= 20 {
        // Pre-encryption-support layout: a flat vector of raw 32-byte
        // secp256k1 secrets, then a parallel vector of address strings —
        // no per-key locked/Optional wrapper at all. Confirmed against
        // the `version <= 20` arm of `Keys::read` in `src/keys.rs`. This
        // shape predates ZWL's wallet-encryption feature, so trusting
        // these bytes directly (as the reference implementation itself
        // does, unconditionally) is safe in the cases that shape actually
        // occurs in.
        let secrets = cur.vector(|c| c.array::<TRANSPARENT_SECRET_LEN>())?;
        let address_count = cur.compact_size()?;
        for _ in 0..address_count {
            cur.skip_zwl_string()?;
        }
        for secret in secrets {
            out.transparent.push(TransparentKey {
                secret: Secret::new(secret),
                provenance: Provenance::HdDerived,
            });
        }
    } else {
        let tkeys = cur.vector(|c| read_tkey(c))?;
        for entry in tkeys {
            match entry {
                TKeyEntry::Recovered(k) => out.transparent.push(k),
                TKeyEntry::Locked => out.diagnostics.push(decryption_not_supported("zwl-tkey")),
            }
        }
    }

    Some(())
}

/// Parse a ZecWallet Lite wallet file.
///
/// Takes a passphrase because ZWL wallets carry their own `encrypted`
/// flag: an encrypted wallet with no passphrase refuses outright, the
/// same contract `zcashd::import_zcashd` uses for a locked wallet. When a
/// passphrase is supplied to an encrypted wallet, `enc_seed` is decrypted
/// into a BIP-39 mnemonic (`ImportedKeys::mnemonic`) — see the module
/// docs for why that, not flat keys, is what decryption yields here. A
/// Poly1305 authentication failure on that decryption is reported as
/// `ImportError::WrongPassphrase`, since a wrong passphrase is by far the
/// most likely cause and is the actionable message for the user.
/// Individual locked `zkey`/`tkey` entries — a different, per-record
/// ciphertext this module still does not decrypt — keep surfacing as
/// diagnostics rather than being silently dropped.
pub fn import_zwl(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let mut cur = Cursor::new(bytes);

    let external_version = cur
        .u64_le()
        .ok_or_else(|| unreadable("file is too short to contain a ZWL version"))?;

    if external_version > MAX_SUPPORTED_VERSION {
        return Err(unreadable(format!(
            "ZecWallet Lite wallet version {external_version} is newer than this build \
             understands (max {MAX_SUPPORTED_VERSION})"
        )));
    }

    let mut out = ImportedKeys::default();

    if external_version < MIN_KEYS_READ_EXTERNAL_VERSION {
        return Ok(out);
    }

    let Some(header) = read_keys_header(&mut cur) else {
        // Truncated or an unrecognized internal Keys version: partial
        // recovery applies, same as everywhere else past this point.
        return Ok(out);
    };

    if header.encrypted {
        let Some(pass) = passphrase else {
            return Err(ImportError::WrongPassphrase);
        };
        match decrypt_seed(&header.enc_seed, &header.nonce, pass) {
            Ok(entropy) => match Mnemonic::<English>::from_entropy(entropy.to_vec()) {
                Ok(mnemonic) => out.mnemonic = Some(SecretString::new(mnemonic.into_phrase())),
                Err(_) => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                    record_type: "zwl-seed".to_owned(),
                    reason: "decrypted seed is not a valid BIP-39 entropy length".to_owned(),
                }),
            },
            // Authentication failure on the seed is fatal, not a
            // per-record diagnostic: it means the passphrase is wrong for
            // the whole wallet, the same contract zcashd's
            // `derive_master_key` uses for its master key.
            Err(()) => return Err(ImportError::WrongPassphrase),
        }
    }

    // Best-effort from here: `None` means "stop parsing", not an error.
    let _ = read_key_vectors(&mut cur, header.keys_version, &mut out);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(version: u64, body: &[u8]) -> Vec<u8> {
        let mut v = version.to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    // --- byte-stream builders, matching the confirmed reference encoding ---

    fn cs(n: u64) -> Vec<u8> {
        assert!(
            n < 0xfd,
            "test helper only handles small CompactSize values"
        );
        vec![n as u8]
    }

    fn opt_none() -> Vec<u8> {
        vec![0]
    }

    fn opt_some(mut data: Vec<u8>) -> Vec<u8> {
        let mut v = vec![1];
        v.append(&mut data);
        v
    }

    fn vec_bytes(data: &[u8]) -> Vec<u8> {
        let mut v = cs(data.len() as u64);
        v.extend_from_slice(data);
        v
    }

    fn zwl_string(s: &str) -> Vec<u8> {
        let mut v = (s.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn u32le(n: u32) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    /// Builds a `Keys`-struct body (everything after `external_version`)
    /// for an unencrypted wallet: `keys_version` header, then whatever
    /// `zkeys`/`tkeys`/`okeys` bytes the caller supplies.
    fn keys_body(keys_version: u64, encrypted: bool, key_vectors: &[u8]) -> Vec<u8> {
        keys_body_with_seed(
            keys_version,
            encrypted,
            &[0u8; ENC_SEED_LEN],
            &[],
            key_vectors,
        )
    }

    /// As `keys_body`, but with caller-supplied `enc_seed`/`nonce` bytes —
    /// needed to exercise real seed decryption.
    fn keys_body_with_seed(
        keys_version: u64,
        encrypted: bool,
        enc_seed: &[u8],
        nonce: &[u8],
        key_vectors: &[u8],
    ) -> Vec<u8> {
        assert_eq!(enc_seed.len(), ENC_SEED_LEN, "test helper misuse");
        let mut v = keys_version.to_le_bytes().to_vec();
        v.push(u8::from(encrypted));
        v.extend_from_slice(enc_seed);
        v.extend_from_slice(&vec_bytes(nonce)); // nonce
        v.extend_from_slice(&[0u8; SEED_LEN]); // plaintext seed slot, unused when encrypted
        v.extend_from_slice(key_vectors);
        v
    }

    /// Encrypt `entropy` the way ZWL does: unsalted double-SHA-256 of the
    /// passphrase as the `secretbox` key, `nonce_bytes` as the nonce.
    /// Independent of `decrypt_seed` — this is what makes the round-trip
    /// test below meaningful rather than circular.
    fn encrypt_test_seed(
        passphrase: &str,
        entropy: &[u8; SEED_LEN],
        nonce_bytes: [u8; NONCE_LEN],
    ) -> ([u8; ENC_SEED_LEN], [u8; NONCE_LEN]) {
        use sha2::{Digest, Sha256};

        let first = Sha256::digest(passphrase.as_bytes());
        let key_bytes: [u8; 32] = Sha256::digest(first).into();

        let cipher = XSalsa20Poly1305::new(&key_bytes.into());
        let ciphertext = cipher
            .encrypt(&SecretboxNonce::from(nonce_bytes), entropy.as_slice())
            .expect("encryption of a well-formed test payload cannot fail");

        (
            ciphertext.try_into().expect("ciphertext must be 48 bytes"),
            nonce_bytes,
        )
    }

    fn zkey_hd(extsk_byte: u8) -> Vec<u8> {
        let mut v = vec![1u8]; // record version
        v.extend_from_slice(&u32le(0)); // keytype = HdKey
        v.push(0); // locked = false
        v.extend_from_slice(&opt_some(vec![extsk_byte; EXTSK_LEN])); // extsk
        v.extend_from_slice(&[0u8; EXTFVK_LEN]); // extfvk
        v.extend_from_slice(&opt_some(u32le(0))); // hdkey_num
        v.extend_from_slice(&opt_none()); // enc_key
        v.extend_from_slice(&opt_none()); // nonce
        v
    }

    fn zkey_locked() -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(0)); // keytype = HdKey
        v.push(1); // locked = true
        v.extend_from_slice(&opt_none()); // extsk: omitted while locked
        v.extend_from_slice(&[0u8; EXTFVK_LEN]);
        v.extend_from_slice(&opt_some(u32le(0)));
        v.extend_from_slice(&opt_some(vec_bytes(&[0xAA; 80]))); // enc_key ciphertext
        v.extend_from_slice(&opt_some(vec_bytes(&[0xBB; 24]))); // nonce
        v
    }

    fn zkey_view_only() -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(2)); // keytype = ImportedViewKey
        v.push(0);
        v.extend_from_slice(&opt_none()); // no spending key, ever
        v.extend_from_slice(&[0u8; EXTFVK_LEN]);
        v.extend_from_slice(&opt_none());
        v.extend_from_slice(&opt_none());
        v.extend_from_slice(&opt_none());
        v
    }

    fn tkey_hd(secret_byte: u8) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(0)); // keytype = HdKey
        v.push(0); // locked = false
        v.extend_from_slice(&opt_some(vec![secret_byte; TRANSPARENT_SECRET_LEN])); // key
        v.extend_from_slice(&zwl_string("t1TestAddress"));
        v.extend_from_slice(&opt_some(u32le(0))); // hdkey_num
        v.extend_from_slice(&opt_none()); // enc_key
        v.extend_from_slice(&opt_none()); // nonce
        v
    }

    fn tkey_locked() -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(0));
        v.push(1); // locked = true
        v.extend_from_slice(&opt_none()); // key: omitted while locked
        v.extend_from_slice(&zwl_string("t1LockedAddress"));
        v.extend_from_slice(&opt_some(u32le(0)));
        v.extend_from_slice(&opt_some(vec_bytes(&[0xCC; 48])));
        v.extend_from_slice(&opt_some(vec_bytes(&[0xDD; 24])));
        v
    }

    fn okey_stub() -> Vec<u8> {
        let mut v = vec![1u8]; // record version
        v.extend_from_slice(&u32le(0)); // keytype
        v.push(0); // locked
        v.extend_from_slice(&opt_some(u32le(0))); // hdkey_num
        v.extend_from_slice(&[0u8; ORCHARD_FVK_LEN]); // fvk
        v.extend_from_slice(&opt_none()); // sk
        v.extend_from_slice(&opt_none()); // enc_key
        v.extend_from_slice(&opt_none()); // nonce
        v
    }

    // --- the tests specified by the task brief ---

    #[test]
    fn rejects_a_version_newer_than_we_understand() {
        let err = import_zwl(&wallet(999, &[]), None).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_file_with_no_version_word() {
        let err = import_zwl(&[0u8; 3], None).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn reads_the_version_of_a_supported_wallet() {
        // An empty body yields no keys but must not be an error: partial
        // recovery applies here too.
        let keys = import_zwl(&wallet(25, &[0x00]), None).unwrap();
        assert!(keys.is_empty());
    }

    // --- round-trip tests against the confirmed layout ---

    #[test]
    fn recovers_a_sapling_and_a_transparent_key_from_an_unencrypted_wallet() {
        // keys_version 21: no okeys vector at all (only present > 21).
        let mut vectors = cs(1);
        vectors.extend_from_slice(&zkey_hd(0xEF));
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&tkey_hd(0xAB));

        let body = keys_body(21, false, &vectors);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();

        assert_eq!(keys.sapling.len(), 1);
        assert_eq!(keys.sapling[0].extsk.expose_secret(), &[0xEF; EXTSK_LEN]);
        assert_eq!(keys.sapling[0].provenance, Provenance::HdDerived);

        assert_eq!(keys.transparent.len(), 1);
        assert_eq!(
            keys.transparent[0].secret.expose_secret(),
            &[0xAB; TRANSPARENT_SECRET_LEN]
        );
        assert_eq!(keys.transparent[0].provenance, Provenance::HdDerived);
        assert!(keys.diagnostics.is_empty());
    }

    #[test]
    fn recovers_keys_when_okeys_are_present_at_a_newer_keys_version() {
        // keys_version 22 turns on the okeys vector ahead of zkeys/tkeys.
        // Orchard key material is skipped (ImportedKeys has no Orchard
        // field yet), but the sapling/transparent keys after it must
        // still parse correctly — this is the check that the skip
        // advances exactly the right number of bytes.
        let mut vectors = cs(1);
        vectors.extend_from_slice(&okey_stub());
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&zkey_hd(0x11));
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&tkey_hd(0x22));

        let body = keys_body(22, false, &vectors);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();

        assert_eq!(keys.sapling.len(), 1);
        assert_eq!(keys.sapling[0].extsk.expose_secret(), &[0x11; EXTSK_LEN]);
        assert_eq!(keys.transparent.len(), 1);
        assert_eq!(
            keys.transparent[0].secret.expose_secret(),
            &[0x22; TRANSPARENT_SECRET_LEN]
        );
    }

    #[test]
    fn a_wallet_with_only_orchard_keys_reports_a_diagnostic_instead_of_looking_empty() {
        // A post-NU5 ZWL wallet whose funds are entirely Orchard-derived
        // has no sapling or transparent keys at all. `ImportedKeys` has no
        // Orchard field, so `is_empty()` would read `true` here — the
        // diagnostics list is the only signal the caller has that
        // anything was actually skipped, and `keys.rs`'s own contract is
        // that diagnostics must never be empty silently.
        let mut vectors = cs(1);
        vectors.extend_from_slice(&okey_stub());
        vectors.extend_from_slice(&cs(0)); // zkeys: none
        vectors.extend_from_slice(&cs(0)); // tkeys: none

        let body = keys_body(22, false, &vectors);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();

        assert!(keys.sapling.is_empty());
        assert!(keys.transparent.is_empty());
        assert!(
            !keys.diagnostics.is_empty(),
            "a wallet holding only Orchard keys must not report as silently empty"
        );
    }

    #[test]
    fn recovers_a_transparent_key_from_the_pre_version_20_legacy_layout() {
        let mut vectors = cs(0); // zkeys: none
        vectors.extend_from_slice(&cs(1)); // one legacy secret
        vectors.extend_from_slice(&[0x33; TRANSPARENT_SECRET_LEN]);
        vectors.extend_from_slice(&cs(1)); // one legacy address
        vectors.extend_from_slice(&zwl_string("t1Legacy"));

        let body = keys_body(20, false, &vectors);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();

        assert_eq!(keys.transparent.len(), 1);
        assert_eq!(
            keys.transparent[0].secret.expose_secret(),
            &[0x33; TRANSPARENT_SECRET_LEN]
        );
        assert_eq!(keys.transparent[0].provenance, Provenance::HdDerived);
    }

    #[test]
    fn a_view_only_zkey_yields_no_key_and_no_diagnostic() {
        // keys_version 21: no okeys vector at all (only present > 21).
        let mut vectors = cs(1);
        vectors.extend_from_slice(&zkey_view_only());
        vectors.extend_from_slice(&cs(0)); // tkeys

        let body = keys_body(21, false, &vectors);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();
        assert!(keys.sapling.is_empty());
        assert!(keys.diagnostics.is_empty());
    }

    #[test]
    fn refuses_an_encrypted_wallet_without_a_passphrase() {
        // keys_version 21: no okeys vector; just empty zkeys/tkeys.
        let vectors = [cs(0), cs(0)].concat();
        let body = keys_body(21, true, &vectors);
        let bytes = wallet(25, &body);

        let err = import_zwl(&bytes, None).unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn an_encrypted_wallet_with_a_passphrase_reports_locked_keys_as_diagnostics() {
        // The seed decrypts fine (a correct passphrase), but individual
        // locked zkey/tkey entries carry their own, still-unimplemented
        // per-record ciphertext — see the module docs. A passphrase must
        // not make those look recovered: every locked entry has to show
        // up as a diagnostic, never a fabricated key.
        // keys_version 21: no okeys vector at all (only present > 21).
        let mut vectors = cs(1);
        vectors.extend_from_slice(&zkey_locked());
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&tkey_locked());

        let entropy = [0x7A; SEED_LEN];
        let (enc_seed, nonce) = encrypt_test_seed("whatever", &entropy, [0x24; NONCE_LEN]);
        let body = keys_body_with_seed(21, true, &enc_seed, &nonce, &vectors);
        let bytes = wallet(25, &body);

        let pass = SecretString::new("whatever".to_owned());
        let keys = import_zwl(&bytes, Some(&pass)).unwrap();

        assert!(keys.sapling.is_empty(), "no fabricated sapling key");
        assert!(keys.transparent.is_empty(), "no fabricated transparent key");
        assert_eq!(keys.diagnostics.len(), 2);
        assert!(
            keys.mnemonic.is_some(),
            "the whole-wallet seed still decrypts even though these two keys don't"
        );
    }

    #[test]
    fn recovers_a_mnemonic_from_an_encrypted_seed() {
        // Round-trip against a synthetic header: encrypt known entropy
        // with ZWL's actual scheme (double_sha256 key, secretbox), then
        // confirm the parser recovers the matching mnemonic.
        let entropy = [0x11; SEED_LEN];
        let passphrase = "some passphrase";
        let (enc_seed, nonce) = encrypt_test_seed(passphrase, &entropy, [0x99; NONCE_LEN]);

        let vectors = [cs(0), cs(0)].concat(); // empty zkeys, empty tkeys
        let body = keys_body_with_seed(21, true, &enc_seed, &nonce, &vectors);
        let bytes = wallet(25, &body);

        let pass = SecretString::new(passphrase.to_owned());
        let keys = import_zwl(&bytes, Some(&pass)).unwrap();

        let expected = Mnemonic::<English>::from_entropy(entropy.to_vec())
            .unwrap()
            .into_phrase();
        assert_eq!(keys.mnemonic.as_ref().unwrap().expose_secret(), &expected);
        assert!(keys.transparent.is_empty() && keys.sapling.is_empty());
        assert!(
            !keys.is_empty(),
            "a recovered mnemonic alone must count as non-empty"
        );
    }

    #[test]
    fn a_wrong_passphrase_on_an_encrypted_seed_is_reported_as_wrong_passphrase() {
        let entropy = [0x22; SEED_LEN];
        let (enc_seed, nonce) =
            encrypt_test_seed("correct passphrase", &entropy, [0x55; NONCE_LEN]);

        let vectors = [cs(0), cs(0)].concat();
        let body = keys_body_with_seed(21, true, &enc_seed, &nonce, &vectors);
        let bytes = wallet(25, &body);

        let wrong = SecretString::new("wrong passphrase".to_owned());
        let err = import_zwl(&bytes, Some(&wrong)).unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn an_unrecognized_keys_version_recovers_nothing_rather_than_guessing() {
        let body = keys_body(MAX_SUPPORTED_KEYS_VERSION + 1, false, &[]);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn a_pre_version_15_file_recovers_nothing_rather_than_guessing() {
        let bytes = wallet(14, &[0xFF; 32]);
        let keys = import_zwl(&bytes, None).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn a_truncated_key_vector_keeps_keys_already_recovered() {
        // keys_version 21: no okeys vector at all (only present > 21).
        let mut vectors = cs(1);
        vectors.extend_from_slice(&zkey_hd(0x44));
        // Claim two tkeys but supply only one, truncating mid-vector.
        vectors.extend_from_slice(&cs(2));
        vectors.extend_from_slice(&tkey_hd(0x55));

        let body = keys_body(21, false, &vectors);
        let bytes = wallet(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();
        assert_eq!(keys.sapling.len(), 1, "the fully-read zkey must survive");
        assert!(
            keys.transparent.is_empty(),
            "a truncated tkey vector must not fabricate a partial key"
        );
    }
}
