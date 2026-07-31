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
//! `external_version`, and an encrypted wallet with no passphrase.
//!
//! ZWL never held Sprout keys, so nothing here contributes to sub-spec 3.
//!
//! **Encryption is detected but not yet decrypted.** ZWL encrypts with a
//! libsodium `secretbox` (XSalsa20-Poly1305), a different primitive than
//! zcashd's AES-256-CBC master key scheme this crate already implements
//! for `zcashd::crypto`. Adding that cipher — plus, for HD-derived keys,
//! a BIP-39 mnemonic and Sapling/Orchard zip32 re-derivation, since a
//! locked wallet's HD key material isn't in the file at all, only the
//! encrypted seed is — is out of scope for this task. A locked wallet
//! with a passphrase supplied still refuses to fabricate keys: locked
//! entries are recorded as diagnostics, never silently dropped.
//!
//! **This is the least-validated code in the crate.** There is no real
//! ZWL wallet fixture to test against (unlike the zcashd path, which has
//! eight). The tests below are round-trips against hand-built byte
//! streams that follow the confirmed reference layout — they prove the
//! parser reads back what it was given, not that the layout matches every
//! real-world ZWL wallet on disk.

use secrecy::{Secret, SecretString};

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

fn unreadable(msg: impl Into<String>) -> ImportError {
    ImportError::UnwalkableBtree(msg.into())
}

fn decryption_not_supported(record_type: &str) -> ImportDiagnostic {
    ImportDiagnostic::DecryptionFailed {
        record_type: record_type.to_owned(),
        reason: "ZecWallet Lite's libsodium-based key encryption is not yet supported by this \
                 build"
            .to_owned(),
    }
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
    cur.skip(ENC_SEED_LEN)?;
    cur.vector_bytes()?; // nonce
    cur.skip(SEED_LEN)?;
    Some(KeysHeader {
        keys_version,
        encrypted,
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
/// same contract `zcashd::import_zcashd` uses for a locked wallet.
/// Decryption itself is not implemented yet (see the module docs) — a
/// passphrase-bearing call to an encrypted wallet still succeeds, but
/// recovers only whatever key material the file happens to hold
/// unencrypted, and reports every locked entry as a diagnostic rather
/// than silently omitting it.
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

    if header.encrypted && passphrase.is_none() {
        return Err(ImportError::WrongPassphrase);
    }

    // Best-effort from here: `None` means "stop parsing", not an error.
    let _ = read_key_vectors(&mut cur, header.keys_version, &mut out);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

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
        let mut v = keys_version.to_le_bytes().to_vec();
        v.push(u8::from(encrypted));
        v.extend_from_slice(&[0u8; 48]); // enc_seed
        v.extend_from_slice(&cs(0)); // nonce: empty
        v.extend_from_slice(&[0u8; 32]); // seed
        v.extend_from_slice(key_vectors);
        v
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
        // Decryption is not implemented (see module docs): a passphrase
        // must not make locked entries look recovered. Every locked
        // entry has to show up as a diagnostic, never a fabricated key.
        // keys_version 21: no okeys vector at all (only present > 21).
        let mut vectors = cs(1);
        vectors.extend_from_slice(&zkey_locked());
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&tkey_locked());

        let body = keys_body(21, true, &vectors);
        let bytes = wallet(25, &body);

        let pass = SecretString::new("whatever".to_owned());
        let keys = import_zwl(&bytes, Some(&pass)).unwrap();

        assert!(keys.sapling.is_empty(), "no fabricated sapling key");
        assert!(keys.transparent.is_empty(), "no fabricated transparent key");
        assert_eq!(keys.diagnostics.len(), 2);
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
