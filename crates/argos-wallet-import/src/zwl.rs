//! ZecWallet Lite wallet file reader.
//!
//! Unlike zcashd, ZWL uses a custom length-prefixed serialization with no
//! magic number and no Berkeley DB involvement. The file opens with a
//! little-endian u64 `external_version`, followed by a `Keys` struct that
//! carries its own, separate version word.
//!
//! Layout confirmed against the upstream writer, `zingolabs/zwl-lib` (MIT;
//! `lib/src/lightwallet.rs` `LightWallet::read`/`write` and
//! `lib/src/lightwallet/{keys,walletokey,walletzkey,wallettkey}.rs`).
//! `zingolabs/zewif-zwl` is not used as a reference: it carries no licence.
//!
//! ```text
//! u64            external_version      (zwl-lib writes 25; accepted through 31)
//! Keys:
//!   u64          keys version          (its own version word; max known: 22,
//!                                       Keys::serialized_version in zwl-lib)
//!   u8           encrypted flag
//!   [u8; 48]     enc_seed              (encrypted seed when locked)
//!   Vector<u8>   nonce
//!   [u8; 32]     seed                  (plaintext seed; zero when locked)
//!   Vector<WalletOKey>  okeys          (only when keys version > 21)
//!   Vector<WalletZKey>  zkeys
//!   Vector<WalletTKey>  tkeys          (only when keys version > 20; older
//!                                      versions use a flat secret-key +
//!                                      address-string pair of vectors)
//! ... blocks and transactions — structurally skipped to reach the chain
//!     name; the versioned options, birthday, tree-state flags, and price
//!     info are bounded through EOF. Unsupported nonempty block, Sapling or
//!     Orchard note, and tree state is reported as incomplete.
//! ```
//!
//! `Vector`, `Optional`, and `CompactSize` above match
//! `zcash_encoding`'s encodings exactly (CompactSize count prefix for
//! `Vector`, a single 0/1 flag byte for `Optional`); this module
//! reimplements them directly rather than taking the dependency, the same
//! way `compact_size` in `zcashd::records` does for zcashd.
//!
//! A truncated or unrecognized shape stops parsing and returns any completed
//! key material with a damage diagnostic, so coverage cannot be Complete.
//! Only an unreadable external version and a missing or wrong passphrase are
//! fatal errors. Unsupported versions return a non-complete result.
//!
//! ZWL never held Sprout keys, so nothing here contributes to sub-spec 3.
//!
//! ## Encrypted wallets: one key for the seed and every imported key
//!
//! ZWL encrypts with a libsodium `secretbox` (XSalsa20-Poly1305), a
//! different primitive than zcashd's AES-256-CBC master key scheme this
//! crate already implements for `zcashd::crypto`. Confirmed against
//! `Keys::encrypt` in `zwl-lib`'s `lib/src/lightwallet/keys.rs`, and
//! `WalletZKey::encrypt` / `WalletTKey::encrypt` beside it:
//!
//! ```text
//! key     = double_sha256(passphrase)         // no salt, no work factor
//! seed    = secretbox_open(enc_seed, nonce, key)          // nonce in the header
//! imported zkey = secretbox_open(enc_key, its nonce, key) // 169-byte extsk
//! imported tkey = secretbox_open(enc_key, its nonce, key) // 32-byte secret
//! ```
//!
//! **The KDF is unsalted double-SHA-256 with no work factor.** That is
//! ZWL's design, not this crate's, but it means a ZWL passphrase is
//! brute-forceable at plain hashing speed — worth stating plainly since
//! this crate exists to handle wallets whose threat model includes that.
//!
//! ZWL stores no per-key ciphertext for its HD-derived keys: locking drops
//! them, and the wallet re-derives each from the seed on unlock. So for HD
//! keys decryption here produces a BIP-39 mnemonic
//! (`ImportedKeys::mnemonic`), not spending keys — zip32/Sapling/Orchard
//! re-derivation from that mnemonic belongs in `argos-core`, not in this
//! deliberately minimal, network-free leaf crate. Imported keys exist in no
//! seed, so `encrypt` seals each one into its record's `enc_key` under the
//! same wallet key; those are opened here and accepted only if they match
//! the extended full viewing key or address stored beside them, exactly as
//! a plaintext record is. One that does not open is a per-record
//! `DecryptionFailed`, never a fabricated key.
//!
//! The network parser is checked against three deterministic, no-funds
//! wallets written by the upstream ZWL writer, including one with nonempty
//! transaction metadata. There is no public no-funds writer fixture here
//! containing a CompactBlockData or Sapling/Orchard note. These shapes stay
//! incomplete until a writer-produced fixture verifies their layout. The
//! older key/decryption tests below still use hand-built streams, so they do
//! not establish compatibility with every historical wallet layout.

use bip0039::{English, Mnemonic};
use crypto_secretbox::{aead::Aead, KeyInit, Nonce as SecretboxNonce, XSalsa20Poly1305};
use secrecy::{ExposeSecret, Secret, SecretString};
use sha2::{Digest, Sha256};

use crate::{
    error::{ImportDiagnostic, ImportError},
    identity,
    keys::{
        merge_embedded_network, unrecognized_network, EmbeddedNetwork, ImportedKeys, Provenance,
        SaplingKey, TransparentKey,
    },
};

/// Highest `external_version` this parser accepts. `zwl-lib`'s writer
/// (`LightWallet::serialized_version`) emits 25; every field whose shape
/// depends on the version is gated individually below. Refusing a newer
/// file is safer than misreading it: a wrong parse yields wrong keys
/// silently, which is worse than a clear failure.
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

/// A key whose spending authority is absent from the file: an HD key the
/// wallet dropped while locked (re-derivable only from the seed), or a
/// standalone key with no usable ciphertext.
fn locked_key(record_type: &str, provenance: Provenance) -> ImportDiagnostic {
    ImportDiagnostic::LockedKey {
        record_type: record_type.to_owned(),
        provenance,
    }
}

/// ZWL's key-derivation function: unsalted double-SHA-256 over the raw
/// passphrase bytes. See the module docs for why that is worth flagging.
/// The result is the one `secretbox` key for the whole wallet: it seals the
/// seed and every imported key alike (`Keys::encrypt` in `zwl-lib`).
fn wallet_key(passphrase: &SecretString) -> Secret<[u8; 32]> {
    let first = Sha256::digest(passphrase.expose_secret().as_bytes());
    Secret::new(Sha256::digest(first).into())
}

/// Open one `secretbox` sealed under the wallet key. `Err(())` on any
/// failure — a malformed nonce or a Poly1305 authentication failure alike.
/// The plaintext is wrapped at once so it is scrubbed when dropped.
fn open_sealed(
    key: &Secret<[u8; 32]>,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Secret<Vec<u8>>, ()> {
    let nonce_bytes: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| ())?;
    let cipher = XSalsa20Poly1305::new(&(*key.expose_secret()).into());
    cipher
        .decrypt(&SecretboxNonce::from(nonce_bytes), ciphertext)
        .map(Secret::new)
        .map_err(|_| ())
}

/// Decrypt `enc_seed` into raw BIP-39 entropy.
///
/// Returns `Err(())` on any failure, leaving the caller to translate that
/// into `ImportError::WrongPassphrase`, since a wrong passphrase is the
/// overwhelmingly likely cause.
fn decrypt_seed(
    enc_seed: &[u8; ENC_SEED_LEN],
    nonce: &[u8],
    key: &Secret<[u8; 32]>,
) -> Result<Secret<[u8; SEED_LEN]>, ()> {
    let plaintext = open_sealed(key, nonce, enc_seed)?;
    let entropy: [u8; SEED_LEN] = plaintext
        .expose_secret()
        .as_slice()
        .try_into()
        .map_err(|_| ())?;
    Ok(Secret::new(entropy))
}

/// Minimal, bounds-checked cursor over attacker-controlled bytes.
///
/// Every read returns a canonical byte coordinate and field on failure.
struct ZwlReadError {
    offset: usize,
    field: &'static str,
    reason: &'static str,
}
type ZwlReadResult<T> = Result<T, ZwlReadError>;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn error(&self, field: &'static str, reason: &'static str) -> ZwlReadError {
        ZwlReadError {
            offset: self.pos,
            field,
            reason,
        }
    }

    fn take(&mut self, n: usize, field: &'static str) -> ZwlReadResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| self.error(field, "value length limit exceeded"))?;
        let s = self.bytes.get(self.pos..end).ok_or(ZwlReadError {
            offset: self.bytes.len(),
            field,
            reason: "truncated field",
        })?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self, field: &'static str) -> ZwlReadResult<u8> {
        self.take(1, field)?
            .first()
            .copied()
            .ok_or_else(|| self.error(field, "truncated field"))
    }

    fn u32_le(&mut self, field: &'static str) -> ZwlReadResult<u32> {
        let arr: [u8; 4] = self
            .take(4, field)?
            .try_into()
            .map_err(|_| self.error(field, "truncated field"))?;
        Ok(u32::from_le_bytes(arr))
    }

    fn u64_le(&mut self, field: &'static str) -> ZwlReadResult<u64> {
        let arr: [u8; 8] = self
            .take(8, field)?
            .try_into()
            .map_err(|_| self.error(field, "truncated field"))?;
        Ok(u64::from_le_bytes(arr))
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> ZwlReadResult<[u8; N]> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| self.error(field, "truncated field"))
    }

    fn skip(&mut self, n: usize, field: &'static str) -> ZwlReadResult<()> {
        self.take(n, field).map(|_| ())
    }

    /// Bitcoin-style CompactSize, the same encoding already implemented
    /// for zcashd record keys.
    fn compact_size(&mut self, field: &'static str) -> ZwlReadResult<u64> {
        let (value, consumed) =
            crate::zcashd::records::compact_size(self.bytes.get(self.pos..).unwrap_or_default())
                .ok_or(ZwlReadError {
                    offset: self.bytes.len(),
                    field,
                    reason: "truncated field",
                })?;
        self.pos += consumed;
        Ok(value)
    }

    /// A `Vec<u8>` written as `Vector::write(w, bytes, |w, b| ...)`, i.e.
    /// CompactSize-prefixed.
    fn vector_bytes(&mut self, field: &'static str) -> ZwlReadResult<Vec<u8>> {
        let count = self.compact_size(field)?;
        let count =
            usize::try_from(count).map_err(|_| self.error(field, "value length limit exceeded"))?;
        Ok(self.take(count, field)?.to_vec())
    }

    /// `zcash_encoding::Optional::read`: a single flag byte (0 = absent,
    /// 1 = present), then the value if present. Any other flag byte value
    /// is non-canonical and treated as a parse failure.
    fn optional<T>(
        &mut self,
        field: &'static str,
        read: impl FnOnce(&mut Self) -> ZwlReadResult<T>,
    ) -> ZwlReadResult<Option<T>> {
        match self.u8(field)? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(self.error(field, "wallet structure could not be read")),
        }
    }

    /// ZWL address strings (`WalletTKey::read`'s `address` field): a
    /// plain little-endian `u64` byte length, NOT CompactSize like
    /// `Vector`. Return a borrowed slice for comparison with the key.
    fn zwl_string(&mut self) -> ZwlReadResult<&'a [u8]> {
        let len = self.u64_le("address")?;
        let len = usize::try_from(len)
            .map_err(|_| self.error("address", "value length limit exceeded"))?;
        self.take(len, "address")
    }
}

/// The fixed-shape prefix of `Keys::read`, up through the plaintext
/// `seed` slot.
struct KeysHeader {
    keys_version: u64,
    encrypted: bool,
    enc_seed: [u8; ENC_SEED_LEN],
    nonce: Vec<u8>,
    seed: [u8; SEED_LEN],
}

fn read_keys_header(cur: &mut Cursor) -> ZwlReadResult<KeysHeader> {
    let keys_version = cur.u64_le("keys_version")?;
    let encrypted = match cur.u8("header")? {
        0 => false,
        1 => true,
        _ => return Err(cur.error("header", "wallet structure could not be read")),
    };
    let enc_seed = cur.array::<ENC_SEED_LEN>("enc_seed")?;
    let nonce = cur.vector_bytes("nonce")?;
    let seed = cur.array::<SEED_LEN>("seed")?;
    Ok(KeysHeader {
        keys_version,
        encrypted,
        enc_seed,
        nonce,
        seed,
    })
}

enum ZKeyEntry {
    /// A usable Sapling extended spending key.
    Recovered(SaplingKey),
    /// The spending key is absent: an HD key the wallet dropped while
    /// locked, or a standalone key with no ciphertext to open.
    Locked(Provenance),
    /// A standalone key's per-record ciphertext did not open under the
    /// wallet key that opened the seed: the record is damaged.
    DecryptionFailed,
    /// A view-key-only entry (`WalletZKeyType::ImportedViewKey`, or an
    /// unrecognized key type). No spending key was ever present here —
    /// this is not a failure.
    NoSpendingKey,
    Mismatch,
}

/// A locked record's per-record ciphertext, present only on an imported
/// key in an encrypted wallet (`WalletZKey::encrypt` / `WalletTKey::encrypt`
/// in `zwl-lib`). HD keys are never sealed this way: the seed recreates them.
struct SealedKey {
    enc_key: Vec<u8>,
    nonce: Vec<u8>,
}

impl Drop for SealedKey {
    fn drop(&mut self) {
        use secrecy::Zeroize;
        self.enc_key.zeroize();
    }
}

fn sealed(enc_key: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> Option<SealedKey> {
    match (enc_key, nonce) {
        (Some(enc_key), Some(nonce)) => Some(SealedKey { enc_key, nonce }),
        (Some(mut enc_key), None) => {
            use secrecy::Zeroize;
            enc_key.zeroize();
            None
        }
        _ => None,
    }
}

/// Open a standalone key's ciphertext. `None` when there is nothing to open
/// (no ciphertext, or an unencrypted wallet with no key); `Some(Err)` when
/// the ciphertext does not open or opens to the wrong length.
fn open_standalone<const N: usize>(
    sealed: Option<SealedKey>,
    key: Option<&Secret<[u8; 32]>>,
) -> Option<Result<Secret<[u8; N]>, ()>> {
    let (sealed, key) = (sealed?, key?);
    Some(
        open_sealed(key, &sealed.nonce, &sealed.enc_key).and_then(|plain| {
            let bytes: [u8; N] = plain
                .expose_secret()
                .as_slice()
                .try_into()
                .map_err(|_| ())?;
            Ok(Secret::new(bytes))
        }),
    )
}

/// Read one `WalletZKey`, with its HD index when it has one. Field order
/// confirmed against `WalletZKey::read` in `zingolabs/zwl-lib`'s
/// `lib/src/lightwallet/walletzkey.rs`. `key` is the wallet key of an
/// encrypted wallet, used to open an imported key's sealed `enc_key`.
fn read_zkey(
    cur: &mut Cursor,
    key: Option<&Secret<[u8; 32]>>,
) -> ZwlReadResult<(ZKeyEntry, Option<u32>)> {
    cur.u8("zkey")?;
    let keytype = cur.u32_le("zkey")?;
    cur.u8("zkey")?;
    let extsk = cur.optional("zkey", |c| c.array::<EXTSK_LEN>("zkey"))?;
    let extfvk = cur.take(EXTFVK_LEN, "zkey")?;
    let hdkey_num = cur.optional("zkey", |c| c.u32_le("zkey"))?;
    let enc_key = cur.optional("zkey", |c| c.vector_bytes("zkey"))?;
    let nonce = cur.optional("zkey", |c| c.vector_bytes("zkey"))?;
    let sealed = sealed(enc_key, nonce);

    let provenance = match keytype {
        0 => Provenance::HdDerived,                       // WalletZKeyType::HdKey
        1 => Provenance::Standalone,                      // WalletZKeyType::ImportedSpendingKey
        2 => return Ok((ZKeyEntry::NoSpendingKey, None)), // ImportedViewKey
        // Unrecognized discriminant: continuing would mean guessing at a
        // shape we do not know, exactly the risk this crate refuses to
        // take elsewhere (see zcashd::plaintext's DER header check).
        _ => return Err(cur.error("zkey", "wallet structure could not be read")),
    };
    let hd_index = hdkey_num.filter(|_| provenance == Provenance::HdDerived);

    let recovered = |bytes: &[u8]| {
        if identity::sapling_matches_extfvk(bytes, extfvk) {
            ZKeyEntry::Recovered(SaplingKey {
                extsk: Secret::new(bytes.to_vec()),
                provenance,
                // ZWL stores no per-key creation time.
                created_at: None,
            })
        } else {
            ZKeyEntry::Mismatch
        }
    };
    let entry = match extsk {
        Some(bytes) => recovered(&bytes),
        None if provenance == Provenance::Standalone => {
            match open_standalone::<EXTSK_LEN>(sealed, key) {
                Some(Ok(bytes)) => recovered(bytes.expose_secret()),
                Some(Err(())) => ZKeyEntry::DecryptionFailed,
                None => ZKeyEntry::Locked(provenance),
            }
        }
        None => ZKeyEntry::Locked(provenance),
    };
    Ok((entry, hd_index))
}

enum TKeyEntry {
    Recovered(TransparentKey, EmbeddedNetwork),
    Locked(Provenance),
    DecryptionFailed,
    Mismatch,
}

/// Read one `WalletTKey` in the post-version-20 shape, with its HD index
/// when it has one. Field order confirmed against `WalletTKey::read` in
/// `zingolabs/zwl-lib`'s `lib/src/lightwallet/wallettkey.rs`.
fn read_tkey(
    cur: &mut Cursor,
    wallet_key: Option<&Secret<[u8; 32]>>,
) -> ZwlReadResult<(TKeyEntry, Option<u32>)> {
    cur.u8("tkey")?;
    let keytype = cur.u32_le("tkey")?;
    cur.u8("tkey")?;
    let key = cur.optional("tkey", |c| c.array::<TRANSPARENT_SECRET_LEN>("tkey"))?;
    let address = cur.zwl_string()?;
    let hdkey_num = cur.optional("tkey", |c| c.u32_le("tkey"))?;
    let enc_key = cur.optional("tkey", |c| c.vector_bytes("tkey"))?;
    let nonce = cur.optional("tkey", |c| c.vector_bytes("tkey"))?;
    let sealed = sealed(enc_key, nonce);

    let provenance = match keytype {
        0 => Provenance::HdDerived,  // WalletTKeyType::HdKey
        1 => Provenance::Standalone, // WalletTKeyType::ImportedKey
        _ => return Err(cur.error("tkey", "wallet structure could not be read")),
    };
    let hd_index = hdkey_num.filter(|_| provenance == Provenance::HdDerived);

    let recovered =
        |secret: Secret<[u8; TRANSPARENT_SECRET_LEN]>| match std::str::from_utf8(address)
            .ok()
            .and_then(|s| identity::transparent_matches_address(secret.expose_secret(), s).ok())
        {
            Some(network) => TKeyEntry::Recovered(
                TransparentKey {
                    secret,
                    provenance,
                    created_at: None,
                },
                network,
            ),
            None => TKeyEntry::Mismatch,
        };
    let entry = match key {
        Some(secret) => recovered(Secret::new(secret)),
        None if provenance == Provenance::Standalone => {
            match open_standalone::<TRANSPARENT_SECRET_LEN>(sealed, wallet_key) {
                Some(Ok(secret)) => recovered(secret),
                Some(Err(())) => TKeyEntry::DecryptionFailed,
                None => TKeyEntry::Locked(provenance),
            }
        }
        None => TKeyEntry::Locked(provenance),
    };
    Ok((entry, hd_index))
}

enum OKeyEntry {
    /// An HD Orchard key: the seed recreates it, so nothing is lost.
    HdDerived(Option<u32>),
    /// An imported Orchard spending key. Argos does not recover Orchard
    /// spending keys, and this one exists in no seed.
    StandaloneSpendingKey,
    /// An imported full viewing key: no spending authority was ever here.
    ViewOnly,
}

/// Read one `WalletOKey` (Orchard). `ImportedKeys` has no Orchard key
/// field, so only the key type and HD index are kept; the cursor must still
/// advance exactly to keep the `zkeys`/`tkeys` vectors aligned. Field order
/// and key types confirmed against `WalletOKey::read` in
/// `zingolabs/zwl-lib`'s `lib/src/lightwallet/walletokey.rs`.
fn read_okey(cur: &mut Cursor) -> ZwlReadResult<OKeyEntry> {
    cur.u8("okey")?;
    let keytype = cur.u32_le("okey")?;
    cur.u8("okey")?;
    let hdkey_num = cur.optional("okey", |c| c.u32_le("okey"))?;
    cur.skip(ORCHARD_FVK_LEN, "okey")?;
    // Read into a scrubbed buffer: an imported Orchard spending key is
    // still a spending key even though it is not recovered.
    let _sk = cur.optional("okey", |c| c.array::<32>("okey").map(Secret::new))?;
    let enc_key = cur.optional("okey", |c| c.vector_bytes("okey"))?;
    let nonce = cur.optional("okey", |c| c.vector_bytes("okey"))?;
    drop(sealed(enc_key, nonce));
    match keytype {
        0 => Ok(OKeyEntry::HdDerived(hdkey_num)), // WalletOKeyType::HdKey
        1 => Ok(OKeyEntry::StandaloneSpendingKey), // ImportedSpendingKey
        2 => Ok(OKeyEntry::ViewOnly),             // ImportedFullViewKey
        _ => Err(cur.error("okey", "wallet structure could not be read")),
    }
}

fn note_hd_index(out: &mut ImportedKeys, index: Option<u32>) {
    if let Some(index) = index {
        out.highest_hd_index = Some(out.highest_hd_index.map_or(index, |h| h.max(index)));
    }
}

/// Read `okeys` (if the `Keys` version supports them), `zkeys`, and
/// `tkeys`, pushing each completed key into `out`. On failure the caller
/// adds a damage diagnostic while retaining those completed keys.
fn read_key_vectors(
    cur: &mut Cursor,
    keys_version: u64,
    wallet_key: Option<&Secret<[u8; 32]>>,
    out: &mut ImportedKeys,
) -> ZwlReadResult<()> {
    if keys_version > 21 {
        let count = cur.compact_size("okeys")?;
        for _ in 0..count {
            // An HD Orchard key is recreated from the seed with the account
            // it names, so it costs nothing. An imported one is a spending
            // key Argos does not recover and no seed holds: say so, per key.
            match read_okey(cur)? {
                OKeyEntry::HdDerived(index) => note_hd_index(out, index),
                OKeyEntry::StandaloneSpendingKey => {
                    out.diagnostics
                        .push(ImportDiagnostic::UnrecoveredStandaloneKey {
                            record_type: "zwl-okey".to_owned(),
                            pool: "Orchard",
                        })
                }
                OKeyEntry::ViewOnly => {}
            }
        }
    }

    let zkey_count = cur.compact_size("zkeys")?;
    for _ in 0..zkey_count {
        let (entry, hd_index) = read_zkey(cur, wallet_key)?;
        note_hd_index(out, hd_index);
        match entry {
            ZKeyEntry::Recovered(k) => out.sapling.push(k),
            // A locked HD key beside a recovered seed is one of the seed's
            // own accounts: the scan recreates it, so it is not missing.
            ZKeyEntry::Locked(Provenance::HdDerived) if out.mnemonic.is_some() => {}
            ZKeyEntry::Locked(provenance) => {
                out.diagnostics.push(locked_key("zwl-zkey", provenance))
            }
            ZKeyEntry::DecryptionFailed => {
                out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                    record_type: "zwl-zkey".to_owned(),
                    reason: "the imported key's ciphertext did not open under the wallet key"
                        .to_owned(),
                })
            }
            ZKeyEntry::NoSpendingKey => {}
            ZKeyEntry::Mismatch => {
                out.diagnostics
                    .push(ImportDiagnostic::PublicIdentifierMismatch {
                        record_type: "zwl-zkey".to_owned(),
                        identifier: "extended full viewing key",
                    })
            }
        }
    }

    if keys_version <= 20 {
        // Pre-encryption-support layout: a flat vector of raw 32-byte
        // secp256k1 secrets, then a parallel vector of address strings —
        // no per-key locked/Optional wrapper at all. Confirmed against
        // the `version <= 20` arm of `Keys::read` in `src/keys.rs`. This
        // shape predates ZWL's wallet-encryption feature. Pair each
        // secret with its parallel address before accepting it.
        let secret_count = cur.compact_size("tkeys")?;
        let mut secrets = Vec::new();
        for _ in 0..secret_count {
            secrets.push(Secret::new(cur.array::<TRANSPARENT_SECRET_LEN>("key")?));
        }
        let address_count = cur.compact_size("address")?;
        let mut pending = secrets.into_iter();
        for _ in 0..address_count {
            let address = cur.zwl_string()?;
            if let Some(secret) = pending.next() {
                if let Some(network) = std::str::from_utf8(address).ok().and_then(|s| {
                    identity::transparent_matches_address(secret.expose_secret(), s).ok()
                }) {
                    merge_embedded_network(out, network);
                    out.transparent.push(TransparentKey {
                        secret,
                        provenance: Provenance::HdDerived,
                        created_at: None,
                    });
                } else {
                    out.diagnostics
                        .push(ImportDiagnostic::PublicIdentifierMismatch {
                            record_type: "zwl-tkey".to_owned(),
                            identifier: "transparent address",
                        });
                }
            }
        }
        if secret_count != address_count {
            out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                record_type: "zwl-tkey".to_owned(),
                reason: "secret and address counts differ".to_owned(),
            });
        }
    } else {
        let tkey_count = cur.compact_size("tkeys")?;
        for _ in 0..tkey_count {
            let (entry, hd_index) = read_tkey(cur, wallet_key)?;
            note_hd_index(out, hd_index);
            match entry {
                TKeyEntry::DecryptionFailed => {
                    out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "zwl-tkey".to_owned(),
                        reason: "the imported key's ciphertext did not open under the wallet key"
                            .to_owned(),
                    })
                }
                TKeyEntry::Recovered(k, network) => {
                    merge_embedded_network(out, network);
                    out.transparent.push(k);
                }
                TKeyEntry::Mismatch => {
                    out.diagnostics
                        .push(ImportDiagnostic::PublicIdentifierMismatch {
                            record_type: "zwl-tkey".to_owned(),
                            identifier: "transparent address",
                        })
                }
                // As for zkeys: covered by the recovered seed.
                TKeyEntry::Locked(Provenance::HdDerived) if out.mnemonic.is_some() => {}
                TKeyEntry::Locked(provenance) => {
                    out.diagnostics.push(locked_key("zwl-tkey", provenance))
                }
            }
        }
    }

    Ok(())
}

fn skip_compact_block(cur: &mut Cursor) -> ZwlReadResult<()> {
    cur.skip(4 + 32, "blocks")?; // height and hash
                                 // Legacy Sapling CommitmentTree: optional left/right nodes, then
                                 // CompactSize-prefixed optional parent nodes (all nodes are 32 bytes).
    for _ in 0..2 {
        cur.optional("blocks", |cur| cur.skip(32, "blocks"))?;
    }
    let parents = cur.compact_size("blocks")?;
    if parents > 32 {
        return Err(cur.error("blocks", "wallet structure could not be read"));
    }
    for _ in 0..parents {
        cur.optional("blocks", |cur| cur.skip(32, "blocks"))?;
    }
    let version = cur.u64_le("blocks")?;
    if version > 20 {
        return Err(cur.error("blocks", "wallet structure could not be read"));
    }
    if version > 11 {
        let len = cur.compact_size("blocks")?;
        let len =
            usize::try_from(len).map_err(|_| cur.error("blocks", "value length limit exceeded"))?;
        cur.skip(len, "blocks")?;
    }
    Ok(())
}

fn skip_vector(
    cur: &mut Cursor,
    field: &'static str,
    mut item: impl FnMut(&mut Cursor) -> ZwlReadResult<()>,
) -> ZwlReadResult<()> {
    let count = cur.compact_size(field)?;
    // Every supported item consumes at least one byte. This also prevents
    // attacker-sized loop counts on a short damaged file.
    if count > cur.bytes.len().saturating_sub(cur.pos) as u64 {
        return Err(cur.error(field, "value length limit exceeded"));
    }
    for _ in 0..count {
        item(cur)?;
    }
    Ok(())
}

fn skip_unverified_history_vector(
    cur: &mut Cursor,
    field: &'static str,
    mut item: impl FnMut(&mut Cursor) -> ZwlReadResult<()>,
) -> ZwlReadResult<bool> {
    let mut saw_item = false;
    skip_vector(cur, field, |cur| {
        saw_item = true;
        item(cur)
    })?;
    Ok(saw_item)
}

fn skip_bytes_vector(cur: &mut Cursor, field: &'static str) -> ZwlReadResult<()> {
    let len = cur.compact_size(field)?;
    let len = usize::try_from(len).map_err(|_| cur.error(field, "value length limit exceeded"))?;
    cur.skip(len, field)
}

fn skip_tree(cur: &mut Cursor, field: &'static str) -> ZwlReadResult<()> {
    for _ in 0..2 {
        cur.optional(field, |cur| cur.skip(32, field))?;
    }
    skip_vector(cur, field, |cur| {
        cur.optional(field, |cur| cur.skip(32, field))?;
        Ok(())
    })
}

fn skip_sapling_witness(cur: &mut Cursor) -> ZwlReadResult<()> {
    skip_tree(cur, "txns")?;
    skip_vector(cur, "txns", |cur| cur.skip(32, "txns"))?;
    cur.optional("txns", |cur| skip_tree(cur, "txns"))?;
    Ok(())
}

fn skip_sapling_note(cur: &mut Cursor) -> ZwlReadResult<()> {
    let version = cur.u64_le("txns")?;
    if version > 20 {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    if version <= 5 {
        cur.skip(8, "txns")?;
    }
    cur.skip(EXTFVK_LEN + 11 + 8, "txns")?;
    cur.skip(if version <= 3 { 32 } else { 33 }, "txns")?;
    skip_vector(cur, "txns", skip_sapling_witness)?;
    if version >= 20 {
        cur.skip(8, "txns")?;
    }
    cur.skip(32, "txns")?;
    if version <= 5 {
        cur.optional("txns", |cur| cur.skip(32, "txns"))?;
        if version >= 2 {
            cur.optional("txns", |cur| cur.skip(4, "txns"))?;
        }
    } else {
        cur.optional("txns", |cur| cur.skip(36, "txns"))?;
    }
    if version > 4 {
        cur.optional("txns", |cur| cur.skip(36, "txns"))?;
    }
    cur.optional("txns", |cur| cur.skip(512, "txns"))?;
    cur.skip(1, "txns")?;
    if version > 2 {
        cur.skip(1, "txns")?;
    }
    Ok(())
}

fn skip_utxo(cur: &mut Cursor) -> ZwlReadResult<()> {
    let version = cur.u64_le("txns")?;
    if version > 3 {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    let address_len = cur.u32_le("txns")? as usize;
    cur.skip(address_len, "txns")?;
    cur.skip(32 + 8 + 8 + 4, "txns")?;
    skip_bytes_vector(cur, "txns")?;
    cur.optional("txns", |cur| cur.skip(32, "txns"))?;
    if version > 1 {
        cur.optional("txns", |cur| cur.skip(4, "txns"))?;
    }
    if version > 2 {
        cur.optional("txns", |cur| cur.skip(36, "txns"))?;
    }
    Ok(())
}

fn skip_orchard_note(cur: &mut Cursor) -> ZwlReadResult<()> {
    let version = cur.u64_le("txns")?;
    if version > 22 {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    cur.skip(ORCHARD_FVK_LEN + 43 + 8 + 32 + 32, "txns")?;
    cur.optional("txns", |cur| cur.skip(8, "txns"))?;
    for _ in 0..2 {
        cur.optional("txns", |cur| cur.skip(36, "txns"))?;
    }
    cur.optional("txns", |cur| cur.skip(512, "txns"))?;
    cur.skip(2, "txns")?;
    Ok(())
}

fn skip_wallet_tx(cur: &mut Cursor, history_damage: &mut Vec<ZwlReadError>) -> ZwlReadResult<()> {
    let version = cur.u64_le("txns")?;
    if version > 23 {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    cur.skip(4, "txns")?; // block height
    if version > 20 {
        cur.skip(1, "txns")?;
    }
    if version >= 4 {
        cur.skip(8, "txns")?;
    }
    cur.skip(32, "txns")?; // txid
    if skip_unverified_history_vector(cur, "txns", skip_sapling_note)? {
        history_damage.push(cur.error(
            "txns",
            "nonempty Sapling note history layout is not verified against an upstream writer fixture",
        ));
    }
    skip_vector(cur, "txns", skip_utxo)?;
    if version > 22 {
        cur.skip(8, "txns")?;
    }
    cur.skip(8 + 8, "txns")?;
    skip_vector(cur, "txns", |cur| {
        let len = cur.u64_le("txns")?;
        let len =
            usize::try_from(len).map_err(|_| cur.error("txns", "value length limit exceeded"))?;
        cur.skip(len, "txns")?;
        cur.skip(8 + 512, "txns")
    })?;
    cur.skip(1, "txns")?;
    if version > 4 {
        cur.optional("txns", |cur| cur.skip(8, "txns"))?;
    }
    if version > 5 {
        skip_vector(cur, "txns", |cur| cur.skip(32, "txns"))?;
    }
    if version > 21 {
        if skip_unverified_history_vector(cur, "txns", skip_orchard_note)? {
            history_damage.push(cur.error(
                "txns",
                "nonempty Orchard note history layout is not verified against an upstream writer fixture",
            ));
        }
        skip_vector(cur, "txns", |cur| cur.skip(32, "txns"))?;
    }
    Ok(())
}

fn read_chain_network(
    cur: &mut Cursor,
    external_version: u64,
    out: &mut ImportedKeys,
) -> ZwlReadResult<()> {
    // `LightWallet::read` in zwl-lib uses Keys::read and WalletTxns::read
    // from external version 15; the older read_old layout is outside scope.
    if !(15..=31).contains(&external_version) {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    let mut history_damage = Vec::new();
    if skip_unverified_history_vector(cur, "blocks", skip_compact_block)? {
        history_damage.push(cur.error(
            "blocks",
            "nonempty block history layout is not verified against an upstream writer fixture",
        ));
    }
    let txns_version = cur.u64_le("txns")?;
    if txns_version > 21 {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    skip_vector(cur, "txns", |cur| {
        cur.skip(32, "txns")?;
        skip_wallet_tx(cur, &mut history_damage)
    })?;
    if txns_version <= 20 {
        skip_vector(cur, "txns", |cur| {
            cur.skip(32, "txns")?;
            skip_wallet_tx(cur, &mut history_damage)
        })?;
    }
    let len = cur.u64_le("chain_name")?;
    let len =
        usize::try_from(len).map_err(|_| cur.error("chain_name", "value length limit exceeded"))?;
    let name = std::str::from_utf8(cur.take(len, "chain_name")?)
        .map_err(|_| cur.error("chain_name", "wallet structure could not be read"))?;
    match name {
        "main" | "mainnet" => merge_embedded_network(out, EmbeddedNetwork::Mainnet),
        "test" | "testnet" => merge_embedded_network(out, EmbeddedNetwork::Testnet),
        "regtest" => merge_embedded_network(out, EmbeddedNetwork::Regtest),
        _ => unrecognized_network(out, "ZecWallet Lite", "unknown chain name"),
    }
    out.diagnostics
        .extend(history_damage.into_iter().map(damage));
    read_wallet_tail(cur, external_version, out)
}

/// The fields following the chain name in the upstream LightWallet writer.
/// A recognized wallet is complete only if this versioned tail reaches EOF.
fn read_wallet_tail(
    cur: &mut Cursor,
    external_version: u64,
    out: &mut ImportedKeys,
) -> ZwlReadResult<()> {
    if external_version > 23 {
        let options_version = cur.u64_le("wallet_options")?;
        if options_version > 2 {
            return Err(cur.error("wallet_options", "wallet structure could not be read"));
        }
        if cur.u8("wallet_options")? > 2 {
            return Err(cur.error("wallet_options", "wallet structure could not be read"));
        }
        if options_version > 1 {
            cur.skip(8, "wallet_options")?; // spam threshold
        }
    }
    // `LightWallet::write` stores `get_birthday()`: the creation height,
    // lowered by `adjust_wallet_birthday` to the birthday of any Sapling key
    // imported since, and by the first transaction seen. Zero means none
    // was recorded.
    let birthday = cur.u64_le("birthday")?;
    out.birthday_height = u32::try_from(birthday).ok().filter(|&height| height > 0);
    if external_version <= 22 && cur.u8("sapling_tree_verified")? > 1 {
        return Err(cur.error(
            "sapling_tree_verified",
            "wallet structure could not be read",
        ));
    }
    if external_version > 21 {
        // This is a protobuf TreeState vector. Until its semantic layout is
        // supported here, never claim complete coverage for a nonempty one.
        if cur
            .optional("verified_tree", |cur| {
                skip_bytes_vector(cur, "verified_tree")
            })?
            .is_some()
        {
            return Err(cur.error("verified_tree", "wallet structure could not be read"));
        }
    }
    if external_version > 13 {
        let price_version = cur.u64_le("price_info")?;
        if price_version > 20 {
            return Err(cur.error("price_info", "wallet structure could not be read"));
        }
        cur.optional("price_info", |cur| cur.skip(8, "price_info"))?;
        cur.skip(8, "price_info")?; // historical retry count
    }
    if external_version > 24
        && cur
            .optional("orchard_witnesses", |cur| {
                // The frontier is not yet independently validated here. Mark
                // nonempty state incomplete without treating its bytes as keys.
                cur.skip(cur.bytes.len().saturating_sub(cur.pos), "orchard_witnesses")
            })?
            .is_some()
    {
        return Err(cur.error("orchard_witnesses", "wallet structure could not be read"));
    }
    if cur.pos != cur.bytes.len() {
        return Err(cur.error("wallet_tail", "wallet structure could not be read"));
    }
    Ok(())
}

/// Parse a ZecWallet Lite wallet file.
///
/// Takes a passphrase because ZWL wallets carry their own `encrypted`
/// flag: an encrypted wallet with no passphrase refuses outright, the
/// same contract `zcashd::import_zcashd` uses for a locked wallet. When a
/// passphrase is supplied to an encrypted wallet, `enc_seed` is decrypted
/// into a BIP-39 mnemonic (`ImportedKeys::mnemonic`), and each imported
/// `zkey`/`tkey` record's own `enc_key` is opened with the same wallet key
/// and checked against the address or viewing key stored beside it. A
/// Poly1305 authentication failure on the seed is reported as
/// `ImportError::WrongPassphrase`, since a wrong passphrase is by far the
/// most likely cause and is the actionable message for the user; a single
/// imported key that does not open is a per-record `DecryptionFailed`.
pub fn import_zwl(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let mut cur = Cursor::new(bytes);

    let external_version = cur
        .u64_le("external_version")
        .map_err(|_| unreadable("file is too short to contain a ZWL version"))?;

    let mut out = ImportedKeys::default();

    if !(MIN_KEYS_READ_EXTERNAL_VERSION..=MAX_SUPPORTED_VERSION).contains(&external_version) {
        out.diagnostics
            .push(ImportDiagnostic::UnsupportedWalletVersion {
                component: "ZecWallet Lite external",
                found: external_version,
                minimum: MIN_KEYS_READ_EXTERNAL_VERSION,
                maximum: MAX_SUPPORTED_VERSION,
            });
        return Ok(out);
    }

    // The internal version word precedes the rest of the fixed header.
    // Detect unsupported layouts before decoding fields whose shape may differ.
    let keys_version = match cur.u64_le("keys_version") {
        Ok(version) => version,
        Err(err) => {
            out.diagnostics.push(damage(err));
            return Ok(out);
        }
    };
    if keys_version > MAX_SUPPORTED_KEYS_VERSION {
        out.diagnostics
            .push(ImportDiagnostic::UnsupportedWalletVersion {
                component: "ZecWallet Lite keys",
                found: keys_version,
                minimum: 0,
                maximum: MAX_SUPPORTED_KEYS_VERSION,
            });
        return Ok(out);
    }
    cur.pos -= 8;
    let header = match read_keys_header(&mut cur) {
        Ok(header) => header,
        Err(err) => {
            out.diagnostics.push(damage(err));
            return Ok(out);
        }
    };

    let mut wallet_key_for_records = None;
    if header.encrypted {
        let Some(pass) = passphrase else {
            return Err(ImportError::WrongPassphrase);
        };
        let key = wallet_key(pass);
        match decrypt_seed(&header.enc_seed, &header.nonce, &key) {
            Ok(entropy) => {
                match Mnemonic::<English>::from_entropy(entropy.expose_secret().to_vec()) {
                    Ok(mnemonic) => out.mnemonic = Some(SecretString::new(mnemonic.into_phrase())),
                    Err(_) => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "zwl-seed".to_owned(),
                        reason: "decrypted seed is not a valid BIP-39 entropy length".to_owned(),
                    }),
                }
            }
            // Authentication failure on the seed is fatal, not a
            // per-record diagnostic: it means the passphrase is wrong for
            // the whole wallet, the same contract zcashd's
            // `derive_master_key` uses for its master key.
            Err(()) => return Err(ImportError::WrongPassphrase),
        }
        wallet_key_for_records = Some(key);
    } else {
        match Mnemonic::<English>::from_entropy(header.seed.to_vec()) {
            Ok(mnemonic) => out.mnemonic = Some(SecretString::new(mnemonic.into_phrase())),
            // All 32-byte values are valid BIP-39 entropy. Retain a
            // non-complete result if that library invariant ever changes.
            Err(_) => out.diagnostics.push(ImportDiagnostic::ContainerDamage {
                format: "ZecWallet Lite",
                location: format!("byte {} seed", cur.pos.saturating_sub(SEED_LEN)),
                reason: "wallet structure could not be read".to_owned(),
            }),
        }
    }

    match read_key_vectors(
        &mut cur,
        header.keys_version,
        wallet_key_for_records.as_ref(),
        &mut out,
    ) {
        Err(err) => {
            out.diagnostics.push(damage(err));
        }
        Ok(()) => match read_chain_network(&mut cur, external_version, &mut out) {
            Ok(()) => (),
            Err(err) => {
                out.diagnostics.push(damage(err));
            }
        },
    }

    if out.mnemonic.is_none()
        && out.sapling.is_empty()
        && out.transparent.is_empty()
        && !out.diagnostics.iter().any(|d| {
            matches!(
                d,
                ImportDiagnostic::LockedKey { .. } | ImportDiagnostic::ContainerDamage { .. }
            )
        })
    {
        out.diagnostics
            .push(ImportDiagnostic::MissingSpendAuthority {
                format: "ZecWallet Lite",
            });
    }

    Ok(out)
}

fn damage(err: ZwlReadError) -> ImportDiagnostic {
    ImportDiagnostic::ContainerDamage {
        format: "ZecWallet Lite",
        location: format!("byte {} {}", err.offset, err.field),
        reason: err.reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_from_upstream_writer_fixtures() {
        for (bytes, expected) in [
            (
                include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat").as_slice(),
                crate::keys::EmbeddedNetwork::Mainnet,
            ),
            (
                include_bytes!("../tests/fixtures/zwl-testnet-empty.dat").as_slice(),
                crate::keys::EmbeddedNetwork::Testnet,
            ),
        ] {
            let imported = import_zwl(bytes, None).unwrap();
            assert_eq!(imported.embedded_network, Some(expected));
        }
    }

    #[test]
    fn network_from_upstream_writer_nonempty_transaction_fixture() {
        let bytes = include_bytes!("../tests/fixtures/zwl-testnet-txn.dat");
        let imported = import_zwl(bytes, None).unwrap();
        assert_eq!(
            imported.embedded_network,
            Some(crate::keys::EmbeddedNetwork::Testnet)
        );
    }

    #[test]
    fn upstream_writer_tail_truncations_are_never_complete() {
        for bytes in [
            include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat").as_slice(),
            include_bytes!("../tests/fixtures/zwl-testnet-empty.dat").as_slice(),
            include_bytes!("../tests/fixtures/zwl-testnet-txn.dat").as_slice(),
        ] {
            let full = import_zwl(bytes, None).unwrap();
            assert_eq!(full.coverage(), crate::keys::ImportCoverage::Complete);
            for cut in 8..bytes.len() {
                let imported = import_zwl(&bytes[..cut], None).unwrap();
                assert_ne!(
                    imported.coverage(),
                    crate::keys::ImportCoverage::Complete,
                    "cut {cut} of {}",
                    bytes.len()
                );
                assert!(
                    imported
                        .diagnostics
                        .iter()
                        .any(|d| matches!(d, ImportDiagnostic::ContainerDamage { .. })),
                    "cut {cut} of {}: {:?}",
                    bytes.len(),
                    imported.diagnostics
                );
            }
        }
    }

    #[test]
    fn nonempty_historical_price_tail_is_valid_and_truncation_is_incomplete() {
        let mut bytes = include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat").to_vec();
        // Upstream price version 20 begins at byte 238. Replace its absent
        // optional timestamp with a present u64 timestamp.
        assert_eq!(bytes[246], 0);
        bytes[246] = 1;
        bytes.splice(247..247, 1234u64.to_le_bytes());
        assert_eq!(
            import_zwl(&bytes, None).unwrap().coverage(),
            crate::keys::ImportCoverage::Complete
        );
        for cut in 212..bytes.len() {
            let imported = import_zwl(&bytes[..cut], None).unwrap();
            assert_ne!(
                imported.coverage(),
                crate::keys::ImportCoverage::Complete,
                "cut {cut}"
            );
        }
    }

    #[test]
    fn unknown_bytes_after_writer_tail_are_incomplete() {
        let mut bytes = include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat").to_vec();
        bytes.push(0x42);
        let imported = import_zwl(&bytes, None).unwrap();
        assert_ne!(imported.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn truncated_tail_retains_preceding_testnet_identity() {
        let bytes = include_bytes!("../tests/fixtures/zwl-testnet-empty.dat");
        let imported = import_zwl(&bytes[..bytes.len() - 1], None).unwrap();
        assert_eq!(imported.embedded_network, Some(EmbeddedNetwork::Testnet));
        assert_ne!(imported.coverage(), crate::keys::ImportCoverage::Complete);
        assert!(imported
            .diagnostics
            .iter()
            .any(|d| matches!(d, ImportDiagnostic::ContainerDamage { .. })));
    }

    #[test]
    fn truncated_later_tkey_retains_earlier_testnet_identity() {
        use secp256k1::{PublicKey, Secp256k1, SecretKey};
        use zcash_protocol::consensus::NetworkType;
        use zcash_transparent::address::TransparentAddress;

        let secret = [0x55; TRANSPARENT_SECRET_LEN];
        let public =
            PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap());
        let address = TransparentAddress::from_pubkey(&public)
            .to_zcash_address(NetworkType::Test)
            .encode();
        let mut first = tkey_hd(0x55);
        let address_start = 1 + 4 + 1 + 1 + TRANSPARENT_SECRET_LEN + 8;
        let address_end = address_start + address.len();
        first[address_start..address_end].copy_from_slice(address.as_bytes());

        let mut vectors = cs(0);
        vectors.extend_from_slice(&cs(2));
        vectors.extend_from_slice(&first);
        vectors.extend_from_slice(&tkey_hd(0x66)[..12]);
        let imported = import_zwl(&wallet(25, &keys_body(21, false, &vectors)), None).unwrap();
        assert_eq!(imported.embedded_network, Some(EmbeddedNetwork::Testnet));
        assert_eq!(imported.transparent.len(), 1);
        assert_ne!(imported.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn nonempty_block_history_cannot_be_complete_without_writer_fixture() {
        let mut bytes = include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat").to_vec();
        assert_eq!(bytes[190], 0); // writer's empty CompactBlockData vector
        let mut block = Vec::new();
        block.extend_from_slice(&419_200u32.to_le_bytes());
        block.extend_from_slice(&[0u8; 32]);
        block.extend_from_slice(&[0, 0, 0]); // empty tree
        block.extend_from_slice(&20u64.to_le_bytes());
        block.push(0); // empty v20 extra data
        bytes[190] = 1;
        bytes.splice(191..191, block);
        assert_ne!(
            import_zwl(&bytes, None).unwrap().coverage(),
            crate::keys::ImportCoverage::Complete
        );
    }

    #[test]
    fn nonempty_sapling_note_history_cannot_be_complete_without_writer_fixture() {
        let mut bytes = include_bytes!("../tests/fixtures/zwl-testnet-txn.dat").to_vec();
        assert_eq!(bytes[285], 0); // writer's empty Sapling note vector
        let mut note = Vec::new();
        note.extend_from_slice(&20u64.to_le_bytes());
        note.extend_from_slice(&vec![0u8; EXTFVK_LEN + 11 + 8 + 33]);
        note.push(0); // no witnesses
        note.extend_from_slice(&0u64.to_le_bytes()); // spent height
        note.extend_from_slice(&[0u8; 32]); // diversifier note key
        note.extend_from_slice(&[0, 0, 0]); // optional outpoints and memo
        note.extend_from_slice(&[0, 0]); // flags
        bytes[285] = 1;
        bytes.splice(286..286, note);
        assert_ne!(
            import_zwl(&bytes, None).unwrap().coverage(),
            crate::keys::ImportCoverage::Complete
        );
    }

    #[test]
    fn unsupported_nested_transaction_version_retains_tkey_network() {
        let mut bytes = include_bytes!("../tests/fixtures/zwl-testnet-txn.dat").to_vec();
        // In the writer fixture, the first WalletTx version begins at 232,
        // after the keys, empty blocks, WalletTxns header, and txid.
        bytes[232] = 24; // upstream WalletTx::serialized_version() is 23
        let imported = import_zwl(&bytes, None).unwrap();
        assert_eq!(imported.embedded_network, Some(EmbeddedNetwork::Testnet));
        assert_ne!(imported.coverage(), crate::keys::ImportCoverage::Complete);
        assert!(imported
            .diagnostics
            .iter()
            .any(|d| matches!(d, ImportDiagnostic::ContainerDamage { .. })));
    }

    fn wallet(version: u64, body: &[u8]) -> Vec<u8> {
        let mut v = version.to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn wallet_with_empty_history(version: u64, body: &[u8]) -> Vec<u8> {
        let mut v = wallet(version, body);
        v.push(0); // Vector<CompactBlockData>
        v.extend_from_slice(&21u64.to_le_bytes()); // WalletTxns version
        v.push(0); // no transactions
        v.extend_from_slice(&zwl_string("main"));
        // Writer-produced v25 options, birthday, tree flags, and price tail.
        v.extend_from_slice(&include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat")[212..]);
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
        use sapling_crypto::zip32::ExtendedSpendingKey;
        let extsk = ExtendedSpendingKey::master(&[extsk_byte; 32]);
        let mut extfvk = Vec::new();
        #[allow(deprecated)]
        extsk
            .to_extended_full_viewing_key()
            .write(&mut extfvk)
            .unwrap();
        assert_eq!(extfvk.len(), EXTFVK_LEN);
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(0));
        v.push(0);
        v.extend_from_slice(&opt_some(extsk.to_bytes().to_vec()));
        v.extend_from_slice(&extfvk);
        v.extend_from_slice(&opt_some(u32le(0)));
        v.extend_from_slice(&opt_none());
        v.extend_from_slice(&opt_none());
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
        use secp256k1::{PublicKey, Secp256k1, SecretKey};
        use zcash_protocol::consensus::NetworkType;
        use zcash_transparent::address::TransparentAddress;
        let secret = [secret_byte; TRANSPARENT_SECRET_LEN];
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let address = TransparentAddress::from_pubkey(&pubkey)
            .to_zcash_address(NetworkType::Main)
            .encode();
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(0));
        v.push(0);
        v.extend_from_slice(&opt_some(secret.to_vec()));
        v.extend_from_slice(&zwl_string(&address));
        v.extend_from_slice(&opt_some(u32le(0)));
        v.extend_from_slice(&opt_none());
        v.extend_from_slice(&opt_none());
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

    #[test]
    fn mutated_zwl_extfvk_rejects_extsk() {
        let good = zkey_hd(0x11);
        let mut bad = zkey_hd(0x22);
        // Extended FVK begins after version, key type, lock flag, optional flag, extsk.
        bad[1 + 4 + 1 + 1 + EXTSK_LEN] ^= 1;
        let mut vectors = cs(0); // no Orchard entries
        vectors.extend_from_slice(&cs(2));
        vectors.extend_from_slice(&bad);
        vectors.extend_from_slice(&good);
        vectors.extend_from_slice(&cs(0));
        let keys = import_zwl(&wallet(25, &keys_body(22, false, &vectors)), None).unwrap();
        assert_eq!(keys.sapling.len(), 1);
        assert_eq!(
            keys.sapling[0].extsk.expose_secret(),
            &sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x11; 32]).to_bytes()
        );
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
        assert!(keys.diagnostics.iter().any(|d| matches!(d,
            ImportDiagnostic::PublicIdentifierMismatch { record_type, identifier: "extended full viewing key" }
            if record_type == "zwl-zkey")));
        assert!(!format!("{:?}", keys.diagnostics).contains("[34, 34, 34"));
    }

    #[test]
    fn mutated_zwl_taddress_rejects_secret() {
        let good = tkey_hd(0x11);
        let mut bad = tkey_hd(0x22);
        let start = 1 + 4 + 1 + 1 + TRANSPARENT_SECRET_LEN + 8;
        let len = u64::from_le_bytes(bad[start - 8..start].try_into().unwrap()) as usize;
        assert_eq!(
            len,
            u64::from_le_bytes(good[start - 8..start].try_into().unwrap()) as usize
        );
        bad[start..start + len].copy_from_slice(&good[start..start + len]);
        let mut vectors = cs(0);
        vectors.extend_from_slice(&cs(0));
        vectors.extend_from_slice(&cs(2));
        vectors.extend_from_slice(&bad);
        vectors.extend_from_slice(&good);
        let keys = import_zwl(&wallet(25, &keys_body(22, false, &vectors)), None).unwrap();
        assert_eq!(keys.transparent.len(), 1);
        assert_eq!(keys.transparent[0].secret.expose_secret(), &[0x11; 32]);
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
        assert!(keys.diagnostics.iter().any(|d| matches!(d,
            ImportDiagnostic::PublicIdentifierMismatch { record_type, identifier: "transparent address" }
            if record_type == "zwl-tkey")));
        assert!(!format!("{:?}", keys.diagnostics).contains("[34, 34, 34"));
    }

    #[test]
    fn plaintext_seed_round_trips_to_mnemonic() {
        let entropy = [0x11; SEED_LEN];
        let mut body = keys_body(22, false, &[0, 0, 0]);
        let seed_start = 8 + 1 + ENC_SEED_LEN + 1;
        body[seed_start..seed_start + SEED_LEN].copy_from_slice(&entropy);
        let keys = import_zwl(&wallet(25, &body), None).unwrap();
        let expected = Mnemonic::<English>::from_entropy(entropy.to_vec())
            .unwrap()
            .into_phrase();
        assert_eq!(keys.mnemonic.as_ref().unwrap().expose_secret(), &expected);
    }

    #[test]
    fn all_zwl_truncation_boundaries_are_non_complete() {
        let mut vectors = cs(1);
        vectors.extend_from_slice(&okey_stub());
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&zkey_hd(0x12));
        let vectors_start = 8 + 8 + 1 + ENC_SEED_LEN + 1 + SEED_LEN;
        let first_zkey_end = vectors_start + vectors.len();
        vectors.extend_from_slice(&cs(2));
        let first_tkey_end = vectors_start + vectors.len() + tkey_hd(0x34).len();
        vectors.extend_from_slice(&tkey_hd(0x34));
        vectors.extend_from_slice(&tkey_hd(0x56));
        let bytes = wallet(25, &keys_body(22, false, &vectors));
        for cut in 8..bytes.len() {
            let keys = import_zwl(&bytes[..cut], None).unwrap();
            assert_ne!(
                keys.coverage(),
                crate::keys::ImportCoverage::Complete,
                "cut {cut}"
            );
            if cut >= vectors_start {
                assert!(keys.diagnostics.iter().any(|d| matches!(d, ImportDiagnostic::ContainerDamage { location, .. } if location.starts_with(&format!("byte {cut} ")))), "missing coordinate at cut {cut}: {:?}", keys.diagnostics);
            }
            if cut >= first_zkey_end {
                assert_eq!(keys.sapling.len(), 1, "first zkey lost at cut {cut}");
                assert_eq!(
                    keys.sapling[0].extsk.expose_secret(),
                    &sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x12; 32]).to_bytes()
                );
            }
            if cut >= first_tkey_end {
                assert_eq!(keys.transparent.len(), 1, "first tkey lost at cut {cut}");
            }
        }
    }

    #[test]
    fn unsupported_external_version_is_non_complete() {
        let keys = import_zwl(&wallet(32, &[]), None).unwrap();
        assert!(matches!(
            keys.diagnostics.as_slice(),
            [ImportDiagnostic::UnsupportedWalletVersion { .. }]
        ));
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn unsupported_keys_version_is_non_complete() {
        let keys = import_zwl(&wallet(25, &keys_body(23, false, &[])), None).unwrap();
        assert!(matches!(
            keys.diagnostics.as_slice(),
            [ImportDiagnostic::UnsupportedWalletVersion { .. }]
        ));
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn pre_v15_layout_is_non_complete() {
        let keys = import_zwl(&wallet(14, &[0xff; 32]), None).unwrap();
        assert!(matches!(
            keys.diagnostics.as_slice(),
            [ImportDiagnostic::UnsupportedWalletVersion { .. }]
        ));
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn recognized_truncated_zwl_is_keys_unread_and_zero_seed_is_present() {
        let keys = import_zwl(&wallet(25, &[]), None).unwrap();
        assert!(matches!(
            keys.diagnostics.as_slice(),
            [ImportDiagnostic::ContainerDamage { .. }]
        ));
        assert_eq!(keys.coverage(), crate::keys::ImportCoverage::KeysUnread);
        let keys = import_zwl(&wallet(25, &keys_body(22, false, &[0, 0, 0])), None).unwrap();
        assert!(keys.mnemonic.is_some()); // zero entropy is still a valid ZWL seed
    }

    #[test]
    fn locked_hd_and_standalone_zkeys_have_distinct_guidance() {
        let mut hd = zkey_locked();
        let mut standalone = zkey_locked();
        standalone[1..5].copy_from_slice(&1u32.to_le_bytes());
        let mut vectors = cs(2);
        vectors.append(&mut hd);
        vectors.append(&mut standalone);
        vectors.extend_from_slice(&cs(0));
        let bytes = wallet(25, &keys_body(21, false, &vectors));
        let keys = import_zwl(&bytes, None).unwrap();
        // The seed is recovered, so the locked HD key is one of its own
        // accounts and is not reported; the standalone one, which no seed
        // holds, still is, with its own guidance.
        assert!(keys.mnemonic.is_some());
        let locked: Vec<_> = keys
            .diagnostics
            .iter()
            .filter(|d| matches!(d, ImportDiagnostic::LockedKey { .. }))
            .collect();
        assert_eq!(locked.len(), 1, "{:?}", keys.diagnostics);
        assert!(matches!(
            locked[0],
            ImportDiagnostic::LockedKey {
                provenance: Provenance::Standalone,
                ..
            }
        ));
        assert!(locked[0]
            .to_string()
            .contains("cannot be recreated from the seed"));
    }

    #[test]
    fn locked_hd_and_standalone_tkeys_have_distinct_guidance() {
        let mut standalone = tkey_locked();
        standalone[1..5].copy_from_slice(&1u32.to_le_bytes());
        let mut vectors = vec![0, 2];
        vectors.extend_from_slice(&tkey_locked());
        vectors.extend_from_slice(&standalone);
        let bytes = wallet(25, &keys_body(21, false, &vectors));
        let keys = import_zwl(&bytes, None).unwrap();
        // The seed is recovered, so the locked HD key is one of its own
        // accounts and is not reported; the standalone one, which no seed
        // holds, still is, with its own guidance.
        assert!(keys.mnemonic.is_some());
        let locked: Vec<_> = keys
            .diagnostics
            .iter()
            .filter(|d| matches!(d, ImportDiagnostic::LockedKey { .. }))
            .collect();
        assert_eq!(locked.len(), 1, "{:?}", keys.diagnostics);
        assert!(matches!(
            locked[0],
            ImportDiagnostic::LockedKey {
                provenance: Provenance::Standalone,
                ..
            }
        ));
        assert!(locked[0]
            .to_string()
            .contains("cannot be recreated from the seed"));
    }

    #[test]
    fn truncated_second_tkey_keeps_first_tkey() {
        let mut vectors = vec![0, 0, 2];
        vectors.extend_from_slice(&tkey_hd(0x11));
        vectors.extend_from_slice(&tkey_hd(0x22));
        let bytes = wallet(25, &keys_body(22, false, &vectors));
        let keys = import_zwl(&bytes[..bytes.len() - 1], None).unwrap();
        assert_eq!(keys.transparent.len(), 1);
        assert!(matches!(
            keys.diagnostics.last(),
            Some(ImportDiagnostic::ContainerDamage { .. })
        ));
    }

    // --- the tests specified by the task brief ---

    #[test]
    fn rejects_a_version_newer_than_we_understand() {
        let keys = import_zwl(&wallet(999, &[]), None).unwrap();
        assert!(matches!(
            keys.diagnostics.as_slice(),
            [ImportDiagnostic::UnsupportedWalletVersion { .. }]
        ));
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
        let bytes = wallet_with_empty_history(25, &body);

        let keys = import_zwl(&bytes, None).unwrap();

        assert_eq!(keys.sapling.len(), 1);
        assert_eq!(
            keys.sapling[0].extsk.expose_secret(),
            &sapling_crypto::zip32::ExtendedSpendingKey::master(&[0xEF; 32]).to_bytes()
        );
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
        assert_eq!(
            keys.sapling[0].extsk.expose_secret(),
            &sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x11; 32]).to_bytes()
        );
        assert_eq!(keys.transparent.len(), 1);
        assert_eq!(
            keys.transparent[0].secret.expose_secret(),
            &[0x22; TRANSPARENT_SECRET_LEN]
        );
    }

    #[test]
    fn a_wallet_with_only_hd_orchard_keys_is_covered_by_its_seed() {
        // A post-NU5 ZWL wallet whose funds are entirely Orchard-derived
        // has no Sapling or transparent keys at all, and `ImportedKeys` has
        // no Orchard field. An HD Orchard key is recreated from the seed
        // with the account it names, so the recovered mnemonic is what
        // carries it: the wallet is neither empty nor incomplete, and the
        // key's index is kept so the scan covers that account.
        let mut vectors = cs(1);
        vectors.extend_from_slice(&okey_stub());
        vectors.extend_from_slice(&cs(0)); // zkeys: none
        vectors.extend_from_slice(&cs(0)); // tkeys: none

        let keys = import_zwl(
            &wallet_with_empty_history(25, &keys_body(22, false, &vectors)),
            None,
        )
        .unwrap();

        assert!(keys.sapling.is_empty());
        assert!(keys.transparent.is_empty());
        assert!(keys.mnemonic.is_some());
        assert!(!keys.is_empty());
        assert_eq!(keys.highest_hd_index, Some(0));
        assert_eq!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn recovers_a_transparent_key_from_the_pre_version_20_legacy_layout() {
        let mut vectors = cs(0); // zkeys: none
        vectors.extend_from_slice(&cs(1)); // one legacy secret
        vectors.extend_from_slice(&[0x33; TRANSPARENT_SECRET_LEN]);
        vectors.extend_from_slice(&cs(1)); // one legacy address
        let address = tkey_hd(0x33);
        let start = 1 + 4 + 1 + 1 + TRANSPARENT_SECRET_LEN;
        let len = u64::from_le_bytes(address[start..start + 8].try_into().unwrap()) as usize;
        vectors.extend_from_slice(&address[start..start + 8 + len]);

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
        let bytes = wallet_with_empty_history(25, &body);

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
        // The seed decrypts fine (a correct passphrase), but these locked
        // entries are HD keys: zwl-lib never seals an HD key per record (the
        // junk `enc_key` here is ignored), so the seed is their only source.
        // A passphrase must not make them look recovered: no key is
        // fabricated from them. With the seed recovered they are the seed's
        // own accounts, recreated by the scan, so they are not reported as
        // locked either (round-2 item D on #275).
        // keys_version 21: no okeys vector at all (only present > 21).
        let mut vectors = cs(1);
        vectors.extend_from_slice(&zkey_locked());
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&tkey_locked());

        let entropy = [0x7A; SEED_LEN];
        let (enc_seed, nonce) = encrypt_test_seed("whatever", &entropy, [0x24; NONCE_LEN]);
        let body = keys_body_with_seed(21, true, &enc_seed, &nonce, &vectors);
        let bytes = wallet_with_empty_history(25, &body);

        let pass = SecretString::new("whatever".to_owned());
        let keys = import_zwl(&bytes, Some(&pass)).unwrap();

        assert!(keys.sapling.is_empty(), "no fabricated sapling key");
        assert!(keys.transparent.is_empty(), "no fabricated transparent key");
        assert!(
            keys.mnemonic.is_some(),
            "the whole-wallet seed still decrypts even though these two keys don't"
        );
        assert!(keys.diagnostics.is_empty(), "{:?}", keys.diagnostics);
        assert_eq!(keys.highest_hd_index, Some(0));
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
        assert_eq!(
            keys.transparent.len(),
            1,
            "the complete first tkey must survive"
        );
    }

    // --- Review findings on #275: per-record encryption, birthday, Orchard
    // classification and HD indices. Layout per `zingolabs/zwl-lib` (MIT):
    // `Keys::encrypt` seals each imported key with `secretbox` under
    // `double_sha256(passphrase)`, the key that also seals the seed. ---

    /// The ZWL wallet key, computed independently of the parser.
    fn zwl_key(passphrase: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(Sha256::digest(passphrase.as_bytes())).into()
    }

    fn seal(key: &[u8; 32], nonce: [u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        XSalsa20Poly1305::new(&(*key).into())
            .encrypt(&SecretboxNonce::from(nonce), plaintext)
            .unwrap()
    }

    /// `WalletZKey::encrypt` for an `ImportedSpendingKey`, then `lock`: the
    /// spending key is dropped and only `enc_key`/`nonce` remain.
    fn zkey_standalone_sealed(extsk_byte: u8, key: &[u8; 32], nonce: [u8; NONCE_LEN]) -> Vec<u8> {
        use sapling_crypto::zip32::ExtendedSpendingKey;
        let extsk = ExtendedSpendingKey::master(&[extsk_byte; 32]);
        let mut extfvk = Vec::new();
        #[allow(deprecated)]
        extsk
            .to_extended_full_viewing_key()
            .write(&mut extfvk)
            .unwrap();
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(1)); // ImportedSpendingKey
        v.push(1); // locked
        v.extend_from_slice(&opt_none()); // extsk dropped by lock()
        v.extend_from_slice(&extfvk);
        v.extend_from_slice(&opt_none()); // no hdkey_num
        v.extend_from_slice(&opt_some(vec_bytes(&seal(key, nonce, &extsk.to_bytes()))));
        v.extend_from_slice(&opt_some(vec_bytes(&nonce)));
        v
    }

    /// `WalletTKey::encrypt` for an `ImportedKey`, then `lock`.
    fn tkey_standalone_sealed(secret_byte: u8, key: &[u8; 32], nonce: [u8; NONCE_LEN]) -> Vec<u8> {
        let plain = tkey_hd(secret_byte);
        let secret = [secret_byte; TRANSPARENT_SECRET_LEN];
        let address_at = 1 + 4 + 1 + 1 + TRANSPARENT_SECRET_LEN;
        let address_len =
            u64::from_le_bytes(plain[address_at..address_at + 8].try_into().unwrap()) as usize;
        let address = &plain[address_at..address_at + 8 + address_len];
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(1)); // ImportedKey
        v.push(1); // locked
        v.extend_from_slice(&opt_none()); // key dropped by lock()
        v.extend_from_slice(address);
        v.extend_from_slice(&opt_none()); // no hdkey_num
        v.extend_from_slice(&opt_some(vec_bytes(&seal(key, nonce, &secret))));
        v.extend_from_slice(&opt_some(vec_bytes(&nonce)));
        v
    }

    fn encrypted_mixed_wallet(passphrase: &str, zkey: &[u8], tkey: &[u8]) -> Vec<u8> {
        let mut vectors = cs(0); // okeys
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(zkey);
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(tkey);
        let (enc_seed, nonce) = encrypt_test_seed(passphrase, &[0x5C; SEED_LEN], [0x31; NONCE_LEN]);
        wallet_with_empty_history(
            25,
            &keys_body_with_seed(22, true, &enc_seed, &nonce, &vectors),
        )
    }

    #[test]
    fn encrypted_wallet_recovers_its_standalone_sapling_and_transparent_keys() {
        let key = zwl_key("correct horse");
        let bytes = encrypted_mixed_wallet(
            "correct horse",
            &zkey_standalone_sealed(0x41, &key, [0x01; NONCE_LEN]),
            &tkey_standalone_sealed(0x42, &key, [0x02; NONCE_LEN]),
        );
        let keys =
            import_zwl(&bytes, Some(&SecretString::new("correct horse".to_owned()))).unwrap();

        assert!(keys.mnemonic.is_some());
        assert_eq!(keys.sapling.len(), 1, "{:?}", keys.diagnostics);
        assert_eq!(keys.sapling[0].provenance, Provenance::Standalone);
        assert_eq!(
            keys.sapling[0].extsk.expose_secret(),
            &sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x41; 32]).to_bytes()
        );
        assert_eq!(keys.transparent.len(), 1, "{:?}", keys.diagnostics);
        assert_eq!(keys.transparent[0].provenance, Provenance::Standalone);
        assert_eq!(keys.transparent[0].secret.expose_secret(), &[0x42; 32]);
        assert!(
            !keys
                .diagnostics
                .iter()
                .any(|d| matches!(d, ImportDiagnostic::LockedKey { .. })),
            "{:?}",
            keys.diagnostics
        );
        assert_eq!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    /// Round-2 item D on #275: an encrypted ZWL wallet drops its HD keys
    /// while locked, but once the seed decrypts they are the seed's own HD
    /// accounts, recreated by the scan (their `hdkey_num` widens its range).
    /// They are not reported as locked or missing.
    #[test]
    fn locked_hd_keys_are_not_reported_once_the_seed_decrypts() {
        let bytes = encrypted_mixed_wallet("correct horse", &zkey_locked(), &tkey_locked());
        let keys =
            import_zwl(&bytes, Some(&SecretString::new("correct horse".to_owned()))).unwrap();
        assert!(keys.mnemonic.is_some());
        assert!(
            !keys
                .diagnostics
                .iter()
                .any(|d| matches!(d, ImportDiagnostic::LockedKey { .. })),
            "{:?}",
            keys.diagnostics
        );
        assert_eq!(keys.highest_hd_index, Some(0), "the HD index still counts");
        assert_eq!(keys.coverage(), crate::keys::ImportCoverage::Complete);
        assert_eq!(keys.coverage_notice(), None);
    }

    #[test]
    fn encrypted_standalone_keys_still_need_the_right_passphrase() {
        let key = zwl_key("correct horse");
        let bytes = encrypted_mixed_wallet(
            "correct horse",
            &zkey_standalone_sealed(0x41, &key, [0x01; NONCE_LEN]),
            &tkey_standalone_sealed(0x42, &key, [0x02; NONCE_LEN]),
        );
        let err = import_zwl(
            &bytes,
            Some(&SecretString::new("battery staple".to_owned())),
        )
        .expect_err("a wrong passphrase must not import");
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn a_tampered_or_mismatched_standalone_ciphertext_is_reported_not_used() {
        let key = zwl_key("correct horse");
        let mut zkey = zkey_standalone_sealed(0x41, &key, [0x01; NONCE_LEN]);
        // The ciphertext's last byte sits just before the nonce Optional.
        let at = zkey.len() - (1 + 1 + NONCE_LEN) - 1;
        zkey[at] ^= 0x80;
        // A key sealed correctly, but filed under another key's address.
        let mut tkey = tkey_standalone_sealed(0x42, &key, [0x02; NONCE_LEN]);
        let other = tkey_standalone_sealed(0x43, &key, [0x02; NONCE_LEN]);
        let cipher_len = TRANSPARENT_SECRET_LEN + 16;
        let tail = 1 + 1 + cipher_len + 1 + 1 + NONCE_LEN;
        let (t_at, o_at) = (tkey.len() - tail, other.len() - tail);
        tkey[t_at..].copy_from_slice(&other[o_at..]);

        let bytes = encrypted_mixed_wallet("correct horse", &zkey, &tkey);
        let keys =
            import_zwl(&bytes, Some(&SecretString::new("correct horse".to_owned()))).unwrap();
        assert!(keys.sapling.is_empty());
        assert!(keys.transparent.is_empty());
        assert!(
            keys.diagnostics.iter().any(|d| matches!(d,
            ImportDiagnostic::DecryptionFailed { record_type, .. } if record_type == "zwl-zkey")),
            "{:?}",
            keys.diagnostics
        );
        assert!(keys.diagnostics.iter().any(|d| matches!(d,
            ImportDiagnostic::PublicIdentifierMismatch { record_type, .. } if record_type == "zwl-tkey")),
            "{:?}", keys.diagnostics);
        assert_ne!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    /// Offset of the birthday within the writer fixtures' 256-byte layout:
    /// after the chain name, options version, memo flag and spam threshold.
    const WRITER_FIXTURE_BIRTHDAY_AT: usize = 229;

    #[test]
    fn the_wallet_tail_birthday_is_read_not_skipped() {
        // The writer fixtures were created at height 0, which `LightWallet`
        // stores as 1.
        let bytes = include_bytes!("../tests/fixtures/zwl-mainnet-empty.dat");
        assert_eq!(
            bytes[WRITER_FIXTURE_BIRTHDAY_AT..WRITER_FIXTURE_BIRTHDAY_AT + 8],
            1u64.to_le_bytes()
        );
        assert_eq!(import_zwl(bytes, None).unwrap().birthday_height, Some(1));

        let mut patched = wallet_with_empty_history(25, &keys_body(22, false, &[0, 0, 0]));
        let at = patched.len() - (bytes.len() - WRITER_FIXTURE_BIRTHDAY_AT);
        patched[at..at + 8].copy_from_slice(&1_234_567u64.to_le_bytes());
        let keys = import_zwl(&patched, None).unwrap();
        assert_eq!(keys.birthday_height, Some(1_234_567));
        assert_eq!(keys.coverage(), crate::keys::ImportCoverage::Complete);

        // Zero means "not recorded"; a value past u32 is not a height.
        for unusable in [0u64, u64::from(u32::MAX) + 1] {
            patched[at..at + 8].copy_from_slice(&unusable.to_le_bytes());
            assert_eq!(import_zwl(&patched, None).unwrap().birthday_height, None);
        }
    }

    fn okey(keytype: u32, hdkey_num: Option<u32>) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&u32le(keytype));
        v.push(0);
        v.extend_from_slice(&match hdkey_num {
            Some(n) => opt_some(u32le(n)),
            None => opt_none(),
        });
        v.extend_from_slice(&[0u8; ORCHARD_FVK_LEN]);
        v.extend_from_slice(&match keytype {
            1 => opt_some(vec![0x55; 32]),
            _ => opt_none(),
        });
        v.extend_from_slice(&opt_none());
        v.extend_from_slice(&opt_none());
        v
    }

    #[test]
    fn hd_and_view_only_orchard_keys_do_not_mark_the_wallet_incomplete() {
        let mut vectors = cs(2);
        vectors.extend_from_slice(&okey(0, Some(0))); // HdKey, re-derived from the seed
        vectors.extend_from_slice(&okey(2, None)); // ImportedFullViewKey, no spend authority
        vectors.extend_from_slice(&[0, 0]);
        let keys = import_zwl(
            &wallet_with_empty_history(25, &keys_body(22, false, &vectors)),
            None,
        )
        .unwrap();
        assert!(keys.diagnostics.is_empty(), "{:?}", keys.diagnostics);
        assert_eq!(keys.coverage(), crate::keys::ImportCoverage::Complete);
    }

    #[test]
    fn an_imported_orchard_spending_key_is_reported_as_unrecovered() {
        let mut vectors = cs(2);
        vectors.extend_from_slice(&okey(0, Some(0)));
        vectors.extend_from_slice(&okey(1, None));
        vectors.extend_from_slice(&[0, 0]);
        let keys = import_zwl(
            &wallet_with_empty_history(25, &keys_body(22, false, &vectors)),
            None,
        )
        .unwrap();
        assert_eq!(keys.diagnostics.len(), 1, "{:?}", keys.diagnostics);
        let shown = keys.diagnostics[0].to_string();
        assert!(shown.contains("Orchard"), "{shown}");
        assert!(shown.contains("not recovered"), "{shown}");
        assert!(!shown.contains("85, 85"), "{shown}");
        assert_eq!(
            keys.coverage(),
            crate::keys::ImportCoverage::KeyMaterialMissing
        );
    }

    #[test]
    fn the_highest_hd_index_in_the_file_is_exposed() {
        let with_index = |mut record: Vec<u8>, index: u32, at: usize| {
            record[at..at + 5].copy_from_slice(&opt_some(u32le(index)));
            record
        };
        let zkey_index_at = 1 + 4 + 1 + 1 + EXTSK_LEN + EXTFVK_LEN;
        let tkey = tkey_hd(0x21);
        let tkey_index_at = tkey.len() - 2 - 5;
        let mut vectors = cs(1);
        vectors.extend_from_slice(&okey(0, Some(4)));
        vectors.extend_from_slice(&cs(2));
        vectors.extend_from_slice(&zkey_hd(0x11));
        vectors.extend_from_slice(&with_index(zkey_hd(0x12), 37, zkey_index_at));
        vectors.extend_from_slice(&cs(1));
        vectors.extend_from_slice(&with_index(tkey, 9, tkey_index_at));
        let keys = import_zwl(
            &wallet_with_empty_history(25, &keys_body(22, false, &vectors)),
            None,
        )
        .unwrap();
        assert_eq!(keys.highest_hd_index, Some(37), "{:?}", keys.diagnostics);

        let none = import_zwl(
            &wallet_with_empty_history(25, &keys_body(22, false, &[0, 0, 0])),
            None,
        )
        .unwrap();
        assert_eq!(none.highest_hd_index, None);
    }
}
