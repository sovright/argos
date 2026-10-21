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
fn locked_key(record_type: &str, provenance: Provenance) -> ImportDiagnostic {
    ImportDiagnostic::LockedKey {
        record_type: record_type.to_owned(),
        provenance,
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
    /// The spending key exists but was omitted from the file because the
    /// wallet was locked at write time. Recoverable only with a working
    /// decryption path, which this build does not yet have.
    Locked(Provenance),
    /// A view-key-only entry (`WalletZKeyType::ImportedViewKey`, or an
    /// unrecognized key type). No spending key was ever present here —
    /// this is not a failure.
    NoSpendingKey,
    Mismatch,
}

/// Read one `WalletZKey`. Field order confirmed against `WalletZKey::read`
/// in `zingolabs/zewif-zwl`'s `src/walletzkey.rs`.
fn read_zkey(cur: &mut Cursor) -> ZwlReadResult<ZKeyEntry> {
    cur.u8("zkey")?;
    let keytype = cur.u32_le("zkey")?;
    cur.u8("zkey")?;
    let extsk = cur.optional("zkey", |c| c.array::<EXTSK_LEN>("zkey"))?;
    let extfvk = cur.take(EXTFVK_LEN, "zkey")?;
    cur.optional("zkey", |c| c.u32_le("zkey"))?;
    cur.optional("zkey", |c| c.vector_bytes("zkey"))?;
    cur.optional("zkey", |c| c.vector_bytes("zkey"))?;

    let provenance = match keytype {
        0 => Provenance::HdDerived,               // WalletZKeyType::HdKey
        1 => Provenance::Standalone,              // WalletZKeyType::ImportedSpendingKey
        2 => return Ok(ZKeyEntry::NoSpendingKey), // ImportedViewKey
        // Unrecognized discriminant: continuing would mean guessing at a
        // shape we do not know, exactly the risk this crate refuses to
        // take elsewhere (see zcashd::plaintext's DER header check).
        _ => return Err(cur.error("zkey", "wallet structure could not be read")),
    };

    Ok(match extsk {
        Some(bytes) if identity::sapling_matches_extfvk(&bytes, extfvk) => {
            ZKeyEntry::Recovered(SaplingKey {
                extsk: Secret::new(bytes.to_vec()),
                provenance,
            })
        }
        Some(_) => ZKeyEntry::Mismatch,
        None => ZKeyEntry::Locked(provenance),
    })
}

enum TKeyEntry {
    Recovered(TransparentKey, EmbeddedNetwork),
    Locked(Provenance),
    Mismatch,
}

/// Read one `WalletTKey` in the post-version-20 shape. Field order
/// confirmed against `WalletTKey::read` in `src/wallettkey.rs`.
fn read_tkey(cur: &mut Cursor) -> ZwlReadResult<TKeyEntry> {
    cur.u8("tkey")?;
    let keytype = cur.u32_le("tkey")?;
    cur.u8("tkey")?;
    let key = cur.optional("tkey", |c| c.array::<TRANSPARENT_SECRET_LEN>("tkey"))?;
    let address = cur.zwl_string()?;
    cur.optional("tkey", |c| c.u32_le("tkey"))?;
    cur.optional("tkey", |c| c.vector_bytes("tkey"))?;
    cur.optional("tkey", |c| c.vector_bytes("tkey"))?;

    let provenance = match keytype {
        0 => Provenance::HdDerived,  // WalletTKeyType::HdKey
        1 => Provenance::Standalone, // WalletTKeyType::ImportedKey
        _ => return Err(cur.error("tkey", "wallet structure could not be read")),
    };

    Ok(match key {
        Some(secret) => match std::str::from_utf8(address)
            .ok()
            .and_then(|s| identity::transparent_matches_address(&secret, s).ok())
        {
            Some(network) => TKeyEntry::Recovered(
                TransparentKey {
                    secret: Secret::new(secret),
                    provenance,
                },
                network,
            ),
            None => TKeyEntry::Mismatch,
        },
        None => TKeyEntry::Locked(provenance),
    })
}

/// Skip one `WalletOKey` (Orchard). `ImportedKeys` has no Orchard variant
/// yet, so this only needs to advance the cursor correctly to keep the
/// `zkeys`/`tkeys` vectors that follow aligned — nothing is extracted.
/// Field order confirmed against `WalletOKey::read` in
/// `src/walletokey.rs`.
fn skip_okey(cur: &mut Cursor) -> ZwlReadResult<()> {
    cur.u8("okey")?;
    cur.u32_le("okey")?;
    cur.u8("okey")?;
    cur.optional("okey", |c| c.u32_le("okey"))?;
    cur.skip(ORCHARD_FVK_LEN, "okey")?;
    cur.optional("okey", |c| c.array::<32>("okey"))?;
    cur.optional("okey", |c| c.vector_bytes("okey"))?;
    cur.optional("okey", |c| c.vector_bytes("okey"))?;
    Ok(())
}

/// Read `okeys` (if the `Keys` version supports them), `zkeys`, and
/// `tkeys`, pushing each completed key into `out`. On failure the caller
/// adds a damage diagnostic while retaining those completed keys.
fn read_key_vectors(
    cur: &mut Cursor,
    keys_version: u64,
    out: &mut ImportedKeys,
) -> ZwlReadResult<()> {
    if keys_version > 21 {
        let count = cur.compact_size("okeys")?;
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

    let zkey_count = cur.compact_size("zkeys")?;
    for _ in 0..zkey_count {
        let entry = read_zkey(cur)?;
        match entry {
            ZKeyEntry::Recovered(k) => out.sapling.push(k),
            ZKeyEntry::Locked(provenance) => {
                out.diagnostics.push(locked_key("zwl-zkey", provenance))
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
            let entry = read_tkey(cur)?;
            match entry {
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
                TKeyEntry::Locked(provenance) => {
                    out.diagnostics.push(locked_key("zwl-tkey", provenance))
                }
            }
        }
    }

    Ok(())
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
) -> ZwlReadResult<()> {
    let mut saw_item = false;
    skip_vector(cur, field, |cur| {
        saw_item = true;
        item(cur)
    })?;
    if saw_item {
        return Err(cur.error(
            field,
            "nonempty history layout is not verified against an upstream writer fixture",
        ));
    }
    Ok(())
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

fn skip_wallet_tx(cur: &mut Cursor) -> ZwlReadResult<()> {
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
    skip_unverified_history_vector(cur, "txns", skip_sapling_note)?;
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
        skip_unverified_history_vector(cur, "txns", skip_orchard_note)?;
        skip_vector(cur, "txns", |cur| cur.skip(32, "txns"))?;
    }
    Ok(())
}

fn read_chain_network(
    cur: &mut Cursor,
    external_version: u64,
) -> ZwlReadResult<Option<EmbeddedNetwork>> {
    // zewif-zwl's ZwlParser uses Keys::read and WalletTxns::read for
    // external versions 15..=31; the older read_old layout is outside scope.
    if !(15..=31).contains(&external_version) {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    skip_unverified_history_vector(cur, "blocks", skip_compact_block)?;
    let txns_version = cur.u64_le("txns")?;
    if txns_version > 21 {
        return Err(cur.error("txns", "wallet structure could not be read"));
    }
    skip_vector(cur, "txns", |cur| {
        cur.skip(32, "txns")?;
        skip_wallet_tx(cur)
    })?;
    if txns_version <= 20 {
        skip_vector(cur, "txns", |cur| {
            cur.skip(32, "txns")?;
            skip_wallet_tx(cur)
        })?;
    }
    let len = cur.u64_le("chain_name")?;
    let len =
        usize::try_from(len).map_err(|_| cur.error("chain_name", "value length limit exceeded"))?;
    let name = std::str::from_utf8(cur.take(len, "chain_name")?)
        .map_err(|_| cur.error("chain_name", "wallet structure could not be read"))?;
    read_wallet_tail(cur, external_version)?;
    Ok(match name {
        "main" | "mainnet" => Some(EmbeddedNetwork::Mainnet),
        "test" | "testnet" => Some(EmbeddedNetwork::Testnet),
        "regtest" => Some(EmbeddedNetwork::Regtest),
        _ => None,
    })
}

/// The fields following the chain name in the upstream LightWallet writer.
/// A recognized wallet is complete only if this versioned tail reaches EOF.
fn read_wallet_tail(cur: &mut Cursor, external_version: u64) -> ZwlReadResult<()> {
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
    cur.skip(8, "birthday")?;
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

    match read_key_vectors(&mut cur, header.keys_version, &mut out) {
        Err(err) => {
            out.embedded_network = None;
            out.diagnostics.push(damage(err));
        }
        Ok(()) => match read_chain_network(&mut cur, external_version) {
            Ok(Some(network)) => merge_embedded_network(&mut out, network),
            Ok(None) => unrecognized_network(&mut out, "ZecWallet Lite", "unknown chain name"),
            Err(err) => {
                out.embedded_network = None;
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
    fn unsupported_nested_transaction_version_leaves_network_unknown() {
        let mut bytes = include_bytes!("../tests/fixtures/zwl-testnet-txn.dat").to_vec();
        // In the writer fixture, the first WalletTx version begins at 232,
        // after the keys, empty blocks, WalletTxns header, and txid.
        bytes[232] = 24; // upstream WalletTx::serialized_version() is 23
        let imported = import_zwl(&bytes, None).unwrap();
        assert_eq!(imported.embedded_network, None);
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
        assert!(matches!(
            &keys.diagnostics[0],
            ImportDiagnostic::LockedKey {
                provenance: Provenance::HdDerived,
                ..
            }
        ));
        assert!(matches!(
            &keys.diagnostics[1],
            ImportDiagnostic::LockedKey {
                provenance: Provenance::Standalone,
                ..
            }
        ));
        assert!(keys.diagnostics[1]
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
        assert!(matches!(
            &keys.diagnostics[0],
            ImportDiagnostic::LockedKey {
                provenance: Provenance::HdDerived,
                ..
            }
        ));
        assert!(matches!(
            &keys.diagnostics[1],
            ImportDiagnostic::LockedKey {
                provenance: Provenance::Standalone,
                ..
            }
        ));
        assert!(keys.diagnostics[1]
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
        let bytes = wallet_with_empty_history(25, &body);

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
        assert_eq!(
            keys.transparent.len(),
            1,
            "the complete first tkey must survive"
        );
    }
}
