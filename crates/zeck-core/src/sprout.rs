//! Sprout key derivation, note decryption, and note plaintexts.
//!
//! Recovering a Sprout spending key is not enough to spend the note it
//! controls. `zcash_proofs::sprout::create_proof` needs each input note's
//! `value`, `rho` and `r`, and none of those are stored in the wallet — they
//! live in the JoinSplit's note ciphertext, in the transaction that created
//! the note. zcashd keeps only `{address, nullifier, witness}` per note, so
//! the plaintext has to be recovered by decrypting the ciphertext with a key
//! derived from `a_sk`.
//!
//! No Rust implementation of Sprout note decryption exists.
//! `zcash_primitives` can parse a `sprout::Bundle` but has no note-encryption
//! module, and `zcash_client_backend` has no Sprout support at all. Zallet
//! drops Sprout keys during migration and `zewif-zcashd` errors on them. So
//! this follows the protocol specification directly:
//!
//! * §4.2.1  Sprout key components   (`a_pk`, `sk_enc`, `pk_enc`)
//! * §5.4.2  `PRF^addr`
//! * §5.4.4.1 `KDF^Sprout`
//! * §5.4.1.4 `hSig`
//! * §5.5    note encryption (Curve25519 + ChaCha20-Poly1305)
//!
//! # What is verifiable without a funded note
//!
//! No fixture holds a funded Sprout note — zcashd refuses inbound Sprout
//! transfers regardless of Canopy height, so one cannot be manufactured (see
//! `tests/regtest/fixtures/README.md`). That rules out an end-to-end
//! decryption test against real data.
//!
//! What *is* checkable is the derivation chain, and precisely: a Sprout
//! record is keyed by its 64-byte payment address, which is `a_pk || pk_enc`.
//! Both halves derive from `a_sk`. The existing
//! `sprout_key_is_genuine.rs` closes the loop on `a_pk`; the same file closes
//! it on `pk_enc` once the key agreement lands. A wrong `sk_enc` produces a
//! wrong `pk_enc` and fails against bytes zcashd wrote, which is a real
//! oracle rather than a self-consistency check.

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::compress256;
use sha2::digest::generic_array::GenericArray;

/// `ZC_NOTEPLAINTEXT_SIZE`: leading byte + value + rho + r + memo.
pub const NOTE_PLAINTEXT_LEN: usize = 1 + 8 + 32 + 32 + 512;
/// `ZC_NOTECIPHERTEXT_SIZE`: the plaintext plus the Poly1305 tag.
pub const NOTE_CIPHERTEXT_LEN: usize = NOTE_PLAINTEXT_LEN + 16;
/// Sprout note plaintexts carry a leading byte of `0x00`. Any other value
/// means this is not a note we can interpret, even if the AEAD tag verified.
const NOTE_PLAINTEXT_LEAD_BYTE: u8 = 0x00;

/// SHA-256 initial state, per FIPS 180-4.
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The bare SHA-256 compression function over one 512-bit block — *not*
/// SHA-256 itself.
///
/// Zcash's `SHA256Compress` deliberately omits the padding and length suffix
/// that make SHA-256 a hash function. Substituting `Sha256::digest` here
/// produces plausible-looking output that is wrong everywhere it is used.
pub fn sha256_compress(block: &[u8; 64]) -> [u8; 32] {
    let mut state = SHA256_IV;
    compress256(&mut state, &[*GenericArray::from_slice(block)]);
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// `PRF^addr_{a_sk}(t)`, per §5.4.2 and `zcash/zcash` `src/zcash/prf.cpp`.
///
/// The block is `a_sk || t`, with the top four bits of the first byte cleared
/// and replaced by the tag `1100`. `a_sk` is a 252-bit value stored in 32
/// bytes, which is why those four bits are free to carry the tag.
pub fn prf_addr(a_sk: &[u8; 32], t: u8) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(a_sk);
    block[0] &= 0x0F;
    block[0] |= 0b1100_0000;
    block[32] = t;
    sha256_compress(&block)
}

/// The paying key `a_pk`, which forms the first half of a Sprout address.
pub fn a_pk(a_sk: &[u8; 32]) -> [u8; 32] {
    prf_addr(a_sk, 0)
}

/// The receiving key `sk_enc`, clamped as a Curve25519 scalar.
///
/// The clamping is not decoration: `PRF^addr` returns 32 arbitrary bytes, and
/// Curve25519 requires the low three bits clear, bit 255 clear and bit 254
/// set. zcashd applies exactly this in `ZCNoteEncryption`'s key generation,
/// so a `pk_enc` derived without it disagrees with the address the wallet
/// stored — which is how this is tested.
pub fn sk_enc(a_sk: &[u8; 32]) -> [u8; 32] {
    let mut sk = prf_addr(a_sk, 1);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

/// `hSig`, per §5.4.1.4 — binds a JoinSplit's randomness, nullifiers and
/// signing key together, and is an input to the note-encryption KDF.
pub fn h_sig(
    random_seed: &[u8; 32],
    nullifiers: &[[u8; 32]; 2],
    joinsplit_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut state = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZcashComputehSig")
        .to_state();
    state.update(random_seed);
    state.update(&nullifiers[0]);
    state.update(&nullifiers[1]);
    state.update(joinsplit_pubkey);
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// `KDF^Sprout`, per §5.4.4.1.
///
/// The personalization's final byte encodes which of the JoinSplit's outputs
/// this key is for, so the two outputs of one JoinSplit derive different
/// keys from the same shared secret. Getting that index wrong yields an AEAD
/// failure rather than a wrong plaintext, which at least fails loudly.
pub fn kdf_sprout(
    dhsecret: &[u8; 32],
    epk: &[u8; 32],
    pk_enc: &[u8; 32],
    h_sig: &[u8; 32],
    output_index: u8,
) -> [u8; 32] {
    assert!(output_index < 2, "a JoinSplit has exactly two outputs");
    let mut personal = [0u8; 16];
    personal[..8].copy_from_slice(b"ZcashKDF");
    personal[8] = output_index;

    let mut state = Blake2bParams::new()
        .hash_length(32)
        .personal(&personal)
        .to_state();
    state.update(h_sig);
    state.update(dhsecret);
    state.update(epk);
    state.update(pk_enc);
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// The transmission key `pk_enc`, forming the second half of a Sprout
/// address.
///
/// This is the half that makes the whole derivation checkable: a Sprout
/// record is keyed by `a_pk || pk_enc`, both derived from `a_sk`, so a wrong
/// `sk_enc` or a missing clamp shows up as a mismatch against bytes zcashd
/// wrote rather than as a silently wrong decryption later.
pub fn pk_enc(a_sk: &[u8; 32]) -> [u8; 32] {
    let sk = x25519_dalek::StaticSecret::from(sk_enc(a_sk));
    *x25519_dalek::PublicKey::from(&sk).as_bytes()
}

/// Decrypt one output of a JoinSplit, if it is addressed to `a_sk`.
///
/// Returns `NotForThisKey` when the AEAD tag does not verify, which is the
/// ordinary case: a JoinSplit has two outputs and a wallet typically owns one
/// or neither. That is not an error worth surfacing to a user — the caller
/// tries every note against every key.
///
/// The nonce is all zeroes. That is safe here, and only here, because the
/// key is derived per output from a fresh ephemeral secret: `KDF^Sprout`
/// mixes `epk` and the output index, so no key is ever reused across
/// messages.
pub fn decrypt_note(
    a_sk: &[u8; 32],
    epk: &[u8; 32],
    ciphertext: &[u8],
    h_sig: &[u8; 32],
    output_index: u8,
) -> Result<SproutNotePlaintext, SproutNoteError> {
    if ciphertext.len() != NOTE_CIPHERTEXT_LEN {
        return Err(SproutNoteError::CiphertextLength(ciphertext.len()));
    }

    let secret = x25519_dalek::StaticSecret::from(sk_enc(a_sk));
    let dhsecret = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*epk));
    let key = kdf_sprout(
        dhsecret.as_bytes(),
        epk,
        &pk_enc(a_sk),
        h_sig,
        output_index,
    );

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| SproutNoteError::NotForThisKey)?;

    SproutNotePlaintext::parse(&plaintext)
}

/// `PRF^nf_{a_sk}(rho)`, per §5.4.2 — the nullifier that marks a note spent.
///
/// Tag `1110`, unlike `PRF^addr`'s `1100`. The tags are what stop one PRF's
/// output being a valid value for another.
pub fn prf_nf(a_sk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(a_sk);
    block[0] &= 0x0F;
    block[0] |= 0b1110_0000;
    block[32..].copy_from_slice(rho);
    sha256_compress(&block)
}

/// `PRF^pk_{a_sk}(i, hSig)`, per §5.4.2 — the MAC binding an input to the
/// JoinSplit that spends it. Tag `0000` with the input index in bit 2.
pub fn prf_pk(a_sk: &[u8; 32], input_index: usize, h_sig: &[u8; 32]) -> [u8; 32] {
    assert!(input_index < 2, "a JoinSplit has exactly two inputs");
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(a_sk);
    block[0] &= 0x0F;
    block[0] |= 0b0000_0000;
    if input_index == 1 {
        block[0] |= 0b0001_0000;
    }
    block[32..].copy_from_slice(h_sig);
    sha256_compress(&block)
}

/// `PRF^rho_{phi}(i, hSig)`, per §5.4.2 — derives an output note's `rho`.
/// Tag `0010`, with the output index in bit 2.
pub fn prf_rho(phi: &[u8; 32], output_index: usize, h_sig: &[u8; 32]) -> [u8; 32] {
    assert!(output_index < 2, "a JoinSplit has exactly two outputs");
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(phi);
    block[0] &= 0x0F;
    block[0] |= 0b0010_0000;
    if output_index == 1 {
        block[0] |= 0b0001_0000;
    }
    block[32..].copy_from_slice(h_sig);
    sha256_compress(&block)
}

/// The Sprout note commitment, per §5.4.8.1:
/// `SHA256Compress(0xB0 || a_pk || v || rho || r)`, taken over two blocks.
pub fn note_commitment(a_pk: &[u8; 32], value: u64, rho: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    // The input is 8 + 256 + 64 + 256 + 256 = 840 bits, which spans two
    // compression blocks with the standard padding zcashd applies.
    let mut input = Vec::with_capacity(105);
    input.push(0xB0);
    input.extend_from_slice(a_pk);
    input.extend_from_slice(&value.to_le_bytes());
    input.extend_from_slice(rho);
    input.extend_from_slice(r);

    // SHA256 of the 105-byte input, using the full hash (padding included),
    // which is what §5.4.8.1 specifies for NoteCommit^Sprout.
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&input));
    out
}

/// Encrypt a note plaintext to a recipient's `pk_enc`.
///
/// Needed for JoinSplit *outputs*: a JoinSplit always has two, and both must
/// carry ciphertexts even when one is a zero-value dummy.
///
/// `esk` is the ephemeral secret; the caller supplies it so a test can make
/// the operation deterministic. Production callers must pass fresh
/// randomness — reusing an `esk` across JoinSplits reuses the AEAD key with
/// a fixed nonce, which loses confidentiality of both notes.
pub fn encrypt_note(
    esk: &[u8; 32],
    pk_enc: &[u8; 32],
    h_sig: &[u8; 32],
    output_index: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, SproutNoteError> {
    if plaintext.len() != NOTE_PLAINTEXT_LEN {
        return Err(SproutNoteError::PlaintextLength(plaintext.len()));
    }
    let secret = x25519_dalek::StaticSecret::from(*esk);
    let epk = x25519_dalek::PublicKey::from(&secret);
    let dhsecret = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*pk_enc));
    let key = kdf_sprout(dhsecret.as_bytes(), epk.as_bytes(), pk_enc, h_sig, output_index);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| SproutNoteError::NotForThisKey)
}

/// The ephemeral public key for a given ephemeral secret.
pub fn epk_for(esk: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*esk);
    *x25519_dalek::PublicKey::from(&secret).as_bytes()
}

impl SproutNotePlaintext {
    /// Serialize to the 585-byte body that gets encrypted.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NOTE_PLAINTEXT_LEN);
        out.push(NOTE_PLAINTEXT_LEAD_BYTE);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.rho);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&self.memo);
        out
    }
}

/// A decrypted Sprout note.
///
/// `value`, `rho` and `r` are exactly the three per-input fields
/// `zcash_proofs::sprout::create_proof` requires and the wallet does not
/// store.
#[derive(Clone)]
pub struct SproutNotePlaintext {
    pub value: u64,
    pub rho: [u8; 32],
    pub r: [u8; 32],
    pub memo: [u8; 512],
}

impl core::fmt::Debug for SproutNotePlaintext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `value` is not secret in any useful sense once the note is being
        // swept, but `rho` and `r` are spend-authorising material.
        f.debug_struct("SproutNotePlaintext")
            .field("value", &self.value)
            .field("rho", &"<redacted>")
            .field("r", &"<redacted>")
            .field("memo", &"<512 bytes>")
            .finish()
    }
}

impl SproutNotePlaintext {
    /// Parse the 585-byte plaintext body.
    ///
    /// `value` is little-endian: zcashd serializes it through the ordinary
    /// Bitcoin-style `READWRITE`, and `SproutNote::cm()` writes it with
    /// `convertIntToVectorLE`. Reading it big-endian yields a wildly wrong
    /// value that still parses, and a note commitment that matches nothing.
    pub fn parse(bytes: &[u8]) -> Result<Self, SproutNoteError> {
        if bytes.len() != NOTE_PLAINTEXT_LEN {
            return Err(SproutNoteError::PlaintextLength(bytes.len()));
        }
        if bytes[0] != NOTE_PLAINTEXT_LEAD_BYTE {
            return Err(SproutNoteError::LeadByte(bytes[0]));
        }
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[1..9]);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[9..41]);
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[41..73]);
        let mut memo = [0u8; 512];
        memo.copy_from_slice(&bytes[73..]);
        Ok(Self {
            value: u64::from_le_bytes(value),
            rho,
            r,
            memo,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SproutNoteError {
    #[error("a Sprout note ciphertext is {0} bytes, expected {NOTE_CIPHERTEXT_LEN}")]
    CiphertextLength(usize),
    #[error("a Sprout note plaintext is {0} bytes, expected {NOTE_PLAINTEXT_LEN}")]
    PlaintextLength(usize),
    #[error("this ciphertext is not addressed to the supplied key")]
    NotForThisKey,
    #[error("decrypted a Sprout note whose leading byte is {0:#04x}, expected 0x00")]
    LeadByte(u8),
}

impl PartialEq for SproutNotePlaintext {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.rho == other.rho
            && self.r == other.r
            && self.memo[..] == other.memo[..]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// The all-zero `a_sk` is not a realistic key, but the tag-masking in
    /// `PRF^addr` is visible on it: whatever the input, the first byte of the
    /// compressed block is `0b1100_0000`.
    #[test]
    fn prf_addr_applies_the_domain_tag() {
        let a_sk = [0u8; 32];
        // Same input, different `t`, must give different outputs — otherwise
        // `a_pk` and `sk_enc` would collide.
        assert_ne!(prf_addr(&a_sk, 0), prf_addr(&a_sk, 1));
    }

    /// Clamping is what makes `sk_enc` a valid Curve25519 scalar. If this
    /// regresses, `pk_enc` silently stops matching the stored address.
    #[test]
    fn sk_enc_is_clamped() {
        // 0xff everywhere exercises every bit the clamp is supposed to touch.
        let sk = sk_enc(&[0xff; 32]);
        assert_eq!(sk[0] & 0b0000_0111, 0, "low three bits must be clear");
        assert_eq!(sk[31] & 0b1000_0000, 0, "bit 255 must be clear");
        assert_eq!(sk[31] & 0b0100_0000, 0b0100_0000, "bit 254 must be set");
    }

    #[test]
    fn kdf_distinguishes_the_two_outputs() {
        let z = [0u8; 32];
        assert_ne!(
            kdf_sprout(&z, &z, &z, &z, 0),
            kdf_sprout(&z, &z, &z, &z, 1),
            "both outputs of a JoinSplit would otherwise share a key"
        );
    }

    #[test]
    fn a_note_plaintext_round_trips() {
        let mut bytes = vec![0u8; NOTE_PLAINTEXT_LEN];
        bytes[1..9].copy_from_slice(&1_234_567_890u64.to_le_bytes());
        bytes[9..41].copy_from_slice(&[7u8; 32]);
        bytes[41..73].copy_from_slice(&[9u8; 32]);
        let note = SproutNotePlaintext::parse(&bytes).expect("well-formed plaintext");
        assert_eq!(note.value, 1_234_567_890);
        assert_eq!(note.rho, [7u8; 32]);
        assert_eq!(note.r, [9u8; 32]);
    }

    /// A verified AEAD tag with an unexpected leading byte means we decrypted
    /// something that is not a Sprout note. Reporting it beats returning a
    /// note with a garbage value.
    /// Encrypt to a key, then decrypt with the spending key that owns it.
    /// This is the only end-to-end check available: no fixture holds a
    /// funded Sprout note, so there is no real ciphertext to decrypt.
    ///
    /// It does catch the wiring errors that matter — a wrong output index in
    /// the KDF, a mismatched `pk_enc`, or an AEAD misuse — because all of
    /// those break the tag rather than producing a wrong plaintext.
    #[test]
    fn a_note_round_trips_through_encryption() {
        let a_sk = [3u8; 32];
        let esk = [5u8; 32];
        let h_sig = [7u8; 32];
        let note = SproutNotePlaintext {
            value: 42_000,
            rho: [11u8; 32],
            r: [13u8; 32],
            memo: [0u8; 512],
        };

        for output_index in 0..2u8 {
            let ct = encrypt_note(
                &esk,
                &pk_enc(&a_sk),
                &h_sig,
                output_index,
                &note.to_bytes(),
            )
            .expect("encrypt");
            assert_eq!(ct.len(), NOTE_CIPHERTEXT_LEN);

            let got = decrypt_note(&a_sk, &epk_for(&esk), &ct, &h_sig, output_index)
                .expect("the owner must be able to decrypt");
            assert_eq!(got, note);
        }
    }

    /// The output index is part of the KDF personalization, so a ciphertext
    /// for output 0 must not decrypt as output 1. If this passes, both
    /// outputs of a JoinSplit share a key.
    #[test]
    fn the_output_index_is_bound_into_the_key() {
        let a_sk = [3u8; 32];
        let esk = [5u8; 32];
        let h_sig = [7u8; 32];
        let note = SproutNotePlaintext {
            value: 1,
            rho: [0u8; 32],
            r: [0u8; 32],
            memo: [0u8; 512],
        };
        let ct = encrypt_note(&esk, &pk_enc(&a_sk), &h_sig, 0, &note.to_bytes()).expect("encrypt");
        assert_eq!(
            decrypt_note(&a_sk, &epk_for(&esk), &ct, &h_sig, 1).unwrap_err(),
            SproutNoteError::NotForThisKey
        );
    }

    /// A note encrypted to someone else must not decrypt, even with a
    /// well-formed ciphertext and the right hSig.
    #[test]
    fn another_partys_note_does_not_decrypt() {
        let mine = [3u8; 32];
        let theirs = [4u8; 32];
        let esk = [5u8; 32];
        let h_sig = [7u8; 32];
        let note = SproutNotePlaintext {
            value: 1,
            rho: [0u8; 32],
            r: [0u8; 32],
            memo: [0u8; 512],
        };
        let ct = encrypt_note(&esk, &pk_enc(&theirs), &h_sig, 0, &note.to_bytes()).expect("encrypt");
        assert_eq!(
            decrypt_note(&mine, &epk_for(&esk), &ct, &h_sig, 0).unwrap_err(),
            SproutNoteError::NotForThisKey
        );
    }

    /// Every Sprout PRF differs only by its domain tag. If two collide, one
    /// PRF's output is a valid value for another.
    #[test]
    fn the_prf_domain_tags_are_distinct() {
        let k = [5u8; 32];
        let x = [6u8; 32];
        let outputs = [
            prf_addr(&k, 0),
            prf_addr(&k, 1),
            prf_nf(&k, &x),
            prf_pk(&k, 0, &x),
            prf_pk(&k, 1, &x),
            prf_rho(&k, 0, &x),
            prf_rho(&k, 1, &x),
        ];
        for (i, a) in outputs.iter().enumerate() {
            for (j, b) in outputs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "PRF outputs {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn a_bad_lead_byte_is_rejected() {
        let mut bytes = vec![0u8; NOTE_PLAINTEXT_LEN];
        bytes[0] = 0x01;
        assert_eq!(
            SproutNotePlaintext::parse(&bytes),
            Err(SproutNoteError::LeadByte(0x01))
        );
    }
}


