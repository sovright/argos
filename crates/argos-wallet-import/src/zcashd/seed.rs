//! zcashd's HD seed: verified, never used for derivation.
//!
//! zcashd 5.0+ stores a BIP-39 phrase under `mnemonicphrase` (plaintext) or
//! `cmnemonicphrase` (encrypted), keyed by the seed's fingerprint, and a
//! `mnemonichdchain` recording how many keys it has derived from it. Every
//! key it derives for the legacy account `0x7FFFFFFF` — `getnewaddress`,
//! `z_getnewaddress`, the keypool — is also written as an individual
//! `key`/`sapzkey` record, which the flat-key passes already recover. Only
//! unified accounts (`z_getnewaccount`) exist solely as derivations from the
//! seed.
//!
//! So the seed is used to answer one question: are the stored keys the whole
//! story? It is decoded, checked against its fingerprint and against the
//! chain, and then dropped. It is deliberately not placed in
//! `ImportedKeys::mnemonic`, which would route the wallet down the HD scan —
//! and the HD scan enumerates accounts `0..n`, never the legacy account, so
//! it would lose every key the file stores.
//!
//! Layouts re-derived from zcashd v6.20.0 and checked against the golden
//! fixtures:
//!
//! - `mnemonicphrase` value: `u32 language || CompactSize(len) || phrase`
//! - `cmnemonicphrase` value: `CompactSize(len) || AES-256-CBC(value above)`,
//!   IV = first 16 bytes of the fingerprint
//! - fingerprint: `BLAKE2b-256("Zcash_HD_Seed_FP", CompactSize(64) || seed)`,
//!   the BIP-39 seed with an empty passphrase
//! - `mnemonichdchain` value: `u32 version || fingerprint(32) ||
//!   i64 create_time || u32 account_counter || u32 legacy_t_external ||
//!   u32 legacy_t_internal || u32 legacy_sapling || bool backup_confirmed`

use bip0039::{English, Mnemonic};
use secrecy::Zeroize;

use crate::{
    error::ImportDiagnostic,
    keys::ImportedKeys,
    zcashd::{compact_size, crypto::MasterKey, encrypted::decrypt, records::parse_record_key},
};

/// Every record type this module owns. The plaintext pass skips these.
pub const SEED_RECORDS: &[&str] = &["chdseed", "cmnemonicphrase", "hdseed", "mnemonicphrase"];

const SEED_FP_PERSONALIZATION: &[u8; 16] = b"Zcash_HD_Seed_FP";
/// zcashd's `Language` enum; the only one it offers when creating a wallet.
const LANGUAGE_ENGLISH: u32 = 0;

/// What `mnemonichdchain` says was derived from the seed.
struct HdChain {
    seed_fp: [u8; 32],
    account_counter: u32,
    legacy_transparent: u64,
    legacy_sapling: u32,
}

/// Verify the wallet's seed and record what it says about coverage.
///
/// Runs after the flat-key passes: the chain's counters are compared against
/// the keys they recovered.
pub fn assess_seed(
    pairs: &[(Vec<u8>, Vec<u8>)],
    master: Option<&MasterKey>,
    out: &mut ImportedKeys,
) {
    let mut plain = Vec::new();
    let mut crypted = Vec::new();
    let mut chain = None;
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };
        match rec.record_type.as_str() {
            // A raw pre-5.0 seed: no phrase and no counters to check the
            // stored keys against, so it can only be reported.
            kind @ ("hdseed" | "chdseed") => {
                out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
                    record_type: kind.to_owned(),
                    reason: "a pre-5.0 zcashd seed, which Argos does not verify".to_owned(),
                })
            }
            "mnemonicphrase" => plain.push((rec.rest, value.as_slice())),
            "cmnemonicphrase" => crypted.push((rec.rest, value.as_slice())),
            "mnemonichdchain" => chain = Some(value.as_slice()),
            _ => {}
        }
    }
    if plain.is_empty() && crypted.is_empty() {
        return;
    }

    // Prefer the encrypted record: it is the one zcashd maintains once a
    // wallet is encrypted. v6.20.0 also leaves the plaintext copy behind,
    // which verifies just as well if decryption is unavailable.
    let mut failure = None;
    let mut verified = None;
    for (record_type, fp_bytes, value) in crypted
        .iter()
        .map(|(fp, v)| ("cmnemonicphrase", fp, *v))
        .chain(plain.iter().map(|(fp, v)| ("mnemonicphrase", fp, *v)))
    {
        let result = <[u8; 32]>::try_from(fp_bytes.as_slice())
            .map_err(|_| "record key is not a 32-byte fingerprint")
            .and_then(|fp| {
                let decrypted;
                let serialized = if record_type == "cmnemonicphrase" {
                    let master = master.ok_or("the wallet is not unlocked")?;
                    let (len, consumed) = compact_size(value).ok_or("ciphertext is truncated")?;
                    let end = consumed
                        .checked_add(usize::try_from(len).map_err(|_| "ciphertext is truncated")?)
                        .ok_or("ciphertext is truncated")?;
                    let ct = value.get(consumed..end).ok_or("ciphertext is truncated")?;
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(fp.get(..16).ok_or("fingerprint is truncated")?);
                    decrypted =
                        Zeroizing(decrypt(master, iv, ct).ok_or("ciphertext did not decrypt")?);
                    decrypted.0.as_slice()
                } else {
                    value
                };
                verify_phrase(serialized, &fp).map(|()| fp)
            });
        match result {
            Ok(fp) => {
                verified = Some(fp);
                break;
            }
            Err(reason) => failure = Some((record_type, reason)),
        }
    }
    let Some(seed_fp) = verified else {
        let (record_type, reason) = failure.unwrap_or(("mnemonicphrase", "no seed record"));
        out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
            record_type: record_type.to_owned(),
            reason: reason.to_owned(),
        });
        return;
    };

    // Without the chain there is nothing to say the stored keys are all of
    // them, so a verified phrase alone is not enough.
    let chain = match chain.map(parse_chain) {
        Some(Some(chain)) if chain.seed_fp == seed_fp => chain,
        Some(Some(_)) => return push_chain_failure(out, "it belongs to a different seed"),
        Some(None) => return push_chain_failure(out, "it could not be parsed"),
        None => return push_chain_failure(out, "it is missing"),
    };
    out.seed_verified = true;

    if chain.account_counter > 0 {
        out.diagnostics
            .push(ImportDiagnostic::UnscannedSeedAccounts {
                accounts: chain.account_counter,
            });
    }
    // At-least, not equal: keys imported with `importprivkey`/`z_importkey`
    // are stored too, with no counter behind them.
    for (pool, expected, found) in [
        (
            "transparent",
            chain.legacy_transparent,
            out.transparent.len(),
        ),
        (
            "Sapling",
            u64::from(chain.legacy_sapling),
            out.sapling.len(),
        ),
    ] {
        let found = u64::try_from(found).unwrap_or(u64::MAX);
        if found < expected {
            out.diagnostics.push(ImportDiagnostic::MissingDerivedKeys {
                pool: pool.to_owned(),
                expected,
                found,
            });
        }
    }
}

fn push_chain_failure(out: &mut ImportedKeys, why: &str) {
    out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
        record_type: "mnemonichdchain".to_owned(),
        reason: format!("the seed decoded, but its key chain record cannot be trusted: {why}"),
    });
}

/// Decode a serialized `MnemonicSeed` and check it hashes to `fp`.
fn verify_phrase(serialized: &[u8], fp: &[u8; 32]) -> Result<(), &'static str> {
    let language = serialized
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("seed record is truncated")?;
    if language != LANGUAGE_ENGLISH {
        return Err("seed phrase is not in English");
    }
    let rest = serialized.get(4..).ok_or("seed record is truncated")?;
    let (len, consumed) = compact_size(rest).ok_or("seed record is truncated")?;
    let end = consumed
        .checked_add(usize::try_from(len).map_err(|_| "seed record is truncated")?)
        .ok_or("seed record is truncated")?;
    if end != rest.len() {
        return Err("seed record has the wrong length");
    }
    let phrase = rest.get(consumed..end).ok_or("seed record is truncated")?;
    let phrase = std::str::from_utf8(phrase).map_err(|_| "seed phrase is not UTF-8")?;
    // `Mnemonic` zeroizes itself on drop; the error is discarded unread
    // because bip0039 errors can echo the offending word.
    let mnemonic =
        Mnemonic::<English>::from_phrase(phrase).map_err(|_| "seed phrase is not valid BIP-39")?;
    let mut seed = mnemonic.to_seed("");
    let mut preimage = [0u8; 65];
    preimage[0] = 64; // CompactSize(64): zcashd hashes the serialized vector
    preimage[1..].copy_from_slice(&seed);
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(SEED_FP_PERSONALIZATION)
        .hash(&preimage);
    seed.zeroize();
    preimage.zeroize();
    if digest.as_bytes() == fp {
        Ok(())
    } else {
        Err("seed phrase does not match its fingerprint")
    }
}

fn parse_chain(value: &[u8]) -> Option<HdChain> {
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(value.get(at..at + 4)?.try_into().ok()?))
    };
    // version(4) fp(32) create_time(8) then four u32 counters and a bool.
    if value.len() != 61 || u32_at(0)? != 1 {
        return None;
    }
    Some(HdChain {
        seed_fp: value.get(4..36)?.try_into().ok()?,
        account_counter: u32_at(44)?,
        legacy_transparent: u64::from(u32_at(48)?) + u64::from(u32_at(52)?),
        legacy_sapling: u32_at(56)?,
    })
}

/// Scrubs a decrypted seed record on every exit path.
struct Zeroizing(Vec<u8>);

impl Drop for Zeroizing {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bdb,
        error::ImportDiagnostic,
        keys::ImportCoverage,
        zcashd::{derive_master_key, find_mkey, parse_record_key},
    };
    use secrecy::SecretString;

    fn pairs(name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        bdb::walk(&std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap()).unwrap()
    }

    fn master(pairs: &[(Vec<u8>, Vec<u8>)]) -> MasterKey {
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        derive_master_key(&pass, &find_mkey(pairs).unwrap()).unwrap()
    }

    fn is(record_type: &str) -> impl Fn(&(Vec<u8>, Vec<u8>)) -> bool + '_ {
        move |(k, _)| parse_record_key(k).is_some_and(|r| r.record_type == record_type)
    }

    /// Run only this module over `pairs`, as if the flat-key passes had
    /// recovered `transparent`/`sapling` keys.
    fn assess(
        pairs: &[(Vec<u8>, Vec<u8>)],
        master: Option<&MasterKey>,
        transparent: usize,
        sapling: usize,
    ) -> ImportedKeys {
        let mut out = ImportedKeys {
            transparent: (0..transparent)
                .map(|_| crate::keys::TransparentKey {
                    secret: secrecy::Secret::new([1; 32]),
                    provenance: crate::keys::Provenance::HdDerived,
                })
                .collect(),
            sapling: (0..sapling)
                .map(|_| crate::keys::SaplingKey {
                    extsk: secrecy::Secret::new(vec![1; 169]),
                    provenance: crate::keys::Provenance::HdDerived,
                })
                .collect(),
            ..ImportedKeys::default()
        };
        assess_seed(pairs, master, &mut out);
        out
    }

    fn only_diagnostic(out: &ImportedKeys) -> &ImportDiagnostic {
        assert_eq!(out.diagnostics.len(), 1, "{:?}", out.diagnostics);
        &out.diagnostics[0]
    }

    #[test]
    fn the_encrypted_seed_verifies_without_its_plaintext_copy() {
        // zcashd v6.20.0 leaves a plaintext `mnemonicphrase` beside the
        // encrypted one; drop it so only decryption can succeed.
        let mut p = pairs("modern-encrypted");
        let m = master(&p);
        p.retain(|r| !is("mnemonicphrase")(r));
        let out = assess(&p, Some(&m), 103, 1);
        assert!(out.seed_verified, "{:?}", out.diagnostics);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[test]
    fn a_seed_under_the_wrong_fingerprint_is_not_verified() {
        let mut p = pairs("modern-plaintext");
        for (k, _) in p.iter_mut().filter(|r| is("mnemonicphrase")(r)) {
            *k.last_mut().unwrap() ^= 1;
        }
        let out = assess(&p, None, 103, 1);
        assert!(!out.seed_verified);
        assert!(matches!(
            only_diagnostic(&out),
            ImportDiagnostic::UnrecoveredSeed { record_type, .. } if record_type == "mnemonicphrase"
        ));
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
    }

    #[test]
    fn a_tampered_phrase_is_not_verified() {
        let mut p = pairs("modern-plaintext");
        for (_, v) in p.iter_mut().filter(|r| is("mnemonicphrase")(r)) {
            // Swap two letters inside the phrase: still UTF-8, no longer the
            // seed the fingerprint names (and almost surely a bad checksum).
            v.swap(6, 7);
        }
        let out = assess(&p, None, 103, 1);
        assert!(!out.seed_verified);
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
    }

    #[test]
    fn a_chain_for_a_different_seed_is_not_trusted() {
        let mut p = pairs("modern-plaintext");
        for (_, v) in p.iter_mut().filter(|r| is("mnemonichdchain")(r)) {
            v[4] ^= 1; // first byte of the chain's seed fingerprint
        }
        let out = assess(&p, None, 103, 1);
        assert!(!out.seed_verified);
        assert!(matches!(
            only_diagnostic(&out),
            ImportDiagnostic::UnrecoveredSeed { record_type, .. } if record_type == "mnemonichdchain"
        ));
    }

    #[test]
    fn unified_accounts_are_reported_by_count() {
        let mut p = pairs("modern-plaintext");
        for (_, v) in p.iter_mut().filter(|r| is("mnemonichdchain")(r)) {
            v[44] = 2; // account_counter, after version(4) + fp(32) + time(8)
        }
        let out = assess(&p, None, 103, 1);
        assert!(out.seed_verified);
        assert_eq!(
            only_diagnostic(&out),
            &ImportDiagnostic::UnscannedSeedAccounts { accounts: 2 }
        );
        assert_eq!(out.coverage(), ImportCoverage::SeedAccountsNotScanned);
    }

    #[test]
    fn fewer_stored_keys_than_the_seed_derived_is_reported() {
        // The fixture's chain counts 2 + 101 transparent and 1 Sapling key.
        let p = pairs("modern-plaintext");
        let out = assess(&p, None, 100, 0);
        assert!(out.seed_verified);
        assert_eq!(
            out.diagnostics,
            vec![
                ImportDiagnostic::MissingDerivedKeys {
                    pool: "transparent".to_owned(),
                    expected: 103,
                    found: 100,
                },
                ImportDiagnostic::MissingDerivedKeys {
                    pool: "Sapling".to_owned(),
                    expected: 1,
                    found: 0,
                },
            ]
        );
        assert_eq!(out.coverage(), ImportCoverage::KeysUnread);
    }

    #[test]
    fn a_seed_without_its_chain_is_not_verified() {
        let mut p = pairs("modern-plaintext");
        p.retain(|r| !is("mnemonichdchain")(r));
        let out = assess(&p, None, 103, 1);
        assert!(!out.seed_verified);
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
    }

    #[test]
    fn a_pre_5_0_seed_is_reported_as_unverified() {
        // `hdseed`/`chdseed` hold a raw seed, not a BIP-39 phrase, and no
        // counters to check the stored keys against.
        for kind in ["hdseed", "chdseed"] {
            let mut k = vec![kind.len() as u8];
            k.extend_from_slice(kind.as_bytes());
            k.extend_from_slice(&[0x01; 32]);
            let out = assess(&[(k, vec![0x02; 40])], None, 0, 0);
            assert!(matches!(
                only_diagnostic(&out),
                ImportDiagnostic::UnrecoveredSeed { record_type, .. } if record_type == kind
            ));
        }
    }

    #[test]
    fn a_wallet_without_a_seed_says_nothing_about_one() {
        let out = assess(&[], None, 3, 0);
        assert!(!out.seed_verified);
        assert!(out.diagnostics.is_empty());
    }
}
