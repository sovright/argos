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
    legacy_t_external: u32,
    legacy_t_internal: u32,
    legacy_sapling: u32,
}

/// zcashd's legacy account, `0x7FFFFFFF`, under which every key it stores
/// individually is derived (`getnewaddress`, `z_getnewaddress`, keypool).
const LEGACY_ACCOUNT: &str = "2147483647'";

/// Which legacy-account chain a stored key's HD keypath puts it on.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Chain {
    External,
    Change,
    Sapling,
}

/// Verify the wallet's seed and record what it says about coverage.
///
/// Coverage is judged by key *identity*, not by counting keys. zcashd writes
/// a metadata record for every key it stores (`keymeta` keyed like its
/// `key`/`ckey` record, `sapzkeymeta` keyed like `sapzkey`/`csapzkey`),
/// carrying the HD keypath and the fingerprint of the seed it came from. A
/// key the chain says was derived counts as present only if a key record
/// exists whose metadata names exactly that keypath under this seed.
/// Counting instead let every `importprivkey` key stand in for one missing
/// derived key, so a damaged wallet with imports read as Complete.
pub fn assess_seed(
    pairs: &[(Vec<u8>, Vec<u8>)],
    master: Option<&MasterKey>,
    out: &mut ImportedKeys,
) {
    let mut records = SeedRecords::default();
    let mut pre_5_0_seed = None;
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };
        match rec.record_type.as_str() {
            kind @ ("hdseed" | "chdseed") => {
                pre_5_0_seed.get_or_insert(kind.to_owned());
            }
            "mnemonicphrase" => records.plain.push((rec.rest, value.as_slice())),
            "cmnemonicphrase" => records.crypted.push((rec.rest, value.as_slice())),
            "mnemonichdchain" => records.chain = Some(value.as_slice()),
            "key" | "ckey" => {
                records.transparent.insert(rec.rest);
            }
            "sapzkey" | "csapzkey" => {
                records.sapling.insert(rec.rest);
            }
            "keymeta" => records.metadata.push((false, rec.rest, value.as_slice())),
            "sapzkeymeta" => records.metadata.push((true, rec.rest, value.as_slice())),
            _ => {}
        }
    }

    assess_mnemonic_seed(&records, master, out);

    // A raw pre-5.0 seed has no phrase and no counters to check against, so
    // it is reported once, however many records carry it. zcashd 5.0 keeps
    // it when it adds a mnemonic, and every key 4.x derived from it was
    // stored individually. Beside a verified 5.x seed that is said without
    // claiming funds may be missing; with no verified seed it stays the
    // unverifiable seed it is.
    if let Some(record_type) = pre_5_0_seed {
        out.diagnostics.push(if out.seed_verified {
            ImportDiagnostic::UncheckedLegacySeed { record_type }
        } else {
            ImportDiagnostic::UnrecoveredSeed {
                record_type,
                reason: "a pre-5.0 zcashd seed, which Argos does not verify".to_owned(),
            }
        });
    }
}

/// The records `assess_seed` reads, collected in one pass.
#[derive(Default)]
struct SeedRecords<'a> {
    plain: Vec<(Vec<u8>, &'a [u8])>,
    crypted: Vec<(Vec<u8>, &'a [u8])>,
    chain: Option<&'a [u8]>,
    transparent: std::collections::HashSet<Vec<u8>>,
    sapling: std::collections::HashSet<Vec<u8>>,
    /// `(is_sapling, record key after the type, value)`.
    metadata: Vec<(bool, Vec<u8>, &'a [u8])>,
}

/// Verify the 5.x seed, and grade coverage from its chain record.
///
/// The phrase is needed only to *prove* the seed. The chain record names the
/// seed's fingerprint and every counter on its own, so whenever it parses and
/// no phrase verifies, coverage is still graded from it: a wallet that lost
/// its phrase record and keys with it must not read as Complete.
fn assess_mnemonic_seed(records: &SeedRecords, master: Option<&MasterKey>, out: &mut ImportedKeys) {
    use std::collections::HashSet;

    let chain = records.chain.map(parse_chain);
    if records.plain.is_empty() && records.crypted.is_empty() {
        match chain {
            None => push_orphaned_derivations(records, out),
            Some(Ok(chain)) => {
                out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
                    record_type: "mnemonicphrase".to_owned(),
                    reason: "its seed phrase record is missing, though its key chain \
                             record is present"
                        .to_owned(),
                });
                check_coverage(&chain, &chain.seed_fp, records, out);
            }
            Some(Err(why)) => push_chain_failure(out, &why),
        }
        return;
    }

    // Every record is tried, not just until one verifies: a second seed the
    // verified one does not account for must be reported, not dropped. The
    // encrypted copy is tried first — it is the one zcashd maintains once a
    // wallet is encrypted — and its failure is the one reported, so a bogus
    // plaintext copy cannot hide a genuine decryption failure.
    let mut verified = None;
    let mut crypted_failure = None;
    let mut plain_failure = None;
    let mut unverified = Vec::new();
    for (record_type, fp_bytes, value) in records
        .crypted
        .iter()
        .map(|(fp, v)| ("cmnemonicphrase", fp, *v))
        .chain(
            records
                .plain
                .iter()
                .map(|(fp, v)| ("mnemonicphrase", fp, *v)),
        )
    {
        match verify_record(record_type, fp_bytes, value, master) {
            Ok(fp) => {
                verified.get_or_insert(fp);
            }
            Err(reason) => {
                unverified.push((record_type, fp_bytes.clone()));
                let slot = if record_type == "cmnemonicphrase" {
                    &mut crypted_failure
                } else {
                    &mut plain_failure
                };
                slot.get_or_insert((record_type, reason));
            }
        }
    }
    let Some(seed_fp) = verified else {
        let (record_type, reason) = crypted_failure
            .or(plain_failure)
            .unwrap_or(("mnemonicphrase", "no seed record"));
        out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
            record_type: record_type.to_owned(),
            reason: reason.to_owned(),
        });
        if let Some(Ok(chain)) = chain {
            check_coverage(&chain, &chain.seed_fp, records, out);
        }
        return;
    };
    // A failed record under the verified seed's own fingerprint is the other
    // copy of that seed; one under a different fingerprint is another seed.
    let mut reported = HashSet::new();
    for (record_type, fp) in unverified {
        if fp.as_slice() != seed_fp.as_slice() && reported.insert(fp) {
            out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
                record_type: record_type.to_owned(),
                reason: "a second seed in this file, which Argos could not verify".to_owned(),
            });
        }
    }

    // Without the chain there is nothing to say the stored keys are all of
    // them, so a verified phrase alone is not enough.
    let chain = match chain {
        Some(Ok(chain)) if chain.seed_fp == seed_fp => chain,
        Some(Ok(_)) => return push_chain_failure(out, "it belongs to a different seed"),
        Some(Err(why)) => return push_chain_failure(out, &why),
        None => return push_chain_failure(out, "it is missing"),
    };
    out.seed_verified = true;
    check_coverage(&chain, &seed_fp, records, out);
}

/// Report what `chain` says was derived from the seed `seed_fp` that the
/// file does not hold.
fn check_coverage(
    chain: &HdChain,
    seed_fp: &[u8; 32],
    records: &SeedRecords,
    out: &mut ImportedKeys,
) {
    use std::collections::HashSet;

    if chain.account_counter > 0 {
        out.diagnostics
            .push(ImportDiagnostic::UnscannedSeedAccounts {
                accounts: chain.account_counter,
            });
    }

    // The derived keys actually present: metadata naming this seed and a
    // legacy-account keypath, backed by a key record under the same key.
    let mut present: HashSet<(Chain, u32)> = HashSet::new();
    for (sapling, rest, value) in &records.metadata {
        let Some((keypath, fp)) = parse_key_metadata(value) else {
            continue;
        };
        if &fp != seed_fp {
            continue;
        }
        let backed = if *sapling {
            records.sapling.contains(rest)
        } else {
            records.transparent.contains(rest)
        };
        if let (true, Some(position)) = (backed, legacy_position(&keypath, *sapling)) {
            present.insert(position);
        }
    }
    // Each chain against its own counter: a surplus on one must not cover a
    // shortfall on another. Counted over the keys present, never by walking
    // `0..expected`: the counter comes from the file, and walking it let a
    // crafted chain record stall the import for minutes.
    for (chain_kind, pool, expected) in [
        (
            Chain::External,
            "transparent (external)",
            chain.legacy_t_external,
        ),
        (
            Chain::Change,
            "transparent (change)",
            chain.legacy_t_internal,
        ),
        (Chain::Sapling, "Sapling", chain.legacy_sapling),
    ] {
        let found = present
            .iter()
            .filter(|(kind, index)| *kind == chain_kind && *index < expected)
            .count();
        let found = u64::try_from(found).unwrap_or(u64::MAX);
        if found < u64::from(expected) {
            out.diagnostics.push(ImportDiagnostic::MissingDerivedKeys {
                pool: pool.to_owned(),
                expected: u64::from(expected),
                found,
            });
        }
    }
}

/// Decode one seed record and check it against its fingerprint.
fn verify_record(
    record_type: &str,
    fp_bytes: &[u8],
    value: &[u8],
    master: Option<&MasterKey>,
) -> Result<[u8; 32], &'static str> {
    let fp =
        <[u8; 32]>::try_from(fp_bytes).map_err(|_| "record key is not a 32-byte fingerprint")?;
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
        decrypted = Zeroizing(decrypt(master, iv, ct).ok_or("ciphertext did not decrypt")?);
        decrypted.0.as_slice()
    } else {
        value
    };
    verify_phrase(serialized, &fp).map(|()| fp)
}

/// A key's metadata: its HD keypath and the fingerprint of the seed it came
/// from. zcashd's `CKeyMetadata` (the same layout for `keymeta` and
/// `sapzkeymeta`): `i32 version || i64 create_time || CompactSize keypath ||
/// 32-byte seed fingerprint`; the HD fields exist from version 10.
fn parse_key_metadata(value: &[u8]) -> Option<(String, [u8; 32])> {
    let version = u32::from_le_bytes(value.get(..4)?.try_into().ok()?);
    if version < 10 {
        return None;
    }
    let rest = value.get(12..)?;
    let (len, consumed) = compact_size(rest)?;
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    let keypath = std::str::from_utf8(rest.get(consumed..end)?)
        .ok()?
        .to_owned();
    let fp = rest.get(end..end.checked_add(32)?)?.try_into().ok()?;
    Some((keypath, fp))
}

/// Where a legacy-account keypath puts a key: `m/44'/c'/2147483647'/{0,1}/i`
/// for transparent, `m/32'/c'/2147483647'/i'` for Sapling. Anything else —
/// an imported key's empty path, a unified account — is not a legacy
/// derivation and is not counted.
fn legacy_position(keypath: &str, sapling: bool) -> Option<(Chain, u32)> {
    let parts: Vec<&str> = keypath.strip_prefix("m/")?.split('/').collect();
    match (sapling, parts.as_slice()) {
        (false, ["44'", _coin, account, branch, index]) if *account == LEGACY_ACCOUNT => {
            let chain = match *branch {
                "0" => Chain::External,
                "1" => Chain::Change,
                _ => return None,
            };
            Some((chain, index.parse().ok()?))
        }
        (true, ["32'", _coin, account, index]) if *account == LEGACY_ACCOUNT => {
            Some((Chain::Sapling, index.strip_suffix('\'')?.parse().ok()?))
        }
        _ => None,
    }
}

/// A file with neither a phrase record nor a chain record can still hold keys
/// derived from a 5.x seed: their metadata names a legacy-account keypath and
/// the seed's fingerprint. With no counters the missing keys cannot be
/// counted, but such a file lost its seed records and must not read as a
/// seedless, Complete wallet. Reported once per seed, however many keys name
/// it.
fn push_orphaned_derivations(records: &SeedRecords, out: &mut ImportedKeys) {
    let mut seeds = std::collections::BTreeSet::new();
    for (sapling, _, value) in &records.metadata {
        let Some((keypath, fp)) = parse_key_metadata(value) else {
            continue;
        };
        if legacy_position(&keypath, *sapling).is_some() {
            seeds.insert(fp);
        }
    }
    for _ in seeds {
        out.diagnostics.push(ImportDiagnostic::UnrecoveredSeed {
            record_type: "mnemonicphrase".to_owned(),
            reason: "its seed phrase and key chain records are missing, though keys \
                     derived from it are present"
                .to_owned(),
        });
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

/// `u32 version || fp(32) || i64 create_time || u32 account_counter ||
/// u32 legacy_t_external || u32 legacy_t_internal || u32 legacy_sapling ||
/// bool backup_confirmed` — 61 bytes at version 1. Read by version rather
/// than exact length: a later zcashd that appends fields to version 1 is
/// still read, and one that bumps the version is refused as that, not as
/// corruption.
fn parse_chain(value: &[u8]) -> Result<HdChain, String> {
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(value.get(at..at + 4)?.try_into().ok()?))
    };
    let version = u32_at(0).ok_or("it is truncated")?;
    if version != 1 {
        return Err(format!(
            "its version {version} is one this Argos does not understand"
        ));
    }
    if value.len() < 61 {
        return Err("it is truncated".to_owned());
    }
    let field = |at: usize| u32_at(at).ok_or_else(|| "it is truncated".to_owned());
    Ok(HdChain {
        seed_fp: value
            .get(4..36)
            .and_then(|b| b.try_into().ok())
            .ok_or("it is truncated")?,
        account_counter: field(44)?,
        legacy_t_external: field(48)?,
        legacy_t_internal: field(52)?,
        legacy_sapling: field(56)?,
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

    /// Run only this module over `pairs`. Coverage is judged from the
    /// records themselves (key, keymeta, chain), not from how many keys the
    /// flat-key passes recovered, so nothing else needs to run first.
    fn assess(pairs: &[(Vec<u8>, Vec<u8>)], master: Option<&MasterKey>) -> ImportedKeys {
        let mut out = ImportedKeys::default();
        assess_seed(pairs, master, &mut out);
        out
    }

    /// The record key after the record type, for records of `record_type`
    /// whose metadata names a legacy-account keypath matching `path_suffix`.
    fn keys_at(pairs: &[(Vec<u8>, Vec<u8>)], meta_type: &str, path_suffix: &str) -> Vec<Vec<u8>> {
        pairs
            .iter()
            .filter_map(|(k, v)| {
                let r = parse_record_key(k)?;
                (r.record_type == meta_type && String::from_utf8_lossy(v).contains(path_suffix))
                    .then_some(r.rest)
            })
            .collect()
    }

    fn record(kind: &str, rest: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut k = vec![kind.len() as u8];
        k.extend_from_slice(kind.as_bytes());
        k.extend_from_slice(rest);
        (k, value.to_vec())
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
        let out = assess(&p, Some(&m));
        assert!(out.seed_verified, "{:?}", out.diagnostics);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[test]
    fn a_seed_under_the_wrong_fingerprint_is_not_verified() {
        let mut p = pairs("modern-plaintext");
        for (k, _) in p.iter_mut().filter(|r| is("mnemonicphrase")(r)) {
            *k.last_mut().unwrap() ^= 1;
        }
        let out = assess(&p, None);
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
        let out = assess(&p, None);
        assert!(!out.seed_verified);
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
    }

    #[test]
    fn a_chain_for_a_different_seed_is_not_trusted() {
        let mut p = pairs("modern-plaintext");
        for (_, v) in p.iter_mut().filter(|r| is("mnemonichdchain")(r)) {
            v[4] ^= 1; // first byte of the chain's seed fingerprint
        }
        let out = assess(&p, None);
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
        let out = assess(&p, None);
        assert!(out.seed_verified);
        assert_eq!(
            only_diagnostic(&out),
            &ImportDiagnostic::UnscannedSeedAccounts { accounts: 2 }
        );
        assert_eq!(out.coverage(), ImportCoverage::SeedAccountsNotScanned);
    }

    /// The blocking finding on #230. Coverage was judged by counting keys,
    /// so each key imported with `importprivkey` bought tolerance for one
    /// missing seed-derived key: a damaged 5.x wallet with imports read as
    /// Complete. Here four derived change keys are gone and four imported
    /// keys stand in their place; the count still matches, the identity
    /// does not.
    #[test]
    fn imported_keys_do_not_stand_in_for_missing_derived_keys() {
        let mut p = pairs("modern-plaintext");
        let lost: Vec<Vec<u8>> = keys_at(&p, "keymeta", "/2147483647'/1/")
            .into_iter()
            .take(4)
            .collect();
        assert_eq!(lost.len(), 4);
        p.retain(|(k, _)| {
            parse_record_key(k).is_none_or(|r| !(r.record_type == "key" && lost.contains(&r.rest)))
        });
        for i in 0..4u8 {
            let mut pubkey = vec![33u8, 0x02];
            pubkey.extend_from_slice(&[0xE0 + i; 32]);
            // An import: a key record, and metadata with no HD keypath and
            // no seed behind it — what zcashd writes for `importprivkey`.
            p.push(record("key", &pubkey, &[0x01; 60]));
            let mut meta = 10u32.to_le_bytes().to_vec();
            meta.extend_from_slice(&0i64.to_le_bytes());
            meta.push(0);
            meta.extend_from_slice(&[0u8; 32]);
            p.push(record("keymeta", &pubkey, &meta));
        }

        let out = assess(&p, None);
        assert!(out.seed_verified);
        assert!(
            out.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::MissingDerivedKeys { pool, expected: 101, found: 97 } if pool.contains("change")
            )),
            "{:?}",
            out.diagnostics
        );
        assert_ne!(out.coverage(), ImportCoverage::Complete);
    }

    /// External and change keys are separate chains with separate counters;
    /// a surplus on one must not cover a shortfall on the other.
    #[test]
    fn external_keys_do_not_cover_a_missing_change_key() {
        let mut p = pairs("modern-plaintext");
        let lost = keys_at(&p, "keymeta", "/2147483647'/1/")
            .into_iter()
            .next()
            .expect("a change key");
        p.retain(|(k, _)| {
            parse_record_key(k).is_none_or(|r| !(r.record_type == "key" && r.rest == lost))
        });
        let out = assess(&p, None);
        let missing: Vec<_> = out
            .diagnostics
            .iter()
            .filter_map(|d| match d {
                ImportDiagnostic::MissingDerivedKeys { pool, .. } => Some(pool.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(missing.len(), 1, "{:?}", out.diagnostics);
        assert!(missing[0].contains("change"), "{missing:?}");
    }

    #[test]
    fn a_missing_sapling_key_is_reported() {
        let mut p = pairs("modern-plaintext");
        p.retain(|r| !is("sapzkey")(r));
        let out = assess(&p, None);
        assert!(
            out.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::MissingDerivedKeys { pool, expected: 1, found: 0 } if pool == "Sapling"
            )),
            "{:?}",
            out.diagnostics
        );
    }

    /// A file with a second seed the verified one does not account for says
    /// so, instead of stopping at the first that verifies.
    #[test]
    fn a_second_seed_is_reported_not_dropped() {
        let mut p = pairs("modern-plaintext");
        p.push(record("mnemonicphrase", &[0x5A; 32], &[0u8; 40]));
        let out = assess(&p, None);
        assert!(out.seed_verified, "the genuine seed still verifies");
        assert!(
            out.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::UnrecoveredSeed { reason, .. } if reason.contains("second seed")
            )),
            "{:?}",
            out.diagnostics
        );
    }

    /// When the encrypted copy genuinely fails and the plaintext copy is
    /// bogus, the report names the encrypted failure, not the bogus one.
    #[test]
    fn a_decryption_failure_is_not_hidden_behind_a_bad_plaintext_copy() {
        let mut p = pairs("modern-encrypted");
        let m = master(&p);
        for (k, v) in p.iter_mut() {
            match parse_record_key(k).map(|r| r.record_type) {
                Some(t) if t == "cmnemonicphrase" => *v.last_mut().unwrap() ^= 0xFF,
                Some(t) if t == "mnemonicphrase" => v.swap(6, 7),
                _ => {}
            }
        }
        let out = assess(&p, Some(&m));
        assert!(!out.seed_verified);
        assert!(
            matches!(
                only_diagnostic(&out),
                ImportDiagnostic::UnrecoveredSeed { record_type, .. } if record_type == "cmnemonicphrase"
            ),
            "{:?}",
            out.diagnostics
        );
    }

    /// A future zcashd that bumps the chain's version is refused as that,
    /// not as corruption; one that appends fields to version 1 is read.
    #[test]
    fn the_chain_record_is_read_by_version_not_by_exact_length() {
        let mut bumped = pairs("modern-plaintext");
        for (_, v) in bumped.iter_mut().filter(|r| is("mnemonichdchain")(r)) {
            v[0] = 2;
        }
        let out = assess(&bumped, None);
        assert!(
            matches!(
                only_diagnostic(&out),
                ImportDiagnostic::UnrecoveredSeed { reason, .. } if reason.contains("version 2")
            ),
            "{:?}",
            out.diagnostics
        );

        let mut extended = pairs("modern-plaintext");
        for (_, v) in extended.iter_mut().filter(|r| is("mnemonichdchain")(r)) {
            v.extend_from_slice(&[0u8; 8]);
        }
        let out = assess(&extended, None);
        assert!(out.seed_verified, "{:?}", out.diagnostics);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Hostile or damaged seed records are refused with a reason, never a
    /// panic and never a wrong verdict.
    #[test]
    fn malformed_seed_records_are_refused_not_misread() {
        type Mutation = fn(&mut Vec<u8>);
        let plain_cases: &[(&str, Mutation)] = &[
            ("inner length past the buffer", |v| v[4] = 0xFC),
            ("inner length disagreeing with the value", |v| v.push(b' ')),
            ("non-UTF-8 phrase", |v| v[8] = 0xFF),
            ("truncated", |v| v.truncate(3)),
        ];
        for (what, mutate) in plain_cases {
            let mut p = pairs("modern-plaintext");
            for (_, v) in p.iter_mut().filter(|r| is("mnemonicphrase")(r)) {
                mutate(v);
            }
            let out = assess(&p, None);
            assert!(!out.seed_verified, "{what}");
            assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered, "{what}");
        }

        let crypted_cases: &[(&str, Mutation)] = &[
            ("truncated ciphertext", |v| v.truncate(20)),
            ("length prefix past the buffer", |v| v[0] = 0xFC),
            ("not a whole number of blocks", |v| {
                v[0] -= 1;
                v.pop();
            }),
        ];
        for (what, mutate) in crypted_cases {
            let mut p = pairs("modern-encrypted");
            let m = master(&p);
            p.retain(|r| !is("mnemonicphrase")(r));
            for (_, v) in p.iter_mut().filter(|r| is("cmnemonicphrase")(r)) {
                mutate(v);
            }
            let out = assess(&p, Some(&m));
            assert!(!out.seed_verified, "{what}");
            assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered, "{what}");
        }
    }

    #[test]
    fn a_seed_without_its_chain_is_not_verified() {
        let mut p = pairs("modern-plaintext");
        p.retain(|r| !is("mnemonichdchain")(r));
        let out = assess(&p, None);
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
            let out = assess(&[(k, vec![0x02; 40])], None);
            assert!(matches!(
                only_diagnostic(&out),
                ImportDiagnostic::UnrecoveredSeed { record_type, .. } if record_type == kind
            ));
        }
    }

    /// One diagnostic for a pre-5.0 seed however many records carry it.
    #[test]
    fn a_pre_5_0_seed_is_reported_once() {
        let rec = |kind: &str| record(kind, &[0x01; 32], &[0x02; 40]);
        let out = assess(&[rec("hdseed"), rec("chdseed"), rec("hdseed")], None);
        assert_eq!(out.diagnostics.len(), 1, "{:?}", out.diagnostics);
    }

    /// Round 2 on #230, the blocker. The phrase is only needed to *prove*
    /// the seed; the chain record alone names the seed and every counter.
    /// With the phrase lost and keys gone too, the file graded Complete.
    #[test]
    fn a_lost_phrase_record_does_not_hide_missing_keys() {
        let mut p = pairs("modern-plaintext");
        p.retain(|r| !is("mnemonicphrase")(r));
        let out = assess(&p, None);
        assert!(!out.seed_verified);
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| matches!(d, ImportDiagnostic::MissingDerivedKeys { .. })),
            "nothing else is damaged: {:?}",
            out.diagnostics
        );

        // Kristi's reproduction: the phrase, the Sapling key and ten
        // transparent keys gone, the chain record intact.
        let lost: Vec<Vec<u8>> = keys_at(&p, "keymeta", "/2147483647'/1/")
            .into_iter()
            .take(10)
            .collect();
        assert_eq!(lost.len(), 10);
        p.retain(|r| !is("sapzkey")(r));
        p.retain(|(k, _)| {
            parse_record_key(k).is_none_or(|r| !(r.record_type == "key" && lost.contains(&r.rest)))
        });
        let out = assess(&p, None);
        assert_ne!(out.coverage(), ImportCoverage::Complete);
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
        for (want_pool, want_expected, want_found) in [("change", 101, 91), ("Sapling", 1, 0)] {
            assert!(
                out.diagnostics.iter().any(|d| matches!(
                    d,
                    ImportDiagnostic::MissingDerivedKeys { pool, expected, found }
                        if pool.contains(want_pool) && *expected == want_expected && *found == want_found
                )),
                "{want_pool}: {:?}",
                out.diagnostics
            );
        }
    }

    /// #249. With the chain record lost too there are no counters, but the
    /// surviving keys' metadata still names the seed: the file lost its seed
    /// records, and must not read as a seedless, Complete wallet.
    #[test]
    fn lost_phrase_and_chain_records_do_not_read_as_complete() {
        let mut p = pairs("modern-plaintext");
        p.retain(|r| !is("mnemonicphrase")(r) && !is("mnemonichdchain")(r));
        let lost: Vec<Vec<u8>> = keys_at(&p, "keymeta", "/2147483647'/1/")
            .into_iter()
            .take(10)
            .collect();
        assert_eq!(lost.len(), 10);
        p.retain(|(k, _)| {
            parse_record_key(k).is_none_or(|r| !(r.record_type == "key" && lost.contains(&r.rest)))
        });
        let out = assess(&p, None);
        assert!(!out.seed_verified);
        assert_eq!(out.coverage(), ImportCoverage::SeedNotRecovered);
        // Once for the seed, not once per one of its ~100 surviving keys.
        assert!(
            matches!(
                only_diagnostic(&out),
                ImportDiagnostic::UnrecoveredSeed { reason, .. }
                    if reason.contains("key chain records are missing")
            ),
            "{:?}",
            out.diagnostics
        );
    }

    /// Imported and pre-HD keys carry no legacy-account keypath, so a file
    /// holding only those has no seed to report.
    #[test]
    fn keys_without_a_legacy_keypath_do_not_imply_a_seed() {
        let mut p = pairs("modern-plaintext");
        p.retain(|r| !is("mnemonicphrase")(r) && !is("mnemonichdchain")(r));
        let before = p.len();
        p.retain(|(k, v)| {
            parse_record_key(k).is_none_or(|r| {
                !matches!(r.record_type.as_str(), "keymeta" | "sapzkeymeta")
                    || parse_key_metadata(v).is_none_or(|(path, _)| {
                        legacy_position(&path, r.record_type == "sapzkeymeta").is_none()
                    })
            })
        });
        // The fixture's chain counts 104 derived keys (2 external, 101
        // change, 1 Sapling): their metadata must actually be gone.
        assert!(before - p.len() > 100, "removed {}", before - p.len());
        assert!(p.iter().any(is("key")), "the key records themselves remain");
        let out = assess(&p, None);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// The counters come from the file. Walking `0..counter` let twelve
    /// bytes of a crafted chain record wedge the import for minutes.
    #[test]
    fn a_huge_counter_is_not_walked() {
        let mut p = pairs("modern-plaintext");
        for (_, v) in p.iter_mut().filter(|r| is("mnemonichdchain")(r)) {
            v[48..60].fill(0xFF);
        }
        let started = std::time::Instant::now();
        let out = assess(&p, None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "took {:?}",
            started.elapsed()
        );
        let missing = out
            .diagnostics
            .iter()
            .filter(|d| {
                matches!(
                    d,
                    ImportDiagnostic::MissingDerivedKeys { expected, .. } if *expected == u64::from(u32::MAX)
                )
            })
            .count();
        assert_eq!(missing, 3, "{:?}", out.diagnostics);
    }

    /// A key whose metadata names a legacy-account path under a *different*
    /// seed is not a derivation of this one — two seeds in one file, or keys
    /// copied in from another wallet — and must not stand in for one.
    #[test]
    fn a_derived_keypath_under_another_seed_does_not_count() {
        let mut p = pairs("modern-plaintext");
        let target = keys_at(&p, "keymeta", "/2147483647'/1/")
            .into_iter()
            .next()
            .expect("a change key");
        for (k, v) in p.iter_mut() {
            let Some(r) = parse_record_key(k) else {
                continue;
            };
            if r.record_type == "keymeta" && r.rest == target {
                // version(4) + create_time(8) + CompactSize(len) + keypath,
                // then the seed fingerprint.
                let fp_at = 12 + 1 + usize::from(v[12]);
                v[fp_at] ^= 0xFF;
            }
        }
        let out = assess(&p, None);
        assert!(out.seed_verified);
        assert!(
            out.diagnostics.iter().any(|d| matches!(
                d,
                ImportDiagnostic::MissingDerivedKeys { pool, expected: 101, found: 100 } if pool.contains("change")
            )),
            "{:?}",
            out.diagnostics
        );
    }

    /// zcashd 5.0 keeps a wallet's pre-5.0 `hdseed` when it adds a mnemonic.
    /// Beside a verified 5.x seed whose chain checks out, that is not a
    /// reason to say funds may be missing: every key 4.x derived from it was
    /// stored individually and has been read.
    #[test]
    fn a_pre_5_0_seed_beside_a_verified_seed_does_not_claim_missing_funds() {
        let mut p = pairs("modern-plaintext");
        p.push(record("hdseed", &[0x01; 32], &[0x02; 40]));
        let out = assess(&p, None);
        assert!(out.seed_verified, "{:?}", out.diagnostics);
        assert_eq!(
            only_diagnostic(&out),
            &ImportDiagnostic::UncheckedLegacySeed {
                record_type: "hdseed".to_owned()
            }
        );
        assert!(!out.coverage().may_hide_funds(), "{:?}", out.coverage());
        assert_ne!(out.coverage(), ImportCoverage::Complete, "still said");
    }

    #[test]
    fn a_wallet_without_a_seed_says_nothing_about_one() {
        let out = assess(&[], None);
        assert!(!out.seed_verified);
        assert!(out.diagnostics.is_empty());
    }
}
