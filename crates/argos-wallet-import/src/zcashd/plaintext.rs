//! Extraction of unencrypted zcashd key records.

use secrecy::Secret;

use crate::{
    error::ImportDiagnostic,
    keys::{ImportedKeys, Provenance, SaplingKey, SproutKey, TransparentKey},
    zcashd::records::{compact_size, parse_record_key},
};

/// Record types we knowingly ignore: wallet bookkeeping with no key
/// material. Listed explicitly so genuinely unknown types still produce a
/// diagnostic.
// Verified against the golden fixtures: these are every non-key record
// type a real zcashd v6.20.0 wallet actually contains. Listing them
// explicitly means a genuinely unknown type still produces a diagnostic
// rather than being lost in the noise.
const IGNORED: &[&str] = &[
    "acc",
    "bestblock",
    "bestblock_nomerkle",
    "cmnemonicphrase",
    "defaultkey",
    "keymeta",
    "minversion",
    "mnemonichdchain",
    "mnemonicphrase",
    "name",
    "networkinfo",
    "orchard_note_commitment_tree",
    "orderposnext",
    "pool",
    "purpose",
    "sapzkeymeta",
    "tx",
    "version",
    "witnesscachesize",
    "zkeymeta",
];

fn read_length_prefixed(value: &[u8]) -> Option<&[u8]> {
    let (len, consumed) = compact_size(value)?;
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    value.get(consumed..end)
}

/// Validate that a `key` record's DER blob has the exact header zcashd's
/// OpenSSL-encoded Bitcoin-style CPrivKey always produces —
/// `30 81 <len> 02 01 01 04 20` — before trusting a fixed-offset slice into
/// it. Only byte 2 (the length) is allowed to vary; every other position is
/// checked explicitly. This is deliberately narrower than "any DER
/// OCTET STRING": a mismatch (short-form header, garbage, or any other
/// shape) means we cannot safely locate the secret, so we refuse to guess
/// rather than risk returning a plausible-looking but wrong key.
fn secret_from_key_der(der: &[u8]) -> Option<&[u8]> {
    let header = der.get(..8)?;
    let expected_fixed: [(usize, u8); 7] = [
        (0, 0x30),
        (1, 0x81),
        (3, 0x02),
        (4, 0x01),
        (5, 0x01),
        (6, 0x04),
        (7, 0x20),
    ];
    for (index, expected) in expected_fixed {
        if *header.get(index)? != expected {
            return None;
        }
    }
    der.get(8..40)
}

/// Extract every unencrypted key record.
///
/// A record we cannot parse is recorded as a diagnostic and skipped; it
/// must never prevent a record we *can* parse from being recovered.
pub fn collect_plaintext(pairs: &[(Vec<u8>, Vec<u8>)], out: &mut ImportedKeys) {
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            // Do not include any bytes from the record key itself: it can
            // carry address material, and diagnostics are surfaced to
            // users and may be logged.
            out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                record_type: "<unparseable>".to_owned(),
                reason: "record key could not be parsed".to_owned(),
            });
            continue;
        };

        match rec.record_type.as_str() {
            "zkey" => {
                let addr: Option<[u8; 64]> = rec.rest.get(..64).and_then(|s| s.try_into().ok());
                // Verified against the golden fixtures: the value is the bare
                // 32-byte a_sk with NO CompactSize prefix (observed value
                // length is exactly 32). Do not use read_length_prefixed here
                // — it would read the first key byte as a length.
                let a_sk: Option<[u8; 32]> = value.get(..32).and_then(|s| s.try_into().ok());

                match (addr, a_sk) {
                    (Some(address), Some(a_sk)) => out.sprout.push(SproutKey {
                        a_sk: Secret::new(a_sk),
                        address,
                        // zcashd Sprout keys were never HD-derived.
                        provenance: Provenance::Standalone,
                    }),
                    _ => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "zkey".to_owned(),
                        reason: "address or spending key has the wrong length".to_owned(),
                    }),
                }
            }
            // Verified against the fixtures: the value is a raw 169-byte
            // extended spending key with NO length prefix — depth(1) +
            // parent_fvk_tag(4) + child_index(4) + chain_code(32) +
            // expsk(96) + dk(32). The key remainder is the 32-byte IVK.
            "sapzkey" => match value.get(..169) {
                Some(extsk) => out.sapling.push(SaplingKey {
                    extsk: Secret::new(extsk.to_vec()),
                    provenance: Provenance::Standalone,
                }),
                None => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                    record_type: "sapzkey".to_owned(),
                    reason: "extended spending key is truncated".to_owned(),
                }),
            },
            "key" => {
                // Verified against the fixtures. The value is
                // CompactSize(len) || DER EC private key || 32-byte hash.
                // Within the DER the secret is NOT at the front: the layout
                // is 30 81 d3 | 02 01 01 | 04 20 | <32-byte secret>, so the
                // secret starts 8 bytes into the DER blob. Taking the first
                // 32 bytes yields DER header bytes, not a key. We validate
                // that exact header before slicing — an unvalidated
                // fixed-offset slice can silently manufacture a wrong key
                // from garbage, or return the genuine secret shifted by one
                // byte when the DER uses a short-form length header instead
                // of the long form zcashd always emits.
                match read_length_prefixed(value).and_then(secret_from_key_der) {
                    Some(s) => match <[u8; 32]>::try_from(s) {
                        Ok(secret) => out.transparent.push(TransparentKey {
                            secret: Secret::new(secret),
                            provenance: Provenance::HdDerived,
                        }),
                        Err(_) => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                            record_type: "key".to_owned(),
                            reason: "secret is not 32 bytes".to_owned(),
                        }),
                    },
                    None => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "key".to_owned(),
                        reason: "private key record is truncated or has an unexpected DER header"
                            .to_owned(),
                    }),
                }
            }
            // Encrypted variants are handled in Task 10 once the master
            // key is available; skip silently here rather than reporting
            // them as unknown.
            "ckey" | "czkey" | "csapzkey" | "mkey" | "hdchain" | "sapzaddr" | "zkeymeta" => {}
            other if IGNORED.contains(&other) => {}
            other => out.diagnostics.push(ImportDiagnostic::UnknownRecord {
                record_type: other.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn record(kind: &str, key_rest: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut k = vec![kind.len() as u8];
        k.extend_from_slice(kind.as_bytes());
        k.extend_from_slice(key_rest);
        (k, value.to_vec())
    }

    #[test]
    fn extracts_a_sprout_spending_key() {
        let addr = [0xAB; 64];
        // The value is the bare 32-byte a_sk with no CompactSize prefix —
        // confirmed against the golden fixtures.
        let value = [0xCD; 32];
        let pairs = vec![record("zkey", &addr, &value)];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert_eq!(out.sprout.len(), 1);
        let k = &out.sprout[0];
        assert_eq!(k.address, addr);
        assert_eq!(k.a_sk.expose_secret(), &[0xCD; 32]);
    }

    #[test]
    fn a_malformed_record_does_not_silence_a_good_one() {
        // This is the governing principle: partial recovery.
        let addr = [0x11; 64];
        let good = [0x22; 32];

        let pairs = vec![
            record("zkey", &[0x99; 3], &[0x00]), // too-short address
            record("zkey", &addr, &good),
        ];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert_eq!(out.sprout.len(), 1, "the good key must survive");
        assert_eq!(out.diagnostics.len(), 1, "the bad one must be reported");
    }

    #[test]
    fn unknown_record_types_are_reported_not_silently_dropped() {
        // "bestblock" is a real, expected zcashd record type (in IGNORED);
        // use a type no real wallet produces so this actually exercises
        // the unknown-type path.
        let pairs = vec![record("not_a_real_record_type", &[], &[0x01])];
        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);
        assert!(out.sprout.is_empty());
        assert_eq!(out.diagnostics.len(), 1);
    }

    #[test]
    fn a_key_record_with_an_unexpected_der_shape_is_rejected() {
        // Case 1: forty bytes of pure garbage, correctly length-prefixed.
        // An unchecked der.get(8..40) slice would happily return bytes
        // [8..40] as a "secret" for an address nobody controls.
        let mut garbage_value = vec![40u8];
        garbage_value.extend((0u8..40).collect::<Vec<u8>>());

        // Case 2: a short-form DER header (7 bytes: 30 25 | 02 01 01 |
        // 04 20) instead of the long form zcashd always emits (8 bytes:
        // 30 81 XX | 02 01 01 | 04 20). An unchecked slice at [8..40]
        // returns the genuine secret shifted by one byte.
        let real_secret: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut short_form_der = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        short_form_der.extend_from_slice(&real_secret);
        short_form_der.push(0xFF); // padding so [8..40] is in-bounds
        let mut short_form_value = vec![short_form_der.len() as u8];
        short_form_value.extend_from_slice(&short_form_der);

        let pairs = vec![
            record("key", &[], &garbage_value),
            record("key", &[], &short_form_value),
        ];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert!(
            out.transparent.is_empty(),
            "neither malformed DER blob may produce a transparent key"
        );
        assert_eq!(out.diagnostics.len(), 2);
    }

    #[test]
    fn a_record_with_an_unparseable_key_is_reported() {
        // Claims a 64-byte record type name but the buffer only holds 2
        // bytes after the length prefix — parse_record_key returns None.
        let raw_key = vec![0x40, b'z', b'k'];
        let pairs = vec![(raw_key, vec![0x00])];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert!(out.transparent.is_empty());
        assert!(out.sprout.is_empty());
        assert!(out.sapling.is_empty());
        assert_eq!(
            out.diagnostics.len(),
            1,
            "the unparseable key must be reported"
        );
    }

    #[test]
    fn extracts_sprout_keys_from_the_golden_fixture() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);
        assert!(
            !out.sprout.is_empty(),
            "no Sprout keys from the real wallet"
        );
        assert!(!out.transparent.is_empty(), "no transparent keys");
    }
}
