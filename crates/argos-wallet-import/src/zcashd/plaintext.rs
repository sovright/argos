//! Extraction of unencrypted zcashd key records.

use secrecy::Secret;

use crate::{
    error::ImportDiagnostic,
    identity,
    keys::{
        merge_embedded_network, unrecognized_network, EmbeddedNetwork, ImportedKeys, Provenance,
        SaplingKey, TransparentKey,
    },
    secret_bytes::SecretArray,
    zcashd::{
        metadata::{is_metadata_record, KeyMetadataIndex, MetadataKind},
        records::{compact_size, parse_record_key},
        RecoveredKeyIds,
    },
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
    "defaultkey",
    "minversion",
    "mnemonichdchain",
    "name",
    "orchard_note_commitment_tree",
    "orderposnext",
    "pool",
    "purpose",
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

fn networkinfo(value: &[u8]) -> Option<EmbeddedNetwork> {
    let (package_len, package_prefix) = compact_size(value)?;
    let package_end = package_prefix.checked_add(usize::try_from(package_len).ok()?)?;
    let package = std::str::from_utf8(value.get(package_prefix..package_end)?).ok()?;
    if package.is_empty() {
        return None;
    }
    let rest = value.get(package_end..)?;
    let (network_len, network_prefix) = compact_size(rest)?;
    let network_end = network_prefix.checked_add(usize::try_from(network_len).ok()?)?;
    if network_end != rest.len() {
        return None;
    }
    let name = std::str::from_utf8(rest.get(network_prefix..network_end)?).ok()?;
    match name {
        "main" | "mainnet" => Some(EmbeddedNetwork::Mainnet),
        "test" | "testnet" => Some(EmbeddedNetwork::Testnet),
        "regtest" => Some(EmbeddedNetwork::Regtest),
        _ => None,
    }
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
/// Returns which transparent and Sapling keys were actually recovered.
pub fn collect_plaintext(
    pairs: &[crate::bdb::RawRecord],
    out: &mut ImportedKeys,
) -> RecoveredKeyIds {
    let mut recovered = RecoveredKeyIds::default();
    // Unreadable metadata is reported from here and not from
    // `collect_encrypted`, which builds the same index: this collector runs
    // for every zcashd wallet, so each damaged record is reported once.
    let metadata = KeyMetadataIndex::build(pairs, Some(&mut out.diagnostics));
    for record in pairs {
        let raw_key = &record.key;
        let value = record.value();
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
            "networkinfo" => match networkinfo(value) {
                Some(network) => merge_embedded_network(out, network),
                None => unrecognized_network(out, "zcashd", "invalid networkinfo value"),
            },
            // Sprout has no spend format after NU7. Recognize the record
            // type only; never parse or decrypt its spending material.
            "zkey" | "czkey" => out.sprout_records += 1,
            // Verified against the fixtures: the value is a raw 169-byte
            // extended spending key with NO length prefix — depth(1) +
            // parent_fvk_tag(4) + child_index(4) + chain_code(32) +
            // expsk(96) + dk(32). The key remainder is the 32-byte IVK.
            "sapzkey" => match value.get(..169) {
                Some(extsk) if identity::sapling_matches_ivk(extsk, &rec.rest) => {
                    out.sapling.push(SaplingKey {
                        extsk: Secret::new(extsk.to_vec()),
                        provenance: Provenance::Standalone,
                        created_at: metadata.created_at(MetadataKind::Sapling, &rec.rest),
                    });
                    recovered.sapling.insert(rec.rest);
                }
                Some(_) => out
                    .diagnostics
                    .push(ImportDiagnostic::PublicIdentifierMismatch {
                        record_type: "sapzkey".to_owned(),
                        identifier: "incoming viewing key",
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
                        Ok(secret) => {
                            let public_key = read_length_prefixed(&rec.rest);
                            let secret = SecretArray::new(secret);
                            if let Some(secret) = public_key.and_then(|public_key| {
                                identity::retain_transparent_secret(secret, public_key)
                            }) {
                                out.transparent.push(TransparentKey {
                                    secret,
                                    provenance: Provenance::HdDerived,
                                    created_at: metadata
                                        .created_at(MetadataKind::Transparent, &rec.rest),
                                });
                                recovered.transparent.insert(rec.rest);
                            } else {
                                out.diagnostics
                                    .push(ImportDiagnostic::PublicIdentifierMismatch {
                                        record_type: "key".to_owned(),
                                        identifier: "public key",
                                    });
                            }
                        }
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
            "ckey" | "csapzkey" | "mkey" | "hdchain" | "sapzaddr" => {}
            // Read into `metadata` above, and by `seed` for coverage.
            other if is_metadata_record(other) => {}
            // Assessed as a whole, with the master key in hand, by `seed`.
            other if super::seed::SEED_RECORDS.contains(&other) => {}
            other if IGNORED.contains(&other) => {}
            other => out.diagnostics.push(ImportDiagnostic::UnknownRecord {
                record_type: other.to_owned(),
            }),
        }
    }
    recovered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, key_rest: &[u8], value: &[u8]) -> crate::bdb::RawRecord {
        let mut k = vec![kind.len() as u8];
        k.extend_from_slice(kind.as_bytes());
        k.extend_from_slice(key_rest);
        crate::bdb::RawRecord::new(k, value.to_vec())
    }

    fn network_value(package: &str, network: &str) -> Vec<u8> {
        let mut value = vec![package.len() as u8];
        value.extend_from_slice(package.as_bytes());
        value.push(network.len() as u8);
        value.extend_from_slice(network.as_bytes());
        value
    }

    #[test]
    fn networkinfo_recognizes_exact_network_aliases() {
        for (name, expected) in [
            ("main", crate::keys::EmbeddedNetwork::Mainnet),
            ("mainnet", crate::keys::EmbeddedNetwork::Mainnet),
            ("test", crate::keys::EmbeddedNetwork::Testnet),
            ("testnet", crate::keys::EmbeddedNetwork::Testnet),
            ("regtest", crate::keys::EmbeddedNetwork::Regtest),
        ] {
            let mut out = ImportedKeys::default();
            collect_plaintext(
                &[record("networkinfo", &[], &network_value("zcashd", name))],
                &mut out,
            );
            assert_eq!(out.embedded_network, Some(expected), "{name}");
        }
    }

    #[test]
    fn networkinfo_malformed_and_conflicting_records_never_claim_a_match() {
        for bad in [vec![3, b'a'], network_value("zcashd", "mainish")] {
            let mut out = ImportedKeys::default();
            collect_plaintext(&[record("networkinfo", &[], &bad)], &mut out);
            assert_eq!(out.embedded_network, None);
            assert!(out
                .diagnostics
                .iter()
                .any(|d| matches!(d, ImportDiagnostic::UnrecognizedNetworkMetadata { .. })));
        }
        let main = record("networkinfo", &[], &network_value("zcashd", "main"));
        let test = record("networkinfo", &[], &network_value("zcashd", "test"));
        let mut matching = ImportedKeys::default();
        collect_plaintext(
            &[
                record("networkinfo", &[], &network_value("zcashd", "main")),
                record("networkinfo", &[], &network_value("zcashd", "main")),
            ],
            &mut matching,
        );
        assert_eq!(
            matching.embedded_network,
            Some(crate::keys::EmbeddedNetwork::Mainnet)
        );
        let mut conflict = ImportedKeys::default();
        collect_plaintext(&[main, test], &mut conflict);
        assert_eq!(conflict.embedded_network, None);
        assert!(conflict
            .diagnostics
            .iter()
            .any(|d| matches!(d, ImportDiagnostic::ConflictingNetworkMetadata { .. })));
    }

    #[test]
    fn mismatched_plaintext_transparent_key_drops_temporary_owner() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let bytes = std::fs::read("tests/fixtures/modern-plaintext.dat").unwrap();
        let mut record = crate::bdb::walk(&bytes)
            .unwrap()
            .records
            .into_iter()
            .find(|record| {
                parse_record_key(&record.key).is_some_and(|parsed| parsed.record_type == "key")
            })
            .expect("fixture has a transparent key");
        *record.key.last_mut().unwrap() ^= 1;
        let dropped = Arc::new(AtomicBool::new(false));
        let mut out = ImportedKeys::default();
        SecretArray::<32>::test_with_drop_probe(Arc::clone(&dropped), || {
            collect_plaintext(&[record], &mut out);
        });
        assert!(out.transparent.is_empty());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn unknown_record_types_are_reported_not_silently_dropped() {
        // "bestblock" is a real, expected zcashd record type (in IGNORED);
        // use a type no real wallet produces so this actually exercises
        // the unknown-type path.
        let pairs = vec![record("not_a_real_record_type", &[], &[0x01])];
        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);
        assert_eq!(out.sprout_records, 0);
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
        let pairs = vec![crate::bdb::RawRecord::new(raw_key, vec![0x00])];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert!(out.transparent.is_empty());
        assert_eq!(out.sprout_records, 0);
        assert!(out.sapling.is_empty());
        assert_eq!(
            out.diagnostics.len(),
            1,
            "the unparseable key must be reported"
        );
    }

    #[test]
    fn recognizes_retired_sprout_records_in_a_mixed_wallet() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap().records;
        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);
        assert!(
            out.sprout_records > 0,
            "no retired Sprout records recognized"
        );
        assert!(!out.transparent.is_empty(), "no transparent keys");
    }
}
