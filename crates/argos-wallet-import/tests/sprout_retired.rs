use argos_wallet_import::{bdb::RawRecord, keys::ImportedKeys, zcashd::collect_plaintext};

#[test]
fn retired_sprout_records_are_recognized_without_parsing_secret_values() {
    let records = ["zkey", "czkey"].map(|kind| {
        let mut key = vec![kind.len() as u8];
        key.extend_from_slice(kind.as_bytes());
        RawRecord::new(key, vec![0xA5])
    });
    let mut imported = ImportedKeys::default();
    collect_plaintext(&records, &mut imported);
    assert_eq!(imported.sprout_records, 2);
    assert!(imported.is_empty());
    assert_eq!(imported.total_keys(), 0);
    assert!(
        imported.diagnostics.is_empty(),
        "retired records do not hide supported keys: {:?}",
        imported.diagnostics
    );
}

#[test]
fn mixed_wallets_keep_transparent_and_sapling_keys_and_report_retired_records() {
    use argos_wallet_import::{keys::SPROUT_UNSPENDABLE_NOTICE, zcashd::import_zcashd};
    use secrecy::SecretString;
    for fixture in ["sprout-plaintext", "sprout-encrypted"] {
        let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat")).unwrap();
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let keys = import_zcashd(&bytes, Some(&pass)).unwrap();
        assert_eq!(keys.sprout_records, 1, "{fixture}");
        assert!(!keys.transparent.is_empty(), "{fixture}");
        assert!(!keys.sapling.is_empty(), "{fixture}");
        assert_eq!(
            keys.total_keys(),
            keys.transparent.len() + keys.sapling.len()
        );
        assert!(SPROUT_UNSPENDABLE_NOTICE.contains("unspendable"));
        assert!(SPROUT_UNSPENDABLE_NOTICE.contains("NU7"));
    }
}

#[test]
fn retired_ciphertext_does_not_require_a_master_key() {
    use argos_wallet_import::zcashd::{classify_encryption, EncryptionMetadata};
    let mut key = vec![5];
    key.extend_from_slice(b"czkey");
    let records = [RawRecord::new(key, vec![0xA5])];
    assert!(matches!(
        classify_encryption(&records),
        EncryptionMetadata::Unencrypted
    ));
}
