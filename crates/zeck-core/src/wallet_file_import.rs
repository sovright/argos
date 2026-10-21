//! Network binding for wallet-file imports.

use argos_wallet_import::{EmbeddedNetwork, ImportDiagnostic, ImportError, ImportedKeys};
use secrecy::SecretString;

use crate::{ZeckError, ZeckNetwork, ZeckResult};

fn network_selection_matches(
    embedded: EmbeddedNetwork,
    selected: ZeckNetwork,
    allow_regtest: bool,
) -> bool {
    matches!(
        (embedded, selected),
        (EmbeddedNetwork::Mainnet, ZeckNetwork::Mainnet)
            | (EmbeddedNetwork::Testnet, ZeckNetwork::Testnet)
    ) || (allow_regtest
        && matches!(
            (embedded, selected),
            (EmbeddedNetwork::Regtest, ZeckNetwork::Testnet)
        ))
}

fn allow_regtest_wallet() -> bool {
    #[cfg(feature = "argos-network")]
    {
        crate::workspace::regtest_consensus_params_installed()
    }
    #[cfg(not(feature = "argos-network"))]
    {
        false
    }
}

/// Import and bind any known wallet network before an operational caller can scan.
pub fn import_wallet_file_for_network(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
    selected: ZeckNetwork,
) -> ZeckResult<ImportedKeys> {
    let keys = argos_wallet_import::import_wallet_file(bytes, passphrase)
        .map_err(ZeckError::WalletFile)?;
    // A file that names two networks leaves `embedded_network` unset, which
    // would otherwise pass under either selection.
    if let Some((first, second)) = keys.diagnostics.iter().find_map(|d| match d {
        ImportDiagnostic::ConflictingNetworkMetadata { first, second } => Some((*first, *second)),
        _ => None,
    }) {
        return Err(ZeckError::WalletFile(ImportError::ConflictingNetwork {
            first,
            second,
        }));
    }
    if let Some(embedded) = keys.embedded_network {
        if !network_selection_matches(embedded, selected, allow_regtest_wallet()) {
            let selected = match selected {
                ZeckNetwork::Mainnet => EmbeddedNetwork::Mainnet,
                ZeckNetwork::Testnet => EmbeddedNetwork::Testnet,
            };
            return Err(ZeckError::WalletFile(ImportError::NetworkMismatch {
                selected,
                embedded,
            }));
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZeckNetwork;
    use argos_wallet_import::EmbeddedNetwork;

    #[test]
    fn network_metadata_matrix_fails_closed() {
        use EmbeddedNetwork::{Mainnet, Regtest, Testnet};
        use ZeckNetwork::{Mainnet as SelectedMainnet, Testnet as SelectedTestnet};
        assert!(network_selection_matches(Mainnet, SelectedMainnet, false));
        assert!(!network_selection_matches(Mainnet, SelectedTestnet, false));
        assert!(!network_selection_matches(Testnet, SelectedMainnet, false));
        assert!(network_selection_matches(Testnet, SelectedTestnet, false));
        assert!(!network_selection_matches(Regtest, SelectedTestnet, false));
        assert!(network_selection_matches(Regtest, SelectedTestnet, true));
        assert!(!network_selection_matches(Regtest, SelectedMainnet, true));
    }

    #[test]
    fn wallet_file_import_rejects_wrong_embedded_network() {
        let bytes =
            include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-testnet-empty.dat");
        let result = import_wallet_file_for_network(bytes, None, ZeckNetwork::Mainnet);
        assert!(matches!(
            result,
            Err(crate::ZeckError::WalletFile(
                ImportError::NetworkMismatch { .. }
            ))
        ));
    }

    #[test]
    fn nonempty_block_and_sapling_note_history_still_reject_wrong_network() {
        let mut bytes =
            include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-testnet-txn.dat").to_vec();
        assert_eq!(bytes[285], 0);
        let mut note = Vec::new();
        note.extend_from_slice(&20u64.to_le_bytes());
        note.extend_from_slice(&vec![0u8; 169 + 11 + 8 + 33]);
        note.push(0);
        note.extend_from_slice(&0u64.to_le_bytes());
        note.extend_from_slice(&[0u8; 32]);
        note.extend_from_slice(&[0, 0, 0, 0, 0]);
        bytes[285] = 1;
        bytes.splice(286..286, note);

        assert_eq!(bytes[190], 0);
        let mut block = Vec::new();
        block.extend_from_slice(&419_200u32.to_le_bytes());
        block.extend_from_slice(&[0u8; 32]);
        block.extend_from_slice(&[0, 0, 0]);
        block.extend_from_slice(&20u64.to_le_bytes());
        block.push(0);
        bytes[190] = 1;
        bytes.splice(191..191, block);

        let err = import_wallet_file_for_network(&bytes, None, ZeckNetwork::Mainnet).unwrap_err();
        assert!(
            matches!(
                &err,
                ZeckError::WalletFile(ImportError::NetworkMismatch { .. })
            ) && err.to_string().contains("mainnet")
                && err.to_string().contains("testnet")
        );
    }

    #[test]
    fn damaged_tail_after_chain_name_still_rejects_wrong_network() {
        let bytes =
            include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-testnet-empty.dat");
        let err =
            import_wallet_file_for_network(&bytes[..bytes.len() - 1], None, ZeckNetwork::Mainnet)
                .unwrap_err();
        assert!(
            matches!(
                &err,
                ZeckError::WalletFile(ImportError::NetworkMismatch { .. })
            ) && err.to_string().contains("mainnet")
                && err.to_string().contains("testnet")
        );
    }

    #[test]
    fn readable_tkey_metadata_precedes_truncated_chain_name() {
        let truncated =
            include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat");
        // Byte 200 is just before the writer's u64 chain-name length in
        // this 256-byte fixture, after its complete Keys and Txns sections.
        let result = import_wallet_file_for_network(&truncated[..200], None, ZeckNetwork::Testnet);
        assert!(matches!(
            result,
            Err(ZeckError::WalletFile(ImportError::NetworkMismatch { .. }))
        ));

        let imported =
            import_wallet_file_for_network(&truncated[..200], None, ZeckNetwork::Mainnet).unwrap();
        assert_eq!(imported.embedded_network, Some(EmbeddedNetwork::Mainnet));
        assert_ne!(
            imported.coverage(),
            argos_wallet_import::ImportCoverage::Complete
        );

        // Before any complete key or chain_name, the selected network remains
        // unknown and partial key recovery is still allowed.
        let imported =
            import_wallet_file_for_network(&truncated[..80], None, ZeckNetwork::Testnet).unwrap();
        assert_eq!(imported.embedded_network, None);
    }

    #[test]
    fn regtest_wallet_requires_installed_local_params() {
        #[cfg(feature = "argos-network")]
        assert_eq!(
            allow_regtest_wallet(),
            crate::workspace::regtest_consensus_params_installed()
        );
        #[cfg(not(feature = "argos-network"))]
        assert!(!allow_regtest_wallet());

        let bytes = include_bytes!("../../argos-wallet-import/tests/fixtures/sprout-plaintext.dat");
        let result = import_wallet_file_for_network(bytes, None, ZeckNetwork::Testnet);
        assert_eq!(result.is_ok(), allow_regtest_wallet());
    }

    /// Review finding 4 on #275: a locked wallet is recognised by type,
    /// not by comparing error text, so the CLI and GUI can ask for a
    /// passphrase without depending on a message's wording.
    #[test]
    fn a_locked_wallet_is_a_typed_wrong_passphrase() {
        let bytes = include_bytes!("../../argos-wallet-import/tests/fixtures/modern-encrypted.dat");
        let err = import_wallet_file_for_network(bytes, None, ZeckNetwork::Mainnet).unwrap_err();
        assert!(
            matches!(err, ZeckError::WalletFile(ImportError::WrongPassphrase)),
            "{err:?}"
        );
        assert!(err.to_string().contains("passphrase"), "{err}");
    }

    /// Review finding 5 on #275: a file that names two networks used to
    /// leave `embedded_network` unset and so passed under either selection.
    /// Here the writer's mainnet transparent address sits under a chain name
    /// patched to `test`.
    #[test]
    fn conflicting_network_metadata_is_refused_under_every_selection() {
        let mut bytes =
            include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat")
                .to_vec();
        assert_eq!(&bytes[208..212], b"main");
        bytes[208..212].copy_from_slice(b"test");
        let parsed = argos_wallet_import::import_wallet_file(&bytes, None).unwrap();
        assert_eq!(parsed.embedded_network, None);
        assert!(parsed.diagnostics.iter().any(|d| matches!(
            d,
            argos_wallet_import::ImportDiagnostic::ConflictingNetworkMetadata { .. }
        )));
        for selected in [ZeckNetwork::Mainnet, ZeckNetwork::Testnet] {
            let err = import_wallet_file_for_network(&bytes, None, selected).unwrap_err();
            assert!(
                matches!(
                    err,
                    ZeckError::WalletFile(ImportError::ConflictingNetwork {
                        first: EmbeddedNetwork::Mainnet,
                        second: EmbeddedNetwork::Testnet,
                    })
                ),
                "{selected:?}: {err:?}"
            );
        }
    }
}
