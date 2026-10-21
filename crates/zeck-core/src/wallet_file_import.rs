//! Network binding for wallet-file imports.

use argos_wallet_import::{EmbeddedNetwork, ImportError, ImportedKeys};
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
        .map_err(|err| ZeckError::Import(err.to_string()))?;
    if let Some(embedded) = keys.embedded_network {
        if !network_selection_matches(embedded, selected, allow_regtest_wallet()) {
            let selected = match selected {
                ZeckNetwork::Mainnet => EmbeddedNetwork::Mainnet,
                ZeckNetwork::Testnet => EmbeddedNetwork::Testnet,
            };
            return Err(ZeckError::Import(
                ImportError::NetworkMismatch { selected, embedded }.to_string(),
            ));
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
        assert!(
            matches!(result, Err(crate::ZeckError::Import(message)) if message.contains("mainnet") && message.contains("testnet"))
        );
    }

    #[test]
    fn malformed_or_absent_metadata_never_claims_a_match() {
        let truncated =
            include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat");
        // Byte 200 is just before the writer's u64 chain-name length in
        // this 256-byte fixture, after its complete Keys and Txns sections.
        let imported =
            import_wallet_file_for_network(&truncated[..200], None, ZeckNetwork::Testnet).unwrap();
        assert_eq!(imported.embedded_network, None);
        assert_ne!(
            imported.coverage(),
            argos_wallet_import::ImportCoverage::Complete
        );

        let imported =
            import_wallet_file_for_network(&truncated[..200], None, ZeckNetwork::Mainnet).unwrap();
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
}
