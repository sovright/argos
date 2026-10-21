use thiserror::Error;

use crate::keys::{EmbeddedNetwork, Provenance};

/// Fatal conditions. These abort an entire import; everything
/// else is collected as an `ImportDiagnostic` so partial recovery still
/// yields the keys we could read.
#[derive(Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("this file is not a recognized Zcash wallet file")]
    UnrecognizedFormat,

    #[error("incorrect passphrase for this wallet")]
    WrongPassphrase,

    #[error("wallet file structure is unreadable: {0}")]
    UnwalkableBtree(String),

    #[error("wallet encryption metadata is damaged. Keep the original wallet file.")]
    DamagedEncryptionMetadata(String),

    #[error("selected {selected} network conflicts with wallet's embedded {embedded} network")]
    NetworkMismatch {
        selected: EmbeddedNetwork,
        embedded: EmbeddedNetwork,
    },
}

/// Non-fatal, per-record problems. Always surfaced to the user with counts
/// — never swallowed. Unmigrated key material still exists only in the
/// original file, so the user must know what we could not read.
#[derive(Error, PartialEq, Eq, Clone)]
pub enum ImportDiagnostic {
    #[error("skipped unparseable {record_type} record: {reason}")]
    UnparseableRecord { record_type: String, reason: String },

    #[error("skipped unknown record type {record_type}")]
    UnknownRecord { record_type: String },

    #[error("skipped {record_type} record: decryption failed ({reason})")]
    DecryptionFailed { record_type: String, reason: String },

    /// An HD seed Argos does not recover. Kept apart from `UnknownRecord`
    /// because it is the one skip that can hide an entire key tree: any
    /// address derived from it that the file does not also store as an
    /// individual key is invisible to the scan.
    #[error(
        "skipped {record_type} record: this is the wallet's HD seed, which Argos \
         does not recover — keys derived from it are only covered if the file \
         also stores them individually"
    )]
    UnrecoveredSeed { record_type: String },

    #[error("{format} wallet container is damaged at {location}: {reason}")]
    ContainerDamage {
        format: &'static str,
        location: String,
        reason: String,
    },

    #[error("unsupported {component} wallet version {found}; supported range is {minimum} through {maximum}")]
    UnsupportedWalletVersion {
        component: &'static str,
        found: u64,
        minimum: u64,
        maximum: u64,
    },

    #[error("stored public identifier does not match the recovered key; the mismatched record was not used")]
    PublicIdentifierMismatch {
        record_type: String,
        identifier: &'static str,
    },

    #[error("locked {record_type} key ({provenance:?}) could not be recovered")]
    LockedKey {
        record_type: String,
        provenance: Provenance,
    },

    #[error("{format} wallet has no recoverable spending authority")]
    MissingSpendAuthority { format: &'static str },

    #[error("wallet contains conflicting network metadata: {first} and {second}")]
    ConflictingNetworkMetadata {
        first: EmbeddedNetwork,
        second: EmbeddedNetwork,
    },

    #[error("{format} wallet network metadata is not recognized: {reason}")]
    UnrecognizedNetworkMetadata {
        format: &'static str,
        reason: &'static str,
    },
}

// Parser inputs may contain key or record bytes. Debug is routinely included
// in error logs, so it names the condition without rendering arbitrary fields.
impl std::fmt::Debug for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnrecognizedFormat => "UnrecognizedFormat",
            Self::WrongPassphrase => "WrongPassphrase",
            Self::UnwalkableBtree(_) => "UnwalkableBtree",
            Self::DamagedEncryptionMetadata(_) => "DamagedEncryptionMetadata",
            Self::NetworkMismatch { .. } => "NetworkMismatch",
        })
    }
}

impl std::fmt::Debug for ImportDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnparseableRecord { .. } => "UnparseableRecord",
            Self::UnknownRecord { .. } => "UnknownRecord",
            Self::DecryptionFailed { .. } => "DecryptionFailed",
            Self::UnrecoveredSeed { .. } => "UnrecoveredSeed",
            Self::ContainerDamage { .. } => "ContainerDamage",
            Self::UnsupportedWalletVersion { .. } => "UnsupportedWalletVersion",
            Self::PublicIdentifierMismatch { .. } => "PublicIdentifierMismatch",
            Self::LockedKey { .. } => "LockedKey",
            Self::MissingSpendAuthority { .. } => "MissingSpendAuthority",
            Self::ConflictingNetworkMetadata { .. } => "ConflictingNetworkMetadata",
            Self::UnrecognizedNetworkMetadata { .. } => "UnrecognizedNetworkMetadata",
        })
    }
}

impl ImportDiagnostic {
    pub fn is_unrecovered_seed(&self) -> bool {
        matches!(self, Self::UnrecoveredSeed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_passphrase_is_distinguishable_from_corruption() {
        let a = ImportError::WrongPassphrase;
        let b = ImportError::UnwalkableBtree("page 3 out of bounds".to_owned());
        assert_ne!(a.to_string(), b.to_string());
        assert!(a.to_string().contains("passphrase"));
        assert!(!b.to_string().contains("passphrase"));
    }

    #[test]
    fn diagnostic_records_what_was_skipped() {
        let d = ImportDiagnostic::UnparseableRecord {
            record_type: "czkey".to_owned(),
            reason: "truncated ciphertext".to_owned(),
        };
        assert!(d.to_string().contains("czkey"));
    }
}
