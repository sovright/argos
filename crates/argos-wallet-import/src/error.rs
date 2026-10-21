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

    #[error("{format} wallet container is damaged at {}: {}", safe_damage_location(.location), safe_damage_reason(.reason))]
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

    #[error("{}", locked_key_guidance(.provenance))]
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

// These strings can originate near attacker-controlled wallet bytes. Only
// canonical parser coordinates and known structural reasons may reach Display.
// Future parsers can add their own fixed field/reason labels here; arbitrary
// record values fall back to a generic message rather than entering logs.
fn safe_damage_location(raw: &str) -> String {
    let words: Vec<&str> = raw.split_ascii_whitespace().collect();
    match words.as_slice() {
        ["page", page] if safe_coordinate(page) => format!("page {page}"),
        ["page", page, "slot", slot] if safe_coordinate(page) && safe_coordinate(slot) => {
            format!("page {page} slot {slot}")
        }
        ["overflow", "page", page] if safe_coordinate(page) => {
            format!("overflow page {page}")
        }
        ["byte", offset] if safe_coordinate(offset) => format!("byte {offset}"),
        ["byte", offset, field] if safe_coordinate(offset) && safe_field(field) => {
            format!("byte {offset} {field}")
        }
        ["byte", offset, "field", field] if safe_coordinate(offset) && safe_field(field) => {
            format!("byte {offset} field {field}")
        }
        _ => "an unknown location".to_owned(),
    }
}

fn safe_coordinate(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn safe_field(field: &str) -> bool {
    matches!(
        field,
        "external_version"
            | "keys_version"
            | "enc_seed"
            | "nonce"
            | "seed"
            | "okeys"
            | "zkeys"
            | "tkeys"
            | "okey"
            | "zkey"
            | "tkey"
            | "address"
            | "key"
            | "value"
            | "header"
            | "vector"
    )
}

fn safe_damage_reason(raw: &str) -> &'static str {
    match raw {
        "entry extends past the page" => "entry extends past the page",
        "page header is truncated" => "page header is truncated",
        "page offset is out of bounds" => "page offset is out of bounds",
        "unexpected page type" => "unexpected page type",
        "leaf entry is truncated" => "leaf entry is truncated",
        "overflow chain is truncated" => "overflow chain is truncated",
        "overflow chain ended early" => "overflow chain ended early",
        "page visit limit exceeded" => "page visit limit exceeded",
        "record limit exceeded" => "record limit exceeded",
        "value length limit exceeded" => "value length limit exceeded",
        "truncated field" => "truncated field",
        "unexpected end of file" => "unexpected end of file",
        _ => "wallet structure could not be read",
    }
}

fn locked_key_guidance(provenance: &Provenance) -> &'static str {
    match provenance {
        Provenance::HdDerived => {
            "locked HD-derived key could not be recovered; recover the wallet seed to recreate it"
        }
        Provenance::Standalone => {
            "locked standalone key could not be recovered and cannot be recreated from the seed"
        }
    }
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

    #[test]
    fn container_damage_display_redacts_untrusted_location_and_reason() {
        let diagnostic = ImportDiagnostic::ContainerDamage {
            format: "Berkeley DB",
            location: "page 4 slot 3 record-value-marker-4c93".to_owned(),
            reason: "entry extends past the page ciphertext-marker-1a72".to_owned(),
        };
        let message = diagnostic.to_string();
        assert!(!message.contains("record-value-marker-4c93"), "{message}");
        assert!(!message.contains("ciphertext-marker-1a72"), "{message}");

        let safe = ImportDiagnostic::ContainerDamage {
            format: "Berkeley DB",
            location: "page 4 slot 3".to_owned(),
            reason: "entry extends past the page".to_owned(),
        }
        .to_string();
        assert!(safe.contains("page 4 slot 3"), "{safe}");
        assert!(safe.contains("entry extends past the page"), "{safe}");
    }

    #[test]
    fn locked_key_display_redacts_record_type_and_distinguishes_provenance() {
        let standalone = ImportDiagnostic::LockedKey {
            record_type: "record-value-marker-48bc".to_owned(),
            provenance: Provenance::Standalone,
        }
        .to_string();
        assert!(
            !standalone.contains("record-value-marker-48bc"),
            "{standalone}"
        );
        assert!(
            standalone.contains("cannot be recreated from the seed"),
            "{standalone}"
        );

        let hd = ImportDiagnostic::LockedKey {
            record_type: "ciphertext-marker-7b1e".to_owned(),
            provenance: Provenance::HdDerived,
        }
        .to_string();
        assert!(!hd.contains("ciphertext-marker-7b1e"), "{hd}");
        assert!(hd.contains("HD-derived"), "{hd}");
        assert_ne!(standalone, hd);
    }
}
