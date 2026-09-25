use thiserror::Error;

/// Fatal conditions. Only these three abort an entire import; everything
/// else is collected as an `ImportDiagnostic` so partial recovery still
/// yields the keys we could read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("this file is not a recognized Zcash wallet file")]
    UnrecognizedFormat,

    #[error("incorrect passphrase for this wallet")]
    WrongPassphrase,

    #[error("wallet file structure is unreadable: {0}")]
    UnwalkableBtree(String),
}

/// Non-fatal, per-record problems. Always surfaced to the user with counts
/// — never swallowed. Unmigrated key material still exists only in the
/// original file, so the user must know what we could not read.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
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
