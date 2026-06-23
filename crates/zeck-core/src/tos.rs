//! Mandatory Terms of Service acceptance.
//!
//! Single source of truth for the Argos Terms of Service text, its version, and
//! the on-disk record of a user's acceptance. Both the GUI and CLI gate use
//! this module so the terms, version, and acceptance semantics never diverge.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ZeckError, ZeckResult};

/// Current Terms of Service version.
///
/// Bump this whenever `assets/terms-of-service.md` changes in substance: the
/// acceptance record is keyed on it, so a new version re-prompts every user.
/// Derived from the source document's `260608` revision marker.
pub const TOS_VERSION: &str = "2026-06-08";

/// Verbatim Terms of Service text, embedded at compile time so it is always
/// available offline.
const TERMS_MARKDOWN: &str = include_str!("../assets/terms-of-service.md");

/// File name of the acceptance record, written under a caller-supplied base
/// directory (the GUI app-data dir, or the CLI `--data-dir`).
const ACCEPTANCE_FILE: &str = "tos-acceptance.json";

/// The full Terms of Service text.
pub fn terms_text() -> &'static str {
    TERMS_MARKDOWN
}

/// On-disk record that a user accepted a specific TOS version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TosAcceptance {
    pub version: String,
    pub accepted_at_unix: i64,
}

/// Whether the current [`TOS_VERSION`] has been accepted under `base_dir`.
///
/// Returns `false` on any error (missing/unreadable/corrupt record) or when the
/// recorded version differs from the current one — i.e. it fails closed toward
/// re-prompting, never toward skipping the gate.
pub fn is_accepted(base_dir: &Path) -> bool {
    let path = base_dir.join(ACCEPTANCE_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<TosAcceptance>(&bytes) {
            Ok(record) => record.version == TOS_VERSION,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Record acceptance of the current [`TOS_VERSION`] under `base_dir`.
///
/// `accepted_at_unix` is supplied by the caller (Unix seconds) so this stays
/// free of an ambient clock dependency. Creates `base_dir` if needed.
pub fn record_acceptance(base_dir: &Path, accepted_at_unix: i64) -> ZeckResult<()> {
    std::fs::create_dir_all(base_dir).map_err(|err| {
        ZeckError::Storage(format!(
            "creating directory for TOS acceptance record {}: {err}",
            base_dir.display()
        ))
    })?;
    let record = TosAcceptance {
        version: TOS_VERSION.to_owned(),
        accepted_at_unix,
    };
    let json = serde_json::to_vec_pretty(&record)
        .map_err(|err| ZeckError::Serialization(format!("serializing TOS acceptance: {err}")))?;
    let path = base_dir.join(ACCEPTANCE_FILE);
    std::fs::write(&path, json).map_err(|err| {
        ZeckError::Storage(format!(
            "writing TOS acceptance record {}: {err}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_text_is_nonempty_and_starts_with_the_title() {
        let text = terms_text();
        assert!(text.len() > 1_000, "embedded terms should be substantial");
        assert!(text.contains("Argos Wallet Rescue Terms of Service"));
    }

    #[test]
    fn unaccepted_dir_reports_not_accepted() {
        let dir = std::env::temp_dir().join(format!("argos-tos-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!is_accepted(&dir));
    }

    #[test]
    fn recorded_acceptance_round_trips() {
        let dir = std::env::temp_dir().join(format!("argos-tos-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!is_accepted(&dir));
        record_acceptance(&dir, 1_700_000_000).expect("record");
        assert!(is_accepted(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn acceptance_of_a_different_version_does_not_satisfy_current() {
        let dir = std::env::temp_dir().join(format!("argos-tos-ver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stale = serde_json::to_vec(&TosAcceptance {
            version: "1900-01-01".to_owned(),
            accepted_at_unix: 1,
        })
        .unwrap();
        std::fs::write(dir.join(ACCEPTANCE_FILE), stale).unwrap();
        // A record for an old version must re-prompt (fail closed).
        assert!(!is_accepted(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
