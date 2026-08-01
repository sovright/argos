pub mod address;
pub mod birthday;
pub mod derivation;
pub mod donation;
pub mod error;
pub mod imported;
pub mod key_source;
pub mod lightwalletd;
pub mod models;
pub mod scan;
pub mod service;
pub mod tos;
pub mod transparent_recovery;
pub mod workspace;

pub use address::validate_destination_address;
pub use birthday::{detect_birthday, estimate_birthday_from_date};
pub use derivation::{derive_accounts, validate_mnemonic_words};
pub use donation::{
    donation_for_send_amount, donation_memo_body, feature_enabled as donation_enabled,
    validate_donation_rate, validate_donor_email, DEFAULT_DONATION_RATE, DONATION_ADDRESS,
    DONATION_MEMO_TAG, MAX_DONOR_EMAIL_BYTES, MIN_DONATION_ZATOSHIS,
};
pub use error::{ZeckError, ZeckResult};
pub use key_source::{ImportedKeySource, KeySource, KeySourceFingerprint, SeedKeySource};

/// Re-exported so front-ends can read a wallet file without taking a
/// direct dependency on the parser crate.
pub use argos_wallet_import;
pub use models::*;
pub use service::RecoveryService;
pub use tos::{
    is_accepted as is_tos_accepted, record_acceptance as record_tos_acceptance, terms_text,
    TosAcceptance, TOS_VERSION,
};
pub use workspace::{
    list_incomplete_sessions, parse_workspace_keying, verify_seed_for_workspace, IncompleteSession,
    SessionMetadata, WorkspaceKeying,
};
