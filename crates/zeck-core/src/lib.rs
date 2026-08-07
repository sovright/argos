pub mod address;
pub mod birthday;
pub mod derivation;
pub mod donation;
pub mod error;
pub mod imported;
pub mod imported_sweep;
pub mod key_source;
pub mod lightwalletd;
pub mod models;
// Transfer-based funding for the regtest harness. Test-only: a released
// binary must contain no code that spends from a hardcoded seed.
#[cfg(feature = "argos-network")]
pub mod regtest_funding;
pub mod scan;
pub mod service;
// Sprout key derivation and note decryption. Needed to spend a Sprout note:
// the proving circuit wants value/rho/r, and the wallet stores none of them.
pub mod sprout;
// The Sprout commitment tree, and the 966-byte authentication path the
// JoinSplit prover parses. Needed because a cached wallet witness is the only
// path source available without a full node.
pub mod sprout_witness;
// JoinSplit assembly and the V4 transaction carrying it. zcash_primitives'
// builder refuses Sprout, so this goes through the public low-level surfaces.
pub mod sprout_spend;
// Joins a wallet's note records to the JoinSplit ciphertexts that carry
// their plaintexts, which is the only place value/rho/r exist.
pub mod sprout_recovery;
// Finds Sprout notes by rebuilding the commitment tree from full blocks,
// for a wallet that has a spending key and no note metadata at all.
pub mod sprout_scan;
// Direct p2p access. Sprout notes are invisible to lightwalletd -- compact
// blocks carry no JoinSplits -- so finding one needs full blocks.
pub mod p2p;
// What a Sprout scan costs in time, bandwidth and disk, and the wording
// that tells the user -- shared so the CLI and GUI cannot drift apart.
pub mod sprout_scan_cost;
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
