//! Read-only parsing of legacy Zcash wallet files into normalized key
//! material.
//!
//! This crate consumes attacker-controlled bytes. It has no network
//! access, performs no filesystem writes, and does not depend on
//! `argos-core`. The blast radius of a parser bug here is "garbage
//! records", not "key exfiltration".

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
// Crate-root `deny` reaches `#[cfg(test)]` modules too, and tests
// legitimately unwrap, index, and panic on known-good fixture data. The
// gate above still binds all non-test code, which is the code that
// touches attacker-controlled bytes.
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

pub mod bdb;
pub mod error;
pub mod keys;
pub mod sniff;
pub mod zcashd;

pub use error::{ImportDiagnostic, ImportError};
pub use keys::{ImportedKeys, Provenance};
pub use sniff::{sniff, WalletFormat};
