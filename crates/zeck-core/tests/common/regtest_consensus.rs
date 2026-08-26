//! Regtest consensus parameters for the helper *subprocesses*.
//!
//! `RegtestHarness::require()` installs these for the test binary, but
//! `REGTEST_PARAMS` is a process-wide `OnceLock` and the helpers run as
//! separate processes, so they inherit nothing. Without this they fail at
//! the first network call with
//!
//! ```text
//! server Sapling activation height 1 does not match expected 280000 for testnet
//! ```
//!
//! which is the original symptom in issue #186 — fixed for in-process tests,
//! and left behind here because nothing in a subprocess had a reason to call
//! the fix.
//!
//! Installed unconditionally rather than behind an env var, unlike the CLI's
//! equivalent. These binaries are `required-features = ["argos-network"]`
//! test helpers that exist only to be driven by the regtest harness; there
//! is no other chain for them to run against, so a switch would only add a
//! way to forget it.
pub fn install_regtest_consensus_params() {
    argos_core::workspace::set_regtest_consensus_params(
        argos_core::workspace::regtest_local_network(),
    )
    .expect("regtest consensus parameters must install in a fresh helper process");
}
