//! Rust-side fixture for the C2 integration tests.
//!
//! Reads the harness URL and funded test seed from environment variables
//! set by `tests/regtest/setup.sh`. Each integration test calls
//! `RegtestHarness::require()` at the top; if the env vars are absent the
//! test prints a clear "harness not running" message and panics — which is
//! intentionally caught by the `#[ignore]` tag on every C2 test so default
//! `cargo test` never sees the panic.
//!
//! See `tests/regtest/README.md` for the boot procedure.

use std::env;

/// Argos test seed (BIP-39 test vector — no real funds anywhere).
///
/// Matches the seed funded by `tests/regtest/setup.sh`. Centralised here so
/// the integration tests and the funding script agree on the same string.
pub const ARGOS_TEST_SEED: &str =
    "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon art";

/// Environment variable holding the lightwalletd endpoint of the running
/// harness. Set by `tests/regtest/setup.sh`; consumed by every C2 test.
pub const ENV_LIGHTWALLETD_URL: &str = "ARGOS_REGTEST_LIGHTWALLETD_URL";

/// Environment variable holding the funded test seed's transparent address.
/// Set by `tests/regtest/setup.sh` after the funding `sendtoaddress`.
/// Optional — tests that only need the lightwalletd endpoint don't have to
/// require it.
pub const ENV_TEST_T_ADDR: &str = "ARGOS_REGTEST_TEST_T_ADDR";

/// A handle on the running regtest stack.
///
/// Construction is deliberately fail-loud: if the environment isn't set up,
/// calling `RegtestHarness::require()` panics with a message pointing to
/// `tests/regtest/README.md` so a contributor running `cargo test
/// --ignored` without the harness sees what to do next.
#[derive(Debug, Clone)]
pub struct RegtestHarness {
    lightwalletd_url: String,
    funded_t_addr: Option<String>,
}

impl RegtestHarness {
    /// Read the harness configuration from the environment, panicking if the
    /// required variables aren't set. Integration tests call this at the
    /// top of `#[test]` so a missing harness is loud and obvious — combined
    /// with `#[ignore]`, the panic stays out of CI.
    pub fn require() -> Self {
        let lightwalletd_url = env::var(ENV_LIGHTWALLETD_URL).unwrap_or_else(|_| {
            panic!(
                "{ENV_LIGHTWALLETD_URL} is not set. \
                 Boot the regtest harness (`cd tests/regtest && docker compose up -d && ./setup.sh`) \
                 and export the lightwalletd URL it prints. \
                 See tests/regtest/README.md.",
            )
        });
        // Install regtest activation heights before the caller derives a
        // branch ID, builds a transaction, or opens a workspace.
        //
        // This lives here rather than in individual tests because
        // `REGTEST_PARAMS` is a process-wide `OnceLock` and cargo runs a
        // test binary's tests as threads in one process. When only one test
        // installed the parameters, whether any *other* test saw them
        // depended on thread scheduling: a sweep could be signed for a
        // pre-NU5 branch and rejected by the node, or a scan could resolve
        // the wrong activation heights, entirely at random
        // (sovright/argos#186).
        //
        // Every regtest test calls `require()`, so installing here makes it
        // deterministic and impossible to forget in a new test. The
        // underlying setter is idempotent for an equal value, so repeated
        // calls across tests are fine.
        #[cfg(feature = "argos-network")]
        argos_core::workspace::set_regtest_consensus_params(
            argos_core::workspace::regtest_local_network(),
        )
        .expect("installing regtest consensus parameters");

        let funded_t_addr = env::var(ENV_TEST_T_ADDR).ok();
        Self {
            lightwalletd_url,
            funded_t_addr,
        }
    }

    /// The lightwalletd endpoint to pass to `RecoveryService::start_scan`'s
    /// `ScanConfig.lightwalletd_url`. Loopback-only (`http://localhost:9067`
    /// by default) and Argos's `validate_lightwalletd_endpoint` accepts the
    /// plaintext form because it's a loopback host.
    pub fn lightwalletd_url(&self) -> &str {
        &self.lightwalletd_url
    }

    /// The funded test seed's transparent address. Returns `None` if the
    /// optional env var wasn't exported (tests that only verify the scan
    /// side don't need it; tests that verify funding amounts do).
    pub fn funded_t_addr(&self) -> Option<&str> {
        self.funded_t_addr.as_deref()
    }

    /// The Argos test seed phrase. Same value as `ARGOS_TEST_SEED` —
    /// exposed as a method so future evolution (e.g. multiple test seeds
    /// for different scenarios) doesn't require changing every test's
    /// import.
    pub fn test_seed(&self) -> &'static str {
        ARGOS_TEST_SEED
    }
}
