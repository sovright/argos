// Shared test helpers for the C2 integration tests under
// `crates/zeck-core/tests/`. See `regtest_harness.rs` for the regtest
// fixture; this module exists so cargo's test runner doesn't compile
// `common/` as its own integration target (it would, if `common/`
// contained a top-level `tests/common.rs`).

pub mod regtest_harness;

// The transparent key the transparent-only sweep test owns outright, kept
// here so `argos-regtest-funder` and the test derive the same address.
pub mod standalone_transparent;

// `FakeLightwalletd` is the in-process gRPC test fixture used by the bad-
// network C2 tests (R-N8, R-N9). It depends on tonic server codegen run by
// `build.rs`, which only fires under the `argos-network` feature, so it is
// also gated on that feature here.
#[cfg(feature = "argos-network")]
pub mod fake_lightwalletd;

// Subprocess driver for the `argos-scan-helper` and `argos-sweep-helper`
// binaries that R-S27 / R-S29 spawn so the test parent can deliver SIGKILL
// at a chosen point. Both helpers are themselves `required-features =
// ["argos-network"]`, so the driver matches that gate.
#[cfg(feature = "argos-network")]
pub mod subprocess_driver;

// TCP-level failover proxy used by R-N16 to simulate DNS resolution drift
// (same lightwalletd_url, different backend on retry).
#[cfg(feature = "argos-network")]
pub mod tcp_failover_proxy;
