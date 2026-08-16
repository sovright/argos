//! The `--wallet-file` scan path, driven through the real binary against a
//! live regtest chain.
//!
//! `wallet_file_cli.rs` covers everything about this surface that can be
//! checked without a node. What it cannot reach is the part that only exists
//! once a network is involved: whether the imported key source actually
//! arrives at the scanner, whether lightwalletd network validation accepts
//! the harness, and whether an imported wallet with no HD seed survives a
//! real sync instead of tripping the account-enumeration path meant for
//! seeds.
//!
//! Requires the regtest harness. Run it the same way as the core suite:
//!
//! ```text
//! cd tests/regtest && docker compose up -d && ./setup.sh
//! export ARGOS_REGTEST_LIGHTWALLETD_URL=http://localhost:9067
//! cargo test -p argos-cli --features argos-network -- --ignored
//! ```
#![cfg(feature = "argos-network")]

use std::path::PathBuf;
use std::process::{Command, Stdio};

const SPROUT_PLAINTEXT: &str = "sprout-plaintext.dat";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../argos-wallet-import/tests/fixtures")
        .join(name)
}

fn harness_url() -> String {
    std::env::var("ARGOS_REGTEST_LIGHTWALLETD_URL").unwrap_or_else(|_| {
        panic!(
            "ARGOS_REGTEST_LIGHTWALLETD_URL is not set. Boot the harness \
             (`cd tests/regtest && docker compose up -d && ./setup.sh`) and \
             export the URL it prints. See tests/regtest/README.md."
        )
    })
}

/// Run `argos` against the regtest chain with stdin closed.
///
/// `ARGOS_REGTEST_CONSENSUS` is what makes the binary evaluate regtest
/// activation heights. It only has an effect because this test builds the
/// crate with `argos-network`; a released build has no such code path.
fn argos_regtest(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_argos"))
        .args(args)
        .env("ARGOS_REGTEST_CONSENSUS", "1")
        .stdin(Stdio::null())
        .output()
        .expect("argos binary should run")
}

/// A seedless zcashd wallet scans through the CLI against a real chain.
///
/// The assertions are structural rather than balance-based on purpose. The
/// core suite's imported sweep spends this same fixture, so whether it still
/// holds funds depends on what else has run against the chain. What must
/// hold regardless is that the CLI reaches the network, is accepted by it,
/// and completes a scan of a wallet that has no HD seed to enumerate.
#[test]
#[ignore = "requires the regtest harness; see the module docs"]
fn a_seedless_wallet_file_scans_through_the_cli() {
    let path = fixture(SPROUT_PLAINTEXT);
    assert!(
        path.exists(),
        "golden fixture is missing: {}",
        path.display()
    );

    let data_dir = std::env::temp_dir().join("argos-regtest-cli-scan");
    let _ = std::fs::remove_dir_all(&data_dir);

    let url = harness_url();
    let out = argos_regtest(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--lightwalletd-url",
        &url,
        "--network",
        "testnet",
        "--data-dir",
        data_dir.to_str().expect("temp dir is UTF-8"),
        // Genesis: the harness funds near height 0, because the regtest
        // subsidy has decayed to nothing by the heights ZIP 212 forces the
        // PCZT tests to. A later birthday would scan straight past the money.
        "--birthday",
        "1",
        "--accept-tos",
        "scan",
    ]);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "scan against the regtest harness failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    // Which path the CLI took, read off the one banner that differs between
    // them. The imported-account path scans Sapling and transparent together
    // and so warns only about Sprout; the transparent-only path warns that
    // it covers transparent alone. This fixture has Sapling keys, so routing
    // it to the transparent-only path would silently skip a whole pool.
    assert!(
        stderr.contains("SPROUT FUNDS ARE NOT COVERED"),
        "a seedless wallet with Sapling keys must take the imported-account \
         path\n--- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("THIS COVERS TRANSPARENT FUNDS ONLY"),
        "this wallet has Sapling keys, so the transparent-only path is the \
         wrong route for it\n--- stderr ---\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}
