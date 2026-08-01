//! The `--wallet-file` surface, exercised end to end against real golden
//! wallets.
//!
//! These run the actual binary rather than calling library functions,
//! because the things most likely to break here are wiring: an argument
//! that doesn't reach the key source, a command that prompts when it
//! shouldn't, or a refusal that turns into a silent empty result. None of
//! those are visible from inside the library.
//!
//! No new dev-dependency: `CARGO_BIN_EXE_<name>` is a cargo built-in that
//! points at the freshly-built binary.

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// zcashd wallet with a Sprout address, a Sapling address, and transparent
/// keys — and, importantly, no HD seed. Written by a real `zcashd`; see
/// `tests/regtest/fixtures/README.md`.
const SPROUT_PLAINTEXT: &str = "sprout-plaintext.dat";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../argos-wallet-import/tests/fixtures")
        .join(name)
}

/// Run `argos` with stdin closed.
///
/// Closing stdin is load-bearing, not tidiness: it means any test that
/// accidentally reaches an interactive prompt fails with a terminal error
/// instead of hanging CI forever.
fn argos(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_argos"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("argos binary should run")
}

#[test]
fn inspect_wallet_reports_a_zcashd_wallets_contents_without_a_network() {
    let path = fixture(SPROUT_PLAINTEXT);
    assert!(
        path.exists(),
        "golden fixture is missing: {}",
        path.display()
    );

    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        out.status.success(),
        "inspect-wallet failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    // The counts come from the fixture's documented contents: 103
    // transparent keys, 1 sapling, 1 sprout. Asserting the sprout line
    // specifically because a Sprout key is the whole reason this parser
    // exists and nothing else in the ecosystem recovers one.
    assert!(
        stdout.contains("Sprout keys       1"),
        "expected the recovered Sprout key to be reported, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Transparent keys  103"),
        "expected 103 transparent keys, got:\n{stdout}"
    );
    // A user must not read "recovered a Sprout key" as "can move the money".
    assert!(
        stdout.contains("not yet recoverable") || stdout.contains("cannot yet move funds"),
        "the report must not imply Sprout funds are spendable, got:\n{stdout}"
    );
}

#[test]
fn scanning_a_seedless_wallet_refuses_instead_of_reporting_no_funds() {
    let tempdir = std::env::temp_dir().join(format!("argos-cli-test-{}", std::process::id()));
    let path = fixture(SPROUT_PLAINTEXT);

    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--data-dir",
        tempdir.to_str().expect("temp path is UTF-8"),
        "scan",
    ]);
    let _ = std::fs::remove_dir_all(&tempdir);

    // The dangerous outcome is exit 0 with an empty result, which reads as
    // "your wallet is empty" for a wallet that may hold real funds.
    assert!(
        !out.status.success(),
        "scanning a seedless wallet must fail rather than report an empty wallet"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no recoverable seed phrase"),
        "the refusal must explain itself, got:\n{stderr}"
    );
    assert!(
        stderr.contains("inspect-wallet"),
        "the refusal must point at the command that does work, got:\n{stderr}"
    );
}

#[test]
fn inspect_wallet_without_a_wallet_file_does_not_prompt_for_a_seed() {
    // Regression guard: `inspect-wallet` shares the argument-parsing path
    // with commands that read a seed phrase from the terminal. If it ever
    // falls through to that prompt, stdin is closed here and the process
    // dies on a terminal error — which is a pass by accident. Assert the
    // specific message instead.
    let out = argos(&["inspect-wallet"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("inspect-wallet needs --wallet-file"),
        "expected the missing-argument error, got:\n{stderr}"
    );
}

#[test]
fn a_file_that_is_not_a_wallet_is_rejected_by_name() {
    // This source file: definitively not a wallet.
    let not_a_wallet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wallet_file_cli.rs");
    let out = argos(&[
        "--wallet-file",
        not_a_wallet.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a recognized Zcash wallet file"),
        "expected the format-sniff rejection, got:\n{stderr}"
    );
}
