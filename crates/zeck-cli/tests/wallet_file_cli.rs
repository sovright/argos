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

/// A seedless wallet with transparent keys is *scanned*, not refused.
///
/// This previously asserted a refusal, which was correct when transparent
/// recovery did not exist: scanning such a wallet through the HD path would
/// have walked zero accounts and reported "no funds" for a wallet that may
/// hold real money. That danger has not gone away — it has moved. The
/// requirement is unchanged and the mechanism is new: the scan must either
/// refuse, or report real transparent numbers *and* name every pool it did
/// not cover. What it must never do is report an empty wallet with no
/// caveat.
///
/// Uses an unroutable endpoint so this stays offline; the transparent-only
/// banner is printed before any network call, and it is emitted on no other
/// code path, so seeing it proves which branch was taken.
#[test]
fn a_seedless_wallet_with_transparent_keys_is_scanned_not_refused() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("seedless"),
        "scan",
    ]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TRANSPARENT FUNDS ONLY"),
        "the transparent-only path must have been taken, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("no recoverable seed phrase"),
        "a wallet with transparent keys must no longer be refused outright, got:\n{stderr}"
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

/// A zcashd wallet that also holds Sapling keys is only *partly* covered by
/// transparent-only recovery. The user must be told that unmissably: a
/// balance reported without that caveat is an active lie about where their
/// money is.
///
/// Runs offline — the warning is printed before any network call, so this
/// asserts it without needing a chain.
#[test]
fn a_wallet_with_shielded_keys_warns_that_they_are_not_covered() {
    let path = fixture(SPROUT_PLAINTEXT);
    // Point at an unroutable endpoint: the scan will fail, but the warning
    // is emitted first and that is what is under test.
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("warn"),
        "scan",
    ]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TRANSPARENT FUNDS ONLY"),
        "the transparent-only caveat must be unmissable, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Sapling key(s) in this wallet are NOT scanned"),
        "it must name the pool being skipped, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Sprout key(s) in this wallet are NOT scanned"),
        "the fixture has a Sprout key too; it must be named, got:\n{stderr}"
    );
}

/// Sweeping is irreversible, so it must refuse to broadcast without an
/// explicit confirmation — the same rule the seed sweep follows.
#[test]
fn a_transparent_sweep_refuses_to_broadcast_without_confirmation() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("confirm"),
        "sweep",
        "--destination",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        "--max-fee",
        "0.001",
    ]);

    assert!(
        !out.status.success(),
        "an unconfirmed sweep must not succeed"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // It must fail for a safety reason or before reaching the network —
    // never by silently broadcasting.
    assert!(
        !combined.contains("Sweep broadcast"),
        "nothing may be broadcast without --confirm-sweep, got:\n{combined}"
    );
}

fn scratch_dir(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("argos-cli-{tag}-{}", std::process::id()))
        .to_str()
        .expect("temp path is UTF-8")
        .to_owned()
}
