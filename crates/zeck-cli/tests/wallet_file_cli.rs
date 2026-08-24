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
    //
    // Asserted in both builds, because both print a Sprout key count — the
    // parser is unconditional — and the claim being guarded is about that
    // count, not about the feature. The wording differs because the honest
    // statement differs: with Sprout compiled in, the notes are not yet
    // recoverable through `scan`/`sweep`; without it, they are recoverable but
    // not by this binary. Sharing one string would have forced one of the two
    // builds to say something untrue.
    #[cfg(feature = "sprout")]
    assert!(
        stdout.contains("not yet recoverable"),
        "the report must not imply Sprout funds are spendable, got:\n{stdout}"
    );
    #[cfg(not(feature = "sprout"))]
    assert!(
        stdout.contains("this build cannot recover them"),
        "a build without Sprout support must say so rather than imply the keys it \
         just counted are spendable, got:\n{stdout}"
    );

    // And it must never point at a subcommand this build does not have.
    #[cfg(not(feature = "sprout"))]
    assert!(
        !stdout.contains("scan-sprout") && !stdout.contains("sweep-sprout"),
        "a default build compiles those subcommands out; naming them sends the user to \
         `unrecognized subcommand` for the one pool that is hardest to recover. Got:\n{stdout}"
    );
}

/// A seedless wallet is *scanned*, not refused.
///
/// This has now been re-pointed twice, and the reason is worth recording.
/// It first asserted an outright refusal, which was correct when neither
/// recovery path existed: scanning through the HD path would have walked
/// zero accounts and reported "no funds" for a wallet that may hold real
/// money. It then asserted the transparent-only path. It now asserts the
/// imported-account path, because a wallet with Sapling keys can be given
/// a wallet-database account that carries its transparent keys too.
///
/// The requirement has never changed: a seedless wallet must never be
/// reported as empty without saying what was not looked at. Only the
/// mechanism keeps improving.
///
/// Uses an unroutable endpoint so this stays offline; the coverage banner
/// is printed before any network call.
#[test]
fn a_seedless_wallet_is_scanned_not_refused() {
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
        !stderr.contains("no recoverable seed phrase"),
        "a wallet with importable keys must no longer be refused outright, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("no HD accounts to scan"),
        "the HD-only refusal must not fire for an importable wallet, got:\n{stderr}"
    );
    // It got as far as the network, which is the only thing that should
    // stop it here.
    assert!(
        stderr.contains("lightwalletd") || stderr.contains("probe"),
        "expected the scan to reach the network and fail there, got:\n{stderr}"
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

/// Sprout is the one pool nothing covers, and the user must be told.
///
/// The stronger half of this test is the negative: Sapling must *not* be
/// listed as uncovered. A zcashd wallet's Sapling keys are registered as a
/// wallet-database account and scanned alongside its transparent keys, so
/// listing Sapling here would mean the routing regressed to the
/// transparent-only path and Sapling funds had silently stopped being
/// scanned.
#[test]
fn a_wallet_with_sprout_keys_says_sprout_is_not_covered() {
    let path = fixture(SPROUT_PLAINTEXT);
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
        stderr.contains("SPROUT FUNDS ARE NOT COVERED"),
        "the Sprout caveat must be unmissable, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Sprout key(s) in this wallet are NOT scanned"),
        "it must name the pool and its key count, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Sapling key(s) in this wallet are NOT scanned"),
        "Sapling is scanned via the imported account path; listing it as uncovered means \
         the routing regressed to transparent-only, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Keep the original wallet file"),
        "the user must be told not to discard the only copy of those keys, got:\n{stderr}"
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

/// Write a key file under the test's temp dir and hand back its path.
fn key_file(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("argos-test-{name}"));
    std::fs::write(&path, contents).expect("test key file should write");
    path
}

/// The same Sapling extended spending key encoded for each network,
/// derived from the fixed seed `[7u8; 32]`. It controls no real funds and
/// has never been on any chain.
///
/// Pinned rather than derived at test time so this test needs no
/// dev-dependency on `sapling-crypto`. Regenerate, if upstream encoding ever
/// changes, by encoding
/// `sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32])` with
/// `zcash_keys::encoding::encode_extended_spending_key` under each network's
/// `HRP_SAPLING_EXTENDED_SPENDING_KEY`.
const TEST_SAPLING_KEY_MAINNET: &str =
    "secret-extended-key-main1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgqvp59t";
const TEST_SAPLING_KEY_TESTNET: &str =
    "secret-extended-key-test1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgts9kat";

#[test]
fn inspect_wallet_reports_a_key_supplied_as_text() {
    let path = key_file(
        "sapling-key-good.txt",
        &format!("# from the paper backup\n{TEST_SAPLING_KEY_MAINNET}\n"),
    );

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        out.status.success(),
        "inspect-wallet failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zs1"),
        "the address the key controls should be shown, got: {stdout}"
    );
    assert!(
        !stdout.contains("secret-extended-key"),
        "the key itself must never be printed back, got: {stdout}"
    );
}

#[test]
fn a_key_for_the_wrong_network_is_refused_by_name() {
    let path = key_file(
        "sapling-key-wrong-network.txt",
        &format!("{TEST_SAPLING_KEY_TESTNET}\n"),
    );

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success(), "a testnet key must not pass on mainnet");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("testnet"),
        "the failure should name the key's real network, got: {stderr}"
    );
}

#[test]
fn a_malformed_key_names_the_line_it_is_on() {
    let path = key_file(
        "sapling-key-bad-line.txt",
        &format!("{TEST_SAPLING_KEY_MAINNET}\nnot-a-key\n"),
    );

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success(), "a malformed line must fail the run");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("line 2"),
        "the failure should name the offending line, got: {stderr}"
    );
}

/// A seed and a standalone key are different provenance models; accepting
/// both would leave it ambiguous which one a scan actually used.
#[test]
fn a_seed_file_and_a_key_file_cannot_be_combined() {
    let keys = key_file("sapling-key-conflict.txt", TEST_SAPLING_KEY_MAINNET);
    let seed = key_file("seed-conflict.txt", "abandon abandon abandon");

    let out = argos(&[
        "--sapling-key-file",
        keys.to_str().expect("path is UTF-8"),
        "--seed-file",
        seed.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success(), "the two flags must conflict");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "clap should report the conflict, got: {stderr}"
    );
}

/// The whole point of the feature: a key with no wallet file behind it must
/// not be turned away at argument parsing.
#[test]
fn a_key_file_alone_does_not_demand_a_wallet_file() {
    let path = key_file("sapling-key-alone.txt", TEST_SAPLING_KEY_MAINNET);

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("needs --wallet-file"),
        "a key file is its own key source, got: {stderr}"
    );
}
