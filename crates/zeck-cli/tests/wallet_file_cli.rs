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
/// keys. Written by a real `zcashd` v6.20.0, so it also holds a 5.x
/// `mnemonicphrase` HD seed, which Argos does not recover. See
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
    // The parser reports a Sprout key count, and recovering those notes still
    // takes a `scan-sprout` this report has not run, so the wording has to
    // keep "found a key" and "can move the funds" apart.
    assert!(
        stdout.contains("not yet recoverable"),
        "the report must not imply Sprout funds are spendable, got:\n{stdout}"
    );
}

/// A zcashd 5.x wallet's seed is skipped, and the report must say so rather
/// than claim the keys were never HD-derived or that every record was read
/// (#225).
#[test]
fn inspect_wallet_does_not_hide_an_unrecovered_seed() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for false_claim in ["not HD-derived", "Every record in this file was read"] {
        assert!(
            !stdout.contains(false_claim),
            "report claims {false_claim:?} for a wallet holding a seed:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("Seed phrase       not recovered from this file"),
        "got:\n{stdout}"
    );
    assert!(
        stdout.contains("this file holds an HD seed that Argos does not recover"),
        "the coverage notice must name the seed, got:\n{stdout}"
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
    assert!(
        !out.status.success(),
        "a testnet key must not pass on mainnet"
    );

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

/// The over-refusal guard, at the surface a user actually types.
///
/// `--wallet-file` + `--sapling-key-file` is refused *only* when the wallet
/// yields a BIP-39 mnemonic, because that wallet takes the HD route and the
/// standalone key would be silently dropped. A seedless zcashd wallet takes
/// the imported-account route, which reads `keys.sapling` directly, so the
/// two must still merge — this is the combination the feature exists for.
///
/// The matching refusal cannot be exercised here: only an *encrypted*
/// ZecWallet Lite wallet recovers a mnemonic, and its passphrase is
/// prompt-only by design, so no non-interactive fixture can reach that
/// branch. Both directions are pinned at the unit level instead, on
/// `argos_core::sapling_key::merge_standalone_sapling_keys` — the single
/// helper this path and the GUI's both call.
#[test]
fn a_seedless_wallet_and_a_key_file_still_merge() {
    let wallet = fixture(SPROUT_PLAINTEXT);
    let keys = key_file("sapling-key-with-wallet.txt", TEST_SAPLING_KEY_MAINNET);

    let out = argos(&[
        "--wallet-file",
        wallet.to_str().expect("fixture path is UTF-8"),
        "--sapling-key-file",
        keys.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        out.status.success(),
        "a seedless wallet plus a supplied key must not be refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("seed phrase"),
        "the HD refusal must not fire for a seedless wallet, got:\n{stderr}"
    );

    // The supplied key landed alongside the wallet's own: the fixture holds
    // one Sapling address, and the pasted key controls a second.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zs1"),
        "the merged key set should report Sapling addresses, got: {stdout}"
    );
    assert!(
        !stdout.contains("secret-extended-key"),
        "no key material may be printed back, got: {stdout}"
    );
}

/// A wallet with no seed phrase sweeps without a memo, and a dropped memo
/// can lose an exchange deposit. `--memo` is therefore refused, and refused
/// before the scan: finding out after hours of scanning is not a refusal
/// anyone would thank us for.
#[test]
fn a_seedless_sweep_refuses_a_memo_before_scanning() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("memo"),
        "sweep",
        "--destination",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        "--memo",
        "exchange deposit 12345",
        "--dry-run",
    ]);

    assert!(
        !out.status.success(),
        "a memo that cannot be sent must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("memo") && stderr.contains("seed phrase"),
        "the refusal must say why, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("scan can take hours"),
        "the memo must be refused before the scan starts, got:\n{stderr}"
    );
}

/// The donation is the same shape of trap with no funds at stake, so it is
/// reported rather than refused — the GUI sends one by default.
#[test]
fn a_seedless_sweep_says_it_sends_no_donation() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("donation"),
        "sweep",
        "--destination",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        "--donation-rate",
        "0.10",
        "--dry-run",
    ]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sends no donation"),
        "a requested donation that will not be sent must be named, got:\n{stderr}"
    );
}

/// A real mainnet Sapling address to sweep to, derived from the BIP-39 test
/// vector rather than copied from anywhere: `show-keys` needs no network.
fn test_vector_sapling_address(dir: &std::path::Path) -> String {
    let seed = dir.join("seed.txt");
    std::fs::write(
        &seed,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art",
    )
    .expect("write seed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let out = argos(&[
        "--seed-file",
        seed.to_str().expect("utf-8"),
        "--num-accounts",
        "1",
        "show-keys",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Sapling address")
                .map(|a| a.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("show-keys printed no Sapling address:\n{stdout}"))
}

/// Reported: `scan-sprout --destination … --lightwalletd-url nonono` started
/// an hours-long scan whose only use of that server — broadcasting the sweep
/// — could never work. The address must be refused before the scan, and the
/// progress line must not claim a checkpoint exists before one is written.
#[test]
fn scan_sprout_refuses_an_unusable_server_before_scanning() {
    let dir = std::env::temp_dir().join(format!("argos-sprout-url-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let destination = test_vector_sapling_address(&dir);
    let wallet = fixture(SPROUT_PLAINTEXT);

    // Killed at a deadline rather than awaited: a build that does not refuse
    // goes on to scan mainnet for hours, and a failing test must neither
    // hang nor load public peers for longer than it takes to fail.
    let mut child = Command::new(env!("CARGO_BIN_EXE_argos"))
        .args([
            "--wallet-file",
            wallet.to_str().expect("utf-8"),
            "--data-dir",
            dir.to_str().expect("utf-8"),
            "--accept-tos",
            "--lightwalletd-url",
            "nonono",
            "scan-sprout",
            "--destination",
            &destination,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("argos binary should run");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().expect("piped"), &mut stderr)
        .expect("stderr");
    let _ = std::fs::remove_dir_all(&dir);
    let status = status.unwrap_or_else(|| {
        panic!("scan-sprout started scanning instead of refusing the server:\n{stderr}")
    });
    assert!(!status.success(), "must refuse, got:\n{stderr}");
    assert!(
        stderr.contains("--lightwalletd-url"),
        "must name the flag:\n{stderr}"
    );
    // Matches the banner as it now reads; the old "Progress is saved to"
    // wording no longer exists anywhere, so asserting its absence guarded
    // nothing.
    assert!(
        !stderr.contains("Progress will be saved to"),
        "refused before the scan, so the scan's progress banner must not appear:\n{stderr}"
    );
}

/// A key-source flag that the chosen command never reads must be refused,
/// not silently dropped. Now that every top-level flag is `global`, it is
/// natural to type `argos show-keys --sprout-key-file …` and assume the key
/// was used.
#[test]
fn a_key_source_the_command_would_ignore_is_refused() {
    let key = key_file("ignored-sprout-key", "SKplaceholder\n");
    let key = key.to_str().unwrap();
    for args in [
        vec!["show-keys", "--sprout-key-file", key],
        vec!["scan", "--sprout-key-file", key, "--accept-tos"],
        vec![
            "sweep-sprout",
            "--sprout-key-file",
            key,
            "--destination",
            "zs1x",
            "--accept-tos",
        ],
        vec!["scan-sprout", "--seed-file", key, "--accept-tos"],
        vec!["scan-sprout", "--sapling-key-file", key, "--accept-tos"],
    ] {
        let out = argos(&args);
        assert!(!out.status.success(), "{args:?} must be refused");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("is not used by"),
            "{args:?}: the refusal must say the flag would be ignored, got:\n{stderr}"
        );
    }
}

/// A full-block scan of a wallet's keys, run earlier in the same data
/// directory, is what settles spends the wallet file cannot see — notes
/// spent from another copy of the wallet. inspect-wallet must find it by
/// itself, from the checkpoint `scan-sprout` leaves behind, and say it did.
#[test]
fn inspect_wallet_consults_a_scan_of_the_same_keys() {
    use secrecy::ExposeSecret;

    let path = fixture(SPROUT_PLAINTEXT);
    let bytes = std::fs::read(&path).expect("fixture is readable");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("the plaintext fixture imports");
    let spending_keys: Vec<[u8; 32]> = keys
        .sprout
        .iter()
        .map(|k| *k.a_sk.expose_secret())
        .collect();
    assert!(!spending_keys.is_empty(), "the fixture holds Sprout keys");

    let dir = scratch_dir("chain-spends");
    std::fs::create_dir_all(&dir).unwrap();
    let mut scanner = argos_core::sprout_scan::SproutScanner::new(&spending_keys);
    scanner
        .scan_block_at(&[], [0xCD; 32], 2_000_000)
        .expect("an empty block");
    let checkpoint = argos_core::sprout_scan_run::checkpoint_path(dir.as_ref(), &spending_keys);
    argos_core::sprout_scan_run::save_checkpoint(
        &scanner,
        argos_core::p2p::wire::P2pNetwork::Mainnet,
        &checkpoint,
    )
    .expect("checkpoint written");

    let with_scan = argos(&[
        "--wallet-file",
        path.to_str().unwrap(),
        "--data-dir",
        &dir,
        "inspect-wallet",
    ]);
    let without_scan = argos(&[
        "--wallet-file",
        path.to_str().unwrap(),
        "--data-dir",
        &scratch_dir("chain-spends-empty"),
        "inspect-wallet",
    ]);
    let _ = std::fs::remove_file(&checkpoint);

    let with = String::from_utf8_lossy(&with_scan.stdout);
    assert!(
        with_scan.status.success(),
        "{}",
        String::from_utf8_lossy(&with_scan.stderr)
    );
    assert!(
        with.contains("full-block scan up to height 2000000"),
        "the scan must be found and named:\n{with}"
    );
    let without = String::from_utf8_lossy(&without_scan.stdout);
    assert!(
        !without.contains("full-block scan up to height"),
        "no scan, no claim of one:\n{without}"
    );
}
