//! `--help` is the only documentation many CLI users read, so the claims in
//! it are pinned to what the code does. Each assertion names the code that
//! makes the claim true; if that code changes, this is the reminder to
//! change the help with it.

use std::process::{Command, Stdio};

fn help(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_argos"))
        .args(args)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .expect("argos binary should run");
    assert!(out.status.success());
    String::from_utf8(out.stdout).expect("help is UTF-8")
}

#[test]
fn top_level_help_matches_behaviour() {
    let h = help(&[]);
    // scan.rs clamps the birthday to Sapling activation: a lightwalletd scan
    // cannot see anything earlier, so "0" never meant genesis.
    assert!(!h.contains("from genesis"), "{h}");
    assert!(h.contains("Sapling activation"), "{h}");
    // ...and must not read as though that clamp applies to Sprout.
    assert!(h.contains("scan-sprout` is not affected"), "{h}");
    // The default server is mainnet whatever --network says, and the
    // lightwalletd chain-name check then refuses it for testnet.
    assert!(h.contains("https://testnet.zec.rocks:443"), "{h}");
    // Only https, or http to localhost (`validate_lightwalletd_endpoint`).
    assert!(h.contains("localhost"), "{h}");
    // The server list has a default, so auto-detect never "requires" the
    // flag; what it does require is a seed (`resolve_birthday`).
    assert!(!h.contains("Requires --lightwalletd-url"), "{h}");
    // --birthday-date conflicts with it rather than being superseded.
    assert!(
        !h.contains("Supersedes --birthday and --birthday-date"),
        "{h}"
    );
    // `collect_sprout_scan_keys` is its only reader.
    assert!(h.contains("Read only by `scan-sprout`"), "{h}");
}

#[test]
fn show_keys_help_says_it_prints_addresses_not_keys() {
    // It prints addresses and derivation paths; no key ever reaches stdout.
    let h = help(&["show-keys"]);
    assert!(!h.contains("all account keys"), "{h}");
    assert!(h.contains("addresses"), "{h}");
}

#[test]
fn sweep_help_matches_what_each_route_honours() {
    let h = help(&["sweep"]);
    // `enforce_max_fee` returns an error; nothing is skipped silently.
    assert!(!h.contains("is skipped"), "{h}");
    // The transparent-only and imported-key routes take only destination
    // and max fee, so memo and donation apply to seed sources alone.
    assert!(h.contains("seed phrase or a ZecWallet Lite wallet"), "{h}");
    // `sapling_receiver`: the transparent leg of a seedless wallet (its own
    // route, and inside `imported_sweep`) needs a Sapling receiver.
    assert!(h.contains("Sapling receiver"), "{h}");
}

#[test]
fn scan_sprout_help_does_not_promise_an_exclusive_peer() {
    // `connect_to_any` races the given peers alongside the DNS seeds and
    // keeps whichever answers first.
    let h = help(&["scan-sprout"]);
    assert!(!h.contains("instead of the DNS seeds"), "{h}");
    assert!(h.contains("alongside"), "{h}");
    // `first_scan_height` starts a fresh walk at 1 and `sprout_scan_bound`
    // ends it at Canopy: the pre-Sapling era is covered, and no birthday
    // narrows it.
    assert!(h.contains("from height 1"), "{h}");
    assert!(h.contains("before Sapling activation"), "{h}");
    assert!(h.contains("1,046,400") && h.contains("1,028,500"), "{h}");
    assert!(h.contains("--birthday does not apply"), "{h}");
    // It also takes --wallet-file, and broadcasts through lightwalletd.
    assert!(h.contains("--wallet-file"), "{h}");
    assert!(h.contains("lightwalletd"), "{h}");
}
