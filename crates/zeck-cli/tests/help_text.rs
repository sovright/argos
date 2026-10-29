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
    // scan.rs clamps the birthday to `sapling_activation_height + 1`, so "0"
    // never meant genesis -- and the activation block itself is skipped.
    assert!(!h.contains("from genesis"), "{h}");
    assert!(h.contains("one block past Sapling activation"), "{h}");
    assert!(h.contains("419201"), "{h}");
    assert!(
        h.contains("the activation block itself is not scanned"),
        "{h}"
    );
    // `resolve_birthday` prefers auto-detect, then the date, then --birthday.
    assert!(
        h.contains("Overridden by --birthday-date and --birthday-auto-detect"),
        "{h}"
    );
    // Auto-detect branches on a recovered seed, not on the file type.
    assert!(h.contains("whose seed could be decrypted"), "{h}");
    // ...or a zcashd wallet.dat, dated by its key times (`resolve_birthday`).
    assert!(h.contains("key creation times"), "{h}");
    // `Mnemonic::from_phrase` takes every BIP-39 length, not only 24.
    assert!(!h.contains("24-word"), "{h}");
    assert!(h.contains("12, 15, 18, 21 or 24 words"), "{h}");
    // scan.rs imports the complete transparent range only when
    // `account.index == 0`.
    assert!(h.contains("account 0 only"), "{h}");
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
    // `refuse_unconsumed_birthday_skip` refuses the date and auto-detect
    // flags on `scan-sprout`, which reads --birthday alone.
    assert!(h.contains("Refused by `scan-sprout`"), "{h}");
    // `needs_chain_fallback`: an undated Sapling key rules out the UTXO
    // fallback, so Sapling is scanned from activation.
    assert!(h.contains("unless a Sapling key is undated"), "{h}");
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
    // `enforce_max_fee` returns an error; nothing is skipped silently. The
    // cap is cumulative and checked inside the broadcast loop, so earlier
    // accounts may already be on-chain when it trips.
    assert!(!h.contains("is skipped"), "{h}");
    assert!(h.contains("Maximum total fee"), "{h}");
    assert!(h.contains("cannot be recalled"), "{h}");
    // The seedless routes (`wallet_seed().is_none()`) send neither memo nor
    // donation: `refuse_memo_without_seed` refuses the memo, and testnet
    // turns the donation off even with a seed.
    assert!(h.contains("whose seed could be decrypted"), "{h}");
    // ...or a zcashd wallet.dat, dated by its key times (`resolve_birthday`).
    assert!(h.contains("key creation times"), "{h}");
    // `normalized_memo_text` writes RECOVERY_MEMO_DEFAULT when no memo is
    // given, so omitting --memo does not mean "no memo" on the seed route —
    // which matters to anyone sending to an exchange address that must not
    // carry one.
    assert!(h.contains("Argos recovery"), "{h}");
    assert!(h.contains("refuses one rather than drop it"), "{h}");
    assert!(h.contains("on mainnet"), "{h}");
    // `sapling_receiver`: the transparent leg of a seedless wallet (its own
    // route, and inside `imported_sweep`) needs a Sapling receiver.
    assert!(h.contains("Sapling receiver"), "{h}");
}

#[test]
fn reconcile_help_explains_observation_and_exact_byte_resubmission() {
    let h = help(&["reconcile"]);
    assert!(h.contains("--txid"), "{h}");
    assert!(h.contains("--resubmit"), "{h}");
    assert!(h.contains("exact stored transaction bytes"), "{h}");
    assert!(h.contains("independent confirmation"), "{h}");
}

#[test]
fn scan_sprout_help_describes_custom_priority_and_public_fallback() {
    // `connect_to_any` tries custom peers in their own priority tier, then
    // public candidates and a separate mainnet fallback tier.
    let h = help(&["scan-sprout"]);
    let prose = h.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(!h.contains("instead of the DNS seeds"), "{h}");
    assert!(
        prose.contains("own priority batches before public DNS-seed peers"),
        "{h}"
    );
    assert!(
        prose.contains("If those attempts fail, Argos samples public peers"),
        "{h}"
    );
    // `first_scan_height` starts a fresh walk at 1 and the walk ends only at
    // the chain tip (`empty_reply_is_chain_tip`): the pre-Sapling era is
    // covered, so are Sprout notes after Canopy, and no birthday narrows it.
    assert!(h.contains("from height 1"), "{h}");
    assert!(h.contains("before Sapling activation"), "{h}");
    assert!(h.contains("to the chain tip"), "{h}");
    assert!(h.contains("after Canopy"), "{h}");
    assert!(
        !h.contains("not including, Canopy"),
        "the scan no longer stops at Canopy: {h}"
    );
    // `connect_with_resolver` gives mainnet fallbacks their own final tier.
    assert!(h.contains("fallback nodes run by the Argos project"), "{h}");
    // `default_params_path` treats the variable as the file itself.
    assert!(h.contains("the file named by $ARGOS_SPROUT_PARAMS"), "{h}");
    // `plan_sprout_decrypt`: the walk always starts at 1; a dated wallet
    // may skip trial decryption, and --birthday can only lower that.
    assert!(!h.contains("--birthday does not apply"), "{h}");
    assert!(h.contains("--no-birthday-skip"), "{h}");
    assert!(h.contains("can only lower"), "{h}");
    // It also takes --wallet-file, and broadcasts through lightwalletd.
    // Pinned to the prose: with top-level flags global (#232), the option
    // list names --wallet-file on every subcommand, so a bare
    // `contains("--wallet-file")` would pass with the sentence deleted.
    assert!(h.contains("--wallet-file, or both"), "{h}");
    assert!(h.contains("lightwalletd"), "{h}");
}

#[test]
fn sweep_sprout_help_names_the_network_it_broadcasts_to() {
    // `sweep_sprout_notes` runs `validate_lightwalletd_network`, and the
    // default server is mainnet.
    let h = help(&["sweep-sprout"]);
    assert!(h.contains("must serve --network"), "{h}");
    assert!(h.contains("the file named by $ARGOS_SPROUT_PARAMS"), "{h}");
}

#[test]
fn inspect_wallet_help_names_both_inputs() {
    // The key-source match accepts a key file alone for inspect-wallet.
    let h = help(&["inspect-wallet"]);
    assert!(h.contains("--sapling-key-file"), "{h}");
}
