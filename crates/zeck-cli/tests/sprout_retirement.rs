//! The retired recovery commands fail before reading a wallet or touching the network.
use std::process::{Command, Stdio};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_argos"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn retired_sprout_commands_are_rejected() {
    for command in ["scan-sprout", "sweep-sprout"] {
        let output = run(&[command, "--help"]);
        assert!(!output.status.success(), "{command} must be unavailable");
        assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    }
}

#[test]
fn retired_sprout_options_are_rejected() {
    for option in [
        "--sprout-key-file",
        "--sprout-pack",
        "--sprout-params",
        "--no-sprout-pack-download",
        "--no-birthday-skip",
        "--show-spent",
    ] {
        let output = run(&["inspect-wallet", option]);
        assert!(!output.status.success(), "{option} must be unavailable");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn help_offers_only_supported_recovery() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for retired in [
        "scan-sprout",
        "sweep-sprout",
        "--sprout-key-file",
        "--no-birthday-skip",
    ] {
        assert!(!help.contains(retired), "help advertises {retired}");
    }
    assert!(help.contains("Sapling"));
}
