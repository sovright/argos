//! Every `argos …` command line the binary prints must actually parse.
//!
//! This exists because of a real failure: a user following
//! `argos scan-sprout --wallet-file <x> --destination <y>`, printed by
//! Argos itself, got `error: unexpected argument '--wallet-file' found`.
//! Seven hints were affected, not the two first reported — including
//! three on the `argos scan` path, which fires straight after a
//! successful key import and is the main recovery route. One was split
//! across source lines by a Rust string continuation, which is how it
//! hid from a grep for the broken shape.
//!
//! #232 fixes the cause by making top-level flags global, so those
//! hints now parse either way round. This test is the guard rather than
//! the fix: it does not care where a flag sits, only that every command
//! line the binary prints is one the binary accepts.
//!
//! The test is deliberately structural rather than six string
//! assertions: it reads the source, finds every command line the binary
//! could print, and checks each one against the real parser. A hint added
//! later gets the same treatment without anyone remembering to add a case.
//!
//! `--help` is appended so clap stops after parsing. Argument-order
//! mistakes are rejected before that point, so a bad hint still fails,
//! but nothing scans, signs or broadcasts — which matters here, because
//! one of the hints carries `--confirm-sweep`.

use std::process::{Command, Stdio};

const SOURCE: &str = include_str!("../src/main.rs");

/// Pull every `argos …` command line out of the source.
///
/// Placeholders like `<path>` or `<your zs1… or unified address>` contain
/// spaces, so they are collapsed to a single token before splitting.
/// A trailing `\` + newline is a shell continuation and is joined.
fn hinted_commands(source: &str) -> Vec<Vec<String>> {
    // Two kinds of continuation have to be joined before scanning.
    //
    // `\\` + newline in the source is an escaped backslash followed by a
    // newline — a shell line-continuation in the *printed* output.
    //
    // A bare `\` at end of line is Rust's own string continuation: it and
    // the following indentation vanish at compile time, so a hint can be
    // split across source lines and still print as one command. That is
    // how the seventh bad hint hid from a grep.
    let mut joined = source.replace("\\\\\\n", " ");
    while let Some(idx) = joined.find("\\\n") {
        let tail = joined[idx + 2..].trim_start();
        joined = format!("{}{}", &joined[..idx], tail);
    }
    let mut out = Vec::new();

    for (idx, _) in joined.match_indices("argos ") {
        // Only treat it as a command if it starts a word.
        let before = joined[..idx].chars().last();
        if matches!(before, Some(c) if c.is_alphanumeric() || c == '-' || c == '/' || c == '_') {
            continue;
        }
        let rest = &joined[idx..];
        let end = rest.find(['`', '"', '\n']).unwrap_or(rest.len());
        let line = &rest[..end];

        // Collapse `<…>` placeholders to one token.
        let mut cleaned = String::new();
        let mut depth = 0usize;
        for ch in line.chars() {
            match ch {
                '<' => {
                    depth += 1;
                    if depth == 1 {
                        cleaned.push_str("PLACEHOLDER");
                    }
                }
                '>' => depth = depth.saturating_sub(1),
                _ if depth > 0 => {}
                _ => cleaned.push(ch),
            }
        }

        let args: Vec<String> = cleaned
            .split_whitespace()
            .skip(1) // the `argos` program name
            .map(str::to_owned)
            .collect();

        // A bare mention of the binary is not a command line.
        if args.is_empty() {
            continue;
        }
        out.push(args);
    }
    out
}

#[test]
fn every_printed_command_line_parses() {
    let commands = hinted_commands(SOURCE);

    // Guard the extractor itself: if a refactor stops it finding
    // anything, the test must fail loudly rather than pass vacuously.
    assert!(
        commands.len() >= 7,
        "expected to find the printed command lines in main.rs, found {}",
        commands.len()
    );

    let mut failures = Vec::new();
    for args in &commands {
        let output = Command::new(env!("CARGO_BIN_EXE_argos"))
            .args(args)
            .arg("--help")
            .stdin(Stdio::null())
            .output()
            .expect("run argos");

        if !output.status.success() {
            failures.push(format!(
                "argos {}\n    {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .replace('\n', "\n    ")
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "these command lines are printed by argos but rejected by its parser:\n\n{}\n\n\
         The clap error under each one says why. A `PLACEHOLDER` value is a `<…>` \
         from the hint; if the flag takes a number or an enum, give the hint a \
         real example value instead.",
        failures.join("\n\n")
    );
}

#[test]
fn the_extractor_finds_a_known_hint() {
    // Guards the extractor, not the flag order: #232 makes top-level
    // flags global, so a hint parses with `--wallet-file` on either
    // side of the subcommand. What must never happen is the extractor
    // silently finding nothing and the real test passing vacuously.
    let commands = hinted_commands(SOURCE);
    assert!(
        commands
            .iter()
            .any(|args| args.contains(&"scan-sprout".to_owned())
                && args.contains(&"--wallet-file".to_owned())),
        "expected the scan-sprout hint carrying --wallet-file; found: {commands:?}"
    );
}
