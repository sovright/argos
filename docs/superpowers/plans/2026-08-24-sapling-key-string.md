# Sapling Extended Spending Key as Text — Implementation Plan

> **Status (2026-08-26):** Implemented and merged to `main`. Retained as a historical execution record; do not re-run these tasks.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user recover funds from a bech32 Sapling extended spending key
(`secret-extended-key-main1…`) held as text, with no `wallet.dat` behind it.

**Architecture:** A new `argos-core` module decodes the string into a
`sapling_crypto::zip32::ExtendedSpendingKey`, then packs it into an
`ImportedKeys` — the same struct the wallet-file parsers produce. From there
`ImportedKeySource` → `run_imported_scan` → `imported_sweep` work untouched.
Both surfaces (CLI `--sapling-key-file`, GUI textarea) are thin wrappers over
that one bridge.

**Tech Stack:** Rust; `zcash_keys::encoding` (bech32 codec, already a
dependency), `zcash_protocol::constants` (HRPs, already a dependency),
`argos-wallet-import` (the `ImportedKeys` shape), clap (CLI), Tauri v2 +
vanilla JS (GUI).

**Spec:** `docs/superpowers/specs/2026-08-24-sapling-key-string-design.md`

## Global Constraints

- **No new dependencies.** `zcash_keys` 0.16 (`sapling` feature) and
  `zcash_protocol` 0.10 are already in `crates/zeck-core/Cargo.toml` at lines
  57 and 60. Adding a crate needs explicit approval and does not belong in
  this plan.
- **A spending key is never a flag value and never an argv element** (threat
  model T-S6): it lands in shell history and in `ps` output for every user on
  the box. File input only on the CLI; textarea only in the GUI.
- **No secret in a `Debug` impl, a log line, or a panic message.**
  `argos-wallet-import` deliberately omits `#[derive(Debug)]` on
  secret-bearing structs (`crates/argos-wallet-import/src/keys.rs:18-22`).
  Never print key material — print the derived address instead.
- **GUI JS must clear typed key material from the DOM once the backend holds
  it** (threat model T-S2), the way `start-scan` already clears the seed.
- **Tauri frontend has no bundler.** Use `window.__TAURI__.core.invoke`, not
  ES module imports.
- Every error message names what the user must do next. "invalid key" is a
  plan failure; "this is a testnet key" is the standard.
- Branch: `feat/imported-sapling-sweep`. Do not branch further.
- Verify with `cargo clippy --all-targets -- -D warnings` before each commit.

---

### Task 1: The decoder — `argos_core::sapling_key`

**Files:**
- Create: `crates/zeck-core/src/sapling_key.rs`
- Modify: `crates/zeck-core/src/lib.rs` (add `pub mod sapling_key;` next to
  `pub mod sprout_key;` on line 29)
- Test: inline `#[cfg(test)] mod tests` in the new file, matching how
  `sprout_key.rs` tests itself

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `pub fn decode_sapling_spending_key(s: &str, network: ZeckNetwork) -> ZeckResult<ExtendedSpendingKey>`
  - `pub fn default_sapling_address(extsk: &ExtendedSpendingKey, network: ZeckNetwork) -> String`
  - where `ExtendedSpendingKey` is `zcash_keys::keys::sapling::ExtendedSpendingKey`
    (a re-export of `sapling_crypto::zip32::ExtendedSpendingKey`).

**Background you need:**

`sapling_crypto`'s `ExtendedSpendingKey` does **not** implement `PartialEq`.
Compare keys via `.to_bytes()`, which returns `[u8; 169]`.

The HRPs live upstream and are exactly the strings ZIP-32 §5.6.3.1 defines:

| Network | `HRP_SAPLING_EXTENDED_SPENDING_KEY` | `HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY` |
|---|---|---|
| mainnet | `secret-extended-key-main` | `zxviews` |
| testnet | `secret-extended-key-test` | `zxviewtestsapling` |

The trailing `1` a user sees in `secret-extended-key-main1q…` is the bech32
separator, not part of the HRP. Do not put it in a constant.

- [ ] **Step 1: Write the failing tests**

Create `crates/zeck-core/src/sapling_key.rs` containing *only* the module doc
and the test module below. It will not compile yet — that is the point.

```rust
//! Reading zcashd's text encoding for Sapling extended spending keys.
//!
//! A user may hold a Sapling spending key as a `secret-extended-key-main1…`
//! string — from `z_exportkey`, from `zcashd-wallet-tool`, or from a paper
//! backup — with no `wallet.dat` at all. That string is the whole of what
//! they have, so decoding it correctly is the entire difference between a
//! recovery and a dead end. This is the same situation `sprout_key` handles
//! for Sprout.
//!
//! # Why this needs no golden-constant caveat
//!
//! `sprout_key` pins zcashd's base58 version bytes by hand and documents that
//! mainnet has no oracle in this repo. Sapling has no such problem: the
//! human-readable parts come from `zcash_protocol::constants`, which is the
//! same source librustzcash, zcashd, and every other wallet encode against.
//! The test below still pins the literal strings, so an upstream rename
//! cannot silently move Argos off the prefix users actually hold.

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_keys::encoding::encode_extended_spending_key;
    use zcash_protocol::constants;

    /// The prefixes users actually type, pinned against ZIP-32 §5.6.3.1.
    /// An upstream rename must break a test, not a recovery.
    #[test]
    fn the_human_readable_prefixes_are_the_ones_zip32_defines() {
        assert_eq!(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "secret-extended-key-main"
        );
        assert_eq!(
            constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "secret-extended-key-test"
        );
    }

    fn a_key() -> ExtendedSpendingKey {
        sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32])
    }

    #[test]
    fn a_mainnet_key_round_trips_and_yields_its_address() {
        let extsk = a_key();
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &extsk,
        );
        assert!(
            encoded.starts_with("secret-extended-key-main1"),
            "encoded key should carry the prefix users recognise, got: {}",
            &encoded[..30.min(encoded.len())]
        );

        let decoded = decode_sapling_spending_key(&encoded, ZeckNetwork::Mainnet)
            .expect("a well-formed mainnet key must decode");
        assert_eq!(decoded.to_bytes(), extsk.to_bytes());

        let address = default_sapling_address(&decoded, ZeckNetwork::Mainnet);
        assert!(
            address.starts_with("zs1"),
            "mainnet Sapling address should start with zs1, got {address}"
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let padded = format!("  {encoded}\t");
        assert!(decode_sapling_spending_key(&padded, ZeckNetwork::Mainnet).is_ok());
    }

    /// The message must name the real problem. A user holding a correct key
    /// for the other network is not helped by "malformed".
    #[test]
    fn a_testnet_key_on_mainnet_names_the_network() {
        let encoded = encode_extended_spending_key(
            constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let err = decode_sapling_spending_key(&encoded, ZeckNetwork::Mainnet)
            .expect_err("a testnet key must not decode as mainnet")
            .to_string();
        assert!(
            err.contains("testnet"),
            "the message should name the key's real network, got: {err}"
        );
    }

    #[test]
    fn a_mainnet_key_on_testnet_names_the_network() {
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let err = decode_sapling_spending_key(&encoded, ZeckNetwork::Testnet)
            .expect_err("a mainnet key must not decode as testnet")
            .to_string();
        assert!(
            err.contains("mainnet"),
            "the message should name the key's real network, got: {err}"
        );
    }

    /// The exact inverse of `sprout_key`'s
    /// `a_sapling_key_is_not_accepted_as_sprout`. Someone with two paper
    /// backups will mix them up eventually.
    #[test]
    fn a_sprout_key_is_not_accepted_as_sapling_and_points_at_the_right_flag() {
        let sprout = "SKxt8pwrQipUL5KgZUcBAqyLj9R1YwMuRRR7rRRRRRRRRRRRRRRR";
        let err = decode_sapling_spending_key(sprout, ZeckNetwork::Mainnet)
            .expect_err("a Sprout key must not decode as Sapling")
            .to_string();
        assert!(
            err.contains("Sprout") && err.contains("--sprout-key-file"),
            "the message should redirect to the Sprout route, got: {err}"
        );
    }

    /// A viewing key can show a balance but cannot move it. Accepting one
    /// would surface funds the user then cannot sweep.
    #[test]
    fn a_viewing_key_is_rejected_as_not_spendable() {
        let extfvk = a_key().to_extended_full_viewing_key();
        let encoded = zcash_keys::encoding::encode_extended_full_viewing_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        );
        let err = decode_sapling_spending_key(&encoded, ZeckNetwork::Mainnet)
            .expect_err("a viewing key must not be accepted as a spending key")
            .to_string();
        assert!(
            err.contains("viewing key") && err.contains("spending key"),
            "the message should explain why a viewing key is not enough, got: {err}"
        );
    }

    #[test]
    fn junk_and_empty_input_are_rejected() {
        for bad in ["", "   ", "not a key", "secret-extended-key-main1", "zs1"] {
            assert!(
                decode_sapling_spending_key(bad, ZeckNetwork::Mainnet).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// A single mistyped character must fail, not silently decode to a
    /// different key. This is what the bech32 checksum is for.
    #[test]
    fn a_single_character_typo_is_caught_by_the_checksum() {
        let encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &a_key(),
        );
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let typo: String = chars.into_iter().collect();
        assert!(
            decode_sapling_spending_key(&typo, ZeckNetwork::Mainnet).is_err(),
            "a one-character typo must not decode"
        );
    }
}
```

Add to `crates/zeck-core/src/lib.rs`, immediately after line 29
(`pub mod sprout_key;`):

```rust
pub mod sapling_key;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p argos-core --lib sapling_key`
Expected: FAIL to compile — `cannot find function decode_sapling_spending_key`,
`cannot find function default_sapling_address`, `cannot find type
ExtendedSpendingKey`, `cannot find type ZeckNetwork`.

- [ ] **Step 3: Write the implementation**

Insert this above the `#[cfg(test)]` block in
`crates/zeck-core/src/sapling_key.rs`:

```rust
use zcash_keys::encoding::{decode_extended_spending_key, AddressCodec};
use zcash_keys::keys::sapling::ExtendedSpendingKey;
use zcash_protocol::constants;

use crate::{
    error::{ZeckError, ZeckResult},
    models::ZeckNetwork,
};

/// The bech32 human-readable part for a spending key on this network.
fn spending_key_hrp(network: ZeckNetwork) -> &'static str {
    match network {
        ZeckNetwork::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        ZeckNetwork::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
    }
}

/// The bech32 human-readable part for a *viewing* key on this network.
///
/// Not accepted as input — used only to recognise one and say why it is not
/// enough.
fn viewing_key_hrp(network: ZeckNetwork) -> &'static str {
    match network {
        ZeckNetwork::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        ZeckNetwork::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
    }
}

fn other_network(network: ZeckNetwork) -> ZeckNetwork {
    match network {
        ZeckNetwork::Mainnet => ZeckNetwork::Testnet,
        ZeckNetwork::Testnet => ZeckNetwork::Mainnet,
    }
}

/// Decode a bech32 Sapling extended spending key.
///
/// Every rejection names what the user must do next: a correct key for the
/// other network says so, a Sprout key is redirected to the Sprout route, and
/// a viewing key is told why viewing is not spending. "Invalid key" sends a
/// user hunting for a different backup when the one in their hand is fine.
pub fn decode_sapling_spending_key(
    s: &str,
    network: ZeckNetwork,
) -> ZeckResult<ExtendedSpendingKey> {
    let trimmed = s.trim();

    if let Ok(key) = decode_extended_spending_key(spending_key_hrp(network), trimmed) {
        return Ok(key);
    }

    let other = other_network(network);
    if decode_extended_spending_key(spending_key_hrp(other), trimmed).is_ok() {
        return Err(ZeckError::Import(format!(
            "this is a {} Sapling spending key, but Argos is set to {}. \
             Re-run against {} to use it.",
            other.label(),
            network.label(),
            other.label(),
        )));
    }

    // zcashd renders Sprout spending keys as base58 `SK…` (mainnet) / `ST…`
    // (testnet). Someone holding two paper backups will mix them up.
    if trimmed.starts_with("SK") || trimmed.starts_with("ST") {
        return Err(ZeckError::Import(
            "that looks like a Sprout spending key, not a Sapling one. \
             Pass it with --sprout-key-file instead (GUI: the Sprout scan panel)."
                .to_owned(),
        ));
    }

    if trimmed.starts_with(viewing_key_hrp(network))
        || trimmed.starts_with(viewing_key_hrp(other))
    {
        return Err(ZeckError::Import(
            "that is a Sapling full viewing key. It can show a balance but \
             cannot move it — Argos needs the spending key \
             (`secret-extended-key-…`) to sweep funds."
                .to_owned(),
        ));
    }

    Err(ZeckError::Import(format!(
        "not a Sapling extended spending key: expected a string beginning \
         `{}1…`. Check for a truncated copy — the checksum rejects a partial key.",
        spending_key_hrp(network),
    )))
}

/// The default Sapling address a key controls, for showing a user which key
/// they just pasted.
///
/// Shown instead of the key itself: an address is safe to display, log, and
/// compare against a block explorer or a paper backup, and the key is not.
pub fn default_sapling_address(extsk: &ExtendedSpendingKey, network: ZeckNetwork) -> String {
    let params = crate::workspace::consensus_network(network);
    let (_, address) = extsk
        .to_diversifiable_full_viewing_key()
        .default_address();
    address.encode(&params)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p argos-core --lib sapling_key`
Expected: PASS, 9 tests.

If `a_sprout_key_is_not_accepted_as_sapling_and_points_at_the_right_flag`
fails because the literal is not valid base58, that is fine — the test only
requires the string to *start* `SK`, which the prefix check keys on. Do not
weaken the assertion on the message.

- [ ] **Step 5: Lint and commit**

Run: `cargo clippy -p argos-core --all-targets -- -D warnings`

```bash
git add crates/zeck-core/src/sapling_key.rs crates/zeck-core/src/lib.rs
git commit -m "feat(sapling): decode a Sapling spending key from its bech32 string"
```

---

### Task 2: Bridge decoded keys into the imported-key path

**Files:**
- Modify: `crates/zeck-core/src/sapling_key.rs` (append the bridge + tests)
- Modify: `crates/argos-wallet-import/src/keys.rs:13-15` (doc comment only)

**Interfaces:**
- Consumes: `decode_sapling_spending_key` from Task 1.
- Produces:
  `pub fn keys_from_sapling_strings(lines: &[String], network: ZeckNetwork) -> ZeckResult<ImportedKeys>`
  — returns an `argos_wallet_import::ImportedKeys` whose `sapling` field holds
  one `SaplingKey` per distinct input, `transparent`/`sprout`/`mnemonic` empty.

**Background you need:**

`ImportedKeys` derives `Default` (`crates/argos-wallet-import/src/keys.rs:133`),
so build it with `..Default::default()`. `SaplingKey` is:

```rust
pub struct SaplingKey {
    pub extsk: Secret<Vec<u8>>,   // raw 169-byte serialization
    pub provenance: Provenance,
}
```

`Provenance::Standalone` is the right variant — a pasted key exists in no
seed. Its doc comment currently claims such a key is "recoverable only from
the wallet file", which this task makes untrue.

- [ ] **Step 1: Write the failing tests**

Append to the `mod tests` block in `crates/zeck-core/src/sapling_key.rs`:

```rust
    use secrecy::ExposeSecret;

    fn encoded_key(seed: [u8; 32], network: ZeckNetwork) -> String {
        let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&seed);
        encode_extended_spending_key(
            match network {
                ZeckNetwork::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
                ZeckNetwork::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            },
            &extsk,
        )
    }

    /// The bridge's whole purpose: produce exactly the shape the wallet-file
    /// parsers produce, so every downstream stage works unchanged.
    #[test]
    fn a_decoded_key_becomes_an_imported_key_set_the_scanner_accepts() {
        let line = encoded_key([7u8; 32], ZeckNetwork::Mainnet);
        let keys = keys_from_sapling_strings(&[line], ZeckNetwork::Mainnet)
            .expect("a well-formed key must build a key set");

        assert_eq!(keys.sapling.len(), 1);
        assert!(keys.transparent.is_empty());
        assert!(keys.sprout.is_empty());
        assert!(keys.mnemonic.is_none(), "a pasted key carries no seed");
        assert!(!keys.is_empty());

        // The bytes must be exactly what `imported::parse_sapling_extsk`
        // expects from a wallet file — that is what makes the paths identical.
        let bytes = keys.sapling[0].extsk.expose_secret().clone();
        assert_eq!(bytes.len(), 169);
        crate::imported::parse_sapling_extsk(&bytes)
            .expect("the bridged bytes must parse on the wallet-file path");

        assert_eq!(
            keys.sapling[0].provenance,
            argos_wallet_import::Provenance::Standalone
        );
    }

    /// Blank lines and `#` comments let a user annotate which key came from
    /// which backup without the file being rejected. Same rule as
    /// `--sprout-key-file`.
    #[test]
    fn blank_lines_and_comments_are_skipped() {
        let line = encoded_key([7u8; 32], ZeckNetwork::Mainnet);
        let input = vec![
            "# from the safe deposit box".to_owned(),
            String::new(),
            "   ".to_owned(),
            line,
        ];
        let keys = keys_from_sapling_strings(&input, ZeckNetwork::Mainnet)
            .expect("comments must not break parsing");
        assert_eq!(keys.sapling.len(), 1);
    }

    /// A repeated key would register a duplicate account and scan the same
    /// key twice for nothing.
    #[test]
    fn a_repeated_key_is_deduplicated() {
        let line = encoded_key([7u8; 32], ZeckNetwork::Mainnet);
        let keys = keys_from_sapling_strings(
            &[line.clone(), line.clone(), line],
            ZeckNetwork::Mainnet,
        )
        .expect("duplicates are a user typo, not an error");
        assert_eq!(keys.sapling.len(), 1);
    }

    #[test]
    fn two_distinct_keys_both_survive() {
        let a = encoded_key([7u8; 32], ZeckNetwork::Mainnet);
        let b = encoded_key([9u8; 32], ZeckNetwork::Mainnet);
        let keys = keys_from_sapling_strings(&[a, b], ZeckNetwork::Mainnet)
            .expect("two good keys must both land");
        assert_eq!(keys.sapling.len(), 2);
    }

    /// Which line failed, not just that something did. A user with twelve
    /// keys in a file needs to know which one to look at.
    #[test]
    fn a_bad_line_reports_its_position() {
        let good = encoded_key([7u8; 32], ZeckNetwork::Mainnet);
        let err = keys_from_sapling_strings(
            &[good, "not a key".to_owned()],
            ZeckNetwork::Mainnet,
        )
        .expect_err("a malformed line must fail the whole set")
        .to_string();
        assert!(
            err.contains("line 2"),
            "the error should name the offending line, got: {err}"
        );
    }

    /// Silently scanning nothing is worse than refusing: it looks like a
    /// wallet with no funds.
    #[test]
    fn an_input_with_no_keys_at_all_is_an_error() {
        let err = keys_from_sapling_strings(
            &["# only a comment".to_owned(), String::new()],
            ZeckNetwork::Mainnet,
        )
        .expect_err("an empty key set must not be reported as success")
        .to_string();
        assert!(
            err.contains("no Sapling"),
            "the error should say no keys were found, got: {err}"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p argos-core --lib sapling_key`
Expected: FAIL to compile — `cannot find function keys_from_sapling_strings`.

- [ ] **Step 3: Write the implementation**

Append to the implementation section of `crates/zeck-core/src/sapling_key.rs`
(above `#[cfg(test)]`), and extend the `use` block at the top of the file with
`use argos_wallet_import::{ImportedKeys, Provenance, SaplingKey};` and
`use secrecy::Secret;`:

```rust
/// Turn pasted or file-supplied key strings into the same `ImportedKeys` a
/// wallet file would have produced.
///
/// This is the whole of the integration. Downstream — `ImportedKeySource`,
/// `run_imported_scan`, `imported_sweep` — cannot tell whether a key came
/// from a file or from a text box, and should not be able to.
///
/// Line numbers in errors are 1-based and count *every* input line,
/// comments included, so they match what the user sees in their editor.
pub fn keys_from_sapling_strings(
    lines: &[String],
    network: ZeckNetwork,
) -> ZeckResult<ImportedKeys> {
    let mut seen: Vec<[u8; 169]> = Vec::new();
    let mut sapling: Vec<SaplingKey> = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let extsk = decode_sapling_spending_key(line, network).map_err(|err| {
            ZeckError::Import(format!("line {}: {err}", index + 1))
        })?;
        let bytes = extsk.to_bytes();
        if seen.contains(&bytes) {
            continue;
        }
        seen.push(bytes);
        sapling.push(SaplingKey {
            extsk: Secret::new(bytes.to_vec()),
            provenance: Provenance::Standalone,
        });
    }

    if sapling.is_empty() {
        return Err(ZeckError::Import(
            "no Sapling spending keys found — expected at least one \
             `secret-extended-key-…` line"
                .to_owned(),
        ));
    }

    Ok(ImportedKeys {
        sapling,
        ..Default::default()
    })
}
```

- [ ] **Step 4: Correct the now-false `Provenance` doc**

In `crates/argos-wallet-import/src/keys.rs`, replace lines 13-15:

```rust
    /// Imported standalone (`z_importkey` / `importprivkey`). Exists in no
    /// seed — recoverable only from the wallet file.
    Standalone,
```

with:

```rust
    /// Imported standalone (`z_importkey` / `importprivkey`), or supplied
    /// directly as a key string. Exists in no seed, so it is recoverable
    /// only from the wallet file or from the key text itself — never
    /// re-derivable.
    Standalone,
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p argos-core --lib sapling_key`
Expected: PASS, 15 tests.

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy -p argos-core --all-targets -- -D warnings`

```bash
git add crates/zeck-core/src/sapling_key.rs crates/argos-wallet-import/src/keys.rs
git commit -m "feat(sapling): bridge decoded key strings into the imported-key path"
```

---

### Task 3: CLI — `--sapling-key-file`

**Files:**
- Modify: `crates/zeck-cli/src/main.rs` (flag declaration near line 60; a new
  loader beside `load_wallet_file` at line 252; the key-source `match` at
  line 1074)
- Test: `crates/zeck-cli/tests/wallet_file_cli.rs` (append)

**Interfaces:**
- Consumes: `argos_core::sapling_key::{keys_from_sapling_strings, decode_sapling_spending_key, default_sapling_address}` from Tasks 1-2.
- Produces: the `--sapling-key-file <PATH>` flag; no library surface.

**Background you need:**

`main.rs:1074` currently reads `match &cli.wallet_file { Some(path) => …,
None => … }` and produces the tuple `(Arc<dyn KeySource>,
Option<SecretString>, Option<Arc<ImportedKeySource>>)`. This task widens it
to a match over *where imported keys came from*. Routing below it needs no
change: `is_transparent_only` (line 376) already sends a Sapling-bearing key
set down the imported-account path.

The existing CLI test harness (`crates/zeck-cli/tests/wallet_file_cli.rs`)
runs the real binary with `stdin` closed, so any accidental interactive prompt
fails instead of hanging CI. Keep that.

- [ ] **Step 1: Write the failing tests**

Append to `crates/zeck-cli/tests/wallet_file_cli.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p argos-cli --test wallet_file_cli`
Expected: FAIL — clap reports `unexpected argument '--sapling-key-file'`, so
each new test fails on a non-zero exit carrying that message. The two
pinned key constants are already real values; nothing needs generating.

- [ ] **Step 3: Sanity-check the pinned constants against the decoder**

Before wiring anything, confirm the strings the CLI test pins are the ones
Task 1's decoder actually accepts. Add this to `sapling_key.rs`'s test module:

```rust
    /// The exact strings `crates/zeck-cli/tests/wallet_file_cli.rs` pins.
    /// If upstream encoding ever moves, this fails here — in a unit test with
    /// a clear message — rather than as a puzzling CLI exit code.
    #[test]
    fn the_strings_the_cli_tests_pin_still_decode() {
        const MAIN: &str = "secret-extended-key-main1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgqvp59t";
        const TEST: &str = "secret-extended-key-test1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgts9kat";

        let main = decode_sapling_spending_key(MAIN, ZeckNetwork::Mainnet)
            .expect("the pinned mainnet key must decode");
        let test = decode_sapling_spending_key(TEST, ZeckNetwork::Testnet)
            .expect("the pinned testnet key must decode");
        assert_eq!(
            main.to_bytes(),
            test.to_bytes(),
            "both strings encode the same key, differing only in network"
        );
    }
```

Run: `cargo test -p argos-core --lib sapling_key`
Expected: PASS, 16 tests.

- [ ] **Step 4: Add the flag**

In `crates/zeck-cli/src/main.rs`, immediately after the `sprout_key_file`
field (which ends at line 61 with `sprout_key_file: Option<PathBuf>,`):

```rust
    /// File holding Sapling extended spending keys
    /// (`secret-extended-key-main1…` mainnet, `secret-extended-key-test1…`
    /// testnet), one per line, for keys with no wallet file behind them.
    ///
    /// A file rather than a flag value, for the same reason as
    /// `--sprout-key-file`: a spending key passed as an argument lands in
    /// shell history and in `ps` output for every user on the box (T-S6).
    ///
    /// Combinable with `--wallet-file`: a user may hold a wallet *and* a
    /// paper key for an address that wallet never knew about.
    #[arg(long, conflicts_with = "seed_file")]
    sapling_key_file: Option<PathBuf>,
```

- [ ] **Step 5: Add the loader**

In `crates/zeck-cli/src/main.rs`, immediately after `load_wallet_file`
(which ends near line 287):

```rust
/// Read a Sapling key file into the same key set a wallet file produces.
///
/// The file is read as UTF-8 text and never logged. Decoding, comment
/// handling, deduplication, and line-numbered errors all live in
/// `argos_core::sapling_key`, so the CLI and the GUI cannot drift apart on
/// what a key file means.
fn load_sapling_key_file(path: &Path, network: ZeckNetwork) -> Result<ImportedKeys> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    argos_core::sapling_key::keys_from_sapling_strings(&lines, network)
        .with_context(|| format!("in {}", path.display()))
}

/// Fold key-file keys into a wallet file's key set.
///
/// Deduplicated against what the wallet already holds: re-pasting a key the
/// wallet contains would otherwise register a second account for the same
/// key and scan it twice.
fn merge_sapling_keys(into: &mut ImportedKeys, extra: ImportedKeys) {
    use secrecy::ExposeSecret;

    for key in extra.sapling {
        let bytes = key.extsk.expose_secret().clone();
        let already = into
            .sapling
            .iter()
            .any(|existing| *existing.extsk.expose_secret() == bytes);
        if !already {
            into.sapling.push(key);
        }
    }
}
```

- [ ] **Step 6: Widen the key-source match**

In `crates/zeck-cli/src/main.rs`, replace the `match &cli.wallet_file {` on
line 1075 with `match (&cli.wallet_file, &cli.sapling_key_file) {`, and
rewrite its arms as follows. The wallet-file arm's body is unchanged except
for the merge; the `None` arm is split in two.

```rust
    ) = match (&cli.wallet_file, &cli.sapling_key_file) {
        (Some(path), key_file) => {
            let mut keys = load_wallet_file(path)?;
            if let Some(key_path) = key_file {
                merge_sapling_keys(&mut keys, load_sapling_key_file(key_path, network)?);
            }
            let phrase = keys.mnemonic.clone();
            // `inspect-wallet` prints a fuller version of this below, so
            // don't say it twice.
            if !matches!(cli.command, Commands::InspectWallet) {
                eprintln!(
                    "Imported {} key(s) from {}.",
                    keys.total_keys(),
                    path.display()
                );
                if !keys.diagnostics.is_empty() {
                    eprintln!(
                        "{} record(s) could not be read — run `argos inspect-wallet \
                         --wallet-file {}` to see them.",
                        keys.diagnostics.len(),
                        path.display()
                    );
                }
            }
            let source = Arc::new(ImportedKeySource::new(keys));
            (source.clone(), phrase, Some(source))
        }
        (None, Some(key_path)) => {
            // A key file is its own key source. There is no seed behind it,
            // so `seed_phrase` stays `None` — birthday auto-detection and
            // `show-keys` are unavailable, exactly as for a wallet file with
            // no recoverable mnemonic.
            let keys = load_sapling_key_file(key_path, network)?;
            if !matches!(cli.command, Commands::InspectWallet) {
                eprintln!(
                    "Loaded {} Sapling key(s) from {}.",
                    keys.sapling.len(),
                    key_path.display()
                );
            }
            let source = Arc::new(ImportedKeySource::new(keys));
            (source.clone(), None, Some(source))
        }
        (None, None) => {
            // Bail before prompting: an interactive seed prompt for a
            // command that only reads a wallet file is pure confusion.
            if matches!(cli.command, Commands::InspectWallet) {
                bail!("inspect-wallet needs --wallet-file or --sapling-key-file");
            }
            let phrase = load_seed_phrase(cli.seed_file.clone())?;
            (
                Arc::new(SeedKeySource::new(phrase.clone())),
                Some(phrase),
                None,
            )
        }
    };
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p argos-cli --test wallet_file_cli`
Expected: PASS — the 6 pre-existing tests plus the 5 new ones.

If `inspect_wallet_reports_a_key_supplied_as_text` fails because
`print_wallet_inspection` prints no address for a Sapling key, extend that
function to print `default_sapling_address` for each entry in
`keys.sapling` — the address, never the key.

- [ ] **Step 8: Lint and commit**

Run: `cargo clippy -p argos-cli --all-targets -- -D warnings`

```bash
git add crates/zeck-cli/src/main.rs crates/zeck-cli/tests/wallet_file_cli.rs crates/zeck-core/src/sapling_key.rs
git commit -m "feat(cli): accept Sapling spending keys via --sapling-key-file"
```

---

### Task 4: GUI backend — `check_sapling_key` and typed keys in the scan

**Files:**
- Modify: `gui/src-tauri/src/commands.rs` (`WalletFileScanInput` at line 261;
  `start_scan_from_wallet_file` at line 281; new command beside
  `check_sprout_key` at line 651)
- Modify: `gui/src-tauri/src/main.rs:35-37` (register the new command)

**Interfaces:**
- Consumes: `argos_core::sapling_key::{decode_sapling_spending_key, default_sapling_address, keys_from_sapling_strings}` from Tasks 1-2.
- Produces:
  - Tauri command `check_sapling_key(key: String, network: String) -> Result<String, String>`
    returning the `zs1…`/`ztestsapling1…` address the key controls.
  - `WalletFileScanInput.path` becomes `Option<String>`; new field
    `sapling_keys: Vec<String>` (serde default). Task 5 depends on both.

- [ ] **Step 1: Make the wallet-file scan input accept typed keys**

In `gui/src-tauri/src/commands.rs`, change `WalletFileScanInput` (line 261):

```rust
#[derive(Deserialize)]
pub struct WalletFileScanInput {
    /// Absent when the user supplied only typed Sapling keys — a key string
    /// is a key source in its own right, with no file behind it.
    #[serde(default)]
    pub path: Option<String>,
    pub passphrase: Option<SecretString>,
    /// Sapling spending keys typed or pasted in the GUI, one per entry.
    #[serde(default)]
    pub sapling_keys: Vec<String>,
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
    pub lightwalletd_url: String,
    pub data_dir: String,
    pub network: ZeckNetwork,
    #[serde(default)]
    pub label: Option<String>,
}
```

- [ ] **Step 2: Merge typed keys into the scan's key source**

Replace the body of `start_scan_from_wallet_file` between `ensure_tos_accepted(&app)?;`
(line 288) and the `let key_source` binding (line 296) with:

```rust
    // Either source alone is enough, and both together are meaningful: a
    // user may hold a wallet whose keys were never rescanned *and* a paper
    // key for an address it never knew about. Mirrors the CLI's
    // `--wallet-file` + `--sapling-key-file` combination.
    let mut keys = match &config.path {
        Some(path) => {
            let bytes =
                fs::read(path).map_err(|err| format!("could not read {path}: {err}"))?;
            argos_core::argos_wallet_import::import_wallet_file(
                &bytes,
                config.passphrase.as_ref(),
            )
            .map_err(|err| err.to_string())?
        }
        None => argos_core::argos_wallet_import::ImportedKeys::default(),
    };

    if !config.sapling_keys.is_empty() {
        let typed = argos_core::sapling_key::keys_from_sapling_strings(
            &config.sapling_keys,
            config.network,
        )
        .map_err(|err| err.to_string())?;
        for key in typed.sapling {
            use secrecy::ExposeSecret;
            let bytes = key.extsk.expose_secret().clone();
            let already = keys
                .sapling
                .iter()
                .any(|existing| *existing.extsk.expose_secret() == bytes);
            if !already {
                keys.sapling.push(key);
            }
        }
    }

    if keys.is_empty() {
        return Err(
            "no keys to scan — open a wallet file or paste a Sapling spending key."
                .to_owned(),
        );
    }
```

- [ ] **Step 3: Add the key-check command**

In `gui/src-tauri/src/commands.rs`, immediately after `check_sprout_key`
(which ends at line 659):

```rust
/// Resolve a typed Sapling spending key to the address it controls.
///
/// Checked before the scan, not an hour into it — and the address is what
/// comes back, never the key, so nothing secret crosses the IPC boundary in
/// the reply or reaches a log.
#[tauri::command]
pub async fn check_sapling_key(key: String, network: String) -> Result<String, String> {
    let network = network_from(&network);
    let extsk = argos_core::sapling_key::decode_sapling_spending_key(key.trim(), network)
        .map_err(|err| err.to_string())?;
    Ok(argos_core::sapling_key::default_sapling_address(
        &extsk, network,
    ))
}
```

- [ ] **Step 4: Register the command**

In `gui/src-tauri/src/main.rs`, add `commands::check_sapling_key,` to the
`tauri::generate_handler!` list, immediately after `commands::check_sprout_key,`
(line 46).

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --manifest-path gui/src-tauri/Cargo.toml`
Expected: PASS. If it fails with `no field 'path'` at the existing call
sites, those are Task 5's JS callers and do not affect the Rust build —
any Rust error here is a real one; fix it before continuing.

Run: `cargo clippy --manifest-path gui/src-tauri/Cargo.toml --all-targets -- -D warnings`

- [ ] **Step 6: Commit**

```bash
git add gui/src-tauri/src/commands.rs gui/src-tauri/src/main.rs
git commit -m "feat(gui): accept typed Sapling spending keys in the scan backend"
```

---

### Task 5: GUI frontend — the paste-a-key panel, and docs

**Files:**
- Modify: `gui/src/index.html` (after `wallet-status`, line 287)
- Modify: `gui/src/main.js` (helpers near the Sprout key block at line 750;
  listeners near line 916; the `start-scan` handler at lines 1145-1236)
- Modify: `CLAUDE.md` (the "What import can and cannot do" section)

**Interfaces:**
- Consumes: `check_sapling_key` and the `path: Option<String>` /
  `sapling_keys: Vec<String>` shape of `WalletFileScanInput`, both from Task 4.
- Produces: no interface for later tasks — this is the last one.

- [ ] **Step 1: Add the markup**

In `gui/src/index.html`, immediately after
`<p id="wallet-status" class="status-line"></p>` (line 287):

```html
          <!-- A key with no wallet file behind it: from z_exportkey, from
               zcashd-wallet-tool, or from a paper backup. Always visible,
               not gated on a wallet file, because the user who needs it has
               no wallet file at all. -->
          <div id="sapling-key-panel">
            <hr />
            <p><strong>Or paste a Sapling spending key</strong></p>
            <label for="sapling-scan-keys">
              Sapling spending keys (one per line,
              <code>secret-extended-key-main1…</code>)
            </label>
            <textarea id="sapling-scan-keys" rows="3" spellcheck="false"
              placeholder="Leave blank if you opened a wallet file above"></textarea>
            <button id="sapling-keys-check" type="button">Check keys</button>
            <ul id="sapling-key-addresses" class="session-list"></ul>
            <p id="sapling-key-status" class="status-line"></p>
          </div>
```

- [ ] **Step 2: Add the JS helpers**

In `gui/src/main.js`, immediately before the `// ─── Sprout scan ───` banner
(line 746):

```js
// ─── Typed Sapling keys ─────────────────────────────────────────────────────
// The route for a user who has a spending key string and no wallet file.

function saplingScanKeys() {
  const box = $("sapling-scan-keys");
  if (!box) return [];
  return box.value.split("\n").map((k) => k.trim()).filter(Boolean);
}

async function checkSaplingKeys() {
  const list = $("sapling-key-addresses");
  list.innerHTML = "";
  const keys = saplingScanKeys();
  if (!keys.length) {
    setStatus(
      "sapling-key-status",
      walletFile
        ? "The Sapling keys in your wallet file will be used."
        : "Paste a Sapling spending key, or open a wallet file that holds some.",
      "",
    );
    return;
  }
  // Checked before the scan, not an hour into it.
  for (const [i, key] of keys.entries()) {
    try {
      const addr = await invoke("check_sapling_key", {
        key,
        network: $("network-select").value,
      });
      const li = document.createElement("li");
      li.textContent = addr;
      list.appendChild(li);
    } catch (err) {
      setStatus("sapling-key-status", `✗ key ${i + 1}: ${err}`, "error");
      return;
    }
  }
  setStatus("sapling-key-status", `${keys.length} key(s) look valid.`, "success");
}
```

- [ ] **Step 3: Wire the button**

In `gui/src/main.js`, immediately after
`$("sprout-scan-check").addEventListener("click", checkSproutKeys);` (line 916):

```js
$("sapling-keys-check")?.addEventListener("click", checkSaplingKeys);
```

- [ ] **Step 4: Let a typed key satisfy the start-scan gate**

In `gui/src/main.js`, replace the guard at lines 1147-1155:

```js
  if (!walletFile && !seedInput.value.trim()) {
    setStatus(
      "config-status",
      "A seed phrase or a wallet file is required — go back and provide one.",
      "error",
    );
    return;
  }
```

with:

```js
  // Three routes to the same scan: a seed phrase, a wallet file, or a
  // pasted Sapling spending key.
  if (!walletFile && !seedInput.value.trim() && !saplingScanKeys().length) {
    setStatus(
      "config-status",
      "A seed phrase, a wallet file, or a Sapling spending key is required — \
go back and provide one.",
      "error",
    );
    return;
  }
```

- [ ] **Step 5: Send the typed keys with the scan**

In `gui/src/main.js`, replace the branch at lines 1219-1228:

```js
    if (walletFile) {
      const { seed: _unused, ...rest } = config;
      handle = await invoke("start_scan_from_wallet_file", {
        config: { ...rest, path: walletFile.path, passphrase: walletFile.passphrase },
      });
    } else {
```

with:

```js
    const typedSaplingKeys = saplingScanKeys();
    if (walletFile || typedSaplingKeys.length) {
      // Routing between the HD path and the imported-account path lives in
      // the core service, not here: it depends on whether the file yielded a
      // mnemonic, which only the backend knows. The GUI just hands over the
      // key material it was given.
      const { seed: _unused, ...rest } = config;
      handle = await invoke("start_scan_from_wallet_file", {
        config: {
          ...rest,
          path: walletFile ? walletFile.path : null,
          passphrase: walletFile ? walletFile.passphrase : null,
          sapling_keys: typedSaplingKeys,
        },
      });
    } else {
```

- [ ] **Step 6: Clear the typed keys once the backend holds them**

In `gui/src/main.js`, immediately after
`if (walletFile) walletFile.passphrase = null;` (line 1236):

```js
    // The backend holds the decoded keys now; a spending key must not sit
    // in the DOM for the lifetime of the scan→sweep→complete flow (T-S2).
    const saplingBox = $("sapling-scan-keys");
    if (saplingBox) saplingBox.value = "";
    $("sapling-key-addresses").innerHTML = "";
```

- [ ] **Step 7: Verify the GUI builds and the panel works**

Run: `cargo check --manifest-path gui/src-tauri/Cargo.toml`
Expected: PASS.

Then run the app (`npm run tauri dev` from `gui/`, or the project's usual
launch) and confirm by hand:
1. The "Or paste a Sapling spending key" panel appears on the wallet screen.
2. Pasting the mainnet key generated in Task 3 Step 2 and clicking **Check
   keys** lists a `zs1…` address.
3. Pasting the testnet key with the network set to mainnet shows an error
   naming testnet.
4. Starting a scan with only a pasted key does not report "a seed phrase or a
   wallet file is required", and the textarea is empty afterwards.

- [ ] **Step 8: Record the new route in CLAUDE.md**

In `CLAUDE.md`, in the "What import can and cannot do" section, immediately
before the paragraph beginning "**Transparent keys are handled outside that
model entirely**", insert:

```markdown
**A Sapling spending key can also arrive as text**, with no wallet file at
all: `argos_core::sapling_key` decodes zcashd's bech32
`secret-extended-key-main1…` / `secret-extended-key-test1…` form and
`keys_from_sapling_strings` packs it into the same `ImportedKeys` a wallet
file produces, so the scan and sweep paths cannot tell the two apart. CLI
`--sapling-key-file` (a file, never a flag — a spending key in argv lands in
shell history and `ps`); GUI a paste field on the wallet screen. Both are
combinable with a wallet file and deduplicate against it. Unlike Sprout's
base58 constants, the human-readable prefixes come from
`zcash_protocol::constants`, so there is no unverifiable-constant caveat —
but the test pinning them to the ZIP-32 literals stays, so an upstream rename
cannot silently move Argos off the prefix users hold. Viewing keys
(`zxviews…`) are deliberately refused: they would show a balance that cannot
be swept.
```

- [ ] **Step 9: Full check and commit**

Run: `cargo test --workspace`
Expected: no new failures against the baseline captured before Task 1.

Run: `cargo clippy --all-targets -- -D warnings`

```bash
git add gui/src/index.html gui/src/main.js CLAUDE.md
git commit -m "feat(gui): paste a Sapling spending key to scan without a wallet file"
```

---

## Verification checklist

Before declaring the work done, all of the following must have been run with
output seen, not assumed:

- [ ] `cargo test -p argos-core --lib sapling_key` — 16 tests pass
- [ ] `cargo test -p argos-cli --test wallet_file_cli` — 11 tests pass
- [ ] `cargo test --workspace` — no new failures vs. the pre-Task-1 baseline
- [ ] `cargo clippy --all-targets -- -D warnings` — clean
- [ ] `cargo check --manifest-path gui/src-tauri/Cargo.toml` — clean
- [ ] The GUI hand-check in Task 5 Step 7 — all four points confirmed
- [ ] `git diff main --stat` shows no change to `Cargo.toml` dependency lists
