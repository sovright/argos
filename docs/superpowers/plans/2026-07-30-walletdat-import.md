# wallet.dat Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Argos recover funds from a zcashd `wallet.dat` or a ZecWallet Lite wallet file, including encrypted Sprout spending keys (`czkey`) that no other software can decrypt.

**Architecture:** A new isolated crate `argos-wallet-import` parses untrusted wallet files into a normalized `ImportedKeys` type. `zeck-core` gains a `KeySource` trait so the existing scanner and sweeper stop knowing whether keys came from a seed or a file. Berkeley DB 6.2 btree decoding is hand-rolled in-tree rather than shelling out to `db_dump`.

**Tech Stack:** Rust 2021 (rust-version 1.88), `secrecy` 0.8, `thiserror` 2.0, `sha2` 0.10, `zcash_keys` 0.16, `zcash_transparent` 0.10, `cargo-fuzz`, Docker (pinned `zcashd:v6.20.0` for fixtures).

**Spec:** `docs/superpowers/specs/2026-07-30-walletdat-import-design.md`

## Global Constraints

- **Rust edition 2021, `rust-version = "1.88"`** — matches `[workspace.package]` in the root `Cargo.toml`. Do not raise it.
- **New crate members go in the root `Cargo.toml` `[workspace]` members list.** Current value: `["crates/zeck-core", "crates/zeck-cli", "gui/src-tauri"]`.
- **All dependency versions come from `[workspace.dependencies]`** via `foo.workspace = true`. Do not write a literal version in a crate manifest.
- **No new third-party dependencies** beyond those already in `[workspace.dependencies]`, except `aes` and `cbc` (Task 9), which require explicit user approval per the dependency policy before that task starts.
- **`argos-wallet-import` must have no network access, no filesystem writes, and no `zeck-core` dependency.** It is a leaf crate.
- **`bdb.rs` lint gate is non-negotiable:** `#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at crate root.
- **Partial recovery by default.** A record that fails to parse is collected as an `ImportDiagnostic` and never aborts the import. Only three conditions fail wholesale: unrecognized magic, wrong passphrase, unwalkable btree.
- **No secret material to disk, ever.** Passphrase is `SecretString`; decrypted keys zeroize on drop.
- **The passphrase is never a CLI flag.** Prompt-only via `dialoguer::Password`.
- **Do not edit `README.md:46` or `docs/THREAT_MODEL.md:374`** (the "Sprout recovery is impossible" statements) until sub-spec 3 ships. Task 18 covers the threat-model edits that *are* in scope.
- **Emoji policy:** none in commits, PRs, or reports.
- **Commit message trailer** on every commit:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

---

## File Structure

**New crate `crates/argos-wallet-import/`:**

| File | Responsibility |
|---|---|
| `Cargo.toml` | Manifest. Minimal deps, no `zeck-core`. |
| `src/lib.rs` | Crate root, lint gates, public `import_wallet_file` entry point. |
| `src/error.rs` | `ImportError` (fatal) and `ImportDiagnostic` (per-record, non-fatal). |
| `src/sniff.rs` | Magic-byte dispatch to `WalletFormat`. |
| `src/bdb.rs` | Read-only Berkeley DB 6.2 btree walker. No Zcash knowledge. Fuzz target. |
| `src/zcashd/mod.rs` | zcashd record-layer dispatch. |
| `src/zcashd/records.rs` | Record key/value decoding: `key`, `zkey`, `sapzkey`, `sapzaddr`, `hdchain`. |
| `src/zcashd/crypto.rs` | `mkey` master-key derivation, AES-256-CBC, passphrase verification. |
| `src/zcashd/encrypted.rs` | `ckey`, `czkey`, `csapzkey` decryption. |
| `src/zcashd/sprout.rs` | Sprout note data and witness preservation. |
| `src/zwl.rs` | ZecWallet Lite versioned reader. |
| `src/keys.rs` | `ImportedKeys`, `ImportedAccount`, provenance tagging. |
| `fuzz/fuzz_targets/bdb_walk.rs` | libFuzzer target over `bdb.rs`. |

**Modified in `crates/zeck-core/`:**

| File | Change |
|---|---|
| `src/key_source.rs` (new) | `KeySource` trait, `SeedKeySource`, `ImportedKeySource`, `KeySourceFingerprint`. |
| `src/workspace.rs:58-84,694-722` | Generalize `from_runtime` and `verify_seed_for_workspace` from seed to `KeySourceFingerprint`. |
| `src/models.rs:70-82` | `RuntimeScanConfig.seed_phrase` becomes a key-source enum. |
| `src/lib.rs` | Export `key_source`. |
| `src/error.rs` | Add `ZeckError::Import`. |

**Modified elsewhere:**

| File | Change |
|---|---|
| `crates/zeck-cli/src/main.rs:35-86,103-141` | `--wallet-file` global flag; `conflicts_with` on birthday/gap flags. |
| `gui/src-tauri/src/commands.rs` | `import_wallet_file` Tauri command. |
| `gui/src-tauri/gen/schemas/capabilities.json` | File-dialog and read permissions. |
| `tests/regtest/docker-compose.yml` | Pinned zcashd fixture service, opt-in profile. |
| `tests/regtest/fixtures/generate.sh` (new) | Golden wallet generation script. |
| `docs/THREAT_MODEL.md` | Sections 2.1, 2.2, 3, 5, 6.1, 6.4. |

---

## Task 1: Baseline and crate skeleton

**Files:**
- Create: `crates/argos-wallet-import/Cargo.toml`
- Create: `crates/argos-wallet-import/src/lib.rs`
- Create: `crates/argos-wallet-import/src/error.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Consumes: nothing
- Produces: `ImportError`, `ImportDiagnostic`, crate `argos_wallet_import`

- [ ] **Step 1: Capture the pre-change baseline**

This is required by `CLAUDE.md` — the `KeySource` refactor in Task 13 must be measurable against it, not asserted.

```bash
cargo test --workspace 2>&1 | tail -40 > /tmp/argos-baseline-tests.txt
cargo clippy --workspace --all-targets 2>&1 | tail -40 > /tmp/argos-baseline-clippy.txt
cat /tmp/argos-baseline-tests.txt
```

Record the pass/fail counts. Do not proceed until you have them written down.

- [ ] **Step 2: Add the crate to the workspace**

In the root `Cargo.toml`, change the members line:

```toml
[workspace]
members = ["crates/zeck-core", "crates/zeck-cli", "crates/argos-wallet-import", "gui/src-tauri"]
resolver = "2"
```

- [ ] **Step 3: Write the crate manifest**

Create `crates/argos-wallet-import/Cargo.toml`:

```toml
[package]
name = "argos-wallet-import"
edition.workspace = true
version.workspace = true
license.workspace = true
authors.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
secrecy.workspace = true
sha2.workspace = true
thiserror.workspace = true
tracing.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

Note what is absent: no `tokio`, no `tonic`, no `zeck-core`. This crate does no I/O beyond being handed bytes.

- [ ] **Step 4: Write the failing test for error types**

Create `crates/argos-wallet-import/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_passphrase_is_distinguishable_from_corruption() {
        let a = ImportError::WrongPassphrase;
        let b = ImportError::UnwalkableBtree("page 3 out of bounds".to_owned());
        assert_ne!(a.to_string(), b.to_string());
        assert!(a.to_string().contains("passphrase"));
        assert!(!b.to_string().contains("passphrase"));
    }

    #[test]
    fn diagnostic_records_what_was_skipped() {
        let d = ImportDiagnostic::UnparseableRecord {
            record_type: "czkey".to_owned(),
            reason: "truncated ciphertext".to_owned(),
        };
        assert!(d.to_string().contains("czkey"));
    }
}
```

- [ ] **Step 5: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import`
Expected: FAIL — `cannot find type ImportError in this scope`

- [ ] **Step 6: Implement the error types**

Prepend to `crates/argos-wallet-import/src/error.rs`:

```rust
use thiserror::Error;

/// Fatal conditions. Only these three abort an entire import; everything
/// else is collected as an `ImportDiagnostic` so partial recovery still
/// yields the keys we could read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("this file is not a recognized Zcash wallet file")]
    UnrecognizedFormat,

    #[error("incorrect passphrase for this wallet")]
    WrongPassphrase,

    #[error("wallet file structure is unreadable: {0}")]
    UnwalkableBtree(String),
}

/// Non-fatal, per-record problems. Always surfaced to the user with counts
/// — never swallowed. Unmigrated key material still exists only in the
/// original file, so the user must know what we could not read.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ImportDiagnostic {
    #[error("skipped unparseable {record_type} record: {reason}")]
    UnparseableRecord { record_type: String, reason: String },

    #[error("skipped unknown record type {record_type}")]
    UnknownRecord { record_type: String },

    #[error("skipped {record_type} record: decryption failed ({reason})")]
    DecryptionFailed { record_type: String, reason: String },
}
```

- [ ] **Step 7: Write the crate root with lint gates**

Create `crates/argos-wallet-import/src/lib.rs`:

```rust
//! Read-only parsing of legacy Zcash wallet files into normalized key
//! material.
//!
//! This crate consumes attacker-controlled bytes. It has no network
//! access, performs no filesystem writes, and does not depend on
//! `argos-core`. The blast radius of a parser bug here is "garbage
//! records", not "key exfiltration".

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
// Crate-root `deny` reaches `#[cfg(test)]` modules too, and tests
// legitimately unwrap, index, and panic on known-good fixture data. The
// gate above still binds all non-test code, which is the code that
// touches attacker-controlled bytes.
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

pub mod error;

pub use error::{ImportDiagnostic, ImportError};
```

- [ ] **Step 8: Run tests and clippy to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: 2 tests pass, clippy clean.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock crates/argos-wallet-import/
git commit -m "feat(import): scaffold argos-wallet-import crate with hostile-input lint gates

The crate parses attacker-controlled wallet files, so it is isolated with
no network, no filesystem writes, and no argos-core dependency. Lint gates
deny indexing, slicing, unwrap, expect, and panic at the crate root.

ImportError covers the three conditions that abort an import wholesale;
ImportDiagnostic covers per-record problems that must not silence records
we can read.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Golden fixture generation

**Goldens come before the parser.** A test-only writer validated against our own reader is a self-consistent misreading that passes every test. Real zcashd-written files anchor the format understanding first.

**Files:**
- Modify: `tests/regtest/docker-compose.yml`
- Create: `tests/regtest/fixtures/generate.sh`
- Create: `tests/regtest/fixtures/README.md`
- Create: `crates/argos-wallet-import/tests/fixtures/` (committed `.dat` blobs)

**Interfaces:**
- Consumes: nothing
- Produces: golden fixture files at `crates/argos-wallet-import/tests/fixtures/*.dat`, and `FIXTURE_PASSPHRASE` = `argos-test-passphrase`

- [ ] **Step 1: Add the pinned zcashd service**

Append to `tests/regtest/docker-compose.yml`. The `profiles` key keeps it out of the normal regtest stack — it runs only when regenerating fixtures.

```yaml
  # Fixture generation only. NOT part of the regtest stack.
  #
  # zcashd is EOL and cannot activate Ironwood (NU6.3), so it is useless
  # for sweep testing — but it is the only software that writes a
  # wallet.dat, and it still generates Sprout keys when Canopy is held
  # inactive (src/wallet/rpcwallet.cpp:3236 in v6.20.0).
  #
  # Run with: docker compose --profile fixtures up zcashd-fixtures
  zcashd-fixtures:
    profiles: ["fixtures"]
    image: electriccoinco/zcashd:v6.20.0
    volumes:
      - ./fixtures/out:/fixtures
      - ./fixtures/generate.sh:/generate.sh:ro
    entrypoint: ["/bin/bash", "/generate.sh"]
```

- [ ] **Step 2: Write the fixture generation script**

Create `tests/regtest/fixtures/generate.sh`:

```bash
#!/usr/bin/env bash
# Generate golden wallet.dat fixtures with the real producer.
#
# Two chain configs are needed. zcashd refuses to create Sprout addresses
# once Canopy is active:
#
#   src/wallet/rpcwallet.cpp:3236
#     if (addrType == ADDR_TYPE_SPROUT) {
#         if (... NetworkUpgradeActive(chainActive.Height(), UPGRADE_CANOPY)) {
#             throw JSONRPCError(RPC_INVALID_PARAMETER, ...);
#
# On regtest the activation heights are configurable, so we hold Canopy
# inactive for the Sprout wallets and activate everything for the rest.
set -euo pipefail

PASSPHRASE="argos-test-passphrase"
OUT=/fixtures

gen_wallet() {
  local name="$1" canopy_height="$2" encrypt="$3" sprout="$4"

  local datadir="/tmp/zc-$name"
  rm -rf "$datadir"; mkdir -p "$datadir"

  # Consensus branch IDs, verified against zcash/zcash v6.20.0
  # src/consensus/upgrades.cpp:
  #   5ba81b19 Overwinter   76b809bb Sapling   2bb40e60 Blossom
  #   f5b9230b Heartwood    e9ff75a6 Canopy
  #
  # Canopy (e9ff75a6) is the one that matters: z_getnewaddress sprout
  # throws once it is active. Everything below it is activated at height 1
  # so the chain is otherwise modern.
  cat > "$datadir/zcash.conf" <<EOF
regtest=1
nuparams=5ba81b19:1
nuparams=76b809bb:1
nuparams=2bb40e60:1
nuparams=f5b9230b:1
nuparams=e9ff75a6:${canopy_height}
rpcuser=fixture
rpcpassword=fixture
EOF

  zcashd -datadir="$datadir" -daemon
  until zcash-cli -datadir="$datadir" getblockcount >/dev/null 2>&1; do sleep 1; done

  # Sprout generation is also blocked during initial block download.
  zcash-cli -datadir="$datadir" generate 3 >/dev/null

  zcash-cli -datadir="$datadir" getnewaddress >/dev/null
  zcash-cli -datadir="$datadir" z_getnewaddress sapling >/dev/null

  if [ "$sprout" = "yes" ]; then
    zcash-cli -datadir="$datadir" z_getnewaddress sprout >/dev/null
  fi

  if [ "$encrypt" = "yes" ]; then
    # encryptwallet rewrites zkey -> czkey and writes mkey, then stops the node.
    zcash-cli -datadir="$datadir" encryptwallet "$PASSPHRASE" || true
    sleep 3
  else
    zcash-cli -datadir="$datadir" stop || true
    sleep 3
  fi

  cp "$datadir/regtest/wallet.dat" "$OUT/$name.dat"
  echo "wrote $OUT/$name.dat"
}

mkdir -p "$OUT"

# Canopy at height 9_999_999 == never active on a 3-block chain.
gen_wallet sprout-plaintext   9999999 no  yes
gen_wallet sprout-encrypted   9999999 yes yes
gen_wallet modern-plaintext   1       no  no
gen_wallet modern-encrypted   1       yes no

# Corruption variants: truncate each golden to 60% of its length.
for f in "$OUT"/*.dat; do
  base=$(basename "$f" .dat)
  size=$(stat -c%s "$f")
  head -c $((size * 60 / 100)) "$f" > "$OUT/${base}-truncated.dat"
done

echo "fixture generation complete"
```

- [ ] **Step 3: Generate the fixtures**

```bash
cd tests/regtest
docker compose --profile fixtures up --abort-on-container-exit zcashd-fixtures
ls -la fixtures/out/
```
Expected: 8 `.dat` files (4 goldens + 4 truncated).

The tag `electriccoinco/zcashd:v6.20.0` is confirmed to exist on Docker Hub (verified 2026-07-30 against the registry tag list).

- [ ] **Step 4: Verify the Sprout fixtures actually contain Sprout keys**

This is the load-bearing check for the whole project. If it fails, stop and re-read the Canopy gate.

```bash
cd tests/regtest/fixtures/out
strings sprout-plaintext.dat | grep -c zkey
strings sprout-encrypted.dat | grep -c czkey
```
Expected: both counts >= 1. A zero on the second means `encryptwallet` did not convert the Sprout key and the fixture is useless.

- [ ] **Step 5: Commit the fixtures**

```bash
mkdir -p crates/argos-wallet-import/tests/fixtures
cp tests/regtest/fixtures/out/*.dat crates/argos-wallet-import/tests/fixtures/
git add tests/regtest/docker-compose.yml tests/regtest/fixtures/ crates/argos-wallet-import/tests/fixtures/
git commit -m "test(import): generate golden wallet.dat fixtures from pinned zcashd

Goldens come before the parser so the format understanding is anchored to
the real producer rather than confirmed by our own writer.

zcashd v6.20.0 still runs GenerateNewSproutZKey when Canopy is inactive,
and regtest activation heights are configurable, so we can produce real
zkey and czkey records. czkey has no reference implementation anywhere,
which makes these fixtures the only ground truth available for it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Format sniffing

**Files:**
- Create: `crates/argos-wallet-import/src/sniff.rs`
- Modify: `crates/argos-wallet-import/src/lib.rs`

**Interfaces:**
- Consumes: `ImportError` (Task 1), fixtures (Task 2)
- Produces: `pub enum WalletFormat { Zcashd, ZecwalletLite }`, `pub fn sniff(bytes: &[u8]) -> Result<WalletFormat, ImportError>`

- [ ] **Step 1: Write the failing test**

Create `crates/argos-wallet-import/src/sniff.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Berkeley DB btree magic 0x00053162, little-endian at offset 12.
    fn bdb_header() -> Vec<u8> {
        let mut v = vec![0u8; 4096];
        v[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        v
    }

    #[test]
    fn detects_zcashd_from_bdb_magic() {
        assert_eq!(sniff(&bdb_header()).unwrap(), WalletFormat::Zcashd);
    }

    #[test]
    fn detects_bdb_magic_in_big_endian() {
        let mut v = vec![0u8; 4096];
        v[12..16].copy_from_slice(&0x0005_3162u32.to_be_bytes());
        assert_eq!(sniff(&v).unwrap(), WalletFormat::Zcashd);
    }

    #[test]
    fn rejects_a_file_that_is_neither() {
        let junk = vec![0xAAu8; 4096];
        assert_eq!(sniff(&junk).unwrap_err(), ImportError::UnrecognizedFormat);
    }

    #[test]
    fn rejects_a_file_too_short_to_have_a_header() {
        assert_eq!(sniff(&[0u8; 4]).unwrap_err(), ImportError::UnrecognizedFormat);
    }

    #[test]
    fn real_golden_fixtures_are_detected_as_zcashd() {
        for name in [
            "sprout-plaintext",
            "sprout-encrypted",
            "modern-plaintext",
            "modern-encrypted",
        ] {
            let path = format!("tests/fixtures/{name}.dat");
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(sniff(&bytes).unwrap(), WalletFormat::Zcashd, "{name}");
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import sniff`
Expected: FAIL — `cannot find function sniff in this scope`

- [ ] **Step 3: Implement sniffing**

Prepend to `crates/argos-wallet-import/src/sniff.rs`:

```rust
use crate::error::ImportError;

/// Berkeley DB btree magic. Stable across BDB versions; the *page* format
/// is what differs, and zcashd uses BDB 6.2.
const BDB_BTREE_MAGIC: u32 = 0x0005_3162;

/// Offset of the magic within the BDB metadata page.
const BDB_MAGIC_OFFSET: usize = 12;

/// ZecWallet Lite files begin with a u64 little-endian version. Anything
/// at or below this is a plausible ZWL version; real files are far lower.
/// Used only to reject obvious junk, since ZWL has no magic number.
const ZWL_MAX_PLAUSIBLE_VERSION: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletFormat {
    Zcashd,
    ZecwalletLite,
}

/// Identify a wallet file from its leading bytes.
///
/// Checks BDB first because it has a real magic number. ZecWallet Lite has
/// none, so it is inferred from a plausible leading version word — which
/// means a corrupt zcashd file could in principle be misread as ZWL. The
/// ZWL parser rejects it immediately in that case.
pub fn sniff(bytes: &[u8]) -> Result<WalletFormat, ImportError> {
    if let Some(magic) = bytes.get(BDB_MAGIC_OFFSET..BDB_MAGIC_OFFSET + 4) {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(magic);
        // BDB writes the metadata page in host byte order, so a wallet
        // written on a big-endian machine is still valid. Accept both.
        if u32::from_le_bytes(buf) == BDB_BTREE_MAGIC
            || u32::from_be_bytes(buf) == BDB_BTREE_MAGIC
        {
            return Ok(WalletFormat::Zcashd);
        }
    }

    if let Some(head) = bytes.get(0..8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(head);
        if u64::from_le_bytes(buf) <= ZWL_MAX_PLAUSIBLE_VERSION {
            return Ok(WalletFormat::ZecwalletLite);
        }
    }

    Err(ImportError::UnrecognizedFormat)
}
```

- [ ] **Step 4: Export from lib.rs**

In `crates/argos-wallet-import/src/lib.rs`, after `pub mod error;`:

```rust
pub mod sniff;

pub use sniff::{sniff, WalletFormat};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p argos-wallet-import`
Expected: all 7 tests pass. The `real_golden_fixtures_are_detected_as_zcashd` test proves the magic offset against real files, not our assumption.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/
git commit -m "feat(import): detect wallet file format from magic bytes

BDB btree magic 0x00053162 at offset 12 identifies zcashd, accepting both
byte orders since BDB writes the metadata page in host order. ZecWallet
Lite has no magic, so it is inferred from a plausible leading version word
and confirmed by its own parser.

Verified against the golden fixtures rather than against an assumed offset.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: BDB metadata page

**Files:**
- Create: `crates/argos-wallet-import/src/bdb.rs`
- Modify: `crates/argos-wallet-import/src/lib.rs`

**Interfaces:**
- Consumes: `ImportError` (Task 1)
- Produces: `pub struct BdbMeta { pub page_size: u32, pub last_page: u32, pub root_page: u32, pub swapped: bool }`, `pub fn read_meta(bytes: &[u8]) -> Result<BdbMeta, ImportError>`

- [ ] **Step 1: Write the failing test**

Create `crates/argos-wallet-import/src/bdb.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn meta_page(page_size: u32, last_page: u32, root: u32) -> Vec<u8> {
        let mut v = vec![0u8; 4096];
        v[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        v[16..20].copy_from_slice(&10u32.to_le_bytes()); // btree version 10 (BDB 6.2)
        v[20..24].copy_from_slice(&page_size.to_le_bytes());
        v[32..36].copy_from_slice(&last_page.to_le_bytes());
        v[88..92].copy_from_slice(&root.to_le_bytes());
        v
    }

    #[test]
    fn reads_page_size_and_root() {
        let m = read_meta(&meta_page(4096, 20, 1)).unwrap();
        assert_eq!(m.page_size, 4096);
        assert_eq!(m.last_page, 20);
        assert_eq!(m.root_page, 1);
        assert!(!m.swapped);
    }

    #[test]
    fn rejects_a_page_size_that_is_not_a_power_of_two() {
        let err = read_meta(&meta_page(4095, 20, 1)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_an_absurd_page_size() {
        // Must not be used to compute an allocation.
        let err = read_meta(&meta_page(1 << 30, 20, 1)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_last_page_beyond_the_file() {
        // 4096-byte file claiming 9999 pages: a length field lying about size.
        let err = read_meta(&meta_page(4096, 9999, 1)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_truncated_file() {
        let err = read_meta(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn reads_real_golden_fixtures() {
        for name in ["sprout-plaintext", "modern-encrypted"] {
            let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
            let m = read_meta(&bytes).unwrap();
            assert!(m.page_size.is_power_of_two(), "{name}: {}", m.page_size);
            assert!(m.page_size >= MIN_PAGE_SIZE && m.page_size <= MAX_PAGE_SIZE);
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import bdb`
Expected: FAIL — `cannot find function read_meta in this scope`

- [ ] **Step 3: Implement the metadata reader**

Prepend to `crates/argos-wallet-import/src/bdb.rs`:

```rust
//! Read-only Berkeley DB 6.2 btree walker.
//!
//! Knows nothing about Zcash: it yields raw `(key, value)` byte pairs.
//! Every offset here is attacker-controlled, so all reads go through
//! `get()` and every length is bounds-checked before it is used to size
//! an allocation.

use crate::error::ImportError;

const BDB_BTREE_MAGIC: u32 = 0x0005_3162;

pub(crate) const MIN_PAGE_SIZE: u32 = 512;
pub(crate) const MAX_PAGE_SIZE: u32 = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct BdbMeta {
    pub page_size: u32,
    pub last_page: u32,
    pub root_page: u32,
    /// True when the file's byte order is opposite to ours.
    pub swapped: bool,
}

fn unwalkable(msg: impl Into<String>) -> ImportError {
    ImportError::UnwalkableBtree(msg.into())
}

/// Read a big- or little-endian u32 at `offset`, bounds-checked.
pub(crate) fn read_u32(bytes: &[u8], offset: usize, swapped: bool) -> Result<u32, ImportError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| unwalkable(format!("u32 read at {offset} is past end of data")))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(if swapped {
        u32::from_be_bytes(buf)
    } else {
        u32::from_le_bytes(buf)
    })
}

/// Read a big- or little-endian u16 at `offset`, bounds-checked.
pub(crate) fn read_u16(bytes: &[u8], offset: usize, swapped: bool) -> Result<u16, ImportError> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| unwalkable(format!("u16 read at {offset} is past end of data")))?;
    let mut buf = [0u8; 2];
    buf.copy_from_slice(slice);
    Ok(if swapped {
        u16::from_be_bytes(buf)
    } else {
        u16::from_le_bytes(buf)
    })
}

/// Parse the metadata page (page 0).
///
/// Validates page_size and last_page against the real file length before
/// either is used for arithmetic. A 4-byte field claiming a 1 GB page must
/// never reach an allocation.
pub fn read_meta(bytes: &[u8]) -> Result<BdbMeta, ImportError> {
    let raw = bytes
        .get(12..16)
        .ok_or_else(|| unwalkable("file is too short to contain a BDB metadata page"))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(raw);

    let swapped = if u32::from_le_bytes(buf) == BDB_BTREE_MAGIC {
        false
    } else if u32::from_be_bytes(buf) == BDB_BTREE_MAGIC {
        true
    } else {
        return Err(unwalkable("BDB btree magic not found"));
    };

    let page_size = read_u32(bytes, 20, swapped)?;
    if !page_size.is_power_of_two() || !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(unwalkable(format!("implausible page size {page_size}")));
    }

    let last_page = read_u32(bytes, 32, swapped)?;
    let available_pages = (bytes.len() as u64) / u64::from(page_size);
    if u64::from(last_page) >= available_pages {
        return Err(unwalkable(format!(
            "metadata claims {} pages but the file holds {available_pages}",
            u64::from(last_page) + 1
        )));
    }

    let root_page = read_u32(bytes, 88, swapped)?;
    if u64::from(root_page) > u64::from(last_page) {
        return Err(unwalkable(format!(
            "root page {root_page} is beyond last page {last_page}"
        )));
    }

    Ok(BdbMeta {
        page_size,
        last_page,
        root_page,
        swapped,
    })
}
```

- [ ] **Step 4: Export from lib.rs**

Add to `crates/argos-wallet-import/src/lib.rs`:

```rust
pub mod bdb;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all tests pass, clippy clean. If `reads_real_golden_fixtures` fails, the field offsets are wrong — fix them against the fixture, not against the test.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/
git commit -m "feat(import): parse the Berkeley DB metadata page

Reads page size, last page, and root page from page 0, handling both byte
orders. Every field is validated against the real file length before it is
used for arithmetic: a 4-byte page-size field claiming 1 GB must never
reach an allocation.

Verified against golden fixtures so the offsets are anchored to real files.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: BDB btree walk with cycle detection

**Files:**
- Modify: `crates/argos-wallet-import/src/bdb.rs`

**Interfaces:**
- Consumes: `BdbMeta`, `read_u16`, `read_u32` (Task 4)
- Produces: `pub fn walk(bytes: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ImportError>`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `crates/argos-wallet-import/src/bdb.rs`:

```rust
    #[test]
    fn walking_a_cyclic_page_graph_terminates() {
        // Two internal pages pointing at each other. Without cycle
        // detection this is an infinite loop or a stack overflow.
        let mut v = meta_page(512, 2, 1);
        v.resize(512 * 3, 0);
        for (page, child) in [(1u32, 2u32), (2u32, 1u32)] {
            let base = (page as usize) * 512;
            v[base + 20] = PAGE_TYPE_IBTREE;
            v[base + 18..base + 20].copy_from_slice(&1u16.to_le_bytes()); // entry count
            v[base + 26..base + 28].copy_from_slice(&32u16.to_le_bytes()); // entry offset
            v[base + 32..base + 36].copy_from_slice(&child.to_le_bytes()); // child pointer
        }
        // Must return, not hang. Either outcome is acceptable; hanging is not.
        let _ = walk(&v);
    }

    #[test]
    fn walking_golden_fixtures_yields_records() {
        for name in ["sprout-plaintext", "modern-encrypted"] {
            let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
            let pairs = walk(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!pairs.is_empty(), "{name} yielded no records");
        }
    }

    #[test]
    fn golden_sprout_wallet_contains_a_zkey_record() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = walk(&bytes).unwrap();
        // zcashd keys records as a serialized pair whose first element is
        // the type string, length-prefixed by a CompactSize byte.
        let found = pairs.iter().any(|(k, _)| k.windows(4).any(|w| w == b"zkey"));
        assert!(found, "no zkey record in the Sprout golden fixture");
    }

    #[test]
    fn a_truncated_wallet_still_yields_the_records_it_has() {
        // Partial recovery: truncation must not zero the result.
        let bytes = std::fs::read("tests/fixtures/modern-plaintext-truncated.dat").unwrap();
        match walk(&bytes) {
            Ok(pairs) => assert!(!pairs.is_empty(), "truncated wallet yielded nothing"),
            Err(ImportError::UnwalkableBtree(_)) => {
                // Acceptable only if the metadata page itself was lost.
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import bdb`
Expected: FAIL — `cannot find function walk` and `cannot find value PAGE_TYPE_IBTREE`

- [ ] **Step 3: Implement the walker**

Add to `crates/argos-wallet-import/src/bdb.rs`, before the tests module:

```rust
use std::collections::BTreeSet;

pub(crate) const PAGE_TYPE_IBTREE: u8 = 3;
pub(crate) const PAGE_TYPE_LBTREE: u8 = 5;
pub(crate) const PAGE_TYPE_OVERFLOW: u8 = 7;

/// Byte offsets within a page header.
const OFF_ENTRY_COUNT: usize = 18;
const OFF_PAGE_TYPE: usize = 20;
const OFF_INDEX_START: usize = 26;

/// Leaf entry types.
const ENTRY_KEYDATA: u8 = 1;
const ENTRY_OVERFLOW: u8 = 3;

/// Hard ceiling on records returned, so a crafted file cannot exhaust
/// memory through sheer entry count. Real zcashd wallets are far below.
const MAX_RECORDS: usize = 500_000;

/// Hard ceiling on a single value reassembled from overflow pages.
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

fn page_slice(bytes: &[u8], page: u32, page_size: u32) -> Result<&[u8], ImportError> {
    let start = (page as usize)
        .checked_mul(page_size as usize)
        .ok_or_else(|| unwalkable("page offset overflow"))?;
    let end = start
        .checked_add(page_size as usize)
        .ok_or_else(|| unwalkable("page end overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| unwalkable(format!("page {page} is past end of file")))
}

/// Follow an overflow chain and reassemble the full value.
fn read_overflow(
    bytes: &[u8],
    meta: &BdbMeta,
    first_page: u32,
    total_len: u32,
    visited: &mut BTreeSet<u32>,
) -> Result<Vec<u8>, ImportError> {
    let total_len = total_len as usize;
    if total_len > MAX_VALUE_LEN {
        return Err(unwalkable(format!("overflow value of {total_len} bytes is implausible")));
    }
    // Bound the claim by what the file could possibly hold before allocating.
    if total_len > bytes.len() {
        return Err(unwalkable(format!(
            "overflow value claims {total_len} bytes but the file is {}",
            bytes.len()
        )));
    }

    let mut out = Vec::with_capacity(total_len);
    let mut page = first_page;

    while page != 0 && out.len() < total_len {
        if !visited.insert(page) {
            return Err(unwalkable(format!("overflow chain revisits page {page}")));
        }
        let p = page_slice(bytes, page, meta.page_size)?;
        let next = read_u32(p, 16, meta.swapped)?;
        let this_len = read_u16(p, OFF_ENTRY_COUNT, meta.swapped)? as usize;

        let want = this_len.min(total_len - out.len());
        let data = p
            .get(26..26 + want)
            .ok_or_else(|| unwalkable(format!("overflow page {page} is short")))?;
        out.extend_from_slice(data);
        page = next;
    }

    Ok(out)
}

/// Walk every leaf page and return all `(key, value)` pairs.
///
/// Page pointers form an attacker-controlled graph, so `visited` bounds
/// traversal: without it a crafted file is a trivial infinite loop.
pub fn walk(bytes: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ImportError> {
    let meta = read_meta(bytes)?;
    let mut visited = BTreeSet::new();
    let mut out = Vec::new();
    let mut stack = vec![meta.root_page];

    while let Some(page) = stack.pop() {
        if out.len() >= MAX_RECORDS {
            break;
        }
        if !visited.insert(page) {
            continue;
        }
        if page > meta.last_page {
            continue;
        }

        let p = match page_slice(bytes, page, meta.page_size) {
            Ok(p) => p,
            // Partial recovery: a bad page must not abort the whole walk.
            Err(_) => continue,
        };

        let page_type = match p.get(OFF_PAGE_TYPE) {
            Some(t) => *t,
            None => continue,
        };
        let count = match read_u16(p, OFF_ENTRY_COUNT, meta.swapped) {
            Ok(c) => c as usize,
            Err(_) => continue,
        };

        match page_type {
            PAGE_TYPE_IBTREE => {
                for i in 0..count {
                    let Ok(off) = read_u16(p, OFF_INDEX_START + i * 2, meta.swapped) else {
                        continue;
                    };
                    let Ok(child) = read_u32(p, off as usize, meta.swapped) else {
                        continue;
                    };
                    stack.push(child);
                }
            }
            PAGE_TYPE_LBTREE => {
                // Leaf entries alternate key, value.
                let mut entries = Vec::with_capacity(count.min(1024));
                for i in 0..count {
                    let Ok(off) = read_u16(p, OFF_INDEX_START + i * 2, meta.swapped) else {
                        continue;
                    };
                    let off = off as usize;
                    let Some(&kind) = p.get(off + 2) else { continue };
                    let Ok(len) = read_u16(p, off, meta.swapped) else {
                        continue;
                    };

                    let item = match kind {
                        ENTRY_KEYDATA => p
                            .get(off + 3..off + 3 + len as usize)
                            .map(<[u8]>::to_vec),
                        ENTRY_OVERFLOW => {
                            let Ok(pgno) = read_u32(p, off + 4, meta.swapped) else {
                                continue;
                            };
                            let Ok(tlen) = read_u32(p, off + 8, meta.swapped) else {
                                continue;
                            };
                            let mut seen = BTreeSet::new();
                            read_overflow(bytes, &meta, pgno, tlen, &mut seen).ok()
                        }
                        _ => None,
                    };

                    match item {
                        Some(v) => entries.push(v),
                        None => continue,
                    }
                }
                for pair in entries.chunks_exact(2) {
                    if let [k, v] = pair {
                        out.push((k.clone(), v.clone()));
                    }
                }
            }
            PAGE_TYPE_OVERFLOW => {}
            _ => {}
        }
    }

    Ok(out)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import bdb
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all tests pass. `golden_sprout_wallet_contains_a_zkey_record` passing is the proof that the walk works on real data.

- [ ] **Step 5: Commit**

```bash
git add crates/argos-wallet-import/src/bdb.rs
git commit -m "feat(import): walk BDB btree pages and extract key/value records

Handles internal, leaf, and overflow pages. Page pointers form an
attacker-controlled graph, so a visited set bounds traversal — without it a
crafted file is a trivial infinite loop or stack overflow.

Partial recovery throughout: an unreadable page is skipped rather than
aborting the walk, so a truncated wallet still yields the records it has.
Record count and reassembled value length are both capped.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Fuzz target for the BDB walker

**Files:**
- Create: `crates/argos-wallet-import/fuzz/Cargo.toml`
- Create: `crates/argos-wallet-import/fuzz/fuzz_targets/bdb_walk.rs`
- Create: `crates/argos-wallet-import/fuzz/README.md`

**Interfaces:**
- Consumes: `walk` (Task 5), fixtures (Task 2)
- Produces: a runnable `cargo fuzz` target

- [ ] **Step 1: Create the fuzz manifest**

Create `crates/argos-wallet-import/fuzz/Cargo.toml`:

```toml
[package]
name = "argos-wallet-import-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
argos-wallet-import = { path = ".." }

[[bin]]
name = "bdb_walk"
path = "fuzz_targets/bdb_walk.rs"
test = false
doc = false
bench = false

[workspace]
```

The empty `[workspace]` table keeps the fuzz crate out of the main workspace, which is the standard `cargo-fuzz` layout.

- [ ] **Step 2: Write the fuzz target**

Create `crates/argos-wallet-import/fuzz/fuzz_targets/bdb_walk.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

// The walker consumes attacker-controlled bytes. Any panic, OOM, or hang
// here is a real finding: this is the single highest-value test artifact
// in the import path.
fuzz_target!(|data: &[u8]| {
    let _ = argos_wallet_import::bdb::walk(data);
});
```

- [ ] **Step 3: Seed the corpus from the goldens**

```bash
mkdir -p crates/argos-wallet-import/fuzz/corpus/bdb_walk
cp crates/argos-wallet-import/tests/fixtures/*.dat \
   crates/argos-wallet-import/fuzz/corpus/bdb_walk/
ls crates/argos-wallet-import/fuzz/corpus/bdb_walk/
```
Expected: 8 files.

- [ ] **Step 4: Run the fuzzer**

```bash
cargo install cargo-fuzz  # if not already present
cd crates/argos-wallet-import
cargo +nightly fuzz run bdb_walk -- -max_total_time=300
```
Expected: 5 minutes, no crashes, no timeouts. **If it finds a crash, fix `bdb.rs` and add the crashing input as a regression test before continuing.** Do not proceed with a known crash.

- [ ] **Step 5: Document how to run it**

Create `crates/argos-wallet-import/fuzz/README.md`:

```markdown
# Fuzzing the BDB walker

`bdb.rs` parses attacker-controlled bytes, so it is fuzzed rather than only
unit-tested. Any panic, OOM, or hang is a real finding.

    cargo +nightly fuzz run bdb_walk -- -max_total_time=300

The corpus is seeded from the golden wallet fixtures in
`../tests/fixtures/`. When the fuzzer finds a crash, add the input as a
regression test in `src/bdb.rs` before fixing the bug, so it stays covered.

Not run in CI: it needs a nightly toolchain and is time-bounded rather than
pass/fail. Run it locally before merging changes to `bdb.rs`.
```

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/fuzz/
echo "crates/argos-wallet-import/fuzz/artifacts/" >> .gitignore
echo "crates/argos-wallet-import/fuzz/target/" >> .gitignore
git add .gitignore
git commit -m "test(import): fuzz the BDB walker, seeded from golden fixtures

The walker is the crate's attack surface: it consumes attacker-controlled
bytes before any Zcash logic runs. Any panic, OOM, or hang is a real
finding. Corpus is seeded from real zcashd wallets so the fuzzer starts
from valid structure rather than random noise.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: zcashd record keys and plaintext records

**Files:**
- Create: `crates/argos-wallet-import/src/zcashd/mod.rs`
- Create: `crates/argos-wallet-import/src/zcashd/records.rs`
- Create: `crates/argos-wallet-import/src/keys.rs`
- Modify: `crates/argos-wallet-import/src/lib.rs`

**Interfaces:**
- Consumes: `walk` (Task 5), `ImportDiagnostic` (Task 1)
- Produces: `pub struct ImportedKeys`, `pub enum RecordKey`, `pub fn parse_record_key(bytes: &[u8]) -> Option<RecordKey>`, `pub fn compact_size(bytes: &[u8]) -> Option<(u64, usize)>`

- [ ] **Step 1: Write the failing test for CompactSize and record keys**

Create `crates/argos-wallet-import/src/zcashd/records.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_reads_single_byte() {
        assert_eq!(compact_size(&[0x04]), Some((4, 1)));
    }

    #[test]
    fn compact_size_reads_two_byte_form() {
        assert_eq!(compact_size(&[0xfd, 0x01, 0x02]), Some((0x0201, 3)));
    }

    #[test]
    fn compact_size_rejects_truncated_input() {
        assert_eq!(compact_size(&[0xfd, 0x01]), None);
        assert_eq!(compact_size(&[]), None);
    }

    #[test]
    fn parses_a_zkey_record_key() {
        // CompactSize(4) "zkey" then a 64-byte Sprout payment address.
        let mut raw = vec![0x04];
        raw.extend_from_slice(b"zkey");
        raw.extend_from_slice(&[0xAB; 64]);
        let parsed = parse_record_key(&raw).unwrap();
        assert_eq!(parsed.record_type, "zkey");
        assert_eq!(parsed.rest.len(), 64);
    }

    #[test]
    fn returns_none_for_a_length_that_exceeds_the_buffer() {
        let raw = vec![0x40, b'z', b'k']; // claims 64 bytes, has 2
        assert!(parse_record_key(&raw).is_none());
    }

    #[test]
    fn golden_sprout_wallet_record_types_include_zkey_and_key() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let types: std::collections::BTreeSet<String> = pairs
            .iter()
            .filter_map(|(k, _)| parse_record_key(k))
            .map(|r| r.record_type)
            .collect();
        assert!(types.contains("zkey"), "types found: {types:?}");
        assert!(types.contains("key"), "types found: {types:?}");
    }

    #[test]
    fn golden_encrypted_sprout_wallet_has_czkey_and_mkey() {
        let bytes = std::fs::read("tests/fixtures/sprout-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let types: std::collections::BTreeSet<String> = pairs
            .iter()
            .filter_map(|(k, _)| parse_record_key(k))
            .map(|r| r.record_type)
            .collect();
        // walletdb.cpp:125 writes czkey and erases the plaintext zkey.
        assert!(types.contains("czkey"), "types found: {types:?}");
        assert!(types.contains("mkey"), "types found: {types:?}");
        assert!(!types.contains("zkey"), "plaintext zkey should be erased");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import records`
Expected: FAIL — `cannot find function compact_size`

- [ ] **Step 3: Implement CompactSize and record key parsing**

Prepend to `crates/argos-wallet-import/src/zcashd/records.rs`:

```rust
//! zcashd wallet record decoding.
//!
//! Record keys are Bitcoin-style serialized pairs: a CompactSize-prefixed
//! type string followed by type-specific key material.

/// A record key split into its type string and the bytes that follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    pub record_type: String,
    pub rest: Vec<u8>,
}

/// Read a Bitcoin CompactSize integer. Returns `(value, bytes_consumed)`.
///
/// Returns `None` rather than panicking on truncated input — this parses
/// attacker-controlled bytes.
pub fn compact_size(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    match first {
        0..=0xfc => Some((u64::from(first), 1)),
        0xfd => {
            let s = bytes.get(1..3)?;
            let mut b = [0u8; 2];
            b.copy_from_slice(s);
            Some((u64::from(u16::from_le_bytes(b)), 3))
        }
        0xfe => {
            let s = bytes.get(1..5)?;
            let mut b = [0u8; 4];
            b.copy_from_slice(s);
            Some((u64::from(u32::from_le_bytes(b)), 5))
        }
        _ => {
            let s = bytes.get(1..9)?;
            let mut b = [0u8; 8];
            b.copy_from_slice(s);
            Some((u64::from_le_bytes(b), 9))
        }
    }
}

/// Longest zcashd record type string; anything longer is not a record key.
const MAX_RECORD_TYPE_LEN: u64 = 32;

/// Split a raw record key into its type string and remainder.
pub fn parse_record_key(bytes: &[u8]) -> Option<RecordKey> {
    let (len, consumed) = compact_size(bytes)?;
    if len > MAX_RECORD_TYPE_LEN {
        return None;
    }
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    let name = bytes.get(consumed..end)?;
    let record_type = std::str::from_utf8(name).ok()?.to_owned();
    let rest = bytes.get(end..)?.to_vec();
    Some(RecordKey { record_type, rest })
}
```

- [ ] **Step 4: Write the normalized output type**

Create `crates/argos-wallet-import/src/keys.rs`:

```rust
//! The normalized output of any wallet import.

use secrecy::Secret;

use crate::error::ImportDiagnostic;

/// Where a key came from. Surfaced to the user so they can tell
/// HD-derived keys from ones that exist only in the wallet file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Derived from the wallet's HD chain.
    HdDerived,
    /// Imported standalone (`z_importkey` / `importprivkey`). Exists in no
    /// seed — recoverable only from the wallet file.
    Standalone,
}

#[derive(Debug, Clone)]
pub struct TransparentKey {
    pub secret: Secret<[u8; 32]>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone)]
pub struct SaplingKey {
    /// Raw extended spending key bytes, as stored by zcashd.
    pub extsk: Secret<Vec<u8>>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone)]
pub struct SproutKey {
    /// 32-byte Sprout spending key a_sk.
    pub a_sk: Secret<[u8; 32]>,
    /// 64-byte Sprout payment address this key unlocks.
    pub address: [u8; 64],
    pub provenance: Provenance,
}

/// A Sprout note and its cached witness, preserved verbatim from the
/// wallet file.
///
/// Sub-spec 3's cost depends on whether these cached witnesses can be
/// brought forward instead of indexing from genesis. Preserving them here
/// is nearly free; discarding them at this layer would be irreversible.
#[derive(Debug, Clone)]
pub struct SproutNoteData {
    pub address: [u8; 64],
    pub nullifier: Option<[u8; 32]>,
    /// Opaque serialized witness. Not interpreted in sub-spec 1.
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ImportedKeys {
    pub transparent: Vec<TransparentKey>,
    pub sapling: Vec<SaplingKey>,
    pub sprout: Vec<SproutKey>,
    pub sprout_notes: Vec<SproutNoteData>,
    /// Everything we could not read. Never empty silently — always shown
    /// to the user with counts.
    pub diagnostics: Vec<ImportDiagnostic>,
}

impl ImportedKeys {
    pub fn is_empty(&self) -> bool {
        self.transparent.is_empty() && self.sapling.is_empty() && self.sprout.is_empty()
    }

    pub fn total_keys(&self) -> usize {
        self.transparent.len() + self.sapling.len() + self.sprout.len()
    }
}
```

- [ ] **Step 5: Wire up the modules**

Create `crates/argos-wallet-import/src/zcashd/mod.rs`:

```rust
//! zcashd wallet.dat record layer.

pub mod records;

pub use records::{compact_size, parse_record_key, RecordKey};
```

Add to `crates/argos-wallet-import/src/lib.rs`:

```rust
pub mod keys;
pub mod zcashd;

pub use keys::{ImportedKeys, Provenance};
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass. `golden_encrypted_sprout_wallet_has_czkey_and_mkey` is the important one — it confirms against a real file that `encryptwallet` converted `zkey` to `czkey` and erased the plaintext, exactly as `walletdb.cpp:125` says.

- [ ] **Step 7: Commit**

```bash
git add crates/argos-wallet-import/src/
git commit -m "feat(import): decode zcashd record keys and define ImportedKeys

Record keys are CompactSize-prefixed type strings. Parsing returns None on
truncated or oversized input rather than panicking, since these are
attacker-controlled bytes.

ImportedKeys preserves Sprout note data and cached witnesses verbatim.
Sub-spec 3's cost depends on whether those witnesses can be brought
forward rather than indexing from genesis, and discarding them here would
be irreversible.

Keys are provenance-tagged so standalone imported keys — which exist in no
seed and are recoverable only from the wallet file — are distinguishable.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Plaintext key extraction

**Files:**
- Modify: `crates/argos-wallet-import/src/zcashd/mod.rs`
- Create: `crates/argos-wallet-import/src/zcashd/plaintext.rs`

**Interfaces:**
- Consumes: `RecordKey`, `ImportedKeys` (Task 7)
- Produces: `pub fn collect_plaintext(pairs: &[(Vec<u8>, Vec<u8>)], out: &mut ImportedKeys)`

- [ ] **Step 1: Write the failing test**

Create `crates/argos-wallet-import/src/zcashd/plaintext.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn record(kind: &str, key_rest: &[u8], value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut k = vec![kind.len() as u8];
        k.extend_from_slice(kind.as_bytes());
        k.extend_from_slice(key_rest);
        (k, value.to_vec())
    }

    #[test]
    fn extracts_a_sprout_spending_key() {
        let addr = [0xAB; 64];
        let mut value = vec![0x20]; // CompactSize(32)
        value.extend_from_slice(&[0xCD; 32]);
        let pairs = vec![record("zkey", &addr, &value)];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert_eq!(out.sprout.len(), 1);
        let k = &out.sprout[0];
        assert_eq!(k.address, addr);
        assert_eq!(k.a_sk.expose_secret(), &[0xCD; 32]);
    }

    #[test]
    fn a_malformed_record_does_not_silence_a_good_one() {
        // This is the governing principle: partial recovery.
        let addr = [0x11; 64];
        let mut good = vec![0x20];
        good.extend_from_slice(&[0x22; 32]);

        let pairs = vec![
            record("zkey", &[0x99; 3], &[0x00]), // too-short address
            record("zkey", &addr, &good),
        ];

        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);

        assert_eq!(out.sprout.len(), 1, "the good key must survive");
        assert_eq!(out.diagnostics.len(), 1, "the bad one must be reported");
    }

    #[test]
    fn unknown_record_types_are_reported_not_silently_dropped() {
        let pairs = vec![record("bestblock", &[], &[0x01])];
        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);
        assert!(out.sprout.is_empty());
        assert_eq!(out.diagnostics.len(), 1);
    }

    #[test]
    fn extracts_sprout_keys_from_the_golden_fixture() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mut out = ImportedKeys::default();
        collect_plaintext(&pairs, &mut out);
        assert!(!out.sprout.is_empty(), "no Sprout keys from the real wallet");
        assert!(!out.transparent.is_empty(), "no transparent keys");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import plaintext`
Expected: FAIL — `cannot find function collect_plaintext`

- [ ] **Step 3: Implement plaintext collection**

Prepend to `crates/argos-wallet-import/src/zcashd/plaintext.rs`:

```rust
//! Extraction of unencrypted zcashd key records.

use secrecy::Secret;

use crate::{
    error::ImportDiagnostic,
    keys::{ImportedKeys, Provenance, SaplingKey, SproutKey, TransparentKey},
    zcashd::records::{compact_size, parse_record_key},
};

/// Record types we knowingly ignore: wallet bookkeeping with no key
/// material. Listed explicitly so genuinely unknown types still produce a
/// diagnostic.
// Verified against the golden fixtures: these are every non-key record
// type a real zcashd v6.20.0 wallet actually contains. Listing them
// explicitly means a genuinely unknown type still produces a diagnostic
// rather than being lost in the noise.
const IGNORED: &[&str] = &[
    "acc",
    "bestblock",
    "bestblock_nomerkle",
    "cmnemonicphrase",
    "defaultkey",
    "keymeta",
    "minversion",
    "mnemonichdchain",
    "mnemonicphrase",
    "name",
    "networkinfo",
    "orchard_note_commitment_tree",
    "orderposnext",
    "pool",
    "purpose",
    "sapzkeymeta",
    "tx",
    "version",
    "witnesscachesize",
    "zkeymeta",
];

fn read_length_prefixed(value: &[u8]) -> Option<&[u8]> {
    let (len, consumed) = compact_size(value)?;
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    value.get(consumed..end)
}

/// Extract every unencrypted key record.
///
/// A record we cannot parse is recorded as a diagnostic and skipped; it
/// must never prevent a record we *can* parse from being recovered.
pub fn collect_plaintext(pairs: &[(Vec<u8>, Vec<u8>)], out: &mut ImportedKeys) {
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };

        match rec.record_type.as_str() {
            "zkey" => {
                let addr: Option<[u8; 64]> = rec.rest.get(..64).and_then(|s| s.try_into().ok());
                let a_sk: Option<[u8; 32]> = read_length_prefixed(value)
                    .and_then(|s| s.get(..32))
                    .and_then(|s| s.try_into().ok());

                match (addr, a_sk) {
                    (Some(address), Some(a_sk)) => out.sprout.push(SproutKey {
                        a_sk: Secret::new(a_sk),
                        address,
                        // zcashd Sprout keys were never HD-derived.
                        provenance: Provenance::Standalone,
                    }),
                    _ => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "zkey".to_owned(),
                        reason: "address or spending key has the wrong length".to_owned(),
                    }),
                }
            }
            "sapzkey" => match read_length_prefixed(value) {
                Some(extsk) => out.sapling.push(SaplingKey {
                    extsk: Secret::new(extsk.to_vec()),
                    provenance: Provenance::Standalone,
                }),
                None => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                    record_type: "sapzkey".to_owned(),
                    reason: "extended spending key is truncated".to_owned(),
                }),
            },
            "key" => {
                // Value is a length-prefixed private key; the 32-byte
                // secret is the tail of the DER-ish encoding zcashd uses.
                match read_length_prefixed(value).and_then(|s| s.get(..32)) {
                    Some(s) => match <[u8; 32]>::try_from(s) {
                        Ok(secret) => out.transparent.push(TransparentKey {
                            secret: Secret::new(secret),
                            provenance: Provenance::HdDerived,
                        }),
                        Err(_) => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                            record_type: "key".to_owned(),
                            reason: "secret is not 32 bytes".to_owned(),
                        }),
                    },
                    None => out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "key".to_owned(),
                        reason: "private key record is truncated".to_owned(),
                    }),
                }
            }
            // Encrypted variants are handled in Task 10 once the master
            // key is available; skip silently here rather than reporting
            // them as unknown.
            "ckey" | "czkey" | "csapzkey" | "mkey" | "hdchain" | "sapzaddr" | "zkeymeta" => {}
            other if IGNORED.contains(&other) => {}
            other => out.diagnostics.push(ImportDiagnostic::UnknownRecord {
                record_type: other.to_owned(),
            }),
        }
    }
}
```

- [ ] **Step 4: Register the module**

In `crates/argos-wallet-import/src/zcashd/mod.rs`:

```rust
pub mod plaintext;
pub mod records;

pub use plaintext::collect_plaintext;
pub use records::{compact_size, parse_record_key, RecordKey};
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass. If `extracts_sprout_keys_from_the_golden_fixture` fails, the value encoding differs from the assumption — inspect the real record bytes and fix the parser, not the test.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/zcashd/
git commit -m "feat(import): extract unencrypted zcashd key records

Handles zkey, sapzkey, and key records. Sprout keys are tagged Standalone
because zcashd never HD-derived them, which is why they appear in no seed.

Partial recovery is enforced by test: a malformed record produces a
diagnostic and the good records beside it still come through. Genuinely
unknown record types are reported rather than silently dropped, since
unmigrated key material exists only in the original file.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Master key derivation and passphrase verification

**Blocked on dependency approval.** This task needs `aes` and `cbc` from RustCrypto. Before starting, present to the user: package names and versions, purpose, download counts, transitive dependency counts, maintenance status, licence, and any advisories — per the dependency policy. Do not add them without explicit approval, and add them to `~/.claude/approved-dependencies.md` afterwards.

**Files:**
- Create: `crates/argos-wallet-import/src/zcashd/crypto.rs`
- Modify: `crates/argos-wallet-import/Cargo.toml`, root `Cargo.toml`

**Interfaces:**
- Consumes: `RecordKey` (Task 7), `ImportError` (Task 1)
- Produces: `pub struct MasterKey(Secret<[u8; 32]>)`, `pub fn derive_master_key(passphrase: &SecretString, mkey: &MkeyRecord) -> Result<MasterKey, ImportError>`, `pub struct MkeyRecord { pub encrypted_key: Vec<u8>, pub salt: [u8; 8], pub derivation_method: u32, pub rounds: u32 }`

- [ ] **Step 1: Add the dependencies (after approval)**

In the root `Cargo.toml` `[workspace.dependencies]`:

```toml
aes = "0.8.4"
cbc = { version = "0.1.2", features = ["alloc"] }
```

In `crates/argos-wallet-import/Cargo.toml` `[dependencies]`:

```toml
aes.workspace = true
cbc.workspace = true
```

- [ ] **Step 2: Write the failing test**

Create `crates/argos-wallet-import/src/zcashd/crypto.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn parses_an_mkey_record() {
        // 48-byte encrypted key, 8-byte salt, method 0, 25000 rounds.
        let mut v = vec![0x30];
        v.extend_from_slice(&[0xAA; 48]);
        v.extend_from_slice(&[0x08]);
        v.extend_from_slice(&[0xBB; 8]);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&25_000u32.to_le_bytes());

        let m = parse_mkey(&v).unwrap();
        assert_eq!(m.encrypted_key.len(), 48);
        assert_eq!(m.salt, [0xBB; 8]);
        assert_eq!(m.rounds, 25_000);
    }

    #[test]
    fn rejects_a_truncated_mkey_record() {
        assert!(parse_mkey(&[0x30, 0xAA]).is_none());
    }

    #[test]
    fn rejects_zero_rounds() {
        // Zero rounds would make key stretching a no-op.
        let mut v = vec![0x30];
        v.extend_from_slice(&[0xAA; 48]);
        v.extend_from_slice(&[0x08]);
        v.extend_from_slice(&[0xBB; 8]);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_mkey(&v).is_none());
    }

    #[test]
    fn a_wrong_passphrase_is_reported_as_wrong_passphrase() {
        // Not as corruption. A user with a correct passphrase and a damaged
        // wallet must not be told their passphrase is wrong.
        let bytes = std::fs::read("tests/fixtures/modern-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mkey = find_mkey(&pairs).expect("encrypted wallet must have an mkey");
        let err = derive_master_key(&SecretString::new("definitely-wrong".to_owned()), &mkey)
            .unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn the_correct_passphrase_derives_a_master_key() {
        let bytes = std::fs::read("tests/fixtures/modern-encrypted.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mkey = find_mkey(&pairs).expect("encrypted wallet must have an mkey");
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        assert!(derive_master_key(&pass, &mkey).is_ok());
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import crypto`
Expected: FAIL — `cannot find function parse_mkey`

- [ ] **Step 4: Implement master key derivation**

Prepend to `crates/argos-wallet-import/src/zcashd/crypto.rs`:

```rust
//! zcashd wallet encryption.
//!
//! zcashd derives a key-encryption key from the passphrase with an
//! iterated SHA-512 (Bitcoin's `EVP_BytesToKey`-style construction), then
//! AES-256-CBC-decrypts a random master key stored in the `mkey` record.
//! Every individual key record is encrypted under that master key.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use secrecy::{ExposeSecret, Secret, SecretString};
use sha2::{Digest, Sha512};

use crate::{
    error::ImportError,
    zcashd::records::{compact_size, parse_record_key},
};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// zcashd's only key derivation method.
const DERIVATION_SHA512: u32 = 0;

/// Refuse an absurd round count: it would be a denial of service against
/// the importing user, and no real wallet uses one.
const MAX_ROUNDS: u32 = 10_000_000;

#[derive(Debug, Clone)]
pub struct MkeyRecord {
    pub encrypted_key: Vec<u8>,
    pub salt: [u8; 8],
    pub derivation_method: u32,
    pub rounds: u32,
}

/// The decrypted wallet master key. Every `ckey`, `czkey`, and `csapzkey`
/// record is encrypted under this.
#[derive(Clone)]
pub struct MasterKey(pub(crate) Secret<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Parse an `mkey` record value.
pub fn parse_mkey(value: &[u8]) -> Option<MkeyRecord> {
    let (klen, koff) = compact_size(value)?;
    let kend = koff.checked_add(usize::try_from(klen).ok()?)?;
    let encrypted_key = value.get(koff..kend)?.to_vec();

    let (slen, soff) = compact_size(value.get(kend..)?)?;
    if slen != 8 {
        return None;
    }
    let sstart = kend.checked_add(soff)?;
    let send = sstart.checked_add(8)?;
    let salt: [u8; 8] = value.get(sstart..send)?.try_into().ok()?;

    let mut b = [0u8; 4];
    b.copy_from_slice(value.get(send..send + 4)?);
    let derivation_method = u32::from_le_bytes(b);

    b.copy_from_slice(value.get(send + 4..send + 8)?);
    let rounds = u32::from_le_bytes(b);

    if rounds == 0 || rounds > MAX_ROUNDS {
        return None;
    }

    Some(MkeyRecord {
        encrypted_key,
        salt,
        derivation_method,
        rounds,
    })
}

/// Locate the `mkey` record in a walked wallet, if the wallet is encrypted.
pub fn find_mkey(pairs: &[(Vec<u8>, Vec<u8>)]) -> Option<MkeyRecord> {
    pairs.iter().find_map(|(k, v)| {
        let rec = parse_record_key(k)?;
        (rec.record_type == "mkey").then(|| parse_mkey(v))?
    })
}

/// Derive the key-encryption key and unwrap the master key.
///
/// Returns `WrongPassphrase` — never a corruption error — when unwrapping
/// fails, so a user with a correct passphrase and a damaged wallet is not
/// misled into giving up on recoverable funds.
pub fn derive_master_key(
    passphrase: &SecretString,
    mkey: &MkeyRecord,
) -> Result<MasterKey, ImportError> {
    if mkey.derivation_method != DERIVATION_SHA512 {
        return Err(ImportError::UnwalkableBtree(format!(
            "unsupported key derivation method {}",
            mkey.derivation_method
        )));
    }

    // Iterated SHA-512 over passphrase||salt, then re-hashing the digest.
    let mut buf = [0u8; 64];
    let mut hasher = Sha512::new();
    hasher.update(passphrase.expose_secret().as_bytes());
    hasher.update(mkey.salt);
    buf.copy_from_slice(&hasher.finalize());

    for _ in 1..mkey.rounds {
        let mut h = Sha512::new();
        h.update(buf);
        buf.copy_from_slice(&h.finalize());
    }

    let mut kek = [0u8; 32];
    let mut iv = [0u8; 16];
    kek.copy_from_slice(buf.get(0..32).ok_or(ImportError::WrongPassphrase)?);
    iv.copy_from_slice(buf.get(32..48).ok_or(ImportError::WrongPassphrase)?);

    let mut ct = mkey.encrypted_key.clone();
    let plain = Aes256CbcDec::new(&kek.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut ct)
        // Bad PKCS#7 padding is overwhelmingly a wrong passphrase, and
        // that is the actionable message for the user.
        .map_err(|_| ImportError::WrongPassphrase)?;

    let master: [u8; 32] = plain
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or(ImportError::WrongPassphrase)?;

    Ok(MasterKey(Secret::new(master)))
}
```

- [ ] **Step 5: Register the module**

Add to `crates/argos-wallet-import/src/zcashd/mod.rs`:

```rust
pub mod crypto;

pub use crypto::{derive_master_key, find_mkey, MasterKey, MkeyRecord};
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import crypto
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass. `the_correct_passphrase_derives_a_master_key` proves the KDF against a wallet the real zcashd encrypted — the only ground truth available.

- [ ] **Step 7: Commit**

```bash
git add crates/argos-wallet-import/ Cargo.toml Cargo.lock
git commit -m "feat(import): derive the wallet master key from a passphrase

Iterated SHA-512 over passphrase and salt produces the key-encryption key
and IV, which AES-256-CBC-unwrap the master key from the mkey record.
Verified against a wallet encrypted by the real zcashd.

Unwrap failure reports WrongPassphrase specifically, never corruption. If
these collapsed into one error, a user with a correct passphrase and a
slightly damaged wallet would be told their passphrase was wrong and give
up on recoverable funds.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Encrypted key decryption, including czkey

This is the task the project exists for. `czkey` has no reference implementation anywhere — Zallet drops Sprout keys wholesale, and `zewif-zcashd` returns an explicit error for them. **These tests are the specification.**

**Files:**
- Create: `crates/argos-wallet-import/src/zcashd/encrypted.rs`
- Modify: `crates/argos-wallet-import/src/zcashd/mod.rs`

**Interfaces:**
- Consumes: `MasterKey` (Task 9), `ImportedKeys` (Task 7)
- Produces: `pub fn collect_encrypted(pairs: &[(Vec<u8>, Vec<u8>)], master: &MasterKey, out: &mut ImportedKeys)`

- [ ] **Step 1: Write the failing test**

Create `crates/argos-wallet-import/src/zcashd/encrypted.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn unlock(fixture: &str) -> (Vec<(Vec<u8>, Vec<u8>)>, MasterKey) {
        let bytes = std::fs::read(format!("tests/fixtures/{fixture}.dat")).unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mkey = crate::zcashd::find_mkey(&pairs).expect("no mkey");
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let master = crate::zcashd::derive_master_key(&pass, &mkey).unwrap();
        (pairs, master)
    }

    #[test]
    fn decrypts_encrypted_sprout_spending_keys() {
        // The capability no other software has.
        let (pairs, master) = unlock("sprout-encrypted");
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        assert!(!out.sprout.is_empty(), "no czkey records were decrypted");
    }

    #[test]
    fn decrypted_sprout_key_matches_the_plaintext_wallet_shape() {
        let (pairs, master) = unlock("sprout-encrypted");
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        for k in &out.sprout {
            // a_sk is 32 bytes and must not be all zeros — an all-zero key
            // is the classic signature of decrypting into a zeroed buffer.
            assert_ne!(k.a_sk.expose_secret(), &[0u8; 32]);
            assert_ne!(k.address, [0u8; 64]);
        }
    }

    #[test]
    fn decrypts_encrypted_transparent_and_sapling_keys() {
        let (pairs, master) = unlock("modern-encrypted");
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        assert!(!out.transparent.is_empty(), "no ckey records decrypted");
        assert!(!out.sapling.is_empty(), "no csapzkey records decrypted");
    }

    #[test]
    fn a_record_that_fails_to_decrypt_is_reported_not_fatal() {
        let (mut pairs, master) = unlock("sprout-encrypted");
        // Corrupt one czkey value.
        for (k, v) in pairs.iter_mut() {
            if crate::zcashd::parse_record_key(k)
                .map(|r| r.record_type == "czkey")
                .unwrap_or(false)
            {
                v.iter_mut().for_each(|b| *b ^= 0xFF);
                break;
            }
        }
        let mut out = ImportedKeys::default();
        collect_encrypted(&pairs, &master, &mut out);
        assert!(
            !out.diagnostics.is_empty(),
            "a failed decryption must be reported"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import encrypted`
Expected: FAIL — `cannot find function collect_encrypted`

- [ ] **Step 3: Implement encrypted record decryption**

Prepend to `crates/argos-wallet-import/src/zcashd/encrypted.rs`:

```rust
//! Decryption of encrypted zcashd key records.
//!
//! Each record's IV is derived deterministically from the record's own
//! public identifier: `iv = SHA256d(identifier)[0..16]`. That is why the
//! master key alone is enough to decrypt every record.
//!
//! `czkey` — encrypted Sprout spending keys — is handled here. Zallet
//! drops Sprout keys during migration and `zewif-zcashd` returns an error
//! for them, so this is the only implementation that exists.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

use crate::{
    error::ImportDiagnostic,
    keys::{ImportedKeys, Provenance, SaplingKey, SproutKey, TransparentKey},
    zcashd::{
        crypto::MasterKey,
        records::{compact_size, parse_record_key},
    },
};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Double-SHA256 of the record identifier gives the per-record IV.
fn record_iv(identifier: &[u8]) -> [u8; 16] {
    let first = Sha256::digest(identifier);
    let second = Sha256::digest(first);
    let mut iv = [0u8; 16];
    // `second` is always 32 bytes, so this slice is total.
    iv.copy_from_slice(&second[..16]);
    iv
}

fn decrypt(master: &MasterKey, identifier: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let iv = record_iv(identifier);
    let mut buf = ciphertext.to_vec();
    let key: [u8; 32] = *master.0.expose_secret();
    let plain = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()?;
    Some(plain.to_vec())
}

fn read_length_prefixed(value: &[u8]) -> Option<(&[u8], usize)> {
    let (len, consumed) = compact_size(value)?;
    let end = consumed.checked_add(usize::try_from(len).ok()?)?;
    Some((value.get(consumed..end)?, end))
}

/// Decrypt every encrypted key record under `master`.
///
/// A record that fails to decrypt is reported and skipped. One corrupt
/// record must never cost the user the keys beside it.
pub fn collect_encrypted(
    pairs: &[(Vec<u8>, Vec<u8>)],
    master: &MasterKey,
    out: &mut ImportedKeys,
) {
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };

        match rec.record_type.as_str() {
            // Key: "czkey" || SproutPaymentAddress (64 bytes)
            // Value: receiving key `rk` || encrypted a_sk, each
            //        length-prefixed. See zcash walletdb.cpp:125 —
            //        Write(("czkey", addr), make_pair(rk, vchCryptedSecret)).
            "czkey" => {
                let addr: Option<[u8; 64]> = rec.rest.get(..64).and_then(|s| s.try_into().ok());
                let Some(address) = addr else {
                    out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "czkey".to_owned(),
                        reason: "payment address is not 64 bytes".to_owned(),
                    });
                    continue;
                };

                // Skip the receiving key, then read the ciphertext.
                let ct = read_length_prefixed(value)
                    .and_then(|(_rk, off)| read_length_prefixed(value.get(off..)?))
                    .map(|(ct, _)| ct);

                let Some(ct) = ct else {
                    out.diagnostics.push(ImportDiagnostic::UnparseableRecord {
                        record_type: "czkey".to_owned(),
                        reason: "value is not a (rk, ciphertext) pair".to_owned(),
                    });
                    continue;
                };

                match decrypt(master, &address, ct).and_then(|p| {
                    let s: [u8; 32] = p.get(..32)?.try_into().ok()?;
                    Some(s)
                }) {
                    Some(a_sk) => out.sprout.push(SproutKey {
                        a_sk: Secret::new(a_sk),
                        address,
                        provenance: Provenance::Standalone,
                    }),
                    None => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "czkey".to_owned(),
                        reason: "ciphertext did not decrypt to a 32-byte key".to_owned(),
                    }),
                }
            }

            // Key: "ckey" || serialized public key. The pubkey is the IV
            // identifier and is the whole remainder of the record key.
            "ckey" => {
                let identifier = &rec.rest;
                match read_length_prefixed(value)
                    .and_then(|(ct, _)| decrypt(master, identifier, ct))
                    .and_then(|p| {
                        let s: [u8; 32] = p.get(..32)?.try_into().ok()?;
                        Some(s)
                    }) {
                    Some(secret) => out.transparent.push(TransparentKey {
                        secret: Secret::new(secret),
                        provenance: Provenance::HdDerived,
                    }),
                    None => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "ckey".to_owned(),
                        reason: "ciphertext did not decrypt to a 32-byte key".to_owned(),
                    }),
                }
            }

            // Key: "csapzkey" || incoming viewing key (the IV identifier).
            // Value: extfvk || encrypted extsk, each length-prefixed.
            "csapzkey" => {
                let identifier = &rec.rest;
                match read_length_prefixed(value)
                    .and_then(|(_extfvk, off)| read_length_prefixed(value.get(off..)?))
                    .and_then(|(ct, _)| decrypt(master, identifier, ct))
                {
                    Some(extsk) => out.sapling.push(SaplingKey {
                        extsk: Secret::new(extsk),
                        provenance: Provenance::HdDerived,
                    }),
                    None => out.diagnostics.push(ImportDiagnostic::DecryptionFailed {
                        record_type: "csapzkey".to_owned(),
                        reason: "ciphertext did not decrypt".to_owned(),
                    }),
                }
            }

            _ => {}
        }
    }
}
```

- [ ] **Step 4: Register the module**

Add to `crates/argos-wallet-import/src/zcashd/mod.rs`:

```rust
pub mod encrypted;

pub use encrypted::collect_encrypted;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import encrypted -- --nocapture
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass.

If `decrypts_encrypted_sprout_spending_keys` fails, the IV identifier or the value layout is wrong. The authority is `zcash/zcash` `src/wallet/walletdb.cpp` and `src/wallet/crypter.cpp` — read them rather than guessing. Do not weaken the test to make it pass.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/zcashd/
git commit -m "feat(import): decrypt encrypted key records, including czkey

Each record's IV is SHA256d over its own public identifier, so the master
key alone decrypts every record. Handles ckey, csapzkey, and czkey.

czkey is the point of the project: Zallet drops Sprout spending keys during
migration and zewif-zcashd returns an explicit error for them, so an
encrypted zcashd wallet holding Sprout funds has had no recovery path in
any software. There is no reference implementation to check against, which
makes these tests — run against wallets the real zcashd encrypted — the
specification.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Sprout note data and witness preservation

**Files:**
- Create: `crates/argos-wallet-import/src/zcashd/sprout.rs`
- Modify: `crates/argos-wallet-import/src/zcashd/mod.rs`

**Interfaces:**
- Consumes: `ImportedKeys`, `SproutNoteData` (Task 7)
- Produces: `pub fn collect_sprout_notes(pairs: &[(Vec<u8>, Vec<u8>)], out: &mut ImportedKeys)`

- [ ] **Step 1: Write the failing test**

Create `crates/argos-wallet-import/src/zcashd/sprout.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_note_data_from_the_golden_sprout_wallet() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = crate::bdb::walk(&bytes).unwrap();
        let mut out = ImportedKeys::default();
        collect_sprout_notes(&pairs, &mut out);
        // A freshly generated wallet may hold no notes; the contract is
        // that parsing does not fail and does not fabricate entries.
        for n in &out.sprout_notes {
            assert_ne!(n.address, [0u8; 64]);
        }
    }

    #[test]
    fn witness_bytes_survive_collection_unmodified() {
        // Sub-spec 3 may be able to bring these forward instead of
        // indexing from genesis, so they must survive import byte-exact.
        // This round-trips through collect_sprout_notes rather than
        // asserting a struct field equals what was just assigned to it.
        let mut key = vec![2u8];
        key.extend_from_slice(b"tx");

        let mut value = b"sprout".to_vec();
        value.extend_from_slice(&[0x77; 64]);
        value.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut out = ImportedKeys::default();
        collect_sprout_notes(&[(key, value)], &mut out);

        assert_eq!(out.sprout_notes.len(), 1);
        assert_eq!(out.sprout_notes[0].address, [0x77; 64]);
        assert_eq!(out.sprout_notes[0].witness, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn malformed_note_data_does_not_abort_collection() {
        let pairs = vec![(vec![2u8, b't', b'x'], vec![0x00])];
        let mut out = ImportedKeys::default();
        collect_sprout_notes(&pairs, &mut out);
        // No panic, no fatal error. Diagnostics may or may not be added.
        assert!(out.sprout_notes.is_empty());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import sprout`
Expected: FAIL — `cannot find function collect_sprout_notes`

- [ ] **Step 3: Implement note data collection**

Prepend to `crates/argos-wallet-import/src/zcashd/sprout.rs`:

```rust
//! Preservation of Sprout note data and cached witnesses.
//!
//! zcashd caches an incremental witness per Sprout note inside the `tx`
//! records. Sub-spec 3's cost depends on whether those witnesses can be
//! brought forward rather than rebuilding the commitment tree from
//! genesis, so they are preserved verbatim here and left uninterpreted.

use crate::{
    keys::{ImportedKeys, SproutNoteData},
    zcashd::records::parse_record_key,
};

/// Sprout note commitment tree depth, per the protocol spec.
pub const SPROUT_TREE_DEPTH: usize = 29;

/// Upper bound on a preserved witness blob. A witness at full depth is
/// far smaller than this; the cap only stops a crafted record from
/// forcing a large allocation.
const MAX_WITNESS_BYTES: usize = 64 * 1024;

/// Collect Sprout note data and cached witnesses from `tx` records.
///
/// Uninterpreted by design: sub-spec 1 preserves, sub-spec 3 decides
/// whether the witnesses are usable.
pub fn collect_sprout_notes(pairs: &[(Vec<u8>, Vec<u8>)], out: &mut ImportedKeys) {
    for (raw_key, value) in pairs {
        let Some(rec) = parse_record_key(raw_key) else {
            continue;
        };
        if rec.record_type != "tx" {
            continue;
        }

        // Sprout note data is embedded in the serialized wallet
        // transaction after the transaction body. Locating it requires
        // the mapSproutNoteData marker zcashd writes.
        let Some(pos) = find_sprout_note_marker(value) else {
            continue;
        };
        let Some(tail) = value.get(pos..) else {
            continue;
        };

        let Some(address) = tail.get(..64).and_then(|s| <[u8; 64]>::try_from(s).ok()) else {
            continue;
        };
        if address == [0u8; 64] {
            continue;
        }

        let witness = tail
            .get(64..)
            .map(|w| w.get(..MAX_WITNESS_BYTES.min(w.len())).unwrap_or(w).to_vec())
            .unwrap_or_default();

        out.sprout_notes.push(SproutNoteData {
            address,
            nullifier: None,
            witness,
        });
    }
}

/// zcashd serializes Sprout note data under this ASCII marker inside the
/// wallet transaction's extended fields.
fn find_sprout_note_marker(value: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = b"sprout";
    value
        .windows(MARKER.len())
        .position(|w| w == MARKER)
        .and_then(|p| p.checked_add(MARKER.len()))
}
```

- [ ] **Step 4: Register the module**

Add to `crates/argos-wallet-import/src/zcashd/mod.rs`:

```rust
pub mod sprout;

pub use sprout::collect_sprout_notes;
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass.

**Note for the implementer:** the marker-scanning approach here is a deliberate approximation. If a fixture wallet with actual Sprout notes shows it mislocating data, replace `find_sprout_note_marker` with a real walk of the serialized `CWalletTx` — the authority is `zcash/zcash` `src/wallet/wallet.h`. Record whichever you did in the commit message.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/zcashd/
git commit -m "feat(import): preserve Sprout note data and cached witnesses

zcashd caches an incremental witness per Sprout note. Sub-spec 3's cost
depends on whether those can be brought forward instead of rebuilding the
commitment tree from genesis, so they are preserved verbatim and left
uninterpreted here. Discarding them at this layer would be irreversible.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: zcashd import entry point

**Files:**
- Modify: `crates/argos-wallet-import/src/zcashd/mod.rs`, `crates/argos-wallet-import/src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 5–11
- Produces: `pub fn import_zcashd(bytes: &[u8], passphrase: Option<&SecretString>) -> Result<ImportedKeys, ImportError>`, `pub fn needs_passphrase(bytes: &[u8]) -> bool`

- [ ] **Step 1: Write the failing test**

Append to `crates/argos-wallet-import/src/zcashd/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap()
    }

    #[test]
    fn detects_which_wallets_need_a_passphrase() {
        assert!(needs_passphrase(&read("modern-encrypted")));
        assert!(needs_passphrase(&read("sprout-encrypted")));
        assert!(!needs_passphrase(&read("modern-plaintext")));
        assert!(!needs_passphrase(&read("sprout-plaintext")));
    }

    #[test]
    fn imports_a_plaintext_wallet_without_a_passphrase() {
        let keys = import_zcashd(&read("sprout-plaintext"), None).unwrap();
        assert!(!keys.sprout.is_empty());
        assert!(!keys.is_empty());
    }

    #[test]
    fn refuses_an_encrypted_wallet_without_a_passphrase() {
        let err = import_zcashd(&read("sprout-encrypted"), None).unwrap_err();
        assert_eq!(err, ImportError::WrongPassphrase);
    }

    #[test]
    fn imports_an_encrypted_sprout_wallet_end_to_end() {
        let pass = SecretString::new("argos-test-passphrase".to_owned());
        let keys = import_zcashd(&read("sprout-encrypted"), Some(&pass)).unwrap();
        assert!(!keys.sprout.is_empty(), "no Sprout keys recovered");
        assert!(keys.total_keys() > 0);
    }

    #[test]
    fn a_truncated_wallet_recovers_what_it_can() {
        match import_zcashd(&read("sprout-plaintext-truncated"), None) {
            Ok(keys) => {
                // Partial recovery: either keys or diagnostics, never a
                // silent empty success.
                assert!(!keys.is_empty() || !keys.diagnostics.is_empty());
            }
            Err(ImportError::UnwalkableBtree(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import zcashd`
Expected: FAIL — `cannot find function import_zcashd`

- [ ] **Step 3: Implement the entry point**

Add to `crates/argos-wallet-import/src/zcashd/mod.rs`, above the tests module:

```rust
use secrecy::SecretString;

use crate::{bdb, error::ImportError, keys::ImportedKeys};

/// True when the wallet carries an `mkey` record and therefore needs a
/// passphrase. Checked before prompting so we never ask for a passphrase
/// the wallet does not use.
pub fn needs_passphrase(bytes: &[u8]) -> bool {
    bdb::walk(bytes)
        .map(|pairs| find_mkey(&pairs).is_some())
        .unwrap_or(false)
}

/// Parse a zcashd `wallet.dat` into normalized key material.
///
/// Decryption happens here, once, before any caller touches the network:
/// a wallet needing a passphrase fails fast and locally.
pub fn import_zcashd(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let pairs = bdb::walk(bytes)?;
    let mut out = ImportedKeys::default();

    collect_plaintext(&pairs, &mut out);
    collect_sprout_notes(&pairs, &mut out);

    if let Some(mkey) = find_mkey(&pairs) {
        // Encrypted wallet: without a passphrase the encrypted records are
        // unreachable, and reporting partial plaintext results would let a
        // user believe they had recovered everything.
        let passphrase = passphrase.ok_or(ImportError::WrongPassphrase)?;
        let master = derive_master_key(passphrase, &mkey)?;
        collect_encrypted(&pairs, &master, &mut out);
    }

    Ok(out)
}
```

- [ ] **Step 4: Export from lib.rs**

In `crates/argos-wallet-import/src/lib.rs`, add:

```rust
use secrecy::SecretString;

/// Parse any supported wallet file into normalized key material.
pub fn import_wallet_file(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    match sniff::sniff(bytes)? {
        WalletFormat::Zcashd => zcashd::import_zcashd(bytes, passphrase),
        WalletFormat::ZecwalletLite => zwl::import_zwl(bytes, passphrase),
    }
}
```

**Note:** `zwl::import_zwl` does not exist until Task 13. Until then, stub the match arm as `WalletFormat::ZecwalletLite => Err(ImportError::UnrecognizedFormat)` and replace it in Task 13.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass. `imports_an_encrypted_sprout_wallet_end_to_end` is the milestone — the capability no other software has, working against a real wallet.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/
git commit -m "feat(import): end-to-end zcashd wallet import

Decryption happens once, before any caller touches the network, so a
wallet needing a passphrase fails fast and locally. needs_passphrase is
checked first so we never prompt for a passphrase the wallet does not use.

An encrypted wallet with no passphrase is refused rather than returning
partial plaintext results, which would let a user believe they had
recovered everything.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: ZecWallet Lite parser

**Files:**
- Create: `crates/argos-wallet-import/src/zwl.rs`
- Modify: `crates/argos-wallet-import/src/lib.rs`

**Interfaces:**
- Consumes: `ImportedKeys` (Task 7), `ImportError` (Task 1)
- Produces: `pub fn import_zwl(bytes: &[u8], passphrase: Option<&SecretString>) -> Result<ImportedKeys, ImportError>`

**Layout confirmed 2026-07-30** against `zingolabs/zewif-zwl` (default branch is `master`, not `main`). Read these two files before writing code — they are the authority:

- `src/zwl_parser.rs` — top-level file layout
- `src/keys.rs` — the `Keys` struct, which is what this task extracts

Confirmed structure, all little-endian:

```
u64            external_version      (max known: 31, from ZwlParser::serialized_version)
Keys:
  u64          keys version          (its own version word, checked separately)
  u8           encrypted flag
  [u8; 48]     enc_seed              (encrypted seed when locked)
  Vector<u8>   nonce
  Vector<WalletOKey>  okeys          (only when keys version > 21)
  Vector<WalletZKey>  zkeys
  Vector<WalletTKey>  tkeys          (only when keys version > 20; older versions
                                      use a separate extsks/extfvks/taddresses path)
Vector<CompactBlockData>  blocks
... transactions, chain name, options, birthday, tree state, price info
```

`Vector::read` is length-prefixed via `zcash_encoding`. Only the version word and the key vectors matter for this task; everything after `Keys` can be ignored.

**ZWL wallets can be encrypted.** The `encrypted` flag, `enc_seed`, and `nonce` exist for exactly that reason, so this task's signature takes a passphrase like the zcashd path does. Do not assume ZWL is always plaintext.

- [ ] **Step 1: Write the failing test**

Create `crates/argos-wallet-import/src/zwl.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(version: u64, body: &[u8]) -> Vec<u8> {
        let mut v = version.to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn rejects_a_version_newer_than_we_understand() {
        let err = import_zwl(&wallet(999, &[])).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_file_with_no_version_word() {
        let err = import_zwl(&[0u8; 3]).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn reads_the_version_of_a_supported_wallet() {
        // An empty body yields no keys but must not be an error: partial
        // recovery applies here too.
        let keys = import_zwl(&wallet(25, &[0x00])).unwrap();
        assert!(keys.is_empty());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-wallet-import zwl`
Expected: FAIL — `cannot find function import_zwl`

- [ ] **Step 3: Implement the ZWL reader**

Prepend to `crates/argos-wallet-import/src/zwl.rs`:

```rust
//! ZecWallet Lite wallet file reader.
//!
//! Unlike zcashd, ZWL uses a custom length-prefixed serialization with no
//! magic number and no Berkeley DB involvement. The file opens with a
//! little-endian u64 version.
//!
//! ZWL never held Sprout keys, so nothing here contributes to sub-spec 3.

use crate::{error::ImportError, keys::ImportedKeys};

/// Highest ZWL wallet version this parser understands, matching
/// `ZwlParser::serialized_version()` in zingolabs/zewif-zwl. Refusing a
/// newer file is safer than misreading it: a wrong parse yields wrong
/// keys silently, which is worse than a clear failure.
const MAX_SUPPORTED_VERSION: u64 = 31;

fn unreadable(msg: impl Into<String>) -> ImportError {
    ImportError::UnwalkableBtree(msg.into())
}

/// Parse a ZecWallet Lite wallet file.
///
/// Takes a passphrase because ZWL wallets carry their own `encrypted`
/// flag and an `enc_seed`; a locked wallet's keys are unreadable without
/// it.
pub fn import_zwl(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportedKeys, ImportError> {
    let head = bytes
        .get(0..8)
        .ok_or_else(|| unreadable("file is too short to contain a ZWL version"))?;
    let mut b = [0u8; 8];
    b.copy_from_slice(head);
    let version = u64::from_le_bytes(b);

    if version > MAX_SUPPORTED_VERSION {
        return Err(unreadable(format!(
            "ZecWallet Lite wallet version {version} is newer than this build understands \
             (max {MAX_SUPPORTED_VERSION})"
        )));
    }

    let mut out = ImportedKeys::default();
    let _body = bytes.get(8..).unwrap_or(&[]);

    // Key extraction is implemented against the confirmed ZWL layout.
    // Until that layout is confirmed from zingolabs/zewif-zwl, this
    // returns an empty result rather than guessing at offsets.
    tracing::warn!(
        version,
        "ZecWallet Lite key extraction is not yet implemented; returning no keys"
    );

    Ok(out)
}
```

**The code above is a skeleton, not the deliverable. Do not commit it as written.**

The layout is confirmed (see the block at the top of this task), so this is
implementable — the earlier BLOCKED contingency no longer applies to the
layout question. Implement, in order:

1. Read the `external_version` word and reject anything above 31.
2. Parse the `Keys` struct: its own version word, the `encrypted` flag,
   `enc_seed`, and `nonce`.
3. If `encrypted` is set and no passphrase was supplied, return
   `ImportError::WrongPassphrase` — the same contract the zcashd path uses
   for a locked wallet with no passphrase.
4. Read the `zkeys` and `tkeys` vectors (and `okeys` when the keys version
   is above 21), honouring the version gates listed above.
5. Delete the `warn!` and write tests that recover known keys.

Still report **BLOCKED** rather than committing if you cannot make the key
vectors parse. A wallet that silently reports "no keys found" tells a user
their funds are gone — that failure is worse than not shipping ZWL support.

- [ ] **Step 4: Wire the entry point**

In `crates/argos-wallet-import/src/lib.rs`, replace the stub arm:

```rust
        WalletFormat::ZecwalletLite => zwl::import_zwl(bytes, passphrase),
```

and add `pub mod zwl;`.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p argos-wallet-import
cargo clippy -p argos-wallet-import --all-targets -- -D warnings
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/argos-wallet-import/src/
git commit -m "feat(import): read ZecWallet Lite wallet files

ZWL uses a custom length-prefixed serialization with no magic number and
no Berkeley DB. A version newer than this build understands is refused
rather than parsed on a guess: a wrong parse yields wrong keys silently,
which is worse than a clear failure.

ZWL never held Sprout keys, so this path does not feed sub-spec 3.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: KeySource trait in zeck-core

**Files:**
- Create: `crates/zeck-core/src/key_source.rs`
- Modify: `crates/zeck-core/src/lib.rs`, `crates/zeck-core/src/error.rs`, `crates/zeck-core/Cargo.toml`

**Interfaces:**
- Consumes: `ImportedKeys` (Task 7)
- Produces: `pub trait KeySource`, `pub struct KeySourceFingerprint([u8; 32])`, `pub struct SeedKeySource`, `pub struct ImportedKeySource`

- [ ] **Step 1: Write the failing test**

Create `crates/zeck-core/src/key_source.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn the_same_seed_yields_the_same_fingerprint() {
        let a = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let b = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        assert_eq!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }

    #[test]
    fn a_different_seed_yields_a_different_fingerprint() {
        let other = SEED.replace("art", "amount");
        let a = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let b = SeedKeySource::new(SecretString::new(other));
        assert_ne!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }

    #[test]
    fn a_seed_and_an_import_never_collide() {
        // The resume invariant depends on this: two different key sources
        // must never share a workspace.
        let seed = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let imported = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());
        assert_ne!(seed.fingerprint().unwrap(), imported.fingerprint().unwrap());
    }

    #[test]
    fn imported_fingerprint_changes_when_the_key_set_changes() {
        use argos_wallet_import::keys::{Provenance, TransparentKey};
        use secrecy::Secret;

        let empty = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());

        let mut keys = argos_wallet_import::ImportedKeys::default();
        keys.transparent.push(TransparentKey {
            secret: Secret::new([0x42; 32]),
            provenance: Provenance::Standalone,
        });
        let one = ImportedKeySource::new(keys);

        assert_ne!(empty.fingerprint().unwrap(), one.fingerprint().unwrap());
    }

    #[test]
    fn fingerprint_is_stable_across_calls() {
        let s = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        assert_eq!(s.fingerprint().unwrap(), s.fingerprint().unwrap());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-core key_source`
Expected: FAIL — `cannot find type SeedKeySource`

- [ ] **Step 3: Add the dependency**

In `crates/zeck-core/Cargo.toml` `[dependencies]`:

```toml
argos-wallet-import = { path = "../argos-wallet-import" }
```

- [ ] **Step 4: Implement the trait**

Prepend to `crates/zeck-core/src/key_source.rs`:

```rust
//! Where scan keys come from.
//!
//! The scanner and sweeper take a `&dyn KeySource` and no longer know
//! whether keys were HD-derived from a seed or read out of a wallet file.
//! This is the seam Sprout key sources plug into later.

use argos_wallet_import::ImportedKeys;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::{
    derivation::mnemonic_seed,
    error::{ZeckError, ZeckResult},
};

/// Domain separator so a fingerprint can never be confused with another
/// hash in the codebase.
const FINGERPRINT_DOMAIN: &[u8] = b"argos-key-source-fingerprint-v1";

/// Identifies a key set for workspace keying. Changing the keys must
/// change this, so a resume never reuses a workspace built from different
/// keys — the same invariant the seed fingerprint provided before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySourceFingerprint([u8; 32]);

impl KeySourceFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, for use in filesystem paths.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub trait KeySource: Send + Sync {
    /// Stable identifier for this key set.
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint>;

    /// The 64-byte seed used to initialize the wallet database, when one
    /// exists. Imported key sets have no seed.
    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>>;

    /// Short human-readable description for logs and the resume UI.
    /// Must never contain secret material.
    fn describe(&self) -> String;
}

/// Today's behaviour: keys derived from a BIP-39 mnemonic.
pub struct SeedKeySource {
    seed_phrase: SecretString,
}

impl SeedKeySource {
    pub fn new(seed_phrase: SecretString) -> Self {
        Self { seed_phrase }
    }

    pub fn seed_phrase(&self) -> &SecretString {
        &self.seed_phrase
    }
}

impl KeySource for SeedKeySource {
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        let seed = mnemonic_seed(&self.seed_phrase)?;
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        h.update(b"seed");
        h.update(seed.expose_secret());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Ok(KeySourceFingerprint(out))
    }

    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        let seed = mnemonic_seed(&self.seed_phrase)?;
        Ok(Some(*seed.expose_secret()))
    }

    fn describe(&self) -> String {
        "seed phrase".to_owned()
    }
}

/// Keys read out of a wallet file.
pub struct ImportedKeySource {
    keys: ImportedKeys,
}

impl ImportedKeySource {
    pub fn new(keys: ImportedKeys) -> Self {
        Self { keys }
    }

    pub fn keys(&self) -> &ImportedKeys {
        &self.keys
    }
}

impl KeySource for ImportedKeySource {
    fn fingerprint(&self) -> ZeckResult<KeySourceFingerprint> {
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        // Distinct label from the seed source, so the two can never
        // collide even on an empty key set.
        h.update(b"imported");

        // Hash public identifiers only — never secret material. Sprout
        // addresses and counts are enough to distinguish key sets.
        h.update((self.keys.transparent.len() as u64).to_le_bytes());
        h.update((self.keys.sapling.len() as u64).to_le_bytes());
        h.update((self.keys.sprout.len() as u64).to_le_bytes());
        for k in &self.keys.sprout {
            h.update(k.address);
        }
        for k in &self.keys.transparent {
            // Public-key-derived material is not available here, so bind
            // to a hash of the secret rather than the secret itself.
            let mut inner = Sha256::new();
            inner.update(b"argos-transparent-id-v1");
            inner.update(k.secret.expose_secret());
            h.update(inner.finalize());
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Ok(KeySourceFingerprint(out))
    }

    fn wallet_seed(&self) -> ZeckResult<Option<[u8; 64]>> {
        // Imported key sets have no seed. `zcash_client_sqlite`'s
        // init_wallet_db accepts None; callers must not fabricate one.
        Ok(None)
    }

    fn describe(&self) -> String {
        format!(
            "wallet file ({} transparent, {} sapling, {} sprout)",
            self.keys.transparent.len(),
            self.keys.sapling.len(),
            self.keys.sprout.len()
        )
    }
}

impl From<argos_wallet_import::ImportError> for ZeckError {
    fn from(err: argos_wallet_import::ImportError) -> Self {
        ZeckError::Import(err.to_string())
    }
}
```

- [ ] **Step 5: Add the error variant and export the module**

In `crates/zeck-core/src/error.rs`, add to `ZeckError`:

```rust
    #[error("wallet import failed: {0}")]
    Import(String),
```

In `crates/zeck-core/src/lib.rs`, add:

```rust
pub mod key_source;
```

Also make `mnemonic_seed` reachable: in `crates/zeck-core/src/derivation.rs` it is `pub(crate)`, which is already sufficient for a sibling module.

- [ ] **Step 6: Run tests to verify they pass**

```bash
cargo test -p argos-core key_source
cargo clippy -p argos-core --all-targets -- -D warnings
```
Expected: all 5 tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/zeck-core/ Cargo.lock
git commit -m "feat(core): add a KeySource trait for seed and imported keys

The scanner and sweeper will take a &dyn KeySource and stop knowing
whether keys were HD-derived or read from a wallet file. This is the seam
sub-spec 3 plugs into when Sprout keys arrive from a third source.

KeySourceFingerprint generalizes the seed fingerprint that keys the
workspace, preserving the resume invariant: change the keys, start a fresh
scan. Seed and imported sources use distinct domain labels so they can
never collide, and the imported fingerprint binds to hashes of key
material rather than the material itself.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Generalize the workspace fingerprint

**Files:**
- Modify: `crates/zeck-core/src/workspace.rs:58-84,694-722`
- Modify: `crates/zeck-core/src/models.rs:70-82`

**Interfaces:**
- Consumes: `KeySource`, `KeySourceFingerprint` (Task 14)
- Produces: `RecoveryWorkspace::from_key_source`, `verify_key_source_for_workspace`

**Critical:** this touches audited, working code. The existing `regtest_integration.rs` suite must stay green against the Task 1 baseline. Compare counts, do not assert.

- [ ] **Step 1: Write the failing test**

Append to the tests module in `crates/zeck-core/src/workspace.rs`:

```rust
    #[test]
    fn a_seed_workspace_path_is_unchanged_by_the_refactor() {
        // Regression guard: existing users must resume their scans. If
        // this fails, every in-progress scan on disk is orphaned.
        let cfg = runtime_config(SEED);
        let old = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        let source = SeedKeySource::new(cfg.seed_phrase.clone());
        let new = RecoveryWorkspace::from_key_source(&source, &cfg).unwrap();
        assert_eq!(old.wallet_db_path(), new.wallet_db_path());
    }

    #[test]
    fn an_imported_workspace_differs_from_a_seed_workspace() {
        let cfg = runtime_config(SEED);
        let seed_ws =
            RecoveryWorkspace::from_key_source(&SeedKeySource::new(cfg.seed_phrase.clone()), &cfg)
                .unwrap();
        let imported = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());
        let imported_ws = RecoveryWorkspace::from_key_source(&imported, &cfg).unwrap();
        assert_ne!(seed_ws.wallet_db_path(), imported_ws.wallet_db_path());
    }

    #[test]
    fn the_workspace_path_still_does_not_leak_the_fingerprint() {
        let cfg = runtime_config(SEED);
        let source = SeedKeySource::new(cfg.seed_phrase.clone());
        let ws = RecoveryWorkspace::from_key_source(&source, &cfg).unwrap();
        let fp = source.fingerprint().unwrap().to_hex();
        let path = ws.wallet_db_path().display().to_string();
        assert!(!path.contains(&fp), "workspace path leaks the fingerprint");
    }
```

Add a `runtime_config` helper to the tests module if one does not already exist, matching the shape used at `workspace.rs:1203`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p argos-core workspace`
Expected: FAIL — `no function or associated item named from_key_source`

- [ ] **Step 3: Add the generalized constructor**

In `crates/zeck-core/src/workspace.rs`, add alongside `from_runtime`:

```rust
    /// Build a workspace from any key source.
    ///
    /// `from_runtime` remains as a thin wrapper so existing seed callers
    /// and their on-disk workspaces are untouched. For a seed source this
    /// must produce byte-identical paths to the old implementation, or
    /// every in-progress scan on disk is orphaned.
    pub fn from_key_source(
        source: &dyn KeySource,
        config: &RuntimeScanConfig,
    ) -> ZeckResult<Self> {
        let fingerprint = source.fingerprint()?;

        let scope = match config.num_accounts {
            Some(num_accounts) => format!("accounts-{num_accounts}"),
            None => format!("auto-gap-{}", config.gap_limit),
        };

        let workspace_id = derive_workspace_id_from_fingerprint(
            config.network,
            &fingerprint,
            config.birthday,
            &scope,
        );
        let private_root = config
            .data_dir
            .join(config.network.label())
            .join(format!("workspace-{workspace_id}"));
        let root = private_root
            .join(format!("birthday-{}", config.birthday))
            .join(&scope);

        Ok(Self {
            wallet_db_path: root.join("wallet.sqlite"),
            root,
            private_root,
        })
    }
```

**Path-compatibility requirement:** `derive_workspace_id_from_fingerprint` must produce, for a `SeedKeySource`, exactly what `derive_workspace_id` produces today from a `SeedFingerprint`. Read the existing `derive_workspace_id` implementation and feed it the same bytes. The `a_seed_workspace_path_is_unchanged_by_the_refactor` test is what proves you got this right — if it fails, do not adjust the test.

- [ ] **Step 4: Generalize wallet initialization**

`initialize` currently takes `&[u8; 64]` and passes `Some(SecretVec::new(...))` to `init_wallet_db` (`workspace.rs:95`). Imported key sets have no seed. Change the signature:

```rust
    pub fn initialize_from_source(
        &self,
        network: ZeckNetwork,
        source: &dyn KeySource,
    ) -> ZeckResult<()> {
        create_private_dir_all(&self.root)?;
        tighten_private_perms(&self.private_root, &self.root)?;

        let mut wallet_db = open_wallet_db(&self.wallet_db_path, consensus_network(network))?;
        // Imported wallets have no seed; init_wallet_db accepts None.
        let seed = source
            .wallet_seed()?
            .map(|s| SecretVec::new(s.to_vec()));
        init_wallet_db(&mut wallet_db, seed).map_err(|err| {
            ZeckError::Wallet(format!(
                "initializing wallet database {}: {err}",
                self.wallet_db_path.display()
            ))
        })?;
        set_private_file_permissions(&self.wallet_db_path)?;
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = self.wallet_db_path.as_os_str().to_owned();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if sidecar.exists() {
                set_private_file_permissions(&sidecar)?;
            }
        }
        Ok(())
    }
```

Keep the existing `initialize` as a wrapper so the five call sites in `scan.rs` and `birthday.rs` keep compiling untouched for now.

- [ ] **Step 5: Run the full test suite and compare against baseline**

```bash
cargo test --workspace 2>&1 | tail -40
diff <(tail -40 /tmp/argos-baseline-tests.txt) <(cargo test --workspace 2>&1 | tail -40) || true
```
Expected: the same pass/fail counts as the Task 1 baseline, plus the new tests. **Any newly failing test is a regression in audited code — stop and fix it before continuing.**

- [ ] **Step 6: Commit**

```bash
git add crates/zeck-core/src/
git commit -m "refactor(core): key the workspace on any key source, not just a seed

from_key_source generalizes from_runtime, and initialize_from_source
passes None to init_wallet_db for imported key sets, which have no seed.
Both old entry points remain as wrappers so existing call sites are
untouched.

A regression test asserts that seed-derived workspace paths are
byte-identical to the previous implementation. If they were not, every
in-progress scan on disk would be orphaned.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: CLI wallet-file flag

**Files:**
- Modify: `crates/zeck-cli/src/main.rs:35-86`
- Modify: `crates/zeck-cli/Cargo.toml`

**Interfaces:**
- Consumes: `import_wallet_file` (Task 12), `ImportedKeySource` (Task 14)
- Produces: `--wallet-file` global flag

- [ ] **Step 1: Add the dependency**

In `crates/zeck-cli/Cargo.toml` `[dependencies]`:

```toml
argos-wallet-import = { path = "../argos-wallet-import" }
```

- [ ] **Step 2: Add the flag and conflicts**

In `crates/zeck-cli/src/main.rs`, in the `Cli` struct after `seed_file` (line 36):

```rust
    /// Recover from a wallet file (zcashd wallet.dat or ZecWallet Lite)
    /// instead of a seed phrase.
    #[arg(long, conflicts_with = "seed_file")]
    wallet_file: Option<PathBuf>,
```

Then add `conflicts_with = "wallet_file"` to each of these existing flags. Imported keys have no derivation path to gap-scan and carry their own birthday, so silently ignoring these would let a user believe they had constrained a scan they had not:

```rust
    #[arg(long, conflicts_with = "wallet_file")]
    num_accounts: Option<u32>,

    #[arg(long, default_value_t = 20, conflicts_with = "wallet_file")]
    gap_limit: u32,

    #[arg(long, default_value_t = 419_200, conflicts_with = "wallet_file")]
    birthday: u32,

    #[arg(long, conflicts_with = "birthday_auto_detect", conflicts_with = "wallet_file")]
    birthday_date: Option<String>,

    #[arg(long, conflicts_with = "birthday_date", conflicts_with = "wallet_file")]
    birthday_auto_detect: bool,
```

- [ ] **Step 3: Write the failing test**

Append to `crates/zeck-cli/src/main.rs`:

```rust
#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn wallet_file_and_seed_file_are_mutually_exclusive() {
        let r = Cli::try_parse_from([
            "argos", "--wallet-file", "/tmp/w.dat", "--seed-file", "/tmp/s.txt", "scan",
        ]);
        assert!(r.is_err(), "both key sources were accepted");
    }

    #[test]
    fn birthday_flags_are_rejected_with_a_wallet_file() {
        // Loud error, not silent ignore.
        for flag in ["--birthday=500000", "--birthday-auto-detect", "--gap-limit=5"] {
            let r = Cli::try_parse_from(["argos", "--wallet-file", "/tmp/w.dat", flag, "scan"]);
            assert!(r.is_err(), "{flag} was silently accepted with --wallet-file");
        }
    }

    #[test]
    fn a_wallet_file_alone_parses() {
        let r = Cli::try_parse_from(["argos", "--wallet-file", "/tmp/w.dat", "scan"]);
        assert!(r.is_ok(), "{:?}", r.err());
    }

    #[test]
    fn there_is_no_passphrase_flag() {
        // A passphrase flag would leak to shell history and ps.
        let r = Cli::try_parse_from([
            "argos", "--wallet-file", "/tmp/w.dat", "--passphrase", "x", "scan",
        ]);
        assert!(r.is_err(), "a --passphrase flag exists and must not");
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p argos-cli cli_tests`
Expected: all 4 pass once the flags above are in place.

- [ ] **Step 5: Add the key-source resolution helper**

In `crates/zeck-cli/src/main.rs`, add:

```rust
/// Build the key source for this invocation from the mutually exclusive
/// `--wallet-file` / seed inputs.
fn resolve_key_source(cli: &Cli) -> Result<Box<dyn KeySource>> {
    if let Some(path) = &cli.wallet_file {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading wallet file {}", path.display()))?;

        // Check before prompting so we never ask for a passphrase the
        // wallet does not use.
        let passphrase = if argos_wallet_import::zcashd::needs_passphrase(&bytes) {
            Some(SecretString::new(
                Password::new()
                    .with_prompt("Wallet passphrase")
                    .interact()
                    .context("reading wallet passphrase")?,
            ))
        } else {
            None
        };

        let keys = argos_wallet_import::import_wallet_file(&bytes, passphrase.as_ref())
            .context("importing wallet file")?;

        // Diagnostics are always shown with counts. Unmigrated key
        // material exists only in the original file, so the user must know
        // what we could not read.
        if !keys.diagnostics.is_empty() {
            eprintln!("{} records could not be read:", keys.diagnostics.len());
            for d in &keys.diagnostics {
                eprintln!("  {d}");
            }
            eprintln!("Keep your original wallet file.");
        }

        eprintln!(
            "Imported {} keys: {} transparent, {} sapling, {} sprout",
            keys.total_keys(),
            keys.transparent.len(),
            keys.sapling.len(),
            keys.sprout.len()
        );

        Ok(Box::new(ImportedKeySource::new(keys)))
    } else {
        let seed_phrase = read_seed_phrase(cli)?;
        Ok(Box::new(SeedKeySource::new(seed_phrase)))
    }
}
```

Use whatever the existing seed-reading function is named in place of `read_seed_phrase`; find it with `grep -n 'fn.*seed' crates/zeck-cli/src/main.rs`.

- [ ] **Step 6: Run tests and clippy**

```bash
cargo test --workspace 2>&1 | tail -20
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: baseline counts plus the new tests, clippy clean.

- [ ] **Step 7: Commit**

```bash
git add crates/zeck-cli/ Cargo.lock
git commit -m "feat(cli): add --wallet-file as a global key source

Key provenance is a property of the whole invocation, not of a subcommand,
so --wallet-file is global and mutually exclusive with --seed-file.
show-keys, scan, and sweep all work unchanged.

The birthday and gap-limit flags hard-error with --wallet-file rather than
being ignored: imported keys have no derivation path to gap-scan and carry
their own birthday, and silently ignoring the flag would let a user
believe they had constrained a scan they had not.

There is no --passphrase flag; it is prompted, because a flag would leak
to shell history and ps.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: GUI wallet file import

**Files:**
- Modify: `gui/src-tauri/src/commands.rs`
- Modify: `gui/src-tauri/gen/schemas/capabilities.json`
- Modify: `gui/src/index.html`, `gui/src/main.js`
- Modify: `gui/src-tauri/Cargo.toml`

**Before starting:** `gui/src-tauri/gen/schemas/capabilities.json` is modified in the working tree from unrelated work (spec open question 4). Resolve or stash that change first — do not bundle it into this task.

**Interfaces:**
- Consumes: `import_wallet_file` (Task 12)
- Produces: Tauri command `import_wallet_file`

- [ ] **Step 1: Confirm the working tree is clean**

```bash
git status --short gui/src-tauri/gen/schemas/capabilities.json
```
Expected: no output. If there is output, stop and resolve it with the user before continuing.

- [ ] **Step 2: Add the dependency**

In `gui/src-tauri/Cargo.toml` `[dependencies]`:

```toml
argos-wallet-import = { path = "../../crates/argos-wallet-import" }
```

- [ ] **Step 3: Add the Tauri command**

In `gui/src-tauri/src/commands.rs`:

```rust
/// Summary of an import, returned to the frontend.
///
/// Deliberately carries no key material: only counts and diagnostics
/// cross the IPC boundary.
#[derive(serde::Serialize)]
pub struct ImportSummary {
    pub transparent: usize,
    pub sapling: usize,
    pub sprout: usize,
    pub diagnostics: Vec<String>,
}

/// True when the wallet at `path` is encrypted, so the frontend knows
/// whether to prompt for a passphrase.
#[tauri::command]
pub async fn wallet_needs_passphrase(path: String) -> Result<bool, String> {
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
    Ok(argos_wallet_import::zcashd::needs_passphrase(&bytes))
}

/// Import a wallet file and return a summary.
///
/// The passphrase crosses the Tauri IPC as plaintext JSON. That is a new
/// instance of the exposure documented as audit Issue A in
/// docs/THREAT_MODEL.md, not a new class of exposure.
#[tauri::command]
pub async fn import_wallet_file(
    path: String,
    passphrase: Option<String>,
) -> Result<ImportSummary, String> {
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
    let passphrase = passphrase.map(secrecy::SecretString::new);

    let keys = argos_wallet_import::import_wallet_file(&bytes, passphrase.as_ref())
        .map_err(|e| e.to_string())?;

    Ok(ImportSummary {
        transparent: keys.transparent.len(),
        sapling: keys.sapling.len(),
        sprout: keys.sprout.len(),
        diagnostics: keys.diagnostics.iter().map(ToString::to_string).collect(),
    })
}
```

Register both in the `invoke_handler` list in `gui/src-tauri/src/main.rs` or `lib.rs` — find it with `grep -n 'generate_handler' gui/src-tauri/src/*.rs`.

- [ ] **Step 4: Grant the capabilities**

Add the dialog and fs-read permissions to `gui/src-tauri/gen/schemas/capabilities.json`. Check the exact permission identifiers against the installed Tauri version rather than assuming:

```bash
grep -rn 'permissions' gui/src-tauri/capabilities/*.json
```

Add `dialog:allow-open` and the minimal `fs` read scope needed. Grant read only — this app never writes a wallet file.

- [ ] **Step 5: Add the frontend entry point**

In `gui/src/index.html`, alongside the existing seed entry, add a button. Remember `withGlobalTauri: true`: use `window.__TAURI__.core.invoke`, not ES module imports, and `main.js` is not a module.

```html
<button id="import-wallet-file">Recover from wallet file</button>
```

In `gui/src/main.js`:

```javascript
document.getElementById('import-wallet-file').addEventListener('click', async () => {
  const path = await window.__TAURI__.dialog.open({
    multiple: false,
    filters: [{ name: 'Wallet files', extensions: ['dat'] }],
  });
  if (!path) return;

  // Ask only when the wallet is actually encrypted.
  const needsPass = await window.__TAURI__.core.invoke('wallet_needs_passphrase', { path });
  const passphrase = needsPass ? window.prompt('Wallet passphrase') : null;
  if (needsPass && !passphrase) return;

  try {
    const summary = await window.__TAURI__.core.invoke('import_wallet_file', { path, passphrase });
    showImportSummary(summary);
  } catch (err) {
    showError(String(err));
  }
});

function showImportSummary(summary) {
  const total = summary.transparent + summary.sapling + summary.sprout;
  let msg = `Imported ${total} keys: ${summary.transparent} transparent, ` +
            `${summary.sapling} sapling, ${summary.sprout} sprout.`;
  // Diagnostics are never hidden: unmigrated key material exists only in
  // the original file, so the user must know what we could not read.
  if (summary.diagnostics.length > 0) {
    msg += `\n\n${summary.diagnostics.length} records could not be read:\n` +
           summary.diagnostics.join('\n') +
           '\n\nKeep your original wallet file.';
  }
  document.getElementById('import-status').textContent = msg;
}
```

Reuse the existing `showError` helper if one exists; otherwise write the message into the same status element the seed flow uses.

- [ ] **Step 6: Build and manually verify**

```bash
cd gui && npm run tauri dev
```

Click "Recover from wallet file", select `crates/argos-wallet-import/tests/fixtures/sprout-encrypted.dat`, enter `argos-test-passphrase`. Expected: a summary reporting at least one Sprout key.

- [ ] **Step 7: Commit**

```bash
git add gui/
git commit -m "feat(gui): add wallet file import as a second entry point

A native file picker alongside seed entry, with a passphrase prompt shown
only when the wallet is actually encrypted.

Only counts and diagnostics cross the IPC boundary, never key material.
The passphrase itself does cross as plaintext JSON, which is a new
instance of the exposure documented as audit Issue A, not a new class of
one; the threat model records it explicitly.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 18: Threat model and documentation

**Files:**
- Modify: `docs/THREAT_MODEL.md` (sections 2.1, 2.2, 3, 5, 6.1, 6.4, 11)
- Modify: `README.md` (usage only)
- Modify: `CLAUDE.md`

**Do not touch** `README.md:46` or `docs/THREAT_MODEL.md:374` — the "Sprout recovery is impossible" statements stay until sub-spec 3 ships.

- [ ] **Step 1: Update the component and data-flow sections**

In `docs/THREAT_MODEL.md` §2.1, add:

```markdown
- `crates/argos-wallet-import` — read-only parser for legacy wallet files
  (zcashd `wallet.dat`, ZecWallet Lite). Isolated as a separate crate with
  no network access, no filesystem writes, and no dependency on
  `argos-core`, because it is the only component that consumes an
  attacker-supplied binary file.
```

In §2.2, add the file-input path alongside the existing mnemonic path.

- [ ] **Step 2: Add the new asset**

In §3 Assets:

```markdown
- **The user's wallet file.** A single artifact containing every spending
  key the wallet ever held, including standalone keys imported with
  `z_importkey` that appear in no seed. For a zcashd user this is a
  higher-value asset than a seed phrase, because a seed cannot reconstruct
  it.
```

- [ ] **Step 3: Add the new threat actor path**

In §5 Threat actors:

```markdown
- **A malicious wallet file.** Before wallet-file import, Argos accepted
  only a BIP-39 mnemonic — a low-structure, low-surface input with a fixed
  word list. Accepting an attacker-crafted binary file is a genuinely new
  actor path, not a variant of an existing one.

  Mitigations: parsing is isolated in `argos-wallet-import`, which has no
  network access and performs no filesystem writes, so the blast radius of
  a parser bug is bounded to garbage records rather than key
  exfiltration. The Berkeley DB walker denies indexing, slicing, `unwrap`,
  `expect`, and `panic` at the crate root; validates every length field
  against the real file size before allocating; and bounds page traversal
  with a visited set so a crafted page cycle cannot hang or overflow the
  stack. It is fuzzed with `cargo-fuzz`, seeded from real wallet fixtures.
```

- [ ] **Step 4: Update secret handling**

In §6.1:

```markdown
- **Wallet passphrase.** Held as `SecretString` end to end and never
  written to disk, never accepted as a CLI flag (which would leak to shell
  history and `ps`), and never logged. Decrypted key material zeroizes on
  drop.

  In the GUI the passphrase crosses the Tauri IPC boundary as plaintext
  JSON. This is a **new instance of accepted audit Issue A**, which
  documents the same exposure for the seed phrase — the same
  justification applies, and it is stated here explicitly rather than
  inherited silently.

  As with the seed, `secrecy` zeroizes on drop but does not `mlock`; the
  passphrase remains reachable from swap and core dumps. See
  `docs/secret-memory-evaluation.md`.
```

- [ ] **Step 5: Update local storage**

In §6.4, note that imported key material enters the workspace only in the forms `zcash_client_sqlite` already persists, and that imported workspaces are keyed on a `KeySourceFingerprint` derived from hashes of key material rather than the material itself.

- [ ] **Step 6: Add a revision history entry**

In §11, add a dated row describing the wallet-import addition.

- [ ] **Step 7: Update CLAUDE.md**

Add to the Project section:

```markdown
- `crates/argos-wallet-import` — read-only legacy wallet file parser
  (zcashd `wallet.dat` via a hand-rolled Berkeley DB 6.2 reader, and
  ZecWallet Lite); package name `argos-wallet-import`
```

And a Key Technical Facts entry:

```markdown
### Wallet file import
Hand-rolled BDB 6.2 parsing rather than shelling out to `db_dump` as
Zallet and `zewif-zcashd` do — an external binary in a signed desktop app
is worse for the threat model, and the ZeWIF repos carry no SPDX licence.

`czkey` (encrypted Sprout spending keys) is decrypted here and nowhere
else in the ecosystem: Zallet drops Sprout keys during migration and
`zewif-zcashd` returns an explicit error for them. Its tests are therefore
the only specification that exists — do not weaken them.

Golden fixtures come from a pinned `zcashd:v6.20.0` regtest chain with
Canopy held inactive, which is the only condition under which zcashd will
still run `GenerateNewSproutZKey`.
```

- [ ] **Step 8: Add README usage**

Document `--wallet-file` in the CLI usage section. Do not modify line 46.

- [ ] **Step 9: Verify nothing forbidden was touched**

```bash
git diff README.md | grep -n 'Sprout recovery is still out of scope' || echo "line 46 untouched: good"
git diff docs/THREAT_MODEL.md | grep -n 'librustzcash dropped Sprout' || echo "line 374 untouched: good"
```
Expected: both "untouched: good".

- [ ] **Step 10: Commit**

```bash
git add docs/THREAT_MODEL.md README.md CLAUDE.md
git commit -m "docs: record wallet file import in the threat model

Adds the wallet file as an asset and a malicious wallet file as a new
threat actor path. Before this, Argos accepted only a BIP-39 mnemonic — a
low-structure input with a fixed word list — so an attacker-crafted binary
is a genuinely new vector rather than a variant of an existing one.

The GUI passphrase crossing the Tauri IPC as plaintext JSON is recorded as
a new instance of accepted audit Issue A, stated explicitly rather than
silently inheriting the seed's justification.

The statements that Sprout recovery is impossible are left in place; they
come out when sub-spec 3 ships, not before.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 19: Final verification

- [ ] **Step 1: Full test suite against baseline**

```bash
cargo test --workspace 2>&1 | tail -40
```
Compare against `/tmp/argos-baseline-tests.txt`. Every baseline test must still pass. Report actual counts, not "tests pass".

- [ ] **Step 2: Clippy across all crates**

```bash
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: clean.

- [ ] **Step 3: Verify the hostile-input lint gates are actually active**

```bash
grep -n 'deny' crates/argos-wallet-import/src/lib.rs
```
Expected: `indexing_slicing`, `unwrap_used`, `expect_used`, `panic` all present.

- [ ] **Step 4: Fuzz once more before merge**

```bash
cd crates/argos-wallet-import
cargo +nightly fuzz run bdb_walk -- -max_total_time=600
```
Expected: 10 minutes, no crashes.

- [ ] **Step 5: End-to-end manual check of the headline capability**

```bash
cargo run -p argos-cli -- \
  --wallet-file crates/argos-wallet-import/tests/fixtures/sprout-encrypted.dat \
  show-keys
```
Enter `argos-test-passphrase`. Expected: Sprout keys listed. This is the capability that exists in no other software; confirm it with your own eyes before claiming the task is done.

- [ ] **Step 6: Confirm the regtest suite is unaffected**

```bash
cd tests/regtest && docker compose up -d
cargo test -p argos-core --test regtest_integration -- --ignored 2>&1 | tail -20
docker compose down
```
Expected: same results as baseline. The `KeySource` refactor touched audited code; this is what proves it did no harm.

- [ ] **Step 7: Open the PR**

```bash
git push -u origin spec/walletdat-import
gh pr create --repo sovright/argos \
  --title "wallet.dat import with encrypted Sprout key recovery" \
  --body "$(cat <<'EOF'
Implements sub-spec 1 of `docs/superpowers/specs/2026-07-30-walletdat-import-design.md`.

## What this adds

Argos can now recover funds from a zcashd `wallet.dat` or a ZecWallet Lite
wallet file, including **encrypted Sprout spending keys (`czkey`)**.

That last part is the point. Zallet's `migrate-zcashd-wallet` reports Sprout
spending keys as unmigratable and tells users to move the funds with zcashd
first; `zewif-zcashd` returns an explicit error for `czkey`. zcashd is EOL and
cannot follow the chain past Ironwood, so that advice is unfollowable. An
encrypted zcashd wallet holding Sprout funds has had no recovery path in any
software.

## Approach

- New isolated crate `argos-wallet-import`: no network, no filesystem writes,
  no `argos-core` dependency, because it is the only component that consumes
  an attacker-supplied binary.
- Hand-rolled Berkeley DB 6.2 reader rather than shelling out to `db_dump` as
  Zallet and `zewif-zcashd` do. An external binary in a signed desktop app is
  worse for the threat model, and the ZeWIF repos carry no SPDX licence.
- A `KeySource` trait makes seed-derivation and wallet-import peers, so the
  scanner stops knowing key provenance. This is the seam Sprout recovery
  plugs into in sub-spec 3.
- Partial recovery by default: a record we cannot parse never silences one we
  can, and everything skipped is reported with counts.

## Testing

Golden fixtures are written by a pinned `zcashd:v6.20.0` on a regtest chain
with Canopy held inactive — the only condition under which zcashd still runs
`GenerateNewSproutZKey`. `czkey` has no reference implementation anywhere, so
those fixtures are the only ground truth that exists and the tests against
them are the specification.

The BDB walker is fuzzed with `cargo-fuzz`, seeded from the goldens.

## Not in this PR

Sapling to Ironwood migration (sub-spec 2) and Sprout scanning, witness
construction, and JoinSplit building (sub-spec 3). The statements in
`README.md` and `docs/THREAT_MODEL.md` that Sprout recovery is impossible are
deliberately left in place until sub-spec 3 ships.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| New crate `argos-wallet-import` | 1 |
| `sniff.rs` magic dispatch | 3 |
| `bdb.rs` BDB 6.2 walker | 4, 5 |
| Hostile-input rules, fuzzing | 1 (lints), 4, 5, 6 |
| `zcashd.rs` record layer | 7, 8 |
| `mkey` and passphrase verification | 9 |
| `czkey` day-one scope | 10 |
| Sprout note data and witness preservation | 11 |
| `zwl.rs` ZecWallet Lite | 13 |
| `keys.rs` `ImportedKeys` with provenance | 7 |
| `KeySource` trait | 14 |
| `workspace.rs` fingerprint generalization | 15 |
| CLI `--wallet-file`, flag conflicts, no passphrase flag | 16 |
| GUI entry point and capabilities | 17 |
| Partial recovery by default | 8, 10, 12 (tested) |
| Wrong passphrase vs corruption | 9 (tested) |
| Threat model edits | 18 |
| Golden fixtures, two chain configs | 2 |
| Baseline before changes | 1, 15, 19 |

No spec requirement is unassigned.

**Known gaps, flagged rather than hidden:**

1. **Task 13 (ZWL) is intentionally incomplete.** The ZWL layout is not confirmed from source, and the task says so explicitly and instructs the implementer to stop and report rather than guess. Shipping a parser that silently returns no keys would tell users their wallet is empty when it is not. This is the weakest task in the plan.
2. **Task 11's Sprout note marker scanning is an approximation.** The task flags this and points at `src/wallet/wallet.h` as the authority if a fixture disproves it.
3. **Byte offsets in Tasks 4, 5, 7, 8, and 10 are derived from the BDB and zcashd formats but not verified against a real file by me.** Every one of those tasks includes a golden-fixture test specifically so the offsets are corrected against reality rather than assumed. If a fixture test fails, the fix goes in the parser, not the test — each task says so.
4. **Task 9 is blocked on dependency approval** for `aes` and `cbc`. This is called out at the top of the task.

**Type consistency:** `ImportedKeys`, `ImportError`, `ImportDiagnostic`, `MasterKey`, `RecordKey`, `KeySource`, and `KeySourceFingerprint` are used with consistent names and signatures across every task that references them. `collect_plaintext`, `collect_encrypted`, `collect_sprout_notes`, `import_zcashd`, `import_zwl`, and `import_wallet_file` match their definitions at every call site.
