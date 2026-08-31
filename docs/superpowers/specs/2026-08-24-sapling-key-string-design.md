# Accepting a Sapling extended spending key as text

**Date:** 2026-08-24
**Branch:** `feat/imported-sapling-sweep`
**Status:** implemented on `main` (CLI key file and GUI paste entry)

## Problem

A user may hold a Sapling extended spending key as a bech32 string —
`secret-extended-key-main1…` from `z_exportkey`, from `zcashd-wallet-tool`
output, or from a paper backup — and no `wallet.dat` at all. Argos has no way
in for that user today.

Sapling extended spending keys currently enter Argos only as **raw bytes**:
`argos_core::imported::parse_sapling_extsk(&[u8])` takes the 169-byte
serialization that the `wallet.dat` and ZecWallet Lite parsers recover from a
file. Nothing accepts the ZIP-32 text form. The only occurrence of the string
`secret-extended-key-main1` in the tree is a *negative* test —
`a_sapling_key_is_not_accepted_as_sprout` in `crates/zeck-core/src/sprout_key.rs`
— asserting that pasting a Sapling key into the Sprout decoder fails.

This is the exact situation `sprout_key.rs` already handles for Sprout: "a
user may hold a spending key as a string, with no `wallet.dat` at all. That
string is the whole of what they have." Sapling deserves the same route.

## What this is not

Not a viewing-key input. `zxviews…` would surface a balance that cannot be
swept, which is a worse outcome than a clear "we need the spending key".
Spending keys only.

## Design

### 1. Decoder — new `crates/zeck-core/src/sapling_key.rs`

A sibling to `sprout_key.rs`, same module purpose, but materially simpler:
the human-readable parts come from `zcash_protocol::constants`, so unlike
Sprout's hand-pinned base58 version bytes there is no unverifiable-constant
problem and no "mainnet has no oracle in this repo" caveat to write.

```rust
pub fn decode_sapling_spending_key(
    s: &str,
    network: ZeckNetwork,
) -> ZeckResult<ExtendedSpendingKey>;

pub fn default_sapling_address(
    extsk: &ExtendedSpendingKey,
    network: ZeckNetwork,
) -> String;
```

Implementation is a thin wrapper over
`zcash_keys::encoding::decode_extended_spending_key(hrp, s)` with the HRP
selected from `zcash_protocol::constants::{mainnet,testnet}::HRP_SAPLING_EXTENDED_SPENDING_KEY`.

**No new dependency.** `zcash_keys` 0.16 is already a workspace dependency with
the `sapling` feature enabled, which is what gates that function
(`zcash_keys-0.16.1/src/encoding.rs:224`).

On failure the decoder retries under the *other* network's HRP; if that
succeeds, the error names the real problem ("this is a testnet key") rather
than reporting a malformed key. This mirrors `sprout_key`'s existing
"other network" behaviour, which has its own test for the same reason: a
user who pastes a correct key for the wrong network is not helped by
"invalid".

`default_sapling_address` exists for the pre-scan validation UX in both
surfaces — it is the same derivation `imported::imported_account_display`
already does, factored so a caller that only has a key can use it.

### 2. Bridge to the imported path

```rust
pub fn keys_from_sapling_strings(
    lines: &[String],
    network: ZeckNetwork,
) -> ZeckResult<ImportedKeys>;
```

Decoded keys are packed into an `ImportedKeys` with the `sapling` field
populated and `Provenance::Standalone`, so `ImportedKeySource` →
`run_imported_scan` → `imported_sweep` all work untouched. This is the whole
reason the change is small: the imported-account path does not care whether a
key came from a file or from a text box.

One doc edit follows: `Provenance::Standalone`'s comment says such a key is
"recoverable only from the wallet file", which stops being true.

### 3. CLI

New flag on the root command:

```
--sapling-key-file <PATH>
```

One key per line; blank lines and `#` comments skipped so a user can annotate
which key came from which backup; duplicates deduped. Byte-for-byte the shape
of `collect_sprout_scan_keys` in `crates/zeck-cli/src/main.rs`.

A file and never a flag value, for the reason already documented on
`--sprout-key-file`: a spending key passed as an argument lands in shell
history and in `ps` output for every user on the box (T-S6).

- Conflicts with `--seed-file` (a seed is a different provenance model).
- Combinable with `--wallet-file`: decoded keys merge into that wallet's
  Sapling set. A user may hold a wallet *and* a paper key for an address the
  wallet never knew about — the same argument `collect_sprout_scan_keys`
  makes for Sprout.

Routing rules need no change — `is_transparent_only` already sends a key set
with Sapling keys down the imported-account path — but the key-source
construction does: `main.rs` currently builds the `ImportedKeySource` only
inside `match &cli.wallet_file`. That match becomes a match over "where the
imported keys came from": wallet file, key file, or both merged.

### 4. GUI

Mirrors the existing Sprout key UI in `gui/src/index.html` and `main.js`:

- a `sapling-scan-keys` textarea alongside the wallet-file picker;
- a **Check keys** button backed by a new `check_sapling_key` Tauri command
  that returns the `zs1…` address each key controls, so a wrong key is caught
  before the scan rather than after it;
- typed keys merged with `walletFile` at scan start, the way the GUI's
  `collect_scan_keys` already does for Sprout.

### 5. Error handling

Every failure names what the user must do:

| Input | Message |
|---|---|
| Correct key, wrong network | names the key's actual network |
| `SK…`/`ST…` Sprout key | points at `--sprout-key-file` |
| `zxviews…` viewing key | states that spending requires the spending key |
| Truncated / mistyped | bech32 checksum failure, reported as malformed |
| Empty file / all comments | "no Sapling keys found in <path>" |

### 6. Testing

TDD — each test written failing first.

**Unit (`sapling_key.rs`):**
- round-trip: encode an `ExtendedSpendingKey` derived from the repo's BIP-39
  test seed, decode it back, assert equality and assert the address it yields;
- wrong-network input produces the network-naming message;
- junk, empty, and whitespace-only input rejected;
- an `SK…` Sprout key must not decode as Sapling — the exact inverse of the
  existing `a_sapling_key_is_not_accepted_as_sprout`.

**CLI (`crates/zeck-cli/tests/wallet_file_cli.rs`):** run the real `argos`
binary against a key file; assert the derived address is reported, and that a
cross-network key fails with the network message.

**Bridge:** assert the `ImportedKeys` built from a text key is equivalent to
what the wallet-file parser produces for the same key material. A regtest scan
test is added only if the existing imported-scan harness makes it cheap; the
scan path itself is already covered for imported keys.

## Files touched

- `crates/zeck-core/src/sapling_key.rs` (new)
- `crates/zeck-core/src/lib.rs` (export)
- `crates/argos-wallet-import/src/keys.rs` (`Provenance::Standalone` doc only)
- `crates/zeck-cli/src/main.rs` (flag + key-file loading)
- `crates/zeck-cli/tests/wallet_file_cli.rs` (tests)
- `gui/src-tauri/src/commands.rs` (`check_sapling_key`, key merging)
- `gui/src-tauri/src/main.rs` (command registration)
- `gui/src/index.html`, `gui/src/main.js` (textarea + check button)
- `CLAUDE.md` (record the new input route)
