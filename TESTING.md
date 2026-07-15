# Argos Testing Plan

## Overview

This document tracks the testing strategy for Argos — a ZecWallet Lite recovery tool. The primary focus is **GUI testing**, with live network scan testing as a key component.

---

## Phase 1 — Local GUI Smoke Tests (No Network Required)

### Step 1: Welcome Screen
- [ ] App launches and window renders at correct size (1180×860, min 940×720)
- [ ] Both entry paths visible: seed phrase and `.dat` file
- [ ] "Start Recovery" navigates to seed entry step

### Step 2: Seed Entry
- [ ] 24-word textarea accepts input
- [ ] Show/hide words toggle works
- [ ] `validate_seed` called on button click — valid seed shows green confirmation
- [ ] Bad checksum caught (e.g. swap last word with another valid BIP-39 word)
- [ ] Wrong word count rejected (23 words, 25 words)
- [ ] Non-BIP-39 words rejected
- [ ] Leading/trailing whitespace trimmed automatically
- [ ] ALL CAPS input normalised to lowercase
- [ ] Cannot advance without passing validation

### Step 3: Configuration Form
- [ ] Network dropdown: Mainnet / Testnet switches correctly
- [ ] Server preset selector populates URL field
- [ ] Custom server URL accepted
- [ ] Birthday height: manual entry works
- [ ] Birthday date picker calls `estimate_birthday_from_date` and fills height field
- [ ] Accounts slider (1–500) moves and updates displayed count
- [ ] Auto gap-limit checkbox enables/disables gap limit field
- [ ] Destination address field: `validate_address` called on blur/button
  - [ ] Rejects transparent (t1…) addresses
  - [ ] Rejects Sapling (zs…) addresses
  - [ ] Accepts unified (u1…) addresses
- [ ] Memo field: 512-byte limit enforced (Unicode/emoji counted in bytes)
- [ ] Max fee field: numeric only, non-numeric input rejected
- [ ] Data directory field accepts a path
- [ ] Cannot advance without a valid destination address

### Step 4: Scan Progress
- [ ] Phase label cycles: ValidatingSeed → DerivingKeys → ProbingLightwalletd → ScanningTransparent → ScanningShielded → Complete
- [ ] Server status shows the connected lightwalletd URL
- [ ] Progress bar fills as blocks are scanned
- [ ] Block counter updates (e.g. "1,234,567 / 2,500,000")
- [ ] ETA countdown updates in real time
- [ ] Account discovery table adds rows when balances found (`account-discovered` event)
- [ ] "Previously active (all funds spent)" shown for zero-balance accounts with history
- [ ] Cancel button stops scan and returns to config
- [ ] Unreachable server shows a clean error message (not a crash or blank screen)
- [ ] Fallback to secondary lightwalletd endpoint is reflected in server status label

### Step 5: Sweep Review
- [ ] Transaction table shows: account index, pool, amount, fee, net amount
- [ ] Skipped accounts section shown when zero-balance accounts exist
- [ ] Fee displayed is within ZIP 317 expected range
- [ ] "I understand this is irreversible" checkbox must be checked before Execute is enabled
- [ ] Back button returns to scan results without losing scan data
- [ ] `propose_sweep` failure surfaces as a readable error (not silent)
- [ ] Execute sweep button triggers real sweep — verify broadcast results and transaction IDs are shown

### Step 6: Complete / Report
- [ ] Recovery report text displayed on screen
- [ ] "Save Report" button opens a file dialog (`save_recovery_report`)
- [ ] Report saved to chosen path and readable as plain text
- [ ] "Start Over" button clears all state and returns to welcome screen

---

## Phase 2 — Live Network Scan Testing (Real ZEC)

**Prerequisites:**
- Test seed phrase from Zaki controlling a wallet with known ZEC balance
- Confirm mainnet vs testnet
- Known birthday height or approximate wallet creation date
- Known expected balance per pool (transparent / Sapling / Orchard)
- Reliable lightwalletd endpoint (e.g. `zec.rocks:443`)

### Network Test Cases

| # | Test | Expected Result |
|---|------|-----------------|
| N1 | Scan with correct birthday height | Finds all expected accounts and balances |
| N2 | Scan with birthday = 0 (genesis) | Same results, much slower |
| N3 | Scan with future birthday height | Misses funds — warning or empty result shown |
| N4 | Single lightwalletd endpoint | Connects and completes scan |
| N5 | Primary endpoint down, fallback in URL list | Falls back automatically, UI reflects new server |
| N6 | All endpoints down | Clean error shown, not a crash |
| N7 | Cancel mid-scan | Scan halts, workspace state persisted to disk |
| N8 | Re-open same data directory | Resumes from saved block cache (faster re-scan) |
| N9 | Transparent funds present | Correct UTXO count and t-address shown |
| N10 | Sapling funds present | Correct shielded balance shown |
| N11 | Orchard funds present | Correct Orchard balance shown |
| N12 | Spent-account gap limit | Scanner does NOT stop at spent account; continues to find funded accounts beyond it |
| N13 | Sweep proposal generated | Amounts + fees match expected; proposal screen renders |
| N14 | Execute sweep | Broadcasts transactions; verify txids and confirmation status shown in UI |

---

## Phase 3 — Edge Cases & Regression

- [ ] Wallet with zero funds — scan completes, empty state shown gracefully
- [ ] Very old wallet (birthday near Sapling activation height ~419,200)
- [ ] Large account count — gap limit of 20 stops scan at correct point
- [ ] Memo with 512-byte boundary (exactly 512 bytes accepted, 513 rejected)
- [ ] Memo with multi-byte Unicode — byte count not character count enforced
- [ ] Window resized to minimum 940×720 — layout does not break or overflow
- [ ] Seed entered with extra spaces between words — normalised correctly
- [ ] Multiple rapid clicks on "Validate Seed" — no duplicate requests sent

---

## Phase 4 — CLI Smoke Tests

```bash
# Show derived keys (no network needed)
argos show-keys --seed "word1 word2 ... word24" --network mainnet

# Scan (network required)
argos scan \
  --seed "word1 word2 ... word24" \
  --lightwalletd-url "zec.rocks:443" \
  --data-dir /tmp/zeck-test \
  --birthday 2000000

# Sweep proposal (dry run, no broadcast)
argos sweep \
  --seed "word1 word2 ... word24" \
  --lightwalletd-url "zec.rocks:443" \
  --data-dir /tmp/zeck-test \
  --destination u1... \
  --memo "recovery test"
```

- [ ] `show-keys` prints Sapling, Orchard, and transparent addresses for accounts 0–4
- [ ] `scan` progress bar updates in terminal
- [ ] `scan` writes workspace to `--data-dir`
- [ ] `sweep` (without `--confirm-sweep`) prints proposal and exits without broadcasting
- [ ] All commands show useful `--help` text

---

## Known Blockers

| Item | Status |
|------|--------|
| Sweep execution (`execute_sweep`) | **Implemented** — full shielding + broadcast + confirmation polling |
| Windows WebView2 on Win10 < 1803 | Untested |
| Code signing (Apple notarization, Windows Authenticode) | **Implemented** — macOS via Apple Developer ID; Windows via Azure Trusted Signing (Iqlusion Inc). See `RELEASE_SIGNING.md` |

---

## Lightwalletd Endpoints for Testing

| Network | Endpoint |
|---------|----------|
| Mainnet | `zec.rocks:443` |
| Mainnet | `na.zec.rocks:443` |
| Testnet | `testnet.zec.rocks:443` |

These are the values of `DEFAULT_MAINNET_LIGHTWALLETD` and
`DEFAULT_TESTNET_LIGHTWALLETD` in `crates/zeck-core/src/lightwalletd.rs`, which
the CLI's `--lightwalletd-url` default and the GUI's server presets both track.

Public endpoints get retired without notice, so the defaults have a
network-gated reachability check. It probes each default *individually* — the
connect helpers fall through to the next endpoint on failure, so a dead primary
stays invisible behind a healthy fallback. Run it periodically:

```bash
cargo test -p argos-core -- --ignored default_endpoints_are_reachable
```

---

*Last updated: 2026-07-15*