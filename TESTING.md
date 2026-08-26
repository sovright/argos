# Argos Testing Plan

## Overview

This document tracks the testing strategy for Argos across seed, wallet-file,
standalone Sapling-key, and Sprout recovery. The primary focus is **GUI
testing**, with CLI and live-network coverage for paths that have no cheap
local substitute.

---

## Phase 1 — Local GUI Smoke Tests (No Network Required)

### Step 1: Welcome Screen
- [ ] App launches and window renders at correct size (1180×860, min 940×720)
- [ ] Both entry paths visible: seed phrase and wallet file / standalone key
- [ ] "I have my 24-word seed phrase" navigates to seed entry
- [ ] "I have a wallet file" navigates to wallet-file entry

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

### Step 2b: Wallet File and Standalone Keys
- [ ] Native picker, drag-and-drop, and typed path all open a supported file
- [ ] Opening a wallet does not modify its bytes or timestamp
- [ ] zcashd `wallet.dat` and ZecWallet Lite files are identified correctly
- [ ] Encrypted wallets request a passphrase; wrong passphrases fail cleanly
- [ ] Summary reports transparent, Sapling, and Sprout key counts, mnemonic presence, and diagnostics
- [ ] A pasted `secret-extended-key-main1…` / `secret-extended-key-test1…` key is checked for the selected network
- [ ] Multiple Sapling keys and `#` comment lines are accepted; duplicates are removed
- [ ] Sapling viewing keys (`zxviews…`) and wrong-network spending keys are rejected
- [ ] A standalone Sapling key can continue without a wallet file
- [ ] A standalone Sapling key cannot be combined with a wallet that recovered a mnemonic

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
- [ ] Imported Sapling balances are reported once per imported key/account
- [ ] Imported transparent balances are included without being mistaken for HD-derived accounts
- [ ] A wallet containing Sprout keys shows an explicit separate-recovery warning before totals

### Step 5: Sweep Review
- [ ] Transaction table shows: account index, pool, amount, fee, net amount
- [ ] Skipped accounts section shown when zero-balance accounts exist
- [ ] Fee displayed is within ZIP 317 expected range
- [ ] "I understand this is irreversible" checkbox must be checked before Execute is enabled
- [ ] Back button returns to scan results without losing scan data
- [ ] `propose_sweep` failure surfaces as a readable error (not silent)
- [ ] Execute sweep button triggers real sweep — verify broadcast results and transaction IDs are shown
- [ ] Imported Sapling and transparent legs report separate txids and retain already-broadcast txids after a later failure

### Step 6: Complete / Report
- [ ] Recovery report text displayed on screen
- [ ] "Save Report" button opens a file dialog (`save_recovery_report`)
- [ ] Report saved to chosen path and readable as plain text
- [ ] "Start Over" button clears all state and returns to welcome screen

### Sprout Wallet Flow
- [ ] A wallet with cached spendable note data offers an immediate Sprout sweep without a scan
- [ ] A wallet with Sprout keys but no usable note data explains the full-block scan cost before enabling it
- [ ] Mainnet warning states 1,046,400 blocks, roughly 26 GB transferred, under 500 MB retained, and hours of work
- [ ] Raw `SK…` / `ST…` keys are checked against the selected network
- [ ] Scan progress is checkpointed; stopping and restarting resumes from the saved height
- [ ] A Sprout destination must be a bare Sapling address or a Unified Address with a Sapling receiver
- [ ] The UI explains that funds land in Sapling, not Orchard
- [ ] A missing or invalid `sprout-groth16.params` fails before broadcast with an actionable message
- [ ] Every sent txid, skipped note, and partial failure remains visible

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
| N15 | Imported zcashd Sapling + transparent scan | Finds both pools and does not use the HD gap-limit route |
| N16 | Imported zcashd Sapling + transparent sweep | Broadcasts each applicable pool leg and reports every txid |
| N17 | Sprout wallet with cached witness | Builds and broadcasts without a chain scan |
| N18 | Bare-key Sprout scan | Full-block scan finds a planted note, resumes, and sweeps it to Sapling |

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
- [ ] Truncated/corrupt wallet file — diagnostics or a bounded error, never a hang or panic
- [ ] Wallet containing several Sapling keys — every funded key is scanned and swept
- [ ] Mixed imported Sapling + transparent wallet — one pool failing does not erase the other pool's results
- [ ] Forged imported transparent or Sprout key — rejected before scan/sweep

---

## Phase 4 — CLI Smoke Tests

```bash
# Show derived keys (no network needed)
chmod 600 /tmp/argos-seed.txt
argos --seed-file /tmp/argos-seed.txt --network mainnet show-keys

# Scan (network required)
argos --seed-file /tmp/argos-seed.txt \
  --lightwalletd-url "https://zec.rocks:443" \
  --data-dir /tmp/zeck-test \
  --birthday 2000000 \
  scan

# Sweep proposal (dry run, no broadcast)
argos --seed-file /tmp/argos-seed.txt \
  --lightwalletd-url "https://zec.rocks:443" \
  --data-dir /tmp/zeck-test \
  sweep --destination u1... --memo "recovery test" --dry-run

# Inspect and recover an imported wallet
argos --wallet-file /path/to/wallet.dat inspect-wallet
argos --wallet-file /path/to/wallet.dat scan
argos --wallet-file /path/to/wallet.dat \
  sweep --destination u1... --dry-run

# Recover standalone Sapling keys
chmod 600 /tmp/sapling-keys.txt
argos --sapling-key-file /tmp/sapling-keys.txt scan

# Sprout: preview cached wallet notes, or scan bare keys
argos --wallet-file /path/to/wallet.dat \
  sweep-sprout --destination u1... --dry-run
chmod 600 /tmp/sprout-keys.txt
argos --sprout-key-file /tmp/sprout-keys.txt scan-sprout
```

- [ ] `show-keys` prints Sapling, Orchard, and transparent addresses for accounts 0–4
- [ ] `scan` progress bar updates in terminal
- [ ] `scan` writes workspace to `--data-dir`
- [ ] `sweep` (without `--confirm-sweep`) prints proposal and exits without broadcasting
- [ ] `inspect-wallet` performs no network access and writes no workspace
- [ ] imported Sapling and transparent keys both scan and sweep
- [ ] `scan-sprout` and `sweep-sprout` appear in ordinary `--help` output without a Cargo feature
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

*Last updated: 2026-08-26*
