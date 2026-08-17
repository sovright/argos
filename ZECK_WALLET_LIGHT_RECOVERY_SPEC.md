# Argos: ZecWallet Light Recovery Tool

## Implementation Specification v0.1

**Purpose:** A cross-platform recovery tool (CLI + GUI) for the discontinued ZecWallet Lite wallet. Re-derives ZecWallet Lite's non-standard key hierarchy from a BIP-39 seed phrase, scans all Zcash value pools via `lightwalletd`, and sweeps discovered funds to a user-supplied Zcash Unified Address. Ships as both a CLI for power users and a simple guided desktop application for Mac, Windows, and Linux.

**Target implementation environment:** Rust core library + CLI, with a Tauri v2 desktop GUI. Designed for implementation via Claude Code.

---

## 1. Problem Statement

ZecWallet Lite (by adityapk00) has been discontinued. Users who backed up their 24-word BIP-39 seed phrase cannot recover funds by importing that phrase into contemporary wallets like Zashi or YWallet, because ZecWallet Lite used a **non-standard key derivation model**.

### How ZecWallet Lite derives keys (the core incompatibility)

Most Zcash wallets derive **one master spending key per account** and use **diversified addresses** (ZIP 32) for receiving. ZecWallet Lite instead derives **multiple child spending keys** from a single seed, each with a single address. In effect:

| Wallet Model | Structure |
|---|---|
| Standard (Zashi, YWallet) | 1 seed → 1 account → many diversified addresses |
| ZecWallet Lite | 1 seed → N child keys → 1 address per key |

When a user imports their seed into Zashi, only ZIP 32 account index 0 is scanned. Funds sitting on child key indices 1, 2, … N are invisible — they appear lost.

### Existing recovery tools and their gaps

| Tool | Approach | Limitation |
|---|---|---|
| ZExCavator (Zingo Labs) | Parses `.dat` wallet files via ZeWIF | Requires the wallet data file; seed-only recovery ("key sweeper") unfunded |
| uzw-parser (james_katz) | Converts ZWL seed to YWallet SQLite DB | Outputs YWallet-specific format; no direct sweep to Unified Address |
| ZecWallet Lite fork (Nu6+ZIP 317) | Patched legacy client | Outdated dependencies; maintenance burden |

**Argos fills the gap:** a standalone, seed-phrase-only recovery tool that derives ZecWallet Lite's full key tree, scans all pools, and sweeps to an Orchard-capable Unified Address — with no dependency on `.dat` files or third-party wallet formats.

---

## 2. Architecture Overview

### Layered design: Core Library → CLI / GUI

Argos is structured as a Rust library (`argos-core`) consumed by two frontends. This ensures the CLI and GUI always share identical recovery logic.

```
┌─────────────────────┐    ┌──────────────────────────┐
│      Argos CLI        │    │      Argos GUI (Tauri v2)  │
│  (clap, indicatif)   │    │  ┌──────────────────────┐ │
│                      │    │  │ Web Frontend          │ │
│  Terminal-based      │    │  │ (HTML/CSS/JS)         │ │
│  power-user flow     │    │  │ Step-by-step wizard   │ │
│                      │    │  └──────────┬───────────┘ │
└──────────┬───────────┘    │             │ Tauri IPC   │
           │                │  ┌──────────▼───────────┐ │
           │                │  │ Tauri Rust commands   │ │
           │                │  └──────────┬───────────┘ │
           │                └─────────────┼─────────────┘
           │                              │
           ▼                              ▼
┌──────────────────────────────────────────────────────┐
│                    argos-core (Rust lib)               │
│                                                      │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────┐ │
│  │ Key Deriver  │──▶│  Scanner     │──▶│  Sweeper  │ │
│  │ (ZWL-compat) │   │  (lwd sync)  │   │  (tx build)│ │
│  └─────────────┘   └──────────────┘   └───────────┘ │
│         │                  │                  │       │
│         ▼                  ▼                  ▼       │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────┐ │
│  │  zip32       │   │ lightwalletd │   │ librustzcash│ │
│  │  bip39       │   │ gRPC client  │   │ tx builder │ │
│  │  zcash_keys  │   │              │   │            │ │
│  └─────────────┘   └──────────────┘   └───────────┘ │
└──────────────────────────────────────────────────────┘
```

### Workspace structure

```
zeck/
├── Cargo.toml              (workspace root)
├── crates/
│   ├── argos-core/          Rust library: derivation, scanning, sweeping
│   │   ├── src/lib.rs
│   │   └── Cargo.toml
│   └── argos-cli/           CLI binary: clap + indicatif + argos-core
│       ├── src/main.rs
│       └── Cargo.toml
├── gui/                    Tauri v2 desktop app
│   ├── src-tauri/          Rust Tauri host: thin wrapper calling argos-core
│   │   ├── src/main.rs
│   │   ├── src/commands.rs (Tauri IPC commands)
│   │   ├── Cargo.toml      (depends on argos-core)
│   │   └── tauri.conf.json
│   └── src/                Web frontend (Vanilla JS or lightweight framework)
│       ├── index.html
│       ├── main.js
│       └── styles.css
└── README.md
```

### Three-phase execution model

1. **Derive** — Reproduce ZecWallet Lite's key hierarchy from the seed phrase
2. **Scan** — Sync each derived account against lightwalletd, discovering balances across transparent, Sprout, Sapling, and Orchard pools
3. **Sweep** — Construct and broadcast transactions sending all discovered funds to the user's destination Unified Address

---

## 3. Phase 1: Key Derivation (ZecWallet Lite Compatible)

### 3.1 Seed to master key

ZecWallet Lite uses standard BIP-39 mnemonic → seed derivation (24 words, no passphrase by default, PBKDF2 with 2048 rounds). The resulting 64-byte seed is the input to ZIP 32 key derivation.

**Reference:** `adityapk00/zecwallet-light-cli` — `lib/src/lightwallet.rs`

### 3.2 ZIP 32 account derivation

From the seed, ZecWallet Lite derives keys at sequential **ZIP 32 account indices**:

```
Seed
 └── Account 0:  m_Sapling / 32' / 133' / 0'
 │    ├── Sapling extended spending key (extsk)
 │    ├── Transparent key: m / 44' / 133' / 0' / 0 / 0 (BIP 44)
 │    └── Orchard spending key (if v1.8.x)
 │
 └── Account 1:  m_Sapling / 32' / 133' / 1'
 │    ├── Sapling extsk
 │    ├── Transparent: m / 44' / 133' / 1' / 0 / 0
 │    └── Orchard SK
 │
 └── Account N:  m_Sapling / 32' / 133' / N'
      └── ...
```

**Key implementation detail:** Each ZecWallet Lite "address" in the UI corresponds to a distinct ZIP 32 account index, NOT a diversified address within one account. This is why standard wallets that only check account 0 miss funds.

**Coin type for Zcash mainnet:** `133'` (SLIP-44)

### 3.3 Per-account key material to derive

For each account index `i` in `0..num_accounts`:

| Pool | Derivation | Crate |
|---|---|---|
| **Sapling** | ZIP 32 extended spending key at `m_Sapling / 32' / 133' / i'` | `sapling-crypto`, `zip32` |
| **Transparent** | BIP 44 path `m / 44' / 133' / i' / 0 / 0` (external chain, address 0). Also scan `/ 0 / 1..20` for additional receive addresses and `/ 1 / 0..20` for change addresses. | `zcash_transparent`, `hdwallet` |
| **Orchard** | ZIP 32 Orchard spending key at `m_Orchard / 32' / 133' / i'` | `orchard` |
| **Sprout** | Not HD-derived in ZecWallet Lite. Sprout keys were generated independently. Argos should attempt Sprout scanning using the Sapling IVK for trial decryption if the lightwalletd server supports Sprout blocks. If the user has standalone Sprout keys, they can be imported separately (stretch goal). | N/A |

### 3.4 Configurable account scan depth

```
--num-accounts <N>    (default: 20, max: 500)
```

The tool MUST support scanning at least 100 accounts. The recommended approach is a two-pass strategy:

1. **Gap limit scan (default):** Scan accounts sequentially. Stop after `--gap-limit` (default: 20) consecutive empty accounts.
2. **Explicit count:** If `--num-accounts` is specified, scan exactly that many accounts regardless of gaps.

### 3.5 Reference source code

The authoritative reference for ZecWallet Lite's key derivation is:

- **Repo:** `github.com/adityapk00/zecwallet-light-cli`
- **Key file:** `lib/src/lightwallet.rs` — wallet initialization, key derivation, account creation
- **Key file:** `lib/src/lightclient.rs` — sync logic, transaction construction
- **Electron frontend:** `github.com/adityapk00/zecwallet-lite` (calls into the Rust lib via FFI)

Implementors MUST audit these files to confirm derivation path correctness before release.

---

## 4. Phase 2: Chain Scanning

### 4.1 lightwalletd connection

Argos connects to a `lightwalletd` instance via gRPC using the compact block protocol defined in `zcash_client_backend::proto`.

```
--lightwalletd-url <URL>    (default: https://zec.rocks:443,https://na.zec.rocks:443)
```

Multiple lightwalletd servers should be configurable for fallback. The tool should also accept a `--server` alias for compatibility with ZecWallet Lite CLI conventions.

### 4.2 Wallet birthday / scan range

```
--birthday <HEIGHT>    (default: 419200, Sapling activation height)
```

- If the user knows approximately when their wallet was created, they can set a birthday height to dramatically reduce sync time.
- If unknown, default to Sapling activation (block 419,200).
- For transparent-only funds that predate Sapling, use `--birthday 0` but warn about sync duration.

### 4.3 Scanning strategy per pool

#### Transparent
- Derive BIP 44 addresses for external chain (`/0/0` through `/0/N`) and internal/change chain (`/1/0` through `/1/N`).
- Query lightwalletd `GetAddressUtxos` RPC for each transparent address.
- Also use `GetTaddressTxids` for historical transaction discovery.

#### Sapling
- For each derived account, register the Sapling incoming viewing key (IVK) and full viewing key (FVK).
- Use `zcash_client_backend`'s scanning infrastructure to trial-decrypt compact blocks.
- Requires downloading compact blocks from birthday to chain tip.

#### Orchard
- For each derived account, register the Orchard incoming viewing key.
- Trial-decrypt Orchard actions in compact blocks.
- Note: ZecWallet Lite v1.8.x added experimental Orchard support. Earlier versions did not create Orchard keys, but funds may have been sent TO Orchard addresses derived from the seed by other wallets.

#### Sprout (best-effort)
- Sprout notes cannot be derived from the HD seed in ZecWallet Lite.
- If the user provides a `.dat` file alongside their seed, Argos should attempt to extract Sprout spending keys from it (defer to ZExCavator/ZeWIF for this).
- For seed-only recovery, log a warning that Sprout funds (if any) cannot be recovered without the wallet file.

### 4.4 Scanning implementation

Use `zcash_client_sqlite` as the backing store for sync state:

```rust
// Pseudocode for scanning loop
let db = WalletDb::for_path("zeck_recovery.sqlite")?;

for account_index in 0..num_accounts {
    let usk = UnifiedSpendingKey::from_seed(
        &network,
        &seed,
        AccountId::try_from(account_index)?,
    )?;

    db.import_account_hd(
        &seed,
        account_index.into(),
        &AccountBirthday::from_treestate(...)?,
        "zwl_account_{account_index}",
    )?;
}

// Run sync loop using zcash_client_backend::sync module
// or a manual scan_cached_blocks loop
```

### 4.5 Progress reporting

The scan phase is the longest-running operation. Argos MUST provide:

- Progress bar showing blocks scanned vs. total
- Per-account balance discovery notifications (e.g., "Account 3: found 1.5 ZEC in Sapling")
- Estimated time remaining
- Ability to interrupt and resume (leveraging `zcash_client_sqlite` checkpoint state)

---

## 5. Phase 3: Fund Sweeping

### 5.1 Destination address

```
--destination <UNIFIED_ADDRESS>
```

The destination MUST be a Zcash Unified Address (as defined in ZIP 316). The tool should validate that the address contains at least an Orchard receiver (preferred) or Sapling receiver.

Recommended workflow: The user generates a fresh Unified Address in their target wallet (e.g., Zashi) and provides it to Argos.

### 5.2 Sweep transaction construction

For each account with a non-zero balance:

1. **Shield transparent funds first:** If the account has transparent UTXOs, construct a shielding transaction sending them to the account's own Sapling or Orchard address. This is necessary because direct transparent-to-external-shielded may exceed ZIP 317 fee limits depending on the number of inputs.

2. **Consolidate shielded funds:** If the account has both Sapling and Orchard notes, consolidate within the account as needed.

3. **Sweep to destination:** Construct a transaction sending the account's entire shielded balance to the destination Unified Address.

**Fee handling (ZIP 317):**
- All transactions must comply with ZIP 317 fee rules.
- Fees are deducted from the swept amount.
- If an account's balance is below the minimum fee threshold (dust), log a warning and skip.

### 5.3 Transaction construction details

```rust
// Use zcash_client_backend's transaction proposal system
let proposal = propose_transfer(
    &db,
    &network,
    account_id,
    &TransactionRequest::new(vec![
        Payment {
            recipient_address: destination_ua,
            amount: full_balance_minus_fee,
            memo: Some("Argos recovery sweep".into()),
            ..
        }
    ]),
)?;

let txids = create_proposed_transactions(
    &db,
    &network,
    &prover,
    &usk,
    &proposal,
)?;
```

### 5.4 Sweep modes

```
--dry-run              Show discovered balances without broadcasting
--sweep                Actually broadcast sweep transactions (requires explicit opt-in)
--memo <TEXT>          Attach memo to sweep transactions (default: "Argos recovery")
--max-fee <ZEC>       Abort if total fees exceed this amount (safety valve)
```

**`--dry-run` MUST be the default behavior.** Users must explicitly pass `--sweep` to broadcast transactions. This prevents accidental fund loss.

### 5.5 Broadcast and confirmation

- Submit transactions via lightwalletd `SendTransaction` RPC.
- Wait for each transaction to be mined (poll `GetTransaction` until confirmed).
- Report txid for each sweep transaction.
- If a transaction fails (e.g., due to a reorg), retry with updated anchors.

---

## 6. CLI Interface

```
zeck [OPTIONS] <COMMAND>

COMMANDS:
  scan       Derive keys, sync, and report balances (no transactions)
  sweep      Derive keys, sync, and sweep all funds to destination
  show-keys  Derive and display all keys/addresses (for debugging)

GLOBAL OPTIONS:
  --seed-file <PATH>           Read seed phrase from file (one line, trimmed)
  --destination <UA>           Zcash Unified Address for sweep destination
  --lightwalletd-url <URL>     lightwalletd gRPC endpoint
                               [default: https://zec.rocks:443,https://na.zec.rocks:443]
  --num-accounts <N>           Exact number of accounts to scan [default: gap-limit mode]
  --gap-limit <N>              Stop after N consecutive empty accounts [default: 20]
  --birthday <HEIGHT>          Wallet birthday block height [default: 419200]
  --data-dir <PATH>            Directory for sync state database [default: ./zeck_data]
  --network <NETWORK>          mainnet | testnet [default: mainnet]
  --verbose                    Enable detailed logging
  --dry-run                    Report balances only, do not broadcast (default for sweep)
  --confirm-sweep              Actually broadcast sweep transactions

EXAMPLES:
  # Interactive seed entry, scan and report balances
  zeck scan --birthday 1500000

  # Scan 50 accounts explicitly
  zeck scan --seed-file ./seed.txt --num-accounts 50

  # Dry run sweep (shows what would happen)
  zeck sweep --destination "u1..." --birthday 1500000

  # Execute sweep
  zeck sweep --destination "u1..." --birthday 1500000 --confirm-sweep

  # Debug: show derived keys and addresses
  zeck show-keys --num-accounts 5
```

---

## 7. GUI Application (Tauri v2)

### 7.1 Why Tauri

| Requirement | Tauri fit |
|---|---|
| Mac + Windows + Linux | Native builds per platform using OS webview |
| Simple UI (wizard flow) | HTML/CSS/JS frontend — fast to develop, easy for Claude Code |
| Rust backend | Tauri commands call directly into `argos-core` with no FFI overhead |
| Small binary size | ~5–10 MB installers (no bundled Chromium, unlike Electron) |
| Security | Command allowlisting, CSP enforcement, no Node.js in production |

**Frontend stack:** Vanilla JS (or Preact if state gets complex). No heavy framework — the UI is a 5-screen wizard, not a SPA. CSS uses a minimal design system (e.g., PicoCSS or hand-rolled) for a clean, trust-inspiring look appropriate to a financial recovery tool.

### 7.2 Screen flow

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  1. Welcome  │────▶│ 2. Seed Entry │────▶│ 3. Configure │
│  Explain what│     │  24-word input│     │  Birthday,   │
│  Argos does   │     │  masked field │     │  accounts,   │
│              │     │  paste support│     │  server URL  │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                    ┌──────────────┐     ┌───────▼───────┐
                    │ 5. Sweep     │◀────│ 4. Scan       │
                    │  Confirm dest│     │  Progress bar  │
                    │  Review txns │     │  Per-account   │
                    │  Broadcast   │     │  balance table │
                    └──────┬───────┘     └───────────────┘
                           │
                    ┌──────▼───────┐
                    │ 6. Complete  │
                    │  Txid list   │
                    │  Summary     │
                    └──────────────┘
```

### 7.3 Screen specifications

**Screen 1 — Welcome**
- Brief explanation of what ZecWallet Lite was and why recovery is needed
- "I have my 24-word seed phrase" → proceed
- "I have a .dat wallet file" → link to ZExCavator (out of scope)
- Link to docs / FAQ

**Screen 2 — Seed Entry**
- 24 text inputs in a 6×4 grid, or one large paste-friendly textarea
- BIP-39 word validation with autocomplete (word list is static, no network call)
- Inputs masked by default with "show" toggle (eye icon)
- Validation: green checkmark when all 24 words are valid BIP-39 and checksum passes
- Seed phrase NEVER logged, NEVER sent over IPC as plaintext — Tauri command receives it, passes to `argos-core` which holds it in `secrecy::Secret`

**Screen 3 — Configuration**
- Wallet birthday height input (with a date-picker helper that estimates block height from a calendar date)
- Number of accounts to scan (slider: 5–200, default 20, with "auto gap-limit" checkbox)
- lightwalletd server URL (advanced, collapsed by default, with a dropdown of known-good servers)
- Destination Unified Address input (validated: must parse as valid UA with Orchard or Sapling receiver)
- "Start Scan" button

**Screen 4 — Scanning (long-running)**
- Overall progress bar (blocks synced / total blocks)
- Estimated time remaining
- Live table of discovered accounts with balances:

```
┌────────┬───────────┬──────────┬─────────┬─────────┬──────────┐
│ Acct # │ Sapling   │ Orchard  │ Transp. │ Total   │ Status   │
├────────┼───────────┼──────────┼─────────┼─────────┼──────────┤
│ 0      │ 2.500 ZEC │ 0.000    │ 0.100   │ 2.600   │ ✓ Found  │
│ 1      │ 0.000     │ 0.000    │ 0.000   │ 0.000   │ — Empty  │
│ 2      │ 0.000     │ 1.200    │ 0.000   │ 1.200   │ ✓ Found  │
│ ...    │           │          │         │         │          │
└────────┴───────────┴──────────┴─────────┴─────────┴──────────┘
Grand Total: 3.800 ZEC across 2 accounts
```

- "Cancel" button to abort scan (state persisted, can resume)
- When complete: "Review & Sweep" button (only if balance > 0)

**Screen 5 — Sweep Confirmation**
- Summary table showing: source accounts, amounts, destination address, estimated fees
- Total ZEC to be received after fees
- Prominent warning: "This will send ALL discovered funds to the destination address. This cannot be undone."
- Confirmation checkbox: "I understand this is irreversible"
- "Sweep Funds" button (disabled until checkbox is checked)

**Screen 6 — Complete**
- List of broadcast transaction IDs (clickable links to block explorer)
- Per-transaction status (pending → confirmed)
- "Done" button to close
- Option to save a recovery report as a text file

### 7.4 Tauri IPC commands

The Tauri Rust backend exposes these commands to the frontend via `#[tauri::command]`:

```rust
// All commands are async, run on Tauri's managed thread pool

#[tauri::command]
async fn validate_seed(words: Vec<String>) -> Result<bool, String>;

#[tauri::command]
async fn validate_address(address: String) -> Result<AddressInfo, String>;

#[tauri::command]
async fn start_scan(config: ScanConfig) -> Result<ScanHandle, String>;
// ScanConfig { seed: SecretString, birthday: u32, num_accounts: u32,
//              gap_limit: u32, lightwalletd_url: String }

#[tauri::command]
async fn get_scan_progress(handle: ScanHandle) -> Result<ScanProgress, String>;
// ScanProgress { blocks_scanned: u64, blocks_total: u64,
//                accounts: Vec<AccountBalance>, phase: ScanPhase }

#[tauri::command]
async fn cancel_scan(handle: ScanHandle) -> Result<(), String>;

#[tauri::command]
async fn propose_sweep(handle: ScanHandle, destination: String)
    -> Result<SweepProposal, String>;
// SweepProposal { transactions: Vec<ProposedTx>, total_send: Amount,
//                 total_fee: Amount, net_received: Amount }

#[tauri::command]
async fn execute_sweep(handle: ScanHandle, destination: String)
    -> Result<Vec<TxBroadcastResult>, String>;

#[tauri::command]
async fn estimate_birthday_from_date(date: String) -> Result<u32, String>;
```

**Event-based progress updates:** Rather than polling, the scan emits Tauri events that the frontend listens to:

```rust
// Rust side
app_handle.emit("scan-progress", &progress)?;
app_handle.emit("account-discovered", &account_balance)?;
app_handle.emit("scan-complete", &summary)?;
app_handle.emit("sweep-tx-broadcast", &tx_result)?;
app_handle.emit("sweep-tx-confirmed", &tx_result)?;
```

```javascript
// Frontend side
listen('scan-progress', (event) => updateProgressBar(event.payload));
listen('account-discovered', (event) => addAccountRow(event.payload));
```

### 7.5 Cross-platform build & distribution

| Platform | Webview engine | Installer format | Signing |
|---|---|---|---|
| **macOS** | WKWebView (system) | `.dmg` + `.app` bundle | Apple Developer ID (notarized) |
| **Windows** | WebView2 (Edge-based, preinstalled Win 10+) | `.msi` + `.exe` (NSIS) | Authenticode via Azure Trusted Signing (Iqlusion Inc) |
| **Linux** | WebKitGTK | `.deb`, `.rpm`, `.AppImage` | GPG-signed checksums |

Build pipeline (CI):

```yaml
# GitHub Actions matrix
strategy:
  matrix:
    include:
      - os: macos-latest
        target: aarch64-apple-darwin    # Apple Silicon
      - os: macos-latest
        target: x86_64-apple-darwin     # Intel Mac
      - os: ubuntu-22.04
        target: x86_64-unknown-linux-gnu
      - os: windows-latest
        target: x86_64-pc-windows-msvc
```

Tauri v2's `tauri-cli` handles installer generation per platform:
```bash
cd gui/
npm install
cargo tauri build --target <target>
# Outputs: gui/src-tauri/target/release/bundle/{dmg,msi,deb,appimage}
```

### 7.6 GUI design principles

- **Trust-first aesthetic:** Clean, minimal design. No flashy animations. Muted color palette. Users are recovering potentially significant funds — the UI should feel serious and reliable.
- **Persistent recovery workspace:** The GUI and CLI persist `zcash_client_sqlite` wallet/cache databases under the user-selected workspace directory so scans and sweep construction use authoritative wallet state. Workspace subdirectories MUST be random per session rather than seed-derived, MUST avoid exposing seed fingerprints in paths, and SHOULD be created with private filesystem permissions where the platform supports them.
- **Offline-capable for key derivation:** The seed validation and address display screens work fully offline. Network is only required for scanning and sweeping.
- **Accessible:** Keyboard navigation, screen reader labels, high contrast support. Many users encountering this tool will not be crypto-native.

---

## 8. Crate Dependencies

### Core (from `librustzcash`) — used by `argos-core`

| Crate | Purpose |
|---|---|
| `zcash_client_backend` | Light client scanning, transaction proposals, lightwalletd gRPC |
| `zcash_client_sqlite` | Wallet state persistence during sync |
| `zcash_keys` | Unified spending key derivation, unified address encoding |
| `zcash_primitives` | Zcash protocol types, transaction components |
| `zcash_proofs` | Sapling proof generation (for spend authorization) |
| `zcash_transparent` | Transparent address/key derivation (BIP 44) |
| `zcash_protocol` | Network constants, consensus parameters |
| `zip32` | HD key derivation (Sapling and Orchard paths) |
| `zcash_address` | Address parsing and validation |

### Shielded protocols

| Crate | Purpose |
|---|---|
| `sapling-crypto` | Sapling note decryption and spend proving |
| `orchard` | Orchard note decryption and spend proving |

### Supporting (shared)

| Crate | Purpose |
|---|---|
| `bip0039` | BIP-39 mnemonic parsing and seed derivation |
| `tonic` | gRPC client for lightwalletd |
| `tokio` | Async runtime |
| `secrecy` | Zeroizing wrappers for key material |
| `tracing` / `tracing-subscriber` | Structured logging |
| `anyhow` / `thiserror` | Error handling |
| `serde` / `serde_json` | Serialization for IPC and config |

### CLI-only

| Crate | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `indicatif` | Terminal progress bars |
| `dialoguer` | Interactive prompts (seed entry with masked input) |

### GUI-only

| Crate | Purpose |
|---|---|
| `tauri` (v2) | Desktop app framework, IPC, window management |
| `tauri-build` | Build-time codegen for Tauri |

Frontend (npm, in `gui/`):

| Package | Purpose |
|---|---|
| `@tauri-apps/api` | Frontend JS bindings for Tauri commands and events |
| `picocss` (optional) | Lightweight classless CSS for clean defaults |

---

## 9. Security Considerations

### 9.1 Seed phrase handling

- **CLI:** Seed phrase MUST be read from stdin or file, never from command-line arguments (which appear in process lists and shell history). If `--seed-file` is not provided, prompt interactively with terminal echo disabled. On Unix platforms, seed files SHOULD be rejected when group/other users can read them.
- **GUI:** Seed phrase is entered in a masked input field. It is passed to the Tauri Rust backend via IPC command and immediately wrapped in `secrecy::Secret`. The frontend clears the input buffer after submission. The Tauri IPC channel is local (no network exposure).
- All seed and key material in memory MUST use `secrecy::Secret<>` or `zeroize::Zeroize` for automatic zeroing on drop.

### 9.2 Network privacy

- The lightwalletd server learns which blocks the client is interested in (but not which specific notes are being decrypted).
- Users concerned about metadata leakage should run their own lightwalletd instance or connect via Tor.
- Custom lightwalletd endpoints MUST use HTTPS unless they target localhost/loopback for local testing, and the reported chain metadata MUST match the selected Argos network before scanning or sweeping.
- Document this in the tool's help text and README.

### 9.3 Transaction safety

- Default to `--dry-run` for sweep operations.
- Require explicit `--confirm-sweep` flag.
- Implement `--max-fee` safety valve.
- Display a summary of all proposed transactions and require interactive confirmation (unless `--yes` is passed for scripted use).

### 9.4 Build reproducibility

- Pin all dependency versions in `Cargo.lock`.
- Provide deterministic build instructions.
- Consider reproducible build CI for release binaries.

---

## 10. Testing Strategy

### 10.1 Key derivation verification

- **Unit test:** Given a known 24-word mnemonic, verify that Argos produces the exact same Sapling, transparent, and Orchard addresses as ZecWallet Lite for accounts 0–9.
- **Reference data:** Generate addresses from a local `zecwallet-light-cli` seed fixture and hard-code expected outputs.
- **Cross-reference:** Also verify against `uzw-parser` (james_katz) output.

### 10.2 Integration testing

- Use `lightwalletd` in `darksidewalletd` mode to simulate a controlled blockchain with known transactions.
- Send test funds to derived addresses, then verify Argos discovers them.
- Test sweep transaction construction and broadcast in regtest mode.

### 10.3 Edge cases to test

- Account 0 has no funds, but account 7 does (gap scanning)
- Transparent change addresses (`/ 1 / N`)
- Mixed-pool balances within a single account
- Dust amounts below fee threshold
- Very large number of accounts (100+)
- Interrupted and resumed scans
- Reorg during scan
- Invalid/unreachable lightwalletd server

---

## 11. Relationship to Existing Ecosystem

### ZExCavator / ZeWIF
Argos is complementary. ZExCavator handles `.dat` file ingestion and ZeWIF export. Argos handles the seed-phrase-only recovery path that ZExCavator's "key sweeper" was planned to address but hasn't been funded. A future version could export ZeWIF as an output format.

### uzw-parser
james_katz's `uzw-parser` solves the same key derivation problem but outputs a YWallet SQLite database. Argos uses the same derivation logic but targets direct on-chain sweep to any Unified Address, making it wallet-agnostic.

### Zashi / librustzcash
Argos builds directly on the `zcash_client_backend` / `zcash_client_sqlite` stack that Zashi uses, benefiting from the same actively-maintained scanning and transaction construction infrastructure. The primary addition is the ZecWallet Lite-compatible multi-account derivation loop.

---

## 12. Implementation Milestones

### Milestone 1: Core Library — Key Derivation & Display
- Set up Cargo workspace: `argos-core`, `argos-cli`
- Parse BIP-39 mnemonic
- Derive Sapling, transparent, and Orchard keys for N accounts
- `argos-cli show-keys` command outputs all derived addresses
- Unit tests against known ZecWallet Lite outputs

### Milestone 2: Core Library — Chain Scanning
- Connect to lightwalletd via gRPC
- Import derived accounts into `zcash_client_sqlite`
- Sync compact blocks and discover balances
- `argos-cli scan` command with progress reporting
- Gap-limit auto-detection

### Milestone 3: Core Library — Sweep Transactions
- Transaction proposal construction via `zcash_client_backend`
- Shielding of transparent UTXOs
- Sweep to destination UA
- `argos-cli sweep` command with dry-run and confirm modes
- Fee estimation and safety checks

### Milestone 4: CLI Polish & Release
- Interactive seed phrase input with echo suppression
- Resume interrupted scans
- Error handling and user-friendly messages
- README, security documentation
- Reproducible build setup
- Binary releases for Linux, macOS, Windows

### Milestone 5: GUI — Scaffold & Seed Entry
- Initialize Tauri v2 project in `gui/`
- Wire up `argos-core` as dependency in `src-tauri/Cargo.toml`
- Implement Screens 1–2 (Welcome, Seed Entry)
- Tauri commands: `validate_seed`, `estimate_birthday_from_date`
- Cross-platform build verification (Mac, Windows, Linux)

### Milestone 6: GUI — Scanning & Balance Display
- Implement Screens 3–4 (Configuration, Scanning)
- Tauri commands: `start_scan`, `get_scan_progress`, `cancel_scan`
- Event-based progress streaming to frontend
- Live account balance table

### Milestone 7: GUI — Sweep & Completion
- Implement Screens 5–6 (Sweep Confirmation, Complete)
- Tauri commands: `propose_sweep`, `execute_sweep`
- Recovery report export
- End-to-end user testing

### Milestone 8: Distribution
- GitHub Actions CI for Mac (ARM + Intel), Windows, Linux
- Code signing: Apple notarization, Authenticode, GPG
- Installer generation (`.dmg`, `.msi`, `.deb`, `.AppImage`)
- Landing page / download site
- User documentation and FAQ

---

## 13. Open Questions

1. **Sprout key extraction:** Can we derive any Sprout-related keys from the ZecWallet Lite seed, or were Sprout keys always independently generated? (Likely the latter — needs verification against source.)

2. **ZecWallet Lite versioning:** Did the key derivation scheme change between versions? (v1.7.x Sapling-only vs. v1.8.x with Orchard support.) Argos should handle both by always attempting all pools.

3. **BIP-39 passphrase:** Did ZecWallet Lite support an optional BIP-39 passphrase? If so, add `--passphrase` option. (Believed to be unsupported / empty string by default.)

4. **Transparent address depth:** How many transparent addresses per account did ZecWallet Lite use? Standard BIP-44 uses gap limit of 20 on external chain, but ZecWallet Lite's behavior should be verified. Consider `--transparent-gap-limit` option.

5. **lightwalletd compatibility:** Ensure Argos works with both ECC's lightwalletd and Zebra-backed instances. The compact block format should be the same, but test against both.

6. **ZeWIF export:** Should Argos optionally export discovered wallet state as a ZeWIF file for import into other wallets? (Nice-to-have for Milestone 4+.)

7. **GUI frontend framework:** Spec currently calls for Vanilla JS to minimize dependencies. If the scanning screen's live-updating table proves complex to manage, consider Preact (~3KB) or Solid.js. Decision deferred until Milestone 5 scaffolding.

8. **Code signing:** *Resolved.* Windows is signed via **Azure Trusted Signing** under the **Iqlusion Inc** organization identity (cloud-held key, OIDC, no per-cert procurement; see `RELEASE_SIGNING.md`). macOS is signed/notarized with an Apple Developer ID via secrets configured in the `release-sign` CI environment.

9. **WebView2 on older Windows:** Windows 10 1803+ ships WebView2, but some users may be on older builds. Tauri v2 bundles a WebView2 bootstrapper that auto-installs it — verify this works smoothly or document the requirement.

---

## Appendix A: ZecWallet Lite Source Code Map

```
adityapk00/zecwallet-light-cli/
├── lib/
│   └── src/
│       ├── lightwallet.rs      ← KEY DERIVATION, wallet init, address generation
│       ├── lightclient.rs      ← Sync loop, transaction construction, send logic
│       ├── compact_formats.rs  ← Compact block protobuf types
│       └── grpc_connector.rs   ← lightwalletd gRPC client
├── cli/
│   └── src/
│       └── main.rs             ← CLI argument parsing, seed-file, --recover flags
└── Cargo.toml                  ← Dependency versions (pinned librustzcash revisions)
```

Key functions to audit:
- `LightWallet::new()` — seed initialization and first account creation
- `LightWallet::add_zaddr()` — derives the next Sapling account
- `LightWallet::add_taddr()` — derives the next transparent account
- `LightWallet::add_orchard_ua()` — derives Orchard key (v1.8.x)

## Appendix B: ZIP 32 Derivation Path Reference

```
Purpose: 32 (ZIP 32 shielded HD)
Coin:    133 (Zcash mainnet) / 1 (testnet)

Sapling:     m_Sapling / purpose' / coin_type' / account'
Orchard:     m_Orchard / purpose' / coin_type' / account'
Transparent: m / 44' / coin_type' / account' / change / address_index
             (BIP 44 standard, coin_type = 133)
```

## Appendix C: Lightwalletd gRPC Methods Used

| Method | Purpose |
|---|---|
| `GetLatestBlock` | Current chain tip |
| `GetBlock` | Individual block retrieval |
| `GetBlockRange` | Bulk compact block download |
| `GetTransaction` | Full transaction data by txid |
| `SendTransaction` | Broadcast signed transaction |
| `GetAddressUtxos` | Transparent UTXO set for an address |
| `GetTreeState` | Commitment tree state at a height |
| `GetLightdInfo` | Server metadata and supported features |
