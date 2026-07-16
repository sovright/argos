# Argos — Claude Context

## Project

Argos is a Zcash wallet recovery tool for ZecWallet Lite seeds. It has three components:
- `crates/zeck-core` — shared Rust library (derivation, scanning, sweeping); package name `argos-core`
- `crates/zeck-cli` — command-line interface; package name `argos-cli`, binary name `argos`
- `gui/` — Tauri v2 desktop app (static HTML/JS frontend + Rust backend); package name `argos-gui`

## Key Technical Facts

### lightwalletd connection drops (GoAway)
Long syncs against public lightwalletd endpoints will regularly receive HTTP/2 GoAway frames (`NO_ERROR`). This is normal server-side connection recycling, not a bug. **Argos handles this with `run_wallet_sync_with_retry` in `crates/zeck-core/src/scan.rs`** — it catches transport errors (GoAway, TLS close_notify, TimedOut, UnexpectedEof, h2 protocol error) and automatically reconnects up to 10 times with a 5-second delay between attempts, re-probing all configured lightwalletd endpoints on each retry.

### Tauri frontend
- Uses `withGlobalTauri: true` — access Tauri APIs via `window.__TAURI__.core.invoke` and `window.__TAURI__.event.listen`, NOT bare ES module imports
- No bundler — `<script src="./main.js">` not `type="module"`
- Default data directory is resolved at runtime via `default_data_dir` Tauri command (maps to `AppDataDir/workspace`). Do NOT write workspace files inside `src-tauri/` or the Tauri dev watcher will trigger a rebuild mid-scan

### Scan architecture

- **Transparent-first quick probe** (`run_transparent_quick_probe` in `scan.rs`): uses `GetAddressUtxos` RPC to surface t-addr balances within seconds of scan start, before the full shielded sync completes. Runs once on the initial gap window and once per gap-extension iteration. Deduplicated against the append-only discovery log.
- **Streaming discoveries**: `ScanProgress.discoveries` is an append-only `Vec<ScanDiscovery>`. The Tauri pump loop (in `commands.rs:start_scan`) tracks `emitted_discoveries: usize` and emits only the tail on each tick — never duplicates. CLI does the same with `discoveries_seen`.
- **Progress poller** (`ProgressPoller` in `scan.rs`): spawns a background task that polls `WalletDb::get_wallet_summary` once per second, writing `blocks_scanned` and `synced_to_height` into shared state. Runs only during `run_wallet_sync_with_retry`, not during pre-scan phases. Survives GoAway reconnects because it polls the DB, not the sync function.
- **ETA tracking**: sliding-window tracker in both CLI (`EtaTracker`) and GUI (JS equivalent). Era hint uses `synced_to_height` (absolute chain height), not `blocks_scanned` (relative delta).
- **Resume invariant**: workspace is keyed on `(data_dir, network, seed_fingerprint, birthday, num_accounts OR gap_limit)`. Changing any of these starts a fresh scan. `fully_scanned_height` from `zcash_client_sqlite` is the resume cursor.

### Birthday auto-detection
`detect_birthday` in `crates/zeck-core/src/birthday.rs` (exported from `lib.rs`):
- **Phase 1**: `GetAddressUtxos` for the first 5 accounts (10 addresses). Returns earliest UTXO height in O(1).
- **Phase 2**: if no transparent history, steps through ~1-year shielded windows from Sapling activation. Each window creates a temp workspace, imports account-0, runs sync under a 45-second `tokio::time::timeout`, then queries the DB for any notes. Reconnects the client after a timeout.
- `ShieldedProbeKeys` struct bundles seed-related params to keep `probe_shielded_window` under the clippy 7-arg limit.

### OS notifications
Best-effort on scan completion. Platform dispatch in `notify_user` (Tauri) and `notify_scan_complete` (CLI):
- macOS: `osascript` AppleScript; strings escaped via `applescript_quote`
- Linux: `notify-send`
- Windows: PowerShell `System.Windows.Forms.NotifyIcon.ShowBalloonTip`; strings escaped via `powershell_quote`

### Lightwalletd endpoints
- Mainnet: `https://zec.rocks:443`, `https://na.zec.rocks:443`
- Testnet: `https://testnet.zec.rocks:443`
- Always include `https://` prefix — bare `host:port` fails TLS

### Test seed (BIP-39 test vector, no real funds)
`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art`

## GitHub
https://github.com/sovright/argos
