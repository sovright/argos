# Argos — Claude Context

## Project

Argos is a Zcash wallet recovery tool for ZecWallet Lite seeds. It has three components:
- `crates/zeck-core` — shared Rust library (derivation, scanning, sweeping); package name `argos-core`
- `crates/zeck-cli` — command-line interface; package name `argos-cli`, binary name `argos`
- `gui/` — Tauri v2 desktop app (static HTML/JS frontend + Rust backend); package name `argos-gui`
- `crates/argos-wallet-import` — read-only legacy wallet file parser
  (zcashd `wallet.dat` via a hand-rolled Berkeley DB 6.2 reader, and
  ZecWallet Lite); package name `argos-wallet-import`

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

### Wallet file import
Hand-rolled BDB 6.2 parsing rather than shelling out to `db_dump` as
Zallet and `zewif-zcashd` do — an external binary in a signed desktop app
is worse for the threat model.

Depending on the ZeWIF crates instead has its own licensing friction, but
"the ZeWIF repos carry no SPDX licence" is too flat — it covers two
different situations. Blockchain Commons' `zewif` and `zewif-zcashd`
*are* licensed — `LICENSE.md` grants dual MIT/Apache-2.0 — but declare it
as `license = "MIT or Apache 2.0"`, which is not a parseable SPDX
expression (`MIT OR Apache-2.0` would be), so GitHub reports NOASSERTION
and `cargo-deny check licenses` cannot classify them. That is a metadata
problem, not a permission problem. `zingolabs/zewif-zwl` is the genuinely
unlicensed one — no licence file, no crate `license` field — and it is the
repo that matters, since `crates/argos-wallet-import/src/zwl.rs` cites it
for the ZecWallet Lite byte layout. Hence that layout is re-derived and
every ZWL fixture is hand-built rather than copied.

`czkey` (encrypted Sprout spending keys) is decrypted here and nowhere
else in the ecosystem: Zallet drops Sprout keys during migration and
`zewif-zcashd` returns an explicit error for them. Its tests
(`crates/argos-wallet-import/tests/sprout_key_is_genuine.rs` and
`transparent_key_is_genuine.rs` re-derive each recovered key and check it
against the address it was stored under) are therefore the only
specification that exists — do not weaken them.

Golden fixtures come from a pinned `zcashd:v6.20.0` regtest chain with
Canopy held inactive, which is the only condition under which zcashd will
still run `GenerateNewSproutZKey`. No fixture holds funded Sprout notes —
zcashd refuses all inbound Sprout transfers regardless of Canopy height —
so the note/witness preservation path is validated structurally, not
against a real note. See `tests/regtest/fixtures/README.md`.

Every ZecWallet Lite test fixture is a hand-built byte stream; there is no
real-world ZWL wallet file fixture. Treat ZWL parsing claims accordingly.

`argos-wallet-import` has no dependency on `argos-core` (the reverse is
true: `argos-core` depends on it), no network access, and no filesystem
writes — it is the only component that consumes an attacker-supplied
binary file. Key provenance is unified behind the `KeySource` trait in
`crates/zeck-core/src/key_source.rs` (`SeedKeySource` /
`ImportedKeySource`). `RuntimeScanConfig` carries an `Arc<dyn KeySource>`;
`RecoveryService::start_scan_from_key_source` is the general entry point
and `start_scan` is a seed-phrase wrapper over it.

**What import can and cannot do.** A decrypted ZecWallet Lite wallet
recovers a BIP-39 mnemonic, so it re-enters the ordinary HD pipeline and
scans and sweeps exactly like a typed seed phrase. A zcashd `wallet.dat`
holds flat, individually-stored keys with no HD seed; the scanner
enumerates HD-derived account slots, so it has nothing to walk.

**Transparent keys are handled outside that model entirely**
(`crates/zeck-core/src/transparent_recovery.rs`): `GetAddressUtxos` plus a
directly-driven `zcash_primitives` builder, no account and no wallet
database. Proven end to end against a real node by
`transparent_only_wallet_sweeps_to_a_shielded_destination` in
`crates/zeck-core/tests/regtest_integration.rs`. A transparent-only wallet
*cannot* have an account — ZIP-316 forbids a transparent-only unified
container (zcash/librustzcash#2582) — which is why bypassing the model is
the fix rather than a shortcut.

**Imported Sapling is scanned** via `run_imported_scan` in `scan.rs`.
`imported::register_imported_accounts` creates one account per Sapling key
(`import_account_ufvk` with `AccountPurpose::Spending { derivation: None }`)
and attaches the transparent keys to the first account as standalone
receivers, so a single sync covers both pools. Deliberately not the HD
loop: an imported key set is fixed and fully known once parsed, so there
are no slots to enumerate and no gap to extend.

**Spending imported Sapling is still not implemented.** Balances are
visible; moving them needs the PCZT path below.

**Sprout is recoverable, and Argos's scope for it ends at Sapling.** This
is a decision, not a gap. A JoinSplit exists only in a v4 transaction and
Orchard actions only in v5 (`zcash_primitives`' `read_v5` hardcodes
`sprout_bundle: None`), so Sprout cannot reach Orchard in one transaction.
Doing the second hop inside Argos would mean holding an intermediate
spending key of its own — so instead the sweep pays the Sapling receiver of
the address the user supplied, under their keys, and the Orchard hop is
theirs. Argos never custodies value, and a crash mid-flow strands nothing.
Do not "finish the chain" by adding a carrier key; the wording in
`sprout_sweep::SPROUT_LANDS_IN_SAPLING` exists to explain this and is
tested for naming the real constraint.

Two paths reach a Sprout note. A `wallet.dat` that zcashd ever synced
carries a cached witness, and consensus accepts the historical anchor it
produces — proven in `sprout_stale_anchor`, where a spend against a root
the chain had already passed was accepted and mined. That path needs no
scan and is what `sweep-sprout` uses. A wallet whose keys were imported
without a rescan has no note data, and only the full-block scan can find
its notes -- Sprout notes are discoverable solely by trial-decrypting every
JoinSplit, and no Sprout address index exists anywhere. That scan
(`sprout_scan` + `p2p`) is wired into both surfaces — `argos scan-sprout`
and the GUI's scan panel — checkpoints to disk, and resumes from a stored
block cursor. Its tree is validated against zcashd's own root, and it has
been driven end to end on regtest: given only a spending key it finds a
planted note and derives a witness anchoring to the chain's root.

**Argos takes a `wallet.dat` or a raw `zkey`, and nothing else.** Not a
txid, not a node URL. `sprout_key` decodes zcashd's `SK…`/`ST…` form, and
`--sprout-key-file` (a file, never a flag — a spending key in argv lands in
shell history and `ps`) feeds the scan. A targeted lookup keyed on the
paying transaction would be far cheaper than the scan, but it needs a txid
the user has no way to know, so it is not a route.

**A balance reported from a wallet file alone is the file's claim, not a
fact.** `sprout_recovery` proves a note is internally self-consistent, not
that its JoinSplit is on-chain — everything it checks comes from the file.
A crafted `wallet.dat` can therefore show a phantom balance; consensus
rejects the sweep, so no funds move, but the number is not trustworthy
until then. The full-block scan derives everything from the chain and is
immune.

Routing (`is_transparent_only` in the CLI): a seedless wallet with Sapling
keys takes the imported-account path; one with only transparent keys takes
`transparent_recovery`, because ZIP-316 gives it no UFVK to anchor an
account to.

Spending imported Sapling does **not** need an upstream change: PCZT is
account-id driven and `Signer::sign_sapling` takes a raw `ask`. Only the
convenience API (`SpendingKeys` / `create_proposed_transactions`) cannot
express it, because it resolves the account from a `UnifiedSpendingKey`'s
UFVK and takes Sapling authority solely from that key.

Two fee traps, both caught by tests rather than reasoning: a Sapling
bundle pads outputs to `MIN_SHIELDED_OUTPUTS`, so one output is billed as
two — always ask `BundleType::num_outputs` rather than assuming; and
`encode_transparent_address` must go through `consensus_network`, or it
emits testnet-prefixed addresses under regtest.

CLI: `--wallet-file <PATH>` (conflicts with `--seed-file`) plus an
`inspect-wallet` subcommand that reports recovered key counts, Sprout
addresses, and unread-record diagnostics with no network access. The
passphrase is prompt-only — never a flag, so it cannot reach shell history
or `ps` (T-S6). Wired in `crates/zeck-cli/src/main.rs`; covered by
`crates/zeck-cli/tests/wallet_file_cli.rs`, which runs the real binary
against the golden fixtures.

### Test seed (BIP-39 test vector, no real funds)
`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art`

## GitHub
https://github.com/sovright/argos
