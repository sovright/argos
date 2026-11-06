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
- Default data directory is resolved at runtime via `default_data_dir` Tauri command (`AppDataDir/workspace`, or `workspace-v2` when the old default is unmarked and must be preserved). Do NOT write workspace files inside `src-tauri/` or the Tauri dev watcher will trigger a rebuild mid-scan

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
unlicensed one — no licence file, no crate `license` field — so nothing is
taken from it. `crates/argos-wallet-import/src/zwl.rs` cites the upstream
writer instead, `zingolabs/zwl-lib` (MIT), for the ZecWallet Lite byte
layout, and no hand-built ZWL test stream is copied from zewif-zwl.

Sprout recovery was removed after NU7 disallowed v4 transactions. The wallet
parser recognizes `zkey`/`czkey` spending-key records only to produce a count
and `keys::SPROUT_UNSPENDABLE_NOTICE`; it does not decode Sprout keys, notes,
witnesses, or transactions. Supported transparent and Sapling records in the
same file continue through normal recovery. The mixed Sprout-era golden
fixtures remain useful for testing that boundary; see
`tests/regtest/fixtures/README.md`.

Three ZecWallet Lite fixtures (`crates/argos-wallet-import/tests/fixtures/zwl-*.dat`)
are written by the upstream writer, `zwl-lib`'s `LightWallet::write`, from
the public test seed (reproduction in that directory's `README.md`). They
pin the container, chain name and versioned tail (birthday included), but
hold no funds, no shielded notes or blocks, no imported keys and no
encryption. Encrypted imported keys, Orchard key records, HD indices and
the older key layouts are tested only with hand-built byte streams, and
there is still no real user's ZWL wallet file fixture. Treat claims about
those shapes accordingly.

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
is recovered from its flat, individually-stored keys only. It usually *does*
hold an HD seed, and for 5.0+ (`mnemonicphrase`/`cmnemonicphrase`)
`zcashd::seed` verifies it — fingerprint, then the `mnemonichdchain` record —
and sets `ImportedKeys::seed_verified`, but deliberately does **not** put it
in `ImportedKeys::mnemonic` (#229). Every key zcashd derives for its legacy
account `0x7FFFFFFF` is also stored individually, and the HD scan only
enumerates accounts `0..n`, so routing the wallet down the HD path would
drop every stored key; `zcashd_seed_covers_stored_keys` in `zeck-core`
proves this against the fixtures. The chain's counters are what let the
import say the stored keys are complete: `accountCounter > 0` means
`z_getnewaccount` unified accounts exist that are never stored and are not
scanned (`UnscannedSeedAccounts`), and a legacy-chain index with no stored
key is `MissingDerivedKeys`. That second check is by key *identity*, never
by count: a derived key counts only if a `key`/`ckey` (or
`sapzkey`/`csapzkey`) record exists whose `keymeta` (`sapzkeymeta`) names
exactly its legacy-account keypath under this seed's fingerprint. Counting
let every `importprivkey` key stand in for a missing derived one, so a
damaged wallet with imports read as Complete — do not go back to counts. A seed that fails verification, and any
pre-5.0 `hdseed`/`chdseed`, is `UnrecoveredSeed`. Both encrypted golden
fixtures still carry a live plaintext `mnemonicphrase` beside
`cmnemonicphrase` (written by v6.20.0 `encryptwallet`), so the seed of such a
wallet is readable without its passphrase; `seed` prefers the encrypted copy.
Never describe these wallets as "not HD-derived" (#225).

**A Sapling spending key can also arrive as text**, with no wallet file at
all: `argos_core::sapling_key` decodes zcashd's bech32
`secret-extended-key-main1…` / `secret-extended-key-test1…` form and
`keys_from_sapling_strings` packs it into the same `ImportedKeys` a wallet
file produces, so the scan and sweep paths cannot tell the two apart. CLI
`--sapling-key-file` (a file, never a flag — a spending key in argv lands in
shell history and `ps`); GUI a paste field on the wallet screen. Both are
combinable with a wallet file and deduplicate against it. The human-readable prefixes come from
`zcash_keys::constants`, so there is no unverifiable-constant caveat —
but the test pinning them to the ZIP-32 literals stays, so an upstream rename
cannot silently move Argos off the prefix users hold. Viewing keys
(`zxviews…`) are deliberately refused: they would show a balance that cannot
be swept.

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

**Imported Sapling is swept through PCZT.** `imported_sweep` proposes one
send-max transfer per imported Sapling account, supplies the raw spend
authorizing key through the low-level PCZT signer, and preserves every txid
if a later account or the transparent leg fails. Transparent UTXOs use the
direct recovery path and may produce a separate transaction.

Routing (`is_transparent_only` in the CLI): a seedless wallet with Sapling
keys takes the imported-account path; one with only transparent keys takes
`transparent_recovery`, because the existing ZIP-316 Revision 0 account format gives it no
UFVK to anchor an account to.

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
`inspect-wallet` subcommand that reports recovered key counts, recognized
Sprout records with an unspendable notice, and unread-record diagnostics with no network access. The
passphrase is prompt-only — never a flag, so it cannot reach shell history
or `ps` (T-S6). Wired in `crates/zeck-cli/src/main.rs`; covered by
`crates/zeck-cli/tests/wallet_file_cli.rs`, which runs the real binary
against the golden fixtures.

### NU7 qualification

The coordinated NU7 SDK requires Rust 1.89. Keep `RUSTFLAGS=''` and
`CARGO_INCREMENTAL=0` consistent across Cargo invocations. The ordinary
regtest schedule remains pre-NU7; `tests/regtest/zebrad-nu7*.toml` use
independent profiles and state. `nu7_readiness.rs` includes an actual old-SDK
SQLite migration fixture and two ignored live boundary tests. The fast chain
and empty fixtures do not qualify funded supported sweeps or imported Sapling
PCZT. See `docs/qualification/nu7-supported-recovery.md` for the release gate.
Never restore removed Sprout scan, spend, P2P or journal machinery when porting
historical tests or documentation.

### Test seed (BIP-39 test vector, no real funds)
`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art`

## GitHub
https://github.com/sovright/argos
