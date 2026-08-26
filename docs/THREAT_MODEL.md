# Argos Threat Model

> **Status:** Living document. This revision describes the security posture of current `main`, including wallet-file import, standalone keys, imported-key sweeping, and generally available Sprout recovery.

## 0. At a glance

This section summarises the document for readers who don't have time for the full text. The detail lives in §1–§11 and is the source of truth. It is **assessment** content (the "Where we stand" column is a point-in-time judgement, per §1.1), not part of the stable threat model itself.

### If you're in a hurry

Argos is a single-use recovery tool. You give it a ZecWallet Lite seed, a
legacy wallet file, or a standalone spending key; it scans the chain and
sweeps recoverable funds into a modern wallet. Recovery secrets never leave
the machine. The seed and seed-derived spending authority are not written to
disk, while the resumable Sprout scanner deliberately writes a spend-capable
checkpoint with private permissions (T-L7). Everything else in this document
is about *what could go wrong around those promises* and how we bound the
damage.

The eight things most worth knowing:

| What | Severity | Where we stand |
|---|---|---|
| Seed phrase in memory or on disk | Critical | ✅ Wrapped in `secrecy::SecretString`, zeroized on drop, never written to disk. Residual: OS swap (we do not `mlock`). |
| Wallet files and standalone spending keys | Critical | ⚠️ Kept local and never placed in CLI argv; wallet files are read-only. GUI-entered secrets cross local Tauri IPC, and user-created key-file permissions remain the user's responsibility (T-S6, T-S7). |
| Sprout scan checkpoint | Critical | ⚠️ Spend-capable by design so a multi-hour scan can resume. Created privately and removed after a successful sweep; interrupted or scan-only runs leave it for the user to protect (T-L7). |
| Dependency / supply-chain compromise | High | ✅ ~73% of our Rust tree is shared with the upstream Zcash ecosystem (`librustzcash`). The Tauri-side residue is a separate supply-chain surface we view as acceptable on the same terms other Tauri apps accept it. The whole tree is gated in CI by `cargo-deny` (advisories/licenses/bans/sources) and `cargo-vet` — every dependency must be covered by an imported upstream audit, a trusted-publisher entry, or an explicit exemption, or CI fails — backed by SLSA Level 3 build provenance. We do not claim first-party audit coverage of our own tree. |
| Hostile lightwalletd | Medium–High | ✅ Crafted compact blocks are rejected by `librustzcash` sync; the server learns *that* you're scanning but no scanning-side keys are sent. |
| Hostile or observed Sprout P2P peer | High | ⚠️ Requests reveal no address selection, and mainnet history is PoW/linkage/checkpoint validated. Plaintext transport still reveals the user's IP and peers can deny service; testnet lacks pinned checkpoints (T-N7). |
| Windows installer authenticity | Medium | ✅ Both macOS (Apple Developer ID notarization) and Windows (Azure Trusted Signing under the Iqlusion Inc organization identity) installers are code-signed in the release pipeline (T-B3). SLSA Level 3 provenance (T-SC6) complements the signatures by anchoring each artifact to its source commit. |
| Clipboard residue after paste | Medium | ⚠️ Argos itself never writes the seed to the clipboard. If the user pastes their seed in, that exposure is theirs to manage. The GUI offers a "Clear clipboard" button — see T-S4. |

Where this puts us relative to neighbours: we ship the same `librustzcash` family that ZODL (formerly Zashi) and zebrad rely on, a Tauri stack that is the same residue any Tauri-based Zcash desktop app carries, and a CI posture (`cargo-deny`, `cargo-vet`, zizmor, SLSA Level 3) that is at or above what those projects have today. The detailed comparison is in §6.6 and §7.

### If you're not deep in security

Your seed phrase, wallet file, and standalone spending keys can each authorize
money. If anyone else gets the relevant secret, they can move those funds.
Argos handles them for one job: read the chain, find recoverable funds, and
sweep them somewhere safer. It never transmits them. The seed is not stored;
the exceptional persistent secret is the resumable Sprout checkpoint described
above.

The honest version of "is this safe?" is: **all software has risk, and Argos is no exception.** Our review shows the risks are bounded if you set up your environment well. Specifically:

- **Match your effort to the amount you're recovering.** For small recoveries (under ~25 ZEC), running Argos on your everyday machine is reasonable as long as you trust it — modern operating systems isolate apps well enough for that. For larger amounts, the operational cost of a clean, dedicated machine starts being worth it: a spare laptop, a fresh OS install, or a live-USB system (Tails, a clean Ubuntu) limits the surface for problems we can't reach from inside Argos.
- Don't run Argos on a machine you suspect is already compromised, regardless of the amount. We can't protect a seed from malware that's already on your computer — no recovery tool can.
- Only download Argos from our official release page. Verify the code signature (macOS and Windows) and the SLSA provenance. We document how in the release notes.
- Sweep to a wallet you control and have backed up. The point of Argos is to move funds *out* of an old wallet you're not going to use again.

The risks we *can't* address from inside Argos — a compromised host, a coerced user ("$5 wrench attack") — are listed honestly in §9 (Out of scope) so you can decide what to do about them.

## 1. Purpose and scope

Argos is a single-use Zcash wallet **recovery** tool for ZecWallet Lite seeds
and wallet files, zcashd `wallet.dat`, and standalone Sapling or Sprout
spending keys. It scans the applicable key set and sweeps recoverable funds to
a modern wallet (ZODL, YWallet). It is not an everyday wallet.

This threat model covers:

- the desktop GUI (Tauri v2: HTML/CSS/JS frontend in WebView2/WKWebView/WebKitGTK + Rust backend)
- the CLI (`argos-cli`)
- the shared core library (`argos-core`)
- the read-only legacy-wallet parser (`argos-wallet-import`)
- the lightwalletd and direct Zcash P2P network boundaries
- the build / release / distribution pipeline (GitHub Actions, Vercel marketing site, signed installers)

It does **not** cover the security of the user's host operating system, the
user's destination wallet, the internal infrastructure of third-party
lightwalletd or P2P operators, or the Zcash consensus protocol itself. It does
cover how Argos behaves when a remote lightwalletd or P2P peer is hostile.

### 1.1 Model vs. assessment

This document contains two distinct kinds of content, and keeping them apart matters for reading it correctly:

- **The threat model** — the *stable* description of what we are protecting and against whom: the system as designed (§2), the assets (§3), the trust relationships (§4), the threat actors (§5), and what is out of scope (§9). These define the frame and change only when the design or the adversary set changes.
- **The threat assessment** — our *current evaluation* of how Argos stands against that model: the per-threat severity/status/mitigation tables (§6, including the supply-chain assessment in §6.6), the dependency-posture assessment (§7), the build/release assessment (§8 open items), and the at-a-glance summary (§0). These reflect the state of the software at a point in time and are expected to move as the code, CI, and release pipeline evolve.

Where the two unavoidably touch — for example, an asset in the model (§3) referenced by a mitigation in the assessment (§6) — the assessment side carries the `T-*` identifiers and the ✅/⚠️/❌ status. The model side states *what is true by design*; the assessment side states *how well we currently meet it*.

## 2. System overview

### 2.1 Components

| Component | Process | Language | Trust boundary |
|---|---|---|---|
| `argos-gui` (Tauri shell + WebView) | 2 processes (Rust host + WebView renderer) | Rust + HTML/CSS/JS | Host process trusts WebView only via `invoke` IPC; WebView is sandboxed by the OS |
| `argos-cli` | 1 process | Rust | Inherits the user's shell trust |
| `argos-core` | (library) | Rust | — |
| `argos-wallet-import` | (library) | Rust | Read-only parser for legacy wallet files (zcashd `wallet.dat`, ZecWallet Lite). Isolated as a separate crate with no network access, no filesystem writes, and no dependency on `argos-core`, because it is the only component that consumes an attacker-supplied binary file. |
| lightwalletd | Remote, over TLS gRPC | Go (third party) | Untrusted network peer |
| Zcash P2P peers | Remote, over plaintext Zcash P2P TCP | Third parties | Untrusted full-block sources used only by Sprout scanning |
| Local workspace (SQLite) | On disk | — | Same trust as the user's home directory |

### 2.2 Data flow

```
 user input (seed, standalone keys, destination, config)  wallet file (zcashd / ZecWallet Lite)
            │                                              │
            │                                              ▼
            │                                   ┌──────────────────────┐
            │                                   │ argos-wallet-import    │
            │                                   │  - SecretString-wrapped│
            │                                   │    passphrase          │
            │                                   │  - BDB / ZWL parsing   │
            │                                   │  - decrypt → ImportedKeys│
            │                                   └──────────────────────┘
            │                                              │
            ▼                                              │
   ┌──────────────────┐                                    │
   │  argos-gui  /  argos-cli                     │◀────────┘
   │   - SecretString-wrapped seed                │
   │   - BIP-39 → seed bytes (Secret<[u8;64]>)    │
   │   - ZIP-32/legacy-transparent derivation     │
   │   - or: KeySource from an imported wallet    │
   └──────────────────┘
            │
            │  full viewing keys + spending keys (in process memory)
            ▼
   ┌──────────────────┐               TLS over HTTP/2                  ┌──────────────┐
   │ zcash_client_*    │  ◀────────  gRPC: compact blocks  ────────▶  │ lightwalletd │
   │  (sync + scan)    │             tx fetch, t-utxo                  │   (remote)    │
   └──────────────────┘                                                └──────────────┘
            │
            │  writes wallet DB (FVKs, IVKs, notes, witnesses)
            ▼
   ┌──────────────────┐
   │  workspace.sqlite  │      ←—— resume cursor across restarts
   │  blocks.sqlite      │      ←—— shared compact-block cache
   └──────────────────┘
            │
            │  Orchard/Sapling/Transparent proposals signed in-process
            ▼
   broadcast (tonic / tls) ──▶ lightwalletd ──▶ Zcash network

   Sprout spending keys ──▶ resumable full-block scanner ──TCP──▶ Zcash P2P peers
            │                         │
            │                         └── 0600 spend-capable checkpoint
            └── Sprout proof + Sapling output ──TLS──▶ lightwalletd broadcast
```

## 3. Assets

In rough priority order:

1. **The 24-word seed phrase.** Sole authority to spend any funds derivable from it.
2. **The user's wallet file.** A single artifact containing every spending key the wallet ever held, including standalone keys imported with `z_importkey` that appear in no seed. For a zcashd user this is a higher-value asset than a seed phrase, because a seed cannot reconstruct it.
3. **Standalone spending-key files and pasted keys.** A Sapling or Sprout spending key is direct authority over one legacy address and must be protected like a seed.
4. **The Sprout scan checkpoint.** Contains raw Sprout spending keys, recovered note plaintexts, witnesses, and the commitment-tree cursor. It is spend-capable, not merely scan metadata.
5. **Recovered ZEC.** Sweep transactions move value from the legacy ZWL accounts, or from imported keys, to the user's chosen destination.
6. **The destination address.** Privacy-sensitive linkage between the user and the recovered funds. Sprout necessarily selects a Sapling receiver even when given a Unified Address.
7. **Workspace contents.** Contains full viewing keys (FVKs), incoming viewing keys (IVKs), per-account note cache, witnesses, and historic balances. With FVKs alone an attacker cannot spend, but can fully reconstruct the wallet's transaction history. The spend-capable Sprout checkpoint is called out separately above.
8. **The recovery report.** Plaintext file written by the user with workspace path, txids, account labels, and net amounts. Contains much of the same information as the workspace contents above, and is more sensitive than the compact-block cache below.
9. **The shared compact-block cache.** Public chain data; not sensitive by itself, but the *set of heights present* leaks an upper bound on which wallets have been scanned on this host.

## 4. Trust relationships

Each entry below names two parties and states how much one trusts the other, and on what basis. (This section describes *relationships* between components, not the internal trust boundary of any single process — the per-process boundaries are in the §2.1 table.)

- **User ↔ host OS:** Argos fully trusts the host it runs on. This trust is unverified and unconditional: a compromised OS defeats every other mitigation in this document.
- **Tauri host process ↔ WebView renderer:** The host process does *not* trust the renderer with arbitrary access. The renderer can only reach the host via explicit `#[tauri::command]` handlers, and is itself constrained by the CSP in `gui/src-tauri/tauri.conf.json` (`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: asset: http://asset.localhost; font-src 'self'; connect-src ipc: http://ipc.localhost`). No remote script or remote `connect-src` is permitted, so the renderer cannot be steered by remote content.
- **Argos ↔ lightwalletd:** Argos does *not* trust the server. Confidentiality and integrity in transit rest entirely on TLS (bundled WebPKI trust roots — see T-N2 for the no-pinning caveat); a hostile server cannot inject spendable state because no scanning-side spending keys are sent and crafted compact blocks are rejected by `librustzcash` sync (T-N3). What the server unavoidably learns is the *that* and *when* of scanning, not key material. The default endpoints (`zec.rocks`, `na.zec.rocks` for mainnet; `testnet.zec.rocks` for testnet) are configurable per scan, so a user who trusts a specific operator (e.g. their own node) can substitute it.
- **Argos ↔ Zcash P2P peers:** Sprout scanning does not send keys or addresses; it asks for the same complete historical block range for every key set. Connections are plaintext TCP, so peers and path observers learn the user's IP and that Argos is requesting old blocks. Block bytes are hostile input. The client bounds message sizes and time, recomputes hashes, verifies header linkage and Equihash proof of work, and pins mainnet segments with known checkpoints. Testnet has no equivalent checkpoint pinning (T-N7).
- **Argos ↔ local disk:** Argos trusts the local filesystem to the same degree it trusts the host OS, and relies on filesystem permissions to keep workspace contents private from other OS users. Workspace directories and database files are written to a user-chosen directory (defaulting to the platform `AppDataDir/workspace`). Workspace directories are created with `0o700` and database files with `0o600` (`workspace.rs:set_private_file_permissions`). Those mode bits do **not** protect against another process already running as the same OS account; that is treated as a host/user-account compromise. The `session.json` sidecar contains no keys — only label, network, birthday, and timestamps — and inherits the OS umask.
- **Build pipeline ↔ release artifact:** Users trust a released artifact only insofar as it is code-signed and provenance-attested by the pipeline. Signing happens in the tag-triggered release workflow, with GitHub Actions environments providing the out-of-tree approval gate (PR #48). macOS signing uses Apple Developer ID secrets; Windows signing uses **Azure Trusted Signing** (cloud-held key, no secret in CI — the runner authenticates via OIDC; PR #96) under the Iqlusion Inc organization identity (see §8, T-B3). Maintainers must keep required reviewers enabled on the release environments, and should also enable environment branch/tag restrictions in repo settings. The SLSA Level 3 build-provenance attestation (T-SC6) additionally gives every artifact a third-party-verifiable source-to-binary chain, generated by the first-party `actions/attest-build-provenance` and verified with `gh attestation verify`.

## 5. Threat actors

The **In scope?** column is a verdict, not a mitigation summary:

- **Yes** — Argos actively mitigates or bounds this actor's capability (the named `T-*` control is the defense).
- **Partial** — Argos fully mitigates one concrete sub-capability, but a specific named residual (a `T-*` gap) remains in scope and unmitigated.
- **No** — out of scope: Argos cannot meaningfully defend this boundary and treats it as the user's or platform's responsibility. A `T-*` control may still *limit damage* without defending the boundary.

Mitigation detail lives in §6; this column only classifies.

| Actor | Capability | In scope? |
|---|---|---|
| Another process running *as the Argos user's OS account* | Read files under that account (workspace DB, recovery report) and list/inspect that account's processes, using only ordinary same-account access | No — POSIX `0o700`/`0o600` permissions do not separate processes with the same UID; Argos can minimize persisted secrets but cannot defend this boundary |
| Code running *inside* the Argos process (in-process attacker — e.g. malware that has already injected into Argos) | Read process memory, read disk, intercept clipboard, screen-capture, keylog | No — an attacker already executing in our address space is inside the trust boundary; T-S1 (zeroize on drop) and T-S4 (clipboard) shrink the persisted/secondary footprint but cannot defend against in-process code |
| A *different unprivileged* OS user on the same host | Read the Argos user's files via normal filesystem access | Yes — bounded by `0o700`/`0o600` permissions (T-L1) |
| A *privileged / root* process, or one exploiting an OS-isolation bug | Cross the account boundary via privilege escalation or a kernel / OS-isolation flaw | No — the integrity of the OS account and process isolation is the host OS's responsibility |
| Network observer (passive sniffer, anywhere on the path) | Passively observe Argos's network traffic, on the local segment or any upstream hop | Yes — all lightwalletd traffic is TLS (T-N1) |
| Hostile lightwalletd operator | Serve crafted compact blocks, log query patterns | Partial — crafted blocks are rejected by `librustzcash` sync and no scanning-side keys are sent (T-N3); residual: the server unavoidably observes query patterns / IP, which is inherent to the protocol (T-N4) |
| Hostile Zcash P2P peer or on-path TCP attacker | Serve malformed or fabricated historical blocks, stall the Sprout scan, or observe the user's IP and old-block request pattern | Partial — framing, allocation, timeout, block-hash, header-linkage, proof-of-work, and mainnet checkpoint checks bound integrity and resource attacks; peers can still deny service, the transport is not confidential, and testnet lacks pinned checkpoints (T-N7) |
| Hostile DNS operator | Return a malicious address for a lightwalletd hostname to redirect the connection | Yes — DNS-only substitution is defeated by TLS certificate validation against the webpki roots (a DNS-only attacker cannot obtain a valid certificate) |
| Attacker able to compromise WebPKI validation for a lightwalletd hostname | Obtain a mis-issued certificate, compromise a WebPKI CA, or otherwise present a certificate accepted by the bundled WebPKI root set | No — a valid-looking rogue certificate defeats TLS validation because default endpoints are not certificate-pinned; pinning (T-N2) is the tracked would-be mitigation |
| Compromised upstream Rust dependency | Inject malicious code at build time (`build.rs`, proc macros, or runtime code) | Partial — new resolutions are gated in CI by `cargo-deny` + `cargo-vet` (each crate must be covered by an imported audit, a trusted-publisher entry, or an explicit exemption, or CI fails); residual: the Tauri-side tree (§6.6.4) is carried as exemptions / publisher-trust, and `build.rs`/proc-macro sandboxing (Geiger-style enumeration) is *not yet* adopted (T-SC1). No JS at runtime (§7). See §6.6, §7 |
| Compromised GitHub Actions / signing key | Sign a malicious installer | Yes — see §8 |
| A malicious wallet file | Craft a `wallet.dat` or ZecWallet Lite file to exploit the parser (hang, crash, or induce it to emit a well-formed but wrong key) | Partial — parsing is isolated in `argos-wallet-import`, which has no network access and performs no filesystem writes, so a parser bug is bounded to garbage records rather than key exfiltration; the Berkeley DB walker denies indexing, slicing, `unwrap`, `expect`, and `panic` at the crate root, validates every length field against the real file size before allocating, and bounds page traversal with a visited set so a crafted page cycle cannot hang or overflow the stack; fuzzed with `cargo-fuzz`, seeded from real wallet fixtures. Residual: recovered transparent, Sapling, and Sprout keys are re-derived and checked against their stored addresses (`tests/transparent_key_is_genuine.rs`, `tests/sapling_key_is_genuine.rs`, `tests/sprout_key_is_genuine.rs`) rather than trusted as parsed, because the domain's failure mode is a well-formed wrong key, not a crash |
| Casual shoulder-surfer | Read the screen while seed is visible | Yes |
| Coerced user ($5 wrench attack) | Forced to run a sweep under duress | No |
| Nation-state with cryptanalytic capability | Break Sapling/Orchard or post-quantum threats | No |

## 6. Threats and mitigations

This section is the **threat assessment** (see §1.1): for each threat implied by the model in §2–§5, it records our current evaluation rather than a fixed design property. Severity: **C**ritical / **H**igh / **M**edium / **L**ow. Status: ✅ mitigated, ⚠️ partial, ❌ open — the status is a point-in-time judgement that moves as the software changes.

### 6.1 Secret handling

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-S1 | Seed phrase remains in process memory after use; swapped to disk | H | ✅ | Seed is wrapped in `secrecy::SecretString` and the BIP-39-derived 64-byte seed in `Secret<[u8;64]>` (PR #47). `Drop` zeroizes underlying memory. We do **not** call `mlock`/`VirtualLock` — swap remains a residual risk on the host. |
| T-S2 | Seed phrase ends up in JS state and outlives the scan | H | ✅ | `state.scanConfig` stores a seed-less copy of the config (network/birthday/account params only). The seed is passed to the `start_scan` Tauri command and the textarea is cleared on submit; no JS reference outlives the call. |
| T-S3 | Seed phrase leaks via logs / tracing / `Debug` impl | H | ✅ | `secrecy` wrappers do not implement `Debug`/`Display` for their inner value. No `println!`/`tracing` calls on seed-bearing variables. |
| T-S4 | Seed phrase leaks via clipboard | M | ⚠️ | **What Argos does:** never calls `writeText(seed)`. The only `writeText` callsites in the GUI are the recovery-report "Copy path" button (PR #53, copies a file path) and the donate-overlay address button (copies a public unified address). There is no "Copy seed" affordance anywhere. **What users can do:** the seed-entry screen and the resume-scan modal both expose a "Clear clipboard" button that calls `navigator.clipboard.writeText("")` to overwrite the bare OS clipboard once the user has finished pasting. **What stays bounded by the user's environment:** clipboard-history managers (e.g. Maccy, ClipboardFusion, the iOS handoff clipboard) may have snapshotted the seed at paste time; our `writeText("")` does not retroactively scrub those. We deliberately do *not* block paste — a password manager → paste flow is safer than retyping a 24-word seed under a keylogger or shoulder-surfer, and "block copy" via `oncopy="return false"` is bypassable theatre on a textarea, not a real control. |
| T-S5 | Seed visible on screen during entry | L | ✅ | Seed textarea is blurred by default; user must explicitly toggle "Show words on screen". |
| T-S6 | Wallet-file passphrase (zcashd `wallet.dat` / ZecWallet Lite import) leaks via memory, disk, logs, or CLI argv | H | ⚠️ | Held as `SecretString` end to end, never written to disk, never accepted as a CLI flag (which would leak to shell history and `ps` — prompt-only via `dialoguer::Password` in `crates/zeck-cli/src/main.rs`), and never logged. Decrypted key material zeroizes on drop. `secrecy` zeroizes on drop but does not `mlock`; the passphrase remains reachable from swap and core dumps, as for the seed. See `docs/secret-memory-evaluation.md`. **The GUI now exposes a wallet-file entry point**, so the passphrase does cross the Tauri IPC boundary as plaintext JSON — a **new instance of accepted audit Issue A**, previously recorded here in advance and now realised deliberately. Two commands carry it (`inspect_wallet_file`, `start_scan_from_wallet_file` in `gui/src-tauri/src/commands.rs`); both deserialize it straight into a `SecretString`, and neither input struct derives `Debug`, `Serialize`, or `Clone`. The frontend drops its copy once the scan is under way (T-S2), and only on success — clearing it on failure would strand a retrying user. The wallet *path*, not its bytes, crosses IPC: the backend opens the file itself, so an attacker-supplied wallet never transits the webview. The CLI remains prompt-only via `dialoguer::Password` in `crates/zeck-cli/src/main.rs`, where no process boundary is crossed at all. |
| T-S7 | A standalone Sapling or Sprout spending key leaks through argv, logs, UI state, or an over-permissive key file | H | ⚠️ | The CLI accepts only `--sapling-key-file` / `--sprout-key-file`, never a key value in argv. Decoders return line-numbered errors without echoing secret text, and key material is not logged. The GUI accepts pasted keys, so they cross the existing local Tauri IPC boundary and reside transiently in WebView memory. Argos cannot force permissions on an existing user-created key file; users are instructed to use `0600`. Sprout scan persistence is assessed separately in T-L7. |

### 6.2 Frontend (Tauri + WebView)

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-F1 | XSS via lightwalletd-controlled data rendered in the UI | H | ⚠️ | Strict CSP forbids inline/remote scripts. We rely on the DOM API (`textContent`, not `innerHTML`) for server-derived strings. Worth auditing every render path that includes an address, label, or memo. |
| T-F2 | Supply-chain attack via npm packages | M | ✅ | `withGlobalTauri: true`; `main.js` has zero imports; no `node_modules` in the runtime bundle (PR #50). |
| T-F3 | Tauri command surface broader than necessary | M | ⚠️ | All commands live in `gui/src-tauri/src/commands.rs`. Worth a periodic review to ensure each one needs to exist and validates its inputs. |
| T-F4 | localStorage leaks (e.g. dismissed-session IDs) | L | ✅ | Only non-sensitive UI state (sidebar width, dismissed-session workspace paths) lives in localStorage. No secrets. |

### 6.3 Network

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-N1 | Passive observer learns user is scanning Zcash | L | ✅ | All lightwalletd traffic is TLS. Endpoint discoverable via SNI, which is expected for a public service. |
| T-N2 | Active MITM substitutes lightwalletd | H | ⚠️ | Bundled WebPKI trust roots only — **no certificate pinning** of `zec.rocks`. A CA compromise, certificate mis-issuance, or other certificate accepted by the WebPKI root set can route queries (and broadcasts) to a hostile node. Pinning the default endpoints is tracked as a follow-up. |
| T-N3 | Hostile lightwalletd serves invalid compact blocks | M | ✅ | `zcash_client_backend::sync::run` validates witness consistency against the chain tip and rejects malformed/inconsistent blocks. |
| T-N4 | Hostile lightwalletd correlates a user's IP with their wallet | H | ⚠️ | Inherent to the lightwalletd protocol. Mitigations: configurable endpoint (run your own), the `GetAddressUtxos` quick-probe queries 10 t-addrs (5 accounts × 2 addresses: external + change) which leaks them in plaintext (post-TLS) to the server, and the compact-block scan range leaks the wallet birthday. No Tor integration. |
| T-N5 | Auto-detect probe leaks viewing-key-derived addresses | M | ⚠️ | The auto-detect flow (`crates/zeck-core/src/birthday.rs`) imports an account into a temp workspace and runs a windowed sync. This sends FVK-derived address queries to the server. Documented in the UI ("requires a server connection"), but worth surfacing more clearly. |
| T-N6 | Sweep transaction broadcast reveals consolidation pattern | M | ⚠️ | A single sweep aggregates funds from many ZWL accounts into one destination, which on-chain analysis can link. Inherent to recovery — no good mitigation without changing the sweep model. |
| T-N7 | A hostile or observed P2P connection corrupts or deanonymizes a Sprout scan | H | ⚠️ | Sprout requests the complete genesis-to-Canopy range regardless of the key, so the request reveals no address-level selection, but plaintext peers and path observers see the user's IP and an Argos user agent. Hostile bytes are bounded by payload and per-page memory ceilings and read/connect timeouts; block hashes are recomputed; header and page linkage, Equihash proof of work, and four mainnet checkpoints are verified. A peer can still stall or refuse service, and testnet has no fixed checkpoints. Users may pass `--peer` for a node they trust. |

### 6.4 Local storage

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-L1 | Different local OS users read the workspace DB | M | ✅ | Workspace directories are created `0o700` and database files `0o600` at creation time (`workspace.rs:set_private_file_permissions`, implemented in PR #43). Workspace contains FVKs/IVKs (privacy leak) and witnesses, not the seed. These mode bits protect against ordinary cross-account reads, not a process already running as the same OS user. `session.json` (label, network, birthday, timestamps — no keys) inherits the OS umask. |
| T-L2 | Recovery report contains sensitive metadata | L | ✅ | Report is user-initiated, written to a user-chosen path. Contents are documented in the UI before save (network, birthday, accounts, mode, workspace path, txids, net amounts). |
| T-L3 | Workspace persists indefinitely after recovery | L | ✅ | The GUI's Recovery-complete screen now exposes a "Delete workspace" action (`RecoveryService::delete_workspace` → `fs::remove_dir_all`). The UI explicitly surfaces that this is not a cryptographic wipe on SSDs — block-level remnants may persist until cells are overwritten or TRIM'd. For high-value seeds, users are directed to encrypt the volume containing the workspace. CLI users can `rm -rf` the workspace path printed at the end of a scan. |
| T-L4 | Resume-session metadata identifies prior recoveries | L | ✅ | The resume panel only shows workspaces under the configured data-dir; dismissed sessions stay dismissed via localStorage (PR #53). Sessions can be excluded without deleting on-disk state. |
| T-L6 | A transparent-only recovery reports a balance that silently excludes shielded pools | M | ✅ | Transparent-only recovery bypasses the wallet database entirely (`transparent_recovery.rs`), so it covers exactly one pool. A wallet also holding Sapling or Sprout keys prints an explicit warning naming each uncovered pool and the count of keys in it, before any balance is shown. The risk being mitigated is not disclosure but *misplaced confidence*: a user who reads a partial total as complete may delete the wallet file that holds the only copy of the keys for the pools never scanned. Covered by `crates/zeck-cli/tests/wallet_file_cli.rs`. |
| T-L5 | Imported wallet-file key material persists on disk beyond what the seed flow already writes | M | ✅ | Imported key material enters the workspace only in the forms `zcash_client_sqlite` already persists for seed-derived keys (FVKs/IVKs, notes, witnesses) — import adds no new on-disk representation. Imported workspaces are keyed on a `KeySourceFingerprint` derived from hashes of the key material, not the material itself, so the resume path and directory naming do not expose spending keys the way a naive cache-by-key scheme would. |
| T-L7 | A resumable Sprout scan leaves spend-capable material on disk | H | ⚠️ | The checkpoint necessarily contains raw Sprout spending keys, note plaintexts, and witnesses so a multi-hour scan can resume. It is created atomically with `0600` mode on Unix and a filename containing only a truncated key-set fingerprint, never the key. Argos deletes it after a successful sweep; an interrupted scan or scan-only run leaves it behind by design. Same-account malware, backups, swap, and forensic recovery remain host-level residuals. |
| T-L8 | A crafted `wallet.dat` reports a phantom Sprout balance | M | ⚠️ | Wallet-backed note recovery verifies internal key/address/note/witness consistency, but every input to that check comes from the file; it cannot prove the JoinSplit was mined. Consensus rejects a fabricated sweep, so funds cannot be stolen through this claim, but the pre-broadcast balance is not authoritative. The full-block Sprout scan derives notes and nullifiers from the validated chain and does not share this limitation. |

### 6.5 Build, release, distribution

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-B1 | Compromised cargo dependency injects code at build time | H | ✅ | We pin via `Cargo.lock`. CI runs `cargo check` + `clippy` + tests + `cargo deny check advisories bans licenses sources` (with `yanked = "deny"`) + `cargo vet --locked` against an audit set imported from librustzcash and the federated Mozilla/Google/Embark/Bytecode Alliance/Fermyon/ISRG databases (T-SC1, PR #70). New `cargo update` resolutions that touch a non-vetted crate surface as a `cargo vet` failure rather than slipping in. |
| T-B2 | Compromised GitHub Actions secret signs a malicious release | C | ✅ | Signing and publish jobs are gated on protected environments (PR #48) with required-reviewer approval; the workflow itself only runs on `v*` tags. Maintainers should keep environment branch/tag restrictions enabled in repo settings, but reviewer approval is the active gate if that setting is absent. macOS signing uses Apple Developer ID secrets. Windows signing stores **no secret at all** — the key is held in Azure Trusted Signing and the runner authenticates via short-lived OIDC scoped to the `release-sign` environment (PR #96), shrinking the stealable-secret surface for Windows to nothing. |
| T-B3 | Windows installer is unsigned | H | ✅ | Resolved (PR #96). Windows installers (MSI + NSIS) **and** the inner `Argos.exe` are code-signed during the build via **Azure Trusted Signing** under the Iqlusion Inc organization identity, gated through the same required-reviewer `release-sign` environment as macOS. Authentication is OIDC (no stored signing secret). Users can additionally verify the SHA256 checksum (T-B4) and the SLSA Level 3 build-provenance attestation (T-SC6) via `gh attestation verify`. |
| T-B4 | Installer tampered with after publish | M | ✅ | SHA256 checksums are published alongside each artifact (deduplicated via PR #47/#48). README directs Windows users to verify the checksum before running the installer. |
| T-B5 | Marketing site (sovright.com / Vercel preview) ships a different binary than the release page | L | ✅ | The site does not host binaries; download links point at `github.com/sovright/argos/releases`. |

### 6.6 Supply chain integrity

Almost all of the executable code in a released Argos binary comes from third-party crates (618 in `Cargo.lock`), and a compromise anywhere in that tree, in the build toolchain, or in CI is the single highest-impact attack class against this project. The threats below are listed separately from §6.5 because the mitigations differ: §6.5 is about *our* build and release pipeline, while §6.6 is about the integrity of the inputs that flow into it.

The high-level posture is: **we adopted the practices the rest of the Zcash Rust ecosystem already follows.** `librustzcash`, `zebrad`, and the Zcash mobile SDKs have collectively converged on `cargo-deny` (advisories + licenses + bans + sources), `cargo-vet` (per-crate third-party audits), `zizmor` (GitHub Actions security analysis), uniformly SHA-pinned Actions, and least-privilege workflow `permissions:`. Argos now does the same — see §6.6.3 for what we took from each upstream and §6.6.4 for how much of our tree is shared with those upstreams (≈73%). The remaining residue lives in items the comparison shows are inherent to our distribution model (T-SC6 reproducible builds) or to upstream constraints out of our hands (T-SC4 toolchain, T-SC2 maintainer takeover).

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-SC1 | Malicious `build.rs` script or procedural macro in a transitive crate runs arbitrary code at compile time (dev machine and CI). | H | ⚠️ | `cargo-vet` gates every transitive crate: each must be covered by an imported upstream audit (from the librustzcash + Mozilla + Google + Embark + Bytecode Alliance + Fermyon + ISRG sets), a trusted-publisher entry, or an explicit `[[exemptions.*]]` entry in `supply-chain/config.toml`, or CI fails (PR #70). Most of the tree is exemptions ("trust but not yet audited") or publisher-trust, **not** first-party code audits — the imported audits cover only the subset of the tree we share with librustzcash. Any new resolution that adds an uncovered crate fails CI. Geiger-style `build.rs` enumeration is not yet adopted; that residue remains. The un-reviewed surface is concentrated in the Tauri stack (§6.6.4 / §7 category 2). |
| T-SC2 | Maintainer-account takeover on a critical crate (librustzcash family, `rustls`, `tauri`, `secrecy`, `secp256k1`, `bip0039`) ships a malicious version that we knowingly bump to. | H | ⚠️ | `cargo-deny` (T-B1) cannot detect a zero-day at bump time, but `cargo-vet` (T-SC1) requires every new resolution be either covered by an imported audit set or explicitly exempted, which surfaces an unexpected crate-version change as a CI failure with a named-auditor accountability trail. Project policy in `CLAUDE.md` requires conservative dependency review; the README/threat model document who maintains the high-value crates (§7). Formalising the diff-review checklist for `cargo update` is still open (§8). |
| T-SC3 | A third-party GitHub Action used in CI gets a tag force-moved (or a branch hijacked) to point at malicious code, which then runs with `GITHUB_TOKEN` or signing-environment access. | H | ✅ | Every third-party Action is now SHA-pinned with a `# vX.Y.Z` trailing comment (see PR #70), and the repository-level **Actions → Require SHA pinning for third-party Actions** setting is enabled (T-SC10), so a workflow that regresses to a tag pin is refused at job-start time. Signing/publish steps remain gated on protected environments (T-B2). |
| T-SC4 | Compromise of the upstream Rust toolchain (rustc / cargo) injects code into produced binaries. | M | ⚠️ | Toolchain version is pinned in CI (Rust 1.88). We rely on rust-lang's release signing and distribution; we do not independently verify toolchain hashes. Out of practical reach for this project; tracked rather than mitigated. |
| T-SC5 | A transitive crate is yanked from crates.io with no upstream replacement, so a freshly-resolved build cannot reproduce. | L | ✅ | `deny.toml` sets `yanked = "deny"`, so CI fails on any yanked crate in the lockfile. Made tractable by PR #69, which bumped the librustzcash family to the 2026-04 release wave that replaced the formerly-yanked `core2 0.3.3` with `corez 0.1.1` throughout the tree. Future yanks are now hard CI failures requiring an upstream-or-replace fix. |
| T-SC6 | The published release binary cannot be independently verified to correspond to the source tree at the tagged commit — i.e. no reproducible builds and no SLSA provenance attestation. | M | ❌ | SHA256 checksums (T-B4) and platform code-signing (T-B2) prove the binary was produced by our release pipeline, but not that the pipeline built the source faithfully. A verifier with the source cannot today rebuild bit-for-bit. Tracked. |
| T-SC7 | A new direct dependency we add is a typosquat or dependency-confusion package masquerading as a legitimate crate. | M | ✅ | Project policy in `CLAUDE.md` requires explicit approval and an `~/.claude/approved-dependencies.md` entry before any new direct dependency is added, with package name, version, adoption signals, maintenance status, and license recorded. This relies on review discipline, not tooling, and is therefore a process control rather than a hard gate. |
| T-SC8 | `cargo update` silently pulls a malicious patch release within the semver range allowed by `Cargo.toml` between manual review windows. | M | ✅ | `Cargo.lock` is committed and version updates require a commit; CI runs against the lockfile. Auto-update bots (Dependabot/Renovate) are intentionally **not** configured, so dependency bumps are always human-driven and reviewable as a diff. |
| T-SC9 | A pull request from a fork (external contributor) triggers our CI workflows, gaining `GITHUB_TOKEN` access and running attacker-controlled code on our runners — used either to exfiltrate via cache writes / artifacts / logs, or to consume CI minutes. | H | ✅ | Repository setting **Actions → Approval for running fork pull request workflows from contributors** set to `all_external_contributors` (verified via `gh api repos/.../actions/permissions/fork-pr-contributor-approval`). Every PR from a fork now requires explicit maintainer approval before any workflow runs. Combined with the protected `release-sign` / `release-publish` environments (T-B2), a fork PR cannot reach signing material even on approval. |
| T-SC10 | A future workflow change reintroduces a tag- or branch-pinned third-party Action (e.g. `actions/checkout@v4`), regressing the SHA-pin posture (T-SC3) silently between reviews. | M | ✅ | Repository setting **Actions → Require SHA pinning for third-party Actions** is enabled (verified via `gh api repos/.../actions/permissions` → `sha_pinning_required: true`). Workflow runs that reference a non-SHA-pinned third-party Action are refused by GitHub at job-start time, so a regression would surface as a CI failure rather than slipping in. |

**Combined effect after the §6.6.3 adoption.** We have strong reproducibility of *what we build today* (lockfile + pinned toolchain + SHA-pinned + repo-enforced Actions), per-crate `cargo-vet` gating across the whole tree — imported upstream audits cover the crates we share with the rest of the Zcash Rust ecosystem, while the rest are carried as trusted-publisher entries or exemptions (T-SC1) — and platform-level gates against fork-PR exfiltration (T-SC9) and SHA-pin regression (T-SC10). The two structural gaps that remain are T-SC4 (upstream Rust toolchain compromise — out of practical reach for a project this size) and T-SC6 (no reproducible builds / SLSA provenance attestation — a real gap, tracked). On the dependency-tree integrity side, the 565 `cargo-vet` exemptions are concentrated in the Tauri stack (§6.6.4); shrinking that further is structurally hard and tracked rather than blocked on.

#### 6.6.1 Comparison with zebrad and ZODL

Argos shares the librustzcash dependency core with two other production Zcash projects, but with different distribution models and supply-chain postures. Honest comparison:

| Practice | Argos (after PR #70) | zebrad (ZcashFoundation/zebra) | ZODL iOS / Android (zodl-inc) |
|---|---|---|---|
| Rust dependency gate in CI | `cargo-deny check advisories bans licenses sources` **and** `cargo-vet --locked` | `cargo-deny` covering advisories, licenses, multiple-versions, wildcards, bans, and sources | n/a — Rust enters as a built artifact via the Zcash mobile SDKs, not compiled directly |
| Yanked-crate policy | `yanked = "deny"` in `deny.toml` — CI **fails** on any yanked dep (T-SC5 ✅; enabled by the librustzcash 2026-04 bump in PR #69) | `yanked = "deny"` in `deny.toml` | n/a |
| Third-party Action pinning | Every Action SHA-pinned with `# vX.Y.Z` trailing comment; repo-level `sha_pinning_required: true` refuses regressions at job-start time (T-SC3 ✅, T-SC10 ✅) | `EmbarkStudios/cargo-deny-action` pinned to a 40-char commit SHA with the tag in a trailing comment (others mostly tag-pinned) | Mobile builds use Fastlane + platform CI; out of this comparison |
| Dependency-update bot | Intentionally **none**; bumps are human-driven and reviewable as a diff (T-SC8 ✅) | Dependabot present (`.github/dependabot.yml`) — auto-PRs are filed and gated through review + the `cargo-deny` job | Gradle lockfile on Android (`buildscript-gradle.lockfile`); SwiftPM on iOS |
| Fork-PR CI gate | Repo setting `fork-pr-contributor-approval: all_external_contributors` — every external PR requires maintainer approval before workflows run (T-SC9 ✅) | First-time-contributors approval | Mobile CI is internal-only |
| Lockfile commitment | `Cargo.lock` committed | `Cargo.lock` committed | `buildscript-gradle.lockfile` (Android); `Package.resolved` (iOS) |
| Release binary integrity | SHA256 checksums + macOS code-signing (Apple Developer ID) + Windows code-signing (Azure Trusted Signing, T-B3); SLSA Level 3 provenance attestation per-release (T-SC6) | Docker images on GitHub Packages + binary releases; relies on GitHub release artifact hosting + Docker pull verification; no SLSA provenance | **App Store / Play Store** distribution — binary integrity is delegated to Apple/Google platform signing; users do not run unsigned binaries |
| Security disclosure | `security@sovright.com`, plain email (PGP intentionally not offered for v0.1.0-rc) | `security@zfnd.org` with a published PGP key; follows the RD-Crypto-Spec responsible-disclosure standard | `responsible_disclosure.md` published in repo with their process |

**What we took from zebrad.** `cargo-deny` modelled on their `deny.toml`, `yanked = "deny"` as a hard CI gate, SHA-pinning third-party Actions to commit hashes with version comments. This subsumes our former `cargo audit` job (advisories + licenses + bans + sources all in one tool) and surfaces yanked transitive crates as failures rather than warnings.

**What we took from `librustzcash` / the Zcash mobile SDKs.** `cargo-vet` with imports from the same federated audit sets `librustzcash` maintains (Bytecode Alliance, Embark, Fermyon, Google, ISRG, Mozilla, Zcash itself); `zizmor` on `.github/workflows/`; least-privilege workflow `permissions: {}` with per-job grants + `persist-credentials: false` on every `actions/checkout`. The `[imports.zcash]` line in `supply-chain/config.toml` is the leverage — it covers ~148 crates of our shared tree for free.

**What does not transfer from ZODL.** ZODL mobile delegates binary-integrity to App Store / Play Store signing and review. Argos ships standalone binaries directly from GitHub Releases on three platforms, so we cannot offload that step the way ZODL can. The integrity guarantees in §6.5 (T-B2/T-B3/T-B4) and the provenance gap in T-SC6 exist because we are not in the mobile-store model — a structural difference, not a posture gap.

**Where we currently match or exceed both upstreams.** No JavaScript runtime dependencies (§7) is a stronger position than either project: zebrad has no JS, ZODL has the full native-mobile dependency surface, and we deliberately ship zero npm packages in the bundle (PR #50). The conservative dependency-bump policy in `CLAUDE.md` is a process control neither upstream documents. Repo-enforced SHA pinning (T-SC10) is a defence-in-depth gate not yet present in either upstream's settings.

**Where we remain behind.** No PGP disclosure key (a v0.1.0+1 decision; see T-SC2 in §8), and no SLSA provenance attestation for the published binaries (T-SC6).

#### 6.6.2 librustzcash and the Zcash mobile Rust SDKs

The ZODL comparison in §6.6.1 stops at the mobile app, but Argos and ZODL share the *same* upstream Rust core — the librustzcash workspace at `zcash/librustzcash` (now ZODL-maintained per `MEMORY.md`). The Zcash mobile Rust SDKs at `zcash/zcash-android-wallet-sdk` (Kotlin) and `zcash/zcash-swift-wallet-sdk` (Swift) **embed librustzcash as an in-tree Rust submodule** and build it into the platform binding (`backend-lib/` on Android, a `rust/` directory + `Cargo.lock` + `Package.resolved` on iOS). Argos consumes the same crates from crates.io. The dependency graph that flows into a built Argos binary, a built ZODL iOS binary, and a built ZODL Android binary therefore shares its largest single chunk.

The posture of that shared upstream is markedly stronger than ours, zebrad's, or the mobile apps' own platform layer:

| Practice | Argos (today) | zebrad | librustzcash | Zcash mobile SDKs |
|---|---|---|---|---|
| Per-crate code audit (third-party crate review, not just advisories) | **none** | none (advisories only via `cargo-deny`) | **`cargo-vet`** with imports from Bytecode Alliance, Embark, Fermyon, Google, ISRG (libprio), Mozilla, and Zcash's own audit set; custom criteria including `crypto-reviewed` and `license-reviewed`; named human auditors per delta (`who = "Kris Nuttycombe <kris@nutty.land>"`, `Daira-Emma Hopwood`, etc.) | Inherit librustzcash's audits transitively because they embed the same workspace |
| License gate | none (we plan `cargo-deny`) | `cargo-deny check licenses` (broad allow-list) | `cargo-deny check licenses` with `allow = ["Apache-2.0", "MIT"]` only — every other SPDX is named per-crate as an exception. Strictest in the comparison. | Inherit librustzcash's `deny.toml` for the embedded Rust workspace |
| Multi-target dependency graph vetting | n/a (one target per platform) | single target | `[graph] targets` enumerates 14 triples (Linux/macOS/Windows/iOS/Android/FreeBSD) so the dep tree is vetted under every consumer's build configuration | Inherited |
| GitHub Actions security analysis | none | none | **`zizmor`** (`zizmor-action`) on every push and PR, with `permissions: {}` at the workflow top level and `persist-credentials: false` on checkout — least-privilege workflows | The Swift SDK also runs `zizmor` + `codeql` on its workflows |
| Action pin form | most tag-pinned, one (`dtolnay/rust-toolchain@master`) on a branch | tag-pinned with one SHA pin (`cargo-deny-action`) | **SHA-pinned with version comment** for every third-party Action (e.g. `actions/checkout@de0fac2…f5447ce83dd # v6.0.2`, `EmbarkStudios/cargo-deny-action@6c8f9fa…b7b7777d1 # v2.0.18`) — the practice T-SC3 calls for | Same SHA-pin pattern |
| Mutation / quality posture adjacent to supply chain | none | none | **`cargo-mutants`** in CI (`mutants.yml`) — separate goal but raises the bar for any malicious code change going undetected | Inherits the Rust core; platform-side test suites separate |
| Disclosure | plain `security@sovright.com`, no PGP for v0.1.0-rc | PGP-keyed (`zfnd.org`), follows RD-Crypto-Spec | inherits ECC / ZODL process | PGP-keyed (`security@z.cash`), follows RD-Crypto-Spec |

The honest takeaway: the upstream Rust supply chain we consume is auditing itself more rigorously than we audit our consumption of it.

#### 6.6.3 What Argos adopted from each

Recorded in the order the items landed. Each maps onto a `T-SC*` row in §6.6 and a check-marked entry in §8.

**From `zebrad` — the practical foundation.**

1. **`cargo-deny` with a checked-in `deny.toml`** (PR #70, T-B1 / T-SC1 part 1). Consolidates advisories + licenses + bans + sources into one CI job; replaced the former `cargo audit` job. License allow-list trimmed to identifiers actually present in the tree; an `openssl-sys` ban catches dep regressions away from `rustls`; `multiple-versions = "warn"` rather than `"deny"` because the Tauri + librustzcash stack has known semver duplicates worth tracking but not yet blocking.
2. **`yanked = "deny"`** (PR #69 then PR #70, T-SC5). zebrad runs this as a hard gate; we could not until the librustzcash 2026-04 release wave (PR #69) replaced the yanked `core2 0.3.3` with `corez 0.1.1` throughout the tree.

**From `librustzcash` and the Zcash mobile SDKs — the highest-leverage items.**

3. **`cargo-vet` with imports from `librustzcash`'s audit set** (PR #70, T-SC1 part 2). `supply-chain/config.toml` lists `[imports.zcash]` plus the same federated imports `librustzcash` already curates (Bytecode Alliance, Embark, Fermyon, Google, ISRG, Mozilla). Result at adoption: `cargo-vet` reported 142 fully audited + 6 partial + 565 exempted out of 618 transitive crates — that "fully audited" count is entirely imported upstream audits (we contribute no first-party crate audits of our own); those imports cover 148 crates of the shared tree (§6.6.4) for free.
4. **`zizmor` on `.github/workflows/`** (PR #70, T-SC1b). Catches Actions-supply-chain misconfigurations (overly broad `permissions:`, persistent credentials, command injection via untrusted GitHub event payloads). Mirrors `librustzcash` and `zcash/zcash-swift-wallet-sdk`.
5. **SHA-pin every third-party Action with a `# vX.Y.Z` trailing comment** (PR #70, T-SC3). Replaced `dtolnay/rust-toolchain@master` and the `@v4` / `@v2` tags on everything else with 40-character commit SHAs.
6. **Least-privilege workflows** (PR #70). Top-level `permissions: {}` on both `ci.yml` and `release.yml`, with per-job grants only as needed; `persist-credentials: false` on every `actions/checkout` step.

**Beyond what either upstream does — repository-level enforcement.**

7. **Fork-PR contributor approval set to `all_external_contributors`** (T-SC9 ✅). Every fork PR requires explicit maintainer approval before any workflow runs; closes the fork-PR CI / cache exfiltration / CI-minutes-burning attack class.
8. **`sha_pinning_required` enabled at the repo level** (T-SC10 ✅). GitHub refuses to start any job that references a non-SHA-pinned third-party Action — locks in T-SC3 against future regressions at the platform layer.

**Still open.**

- **PGP-keyed responsible disclosure** — both mobile SDKs and `zebrad` publish a PGP key and follow the RD-Crypto-Spec standard. Argos explicitly dropped PGP for v0.1.0-rc (commit `3406c83`); revisit once we have a security mailing address with a steward.
- **SLSA provenance attestation** (T-SC6) — neither structural to upstream nor blocked on it; tracked in §8 as the largest remaining gap.

#### 6.6.4 How much of our dependency surface actually diverges?

The §6.6.1–6.6.3 record of what we adopted from each upstream rests on a quantitative claim: that the value of inheriting an upstream's audit posture depends on how much of our tree they actually cover. This subsection measures it.

Comparing `Cargo.lock` crate sets (verified 2026-05-27 against `ZcashFoundation/zebra` and `zcash/librustzcash` `main`):

| Set | Crates |
|---|---|
| Argos total | 618 |
| Shared with librustzcash | 364 (59%) |
| Shared with zebra | 423 (68%) |
| Shared with **either** upstream | **452 (73%)** |
| Unique to Argos (in neither) | **166 (27%)** |

So **73% of Argos's dependency surface is already exercised — and in librustzcash's case, audited — by an upstream Zcash project**. Adopting `cargo-vet` with `[imports.zcash]` (T-SC1, §6.6.3) captures that majority for free.

The 27% that diverges is overwhelmingly **the Tauri desktop-GUI stack**, broken down roughly as:

- **~52+ crates** in the Tauri / WebView / GTK3 stack: `tauri`, `wry`, the full `gtk-rs` family (`gtk`/`gdk`/`atk`/`gio`/`glib`/`gobject-sys`/`gtk3-macros`/`gdkwayland-sys`/`gdkx11`), `cairo-rs` + `cairo-sys-rs`, `webkit2gtk-*`, `javascriptcore-rs`, `core-graphics`, `cocoa`/`objc` (macOS), `libappindicator`, `embed_plist` (macOS bundling), `embed-resource` (Windows), `kuchikiki` + `html5ever` + `cssparser` + `selectors` (HTML/CSS Tauri uses internally), `keyboard-types`, `dpi`, `cookie`, `ico`, `infer`, `json-patch`.
- **~15 crates** in the `smol`/`async-std` runtime adjacent to Tauri's internal IPC — `async-broadcast`, `async-channel`, `async-executor`, `async-io`, `async-lock`, `async-process`, `async-signal`, `async-task`, `blocking`, `event-listener-strategy`, `futures-lite`, etc. — pulled by Tauri even though our application code uses `tokio`.
- **A handful of CLI helpers** unique to us: `dialoguer`, `keepawake`.
- **The remainder** (~95 crates): compression (`brotli`, `brotli-decompressor`, `fdeflate`), HTML/text helpers (`dom_query`, `futf`, `cesu8`), build-tooling adjacent (`cargo_toml`, `cfg-expr`, `cfb`, `ctor`, `ico`, `infer`), Unicode/i18n (`icu_locale_core`), and miscellaneous utility crates.

This is the same set the categorization in §7 calls *category 2* (the Tauri desktop-GUI stack), and it overlaps almost perfectly with the unmaintained-crate ignores in `deny.toml` (RUSTSEC-2024-0411..0420, 2025-0080, 2025-0081, 2025-0100) — those are exactly the gtk-rs GTK3 transitive set Tauri pulls in.

**Practical implications:**

1. The 73% we share is well-trodden ground. Bumps to that part of the tree carry low novel risk because both upstreams exercise it and librustzcash audits it.
2. The 27% that's ours alone is where new supply-chain risk concentrates. Future first-party `cargo-vet` audits should focus here first; importing more federated audit sets (Mozilla / Google / Embark already in §6.6.3's plan) covers some of the async-runtime tail but is light on the gtk-rs family.
3. Shrinking the divergence meaningfully requires one of: (a) Tauri upstream migrating to GTK4 (out of our hands; an upstream-scale change), (b) finding an audit source that targets the desktop-GUI stack specifically (none in our current import set does), or (c) first-party audits of the Tauri tree, which is real effort.

The honest framing: T-SC1's `cargo-vet` adoption gives us large coverage cheaply; the remaining work to drive exemptions toward zero is concentrated in a single, structurally hard-to-audit subsystem.

## 7. Dependency posture

Argos's dependency tree is best summarised as **three categories**, in roughly the order they contribute to attack surface:

1. **The librustzcash + Zcash ecosystem core that we share with `zebrad` and `ZODL`** — the librustzcash family (`zcash_client_backend`, `zcash_client_sqlite`, `zcash_keys`, `zcash_protocol`, `zcash_primitives`, `zcash_transparent`, `sapling-crypto`, `orchard`), maintained by ZODL (formerly the ECC mobile team); the cryptographic primitives they pull (`bls12_381`, `pasta_curves`, `halo2`, `equihash`, `secp256k1`); `secrecy` for key handling; `rustls` with the `ring` provider and no `aws-lc-sys` (PR #54) for TLS; `tonic` + `prost` + `tokio` for the gRPC lightwalletd client. This category is roughly the same set of crates that `zebrad` and `ZODL` consume — quantified in §6.6.4, **452 of our 618 lockfile crates (73%) are shared with either upstream**, and the librustzcash maintainers maintain `cargo-vet` audits for the crates they publish.

2. **The Tauri desktop-GUI stack** — `tauri` itself; `wry` (cross-platform WebView bindings); the `gtk-rs` family on Linux (`gtk`/`gdk`/`atk`/`gio`/`glib`/`gobject-sys`/`gtk3-macros`/`gdkwayland-sys`/`gdkx11` + their `*-sys` companions); `cairo-rs` + `cairo-sys-rs`; `webkit2gtk-*` + `javascriptcore-rs` on Linux, `core-graphics`/`cocoa`/`objc` on macOS, `embed_plist` for macOS bundling, `embed-resource` for Windows; the HTML/CSS parsing crates Tauri uses internally (`kuchikiki`, `html5ever`, `cssparser`, `selectors`); plus the smol-family async runtime Tauri's IPC pulls in (`async-channel`, `async-io`, `async-lock`, `blocking`, `futures-lite`). This is essentially all of the **~166 crates unique to Argos's tree** (§6.6.4) — neither `zebrad` nor `ZODL` consume it, and it dominates the unmaintained-crate advisory ignores in `deny.toml` (the RUSTSEC-2024-0411..0420 / 2025-0080 / 2025-0081 GTK3 family).

3. **Project-specific helpers for the recovery workflow.** A small tail: `keepawake` to hold a power-management guard so the OS doesn't sleep mid-scan (recovery scans of older wallets routinely run for hours); `bip0039` for the seed phrase; `clap` + `dialoguer` + `indicatif` for the CLI; `rusqlite` for the workspace database. `keepawake` in particular is unique to our long-scan use case — `zebrad` runs as a server and `ZODL` is a foreground app, so neither needs it.

JavaScript dependencies: **none at runtime**. The Tauri GUI ships zero npm packages in the browser bundle (PR #50).

**Tooling for the integrity of these inputs.** CI runs three gates against every push and PR, all modelled on the practices librustzcash and `zebrad` already use (see §6.6 for the comparison and §6.6.3 for what we adopted from each):

- `cargo deny check advisories bans licenses sources` (T-B1, T-SC1 part 1) — replaces the previous `cargo audit` job. Configuration lives in `deny.toml`; the carry-over advisory ignores for the GTK3 / Tauri stack and the `time` 0.3.x DoS sit there. `yanked = "deny"` is in force.
- `cargo vet --locked` (T-SC1 part 2) — third-party crate audits, with `supply-chain/config.toml` importing the same audit sets librustzcash maintains: Bytecode Alliance, Embark, Fermyon, Google, ISRG, Mozilla, and Zcash itself. Initial state at adoption: `cargo-vet` reported 142 fully audited + 6 partial + 565 exempted (the "fully audited" figure is imported upstream audits, not first-party review); the exemptions are concentrated in category 2 (the Tauri stack).
- `zizmor` (T-SC1b) on `.github/workflows/` — catches Actions-supply-chain misconfigurations (overly broad `permissions:` blocks, persistent credentials, command injection via untrusted GitHub event payloads). Mirrors librustzcash and `zcash/zcash-swift-wallet-sdk`.

Plus two repository-level gates (T-SC9, T-SC10): every fork PR requires maintainer approval before workflows run, and any workflow that references a non-SHA-pinned third-party Action is refused by GitHub at job-start time.

For the full threat enumeration of supply-chain integrity see §6.6, the cross-project posture comparison see §6.6.1–§6.6.2, the adoption summary see §6.6.3, and the divergence quantification see §6.6.4.

## 8. Open issues and known gaps

These are intentionally listed in one place so the document drives a backlog rather than just describing the world:

- [x] **T-S2** — strip the seed from `state.scanConfig` in the GUI (PR #53 follow-up).
- [ ] **T-N2** — pin the certificate of `zec.rocks` / `na.zec.rocks` for the default endpoints.
- [ ] **T-N5** — surface the auto-detect privacy implication more loudly in the UI.
- [x] **T-L3** — add a "Delete workspace" action that securely wipes a session post-recovery.
- [x] **T-B1** — gate CI on advisories (originally `cargo audit`; upgraded to `cargo-deny check advisories bans licenses sources` + `cargo-vet --locked` in PR #70).
- [x] **T-B3** — Windows code-signing landed via **Azure Trusted Signing** under the Iqlusion Inc organization identity (PR #96). Signing runs in the same protected `release-sign` environment as macOS, authenticated by OIDC with no stored signing secret; it signs the inner `Argos.exe` and the MSI/NSIS installers during the build. See `RELEASE_SIGNING.md`.
- [x] **T-SC1** — adopt `cargo-deny` + `cargo-vet` with `[imports.zcash]` and the federated audit sets librustzcash already pulls (PR #70). Geiger-style `build.rs` enumeration / sandboxing remains a separate item if we want to tighten further.
- [x] **T-SC1b** — adopt `zizmor` (`zizmorcore/zizmor-action`) on `.github/workflows/` (PR #70).
- [ ] **T-SC2** — formalize a dependency-bump review checklist (diff the changelog, scan for new `build.rs` / network calls / proc macros) and record sign-off in the PR. `cargo-vet` now catches new untrusted resolutions automatically; the checklist would tighten the human-review side around bumps to crates *already exempted*.
- [x] **T-SC3** — SHA-pin every third-party GitHub Action with a `# vX.Y.Z` trailing comment (PR #70) and enforce at the repo level (T-SC10).
- [~] **T-SC6** — SLSA Level 3 build-provenance attestations now published for every release artifact via the first-party `actions/attest-build-provenance` (verify with `gh attestation verify`). Reproducible (bit-for-bit) builds remain open and are the larger remaining gap. (Originally provisioned via `slsa-github-generator`, replaced because that reusable workflow internally uses tag-pinned actions, incompatible with the `sha_pinning_required` policy from T-SC10.)
- [x] **T-SC9** — set repository `fork-pr-contributor-approval` to `all_external_contributors` so every fork PR requires maintainer approval before workflows run.
- [x] **T-SC10** — enable repository `sha_pinning_required` so workflows referencing a non-SHA-pinned Action are refused at job-start time.

## 9. Out of scope

- Host OS compromise (root/admin malware).
- Side-channel attacks (cache, EM, power).
- Physical attacks on the user's machine (cold-boot, evil maid).
- Quantum-cryptographic attacks against Sapling/Orchard.
- User coercion / duress.
- Deriving Sprout keys from a ZecWallet Lite seed. Those keys were generated independently and do not exist in the HD seed tree. Sprout recovery itself is implemented end to end when the user supplies a zcashd `wallet.dat` or standalone Sprout spending key.
- Moving Sprout directly to Orchard. A Sprout JoinSplit exists only in transaction version 4 while Orchard actions require version 5. Argos lands the value in the user's Sapling receiver; any Sapling-to-Orchard hop belongs to the user's destination wallet so Argos never holds an intermediate key.

## 10. Reporting a security issue

Please **do not** open a public GitHub issue for a security vulnerability. Email `security@sovright.com` with a description and reproduction steps; we will respond within five business days. No PGP key is available at this time. Plain email is sufficient for v0.1.0-rc.

## 11. Revision history

| Date | Author | Notes |
|---|---|---|
| 2026-08-26 | Codex | Updated the model for standalone Sapling/Sprout keys, imported Sapling sweeping, generally available Sprout recovery, the full-block P2P trust relationship, spend-capable Sprout checkpoints, and wallet-file phantom-balance limits. |
| 2026-05-13 | Kristi | Correct T-L1 status (permissions implemented); fix CSP quote; clarify T-N4 address count; PGP note. |
| 2026-05-19 | Zaki | Initial draft. Covers v0.1.0-rc. Open items listed in §8. |
| 2026-05-27 | Zaki | Added §6.6 Supply chain integrity (T-SC1..T-SC8), §6.6.1 cross-project posture comparison (zebrad + ZODL), §6.6.2 extending to librustzcash and the Zcash mobile Rust SDKs (documenting their `cargo-vet` posture with federated audits from Bytecode Alliance / Embark / Fermyon / Google / ISRG / Mozilla, `zizmor` on workflows, uniformly SHA-pinned Actions), §6.6.3 adoption plan, and §6.6.4 quantifying dependency-surface divergence: 452/618 (73%) of our crates are shared with zebra or librustzcash; the 166 unique to Argos are essentially the Tauri desktop-GUI stack. |
| 2026-05-28 | Zaki | Added T-SC9 (fork-PR CI execution) and T-SC10 (SHA-pin regression), both ✅ via repository-level Actions settings (`fork-pr-contributor-approval: all_external_contributors`, `sha_pinning_required: true`). T-SC3 upgraded ⚠️→✅ on the back of T-SC10. |
| 2026-05-28 | Zaki | Holistic pass after PRs #69 (librustzcash 2026-04 bump) and #70 (cargo-deny + cargo-vet + zizmor + SHA-pin Actions + least-privilege workflows): rewrote §7 to lead with the three-category framing (librustzcash + Zcash ecosystem shared with zebrad/ZODL; Tauri desktop-GUI stack; project-specific helpers including `keepawake` for long scans); reframed §6.6 + §6.6.3 from prospective adoption plan to retrospective record of what we took from each upstream; updated T-B1 / T-SC1 / T-SC2 / T-SC5 statuses to reflect the new tooling; refreshed §6.6.1 comparison table to the post-#70 state; updated §8 backlog (T-SC1 / T-SC1b / T-SC3 / T-SC9 / T-SC10 now ✅; T-SC6 named as the largest remaining supply-chain gap). |
| 2026-05-28 | Zaki | T-B3 status moved ❌ → ⚠️: Windows code-signing certificate procurement is in progress. §4 build-pipeline trust boundary and §6.6.1 comparison-table release-binary row updated to reflect (a) Windows signing in progress, (b) SLSA Level 3 provenance attestation (T-SC6) coming via PR #71 as the third-party-verifiable source-to-binary chain in the interim. |
| 2026-05-29 | Zaki | T-B3 status moved ⚠️ → ✅ (PR #96): Windows code-signing landed via Azure Trusted Signing under the Iqlusion Inc organization identity. Signs the inner `Argos.exe` + MSI/NSIS installers during the build, in the protected `release-sign` environment, authenticated by OIDC with no stored signing secret (also tightening T-B2). Updated §0 at-a-glance, §4 build-pipeline boundary, T-B2/T-B3, §6.6.1 release-binary row, and §8 checklist. Runbook: `RELEASE_SIGNING.md`. |
| 2026-05-29 | Zaki | Migrated SLSA provenance from the `slsa-github-generator` reusable workflow to the first-party `actions/attest-build-provenance` (per-build-job, SHA-pinned). The generator was incompatible with the `sha_pinning_required` policy (T-SC10) because it internally calls tag-pinned actions, which silently broke provenance on every release. Updated §4 boundary, T-B3, T-SC6, and the README verification section (now `gh attestation verify` instead of `slsa-verifier` + `.intoto.jsonl`). |
| 2026-06-22 | Zaki | Least Authority audit clarifications (Suggestions 10–13), docs-only: added §1.1 separating the stable threat **model** (§2–§5, §9) from the point-in-time threat **assessment** (§0, §6–§8) and signposted §0 and §6 accordingly (S10); renamed §4 "Trust boundaries" → "Trust relationships" and reworded each entry to state the trust decision and its basis, notably the Argos ↔ lightwalletd relationship (S11); clarified the §5 threat-actor definitions and scope wording, and split the former "Hostile DNS / TLS-trust-store attacker" row into separate "Hostile DNS operator" and "WebPKI certificate validation" actors (S12); moved the recovery report above the compact-block cache in the §3 asset priority list (S13). No substantive change to the model. |
| 2026-06-26 | Zaki | Least Authority follow-up on §5 threat actors (docs-only): made **In scope?** a defined three-way verdict (Yes / Partial / No) instead of freeform "Partially …" prose, and normalized every row to it. Reclassified the mis-scoped rows — Hostile DNS operator ⟶ **Yes** (TLS defeats DNS-only substitution), WebPKI-compromise ⟶ **No** (no cert pinning; T-N2 is the tracked gap), in-process attacker ⟶ **No** (inside the trust boundary), Hostile lightwalletd ⟶ **Partial** (T-N3 mitigated, T-N4 metadata residual); split the former cross-account row into unprivileged (Yes, T-L1) vs privileged/OS-isolation-bug (No); reworded the dependency row to the `cargo-vet` *gate* framing (consistent with the audit-coverage cleanup the same day). No change to the model. |
| 2026-06-26 | Zaki | Docs-only: removed overclaims of audit coverage of our own dependency tree. `cargo-vet` is a per-crate gate (imported upstream audit, trusted-publisher entry, or explicit exemption — or CI fails), and the imported audits cover only the subset of the tree we share with librustzcash; we contribute no first-party crate audits. Reworded §0 at-a-glance, §6.6 intro, T-SC1, the §6.6 combined-effect summary, §6.6.3, and §7 accordingly; §6.6.4's shared-surface measurement is unchanged. No change to the model. |
| 2026-07-31 | Claude (Task 18) | Wallet file import (zcashd `wallet.dat`, ZecWallet Lite): added `argos-wallet-import` to §2.1 components and the file-input path to §2.2 data flow; added the wallet file as a new asset in §3 (higher-value than a seed for a zcashd user, because a seed cannot reconstruct standalone `z_importkey` material); added "a malicious wallet file" as a new threat-actor row in §5 — Argos previously accepted only a low-structure BIP-39 mnemonic, so an attacker-crafted binary is a genuinely new actor path, mitigated by crate isolation (no network, no filesystem writes, no dependency on `argos-core`), hostile-input hardening in the Berkeley DB walker, fuzzing, and re-deriving recovered keys against their stored addresses rather than trusting the parse; added T-S6 to §6.1 for the wallet passphrase, recording the GUI's plaintext-JSON Tauri IPC crossing as a new instance of accepted audit Issue A rather than silently inheriting the seed's justification; added T-L5 to §6.4 noting imported key material persists only in forms `zcash_client_sqlite` already writes, keyed by a `KeySourceFingerprint` rather than the key material itself. Narrowed the §9 Sprout out-of-scope statement: Argos can now recover Sprout spending keys from a `wallet.dat`, but spending them is not yet implemented, so Sprout funds are identified, not yet recoverable end to end; `README.md`'s equivalent line narrowed the same way. This is a model change, not assessment-only, because a genuinely new input class and threat actor were added. |
| 2026-08-01 | Claude | Corrected T-S6 (assessment-only, no model change): the previous entry described the wallet passphrase crossing the Tauri IPC boundary as a live exposure, but the GUI exposes no wallet-file entry point — import is CLI-only, where the passphrase is prompt-only and never crosses a process boundary. The IPC crossing is now recorded as a *future* instance of accepted audit Issue A rather than a current one, so the mitigation column describes what Argos actually does. Also names the prompt site (`crates/zeck-cli/src/main.rs`). |
| 2026-08-02 | Claude | Transparent-only recovery from a zcashd `wallet.dat` (assessment update, no change to the model's assets or actors): added T-L6 to §6.4 for the risk that a single-pool recovery is read as a complete one. The mechanism is new — transparent recovery deliberately bypasses the `zcash_client_sqlite` account model, because ZIP-316 forbids a transparent-only unified viewing key and such a wallet therefore cannot have an account (zcash/librustzcash#2582) — but the exposure is one of misplaced confidence rather than disclosure: a user who reads a transparent-only total as the whole wallet may discard the file holding the only copy of their Sapling or Sprout keys. Mitigated by naming every uncovered pool before any balance is displayed. Signing keys never leave process memory and no new on-disk artifact is created; the sweep writes nothing to the workspace. |
| 2026-08-03 | Claude | GUI wallet-file import (model change, not assessment-only): the GUI gained a wallet-file entry point, so the passphrase now crosses the Tauri IPC boundary as plaintext JSON. T-S6 previously stated the opposite and recorded the crossing as a future event; that prediction is now realised and the row describes what Argos actually does. The crossing is a deliberate new instance of accepted audit Issue A, not an inherited one. Two new commands carry the passphrase (`inspect_wallet_file`, `start_scan_from_wallet_file`); their input structs deliberately derive none of `Debug`, `Serialize`, or `Clone`, matching `ScanConfigInput`. Note what does *not* cross IPC: the wallet file's bytes. The frontend passes a path — obtained from Tauri's native drag-drop event or typed by the user — and the backend reads the file, so attacker-supplied binary input never transits the webview and the parser keeps its existing isolation. A native file picker was deliberately not added: it would require `tauri-plugin-dialog`, a new dependency. |
