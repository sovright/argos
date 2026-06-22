# Argos Threat Model

> **Status:** Initial draft, v0.1.0-rc. This document describes the security posture of Argos as of the v0.1.0 release candidate. It is a living document; revisit on every release and whenever a new attack surface is added.

## 0. At a glance

This section summarises the document for readers who don't have time for the full text. The detail lives in §1–§11 and is the source of truth. It is **assessment** content (the "Where we stand" column is a point-in-time judgement, per §1.1), not part of the stable threat model itself.

### If you're in a hurry

Argos is a single-use recovery tool. You give it a 24-word seed phrase, it scans the chain, it sweeps your funds into a modern wallet. The seed never leaves your machine, never touches disk, and only lives in memory for the length of the session. Everything else in this document is about *what could go wrong around that core promise* and how we bound the damage.

The five things most worth knowing:

| What | Severity | Where we stand |
|---|---|---|
| Seed phrase in memory or on disk | Critical | ✅ Wrapped in `secrecy::SecretString`, zeroized on drop, never written to disk. Residual: OS swap (we do not `mlock`). |
| Dependency / supply-chain compromise | High | ✅ ~73% of our Rust tree is shared with the upstream Zcash ecosystem (`librustzcash`). The Tauri-side residue is a separate supply-chain surface we view as acceptable on the same terms other Tauri apps accept it. The rest of the tree is covered by `cargo-deny` + `cargo-vet` audits and SLSA Level 3 build provenance. |
| Hostile lightwalletd | Medium–High | ✅ Crafted compact blocks are rejected by `librustzcash` sync; the server learns *that* you're scanning but no scanning-side keys are sent. |
| Windows installer authenticity | Medium | ✅ Both macOS (Apple Developer ID notarization) and Windows (Azure Trusted Signing under the Iqlusion Inc organization identity) installers are code-signed in the release pipeline (T-B3). SLSA Level 3 provenance (T-SC6) complements the signatures by anchoring each artifact to its source commit. |
| Clipboard residue after paste | Medium | ⚠️ Argos itself never writes the seed to the clipboard. If the user pastes their seed in, that exposure is theirs to manage. The GUI offers a "Clear clipboard" button — see T-S4. |

Where this puts us relative to neighbours: we ship the same `librustzcash` family that ZODL (formerly Zashi) and zebrad rely on, a Tauri stack that is the same residue any Tauri-based Zcash desktop app carries, and a CI posture (`cargo-deny`, `cargo-vet`, zizmor, SLSA Level 3) that is at or above what those projects have today. The detailed comparison is in §6.6 and §7.

### If you're not deep in security

Your seed phrase is the master key to your money. If anyone else gets it, they can move your funds. Argos handles your seed for a specific job: it reads the chain, finds your funds, and helps you sweep them somewhere safer. It doesn't store the seed, doesn't send it anywhere, and doesn't keep it after the app closes.

The honest version of "is this safe?" is: **all software has risk, and Argos is no exception.** Our review shows the risks are bounded if you set up your environment well. Specifically:

- **Match your effort to the amount you're recovering.** For small recoveries (under ~25 ZEC), running Argos on your everyday machine is reasonable as long as you trust it — modern operating systems isolate apps well enough for that. For larger amounts, the operational cost of a clean, dedicated machine starts being worth it: a spare laptop, a fresh OS install, or a live-USB system (Tails, a clean Ubuntu) limits the surface for problems we can't reach from inside Argos.
- Don't run Argos on a machine you suspect is already compromised, regardless of the amount. We can't protect a seed from malware that's already on your computer — no recovery tool can.
- Only download Argos from our official release page. Verify the code signature (macOS and Windows) and the SLSA provenance. We document how in the release notes.
- Sweep to a wallet you control and have backed up. The point of Argos is to move funds *out* of an old wallet you're not going to use again.

The risks we *can't* address from inside Argos — a compromised host, a coerced user ("$5 wrench attack") — are listed honestly in §9 (Out of scope) so you can decide what to do about them.

## 1. Purpose and scope

Argos is a single-use Zcash wallet **recovery** tool for ZecWallet Lite seeds. Its purpose is to take a 24-word BIP-39 seed phrase, scan the Zcash chain for funds derived under ZecWallet Lite's account layout, and sweep them to a modern wallet (ZODL, YWallet) in a single session. It is not an everyday wallet.

This threat model covers:

- the desktop GUI (Tauri v2: HTML/CSS/JS frontend in WebView2/WKWebView/WebKitGTK + Rust backend)
- the CLI (`argos-cli`)
- the shared core library (`argos-core`)
- the build / release / distribution pipeline (GitHub Actions, Vercel marketing site, signed installers)

It does **not** cover the security of the user's host operating system, the user's destination wallet, the lightwalletd nodes operated by third parties, or the Zcash consensus protocol itself.

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
| lightwalletd | Remote, over TLS gRPC | Go (third party) | Untrusted network peer |
| Local workspace (SQLite) | On disk | — | Same trust as the user's home directory |

### 2.2 Data flow

```
   user input (seed, destination, config)
            │
            ▼
   ┌──────────────────┐
   │  argos-gui  /  argos-cli                     │
   │   - SecretString-wrapped seed                │
   │   - BIP-39 → seed bytes (Secret<[u8;64]>)    │
   │   - ZIP-32/legacy-transparent derivation     │
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
```

## 3. Assets

In rough priority order:

1. **The 24-word seed phrase.** Sole authority to spend any funds derivable from it.
2. **Recovered ZEC.** Sweep transactions move value from the legacy ZWL accounts to the user's chosen destination.
3. **The destination unified address.** Privacy-sensitive linkage between the user and the recovered funds.
4. **Workspace contents.** Contains full viewing keys (FVKs), incoming viewing keys (IVKs), per-account note cache, witnesses, and historic balances. With FVKs alone an attacker cannot spend, but can fully reconstruct the wallet's transaction history.
5. **The recovery report.** Plaintext file written by the user with workspace path, txids, account labels, and net amounts. Contains much of the same information as the workspace contents above, and is more sensitive than the compact-block cache below.
6. **The shared compact-block cache.** Public chain data; not sensitive by itself, but the *set of heights present* leaks an upper bound on which wallets have been scanned on this host.

## 4. Trust relationships

Each entry below names two parties and states how much one trusts the other, and on what basis. (This section describes *relationships* between components, not the internal trust boundary of any single process — the per-process boundaries are in the §2.1 table.)

- **User ↔ host OS:** Argos fully trusts the host it runs on. This trust is unverified and unconditional: a compromised OS defeats every other mitigation in this document.
- **Tauri host process ↔ WebView renderer:** The host process does *not* trust the renderer with arbitrary access. The renderer can only reach the host via explicit `#[tauri::command]` handlers, and is itself constrained by the CSP in `gui/src-tauri/tauri.conf.json` (`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: asset: http://asset.localhost; font-src 'self'; connect-src ipc: http://ipc.localhost`). No remote script or remote `connect-src` is permitted, so the renderer cannot be steered by remote content.
- **Argos ↔ lightwalletd:** Argos does *not* trust the server. Confidentiality and integrity in transit rest entirely on TLS (standard webpki trust roots — see T-N2 for the no-pinning caveat); a hostile server cannot inject spendable state because no scanning-side spending keys are sent and crafted compact blocks are rejected by `librustzcash` sync (T-N3). What the server unavoidably learns is the *that* and *when* of scanning, not key material. The default endpoints (`zec.rocks`, `na.zec.rocks` for mainnet; `lightwalletd.testnet.electriccoin.co` for testnet) are configurable per scan, so a user who trusts a specific operator (e.g. their own node) can substitute it.
- **Argos ↔ local disk:** Argos trusts the local filesystem to the same degree it trusts the host OS, and relies on filesystem permissions to keep workspace contents private from other local users. Workspace directories and database files are written to a user-chosen directory (defaulting to the platform `AppDataDir/workspace`). Workspace directories are created with `0o700` and database files with `0o600` (`workspace.rs:set_private_file_permissions`). The `session.json` sidecar contains no keys — only label, network, birthday, and timestamps — and inherits the OS umask.
- **Build pipeline ↔ release artifact:** Users trust a released artifact only insofar as it is code-signed and provenance-attested by the pipeline. Signing happens in GitHub Actions environments gated to protected branches (PR #48). macOS signing uses Apple Developer ID secrets; Windows signing uses **Azure Trusted Signing** (cloud-held key, no secret in CI — the runner authenticates via OIDC; PR #96) under the Iqlusion Inc organization identity (see §8, T-B3). The SLSA Level 3 build-provenance attestation (T-SC6) additionally gives every artifact a third-party-verifiable source-to-binary chain, generated by the first-party `actions/attest-build-provenance` and verified with `gh attestation verify`.

## 5. Threat actors

"In scope" means the actor's capability is something Argos attempts to mitigate or bound; "out of scope" means Argos cannot meaningfully defend against it and treats it as the user's or platform's responsibility.

| Actor | Capability | In scope? |
|---|---|---|
| Another local user / process running *as the Argos user's account* | Read files under that account (workspace DB, recovery report) and list/inspect that account's processes, using only ordinary OS-account access | Yes — disk exposure is bounded by `0o700`/`0o600` permissions (T-L1) |
| Code running *inside* the Argos process (in-process attacker — e.g. malware that has already injected into Argos) | Read process memory, read disk, intercept clipboard, screen-capture, keylog | Partially — we mitigate disk/clipboard exposure (T-S1, T-S4) but cannot defeat an attacker already executing inside our address space |
| A *different* unprivileged user / process crossing the OS account boundary | Reach the Argos user's processes or files via OS isolation bugs or privilege escalation | Out of scope — defending the OS account boundary is the host OS's responsibility |
| Network observer (passive sniffer, anywhere on the path) | Passively observe Argos's network traffic, on the local segment or any upstream hop | Yes — all lightwalletd traffic is TLS (T-N1) |
| Hostile lightwalletd operator | Serve crafted compact blocks, log query patterns | Yes |
| Hostile DNS operator | Return a malicious address for a lightwalletd hostname to redirect the connection | Partially — DNS substitution alone is caught by TLS certificate validation against webpki roots; the residual gap is the absence of certificate pinning (T-N2) |
| Attacker able to compromise the local TLS trust store | Install a rogue CA / trust anchor so a substituted endpoint presents a valid-looking certificate | Partially — webpki trust roots are honoured as-is; a poisoned local trust store defeats TLS validation (no certificate pinning of the default endpoints — T-N2) |
| Compromised upstream Rust dependency | Inject malicious code at build time (`build.rs`, proc macros, or runtime code) | Partially — *build-time* compromise of the ≈73% of the tree shared with upstream Zcash projects is covered by `cargo-deny` + `cargo-vet`; the Tauri-side residue (§6.6.4) is exempted-but-tracked, and `build.rs`/proc-macro sandboxing (Geiger-style enumeration) is *not yet* adopted (T-SC1). No JS at runtime (§7). See §6.6, §7 |
| Compromised GitHub Actions / signing key | Sign a malicious installer | Yes — see §8 |
| Casual shoulder-surfer | Read the screen while seed is visible | Yes |
| Coerced user ($5 wrench attack) | Forced to run a sweep under duress | Out of scope |
| Nation-state with cryptanalytic capability | Break Sapling/Orchard or post-quantum threats | Out of scope |

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
| T-N2 | Active MITM substitutes lightwalletd | H | ⚠️ | Standard webpki trust roots only — **no certificate pinning** of `zec.rocks`. A user with a poisoned trust store can have their queries (and broadcasts) routed to a hostile node. Pinning the default endpoints is tracked as a follow-up. |
| T-N3 | Hostile lightwalletd serves invalid compact blocks | M | ✅ | `zcash_client_backend::sync::run` validates witness consistency against the chain tip and rejects malformed/inconsistent blocks. |
| T-N4 | Hostile lightwalletd correlates a user's IP with their wallet | H | ⚠️ | Inherent to the lightwalletd protocol. Mitigations: configurable endpoint (run your own), the `GetAddressUtxos` quick-probe queries 10 t-addrs (5 accounts × 2 addresses: external + change) which leaks them in plaintext (post-TLS) to the server, and the compact-block scan range leaks the wallet birthday. No Tor integration. |
| T-N5 | Auto-detect probe leaks viewing-key-derived addresses | M | ⚠️ | The auto-detect flow (`crates/zeck-core/src/birthday.rs`) imports an account into a temp workspace and runs a windowed sync. This sends FVK-derived address queries to the server. Documented in the UI ("requires a server connection"), but worth surfacing more clearly. |
| T-N6 | Sweep transaction broadcast reveals consolidation pattern | M | ⚠️ | A single sweep aggregates funds from many ZWL accounts into one destination, which on-chain analysis can link. Inherent to recovery — no good mitigation without changing the sweep model. |

### 6.4 Local storage

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-L1 | Other local users / processes read the workspace DB | M | ✅ | Workspace directories are created `0o700` and database files `0o600` at creation time (`workspace.rs:set_private_file_permissions`, implemented in PR #43). Workspace contains FVKs/IVKs (privacy leak) and witnesses, not the seed. `session.json` (label, network, birthday, timestamps — no keys) inherits the OS umask. |
| T-L2 | Recovery report contains sensitive metadata | L | ✅ | Report is user-initiated, written to a user-chosen path. Contents are documented in the UI before save (network, birthday, accounts, mode, workspace path, txids, net amounts). |
| T-L3 | Workspace persists indefinitely after recovery | L | ✅ | The GUI's Recovery-complete screen now exposes a "Delete workspace" action (`RecoveryService::delete_workspace` → `fs::remove_dir_all`). The UI explicitly surfaces that this is not a cryptographic wipe on SSDs — block-level remnants may persist until cells are overwritten or TRIM'd. For high-value seeds, users are directed to encrypt the volume containing the workspace. CLI users can `rm -rf` the workspace path printed at the end of a scan. |
| T-L4 | Resume-session metadata identifies prior recoveries | L | ✅ | The resume panel only shows workspaces under the configured data-dir; dismissed sessions stay dismissed via localStorage (PR #53). Sessions can be excluded without deleting on-disk state. |

### 6.5 Build, release, distribution

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-B1 | Compromised cargo dependency injects code at build time | H | ✅ | We pin via `Cargo.lock`. CI runs `cargo check` + `clippy` + tests + `cargo deny check advisories bans licenses sources` (with `yanked = "deny"`) + `cargo vet --locked` against an audit set imported from librustzcash and the federated Mozilla/Google/Embark/Bytecode Alliance/Fermyon/ISRG databases (T-SC1, PR #70). New `cargo update` resolutions that touch a non-vetted crate surface as a `cargo vet` failure rather than slipping in. |
| T-B2 | Compromised GitHub Actions secret signs a malicious release | C | ✅ | Signing and publish jobs are gated on protected environments (PR #48); only tagged release workflows can access them. macOS signing uses Apple Developer ID secrets. Windows signing stores **no secret at all** — the key is held in Azure Trusted Signing and the runner authenticates via short-lived OIDC scoped to the `release-sign` environment (PR #96), shrinking the stealable-secret surface for Windows to nothing. |
| T-B3 | Windows installer is unsigned | H | ✅ | Resolved (PR #96). Windows installers (MSI + NSIS) **and** the inner `Argos.exe` are code-signed during the build via **Azure Trusted Signing** under the Iqlusion Inc organization identity, gated through the same protected `release-sign` environment as macOS. Authentication is OIDC (no stored signing secret). Users can additionally verify the SHA256 checksum (T-B4) and the SLSA Level 3 build-provenance attestation (T-SC6) via `gh attestation verify`. |
| T-B4 | Installer tampered with after publish | M | ✅ | SHA256 checksums are published alongside each artifact (deduplicated via PR #47/#48). README directs Windows users to verify the checksum before running the installer. |
| T-B5 | Marketing site (sovright.com / Vercel preview) ships a different binary than the release page | L | ✅ | The site does not host binaries; download links point at `github.com/sovright/argos/releases`. |

### 6.6 Supply chain integrity

Almost all of the executable code in a released Argos binary comes from third-party crates (618 in `Cargo.lock`), and a compromise anywhere in that tree, in the build toolchain, or in CI is the single highest-impact attack class against this project. The threats below are listed separately from §6.5 because the mitigations differ: §6.5 is about *our* build and release pipeline, while §6.6 is about the integrity of the inputs that flow into it.

The high-level posture is: **we adopted the practices the rest of the Zcash Rust ecosystem already follows.** `librustzcash`, `zebrad`, and the Zcash mobile SDKs have collectively converged on `cargo-deny` (advisories + licenses + bans + sources), `cargo-vet` (per-crate third-party audits), `zizmor` (GitHub Actions security analysis), uniformly SHA-pinned Actions, and least-privilege workflow `permissions:`. Argos now does the same — see §6.6.3 for what we took from each upstream and §6.6.4 for how much of our tree those upstream audits actually cover (≈73%). The remaining residue lives in items the comparison shows are inherent to our distribution model (T-SC6 reproducible builds) or to upstream constraints out of our hands (T-SC4 toolchain, T-SC2 maintainer takeover).

| ID | Threat | Severity | Status | Mitigation |
|---|---|---|---|---|
| T-SC1 | Malicious `build.rs` script or procedural macro in a transitive crate runs arbitrary code at compile time (dev machine and CI). | H | ⚠️ | `cargo-vet` with imports from the librustzcash + Mozilla + Google + Embark + Bytecode Alliance + Fermyon + ISRG audit sets covers 148 of our 618 transitive crates with first-party / federated audits (PR #70). The remaining 565 crates carry `[[exemptions.*]]` entries in `supply-chain/config.toml` — "trust but not yet audited"; any new resolution that adds a non-exempted, non-vetted crate fails CI. Geiger-style `build.rs` enumeration is not yet adopted; that residue remains. The unaudited surface is concentrated in the Tauri stack (§6.6.4 / §7 category 2). |
| T-SC2 | Maintainer-account takeover on a critical crate (librustzcash family, `rustls`, `tauri`, `secrecy`, `secp256k1`, `bip0039`) ships a malicious version that we knowingly bump to. | H | ⚠️ | `cargo-deny` (T-B1) cannot detect a zero-day at bump time, but `cargo-vet` (T-SC1) requires every new resolution be either covered by an imported audit set or explicitly exempted, which surfaces an unexpected crate-version change as a CI failure with a named-auditor accountability trail. Project policy in `CLAUDE.md` requires conservative dependency review; the README/threat model document who maintains the high-value crates (§7). Formalising the diff-review checklist for `cargo update` is still open (§8). |
| T-SC3 | A third-party GitHub Action used in CI gets a tag force-moved (or a branch hijacked) to point at malicious code, which then runs with `GITHUB_TOKEN` or signing-environment access. | H | ✅ | Every third-party Action is now SHA-pinned with a `# vX.Y.Z` trailing comment (see PR #70), and the repository-level **Actions → Require SHA pinning for third-party Actions** setting is enabled (T-SC10), so a workflow that regresses to a tag pin is refused at job-start time. Signing/publish steps remain gated on protected environments (T-B2). |
| T-SC4 | Compromise of the upstream Rust toolchain (rustc / cargo) injects code into produced binaries. | M | ⚠️ | Toolchain version is pinned in CI (Rust 1.87). We rely on rust-lang's release signing and distribution; we do not independently verify toolchain hashes. Out of practical reach for this project; tracked rather than mitigated. |
| T-SC5 | A transitive crate is yanked from crates.io with no upstream replacement, so a freshly-resolved build cannot reproduce. | L | ✅ | `deny.toml` sets `yanked = "deny"`, so CI fails on any yanked crate in the lockfile. Made tractable by PR #69, which bumped the librustzcash family to the 2026-04 release wave that replaced the formerly-yanked `core2 0.3.3` with `corez 0.1.1` throughout the tree. Future yanks are now hard CI failures requiring an upstream-or-replace fix. |
| T-SC6 | The published release binary cannot be independently verified to correspond to the source tree at the tagged commit — i.e. no reproducible builds and no SLSA provenance attestation. | M | ❌ | SHA256 checksums (T-B4) and platform code-signing (T-B2) prove the binary was produced by our release pipeline, but not that the pipeline built the source faithfully. A verifier with the source cannot today rebuild bit-for-bit. Tracked. |
| T-SC7 | A new direct dependency we add is a typosquat or dependency-confusion package masquerading as a legitimate crate. | M | ✅ | Project policy in `CLAUDE.md` requires explicit approval and an `~/.claude/approved-dependencies.md` entry before any new direct dependency is added, with package name, version, adoption signals, maintenance status, and license recorded. This relies on review discipline, not tooling, and is therefore a process control rather than a hard gate. |
| T-SC8 | `cargo update` silently pulls a malicious patch release within the semver range allowed by `Cargo.toml` between manual review windows. | M | ✅ | `Cargo.lock` is committed and version updates require a commit; CI runs against the lockfile. Auto-update bots (Dependabot/Renovate) are intentionally **not** configured, so dependency bumps are always human-driven and reviewable as a diff. |
| T-SC9 | A pull request from a fork (external contributor) triggers our CI workflows, gaining `GITHUB_TOKEN` access and running attacker-controlled code on our runners — used either to exfiltrate via cache writes / artifacts / logs, or to consume CI minutes. | H | ✅ | Repository setting **Actions → Approval for running fork pull request workflows from contributors** set to `all_external_contributors` (verified via `gh api repos/.../actions/permissions/fork-pr-contributor-approval`). Every PR from a fork now requires explicit maintainer approval before any workflow runs. Combined with the protected `release-sign` / `release-publish` environments (T-B2), a fork PR cannot reach signing material even on approval. |
| T-SC10 | A future workflow change reintroduces a tag- or branch-pinned third-party Action (e.g. `actions/checkout@v4`), regressing the SHA-pin posture (T-SC3) silently between reviews. | M | ✅ | Repository setting **Actions → Require SHA pinning for third-party Actions** is enabled (verified via `gh api repos/.../actions/permissions` → `sha_pinning_required: true`). Workflow runs that reference a non-SHA-pinned third-party Action are refused by GitHub at job-start time, so a regression would surface as a CI failure rather than slipping in. |

**Combined effect after the §6.6.3 adoption.** We have strong reproducibility of *what we build today* (lockfile + pinned toolchain + SHA-pinned + repo-enforced Actions), per-crate audit coverage on the 73% of our tree shared with the rest of the Zcash Rust ecosystem (T-SC1 via `cargo-vet`), and platform-level gates against fork-PR exfiltration (T-SC9) and SHA-pin regression (T-SC10). The two structural gaps that remain are T-SC4 (upstream Rust toolchain compromise — out of practical reach for a project this size) and T-SC6 (no reproducible builds / SLSA provenance attestation — a real gap, tracked). On the dependency-tree integrity side, the 565 `cargo-vet` exemptions are concentrated in the Tauri stack (§6.6.4); shrinking that further is structurally hard and tracked rather than blocked on.

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

3. **`cargo-vet` with imports from `librustzcash`'s audit set** (PR #70, T-SC1 part 2). `supply-chain/config.toml` lists `[imports.zcash]` plus the same federated imports `librustzcash` already curates (Bytecode Alliance, Embark, Fermyon, Google, ISRG, Mozilla). Result at adoption: 142 fully audited + 6 partial + 565 exempted out of 618 transitive crates — the imports cover 148 crates of the shared tree (§6.6.4) for free.
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

1. **The librustzcash + Zcash ecosystem core that we share with `zebrad` and `ZODL`** — the librustzcash family (`zcash_client_backend`, `zcash_client_sqlite`, `zcash_keys`, `zcash_protocol`, `zcash_primitives`, `zcash_transparent`, `sapling-crypto`, `orchard`), maintained by ZODL (formerly the ECC mobile team); the cryptographic primitives they pull (`bls12_381`, `pasta_curves`, `halo2`, `equihash`, `secp256k1`); `secrecy` for key handling; `rustls` with the `ring` provider and no `aws-lc-sys` (PR #54) for TLS; `tonic` + `prost` + `tokio` for the gRPC lightwalletd client. This category is roughly the same set of crates that `zebrad` and `ZODL` consume — quantified in §6.6.4, **452 of our 618 lockfile crates (73%) are shared with either upstream**, and the librustzcash maintainers actively audit them via `cargo-vet`.

2. **The Tauri desktop-GUI stack** — `tauri` itself; `wry` (cross-platform WebView bindings); the `gtk-rs` family on Linux (`gtk`/`gdk`/`atk`/`gio`/`glib`/`gobject-sys`/`gtk3-macros`/`gdkwayland-sys`/`gdkx11` + their `*-sys` companions); `cairo-rs` + `cairo-sys-rs`; `webkit2gtk-*` + `javascriptcore-rs` on Linux, `core-graphics`/`cocoa`/`objc` on macOS, `embed_plist` for macOS bundling, `embed-resource` for Windows; the HTML/CSS parsing crates Tauri uses internally (`kuchikiki`, `html5ever`, `cssparser`, `selectors`); plus the smol-family async runtime Tauri's IPC pulls in (`async-channel`, `async-io`, `async-lock`, `blocking`, `futures-lite`). This is essentially all of the **~166 crates unique to Argos's tree** (§6.6.4) — neither `zebrad` nor `ZODL` consume it, and it dominates the unmaintained-crate advisory ignores in `deny.toml` (the RUSTSEC-2024-0411..0420 / 2025-0080 / 2025-0081 GTK3 family).

3. **Project-specific helpers for the recovery workflow.** A small tail: `keepawake` to hold a power-management guard so the OS doesn't sleep mid-scan (recovery scans of older wallets routinely run for hours); `bip0039` for the seed phrase; `clap` + `dialoguer` + `indicatif` for the CLI; `rusqlite` for the workspace database. `keepawake` in particular is unique to our long-scan use case — `zebrad` runs as a server and `ZODL` is a foreground app, so neither needs it.

JavaScript dependencies: **none at runtime**. The Tauri GUI ships zero npm packages in the browser bundle (PR #50).

**Tooling for the integrity of these inputs.** CI runs three gates against every push and PR, all modelled on the practices librustzcash and `zebrad` already use (see §6.6 for the comparison and §6.6.3 for what we adopted from each):

- `cargo deny check advisories bans licenses sources` (T-B1, T-SC1 part 1) — replaces the previous `cargo audit` job. Configuration lives in `deny.toml`; the carry-over advisory ignores for the GTK3 / Tauri stack and the `time` 0.3.x DoS sit there. `yanked = "deny"` is in force.
- `cargo vet --locked` (T-SC1 part 2) — third-party crate audits, with `supply-chain/config.toml` importing the same audit sets librustzcash maintains: Bytecode Alliance, Embark, Fermyon, Google, ISRG, Mozilla, and Zcash itself. Initial state at adoption: 142 fully audited + 6 partial + 565 exempted; the exemptions are concentrated in category 2 (the Tauri stack).
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
- Pre-Sapling (Sprout) note recovery — librustzcash dropped Sprout scanning long before this project began; ZWL seeds whose only funds are in Sprout notes (block <419,200, before October 2018) cannot be recovered via Argos.

## 10. Reporting a security issue

Please **do not** open a public GitHub issue for a security vulnerability. Email `security@sovright.com` with a description and reproduction steps; we will respond within five business days. No PGP key is available at this time. Plain email is sufficient for v0.1.0-rc.

## 11. Revision history

| Date | Author | Notes |
|---|---|---|
| 2026-05-13 | Kristi | Correct T-L1 status (permissions implemented); fix CSP quote; clarify T-N4 address count; PGP note. |
| 2026-05-19 | Zaki | Initial draft. Covers v0.1.0-rc. Open items listed in §8. |
| 2026-05-27 | Zaki | Added §6.6 Supply chain integrity (T-SC1..T-SC8), §6.6.1 cross-project posture comparison (zebrad + ZODL), §6.6.2 extending to librustzcash and the Zcash mobile Rust SDKs (documenting their `cargo-vet` posture with federated audits from Bytecode Alliance / Embark / Fermyon / Google / ISRG / Mozilla, `zizmor` on workflows, uniformly SHA-pinned Actions), §6.6.3 adoption plan, and §6.6.4 quantifying dependency-surface divergence: 452/618 (73%) of our crates are shared with zebra or librustzcash; the 166 unique to Argos are essentially the Tauri desktop-GUI stack. |
| 2026-05-28 | Zaki | Added T-SC9 (fork-PR CI execution) and T-SC10 (SHA-pin regression), both ✅ via repository-level Actions settings (`fork-pr-contributor-approval: all_external_contributors`, `sha_pinning_required: true`). T-SC3 upgraded ⚠️→✅ on the back of T-SC10. |
| 2026-05-28 | Zaki | Holistic pass after PRs #69 (librustzcash 2026-04 bump) and #70 (cargo-deny + cargo-vet + zizmor + SHA-pin Actions + least-privilege workflows): rewrote §7 to lead with the three-category framing (librustzcash + Zcash ecosystem shared with zebrad/ZODL; Tauri desktop-GUI stack; project-specific helpers including `keepawake` for long scans); reframed §6.6 + §6.6.3 from prospective adoption plan to retrospective record of what we took from each upstream; updated T-B1 / T-SC1 / T-SC2 / T-SC5 statuses to reflect the new tooling; refreshed §6.6.1 comparison table to the post-#70 state; updated §8 backlog (T-SC1 / T-SC1b / T-SC3 / T-SC9 / T-SC10 now ✅; T-SC6 named as the largest remaining supply-chain gap). |
| 2026-05-28 | Zaki | T-B3 status moved ❌ → ⚠️: Windows code-signing certificate procurement is in progress. §4 build-pipeline trust boundary and §6.6.1 comparison-table release-binary row updated to reflect (a) Windows signing in progress, (b) SLSA Level 3 provenance attestation (T-SC6) coming via PR #71 as the third-party-verifiable source-to-binary chain in the interim. |
| 2026-05-29 | Zaki | T-B3 status moved ⚠️ → ✅ (PR #96): Windows code-signing landed via Azure Trusted Signing under the Iqlusion Inc organization identity. Signs the inner `Argos.exe` + MSI/NSIS installers during the build, in the protected `release-sign` environment, authenticated by OIDC with no stored signing secret (also tightening T-B2). Updated §0 at-a-glance, §4 build-pipeline boundary, T-B2/T-B3, §6.6.1 release-binary row, and §8 checklist. Runbook: `RELEASE_SIGNING.md`. |
| 2026-05-29 | Zaki | Migrated SLSA provenance from the `slsa-github-generator` reusable workflow to the first-party `actions/attest-build-provenance` (per-build-job, SHA-pinned). The generator was incompatible with the `sha_pinning_required` policy (T-SC10) because it internally calls tag-pinned actions, which silently broke provenance on every release. Updated §4 boundary, T-B3, T-SC6, and the README verification section (now `gh attestation verify` instead of `slsa-verifier` + `.intoto.jsonl`). |
| 2026-06-22 | Zaki | Least Authority audit clarifications (Suggestions 10–13), docs-only: added §1.1 separating the stable threat **model** (§2–§5, §9) from the point-in-time threat **assessment** (§0, §6–§8) and signposted §0 and §6 accordingly (S10); renamed §4 "Trust boundaries" → "Trust relationships" and reworded each entry to state the trust decision and its basis, notably the Argos ↔ lightwalletd relationship (S11); clarified the §5 threat-actor definitions and scope wording, and split the former "Hostile DNS / TLS-trust-store attacker" row into separate "Hostile DNS operator" and "local TLS trust store" actors (S12); moved the recovery report above the compact-block cache in the §3 asset priority list (S13). No substantive change to the model. |
