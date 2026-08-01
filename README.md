# Argos

Argos is a recovery workspace for legacy ZecWallet Lite seeds.

This repository now contains:

- `crates/argos-core`: shared Rust library for seed validation, address derivation, lightwalletd probing, and recovery session orchestration.
- `crates/argos-cli`: a terminal interface for showing keys, scanning derived accounts, and preparing sweep requests.
- `gui/`: a Tauri v2 desktop shell with a step-by-step recovery wizard.

## Current Status

Argos now includes the major recovery phases end to end:

- BIP-39 validation and normalization
- ZecWallet Lite-compatible Sapling, Orchard, and transparent derivation
- Unified-address destination validation
- Persisted recovery workspaces under random per-session subdirectories of `--data-dir` / the GUI workspace directory field
- `zcash_client_sqlite`-backed compact-block sync for authoritative transparent, Sapling, and Orchard balances
- Shared scan/sweep command surface for the CLI and GUI
- Real sweep planning with ZIP 317 fee estimation, memo support, and max-fee guards
- Real shielding/sweep transaction construction and broadcast through `lightwalletd`
- lightwalletd endpoint fallback, using comma-separated server URLs tried in order
- Progress metadata for elapsed time and ETA, plus GUI discovery notifications and recovery-report export
- Legacy wallet file import (`--wallet-file`): zcashd `wallet.dat` and ZecWallet Lite, including encrypted wallets

## Recovering from a wallet file

Instead of a seed phrase, Argos can read keys directly out of a legacy
wallet file. The file is opened read-only and never modified. If it is
encrypted you are prompted for the passphrase — there is deliberately no
flag for it, so it cannot end up in shell history or in `ps` output.

```
argos --wallet-file /path/to/wallet.dat inspect-wallet
```

`inspect-wallet` is entirely local: no network, nothing written to disk.
It reports how many transparent, Sapling, and Sprout keys were recovered,
lists Sprout addresses, and names every record it could not read.

**What you can do with the result depends on the wallet:**

| Wallet | Scan and sweep? |
|---|---|
| ZecWallet Lite | **Yes.** Decryption recovers the BIP-39 mnemonic, so the wallet re-enters the normal HD recovery path. Add `--wallet-file` to `scan` or `sweep`. |
| zcashd `wallet.dat` | **Not yet.** Keys are stored individually with no HD seed behind them, and Argos has no standalone-key scan or spend path. `inspect-wallet` works; `scan` refuses. |

That refusal is deliberate. Argos will not scan a zcashd wallet, find
nothing because it had no accounts to look at, and report an empty result
— which is indistinguishable from "your funds are gone" to the person who
most needs the answer.

## Security audit

Argos was independently audited by [Least Authority](https://leastauthority.com). The audit
covered the Rust core, CLI, and Tauri GUI, and reviewed the project [threat model](docs/THREAT_MODEL.md).

- **Final Audit Report (29 June 2026):** [`site/assets/least-authority-argos-audit-2026-06-29.pdf`](site/assets/least-authority-argos-audit-2026-06-29.pdf)
- Initial review revision: `78ffb4d`; verification revision: `11bb6dbd`
- The report raised **9 issues** (8 Medium, 1 Low) and **13 suggestions**. As of the final
  report, **every issue and suggestion is marked Resolved.**

The findings and their fixes are tracked in this repository's pull-request history.

## Operational Notes

- Recovery sessions persist wallet/cache state on disk for auditability and sweep construction. Workspace subdirectories are random per session so the path does not reveal a stable seed fingerprint.
- On Unix platforms, Argos creates recovery workspace directories with private `0700` permissions and wallet/cache database files with `0600` permissions.
- Transparent funds are imported into the wallet workspace using Argos's audited legacy derivation, not modern per-account transparent derivation.
- Public lightwalletd servers learn scan metadata such as requested block ranges. Use your own lightwalletd or a local privacy proxy when that metadata matters.
- Custom lightwalletd endpoints must use HTTPS unless they target localhost/loopback for local testing.
- Broadcasted transactions are polled for confirmation during a bounded wait window. If they are still unmined at the end of that window, Argos reports them as pending instead of pretending they confirmed.
- Sprout recovery from a seed phrase is still out of scope because ZecWallet Lite did not derive Sprout keys from the HD seed. Argos can now recover Sprout spending keys directly from a zcashd `wallet.dat`, but spending recovered Sprout funds is not yet implemented — extracting the key does not yet mean the funds can be moved.
- The GUI defaults to auto gap-limit mode and can switch to an explicit account count when the user wants an exact scan depth.
- The desktop complete screen can save a plain-text recovery report inside the persisted workspace.

## Workspace

```text
.
├── crates/
│   ├── argos-core/
│   └── argos-cli/
├── gui/
│   ├── src/
│   └── src-tauri/
└── ZECK_WALLET_LIGHT_RECOVERY_SPEC.md
```

## Installing on Windows

**The prebuilt installer is the supported Windows path.** Download the `.exe` from the [Releases page](https://github.com/sovright/argos/releases), verify its build provenance with `gh attestation verify` (see [Verifying release provenance](#verifying-release-provenance) below), and run the installer. No additional dependencies are required.

Building from source is an advanced/auditor path and is supported on **Windows x64** only. Windows on ARM (aarch64-pc-windows-msvc) is not currently a supported build target; ARM64 Windows users should use the prebuilt binary.

Security note: for a wallet-recovery tool, the ability to audit and build from source is a trust property. If you are relying on the prebuilt binary, verify its provenance attestation before running it.

## Verifying release provenance

**This is the primary, recommended verification step.** It is the only check that defends against a tampered release, because it validates the artifact independently of the release page it was downloaded from.

Each tagged release publishes a [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) build-provenance attestation for every binary, generated by GitHub's first-party [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance). The attestation is Sigstore-signed (no long-lived key — anchored to the GitHub Actions OIDC identity of this repository) and proves that the exact bytes of a release artifact were produced by `.github/workflows/release.yml` at the tagged commit.

To verify a downloaded artifact, run this before installing or running it:

```bash
# Uses the GitHub CLI (gh). The attestation lives in this repo's attestation
# store — no separate provenance file to download. Replace <release-tag> with
# the tag you downloaded from, e.g. v0.1.0.
gh attestation verify <downloaded-file> \
  --repo sovright/argos \
  --signer-workflow sovright/argos/.github/workflows/release.yml \
  --source-ref refs/tags/<release-tag>
```

A passing verification confirms that `<downloaded-file>` was produced by this repository's release workflow for the tag you selected. Release bundles are also code-signed: macOS via Apple Developer ID (notarized), and Windows via Azure Trusted Signing under the Iqlusion Inc organization identity. The provenance attestation complements the platform code-signing by anchoring each artifact to a specific source-tree commit rather than only to a signing identity.

### SHA256 checksums (corruption check only)

Each release also publishes a `SHA256SUMS` manifest. This is a convenience check for **detecting accidental download corruption — not a security or tamper control.** The checksum file is hosted on the same release page as the binaries, so an attacker who can replace a binary can also replace its checksum. It cannot prove that an artifact is authentic; only the `gh attestation verify` provenance check above can do that. Use the checksum at most as a quick sanity check after downloading, and always rely on the provenance attestation for trust.

## Development

```bash
cargo fmt
cargo test -p argos-core
cargo check --workspace
cd gui && npm install
cd gui && npm run build
```
