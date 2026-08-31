# Argos

Argos is a recovery workspace for legacy Zcash wallets. It recovers from
ZecWallet Lite seed phrases and wallet files, zcashd `wallet.dat` files, and
standalone Sapling or Sprout spending keys.

This repository now contains:

- `crates/zeck-core`: shared Rust library for key handling, scanning, and recovery session orchestration (package name `argos-core`).
- `crates/zeck-cli`: a terminal interface for inspecting recovery sources, scanning, and sweeping funds (package name `argos-cli`; binary name `argos`).
- `gui/`: a Tauri v2 desktop shell with a step-by-step recovery wizard.
- `crates/argos-wallet-import`: an isolated, read-only parser for legacy wallet files.

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
- Standalone Sapling extended spending keys, supplied through `--sapling-key-file` or pasted into the desktop app
- Scan and sweep support for imported transparent and Sapling keys
- Generally available Sprout recovery from `wallet.dat` or standalone `SK…` / `ST…` spending keys, including resumable full-block scans when a wallet has no cached note witnesses

## Recovery sources

| Source | Coverage |
|---|---|
| 24-word ZecWallet Lite seed | Derives, scans, and sweeps transparent, Sapling, and Orchard funds across the legacy account layout. ZecWallet Lite did not derive Sprout keys from this seed. |
| ZecWallet Lite wallet file | Recovers the mnemonic and re-enters the same complete HD recovery path as a typed seed. |
| zcashd `wallet.dat` | Scans and sweeps every imported transparent and Sapling key. Sprout notes use the separate Sprout workflow described below. |
| Sapling extended spending key | Scans and sweeps `secret-extended-key-main1…` or `secret-extended-key-test1…` keys without requiring a wallet file. |
| Sprout spending key | Scans and sweeps `SK…` (mainnet) or `ST…` (testnet) keys without requiring a wallet file. |

Wallet files are opened read-only and never modified. If one is encrypted,
Argos prompts for its passphrase. There is deliberately no passphrase flag,
so the passphrase cannot end up in shell history or `ps` output.

```
argos --wallet-file /path/to/wallet.dat inspect-wallet
```

`inspect-wallet` is entirely local: no network, nothing written to disk.
It reports how many transparent, Sapling, and Sprout keys were recovered,
lists Sprout addresses, and names every record it could not read.

The ordinary `scan` and `sweep` commands cover imported Sapling and
transparent keys. A zcashd wallet commonly contains several Sapling keys;
Argos creates one imported account per key and sweeps each funded account.
Transparent funds use a separate direct recovery path and may produce a
separate transaction.

```bash
# Scan every imported transparent and Sapling key.
argos --wallet-file /path/to/wallet.dat scan

# Preview, then confirm, a sweep to a Unified Address.
argos --wallet-file /path/to/wallet.dat sweep --destination u1... --dry-run
argos --wallet-file /path/to/wallet.dat sweep --destination u1... --confirm-sweep
```

## Recovering a standalone Sapling key

Put one key per line in a private text file. Blank lines and lines beginning
with `#` are ignored. A key file may be combined with a seedless wallet file;
duplicate keys are removed. It cannot be combined with a ZecWallet Lite file
that contains a mnemonic, because that file uses the HD account path.

```bash
chmod 600 sapling-keys.txt
argos --sapling-key-file sapling-keys.txt scan
argos --sapling-key-file sapling-keys.txt sweep --destination u1... --dry-run
```

Viewing keys such as `zxviews…` are rejected: they can reveal balances but
cannot authorize the sweep Argos is promising.

## Recovering Sprout funds

Sprout support is part of normal Argos builds and requires no Cargo feature.
It is intentionally separate from the ordinary compact-block scan:

- If a synced `wallet.dat` contains note data and a cached witness,
  `sweep-sprout` can use that historical witness without scanning the chain.
- If all you have is a spending key, or the wallet has no usable note data,
  `scan-sprout` trial-decrypts every historical JoinSplit. Compact blocks do
  not contain those ciphertexts, so this reads full blocks directly from the
  Zcash P2P network from genesis to Canopy. On mainnet that is 1,046,400
  blocks, roughly 26 GB of transfer, hours of work, and under 500 MB retained
  on disk. Progress is checkpointed and resumable.

The Sprout checkpoint is spend-capable: it contains the raw keys, recovered
note plaintexts, and witnesses needed to resume and sweep. Argos creates it
with private permissions on Unix and removes it after a successful sweep.
Protect it like the original key file and delete any leftover checkpoint only
after the destination transaction is confirmed.

```bash
# First see whether the wallet already has spendable note data.
argos --wallet-file /path/to/wallet.dat inspect-wallet

# Preview a direct wallet-backed Sprout sweep.
argos --wallet-file /path/to/wallet.dat sweep-sprout \
  --destination u1... --dry-run

# Scan one or more standalone keys, then optionally sweep the result.
chmod 600 sprout-keys.txt
argos --sprout-key-file sprout-keys.txt scan-sprout
argos --sprout-key-file sprout-keys.txt scan-sprout \
  --destination u1... --confirm-sweep
```

Sprout funds land in Sapling, even when the destination is a Unified Address.
A Sprout JoinSplit is a version 4 transaction while Orchard actions require
version 5, so one transaction cannot reach Orchard. If desired, move the
funds from Sapling to Orchard afterward from your own wallet. Broadcasting a
Sprout sweep also requires the approximately 725 MB
`sprout-groth16.params`; Argos checks `--sprout-params`, then
`$ARGOS_SPROUT_PARAMS`, then the conventional `~/.zcash-params` location.

Ordinary imported-key results state that Sprout is handled separately rather
than folding it silently into a zero balance. Argos will not
report a balance that silently excludes a pool it never looked at — "0.5
ZEC recovered" reads as complete to the person who most needs the answer,
so every uncovered pool is named, with a reminder to keep the original
wallet file.

Transparent recovery does not use the wallet-database account model at
all. That model exists to serve shielded scanning; transparent funds need
only `GetAddressUtxos` and the transaction builder. This matters because a
transparent-only wallet *cannot* have an account: ZIP-316 forbids a
unified viewing key containing only transparent items.

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
- A ZecWallet Lite seed alone cannot recover Sprout funds because those keys were generated independently. Use the original `wallet.dat` or a standalone Sprout spending key instead.
- A balance reconstructed only from cached `wallet.dat` records is the file's claim until the sweep is accepted by consensus. A full-block Sprout scan derives its result from the chain.
- The GUI defaults to auto gap-limit mode and can switch to an explicit account count when the user wants an exact scan depth.
- The desktop complete screen can save a plain-text recovery report inside the persisted workspace.

## Workspace

```text
.
├── crates/
│   ├── zeck-core/            # package: argos-core
│   ├── zeck-cli/             # package: argos-cli; binary: argos
│   └── argos-wallet-import/
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

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
