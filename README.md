# Argos

Argos is a recovery workspace for legacy Zcash wallets. It recovers from
ZecWallet Lite seed phrases and wallet files, zcashd `wallet.dat` files, and
standalone Sapling spending keys.

> **Sprout funds are unspendable under NU7.** NU7 disallows version 4
> transactions, the only format that supports Sprout spends. Argos no longer
> scans or sweeps Sprout funds. Wallet import recognizes Sprout records and
> explains this limitation while continuing transparent and Sapling recovery.
> See [ZIP 259](https://zips.z.cash/zip-0259).

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

## Recovery sources

| Source | Coverage |
|---|---|
| BIP-39 seed phrase (12–24 words; ZecWallet Lite used 24) | Derives, scans, and sweeps transparent, Sapling, and Orchard funds across the legacy account layout. ZecWallet Lite did not derive Sprout keys from this seed. |
| ZecWallet Lite wallet file | Recovers the mnemonic and re-enters the same complete HD recovery path as a typed seed. |
| zcashd `wallet.dat` | Scans and sweeps every imported transparent and Sapling key. Sprout records are identified as unsupported under NU7. |
| Sapling extended spending key | Scans and sweeps `secret-extended-key-main1…` or `secret-extended-key-test1…` keys without requiring a wallet file. |

Wallet files are opened read-only and never modified. If one is encrypted,
Argos prompts for its passphrase. There is deliberately no passphrase flag,
so the passphrase cannot end up in shell history or `ps` output.

In the desktop app, a successful inspection creates an opaque review ID for a
backend-owned snapshot of the opened file: its length, SHA-256 digest, and
filesystem object identity. Later wallet-backed scans reopen and verify that
exact source. An in-place edit or even
an identical-byte replacement is refused with “wallet changed since review;
inspect it again.”

The parser also validates recovered transparent and Sapling secret keys against the addresses or viewing keys stored in the wallet at runtime;
well-formed but mismatched key material is not accepted as spend authority.

```
argos --wallet-file /path/to/wallet.dat inspect-wallet
```

`inspect-wallet` is entirely local: no network, nothing written to disk.
It reports recovered transparent and Sapling key counts, warns when Sprout
records are present, and names every supported record it could not read.
Sprout record counts are not a balance or a claim that keys were recovered.

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

## Smaller compact-block batches

Starting with 1.5.5, both executables accept `--scan-batch-size`. To reduce
regular compact-block batches from the default 1,000 blocks to 100:

```sh
argos-gui --verbose --scan-batch-size 100
```

For the CLI, add `--scan-batch-size 100` to your existing `argos ... scan`
command. The effective size is clamped to 10–10,000 blocks. Smaller batches
use less memory and commit progress more frequently, with more server requests.
The desktop app does not currently expose this control in its settings.

## Automatic transparent address coverage

Ordinary seed recovery checks account 0 receive indices **0–999** in addition
to the standard receivers of the shielded accounts being recovered. It checks
the entire range even when earlier addresses are unused. All funded addresses
in that range feed into the normal balance summary and shielding/sweep flow;
there is no need to know a target address or use **Find this address** first.

In the GUI, open **Advanced: change the transparent address range** to adjust
the first index, count, or include the corresponding change-address range.
The CLI exposes the same settings for both `scan` and `sweep`:

```sh
argos --transparent-index-start 0 --transparent-index-count 2000 --transparent-change scan
```

Use the same range flags for a later CLI `sweep` command.

The range is independent of the shielded account count/gap. It is limited to
10,000 indices per branch per scan and must stay within non-hardened BIP44
indices. A changed range uses a separate workspace; resuming a saved scan
restores its original scope, including the historical scope of old sessions.
Wallet files containing an HD seed use the same range. Standalone/imported-key
and exact-address-match recovery retain their own key scope.

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

## Sprout after NU7

NU7 disallows version 4 transactions, so remaining Sprout funds are
unspendable under those rules. Argos has removed Sprout key import, scanning,
sweeping, and pack tooling. A wallet containing Sprout records still imports
its supported transparent and Sapling keys; the Sprout notice is separate
from the supported-pool balance.

Existing wallets, checkpoints, journals, and packs are left untouched.
Preserve old recovery artifacts and transaction records. This version does
not reconcile or clean up artifacts created by the removed Sprout workflow.

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
- New private storage is assembled create-only in a staging root. Argos syncs the root marker, workspace leaf, empty database, and database marker before atomically publishing the root. A crash before publication leaves no trusted final root; a published partial or identity-mismatched generation fails closed. The resume panel represents an insecure or unmarked legacy workspace only as a rescan-required row derived from its path. It never reads that workspace's label, balances, scan height, or database. Preserve that tree, reconcile its pending or unknown transaction IDs using the prior trusted version or independent chain checks, and start a rescan in a genuinely absent data directory; do not delete the old evidence during reconciliation.
- Private recovery directories and sensitive files use exact current-user-owned `0700`/`0600` modes without extended or inherited ACLs on supported Unix systems. On Windows the current token user must own them and a protected current-user+LocalSystem DACL is required. All reused objects must already match these controls and their create-time lineage before any permission change, read, truncate, append, or other sensitive use. Argos never repairs them in place because changing permissions cannot revoke stale handles. Preserve an insecure or unmarked legacy workspace, reconcile its transaction history using trusted independent evidence, then create a new recovery under a genuinely absent data-directory path and rescan; changing its mode, DACL, or marker does not make it trusted. Windows authenticates the private-root lineage marker with DPAPI `CurrentUser` and keeps a permanent per-leaf/database anchor in HKCU, keyed by the full canonical workspace/database context, whose state advances `Pending` -> `Active` -> `Revoked`. The first database authorization in a process performs an exclusive cold preflight; retained exact-object authority then permits that process's SQLite writer and progress readers to coexist. SQLite sidecars proven absent before connection open are the narrow creation exception: SQLite creates them while Argos retains their exact-private parent, then Argos normalizes and verifies them before releasing that parent. Workspace cleanup first syncs its durable cleanup marker, then revokes the Windows lineage anchor before deleting the tombstone. These controls do not isolate another process running as the same user or an administrator, and rollback of the user's HKCU/profile state remains a Windows residual.
- The GUI clears seed, passphrase, and pasted-key fields once a scan accepts them; when a running scan finishes, fails, or is cancelled; on **Forget this file**, abandonment to the welcome screen, **Start over**, and window close. A failed scan start preserves the wallet passphrase and pasted keys for retry within the existing review deadline; changing the data directory invalidates derived scan and proposal evidence. Ordinary navigation and a wallet-inspection error also keep the wallet passphrase only within the active review window: the GUI drops the passphrase, pasted keys, and opaque review ID after 29 minutes, before the backend's 30-minute review limit. Running scans retain their keys until completion or explicit release, and release waits for workers before the last owner is dropped.
- Secret owners use best-effort zeroization on drop. This shortens ordinary plaintext lifetime but cannot defeat swap, crash/core dumps, allocator or compiler copies, kernel caches, DMA, forensic capture, or a compromised process; use an encrypted disk and encrypted or disabled swap for high-value recovery.
- Transparent funds are imported into the wallet workspace using Argos's audited legacy derivation, not modern per-account transparent derivation.
- Public lightwalletd servers learn scan metadata such as requested block ranges. Use your own lightwalletd or a local privacy proxy when that metadata matters.
- Custom lightwalletd endpoints must use HTTPS unless they target localhost/loopback for local testing.
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
