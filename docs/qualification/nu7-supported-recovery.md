# NU7 supported-recovery qualification

This change carries supported transparent, Sapling, Orchard and Ironwood
recovery onto the NU7 SDK after Sprout removal. It does not restore Sprout
spending, scanning, P2P or artifact reconciliation.

## What the qualification layers establish

| Layer | Evidence required | Limit |
|---|---|---|
| Offline `nu7_readiness` | Production activation/branch constants; v5/v6 wire round trips; actual builder expiry; PCZT branch serialization; local schedule/reopen; old-SDK database migration | Empty transactions and accounts contain no funds and do not prove signing or node acceptance. |
| Fast live `nu7-fast` profile | Zebra accepts blocks 9, 10 and 11; complete blocks parse with the expected embedded branch; lightwalletd serves NU7 compact block 10 | Synthetic coinbase blocks at activation 10 do not qualify a funded sweep or PCZT; ZIP 212 is not enforced. |
| Full live `nu7` profile | Prepared supported balances; actual accepted and mined recovery transactions around activation 32,500, including imported Sapling PCZT | Remains a release gate until executed and recorded against this branch. |

Run commands, private endpoints, native proxy fallback and chain-state handling
are in [the harness guide](../../tests/regtest/README.md#dedicated-nu7-qualification).
The profiles have independent volumes and bind published ports only to loopback.
`nu7.sh` refuses to rewind/delete existing state and never funds a wallet.

## Retained source and fixture provenance

The harness pins the same official artifacts as the source NU7 qualification:

- [Zebra v7.0.0](https://github.com/ZcashFoundation/zebra/releases/tag/v7.0.0), image
  `zfnd/zebra:7.0.0@sha256:a70d2be8ffef3a4b6e37355724e36a0e6c1838e46baa28bfb216739f00cf2d34`.
  Preserve needed older node volumes before upgrading: Zebra 7 migrates state
  to v29, which Zebra 6 cannot reopen.
- [lightwalletd v0.6.0](https://github.com/zcash/lightwalletd/releases/tag/v0.6.0), image
  `electriccoinco/lightwalletd:v0.6.0@sha256:abc8199dae800e050415a3459f71c7850aeefeb1ca6a681e9b9eda7249ce8613`.
  The image is amd64-only; the native fallback uses the official tag commit
  `e7436d2adb9ab5828eb8a27de534e16218841fc2`.
- [The old-SDK SQLite fixture](../../tests/regtest/legacy-wallet-db/README.md)
  has SHA-256 `51bce8f9dc545187702cf1b4bb5e32277a18a0182002836c53fdb289ed7df328`.
  Tests copy it before migration and preserve the original. It holds one
  synthetic public account, scan work and no funds.

These pins are retained from PR #291, not a claim that upstream registries or
release metadata were independently refreshed for this carry-forward.

## Current execution and outstanding gate

On 2026-11-06 the local Docker CLI was present, but both configured daemon
sockets (`default` and `desktop-linux`) were unavailable. The Docker Compose
plugin was also absent. No `zebrad` or `lightwalletd` executable was on PATH.
The existing lightwalletd checkout was at `d35b141d8801e6ff251aeb906158a220ddff2201`,
not the pinned NU7 fallback revision, and had no root binary. The live boundary
tests were therefore not executed during qualification-file preparation.
Historical successful runs on the superseded branch are not current-branch
validation evidence. CI has a dedicated NU7-only live block/proxy job.

**The funded full-height supported sweep/PCZT rehearsal remains unexecuted and
is a release gate.** The funding helper installs the ordinary pre-NU7 local
schedule and shares a treasury at `$TMPDIR/argos-regtest-treasury`. A rehearsal
must isolate `TMPDIR`, prepare its treasury near genesis, install the qualified
NU7 schedule in post-activation funding/test processes, and observe actual
mined supported-pool recoveries and imported Sapling PCZT transactions. Merely
starting the full profile or migrating an empty database cannot satisfy it.

**Gate waived for 2.0.0.** On 2026-11-06 a maintainer chose to release 2.0.0
without executing this rehearsal. This is a waiver, not a pass: no funded
NU7 sweep or imported-Sapling PCZT transaction has been observed mined for
this release. The evidence behind 2.0.0 is the offline and fast-profile layers
above, plus the unit and proposal tests listed below. The rehearsal stays the
outstanding qualification item for supported recovery after NU7.
No release, real-wallet funding or mainnet spending is authorized here.

## Local carry-forward results

The Rust 1.89 workspace suite passed 1,120 tests with no failures; 40 cases
requiring harness/network setup were ignored. Seven offline NU7 qualification
tests passed, including migration of the old-SDK database fixture. Strict
all-target/all-feature Clippy, formatting, dependency advisories and locked
cargo-vet passed. GUI validation passed 189 Node tests and 26 layout tests each
in Chromium and WebKit. Independent runtime review identified partial-batch
donation underreporting; its fix passed a regression that fails when the old
error-ordering behavior is deliberately restored. New real Orchard, Ironwood
and mixed-pool proposal tests preserve notes, budgets and fees across batches.
These local results do not satisfy the funded gate above.
