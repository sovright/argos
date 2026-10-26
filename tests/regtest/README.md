# Argos regtest harness

A Docker-based local Zcash regtest stack for the C2 integration tests defined
in `crates/zeck-core/tests/regtest_integration.rs`. These tests exercise the
fund-recovery flow against a real Zcash node — scan, sweep, broadcast, resume
— in scenarios that aren't reachable from pure unit tests (GoAway frames mid
scan, hostile compact blocks, mid-scan crashes, reorgs, etc.).

The harness is **opt-in** and **never runs in CI**:

- The integration tests are tagged `#[ignore]` so default `cargo test` skips them.
- Booting a regtest stack on every PR would inflate CI runtime past the cache
  TTL and is not worth it for tests this rarely fail.
- Contributors run this locally before merging changes to scan/sweep logic.

## What boots

```
zebrad-regtest       Private Zcash network, listens on 127.0.0.1:18232 (RPC)
lightwalletd-regtest gRPC server pointing at zebrad, on 127.0.0.1:9067 (no TLS)
```

The node is **Zebra**, not zcashd. It had to be: `UPGRADE_NU6_3` appears
nowhere in zcash/zcash — not in v6.20.0, the newest release, nor on master —
so a zcashd chain can never activate Ironwood (NU6.3), and the post-activation
sweep path is untestable on it by construction. Zebra implements NU6.3 with
per-upgrade configurable Regtest activation heights.

Both images are pinned by release tag and image digest (`zfnd/zebra:7.0.0`,
`electriccoinco/lightwalletd:v0.6.0`), rather than tracking `latest`: the activation heights and consensus rules under
test are version-sensitive, and a silently updated node would change what the
tests mean. lightwalletd preserves the Ironwood compact-block fields the client backend
expects to decode. The ordinary chain deliberately omits NU7 activation;
`ArgosParams::regtest_all_active()` still activates through NU6.3 only. The
`sprout` and `fixtures` profiles retain zcashd v6.20.0 and their existing rules.

Both bound to **loopback only**. Never expose these ports — the regtest RPC
credentials are well-known and a remote miner with control of those ports
can mint regtest coins indefinitely.

## Prerequisites

- **Docker** (Docker Desktop on macOS / Windows; native `docker` + `docker
  compose` plugin on Linux). Tested with Docker 24+.
- **`curl`** for the setup script's JSON-RPC calls.
- **`argos-cli`** built. The setup script derives the test seed's
  transparent address using `argos show-keys`, so the binary must be on
  `PATH` or pointed to via `$ARGOS_CLI`:

  ```bash
  cargo build -p argos-cli --release
  export ARGOS_CLI="$(pwd)/target/release/argos"
  ```

## One-time setup

From the **repository root**:

```bash
cd tests/regtest

# Boot the stack (-d = detached).
docker compose up -d

# Wait for the healthcheck to pass and run the funding script.
# Fills the treasury with coinbase near genesis, mines to the ZIP 212
# enforcement height, then pays every test address from the treasury in one
# transaction. Takes roughly an hour on first run, most of it mining.
#
# Re-run it whenever the suite has drained the funded addresses — that is the
# supported way to recover a chain, and it does not require rebuilding.
./setup.sh
```

Then export what the integration tests read. `setup.sh` prints both:

```bash
export ARGOS_REGTEST_LIGHTWALLETD_URL=http://localhost:9067
export ARGOS_REGTEST_TEST_T_ADDR_1=funded
```

Run the suite single-threaded. Funding shares one treasury workspace and
SQLite permits one writer, so parallel tests that fund themselves collide
with `database is locked`:

```bash
cargo test -p argos-core --features argos-network -- --ignored --test-threads=1
```

### How funding works, and what it means for the tests

Zebra has **no wallet** — no `sendtoaddress`, no `getnewaddress` — so the old
`zcash-cli sendtoaddress` funding is gone. `setup.sh` runs the
`argos-regtest-funder` helper instead.

**Only the treasury is paid with coinbase, and only near genesis.** Everything
else is funded by an ordinary shielded transfer *from* the treasury, at
whatever height the chain has reached.

That split exists because two requirements do not overlap in time:

| Requirement | Constraint |
|---|---|
| PCZT construction needs ZIP 212 fully enforced | height > 32,257 |
| Regtest coinbase pays anything | height < ~6,000 (subsidy halves every ~150 blocks) |

Coinbase funding therefore only works near genesis, which used to mean every
address was funded exactly once and could never be refilled. A sweep test
drains its address, so the suite could not be run twice against one chain: the
second run reported empty wallets that looked like defects. A transfer does not
care what the subsidy is doing, so the treasury can pay any address at any
height.

Do **not** try to fix the subsidy with `pre_blossom_halving_interval` in
`zebrad-regtest.toml`. Zebra accepts the key on Regtest and ignores it —
`Parameters::new_regtest` hardcodes the interval. Measured against the pinned
v6.2.3 with it set to 1,000,000: 6.25 ZEC at height 1, 5.96e-6 at 6,000, 0.0
at 32,400, identical to the default.

**The treasury cannot be topped up.** Its own funding is coinbase, so whatever
`REGTEST_TREASURY_BLOCKS` buys at genesis (200 blocks ≈ 1,250 ZEC) is all it
will ever hold. That is roughly twenty `setup.sh` runs. When it runs dry the
error is `Insufficient balance ... including fee`, which reads like a wallet
bug and is really an exhausted faucet; rebuild the chain with
`docker compose down -v`.

A test that needs funds should call `common::regtest_harness::fund_test_account`
rather than rely on what `setup.sh` left, since sweep tests drain shared
accounts and test order would otherwise decide which of them has money.

Transparent coinbase cannot be used, and the reason is worth knowing before
writing a test against this harness. Spending transparent coinbase requires
`CoinbaseFilter::CoinbaseOnly`, which selects only outputs the wallet *knows*
are coinbase — knowledge that is the transaction's index within its block.
`GetAddressUtxos` reports txid, output index, value and height, but not that
index, so `tx_index` is NULL in the wallet database and every output is
conservatively treated as non-coinbase. A shielding proposal then fails with
`Insufficient balance (have 0)` while the wallet visibly holds hundreds of ZEC.

**The test seed holds shielded funds, not transparent UTXOs.** Tests written
against `ARGOS_REGTEST_TEST_T_ADDR` and a funded t-address will not find one.
There is no lightwalletd-only route to non-coinbase transparent funds on a
fresh chain; producing them would need a second, non-coinbase transaction from
a wallet the harness does not have.

## Running the integration tests

From the **repository root**:

```bash
cargo test --workspace --features argos-network -- --ignored
```

Both flags are required:

- `--features argos-network` enables the `argos-core` feature carrying
  everything the harness needs: regtest consensus parameters
  (`ArgosParams::Regtest`), the relaxed lightwalletd network validation, and
  acceptance of `uregtest`-encoded sweep destinations. All of it is compiled
  out of production builds, so a released binary has no code path that can
  retarget consensus parameters or bypass network validation.

  Both relaxations are anchored on `regtest_consensus_params_installed()` — a
  deliberate local act — rather than on the chain name the server reports, so
  a hostile server cannot talk its way into them by calling itself `regtest`.
- `--ignored` runs the `#[ignore]`-tagged C2 tests; default `cargo test`
  still skips them.

Without `--features argos-network`, the integration test file is gated out
by `#![cfg(feature = "argos-network")]` and compiles to an empty test
binary. CI runs the default form only.

Each integration test prints a `[regtest]` header noting the harness URL it
connected to, so a mid-test failure is easy to attribute to the stack vs to
Argos logic.

## The chain must be past the ZIP 212 grace period for PCZT tests

`an_imported_sapling_key_can_be_spent_via_pczt` builds its transaction
through the PCZT roles, and PCZT construction **requires ZIP 212 to be
fully enforced for outputs**. Enforcement is not simply "Canopy is active":
`zip212_enforcement` returns a *grace period* for the first
`ZIP212_GRACE_PERIOD` (32,256) blocks after Canopy activation, and the PCZT
builder rejects anything short of full enforcement with:

    PCZTs require that ZIP 212 is enforced for outputs

The regtest chain activates every upgrade at height 1, so the grace period
runs to height 32,257. A freshly-booted harness sits at a few hundred
blocks and is therefore *inside* the grace period, and this test fails for
a reason that has nothing to do with the code under test.

Mine past it once — the `zebrad-data` volume persists, so this is a
one-time cost per volume:

    # ~6 blocks/sec, so roughly 80 minutes from a fresh chain
    while [ "$(zebra_rpc getblockcount)" -lt 32400 ]; do
        zebra_rpc generate 500
    done

Nothing else in the suite needs this: the ordinary transaction builder
accepts the grace period, so the seed-based sweep tests pass on a short
chain. Only the PCZT path is affected.

**Do not** "fix" a ZIP 212 failure by relaxing the check or switching the
imported sweep off PCZT. PCZT is the only route that can spend a standalone
Sapling key at all — see `crates/zeck-core/src/imported_sweep.rs`.

## Teardown

```bash
cd tests/regtest
docker compose down -v        # -v wipes the named volumes too
```

Without `-v`, the named volumes (`zebrad-data`, `lwd-data`) persist between
runs, so the chain state survives a `down`/`up`. Re-running `setup.sh` against
an existing chain tops every test address back up from the treasury, so a
drained chain does not need `-v` — reach for it when the treasury itself is
exhausted, or when you want a genuinely clean slate.

## What this harness is not

- **It is not a fuzzing harness.** Fault injection (GoAway frames, malformed
  compact blocks, TLS-handshake failure, etc.) needs server-side cooperation
  — typically a custom lightwalletd build or a Mitm proxy. Those stubs in
  `crates/zeck-core/tests/regtest_integration.rs` will need additional
  scaffolding before their bodies can be implemented; the harness here just
  provides the baseline "two healthy services + a funded seed" foundation.
  (The network-resilience tests do now run against `FakeLightwalletd`, an
  in-process gRPC proxy — see `crates/zeck-core/tests/common/`. Note its proto
  is a *subset* of upstream: an RPC missing there is not a compile error, it is
  an `UNIMPLEMENTED` at runtime that fails a scan during setup. When upgrading
  `zcash_client_backend`, diff its `sync.rs` against that service definition.)
- **It is not for cross-platform verification.** docker-compose runs
  Linux containers regardless of host. macOS users still get the right
  test outcome but the in-container OS is Linux.
- **It is not a replacement for the manual C3 testnet smoke flow** documented
  in `docs/superpowers/test-plans/recovery-resilience.md`. Regtest validates
  Argos against a deterministic toy chain; testnet validates against the real
  Zcash p2p network and the public lightwalletd operators we depend on.

## Bare-metal alternative

If you already have `zebrad` + `lightwalletd` installed locally, you can skip
docker entirely. The integration tests only care about
`ARGOS_REGTEST_LIGHTWALLETD_URL` and a funded test seed. Configure your local
zebrad with the equivalent of `zebrad-regtest.toml` — the NU6.3 activation
height in particular must match `ArgosParams::regtest_all_active()` — boot
lightwalletd against it, run `setup.sh` with `REGTEST_ZEBRA_RPC_URL` pointed
at your node, then export the URL and run
`cargo test -p argos-core --features argos-network -- --ignored`.

## Status of the tests

`post_ironwood_sweep_is_accepted_by_the_node` is the harness's reason for
existing and runs green: it funds the seed, scans, sweeps, and asserts the
node accepted the result. Observed end to end — the sweep was signed with
consensus branch `37a5165b` and mined by Zebra. It funds itself, so it is
re-runnable without a manual top-up between runs.

The remaining network-resilience tests (GoAway frames, hostile compact blocks,
latency, reorg, DNS drift) predate the Zebra migration and were written against
a transparent-funded seed. See the funding section above for why that funding
shape is no longer available; they need either re-pointing at shielded funds or
a different funding route.

### Exact matched transparent key recovery

After preparing the funded harness above, run the index-997 discovery and
recovery regression with:

```sh
ARGOS_REGTEST_LIGHTWALLETD_URL=http://127.0.0.1:9067 cargo test -p argos-core --features argos-network --test regtest_integration address_match_index_997_recovers_and_sweeps_funded_utxos -- --ignored --nocapture --test-threads=1
```

The test funds the public harness seed's account-0 receive address at index
997, searches indices 0–999, imports the matched key, closes discovery, scans
its UTXOs, and proposes and submits a sweep. It exercises the backend services
used by the GUI; native GUI interaction still requires a separate check.

For the corresponding internal Sapling matched-recovery check, use the test
filter `internal_sapling_match_recovers_and_sweeps_mined_note` with the same
command. It funds an internal receiver at account 4 and a nonzero diversifier,
then requires the sweep to be mined. Both tests use public synthetic seeds.

For ordinary seed recovery without known-address discovery, use the test
filter `automatic_transparent_range_recovers_low_and_high_indices`. It funds
account-0 receive indices 7 and 997, scans one shielded account with the default
transparent range, and checks that the mined sweep consumes both addresses'
UTXOs. The explicit range must survive resume before sweeping.


## Dedicated NU7 qualification

The `nu7` profile has independent state, RPC `127.0.0.1:18252`, and
lightwalletd `127.0.0.1:9077`. Its NU7 activation is **32,500**, matching
`qualified_params_at(32_500)` in `nu7_readiness.rs`. Earlier upgrades activate at 1.
The height is after ZIP 212 enforcement at 32,257 so PCZT experiments can be
performed on either side. Mining to that height can take over an hour.

For a quick branch-boundary check, `nu7-fast` uses a separate volume,
activation height **10**, RPC `127.0.0.1:18262`, and lightwalletd
`127.0.0.1:9087`. ZIP 212 is not enforced at this height; it provides no PCZT
qualification evidence.

```sh
cd tests/regtest
docker compose --profile nu7-fast up -d zebrad-nu7-fast lightwalletd-nu7-fast
ARGOS_NU7_PROFILE=fast ./nu7.sh before   # mines exactly to height 9
cd ../..
CARGO_INCREMENTAL=0 RUSTFLAGS='' CARGO_TARGET_DIR=/private/tmp/argos-nu7-target \
  cargo +1.89 test -p argos-core --features argos-network --test nu7_readiness \
  private_ -- --ignored --nocapture --test-threads=1
```

The node test starts at height 9 and mines blocks 10 and 11. A repeat run
at height 10 or 11 reuses the accepted blocks and mines only any missing
block through 11; it never rewinds or deletes state. It parses the actual
node's complete serialized blocks and checks every embedded transaction's
branch before, at, and after activation. The separate proxy test requires
lightwalletd to report branch `77190ad9` and serve compact block 10. This is actual
node acceptance of synthetic regtest coinbase blocks, **not evidence of
funded transparent, Sapling, Orchard, Ironwood, or PCZT sweep acceptance**.
Those recovery gates require separately prepared synthetic regtest balances
and observed mined sweep transactions on the full profile.

For the full profile, use `docker compose --profile nu7 up -d zebrad-nu7
lightwalletd-nu7` and `./nu7.sh before` to stop at 32,499. `./nu7.sh at` and
`./nu7.sh after` are explicit manual controls for either profile; set
`ARGOS_NU7_PROFILE=fast` to address the fast profile. The node test supports
reusing the three retained boundary blocks while the tip remains at 9-11.
The controller refuses to rewind or delete an existing chain. Use separate,
intentionally created volumes for repeated boundary rehearsals. It always
addresses a fixed private loopback RPC, never a public endpoint. It performs
no funding and never starts a VM automatically.

Offline qualification runs without Docker:

```sh
CARGO_INCREMENTAL=0 RUSTFLAGS='' CARGO_TARGET_DIR=/private/tmp/argos-nu7-target \
  cargo +1.89 test -p argos-core --features argos-network --test nu7_readiness
```

These tests pin both production activation heights and branch `77190ad9`,
parse independently encoded empty v5/v6 wire transactions, reject placeholder
branches/truncation, preserve the real branch through PCZT creation/encoding,
check the actual builder's 40/120-block expiry behavior, preserve the legacy
regtest schedule, and reopen a
persisted account across the local activation. The retained pre-NU7 SQLite
fixture additionally verifies migration from the old SDK family and a second
reopen; see [fixture reproduction](legacy-wallet-db/README.md). Empty parser
fixtures and empty wallet databases hold no notes or spendable value.

The release/image pins were checked against primary sources on 2026-10-26:

- [Zebra v7.0.0 release](https://github.com/ZcashFoundation/zebra/releases/tag/v7.0.0)
  activates the official NU7 branch and changes the Zebra state database to
  v29. Preserve any needed v28 node volume before its first upgrade; Zebra6
  cannot open a migrated v29 state directory.
- [Zebra image manifest](https://hub.docker.com/v2/repositories/zfnd/zebra/tags/7.0.0):
  `sha256:a70d2be8ffef3a4b6e37355724e36a0e6c1838e46baa28bfb216739f00cf2d34`
  (amd64 and arm64).
- [lightwalletd v0.6.0 release](https://github.com/zcash/lightwalletd/releases/tag/v0.6.0)
  has no functional changes since v0.5.5 and includes updated Go TLS trust.
- [lightwalletd image manifest](https://hub.docker.com/v2/repositories/electriccoinco/lightwalletd/tags/v0.6.0):
  `sha256:abc8199dae800e050415a3459f71c7850aeefeb1ca6a681e9b9eda7249ce8613`
  (amd64 only, hence explicit emulation on Apple Silicon).


The full profile's funded sweep/PCZT qualification remains a release gate.
The current funding binary installs the legacy pre-NU7 local schedule, and
its treasury workspace is under `$TMPDIR/argos-regtest-treasury`. A full
rehearsal must use its own `TMPDIR`, install the qualified NU7 schedule in
any post-activation funding process, and demonstrate actual mined recovery
transactions. Merely booting this profile does not satisfy that gate.

Local evidence on 2026-10-26: the pinned Zebra 7.0.0 node accepted blocks
9 (`37a5165b`), 10 and 11 (`77190ad9`); the Rust block parser consumed each
complete serialized block. The amd64 lightwalletd container started and
ingested the pre-activation tip, then suffered a Go `net/http` runtime
SIGSEGV under emulation before the proxy check. This did not erase the
node's accepted blocks. A native arm64 proxy was built from the official
[v0.6.0 tag](https://github.com/zcash/lightwalletd/tree/v0.6.0), commit
`e7436d2adb9ab5828eb8a27de534e16218841fc2`, with installed
`go1.27.3 darwin/arm64`; its startup reported height 11 and branch `77190ad9`.
The proxy gate accepts native endpoint `http://127.0.0.1:9088` through
`ARGOS_NU7_LIGHTWALLETD_URL` (only this or the default dedicated loopback
9087 endpoint is permitted). The native binary is a local qualification
artifact, while Compose and CI retain the official digest-pinned image.

Run the exact same proxy test against a native fallback with:

```sh
ARGOS_NU7_LIGHTWALLETD_URL=http://127.0.0.1:9088 \
  CARGO_INCREMENTAL=0 RUSTFLAGS='' CARGO_TARGET_DIR=/private/tmp/argos-nu7-target \
  cargo +1.89 test -p argos-core --features argos-network --test nu7_readiness \
  private_ -- --ignored --nocapture --test-threads=1
```

Final local verification on 2026-10-26: **7 offline tests passed** (the two
live tests were ignored in that run), then **both live tests passed** against
the pinned Zebra container and native official-tag proxy. The live output
recorded branch `37a5165b` at block 9, `77190ad9` at blocks 10 and 11, and
successful retrieval of NU7 compact block 10 through lightwalletd. The
pre-NU7 SQLite fixture retained its original checksum after migration tests.
Logs were retained at `/private/tmp/argos-nu7-qualification-offline-final.log`
and `/private/tmp/argos-nu7-qualification-live-final.log`. This qualifies the
listed branch, encoding, database, expiry, block and proxy boundaries; the
full funded sweep/PCZT release gate above remains unexecuted.
