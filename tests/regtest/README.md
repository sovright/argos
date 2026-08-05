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

Both images are pinned (`zfnd/zebra:6.2.3`, `electriccoinco/lightwalletd:v0.5.1`)
rather than tracking `latest`: the activation heights and consensus rules under
test are version-sensitive, and a silently updated node would change what the
tests mean. lightwalletd v0.5.1 is the first release carrying the Ironwood
compact-block fields the client backend expects to decode.

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
