# Recovery resilience test plan

> **Status:** This plan records the original seed-recovery resilience work.
> Current coverage for wallet-file import, standalone Sapling keys, imported-key
> sweeping, and generally available Sprout recovery is maintained in
> [`TESTING.md`](../../../TESTING.md).

Companion to the sweep + donation tests already on PR #66. This plan covers
everything *outside* sweep + donation that determines whether a real user
recovers their funds: the scan side, the network resilience layer, resume /
crash robustness, workspace integrity, and the long-running scan behaviour.

The structure follows the [Argos threat model](../../THREAT_MODEL.md) — each
test maps to a threat row (`T-S*`, `T-N*`, `T-L*`, `T-B*`) or to a stated
fund-recovery invariant.

> **Scoping note:** sweep + donation edge cases (donation threshold,
> two-pass fee convergence, donation memo, donation `Err`-fallback, GUI form
> reset) live on PR #66's own test surface. This plan is the parallel branch
> for everything that isn't sweep + donation, so reviews stay focused.

## Categories

| Category | Where it runs | How to invoke |
|---|---|---|
| **C1** Unit tests, no network | CI on every push/PR | `cargo test --workspace` |
| **C2** Integration tests against a local regtest node | Local only, opt-in | `cargo test --workspace --features argos-network -- --ignored` after booting `tests/regtest/`. The `argos-network` feature relaxes `validate_lightwalletd_network` for the local chain; without it Argos refuses to talk to a regtest server. |
| **C3** Testnet smoke flow | Local, manual; required before a release tag | Documented checklist in this file |
| **C4** Mainnet small-amount gate | Manual, one-off pre-release | Section below |

CI today is C1 only. C2 is opt-in by design — the regtest node is heavy to
boot and CI runners don't keep it warm. C3/C4 are humans driving the app.

## Test inventory

### Seed handling and derivation (T-S1..T-S3)

| ID | Test | Category | Status |
|---|---|---|---|
| R-D1 | `valid_24_word_seed_validates` | C1 | ✅ in `derivation.rs` |
| R-D2 | `wrong_word_count_rejected` (23 words) | C1 | ✅ in `derivation.rs` |
| R-D3 | `non_bip39_word_rejected` | C1 | ✅ in `derivation.rs` |
| R-D4 | `words_with_whitespace_padding_validated` | C1 | ✅ in `derivation.rs` |
| R-D5 | Empty seed string rejected | C1 | ➕ added in this branch |
| R-D6 | Whitespace-only seed rejected | C1 | ➕ added in this branch |
| R-D7 | Seed with embedded ASCII control characters rejected | C1 | ➕ added in this branch |
| R-D8 | Very long input (1MB random bytes) rejected without panic | C1 | ➕ added in this branch |
| R-D9 | 24 valid words with deliberately broken checksum rejected | C1 | ➕ added in this branch |
| R-D10 | Unicode garbage rejected without panic | C1 | ➕ added in this branch |

### Address validation (T-F1 / T-N2 / T-B4 — destination integrity)

| ID | Test | Category | Status |
|---|---|---|---|
| R-A1 | `valid_unified_address_accepted` | C1 | ✅ |
| R-A2 | `transparent_address_rejected` | C1 | ✅ |
| R-A3 | `sapling_address_rejected` | C1 | ✅ |
| R-A4 | `garbage_string_rejected` | C1 | ✅ |
| R-A5 | `empty_string_rejected` | C1 | ✅ |
| R-A6 | Very long random string rejected without panic | C1 | ➕ added in this branch |
| R-A7 | UA prefix in upper-case rejected (case-sensitive Bech32m) | C1 | ➕ added in this branch |
| R-A8 | UA with embedded whitespace rejected | C1 | ➕ added in this branch |
| R-A9 | ZIP-321 payment URI (`zcash:u1…`) rejected as a destination | C1 | ➕ added in this branch |

### Lightwalletd endpoint integrity (T-N1 / T-N2)

| ID | Test | Category | Status |
|---|---|---|---|
| R-N1 | `endpoint_validation_rejects_remote_plaintext_http` | C1 | ✅ |
| R-N2 | `endpoint_validation_allows_loopback_http_for_local_testing` | C1 | ✅ |
| R-N3 | `network_validation_rejects_wrong_chain` | C1 | ✅ |
| R-N4 | URL without scheme rejected | C1 | ➕ added in this branch |
| R-N5 | `ftp://` and `file://` schemes rejected | C1 | ➕ added in this branch |
| R-N6 | IPv6 loopback `[::1]` over http allowed (local testing) | C1 | ➕ added in this branch |
| R-N7 | URL with embedded credentials (`https://u:p@host:port`) — documented behaviour | C1 | ➕ added in this branch |
| R-N8 | GoAway frame mid-scan triggers reconnect, no duplicate emissions | C2 | ✅ implemented (FakeLightwalletd injects `Status::unavailable("h2 protocol error: GoAway ...")` after N blocks; asserts baseline-equivalent `synced_to_height` and discovery dedup) |
| R-N9 | Hostile compact block rejected, scan errors cleanly | C2 | ✅ implemented (FakeLightwalletd XORs `prev_hash` at a configured height; asserts scan ends in Error not panic, then a fresh-workspace rescan reaches baseline) |
| R-N10 | All configured endpoints unreachable surfaces a clean error | C2 | ✅ implemented |
| R-N11 | TLS handshake failure surfaced without falling back to plaintext | C2 | ✅ implemented (TCP accepts, no TLS frames sent; cert-specific failures deferred to a TLS-cert fixture) |
| R-N12 | Multi-endpoint fallback respects order with one slow endpoint | C2 | ✅ implemented |
| R-N13 | Sustained high latency (e.g. 300 ms RTT) — scan completes; ETA / stall-detection sane | C2 | ✅ implemented (FakeLightwalletd `latency(Duration)`; baseline-equivalence assertion) |
| R-N14 | Bandwidth throttle (e.g. 256 kbps) — `ProgressPoller` does NOT flag a false stall | C2 | ✅ implemented (FakeLightwalletd `bandwidth_bytes_per_sec`; asserts no `"stalled"` substring during scan) |
| R-N15 | Hung stream / dead peer — TCP up, no h2 frames — surfaced as Err within bounded time | C2 | ✅ implemented (stall watchdog at `scan.rs::stall_watchdog`, 60 s no-advance trips with `"h2 protocol error"` so the existing retry matcher catches it; FakeLightwalletd `hang_after_blocks(N)` drives the test) |
| R-N16 | DNS resolution drift between retries (mainnet endpoint resolves to a different IP mid-scan) | C2 | ✅ implemented (`TcpFailoverProxy` fronts two `FakeLightwalletd` backends; first connection hits fake_a (closes after 3 blocks), retry hits fake_b; asserts baseline `synced_to_height`) |
| R-N17 | Captive-portal-shaped MitM — TLS-stripping HTTP 200 — surfaced as Err, not silent success | C2 | ✅ implemented (`serve_captive_portal_shim` writes raw HTTP 200) |
| R-N18 | Asymmetric loss — outbound bytes flow, return path silently dropped | C2 | ✅ implemented (`serve_asymmetric_loss_proxy` drops upstream→client bytes at the application layer after N bytes on conn #1 — no `tc netem` / sudo required; stall watchdog catches the stall, retry recovers on clean conn #2) |
| R-N19 | Long sleep + resume on different network (wifi → cellular) | C3 manual | 🔲 documented checklist below |

### Workspace integrity (T-L1 / T-L3 / T-L4)

| ID | Test | Category | Status |
|---|---|---|---|
| R-W1..R-W20 | Keying isolation + metadata round-trips | C1 | ✅ 20 tests in `workspace.rs` |
| R-W21 | Created workspace directory has mode `0o700` (Unix) | C1 | ➕ added in this branch |
| R-W22 | Wallet DB files have mode `0o600` (Unix) | C1 | ➕ added in this branch |
| R-W23 | Workspace path with unicode characters round-trips correctly | C1 | ➕ added in this branch |
| R-W24 | Two argos instances on same workspace — first cancels, second proceeds | C2 | ✅ implemented |
| R-W25 | Workspace deleted between scan and sweep — clean error | C2 | ✅ implemented |
| R-W26 | Workspace permissions tampered (chmod 0444) — clean error | C2 | ✅ implemented |

### Scan-side resilience (T-N3 / T-N4 / T-N5)

| ID | Test | Category | Status |
|---|---|---|---|
| R-S1..R-S20 | Gap-limit triggering + discovery dedup | C1 | ✅ 20 tests in `scan.rs` |
| R-S21 | Birthday=0 normalised to Sapling activation | C1 | ➕ added in this branch |
| R-S22 | Birthday far above chain tip rejected | C1 | ➕ added in this branch |
| R-S23 | `gap_limit` 0/1/500/501 boundary in `validate_scan_config` | C1 | ➕ added in this branch |
| R-S24 | `num_accounts` 0/1/500/501 boundary | C1 | ➕ added in this branch |
| R-S26 | Reorg during scan invalidates and re-scans the reorganised range | C2 | ✅ implemented |
| R-S27 | Crash mid-scan — resume picks up from `fully_scanned_height` | C2 | ✅ implemented (subprocess SIGKILL of `argos-scan-helper` past block 50, resume run must reach baseline `total_zatoshis`) |
| R-S28 | Machine sleep during scan surfaces `sleep_event` | C2 | 🔲 stub (manual on a real machine — laptop lid close) |
| R-S29 | Crash mid-broadcast — resume detects broadcast tx in wallet DB | C2 | ✅ implemented (setup.sh funds 2 accounts; `argos-sweep-helper` with `--pause-millis-between-broadcasts 30000` sleeps in the gap; SIGKILL; resume run produces exactly 1 broadcast, proving no double-spend) |

### Long-running scan behaviour (T-N4 / G2)

| ID | Test | Category | Status |
|---|---|---|---|
| R-L1 | Full mainnet scan from Sapling activation to tip | C3 manual | Checklist below |
| R-L2 | Scan crosses sandblasting era — `in_sandblasting_zone` flag toggles | C3 manual | Checklist below |
| R-L3 | Scan with `gap_limit = 500` derives all 500 accounts | C3 manual | Checklist below |
| R-L4 | ETA-tracker behaviour mid-batch (no rate updates between commits) | C3 manual | Checklist below |

### Birthday subsystem (already has C1 coverage; one gap)

| ID | Test | Category | Status |
|---|---|---|---|
| R-B1..R-B12 | Date↔height conversion edge cases | C1 | ✅ 12 tests in `birthday.rs` |
| R-B13 | Auto-detect birthday probe surfaces FVK-derived addresses to server — privacy implication exposed in the result | C1 | ➕ added in this branch |

## Bad-network coverage gap (R-N13..R-N19)

Argos's real users are recovering funds on whatever connection they have — coffee-shop wifi, hotel networks, 4G hotspots, captive portals, VPN-tunneled corporate networks. The implemented R-N* rows cover endpoint-validation correctness and a handful of mid-stream failure modes (GoAway, hostile block, all-down, TLS-handshake). They do **not** cover the common-but-painful slow-or-flaky-link cases that determine whether a real recovery succeeds.

This section enumerates that gap and what each row needs to land.

### What's already there

The `FakeLightwalletd` fixture (`crates/zeck-core/tests/common/fake_lightwalletd.rs`, landed in PR #88, fault-injection in PR #91) already exposes a builder API with three knobs: `close_stream_after_blocks`, `inject_hostile_block_at_height`, and `latency` (the last is wired into the builder but applied nowhere — explicitly `TODO(bad-network)` in the source). Proxy-mode forwards every RPC to the real regtest harness, so we can layer new faults on top of a real chain without synthesising one ourselves.

### Per-row scoping

| Row | What the test asserts | What the fixture needs |
|---|---|---|
| R-N13 sustained latency | Scan completes; `EtaTracker` warmup behaviour stays sane; no spurious "stalled" message when bytes are still flowing | Wire the existing `latency(Duration)` knob into `get_block_range` (and `get_taddress_txids`) as a `tokio::time::sleep` before each emitted item. ~15 lines. |
| R-N14 bandwidth throttle | `ProgressPoller`'s "no advance for N seconds" heuristic does NOT flag a stall when blocks are still arriving, just slowly. Sweep proposal still composable on completion. | New `bandwidth_bytes_per_sec` knob. Implementation: per-byte token bucket on the outbound `mpsc::Sender<CompactBlock>` — wrap each block send with `tokio::time::sleep(block_bytes / rate)`. ~30 lines including a small `TokenBucket` helper. |
| R-N15 hung-stream / dead peer | A connection that accepts TCP, completes h2 handshake, then sends zero block frames must surface as Err within a bounded timeout (today: nothing in `run_wallet_sync_with_retry` enforces this — see #88's deferred discussion). | New `hang_after_blocks(N)` knob. After emitting N blocks, the spawned forwarder task simply parks itself indefinitely without sending or closing. Tests the absence of an upstream per-stream watchdog as well as Argos's own timeouts. ~20 lines. |
| R-N16 DNS resolution drift | Mid-scan, the lightwalletd URL's hostname starts resolving to a different IP. Argos's retry loop reconnects; if the new IP is the harness, the scan completes; if the new IP is unreachable, the retry budget exhausts cleanly. | No fixture change — drive via a hosts-file flip mid-test, OR a per-loopback-port redirect using two FakeLightwalletds at different ports and a hostname that maps to one then the other. The hosts-file path needs root; the dual-port path is harness-only and cleaner. **Open: pick which is simpler to maintain in CI documentation.** |
| R-N17 captive-portal MitM | A peer that accepts the connection and responds with HTTP 200 (typical captive-portal hello page) instead of an h2 frame. Argos must surface this as Err, not silently treat it as a successful empty response. | New helper: spawn a `tokio::net::TcpListener` that, on accept, writes a `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n` and closes. Configured via a `serve_http_instead_of_grpc()` builder method. ~25 lines. |
| R-N18 asymmetric loss | Outbound bytes from Argos reach the server; the server's responses are dropped before they reach Argos. Argos must surface Err within a bounded time rather than hanging indefinitely. | On Linux, drive via `tc netem` against the test's loopback (`sudo tc qdisc add dev lo root netem loss 100% direction ingress` for the listener port). On macOS, `pfctl` equivalent. This row is a strong candidate for **C3 manual on Linux** (since `tc` needs sudo) and a documented skip on macOS until someone wires up `pfctl`. |
| R-N19 sleep + different network | The mid-scan GUI is suspended for an extended period and resumes on a different network (wifi → cellular). Resume must complete without re-scanning blocks already covered. | **C3 manual.** Not automatable from `cargo test`; requires a real laptop with two NICs to be lid-closed and lid-opened across a hotspot toggle. |

### Implementation order

R-N13 / R-N14 / R-N15 / R-N17 all touch the same `FakeLightwalletd` builder + `get_block_range` body — natural single follow-up PR. R-N16 and R-N18 each need different infrastructure (DNS plumbing, OS-level traffic shaping) and warrant their own PRs. R-N19 stays manual.

The single-PR cluster is roughly **150–200 lines of fixture code plus 4 tests**, all gated `#[ignore]` so CI is unaffected.

### What no automatable test can buy us

Whether `run_wallet_sync_with_retry` handles **zec.rocks's actual production GoAway emission pattern** is, in the end, a C3 question — there's no synthetic substitute that's truly equivalent. The fixture verifies the contract our retry loop is written against; production verifies the contract zec.rocks emits. The gap between those two is the gap a long-running monitoring job would cover, not `cargo test`.

## Manual checklists

### C3 — testnet smoke flow

Run before any release candidate.

- [ ] Scan a known funded testnet seed end-to-end; reach the sweep proposal screen.
- [ ] Verify proposal numbers match a `zcash-cli`/`zebrad` query against the same addresses.
- [ ] Sweep to a testnet UA; confirm the txid on-chain.
- [ ] Restart the GUI mid-scan, re-open with the same seed/destination/birthday; confirm resume.
- [ ] Disconnect network mid-scan for 30s, reconnect; confirm scan resumes without re-scanning blocks already covered.
- [ ] Close the GUI lid (laptop sleep) for 1 minute mid-scan; confirm `sleep_event` populated when resumed.
- [ ] Configure two lightwalletd endpoints, the first deliberately unreachable; verify fallback to the second.
- [ ] **R-N19** — Start a long scan on wifi, lid-close the laptop, switch to a cellular hotspot, lid-open. Confirm the scan resumes without re-scanning blocks already covered and the `sleep_event` is populated.
- [ ] **R-N18 (Linux only, optional)** — Run a scan against the harness; mid-scan, apply `sudo tc qdisc add dev lo root netem loss 100% direction ingress` against the lightwalletd port to simulate one-way loss. Confirm Argos surfaces a transport error within a bounded time rather than hanging silently.

### C4 — mainnet small-amount gate

Required before tagging `v0.1.0`.

- [ ] Recover a seed holding 0.01 ZEC or less. Sweep to a UA we control. Confirm txid on a block explorer.
- [ ] Repeat with `--donation-rate 0.10` set (sweep + donation tests on PR #66 cover the units; this is the integration gate).
- [ ] Decrypt the donation memo with the donation address's viewing key — confirms the off-chain receipt pipeline is real.

## Regtest harness (C2)

The C2 integration tests need a Zcash regtest node and a funded regtest seed.
Out of scope for this PR — the stubs in `crates/zeck-core/tests/regtest_integration.rs`
mark their preconditions explicitly with `#[ignore]` and require:

- A running `zcashd` or `zebrad` in regtest mode listening on a known port.
- A `lightwalletd` instance pointed at that node.
- An environment variable `ARGOS_REGTEST_LIGHTWALLETD_URL` set to the
  `https://localhost:PORT` endpoint.
- A funded seed available in the regtest node — generated and miner-funded
  by a helper script (out of scope for this PR; a separate "regtest harness"
  follow-up sets that up).

When all three are present, run:

```bash
cargo test --workspace --features argos-network -- --ignored
```

CI deliberately does not run these — boot cost is too high for per-PR turnaround.

## Out of scope here

Everything related to sweep + donation lives on PR #66 and is not duplicated
in this plan. See the test counts there (121 passing as of `19731e3`).

Threat-model items that have no automatable test today and stay manual /
documented:

- T-N6 (sweep on-chain consolidation pattern) — inherent to recovery, not testable.
- T-S4 (clipboard leak surface) — bounded by the user's OS clipboard manager.
- T-SC* (supply-chain) — covered by CI tooling (cargo-deny / cargo-vet / zizmor).
- T-SC4 (Rust toolchain compromise) — out of practical reach.
- T-SC6 (SLSA provenance) — landed via PR #71.
