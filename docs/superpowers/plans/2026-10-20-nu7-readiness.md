# NU7 Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep Argos scanning and recovering supported funds across NU7, and give Sprout holders an accurate deadline and safe cutoff for recovery.

**Architecture:** Keep consensus parameters and transaction rules in the coordinated upstream Zcash stack. Add one shared Sprout eligibility check around the existing sweep pipeline, make the historical-block client's protocol version network-specific, and extend the isolated node harness to exercise activation. CLI and GUI consume the same core decisions.

**Tech Stack:** Rust, librustzcash, PCZT, SQLite, Tokio P2P, Tauri/JavaScript, Zebra, lightwalletd, Docker Compose, GitHub Actions.

**Spec:** [ZIP 259: deployment](https://zips.z.cash/zip-0259), [ZIP 2003: v4 retirement](https://zips.z.cash/zip-2003), and [ZIP 218: spacing and shielded limits](https://zips.z.cash/zip-0218). These are the protocol requirements for this plan; recheck their status and constants before implementation and release.

**Status:** Planning only. No compatibility changes, node qualification, recovery broadcasts, or releases are completed by this document.

**Baseline:** `sovright/argos` main commit `89c1a10b4ae9f8718378d6992e62ac5097824c51` (v1.5.2), inspected 2026-10-20. Source anchors below refer to that commit, not an older local checkout.

## Global constraints

- NU7 branch ID: `0x77190AD9`; testnet activation: `4_465_026`; required P2P versions: testnet `170_180`, mainnet `170_190` ([ZIP 259](https://zips.z.cash/zip-0259)).
- Mainnet activation height remains unassigned in the deployment ZIP at this inspection. Height `3_543_405` is proposed in [zcash/zips#1405](https://github.com/zcash/zips/pull/1405) (open as of 2026-10-21), and November 5, 2026 is the [announced target](https://forum.zcashcommunity.com/t/nu7-timeline/57655); neither is an implementation constant until that PR merges, at which point Task 1 can adopt the height directly. Record the final authoritative height and supporting node/library versions before releasing a mainnet readiness claim. Do not invent a height or silently interpret an unassigned height as verified compatibility.
- NU7 retains v5/v6 and rejects every v4 transaction. Sprout has no supported post-NU7 spend format; changing a branch ID cannot restore it. Remaining funds are unspendable under these rules, not proven burned or guaranteed recoverable later ([ZIP 2003](https://zips.z.cash/zip-2003)).
- Construction decisions use the candidate next block (`tip + 1`) with checked arithmetic. Recheck eligibility after expensive proving and before broadcast; retain historical decoding independently of spend eligibility.
- Target spacing becomes 25 seconds. The recommended default expiry becomes 120 blocks after target height for supported post-activation transactions; explicit user expiry settings retain their meaning. Do not extend Sprout validity across activation ([ZIP 218](https://zips.z.cash/zip-0218)).
- Respect both the global shielded budget of 330 and per-pool limits (Sapling inputs plus outputs <= 300; Orchard actions <= 330; Ironwood actions <= 330), including padding and change. Preserve existing anchor/confirmation choices unless separately justified ([ZIP 218](https://zips.z.cash/zip-0218)).
- Preserve mainnet/testnet validation and compile out `argos-network` overrides in release builds. Regtest RPC remains loopback-only; use disposable test data and no real wallet secrets.
- Node acceptance, mempool presence, and canonical mined confirmation are different evidence. Preserve journal records and stop on ambiguous broadcast transport outcomes; never retry automatically based solely on uncertainty.
- NSM accounting and fee distribution belong to consensus nodes. Do not invent an extra wallet fee payment, transaction field, or NSM burn transaction.

## Review focus

1. A proof starts before activation but finishes after it: stop before broadcast and retain prior results (Task 2).
2. A server is stale, on the wrong chain, or unavailable: surface uncertainty; a height/version advertisement alone is not readiness evidence (Tasks 2, 3, 6).
3. A large sweep passes per-pool limits but exceeds the combined budget, or padding pushes it over a limit: split proposals without losing funds or looping (Task 4).
4. A previously accepted Sprout transaction never mines before activation: retain the broadcast record while explaining that recovery did not complete (Tasks 2, 6).
5. A resumed database or reorganized chain crosses activation: reconcile balances and spent state without duplicates or fabricated success (Tasks 5, 6).

## Current gaps and file map

| Area | Baseline evidence | Planned ownership |
| --- | --- | --- |
| Protocol stack | `Cargo.toml:75-94`; `Cargo.lock` locks protocol 0.10.1, primitives 0.30.0, backend 0.24.0-rc.4, SQLite 0.22.0-rc.4. The locked protocol has experimental NU7 behind a cfg, placeholder branch ID `0xffffffff`, and no activation heights. | Task 1: coordinated versions, provenance, branch/height tests |
| Sprout sweep | `sprout_spend.rs:728` assembles v4; `sprout_sweep.rs:1002-1026` already refreshes tip per note, but lacks the NU7 cutoff. `EXPIRY_DELTA` is 40. | Task 2: shared cutoff, UI/CLI messages, pending-state reporting |
| Historical P2P | `p2p/peer.rs:50` advertises 170160. `p2p/block.rs` delegates transaction decoding to upstream. | Task 3: network-specific advertisement and real historical block qualification |
| Ordinary sweeps | `service.rs` delegates proposals to upstream; `transparent_recovery.rs` uses a height-aware builder; `imported_sweep.rs` drives PCZT and circuit selection. | Task 4: expiry, action budgets, supported-pool regression tests |
| Private network | `workspace.rs` and `tests/regtest/zebrad-regtest.toml` stop at NU6.3. Compose pins Zebra 6.2.3 and lightwalletd 0.5.1. Its active Sprout profile uses zcashd because Zebra cannot generate pre-Canopy templates; `zebrad-sprout.toml` is not wired into it. | Task 5: qualify a Sprout chain bootstrap, delayed NU7 activation, and node-accepted integration tests |
| Release | Current CI tests do not establish NU7 compatibility. | Task 6: testnet receipts, platform checks, release evidence |

All Rust filenames in the table are under `crates/zeck-core/src/` unless otherwise specified. Use function names to relocate anchors after earlier tasks change line numbers.

## Delivery order and dependencies

Ship Task 2's factual Sprout warning copy first; it does not depend on dependency upgrades or a final mainnet height. Its executable cutoff depends on Task 1's authoritative parameters. Task 3's wire-version change is independent; its full parsing qualification uses Task 1's upgraded library. Tasks 4 and 5 depend on Task 1; Task 6 depends on all preceding work. Keep these as focused implementation PRs rather than one release-sized diff.

Use a bounded implementation/review assignment for each independent area, with stronger reasoning for consensus, broadcast, and accounting decisions. Reassess assignments when upstream API changes or test failures add uncertainty. Verify agent results before integration.

### Task 1: Adopt and pin a NU7-aware protocol stack

**Files:** Modify `Cargo.toml`, `Cargo.lock`, `crates/zeck-core/src/workspace.rs`; add `crates/zeck-core/tests/nu7_parameters.rs`; update `supply-chain/` audit records only for actual dependency changes.

**Interfaces:** Preserve `ArgosParams: Parameters` and `consensus_network(ZeckNetwork)`. Later tasks obtain `NetworkUpgrade::Nu7` and `BranchId::Nu7` from the upstream crates, not duplicated numeric mappings.

- [ ] Write `nu7_parameters` tests asserting branch round-trip `0x77190AD9`, public testnet activation `4_465_026`, NU6.3 immediately before activation, and NU7 at/after it. Explicitly assert the authoritative mainnet schedule when assigned; while unassigned, assert `None` and mark mainnet qualification pending.
- [ ] Run `cargo test -p argos-core --test nu7_parameters`; confirm the baseline fails for the missing production NU7 behavior.
- [ ] Select compatible released versions of protocol/primitives/proofs/backend/SQLite/keys/transparent/PCZT/Orchard. Record versions, source revisions, and upstream NU7 support evidence in the PR. An RC label or enum's existence alone is insufficient. If no suitable published set exists, report the exact missing components; any temporary source pin must be immutable, reviewed, and recorded as a release exception.
- [ ] Update the stack together and adapt API changes while retaining recovery data and pool coverage. Add the upstream NU7 field to feature-gated local parameters, keeping existing profiles pre-NU7 unless a test explicitly activates it.
- [ ] Rerun parameter tests, `cargo check --workspace --locked`, `cargo test --workspace --locked`, and `cargo vet --locked`. Resolve actual audit gaps without broad trust exemptions. Commit this deliverable independently.

**Exit evidence:** Exact dependency set, authoritative constants, passing parameter tests and existing recovery regressions; any missing mainnet assignment remains a named release gate.

### Task 2: Warn Sprout holders and enforce the recovery deadline

**Files:** Create `crates/zeck-core/src/nu7.rs`; modify `lib.rs`, `sprout_sweep.rs`, `sprout_spend.rs`, `crates/zeck-cli/src/main.rs`, `gui/src-tauri/src/commands.rs`, `gui/src/main.js`, `gui/src/index.html`, `tests/gui/wallet_sprout_preview.test.cjs`, `README.md`, and `site/guide.html`.

**Interfaces:** Add `pub fn ensure_sprout_spend_allowed(params: &impl zcash_protocol::consensus::Parameters, tip: zcash_protocol::consensus::BlockHeight) -> crate::ZeckResult<()>` in `nu7.rs`. It rejects overflow or NU7 active at `tip + 1`, using upstream parameters. The CLI/GUI use the core result; they do not maintain separate activation arithmetic. Unassigned mainnet activation remains visibly unknown until Task 1 resolves it.

- [ ] Land warning copy first: Sprout spends require a v4 transaction mined before activation; broadcast alone is insufficient. Show network and known activation height, or explicitly say the mainnet height is awaiting assignment. Recommend starting recovery promptly without promising inclusion. Correct `sprout_spend.rs`'s unconditional statement that v4 remains valid. Keep scan/export/reporting available after cutoff.
- [ ] Add failing `nu7::tests` with a local activation at `A`: tip `A-2` permits candidate `A-1`; tip `A-1` rejects candidate `A`; tip `A` rejects; overflow fails. Cover unassigned activation explicitly without claiming mainnet readiness.
- [ ] Extend `sprout_sweep::tests` fake-node/build tests: cutoff before proving invokes neither build nor send; a proof crossing activation invokes build but not send; a failed post-proof tip read sends nothing; already completed notes remain in the result; a transport-ambiguous send stops without another broadcast or invented journal entry.
- [ ] Run `cargo test -p argos-core nu7` and `cargo test -p argos-core sprout_sweep::tests` to observe the failures, then implement the helper and call it before each proof and immediately before sending. Preserve the existing per-note tip refresh.
- [ ] Bound v4 expiry to the final pre-NU7 inclusion window using the node's verified expiry-height semantics. Add a last-valid-block test before choosing the exact clamp; do not apply the post-NU7 120-block default to Sprout. Preserve network identity validation and surface stale-tip uncertainty instead of trusting an advertised height as consensus proof.
- [ ] Add GUI/CLI assertions for warnings and cutoff results. Distinguish accepted/pending transactions from mined recovery, including earlier journal entries that never mined by activation. Retain those records for reconciliation rather than deleting them or silently retrying. Run the core tests and `node --test tests/gui/*.test.cjs`; commit the cutoff and reporting changes independently of the early copy change.

**Exit evidence:** Warning copy in both surfaces; tests prove no post-cutoff proving/broadcast and accurate partial outcomes. A preactivation node-mined Sprout migration and postactivation refusal are required in Task 5 before full qualification.

### Task 3: Keep historical-block P2P access working

**Files:** Modify `crates/zeck-core/src/p2p/peer.rs` and `p2p/wire.rs` tests as needed; extend existing P2P fixtures rather than introducing a second client.

**Interfaces:** Add `pub(super) fn protocol_version(network: P2pNetwork) -> u32` in `peer.rs`; both VERSION and GETHEADERS use it. Return mainnet `170_190`, testnet `170_180`, and the private harness's explicitly selected compatible value for regtest. Preserve `Peer::connect(addr, network)` and `P2pNetwork` magic/port separation.

- [ ] Add failing table tests for mainnet/testnet advertisement and matching GETHEADERS payload versions. Add fake-peer tests that enforce those floors and return known historical headers and blocks; wrong-network magic must still fail.
- [ ] Run `cargo test -p argos-core p2p::` to establish the baseline failure, then replace the shared 170160 constant at both message construction sites. Update the comment that currently describes historical data as sufficient reason to ignore contemporary protocol capabilities.
- [ ] Verify historical decoding with the upgraded transaction library, including old Sprout data and supported modern block contents consumed by the spend-history scan. No wholesale parser rewrite or transaction-relay capability is implied by the version increase.
- [ ] Run the P2P suite and perform a read-only public testnet qualification: record node/client versions, selected network, known block height/hash, successful handshake, block download, and existing header/PoW checks. Compare the fetched hash against an independent canonical source; a handshake alone does not pass. Commit the scanner change.

**Exit evidence:** Network-specific wire versions plus verified historical block delivery from a NU7-enforcing peer. Mainnet production connectivity must be rechecked against upgraded peers during Task 6.

### Task 4: Apply spacing, expiry, and action budgets to supported sweeps

**Files:** Modify `crates/zeck-core/src/service.rs`, `transparent_recovery.rs`, and `imported_sweep.rs` only where upstream does not supply the needed behavior; add `crates/zeck-core/tests/nu7_sweep_policy.rs` and integration cases in Task 5.

**Interfaces:** Preserve existing sweep entry points and request types. Upstream candidate-height-aware proposal/builder APIs own transaction format and expiry selection; any Argos batching adjustment stays inside the existing proposal flow. Return actionable limit errors where a valid split cannot be formed.

- [ ] Add failing policy tests for target `A-1`, `A`, and `A+1`: correct branch and valid v5/v6 format, 40-block default expiry before activation, 120 after it, and preservation of any explicitly configured expiry. Cover seed-based and imported-key construction separately.
- [ ] Add exact-limit and over-limit proposal fixtures: Sapling 300/301 inputs plus outputs, Orchard 330/331 actions, Ironwood 330/331 actions, and 200 Orchard plus 200 Ironwood actions exceeding the combined 330 budget even though each per-pool limit passes. Include proof padding, change, and optional donation outputs in final counts.
- [ ] Run `cargo test -p argos-core --test nu7_sweep_policy` to expose baseline gaps, then use upgraded upstream enforcement. Partition large recoveries into valid proposals when supported; never drop notes, lower the intended amount silently, or retry an impossible shape indefinitely.
- [ ] Exercise Sapling, Orchard, and Ironwood funds, imported transparent inputs, imported Sapling PCZTs, and optional donations. Check existing circuit selection against the upgraded protocol revision and preserve the accounting distinction between pools.
- [ ] Audit block-count-to-time displays, confirmation waits, anchor selection, scan retry/freshness thresholds, and database rewind retention. Adjust only values that represent a wall-clock duration; do not triple every constant. Verify the actual wallet rewind capacity against ZIP 218's at-least-600-block recommendation, and record any dependency limitation instead of asserting support.
- [ ] Rerun policy and existing recovery tests; commit construction-policy changes with the affected call paths and final action counts documented.

**Exit evidence:** Supported sweep proposals remain valid on both sides of activation; large recoveries split successfully or fail with a precise explanation and intact funds. Actual node acceptance/mining is demonstrated in Task 5.

### Task 5: Exercise activation against an isolated node

**Files:** Modify `tests/regtest/docker-compose.yml`, `zebrad-regtest.toml`, `zebrad-sprout.toml`, `setup.sh`, and `README.md`; add `tests/regtest/fixtures/generate-nu7-prefix.sh` and `tests/regtest/fixtures/nu7-prefix/README.md` for the qualified bootstrap below; modify `crates/zeck-core/src/workspace.rs` and `crates/zeck-core/tests/common/regtest_harness.rs`; add `crates/zeck-core/tests/nu7_activation.rs`; add a bounded activation job to `.github/workflows/ci.yml`.

**Interfaces:** Keep existing harness profiles working. Add a separate NU7 profile with a delayed activation `A` that is a multiple of 3, synchronized in Zebra and the `LocalNetwork` installed in each test/helper process. Use a fixed fixture height of `A = 1_200` only after confirming the chosen node's funding/subsidy configuration accepts the whole schedule.

- [ ] Pin a NU7-aware Zebra build and compatible lightwalletd version or digest, recording identities and readiness responses. Start a new disposable Compose project/volume; do not reuse or migrate a developer's existing chain. Follow the chosen node release's custom-network monetary constraints, including a compatible slow-start/funding configuration.
- [ ] Qualify a Sprout bootstrap before depending on it: generate a pre-Canopy block prefix and disposable funded Sprout notes with zcashd, export raw blocks plus expected hashes/tree roots, and feed the prefix through the selected NU7 node's supported validation/import path. First confirm matching genesis and early consensus/subsidy parameters. Require the NU7 node to independently accept the prefix and reproduce its hashes and Sprout state. Do not copy incompatible databases or mistake `zebrad-sprout.toml` for an active Compose service. If this is unsupported, record a named node/fixture blocker and keep the real Sprout-boundary gate pending; client mocks and existing zcashd spend tests are not substitutes.
- [ ] After bootstrap succeeds, wire a separate NU7 Compose service to the validated prefix and document its generator/replay commands and disposable seed provenance. Use a compatible schedule with Canopy 1000 through NU6.3 1005 and NU7 at 1200. Advance the NU7-capable node through those upgrades; zcashd must not be used to cross NU6.3/NU7. Never attempt to fund Sprout on the all-upgrades-active profile.
- [ ] Add activation tests with explicit node assertions that NU7 is inactive at `A-1` and active at `A`. Observe failing client behavior before implementing missing paths; do not mistake an all-upgrades-at-height-1 test for an activation-boundary test.
- [ ] Mine a real Argos Sprout-to-Sapling recovery before `A`; check its canonical transaction, output, and spent note. After `A`, assert Argos refuses before proving/sending. Separately construct a test-only, otherwise valid v4 fixture whose expiry extends beyond `A`, bypassing the production expiry clamp only in the fixture generator. Establish a preactivation acceptance control and assert the postactivation node rejection specifically identifies v4 retirement. Expiry, stale branch/signature, spent-input, unknown-anchor, and malformed-proof failures do not prove this rule; retain the actual rejection code/reason and independent validation of the fixture's other fields.
- [ ] Mine supported-pool sweeps at/after `A`, including the Task 4 large-wallet cases. Assert target branch, format, fees/change/donation accounting, final balances, and canonical inclusion rather than only RPC return codes.
- [ ] Test interruption/resume across `A`, a proof crossing `A`, pending-v4 invalidation, and a node-supported reorg around activation. Reconcile transaction status and balances after rescan; no duplicate sends or lost journal evidence. Test deeper database rewind support separately within the verified storage horizon.
- [ ] Document the profile boot/funding procedure and required environment variables. Run `cargo test -p argos-core --locked --features argos-network --test nu7_activation -- --ignored --nocapture --test-threads=1` against it. Expected: a nonzero, explicitly enumerated set of passing activation cases. Extend CI with the same bounded suite and fail if its expected tests are absent or skipped; retain existing Sprout-node tests.

**Exit evidence:** Pinned node/library identities, test names/counts, canonical block/transaction receipts, and scan/resume/reorg results. Regtest results do not establish public testnet or production readiness.

### Task 6: Qualify public testnet and ship a compatibility release

**Files:** Update this plan's evidence/status, `README.md`, `site/guide.html`, `tests/regtest/README.md`, and version/release files through the normal release process. Use `.github/workflows/release.yml`; do not bypass signing or supply-chain checks.

**Interfaces:** Release evidence identifies the exact Argos commit, lockfile, node/lightwalletd versions, network, heights, transaction/block hashes, artifact digests, and observations. It contains no private keys, seed phrases, real wallet files, or secret-bearing logs.

- [ ] On public testnet, run a fresh scan and a resumed scan across known NU7 history with disposable keys. Complete supported-fund recovery and confirm canonical mined transactions. Demonstrate post-NU7 Sprout refusal and historical scan/reporting; pre-NU7 Sprout mining evidence comes from the controlled boundary fixture because public testnet has passed activation (on 2026-10-21, `testnet.zec.rocks` `GetLightdInfo` reported height 4,525,013 with consensus branch ID `77190ad9`).
- [ ] Confirm backend synchronization and network identity against independent canonical block hashes at common heights. Check both historical P2P delivery and the lightwalletd-supported sweep path. Stale or unavailable endpoints leave qualification pending.
- [ ] Run `cargo fmt --all -- --check`, `cargo check --workspace --locked`, `cargo clippy --workspace --locked -- -D warnings`, `cargo test --workspace --locked`, `cargo vet --locked`, `cargo deny check`, and `node --test tests/gui/*.test.cjs`. Complete Task 5's node suite separately; ordinary green unit CI does not replace it. Verify required Windows x64/ARM64 checks and Linux/macOS builds in the release workflow.
- [ ] Record the final mainnet activation height and the exact dependency/node revisions that implement it. Rerun parameter and boundary tests if these change; block the NU7-ready release claim while any schedule or compatibility gate is unresolved.
- [ ] Publish release notes with the Sprout mined-before-activation requirement, supported pools, minimum compatible version, actual known limitations, and instructions for pending transactions. Verify downloadable CLI/GUI artifacts, signatures/attestations and checksums, plus the published guide's content. Do not treat merging this planning PR as permission to merge implementation PRs or publish a release.
- [ ] At mainnet activation, use read-only checks for peer delivery, endpoint freshness, canonical hashes, scanning, and user-visible cutoff behavior. Real-value recovery transactions require the user's separate recovery authorization. Record incidents and remaining unknowns before changing the status to operationally verified.

## Completion checklist

- [ ] Sprout deadline messaging shipped with accurate network/height status.
- [ ] Production NU7 parameters and dependency set verified, with final mainnet height assigned.
- [ ] No Sprout proof or broadcast starts when its next candidate block is NU7-active; post-proof crossing is stopped.
- [ ] Accepted/pending/mined recovery statuses and historical journal evidence remain distinct.
- [ ] Historical blocks download and validate through NU7-enforcing peers on the selected network.
- [ ] Supported pools, expiry, padding, action budgets, donations, resume, and reorg behavior pass the node suite.
- [ ] Public testnet qualification has canonical mined receipts and exact build identities.
- [ ] Platform/release/supply-chain checks pass for the distributed artifacts.
- [ ] Mainnet observations are recorded separately from preactivation readiness.

Until these gates have evidence, report each area as planned, implemented but unqualified, qualified on regtest, qualified on public testnet, or operationally verified on mainnet. Missing evidence remains unknown.
