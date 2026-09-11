# Multi-seed integration assessment

Date: 2026-09-11. Source inspection and implementation/review plan; no runtime qualification or completed security audit is claimed.

## Baseline and recommendation

Live GitHub main: `8218e5f855e9396409b6d1b5ec8c15cbd7771dcb` (v1.2.0). Local HEAD: `7bc8e11b799f5df2f1f293ef060c9fef52c36119`; its tree is identical to that main commit (`git diff` empty).

[PR #42](https://github.com/sovright/argos/pull/42), head `aac5c07dabe8e53395bc608fecfa415a6d76ded1`, was closed as too complex. It added a shared persistent block cache, a fetcher/scanner split, orchestration, new resume semantics, and CLI/GUI multi-seed flows. Its integration tests explicitly did not exercise actual multi-seed shielded scanning. The review comment also identifies ETA, reconnect-count, and error-format fixes on `fix/pr42-review-issues`; their current availability and applicability have not been verified.

Build a small batch coordinator over the current `RecoveryService`, retaining separate existing workspaces and the current sync engine. Start with seed phrases, support for up to eight simultaneously active scans, and a queue for additional seeds. Reuse existing single-session sweep methods sequentially. Keep multi-wallet-file and Sprout batch recovery outside the initial feature scope while preserving their existing single-source flows.

This provides simultaneous scans without requiring shared downloads. Each active seed downloads its own compact blocks and performs its own trial decryption. Eight simultaneous scans is a product requirement, not a measured capability yet. Qualify bandwidth, CPU, memory, and responsiveness at that concurrency, including overlapping heavy historical ranges. Separate downloads remain the initial implementation approach; if measurements cannot meet the eight-scan requirement, revisit download sharing or scheduling within each scan before claiming support. A queue running only two scans at a time does not satisfy this requirement.

## What changed since PR #42

| Area | Current implementation | Integration consequence |
|---|---|---|
| Session ownership | `service.rs` stores sessions by handle in a map | Most basic multi-session machinery already exists; add batch lifecycle and admission control |
| Sync | `scan.rs` uses bounded `MemoryBlockCache` and upstream `sync::run` | Old persistent-cache rewrite would reverse this design and require fresh correctness/performance work |
| Reliability | Progress-aware retry budgets, stall watchdog, sandblasting allowance, gap-extension passes | Retain these by calling the current scan path |
| Resume | Hashed workspace identity includes network, seed, birthday, and account scope; `session.json` supports unfinished scans | Preserve paths and identity; do not adopt old fingerprint-only resume or silently override an earlier requested birthday |
| Key sources | `KeySource` supports typed seeds and imported keys with separate recovery routes | Keep coordinator compatible with this abstraction without expanding initial UI scope |
| Sweeping | Fee/donation logic, shielding confirmation waits, partial transaction outcomes, imported-key routing | Call current service methods; do not transplant the old sweep implementation |
| GUI | One `state.scanHandle`; existing scan/resume/sweep/delete screens | Requires per-entry state and explicit batch controls |

PR #42's entry rows, status-card concept, parser cases, and failure-isolation intent are useful references. Its engine and workspace changes should be redesigned against current code, not rebased wholesale.

## Concrete implementation slices

1. **Batch model and ownership.** Stable opaque batch/entry IDs; per-entry label, birthday, account settings, scan handle, status, and outcome. Validate and deduplicate seeds before starting jobs. Preserve input identity even when scheduling by birthday. Enforce an atomic service-wide cap of eight active scans across batches and standalone starts, with queued cancellation, per-entry retry, and cancel-all. Concurrent starts and retries must never admit a ninth active scan; queued entries must start when a slot is released. Atomically reserve workspaces: current startup checks conflicts, releases the registry read lock, then inserts later, allowing competing starts to miss each other. Coordinate scan, sweep, and deletion ownership and review cross-process collisions too.
2. **Events and lifecycle.** Wrap every discovery and sweep event with its scan/entry identity. Progress/completion already include a handle; `scan-discovery`, `sweep-tx-broadcast`, and `sweep-tx-confirmed` currently emit bare records. Subscribe before launch and reconcile snapshots so fast completion is not lost. Explicitly release retained secret-bearing sessions when the user finishes or removes an entry; completed sessions currently remain available for sweeping.
3. **GUI and resume.** Add masked, individually labeled seed rows and per-row validation. Make all eight active entries accessible with readable progress, stable labels, and individual controls; show queued entries separately. Show queued/running/complete/failed/cancelled separately, with per-seed discoveries and actionable errors. Resume each existing workspace with its original settings and re-entered seed; any persisted batch manifest contains only necessary nonsecret metadata. Keep single-source wallet import and Sprout flows functional.
4. **CLI and sweeping.** Offer protected seed-file input or repeated secure prompts, with unambiguous per-seed birthdays; do not restore PR #42's raw phrase command-line arguments. Quote per-seed and aggregate fees/donations. Confirm the selected seeds and destination, execute sequentially, preserve every broadcast record on partial failure, and prevent repeated concurrent execution. Define whether a batch fee limit is aggregate or per seed rather than multiplying an ambiguous cap.
5. **Qualification and reviews.** Complete the evidence below, address findings, then review the final diff and packaged app before release.

## Security review requirements

Extend `docs/THREAT_MODEL.md` and use its existing secret-memory analysis as a baseline. Review both the design before implementation and the final implementation.

- Trace every seed through DOM, JavaScript state, IPC, Rust ownership, queueing, cancellation, completion, and shutdown. Check errors, logs, manifests, notifications, exports, and CLI argv for secret leakage. JavaScript/IPC clearing is best effort and must not be described as guaranteed memory erasure.
- Test saturation at eight active scans, ninth-scan queueing, cancellation/retry slot accounting, same-seed duplicates, concurrent starts, scan-versus-sweep/delete races, repeated sweep requests, and cross-process workspace access. Distinct birthdays must not permit accidental duplicate spending operations for the same seed.
- Verify event ownership and prevent one seed's balance, destination confirmation, receipt, or deletion action from being attributed to another. Use opaque IDs rather than exposing seed fingerprints.
- Preserve workspace identity, private permissions, fee guards, network validation, and partial-broadcast outcomes. Missing or corrupted resume metadata must never silently select a different scan scope.
- Bound active work and retained state. Assess whether multiple simultaneous transparent address probes increase cross-wallet linkage by the server; do not claim independent downloads provide wallet unlinkability.
- If shared downloads are later introduced, separately review chain validation, reorg/rewind handling, subtree/frontier data, transparent/full-transaction retrieval, lagging consumers, cache eviction, and poisoned/stale cache recovery. Calling `scan_cached_blocks` alone is not evidence of equivalence to the full sync engine.

Source inspection identifies integration hazards, not demonstrated exploits. Runtime race and failure tests remain necessary.

## Usability review requirements

Review the entry/progress/recovery prototype before backend scope is finalized, then test the implemented app with synthetic seeds and representative recovery users.

- Enter eight seeds, correct one invalid row, detect a duplicate, and assign different birthdays without losing row identity or exposing other phrases.
- Understand that a zero balance while scanning is provisional, and distinguish an empty completed seed from a failed or cancelled seed. Aggregate completion must not hide failures.
- Cancel one entry while others continue; cancel the batch; close/reopen; resume the intended workspace after re-entering its seed. Explain queued work and resource use plainly.
- Review a sweep containing funded, empty, failed, and partially recovered seeds. Identify the destination, selected sources, total fees/donation, completed transactions, and retryable remainder without guessing.
- Verify keyboard navigation, screen-reader labels, focus after add/remove/error, long labels, narrow layouts, and restrained progress announcements. Labels must remain stable if scheduling order changes.
- Confirm that deletion identifies exactly which workspace is affected and that receipts remain understandable after partial failure.

## Validation and release evidence

- Fund eight distinct test seeds across relevant pools and compare each concurrent result with its standalone baseline: discoveries, balances, scan coverage, and sweep outcomes. Include different birthdays and account-gap expansion.
- Exercise one stalled/disconnected/failed scanner beside a healthy scanner, per-seed and batch cancellation, process termination/resume, duplicate starts, missing workspaces, and partial sweep broadcasts.
- Run `cargo test --workspace`, workspace all-target clippy, and existing CI dependency/security checks. Run the relevant node-backed `argos-network` tests with a configured harness; default tests alone do not execute ignored chain tests.
- Measure one, two, four, and eight simultaneously active seeds plus a ninth queued seed on representative desktop hardware, including overlapping heavy historical ranges. Verify that all eight scans advance, the ninth remains queued until a slot opens, and cancellation/retry cannot exceed the cap. Record memory, CPU, bytes downloaded, completion time, and UI responsiveness.
- Check single-seed GUI/CLI behavior plus wallet-file, imported-key, and Sprout regressions. Test packaged desktop behavior, not only library APIs.
- Record security findings with severity, evidence, remediation, and retest results; record usability tasks with observed failures and fixes. Obtain release-owner disposition for unresolved findings.

The review outcome should determine readiness. No code or runtime tests were changed or run during this assessment.

## Implementation pass (2026-09-11)

Work is on `feat/multiseed-eight-scans`. The initial core/GUI/CLI implementation now exists; see [security and usability review](../../reviews/2026-09-11-multiseed-review.md) for evidence and remaining gates. The earlier sections record the design baseline, not a claim that every release requirement is complete.

Implemented: eight service-wide active slots, up to 64 retained/queued sessions, duplicate admission protection including mnemonic imports, per-seed retry/cancel/release, attributed events, masked GUI entry rows and per-seed controls, and protected CLI `--seeds-file` scan/sweep. GUI sweeping is deliberately reviewed one seed at a time; CLI previews successful seeds then sweeps sequentially when explicitly requested. No shared block cache or workspace migration was introduced.

Terminal sessions now remain until explicit release or application exit, bounded by the 64-session cap. This replaces the old five-minute expiry for failed/cancelled sessions so a user can return after other seeds finish. Completed scans already retained their keys for sweeping. Release preserves the existing on-disk workspace. Queued scans have no persisted workspace until they begin; after application exit their seeds and settings must be entered again. No persistent batch manifest has been added.
