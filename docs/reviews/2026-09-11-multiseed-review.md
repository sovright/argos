# Multi-seed first-party implementation review

Date: 2026-09-11. Branch: `feat/multiseed-eight-scans`.

## Disposition

Initial implementation is available for code review. **Not release-qualified.**
This is source inspection, automated local tests, and a synthetic browser
walkthrough by the implementing agent, not an independent security audit or
a representative-user study.

The change reuses the current scan engine and per-wallet workspaces. Eight
active tasks share a service-level semaphore; extra entries queue. A service
retains at most 64 sessions, including terminal sessions. GUI sweeps remain
per seed; the CLI can preview multiple seeds then sweep them sequentially.
No actual funds were scanned or moved during this pass.

## Security findings addressed

| Finding | Change and evidence |
|---|---|
| Concurrent starts could miss each other's workspace registration | Admission mutex covers conflict checks and registration. A raced duplicate-start test verifies one owner. |
| Different birthdays, or typed versus wallet-file mnemonics, could represent the same spending authority | In-memory admission identity follows the underlying seed independently of provenance/scope. Workspace derivation remains unchanged. Regression tests cover both cases. |
| Discovery and sweep events lacked a source handle | Tauri wraps these events with the scan handle; single-seed discovery listeners reject mismatched handles. Batch progress uses per-handle snapshots. |
| Sweep, release, proposal, or deletion could overlap on one wallet | Per-session operation guards reject conflicting operations. Tests verify busy-wallet release, deletion, and repeated execution are refused. |
| Queued cancellation could accidentally start work or over-admit | Tests hold eight real service slots with an injected scanner, cancel queued/active work, and verify admission and permit recovery. |
| Retry could attach another seed to an existing label/workspace | Retry verifies original seed identity and preserves settings; wrong-seed retry starts nothing. |
| UI could apply an asynchronous proposal or receipt to the wrong selected seed | Selection is blocked during execution; proposal responses verify handle and request generation; receipt rendering is tied to the selected entry. |
| Raw phrase arguments and echoed parse errors expose secrets | CLI batch input uses a protected file and secret wrappers. Malformed-line tests check errors do not include secret text; incompatible sources are rejected. |

## Usability observations and changes

The real HTML/JavaScript was served locally with synthetic Tauri responses.
The fixture does not validate BIP-39 cryptography, contact lightwalletd, or
broadcast transactions; cryptographic input validation is covered in Rust.

The walkthrough exercised nine entry rows, per-row labels, shared scan
settings, eight active rows plus a queued ninth, cancellation of one seed,
admission of the queued seed, completed-seed sweep review, a synthetic
receipt, and returning to the batch. Source identity stayed visible in sweep
and receipt screens. The synthetic UI reported no console errors in the
inspected pass.

Changes prompted by inspection:

- Stable seed numbers disambiguate user labels; visual button text is compact
  while accessible names retain the full source label.
- Cards use a responsive grid instead of a long full-width stack. Card nodes
  remain stable while status text updates, preserving control focus.
- Incomplete balances explicitly say provisional. Counts distinguish queued,
  running, complete, failed, and cancelled seeds.
- Per-seed retry requires re-entry; release explains that it forgets the
  session's keys without deleting the workspace.
- Scan settings explain shared defaults, per-seed birthday overrides, and
  that first-seed birthday detection does not inspect other seeds.
- Fee limits are described as applying separately to each seed sweep rather
  than as a single batch-wide cap.

## Validation evidence

- `cargo test --workspace`: **568 passed, 0 failed, 17 ignored**.
- `cargo test -p argos-core batch_tests --lib`: **7 passed**. Includes an
  injected scanner to exercise lifecycle behavior without network timing.
- `cargo check --workspace --all-targets`: passed during implementation.
- `cargo check --workspace --all-targets --features argos-network`: passed
  during implementation; this compiles the harness paths, not node tests.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo deny check`: advisories, bans, licenses, sources passed; existing
  advisory-not-detected warnings remain.
- `cargo vet --locked`: passed (199 fully audited, 6 partially audited,
  545 exempted). This is dependency evidence, not first-party code audit.
- `node --check gui/src/main.js`: passed.
- Browser walkthrough: synthetic results only, as scoped above. Final compact
  button/label and single-scan snapshot refinements received source/syntax
  checks; a packaged-app walkthrough remains required.

## Outstanding release gates

1. **Cross-process ownership (high-priority security qualification).** The
   admission and operation guards apply to one service and its clones. Separate
   app/CLI processes do not share them; no filesystem advisory lock has been
   added. Review and implement or explicitly constrain this before release.
2. **Funded-chain correctness.** Compare eight distinct funded seeds against
   standalone baselines, with different birthdays, gap expansion, pool
   coverage, interrupted resume, and partial sweeps. The local Docker daemon
   returned HTTP 500 for its API; no node-backed tests were executed here.
   The existing R-W24 test now expects duplicate refusal followed by explicit
   cancel/release/resume, and still requires the harness.
3. **Performance.** Measure one/two/four/eight simultaneous real scans on
   representative hardware, including heavy historical ranges. Separate
   downloads and per-seed trial decryption may saturate network/CPU/memory.
4. **Secret lifetime and restart UX.** Terminal sessions now retain keys until
   release/application exit, rather than expiring errors/cancellations after
   five minutes. Review that tradeoff with users. Queued work has no persisted
   workspace until admitted; no batch manifest restores queue membership after
   exit. Existing per-workspace resume still requires the seed and settings.
5. **Packaged app and human reviews.** Run keyboard/screen-reader/narrow-window
   checks, real cancel/retry/resume/delete workflows, and multi-receipt switching
   on supported desktop platforms. Obtain representative-user feedback and an
   independent security review of the final implementation.

## Try the development implementation

GUI: enter the first seed, choose **Add another seed**, validate the phrases,
then configure and start. Each extra row can override the shared birthday.
Select a completed seed to review its sweep. Use its receipt control to revisit
results. To resume all seeds after restarting the app, re-enter the same seeds
and per-seed settings so the existing workspace paths resolve unchanged.

CLI: put one seed per line in a private file, optionally followed by
`| birthday-block`; blank lines and `#` comment lines are ignored. For example:

```sh
chmod 600 seeds.txt
argos --seeds-file seeds.txt scan
argos --seeds-file seeds.txt sweep --destination <your-unified-address> --dry-run
```

The parser accepts at most 64 entries; eight execute at once. Do not place
actual phrases in shell arguments. Broadcasting retains the existing explicit
`--confirm-sweep` gate.

## GUI follow-up (2026-09-11)

The desktop flow now includes per-card block progress bars and a reachable
**Start a new recovery** action after all scans become terminal. Selecting a
seed clears stale balance/workspace/server/banner fields. Per-entry mutations
serialize cancel/retry/release controls and invalidate older progress replies;
a prior batch's in-flight polling cannot update a newly started batch.

Verified in the synthetic browser fixture: nine entered seeds, eight active
cards and a queued ninth, cancellation, retry by re-entering a seed, selecting
a running seed after another seed completed with a balance, cancelling all
unfinished scans, and returning to the welcome screen for a fresh recovery.
`cargo build -p argos-gui` and `node --check gui/src/main.js` passed. The local
native development executable is `target/debug/argos-gui`. This is build and
synthetic-UI evidence, not packaged-release or funded-chain qualification.
