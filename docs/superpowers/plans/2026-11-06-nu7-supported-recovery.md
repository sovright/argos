# NU7 Supported Recovery Implementation Plan

> **For agentic workers:** Use the approved dynamic workflow, with independent file scopes and a whole-branch review.

**Goal:** Port non-Sprout NU7 readiness from PR #291 onto current main and open a validated follow-up PR.
**Architecture:** Reuse the reviewed algorithms and tests from 850697b; adapt them to e5e0fe4 without reverting later security fixes. Extract generic NU7 validation from the old Sprout-oriented module.
**Tech Stack:** Rust 1.89, coordinated Zcash SDK, Tauri/JavaScript, Zebra/lightwalletd qualification.
**Spec:** `docs/superpowers/specs/2026-11-06-nu7-supported-recovery.md`

## Global constraints
Use `RUSTFLAGS='' CARGO_INCREMENTAL=0 cargo +1.89 ...` consistently. Preserve the primary dirty checkout. Root owns Cargo builds/lockfiles; parallel workers do not compete for target locks. Never restore removed Sprout/P2P paths. No release or funded mainnet action.

## Review focus
- Old wallet database and key identity fixtures survive the SDK migration.
- Multiple supported batches retain notes, exact fees, donations and partial failure evidence.
- Signed bytes and reviewed authority cannot cross branch or expiry changes.
- Birthday network mismatch/offline fallback never silently skips recoverable history.
- Sprout-only/mixed wallets and TOS/storage behavior remain as established by #301.

## Tasks
- [x] SDK/API migration: root ports manifest and retained leaf API changes, resolves lock without downgrading main security fixes, updates exact vet policy; validate workspace check, historical fixtures and migration test.
- [x] Runtime: port nu7/nu7_limits, service/imported sweep, submission/reconciliation and workspace/scan changes with their boundary/fee/partial-success/retry tests. Extract generic validation; no Sprout availability API.
- [x] Birthday and GUI/CLI: port network-aware date handling and supported reviewed-intent/frontend checks; preserve current TOS and removal regressions. Run targeted then full GUI tests.
- [x] Qualification: port NU7 fixture/profiles/scripts and CI/release Rust floor, current docs; validate YAML/scripts and offline/live tests where available. Record funded rehearsal gap.
- [ ] Integration: format, full Rust tests, strict all-feature Clippy, GUI/layout, deny/vet and diff checks; independently review final diff, fix blockers with regressions, commit/push/open PR and follow current-head CI.

## Evidence and decisions
- Baseline: e5e0fe4 merges reviewed 5b39f2d; all 18 PR status entries succeeded immediately before merge.
- User approved the five-part carry-forward scope after #301 merged. Existing approval is the implementation handoff; no additional plan confirmation needed.

- Dependency policy: retained aes 0.9.3 and ctutils 0.4.6 from #291 rather than expanding exemptions to newly resolved patches. Refreshed imported audits cover the remaining patch upgrades; cargo-vet succeeds without new patch exemptions.

## Local validation at PR preparation
- Rust 1.89 workspace all-feature suite: 1,120 passed, zero failed, 40 harness/network cases ignored. Includes 7 offline NU7 qualification tests and old-SDK migration.
- Strict workspace/all-target/all-feature Clippy, formatting and diff checks passed.
- Node GUI: 189 passed. Layout: 26 Chromium and 26 WebKit tests passed.
- cargo-deny passed; locked cargo-vet passed (201 fully audited, 20 partially audited, 533 exemptions under existing policy). Audit tooling normalized four publisher comments without changing trust.
- Independent Astra runtime review found partial-batch donation underreporting. Fixed per-tx accounting before error propagation, with a six-scenario regression and explicit excluded-status coverage. Temporarily restoring error-first behavior fails the regression (7,000 versus 32,000); restored implementation passes.
- Added real Orchard, Ironwood and mixed-pool proposals checking exact selected-note preservation, pool identity, padded limits, fees and output accounting. All pass.
- GUI birthday responses are discarded if network/endpoint/date changes in flight; stale all-feature test fixtures were aligned to current local-consensus and authenticated-directory behavior.
- CI/Compose/actionlint/shell/fixture/controller checks passed. Current-commit hosted CI and the live node/proxy boundary job are checked on the follow-up PR. Funded sweep/PCZT rehearsal remains outside these results and is a release gate.
