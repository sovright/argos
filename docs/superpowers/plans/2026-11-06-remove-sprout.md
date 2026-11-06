# Sprout Removal Implementation Plan

> **For agentic workers:** Use parallel bounded implementation tasks with integration and independent whole-branch review.

**Goal:** Remove unsupported Sprout recovery while retaining clear wallet-import notices and supported recovery.

**Architecture:** Delete Sprout-only modules and tooling. Replace normalized Sprout secret/note data with a recognized spending-key record count and shared explanatory copy. CLI and GUI consume that count while using existing supported key paths.

**Tech Stack:** Rust, Tauri, JavaScript, Cargo, Node tests.

**Spec:** ../specs/2026-11-06-remove-sprout-design.md

## Global Constraints

- Preserve dirty primary checkout; reuse a clean merged donor at /private/tmp/argos-remove-sprout.
- Do not delete existing user wallet, checkpoint, journal, or pack files.
- ImportedKeys exposes sprout_records: usize and keys::SPROUT_UNSPENDABLE_NOTICE, no Sprout secrets or notes.
- Birthday functions drop only extra_sprout_keys argument and Sprout-specific fields/helpers.
- Keep RUSTFLAGS='' and CARGO_INCREMENTAL=0 for every cargo command.
- No release, merge, broadcast, or general NU7-readiness claim.

## Review Focus

- Mixed encrypted wallets continue recovering supported keys despite ignored Sprout records.
- Sprout-only wallets receive the unspendable notice without a recovery action.
- Supported birthday selection and fingerprints do not depend on unsupported Sprout keys.
- Existing sensitive artifacts remain untouched and shared filesystem protections remain enforced.
- Removed command names and GUI IPC cannot reach a stale spend path.

### Task 1: Importer recognition

- [x] Add failing mixed-wallet and Sprout-only recognition tests.
- [x] Remove Sprout key decryption, note/transaction parsing and normalized secret types; recognize records and surface the notice.
- [x] Run importer tests and preserve supported-pool fixture coverage.

### Task 2: CLI and GUI removal

- [x] Add regressions for removed CLI commands/flags and wallet notice behavior.
- [x] Delete CLI commands, GUI panels/IPC/state and dedicated tests; preserve supported recovery.
- [x] Run CLI and GUI tests, including supported mixed-wallet flows.

### Task 3: Core and tooling removal

- [x] Remove dedicated Sprout/P2P modules, pack crate, dedicated integration tests and dependencies.
- [x] Simplify birthday and imported-key helpers; verify unsupported records do not alter supported recovery.
- [x] Remove Sprout-only CI jobs/profiles and update active docs while retaining historical release/audit records.

### Task 4: Integration and review

- [x] Regenerate lockfile; run formatting, workspace check/tests/Clippy and GUI tests.
- [x] Review remaining Sprout references for stale actions or unsupported claims.
- [x] Independent whole-branch review, fix substantive findings, rerun affected checks, commit and report evidence.

## Execution evidence

- Base: `da1e2ee3dc4142cc5f93a6290285048b55d0914b` (`origin/main`). Reused the clean, merged release worktree at `/private/tmp/argos-remove-sprout`; primary checkout left unchanged.
- `RUSTFLAGS='' CARGO_INCREMENTAL=0 cargo test --workspace --locked`: 1,062 passed, 0 failed, 1 ignored across 19 suites on macOS (Rust 1.99.1). The ignored test probes public lightwalletd endpoint availability and requires external network access.
- `RUSTFLAGS='' CARGO_INCREMENTAL=0 cargo +1.88 clippy --workspace --all-targets --all-features --locked -- -D warnings`: passed.
- `RUSTFLAGS='' CARGO_INCREMENTAL=0 cargo +1.88 check --workspace --all-targets --all-features --locked`: passed; this compiles the supported-pool private-network harness without running its external node tests.
- `node --test tests/gui/*.test.cjs tests/gui-layout/*.test.cjs`: 210 passed, 0 failed. Full frontend boot smoke also checked mixed and Sprout-only wallets, with no removed IPC or browser errors; inspected the mixed-wallet notice screenshot.
- `cargo vet --locked`: succeeded with existing audit/exemption policy; `cargo fmt --all -- --check` and `git diff --check`: passed.
- CI and Compose YAML parse, and remaining named exact CI tests resolve to surviving functions. Active docs and website offer no removed commands.
- Independent review found stale Sapling-input guidance and late CLI handling of unsupported-only wallets. Both fixed with RED-to-GREEN regressions. Sprout-only CLI recovery now refuses before workspace/TOS setup, birthday lookup, destination checks or network use; supplemental supported Sapling keys still recover normally.

## Compatibility decisions

Preserved the legacy zero-count fingerprint slot for supported-only wallets, so this removal does not change their existing workspace identity. Recognized Sprout record counts never influence supported spending-authority identity or birthdays. Shared filesystem authentication formats and surviving production guards remain unchanged. Existing user artifacts and historical design/audit records are preserved. No production broadcast, hosted Windows execution, merge, release or deployment was performed.
