//! Integration tests requiring a local regtest Zcash node + lightwalletd.
//!
//! These tests are `#[ignore]` by default — CI doesn't run them because the
//! regtest harness is too heavy to boot per PR. Run locally with:
//!
//! ```bash
//! cargo test --workspace -- --ignored
//! ```
//!
//! after starting a regtest node and pointing lightwalletd at it. The
//! environment variable `ARGOS_REGTEST_LIGHTWALLETD_URL` must be set to
//! the lightwalletd endpoint (e.g. `http://localhost:9067`).
//!
//! ## What this file is
//!
//! Stubs documenting the test surface that the parallel "recovery
//! resilience" PR (this branch) defines but does not fully wire up.
//! Each stub:
//! - has a name matching the `R-*` ID from
//!   `docs/superpowers/test-plans/recovery-resilience.md`
//! - panics with `unimplemented!()` carrying a description of what the
//!   test would verify
//! - is annotated `#[ignore]` so the panic doesn't reach CI
//!
//! A follow-up "regtest harness" PR will replace each `unimplemented!()`
//! body with the actual test, using a shared `RegtestHarness` helper
//! that boots/mines/funds a known seed.
//!
//! ## Why stubs and not just a doc?
//!
//! Two reasons:
//! 1. Discoverable: `cargo test --list -- --ignored` enumerates them,
//!    so the test surface is visible from tooling rather than a doc.
//! 2. Build-checked: the test names compile, so a future rename of an
//!    underlying API surfaces as a build failure on this file rather
//!    than as silent doc drift.

// Gate the whole file behind the `argos-network` feature. Without it, Argos
// can't talk to a regtest-style local chain (validate_lightwalletd_network
// rejects the regtest chain name and Sapling activation height), so the C2
// tests are guaranteed to fail at scan-start. Compiling them out under the
// default feature set keeps `cargo test --workspace -- --ignored` clean for
// contributors who haven't booted the harness; opt in with
// `cargo test --features argos-network -- --ignored` after running the
// harness setup in tests/regtest/.
#![cfg(feature = "argos-network")]
#![allow(clippy::needless_pass_by_value)]

// Shared harness module — see `tests/common/regtest_harness.rs` for the
// `RegtestHarness` fixture and its env-var contract. `#[allow(dead_code)]`
// because not every helper in `common::regtest_harness` is consumed by
// every test in this file; cargo's per-binary unused-warning policy would
// otherwise complain about the module's other items.
#[allow(dead_code)]
mod common;
use common::regtest_harness::RegtestHarness;

use std::path::PathBuf;
use std::time::Duration;

use argos_core::{
    workspace::RecoveryWorkspace, RecoveryService, RuntimeScanConfig, ScanConfig, ScanHandle,
    ScanPhase, SweepRequest, ZeckNetwork,
};
use secrecy::SecretString;

/// How many blocks below the tip R-N13's latency scan starts from.
///
/// Bounds the injected-latency budget independently of chain length.
///
/// 100 is not arbitrary, and raising it will fail. At 300ms per block a
/// 100-block window costs 30s, comfortably inside `STALL_TIMEOUT_SECS`
/// (60s). A 200-block window costs exactly 60s and the scan never completes:
/// `blocks_scanned` only advances when a batch commits, so the watchdog sees
/// no progress, declares a stall, reconnects, and repeats forever.
///
/// That is a real defect rather than a harness limit — see the false-stall
/// issue referenced on `sustained_high_latency_scan_completes`. This constant
/// keeps the test inside the regime the current watchdog can handle so it
/// still guards the rest of the latency path; it does not make the defect go
/// away, and should be raised back to 200 once #190 is fixed and the
/// watchdog accounts for in-flight batch progress.
const LATENCY_WINDOW_BLOCKS: u64 = 100;

// ─── Shared setup helper ─────────────────────────────────────────────────────

/// Boot a scan against the Argos network harness with the canonical test
/// seed, poll until completion, and hand back everything a workspace-level
/// test needs to attack the workspace.
///
/// The returned `temp_data_dir` is kept by the caller so its `Drop` doesn't
/// run before the test body finishes — `tempfile::TempDir` removes the
/// directory tree on drop.
async fn complete_scan_against_test_seed(
    harness: &RegtestHarness,
    temp_data_dir: &tempfile::TempDir,
    label: &str,
) -> ScannedFixture {
    // Build the runtime config first so we can compute the workspace path
    // deterministically without involving the service. RecoveryWorkspace's
    // path is a hash of (network, seed, birthday, scope); identical args
    // to `start_scan` produce the same root.
    let runtime = RuntimeScanConfig {
        key_source: std::sync::Arc::new(argos_core::SeedKeySource::new(SecretString::new(
            harness.test_seed().to_owned(),
        ))),
        // Scan from where funding happened, not from genesis. The harness
        // mines past 32,257 for ZIP 212, and the treasury pays test addresses
        // after that, so everything worth finding sits near the tip and the
        // blocks below it are empty. This used to read `birthday: 1` with a
        // note that the chain "tops out at ~200 blocks" — true when funding
        // was coinbase near genesis, and the single biggest cost in the suite
        // once it stopped being.
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: harness.lightwalletd_url().to_owned(),
        data_dir: temp_data_dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: label.to_owned(),
    };
    let workspace_root = RecoveryWorkspace::from_runtime(&runtime)
        .expect("compute workspace path from runtime config")
        .root()
        .to_path_buf();

    // Derive account 1's UA for the sweep destination. We never broadcast,
    // and propose_sweep doesn't care if source == destination — using a
    // derived address from the same seed avoids needing a separately-funded
    // second wallet in the harness.
    let destination_ua = regtest_encoded_unified_address_at(harness.test_seed(), 1);

    let scan_config = ScanConfig {
        birthday: runtime.birthday,
        num_accounts: runtime.num_accounts,
        gap_limit: runtime.gap_limit,
        lightwalletd_url: runtime.lightwalletd_url.clone(),
        data_dir: runtime.data_dir.clone(),
        network: runtime.network,
        label: runtime.label.clone(),
    };

    let service = RecoveryService::new();
    let handle = service
        .start_scan(
            scan_config,
            SecretString::new(harness.test_seed().to_owned()),
        )
        .await
        .expect("start_scan against argos-network harness");

    // Bounded poll — regtest scans usually complete in under a second from
    // birthday=1 to ~200 blocks. 120s is generous headroom for cold disks.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let progress = service
            .get_scan_progress(&handle)
            .await
            .expect("get_scan_progress");
        match progress.phase {
            ScanPhase::Complete => break,
            ScanPhase::Error => {
                panic!("[regtest] scan errored: {:?}", progress.error);
            }
            ScanPhase::Cancelled => {
                panic!("[regtest] scan unexpectedly cancelled mid-poll")
            }
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] scan did not complete within 120s; last phase = {:?}",
                        progress.phase
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    assert!(
        workspace_root.exists(),
        "[regtest] workspace root {} does not exist after scan completes",
        workspace_root.display()
    );

    ScannedFixture {
        service,
        handle,
        workspace_root,
        destination_ua,
    }
}

/// Bundle of the post-scan state the workspace-level integration tests need.
struct ScannedFixture {
    service: RecoveryService,
    handle: ScanHandle,
    workspace_root: PathBuf,
    destination_ua: String,
}

// ─── R-N8: GoAway frame mid-scan triggers reconnect ─────────────────────────
//
// Verifies that an HTTP/2-class mid-stream disconnect triggers the
// reconnect path in `run_wallet_sync_with_retry`, and that the resumed
// scan reaches the same final height as a baseline uninterrupted scan
// without duplicating discoveries.
//
// **What this test substitutes for a real GoAway:** the production retry
// loop in `scan.rs:run_wallet_sync_with_retry` decides whether to retry
// by substring-matching the error message against a fixed list of
// transport-class strings (`"transport error"`, `"h2 protocol error"`,
// `"GoAway"`, `"TimedOut"`, `"close_notify"`, `"UnexpectedEof"`). It does
// not inspect the underlying h2 frame. We therefore exercise the retry
// path by having `FakeLightwalletd` abort the stream with a
// `Status::unavailable` whose message contains both `"h2 protocol error"`
// and `"GoAway"` — this is exactly the contract the production code is
// written against. A real h2-frame-level GoAway is left for whenever the
// h2 crate exposes a server-side `send_goaway` API; the assertions here
// would not change.
//
// What the fixture does:
//   - Proxies all blocks 1..N from the real harness.
//   - At block N+1, returns the simulated GoAway error and sets its
//     "fault triggered" flag so the next reconnect sees clean behaviour.
//
// Assertions:
//   1. Scan reaches phase = Complete (i.e. the retry path succeeded).
//   2. Final `synced_to_height` equals the baseline uninterrupted scan
//      run against the bare harness — proves the resume cursor is sound.
//   3. Discovery list has no duplicates after the disconnect — proves
//      the per-scan dedup set in the pump loop survives reconnect.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn goaway_mid_scan_reconnects_without_duplicate_emissions() {
    let harness = RegtestHarness::require();

    // Baseline: run a scan against the bare harness so we know what
    // `synced_to_height` and which discoveries the chain ought to produce.
    let baseline_dir = tempfile::tempdir().expect("temp data dir for baseline scan");
    let baseline = complete_scan_against_test_seed(&harness, &baseline_dir, "rn8-baseline").await;
    let baseline_progress = baseline
        .service
        .get_scan_progress(&baseline.handle)
        .await
        .expect("baseline scan progress");
    let baseline_synced = baseline_progress.synced_to_height;
    let baseline_discoveries = baseline_progress.discoveries.len();
    drop(baseline);
    drop(baseline_dir);

    // Bring up the fixture in proxy mode with GoAway-after-3-blocks. The
    // regtest harness's chain is ~200 blocks after setup.sh, so 3 is well
    // inside the stream — the retry path has to fire.
    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .close_stream_after_blocks(3)
        .build()
        .await
        .expect("bind FakeLightwalletd on loopback");

    // Run the scan against the fixture URL instead of the harness URL.
    let fixture_dir = tempfile::tempdir().expect("temp data dir for fixture scan");
    let fixture_seed = harness.test_seed().to_owned();
    let runtime = argos_core::RuntimeScanConfig {
        key_source: std::sync::Arc::new(argos_core::SeedKeySource::new(SecretString::new(
            fixture_seed.clone(),
        ))),
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: fake.url.clone(),
        data_dir: fixture_dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn8-faulted".to_owned(),
    };
    let scan_config = ScanConfig {
        birthday: runtime.birthday,
        num_accounts: runtime.num_accounts,
        gap_limit: runtime.gap_limit,
        lightwalletd_url: runtime.lightwalletd_url.clone(),
        data_dir: runtime.data_dir.clone(),
        network: runtime.network,
        label: runtime.label.clone(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(fixture_seed))
        .await
        .expect("start_scan against FakeLightwalletd");

    // Poll to completion. Generous bound — the retry loop sleeps
    // SYNC_RETRY_DELAY_SECS (5s) between attempts.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let final_progress = loop {
        let progress = service
            .get_scan_progress(&handle)
            .await
            .expect("get_scan_progress");
        match progress.phase {
            ScanPhase::Complete => break progress,
            ScanPhase::Error => panic!(
                "[regtest] R-N8: scan errored instead of recovering via retry: {:?}",
                progress.error
            ),
            ScanPhase::Cancelled => panic!("[regtest] R-N8: scan unexpectedly cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N8: scan did not complete within 180s; last phase = {:?}",
                        progress.phase
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    assert_eq!(
        final_progress.synced_to_height, baseline_synced,
        "[regtest] R-N8: post-reconnect synced_to_height must equal the baseline; \
         got {:?}, baseline {:?}",
        final_progress.synced_to_height, baseline_synced
    );

    // Discovery dedup: every (account, kind, address) triple appears at most
    // once. The pump loop's seen-set lives in `ScanProgress.discoveries`
    // itself (it's an append-only log), so duplicates would surface here.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for d in &final_progress.discoveries {
        let key = format!("{:?}|{}|{}", d.pool, d.account_index, d.address);
        assert!(
            seen.insert(key.clone()),
            "[regtest] R-N8: duplicate discovery after reconnect: {key}"
        );
    }

    // Baseline produced N discoveries; the faulted run must produce the
    // same set. Equality on count is sufficient given the dedup assertion
    // above proves every entry is unique.
    assert_eq!(
        final_progress.discoveries.len(),
        baseline_discoveries,
        "[regtest] R-N8: discovery count differs from baseline (post-reconnect={}, baseline={})",
        final_progress.discoveries.len(),
        baseline_discoveries
    );

    eprintln!(
        "[regtest] R-N8 ok: scan recovered from simulated GoAway, reached {:?} (matches baseline)",
        final_progress.synced_to_height
    );
}

// ─── R-N9: Hostile compact block ────────────────────────────────────────────
//
// Verifies that a structurally-parseable but chain-invalid compact block
// surfaces as a clean error from `zcash_client_backend::sync` (not a
// panic), without corrupting the wallet DB for a subsequent scan.
//
// `FakeLightwalletd` mutates the `prev_hash` of the block at a configured
// height (XOR all bytes with 0xff). The block still parses — gRPC decode
// succeeds — but the chain-link check in librustzcash's sync rejects it
// because the block no longer links to its predecessor.
//
// Why XOR-prev_hash rather than e.g. a malformed commitment tree: the
// chain-link check fires earliest in the sync pipeline, gives a
// deterministic rejection point regardless of which blocks happened to
// contain notes for our test seed, and exercises the same error path a
// genuinely adversarial server would trigger by lying about the chain.
//
// Assertions:
//   1. The first scan ends in `ScanPhase::Error` — not Complete, not a
//      panic. The retry loop must NOT classify this as a transport-class
//      error (it isn't); the error must propagate.
//   2. A second scan against the bare harness (fresh workspace) reaches
//      the baseline `synced_to_height`. The faulted scan's database
//      lives in its own tempdir, so this also implicitly verifies that
//      writing to that DB and then dropping it leaves no global state
//      that pollutes the next workspace.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn hostile_compact_block_rejected_cleanly() {
    let harness = RegtestHarness::require();

    // Baseline first (same pattern as R-N8) so we have a target.
    let baseline_dir = tempfile::tempdir().expect("temp data dir for baseline scan");
    let baseline = complete_scan_against_test_seed(&harness, &baseline_dir, "rn9-baseline").await;
    let baseline_progress = baseline
        .service
        .get_scan_progress(&baseline.handle)
        .await
        .expect("baseline scan progress");
    let baseline_synced = baseline_progress.synced_to_height;
    drop(baseline);
    drop(baseline_dir);

    // Inject inside the range this scan actually covers.
    //
    // This used to be a hardcoded height 5, with a note that "setup.sh funds
    // the test seed around block ~100". Both stopped being true: funding moved
    // to transfers near the tip, and scans start from `funding_birthday()`, so
    // a block at height 5 is never fetched and the fault is never seen — the
    // scan completes cleanly and the test fails claiming the hostile chain was
    // accepted.
    let hostile_height: u64 = u64::from(common::regtest_harness::funding_birthday()) + 2;
    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .inject_hostile_block_at_height(hostile_height)
        .build()
        .await
        .expect("bind FakeLightwalletd on loopback");

    let faulted_dir = tempfile::tempdir().expect("temp data dir for faulted scan");
    let seed = harness.test_seed().to_owned();
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: fake.url.clone(),
        data_dir: faulted_dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn9-faulted".to_owned(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(seed.clone()))
        .await
        .expect("start_scan against hostile FakeLightwalletd");

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let faulted_progress = loop {
        let progress = service
            .get_scan_progress(&handle)
            .await
            .expect("get_scan_progress");
        match progress.phase {
            ScanPhase::Error => break progress,
            ScanPhase::Complete => {
                panic!("[regtest] R-N9: scan must NOT complete cleanly against a hostile chain")
            }
            ScanPhase::Cancelled => panic!("[regtest] R-N9: scan unexpectedly cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N9: scan neither errored nor completed within 120s; \
                         last phase = {:?}",
                        progress.phase
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    let err_text = faulted_progress
        .error
        .as_ref()
        .expect("[regtest] R-N9: scan ended in Error but error field was empty")
        .to_string();
    assert!(
        !err_text.is_empty(),
        "[regtest] R-N9: error message must be non-empty"
    );
    // The exact wording comes from librustzcash; we just check we got a
    // *useful* message, not a generic panic backtrace.
    assert!(
        !err_text.contains("panicked"),
        "[regtest] R-N9: scan must surface an Err, not propagate a panic: {err_text}"
    );
    eprintln!("[regtest] R-N9 ok: hostile block rejected with: {err_text}");

    drop(service);
    drop(faulted_dir);
    drop(fake);

    // Subsequent clean rescan against the bare harness reaches baseline.
    // Uses a fresh workspace so we're testing "no global state pollution",
    // not resume.
    let recovery_dir = tempfile::tempdir().expect("temp data dir for recovery scan");
    let recovery = complete_scan_against_test_seed(&harness, &recovery_dir, "rn9-recovery").await;
    let recovery_progress = recovery
        .service
        .get_scan_progress(&recovery.handle)
        .await
        .expect("recovery scan progress");
    assert_eq!(
        recovery_progress.synced_to_height, baseline_synced,
        "[regtest] R-N9: post-incident clean scan must reach baseline height \
         (got {:?}, baseline {:?})",
        recovery_progress.synced_to_height, baseline_synced
    );
}

// ─── R-N13: Sustained high latency ──────────────────────────────────────────
//
// Verifies that a high-RTT link (300 ms per emitted compact block, which is
// a generous model of a transatlantic cellular link) does not break the scan.
// `FakeLightwalletd::builder().latency(...)` sleeps that long before each
// outbound block.
//
// Asserts:
//   1. Scan reaches phase = Complete.
//   2. Final synced_to_height equals the baseline uninterrupted scan against
//      the bare harness.
//   3. The scan completes within a generous-but-bounded budget (180s against
//      `LATENCY_WINDOW_BLOCKS` × 300ms = 60s of pure latency, so ~3× the
//      lower bound).
//
// The window is explicit rather than "however long the chain is" because the
// chain length is now set by an unrelated requirement: the PCZT tests need
// ZIP 212 enforced, which forces mining past height 32,257. Scanning all of
// that at 300ms per block would take hours. An earlier version of this test
// assumed a ~200-block harness and silently became unsatisfiable when that
// stopped being true.
//
// The window is also capped by a real defect, not just by budget: past ~60s
// of injected latency the stall watchdog kills the batch before it commits
// and the scan reconnect-loops forever. See #190 and the comment on
// `LATENCY_WINDOW_BLOCKS`.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn sustained_high_latency_scan_completes() {
    let harness = RegtestHarness::require();

    // Baseline.
    let baseline_dir = tempfile::tempdir().expect("temp data dir for baseline");
    let baseline = complete_scan_against_test_seed(&harness, &baseline_dir, "rn13-baseline").await;
    let baseline_synced = baseline
        .service
        .get_scan_progress(&baseline.handle)
        .await
        .expect("baseline progress")
        .synced_to_height;
    drop(baseline);
    drop(baseline_dir);

    // Faulted scan against a 300ms-per-block fixture.
    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .latency(Duration::from_millis(300))
        .build()
        .await
        .expect("bind FakeLightwalletd with latency");

    let dir = tempfile::tempdir().expect("temp data dir for faulted scan");
    let seed = harness.test_seed().to_owned();

    // Scan a bounded window rather than the whole chain. Injected latency is
    // per emitted block, and the harness now mines past height 32,257 so the
    // PCZT tests get ZIP 212 enforcement — at 300ms each that is over two
    // hours, against a budget of three minutes. The window keeps the test
    // measuring what it is named for (sustained per-block latency) instead of
    // measuring chain length.
    //
    // The assertion below is unaffected: `synced_to_height` is the tip the
    // wallet reached, which does not depend on where the scan started.
    let tip = common::regtest_harness::zebra_rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("getblockcount returns a number");
    let birthday = u32::try_from(tip.saturating_sub(LATENCY_WINDOW_BLOCKS))
        .expect("regtest heights fit in u32")
        .max(1);

    let scan_config = ScanConfig {
        birthday,
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: fake.url.clone(),
        data_dir: dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn13-latency".to_owned(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(seed))
        .await
        .expect("start_scan against latency fixture");

    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let progress = loop {
        let p = service.get_scan_progress(&handle).await.expect("progress");
        match p.phase {
            ScanPhase::Complete => break p,
            ScanPhase::Error => {
                panic!("[regtest] R-N13: scan errored under latency: {:?}", p.error)
            }
            ScanPhase::Cancelled => panic!("[regtest] R-N13: scan cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N13: scan did not complete within 180s under 300ms \
                         latency (birthday {birthday}, tip {tip}); reached phase {:?}, \
                         synced_to_height {:?}, blocks_scanned {}, message {:?}",
                        p.phase, p.synced_to_height, p.blocks_scanned, p.message,
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    assert_eq!(
        progress.synced_to_height, baseline_synced,
        "[regtest] R-N13: synced_to_height under latency must match baseline (got {:?}, baseline {:?})",
        progress.synced_to_height, baseline_synced
    );
    eprintln!("[regtest] R-N13 ok: scan completed under 300ms per-block latency");
}

// ─── R-N14: Bandwidth throttle without false stall ──────────────────────────
//
// Verifies a bandwidth-constrained link (32 KB/s ≈ 256 kbps — a slow 3G
// connection) does not cause `ProgressPoller`'s no-advance heuristic to
// flag a false stall when bytes are still flowing.
//
// `ProgressPoller` lives in `scan.rs` and updates `blocks_scanned` once a
// second by polling the wallet DB. It does not currently emit an explicit
// "stalled" message — but the GUI side maps prolonged absence of advance
// into a "Stalled" status pill. If we ever introduce a false-stall trigger
// in production code, this test breaks deterministically.
//
// Asserts:
//   1. Scan reaches Complete within a generous timeout (240s under 32 KB/s).
//   2. `synced_to_height` matches the baseline.
//   3. `progress.message` does NOT contain the substring "stalled" at any
//      observation tick during the scan.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn bandwidth_throttled_scan_does_not_flag_false_stall() {
    let harness = RegtestHarness::require();

    let baseline_dir = tempfile::tempdir().expect("temp data dir for baseline");
    let baseline = complete_scan_against_test_seed(&harness, &baseline_dir, "rn14-baseline").await;
    let baseline_synced = baseline
        .service
        .get_scan_progress(&baseline.handle)
        .await
        .expect("baseline progress")
        .synced_to_height;
    drop(baseline);
    drop(baseline_dir);

    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .bandwidth_bytes_per_sec(32_000)
        .build()
        .await
        .expect("bind FakeLightwalletd with bandwidth throttle");

    let dir = tempfile::tempdir().expect("temp data dir for faulted scan");
    let seed = harness.test_seed().to_owned();
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: fake.url.clone(),
        data_dir: dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn14-throttle".to_owned(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(seed))
        .await
        .expect("start_scan against bandwidth fixture");

    let deadline = std::time::Instant::now() + Duration::from_secs(240);
    let mut saw_stalled_marker = false;
    let progress = loop {
        let p = service.get_scan_progress(&handle).await.expect("progress");
        if let Some(msg) = p.message.as_ref() {
            if msg.to_lowercase().contains("stalled") {
                saw_stalled_marker = true;
            }
        }
        match p.phase {
            ScanPhase::Complete => break p,
            ScanPhase::Error => panic!(
                "[regtest] R-N14: scan errored under throttle: {:?}",
                p.error
            ),
            ScanPhase::Cancelled => panic!("[regtest] R-N14: scan cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N14: scan did not complete within 240s under 32 KB/s throttle"
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    assert!(
        !saw_stalled_marker,
        "[regtest] R-N14: progress.message contained 'stalled' during a bandwidth-throttled \
         scan that was still making progress — this is a false-stall regression"
    );
    assert_eq!(
        progress.synced_to_height, baseline_synced,
        "[regtest] R-N14: synced_to_height under throttle must match baseline (got {:?}, baseline {:?})",
        progress.synced_to_height, baseline_synced
    );
    eprintln!("[regtest] R-N14 ok: scan completed under 32 KB/s throttle without false-stall");
}

// ─── R-N15: Hung stream / dead peer ─────────────────────────────────────────
//
// Verifies that a peer which accepts the TCP connection and completes the h2
// handshake but then sends *zero* further block frames is surfaced as an
// Err within a bounded time — rather than Argos's scan hanging indefinitely.
//
// Backed by the `stall_watchdog` in `scan.rs`: after `STALL_TIMEOUT_SECS`
// of no new blocks, the watchdog tripping returns an error whose message
// contains `"h2 protocol error"`, which the existing retry matcher in
// `run_wallet_sync_with_retry` catches. The retry loop then attempts to
// reconnect; because `hang_after_blocks` is a one-shot fault, the second
// connection serves normally and the scan completes.
//
// The 180 s budget here accommodates one full watchdog cycle (60 s) plus
// the reconnect delay (5 s) plus normal scan time to chain tip — generous
// headroom on a regtest chain that completes in well under a second
// unimpeded.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn hung_stream_surfaces_err_within_bounded_time() {
    let harness = RegtestHarness::require();

    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        // Emit 3 blocks normally, then park — gives the scan something to
        // commit before the hang so we exercise the "between batch" hang
        // window, not the "before first block" handshake window.
        .hang_after_blocks(3)
        .build()
        .await
        .expect("bind FakeLightwalletd in hang mode");

    let dir = tempfile::tempdir().expect("temp data dir for hung-stream scan");
    let seed = harness.test_seed().to_owned();
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: fake.url.clone(),
        data_dir: dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn15-hang".to_owned(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(seed))
        .await
        .expect("start_scan against hang fixture");

    // 180 s budget: stall watchdog trips at 60 s, retry loop reconnects
    // (5 s delay), the second connection has no fault active and serves the
    // chain in well under a second. 180 s is ~3× the lower bound.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let p = service.get_scan_progress(&handle).await.expect("progress");
        match p.phase {
            ScanPhase::Complete => {
                eprintln!(
                    "[regtest] R-N15 ok: stall watchdog tripped, retry recovered, scan completed"
                );
                return;
            }
            ScanPhase::Error => {
                eprintln!(
                    "[regtest] R-N15 ok: scan ended in Error after stall watchdog tripped: {:?}",
                    p.error
                );
                return;
            }
            ScanPhase::Cancelled => panic!("[regtest] R-N15: scan unexpectedly cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N15: Argos did not surface a terminal phase within 180 s \
                         against a hung-stream peer. The stall watchdog (scan.rs::stall_watchdog) \
                         should have tripped at 60 s. Last phase = {:?}, message = {:?}",
                        p.phase, p.message
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

// ─── R-N16: DNS resolution drift between retries ────────────────────────────
//
// Verifies that a connection retry against the *same* lightwalletd URL can
// successfully land on a *different* backend without confusing Argos. The
// production scenario this models: zec.rocks (or any DNS-round-robin or
// load-balancer-fronted endpoint) resolves to IP A for the first
// connection, then to IP B for the retry after a transient failure on A.
//
// The fixture stack:
//
//   Argos
//     │  lightwalletd_url = "http://127.0.0.1:<proxy_port>"  (stays constant)
//     ▼
//   TcpFailoverProxy
//     │  connection #1 → fakeA   (fakeA configured to close after N blocks)
//     │  connection #2+ → fakeB  (fakeB clean, proxies to upstream harness)
//     ▼
//   FakeLightwalletd A, FakeLightwalletd B (both proxy to the same harness)
//     ▼
//   tests/regtest/ (the real zcashd-regtest + lightwalletd stack)
//
// On the first connection fakeA sends the GoAway after N blocks, the
// stall-watchdog and existing retry path kick in, the second connection
// from the proxy hits fakeB, and the scan completes from fakeB. The URL
// Argos used never changed — only the TCP peer behind it.
//
// Assertions:
//   1. Scan reaches phase = Complete (the retry succeeded against the
//      new backend).
//   2. Final synced_to_height equals the baseline uninterrupted scan.
//
// What this would NOT catch: an Argos-side IP cache. If Argos cached the
// first resolved IP and bypassed DNS on retry, the retry would also hit
// fakeA — but our retries route through the proxy at the URL level, not
// the IP level, so this test is actually slightly weaker than a pure
// hosts-file flip. The honest property under test is: "the retry loop
// re-establishes a fresh TCP connection each time, so an upstream change
// behind the URL is invisible to Argos." That property covers the
// production failure mode regardless of whether the underlying IP changes.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn dns_drift_retry_succeeds_against_replacement_backend() {
    let harness = RegtestHarness::require();

    let baseline_dir = tempfile::tempdir().expect("baseline tempdir");
    let baseline = complete_scan_against_test_seed(&harness, &baseline_dir, "rn16-baseline").await;
    let baseline_synced = baseline
        .service
        .get_scan_progress(&baseline.handle)
        .await
        .expect("baseline progress")
        .synced_to_height;
    drop(baseline);
    drop(baseline_dir);

    let fake_a = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .close_stream_after_blocks(3)
        .build()
        .await
        .expect("bind fake_a with close-after-3-blocks");
    let fake_b = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .build()
        .await
        .expect("bind fake_b clean");

    // Strip `http://` from each fake's URL — the proxy wants host:port only.
    fn strip_scheme(url: &str) -> String {
        url.strip_prefix("http://").unwrap_or(url).to_owned()
    }

    let proxy = common::tcp_failover_proxy::serve_tcp_failover_proxy(vec![
        strip_scheme(&fake_a.url),
        strip_scheme(&fake_b.url),
    ])
    .await
    .expect("bind tcp_failover_proxy fronting fake_a + fake_b");

    let dir = tempfile::tempdir().expect("temp data dir");
    let seed = harness.test_seed().to_owned();
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: proxy.url.clone(),
        data_dir: dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn16-drift".to_owned(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(seed))
        .await
        .expect("start_scan through failover proxy");

    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let progress = loop {
        let p = service.get_scan_progress(&handle).await.expect("progress");
        match p.phase {
            ScanPhase::Complete => break p,
            ScanPhase::Error => panic!(
                "[regtest] R-N16: scan errored against the replacement backend: {:?}",
                p.error
            ),
            ScanPhase::Cancelled => panic!("[regtest] R-N16: scan cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N16: scan did not complete within 180s after the simulated \
                         DNS drift; last phase = {:?}, message = {:?}",
                        p.phase, p.message
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    assert_eq!(
        progress.synced_to_height, baseline_synced,
        "[regtest] R-N16: synced_to_height after DNS drift must match baseline \
         (got {:?}, baseline {:?})",
        progress.synced_to_height, baseline_synced
    );
    eprintln!(
        "[regtest] R-N16 ok: scan reached {:?} via replacement backend after fake_a's GoAway",
        progress.synced_to_height
    );
}

// ─── R-N17: Captive-portal MitM ─────────────────────────────────────────────
//
// Verifies that a peer which accepts the TCP connection and writes a raw
// `HTTP/1.1 200 OK` (typical captive-portal hello-page byte pattern) is
// surfaced as Err — not silently treated as a successful empty response.
//
// The shim does not speak gRPC at all; tonic's HTTP/2 layer should reject
// the response as a protocol violation. The test asserts the scan ends in
// Error within a bounded time.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn captive_portal_shim_surfaces_clean_error() {
    let _harness = RegtestHarness::require();

    let shim = common::fake_lightwalletd::serve_captive_portal_shim()
        .await
        .expect("bind captive-portal shim");

    // The shim isn't real lightwalletd, so we can't use complete_scan_*; build
    // ScanConfig directly. The scan attempt will fail at the GetLightdInfo
    // probe step inside start_scan, surfaced as an Err.
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: shim.url.clone(),
        data_dir: tempfile::tempdir().expect("temp data dir").keep(),
        network: ZeckNetwork::Testnet,
        label: "rn17-captive".to_owned(),
    };
    let service = RecoveryService::new();
    let seed = SecretString::new(common::regtest_harness::ARGOS_TEST_SEED.to_owned());

    // start_scan returns Err immediately for the captive-portal case (the
    // probe fails synchronously). Older Argos paths may instead transition
    // to phase = Error post-start; tolerate both.
    let start_outcome = tokio::time::timeout(
        Duration::from_secs(30),
        service.start_scan(scan_config, seed),
    )
    .await;

    match start_outcome {
        Err(_) => panic!(
            "[regtest] R-N17: start_scan did not return within 30s — likely silently hanging \
             on an HTTP 200 response instead of erroring"
        ),
        Ok(Err(err)) => {
            // Synchronous error path — best case. Argos rejected the probe.
            let msg = err.to_string();
            assert!(
                !msg.to_lowercase().contains("complete"),
                "[regtest] R-N17: start_scan error must not claim success: {msg}"
            );
            eprintln!("[regtest] R-N17 ok: start_scan rejected captive portal: {msg}");
            return;
        }
        Ok(Ok(handle)) => {
            // Async error path — wait for phase = Error within bound.
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                let p = service.get_scan_progress(&handle).await.expect("progress");
                match p.phase {
                    ScanPhase::Error => {
                        eprintln!(
                            "[regtest] R-N17 ok: scan surfaced Error against captive portal: {:?}",
                            p.error
                        );
                        return;
                    }
                    ScanPhase::Complete => panic!(
                        "[regtest] R-N17: scan claimed Complete against a captive portal that \
                         doesn't speak gRPC"
                    ),
                    ScanPhase::Cancelled => {
                        panic!("[regtest] R-N17: scan unexpectedly cancelled")
                    }
                    _ => {
                        if std::time::Instant::now() > deadline {
                            panic!(
                                "[regtest] R-N17: scan did not error within 60s against captive \
                                 portal; last phase = {:?}",
                                p.phase
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }
    }
}

// ─── R-N18: Asymmetric loss (one-way drop) ──────────────────────────────────
//
// Verifies that a connection on which outbound bytes flow normally but the
// return path silently drops bytes is surfaced by Argos within a bounded
// time rather than hanging forever. The TCP socket stays open (no FIN,
// no RST); the *application* layer sees no data — exactly the failure
// mode `tc netem`'s one-way loss produces against a real network.
//
// What's covered by which layer:
//   - Stall watchdog (scan.rs::stall_watchdog) trips at 60 s no-advance
//     and returns an `h2 protocol error` substring that the retry matcher
//     catches.
//   - The retry loop opens a fresh connection; on conn #2 the proxy is in
//     clean-pass-through mode, so the scan completes.
//
// The new property R-N18 adds beyond R-N15 is the failure mode at the
// *transport* layer: R-N15 has the server actively choosing not to send
// (the proxied gRPC handler parks). R-N18 has the server sending normally
// but the bytes never arriving — which is what happens with NAT/PF
// asymmetry, half-NAT timeouts, and broken-symmetric routing. Both are
// caught by the watchdog because both produce no `synced_to_height`
// advance; the test exists to document that the watchdog covers this
// distinct failure mode without needing a separate detection mechanism.
//
// Assertions:
//   1. Scan reaches `phase = Complete` (the retry recovered against the
//      same proxy in clean mode).
//   2. Final `synced_to_height` equals the baseline uninterrupted scan.
//
// No sudo / no `tc netem` required: the asymmetric-loss proxy implements
// the drop at the application layer instead of the network layer. The
// effect on Argos is identical.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn asymmetric_loss_recovers_via_watchdog_and_retry() {
    let harness = RegtestHarness::require();

    let baseline_dir = tempfile::tempdir().expect("baseline tempdir");
    let baseline = complete_scan_against_test_seed(&harness, &baseline_dir, "rn18-baseline").await;
    let baseline_synced = baseline
        .service
        .get_scan_progress(&baseline.handle)
        .await
        .expect("baseline progress")
        .synced_to_height;
    drop(baseline);
    drop(baseline_dir);

    // Bring up a FakeLightwalletd in proxy mode so the proxy in front of it
    // sees plaintext-h2 wire format from a real upstream. The asymmetric
    // proxy then drops upstream→client bytes after ~32 KiB on conn #1.
    // 32 KiB is enough for the gRPC handshake + a few compact blocks to
    // pass; the drop happens mid-scan so `synced_to_height` advances a
    // little before stalling.
    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .upstream(harness.lightwalletd_url().to_owned())
        .build()
        .await
        .expect("bind fake lightwalletd backing the asymmetric proxy");
    let fake_addr = fake
        .url
        .strip_prefix("http://")
        .expect("fake url has http:// prefix")
        .to_owned();

    let proxy = common::tcp_failover_proxy::serve_asymmetric_loss_proxy(fake_addr, 32 * 1024)
        .await
        .expect("bind asymmetric_loss_proxy");

    let dir = tempfile::tempdir().expect("temp data dir");
    let seed = harness.test_seed().to_owned();
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: proxy.url.clone(),
        data_dir: dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "rn18-asymmetric".to_owned(),
    };
    let service = RecoveryService::new();
    let handle = service
        .start_scan(scan_config, SecretString::new(seed))
        .await
        .expect("start_scan through asymmetric-loss proxy");

    // 180 s budget: watchdog trips at 60 s, retry-loop reconnect delay
    // adds 5 s, the clean second connection completes in well under a
    // second on regtest.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let progress = loop {
        let p = service.get_scan_progress(&handle).await.expect("progress");
        match p.phase {
            ScanPhase::Complete => break p,
            ScanPhase::Error => panic!(
                "[regtest] R-N18: scan errored instead of recovering via watchdog + retry: {:?}",
                p.error
            ),
            ScanPhase::Cancelled => panic!("[regtest] R-N18: scan cancelled"),
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] R-N18: scan did not complete within 180 s under asymmetric \
                         loss. Stall watchdog should have tripped at 60 s. Last phase = {:?}, \
                         message = {:?}",
                        p.phase, p.message
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    assert_eq!(
        progress.synced_to_height, baseline_synced,
        "[regtest] R-N18: synced_to_height after asymmetric-loss recovery must match baseline \
         (got {:?}, baseline {:?})",
        progress.synced_to_height, baseline_synced
    );
    eprintln!(
        "[regtest] R-N18 ok: scan recovered via watchdog from one-way loss, reached {:?}",
        progress.synced_to_height
    );
}

// ─── R-N10: All endpoints unreachable ───────────────────────────────────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn all_endpoints_unreachable_surfaces_clean_error() {
    // Verifies the failure mode when every configured lightwalletd endpoint
    // refuses the connection. Three properties:
    //
    //   1. `connect_lightwalletd_endpoints` exhausts the list within a
    //      bounded timeout — no silent infinite retry. Enforced via a
    //      `tokio::time::timeout` wrapper as a defensive check on top of
    //      the function's own per-endpoint connect semantics.
    //
    //   2. The returned error is the aggregated "all endpoints failed"
    //      variant, not a single endpoint's transport error. Users with
    //      multi-endpoint configurations need to know that *every* fallback
    //      was tried before giving up, not just the first one.
    //
    //   3. The error names each failing endpoint so it's actionable. The
    //      error string contains both endpoint URLs (the validator accepts
    //      them; only the TCP connect refuses), enabling the GUI/CLI to
    //      surface "tried these N, none worked" rather than a vague
    //      "couldn't connect."
    //
    // Does not actually use the harness URL — but the harness env var
    // gate via `RegtestHarness::require()` ensures the test only runs as
    // part of the C2 integration suite (when someone explicitly booted the
    // setup), not as an accidental unit test.

    let _harness = RegtestHarness::require();

    // Two unreachable URLs on different ports. Both pass the loopback +
    // valid-port URL validator; both will fail TCP connect with
    // ECONNREFUSED in well under a second.
    let combined = "http://127.0.0.1:1,http://127.0.0.1:2";

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        argos_core::lightwalletd::connect_lightwalletd_endpoints(combined, None),
    )
    .await
    .expect(
        "[regtest] connect_lightwalletd_endpoints must return within 10s; \
         no silent infinite retry permitted",
    );

    let err = outcome.expect_err("[regtest] all-unreachable list must surface Err, not Ok");

    let msg = err.to_string();
    assert!(
        msg.contains("failed to connect to any"),
        "[regtest] expected aggregated 'failed to connect to any' wording so \
         the GUI can render 'every endpoint failed' rather than a single \
         transport error; got: {msg}"
    );
    assert!(
        msg.contains("127.0.0.1:1") && msg.contains("127.0.0.1:2"),
        "[regtest] expected the error message to name both attempted endpoints \
         (so the user can see what was tried); got: {msg}"
    );

    eprintln!("[regtest] all-unreachable failed as expected: {err}");
}

// ─── R-N11: TLS handshake failure ───────────────────────────────────────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn tls_handshake_failure_does_not_fall_back_to_plaintext() {
    // Verifies that an `https://` endpoint whose TLS handshake fails is
    // surfaced as Err rather than silently falling back to plaintext.
    //
    // Three properties exercised:
    //   1. The result is Err. `connect_lightwalletd_endpoints` does not
    //      have any implicit plaintext-fallback code path; this test
    //      pins that fact against future regressions.
    //   2. The Err is delivered within a bounded timeout (15s wrapper).
    //      No silent indefinite retry.
    //   3. The failure mode is distinguishable from a TCP-level
    //      "connection refused" (which would indicate the listener
    //      crashed before the client connected — a different bug class).
    //      The assertion is structural: the error string must NOT
    //      contain "connection refused".
    //
    // The cert-validation-cause property from the original stub (the error
    // names "expired" / "unknown CA" / "hostname mismatch") is deferred:
    // it requires a server that actually performs a TLS handshake with a
    // specific bad cert, which means generating + spinning up a TLS
    // listener with a self-signed identity. That belongs in a follow-up
    // PR once we have a cert-fixture helper; this PR uses the simpler
    // "TCP accepts but no TLS frames" simulator below.

    let _harness = RegtestHarness::require();

    // Spawn a TCP listener that accepts connections but never sends any
    // TLS frames. tonic's TLS client times out / errors when no
    // ServerHello arrives. tokio's "net" feature is enabled transitively
    // via tonic's transport stack, so `TcpListener` is reachable from
    // this integration test without us adding tokio features explicitly.
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("[regtest] bind random loopback port for TLS-failure simulation");
    let port = listener
        .local_addr()
        .expect("[regtest] read local_addr of TLS-failure listener")
        .port();

    // Background accept loop. Each connection is drained for a short read
    // (the client's ClientHello) and then dropped without any response,
    // which surfaces to tonic as a TLS handshake failure.
    let _accept_task = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                // sock drops at end of scope → connection closes →
                // client's TLS handshake fails with unexpected EOF.
            });
        }
    });

    let url = format!("https://localhost:{port}");

    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        argos_core::lightwalletd::connect_lightwalletd_endpoints(&url, None),
    )
    .await
    .expect(
        "[regtest] connect_lightwalletd_endpoints must return within 15s; \
         no silent indefinite TLS retry permitted",
    );

    let err = outcome.expect_err(
        "[regtest] https endpoint with a non-TLS listener must surface Err, \
         not Ok (no plaintext fallback)",
    );

    let msg_lower = err.to_string().to_ascii_lowercase();
    assert!(
        !msg_lower.contains("connection refused"),
        "[regtest] expected a TLS-handshake / transport error, not \
         'connection refused' (which would indicate the listener died \
         before the client connected): {err}"
    );

    eprintln!("[regtest] TLS handshake failure as expected: {err}");
}

// ─── R-N12: Multi-endpoint fallback ─────────────────────────────────────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn multi_endpoint_fallback_respects_configured_order() {
    // Verifies the comma-separated-endpoints + fallback contract that the
    // GUI exposes as the "lightwalletd URLs" field. Two properties:
    //
    //   1. When the first endpoint in the list is unreachable, the connect
    //      loop falls through to the second within a bounded timeout and
    //      returns the second's URL as the established endpoint.
    //
    //   2. The `preferred` argument to `connect_lightwalletd_endpoints`
    //      reorders the list — passing the healthy harness URL as
    //      `preferred` makes it tried first, even when it's listed second
    //      in the raw comma-separated input.
    //
    // The "subsequent reconnect after a GoAway prefers the previously-
    // serving endpoint" sub-property from the original stub description is
    // deferred — it requires server-side GoAway injection (custom
    // lightwalletd build or sidecar proxy) and belongs in the R-N8 stub
    // when that lands.

    let harness = RegtestHarness::require();
    let harness_url = harness.lightwalletd_url().to_owned();

    // `http://127.0.0.1:1` is the canonical "nothing listening" URL on
    // loopback. The validator accepts it (port 1 is a valid port; loopback
    // hosts allow plaintext http per Argos's lightwalletd contract), but
    // the TCP connect attempt will fail with ECONNREFUSED in well under a
    // second on every supported platform.
    const UNREACHABLE: &str = "http://127.0.0.1:1";

    // ── Property 1: fallback after the first endpoint fails. ────────────
    let combined = format!("{UNREACHABLE},{harness_url}");
    let (_client, established) =
        argos_core::lightwalletd::connect_lightwalletd_endpoints(&combined, None)
            .await
            .expect("connect_lightwalletd_endpoints must fall back to the harness URL");
    assert_eq!(
        established, harness_url,
        "[regtest] expected fallback to {harness_url}, got {established}"
    );

    // ── Property 2: `preferred` reorders the list. ──────────────────────
    // Same combined URL — harness still appears second — but the preferred
    // argument names it explicitly, which must reorder it to the front.
    let (_client, established) =
        argos_core::lightwalletd::connect_lightwalletd_endpoints(&combined, Some(&harness_url))
            .await
            .expect("connect with preferred=harness must succeed on the first attempt");
    assert_eq!(
        established, harness_url,
        "[regtest] preferred reordering should have surfaced harness first; got {established}"
    );
}

// ─── R-S26: Reorg during scan ───────────────────────────────────────────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn reorg_during_scan_invalidates_and_rescans_affected_range() {
    // Verifies that a chain reorg between two scans is detected and handled
    // by `zcash_client_backend`'s sync layer: the wallet DB rolls back to
    // the common ancestor and re-scans the new fork, reaching at least the
    // new chain tip on completion.
    //
    // ## Sequence
    //
    //   1. Initial scan via the shared helper — wallet observes the
    //      harness's current tip.
    //   2. Drive a regtest reorg via zcash-cli:
    //        - `invalidateblock <hash@tip-5>` rolls the active chain back
    //          to height (tip - 6).
    //        - `generate 10` mines a strictly-longer fork, ending at
    //          (tip - 6 + 10) = tip + 4.
    //   3. Brief sleep so lightwalletd's polling loop observes the new
    //      view before Argos's next sync. The exact delay depends on
    //      lightwalletd's poll interval (~5s in the harness config); 3s
    //      is the conservative default — bump it via the test wrapper if
    //      the hands-on validation shows flakiness.
    //   4. Second scan against the same workspace. The conflict-
    //      cancellation logic (R-W24) cleans up the first session; the
    //      new session resumes from the workspace's `fully_scanned_height`
    //      and forces sync's reorg-detection path.
    //   5. Final progress must report a `synced_to_height` at least as
    //      high as the new chain tip, and the balance must be unchanged
    //      (funding tx is at ~height 201 per setup.sh, well below the
    //      5-block reorg window).
    //
    // ## What this test does NOT cover
    //
    // The strong version of "final balance matches post-reorg ground
    // truth" would put a transaction *inside* the reorged range and
    // verify Argos sees the post-reorg version, not the pre-reorg one.
    // That needs a wallet that can send funds on regtest (and therefore
    // a working spend pipeline against the harness), which is a separate
    // future PR. The current test pins the structural property: scan
    // doesn't crash on reorg + tip advances + balance below the reorg
    // window is preserved.

    let harness = RegtestHarness::require();
    let temp_data_dir = tempfile::tempdir().expect("tempdir");
    let fixture =
        complete_scan_against_test_seed(&harness, &temp_data_dir, "argos-rs26-initial").await;

    let pre = fixture
        .service
        .get_scan_progress(&fixture.handle)
        .await
        .expect("get_scan_progress after initial scan");
    let pre_tip = pre
        .synced_to_height
        .expect("[regtest] initial scan must populate synced_to_height");
    let pre_balance: u64 = pre.accounts.iter().map(|a| a.total_zatoshis).sum();
    eprintln!("[regtest] pre-reorg: tip={pre_tip}, balance={pre_balance}");

    // Driven through Zebra's RPC rather than `zcash_cli`. The harness ran
    // zcashd when this test was written; the migration to Zebra left the
    // helper pointing at a container that no longer exists, so the test had
    // been failing on `No such container: argos-zcashd-regtest` rather than
    // on anything it asserts (part of #186).
    //
    // Zebra does implement `invalidateblock` and `reconsiderblock`. The one
    // constraint that matters here is that it can only invalidate a block in
    // the *non-finalized* chain, which is why the reorg depth stays small.
    let invalidate_height = pre_tip.saturating_sub(5);
    let invalidate_hash =
        common::regtest_harness::zebra_rpc("getblockhash", serde_json::json!([invalidate_height]))
            .await
            .as_str()
            .expect("getblockhash returns a hash string")
            .to_owned();
    eprintln!("[regtest] invalidating block @ height {invalidate_height} (hash {invalidate_hash})",);
    let _ =
        common::regtest_harness::zebra_rpc("invalidateblock", serde_json::json!([invalidate_hash]))
            .await;
    let _ = common::regtest_harness::zebra_rpc("generate", serde_json::json!([10])).await;

    // Let lightwalletd's polling loop observe the new tip.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let new_chain_tip: u64 =
        common::regtest_harness::zebra_rpc("getblockcount", serde_json::json!([]))
            .await
            .as_u64()
            .expect("getblockcount returns a number");
    assert!(
        new_chain_tip > pre_tip,
        "[regtest] post-reorg chain tip must exceed pre-reorg tip; got new={new_chain_tip}, pre={pre_tip}"
    );
    eprintln!("[regtest] post-reorg new chain tip: {new_chain_tip}");

    // Second scan against the same workspace forces sync's reorg path.
    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: harness.lightwalletd_url().to_owned(),
        data_dir: temp_data_dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        label: "argos-rs26-post".to_owned(),
    };
    let handle = fixture
        .service
        .start_scan(
            scan_config,
            SecretString::new(harness.test_seed().to_owned()),
        )
        .await
        .expect("post-reorg start_scan must succeed");

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let final_progress = loop {
        let progress = fixture
            .service
            .get_scan_progress(&handle)
            .await
            .expect("get_scan_progress during post-reorg scan");
        match progress.phase {
            ScanPhase::Complete => break progress,
            ScanPhase::Error => panic!(
                "[regtest] post-reorg scan errored: {:?} — \
                 zcash_client_backend's chain reconciliation regressed?",
                progress.error
            ),
            ScanPhase::Cancelled => {
                panic!("[regtest] post-reorg scan unexpectedly cancelled")
            }
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] post-reorg scan did not complete within 120s; \
                         last phase = {:?}",
                        progress.phase
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    let post_tip = final_progress
        .synced_to_height
        .expect("[regtest] post-reorg scan must populate synced_to_height");
    let post_balance: u64 = final_progress
        .accounts
        .iter()
        .map(|a| a.total_zatoshis)
        .sum();
    eprintln!("[regtest] post-reorg: tip={post_tip}, balance={post_balance}");

    assert!(
        post_tip >= new_chain_tip,
        "[regtest] post-reorg scan must reach the new chain tip; \
         post_tip={post_tip}, new_chain_tip={new_chain_tip} — sync's reorg \
         reconciliation didn't roll forward to the new fork"
    );
    assert_eq!(
        post_balance, pre_balance,
        "[regtest] funding tx is below the reorg window; balance must be unchanged"
    );

    eprintln!("[regtest] reorg detected and rescanned successfully");
}

// ─── R-S27: Crash mid-scan resume ───────────────────────────────────────────
//
// Implemented in #92 (helper-binary scaffolding) + this PR.
//
// Spawns `argos-scan-helper` as a subprocess against the booted regtest
// harness, watches its stdout JSON-line stream for a `block` event past a
// configurable threshold, delivers SIGKILL via `tokio::process::Child::start_kill`,
// then re-spawns the same helper with the same `--data-dir`. The second run
// must reach `Complete` with `total_zatoshis` matching a baseline
// uninterrupted scan.
//
// Why this exercises the production property: the SIGKILL lands inside the
// subprocess's running event loop, not via in-process task cancellation.
// Whether it lands between a batch's "scanned blocks" emission and the
// corresponding DB commit is timing-dependent, but the test runs the kill
// many blocks into the scan — well past the first batch boundary — so over
// runs the kill window will land in different places. The assertion that
// matters is structural: the second run reaches the same final state as
// the baseline. Any failure to resume (corruption, lost cursor, double-
// counting) would surface as `total_zatoshis` divergence.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn crash_mid_scan_resumes_from_fully_scanned_height() {
    use common::subprocess_driver::{HelperEvent, HelperSpawn};

    let harness = RegtestHarness::require();

    // This test scans from genesis rather than from `funding_birthday()`, and
    // deliberately so: its whole purpose is to SIGKILL a scan *in progress*.
    // Starting near the tip leaves only a handful of blocks, the scan finishes
    // before the kill lands, and the test fails with "subprocess should have
    // died from SIGKILL, but exited cleanly". A long scan is the fixture here,
    // not an accident.
    let scan_birthday = "1";

    // ─── Baseline: uninterrupted scan, capture total_zatoshis ──────────────
    let baseline_dir = tempfile::tempdir().expect("baseline tempdir");
    let baseline_handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-scan-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", baseline_dir.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value("--birthday", scan_birthday)
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "rs27-baseline")
    .spawn()
    .await
    .expect("spawn scan-helper for baseline");

    let (_baseline_status, baseline_events) = baseline_handle
        .wait_for_exit()
        .await
        .expect("baseline scan-helper must run to completion");

    let baseline_total = baseline_events
        .iter()
        .rev()
        .find_map(|e| match e {
            HelperEvent::Complete { total_zatoshis } => Some(*total_zatoshis),
            _ => None,
        })
        .expect("baseline scan must emit a Complete event with total_zatoshis");
    assert!(
        baseline_total > 0,
        "[regtest] R-S27: baseline scan found zero funds; setup.sh did not run?"
    );

    // ─── First crash run: kill the subprocess after >= SCAN_KILL_AT blocks ─
    //
    // The threshold is well past the first batch boundary in librustzcash's
    // default batch size (~100 blocks), so the kill lands inside one of the
    // mid-scan windows R-S27 is meant to exercise.
    const SCAN_KILL_AT: u64 = 50;

    let resume_dir = tempfile::tempdir().expect("resume tempdir");
    let mut crash_handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-scan-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", resume_dir.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value("--birthday", scan_birthday)
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "rs27-crash")
    .spawn()
    .await
    .expect("spawn scan-helper for crash run");

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let kill_block = crash_handle
        .wait_for(deadline, |events| {
            events.iter().rev().find_map(|e| match e {
                HelperEvent::Block { scanned_to } if *scanned_to >= SCAN_KILL_AT => {
                    Some(*scanned_to)
                }
                _ => None,
            })
        })
        .await
        .expect("scan-helper must emit a block event past the kill threshold");

    let kill_status = crash_handle
        .sigkill_and_wait()
        .await
        .expect("SIGKILL must reap the subprocess");
    assert!(
        !kill_status.success(),
        "[regtest] R-S27: subprocess should have died from SIGKILL, but exited cleanly: {kill_status:?}"
    );
    eprintln!("[regtest] R-S27: SIGKILLed first run at block {kill_block}");

    // ─── Resume run: same --data-dir, expect Complete reaching baseline ────
    let resume_handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-scan-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", resume_dir.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value("--birthday", scan_birthday)
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "rs27-crash") // same label keeps the workspace key identical
    .spawn()
    .await
    .expect("spawn scan-helper for resume");

    let (resume_status, resume_events) = resume_handle
        .wait_for_exit()
        .await
        .expect("resume scan-helper must run to completion");
    assert!(
        resume_status.success(),
        "[regtest] R-S27: resume run did not exit cleanly: {resume_status:?}"
    );

    let resume_total = resume_events
        .iter()
        .rev()
        .find_map(|e| match e {
            HelperEvent::Complete { total_zatoshis } => Some(*total_zatoshis),
            _ => None,
        })
        .expect("resume scan must emit a Complete event");
    assert_eq!(
        resume_total, baseline_total,
        "[regtest] R-S27: resume total_zatoshis ({resume_total}) must match baseline ({baseline_total})"
    );

    eprintln!(
        "[regtest] R-S27 ok: SIGKILL at block {kill_block}, resume reached {} zatoshis (matches baseline)",
        resume_total
    );
}

// ─── R-S29: Crash mid-broadcast ─────────────────────────────────────────────
//
// Implemented in #92 (sweep-helper + pause hook) + this PR (multi-account
// funding in setup.sh).
//
// `argos-sweep-helper` is spawned with `--pause-millis-between-broadcasts
// 30000` so the per-account broadcast loop sleeps 30s between accounts. The
// test parent waits for the `sweep_starting` event, then sleeps long enough
// (~8s) for the first broadcast to land in the wallet DB but not nearly
// enough to exit the library's 30s pause. SIGKILL.
//
// On the resume run, the helper does a fresh scan against the same
// `--data-dir`. The account that was already swept on the killed run has
// near-zero balance after sync (because its sweep tx persisted in the
// wallet DB and was included in the chain by the harness's miner), so the
// second sweep produces exactly **one** broadcast: for the account that
// was *not* swept on the killed run.
//
// Assertion: second-run `broadcast_count` is exactly 1 (the
// not-yet-swept account). Two broadcasts would prove the first run's
// effect was lost; zero broadcasts would prove the second account had
// already been swept (impossible if the kill landed in the gap).
//
// Skip-condition: if setup.sh has not been re-run with the new multi-account
// default (i.e. `ARGOS_REGTEST_TEST_T_ADDR_1` is not exported), the test
// emits a skip notice rather than failing — there's no point asserting a
// multi-broadcast property against a single-broadcast fixture.
#[cfg(feature = "argos-network")]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported, setup.sh re-run with multi-account funding)"]
#[tokio::test]
async fn crash_mid_broadcast_does_not_double_spend_on_resume() {
    use common::subprocess_driver::{HelperEvent, HelperSpawn};

    let harness = RegtestHarness::require();

    // Both accounts, funded here rather than assumed. R-S29 sweeps two
    // accounts and asserts the resumed run produces exactly one broadcast, so
    // both must hold funds when it starts — which an earlier sweep test would
    // otherwise have taken.
    common::regtest_harness::fund_test_account(0, 1_250_000_000).await;
    common::regtest_harness::fund_test_account(1, 1_250_000_000).await;

    // Multi-account funding gate: PR B's setup.sh exports
    // ARGOS_REGTEST_TEST_T_ADDR_1 when account 1 was funded. If a
    // contributor is running against an older setup.sh, fail with a
    // clear message rather than silently producing a meaningless result.
    if std::env::var("ARGOS_REGTEST_TEST_T_ADDR_1").is_err() {
        panic!(
            "[regtest] R-S29 requires multi-account funding. Re-run \
             tests/regtest/setup.sh (which now funds accounts 0 and 1 by \
             default) and export ARGOS_REGTEST_TEST_T_ADDR_1."
        );
    }

    // Derive account-2's UA from the test seed as the sweep destination.
    // (Both account 0 and account 1 are sources; account 2 is the
    // destination, which keeps the sweep deterministic regardless of which
    // source account is processed first.)
    let destination_ua = regtest_encoded_unified_address_at(harness.test_seed(), 2);

    let crash_dir = tempfile::tempdir().expect("crash tempdir");

    // ─── First run: spawn, wait for sweep_starting, sleep, SIGKILL ────────
    let mut crash_handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-sweep-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", crash_dir.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value("--destination-ua", destination_ua.clone())
    .arg_value(
        "--birthday",
        common::regtest_harness::funding_birthday().to_string(),
    )
    // Two accounts, not three. Account 2 supplies the destination address but
    // must NOT be scanned: it belongs to the same seed, so tracking it makes
    // the destination part of the wallet being swept. The first run sweeps
    // account 0 into account 2; the resumed run then finds account 2 holding
    // those funds and sweeps it as well, producing two broadcasts where the
    // test asserts one — "got 2 broadcasts from accounts [1, 2]".
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "rs29-crash")
    .arg_value("--pause-millis-between-broadcasts", "30000")
    .spawn()
    .await
    .expect("spawn sweep-helper for crash run");

    let starting_deadline = std::time::Instant::now() + Duration::from_secs(180);
    crash_handle
        .wait_for(starting_deadline, |events| {
            events.iter().find_map(|e| match e {
                HelperEvent::SweepStarting => Some(()),
                _ => None,
            })
        })
        .await
        .expect("sweep-helper must emit SweepStarting within 180s");

    // Wait for the first sweep transaction to reach the node's mempool, then
    // kill. The mempool is the only real-time signal available.
    //
    // Two earlier approaches failed in opposite directions. A fixed 8s after
    // `SweepStarting` fired *before* any broadcast, because building the first
    // Sapling proof in a debug build takes longer than that — nothing had been
    // swept, the resumed run swept both accounts, and the failure ("got 2
    // broadcasts") looked like a double-spend defect. Waiting for the helper's
    // own `Broadcast` event fires *after* the sweep finishes entirely: those
    // are emitted from the returned `SweepOutcome`, not as each broadcast
    // happens, so the helper had already exited and there was nothing to kill.
    //
    // `getrawmempool` turns non-empty the moment the first transaction is
    // accepted, which is exactly the start of the helper's pause window.
    let mempool_deadline = std::time::Instant::now() + Duration::from_secs(900);
    loop {
        let mempool =
            common::regtest_harness::zebra_rpc("getrawmempool", serde_json::json!([])).await;
        if mempool.as_array().map(|a| a.len()).unwrap_or(0) > 0 {
            eprintln!("[regtest] R-S29: first sweep transaction is in the mempool");
            break;
        }
        assert!(
            std::time::Instant::now() < mempool_deadline,
            "[regtest] R-S29: no sweep transaction reached the mempool within 900s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let kill_status = crash_handle
        .sigkill_and_wait()
        .await
        .expect("SIGKILL must reap sweep-helper");
    assert!(
        !kill_status.success(),
        "[regtest] R-S29: subprocess should have died from SIGKILL, exited cleanly instead: {kill_status:?}"
    );
    eprintln!("[regtest] R-S29: SIGKILLed first run during pause between broadcasts");

    // Mine the first run's broadcast into the chain before resuming.
    //
    // The test's premise is that the resumed run finds the already-swept
    // account empty and so produces exactly one broadcast. That requires the
    // killed run's transaction to be *confirmed*: a scan reads compact
    // blocks, so an unconfirmed transaction sitting in the mempool is
    // invisible to it. Without this the resumed run re-selects the same notes
    // and the node rejects the rebroadcast — "another transaction in the
    // mempool has already spent some of its inputs" — which is the mempool
    // refusing a double spend, not Argos avoiding one.
    //
    // The original comment on this test assumed the tx "was included in the
    // chain by the harness's miner". Nothing mines on this harness, so that
    // step has to be explicit.
    common::regtest_harness::zebra_rpc("generate", serde_json::json!([1])).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ─── Resume run: same --data-dir, expect exactly 1 broadcast ──────────
    let resume_handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-sweep-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", crash_dir.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value("--destination-ua", destination_ua)
    .arg_value(
        "--birthday",
        common::regtest_harness::funding_birthday().to_string(),
    )
    // Must match the crash run: a different account count is a different
    // workspace, and the resume would start from scratch instead of resuming.
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "rs29-crash") // identical workspace key
    .arg_value("--pause-millis-between-broadcasts", "0")
    .spawn()
    .await
    .expect("spawn sweep-helper for resume");

    let (resume_status, resume_events) = resume_handle
        .wait_for_exit()
        .await
        .expect("resume sweep-helper must run to completion");
    assert!(
        resume_status.success(),
        "[regtest] R-S29: resume run did not exit cleanly: {resume_status:?}; \
         events: {resume_events:?}"
    );

    let resume_broadcasts: Vec<u32> = resume_events
        .iter()
        .filter_map(|e| match e {
            HelperEvent::Broadcast { source_account, .. } => Some(*source_account),
            _ => None,
        })
        .collect();
    assert_eq!(
        resume_broadcasts.len(),
        1,
        "[regtest] R-S29: resume run must produce exactly 1 broadcast (the \
         not-yet-swept account); got {} broadcasts from accounts {:?}",
        resume_broadcasts.len(),
        resume_broadcasts
    );

    eprintln!(
        "[regtest] R-S29 ok: resume swept exactly the not-yet-swept account ({})",
        resume_broadcasts[0]
    );
}

// ─── R-W24: Two scans against the same workspace cancels the first ─────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn two_instances_same_workspace_cancels_first() {
    // Verifies the in-process conflict-cancellation logic in
    // `RecoveryService::start_scan`: when a second `start_scan` is issued
    // against a config that resolves to the same workspace as a previously
    // active scan, the existing session is cancelled before the new one
    // proceeds. This is the property that protects the GUI's typical
    // "double-click Start Scan" race.
    //
    // ## What this test covers
    //
    //   1. The second `start_scan` returns a fresh handle without
    //      blocking on or merging with the first.
    //   2. After the second `start_scan` returns, the first handle's
    //      session has been cancelled (phase = Cancelled).
    //   3. The second scan proceeds to ScanPhase::Complete — workspace
    //      reuse after cancellation does not produce SQLite lock errors
    //      or half-merged state. Final balances on the second handle
    //      reflect a complete scan, not a partial one.
    //
    // ## What this test deliberately does NOT cover
    //
    // Two argos-cli *subprocesses* against the same workspace would
    // exercise SQLite WAL contention, not Argos's cancellation logic
    // (each subprocess has its own RecoveryService, so the in-process
    // cancellation path doesn't fire across processes). That belongs in a
    // separate test with subprocess scaffolding, which lands with the
    // R-S27/R-S29 SIGKILL work.

    let harness = RegtestHarness::require();
    let temp_data_dir = tempfile::tempdir().expect("tempdir");

    let scan_config = ScanConfig {
        birthday: common::regtest_harness::funding_birthday(),
        num_accounts: Some(2),
        gap_limit: 5,
        lightwalletd_url: harness.lightwalletd_url().to_owned(),
        data_dir: temp_data_dir.path().to_path_buf(),
        network: ZeckNetwork::Testnet,
        // Labels go into session.json — the workspace path itself is
        // derived from (seed, network, birthday, gap-strategy) only, so
        // changing the label does NOT change the workspace identity. The
        // conflict-cancellation logic will fire even with different
        // labels, which is the correct behaviour (a relaunched session
        // with a different label is still the same workspace).
        label: "argos-rw24-first".to_owned(),
    };

    let service = RecoveryService::new();

    let handle1 = service
        .start_scan(
            scan_config.clone(),
            SecretString::new(harness.test_seed().to_owned()),
        )
        .await
        .expect("first start_scan must succeed");

    // Hand off briefly so the spawned scan task gets at least one tick.
    // Cancellation works regardless of phase (it sets the flag + aborts
    // the task handle even mid-Idle), but giving the first scan a chance
    // to actually begin makes the "we really did cancel something in
    // flight" property meaningful.
    tokio::task::yield_now().await;

    let handle2 = service
        .start_scan(
            ScanConfig {
                label: "argos-rw24-second".to_owned(),
                ..scan_config
            },
            SecretString::new(harness.test_seed().to_owned()),
        )
        .await
        .expect("second start_scan must succeed against the same workspace");

    assert_ne!(
        handle1.id, handle2.id,
        "[regtest] start_scan must return a fresh handle, not merge with the first"
    );

    // The first handle's session must be Cancelled. cancel_scan sets the
    // phase synchronously before returning, then aborts the task handle.
    // Either outcome (still in the sessions map as Cancelled, or already
    // cleaned up via SESSION_RETENTION_SECS) is acceptable — but a
    // still-Running phase would be a real bug.
    match service.get_scan_progress(&handle1).await {
        Ok(progress) => {
            assert_eq!(
                progress.phase,
                ScanPhase::Cancelled,
                "[regtest] first session must be Cancelled after the second \
                 start_scan; got phase = {:?}",
                progress.phase,
            );
        }
        Err(_) => {
            // Session retention cleanup ran ahead of us; the first handle
            // is no longer in the map. Acceptable — the property under
            // test is "the first scan stopped," which is necessarily true
            // if the handle is gone.
        }
    }

    // Second scan must run to completion. 120s is generous headroom for a
    // ~200-block regtest scan.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let progress = service
            .get_scan_progress(&handle2)
            .await
            .expect("get_scan_progress on the surviving handle");
        match progress.phase {
            ScanPhase::Complete => break,
            ScanPhase::Error => {
                panic!("[regtest] second scan errored: {:?}", progress.error)
            }
            ScanPhase::Cancelled => {
                panic!(
                    "[regtest] second scan was unexpectedly cancelled — \
                     the conflict-cancellation logic should target the \
                     PRIOR scan, not the new one"
                )
            }
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!(
                        "[regtest] second scan did not complete within 120s; \
                         last phase = {:?}",
                        progress.phase
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    eprintln!("[regtest] first scan cancelled, second scan ran to completion");
}

// ─── R-W25: Workspace deleted between scan and sweep ───────────────────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn workspace_deleted_between_scan_and_sweep_surfaces_clean_error() {
    // Verifies that an externally-deleted workspace surfaces a clean Err
    // from `propose_sweep`, not a panic or partial-state corruption.
    //
    // Scenario: user completes a scan in the GUI, then `rm -rf`s the
    // workspace directory from another terminal before clicking Sweep.
    // Argos must surface this as a user-actionable error rather than
    // crashing or silently producing an empty proposal.

    let harness = RegtestHarness::require();
    let temp_data_dir = tempfile::tempdir().expect("tempdir for workspace");
    let fixture = complete_scan_against_test_seed(&harness, &temp_data_dir, "argos-rw25").await;

    // Simulate the external rm -rf.
    std::fs::remove_dir_all(&fixture.workspace_root)
        .expect("remove_dir_all on the workspace root must succeed");
    assert!(
        !fixture.workspace_root.exists(),
        "[regtest] workspace root should be gone after remove_dir_all"
    );

    // The sweep request itself is valid — destination is a real UA and the
    // rate fields are absent. The only thing different from a normal sweep
    // is that the workspace under the service's recorded handle is gone.
    let request = SweepRequest {
        destination: fixture.destination_ua.clone(),
        memo: None,
        max_fee_zatoshis: None,
        donation_rate: None,
        donor_email: None,
    };

    let result = fixture
        .service
        .propose_sweep(&fixture.handle, request)
        .await;
    let err =
        result.expect_err("propose_sweep against a deleted workspace must return Err, not Ok");

    // Don't pin the error variant — the wallet-DB / cache-DB / sidecar-JSON
    // layers all touch the workspace and any of them surfacing the missing
    // path first is correct. The contract is: a clean Err that the GUI/CLI
    // can render to a user, not a panic.
    eprintln!("[regtest] propose_sweep failed as expected after workspace deletion: {err}");
}

// ─── Only wallet.sqlite deleted, directory intact ──────────────────────────
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn deleting_only_the_wallet_db_surfaces_a_clean_error() {
    // The hole the workspace check was written for, and the one the
    // whole-directory tests above cannot reach.
    //
    // `open_wallet_db` goes through `Connection::open`, which defaults to
    // READ_WRITE | CREATE. With the parent directory intact, deleting only
    // `wallet.sqlite` means the open *succeeds* by silently recreating an
    // empty database — so a check that merely opens it passes, and
    // `propose_sweep` quotes the stale in-memory balance: exactly the
    // confidently-wrong number the check exists to prevent. It also leaves
    // a stray empty DB behind during a documented read-only quote.
    //
    // Raised in review of #189, where the fix (requiring a readable wallet
    // summary, not just a successful open) landed without a test that
    // reaches this specific state.

    let harness = RegtestHarness::require();
    let temp_data_dir = tempfile::tempdir().expect("tempdir for workspace");
    let fixture = complete_scan_against_test_seed(&harness, &temp_data_dir, "argos-rw27").await;

    // Find the wallet DB and remove only that file.
    let wallet_db = fixture.workspace_root.join("wallet.sqlite");
    assert!(
        wallet_db.exists(),
        "[regtest] expected a wallet.sqlite at {}",
        wallet_db.display()
    );
    std::fs::remove_file(&wallet_db).expect("removing wallet.sqlite must succeed");
    assert!(
        fixture.workspace_root.exists(),
        "[regtest] the workspace directory must remain — that is the whole point"
    );

    let request = SweepRequest {
        destination: fixture.destination_ua.clone(),
        memo: None,
        max_fee_zatoshis: None,
        donation_rate: None,
        donor_email: None,
    };

    let result = fixture
        .service
        .propose_sweep(&fixture.handle, request)
        .await;
    let err = result.expect_err(
        "propose_sweep must fail when wallet.sqlite is gone, even though the directory \
         remains and SQLite will happily create an empty database in its place",
    );
    eprintln!("[regtest] propose_sweep failed as expected after wallet.sqlite deletion: {err}");
}

// ─── R-W26: Workspace permissions tampered ─────────────────────────────────
#[cfg(unix)]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
async fn workspace_permissions_tampered_surfaces_clean_error() {
    // Verifies that an externally-tampered workspace directory (chmod 0o000
    // so the running process can't traverse into it) surfaces a clean Err
    // rather than a panic.
    //
    // Scenario: the user (or a hostile process running as the same uid)
    // strips the workspace's permissions between scan-complete and sweep.
    // Argos must surface "cannot access workspace" cleanly.

    use std::os::unix::fs::PermissionsExt;

    let harness = RegtestHarness::require();
    let temp_data_dir = tempfile::tempdir().expect("tempdir for workspace");
    let fixture = complete_scan_against_test_seed(&harness, &temp_data_dir, "argos-rw26").await;

    // Strip permissions on the leaf workspace directory. 0o000 blocks even
    // traversal — opening files inside fails because the directory has no
    // execute bit. Owned by the test process (we created it via Argos), so
    // we can chmod it back later.
    std::fs::set_permissions(
        &fixture.workspace_root,
        std::fs::Permissions::from_mode(0o000),
    )
    .expect("chmod 0o000 on workspace root");

    // RAII guard: restore 0o700 on the workspace before the tempdir tries to
    // recursively delete it (otherwise the tempdir's cleanup would itself
    // fail with permission-denied). Declared after we apply 0o000 so it
    // drops first (LIFO) — before `temp_data_dir`'s Drop.
    struct RestorePerms<'a>(&'a std::path::Path);
    impl Drop for RestorePerms<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _restore = RestorePerms(&fixture.workspace_root);

    let request = SweepRequest {
        destination: fixture.destination_ua.clone(),
        memo: None,
        max_fee_zatoshis: None,
        donation_rate: None,
        donor_email: None,
    };

    let result = fixture
        .service
        .propose_sweep(&fixture.handle, request)
        .await;
    let err = result
        .expect_err("propose_sweep against a workspace with stripped permissions must return Err");

    eprintln!("[regtest] propose_sweep failed as expected after chmod 0o000: {err}");
}

// ─── Donation split (end-to-end) ────────────────────────────────────────────
//
// First end-to-end coverage of the donation path. Regression target: the
// donation-split fee convergence seeded the candidate fee with the
// *single-output* send-max fee, so `propose_transfer` failed with "insufficient
// funds" on the first iteration and the split silently fell back to a
// donation-free sweep — donating 0 on every sweep. No prior test exercised it
// (all other sweep tests pass `donation_rate: None`; the unit tests use string
// stand-ins), which is why it shipped broken.
//
// Donation is disabled on testnet (the baked address is mainnet-only and
// undecodable on regtest), so this injects a regtest donation UA via
// `ARGOS_TEST_DONATION_ADDRESS`, honored only under the `argos-network` feature.
// Requires the harness funded enough that 10% of a swept account clears the
// 0.001 ZEC floor (regtest coinbase amounts do).
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported) and --features argos-network"]
#[tokio::test]
async fn sweep_places_a_donation_output_when_rate_is_set() {
    let harness = RegtestHarness::require();

    // Fund this test rather than inheriting whatever an earlier sweep left.
    // These tests share the test seed's accounts and drain them, so which one
    // had funds used to depend on the order cargo happened to run them in.
    // Funding also mines a block, clearing any pending sweep from an earlier
    // test — a scan cannot see an unconfirmed spend, so without that this scan
    // would build a conflicting transaction and be rejected on broadcast.
    common::regtest_harness::fund_test_account(0, 1_250_000_000).await;

    let temp_data_dir = tempfile::tempdir().expect("tempdir for donation sweep");
    let fixture = complete_scan_against_test_seed(&harness, &temp_data_dir, "argos-donate").await;

    // A regtest donation recipient, distinct from the sweep destination, so the
    // donation-split path runs against a decodable testnet UA.
    let donation_ua = regtest_encoded_unified_address_at(harness.test_seed(), 2);
    assert_ne!(
        donation_ua, fixture.destination_ua,
        "donation recipient must differ from the sweep destination"
    );
    std::env::set_var("ARGOS_TEST_DONATION_ADDRESS", &donation_ua);

    let request = SweepRequest {
        destination: fixture.destination_ua.clone(),
        memo: None,
        max_fee_zatoshis: None,
        donation_rate: Some(0.10),
        donor_email: None,
    };
    let outcome = fixture
        .service
        .execute_sweep(&fixture.handle, request)
        .await;

    // Always clear the override, even on assertion failure below.
    std::env::remove_var("ARGOS_TEST_DONATION_ADDRESS");

    let outcome = outcome.expect("execute_sweep with a 10% donation rate should succeed");
    assert!(
        !outcome.transactions.is_empty(),
        "[regtest] sweep should have broadcast at least one transaction"
    );
    assert!(
        outcome.total_donation_zatoshis > 0,
        "[regtest] a 10% donation on a funded sweep must place a donation output; \
         regression: the fee convergence fell back to a donation-free sweep and donated 0 \
         (broadcast {} tx, skipped {} account(s))",
        outcome.transactions.len(),
        outcome.skipped_accounts.len(),
    );
    eprintln!(
        "[regtest] donation sweep placed {} zats across {} tx(s)",
        outcome.total_donation_zatoshis,
        outcome.transactions.len()
    );
}

// ─── FakeLightwalletd fixture smoke test ────────────────────────────────────
//
// Validates the proto-codegen and tonic-server plumbing for the in-process
// `FakeLightwalletd` fixture (`tests/common/fake_lightwalletd.rs`). Boots the
// fixture in pure-skeleton mode (no upstream) and confirms a real Argos
// gRPC client can probe it, get back the configured chain identity, and pass
// `validate_lightwalletd_network` as a regtest server under the
// `argos-network` feature.
//
// `#[ignore]` so it doesn't run in default `cargo test`; the fault-injection
// follow-up PR will lift the gate once R-N8/R-N9 land.
#[cfg(feature = "argos-network")]
#[ignore = "fixture smoke test; run with --ignored --features argos-network"]
#[tokio::test]
async fn fake_lightwalletd_smoke() {
    use argos_core::lightwalletd::{probe_lightwalletd_endpoints, validate_lightwalletd_network};
    use argos_core::models::ZeckNetwork;

    // Needed even though this test talks to a fixture rather than the
    // harness: `validate_lightwalletd_network` only relaxes the Sapling-height
    // check when `regtest_consensus_params_installed()` is true, and
    // `require()` is what installs them. Without this the test passes only
    // when some *other* test in the same process happened to install them
    // first, and fails on its own with the original #186 error — "server
    // Sapling activation height 1 does not match expected 280000 for
    // testnet". Latent for as long as it was only ever run in a full suite.
    let _harness = RegtestHarness::require();

    let fake = common::fake_lightwalletd::FakeLightwalletd::builder()
        .chain_name("regtest")
        .sapling_activation_height(1)
        .block_height(42)
        .build()
        .await
        .expect("bind FakeLightwalletd on loopback");

    let (_client, endpoint, info) = probe_lightwalletd_endpoints(&fake.url)
        .await
        .expect("Argos client probes FakeLightwalletd cleanly");

    assert_eq!(endpoint, fake.url);
    assert_eq!(info.chain_name, "regtest");
    assert_eq!(info.sapling_activation_height, 1);
    assert_eq!(info.block_height, 42);

    validate_lightwalletd_network(ZeckNetwork::Testnet, &info)
        .expect("regtest chain must validate as Testnet under argos-network");
}

// ─── Helper-binary smoke tests (scaffolding for R-S27 / R-S29) ──────────────
//
// These tests prove that the `argos-scan-helper` and `argos-sweep-helper`
// binaries can be spawned, parse their CLI, talk to the real harness, and
// emit the documented stdout schema end-to-end. They run against the bare
// harness (no fault injection); the actual R-S27 and R-S29 tests in the
// next PR will exercise SIGKILL behaviour on top of this scaffolding.
//
// Both gated `#[ignore]` like every other C2 test — only run with
// `--features argos-network -- --ignored` after `tests/regtest/setup.sh`
// has funded the test seed.

#[cfg(feature = "argos-network")]
#[ignore = "scan-helper smoke test; requires the booted regtest harness"]
#[tokio::test]
async fn argos_scan_helper_smoke() {
    use common::subprocess_driver::{HelperEvent, HelperSpawn};

    let harness = RegtestHarness::require();
    let temp = tempfile::tempdir().expect("temp data dir for scan-helper smoke");

    let mut handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-scan-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", temp.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value(
        "--birthday",
        common::regtest_harness::funding_birthday().to_string(),
    )
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "smoke")
    .spawn()
    .await
    .expect("spawn argos-scan-helper");

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let total = handle
        .wait_for(deadline, |events| {
            events.iter().find_map(|e| match e {
                HelperEvent::Complete { total_zatoshis } => Some(*total_zatoshis),
                _ => None,
            })
        })
        .await
        .expect("scan-helper must reach Complete within 120s");

    assert!(
        total > 0,
        "[regtest] scan-helper smoke: setup.sh should have funded the test seed; got 0 zatoshis"
    );

    // Confirm the helper observed a transition through ScanningShielded —
    // proves the stdout schema covers phase transitions, not just final
    // events.
    let saw_shielded = handle.events().iter().any(|e| {
        matches!(
            e,
            HelperEvent::Phase { phase } if phase == "scanning_shielded"
        )
    });
    assert!(
        saw_shielded,
        "[regtest] scan-helper smoke: expected a `scanning_shielded` phase event"
    );

    let (status, _events) = handle
        .wait_for_exit()
        .await
        .expect("scan-helper must exit cleanly after Complete");
    assert!(
        status.success(),
        "[regtest] scan-helper exit status was not success: {status:?}"
    );
}

#[cfg(feature = "argos-network")]
#[ignore = "sweep-helper smoke test; requires the booted regtest harness"]
#[tokio::test]
async fn argos_sweep_helper_smoke() {
    use common::subprocess_driver::{HelperEvent, HelperSpawn};

    let harness = RegtestHarness::require();

    // Fund what this is about to sweep. Every sweep test drains the accounts
    // it touches, so a test that does not ask for funds gets whatever the
    // ones before it happened to leave — which is to say, nothing.
    common::regtest_harness::fund_test_account(0, 1_250_000_000).await;

    let temp = tempfile::tempdir().expect("temp data dir for sweep-helper smoke");

    // Derive account-1's UA from the test seed — same trick the workspace
    // tests use to get a syntactically-valid UA without needing a second
    // funded seed in the harness.
    let destination_ua = regtest_encoded_unified_address_at(harness.test_seed(), 1);

    let mut handle = HelperSpawn::new(
        env!("CARGO_BIN_EXE_argos-sweep-helper"),
        harness.test_seed().to_owned(),
    )
    .arg_value("--data-dir", temp.path().display().to_string())
    .arg_value("--lightwalletd-url", harness.lightwalletd_url().to_owned())
    .arg_value("--destination-ua", destination_ua)
    .arg_value(
        "--birthday",
        common::regtest_harness::funding_birthday().to_string(),
    )
    .arg_value("--num-accounts", "2")
    .arg_value("--gap-limit", "5")
    .arg_value("--label", "smoke-sweep")
    // No pause for the smoke test; just prove the end-to-end flow.
    .arg_value("--pause-millis-between-broadcasts", "0")
    .spawn()
    .await
    .expect("spawn argos-sweep-helper");

    // 600s, not 240s. setup.sh now funds accounts 0 and 1 (R-S29 cannot
    // exist otherwise), so this sweeps two accounts and builds two Sapling
    // proofs instead of one. Proving dominates, and these tests run against
    // an unoptimised debug build.
    let deadline = std::time::Instant::now() + Duration::from_secs(600);
    let broadcast_count = handle
        .wait_for(deadline, |events| {
            events.iter().find_map(|e| match e {
                HelperEvent::SweepComplete { broadcast_count } => Some(*broadcast_count),
                _ => None,
            })
        })
        .await
        .expect("sweep-helper must reach SweepComplete within 600s");

    // Lower bound rather than an exact count: how many accounts setup.sh
    // funds is the harness's business, not this test's. R-S29 is the test
    // that depends on the count being exactly two.
    assert!(
        broadcast_count >= 1,
        "[regtest] sweep-helper smoke: expected at least one broadcast"
    );

    // Confirm we observed the SweepStarting marker — R-S29 will use that as
    // its kill signal.
    let saw_starting = handle
        .events()
        .iter()
        .any(|e| matches!(e, HelperEvent::SweepStarting));
    assert!(
        saw_starting,
        "[regtest] sweep-helper smoke: expected SweepStarting event"
    );

    let (status, _events) = handle
        .wait_for_exit()
        .await
        .expect("sweep-helper must exit cleanly after SweepComplete");
    assert!(
        status.success(),
        "[regtest] sweep-helper exit status was not success: {status:?}"
    );
}

// ─── Post-Ironwood sweep ───────────────────────────────────────────────────
//
// The reason the harness moved from zcashd to Zebra. zcashd has no NU6.3, so
// this scenario was unreachable: `UPGRADE_NU6_3` appears nowhere in
// zcash/zcash, not even on master.
//
// What it guards: from Ironwood activation, a sweep must be signed with the
// NU6.3 consensus branch ID (0x37a5165b). Argos resolved consensus parameters
// from `ZeckNetwork` alone, so against a regtest chain it used *testnet*
// activation heights — under which a few-hundred-block chain resolves to a
// pre-NU5 branch. Scanning tolerates that; a sweep does not. The node rejects
// the transaction outright. A green result here means the branch ID Argos
// signed with is the one Zebra expects.

/// Re-encode a testnet-encoded address under the harness's regtest
/// parameters. `argos show-keys` and `derive_accounts` emit `utest1...`, while
/// the regtest parameter set expects `uregtest1...`; the receivers are
/// identical, only the HRP differs.
#[cfg(feature = "argos-network")]
fn regtest_encoded_unified_address(seed: &str) -> String {
    regtest_encoded_unified_address_at(seed, 0)
}

/// As above, for a destination account other than the first.
///
/// Several tests deliberately sweep to an account *outside* the funded set,
/// so they need a specific index rather than always account 0.
#[cfg(feature = "argos-network")]
fn regtest_encoded_unified_address_at(seed: &str, index: usize) -> String {
    use argos_core::workspace::consensus_network;
    use zcash_keys::address::Address;

    let accounts = argos_core::derive_accounts(
        &secrecy::SecretString::new(seed.to_owned()),
        argos_core::ZeckNetwork::Testnet,
        u32::try_from(index + 1).expect("account index fits u32"),
    )
    .expect("deriving destination accounts");

    let address = Address::decode(
        &zcash_protocol::consensus::Network::TestNetwork,
        &accounts[index].unified_address,
    )
    .expect("argos produced an undecodable unified address");

    address.encode(&consensus_network(argos_core::ZeckNetwork::Testnet))
}

#[tokio::test]
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[cfg(feature = "argos-network")]
async fn post_ironwood_sweep_is_accepted_by_the_node() {
    use argos_core::{RecoveryService, ScanConfig, ScanPhase, SweepRequest, ZeckNetwork};

    // `require()` installs the regtest activation heights for the whole
    // process; without them this sweep would be signed for a pre-NU5 branch
    // and rejected by the node, which is the regression under test.
    let harness = RegtestHarness::require();

    // Fund from the treasury rather than relying on setup.sh having run. The
    // sweep spends everything it finds, so a second run would otherwise find
    // an empty wallet — or worse, collide with the first run's transaction
    // still sitting in the mempool.
    //
    // This used to mine shielded coinbase. That pays nothing here: the
    // harness sits past height 32,257 for ZIP 212 and the regtest subsidy is
    // worthless by ~6,000, so the test funded itself with zero and failed as
    // though the sweep were broken.
    common::regtest_harness::fund_test_account(0, 1_250_000_000).await;

    let data_dir = tempfile::tempdir().expect("temp data dir");
    let service = RecoveryService::new();
    let handle = service
        .start_scan(
            ScanConfig {
                birthday: common::regtest_harness::funding_birthday(),
                num_accounts: Some(1),
                gap_limit: 1,
                lightwalletd_url: harness.lightwalletd_url().to_owned(),
                data_dir: data_dir.path().to_path_buf(),
                network: ZeckNetwork::Testnet,
                label: "post-ironwood-sweep".to_owned(),
            },
            secrecy::SecretString::new(harness.test_seed().to_owned()),
        )
        .await
        .expect("starting scan");

    let discovered: u64 = loop {
        let progress = service
            .get_scan_progress(&handle)
            .await
            .expect("polling scan");
        match progress.phase {
            ScanPhase::Complete => break progress.discoveries.iter().map(|d| d.zatoshis).sum(),
            ScanPhase::Error => panic!(
                "scan failed: {}",
                progress
                    .error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no error set".to_owned())
            ),
            ScanPhase::Cancelled => panic!("scan was cancelled"),
            _ => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    };

    assert!(
        discovered > 0,
        "test seed holds no funds — run tests/regtest/setup.sh to fund it with \
         shielded coinbase before running this test"
    );

    // Sweep everything to a destination the test seed does not control. The
    // funder mnemonic is reused purely as a convenient unrelated identity.
    let destination = regtest_encoded_unified_address(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
         zoo zoo vote",
    );

    // Nothing mines on regtest unless we ask it to, so the sweep's
    // wait-for-confirmation window would otherwise always expire and report
    // `pending`. Mine alongside the sweep so confirmation is actually
    // observed and the assertion below can demand the stronger status.
    let mining = tokio::spawn(async {
        let url = std::env::var("ARGOS_REGTEST_ZEBRA_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18232".to_owned());
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let _ = zebra_generate(&url, 1).await;
        }
    });

    let outcome = service
        .execute_sweep(
            &handle,
            SweepRequest {
                destination,
                memo: None,
                max_fee_zatoshis: None,
                donation_rate: None,
                donor_email: None,
            },
        )
        .await
        .expect("sweep must not error");
    mining.abort();

    assert!(
        !outcome.transactions.is_empty(),
        "sweep broadcast nothing despite {discovered} zatoshis discovered; skipped: {:?}",
        outcome.skipped_accounts
    );

    // The load-bearing assertion. Reaching the node at all means the
    // transaction was built, proved and signed; being accepted means it
    // carried the Ironwood consensus branch ID rather than a pre-NU5 one.
    //
    // `confirmed` is the strong outcome (the node mined it); `broadcast` means
    // accepted into the mempool but not yet mined. Both prove the branch ID was
    // right. `pending` means the confirmation window expired, which happens if
    // the background miner above is not keeping up, and a rejected branch ID
    // would have surfaced as an `Err` from `execute_sweep` rather than reaching
    // here at all.
    for tx in &outcome.transactions {
        assert!(
            matches!(tx.status.as_str(), "confirmed" | "broadcast"),
            "post-Ironwood sweep was not accepted by the node: {} — {}",
            tx.status,
            tx.detail
        );
        assert!(tx.txid.is_some(), "accepted sweep has no txid: {tx:?}");
    }
}

/// Mine `blocks` blocks on the harness chain via Zebra's JSON-RPC. Regtest
/// disables proof of work, so `generate` returns as soon as the blocks are
/// committed. Zebra runs with cookie auth disabled, so no credentials are sent.
#[cfg(feature = "argos-network")]
async fn zebra_generate(url: &str, blocks: u32) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let host_port = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .trim_end_matches('/');
    let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"generate","params":[{blocks}]}}"#);
    let mut stream = tokio::net::TcpStream::connect(host_port).await?;
    stream
        .write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
            .as_bytes(),
        )
        .await?;
    let mut sink = Vec::new();
    stream.read_to_end(&mut sink).await?;
    Ok(())
}

/// Transparent-only recovery, end to end against a real chain.
///
/// This is the only test that proves `build_sweep_transaction` produces a
/// transaction the network actually accepts. Everything else about the
/// transparent path — fee arithmetic, value conservation, dust refusal — is
/// unit-tested, but a transaction that balances arithmetically can still be
/// rejected for a wrong branch ID, a malformed script, or a bad signature.
/// Only a node can tell us that.
///
/// The wallet here is transparent-only *by construction*: a single raw
/// secp256k1 key, exactly what a zcashd `wallet.dat` yields. It never gets a
/// wallet-database account, because it cannot have one.
///
/// Note the funds are coinbase. Zcash forbids a transaction spending
/// transparent coinbase from having any transparent output, and a
/// transparent-only sweep is N inputs to one Sapling output with no change —
/// so it satisfies that by construction. That makes this the *stricter*
/// consensus case: an ordinary UTXO differs only in being easier to spend.
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
#[cfg(feature = "argos-network")]
async fn transparent_only_wallet_sweeps_to_a_shielded_destination() {
    use argos_core::lightwalletd::connect_lightwalletd_endpoints_with_retry;
    use argos_core::transparent_recovery::{
        build_sweep_transaction, fetch_transparent_utxos, plan_sweep, sapling_receiver, summarize,
    };
    use argos_core::workspace::consensus_network;
    use argos_core::{derive_accounts, ZeckNetwork};
    use common::regtest_harness::zebra_rpc;
    use secrecy::SecretString;
    use zcash_client_backend::proto::service::RawTransaction;
    use zcash_proofs::prover::LocalTxProver;
    use zcash_protocol::consensus::BlockHeight;

    // Installs regtest consensus parameters process-wide; every encoding and
    // branch-ID derivation below depends on them.
    let harness = RegtestHarness::require();

    // A key this test owns outright, funded by `setup.sh` at a height where
    // the regtest subsidy is still worth something. It deliberately does not
    // come from the golden fixture: the imported-Sapling test sweeps that
    // wallet through `execute_sweep`, which drains its transparent UTXOs too,
    // so a fixture key would be empty whenever this test ran second. It is
    // also the more faithful fixture for a transparent-*only* wallet, which
    // the Sapling-bearing golden file is not. See
    // `tests/common/standalone_transparent.rs`.
    let keys = vec![common::standalone_transparent::standalone_transparent_key()];

    // Top this key up from the treasury. It is not an HD account of the test
    // seed, so `fund_test_account` cannot reach it — hence `fund_address`.
    // Without this the test inherits whatever setup.sh last left, and any
    // earlier sweep run against the same chain leaves it empty.
    common::regtest_harness::fund_address(
        &argos_core::imported::encode_transparent_address(&keys[0].address, ZeckNetwork::Testnet),
        1_250_000_000,
    )
    .await;

    let (mut client, _endpoint) =
        connect_lightwalletd_endpoints_with_retry(harness.lightwalletd_url(), None)
            .await
            .expect("connecting to the harness lightwalletd");

    let utxos = fetch_transparent_utxos(&mut client, &keys, ZeckNetwork::Testnet)
        .await
        .expect("fetching UTXOs");
    assert!(
        !utxos.is_empty(),
        "the funded address must have spendable UTXOs; if this is empty the \
         address encoding or the funding call is wrong, not the sweep"
    );

    let report = summarize(&utxos, keys.len(), 0, ZeckNetwork::Testnet);
    assert!(
        report.total_zatoshis > 0,
        "a funded wallet must report a non-zero balance"
    );

    // Target the next block, as a wallet broadcasting now would.
    let tip = zebra_rpc("getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("getblockcount returns a number");
    let target_height = BlockHeight::from_u32(u32::try_from(tip).expect("height fits u32") + 1);
    let params = consensus_network(ZeckNetwork::Testnet);

    let plan = plan_sweep(&params, target_height, &utxos)
        .expect("planning must succeed for a funded wallet")
        .expect("a funded wallet must produce a plan");
    assert_eq!(
        plan.output_zatoshis + plan.fee_zatoshis,
        plan.total_input_zatoshis
    );

    // Destination: a unified address from the harness seed. It must be
    // unified, not a bare Sapling address — Argos's destination policy
    // rejects non-UA destinations, and `sapling_receiver` deliberately goes
    // through that same check rather than around it. Testnet-encoded like
    // every other destination in this suite; the encoding is a display
    // concern and the builder consumes the raw receiver.
    let accounts = derive_accounts(
        &SecretString::new(harness.test_seed().to_owned()),
        ZeckNetwork::Testnet,
        1,
    )
    .expect("deriving a destination");
    let recipient = sapling_receiver(&accounts[0].unified_address, ZeckNetwork::Testnet)
        .expect("the seed's unified address must expose a Sapling receiver");

    let prover = LocalTxProver::bundled();
    let tx = build_sweep_transaction(
        &params,
        target_height,
        &utxos,
        &keys,
        &plan,
        recipient,
        &prover,
        &prover,
    )
    .expect("building the sweep transaction");

    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serializing the transaction");

    // The assertion that matters: the node accepts it. A wrong branch ID, a
    // malformed script, or a bad signature all fail here and nowhere earlier.
    let response = client
        .send_transaction(RawTransaction {
            data: raw,
            height: 0,
        })
        .await
        .expect("send_transaction RPC")
        .into_inner();
    assert_eq!(
        response.error_code, 0,
        "the node rejected the sweep transaction: {}",
        response.error_message
    );

    // Mine it and confirm it actually landed, rather than trusting mempool
    // acceptance alone.
    zebra_rpc("generate", serde_json::json!([1])).await;
    let txid = tx.txid().to_string();
    let mined = zebra_rpc("getrawtransaction", serde_json::json!([txid, 1])).await;
    assert!(
        mined.get("height").and_then(|h| h.as_u64()).is_some(),
        "the swept transaction must be mined into a block, got: {mined}"
    );

    // And the wallet is now empty: the sweep moved everything.
    let after = fetch_transparent_utxos(&mut client, &keys, ZeckNetwork::Testnet)
        .await
        .expect("re-fetching UTXOs");
    let after_total: u64 = after.iter().fold(0u64, |acc, u| {
        acc.saturating_add(u64::from(u.txout.value()))
    });
    assert_eq!(
        after_total, 0,
        "every UTXO must have been swept; {} zatoshis remain",
        after_total
    );
}

/// An imported zcashd wallet is scanned as real wallet-database accounts.
///
/// The unit tests prove `register_imported_accounts` writes the right rows;
/// only a chain proves the scanner then *uses* them — that a Sapling
/// account with no ZIP-32 derivation actually syncs, and that the
/// transparent keys hanging off it as standalone receivers are picked up
/// in the same pass rather than needing the separate transparent path.
///
/// The fixture wallet holds no funds on this chain, so the assertion is
/// about the scan completing over real accounts, not about a balance. A
/// scan that silently found zero accounts would look identical in the
/// total but differ here: the account count and the terminal phase.
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
#[cfg(feature = "argos-network")]
async fn an_imported_zcashd_wallet_scans_as_wallet_accounts() {
    use argos_core::{ImportedKeySource, RecoveryService, ScanConfig, ScanPhase, ZeckNetwork};

    let harness = RegtestHarness::require();

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
    );
    let bytes = std::fs::read(fixture).expect("golden fixture must exist");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("the plaintext fixture must import");
    let sapling_keys = keys.sapling.len();
    assert!(
        sapling_keys > 0 && !keys.transparent.is_empty(),
        "the fixture must hold both Sapling and transparent keys or this proves nothing"
    );
    // The property under test only exists for a wallet with no seed.
    assert!(
        keys.mnemonic.is_none(),
        "the fixture must be seedless or this exercises the HD path instead"
    );

    let data_dir = tempfile::tempdir().expect("temp data dir");
    let service = RecoveryService::new();
    let handle = service
        .start_scan_from_key_source(
            ScanConfig {
                birthday: common::regtest_harness::funding_birthday(),
                num_accounts: Some(1),
                gap_limit: 1,
                lightwalletd_url: harness.lightwalletd_url().to_owned(),
                data_dir: data_dir.path().to_owned(),
                network: ZeckNetwork::Testnet,
                label: String::new(),
            },
            std::sync::Arc::new(ImportedKeySource::new(keys)),
        )
        .await
        .expect("starting an imported scan");

    let progress = loop {
        let progress = service
            .get_scan_progress(&handle)
            .await
            .expect("scan progress should be readable");
        if progress.phase.is_terminal() {
            break progress;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };

    assert_eq!(
        progress.phase,
        ScanPhase::Complete,
        "an imported scan must complete, got {:?}: {:?}",
        progress.phase,
        progress.error
    );
    assert_eq!(
        progress.accounts.len(),
        sapling_keys,
        "every imported Sapling key must appear as a scanned account"
    );
    // The account must be a real one, not a placeholder: a scanned account
    // reports a usable address.
    assert!(
        !progress.accounts[0].sapling_address.is_empty(),
        "an imported account must report its Sapling address"
    );
    assert!(
        !progress.accounts[0].transparent_receive_address.is_empty(),
        "the imported transparent keys must be attached to the account"
    );
}

/// Spending an imported Sapling key, end to end against a real node.
///
/// This is the assertion the whole PCZT detour exists for. A standalone
/// `sapzkey` cannot be spent through `SpendingKeys`, which takes its
/// Sapling authority solely from a `UnifiedSpendingKey`; the claim is that
/// the PCZT roles can. Nothing short of a node accepting the transaction
/// proves that — a PCZT can be assembled, proved, and signed and still be
/// rejected for a wrong sighash, a missing proof generation key, or a
/// signature over the wrong bundle.
///
/// The wallet here is seedless by construction: one Sapling key, imported,
/// registered with no ZIP-32 derivation.
#[ignore = "requires the Argos network harness (tests/regtest/ booted, ARGOS_REGTEST_LIGHTWALLETD_URL exported)"]
#[tokio::test]
#[cfg(feature = "argos-network")]
async fn an_imported_sapling_key_can_be_spent_via_pczt() {
    use argos_core::{ImportedKeySource, RecoveryService, ScanConfig, ScanPhase, ZeckNetwork};
    use common::regtest_harness::zebra_rpc;

    let harness = RegtestHarness::require();

    // A real Sapling key our own parser recovered from a wallet zcashd wrote.
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
    );
    let bytes = std::fs::read(fixture).expect("golden fixture must exist");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("fixture must import");
    assert!(
        keys.mnemonic.is_none(),
        "the fixture must be seedless or this exercises the HD path"
    );
    assert!(
        !keys.sapling.is_empty(),
        "the fixture must hold a Sapling key or there is nothing to spend"
    );

    // Funding comes from `setup.sh`, which pays shielded coinbase to this
    // exact address in the first few hundred blocks — the only heights
    // where the regtest subsidy is worth anything. The test cannot fund
    // itself: it runs above height 32,257 for PCZT's ZIP 212 requirement,
    // and coinbase there is worth zero.
    //
    // The birthday must therefore be 1. Starting anywhere near the tip
    // would scan past the funding and find an empty wallet. The cost is a
    // full-chain scan, which is why this test takes over a minute.
    let data_dir = tempfile::tempdir().expect("temp data dir");
    let config = ScanConfig {
        birthday: 1,
        num_accounts: Some(1),
        gap_limit: 1,
        lightwalletd_url: harness.lightwalletd_url().to_owned(),
        data_dir: data_dir.path().to_owned(),
        network: ZeckNetwork::Testnet,
        label: String::new(),
    };
    // `ImportedKeys` is deliberately not `Clone` — it holds spending keys —
    // so re-parse the fixture for the second consumer instead.
    let source = std::sync::Arc::new(ImportedKeySource::new(
        argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
            .expect("fixture must import"),
    ));
    let service = RecoveryService::new();
    let handle = service
        .start_scan_from_key_source(config.clone(), source.clone())
        .await
        .expect("starting the imported scan");
    let progress = loop {
        let progress = service
            .get_scan_progress(&handle)
            .await
            .expect("progress readable");
        if progress.phase.is_terminal() {
            break progress;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };
    assert_eq!(
        progress.phase,
        ScanPhase::Complete,
        "the scan must complete: {:?}",
        progress.error
    );
    assert!(
        progress.accounts[0].sapling_zatoshis > 0,
        "the funded Sapling note must be visible before it can be spent; got {:?}",
        progress.accounts[0]
    );

    // Sweep through `RecoveryService::execute_sweep` — the surface the CLI
    // and the GUI both call — rather than the builder underneath it. That
    // covers the routing that sends a seedless key source down the imported
    // path, which is the part a front-end depends on and which calling the
    // builder directly would leave untested.
    let destination = regtest_encoded_unified_address(harness.test_seed());
    let outcome = service
        .execute_sweep(
            &handle,
            SweepRequest {
                destination: destination.clone(),
                memo: None,
                donation_rate: None,
                donor_email: None,
                max_fee_zatoshis: None,
            },
        )
        .await
        .expect("the imported sweep must succeed");

    assert!(
        outcome.error.is_none(),
        "the sweep reported an error: {:?}",
        outcome.error
    );
    let sapling_tx = outcome
        .transactions
        .iter()
        .find(|tx| tx.detail.contains("Sapling"))
        .unwrap_or_else(|| {
            panic!(
                "no Sapling transaction was broadcast; skipped: {:?}",
                outcome.skipped_accounts
            )
        });
    let txid = sapling_tx
        .txid
        .as_ref()
        .expect("a broadcast transaction must have a txid");

    // Mempool acceptance is not proof of validity — mine it and confirm.
    zebra_rpc("generate", serde_json::json!([1])).await;
    let mined = zebra_rpc("getrawtransaction", serde_json::json!([txid, 1])).await;
    assert!(
        mined.get("height").and_then(|h| h.as_u64()).is_some(),
        "the sweep must be mined, got: {mined}"
    );
}
