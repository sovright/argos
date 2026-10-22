//! The `--wallet-file` surface, exercised end to end against real golden
//! wallets.
//!
//! These run the actual binary rather than calling library functions,
//! because the things most likely to break here are wiring: an argument
//! that doesn't reach the key source, a command that prompts when it
//! shouldn't, or a refusal that turns into a silent empty result. None of
//! those are visible from inside the library.
//!
//! No new dev-dependency: `CARGO_BIN_EXE_<name>` is a cargo built-in that
//! points at the freshly-built binary.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};

use argos_core::broadcast::{
    BroadcastStore, EndpointTxEvidence, PreparedTransaction, SubmissionDisposition, TxObservation,
    TxObservationState,
};
use argos_core::{TxLifecycleState, ZeckNetwork};
use secrecy::ExposeSecret;
use zcash_primitives::transaction::TxId;

/// zcashd wallet with a Sprout address, a Sapling address, and transparent
/// keys. Written by a real `zcashd` v6.20.0, so it also holds a 5.x
/// `mnemonicphrase` HD seed, which Argos verifies but does not scan from. See
/// `tests/regtest/fixtures/README.md`.
const SPROUT_PLAINTEXT: &str = "sprout-plaintext.dat";

// The Unix artifact authority uses nonblocking flock locks. A concurrently
// spawned child briefly inherits the test process's descriptors between fork
// and exec, so keep process creation out of in-process journal mutations.
static ARGOS_SPAWN_GATE: Mutex<()> = Mutex::new(());

fn lock_argos_spawn() -> MutexGuard<'static, ()> {
    ARGOS_SPAWN_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn spawn_argos(command: &mut Command) -> Child {
    let _guard = lock_argos_spawn();
    command.spawn().expect("argos binary should run")
}

fn fixture(name: &str) -> PathBuf {
    relabeled_fixture(name, "mainnet")
}

/// The zcashd golden files were written on regtest, and operational imports
/// refuse that network in a production build. Tests that exercise ordinary
/// CLI behaviour use a disposable copy whose sole `networkinfo` value names
/// `network` instead. The checked-in writer fixtures stay byte-for-byte
/// unchanged, and files with no regtest marker (ZecWallet Lite) are used as
/// they are.
fn relabeled_fixture(name: &str, network: &str) -> PathBuf {
    assert_eq!(network.len(), 7, "the marker is replaced in place");
    let original = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../argos-wallet-import/tests/fixtures")
        .join(name);
    let Ok(mut bytes) = std::fs::read(&original) else {
        return original;
    };
    let matches: Vec<_> = bytes
        .windows(7)
        .enumerate()
        .filter_map(|(offset, window)| (window == b"regtest").then_some(offset))
        .collect();
    if matches.is_empty() {
        return original;
    }
    assert_eq!(matches.len(), 1, "golden wallet network marker changed");
    bytes[matches[0]..matches[0] + 7].copy_from_slice(network.as_bytes());
    let path = std::env::temp_dir().join(format!(
        "argos-cli-{network}-golden-{}-{name}",
        std::process::id()
    ));
    // Tests run in parallel: write to a unique temporary name, then rename,
    // so no reader can see a half-written copy.
    let partial = path.with_extension(format!("partial-{:?}", std::thread::current().id()));
    std::fs::write(&partial, bytes).unwrap();
    std::fs::rename(&partial, &path).unwrap();
    path
}

#[test]
fn wallet_network_mismatch_stops_before_lightwalletd() {
    let path = fixture("zwl-testnet-empty.dat");
    let out = argos(&[
        "--wallet-file",
        path.to_str().unwrap(),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("network-mismatch"),
        "scan",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mainnet") && stderr.contains("testnet"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("127.0.0.1") && !stderr.contains("lightwalletd probe"),
        "{stderr}"
    );
}

#[test]
fn reconcile_empty_registry_needs_no_wallet_or_network_probe() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = artifact_data_dir(&dir);
    let out = argos(&[
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--lightwalletd-url",
        "http://127.0.0.1:1",
        "--accept-tos",
        "reconcile",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("No stored transactions"), "{stdout}");
}

#[test]
fn reconcile_unknown_txid_refuses_before_network_probe() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = artifact_data_dir(&dir);
    let out = argos(&[
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--lightwalletd-url",
        "http://127.0.0.1:1",
        "--accept-tos",
        "reconcile",
        "--txid",
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("not found"), "{stderr}");
    assert!(!stderr.contains("127.0.0.1"), "{stderr}");
}

#[test]
fn reconcile_observes_every_stored_txid_or_only_the_selected_one() {
    use argos_core::broadcast::{BroadcastStore, PreparedTransaction, SubmissionDisposition};
    use argos_core::{service::NetworkOperationGuard, TxLifecycleState, ZeckNetwork};
    use zcash_primitives::transaction::TxId;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = artifact_data_dir(&dir);
    let guard = NetworkOperationGuard::acquire(&data_dir, ZeckNetwork::Mainnet).unwrap();
    let mut log = guard.open_broadcast_log().unwrap();
    let first = TxId::from_bytes([0xA1; 32]);
    let second = TxId::from_bytes([0xB2; 32]);
    for txid in [first, second] {
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![0x01],
            fee_zatoshis: 15_000,
            expiry_height: None,
        })
        .unwrap();
        log.transition(
            txid,
            TxLifecycleState::SubmissionUnknown,
            Some(&SubmissionDisposition::AmbiguousTransport),
            None,
        )
        .unwrap();
    }
    drop(log);
    drop(guard);
    let common = [
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--lightwalletd-url",
        "http://127.0.0.1:1",
        "--accept-tos",
        "reconcile",
    ];
    let all = argos(&common);
    let all_stdout = String::from_utf8_lossy(&all.stdout);
    let all_stderr = String::from_utf8_lossy(&all.stderr);
    assert!(
        all.status.success(),
        "stdout: {all_stdout}\nstderr: {all_stderr}"
    );
    assert!(all_stdout.contains(&first.to_string()), "{all_stdout}");
    assert!(all_stdout.contains(&second.to_string()), "{all_stdout}");
    assert!(all_stdout.contains("SubmissionUnknown"), "{all_stdout}");

    let selected = argos(&[
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--lightwalletd-url",
        "http://127.0.0.1:1",
        "--accept-tos",
        "reconcile",
        "--txid",
        &first.to_string(),
    ]);
    let selected_stdout = String::from_utf8_lossy(&selected.stdout);
    let selected_stderr = String::from_utf8_lossy(&selected.stderr);
    assert!(
        selected.status.success(),
        "stdout: {selected_stdout}\nstderr: {selected_stderr}"
    );
    assert!(
        selected_stdout.contains(&first.to_string()),
        "{selected_stdout}"
    );
    assert!(
        !selected_stdout.contains(&second.to_string()),
        "{selected_stdout}"
    );
}

#[test]
fn scan_routes_writer_wallet_seed_with_standalone_key_as_combined() {
    let mut bytes = std::fs::read(fixture("zwl-mainnet-empty.dat")).unwrap();
    // Writer fixture: one valid transparent key; keytype at 102..106.
    // Reclassify that key as an imported standalone key.
    assert_eq!(&bytes[102..106], &0u32.to_le_bytes());
    bytes[102..106].copy_from_slice(&1u32.to_le_bytes());
    let path = temporary_wallet("mixed-writer-key", &bytes);
    let inspect = argos(&["--wallet-file", path.to_str().unwrap(), "inspect-wallet"]);
    assert!(inspect.status.success());
    let shown = String::from_utf8_lossy(&inspect.stdout);
    assert!(
        shown.contains("standalone") && shown.contains("combined"),
        "{shown}"
    );
    let out = argos(&[
        "--wallet-file",
        path.to_str().unwrap(),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("mixed-writer-key"),
        "scan",
    ]);
    assert!(!out.status.success()); // deliberately unreachable lightwalletd
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("127.0.0.1") || stderr.contains("lightwalletd"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("cannot be scanned alongside") && !stderr.contains("nothing to scan"),
        "{stderr}"
    );
}

/// Run `argos` with stdin closed.
///
/// Closing stdin is load-bearing, not tidiness: it means any test that
/// accidentally reaches an interactive prompt fails with a terminal error
/// instead of hanging CI forever.
fn argos(args: &[&str]) -> std::process::Output {
    let isolated = (!args.contains(&"--data-dir")).then(|| tempfile::tempdir().unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_argos"));
    if let Some(dir) = isolated.as_ref() {
        command.arg("--data-dir").arg(artifact_data_dir(dir));
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_argos(&mut command)
        .wait_with_output()
        .expect("argos binary should finish")
}

fn sprout_lifecycle_output(
    _tag: &str,
    state: TxLifecycleState,
    mined_height: Option<u32>,
) -> std::process::Output {
    let spawn_guard = lock_argos_spawn();
    let wallet = fixture(SPROUT_PLAINTEXT);
    let bytes = std::fs::read(&wallet).expect("fixture");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("Sprout fixture imports");
    let spending_keys = keys
        .sprout
        .iter()
        .map(|key| *key.a_sk.expose_secret())
        .collect::<Vec<_>>();
    // The writer-produced golden wallet deliberately contains no Sprout
    // note records (the importer pins that invariant). Use an explicit
    // orphan row to exercise the source-bound journal status the CLI must
    // still render and reconcile.
    let outpoint = argos_core::argos_wallet_import::keys::JsOutPoint {
        txid: [0x11; 32],
        js_index: 0,
        output_index: 0,
    };
    let dir = tempfile::tempdir().unwrap();
    let data_dir = artifact_data_dir(&dir);
    let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
        &data_dir,
        &spending_keys,
        ZeckNetwork::Mainnet,
    );
    let mut snapshot = journal
        .load_or_migrate()
        .expect("create v4 journal authority");
    let transaction = lifecycle_transaction();
    journal
        .scoped_store(
            argos_core::sprout_sweep_journal::JournalNoteContext {
                outpoint,
                value_zatoshis: 1_000_000,
            },
            &mut snapshot,
        )
        .persist_prepared(&transaction)
        .expect("persist v4 lifecycle transaction");
    if state != TxLifecycleState::NotSubmitted {
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::SubmissionUnknown,
                None,
                None,
            )
            .expect("append unknown lifecycle transition");
    }
    if matches!(state, TxLifecycleState::Pending | TxLifecycleState::Mined) {
        let pending = TxObservation {
            state: TxObservationState::PresentUnmined,
            mined_height: None,
            expiry_height: transaction.expiry_height,
            primary_tip: Some(200),
            secondary_tip: Some(200),
            evidence: ["alpha", "beta"]
                .into_iter()
                .map(|operator| EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(200),
                    reported_height: None,
                    block_hash: None,
                    tx_in_block: false,
                })
                .collect(),
        };
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                TxLifecycleState::Pending,
                Some(&SubmissionDisposition::Accepted),
                Some(&pending),
            )
            .expect("append pending lifecycle transition");
    }
    if state == TxLifecycleState::Mined {
        let block_hash = vec![0x33; 32];
        let observation = TxObservation {
            state: TxObservationState::Mined,
            mined_height,
            expiry_height: transaction.expiry_height,
            primary_tip: Some(300),
            secondary_tip: Some(300),
            evidence: ["alpha", "beta"]
                .into_iter()
                .map(|operator| EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(300),
                    reported_height: mined_height,
                    block_hash: mined_height.map(|_| block_hash.clone()),
                    tx_in_block: mined_height.is_some(),
                })
                .collect(),
        };
        journal
            .append_transition(
                &mut snapshot,
                transaction.txid,
                state,
                None,
                Some(&observation),
            )
            .expect("append lifecycle transition");
    }
    drop(spawn_guard);
    argos(&[
        "--wallet-file",
        wallet.to_str().expect("UTF-8 wallet path"),
        "--data-dir",
        data_dir.to_str().expect("UTF-8 data dir"),
        "inspect-wallet",
    ])
}

fn lifecycle_transaction() -> PreparedTransaction {
    PreparedTransaction {
        txid: TxId::from_bytes([
            0x82, 0xc4, 0x41, 0x23, 0xee, 0x91, 0xd0, 0xdf, 0xc7, 0x26, 0x8c, 0x1a, 0xad, 0xa2,
            0x91, 0x91, 0x5c, 0xf5, 0xfa, 0xec, 0xab, 0x7d, 0xa6, 0x07, 0xc3, 0xbb, 0x4e, 0xe2,
            0xef, 0x75, 0x8c, 0xf8,
        ]),
        // Empty NU5 v5 transaction with expiry height 300. The journal
        // validates these exact bytes against the txid before persisting.
        raw_tx: vec![
            5, 0, 0, 128, 10, 39, 167, 38, 180, 208, 214, 194, 0, 0, 0, 0, 44, 1, 0, 0, 0, 0, 0, 0,
            0,
        ],
        fee_zatoshis: 10_000,
        expiry_height: Some(300),
    }
}

#[test]
fn pending_and_unknown_cli_results_keep_the_source_warning() {
    for (tag, state) in [
        ("lifecycle-pending-warning", TxLifecycleState::Pending),
        (
            "lifecycle-unknown-warning",
            TxLifecycleState::SubmissionUnknown,
        ),
    ] {
        let output = sprout_lifecycle_output(tag, state, None);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(
                "Keep the original wallet or Sprout key and the scan checkpoint. Broadcast is not confirmation."
            ),
            "{state}: {stdout}"
        );
    }
}

#[test]
fn cli_never_calls_pending_value_swept() {
    let output = sprout_lifecycle_output(
        "lifecycle-pending-language",
        TxLifecycleState::Pending,
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("broadcast/pending "), "{stdout}");
    let lifecycle = stdout
        .lines()
        .filter(|line| {
            line.contains("broadcast/pending")
                || line.contains("submission status unknown")
                || line.contains("mined at height")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !lifecycle.to_ascii_lowercase().contains("swept"),
        "pending lifecycle output claimed finality: {lifecycle}"
    );
    assert!(
        !stdout.contains("These were recovered from this file alone — no scan needed"),
        "active-only journal was described as a newly recovered note: {stdout}"
    );
    assert!(
        !stdout.contains("To move them:"),
        "active-only journal offered a conflicting new sweep: {stdout}"
    );
    assert!(
        !stdout.contains("Nothing is left to sweep"),
        "pending history was hidden by a terminal verdict: {stdout}"
    );
}

#[test]
fn cli_prints_mined_height_only_for_mined_evidence() {
    let pending =
        sprout_lifecycle_output("lifecycle-pending-height", TxLifecycleState::Pending, None);
    let pending_stdout = String::from_utf8_lossy(&pending.stdout);
    assert!(
        !pending_stdout.contains("mined at height"),
        "{pending_stdout}"
    );

    let mined =
        sprout_lifecycle_output("lifecycle-mined-height", TxLifecycleState::Mined, Some(123));
    let mined_stdout = String::from_utf8_lossy(&mined.stdout);
    assert!(
        mined_stdout.contains("mined at height 123 0.01000000 ZEC"),
        "{mined_stdout}"
    );
    assert!(
        mined_stdout.contains(
            "Keep the original wallet or Sprout key and the scan checkpoint. Broadcast is not confirmation."
        ),
        "stored mined evidence is stale until this invocation reobserves it: {mined_stdout}"
    );
}

#[test]
fn v1_journal_is_reported_as_uncertain_not_already_swept() {
    let spawn_guard = lock_argos_spawn();
    let wallet = fixture(SPROUT_PLAINTEXT);
    let bytes = std::fs::read(&wallet).expect("fixture");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("Sprout fixture imports");
    let spending_keys = keys
        .sprout
        .iter()
        .map(|key| *key.a_sk.expose_secret())
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = artifact_data_dir(&dir);
    let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
        &data_dir,
        &spending_keys,
        ZeckNetwork::Mainnet,
    );
    let mut snapshot = journal
        .load_or_migrate()
        .expect("create v4 journal authority");
    let transaction = lifecycle_transaction();
    let outpoint = argos_core::argos_wallet_import::keys::JsOutPoint {
        txid: [0x11; 32],
        js_index: 0,
        output_index: 0,
    };
    journal
        .scoped_store(
            argos_core::sprout_sweep_journal::JournalNoteContext {
                outpoint,
                value_zatoshis: 1_000_000,
            },
            &mut snapshot,
        )
        .persist_prepared(&transaction)
        .expect("create authenticated journal object");
    std::fs::write(
        journal.path(),
        format!(
            "{}:{}:{} {}\n",
            outpoint
                .txid
                .iter()
                .rev()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            outpoint.js_index,
            outpoint.output_index,
            transaction.txid
        ),
    )
    .expect("replace authenticated journal content with legacy v1 fixture");
    drop(spawn_guard);
    let output = argos(&[
        "--wallet-file",
        wallet.to_str().expect("UTF-8 wallet path"),
        "--data-dir",
        data_dir.to_str().expect("UTF-8 data dir"),
        "inspect-wallet",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("legacy journal content has no mandatory v4 lineage boundary"),
        "{stdout}"
    );
    assert!(
        !stdout.to_ascii_lowercase().contains("already swept"),
        "{stdout}"
    );
    assert!(
        stdout.contains("preserve it unchanged for explicit reconciliation"),
        "legacy journal refusal omitted preservation guidance: {stdout}"
    );
    assert!(
        !stdout.contains("Nothing is left to sweep"),
        "legacy history was hidden by a terminal verdict: {stdout}"
    );
}

#[test]
fn unreadable_journal_keeps_source_warning_and_suppresses_all_clear() {
    let spawn_guard = lock_argos_spawn();
    let wallet = fixture(SPROUT_PLAINTEXT);
    let bytes = std::fs::read(&wallet).expect("fixture");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("Sprout fixture imports");
    let spending_keys = keys
        .sprout
        .iter()
        .map(|key| *key.a_sk.expose_secret())
        .collect::<Vec<_>>();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = artifact_data_dir(&dir);
    let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
        &data_dir,
        &spending_keys,
        ZeckNetwork::Mainnet,
    );
    let mut snapshot = journal
        .load_or_migrate()
        .expect("create v4 journal authority");
    let transaction = lifecycle_transaction();
    journal
        .scoped_store(
            argos_core::sprout_sweep_journal::JournalNoteContext {
                outpoint: argos_core::argos_wallet_import::keys::JsOutPoint {
                    txid: [0x11; 32],
                    js_index: 0,
                    output_index: 0,
                },
                value_zatoshis: 1_000_000,
            },
            &mut snapshot,
        )
        .persist_prepared(&transaction)
        .expect("create authenticated journal object");
    std::fs::write(journal.path(), b"{broken journal\n").unwrap();

    drop(spawn_guard);
    let output = argos(&[
        "--wallet-file",
        wallet.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
        "inspect-wallet",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Sweep lifecycle journal could not be read")
            && stdout.contains(
                "Keep the original wallet or Sprout key and the scan checkpoint. Broadcast is not confirmation."
            ),
        "{stdout}"
    );
    assert!(!stdout.contains("Nothing is left to sweep"), "{stdout}");
}

fn temporary_wallet(tag: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("argos-cli-{tag}-{}.dat", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}

// A no-funds ZWL wallet using the writer's versioned layout. The seed is
// public test entropy; these records have no chain history.
fn zwl_with_tkeys(entries: &[(u32, bool, Option<[u8; 32]>, &str)]) -> Vec<u8> {
    let mut bytes = 25u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&22u64.to_le_bytes());
    bytes.push(0); // wallet is not encrypted
    bytes.extend_from_slice(&[0; 48]); // encrypted seed slot
    bytes.push(0); // nonce
    bytes.extend_from_slice(&[0; 32]); // plaintext seed
    bytes.push(0); // Orchard keys
    bytes.push(0); // Sapling keys
    bytes.push(entries.len() as u8);
    for (kind, locked, secret, address) in entries {
        bytes.push(1); // tkey record version
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.push(u8::from(*locked));
        match secret {
            Some(secret) => {
                bytes.push(1);
                bytes.extend_from_slice(secret);
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&(address.len() as u64).to_le_bytes());
        bytes.extend_from_slice(address.as_bytes());
        bytes.push(0); // HD index
        if *locked {
            bytes.push(1);
            bytes.push(48);
            bytes.extend_from_slice(&[0xcc; 48]);
            bytes.push(1);
            bytes.push(24);
            bytes.extend_from_slice(&[0xdd; 24]);
        } else {
            bytes.extend_from_slice(&[0, 0]); // no ciphertext or nonce
        }
    }
    bytes.push(0); // empty block history
    bytes.extend_from_slice(&21u64.to_le_bytes()); // WalletTxns version
    bytes.push(0); // no transactions
    bytes.extend_from_slice(&4u64.to_le_bytes());
    bytes.extend_from_slice(b"main");
    bytes.extend_from_slice(
        &include_bytes!("../../argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat")[212..],
    );
    bytes
}

#[test]
fn inspect_wallet_reports_structural_damage_and_preserve_file() {
    let mut bytes = std::fs::read(fixture("zwl-mainnet-empty.dat")).unwrap();
    bytes.truncate(20);
    let path = temporary_wallet("truncated-zwl", &bytes);
    let out = argos(&["--wallet-file", path.to_str().unwrap(), "inspect-wallet"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(shown.contains("Recovery coverage: Incomplete"), "{shown}");
    assert!(shown.contains("wallet container is damaged"), "{shown}");
    assert!(shown.contains("Keep the original wallet file"), "{shown}");

    // A zcashd BDB whose metadata names pages absent from the file is
    // unrecoverable as a whole, but still needs the same preserve warning.
    let bdb = fixture("modern-plaintext-truncated.dat");
    let out = argos(&["--wallet-file", bdb.to_str().unwrap(), "inspect-wallet"]);
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(
        error.contains("wallet file structure is unreadable"),
        "{error}"
    );
    assert!(error.contains("Keep the original wallet file"), "{error}");
}

#[test]
fn inspect_wallet_distinguishes_locked_hd_and_standalone_keys() {
    let hd_only = zwl_with_tkeys(&[(0, true, None, "t1LockedHd")]);
    let hd_path = temporary_wallet("locked-hd-only", &hd_only);
    let hd_out = argos(&["--wallet-file", hd_path.to_str().unwrap(), "inspect-wallet"]);
    assert!(
        hd_out.status.success(),
        "{}",
        String::from_utf8_lossy(&hd_out.stderr)
    );
    // The seed is recovered, so a locked HD key is one of its own accounts:
    // not reported as locked, and coverage stays complete (round-2 item D
    // on #275).
    let hd_shown = String::from_utf8_lossy(&hd_out.stdout);
    assert!(
        !hd_shown.contains("recover the wallet seed to recreate it"),
        "{hd_shown}"
    );
    assert!(
        hd_shown.contains("Every record that can hold a key was read."),
        "{hd_shown}"
    );

    let bytes = zwl_with_tkeys(&[
        (0, true, None, "t1LockedHd"),
        (1, true, None, "t1LockedStandalone"),
    ]);
    let path = temporary_wallet("locked-provenance", &bytes);
    let out = argos(&["--wallet-file", path.to_str().unwrap(), "inspect-wallet"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(
        !shown.contains("recover the wallet seed to recreate it"),
        "{shown}"
    );
    assert!(
        shown.contains("cannot be recreated from the seed"),
        "{shown}"
    );
    assert!(shown.contains("Keep the original wallet file"), "{shown}");
    assert!(
        shown.contains("It may contain keys or records Argos has not recovered"),
        "the fund-hiding banner must remain visible: {shown}"
    );
    assert!(
        !shown.contains("Anything listed above exists only there"),
        "recovered HD keys can be recreated from the seed: {shown}"
    );
}

#[test]
fn inspect_wallet_redacts_identifier_mismatch() {
    let bytes = zwl_with_tkeys(&[(0, false, Some([1; 32]), "t1SentinelWrongAddress")]);
    let path = temporary_wallet("identifier-mismatch", &bytes);
    let out = argos(&["--wallet-file", path.to_str().unwrap(), "inspect-wallet"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(
        shown.contains("stored public identifier does not match"),
        "{shown}"
    );
    assert!(shown.contains("mismatched record was not used"), "{shown}");
    assert!(
        !shown.contains("t1SentinelWrongAddress") && !shown.contains("01010101"),
        "{shown}"
    );
}

#[test]
fn damaged_encryption_metadata_does_not_prompt_for_passphrase() {
    use argos_core::argos_wallet_import::{bdb, zcashd::records::parse_record_key};
    let mut bytes = std::fs::read(fixture("modern-encrypted.dat")).unwrap();
    let walked = bdb::walk(&bytes).unwrap();
    let value = walked
        .records
        .iter()
        .find(|record| {
            parse_record_key(&record.key).is_some_and(|parsed| parsed.record_type == "mkey")
        })
        .unwrap()
        .value();
    let offset = bytes
        .windows(value.len())
        .position(|window| window == value)
        .unwrap();
    bytes[offset] = 0xfc;
    let path = temporary_wallet("damaged-mkey", &bytes);
    let out = argos(&["--wallet-file", path.to_str().unwrap(), "inspect-wallet"]);
    assert!(!out.status.success());
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        shown.contains("wallet encryption metadata is damaged"),
        "{shown}"
    );
    assert!(shown.contains("Keep the original wallet file"), "{shown}");
    assert!(!shown.contains("Enter the wallet passphrase"), "{shown}");
}

#[test]
fn wallet_network_mismatch_names_both_networks() {
    let path = fixture("zwl-testnet-empty.dat");
    let out = argos(&["--wallet-file", path.to_str().unwrap(), "inspect-wallet"]);
    assert!(!out.status.success());
    let shown = String::from_utf8_lossy(&out.stderr);
    assert!(
        shown.contains("selected mainnet") && shown.contains("embedded testnet"),
        "{shown}"
    );
}

// Missing dispatch, wrong-network wording, or warning after validation would
// leave a recovery operator unaware of the deadline before starting work.
fn nu7_warning(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn nu7_warning_reaches_wallet_inspection_only_when_sprout_keys_exist() {
    let wallet = fixture(SPROUT_PLAINTEXT);
    let out = argos(&["--wallet-file", wallet.to_str().unwrap(), "inspect-wallet"]);
    assert!(out.status.success());
    let warning = nu7_warning(&out.stderr);
    assert!(warning.contains("NU7"), "{warning}");
    assert!(warning.contains("all version 4"), "{warning}");
    assert!(warning.contains("unspendable"), "{warning}");
    assert!(warning.contains("mined before activation"), "{warning}");
    assert!(
        warning.contains("broadcast alone is not enough"),
        "{warning}"
    );
    assert!(warning.contains("Start recovery promptly"), "{warning}");
    assert!(
        warning.contains("targeted for about November 5, 2026"),
        "{warning}"
    );
    assert!(
        warning.contains("final height is not yet assigned (proposed in zcash/zips#1405)"),
        "{warning}"
    );
    assert!(
        warning.contains("https://zips.z.cash/zip-0259"),
        "{warning}"
    );

    let keys = key_file("nu7-sapling-only.txt", TEST_SAPLING_KEY_MAINNET);
    let out = argos(&[
        "--sapling-key-file",
        keys.to_str().unwrap(),
        "inspect-wallet",
    ]);
    assert!(out.status.success());
    assert!(!nu7_warning(&out.stderr).contains("NU7"));
}

#[test]
fn nu7_warning_precedes_scan_preparation_for_wallet_and_standalone_keys() {
    let wallet = fixture(SPROUT_PLAINTEXT);
    let spending_key = argos_core::sprout_key::encode_sprout_spending_key(
        &[7; 32],
        argos_core::ZeckNetwork::Mainnet,
    );
    let keys = key_file("nu7-sprout.txt", &spending_key);
    for (source, path) in [("--wallet-file", wallet), ("--sprout-key-file", keys)] {
        let out = argos(&[
            source,
            path.to_str().unwrap(),
            "--accept-tos",
            "--data-dir",
            &scratch_dir("nu7-scan"),
            "scan-sprout",
            "--destination",
            "invalid-destination",
        ]);
        assert!(!out.status.success());
        let stderr = nu7_warning(&out.stderr);
        let warning = stderr.find("NU7").expect("warn before scan preparation");
        let failure = stderr
            .find("Error:")
            .expect("invalid destination must fail");
        assert!(warning < failure, "{stderr}");
    }
}

/// PR #263 review item 4: `scan` and `sweep` warn about NU7 only when the
/// wallet file holds Sprout keys. A zcashd wallet with transparent and Sapling
/// keys but no Sprout must stay silent, or the warning becomes noise.
///
/// Each run is checked to have got past the point where the warning is
/// printed (the import line for `scan`, the destination refusal for
/// `sweep`), and the Sprout fixture is run the same way as a control, so the
/// silence cannot come from failing too early.
#[test]
fn nu7_warning_stays_silent_for_scan_and_sweep_of_a_wallet_without_sprout() {
    const NO_SPROUT: &str = "modern-plaintext.dat";
    let run = |wallet: &str, sweep: bool| {
        let path = fixture(wallet);
        let dir = scratch_dir(&format!("nu7-silent-{wallet}-{sweep}"));
        let mut args = vec![
            "--wallet-file",
            path.to_str().unwrap(),
            "--accept-tos",
            "--lightwalletd-url",
            "https://127.0.0.1:1",
            "--data-dir",
            &dir,
        ];
        if sweep {
            // Refused before any network access, after the warning point.
            args.extend(["sweep", "--destination", "invalid-destination"]);
        } else {
            args.push("scan");
        }
        let out = argos(&args);
        assert!(!out.status.success());
        nu7_warning(&out.stderr)
    };

    for sweep in [false, true] {
        let silent = run(NO_SPROUT, sweep);
        assert!(silent.contains("Imported"), "{silent}");
        assert!(silent.contains("Error:"), "{silent}");
        assert!(!silent.contains("NU7"), "sweep={sweep}: {silent}");
        assert!(!silent.contains("version 4"), "sweep={sweep}: {silent}");

        let control = run(SPROUT_PLAINTEXT, sweep);
        assert!(control.contains("NU7"), "sweep={sweep}: {control}");
    }
}

#[test]
fn nu7_testnet_warning_explains_the_activation_boundary_without_urging_a_spend() {
    let wallet = relabeled_fixture(SPROUT_PLAINTEXT, "testnet");
    let out = argos(&[
        "--wallet-file",
        wallet.to_str().unwrap(),
        "--network",
        "testnet",
        "inspect-wallet",
    ]);
    assert!(out.status.success());
    let warning = nu7_warning(&out.stderr);
    assert!(warning.contains("4,465,026"), "{warning}");
    assert!(warning.contains("At or after"), "{warning}");
    assert!(warning.contains("cannot spend"), "{warning}");
    assert!(!warning.contains("Start recovery promptly"), "{warning}");
}

#[test]
fn nu7_warning_precedes_wallet_sweep_recovery_including_dry_runs() {
    let wallet = fixture(SPROUT_PLAINTEXT);
    for gate in ["--dry-run", "--confirm-sweep"] {
        let out = argos(&[
            "--wallet-file",
            wallet.to_str().unwrap(),
            "--accept-tos",
            "--data-dir",
            &scratch_dir("nu7-sweep"),
            "sweep-sprout",
            "--destination",
            "invalid-destination",
            gate,
        ]);
        assert!(!out.status.success());
        let stderr = nu7_warning(&out.stderr);
        let warning = stderr
            .find("NU7")
            .expect("warn even when preview cannot recover notes");
        let recovery = stderr
            .find("No spendable Sprout notes")
            .expect("fixture has no notes");
        assert!(warning < recovery, "{stderr}");
    }
}

#[test]
fn inspect_wallet_reports_a_zcashd_wallets_contents_without_a_network() {
    let path = fixture(SPROUT_PLAINTEXT);
    assert!(
        path.exists(),
        "golden fixture is missing: {}",
        path.display()
    );

    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        out.status.success(),
        "inspect-wallet failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    // The counts come from the fixture's documented contents: 103
    // transparent keys, 1 sapling, 1 sprout. Asserting the sprout line
    // specifically because a Sprout key is the whole reason this parser
    // exists and nothing else in the ecosystem recovers one.
    assert!(
        stdout.contains("Sprout keys       1"),
        "expected the recovered Sprout key to be reported, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Transparent keys  103"),
        "expected 103 transparent keys, got:\n{stdout}"
    );
    // A user must not read "recovered a Sprout key" as "can move the money".
    // The parser reports a Sprout key count, and recovering those notes still
    // takes a `scan-sprout` this report has not run, so the wording has to
    // keep "found a key" and "can move the funds" apart.
    assert!(
        stdout.contains("not yet recoverable"),
        "the report must not imply Sprout funds are spendable, got:\n{stdout}"
    );
}

/// A zcashd 5.x wallet's seed is verified, and because the wallet never
/// created a unified account, the report may say the stored keys are the
/// whole story — but must not claim the keys were never HD-derived (#225),
/// nor that the seed is what the scan uses (#229).
#[test]
fn inspect_wallet_reports_a_verified_seed() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for false_claim in ["not HD-derived", "has no HD seed"] {
        assert!(!stdout.contains(false_claim), "got:\n{stdout}");
    }
    assert!(
        stdout.contains("Seed phrase       verified — every key it derived is read from this file"),
        "got:\n{stdout}"
    );
    assert!(
        stdout.contains("Every record that can hold a key was read."),
        "got:\n{stdout}"
    );
    assert!(!stdout.contains("Recovery coverage"), "got:\n{stdout}");
}

/// A seedless wallet is *scanned*, not refused.
///
/// This has now been re-pointed twice, and the reason is worth recording.
/// It first asserted an outright refusal, which was correct when neither
/// recovery path existed: scanning through the HD path would have walked
/// zero accounts and reported "no funds" for a wallet that may hold real
/// money. It then asserted the transparent-only path. It now asserts the
/// imported-account path, because a wallet with Sapling keys can be given
/// a wallet-database account that carries its transparent keys too.
///
/// The requirement has never changed: a seedless wallet must never be
/// reported as empty without saying what was not looked at. Only the
/// mechanism keeps improving.
///
/// Uses an unroutable endpoint so this stays offline; the coverage banner
/// is printed before any network call.
#[test]
fn a_seedless_wallet_is_scanned_not_refused() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("seedless"),
        "scan",
    ]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("no recoverable seed phrase"),
        "a wallet with importable keys must no longer be refused outright, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("no HD accounts to scan"),
        "the HD-only refusal must not fire for an importable wallet, got:\n{stderr}"
    );
    // It got as far as the network, which is the only thing that should
    // stop it here.
    assert!(
        stderr.contains("lightwalletd") || stderr.contains("probe"),
        "expected the scan to reach the network and fail there, got:\n{stderr}"
    );
}

#[test]
fn inspect_wallet_without_a_wallet_file_does_not_prompt_for_a_seed() {
    // Regression guard: `inspect-wallet` shares the argument-parsing path
    // with commands that read a seed phrase from the terminal. If it ever
    // falls through to that prompt, stdin is closed here and the process
    // dies on a terminal error — which is a pass by accident. Assert the
    // specific message instead.
    let out = argos(&["inspect-wallet"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("inspect-wallet needs --wallet-file"),
        "expected the missing-argument error, got:\n{stderr}"
    );
}

#[test]
fn a_file_that_is_not_a_wallet_is_rejected_by_name() {
    // This source file: definitively not a wallet.
    let not_a_wallet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wallet_file_cli.rs");
    let out = argos(&[
        "--wallet-file",
        not_a_wallet.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a recognized Zcash wallet file"),
        "expected the format-sniff rejection, got:\n{stderr}"
    );
}

/// Sprout is the one pool nothing covers, and the user must be told.
///
/// The stronger half of this test is the negative: Sapling must *not* be
/// listed as uncovered. A zcashd wallet's Sapling keys are registered as a
/// wallet-database account and scanned alongside its transparent keys, so
/// listing Sapling here would mean the routing regressed to the
/// transparent-only path and Sapling funds had silently stopped being
/// scanned.
#[test]
fn a_wallet_with_sprout_keys_says_sprout_is_not_covered() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("warn"),
        "scan",
    ]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NU7"),
        "ordinary recovery must warn: {stderr}"
    );
    assert!(
        stderr.contains("SPROUT FUNDS ARE NOT COVERED"),
        "the Sprout caveat must be unmissable, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Sprout key(s) in this wallet are NOT scanned"),
        "it must name the pool and its key count, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Sapling key(s) in this wallet are NOT scanned"),
        "Sapling is scanned via the imported account path; listing it as uncovered means \
         the routing regressed to transparent-only, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Keep the original wallet file"),
        "the user must be told not to discard the only copy of those keys, got:\n{stderr}"
    );
}

/// Sweeping is irreversible, so it must refuse to broadcast without an
/// explicit confirmation — the same rule the seed sweep follows.
#[test]
fn a_transparent_sweep_refuses_to_broadcast_without_confirmation() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("confirm"),
        "sweep",
        "--destination",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        "--max-fee",
        "0.001",
    ]);

    assert!(
        !out.status.success(),
        "an unconfirmed sweep must not succeed"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // It must fail for a safety reason or before reaching the network —
    // never by silently broadcasting.
    assert!(
        !combined.contains("Sweep broadcast"),
        "nothing may be broadcast without --confirm-sweep, got:\n{combined}"
    );
}

fn scratch_dir(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("argos-cli-{tag}-{}", std::process::id()))
        .to_str()
        .expect("temp path is UTF-8")
        .to_owned()
}

fn artifact_data_dir(outer: &tempfile::TempDir) -> PathBuf {
    outer.path().join("recovery-data")
}

/// Write a key file under the test's temp dir and hand back its path.
fn key_file(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("argos-test-{name}"));
    std::fs::write(&path, contents).expect("test key file should write");
    path
}

/// The same Sapling extended spending key encoded for each network,
/// derived from the fixed seed `[7u8; 32]`. It controls no real funds and
/// has never been on any chain.
///
/// Pinned rather than derived at test time so this test needs no
/// dev-dependency on `sapling-crypto`. Regenerate, if upstream encoding ever
/// changes, by encoding
/// `sapling_crypto::zip32::ExtendedSpendingKey::master(&[7u8; 32])` with
/// `zcash_keys::encoding::encode_extended_spending_key` under each network's
/// `HRP_SAPLING_EXTENDED_SPENDING_KEY`.
const TEST_SAPLING_KEY_MAINNET: &str =
    "secret-extended-key-main1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgqvp59t";
const TEST_SAPLING_KEY_TESTNET: &str =
    "secret-extended-key-test1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgts9kat";

#[test]
fn inspect_wallet_reports_a_key_supplied_as_text() {
    let path = key_file(
        "sapling-key-good.txt",
        &format!("# from the paper backup\n{TEST_SAPLING_KEY_MAINNET}\n"),
    );

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        out.status.success(),
        "inspect-wallet failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zs1"),
        "the address the key controls should be shown, got: {stdout}"
    );
    assert!(
        !stdout.contains("secret-extended-key"),
        "the key itself must never be printed back, got: {stdout}"
    );
}

#[test]
fn a_key_for_the_wrong_network_is_refused_by_name() {
    let path = key_file(
        "sapling-key-wrong-network.txt",
        &format!("{TEST_SAPLING_KEY_TESTNET}\n"),
    );

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        !out.status.success(),
        "a testnet key must not pass on mainnet"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("testnet"),
        "the failure should name the key's real network, got: {stderr}"
    );
}

#[test]
fn a_malformed_key_names_the_line_it_is_on() {
    let path = key_file(
        "sapling-key-bad-line.txt",
        &format!("{TEST_SAPLING_KEY_MAINNET}\nnot-a-key\n"),
    );

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success(), "a malformed line must fail the run");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("line 2"),
        "the failure should name the offending line, got: {stderr}"
    );
}

/// A seed and a standalone key are different provenance models; accepting
/// both would leave it ambiguous which one a scan actually used.
#[test]
fn a_seed_file_and_a_key_file_cannot_be_combined() {
    let keys = key_file("sapling-key-conflict.txt", TEST_SAPLING_KEY_MAINNET);
    let seed = key_file("seed-conflict.txt", "abandon abandon abandon");

    let out = argos(&[
        "--sapling-key-file",
        keys.to_str().expect("path is UTF-8"),
        "--seed-file",
        seed.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(!out.status.success(), "the two flags must conflict");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "clap should report the conflict, got: {stderr}"
    );
}

/// The whole point of the feature: a key with no wallet file behind it must
/// not be turned away at argument parsing.
#[test]
fn a_key_file_alone_does_not_demand_a_wallet_file() {
    let path = key_file("sapling-key-alone.txt", TEST_SAPLING_KEY_MAINNET);

    let out = argos(&[
        "--sapling-key-file",
        path.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("needs --wallet-file"),
        "a key file is its own key source, got: {stderr}"
    );
}

/// `--wallet-file` + `--sapling-key-file` merges for every wallet. A
/// seedless zcashd wallet takes the imported-account route, which reads
/// `keys.sapling` directly; a wallet with a mnemonic takes the Combined
/// route, which registers the supplied key beside the seed's accounts
/// (see `a_seed_wallet_and_a_key_file_merge_into_one_recovery`).
#[test]
fn a_seedless_wallet_and_a_key_file_still_merge() {
    let wallet = fixture(SPROUT_PLAINTEXT);
    let keys = key_file("sapling-key-with-wallet.txt", TEST_SAPLING_KEY_MAINNET);

    let out = argos(&[
        "--wallet-file",
        wallet.to_str().expect("fixture path is UTF-8"),
        "--sapling-key-file",
        keys.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    assert!(
        out.status.success(),
        "a seedless wallet plus a supplied key must not be refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("seed phrase"),
        "the HD refusal must not fire for a seedless wallet, got:\n{stderr}"
    );

    // The supplied key landed alongside the wallet's own: the fixture holds
    // one Sapling address, and the pasted key controls a second.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zs1"),
        "the merged key set should report Sapling addresses, got: {stdout}"
    );
    assert!(
        !stdout.contains("secret-extended-key"),
        "no key material may be printed back, got: {stdout}"
    );
}

/// Review finding 6 on #275: a wallet file with a seed phrase (here the
/// writer-produced ZecWallet Lite fixture) plus a key file used to be
/// refused with "run two scans". The Combined route scans both, so the
/// supplied key is merged and reported beside the wallet's own.
#[test]
fn a_seed_wallet_and_a_key_file_merge_into_one_recovery() {
    let wallet = fixture("zwl-mainnet-empty.dat");
    let keys = key_file("sapling-key-with-seed-wallet.txt", TEST_SAPLING_KEY_MAINNET);
    let out = argos(&[
        "--wallet-file",
        wallet.to_str().expect("fixture path is UTF-8"),
        "--sapling-key-file",
        keys.to_str().expect("path is UTF-8"),
        "inspect-wallet",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a seed wallet plus a supplied key must not be refused: {stderr}"
    );
    assert!(!stderr.contains("two scans"), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zs1"),
        "the supplied key is reported: {stdout}"
    );
    assert!(!stdout.contains("secret-extended-key"), "{stdout}");
}

/// A wallet with no seed phrase sweeps without a memo, and a dropped memo
/// can lose an exchange deposit. `--memo` is therefore refused, and refused
/// before the scan: finding out after hours of scanning is not a refusal
/// anyone would thank us for.
#[test]
fn a_seedless_sweep_refuses_a_memo_before_scanning() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("memo"),
        "sweep",
        "--destination",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        "--memo",
        "exchange deposit 12345",
        "--dry-run",
    ]);

    assert!(
        !out.status.success(),
        "a memo that cannot be sent must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("memo") && stderr.contains("seed phrase"),
        "the refusal must say why, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("scan can take hours"),
        "the memo must be refused before the scan starts, got:\n{stderr}"
    );
}

/// The donation is the same shape of trap with no funds at stake, so it is
/// reported rather than refused — the GUI sends one by default.
#[test]
fn a_seedless_sweep_says_it_sends_no_donation() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("donation"),
        "sweep",
        "--destination",
        "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf",
        "--donation-rate",
        "0.10",
        "--dry-run",
    ]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sends no donation"),
        "a requested donation that will not be sent must be named, got:\n{stderr}"
    );
}

/// A real mainnet Sapling address to sweep to, derived from the BIP-39 test
/// vector rather than copied from anywhere: `show-keys` needs no network.
fn test_vector_sapling_address(dir: &std::path::Path) -> String {
    let seed = dir.join("seed.txt");
    std::fs::write(
        &seed,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art",
    )
    .expect("write seed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let out = argos(&[
        "--seed-file",
        seed.to_str().expect("utf-8"),
        "--num-accounts",
        "1",
        "show-keys",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Sapling address")
                .map(|a| a.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("show-keys printed no Sapling address:\n{stdout}"))
}

/// Reported: `scan-sprout --destination … --lightwalletd-url nonono` started
/// an hours-long scan whose only use of that server — broadcasting the sweep
/// — could never work. The address must be refused before the scan, and the
/// progress line must not claim a checkpoint exists before one is written.
#[test]
fn scan_sprout_refuses_an_unusable_server_before_scanning() {
    let outer = tempfile::tempdir().unwrap();
    let dir = artifact_data_dir(&outer);
    let destination = test_vector_sapling_address(outer.path());
    let wallet = fixture(SPROUT_PLAINTEXT);

    // Killed at a deadline rather than awaited: a build that does not refuse
    // goes on to scan mainnet for hours, and a failing test must neither
    // hang nor load public peers for longer than it takes to fail.
    let mut command = Command::new(env!("CARGO_BIN_EXE_argos"));
    command
        .args([
            "--wallet-file",
            wallet.to_str().expect("utf-8"),
            "--data-dir",
            dir.to_str().expect("utf-8"),
            "--accept-tos",
            "--lightwalletd-url",
            "nonono",
            "scan-sprout",
            "--destination",
            &destination,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = spawn_argos(&mut command);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().expect("piped"), &mut stderr)
        .expect("stderr");
    let status = status.unwrap_or_else(|| {
        panic!("scan-sprout started scanning instead of refusing the server:\n{stderr}")
    });
    assert!(!status.success(), "must refuse, got:\n{stderr}");
    assert!(
        stderr.contains("--lightwalletd-url"),
        "must name the flag:\n{stderr}"
    );
    // Matches the banner as it now reads; the old "Progress is saved to"
    // wording no longer exists anywhere, so asserting its absence guarded
    // nothing.
    assert!(
        !stderr.contains("Progress will be saved to"),
        "refused before the scan, so the scan's progress banner must not appear:\n{stderr}"
    );
}

/// A key-source flag that the chosen command never reads must be refused,
/// not silently dropped. Now that every top-level flag is `global`, it is
/// natural to type `argos show-keys --sprout-key-file …` and assume the key
/// was used.
#[test]
fn a_key_source_the_command_would_ignore_is_refused() {
    let key = key_file("ignored-sprout-key", "SKplaceholder\n");
    let key = key.to_str().unwrap();
    for args in [
        vec!["show-keys", "--sprout-key-file", key],
        vec!["scan", "--sprout-key-file", key, "--accept-tos"],
        vec![
            "sweep-sprout",
            "--sprout-key-file",
            key,
            "--destination",
            "zs1x",
            "--accept-tos",
        ],
        vec!["scan-sprout", "--seed-file", key, "--accept-tos"],
        vec!["scan-sprout", "--sapling-key-file", key, "--accept-tos"],
    ] {
        let out = argos(&args);
        assert!(!out.status.success(), "{args:?} must be refused");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("is not used by"),
            "{args:?}: the refusal must say the flag would be ignored, got:\n{stderr}"
        );
    }
}

/// The seed diagnostics are not unread records: printing a missing derived
/// key or an unscanned account under "record(s) could not be read" — and
/// closing with "anything listed above exists only there" — told the user
/// something false about both.
#[test]
fn seed_diagnostics_are_not_listed_as_unread_records() {
    let path = fixture(SPROUT_PLAINTEXT);
    let mut bytes = std::fs::read(&path).expect("fixture");
    // Point the chain at an unknown future version: the seed can no longer
    // be verified, so a seed diagnostic is printed, and no record is unread.
    let chain = bytes
        .windows(4)
        .zip(0..)
        .find_map(|(w, i)| {
            (w == [1, 0, 0, 0] && bytes.get(i + 4..i + 36) == Some(&SEED_FP_SPROUT_PLAINTEXT))
                .then_some(i)
        })
        .expect("the mnemonichdchain value starts with version 1 and the seed fingerprint");
    bytes[chain] = 9;
    let dir = std::env::temp_dir().join(format!("argos-seed-heading-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let wallet = dir.join("wallet.dat");
    std::fs::write(&wallet, &bytes).expect("write wallet");

    let out = argos(&[
        "--wallet-file",
        wallet.to_str().expect("utf-8"),
        "inspect-wallet",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("version 9"),
        "the seed diagnostic is shown:\n{stdout}"
    );
    assert!(
        !stdout.contains("could not be read"),
        "a seed diagnostic is not an unread record:\n{stdout}"
    );
}

/// `sprout-plaintext.dat`'s seed fingerprint, as it appears in its
/// `mnemonichdchain` value.
const SEED_FP_SPROUT_PLAINTEXT: [u8; 32] = [
    0x7d, 0xd4, 0xe7, 0xc1, 0x66, 0xbd, 0x35, 0x66, 0x5e, 0x7e, 0xd1, 0xcf, 0x9f, 0x56, 0x19, 0xcf,
    0x3d, 0x37, 0x0f, 0x1d, 0xe0, 0x00, 0x78, 0x59, 0x18, 0xb1, 0x54, 0x43, 0xdd, 0x37, 0xcf, 0xa2,
];

/// A saved checkpoint alone cannot settle spends, and inspection makes no
/// network contact. It must find the scan, say its evidence was not
/// verified offline, and keep the wallet file's own accounting.
#[test]
fn inspection_refuses_an_unverified_scan_of_the_same_keys() {
    use secrecy::ExposeSecret;

    let path = fixture(SPROUT_PLAINTEXT);
    let bytes = std::fs::read(&path).expect("fixture is readable");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("the plaintext fixture imports");
    let spending_keys: Vec<[u8; 32]> = keys
        .sprout
        .iter()
        .map(|k| *k.a_sk.expose_secret())
        .collect();
    assert!(!spending_keys.is_empty(), "the fixture holds Sprout keys");

    let outer = tempfile::tempdir().unwrap();
    let dir = artifact_data_dir(&outer);
    let mut scanner = argos_core::sprout_scan::SproutScanner::new(&spending_keys);
    scanner
        .scan_block_at(&[], [0xCD; 32], 2_000_000)
        .expect("an empty block");
    let checkpoint = argos_core::sprout_scan_run::checkpoint_path(&dir, &spending_keys);
    argos_core::sprout_scan_run::save_checkpoint(
        &scanner,
        argos_core::p2p::wire::P2pNetwork::Mainnet,
        &checkpoint,
    )
    .expect("checkpoint written");

    let with_scan = argos(&[
        "--wallet-file",
        path.to_str().unwrap(),
        "--data-dir",
        dir.to_str().unwrap(),
        "inspect-wallet",
    ]);
    let empty_data_dir = outer.path().join("empty-recovery-data");
    let without_scan = argos(&[
        "--wallet-file",
        path.to_str().unwrap(),
        "--data-dir",
        empty_data_dir.to_str().unwrap(),
        "inspect-wallet",
    ]);
    let _ = std::fs::remove_file(&checkpoint);

    assert!(
        nu7_warning(&with_scan.stderr).contains("mined before activation"),
        "resuming with a checkpoint must retain the deadline warning"
    );

    let with = String::from_utf8_lossy(&with_scan.stdout);
    assert!(
        with_scan.status.success(),
        "{}",
        String::from_utf8_lossy(&with_scan.stderr)
    );
    // Inspection never dials a peer, so this synthetic checkpoint is never
    // promoted into spent-note evidence merely because it exists.
    let with = with.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        with.contains("was not verified offline")
            && with.contains(&checkpoint.display().to_string())
            && with.contains("Spent status is the wallet file's own record"),
        "the scan must be found and not used without live verification:\n{with}"
    );
    let without = String::from_utf8_lossy(&without_scan.stdout);
    let without = without.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !without.contains("stopped at height"),
        "no scan, no claim of one:\n{without}"
    );
    assert!(
        without.contains("No full-block scan of this wallet's Sprout keys was found"),
        "and it must say where it looked (finding 2):\n{without}"
    );
}

/// With stdout captured — as here, or redirected to a file — a scan must
/// still say on stderr how it ended. A user ran a 149-minute scan with
/// stdout redirected, saw nothing on the terminal, and asked whether that
/// meant no funds were found.
#[test]
fn a_scan_says_how_it_ended_on_stderr_when_stdout_is_captured() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("fixture path is UTF-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "https://127.0.0.1:1",
        "--data-dir",
        &scratch_dir("summary"),
        "scan",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Scan did not finish") || stderr.contains("Scan finished"),
        "the ending must be said on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("written to stdout"),
        "and where the full result went:\n{stderr}"
    );
}

/// Run `argos`, killing it at a deadline: a build that does not stop where
/// the test expects goes on to dial public peers for hours.
fn argos_with_deadline(args: &[&str], secs: u64) -> (Option<std::process::ExitStatus>, String) {
    let isolated = (!args.contains(&"--data-dir")).then(|| tempfile::tempdir().unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_argos"));
    if let Some(dir) = isolated.as_ref() {
        command.arg("--data-dir").arg(artifact_data_dir(dir));
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = spawn_argos(&mut command);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().expect("piped"), &mut stderr)
        .expect("stderr");
    (status, stderr)
}

/// A zcashd wallet.dat has no seed, but it records when each key was made.
/// Auto-detect reads that, offline: every fixture key is dated, so the chain
/// is never asked, and the run only stops when the scan itself refuses the
/// unusable server.
#[test]
fn auto_detect_dates_a_seedless_wallet_from_its_key_times() {
    let path = fixture(SPROUT_PLAINTEXT);
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("utf-8"),
        "--accept-tos",
        "--birthday-auto-detect",
        "--lightwalletd-url",
        "nonono",
        "--data-dir",
        &scratch_dir("autodetect-mainnet"),
        "scan",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("needs a seed phrase") && !stderr.contains("HD-derived addresses"),
        "a zcashd wallet must no longer be refused:\n{stderr}"
    );
    assert!(stderr.contains("Birthday: block "), "{stderr}");
    assert!(
        stderr.contains("(about 2026-"),
        "the date must be shown:\n{stderr}"
    );
    assert!(
        stderr.contains("from the wallet file's key creation times"),
        "the source must be named:\n{stderr}"
    );
    assert!(
        !stderr.contains("Checking the wallet file's transparent addresses on chain"),
        "complete metadata must not consult the chain:\n{stderr}"
    );
}

/// Testnet times are never converted, so there is no birthday to offer;
/// the scan goes ahead from the start rather than guessing.
#[test]
fn auto_detect_on_testnet_scans_from_the_start() {
    let path = relabeled_fixture(SPROUT_PLAINTEXT, "testnet");
    let out = argos(&[
        "--wallet-file",
        path.to_str().expect("utf-8"),
        "--accept-tos",
        "--network",
        "testnet",
        "--birthday-auto-detect",
        "--lightwalletd-url",
        "nonono",
        "--data-dir",
        &scratch_dir("autodetect-testnet"),
        "scan",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("only converted to heights on mainnet"),
        "{stderr}"
    );
    assert!(stderr.contains("from the start"), "{stderr}");
    // Testnet Sapling activation, not the mainnet default or block 1.
    assert!(stderr.contains("Sapling pool (block 280000)"), "{stderr}");
    assert!(!stderr.contains("Birthday: block "), "{stderr}");
}

/// The Sprout scan states where trial decryption starts, and why, before
/// any network step -- here it is stopped by the unusable server right
/// after. The fixture's Sprout key is dated, so on mainnet there is a skip.
#[test]
fn scan_sprout_states_the_skip_and_can_turn_it_off() {
    let outer = tempfile::tempdir().unwrap();
    let dir = artifact_data_dir(&outer);
    let destination = test_vector_sapling_address(outer.path());
    let wallet = fixture(SPROUT_PLAINTEXT);
    let base = [
        "--wallet-file",
        wallet.to_str().expect("utf-8"),
        "--data-dir",
        dir.to_str().expect("utf-8"),
        "--accept-tos",
        "--lightwalletd-url",
        "nonono",
        "scan-sprout",
        "--destination",
        &destination,
    ];

    let (status, stderr) = argos_with_deadline(&base, 20);
    assert!(status.is_some_and(|s| !s.success()), "must stop:\n{stderr}");
    assert!(
        stderr.contains("Trial decryption starts at block "),
        "the skip must be stated:\n{stderr}"
    );
    assert!(stderr.contains("creation times"), "and why:\n{stderr}");
    assert!(
        stderr.contains("--no-birthday-skip"),
        "and how to undo it:\n{stderr}"
    );

    let mut off = base.to_vec();
    off.push("--no-birthday-skip");
    let (status, stderr) = argos_with_deadline(&off, 20);
    assert!(status.is_some_and(|s| !s.success()), "must stop:\n{stderr}");
    assert!(stderr.contains("every block from 1"), "{stderr}");
    assert!(
        !stderr.contains("Trial decryption starts at block "),
        "{stderr}"
    );

    let mut lower = base.to_vec();
    lower.extend(["--birthday", "500000"]);
    let (status, stderr) = argos_with_deadline(&lower, 20);
    assert!(status.is_some_and(|s| !s.success()), "must stop:\n{stderr}");
    assert!(
        stderr.contains("Trial decryption starts at block 500000, the birthday given"),
        "a lower --birthday wins:\n{stderr}"
    );
}

/// Only scan-sprout skips trial decryption, so the flag anywhere else
/// would be silently ignored.
#[test]
fn no_birthday_skip_is_refused_where_nothing_is_skipped() {
    let path = fixture(SPROUT_PLAINTEXT);
    let wallet = path.to_str().expect("utf-8");
    for args in [
        vec![
            "--wallet-file",
            wallet,
            "inspect-wallet",
            "--no-birthday-skip",
        ],
        vec![
            "--wallet-file",
            wallet,
            "scan",
            "--no-birthday-skip",
            "--accept-tos",
        ],
        vec![
            "--wallet-file",
            wallet,
            "sweep-sprout",
            "--destination",
            "zs1x",
            "--no-birthday-skip",
            "--accept-tos",
        ],
        vec!["show-keys", "--no-birthday-skip"],
    ] {
        let out = argos(&args);
        assert!(!out.status.success(), "{args:?} must be refused");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--no-birthday-skip is not used by"),
            "{args:?}: got:\n{stderr}"
        );
    }
}

/// Kristi's #3 on #260: `scan-sprout` takes its decrypt floor from
/// --birthday only. --birthday-date and --birthday-auto-detect were accepted
/// and silently ignored, though the help says the date overrides --birthday;
/// a user passing one would believe it lowered the floor. Refused before any
/// network step.
#[test]
fn scan_sprout_refuses_birthday_date_and_auto_detect() {
    let path = fixture(SPROUT_PLAINTEXT);
    let wallet = path.to_str().expect("utf-8");
    let dir = scratch_dir("scan-sprout-birthday-flags");
    for flag in [
        vec!["--birthday-date", "2017-01-01"],
        vec!["--birthday-auto-detect"],
    ] {
        let mut args = vec![
            "--wallet-file",
            wallet,
            "--accept-tos",
            "--data-dir",
            &dir,
            "--lightwalletd-url",
            "nonono",
        ];
        args.extend(flag.iter().copied());
        args.extend(["scan-sprout", "--destination", "zs1x"]);
        let (status, stderr) = argos_with_deadline(&args, 20);
        assert!(
            status.is_some_and(|s| !s.success()),
            "{flag:?} must be refused:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("{} is not used by `argos scan-sprout`", flag[0])),
            "{flag:?}: got:\n{stderr}"
        );
        assert!(stderr.contains("--birthday <height>"), "{stderr}");
        assert!(
            !stderr.contains("Trial decryption"),
            "refused before the plan is stated:\n{stderr}"
        );
    }
}

/// Kristi's test gap on #260: `scan` and `sweep` must land on the same
/// birthday, or they key different workspaces. For a fully dated wallet.dat
/// detection is offline and deterministic, so the two agree; the
/// chain-dependent fallback is tracked separately.
#[test]
fn scan_and_sweep_auto_detect_the_same_birthday() {
    let outer = tempfile::tempdir().unwrap();
    let dir = artifact_data_dir(&outer);
    let destination = test_vector_sapling_address(outer.path());
    let wallet = fixture(SPROUT_PLAINTEXT);
    let base = [
        "--wallet-file",
        wallet.to_str().expect("utf-8"),
        "--data-dir",
        dir.to_str().expect("utf-8"),
        "--accept-tos",
        "--birthday-auto-detect",
        "--lightwalletd-url",
        "nonono",
    ];
    let birthday_line = |stderr: &str| -> String {
        stderr
            .lines()
            .find(|l| l.contains("Birthday: block "))
            .unwrap_or_else(|| panic!("no birthday line:\n{stderr}"))
            .to_owned()
    };

    let mut scan = base.to_vec();
    scan.push("scan");
    let (_, scan_stderr) = argos_with_deadline(&scan, 20);

    let mut sweep = base.to_vec();
    sweep.extend(["sweep", "--destination", &destination, "--dry-run"]);
    let (_, sweep_stderr) = argos_with_deadline(&sweep, 20);

    assert_eq!(birthday_line(&scan_stderr), birthday_line(&sweep_stderr));
}

/// Kristi's #1 on #260, CLI paste route: a `--sapling-key-file` key has no
/// creation time and could hold notes from any height after activation. The
/// file's dated transparent keys must not let a transparent output decide
/// where Sapling starts, so the chain is never asked (with an unusable
/// server, a chain check would say "could not be checked").
#[test]
fn auto_detect_with_a_sapling_key_file_does_not_use_the_chain() {
    let wallet = fixture("modern-plaintext.dat");
    let key = key_file(
        "sapling-key-autodetect.txt",
        &format!("{TEST_SAPLING_KEY_MAINNET}\n"),
    );
    let out = argos(&[
        "--wallet-file",
        wallet.to_str().expect("utf-8"),
        "--sapling-key-file",
        key.to_str().expect("utf-8"),
        "--accept-tos",
        "--birthday-auto-detect",
        "--lightwalletd-url",
        "nonono",
        "--data-dir",
        &scratch_dir("autodetect-sapling-key-file"),
        "scan",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Checking the wallet file's transparent addresses on chain"),
        "an undated Sapling key must rule out the chain fallback:\n{stderr}"
    );
    assert!(!stderr.contains("could not be checked"), "{stderr}");
    assert!(stderr.contains("Sapling activation"), "{stderr}");
    assert!(stderr.contains("No birthday could be detected"), "{stderr}");
    // Kristi's #2 on #260: the same height a plain `scan` with no --birthday
    // uses on mainnet, so the two key the same workspace and a resume holds.
    assert!(stderr.contains("Sapling pool (block 419200)"), "{stderr}");
    assert!(!stderr.contains("Birthday: block "), "{stderr}");
}
