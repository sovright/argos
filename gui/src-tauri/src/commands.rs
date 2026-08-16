#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use argos_core::{
    detect_birthday as zeck_detect_birthday, estimate_birthday_from_date as estimate_birthday,
    list_incomplete_sessions as zeck_list_incomplete_sessions, parse_workspace_keying,
    validate_destination_address, validate_mnemonic_words, verify_seed_for_workspace,
    BirthdayDetectResult, IncompleteSession, RecoveryService, ScanConfig, ScanHandle, SweepOutcome,
    SweepProposal, SweepRequest, ZeckNetwork,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Clone)]
pub struct AppState {
    pub service: RecoveryService,
}

fn ensure_tos_accepted(app: &AppHandle) -> Result<(), String> {
    let base = tos_base_dir(app)?;
    ensure_tos_accepted_for_base(&base)
}

fn ensure_tos_accepted_for_base(base: &Path) -> Result<(), String> {
    if argos_core::is_tos_accepted(base) {
        Ok(())
    } else {
        Err(format!(
            "Argos Terms of Service ({}) must be accepted before scanning, probing, or sweeping.",
            argos_core::TOS_VERSION
        ))
    }
}

// No `Debug`/`Serialize`/`Clone`: this struct carries the cleartext seed, so it
// must never be debug-printed, serialized, or duplicated. It only deserializes
// the Tauri command payload, and its `SecretString` seed field redacts and
// zeroizes the seed once parsed (audit Issue A).
#[derive(Deserialize)]
pub struct ScanConfigInput {
    pub seed: SecretString,
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
    pub lightwalletd_url: String,
    pub data_dir: String,
    pub network: ZeckNetwork,
    /// User-supplied label for the scan, written to the on-disk session
    /// sidecar so the launch-time "resume an unfinished scan" UI can show
    /// something more recognizable than a fingerprint suffix. Optional —
    /// empty/missing strings render as "(unlabeled scan)".
    #[serde(default)]
    pub label: Option<String>,
}

#[tauri::command]
pub async fn validate_seed(words: Vec<String>) -> Result<bool, String> {
    validate_mnemonic_words(&words)
        .map(|_| true)
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn validate_address(
    address: String,
    network: ZeckNetwork,
) -> Result<argos_core::AddressInfo, String> {
    validate_destination_address(&address, network).map_err(|err| err.to_string())
}

/// What Argos found in a legacy wallet file, with nothing secret in it.
///
/// Deliberately counts rather than keys: this crosses the IPC boundary to
/// the webview, and the frontend has no use for key material. Mirrors what
/// `argos inspect-wallet` prints.
#[derive(Serialize)]
pub struct WalletFileSummary {
    pub path: String,
    pub transparent_keys: usize,
    pub sapling_keys: usize,
    pub sprout_keys: usize,
    /// Sprout addresses, which are public and are the only way a user can
    /// tell which funds this file holds for the Sprout pool.
    pub sprout_addresses: Vec<String>,
    /// Sprout notes recovered from this file alone, and their total value.
    ///
    /// This is the whole difference between "your funds are right here" and
    /// "this needs a multi-hour full-block scan", so it is computed here
    /// rather than left for the frontend to infer from key counts. A wallet
    /// can hold Sprout keys and still recover nothing, if the note
    /// ciphertexts or cached witnesses are absent.
    pub sprout_spendable_notes: usize,
    pub sprout_spendable_zatoshis: u64,
    /// Why notes could not be recovered, when none were. Shown rather than
    /// summarised away: "no notes" and "notes that failed to decrypt" call
    /// for very different next steps.
    pub sprout_issues: Vec<String>,
    /// What a full-block Sprout scan would cost, in the user's terms.
    /// Rendered from `argos-core` so the GUI and CLI cannot drift.
    pub sprout_scan_warning: Vec<String>,
    /// True when the file yielded a BIP-39 mnemonic, which means it re-enters
    /// the ordinary HD pipeline and scans and sweeps like a typed seed.
    pub has_mnemonic: bool,
    /// True when the file has no Sapling keys, so recovery goes down the
    /// transparent-only path (ZIP-316 gives it no UFVK to anchor an account).
    pub transparent_only: bool,
    /// Records the parser could not read. Surfaced because a wallet that
    /// silently drops records looks identical to one that had nothing.
    pub diagnostics: Vec<String>,
    /// True when the file is encrypted and the supplied passphrase (or its
    /// absence) could not open it.
    pub needs_passphrase: bool,
}

/// Show a native file picker and return the chosen wallet file's path.
///
/// Lives in Rust rather than being called from JavaScript, matching how the
/// opener plugin is used here: the capability file grants the webview no
/// `dialog:` permission, so the frontend cannot open a dialog of its own
/// choosing. Returns `None` when the user cancels, which is not an error.
///
/// Only the path crosses back. Argos reads the file in the backend, so a
/// wallet's bytes never transit the webview.
#[tauri::command]
pub async fn pick_wallet_file(app: AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Open a Zcash wallet file")
        // zcashd writes `wallet.dat`; ZecWallet Lite writes files with
        // assorted names, so an "any file" option has to stay reachable or
        // the picker would hide wallets it can actually read.
        .add_filter("Wallet files", &["dat"])
        .add_filter("All files", &["*"])
        .pick_file(move |picked| {
            let _ = tx.send(picked);
        });

    let picked = rx
        .await
        .map_err(|_| "the file picker closed unexpectedly".to_owned())?;

    Ok(picked
        .and_then(|path| path.into_path().ok())
        .map(|path| path.to_string_lossy().into_owned()))
}

/// Whether this build can recover Sprout funds.
///
/// A constant resolved at compile time, because that is exactly what it
/// reports: with the `sprout` feature off there is no Sprout backend linked
/// in at all — the recovery, scan and sweep modules are absent, and with them
/// the five Tauri commands the Sprout panel calls. There is nothing to
/// feature-detect at runtime, so the honest answer is whichever constant the
/// build was compiled with.
///
/// It is a command rather than a build-time edit to the frontend because
/// `gui/src/main.js` is a single static file with no bundler, shared by both
/// builds. Deleting the panel in one and re-adding it in the other would
/// churn the same code twice and let the two copies drift; asking the backend
/// at runtime keeps one frontend serving both.
///
/// The frontend must treat a failed call as `false` too. Guessing "supported"
/// would put a user in front of live-looking Sprout controls that cannot work.
#[cfg(feature = "sprout")]
#[tauri::command]
pub fn sprout_supported() -> bool {
    true
}

/// See the counterpart above. Without the feature the Sprout commands are not
/// compiled at all, so invoking one throws; the frontend has to know that
/// before it draws a single live-looking control.
#[cfg(not(feature = "sprout"))]
#[tauri::command]
pub fn sprout_supported() -> bool {
    false
}

/// The Sprout-derived portion of a `WalletFileSummary`.
///
/// Extracted so the Sprout recovery computation — forged-key rejection, note
/// decryption, scan-cost wording — compiles out with the `sprout` feature.
/// The fields are plain data (counts, encoded strings) so the JSON the
/// frontend consumes is identical either way; only their *values* change: a
/// default build cannot recover or validate Sprout notes, so it reports the
/// key count from the parser and leaves the rest empty.
struct SproutSummary {
    sprout_keys: usize,
    sprout_addresses: Vec<String>,
    sprout_spendable_notes: usize,
    sprout_spendable_zatoshis: u64,
    sprout_issues: Vec<String>,
    sprout_scan_warning: Vec<String>,
}

/// Compute the Sprout summary for a wallet. Body is verbatim the logic that
/// previously lived inline in `inspect_wallet_file`: reject forged keys, then
/// try to recover notes, then quote the scan cost when a scan would be needed.
#[cfg(feature = "sprout")]
fn compute_sprout_summary(
    keys: &mut argos_core::argos_wallet_import::ImportedKeys,
    network_name: &str,
) -> SproutSummary {
    // Decrypting the note ciphertexts is what distinguishes a wallet whose
    // Sprout funds are recoverable right now from one that would need the
    // full-block scan. Doing it here keeps that judgement out of the
    // frontend, which can only see counts.
    // Dropped before anything is reported: a key that does not control its
    // stored address must not be counted, shown, or spent with.
    let forged = argos_core::sprout_recovery::reject_forged_sprout_keys(keys);

    let recovered = argos_core::sprout_recovery::recover_spendable_sprout_notes(keys);
    let needs_scan = !keys.sprout.is_empty() && recovered.notes.is_empty();

    SproutSummary {
        sprout_keys: keys.sprout.len(),
        // Encoded `zc…`/`zt…`, matching the CLI. Hex was shown here before
        // and matched nothing a user has ever seen — not a paper backup, not
        // a block explorer — while the CLI encoded properly, so the same
        // address appeared in two irreconcilable forms across the two
        // surfaces this project claims cannot drift.
        sprout_addresses: keys
            .sprout
            .iter()
            .map(|k| {
                argos_core::sprout_key::encode_sprout_address(
                    &argos_core::sprout::SproutPaymentAddress::from_bytes(k.address),
                    network_from(network_name),
                )
            })
            .collect(),
        sprout_spendable_notes: recovered.notes.len(),
        sprout_spendable_zatoshis: recovered.total_value(),
        sprout_issues: forged
            .iter()
            .map(|f| f.to_string())
            .chain(recovered.issues.iter().map(|i| i.to_string()))
            .collect(),
        sprout_scan_warning: if needs_scan {
            argos_core::sprout_scan_cost::SproutScanCost::for_network(
                network_from(network_name).into(),
            )
            .warning_lines()
        } else {
            Vec::new()
        },
    }
}

/// Without the Sprout code path compiled in there is no recovery or
/// validation logic to run. The always-on parser still counts the keys, so
/// the summary reports that count (unvalidated) and leaves everything the
/// recovery path would have produced empty.
#[cfg(not(feature = "sprout"))]
fn compute_sprout_summary(
    keys: &mut argos_core::argos_wallet_import::ImportedKeys,
    _network_name: &str,
) -> SproutSummary {
    SproutSummary {
        sprout_keys: keys.sprout.len(),
        sprout_addresses: Vec::new(),
        sprout_spendable_notes: 0,
        sprout_spendable_zatoshis: 0,
        sprout_issues: Vec::new(),
        sprout_scan_warning: Vec::new(),
    }
}

/// Read a legacy wallet file and report what is in it. No network, and
/// nothing is written anywhere.
///
/// The passphrase crosses the IPC boundary as a `SecretString`, the same
/// treatment the seed phrase gets (audit Issue A). That is a real exposure
/// and is recorded in docs/THREAT_MODEL.md as T-S6: a compromised webview
/// sees it. The CLI avoids the question entirely by prompting on a terminal;
/// a GUI has no equivalent, so the choice is this or no GUI import at all.
#[tauri::command]
pub async fn inspect_wallet_file(
    path: String,
    passphrase: Option<SecretString>,
    network: Option<String>,
) -> Result<WalletFileSummary, String> {
    // Needed to encode Sprout addresses in the form the user can actually
    // match against a backup. Optional so an older frontend still works,
    // defaulting to mainnet as everything else here does.
    let network_name = network.unwrap_or_else(|| "mainnet".to_owned());
    let bytes = fs::read(&path).map_err(|err| format!("could not read {path}: {err}"))?;
    let keys =
        match argos_core::argos_wallet_import::import_wallet_file(&bytes, passphrase.as_ref()) {
            Ok(keys) => keys,
            // An encrypted wallet with a missing or wrong passphrase is an
            // ordinary user situation, not a failure to show raw. Matched on the
            // typed variant rather than the message text, so rewording the error
            // cannot silently turn "ask for the passphrase" into "give up".
            Err(argos_core::argos_wallet_import::ImportError::WrongPassphrase) => {
                return Ok(WalletFileSummary {
                    path,
                    transparent_keys: 0,
                    sapling_keys: 0,
                    sprout_keys: 0,
                    sprout_addresses: Vec::new(),
                    sprout_spendable_notes: 0,
                    sprout_spendable_zatoshis: 0,
                    sprout_issues: Vec::new(),
                    sprout_scan_warning: Vec::new(),
                    has_mnemonic: false,
                    transparent_only: false,
                    diagnostics: Vec::new(),
                    needs_passphrase: true,
                });
            }
            Err(err) => return Err(err.to_string()),
        };

    // The Sprout-specific recovery (forged-key rejection, note decryption,
    // scan-cost wording) is computed in a helper so it compiles out with the
    // `sprout` feature. It takes `&mut keys` because rejecting forged Sprout
    // keys must drop them before anything else reads the wallet.
    let mut keys = keys;
    let sprout = compute_sprout_summary(&mut keys, &network_name);

    Ok(WalletFileSummary {
        path,
        transparent_keys: keys.transparent.len(),
        sapling_keys: keys.sapling.len(),
        sprout_keys: sprout.sprout_keys,
        sprout_addresses: sprout.sprout_addresses,
        sprout_spendable_notes: sprout.sprout_spendable_notes,
        sprout_spendable_zatoshis: sprout.sprout_spendable_zatoshis,
        sprout_issues: sprout.sprout_issues,
        sprout_scan_warning: sprout.sprout_scan_warning,
        has_mnemonic: keys.mnemonic.is_some(),
        transparent_only: argos_core::key_source::classify_recovery_route(&keys)
            == argos_core::key_source::RecoveryRoute::TransparentOnly,
        diagnostics: keys.diagnostics.iter().map(|d| d.to_string()).collect(),
        needs_passphrase: false,
    })
}

// No `Debug`/`Serialize`/`Clone`, for the same reason as `ScanConfigInput`:
// this carries a wallet passphrase.
#[derive(Deserialize)]
pub struct WalletFileScanInput {
    pub path: String,
    pub passphrase: Option<SecretString>,
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
    pub lightwalletd_url: String,
    pub data_dir: String,
    pub network: ZeckNetwork,
    #[serde(default)]
    pub label: Option<String>,
}

/// Scan a legacy wallet file's keys.
///
/// Routing lives in the core service, not here: a wallet that yields a
/// mnemonic goes down the ordinary HD path, and one that does not is scanned
/// as imported accounts. The GUI only has to hand over the key source, which
/// is why this is a thin wrapper over `start_scan_from_key_source`.
#[tauri::command]
pub async fn start_scan_from_wallet_file(
    app: AppHandle,
    state: State<'_, AppState>,
    config: WalletFileScanInput,
) -> Result<ScanHandle, String> {
    use std::sync::Arc;

    ensure_tos_accepted(&app)?;

    let bytes =
        fs::read(&config.path).map_err(|err| format!("could not read {}: {err}", config.path))?;
    let keys =
        argos_core::argos_wallet_import::import_wallet_file(&bytes, config.passphrase.as_ref())
            .map_err(|err| err.to_string())?;

    let key_source: Arc<dyn argos_core::KeySource> =
        Arc::new(argos_core::ImportedKeySource::new(keys));

    let handle = state
        .service
        .start_scan_from_key_source(
            ScanConfig {
                birthday: config.birthday,
                num_accounts: config.num_accounts,
                gap_limit: config.gap_limit,
                lightwalletd_url: config.lightwalletd_url,
                data_dir: PathBuf::from(config.data_dir),
                network: config.network,
                label: config.label.unwrap_or_default(),
            },
            key_source,
        )
        .await
        .map_err(|err| err.to_string())?;

    spawn_scan_progress_pump(app, state.service.clone(), handle.clone());

    Ok(handle)
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    config: ScanConfigInput,
) -> Result<ScanHandle, String> {
    ensure_tos_accepted(&app)?;
    let handle = state
        .service
        .start_scan(
            ScanConfig {
                birthday: config.birthday,
                num_accounts: config.num_accounts,
                gap_limit: config.gap_limit,
                lightwalletd_url: config.lightwalletd_url,
                data_dir: PathBuf::from(config.data_dir),
                network: config.network,
                label: config.label.unwrap_or_default(),
            },
            config.seed,
        )
        .await
        .map_err(|err| err.to_string())?;

    spawn_scan_progress_pump(app, state.service.clone(), handle.clone());

    Ok(handle)
}

/// Forward `scan-progress` / `scan-discovery` / `scan-complete` events to
/// the frontend while a scan is running. Identical for fresh scans and
/// resumed scans, so it's factored out.
fn spawn_scan_progress_pump(app: AppHandle, service: RecoveryService, handle: ScanHandle) {
    tokio::spawn(async move {
        let mut emitted_discoveries = 0usize;
        loop {
            let progress = match service.get_scan_progress(&handle).await {
                Ok(progress) => progress,
                Err(_) => break,
            };

            if emitted_discoveries > progress.discoveries.len() {
                emitted_discoveries = progress.discoveries.len();
            }
            if progress.discoveries.len() > emitted_discoveries {
                for discovery in &progress.discoveries[emitted_discoveries..] {
                    let _ = app.emit("scan-discovery", discovery);
                }
                emitted_discoveries = progress.discoveries.len();
            }
            let _ = app.emit("scan-progress", &progress);

            if matches!(
                progress.phase,
                argos_core::ScanPhase::Complete
                    | argos_core::ScanPhase::Cancelled
                    | argos_core::ScanPhase::Error
            ) {
                let _ = app.emit("scan-complete", &progress);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    });
}

#[tauri::command]
pub async fn get_scan_progress(
    state: State<'_, AppState>,
    handle: ScanHandle,
) -> Result<argos_core::ScanProgress, String> {
    state
        .service
        .get_scan_progress(&handle)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn cancel_scan(state: State<'_, AppState>, handle: ScanHandle) -> Result<(), String> {
    state
        .service
        .cancel_scan(&handle)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn propose_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    handle: ScanHandle,
    destination: String,
    memo: Option<String>,
    max_fee_zec: Option<String>,
    donation_rate: Option<f64>,
    donor_email: Option<String>,
) -> Result<SweepProposal, String> {
    ensure_tos_accepted(&app)?;
    let max_fee_zatoshis = max_fee_zec
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_zec_to_zatoshis)
        .transpose()?;

    state
        .service
        .propose_sweep(
            &handle,
            SweepRequest {
                destination,
                memo,
                max_fee_zatoshis,
                donation_rate,
                donor_email,
            },
        )
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn execute_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    handle: ScanHandle,
    destination: String,
    memo: Option<String>,
    max_fee_zec: Option<String>,
    donation_rate: Option<f64>,
    donor_email: Option<String>,
) -> Result<SweepOutcome, String> {
    ensure_tos_accepted(&app)?;
    let max_fee_zatoshis = max_fee_zec
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_zec_to_zatoshis)
        .transpose()?;

    // `execute_sweep` returns an `Err` only when nothing was broadcast. A
    // mid-sequence abort *after* one or more broadcasts comes back as an `Ok`
    // outcome carrying the partial records plus `error`, so the records of
    // funds already on-chain are never lost to the frontend (audit Issue E).
    let outcome = state
        .service
        .execute_sweep(
            &handle,
            SweepRequest {
                destination,
                memo,
                max_fee_zatoshis,
                donation_rate,
                donor_email,
            },
        )
        .await
        .map_err(|err| err.to_string())?;

    for result in &outcome.transactions {
        let _ = app.emit("sweep-tx-broadcast", result);
        if result.status == "confirmed" {
            let _ = app.emit("sweep-tx-confirmed", result);
        }
    }

    Ok(outcome)
}

/// What a Sprout sweep would move, before anything is built.
#[cfg(feature = "sprout")]
#[derive(Serialize)]
pub struct SproutSweepPreview {
    pub notes: usize,
    pub gross_zatoshis: u64,
    pub fee_zatoshis: u64,
    pub net_zatoshis: u64,
    /// Whether the Sprout proving parameters are already present. The GUI
    /// needs this before the user commits: without them the sweep cannot
    /// start, and a 725 MB download is not something to discover halfway
    /// through a recovery.
    pub params_present: bool,
    pub params_path: String,
    /// Why the funds land in Sapling and not Orchard. Shown before the user
    /// commits, because pasting a unified address reasonably creates the
    /// opposite expectation.
    pub lands_in_sapling: String,
}

/// Preview a Sprout sweep.
///
/// The wallet file is re-read rather than kept in memory between calls:
/// holding decrypted Sprout spending keys in the backend for the lifetime
/// of the app would widen the window in which they can be captured, for no
/// benefit beyond skipping a file read.
#[cfg(feature = "sprout")]
#[tauri::command]
pub async fn preview_sprout_sweep(
    app: AppHandle,
    path: String,
    passphrase: Option<SecretString>,
) -> Result<SproutSweepPreview, String> {
    ensure_tos_accepted(&app)?;

    let bytes = fs::read(&path).map_err(|err| format!("could not read {path}: {err}"))?;
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, passphrase.as_ref())
        .map_err(|err| err.to_string())?;

    let recovered = argos_core::sprout_recovery::recover_spendable_sprout_notes(&keys);
    let plan = argos_core::sprout_sweep::plan_sweep(&recovered.notes).map_err(|e| e.to_string())?;

    let params_path = argos_core::sprout_sweep::default_params_path();
    Ok(SproutSweepPreview {
        notes: plan.notes,
        gross_zatoshis: plan.gross_zatoshis,
        fee_zatoshis: plan.fee_zatoshis,
        net_zatoshis: plan.net_zatoshis,
        params_present: params_path.exists(),
        params_path: params_path.display().to_string(),
        lands_in_sapling: argos_core::sprout_sweep::SPROUT_LANDS_IN_SAPLING.to_owned(),
    })
}

/// One broadcast Sprout sweep, for the frontend.
#[cfg(feature = "sprout")]
#[derive(Serialize)]
pub struct SproutSweepResult {
    pub txid: String,
    pub value_swept: u64,
}

#[cfg(feature = "sprout")]
#[derive(Serialize)]
pub struct SproutSweepReport {
    pub sent: Vec<SproutSweepResult>,
    pub total_swept: u64,
    /// True when the destination was a unified address, so the funds landed
    /// in its Sapling receiver and a further hop is needed for Orchard.
    pub landed_in_unified_sapling: bool,
    /// Notes that did not move, and why. Surfaced rather than summarised:
    /// a user seeing less than expected needs to know which notes stayed
    /// behind.
    pub skipped: Vec<String>,
    /// Set when the sweep stopped partway. `sent` still lists what was
    /// broadcast before it did — those funds have moved.
    pub error: Option<String>,
}

/// Prove and broadcast a Sprout sweep.
///
/// Progress is emitted as `sprout-sweep-progress` events because proving
/// takes minutes per note, and a silent multi-minute window is
/// indistinguishable from a hang.
#[cfg(feature = "sprout")]
#[tauri::command]
pub async fn execute_sprout_sweep(
    app: AppHandle,
    path: String,
    passphrase: Option<SecretString>,
    destination: String,
    lightwalletd_url: String,
    network: String,
) -> Result<SproutSweepReport, String> {
    ensure_tos_accepted(&app)?;

    let network = match network.as_str() {
        "testnet" => argos_core::ZeckNetwork::Testnet,
        _ => argos_core::ZeckNetwork::Mainnet,
    };

    let bytes = fs::read(&path).map_err(|err| format!("could not read {path}: {err}"))?;
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, passphrase.as_ref())
        .map_err(|err| err.to_string())?;

    let recovered = argos_core::sprout_recovery::recover_spendable_sprout_notes(&keys);
    if recovered.notes.is_empty() {
        return Err(
            "no spendable Sprout notes could be recovered from this wallet file".to_owned(),
        );
    }

    let params_path = argos_core::sprout_sweep::default_params_path();
    let emitter = app.clone();
    let outcome = argos_core::sprout_sweep::sweep_sprout_notes(
        &recovered.notes,
        network,
        &lightwalletd_url,
        &destination,
        &params_path,
        [0u8; 512],
        move |msg| {
            let _ = emitter.emit("sprout-sweep-progress", msg);
        },
    )
    .await
    .map_err(|err| err.to_string())?;

    Ok(SproutSweepReport {
        sent: outcome
            .sent
            .into_iter()
            .map(|s| SproutSweepResult {
                txid: s.txid,
                value_swept: s.value_swept,
            })
            .collect(),
        total_swept: outcome.total_swept,
        landed_in_unified_sapling: outcome.destination_kind
            == Some(argos_core::sprout_sweep::DestinationKind::SaplingReceiverOfUnified),
        skipped: outcome.skipped,
        error: outcome.error,
    })
}

/// A Sprout scan's outcome, for the frontend.
#[cfg(feature = "sprout")]
#[derive(Serialize)]
pub struct SproutScanReport {
    pub blocks_scanned: u64,
    pub joinsplits_seen: u64,
    pub notes_found: usize,
    pub spent_notes: usize,
    pub total_zatoshis: u64,
}

/// Check a raw Sprout spending key and report the address it controls.
///
/// Separate from the scan so a typo is caught in a second rather than six
/// hours in. The address is returned so the user can confirm Argos is about
/// to look for the one they meant.
#[cfg(feature = "sprout")]
#[tauri::command]
pub async fn check_sprout_key(key: String, network: String) -> Result<String, String> {
    let network = network_from(&network);
    let a_sk = argos_core::sprout_key::decode_sprout_spending_key(key.trim(), network)
        .map_err(|err| err.to_string())?;
    Ok(argos_core::sprout_key::encode_sprout_address(
        &argos_core::sprout::SproutPaymentAddress::from_spending_key(&a_sk),
        network,
    ))
}

/// Gather the spending keys a scan should look for.
///
/// From the wallet file, from typed `SK…`/`ST…` keys, or both — a user may
/// hold a wallet whose keys were never rescanned *and* a paper key for an
/// address it never knew about. Mirrors `collect_sprout_scan_keys` in the
/// CLI, including the dedup: a repeated key trial-decrypts every ciphertext
/// twice for nothing.
#[cfg(feature = "sprout")]
fn collect_scan_keys(
    path: Option<&str>,
    passphrase: Option<&SecretString>,
    typed: &[String],
    network: argos_core::ZeckNetwork,
) -> Result<Vec<[u8; 32]>, String> {
    use secrecy::ExposeSecret;

    let mut keys: Vec<[u8; 32]> = Vec::new();

    for (index, key) in typed.iter().enumerate() {
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        keys.push(
            argos_core::sprout_key::decode_sprout_spending_key(key, network)
                .map_err(|err| format!("key {}: {err}", index + 1))?,
        );
    }

    if let Some(path) = path {
        let bytes = fs::read(path).map_err(|err| format!("could not read {path}: {err}"))?;
        let wallet = argos_core::argos_wallet_import::import_wallet_file(&bytes, passphrase)
            .map_err(|err| err.to_string())?;
        for key in &wallet.sprout {
            keys.push(*key.a_sk.expose_secret());
        }
    }

    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return Err(
            "no Sprout spending keys to scan for. Open a wallet file holding Sprout keys, \
             or paste one or more SK…/ST… keys."
                .to_owned(),
        );
    }
    Ok(keys)
}

/// Scan the chain for notes belonging to raw Sprout spending keys.
///
/// Runs for hours, so progress arrives as `sprout-scan-progress` events and
/// the scan checkpoints as it goes — closing the app and reopening resumes
/// rather than restarting.
#[cfg(feature = "sprout")]
#[tauri::command]
pub async fn start_sprout_scan(
    app: AppHandle,
    keys: Vec<String>,
    path: Option<String>,
    passphrase: Option<SecretString>,
    network: String,
    data_dir: String,
    peers: Vec<String>,
) -> Result<SproutScanReport, String> {
    ensure_tos_accepted(&app)?;
    let network = network_from(&network);

    // The panel offers to use the wallet file's own keys; it now actually
    // can. Previously this took typed keys only, so the one user it exists
    // for — a wallet holding Sprout keys but no note data — was told to
    // leave the box blank and then refused, with no way to see the keys.
    let decoded = collect_scan_keys(path.as_deref(), passphrase.as_ref(), &keys, network)?;

    let p2p: argos_core::p2p::wire::P2pNetwork = network.into();
    let dir = PathBuf::from(data_dir);
    let checkpoint = argos_core::sprout_scan_run::checkpoint_path(&dir, &decoded);

    let emitter = app.clone();
    let result = argos_core::sprout_scan_run::run_sprout_scan(
        &decoded,
        p2p,
        &peers,
        &checkpoint,
        move |tick| {
            let _ = emitter.emit(
                "sprout-scan-progress",
                serde_json::json!({
                    "height": tick.height,
                    "target": tick.target,
                    "notesFound": tick.notes_found,
                    "joinsplitsSeen": tick.joinsplits_seen,
                }),
            );
        },
    )
    .await
    .map_err(|err| err.to_string())?;

    Ok(SproutScanReport {
        blocks_scanned: result.progress.blocks_scanned,
        joinsplits_seen: result.progress.joinsplits_seen,
        notes_found: result.notes.len(),
        spent_notes: result.spent_notes,
        total_zatoshis: result.total_value(),
    })
}

/// Sweep the notes a scan found.
///
/// Resuming a finished scan is instant — the checkpoint's cursor is already
/// at the target, so `run_sprout_scan` skips its loop and goes straight to
/// producing the notes. That is what makes this cheap enough to be a button
/// rather than another six hours.
///
/// Without it, a scan that found funds after six hours was a dead end: the
/// wallet-file sweep re-reads the file and cannot see scan-found notes, so
/// the user was shown money and given nothing to click.
#[cfg(feature = "sprout")]
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn sweep_sprout_from_scan(
    app: AppHandle,
    keys: Vec<String>,
    path: Option<String>,
    passphrase: Option<SecretString>,
    destination: String,
    network: String,
    data_dir: String,
    lightwalletd_url: String,
    peers: Vec<String>,
) -> Result<SproutSweepReport, String> {
    ensure_tos_accepted(&app)?;
    let net = network_from(&network);
    let decoded = collect_scan_keys(path.as_deref(), passphrase.as_ref(), &keys, net)?;

    // Validated before anything else: an address with no Sapling receiver
    // should fail here, not after the notes are re-derived.
    argos_core::sprout_sweep::parse_sapling_destination(&destination, net)
        .map_err(|err| err.to_string())?;

    let p2p: argos_core::p2p::wire::P2pNetwork = net.into();
    let dir = PathBuf::from(data_dir);
    let checkpoint = argos_core::sprout_scan_run::checkpoint_path(&dir, &decoded);
    if !checkpoint.exists() {
        return Err(
            "no saved scan was found for these keys. Run the scan first — its results are              what this sweeps."
                .to_owned(),
        );
    }

    let emitter = app.clone();
    let result = argos_core::sprout_scan_run::run_sprout_scan(
        &decoded,
        p2p,
        &peers,
        &checkpoint,
        move |tick| {
            let _ = emitter.emit(
                "sprout-scan-progress",
                serde_json::json!({
                    "height": tick.height,
                    "target": tick.target,
                    "notesFound": tick.notes_found,
                    "joinsplitsSeen": tick.joinsplits_seen,
                }),
            );
        },
    )
    .await
    .map_err(|err| err.to_string())?;

    if result.notes.is_empty() {
        return Err("the saved scan found no unspent Sprout notes to sweep".to_owned());
    }

    let params_path = argos_core::sprout_sweep::default_params_path();
    let emitter = app.clone();
    let outcome = argos_core::sprout_sweep::sweep_sprout_notes(
        &result.notes,
        net,
        &lightwalletd_url,
        &destination,
        &params_path,
        [0u8; 512],
        move |msg| {
            let _ = emitter.emit("sprout-sweep-progress", msg);
        },
    )
    .await
    .map_err(|err| err.to_string())?;

    Ok(SproutSweepReport {
        sent: outcome
            .sent
            .into_iter()
            .map(|s| SproutSweepResult {
                txid: s.txid,
                value_swept: s.value_swept,
            })
            .collect(),
        total_swept: outcome.total_swept,
        landed_in_unified_sapling: outcome.destination_kind
            == Some(argos_core::sprout_sweep::DestinationKind::SaplingReceiverOfUnified),
        skipped: outcome.skipped,
        error: outcome.error,
    })
}

#[cfg(feature = "sprout")]
fn network_from(name: &str) -> argos_core::ZeckNetwork {
    match name {
        "testnet" => argos_core::ZeckNetwork::Testnet,
        _ => argos_core::ZeckNetwork::Mainnet,
    }
}

#[tauri::command]
pub fn default_data_dir(app: AppHandle) -> Result<String, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("resolving app data dir: {err}"))?;
    Ok(base.join("workspace").display().to_string())
}

#[tauri::command]
pub fn donation_address() -> String {
    argos_core::DONATION_ADDRESS.to_owned()
}

/// The running build's version, for the sidebar.
///
/// Support answers increasingly begin "check your version" — most immediately
/// because builds before 1.1.0 cannot complete a sweep now that Ironwood
/// (NU6.3) has activated at mainnet height 3_428_143. Someone hitting that has
/// a wallet that scans correctly and a sweep that fails, and no way to tell
/// from inside the app which build they are on.
///
/// Reports the compiled-in package version rather than anything read at
/// runtime, so it always describes the binary actually executing.
#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Exact set of external URLs the UI is allowed to open in the OS browser.
///
/// This is the egress allowlist that replaces the broad `opener:default`
/// capability grant (audit Issue D). Code running in the webview can only open
/// one of these exact URLs, so a future webview compromise cannot use the
/// opener as a channel to exfiltrate the seed (e.g. opening a URL of the form
/// `https://evil/?s=<seed>`). Keep this in sync with the `<a href>` links in
/// `gui/src/*.html`. Adding a link there without adding it here means the link
/// will silently fail to open, which is the intended fail-closed behavior.
const ALLOWED_EXTERNAL_URLS: &[&str] = &[
    "https://github.com/sovright/argos/discussions",
    "https://github.com/zingolabs/zexcavator",
    "https://leastauthority.com",
    "https://signal.group/#CjQKIKE0kww-DmAPcnN92JPeSt7_e2YYyLOy11l1up_vHvC1EhDUYW2_t9TDKpeXh7lP2l5Q",
    "https://sovright.com",
    "https://www.theblock.co/post/175259/someone-is-clogging-up-the-zcash-blockchain-with-a-spam-attack",
    "mailto:support@sovright.com",
];

/// Open an external URL in the OS default handler, but only if it is on the
/// hard-coded allowlist. Replaces direct frontend access to the opener
/// plugin's `open_url` (audit Issue D): the plugin is still invoked, but from
/// Rust and only for vetted destinations, so the webview has no arbitrary
/// outbound-egress primitive.
/// Exact-match allowlist check. Pulled out of the command so it is unit-testable
/// without an `AppHandle`. Full-string equality (not prefix/substring), so
/// `https://evil/?s=<seed>` or `https://sovright.com.evil/` are rejected.
fn is_allowed_external_url(url: &str) -> bool {
    ALLOWED_EXTERNAL_URLS.contains(&url)
}

#[tauri::command]
pub fn open_external_url(app: AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    if !is_allowed_external_url(&url) {
        return Err(format!("refusing to open non-allowlisted URL: {url}"));
    }

    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|err| err.to_string())
}

#[derive(Serialize)]
pub struct TosStatus {
    pub accepted: bool,
    pub version: String,
    pub text: String,
}

/// Base directory for the TOS acceptance record: the app data dir root, so it
/// survives "Delete workspace" (which only removes the `workspace` subdir).
fn tos_base_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|err| format!("resolving app data dir: {err}"))
}

/// Whether the current Terms of Service version has been accepted, plus the
/// version and full text for the acceptance gate to render.
#[tauri::command]
pub fn tos_status(app: AppHandle) -> Result<TosStatus, String> {
    let base = tos_base_dir(&app)?;
    Ok(TosStatus {
        accepted: argos_core::is_tos_accepted(&base),
        version: argos_core::TOS_VERSION.to_owned(),
        text: argos_core::terms_text().to_owned(),
    })
}

/// Record acceptance of the current Terms of Service version.
#[tauri::command]
pub fn accept_tos(app: AppHandle) -> Result<(), String> {
    let base = tos_base_dir(&app)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    argos_core::record_tos_acceptance(&base, now).map_err(|err| err.to_string())
}

/// Reject the Terms of Service: nothing is recorded and the app exits.
#[tauri::command]
pub fn reject_tos(app: AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub async fn estimate_birthday_from_date(
    app: AppHandle,
    date: String,
    lightwalletd_url: String,
) -> Result<u32, String> {
    ensure_tos_accepted(&app)?;
    estimate_birthday(&date, &lightwalletd_url)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn detect_birthday(
    app: AppHandle,
    // `SecretString`, not `String`: the seed must not cross the Tauri boundary
    // as a plain string that could be debug-printed or logged (audit Issue A).
    seed: SecretString,
    lightwalletd_url: String,
    network: ZeckNetwork,
) -> Result<BirthdayDetectResult, String> {
    ensure_tos_accepted(&app)?;
    let seed_phrase = seed;
    let app_clone = app.clone();
    zeck_detect_birthday(
        &seed_phrase,
        network,
        &lightwalletd_url,
        move |msg: &str| {
            let _ = app_clone.emit("birthday-probe-progress", msg.to_owned());
        },
    )
    .await
    .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn save_recovery_report(
    state: State<'_, AppState>,
    handle: ScanHandle,
    path: String,
    report: String,
) -> Result<String, String> {
    let progress = state
        .service
        .get_scan_progress(&handle)
        .await
        .map_err(|err| err.to_string())?;
    let workspace_dir = progress
        .summary
        .as_ref()
        .map(|summary| PathBuf::from(&summary.workspace_dir))
        .ok_or_else(|| "recovery report can only be saved after workspace sync".to_owned())?;
    let path = resolve_report_path(&workspace_dir, path.trim())?;

    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err("report path must not be a symlink".to_owned());
        }
        if !metadata.is_file() {
            return Err("report path must refer to a regular file".to_owned());
        }
    }

    write_private_report(&path, report.as_bytes())
        .map_err(|err| format!("writing {}: {err}", path.display()))?;
    Ok(path.display().to_string())
}

/// Write `contents` to `path` with owner-only (`0o600`) permissions on Unix.
///
/// `OpenOptions::mode` only constrains the bits of a *newly created* file, and
/// the caller deliberately permits writing into an existing regular file (which
/// with `truncate` would retain its prior, looser mode). So this both creates
/// at `0o600` AND re-tightens after the write, ensuring a reused report path is
/// protected too (audit Suggestion 3). Windows has no mode bits; there it is a
/// plain create+truncate write. The caller owns the symlink/regular-file guard.
fn write_private_report(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Recursive-delete the on-disk recovery workspace for a completed scan.
/// Backs the "Delete workspace" affordance described in T-L3 of the threat
/// model. Not a cryptographic wipe — see RecoveryService::delete_workspace
/// for the caveat. The UI is responsible for surfacing that honestly.
#[tauri::command]
pub async fn delete_workspace(
    state: State<'_, AppState>,
    handle: ScanHandle,
) -> Result<String, String> {
    let deleted = state
        .service
        .delete_workspace(&handle)
        .await
        .map_err(|err| err.to_string())?;
    Ok(deleted.display().to_string())
}

fn resolve_report_path(workspace_dir: &Path, requested: &str) -> Result<PathBuf, String> {
    if requested.is_empty() {
        return Err("report path cannot be empty".to_owned());
    }

    let requested = PathBuf::from(requested);
    if requested
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("report path must stay inside the recovery workspace".to_owned());
    }

    let workspace_root = fs::canonicalize(workspace_dir).map_err(|err| {
        format!(
            "opening recovery workspace {}: {err}",
            workspace_dir.display()
        )
    })?;
    let candidate = if requested.is_absolute() {
        requested
    } else {
        workspace_root.join(requested)
    };
    let parent = candidate
        .parent()
        .ok_or_else(|| "report path must include a file name".to_owned())?;

    // Auto-create relative subdirectories under the workspace, but never blindly
    // mkdir for absolute user-supplied paths — those must already exist so the
    // canonicalize-and-prefix-check below can guard against escapes.
    if !parent.exists() && parent.starts_with(&workspace_root) {
        fs::create_dir_all(parent)
            .map_err(|err| format!("creating {}: {err}", parent.display()))?;
    }

    let canonical_parent = fs::canonicalize(parent)
        .map_err(|err| format!("report directory must be inside the workspace: {err}"))?;
    if !canonical_parent.starts_with(&workspace_root) {
        return Err("report path must stay inside the recovery workspace".to_owned());
    }
    let file_name = candidate
        .file_name()
        .filter(|file_name| !file_name.is_empty())
        .ok_or_else(|| "report path must include a file name".to_owned())?;

    Ok(canonical_parent.join(file_name))
}

/// Best-effort OS-level notification used when a long scan finishes. Mirrors
/// the CLI implementation: shells out to platform tools so we don't pull in a
/// new Tauri plugin or Rust dependency. Errors are swallowed because the
/// notification is convenience, not a guarantee.
#[tauri::command]
pub async fn notify_user(title: String, body: String) -> Result<(), String> {
    if title.trim().is_empty() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification {body} with title {title}",
            title = applescript_quote(&title),
            body = applescript_quote(&body),
        );
        let _ = Command::new("osascript").arg("-e").arg(script).status();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send").arg(&title).arg(&body).status();
    }

    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms;\
             $n=[System.Windows.Forms.NotifyIcon]::new();\
             $n.Icon=[System.Drawing.SystemIcons]::Information;\
             $n.Visible=$true;\
             $n.ShowBalloonTip(5000,{title},{body},0);\
             Start-Sleep 2;\
             $n.Dispose()",
            title = powershell_quote(&title),
            body = powershell_quote(&body),
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status();
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (title, body);
    }

    Ok(())
}

/// Frontend-facing row for an incomplete scan workspace. Mirrors
/// `IncompleteSession` with the path serialized as a string so it
/// round-trips through Tauri without needing PathBuf serde wiring.
#[derive(Debug, Clone, Serialize)]
pub struct SessionRow {
    pub workspace_path: String,
    pub label: String,
    pub network: ZeckNetwork,
    pub birthday: u32,
    pub synced_to_height: Option<u32>,
    pub target_height: Option<u32>,
    pub last_run_at_epoch_seconds: Option<i64>,
}

impl From<IncompleteSession> for SessionRow {
    fn from(s: IncompleteSession) -> Self {
        Self {
            workspace_path: s.workspace_path.display().to_string(),
            label: s.label,
            network: s.network,
            birthday: s.birthday,
            synced_to_height: s.synced_to_height,
            target_height: s.target_height,
            last_run_at_epoch_seconds: s.last_run_at_epoch_seconds,
        }
    }
}

/// List any workspaces under `data_dir` that have an incomplete or missing
/// session sidecar. Called on GUI launch so the user can pick up where
/// they left off without re-entering all their scan parameters.
#[tauri::command]
pub async fn list_incomplete_sessions(
    app: AppHandle,
    data_dir: Option<String>,
) -> Result<Vec<SessionRow>, String> {
    let resolved = match data_dir {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => {
            let base = app
                .path()
                .app_data_dir()
                .map_err(|err| format!("resolving app data dir: {err}"))?;
            base.join("workspace")
        }
    };
    let rows = zeck_list_incomplete_sessions(&resolved)
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(SessionRow::from)
        .collect();
    Ok(rows)
}

// No `Debug`/`Clone`: carries the cleartext seed (see `ScanConfigInput`). The
// `SecretString` seed field redacts and zeroizes once parsed (audit Issue A).
#[derive(Deserialize)]
pub struct ResumeSessionInput {
    pub workspace_path: String,
    pub seed: SecretString,
    pub lightwalletd_url: String,
    /// If supplied (non-empty after trimming), overwrites the existing
    /// label in the sidecar at resume time. Mostly useful when resuming a
    /// legacy "(unlabeled scan)" workspace.
    pub label: Option<String>,
}

/// Resume an incomplete scan: verify the seed matches the workspace, then
/// hand off to the existing scan entry point with parameters reconstructed
/// from the workspace path. The data dir for `ScanConfig` is inferred from
/// the workspace path's keying segments so the same `RecoveryWorkspace`
/// resolves and the existing resume logic in `scan.rs` picks up where the
/// previous run left off.
#[tauri::command]
pub async fn resume_session(
    app: AppHandle,
    state: State<'_, AppState>,
    input: ResumeSessionInput,
) -> Result<ScanHandle, String> {
    ensure_tos_accepted(&app)?;
    let workspace_path = PathBuf::from(input.workspace_path.trim());
    if workspace_path.as_os_str().is_empty() {
        return Err("workspace path cannot be empty".to_owned());
    }
    let seed_phrase = input.seed;

    verify_seed_for_workspace(&workspace_path, &seed_phrase).map_err(|err| err.to_string())?;
    let keying = parse_workspace_keying(&workspace_path).map_err(|err| err.to_string())?;
    let data_dir = data_dir_from_workspace(&workspace_path)
        .ok_or_else(|| "workspace path is not under a recognizable data dir".to_owned())?;

    let label = input
        .label
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    let handle = state
        .service
        .start_scan(
            ScanConfig {
                birthday: keying.birthday,
                num_accounts: keying.num_accounts,
                gap_limit: keying.gap_limit,
                lightwalletd_url: input.lightwalletd_url,
                data_dir,
                network: keying.network,
                label,
            },
            seed_phrase,
        )
        .await
        .map_err(|err| err.to_string())?;

    spawn_scan_progress_pump(app, state.service.clone(), handle.clone());
    Ok(handle)
}

/// Strip the four keying segments (`<network>/<fp>/birthday-N/<scope>`)
/// from `workspace_path` to recover the original data dir.
fn data_dir_from_workspace(workspace_path: &Path) -> Option<PathBuf> {
    let mut p = workspace_path.to_path_buf();
    for _ in 0..4 {
        if !p.pop() {
            return None;
        }
    }
    Some(p)
}

#[cfg(target_os = "windows")]
fn powershell_quote(input: &str) -> String {
    let escaped: String = input
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| {
            if c == '\'' {
                "''".to_string()
            } else {
                c.to_string()
            }
        })
        .collect();
    format!("'{escaped}'")
}

#[cfg(target_os = "macos")]
fn applescript_quote(input: &str) -> String {
    let escaped: String = input
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '\\' => "\\\\".to_string(),
            '"' => "\\\"".to_string(),
            other => other.to_string(),
        })
        .collect();
    format!("\"{escaped}\"")
}

fn parse_zec_to_zatoshis(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("max fee cannot be empty".to_owned());
    }

    let (whole, fractional) = match trimmed.split_once('.') {
        Some((whole, fractional)) => (whole, fractional),
        None => (trimmed, ""),
    };

    if fractional.len() > 8 {
        return Err("max fee supports at most 8 decimal places".to_owned());
    }

    let whole_part = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u64>()
            .map_err(|_| "invalid whole ZEC amount".to_owned())?
    };

    let fractional_digits = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<u64>()
            .map_err(|_| "invalid fractional ZEC amount".to_owned())?
    };

    let scale = 10u64.pow((8usize.saturating_sub(fractional.len())) as u32);
    whole_part
        .checked_mul(100_000_000)
        .and_then(|whole_zats| whole_zats.checked_add(fractional_digits.checked_mul(scale)?))
        .ok_or_else(|| "max fee is too large".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sidebar version is a support-facing claim about which binary is
    /// running, so it must be a real, non-empty version rather than a
    /// placeholder that silently ships as "0.0.0" or "".
    #[test]
    fn app_version_reports_the_compiled_package_version() {
        let reported = app_version();
        assert_eq!(reported, env!("CARGO_PKG_VERSION"));
        assert!(!reported.is_empty(), "version must not be empty");
        assert!(
            reported.split('.').count() >= 3,
            "expected a semver-shaped version, got {reported:?}"
        );
        assert_ne!(reported, "0.0.0", "version must not be a placeholder");
    }

    fn temp_workspace() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("argos-report-path-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&path).expect("temp workspace should be created");
        path
    }

    #[test]
    fn report_path_resolves_inside_workspace() {
        let workspace = temp_workspace();
        let path = resolve_report_path(&workspace, "argos-recovery-report.txt")
            .expect("report path should resolve");

        assert!(path.starts_with(fs::canonicalize(&workspace).expect("canonical workspace")));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("argos-recovery-report.txt")
        );

        fs::remove_dir_all(workspace).expect("temp workspace should be removed");
    }

    #[test]
    fn report_path_rejects_parent_traversal() {
        let workspace = temp_workspace();
        let err = resolve_report_path(&workspace, "../outside.txt")
            .expect_err("parent traversal should be rejected");

        assert!(err.contains("inside the recovery workspace"));

        fs::remove_dir_all(workspace).expect("temp workspace should be removed");
    }

    #[test]
    fn report_path_auto_creates_subdir_inside_workspace() {
        let workspace = temp_workspace();
        let path = resolve_report_path(&workspace, "reports/argos-recovery-report.txt")
            .expect("subdir should be auto-created");

        let canonical_workspace = fs::canonicalize(&workspace).expect("canonical workspace");
        assert!(path.starts_with(&canonical_workspace));
        assert!(path.parent().expect("parent").exists());

        fs::remove_dir_all(workspace).expect("temp workspace should be removed");
    }

    #[test]
    fn report_path_accepts_absolute_path_inside_workspace() {
        let workspace = temp_workspace();
        let canonical_workspace = fs::canonicalize(&workspace).expect("canonical workspace");
        let absolute = canonical_workspace.join("argos-recovery-report.txt");

        let path = resolve_report_path(
            &workspace,
            absolute.to_str().expect("absolute path should be utf-8"),
        )
        .expect("absolute path inside workspace should resolve");

        assert_eq!(path, absolute);

        fs::remove_dir_all(workspace).expect("temp workspace should be removed");
    }

    #[test]
    fn report_path_rejects_absolute_path_outside_workspace() {
        let workspace = temp_workspace();
        let outside = std::env::temp_dir().join("argos-outside-report.txt");

        let err = resolve_report_path(
            &workspace,
            outside.to_str().expect("outside path should be utf-8"),
        )
        .expect_err("absolute path outside workspace should be rejected");

        // Either the parent canonicalization fails (parent missing) or the
        // prefix check fails — both are acceptable rejections.
        assert!(
            err.contains("inside the recovery workspace")
                || err.contains("must be inside the workspace")
        );

        fs::remove_dir_all(workspace).expect("temp workspace should be removed");
    }

    #[test]
    fn one_zatoshi() {
        assert_eq!(parse_zec_to_zatoshis("0.00000001").unwrap(), 1);
    }

    #[test]
    fn whole_zec() {
        assert_eq!(parse_zec_to_zatoshis("1").unwrap(), 100_000_000);
    }

    #[test]
    fn mixed() {
        assert_eq!(parse_zec_to_zatoshis("0.0002").unwrap(), 20_000);
    }

    #[test]
    fn leading_dot() {
        assert_eq!(parse_zec_to_zatoshis(".5").unwrap(), 50_000_000);
    }

    #[test]
    fn too_many_decimals_rejected() {
        assert!(parse_zec_to_zatoshis("0.999999999").is_err());
    }

    #[test]
    fn negative_rejected() {
        assert!(parse_zec_to_zatoshis("-0.001").is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(parse_zec_to_zatoshis("").is_err());
    }

    #[test]
    fn non_numeric_rejected() {
        assert!(parse_zec_to_zatoshis("abc").is_err());
    }

    #[test]
    fn overflow_rejected() {
        assert!(parse_zec_to_zatoshis("99999999999999999999").is_err());
    }

    #[test]
    fn sensitive_commands_fail_closed_before_tos_acceptance() {
        let dir =
            std::env::temp_dir().join(format!("argos-gui-tos-unaccepted-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let err = ensure_tos_accepted_for_base(&dir)
            .expect_err("unaccepted TOS should block sensitive commands");
        assert!(err.contains("Terms of Service"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_quote_simple() {
        assert_eq!(applescript_quote("hello"), "\"hello\"");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_quote_escapes_double_quote() {
        assert_eq!(applescript_quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_quote_escapes_backslash() {
        assert_eq!(applescript_quote("C:\\path"), "\"C:\\\\path\"");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_quote_strips_control_chars() {
        assert_eq!(applescript_quote("abc\x00def"), "\"abcdef\"");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_report_tightens_a_reused_file_to_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("argos-report-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("recovery-report.txt");
        // Simulate a pre-existing, world-readable report file at the target path.
        std::fs::write(&path, b"stale").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen");

        super::write_private_report(&path, b"fresh").expect("write report");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a reused report file must be re-tightened to 0o600"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"fresh");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn external_url_allowlist_accepts_listed_and_rejects_everything_else() {
        use super::is_allowed_external_url;
        // Every allowlisted URL is accepted.
        for url in super::ALLOWED_EXTERNAL_URLS {
            assert!(is_allowed_external_url(url), "{url} should be allowed");
        }
        // Exfiltration and look-alike attempts are rejected (exact match, not prefix/substring).
        assert!(!is_allowed_external_url(
            "https://evil.example/?s=secret-seed"
        ));
        assert!(!is_allowed_external_url(
            "https://sovright.com.evil.example/"
        ));
        assert!(!is_allowed_external_url("https://sovright.com/extra"));
        assert!(!is_allowed_external_url("file:///etc/passwd"));
        assert!(!is_allowed_external_url("javascript:alert(1)"));
        assert!(!is_allowed_external_url(""));
    }

    // Fail-closed sync guard: every external http(s)/mailto link in the shipped
    // HTML must be on the allowlist, or the UI link silently breaks (audit Issue
    // D). This catches a maintainer adding a link without updating the allowlist.
    #[test]
    fn every_html_external_link_is_allowlisted() {
        let html =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/index.html"))
                .expect("read index.html");
        for (idx, _) in html.match_indices("href=\"") {
            let rest = &html[idx + 6..];
            let end = rest.find('"').expect("closing quote");
            let href = &rest[..end];
            if href.starts_with("http://")
                || href.starts_with("https://")
                || href.starts_with("mailto:")
            {
                assert!(
                    super::is_allowed_external_url(href),
                    "external link {href} in index.html is not in ALLOWED_EXTERNAL_URLS"
                );
            }
        }
    }
}
