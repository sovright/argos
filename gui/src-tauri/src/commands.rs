#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;
use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::reviewed_intent::{WalletReviewId, WalletReviewRegistry};
use argos_core::{
    detect_birthday as zeck_detect_birthday, estimate_birthday_from_date as estimate_birthday,
    list_incomplete_sessions as zeck_list_incomplete_sessions, parse_workspace_keying,
    validate_destination_address, validate_mnemonic_words, BirthdayDetectResult, IncompleteSession,
    RecoveryService, ReviewedSweepProposal, ScanConfig, ScanHandle, SweepOutcome, SweepProposalId,
    SweepRequest, ZeckNetwork,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

pub struct AppState {
    pub service: RecoveryService,
    pub address_search: argos_core::address_search::AddressSearchService,
    pub wallet_reviews: WalletReviewRegistry,
}

#[tauri::command]
pub fn release_wallet_review(
    review_id: WalletReviewId,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.wallet_reviews.release(&review_id)
}

#[derive(Deserialize)]
pub struct AddressSearchCandidateInput {
    pub label: String,
    pub seed: SecretString,
    #[serde(default)]
    pub passphrase: Option<SecretString>,
}

#[derive(Deserialize)]
pub struct AddressSearchInput {
    pub target: String,
    pub network: ZeckNetwork,
    pub seeds: Vec<AddressSearchCandidateInput>,
    pub profile: argos_core::address_search::SearchProfile,
    pub account_start: u32,
    pub account_count: u32,
    pub index_start: u32,
    pub index_count: u32,
    pub include_change: bool,
}

#[derive(Serialize)]
pub struct AddressSearchHandle {
    pub id: String,
}

#[tauri::command]
pub async fn start_address_search(
    state: State<'_, AppState>,
    input: AddressSearchInput,
) -> Result<AddressSearchHandle, String> {
    state
        .address_search
        .start(argos_core::address_search::SearchRequest {
            target: input.target,
            network: input.network,
            seeds: input
                .seeds
                .into_iter()
                .map(|candidate| argos_core::address_search::CandidateSeed {
                    label: candidate.label,
                    seed: candidate.seed,
                    passphrase: candidate
                        .passphrase
                        .unwrap_or_else(|| SecretString::new(String::new())),
                })
                .collect(),
            profile: input.profile,
            account_start: input.account_start,
            account_count: input.account_count,
            index_start: input.index_start,
            index_count: input.index_count,
            include_change: input.include_change,
        })
        .map(|id| AddressSearchHandle { id })
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn get_address_search(
    state: State<'_, AppState>,
    id: String,
) -> Result<argos_core::address_search::SearchSnapshot, String> {
    state
        .address_search
        .snapshot(&id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn cancel_address_search(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state
        .address_search
        .cancel(&id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn release_address_search(state: State<'_, AppState>, id: String) -> Result<(), String> {
    cancel_and_release_address_search(state.address_search.clone(), id).await;
    Ok(())
}

async fn cancel_and_release_address_search(
    search: argos_core::address_search::AddressSearchService,
    id: String,
) {
    let _ = search.cancel(&id);
    loop {
        match search.snapshot(&id) {
            Ok(snapshot)
                if matches!(
                    snapshot.status,
                    argos_core::address_search::SearchStatus::Running
                ) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Ok(_) => {
                let _ = search.release(&id);
                break;
            }
            Err(_) => break,
        }
    }
}

fn ensure_tos_accepted<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
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

/// Parse the optional confirmation sources. None are required: with the
/// defaults, confirmation rests on one operator and the sweep review says so.
/// The scan URLs are validated with them so a duplicate authority is refused.
fn parse_gui_confirmation_sources(
    scan_urls: &str,
    raw: &[String],
) -> Result<Vec<argos_core::ConfirmationEndpoint>, String> {
    let raw = raw.iter().map(String::as_str).collect::<Vec<_>>();
    let explicit = argos_core::lightwalletd::parse_confirmation_sources(&raw)
        .map_err(|err| err.to_string())?;
    argos_core::lightwalletd::confirmation_endpoints(scan_urls, &explicit)
        .map_err(|err| err.to_string())?;
    Ok(explicit)
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
    #[serde(default)]
    pub confirmation_sources: Vec<String>,
    pub data_dir: String,
    pub network: ZeckNetwork,
    #[serde(default = "argos_core::default_transparent_scan")]
    pub transparent_scan: Option<argos_core::TransparentScanConfig>,
    /// User-supplied label for the scan, written to the on-disk session
    /// sidecar so the launch-time "resume an unfinished scan" UI can show
    /// something more recognizable than a fingerprint suffix. Optional —
    /// empty/missing strings render as "(unlabeled scan)".
    #[serde(default)]
    pub label: Option<String>,
}

/// Scan settings for a matched-address handoff. Secret input is retained by
/// `AddressSearchService`, so there is intentionally no seed field here.
#[derive(Deserialize)]
pub struct MatchedScanConfigInput {
    pub birthday: u32,
    pub lightwalletd_url: String,
    #[serde(default)]
    pub confirmation_sources: Vec<String>,
    pub data_dir: String,
    pub network: ZeckNetwork,
    #[serde(default)]
    pub transparent_scan: Option<argos_core::TransparentScanConfig>,
    #[serde(default)]
    pub label: Option<String>,
    /// As on `WalletFileScanInput`. A matched-address sweep never sends a
    /// memo, so a non-blank one is always refused here.
    #[serde(default)]
    pub sweep_memo: Option<String>,
}

#[tauri::command]
pub async fn start_matched_recovery(
    app: AppHandle,
    state: State<'_, AppState>,
    search_id: String,
    match_id: String,
    config: MatchedScanConfigInput,
) -> Result<ScanHandle, String> {
    ensure_tos_accepted(&app)?;
    let confirmation_sources =
        parse_gui_confirmation_sources(&config.lightwalletd_url, &config.confirmation_sources)?;
    if config.transparent_scan.is_some() {
        return Err(
            "matched-address recovery cannot widen its transparent address range".to_owned(),
        );
    }
    let snapshot = state
        .address_search
        .snapshot(&search_id)
        .map_err(|err| err.to_string())?;
    if snapshot.network != config.network {
        return Err("matched-address recovery network differs from the search network".to_owned());
    }
    let (matched, seed) = state
        .address_search
        .matched_seed(&search_id, &match_id)
        .map_err(|err| err.to_string())?;
    let coordinates = argos_core::MatchCoordinates {
        pool: matched.pool,
        account: matched.account,
        scope: matched.scope,
        index: matched.index,
        network: snapshot.network,
        address: matched.address,
        path: matched.path,
    };
    let key_source =
        argos_core::prepare_match_recovery(seed.expose_secret(), config.network, coordinates)
            .map_err(|err| err.to_string())?;
    argos_core::refuse_memo_for_key_source(key_source.as_ref(), config.sweep_memo.as_deref())
        .map_err(|err| err.to_string())?;
    let handle = state
        .service
        .start_scan_from_key_source(
            ScanConfig {
                birthday: config.birthday,
                num_accounts: Some(1),
                gap_limit: 1,
                lightwalletd_url: config.lightwalletd_url,
                confirmation_sources,
                data_dir: PathBuf::from(config.data_dir),
                network: config.network,
                label: config.label.unwrap_or_default(),
                transparent_scan: None,
            },
            key_source,
        )
        .await
        .map_err(|err| err.to_string())?;
    // The search remains registered until explicit close/release. A result set
    // may contain multiple funded paths, and handing one capability to a scan
    // must not destroy the others. The frontend's close and beforeunload paths
    // call `release_address_search`, whose backend-owned cleanup waits for the
    // worker and then drops every retained matched seed.
    spawn_scan_progress_pump(app, state.service.clone(), handle.clone());
    Ok(handle)
}

#[tauri::command]
pub async fn validate_seed(words: Vec<SecretString>) -> Result<bool, String> {
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
    /// Opaque backend authority for the exact file object and bytes inspected.
    pub review_id: Option<WalletReviewId>,
    pub path: String,
    pub transparent_keys: usize,
    pub sapling_keys: usize,
    /// Count of retired Sprout key records recognized without recovering secrets.
    pub sprout_records: usize,
    pub sprout_notice: String,
    /// True when the file yielded a BIP-39 mnemonic, which means it re-enters
    /// the ordinary HD pipeline and scans and sweeps like a typed seed.
    pub has_mnemonic: bool,
    /// The "Seed phrase" line for a zcashd 5.x seed verified against its
    /// fingerprint and key chain, in the CLI's words. Its keys are read from
    /// the file individually, not derived. `None` when there is no such seed.
    pub seed_note: Option<String>,
    /// True when the file has no Sapling keys, so recovery goes down the
    /// transparent-only path (ZIP-316 gives it no UFVK to anchor an account).
    pub transparent_only: bool,
    /// Records the parser could not read. Surfaced because a wallet that
    /// silently drops records looks identical to one that had nothing.
    pub diagnostics: Vec<String>,
    /// Findings about the wallet's HD seed. Kept apart from `diagnostics`:
    /// they were read fine, and listing them as unread records is false.
    pub seed_diagnostics: Vec<String>,
    /// How much of the file this import covers, in the same words the CLI
    /// prints. `None` when every record that can hold a key was read.
    pub coverage_notice: Option<String>,
    /// True when the skipped records may hold funds (an unread key record or
    /// an unrecovered HD seed), so the notice must follow the user to the
    /// totals and the delete-workspace screen.
    pub coverage_may_hide_funds: bool,
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

#[tauri::command]
pub async fn inspect_wallet_file(
    state: State<'_, AppState>,
    path: String,
    passphrase: Option<SecretString>,
    network: Option<String>,
) -> Result<WalletFileSummary, String> {
    let network_name = network.unwrap_or_else(|| "mainnet".to_owned());
    let selected = parse_wallet_network(&network_name)?;
    let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path)
        .map_err(|err| format!("could not read {path}: {err}"))?;
    // Recovery runs only once the core importer has accepted the wallet's
    // embedded network; it is async (a saved scan is named offline), so it
    // follows the import rather than running inside its continuation.
    let keys = match import_gui_wallet_then(
        snapshot.bytes(),
        passphrase.as_ref(),
        selected,
        |keys| keys,
    ) {
        Ok(keys) => keys,
        // An encrypted wallet with a missing or wrong passphrase is an
        // ordinary user situation, not a failure to show raw. Matched on
        // the parser's typed error, which the core wrapper carries in
        // ZeckError::WalletFile, rather than on its message text: a
        // reworded message must not turn the passphrase prompt into a
        // raw error.
        Err(argos_core::ZeckError::WalletFile(
            argos_core::argos_wallet_import::ImportError::WrongPassphrase,
        )) => {
            return Ok(WalletFileSummary {
                review_id: None,
                path,
                transparent_keys: 0,
                sapling_keys: 0,
                sprout_records: 0,
                sprout_notice: String::new(),
                has_mnemonic: false,
                seed_note: None,
                transparent_only: false,
                diagnostics: Vec::new(),
                seed_diagnostics: Vec::new(),
                coverage_notice: None,
                coverage_may_hide_funds: false,
                needs_passphrase: true,
            });
        }
        Err(err) => return Err(err.to_string()),
    };
    let review_id = if keys.is_empty() {
        None
    } else {
        Some(state.wallet_reviews.register(
            PathBuf::from(&path),
            std::sync::Arc::new(snapshot.identity().clone()),
        )?)
    };

    Ok(wallet_summary_from_keys(path, review_id, keys))
}

/// Keep IPC coverage and diagnostics bound to the same parsed key set.
fn wallet_summary_from_keys(
    path: String,
    review_id: Option<WalletReviewId>,
    keys: argos_core::argos_wallet_import::ImportedKeys,
) -> WalletFileSummary {
    WalletFileSummary {
        review_id,
        path,
        transparent_keys: keys.transparent.len(),
        sapling_keys: keys.sapling.len(),
        sprout_records: keys.sprout_records,
        sprout_notice: if keys.sprout_records > 0 {
            argos_core::argos_wallet_import::keys::SPROUT_UNSPENDABLE_NOTICE.to_owned()
        } else {
            String::new()
        },
        has_mnemonic: keys.mnemonic.is_some(),
        seed_note: keys.verified_seed_note().map(str::to_owned),
        transparent_only: argos_core::key_source::classify_recovery_route(&keys)
            == argos_core::key_source::RecoveryRoute::TransparentOnly,
        diagnostics: keys
            .diagnostics
            .iter()
            .filter(|d| !d.is_about_seed())
            .map(|d| d.to_string())
            .collect(),
        seed_diagnostics: keys
            .diagnostics
            .iter()
            .filter(|d| d.is_about_seed())
            .map(|d| d.to_string())
            .collect(),
        coverage_notice: keys.coverage_notice(),
        coverage_may_hide_funds: keys.coverage().may_hide_funds(),
        needs_passphrase: false,
    }
}

// No `Debug`/`Serialize`/`Clone`, for the same reason as `ScanConfigInput`:
// this carries a wallet passphrase.
#[derive(Deserialize)]
pub struct WalletFileScanInput {
    /// Absent when the user supplied only typed Sapling keys — a key string
    /// is a key source in its own right, with no file behind it.
    #[serde(default)]
    pub review_id: Option<WalletReviewId>,
    pub passphrase: Option<SecretString>,
    /// Sapling spending keys typed or pasted in the GUI, one per entry.
    #[serde(default)]
    pub sapling_keys: Vec<SecretString>,
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
    pub lightwalletd_url: String,
    #[serde(default)]
    pub confirmation_sources: Vec<String>,
    pub data_dir: String,
    pub network: ZeckNetwork,
    #[serde(default = "argos_core::default_transparent_scan")]
    pub transparent_scan: Option<argos_core::TransparentScanConfig>,
    #[serde(default)]
    pub label: Option<String>,
    /// The memo the user entered for the sweep. Checked before the scan, so
    /// a memo this key source's sweep cannot send is refused now rather than
    /// after hours of scanning, from a screen that cannot edit it.
    #[serde(default)]
    pub sweep_memo: Option<String>,
    /// Where the sweep will pay. Checked before the scan for the same reason
    /// as the memo: the config screen has already collected it, and a
    /// destination the sweep cannot reach should not cost hours of scanning.
    pub destination: String,
}

/// Decode GUI key strings without ever collecting them into an ordinary
/// `Vec<String>`. The Tauri boundary owns each entry as `SecretString`; this
/// helper borrows it only long enough to decode into the zeroizing imported
/// key representation.
fn keys_from_secret_sapling_strings(
    lines: &[SecretString],
    network: ZeckNetwork,
) -> Result<argos_core::argos_wallet_import::ImportedKeys, String> {
    use argos_core::argos_wallet_import::{Provenance, SaplingKey};
    use secrecy::{ExposeSecret, Secret};

    let mut keys = argos_core::argos_wallet_import::ImportedKeys::default();
    for (index, line) in lines.iter().enumerate() {
        let line = line.expose_secret().trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let extsk = argos_core::sapling_key::decode_sapling_spending_key(line, network)
            .map_err(|err| format!("line {}: {err}", index + 1))?;
        let decoded = argos_core::argos_wallet_import::ImportedKeys {
            sapling: vec![SaplingKey {
                extsk: Secret::new(extsk.to_bytes().to_vec()),
                provenance: Provenance::Standalone,
                created_at: None,
            }],
            ..Default::default()
        };
        argos_core::sapling_key::merge_sapling_keys(&mut keys, decoded);
    }
    if keys.sapling.is_empty() {
        return Err(
            "no Sapling spending keys found — expected at least one `secret-extended-key-…` line"
                .to_owned(),
        );
    }
    Ok(keys)
}

/// Reconstruct exactly the source used by a wallet-file or pasted-key scan.
/// Both fresh scans and resumes use reviewed bytes, network validation,
/// and the same ordered merge before fingerprinting.
fn reviewed_wallet_scan_keys(
    reviews: &WalletReviewRegistry,
    review_id: Option<&WalletReviewId>,
    passphrase: Option<&SecretString>,
    sapling_keys: &[SecretString],
    network: ZeckNetwork,
) -> Result<(argos_core::argos_wallet_import::ImportedKeys, Vec<String>), String> {
    let mut keys = match review_id {
        Some(review_id) => {
            let (_, snapshot) = reviews.verify(review_id)?;
            argos_core::import_wallet_file_for_network(snapshot.bytes(), passphrase, network)
                .map_err(|err| err.to_string())?
        }
        None => argos_core::argos_wallet_import::ImportedKeys::default(),
    };
    let warnings = if keys.sprout_records > 0 {
        vec![argos_core::argos_wallet_import::keys::SPROUT_UNSPENDABLE_NOTICE.to_owned()]
    } else {
        Vec::new()
    };
    if !sapling_keys.is_empty() {
        let typed = keys_from_secret_sapling_strings(sapling_keys, network)?;
        argos_core::sapling_key::merge_standalone_sapling_keys(&mut keys, typed)
            .map_err(|err| err.to_string())?;
    }
    if keys.is_empty() {
        return Err(
            "no keys to scan — open a wallet file or paste a Sapling spending key.".to_owned(),
        );
    }
    Ok((keys, warnings))
}

/// Refuse, before the scan, a destination a seedless sweep cannot pay.
///
/// With a mnemonic, transparent keys may overlap HD receivers discovered
/// during the scan. The core sweep checks the resulting direct leg after
/// that discovery; preflight only decides seedless sources exactly.
fn refuse_unreachable_sweep_destination(
    keys: &argos_core::argos_wallet_import::ImportedKeys,
    destination: &str,
    network: ZeckNetwork,
) -> Result<(), String> {
    if keys.mnemonic.is_some() {
        return Ok(());
    }
    argos_core::transparent_recovery::refuse_destination_the_transparent_leg_cannot_reach(
        keys,
        destination,
        network,
    )
    .map_err(|err| err.to_string())
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
    let confirmation_sources =
        parse_gui_confirmation_sources(&config.lightwalletd_url, &config.confirmation_sources)?;

    // Either source alone is enough, and both together are meaningful: a
    // user may hold a wallet whose keys were never rescanned *and* a paper
    // key for an address it never knew about. Mirrors the CLI's
    // `--wallet-file` + `--sapling-key-file` combination.
    let (keys, warnings) = reviewed_wallet_scan_keys(
        &state.wallet_reviews,
        config.review_id.as_ref(),
        config.passphrase.as_ref(),
        &config.sapling_keys,
        config.network,
    )?;
    for warning in warnings {
        let _ = app.emit("wallet-import-warning", warning);
    }

    // Before the scan, so the check runs on the parsed keys while their
    // mnemonic is still visible.
    refuse_unreachable_sweep_destination(&keys, &config.destination, config.network)?;

    let key_source: Arc<dyn argos_core::KeySource> =
        Arc::new(argos_core::ImportedKeySource::new(keys));
    argos_core::refuse_memo_for_key_source(key_source.as_ref(), config.sweep_memo.as_deref())
        .map_err(|err| err.to_string())?;

    let handle = state
        .service
        .start_scan_from_key_source(
            ScanConfig {
                birthday: config.birthday,
                num_accounts: config.num_accounts,
                gap_limit: config.gap_limit,
                lightwalletd_url: config.lightwalletd_url,
                confirmation_sources,
                data_dir: PathBuf::from(config.data_dir),
                network: config.network,
                label: config.label.unwrap_or_default(),
                transparent_scan: config.transparent_scan,
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
    let confirmation_sources =
        parse_gui_confirmation_sources(&config.lightwalletd_url, &config.confirmation_sources)?;
    let handle = state
        .service
        .start_scan(
            ScanConfig {
                birthday: config.birthday,
                num_accounts: config.num_accounts,
                gap_limit: config.gap_limit,
                lightwalletd_url: config.lightwalletd_url,
                confirmation_sources,
                data_dir: PathBuf::from(config.data_dir),
                network: config.network,
                label: config.label.unwrap_or_default(),
                transparent_scan: config.transparent_scan,
            },
            config.seed,
        )
        .await
        .map_err(|err| err.to_string())?;

    spawn_scan_progress_pump(app, state.service.clone(), handle.clone());

    Ok(handle)
}

#[derive(Clone, Serialize)]
struct ScanDiscoveryEvent {
    handle: ScanHandle,
    discovery: argos_core::ScanDiscovery,
}

/// Forward `scan-progress` / `scan-discovery` / `scan-complete` events to
/// the frontend while a scan is running. Identical for fresh scans and
/// resumed scans, so it's factored out.
fn spawn_scan_progress_pump<R: tauri::Runtime>(
    app: AppHandle<R>,
    service: RecoveryService,
    handle: ScanHandle,
) {
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
                    let _ = app.emit(
                        "scan-discovery",
                        ScanDiscoveryEvent {
                            handle: handle.clone(),
                            discovery: discovery.clone(),
                        },
                    );
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

/// Release all in-memory authority for a recovery scan. Unlike cancellation,
/// this also removes completed sessions and waits for any running worker to
/// stop before the final key owner is dropped.
#[tauri::command]
pub async fn release_scan(state: State<'_, AppState>, handle: ScanHandle) -> Result<(), String> {
    state
        .service
        .release_scan(&handle)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn reconcile_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    handle: ScanHandle,
) -> Result<Vec<argos_core::reconciliation::ReconciledTransaction>, String> {
    ensure_tos_accepted(&app)?;
    state
        .service
        .reconcile_sweep(&handle)
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn retry_unknown_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    handle: ScanHandle,
    txid: String,
) -> Result<argos_core::reconciliation::ReconciledTransaction, String> {
    ensure_tos_accepted(&app)?;
    state
        .service
        .retry_unknown_sweep(&handle, &txid)
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
) -> Result<ReviewedSweepProposal, String> {
    ensure_tos_accepted(&app)?;
    let max_fee_zatoshis = max_fee_zec
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_zec_to_zatoshis)
        .transpose()?;

    // Observe every durable transaction first. A previously accepted sweep
    // may now have canonical mining evidence, but only a fresh proposal can
    // quote the remaining funds after that transition.
    state
        .service
        .reconcile_sweep(&handle)
        .await
        .map_err(|err| err.to_string())?;

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
pub async fn execute_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    handle: ScanHandle,
    proposal_id: SweepProposalId,
) -> Result<SweepOutcome, String> {
    ensure_tos_accepted(&app)?;

    // `execute_sweep` returns an `Err` only when nothing was broadcast. A
    // mid-sequence abort *after* one or more broadcasts comes back as an `Ok`
    // outcome carrying the partial records plus `error`, so the records of
    // funds already on-chain are never lost to the frontend (audit Issue E).
    let outcome = state
        .service
        .execute_sweep(&handle, &proposal_id)
        .await
        .map_err(|err| err.to_string())?;

    for result in &outcome.transactions {
        for event_name in sweep_event_names(result.status) {
            let _ = app.emit(event_name, result);
        }
    }

    Ok(outcome)
}

fn sweep_event_names(status: argos_core::TxLifecycleState) -> &'static [&'static str] {
    use argos_core::TxLifecycleState as State;
    match status {
        State::NotSubmitted | State::SubmissionUnknown | State::Rejected => &["sweep-tx-result"],
        // One operator's mining report is not independent confirmation.
        State::Pending | State::Expired | State::MinedSingleSource => {
            &["sweep-tx-result", "sweep-tx-broadcast"]
        }
        State::Mined => &[
            "sweep-tx-result",
            "sweep-tx-broadcast",
            "sweep-tx-confirmed",
        ],
    }
}

/// Validate a supported Sapling spending key without exposing its secret.
#[tauri::command]
pub async fn check_sapling_key(key: SecretString, network: String) -> Result<String, String> {
    use secrecy::ExposeSecret;

    let network = parse_wallet_network(&network)?;
    let extsk =
        argos_core::sapling_key::decode_sapling_spending_key(key.expose_secret().trim(), network)
            .map_err(|err| err.to_string())?;
    Ok(argos_core::sapling_key::default_sapling_address(
        &extsk, network,
    ))
}

/// The completion screen's summary, next steps, donation line, and status
/// labels, from the same rules the CLI prints. Stateless: the frontend calls
/// it again whenever a reconciliation changes a displayed row.
#[tauri::command]
pub fn sweep_completion_guidance(
    input: argos_core::sweep_guidance::CompletionGuidanceInput,
) -> argos_core::sweep_guidance::CompletionGuidance {
    argos_core::sweep_guidance::completion_guidance(&input)
}

fn parse_wallet_network(name: &str) -> Result<argos_core::ZeckNetwork, String> {
    match name {
        "mainnet" => Ok(argos_core::ZeckNetwork::Mainnet),
        "testnet" => Ok(argos_core::ZeckNetwork::Testnet),
        _ => Err("unrecognized wallet network; select mainnet or testnet".to_owned()),
    }
}

/// Run the command's recovery or address-encoding continuation only after
/// the shared core importer has accepted the wallet's embedded network.
fn import_gui_wallet_then<T>(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
    selected: argos_core::ZeckNetwork,
    next: impl FnOnce(argos_core::argos_wallet_import::ImportedKeys) -> T,
) -> argos_core::ZeckResult<T> {
    argos_core::import_wallet_file_for_network(bytes, passphrase, selected).map(next)
}

#[tauri::command]
pub fn default_data_dir(app: AppHandle) -> Result<String, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("resolving app data dir: {err}"))?;
    default_data_dir_for_base(&base).map(|dir| dir.display().to_string())
}

fn default_data_dir_for_base(base: &Path) -> Result<PathBuf, String> {
    argos_core::service::default_recovery_data_dir(
        &base.join("workspace"),
        &base.join("workspace-v2"),
    )
    .map_err(|err| err.to_string())
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
fn tos_base_dir<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
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

/// How a loaded wallet file is dated.
enum BirthdayRoute {
    /// The file yielded a mnemonic: probe its HD addresses on chain.
    Seed(SecretString),
    /// A seedless zcashd wallet.dat: date it from its key creation times.
    /// `pasted` counts the Sapling keys merged in from the paste box, which
    /// carry no time; the message names them rather than blame the file.
    WalletDat {
        keys: argos_core::argos_wallet_import::ImportedKeys,
        pasted: usize,
    },
}

/// Pick the route. A ZecWallet Lite file without its seed has nothing
/// dated, and reporting it as a wallet.dat whose keys zcashd left undated
/// would be wrong, so it keeps the refusal. The wording mirrors the CLI's.
fn birthday_route(
    keys: argos_core::argos_wallet_import::ImportedKeys,
    pasted: usize,
    format: argos_core::argos_wallet_import::WalletFormat,
) -> Result<BirthdayRoute, String> {
    if let Some(phrase) = keys.mnemonic {
        return Ok(BirthdayRoute::Seed(phrase));
    }
    match format {
        argos_core::argos_wallet_import::WalletFormat::Zcashd => {
            Ok(BirthdayRoute::WalletDat { keys, pasted })
        }
        argos_core::argos_wallet_import::WalletFormat::ZecwalletLite => Err(
            "Auto-detect needs a seed phrase to probe on chain, or a zcashd wallet.dat whose key \
             creation times date it, and this wallet file offers neither. Enter a block height \
             or a date instead."
                .to_owned(),
        ),
    }
}

/// Re-open a wallet file and choose how to date it, so a mnemonic stays in
/// the backend and never crosses IPC. Pasted Sapling keys are merged in as
/// the scan merges them: they carry no creation time, and leaving them out
/// would let the file's dated keys set a birthday later than theirs. Being
/// undated Sapling keys, they also rule out the transparent-UTXO fallback
/// (see `argos_core::birthday::needs_chain_fallback`), so a wallet with one
/// gets no birthday and Sapling is scanned from activation.
fn birthday_route_for_bytes(
    bytes: &[u8],
    passphrase: Option<&SecretString>,
    sapling_keys: &[SecretString],
    network: ZeckNetwork,
) -> Result<BirthdayRoute, String> {
    let format = argos_core::argos_wallet_import::sniff(bytes).map_err(|err| err.to_string())?;
    let keys = import_gui_wallet_then(bytes, passphrase, network, |keys| keys)
        .map_err(|err| err.to_string())?;
    birthday_route_for_keys(keys, format, sapling_keys, network)
}

/// `birthday_route_for_file` once the file is imported and bound to
/// `network`: merge any pasted Sapling keys and choose the route.
fn birthday_route_for_keys(
    mut keys: argos_core::argos_wallet_import::ImportedKeys,
    format: argos_core::argos_wallet_import::WalletFormat,
    sapling_keys: &[SecretString],
    network: ZeckNetwork,
) -> Result<BirthdayRoute, String> {
    let mut pasted = 0;
    if keys.mnemonic.is_none()
        && sapling_keys
            .iter()
            .any(|k| !secrecy::ExposeSecret::expose_secret(k).trim().is_empty())
    {
        let typed = keys_from_secret_sapling_strings(sapling_keys, network)?;
        pasted = argos_core::sapling_key::merge_standalone_sapling_keys(&mut keys, typed)
            .map_err(|err| err.to_string())?;
    }
    birthday_route(keys, pasted, format)
}

#[cfg(test)]
fn birthday_route_for_file(
    path: &str,
    passphrase: Option<&SecretString>,
    sapling_keys: &[SecretString],
    network: ZeckNetwork,
) -> Result<BirthdayRoute, String> {
    let bytes = argos_core::wallet_file::read_wallet_file(path)
        .map_err(|err| format!("could not read {path}: {err}"))?;
    birthday_route_for_bytes(&bytes, passphrase, sapling_keys, network)
}

/// Turn a wallet.dat birthday into what the birthday field shows. No height
/// is an error carrying the core's reason, so the field keeps its value
/// (which scans from the start of Sapling) rather than taking a guess.
fn wallet_dat_birthday_result(
    found: argos_core::WalletFileBirthday,
    network: ZeckNetwork,
) -> Result<BirthdayDetectResult, String> {
    let Some(height) = found.height else {
        return Err(found.message);
    };
    let (method, source) = match found.source {
        argos_core::WalletBirthdaySource::TransparentUtxos => (
            "transparent_utxos",
            "on-chain unspent outputs, so it may be later than the wallet's real age",
        ),
        argos_core::WalletBirthdaySource::WalletMetadata
        | argos_core::WalletBirthdaySource::None => {
            ("wallet_metadata", "the wallet file's key creation times")
        }
    };
    let date = match network {
        ZeckNetwork::Mainnet => format!(
            " (about {})",
            argos_core::estimate_date_from_height_offline(height)
        ),
        ZeckNetwork::Testnet => String::new(),
    };
    Ok(BirthdayDetectResult {
        birthday: height,
        method: method.to_owned(),
        message: format!("Block {height}{date}, from {source}. {}", found.message),
    })
}

/// Auto-detect the birthday of a loaded wallet file: by its mnemonic when
/// it has one, else by a wallet.dat's key creation times, falling back to
/// the earliest unspent output of its transparent keys.
#[tauri::command]
pub async fn detect_birthday_from_wallet_file(
    app: AppHandle,
    state: State<'_, AppState>,
    review_id: WalletReviewId,
    passphrase: Option<SecretString>,
    sapling_keys: Option<Vec<SecretString>>,
    lightwalletd_url: String,
    network: ZeckNetwork,
) -> Result<BirthdayDetectResult, String> {
    ensure_tos_accepted(&app)?;
    let (_, snapshot) = state.wallet_reviews.verify(&review_id)?;
    let route = birthday_route_for_bytes(
        snapshot.bytes(),
        passphrase.as_ref(),
        sapling_keys.as_deref().unwrap_or_default(),
        network,
    )?;
    let app_clone = app.clone();
    let progress = move |msg: &str| {
        let _ = app_clone.emit("birthday-probe-progress", msg.to_owned());
    };
    match route {
        BirthdayRoute::Seed(seed_phrase) => {
            zeck_detect_birthday(&seed_phrase, network, &lightwalletd_url, progress)
                .await
                .map_err(|err| err.to_string())
        }
        BirthdayRoute::WalletDat { keys, pasted } => {
            let found = argos_core::detect_wallet_file_birthday(
                &keys,
                network,
                pasted,
                argos_core::unix_time_now(),
                Some(&lightwalletd_url),
                progress,
            )
            .await;
            wallet_dat_birthday_result(found, network)
        }
    }
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
    let authority = argos_core::workspace::PrivateWorkspaceFileAuthority::acquire(&workspace_dir)
        .map_err(|err| err.to_string())?;
    let path = resolve_report_path(&workspace_dir, path.trim())?;
    authority
        .write_private_file(&path, report.as_bytes())
        .map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
}

/// Write `contents` to `path` only when it can be created privately or an
/// existing target already satisfies the platform's exact private policy.
/// Reused permissive files are preserved and refused rather than repaired in
/// place after their old readers may already have retained access.
#[cfg(test)]
fn write_private_report(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    argos_core::private_fs::write_private_file(path, contents)
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
        argos_core::private_fs::create_private_dir_all(parent)
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
    pub match_coordinates: Option<argos_core::MatchCoordinates>,
    pub transparent_scan: Option<argos_core::TransparentScanConfig>,
    pub requires_rescan: bool,
    pub legacy_untrusted: bool,
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
            match_coordinates: s.match_coordinates,
            transparent_scan: s.transparent_scan,
            requires_rescan: s.requires_rescan,
            legacy_untrusted: s.legacy_untrusted,
        }
    }
}

/// List resumable incomplete workspaces and preserved legacy workspaces that
/// require a fresh scan. Called on GUI launch so the user gets explicit,
/// non-resumable remediation guidance for untrusted storage.
#[tauri::command]
pub async fn list_incomplete_sessions(
    app: AppHandle,
    data_dir: Option<String>,
) -> Result<Vec<SessionRow>, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("resolving app data dir: {err}"))?;
    sessions_for_data_dir(&base, data_dir.as_deref())
}

fn sessions_for_data_dir(base: &Path, data_dir: Option<&str>) -> Result<Vec<SessionRow>, String> {
    let resolved = match data_dir.map(str::trim).filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => default_data_dir_for_base(base)?,
    };
    let mut sessions = zeck_list_incomplete_sessions(&resolved).map_err(|err| err.to_string())?;
    if resolved == base.join("workspace-v2") {
        // The upgraded default must not hide the preserved legacy evidence.
        // Legacy rows contain only path-derived, non-resumable guidance.
        sessions.extend(
            zeck_list_incomplete_sessions(&base.join("workspace"))
                .map_err(|err| err.to_string())?
                .into_iter()
                .filter(|row| row.legacy_untrusted),
        );
    }
    let rows = sessions.into_iter().map(SessionRow::from).collect();
    Ok(rows)
}

// No `Debug`/`Clone`: carries the cleartext seed (see `ScanConfigInput`). The
// `SecretString` seed field redacts and zeroizes once parsed (audit Issue A).
#[derive(Deserialize)]
pub struct ResumeSessionInput {
    pub workspace_path: String,
    /// Required at this boundary so older callers cannot bypass preflight.
    pub destination: String,
    #[serde(default)]
    pub sweep_memo: Option<String>,
    #[serde(default)]
    pub seed: Option<SecretString>,
    #[serde(default)]
    pub passphrase: Option<SecretString>,
    #[serde(default)]
    pub wallet_review_id: Option<WalletReviewId>,
    #[serde(default)]
    pub wallet_passphrase: Option<SecretString>,
    #[serde(default)]
    pub sapling_keys: Vec<SecretString>,
    pub lightwalletd_url: String,
    #[serde(default)]
    pub confirmation_sources: Vec<String>,
    /// If supplied (non-empty after trimming), overwrites the existing
    /// label in the sidecar at resume time. Mostly useful when resuming a
    /// legacy "(unlabeled scan)" workspace.
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct ResumeSessionResult {
    pub handle: ScanHandle,
    pub network: ZeckNetwork,
    pub data_dir: String,
    pub lightwalletd_url: String,
    pub confirmation_sources: Vec<String>,
}

/// No filesystem writes or service calls: authenticate the supplied authority
/// against the selected workspace before a scan can create or alter anything.
fn prepare_resume_key_source(
    input: &ResumeSessionInput,
    reviews: &WalletReviewRegistry,
    workspace_path: &Path,
    network: ZeckNetwork,
    coordinates: Option<argos_core::MatchCoordinates>,
) -> Result<(std::sync::Arc<dyn argos_core::KeySource>, Vec<String>), String> {
    use std::sync::Arc;

    let imported = input.wallet_review_id.is_some() || !input.sapling_keys.is_empty();
    if input.seed.is_some() && imported {
        return Err("choose either the original seed phrase or the original wallet file / Sapling keys, not both".to_owned());
    }
    if input.wallet_passphrase.is_some() && input.wallet_review_id.is_none() {
        return Err("a wallet-file password requires a reviewed wallet file".to_owned());
    }
    let (source, warnings): (Arc<dyn argos_core::KeySource>, Vec<String>) = if let Some(
        seed_phrase,
    ) = &input.seed
    {
        let source: Arc<dyn argos_core::KeySource> = if let Some(coordinates) = coordinates {
            let empty = SecretString::new(String::new());
            let passphrase = input.passphrase.as_ref().unwrap_or(&empty);
            let seed = argos_core::address_search::candidate_seed(seed_phrase, passphrase)
                .map_err(|err| err.to_string())?;
            argos_core::prepare_match_recovery(seed.expose_secret(), network, coordinates)
                .map_err(|err| err.to_string())?
        } else {
            if input
                .passphrase
                .as_ref()
                .is_some_and(|p| !p.expose_secret().is_empty())
            {
                return Err("this scan was created without a BIP-39 passphrase".to_owned());
            }
            Arc::new(argos_core::SeedKeySource::new(seed_phrase.clone()))
        };
        (source, Vec::new())
    } else {
        if coordinates.is_some() {
            return Err(
                "this address-match scan requires its original seed phrase and BIP-39 passphrase"
                    .to_owned(),
            );
        }
        if input
            .passphrase
            .as_ref()
            .is_some_and(|p| !p.expose_secret().is_empty())
        {
            return Err("a BIP-39 passphrase requires a seed phrase; use the wallet-file password for an encrypted file".to_owned());
        }
        let (keys, warnings) = reviewed_wallet_scan_keys(
            reviews,
            input.wallet_review_id.as_ref(),
            input.wallet_passphrase.as_ref(),
            &input.sapling_keys,
            network,
        )?;
        (Arc::new(argos_core::ImportedKeySource::new(keys)), warnings)
    };
    argos_core::workspace::verify_key_source_for_workspace(workspace_path, source.as_ref())
        .map_err(|err| err.to_string())?;
    if let Some(keys) = source.imported_keys() {
        refuse_unreachable_sweep_destination(keys, &input.destination, network)?;
    }
    argos_core::refuse_memo_for_key_source(source.as_ref(), input.sweep_memo.as_deref())
        .map_err(|err| err.to_string())?;
    Ok((source, warnings))
}

/// Resume an incomplete scan: verify the recovery source matches the workspace, then
/// hand off to the existing scan entry point with parameters reconstructed
/// from the workspace path. The data dir for `ScanConfig` is inferred from
/// the workspace path's keying segments so the same `RecoveryWorkspace`
/// resolves and the existing resume logic in `scan.rs` picks up where the
/// previous run left off.
#[tauri::command]
pub async fn resume_session<R: tauri::Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    input: ResumeSessionInput,
) -> Result<ResumeSessionResult, String> {
    ensure_tos_accepted(&app)?;
    let confirmation_sources =
        parse_gui_confirmation_sources(&input.lightwalletd_url, &input.confirmation_sources)?;
    let workspace_path = PathBuf::from(input.workspace_path.trim());
    if workspace_path.as_os_str().is_empty() {
        return Err("workspace path cannot be empty".to_owned());
    }
    let keying = parse_workspace_keying(&workspace_path).map_err(|err| err.to_string())?;
    let data_dir = data_dir_from_workspace(&workspace_path)
        .ok_or_else(|| "workspace path is not under a recognizable data dir".to_owned())?;

    let label = input
        .label
        .as_ref()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    let scan_config = ScanConfig {
        birthday: keying.birthday,
        num_accounts: keying.num_accounts,
        gap_limit: keying.gap_limit,
        lightwalletd_url: input.lightwalletd_url.clone(),
        confirmation_sources,
        data_dir: data_dir.clone(),
        network: keying.network,
        label,
        transparent_scan: keying.transparent_scan,
    };
    let metadata = argos_core::workspace::read_session_metadata(&workspace_path)
        .map_err(|err| err.to_string())?;
    let (key_source, warnings) = prepare_resume_key_source(
        &input,
        &state.wallet_reviews,
        &workspace_path,
        keying.network,
        metadata.and_then(|m| m.match_coordinates),
    )?;
    for warning in warnings {
        let _ = app.emit("wallet-import-warning", warning);
    }
    let handle = state
        .service
        .start_scan_from_key_source(scan_config, key_source)
        .await
        .map_err(|err| err.to_string())?;

    spawn_scan_progress_pump(app, state.service.clone(), handle.clone());
    Ok(ResumeSessionResult {
        handle,
        network: keying.network,
        data_dir: data_dir.to_string_lossy().into_owned(),
        lightwalletd_url: input.lightwalletd_url,
        confirmation_sources: input.confirmation_sources,
    })
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

#[cfg(any(target_os = "windows", test))]
fn powershell_quote(input: &str) -> String {
    // PowerShell ends a single-quoted string at ASCII `'` and at the
    // typographic quotes U+2018-U+201B; each is escaped by doubling it.
    // Server-controlled text reaches the notification body through scan
    // errors, so missing the typographic ones let it run code.
    let escaped: String = input
        .chars()
        .filter(|c| !c.is_control())
        .flat_map(|c| std::iter::once(c).chain(is_powershell_single_quote(c).then_some(c)))
        .collect();
    format!("'{escaped}'")
}

#[cfg(any(target_os = "windows", test))]
fn is_powershell_single_quote(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
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

    #[test]
    fn resume_wallet_input_does_not_require_a_seed_phrase() {
        let input = serde_json::from_value::<super::ResumeSessionInput>(serde_json::json!({
            "workspace_path": "/fixture/workspace",
            "wallet_review_id": "backend-issued-review",
            "destination": ORCHARD_SAPLING_UA,
            "lightwalletd_url": "https://fixture.invalid"
        }));
        assert!(
            input.is_ok(),
            "wallet-file resume must accept the original key source"
        );
    }

    const RESUME_SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn resume_input() -> super::ResumeSessionInput {
        serde_json::from_value(serde_json::json!({
            "workspace_path": "/fixture/workspace",
            "destination": ORCHARD_SAPLING_UA,
            "lightwalletd_url": "https://fixture.invalid"
        }))
        .unwrap()
    }

    fn resume_workspace(source: std::sync::Arc<dyn argos_core::KeySource>) -> std::path::PathBuf {
        resume_workspace_in_data_dir(source, unused_temp_dir("resume-no-mutations"))
    }

    fn resume_workspace_in_data_dir(
        source: std::sync::Arc<dyn argos_core::KeySource>,
        data_dir: std::path::PathBuf,
    ) -> std::path::PathBuf {
        let config = argos_core::RuntimeScanConfig {
            key_source: source,
            birthday: 419_200,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://fixture.invalid".into(),
            confirmation_sources: Vec::new(),
            data_dir,
            network: argos_core::ZeckNetwork::Mainnet,
            label: String::new(),
        };
        argos_core::workspace::RecoveryWorkspace::from_runtime(&config)
            .unwrap()
            .root()
            .to_owned()
    }

    fn reviewed_resume_file(
        path: &std::path::Path,
    ) -> (super::WalletReviewRegistry, super::WalletReviewId) {
        let reviews = super::WalletReviewRegistry::default();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(path).unwrap();
        let id = reviews
            .register(
                path.to_owned(),
                std::sync::Arc::new(snapshot.identity().clone()),
            )
            .unwrap();
        (reviews, id)
    }

    #[test]
    fn resume_refuses_unreachable_destination_and_seedless_memo_before_scanning() {
        let path = std::path::PathBuf::from(relabeled_fixture("modern-plaintext.dat", "mainnet"));
        let keys = argos_core::import_wallet_file_for_network(
            &std::fs::read(&path).unwrap(),
            None,
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        let workspace = resume_workspace(std::sync::Arc::new(argos_core::ImportedKeySource::new(
            keys,
        )));
        let (reviews, id) = reviewed_resume_file(&path);
        for (destination, memo, expected) in [
            (ORCHARD_ONLY_UA, None, "Sapling"),
            (ORCHARD_SAPLING_UA, Some("exchange deposit"), "memo"),
        ] {
            let input = serde_json::from_value::<super::ResumeSessionInput>(serde_json::json!({
                "workspace_path": workspace,
                "wallet_review_id": id,
                "destination": destination,
                "sweep_memo": memo,
                "lightwalletd_url": "http://127.0.0.1:1"
            }))
            .unwrap();
            let error = super::prepare_resume_key_source(
                &input,
                &reviews,
                &workspace,
                ZeckNetwork::Mainnet,
                None,
            )
            .err()
            .expect("refuse before scanning");
            assert!(error.contains(expected), "{error}");
            assert!(!workspace.exists());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn resume_refuses_added_keys_and_preserves_original_key_order() {
        let path = std::path::PathBuf::from(relabeled_fixture("modern-plaintext.dat", "mainnet"));
        let (reviews, id) = reviewed_resume_file(&path);
        let mut input = resume_input();
        input.wallet_review_id = Some(id);
        let (keys, _) = super::reviewed_wallet_scan_keys(
            &reviews,
            input.wallet_review_id.as_ref(),
            None,
            &[],
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        let file_only_workspace = resume_workspace(std::sync::Arc::new(
            argos_core::ImportedKeySource::new(keys),
        ));
        input
            .sapling_keys
            .push(SecretString::new(TEST_SAPLING_KEY_MAINNET.into()));
        assert!(
            super::prepare_resume_key_source(
                &input,
                &reviews,
                &file_only_workspace,
                ZeckNetwork::Mainnet,
                None
            )
            .is_err(),
            "adding a key must not resume the file-only scan"
        );
        let (mut combined, _) = super::reviewed_wallet_scan_keys(
            &reviews,
            input.wallet_review_id.as_ref(),
            None,
            &input.sapling_keys,
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        assert!(combined.sapling.len() >= 2);
        // The original order is part of the saved identity, even for equal key sets.
        combined.sapling.swap(0, 1);
        let reordered_workspace = resume_workspace(std::sync::Arc::new(
            argos_core::ImportedKeySource::new(combined),
        ));
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &reordered_workspace,
            ZeckNetwork::Mainnet,
            None
        )
        .is_err());
        let (original_order, _) = super::reviewed_wallet_scan_keys(
            &reviews,
            input.wallet_review_id.as_ref(),
            None,
            &input.sapling_keys,
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        let original_workspace = resume_workspace(std::sync::Arc::new(
            argos_core::ImportedKeySource::new(original_order),
        ));
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &original_workspace,
            ZeckNetwork::Mainnet,
            None
        )
        .is_ok());
        for workspace in [file_only_workspace, reordered_workspace, original_workspace] {
            assert!(!workspace.exists());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn resume_session_command_restores_reviewed_wallet_with_authenticated_storage_offline() {
        use tauri::Manager;
        let base = unused_temp_dir("resume-command");
        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        // An absolute test-only identifier makes Tauri's app-data resolver point
        // to this disposable directory without changing process environment.
        context.config_mut().identifier = base.to_string_lossy().into_owned();
        let app = tauri::test::mock_builder()
            .manage(super::AppState {
                service: argos_core::RecoveryService::new(),
                address_search: argos_core::address_search::AddressSearchService::default(),

                wallet_reviews: crate::reviewed_intent::WalletReviewRegistry::default(),
            })
            .build(context)
            .unwrap();
        assert_eq!(app.path().app_data_dir().unwrap(), base);
        let path = std::path::PathBuf::from(relabeled_fixture("modern-plaintext.dat", "mainnet"));
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let review_id = app
            .state::<super::AppState>()
            .wallet_reviews
            .register(
                path.clone(),
                std::sync::Arc::new(snapshot.identity().clone()),
            )
            .unwrap();
        let keys = argos_core::import_wallet_file_for_network(
            snapshot.bytes(),
            None,
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        let source = std::sync::Arc::new(argos_core::ImportedKeySource::new(keys));
        // The publication parent must belong to this test's user. Linux /tmp
        // is root-owned even though its sticky bit permits creating children.
        let publication_parent = base.join("publication");
        let data_dir = publication_parent.join("recovery-data");
        let workspace = resume_workspace_in_data_dir(source.clone(), data_dir.clone());
        // A loopback listener accepts no application requests. No public node,
        // chain fixture, real wallet or broadcast is involved in this test.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let input = || {
            let mut input = resume_input();
            input.workspace_path = workspace.to_string_lossy().into_owned();
            input.wallet_review_id = Some(review_id.clone());
            input.lightwalletd_url = endpoint.clone();
            input
        };
        let error = super::resume_session(app.handle().clone(), app.state(), input())
            .await
            .err()
            .unwrap();
        assert!(error.contains("Terms of Service"));
        argos_core::record_tos_acceptance(&base, 1_900_000_000).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&publication_parent)
                .unwrap();
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&publication_parent).unwrap();
        let service = app.state::<super::AppState>().service.clone();
        let original = service
            .start_scan_from_key_source(
                argos_core::ScanConfig {
                    birthday: 419_200,
                    num_accounts: None,
                    gap_limit: 20,
                    transparent_scan: None,
                    lightwalletd_url: endpoint.clone(),
                    confirmation_sources: Vec::new(),
                    data_dir: data_dir.clone(),
                    network: ZeckNetwork::Mainnet,
                    label: "original offline scan".into(),
                },
                source,
            )
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !workspace.join("session.json").exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("initial scan writes authenticated session before network work");
        service.release_scan(&original).await.unwrap();
        let saved_metadata = std::fs::read(workspace.join("session.json")).unwrap();
        for bad_memo in [false, true] {
            let mut rejected = input();
            if bad_memo {
                rejected.sweep_memo = Some("exchange deposit".into());
            } else {
                rejected.destination = ORCHARD_ONLY_UA.into();
            }
            assert!(
                super::resume_session(app.handle().clone(), app.state(), rejected)
                    .await
                    .is_err()
            );
            assert_eq!(
                std::fs::read(workspace.join("session.json")).unwrap(),
                saved_metadata
            );
        }
        let resumed = super::resume_session(app.handle().clone(), app.state(), input())
            .await
            .unwrap();
        assert_eq!(resumed.network, ZeckNetwork::Mainnet);
        assert_eq!(std::path::PathBuf::from(resumed.data_dir), data_dir);
        assert_eq!(resumed.lightwalletd_url, endpoint);
        assert!(service.get_scan_progress(&resumed.handle).await.is_ok());
        service.release_scan(&resumed.handle).await.unwrap();
        assert!(argos_core::workspace::read_session_metadata(&workspace)
            .unwrap()
            .is_some());
        drop(listener);
        std::fs::remove_dir_all(data_dir).unwrap();
        std::fs::remove_dir_all(base).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn resume_wallet_reimports_plaintext_and_encrypted_dat_without_seed() {
        for (name, password) in [
            ("modern-plaintext.dat", None),
            (
                "modern-encrypted.dat",
                Some(SecretString::new("argos-test-passphrase".into())),
            ),
        ] {
            let path = std::path::PathBuf::from(relabeled_fixture(name, "mainnet"));
            let bytes = std::fs::read(&path).unwrap();
            let keys = argos_core::import_wallet_file_for_network(
                &bytes,
                password.as_ref(),
                ZeckNetwork::Mainnet,
            )
            .unwrap();
            assert!(keys.mnemonic.is_none());
            let source = std::sync::Arc::new(argos_core::ImportedKeySource::new(keys));
            let workspace = resume_workspace(source.clone());
            let (reviews, id) = reviewed_resume_file(&path);
            let mut input = resume_input();
            input.wallet_review_id = Some(id);
            input.wallet_passphrase = password;
            let (actual, _) = super::prepare_resume_key_source(
                &input,
                &reviews,
                &workspace,
                ZeckNetwork::Mainnet,
                None,
            )
            .unwrap();
            use argos_core::KeySource;
            assert_eq!(actual.fingerprint().unwrap(), source.fingerprint().unwrap());
            assert!(
                !workspace.exists(),
                "verification must not create scan artifacts"
            );
            if input.wallet_passphrase.is_some() {
                input.wallet_passphrase = Some(SecretString::new("incorrect-password".into()));
                assert!(super::prepare_resume_key_source(
                    &input,
                    &reviews,
                    &workspace,
                    ZeckNetwork::Mainnet,
                    None
                )
                .is_err());
            }
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn resume_wallet_refuses_wrong_source_and_changed_review_without_mutation() {
        let path = std::path::PathBuf::from(relabeled_fixture("modern-plaintext.dat", "mainnet"));
        let original = std::fs::read(&path).unwrap();
        let (reviews, id) = reviewed_resume_file(&path);
        let other_keys = super::keys_from_secret_sapling_strings(
            &[SecretString::new(TEST_SAPLING_KEY_MAINNET.into())],
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        let workspace = resume_workspace(std::sync::Arc::new(argos_core::ImportedKeySource::new(
            other_keys,
        )));
        // Existing scan evidence must remain byte-for-byte untouched on refusal.
        std::fs::create_dir_all(&workspace).unwrap();
        let wallet_db = workspace.join("wallet.sqlite");
        std::fs::write(&wallet_db, b"existing scan evidence").unwrap();
        let mut input = resume_input();
        input.wallet_review_id = Some(id);
        let error = super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            None,
        )
        .err()
        .unwrap();
        assert!(
            error.contains("does not match the selected scan"),
            "{error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read(&wallet_db).unwrap(),
            b"existing scan evidence"
        );
        std::fs::write(&path, b"changed after review").unwrap();
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            None
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"changed after review");
        assert_eq!(
            std::fs::read(&wallet_db).unwrap(),
            b"existing scan evidence"
        );
        assert_eq!(std::fs::read_dir(&workspace).unwrap().count(), 1);
        std::fs::remove_dir_all(super::data_dir_from_workspace(&workspace).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn resume_address_match_preserves_seed_and_case_sensitive_bip39_passphrase() {
        let reviews = super::WalletReviewRegistry::default();
        let mut input = resume_input();
        input.seed = Some(SecretString::new(RESUME_SEED.into()));
        input.passphrase = Some(SecretString::new("CaseSensitive".into()));
        let seed = argos_core::address_search::candidate_seed(
            input.seed.as_ref().unwrap(),
            input.passphrase.as_ref().unwrap(),
        )
        .unwrap();
        let account = argos_core::derivation::derive_accounts_from_seed(
            seed.expose_secret(),
            ZeckNetwork::Mainnet,
            1,
        )
        .unwrap()
        .remove(0);
        let coordinates = argos_core::MatchCoordinates {
            pool: argos_core::DiscoveryPool::Transparent,
            account: 0,
            scope: argos_core::AddressScope::External,
            index: 0,
            network: ZeckNetwork::Mainnet,
            address: account.transparent_receive_address,
            path: account.transparent_receive_path,
        };
        let source = argos_core::prepare_match_recovery(
            seed.expose_secret(),
            ZeckNetwork::Mainnet,
            coordinates.clone(),
        )
        .unwrap();
        let workspace = resume_workspace(source);
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            Some(coordinates.clone())
        )
        .is_ok());
        input.passphrase = Some(SecretString::new("casesensitive".into()));
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            Some(coordinates.clone())
        )
        .is_err());
        input.seed = None;
        input.passphrase = None;
        input
            .sapling_keys
            .push(SecretString::new(TEST_SAPLING_KEY_MAINNET.into()));
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            Some(coordinates)
        )
        .is_err());
        assert!(!workspace.exists());
    }

    #[test]
    fn resume_wallet_keeps_imported_identity_for_mnemonic_and_combined_sources() {
        // Synthetic plaintext ZecWallet Lite file with no real wallet authority.
        let mut bytes = 25u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&22u64.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[0u8; 48]);
        bytes.push(0);
        bytes.extend_from_slice(&[0x11u8; 32]);
        bytes.extend_from_slice(&[0, 0, 0]);
        let path = unused_temp_dir("resume-zwl");
        std::fs::write(&path, &bytes).unwrap();
        let (reviews, id) = reviewed_resume_file(&path);
        for with_pasted in [false, true] {
            let mut input = resume_input();
            input.wallet_review_id = Some(id.clone());
            let mut keys =
                argos_core::import_wallet_file_for_network(&bytes, None, ZeckNetwork::Mainnet)
                    .unwrap();
            assert!(keys.mnemonic.is_some());
            let original_mnemonic = keys.mnemonic.as_ref().unwrap().clone();
            if with_pasted {
                input
                    .sapling_keys
                    .push(SecretString::new(TEST_SAPLING_KEY_MAINNET.into()));
                let typed = super::keys_from_secret_sapling_strings(
                    &input.sapling_keys,
                    ZeckNetwork::Mainnet,
                )
                .unwrap();
                argos_core::sapling_key::merge_standalone_sapling_keys(&mut keys, typed).unwrap();
            }
            let source = std::sync::Arc::new(argos_core::ImportedKeySource::new(keys));
            let workspace = resume_workspace(source.clone());
            let (actual, _) = super::prepare_resume_key_source(
                &input,
                &reviews,
                &workspace,
                ZeckNetwork::Mainnet,
                None,
            )
            .unwrap();
            use argos_core::KeySource;
            assert_eq!(actual.fingerprint().unwrap(), source.fingerprint().unwrap());
            let mut seed_only = resume_input();
            seed_only.seed = Some(original_mnemonic);
            assert!(
                super::prepare_resume_key_source(
                    &seed_only,
                    &reviews,
                    &workspace,
                    ZeckNetwork::Mainnet,
                    None
                )
                .is_err(),
                "the recovered seed must not impersonate a mnemonic wallet-file workspace"
            );
            if with_pasted {
                input.sapling_keys.clear();
                assert!(super::prepare_resume_key_source(
                    &input,
                    &reviews,
                    &workspace,
                    ZeckNetwork::Mainnet,
                    None
                )
                .is_err());
            }
            assert!(!workspace.exists());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn resume_accepts_original_seed_and_standalone_sapling_sources() {
        let reviews = super::WalletReviewRegistry::default();
        let mut input = resume_input();
        input.seed = Some(SecretString::new(RESUME_SEED.into()));
        let workspace = resume_workspace(std::sync::Arc::new(argos_core::SeedKeySource::new(
            input.seed.as_ref().unwrap().clone(),
        )));
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            None
        )
        .is_ok());
        input.seed = None;
        input
            .sapling_keys
            .push(SecretString::new(TEST_SAPLING_KEY_MAINNET.into()));
        let keys =
            super::keys_from_secret_sapling_strings(&input.sapling_keys, ZeckNetwork::Mainnet)
                .unwrap();
        let workspace = resume_workspace(std::sync::Arc::new(argos_core::ImportedKeySource::new(
            keys,
        )));
        assert!(super::prepare_resume_key_source(
            &input,
            &reviews,
            &workspace,
            ZeckNetwork::Mainnet,
            None
        )
        .is_ok());
        assert!(!workspace.exists());
    }

    #[test]
    fn resume_rejects_missing_conflicting_and_unreviewed_sources() {
        let reviews = super::WalletReviewRegistry::default();
        let workspace = resume_workspace(std::sync::Arc::new(argos_core::SeedKeySource::new(
            SecretString::new(RESUME_SEED.into()),
        )));
        let mut input = resume_input();
        for source_case in 0..6 {
            input.seed = None;
            input.wallet_review_id = None;
            input.wallet_passphrase = None;
            input.passphrase = None;
            input.sapling_keys.clear();
            match source_case {
                0 => {}
                1 => {
                    input.seed = Some(SecretString::new(RESUME_SEED.into()));
                    input.wallet_review_id = Some(super::WalletReviewId("unissued".into()));
                }
                2 => input.wallet_review_id = Some(super::WalletReviewId("unissued".into())),
                3 => input.wallet_passphrase = Some(SecretString::new("file password".into())),
                4 => {
                    input.seed = Some(SecretString::new(RESUME_SEED.into()));
                    input
                        .sapling_keys
                        .push(SecretString::new(TEST_SAPLING_KEY_MAINNET.into()));
                }
                5 => {
                    input.passphrase = Some(SecretString::new("BIP39 password".into()));
                    input
                        .sapling_keys
                        .push(SecretString::new(TEST_SAPLING_KEY_MAINNET.into()));
                }
                _ => unreachable!(),
            }
            assert!(
                super::prepare_resume_key_source(
                    &input,
                    &reviews,
                    &workspace,
                    ZeckNetwork::Mainnet,
                    None
                )
                .is_err(),
                "case {source_case}"
            );
            assert!(!workspace.exists());
        }
    }

    fn unused_temp_dir(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("argos-{label}-{}", uuid::Uuid::new_v4()));
        assert!(!path.exists());
        path
    }

    #[test]
    fn legacy_gui_default_selects_versioned_directory_and_keeps_legacy_rows_visible() {
        let base = unused_temp_dir("legacy-gui-default");
        let legacy = base.join("workspace");
        let wallet =
            legacy.join("mainnet/workspace-deadbeefdeadbeefdeadbeefdeadbeef/birthday-1528061/auto-gap-20/wallet.sqlite");
        std::fs::create_dir_all(wallet.parent().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(&wallet, b"v1.5.3 wallet evidence").unwrap();
        let selected = super::default_data_dir_for_base(&base).unwrap();
        assert_eq!(selected, base.join("workspace-v2"));
        assert!(!selected.exists());
        for requested in [None, Some(selected.to_str().unwrap())] {
            let rows = super::sessions_for_data_dir(&base, requested).unwrap();
            assert_eq!(rows.len(), 1);
            assert!(rows[0].legacy_untrusted && rows[0].requires_rescan);
            assert_eq!(
                std::path::PathBuf::from(&rows[0].workspace_path),
                wallet.parent().unwrap()
            );
        }
        assert_eq!(std::fs::read(&wallet).unwrap(), b"v1.5.3 wallet evidence");
        assert!(!legacy.join(".argos-private-artifact-root-v1").exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn validate_seed_accepts_protected_words_at_the_ipc_boundary() {
        let words = vec![secrecy::SecretString::new("abandon".to_owned()); 24];
        let future = super::validate_seed(words);
        drop(future);
    }

    fn test_wallet_review() -> (
        crate::reviewed_intent::WalletReviewRegistry,
        crate::reviewed_intent::WalletReviewId,
        std::path::PathBuf,
    ) {
        let registry = crate::reviewed_intent::WalletReviewRegistry::default();
        let dir =
            std::env::temp_dir().join(format!("argos-command-review-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        std::fs::write(&path, b"wallet-A").unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let id = registry
            .register(
                path.clone(),
                std::sync::Arc::new(snapshot.identity().clone()),
            )
            .unwrap();
        (registry, id, path)
    }

    #[test]
    fn wallet_review_rejects_changed_file_for_scan() {
        let (registry, id, path) = test_wallet_review();
        std::fs::write(path, b"wallet-B").unwrap();
        assert!(registry.verify(&id).is_err());
    }

    #[test]
    fn completion_guidance_command_reads_the_frontend_shape() {
        let input = serde_json::from_value(serde_json::json!({
            "transactions": [
                { "status": "mined", "safe_to_discard": true },
                { "status": "submission_unknown" }
            ],
            "skipped_accounts": 0,
            "follow_up_review_required": false,
            "error": null,
            "status_only": false,
            "donation_requested": true,
            "donated_zatoshis": 0,
            "donation_note": null
        }))
        .unwrap();
        let guidance = super::sweep_completion_guidance(input);
        assert!(!guidance.recovery_complete);
        assert_eq!(guidance.status_labels.len(), 2);
        assert!(guidance.summary.contains("may already have moved"));
        let json = serde_json::to_value(&guidance).unwrap();
        for field in [
            "recovery_complete",
            "summary",
            "next_steps",
            "donation",
            "status_labels",
        ] {
            assert!(json.get(field).is_some(), "{field}");
        }
    }

    use super::refuse_unreachable_sweep_destination;
    use argos_core::argos_wallet_import::{keys::TransparentKey, ImportedKeys, Provenance};

    use secrecy::ExposeSecret;

    /// The birthday route for a regtest golden fixture standing in for a
    /// real-network `wallet.dat`. The operational import refuses a regtest
    /// file under mainnet or testnet, so these tests import it unbound and
    /// exercise only the route choice after the import.
    fn route_for_regtest_fixture(
        name: &str,
        passphrase: Option<&SecretString>,
        typed: &[SecretString],
        network: ZeckNetwork,
    ) -> BirthdayRoute {
        let bytes = std::fs::read(fixture(name)).expect("fixture");
        let format = argos_core::argos_wallet_import::sniff(&bytes).expect("sniff");
        let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, passphrase)
            .expect("import");
        birthday_route_for_keys(keys, format, typed, network).unwrap()
    }

    fn fixture(name: &str) -> String {
        format!(
            "{}/../../crates/argos-wallet-import/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    /// A disposable copy of a regtest-written zcashd golden file whose sole
    /// `networkinfo` value names `network` instead, for paths that enforce
    /// the wallet's embedded network. The checked-in fixture is unchanged.
    fn relabeled_fixture(name: &str, network: &str) -> String {
        assert_eq!(network.len(), 7, "the marker is replaced in place");
        let mut bytes = std::fs::read(fixture(name)).unwrap();
        let matches: Vec<_> = bytes
            .windows(7)
            .enumerate()
            .filter_map(|(offset, window)| (window == b"regtest").then_some(offset))
            .collect();
        assert_eq!(matches.len(), 1, "golden wallet network marker changed");
        bytes[matches[0]..matches[0] + 7].copy_from_slice(network.as_bytes());
        let path = std::env::temp_dir().join(format!(
            "argos-gui-{network}-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    use argos_core::argos_wallet_import::WalletFormat;

    /// A Sapling extended spending key from the fixed seed `[7u8; 32]`,
    /// controlling no funds; the same constant the CLI tests pin.
    const TEST_SAPLING_KEY_MAINNET: &str =
        "secret-extended-key-main1qqqqqqqqqqqqqqyx7gddcfgw5zrw2n3nqd8f507vcpv82synampp4p8ljdz2t3ulhcn5yrvjwfsua98evx3p4v6596l8ttyctcphvxvyjf450h2dtevsakxzfjncm4v2gngdakt5384xumspjaw5uelkz2prq6cnmpd4kdczrjxr4zw2svjfq4j9amnkld3h6xetz4zq7p2lp5kzugwr7p2ln77xlj8ley3v2m8k44zduvjuynw7tpzpfv2mreh0qacxzeqrrcymmjgqvp59t";

    /// Fixed, and later than the fixtures' 2026 key times, so no test
    /// depends on today's date.
    const NOW: i64 = 1_900_000_000;

    fn wallet_dat_keys(route: BirthdayRoute) -> ImportedKeys {
        wallet_dat_route(route).0
    }

    fn wallet_dat_route(route: BirthdayRoute) -> (ImportedKeys, usize) {
        match route {
            BirthdayRoute::WalletDat { keys, pasted } => (keys, pasted),
            BirthdayRoute::Seed(_) => panic!("a zcashd wallet has no mnemonic"),
        }
    }

    /// A zcashd wallet.dat has no seed, but dates itself: every fixture key
    /// carries a creation time, so the birthday comes from the file with no
    /// network, and says so.
    #[test]
    fn a_zcashd_wallet_is_dated_from_its_key_times() {
        for (name, passphrase) in [
            ("modern-plaintext.dat", None),
            (
                "modern-encrypted.dat",
                Some(SecretString::from("argos-test-passphrase".to_owned())),
            ),
        ] {
            let keys = wallet_dat_keys(route_for_regtest_fixture(
                name,
                passphrase.as_ref(),
                &[],
                ZeckNetwork::Mainnet,
            ));
            let found =
                argos_core::wallet_file_birthday_from_metadata(&keys, ZeckNetwork::Mainnet, 0, NOW);
            let result = wallet_dat_birthday_result(found, ZeckNetwork::Mainnet).expect(name);
            assert_eq!(result.method, "wallet_metadata", "{name}");
            assert!(result.birthday > 1, "{name}");
            assert!(
                result.message.contains("key creation times"),
                "{}",
                result.message
            );
            assert!(
                result.message.contains("(about 2026-"),
                "{}",
                result.message
            );
        }
    }

    /// Testnet times are never converted: the user is told, not handed a
    /// guess.
    #[test]
    fn a_testnet_wallet_dat_gets_no_birthday() {
        let keys = wallet_dat_keys(route_for_regtest_fixture(
            "modern-plaintext.dat",
            None,
            &[],
            ZeckNetwork::Testnet,
        ));
        let found =
            argos_core::wallet_file_birthday_from_metadata(&keys, ZeckNetwork::Testnet, 0, NOW);
        let err = wallet_dat_birthday_result(found, ZeckNetwork::Testnet).unwrap_err();
        assert!(err.contains("mainnet"), "{err}");
    }

    /// A pasted Sapling key is scanned with the file's, and has no time, so
    /// it must count: otherwise the file's dated keys could set a birthday
    /// later than the pasted key's notes.
    #[test]
    fn a_pasted_sapling_key_counts_as_undated() {
        let pasted = [SecretString::new(TEST_SAPLING_KEY_MAINNET.to_owned())];
        let (keys, pasted) = wallet_dat_route(route_for_regtest_fixture(
            "modern-plaintext.dat",
            None,
            &pasted,
            ZeckNetwork::Mainnet,
        ));
        assert_eq!(pasted, 1);
        let found = argos_core::wallet_file_birthday_from_metadata(
            &keys,
            ZeckNetwork::Mainnet,
            pasted,
            NOW,
        );
        assert_eq!(found.source, argos_core::WalletBirthdaySource::None);
        assert_eq!(found.height, None);
        // Named as the pasted key it is, not as an undated key in the file.
        assert!(
            found
                .message
                .contains("1 key(s) added from a key file or paste box"),
            "{}",
            found.message
        );
        assert!(!found.message.contains("zcashd"), "{}", found.message);
    }

    /// Kristi's #1 on #260: an undated Sapling key -- pasted, or imported
    /// into the file without a time -- must not let a transparent output
    /// decide where Sapling starts. Detection returns no birthday without
    /// asking the chain (the URL here is unreachable on purpose: a chain
    /// check would surface as "could not be checked"), and the field keeps
    /// its value, which scans from Sapling activation.
    #[test]
    fn an_undated_sapling_key_gets_no_birthday_from_the_chain() {
        let detect = |keys: &ImportedKeys, pasted: usize| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(argos_core::detect_wallet_file_birthday(
                    keys,
                    ZeckNetwork::Mainnet,
                    pasted,
                    NOW,
                    Some("https://127.0.0.1:9"),
                    |_| {},
                ))
        };

        // Pasted route.
        let typed = [SecretString::new(TEST_SAPLING_KEY_MAINNET.to_owned())];
        let (mut keys, pasted) = wallet_dat_route(route_for_regtest_fixture(
            "modern-plaintext.dat",
            None,
            &typed,
            ZeckNetwork::Mainnet,
        ));
        assert_eq!(pasted, 1);
        // Give the file an undated transparent key as well, so the chain
        // fallback would otherwise be taken.
        if let Some(t) = keys.transparent.first_mut() {
            t.created_at = None;
        } else {
            keys.transparent.push(TransparentKey {
                secret: secrecy::Secret::new([1u8; 32]),
                provenance: Provenance::Standalone,
                created_at: None,
            });
        }
        let found = detect(&keys, pasted);
        assert_eq!(found.source, argos_core::WalletBirthdaySource::None);
        assert_eq!(found.height, None);
        assert!(
            found.message.contains("Sapling activation"),
            "{}",
            found.message
        );
        assert!(
            !found.message.contains("could not be checked"),
            "{}",
            found.message
        );
        let err = wallet_dat_birthday_result(found, ZeckNetwork::Mainnet).unwrap_err();
        assert!(err.contains("Sapling activation"), "{err}");

        // File route: a Sapling key in the file itself with no time, as
        // zcashd leaves a `z_importkey`'d key.
        let mut keys = wallet_dat_keys(route_for_regtest_fixture(
            "modern-plaintext.dat",
            None,
            &[],
            ZeckNetwork::Mainnet,
        ));
        assert!(!keys.sapling.is_empty(), "fixture holds a Sapling key");
        keys.sapling[0].created_at = None;
        keys.transparent.push(TransparentKey {
            secret: secrecy::Secret::new([2u8; 32]),
            provenance: Provenance::Standalone,
            created_at: None,
        });
        let found = detect(&keys, 0);
        assert_eq!(found.source, argos_core::WalletBirthdaySource::None);
        assert_eq!(found.height, None);
        assert!(
            found.message.contains("Sapling activation"),
            "{}",
            found.message
        );
    }

    /// The chain fallback is labelled as what it is.
    #[test]
    fn the_utxo_fallback_says_it_may_be_late() {
        let found = argos_core::WalletFileBirthday {
            height: Some(1_200_000),
            source: argos_core::WalletBirthdaySource::TransparentUtxos,
            keys_without_time: 3,
            message: "core message".to_owned(),
        };
        let result = wallet_dat_birthday_result(found, ZeckNetwork::Mainnet).unwrap();
        assert_eq!(result.method, "transparent_utxos");
        assert_eq!(result.birthday, 1_200_000);
        assert!(result.message.contains("unspent"), "{}", result.message);
        assert!(result.message.contains("later than"), "{}", result.message);
    }

    /// Hand-built ZecWallet Lite v25 file with an encrypted seed. The seed
    /// ciphertext is `encrypt_test_seed` from `argos-wallet-import`'s own
    /// tests (XSalsa20-Poly1305, unsalted double-SHA-256 key) for entropy
    /// `[0x11; 32]`, passphrase "some passphrase", nonce `[0x99; 24]`.
    fn encrypted_zwl_bytes() -> Vec<u8> {
        const ENC_SEED: &str = "01e1e103955249869a29a92fd73be26b58cbc0a722a5fb6d8124f72219bf9f2476f4776dac43f6828d54a4885bf435dc";
        let mut bytes = 25u64.to_le_bytes().to_vec(); // external version
        bytes.extend_from_slice(&21u64.to_le_bytes()); // keys version
        bytes.push(1); // encrypted
        bytes.extend(
            (0..ENC_SEED.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&ENC_SEED[i..i + 2], 16).expect("hex")),
        );
        bytes.push(24); // nonce length (CompactSize)
        bytes.extend_from_slice(&[0x99; 24]);
        bytes.extend_from_slice(&[0u8; 32]); // plaintext seed slot, unused when encrypted
        bytes.extend_from_slice(&[0, 0]); // no zkeys, no tkeys
        bytes
    }

    /// The positive path through a real file on disk: the backend re-opens
    /// the file, decrypts the seed and hands back the mnemonic, so it never
    /// has to cross IPC.
    #[test]
    fn an_encrypted_zwl_file_yields_its_mnemonic_for_detection() {
        let dir = std::env::temp_dir().join(format!("argos-birthday-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("zwl.dat");
        std::fs::write(&path, encrypted_zwl_bytes()).expect("write fixture");
        let path_str = path.to_str().expect("utf-8 path").to_owned();

        let pass = SecretString::from("some passphrase".to_owned());
        let route = birthday_route_for_file(&path_str, Some(&pass), &[], ZeckNetwork::Mainnet)
            .expect("decrypts");
        let phrase = match route {
            BirthdayRoute::Seed(phrase) => phrase,
            BirthdayRoute::WalletDat { .. } => panic!("a ZWL mnemonic is probed as a seed"),
        };
        // BIP-39 of entropy [0x11; 32].
        assert_eq!(
            phrase.expose_secret(),
            "baby mass dust captain baby mass dust captain baby mass dust captain \
             baby mass dust captain baby mass dust captain baby mass dust cake"
        );

        let err = match birthday_route_for_file(&path_str, None, &[], ZeckNetwork::Mainnet) {
            Err(err) => err,
            Ok(_) => panic!("needs the passphrase"),
        };
        assert!(!err.contains(phrase.expose_secret().as_str()), "{err}");
        let wrong = SecretString::from("wrong".to_owned());
        assert!(
            birthday_route_for_file(&path_str, Some(&wrong), &[], ZeckNetwork::Mainnet).is_err(),
            "wrong passphrase"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round-2 item C on #275: birthday detection binds the wallet file to
    /// the selected network, as the scan and sweep paths do, so a mainnet
    /// file is refused under testnet before anything is probed.
    #[test]
    fn birthday_detection_refuses_a_wallet_from_the_other_network() {
        let dir = std::env::temp_dir().join(format!("argos-bday-net-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("zwl-mainnet.dat");
        std::fs::write(
            &path,
            include_bytes!(
                "../../../crates/argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat"
            ),
        )
        .expect("write fixture");
        let path_str = path.to_str().expect("utf-8 path").to_owned();

        let err = match birthday_route_for_file(&path_str, None, &[], ZeckNetwork::Testnet) {
            Err(err) => err,
            Ok(_) => panic!("a mainnet wallet must not be dated under testnet"),
        };
        assert!(
            err.contains("mainnet") && err.contains("testnet"),
            "names both networks: {err}"
        );
        // Under its own network the file reaches the route decision.
        let same = match birthday_route_for_file(&path_str, None, &[], ZeckNetwork::Mainnet) {
            Err(err) => err,
            Ok(_) => String::new(),
        };
        assert!(
            !(same.contains("mainnet") && same.contains("testnet")),
            "{same}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mnemonic_takes_the_seed_route_and_a_seedless_zwl_is_refused() {
        let keys = ImportedKeys {
            mnemonic: Some(SecretString::from("abandon art".to_owned())),
            ..Default::default()
        };
        match birthday_route(keys, 0, WalletFormat::ZecwalletLite).expect("mnemonic present") {
            BirthdayRoute::Seed(phrase) => assert_eq!(phrase.expose_secret(), "abandon art"),
            BirthdayRoute::WalletDat { .. } => panic!("a mnemonic is probed as a seed"),
        }
        let err = match birthday_route(ImportedKeys::default(), 0, WalletFormat::ZecwalletLite) {
            Err(err) => err,
            Ok(_) => panic!("a seedless ZWL file has nothing dated"),
        };
        assert!(err.contains("height") && err.contains("date"), "{err}");
        assert!(matches!(
            birthday_route(ImportedKeys::default(), 0, WalletFormat::Zcashd),
            Ok(BirthdayRoute::WalletDat { .. })
        ));
    }

    #[tokio::test]
    async fn delete_workspace_command_uses_guarded_recovery_service() {
        use tauri::Manager;
        let app = tauri::test::mock_builder()
            .manage(super::AppState {
                service: argos_core::RecoveryService::new(),
                address_search: argos_core::address_search::AddressSearchService::default(),

                wallet_reviews: crate::reviewed_intent::WalletReviewRegistry::default(),
            })
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let missing = argos_core::ScanHandle::new();
        let backend = app
            .state::<super::AppState>()
            .service
            .delete_workspace(&missing)
            .await
            .unwrap_err();
        let command = super::delete_workspace(app.state(), missing)
            .await
            .unwrap_err();
        assert_eq!(command, backend.to_string());
    }

    // Orchard-only and Orchard+Sapling mainnet unified addresses. The first
    // is built from a fixed key in `transparent_recovery`'s tests.
    const ORCHARD_ONLY_UA: &str =
        "u1u4zdvtcrjt4cnffw3shrx440754g0mhr4a7fenck686tfr6rdqy9wu5v39ydpgm4ut37qnlh9kpw9fsp8wcwyu2y2r5stjhj0qwfnmrq";
    const ORCHARD_SAPLING_UA: &str =
        "u1nvgt6yr35mhc9wdf4wckvl38476vqy96dx3cwkfdwy4jet9300l5v8l2yg27ql7w9qwm0lf8kncnj9nus4mgete06j3cu3mhrqvstg6swvdya6xgzwhh6a9xxdhxkavvvmztqeuaurjtqfk3dzetuzgnu0zjvmdpe8ehvj53sy6yhzxj";

    fn transparent_keys() -> ImportedKeys {
        ImportedKeys {
            transparent: vec![TransparentKey {
                secret: secrecy::Secret::new([1u8; 32]),
                provenance: Provenance::Standalone,
                created_at: None,
            }],
            ..Default::default()
        }
    }

    /// The transparent leg of a seedless sweep needs a Sapling receiver. The
    /// GUI used to find that out only after the scan, so it is refused here.
    #[test]
    fn a_seedless_sweep_with_transparent_keys_refuses_an_orchard_only_destination() {
        let err = refuse_unreachable_sweep_destination(
            &transparent_keys(),
            ORCHARD_ONLY_UA,
            ZeckNetwork::Mainnet,
        )
        .expect_err("transparent funds cannot reach an Orchard-only address");
        assert!(
            err.contains("Sapling") && !err.contains("not a Zcash address"),
            "{err}"
        );

        refuse_unreachable_sweep_destination(
            &transparent_keys(),
            ORCHARD_SAPLING_UA,
            ZeckNetwork::Mainnet,
        )
        .expect("a Sapling receiver is reachable");
    }

    #[test]
    fn destinations_are_unconstrained_without_a_transparent_leg() {
        // No transparent keys: only Sapling legs, which Orchard-only can take.
        refuse_unreachable_sweep_destination(
            &ImportedKeys::default(),
            ORCHARD_ONLY_UA,
            ZeckNetwork::Mainnet,
        )
        .expect("no transparent leg, nothing to refuse");

        // A standalone key can overlap an HD receiver discovered during the
        // scan. Preflight cannot establish whether a direct leg remains.
        let mut seeded = transparent_keys();
        seeded.mnemonic = Some(secrecy::SecretString::new("abandon".to_owned()));
        refuse_unreachable_sweep_destination(&seeded, ORCHARD_ONLY_UA, ZeckNetwork::Mainnet)
            .expect("mixed-source overlap must reach the scan to resolve its legs");

        seeded.transparent[0].provenance = Provenance::HdDerived;
        refuse_unreachable_sweep_destination(&seeded, ORCHARD_ONLY_UA, ZeckNetwork::Mainnet)
            .expect("HD-derived transparent keys use the mnemonic's sweep path");
    }

    #[test]
    fn scan_discovery_event_serializes_its_handle() {
        let event = super::ScanDiscoveryEvent {
            handle: argos_core::ScanHandle {
                id: "scan-a".into(),
            },
            discovery: argos_core::ScanDiscovery {
                account_index: 3,
                pool: argos_core::DiscoveryPool::Orchard,
                zatoshis: 42,
                at_block_height: 123,
                address: "u-test".into(),
            },
        };
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["handle"]["id"], "scan-a");
        assert_eq!(value["discovery"]["zatoshis"], 42);
        assert_eq!(value["discovery"]["account_index"], 3);
    }

    #[test]
    fn execute_sweep_authority_contains_only_handle_and_proposal_id() {
        // Binding the actual command to this function pointer makes additional
        // destination, memo, donation, or fee arguments a compile-time error.
        let _command: fn(
            AppHandle,
            State<'static, AppState>,
            ScanHandle,
            argos_core::SweepProposalId,
        ) -> _ = super::execute_sweep;
    }

    #[test]
    fn reconciliation_commands_accept_only_existing_handle_and_txid() {
        let _status: fn(AppHandle, State<'static, AppState>, ScanHandle) -> _ =
            super::reconcile_sweep;
        let _retry: fn(AppHandle, State<'static, AppState>, ScanHandle, String) -> _ =
            super::retry_unknown_sweep;
    }

    #[test]
    fn gui_accepts_default_single_operator_confirmation() {
        // The defaults (two hosts of one operator) must be enough to scan
        // and sweep; review shows the single-operator notice instead.
        let sources = super::parse_gui_confirmation_sources(
            "https://zec.rocks:443,https://na.zec.rocks:443",
            &[],
        )
        .expect("default configuration needs no extra confirmation source");
        assert!(sources.is_empty());
        let sources = super::parse_gui_confirmation_sources(
            "https://zec.rocks:443,https://na.zec.rocks:443",
            &["independent=https://other.example:443".to_owned()],
        )
        .expect("an optional independent operator is accepted");
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].operator_id, "independent");
        // Malformed entries are still refused.
        assert!(super::parse_gui_confirmation_sources(
            "https://zec.rocks:443",
            &["no-separator".to_owned()],
        )
        .is_err());
        assert!(super::parse_gui_confirmation_sources(
            "https://zec.rocks:443",
            &[
                "one=https://one.example:443".to_owned(),
                "two=https://one.example:443".to_owned(),
            ],
        )
        .is_err());
    }

    #[test]
    fn sweep_events_distinguish_result_submission_and_mining() {
        use argos_core::TxLifecycleState as State;
        assert_eq!(
            super::sweep_event_names(State::NotSubmitted),
            &["sweep-tx-result"]
        );
        assert_eq!(
            super::sweep_event_names(State::Rejected),
            &["sweep-tx-result"]
        );
        assert_eq!(
            super::sweep_event_names(State::SubmissionUnknown),
            &["sweep-tx-result"]
        );
        for state in [State::Pending, State::Expired] {
            assert_eq!(
                super::sweep_event_names(state),
                &["sweep-tx-result", "sweep-tx-broadcast"]
            );
        }
        assert_eq!(
            super::sweep_event_names(State::Mined),
            &[
                "sweep-tx-result",
                "sweep-tx-broadcast",
                "sweep-tx-confirmed"
            ]
        );
    }

    fn summary_with_diagnostics(
        diagnostics: Vec<argos_core::argos_wallet_import::ImportDiagnostic>,
        has_mnemonic: bool,
    ) -> serde_json::Value {
        use argos_core::argos_wallet_import::ImportedKeys;
        use secrecy::SecretString;

        let mut keys = ImportedKeys {
            diagnostics,
            ..Default::default()
        };
        if has_mnemonic {
            keys.mnemonic = Some(SecretString::new("public test seed".to_owned()));
        }
        serde_json::to_value(wallet_summary_from_keys("test.dat".to_owned(), None, keys)).unwrap()
    }

    #[test]
    fn wallet_summary_marks_container_damage_as_fund_hiding() {
        use argos_core::argos_wallet_import::ImportDiagnostic;
        let summary = summary_with_diagnostics(
            vec![ImportDiagnostic::ContainerDamage {
                format: "ZWL",
                location: "byte 42".to_owned(),
                reason: "truncated field".to_owned(),
            }],
            false,
        );
        assert_eq!(summary["coverage_may_hide_funds"], true);
        assert!(summary["coverage_notice"]
            .as_str()
            .unwrap()
            .contains("Incomplete"));
        assert!(summary["diagnostics"][0]
            .as_str()
            .unwrap()
            .contains("wallet container is damaged"));
        assert!(!summary.to_string().contains("public test seed"));
    }

    #[test]
    fn unwalkable_bdb_error_preserves_original_file() {
        let bytes = include_bytes!(
            "../../../crates/argos-wallet-import/tests/fixtures/modern-plaintext-truncated.dat"
        );
        let err = import_gui_wallet_then(bytes, None, argos_core::ZeckNetwork::Mainnet, |_| ())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("wallet file structure is unreadable"), "{err}");
        assert!(err.contains("Keep the original wallet file"), "{err}");
    }

    #[test]
    fn wallet_summary_keeps_locked_key_guidance() {
        use argos_core::argos_wallet_import::{ImportDiagnostic, Provenance};
        let summary = summary_with_diagnostics(
            vec![
                ImportDiagnostic::LockedKey {
                    record_type: "zwl-tkey".to_owned(),
                    provenance: Provenance::HdDerived,
                },
                ImportDiagnostic::LockedKey {
                    record_type: "zwl-tkey".to_owned(),
                    provenance: Provenance::Standalone,
                },
            ],
            true,
        );
        let diagnostics = summary["diagnostics"].as_array().unwrap();
        assert!(diagnostics[0]
            .as_str()
            .unwrap()
            .contains("recover the wallet seed to recreate it"));
        assert!(diagnostics[1]
            .as_str()
            .unwrap()
            .contains("cannot be recreated from the seed"));
        assert_eq!(summary["coverage_may_hide_funds"], true);
    }

    #[test]
    fn wallet_summary_redacts_identifier_mismatch() {
        use argos_core::argos_wallet_import::ImportDiagnostic;
        let mut bytes = include_bytes!(
            "../../../crates/argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat"
        )
        .to_vec();
        let original = b"t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F";
        let sentinel = b"t1SentinelWrongAddressAAAAAAAAAAAAA";
        assert_eq!(original.len(), sentinel.len());
        let offsets: Vec<_> = bytes
            .windows(original.len())
            .enumerate()
            .filter_map(|(index, window)| (window == original).then_some(index))
            .collect();
        assert_eq!(offsets.len(), 1, "writer fixture address changed");
        bytes[offsets[0]..offsets[0] + original.len()].copy_from_slice(sentinel);

        let keys =
            import_gui_wallet_then(&bytes, None, argos_core::ZeckNetwork::Mainnet, |keys| keys)
                .unwrap();
        assert!(
            keys.transparent.is_empty(),
            "mismatched key must be rejected"
        );
        assert!(keys.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            ImportDiagnostic::PublicIdentifierMismatch { .. }
        )));
        let summary = serde_json::to_value(wallet_summary_from_keys(
            "public-fixture.dat".to_owned(),
            None,
            keys,
        ))
        .unwrap();
        let serialized = summary.to_string();
        assert!(
            serialized.contains("mismatched record was not used"),
            "{serialized}"
        );
        assert!(
            !serialized.contains("t1SentinelWrongAddress"),
            "{serialized}"
        );
        assert_eq!(summary["coverage_may_hide_funds"], true);
    }

    #[test]
    fn damaged_mkey_is_not_reported_as_needing_passphrase() {
        use argos_core::argos_wallet_import::{bdb, zcashd::records::parse_record_key};
        let mut bytes = include_bytes!(
            "../../../crates/argos-wallet-import/tests/fixtures/modern-encrypted.dat"
        )
        .to_vec();
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
        let err = import_gui_wallet_then(&bytes, None, argos_core::ZeckNetwork::Mainnet, |keys| {
            keys.total_keys()
        })
        .err()
        .unwrap()
        .to_string();
        assert!(
            err.contains("wallet encryption metadata is damaged"),
            "{err}"
        );
        assert!(err.contains("Keep the original wallet file"), "{err}");
        assert_ne!(
            err,
            argos_core::argos_wallet_import::ImportError::WrongPassphrase.to_string()
        );
    }

    use super::*;

    #[test]
    fn inspect_wallet_rejects_embedded_network_mismatch() {
        let bytes = include_bytes!(
            "../../../crates/argos-wallet-import/tests/fixtures/zwl-testnet-empty.dat"
        );
        let reached_recovery = std::cell::Cell::new(false);
        let err = import_gui_wallet_then(bytes, None, argos_core::ZeckNetwork::Mainnet, |keys| {
            reached_recovery.set(true);
            keys
        })
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("mainnet") && err.contains("testnet"), "{err}");
        assert!(
            !reached_recovery.get(),
            "recovery ran on a wrong-network wallet"
        );
    }

    #[test]
    fn matching_embedded_network_reaches_recovery() {
        let bytes = include_bytes!(
            "../../../crates/argos-wallet-import/tests/fixtures/zwl-testnet-empty.dat"
        );
        let reached_recovery = std::cell::Cell::new(false);
        let recovered =
            import_gui_wallet_then(bytes, None, argos_core::ZeckNetwork::Testnet, |keys| {
                assert_eq!(
                    keys.embedded_network,
                    Some(argos_core::argos_wallet_import::EmbeddedNetwork::Testnet)
                );
                reached_recovery.set(true);
                keys
            })
            .unwrap();
        assert!(
            reached_recovery.get(),
            "matching wallet never reached recovery"
        );
        assert!(
            recovered.mnemonic.is_some(),
            "public seed fixture lost its mnemonic"
        );
    }

    #[test]
    fn ordinary_scan_inputs_default_to_the_complete_receive_range() {
        let seed: ScanConfigInput = serde_json::from_value(serde_json::json!({
            "seed": "synthetic seed text for serde only",
            "birthday": 419200,
            "num_accounts": null,
            "gap_limit": 20,
            "lightwalletd_url": "https://fixture.invalid",
            "data_dir": "/fixture",
            "network": "mainnet"
        }))
        .expect("seed scan input should deserialize");
        assert_eq!(
            seed.transparent_scan,
            argos_core::default_transparent_scan()
        );

        let wallet: WalletFileScanInput = serde_json::from_value(serde_json::json!({
            "path": "/fixture/wallet.dat",
            "passphrase": null,
            "sapling_keys": [],
            "birthday": 419200,
            "num_accounts": null,
            "gap_limit": 20,
            "lightwalletd_url": "https://fixture.invalid",
            "data_dir": "/fixture",
            "network": "mainnet",
            "destination": "u1fixture"
        }))
        .expect("wallet-file scan input should deserialize");
        assert_eq!(
            wallet.transparent_scan,
            argos_core::default_transparent_scan()
        );
    }

    #[test]
    fn matched_scan_explicit_null_keeps_the_complete_range_disabled() {
        let matched: MatchedScanConfigInput = serde_json::from_value(serde_json::json!({
            "birthday": 419200,
            "lightwalletd_url": "https://fixture.invalid",
            "data_dir": "/fixture",
            "network": "mainnet",
            "transparent_scan": null
        }))
        .expect("matched scan input should deserialize");
        assert_eq!(matched.transparent_scan, None);
    }

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

    #[test]
    fn powershell_quote_doubles_every_single_quote_powershell_recognises() {
        assert_eq!(powershell_quote("it's"), "'it''s'");
        // PowerShell also ends a single-quoted string at U+2018..U+201B; an
        // unescaped one would let server text after it run as code.
        assert_eq!(
            powershell_quote("x\u{2019}+$(calc)+\u{2018}y\u{201A}\u{201B}"),
            "'x\u{2019}\u{2019}+$(calc)+\u{2018}\u{2018}y\u{201A}\u{201A}\u{201B}\u{201B}'"
        );
        assert_eq!(powershell_quote("abc\x00def"), "'abcdef'");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_report_refuses_a_reused_permissive_file_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("argos-report-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("recovery-report.txt");
        // Simulate a pre-existing, world-readable report file at the target path.
        std::fs::write(&path, b"stale").expect("seed file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen");

        super::write_private_report(&path, b"fresh")
            .expect_err("a reused permissive report must fail closed");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "a reused permissive report file must not be repaired in place"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"stale");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_write_private_report_creates_private_and_refuses_untrusted_reuse() {
        let outer = unused_temp_dir("windows-private-report");
        argos_core::private_fs::create_private_dir_all(&outer).unwrap();
        let private = outer.join("private-report.txt");
        super::write_private_report(&private, b"private").expect("create private report");
        assert_eq!(std::fs::read(&private).unwrap(), b"private");

        let reused = outer.join("reused-report.txt");
        std::fs::write(&reused, b"stale").unwrap();
        super::write_private_report(&reused, b"replacement")
            .expect_err("an untrusted reused report must fail closed");
        assert_eq!(std::fs::read(&reused).unwrap(), b"stale");
        std::fs::remove_dir_all(&outer).unwrap();
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

    #[test]
    fn wallet_summary_explains_retired_sprout_records_without_hiding_supported_keys() {
        let mut keys = transparent_keys();
        keys.sprout_records = 2;
        let summary = super::wallet_summary_from_keys("mixed.dat".into(), None, keys);
        assert_eq!(summary.transparent_keys, 1);
        assert_eq!(summary.sprout_records, 2);
        assert_eq!(
            summary.sprout_notice,
            argos_core::argos_wallet_import::keys::SPROUT_UNSPENDABLE_NOTICE
        );
        assert!(summary.sprout_notice.contains("unspendable"));
        assert!(!summary.needs_passphrase);
    }

    #[test]
    fn wallet_summary_has_no_retirement_notice_without_sprout_records() {
        let summary =
            super::wallet_summary_from_keys("supported.dat".into(), None, transparent_keys());
        assert_eq!(summary.sprout_records, 0);
        assert!(summary.sprout_notice.is_empty());
    }
}
