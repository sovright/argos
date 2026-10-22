#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;
use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::reviewed_intent::{
    CheckpointReservation, ReviewedIntentStore, ReviewedSproutSweep, ReviewedWalletSource,
    ScanCatchupLease, ScanMaterial, ScanWorkerCompletion, SecretSproutKeys, SproutIntentSource,
    SproutProposalId, SproutScanHandle, SproutScanProgressEvent, SproutScanSnapshot,
    SproutSweepIntent, SproutSweepPreviewData, WalletCheckpointAuthority, WalletReviewId,
    WalletReviewRegistry,
};
use argos_core::{
    detect_birthday as zeck_detect_birthday, estimate_birthday_from_date as estimate_birthday,
    list_incomplete_sessions as zeck_list_incomplete_sessions, parse_workspace_keying,
    validate_destination_address, validate_mnemonic_words, verify_seed_for_workspace,
    BirthdayDetectResult, IncompleteSession, RecoveryService, ReviewedSweepProposal, ScanConfig,
    ScanHandle, SweepOutcome, SweepProposalId, SweepRequest, ZeckNetwork,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

pub struct AppState {
    pub service: RecoveryService,
    pub address_search: argos_core::address_search::AddressSearchService,
    pub reviewed_intent: ReviewedIntentStore,
    pub wallet_reviews: WalletReviewRegistry,
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
    pub sprout_keys: usize,
    /// NU7's Sprout spending deadline; empty when no Sprout keys were found.
    pub sprout_nu7_warning: String,
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
    /// A source-bound lifecycle row exists even when no note is ready for a
    /// new transaction. The renderer uses this typed flag to open a status
    /// preview without parsing human-readable accounting text.
    pub sprout_has_lifecycle_status: bool,
    /// Why notes could not be recovered, when none were. Shown rather than
    /// summarised away: "no notes" and "notes that failed to decrypt" call
    /// for very different next steps.
    pub sprout_issues: Vec<String>,
    /// What a full-block Sprout scan would cost, in the user's terms.
    /// Rendered from `argos-core` so the GUI and CLI cannot drift.
    pub sprout_scan_warning: Vec<String>,
    /// Why the Sprout total is what it is — notes the wallet spent, dust,
    /// unconfirmed spends, unreadable transactions. From `argos-core`, the
    /// same sentences the CLI prints.
    pub sprout_accounting: Vec<String>,
    /// Every Sprout note was spent by the wallet itself or is dust. Not a
    /// case for the full-block scan, and must not be presented as one.
    pub sprout_nothing_left: bool,
    /// Some of the file's note data was read, even if nothing is spendable.
    pub sprout_history_read: bool,
    /// The limit of reading spends from a file, shown before a sweep.
    pub sprout_spent_status: String,
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

/// Drop any Sprout key that does not control the address it was filed under,
/// emitting a `sprout-forged-key` event for each so the frontend can surface
/// it. Mirrors the CLI loader and the `inspect` command, so the GUI's
/// scan/preview/sweep paths do not silently trial-decrypt against a forged
/// key. A forged key finds no notes (and the downstream commitment check
/// stops it from ever spending someone else's), but without this the user
/// gets an unexplained empty result instead of the reason.
fn drop_and_warn_forged_sprout_keys(
    app: &AppHandle,
    keys: &mut argos_core::argos_wallet_import::ImportedKeys,
) -> Vec<String> {
    let warnings = drop_forged_sprout_keys(keys);
    for warning in &warnings {
        let _ = app.emit("sprout-forged-key", warning);
    }
    warnings
}

/// Drop every Sprout key that does not control the address it was filed
/// under, and say why for each. The rule `inspect` applies, so a review and
/// the inspection of the same file agree on which keys count.
fn drop_forged_sprout_keys(
    keys: &mut argos_core::argos_wallet_import::ImportedKeys,
) -> Vec<String> {
    argos_core::sprout_recovery::reject_forged_sprout_keys(keys)
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The Sprout-derived portion of a `WalletFileSummary`.
///
/// Kept as its own struct so the Sprout recovery computation — forged-key
/// rejection, note decryption, scan-cost wording — stays in one helper
/// instead of spreading through `inspect_wallet_file`. The fields are plain
/// data (counts, encoded strings), which is what the frontend consumes.
struct SproutSummary {
    sprout_keys: usize,
    sprout_addresses: Vec<String>,
    sprout_spendable_notes: usize,
    sprout_spendable_zatoshis: u64,
    sprout_has_lifecycle_status: bool,
    sprout_issues: Vec<String>,
    sprout_scan_warning: Vec<String>,
    sprout_accounting: Vec<String>,
    sprout_nothing_left: bool,
    sprout_spent_status: String,
    sprout_history_read: bool,
}

const SPROUT_KEEP_SOURCE_WARNING: &str =
    "Keep the original wallet or Sprout key and the scan checkpoint. Broadcast is not confirmation.";

/// Compute the Sprout summary for a wallet. Body is verbatim the logic that
/// previously lived inline in `inspect_wallet_file`: reject forged keys, then
/// try to recover notes, then quote the scan cost when a scan would be needed.
async fn compute_sprout_summary(
    app: &AppHandle,
    keys: &mut argos_core::argos_wallet_import::ImportedKeys,
    network: argos_core::ZeckNetwork,
    data_dir: Option<&str>,
) -> SproutSummary {
    // Decrypting the note ciphertexts is what distinguishes a wallet whose
    // Sprout funds are recoverable right now from one that would need the
    // full-block scan. Doing it here keeps that judgement out of the
    // frontend, which can only see counts.
    // Dropped before anything is reported: a key that does not control its
    // stored address must not be counted, shown, or spent with.
    let forged = argos_core::sprout_recovery::reject_forged_sprout_keys(keys);

    let recovered =
        recover_for_wallet_open(keys, network, resolve_data_dir(app, data_dir).ok()).await;
    let journal_result = if keys.sprout.is_empty() {
        Ok(argos_core::sprout_sweep::SproutJournalSnapshot::default())
    } else {
        resolve_data_dir(app, data_dir).and_then(|dir| {
            let spending_keys = wallet_sprout_keys(keys);
            argos_core::sprout_sweep::SweepJournal::for_keys(
                &dir,
                spending_keys.as_slice(),
                network,
            )
            .load_scoped_snapshot(
                &recovered
                    .notes
                    .iter()
                    .map(|note| note.outpoint)
                    .collect::<Vec<_>>(),
            )
            .map_err(|err| err.to_string())
        })
    };
    let (snapshot, journal_warning) = match journal_result {
        Ok(snapshot) => (snapshot, None),
        Err(err) => (
            argos_core::sprout_sweep::SproutJournalSnapshot::default(),
            Some(format!(
                "Sweep lifecycle journal could not be read: {err}. {SPROUT_KEEP_SOURCE_WARNING}"
            )),
        ),
    };
    let journal_read = journal_warning.is_none();
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
    let (ready_notes, ready_zatoshis, _) =
        sprout_ready_summary(&recovered.notes, &snapshot).unwrap_or((0, 0, true));
    let SproutScreen {
        nothing_left,
        needs_scan: _,
        history_read,
        quote_scan_cost,
    } = sprout_screen_with_journal(!keys.sprout.is_empty(), &recovered, &snapshot, journal_read);
    let mut accounting = recovered.accounting_lines();
    accounting.extend(inventory.accounting_lines());
    accounting.extend(journal_warning.iter().cloned());
    accounting.extend(argos_core::sprout_recovery::unreadable_transactions_warning(keys));

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
                    network,
                )
            })
            .collect(),
        sprout_spendable_notes: ready_notes,
        sprout_spendable_zatoshis: ready_zatoshis,
        sprout_has_lifecycle_status: sprout_has_lifecycle_status(&snapshot),
        sprout_issues: forged
            .iter()
            .map(|f| f.to_string())
            .chain(recovered.issues.iter().map(|i| i.to_string()))
            .collect(),
        sprout_scan_warning: if quote_scan_cost {
            argos_core::sprout_scan_cost::SproutScanCost::for_network(network.into())
                .warning_lines()
        } else {
            Vec::new()
        },
        sprout_accounting: accounting,
        sprout_nothing_left: nothing_left,
        sprout_spent_status: recovered.spent_status(),
        sprout_history_read: history_read,
    }
}

/// What the Sprout section of the wallet screen should say.
#[derive(Debug, PartialEq, Eq)]
struct SproutScreen {
    /// Every note was spent by the wallet itself or is dust.
    nothing_left: bool,
    /// Nothing spendable came out of the file, and something might still be
    /// found from the chain.
    needs_scan: bool,
    /// The file holds note data — read, or present but unreadable — so
    /// "this file holds no note data" would be false, even when nothing is
    /// spendable.
    history_read: bool,
    /// The scan is offered, so its cost must be quoted beside it.
    quote_scan_cost: bool,
}

#[cfg(test)]
fn sprout_screen(
    has_keys: bool,
    recovered: &argos_core::sprout_recovery::SproutRecovery,
) -> SproutScreen {
    let snapshot = argos_core::sprout_sweep::SproutJournalSnapshot::default();
    sprout_screen_with_journal(has_keys, recovered, &snapshot, true)
}

fn sprout_has_lifecycle_status(snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot) -> bool {
    snapshot.entries().next().is_some()
}

fn sprout_screen_with_journal(
    has_keys: bool,
    recovered: &argos_core::sprout_recovery::SproutRecovery,
    snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot,
    journal_read: bool,
) -> SproutScreen {
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, snapshot);
    let journal_empty = snapshot.entries().next().is_none();
    let nothing_left =
        has_keys && journal_read && journal_empty && recovered.nothing_left_to_sweep(&inventory);
    let needs_scan = has_keys && recovered.notes.is_empty() && !nothing_left && journal_empty;
    SproutScreen {
        nothing_left,
        needs_scan,
        // A fully spent wallet is still offered the scan, as a check.
        // Lifecycle-only rows also need the quote because terminal entries
        // can require a recovery scan before a new transaction is possible.
        quote_scan_cost: has_keys && recovered.notes.is_empty(),
        history_read: !(recovered.spent.is_empty()
            && recovered.dust.is_empty()
            && recovered.unreadable_transactions == 0),
    }
}

/// Read a legacy wallet file and report what is in it. No network is used.
/// Legacy or unmarked sweep journals are preserved and refused, never migrated.
///
/// The passphrase crosses the IPC boundary as a `SecretString`, the same
/// treatment the seed phrase gets (audit Issue A). That is a real exposure
/// and is recorded in docs/THREAT_MODEL.md as T-S6: a compromised webview
/// sees it. The CLI avoids the question entirely by prompting on a terminal;
/// a GUI has no equivalent, so the choice is this or no GUI import at all.
#[tauri::command]
pub async fn inspect_wallet_file(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    passphrase: Option<SecretString>,
    network: Option<String>,
    data_dir: Option<String>,
) -> Result<WalletFileSummary, String> {
    // Needed to encode Sprout addresses in the form the user can actually
    // match against a backup. Optional so an older frontend still works,
    // defaulting to mainnet as everything else here does.
    let network_name = network.unwrap_or_else(|| "mainnet".to_owned());
    let selected = parse_wallet_network(&network_name)?;
    let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path)
        .map_err(|err| format!("could not read {path}: {err}"))?;
    // Recovery runs only once the core importer has accepted the wallet's
    // embedded network; it is async (a saved scan is named offline), so it
    // follows the import rather than running inside its continuation.
    let mut keys = match import_gui_wallet_then(
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
                sprout_keys: 0,
                sprout_nu7_warning: String::new(),
                sprout_addresses: Vec::new(),
                sprout_spendable_notes: 0,
                sprout_spendable_zatoshis: 0,
                sprout_has_lifecycle_status: false,
                sprout_issues: Vec::new(),
                sprout_scan_warning: Vec::new(),
                sprout_accounting: Vec::new(),
                sprout_nothing_left: false,
                sprout_history_read: false,
                sprout_spent_status: String::new(),
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
    let sprout = compute_sprout_summary(&app, &mut keys, selected, data_dir.as_deref()).await;
    let review_id = if keys.is_empty() {
        None
    } else {
        Some(state.wallet_reviews.register(
            PathBuf::from(&path),
            std::sync::Arc::new(snapshot.identity().clone()),
        )?)
    };

    Ok(wallet_summary_from_keys(
        path,
        review_id,
        keys,
        sprout,
        &network_name,
    ))
}

/// Keep IPC coverage and diagnostics bound to the same parsed key set.
fn wallet_summary_from_keys(
    path: String,
    review_id: Option<WalletReviewId>,
    keys: argos_core::argos_wallet_import::ImportedKeys,
    sprout: SproutSummary,
    network_name: &str,
) -> WalletFileSummary {
    WalletFileSummary {
        review_id,
        path,
        transparent_keys: keys.transparent.len(),
        sapling_keys: keys.sapling.len(),
        sprout_keys: sprout.sprout_keys,
        sprout_nu7_warning: summary_nu7_warning(sprout.sprout_keys, network_name),
        sprout_addresses: sprout.sprout_addresses,
        sprout_spendable_notes: sprout.sprout_spendable_notes,
        sprout_spendable_zatoshis: sprout.sprout_spendable_zatoshis,
        sprout_has_lifecycle_status: sprout.sprout_has_lifecycle_status,
        sprout_issues: sprout.sprout_issues,
        sprout_scan_warning: sprout.sprout_scan_warning,
        sprout_accounting: sprout.sprout_accounting,
        sprout_nothing_left: sprout.sprout_nothing_left,
        sprout_history_read: sprout.sprout_history_read,
        sprout_spent_status: sprout.sprout_spent_status,
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
    let mut keys = match &config.review_id {
        Some(review_id) => {
            let (_, snapshot) = state.wallet_reviews.verify(review_id)?;
            argos_core::import_wallet_file_for_network(
                snapshot.bytes(),
                config.passphrase.as_ref(),
                config.network,
            )
            .map_err(|err| err.to_string())?
        }
        None => argos_core::argos_wallet_import::ImportedKeys::default(),
    };
    // A forged Sprout key must not survive into the scan, whether the keys
    // came from a wallet file or from pasted text.
    drop_and_warn_forged_sprout_keys(&app, &mut keys);

    if !config.sapling_keys.is_empty() {
        let typed = keys_from_secret_sapling_strings(&config.sapling_keys, config.network)?;
        // A wallet file with a mnemonic takes the Combined route, which
        // registers pasted keys beside the seed's accounts. The same helper
        // the CLI calls, so the two surfaces cannot drift on which
        // combinations are allowed or on the birthday a pasted key gets.
        argos_core::sapling_key::merge_standalone_sapling_keys(&mut keys, typed)
            .map_err(|err| err.to_string())?;
    }

    if keys.is_empty() {
        return Err(
            "no keys to scan — open a wallet file or paste a Sapling spending key.".to_owned(),
        );
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

/// [`sprout_sweep_preview`] for a wallet review, with the review's scan
/// verification notice (#272) carried on any error.
fn plan_wallet_sprout_preview(
    recovered: &argos_core::sprout_recovery::SproutRecovery,
    snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot,
) -> Result<SproutSweepPreviewData, String> {
    sprout_sweep_preview(&recovered.notes, snapshot)
        .map_err(|err| with_chain_notice(err, recovered.chain_notice.as_deref()))
}

/// One broadcast Sprout sweep, for the frontend.
#[derive(Clone, Serialize)]
pub struct SproutSweepResult {
    pub txid: String,
    pub value_zatoshis: Option<u64>,
    pub state: argos_core::TxLifecycleState,
    pub mined_height: Option<u32>,
    /// Replaced by a later plan for the same note; listed, needs no action.
    pub superseded: bool,
}

#[derive(Serialize)]
pub struct SproutSweepReport {
    pub transactions: Vec<SproutSweepResult>,
    pub mined_zatoshis: u64,
    pub pending_zatoshis: u64,
    pub unknown_zatoshis: u64,
    pub skipped: Vec<String>,
    pub rejected: Vec<String>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    pub fresh_all_mined: bool,
}

fn sprout_result_from_entry(
    entry: &argos_core::sprout_sweep::SproutJournalEntry,
) -> SproutSweepResult {
    SproutSweepResult {
        txid: entry.txid().to_string(),
        value_zatoshis: entry.value_zatoshis,
        state: entry.state,
        mined_height: entry
            .observation
            .as_ref()
            .filter(|observation| observation.has_canonical_mined_evidence())
            .and_then(|observation| observation.mined_height),
        // Built from a live journal entry, which a later plan has not replaced.
        superseded: false,
    }
}

fn sprout_sweep_preview(
    notes: &[argos_core::sprout_recovery::SpendableSproutNote],
    snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot,
) -> Result<SproutSweepPreviewData, String> {
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(notes, snapshot);
    let plan = argos_core::sprout_sweep::plan_sweep_candidates(&inventory.ready)
        .map_err(|err| err.to_string())?;
    let (notes, gross_zatoshis, fee_zatoshis, net_zatoshis) = plan
        .map(|plan| {
            (
                plan.notes,
                plan.gross_zatoshis,
                plan.fee_zatoshis,
                plan.net_zatoshis,
            )
        })
        .unwrap_or((0, 0, 0, 0));
    let active = snapshot
        .entries()
        .filter(|entry| match entry.state {
            argos_core::TxLifecycleState::Expired | argos_core::TxLifecycleState::Rejected => false,
            argos_core::TxLifecycleState::Mined => !entry
                .observation
                .as_ref()
                .is_some_and(|observation| observation.has_canonical_mined_evidence()),
            _ => true,
        })
        .map(sprout_result_from_entry)
        .collect();
    let mined = snapshot
        .entries()
        .filter(|entry| {
            entry.state == argos_core::TxLifecycleState::Mined
                && entry
                    .observation
                    .as_ref()
                    .is_some_and(|observation| observation.has_canonical_mined_evidence())
        })
        .map(sprout_result_from_entry)
        .collect();
    Ok(SproutSweepPreviewData {
        notes,
        gross_zatoshis,
        fee_zatoshis,
        net_zatoshis,
        active,
        mined,
    })
}

fn sprout_ready_summary(
    notes: &[argos_core::sprout_recovery::SpendableSproutNote],
    snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot,
) -> Result<(usize, u64, bool), String> {
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(notes, snapshot);
    let plan = argos_core::sprout_sweep::plan_sweep_candidates(&inventory.ready)
        .map_err(|err| err.to_string())?;
    Ok((
        plan.as_ref().map_or(0, |plan| plan.notes),
        plan.as_ref().map_or(0, |plan| plan.gross_zatoshis),
        snapshot.entries().next().is_some(),
    ))
}

#[derive(Clone, Copy)]
enum SproutProposalOrigin {
    Wallet,
    SavedScan,
}

fn empty_sprout_proposal_error(
    origin: SproutProposalOrigin,
    plan_empty: bool,
    mut journal_states: impl Iterator<Item = argos_core::TxLifecycleState>,
) -> Option<String> {
    if !plan_empty || journal_states.next().is_none() {
        return None;
    }
    let source = match origin {
        SproutProposalOrigin::Wallet => "wallet source",
        SproutProposalOrigin::SavedScan => "saved scan",
    };
    Some(format!(
        "the {source} has terminal Sprout lifecycle status, but no note is ready for a new plan. \
         {SPROUT_KEEP_SOURCE_WARNING} Recover or rescan the source before reviewing a new sweep."
    ))
}

fn with_chain_notice(message: impl Into<String>, notice: Option<&str>) -> String {
    match notice {
        Some(notice) if !notice.is_empty() => format!("{}. {notice}", message.into()),
        _ => message.into(),
    }
}

/// Strict: an unknown network name is refused, never defaulted, on the
/// paths that bind a scan or a sweep to a chain. [`network_from`] is the
/// lenient form, built on this one.
fn sprout_network(name: &str) -> Result<ZeckNetwork, String> {
    match name {
        "mainnet" => Ok(ZeckNetwork::Mainnet),
        "testnet" => Ok(ZeckNetwork::Testnet),
        _ => Err("choose mainnet or testnet".to_owned()),
    }
}

fn append_chain_notice(warnings: &mut Vec<String>, notice: Option<String>) {
    if let Some(notice) = notice {
        warnings.push(notice);
    }
}

fn no_sprout_notes_error(
    recovered: &argos_core::sprout_recovery::SproutRecovery,
    inventory: &argos_core::sprout_sweep::SproutSweepInventory<'_>,
) -> String {
    let message = if recovered.nothing_left_to_sweep(inventory) {
        "nothing is left to sweep: every Sprout note in this wallet file is spent (by the \
         file's own record, or by this wallet's full-block scan) or worth less than the fee"
    } else {
        "no spendable Sprout notes could be recovered from this wallet file"
    };
    with_chain_notice(message.to_owned(), recovered.chain_notice.as_deref())
}

/// Recover once and store the exact notes and execution settings reviewed by
/// the user. No wallet path or passphrase is accepted at execution time.
///
/// `peers` is the scan panel's peer list: a saved scan of these keys is
/// verified against live headers through them (dialled before the DNS
/// seeds) before its spent verdicts shape the reviewed notes. A malformed
/// entry does not fail the review; see [`recover_for_sweep_preview`].
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn propose_wallet_sprout_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    review_id: WalletReviewId,
    passphrase: Option<SecretString>,
    destination: String,
    lightwalletd_url: String,
    confirmation_sources: Option<Vec<String>>,
    network: String,
    data_dir: Option<String>,
    peers: Option<Vec<String>>,
) -> Result<ReviewedSproutSweep, String> {
    ensure_tos_accepted(&app)?;
    let network = sprout_network(&network)?;
    let confirmation_sources = parse_gui_confirmation_sources(
        &lightwalletd_url,
        confirmation_sources.as_deref().unwrap_or(&[]),
    )?;
    // Validated before the wallet file is decrypted: neither check needs the
    // keys, so a bad address or server is reported without them.
    validate_sweep_request(&destination, network, &lightwalletd_url)?;
    let (reviewed_source, snapshot) = state.wallet_reviews.verify(&review_id)?;
    let mut keys =
        import_gui_wallet_then(snapshot.bytes(), passphrase.as_ref(), network, |keys| keys)
            .map_err(|err| err.to_string())?;
    let dir = with_resolved_sprout_data_dir(resolve_data_dir(&app, data_dir.as_deref()), |dir| {
        Ok(dir.to_path_buf())
    })?;
    let raw_peers = peers.unwrap_or_default();
    propose_wallet_sprout_sweep_core(
        &state.reviewed_intent,
        reviewed_source,
        &mut keys,
        dir,
        destination,
        network,
        lightwalletd_url,
        confirmation_sources,
        &raw_peers,
        |warning| {
            let _ = app.emit("sprout-forged-key", warning);
        },
    )
    .await
}

/// `propose_wallet_sprout_sweep` after the file is read and decrypted, with
/// no `AppHandle`: drop forged keys (reporting each through `on_forged`),
/// recover the notes (verifying a saved scan through `raw_peers`), load the
/// exact journal scope, and store the reviewed proposal.
#[allow(clippy::too_many_arguments)]
async fn propose_wallet_sprout_sweep_core(
    store: &ReviewedIntentStore,
    reviewed_source: std::sync::Arc<ReviewedWalletSource>,
    keys: &mut argos_core::argos_wallet_import::ImportedKeys,
    dir: PathBuf,
    destination: String,
    network: ZeckNetwork,
    lightwalletd_url: String,
    confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    raw_peers: &[String],
    on_forged: impl Fn(&str),
) -> Result<ReviewedSproutSweep, String> {
    // As inspect does: a forged key is dropped and named in the review, and
    // the genuine keys' notes are still swept. A forged key controls no note
    // of its own, and the commitment check stops it spending anyone else's.
    let forged_warnings = drop_forged_sprout_keys(keys);
    for warning in &forged_warnings {
        on_forged(warning);
    }
    // A malformed peer degrades the review to the wallet file's own record
    // with a warning (#272), but the proposal it yields is refused at
    // execute: the sweep never runs on a review whose scan could not be
    // verified because of the peer field.
    let (peers, peer_error) = match parse_custom_peers(raw_peers) {
        Ok(peers) => (peers, None),
        Err(err) => (Vec::new(), Some(err)),
    };
    let recovered = recover_for_sweep_preview(keys, network, Some(dir.clone()), raw_peers).await;
    let notice = recovered.chain_notice.as_deref();
    let wallet_checkpoint = WalletCheckpointAuthority {
        data_dir: dir.clone(),
        keys: wallet_sprout_keys(keys),
        peers,
    };
    let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
        &dir,
        wallet_checkpoint.keys.as_slice(),
        network,
    );
    let outpoints = recovered
        .notes
        .iter()
        .map(|note| note.outpoint)
        .collect::<Vec<_>>();
    let snapshot = journal
        .load_scoped_snapshot(&outpoints)
        .map_err(|err| with_chain_notice(err.to_string(), notice))?;
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
    let plan = plan_wallet_sprout_preview(&recovered, &snapshot)?;
    let plan_empty = plan.notes == 0 && plan.active.is_empty() && plan.mined.is_empty();
    if let Some(message) = empty_sprout_proposal_error(
        SproutProposalOrigin::Wallet,
        plan_empty,
        snapshot.entries().map(|entry| entry.state),
    ) {
        return Err(with_chain_notice(message, notice));
    }
    if plan_empty {
        return Err(no_sprout_notes_error(&recovered, &inventory));
    }
    // The reviewed notes and backend-owned wallet identity are held together.
    // Execute reopens only to verify identity; it never re-imports notes or
    // accepts a path from the webview.
    let mut review = store.insert_proposal(
        SproutSweepIntent {
            source: SproutIntentSource::Wallet(reviewed_source),
            notes: recovered.notes,
            destination,
            network,
            lightwalletd_url,
            confirmation_sources,
            journal,
            wallet_checkpoint: Some(wallet_checkpoint),
            checkpoint_authority: None,
            _checkpoint_reservation: None,
            tip_warning: None,
            peer_error,
        },
        plan,
    )?;
    review.warnings = forged_warnings;
    review.scan_warning = recovered.chain_notice;
    Ok(review)
}

/// A wallet review built while the scan panel's peer field was malformed
/// showed the wallet file's own record with a warning; executing it is
/// refused, as #272's sweep refuses that field.
fn refuse_unverified_review(intent: &SproutSweepIntent) -> Result<(), String> {
    match &intent.peer_error {
        Some(err) => Err(format!(
            "{err} This review's saved scan was not verified. Fix the scan panel's peer \
             field and review the sweep again."
        )),
        None => Ok(()),
    }
}

/// After the peer field is accepted, verify a wallet proposal's saved scan
/// against live headers again, through the peers it was reviewed with,
/// exactly as #272's sweep did at execute. Every reviewed note must still be
/// spendable by that fresh evidence, or the sweep is refused and must be
/// reviewed again.
///
/// The lifecycle journal is not read or written here: recovery does not
/// drop journaled notes (classification does), and `sweep_sprout_notes`
/// reconciles them under its operation guard only after this check passes,
/// so a refused execute leaves the journal exactly as the review saw it.
///
/// Returns execute's own verdict, which the sweep report carries in place
/// of the review's. A scan-derived proposal has nothing to re-verify here.
fn verify_review_at_execute(
    intent: &SproutSweepIntent,
) -> impl std::future::Future<Output = Result<Option<String>, String>> + Send + '_ {
    // Retained namespace authority makes the whole intent !Sync. Validate its
    // peer field now, then borrow only the Sync verification inputs across await.
    let peer_check = refuse_unverified_review(intent);
    let notes = intent.notes.as_slice();
    let network = intent.network;
    let wallet_checkpoint = intent.wallet_checkpoint.as_ref();
    async move {
        peer_check?;
        verify_review_with(
            notes,
            network,
            wallet_checkpoint,
            |dir, network, keys, peers| async move {
                argos_core::sprout_scan_run::chain_spends_for_wallet(dir, network, keys, peers)
                    .await
            },
        )
        .await
    }
}

type ReverifyEvidence = (
    Option<std::sync::Arc<argos_core::sprout_recovery::ChainSpends>>,
    Option<String>,
);

/// Keep the lookup injectable for offline refusal tests. Borrow the reviewed
/// key wrapper throughout the lookup; do not create an unwrapped key copy.
async fn verify_review_with<'a, F, Fut>(
    notes: &'a [argos_core::sprout_recovery::SpendableSproutNote],
    network: ZeckNetwork,
    wallet_checkpoint: Option<&'a WalletCheckpointAuthority>,
    lookup: F,
) -> Result<Option<String>, String>
where
    F: FnOnce(&'a Path, argos_core::p2p::wire::P2pNetwork, &'a [[u8; 32]], &'a [String]) -> Fut,
    Fut: std::future::Future<Output = ReverifyEvidence>,
{
    let Some(reverify) = wallet_checkpoint else {
        return Ok(None);
    };
    let (chain, notice) = lookup(
        &reverify.data_dir,
        network.into(),
        reverify.keys.as_slice(),
        &reverify.peers,
    )
    .await;
    reviewed_notes_still_spendable(notes, chain.as_deref())
        .map_err(|err| with_chain_notice(err, notice.as_deref()))?;
    Ok(notice)
}

/// The reviewed notes, judged by execute-time evidence: refused if the live
/// scan shows any of them spent on chain, as recovery would then drop them.
/// The wallet file itself cannot change under a proposal (its notes are held
/// in it), so this is the only input that can drop a reviewed note.
fn reviewed_notes_still_spendable(
    notes: &[argos_core::sprout_recovery::SpendableSproutNote],
    chain: Option<&argos_core::sprout_recovery::ChainSpends>,
) -> Result<(), String> {
    let outpoint = |note: &argos_core::sprout_recovery::SpendableSproutNote| {
        let txid: String = note
            .outpoint
            .txid
            .iter()
            .rev()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "{txid}:{}:{}",
            note.outpoint.js_index, note.outpoint.output_index
        )
    };
    let mut changed = Vec::new();
    for note in notes {
        let nullifier = argos_core::sprout::prf_nf(&note.a_sk, &note.note.rho);
        if chain.is_some_and(|chain| chain.nullifiers.contains_key(&nullifier)) {
            changed.push(format!("{} spent on chain", outpoint(note)));
        }
    }
    if changed.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the saved scan changed since this sweep was reviewed: {} of {} \
         reviewed Sprout note(s) are no longer spendable ({}). Nothing was sent. Review the \
         sweep again",
        changed.len(),
        notes.len(),
        changed.join("; ")
    ))
}

async fn execute_reviewed_sprout_sweep(
    app: AppHandle,
    intent: SproutSweepIntent,
) -> Result<SproutSweepReport, String> {
    verified_then_sweep(intent, |intent, chain_notice| {
        sweep_reviewed_intent(app, intent, chain_notice)
    })
    .await
}

/// Only the closure after successful verification may enter the spending step.
async fn verified_then_sweep<F, Fut>(
    intent: SproutSweepIntent,
    sweep: F,
) -> Result<SproutSweepReport, String>
where
    F: FnOnce(SproutSweepIntent, Option<String>) -> Fut,
    Fut: std::future::Future<Output = Result<SproutSweepReport, String>>,
{
    let chain_notice = verify_review_at_execute(&intent).await?;
    sweep(intent, chain_notice).await
}

async fn sweep_reviewed_intent(
    app: AppHandle,
    intent: SproutSweepIntent,
    chain_notice: Option<String>,
) -> Result<SproutSweepReport, String> {
    let source = match &intent.source {
        SproutIntentSource::Wallet(_) => argos_core::sprout_sweep::NoteSource::WalletFile,
        SproutIntentSource::Scan(_) => argos_core::sprout_sweep::NoteSource::Scan,
    };
    let emitter = app.clone();
    let mut outcome = argos_core::sprout_sweep::sweep_sprout_notes(
        &intent.notes,
        intent.network,
        &intent.lightwalletd_url,
        &intent.destination,
        &argos_core::sprout_sweep::default_params_path(),
        argos_core::sprout_sweep::SweepOptions {
            source,
            journal: &intent.journal,
            confirmation_sources: &intent.confirmation_sources,
        },
        move |msg| {
            let _ = emitter.emit("sprout-sweep-progress", msg);
        },
    )
    .await
    .map_err(|err| with_chain_notice(err.to_string(), chain_notice.as_deref()))?;

    apply_sprout_tip_warning(&mut outcome, intent.tip_warning);
    if let Some(authority) = &intent.checkpoint_authority {
        match argos_core::sprout_sweep::finalize_scan_checkpoint(
            authority,
            &intent.journal,
            intent.network,
            outcome.fresh_all_mined,
        ) {
            Ok(argos_core::sprout_sweep::ScanCheckpointCleanup::Removed)
            | Ok(argos_core::sprout_sweep::ScanCheckpointCleanup::AlreadyAbsent) => {}
            Ok(argos_core::sprout_sweep::ScanCheckpointCleanup::Retained(reason)) => {
                outcome.fresh_all_mined = false;
                outcome
                    .warnings
                    .push(format!("Checkpoint retained: {reason}."));
            }
            Err(err) => apply_checkpoint_cleanup_error(&mut outcome, &err),
        }
    }
    // Execute's own verification verdict, not the review's (#272).
    append_chain_notice(&mut outcome.warnings, chain_notice);
    Ok(sprout_sweep_report(outcome))
}

fn apply_sprout_tip_warning(
    outcome: &mut argos_core::sprout_sweep::SproutSweepOutcome,
    warning: Option<String>,
) {
    if let Some(warning) = warning {
        outcome.fresh_all_mined = false;
        outcome.warnings.insert(0, warning);
    }
}

fn apply_checkpoint_cleanup_error(
    outcome: &mut argos_core::sprout_sweep::SproutSweepOutcome,
    err: &dyn std::fmt::Display,
) {
    outcome.fresh_all_mined = false;
    outcome
        .warnings
        .push(format!("Checkpoint cleanup failed: {err}"));
}

#[tauri::command]
pub async fn execute_wallet_sprout_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    proposal_id: SproutProposalId,
) -> Result<SproutSweepReport, String> {
    ensure_tos_accepted(&app)?;
    let intent = state.reviewed_intent.take_wallet_proposal(&proposal_id)?;
    let SproutIntentSource::Wallet(reviewed_source) = &intent.source else {
        return Err("proposal belongs to a scan-derived sweep".into());
    };
    // Consume the one-shot proposal first, then bind every checkpoint query,
    // proof and send to the same file object and bytes the user inspected.
    // The proposal's Arc remains valid even if the registry entry expires.
    let _verified = state.wallet_reviews.verify_source(reviewed_source)?;
    execute_reviewed_sprout_sweep(app, intent).await
}

/// A Sprout scan's outcome, for the frontend.
#[derive(Clone, Serialize)]
pub struct SproutScanReport {
    pub blocks_scanned: u64,
    pub joinsplits_seen: u64,
    pub notes_found: usize,
    pub spent_notes: usize,
    pub total_zatoshis: u64,
    /// A saved transaction exists even when the resumed scan found no new
    /// unspent note. The frontend uses this typed fact to open status review.
    pub has_lifecycle_status: bool,
    /// Set when the chain tip could not be confirmed with lightwalletd, so
    /// the results past the last pinned checkpoint rest on the peer alone.
    pub tip_warning: Option<String>,
    /// The block trial decryption started from, as actually used: after a
    /// resume this is the checkpoint's bound. `None` is every block.
    pub decrypt_from_height: Option<u32>,
    /// Why, in the words the CLI prints.
    pub decrypt_line: String,
}

/// Check a raw Sprout spending key and report the address it controls.
///
/// Separate from the scan so a typo is caught in a second rather than six
/// hours in. The address is returned so the user can confirm Argos is about
/// to look for the one they meant.
#[tauri::command]
pub async fn check_sprout_key(key: SecretString, network: String) -> Result<String, String> {
    use secrecy::ExposeSecret;

    let network = parse_wallet_network(&network)?;
    let a_sk =
        argos_core::sprout_key::decode_sprout_spending_key(key.expose_secret().trim(), network)
            .map_err(|err| err.to_string())?;
    Ok(argos_core::sprout_key::encode_sprout_address(
        &argos_core::sprout::SproutPaymentAddress::from_spending_key(&a_sk),
        network,
    ))
}

/// Resolve a typed Sapling spending key to the address it controls.
///
/// Checked before the scan, not an hour into it — and the address is what
/// comes back, never the key, so nothing secret crosses the IPC boundary in
/// the reply or reaches a log.
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

/// Gather the spending keys a scan should look for.
///
/// From the wallet file, from typed `SK…`/`ST…` keys, or both — a user may
/// hold a wallet whose keys were never rescanned *and* a paper key for an
/// address it never knew about. Mirrors `collect_sprout_scan_keys` in the
/// CLI, including the dedup: a repeated key trial-decrypts every ciphertext
/// twice for nothing.
/// The Sprout keys a scan covers, with the pasted ones and the wallet kept
/// apart: pasted keys carry no creation time, and the skip decision needs
/// the wallet's own records.
struct ScanKeys {
    /// Every key, deduplicated: what the scan decrypts for.
    all: SecretSproutKeys,
    typed: SecretSproutKeys,
    wallet: Option<argos_core::argos_wallet_import::ImportedKeys>,
}

fn collect_scan_keys_from_bytes(
    wallet_bytes: Option<&[u8]>,
    passphrase: Option<&SecretString>,
    typed: &[SecretString],
    network: argos_core::ZeckNetwork,
) -> Result<ScanKeys, String> {
    use secrecy::ExposeSecret;

    let mut typed_values =
        secrecy::zeroize::Zeroizing::new(Vec::<[u8; 32]>::with_capacity(typed.len()));

    for (index, key) in typed.iter().enumerate() {
        let key = key.expose_secret().trim();
        // Blank lines and `#` comments are annotation, as in the CLI key file
        // and `keys_from_sapling_strings`. `typed` is the box's raw lines, so
        // `index` is the line the user sees.
        if key.is_empty() || key.starts_with('#') {
            continue;
        }
        typed_values.push(
            argos_core::sprout_key::decode_sprout_spending_key(key, network)
                .map_err(|err| format!("line {}: {err}", index + 1))?,
        );
    }

    let typed_keys = SecretSproutKeys::new(typed_values.to_vec());
    let mut wallet_keys = None;
    if let Some(bytes) = wallet_bytes {
        let mut wallet = argos_core::import_wallet_file_for_network(bytes, passphrase, network)
            .map_err(|err| err.to_string())?;
        // Drop any Sprout key that does not control its stored address before
        // it is trial-decrypted against — parity with the CLI loader and the
        // sweep commands. No AppHandle here to warn on; the sweep/preview
        // paths surface it, and a forged key would find nothing regardless.
        let _ = argos_core::sprout_recovery::reject_forged_sprout_keys(&mut wallet);
        wallet_keys = Some(wallet);
    }

    // Allocate the final key set once. Growing a Vec after it contains keys
    // can leave its old allocation unwiped after reallocation.
    let wallet_len = wallet_keys.as_ref().map_or(0, |wallet| wallet.sprout.len());
    let mut keys = secrecy::zeroize::Zeroizing::new(Vec::<[u8; 32]>::with_capacity(
        typed_values.len() + wallet_len,
    ));
    keys.extend_from_slice(&typed_values);
    if let Some(wallet) = &wallet_keys {
        keys.extend(wallet.sprout.iter().map(|key| *key.a_sk.expose_secret()));
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
    Ok(ScanKeys {
        all: SecretSproutKeys::new(std::mem::take(&mut *keys)),
        typed: typed_keys,
        wallet: wallet_keys,
    })
}

#[cfg(test)]
fn collect_scan_keys(
    path: Option<&str>,
    passphrase: Option<&SecretString>,
    typed: &[SecretString],
    network: argos_core::ZeckNetwork,
) -> Result<ScanKeys, String> {
    let bytes = path
        .map(argos_core::wallet_file::read_wallet_file)
        .transpose()
        .map_err(|err| err.to_string())?;
    collect_scan_keys_from_bytes(bytes.as_deref(), passphrase, typed, network)
}

/// Where the Sprout scan starts trial-decrypting, and the line saying why.
/// The same decision as `argos scan-sprout`: the skip comes only from the
/// wallet's dated Sprout keys, every pasted key is an extra that rules it
/// out, and a birthday the user entered can only lower it.
fn sprout_scan_plan(
    wallet: Option<&argos_core::argos_wallet_import::ImportedKeys>,
    typed: &[[u8; 32]],
    network: ZeckNetwork,
    birthday_floor: Option<u32>,
    decrypt_every_block: bool,
    now: i64,
) -> argos_core::SproutDecryptPlan {
    let empty = argos_core::argos_wallet_import::ImportedKeys::default();
    // Pasted Sprout keys are Sprout extras, read only by the skip; no
    // Sapling keys are added on this path.
    let dated = argos_core::wallet_file_birthday_from_metadata(
        wallet.unwrap_or(&empty),
        typed,
        network,
        0,
        now,
    );
    argos_core::plan_sprout_decrypt(
        dated.sprout_skip_height,
        &dated.sprout_skip_reason,
        birthday_floor,
        decrypt_every_block,
    )
}

/// The plan's line plus how to undo a skip in this app.
fn sprout_plan_line(plan: &argos_core::SproutDecryptPlan) -> String {
    if plan.decrypt_from.is_some() {
        format!(
            "{} To decrypt every block, tick \"Decrypt every block\" or enter an earlier \
             birthday for this scan.",
            plan.line
        )
    } else {
        plan.line.clone()
    }
}

/// How many user-supplied peers a scan accepts.
///
/// Small on purpose: these are dialled before the DNS seeds, so a long list
/// of dead entries only delays reaching a peer that works.
const MAX_CUSTOM_PEERS: usize = 8;

/// Parse and validate user-supplied P2P peers into `host:port` strings.
///
/// The GUI's counterpart to `argos scan-sprout --peer`: the escape hatch for
/// when every public peer's inbound slots are full. Entries may arrive one
/// per element or several in one element separated by commas or newlines.
/// Each is trimmed, empties are dropped, and duplicates (ASCII
/// case-insensitive) collapse to the first occurrence.
///
/// A bad entry is an error rather than something to skip: silently dropping
/// the one node a user typed would leave them watching Argos dial the same
/// busy public peers with no idea their input was ignored.
///
/// Purely syntactic — nothing is resolved or dialled here.
fn parse_custom_peers(entries: &[String]) -> Result<Vec<String>, String> {
    let mut peers: Vec<String> = Vec::new();
    let candidates = entries
        .iter()
        .flat_map(|entry| entry.split([',', '\n', '\r']))
        .map(str::trim)
        .filter(|entry| !entry.is_empty());

    for entry in candidates {
        validate_peer(entry).map_err(|why| {
            format!(
                "custom peer \"{entry}\" is not valid: {why}. Use host:port, for example \
                 192.0.2.10:8233, node.example.org:8233 or [2001:db8::1]:8233."
            )
        })?;
        if !peers.iter().any(|seen| seen.eq_ignore_ascii_case(entry)) {
            peers.push(entry.to_owned());
        }
    }

    if peers.len() > MAX_CUSTOM_PEERS {
        return Err(format!(
            "at most {MAX_CUSTOM_PEERS} custom peers are accepted; {} were given.",
            peers.len()
        ));
    }
    Ok(peers)
}

/// Check one trimmed, non-empty entry is `host:port` or `[ipv6]:port`.
fn validate_peer(entry: &str) -> Result<(), &'static str> {
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        let (addr, port) = rest
            .split_once("]:")
            .ok_or("a bracketed IPv6 address must be followed by :port")?;
        addr.parse::<std::net::Ipv6Addr>()
            .map_err(|_| "the bracketed part is not an IPv6 address")?;
        (None, port)
    } else {
        let (host, port) = entry.rsplit_once(':').ok_or("the port is missing")?;
        (Some(host), port)
    };

    if let Some(host) = host {
        if host.contains(':') {
            return Err("an IPv6 address must be written in brackets, as [addr]:port");
        }
        let label_ok = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if host.is_empty() || host.len() > 253 || !host.split('.').all(label_ok) {
            return Err("the host is not an IP address or hostname");
        }
    }

    // Digits only: `u16::from_str` would also take a leading `+`.
    if port.is_empty() {
        return Err("the port is missing");
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the port is not a number");
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err("the port must be between 1 and 65535"),
        Ok(_) => Ok(()),
    }
}

/// Start a resumable Sprout scan and return its backend handle immediately.
fn begin_sprout_scan_session(
    store: &ReviewedIntentStore,
    decoded: SecretSproutKeys,
    dir: &Path,
    network: ZeckNetwork,
    lightwalletd_url: String,
    confirmation_sources: Vec<argos_core::ConfirmationEndpoint>,
    peers: Vec<String>,
) -> Result<(SproutScanHandle, ScanMaterial, CheckpointReservation), String> {
    let checkpoint = argos_core::sprout_scan_run::checkpoint_path_for_network(
        dir,
        decoded.as_slice(),
        network.into(),
    );
    let reservation = store.reserve_checkpoint(&checkpoint)?;
    let fingerprint = argos_core::sprout_scan_run::key_set_fingerprint(decoded.as_slice());
    let handle = store.insert_scan(
        decoded,
        fingerprint,
        checkpoint,
        network,
        lightwalletd_url,
        confirmation_sources,
        peers,
    )?;
    let material = store.scan_material(&handle)?;
    Ok((handle, material, reservation))
}

fn finish_sprout_scan_task(
    store: &ReviewedIntentStore,
    handle: &SproutScanHandle,
    result: Result<Result<SproutScanReport, String>, tokio::task::JoinError>,
) {
    let result = match result {
        Ok(result) => result,
        Err(err) => Err(format!("Sprout scan worker stopped unexpectedly: {err}")),
    };
    store.finish_scan(handle, result);
}

/// Run a scan on its own task, owned by the store: the abort handle is
/// attached before the result is awaited, so releasing the scan stops the
/// worker (and drops the checkpoint reservation the future owns) rather than
/// leaving it to run on detached for hours. A release that lands before the
/// attach is handled by `attach_worker`, which aborts the orphan.
#[cfg(test)]
async fn run_attached_scan_worker<F>(
    store: &ReviewedIntentStore,
    handle: &SproutScanHandle,
    scan: F,
) where
    F: std::future::Future<Output = Result<SproutScanReport, String>> + Send + 'static,
{
    let scan_task = tokio::spawn(scan);
    let completion = ScanWorkerCompletion::new();
    let _completion_guard = completion.guard();
    store.attach_worker(handle, scan_task.abort_handle(), completion);
    finish_sprout_scan_task(store, handle, scan_task.await);
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn start_sprout_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    keys: Vec<SecretString>,
    review_id: Option<WalletReviewId>,
    passphrase: Option<SecretString>,
    network: String,
    data_dir: String,
    lightwalletd_url: String,
    confirmation_sources: Option<Vec<String>>,
    peers: Vec<String>,
    birthday_floor: Option<u32>,
    decrypt_every_block: Option<bool>,
) -> Result<SproutScanHandle, String> {
    ensure_tos_accepted(&app)?;
    let network = sprout_network(&network)?;
    let confirmation_sources = parse_gui_confirmation_sources(
        &lightwalletd_url,
        confirmation_sources.as_deref().unwrap_or(&[]),
    )?;
    let peers = parse_custom_peers(&peers)?;

    // The panel offers to use the wallet file's own keys; it now actually
    // can. Previously this took typed keys only, so the one user it exists
    // for — a wallet holding Sprout keys but no note data — was told to
    // leave the box blank and then refused, with no way to see the keys.
    let wallet_snapshot = match review_id.as_ref() {
        Some(review_id) => Some(state.wallet_reviews.verify(review_id)?.1),
        None => None,
    };
    let scan_keys = collect_scan_keys_from_bytes(
        wallet_snapshot.as_ref().map(|snapshot| snapshot.bytes()),
        passphrase.as_ref(),
        &keys,
        network,
    )?;
    // Planned here, not in the worker: the wallet file's `ImportedKeys` are
    // needed only for this decision and die with this command rather than
    // living as long as an hours-long scan.
    let plan = sprout_scan_plan(
        scan_keys.wallet.as_ref(),
        scan_keys.typed.as_slice(),
        network,
        birthday_floor,
        decrypt_every_block.unwrap_or(false),
        argos_core::unix_time_now(),
    );
    let decrypt_line = sprout_plan_line(&plan);
    let decrypt_from = plan.decrypt_from;
    // Before any network step, so the panel says what will be left
    // undecrypted while the hours run, not only at the end.
    let _ = app.emit("sprout-scan-plan", decrypt_line.clone());
    let decoded = scan_keys.all;
    // Blank resolves to the app default, as it does for inspection, preview
    // and sweep — a blank field must not write a CWD-relative checkpoint that
    // those then never find.
    let dir = resolve_data_dir(&app, Some(&data_dir))?;
    let store = state.reviewed_intent.clone();
    let (handle, material, checkpoint_reservation) = begin_sprout_scan_session(
        &store,
        decoded,
        &dir,
        network,
        lightwalletd_url,
        confirmation_sources,
        peers,
    )?;
    let worker_handle = handle.clone();
    let scan_app = app.clone();
    let progress_handle = worker_handle.clone();
    let scan_task = tokio::spawn(async move {
        let _checkpoint_reservation = checkpoint_reservation;
        let (tip_anchor, tip_warning) =
            sprout_tip_anchor(material.network, &material.lightwalletd_url).await;
        let tip_height = tip_anchor.as_ref().map(|anchor| anchor.height);
        let emitter = scan_app;
        let p2p: argos_core::p2p::wire::P2pNetwork = material.network.into();
        argos_core::sprout_scan_run::run_sprout_scan_with_decrypt_from(
            material.keys.as_slice(),
            p2p,
            &material.peers,
            tip_anchor,
            &material.checkpoint,
            decrypt_from,
            move |tick| {
                let _ = emitter.emit(
                    "sprout-scan-progress",
                    SproutScanProgressEvent {
                        handle: progress_handle.clone(),
                        height: tick.height,
                        target: tick.target,
                        notes_found: tick.notes_found,
                        joinsplits_seen: tick.joinsplits_seen,
                        peer_wait: tick.peer_wait.map(|wait| wait.to_string()),
                    },
                );
            },
        )
        .await
        .map_err(|err| err.to_string())
        .and_then(|result| {
            let journal_dir = argos_core::sprout_scan_run::checkpoint_data_dir(
                &material.checkpoint,
                material.keys.as_slice(),
                material.network.into(),
            )
            .map_err(|err| err.to_string())?;
            let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
                journal_dir,
                material.keys.as_slice(),
                material.network,
            );
            let outpoints = result
                .notes
                .iter()
                .map(|note| note.outpoint)
                .collect::<Vec<_>>();
            let snapshot = journal
                .load_scoped_snapshot(&outpoints)
                .map_err(|err| err.to_string())?;
            let has_lifecycle_status = snapshot.entries().next().is_some();
            Ok(SproutScanReport {
                blocks_scanned: result.progress.blocks_scanned,
                joinsplits_seen: result.progress.joinsplits_seen,
                notes_found: result.notes.len(),
                spent_notes: result.spent_notes,
                total_zatoshis: result.total_value(),
                has_lifecycle_status,
                tip_warning,
                decrypt_from_height: result.decrypt_from_height,
                // The plan line promised a skip the scan did not apply;
                // replace it rather than leave the panel saying otherwise.
                decrypt_line: argos_core::sprout_scan_run::dropped_bound_line(
                    decrypt_from,
                    tip_height,
                )
                .unwrap_or(decrypt_line),
            })
        })
    });
    let abort = scan_task.abort_handle();
    let completion = ScanWorkerCompletion::new();
    let completion_guard = completion.guard();
    let supervisor_store = store.clone();
    let supervisor_handle = worker_handle.clone();
    tokio::spawn(async move {
        let _completion_guard = completion_guard;
        finish_sprout_scan_task(&supervisor_store, &supervisor_handle, scan_task.await);
        if let Ok(snapshot) = supervisor_store.snapshot(&supervisor_handle) {
            let _ = app.emit("sprout-scan-complete", snapshot);
        }
    });
    // Attach before returning the handle. Release can therefore abort the
    // scan and wait for the supervisor to observe its drop before it reports
    // that the secret session is gone.
    store.attach_worker(&worker_handle, abort, completion);
    Ok(handle)
}

#[tauri::command]
pub fn get_sprout_scan(
    state: State<'_, AppState>,
    handle: SproutScanHandle,
) -> Result<SproutScanSnapshot, String> {
    state.reviewed_intent.snapshot(&handle)
}

#[tauri::command]
pub async fn release_sprout_scan(
    state: State<'_, AppState>,
    handle: SproutScanHandle,
) -> Result<(), String> {
    state.reviewed_intent.release_scan(&handle).await
}

#[tauri::command]
pub fn release_sprout_proposal(
    state: State<'_, AppState>,
    proposal_id: SproutProposalId,
) -> Result<(), String> {
    state.reviewed_intent.release_proposal(&proposal_id)
}

/// Learn a block near the tip from lightwalletd for the scan to match, and
/// the caveat to show if that failed. Best-effort, as in the CLI: the scan
/// runs either way, but the user must know which kind of result they got.
async fn sprout_tip_anchor(
    network: ZeckNetwork,
    lightwalletd_url: &str,
) -> (
    Option<argos_core::sprout_scan_run::TipAnchor>,
    Option<String>,
) {
    match argos_core::sprout_scan_run::independent_tip_anchor(network, lightwalletd_url).await {
        Ok(anchor) => (Some(anchor), None),
        Err(err) => (
            None,
            Some(argos_core::sprout_scan_run::unconfirmed_tip_warning(
                network.into(),
                &err.to_string(),
            )),
        ),
    }
}

/// The sweep goes through lightwalletd, which `sweep_sprout_notes` probes
/// only after the catch-up scan. A server address that cannot work is
/// refused here, before that scan, as the CLI does. Syntax only: an
/// unreachable or wrong-network server is still caught by that probe.
fn validate_sweep_endpoint(lightwalletd_url: &str) -> Result<(), String> {
    argos_core::lightwalletd::validated_lightwalletd_endpoints(lightwalletd_url)
        .map(|_| ())
        .map_err(|err| {
            format!(
                "the sweep is broadcast through the lightwalletd server, and that address \
                 cannot work ({err}). Fix it before sweeping."
            )
        })
}

/// What a sweep can be refused for on its own inputs: a destination with no
/// Sapling receiver, or a server address that cannot work. Neither needs the
/// keys, so both are checked before the wallet file is decrypted.
fn validate_sweep_request(
    destination: &str,
    network: ZeckNetwork,
    lightwalletd_url: &str,
) -> Result<(), String> {
    argos_core::sprout_sweep::parse_sapling_destination(destination, network)
        .map_err(|err| err.to_string())?;
    validate_sweep_endpoint(lightwalletd_url)
}

/// A sweep's outcome, for the frontend.
///
/// `tip_warning` leads the warnings when the catch-up scan before a sweep
/// could not confirm it reached the chain tip: a user told nothing would
/// take the result for a confirmed one.
fn sprout_sweep_report(
    mut outcome: argos_core::sprout_sweep::SproutSweepOutcome,
) -> SproutSweepReport {
    let keep_source = !outcome.fresh_all_mined
        || !outcome.skipped.is_empty()
        || !outcome.rejected.is_empty()
        || outcome.error.is_some();
    if keep_source
        && !outcome
            .warnings
            .iter()
            .any(|warning| warning == SPROUT_KEEP_SOURCE_WARNING)
    {
        outcome.warnings.push(SPROUT_KEEP_SOURCE_WARNING.to_owned());
    }
    SproutSweepReport {
        transactions: outcome
            .transactions
            .into_iter()
            .map(|transaction| SproutSweepResult {
                txid: transaction.txid,
                value_zatoshis: transaction.value_zatoshis,
                state: transaction.state,
                mined_height: transaction.mined_height,
                superseded: transaction.superseded,
            })
            .collect(),
        mined_zatoshis: outcome.mined_zatoshis,
        pending_zatoshis: outcome.pending_zatoshis,
        unknown_zatoshis: outcome.unknown_zatoshis,
        skipped: outcome.skipped,
        rejected: outcome.rejected.iter().map(|r| r.to_string()).collect(),
        warnings: outcome.warnings,
        error: outcome.error,
        fresh_all_mined: outcome.fresh_all_mined,
    }
}

/// Catch up the exact saved scan and store the resulting notes for review.
fn begin_sprout_catchup(
    store: &ReviewedIntentStore,
    handle: &SproutScanHandle,
) -> Result<(ScanMaterial, CheckpointReservation, ScanCatchupLease), String> {
    store.ensure_scan_proposal_capacity(handle)?;
    let catchup = store.register_catchup(handle)?;
    let material = store.scan_material(handle)?;
    if argos_core::sprout_scan_run::key_set_fingerprint(material.keys.as_slice())
        != material.key_fingerprint
    {
        return Err("Sprout scan key identity changed".into());
    }
    let reservation = store.reserve_checkpoint(&material.checkpoint)?;
    Ok((material, reservation, catchup))
}

#[tauri::command]
pub async fn propose_sprout_scan_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    scan_handle: SproutScanHandle,
    destination: String,
) -> Result<ReviewedSproutSweep, String> {
    ensure_tos_accepted(&app)?;
    let (material, checkpoint_reservation, catchup) =
        begin_sprout_catchup(&state.reviewed_intent, &scan_handle)?;
    let work = async move {
        // Checked before the catch-up: an address with no Sapling receiver or a
        // server address that cannot work should fail here, not after it.
        validate_sweep_request(&destination, material.network, &material.lightwalletd_url)?;
        let dir = argos_core::sprout_scan_run::checkpoint_data_dir(
            &material.checkpoint,
            material.keys.as_slice(),
            material.network.into(),
        )
        .map_err(|err| err.to_string())?;
        let mut journal = argos_core::sprout_sweep::SweepJournal::for_keys(
            dir,
            material.keys.as_slice(),
            material.network,
        );
        if let Some(recovered) =
            argos_core::sprout_sweep::resume_interrupted_scan_checkpoint_cleanup(
                &material.checkpoint,
                &journal,
                material.network,
            )
            .map_err(|err| err.to_string())?
        {
            return Err(match recovered {
            argos_core::sprout_sweep::ScanCheckpointCleanup::Removed
            | argos_core::sprout_sweep::ScanCheckpointCleanup::AlreadyAbsent => {
                "Argos completed an interrupted cleanup of the prior Sprout checkpoint. Start a fresh scan before proposing another sweep.".to_owned()
            }
            argos_core::sprout_sweep::ScanCheckpointCleanup::Retained(reason) => {
                format!("interrupted checkpoint cleanup was retained: {reason}")
            }
        });
        }
        // The resume continues under the bound the scan actually used, read
        // from its checkpoint, never one supplied by the form: the birthday
        // there may have changed since the scan, and a lower one would make the
        // resume conflict after hours of scanning. Lowering it means a new scan.
        let Some(decrypt_from) = argos_core::sprout_scan_run::saved_decrypt_from(
            &material.checkpoint,
            material.network.into(),
            material.keys.as_slice(),
        )
        .map_err(|err| err.to_string())?
        else {
            return Err(
                "no saved scan was found for these keys. Run the scan first — its results are \
             what this sweeps."
                    .to_owned(),
            );
        };
        let (tip_anchor, tip_warning) =
            sprout_tip_anchor(material.network, &material.lightwalletd_url).await;
        let emitter = app.clone();
        let progress_handle = scan_handle.clone();
        let p2p: argos_core::p2p::wire::P2pNetwork = material.network.into();
        let result = argos_core::sprout_scan_run::run_sprout_scan_with_decrypt_from(
            material.keys.as_slice(),
            p2p,
            &material.peers,
            tip_anchor,
            &material.checkpoint,
            decrypt_from,
            move |tick| {
                let _ = emitter.emit(
                    "sprout-scan-progress",
                    SproutScanProgressEvent {
                        handle: progress_handle.clone(),
                        height: tick.height,
                        target: tick.target,
                        notes_found: tick.notes_found,
                        joinsplits_seen: tick.joinsplits_seen,
                        peer_wait: tick.peer_wait.map(|wait| wait.to_string()),
                    },
                );
            },
        )
        .await
        .map_err(|err| err.to_string())?;
        let outpoints = result
            .notes
            .iter()
            .map(|note| note.outpoint)
            .collect::<Vec<_>>();
        let snapshot = journal
            .load_scoped_snapshot(&outpoints)
            .map_err(|err| err.to_string())?;
        let plan = sprout_sweep_preview(&result.notes, &snapshot)?;
        let plan_empty = plan.notes == 0 && plan.active.is_empty() && plan.mined.is_empty();
        if let Some(message) = empty_sprout_proposal_error(
            SproutProposalOrigin::SavedScan,
            plan_empty,
            snapshot.entries().map(|entry| entry.state),
        ) {
            return Err(message);
        }
        if plan_empty {
            return Err("the saved scan found no unspent Sprout notes to sweep".into());
        }
        let checkpoint_authority = argos_core::sprout_sweep::prepare_scan_checkpoint_authority(
            &material.checkpoint,
            result
                .checkpoint_generation
                .as_ref()
                .ok_or("the completed scan did not return a checkpoint generation")?,
            &mut journal,
            &result.notes,
            material.network,
        )
        .map_err(|err| err.to_string())?;
        state.reviewed_intent.insert_proposal(
            SproutSweepIntent {
                source: SproutIntentSource::Scan(scan_handle),
                notes: result.notes,
                destination,
                network: material.network,
                lightwalletd_url: material.lightwalletd_url,
                confirmation_sources: material.confirmation_sources,
                journal,
                wallet_checkpoint: None,
                checkpoint_authority: Some(checkpoint_authority),
                _checkpoint_reservation: Some(checkpoint_reservation),
                tip_warning,
                peer_error: None,
            },
            plan,
        )
    };
    tokio::select! {
        result = work => result,
        () = catchup.cancelled() => Err("Sprout scan was released while its catch-up was running".into()),
    }
}

#[tauri::command]
pub async fn execute_sprout_scan_sweep(
    app: AppHandle,
    state: State<'_, AppState>,
    proposal_id: SproutProposalId,
) -> Result<SproutSweepReport, String> {
    ensure_tos_accepted(&app)?;
    let intent = state.reviewed_intent.take_scan_proposal(&proposal_id)?;
    execute_reviewed_sprout_sweep(app, intent).await
}

/// The wallet summary's NU7 warning: empty unless the file holds Sprout keys.
fn summary_nu7_warning(sprout_keys: usize, network_name: &str) -> String {
    if sprout_keys == 0 {
        return String::new();
    }
    argos_core::sprout_sweep::nu7_recovery_warning(network_from(network_name))
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

/// The NU7 warning text, re-fetched by the frontend when the network picker
/// changes after a wallet was opened, and after a Sprout sweep broadcast
/// (`broadcast`), when the advice becomes "confirm it is mined".
#[tauri::command]
pub fn sprout_nu7_warning(network: String, broadcast: bool) -> String {
    let network = network_from(&network);
    if broadcast {
        argos_core::sprout_sweep::nu7_broadcast_warning(network)
    } else {
        argos_core::sprout_sweep::nu7_recovery_warning(network)
    }
}

// Not gated on `sprout`: `check_sapling_key` is a core-Sapling command and
// needs this too. It is a plain string-to-enum mapping with no Sprout
// dependency of its own.
fn parse_wallet_network(name: &str) -> Result<argos_core::ZeckNetwork, String> {
    match name {
        "mainnet" => Ok(argos_core::ZeckNetwork::Mainnet),
        "testnet" => Ok(argos_core::ZeckNetwork::Testnet),
        _ => Err("unrecognized wallet network; select mainnet or testnet".to_owned()),
    }
}

/// Lenient: anything but "testnet" is mainnet. For display and checks that
/// cannot move funds; paths that spend use the strict [`sprout_network`].
fn network_from(name: &str) -> argos_core::ZeckNetwork {
    sprout_network(name).unwrap_or(argos_core::ZeckNetwork::Mainnet)
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

/// Recovery for opening a wallet (`inspect_wallet_file`), which makes no
/// network contact: a saved scan is named, not used, until a sweep preview
/// verifies it against live peers. Its own function so the no-network
/// wiring is tested rather than only the lower layer it delegates to.
async fn recover_for_wallet_open(
    keys: &argos_core::argos_wallet_import::ImportedKeys,
    network: argos_core::ZeckNetwork,
    dir: Option<PathBuf>,
) -> argos_core::sprout_recovery::SproutRecovery {
    recover_with_scan_in_dir(keys, network, dir, None).await
}

/// Recovery for a sweep preview. A malformed entry in the scan panel's peer
/// field does not fail the preview: live verification is skipped, so no
/// network attempt is made and an unverified scan supplies no spent verdict
/// (fail closed), the wallet file's own record stands, and the reason leads
/// the preview's scan warning. The sweep itself still refuses the field.
async fn recover_for_sweep_preview(
    keys: &argos_core::argos_wallet_import::ImportedKeys,
    network: argos_core::ZeckNetwork,
    dir: Option<PathBuf>,
    raw_peers: &[String],
) -> argos_core::sprout_recovery::SproutRecovery {
    match parse_custom_peers(raw_peers) {
        Ok(peers) => recover_with_scan_in_dir(keys, network, dir, Some(&peers)).await,
        Err(err) => {
            let mut recovered = recover_with_scan_in_dir(keys, network, dir, None).await;
            let line = format!(
                "The scan panel's peers were not used: {err} No saved scan was verified \
                 for this preview, so spent status is the wallet file's own record. Fix \
                 the peer field before sweeping."
            );
            recovered.chain_notice = Some(match recovered.chain_notice.take() {
                Some(notice) => format!("{line} {notice}"),
                None => line,
            });
            recovered
        }
    }
}

/// Recover a wallet file's Sprout notes, letting a full-block scan of the
/// same keys settle every spend it saw on chain. Looks in the data directory
/// the scan panel writes to (the field, else the app default), so a scan run
/// from this app is found without asking. The scan is optional: without one,
/// or with one that cannot be used, the file's own record stands, and the
/// reason is shown rather than failing the wallet screen.
///
/// `peers` is `None` for wallet inspection, which makes no network contact:
/// a saved scan is then named but its evidence is not used. A sweep passes
/// the user's peer list (possibly empty), dialled before the DNS seeds, to
/// verify the scan's cursor against live headers first.
async fn recover_with_scan_in_dir(
    keys: &argos_core::argos_wallet_import::ImportedKeys,
    network: argos_core::ZeckNetwork,
    dir: Option<PathBuf>,
    peers: Option<&[String]>,
) -> argos_core::sprout_recovery::SproutRecovery {
    let spending_keys = wallet_sprout_keys(keys);
    // The lookup's notice is shown on the wallet screen, not logged: a scan
    // that exists but cannot be used must not look like no scan at all.
    let (chain, notice) = match (&dir, peers) {
        (Some(dir), None) => (
            None,
            argos_core::sprout_scan_run::wallet_scan_notice_offline(
                dir,
                network.into(),
                spending_keys.as_slice(),
            ),
        ),
        (Some(dir), Some(peers)) => {
            argos_core::sprout_scan_run::chain_spends_for_wallet(
                dir,
                network.into(),
                spending_keys.as_slice(),
                peers,
            )
            .await
        }
        (None, _) => (None, None),
    };
    let mut recovered = argos_core::sprout_recovery::recover_spendable_sprout_notes_with_chain(
        keys,
        chain.as_deref(),
    );
    recovered.chain_notice = notice;
    recovered
}

/// The data directory the scan panel writes to: the field, else the app
/// default.
fn with_resolved_sprout_data_dir<T>(
    resolved: Result<PathBuf, String>,
    next: impl FnOnce(&Path) -> Result<T, String>,
) -> Result<T, String> {
    let dir = resolved?;
    argos_core::service::ensure_recovery_data_dir(&dir).map_err(|err| err.to_string())?;
    next(&dir)
}

fn resolve_data_dir(app: &AppHandle, data_dir: Option<&str>) -> Result<PathBuf, String> {
    match data_dir.map(str::trim).filter(|d| !d.is_empty()) {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => default_data_dir(app.clone()).map(PathBuf::from),
    }
}

/// The wallet file's Sprout spending keys, as the checkpoint and the sweep
/// journal are keyed.
fn wallet_sprout_keys(keys: &argos_core::argos_wallet_import::ImportedKeys) -> SecretSproutKeys {
    use secrecy::ExposeSecret;
    let mut spending_keys = Vec::with_capacity(keys.sprout.len());
    spending_keys.extend(keys.sprout.iter().map(|k| *k.a_sk.expose_secret()));
    SecretSproutKeys::new(spending_keys)
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
        // Not the Sprout paste box: the birthday field drives the Sapling
        // scan, which reads no Sprout keys from it.
        BirthdayRoute::WalletDat { keys, pasted } => {
            let found = argos_core::detect_wallet_file_birthday(
                &keys,
                &[],
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
    pub seed: SecretString,
    #[serde(default)]
    pub passphrase: Option<SecretString>,
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
) -> Result<ResumeSessionResult, String> {
    ensure_tos_accepted(&app)?;
    let confirmation_sources =
        parse_gui_confirmation_sources(&input.lightwalletd_url, &input.confirmation_sources)?;
    let workspace_path = PathBuf::from(input.workspace_path.trim());
    if workspace_path.as_os_str().is_empty() {
        return Err("workspace path cannot be empty".to_owned());
    }
    let seed_phrase = input.seed;
    let keying = parse_workspace_keying(&workspace_path).map_err(|err| err.to_string())?;
    let data_dir = data_dir_from_workspace(&workspace_path)
        .ok_or_else(|| "workspace path is not under a recognizable data dir".to_owned())?;

    let label = input
        .label
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
    let handle = if let Some(coordinates) = metadata.and_then(|m| m.match_coordinates) {
        let passphrase = input
            .passphrase
            .unwrap_or_else(|| SecretString::new(String::new()));
        let seed = argos_core::address_search::candidate_seed(&seed_phrase, &passphrase)
            .map_err(|err| err.to_string())?;
        let key_source =
            argos_core::prepare_match_recovery(seed.expose_secret(), keying.network, coordinates)
                .map_err(|err| err.to_string())?;
        argos_core::workspace::verify_key_source_for_workspace(
            &workspace_path,
            key_source.as_ref(),
        )
        .map_err(|err| err.to_string())?;
        state
            .service
            .start_scan_from_key_source(scan_config, key_source)
            .await
    } else {
        if input
            .passphrase
            .as_ref()
            .is_some_and(|p| !p.expose_secret().is_empty())
        {
            return Err("this scan was created without a BIP-39 passphrase".to_owned());
        }
        verify_seed_for_workspace(&workspace_path, &seed_phrase).map_err(|err| err.to_string())?;
        state.service.start_scan(scan_config, seed_phrase).await
    }
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
    use super::{sprout_nu7_warning, summary_nu7_warning};

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

    fn unused_artifact_data_dir(label: &str) -> std::path::PathBuf {
        unused_temp_dir(label)
            .join("publication")
            .join("recovery-data")
    }

    fn remove_artifact_fixture(data_dir: &std::path::Path) {
        let outer = data_dir
            .parent()
            .and_then(std::path::Path::parent)
            .expect("artifact fixture has publication and outer parents");
        if outer.exists() {
            std::fs::remove_dir_all(outer).unwrap();
        }
    }

    #[test]
    fn validate_seed_accepts_protected_words_at_the_ipc_boundary() {
        let words = vec![secrecy::SecretString::new("abandon".to_owned()); 24];
        let future = super::validate_seed(words);
        drop(future);
    }

    fn preview_note(value: u64, id: u8) -> argos_core::sprout_recovery::SpendableSproutNote {
        let a_sk = [0x42; 32];
        let address = argos_core::sprout::SproutPaymentAddress::from_spending_key(&a_sk);
        let rho = [0x11; 32];
        let r = [0x22; 32];
        argos_core::sprout_recovery::SpendableSproutNote {
            note: argos_core::sprout::SproutNotePlaintext {
                value,
                rho,
                r,
                memo: [0; 512],
            },
            a_sk,
            address,
            commitment: argos_core::sprout::note_commitment(address.a_pk(), value, &rho, &r),
            anchor: [0; 32],
            witness_path: vec![0; argos_core::sprout_witness::WITNESS_PATH_SIZE],
            outpoint: argos_core::argos_wallet_import::keys::JsOutPoint {
                txid: [id; 32],
                js_index: 0,
                output_index: 0,
            },
        }
    }

    fn test_sprout_journal(marker: u8) -> argos_core::sprout_sweep::SweepJournal {
        argos_core::sprout_sweep::SweepJournal::for_keys(
            &unused_artifact_data_dir("command-journal"),
            &[[marker; 32]],
            argos_core::ZeckNetwork::Mainnet,
        )
    }

    fn append_unknown_journal_entry(
        journal: &argos_core::sprout_sweep::SweepJournal,
        snapshot: &mut argos_core::sprout_sweep::SproutJournalSnapshot,
        outpoint: argos_core::argos_wallet_import::keys::JsOutPoint,
        value_zatoshis: u64,
        fixture: usize,
    ) {
        use argos_core::broadcast::BroadcastStore as _;

        let (txid, raw_tx) = match fixture {
            0 => (
                zcash_primitives::transaction::TxId::from_bytes([
                    0xb6, 0x87, 0xca, 0x64, 0xc4, 0x39, 0xe3, 0xc6, 0x0e, 0x5f, 0x72, 0x31, 0x13,
                    0x88, 0xd9, 0x8b, 0x54, 0x3e, 0xa7, 0xe0, 0xd1, 0xa4, 0x50, 0x61, 0x44, 0x99,
                    0xae, 0xbf, 0xc1, 0xd5, 0x78, 0x1a,
                ]),
                vec![
                    0x05, 0x00, 0x00, 0x80, 0x0a, 0x27, 0xa7, 0x26, 0xb4, 0xd0, 0xd6, 0xc2, 0x00,
                    0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            1 => (
                zcash_primitives::transaction::TxId::from_bytes([
                    0xd6, 0xe3, 0xf6, 0xc6, 0x75, 0xca, 0xac, 0xdb, 0x2e, 0x4d, 0xeb, 0x56, 0xe9,
                    0x73, 0xf2, 0x1d, 0xf3, 0x89, 0x17, 0xf3, 0x21, 0x71, 0xd6, 0x36, 0xa1, 0x91,
                    0x2b, 0x8c, 0x28, 0x65, 0x19, 0xe2,
                ]),
                vec![
                    0x05, 0x00, 0x00, 0x80, 0x0a, 0x27, 0xa7, 0x26, 0xb4, 0xd0, 0xd6, 0xc2, 0x01,
                    0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            _ => panic!("unsupported transaction fixture"),
        };
        let transaction = argos_core::broadcast::PreparedTransaction {
            txid,
            raw_tx,
            fee_zatoshis: 20_000,
            expiry_height: Some(100),
        };
        journal
            .scoped_store(
                argos_core::sprout_sweep_journal::JournalNoteContext {
                    outpoint,
                    value_zatoshis,
                },
                snapshot,
            )
            .persist_prepared(&transaction)
            .unwrap();
        journal
            .append_transition(
                snapshot,
                transaction.txid,
                argos_core::TxLifecycleState::SubmissionUnknown,
                Some(&argos_core::broadcast::SubmissionDisposition::AmbiguousTransport),
                None,
            )
            .unwrap();
    }

    fn test_wallet_source() -> std::sync::Arc<crate::reviewed_intent::ReviewedWalletSource> {
        let registry = crate::reviewed_intent::WalletReviewRegistry::default();
        let dir =
            std::env::temp_dir().join(format!("argos-command-wallet-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        std::fs::write(&path, b"wallet").unwrap();
        let snapshot = argos_core::wallet_file::read_wallet_snapshot(&path).unwrap();
        let id = registry
            .register(path, std::sync::Arc::new(snapshot.identity().clone()))
            .unwrap();
        registry.resolve(&id).unwrap()
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
    fn wallet_review_rejects_changed_file_for_sprout_proposal() {
        let (registry, id, path) = test_wallet_review();
        std::fs::write(path, b"wallet-B").unwrap();
        assert!(registry.verify(&id).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn wallet_review_rejects_replaced_file_before_sprout_execute() {
        let (registry, id, path) = test_wallet_review();
        let source = registry.resolve(&id).unwrap();
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, b"wallet-A").unwrap();
        std::fs::rename(replacement, path).unwrap();
        assert!(registry.verify_source(&source).is_err());

        let code = include_str!("commands.rs");
        let execute = code
            .split("pub async fn execute_wallet_sprout_sweep")
            .nth(1)
            .unwrap();
        assert!(
            execute.find("wallet_reviews.verify_source").unwrap()
                < execute.find("execute_reviewed_sprout_sweep").unwrap(),
            "wallet verification must precede checkpoint, proving and send work"
        );
    }

    #[test]
    fn sprout_javascript_bindings_forward_confirmation_sources() {
        let javascript = include_str!("../../src/main.js");
        for command in ["propose_wallet_sprout_sweep", "start_sprout_scan"] {
            let start = javascript
                .find(&format!("invoke(\"{command}\""))
                .unwrap_or_else(|| panic!("missing {command} binding"));
            let payload = &javascript[start..javascript.len().min(start + 1_200)];
            let expected = if command == "propose_wallet_sprout_sweep" {
                "confirmationSources: previewConfig.confirmationSources,"
            } else {
                "confirmationSources: confirmationSourcesFromForm(),"
            };
            assert!(
                payload.contains(expected),
                "{command} omits the independently administered confirmation sources"
            );
        }
        assert!(javascript.contains("confirmationSources: confirmationSourcesFromForm(),"));
    }

    /// PR #263 review item 4: the wallet summary carries the NU7 warning
    /// only when the file holds Sprout keys, and for the network asked for.
    #[test]
    fn summary_nu7_warning_is_empty_without_sprout_keys() {
        assert_eq!(summary_nu7_warning(0, "mainnet"), "");
        assert_eq!(summary_nu7_warning(0, "testnet"), "");
    }

    #[test]
    fn summary_nu7_warning_follows_the_selected_network() {
        let mainnet = summary_nu7_warning(1, "mainnet");
        assert!(mainnet.contains("November 5, 2026"), "{mainnet}");
        assert!(!mainnet.contains("4,465,026"), "{mainnet}");
        let testnet = summary_nu7_warning(2, "testnet");
        assert!(testnet.contains("4,465,026"), "{testnet}");
        assert!(!testnet.contains("November 5"), "{testnet}");
    }

    /// PR #263 review items 2 and 3: the GUI re-fetches the warning when the
    /// network changes, and after a broadcast switches to the mining wording.
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

    #[test]
    fn sprout_nu7_warning_command_picks_network_and_broadcast_wording() {
        let before = sprout_nu7_warning("testnet".into(), false);
        assert!(before.contains("4,465,026"), "{before}");
        let after = sprout_nu7_warning("mainnet".into(), true);
        assert!(after.contains("confirm it is mined"), "{after}");
        assert!(!after.contains("Start recovery promptly"), "{after}");
        let start = sprout_nu7_warning("mainnet".into(), false);
        assert!(start.contains("Start recovery promptly"), "{start}");
    }

    #[test]
    fn scan_keys_skip_comments_and_blank_lines() {
        let typed = vec![
            SecretString::new("# note".to_string()),
            SecretString::new(String::new()),
            SecretString::new("  # indented".to_string()),
        ];
        // Comments are skipped rather than decoded, so what remains is the
        // "nothing to scan" refusal, not a bad-key error on line 1.
        let err = super::collect_scan_keys(None, None, &typed, argos_core::ZeckNetwork::Mainnet)
            .err()
            .expect("refused");
        assert!(err.starts_with("no Sprout spending keys"), "{err}");
    }

    #[test]
    fn scan_key_error_names_the_visible_line() {
        let typed = vec![
            SecretString::new("# note".to_string()),
            SecretString::new(String::new()),
            SecretString::new("not-a-key".to_string()),
        ];
        let err = super::collect_scan_keys(None, None, &typed, argos_core::ZeckNetwork::Mainnet)
            .err()
            .expect("refused");
        assert!(err.starts_with("line 3:"), "{err}");
    }

    use super::{
        refuse_unreachable_sweep_destination, sprout_sweep_report, validate_sweep_endpoint,
        validate_sweep_request,
    };
    use argos_core::argos_wallet_import::{keys::TransparentKey, ImportedKeys, Provenance};
    use argos_core::sprout_recovery::{SpentSproutNote, SproutRecovery};
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
            ("sprout-plaintext.dat", None),
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
            let found = argos_core::wallet_file_birthday_from_metadata(
                &keys,
                &[],
                ZeckNetwork::Mainnet,
                0,
                NOW,
            );
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
            "sprout-plaintext.dat",
            None,
            &[],
            ZeckNetwork::Testnet,
        ));
        let found = argos_core::wallet_file_birthday_from_metadata(
            &keys,
            &[],
            ZeckNetwork::Testnet,
            0,
            NOW,
        );
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
            &[],
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
                    &[],
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
            sprout_skip_height: None,
            sprout_skip_reason: String::new(),
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

    /// The Sprout panel skips only on the wallet's own dated Sprout keys; a
    /// pasted key, testnet, or either opt-out removes or lowers the skip.
    #[test]
    fn the_sprout_panel_skip_follows_the_wallets_own_key_times() {
        let bytes =
            argos_core::wallet_file::read_wallet_file(fixture("sprout-plaintext.dat")).unwrap();
        let wallet = argos_core::argos_wallet_import::import_wallet_file(&bytes, None).unwrap();
        let net = ZeckNetwork::Mainnet;
        let skip = sprout_scan_plan(Some(&wallet), &[], net, None, false, NOW)
            .decrypt_from
            .expect("dated mainnet wallet skips");
        assert!(skip > 1);
        assert_eq!(
            sprout_scan_plan(Some(&wallet), &[[9u8; 32]], net, None, false, NOW).decrypt_from,
            None
        );
        assert_eq!(
            sprout_scan_plan(None, &[[9u8; 32]], net, None, false, NOW).decrypt_from,
            None
        );
        assert_eq!(
            sprout_scan_plan(Some(&wallet), &[], ZeckNetwork::Testnet, None, false, NOW)
                .decrypt_from,
            None
        );
        assert_eq!(
            sprout_scan_plan(Some(&wallet), &[], net, None, true, NOW).decrypt_from,
            None
        );
        assert_eq!(
            sprout_scan_plan(Some(&wallet), &[], net, Some(1_000), false, NOW).decrypt_from,
            Some(1_000)
        );
        assert_eq!(
            sprout_scan_plan(Some(&wallet), &[], net, Some(skip + 5), false, NOW).decrypt_from,
            Some(skip)
        );
    }

    /// The same rule at the propose path itself, not only its helper: a
    /// forged key is dropped and reported, and the proposal goes on with the
    /// genuine keys. The fixture holds no funded Sprout note (none can be
    /// made; see the fixtures README), so the proposal ends at "no spendable
    /// notes" rather than a review; a refusal on the forged key would fail
    /// before that, with a different error and nothing reported.
    #[tokio::test]
    async fn proposing_from_a_wallet_with_a_forged_key_drops_it_and_carries_on() {
        let bytes =
            argos_core::wallet_file::read_wallet_file(fixture("sprout-plaintext.dat")).unwrap();
        let mut keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None).unwrap();
        let genuine = keys.sprout.len();
        assert!(genuine > 0, "fixture holds Sprout keys");
        let a_sk = *keys.sprout[0].a_sk.expose_secret();
        keys.sprout
            .push(argos_core::argos_wallet_import::keys::SproutKey {
                a_sk: secrecy::Secret::new(a_sk),
                address: [0xAA; 64],
                provenance: Provenance::Standalone,
                created_at: None,
            });
        let store = ReviewedIntentStore::default();
        let reported = std::cell::RefCell::new(Vec::new());
        let dir = unused_artifact_data_dir("forged");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let err = super::propose_wallet_sprout_sweep_core(
            &store,
            test_wallet_source(),
            &mut keys,
            dir.clone(),
            "zs-reviewed".into(),
            ZeckNetwork::Mainnet,
            "https://zec.rocks:443".into(),
            Vec::new(),
            &[],
            |warning| reported.borrow_mut().push(warning.to_owned()),
        )
        .await
        .err()
        .expect("the fixture has no spendable note");
        assert!(err.contains("no spendable Sprout notes"), "{err}");
        assert_eq!(keys.sprout.len(), genuine, "genuine keys are kept");
        let reported = reported.into_inner();
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert!(reported[0].contains("does not control"), "{}", reported[0]);
        remove_artifact_fixture(&dir);
    }

    #[test]
    /// Finding 6 on #271: one forged Sprout key used to refuse the whole
    /// wallet-file sweep while inspect dropped it and warned. The sweep now
    /// does what inspect does: the genuine keys stay, and the forged one is
    /// reported in the review rather than silently ignored.
    fn a_forged_sprout_key_is_dropped_with_a_warning_and_the_rest_kept() {
        let bytes =
            argos_core::wallet_file::read_wallet_file(fixture("sprout-plaintext.dat")).unwrap();
        let mut keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None).unwrap();
        let genuine = keys.sprout.len();
        assert!(genuine > 0, "fixture holds Sprout keys");
        let a_sk = *keys.sprout[0].a_sk.expose_secret();
        keys.sprout
            .push(argos_core::argos_wallet_import::keys::SproutKey {
                a_sk: secrecy::Secret::new(a_sk),
                address: [0xAA; 64],
                provenance: Provenance::Standalone,
                created_at: None,
            });
        let warnings = super::drop_forged_sprout_keys(&mut keys);
        assert_eq!(keys.sprout.len(), genuine, "genuine keys are kept");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("does not control"), "{}", warnings[0]);
    }

    /// The scan and the sweep-from-scan must derive the same key set from
    /// the same inputs, or the sweep would look for a checkpoint under a
    /// different fingerprint. (The bound itself is read from the
    /// checkpoint, not re-derived.)
    #[test]
    fn scan_keys_keep_the_pasted_keys_apart() {
        let keys = collect_scan_keys(
            Some(&relabeled_fixture("sprout-plaintext.dat", "mainnet")),
            None,
            &[],
            ZeckNetwork::Mainnet,
        )
        .unwrap();
        assert!(keys.typed.is_empty());
        assert_eq!(keys.all.len(), keys.wallet.as_ref().unwrap().sprout.len());
    }

    #[tokio::test]
    async fn delete_workspace_command_uses_guarded_recovery_service() {
        use tauri::Manager;
        let app = tauri::test::mock_builder()
            .manage(super::AppState {
                service: argos_core::RecoveryService::new(),
                address_search: argos_core::address_search::AddressSearchService::default(),
                reviewed_intent: crate::reviewed_intent::ReviewedIntentStore::default(),
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

    #[test]
    fn sprout_execution_authority_contains_only_proposal_id() {
        let _wallet: fn(AppHandle, State<'static, AppState>, SproutProposalId) -> _ =
            super::execute_wallet_sprout_sweep;
        let _scan: fn(AppHandle, State<'static, AppState>, SproutProposalId) -> _ =
            super::execute_sprout_scan_sweep;
    }

    #[test]
    fn scan_start_reserves_the_checkpoint_before_inserting_another_session() {
        let store = ReviewedIntentStore::default();
        let dir = std::env::temp_dir().join(format!("argos-scan-start-{}", uuid::Uuid::new_v4()));
        let (handle, _, reservation) = super::begin_sprout_scan_session(
            &store,
            vec![[7; 32]].into(),
            &dir,
            ZeckNetwork::Mainnet,
            "https://node".into(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(super::begin_sprout_scan_session(
            &store,
            vec![[7; 32]].into(),
            &dir,
            ZeckNetwork::Mainnet,
            "https://node".into(),
            Vec::new(),
            Vec::new()
        )
        .is_err());
        assert!(store.snapshot(&handle).is_ok());
        drop(reservation);
    }

    #[test]
    fn catchup_cannot_overlap_its_scans_checkpoint() {
        let store = ReviewedIntentStore::default();
        let dir = std::env::temp_dir().join(format!("argos-catchup-{}", uuid::Uuid::new_v4()));
        let (handle, _, reservation) = super::begin_sprout_scan_session(
            &store,
            vec![[9; 32]].into(),
            &dir,
            ZeckNetwork::Mainnet,
            "https://node".into(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        store.finish_scan(
            &handle,
            Ok(SproutScanReport {
                blocks_scanned: 1,
                joinsplits_seen: 1,
                notes_found: 1,
                spent_notes: 0,
                total_zatoshis: 100_000,
                has_lifecycle_status: false,
                tip_warning: None,
                decrypt_from_height: None,
                decrypt_line: String::new(),
            }),
        );
        assert!(super::begin_sprout_catchup(&store, &handle).is_err());
        drop(reservation);
        assert!(super::begin_sprout_catchup(&store, &handle).is_ok());
    }

    #[test]
    fn full_proposal_store_rejects_catchup_before_work_starts() {
        let store = ReviewedIntentStore::default();
        let dir = std::env::temp_dir().join(format!("argos-cap-{}", uuid::Uuid::new_v4()));
        let (handle, _, reservation) = super::begin_sprout_scan_session(
            &store,
            vec![[10; 32]].into(),
            &dir,
            ZeckNetwork::Mainnet,
            "https://node".into(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        store.finish_scan(
            &handle,
            Ok(SproutScanReport {
                blocks_scanned: 1,
                joinsplits_seen: 1,
                notes_found: 1,
                spent_notes: 0,
                total_zatoshis: 100_000,
                has_lifecycle_status: false,
                tip_warning: None,
                decrypt_from_height: None,
                decrypt_line: String::new(),
            }),
        );
        drop(reservation);
        for _ in 0..crate::reviewed_intent::MAX_PROPOSALS {
            store
                .insert_proposal(
                    SproutSweepIntent {
                        source: SproutIntentSource::Wallet(test_wallet_source()),
                        notes: Vec::new(),
                        destination: "zs-reviewed".into(),
                        network: ZeckNetwork::Mainnet,
                        lightwalletd_url: "https://node".into(),
                        confirmation_sources: Vec::new(),
                        journal: test_sprout_journal(10),
                        wallet_checkpoint: None,
                        checkpoint_authority: None,
                        _checkpoint_reservation: None,
                        tip_warning: None,
                        peer_error: None,
                    },
                    SproutSweepPreviewData {
                        notes: 1,
                        gross_zatoshis: 100_000,
                        fee_zatoshis: 10_000,
                        net_zatoshis: 90_000,
                        active: Vec::new(),
                        mined: Vec::new(),
                    },
                )
                .unwrap();
        }
        assert!(super::begin_sprout_catchup(&store, &handle).is_err());
    }

    #[tokio::test]
    async fn panicked_scan_worker_releases_checkpoint_and_marks_session_failed() {
        let store = ReviewedIntentStore::default();
        let dir = std::env::temp_dir().join(format!("argos-panic-{}", uuid::Uuid::new_v4()));
        let (handle, material, reservation) = super::begin_sprout_scan_session(
            &store,
            vec![[11; 32]].into(),
            &dir,
            ZeckNetwork::Mainnet,
            "https://node".into(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            let _reservation = reservation;
            panic!("simulated scan panic");
            #[allow(unreachable_code)]
            Err::<SproutScanReport, String>("unreachable".into())
        });
        super::finish_sprout_scan_task(&store, &handle, task.await);
        let snapshot = store.snapshot(&handle).unwrap();
        assert!(matches!(
            snapshot.status,
            crate::reviewed_intent::SproutScanStatus::Failed
        ));
        assert!(store.reserve_checkpoint(&material.checkpoint).is_ok());
    }

    fn empty_sprout_summary() -> SproutSummary {
        SproutSummary {
            sprout_keys: 0,
            sprout_addresses: Vec::new(),
            sprout_spendable_notes: 0,
            sprout_spendable_zatoshis: 0,
            sprout_has_lifecycle_status: false,
            sprout_issues: Vec::new(),
            sprout_scan_warning: Vec::new(),
            sprout_accounting: Vec::new(),
            sprout_nothing_left: false,
            sprout_spent_status: String::new(),
            sprout_history_read: false,
        }
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
        serde_json::to_value(wallet_summary_from_keys(
            "test.dat".to_owned(),
            None,
            keys,
            empty_sprout_summary(),
            "mainnet",
        ))
        .unwrap()
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
            empty_sprout_summary(),
            "mainnet",
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

    /// The wiring `start_sprout_scan` uses: a scan run through
    /// `run_attached_scan_worker` is stopped by `release_scan`, freeing its
    /// checkpoint. Without the attach, the never-ending scan below would
    /// keep the driver (and the reservation) alive and the timeout would
    /// fire. Covers both orderings: release after the attach, and release
    /// before the worker task has been polled at all.
    #[tokio::test]
    async fn releasing_a_scan_stops_the_worker_started_for_it() {
        for settle in [true, false] {
            let store = ReviewedIntentStore::default();
            let dir = std::env::temp_dir().join(format!("argos-attach-{}", uuid::Uuid::new_v4()));
            let (handle, material, reservation) = super::begin_sprout_scan_session(
                &store,
                vec![[12; 32]].into(),
                &dir,
                ZeckNetwork::Mainnet,
                "https://node".into(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
            let (driver_store, driver_handle) = (store.clone(), handle.clone());
            let driver = tokio::spawn(async move {
                super::run_attached_scan_worker(&driver_store, &driver_handle, async move {
                    let _reservation = reservation;
                    std::future::pending::<Result<SproutScanReport, String>>().await
                })
                .await;
            });
            if settle {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(store.reserve_checkpoint(&material.checkpoint).is_err());
            store.release_scan(&handle).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), driver)
                .await
                .expect("release stops the attached worker")
                .expect("the driver itself does not panic");
            assert!(
                store.reserve_checkpoint(&material.checkpoint).is_ok(),
                "the released scan's checkpoint is free again"
            );
        }
    }

    #[test]
    fn sweep_refuses_an_unusable_lightwalletd_url_up_front() {
        for bad in ["nonono", "", "http://wallet.example:9067"] {
            let err = validate_sweep_endpoint(bad).expect_err(bad);
            assert!(err.contains("lightwalletd"), "{bad}: {err}");
        }
        validate_sweep_endpoint("https://zec.rocks:443").expect("a real endpoint passes");
    }

    #[test]
    fn the_tip_warning_leads_the_sweep_report() {
        let mut outcome = argos_core::sprout_sweep::SproutSweepOutcome {
            warnings: vec!["journal".to_owned()],
            fresh_all_mined: true,
            ..Default::default()
        };
        apply_sprout_tip_warning(&mut outcome, Some("tip unconfirmed".to_owned()));
        assert!(!outcome.fresh_all_mined);
        let report = sprout_sweep_report(outcome);
        assert_eq!(
            report.warnings,
            vec![
                "tip unconfirmed",
                "journal",
                "Keep the original wallet or Sprout key and the scan checkpoint. Broadcast is not confirmation."
            ]
        );

        // A tip the catch-up scan did confirm adds nothing.
        let report = sprout_sweep_report(argos_core::sprout_sweep::SproutSweepOutcome {
            warnings: vec!["journal".to_owned()],
            fresh_all_mined: true,
            ..Default::default()
        });
        assert_eq!(report.warnings, vec!["journal"]);

        let mut outcome = argos_core::sprout_sweep::SproutSweepOutcome {
            fresh_all_mined: true,
            ..Default::default()
        };
        apply_checkpoint_cleanup_error(&mut outcome, &"directory sync failed");
        let report = sprout_sweep_report(outcome);
        assert!(!report.fresh_all_mined);
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("Checkpoint cleanup failed")
                && warning.contains("directory sync failed")
        }));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning == SPROUT_KEEP_SOURCE_WARNING));
    }

    #[test]
    fn wallet_and_scan_commands_share_the_same_lifecycle_report_adapter() {
        let outcome = argos_core::sprout_sweep::SproutSweepOutcome {
            transactions: vec![
                argos_core::sprout_sweep::SproutSweepTransaction {
                    txid: "pending".to_owned(),
                    value_zatoshis: Some(7),
                    state: argos_core::TxLifecycleState::Pending,
                    mined_height: None,
                    superseded: false,
                },
                argos_core::sprout_sweep::SproutSweepTransaction {
                    txid: "unknown".to_owned(),
                    value_zatoshis: None,
                    state: argos_core::TxLifecycleState::SubmissionUnknown,
                    mined_height: None,
                    superseded: false,
                },
                argos_core::sprout_sweep::SproutSweepTransaction {
                    txid: "mined".to_owned(),
                    value_zatoshis: Some(11),
                    state: argos_core::TxLifecycleState::Mined,
                    mined_height: Some(123),
                    superseded: false,
                },
            ],
            mined_zatoshis: 11,
            pending_zatoshis: 7,
            fresh_all_mined: false,
            ..Default::default()
        };
        let wallet = super::sprout_sweep_report(outcome.clone());
        let scan = super::sprout_sweep_report(outcome);
        let wallet = serde_json::to_value(wallet).unwrap();
        let scan = serde_json::to_value(scan).unwrap();
        assert_eq!(wallet, scan);
        assert!(
            wallet.get("landed_in_unified_sapling").is_none(),
            "post-execution reports cannot attribute a historical transaction to the current destination"
        );
    }

    #[test]
    fn sprout_summary_and_preview_count_only_executable_ready_notes() {
        use argos_core::broadcast::{EndpointTxEvidence, TxObservation, TxObservationState};

        let journal = test_sprout_journal(0x42);
        let mut snapshot = journal.load_or_migrate().unwrap();
        let recovered = [preview_note(1_000_000, 0x11), preview_note(2_000_000, 0x12)];
        append_unknown_journal_entry(
            &journal,
            &mut snapshot,
            recovered[0].outpoint,
            recovered[0].note.value,
            0,
        );
        append_unknown_journal_entry(
            &journal,
            &mut snapshot,
            recovered[1].outpoint,
            recovered[1].note.value,
            1,
        );
        let mined_txid = snapshot
            .entries()
            .find(|entry| entry.outpoint.txid == [0x12; 32])
            .expect("second authorized entry")
            .txid();
        let observation = TxObservation {
            state: TxObservationState::Mined,
            mined_height: Some(100),
            expiry_height: None,
            primary_tip: Some(110),
            secondary_tip: Some(110),
            evidence: ["alpha", "bravo"]
                .into_iter()
                .map(|operator| EndpointTxEvidence {
                    operator_id: operator.to_owned(),
                    endpoint: format!("https://{operator}.example"),
                    tip_height: Some(110),
                    reported_height: Some(100),
                    block_hash: Some(vec![0x55; 32]),
                    tx_in_block: true,
                })
                .collect(),
        };
        journal
            .append_transition(
                &mut snapshot,
                mined_txid,
                argos_core::TxLifecycleState::Mined,
                None,
                Some(&observation),
            )
            .unwrap();

        let (notes, value, lifecycle) = sprout_ready_summary(&recovered, &snapshot).unwrap();
        assert_eq!((notes, value, lifecycle), (0, 0, true));

        let preview = sprout_sweep_preview(&recovered, &snapshot).unwrap();
        assert_eq!((preview.notes, preview.gross_zatoshis), (0, 0));
        assert_eq!((preview.active.len(), preview.mined.len()), (1, 1));

        let dust = [preview_note(
            argos_core::sprout_sweep::SPROUT_SWEEP_FEE,
            0x31,
        )];
        let preview = sprout_sweep_preview(
            &dust,
            &argos_core::sprout_sweep::SproutJournalSnapshot::default(),
        )
        .unwrap();
        assert_eq!((preview.notes, preview.gross_zatoshis), (0, 0));

        let huge = [preview_note(u64::MAX, 0x41), preview_note(u64::MAX, 0x42)];
        let preview = sprout_sweep_preview(
            &huge,
            &argos_core::sprout_sweep::SproutJournalSnapshot::default(),
        )
        .expect("preview aggregation must not panic or wrap");
        assert_eq!(preview.gross_zatoshis, u64::MAX);
        remove_artifact_fixture(journal.data_dir());
    }

    #[test]
    fn inspect_comment_matches_refused_legacy_journal_policy() {
        let source = include_str!("commands.rs");
        let inspect = source
            .split("pub async fn inspect_wallet_file")
            .next()
            .expect("inspect declaration");
        let comment = &inspect[inspect.len().saturating_sub(600)..];
        assert!(
            !comment.contains("nothing is written anywhere"),
            "{comment}"
        );
        assert!(comment.contains("journal") && comment.contains("preserved"));
        assert!(comment.contains("refused") && comment.contains("never migrated"));
    }

    #[test]
    fn nonfresh_sprout_report_keeps_the_source_warning() {
        let outcome = argos_core::sprout_sweep::SproutSweepOutcome {
            transactions: vec![argos_core::sprout_sweep::SproutSweepTransaction {
                txid: "stored-mined".to_owned(),
                value_zatoshis: Some(11),
                state: argos_core::TxLifecycleState::Mined,
                mined_height: Some(123),
                superseded: false,
            }],
            mined_zatoshis: 11,
            fresh_all_mined: false,
            ..Default::default()
        };
        let report = super::sprout_sweep_report(outcome);
        assert!(report.warnings.iter().any(|warning| warning
            .contains("Keep the original wallet or Sprout key and the scan checkpoint")));

        let fresh = super::sprout_sweep_report(argos_core::sprout_sweep::SproutSweepOutcome {
            fresh_all_mined: true,
            ..Default::default()
        });
        assert!(fresh.warnings.is_empty());
    }

    #[test]
    fn unknown_only_preview_returns_status_without_loading_proving_parameters() {
        let journal = test_sprout_journal(0x42);
        let mut snapshot = journal.load_or_migrate().unwrap();
        let note = preview_note(1_000_000, 0x11);
        append_unknown_journal_entry(&journal, &mut snapshot, note.outpoint, note.note.value, 0);
        let preview = super::sprout_sweep_preview(&[], &snapshot).unwrap();
        assert_eq!(preview.notes, 0);
        assert_eq!(preview.active.len(), 1);
        // A 1.5.x "broadcast" entry cannot prove node acceptance, so it is
        // retained as submission-unknown rather than upgraded to pending.
        assert_eq!(
            preview.active[0].state,
            argos_core::TxLifecycleState::SubmissionUnknown
        );
        assert!(preview.mined.is_empty());
        remove_artifact_fixture(journal.data_dir());
    }

    #[test]
    fn terminal_wallet_and_scan_journals_do_not_report_no_funds() {
        use argos_core::TxLifecycleState::{Expired, Rejected};

        for state in [Expired, Rejected] {
            let wallet = super::empty_sprout_proposal_error(
                super::SproutProposalOrigin::Wallet,
                true,
                [state].into_iter(),
            )
            .expect("an empty terminal journal still needs recovery guidance");
            let scan = super::empty_sprout_proposal_error(
                super::SproutProposalOrigin::SavedScan,
                true,
                [state].into_iter(),
            )
            .expect("an empty terminal scan journal still needs recovery guidance");

            for message in [&wallet, &scan] {
                assert!(message.contains("Keep the original wallet or Sprout key"));
                assert!(message.contains("rescan") || message.contains("recover"));
                assert!(!message.contains("nothing is left"), "{message}");
                assert!(!message.contains("no unspent Sprout notes"), "{message}");
            }
        }
    }

    #[test]
    fn unresolvable_data_directory_stops_before_proving_or_sending() {
        let invoked = std::cell::Cell::new(false);
        let result = super::with_resolved_sprout_data_dir(
            Err("resolving app data dir: unavailable".to_owned()),
            |_| {
                invoked.set(true);
                Ok::<_, String>(())
            },
        );
        assert!(result.is_err());
        assert!(!invoked.get(), "proving or sending work must not start");
    }

    #[test]
    fn fresh_gui_workspace_is_authenticated_before_sprout_work_starts() {
        let workspace = unused_artifact_data_dir("fresh-gui-workspace");
        assert!(!workspace.exists());

        super::with_resolved_sprout_data_dir(Ok(workspace.clone()), |resolved| {
            assert_eq!(resolved, workspace);
            argos_core::service::ensure_recovery_data_dir(resolved)
                .map_err(|err| err.to_string())?;
            Ok::<_, String>(())
        })
        .unwrap();
        remove_artifact_fixture(&workspace);
    }

    #[test]
    fn a_sweep_request_is_refused_on_its_own_inputs() {
        // Checked before the wallet file is decrypted: neither check needs
        // the keys, so a bad address or server is reported without them.
        let err = validate_sweep_request("not-an-address", ZeckNetwork::Mainnet, "nonono")
            .expect_err("an undecodable destination is refused");
        assert!(
            !err.contains("lightwalletd"),
            "destination is checked first: {err}"
        );

        // The test seed's account-0 Sapling address (see derivation.rs).
        let good = "zs16uhd4mux24se6wkm74vld0ec63d4dxt3d7m80l5xytreplkkllrrf9c7fj859mhp8tkcq9hxfvj";
        let err = validate_sweep_request(good, ZeckNetwork::Mainnet, "nonono")
            .expect_err("an unusable server is refused");
        assert!(err.contains("lightwalletd"), "{err}");

        validate_sweep_request(good, ZeckNetwork::Mainnet, "https://zec.rocks:443")
            .expect("a real address and server pass");
    }

    #[test]
    fn a_wrong_network_server_is_left_to_the_sweeps_own_probe() {
        // The up-front check is syntax only: no network access, so it cannot
        // tell a testnet server from a mainnet one. That is caught by the
        // probe `sweep_sprout_notes` runs before loading the proving
        // parameters (`validate_lightwalletd_network`, tested in core as
        // `network_validation_rejects_wrong_chain`).
        validate_sweep_endpoint("https://testnet.zec.rocks:443")
            .expect("a well-formed testnet URL passes the syntax check");
    }

    #[test]
    fn preview_response_serializes_its_current_scan_warning() {
        let preview = ReviewedSproutSweep {
            proposal_id: crate::reviewed_intent::SproutProposalId("fixture".to_owned()),
            plan: SproutSweepPreviewData {
                notes: 1,
                gross_zatoshis: 100_000,
                fee_zatoshis: 10_000,
                net_zatoshis: 90_000,
                active: Vec::new(),
                mined: Vec::new(),
            },
            params_present: true,
            params_path: "/fixture/params".to_owned(),
            lands_in_sapling: "Lands in Sapling".to_owned(),
            nu7_warning: "NU7 fixture".to_owned(),
            warnings: Vec::new(),
            scan_warning: Some("fresh checkpoint verification failed".to_owned()),
        };
        let json = serde_json::to_value(preview).unwrap();
        assert_eq!(json["scan_warning"], "fresh checkpoint verification failed");
        assert_eq!(json["net_zatoshis"], 90_000);
    }

    /// #272's "the sweep itself still refuses the field", under #271's
    /// proposal model: a review built with a malformed peer list is refused
    /// at execute, and one built with a valid list is not.
    #[test]
    fn a_review_built_with_a_malformed_peer_is_refused_at_execute() {
        let intent = |peer_error: Option<String>| SproutSweepIntent {
            source: SproutIntentSource::Wallet(test_wallet_source()),
            notes: Vec::new(),
            destination: "zs-reviewed".into(),
            network: ZeckNetwork::Mainnet,
            lightwalletd_url: "https://node".into(),
            confirmation_sources: Vec::new(),
            journal: test_sprout_journal(0x5A),
            wallet_checkpoint: None,
            checkpoint_authority: None,
            _checkpoint_reservation: None,
            tip_warning: None,
            peer_error,
        };
        let err = parse_custom_peers(&["no-port-here".to_owned()]).unwrap_err();
        let refused = refuse_unverified_review(&intent(Some(err))).unwrap_err();
        assert!(refused.contains("no-port-here"), "{refused}");
        assert!(refused.contains("host:port"), "{refused}");
        assert!(refused.contains("review the sweep again"), "{refused}");
        assert!(refuse_unverified_review(&intent(None)).is_ok());
    }

    /// With #277's journal an empty recovery is not itself an error (saved
    /// transactions may still need a status check), so the notice rides on
    /// the empty-plan error the review returns instead.
    #[test]
    fn preview_error_carries_fresh_verification_notice_when_no_note_is_available() {
        let recovered = SproutRecovery {
            chain_notice: Some("preview verification found a deep reorg".to_owned()),
            ..Default::default()
        };
        let snapshot = argos_core::sprout_sweep::SproutJournalSnapshot::default();
        let plan = plan_wallet_sprout_preview(&recovered, &snapshot).unwrap();
        assert_eq!(plan.notes, 0);
        let inventory =
            argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
        let error = no_sprout_notes_error(&recovered, &inventory);
        assert!(
            error.contains("preview verification found a deep reorg"),
            "{error}"
        );
    }

    /// A wallet holding one real, self-consistent Sprout note: the
    /// ciphertext comes from the encryption path and the witness is a
    /// genuine zcashd-shaped blob, so recovery yields a spendable note.
    fn wallet_with_one_note(value: u64) -> (ImportedKeys, [u8; 32]) {
        use argos_core::argos_wallet_import::keys::{
            JsOutPoint, SproutJoinSplit, SproutKey, SproutNoteData,
        };
        use argos_core::sprout::{self, SproutNotePlaintext, SproutPaymentAddress};
        let a_sk = [0x42u8; 32];
        let address = SproutPaymentAddress::from_spending_key(&a_sk);
        let (rho, r) = ([0x11u8; 32], [0x22u8; 32]);
        let random_seed = [0x33u8; 32];
        let nullifiers = [[0x44u8; 32], [0x55u8; 32]];
        let joinsplit_pubkey = [0x66u8; 32];
        let esk = [0x77u8; 32];
        let h_sig = sprout::h_sig(&random_seed, &nullifiers, &joinsplit_pubkey);
        let note = SproutNotePlaintext {
            value,
            rho,
            r,
            memo: [0u8; 512],
        };
        let ciphertext =
            sprout::encrypt_note(&esk, address.pk_enc(), &h_sig, 0, &note.to_bytes()).unwrap();
        let commitment = sprout::note_commitment(address.a_pk(), value, &rho, &r);
        let txid = [0x99u8; 32];
        let mut keys = ImportedKeys::default();
        keys.sprout.push(SproutKey {
            a_sk: secrecy::Secret::new(a_sk),
            address: address.to_bytes(),
            provenance: Provenance::Standalone,
            created_at: None,
        });
        keys.sprout_joinsplits.push(SproutJoinSplit {
            txid,
            js_index: 0,
            anchor: [0u8; 32],
            nullifiers,
            commitments: [commitment, [0u8; 32]],
            ephemeral_key: sprout::epk_for(&esk),
            random_seed,
            joinsplit_pubkey,
            ciphertexts: [ciphertext, vec![0u8; 601]],
        });
        let mut tree = argos_core::sprout_witness::IncrementalMerkleTree::default();
        tree.append(commitment).unwrap();
        let witness = argos_core::sprout_witness::IncrementalWitness::from_tree(tree);
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&witness.to_bytes());
        blob.extend_from_slice(&0i32.to_le_bytes());
        keys.sprout_notes.push(SproutNoteData {
            address: address.to_bytes(),
            nullifier: None,
            witness: blob,
            outpoint: JsOutPoint {
                txid,
                js_index: 0,
                output_index: 0,
            },
        });
        (keys, a_sk)
    }

    /// Review a one-note wallet sweep in `dir` with a valid peer list, and
    /// take the proposal back out as execute does.
    async fn reviewed_one_note_wallet(
        dir: &std::path::Path,
    ) -> (ReviewedSproutSweep, SproutSweepIntent) {
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let store = ReviewedIntentStore::default();
        let review = propose_wallet_sprout_sweep_core(
            &store,
            test_wallet_source(),
            &mut keys,
            dir.to_path_buf(),
            "zs-reviewed".into(),
            ZeckNetwork::Mainnet,
            "https://zec.rocks:443".into(),
            Vec::new(),
            &["192.0.2.10:8233".to_owned()],
            |_| {},
        )
        .await
        .expect("one spendable note is reviewed");
        let intent = store.take_wallet_proposal(&review.proposal_id).unwrap();
        (review, intent)
    }

    /// #272: the wallet sweep verifies its saved scan against live peers
    /// again at execute, through the reviewed peer list, and the report
    /// carries execute's own verdict, not the one shown with the review.
    /// Here the review found no scan; by execute an unusable scan covering
    /// these keys has appeared, and that is what execute reports. Neither
    /// verification touches the sweep journal.
    #[tokio::test]
    async fn execute_uses_its_current_notice_even_when_preview_had_a_different_verdict() {
        let dir = unused_artifact_data_dir("reverify-current-notice");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let (review, intent) = reviewed_one_note_wallet(&dir).await;
        let preview_notice = review.scan_warning.clone().expect("review verdict");
        assert!(
            preview_notice.contains("No full-block scan"),
            "{preview_notice}"
        );

        // A scan of a wider key set that includes this wallet's key, cut
        // short so it cannot be read: found, but unusable, offline.
        let a_sk = intent.notes[0].a_sk;
        let wider = [a_sk, [0x01; 32]];
        let mut scanner = argos_core::sprout_scan::SproutScanner::new(&wider);
        scanner.scan_block_at(&[], [0xCD; 32], 2_000_000).unwrap();
        let mut sorted = wider;
        sorted.sort();
        let checkpoint = argos_core::sprout_scan_run::checkpoint_path(&dir, &sorted);
        argos_core::sprout_scan_run::save_checkpoint(
            &scanner,
            argos_core::p2p::wire::P2pNetwork::Mainnet,
            &checkpoint,
        )
        .unwrap();
        let bytes = std::fs::read(&checkpoint).unwrap();
        std::fs::write(&checkpoint, &bytes[..bytes.len() - 16]).unwrap();

        let notice = verify_review_at_execute(&intent)
            .await
            .expect("an unusable scan is a warning, as main's execute made it")
            .expect("execute reports its own verdict");
        assert!(notice.contains("could not be used"), "{notice}");
        assert_ne!(notice, preview_notice);
        assert!(
            !intent.journal.path().exists(),
            "verification writes nothing to the sweep journal"
        );
        remove_artifact_fixture(&dir);
    }

    /// A reviewed note the execute-time scan evidence shows spent on chain
    /// is refused; evidence that does not name it lets the sweep proceed.
    #[test]
    fn a_reviewed_note_the_current_scan_shows_spent_is_refused() {
        let (keys, a_sk) = wallet_with_one_note(1_000_000);
        let notes =
            argos_core::sprout_recovery::recover_spendable_sprout_notes_with_chain(&keys, None)
                .notes;
        assert_eq!(notes.len(), 1);
        let nullifier = argos_core::sprout::prf_nf(&a_sk, &notes[0].note.rho);
        let mut chain = argos_core::sprout_recovery::ChainSpends {
            nullifiers: Default::default(),
            scanned_to: 2_000_000,
            complete: true,
        };
        assert!(reviewed_notes_still_spendable(&notes, Some(&chain)).is_ok());
        chain.nullifiers.insert(nullifier, Some([0xEE; 32]));
        let err = reviewed_notes_still_spendable(&notes, Some(&chain)).unwrap_err();
        assert!(
            err.contains("changed since this sweep was reviewed"),
            "{err}"
        );
        assert!(err.contains("spent on chain"), "{err}");
    }

    #[tokio::test]
    async fn execute_check_refuses_when_the_lookup_shows_a_reviewed_note_spent() {
        let dir = unused_artifact_data_dir("execute-lookup");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let (_, intent) = reviewed_one_note_wallet(&dir).await;
        let nullifier =
            argos_core::sprout::prf_nf(&intent.notes[0].a_sk, &intent.notes[0].note.rho);
        let evidence = |spent: bool| {
            let mut chain = argos_core::sprout_recovery::ChainSpends {
                nullifiers: Default::default(),
                scanned_to: 2_000_000,
                complete: true,
            };
            if spent {
                chain.nullifiers.insert(nullifier, Some([0xEE; 32]));
            }
            (Some(std::sync::Arc::new(chain)), Some("fresh".to_owned()))
        };
        let err = verify_review_with(
            &intent.notes,
            intent.network,
            intent.wallet_checkpoint.as_ref(),
            |_, _, _, _| async { evidence(true) },
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("changed since this sweep was reviewed"),
            "{err}"
        );
        assert!(err.contains("spent on chain"), "{err}");
        let notice = verify_review_with(
            &intent.notes,
            intent.network,
            intent.wallet_checkpoint.as_ref(),
            |_, _, _, _| async { evidence(false) },
        )
        .await
        .expect("a current scan that names no reviewed note permits execute");
        assert_eq!(notice.as_deref(), Some("fresh"));
        remove_artifact_fixture(&dir);
    }

    fn empty_sweep_report() -> SproutSweepReport {
        SproutSweepReport {
            transactions: Vec::new(),
            mined_zatoshis: 0,
            pending_zatoshis: 0,
            unknown_zatoshis: 0,
            skipped: Vec::new(),
            rejected: Vec::new(),
            warnings: Vec::new(),
            error: None,
            fresh_all_mined: true,
        }
    }

    #[tokio::test]
    async fn the_sweep_step_runs_only_after_verification_passes() {
        let dir = unused_artifact_data_dir("execute-ordering");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let sweep = |_: SproutSweepIntent, _: Option<String>| async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(empty_sweep_report())
        };
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let store = ReviewedIntentStore::default();
        let review = propose_wallet_sprout_sweep_core(
            &store,
            test_wallet_source(),
            &mut keys,
            dir.clone(),
            "zs-reviewed".into(),
            ZeckNetwork::Mainnet,
            "https://zec.rocks:443".into(),
            Vec::new(),
            &["no-port-here".to_owned()],
            |_| {},
        )
        .await
        .expect("a malformed peer degrades the review");
        let refused = store.take_wallet_proposal(&review.proposal_id).unwrap();
        let err = verified_then_sweep(refused, &sweep)
            .await
            .err()
            .expect("verification refuses");
        assert!(err.contains("no-port-here"), "{err}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let (_, mut passing) = reviewed_one_note_wallet(&dir).await;
        passing.wallet_checkpoint = None;
        assert!(verified_then_sweep(passing, &sweep).await.is_ok());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        remove_artifact_fixture(&dir);
    }

    /// The peer-field refusal comes first: a review built with a malformed
    /// peer list is refused at execute before any verification is tried.
    #[tokio::test]
    async fn execute_refuses_a_malformed_peer_review_before_verifying() {
        let dir = unused_artifact_data_dir("reverify-malformed-peer");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let (mut keys, _) = wallet_with_one_note(1_000_000);
        let store = ReviewedIntentStore::default();
        let review = propose_wallet_sprout_sweep_core(
            &store,
            test_wallet_source(),
            &mut keys,
            dir.clone(),
            "zs-reviewed".into(),
            ZeckNetwork::Mainnet,
            "https://zec.rocks:443".into(),
            Vec::new(),
            &["no-port-here".to_owned()],
            |_| {},
        )
        .await
        .expect("a malformed peer degrades the review, not fails it");
        let intent = store.take_wallet_proposal(&review.proposal_id).unwrap();
        let err = refuse_unverified_review(&intent).unwrap_err();
        assert!(err.contains("no-port-here"), "{err}");
        assert!(err.contains("review the sweep again"), "{err}");
        assert!(
            !intent.journal.path().exists(),
            "a refused execute records nothing in the sweep journal"
        );
        remove_artifact_fixture(&dir);
    }

    #[tokio::test]
    async fn inspection_keeps_wallet_file_accounting_when_scan_verification_is_unavailable() {
        let dir = unused_artifact_data_dir("gui-unverified-sprout");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let a_sk = [0x52; 32];
        let mut keys = argos_core::argos_wallet_import::ImportedKeys::default();
        keys.sprout
            .push(argos_core::argos_wallet_import::keys::SproutKey {
                a_sk: secrecy::Secret::new(a_sk),
                address: argos_core::sprout::SproutPaymentAddress::from_spending_key(&a_sk)
                    .to_bytes(),
                provenance: argos_core::argos_wallet_import::keys::Provenance::Standalone,
                created_at: None,
            });
        let recovered = recover_with_scan_in_dir(
            &keys,
            argos_core::ZeckNetwork::Mainnet,
            Some(dir.clone()),
            None,
        )
        .await;
        let checkpoint = argos_core::sprout_scan_run::checkpoint_path(&dir, &[a_sk]);
        let accounting = recovered.accounting_lines().join(" ");
        assert!(accounting.contains(&checkpoint.display().to_string()));
        assert!(accounting.contains("wallet file's own record"));
        assert!(recovered.spent.is_empty());

        // With a scan present, opening the wallet still makes no network
        // contact: the scan is named and its evidence is not used. Driven
        // through `recover_for_wallet_open`, the helper `inspect_wallet_file`
        // uses, so a change that makes wallet open dial peers fails here: it
        // would reach `chain_spends_for_wallet`, which cannot answer "not
        // verified offline" and, with no network, cannot answer promptly.
        let mut scanner = argos_core::sprout_scan::SproutScanner::new(&[a_sk]);
        scanner.scan_block_at(&[], [0xCD; 32], 2_000_000).unwrap();
        argos_core::sprout_scan_run::save_checkpoint(
            &scanner,
            argos_core::p2p::wire::P2pNetwork::Mainnet,
            &checkpoint,
        )
        .unwrap();
        let recovered = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recover_for_wallet_open(&keys, argos_core::ZeckNetwork::Mainnet, Some(dir.clone())),
        )
        .await
        .expect("opening a wallet makes no network attempt, so it returns at once");
        let accounting = recovered.accounting_lines().join(" ");
        assert!(accounting.contains("not verified offline"), "{accounting}");
        assert!(accounting.contains(&checkpoint.display().to_string()));
        assert!(recovered.spent.is_empty());
        remove_artifact_fixture(&dir);
    }

    /// Review of #272, round 2: a malformed entry in the scan panel's peer
    /// field used to fail the wallet's sweep preview outright. It now skips
    /// live verification and makes no network attempt, keeps the wallet
    /// file's own spent record (fail closed: the unverified scan is not
    /// used), and says why in the preview's scan warning.
    #[tokio::test]
    async fn a_malformed_scan_peer_degrades_the_preview_to_a_warning() {
        let dir = unused_artifact_data_dir("gui-preview-bad-peer");
        argos_core::service::ensure_recovery_data_dir(&dir).unwrap();
        let a_sk = [0x53; 32];
        let mut keys = argos_core::argos_wallet_import::ImportedKeys::default();
        keys.sprout
            .push(argos_core::argos_wallet_import::keys::SproutKey {
                a_sk: secrecy::Secret::new(a_sk),
                address: argos_core::sprout::SproutPaymentAddress::from_spending_key(&a_sk)
                    .to_bytes(),
                provenance: argos_core::argos_wallet_import::keys::Provenance::Standalone,
                created_at: None,
            });
        let checkpoint = argos_core::sprout_scan_run::checkpoint_path(&dir, &[a_sk]);
        let mut scanner = argos_core::sprout_scan::SproutScanner::new(&[a_sk]);
        scanner.scan_block_at(&[], [0xCD; 32], 2_000_000).unwrap();
        argos_core::sprout_scan_run::save_checkpoint(
            &scanner,
            argos_core::p2p::wire::P2pNetwork::Mainnet,
            &checkpoint,
        )
        .unwrap();

        let recovered = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recover_for_sweep_preview(
                &keys,
                argos_core::ZeckNetwork::Mainnet,
                Some(dir.clone()),
                &["no-port-here".to_owned()],
            ),
        )
        .await
        .expect("a malformed peer list makes no network attempt");
        let notice = recovered
            .chain_notice
            .clone()
            .expect("the preview says why");
        assert!(notice.contains("no-port-here"), "{notice}");
        assert!(notice.contains("is not valid"), "{notice}");
        assert!(notice.contains("wallet file's own"), "{notice}");
        assert!(notice.contains("before sweeping"), "{notice}");
        assert!(recovered.spent.is_empty());

        // The sweep itself still refuses the same field, with the format.
        let err = parse_custom_peers(&["no-port-here".to_owned()]).unwrap_err();
        assert!(err.contains("host:port"), "{err}");
        remove_artifact_fixture(&dir);
    }

    fn spent_note() -> SpentSproutNote {
        SpentSproutNote {
            outpoint: argos_core::argos_wallet_import::keys::JsOutPoint {
                txid: [1; 32],
                js_index: 0,
                output_index: 0,
            },
            value: 5,
            spent_in: argos_core::sprout_recovery::SpentEvidence::Wallet { txid: [2; 32] },
        }
    }

    /// Kristi's F7/F8 on #239: what the Sprout screen says is decided here,
    /// not injected by the frontend test, so it is pinned in Rust.
    #[test]
    fn the_sprout_screen_matches_what_recovery_found() {
        // Keys, no note data at all: the scan is the only route.
        let empty = SproutRecovery::default();
        let screen = sprout_screen(true, &empty);
        assert!(screen.needs_scan && !screen.nothing_left && !screen.history_read);

        // Every note spent by the wallet itself: nothing left, no scan needed.
        let spent = SproutRecovery {
            spent: vec![spent_note()],
            ..Default::default()
        };
        let screen = sprout_screen(true, &spent);
        assert!(screen.nothing_left && !screen.needs_scan && screen.history_read);

        // Spent notes plus one unusable note: a scan is still worth it, but
        // the file's note data was read, so it must not say otherwise.
        let mixed = SproutRecovery {
            spent: vec![spent_note()],
            issues: vec![
                argos_core::sprout_recovery::SproutRecoveryIssue::NoSpendingKey {
                    outpoint: spent_note().outpoint,
                },
            ],
            ..Default::default()
        };
        let screen = sprout_screen(true, &mixed);
        assert!(screen.needs_scan && !screen.nothing_left && screen.history_read);

        // No Sprout keys: nothing to say.
        let screen = sprout_screen(false, &empty);
        assert!(!screen.needs_scan && !screen.nothing_left && !screen.quote_scan_cost);

        // Round-5 finding 8: note data that exists but could not be read is
        // still note data — the file does hold it.
        let unread = SproutRecovery {
            unreadable_transactions: 2,
            ..Default::default()
        };
        assert!(sprout_screen(true, &unread).history_read);

        // Finding 6: wherever the scan is offered, its cost is quoted —
        // including a fully spent wallet, where it is offered as a check.
        assert!(sprout_screen(true, &spent).quote_scan_cost);
        assert!(sprout_screen(true, &empty).quote_scan_cost);
    }

    #[test]
    fn sprout_screen_uses_journal_and_read_failures_conservatively() {
        let spent = SproutRecovery {
            spent: vec![spent_note()],
            ..Default::default()
        };
        let journal = test_sprout_journal(0x42);
        let mut snapshot = journal.load_or_migrate().unwrap();
        let note = preview_note(1_000_000, 0x11);
        append_unknown_journal_entry(&journal, &mut snapshot, note.outpoint, note.note.value, 0);
        assert!(sprout_has_lifecycle_status(&snapshot));
        let with_orphan = sprout_screen_with_journal(true, &spent, &snapshot, true);
        assert!(!with_orphan.nothing_left);
        assert!(
            with_orphan.quote_scan_cost,
            "a zero-note lifecycle screen still offers recovery scan guidance"
        );

        let unreadable = sprout_screen_with_journal(
            true,
            &spent,
            &argos_core::sprout_sweep::SproutJournalSnapshot::default(),
            false,
        );
        assert!(!unreadable.nothing_left);
        remove_artifact_fixture(journal.data_dir());
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
            argos_core::sprout_recovery::recover_spendable_sprout_notes_with_chain(&keys, None)
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
    fn wallet_sprout_import_rejects_embedded_network_mismatch() {
        let bytes = include_bytes!(
            "../../../crates/argos-wallet-import/tests/fixtures/zwl-mainnet-empty.dat"
        );
        let reached_recovery = std::cell::Cell::new(false);
        let err = import_gui_wallet_then(bytes, None, argos_core::ZeckNetwork::Testnet, |keys| {
            reached_recovery.set(true);
            argos_core::sprout_recovery::recover_spendable_sprout_notes_with_chain(&keys, None)
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
                argos_core::sprout_recovery::recover_spendable_sprout_notes_with_chain(&keys, None)
            })
            .unwrap();
        assert!(
            reached_recovery.get(),
            "matching wallet never reached recovery"
        );
        assert!(
            recovered.notes.is_empty(),
            "public no-funds fixture gained notes"
        );
    }

    fn peers(entries: &[&str]) -> Result<Vec<String>, String> {
        let owned: Vec<String> = entries.iter().map(|e| (*e).to_owned()).collect();
        parse_custom_peers(&owned)
    }

    #[test]
    fn custom_peers_accept_ipv4_hostname_and_bracketed_ipv6() {
        assert_eq!(
            peers(&["192.0.2.10:8233", "node.example.org:8233", "[::1]:8233"]),
            Ok(vec![
                "192.0.2.10:8233".to_owned(),
                "node.example.org:8233".to_owned(),
                "[::1]:8233".to_owned(),
            ])
        );
        assert_eq!(
            peers(&["localhost:18233"]),
            Ok(vec!["localhost:18233".to_owned()])
        );
        assert_eq!(
            peers(&["[2001:db8::1]:65535"]),
            Ok(vec!["[2001:db8::1]:65535".to_owned()])
        );
    }

    #[test]
    fn custom_peers_trim_split_and_drop_empties() {
        assert_eq!(peers(&[]), Ok(vec![]));
        assert_eq!(peers(&["", "   ", "\n", " , ,\n"]), Ok(vec![]));
        assert_eq!(
            peers(&["  192.0.2.10:8233 ,node.example.org:8233\r\n[::1]:8233\n"]),
            Ok(vec![
                "192.0.2.10:8233".to_owned(),
                "node.example.org:8233".to_owned(),
                "[::1]:8233".to_owned(),
            ])
        );
    }

    #[test]
    fn custom_peers_reject_a_missing_port() {
        for bad in [
            "192.0.2.10",
            "node.example.org",
            "node.example.org:",
            "[::1]",
            "[::1]:",
        ] {
            let err = peers(&[bad]).expect_err(bad);
            assert!(err.contains(bad), "error should name the entry: {err}");
        }
    }

    #[test]
    fn custom_peers_reject_an_out_of_range_or_malformed_port() {
        for bad in [
            "192.0.2.10:0",
            "192.0.2.10:65536",
            "192.0.2.10:99999999999",
            "192.0.2.10:-1",
            "192.0.2.10:+8233",
            "192.0.2.10:82e3",
            "[::1]:0",
        ] {
            let err = peers(&[bad]).expect_err(bad);
            assert!(err.contains(bad), "error should name the entry: {err}");
        }
    }

    #[test]
    fn custom_peers_reject_a_malformed_host() {
        for bad in [
            ":8233",
            "::1:8233",
            "[::1:8233",
            "[not-an-address]:8233",
            "[]:8233",
            "https://node.example.org:8233",
            "node example.org:8233",
            "node..example.org:8233",
            "-node.example.org:8233",
            "user@node.example.org:8233",
        ] {
            let err = peers(&[bad]).expect_err(bad);
            assert!(err.contains(bad), "error should name the entry: {err}");
        }
    }

    #[test]
    fn custom_peers_one_bad_entry_fails_the_whole_list() {
        assert!(peers(&["192.0.2.10:8233", "oops"]).is_err());
        assert!(peers(&["192.0.2.10:8233,oops"]).is_err());
    }

    #[test]
    fn custom_peers_deduplicate_keeping_first_occurrence_order() {
        assert_eq!(
            peers(&[
                "node.example.org:8233",
                "192.0.2.10:8233",
                "Node.Example.ORG:8233",
                " 192.0.2.10:8233 ",
            ]),
            Ok(vec![
                "node.example.org:8233".to_owned(),
                "192.0.2.10:8233".to_owned(),
            ])
        );
        // Same host on another port is a different peer.
        assert_eq!(
            peers(&["192.0.2.10:8233", "192.0.2.10:8234"]).map(|p| p.len()),
            Ok(2)
        );
    }

    #[test]
    fn custom_peers_are_capped_after_deduplication() {
        let at_cap: Vec<String> = (0..MAX_CUSTOM_PEERS)
            .map(|i| format!("192.0.2.{i}:8233"))
            .collect();
        assert_eq!(
            parse_custom_peers(&at_cap).map(|p| p.len()),
            Ok(MAX_CUSTOM_PEERS)
        );

        // Duplicates do not count towards the cap.
        let mut padded = at_cap.clone();
        padded.extend(at_cap.iter().cloned());
        assert_eq!(
            parse_custom_peers(&padded).map(|p| p.len()),
            Ok(MAX_CUSTOM_PEERS)
        );

        let mut over = at_cap;
        over.push("192.0.2.200:8233".to_owned());
        let err = parse_custom_peers(&over).expect_err("over the cap");
        assert!(err.contains(&MAX_CUSTOM_PEERS.to_string()), "{err}");
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
}
