use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use argos_core::{
    detect_birthday as zeck_detect_birthday, estimate_birthday_from_date as estimate_birthday,
    list_incomplete_sessions as zeck_list_incomplete_sessions, parse_workspace_keying,
    validate_destination_address, validate_mnemonic_words, verify_seed_for_workspace,
    BirthdayDetectResult, IncompleteSession, RecoveryService, ScanConfig, ScanHandle,
    SweepOutcome, SweepProposal, SweepRequest, ZeckNetwork,
};

#[derive(Clone)]
pub struct AppState {
    pub service: RecoveryService,
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
pub async fn validate_address(address: String) -> Result<argos_core::AddressInfo, String> {
    validate_destination_address(&address).map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    config: ScanConfigInput,
) -> Result<ScanHandle, String> {
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
pub async fn propose_sweep(
    state: State<'_, AppState>,
    handle: ScanHandle,
    destination: String,
    memo: Option<String>,
    max_fee_zec: Option<String>,
    donation_rate: Option<f64>,
    donor_email: Option<String>,
) -> Result<SweepProposal, String> {
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

#[tauri::command]
pub async fn estimate_birthday_from_date(
    date: String,
    lightwalletd_url: String,
) -> Result<u32, String> {
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
        .map(|c| if c == '\'' { "''".to_string() } else { c.to_string() })
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

    fn temp_workspace() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "argos-report-path-test-{}-{n}",
            std::process::id()
        ));
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
        assert_eq!(mode, 0o600, "a reused report file must be re-tightened to 0o600");
        assert_eq!(std::fs::read(&path).expect("read"), b"fresh");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
