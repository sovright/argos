#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod reviewed_intent;

use argos_core::RecoveryService;
use clap::Parser;
use commands::AppState;
use tauri::Manager;

#[derive(Debug, Parser)]
#[command(
    name = "argos-gui",
    version,
    about = "Argos wallet recovery desktop app"
)]
struct GuiArgs {
    /// Blocks downloaded and scanned at a time. Lower values use less memory
    /// and make more requests. Default: 1000. Clamped to 10–10000.
    #[arg(long, value_name = "BLOCKS")]
    scan_batch_size: Option<u32>,

    /// Enable debug diagnostics for Argos.
    #[arg(short, long)]
    verbose: bool,
}

impl GuiArgs {
    fn apply_sync_batch_size(&self) -> u32 {
        self.scan_batch_size
            .map(argos_core::scan::set_sync_batch_size)
            .unwrap_or_else(argos_core::scan::sync_batch_size)
    }
}

fn main() {
    let args = GuiArgs::parse();
    let batch_size = args.apply_sync_batch_size();

    // Surface argos-core diagnostics to stderr (visible in `npm run dev`).
    // Honors RUST_LOG; defaults to info, with debug for argos-core so the
    // per-account donation decision and any fallback warnings are observable.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(if args.verbose {
                    "info,argos_core=debug,argos_gui=debug"
                } else {
                    "info,argos_core=debug"
                })
            }),
        )
        .try_init();

    if let Some(requested) = args
        .scan_batch_size
        .filter(|&requested| requested != batch_size)
    {
        tracing::warn!(
            requested,
            batch_size,
            "--scan-batch-size clamped to supported range"
        );
    }
    tracing::info!(batch_size, "GUI sync batch size (blocks)");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Native file picker for the wallet-file screen. Driven entirely
        // from Rust via the `pick_wallet_file` command, the same way the
        // opener plugin is: the capability file grants the webview no
        // `dialog:` permission, so JavaScript cannot open a dialog of its
        // own choosing, and the only reachable surface is picking one file.
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            service: RecoveryService::new(),
            address_search: argos_core::address_search::AddressSearchService::default(),
            reviewed_intent: reviewed_intent::ReviewedIntentStore::default(),
            wallet_reviews: reviewed_intent::WalletReviewRegistry::default(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::validate_seed,
            commands::validate_address,
            commands::start_address_search,
            commands::get_address_search,
            commands::cancel_address_search,
            commands::release_address_search,
            commands::start_matched_recovery,
            commands::start_scan,
            commands::pick_wallet_file,
            commands::inspect_wallet_file,
            commands::release_wallet_review,
            commands::start_scan_from_wallet_file,
            commands::get_scan_progress,
            commands::cancel_scan,
            commands::release_scan,
            commands::reconcile_sweep,
            commands::retry_unknown_sweep,
            commands::propose_sweep,
            commands::execute_sweep,
            commands::estimate_birthday_from_date,
            commands::detect_birthday,
            commands::detect_birthday_from_wallet_file,
            commands::save_recovery_report,
            commands::delete_workspace,
            commands::check_sprout_key,
            commands::check_sapling_key,
            commands::start_sprout_scan,
            commands::pick_sprout_pack_folder,
            commands::describe_sprout_pack,
            commands::get_sprout_scan,
            commands::release_sprout_scan,
            commands::release_sprout_proposal,
            commands::propose_wallet_sprout_sweep,
            commands::execute_wallet_sprout_sweep,
            commands::propose_sprout_scan_sweep,
            commands::execute_sprout_scan_sweep,
            commands::sprout_nu7_warning,
            commands::sweep_completion_guidance,
            commands::default_data_dir,
            commands::notify_user,
            commands::list_incomplete_sessions,
            commands::resume_session,
            commands::donation_address,
            commands::app_version,
            commands::open_external_url,
            commands::tos_status,
            commands::accept_tos,
            commands::reject_tos
        ])
        .setup(|app| {
            let _window = app.get_webview_window("main");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Argos GUI");
}

#[cfg(test)]
mod args_tests {
    use super::GuiArgs;
    use argos_core::scan::{set_sync_batch_size, sync_batch_size};
    use clap::{error::ErrorKind, Parser};
    use std::sync::Mutex;

    static BATCH_SIZE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn gui_scan_batch_size_reaches_the_sync_setting_and_preserves_core_clamps() {
        let _lock = BATCH_SIZE_TEST_LOCK.lock().unwrap();
        struct ResetBatchSize(u32);
        impl Drop for ResetBatchSize {
            fn drop(&mut self) {
                set_sync_batch_size(self.0);
            }
        }
        let _reset = ResetBatchSize(sync_batch_size());

        let defaults = GuiArgs::try_parse_from(["argos-gui"]).unwrap();
        assert_eq!(defaults.scan_batch_size, None);
        assert!(!defaults.verbose);
        assert_eq!(defaults.apply_sync_batch_size(), 1000);

        for (requested, expected) in [("100", 100), ("1", 10), ("10001", 10000)] {
            let args =
                GuiArgs::try_parse_from(["argos-gui", "--verbose", "--scan-batch-size", requested])
                    .unwrap();
            assert!(args.verbose);
            assert_eq!(args.apply_sync_batch_size(), expected);
            assert_eq!(sync_batch_size(), expected);
        }
    }

    #[test]
    fn gui_rejects_missing_malformed_and_overflowing_batch_sizes() {
        for value in ["nope", "-1", "4294967296"] {
            let error =
                GuiArgs::try_parse_from(["argos-gui", "--scan-batch-size", value]).unwrap_err();
            assert!(error.to_string().contains(value));
        }
        let missing = GuiArgs::try_parse_from(["argos-gui", "--scan-batch-size"]).unwrap_err();
        assert_eq!(missing.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn gui_help_and_version_exit_before_starting_the_app() {
        let help = GuiArgs::try_parse_from(["argos-gui", "--help"]).unwrap_err();
        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        let help = help.to_string();
        assert!(help.contains("--scan-batch-size <BLOCKS>"));
        assert!(help.contains("--verbose"));
        let version = GuiArgs::try_parse_from(["argos-gui", "--version"]).unwrap_err();
        assert_eq!(version.kind(), ErrorKind::DisplayVersion);
        assert!(version.to_string().contains(env!("CARGO_PKG_VERSION")));
    }
}

#[cfg(test)]
mod version_tests {
    /// `tauri.conf.json` carries its own hardcoded version, and the sidebar
    /// build display reads `CARGO_PKG_VERSION`. Nothing connected the two,
    /// so they could drift and the app would report a version it was not.
    /// Raised in review of #189.
    ///
    /// Pinned by a test rather than by generating one from the other: Tauri
    /// reads its config at build time and does not accept a reference to
    /// Cargo.toml, so the honest options are "generate the file" or "fail
    /// loudly when they disagree". This is the second, and it fails at the
    /// moment someone edits one of them.
    #[test]
    fn tauri_conf_version_matches_the_crate() {
        let conf = include_str!("../tauri.conf.json");
        let parsed: serde_json::Value =
            serde_json::from_str(conf).expect("tauri.conf.json must be valid JSON");
        let declared = parsed
            .get("version")
            .and_then(|v| v.as_str())
            .expect("tauri.conf.json must declare a version");

        assert_eq!(
            declared,
            env!("CARGO_PKG_VERSION"),
            "tauri.conf.json says {declared} but the crate is {}. The sidebar reports \
             CARGO_PKG_VERSION while the bundle is stamped from the config, so a user \
             would see one version and have another installed.",
            env!("CARGO_PKG_VERSION")
        );
    }
}
