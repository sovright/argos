#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use argos_core::RecoveryService;
use commands::AppState;
use tauri::Manager;

fn main() {
    // Surface argos-core diagnostics to stderr (visible in `npm run dev`).
    // Honors RUST_LOG; defaults to info, with debug for argos-core so the
    // per-account donation decision and any fallback warnings are observable.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,argos_core=debug")),
        )
        .try_init();

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
        })
        .invoke_handler(tauri::generate_handler![
            commands::validate_seed,
            commands::validate_address,
            commands::start_scan,
            commands::pick_wallet_file,
            commands::inspect_wallet_file,
            commands::start_scan_from_wallet_file,
            commands::get_scan_progress,
            commands::cancel_scan,
            commands::propose_sweep,
            commands::execute_sweep,
            commands::estimate_birthday_from_date,
            commands::detect_birthday,
            commands::save_recovery_report,
            commands::delete_workspace,
            commands::default_data_dir,
            commands::notify_user,
            commands::list_incomplete_sessions,
            commands::resume_session,
            commands::donation_address,
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
