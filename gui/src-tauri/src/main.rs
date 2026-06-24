#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::AppState;
use tauri::Manager;
use argos_core::RecoveryService;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            service: RecoveryService::new(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::validate_seed,
            commands::validate_address,
            commands::start_scan,
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
