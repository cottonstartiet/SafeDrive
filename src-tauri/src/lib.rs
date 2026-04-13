pub mod core;
pub mod commands;

use std::sync::Mutex;
use commands::{AppState, open_volume, list_files, extract_all, extract_files, mount_volume, unmount_volume, close_volume, is_elevated, preview_image, verify_lock_password};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            volume: Mutex::new(None),
            mount_handle: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            open_volume,
            list_files,
            extract_all,
            extract_files,
            mount_volume,
            unmount_volume,
            close_volume,
            is_elevated,
            preview_image,
            verify_lock_password,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
