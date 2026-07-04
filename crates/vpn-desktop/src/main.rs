// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell. The window's JS calls these commands via
//! `window.__TAURI__.core.invoke`. All real work lives in [`backend`], which
//! is also reachable headlessly through `vpn-desktop --selftest` (used to
//! verify the backend without opening a window).

mod backend;
mod creds;
mod daemon;
mod dns;

use backend::{AppState, ProfileSummary};
use vpn_control::{ConnectOutcome, IkeSa};

#[tauri::command]
async fn list_profiles(state: tauri::State<'_, AppState>) -> Result<Vec<ProfileSummary>, String> {
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend::list_profiles(&s))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn profiles_dir(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || Ok(backend::profiles_dir(&s)))
        .await
        .map_err(|e| e.to_string())?
}

/// Open a native file picker and import the chosen `.ini`. Returns the new
/// profile id, or `None` if the dialog was cancelled.
#[tauri::command]
async fn import_profile_dialog(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("NCP profile", &["ini"])
            .set_title("Import NCP profile")
            .blocking_pick_file();
        match picked {
            Some(fp) => {
                let path = fp.into_path().map_err(|e| e.to_string())?;
                backend::import_path(&s, &path).map(Some)
            }
            None => Ok(None),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn connect(
    state: tauri::State<'_, AppState>,
    id: String,
    gateway_override: Option<String>,
) -> Result<ConnectOutcome, String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::connect(&s, id, gateway_override))
        .await
    {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>, name: String) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::disconnect(&s, name)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn status(state: tauri::State<'_, AppState>) -> Result<Vec<IkeSa>, String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::status(&s)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn daemon_running(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || Ok(backend::daemon_running(&s)))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn start_daemon(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::daemon_start(&s)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn stop_daemon(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::daemon_stop(&s)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn save_credentials(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::save_credentials(&s, id)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn forget_credentials(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::forget_credentials(&s, id)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

fn selftest() {
    let state = AppState::from_env();
    let profiles = backend::list_profiles(&state);
    println!(
        "{}",
        serde_json::to_string_pretty(&profiles).expect("serialize profiles")
    );
    match backend::status(&state) {
        Ok(sas) => println!("status: {}", serde_json::to_string(&sas).expect("serialize sas")),
        Err(e) => eprintln!("status unavailable (expected without a running charon): {e}"),
    }
}

/// Headless verification harness: drives the exact same `backend` path the
/// Tauri commands use, so the connect/keychain/override flows can be exercised
/// (and CI-checked) without opening a window. Not part of the shipped UX.
fn dev(args: &[String]) {
    let state = AppState::from_env();
    let result: std::result::Result<String, String> = match args.first().map(String::as_str) {
        Some("connect") => {
            let id = args.get(1).cloned().unwrap_or_default();
            let gw = args.get(2).cloned();
            backend::connect(&state, id, gw)
                .map(|o| serde_json::to_string(&o).expect("serialize outcome"))
        }
        Some("disconnect") => backend::disconnect(&state, args.get(1).cloned().unwrap_or_default())
            .map(|_| "disconnected".to_string()),
        Some("daemon-status") => Ok(if backend::daemon_running(&state) {
            "running".to_string()
        } else {
            "stopped".to_string()
        }),
        Some("import") => backend::import_path(&state, std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("")))
            .map(|id| format!("imported {id}")),
        Some("profiles-dir") => Ok(backend::profiles_dir(&state)),
        Some("daemon-start") => backend::daemon_start(&state).map(|_| "started".to_string()),
        Some("daemon-stop") => backend::daemon_stop(&state).map(|_| "stopped".to_string()),
        Some("save-creds") => {
            backend::save_credentials(&state, args.get(1).cloned().unwrap_or_default())
                .map(|_| "saved".to_string())
        }
        Some("forget-creds") => {
            backend::forget_credentials(&state, args.get(1).cloned().unwrap_or_default())
                .map(|_| "forgotten".to_string())
        }
        // Store an explicit PSK for a profile id — lets a test prove the
        // keychain PSK (not the .ini's) is what authenticates the tunnel.
        Some("set-creds") => {
            let id = args.get(1).cloned().unwrap_or_default();
            let value = args.get(2).cloned().unwrap_or_default();
            creds::store(&id, &vpn_core::Secret::new(value)).map(|_| "set".to_string())
        }
        other => Err(format!("unknown dev command: {other:?}")),
    };
    match result {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("--selftest") => return selftest(),
        Some("--dev") => return dev(&argv[1..]),
        _ => {}
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::from_env())
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            profiles_dir,
            import_profile_dialog,
            connect,
            disconnect,
            status,
            daemon_running,
            start_daemon,
            stop_daemon,
            save_credentials,
            forget_credentials
        ])
        .setup(|app| {
            tray::build(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Closing the window hides it to the tray instead of quitting, so
            // the tunnel (and the app that drives it) keeps running.
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = window.hide();
                api.prevent_close();
            }
            // Dragging .ini files onto the window imports them; Enter/Leave
            // drive a drop-zone highlight in the UI.
            tauri::WindowEvent::DragDrop(drag) => {
                use tauri::{Emitter, Manager};
                match drag {
                    tauri::DragDropEvent::Enter { .. } => {
                        let _ = window.emit("drag-active", true);
                    }
                    tauri::DragDropEvent::Leave => {
                        let _ = window.emit("drag-active", false);
                    }
                    tauri::DragDropEvent::Drop { paths, .. } => {
                        let _ = window.emit("drag-active", false);
                        let state = window.state::<AppState>();
                        let imported: Vec<String> = paths
                            .iter()
                            .filter_map(|p| backend::import_path(state.inner(), p).ok())
                            .collect();
                        if !imported.is_empty() {
                            let _ = window.emit("profiles-changed", imported);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running the IPsec VPN Client");
}

/// System-tray icon + menu, so the app keeps running (and the tunnel stays up)
/// when the window is closed.
mod tray {
    use tauri::{
        menu::{Menu, MenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
        AppHandle, Manager,
    };

    fn reveal(app: &AppHandle) {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }

    pub fn build(app: &AppHandle) -> tauri::Result<()> {
        let show = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&show, &quit])?;

        TrayIconBuilder::with_id("main-tray")
            .icon(app.default_window_icon().expect("bundled window icon").clone())
            .tooltip("IPsec VPN Client")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id.as_ref() {
                "show" => reveal(app),
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    reveal(tray.app_handle());
                }
            })
            .build(app)?;
        Ok(())
    }
}
