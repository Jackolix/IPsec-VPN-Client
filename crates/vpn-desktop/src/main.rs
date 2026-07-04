// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell. The window's JS calls these commands via
//! `window.__TAURI__.core.invoke`. All real work lives in [`backend`], which
//! is also reachable headlessly through `vpn-desktop --selftest` (used to
//! verify the backend without opening a window).

mod backend;
mod creds;
mod daemon;

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
        .manage(AppState::from_env())
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            connect,
            disconnect,
            status,
            daemon_running,
            start_daemon,
            stop_daemon,
            save_credentials,
            forget_credentials
        ])
        .run(tauri::generate_context!())
        .expect("error while running the IPsec VPN Client");
}
