// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell. The window's JS calls these commands via
//! `window.__TAURI__.core.invoke`. All real work lives in [`backend`], which
//! is also reachable headlessly through `vpn-desktop --selftest` (used to
//! verify the backend without opening a window).

mod backend;

use backend::{AppState, ProfileSummary};
use vpn_control::IkeSa;

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
) -> Result<(), String> {
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

fn main() {
    if std::env::args().any(|a| a == "--selftest") {
        selftest();
        return;
    }

    tauri::Builder::default()
        .manage(AppState::from_env())
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            connect,
            disconnect,
            status
        ])
        .run(tauri::generate_context!())
        .expect("error while running the IPsec VPN Client");
}
