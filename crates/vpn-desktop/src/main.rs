// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri desktop shell. The window's JS calls these commands via
//! `window.__TAURI__.core.invoke`. All real work lives in [`backend`], which
//! is also reachable headlessly through `vpn-desktop --selftest` (used to
//! verify the backend without opening a window).

mod backend;
mod creds;
mod daemon;
mod deeplink;
mod dns;
mod overrides;
mod portal;
mod ssl;
mod update;

use backend::{AppState, ProfileEdit, ProfileSummary};
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

/// Open a native file picker and import the chosen profile. Returns the new
/// profile id, or `None` if the dialog was cancelled.
#[tauri::command]
async fn import_profile_dialog(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<backend::ImportOutcome>, String> {
    use tauri_plugin_dialog::DialogExt;
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app
            .dialog()
            .file()
            // One combined filter first so the default view shows everything
            // importable, then per-vendor ones for a user who knows what they
            // are looking for. `.pro` and `.mobileconfig` are offered so a
            // provisioning file leads to the portal sign-in, and a portal
            // profile imports directly.
            .add_filter("VPN profile", &["ini", "scx", "tgb", "mobileconfig", "ovpn", "pro"])
            .add_filter("NCP profile", &["ini"])
            .add_filter("Sophos profile", &["scx", "tgb", "mobileconfig", "ovpn", "pro"])
            .set_title("Import VPN profile")
            .blocking_pick_file();
        match picked {
            Some(fp) => {
                let path = fp.into_path().map_err(|e| e.to_string())?;
                backend::classify_import(&s, &path).map(Some)
            }
            None => Ok(None),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Sign in to the portal a `.pro` names and import the profile it serves.
#[tauri::command]
async fn import_from_portal(
    state: tauri::State<'_, AppState>,
    portal_url: String,
    username: String,
    password: String,
    name: String,
) -> Result<String, String> {
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        backend::import_from_portal(&s, portal_url, username, password, name)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Collect what an `itmvpn://` link left for the window, if anything. Called
/// once on load: a link that *launched* the app is staged before the web view
/// exists, so it cannot be delivered as an event.
#[tauri::command]
async fn take_link_request(
    state: tauri::State<'_, AppState>,
) -> Result<Option<backend::LinkRequest>, String> {
    Ok(backend::take_link_request(state.inner()))
}

/// Import the profile an `itmvpn://` link brought in, after the user confirmed
/// it. Returns the new profile id.
#[tauri::command]
async fn confirm_link_import(
    state: tauri::State<'_, AppState>,
    token: u64,
) -> Result<String, String> {
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend::commit_link_import(&s, token))
        .await
        .map_err(|e| e.to_string())?
}

/// Throw away the profile an `itmvpn://` link brought in — the user declined it,
/// so it should not linger in memory waiting to be confirmed by a later dialog.
#[tauri::command]
async fn cancel_link_import(state: tauri::State<'_, AppState>) -> Result<(), String> {
    backend::cancel_link_import(state.inner());
    Ok(())
}

/// Delete an imported profile: its `.ini`, its saved edits, and its stored PSK.
#[tauri::command]
async fn delete_profile(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::delete_profile(&s, id)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

/// The editable parameters of a profile, as currently in effect.
#[tauri::command]
async fn get_profile_edit(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<ProfileEdit, String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::get_profile_edit(&s, id)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

/// Persist edited parameters (only what differs from the `.ini` is stored).
/// Returns the names of the fields that are now overridden.
#[tauri::command]
async fn save_profile_edit(
    state: tauri::State<'_, AppState>,
    id: String,
    edit: overrides::Edit,
) -> Result<Vec<String>, String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::save_profile_edit(&s, id, edit))
        .await
    {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

/// Drop a profile's edits, falling back to the imported `.ini`.
#[tauri::command]
async fn reset_profile_edit(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::reset_profile_edit(&s, id)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
/// `login` carries the XAuth/EAP username and password when the UI has just
/// prompted for them. It is omitted on an ordinary connect, where a saved
/// login (if any) is used instead.
async fn connect(
    state: tauri::State<'_, AppState>,
    id: String,
    login: Option<backend::UserLogin>,
) -> Result<ConnectOutcome, String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::connect(&s, id, login)).await {
        Ok(result) => result,
        Err(e) => Err(e.to_string()),
    }
}

/// Does this profile need a username and password before it can connect?
/// Lets the UI raise the prompt before calling `connect`, rather than having
/// to interpret a failure.
#[tauri::command]
async fn needs_user_login(state: tauri::State<'_, AppState>, id: String) -> Result<bool, String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::needs_user_login(&s, &id)).await {
        Ok(result) => Ok(result),
        Err(e) => Err(e.to_string()),
    }
}

/// Forget a saved XAuth/EAP login (the PSK entry is separate and stays).
#[tauri::command]
async fn forget_user_login(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::forget_user_login(&s, id)).await {
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

/// Drive the tray icon's status badge, tooltip and quick-connect menu.
///
/// All of it comes from the UI rather than being recomputed here: it is the UI
/// that reconciles every profile against what charon and the broker report
/// (`reconcile()` in `ui/index.html`), watches the byte counters for a stall,
/// and knows which profiles were used most recently. Deriving any of it a
/// second time in Rust would give the tray an opinion that could disagree with
/// the window. `detail` is the tooltip's second line.
#[tauri::command]
fn set_tray_status(
    app: tauri::AppHandle,
    status: String,
    detail: Option<String>,
    profiles: Option<Vec<tray::MenuProfile>>,
) {
    tray::set_status(
        &app,
        tray::Status::parse(&status),
        detail.as_deref().unwrap_or_default(),
        &profiles.unwrap_or_default(),
    );
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

/// Replace the profile's PSK with a user-supplied one (keychain only).
#[tauri::command]
async fn set_credentials(
    state: tauri::State<'_, AppState>,
    id: String,
    psk: String,
) -> Result<(), String> {
    let s = state.inner().clone();
    match tauri::async_runtime::spawn_blocking(move || backend::set_credentials(&s, id, psk)).await {
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

/// The running build's version, for the UI to show and to compare against.
#[tauri::command]
fn app_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Ask the release endpoint whether a newer version exists. `None` = current.
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<update::Available>, String> {
    update::check(&app).await
}

/// Download and run the newer installer. On Windows this ends the process, so
/// the call only ever returns on failure.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    update::install(&app).await
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
        // `connect <id> [user] [password] [save]` — the optional login stands in
        // for the GUI's prompt so the XAuth/EAP path is drivable headlessly.
        Some("connect") => {
            let login = args.get(2).map(|username| backend::UserLogin {
                username: username.clone(),
                password: args.get(3).cloned().unwrap_or_default(),
                save: args.get(4).map(|s| s == "save").unwrap_or(false),
            });
            backend::connect(&state, args.get(1).cloned().unwrap_or_default(), login)
                .map(|o| serde_json::to_string(&o).expect("serialize outcome"))
        }
        // `link <itmvpn://…> [import]` — run a deep link through the same
        // staging the GUI does, printing what the confirmation dialog would
        // show. Without `import` nothing is written, which is the point: it
        // exercises the untrusted path without landing a profile.
        Some("link") => url::Url::parse(args.get(1).map(String::as_str).unwrap_or(""))
            .map_err(|e| format!("bad url: {e}"))
            .and_then(|u| deeplink::parse(&u))
            .and_then(|link| backend::stage_link_import(&state, link))
            .and_then(|request| {
                let staged = serde_json::to_string_pretty(&request).expect("serialize request");
                let token = match &request {
                    backend::LinkRequest::Confirm(preview) => Some(preview.token),
                    _ => None,
                };
                match (args.get(2).map(String::as_str), token) {
                    (Some("import"), Some(token)) => backend::commit_link_import(&state, token)
                        .map(|id| format!("{staged}\nimported: {id}")),
                    _ => {
                        backend::cancel_link_import(&state);
                        Ok(staged)
                    }
                }
            }),
        Some("needs-user-login") => Ok(
            if backend::needs_user_login(&state, args.get(1).map(String::as_str).unwrap_or("")) {
                "yes".to_string()
            } else {
                "no".to_string()
            },
        ),
        Some("forget-user-login") => {
            backend::forget_user_login(&state, args.get(1).cloned().unwrap_or_default())
                .map(|_| "forgotten".to_string())
        }
        // Store a login without connecting — mirrors `set-creds` for the PSK,
        // and lets the keychain path be tested without dialling a gateway.
        Some("set-user-login") => backend::set_user_login(
            &state,
            args.get(1).cloned().unwrap_or_default(),
            args.get(2).cloned().unwrap_or_default(),
            args.get(3).cloned().unwrap_or_default(),
        )
        .map(|_| "set".to_string()),
        Some("disconnect") => backend::disconnect(&state, args.get(1).cloned().unwrap_or_default())
            .map(|_| "disconnected".to_string()),
        // Live connections across both datapaths (IPsec SAs + any SSL tunnel).
        Some("status") => backend::status(&state)
            .map(|sas| serde_json::to_string_pretty(&sas).expect("serialize status")),
        Some("daemon-status") => Ok(if backend::daemon_running(&state) {
            "running".to_string()
        } else {
            "stopped".to_string()
        }),
        Some("import") => backend::import_path(&state, std::path::Path::new(args.get(1).map(String::as_str).unwrap_or("")))
            .map(|id| format!("imported {id}")),
        // `import-portal <url> <username> <password> <name>` — drive the portal
        // sign-in + download + import headlessly, the way the GUI does after a
        // `.pro` is picked. Prints the new profile id; the key it downloads goes
        // into the profile file, never to stdout.
        Some("import-portal") => backend::import_from_portal(
            &state,
            args.get(1).cloned().unwrap_or_default(),
            args.get(2).cloned().unwrap_or_default(),
            args.get(3).cloned().unwrap_or_default(),
            args.get(4).cloned().unwrap_or_default(),
        )
        .map(|id| format!("imported {id}")),
        // `download-ssl <url> <username> <password> <outfile>` — sign in to the
        // portal and write the OpenVPN `.ovpn` it serves to a file, for
        // inspection ahead of a dedicated SSL VPN engine. The file holds a live
        // private key: only its path is printed, never its contents.
        Some("download-ssl") => {
            let out = args.get(4).cloned().unwrap_or_default();
            if out.is_empty() {
                Err("usage: download-ssl <url> <username> <password> <outfile>".to_string())
            } else {
                portal::download_ssl_profile(
                    args.get(1).map(String::as_str).unwrap_or(""),
                    args.get(2).map(String::as_str).unwrap_or(""),
                    args.get(3).map(String::as_str).unwrap_or(""),
                )
                .and_then(|ovpn| {
                    std::fs::write(&out, ovpn).map_err(|e| format!("could not write {out}: {e}"))
                })
                .map(|_| format!("wrote SSL VPN profile to {out}"))
            }
        }
        // `download-ipsec <url> <username> <password> <outfile>` — the IPsec
        // counterpart of `download-ssl`: sign in and write the `.mobileconfig`
        // the portal serves to a file. Exercises the fallback the provisioning
        // import uses when a portal offers no SSL VPN. The file holds a live PSK:
        // only its path is printed, never its contents.
        Some("download-ipsec") => {
            let out = args.get(4).cloned().unwrap_or_default();
            if out.is_empty() {
                Err("usage: download-ipsec <url> <username> <password> <outfile>".to_string())
            } else {
                portal::download_ipsec_profile(
                    args.get(1).map(String::as_str).unwrap_or(""),
                    args.get(2).map(String::as_str).unwrap_or(""),
                    args.get(3).map(String::as_str).unwrap_or(""),
                )
                .and_then(|cfg| {
                    std::fs::write(&out, cfg).map_err(|e| format!("could not write {out}: {e}"))
                })
                .map(|_| format!("wrote IPsec profile to {out}"))
            }
        }
        // `portal-services <url> <username> <password>` — print the portal's
        // advertised, non-secret service flags (which of IPsec / SSL VPN are on,
        // and how they authenticate). Diagnosis only; no secrets are printed.
        Some("portal-services") => portal::services(
            args.get(1).map(String::as_str).unwrap_or(""),
            args.get(2).map(String::as_str).unwrap_or(""),
            args.get(3).map(String::as_str).unwrap_or(""),
        ),
        Some("list") => Ok(serde_json::to_string_pretty(&backend::list_profiles(&state))
            .expect("serialize profiles")),
        Some("profiles-dir") => Ok(backend::profiles_dir(&state)),
        Some("delete") => backend::delete_profile(&state, args.get(1).cloned().unwrap_or_default())
            .map(|_| "deleted".to_string()),
        Some("get-edit") => backend::get_profile_edit(&state, args.get(1).cloned().unwrap_or_default())
            .map(|e| serde_json::to_string_pretty(&e).expect("serialize edit")),
        // Takes the same JSON `get-edit` prints (its `edit` object), so a test
        // can round-trip: read the parameters, change one, save it back.
        Some("save-edit") => {
            let id = args.get(1).cloned().unwrap_or_default();
            serde_json::from_str::<overrides::Edit>(args.get(2).map(String::as_str).unwrap_or(""))
                .map_err(|e| format!("bad edit json: {e}"))
                .and_then(|edit| backend::save_profile_edit(&state, id, edit))
                .map(|names| format!("overrides: {}", names.join(", ")))
        }
        Some("reset-edit") => backend::reset_profile_edit(&state, args.get(1).cloned().unwrap_or_default())
            .map(|_| "reset".to_string()),
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
        // Must be the first plugin registered: a second launch hands off to
        // this instance (focusing its window) instead of opening a duplicate.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::reveal(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        // Registered after single-instance, whose `deep-link` feature hands a
        // second launch's `itmvpn://` URL to this plugin instead of letting it
        // start a second copy of the app.
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState::from_env())
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            profiles_dir,
            import_profile_dialog,
            import_from_portal,
            delete_profile,
            connect,
            disconnect,
            status,
            set_tray_status,
            daemon_running,
            start_daemon,
            stop_daemon,
            save_credentials,
            set_credentials,
            forget_credentials,
            needs_user_login,
            forget_user_login,
            get_profile_edit,
            save_profile_edit,
            reset_profile_edit,
            take_link_request,
            confirm_link_import,
            cancel_link_import,
            app_version,
            check_update,
            install_update
        ])
        .setup(|app| {
            tray::build(app.handle())?;
            update::watch(app.handle());
            deeplink::watch(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Closing the window hides it to the tray instead of quitting, so
            // the tunnel (and the app that drives it) keeps running.
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = window.hide();
                api.prevent_close();
            }
            // Dragging profile files onto the window imports them; Enter/Leave
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
                        let mut imported: Vec<String> = Vec::new();
                        let mut errors: Vec<String> = Vec::new();
                        let mut provisioning = false;
                        for p in paths {
                            match backend::classify_import(state.inner(), p) {
                                Ok(backend::ImportOutcome::Profile { id }) => imported.push(id),
                                // A modal can't be opened from here; hand the
                                // portal target to the UI to run the sign-in.
                                Ok(backend::ImportOutcome::Provisioning { url, name, otp }) => {
                                    provisioning = true;
                                    let _ = window.emit(
                                        "provisioning-dropped",
                                        serde_json::json!({ "url": url, "name": name, "otp": otp }),
                                    );
                                }
                                Err(e) => errors.push(e),
                            }
                        }
                        let nothing_imported = imported.is_empty();
                        if !nothing_imported {
                            let _ = window.emit("profiles-changed", imported);
                        }
                        // A drop that imported nothing used to fail silently, so a
                        // parse error or an "already exists" collision looked like
                        // drag-drop was broken. Surface the reason instead.
                        if nothing_imported && !provisioning && !errors.is_empty() {
                            let _ = window.emit("import-error", errors.join("\n"));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running the VPN Client");
}

/// System-tray icon + menu, so the app keeps running (and the tunnel stays up)
/// when the window is closed.
mod tray {
    use tauri::{
        image::Image,
        menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
        AppHandle, Emitter, Manager, Wry,
    };

    pub(crate) const TRAY_ID: &str = "main-tray";

    /// Menu-item id prefix for the quick-connect entries. Profile ids are
    /// restricted to `[A-Za-z0-9._-]` by `backend::check_id`, so nothing in one
    /// can be mistaken for this separator.
    const PROFILE_PREFIX: &str = "profile:";

    /// Event carrying a clicked profile's id to the UI, which owns the connect
    /// flow (credential prompts, IKE version retry, the notices).
    pub(crate) const PROFILE_EVENT: &str = "tray-profile";

    /// What the tray icon reports at a glance. Mirrors the states the UI keeps
    /// per profile (`state` in `ui/index.html`), aggregated over all of them:
    /// a stalled tunnel wins over a healthy one (it is the actionable
    /// condition), which wins over a handshake in flight, which wins over
    /// nothing at all.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Status {
        Disconnected,
        Connecting,
        Connected,
        /// The SA is up and charon still calls it established, but the data
        /// path is one-way dead — see the stall detector in `ui/index.html`.
        Stalled,
    }

    impl Status {
        /// Parse the value the UI sends. An unrecognised one reads as
        /// disconnected rather than failing: a quiet grey dot beats an error
        /// the user never sees, on an indicator that is not load-bearing.
        pub fn parse(s: &str) -> Status {
            match s {
                "established" | "connected" => Status::Connected,
                "connecting" => Status::Connecting,
                "stalled" => Status::Stalled,
                _ => Status::Disconnected,
            }
        }

        /// Badge fill, matching the LED colours the window already uses
        /// (`--ok` / `--warn` / `--crit` / `--muted` in `ui/index.html`) so the
        /// tray and the dashboard never disagree about what green means.
        fn colour(self) -> [u8; 3] {
            match self {
                Status::Connected => [0x46, 0xc2, 0x66],
                Status::Connecting => [0xd9, 0xa5, 0x31],
                Status::Stalled => [0xf0, 0x60, 0x3a],
                Status::Disconnected => [0x86, 0x95, 0xab],
            }
        }

        fn label(self) -> &'static str {
            match self {
                Status::Connected => "connected",
                Status::Connecting => "connecting",
                Status::Stalled => "connected, no traffic",
                Status::Disconnected => "disconnected",
            }
        }

        /// Does this state mean there is a tunnel to tear down? Drives the
        /// checkmark beside a menu entry, and with it what clicking does.
        fn is_up(self) -> bool {
            matches!(self, Status::Connected | Status::Stalled)
        }
    }

    /// One quick-connect entry, as the UI hands it over: already ordered
    /// most-recently-used first and capped, because recency is the UI's to
    /// know (see `recents()` in `ui/index.html`).
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct MenuProfile {
        pub id: String,
        pub name: String,
        /// The same vocabulary [`Status::parse`] accepts.
        pub state: String,
    }

    /// Alpha-blend a straight-RGBA source pixel over a straight-RGBA destination.
    fn blend(dst: &mut [u8], src: [u8; 4]) {
        let a = src[3] as u32;
        if a == 0 {
            return;
        }
        for c in 0..3 {
            dst[c] = ((src[c] as u32 * a + dst[c] as u32 * (255 - a)) / 255) as u8;
        }
        dst[3] = (a + (dst[3] as u32 * (255 - a)) / 255).min(255) as u8;
    }

    /// Antialiasing ramp over one pixel, from a signed distance to an edge
    /// (positive inside).
    fn coverage(signed_distance: f32) -> f32 {
        (signed_distance + 0.5).clamp(0.0, 1.0)
    }

    /// Paint a status dot into the bottom-right corner of the app icon.
    ///
    /// Composited at runtime rather than shipped as three more `.png`s: the
    /// icon is the one asset that has to track the branding, and hand-staged
    /// variants of it would go stale the next time the logo changes (nothing
    /// regenerates icons — see the note in `build.rs`).
    ///
    /// The dot is deliberately large — 40% of the icon across — because the
    /// Windows tray draws at 16px, where a tastefully small badge disappears
    /// altogether. A ring in the window background colour separates it from
    /// whatever it lands on in the logo.
    fn badged(base: &Image<'_>, status: Status) -> Image<'static> {
        let (w, h) = (base.width(), base.height());
        let mut rgba = base.rgba().to_vec();
        // An icon whose buffer does not match its dimensions gets no badge
        // rather than an out-of-bounds panic inside the tray.
        if w == 0 || h == 0 || rgba.len() < w as usize * h as usize * 4 {
            return Image::new_owned(rgba, w, h);
        }

        let side = w.min(h) as f32;
        let radius = side * 0.20;
        let ring = (side * 0.055).max(1.0);
        let cx = w as f32 - radius - ring;
        let cy = h as f32 - radius - ring;
        let [r, g, b] = status.colour();

        for y in 0..h {
            for x in 0..w {
                let dx = x as f32 + 0.5 - cx;
                let dy = y as f32 + 0.5 - cy;
                let dist = (dx * dx + dy * dy).sqrt();
                let outer = coverage(radius + ring - dist);
                if outer == 0.0 {
                    continue;
                }
                let inner = coverage(radius - dist);
                let px = (y as usize * w as usize + x as usize) * 4;
                let dst = &mut rgba[px..px + 4];
                // Ring first, then the fill on top of it.
                blend(dst, [0x0b, 0x12, 0x1b, (outer * 255.0) as u8]);
                if inner > 0.0 {
                    blend(dst, [r, g, b, (inner * 255.0) as u8]);
                }
            }
        }
        Image::new_owned(rgba, w, h)
    }

    /// The label for a quick-connect entry. The checkmark already says "up",
    /// so only the states it cannot express get spelled out.
    fn entry_label(profile: &MenuProfile) -> String {
        match Status::parse(&profile.state) {
            Status::Connecting => format!("{} — connecting…", profile.name),
            Status::Stalled => format!("{} — no traffic", profile.name),
            _ => profile.name.clone(),
        }
    }

    /// Build the tray menu: window, the quick-connect entries, quit.
    ///
    /// Rebuilt whole on every change rather than mutated in place — a handful
    /// of items costs nothing to recreate, and it keeps the menu a pure
    /// function of the state the UI last sent.
    fn menu(app: &AppHandle, profiles: &[MenuProfile]) -> tauri::Result<Menu<Wry>> {
        let show = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

        let mut items: Vec<Box<dyn IsMenuItem<Wry>>> = vec![Box::new(show)];
        if !profiles.is_empty() {
            items.push(Box::new(PredefinedMenuItem::separator(app)?));
            for p in profiles {
                let status = Status::parse(&p.state);
                // A check item, so a live tunnel is marked the way the platform
                // marks anything else that is on — and clicking it reads as
                // turning it off, which is what it does.
                items.push(Box::new(CheckMenuItem::with_id(
                    app,
                    format!("{PROFILE_PREFIX}{}", p.id),
                    entry_label(p),
                    true,
                    status.is_up(),
                    None::<&str>,
                )?));
            }
        }
        items.push(Box::new(PredefinedMenuItem::separator(app)?));
        items.push(Box::new(quit));

        let refs: Vec<&dyn IsMenuItem<Wry>> = items.iter().map(|i| i.as_ref()).collect();
        Menu::with_items(app, &refs)
    }

    /// Repaint the tray icon, its tooltip and its menu for the current state.
    ///
    /// Failures are swallowed: the tray is an indicator, and a machine that
    /// refuses to update it must not break the connection it reports on.
    pub fn set_status(app: &AppHandle, status: Status, detail: &str, profiles: &[MenuProfile]) {
        let Some(tray) = app.tray_by_id(TRAY_ID) else {
            return;
        };
        if let Some(base) = app.default_window_icon() {
            let _ = tray.set_icon(Some(badged(base, status)));
        }
        // Hovering is how you find out *which* tunnel is up without opening
        // the window, so the detail line goes in the tooltip.
        let label = status.label();
        let tooltip = if detail.is_empty() {
            format!("VPN Client — {label}")
        } else {
            format!("VPN Client — {label}\n{detail}")
        };
        let _ = tray.set_tooltip(Some(tooltip));
        if let Ok(m) = menu(app, profiles) {
            let _ = tray.set_menu(Some(m));
        }
    }

    pub(crate) fn reveal(app: &AppHandle) {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }

    pub fn build(app: &AppHandle) -> tauri::Result<()> {
        // No quick-connect entries yet: the UI fills them in as soon as it has
        // read the profile directory, a beat after the window boots.
        let menu = menu(app, &[])?;

        // Start on the grey dot: until the UI has polled charon and the broker,
        // "disconnected" is the honest answer, and it puts the badge on screen
        // from the first frame so its later absence never reads as a bug.
        let base = app.default_window_icon().expect("bundled window icon");

        TrayIconBuilder::with_id(TRAY_ID)
            .icon(badged(base, Status::Disconnected))
            .tooltip("VPN Client — disconnected")
            .menu(&menu)
            .show_menu_on_left_click(false)
            // Registered globally rather than against this menu instance, so it
            // keeps working across the `set_menu` that every state change does.
            .on_menu_event(|app, event| match event.id.as_ref() {
                "show" => reveal(app),
                "quit" => app.exit(0),
                // Connecting needs the credential prompts, the IKE-version
                // retry and the error notices that all live in the UI, so the
                // click is handed there rather than reimplemented here.
                other => {
                    if let Some(id) = other.strip_prefix(PROFILE_PREFIX) {
                        let _ = app.emit(PROFILE_EVENT, id.to_string());
                    }
                }
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

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A fully transparent square, so anything the badge paints is visible
        /// as a change rather than hidden by the logo underneath.
        fn blank(side: u32) -> Image<'static> {
            Image::new_owned(vec![0u8; (side * side * 4) as usize], side, side)
        }

        /// The pixel at the badge's centre, as RGBA.
        fn centre(img: &Image<'_>) -> [u8; 4] {
            let side = img.width().min(img.height()) as f32;
            let radius = side * 0.20;
            let ring = (side * 0.055).max(1.0);
            let x = (img.width() as f32 - radius - ring) as u32;
            let y = (img.height() as f32 - radius - ring) as u32;
            let px = (y as usize * img.width() as usize + x as usize) * 4;
            let b = img.rgba();
            [b[px], b[px + 1], b[px + 2], b[px + 3]]
        }

        #[test]
        fn each_status_paints_its_own_colour() {
            let base = blank(32);
            assert_eq!(centre(&badged(&base, Status::Connected)), [0x46, 0xc2, 0x66, 255]);
            assert_eq!(centre(&badged(&base, Status::Connecting)), [0xd9, 0xa5, 0x31, 255]);
            assert_eq!(centre(&badged(&base, Status::Disconnected)), [0x86, 0x95, 0xab, 255]);
        }

        #[test]
        fn badge_stays_in_its_corner() {
            let out = badged(&blank(32), Status::Connected);
            assert_eq!((out.width(), out.height()), (32, 32));
            // The top-left quadrant is where the wordmark lives; the badge must
            // not reach into it at any icon size we ship.
            let b = out.rgba();
            for y in 0..16u32 {
                for x in 0..16u32 {
                    let px = (y as usize * 32 + x as usize) * 4;
                    assert_eq!(b[px + 3], 0, "badge bled into ({x},{y})");
                }
            }
        }

        /// Windows renders the tray at 16px. The dot has to survive that, so it
        /// must be several pixels across even on the smallest icon we could be
        /// handed — this is the whole reason it is 40% of the icon.
        #[test]
        fn dot_is_legible_at_tray_size() {
            let out = badged(&blank(16), Status::Connected);
            let b = out.rgba();
            let opaque = (0..16 * 16).filter(|i| b[i * 4 + 3] > 128).count();
            assert!(opaque >= 20, "badge covers only {opaque} of 256 px");
        }

        /// An icon whose buffer is shorter than its declared dimensions must
        /// come back unbadged, not panic inside the tray.
        #[test]
        fn truncated_icon_is_passed_through() {
            let broken = Image::new_owned(vec![0u8; 16], 32, 32);
            let out = badged(&broken, Status::Connected);
            assert_eq!(out.rgba().len(), 16);
        }

        #[test]
        fn ui_state_names_map_to_statuses() {
            // "established" is the name the UI's state map uses; the others are
            // spelled the same on both sides.
            assert_eq!(Status::parse("established"), Status::Connected);
            assert_eq!(Status::parse("connecting"), Status::Connecting);
            assert_eq!(Status::parse("stalled"), Status::Stalled);
            assert_eq!(Status::parse("disconnected"), Status::Disconnected);
            assert_eq!(Status::parse("nonsense"), Status::Disconnected);
        }

        /// A stalled tunnel is still a tunnel: the entry stays checked, so
        /// clicking it tears down rather than trying to connect what is
        /// already connected.
        #[test]
        fn a_stalled_tunnel_still_counts_as_up() {
            assert!(Status::Stalled.is_up());
            assert!(Status::Connected.is_up());
            assert!(!Status::Connecting.is_up());
            assert!(!Status::Disconnected.is_up());
        }

        fn entry(state: &str) -> String {
            entry_label(&MenuProfile {
                id: "x".into(),
                name: "ITM-Office".into(),
                state: state.into(),
            })
        }

        #[test]
        fn only_states_the_checkmark_cannot_show_are_spelled_out() {
            assert_eq!(entry("established"), "ITM-Office");
            assert_eq!(entry("disconnected"), "ITM-Office");
            assert_eq!(entry("connecting"), "ITM-Office — connecting…");
            assert_eq!(entry("stalled"), "ITM-Office — no traffic");
        }

        /// The menu id has to survive the round trip back to a profile id, for
        /// every id `backend::check_id` lets through.
        #[test]
        fn profile_ids_round_trip_through_menu_ids() {
            for id in ["ITM-Office", "a.b.c", "x_1-2", "IPSEC_ITM_2"] {
                let menu_id = format!("{PROFILE_PREFIX}{id}");
                assert_eq!(menu_id.strip_prefix(PROFILE_PREFIX), Some(id));
            }
            // A built-in item must never be mistaken for a profile.
            assert_eq!("quit".strip_prefix(PROFILE_PREFIX), None);
            assert_eq!("show".strip_prefix(PROFILE_PREFIX), None);
        }
    }
}
