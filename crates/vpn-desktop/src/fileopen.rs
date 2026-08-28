//! Profiles the OS hands to the app: a `.scx`, `.tgb`, `.pro` or `.ini` opened
//! from Explorer (double-clicked, "Open with", or dropped on the app's icon).
//!
//! Windows and Linux deliver such a file as a path on the command line — of a
//! cold start, or of a second launch that the single-instance plugin folds into
//! the running one. macOS delivers it as [`tauri::RunEvent::Opened`] instead.
//! All three land in [`import`].
//!
//! Trust-wise this is a drag-and-drop onto the window, not an `itmvpn://` link:
//! the user picked the file out of their own file system, so it is imported
//! straight away rather than staged behind a confirmation dialog (see
//! [`crate::backend::stage_link_import`] for the case that is not).

use crate::backend::{self, AppState, ImportOutcome, LinkRequest};
use std::path::{Path, PathBuf};

/// Pick the profile files out of a command line.
///
/// Filtering by extension rather than by position is what makes this safe to
/// point at either kind of argv: a cold start's (`--selftest`, `--dev`, an
/// `itmvpn://` URL) or a second instance's, which still has the executable
/// itself in slot 0. None of those carry a profile extension, so none survive.
/// A relative path is resolved against `cwd` — the *second* instance's working
/// directory, which is not this process's.
fn profile_paths<I>(args: I, cwd: &Path) -> Vec<PathBuf>
where
    I: IntoIterator<Item = String>,
{
    args.into_iter()
        .map(|arg| {
            let path = PathBuf::from(arg);
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        })
        .filter(|path| backend::is_importable_path(path) && path.is_file())
        .collect()
}

/// A profile file named on this process's own command line — how the shell
/// starts the app for a file when it is not already running.
///
/// Called from `setup`, so nothing can be emitted yet; [`deliver`] parks the
/// result for the web view to collect on load.
pub fn watch(app: &tauri::AppHandle) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let paths = profile_paths(std::env::args().skip(1), &cwd);
    if paths.is_empty() {
        return;
    }
    deliver(app, import(app, &paths));
}

/// A file opened while the app was already running: the shell starts a second
/// copy, and the single-instance plugin hands us its arguments instead.
pub fn second_instance(app: &tauri::AppHandle, argv: Vec<String>, cwd: String) {
    // Whatever the second launch was for, the point of it was to bring this
    // window forward.
    crate::tray::reveal(app);
    let paths = profile_paths(argv, Path::new(&cwd));
    if paths.is_empty() {
        return;
    }
    deliver(app, import(app, &paths));
}

/// macOS' equivalent of a file on the command line. The URLs are `file://`
/// ones; anything else the app is registered for (an `itmvpn://` link) is the
/// deep-link plugin's, and is dropped here.
#[cfg(target_os = "macos")]
pub fn opened(app: &tauri::AppHandle, urls: &[url::Url]) {
    crate::tray::reveal(app);
    let paths: Vec<PathBuf> = urls
        .iter()
        .filter_map(|u| u.to_file_path().ok())
        .filter(|path| backend::is_importable_path(path) && path.is_file())
        .collect();
    if paths.is_empty() {
        return;
    }
    deliver(app, import(app, &paths));
}

/// Import every file, and boil the results down to the one thing the window can
/// act on. The window shows one modal at a time, so a batch that both imported a
/// profile and named a portal reports the import; a batch that imported nothing
/// reports why, exactly as a failed drag-and-drop does.
fn import(app: &tauri::AppHandle, paths: &[PathBuf]) -> LinkRequest {
    use tauri::Manager;

    let state = app.state::<AppState>();
    let mut ids: Vec<String> = Vec::new();
    let mut provisioning: Option<LinkRequest> = None;
    let mut errors: Vec<String> = Vec::new();
    for path in paths {
        match backend::classify_import(state.inner(), path) {
            Ok(ImportOutcome::Profile { id }) => ids.push(id),
            // A `.pro` holds no connection; it names a portal to sign in to,
            // which is a dialog the UI owns.
            Ok(ImportOutcome::Provisioning { url, name, otp }) => {
                provisioning.get_or_insert(LinkRequest::Provisioning { url, name, otp });
            }
            Err(e) => errors.push(e),
        }
    }

    if !ids.is_empty() {
        return LinkRequest::Imported { ids };
    }
    if let Some(request) = provisioning {
        return request;
    }
    LinkRequest::Failed {
        message: if errors.is_empty() {
            "that file could not be imported".to_string()
        } else {
            errors.join("\n")
        },
    }
}

/// Hand a request to the window — or park it, when the web view has not
/// attached its listeners yet (a launch), in which case it is collected by the
/// `take_link_request` command on load.
///
/// Shared with [`crate::deeplink`], which delivers the same requests.
pub fn deliver(app: &tauri::AppHandle, request: LinkRequest) {
    use tauri::{Emitter, Manager};

    let state = app.state::<AppState>();
    let listening = app
        .get_webview_window("main")
        .filter(|_| backend::ui_ready(state.inner()));
    let Some(window) = listening else {
        return backend::defer_link_request(state.inner(), request);
    };

    match request {
        LinkRequest::Confirm(preview) => {
            let _ = window.emit("link-import", preview);
        }
        // The same event a drag-and-drop import raises.
        LinkRequest::Imported { ids } => {
            let _ = window.emit("profiles-changed", ids);
        }
        LinkRequest::Provisioning { url, name, otp } => {
            let _ = window.emit(
                "provisioning-dropped",
                serde_json::json!({ "url": url, "name": name, "otp": otp }),
            );
        }
        LinkRequest::Failed { message } => {
            let _ = window.emit("import-error", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_profiles_out_of_an_argv_and_ignores_everything_else() {
        let dir = std::env::temp_dir().join(format!("vpn-fileopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        for name in ["acme_site.scx", "old.tgb", "portal.pro", "ncp.ini", "notes.txt"] {
            std::fs::write(dir.join(name), "x").expect("write");
        }

        let argv = vec![
            // A second instance's argv still starts with the executable.
            dir.join("vpn-desktop.exe").display().to_string(),
            "--selftest".to_string(),
            "itmvpn://import?data=AA".to_string(),
            "notes.txt".to_string(),
            "gone.scx".to_string(),
            dir.join("acme_site.scx").display().to_string(),
            "old.tgb".to_string(),
            "portal.pro".to_string(),
            "ncp.ini".to_string(),
        ];
        let got: Vec<String> = profile_paths(argv, &dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, ["acme_site.scx", "old.tgb", "portal.pro", "ncp.ini"]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
