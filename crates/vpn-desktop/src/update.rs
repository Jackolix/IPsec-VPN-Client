//! In-app updates.
//!
//! The app looks for a `latest.json` published beside the installers on the
//! GitHub Release, and when it names a version newer than this build, fetches
//! what that manifest points at for this platform. The two platforms then
//! diverge completely, and the difference is not cosmetic:
//!
//! **Windows** downloads the NSIS installer and hands it to the OS to run.
//! Everything the product ships lives inside that one installer — the GUI, the
//! broker service, charon and OpenVPN — so an update replaces the whole set at
//! once and there is no version skew to reason about between the unelevated app
//! and the privileged service it talks to. Two consequences the UI has to be
//! honest about, both the installer's doing rather than ours: its PREINSTALL
//! hook stops the broker service (which reverts DNS and stops charon), so
//! installing tears down a live tunnel; and because the bundle is perMachine,
//! running it raises a UAC prompt.
//!
//! **macOS** swaps the `.app` bundle in place and relaunches — and *only* the
//! bundle. The privileged half installed under `/Library` (the helper daemon,
//! charon, openvpn) is untouched, because replacing it needs root and an
//! update must not raise an authorization prompt of its own. So macOS does have
//! the version skew Windows does not, and it is silent unless something looks
//! for it: [`crate::helper::status`] compares the app version recorded at
//! install time against the running one and the window offers to update the
//! helper. Two further macOS-only limits: the swap needs the bundle to be
//! writable, so an app run straight from the disk image can never update itself
//! (see [`crate::helper::bad_install_location`]), and the manifest carries only
//! `darwin-aarch64` — Apple Silicon is the only macOS build there is.
//!
//! Trust comes from the signature, not the transport. `latest.json` names a
//! minisign signature for the installer, and the plugin verifies it against the
//! public key compiled in from `tauri.conf.json` before anything is executed —
//! so whoever serves the release cannot get code run here without the private
//! key, which never leaves the release workflow's secrets.

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

/// A published release newer than the running build.
#[derive(Serialize, Clone)]
pub struct Available {
    pub version: String,
    pub current_version: String,
    /// The release notes, as the Release carries them. Often empty.
    pub notes: String,
    pub date: Option<String>,
}

/// Ask the endpoint whether anything newer exists. `Ok(None)` means this build
/// is current — the ordinary answer, and not an error.
pub async fn check(app: &AppHandle) -> Result<Option<Available>, String> {
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?;
    Ok(update.map(|u| Available {
        version: u.version.clone(),
        current_version: u.current_version.clone(),
        notes: u.body.clone().unwrap_or_default(),
        date: u.date.map(|d| d.to_string()),
    }))
}

/// Download the newer installer and run it. Emits `update-progress`
/// (`{downloaded, total}` in bytes) while the download runs, then
/// `update-downloaded` — the plugin's callback fires when the last byte lands,
/// *before* it checks the signature, so the UI must not claim more than that.
///
/// Re-checks rather than holding the `Update` from an earlier [`check`]: the
/// request is one small GET, and keeping a live handle in app state only buys a
/// way for the two to disagree.
pub async fn install(app: &AppHandle) -> Result<(), String> {
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "This build is already the latest version.".to_string())?;

    let progress_app = app.clone();
    let mut downloaded: u64 = 0;
    let done_app = app.clone();

    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = progress_app.emit(
                    "update-progress",
                    serde_json::json!({ "downloaded": downloaded, "total": total }),
                );
            },
            move || {
                let _ = done_app.emit("update-downloaded", ());
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    // Windows never gets here: the plugin launches the installer and exits the
    // process, because the installer cannot overwrite a running .exe. The
    // installer restarts the app itself. This is the path the other platforms
    // take, where the swap happens in-place and we relaunch — on macOS with an
    // installed helper that is now a version behind, which the window points
    // out on the next render.
    app.restart()
}

/// Check shortly after launch and then a few times a day, telling the window
/// whenever something newer is out — so the user meets an update as a banner
/// rather than having to go looking for a button.
///
/// The recheck is not busywork: this app lives in the tray and keeps the tunnel
/// up, so it is routinely left running for weeks, and a launch-only check would
/// reach exactly those users last.
///
/// Deliberately quiet on failure: no network, a blocked endpoint, or a release
/// without a `latest.json` are all ordinary for a VPN client that may be started
/// on a captive network, and none of them are worth interrupting anyone over.
/// The manual check in the UI reports its errors, which is where a user who
/// cares will look. Re-emitting a version the user already dismissed is
/// harmless — the UI remembers the dismissal and stays quiet until a newer one.
pub fn watch(app: &AppHandle) {
    let app = app.clone();
    // Sleeping on a plain thread rather than in the async task: the window has
    // to paint and the vici/broker probes have to settle first, and nothing here
    // is urgent enough to compete with them for the first seconds.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(8));
        loop {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                match check(&app).await {
                    Ok(Some(available)) => {
                        let _ = app.emit("update-available", available);
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("update check failed: {e}"),
                }
            });
            std::thread::sleep(std::time::Duration::from_secs(6 * 60 * 60));
        }
    });
}
