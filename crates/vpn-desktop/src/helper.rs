//! Install, remove and query the macOS privileged helper (a LaunchDaemon).
//!
//! The helper is what removes the authorization prompt from every connect and
//! disconnect. Installing it needs root exactly once: this raises a single
//! prompt and runs the helper binary's own `install` subcommand behind it, which
//! copies itself and charon to root-owned locations and bootstraps the daemon.
//!
//! The app never becomes root itself. It elevates one known binary — the one
//! shipped inside its own bundle — and everything else goes over the socket.

/// Where the helper binary ships inside the app bundle, plus the dev-build
/// fallback so this works from `cargo build` without bundling.
#[cfg(target_os = "macos")]
fn helper_bin() -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("VPN_HELPER_BIN") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // <App>.app/Contents/MacOS/vpn-desktop -> ../Resources/helper/vpn-broker
            candidates.push(dir.join("../Resources/helper/vpn-broker"));
            candidates.push(dir.join("helper/vpn-broker"));
            // Dev: target/<profile>/vpn-desktop -> target/<profile>/vpn-broker
            candidates.push(dir.join("vpn-broker"));
        }
    }
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| "the helper binary was not found (build it with `cargo build -p vpn-broker`)".to_string())
}

/// Should the app install the helper without being asked?
///
/// The helper is meant to be the default, the way the Windows installer
/// registers the broker service: a background daemon that is simply there, not
/// something a user has to discover. macOS has no installer hook for a `.dmg`
/// — dragging an app to /Applications runs nothing — so the closest equivalent
/// is to set it up on first launch.
///
/// Returns true at most once per user. The marker is written *before* the
/// attempt, so declining the authorization prompt is remembered too: being
/// asked once is setup, being asked at every launch is nagging. The strip and
/// the sidebar row stay, so a user who said no can still say yes later.
#[cfg(target_os = "macos")]
pub fn setup_pending() -> bool {
    let (installed, reachable) = status();
    if installed && reachable {
        return false;
    }
    let marker = crate::backend::app_data_dir().join("helper-setup-attempted");
    if marker.exists() {
        return false;
    }
    if let Some(dir) = marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // If the marker cannot be written, don't offer: a prompt on every launch is
    // worse than no prompt at all.
    std::fs::write(&marker, "1").is_ok()
}

#[cfg(not(target_os = "macos"))]
pub fn setup_pending() -> bool {
    false
}

/// Is the helper installed and answering?
#[cfg(target_os = "macos")]
pub fn status() -> (bool, bool) {
    (
        vpn_broker::launchd::installed(),
        vpn_broker::unix_client::available(),
    )
}

/// Install the helper. Raises one authorization prompt.
#[cfg(target_os = "macos")]
pub fn install() -> Result<String, String> {
    let bin = helper_bin()?;
    let script = format!("{} install", crate::daemon::sh_quote(&bin.to_string_lossy()));
    crate::daemon::osascript_admin(&script, "install the VPN helper")?;
    // launchd starts it asynchronously; wait briefly for the socket rather
    // than reporting success on a daemon that has not come up.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if vpn_broker::unix_client::available() {
            return Ok("helper installed — connect and disconnect no longer prompt".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    Err("the helper was installed but is not answering on its socket".to_string())
}

/// Remove the helper. Raises one authorization prompt.
#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<String, String> {
    let bin = helper_bin()?;
    let script = format!("{} uninstall", crate::daemon::sh_quote(&bin.to_string_lossy()));
    crate::daemon::osascript_admin(&script, "remove the VPN helper")?;
    Ok("helper removed — connect and disconnect will prompt again".to_string())
}

/// Remove the whole application: the privileged parts, this user's data, and
/// finally the bundle itself.
///
/// macOS has no uninstaller and no equivalent of Add/Remove Programs — the
/// convention is that dragging an app to the Trash is enough. It is not enough
/// here: a LaunchDaemon, a root-owned copy of charon and openvpn, and any
/// `/etc/resolver` files outlive the bundle and cannot be removed without
/// root. So the app removes itself, which is what every macOS app with a
/// privileged helper ends up doing.
///
/// Raises at most one authorization prompt (for the privileged half). Every
/// step after that is best-effort: a keychain entry that will not delete is
/// not a reason to leave a LaunchDaemon behind, so failures are collected and
/// reported rather than aborting the removal half-way.
#[cfg(target_os = "macos")]
pub fn uninstall_app(state: &crate::backend::AppState) -> Result<String, String> {
    let mut left_behind: Vec<String> = Vec::new();

    // Tunnels first, through the helper that owns the processes. charon is
    // stopped by the privileged half below; the SSL tunnels are the helper's
    // own children, so they go while it is still there to be asked.
    let _ = crate::ssl::disconnect("");

    // The privileged half: LaunchDaemon, helper binary, /Library/Application
    // Support, /var/run, /var/log, /etc/resolver. This is the only step that
    // needs a password, and the only one that can fail hard — everything it
    // removes is unreachable to us afterwards.
    let bin = helper_bin()?;
    let script = format!("{} uninstall", crate::daemon::sh_quote(&bin.to_string_lossy()));
    crate::daemon::osascript_admin(&script, "remove the VPN helper")?;

    // Keychain entries are keyed by profile id, so they have to go before the
    // profiles that name them — after this the ids are gone and the entries
    // would be unreachable, waiting to be inherited by the next profile
    // imported under the same name.
    for p in crate::backend::list_profiles(state) {
        if let Err(e) = crate::creds::delete(&p.id) {
            left_behind.push(format!("keychain entry for {}: {e}", p.id));
        }
        if let Err(e) = crate::creds::delete_user(&p.id) {
            left_behind.push(format!("keychain login for {}: {e}", p.id));
        }
    }

    for dir in user_data_dirs() {
        remove_if_present(&dir, &mut left_behind);
    }

    // Last, because it takes the code that is running out from under itself.
    let trashed = trash_own_bundle();

    let mut msg = match trashed {
        Ok(true) => "VPN Client has been removed and moved to the Trash.".to_string(),
        // A `cargo run` build is not in a bundle and there is nothing to trash.
        Ok(false) => "Everything VPN Client installed has been removed.".to_string(),
        Err(e) => {
            left_behind.push(format!("the app bundle: {e}"));
            "Everything VPN Client installed has been removed.".to_string()
        }
    };
    if !left_behind.is_empty() {
        msg.push_str(&format!(
            " These could not be removed and are safe to delete by hand: {}.",
            left_behind.join("; ")
        ));
    }
    Ok(msg)
}

/// Everything this app writes under the user's home.
///
/// Profiles are in the first entry, and they are not backed up anywhere: this
/// is why the dialog that calls into here has to name them.
#[cfg(target_os = "macos")]
fn user_data_dirs() -> Vec<std::path::PathBuf> {
    let mut out = vec![crate::backend::app_data_dir()];
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
        return out;
    };
    let lib = home.join("Library");
    for rel in [
        "Caches/dev.jackolix.ipsecvpn",
        // WebView state: the window's localStorage lives here, so leaving it
        // would carry dismissed banners and the last view into a reinstall.
        "WebKit/dev.jackolix.ipsecvpn",
        "HTTPStorages/dev.jackolix.ipsecvpn",
        "Saved Application State/dev.jackolix.ipsecvpn.savedState",
        "Preferences/dev.jackolix.ipsecvpn.plist",
    ] {
        out.push(lib.join(rel));
    }
    out
}

#[cfg(target_os = "macos")]
fn remove_if_present(path: &std::path::Path, failures: &mut Vec<String>) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return, // absent is the expected case for most of these
    };
    let r = if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    if let Err(e) = r {
        failures.push(format!("{}: {e}", path.display()));
    }
}

/// Move the running `.app` to the Trash. `Ok(false)` when we are not running
/// from a bundle at all.
///
/// Finder rather than a plain rename, so the bundle lands in the Trash the way
/// a drag would — recoverable, and counted against the right volume's Trash.
/// Deleting a running bundle is safe: the move is a rename, and the pages this
/// process has mapped keep pointing at the same inode.
#[cfg(target_os = "macos")]
fn trash_own_bundle() -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // .../VPN Client.app/Contents/MacOS/vpn-desktop -> .../VPN Client.app
    let Some(bundle) = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
    else {
        return Ok(false);
    };
    let script = format!(
        r#"tell application "Finder" to delete POSIX file "{}""#,
        bundle.to_string_lossy().replace('\\', r"\\").replace('"', "\\\"")
    );
    let out = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("cannot run osascript: {e}"))?;
    if out.status.success() {
        Ok(true)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

// The helper is macOS-only; Windows has the broker service and Linux uses the
// dev container.
#[cfg(not(target_os = "macos"))]
pub fn status() -> (bool, bool) {
    (false, false)
}
#[cfg(not(target_os = "macos"))]
pub fn install() -> Result<String, String> {
    Err("the privileged helper is macOS-only".to_string())
}
#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<String, String> {
    Err("the privileged helper is macOS-only".to_string())
}
#[cfg(not(target_os = "macos"))]
pub fn uninstall_app(_state: &crate::backend::AppState) -> Result<String, String> {
    // Windows uninstalls through Add/Remove Programs, which the NSIS and MSI
    // packages register; Linux through the package manager.
    Err("in-app uninstall is macOS-only".to_string())
}
