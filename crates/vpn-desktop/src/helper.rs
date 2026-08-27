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
