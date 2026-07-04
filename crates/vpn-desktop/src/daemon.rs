//! Lifecycle control for the native Windows strongSwan daemon
//! (`charon-svc.exe`). Unlike the Linux dev container, the daemon terminates
//! the tunnel on the Windows host via the Windows Filtering Platform, which
//! needs Administrator rights — so the GUI (which runs unelevated) launches it
//! through a UAC prompt and talks to it over loopback vici afterwards.
//!
//! `charon-svc.exe` and its DLLs are shipped as bundled app resources (see
//! `tauri.conf.json` `bundle.resources`), so the app is self-contained. We
//! elevate `charon-svc.exe` directly with its own directory as the working
//! directory (so it finds its sibling DLLs); it comes up on its default vici
//! port with routing/virtual-IP install on by default — no config file needed.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// charon-svc's built-in Windows vici default; the app targets this for the
/// native backend (the Linux dev container uses 45022 instead).
pub const NATIVE_VICI_ADDR: &str = "127.0.0.1:4502";

/// Is a vici control socket accepting connections at `addr`? A successful TCP
/// connect means charon is up (vici is charon's only TCP listener).
pub fn is_running(addr: &str) -> bool {
    addr.to_socket_addr()
        .and_then(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(400)).ok())
        .is_some()
}

/// Locate `charon-svc.exe`. Resolution order:
///   1. `VPN_CHARON_EXE` (explicit full path) / `VPN_CHARON_DIR` (its folder),
///   2. bundled next to the app exe (`<exe_dir>/charon/`, or beside it),
///   3. the dev build tree (`out/strongswan-windows`, relative to cwd or the
///      target/ dir), so `cargo run` and the CLI work without a bundle.
fn charon_exe() -> Result<PathBuf, String> {
    const EXE: &str = "charon-svc.exe";
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(p) = std::env::var_os("VPN_CHARON_EXE") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(d) = std::env::var_os("VPN_CHARON_DIR") {
        candidates.push(PathBuf::from(d).join(EXE));
    }
    // Bundled resource layout (Tauri copies bundle.resources next to the exe).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("charon").join(EXE));
            candidates.push(dir.join(EXE));
            candidates.push(dir.join("resources").join("charon").join(EXE));
            // Dev: target/debug/vpn-desktop.exe -> repo/out/strongswan-windows
            candidates.push(dir.join("../../out/strongswan-windows").join(EXE));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("out/strongswan-windows").join(EXE));
    }

    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            "charon-svc.exe not found (build it with scripts/build-strongswan-windows.ps1, \
             or set VPN_CHARON_DIR)"
                .to_string()
        })
}

/// Start the native daemon if it is not already listening at `addr`. On
/// Windows this raises a UAC prompt (elevating `charon-svc.exe`) and then waits
/// for vici to come up. A no-op if already running.
#[cfg(windows)]
pub fn start(addr: &str) -> Result<(), String> {
    if is_running(addr) {
        return Ok(());
    }
    // If the broker service is installed it owns charon's lifecycle — don't
    // elevate-spawn a second copy. Just wait for the broker to bring it up.
    if vpn_broker::client::available() {
        let deadline = Instant::now() + Duration::from_secs(40);
        while Instant::now() < deadline {
            if is_running(addr) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        return Err("the VPN broker service is running but charon isn't responding".to_string());
    }
    let exe = charon_exe()?;
    let dir: &Path = exe.parent().ok_or("charon-svc.exe has no parent directory")?;
    let exe_ps = exe.to_string_lossy().replace('\'', "''");
    let dir_ps = dir.to_string_lossy().replace('\'', "''");

    // A non-elevated powershell issues Start-Process -Verb RunAs, which raises
    // the UAC prompt and launches charon-svc.exe elevated. Its working dir is
    // its own folder so the sibling DLLs resolve; it keeps running in the
    // background after this command returns (once the prompt is answered).
    let inner = format!(
        "Start-Process -FilePath '{exe_ps}' -WorkingDirectory '{dir_ps}' -Verb RunAs"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &inner])
        .status()
        .map_err(|e| format!("failed to launch elevated charon-svc: {e}"))?;
    if !status.success() {
        return Err("elevation was declined or failed (UAC)".to_string());
    }

    // Wait for WFP init + vici bind (the time spent at the UAC prompt is
    // already elapsed above).
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if is_running(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("charon-svc did not start listening within 40s".to_string())
}

/// Stop the native daemon. On Windows this raises a UAC prompt (an elevated
/// process can only be killed by an elevated one) and waits for it to exit.
#[cfg(windows)]
pub fn stop(addr: &str) -> Result<(), String> {
    if !is_running(addr) {
        return Ok(());
    }
    // charon under the broker service is stopped by stopping that service, not
    // by killing the process out from under it.
    if vpn_broker::client::available() {
        return Err("charon is managed by the VPN broker service; stop that service to stop it".to_string());
    }
    let inner = "Start-Process -FilePath 'taskkill' -Verb RunAs \
                 -ArgumentList @('/F','/IM','charon-svc.exe')";
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", inner])
        .status()
        .map_err(|e| format!("failed to stop charon-svc: {e}"))?;
    if !status.success() {
        return Err("elevation was declined or failed (UAC)".to_string());
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !is_running(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    Err("charon-svc was still running after the stop request".to_string())
}

// On non-Windows the tunnel backend is the strongSwan container, which is
// managed by the dev scripts, not spawned/elevated by the app.
#[cfg(not(windows))]
pub fn start(_addr: &str) -> Result<(), String> {
    Err("native daemon control is Windows-only; start the backend container instead".to_string())
}

#[cfg(not(windows))]
pub fn stop(_addr: &str) -> Result<(), String> {
    Err("native daemon control is Windows-only".to_string())
}

/// Tiny helper so `is_running` can take a `&str` addr without pulling in a
/// resolver crate; parses `host:port` for the loopback vici endpoint.
trait ToSocketAddr {
    fn to_socket_addr(&self) -> Option<std::net::SocketAddr>;
}
impl ToSocketAddr for str {
    fn to_socket_addr(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok().and_then(|mut it| it.next())
    }
}
