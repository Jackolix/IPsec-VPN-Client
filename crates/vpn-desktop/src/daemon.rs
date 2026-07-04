//! Lifecycle control for the native Windows strongSwan daemon
//! (`charon-svc.exe`). Unlike the Linux dev container, the daemon terminates
//! the tunnel on the Windows host via the Windows Filtering Platform, which
//! needs Administrator rights — so the GUI (which runs unelevated) launches it
//! through a UAC prompt and talks to it over loopback vici afterwards.
//!
//! The heavy lifting (materializing an effective `strongswan.conf`, setting
//! `STRONGSWAN_CONF`, launching `charon-svc.exe`) lives in the tested
//! `scripts/run-charon-windows.ps1`; here we just elevate it. Elevation resets
//! the environment, so we must elevate the *script* (which re-establishes the
//! config in the elevated context), not `charon-svc.exe` directly.

use std::net::TcpStream;
use std::path::PathBuf;
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

/// Locate `scripts/run-charon-windows.ps1`. `VPN_CHARON_SCRIPT` overrides;
/// otherwise look next to the current working directory (the repo root when
/// launched via cargo / the run scripts).
fn run_script() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("VPN_CHARON_SCRIPT") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("VPN_CHARON_SCRIPT does not point at a file: {}", p.display()));
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let p = cwd.join("scripts").join("run-charon-windows.ps1");
    if p.is_file() {
        return Ok(p);
    }
    Err(format!(
        "run-charon-windows.ps1 not found at {} (set VPN_CHARON_SCRIPT to its path)",
        p.display()
    ))
}

/// Start the native daemon if it is not already listening at `addr`. On
/// Windows this raises a UAC prompt (elevating the launch script) and then
/// waits for vici to come up. A no-op if already running.
#[cfg(windows)]
pub fn start(addr: &str) -> Result<(), String> {
    if is_running(addr) {
        return Ok(());
    }
    let script = run_script()?;
    let script = script.to_string_lossy().replace('\'', "''");

    // A non-elevated powershell issues Start-Process -Verb RunAs, which raises
    // the UAC prompt and launches an elevated powershell running the script.
    // The elevated process keeps charon-svc alive in the foreground; this outer
    // command returns as soon as the prompt is answered.
    let inner = format!(
        "Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList \
         @('-NoProfile','-ExecutionPolicy','Bypass','-File','{script}')"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &inner])
        .status()
        .map_err(|e| format!("failed to launch elevated charon-svc: {e}"))?;
    if !status.success() {
        return Err("elevation was declined or failed (UAC)".to_string());
    }

    // Wait for WFP init + vici bind (and however long the user took at the UAC
    // prompt is already spent above).
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if is_running(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("charon-svc did not start listening within 40s (check the elevated console/charon.log)".to_string())
}

/// Stop the native daemon. On Windows this raises a UAC prompt (an elevated
/// process can only be killed by an elevated one) and waits for it to exit.
#[cfg(windows)]
pub fn stop(addr: &str) -> Result<(), String> {
    if !is_running(addr) {
        return Ok(());
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
