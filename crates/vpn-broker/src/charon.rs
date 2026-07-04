//! Supervise the native strongSwan daemon, `charon-svc.exe`. The broker runs
//! as LocalSystem, so it can spawn charon directly (no UAC) and charon installs
//! its SAs through the Windows Filtering Platform, which needs that privilege.
//!
//! charon comes up on its built-in Windows vici default (`127.0.0.1:4502`); the
//! GUI drives connect/status/disconnect over that socket exactly as before.
//! We run it on defaults (no config file needed), matching the app's proven
//! elevate-and-spawn path — the only change is *who* spawns it.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::time::{Duration, Instant};

/// charon-svc's Windows vici default.
pub const VICI_ADDR: &str = "127.0.0.1:4502";

/// Is charon's vici socket accepting connections? A successful TCP connect
/// means it's up (vici is charon's only TCP listener).
pub fn is_running() -> bool {
    use std::net::ToSocketAddrs;
    VICI_ADDR
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .and_then(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(400)).ok())
        .is_some()
}

/// Locate `charon-svc.exe`. The broker exe is installed next to the bundled
/// `charon\` folder; in dev it resolves from the build tree. `VPN_CHARON_DIR`
/// / `VPN_CHARON_EXE` override for unusual layouts.
fn charon_exe() -> Result<PathBuf, String> {
    const EXE: &str = "charon-svc.exe";
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(p) = std::env::var_os("VPN_CHARON_EXE") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(d) = std::env::var_os("VPN_CHARON_DIR") {
        candidates.push(PathBuf::from(d).join(EXE));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("charon").join(EXE));
            candidates.push(dir.join(EXE));
            // Dev: target/debug/vpn-broker.exe -> repo/out/strongswan-windows
            candidates.push(dir.join("../../out/strongswan-windows").join(EXE));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("out/strongswan-windows").join(EXE));
    }

    candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
        "charon-svc.exe not found (build it with scripts/build-strongswan-windows.ps1, \
         or set VPN_CHARON_DIR)"
            .to_string()
    })
}

/// Start charon as a child if it isn't already listening, and wait for vici.
/// Returns the child handle to keep (so a stop can terminate it), or `None`
/// when charon was already up (not ours to own).
pub fn start() -> Result<Option<Child>, String> {
    if is_running() {
        return Ok(None);
    }
    let exe = charon_exe()?;
    let dir = exe.parent().ok_or("charon-svc.exe has no parent directory")?.to_path_buf();
    let child = std::process::Command::new(&exe)
        .current_dir(&dir)
        .spawn()
        .map_err(|e| format!("failed to launch charon-svc: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if is_running() {
            return Ok(Some(child));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("charon-svc did not start listening within 40s".to_string())
}

/// Stop charon. `charon-svc` detaches after launch, so the `Child` handle we
/// kept may no longer be the live daemon — kill by image name (the broker is
/// SYSTEM, so this needs no elevation), then reap our handle for good measure.
/// This mirrors what the GUI's own `daemon.rs` does with an elevated taskkill.
pub fn stop(child: Option<&mut Child>) {
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/IM", "charon-svc.exe"])
        .output();
    if let Some(c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }
}
