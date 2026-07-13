//! Supervise the native strongSwan daemon, `charon-svc.exe`. The broker runs as
//! LocalSystem, so it can spawn charon directly (no UAC) — and charon needs that
//! privilege: it creates a Wintun adapter and installs the virtual IP and routes
//! on it.
//!
//! charon comes up on a vici port dedicated to this app (see [`VICI_ADDR`]) and
//! the GUI drives connect/status/disconnect over it.
//!
//! It deliberately does *not* use `charon-svc`'s built-in default (4502): that
//! default is the same for every strongSwan-based client, so on a machine that
//! also has one installed (Sophos Connect ships one, and runs it permanently)
//! whoever binds first owns the port. We used to treat any listener there as
//! "our backend is up", which meant never starting our own daemon and instead
//! pushing connections — and the PSK — into theirs, then killing it on stop.
//! Hence both halves of the fix: our own port, and [`is_ours`] to prove the
//! daemon behind it is the binary we shipped.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::time::{Duration, Instant};

/// vici socket for *our* charon. Must match `plugins.vici.socket` in the
/// bundled `strongswan.conf`, and `NATIVE_VICI_ADDR` in the desktop app.
pub const VICI_ADDR: &str = "127.0.0.1:45023";

/// Is anything listening on our vici port? Says nothing about *whose* daemon it
/// is — see [`is_ours`].
pub fn is_running() -> bool {
    use std::net::ToSocketAddrs;
    VICI_ADDR
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .and_then(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(400)).ok())
        .is_some()
}

/// Is the daemon on our vici port the `charon-svc.exe` we shipped?
///
/// `Ok(true)`: ours, adopt it. `Ok(false)`: nothing is listening. `Err`: someone
/// else's process holds the port — refuse, rather than drive (or kill) a daemon
/// that isn't ours. The broker runs as LocalSystem, so it can read the image
/// path of even a SYSTEM-owned process; if it somehow can't, we treat that as
/// foreign, because "cannot prove it's ours" is exactly the case this guards.
pub fn is_ours() -> Result<bool, String> {
    let Some(pid) = vpn_broker::listener::owner_pid(VICI_ADDR) else {
        return Ok(false);
    };
    let ours = charon_exe()?;
    match vpn_broker::listener::image_of(pid) {
        Some(img) if vpn_broker::listener::same_file(&img, &ours) => Ok(true),
        Some(img) => Err(format!(
            "vici port {VICI_ADDR} is held by {} (pid {pid}), which is not our charon-svc — \
             refusing to use it",
            img.display()
        )),
        None => Err(format!(
            "vici port {VICI_ADDR} is held by pid {pid}, whose image could not be read — \
             refusing to use a daemon we cannot identify"
        )),
    }
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

/// Start charon as a child if our daemon isn't already listening, and wait for
/// vici. Returns the child handle to keep (so a stop can terminate it), or
/// `None` when our charon was already up (not ours to own).
///
/// Errors when the port is held by a process that isn't our charon: driving a
/// foreign daemon is how the PSK ended up in another vendor's client.
pub fn start() -> Result<Option<Child>, String> {
    if is_ours()? {
        return Ok(None);
    }
    let exe = charon_exe()?;
    let dir = exe.parent().ok_or("charon-svc.exe has no parent directory")?.to_path_buf();

    // charon-svc cannot find strongswan.conf on Windows by itself; STRONGSWAN_CONF
    // is the only way to point it at one. Without it charon uses its built-in
    // defaults — vici on 4502, the shared port we moved off — and would come up
    // somewhere the app never looks.
    let conf = dir.join("etc").join("strongswan.conf");
    if !conf.is_file() {
        return Err(format!(
            "strongswan.conf not found at {} — charon would come up on its default \
             vici port instead of {VICI_ADDR}",
            conf.display()
        ));
    }
    let child = std::process::Command::new(&exe)
        .current_dir(&dir)
        .env("STRONGSWAN_CONF", &conf)
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
/// kept may no longer be the live daemon — find the daemon by our vici port and
/// kill that pid (the broker is SYSTEM, so this needs no elevation), then reap
/// our handle for good measure.
///
/// Killing by image name (`taskkill /IM charon-svc.exe`) would also take down
/// any other vendor's strongSwan running under the same executable name, so we
/// only ever kill the pid we have positively identified as ours.
pub fn stop(child: Option<&mut Child>) {
    if matches!(is_ours(), Ok(true)) {
        if let Some(pid) = vpn_broker::listener::owner_pid(VICI_ADDR) {
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output();
        }
    }
    if let Some(c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }
}
