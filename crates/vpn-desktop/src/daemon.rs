//! Lifecycle control for the native strongSwan daemon — `charon-svc.exe` on
//! Windows, `charon` on macOS. Unlike the Linux dev container, the daemon
//! terminates the tunnel on the host itself: it does ESP in userland over a
//! virtual adapter it creates, and installs the virtual IP and routes on that
//! adapter. All of that needs administrator rights — so the GUI (which runs
//! unprivileged) launches it through the platform's elevation prompt and talks
//! to it over a local vici endpoint afterwards.
//!
//! `charon-svc.exe` and its DLLs (including `wintun.dll`, which carries the
//! signed driver, and `libipsec-0.dll`) are shipped as bundled app resources
//! (see `tauri.conf.json` `bundle.resources`), so the app is self-contained. We
//! elevate `charon-svc.exe` with its own directory as the working directory, so
//! the sibling DLLs resolve.
//!
//! macOS is the same shape with three substitutions: the tunnel rides a utun
//! instead of a Wintun adapter, the privilege prompt is `osascript`'s
//! authorization dialog instead of UAC, and vici is a root-owned Unix socket
//! instead of a loopback TCP port. Its dylibs are relocated to `@rpath` and
//! re-signed at build time (`scripts/build-strongswan-macos.sh`), so the binary
//! finds them beside itself wherever the bundle lands.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// vici socket for *our* charon — a port dedicated to this app, not
/// `charon-svc`'s built-in default (4502). That default is shared by every
/// strongSwan-based client: Sophos Connect ships one and runs it permanently,
/// so on such a machine the app used to find *its* daemon on 4502, conclude the
/// backend was up, and push connections and the PSK into it. Must match
/// `plugins.vici.socket` in the bundled `strongswan.conf` and the broker's
/// `VICI_ADDR`. (The Linux dev container uses 45022.)
#[cfg(not(unix))]
pub const NATIVE_VICI_ADDR: &str = "127.0.0.1:45023";

/// vici socket for *our* charon on macOS — a path dedicated to this app, not
/// strongSwan's built-in default (`/var/run/charon.vici`).
///
/// Same reasoning as `NATIVE_VICI_ADDR` on Windows, and the same failure it
/// prevents:
/// the default path is baked into every strongSwan-based client, so on a
/// machine that has another one installed we would find *its* daemon, conclude
/// the backend was up, and push connections and the PSK into it. Unlike
/// Windows this is a Unix socket rather than a loopback TCP port, so the
/// filesystem is the access control — it is root-owned, and an unprivileged
/// process cannot drive charon through it. Must match `plugins.vici.socket` in
/// `macos/strongswan.conf`.
#[cfg(target_os = "macos")]
pub const NATIVE_VICI_SOCKET: &str = "/var/run/ipsec-vpn/charon.vici";

/// The `strongswan.conf` shipped beside charon. charon-svc cannot locate it on
/// Windows by itself — it is passed via the `STRONGSWAN_CONF` environment
/// variable — and it is what puts vici on [`NATIVE_VICI_ADDR`] instead of the
/// shared default port, so a missing conf is a hard error rather than a daemon
/// that silently comes up somewhere we won't look.
#[cfg(any(windows, target_os = "macos"))]
fn strongswan_conf(dir: &Path) -> Result<PathBuf, String> {
    let conf = dir.join("etc").join("strongswan.conf");
    if conf.is_file() {
        return Ok(conf);
    }
    Err(format!(
        "strongswan.conf not found at {} — charon would come up on its built-in \
         default vici endpoint instead of ours, and the app would never find it",
        conf.display()
    ))
}

/// Is a vici control endpoint live at `addr` — a `host:port` for the TCP
/// transport, or an absolute path for a Unix socket?
///
/// This cannot tell *whose* daemon answers: identifying the process behind the
/// endpoint requires opening it, which an unelevated GUI may not do to a SYSTEM
/// process. The broker (LocalSystem) enforces that check — see
/// `vpn_broker::charon::is_ours` — and the dedicated port/path above is what
/// keeps another vendor's charon from landing here in the first place.
pub fn is_running(addr: &str) -> bool {
    #[cfg(unix)]
    if addr.starts_with('/') {
        return unix_socket_live(Path::new(addr));
    }
    addr.to_socket_addr()
        .and_then(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(400)).ok())
        .is_some()
}

/// Whether a root-owned vici Unix socket has a daemon behind it.
///
/// "Can I connect?" is the wrong question here: the socket is owned by root, so
/// the unprivileged GUI is refused with `EACCES` whether charon is alive or
/// not. That refusal is itself the proof the daemon is there — the kernel only
/// checks permissions on a socket something is listening on.
///
/// `ECONNREFUSED` is the opposite signal: the path exists but nothing is bound
/// to it, which is the signature of a stale socket file left behind by a
/// daemon that crashed rather than shut down. Treating that as "running" would
/// wedge the app into never restarting the backend.
#[cfg(unix)]
fn unix_socket_live(path: &Path) -> bool {
    use std::io::ErrorKind;
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => true,
        Err(e) => e.kind() == ErrorKind::PermissionDenied,
    }
}

/// Locate `charon-svc.exe`. Resolution order:
///   1. `VPN_CHARON_EXE` (explicit full path) / `VPN_CHARON_DIR` (its folder),
///   2. bundled next to the app exe (`<exe_dir>/charon/`, or beside it),
///   3. the dev build tree (`out/strongswan-windows`, relative to cwd or the
///      target/ dir), so `cargo run` and the CLI work without a bundle.
#[cfg(windows)]
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
    let conf = strongswan_conf(dir)?;
    let exe_ps = exe.to_string_lossy().replace('\'', "''");
    let dir_ps = dir.to_string_lossy().replace('\'', "''");
    let conf_ps = conf.to_string_lossy().replace('\'', "''");

    // A non-elevated powershell issues Start-Process -Verb RunAs, which raises
    // the UAC prompt and launches charon-svc.exe elevated. Its working dir is
    // its own folder so the sibling DLLs resolve; it keeps running in the
    // background after this command returns (once the prompt is answered).
    //
    // charon is launched through `cmd /c set … && start` rather than directly,
    // because it must be told where strongswan.conf is: on Windows it cannot
    // derive the path, and STRONGSWAN_CONF is the only way to pass it. Without
    // it charon falls back to its built-in defaults — including vici on 4502,
    // the port we moved off of — and the app would never find it. Setting the
    // variable inside the elevated shell (rather than in our own environment)
    // avoids relying on it surviving the UAC elevation boundary.
    let inner = format!(
        "Start-Process -FilePath 'cmd.exe' -Verb RunAs -ArgumentList '/c',\
         'set \"STRONGSWAN_CONF={conf_ps}\" && start \"charon\" /D \"{dir_ps}\" \"{exe_ps}\"'"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &inner])
        .status()
        .map_err(|e| format!("failed to launch elevated charon-svc: {e}"))?;
    if !status.success() {
        return Err("elevation was declined or failed (UAC)".to_string());
    }

    // Wait for the Wintun adapter to come up + vici to bind (the time spent at
    // the UAC prompt is already elapsed above).
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
    // Kill the pid holding our vici port, never `/IM charon-svc.exe`: that image
    // name is not ours alone (Sophos Connect ships a charon-svc too), and by
    // name we would take down another vendor's live VPN.
    let pid = vpn_broker::listener::owner_pid(addr)
        .ok_or("charon is listening but its process could not be identified")?;
    let inner = format!(
        "Start-Process -FilePath 'taskkill' -Verb RunAs -ArgumentList @('/F','/PID','{pid}')"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &inner])
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


// ---- macOS ----------------------------------------------------------------

/// Locate the macOS `charon` binary. Resolution order mirrors [`charon_exe`]:
///   1. `VPN_CHARON_BIN` (explicit full path) / `VPN_CHARON_DIR` (its folder),
///   2. bundled in the `.app` — note this is `Contents/Resources/`, *not*
///      beside the executable as it is on Windows: Tauri puts `bundle.resources`
///      next to the exe on Windows and under `Resources/` on macOS,
///   3. the dev build tree (`out/strongswan-macos`, relative to cwd or the
///      target/ dir), so `cargo run` and the CLI work without a bundle.
#[cfg(target_os = "macos")]
fn charon_bin() -> Result<PathBuf, String> {
    const BIN: &str = "charon";
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(p) = std::env::var_os("VPN_CHARON_BIN") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(d) = std::env::var_os("VPN_CHARON_DIR") {
        candidates.push(PathBuf::from(d).join(BIN));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // <App>.app/Contents/MacOS/vpn-desktop -> ../Resources/charon/charon
            candidates.push(dir.join("../Resources/charon").join(BIN));
            candidates.push(dir.join("charon").join(BIN));
            // Dev: target/debug/vpn-desktop -> repo/out/strongswan-macos
            candidates.push(dir.join("../../out/strongswan-macos").join(BIN));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("out/strongswan-macos").join(BIN));
    }

    candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
        "charon not found (build it with scripts/build-strongswan-macos.sh, \
         or set VPN_CHARON_DIR)"
            .to_string()
    })
}

/// Wrap `s` as a single-quoted POSIX shell word.
#[cfg(target_os = "macos")]
pub(crate) fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Run `shell_cmd` as root behind macOS' authorization prompt — the analogue of
/// the UAC prompt on Windows.
///
/// `do shell script` takes an AppleScript *string literal*, so the command is
/// escaped twice: once as shell words by [`sh_quote`], then for AppleScript
/// here. Only backslash and double quote need escaping in the literal.
#[cfg(target_os = "macos")]
pub(crate) fn osascript_admin(shell_cmd: &str, what: &str) -> Result<(), String> {
    let literal = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{literal}\" with administrator privileges");
    let out = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("failed to run osascript to {what} charon: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    // -128 is AppleScript's "User canceled": the prompt was dismissed, which is
    // a decision rather than a fault, and reads badly as a raw osascript error.
    if err.contains("-128") {
        return Err("authorization was declined".to_string());
    }
    Err(if err.trim().is_empty() {
        format!("could not {what} charon ({})", out.status)
    } else {
        err.trim().to_string()
    })
}

/// Start the native daemon if it is not already listening at `addr`. On macOS
/// this raises the authorization prompt — charon needs root to open a utun
/// device, install the virtual IP and add routes — and then waits for the vici
/// socket to come up. A no-op if already running.
#[cfg(target_os = "macos")]
pub fn start(addr: &str) -> Result<(), String> {
    if is_running(addr) {
        return Ok(());
    }
    // If the LaunchDaemon helper is installed it owns charon's lifecycle and
    // can start it without any prompt at all. Same precedence as the Windows
    // broker: helper first, elevation only as the fallback.
    if vpn_broker::unix_client::available() {
        let resp = vpn_broker::unix_client::request(&vpn_broker::protocol::Request::CharonStart)
            .map_err(|e| format!("the VPN helper is not reachable: {e}"))?;
        return if resp.ok {
            Ok(())
        } else {
            Err(resp.msg)
        };
    }
    let bin = charon_bin()?;
    let dir: &Path = bin.parent().ok_or("charon has no parent directory")?;
    let conf = strongswan_conf(dir)?;
    let run_dir = Path::new(addr)
        .parent()
        .ok_or("the vici socket path names no directory")?;

    // The run directory holds the vici socket, the resolve plugin's captured
    // DNS and charon's log. It is created here because charon does not create
    // it and would simply fail to bind the socket.
    //
    // Its group lets this app traverse the directory and read the resolve
    // plugin's captured DNS. It does NOT govern access to the vici socket:
    // charon chown()s that to its own configured gid immediately after binding,
    // overriding the group the socket would otherwise inherit from the
    // directory. Who may drive the daemon is set by `charon.group` in the
    // bundled strongswan.conf.
    //
    // charon is backgrounded with all three streams redirected: `do shell
    // script` waits for the command's stdout AND stderr to close, so without
    // this the call would block for as long as the daemon runs. STRONGSWAN_CONF
    // is set in the elevated shell rather than inherited, because charon cannot
    // derive the conf path once the dist tree is relocated out of its build
    // prefix — and without it, it comes up on the built-in default vici socket
    // that every other strongSwan client also uses.
    let script = format!(
        "/bin/mkdir -p {run} && /usr/sbin/chown root:staff {run} \
         && /bin/chmod 750 {run} \
         && /usr/bin/env STRONGSWAN_CONF={conf} {bin} \
         >{run}/charon-stdout.log 2>&1 &",
        run = sh_quote(&run_dir.to_string_lossy()),
        conf = sh_quote(&conf.to_string_lossy()),
        bin = sh_quote(&bin.to_string_lossy()),
    );
    osascript_admin(&script, "start")?;

    // Wait for the utun to come up + vici to bind (the time spent at the
    // authorization prompt is already elapsed above).
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if is_running(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("charon did not start listening within 40s".to_string())
}

/// Stop the native daemon. Raises the authorization prompt: a root process can
/// only be signalled by root.
#[cfg(target_os = "macos")]
pub fn stop(addr: &str) -> Result<(), String> {
    if !is_running(addr) {
        return Ok(());
    }
    if vpn_broker::unix_client::available() {
        let resp = vpn_broker::unix_client::request(&vpn_broker::protocol::Request::CharonStop)
            .map_err(|e| format!("the VPN helper is not reachable: {e}"))?;
        return if resp.ok {
            Ok(())
        } else {
            Err(resp.msg)
        };
    }
    // Identify charon by whoever holds *our* vici socket, never by process
    // name: `charon` is not our image name alone (other strongSwan-based
    // clients ship one too), and by name we would take down another vendor's
    // live VPN. This is the macOS analogue of the broker's `owner_pid`.
    //
    // lsof runs inside the elevated shell because a root-owned socket is not
    // visible to the unprivileged user, and SIGTERM (not SIGKILL) so charon
    // tears its SAs, routes and utun down on the way out.
    let script = format!(
        "pid=$(/usr/sbin/lsof -t {sock} 2>/dev/null | /usr/bin/head -1); \
         if [ -z \"$pid\" ]; then \
           echo 'charon is listening but its process could not be identified' >&2; exit 1; \
         fi; \
         /bin/kill -TERM \"$pid\"",
        sock = sh_quote(addr),
    );
    osascript_admin(&script, "stop")?;

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !is_running(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    Err("charon was still running after the stop request".to_string())
}

// On Linux the tunnel backend is the strongSwan container, which is managed by
// the dev scripts, not spawned/elevated by the app.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn start(_addr: &str) -> Result<(), String> {
    Err("native daemon control is Windows/macOS-only; start the backend container instead"
        .to_string())
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn stop(_addr: &str) -> Result<(), String> {
    Err("native daemon control is Windows/macOS-only".to_string())
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
