//! Drive an OpenVPN process for one Sophos SSL VPN tunnel.
//!
//! Sophos "SSL VPN" is stock OpenVPN: the portal hands out an `.ovpn` with an
//! embedded per-user client certificate and key, `auth-user-pass` for a second
//! credential round, and the server pushes routes and DNS at connect time. The
//! IPsec datapath (charon/libipsec/Wintun) cannot carry it, so this supervises a
//! real `openvpn` binary instead — the same shape as [`crate::charon`], but one
//! process per tunnel rather than a single long-lived daemon.
//!
//! We talk to it over OpenVPN's management interface (a loopback TCP socket),
//! which is to OpenVPN what vici is to charon: it releases the start-up hold,
//! reports the connection state machine, and carries the disconnect signal. The
//! login itself is supplied through a transient `--auth-user-pass` file rather
//! than over the socket — OpenVPN 2.6's management password query stalls before
//! it dials the gateway, whereas the file path is reliable across versions.
//!
//! SECURITY: the broker runs as LocalSystem, and an `.ovpn` is *code* — OpenVPN
//! directives like `up`, `down`, `plugin` and `tls-verify` name programs it will
//! run. A hostile profile could therefore run anything as SYSTEM. Two defences,
//! both here: [`sanitize`] refuses a config that carries such a directive, and
//! the process is launched with `--script-security 1` (no user scripts) placed
//! *after* `--config` so it overrides anything the file tried to set. The config
//! holds a live private key and the auth file holds the password: both are
//! written to transient files deleted the moment the tunnel stops (and on drop,
//! and swept at broker startup after a crash).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Overall budget for reaching CONNECTED: TLS, `auth-user-pass`, the server's
/// config push and route installation all fit inside this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// How long to wait for openvpn to open its management port after launch.
const MGMT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a graceful SIGTERM is given before the child is killed outright.
const STOP_GRACE: Duration = Duration::from_secs(4);
/// How many of openvpn's own `>LOG:` lines to keep for diagnosing a failure.
const LOG_RING: usize = 40;
/// The wintun adapter openvpn uses. Named distinctly so it never collides with
/// charon's own wintun device ("strongSwan Tunnel"); pre-created via tapctl
/// because openvpn reuses an existing adapter rather than making one.
const ADAPTER_NAME: &str = "OpenVPN Data Channel";

/// A live (or connecting) OpenVPN tunnel. Dropping it tears the tunnel down and
/// deletes the on-disk config, so a lost handle never leaks a running process or
/// the private key.
pub struct Tunnel {
    child: Child,
    /// Write half of the management socket, for sending `signal SIGTERM`.
    mgmt: TcpStream,
    config_path: PathBuf,
    /// The `--auth-user-pass` file (username/password). Deleted with the config.
    auth_path: PathBuf,
    /// The virtual IP the gateway assigned, from the CONNECTED state line.
    pub vpn_ip: Option<String>,
}

impl Tunnel {
    /// Tear the tunnel down: ask openvpn to exit cleanly over the management
    /// socket, wait briefly, then kill and reap if it hasn't gone. The config
    /// file (with its private key) is removed either way.
    pub fn disconnect(mut self) {
        self.shutdown();
    }

    /// Whether the openvpn process is still running (so a status query can drop
    /// a tunnel whose process has died underneath it).
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn shutdown(&mut self) {
        // Best-effort graceful stop: SIGTERM over the management interface lets
        // openvpn pull down its routes and adapter itself.
        let _ = self.mgmt.write_all(b"signal SIGTERM\n");
        let _ = self.mgmt.flush();

        let deadline = Instant::now() + STOP_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        // The config carries a live private key and the auth file the password —
        // don't leave either on disk.
        let _ = std::fs::remove_file(&self.config_path);
        let _ = std::fs::remove_file(&self.auth_path);
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Delete any staged `.ovpn` configs left behind by a previous run. Normal
/// teardown removes a tunnel's config (via [`Tunnel`] drop), but a broker that
/// was killed or crashed mid-tunnel cannot run that cleanup — so its config,
/// which holds a live private key, would linger. The broker calls this at
/// startup, when nothing legitimately holds one, to guarantee it is gone.
pub fn sweep_stale_configs() {
    let Ok(entries) = std::fs::read_dir(work_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_staged = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("sslvpn-") && (n.ends_with(".ovpn") || n.ends_with(".auth")))
            .unwrap_or(false);
        if is_staged {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// A failed SSL VPN connect, split so the GUI can show a short `reason` in the
/// banner and openvpn's full output (`log`) in the log panel, rather than one
/// giant string. `log` is empty when the failure happened before openvpn
/// produced any output. Neither field carries a secret (the credentials go
/// through the auth file, never the log at `--verb 3`).
pub struct ConnectError {
    pub reason: String,
    pub log: String,
}

impl From<String> for ConnectError {
    fn from(reason: String) -> Self {
        ConnectError { reason, log: String::new() }
    }
}

/// Bring up an SSL VPN tunnel from an `.ovpn` config, supplying `username`/
/// `password` for its `auth-user-pass` round via a transient file. Returns once
/// openvpn reports CONNECTED, or a [`ConnectError`] whose `reason` is safe to
/// show and whose `log` holds openvpn's own output for the panel.
pub fn connect(config: &str, username: &str, password: &str) -> Result<Tunnel, ConnectError> {
    sanitize(config)?;

    let exe = openvpn_exe()?;
    ensure_adapter(&exe)?;
    let dir = work_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let port = free_port()?;
    let config_path = dir.join(format!("sslvpn-{}.ovpn", port));
    std::fs::write(&config_path, config)
        .map_err(|e| format!("could not stage the SSL VPN config: {e}"))?;

    // Feed the credentials through an `--auth-user-pass` file rather than over
    // the management interface: OpenVPN 2.6's management password query stalls
    // before it even dials the gateway, whereas the file path is reliable across
    // versions. The file (username on line 1, password on line 2) is as
    // sensitive as the private key already beside it, and shares its lifecycle —
    // deleted on teardown, on drop, and swept at startup.
    let auth_path = dir.join(format!("sslvpn-{}.auth", port));
    std::fs::write(&auth_path, format!("{}\n{}\n", username, password))
        .map_err(|e| format!("could not stage the SSL VPN credentials: {e}"))?;

    // Guard against leaking either secret-bearing file if we bail before building
    // a Tunnel (which would otherwise own the cleanup).
    let guard = FileGuard(vec![config_path.clone(), auth_path.clone()]);

    let log_path = dir.join(format!("openvpn-{}.log", port));
    // One file, two handles (stdout+stderr) — created once so the second doesn't
    // truncate the first out from under it.
    let (stdout, stderr) = match std::fs::File::create(&log_path) {
        Ok(f) => match f.try_clone() {
            Ok(g) => (std::process::Stdio::from(f), std::process::Stdio::from(g)),
            Err(_) => (std::process::Stdio::from(f), std::process::Stdio::null()),
        },
        _ => (std::process::Stdio::null(), std::process::Stdio::null()),
    };

    // `--config` first, then the hardening flags, so they override anything the
    // file set. `--management-hold` starts openvpn paused so we can enable state
    // reporting before it proceeds; `--auth-user-pass <file>` supplies the login.
    let mut cmd = Command::new(&exe);
    cmd.arg("--config")
        .arg(&config_path)
        .args(["--script-security", "1"])
        // Use the wintun adapter we ship (the DLL sits beside openvpn.exe),
        // rather than requiring a TAP driver install. Layer-3, self-contained,
        // same driver charon uses. `--windows-driver` after `--config` overrides
        // anything the profile set.
        .args(["--windows-driver", "wintun"])
        // A distinctly named adapter so openvpn creates its own rather than
        // grabbing charon's wintun device (both use wintun; without this openvpn
        // finds charon's "strongSwan Tunnel" adapter and reports it "in use").
        .arg("--dev-node")
        .arg(ADAPTER_NAME)
        .arg("--auth-user-pass")
        .arg(&auth_path)
        .args(["--management", "127.0.0.1", &port.to_string()])
        .arg("--management-hold")
        .args(["--auth-retry", "none"])
        .args(["--verb", "3"])
        .current_dir(&dir)
        .stdout(stdout)
        .stderr(stderr);
    // Point OpenSSL 3 at the bundled provider modules (the legacy provider ships
    // there) so a gateway still on an older cipher can be negotiated. Harmless
    // when unused. Only the bundled layout has this directory.
    if let Some(exe_dir) = exe.parent() {
        let modules = exe_dir.join("ssl").join("modules");
        if modules.is_dir() {
            cmd.env("OPENSSL_MODULES", &modules);
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to launch openvpn: {e}"))?;

    let stream = match connect_mgmt(port, &mut child) {
        Ok(s) => s,
        Err(e) => {
            stop_child(&mut child, None);
            return Err(ConnectError { reason: e, log: read_log(&log_path) });
        }
    };
    // A cleanup handle to the management socket, so a failed connect can stop
    // openvpn *gracefully* — a hard kill leaves its wintun adapter registered,
    // and the leaked adapters then block the next attempt.
    let cleanup = stream.try_clone().ok();

    match drive(&mut child, stream) {
        Ok((vpn_ip, mgmt)) => {
            guard.disarm();
            Ok(Tunnel { child, mgmt, config_path, auth_path, vpn_ip })
        }
        Err(e) => {
            stop_child(&mut child, cleanup);
            Err(ConnectError { reason: e, log: read_log(&log_path) })
        }
    }
}

/// Stop an openvpn child, gracefully if we still have its management socket
/// (SIGTERM lets it remove its wintun adapter), then kill and reap as a backstop.
fn stop_child(child: &mut Child, mgmt: Option<TcpStream>) {
    if let Some(mut w) = mgmt {
        let _ = w.write_all(b"signal SIGTERM\n");
        let _ = w.flush();
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Enable state reporting, release the hold, and wait for CONNECTED (the login
/// comes from the `--auth-user-pass` file). On success returns the assigned IP
/// and the write half of the management socket (kept for the eventual
/// disconnect).
fn drive(
    child: &mut Child,
    mut stream: TcpStream,
) -> Result<(Option<String>, TcpStream), String> {
    // Single-threaded read+write on the one socket, polling with a short read
    // timeout. A background reader thread with a cloned writer looked equivalent
    // but did not work: openvpn accepted `state on`/`log on` yet never saw the
    // following `hold release` (no SUCCESS, no progress) and stayed paused. Doing
    // it the way the interface expects — one owner, read then write — is
    // reliable, matching a hand-driven session.
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .map_err(|e| format!("management socket error: {e}"))?;

    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut recent: VecDeque<String> = VecDeque::with_capacity(LOG_RING);
    let mut rbuf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    // The setup commands are sent only *after* openvpn's first line: it opens the
    // management port a moment before it is ready to parse commands, and anything
    // sent into that gap (notably "hold release") is silently dropped, leaving it
    // paused. Its banner is the "ready" signal.
    let mut setup_sent = false;

    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "the SSL VPN did not connect within {}s{}",
                CONNECT_TIMEOUT.as_secs(),
                tail(&recent)
            ));
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("openvpn exited ({status}){}", tail(&recent)));
        }

        // Consume every complete line currently buffered.
        while let Some(pos) = rbuf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = rbuf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&raw).trim_end().to_string();
            if line.is_empty() {
                continue;
            }
            // Keep every management line (not just `>LOG:`) so a failed connect
            // shows the real dialogue.
            push_recent(&mut recent, &line);

            // A state notification may arrive raw (`>STATE:…`, from `state on`) or
            // wrapped in a log echo (`>LOG:…,MANAGEMENT: >STATE:…`, from `log on`);
            // match it wherever it appears so detection never hinges on which one
            // openvpn sent.
            if let Some(idx) = line.find(">STATE:") {
                // >STATE:<time>,<state>,<detail>,<local/vpn ip>,<remote ip>,...
                let fields: Vec<&str> = line[idx + ">STATE:".len()..].split(',').collect();
                match fields.get(1).copied().unwrap_or("") {
                    "CONNECTED" => {
                        let vpn_ip = fields
                            .get(3)
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                            .map(str::to_string);
                        return Ok((vpn_ip, stream));
                    }
                    "EXITING" => {
                        let reason = fields.get(2).copied().unwrap_or("");
                        return Err(exit_reason(reason, &recent));
                    }
                    _ => {}
                }
            } else if setup_sent && line.starts_with(">HOLD:") {
                // A reconnect re-entered hold — let it proceed again.
                send(&mut stream, "hold release")?;
            } else if line.strip_prefix(">PASSWORD:").is_some_and(|r| r.contains("Verification Failed"))
            {
                return Err("the gateway rejected the username or password".to_string());
            } else if let Some(rest) = line.strip_prefix(">FATAL:") {
                return Err(format!("openvpn could not start: {}{}", rest.trim(), tail(&recent)));
            }
        }

        // openvpn has spoken and is ready: enable state + real-time log reporting
        // and release the start-up hold, once.
        if !setup_sent && !recent.is_empty() {
            send(&mut stream, "state on")?;
            send(&mut stream, "log on")?;
            send(&mut stream, "hold release")?;
            setup_sent = true;
        }

        // Read more, tolerating the poll timeout.
        match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(format!("openvpn closed its management interface{}", tail(&recent)))
            }
            Ok(n) => rbuf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(format!("management read failed: {e}{}", tail(&recent))),
        }
    }
}

/// Append a management line to the bounded diagnostic ring, trimming the noisy
/// `>LOG:<time>,<flags>,` prefix down to the message.
fn push_recent(recent: &mut VecDeque<String>, line: &str) {
    let shown = match line.strip_prefix(">LOG:") {
        Some(rest) => rest.splitn(3, ',').nth(2).unwrap_or(rest).trim(),
        None => line.trim(),
    };
    if shown.is_empty() {
        return;
    }
    if recent.len() == LOG_RING {
        recent.pop_front();
    }
    recent.push_back(shown.to_string());
}

/// Turn an EXITING detail into an actionable message.
fn exit_reason(reason: &str, recent: &VecDeque<String>) -> String {
    match reason {
        "auth-failure" => "the gateway rejected the username or password".to_string(),
        "" => format!("openvpn exited before connecting{}", tail(recent)),
        other => format!("openvpn exited before connecting ({other}){}", tail(recent)),
    }
}

/// Connect to openvpn's management port, retrying while it comes up. Fails fast
/// if the child dies first.
fn connect_mgmt(port: u16, child: &mut Child) -> Result<TcpStream, String> {
    let deadline = Instant::now() + MGMT_CONNECT_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("openvpn exited before it opened its management interface ({status})"));
        }
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => {
                // A read timeout keeps the reader thread from blocking forever if
                // the socket wedges; lines still arrive well within it.
                let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                return Ok(s);
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("could not reach openvpn's management interface: {e}")),
        }
    }
}

/// Send one management command (newline-terminated).
fn send(w: &mut TcpStream, cmd: &str) -> Result<(), String> {
    w.write_all(cmd.as_bytes())
        .and_then(|_| w.write_all(b"\n"))
        .and_then(|_| w.flush())
        .map_err(|e| format!("management socket write failed: {e}"))
}

/// Directives that make OpenVPN run a program or read a path as the (SYSTEM)
/// user it runs under, or that would hijack the controls we rely on. A config
/// carrying any of these is refused rather than run. Compared case-insensitively
/// against the first token of each directive, with a leading `--` tolerated.
const FORBIDDEN: &[&str] = &[
    // Run an external program at a lifecycle hook.
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "ipchange",
    "tls-verify",
    "auth-user-pass-verify",
    "client-connect",
    "client-disconnect",
    "learn-address",
    "plugin",
    // Loosen script execution or hand secrets to a script.
    "script-security",
    "setenv-safe",
    // Take over the controls this driver owns, or pull in more config from disk.
    "management",
    "management-hold",
    "management-query-passwords",
    "config",
];

/// Refuse an `.ovpn` that could run code as SYSTEM or seize our controls. Lines
/// inside inline `<tag>…</tag>` blocks (the CA/cert/key blobs) are data, not
/// directives, and are skipped.
pub fn sanitize(config: &str) -> Result<(), String> {
    let mut in_block = false;
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if in_block {
            if line.starts_with("</") {
                in_block = false;
            }
            continue;
        }
        if line.starts_with('<') && !line.starts_with("</") {
            in_block = true;
            continue;
        }
        let first = line.split_whitespace().next().unwrap_or("");
        let keyword = first.trim_start_matches("--").to_ascii_lowercase();
        if FORBIDDEN.contains(&keyword.as_str()) {
            return Err(format!(
                "the SSL VPN profile contains a '{keyword}' directive, which is not allowed for \
                 safety and cannot be imported"
            ));
        }
    }
    Ok(())
}

/// Locate the `openvpn` binary. `VPN_OPENVPN_EXE` overrides; otherwise the one
/// bundled next to the broker is used. As a development convenience (before the
/// bundle exists) the OpenVPN that ships with Sophos Connect is accepted as a
/// last resort.
fn openvpn_exe() -> Result<PathBuf, String> {
    const EXE: &str = "openvpn.exe";
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(p) = std::env::var_os("VPN_OPENVPN_EXE") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Bundled beside the broker (production layout).
            candidates.push(dir.join("openvpn").join(EXE));
            candidates.push(dir.join(EXE));
            // Dev: target/debug/vpn-broker.exe -> repo/out/openvpn (mirrors the
            // charon dev fallback), populated by scripts/fetch-openvpn-windows.ps1.
            candidates.push(dir.join("../../out/openvpn").join(EXE));
        }
    }
    // Last-resort dev fallback; a shipped build always bundles its own openvpn.
    candidates.push(PathBuf::from(r"C:\Program Files (x86)\Sophos\Connect\openvpn.exe"));

    candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
        "openvpn.exe not found (bundle it beside the broker or set VPN_OPENVPN_EXE)".to_string()
    })
}

/// Make sure the dedicated wintun adapter openvpn will use exists, creating it
/// with `tapctl` if not. openvpn reuses an existing wintun adapter rather than
/// creating one, and would otherwise grab charon's; a distinctly named,
/// pre-created adapter keeps the two datapaths from colliding. Persistent, so
/// this is a no-op on every connect after the first.
///
/// `tapctl` ships beside openvpn in the bundle. If it is absent (the dev
/// fallback to Sophos Connect's openvpn has none), this is skipped and openvpn
/// falls back to whatever adapter is available.
fn ensure_adapter(openvpn_exe: &Path) -> Result<(), String> {
    let Some(tapctl) = openvpn_exe.parent().map(|d| d.join("tapctl.exe")).filter(|p| p.is_file())
    else {
        return Ok(());
    };

    let listing = Command::new(&tapctl)
        .arg("list")
        .output()
        .map_err(|e| format!("could not run tapctl: {e}"))?;
    // `tapctl list` prints "<guid>\t<name>" per adapter.
    if String::from_utf8_lossy(&listing.stdout)
        .lines()
        .any(|l| l.contains(ADAPTER_NAME))
    {
        return Ok(());
    }

    let created = Command::new(&tapctl)
        .args(["create", "--name", ADAPTER_NAME, "--hwid", "wintun"])
        .output()
        .map_err(|e| format!("could not create the wintun adapter: {e}"))?;
    if !created.status.success() {
        return Err(format!(
            "could not create the '{ADAPTER_NAME}' wintun adapter: {}",
            String::from_utf8_lossy(&created.stderr).trim()
        ));
    }
    Ok(())
}

/// A free loopback TCP port for the management interface. Bind to port 0, read
/// the port the OS chose, and release it for openvpn to take.
fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("could not reserve a management port: {e}"))?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("could not read the reserved port: {e}"))
}

/// Where the transient config and openvpn's log live — beside charon's, under
/// ProgramData, since the service has no console.
fn work_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("ipsec-vpn")
}

/// openvpn's captured output for the log panel — trimmed, and capped to the last
/// lines so a pathological log can't bloat the response. Empty when there is
/// nothing to show (e.g. the failure preceded any output). Splitting by line
/// avoids slicing through a UTF-8 boundary.
fn read_log(log_path: &Path) -> String {
    let Ok(s) = std::fs::read_to_string(log_path) else {
        return String::new();
    };
    let s = s.trim();
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(120);
    lines[start..].join("\n")
}

/// Render the recent-log ring as a trailing " (…)" clause, or nothing.
fn tail(recent: &VecDeque<String>) -> String {
    if recent.is_empty() {
        return String::new();
    }
    let lines: Vec<&str> = recent.iter().rev().take(6).map(String::as_str).rev().collect();
    format!(" ({})", lines.join(" | "))
}

/// Deletes its paths on drop unless disarmed — so an early return can't leave
/// the private-key config or the credentials file on disk, while the success
/// path hands ownership to the [`Tunnel`].
struct FileGuard(Vec<PathBuf>);
impl FileGuard {
    fn disarm(self) {
        std::mem::forget(self);
    }
}
impl Drop for FileGuard {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_accepts_a_normal_sophos_ovpn() {
        let ovpn = "client\ndev tun\nproto tcp\nremote vpn.example.com 8443\n\
                    <ca>\n-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n</ca>\n\
                    auth-user-pass\ncipher AES-128-CBC\nauth SHA256\nverb 3\n";
        assert!(sanitize(ovpn).is_ok());
    }

    #[test]
    fn sanitize_rejects_a_script_hook() {
        assert!(sanitize("client\nup /tmp/evil.sh\n").is_err());
        assert!(sanitize("client\n--down C:/evil.bat\n").is_err());
        assert!(sanitize("client\nplugin /tmp/x.so\n").is_err());
        assert!(sanitize("client\ntls-verify /tmp/v.sh\n").is_err());
    }

    #[test]
    fn sanitize_rejects_control_hijack() {
        assert!(sanitize("client\nmanagement 127.0.0.1 9999\n").is_err());
        assert!(sanitize("client\nscript-security 2\n").is_err());
        assert!(sanitize("client\nconfig other.conf\n").is_err());
    }

    #[test]
    fn sanitize_ignores_directives_inside_inline_blocks() {
        // A cert blob must not be mistaken for directives even if a line looks
        // keyword-ish; and comments are skipped.
        let ovpn = "client\n# up here is only a comment\n<key>\nup\nplugin\n</key>\nremote h 8443\n";
        assert!(sanitize(ovpn).is_ok());
    }

    #[test]
    fn sanitize_case_insensitive() {
        assert!(sanitize("client\nUP /tmp/evil\n").is_err());
    }
}
