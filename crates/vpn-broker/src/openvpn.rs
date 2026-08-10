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
//! which is to OpenVPN what vici is to charon: it delivers the `auth-user-pass`
//! prompt so the password never touches a file or the command line, reports the
//! connection state machine, and carries the disconnect signal.
//!
//! SECURITY: the broker runs as LocalSystem, and an `.ovpn` is *code* — OpenVPN
//! directives like `up`, `down`, `plugin` and `tls-verify` name programs it will
//! run. A hostile profile could therefore run anything as SYSTEM. Two defences,
//! both here: [`sanitize`] refuses a config that carries such a directive, and
//! the process is launched with `--script-security 1` (no user scripts) placed
//! *after* `--config` so it overrides anything the file tried to set. The config
//! also holds a live private key: it is written to a transient file that is
//! deleted the moment the tunnel stops (and again on drop).

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::mpsc;
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

/// A live (or connecting) OpenVPN tunnel. Dropping it tears the tunnel down and
/// deletes the on-disk config, so a lost handle never leaks a running process or
/// the private key.
pub struct Tunnel {
    child: Child,
    /// Write half of the management socket, for sending `signal SIGTERM`.
    mgmt: TcpStream,
    config_path: PathBuf,
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
        // The config carries a live private key — don't leave it on disk.
        let _ = std::fs::remove_file(&self.config_path);
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
            .map(|n| n.starts_with("sslvpn-") && n.ends_with(".ovpn"))
            .unwrap_or(false);
        if is_staged {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Bring up an SSL VPN tunnel from an `.ovpn` config, answering its
/// `auth-user-pass` prompt with `username`/`password`. Returns once openvpn
/// reports CONNECTED, or an error that carries no secret and is safe to show.
pub fn connect(config: &str, username: &str, password: &str) -> Result<Tunnel, String> {
    sanitize(config)?;

    let exe = openvpn_exe()?;
    let dir = work_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let port = free_port()?;
    let config_path = dir.join(format!("sslvpn-{}.ovpn", port));
    std::fs::write(&config_path, config)
        .map_err(|e| format!("could not stage the SSL VPN config: {e}"))?;
    // Guard against leaking the key file if we bail before building a Tunnel
    // (which would otherwise own the cleanup).
    let guard = FileGuard(config_path.clone());

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
    // reporting and be ready for the password prompt before it proceeds;
    // `--management-query-passwords` delivers `auth-user-pass` over the socket
    // instead of prompting on a console the service does not have.
    let mut child = Command::new(&exe)
        .arg("--config")
        .arg(&config_path)
        .args(["--script-security", "1"])
        .args(["--management", "127.0.0.1", &port.to_string()])
        .arg("--management-hold")
        .arg("--management-query-passwords")
        .arg("--auth-nocache")
        .args(["--auth-retry", "none"])
        .args(["--verb", "3"])
        .current_dir(&dir)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("failed to launch openvpn: {e}"))?;

    let stream = match connect_mgmt(port, &mut child) {
        Ok(s) => s,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(with_log(e, &log_path));
        }
    };

    match drive(&mut child, stream, username, password) {
        Ok((vpn_ip, mgmt)) => {
            guard.disarm();
            Ok(Tunnel { child, mgmt, config_path, vpn_ip })
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(with_log(e, &log_path))
        }
    }
}

/// Enable state reporting, release the hold, answer the credential prompt, and
/// wait for CONNECTED. On success returns the assigned IP and the write half of
/// the management socket (kept for the eventual disconnect).
fn drive(
    child: &mut Child,
    stream: TcpStream,
    username: &str,
    password: &str,
) -> Result<(Option<String>, TcpStream), String> {
    let mut writer = stream.try_clone().map_err(|e| format!("management socket error: {e}"))?;

    // A reader thread turns the socket into a line stream we can select on with a
    // timeout, so the main loop can also watch the deadline and the child.
    let (tx, rx) = mpsc::channel::<String>();
    let reader = stream;
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Turn on state reporting. The hold is *not* released here: sending "hold
    // release" before openvpn has registered the hold is a no-op and the tunnel
    // then sits paused forever. Instead we release in response to openvpn's own
    // ">HOLD:" notification below, which it (re)emits whenever it is waiting.
    send(&mut writer, "state on")?;

    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut recent: VecDeque<String> = VecDeque::with_capacity(LOG_RING);

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

        let line = match rx.recv_timeout(Duration::from_millis(400)) {
            Ok(l) => l,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(format!("openvpn closed its management interface{}", tail(&recent)))
            }
        };

        if line.starts_with(">HOLD:") {
            // openvpn is paused waiting for us — let it proceed. Re-emitted on
            // every hold, so this also covers a reconnect that re-enters hold.
            send(&mut writer, "hold release")?;
        } else if let Some(rest) = line.strip_prefix(">PASSWORD:") {
            if rest.starts_with("Need 'Auth'") {
                // Answer the username/password round. Values are quoted and
                // backslash-escaped as the management parser expects.
                send(&mut writer, &format!("username \"Auth\" {}", escape(username)))?;
                send(&mut writer, &format!("password \"Auth\" {}", escape(password)))?;
            } else if rest.starts_with("Verification Failed: 'Auth'") {
                return Err("the gateway rejected the username or password".to_string());
            } else if rest.starts_with("Need ") {
                // Some other secret we cannot supply — most likely the private
                // key is passphrase-protected, which the portal profile is not
                // expected to be.
                let what = rest.split('\'').nth(1).unwrap_or("a credential");
                return Err(format!(
                    "the SSL VPN profile needs {what}, which this client cannot supply"
                ));
            }
        } else if let Some(rest) = line.strip_prefix(">STATE:") {
            // >STATE:<time>,<state>,<detail>,<local/vpn ip>,<remote ip>,...
            let fields: Vec<&str> = rest.split(',').collect();
            match fields.get(1).copied().unwrap_or("") {
                "CONNECTED" => {
                    let vpn_ip = fields
                        .get(3)
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    return Ok((vpn_ip, writer));
                }
                "EXITING" => {
                    let reason = fields.get(2).copied().unwrap_or("");
                    return Err(exit_reason(reason, &recent));
                }
                _ => {}
            }
        } else if let Some(rest) = line.strip_prefix(">FATAL:") {
            return Err(format!("openvpn could not start: {}{}", rest.trim(), tail(&recent)));
        } else if let Some(rest) = line.strip_prefix(">LOG:") {
            if recent.len() == LOG_RING {
                recent.pop_front();
            }
            // >LOG:<time>,<flags>,<message> — keep just the message.
            let msg = rest.splitn(3, ',').nth(2).unwrap_or(rest);
            recent.push_back(msg.trim().to_string());
        }
    }
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

/// Escape a value for a quoted management-interface argument: the parser honours
/// backslash escapes for `\` and `"` inside the quotes.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
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
            candidates.push(dir.join("openvpn").join(EXE));
            candidates.push(dir.join(EXE));
        }
    }
    // Dev fallback only; a shipped build bundles its own openvpn.
    candidates.push(PathBuf::from(r"C:\Program Files (x86)\Sophos\Connect\openvpn.exe"));

    candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
        "openvpn.exe not found (bundle it beside the broker or set VPN_OPENVPN_EXE)".to_string()
    })
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

/// Append openvpn's captured output to an error, when we have a log to add.
fn with_log(err: String, log_path: &Path) -> String {
    match std::fs::read_to_string(log_path) {
        Ok(s) if !s.trim().is_empty() => {
            let s = s.trim();
            let tail = &s[s.len().saturating_sub(1500)..];
            format!("{err}; openvpn said: {tail}")
        }
        _ => err,
    }
}

/// Render the recent-log ring as a trailing " (…)" clause, or nothing.
fn tail(recent: &VecDeque<String>) -> String {
    if recent.is_empty() {
        return String::new();
    }
    let lines: Vec<&str> = recent.iter().rev().take(6).map(String::as_str).rev().collect();
    format!(" ({})", lines.join(" | "))
}

/// Deletes a path on drop unless disarmed — so an early return can't leave the
/// private-key config on disk, while the success path hands ownership to the
/// [`Tunnel`].
struct FileGuard(PathBuf);
impl FileGuard {
    fn disarm(self) {
        std::mem::forget(self);
    }
}
impl Drop for FileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(escape("simple"), "\"simple\"");
        assert_eq!(escape(r#"a"b"#), r#""a\"b""#);
        assert_eq!(escape(r"a\b"), r#""a\\b""#);
    }

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
