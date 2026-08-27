//! The operations the macOS helper performs as root: charon's lifecycle, and
//! DNS for a tunnel.
//!
//! SECURITY. Everything here runs as root on behalf of a request that arrived
//! over a socket, so the rule throughout is that **the request is data, never
//! instruction**:
//!
//!   * charon's path is a compile-time constant under a root-owned directory.
//!     A request cannot name a binary, so it cannot make root run one.
//!   * DNS servers are re-parsed as `Ipv4Addr` here. Whatever the GUI thought
//!     it validated is irrelevant — this side validates again.
//!   * The split-DNS domain is re-checked against [`safe_domain`] before it is
//!     used as a filename, because it ends up as a path under /etc/resolver.
//!   * No shell is involved anywhere. Every external command is executed
//!     directly with an argument vector, so quoting cannot be escaped.
//!
//! The GUI-side equivalents in `vpn-desktop` do their own validation too. That
//! is duplication on purpose: this side is the one that has to be right.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::protocol::{MACOS_CHARON_DIR, Response};

/// The vici socket our charon binds. Must match `NATIVE_VICI_SOCKET` in the
/// desktop app and `plugins.vici.socket` in the installed strongswan.conf.
const VICI_SOCKET: &str = "/var/run/ipsec-vpn/charon.vici";
const RUN_DIR: &str = "/var/run/ipsec-vpn";

fn charon_bin() -> PathBuf {
    Path::new(MACOS_CHARON_DIR).join("charon")
}
fn charon_conf() -> PathBuf {
    Path::new(MACOS_CHARON_DIR).join("etc").join("strongswan.conf")
}

// ---- charon ---------------------------------------------------------------

/// Is charon listening on the vici socket? As root, a plain connect answers
/// this directly — the permission ambiguity the unprivileged GUI has to reason
/// about (EACCES meaning "alive") does not arise here.
pub fn charon_running() -> bool {
    match std::os::unix::net::UnixStream::connect(VICI_SOCKET) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn charon_start() -> Response {
    if charon_running() {
        return Response::ok("charon is already running");
    }
    let bin = charon_bin();
    let conf = charon_conf();
    if !bin.is_file() {
        return Response::err(format!("charon is not installed at {}", bin.display()));
    }
    if !conf.is_file() {
        // Without it charon comes up on strongSwan's built-in default vici
        // socket, which every other strongSwan client also uses, and nothing
        // would find it there.
        return Response::err(format!("strongswan.conf is missing at {}", conf.display()));
    }
    if let Err(e) = std::fs::create_dir_all(RUN_DIR) {
        return Response::err(format!("cannot create {RUN_DIR}: {e}"));
    }
    // A socket left by a daemon that crashed rather than shut down: charon will
    // not bind over it.
    if !charon_running() {
        let _ = std::fs::remove_file(VICI_SOCKET);
    }

    // Spawned directly — no shell, no `osascript`. We are already root.
    let child = Command::new(&bin)
        .env("STRONGSWAN_CONF", &conf)
        .current_dir(MACOS_CHARON_DIR)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if let Err(e) = child {
        return Response::err(format!("cannot start charon: {e}"));
    }

    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        if charon_running() {
            return Response::ok("charon started");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Response::err("charon did not start listening within 40s")
}

pub fn charon_stop() -> Response {
    if !charon_running() {
        return Response::ok("charon is not running");
    }
    // Identify charon by who holds *our* vici socket, never by process name:
    // `charon` is not our image name alone, and by name we would take down
    // another vendor's live VPN.
    let Some(pid) = socket_owner_pid(VICI_SOCKET) else {
        return Response::err("charon is listening but its process could not be identified");
    };
    // SIGTERM so it tears down SAs, routes and the utun on the way out.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Response::err(format!(
            "cannot signal charon: {}",
            std::io::Error::last_os_error()
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !charon_running() {
            return Response::ok("charon stopped");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Response::err("charon was still running after the stop request")
}

/// The pid holding `sock`, via `lsof -t`. The macOS analogue of the Windows
/// broker's `listener::owner_pid`.
fn socket_owner_pid(sock: &str) -> Option<i32> {
    let out = Command::new("/usr/sbin/lsof").args(["-t", sock]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .and_then(|l| l.trim().parse::<i32>().ok())
}

// ---- DNS ------------------------------------------------------------------

/// Is `d` safe to use as a filename under `/etc/resolver`?
///
/// The domain originates in a profile file or in whatever a gateway pushed, and
/// it is about to become a path this process writes to as root. `../../etc/...`
/// must never become a write target, so this allows only what a DNS name can
/// legitimately contain and refuses everything else rather than sanitising it.
pub fn safe_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_matches('.');
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    let ok = d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !d.contains("..");
    ok.then(|| d.to_ascii_lowercase())
}

fn resolver_path(domain: &str) -> PathBuf {
    Path::new("/etc/resolver").join(domain)
}

fn flush_dns() {
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").status();
    let _ = Command::new("/usr/bin/killall").args(["-HUP", "mDNSResponder"]).status();
}

/// Apply split-DNS for `conn`: `/etc/resolver/<domain>` naming `servers`.
///
/// Only the split-DNS case is served here. A catch-all — taking over the
/// primary service's resolvers — is a system-wide change that the GUI decides
/// on and that only a genuine full tunnel warrants; it is not something the
/// helper offers as a verb.
pub fn apply_dns(conn: &str, servers: &[String], domain: Option<&str>) -> Response {
    let Some(domain) = domain.and_then(|d| safe_domain(d)) else {
        return Response::err("no usable DNS domain was supplied");
    };
    // Re-parsed here regardless of what the client believed.
    let mut lines = String::new();
    for s in servers {
        match s.trim().parse::<Ipv4Addr>() {
            Ok(ip) => lines.push_str(&format!("nameserver {ip}\n")),
            Err(_) => return Response::err(format!("{s:?} is not an IPv4 address")),
        }
    }
    if lines.is_empty() {
        return Response::err("no DNS servers were supplied");
    }
    if let Err(e) = std::fs::create_dir_all("/etc/resolver") {
        return Response::err(format!("cannot create /etc/resolver: {e}"));
    }
    let path = resolver_path(&domain);
    if let Err(e) = std::fs::write(&path, lines) {
        return Response::err(format!("cannot write {}: {e}", path.display()));
    }
    // Remember which file belongs to which connection, so a revert removes
    // exactly it — and so a helper restart does not lose track.
    let _ = std::fs::create_dir_all(RUN_DIR);
    let _ = std::fs::write(record_path(conn), &domain);
    flush_dns();
    Response::ok(format!("split-DNS: *.{domain} resolves over the tunnel"))
}

/// Remove whatever [`apply_dns`] installed for `conn`.
pub fn revert_dns(conn: &str) -> Response {
    let record = record_path(conn);
    let Ok(domain) = std::fs::read_to_string(&record) else {
        return Response::ok(""); // nothing was applied
    };
    let Some(domain) = safe_domain(&domain) else {
        return Response::err("the recorded DNS domain is not a valid name");
    };
    let path = resolver_path(&domain);
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Response::err(format!("cannot remove {}: {e}", path.display()));
        }
    }
    let _ = std::fs::remove_file(&record);
    flush_dns();
    Response::ok("")
}

/// Where a connection's applied domain is recorded. The connection name comes
/// from a request, so it is reduced to a safe filename rather than trusted.
fn record_path(conn: &str) -> PathBuf {
    let safe: String = conn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    Path::new(RUN_DIR).join(format!("dns-{safe}.record"))
}

#[cfg(test)]
mod tests {
    use super::{record_path, safe_domain};

    #[test]
    fn refuses_domains_that_could_escape_etc_resolver() {
        for bad in ["../../etc/sudoers", "a/b", "foo bar", "foo;reboot", "", "..", "$(id)"] {
            assert!(safe_domain(bad).is_none(), "should have refused {bad:?}");
        }
        assert_eq!(safe_domain(" .Corp.Example.COM. ").as_deref(), Some("corp.example.com"));
    }

    /// The connection name is attacker-influenced in the same way the domain
    /// is, and it also becomes a filename.
    #[test]
    fn connection_names_cannot_escape_the_run_directory() {
        let p = record_path("../../../etc/crontab");
        assert_eq!(p.parent().unwrap().to_str().unwrap(), "/var/run/ipsec-vpn");
        assert!(!p.to_string_lossy().contains(".."));
    }
}
