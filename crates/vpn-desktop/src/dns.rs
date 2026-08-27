//! Apply a profile's DNS over the tunnel on Windows.
//!
//! IPsec/WFP installs no adapter and charon-svc doesn't touch Windows DNS, so
//! the app configures resolution itself. We use the Name Resolution Policy
//! Table (NRPT) rather than per-adapter DNS: an NRPT rule is system-wide policy
//! keyed by namespace, so it never clobbers an adapter's existing resolvers and
//! reverts cleanly by just removing the rule. With a `domain` it's split-DNS
//! (only that suffix resolves via the VPN servers); without one it's a catch-all
//! (`.`) so every query goes to the VPN servers while connected.
//!
//! NRPT changes need Administrator. When the privileged broker service is
//! installed it does this for us over its named pipe — no UAC prompt. Only when
//! the broker isn't present (a dev build, or before the service is installed) do
//! we fall back to an elevated PowerShell (a UAC prompt); the namespace we
//! created is then recorded to a temp file so disconnect can remove exactly that
//! rule.

use std::net::Ipv4Addr;
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use std::path::PathBuf;

/// DNS servers the gateway pushed over IKE mode config, if our daemon captured
/// any. charon's `resolve` plugin writes them to a resolv.conf-style file (see
/// the Windows `strongswan.conf`); this reads that file back so the app can
/// apply them via NRPT. Empty when the file is absent — which is exactly the
/// case on a daemon built without the plugin, so callers get today's behaviour
/// (profile DNS only) until the daemon is rebuilt with `--enable-resolve`.
#[cfg(any(windows, target_os = "macos"))]
pub fn pushed_servers() -> Vec<Ipv4Addr> {
    std::fs::read_to_string(pushed_dns_path())
        .map(|text| parse_resolv_conf(&text))
        .unwrap_or_default()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn pushed_servers() -> Vec<Ipv4Addr> {
    // On Linux the resolve plugin applies pushed DNS itself (resolvconf /
    // systemd-resolved), so there is nothing for the app to re-apply.
    Vec::new()
}

/// Where the `resolve` plugin writes the captured servers. Must match
/// `charon.plugins.resolve.file` in the bundled `strongswan.conf`, keyed off
/// `%ProgramData%` so the two agree regardless of the drive layout.
#[cfg(windows)]
fn pushed_dns_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("ipsec-vpn").join("resolv.conf")
}

/// The macOS equivalent, matching `charon.plugins.resolve.file` in
/// `macos/strongswan.conf`. It is deliberately *not* `/etc/resolv.conf`: macOS
/// resolves through mDNSResponder, which reads the SystemConfiguration dynamic
/// store and `/etc/resolver/*` and ignores that file — so this is purely our
/// capture channel, and charon never touches a system file it could not revert.
#[cfg(target_os = "macos")]
fn pushed_dns_path() -> PathBuf {
    PathBuf::from("/var/run/ipsec-vpn/resolv.conf")
}

/// The DNS search domain the gateway pushed over IKE mode config, if our daemon
/// captured one. Same file as [`pushed_servers`], read from its `search`/
/// `domain` line.
///
/// This matters beyond convenience: a profile that names no domain of its own
/// otherwise falls back to the catch-all NRPT namespace, which only one
/// connection on the machine can hold. Taking the domain the gateway already
/// told us gives each tunnel its own namespace instead, so two of them can
/// resolve names side by side.
#[cfg(any(windows, target_os = "macos"))]
pub fn pushed_domain() -> Option<String> {
    std::fs::read_to_string(pushed_dns_path())
        .ok()
        .and_then(|text| parse_resolv_domain(&text))
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn pushed_domain() -> Option<String> {
    None
}

/// First `search` or `domain` entry in resolv.conf text. `search` may list
/// several; the first is the primary one, and the only one a single NRPT
/// namespace can express.
#[cfg(any(windows, target_os = "macos"))]
fn parse_resolv_domain(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some(rest) = line.strip_prefix("search").or_else(|| line.strip_prefix("domain")) else {
            continue;
        };
        // Require whitespace after the keyword, so `searchX` does not match.
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(tok) = rest.split_whitespace().next() {
            let d = tok.trim_matches('.');
            if !d.is_empty() {
                return Some(d.to_string());
            }
        }
    }
    None
}

/// Pull the IPv4 `nameserver` entries out of resolv.conf text. Anything else
/// (comments, IPv6 servers we cannot yet apply) is ignored, so a malformed or
/// partially written file yields whatever valid servers it does contain rather
/// than an error. The `search`/`domain` line is read separately by
/// [`pushed_domain`].
fn parse_resolv_conf(text: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        // Require whitespace after the keyword so `nameserverX` does not match.
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(tok) = rest.split_whitespace().next() {
            if let Ok(addr) = tok.parse::<Ipv4Addr>() {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    out
}

#[cfg(windows)]
fn record_path(conn: &str) -> PathBuf {
    let safe: String = conn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    std::env::temp_dir().join(format!("vpn-dns-{safe}.namespace"))
}

/// The NRPT namespace for a profile: the domain suffix (`.corp.example`) for
/// split-DNS, or `.` (all names) when the profile names no domain.
#[cfg(windows)]
fn namespace(domain: Option<&str>) -> String {
    match domain {
        Some(d) if !d.trim().is_empty() => format!(".{}", d.trim().trim_start_matches('.')),
        _ => ".".to_string(),
    }
}

/// Run a block of PowerShell elevated (one UAC prompt) and wait for it. The
/// block writes `OK` or `ERR: ...` to a result file we read back, so a failure
/// in the elevated context is surfaced instead of silently swallowed.
#[cfg(windows)]
fn run_elevated(body: &str) -> Result<(), String> {
    let dir = std::env::temp_dir();
    let script = dir.join(format!("vpn-dns-{}.ps1", std::process::id()));
    let result = dir.join(format!("vpn-dns-{}.result", std::process::id()));
    let _ = std::fs::remove_file(&result);
    let wrapped = format!(
        "$ErrorActionPreference='Stop'; try {{ {body}\n 'OK' | Out-File -Encoding ascii -LiteralPath '{res}' }} \
         catch {{ \"ERR: $_\" | Out-File -Encoding ascii -LiteralPath '{res}' }}",
        res = result.display()
    );
    std::fs::write(&script, wrapped).map_err(|e| format!("write dns script: {e}"))?;

    let inner = format!(
        "Start-Process -FilePath 'powershell' -Verb RunAs -Wait -WindowStyle Hidden \
         -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','{}')",
        script.display()
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &inner])
        .status()
        .map_err(|e| format!("failed to elevate for DNS: {e}"))?;
    let _ = std::fs::remove_file(&script);
    if !status.success() {
        return Err("DNS elevation was declined or failed (UAC)".to_string());
    }
    match std::fs::read_to_string(&result) {
        Ok(s) if s.trim() == "OK" => {
            let _ = std::fs::remove_file(&result);
            Ok(())
        }
        Ok(s) => {
            let _ = std::fs::remove_file(&result);
            Err(s.trim().to_string())
        }
        Err(_) => Err("DNS change produced no result (UAC declined?)".to_string()),
    }
}

/// Route DNS for this connection over the tunnel via an NRPT rule. Returns a
/// short human summary for the connect log. No-op with no servers.
#[cfg(windows)]
pub fn apply(
    conn: &str,
    servers: &[Ipv4Addr],
    domain: Option<&str>,
    subnets: &[String],
) -> Result<String, String> {
    if servers.is_empty() {
        return Ok(String::new());
    }
    // Preferred path: hand it to the broker service (runs as SYSTEM, no UAC).
    // A reachable broker is authoritative — surface its result either way. Only
    // fall back to the elevated PowerShell path when the broker isn't installed.
    // The broker is also where the namespace policy lives: it holds the durable
    // record of which connection owns which namespace, so it decides whether
    // this one may have the catch-all (hence `subnets`, its fallback).
    let req = vpn_broker::protocol::Request::ApplyDns {
        conn: conn.to_string(),
        servers: servers.iter().map(|s| s.to_string()).collect(),
        domain: domain.map(str::to_string),
        subnets: subnets.to_vec(),
    };
    match vpn_broker::client::request(&req) {
        Ok(r) if r.ok => return Ok(r.msg),
        Ok(r) => return Err(r.msg),
        Err(_) => {} // broker not installed — fall back to UAC below
    }

    let ns = namespace(domain);
    let list = servers.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",");
    // Replace any stale rule for this namespace, then add ours.
    let body = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '{ns}' }} | \
         Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;\
         Add-DnsClientNrptRule -Namespace '{ns}' -NameServers @({list});\
         Clear-DnsClientCache -ErrorAction SilentlyContinue"
    );
    run_elevated(&body)?;
    let _ = std::fs::write(record_path(conn), &ns);

    let servers_txt = servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
    Ok(if ns == "." {
        format!("DNS routed over the tunnel via {servers_txt} (all names)")
    } else {
        format!("split-DNS: *{ns} resolves via {servers_txt}")
    })
}

/// Remove the NRPT rule [`apply`] created for `conn`. No-op when nothing was
/// recorded (a profile with no DNS, or already reverted).
#[cfg(windows)]
pub fn revert(conn: &str) -> Result<(), String> {
    // Preferred path: the broker (which owns its own record of what it applied).
    let req = vpn_broker::protocol::Request::RevertDns { conn: conn.to_string() };
    match vpn_broker::client::request(&req) {
        Ok(r) if r.ok => return Ok(()),
        Ok(r) => return Err(r.msg),
        Err(_) => {} // broker not installed — fall back to the temp-file record
    }

    let path = record_path(conn);
    let Ok(ns) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let ns = ns.trim();
    let body = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '{ns}' }} | \
         Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;\
         Clear-DnsClientCache -ErrorAction SilentlyContinue"
    );
    let r = run_elevated(&body);
    let _ = std::fs::remove_file(&path);
    r
}

// ---- Linux (systemd-resolved) ---------------------------------------------
// On Linux we route DNS through systemd-resolved with `resolvectl`, which is
// clean and fully revertible (`resolvectl revert <link>`). DNS servers are set
// on a link (the default-route interface unless `VPN_DNS_LINK` overrides) with
// a *routing domain*: `~<domain>` sends only that suffix to the VPN resolvers
// (split-DNS), `~.` sends everything. We remember the link per connection so a
// disconnect reverts exactly it.
//
// Note: setting link DNS needs privilege; in a desktop session systemd-resolved
// authorises it via polkit (which may prompt). A future Linux privileged helper
// (the analogue of the Windows broker) would remove that prompt. If the gateway
// pushes DNS (our IKE_AUTH requests CP DNS) and charon's `resolve` plugin is
// loaded, that path also works without this — this covers the profile's own
// DNS.
#[cfg(target_os = "linux")]
fn link_record_path(conn: &str) -> PathBuf {
    let safe: String = conn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    std::env::temp_dir().join(format!("vpn-dns-{safe}.link"))
}

/// The link to set VPN DNS on: `VPN_DNS_LINK` if set, else the interface of the
/// current default route.
#[cfg(target_os = "linux")]
fn dns_link() -> Result<String, String> {
    if let Ok(l) = std::env::var("VPN_DNS_LINK") {
        if !l.trim().is_empty() {
            return Ok(l.trim().to_string());
        }
    }
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| format!("cannot run ip route: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    // "default via X dev eth0 proto ... " -> take the token after "dev".
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            if let Some(dev) = it.next() {
                return Ok(dev.to_string());
            }
        }
    }
    Err("no default-route interface found (set VPN_DNS_LINK)".to_string())
}

#[cfg(target_os = "linux")]
fn resolvectl(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new("resolvectl")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run resolvectl: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(if err.trim().is_empty() {
        format!("resolvectl {args:?} failed ({})", out.status)
    } else {
        err.trim().to_string()
    })
}

#[cfg(target_os = "linux")]
pub fn apply(
    conn: &str,
    servers: &[Ipv4Addr],
    domain: Option<&str>,
    _subnets: &[String],
) -> Result<String, String> {
    if servers.is_empty() {
        return Ok(String::new());
    }
    let link = dns_link()?;
    let mut dns_args = vec!["dns", &link];
    let server_strs: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    dns_args.extend(server_strs.iter().map(String::as_str));
    resolvectl(&dns_args)?;

    let routing_domain = match domain {
        Some(d) if !d.trim().is_empty() => format!("~{}", d.trim().trim_start_matches('.')),
        _ => "~.".to_string(),
    };
    resolvectl(&["domain", &link, &routing_domain])?;

    let _ = std::fs::write(link_record_path(conn), &link);
    let servers_txt = server_strs.join(", ");
    Ok(if routing_domain == "~." {
        format!("DNS routed over the tunnel via {servers_txt} on {link} (all names)")
    } else {
        format!("split-DNS: *.{} resolves via {servers_txt} on {link}", routing_domain.trim_start_matches("~"))
    })
}

#[cfg(target_os = "linux")]
pub fn revert(conn: &str) -> Result<(), String> {
    let path = link_record_path(conn);
    let Ok(link) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let r = resolvectl(&["revert", link.trim()]);
    let _ = std::fs::remove_file(&path);
    r
}


// ---- macOS ----------------------------------------------------------------
//
// macOS has no single equivalent of Windows' NRPT, so this uses the two
// mechanisms that between them cover the same ground:
//
//   split-DNS   `/etc/resolver/<domain>` — a file naming the resolvers for one
//               suffix. This is the closest thing to an NRPT rule the system
//               has: it is system-wide policy keyed by namespace, it never
//               touches any interface's own DNS settings, and it reverts by
//               deleting the file. Preferred whenever the profile or the
//               gateway names a domain.
//
//   catch-all   there is no `/etc/resolver/.`, so a tunnel that scopes to no
//               domain instead sets the VPN's resolvers on the primary network
//               service with `networksetup`. That *does* overwrite existing
//               settings, so the previous list is recorded first and restored
//               verbatim on disconnect.
//
// Both need root and the GUI is unprivileged, so each runs behind the same
// authorization prompt `daemon::start` uses. `subnets` is unused: unlike NRPT,
// neither mechanism scopes by address range.
//
// charon's `resolve` plugin is NOT allowed to do any of this itself (see
// `pushed_dns_path`) — it writes to a capture file and the app applies it, so
// that what gets reverted is exactly what got applied.

/// Where a connection's DNS changes are recorded so [`revert`] can undo exactly
/// them. Same approach as the Linux link record.
#[cfg(target_os = "macos")]
fn dns_record_path(conn: &str) -> PathBuf {
    let safe: String = conn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    std::env::temp_dir().join(format!("vpn-dns-{safe}.macos"))
}

/// Is `d` safe to use as a filename under `/etc/resolver`?
///
/// This matters: the domain arrives from a profile file or from whatever the
/// gateway pushed, and it is about to be interpolated into a path in a command
/// run as root. A value like `../../etc/sudoers` must never become a write
/// target, so this allows only what a DNS name can legitimately contain and
/// rejects everything else rather than trying to sanitise it.
#[cfg(target_os = "macos")]
fn safe_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_matches('.');
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    let ok = d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !d.contains("..");
    ok.then(|| d.to_ascii_lowercase())
}

/// The network service (`Wi-Fi`, `Ethernet`, …) carrying the default route.
/// `networksetup` addresses services by that display name, while the routing
/// table only knows the BSD device, so the two have to be joined through
/// `-listnetworkserviceorder`.
#[cfg(target_os = "macos")]
fn primary_service() -> Result<String, String> {
    let out = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("cannot run route: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let device = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(str::trim)
        .ok_or("no default route, so there is no service to set DNS on")?
        .to_string();

    let out = std::process::Command::new("/usr/sbin/networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .map_err(|e| format!("cannot run networksetup: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    service_for_device(&text, &device)
        .ok_or_else(|| format!("no network service found for interface {device}"))
}

/// Pull the service name for `device` out of `networksetup -listnetworkserviceorder`.
///
/// The listing comes in pairs, the name first and the device on the next line:
///
/// ```text
/// (3) Wi-Fi
/// (Hardware Port: Wi-Fi, Device: en0)
/// ```
///
/// The name is taken from the numbered line rather than from `Hardware Port`,
/// because those two differ as soon as anyone renames a service — and
/// `networksetup -setdnsservers` only accepts the service name.
#[cfg(target_os = "macos")]
fn service_for_device(listing: &str, device: &str) -> Option<String> {
    let mut name: Option<&str> = None;
    for line in listing.lines() {
        let line = line.trim();
        if let Some((num, label)) = line.strip_prefix('(').and_then(|r| r.split_once(')')) {
            // A disabled service is marked "(*) Name"; it still resolves to a
            // device, but setting DNS on it would have no effect.
            if num.chars().all(|c| c.is_ascii_digit()) && !num.is_empty() {
                name = Some(label.trim());
                continue;
            }
        }
        if let Some(rest) = line.split_once("Device: ").map(|(_, r)| r) {
            if rest.trim_end_matches(')').trim() == device {
                return name.map(str::to_string);
            }
        }
    }
    None
}

/// The resolvers currently set on `service`, or an empty vec if none are.
#[cfg(target_os = "macos")]
fn current_servers(service: &str) -> Vec<String> {
    let Ok(out) = std::process::Command::new("/usr/sbin/networksetup")
        .args(["-getdnsservers", service])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // "There aren't any DNS Servers set on Wi-Fi." when the list is empty.
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
}

/// mDNSResponder caches aggressively, so a change that is not flushed can take
/// a noticeable while to take effect.
#[cfg(target_os = "macos")]
const FLUSH: &str = "/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder";

/// What DNS treatment a tunnel should get.
#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq)]
enum Scope {
    /// Only `<domain>` resolves over the tunnel, via `/etc/resolver/<domain>`.
    Split(String),
    /// Every query goes to the VPN resolvers, via `networksetup`.
    Everything,
    /// System DNS is left untouched.
    LeaveAlone,
}

/// Decide how far a tunnel's DNS should reach.
///
/// The middle case is the one that matters. A split tunnel that names no DNS
/// domain used to fall through to the catch-all, which pointed *every* query on
/// the machine at the VPN resolver — so a tunnel carrying one /24 silently took
/// over all name resolution, and looked for all the world like a full tunnel
/// even though the routing table was correctly split.
///
/// Windows does take the catch-all here, because an NRPT rule for `.` is its
/// only way to express "no namespace". macOS is not stuck with that: leaving
/// resolution alone is a real option, and it is the honest one — a tunnel that
/// cannot say which names it serves should not claim all of them. Naming a DNS
/// domain on the profile turns internal resolution back on, scoped properly.
///
/// A genuine full tunnel (`0.0.0.0/0` among the remote subnets) still gets the
/// catch-all: it really does carry everything, so its resolvers should too.
#[cfg(target_os = "macos")]
fn dns_scope(domain: Option<&str>, subnets: &[String]) -> Scope {
    if let Some(d) = domain.and_then(safe_domain) {
        return Scope::Split(d);
    }
    let full_tunnel = subnets
        .iter()
        .any(|s| s.rsplit('/').next() == Some("0"));
    if full_tunnel {
        Scope::Everything
    } else {
        Scope::LeaveAlone
    }
}

#[cfg(target_os = "macos")]
pub fn apply(
    conn: &str,
    servers: &[Ipv4Addr],
    domain: Option<&str>,
    subnets: &[String],
) -> Result<String, String> {
    if servers.is_empty() {
        return Ok(String::new());
    }
    let quoted: Vec<String> = servers
        .iter()
        .map(|s| crate::daemon::sh_quote(&format!("nameserver {s}")))
        .collect();
    let servers_txt = servers
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    match dns_scope(domain, subnets) {
        // Nothing to apply, and nothing to revert.
        Scope::LeaveAlone => Ok(format!(
            "system DNS left unchanged: this tunnel carries {} but names no DNS \
             domain, and the gateway pushed none — sending every query on the \
             machine to {servers_txt} would take over resolution far beyond what \
             the tunnel actually carries. Set a DNS domain on the profile to \
             resolve internal names over it.",
            subnets.join(", ")
        )),
        // Split-DNS: only this suffix resolves through the tunnel.
        Scope::Split(d) => {
            // The helper does this without a prompt when it is installed. It
            // re-validates the domain and re-parses the servers on its side —
            // this call is a request, not an instruction.
            if vpn_broker::unix_client::available() {
                let resp = vpn_broker::unix_client::request(
                    &vpn_broker::protocol::Request::ApplyDns {
                        conn: conn.to_string(),
                        servers: servers.iter().map(|s| s.to_string()).collect(),
                        domain: Some(d.clone()),
                        subnets: subnets.to_vec(),
                    },
                )
                .map_err(|e| format!("the VPN helper is not reachable: {e}"))?;
                if !resp.ok {
                    return Err(resp.msg);
                }
                // Recorded so revert knows the helper owns this one.
                let _ = std::fs::write(dns_record_path(conn), format!("helper\t{d}\n"));
                return Ok(format!("split-DNS: *.{d} resolves via {servers_txt}"));
            }
            let path = format!("/etc/resolver/{d}");
            let script = format!(
                "/bin/mkdir -p /etc/resolver && /usr/bin/printf '%s\\n' {lines} > {path} && {FLUSH}",
                lines = quoted.join(" "),
                path = crate::daemon::sh_quote(&path),
            );
            crate::daemon::osascript_admin(&script, "apply DNS")?;
            let _ = std::fs::write(dns_record_path(conn), format!("resolver\t{d}\n"));
            Ok(format!("split-DNS: *.{d} resolves via {servers_txt}"))
        }
        // Catch-all: every query goes to the VPN resolvers while connected.
        Scope::Everything => {
            let service = primary_service()?;
            let previous = current_servers(&service);
            let script = format!(
                "/usr/sbin/networksetup -setdnsservers {svc} {new} && {FLUSH}",
                svc = crate::daemon::sh_quote(&service),
                new = servers
                    .iter()
                    .map(|s| crate::daemon::sh_quote(&s.to_string()))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            crate::daemon::osascript_admin(&script, "apply DNS")?;
            // Recorded before it can matter, so a revert restores the exact
            // list that was there — "Empty" when nothing was set, which is what
            // networksetup wants to mean "back to DHCP".
            let _ = std::fs::write(
                dns_record_path(conn),
                format!("service\t{service}\t{}\n", previous.join(" ")),
            );
            Ok(format!(
                "DNS routed over the tunnel via {servers_txt} on {service} (all names)"
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub fn revert(conn: &str) -> Result<(), String> {
    let path = dns_record_path(conn);
    let Ok(record) = std::fs::read_to_string(&path) else {
        return Ok(()); // nothing was applied
    };
    let mut fields = record.trim_end_matches('\n').split('\t');
    let script = match (fields.next(), fields.next()) {
        // Applied through the helper, so it has to be undone through the
        // helper — the GUI cannot remove a root-owned /etc/resolver file.
        (Some("helper"), Some(_)) => {
            let resp = vpn_broker::unix_client::request(
                &vpn_broker::protocol::Request::RevertDns { conn: conn.to_string() },
            )
            .map_err(|e| format!("the VPN helper is not reachable: {e}"))?;
            let _ = std::fs::remove_file(&path);
            return if resp.ok { Ok(()) } else { Err(resp.msg) };
        }
        (Some("resolver"), Some(d)) => {
            let d = safe_domain(d).ok_or("the recorded split-DNS domain is not a valid name")?;
            format!(
                "/bin/rm -f {p} && {FLUSH}",
                p = crate::daemon::sh_quote(&format!("/etc/resolver/{d}")),
            )
        }
        (Some("service"), Some(service)) => {
            // An empty third field means nothing was set before, and
            // networksetup spells that "Empty" rather than an empty argument.
            let previous = fields.next().unwrap_or("").trim();
            let restore = if previous.is_empty() {
                "Empty".to_string()
            } else {
                previous
                    .split_whitespace()
                    .map(crate::daemon::sh_quote)
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            format!(
                "/usr/sbin/networksetup -setdnsservers {svc} {restore} && {FLUSH}",
                svc = crate::daemon::sh_quote(service),
            )
        }
        _ => return Err("the recorded DNS state could not be read".to_string()),
    };
    let r = crate::daemon::osascript_admin(&script, "revert DNS");
    let _ = std::fs::remove_file(&path);
    r
}

// ---- Other platforms ------------------------------------------------------
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn apply(
    _conn: &str,
    _servers: &[Ipv4Addr],
    _domain: Option<&str>,
    _subnets: &[String],
) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn revert(_conn: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::{dns_scope, safe_domain, service_for_device, Scope};

    const LISTING: &str = "\
An asterisk (*) denotes that a network service is disabled.
(1) ThinkPad Lan
(Hardware Port: ThinkPad Lan, Device: en5)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
";

    #[test]
    fn finds_the_service_carrying_the_default_route() {
        assert_eq!(service_for_device(LISTING, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(
            service_for_device(LISTING, "en5").as_deref(),
            Some("ThinkPad Lan")
        );
        assert_eq!(service_for_device(LISTING, "utun9"), None);
    }

    #[test]
    fn takes_the_renamed_service_name_not_the_hardware_port() {
        let renamed = "(1) Office uplink\n(Hardware Port: Wi-Fi, Device: en0)\n";
        assert_eq!(
            service_for_device(renamed, "en0").as_deref(),
            Some("Office uplink")
        );
    }

    /// The bug this guards: a split tunnel carrying one /24, with no DNS
    /// domain, used to point every query on the machine at the VPN resolver.
    #[test]
    fn a_split_tunnel_without_a_domain_leaves_system_dns_alone() {
        assert_eq!(
            dns_scope(None, &["10.98.32.0/24".to_string()]),
            Scope::LeaveAlone
        );
        // An empty or unusable domain is not a domain.
        assert_eq!(dns_scope(Some(""), &["10.0.0.0/8".to_string()]), Scope::LeaveAlone);
        assert_eq!(dns_scope(Some("../x"), &["10.0.0.0/8".to_string()]), Scope::LeaveAlone);
    }

    #[test]
    fn a_named_domain_scopes_dns_to_it() {
        assert_eq!(
            dns_scope(Some("corp.example.com"), &["10.98.32.0/24".to_string()]),
            Scope::Split("corp.example.com".to_string())
        );
    }

    /// A tunnel that really does carry everything should resolve everything.
    #[test]
    fn a_real_full_tunnel_still_takes_the_catch_all() {
        assert_eq!(dns_scope(None, &["0.0.0.0/0".to_string()]), Scope::Everything);
        assert_eq!(
            dns_scope(None, &["10.0.0.0/8".to_string(), "0.0.0.0/0".to_string()]),
            Scope::Everything
        );
        // A /0 must be matched on the prefix, not by substring: "10.0.0.0/8"
        // ends in "0" and must not be mistaken for a default route.
        assert_eq!(dns_scope(None, &["10.0.0.0/8".to_string()]), Scope::LeaveAlone);
    }

    #[test]
    fn accepts_real_dns_names() {
        assert_eq!(safe_domain("corp.example.com").as_deref(), Some("corp.example.com"));
        assert_eq!(safe_domain(" .Corp.Example.COM. ").as_deref(), Some("corp.example.com"));
    }

    /// The domain reaches this from a profile file or from whatever the gateway
    /// pushed, and it is interpolated into a path in a command run as root — so
    /// anything that could escape /etc/resolver must be refused outright rather
    /// than sanitised into something else.
    #[test]
    fn refuses_anything_that_could_escape_etc_resolver() {
        for bad in [
            "../../etc/sudoers",
            "a/b",
            "foo bar",
            "foo;reboot",
            "$(whoami)",
            "'",
            "",
            "..",
        ] {
            assert!(safe_domain(bad).is_none(), "should have refused {bad:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_resolv_conf;
    use std::net::Ipv4Addr;

    #[test]
    fn reads_the_pushed_nameservers() {
        let text = "# generated by charon\n\
                    nameserver 10.98.49.1\n\
                    nameserver 10.98.49.2\n\
                    search corp.example\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                Ipv4Addr::new(10, 98, 49, 1),
                Ipv4Addr::new(10, 98, 49, 2)
            ]
        );
    }

    #[test]
    fn ignores_noise_and_dedupes() {
        // A comment, a duplicate, an IPv6 server we cannot apply, a bare word,
        // and a `nameserverX` that only looks like the keyword.
        let text = "; a comment\n\
                    nameserver 10.0.0.53\n\
                    nameserver 10.0.0.53\n\
                    nameserver fd00::1\n\
                    nameserver not-an-ip\n\
                    nameserverX 10.0.0.99\n\
                    \n";
        assert_eq!(parse_resolv_conf(text), vec![Ipv4Addr::new(10, 0, 0, 53)]);
    }

    #[cfg(windows)]
    #[test]
    fn reads_the_pushed_search_domain() {
        use super::parse_resolv_domain;
        // This is what saves a profile with no domain of its own from having to
        // claim the catch-all namespace.
        let text = "nameserver 10.228.184.51\nsearch kanzlei.local\n";
        assert_eq!(parse_resolv_domain(text).as_deref(), Some("kanzlei.local"));
        // `domain` is the older spelling of the same thing.
        assert_eq!(
            parse_resolv_domain("domain corp.example\n").as_deref(),
            Some("corp.example")
        );
        // `search` may list several; the first is the primary one.
        assert_eq!(
            parse_resolv_domain("search a.example b.example\n").as_deref(),
            Some("a.example")
        );
        // Nothing to take: no domain line, a keyword that only looks like one,
        // and a comment.
        assert_eq!(parse_resolv_domain("nameserver 10.0.0.53\n"), None);
        assert_eq!(parse_resolv_domain("searchX corp.example\n"), None);
        assert_eq!(parse_resolv_domain("# search corp.example\n"), None);
    }

    #[test]
    fn empty_or_serverless_file_yields_nothing() {
        assert!(parse_resolv_conf("").is_empty());
        assert!(parse_resolv_conf("search corp.example\ndomain corp.example\n").is_empty());
    }
}
