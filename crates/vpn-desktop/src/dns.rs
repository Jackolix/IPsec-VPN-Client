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
#[cfg(any(windows, target_os = "linux"))]
use std::path::PathBuf;

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
pub fn apply(conn: &str, servers: &[Ipv4Addr], domain: Option<&str>) -> Result<String, String> {
    if servers.is_empty() {
        return Ok(String::new());
    }
    // Preferred path: hand it to the broker service (runs as SYSTEM, no UAC).
    // A reachable broker is authoritative — surface its result either way. Only
    // fall back to the elevated PowerShell path when the broker isn't installed.
    let req = vpn_broker::protocol::Request::ApplyDns {
        conn: conn.to_string(),
        servers: servers.iter().map(|s| s.to_string()).collect(),
        domain: domain.map(str::to_string),
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
pub fn apply(conn: &str, servers: &[Ipv4Addr], domain: Option<&str>) -> Result<String, String> {
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

// ---- Other platforms (macOS is build-only for now) ------------------------
#[cfg(not(any(windows, target_os = "linux")))]
pub fn apply(_conn: &str, _servers: &[Ipv4Addr], _domain: Option<&str>) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn revert(_conn: &str) -> Result<(), String> {
    Ok(())
}
