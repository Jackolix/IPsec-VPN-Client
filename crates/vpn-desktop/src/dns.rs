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
//! NRPT changes need Administrator, so this runs through an elevated PowerShell
//! (a UAC prompt); the namespace we created is recorded to a temp file so
//! disconnect can remove exactly that rule.

use std::net::Ipv4Addr;
use std::path::PathBuf;

fn record_path(conn: &str) -> PathBuf {
    let safe: String = conn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    std::env::temp_dir().join(format!("vpn-dns-{safe}.namespace"))
}

/// The NRPT namespace for a profile: the domain suffix (`.corp.example`) for
/// split-DNS, or `.` (all names) when the profile names no domain.
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

// ---- non-Windows stubs ----------------------------------------------------
#[cfg(not(windows))]
pub fn apply(_conn: &str, _servers: &[Ipv4Addr], _domain: Option<&str>) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(not(windows))]
pub fn revert(_conn: &str) -> Result<(), String> {
    Ok(())
}
