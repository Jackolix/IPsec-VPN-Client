//! NRPT DNS control, run directly (the broker is already LocalSystem, so no
//! elevation/UAC). Mirrors the policy the GUI used to apply through an elevated
//! PowerShell: a Name Resolution Policy Table rule keyed by namespace, which is
//! system-wide and never touches an adapter's own resolvers.
//!
//! Each applied rule's namespace is recorded under `%ProgramData%\ipsec-vpn\dns`
//! so it can be reverted after a broker restart or crash (see [`revert_all`]).

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Where we record `<conn>.ns` -> namespace so a revert (even after a restart)
/// removes exactly the rule we added.
fn record_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("ipsec-vpn").join("dns")
}

fn record_path(conn: &str) -> PathBuf {
    record_dir().join(format!("{}.ns", sanitize(conn)))
}

fn sanitize(conn: &str) -> String {
    conn.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// The NRPT namespace for a profile: the domain suffix (`.corp.example`) for
/// split-DNS, or `.` (all names) when the profile names no domain.
fn namespace(domain: Option<&str>) -> String {
    match domain {
        Some(d) if !d.trim().is_empty() => format!(".{}", d.trim().trim_start_matches('.')),
        _ => ".".to_string(),
    }
}

/// Run a PowerShell snippet as the current (SYSTEM) user and surface failures.
fn run_ps(body: &str) -> Result<(), String> {
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", body])
        .output()
        .map_err(|e| format!("failed to run powershell: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let msg = err.trim();
    Err(if msg.is_empty() {
        format!("powershell exited with {}", out.status)
    } else {
        msg.to_string()
    })
}

/// Route DNS for this connection over the tunnel via an NRPT rule. Returns a
/// short human summary for the connect log. No-op with no servers.
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
    run_ps(&body)?;

    // Record the namespace so we can revert exactly this rule later.
    let _ = std::fs::create_dir_all(record_dir());
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
pub fn revert(conn: &str) -> Result<(), String> {
    let path = record_path(conn);
    let Ok(ns) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    remove_namespace(ns.trim())?;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Remove every rule we recorded (used on service stop so a crash/restart can't
/// leave a stale resolver override pointing at a now-dead tunnel).
pub fn revert_all() {
    let Ok(entries) = std::fs::read_dir(record_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ns") {
            continue;
        }
        if let Ok(ns) = std::fs::read_to_string(&path) {
            let _ = remove_namespace(ns.trim());
        }
        let _ = std::fs::remove_file(&path);
    }
}

fn remove_namespace(ns: &str) -> Result<(), String> {
    if ns.is_empty() {
        return Ok(());
    }
    let body = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '{ns}' }} | \
         Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;\
         Clear-DnsClientCache -ErrorAction SilentlyContinue"
    );
    run_ps(&body)
}
