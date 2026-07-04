//! Apply a profile's DNS over the tunnel on Windows.
//!
//! IPsec/WFP installs no adapter and charon-svc doesn't touch Windows DNS, so
//! the app configures it after the tunnel is up: point the tunnel interface's
//! resolvers at the VPN DNS servers and, when the profile names a domain, add a
//! split-DNS NRPT rule so only that suffix resolves over the tunnel. Changing
//! DNS/NRPT needs Administrator, so it runs through an elevated PowerShell (a
//! UAC prompt); what was applied is recorded to a temp file so disconnect can
//! revert it precisely (the virtual IP is gone by then).

use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(serde::Serialize, serde::Deserialize)]
struct Applied {
    if_index: u32,
    domain: Option<String>,
}

fn record_path(conn: &str) -> PathBuf {
    let safe: String = conn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    std::env::temp_dir().join(format!("vpn-dns-{safe}.json"))
}

/// The interface index currently holding `vip`. Read-only, no elevation.
#[cfg(windows)]
fn interface_for_vip(vip: &str) -> Option<u32> {
    let cmd = format!(
        "(Get-NetIPAddress -IPAddress '{vip}' -ErrorAction SilentlyContinue | \
         Select-Object -First 1).InterfaceIndex"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse::<u32>().ok()
}

/// Run a block of PowerShell elevated (one UAC prompt) and wait for it. The
/// block writes `OK` or `ERR: ...` to `result`, which we read back so a failure
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

/// Configure DNS for a freshly-established tunnel. Returns a short human summary
/// for the connect log. On non-Windows this is a no-op (the eventual Linux
/// backend uses strongSwan's `resolve` plugin instead).
#[cfg(windows)]
pub fn apply(conn: &str, servers: &[Ipv4Addr], domain: Option<&str>, vip: &str) -> Result<String, String> {
    if servers.is_empty() {
        return Ok(String::new());
    }
    let if_index = interface_for_vip(vip)
        .ok_or_else(|| format!("could not find the tunnel interface for virtual IP {vip}"))?;
    let list = servers
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");

    let mut body = format!(
        "Set-DnsClientServerAddress -InterfaceIndex {if_index} -ServerAddresses @({list});"
    );
    let summary;
    if let Some(d) = domain {
        let d = d.trim_start_matches('.');
        // Replace any stale rule for this namespace, then add split-DNS.
        body.push_str(&format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '.{d}' }} | \
             Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;\
             Add-DnsClientNrptRule -Namespace '.{d}' -NameServers @({list});"
        ));
        summary = format!(
            "DNS {} for *.{} (split-DNS) on if{}",
            servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "),
            d,
            if_index
        );
    } else {
        summary = format!(
            "DNS {} on the tunnel interface (if{})",
            servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", "),
            if_index
        );
    }
    body.push_str("Clear-DnsClientCache -ErrorAction SilentlyContinue");

    run_elevated(&body)?;
    let rec = Applied { if_index, domain: domain.map(|d| d.trim_start_matches('.').to_string()) };
    let _ = std::fs::write(record_path(conn), serde_json::to_vec(&rec).unwrap_or_default());
    Ok(summary)
}

/// Undo whatever [`apply`] configured for `conn`. No-op when nothing was
/// recorded (e.g. a profile with no DNS).
#[cfg(windows)]
pub fn revert(conn: &str) -> Result<(), String> {
    let path = record_path(conn);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(());
    };
    let rec: Applied = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut body = format!(
        "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction SilentlyContinue;",
        rec.if_index
    );
    if let Some(d) = &rec.domain {
        body.push_str(&format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '.{d}' }} | \
             Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;"
        ));
    }
    body.push_str("Clear-DnsClientCache -ErrorAction SilentlyContinue");
    let r = run_elevated(&body);
    let _ = std::fs::remove_file(&path);
    r
}

// ---- non-Windows stubs ----------------------------------------------------
#[cfg(not(windows))]
pub fn apply(_conn: &str, _servers: &[Ipv4Addr], _domain: Option<&str>, _vip: &str) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(not(windows))]
pub fn revert(_conn: &str) -> Result<(), String> {
    Ok(())
}
