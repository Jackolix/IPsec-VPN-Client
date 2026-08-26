//! NRPT DNS control, run directly (the broker is already LocalSystem, so no
//! elevation/UAC). Mirrors the policy the GUI used to apply through an elevated
//! PowerShell: a Name Resolution Policy Table rule keyed by namespace, which is
//! system-wide and never touches an adapter's own resolvers.
//!
//! Each applied rule's namespace is recorded under `%ProgramData%\ipsec-vpn\dns`
//! so it can be reverted after a broker restart or crash (see [`revert_all`]).

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// The catch-all namespace: "resolve *everything* through these servers". It is
/// system-wide, so at most one connection can hold it — see [`apply`].
const CATCH_ALL: &str = ".";

/// Where we record `<conn>.ns` -> the namespaces it holds (one per line) so a
/// revert (even after a restart) removes exactly the rules we added.
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

/// The NRPT namespace for a domain suffix (`corp.example` -> `.corp.example`),
/// or the catch-all when no domain is known.
fn namespace(domain: Option<&str>) -> String {
    match domain {
        Some(d) if !d.trim().is_empty() => format!(".{}", d.trim().trim_start_matches('.')),
        _ => CATCH_ALL.to_string(),
    }
}

/// The reverse-lookup zone covering `cidr`, at whichever octet boundary the
/// prefix reaches (`10.98.43.0/24` -> `43.98.10.in-addr.arpa`). `None` for a
/// prefix shorter than /8, which would claim more than this tunnel owns, and
/// for the default route, which owns nothing in particular.
///
/// This is the consolation prize for a connection that could not have the
/// catch-all: addresses on its own network still resolve to names through its
/// own servers, and nobody else's names are touched.
///
/// The octets are re-parsed as numbers rather than passed through as text: this
/// string ends up inside a single-quoted PowerShell argument, so it must not be
/// possible to smuggle anything through a malformed subnet.
fn reverse_zone(cidr: &str) -> Option<String> {
    let (addr, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    let octets: Vec<u8> = addr.trim().split('.').map(|o| o.parse().ok()).collect::<Option<_>>()?;
    if octets.len() != 4 || !(8..=32).contains(&prefix) {
        return None;
    }
    // Only whole octets can be expressed as a reverse zone; a /24 gives three,
    // a /16 two, a /20 still only two (it spans more than one third octet).
    let keep = (prefix / 8) as usize;
    let labels: Vec<String> =
        octets[..keep].iter().rev().map(|o| o.to_string()).collect();
    Some(format!(".{}.in-addr.arpa", labels.join(".")))
}

/// Which connection, if any, currently holds `ns` — read from the records, so
/// it survives a broker restart. `None` when the namespace is free.
fn holder_of(ns: &str) -> Option<String> {
    let entries = std::fs::read_dir(record_dir()).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ns") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if text.lines().any(|l| l.trim() == ns) {
            return path.file_stem().and_then(|s| s.to_str()).map(str::to_string);
        }
    }
    None
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

/// Route DNS for this connection over the tunnel via NRPT rules. Returns a short
/// human summary for the connect log. No-op with no servers.
///
/// A namespace is a system-wide resource, so it belongs to whichever connection
/// claimed it first; a later connection asking for the same one is refused it
/// rather than silently taking it over (which would also make the first one's
/// disconnect tear down DNS the second is relying on). Wanting the catch-all
/// when someone else holds it falls back to this connection's own reverse
/// zones — see [`reverse_zone`].
/// `spoken_for` are namespaces some other datapath has already claimed — see
/// `Broker::ssl_dns_claims`. They are treated exactly like a namespace another
/// connection's NRPT rule holds.
pub fn apply(
    conn: &str,
    servers: &[Ipv4Addr],
    domain: Option<&str>,
    subnets: &[String],
    spoken_for: &[String],
) -> Result<String, String> {
    if servers.is_empty() {
        return Ok(String::new());
    }
    let me = sanitize(conn);
    let wanted = namespace(domain);
    let free = |ns: &String| {
        !spoken_for.contains(ns) && holder_of(ns).is_none_or(|h| h == me)
    };

    // What this connection is entitled to ask for. The catch-all, once someone
    // else holds it, is not on the table at any price.
    let asked: Vec<String> = if wanted == CATCH_ALL && !free(&wanted) {
        let mut zones: Vec<String> = subnets.iter().filter_map(|s| reverse_zone(s)).collect();
        zones.sort();
        zones.dedup();
        zones
    } else {
        vec![wanted.clone()]
    };

    // Of those, the ones actually free (or already ours, on a reconnect).
    let (mine, taken): (Vec<String>, Vec<String>) = asked.into_iter().partition(free);

    let servers_txt = servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
    if mine.is_empty() {
        // Nothing left to claim. Not an error: the tunnel is up and, if another
        // connection already resolves these names, they still resolve — but say
        // so plainly, because it is not what the profile asked for.
        return Ok(match wanted.as_str() {
            CATCH_ALL => format!(
                "DNS left as it is: another VPN already resolves all names, and this profile \
                 names no DNS domain of its own to scope a rule to. Set one in the profile to \
                 resolve {servers_txt}'s names alongside it."
            ),
            ns => format!("DNS left as it is: another VPN already resolves *{ns}"),
        });
    }

    let list = servers.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",");
    for ns in &mine {
        // Replace any stale rule for this namespace (ours, or one left behind by
        // something that crashed), then add ours.
        let body = format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '{ns}' }} | \
             Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue;\
             Add-DnsClientNrptRule -Namespace '{ns}' -NameServers @({list});\
             Clear-DnsClientCache -ErrorAction SilentlyContinue"
        );
        run_ps(&body)?;
    }

    // Record the namespaces so a revert removes exactly the rules we added.
    let _ = std::fs::create_dir_all(record_dir());
    let _ = std::fs::write(record_path(conn), mine.join("\n"));

    let mut msg = if mine.len() == 1 && mine[0] == CATCH_ALL {
        format!("DNS routed over the tunnel via {servers_txt} (all names)")
    } else {
        format!(
            "split-DNS: {} resolves via {servers_txt}",
            mine.iter().map(|ns| format!("*{ns}")).collect::<Vec<_>>().join(", ")
        )
    };
    if wanted == CATCH_ALL && mine[0] != CATCH_ALL {
        msg.push_str(
            " — another VPN already resolves all names, so only this network's own addresses \
             were claimed. Set a DNS domain in the profile to resolve its names too.",
        );
    } else if !taken.is_empty() {
        msg.push_str(" (another VPN already resolves the rest)");
    }
    Ok(msg)
}

/// Remove the NRPT rules [`apply`] created for `conn`. No-op when nothing was
/// recorded (a profile with no DNS, or already reverted).
pub fn revert(conn: &str) -> Result<(), String> {
    let path = record_path(conn);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    // Drop our record first, so a namespace we own is not read back as still
    // held while we are removing it.
    let _ = std::fs::remove_file(&path);
    for ns in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        // Only remove a rule still recorded to us. Another connection owning it
        // means it claimed it after a broker restart lost our bookkeeping —
        // tearing it down would take DNS away from a tunnel that is still up.
        if let Some(holder) = holder_of(ns) {
            if holder != sanitize(conn) {
                continue;
            }
        }
        remove_namespace(ns)?;
    }
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
        if let Ok(text) = std::fs::read_to_string(&path) {
            for ns in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let _ = remove_namespace(ns);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_from_a_domain_or_the_catch_all() {
        assert_eq!(namespace(Some("kanzlei.local")), ".kanzlei.local");
        // A domain already written with a leading dot must not become "..".
        assert_eq!(namespace(Some(".kanzlei.local")), ".kanzlei.local");
        assert_eq!(namespace(None), CATCH_ALL);
        assert_eq!(namespace(Some("  ")), CATCH_ALL);
    }

    #[test]
    fn reverse_zones_stop_at_octet_boundaries() {
        assert_eq!(reverse_zone("10.98.43.0/24").as_deref(), Some(".43.98.10.in-addr.arpa"));
        assert_eq!(reverse_zone("10.10.0.0/16").as_deref(), Some(".10.10.in-addr.arpa"));
        assert_eq!(reverse_zone("10.0.0.0/8").as_deref(), Some(".10.in-addr.arpa"));
        // A /20 spans several third octets, so it only yields the first two.
        assert_eq!(reverse_zone("10.10.0.0/20").as_deref(), Some(".10.10.in-addr.arpa"));
        // Nothing shorter than /8: that would claim more than the tunnel owns.
        assert_eq!(reverse_zone("0.0.0.0/0"), None);
    }

    #[test]
    fn reverse_zone_rejects_anything_not_a_subnet() {
        // The result is interpolated into PowerShell, so a non-numeric octet has
        // to be refused rather than passed through.
        assert_eq!(reverse_zone("10.98.x.0/24"), None);
        assert_eq!(reverse_zone("10.0.0.0/8'; Stop-Service #"), None);
        assert_eq!(reverse_zone("evil"), None);
        assert_eq!(reverse_zone("10.0.0.0/99"), None);
    }
}
