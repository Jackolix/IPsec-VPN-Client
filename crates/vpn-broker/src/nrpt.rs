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
/// string becomes a namespace in the system's DNS policy, so nothing but a
/// well-formed reverse zone may reach it through a malformed subnet.
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

/// The local NRPT, as the DNS Client service reads it.
///
/// This used to go through `Add-DnsClientNrptRule` and friends, and that cost
/// more than the whole IKE handshake: every call started a PowerShell, loaded
/// the DnsClient CIM module and only then touched the table — 2 to 4.5 s
/// measured, once on connect and again on disconnect, which is most of why a
/// tunnel took ten seconds here and one on macOS. The cmdlets are a front end
/// for this registry key: a rule is one subkey, and the DNS Client service
/// watches the key and re-reads the table when it changes. So write it
/// directly, the way other VPN clients do, and flush the resolver cache so
/// names already cached against the old table are looked up again.
///
/// Same scope as before: these are *local* rules. A machine that receives NRPT
/// rules from Group Policy ignores the local table entirely, with or without
/// PowerShell.
mod table {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE,
        REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const BASE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

    /// `ConfigOptions` bit for "send these names to GenericDNSServers" — what
    /// `Add-DnsClientNrptRule -NameServers` sets, and all a split-DNS rule is.
    const GENERIC_DNS_SERVERS: u32 = 0x8;
    /// The rule format `Add-DnsClientNrptRule` writes on every supported Windows.
    const RULE_VERSION: u32 = 2;

    #[link(name = "dnsapi")]
    extern "system" {
        /// Exported by dnsapi.dll and what `Clear-DnsClientCache` and
        /// `ipconfig /flushdns` call; absent from the SDK headers, hence here.
        fn DnsFlushResolverCache() -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// An open registry key, closed on drop.
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(path: &str, access: u32) -> Result<Option<Key>, String> {
        let mut h: HKEY = null_mut();
        let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(path).as_ptr(), 0, access, &mut h) };
        match rc {
            ERROR_SUCCESS => Ok(Some(Key(h))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            rc => Err(format!("cannot open HKLM\\{path}: error {rc}")),
        }
    }

    fn create(path: &str) -> Result<Key, String> {
        let mut h: HKEY = null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(path).as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut h,
                null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(format!("cannot create HKLM\\{path}: error {rc}"));
        }
        Ok(Key(h))
    }

    fn set(key: &Key, name: &str, kind: u32, data: &[u8]) -> Result<(), String> {
        let rc = unsafe {
            RegSetValueExW(key.0, wide(name).as_ptr(), 0, kind, data.as_ptr(), data.len() as u32)
        };
        if rc != ERROR_SUCCESS {
            return Err(format!("cannot write NRPT value {name}: error {rc}"));
        }
        Ok(())
    }

    fn set_dword(key: &Key, name: &str, v: u32) -> Result<(), String> {
        set(key, name, REG_DWORD, &v.to_le_bytes())
    }

    /// REG_SZ and REG_MULTI_SZ both travel as UTF-16LE bytes; a multi-string
    /// is each entry NUL-terminated plus one more NUL to end the list.
    fn utf16_bytes(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn set_sz(key: &Key, name: &str, v: &str) -> Result<(), String> {
        set(key, name, REG_SZ, &utf16_bytes(&wide(v)))
    }

    fn set_multi_sz(key: &Key, name: &str, items: &[&str]) -> Result<(), String> {
        let mut units: Vec<u16> = Vec::new();
        for item in items {
            units.extend(wide(item));
        }
        units.push(0);
        set(key, name, REG_MULTI_SZ, &utf16_bytes(&units))
    }

    /// The namespaces a rule subkey covers (its `Name` multi-string).
    fn rule_names(sub: &str) -> Vec<String> {
        let Ok(Some(rule)) = open(&format!("{BASE}\\{sub}"), KEY_READ) else {
            return Vec::new();
        };
        let name = wide("Name");
        let mut len: u32 = 0;
        let rc = unsafe {
            RegQueryValueExW(rule.0, name.as_ptr(), null_mut(), null_mut(), null_mut(), &mut len)
        };
        if rc != ERROR_SUCCESS || len == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        let rc = unsafe {
            RegQueryValueExW(
                rule.0,
                name.as_ptr(),
                null_mut(),
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return Vec::new();
        }
        buf.split(|&u| u == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    /// Every rule subkey's name.
    fn subkeys(base: &Key) -> Vec<String> {
        let mut out = Vec::new();
        for index in 0.. {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    base.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS {
                break;
            }
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
        out
    }

    /// Delete every rule covering `ns` — ours, or one something else left
    /// behind — exactly as the `Where-Object` pipeline it replaces did.
    pub fn remove(ns: &str) -> Result<(), String> {
        let Some(base) = open(BASE, KEY_READ)? else {
            return Ok(());
        };
        // Collected first: deleting while enumerating shifts the indices.
        let doomed: Vec<String> = subkeys(&base)
            .into_iter()
            .filter(|sub| rule_names(sub).iter().any(|n| n.eq_ignore_ascii_case(ns)))
            .collect();
        drop(base);
        for sub in doomed {
            let path = wide(&format!("{BASE}\\{sub}"));
            // A rule has no subkeys, but nothing stops one being given some;
            // the tree delete clears them, the key delete takes the rule.
            let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr()) };
            if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
                return Err(format!("cannot remove the NRPT rule for {ns}: error {rc}"));
            }
            let rc = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, path.as_ptr()) };
            if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
                return Err(format!("cannot remove the NRPT rule for {ns}: error {rc}"));
            }
        }
        Ok(())
    }

    /// Add the rule `ns` -> `servers`, under a subkey named for it.
    pub fn add(ns: &str, servers: &[String]) -> Result<(), String> {
        let rule = create(&format!("{BASE}\\{}", super::rule_key(ns)))?;
        set_dword(&rule, "Version", RULE_VERSION)?;
        set_multi_sz(&rule, "Name", &[ns])?;
        set_sz(&rule, "GenericDNSServers", &servers.join("; "))?;
        set_dword(&rule, "ConfigOptions", GENERIC_DNS_SERVERS)?;
        set_sz(&rule, "IPSECCARestriction", "")?;
        set_sz(&rule, "Comment", "")?;
        set_sz(&rule, "DisplayName", "")?;
        Ok(())
    }

    pub fn flush() {
        unsafe { DnsFlushResolverCache() };
    }
}

/// The registry subkey a namespace's rule lives under: a GUID, as every NRPT
/// rule's is, but derived from the namespace so a reconnect rewrites the same
/// rule rather than adding a twin. FNV-1a, twice with different offsets, for
/// 128 bits — this needs to be stable and distinct, not secret.
fn rule_key(ns: &str) -> String {
    fn fnv(seed: u64, s: &str) -> u64 {
        s.bytes().fold(seed, |h, b| (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3))
    }
    let ns = ns.to_ascii_lowercase();
    let a = fnv(0xcbf2_9ce4_8422_2325, &ns);
    let b = fnv(0x8422_2325_cbf2_9ce4, &format!("ipsec-vpn:{ns}"));
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
        a >> 32,
        (a >> 16) & 0xffff,
        a & 0xffff,
        b >> 48,
        b & 0xffff_ffff_ffff
    )
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

    let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    for ns in &mine {
        // Replace any stale rule for this namespace (ours, or one left behind by
        // something that crashed), then add ours.
        table::remove(ns)?;
        table::add(ns, &list)?;
    }
    table::flush();

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
    table::remove(ns)?;
    table::flush();
    Ok(())
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
        // The result becomes a system DNS namespace, so a non-numeric octet has
        // to be refused rather than passed through.
        assert_eq!(reverse_zone("10.98.x.0/24"), None);
        assert_eq!(reverse_zone("10.0.0.0/8'; Stop-Service #"), None);
        assert_eq!(reverse_zone("evil"), None);
        assert_eq!(reverse_zone("10.0.0.0/99"), None);
    }

    #[test]
    fn a_namespace_always_maps_to_the_same_guid_shaped_key() {
        let key = rule_key(".corp.example");
        assert_eq!(key.len(), 38, "{key}");
        assert!(key.starts_with('{') && key.ends_with('}'));
        assert_eq!(key.matches('-').count(), 4);
        // Stable, and case-blind like DNS — a reconnect must land on the same rule.
        assert_eq!(key, rule_key(".CORP.example"));
        assert_ne!(key, rule_key(".other.local"));
        assert_ne!(rule_key("."), rule_key(".43.98.10.in-addr.arpa"));
    }
}
