//! Backend logic for the desktop app, kept free of any Tauri types so it can
//! be exercised headlessly (see `--selftest` in `main.rs`).
//!
//! Profiles are `.ini` files in a scanned directory; each is imported with
//! `ncp-profile` on demand, so the PSK only ever lives in memory for the
//! duration of a connect. Connection control goes through `vpn-control`.

use serde::Serialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use vpn_control::{IkeSa, Transport};

#[derive(Clone)]
pub struct AppState {
    pub profile_dir: PathBuf,
    pub transport: Transport,
}

impl AppState {
    pub fn from_env() -> Self {
        let profile_dir = std::env::var_os("VPN_PROFILE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_profile_dir);
        // Make sure it exists so the picker/drag-drop have somewhere to copy to
        // and the scan doesn't fail on a fresh install.
        let _ = std::fs::create_dir_all(&profile_dir);

        let transport = match std::env::var("VPN_VICI_TCP") {
            Ok(addr) if !addr.trim().is_empty() => Transport::Tcp(addr),
            _ => default_transport(),
        };

        AppState {
            profile_dir,
            transport,
        }
    }
}

/// Where imported profiles live when `VPN_PROFILE_DIR` isn't set. A per-user
/// data dir, so an installed app (whose working directory is unpredictable)
/// always finds the same stable folder.
fn default_profile_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));

    base.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join("ipsec-vpn")
        .join("profiles")
}

fn default_transport() -> Transport {
    #[cfg(unix)]
    {
        Transport::Unix("/var/run/charon.vici".to_string())
    }
    // On Windows the app can spawn the native charon-svc daemon itself, which
    // listens on charon-svc's default vici port; that's the default target.
    // (The Linux dev container publishes vici on 45022 and sets VPN_VICI_TCP to
    // override this.)
    #[cfg(not(unix))]
    {
        Transport::Tcp(crate::daemon::NATIVE_VICI_ADDR.to_string())
    }
}

/// The vici endpoint the app talks to — used both to drive charon and to know
/// where the native daemon should come up.
fn vici_addr(state: &AppState) -> String {
    match &state.transport {
        Transport::Tcp(a) => a.clone(),
        _ => crate::daemon::NATIVE_VICI_ADDR.to_string(),
    }
}

/// Is the tunnel backend (native charon-svc, or the dev container) reachable?
pub fn daemon_running(state: &AppState) -> bool {
    crate::daemon::is_running(&vici_addr(state))
}

/// Start the native Windows daemon (raises a UAC prompt). No-op if already up.
pub fn daemon_start(state: &AppState) -> std::result::Result<(), String> {
    crate::daemon::start(&vici_addr(state))
}

/// Stop the native Windows daemon (raises a UAC prompt).
pub fn daemon_stop(state: &AppState) -> std::result::Result<(), String> {
    crate::daemon::stop(&vici_addr(state))
}

#[derive(Debug, Serialize)]
pub struct WarnItem {
    pub level: String,
    pub text: String,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub gateway: String,
    pub kind: String,
    pub local_id: Option<String>,
    pub remote: Vec<String>,
    pub ike: String,
    pub esp: String,
    pub pfs: Option<String>,
    pub auth: String,
    pub virtual_ip_requested: bool,
    pub warnings: Vec<WarnItem>,
    /// Whether the PSK for this profile is saved in the OS keychain.
    pub stored: bool,
    /// DNS servers used over the tunnel (from the profile), if any.
    pub dns: Vec<String>,
    /// Split-DNS domain scoping those servers, if the profile names one.
    pub dns_domain: Option<String>,
}

/// A purely informational label for the profile list: a bare private IP reads
/// as a lab/test target, an FQDN or public IP as production.
fn classify(gateway: &str) -> &'static str {
    match gateway.parse::<Ipv4Addr>() {
        Ok(ip) if ip.is_private() || ip.is_loopback() => "lab",
        _ => "prod",
    }
}

/// Split "Foo=1 interpreted as bar (note...)" into a headline and a note,
/// and pick a severity from the wording the importer uses.
fn to_warn_item(raw: &str) -> WarnItem {
    let level = if raw.contains("LOW-confidence") {
        "low"
    } else if raw.contains("unconfirmed") {
        "medium"
    } else if raw.contains("ignored") || raw.contains("not interpreted") || raw.contains("not supported") {
        "ignored"
    } else {
        "info"
    };
    let (text, note) = match raw.split_once(" (") {
        Some((head, tail)) => (head.trim().to_string(), tail.trim_end_matches(')').trim().to_string()),
        None => (raw.to_string(), String::new()),
    };
    WarnItem {
        level: level.to_string(),
        text,
        note,
    }
}

fn summarize(
    id: &str,
    config: &vpn_core::ConnectionConfig,
    warnings: &[ncp_profile::ImportWarning],
) -> ProfileSummary {
    ProfileSummary {
        id: id.to_string(),
        name: config.name.clone(),
        gateway: config.gateway.clone(),
        kind: classify(&config.gateway).to_string(),
        local_id: config.local_id.clone(),
        remote: config.remote_subnets.iter().map(|n| n.to_string()).collect(),
        ike: config.ike_proposal(),
        esp: config.esp_proposal(),
        pfs: config.pfs.map(|g| g.swanctl_name().to_string()),
        auth: "psk".to_string(),
        virtual_ip_requested: config.request_virtual_ip,
        warnings: warnings.iter().map(|w| to_warn_item(&w.to_string())).collect(),
        stored: crate::creds::has(id),
        dns: config.dns.servers.iter().map(|s| s.to_string()).collect(),
        dns_domain: config.dns.domain.clone(),
    }
}

fn load(path: &std::path::Path) -> std::result::Result<ncp_profile::ImportedProfile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    ncp_profile::import_profile(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn profile_path(state: &AppState, id: &str) -> PathBuf {
    state.profile_dir.join(format!("{id}.ini"))
}

/// Scan the profile directory and interpret every `.ini` file. Files that
/// fail to parse are skipped (a real UI would flag them separately).
pub fn list_profiles(state: &AppState) -> Vec<ProfileSummary> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&state.profile_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ini") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Ok(imported) = load(&path) {
            out.push(summarize(id, &imported.config, &imported.warnings));
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// The directory profiles are read from (shown in the UI, so the user knows
/// where their `.ini` files live).
pub fn profiles_dir(state: &AppState) -> String {
    state.profile_dir.display().to_string()
}

/// Import a `.ini` file into the profile directory so it shows up in the list.
/// Validates the extension and that it parses as an NCP profile (so junk is
/// rejected), then copies it in under a sanitized name. Returns the new
/// profile id (its file stem).
pub fn import_path(state: &AppState, src: &std::path::Path) -> std::result::Result<String, String> {
    if src.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("ini")) != Some(true) {
        return Err("only .ini profiles can be imported".to_string());
    }
    let text = std::fs::read_to_string(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    // Parse to reject files that aren't valid NCP profiles.
    ncp_profile::import_profile(&text).map_err(|e| format!("not a valid NCP profile: {e}"))?;

    let stem = src
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| {
            s.chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .ok_or("the file needs a name")?;

    std::fs::create_dir_all(&state.profile_dir).map_err(|e| e.to_string())?;
    let dest = state.profile_dir.join(format!("{stem}.ini"));
    // Don't silently overwrite a different existing profile.
    if dest.exists() && std::fs::canonicalize(&dest).ok() != std::fs::canonicalize(src).ok() {
        return Err(format!("a profile named \"{stem}\" already exists"));
    }
    std::fs::write(&dest, text).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    Ok(stem)
}

/// Connect the profile identified by `id` to the gateway it names.
pub fn connect(
    state: &AppState,
    id: String,
) -> std::result::Result<vpn_control::ConnectOutcome, String> {
    let mut imported = load(&profile_path(state, &id))?;
    // Prefer a PSK saved in the OS keychain over the one parsed from the
    // (plaintext-on-disk) .ini, so saved credentials are what actually
    // authenticate the tunnel.
    if let Some(psk) = crate::creds::load(&id)? {
        imported.config.auth = vpn_core::AuthMethod::PresharedKey(psk);
    }
    let name = vpn_core::swanctl::sanitize_name(&imported.config.name);
    let mut outcome =
        vpn_control::connect_logged(&state.transport, &imported.config, &name).map_err(|e| e.to_string())?;

    // With the tunnel up, apply the profile's DNS so names on the remote
    // network resolve over the VPN. Failure here doesn't fail the connect —
    // the tunnel still carries traffic — it's just surfaced in the log.
    if outcome.connected && !imported.config.dns.is_empty() {
        apply_dns(state, &name, &imported.config.dns, &mut outcome);
    }
    Ok(outcome)
}

/// Configure DNS for an established tunnel (via an NRPT rule) and note the
/// result in the connect log. Best-effort: a DNS failure doesn't fail the
/// connect.
fn apply_dns(
    _state: &AppState,
    name: &str,
    dns: &vpn_core::DnsConfig,
    outcome: &mut vpn_control::ConnectOutcome,
) {
    let (msg, bad) = match crate::dns::apply(name, &dns.servers, dns.domain.as_deref()) {
        Ok(summary) if !summary.is_empty() => (summary, false),
        Ok(_) => return,
        Err(e) => (format!("DNS setup failed: {e}"), true),
    };
    outcome.log.push(vpn_control::LogLine {
        group: "DNS".to_string(),
        level: if bad { 1 } else { 2 },
        ikesa: Some(name.to_string()),
        msg,
    });
}

/// Copy a profile's PSK from its `.ini` into the OS keychain.
pub fn save_credentials(state: &AppState, id: String) -> std::result::Result<(), String> {
    let imported = load(&profile_path(state, &id))?;
    let vpn_core::AuthMethod::PresharedKey(psk) = &imported.config.auth;
    crate::creds::store(&id, psk)
}

/// Remove a profile's saved PSK from the OS keychain.
pub fn forget_credentials(_state: &AppState, id: String) -> std::result::Result<(), String> {
    crate::creds::delete(&id)
}

pub fn disconnect(state: &AppState, name: String) -> std::result::Result<(), String> {
    // Undo any DNS we applied for this connection first (best-effort — a stale
    // resolver override is worse than a failed revert log).
    if let Err(e) = crate::dns::revert(&name) {
        eprintln!("dns revert for {name} failed: {e}");
    }
    vpn_control::disconnect(&state.transport, &name).map_err(|e| e.to_string())
}

pub fn status(state: &AppState) -> std::result::Result<Vec<IkeSa>, String> {
    vpn_control::status(&state.transport).map_err(|e| e.to_string())
}
