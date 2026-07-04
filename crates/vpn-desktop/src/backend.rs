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
            .unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join("profiles")
            });

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
    pub locked: bool,
    /// Whether the PSK for this profile is saved in the OS keychain.
    pub stored: bool,
    /// DNS servers used over the tunnel (from the profile), if any.
    pub dns: Vec<String>,
    /// Split-DNS domain scoping those servers, if the profile names one.
    pub dns_domain: Option<String>,
}

/// A gateway that is a bare private IP is treated as a lab/test target; an
/// FQDN (or public IP) is treated as production and locked against an
/// accidental connect without an explicit override.
fn classify(gateway: &str) -> (&'static str, bool) {
    match gateway.parse::<Ipv4Addr>() {
        Ok(ip) if ip.is_private() || ip.is_loopback() => ("lab", false),
        _ => ("prod", true),
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
    let (kind, locked) = classify(&config.gateway);
    ProfileSummary {
        id: id.to_string(),
        name: config.name.clone(),
        gateway: config.gateway.clone(),
        kind: kind.to_string(),
        local_id: config.local_id.clone(),
        remote: config.remote_subnets.iter().map(|n| n.to_string()).collect(),
        ike: config.ike_proposal(),
        esp: config.esp_proposal(),
        pfs: config.pfs.map(|g| g.swanctl_name().to_string()),
        auth: "psk".to_string(),
        virtual_ip_requested: config.request_virtual_ip,
        warnings: warnings.iter().map(|w| to_warn_item(&w.to_string())).collect(),
        locked,
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

/// Connect the profile identified by `id`. Production (locked) profiles
/// require an explicit `gateway_override` so the operator can't accidentally
/// dial the production gateway.
pub fn connect(
    state: &AppState,
    id: String,
    gateway_override: Option<String>,
) -> std::result::Result<vpn_control::ConnectOutcome, String> {
    let mut imported = load(&profile_path(state, &id))?;
    let (_, locked) = classify(&imported.config.gateway);
    match &gateway_override {
        Some(gw) if !gw.trim().is_empty() => imported.config.gateway = gw.trim().to_string(),
        _ if locked => {
            return Err(format!(
                "{} is a production gateway; provide a gateway override to connect to a lab responder instead.",
                imported.config.gateway
            ));
        }
        _ => {}
    }
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

/// Configure DNS for an established tunnel and note the result in the connect
/// log. Needs the tunnel's virtual IP to find the interface, so it reads it
/// back from charon's SA list.
fn apply_dns(
    state: &AppState,
    name: &str,
    dns: &vpn_core::DnsConfig,
    outcome: &mut vpn_control::ConnectOutcome,
) {
    let mut note = |msg: String, bad: bool| {
        outcome.log.push(vpn_control::LogLine {
            group: "DNS".to_string(),
            level: if bad { 1 } else { 2 },
            ikesa: Some(name.to_string()),
            msg,
        });
    };
    let vip = vpn_control::status(&state.transport)
        .ok()
        .and_then(|sas| sas.into_iter().find(|s| s.name == name))
        .and_then(|s| s.virtual_ips.into_iter().next());
    let Some(vip) = vip else {
        note("no virtual IP assigned; skipping DNS setup".to_string(), true);
        return;
    };
    match crate::dns::apply(name, &dns.servers, dns.domain.as_deref(), &vip) {
        Ok(summary) if !summary.is_empty() => note(summary, false),
        Ok(_) => {}
        Err(e) => note(format!("DNS setup failed: {e}"), true),
    }
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
