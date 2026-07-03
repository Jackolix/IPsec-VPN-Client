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
    // On Windows/macOS dev the tunnel runs in a container whose charon vici
    // socket is exposed over TCP; this is the default the run script sets up.
    #[cfg(not(unix))]
    {
        Transport::Tcp("127.0.0.1:45022".to_string())
    }
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
    vpn_control::connect_logged(&state.transport, &imported.config, &name).map_err(|e| e.to_string())
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
    vpn_control::disconnect(&state.transport, &name).map_err(|e| e.to_string())
}

pub fn status(state: &AppState) -> std::result::Result<Vec<IkeSa>, String> {
    vpn_control::status(&state.transport).map_err(|e| e.to_string())
}
