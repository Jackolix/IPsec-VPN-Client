//! Backend logic for the desktop app, kept free of any Tauri types so it can
//! be exercised headlessly (see `--selftest` in `main.rs`).
//!
//! Profiles are files in a scanned directory — NCP `.ini`, Sophos `.scx` or
//! legacy `.tgb` — each imported on demand by the importer matching its
//! format, so the PSK only ever lives in memory for the duration of a
//! connect. Connection control goes through `vpn-control`.

use serde::Serialize;
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
    /// Names of the fields the user has overridden (empty = the file as-is).
    /// Everything above already reflects them; this is what the UI marks up.
    pub edits: Vec<String>,
    /// The profile's file name, extension included — profiles no longer all
    /// end in `.ini`, and the UI names the file when it is about to delete it.
    pub file: String,
    /// Which importer read it, for the UI to label the profile's origin.
    pub format: String,
    /// IKE version the profile negotiates (`1` or `2`).
    pub ike_version: String,
    /// Set when the gateway wants a username and password on top of the PSK.
    pub user_auth: Option<String>,
}

/// A profile opened for editing: its current effective values, plus which of
/// them are user overrides rather than what the `.ini` said.
#[derive(Debug, Serialize)]
pub struct ProfileEdit {
    pub id: String,
    pub edit: crate::overrides::Edit,
    pub edits: Vec<String>,
    /// Whether a PSK is stored in the keychain — the edit dialog offers to
    /// replace it (the `.ini`'s own PSK is never editable in place).
    pub stored: bool,
}

/// Split "Foo=1 interpreted as bar (note...)" into a headline and a note,
/// and pick a severity from the wording the importer uses.
fn to_warn_item(raw: &str) -> WarnItem {
    let level = if raw.contains("LOW-confidence") {
        "low"
    } else if raw.contains("unconfirmed") || raw.contains("were not applied") {
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
    file: &str,
    config: &vpn_core::ConnectionConfig,
    warnings: &[vpn_core::ImportWarning],
    edits: Vec<String>,
) -> ProfileSummary {
    ProfileSummary {
        edits,
        file: file.to_string(),
        format: format_label(file).to_string(),
        ike_version: config.ike_version.swanctl_value().to_string(),
        user_auth: config.user_auth.as_ref().map(|ua| {
            let method = match config.ike_version {
                vpn_core::IkeVersion::V1 => "XAuth",
                vpn_core::IkeVersion::V2 => "EAP-MSCHAPv2",
            };
            if ua.otp {
                format!("{method} + one-time code")
            } else {
                method.to_string()
            }
        }),
        id: id.to_string(),
        name: config.name.clone(),
        gateway: config.gateway.clone(),
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

/// File extensions a profile may have, in the order [`profile_path`] resolves
/// them. Ids stay bare file stems, so an override sidecar or a keychain entry
/// written before Sophos profiles existed still addresses the same profile.
const PROFILE_EXTENSIONS: [&str; 3] = ["ini", "scx", "tgb"];

/// Human-readable origin of a profile, from its extension. The importers pick
/// by content, but the extension is what survived the copy into the profile
/// directory and is what the user sees in the folder.
fn format_label(file: &str) -> &'static str {
    match file.rsplit('.').next().unwrap_or_default() {
        "scx" => "Sophos Connect",
        "tgb" => "Sophos (legacy)",
        _ => "NCP",
    }
}

/// Interpret a profile file, whichever format it is in.
///
/// Dispatch is on content, not extension: these files are routinely renamed on
/// the way to a user, and a file that claims one format while being another
/// should be read as what it actually is.
fn parse(path: &std::path::Path) -> std::result::Result<vpn_core::ImportedProfile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_text(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse_text(text: &str) -> std::result::Result<vpn_core::ImportedProfile, String> {
    match sophos_profile::detect(text) {
        Some(sophos_profile::Format::Provisioning) => Err(provisioning_message(text)),
        Some(_) => sophos_profile::import_profile(text).map_err(|e| e.to_string()),
        None => ncp_profile::import_profile(text).map_err(|e| e.to_string()),
    }
}

/// A `.pro` holds no connection to import — it names the user portal the real
/// profile is downloaded from. Say which portal, so the message is actionable
/// rather than just a rejection.
fn provisioning_message(text: &str) -> String {
    let portal = sophos_profile::pro::parse(text)
        .ok()
        .and_then(|entries| entries.first().and_then(|e| e.portal_url()));
    match portal {
        Some(url) => format!(
            "this is a Sophos provisioning file, not a profile — sign in at {url}, download the \
             .scx profile from the portal, and import that file instead"
        ),
        None => "this is a Sophos provisioning file, not a profile — it names a user portal to \
                 download the real profile from"
            .to_string(),
    }
}

/// A profile as it is actually used: the `.ini` re-parsed from disk, with the
/// user's saved overrides replayed on top. Also reports which fields those
/// overrides changed, so the UI can mark them.
///
/// Overrides that no longer apply (a hand-edited sidecar, or one written
/// against an `.ini` that has since been replaced) are dropped with a warning
/// rather than taking the profile down — the file is always a usable fallback.
fn load(
    state: &AppState,
    id: &str,
) -> std::result::Result<(vpn_core::ImportedProfile, Vec<String>), String> {
    let mut imported = parse(&profile_path(state, id))?;
    let base = crate::overrides::Edit::from_config(&imported.config);
    let (edited, mut names) = crate::overrides::load(&state.profile_dir, id).overlay(&base);
    if !names.is_empty() {
        if let Err(e) = edited.apply_to(&mut imported.config) {
            // Phrased for `to_warn_item`, which splits a trailing parenthetical
            // off as the note.
            imported.warnings.push(vpn_core::ImportWarning(format!(
                "saved edits were not applied; using the profile file as imported ({e})"
            )));
            names.clear();
        }
    }
    Ok((imported, names))
}

/// The file backing a profile id. The id is the file stem, so the extension is
/// whichever one is actually on disk; [`import_path`] refuses a second file
/// with the same stem, so at most one can match.
fn profile_path(state: &AppState, id: &str) -> PathBuf {
    PROFILE_EXTENSIONS
        .iter()
        .map(|ext| state.profile_dir.join(format!("{id}.{ext}")))
        .find(|p| p.is_file())
        // Nothing on disk: name the .ini so "cannot read ...ini" still reads
        // sensibly for the overwhelmingly common case.
        .unwrap_or_else(|| state.profile_dir.join(format!("{id}.ini")))
}

/// Is this a file extension we import profiles from?
fn is_profile_extension(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| PROFILE_EXTENSIONS.iter().any(|k| ext.eq_ignore_ascii_case(k)))
        .unwrap_or(false)
}

/// A profile id addresses files in the profile directory, so one that came back
/// from the UI must not be able to name anything outside it. Ids are file stems
/// minted by [`import_path`], which already restricts them to this charset — an
/// id that doesn't fit is rejected rather than sanitized into a different
/// profile's name.
fn check_id(id: &str) -> std::result::Result<(), String> {
    let ok = !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(format!("\"{id}\" is not a valid profile id"))
    }
}

/// Scan the profile directory and interpret every profile file, in any of the
/// formats we import. Files that fail to parse are skipped (a real UI would
/// flag them separately).
pub fn list_profiles(state: &AppState) -> Vec<ProfileSummary> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&state.profile_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_profile_extension(&path) {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let file = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default()
            .to_string();
        if let Ok((imported, edits)) = load(state, id) {
            out.push(summarize(
                id,
                &file,
                &imported.config,
                &imported.warnings,
                edits,
            ));
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// The editable view of a profile — what the edit dialog opens on.
pub fn get_profile_edit(state: &AppState, id: String) -> std::result::Result<ProfileEdit, String> {
    let (imported, edits) = load(state, &id)?;
    Ok(ProfileEdit {
        edit: crate::overrides::Edit::from_config(&imported.config),
        edits,
        stored: crate::creds::has(&id),
        id,
    })
}

/// Validate an edited profile and persist the fields that differ from the
/// `.ini`. Returns the field names that are now overridden.
pub fn save_profile_edit(
    state: &AppState,
    id: String,
    edit: crate::overrides::Edit,
) -> std::result::Result<Vec<String>, String> {
    // Validate against the profile as imported: an edit that can't be applied
    // must not reach the sidecar, or the profile would carry a broken override.
    let mut imported = parse(&profile_path(state, &id))?;
    let base = crate::overrides::Edit::from_config(&imported.config);
    edit.apply_to(&mut imported.config)?;
    // Diff the *normalized* edit (trimmed, empty-vs-absent resolved) so that
    // e.g. a re-typed identical value doesn't register as an override.
    let normalized = crate::overrides::Edit::from_config(&imported.config);
    let (overrides, names) = crate::overrides::Overrides::diff(&base, &normalized);
    crate::overrides::save(&state.profile_dir, &id, &overrides)?;
    Ok(names)
}

/// Discard a profile's edits; it falls back to its `.ini` verbatim.
pub fn reset_profile_edit(state: &AppState, id: String) -> std::result::Result<(), String> {
    crate::overrides::clear(&state.profile_dir, &id)
}

/// The directory profiles are read from (shown in the UI, so the user knows
/// where their `.ini` files live).
pub fn profiles_dir(state: &AppState) -> String {
    state.profile_dir.display().to_string()
}

/// Import a profile file into the profile directory so it shows up in the
/// list. Validates that it parses (so junk is rejected), then copies it in
/// under a sanitized name, keeping the extension so the format stays evident
/// on disk. Returns the new profile id (its file stem).
///
/// A Sophos `.pro` is refused here on purpose: it holds no connection, and
/// storing it would put an entry in the list that can never be connected.
pub fn import_path(state: &AppState, src: &std::path::Path) -> std::result::Result<String, String> {
    // Accept the provisioning extension so the file gets the explanation from
    // `parse_text` rather than a flat "unsupported file type".
    let known = is_profile_extension(src)
        || src
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("pro"))
            .unwrap_or(false);
    if !known {
        return Err(format!(
            "only {} profiles can be imported",
            PROFILE_EXTENSIONS
                .iter()
                .map(|e| format!(".{e}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let text = std::fs::read_to_string(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    // Parse to reject files that aren't valid profiles in any format we read.
    parse_text(&text)?;

    let sanitize = |s: &str| {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
            .collect::<String>()
    };
    let stem = src
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize)
        .filter(|s| !s.is_empty())
        .ok_or("the file needs a name")?;
    let ext = src
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| sanitize(&e.to_ascii_lowercase()))
        .filter(|e| !e.is_empty())
        .ok_or("the file needs an extension")?;

    std::fs::create_dir_all(&state.profile_dir).map_err(|e| e.to_string())?;
    let dest = state.profile_dir.join(format!("{stem}.{ext}"));
    // Don't silently overwrite a different existing profile — including one in
    // another format, since a profile id is the stem alone and two files
    // sharing a stem would be one profile with two backing files.
    let taken = PROFILE_EXTENSIONS
        .iter()
        .map(|e| state.profile_dir.join(format!("{stem}.{e}")))
        .find(|p| p.exists() && std::fs::canonicalize(p).ok() != std::fs::canonicalize(src).ok());
    if taken.is_some() {
        return Err(format!("a profile named \"{stem}\" already exists"));
    }
    std::fs::write(&dest, text).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    Ok(stem)
}

/// Connect the profile identified by `id` to the gateway it names.
/// Remove an imported profile and everything that trails it: the `.ini`, its
/// override sidecar, and any PSK it left in the keychain. All three go, or the
/// leftovers would be silently adopted by the next profile imported under the
/// same name.
///
/// If the profile's tunnel is up it is torn down first — once the `.ini` is
/// gone nothing in the UI can name that connection, so it could not otherwise
/// be disconnected.
pub fn delete_profile(state: &AppState, id: String) -> std::result::Result<(), String> {
    check_id(&id)?;
    let path = profile_path(state, &id);

    // Best-effort: a profile that no longer parses can't tell us its connection
    // name, and a charon that isn't running can't be asked to disconnect. Losing
    // the tunnel teardown is not a reason to refuse the delete.
    if let Ok((imported, _)) = load(state, &id) {
        let name = vpn_core::swanctl::sanitize_name(&imported.config.name);
        let up = status(state)
            .map(|sas| sas.iter().any(|sa| sa.name == name))
            .unwrap_or(false);
        if up {
            if let Err(e) = disconnect(state, name) {
                eprintln!("disconnect before deleting {id} failed: {e}");
            }
        }
    }

    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("there is no profile named \"{id}\""))
        }
        Err(e) => return Err(format!("cannot delete {}: {e}", path.display())),
    }
    crate::overrides::clear(&state.profile_dir, &id)?;
    crate::creds::delete(&id)?;
    Ok(())
}

pub fn connect(
    state: &AppState,
    id: String,
) -> std::result::Result<vpn_control::ConnectOutcome, String> {
    let (mut imported, _) = load(state, &id)?;
    // Prefer a PSK saved in the OS keychain over the one parsed from the
    // (plaintext-on-disk) .ini, so saved credentials are what actually
    // authenticate the tunnel.
    if let Some(psk) = crate::creds::load(&id)? {
        imported.config.auth = vpn_core::AuthMethod::PresharedKey(psk);
    }
    let name = vpn_core::swanctl::sanitize_name(&imported.config.name);

    // charon's `initiate` is unconditional: called against a connection that is
    // already up, it negotiates a *second* CHILD_SA on the same IKE_SA rather
    // than refusing. They stack up (and only one gets torn down on disconnect),
    // so adopt the live SA instead of initiating over it. This happens whenever
    // a tunnel outlives the app — the SA belongs to charon, not to us.
    if let Some(existing) = established_sa(state, &name) {
        let mut outcome = vpn_control::ConnectOutcome {
            connected: true,
            error: None,
            log: vec![note_line(
                &name,
                2,
                format!(
                    "{name} is already established ({} → {}); adopting the existing SA",
                    existing.local_host, existing.remote_host
                ),
            )],
        };
        if imported.config.request_virtual_ip {
            wait_for_virtual_ip(state, &name, &mut outcome);
        }
        return Ok(outcome);
    }

    let mut outcome =
        vpn_control::connect_logged(&state.transport, &imported.config, &name).map_err(|e| e.to_string())?;

    // An established CHILD_SA does not mean the tunnel carries traffic yet: the
    // assigned virtual IP still has to land on an OS interface first.
    if outcome.connected && imported.config.request_virtual_ip {
        wait_for_virtual_ip(state, &name, &mut outcome);
    }

    // With the tunnel up, apply the profile's DNS so names on the remote
    // network resolve over the VPN. Failure here doesn't fail the connect —
    // the tunnel still carries traffic — it's just surfaced in the log.
    if outcome.connected && !imported.config.dns.is_empty() {
        apply_dns(state, &name, &imported.config.dns, &mut outcome);
    }
    Ok(outcome)
}

/// The live SA for `name`, if charon already has one carrying traffic — i.e. an
/// established IKE_SA with at least one installed CHILD_SA. A half-open SA
/// doesn't count: there's nothing to adopt, and `initiate` is the right call.
fn established_sa(state: &AppState, name: &str) -> Option<IkeSa> {
    status(state).ok()?.into_iter().find(|sa| {
        sa.name == name
            && sa.state == "ESTABLISHED"
            && sa.children.iter().any(|c| c.state == "INSTALLED")
    })
}

/// How long to wait for the virtual IP to become usable before giving up and
/// reporting the tunnel as up anyway (it is — just not yet sourceable).
const VIP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Of that budget, how long to wait for charon to even report an assigned
/// address. It arrives with the IKE_SA, so this is generous.
const VIP_ASSIGN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const VIP_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Block until the gateway-assigned virtual IP is actually usable as a source
/// address, so "established" means the tunnel really carries traffic.
///
/// charon reports the CHILD_SA up as soon as it is negotiated, but the OS still
/// has to install the virtual IP. On Windows a freshly added address spends a
/// moment in duplicate-address detection (`Tentative`), and — this is the part
/// that makes it look like a protocol bug — ICMP still flows from it while no
/// socket can *bind* to it. So ping works and every TCP connect fails, for
/// several seconds after the UI has already said "established".
///
/// Best-effort: a timeout is a warning, never a failed connect.
fn wait_for_virtual_ip(
    state: &AppState,
    name: &str,
    outcome: &mut vpn_control::ConnectOutcome,
) {
    let started = std::time::Instant::now();
    let Some(vip) = assigned_vip(state, name, started) else {
        note(outcome, name, 1, "no virtual IP was assigned; skipping the readiness wait".to_string());
        return;
    };
    while started.elapsed() < VIP_TIMEOUT {
        // Binding is the same operation a TCP connect performs, so it tests
        // exactly what fails while the address is Tentative — and it needs no
        // platform-specific API to ask.
        if std::net::UdpSocket::bind((vip, 0)).is_ok() {
            note(
                outcome,
                name,
                2,
                format!("virtual IP {vip} ready after {:.1}s", started.elapsed().as_secs_f32()),
            );
            return;
        }
        std::thread::sleep(VIP_POLL);
    }
    note(
        outcome,
        name,
        1,
        format!(
            "virtual IP {vip} was still not usable after {}s — connections over the tunnel may fail until it is",
            VIP_TIMEOUT.as_secs()
        ),
    );
}

/// The virtual IP charon assigned to this connection, once it reports one.
fn assigned_vip(state: &AppState, name: &str, started: std::time::Instant) -> Option<std::net::IpAddr> {
    while started.elapsed() < VIP_ASSIGN_TIMEOUT {
        if let Ok(sas) = status(state) {
            let vip = sas
                .iter()
                .find(|sa| sa.name == name)
                .and_then(|sa| sa.virtual_ips.first())
                .and_then(|v| v.parse::<std::net::IpAddr>().ok());
            if vip.is_some() {
                return vip;
            }
        }
        std::thread::sleep(VIP_POLL);
    }
    None
}

/// A log line attributed to this connection, in charon's own shape, so the UI
/// renders our findings exactly like the daemon's.
fn note_line(name: &str, level: i32, msg: String) -> vpn_control::LogLine {
    vpn_control::LogLine {
        group: "NET".to_string(),
        level,
        ikesa: Some(name.to_string()),
        msg,
    }
}

fn note(outcome: &mut vpn_control::ConnectOutcome, name: &str, level: i32, msg: String) {
    outcome.log.push(note_line(name, level, msg));
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
    let mut line = note_line(name, if bad { 1 } else { 2 }, msg);
    line.group = "DNS".to_string();
    outcome.log.push(line);
}

/// Copy a profile's PSK from its `.ini` into the OS keychain.
pub fn save_credentials(state: &AppState, id: String) -> std::result::Result<(), String> {
    let (imported, _) = load(state, &id)?;
    let vpn_core::AuthMethod::PresharedKey(psk) = &imported.config.auth;
    crate::creds::store(&id, psk)
}

/// Replace a profile's PSK with one the user typed. It goes straight to the OS
/// keychain — where [`connect`] prefers it over the `.ini`'s — so the new key is
/// never written to disk in plaintext, and the profile file stays untouched.
pub fn set_credentials(
    _state: &AppState,
    id: String,
    psk: String,
) -> std::result::Result<(), String> {
    if psk.is_empty() {
        return Err("the pre-shared key cannot be empty".to_string());
    }
    crate::creds::store(&id, &vpn_core::Secret::new(psk))
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
