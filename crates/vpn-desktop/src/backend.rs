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
    /// What an `itmvpn://` link brought in, until the user has dealt with it.
    /// Held in memory rather than written out, because a link can come from any
    /// web page — see [`stage_link_import`].
    pending_link: std::sync::Arc<std::sync::Mutex<Staged>>,
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
            pending_link: Default::default(),
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

#[derive(Debug, Clone, Serialize)]
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
    /// Whether that login is saved in the keychain (so connect won't prompt).
    pub user_stored: bool,
    /// The username saved for it, to prefill the prompt when re-entering a
    /// password. Not a secret — the password never leaves the keychain.
    pub user_name: Option<String>,
    /// Which datapath this profile uses: `ipsec` (charon) or `ssl` (OpenVPN via
    /// the broker). The UI adapts labels and skips IPsec-only editing for SSL.
    pub kind: String,
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
        user_stored: config.user_auth.is_some() && crate::creds::has_user(id),
        user_name: config
            .user_auth
            .as_ref()
            .and_then(|_| crate::creds::load_user(id).ok().flatten())
            .map(|c| c.username),
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
        kind: "ipsec".to_string(),
    }
}

/// Summarize an SSL VPN (OpenVPN) profile for the list. It carries none of the
/// IPsec knobs — routes, DNS, ciphers and the second-factor login are all
/// settled by the gateway at connect time — so the IPsec-shaped fields are
/// filled with what actually describes an OpenVPN tunnel.
fn summarize_ssl(id: &str, file: &str, text: &str) -> ProfileSummary {
    let meta = crate::ssl::parse_meta(text);
    let gateway = if meta.port.is_empty() {
        meta.gateway.clone()
    } else {
        format!("{}:{}", meta.gateway, meta.port)
    };
    ProfileSummary {
        id: id.to_string(),
        name: id.to_string(),
        gateway,
        local_id: None,
        remote: Vec::new(),
        ike: "OpenVPN / TLS".to_string(),
        esp: "negotiated (AES-GCM)".to_string(),
        pfs: None,
        auth: "certificate".to_string(),
        virtual_ip_requested: true,
        warnings: vec![WarnItem {
            level: "info".to_string(),
            text: "Routes and DNS are pushed by the gateway on connect".to_string(),
            note: "an SSL VPN profile needs no subnets set by hand".to_string(),
        }],
        stored: false,
        dns: Vec::new(),
        dns_domain: None,
        edits: Vec::new(),
        file: file.to_string(),
        format: format_label(file).to_string(),
        ike_version: "-".to_string(),
        user_auth: meta.needs_user.then(|| "Username & password".to_string()),
        user_stored: meta.needs_user && crate::creds::has_user(id),
        user_name: meta
            .needs_user
            .then(|| crate::creds::load_user(id).ok().flatten().map(|c| c.username))
            .flatten(),
        kind: "ssl".to_string(),
    }
}

/// File extensions a profile may have, in the order [`profile_path`] resolves
/// them. Ids stay bare file stems, so an override sidecar or a keychain entry
/// written before Sophos profiles existed still addresses the same profile.
const PROFILE_EXTENSIONS: [&str; 5] = ["ini", "scx", "tgb", "mobileconfig", "ovpn"];

/// Human-readable origin of a profile, from its extension. The importers pick
/// by content, but the extension is what survived the copy into the profile
/// directory and is what the user sees in the folder.
fn format_label(file: &str) -> &'static str {
    match file.rsplit('.').next().unwrap_or_default() {
        "scx" => "Sophos Connect",
        "tgb" => "Sophos (legacy)",
        "mobileconfig" => "Sophos (portal)",
        "ovpn" => "Sophos SSL VPN",
        _ => "NCP",
    }
}

/// Is this profile file an SSL VPN (OpenVPN) config, driven by the broker rather
/// than by charon? Dispatch through the app hinges on this.
fn is_ssl_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("ovpn"))
        .unwrap_or(false)
}

/// Whether the profile with this id is an SSL VPN profile.
fn is_ssl_profile(state: &AppState, id: &str) -> bool {
    is_ssl_path(&profile_path(state, id))
}

/// The connection name a profile is keyed by, matching the front-end's own
/// `sanitize` (non `[A-Za-z0-9_-]` → `_`). Used for the SSL path, whose name has
/// to line up with what the GUI computes from the profile name and passes back
/// to `disconnect`.
fn conn_name(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    if out.is_empty() {
        "conn".to_string()
    } else {
        out
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
            "this is a Sophos provisioning file, not a profile — sign in at {url}, open the VPN \
             section, and download the IPsec configuration (the portal serves it as a \
             .mobileconfig). Import that file instead. Note the portal profile lists no networks, \
             so add the subnet(s) you need to reach in the profile's settings before connecting"
        ),
        None => "this is a Sophos provisioning file, not a profile — it names a user portal to \
                 download the real profile (a .mobileconfig) from"
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
        if is_ssl_path(&path) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                out.push(summarize_ssl(id, &file, &text));
            }
        } else if let Ok((imported, edits)) = load(state, id) {
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
    if is_ssl_profile(state, &id) {
        return Err("SSL VPN profiles have no editable parameters — the gateway pushes routes \
                    and DNS on connect".to_string());
    }
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
    if is_ssl_profile(state, &id) {
        return Err("SSL VPN profiles have no editable parameters".to_string());
    }
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
    // Validate so junk is rejected. An `.ovpn` is not an IPsec profile — check
    // it against OpenVPN's own markers rather than the IPsec importers.
    if is_ssl_path(src) {
        if !crate::ssl::looks_like_ovpn(&text) {
            return Err("this .ovpn file is not a valid OpenVPN configuration".to_string());
        }
    } else {
        parse_text(&text)?;
    }

    let stem = src
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("the file needs a name")?;
    let ext = src
        .extension()
        .and_then(|e| e.to_str())
        .ok_or("the file needs an extension")?;
    save_imported_text(state, stem, ext, &text)
}

/// Sanitize the name and extension used for a stem/ext pair. A profile id is the
/// stem alone, so the character set is kept tight — it becomes a file name.
fn sanitize_stem(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

/// Write already-validated profile text into the profile directory as
/// `<stem>.<ext>`, refusing to clobber a different existing profile. Shared by
/// file import and portal download so both land a profile the same way, with
/// the same id (the sanitized stem) the rest of the app addresses it by.
fn save_imported_text(
    state: &AppState,
    raw_stem: &str,
    raw_ext: &str,
    text: &str,
) -> std::result::Result<String, String> {
    let stem = sanitize_stem(raw_stem);
    let stem = stem.trim_matches('.');
    if stem.is_empty() {
        return Err("the profile needs a name".to_string());
    }
    let ext = sanitize_stem(&raw_ext.to_ascii_lowercase());
    if ext.is_empty() {
        return Err("the profile needs a file type".to_string());
    }

    std::fs::create_dir_all(&state.profile_dir).map_err(|e| e.to_string())?;
    let dest = state.profile_dir.join(format!("{stem}.{ext}"));
    // Don't silently overwrite a different existing profile — including one in
    // another format, since a profile id is the stem alone and two files
    // sharing a stem would be one profile with two backing files.
    let taken = PROFILE_EXTENSIONS
        .iter()
        .map(|e| state.profile_dir.join(format!("{stem}.{e}")))
        .find(|p| p.exists() && std::fs::canonicalize(p).ok() != std::fs::canonicalize(&dest).ok());
    if taken.is_some() {
        return Err(format!("a profile named \"{stem}\" already exists"));
    }
    std::fs::write(&dest, text).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    Ok(stem.to_string())
}

/// Sign in to the user portal a `.pro` points at, download the profile it
/// serves, and import it — the automated version of "download it from the portal
/// yourself and import that file". Returns the new profile's id.
///
/// Prefers the portal's SSL VPN (`.ovpn`) over its IPsec (`.mobileconfig`): the
/// SSL profile is self-contained (the gateway pushes routes and DNS), while the
/// portal's IPsec profile carries no subnets and can't connect until they are
/// added by hand. Falls back to IPsec when the portal offers no SSL VPN.
pub fn import_from_portal(
    state: &AppState,
    portal_url: String,
    username: String,
    password: String,
    name: String,
) -> std::result::Result<String, String> {
    let profile = crate::portal::download_preferred(&portal_url, &username, &password)?;
    // Keep the extension matching the format so it is obvious in the profile
    // folder and re-parses the same way on load (`.ovpn` → SSL, `.mobileconfig`
    // → IPsec).
    let stem = if name.trim().is_empty() { "Sophos VPN" } else { name.trim() };
    save_imported_text(state, stem, profile.ext, &profile.text)
}

/// Classify a file the user picked for import: a provisioning `.pro` becomes a
/// portal to sign in to (handled by [`import_from_portal`]), anything else is
/// imported in place. Lets the GUI offer the sign-in flow instead of a dead-end
/// error for a `.pro`.
pub fn classify_import(
    state: &AppState,
    src: &std::path::Path,
) -> std::result::Result<ImportOutcome, String> {
    let text = std::fs::read_to_string(src)
        .map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    if let Some(target) = crate::portal::target(&text) {
        return Ok(ImportOutcome::Provisioning {
            url: target.url,
            name: target.name,
            otp: target.otp,
        });
    }
    import_path(state, src).map(|id| ImportOutcome::Profile { id })
}

/// The result of picking a file to import: a profile landed, or a `.pro` that
/// points at a portal the GUI should offer to sign in to.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ImportOutcome {
    Profile { id: String },
    Provisioning { url: String, name: String, otp: bool },
}

/// A profile carried in by an `itmvpn://` link: decoded and parsed, but not yet
/// on disk. It lives in [`AppState::pending_link`] until the user confirms.
struct PendingImport {
    /// Identifies this staging, so a confirmation can only import the profile
    /// the dialog actually described — see [`ImportPreview::token`].
    token: u64,
    stem: String,
    ext: String,
    text: String,
}

/// Everything an `itmvpn://` link left behind for the UI to act on.
#[derive(Default)]
struct Staged {
    /// A request the window has not been told about yet. A link that *launched*
    /// the app is staged before the web view has attached its event listeners,
    /// so it would miss an emitted event; it collects the request from here
    /// instead, once, on load ([`take_link_request`]).
    undelivered: Option<LinkRequest>,
    /// The profile itself, held until it is confirmed or declined.
    profile: Option<PendingImport>,
}

/// What a deep link turned out to be asking for.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum LinkRequest {
    /// A profile is staged; the UI shows this and calls [`commit_link_import`]
    /// if the user agrees.
    Confirm(ImportPreview),
    /// The link carried a `.pro`, which names a portal rather than holding a
    /// connection — the same sign-in the GUI runs for a dropped `.pro`.
    Provisioning { url: String, name: String, otp: bool },
    /// The link was malformed or carried something that is not a profile. Kept
    /// as a request of its own so a link that launched the app can still explain
    /// itself once the window is up, instead of the launch looking like nothing
    /// happened.
    Failed { message: String },
}

/// What the confirmation dialog shows about a staged profile. Enough for a user
/// to recognise a profile they were expecting — and to notice one they were not,
/// which is the whole point of confirming: an `itmvpn://` link can come from any
/// page, not only from the config site.
#[derive(Debug, Clone, Serialize)]
pub struct ImportPreview {
    /// Handed back to [`commit_link_import`] on confirm. A second link staged
    /// while this dialog is open replaces what is staged, and without the token
    /// the confirmation would import that newer profile while showing this one.
    pub token: u64,
    /// The id (file stem) the profile would land under.
    pub id: String,
    pub name: String,
    pub gateway: String,
    /// The networks the profile would route over the tunnel.
    pub remote: Vec<String>,
    pub dns: Vec<String>,
    /// Human-readable format, as in the profile list.
    pub format: String,
    pub auth: String,
    pub warnings: Vec<WarnItem>,
    /// What this would do to a profile that is already installed under the same
    /// name: `none`, `replace` (same file, overwritten in place — the id keeps
    /// its stored credentials), or `refuse` (one of that name exists in another
    /// format, which [`save_imported_text`] will not clobber). Said up front,
    /// because "import" quietly meaning "replace" is exactly what a link from a
    /// page nobody vetted should not get to do unannounced.
    pub collision: String,
}

/// Decode-and-check a profile a deep link brought in, and park it for
/// confirmation. Nothing is written to disk here: the link is untrusted input,
/// so the file only lands once the user has seen what is in it and agreed
/// ([`commit_link_import`]).
///
/// Validation is the same as for a file import — junk is rejected here rather
/// than after the confirmation, so a broken link fails with a reason instead of
/// an empty dialog.
pub fn stage_link_import(
    state: &AppState,
    link: crate::deeplink::LinkImport,
) -> std::result::Result<LinkRequest, String> {
    if let Some(target) = crate::portal::target(&link.text) {
        return Ok(LinkRequest::Provisioning {
            url: target.url,
            name: target.name,
            otp: target.otp,
        });
    }

    // `format_label` reads the extension off a file name, which a link has no
    // real one of; name the format from the extension it claims.
    let format = format_label(&format!("profile.{}", link.ext)).to_string();
    // Two different names: `stem` is what the file (and therefore the profile id)
    // is called, which the link may set; `display` is the name the profile
    // carries inside itself, which is what the profile list shows. Titling the
    // dialog with the stem would name something the user never sees again.
    let (stem, display, preview) = if link.ext == "ovpn" {
        // An `.ovpn` is not an IPsec profile — check it against OpenVPN's own
        // markers, exactly as `import_path` does for a picked file.
        if !crate::ssl::looks_like_ovpn(&link.text) {
            return Err("that link does not contain a valid OpenVPN configuration".to_string());
        }
        let meta = crate::ssl::parse_meta(&link.text);
        let name = link.name.clone().unwrap_or_else(|| "Sophos SSL VPN".to_string());
        let gateway = if meta.port.is_empty() {
            meta.gateway.clone()
        } else {
            format!("{}:{}", meta.gateway, meta.port)
        };
        let auth = if meta.needs_user {
            "Certificate + username and password".to_string()
        } else {
            "Certificate".to_string()
        };
        let warnings = vec![WarnItem {
            level: "info".to_string(),
            text: "Routes and DNS are pushed by the gateway on connect".to_string(),
            note: String::new(),
        }];
        // An SSL profile carries no name of its own — the list shows its id — so
        // both names are the same here.
        (
            name.clone(),
            name,
            (gateway, Vec::new(), Vec::new(), auth, warnings),
        )
    } else {
        let imported = parse_text(&link.text)?;
        let config = &imported.config;
        let stem = link.name.clone().unwrap_or_else(|| config.name.clone());
        let auth = match config.user_auth.as_ref() {
            Some(_) => match config.ike_version {
                vpn_core::IkeVersion::V1 => "Pre-shared key + XAuth login".to_string(),
                vpn_core::IkeVersion::V2 => "Pre-shared key + EAP login".to_string(),
            },
            None => "Pre-shared key".to_string(),
        };
        (
            stem,
            config.name.clone(),
            (
                config.gateway.clone(),
                config.remote_subnets.iter().map(|n| n.to_string()).collect(),
                config.dns.servers.iter().map(|s| s.to_string()).collect(),
                auth,
                imported
                    .warnings
                    .iter()
                    .map(|w| to_warn_item(&w.to_string()))
                    .collect(),
            ),
        )
    };

    let (gateway, remote, dns, auth, warnings) = preview;
    let id = sanitize_stem(&stem).trim_matches('.').to_string();
    if id.is_empty() {
        return Err("the profile in that link has no usable name".to_string());
    }
    let dest = state.profile_dir.join(format!("{id}.{}", link.ext));
    let installed: Vec<PathBuf> = PROFILE_EXTENSIONS
        .iter()
        .map(|e| state.profile_dir.join(format!("{id}.{e}")))
        .filter(|p| p.exists())
        .collect();
    let collision = match installed.as_slice() {
        [] => "none",
        [only] if *only == dest => "replace",
        _ => "refuse",
    }
    .to_string();

    // Wraps only after 2^64 links; a repeat would have to coincide with a
    // dialog left open across all of them.
    static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let token = NEXT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    pending_slot(state).profile = Some(PendingImport {
        token,
        stem,
        ext: link.ext,
        text: link.text,
    });

    Ok(LinkRequest::Confirm(ImportPreview {
        token,
        id,
        name: display,
        gateway,
        remote,
        dns,
        format,
        auth,
        warnings,
        collision,
    }))
}

/// Park a request for the window to collect when it is ready, instead of
/// emitting it at a window that may not be listening yet (see [`Staged`]).
pub fn defer_link_request(state: &AppState, request: LinkRequest) {
    pending_slot(state).undelivered = Some(request);
}

/// Hand the window whatever a link left for it, once.
pub fn take_link_request(state: &AppState) -> Option<LinkRequest> {
    pending_slot(state).undelivered.take()
}

/// Write the staged profile out — the user said yes. `token` is the one the
/// confirmed preview carried, so a link that arrived while the dialog was open
/// cannot slip its own profile past a confirmation meant for another.
/// Returns the new id.
pub fn commit_link_import(state: &AppState, token: u64) -> std::result::Result<String, String> {
    let mut slot = pending_slot(state);
    match slot.profile.as_ref() {
        Some(p) if p.token == token => {}
        Some(_) => {
            return Err(
                "another link came in while this was open — open the link you want again"
                    .to_string(),
            )
        }
        None => return Err("that import is no longer waiting — open the link again".to_string()),
    }
    let pending = slot.profile.take().expect("checked just above");
    drop(slot);
    save_imported_text(state, &pending.stem, &pending.ext, &pending.text)
}

/// Drop the staged profile — the user said no, or closed the dialog.
pub fn cancel_link_import(state: &AppState) {
    *pending_slot(state) = Staged::default();
}

/// The staging slot, surviving a panic in whoever held the lock last: a poisoned
/// mutex here would otherwise make every later deep link fail until restart, and
/// what it guards is a single replaceable profile.
fn pending_slot(state: &AppState) -> std::sync::MutexGuard<'_, Staged> {
    state
        .pending_link
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Remove an imported profile and everything that trails it: the profile file,
/// its override sidecar, and both keychain entries it may have left (the PSK
/// and the XAuth/EAP login). All of it goes, or the leftovers would be
/// silently adopted by the next profile imported under the same name.
///
/// If the profile's tunnel is up it is torn down first — once the `.ini` is
/// gone nothing in the UI can name that connection, so it could not otherwise
/// be disconnected.
pub fn delete_profile(state: &AppState, id: String) -> std::result::Result<(), String> {
    check_id(&id)?;
    let path = profile_path(state, &id);

    // An SSL profile's tunnel lives in the broker, not charon — tear it down
    // there before the file that names it is gone. (The IPsec teardown below is
    // skipped for SSL, since it can't be parsed as an IPsec profile.)
    if is_ssl_path(&path) {
        if let Ok(Some(s)) = crate::ssl::status() {
            if s.name == conn_name(&id) {
                if let Err(e) = crate::ssl::disconnect() {
                    eprintln!("SSL disconnect before deleting {id} failed: {e}");
                }
            }
        }
    }

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
    // The XAuth/EAP login is a second keychain entry and would otherwise be
    // inherited by the next profile imported under the same name.
    crate::creds::delete_user(&id)?;
    Ok(())
}

/// A username and password typed into the connect prompt, and whether the
/// user asked to keep them. Only reaches [`connect`]; never stored on the
/// profile.
#[derive(Debug, Default, serde::Deserialize)]
pub struct UserLogin {
    pub username: String,
    pub password: String,
    /// Save to the OS keychain so the next connect doesn't prompt.
    #[serde(default)]
    pub save: bool,
}

pub fn connect(
    state: &AppState,
    id: String,
    login: Option<UserLogin>,
) -> std::result::Result<vpn_control::ConnectOutcome, String> {
    if is_ssl_profile(state, &id) {
        return ssl_connect(state, &id, login);
    }
    let (mut imported, _) = load(state, &id)?;
    // Prefer a PSK saved in the OS keychain over the one parsed from the
    // (plaintext-on-disk) profile file, so saved credentials are what actually
    // authenticate the tunnel.
    if let Some(psk) = crate::creds::load(&id)? {
        imported.config.auth = vpn_core::AuthMethod::PresharedKey(psk);
    }

    // Second authentication round: the gateway wants a person's login on top
    // of the PSK. Take what was just typed, else what was saved; the username
    // goes into the config (charon sends it as the XAuth/EAP identity) while
    // the password is passed separately and never stored on the profile.
    let user_password = resolve_user_login(&id, &mut imported.config, login)?;
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

    let mut outcome = vpn_control::connect_logged(
        &state.transport,
        &imported.config,
        &name,
        user_password.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    // An established CHILD_SA does not mean the tunnel carries traffic yet: the
    // assigned virtual IP still has to land on an OS interface first.
    if outcome.connected && imported.config.request_virtual_ip {
        wait_for_virtual_ip(state, &name, &mut outcome);
    }

    // With the tunnel up, apply DNS so names on the remote network resolve over
    // the VPN. Two sources, merged: the profile's own servers, and any the
    // gateway pushed over mode config (captured by charon's resolve plugin) —
    // so a portal profile that carries no DNS of its own still resolves
    // internal names. Failure here doesn't fail the connect; it's just logged.
    if outcome.connected {
        let mut dns = imported.config.dns.clone();
        for server in crate::dns::pushed_servers() {
            if !dns.servers.contains(&server) {
                dns.servers.push(server);
            }
        }
        if !dns.servers.is_empty() {
            apply_dns(state, &name, &dns, &mut outcome);
        }
    }
    Ok(outcome)
}

/// Bring up an SSL VPN (OpenVPN) profile via the broker. The `.ovpn` (which
/// carries a private key) is read and handed to the broker, which runs openvpn
/// as LocalSystem — the privilege the adapter and routes need. The gateway asks
/// for a username and password (`auth-user-pass`); they come from the connect
/// prompt or the keychain, exactly as the IPsec second factor does.
fn ssl_connect(
    state: &AppState,
    id: &str,
    login: Option<UserLogin>,
) -> std::result::Result<vpn_control::ConnectOutcome, String> {
    let path = profile_path(state, id);
    let config = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let name = conn_name(id);

    // Resolve the username/password: what was typed, else what was saved.
    let (username, password) = match login {
        Some(l) => {
            let username = l.username.trim().to_string();
            if username.is_empty() {
                return Err("the username cannot be empty".to_string());
            }
            if l.password.is_empty() {
                return Err("the password cannot be empty".to_string());
            }
            if l.save {
                crate::creds::store_user(
                    id,
                    &crate::creds::UserCreds {
                        username: username.clone(),
                        password: vpn_core::Secret::new(l.password.clone()),
                    },
                )?;
            }
            (username, l.password)
        }
        None => {
            let saved = crate::creds::load_user(id)?
                .ok_or("this SSL VPN profile needs a username and password")?;
            (saved.username, saved.password.expose().to_string())
        }
    };

    match crate::ssl::connect(&name, &config, &username, &password) {
        Ok(ip) => {
            let msg = if ip.is_empty() {
                "SSL VPN connected".to_string()
            } else {
                format!("SSL VPN connected; assigned IP {ip}. Routes and DNS applied from the gateway push.")
            };
            Ok(vpn_control::ConnectOutcome {
                connected: true,
                error: None,
                log: vec![note_line(&name, 2, msg)],
            })
        }
        Err(e) => {
            // Short reason in the banner; openvpn's own output as its own log
            // lines in the panel, rather than one wall-of-text error.
            let mut log = vec![note_line(&name, 0, format!("SSL VPN connect failed: {}", e.reason))];
            for raw in e.log.lines() {
                let line = strip_ovpn_timestamp(raw.trim());
                if !line.is_empty() {
                    log.push(ovpn_log_line(&name, line));
                }
            }
            Ok(vpn_control::ConnectOutcome {
                connected: false,
                error: Some(e.reason),
                log,
            })
        }
    }
}

/// One openvpn output line as a log entry for the panel. Tagged `OVP` so it
/// reads as coming from the OpenVPN engine rather than charon; the UI colours
/// the message by wording, as it does charon's.
fn ovpn_log_line(name: &str, msg: &str) -> vpn_control::LogLine {
    vpn_control::LogLine {
        group: "OVP".to_string(),
        level: 1,
        ikesa: Some(name.to_string()),
        msg: msg.to_string(),
    }
}

/// Drop openvpn's own leading `YYYY-MM-DD HH:MM:SS ` timestamp: the log panel
/// stamps every line itself, so keeping openvpn's would double it up.
fn strip_ovpn_timestamp(line: &str) -> &str {
    let bytes = line.as_bytes();
    // "2026-08-10 15:49:14 " — date, space, time, space.
    if bytes.len() > 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b' '
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b' '
        && bytes[..19].iter().all(|&b| b.is_ascii_digit() || b == b'-' || b == b' ' || b == b':')
    {
        line[20..].trim_start()
    } else {
        line
    }
}

/// Settle the XAuth/EAP login for a connect, writing the username into the
/// config and returning the password for the caller to hand to charon.
///
/// Returns `None` for a profile that needs no second round — including when a
/// login was passed anyway, so a stale prompt can never bolt user auth onto a
/// profile whose gateway doesn't ask for it.
fn resolve_user_login(
    id: &str,
    config: &mut vpn_core::ConnectionConfig,
    login: Option<UserLogin>,
) -> std::result::Result<Option<vpn_core::Secret>, String> {
    let Some(user_auth) = config.user_auth.as_mut() else {
        return Ok(None);
    };

    let (username, password) = match login {
        Some(l) => {
            let username = l.username.trim().to_string();
            if username.is_empty() {
                return Err("the username cannot be empty".to_string());
            }
            if l.password.is_empty() {
                return Err("the password cannot be empty".to_string());
            }
            // Honour the profile: a gateway that says its credentials must not
            // be kept (typically because it expects a one-time code) doesn't
            // get them written to the keychain whatever the checkbox said.
            if l.save && user_auth.can_save && !user_auth.otp {
                crate::creds::store_user(
                    id,
                    &crate::creds::UserCreds {
                        username: username.clone(),
                        password: vpn_core::Secret::new(l.password.clone()),
                    },
                )?;
            }
            (username, vpn_core::Secret::new(l.password))
        }
        None => {
            let saved = crate::creds::load_user(id)?.ok_or_else(|| {
                "this profile's gateway asks for a username and password".to_string()
            })?;
            (saved.username, saved.password)
        }
    };

    user_auth.username = Some(username);
    Ok(Some(password))
}

/// Whether a profile still needs to be asked for a login before it can
/// connect: its gateway wants one and nothing usable is saved.
pub fn needs_user_login(state: &AppState, id: &str) -> bool {
    if is_ssl_profile(state, id) {
        // A Sophos SSL VPN profile authenticates with a certificate plus a
        // username/password (`auth-user-pass`); prompt unless one is saved.
        let needs = std::fs::read_to_string(profile_path(state, id))
            .map(|t| crate::ssl::parse_meta(&t).needs_user)
            .unwrap_or(true);
        return needs && !crate::creds::has_user(id);
    }
    load(state, id)
        .map(|(imported, _)| {
            imported.config.user_auth.is_some() && !crate::creds::has_user(id)
        })
        .unwrap_or(false)
}

/// Forget a profile's saved XAuth/EAP login. The PSK entry is separate and
/// stays put.
pub fn forget_user_login(_state: &AppState, id: String) -> std::result::Result<(), String> {
    crate::creds::delete_user(&id)
}

/// Save a login without connecting. The GUI stores credentials as a
/// side-effect of a successful prompt; this is the same store on its own, for
/// the headless harness.
pub fn set_user_login(
    _state: &AppState,
    id: String,
    username: String,
    password: String,
) -> std::result::Result<(), String> {
    if username.trim().is_empty() {
        return Err("the username cannot be empty".to_string());
    }
    if password.is_empty() {
        return Err("the password cannot be empty".to_string());
    }
    crate::creds::store_user(
        &id,
        &crate::creds::UserCreds {
            username: username.trim().to_string(),
            password: vpn_core::Secret::new(password),
        },
    )
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
    // If this name is the live SSL tunnel, tear it down through the broker; the
    // broker also drops the OpenVPN routes and DNS it installed.
    if let Ok(Some(s)) = crate::ssl::status() {
        if s.name == name {
            return crate::ssl::disconnect();
        }
    }
    // Undo any DNS we applied for this connection first (best-effort — a stale
    // resolver override is worse than a failed revert log).
    if let Err(e) = crate::dns::revert(&name) {
        eprintln!("dns revert for {name} failed: {e}");
    }
    vpn_control::disconnect(&state.transport, &name).map_err(|e| e.to_string())
}

/// Live connections across both datapaths: charon's IKE SAs plus, if one is up,
/// the broker's SSL VPN tunnel rendered as a synthetic SA so the UI shows and
/// can tear it down the same way.
pub fn status(state: &AppState) -> std::result::Result<Vec<IkeSa>, String> {
    let ssl = crate::ssl::status().ok().flatten();
    let mut sas = match vpn_control::status(&state.transport) {
        Ok(sas) => sas,
        // charon may be down while an SSL tunnel is up (SSL needs no charon):
        // don't report the backend as unreachable in that case.
        Err(e) => {
            if ssl.is_some() {
                Vec::new()
            } else {
                return Err(e.to_string());
            }
        }
    };
    if let Some(s) = ssl {
        sas.push(synth_ssl_sa(&s));
    }
    Ok(sas)
}

/// Render the broker's SSL tunnel as an `IkeSa` so the IPsec-shaped UI can key
/// off it (match by name, show "established", offer disconnect). The byte
/// counters and hosts charon would fill are not available for OpenVPN, so they
/// are left at their zero/empty defaults.
fn synth_ssl_sa(s: &crate::ssl::SslStatus) -> IkeSa {
    IkeSa {
        name: s.name.clone(),
        state: "ESTABLISHED".to_string(),
        local_host: String::new(),
        remote_host: String::new(),
        virtual_ips: if s.ip.is_empty() { Vec::new() } else { vec![s.ip.clone()] },
        children: vec![vpn_control::ChildSa {
            name: s.name.clone(),
            state: "INSTALLED".to_string(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            local_ts: if s.ip.is_empty() { Vec::new() } else { vec![format!("{}/32", s.ip)] },
            remote_ts: Vec::new(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_openvpn_timestamp() {
        assert_eq!(
            strip_ovpn_timestamp("2026-08-10 15:49:15 AUTH: Received control message: AUTH_FAILED"),
            "AUTH: Received control message: AUTH_FAILED"
        );
    }

    #[test]
    fn leaves_untimestamped_lines_alone() {
        assert_eq!(strip_ovpn_timestamp("VERIFY OK: depth=0"), "VERIFY OK: depth=0");
        assert_eq!(strip_ovpn_timestamp(""), "");
        // A short line the length check must not index past.
        assert_eq!(strip_ovpn_timestamp("done"), "done");
        // Looks date-ish but isn't the full stamp — left as-is, no panic.
        assert_eq!(strip_ovpn_timestamp("2026-08-10 partial"), "2026-08-10 partial");
    }

    /// A throwaway state whose profile directory is empty and per-test.
    fn scratch_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!("vpn_link_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch profile dir");
        AppState {
            profile_dir: dir,
            transport: Transport::Tcp("127.0.0.1:0".to_string()),
            pending_link: Default::default(),
        }
    }

    /// Minimal NCP profile the importer accepts — no real key, no real gateway.
    const SAMPLE: &str = "[PROFILE1]\n\
                          Name=Link Test\n\
                          Gateway=vpn.example.test\n\
                          Secret=\"not-a-real-key\"\n\
                          IkeIdType=3\n\
                          IkeIdStr=user@example.test\n\
                          ExchMode=34\n\
                          IKEv2Auth=2\n\
                          IkeDhGroup=14\n\
                          PFS=14\n\
                          IKEv2Policy=P\n\
                          IPSEC-Policy=P\n\
                          Network1=10.0.0.0\n\
                          SubMask1=255.255.255.0\n\
                          [IKEV2POLICY1]\n\
                          Ikev2Name=P\nIkev2Crypt=6\nIkev2PRF=5\nIkev2IntAlgo=12\n\
                          [IPSECPOLICY1]\n\
                          IPSecName=P\nIpsecCrypt=6\nIpsecAuth=5\n";

    fn sample_link(ext: &str, name: Option<&str>) -> crate::deeplink::LinkImport {
        crate::deeplink::LinkImport {
            name: name.map(str::to_string),
            ext: ext.to_string(),
            text: SAMPLE.to_string(),
        }
    }

    /// The point of staging: a link describes a profile without writing one.
    #[test]
    fn a_staged_link_reaches_disk_only_once_confirmed() {
        let state = scratch_state("confirm");
        let request = stage_link_import(&state, sample_link("ini", Some("Kanzlei"))).expect("stages");
        let LinkRequest::Confirm(preview) = request else {
            panic!("expected a profile to confirm");
        };
        // The link names the file; the profile names itself. Both are shown, so
        // the dialog's title matches what the profile list will call it.
        assert_eq!(preview.id, "Kanzlei");
        assert_eq!(preview.name, "Link Test");
        assert_eq!(preview.gateway, "vpn.example.test");
        assert_eq!(preview.collision, "none");
        assert_eq!(preview.remote, vec!["10.0.0.0/24"]);
        assert!(
            !state.profile_dir.join("Kanzlei.ini").exists(),
            "staging must not write the profile out"
        );

        assert_eq!(commit_link_import(&state, preview.token).as_deref(), Ok("Kanzlei"));
        assert!(state.profile_dir.join("Kanzlei.ini").exists());
        // The staged copy is spent: a second confirm has nothing to import.
        assert!(commit_link_import(&state, preview.token).is_err());
        let _ = std::fs::remove_dir_all(&state.profile_dir);
    }

    /// Declining must leave nothing behind for a later dialog to import.
    #[test]
    fn declining_drops_the_staged_profile() {
        let state = scratch_state("cancel");
        let request = stage_link_import(&state, sample_link("ini", Some("Kanzlei"))).expect("stages");
        let LinkRequest::Confirm(preview) = request else { panic!("expected a profile") };
        cancel_link_import(&state);
        assert!(commit_link_import(&state, preview.token).is_err());
        assert!(!state.profile_dir.join("Kanzlei.ini").exists());
        let _ = std::fs::remove_dir_all(&state.profile_dir);
    }

    /// A link arriving while the dialog is open replaces what is staged, so the
    /// confirmation must not import the newcomer in the shown profile's place.
    #[test]
    fn confirming_imports_the_profile_that_was_shown() {
        let state = scratch_state("token");
        let first = stage_link_import(&state, sample_link("ini", Some("Shown"))).expect("stages");
        let LinkRequest::Confirm(shown) = first else { panic!("expected a profile") };
        // A second link lands while the first dialog is still open.
        let second = stage_link_import(&state, sample_link("ini", Some("Sneaky"))).expect("stages");
        let LinkRequest::Confirm(newer) = second else { panic!("expected a profile") };

        assert!(commit_link_import(&state, shown.token).is_err(), "stale confirmation");
        assert!(!state.profile_dir.join("Sneaky.ini").exists());
        assert!(!state.profile_dir.join("Shown.ini").exists());
        // The newer one is still confirmable on its own terms.
        assert_eq!(commit_link_import(&state, newer.token).as_deref(), Ok("Sneaky"));
        let _ = std::fs::remove_dir_all(&state.profile_dir);
    }

    /// Landing on top of an installed profile is announced before the user
    /// commits — replacing one in place, and being refused across formats.
    #[test]
    fn a_collision_with_an_installed_profile_is_reported_up_front() {
        let state = scratch_state("collide");
        let first = stage_link_import(&state, sample_link("ini", Some("Kanzlei"))).expect("stages");
        let LinkRequest::Confirm(first) = first else { panic!("expected a profile") };
        commit_link_import(&state, first.token).expect("imports");

        let same = stage_link_import(&state, sample_link("ini", Some("Kanzlei"))).expect("stages");
        let LinkRequest::Confirm(preview) = same else { panic!("expected a profile") };
        assert_eq!(preview.collision, "replace");
        assert!(
            commit_link_import(&state, preview.token).is_ok(),
            "same file is overwritten in place"
        );

        let other = stage_link_import(&state, sample_link("scx", Some("Kanzlei"))).expect("stages");
        let LinkRequest::Confirm(preview) = other else { panic!("expected a profile") };
        assert_eq!(preview.collision, "refuse");
        assert!(
            commit_link_import(&state, preview.token).is_err(),
            "a second format under the same id must not land"
        );
        let _ = std::fs::remove_dir_all(&state.profile_dir);
    }

    /// A link that launched the app is parked, then collected exactly once.
    #[test]
    fn a_deferred_request_is_delivered_once() {
        let state = scratch_state("defer");
        assert!(take_link_request(&state).is_none());
        defer_link_request(
            &state,
            LinkRequest::Failed { message: "nope".to_string() },
        );
        assert!(matches!(
            take_link_request(&state),
            Some(LinkRequest::Failed { .. })
        ));
        assert!(take_link_request(&state).is_none());
        let _ = std::fs::remove_dir_all(&state.profile_dir);
    }

    /// A `.pro` names a portal instead of carrying a connection, so it must not
    /// be staged as an importable profile.
    #[test]
    fn a_provisioning_file_becomes_a_portal_sign_in() {
        let state = scratch_state("pro");
        let link = crate::deeplink::LinkImport {
            name: Some("Portal".to_string()),
            ext: "pro".to_string(),
            text: "[{\"display_name\":\"Example VPN\",\"gateway\":\"portal.example.test\"}]"
                .to_string(),
        };
        match stage_link_import(&state, link) {
            Ok(LinkRequest::Provisioning { url, .. }) => {
                assert!(url.contains("portal.example.test"), "{url}")
            }
            other => panic!("expected a portal sign-in, got {other:?}"),
        }
        assert!(commit_link_import(&state, 1).is_err(), "nothing to import");
        let _ = std::fs::remove_dir_all(&state.profile_dir);
    }
}
