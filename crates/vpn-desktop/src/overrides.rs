//! User edits to an imported profile, kept beside it as `<id>.override.json`.
//!
//! The `.ini` a user imports is treated as read-only source material: it is
//! re-parsed on every load (see [`backend::load`](crate::backend)), which is
//! what keeps the PSK off our own disk footprint. Editing a parameter therefore
//! can't mean "rewrite the .ini" — instead we store the changed fields in a
//! sidecar and replay them onto the freshly parsed [`ConnectionConfig`].
//!
//! Only fields that actually differ from the file are written, so re-importing
//! an updated `.ini` still picks up everything the user never touched, and
//! [`clear`] (the UI's "Reset to file") is just a delete.
//!
//! The PSK is deliberately not an overridable field: it lives in the OS
//! keychain (see [`creds`](crate::creds)), never in this file.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vpn_core::{
    ConnectionConfig, DhGroup, DnsConfig, EncAlg, IkeIdType, IkeVersion, IntegAlg, Ipv4Net, PrfAlg,
};

/// The editable view of a connection: every field the UI can change, as the
/// plain strings/bools it round-trips. `Edit` is what the UI reads and writes;
/// what lands on disk is the subset that differs from the parsed `.ini`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub name: String,
    pub gateway: String,
    /// `ikev1` or `ikev2`. Editable because the two Sophos exports for one
    /// gateway can disagree, and only the gateway settles it.
    pub ike_version: String,
    /// Whether the gateway asks for a username and password on top of the PSK
    /// (XAuth under IKEv1, EAP under IKEv2).
    ///
    /// Editable for the same reason: a `.tgb` that says `Xauth = 0` has been
    /// seen against a gateway that requires it — main mode then fails with
    /// AUTHENTICATION_FAILED, and nothing in the profile hints at the cause.
    pub user_auth: bool,
    /// Empty means "no local IKE identity" (charon derives one).
    pub local_id: String,
    /// One of [`IkeIdType::name`], or empty for "let charon infer".
    pub local_id_type: String,
    pub ike_enc: String,
    pub ike_integ: String,
    pub ike_prf: String,
    pub ike_dh: String,
    pub esp_enc: String,
    pub esp_integ: String,
    /// A DH group name, or empty for "PFS off".
    pub pfs: String,
    /// Remote traffic selectors in CIDR form.
    pub remote: Vec<String>,
    pub request_virtual_ip: bool,
    pub compression: bool,
    /// DNS servers used over the tunnel (IPv4 literals).
    pub dns: Vec<String>,
    /// Split-DNS suffix scoping those servers; empty for none.
    pub dns_domain: String,
    /// DPD probe interval in seconds; 0 disables probing.
    pub dpd_delay: u32,
    pub auto_reconnect: bool,
}

impl Edit {
    /// The current effective values of `config` — what the edit dialog opens on.
    pub fn from_config(config: &ConnectionConfig) -> Self {
        Edit {
            name: config.name.clone(),
            gateway: config.gateway.clone(),
            ike_version: config.ike_version.name().to_string(),
            user_auth: config.user_auth.is_some(),
            local_id: config.local_id.clone().unwrap_or_default(),
            local_id_type: config.local_id_type.map(|t| t.name().to_string()).unwrap_or_default(),
            ike_enc: config.ike_enc.swanctl_name().to_string(),
            ike_integ: config.ike_integ.swanctl_name().to_string(),
            ike_prf: config.ike_prf.swanctl_name().to_string(),
            ike_dh: config.ike_dh.swanctl_name().to_string(),
            esp_enc: config.esp_enc.swanctl_name().to_string(),
            esp_integ: config.esp_integ.swanctl_name().to_string(),
            pfs: config.pfs.map(|g| g.swanctl_name().to_string()).unwrap_or_default(),
            remote: config.remote_subnets.iter().map(|n| n.to_string()).collect(),
            request_virtual_ip: config.request_virtual_ip,
            compression: config.compression,
            dns: config.dns.servers.iter().map(|s| s.to_string()).collect(),
            dns_domain: config.dns.domain.clone().unwrap_or_default(),
            dpd_delay: config.dpd.delay_secs,
            auto_reconnect: config.dpd.auto_reconnect,
        }
    }

    /// Validate and apply onto `config`. Rejects anything charon would choke on
    /// (or worse, silently negotiate wrong), so a bad edit fails here rather
    /// than at IKE_AUTH.
    pub fn apply_to(&self, config: &mut ConnectionConfig) -> Result<(), String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("the connection needs a name".to_string());
        }
        let gateway = self.gateway.trim();
        if gateway.is_empty() {
            return Err("the connection needs a gateway".to_string());
        }
        // Same character set the importer enforces: this string reaches charon.
        if gateway.len() > 255
            || !gateway
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        {
            return Err(format!("gateway {gateway:?} contains invalid characters"));
        }

        let local_id_type = match self.local_id_type.trim() {
            "" => None,
            t => Some(IkeIdType::from_name(t).ok_or(format!("unknown IKE ID type {t:?}"))?),
        };

        let ike_version = IkeVersion::from_name(self.ike_version.trim())
            .ok_or_else(|| format!("unknown IKE version {:?}", self.ike_version))?;
        // Turning the round on keeps whatever the profile said about saving
        // and one-time codes; turning it off drops it entirely.
        let user_auth = match (self.user_auth, config.user_auth.take()) {
            (true, Some(existing)) => Some(existing),
            (true, None) => Some(vpn_core::UserAuth {
                username: None,
                can_save: true,
                otp: false,
            }),
            (false, _) => None,
        };

        let ike_enc = enc(&self.ike_enc)?;
        let ike_integ = integ(&self.ike_integ)?;
        let ike_prf = PrfAlg::from_swanctl_name(self.ike_prf.trim())
            .ok_or_else(|| format!("unknown PRF {:?}", self.ike_prf))?;
        let ike_dh = dh(&self.ike_dh)?;
        let esp_enc = enc(&self.esp_enc)?;
        let esp_integ = integ(&self.esp_integ)?;
        let pfs = match self.pfs.trim() {
            "" => None,
            g => Some(dh(g)?),
        };

        let mut remote = Vec::new();
        for r in self.remote.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            remote.push(r.parse::<Ipv4Net>()?);
        }

        let mut servers = Vec::new();
        for d in self.dns.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            servers.push(
                d.parse::<std::net::Ipv4Addr>()
                    .map_err(|_| format!("{d:?} is not an IPv4 DNS server"))?,
            );
        }
        let domain = self.dns_domain.trim();
        // A split-DNS suffix becomes an NRPT rule namespace; keep it to what the
        // broker's own validation will accept.
        if !domain.is_empty()
            && !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(format!("DNS domain {domain:?} contains invalid characters"));
        }
        if !domain.is_empty() && servers.is_empty() {
            return Err("a split-DNS domain needs at least one DNS server".to_string());
        }

        config.name = name.to_string();
        config.gateway = gateway.to_string();
        config.ike_version = ike_version;
        config.user_auth = user_auth;
        config.local_id = Some(self.local_id.trim().to_string()).filter(|s| !s.is_empty());
        config.local_id_type = local_id_type;
        config.ike_enc = ike_enc;
        config.ike_integ = ike_integ;
        config.ike_prf = ike_prf;
        config.ike_dh = ike_dh;
        config.esp_enc = esp_enc;
        config.esp_integ = esp_integ;
        config.pfs = pfs;
        config.remote_subnets = remote;
        config.request_virtual_ip = self.request_virtual_ip;
        config.compression = self.compression;
        config.dns = DnsConfig {
            servers,
            domain: Some(domain.to_string()).filter(|s| !s.is_empty()),
        };
        config.dpd.delay_secs = self.dpd_delay;
        config.dpd.auto_reconnect = self.auto_reconnect;
        Ok(())
    }
}

fn enc(name: &str) -> Result<EncAlg, String> {
    EncAlg::from_swanctl_name(name.trim()).ok_or(format!("unknown encryption algorithm {name:?}"))
}
fn integ(name: &str) -> Result<IntegAlg, String> {
    IntegAlg::from_swanctl_name(name.trim()).ok_or(format!("unknown integrity algorithm {name:?}"))
}
fn dh(name: &str) -> Result<DhGroup, String> {
    DhGroup::from_swanctl_name(name.trim()).ok_or(format!("unknown DH group {name:?}"))
}

/// What actually lands on disk: only the fields the user changed. Serialized
/// with `skip_serializing_if`, so an untouched field is absent (and a later
/// `.ini` re-import still governs it).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ike_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_auth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_id_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ike_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ike_integ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ike_prf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ike_dh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esp_enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esp_integ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pfs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_virtual_ip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpd_delay: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_reconnect: Option<bool>,
}

macro_rules! diff_fields {
    ($base:expr, $edited:expr, $out:expr, $names:expr, $($f:ident),+ $(,)?) => {
        $(
            if $base.$f != $edited.$f {
                $out.$f = Some($edited.$f.clone());
                $names.push(stringify!($f).to_string());
            }
        )+
    };
}

impl Overrides {
    /// The fields of `edited` that differ from `base` (the values parsed from
    /// the `.ini`), plus their names for the UI's "modified" markers.
    pub fn diff(base: &Edit, edited: &Edit) -> (Self, Vec<String>) {
        let mut out = Overrides::default();
        let mut names = Vec::new();
        diff_fields!(
            base, edited, out, names, name, gateway, ike_version, user_auth, local_id, local_id_type,
            ike_enc, ike_integ,
            ike_prf, ike_dh, esp_enc, esp_integ, pfs, remote, request_virtual_ip, compression, dns,
            dns_domain, dpd_delay, auto_reconnect,
        );
        (out, names)
    }

    /// Overlay these overrides onto the values parsed from the `.ini`.
    pub fn overlay(&self, base: &Edit) -> (Edit, Vec<String>) {
        let mut e = base.clone();
        let mut names = Vec::new();
        macro_rules! set {
            ($($f:ident),+ $(,)?) => {
                $(
                    if let Some(v) = self.$f.clone() {
                        if v != e.$f {
                            names.push(stringify!($f).to_string());
                        }
                        e.$f = v;
                    }
                )+
            };
        }
        set!(
            name, gateway, ike_version, user_auth, local_id, local_id_type, ike_enc, ike_integ,
            ike_prf, ike_dh, esp_enc,
            esp_integ, pfs, remote, request_virtual_ip, compression, dns, dns_domain, dpd_delay,
            auto_reconnect,
        );
        (e, names)
    }

    /// No field is overridden. Leans on `skip_serializing_if`, so it can't drift
    /// out of sync with what `save` would write.
    pub fn is_empty(&self) -> bool {
        matches!(serde_json::to_value(self), Ok(serde_json::Value::Object(o)) if o.is_empty())
    }
}

fn override_path(profile_dir: &Path, id: &str) -> PathBuf {
    profile_dir.join(format!("{id}.override.json"))
}

/// Read a profile's saved overrides. A sidecar that is missing — or corrupt,
/// which must not take the profile down with it — reads as "no overrides".
pub fn load(profile_dir: &Path, id: &str) -> Overrides {
    std::fs::read_to_string(override_path(profile_dir, id))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Persist `overrides` for `id`, or remove the sidecar when nothing differs
/// from the `.ini` any more.
pub fn save(profile_dir: &Path, id: &str, overrides: &Overrides) -> Result<(), String> {
    let path = override_path(profile_dir, id);
    if overrides.is_empty() {
        return clear(profile_dir, id);
    }
    let text = serde_json::to_string_pretty(overrides).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Drop all overrides for `id` — the profile falls back to its `.ini` verbatim.
pub fn clear(profile_dir: &Path, id: &str) -> Result<(), String> {
    match std::fs::remove_file(override_path(profile_dir, id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot reset {id}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_edit() -> Edit {
        Edit {
            name: "conn".to_string(),
            gateway: "vpn.example.test".to_string(),
            ike_version: "ikev2".to_string(),
            user_auth: false,
            local_id: "user@example.test".to_string(),
            local_id_type: "rfc822".to_string(),
            ike_enc: "aes256".to_string(),
            ike_integ: "sha256".to_string(),
            ike_prf: "prfsha256".to_string(),
            ike_dh: "modp3072".to_string(),
            esp_enc: "aes256".to_string(),
            esp_integ: "sha256".to_string(),
            pfs: "modp3072".to_string(),
            remote: vec!["10.0.0.0/24".to_string()],
            request_virtual_ip: true,
            compression: false,
            dns: vec![],
            dns_domain: String::new(),
            dpd_delay: 30,
            auto_reconnect: true,
        }
    }

    #[test]
    fn diff_records_only_changed_fields() {
        let base = base_edit();
        let mut edited = base.clone();
        edited.gateway = "other.example.test".to_string();
        edited.pfs = String::new();

        let (o, names) = Overrides::diff(&base, &edited);
        assert_eq!(o.gateway.as_deref(), Some("other.example.test"));
        assert_eq!(o.pfs.as_deref(), Some(""));
        assert!(o.ike_enc.is_none());
        assert_eq!(names, vec!["gateway", "pfs"]);
    }

    #[test]
    fn overlay_is_the_inverse_of_diff() {
        let base = base_edit();
        let mut edited = base.clone();
        edited.ike_dh = "ecp384".to_string();
        edited.dns = vec!["10.0.0.53".to_string()];
        edited.dns_domain = "corp.example.test".to_string();

        let (o, _) = Overrides::diff(&base, &edited);
        let (back, names) = o.overlay(&base);
        assert_eq!(back, edited);
        assert_eq!(names, vec!["ike_dh", "dns", "dns_domain"]);
    }

    #[test]
    fn identical_edit_writes_no_overrides() {
        let base = base_edit();
        let (o, names) = Overrides::diff(&base, &base.clone());
        assert!(o.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn round_trip_through_the_sidecar_file() {
        let dir = std::env::temp_dir().join(format!("vpn_ovr_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = base_edit();
        let mut edited = base.clone();
        edited.gateway = "moved.example.test".to_string();

        let (o, _) = Overrides::diff(&base, &edited);
        save(&dir, "p", &o).unwrap();
        assert_eq!(load(&dir, "p").gateway.as_deref(), Some("moved.example.test"));

        // Saving an empty set removes the sidecar (back to the .ini verbatim).
        save(&dir, "p", &Overrides::default()).unwrap();
        assert!(load(&dir, "p").is_empty());
        assert!(!override_path(&dir, "p").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_values_are_rejected_before_they_reach_charon() {
        let mut cfg = ncp_profile::import_profile(FIXTURE).unwrap().config;

        let mut e = Edit::from_config(&cfg);
        e.gateway = "vpn.example.test/../etc".to_string();
        assert!(e.apply_to(&mut cfg).is_err());

        let mut e = Edit::from_config(&cfg);
        e.remote = vec!["10.0.0.0/33".to_string()];
        assert!(e.apply_to(&mut cfg).is_err());

        let mut e = Edit::from_config(&cfg);
        e.ike_dh = "modp8192".to_string();
        assert!(e.apply_to(&mut cfg).is_err());

        let mut e = Edit::from_config(&cfg);
        e.name = "  ".to_string();
        assert!(e.apply_to(&mut cfg).is_err());

        // A domain with no servers has nothing to scope — an NRPT rule pointing
        // at no resolver would black-hole the suffix.
        let mut e = Edit::from_config(&cfg);
        e.dns = vec![];
        e.dns_domain = "corp.example.test".to_string();
        assert!(e.apply_to(&mut cfg).is_err());
    }

    #[test]
    fn a_valid_edit_reaches_the_config() {
        let mut cfg = ncp_profile::import_profile(FIXTURE).unwrap().config;
        let mut e = Edit::from_config(&cfg);
        e.gateway = "new-gw.example.test".to_string();
        e.pfs = String::new();
        e.remote = vec!["10.9.0.0/16".to_string(), "192.168.5.5".to_string()];
        e.dns = vec!["10.9.0.53".to_string()];
        e.dns_domain = "corp.example.test".to_string();
        e.dpd_delay = 0;
        e.apply_to(&mut cfg).unwrap();

        assert_eq!(cfg.gateway, "new-gw.example.test");
        assert_eq!(cfg.pfs, None);
        assert_eq!(cfg.esp_proposal(), "aes256-sha256");
        assert_eq!(
            cfg.remote_subnets.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            ["10.9.0.0/16", "192.168.5.5/32"]
        );
        assert_eq!(cfg.dns.domain.as_deref(), Some("corp.example.test"));
        assert_eq!(cfg.dpd.delay_secs, 0);
    }

    /// The portal `.mobileconfig` imports with no remote subnets on purpose
    /// (a synthesised 0.0.0.0/0 would capture the default route). The user
    /// supplies the networks in the edit dialog; this is that path — the edit
    /// turns an unconnectable profile into a usable one.
    #[test]
    fn a_subnetless_profile_gains_its_networks_by_editing() {
        let mut cfg = ncp_profile::import_profile(FIXTURE).unwrap().config;
        cfg.remote_subnets.clear();

        let mut e = Edit::from_config(&cfg);
        assert!(e.remote.is_empty(), "starts with no networks");
        e.remote = vec!["172.21.108.0/24".to_string(), "10.98.49.0/24".to_string()];
        e.apply_to(&mut cfg).unwrap();

        assert_eq!(
            cfg.remote_subnets.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            ["172.21.108.0/24", "10.98.49.0/24"]
        );
    }

    /// Full tunnel is the explicit opt-in: typing 0.0.0.0/0 is accepted and is
    /// how a user deliberately routes everything (the importer never does it).
    #[test]
    fn full_tunnel_is_an_explicit_edit() {
        let mut cfg = ncp_profile::import_profile(FIXTURE).unwrap().config;
        let mut e = Edit::from_config(&cfg);
        e.remote = vec!["0.0.0.0/0".to_string()];
        e.apply_to(&mut cfg).unwrap();
        assert_eq!(cfg.remote_subnets.len(), 1);
        assert_eq!(cfg.remote_subnets[0].to_string(), "0.0.0.0/0");
    }

    /// The same redacted export `ncp-profile` pins its code table against, so
    /// these tests edit a config that really came out of the importer.
    const FIXTURE: &str = include_str!("../../ncp-profile/tests/fixtures/efa_mdt_42.redacted.ini");
}
