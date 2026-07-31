//! Importer for Sophos Connect `.scx` profiles.
//!
//! Despite the extension these are plain JSON — Sophos Connect is built on
//! strongSwan, and the file is close to a serialised swanctl connection, which
//! makes the mapping onto [`ConnectionConfig`] unusually direct. Unusually
//! direct is not the same as unambiguous, though: the format is undocumented,
//! so anything the file does not state outright (the IKE version, which EAP
//! method backs the interactive round) is warned about rather than assumed
//! silently.
//!
//! SECURITY: `remote_auth.psk.secret` is a live pre-shared key. It goes
//! straight into [`Secret`] and must never be logged or written back out.

use crate::error::ImportError;
use crate::proposal;
use serde::Deserialize;
use vpn_core::import::Warnings;
use vpn_core::{
    AuthMethod, ConnectionConfig, DnsConfig, DpdConfig, IkeIdType, IkeVersion, ImportedProfile,
    Ipv4Net, Secret, UserAuth,
};

/// Hard cap on input size; a real `.scx` is a couple of kilobytes.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

/// Sophos's own default when the profile omits DPD.
const DEFAULT_DPD_DELAY: u32 = 30;

#[derive(Debug, Deserialize)]
pub struct Scx {
    #[serde(default)]
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    domain_suffix: String,
    /// Which Sophos platform wrote this: `xg` is SFOS (the firewall line).
    #[serde(default, rename = "type")]
    kind: String,
    /// The firewall pushes updates for a managed profile; we never fetch them.
    #[serde(default)]
    managed: bool,
    #[serde(default)]
    gateway: String,
    /// Virtual IP to request. `0.0.0.0` is "assign me one".
    #[serde(default)]
    vip: String,
    #[serde(default)]
    run_logon_script: bool,
    #[serde(default)]
    proposals: Vec<String>,
    /// Written as a number by SFOS 21 and as a padded string (`"60 "`) by
    /// SFOS 18.5, so it is read either way.
    #[serde(default, deserialize_with = "flexible_u32")]
    dpd_delay: Option<u32>,
    #[serde(default)]
    local_auth: LocalAuth,
    #[serde(default)]
    remote_auth: RemoteAuth,
    #[serde(default)]
    child: Child,
}

#[derive(Debug, Default, Deserialize)]
struct LocalAuth {
    #[serde(default)]
    psk: PskId,
    /// Present when the gateway demands a username/password round.
    xauth: Option<Xauth>,
    #[serde(default)]
    otp: bool,
}

#[derive(Debug, Default, Deserialize)]
struct Xauth {
    #[serde(default)]
    can_save: bool,
}

#[derive(Debug, Default, Deserialize)]
struct RemoteAuth {
    #[serde(default)]
    psk: RemotePsk,
}

#[derive(Debug, Default, Deserialize)]
struct PskId {
    #[serde(default)]
    id: String,
}

#[derive(Debug, Default, Deserialize)]
struct RemotePsk {
    #[serde(default)]
    id: String,
    /// The live pre-shared key.
    secret: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Child {
    #[serde(default)]
    proposals: Vec<String>,
    #[serde(default)]
    remote_ts: Vec<String>,
}

/// Read a number that different SFOS versions write differently: `60`, `"60"`
/// or `"60 "` all mean the same thing. A value that is neither is treated as
/// absent rather than failing the whole import — the field it guards has a
/// sane default, and one odd timer is no reason to reject a profile.
fn flexible_u32<'de, D>(de: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match serde::Deserialize::deserialize(de)? {
        serde_json::Value::Number(n) => n.as_u64().map(|v| v as u32),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    })
}

/// Does this look like an `.scx` rather than one of the other JSON formats?
/// A `.pro` is a JSON *array*; an `.scx` is an object with a gateway.
pub fn looks_like(input: &str) -> bool {
    serde_json::from_str::<Scx>(input)
        .map(|s| !s.gateway.trim().is_empty())
        .unwrap_or(false)
}

pub fn import(input: &str) -> Result<ImportedProfile, ImportError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(ImportError::TooLarge(MAX_INPUT_LEN));
    }
    let scx: Scx = serde_json::from_str(input)?;
    let mut warn = Warnings::new();

    if !scx.kind.is_empty() && !scx.kind.eq_ignore_ascii_case("xg") {
        warn.warn(format!(
            "profile type is {:?}, not the SFOS/XG firewall this importer was written against — \
             verify every setting before connecting",
            scx.kind
        ));
    }
    if scx.managed {
        warn.warn(
            "this is a managed profile: the firewall normally pushes updated settings to the \
             Sophos client, which we do not do — a changed gateway or key must be re-imported",
        );
    }
    if scx.run_logon_script {
        warn.warn(
            "the profile asks the client to run a logon script after connecting; we never execute \
             scripts from a profile, so it was ignored",
        );
    }

    let gateway = scx.gateway.trim().to_string();
    if gateway.is_empty() {
        return Err(ImportError::MissingField("gateway"));
    }
    validate_gateway(&gateway)?;

    let name = pick_name(&scx);

    let secret = scx
        .remote_auth
        .psk
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ImportError::Unsupported(
            "a profile without a pre-shared key (certificate authentication)".to_string(),
        ))?;

    if is_private(&gateway) {
        warn.warn(format!(
            "the profile dials {gateway}, a private address — it will only connect from inside \
             that network, or over another tunnel that reaches it"
        ));
    }

    // The gateway's own PSK identity; `%any` and `0.0.0.0` (the usual values)
    // mean it does not pin one, and there is nothing for us to carry.
    let remote_id = scx.remote_auth.psk.id.trim();
    if !remote_id.is_empty() && remote_id != "%any" && remote_id != "0.0.0.0" {
        warn.warn(format!(
            "the profile pins the gateway's identity to {remote_id:?}; we do not check the \
             responder's identity yet"
        ));
    }

    let (local_id, local_id_type) = local_identity(&scx.local_auth.psk.id, &mut warn);

    let ike_src = first_proposal(&scx.proposals, "proposals", &mut warn)?;
    let (ike, ike_prf) = proposal::parse(ike_src, "IKE proposal")?;
    let esp_src = first_proposal(&scx.child.proposals, "child.proposals", &mut warn)?;
    let (esp, _) = proposal::parse(esp_src, "ESP proposal")?;

    let mut remote_subnets = Vec::new();
    for ts in &scx.child.remote_ts {
        let net: Ipv4Net = ts.trim().parse().map_err(|_| ImportError::BadValue {
            field: "child.remote_ts",
            value: ts.clone(),
            why: "not an IPv4 network in CIDR form",
        })?;
        remote_subnets.push(net);
    }
    if remote_subnets.is_empty() {
        warn.warn(
            "the profile names no remote networks; the gateway decides what the tunnel carries",
        );
    }

    // A Sophos gateway hands out the virtual IP, the DNS servers and the split
    // domain over the IKE configuration payload rather than in the profile, so
    // `vip` is a request rather than an address.
    let request_virtual_ip = !scx.vip.trim().is_empty();
    if request_virtual_ip && scx.vip.trim() != "0.0.0.0" {
        warn.warn(format!(
            "the profile asks for the specific virtual IP {}; we request one from the gateway \
             instead",
            scx.vip.trim()
        ));
    }

    let domain = Some(scx.domain_suffix.trim())
        .filter(|d| !d.is_empty())
        .map(str::to_string);
    if domain.is_some() {
        warn.warn(
            "the profile scopes DNS to a domain, but its resolvers are assigned by the gateway \
             at connect time rather than named in the file — split-DNS is not applied for this \
             profile yet",
        );
    }

    let user_auth = scx.local_auth.xauth.as_ref().map(|x| {
        warn.warn(
            "the gateway requires a second, interactive authentication round; it will be \
             negotiated as EAP-MSCHAPv2 over IKEv2 (unconfirmed — verify on first connect) and \
             you will be asked for a username and password",
        );
        UserAuth {
            username: None,
            can_save: x.can_save,
            otp: scx.local_auth.otp,
        }
    });
    if let Some(ua) = &user_auth {
        if ua.otp {
            warn.warn(
                "the gateway expects a one-time password, so a saved password alone will not \
                 authenticate",
            );
        }
    }

    // Nothing in the file states the IKE version. Sophos Connect speaks IKEv2
    // to an SFOS firewall, and it is the only version the daemon we ship is
    // built with, so that is what we import — the .tgb path is where IKEv1
    // shows up explicitly.
    let config = ConnectionConfig {
        name,
        gateway,
        local_id,
        local_id_type,
        auth: AuthMethod::PresharedKey(Secret::new(secret.to_string())),
        ike_version: IkeVersion::V2,
        user_auth,
        ike_enc: ike.enc,
        ike_integ: ike.integ,
        ike_prf: ike.prf(ike_prf),
        ike_dh: ike.dh.ok_or(ImportError::UnknownAlgorithm {
            context: "IKE proposal",
            token: "<no Diffie-Hellman group>".to_string(),
        })?,
        esp_enc: esp.enc,
        esp_integ: esp.integ,
        pfs: esp.dh,
        remote_subnets,
        request_virtual_ip,
        compression: false,
        dpd: DpdConfig {
            delay_secs: scx.dpd_delay.unwrap_or(DEFAULT_DPD_DELAY),
            auto_reconnect: true,
        },
        dns: DnsConfig {
            servers: Vec::new(),
            domain,
        },
    };

    Ok(ImportedProfile {
        config,
        warnings: warn.into_vec(),
    })
}

fn pick_name(scx: &Scx) -> String {
    for candidate in [scx.display_name.trim(), scx.name.trim()] {
        if !candidate.is_empty() {
            return candidate.to_string();
        }
    }
    "Sophos VPN".to_string()
}

/// Take the first proposal and note the ones we drop: the model holds a single
/// algorithm set, while the file may offer the gateway a choice.
fn first_proposal<'a>(
    proposals: &'a [String],
    field: &'static str,
    warn: &mut Warnings,
) -> Result<&'a str, ImportError> {
    let first = proposals
        .iter()
        .map(|p| p.trim())
        .find(|p| !p.is_empty())
        .ok_or(ImportError::MissingField(field))?;
    if proposals.len() > 1 {
        warn.warn(format!(
            "{field} offers {} algorithm sets; only the first ({first}) is used",
            proposals.len()
        ));
    }
    Ok(first)
}

/// Work out the identity we present and, importantly, its IKE type — charon
/// otherwise infers the type from the string, which is how a bare token ends
/// up on the wire as an FQDN when the gateway expects something else.
fn local_identity(id: &str, warn: &mut Warnings) -> (Option<String>, Option<IkeIdType>) {
    let id = id.trim();
    // `0.0.0.0` is how these profiles spell "no identity pinned" — SFOS writes
    // it for both ends when the gateway matches on %any. Sending it literally
    // would present an IPv4 identity of 0.0.0.0, which no gateway expects, so
    // treat it as unset and let charon use the local address.
    if id.is_empty() || id == "%any" || id == "0.0.0.0" || id == "::" {
        return (None, None);
    }
    let kind = if id.parse::<std::net::Ipv4Addr>().is_ok() {
        IkeIdType::Ipv4
    } else if id.contains('@') {
        IkeIdType::Rfc822
    } else {
        warn.warn(format!(
            "the local identity {id:?} has no stated type; sending it as an FQDN (verify on first \
             connect)"
        ));
        IkeIdType::Fqdn
    };
    (Some(id.to_string()), Some(kind))
}

/// Is the gateway an address that only answers from inside its own network?
/// Shared with the `.tgb` importer's identical check.
fn is_private(gateway: &str) -> bool {
    gateway
        .parse::<std::net::Ipv4Addr>()
        .map(|a| a.is_private() || a.is_loopback() || a.is_link_local())
        .unwrap_or(false)
}

/// Same conservative charset the NCP importer enforces: the gateway string
/// reaches charon, so a hostile profile must not be able to smuggle anything
/// else through it.
fn validate_gateway(gw: &str) -> Result<(), ImportError> {
    let ok = gw.len() <= 255
        && gw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if ok {
        Ok(())
    } else {
        Err(ImportError::BadValue {
            field: "gateway",
            value: gw.to_string(),
            why: "contains characters that are not valid in a host name or address",
        })
    }
}
