//! Map a parsed NCP ini document onto the internal [`ConnectionConfig`].
//!
//! Policy: anything safety-critical (auth method, algorithms, DH groups)
//! with an unknown code is a hard error — failing to connect is safe,
//! silently negotiating the wrong thing is not. Known-but-unconfirmed codes
//! import fine but produce warnings the UI must show.

use crate::codes::{self, Confidence, Ikev2AuthMethod};
use crate::parser::{self, Document, ParseError, Section};
use std::net::Ipv4Addr;
use thiserror::Error;
use vpn_core::{AuthMethod, ConnectionConfig, Ipv4Net, Secret};

#[derive(Debug, Error)]
pub enum ImportError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("no [PROFILE...] section found")]
    NoProfileSection,
    #[error("[{section}] is missing required field {field}")]
    MissingField {
        section: String,
        field: &'static str,
    },
    #[error("{field}={value}: not a number")]
    NotANumber { field: &'static str, value: String },
    #[error("{field}={value}: invalid IPv4 address")]
    BadAddress { field: String, value: String },
    #[error("Network{index}/SubMask{index}: non-contiguous netmask")]
    BadNetmask { index: u32 },
    #[error("gateway contains invalid characters: {0:?}")]
    BadGateway(String),
    #[error("referenced policy section not found: {kind} named {name:?}")]
    PolicyNotFound { kind: &'static str, name: String },
    #[error("{field}={code}: unknown code — refusing to guess a {what}")]
    UnknownCode {
        field: &'static str,
        code: u32,
        what: &'static str,
    },
    #[error("profile is not IKEv2 (ExchMode={0}); only IKEv2 is supported")]
    NotIkev2(u32),
    #[error("unsupported auth method (only PSK is implemented)")]
    UnsupportedAuth,
}

/// A non-fatal finding the UI must surface before first connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportWarning(pub String);

impl std::fmt::Display for ImportWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub struct ImportedProfile {
    pub config: ConnectionConfig,
    pub warnings: Vec<ImportWarning>,
}

struct Ctx {
    warnings: Vec<ImportWarning>,
}

impl Ctx {
    fn warn(&mut self, msg: String) {
        self.warnings.push(ImportWarning(msg));
    }

    /// Record a warning when a mapping is not high-confidence.
    fn note_confidence(&mut self, field: &str, code: u32, meaning: &str, c: Confidence) {
        match c {
            Confidence::High => {}
            Confidence::Medium => self.warn(format!(
                "{field}={code} interpreted as {meaning} (unconfirmed mapping — verify on first connect)"
            )),
            Confidence::Low => self.warn(format!(
                "{field}={code} interpreted as {meaning} (LOW-confidence guess — confirm before use)"
            )),
        }
    }
}

fn required<'a>(section: &'a Section, field: &'static str) -> Result<&'a str, ImportError> {
    section.get(field).ok_or_else(|| ImportError::MissingField {
        section: section.name.clone(),
        field,
    })
}

fn parse_u32(field: &'static str, value: &str) -> Result<u32, ImportError> {
    value.trim().parse().map_err(|_| ImportError::NotANumber {
        field,
        value: value.to_string(),
    })
}

fn parse_ipv4(field: &str, value: &str) -> Result<Ipv4Addr, ImportError> {
    value.trim().parse().map_err(|_| ImportError::BadAddress {
        field: field.to_string(),
        value: value.to_string(),
    })
}

fn validate_gateway(gw: &str) -> Result<(), ImportError> {
    let ok = !gw.is_empty()
        && gw.len() <= 255
        && gw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if ok {
        Ok(())
    } else {
        Err(ImportError::BadGateway(gw.to_string()))
    }
}

/// Find the policy section (`[IKEV2POLICYn]` / `[IPSECPOLICYn]`) whose name
/// field matches the profile's reference.
fn find_policy<'a>(
    doc: &'a Document,
    section_prefix: &'static str,
    name_field: &str,
    wanted: &str,
) -> Option<&'a Section> {
    doc.sections_with_prefix(section_prefix)
        .find(|s| s.get(name_field).is_some_and(|n| n == wanted))
}

/// Cross-check an interpreted algorithm against the human-readable policy
/// name (e.g. `WIZ-AES256-SHA256`) — a cheap corroboration for the code maps.
fn corroborate(ctx: &mut Ctx, policy_name: &str, token: &str, matches: bool) {
    if policy_name.to_ascii_uppercase().contains(token) && !matches {
        ctx.warn(format!(
            "policy name {policy_name:?} mentions {token} but the numeric codes mapped to a different algorithm — check the code tables"
        ));
    }
}

pub fn import_profile(input: &str) -> Result<ImportedProfile, ImportError> {
    let doc = parser::parse(input)?;
    let mut ctx = Ctx {
        warnings: Vec::new(),
    };

    let profile = doc
        .sections_with_prefix("PROFILE")
        .next()
        .ok_or(ImportError::NoProfileSection)?;

    let name = required(profile, "Name")?.to_string();
    let gateway = required(profile, "Gateway")?.to_string();
    validate_gateway(&gateway)?;

    // --- IKE version -----------------------------------------------------
    let exch_mode = parse_u32("ExchMode", required(profile, "ExchMode")?)?;
    match codes::exch_mode_is_ikev2(exch_mode) {
        Some(m) => ctx.note_confidence("ExchMode", exch_mode, "IKEv2", m.confidence),
        None => return Err(ImportError::NotIkev2(exch_mode)),
    }

    // --- Authentication --------------------------------------------------
    let auth_code = parse_u32("IKEv2Auth", required(profile, "IKEv2Auth")?)?;
    let auth = match codes::ikev2_auth(auth_code) {
        Some(m) => {
            ctx.note_confidence("IKEv2Auth", auth_code, "pre-shared key", m.confidence);
            match m.value {
                Ikev2AuthMethod::PresharedKey => {
                    let secret = required(profile, "Secret")?;
                    AuthMethod::PresharedKey(Secret::new(secret.to_string()))
                }
            }
        }
        None => {
            return Err(ImportError::UnknownCode {
                field: "IKEv2Auth",
                code: auth_code,
                what: "authentication method",
            })
        }
    };

    // --- Identity ----------------------------------------------------------
    // The type matters: strongSwan infers the ID type from the string unless we
    // force it, and a bare token like `efa_mdt_42` infers as FQDN while the
    // gateway expects RFC822 (NCP's IkeIdType=3) — a mismatch the peer silently
    // drops at IKE_AUTH. So we carry the declared type through to the emitter.
    let local_id = profile.get("IkeIdStr").map(str::to_string);
    let mut local_id_type = None;
    if let Some(id_type_str) = profile.get("IkeIdType") {
        let code = parse_u32("IkeIdType", id_type_str)?;
        match codes::ike_id_type(code) {
            Some(m) => {
                ctx.note_confidence("IkeIdType", code, &format!("{:?}", m.value), m.confidence);
                local_id_type = Some(match m.value {
                    codes::IkeIdType::Ipv4Addr => vpn_core::IkeIdType::Ipv4,
                    codes::IkeIdType::Fqdn => vpn_core::IkeIdType::Fqdn,
                    codes::IkeIdType::UserFqdn => vpn_core::IkeIdType::Rfc822,
                    codes::IkeIdType::KeyId => vpn_core::IkeIdType::KeyId,
                });
            }
            None => ctx.warn(format!(
                "IkeIdType={code} is unknown; passing IkeIdStr through as-is"
            )),
        }
    }

    // --- IKE proposal (from the referenced [IKEV2POLICYn]) ----------------
    let ike_policy_name = required(profile, "IKEv2Policy")?;
    let ike_policy = find_policy(&doc, "IKEV2POLICY", "Ikev2Name", ike_policy_name)
        .ok_or_else(|| ImportError::PolicyNotFound {
            kind: "IKEv2Policy",
            name: ike_policy_name.to_string(),
        })?;

    let ike_enc_code = parse_u32("Ikev2Crypt", required(ike_policy, "Ikev2Crypt")?)?;
    let ike_enc = codes::enc_alg(ike_enc_code).ok_or(ImportError::UnknownCode {
        field: "Ikev2Crypt",
        code: ike_enc_code,
        what: "encryption algorithm",
    })?;
    ctx.note_confidence(
        "Ikev2Crypt",
        ike_enc_code,
        ike_enc.value.swanctl_name(),
        ike_enc.confidence,
    );

    let prf_code = parse_u32("Ikev2PRF", required(ike_policy, "Ikev2PRF")?)?;
    let ike_prf = codes::prf_alg(prf_code).ok_or(ImportError::UnknownCode {
        field: "Ikev2PRF",
        code: prf_code,
        what: "PRF algorithm",
    })?;
    ctx.note_confidence(
        "Ikev2PRF",
        prf_code,
        ike_prf.value.swanctl_name(),
        ike_prf.confidence,
    );

    let ike_int_code = parse_u32("Ikev2IntAlgo", required(ike_policy, "Ikev2IntAlgo")?)?;
    let ike_integ = codes::ike_integ_alg(ike_int_code).ok_or(ImportError::UnknownCode {
        field: "Ikev2IntAlgo",
        code: ike_int_code,
        what: "integrity algorithm",
    })?;
    ctx.note_confidence(
        "Ikev2IntAlgo",
        ike_int_code,
        ike_integ.value.swanctl_name(),
        ike_integ.confidence,
    );

    let dh_code = parse_u32("IkeDhGroup", required(profile, "IkeDhGroup")?)?;
    let ike_dh = codes::dh_group(dh_code).ok_or(ImportError::UnknownCode {
        field: "IkeDhGroup",
        code: dh_code,
        what: "DH group",
    })?;
    ctx.note_confidence(
        "IkeDhGroup",
        dh_code,
        ike_dh.value.swanctl_name(),
        ike_dh.confidence,
    );

    corroborate(&mut ctx, ike_policy_name, "AES256", ike_enc.value == vpn_core::EncAlg::Aes256);
    corroborate(&mut ctx, ike_policy_name, "SHA256", ike_integ.value == vpn_core::IntegAlg::Sha256);

    // --- ESP proposal (from the referenced [IPSECPOLICYn]) ----------------
    let esp_policy_name = required(profile, "IPSEC-Policy")?;
    let esp_policy = find_policy(&doc, "IPSECPOLICY", "IPSecName", esp_policy_name)
        .ok_or_else(|| ImportError::PolicyNotFound {
            kind: "IPSEC-Policy",
            name: esp_policy_name.to_string(),
        })?;

    let esp_enc_code = parse_u32("IpsecCrypt", required(esp_policy, "IpsecCrypt")?)?;
    let esp_enc = codes::enc_alg(esp_enc_code).ok_or(ImportError::UnknownCode {
        field: "IpsecCrypt",
        code: esp_enc_code,
        what: "encryption algorithm",
    })?;
    ctx.note_confidence(
        "IpsecCrypt",
        esp_enc_code,
        esp_enc.value.swanctl_name(),
        esp_enc.confidence,
    );

    let esp_auth_code = parse_u32("IpsecAuth", required(esp_policy, "IpsecAuth")?)?;
    let esp_integ = codes::esp_integ_alg(esp_auth_code).ok_or(ImportError::UnknownCode {
        field: "IpsecAuth",
        code: esp_auth_code,
        what: "integrity algorithm",
    })?;
    ctx.note_confidence(
        "IpsecAuth",
        esp_auth_code,
        esp_integ.value.swanctl_name(),
        esp_integ.confidence,
    );

    corroborate(&mut ctx, esp_policy_name, "AES256", esp_enc.value == vpn_core::EncAlg::Aes256);
    corroborate(&mut ctx, esp_policy_name, "SHA256", esp_integ.value == vpn_core::IntegAlg::Sha256);

    // --- PFS ---------------------------------------------------------------
    let pfs_code = parse_u32("PFS", required(profile, "PFS")?)?;
    let pfs = if pfs_code == 0 {
        None
    } else {
        let g = codes::dh_group(pfs_code).ok_or(ImportError::UnknownCode {
            field: "PFS",
            code: pfs_code,
            what: "DH group",
        })?;
        ctx.note_confidence("PFS", pfs_code, g.value.swanctl_name(), g.confidence);
        Some(g.value)
    };

    // --- Traffic selectors: Network1/SubMask1, Network2/... ---------------
    let mut remote_subnets = Vec::new();
    for i in 1u32.. {
        let net_key = format!("Network{i}");
        let mask_key = format!("SubMask{i}");
        let Some(net) = profile.get(&net_key) else { break };
        let Some(mask) = profile.get(&mask_key) else {
            return Err(ImportError::MissingField {
                section: profile.name.clone(),
                field: "SubMaskN (matching NetworkN)",
            });
        };
        let addr = parse_ipv4(&net_key, net)?;
        let mask = parse_ipv4(&mask_key, mask)?;
        let subnet = Ipv4Net::from_addr_and_mask(addr, mask)
            .ok_or(ImportError::BadNetmask { index: i })?;
        remote_subnets.push(subnet);
    }
    if remote_subnets.is_empty() {
        ctx.warn(
            "no Network1/SubMask1 found — no traffic selector; tunnel would carry no traffic"
                .to_string(),
        );
    }

    // --- Virtual IP --------------------------------------------------------
    let assign_code = parse_u32("IpAddrAssign", profile.get("IpAddrAssign").unwrap_or("0"))?;
    let request_virtual_ip = match codes::ip_addr_assign_is_server(assign_code) {
        Some(m) => {
            ctx.note_confidence(
                "IpAddrAssign",
                assign_code,
                "server-assigned virtual IP",
                m.confidence,
            );
            m.value
        }
        None => {
            ctx.warn(format!(
                "IpAddrAssign={assign_code} is unknown; requesting a server-assigned virtual IP anyway"
            ));
            true
        }
    };

    let compression = profile.get("UseComp").map(str::trim) == Some("1");

    // --- DNS ---------------------------------------------------------------
    // DNS1..DNS4 are the resolvers to use over the tunnel; DomainName, when
    // present, scopes them to that suffix (split-DNS). A 0.0.0.0/empty slot
    // means "unset".
    let mut dns_servers = Vec::new();
    for key in ["DNS1", "DNS2", "DNS3", "DNS4"] {
        let Some(raw) = profile.get(key) else { continue };
        let raw = raw.trim();
        if raw.is_empty() || raw == "0.0.0.0" {
            continue;
        }
        match raw.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => dns_servers.push(ip),
            Err(_) => ctx.warn(format!("{key}={raw} is not a valid IPv4 DNS server and was ignored")),
        }
    }
    let dns_domain = profile
        .get("DomainName")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let dns = vpn_core::DnsConfig {
        servers: dns_servers,
        domain: dns_domain,
    };

    // --- Fields we deliberately ignore for now ----------------------------
    for field in ["ConnMedia", "ConnMode", "SeamRoaming", "PriVoIP"] {
        if let Some(v) = profile.get(field) {
            ctx.warn(format!(
                "{field}={v} is not interpreted yet and was ignored"
            ));
        }
    }
    // NCP profiles are rejected above unless they are IKEv2, so extended auth
    // here means the IKEv2 successor to XAuth: EAP. The profile says nothing
    // about which EAP method the gateway offers, hence the warning.
    let user_auth = if profile.get("UseXAUTH").map(str::trim) == Some("1") {
        ctx.warn(
            "UseXAUTH=1: a second authentication round will be negotiated as EAP-MSCHAPv2 \
             (unconfirmed — verify on first connect); you will be asked for a username and \
             password"
                .to_string(),
        );
        Some(vpn_core::UserAuth {
            username: None,
            can_save: true,
            otp: false,
        })
    } else {
        None
    };

    Ok(ImportedProfile {
        config: ConnectionConfig {
            name,
            gateway,
            local_id,
            local_id_type,
            auth,
            // The importer rejects anything but ExchMode=34 (IKEv2) above.
            ike_version: vpn_core::IkeVersion::V2,
            user_auth,
            ike_enc: ike_enc.value,
            ike_integ: ike_integ.value,
            ike_prf: ike_prf.value,
            ike_dh: ike_dh.value,
            esp_enc: esp_enc.value,
            esp_integ: esp_integ.value,
            pfs,
            remote_subnets,
            request_virtual_ip,
            compression,
            // DPD/auto-reconnect isn't expressed in the fields we parse from
            // the NCP profile yet; use the always-on VPN default.
            dpd: vpn_core::DpdConfig::default(),
            dns,
        },
        warnings: ctx.warnings,
    })
}
