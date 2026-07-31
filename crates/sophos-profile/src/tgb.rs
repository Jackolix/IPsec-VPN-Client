//! Importer for the legacy Sophos/Cyberoam `.tgb` profile.
//!
//! This is what an SFOS firewall hands out for the old Cyberoam VPN client
//! (itself a TheGreenBow build, hence the extension). It is ini-shaped, and
//! describes IKEv1: a main-mode phase 1 and a quick-mode phase 2, with the
//! algorithms reached through a chain of section references rather than stated
//! in place —
//!
//! ```text
//! [Phase 2] -> the connection -> its ISAKMP peer  -> main-mode config -> transform
//!                             -> its remote id    -> quick-mode config -> suite -> protocol -> transform
//! ```
//!
//! Each hop is resolved explicitly below, and a dangling reference is an error:
//! a half-read profile would otherwise silently negotiate defaults.
//!
//! SECURITY: the peer's `Authentication` value is a live pre-shared key.

use crate::error::ImportError;
use std::net::Ipv4Addr;
use vpn_core::import::Warnings;
use vpn_core::ini::{self, Document, Section};
use vpn_core::{
    AuthMethod, ConnectionConfig, DhGroup, DnsConfig, DpdConfig, EncAlg, IkeIdType, IkeVersion,
    ImportedProfile, IntegAlg, Ipv4Net, PrfAlg, Secret, UserAuth,
};

/// Does this look like a `.tgb`? Both markers are written by the generator.
pub fn looks_like(input: &str) -> bool {
    let head: String = input.chars().take(4096).collect();
    head.contains("[Phase 1]") || head.contains("VpnConf")
}

pub fn import(input: &str) -> Result<ImportedProfile, ImportError> {
    let doc = ini::parse(input)?;
    let mut warn = Warnings::new();

    // --- phase 1: the peer we dial and how we authenticate to it -----------
    let (peer_name, peer) = isakmp_peer(&doc, &mut warn)?;
    let name = peer_name
        .strip_suffix("-P1")
        .unwrap_or(&peer_name)
        .to_string();

    let gateway = required(peer, "Address")?.trim().to_string();
    validate_gateway(&gateway)?;
    if is_private(&gateway) {
        warn.warn(format!(
            "the profile dials {gateway}, a private address — these exports are often generated \
             against the firewall's internal interface, so this may need to be changed to its \
             public address before it will connect from outside"
        ));
    }

    let secret = required(peer, "Authentication")?;
    if secret.trim().is_empty() {
        return Err(ImportError::EmptyField("Authentication"));
    }

    let (local_id, local_id_type) = local_identity(&doc, peer, &mut warn)?;

    let main_mode = section(&doc, required(peer, "Configuration")?)?;
    match required(main_mode, "EXCHANGE_TYPE")?.trim().to_ascii_uppercase().as_str() {
        // Main mode.
        "ID_PROT" => {}
        other => {
            // Aggressive mode exposes the PSK-derived hash to an eavesdropper
            // and needs a flag we do not model; refuse rather than quietly
            // negotiating main mode against a gateway expecting aggressive.
            return Err(ImportError::Unsupported(format!(
                "phase 1 exchange type {other} (only main mode, ID_PROT, is implemented)"
            )));
        }
    }
    let p1 = section(&doc, first_ref(required(main_mode, "Transforms")?, &mut warn, "Transforms")?)?;

    match required(p1, "AUTHENTICATION_METHOD")?.trim().to_ascii_uppercase().as_str() {
        "PRE_SHARED" | "XAUTH_INIT_PRE_SHARED" | "XAUTH_INIT_PRESHARED" => {}
        other => {
            return Err(ImportError::Unsupported(format!(
                "authentication method {other} (only pre-shared keys are implemented)"
            )))
        }
    }

    let ike_enc = enc_alg(
        required(p1, "ENCRYPTION_ALGORITHM")?,
        p1.get("KEY_LENGTH"),
        "phase 1",
    )?;
    let ike_integ = integ_alg(required(p1, "HASH_ALGORITHM")?, "phase 1")?;
    let ike_dh = dh_group(required(p1, "GROUP_DESCRIPTION")?, "phase 1")?;

    // --- phase 2: what the tunnel carries and how it is protected ----------
    let (_conn_name, conn) = connection(&doc, &peer_name, &mut warn)?;
    let quick_mode = section(&doc, required(conn, "Configuration")?)?;
    let suite = section(
        &doc,
        first_ref(required(quick_mode, "Suites")?, &mut warn, "Suites")?,
    )?;
    let protocol = section(
        &doc,
        first_ref(required(suite, "Protocols")?, &mut warn, "Protocols")?,
    )?;
    if let Some(id) = protocol.get("PROTOCOL_ID") {
        if !id.trim().eq_ignore_ascii_case("IPSEC_ESP") {
            return Err(ImportError::Unsupported(format!(
                "phase 2 protocol {} (only ESP is implemented)",
                id.trim()
            )));
        }
    }
    let p2 = section(
        &doc,
        first_ref(required(protocol, "Transforms")?, &mut warn, "Transforms")?,
    )?;

    if let Some(mode) = p2.get("ENCAPSULATION_MODE") {
        if !mode.trim().eq_ignore_ascii_case("TUNNEL") {
            return Err(ImportError::Unsupported(format!(
                "phase 2 encapsulation mode {} (only TUNNEL is implemented)",
                mode.trim()
            )));
        }
    }
    let esp_enc = enc_alg(required(p2, "TRANSFORM_ID")?, p2.get("KEY_LENGTH"), "phase 2")?;
    let esp_integ = integ_alg(required(p2, "AUTHENTICATION_ALGORITHM")?, "phase 2")?;
    let pfs = match p2.get("GROUP_DESCRIPTION") {
        Some(g) if !g.trim().is_empty() => Some(dh_group(g, "phase 2")?),
        _ => None,
    };

    let remote_subnets = remote_selectors(&doc, conn, &mut warn)?;

    // --- everything else ---------------------------------------------------
    let xauth = peer.get("Xauth").map(str::trim).unwrap_or("0") != "0";
    let user_auth = xauth.then(|| {
        warn.warn(
            "the gateway requires XAuth; you will be asked for a username and password on connect",
        );
        UserAuth {
            username: None,
            // The profile has no say in it, and an XAuth password is the
            // user's, so default to offering to remember it.
            can_save: true,
            otp: false,
        }
    });

    let dpd = doc
        .section("General")
        .and_then(|g| g.get("DPD-interval"))
        .and_then(|v| v.trim().parse::<u32>().ok());

    if peer.get("NATT_ENABLED").map(str::trim) == Some("0") {
        warn.warn(
            "the profile disables NAT traversal; charon negotiates it whenever the path needs it, \
             so this was ignored",
        );
    }

    let config = ConnectionConfig {
        name,
        gateway,
        local_id,
        local_id_type,
        auth: AuthMethod::PresharedKey(Secret::new(secret.to_string())),
        // Stated outright by the file: main mode and quick mode are IKEv1.
        ike_version: IkeVersion::V1,
        user_auth,
        ike_enc,
        ike_integ,
        // IKEv1 derives its keys with the negotiated hash; there is no separate
        // PRF transform to import.
        ike_prf: match ike_integ {
            IntegAlg::Sha1 => PrfAlg::Sha1,
            IntegAlg::Sha256 => PrfAlg::Sha256,
            IntegAlg::Sha384 => PrfAlg::Sha384,
            IntegAlg::Sha512 => PrfAlg::Sha512,
        },
        ike_dh,
        esp_enc,
        esp_integ,
        pfs,
        remote_subnets,
        // IKEv1 has no configuration payload of its own; an address is handed
        // out by mode config, which we do not drive, so ask for nothing.
        request_virtual_ip: false,
        compression: false,
        dpd: DpdConfig {
            delay_secs: dpd.unwrap_or(30),
            auto_reconnect: true,
        },
        dns: DnsConfig::default(),
    };

    Ok(ImportedProfile {
        config,
        warnings: warn.into_vec(),
    })
}

/// The phase-1 peer: `[Phase 2]` names a connection which names its peer;
/// failing that, `[Phase 1]` maps peer addresses to their sections directly.
fn isakmp_peer<'a>(
    doc: &'a Document,
    warn: &mut Warnings,
) -> Result<(String, &'a Section), ImportError> {
    if let Some(p2) = doc.section("Phase 2") {
        if let Some((_, conn_ref)) = p2.entries.first() {
            let conn = section(doc, first_ref(conn_ref, warn, "Phase 2")?)?;
            if let Some(peer_ref) = conn.get("ISAKMP-peer") {
                return Ok((peer_ref.trim().to_string(), section(doc, peer_ref)?));
            }
        }
    }
    let p1 = doc
        .section("Phase 1")
        .ok_or_else(|| ImportError::SectionNotFound("Phase 1".to_string()))?;
    let (_, peer_ref) = p1
        .entries
        .first()
        .ok_or(ImportError::EmptyField("Phase 1"))?;
    if p1.entries.len() > 1 {
        warn.warn(format!(
            "the file defines {} phase 1 peers; only the first ({}) is imported",
            p1.entries.len(),
            peer_ref.trim()
        ));
    }
    Ok((peer_ref.trim().to_string(), section(doc, peer_ref)?))
}

/// The phase-2 connection belonging to `peer_name`.
fn connection<'a>(
    doc: &'a Document,
    peer_name: &str,
    warn: &mut Warnings,
) -> Result<(String, &'a Section), ImportError> {
    let p2 = doc
        .section("Phase 2")
        .ok_or_else(|| ImportError::SectionNotFound("Phase 2".to_string()))?;
    if p2.entries.len() > 1 {
        warn.warn(format!(
            "the file defines {} phase 2 connections; only the first is imported",
            p2.entries.len()
        ));
    }
    let (_, conn_ref) = p2
        .entries
        .first()
        .ok_or(ImportError::EmptyField("Phase 2"))?;
    let conn_name = first_ref(conn_ref, warn, "Phase 2")?.to_string();
    let conn = section(doc, &conn_name)?;
    if let Some(owner) = conn.get("ISAKMP-peer") {
        if !owner.trim().eq_ignore_ascii_case(peer_name) {
            warn.warn(format!(
                "phase 2 connection {conn_name} belongs to peer {}, not {peer_name}",
                owner.trim()
            ));
        }
    }
    Ok((conn_name, conn))
}

/// The traffic selectors, from the connection's remote-id section. A
/// `0.0.0.0/0` selector is how these profiles say "full tunnel".
fn remote_selectors(
    doc: &Document,
    conn: &Section,
    warn: &mut Warnings,
) -> Result<Vec<Ipv4Net>, ImportError> {
    let Some(id_ref) = conn.get("Remote-ID") else {
        warn.warn("the profile names no remote networks; the gateway decides what the tunnel carries");
        return Ok(Vec::new());
    };
    let id = section(doc, id_ref)?;
    let kind = id
        .get("ID-Type")
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    let net = match kind.as_str() {
        "IPV4_ADDR_SUBNET" => {
            let addr = ipv4(required(id, "Network")?, "Network")?;
            let mask = ipv4(required(id, "Netmask")?, "Netmask")?;
            Ipv4Net::from_addr_and_mask(addr, mask).ok_or(ImportError::BadValue {
                field: "Netmask",
                value: mask.to_string(),
                why: "not a contiguous netmask",
            })?
        }
        "IPV4_ADDR" => Ipv4Net {
            addr: ipv4(required(id, "Address")?, "Address")?,
            prefix_len: 32,
        },
        other => {
            return Err(ImportError::Unsupported(format!(
                "remote selector type {other} (only IPV4_ADDR and IPV4_ADDR_SUBNET are \
                 implemented)"
            )))
        }
    };
    Ok(vec![net])
}

/// The identity we present, and its IKE type. The `.tgb` states the type
/// outright, which is the one place this format beats the JSON one.
fn local_identity(
    doc: &Document,
    peer: &Section,
    warn: &mut Warnings,
) -> Result<(Option<String>, Option<IkeIdType>), ImportError> {
    let Some(id_ref) = peer.get("ID") else {
        return Ok((None, None));
    };
    let id = section(doc, id_ref)?;
    let kind = id
        .get("ID-Type")
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    // The value's key depends on the type; take whichever the section carries.
    let value = ["Address", "Value", "FQDN", "Email", "ID"]
        .iter()
        .find_map(|k| id.get(k))
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let Some(value) = value else {
        warn.warn(format!(
            "identity section [{}] has no value; letting charon derive the identity",
            id_ref.trim()
        ));
        return Ok((None, None));
    };
    let kind = match kind.as_str() {
        "IPV4_ADDR" => IkeIdType::Ipv4,
        "FQDN" | "DNS" => IkeIdType::Fqdn,
        "USER_FQDN" | "EMAIL" | "RFC822" => IkeIdType::Rfc822,
        "KEY_ID" | "KEYID" => IkeIdType::KeyId,
        other => {
            warn.warn(format!(
                "identity type {other} is not one we map; letting charon infer it from {value:?}"
            ));
            return Ok((Some(value.to_string()), None));
        }
    };
    Ok((Some(value.to_string()), Some(kind)))
}

fn section<'a>(doc: &'a Document, name: &str) -> Result<&'a Section, ImportError> {
    let name = name.trim();
    doc.section(name)
        .ok_or_else(|| ImportError::SectionNotFound(name.to_string()))
}

fn required<'a>(section: &'a Section, key: &'static str) -> Result<&'a str, ImportError> {
    section.get(key).ok_or(ImportError::MissingField(key))
}

/// These fields may list several alternatives; the model holds one.
fn first_ref<'a>(
    value: &'a str,
    warn: &mut Warnings,
    field: &'static str,
) -> Result<&'a str, ImportError> {
    let mut parts = value.split(',').map(str::trim).filter(|p| !p.is_empty());
    let first = parts.next().ok_or(ImportError::EmptyField(field))?;
    if parts.next().is_some() {
        warn.warn(format!("{field} lists several options; only {first} is used"));
    }
    Ok(first)
}

fn ipv4(value: &str, field: &'static str) -> Result<Ipv4Addr, ImportError> {
    value.trim().parse().map_err(|_| ImportError::BadValue {
        field,
        value: value.trim().to_string(),
        why: "not an IPv4 address",
    })
}

/// `KEY_LENGTH` is written as `256,128:256` — the chosen length, then the
/// range the client may negotiate down to.
fn key_length(raw: Option<&str>) -> Option<u32> {
    raw?.split(&[',', ':'][..]).next()?.trim().parse().ok()
}

fn enc_alg(name: &str, keylen: Option<&str>, ctx: &'static str) -> Result<EncAlg, ImportError> {
    let name = name.trim().to_ascii_uppercase();
    let bits = key_length(keylen);
    match name.as_str() {
        "AES" | "AES_CBC" => match bits {
            Some(128) => Ok(EncAlg::Aes128),
            Some(192) => Ok(EncAlg::Aes192),
            Some(256) | None => Ok(EncAlg::Aes256),
            Some(other) => Err(ImportError::UnknownAlgorithm {
                context: ctx,
                token: format!("AES with a {other}-bit key"),
            }),
        },
        other => Err(ImportError::UnknownAlgorithm {
            context: ctx,
            token: other.to_string(),
        }),
    }
}

fn integ_alg(name: &str, ctx: &'static str) -> Result<IntegAlg, ImportError> {
    match name.trim().to_ascii_uppercase().as_str() {
        "SHA" | "SHA1" | "HMAC_SHA1" | "HMAC_SHA" => Ok(IntegAlg::Sha1),
        "SHA2_256" | "HMAC_SHA2_256" | "SHA256" => Ok(IntegAlg::Sha256),
        "SHA2_384" | "HMAC_SHA2_384" | "SHA384" => Ok(IntegAlg::Sha384),
        "SHA2_512" | "HMAC_SHA2_512" | "SHA512" => Ok(IntegAlg::Sha512),
        other => Err(ImportError::UnknownAlgorithm {
            context: ctx,
            token: other.to_string(),
        }),
    }
}

fn dh_group(name: &str, ctx: &'static str) -> Result<DhGroup, ImportError> {
    match name.trim().to_ascii_uppercase().as_str() {
        "MODP_1024" => Ok(DhGroup::Modp1024),
        "MODP_1536" => Ok(DhGroup::Modp1536),
        "MODP_2048" => Ok(DhGroup::Modp2048),
        "MODP_3072" => Ok(DhGroup::Modp3072),
        "MODP_4096" => Ok(DhGroup::Modp4096),
        "ECP_256" => Ok(DhGroup::Ecp256),
        "ECP_384" => Ok(DhGroup::Ecp384),
        other => Err(ImportError::UnknownAlgorithm {
            context: ctx,
            token: other.to_string(),
        }),
    }
}

fn is_private(gateway: &str) -> bool {
    gateway
        .parse::<Ipv4Addr>()
        .map(|a| a.is_private() || a.is_loopback() || a.is_link_local())
        .unwrap_or(false)
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
        Err(ImportError::BadValue {
            field: "Address",
            value: gw.to_string(),
            why: "contains characters that are not valid in a host name or address",
        })
    }
}
