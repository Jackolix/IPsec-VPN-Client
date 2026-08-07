//! Importer for the Apple `.mobileconfig` the Sophos user portal hands out for
//! IPsec.
//!
//! When a person signs in to a Sophos firewall's user portal and downloads the
//! IPsec configuration, they get an Apple *configuration profile* — an XML
//! property list meant for iOS — rather than an `.scx`. It carries a
//! `com.apple.vpn.managed` payload whose `VPNType` is `IPSec`: Apple's name for
//! a Cisco-style tunnel, which is **IKEv1 with XAuth**. So unlike the `.scx`
//! (where the version is a guess), the version here is stated by the format and
//! imported as IKEv1.
//!
//! What the file does *not* carry is the phase-1/phase-2 algorithms or the
//! remote subnets — iOS negotiates its own defaults and lets the gateway decide
//! the selectors. This importer fills in a proposal that a Sophos gateway
//! accepts (verified live), leans on the model's stronger fallbacks, and warns
//! that both were assumed.
//!
//! SECURITY: `IPSec.SharedSecret` is a live pre-shared key, base64-encoded in a
//! `<data>` element. It is decoded straight into [`Secret`] and must never be
//! logged or written back out.

use crate::error::ImportError;
use plist::{Dictionary, Value};
use vpn_core::import::Warnings;
use vpn_core::{
    AuthMethod, ConnectionConfig, DhGroup, DnsConfig, DpdConfig, EncAlg, IkeVersion, ImportedProfile,
    IntegAlg, Ipv4Net, PrfAlg, Secret, UserAuth,
};

/// Hard cap on input size; a real `.mobileconfig` is a few kilobytes.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

/// Apple's payload type for a VPN, and the `VPNType` value that means a
/// Cisco-style (IKEv1 + XAuth) IPsec tunnel — the only kind these portals emit.
const VPN_PAYLOAD_TYPE: &str = "com.apple.vpn.managed";
const VPN_TYPE_IPSEC: &str = "IPSec";

/// Does this look like an Apple configuration profile carrying a VPN payload?
/// The other three formats are JSON or ini, so the XML markers are unambiguous.
pub fn looks_like(input: &str) -> bool {
    let head: String = input.chars().take(4096).collect();
    let head = head.trim_start();
    (head.starts_with("<?xml") || head.starts_with("<plist"))
        && input.contains(VPN_PAYLOAD_TYPE)
}

pub fn import(input: &str) -> Result<ImportedProfile, ImportError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(ImportError::TooLarge(MAX_INPUT_LEN));
    }
    let root = Value::from_reader_xml(input.as_bytes())
        .map_err(|e| ImportError::Plist(e.to_string()))?;
    let mut warn = Warnings::new();

    let top = root
        .as_dictionary()
        .ok_or(ImportError::Plist("the property list is not a dictionary".to_string()))?;
    let payloads = top
        .get("PayloadContent")
        .and_then(Value::as_array)
        .ok_or(ImportError::MissingField("PayloadContent"))?;

    // A configuration profile can bundle several payloads (Wi-Fi, certificates,
    // …); pick the VPN one, and refuse an IKEv2 profile rather than silently
    // importing it as the IKEv1 tunnel this format usually describes.
    let vpn = find_vpn_payload(payloads)?;

    let ipsec = vpn
        .get("IPSec")
        .and_then(Value::as_dictionary)
        .ok_or(ImportError::MissingField("IPSec"))?;

    let gateway = ipsec
        .get("RemoteAddress")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ImportError::MissingField("IPSec.RemoteAddress"))?
        .to_string();
    validate_gateway(&gateway)?;
    if is_private(&gateway) {
        warn.warn(format!(
            "the profile dials {gateway}, a private address — it will only connect from inside \
             that network, or over another tunnel that reaches it"
        ));
    }

    let method = ipsec
        .get("AuthenticationMethod")
        .and_then(Value::as_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    if !method.eq_ignore_ascii_case("SharedSecret") {
        // Certificate-authenticated profiles carry an identity we do not import
        // yet; fail rather than dropping to a key that is not there.
        return Err(ImportError::Unsupported(format!(
            "IPsec authentication method {method:?} (only SharedSecret / pre-shared key is \
             implemented)"
        )));
    }

    // The PSK is a base64 <data> element. `as_data` hands back the decoded
    // bytes; the key itself is text.
    let secret_bytes = ipsec
        .get("SharedSecret")
        .and_then(Value::as_data)
        .ok_or(ImportError::MissingField("IPSec.SharedSecret"))?;
    let secret = std::str::from_utf8(secret_bytes).map_err(|_| ImportError::BadValue {
        field: "IPSec.SharedSecret",
        // Never the key itself — only that it was not text.
        value: "<binary>".to_string(),
        why: "the pre-shared key is not valid UTF-8",
    })?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(ImportError::EmptyField("IPSec.SharedSecret"));
    }

    // XAuth: the file states whether the second round is required, and — unlike
    // the .scx/.tgb — names the user, which we can prefill (the person still
    // supplies the password at connect time).
    let xauth_enabled = ipsec
        .get("XAuthEnabled")
        .and_then(Value::as_signed_integer)
        .unwrap_or(0)
        != 0;
    let username = ipsec
        .get("XAuthName")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let user_auth = xauth_enabled.then(|| {
        warn.warn(
            "the gateway requires XAuth; you will be asked for a username and password on connect",
        );
        UserAuth {
            username: username.clone(),
            // The profile has no say in it, and an XAuth password is the user's,
            // so default to offering to remember it.
            can_save: true,
            otp: false,
        }
    });

    let name = vpn
        .get("UserDefinedName")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Sophos VPN")
        .to_string();

    // The profile states no algorithms — iOS negotiates defaults — so use a
    // proposal a Sophos gateway accepts (AES-256 / SHA2-256 / MODP-2048,
    // verified live) and let the model offer stronger alternatives alongside it.
    warn.warn(
        "the profile states no encryption algorithms (iOS negotiates its own); proposing \
         AES-256/SHA2-256 with DH group 14, plus stronger alternatives — verify on first connect",
    );
    // The file names no selectors — an iOS IPsec profile routes everything and
    // relies on the gateway to narrow it, which a split-tunnel Sophos gateway
    // (the common case) does not do. Defaulting to 0.0.0.0/0 here would capture
    // the machine's default route and, against a gateway that does not carry
    // internet traffic, cut the user off. So import no networks and let the
    // connect flow refuse a silent full tunnel: the user adds the subnet(s)
    // they need, or opts into a full tunnel explicitly.
    warn.warn(
        "the profile names no remote networks — unlike a Sophos Connect (.scx) export, an iOS \
         profile does not list them. Add the subnet(s) you need to reach before connecting, or \
         choose to route all traffic through the VPN",
    );
    let remote_subnets: Vec<Ipv4Net> = Vec::new();

    let config = ConnectionConfig {
        name,
        gateway,
        // The file carries no IKE identity for the PSK round (XAuthName is the
        // XAuth user, not the IKE ID); let charon derive it from the address.
        local_id: None,
        local_id_type: None,
        auth: AuthMethod::PresharedKey(Secret::new(secret.to_string())),
        // Stated by the format: VPNType IPSec is Apple's Cisco-style IKEv1.
        ike_version: IkeVersion::V1,
        user_auth,
        ike_enc: EncAlg::Aes256,
        ike_integ: IntegAlg::Sha256,
        // IKEv1 derives its keys from the negotiated hash; no separate PRF.
        ike_prf: PrfAlg::Sha256,
        ike_dh: DhGroup::Modp2048,
        esp_enc: EncAlg::Aes256,
        esp_integ: IntegAlg::Sha256,
        pfs: Some(DhGroup::Modp2048),
        remote_subnets,
        // Remote-access: the gateway hands out the tunnel address over IKEv1
        // mode config and expects it as the phase-2 local selector. Without this
        // the quick mode is answered with INVALID_ID_INFORMATION.
        request_virtual_ip: true,
        compression: false,
        dpd: DpdConfig {
            delay_secs: 30,
            auto_reconnect: true,
        },
        dns: DnsConfig::default(),
    };

    Ok(ImportedProfile {
        config,
        warnings: warn.into_vec(),
    })
}

/// Find the `com.apple.vpn.managed` payload that describes an IPsec tunnel.
///
/// A profile with an IKEv2 VPN payload is refused outright: importing it as the
/// IKEv1 tunnel this format usually carries would negotiate the wrong thing.
fn find_vpn_payload(payloads: &[Value]) -> Result<&Dictionary, ImportError> {
    let mut saw_other_vpn: Option<String> = None;
    for payload in payloads {
        let Some(dict) = payload.as_dictionary() else {
            continue;
        };
        let ptype = dict
            .get("PayloadType")
            .and_then(Value::as_string)
            .unwrap_or_default();
        if ptype != VPN_PAYLOAD_TYPE {
            continue;
        }
        let vpn_type = dict
            .get("VPNType")
            .and_then(Value::as_string)
            .unwrap_or_default()
            .trim();
        if vpn_type.eq_ignore_ascii_case(VPN_TYPE_IPSEC) && dict.get("IPSec").is_some() {
            return Ok(dict);
        }
        saw_other_vpn = Some(vpn_type.to_string());
    }
    Err(match saw_other_vpn {
        Some(other) => ImportError::Unsupported(format!(
            "a VPN payload of type {other:?} (only the Cisco-IPsec/IKEv1 profile these portals \
             export is implemented)"
        )),
        None => ImportError::MissingField("an IPsec VPN payload"),
    })
}

/// Is the gateway an address that only answers from inside its own network?
fn is_private(gateway: &str) -> bool {
    gateway
        .parse::<std::net::Ipv4Addr>()
        .map(|a| a.is_private() || a.is_loopback() || a.is_link_local())
        .unwrap_or(false)
}

/// The same conservative charset the other importers enforce: the gateway
/// string reaches charon, so a hostile profile must not smuggle anything else
/// through it.
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
            field: "IPSec.RemoteAddress",
            value: gw.to_string(),
            why: "contains characters that are not valid in a host name or address",
        })
    }
}
