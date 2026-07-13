//! Numeric code tables for the NCP `.ini` profile format.
//!
//! There is no public schema for this format. Every mapping below carries a
//! [`Confidence`] describing how it was derived; anything below `High` is
//! reported to the user as an import warning so a wrong guess fails loud in
//! the UI instead of silently negotiating the wrong thing.
//!
//! Evidence used so far:
//! - IANA IKEv2 transform/ID registries, where NCP appears to reuse the
//!   standard numbering (DH groups, IKE ID types).
//! - The sample profile's policy names (`WIZ-AES256-SHA256`), which
//!   corroborate the algorithm codes they reference.
//! - Field names and known NCP client conventions.
//! - **2026-07-03 live confirmation**: a full IKEv2 tunnel (IKE_SA +
//!   CHILD_SA, virtual IP assigned, ESP `AES_CBC-256/HMAC_SHA2_256_128`)
//!   was established against a LANCOM vRouter (NCP-family gateway) using a
//!   LANCOM-exported test profile. Codes observed in that profile are
//!   marked `High` with a "confirmed live" note; a wrong mapping would have
//!   been rejected during negotiation.
//!
//! When a code is confirmed against a real NCP client or NCP documentation,
//! bump its confidence and note the source here.

use vpn_core::{DhGroup, EncAlg, IntegAlg, PrfAlg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Confirmed against NCP behavior/documentation or a standard registry
    /// the format demonstrably follows.
    High,
    /// Consistent with conventions and corroborated indirectly (e.g. by the
    /// policy name), but not confirmed.
    Medium,
    /// Named guess. Must be user-confirmed before first use.
    Low,
}

/// A mapped value together with how sure we are about the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapped<T> {
    pub value: T,
    pub confidence: Confidence,
}

fn mapped<T>(value: T, confidence: Confidence) -> Option<Mapped<T>> {
    Some(Mapped { value, confidence })
}

/// `ExchMode` — IKE exchange mode. 34 confirmed live as IKEv2. IKEv1 values
/// (main/aggressive mode) are unmapped: this client is IKEv2-only for now.
pub fn exch_mode_is_ikev2(code: u32) -> Option<Mapped<bool>> {
    match code {
        34 => mapped(true, Confidence::High),
        _ => None,
    }
}

/// `IKEv2Auth` — IKEv2 authentication method. 2 observed on a profile with a
/// `Secret=` PSK present and `UseXAUTH=0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2AuthMethod {
    PresharedKey,
}

pub fn ikev2_auth(code: u32) -> Option<Mapped<Ikev2AuthMethod>> {
    match code {
        2 => mapped(Ikev2AuthMethod::PresharedKey, Confidence::High), // confirmed live
        _ => None,
    }
}

/// `Ikev2Crypt` / `IpsecCrypt` — encryption algorithm. 6 confirmed live as
/// AES-256 (ESP SA came up as AES_CBC-256).
pub fn enc_alg(code: u32) -> Option<Mapped<EncAlg>> {
    match code {
        6 => mapped(EncAlg::Aes256, Confidence::High),
        _ => None,
    }
}

/// `Ikev2PRF` — pseudo-random function. 5 matches the IANA IKEv2 PRF
/// transform ID for PRF_HMAC_SHA2_256 and the policy name's SHA256.
pub fn prf_alg(code: u32) -> Option<Mapped<PrfAlg>> {
    match code {
        2 => mapped(PrfAlg::Sha1, Confidence::Low),
        5 => mapped(PrfAlg::Sha256, Confidence::High), // confirmed live
        6 => mapped(PrfAlg::Sha384, Confidence::Low),
        7 => mapped(PrfAlg::Sha512, Confidence::Low),
        _ => None,
    }
}

/// `Ikev2IntAlgo` — IKE integrity algorithm. 12 matches the IANA IKEv2
/// integrity transform ID for AUTH_HMAC_SHA2_256_128 and the policy name.
pub fn ike_integ_alg(code: u32) -> Option<Mapped<IntegAlg>> {
    match code {
        2 => mapped(IntegAlg::Sha1, Confidence::Low),
        12 => mapped(IntegAlg::Sha256, Confidence::High), // confirmed live
        13 => mapped(IntegAlg::Sha384, Confidence::Low),
        14 => mapped(IntegAlg::Sha512, Confidence::Low),
        _ => None,
    }
}

/// `IpsecAuth` — ESP authentication/integrity algorithm. NOTE: a different
/// code space from `Ikev2IntAlgo` (5 here vs 12 there, both SHA-256).
/// 5 confirmed live (ESP SA came up as HMAC_SHA2_256_128).
pub fn esp_integ_alg(code: u32) -> Option<Mapped<IntegAlg>> {
    match code {
        5 => mapped(IntegAlg::Sha256, Confidence::High),
        _ => None,
    }
}

/// `IkeDhGroup` / `PFS` — Diffie-Hellman group, the IANA group numbers
/// directly (15 = modp3072, confirmed live — a wrong group would have drawn
/// INVALID_KE_PAYLOAD); `PFS=0` is read as "PFS disabled".
pub fn dh_group(code: u32) -> Option<Mapped<DhGroup>> {
    DhGroup::from_iana(code).and_then(|g| mapped(g, Confidence::High))
}

/// `IkeIdType` — local IKE identity type, apparently the IANA IKEv2 ID type
/// registry (1 = IPV4_ADDR, 2 = FQDN, 3 = RFC822/USER_FQDN, 11 = KEY_ID).
/// This is *not* just informational: we emit a strongSwan-typed identity from
/// it (e.g. `rfc822:` for type 3) so charon presents the exact type the peer
/// expects instead of inferring it from the string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeIdType {
    Ipv4Addr,
    Fqdn,
    UserFqdn,
    KeyId,
}

pub fn ike_id_type(code: u32) -> Option<Mapped<IkeIdType>> {
    match code {
        1 => mapped(IkeIdType::Ipv4Addr, Confidence::Medium),
        2 => mapped(IkeIdType::Fqdn, Confidence::Medium),
        // 2026-07-13 confirmed live against the production LANCOM
        // (LANCOM-EXAMPLE) with a bare, non-email token (`vpnuser-example`,
        // no `@`) forced through the `rfc822:` prefix — a real test of the
        // forced type, unlike the earlier local-gateway confirmation whose
        // id string already contained `@` and would've inferred correctly
        // either way.
        3 => mapped(IkeIdType::UserFqdn, Confidence::High),
        11 => mapped(IkeIdType::KeyId, Confidence::Medium),
        _ => None,
    }
}

/// `IpAddrAssign` — virtual IP assignment. 0 confirmed live: the gateway
/// assigned a virtual IP via IKE config payload when we requested one.
pub fn ip_addr_assign_is_server(code: u32) -> Option<Mapped<bool>> {
    match code {
        0 => mapped(true, Confidence::High),
        _ => None,
    }
}
