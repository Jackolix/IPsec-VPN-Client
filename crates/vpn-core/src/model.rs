use std::fmt;
use std::net::Ipv4Addr;

/// A pre-shared key or other secret. Redacted in all `Debug`/`Display` output;
/// the raw value is only reachable via [`Secret::expose`], which keeps every
/// use of the plaintext greppable. Best-effort zeroed on drop.
///
/// Phase 1 will move storage to the OS keychain; this type is the only place
/// the plaintext is allowed to live in the meantime.
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    /// Access the plaintext. Callers must not log or persist it outside the
    /// generated backend config.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best effort without a zeroize dependency: overwrite the buffer.
        // The optimizer may elide this; acceptable for Phase 0.
        unsafe {
            for b in self.0.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***REDACTED***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***REDACTED***")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncAlg {
    Aes128,
    Aes192,
    Aes256,
}

impl EncAlg {
    pub fn swanctl_name(self) -> &'static str {
        match self {
            EncAlg::Aes128 => "aes128",
            EncAlg::Aes192 => "aes192",
            EncAlg::Aes256 => "aes256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl IntegAlg {
    pub fn swanctl_name(self) -> &'static str {
        match self {
            IntegAlg::Sha1 => "sha1",
            IntegAlg::Sha256 => "sha256",
            IntegAlg::Sha384 => "sha384",
            IntegAlg::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl PrfAlg {
    pub fn swanctl_name(self) -> &'static str {
        match self {
            PrfAlg::Sha1 => "prfsha1",
            PrfAlg::Sha256 => "prfsha256",
            PrfAlg::Sha384 => "prfsha384",
            PrfAlg::Sha512 => "prfsha512",
        }
    }
}

/// IKE Diffie-Hellman groups, named by their IANA transform ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhGroup {
    Modp1024, // group 2
    Modp1536, // group 5
    Modp2048, // group 14
    Modp3072, // group 15
    Modp4096, // group 16
    Ecp256,   // group 19
    Ecp384,   // group 20
}

impl DhGroup {
    pub fn from_iana(id: u32) -> Option<Self> {
        Some(match id {
            2 => DhGroup::Modp1024,
            5 => DhGroup::Modp1536,
            14 => DhGroup::Modp2048,
            15 => DhGroup::Modp3072,
            16 => DhGroup::Modp4096,
            19 => DhGroup::Ecp256,
            20 => DhGroup::Ecp384,
            _ => return None,
        })
    }

    pub fn swanctl_name(self) -> &'static str {
        match self {
            DhGroup::Modp1024 => "modp1024",
            DhGroup::Modp1536 => "modp1536",
            DhGroup::Modp2048 => "modp2048",
            DhGroup::Modp3072 => "modp3072",
            DhGroup::Modp4096 => "modp4096",
            DhGroup::Ecp256 => "ecp256",
            DhGroup::Ecp384 => "ecp384",
        }
    }
}

/// How the peer authenticates. Only PSK for Phase 0.
#[derive(Debug)]
pub enum AuthMethod {
    PresharedKey(Secret),
}

/// An IPv4 network in CIDR terms (address + prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Net {
    /// Build from a dotted-quad netmask (e.g. 255.255.255.0 -> /24).
    /// Rejects non-contiguous masks like 255.0.255.0.
    pub fn from_addr_and_mask(addr: Ipv4Addr, mask: Ipv4Addr) -> Option<Self> {
        let m = u32::from(mask);
        if m != 0 && !(m.leading_ones() + m.trailing_zeros() == 32) {
            return None;
        }
        Some(Ipv4Net {
            addr,
            prefix_len: m.leading_ones() as u8,
        })
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// The internal, importer-independent connection configuration.
#[derive(Debug)]
pub struct ConnectionConfig {
    /// Display name; also used (sanitized) as the swanctl connection name.
    pub name: String,
    /// Gateway FQDN or IP address.
    pub gateway: String,
    /// Local IKE identity (e.g. a USER_FQDN / KEY_ID string). `None` = derive
    /// from local address.
    pub local_id: Option<String>,
    pub auth: AuthMethod,
    /// IKE (phase 1) proposal.
    pub ike_enc: EncAlg,
    pub ike_integ: IntegAlg,
    pub ike_prf: PrfAlg,
    pub ike_dh: DhGroup,
    /// ESP (phase 2 / CHILD_SA) proposal.
    pub esp_enc: EncAlg,
    pub esp_integ: IntegAlg,
    /// PFS group for CHILD_SA rekeying; `None` disables PFS.
    pub pfs: Option<DhGroup>,
    /// Remote traffic selectors (protected subnets behind the gateway).
    pub remote_subnets: Vec<Ipv4Net>,
    /// Request a server-assigned virtual IP via IKE configuration payload.
    pub request_virtual_ip: bool,
    /// IPComp compression.
    pub compression: bool,
    /// Dead-Peer-Detection / auto-reconnect behaviour.
    pub dpd: DpdConfig,
}

/// Dead-Peer-Detection and auto-reconnect policy.
///
/// DPD periodically probes an otherwise-idle peer (IKEv2 liveness check); if it
/// stops answering, `auto_reconnect` decides whether charon re-establishes the
/// tunnel on its own (also covers the peer closing the SA).
#[derive(Debug, Clone, Copy)]
pub struct DpdConfig {
    /// Liveness-probe interval in seconds. `0` disables DPD probing.
    pub delay_secs: u32,
    /// Re-establish the SA automatically when the peer is declared dead or
    /// closes the tunnel, instead of just clearing it.
    pub auto_reconnect: bool,
}

impl Default for DpdConfig {
    /// Probe every 30s and reconnect automatically — a sensible always-on VPN
    /// default that recovers from peer reboots, roaming and link flaps.
    fn default() -> Self {
        DpdConfig {
            delay_secs: 30,
            auto_reconnect: true,
        }
    }
}

impl ConnectionConfig {
    /// IKE (phase 1) proposal string, e.g. `aes256-sha256-prfsha256-modp3072`.
    /// Shared by the swanctl renderer and the vici bridge.
    pub fn ike_proposal(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.ike_enc.swanctl_name(),
            self.ike_integ.swanctl_name(),
            self.ike_prf.swanctl_name(),
            self.ike_dh.swanctl_name()
        )
    }

    /// ESP (phase 2) proposal string, e.g. `aes256-sha256-modp3072` (the DH
    /// suffix is present only when PFS is enabled).
    pub fn esp_proposal(&self) -> String {
        match self.pfs {
            Some(g) => format!(
                "{}-{}-{}",
                self.esp_enc.swanctl_name(),
                self.esp_integ.swanctl_name(),
                g.swanctl_name()
            ),
            None => format!(
                "{}-{}",
                self.esp_enc.swanctl_name(),
                self.esp_integ.swanctl_name()
            ),
        }
    }
}
