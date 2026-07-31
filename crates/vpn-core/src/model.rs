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

    /// Inverse of [`EncAlg::swanctl_name`] — parses the name a UI round-trips.
    pub fn from_swanctl_name(name: &str) -> Option<Self> {
        Some(match name {
            "aes128" => EncAlg::Aes128,
            "aes192" => EncAlg::Aes192,
            "aes256" => EncAlg::Aes256,
            _ => return None,
        })
    }

    /// Every value, in the order a picker should offer them.
    pub const ALL: [EncAlg; 3] = [EncAlg::Aes128, EncAlg::Aes192, EncAlg::Aes256];
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

    pub fn from_swanctl_name(name: &str) -> Option<Self> {
        Some(match name {
            "sha1" => IntegAlg::Sha1,
            "sha256" => IntegAlg::Sha256,
            "sha384" => IntegAlg::Sha384,
            "sha512" => IntegAlg::Sha512,
            _ => return None,
        })
    }

    pub const ALL: [IntegAlg; 4] = [
        IntegAlg::Sha1,
        IntegAlg::Sha256,
        IntegAlg::Sha384,
        IntegAlg::Sha512,
    ];
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

    pub fn from_swanctl_name(name: &str) -> Option<Self> {
        Some(match name {
            "prfsha1" => PrfAlg::Sha1,
            "prfsha256" => PrfAlg::Sha256,
            "prfsha384" => PrfAlg::Sha384,
            "prfsha512" => PrfAlg::Sha512,
            _ => return None,
        })
    }

    pub const ALL: [PrfAlg; 4] = [PrfAlg::Sha1, PrfAlg::Sha256, PrfAlg::Sha384, PrfAlg::Sha512];
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

    pub fn from_swanctl_name(name: &str) -> Option<Self> {
        Some(match name {
            "modp1024" => DhGroup::Modp1024,
            "modp1536" => DhGroup::Modp1536,
            "modp2048" => DhGroup::Modp2048,
            "modp3072" => DhGroup::Modp3072,
            "modp4096" => DhGroup::Modp4096,
            "ecp256" => DhGroup::Ecp256,
            "ecp384" => DhGroup::Ecp384,
            _ => return None,
        })
    }

    pub const ALL: [DhGroup; 7] = [
        DhGroup::Modp1024,
        DhGroup::Modp1536,
        DhGroup::Modp2048,
        DhGroup::Modp3072,
        DhGroup::Modp4096,
        DhGroup::Ecp256,
        DhGroup::Ecp384,
    ];
}

/// How the peer authenticates. Only PSK for Phase 0.
#[derive(Debug)]
pub enum AuthMethod {
    PresharedKey(Secret),
}

/// Which IKE version a profile speaks.
///
/// NCP exports and Sophos `.scx` are IKEv2. The legacy Sophos/Cyberoam `.tgb`
/// export is IKEv1 — it describes a main-mode phase 1 (`ID_PROT`) and a
/// quick-mode phase 2 — so the version cannot be assumed any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeVersion {
    V1,
    V2,
}

impl IkeVersion {
    /// The value strongSwan expects for `version` (`1` or `2`).
    pub fn swanctl_value(self) -> &'static str {
        match self {
            IkeVersion::V1 => "1",
            IkeVersion::V2 => "2",
        }
    }

    /// Stable name for the override file and the UI.
    pub fn name(self) -> &'static str {
        match self {
            IkeVersion::V1 => "ikev1",
            IkeVersion::V2 => "ikev2",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ikev1" => IkeVersion::V1,
            "ikev2" => IkeVersion::V2,
            _ => return None,
        })
    }

    pub const ALL: [IkeVersion; 2] = [IkeVersion::V2, IkeVersion::V1];
}

/// A second, interactive authentication round layered on top of the PSK.
///
/// Sophos fronts its remote-access tunnels with one: under IKEv1 it is XAuth,
/// under IKEv2 the equivalent EAP exchange. The profile only ever carries
/// *whether* it is required (and whether the client may remember the answer) —
/// the username and password belong to the person connecting, so they are
/// collected at connect time and kept in the OS keychain, never in the profile
/// file.
#[derive(Debug, Clone, Default)]
pub struct UserAuth {
    /// Username, when one is known (from the keychain, or typed by the user).
    /// `None` means the UI must ask before the tunnel can come up.
    pub username: Option<String>,
    /// Whether the gateway told us the client may save these credentials.
    /// `false` means prompt on every connect and never write to the keychain.
    pub can_save: bool,
    /// The gateway expects a one-time password appended to (or in place of)
    /// the fixed one, so a saved password alone will not authenticate.
    pub otp: bool,
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

/// Parses the CIDR form this type prints, so an edited traffic selector can be
/// round-tripped through a text field. A bare address means a /32 host route.
impl std::str::FromStr for Ipv4Net {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (
                a.trim(),
                l.trim()
                    .parse::<u8>()
                    .map_err(|_| format!("{s:?}: prefix length is not a number"))?,
            ),
            None => (s, 32),
        };
        if len > 32 {
            return Err(format!("{s:?}: prefix length must be 0–32"));
        }
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("{s:?}: not an IPv4 network"))?;
        Ok(Ipv4Net {
            addr,
            prefix_len: len,
        })
    }
}

/// The IKE identity type declared by a profile. Maps to an IANA IKEv2 ID
/// type; we use it to emit a strongSwan-typed identity so charon presents the
/// exact type the peer expects instead of inferring it from the string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeIdType {
    /// IANA 1 — an IPv4 address literal (inferred correctly, no prefix needed).
    Ipv4,
    /// IANA 2 — a DNS name (`fqdn:`).
    Fqdn,
    /// IANA 3 — RFC822/USER_FQDN address (`rfc822:`). NCP's `IkeIdType=3`.
    Rfc822,
    /// IANA 11 — an opaque key id (`keyid:`).
    KeyId,
}

impl IkeIdType {
    /// The strongSwan identity prefix, which doubles as this type's stable name
    /// in the profile-override file and the UI.
    pub fn name(self) -> &'static str {
        match self {
            IkeIdType::Ipv4 => "ipv4",
            IkeIdType::Fqdn => "fqdn",
            IkeIdType::Rfc822 => "rfc822",
            IkeIdType::KeyId => "keyid",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "ipv4" => IkeIdType::Ipv4,
            "fqdn" => IkeIdType::Fqdn,
            "rfc822" => IkeIdType::Rfc822,
            "keyid" => IkeIdType::KeyId,
            _ => return None,
        })
    }

    pub const ALL: [IkeIdType; 4] = [
        IkeIdType::Ipv4,
        IkeIdType::Fqdn,
        IkeIdType::Rfc822,
        IkeIdType::KeyId,
    ];
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
    /// The IKE ID *type* the profile declared for [`local_id`]. strongSwan
    /// otherwise infers the type from the string, which is wrong for a bare
    /// token the gateway treats as RFC822 — so we force it (see
    /// [`ConnectionConfig::local_id_wire`]). `None` = let charon infer.
    pub local_id_type: Option<IkeIdType>,
    pub auth: AuthMethod,
    /// IKE version to negotiate.
    pub ike_version: IkeVersion,
    /// Second authentication round (XAuth/EAP), when the gateway demands one.
    pub user_auth: Option<UserAuth>,
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
    /// DNS to use while the tunnel is up.
    pub dns: DnsConfig,
}

/// DNS behaviour for a connection.
///
/// `servers` are the resolvers reachable over the tunnel. If `domain` is set,
/// only names under it are resolved via those servers (split-DNS, implemented
/// on Windows with an NRPT rule); otherwise the servers become the interface's
/// resolvers for the duration of the tunnel.
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    pub servers: Vec<std::net::Ipv4Addr>,
    pub domain: Option<String>,
}

impl DnsConfig {
    /// Nothing to configure (no servers parsed from the profile).
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
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

    /// The local IKE identity as strongSwan should parse it: a typed prefix
    /// forces the ID type so a bare token like `acme_site_01` is presented as
    /// RFC822 (what the gateway expects) rather than an inferred FQDN. Returns
    /// `None` when the profile declares no local id.
    pub fn local_id_wire(&self) -> Option<String> {
        let id = self.local_id.as_ref()?;
        Some(match self.local_id_type {
            Some(IkeIdType::Fqdn) => format!("fqdn:{id}"),
            Some(IkeIdType::Rfc822) => format!("rfc822:{id}"),
            Some(IkeIdType::KeyId) => format!("keyid:{id}"),
            // An IPv4 literal is inferred correctly; no prefix, and none when
            // the type is unknown (fall back to charon's inference).
            Some(IkeIdType::Ipv4) | None => id.clone(),
        })
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
