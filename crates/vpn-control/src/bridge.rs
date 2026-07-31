//! Translate the internal [`ConnectionConfig`] into vici messages.
//!
//! This mirrors the swanctl.conf structure but hands everything to charon
//! over the control socket — crucially, the PSK travels via `load-shared`
//! (in memory) and is never written to a config file on disk.
//!
//! Pure data mapping, so it is unit-tested on any platform.

use vici::Message;
use vpn_core::{AuthMethod, ConnectionConfig, IkeVersion, Ipv4Net, Secret};

/// The CHILD_SA configurations a connection needs, as `(name, remote subnets)`.
///
/// IKEv2 carries several traffic selectors in one CHILD_SA, so every subnet
/// fits in a single child. IKEv1 quick mode negotiates exactly one selector
/// pair per SA: a child offering three subnets is narrowed by the gateway to
/// the first, and the rest are silently unreachable. So under IKEv1 each
/// subnet gets its own child, named `<conn>-1`, `<conn>-2`, … — verified
/// against a real gateway, which installs one SA per subnet.
///
/// A connection with no subnets (or one, or IKEv2) keeps the single child
/// named after the connection, which is what the disconnect path and the
/// existing status output expect.
pub fn child_selectors(config: &ConnectionConfig, name: &str) -> Vec<(String, Vec<Ipv4Net>)> {
    let split = config.ike_version == IkeVersion::V1 && config.remote_subnets.len() > 1;
    if !split {
        return vec![(name.to_string(), config.remote_subnets.clone())];
    }
    config
        .remote_subnets
        .iter()
        .enumerate()
        .map(|(i, net)| (format!("{name}-{}", i + 1), vec![*net]))
        .collect()
}

/// Just the child names, in the order they must be initiated.
pub fn child_names(config: &ConnectionConfig, name: &str) -> Vec<String> {
    child_selectors(config, name)
        .into_iter()
        .map(|(n, _)| n)
        .collect()
}

/// Build the `load-conn` argument: a message with a single section named
/// after the connection, holding the IKE/child configuration. Contains no
/// secret material.
pub fn load_conn_message(config: &ConnectionConfig, name: &str) -> Message {
    let mut local = Message::new().str("auth", "psk");
    if let Some(id) = config.local_id_wire() {
        local = local.str("id", id);
    }
    let remote = Message::new().str("auth", "psk");

    // Auto-reconnect: on a dead peer (DPD) or the peer closing the SA,
    // `restart` makes charon re-establish it; otherwise it just clears.
    let on_fail = if config.dpd.auto_reconnect { "restart" } else { "clear" };
    let mut children = Message::new();
    for (child_name, subnets) in child_selectors(config, name) {
        let mut child = Message::new()
            .list("esp_proposals", config.esp_proposals())
            .str("start_action", "none")
            .str("dpd_action", on_fail)
            .str("close_action", if config.dpd.auto_reconnect { "restart" } else { "none" });
        if config.compression {
            child = child.str("ipcomp", "yes");
        }
        if !subnets.is_empty() {
            child = child.list("remote_ts", subnets.iter().map(|n| n.to_string()));
        }
        children = children.section(&child_name, child);
    }

    let mut conn = Message::new()
        .str("version", config.ike_version.swanctl_value())
        .list("remote_addrs", [config.gateway.clone()])
        .list("proposals", config.ike_proposals());

    // A gateway that wants XAuth/EAP gets two local auth rounds: the PSK
    // first, then the interactive one. strongSwan distinguishes rounds by the
    // `local-N` suffix, so a profile without user auth keeps the plain
    // `local` section it has always had.
    conn = match &config.user_auth {
        None => conn.section("local", local),
        Some(ua) => {
            let mut round2 = Message::new().str("auth", user_auth_method(config));
            if let Some(user) = &ua.username {
                // XAuth and EAP name the identity differently; sending the one
                // that belongs to the other round is silently ignored.
                round2 = match config.ike_version {
                    IkeVersion::V1 => round2.str("xauth_id", user.clone()),
                    IkeVersion::V2 => round2.str("eap_id", user.clone()),
                };
            }
            conn.section("local-1", local).section("local-2", round2)
        }
    };

    let mut conn = conn
        .section("remote", remote)
        .section("children", children);
    // DPD liveness probing on the IKE_SA (0 = off).
    if config.dpd.delay_secs > 0 {
        conn = conn.str("dpd_delay", format!("{}s", config.dpd.delay_secs));
    }
    if config.request_virtual_ip {
        conn = conn.list("vips", ["0.0.0.0".to_string()]);
    }

    Message::new().section(name, conn)
}

/// strongSwan's name for the second auth round. IKEv1 calls it XAuth; the
/// IKEv2 equivalent is EAP, where MSCHAPv2 is what a Sophos gateway offers for
/// username/password.
fn user_auth_method(config: &ConnectionConfig) -> &'static str {
    match config.ike_version {
        IkeVersion::V1 => "xauth",
        IkeVersion::V2 => "eap-mschapv2",
    }
}

/// Build the `load-shared` argument carrying the XAuth/EAP password.
///
/// Separate from [`load_shared_message`] because this secret is the user's,
/// not the profile's: it is collected at connect time and passed in here, so
/// it never lives in [`ConnectionConfig`] where it could be cloned or dumped.
pub fn load_shared_user_auth_message(
    config: &ConnectionConfig,
    name: &str,
    password: &Secret,
) -> Message {
    let kind = match config.ike_version {
        IkeVersion::V1 => "XAUTH",
        IkeVersion::V2 => "EAP",
    };
    let owner = config
        .user_auth
        .as_ref()
        .and_then(|ua| ua.username.clone())
        .unwrap_or_else(|| "%any".to_string());
    Message::new()
        .str("id", format!("user-{name}"))
        .str("type", kind)
        .str("data", password.expose())
        .list("owners", [owner])
}

/// Build the `load-shared` argument carrying the PSK. The plaintext lives
/// only in the returned message (and is dropped once sent).
pub fn load_shared_message(config: &ConnectionConfig, name: &str) -> Message {
    let AuthMethod::PresharedKey(psk) = &config.auth;
    let owner = config
        .local_id_wire()
        .unwrap_or_else(|| "%any".to_string());
    Message::new()
        .str("id", format!("ike-{name}"))
        .str("type", "IKE")
        .str("data", psk.expose())
        .list("owners", [owner])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use vpn_core::{DhGroup, EncAlg, IntegAlg, Ipv4Net, PrfAlg, Secret};

    /// Shared with the connect-flow tests in `lib.rs`.
    pub(crate) fn sample() -> ConnectionConfig {
        ConnectionConfig {
            name: "vRouter-TEST-1".to_string(),
            gateway: "192.168.100.10".to_string(),
            local_id: Some("test-1@test.local".to_string()),
            local_id_type: None,
            auth: AuthMethod::PresharedKey(Secret::new("s3cr3t".to_string())),
            ike_version: IkeVersion::V2,
            user_auth: None,
            ike_enc: EncAlg::Aes256,
            ike_integ: IntegAlg::Sha256,
            ike_prf: PrfAlg::Sha256,
            ike_dh: DhGroup::Modp3072,
            esp_enc: EncAlg::Aes256,
            esp_integ: IntegAlg::Sha256,
            pfs: Some(DhGroup::Modp3072),
            remote_subnets: vec![Ipv4Net {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix_len: 24,
            }],
            request_virtual_ip: true,
            compression: false,
            dpd: vpn_core::DpdConfig::default(),
            dns: vpn_core::DnsConfig::default(),
        }
    }

    #[test]
    fn load_conn_has_expected_shape() {
        let msg = load_conn_message(&sample(), "vRouter-TEST-1");
        let conn = msg.get_section("vRouter-TEST-1").expect("named section");
        assert_eq!(conn.get_str("version").as_deref(), Some("2"));
        // The profile's own proposal is offered first; the rest are stronger
        // alternatives for a gateway whose export disagrees with its policy.
        let proposals = conn.get_list("proposals").expect("proposals");
        assert_eq!(proposals[0], "aes256-sha256-prfsha256-modp3072");
        assert!(proposals.len() > 1, "expected fallbacks: {proposals:?}");
        assert!(
            !proposals.iter().any(|p| p.contains("sha1") || p.contains("modp2048")),
            "an alternative must never be weaker than the profile: {proposals:?}"
        );
        assert_eq!(
            conn.get_section("local").unwrap().get_str("id").as_deref(),
            Some("test-1@test.local")
        );
        let child = conn
            .get_section("children")
            .unwrap()
            .get_section("vRouter-TEST-1")
            .unwrap();
        assert_eq!(
            child.get_list("esp_proposals").unwrap()[0],
            "aes256-sha256-modp3072"
        );
        assert_eq!(child.get_list("remote_ts"), Some(vec!["10.0.0.0/24".to_string()]));
    }

    #[test]
    fn load_conn_sets_dpd_and_auto_reconnect() {
        let msg = load_conn_message(&sample(), "vRouter-TEST-1");
        let conn = msg.get_section("vRouter-TEST-1").unwrap();
        assert_eq!(conn.get_str("dpd_delay").as_deref(), Some("30s"));
        let child = conn
            .get_section("children")
            .unwrap()
            .get_section("vRouter-TEST-1")
            .unwrap();
        assert_eq!(child.get_str("dpd_action").as_deref(), Some("restart"));
        assert_eq!(child.get_str("close_action").as_deref(), Some("restart"));
    }

    #[test]
    fn dpd_off_omits_delay_and_clears() {
        let mut cfg = sample();
        cfg.dpd = vpn_core::DpdConfig { delay_secs: 0, auto_reconnect: false };
        let msg = load_conn_message(&cfg, "c");
        let conn = msg.get_section("c").unwrap();
        assert_eq!(conn.get_str("dpd_delay"), None);
        let child = conn.get_section("children").unwrap().get_section("c").unwrap();
        assert_eq!(child.get_str("dpd_action").as_deref(), Some("clear"));
        assert_eq!(child.get_str("close_action").as_deref(), Some("none"));
    }

    #[test]
    fn load_conn_carries_no_secret() {
        let msg = load_conn_message(&sample(), "vRouter-TEST-1");
        assert!(!msg.pretty().contains("s3cr3t"));
    }

    /// Without user auth the connection keeps the single, unnumbered `local`
    /// section — numbering it would change what charon sees for every profile
    /// that already works.
    #[test]
    fn no_user_auth_keeps_single_local_section() {
        let conn = load_conn_message(&sample(), "c");
        let conn = conn.get_section("c").unwrap();
        assert!(conn.get_section("local").is_some());
        assert!(conn.get_section("local-1").is_none());
        assert!(conn.get_section("local-2").is_none());
    }

    #[test]
    fn ikev2_user_auth_adds_an_eap_round() {
        let mut cfg = sample();
        cfg.user_auth = Some(vpn_core::UserAuth {
            username: Some("vpnuser".to_string()),
            can_save: true,
            otp: false,
        });
        let msg = load_conn_message(&cfg, "c");
        let conn = msg.get_section("c").unwrap();
        let first = conn.get_section("local-1").expect("psk round");
        assert_eq!(first.get_str("auth").as_deref(), Some("psk"));
        let second = conn.get_section("local-2").expect("user auth round");
        assert_eq!(second.get_str("auth").as_deref(), Some("eap-mschapv2"));
        assert_eq!(second.get_str("eap_id").as_deref(), Some("vpnuser"));
        assert!(conn.get_section("local").is_none());
    }

    /// The legacy `.tgb` profiles are IKEv1, where the same round is XAuth and
    /// the identity travels under a different key.
    #[test]
    fn ikev1_user_auth_uses_xauth() {
        let mut cfg = sample();
        cfg.ike_version = IkeVersion::V1;
        cfg.user_auth = Some(vpn_core::UserAuth {
            username: Some("vpnuser".to_string()),
            can_save: false,
            otp: false,
        });
        let msg = load_conn_message(&cfg, "c");
        let conn = msg.get_section("c").unwrap();
        assert_eq!(conn.get_str("version").as_deref(), Some("1"));
        let second = conn.get_section("local-2").unwrap();
        assert_eq!(second.get_str("auth").as_deref(), Some("xauth"));
        assert_eq!(second.get_str("xauth_id").as_deref(), Some("vpnuser"));
    }

    fn nets(list: &[(&str, u8)]) -> Vec<Ipv4Net> {
        list.iter()
            .map(|(a, p)| Ipv4Net {
                addr: a.parse().unwrap(),
                prefix_len: *p,
            })
            .collect()
    }

    /// IKEv2 carries several selectors in one CHILD_SA, so the single child
    /// named after the connection keeps all the subnets.
    #[test]
    fn ikev2_keeps_one_child_for_every_subnet() {
        let mut cfg = sample();
        cfg.remote_subnets = nets(&[("10.0.0.0", 24), ("172.21.108.0", 24), ("198.51.100.7", 32)]);
        assert_eq!(child_names(&cfg, "c"), ["c"]);

        let msg = load_conn_message(&cfg, "c");
        let children = msg.get_section("c").unwrap().get_section("children").unwrap();
        let child = children.get_section("c").expect("one child named after the conn");
        assert_eq!(
            child.get_list("remote_ts"),
            Some(vec![
                "10.0.0.0/24".to_string(),
                "172.21.108.0/24".to_string(),
                "198.51.100.7/32".to_string()
            ])
        );
    }

    /// IKEv1 quick mode negotiates one selector pair per SA — offering three
    /// subnets in one child gets narrowed to the first, leaving the rest
    /// silently unreachable. Each subnet therefore needs its own child.
    #[test]
    fn ikev1_splits_each_subnet_into_its_own_child() {
        let mut cfg = sample();
        cfg.ike_version = IkeVersion::V1;
        cfg.remote_subnets = nets(&[("172.21.108.0", 24), ("10.98.49.0", 24), ("198.51.100.7", 32)]);
        assert_eq!(child_names(&cfg, "c"), ["c-1", "c-2", "c-3"]);

        let msg = load_conn_message(&cfg, "c");
        let children = msg.get_section("c").unwrap().get_section("children").unwrap();
        for (child, expected) in [
            ("c-1", "172.21.108.0/24"),
            ("c-2", "10.98.49.0/24"),
            ("c-3", "198.51.100.7/32"),
        ] {
            assert_eq!(
                children.get_section(child).unwrap().get_list("remote_ts"),
                Some(vec![expected.to_string()]),
                "{child}"
            );
        }
        // Every child still carries the ESP proposal and reconnect policy.
        let first = children.get_section("c-1").unwrap();
        assert_eq!(
            first.get_list("esp_proposals").unwrap()[0],
            "aes256-sha256-modp3072"
        );
        assert_eq!(first.get_str("dpd_action").as_deref(), Some("restart"));
    }

    /// A single subnet under IKEv1 needs no splitting, and must keep the
    /// connection's own name — that is what the status and disconnect paths
    /// have always seen.
    #[test]
    fn ikev1_with_one_subnet_keeps_the_plain_child_name() {
        let mut cfg = sample();
        cfg.ike_version = IkeVersion::V1;
        cfg.remote_subnets = nets(&[("0.0.0.0", 0)]);
        assert_eq!(child_names(&cfg, "c"), ["c"]);
    }

    #[test]
    fn user_auth_password_is_a_separate_shared_secret() {
        let mut cfg = sample();
        cfg.user_auth = Some(vpn_core::UserAuth {
            username: Some("vpnuser".to_string()),
            can_save: true,
            otp: false,
        });
        let pw = Secret::new("pa55word".to_string());
        let msg = load_shared_user_auth_message(&cfg, "c", &pw);
        assert_eq!(msg.get_str("type").as_deref(), Some("EAP"));
        assert_eq!(msg.get_list("owners"), Some(vec!["vpnuser".to_string()]));
        // The PSK message keeps its own id, so loading one cannot clobber the
        // other in charon's credential set.
        assert_eq!(msg.get_str("id").as_deref(), Some("user-c"));
        assert_eq!(
            load_shared_message(&cfg, "c").get_str("id").as_deref(),
            Some("ike-c")
        );
    }

    #[test]
    fn load_shared_carries_psk_and_owner() {
        let msg = load_shared_message(&sample(), "vRouter-TEST-1");
        assert_eq!(msg.get_str("type").as_deref(), Some("IKE"));
        assert_eq!(msg.get_str("data").as_deref(), Some("s3cr3t"));
        assert_eq!(msg.get_str("id").as_deref(), Some("ike-vRouter-TEST-1"));
        assert_eq!(
            msg.get_list("owners"),
            Some(vec!["test-1@test.local".to_string()])
        );
    }
}
