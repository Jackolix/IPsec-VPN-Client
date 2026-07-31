//! Translate the internal [`ConnectionConfig`] into vici messages.
//!
//! This mirrors the swanctl.conf structure but hands everything to charon
//! over the control socket — crucially, the PSK travels via `load-shared`
//! (in memory) and is never written to a config file on disk.
//!
//! Pure data mapping, so it is unit-tested on any platform.

use vici::Message;
use vpn_core::{AuthMethod, ConnectionConfig, IkeVersion, Secret};

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
    let mut child = Message::new()
        .list("esp_proposals", [config.esp_proposal()])
        .str("start_action", "none")
        .str("dpd_action", on_fail)
        .str("close_action", if config.dpd.auto_reconnect { "restart" } else { "none" });
    if config.compression {
        child = child.str("ipcomp", "yes");
    }
    if !config.remote_subnets.is_empty() {
        child = child.list(
            "remote_ts",
            config.remote_subnets.iter().map(|n| n.to_string()),
        );
    }
    let children = Message::new().section(name, child);

    let mut conn = Message::new()
        .str("version", config.ike_version.swanctl_value())
        .list("remote_addrs", [config.gateway.clone()])
        .list("proposals", [config.ike_proposal()]);

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
        assert_eq!(
            conn.get_list("proposals"),
            Some(vec!["aes256-sha256-prfsha256-modp3072".to_string()])
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
            child.get_list("esp_proposals"),
            Some(vec!["aes256-sha256-modp3072".to_string()])
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
