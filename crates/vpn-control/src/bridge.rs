//! Translate the internal [`ConnectionConfig`] into vici messages.
//!
//! This mirrors the swanctl.conf structure but hands everything to charon
//! over the control socket — crucially, the PSK travels via `load-shared`
//! (in memory) and is never written to a config file on disk.
//!
//! Pure data mapping, so it is unit-tested on any platform.

use vici::Message;
use vpn_core::{AuthMethod, ConnectionConfig};

/// Build the `load-conn` argument: a message with a single section named
/// after the connection, holding the IKE/child configuration. Contains no
/// secret material.
pub fn load_conn_message(config: &ConnectionConfig, name: &str) -> Message {
    let mut local = Message::new().str("auth", "psk");
    if let Some(id) = &config.local_id {
        local = local.str("id", id);
    }
    let remote = Message::new().str("auth", "psk");

    let mut child = Message::new()
        .list("esp_proposals", [config.esp_proposal()])
        .str("start_action", "none");
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
        .str("version", "2")
        .list("remote_addrs", [config.gateway.clone()])
        .list("proposals", [config.ike_proposal()])
        .section("local", local)
        .section("remote", remote)
        .section("children", children);
    if config.request_virtual_ip {
        conn = conn.list("vips", ["0.0.0.0".to_string()]);
    }

    Message::new().section(name, conn)
}

/// Build the `load-shared` argument carrying the PSK. The plaintext lives
/// only in the returned message (and is dropped once sent).
pub fn load_shared_message(config: &ConnectionConfig, name: &str) -> Message {
    let AuthMethod::PresharedKey(psk) = &config.auth;
    let owner = config
        .local_id
        .clone()
        .unwrap_or_else(|| "%any".to_string());
    Message::new()
        .str("id", format!("ike-{name}"))
        .str("type", "IKE")
        .str("data", psk.expose())
        .list("owners", [owner])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use vpn_core::{DhGroup, EncAlg, IntegAlg, Ipv4Net, PrfAlg, Secret};

    fn sample() -> ConnectionConfig {
        ConnectionConfig {
            name: "vRouter-TEST-1".to_string(),
            gateway: "192.168.100.10".to_string(),
            local_id: Some("test-1@test.local".to_string()),
            auth: AuthMethod::PresharedKey(Secret::new("s3cr3t".to_string())),
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
    fn load_conn_carries_no_secret() {
        let msg = load_conn_message(&sample(), "vRouter-TEST-1");
        assert!(!msg.pretty().contains("s3cr3t"));
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
