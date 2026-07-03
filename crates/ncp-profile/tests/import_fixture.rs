//! End-to-end fixture test: NCP ini -> config model -> swanctl.conf.
//!
//! The fixture is a structural copy of the real EFA_MDT_42 export with the
//! PSK and production gateway replaced. This pins the code-mapping table:
//! any change to how codes are interpreted shows up here.

use ncp_profile::import_profile;
use vpn_core::swanctl::{render, SecretRendering};
use vpn_core::{AuthMethod, DhGroup, EncAlg, IntegAlg, PrfAlg};

const FIXTURE: &str = include_str!("fixtures/efa_mdt_42.redacted.ini");

#[test]
fn imports_sample_profile() {
    let imported = import_profile(FIXTURE).expect("fixture must import");
    let c = &imported.config;

    assert_eq!(c.name, "EFA_MDT_42");
    assert_eq!(c.gateway, "gateway.example.test");
    assert_eq!(c.local_id.as_deref(), Some("efa_mdt_42"));
    assert_eq!(c.ike_enc, EncAlg::Aes256);
    assert_eq!(c.ike_integ, IntegAlg::Sha256);
    assert_eq!(c.ike_prf, PrfAlg::Sha256);
    assert_eq!(c.ike_dh, DhGroup::Modp3072);
    assert_eq!(c.esp_enc, EncAlg::Aes256);
    assert_eq!(c.esp_integ, IntegAlg::Sha256);
    assert_eq!(c.pfs, Some(DhGroup::Modp3072));
    assert_eq!(c.remote_subnets.len(), 1);
    assert_eq!(c.remote_subnets[0].to_string(), "10.102.15.0/24");
    assert!(c.request_virtual_ip);
    assert!(!c.compression);

    let AuthMethod::PresharedKey(psk) = &c.auth;
    assert_eq!(psk.expose(), "REDACTED-PSK-PLACEHOLDER");
    // The Debug impl must never leak the secret.
    assert!(!format!("{:?}", c).contains("REDACTED-PSK-PLACEHOLDER"));
}

#[test]
fn warning_expectations_match_confidence_levels() {
    let imported = import_profile(FIXTURE).unwrap();
    let all = imported
        .warnings
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    // Algorithm codes were confirmed live against a LANCOM vRouter
    // (2026-07-03, see codes.rs) and must no longer warn.
    for confirmed in ["Ikev2Crypt", "Ikev2PRF", "Ikev2IntAlgo", "IpsecAuth", "IkeDhGroup"] {
        assert!(
            !all.contains(confirmed),
            "{confirmed} is confirmed High and should not warn:\n{all}"
        );
    }
    // Fields we deliberately ignore must still be surfaced.
    assert!(all.contains("SeamRoaming"), "missing ignored-field warning:\n{all}");
}

#[test]
fn renders_expected_swanctl_conf() {
    let imported = import_profile(FIXTURE).unwrap();
    let conf = render(&imported.config, SecretRendering::Include);

    assert!(conf.contains("version = 2"));
    assert!(conf.contains("remote_addrs = gateway.example.test"));
    assert!(conf.contains("proposals = aes256-sha256-prfsha256-modp3072"));
    assert!(conf.contains("esp_proposals = aes256-sha256-modp3072"));
    assert!(conf.contains("remote_ts = 10.102.15.0/24"));
    assert!(conf.contains("vips = 0.0.0.0"));
    assert!(conf.contains("id = \"efa_mdt_42\""));
    assert!(conf.contains("secret = \"REDACTED-PSK-PLACEHOLDER\""));
    assert!(!conf.contains("ipcomp"));

    let redacted = render(&imported.config, SecretRendering::Redact);
    assert!(!redacted.contains("REDACTED-PSK-PLACEHOLDER"));
    assert!(redacted.contains("***REDACTED***"));
}

#[test]
fn unknown_algorithm_code_fails_loud() {
    let mutated = FIXTURE.replace("Ikev2Crypt=6", "Ikev2Crypt=99");
    let err = import_profile(&mutated).unwrap_err();
    assert!(err.to_string().contains("Ikev2Crypt=99"));
}

#[test]
fn unknown_auth_method_fails_loud() {
    let mutated = FIXTURE.replace("IKEv2Auth=2", "IKEv2Auth=7");
    assert!(import_profile(&mutated).is_err());
}

#[test]
fn non_ikev2_profile_is_rejected() {
    let mutated = FIXTURE.replace("ExchMode=34", "ExchMode=2");
    assert!(import_profile(&mutated).is_err());
}

#[test]
fn hostile_gateway_is_rejected() {
    let mutated = FIXTURE.replace(
        "Gateway=gateway.example.test",
        "Gateway=evil }\ninjected = 1",
    );
    assert!(import_profile(&mutated).is_err());
}
