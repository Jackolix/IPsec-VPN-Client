//! End-to-end import of each Sophos format.
//!
//! The fixtures are redacted copies of files a real SFOS firewall produced:
//! same keys, same section chains, same quirks — notably that the identity the
//! client presents is the gateway's own public address, which both formats
//! agree on — with the pre-shared key and the customer's addresses replaced.

use sophos_profile::{detect, import_profile, Format, ImportError};
use vpn_core::{DhGroup, EncAlg, IkeIdType, IkeVersion, IntegAlg, PrfAlg};

const SCX: &str = include_str!("fixtures/connect.redacted.scx");
const TGB: &str = include_str!("fixtures/legacy.redacted.tgb");
const PRO: &str = include_str!("fixtures/portal.redacted.pro");

#[test]
fn imports_a_sophos_connect_profile() {
    let imported = import_profile(SCX).expect("scx imports");
    let c = &imported.config;

    assert_eq!(c.name, "Example IPsec");
    assert_eq!(c.gateway, "203.0.113.10");
    assert_eq!(c.ike_version, IkeVersion::V2);

    // The firewall hands the client its own public address as the identity to
    // present, and it has to go out typed as an IPv4 ID.
    assert_eq!(c.local_id.as_deref(), Some("203.0.113.10"));
    assert_eq!(c.local_id_type, Some(IkeIdType::Ipv4));

    assert_eq!(c.ike_enc, EncAlg::Aes256);
    assert_eq!(c.ike_integ, IntegAlg::Sha256);
    assert_eq!(c.ike_prf, PrfAlg::Sha256);
    assert_eq!(c.ike_dh, DhGroup::Modp2048);
    assert_eq!(c.ike_proposal(), "aes256-sha256-prfsha256-modp2048");

    assert_eq!(c.esp_enc, EncAlg::Aes256);
    assert_eq!(c.esp_integ, IntegAlg::Sha256);
    assert_eq!(c.pfs, Some(DhGroup::Modp2048));

    let subnets: Vec<String> = c.remote_subnets.iter().map(|n| n.to_string()).collect();
    assert_eq!(subnets, ["10.168.111.0/24", "198.51.100.7/32"]);

    assert!(c.request_virtual_ip, "vip 0.0.0.0 means ask for one");
    assert_eq!(c.dpd.delay_secs, 60);

    let ua = c.user_auth.as_ref().expect("xauth block means user auth");
    assert!(ua.can_save);
    assert!(!ua.otp);
    assert!(ua.username.is_none(), "the username is the user's to supply");
}

#[test]
fn imports_the_legacy_tgb_profile() {
    let imported = import_profile(TGB).expect("tgb imports");
    let c = &imported.config;

    assert_eq!(c.name, "IPsecVPN");
    // Stated outright by the file: main mode and quick mode.
    assert_eq!(c.ike_version, IkeVersion::V1);
    assert_eq!(c.gateway, "192.168.2.2");
    assert_eq!(c.local_id.as_deref(), Some("203.0.113.10"));
    assert_eq!(c.local_id_type, Some(IkeIdType::Ipv4));

    assert_eq!(c.ike_enc, EncAlg::Aes256);
    assert_eq!(c.ike_integ, IntegAlg::Sha256);
    assert_eq!(c.ike_dh, DhGroup::Modp2048);
    assert_eq!(c.esp_enc, EncAlg::Aes256);
    assert_eq!(c.esp_integ, IntegAlg::Sha256);
    assert_eq!(c.pfs, Some(DhGroup::Modp2048), "PFSGRP14 in phase 2");

    // 0.0.0.0/0.0.0.0 is how these profiles say "full tunnel".
    assert_eq!(c.remote_subnets.len(), 1);
    assert_eq!(c.remote_subnets[0].to_string(), "0.0.0.0/0");

    assert_eq!(c.dpd.delay_secs, 60, "from [General] DPD-interval");
    assert!(c.user_auth.is_none(), "Xauth = 0");
}

/// The export was generated against the firewall's internal interface, so the
/// address in it is not reachable from outside — the import has to say so
/// rather than leave the user with a connection that just times out.
#[test]
fn warns_that_a_private_gateway_will_not_be_reachable() {
    let imported = import_profile(TGB).unwrap();
    assert!(
        imported
            .warnings
            .iter()
            .any(|w| w.0.contains("192.168.2.2") && w.0.contains("private")),
        "expected a warning about the private gateway, got: {:?}",
        imported.warnings
    );
}

#[test]
fn scx_warns_that_the_second_auth_round_is_a_guess() {
    let imported = import_profile(SCX).unwrap();
    assert!(
        imported
            .warnings
            .iter()
            .any(|w| w.0.contains("EAP-MSCHAPv2") && w.0.contains("unconfirmed")),
        "got: {:?}",
        imported.warnings
    );
}

/// The one thing that must never happen: a parse error, a warning or any other
/// user-visible text quoting the key back out of the file.
#[test]
fn no_warning_ever_repeats_the_pre_shared_key() {
    for input in [SCX, TGB] {
        let imported = import_profile(input).unwrap();
        for w in &imported.warnings {
            assert!(
                !w.0.contains("REDACTED-NOT-A-REAL-KEY"),
                "warning leaked the key: {w}"
            );
        }
        // Debug on the config redacts it too — that is what gets logged.
        let dumped = format!("{:?}", imported.config);
        assert!(!dumped.contains("REDACTED-NOT-A-REAL-KEY"), "{dumped}");
    }
}

#[test]
fn a_provisioning_file_is_recognised_but_not_a_connection() {
    assert_eq!(detect(PRO), Some(Format::Provisioning));
    assert!(matches!(
        import_profile(PRO),
        Err(ImportError::IsProvisioning)
    ));

    let entries = sophos_profile::pro::parse(PRO).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].portal_url().as_deref(),
        Some("https://203.0.113.10:4443")
    );
}

#[test]
fn each_fixture_is_detected_as_its_own_format() {
    assert_eq!(detect(SCX), Some(Format::Connect));
    assert_eq!(detect(TGB), Some(Format::Legacy));
}

/// A truncated file must fail cleanly rather than import half a connection.
#[test]
fn a_tgb_missing_a_referenced_section_is_refused() {
    let broken = TGB.replace("[AES256-SHA2_256-GRP14]", "[SOMETHING-ELSE]");
    assert!(matches!(
        import_profile(&broken),
        Err(ImportError::SectionNotFound(_))
    ));
}

/// Aggressive mode leaks the PSK hash and needs a flag the model does not
/// carry, so it must be refused, not quietly downgraded to main mode.
#[test]
fn aggressive_mode_is_refused() {
    let aggressive = TGB.replace("EXCHANGE_TYPE = ID_PROT", "EXCHANGE_TYPE = AGGRESSIVE");
    assert!(matches!(
        import_profile(&aggressive),
        Err(ImportError::Unsupported(_))
    ));
}
