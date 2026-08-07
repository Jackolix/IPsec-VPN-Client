//! Sophos Connect provisioning files (`.pro`).
//!
//! A `.pro` is not a connection profile and cannot be turned into one: it is a
//! pointer to a customer's user portal. The Sophos client signs the user in
//! there and downloads the real profile, which is why the file carries a
//! gateway and a portal port but no algorithms, no traffic selectors and no
//! key.
//!
//! So the importer's job here is to say so precisely, rather than fail with a
//! parse error that makes a valid file look corrupt. Actually fetching the
//! profile means an authenticated HTTPS session against the customer's portal
//! — deliberately not implemented here.

use crate::error::ImportError;
use serde::Deserialize;

/// One entry of a provisioning file. Unknown fields are ignored: the format
/// grows across Sophos Connect releases, and a field we do not read is not a
/// reason to reject the file.
#[derive(Debug, Clone, Deserialize)]
pub struct Provisioning {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub gateway: String,
    /// HTTPS port of the user portal the profile is downloaded from.
    pub user_portal_port: Option<u16>,
    /// The portal expects a one-time password as well as the user's own.
    #[serde(default)]
    pub otp: bool,
    /// Whether the client may remember the portal credentials.
    #[serde(default)]
    pub can_save_credentials: bool,
}

impl Provisioning {
    /// The user portal a person signs in to, for the UI to show or open.
    pub fn portal_url(&self) -> Option<String> {
        let host = self.gateway.trim();
        if host.is_empty() {
            return None;
        }
        Some(match self.user_portal_port {
            Some(port) if port != 443 => format!("https://{host}:{port}"),
            _ => format!("https://{host}"),
        })
    }

    pub fn label(&self) -> String {
        let name = self.display_name.trim();
        if name.is_empty() {
            self.gateway.trim().to_string()
        } else {
            name.to_string()
        }
    }
}

/// A provisioning file is a JSON array; an `.scx` profile is an object.
pub fn looks_like(input: &str) -> bool {
    parse(input).map(|p| !p.is_empty()).unwrap_or(false)
}

pub fn parse(input: &str) -> Result<Vec<Provisioning>, ImportError> {
    let entries: Vec<Provisioning> = serde_json::from_str(input)?;
    Ok(entries.into_iter().filter(|e| !e.gateway.trim().is_empty()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
        {
            "display_name": "Example IPsec VPN",
            "gateway": "203.0.113.10",
            "user_portal_port": 4443,
            "otp": false,
            "can_save_credentials": false
        }
    ]"#;

    #[test]
    fn reads_the_portal_it_points_at() {
        let entries = parse(SAMPLE).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label(), "Example IPsec VPN");
        assert_eq!(
            entries[0].portal_url().as_deref(),
            Some("https://203.0.113.10:4443")
        );
        assert!(!entries[0].can_save_credentials);
    }

    #[test]
    fn a_standard_https_port_is_left_off_the_url() {
        let entries = parse(r#"[{"gateway": "vpn.example.com", "user_portal_port": 443}]"#).unwrap();
        assert_eq!(
            entries[0].portal_url().as_deref(),
            Some("https://vpn.example.com")
        );
        // With no display name the gateway itself labels the entry.
        assert_eq!(entries[0].label(), "vpn.example.com");
    }

    #[test]
    fn entries_without_a_gateway_are_dropped() {
        assert!(parse(r#"[{"display_name": "broken"}]"#).unwrap().is_empty());
    }

    #[test]
    fn an_scx_object_is_not_a_provisioning_file() {
        assert!(!looks_like(r#"{"gateway": "203.0.113.10"}"#));
    }
}
