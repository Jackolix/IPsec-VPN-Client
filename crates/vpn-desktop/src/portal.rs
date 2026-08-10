//! Download a profile from the Sophos user portal a `.pro` points at.
//!
//! A `.pro` provisioning file carries no connection — only the address of a
//! user portal. Rather than make the user open a browser, sign in, find the
//! right download and re-import it, this reproduces what the portal's own web
//! app does: sign in, take the CSRF token the session hands back, and pull the
//! configuration. Two kinds are available:
//!
//!   * IPsec, served as an Apple `.mobileconfig` — [`download_ipsec_profile`],
//!     which [`sophos_profile`] already imports.
//!   * SSL VPN, served as an OpenVPN `.ovpn` — [`download_ssl_profile`]. This is
//!     a stock OpenVPN config with an embedded per-user client certificate; the
//!     IPsec datapath cannot carry it, so for now it is downloaded for
//!     inspection ahead of a dedicated OpenVPN engine.
//!
//! SECURITY: both downloads carry live secrets — the `.mobileconfig` a
//! pre-shared key, the `.ovpn` a private key. They are handled exactly like an
//! imported file — written to disk, never logged. The portal password is used
//! for the sign-in and dropped; it is never stored here. Errors are built to
//! carry no secret and are safe to show.

use serde::Serialize;
use std::time::Duration;

/// What a `.pro` points at: the portal to sign in to, a suggested profile name,
/// and whether it expects a one-time code (which we cannot do yet).
#[derive(Debug, Clone, Serialize)]
pub struct PortalTarget {
    pub url: String,
    pub name: String,
    pub otp: bool,
}

/// Read the portal a provisioning file points at, or `None` if the text is not
/// a `.pro` with a usable portal address.
pub fn target(text: &str) -> Option<PortalTarget> {
    let entry = sophos_profile::pro::parse(text).ok()?.into_iter().next()?;
    Some(PortalTarget {
        url: entry.portal_url()?,
        name: entry.label(),
        otp: entry.otp,
    })
}

/// Normalise and sanity-check the portal address. It comes from the `.pro`, but
/// it still reaches a network client, so hold it to https and a sane length
/// before using it. Returns the trailing-slash-trimmed base.
fn normalized_base(portal_url: &str) -> Result<String, String> {
    let base = portal_url.trim().trim_end_matches('/');
    if !base.starts_with("https://") {
        return Err("the portal address must be an https URL".to_string());
    }
    if base.len() > 300 {
        return Err("the portal address is implausibly long".to_string());
    }
    Ok(base.to_string())
}

/// Reject empty credentials before spending a round-trip on them.
fn validate_credentials(username: &str, password: &str) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("the portal username cannot be empty".to_string());
    }
    if password.is_empty() {
        return Err("the portal password cannot be empty".to_string());
    }
    Ok(())
}

/// A blocking HTTP client configured for a Sophos user portal.
fn portal_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        // The session rides a cookie across the calls below.
        .cookie_store(true)
        // Sophos appliances present a self-signed certificate; the Sophos client
        // accepts it too. Trust here rests on the credentials and on the key the
        // download returns, not on a public CA.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("could not create the portal client: {e}"))
}

/// Sign in to the portal. 200 = signed in; 299 = the portal wants a one-time
/// code, which we cannot answer yet.
fn sign_in(
    client: &reqwest::blocking::Client,
    base: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let login = client
        .post(format!("{base}/api/v1/vpnportal/login"))
        .header("Content-Type", "application/json; charset=utf-8")
        .body(serde_json::json!({ "username": username, "password": password }).to_string())
        .send()
        .map_err(|e| format!("could not reach the portal: {e}"))?;
    match login.status().as_u16() {
        200 => Ok(()),
        299 => Err(
            "this portal requires a one-time code as well as the password, which is not \
             supported yet"
                .to_string(),
        ),
        401 | 403 => Err("the portal rejected the username or password".to_string()),
        other => Err(format!(
            "portal sign-in failed (HTTP {other}) — check the username and password"
        )),
    }
}

/// After sign-in, read the session's CSRF token (returned as a response header)
/// and the portal's per-user configuration (which services are enabled and how
/// they authenticate). Both downloads need the CSRF token.
fn session_config(
    client: &reqwest::blocking::Client,
    base: &str,
) -> Result<(String, serde_json::Value), String> {
    let user_config = client
        .get(format!("{base}/api/v1/vpnportal/user-config"))
        .send()
        .map_err(|e| format!("portal query failed: {e}"))?;
    match user_config.status().as_u16() {
        200 => {}
        401 | 403 => return Err("the portal rejected the username or password".to_string()),
        other => return Err(format!("portal query failed (HTTP {other})")),
    }
    let csrf = user_config
        .headers()
        .get("X-Csrf-Token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or("the portal did not return a session token")?;
    let cfg: serde_json::Value = user_config
        .json()
        .map_err(|e| format!("could not read the portal's response: {e}"))?;
    Ok((csrf, cfg))
}

/// Sign in and report the portal's advertised, non-secret service flags — which
/// of IPsec / SSL VPN are enabled for this user and how they authenticate.
///
/// Used for diagnosis, so it only surfaces short scalar fields (flags like
/// `ipsec: "on"`, `sslvpn: "off"`, `ipsecauthtype: "psk"`). Anything long enough
/// to be a key or certificate is deliberately withheld.
pub fn services(portal_url: &str, username: &str, password: &str) -> Result<String, String> {
    let base = normalized_base(portal_url)?;
    validate_credentials(username, password)?;

    let client = portal_client()?;
    sign_in(&client, &base, username, password)?;
    let (_csrf, cfg) = session_config(&client, &base)?;

    let obj = cfg
        .as_object()
        .ok_or("the portal's response was not a configuration object")?;
    let mut lines: Vec<String> = obj
        .iter()
        .filter_map(|(k, v)| match v {
            serde_json::Value::Bool(b) => Some(format!("{k} = {b}")),
            serde_json::Value::Number(n) => Some(format!("{k} = {n}")),
            // Short strings are flags (on/off/psk/cert); long ones may be secrets.
            serde_json::Value::String(s) if s.len() <= 40 => Some(format!("{k} = {s}")),
            _ => None,
        })
        .collect();
    lines.sort();
    Ok(lines.join("\n"))
}

/// Sign in to the portal and download the IPsec profile, returning the
/// `.mobileconfig` text.
pub fn download_ipsec_profile(
    portal_url: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let base = normalized_base(portal_url)?;
    validate_credentials(username, password)?;

    let client = portal_client()?;
    sign_in(&client, &base, username, password)?;
    let (csrf, cfg) = session_config(&client, &base)?;

    if cfg.get("ipsec").and_then(|v| v.as_str()) == Some("off") {
        return Err("IPsec is disabled for this user on the portal".to_string());
    }
    match cfg.get("ipsecauthtype").and_then(|v| v.as_str()).unwrap_or("psk") {
        "psk" => {}
        "cert" => {
            return Err(
                "this portal authenticates IPsec with a certificate, which is not supported yet \
                 (only pre-shared key)"
                    .to_string(),
            )
        }
        other => {
            return Err(format!(
                "this portal authenticates IPsec with '{other}', which is not supported"
            ))
        }
    }

    // Download the IPsec profile. The endpoint needs the CSRF token as a header;
    // the body is empty for a pre-shared-key profile.
    let download = client
        .post(format!("{base}/api/v1/vpnportal/ipsec/ios-config"))
        .header("X-Csrf-Token", csrf)
        .header("Content-Type", "application/json; charset=utf-8")
        .body("")
        .send()
        .map_err(|e| format!("profile download failed: {e}"))?;
    if !download.status().is_success() {
        return Err(format!(
            "the portal refused the profile download (HTTP {})",
            download.status().as_u16()
        ));
    }
    let text = download
        .text()
        .map_err(|e| format!("could not read the downloaded profile: {e}"))?;

    // Make sure we got a profile we can actually import, not an error page.
    if !matches!(
        sophos_profile::detect(&text),
        Some(sophos_profile::Format::MobileConfig)
    ) {
        return Err(
            "the portal did not return an IPsec profile — it may not offer one for this user"
                .to_string(),
        );
    }
    Ok(text)
}

/// Sign in to the portal and download the SSL VPN profile, returning the
/// `.ovpn` text.
///
/// This is a stock OpenVPN configuration with an embedded per-user client
/// certificate and key. The IPsec datapath cannot carry it — driving it needs a
/// separate OpenVPN engine — so today this exists to pull the real config for
/// inspection ahead of that engine.
pub fn download_ssl_profile(
    portal_url: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let base = normalized_base(portal_url)?;
    validate_credentials(username, password)?;

    let client = portal_client()?;
    sign_in(&client, &base, username, password)?;
    let (_csrf, cfg) = session_config(&client, &base)?;

    // The portal reports SSL VPN availability under `sslvpn`; when it is
    // explicitly off there is nothing to download. An unknown/absent field is
    // not treated as off, so a portal that names it differently still proceeds.
    if cfg.get("sslvpn").and_then(|v| v.as_str()) == Some("off") {
        return Err("SSL VPN is disabled for this user on the portal".to_string());
    }

    // Download the OpenVPN profile. Unlike the IPsec download this is a plain
    // GET authenticated by the session cookie alone — no CSRF token or body —
    // matching the portal's own client. `generic-v3-config` is the current
    // (v3) config format; the portal also serves an older `generic-config`.
    let download = client
        .get(format!("{base}/api/v1/vpnportal/sslvpn/generic-v3-config"))
        .send()
        .map_err(|e| format!("profile download failed: {e}"))?;
    if !download.status().is_success() {
        return Err(format!(
            "the portal refused the SSL VPN download (HTTP {})",
            download.status().as_u16()
        ));
    }
    let text = download
        .text()
        .map_err(|e| format!("could not read the downloaded profile: {e}"))?;

    // Make sure we got an OpenVPN config, not an error page. The `sophos_profile`
    // importer does not know `.ovpn`, so check for the config's own markers.
    if !looks_like_ovpn(&text) {
        return Err(
            "the portal did not return an SSL VPN profile — it may not offer one for this user"
                .to_string(),
        );
    }
    Ok(text)
}

/// Cheap structural check that `text` is an OpenVPN client config, not an HTML
/// error page or an empty body. An `.ovpn` names a `remote` and either declares
/// itself a `client`/`dev tun` or inlines its CA — HTML has none of these.
fn looks_like_ovpn(text: &str) -> bool {
    let has_remote = text
        .lines()
        .any(|l| l.trim_start().starts_with("remote "));
    let has_client_marker = text.lines().any(|l| {
        let l = l.trim_start();
        l == "client" || l.starts_with("dev tun") || l.starts_with("<ca>")
    });
    has_remote && has_client_marker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_an_ovpn() {
        let ovpn = "client\ndev tun\nproto tcp\nremote vpn.example.com 8443\n<ca>\n-----BEGIN CERTIFICATE-----\n";
        assert!(looks_like_ovpn(ovpn));
    }

    #[test]
    fn rejects_an_html_error_page() {
        let html = "<!DOCTYPE html>\n<html><body>Access denied</body></html>";
        assert!(!looks_like_ovpn(html));
    }

    #[test]
    fn rejects_an_empty_body() {
        assert!(!looks_like_ovpn(""));
    }

    #[test]
    fn needs_more_than_a_remote_line() {
        // A stray "remote " in prose must not read as a config.
        assert!(!looks_like_ovpn("please connect to the remote server"));
    }
}
