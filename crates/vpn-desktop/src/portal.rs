//! Download a profile from the Sophos user portal a `.pro` points at.
//!
//! A `.pro` provisioning file carries no connection — only the address of a
//! user portal. Rather than make the user open a browser, sign in, find the
//! right download and re-import it, this reproduces what the portal's own web
//! app does: sign in, take the CSRF token the session hands back, and pull the
//! IPsec configuration. The portal serves it as an Apple `.mobileconfig`, which
//! [`sophos_profile`] already imports.
//!
//! SECURITY: the downloaded `.mobileconfig` contains a live pre-shared key. It
//! is handled exactly like an imported file — written to the profile directory,
//! never logged. The portal password is used for the sign-in and dropped; it is
//! never stored here.

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

/// Sign in to the portal and download the IPsec profile, returning the
/// `.mobileconfig` text. Errors carry no secret and are safe to show.
pub fn download_ipsec_profile(
    portal_url: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let base = portal_url.trim().trim_end_matches('/');
    // The portal address comes from the .pro, but it still reaches a network
    // client, so hold it to https and a sane length before using it.
    if !base.starts_with("https://") {
        return Err("the portal address must be an https URL".to_string());
    }
    if base.len() > 300 {
        return Err("the portal address is implausibly long".to_string());
    }
    if username.trim().is_empty() {
        return Err("the portal username cannot be empty".to_string());
    }
    if password.is_empty() {
        return Err("the portal password cannot be empty".to_string());
    }

    let client = reqwest::blocking::Client::builder()
        // The session rides a cookie across the three calls below.
        .cookie_store(true)
        // Sophos appliances present a self-signed certificate; the Sophos client
        // accepts it too. Trust here rests on the credentials and on the key the
        // download returns, not on a public CA.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("could not create the portal client: {e}"))?;

    // 1. Sign in. 200 = signed in; 299 = the portal wants a one-time code next.
    let login = client
        .post(format!("{base}/api/v1/vpnportal/login"))
        .header("Content-Type", "application/json; charset=utf-8")
        .body(
            serde_json::json!({ "username": username, "password": password }).to_string(),
        )
        .send()
        .map_err(|e| format!("could not reach the portal: {e}"))?;
    match login.status().as_u16() {
        200 => {}
        299 => {
            return Err(
                "this portal requires a one-time code as well as the password, which is not \
                 supported yet"
                    .to_string(),
            )
        }
        401 | 403 => return Err("the portal rejected the username or password".to_string()),
        other => {
            return Err(format!(
                "portal sign-in failed (HTTP {other}) — check the username and password"
            ))
        }
    }

    // 2. Read the session's CSRF token (returned as a response header) and which
    //    IPsec authentication the portal is configured for.
    let user_config = client
        .get(format!("{base}/api/v1/vpnportal/user-config"))
        .send()
        .map_err(|e| format!("portal query failed: {e}"))?;
    match user_config.status().as_u16() {
        200 => {}
        401 | 403 => {
            return Err("the portal rejected the username or password".to_string())
        }
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

    // 3. Download the IPsec profile. The endpoint needs the CSRF token as a
    //    header; the body is empty for a pre-shared-key profile.
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
