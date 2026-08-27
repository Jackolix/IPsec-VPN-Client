//! Desktop-side support for Sophos SSL VPN (OpenVPN) profiles.
//!
//! An `.ovpn` is not an IPsec profile — it cannot be parsed into a
//! [`vpn_core::ConnectionConfig`], and it is not carried by charon. It is driven
//! by the privileged broker, which runs a real `openvpn` process (see
//! `vpn-broker`'s `openvpn` module). This module reads the little metadata the
//! GUI needs to display, and relays connect/disconnect/status to the broker over
//! its pipe.
//!
//! The `.ovpn` holds a live private key. It is only ever read from the profile
//! directory and handed straight to the broker; it is never logged here.

use serde::Serialize;

/// The display metadata read out of an `.ovpn`: where it connects and how.
#[derive(Debug, Clone, Serialize)]
pub struct SslMeta {
    pub gateway: String,
    pub port: String,
    pub proto: String,
    /// Whether the profile asks for a username and password (`auth-user-pass`).
    pub needs_user: bool,
}

/// A live SSL tunnel as the broker reports it.
#[derive(Debug, Clone, Default)]
pub struct SslStatus {
    /// The connection name the tunnel was started under.
    pub name: String,
    /// The assigned virtual IP (may be empty briefly).
    pub ip: String,
    /// The gateway pushed `redirect-gateway`: this tunnel took the default
    /// route, so no other tunnel may also claim it.
    ///
    /// (The broker also reports the pushed DNS domain, but keeps it to itself:
    /// it is only needed there, to stop an NRPT rule overriding the resolution
    /// this tunnel already has on its own adapter.)
    pub full: bool,
}

/// A failed SSL connect: a short `reason` for the banner, and openvpn's captured
/// output (`log`, possibly empty and multi-line) for the log panel.
#[derive(Debug, Clone)]
pub struct SslError {
    pub reason: String,
    pub log: String,
}

/// Cheap structural check that `text` is an OpenVPN client config, not an HTML
/// error page or an IPsec profile. An `.ovpn` names a `remote` and declares
/// itself a `client`/`dev tun` or inlines its CA.
pub fn looks_like_ovpn(text: &str) -> bool {
    let has_remote = text.lines().any(|l| l.trim_start().starts_with("remote "));
    let has_client_marker = text.lines().any(|l| {
        let l = l.trim_start();
        l == "client" || l.starts_with("dev tun") || l.starts_with("<ca>")
    });
    has_remote && has_client_marker
}

/// Read display metadata from an `.ovpn`: the `remote host port`, the `proto`,
/// and whether it uses `auth-user-pass`.
pub fn parse_meta(text: &str) -> SslMeta {
    let mut gateway = String::new();
    let mut port = String::new();
    let mut proto = String::new();
    let mut needs_user = false;

    for raw in text.lines() {
        let line = raw.trim();
        let mut it = line.split_whitespace();
        match it.next() {
            Some("remote") if gateway.is_empty() => {
                gateway = it.next().unwrap_or("").to_string();
                port = it.next().unwrap_or("").to_string();
            }
            Some("proto") => proto = it.next().unwrap_or("").to_string(),
            Some("auth-user-pass") => needs_user = true,
            _ => {}
        }
    }
    SslMeta { gateway, port, proto, needs_user }
}

/// Ask the privileged helper to bring up the SSL tunnel `name` from `config`,
/// answering its `auth-user-pass` round with `username`/`password`. Returns the
/// assigned IP.
///
/// Windows and macOS reach their helper through the same request, so the body
/// is shared; only the transport under [`helper_request`] differs.
#[cfg(any(windows, target_os = "macos"))]
pub fn connect(
    name: &str,
    config: &str,
    username: &str,
    password: &str,
    allow_full: bool,
) -> Result<String, SslError> {
    let resp = helper_request(&vpn_broker::protocol::Request::SslConnect {
        name: name.to_string(),
        config: config.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        allow_full,
    })
    .map_err(|e| SslError {
        reason: format!("the VPN helper is not reachable: {e}"),
        log: String::new(),
    })?;
    if resp.ok {
        Ok(resp.msg)
    } else {
        Err(parse_ssl_error(&resp.msg))
    }
}

/// The broker encodes an SSL connect failure as JSON `{"reason","log"}` so the
/// short reason and openvpn's output travel separately. A failure that isn't
/// that shape (a transport-level error) is taken verbatim as the reason.
#[cfg(any(windows, target_os = "macos"))]
fn parse_ssl_error(msg: &str) -> SslError {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(msg) {
        if let Some(reason) = v.get("reason").and_then(|s| s.as_str()) {
            return SslError {
                reason: reason.to_string(),
                log: v.get("log").and_then(|s| s.as_str()).unwrap_or_default().to_string(),
            };
        }
    }
    SslError { reason: msg.to_string(), log: String::new() }
}

/// Ask the broker to tear down the SSL tunnel called `name`, if it is up. Other
/// SSL tunnels are left alone.
#[cfg(any(windows, target_os = "macos"))]
pub fn disconnect(name: &str) -> Result<(), String> {
    let resp = helper_request(&vpn_broker::protocol::Request::SslDisconnect {
        name: name.to_string(),
    })
    .map_err(|e| format!("the VPN helper is not reachable: {e}"))?;
    if resp.ok {
        Ok(())
    } else {
        Err(resp.msg)
    }
}

/// Ask the privileged helper which SSL tunnels are up. Empty when none is.
#[cfg(any(windows, target_os = "macos"))]
pub fn status() -> Result<Vec<SslStatus>, String> {
    let resp = helper_request(&vpn_broker::protocol::Request::SslStatus)
        .map_err(|e| format!("the VPN helper is not reachable: {e}"))?;
    if !resp.ok {
        return Err(resp.msg);
    }
    if resp.msg.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value = serde_json::from_str(&resp.msg)
        .map_err(|e| format!("could not read the helper's SSL status: {e}"))?;
    Ok(parse_status(&v))
}

/// Read the broker's SSL status payload. It is an array since concurrent
/// tunnels became possible; a bare object is what a broker older than the app
/// (an upgrade that left the service binary behind) still sends, and is read as
/// the single tunnel it means.
#[cfg(any(windows, target_os = "macos"))]
fn parse_status(v: &serde_json::Value) -> Vec<SslStatus> {
    let one = |o: &serde_json::Value| SslStatus {
        name: o.get("name").and_then(|s| s.as_str()).unwrap_or_default().to_string(),
        ip: o.get("ip").and_then(|s| s.as_str()).unwrap_or_default().to_string(),
        // Absent from an older broker's reply: read as "not a full tunnel",
        // which is all it could report before it looked.
        full: o.get("full").and_then(|s| s.as_bool()).unwrap_or(false),
    };
    match v.as_array() {
        Some(items) => items.iter().map(one).collect(),
        None => vec![one(v)],
    }
}

/// One request to whichever privileged helper this platform has.
///
/// The protocol is the same on both; the transport is not — an ACL'd named pipe
/// on Windows, a Unix socket on macOS — so this is the single place the two
/// diverge, and every caller above is written once.
#[cfg(any(windows, target_os = "macos"))]
fn helper_request(
    req: &vpn_broker::protocol::Request,
) -> Result<vpn_broker::protocol::Response, String> {
    #[cfg(windows)]
    {
        vpn_broker::client::request(req)
    }
    #[cfg(target_os = "macos")]
    {
        vpn_broker::unix_client::request(req)
    }
}

// On Linux there is no privileged helper, so SSL VPN is unavailable; keep the
// surface present so the rest of the app builds on CI.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn connect(
    _name: &str,
    _config: &str,
    _username: &str,
    _password: &str,
    _allow_full: bool,
) -> Result<String, SslError> {
    Err(SslError {
        reason: "SSL VPN needs a privileged helper, which this platform has none of"
            .to_string(),
        log: String::new(),
    })
}
#[cfg(not(any(windows, target_os = "macos")))]
pub fn disconnect(_name: &str) -> Result<(), String> {
    Err("SSL VPN needs a privileged helper, which this platform has none of".to_string())
}
#[cfg(not(any(windows, target_os = "macos")))]
pub fn status() -> Result<Vec<SslStatus>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "client\ndev tun\nproto tcp\nremote vpn.example.com 8443\n\
                          auth-user-pass\ncipher AES-128-CBC\n<ca>\nx\n</ca>\n";

    #[test]
    fn detects_ovpn() {
        assert!(looks_like_ovpn(SAMPLE));
        assert!(!looks_like_ovpn("<!DOCTYPE html><html></html>"));
        assert!(!looks_like_ovpn(""));
    }

    #[test]
    fn reads_remote_and_auth() {
        let m = parse_meta(SAMPLE);
        assert_eq!(m.gateway, "vpn.example.com");
        assert_eq!(m.port, "8443");
        assert_eq!(m.proto, "tcp");
        assert!(m.needs_user);
    }

    #[test]
    fn first_remote_wins() {
        let m = parse_meta("remote a.example 1\nremote b.example 2\n");
        assert_eq!(m.gateway, "a.example");
        assert_eq!(m.port, "1");
    }

    #[cfg(windows)]
    #[test]
    fn parses_structured_and_plain_failures() {
        // The broker's JSON shape splits into reason + log.
        let e = parse_ssl_error(r#"{"reason":"the gateway rejected the username or password","log":"line1\nline2"}"#);
        assert_eq!(e.reason, "the gateway rejected the username or password");
        assert_eq!(e.log, "line1\nline2");
        // A non-JSON failure is taken verbatim as the reason, with no log.
        let e = parse_ssl_error("the VPN helper is not reachable: pipe closed");
        assert_eq!(e.reason, "the VPN helper is not reachable: pipe closed");
        assert!(e.log.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn reads_both_status_shapes() {
        let list: serde_json::Value =
            serde_json::from_str(r#"[{"name":"a","ip":"10.1.1.2"},{"name":"b","ip":"10.2.2.2"}]"#)
                .unwrap();
        let got = parse_status(&list);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].name, "b");
        assert_eq!(got[1].ip, "10.2.2.2");

        // An older broker (one that predates concurrent tunnels) still sends a
        // bare object; read it as the single tunnel it means.
        let one: serde_json::Value = serde_json::from_str(r#"{"name":"a","ip":"10.1.1.2"}"#).unwrap();
        let got = parse_status(&one);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "a");
    }
}
