//! Wire protocol between the GUI (client) and the broker service (server).
//!
//! One request, one response, newline-delimited JSON. Kept deliberately tiny:
//! the broker runs as LocalSystem, so its command surface is a liability — the
//! GUI can only ask it to route DNS for a connection or undo it. It cannot make
//! the broker run arbitrary commands, and the DNS servers it names are still
//! validated as IPv4 addresses on the far side.

use serde::{Deserialize, Serialize};

/// The named pipe the broker listens on. `\\.\pipe\...` is the Windows local
/// pipe namespace; access is restricted by the pipe's DACL (see the server).
pub const PIPE_NAME: &str = r"\\.\pipe\ipsec-vpn-broker";

/// SCM service name (used by install/uninstall and status checks).
pub const SERVICE_NAME: &str = "ipsec-vpn-broker";

/// Human-facing service display name.
pub const SERVICE_DISPLAY_NAME: &str = "IPsec VPN Broker";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Liveness check — the GUI uses this to decide whether the broker is
    /// installed and reachable (and thus whether it can skip the UAC path).
    Ping,
    /// Route DNS for `conn` over the tunnel via an NRPT rule. `servers` are
    /// IPv4 text; `domain` scopes it to a suffix (split-DNS) when present.
    ApplyDns {
        conn: String,
        servers: Vec<String>,
        domain: Option<String>,
    },
    /// Remove the NRPT rule previously applied for `conn`.
    RevertDns { conn: String },
    /// Bring up an SSL VPN (OpenVPN) tunnel. The broker runs `openvpn` as
    /// LocalSystem — which is what installs the adapter and routes the
    /// unelevated GUI cannot — after sanitising the config. `config` is the
    /// `.ovpn` text (which carries a private key); `username`/`password` answer
    /// its `auth-user-pass` round. On success the response `msg` is the assigned
    /// tunnel IP.
    SslConnect {
        /// The connection name the GUI keys this tunnel by (a sanitized profile
        /// name); echoed back by [`Request::SslStatus`] so status/disconnect can
        /// map to the right profile.
        name: String,
        config: String,
        username: String,
        password: String,
    },
    /// Tear down the SSL VPN tunnel, if one is up.
    SslDisconnect,
    /// Report the SSL VPN tunnel state. Response `msg` is a JSON object
    /// `{"name","ip"}` when a tunnel is up, or empty when none is.
    SslStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    /// On success, a short human summary (may be empty). On failure, the error.
    pub msg: String,
}

impl Response {
    pub fn ok(msg: impl Into<String>) -> Self {
        Response { ok: true, msg: msg.into() }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Response { ok: false, msg: msg.into() }
    }
}
