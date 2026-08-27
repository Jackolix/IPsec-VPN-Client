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

/// The Unix socket the macOS helper listens on, and the launchd label /
/// install paths that go with it.
///
/// The helper binary and charon are installed OUTSIDE the app bundle, under
/// root-owned directories. That is not tidiness: launchd runs the helper as
/// root, and the helper execs charon as root, so both must live somewhere an
/// unprivileged user cannot write. An app bundle in ~/Applications or
/// ~/Downloads is user-writable — pointing root at a binary in there would let
/// any local user swap it and be root.
pub const MACOS_SOCKET: &str = "/var/run/ipsec-vpn/helper.sock";
pub const MACOS_LABEL: &str = "dev.jackolix.ipsecvpn.helper";
pub const MACOS_PLIST: &str = "/Library/LaunchDaemons/dev.jackolix.ipsecvpn.helper.plist";
pub const MACOS_HELPER_BIN: &str = "/Library/PrivilegedHelperTools/dev.jackolix.ipsecvpn.helper";
pub const MACOS_SUPPORT_DIR: &str = "/Library/Application Support/dev.jackolix.ipsecvpn";
/// Where the helper looks for charon. Derived from [`MACOS_SUPPORT_DIR`] and
/// never taken from a request — see the module note above.
pub const MACOS_CHARON_DIR: &str = "/Library/Application Support/dev.jackolix.ipsecvpn/charon";
/// Runtime state: the two sockets, charon's log, the captured resolv.conf and
/// the DNS records. Cleared on boot by the OS, and by `vpn-broker uninstall`.
pub const MACOS_RUN_DIR: &str = "/var/run/ipsec-vpn";
/// The helper's own stderr. In /var/log rather than [`MACOS_RUN_DIR`] because
/// launchd will not create a missing directory for a `StandardErrorPath`, and
/// /var/run does not survive a reboot.
pub const MACOS_HELPER_LOG: &str = "/var/log/ipsec-vpn-helper.log";

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
    ///
    /// With no `domain` the rule would have to claim the catch-all namespace,
    /// which is system-wide and cannot be shared — so only the first connection
    /// gets it. A later one is scoped to the reverse-lookup zones of `subnets`
    /// instead (`10.0.0.0/8` -> `10.in-addr.arpa`), which at least resolves
    /// addresses on its own network without hijacking anyone else's names.
    /// `subnets` is CIDR text and may be empty.
    ApplyDns {
        conn: String,
        servers: Vec<String>,
        domain: Option<String>,
        #[serde(default)]
        subnets: Vec<String>,
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
        /// map to the right profile. Connecting a name that is already up
        /// replaces that tunnel and leaves any other one alone.
        name: String,
        config: String,
        username: String,
        password: String,
        /// May this tunnel take the default route? The GUI says no when another
        /// tunnel — on either datapath — already routes everything, and the
        /// broker then refuses the gateway's `redirect-gateway` at the push,
        /// before any route is installed. Defaults to permitting it, which is
        /// both the old behaviour and what an older GUI's request means.
        #[serde(default = "permitted")]
        allow_full: bool,
    },
    /// Tear down the SSL VPN tunnel called `name`. An empty name means *all* of
    /// them — which is also what an older GUI's name-less request decodes to,
    /// since it predates concurrent tunnels and only ever had one to mean.
    SslDisconnect {
        #[serde(default)]
        name: String,
    },
    /// Report the SSL VPN tunnels that are up. Response `msg` is a JSON array of
    /// `{"name","ip","full","domain"}` objects, or empty when none is up.
    SslStatus,
    /// Start the native strongSwan daemon, and report when its vici socket is
    /// up. macOS only — the Windows broker supervises `charon-svc.exe` as part
    /// of its own service lifecycle, so it has no equivalent request.
    ///
    /// Deliberately carries NO arguments. The helper resolves charon from its
    /// own fixed, root-owned install directory; accepting a path here would let
    /// any client that reaches the socket have root execute a binary of its
    /// choosing.
    CharonStart,
    /// Stop the native strongSwan daemon. macOS only.
    CharonStop,
}

/// `serde` default for [`Request::SslConnect::allow_full`].
fn permitted() -> bool {
    true
}

/// The failure `reason` a connect carries when it was abandoned at the gateway's
/// push because it wanted the default route and `allow_full` said no.
///
/// It lives in the protocol because both sides need it: the broker sends it, and
/// the GUI matches on it to say *which* tunnel is in the way — something the
/// broker cannot know, since charon's tunnels are not its business. It still has
/// to read sensibly on its own, for any client that doesn't recognise it.
pub const FULL_TUNNEL_REFUSED: &str =
    "this gateway routes all traffic, and another VPN already does — disconnect that one first";

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
