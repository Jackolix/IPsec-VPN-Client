//! Shared connection control used by both the CLI agent and the desktop app.
//!
//! Turns a [`ConnectionConfig`] into vici messages ([`bridge`]) and runs the
//! connect / status / disconnect flows against charon over a [`Transport`]
//! (Unix socket on the eventual Linux target, TCP when a Windows/macOS build
//! drives charon in a container). The PSK is pushed via `load-shared` in
//! memory; no swanctl.conf secret is written to disk.

pub mod bridge;
pub mod status;

pub use status::{ChildSa, IkeSa};

use serde::Serialize;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;
use thiserror::Error;
use vici::{Client, Message};
use vpn_core::{ConnectionConfig, IkeVersion, Secret};

const READ_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on captured handshake log lines, so a chatty charon can't grow the
/// buffer without bound (a normal `initiate` produces well under this).
const MAX_LOG_LINES: usize = 400;

/// One line of charon's log stream, captured during a connect so the caller
/// can show live handshake progress (and, on failure, the reason).
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    /// charon subsystem: `IKE`, `CFG`, `KNL`, `NET`, `ENC`, …
    pub group: String,
    /// charon log level (0 = audit/always … 4 = most verbose).
    pub level: i32,
    /// The IKE SA this line belongs to, when charon attributes it to one.
    pub ikesa: Option<String>,
    pub msg: String,
}

/// Result of a connect attempt: whether the tunnel came up, the charon error
/// message if not, and the handshake log captured either way. Only a genuine
/// transport/protocol failure (couldn't talk to charon, or `load-conn` was
/// rejected) is reported as an `Err`; a handshake that charon declines still
/// returns `Ok` so the caller can display the captured reason.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectOutcome {
    pub connected: bool,
    pub error: Option<String>,
    pub log: Vec<LogLine>,
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error(transparent)]
    Vici(#[from] vici::Error),
    #[error("{0} was rejected by charon: {1}")]
    Rejected(&'static str, String),
    #[error("the Unix vici socket is not available on this platform; use a TCP transport")]
    NoUnixTransport,
    #[error("this profile's gateway asks for a username and password, which were not supplied")]
    MissingUserPassword,
    #[error(
        "this profile names no remote networks, so bringing it up would route all traffic through \
         the VPN — and if the gateway does not carry it, cut off internet access. Add the \
         subnet(s) you need to reach, or choose to route all traffic through the VPN on purpose"
    )]
    NoRemoteNetworks,
}

pub type Result<T> = std::result::Result<T, ControlError>;

/// How to reach charon's vici interface.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Unix domain socket path (Linux target, e.g. `/var/run/charon.vici`).
    Unix(String),
    /// `host:port` for a TCP vici socket (e.g. charon in a container exposed
    /// to a Windows/macOS host).
    Tcp(String),
}

/// One concrete stream type so the flows are generic over a single
/// `Client<ViciStream>` rather than two transport-specific clients.
enum ViciStream {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for ViciStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ViciStream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            ViciStream::Unix(s) => s.read(buf),
        }
    }
}
impl Write for ViciStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ViciStream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            ViciStream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ViciStream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            ViciStream::Unix(s) => s.flush(),
        }
    }
}

fn open(transport: &Transport) -> Result<Client<ViciStream>> {
    let stream = match transport {
        Transport::Tcp(addr) => {
            let s = std::net::TcpStream::connect(addr).map_err(vici::Error::from)?;
            let _ = s.set_read_timeout(Some(READ_TIMEOUT));
            let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
            ViciStream::Tcp(s)
        }
        Transport::Unix(path) => {
            #[cfg(unix)]
            {
                use std::os::unix::net::UnixStream;
                let s = UnixStream::connect(path).map_err(vici::Error::from)?;
                let _ = s.set_read_timeout(Some(READ_TIMEOUT));
                let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
                ViciStream::Unix(s)
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(ControlError::NoUnixTransport);
            }
        }
    };
    Ok(Client::new(stream))
}

fn check(resp: Message, ctx: &'static str) -> Result<()> {
    match resp.get_str("success").as_deref() {
        Some("yes") => Ok(()),
        _ => Err(ControlError::Rejected(
            ctx,
            resp.get_str("errmsg")
                .unwrap_or_else(|| "unknown error".to_string()),
        )),
    }
}

/// Load the connection + PSK and initiate the tunnel, capturing charon's log
/// stream during the handshake. Registering for the `log` event around
/// `initiate` turns the otherwise opaque call into a live transcript of the
/// exchange (`IKE_SA_INIT`, authentication, `CHILD_SA` install — or the reason
/// it failed), which the GUI surfaces in its charon console.
pub fn connect_logged(
    transport: &Transport,
    config: &ConnectionConfig,
    name: &str,
    user_password: Option<&Secret>,
) -> Result<ConnectOutcome> {
    // A profile whose gateway wants a second round cannot authenticate without
    // the password, and charon would fail somewhere deep in the exchange with
    // a message that doesn't say what is missing. Refuse up front instead.
    if config.user_auth.is_some() && user_password.is_none() {
        return Err(ControlError::MissingUserPassword);
    }

    // A profile with no traffic selectors would negotiate 0.0.0.0/0 and — with
    // charon's `install_routes` on — capture the machine's default route into
    // the tunnel. Against a split-tunnel gateway that does not carry internet
    // traffic (the common Sophos case), that silently kills connectivity. Never
    // do it implicitly: a full tunnel has to be an explicit 0.0.0.0/0 in the
    // profile, so an empty selector set is refused before any route is touched.
    if config.remote_subnets.is_empty() {
        return Err(ControlError::NoRemoteNetworks);
    }

    let mut client = open(transport)?;
    // Resolved once for the whole connect: the version fallback below runs a
    // second attempt, and a cold lookup costs about a second.
    let peers = peer_ids(&config.gateway);
    let primary = config.ike_version;
    let mut outcome = attempt(&mut client, config, name, primary, user_password, &peers)?;

    // The IKE version is not stated in a Sophos `.scx` (and a `.mobileconfig`
    // states it, but old gateways still disagree), so the version we import can
    // be wrong. An SFOS responder answers an IKE_SA_INIT it has no policy for —
    // version included — with NO_PROPOSAL_CHOSEN, which is a fast, unambiguous
    // "wrong version" (not an algorithm mismatch). Rather than make the user
    // edit the profile, retry once with the other version. Verified live:
    // SFOS 18.5 needs IKEv1, SFOS 21 needs IKEv2.
    if !outcome.connected && suggests_wrong_ike_version(&outcome.log) {
        let alternate = other_version(primary);
        outcome.log.push(note(
            name,
            format!(
                "the gateway did not accept IKEv{}; retrying as IKEv{}",
                primary.swanctl_value(),
                alternate.swanctl_value()
            ),
        ));
        let retry = attempt(&mut client, config, name, alternate, user_password, &peers)?;

        let mut log = outcome.log;
        log.extend(retry.log);
        if log.len() > MAX_LOG_LINES {
            log.truncate(MAX_LOG_LINES);
        }
        // Report the profile's own version on a double failure: it is the one
        // the user configured, and its error is the more meaningful of the two.
        let error = if retry.connected { None } else { outcome.error };
        return Ok(ConnectOutcome {
            connected: retry.connected,
            error,
            log,
        });
    }

    Ok(outcome)
}

/// One load-and-initiate pass at a single IKE version. Separated from
/// [`connect_logged`] so the version-fallback path can run it twice against the
/// same open client without duplicating the flow.
fn attempt(
    client: &mut Client<ViciStream>,
    config: &ConnectionConfig,
    name: &str,
    version: IkeVersion,
    user_password: Option<&Secret>,
    peers: &[String],
) -> Result<ConnectOutcome> {
    check(
        client.request("load-conn", bridge::load_conn_message_for(config, name, version))?,
        "load-conn",
    )?;
    check(
        client.request("load-shared", bridge::load_shared_message(config, name, peers))?,
        "load-shared",
    )?;
    if let Some(password) = user_password.filter(|_| config.user_auth.is_some()) {
        check(
            client.request(
                "load-shared",
                bridge::load_shared_user_auth_message_for(config, name, password, version, peers),
            )?,
            "load-shared (user auth)",
        )?;
    }

    // Under IKEv1 a profile's subnets become one CHILD_SA each (quick mode
    // negotiates a single selector pair), so there may be several to bring up.
    let children = bridge::child_names_for(config, name, version);
    let mut log: Vec<LogLine> = Vec::new();
    let mut established = 0usize;
    let mut first_error: Option<String> = None;

    for child in &children {
        let before = log.len();
        let (events, response) = client.stream_request(
            "initiate",
            "log",
            Message::new().str("child", child).str("ike", name),
        )?;
        for event in events.iter() {
            if log.len() >= MAX_LOG_LINES {
                break;
            }
            log.push(parse_log_line(event));
        }
        if response.get_str("success").as_deref() == Some("yes") {
            established += 1;
            continue;
        }

        let err = response
            .get_str("errmsg")
            .unwrap_or_else(|| "charon declined to initiate the connection".to_string());
        // Which subnet failed matters when the others came up: the tunnel
        // looks fine but part of the remote network is unreachable.
        if children.len() > 1 {
            log.push(note(name, format!("{child} did not come up: {err}")));
        }
        first_error.get_or_insert(err);

        // Credentials the gateway just rejected will be rejected again: every
        // remaining child would open its own IKE_SA and repeat the same login.
        // That cannot succeed, and it is actively harmful — a gateway that
        // locks an account after N bad attempts (Sophos does) gets N tries
        // burned per click, so a mistyped password locks the user out and the
        // profile then fails even once it is corrected. A rejected subnet is
        // different: the others are still worth trying.
        if suggests_auth_failure(&log[before..]) {
            if children.len() > 1 {
                log.push(note(
                    name,
                    "the gateway rejected these credentials — not trying the remaining \
                     networks, so a repeated attempt cannot lock the account"
                        .to_string(),
                ));
            }
            break;
        }
    }

    // One established CHILD_SA means the tunnel carries traffic, so that is
    // what "connected" means; a partial failure is reported in the log rather
    // than by throwing away a working tunnel.
    let connected = established > 0;
    if connected && established < children.len() {
        log.push(note(
            name,
            format!(
                "{established} of {} remote networks came up; the rest are not reachable over \
                 this tunnel",
                children.len()
            ),
        ));
    }
    let error = if connected { None } else { first_error };

    Ok(ConnectOutcome {
        connected,
        error,
        log,
    })
}

/// The other IKE version, for the fallback retry.
fn other_version(v: IkeVersion) -> IkeVersion {
    match v {
        IkeVersion::V1 => IkeVersion::V2,
        IkeVersion::V2 => IkeVersion::V1,
    }
}

/// Does the captured handshake say the gateway rejected the IKE *version*
/// rather than something we could not fix by switching it?
///
/// `NO_PROPOSAL_CHOSEN` from a strongSwan responder (SFOS is one) at IKE_SA_INIT
/// means no connection policy matched at all — a version mismatch reads exactly
/// like this. It is deliberately the only trigger: an authentication failure or
/// an unreachable gateway must *not* provoke a pointless second attempt at the
/// other version.
fn suggests_wrong_ike_version(log: &[LogLine]) -> bool {
    log.iter().any(|line| {
        let msg = line.msg.to_ascii_uppercase();
        msg.contains("NO_PROPOSAL_CHOSEN") || msg.contains("NO_PROP")
    })
}

/// Did the peer reject who we are, rather than what we asked for? Covers both
/// authentication rounds charon reports separately: the IKE authentication
/// itself (`AUTHENTICATION_FAILED`, IKEv1 or IKEv2) and the interactive second
/// round on top of it (`XAuth authentication of '...' failed`, and the EAP
/// equivalent).
///
/// This is deliberately narrow. It gates *stopping early*, and stopping early
/// on a failure that was not about credentials would leave working subnets
/// unreachable.
fn suggests_auth_failure(log: &[LogLine]) -> bool {
    log.iter().any(|line| {
        let msg = line.msg.to_ascii_uppercase();
        msg.contains("AUTHENTICATION_FAILED")
            || msg.contains("AUTHENTICATION FAILED")
            || (msg.contains("XAUTH") && msg.contains("FAILED"))
            || (msg.contains("EAP") && msg.contains("FAILED"))
    })
}

/// Load the connection + PSK and initiate the tunnel, returning only success
/// or failure. Thin wrapper over [`connect_logged`] for the CLI, which prints
/// charon's log itself rather than collecting it.
pub fn connect(
    transport: &Transport,
    config: &ConnectionConfig,
    name: &str,
    user_password: Option<&Secret>,
) -> Result<()> {
    let outcome = connect_logged(transport, config, name, user_password)?;
    if outcome.connected {
        Ok(())
    } else {
        Err(ControlError::Rejected(
            "initiate",
            outcome.error.unwrap_or_default(),
        ))
    }
}

/// A line of our own in the handshake transcript, phrased like charon's so the
/// UI renders it the same way.
fn note(ike: &str, msg: String) -> LogLine {
    LogLine {
        group: "CFG".to_string(),
        level: 0,
        ikesa: Some(ike.to_string()),
        msg,
    }
}

fn parse_log_line(event: &Message) -> LogLine {
    LogLine {
        group: event.get_str("group").unwrap_or_default(),
        level: event
            .get_str("level")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0),
        ikesa: event.get_str("ikesa-name"),
        msg: event.get_str("msg").unwrap_or_default(),
    }
}

/// List active IKE/CHILD SAs.
pub fn status(transport: &Transport) -> Result<Vec<IkeSa>> {
    let mut client = open(transport)?;
    let (events, _resp) = client.stream_request("list-sas", "list-sa", Message::new())?;
    Ok(status::parse_sas(&events))
}

/// Every identity charon may use for the far end of a connection to `gateway`.
///
/// A connection that does not pin the peer's identity gets the gateway's
/// *address* as the remote ID, so a profile that names its gateway by hostname
/// needs the resolved addresses among its secret's owners too — the hostname
/// alone would match nothing and charon would report no shared key at all.
/// Resolution is best effort: charon has to resolve the same name to reach the
/// gateway, so a failure here is a failure there, and the hostname stays in the
/// list either way.
fn peer_ids(gateway: &str) -> Vec<String> {
    let mut ids = vec![gateway.to_string()];
    if gateway.parse::<std::net::IpAddr>().is_ok() {
        return ids;
    }
    // The port is irrelevant — `to_socket_addrs` is just the resolver.
    if let Ok(addrs) = (gateway, 500u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip().to_string();
            if !ids.contains(&ip) {
                ids.push(ip);
            }
        }
    }
    ids
}

/// Terminate the named IKE SA and drop the credentials it was loaded with.
pub fn disconnect(transport: &Transport, name: &str) -> Result<()> {
    let mut client = open(transport)?;
    let terminated = check(
        client.request("terminate", Message::new().str("ike", name))?,
        "terminate",
    );

    // Everything pushed over vici outlives the SA it was pushed for: charon
    // holds loaded connections and secrets until they are unloaded or it
    // restarts. A disconnected profile's PSK left in the credential set still
    // competes for every later connection (see `bridge::secret_owners`), so
    // retire it along with the tunnel. Failures are uninteresting here — "not
    // loaded" is the state being asked for.
    for id in [format!("ike-{name}"), format!("user-{name}")] {
        let _ = client.request("unload-shared", Message::new().str("id", id));
    }
    let _ = client.request("unload-conn", Message::new().str("name", name));

    terminated
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A profile that needs a login must be refused before any connection is
    /// opened — the point of the guard is that charon never sees a half-built
    /// credential set, so this must not depend on a reachable daemon. The
    /// transport below points at a port nothing listens on: if the check ever
    /// moves after `open`, this fails with a connection error instead.
    #[test]
    fn refuses_to_connect_without_the_user_password() {
        let mut config = bridge::tests::sample();
        config.user_auth = Some(vpn_core::UserAuth {
            username: Some("vpnuser".to_string()),
            can_save: true,
            otp: false,
        });
        let transport = Transport::Tcp("127.0.0.1:1".to_string());
        let err = connect_logged(&transport, &config, "c", None).unwrap_err();
        assert!(
            matches!(err, ControlError::MissingUserPassword),
            "expected the missing-password guard, got: {err}"
        );
    }

    /// A profile with no traffic selectors must be refused before anything is
    /// opened, so it can never capture the default route into a tunnel the
    /// gateway may not carry. Same reasoning as the missing-password guard: the
    /// transport points at a dead port, so a regression that moved the check
    /// after `open` would fail with a connection error instead.
    #[test]
    fn refuses_a_profile_with_no_remote_networks() {
        let mut config = bridge::tests::sample();
        config.remote_subnets.clear();
        let transport = Transport::Tcp("127.0.0.1:1".to_string());
        let err = connect_logged(&transport, &config, "c", None).unwrap_err();
        assert!(
            matches!(err, ControlError::NoRemoteNetworks),
            "expected the no-networks guard, got: {err}"
        );
    }

    fn log_line(msg: &str) -> LogLine {
        LogLine {
            group: "IKE".to_string(),
            level: 1,
            ikesa: None,
            msg: msg.to_string(),
        }
    }

    /// The one signal that provokes the version retry, in the shape charon
    /// actually logs it — a parsed `N(NO_PROP)` notify on the IKE_SA_INIT
    /// response.
    #[test]
    fn no_proposal_chosen_triggers_the_version_fallback() {
        let log = [
            log_line("initiating IKE_SA c[1] to 203.0.113.10"),
            log_line("parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]"),
        ];
        assert!(suggests_wrong_ike_version(&log));
    }

    /// An authentication failure or an unreachable gateway must not: switching
    /// the IKE version cannot fix either, and a needless second attempt only
    /// doubles the wait and muddies the log.
    #[test]
    fn auth_failure_does_not_trigger_the_fallback() {
        let log = [
            log_line("XAuth authentication of 'user' failed"),
            log_line("received AUTHENTICATION_FAILED notify error"),
        ];
        assert!(!suggests_wrong_ike_version(&log));

        let unreachable = [log_line("retransmit 5 of request with message ID 0")];
        assert!(!suggests_wrong_ike_version(&unreachable));
    }

    /// The counterpart to the test above: what must *not* trigger the fallback
    /// is exactly what must stop the per-subnet loop, so a rejected login is
    /// tried once rather than once per remote network.
    #[test]
    fn auth_failure_stops_the_per_subnet_loop() {
        assert!(suggests_auth_failure(&[log_line(
            "XAuth authentication of 'ikoelbl' (myself) failed"
        )]));
        assert!(suggests_auth_failure(&[log_line(
            "received AUTHENTICATION_FAILED notify error"
        )]));
        assert!(suggests_auth_failure(&[log_line("EAP-MSCHAPv2 authentication failed")]));

        // A subnet the gateway has no policy for, or a peer that never answered,
        // says nothing about our credentials — the remaining subnets are still
        // worth initiating.
        assert!(!suggests_auth_failure(&[log_line(
            "no acceptable traffic selectors found"
        )]));
        assert!(!suggests_auth_failure(&[log_line(
            "retransmit 5 of request with message ID 0"
        )]));
        assert!(!suggests_auth_failure(&[log_line(
            "received NO_PROPOSAL_CHOSEN notify error"
        )]));
    }

    #[test]
    fn other_version_flips() {
        assert_eq!(other_version(IkeVersion::V1), IkeVersion::V2);
        assert_eq!(other_version(IkeVersion::V2), IkeVersion::V1);
    }
}
