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
use std::time::Duration;
use thiserror::Error;
use vici::{Client, Message};
use vpn_core::{ConnectionConfig, Secret};

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

    let mut client = open(transport)?;
    check(
        client.request("load-conn", bridge::load_conn_message(config, name))?,
        "load-conn",
    )?;
    check(
        client.request("load-shared", bridge::load_shared_message(config, name))?,
        "load-shared",
    )?;
    if let Some(password) = user_password.filter(|_| config.user_auth.is_some()) {
        check(
            client.request(
                "load-shared",
                bridge::load_shared_user_auth_message(config, name, password),
            )?,
            "load-shared (user auth)",
        )?;
    }

    let (events, response) = client.stream_request(
        "initiate",
        "log",
        Message::new().str("child", name).str("ike", name),
    )?;
    let log = events.iter().take(MAX_LOG_LINES).map(parse_log_line).collect();
    let connected = response.get_str("success").as_deref() == Some("yes");
    let error = if connected {
        None
    } else {
        Some(
            response
                .get_str("errmsg")
                .unwrap_or_else(|| "charon declined to initiate the connection".to_string()),
        )
    };
    Ok(ConnectOutcome {
        connected,
        error,
        log,
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

/// Terminate the named IKE SA.
pub fn disconnect(transport: &Transport, name: &str) -> Result<()> {
    let mut client = open(transport)?;
    check(
        client.request("terminate", Message::new().str("ike", name))?,
        "terminate",
    )
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
}
