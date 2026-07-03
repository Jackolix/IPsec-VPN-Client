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

use std::io::{Read, Write};
use std::time::Duration;
use thiserror::Error;
use vici::{Client, Message};
use vpn_core::ConnectionConfig;

const READ_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ControlError {
    #[error(transparent)]
    Vici(#[from] vici::Error),
    #[error("{0} was rejected by charon: {1}")]
    Rejected(&'static str, String),
    #[error("the Unix vici socket is not available on this platform; use a TCP transport")]
    NoUnixTransport,
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

/// Load the connection + PSK and initiate the tunnel.
pub fn connect(transport: &Transport, config: &ConnectionConfig, name: &str) -> Result<()> {
    let mut client = open(transport)?;
    check(
        client.request("load-conn", bridge::load_conn_message(config, name))?,
        "load-conn",
    )?;
    check(
        client.request("load-shared", bridge::load_shared_message(config, name))?,
        "load-shared",
    )?;
    check(
        client.request(
            "initiate",
            Message::new().str("child", name).str("ike", name),
        )?,
        "initiate",
    )
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
