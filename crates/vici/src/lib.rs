//! Minimal blocking client for strongSwan's [vici][] control protocol.
//!
//! [vici]: https://docs.strongswan.org/docs/latest/plugins/vici.html
//!
//! Two layers: [`message`] is the pure, cross-platform message codec (fully
//! unit-tested anywhere), and [`protocol`] adds packet framing plus the
//! blocking [`protocol::Client`]. The Unix-socket transport is compiled only
//! on `unix`; on other platforms the codec still builds and tests so the
//! workspace stays green on a Windows dev box.

pub mod message;
pub mod protocol;

pub use message::{CodecError, Message, Value};
pub use protocol::{Client, Error};

use std::time::Duration;

/// Default location of charon's vici Unix socket.
pub const DEFAULT_SOCKET: &str = "/var/run/charon.vici";

const READ_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to charon's vici Unix socket.
#[cfg(unix)]
pub fn connect_unix<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<Client<std::os::unix::net::UnixStream>, Error> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(Client::new(stream))
}

/// Connect to a vici TCP socket (charon must be configured for one). Provided
/// mainly so the transport layer builds and is usable on non-Unix hosts.
pub fn connect_tcp<A: std::net::ToSocketAddrs>(
    addr: A,
) -> Result<Client<std::net::TcpStream>, Error> {
    let stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(Client::new(stream))
}
