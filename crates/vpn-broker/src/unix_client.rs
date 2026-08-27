//! macOS client for the helper's Unix socket. Pure std: connecting to the
//! socket gives a bidirectional byte stream, and the access check happens in
//! the kernel against the socket's mode when we connect.
//!
//! The GUI uses [`available`] to decide whether the helper is installed (and it
//! can therefore skip the authorization prompt) and [`request`] to drive it.

use crate::protocol::{Request, Response, MACOS_SOCKET};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Long enough to cover a charon start, which waits for the vici socket.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Send one request and read the one-line response. `Err` means the helper is
/// not installed/running or the exchange failed — callers treat that as
/// "helper unavailable" and fall back to the authorization-prompt path.
pub fn request(req: &Request) -> Result<Response, String> {
    let stream = UnixStream::connect(MACOS_SOCKET)
        .map_err(|e| format!("helper socket unavailable: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;

    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    (&stream).write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    (&stream).flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    if resp.trim().is_empty() {
        return Err("the helper closed the connection without a response".into());
    }
    serde_json::from_str::<Response>(resp.trim()).map_err(|e| format!("bad helper response: {e}"))
}

/// Is the helper reachable? A successful `Ping` round-trip.
pub fn available() -> bool {
    matches!(request(&Request::Ping), Ok(r) if r.ok)
}
