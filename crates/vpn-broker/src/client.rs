//! Windows client for the broker pipe. Pure std — opening `\\.\pipe\...` for
//! read+write gives a bidirectional byte stream, so no FFI is needed here; the
//! access check happens in the kernel against the pipe's DACL when we open it.
//!
//! The GUI uses [`available`] to decide whether the broker is installed (and it
//! can therefore skip the UAC path), and [`request`] to drive it.

use crate::protocol::{Request, Response, PIPE_NAME};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

/// Send one request and read the one-line response. Returns `Err` if the broker
/// isn't installed/running (pipe missing) or the exchange fails — callers treat
/// that as "broker unavailable" and fall back to the elevated path.
pub fn request(req: &Request) -> Result<Response, String> {
    // A busy pipe (another client mid-exchange) briefly returns ERROR_PIPE_BUSY;
    // retry the open for a short window before giving up.
    let mut file = open_with_retry(Duration::from_millis(1500))?;

    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(file.try_clone().map_err(|e| e.to_string())?);
    let mut resp = String::new();
    reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    if resp.trim().is_empty() {
        return Err("broker closed the connection without a response".into());
    }
    serde_json::from_str::<Response>(resp.trim()).map_err(|e| format!("bad broker response: {e}"))
}

/// Is the broker reachable? A successful `Ping` round-trip.
pub fn available() -> bool {
    matches!(request(&Request::Ping), Ok(r) if r.ok)
}

fn open_with_retry(budget: Duration) -> Result<std::fs::File, String> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        match OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(f) => return Ok(f),
            Err(e) => {
                // ERROR_PIPE_BUSY (231): all instances busy — wait and retry.
                let busy = e.raw_os_error() == Some(231);
                if !busy || std::time::Instant::now() >= deadline {
                    return Err(format!("broker pipe unavailable: {e}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}
