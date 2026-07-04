//! Named-pipe IPC server (transport only — request dispatch is the caller's
//! closure). The pipe's DACL is the security boundary: the broker runs as
//! LocalSystem, so the pipe must be reachable by the unelevated desktop user
//! but not by anything broader.
//!
//! SDDL `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`:
//!   * `SY` LocalSystem — full (the service itself),
//!   * `BA` Builtin Administrators — full,
//!   * `IU` Interactive users — read+write (the console user's GUI).
//! No entry for Everyone/Network, and `PIPE_REJECT_REMOTE_CLIENTS` blocks
//! access over the network redirector, so only a locally, interactively
//! logged-on user can drive it.

use crate::protocol::{Request, Response, PIPE_NAME};
use std::ptr::null_mut;
use std::sync::Arc;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Access control for the pipe (see module docs).
const SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
const SDDL_REVISION_1: u32 = 1;
/// Cap a single request so a misbehaving client can't grow our buffer.
const MAX_REQUEST: usize = 64 * 1024;

/// Request handler: maps one parsed request to a response. Shared across
/// per-connection threads, so it must be `Send + Sync`.
pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Move a raw pipe HANDLE into a worker thread. Each handle is owned by exactly
/// one connection thread, which closes it — so this transfer is sound.
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}

/// Serve the pipe forever, dispatching each connection through `handler`.
/// Returns only on a fatal setup error; the accept loop otherwise never ends
/// (the service stops it by exiting the process).
pub fn serve(handler: Handler) -> Result<(), String> {
    let sa = build_security_attributes()?;
    let name = to_wide(PIPE_NAME);

    loop {
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                &sa,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(format!("CreateNamedPipe failed (err {})", unsafe { GetLastError() }));
        }

        // Block until a client connects. ERROR_PIPE_CONNECTED means one raced in
        // between create and connect — still a live connection.
        let connected =
            unsafe { ConnectNamedPipe(pipe, null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            unsafe { CloseHandle(pipe) };
            continue;
        }

        let handler = handler.clone();
        let owned = SendHandle(pipe);
        std::thread::spawn(move || {
            let h = owned; // move the handle in; closed inside serve_conn
            unsafe { serve_conn(h.0, handler.as_ref()) };
        });
    }
}

/// Read one request line, dispatch it, write one response line, disconnect.
unsafe fn serve_conn(pipe: HANDLE, handler: &(dyn Fn(Request) -> Response + Send + Sync)) {
    let resp = match read_line(pipe) {
        Ok(line) if !line.trim().is_empty() => match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => handler(req),
            Err(e) => Response::err(format!("bad request: {e}")),
        },
        Ok(_) => Response::err("empty request"),
        Err(e) => Response::err(e),
    };

    let mut out =
        serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false,"msg":"encode error"}"#.to_string());
    out.push('\n');
    write_all(pipe, out.as_bytes());

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

/// Read from the pipe until a newline (or the client stops / the cap is hit).
unsafe fn read_line(pipe: HANDLE) -> Result<String, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let mut read: u32 = 0;
        let ok = ReadFile(pipe, chunk.as_mut_ptr(), chunk.len() as u32, &mut read, null_mut());
        if ok == 0 {
            // A client that wrote its line and is waiting for us won't cause a
            // read error; a real error/EOF here means give up on what we have.
            break;
        }
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read as usize]);
        if buf.contains(&b'\n') || buf.len() >= MAX_REQUEST {
            break;
        }
    }
    let end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).map_err(|_| "request was not valid UTF-8".to_string())
}

unsafe fn write_all(pipe: HANDLE, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let mut written: u32 = 0;
        let ok = WriteFile(pipe, bytes.as_ptr(), bytes.len() as u32, &mut written, null_mut());
        if ok == 0 || written == 0 {
            break;
        }
        bytes = &bytes[written as usize..];
    }
}

/// Build SECURITY_ATTRIBUTES from [`SDDL`]. The descriptor is intentionally
/// leaked — it lives for the whole process and is reused for every instance.
fn build_security_attributes() -> Result<SECURITY_ATTRIBUTES, String> {
    let wide = to_wide(SDDL);
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!("SDDL parse failed (err {})", unsafe { GetLastError() }));
    }
    Ok(SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    })
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
