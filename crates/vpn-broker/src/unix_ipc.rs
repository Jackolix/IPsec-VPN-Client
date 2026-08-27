//! Unix-socket IPC server for the macOS helper (transport only — request
//! dispatch is the caller's closure).
//!
//! The Windows broker's security boundary is the pipe's DACL. macOS has no
//! equivalent on a Unix socket, so the boundary here is built from two parts:
//!
//!   * **File permissions.** The socket is `root:staff` mode 0660, so it is
//!     reachable by local users but not over the network and not by anything
//!     running as `nobody`.
//!   * **Peer credentials.** `LOCAL_PEERCRED` names the uid on the other end
//!     before a single byte is read. Requests from root or from a uid below
//!     500 (the system accounts) are refused: this helper exists to serve a
//!     logged-in person's GUI, and nothing else has business driving it.
//!
//! What that does NOT establish is *which program* is talking — proving that
//! needs the peer's code signature, which in turn needs the app to be signed
//! with a Developer ID. Until then the real mitigation is the shape of the API
//! rather than the gate in front of it: see `privileged`, where every operation
//! is a fixed verb over arguments the helper re-validates itself. There is no
//! request that names a path, a command, or a shell string, so reaching this
//! socket buys an attacker the ability to connect or disconnect a VPN — not to
//! run code as root.

use crate::protocol::{Request, Response, MACOS_SOCKET};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

/// Request handler: maps one parsed request to a response. Shared across
/// per-connection threads, so it must be `Send + Sync`.
pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Cap a single request so a misbehaving client cannot grow our buffer. An
/// `.ovpn` (once SSL VPN lands here) is the largest thing this will carry.
const MAX_REQUEST: usize = 256 * 1024;

/// The first uid macOS assigns to a human account. Everything below it is a
/// system account, and none of them should be driving a VPN GUI.
const FIRST_HUMAN_UID: u32 = 500;

/// Serve the socket forever, dispatching each connection through `handler`.
/// Returns only on a fatal setup error.
pub fn serve(handler: Handler) -> Result<(), String> {
    let path = Path::new(MACOS_SOCKET);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    // A socket left behind by a previous run would make bind() fail with
    // EADDRINUSE even though nothing is listening.
    let _ = std::fs::remove_file(path);

    let listener =
        UnixListener::bind(path).map_err(|e| format!("cannot bind {MACOS_SOCKET}: {e}"))?;

    // 0660 root:staff. Set after bind, because the mode a socket is created
    // with is subject to the process umask and launchd's is not ours to assume.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("cannot set permissions on {MACOS_SOCKET}: {e}"))?;
    set_group_staff(path);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let h = Arc::clone(&handler);
                // One thread per connection, matching the Windows broker. Each
                // exchange is a single request/response, so these are short.
                std::thread::spawn(move || {
                    if let Err(e) = handle(s, h) {
                        eprintln!("helper: connection failed: {e}");
                    }
                });
            }
            Err(e) => eprintln!("helper: accept failed: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: UnixStream, handler: Handler) -> Result<(), String> {
    let uid = peer_uid(&stream)?;
    if uid < FIRST_HUMAN_UID {
        // Answered rather than dropped, so a confused caller gets a reason
        // instead of a hang. It still learns nothing it did not already know.
        return reply(stream, &Response::err("not permitted for this account"));
    }

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    // read_line on its own would happily grow until memory ran out. Spelled
    // with UFCS because `.take()` on a BufReader otherwise resolves to
    // Iterator::take.
    let mut limited = std::io::Read::take(&mut reader, MAX_REQUEST as u64);
    let read = limited.read_line(&mut line).map_err(|e| e.to_string())?;
    if read == 0 {
        return Ok(()); // client hung up
    }
    if read >= MAX_REQUEST {
        return reply(stream, &Response::err("request too large"));
    }

    let resp = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => handler(req),
        Err(e) => Response::err(format!("bad request: {e}")),
    };
    reply(stream, &resp)
}

fn reply(mut stream: UnixStream, resp: &Response) -> Result<(), String> {
    let mut out = serde_json::to_string(resp).map_err(|e| e.to_string())?;
    out.push('\n');
    stream.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

/// The uid on the other end of `stream`, via `LOCAL_PEERCRED`.
///
/// This is read from the connected socket, so it is the kernel's account of who
/// connected — not something the peer can assert.
fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "cannot read peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }
    if cred.cr_version != libc::XUCRED_VERSION {
        return Err("peer credentials are of an unexpected version".to_string());
    }
    Ok(cred.cr_uid)
}

/// Put the socket in the `staff` group so a logged-in user can reach it while
/// 0660 keeps everyone else out. Best-effort: if the lookup fails the socket
/// stays root-owned and only root can talk to it, which fails closed.
fn set_group_staff(path: &Path) {
    let name = std::ffi::CString::new("staff").expect("literal has no NUL");
    let gid = unsafe {
        let grp = libc::getgrnam(name.as_ptr());
        if grp.is_null() {
            eprintln!("helper: group 'staff' not found; socket stays root-only");
            return;
        }
        (*grp).gr_gid
    };
    let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };
    if unsafe { libc::chown(c_path.as_ptr(), 0, gid) } != 0 {
        eprintln!(
            "helper: cannot set socket group: {}",
            std::io::Error::last_os_error()
        );
    }
}
