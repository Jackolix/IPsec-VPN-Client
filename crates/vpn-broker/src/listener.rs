//! Who owns a loopback TCP port, and what binary is that.
//!
//! We drive charon over a TCP vici socket, and for a long time "something is
//! listening there" was taken to mean "our charon is up". That is false on any
//! machine with another strongSwan-based VPN client installed: `charon-svc`'s
//! built-in vici default is the same for everyone, so the first daemon to claim
//! it wins — and we would happily push connections (and the PSK) into a
//! stranger's daemon, then kill it on disconnect. Sophos Connect ships exactly
//! such a daemon and runs it permanently.
//!
//! So: identify the listener by process, not by "the port answered". A dedicated
//! port (see `charon::VICI_ADDR`) removes the collision; these helpers let the
//! broker *prove* the daemon behind it is the one we shipped before adopting or
//! killing it.
//!
//! [`image_of`] needs to open the process, which only succeeds when the caller
//! is at least as privileged as the target: the LocalSystem broker can read a
//! SYSTEM-owned charon's path, an unelevated GUI cannot (it gets `None`). That
//! asymmetry is why the identity check belongs in the broker.

use std::net::SocketAddr;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The pid listening on `addr` (an IPv4 `host:port`), if any.
pub fn owner_pid(addr: &str) -> Option<u32> {
    let want: SocketAddr = addr.parse().ok()?;
    let want_port = want.port();

    // Sized in two calls: ask for the buffer size, then fill it.
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if rc != 0 {
        return None;
    }

    // MIB_TCPTABLE_OWNER_PID is a count followed by that many rows.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let rows = unsafe {
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
    };
    rows.iter()
        .find(|row| {
            // dwLocalPort holds the port in network byte order in its low half.
            let port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
            port == want_port
        })
        .map(|row| row.dwOwningPid)
}

/// The full image path of `pid`. `None` when the process is gone or the caller
/// is not privileged enough to open it (an unelevated process cannot open a
/// SYSTEM-owned one) — so a `None` means "cannot tell", never "not ours".
pub fn image_of(pid: u32) -> Option<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 || len == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }
}

/// Do two paths name the same file? Compared canonically, so `..`, short names
/// and case differences don't make our own daemon look foreign.
pub fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
