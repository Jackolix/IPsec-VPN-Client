//! Shared surface of the privileged broker: the IPC protocol (portable) and a
//! Windows named-pipe client the unelevated GUI links against.
//!
//! The broker binary (a LocalSystem Windows service) does the two things the
//! GUI would otherwise need a UAC prompt for — supervising `charon-svc.exe`
//! (WFP needs Administrator) and installing Windows NRPT DNS rules. The GUI
//! sends it small, validated requests over an ACL'd named pipe instead.

pub mod protocol;

#[cfg(windows)]
pub mod client;
