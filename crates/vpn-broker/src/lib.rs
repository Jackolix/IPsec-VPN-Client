//! Shared surface of the privileged helper: the IPC protocol (portable) plus
//! the per-platform transport the unprivileged GUI links against.
//!
//! Both platforms solve the same problem — the GUI runs unprivileged, but
//! bringing a tunnel up needs root — and both do it by moving those operations
//! behind a small, validated request surface. What differs is everything else:
//!
//! | | Windows | macOS |
//! |---|---|---|
//! | form | LocalSystem SCM service | launchd `LaunchDaemon` |
//! | transport | named pipe | Unix socket |
//! | access control | pipe DACL | file mode + `LOCAL_PEERCRED` |
//! | charon | supervised by the service | started on request |
//! | DNS | NRPT rules | `/etc/resolver` files |
//!
//! The protocol is shared because the *shape* is shared: one request, one
//! response, newline-delimited JSON, with a deliberately tiny command surface.

pub mod protocol;

#[cfg(windows)]
pub mod client;

/// Identify the process behind a loopback port, so neither the GUI nor the
/// broker mistakes another vendor's strongSwan for ours.
#[cfg(windows)]
pub mod listener;

/// macOS: the LaunchDaemon helper's socket server, its privileged operations,
/// its installer, and the client the GUI uses to reach it.
#[cfg(target_os = "macos")]
pub mod launchd;
#[cfg(target_os = "macos")]
pub mod privileged;
#[cfg(target_os = "macos")]
pub mod unix_client;
#[cfg(target_os = "macos")]
pub mod unix_ipc;
