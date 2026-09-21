//! Opening a Remote Desktop session to a host behind the tunnel.
//!
//! A host list already knows where the equipment is; for an RDP box the next
//! thing a user does is type that address into `mstsc`. This hands the address
//! to the platform's own RDP client instead.
//!
//! # What counts as an RDP host
//!
//! A host whose port is [`PORT`] — nothing else. There is no extra flag in the
//! host schema and no extra control in the row editor: the port is already
//! there, already means "probe the service rather than ping the box", and
//! naming 3389 is the one thing every RDP entry has in common. The cost is that
//! RDP on a non-standard port gets no button; the benefit is that the feature
//! is invisible until it applies, and an edited host list cannot silently lose
//! a flag it never carried.
//!
//! # Why the address is re-read rather than passed in
//!
//! [`launch`] is reached from a Tauri command that takes a profile id and a row
//! index, and looks the host up in that profile's normalized list. The web view
//! never supplies the string that becomes a command-line argument. That keeps
//! the only addresses this app can hand to a process the ones that already
//! survived [`hosts::normalize`](crate::hosts::normalize) — ASCII alphanumeric,
//! `.`, `-` and `_`, length-capped, with a non-zero port.
//!
//! Nothing here is elevated. The RDP client runs as the user, under the user's
//! session, exactly as it would had they launched it from the Start menu; the
//! broker is not involved and gains no new verb.

use crate::hosts::Host;
use std::process::Command;

/// The port that makes a host an RDP host.
pub const PORT: u16 = 3389;

/// Is this an entry the RDP button belongs on?
pub fn is_rdp(host: &Host) -> bool {
    host.port == Some(PORT)
}

/// Open the platform's RDP client against `host`.
///
/// Returns as soon as the client is spawned: whether it then connects, prompts
/// for credentials or times out is between the user and the far end. A failure
/// here means the client could not be started at all.
pub fn launch(host: &Host) -> Result<String, String> {
    if !is_rdp(host) {
        return Err(format!(
            "{} is not an RDP host (port {PORT} is what marks one)",
            host.name
        ));
    }
    let target = format!("{}:{PORT}", host.addr);
    spawn(&target)?;
    Ok(target)
}

#[cfg(windows)]
fn spawn(target: &str) -> Result<(), String> {
    // Built-in since XP, so there is nothing to detect and no fallback worth
    // writing. `/v:` takes `host:port` directly.
    Command::new("mstsc.exe")
        .arg(format!("/v:{target}"))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start Remote Desktop (mstsc.exe): {e}"))
}

#[cfg(target_os = "macos")]
fn spawn(target: &str) -> Result<(), String> {
    // Windows App (and Microsoft Remote Desktop before it) registers the `rdp:`
    // scheme, whose parameters are the ones from an .rdp file. `full address`
    // has a space in it, hence the escape; `s:` is the scheme's string marker,
    // not a host prefix.
    let url = format!("rdp://full%20address=s:{target}");
    let status = Command::new("/usr/bin/open")
        .arg(&url)
        .status()
        .map_err(|e| format!("could not run `open`: {e}"))?;
    if !status.success() {
        return Err(
            "no app is registered for rdp:// links — install Windows App from the Mac App Store"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn(target: &str) -> Result<(), String> {
    // No built-in client, so try the two that are actually installed in
    // practice, in the order of how well they take a bare address.
    let attempts: [(&str, Vec<String>); 2] = [
        ("xfreerdp", vec![format!("/v:{target}")]),
        ("remmina", vec!["-c".to_string(), format!("rdp://{target}")]),
    ];
    for (bin, args) in attempts {
        match Command::new(bin).args(&args).spawn() {
            Ok(_) => return Ok(()),
            // Anything other than "not installed" is worth reporting as-is.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("could not start {bin}: {e}")),
        }
    }
    Err("no RDP client found — install xfreerdp or remmina".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(port: Option<u16>) -> Host {
        Host {
            name: "Terminal server".to_string(),
            addr: "10.0.15.9".to_string(),
            port,
        }
    }

    #[test]
    fn only_the_rdp_port_marks_an_rdp_host() {
        assert!(is_rdp(&h(Some(PORT))));
        assert!(!is_rdp(&h(Some(443))));
        assert!(!is_rdp(&h(None)));
    }

    /// The guard is on `launch` too, not just on what the UI chooses to draw:
    /// the row index the web view sends is not a promise about the row.
    #[test]
    fn launching_a_non_rdp_host_is_refused_before_any_process_starts() {
        assert!(launch(&h(Some(443))).is_err());
        assert!(launch(&h(None)).is_err());
    }
}
