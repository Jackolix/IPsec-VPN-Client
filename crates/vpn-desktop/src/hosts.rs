//! Hosts and equipment reachable over a tunnel, and the companion file that
//! ships them alongside a profile.
//!
//! A profile says how to build the tunnel; it says nothing about what is on the
//! other end. This module carries the other half: the switch, the NAS, the
//! machine's web UI — the things a person actually opens the VPN to reach.
//!
//! Hosts are deliberately *not* part of [`ConnectionConfig`](vpn_core::ConnectionConfig).
//! That type describes the tunnel and is consumed by `vpn-cli`, `vpn-agent` and
//! the vici bridge, none of which have any use for a list of equipment.
//!
//! # Where a host list comes from
//!
//! Two sources, layered the same way every other profile field is:
//!
//! 1. A companion `<id>.hosts.json` beside the profile — what an administrator
//!    ships. It is read-only to us.
//! 2. The user's own edits, in the `<id>.override.json` sidecar (see
//!    [`overrides`](crate::overrides)), replayed on top.
//!
//! The profile file itself is never written to. It is re-parsed on every load
//! and holds a live pre-shared key; rewriting it to store a switch's IP address
//! would put that key through our own serializer for no reason. The companion
//! file exists precisely so the shippable half carries no secret and can be
//! mailed, committed or handed to a customer on its own.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Upper bound on a profile's host list.
///
/// A profile file can arrive from anywhere — the importers treat their input as
/// hostile, and a companion file deserves the same suspicion. Each host is an
/// address this app will send a packet to on the user's behalf, so the list
/// length is capped rather than trusted.
pub const MAX_HOSTS: usize = 64;

/// Longest accepted host label. Generous for a human name, short enough that a
/// pathological one cannot wreck the list rendering.
const MAX_NAME_LEN: usize = 64;

/// Longest accepted address. 253 is the maximum length of a DNS name.
const MAX_ADDR_LEN: usize = 253;

/// One piece of equipment behind the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    /// What to call it in the UI ("Core switch", "NAS").
    pub name: String,
    /// An IPv4 literal or a DNS name. IPv6 is deliberately absent: the whole
    /// config model is IPv4-only ([`Ipv4Net`](vpn_core::Ipv4Net), and the
    /// traffic selectors it builds), so accepting an IPv6 host here would
    /// promise reachability the tunnel cannot describe.
    pub addr: String,
    /// When set, reachability is a TCP connect to this port instead of an ICMP
    /// echo — the right probe for equipment that answers a service but drops
    /// pings, and a direct answer to "is the web UI up?".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Host {
    /// How the address should be shown and copied: `addr` on its own, or
    /// `addr:port` when the entry names a service.
    pub fn display_addr(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.addr),
            None => self.addr.clone(),
        }
    }

    /// Is `addr` an IPv4 literal rather than a name needing resolution?
    pub fn literal(&self) -> Option<std::net::Ipv4Addr> {
        self.addr.parse().ok()
    }
}

/// Validate and normalize a host list: trim, drop blank rows, reject anything
/// malformed, collapse exact duplicates and enforce [`MAX_HOSTS`].
///
/// A row that is entirely empty is dropped rather than rejected — the row
/// editor leaves one behind whenever a user adds a row and changes their mind,
/// and that should not be an error.
pub fn normalize(hosts: &[Host]) -> Result<Vec<Host>, String> {
    let mut out: Vec<Host> = Vec::new();
    for h in hosts {
        let name = h.name.trim();
        let addr = h.addr.trim();
        if name.is_empty() && addr.is_empty() {
            continue;
        }
        if addr.is_empty() {
            return Err(format!("host {name:?} needs an address"));
        }
        if name.is_empty() {
            return Err(format!("the host at {addr} needs a name"));
        }
        if name.chars().count() > MAX_NAME_LEN {
            return Err(format!("host name {name:?} is too long (max {MAX_NAME_LEN})"));
        }
        // Control characters would corrupt the list rendering and serve no
        // purpose in a label.
        if name.chars().any(|c| c.is_control()) {
            return Err(format!("host name {name:?} contains control characters"));
        }
        if addr.len() > MAX_ADDR_LEN {
            return Err(format!("host address {addr:?} is too long"));
        }
        // The same conservative set the gateway field uses. This string reaches
        // a resolver, so it is checked rather than passed through.
        if !addr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(format!("host address {addr:?} contains invalid characters"));
        }
        if let Some(0) = h.port {
            return Err(format!("host {name:?}: port 0 is not a port"));
        }
        let host = Host {
            name: name.to_string(),
            addr: addr.to_string(),
            port: h.port,
        };
        if out.contains(&host) {
            continue; // exact duplicate row — nothing to add
        }
        if out.len() >= MAX_HOSTS {
            return Err(format!("a profile may list at most {MAX_HOSTS} hosts"));
        }
        out.push(host);
    }
    Ok(out)
}

fn companion_path(profile_dir: &Path, id: &str) -> PathBuf {
    profile_dir.join(format!("{id}.hosts.json"))
}

/// Read the companion host list shipped beside a profile.
///
/// Missing, unreadable or malformed reads as "no hosts", exactly as a corrupt
/// override sidecar does: a bad companion file must not take the profile — and
/// with it the ability to connect — down with it.
pub fn load_companion(profile_dir: &Path, id: &str) -> Vec<Host> {
    let Ok(text) = std::fs::read_to_string(companion_path(profile_dir, id)) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<Vec<Host>>(&text) else {
        return Vec::new();
    };
    normalize(&parsed).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, addr: &str, port: Option<u16>) -> Host {
        Host {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
        }
    }

    #[test]
    fn normalize_trims_and_keeps_order() {
        let got = normalize(&[h("  Switch ", " 10.0.15.2 ", None), h("NAS", "nas.corp", None)])
            .unwrap();
        assert_eq!(got, vec![h("Switch", "10.0.15.2", None), h("NAS", "nas.corp", None)]);
    }

    /// The row editor leaves an empty row behind when a user adds one and then
    /// changes their mind; that is not an error.
    #[test]
    fn a_wholly_empty_row_is_dropped_not_rejected() {
        let got = normalize(&[h("Switch", "10.0.15.2", None), h("  ", "", None)]).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn a_half_filled_row_is_an_error() {
        assert!(normalize(&[h("Switch", "", None)]).is_err());
        assert!(normalize(&[h("", "10.0.15.2", None)]).is_err());
    }

    /// The address reaches a resolver, so it is validated rather than trusted.
    #[test]
    fn hostile_addresses_are_rejected() {
        assert!(normalize(&[h("x", "10.0.0.1/../etc", None)]).is_err());
        assert!(normalize(&[h("x", "10.0.0.1 && rm", None)]).is_err());
        assert!(normalize(&[h("x", "http://10.0.0.1", None)]).is_err());
        assert!(normalize(&[h("x", &"a".repeat(300), None)]).is_err());
        assert!(normalize(&[h("bad\u{7}name", "10.0.0.1", None)]).is_err());
        assert!(normalize(&[h("x", "10.0.0.1", Some(0))]).is_err());
    }

    /// Both halves of the same device are legitimate; only an identical row is
    /// redundant.
    #[test]
    fn duplicates_collapse_but_two_services_on_one_box_do_not() {
        let got = normalize(&[
            h("Web UI", "10.0.15.9", Some(443)),
            h("SSH", "10.0.15.9", Some(22)),
            h("Web UI", "10.0.15.9", Some(443)),
        ])
        .unwrap();
        assert_eq!(got.len(), 2);
    }

    /// A companion file is untrusted input; the cap is enforced, not assumed.
    #[test]
    fn the_list_is_capped() {
        let many: Vec<Host> = (0..MAX_HOSTS + 1)
            .map(|i| h(&format!("h{i}"), &format!("10.0.15.{i}"), None))
            .collect();
        assert!(normalize(&many).is_err());
        assert!(normalize(&many[..MAX_HOSTS]).is_ok());
    }

    #[test]
    fn display_addr_appends_only_a_real_port() {
        assert_eq!(h("x", "10.0.15.9", Some(443)).display_addr(), "10.0.15.9:443");
        assert_eq!(h("x", "10.0.15.9", None).display_addr(), "10.0.15.9");
    }

    #[test]
    fn companion_round_trip_and_tolerance() {
        let dir = std::env::temp_dir().join(format!("vpn_hosts_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        assert!(load_companion(&dir, "nothing").is_empty());

        std::fs::write(
            companion_path(&dir, "p"),
            r#"[{"name":"Switch","addr":"10.0.15.2"},{"name":"Web","addr":"10.0.15.9","port":443}]"#,
        )
        .unwrap();
        let got = load_companion(&dir, "p");
        assert_eq!(got, vec![h("Switch", "10.0.15.2", None), h("Web", "10.0.15.9", Some(443))]);

        // A corrupt companion file must not take the profile down with it.
        std::fs::write(companion_path(&dir, "bad"), "{not json").unwrap();
        assert!(load_companion(&dir, "bad").is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
