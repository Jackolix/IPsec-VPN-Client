//! Is a host behind the tunnel actually reachable — and if not, why not.
//!
//! # Why this does not go through the broker
//!
//! Both platforms can probe without any privilege at all:
//!
//! - **macOS** allows an unprivileged ICMP datagram socket
//!   (`SOCK_DGRAM`/`IPPROTO_ICMP`) to any user. No raw socket, no root.
//! - **Windows** has `IcmpSendEcho` in `iphlpapi`, which does the echo in the
//!   kernel on the caller's behalf. Also unprivileged.
//!
//! So the GUI does this itself. Teaching the privileged helper a "send a packet
//! to this address" verb would hand a LaunchDaemon / LocalSystem service an
//! arbitrary-destination network primitive to gain exactly nothing, and the
//! whole point of that helper is that it exposes the smallest possible surface.
//!
//! # Two Darwin details that are easy to get wrong
//!
//! Both were confirmed against a live host rather than assumed:
//!
//! 1. Darwin requires a **correct ICMP checksum** in the packet you send.
//!    Linux fills it in for `SOCK_DGRAM`; macOS does not, and a packet with a
//!    zero checksum is silently dropped — it looks exactly like an unreachable
//!    host.
//! 2. Darwin's reply buffer **includes the 20-byte IP header**, so the ICMP
//!    type is at offset 20, not 0. Linux hands back the ICMP message alone.
//!    [`icmp_body`] handles either.
//! 3. A reply must be matched to the request that earned it, by **both** source
//!    address and a token echoed in the payload. Probes run concurrently, one
//!    socket each, and without that check a single answering host makes every
//!    other host on the list report as up with its round-trip time — the whole
//!    feature silently turns into "everything is green". Neither the ident
//!    field nor the socket alone is enough: Darwin rewrites the ident it is
//!    given for a datagram ICMP socket.
//!
//! # Why an unreachable host is not just a red dot
//!
//! A profile knows its remote traffic selectors, so it knows which addresses
//! the tunnel even carries. That turns "no answer" into a real answer: an
//! address outside every selector is *not routed over this tunnel*, which is a
//! configuration problem, not a dead switch. See [`Scope`].
//!
//! That check is also a safety rail. A profile can be handed to a user by
//! anyone, and its host list is a set of addresses this app will send packets
//! to. Out-of-scope hosts are therefore never probed automatically — only when
//! the user asks for that host by hand.

use crate::hosts::Host;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use vpn_core::Ipv4Net;

/// How long a single host may take. Short enough that a full list of dead
/// hosts still settles quickly, long enough for a round trip over a tunnel.
const TIMEOUT: Duration = Duration::from_millis(1500);

/// Whether the tunnel carries this address at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Inside one of the profile's remote traffic selectors.
    InTunnel,
    /// Outside every selector — the tunnel does not route it.
    OutsideTunnel,
    /// The name did not resolve, so there is no address to place.
    Unresolved,
}

/// The outcome of probing one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Answered.
    Up,
    /// Resolved and probed, no answer.
    Down,
    /// The name could not be resolved.
    DnsFailed,
    /// Deliberately not probed (out of scope on an automatic sweep).
    Skipped,
    /// The probe itself could not run.
    Error,
}

/// One host's reachability, as the UI renders it.
#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    pub name: String,
    /// The address as configured, `addr` or `addr:port` — also what the UI
    /// copies to the clipboard.
    pub addr: String,
    /// What the name resolved to, when it is a name rather than a literal.
    pub resolved: Option<String>,
    pub scope: Scope,
    pub state: State,
    /// Round-trip time in milliseconds, when the host answered.
    pub rtt_ms: Option<f64>,
    /// Which probe was used, for the UI to label ("ICMP" / "TCP 443").
    pub probe: String,
    /// A sentence saying what the result means. This is the point of the
    /// feature: "no answer" is not actionable, "not routed over this tunnel" is.
    pub detail: String,
}

/// What the probe needs to know about the profile to explain its results.
pub struct Context {
    /// The profile's remote traffic selectors.
    pub remote: Vec<Ipv4Net>,
    /// Whether the tunnel is currently established.
    pub connected: bool,
    /// The profile's split-DNS suffix, if it has one.
    pub dns_domain: Option<String>,
}

/// Probe every host in `hosts`.
///
/// `manual` is the user asking (a Check button); `false` is the automatic sweep
/// after connecting, which leaves out-of-scope hosts alone — see the module
/// docs.
pub fn probe_all(hosts: &[Host], ctx: &Context, manual: bool) -> Vec<HostStatus> {
    // One thread per host so a list of dead hosts costs one timeout, not N.
    // The list is capped at `hosts::MAX_HOSTS`, so this cannot fan out far.
    let mut handles = Vec::with_capacity(hosts.len());
    for host in hosts {
        let host = host.clone();
        let remote = ctx.remote.clone();
        let connected = ctx.connected;
        let domain = ctx.dns_domain.clone();
        handles.push(std::thread::spawn(move || {
            probe_one(
                &host,
                &Context {
                    remote,
                    connected,
                    dns_domain: domain,
                },
                manual,
            )
        }));
    }
    handles
        .into_iter()
        .zip(hosts)
        .map(|(h, host)| {
            h.join().unwrap_or_else(|_| HostStatus {
                name: host.name.clone(),
                addr: host.display_addr(),
                resolved: None,
                scope: Scope::Unresolved,
                state: State::Error,
                rtt_ms: None,
                probe: probe_label(host),
                detail: "the reachability check did not finish".to_string(),
            })
        })
        .collect()
}

fn probe_label(host: &Host) -> String {
    match host.port {
        Some(p) => format!("TCP {p}"),
        None => "ICMP".to_string(),
    }
}

fn probe_one(host: &Host, ctx: &Context, manual: bool) -> HostStatus {
    let probe = probe_label(host);
    let mut status = HostStatus {
        name: host.name.clone(),
        addr: host.display_addr(),
        resolved: None,
        scope: Scope::Unresolved,
        state: State::Error,
        rtt_ms: None,
        probe,
        detail: String::new(),
    };

    // 1. Resolve. A literal needs no lookup; a name goes through the system
    //    resolver, which is what /etc/resolver (macOS) and the NRPT rule
    //    (Windows) have already been pointed at the tunnel's DNS.
    let ip = match host.literal() {
        Some(ip) => ip,
        None => match resolve(&host.addr) {
            Some(ip) => {
                status.resolved = Some(ip.to_string());
                ip
            }
            None => {
                status.state = State::DnsFailed;
                status.detail = dns_failure_detail(host, ctx);
                return status;
            }
        },
    };
    if host.literal().is_none() {
        status.resolved = Some(ip.to_string());
    }

    // 2. Place it against the tunnel's traffic selectors.
    let in_tunnel = ctx.remote.iter().any(|n| n.contains(ip));
    status.scope = if in_tunnel {
        Scope::InTunnel
    } else {
        Scope::OutsideTunnel
    };

    if !in_tunnel && !manual {
        status.state = State::Skipped;
        status.detail = out_of_scope_detail(ip, ctx);
        return status;
    }

    // 3. Probe.
    let result = match host.port {
        Some(port) => tcp_probe(ip, port),
        None => icmp_probe(ip),
    };
    match result {
        Ok(rtt) => {
            status.state = State::Up;
            status.rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
            status.detail = if in_tunnel {
                "answered over the tunnel".to_string()
            } else {
                format!("answered, but {ip} is not routed over this tunnel — this reply came from somewhere else on your network")
            };
        }
        Err(e) => {
            status.state = State::Down;
            status.detail = if !in_tunnel {
                out_of_scope_detail(ip, ctx)
            } else if !ctx.connected {
                format!("no answer — the tunnel is not connected, so {ip} is not reachable yet")
            } else if host.port.is_some() {
                format!("no answer on {} ({e}) — the host may be up but the service down", status.probe)
            } else {
                format!("no answer ({e}) — the host may be down, or it may be dropping pings; give it a port to probe the service instead")
            };
        }
    }
    status
}

/// Why a name did not resolve, in terms the user can act on.
fn dns_failure_detail(host: &Host, ctx: &Context) -> String {
    match (&ctx.dns_domain, ctx.connected) {
        (Some(d), true) if !host.addr.ends_with(d.as_str()) => format!(
            "{} did not resolve — this profile only sends names under {d} to the tunnel's DNS, \
             and this name is not one of them",
            host.addr
        ),
        (_, true) => format!(
            "{} did not resolve — the tunnel is up, so this points at its DNS configuration \
             rather than the host",
            host.addr
        ),
        (_, false) => format!("{} did not resolve — connect the tunnel first", host.addr),
    }
}

fn out_of_scope_detail(ip: Ipv4Addr, ctx: &Context) -> String {
    if ctx.remote.is_empty() {
        return format!(
            "{ip} is not routed over this tunnel — the profile lists no remote subnets at all, \
             so add the networks you need under Traffic & addressing"
        );
    }
    let nets: Vec<String> = ctx.remote.iter().map(|n| n.to_string()).collect();
    format!(
        "{ip} is not routed over this tunnel — it carries {} only",
        nets.join(", ")
    )
}

fn resolve(name: &str) -> Option<Ipv4Addr> {
    (name, 0u16).to_socket_addrs().ok()?.find_map(|a| match a {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        // The config model is IPv4-only, so a AAAA-only name has no address
        // this tunnel could carry.
        SocketAddr::V6(_) => None,
    })
}

fn tcp_probe(ip: Ipv4Addr, port: u16) -> Result<Duration, String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, TIMEOUT)
        .map(|_| start.elapsed())
        .map_err(|e| e.to_string())
}

/// The internet checksum (RFC 1071). Darwin will not compute it for us.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// An echo request with a correct checksum, carrying `token` as its payload.
///
/// The token is what identifies the answer: see the module docs.
fn echo_request(ident: u16, seq: u16, token: [u8; 8]) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    pkt[0] = 8; // echo request
    pkt[1] = 0; // code
    pkt[4..6].copy_from_slice(&ident.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..].copy_from_slice(&token);
    let c = checksum(&pkt);
    pkt[2..4].copy_from_slice(&c.to_be_bytes());
    pkt
}

/// A value no concurrent probe will repeat.
fn probe_token() -> [u8; 8] {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let mut token = [0u8; 8];
    token[..4].copy_from_slice(&std::process::id().to_be_bytes());
    token[4..].copy_from_slice(&SEQ.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    token
}

/// The ICMP message inside a reply buffer, past the IP header if one is there.
fn icmp_body(buf: &[u8]) -> &[u8] {
    if buf.len() >= 20 && (buf[0] >> 4) == 4 {
        let ihl = usize::from(buf[0] & 0x0f) * 4;
        if buf.len() > ihl {
            return &buf[ihl..];
        }
    }
    buf
}

/// Is this the echo reply to *our* request, rather than to a probe running
/// beside it? Type 0 plus the exact payload we sent.
fn is_our_reply(buf: &[u8], token: &[u8; 8]) -> bool {
    let icmp = icmp_body(buf);
    icmp.len() >= 16 && icmp[0] == 0 && &icmp[8..16] == token
}

#[cfg(unix)]
fn icmp_probe(ip: Ipv4Addr) -> Result<Duration, String> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: every raw pointer below points at a live, correctly sized local,
    // and the fd is wrapped in an OwnedFd immediately so it is closed on every
    // path out of this function.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
        if fd < 0 {
            // On Linux this is the usual outcome unless net.ipv4.ping_group_range
            // includes the user; macOS and Windows never need anything.
            return Err(format!(
                "cannot open an ICMP socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);

        let tv = libc::timeval {
            tv_sec: TIMEOUT.as_secs() as _,
            tv_usec: TIMEOUT.subsec_micros() as _,
        };
        if libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        ) < 0
        {
            return Err(format!(
                "cannot set the ICMP timeout: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        };
        #[cfg(target_os = "macos")]
        {
            sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }

        let ident = std::process::id() as u16;
        let token = probe_token();
        let pkt = echo_request(ident, 1, token);
        let start = Instant::now();
        let sent = libc::sendto(
            raw,
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            std::ptr::addr_of!(sa).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if sent < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }

        let mut buf = [0u8; 128];
        loop {
            let mut from: libc::sockaddr_in = std::mem::zeroed();
            let mut from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let n = libc::recvfrom(
                raw,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                std::ptr::addr_of_mut!(from).cast(),
                std::ptr::addr_of_mut!(from_len),
            );
            if n < 0 {
                return Err("timed out".to_string());
            }
            let source = Ipv4Addr::from(from.sin_addr.s_addr.to_ne_bytes());
            // Both checks matter: the address rules out another host's reply,
            // and the token rules out another probe's reply from the same host.
            if source == ip && is_our_reply(&buf[..n as usize], &token) {
                return Ok(start.elapsed());
            }
            // Somebody else's answer. Keep waiting, but never past our own
            // deadline — the socket timeout only bounds a single recvfrom.
            if start.elapsed() >= TIMEOUT {
                return Err("timed out".to_string());
            }
        }
    }
}

#[cfg(windows)]
fn icmp_probe(ip: Ipv4Addr) -> Result<Duration, String> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    // SAFETY: the reply buffer is sized per the API contract (one
    // ICMP_ECHO_REPLY plus the payload it echoes back, plus the 8 bytes the
    // documentation requires for an error message), and the handle is closed
    // on every path.
    unsafe {
        let handle = IcmpCreateFile();
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "cannot open the ICMP handle: {}",
                std::io::Error::last_os_error()
            ));
        }
        let payload = probe_token();
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8];
        let replies = IcmpSendEcho(
            handle,
            // IPAddr is the in_addr bit pattern: octets in memory order.
            u32::from_ne_bytes(ip.octets()),
            payload.as_ptr().cast(),
            payload.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            reply.len() as u32,
            TIMEOUT.as_millis() as u32,
        );
        IcmpCloseHandle(handle);

        if replies == 0 {
            return Err("timed out".to_string());
        }
        let echo = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
        // IP_SUCCESS is 0; anything else is a delivery failure, not a reply.
        if echo.Status != 0 {
            return Err(format!("no reply (status {})", echo.Status));
        }
        Ok(Duration::from_millis(u64::from(echo.RoundTripTime)))
    }
}

#[cfg(not(any(unix, windows)))]
fn icmp_probe(_ip: Ipv4Addr) -> Result<Duration, String> {
    Err("ICMP is not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(remote: &[&str], connected: bool, domain: Option<&str>) -> Context {
        Context {
            remote: remote.iter().map(|s| s.parse().unwrap()).collect(),
            connected,
            dns_domain: domain.map(|s| s.to_string()),
        }
    }

    fn host(name: &str, addr: &str, port: Option<u16>) -> Host {
        Host {
            name: name.into(),
            addr: addr.into(),
            port,
        }
    }

    /// The checksum is the one thing macOS silently punishes getting wrong, so
    /// it is pinned against a known-good vector: an all-zero buffer sums to
    /// zero, and the complement of zero is 0xFFFF.
    #[test]
    fn checksum_matches_rfc1071() {
        assert_eq!(checksum(&[0, 0, 0, 0]), 0xFFFF);
        // A packet's checksum, recomputed with the field included, is zero.
        let pkt = echo_request(0x1234, 1, *b"tok12345");
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn an_echo_request_is_well_formed() {
        let pkt = echo_request(0xABCD, 7, *b"tok12345");
        assert_eq!(pkt[0], 8, "type 8 = echo request");
        assert_eq!(pkt[1], 0, "code 0");
        assert_ne!(&pkt[2..4], &[0, 0], "checksum must be filled in for Darwin");
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0xABCD);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 7);
    }

    /// A reply as each platform frames it: Darwin prepends the IP header,
    /// Linux hands back the ICMP message alone. Both must match.
    #[test]
    fn a_reply_is_recognised_behind_either_framing() {
        let token = *b"tok12345";

        let mut bare = vec![0u8; 16];
        bare[0] = 0; // echo reply
        bare[8..16].copy_from_slice(&token);
        assert!(is_our_reply(&bare, &token));

        let mut with_ip = vec![0u8; 36];
        with_ip[0] = 0x45; // IPv4, IHL 5 -> 20 byte header
        with_ip[20] = 0;
        with_ip[28..36].copy_from_slice(&token);
        assert!(is_our_reply(&with_ip, &token));
    }

    /// The bug this guards: probes run concurrently, and without matching the
    /// echoed payload one answering host makes every other host on the list
    /// report as up. A reply carrying somebody else's token is not ours.
    #[test]
    fn another_probes_reply_is_not_mistaken_for_ours() {
        let mine = *b"tok12345";
        let theirs = *b"tok99999";

        let mut reply = vec![0u8; 16];
        reply[0] = 0;
        reply[8..16].copy_from_slice(&theirs);
        assert!(!is_our_reply(&reply, &mine));

        // Our own request echoed back by nothing is type 8, not a reply.
        let mut request = vec![0u8; 16];
        request[0] = 8;
        request[8..16].copy_from_slice(&mine);
        assert!(!is_our_reply(&request, &mine));

        // Truncated to the header alone: no payload to match, so no match.
        assert!(!is_our_reply(&[0u8; 8], &mine));
    }

    /// Concurrent probes must never draw the same token.
    #[test]
    fn tokens_are_unique_per_probe() {
        let handles: Vec<_> = (0..32).map(|_| std::thread::spawn(probe_token)).collect();
        let mut seen: Vec<[u8; 8]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "a token was handed out twice");
    }

    /// An address the tunnel does not carry is never probed on an automatic
    /// sweep, and the reason says so.
    #[test]
    fn out_of_scope_hosts_are_skipped_when_not_asked_for() {
        let c = ctx(&["10.0.15.0/24"], true, None);
        let got = probe_all(&[host("Elsewhere", "192.168.1.1", None)], &c, false);
        assert_eq!(got[0].state, State::Skipped);
        assert_eq!(got[0].scope, Scope::OutsideTunnel);
        assert!(got[0].detail.contains("not routed over this tunnel"), "{}", got[0].detail);
        assert!(got[0].detail.contains("10.0.15.0/24"), "{}", got[0].detail);
    }

    /// A profile with no remote subnets cannot reach anything; say that
    /// instead of blaming the host.
    #[test]
    fn a_profile_without_subnets_says_so() {
        let c = ctx(&[], true, None);
        let got = probe_all(&[host("Switch", "10.0.15.2", None)], &c, false);
        assert_eq!(got[0].state, State::Skipped);
        assert!(got[0].detail.contains("lists no remote subnets"), "{}", got[0].detail);
    }

    #[test]
    fn scope_follows_the_traffic_selectors() {
        let c = ctx(&["10.0.15.0/24", "192.168.5.5/32"], true, None);
        let got = probe_all(
            &[host("A", "10.0.15.200", None), host("B", "192.168.5.5", None)],
            &c,
            false,
        );
        assert_eq!(got[0].scope, Scope::InTunnel);
        assert_eq!(got[1].scope, Scope::InTunnel);
    }

    /// A name outside the split-DNS suffix is the single most confusing
    /// failure here, so it gets its own explanation.
    #[test]
    fn a_name_outside_the_split_dns_suffix_is_explained() {
        let h = host("NAS", "nas.other.example", None);
        let c = ctx(&["10.0.15.0/24"], true, Some("corp.example"));
        let d = dns_failure_detail(&h, &c);
        assert!(d.contains("only sends names under corp.example"), "{d}");
    }

    #[test]
    fn a_disconnected_tunnel_is_blamed_before_the_host() {
        let h = host("NAS", "nas.corp.example", None);
        let c = ctx(&["10.0.15.0/24"], false, Some("corp.example"));
        assert!(dns_failure_detail(&h, &c).contains("connect the tunnel first"));
    }

    /// The probe label is what the UI shows next to the result.
    #[test]
    fn the_probe_is_labelled_by_what_it_actually_does() {
        assert_eq!(probe_label(&host("x", "10.0.15.9", Some(443))), "TCP 443");
        assert_eq!(probe_label(&host("x", "10.0.15.9", None)), "ICMP");
    }

    /// A closed port on the loopback answers immediately — enough to prove the
    /// TCP path reports failure rather than hanging, without touching the
    /// network.
    #[test]
    fn the_tcp_probe_reports_a_refused_connection() {
        // Bind and drop, so the port is almost certainly free.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(tcp_probe(Ipv4Addr::LOCALHOST, port).is_err());
    }

    /// And an open one succeeds, so a green result means something.
    #[test]
    fn the_tcp_probe_reports_an_open_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(tcp_probe(Ipv4Addr::LOCALHOST, port).is_ok());
    }
}
