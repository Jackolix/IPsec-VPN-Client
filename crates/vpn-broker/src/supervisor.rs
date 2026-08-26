//! The broker's actual work: bring charon up, serve IPC, and clean up on stop.
//!
//! Security note: requests arrive from an interactive (but possibly non-admin)
//! user, and some fields are interpolated into a PowerShell command that runs
//! as SYSTEM (the NRPT rule). Those fields are therefore validated strictly
//! here — DNS servers must parse as IPv4, and a domain may only contain DNS
//! label characters — so a request can never smuggle in a command. This is the
//! privilege boundary; keep it airtight.

use crate::protocol::{Request, Response};
use crate::{charon, ipc, nrpt, openvpn};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex};

/// Most profiles carry two DNS servers; cap generously and reject the absurd.
const MAX_SERVERS: usize = 8;
const MAX_DOMAIN_LEN: usize = 253;
/// A profile's protected subnets, sent along so a connection refused the
/// catch-all namespace can still claim its own reverse zones. Generous.
const MAX_SUBNETS: usize = 64;
/// How many SSL VPN tunnels may be up at once. Each one is an openvpn process
/// with its own wintun adapter, so the cap is really about not littering the
/// machine with adapters — no one legitimately runs eight at a time.
const MAX_SSL_TUNNELS: usize = 8;

/// One live SSL VPN tunnel: the connection name the GUI keys it by, the wintun
/// adapter slot it occupies, and the process itself.
struct SslEntry {
    name: String,
    slot: usize,
    tunnel: openvpn::Tunnel,
}

/// The SSL tunnels this broker owns. Slots are handed out from here, and a
/// connect in flight reserves its slot before the lock is released for the
/// up-to-45s handshake — otherwise two concurrent connects would both see the
/// same slot free and fight over one adapter.
#[derive(Default)]
struct SslRegistry {
    tunnels: Vec<SslEntry>,
    reserved: Vec<usize>,
}

impl SslRegistry {
    /// Drop tunnels whose openvpn process has died underneath us, freeing their
    /// slots (and, via `Drop`, their staged config and credentials).
    fn prune(&mut self) {
        self.tunnels.retain_mut(|e| e.tunnel.is_alive());
    }

    /// The lowest slot neither a live tunnel nor an in-flight connect holds,
    /// marked reserved so a concurrent connect can't be handed the same one.
    fn take_slot(&mut self) -> Result<usize, String> {
        let mut occupied: Vec<usize> = self.tunnels.iter().map(|e| e.slot).collect();
        occupied.extend_from_slice(&self.reserved);
        let slot = lowest_free_slot(&occupied)?;
        self.reserved.push(slot);
        Ok(slot)
    }

    fn release_slot(&mut self, slot: usize) {
        self.reserved.retain(|s| *s != slot);
    }
}

pub struct Broker {
    /// The charon child we started (if any). `None` when charon was already
    /// running (not ours to stop) or failed to start.
    charon: Mutex<Option<Child>>,
    /// The live SSL VPN (OpenVPN) tunnels, keyed by the connection name the GUI
    /// uses. Several may be up at once — one per wintun adapter slot.
    ssl: Mutex<SslRegistry>,
}

impl Broker {
    pub fn new() -> Arc<Self> {
        Arc::new(Broker {
            charon: Mutex::new(None),
            ssl: Mutex::new(SslRegistry::default()),
        })
    }

    /// Start charon (best-effort) and spawn the IPC server on a background
    /// thread. Returns once serving; the caller waits for the stop signal.
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        // Remove any SSL config a previous, killed broker left staged before we
        // start serving — it would hold a live private key.
        openvpn::sweep_stale_configs();

        match charon::start() {
            Ok(child) => *self.charon.lock().unwrap() = child,
            // Don't fail the whole service if charon won't come up — the GUI
            // will surface a connect failure, and DNS IPC still works.
            Err(e) => log(&format!("charon start failed: {e}")),
        }

        let me = Arc::clone(self);
        let handler: ipc::Handler = Arc::new(move |req| me.handle(req));
        std::thread::spawn(move || {
            if let Err(e) = ipc::serve(handler) {
                log(&format!("ipc server exited: {e}"));
            }
        });
        Ok(())
    }

    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Ping => Response::ok("pong"),
            Request::ApplyDns { conn, servers, domain, subnets } => {
                let parsed = match validate_servers(&servers) {
                    Ok(v) => v,
                    Err(e) => return Response::err(e),
                };
                let domain = match validate_domain(domain.as_deref()) {
                    Ok(d) => d,
                    Err(e) => return Response::err(e),
                };
                let subnets = match validate_subnets(&subnets) {
                    Ok(v) => v,
                    Err(e) => return Response::err(e),
                };
                let spoken_for = self.ssl_dns_claims(&conn);
                match nrpt::apply(&conn, &parsed, domain.as_deref(), &subnets, &spoken_for) {
                    Ok(msg) => Response::ok(msg),
                    Err(e) => Response::err(e),
                }
            }
            Request::RevertDns { conn } => match nrpt::revert(&conn) {
                Ok(()) => Response::ok(""),
                Err(e) => Response::err(e),
            },
            Request::SslConnect { name, config, username, password, allow_full } => {
                // Reconnecting a name that is already up replaces that tunnel;
                // any other one stays. Take it out and tear it down *before*
                // reserving a slot, so the adapter it held is free to be reused.
                // The lock is released for the up-to-45s connect either way, so
                // a status query isn't blocked behind it.
                let old = {
                    let mut reg = self.ssl.lock().unwrap();
                    reg.prune();
                    let idx = reg.tunnels.iter().position(|e| e.name == name);
                    idx.map(|i| reg.tunnels.remove(i))
                };
                if let Some(old) = old {
                    old.tunnel.disconnect();
                }

                let slot = match self.ssl.lock().unwrap().take_slot() {
                    Ok(s) => s,
                    Err(e) => return Response::err(e),
                };
                match openvpn::connect(&config, &username, &password, slot, allow_full) {
                    Ok(tunnel) => {
                        let ip = tunnel.vpn_ip.clone().unwrap_or_default();
                        let mut reg = self.ssl.lock().unwrap();
                        reg.release_slot(slot);
                        reg.tunnels.push(SslEntry { name, slot, tunnel });
                        Response::ok(ip)
                    }
                    // Encode the failure as JSON so the GUI can show the short
                    // reason in the banner and openvpn's log in the panel,
                    // instead of one wall-of-text error. (A plain-string failure
                    // — e.g. a transport error — is still handled on the far side.)
                    Err(e) => {
                        self.ssl.lock().unwrap().release_slot(slot);
                        Response::err(
                            serde_json::json!({ "reason": e.reason, "log": e.log }).to_string(),
                        )
                    }
                }
            }
            Request::SslDisconnect { name } => {
                // Take the matching tunnels out under the lock, then tear them
                // down with it released — disconnect waits on the process.
                let doomed: Vec<SslEntry> = {
                    let mut reg = self.ssl.lock().unwrap();
                    if name.is_empty() {
                        std::mem::take(&mut reg.tunnels)
                    } else {
                        let mut out = Vec::new();
                        while let Some(i) = reg.tunnels.iter().position(|e| e.name == name) {
                            out.push(reg.tunnels.remove(i));
                        }
                        out
                    }
                };
                for entry in doomed {
                    entry.tunnel.disconnect();
                }
                Response::ok("")
            }
            Request::SslStatus => {
                let mut reg = self.ssl.lock().unwrap();
                // Dropping a tunnel whose process died also deletes its staged
                // config, and frees its adapter slot for the next connect.
                reg.prune();
                let up: Vec<serde_json::Value> = reg
                    .tunnels
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "name": e.name,
                            "ip": e.tunnel.vpn_ip.clone().unwrap_or_default(),
                            // What the gateway pushed: whether it took the
                            // default route, and the search domain it named.
                            "full": e.tunnel.pushed.full,
                            "domain": e.tunnel.pushed.domain.clone().unwrap_or_default(),
                        })
                    })
                    .collect();
                drop(reg);
                if up.is_empty() {
                    Response::ok("")
                } else {
                    Response::ok(serde_json::Value::Array(up).to_string())
                }
            }
        }
    }

    /// The NRPT namespaces already spoken for by a live SSL tunnel other than
    /// `conn`. openvpn applies the gateway's DNS on its own adapter, and an NRPT
    /// rule is system-wide policy that *overrides* adapter resolvers rather than
    /// sitting alongside them — so a rule covering these names would silently
    /// take resolution away from a tunnel that is up and working.
    ///
    /// A gateway that took the default route (`redirect-gateway`) has claimed
    /// resolution for everything; one that named a search domain has claimed
    /// that suffix.
    fn ssl_dns_claims(&self, conn: &str) -> Vec<String> {
        let mut reg = self.ssl.lock().unwrap();
        reg.prune();
        reg.tunnels
            .iter()
            .filter(|e| e.name != conn)
            .flat_map(|e| {
                let mut claims = Vec::new();
                if e.tunnel.pushed.full {
                    claims.push(".".to_string());
                }
                if let Some(d) = &e.tunnel.pushed.domain {
                    claims.push(format!(".{}", d.trim_start_matches('.')));
                }
                claims
            })
            .collect()
    }

    /// Revert any DNS we applied, tear down every SSL tunnel, and stop charon
    /// (by image name, since it detaches — see `charon::stop`).
    pub fn shutdown(&self) {
        nrpt::revert_all();
        let doomed = std::mem::take(&mut self.ssl.lock().unwrap().tunnels);
        for entry in doomed {
            entry.tunnel.disconnect();
        }
        let mut child = self.charon.lock().unwrap().take();
        charon::stop(child.as_mut());
    }
}

/// The lowest adapter slot not in `occupied`, or an error when every one is
/// taken. Reusing the lowest free slot (rather than counting up) keeps the
/// machine's set of wintun adapters as small as the busiest moment needed.
fn lowest_free_slot(occupied: &[usize]) -> Result<usize, String> {
    (0..MAX_SSL_TUNNELS)
        .find(|s| !occupied.contains(s))
        .ok_or_else(|| format!("too many SSL VPN tunnels are already up (max {MAX_SSL_TUNNELS})"))
}

/// Parse and bound the DNS server list. Anything that isn't a plain IPv4
/// address is rejected — this is what keeps the NRPT PowerShell safe.
fn validate_servers(servers: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    if servers.len() > MAX_SERVERS {
        return Err(format!("too many DNS servers (max {MAX_SERVERS})"));
    }
    servers
        .iter()
        .map(|s| s.trim().parse::<Ipv4Addr>().map_err(|_| format!("not an IPv4 DNS server: {s:?}")))
        .collect()
}

/// Subnets are re-emitted as `<octet>.in-addr.arpa` namespaces inside the NRPT
/// PowerShell, so each one must parse as a plain IPv4 CIDR before it gets
/// anywhere near a command line. Anything that doesn't is rejected outright
/// rather than skipped, so a malformed request is visible instead of silent.
fn validate_subnets(subnets: &[String]) -> Result<Vec<String>, String> {
    if subnets.len() > MAX_SUBNETS {
        return Err(format!("too many subnets (max {MAX_SUBNETS})"));
    }
    subnets
        .iter()
        .map(|s| {
            let (addr, prefix) = s.trim().split_once('/').ok_or_else(|| {
                format!("not an IPv4 subnet: {s:?}")
            })?;
            let addr: Ipv4Addr =
                addr.parse().map_err(|_| format!("not an IPv4 subnet: {s:?}"))?;
            let prefix: u8 =
                prefix.parse().map_err(|_| format!("not an IPv4 subnet: {s:?}"))?;
            if prefix > 32 {
                return Err(format!("not an IPv4 subnet: {s:?}"));
            }
            Ok(format!("{addr}/{prefix}"))
        })
        .collect()
}

/// A domain, if present, may only contain DNS label characters. This blocks any
/// attempt to break out of the single-quoted PowerShell string it lands in.
fn validate_domain(domain: Option<&str>) -> Result<Option<String>, String> {
    let Some(d) = domain.map(str::trim).filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    if d.len() > MAX_DOMAIN_LEN {
        return Err("domain too long".to_string());
    }
    if !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err("domain has invalid characters".to_string());
    }
    Ok(Some(d.to_string()))
}

/// Append a line to the broker log under ProgramData (best-effort; the service
/// has no console). Handy for diagnosing start/stop and charon issues.
pub fn log(msg: &str) {
    use std::io::Write;
    let path = log_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{msg}");
    }
}

fn log_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("ipsec-vpn").join("broker.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_must_be_ipv4() {
        assert!(validate_servers(&["1.1.1.1".into(), "8.8.8.8".into()]).is_ok());
        assert!(validate_servers(&["1.1.1.1; Stop-Process".into()]).is_err());
        assert!(validate_servers(&["not-an-ip".into()]).is_err());
    }

    #[test]
    fn slots_fill_the_lowest_gap() {
        assert_eq!(lowest_free_slot(&[]).unwrap(), 0);
        assert_eq!(lowest_free_slot(&[0]).unwrap(), 1);
        // A tunnel in the middle going away frees its slot for the next connect,
        // rather than the count marching upwards and leaving adapters behind.
        assert_eq!(lowest_free_slot(&[0, 2]).unwrap(), 1);
        let full: Vec<usize> = (0..MAX_SSL_TUNNELS).collect();
        assert!(lowest_free_slot(&full).is_err());
    }

    #[test]
    fn reserving_a_slot_excludes_it_from_the_next() {
        let mut reg = SslRegistry::default();
        assert_eq!(reg.take_slot().unwrap(), 0);
        // The first connect is still in flight (no tunnel recorded yet), so a
        // concurrent one must not be handed the same adapter.
        assert_eq!(reg.take_slot().unwrap(), 1);
        reg.release_slot(0);
        assert_eq!(reg.take_slot().unwrap(), 0);
    }

    #[test]
    fn subnets_must_be_cidr() {
        assert_eq!(
            validate_subnets(&["10.98.43.0/24".into(), "10.10.0.0/16".into()]).unwrap(),
            vec!["10.98.43.0/24".to_string(), "10.10.0.0/16".to_string()]
        );
        assert!(validate_subnets(&["10.98.43.0".into()]).is_err());
        assert!(validate_subnets(&["10.98.43.0/33".into()]).is_err());
        // These end up in the NRPT PowerShell as reverse zones.
        assert!(validate_subnets(&["10.0.0.0/8'; Stop-Service #".into()]).is_err());
        let many: Vec<String> = (0..MAX_SUBNETS + 1).map(|_| "10.0.0.0/8".to_string()).collect();
        assert!(validate_subnets(&many).is_err());
    }

    #[test]
    fn domain_rejects_injection() {
        assert_eq!(validate_domain(Some("example.local")).unwrap().as_deref(), Some("example.local"));
        assert_eq!(validate_domain(Some("  ")).unwrap(), None);
        assert_eq!(validate_domain(None).unwrap(), None);
        assert!(validate_domain(Some("evil'); Stop-Service #")).is_err());
        assert!(validate_domain(Some("a b")).is_err());
    }
}
