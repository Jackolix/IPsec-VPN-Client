//! The broker's actual work: bring charon up, serve IPC, and clean up on stop.
//!
//! Security note: requests arrive from an interactive (but possibly non-admin)
//! user, and some fields are interpolated into a PowerShell command that runs
//! as SYSTEM (the NRPT rule). Those fields are therefore validated strictly
//! here — DNS servers must parse as IPv4, and a domain may only contain DNS
//! label characters — so a request can never smuggle in a command. This is the
//! privilege boundary; keep it airtight.

use crate::protocol::{Request, Response};
use crate::{charon, ipc, nrpt};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex};

/// Most profiles carry two DNS servers; cap generously and reject the absurd.
const MAX_SERVERS: usize = 8;
const MAX_DOMAIN_LEN: usize = 253;

pub struct Broker {
    /// The charon child we started (if any). `None` when charon was already
    /// running (not ours to stop) or failed to start.
    charon: Mutex<Option<Child>>,
}

impl Broker {
    pub fn new() -> Arc<Self> {
        Arc::new(Broker { charon: Mutex::new(None) })
    }

    /// Start charon (best-effort) and spawn the IPC server on a background
    /// thread. Returns once serving; the caller waits for the stop signal.
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
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
            Request::ApplyDns { conn, servers, domain } => {
                let parsed = match validate_servers(&servers) {
                    Ok(v) => v,
                    Err(e) => return Response::err(e),
                };
                let domain = match validate_domain(domain.as_deref()) {
                    Ok(d) => d,
                    Err(e) => return Response::err(e),
                };
                match nrpt::apply(&conn, &parsed, domain.as_deref()) {
                    Ok(msg) => Response::ok(msg),
                    Err(e) => Response::err(e),
                }
            }
            Request::RevertDns { conn } => match nrpt::revert(&conn) {
                Ok(()) => Response::ok(""),
                Err(e) => Response::err(e),
            },
        }
    }

    /// Revert any DNS we applied and stop charon (by image name, since it
    /// detaches — see `charon::stop`).
    pub fn shutdown(&self) {
        nrpt::revert_all();
        let mut child = self.charon.lock().unwrap().take();
        charon::stop(child.as_mut());
    }
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
    fn domain_rejects_injection() {
        assert_eq!(validate_domain(Some("kanzlei.local")).unwrap().as_deref(), Some("kanzlei.local"));
        assert_eq!(validate_domain(Some("  ")).unwrap(), None);
        assert_eq!(validate_domain(None).unwrap(), None);
        assert!(validate_domain(Some("evil'); Stop-Service #")).is_err());
        assert!(validate_domain(Some("a b")).is_err());
    }
}
