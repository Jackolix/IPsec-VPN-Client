//! The privileged broker binary. Subcommands:
//!   * `run`      — service entry point (what the SCM launches; also the default)
//!   * `console`  — run the supervisor in the foreground for debugging
//!   * `install`  / `uninstall` — register/remove the Windows service (elevated)
//!   * `stop`     — stop the service without removing it (elevated; used by the
//!                  installer's upgrade hook to release the locked binaries)
//!   * `ping`     — client-side liveness check against the broker pipe
//!
//! Everything real is Windows-only; on other platforms this is a stub so the
//! workspace still builds (the CI Linux job compiles it).

// Only the Windows service body uses it; on other platforms `main` just
// reports that there is nothing to run.
#[cfg(windows)]
use vpn_broker::protocol;

#[cfg(windows)]
mod charon;
#[cfg(windows)]
mod install;
#[cfg(windows)]
mod ipc;
#[cfg(windows)]
mod nrpt;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod supervisor;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);

    #[cfg(windows)]
    std::process::exit(run_windows(cmd, &args));

    #[cfg(target_os = "macos")]
    std::process::exit(run_macos(cmd));

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = cmd;
        let _ = args;
        eprintln!("vpn-broker is a Windows/macOS helper; nothing to do on this platform.");
        std::process::exit(1);
    }
}

/// The macOS helper: `run` is what launchd invokes, `install`/`uninstall` are
/// what the app invokes once behind an authorization prompt.
#[cfg(target_os = "macos")]
fn run_macos(cmd: Option<&str>) -> i32 {
    use std::sync::Arc;
    use vpn_broker::protocol::{Request, Response};
    use vpn_broker::{launchd, privileged, unix_ipc};

    match cmd {
        Some("run") => {
            let handler: unix_ipc::Handler = Arc::new(|req: Request| match req {
                Request::Ping => Response::ok("helper is running"),
                Request::CharonStart => privileged::charon_start(),
                Request::CharonStop => privileged::charon_stop(),
                Request::ApplyDns { conn, servers, domain, .. } => {
                    privileged::apply_dns(&conn, &servers, domain.as_deref())
                }
                Request::RevertDns { conn } => privileged::revert_dns(&conn),
                Request::SslConnect { name, config, username, password, allow_full } => {
                    privileged::ssl_connect(&name, &config, &username, &password, allow_full)
                }
                Request::SslDisconnect { name } => privileged::ssl_disconnect(&name),
                Request::SslStatus => privileged::ssl_status(),
            });
            // A staged .ovpn holds a private key and its auth file holds a
            // password; a crash is exactly when those get orphaned.
            privileged::ssl_sweep();

            // Bring charon up with the daemon, the way the Windows service
            // supervises charon-svc as part of its own lifecycle. launchd loads
            // this at boot, so the backend is simply always there: no "backend
            // stopped" for a user to notice, and no start on the critical path
            // of a connect.
            //
            // On its own thread, because it waits for the vici socket and the
            // control socket must be accepting requests meanwhile. A failure is
            // logged and left alone — a connect will ask for a start again, and
            // that path reports the reason to the GUI.
            std::thread::spawn(|| {
                let resp = privileged::charon_start();
                if !resp.ok {
                    eprintln!("helper: could not start charon at load: {}", resp.msg);
                }
            });

            if let Err(e) = unix_ipc::serve(handler) {
                eprintln!("helper: {e}");
                return 1;
            }
            0
        }
        Some("install") => {
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("cannot locate this binary: {e}");
                    return 1;
                }
            };
            let Some(charon) = launchd::bundled_charon_dir(&exe) else {
                eprintln!("no charon directory found beside this binary");
                return 1;
            };
            // Optional: a build without the SSL datapath staged still gets a
            // working IPsec helper.
            let openvpn = launchd::bundled_openvpn_dir(&exe);
            match launchd::install(&exe, &charon, openvpn.as_deref()) {
                Ok(msg) => {
                    println!("{msg}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Some("uninstall") => match launchd::uninstall() {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Some("status") => {
            let installed = launchd::installed();
            let reachable = vpn_broker::unix_client::available();
            println!("installed: {installed}\nreachable: {reachable}");
            i32::from(!(installed && reachable))
        }
        _ => {
            eprintln!("usage: vpn-broker <run|install|uninstall|status>");
            2
        }
    }
}

#[cfg(windows)]
fn run_windows(cmd: Option<&str>, args: &[String]) -> i32 {
    match cmd {
        Some("install") => report(install::install()),
        Some("uninstall") => report(install::uninstall()),
        // Stop the running service (without removing it) so an upgrade can
        // overwrite the locked binaries; the installer's pre-install hook uses
        // this, and post-install `install` starts it again.
        Some("stop") => report(install::stop()),
        Some("console") => {
            let broker = supervisor::Broker::new();
            if let Err(e) = broker.start() {
                eprintln!("start failed: {e}");
                return 1;
            }
            eprintln!("broker running in console mode (Ctrl+C to stop)");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Some("ping") => match vpn_broker::client::request(&protocol::Request::Ping) {
            Ok(r) => {
                println!("{}", r.msg);
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        // `ovpn-connect <config.ovpn> <user> <pass> [seconds]` — bring up an SSL
        // VPN tunnel from a config file in the foreground, hold it briefly, then
        // tear it down. Needs elevation for the adapter and routes. For testing
        // the OpenVPN engine before it is wired to the GUI.
        Some("ovpn-connect") => ovpn_connect(&args[1..]),
        // Client-side counterparts that drive a *running* broker over the pipe,
        // so the SSL tunnel is brought up by the LocalSystem service (which can
        // install the adapter and routes an unelevated caller cannot).
        //   ssl-connect <config.ovpn> <username> <password>
        //   ssl-status | ssl-disconnect [name]   (no name: every tunnel)
        Some("ssl-connect") => ssl_connect_client(&args[1..]),
        Some("ssl-status") => ssl_client(&protocol::Request::SslStatus),
        Some("ssl-disconnect") => ssl_client(&protocol::Request::SslDisconnect {
            name: args.get(1).cloned().unwrap_or_default(),
        }),
        // No args == launched by the SCM.
        Some("run") | None => report(service::run()),
        Some(other) => {
            eprintln!("unknown command: {other}");
            2
        }
    }
}

/// Drive [`vpn_broker::openvpn::connect`] from the command line for testing. Reads the
/// config from a file (so the private key never rides argv), connects, prints
/// the assigned IP, holds the tunnel up for a few seconds, then disconnects.
#[cfg(windows)]
fn ovpn_connect(args: &[String]) -> i32 {
    let (Some(config_path), Some(user), Some(pass)) =
        (args.first(), args.get(1), args.get(2))
    else {
        eprintln!("usage: ovpn-connect <config.ovpn> <username> <password> [seconds]");
        return 2;
    };
    let hold = args.get(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(10);

    let config = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read {config_path}: {e}");
            return 1;
        }
    };

    // Slot 0 — this foreground test drives one tunnel and owns the machine.
    match vpn_broker::openvpn::connect(&config, user, pass, 0, true) {
        Ok(tunnel) => {
            println!(
                "connected; assigned IP: {}",
                tunnel.vpn_ip.clone().unwrap_or_else(|| "<none>".to_string())
            );
            println!("holding the tunnel up for {hold}s, then disconnecting...");
            std::thread::sleep(std::time::Duration::from_secs(hold));
            tunnel.disconnect();
            println!("disconnected");
            0
        }
        Err(e) => {
            eprintln!("error: {}", e.reason);
            if !e.log.is_empty() {
                eprintln!("--- openvpn log ---");
                eprintln!("{}", e.log);
            }
            1
        }
    }
}

/// Send an `SslConnect` to the running broker, reading the `.ovpn` from a file
/// so the private key never rides argv. Prints the assigned IP on success.
#[cfg(windows)]
fn ssl_connect_client(args: &[String]) -> i32 {
    let (Some(config_path), Some(user), Some(pass)) = (args.first(), args.get(1), args.get(2))
    else {
        eprintln!("usage: ssl-connect <config.ovpn> <username> <password>");
        return 2;
    };
    let config = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read {config_path}: {e}");
            return 1;
        }
    };
    // Name this test connection after the config file's stem.
    let name = std::path::Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sslvpn")
        .to_string();
    ssl_client(&protocol::Request::SslConnect {
        name,
        config,
        username: user.clone(),
        password: pass.clone(),
        // This foreground test drives one tunnel; nothing else can be in its way.
        allow_full: true,
    })
}

/// Send one SSL request to the broker and print the response.
#[cfg(windows)]
fn ssl_client(req: &protocol::Request) -> i32 {
    match vpn_broker::client::request(req) {
        Ok(r) if r.ok => {
            if r.msg.is_empty() {
                println!("ok");
            } else {
                println!("{}", r.msg);
            }
            0
        }
        Ok(r) => {
            eprintln!("error: {}", r.msg);
            1
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(windows)]
fn report(res: Result<(), String>) -> i32 {
    match res {
        Ok(()) => {
            println!("ok");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
