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
mod openvpn;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod supervisor;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);

    #[cfg(windows)]
    std::process::exit(run_windows(cmd, &args));

    #[cfg(not(windows))]
    {
        let _ = cmd;
        let _ = args;
        eprintln!("vpn-broker is a Windows-only service; nothing to do on this platform.");
        std::process::exit(1);
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
        //   ssl-status | ssl-disconnect
        Some("ssl-connect") => ssl_connect_client(&args[1..]),
        Some("ssl-status") => ssl_client(&protocol::Request::SslStatus),
        Some("ssl-disconnect") => ssl_client(&protocol::Request::SslDisconnect),
        // No args == launched by the SCM.
        Some("run") | None => report(service::run()),
        Some(other) => {
            eprintln!("unknown command: {other}");
            2
        }
    }
}

/// Drive [`openvpn::connect`] from the command line for testing. Reads the
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

    match openvpn::connect(&config, user, pass) {
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
