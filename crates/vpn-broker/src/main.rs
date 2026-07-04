//! The privileged broker binary. Subcommands:
//!   * `run`      — service entry point (what the SCM launches; also the default)
//!   * `console`  — run the supervisor in the foreground for debugging
//!   * `install`  / `uninstall` — register/remove the Windows service (elevated)
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
mod service;
#[cfg(windows)]
mod supervisor;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);

    #[cfg(windows)]
    std::process::exit(run_windows(cmd));

    #[cfg(not(windows))]
    {
        let _ = cmd;
        eprintln!("vpn-broker is a Windows-only service; nothing to do on this platform.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_windows(cmd: Option<&str>) -> i32 {
    match cmd {
        Some("install") => report(install::install()),
        Some("uninstall") => report(install::uninstall()),
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
        // No args == launched by the SCM.
        Some("run") | None => report(service::run()),
        Some(other) => {
            eprintln!("unknown command: {other}");
            2
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
