//! Phase 1 agent. Runs on Linux (inside the strongSwan container during
//! development), imports an NCP profile, and drives charon over vici:
//!
//!   vpn-agent connect --profile p.ini [--gateway-override HOST]
//!   vpn-agent status
//!   vpn-agent disconnect --name NAME
//!
//! The PSK is handed to charon via `load-shared` in memory; no swanctl.conf
//! containing the secret is written to disk.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg_attr(not(unix), allow(dead_code))]
mod bridge;

#[derive(Parser)]
#[command(name = "vpn-agent", about = "Import NCP profiles and drive charon over vici")]
struct Cli {
    /// Path to charon's vici socket.
    #[arg(long, default_value = vici::DEFAULT_SOCKET)]
    socket: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Import a profile, load it into charon, and initiate the tunnel.
    Connect {
        #[arg(long)]
        profile: PathBuf,
        /// Connect to this gateway instead of the profile's own (use for a
        /// test responder).
        #[arg(long)]
        gateway_override: Option<String>,
    },
    /// List active IKE/CHILD SAs.
    Status,
    /// Terminate the named IKE SA.
    Disconnect {
        #[arg(long)]
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli)
}

#[cfg(unix)]
fn run(cli: Cli) -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    use ncp_profile::import_profile;
    use vici::Message;
    use vpn_core::swanctl::sanitize_name;

    fn check(resp: &Message, ctx: &str) -> anyhow::Result<()> {
        match resp.get_str("success").as_deref() {
            Some("yes") => Ok(()),
            _ => bail!(
                "{ctx} failed: {}",
                resp.get_str("errmsg").unwrap_or_else(|| "unknown error".to_string())
            ),
        }
    }

    match cli.command {
        Command::Connect {
            profile,
            gateway_override,
        } => {
            let text = std::fs::read_to_string(&profile)
                .with_context(|| format!("cannot read {}", profile.display()))?;
            let mut imported = import_profile(&text)
                .with_context(|| format!("failed to import {}", profile.display()))?;
            if let Some(gw) = gateway_override {
                eprintln!("overriding gateway {} -> {gw}", imported.config.gateway);
                imported.config.gateway = gw;
            }
            for w in &imported.warnings {
                eprintln!("! {w}");
            }

            let name = sanitize_name(&imported.config.name);
            let mut client = vici::connect_unix(&cli.socket)
                .with_context(|| format!("cannot connect to vici at {}", cli.socket))?;

            let resp = client.request("load-conn", bridge::load_conn_message(&imported.config, &name))?;
            check(&resp, "load-conn")?;

            let resp =
                client.request("load-shared", bridge::load_shared_message(&imported.config, &name))?;
            check(&resp, "load-shared")?;

            // The PSK is now in charon; drop our plaintext copy.
            drop(imported);

            let resp = client.request(
                "initiate",
                Message::new().str("child", &name[..]).str("ike", &name[..]),
            )?;
            check(&resp, "initiate")?;
            println!("Tunnel '{name}' initiated.");
        }
        Command::Status => {
            let mut client = vici::connect_unix(&cli.socket)
                .with_context(|| format!("cannot connect to vici at {}", cli.socket))?;
            let (events, _resp) =
                client.stream_request("list-sas", "list-sa", Message::new())?;
            print!("{}", bridge::format_sas(&events));
        }
        Command::Disconnect { name } => {
            let mut client = vici::connect_unix(&cli.socket)
                .with_context(|| format!("cannot connect to vici at {}", cli.socket))?;
            let resp = client.request("terminate", Message::new().str("ike", &name[..]))?;
            check(&resp, "terminate")?;
            println!("Tunnel '{name}' terminated.");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn run(_cli: Cli) -> anyhow::Result<()> {
    anyhow::bail!(
        "vpn-agent talks to charon over a Unix socket and must run on Linux \
         (inside the strongSwan container during development)."
    )
}
