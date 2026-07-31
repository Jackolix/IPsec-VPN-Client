//! Phase 1 agent. Runs on Linux (inside the strongSwan container during
//! development), imports an NCP profile, and drives charon over vici:
//!
//!   vpn-agent connect --profile p.ini [--gateway-override HOST]
//!   vpn-agent status
//!   vpn-agent disconnect --name NAME
//!
//! The connection flows live in the shared `vpn-control` crate. The PSK is
//! handed to charon via `load-shared` in memory; no swanctl.conf containing
//! the secret is written to disk.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vpn_control::{status::render_text, Transport};

#[derive(Parser)]
#[command(name = "vpn-agent", about = "Import NCP profiles and drive charon over vici")]
struct Cli {
    /// Path to charon's vici Unix socket.
    #[arg(long, default_value = "/var/run/charon.vici")]
    socket: String,
    /// Use a TCP vici socket (`host:port`) instead of the Unix socket.
    #[arg(long)]
    tcp: Option<String>,
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
        /// XAuth/EAP username, for a gateway that asks for a login on top of
        /// the pre-shared key (Sophos profiles typically do).
        #[arg(long)]
        username: Option<String>,
        /// XAuth/EAP password. Prompted for if a username was given without
        /// one, so it need not appear in the shell history.
        #[arg(long)]
        password: Option<String>,
    },
    /// List active IKE/CHILD SAs.
    Status,
    /// Terminate the named IKE SA.
    Disconnect {
        #[arg(long)]
        name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let transport = match &cli.tcp {
        Some(addr) => Transport::Tcp(addr.clone()),
        None => Transport::Unix(cli.socket.clone()),
    };

    match cli.command {
        Command::Connect {
            profile,
            gateway_override,
            username,
            password,
        } => {
            use vpn_core::swanctl::sanitize_name;

            let text = std::fs::read_to_string(&profile)
                .with_context(|| format!("cannot read {}", profile.display()))?;
            // Same content-based dispatch the desktop and vpn-cli use, so a
            // Sophos export can be driven from here too.
            let mut imported = match sophos_profile::detect(&text) {
                Some(sophos_profile::Format::Provisioning) => anyhow::bail!(
                    "{} is a provisioning file, not a profile — sign in to the user portal it \
                     names and import the profile downloaded from there",
                    profile.display()
                ),
                Some(_) => sophos_profile::import_profile(&text)
                    .with_context(|| format!("failed to import {}", profile.display()))?,
                None => ncp_profile::import_profile(&text)
                    .with_context(|| format!("failed to import {}", profile.display()))?,
            };
            if let Some(gw) = gateway_override {
                eprintln!("overriding gateway {} -> {gw}", imported.config.gateway);
                imported.config.gateway = gw;
            }
            for w in &imported.warnings {
                eprintln!("! {w}");
            }

            // The profile only says *that* a login is required; the username
            // and password are the user's to supply.
            let user_password = match (&imported.config.user_auth, &username) {
                (Some(_), Some(user)) => {
                    imported.config.user_auth.as_mut().unwrap().username = Some(user.clone());
                    let pw = match &password {
                        Some(p) => p.clone(),
                        None => rpassword::prompt_password(format!("Password for {user}: "))
                            .context("could not read the password")?,
                    };
                    Some(vpn_core::Secret::new(pw))
                }
                (Some(_), None) => anyhow::bail!(
                    "this profile's gateway asks for a username and password; pass --username"
                ),
                (None, Some(_)) => {
                    eprintln!("! this profile needs no second authentication round; ignoring --username");
                    None
                }
                (None, None) => None,
            };

            let name = sanitize_name(&imported.config.name);
            let outcome = vpn_control::connect_logged(
                &transport,
                &imported.config,
                &name,
                user_password.as_ref(),
            )?;
            drop(user_password); // and the password once it has been sent
            drop(imported); // discard the plaintext PSK once charon has it

            // Live handshake transcript from charon's log bus.
            for line in &outcome.log {
                eprintln!("  [{}] {}", line.group, line.msg);
            }
            if outcome.connected {
                println!("Tunnel '{name}' initiated.");
            } else {
                anyhow::bail!(
                    "handshake failed: {}",
                    outcome.error.as_deref().unwrap_or("unknown reason")
                );
            }
        }
        Command::Status => {
            let sas = vpn_control::status(&transport)?;
            print!("{}", render_text(&sas));
        }
        Command::Disconnect { name } => {
            vpn_control::disconnect(&transport, &name)?;
            println!("Tunnel '{name}' terminated.");
        }
    }
    Ok(())
}
