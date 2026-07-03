//! Phase 0 CLI.
//!
//! `show`     — parse an NCP ini and print the interpreted config (redacted)
//!              plus every mapping warning.
//! `generate` — write a real swanctl.conf (contains the PSK!) for the
//!              strongSwan initiator to load. Output paths are gitignored.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ncp_profile::{import_profile, ImportedProfile};
use std::fs;
use std::path::{Path, PathBuf};
use vpn_core::swanctl::{render, sanitize_name, SecretRendering};

#[derive(Parser)]
#[command(name = "vpn-cli", about = "NCP profile importer / strongSwan config generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a profile and print the interpreted config (secret redacted).
    Show { profile: PathBuf },
    /// Generate a swanctl.conf for the profile. THE OUTPUT CONTAINS THE PSK.
    Generate {
        profile: PathBuf,
        /// Output directory (default: ./out)
        #[arg(short, long, default_value = "out")]
        out_dir: PathBuf,
        /// Connect to this address instead of the profile's gateway.
        /// Use this to target a test responder instead of production.
        #[arg(long)]
        gateway_override: Option<String>,
    },
}

const MAX_PROFILE_BYTES: u64 = 1024 * 1024;

fn load(path: &Path) -> Result<ImportedProfile> {
    let meta = fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if meta.len() > MAX_PROFILE_BYTES {
        bail!("{} is too large to be a profile export", path.display());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    import_profile(&text).with_context(|| format!("failed to import {}", path.display()))
}

fn print_summary(imported: &ImportedProfile) {
    let c = &imported.config;
    println!("Profile:        {}", c.name);
    println!("Gateway:        {}", c.gateway);
    println!(
        "Local ID:       {}",
        c.local_id.as_deref().unwrap_or("(none)")
    );
    println!("Auth:           pre-shared key (***REDACTED***)");
    println!(
        "IKE proposal:   {}-{}-{}-{}",
        c.ike_enc.swanctl_name(),
        c.ike_integ.swanctl_name(),
        c.ike_prf.swanctl_name(),
        c.ike_dh.swanctl_name()
    );
    println!(
        "ESP proposal:   {}-{}{}",
        c.esp_enc.swanctl_name(),
        c.esp_integ.swanctl_name(),
        match c.pfs {
            Some(g) => format!(" (PFS {})", g.swanctl_name()),
            None => " (no PFS)".to_string(),
        }
    );
    print!("Remote subnets: ");
    if c.remote_subnets.is_empty() {
        println!("(none!)");
    } else {
        println!(
            "{}",
            c.remote_subnets
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "Virtual IP:     {}",
        if c.request_virtual_ip {
            "requested from gateway"
        } else {
            "no"
        }
    );
    println!("Compression:    {}", if c.compression { "yes" } else { "no" });

    if !imported.warnings.is_empty() {
        println!("\n{} warning(s):", imported.warnings.len());
        for w in &imported.warnings {
            println!("  ! {w}");
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Show { profile } => {
            let imported = load(&profile)?;
            print_summary(&imported);
            println!("\n--- swanctl.conf (secret redacted) ---");
            print!("{}", render(&imported.config, SecretRendering::Redact));
        }
        Command::Generate {
            profile,
            out_dir,
            gateway_override,
        } => {
            let mut imported = load(&profile)?;
            if let Some(gw) = gateway_override {
                println!(
                    "NOTE: overriding gateway {} -> {gw}",
                    imported.config.gateway
                );
                imported.config.gateway = gw;
            } else {
                println!(
                    "WARNING: targeting the profile's own gateway ({}). Only proceed \
                     if you are authorized to connect to it; use --gateway-override \
                     for a test responder.",
                    imported.config.gateway
                );
            }
            print_summary(&imported);

            fs::create_dir_all(&out_dir)
                .with_context(|| format!("cannot create {}", out_dir.display()))?;
            let file = out_dir.join(format!(
                "{}.swanctl.conf",
                sanitize_name(&imported.config.name)
            ));
            fs::write(&file, render(&imported.config, SecretRendering::Include))
                .with_context(|| format!("cannot write {}", file.display()))?;
            println!(
                "\nWrote {} — contains the PSK; do not commit or share it.",
                file.display()
            );
        }
    }
    Ok(())
}
