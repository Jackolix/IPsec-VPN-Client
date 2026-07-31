//! Phase 0 CLI.
//!
//! `show`     — parse a profile (NCP `.ini`, Sophos `.scx`/`.tgb`) and print
//!              the interpreted config (redacted) plus every mapping warning.
//! `generate` — write a real swanctl.conf (contains the PSK!) for the
//!              strongSwan initiator to load. Output paths are gitignored.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use vpn_core::swanctl::{render, sanitize_name, SecretRendering};
use vpn_core::ImportedProfile;

#[derive(Parser)]
#[command(name = "vpn-cli", about = "VPN profile importer / strongSwan config generator")]
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

/// What a file turned out to hold. A Sophos `.pro` is not a connection — it
/// points at a user portal the profile is downloaded from — so it cannot be
/// folded into [`ImportedProfile`].
enum Loaded {
    Profile(Box<ImportedProfile>),
    Provisioning(Vec<sophos_profile::Provisioning>),
}

fn read_profile(path: &Path) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if meta.len() > MAX_PROFILE_BYTES {
        bail!("{} is too large to be a profile export", path.display());
    }
    fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}

/// Pick the importer by content rather than by extension: these files are
/// routinely renamed on the way to a user.
fn load(path: &Path) -> Result<Loaded> {
    let text = read_profile(path)?;
    let failed = || format!("failed to import {}", path.display());

    match sophos_profile::detect(&text) {
        Some(sophos_profile::Format::Provisioning) => Ok(Loaded::Provisioning(
            sophos_profile::pro::parse(&text).with_context(failed)?,
        )),
        Some(_) => Ok(Loaded::Profile(Box::new(
            sophos_profile::import_profile(&text).with_context(failed)?,
        ))),
        None => Ok(Loaded::Profile(Box::new(
            ncp_profile::import_profile(&text).with_context(failed)?,
        ))),
    }
}

/// `generate` needs an actual connection; a provisioning file has none.
fn load_connection(path: &Path) -> Result<ImportedProfile> {
    match load(path)? {
        Loaded::Profile(p) => Ok(*p),
        Loaded::Provisioning(_) => bail!(
            "{} is a provisioning file: it names a user portal to sign in to, and the profile \
             itself is downloaded from there. Run `show` to see the portal.",
            path.display()
        ),
    }
}

fn print_provisioning(entries: &[sophos_profile::Provisioning]) {
    println!("Sophos provisioning file — no connection settings in it.\n");
    for e in entries {
        println!("Entry:          {}", e.label());
        println!(
            "User portal:    {}",
            e.portal_url().unwrap_or_else(|| "(none)".to_string())
        );
        println!(
            "One-time code:  {}",
            if e.otp { "required" } else { "not required" }
        );
        println!(
            "Save login:     {}",
            if e.can_save_credentials {
                "allowed"
            } else {
                "not allowed"
            }
        );
    }
    println!(
        "\nSign in to the portal and download the .scx profile from it, then import that \
         file. Fetching it automatically is not implemented."
    );
}

fn print_summary(imported: &ImportedProfile) {
    let c = &imported.config;
    println!("Profile:        {}", c.name);
    println!("Gateway:        {}", c.gateway);
    println!("IKE version:    {}", c.ike_version.swanctl_value());
    println!(
        "Local ID:       {}{}",
        c.local_id.as_deref().unwrap_or("(none)"),
        match c.local_id_type {
            Some(t) => format!(" ({})", t.name()),
            None => String::new(),
        }
    );
    println!("Auth:           pre-shared key (***REDACTED***)");
    if let Some(ua) = &c.user_auth {
        println!(
            "User auth:      {} (username/password asked for on connect{})",
            match c.ike_version {
                vpn_core::IkeVersion::V1 => "XAuth",
                vpn_core::IkeVersion::V2 => "EAP-MSCHAPv2",
            },
            if ua.otp { ", one-time code" } else { "" }
        );
    }
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
        Command::Show { profile } => match load(&profile)? {
            Loaded::Provisioning(entries) => print_provisioning(&entries),
            Loaded::Profile(imported) => {
                print_summary(&imported);
                println!("\n--- swanctl.conf (secret redacted) ---");
                print!("{}", render(&imported.config, SecretRendering::Redact));
            }
        },
        Command::Generate {
            profile,
            out_dir,
            gateway_override,
        } => {
            let mut imported = load_connection(&profile)?;
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
