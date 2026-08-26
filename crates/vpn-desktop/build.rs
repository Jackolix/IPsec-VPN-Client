use std::path::PathBuf;

fn main() {
    check_staged_charon();
    tauri_build::build();
}

/// The plugin names that must appear in a staged `charon-svc.exe`, and what
/// breaks without each. The daemon is built `--disable-defaults`, so a plugin
/// left off the `./configure` line is simply absent from the binary — see the
/// rationale in `docker/strongswan-windows/Dockerfile`.
const REQUIRED_PLUGINS: [(&str, &str); 3] = [
    ("xauth-generic", "IKEv1 XAuth — the interactive round a Sophos .tgb profile needs"),
    ("eap-mschapv2", "the IKEv2 equivalent, used by the Sophos .scx/portal profiles"),
    ("eap-identity", "the EAP identity exchange that precedes it"),
];

/// Refuse to bundle a charon that cannot serve the profiles this app ships for.
///
/// `out/strongswan-windows` is staged by hand (`scripts/build-strongswan-windows.ps1`
/// runs a Docker cross-build) and nothing else rebuilds it — so it silently goes
/// stale while the Dockerfile beside it gains plugins. Installing such a bundle
/// *downgrades* the daemon on the target machine, and a Sophos gateway then
/// answers `NO_PROPOSAL_CHOSEN` at IKE_SA_INIT, which surfaces in the app as the
/// far less obvious "establishing CHILD_SA failed".
///
/// A missing tree is fine (a dev build, or a platform that bundles no daemon).
/// A tree that is *present but incapable* is not: that is the case that ships.
fn check_staged_charon() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let staged = manifest_dir().join("../../out/strongswan-windows");
    let exe = staged.join("charon-svc.exe");
    println!("cargo:rerun-if-changed={}", exe.display());

    if !exe.is_file() {
        return; // nothing staged — nothing to ship, nothing to check
    }
    let Ok(bytes) = std::fs::read(&exe) else {
        return;
    };
    let missing: Vec<&(&str, &str)> = REQUIRED_PLUGINS
        .iter()
        .filter(|(name, _)| !contains(&bytes, name.as_bytes()))
        .collect();

    if !missing.is_empty() {
        let detail = missing
            .iter()
            .map(|(name, why)| format!("    {name} — {why}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "\n\nThe staged strongSwan daemon is out of date and would be bundled as-is.\n\
             \n  {}\n\nis missing:\n{detail}\n\n\
             Rebuild it (Docker Desktop must be running):\n\
             \n    powershell -File scripts/build-strongswan-windows.ps1\n\n\
             Bundling it anyway downgrades charon on the target machine, and Sophos IPsec \
             then fails at IKE_SA_INIT with NO_PROPOSAL_CHOSEN.\n",
            exe.display()
        );
    }

    // The daemon's own config is staged from `docker/strongswan-windows/strongswan.conf`
    // and can be stale independently of the binary. Without the resolve block
    // charon discards the gateway's pushed DNS, so a profile that carries no DNS
    // of its own resolves nothing.
    let conf = staged.join("etc").join("strongswan.conf");
    println!("cargo:rerun-if-changed={}", conf.display());
    if let Ok(text) = std::fs::read_to_string(&conf) {
        if !text.contains("resolve") {
            println!(
                "cargo:warning=staged {} has no resolve block — the gateway's pushed DNS \
                 will be discarded; re-run scripts/build-strongswan-windows.ps1",
                conf.display()
            );
        }
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
}

/// Substring search over the raw binary. The plugin names live in it as plain
/// ASCII (a monolithic build registers them by name), so this needs no PE parsing.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
