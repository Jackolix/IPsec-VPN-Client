//! Install and remove the macOS LaunchDaemon.
//!
//! This is the counterpart of the Windows `install` module (which registers an
//! SCM service). It runs *as root* — the app elevates it once with a single
//! authorization prompt — and does four things:
//!
//!   1. copies the helper binary to /Library/PrivilegedHelperTools,
//!   2. copies the charon tree out of the app bundle into
//!      /Library/Application Support/dev.jackolix.ipsecvpn,
//!   3. writes the launchd plist,
//!   4. bootstraps the daemon.
//!
//! Step 2 is the security-critical one. launchd runs the helper as root and the
//! helper execs charon as root, so neither may live in a directory an
//! unprivileged user can write — and an app bundle is exactly that, sitting in
//! ~/Applications or wherever it was dragged. Copying to a root-owned location
//! and chowning to root:wheel 0755 is what makes "root runs this binary" safe.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::protocol::{
    MACOS_CHARON_DIR, MACOS_HELPER_BIN, MACOS_HELPER_LOG, MACOS_LABEL, MACOS_PLIST,
    MACOS_RUN_DIR, MACOS_SUPPORT_DIR, MACOS_VERSION_FILE, MACOS_VERSION_UNSTAMPED,
};

fn plist_contents() -> String {
    // KeepAlive so a crashed helper comes back; RunAtLoad so it is up before
    // the GUI asks for anything. The log goes to /var/log because /var/run is
    // cleared on boot and launchd will not create a missing directory for it.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{MACOS_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{MACOS_HELPER_BIN}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{MACOS_HELPER_LOG}</string>
</dict>
</plist>
"#
    )
}

/// Copy `src` to `dst` and make it root-owned and non-writable by anyone else.
fn install_root_owned(src: &Path, dst: &Path, mode: u32) -> Result<(), String> {
    if let Some(dir) = dst.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    // Remove first: overwriting a running binary in place fails with ETXTBSY.
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)
        .map_err(|e| format!("cannot copy {} to {}: {e}", src.display(), dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set mode on {}: {e}", dst.display()))?;
    strip_quarantine(dst);
    chown_root(dst)
}

/// Drop `com.apple.quarantine` from an installed file.
///
/// This matters only for the case that is hardest to test: a *downloaded* app.
/// Everything in a bundle that arrived from a browser carries the quarantine
/// attribute, and `std::fs::copy` on macOS preserves extended attributes (it is
/// `fcopyfile` with `COPYFILE_ALL`) — so without this, charon and openvpn land
/// in /Library still marked as downloaded, and a root daemon then execs them.
/// A locally built app has no quarantine attribute at all, which is exactly why
/// this would never show up in development.
///
/// Best-effort: the attribute is usually absent, and `ENOATTR` is the normal
/// result rather than a failure.
fn strip_quarantine(path: &Path) {
    const QUARANTINE: &[u8] = b"com.apple.quarantine\0";
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    unsafe {
        libc::removexattr(
            c_path.as_ptr(),
            QUARANTINE.as_ptr() as *const libc::c_char,
            0,
        );
    }
}

fn chown_root(path: &Path) -> Result<(), String> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "path contains a NUL".to_string())?;
    // 0:0 — root:wheel. Anything else and an unprivileged user could replace
    // the binary that root is about to execute.
    if unsafe { libc::chown(c.as_ptr(), 0, 0) } != 0 {
        return Err(format!(
            "cannot chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn copy_tree_root_owned(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("cannot create {}: {e}", dst.display()))?;
    chown_root(dst)?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("cannot set mode on {}: {e}", dst.display()))?;
    let entries = std::fs::read_dir(src)
        .map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            copy_tree_root_owned(&from, &to)?;
        } else {
            // 0755 throughout: charon and its dylibs are all executable, and
            // strongswan.conf being world-readable is harmless (it holds no
            // secret — the PSK is pushed over vici, never written to disk).
            install_root_owned(&from, &to, 0o755)?;
        }
    }
    Ok(())
}

/// Install the helper and start it. `helper_src` is this binary, `charon_src`
/// the `charon/` directory inside the app bundle, and `openvpn_src` the
/// `openvpn/` one when the SSL VPN datapath is staged. Must run as root.
///
/// openvpn is copied for exactly the same reason charon is: the helper runs it
/// as root, so it must not live anywhere an unprivileged user can write. It is
/// optional only so a build without the SSL datapath staged still installs a
/// working IPsec helper.
pub fn install(
    helper_src: &Path,
    charon_src: &Path,
    openvpn_src: Option<&Path>,
) -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("installing the helper needs root".to_string());
    }
    if !charon_src.join("charon").is_file() {
        return Err(format!(
            "no charon found at {} — build it with scripts/build-strongswan-macos.sh",
            charon_src.display()
        ));
    }

    // Stop an existing one first, so the binary is not busy and the new one is
    // what comes back.
    let _ = bootout();

    install_root_owned(helper_src, Path::new(MACOS_HELPER_BIN), 0o755)?;
    copy_tree_root_owned(charon_src, Path::new(MACOS_CHARON_DIR))?;
    let mut datapaths = "IPsec".to_string();
    if let Some(src) = openvpn_src {
        copy_tree_root_owned(src, &Path::new(MACOS_SUPPORT_DIR).join("openvpn"))?;
        datapaths.push_str(" + SSL");
    }

    // Stamped before the daemon comes up, so the GUI never sees a running
    // helper with no version beside it and concludes it is a hand-installed
    // one. Missing rather than wrong when the version cannot be determined.
    let _ = std::fs::remove_file(MACOS_VERSION_FILE);
    let stamp = installing_app_version(helper_src)
        .unwrap_or_else(|| MACOS_VERSION_UNSTAMPED.to_string());
    if std::fs::write(MACOS_VERSION_FILE, &stamp).is_ok() {
        let _ =
            std::fs::set_permissions(MACOS_VERSION_FILE, std::fs::Permissions::from_mode(0o644));
        let _ = chown_root(Path::new(MACOS_VERSION_FILE));
    }

    std::fs::write(MACOS_PLIST, plist_contents())
        .map_err(|e| format!("cannot write {MACOS_PLIST}: {e}"))?;
    std::fs::set_permissions(MACOS_PLIST, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("cannot set mode on {MACOS_PLIST}: {e}"))?;
    chown_root(Path::new(MACOS_PLIST))?;

    // `bootstrap system` is the modern replacement for `launchctl load`.
    let out = Command::new("/bin/launchctl")
        .args(["bootstrap", "system", MACOS_PLIST])
        .output()
        .map_err(|e| format!("cannot run launchctl: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("launchctl bootstrap failed: {}", err.trim()));
    }
    Ok(format!("helper installed and started ({MACOS_LABEL}); datapaths: {datapaths}"))
}

/// The version of the app bundle `helper_src` was copied out of.
///
/// Read from the bundle's own `Info.plist` rather than passed in as an
/// argument, so `sudo vpn-broker install` from a checkout behaves the same as
/// the GUI doing it — and so there is no way for the two to disagree. `None`
/// when the helper is not inside a bundle at all, which is every dev build;
/// the GUI treats an unknown version as "not stale" rather than nagging.
fn installing_app_version(helper_src: &Path) -> Option<String> {
    // <App>.app/Contents/Resources/helper/vpn-broker -> <App>.app/Contents
    let contents = helper_src.parent()?.parent()?.parent()?;
    let plist = contents.join("Info.plist");
    if !plist.is_file() {
        return None;
    }
    // plutil, not a text search: Tauri writes XML today but a binary plist is
    // just as valid and would silently stop matching.
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleShortVersionString", "raw", "-o", "-"])
        .arg(&plist)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// The app version that installed what is currently under /Library, if it
/// recorded one. See [`MACOS_VERSION_FILE`].
pub fn installed_version() -> Option<String> {
    let v = std::fs::read_to_string(MACOS_VERSION_FILE).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Stop and remove the helper, and everything it put outside the app bundle.
/// Must run as root.
///
/// The order matters. charon and openvpn are the only things that can undo
/// their own routes, `/etc/resolver` files and utun devices, so they are asked
/// to shut down *before* the bootout — once the helper is gone there is
/// nothing left to ask, and a half-removed install leaves the machine routing
/// traffic into a tunnel nobody owns.
pub fn uninstall() -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("removing the helper needs root".to_string());
    }

    crate::privileged::kill_our_openvpn();
    let _ = crate::privileged::charon_stop();
    // After the daemons, while the records under RUN_DIR still exist.
    crate::privileged::purge_dns();

    let _ = bootout();
    let _ = std::fs::remove_file(MACOS_PLIST);
    let _ = std::fs::remove_file(MACOS_HELPER_BIN);
    let _ = std::fs::remove_dir_all(MACOS_SUPPORT_DIR);
    // The sockets, charon's log and the DNS records; then the helper's own
    // stderr. Both directories are ours alone, created by us.
    let _ = std::fs::remove_dir_all(MACOS_RUN_DIR);
    let _ = std::fs::remove_file(MACOS_HELPER_LOG);

    // Report what is actually gone rather than that the calls were made: this
    // is the one moment a user is told the machine is clean.
    let left: Vec<&str> = [
        MACOS_PLIST,
        MACOS_HELPER_BIN,
        MACOS_SUPPORT_DIR,
        MACOS_RUN_DIR,
    ]
    .into_iter()
    .filter(|p| Path::new(p).exists())
    .collect();
    if left.is_empty() {
        Ok("helper removed".to_string())
    } else {
        Err(format!("could not remove: {}", left.join(", ")))
    }
}

fn bootout() -> Result<(), String> {
    let out = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{MACOS_LABEL}")])
        .output()
        .map_err(|e| format!("cannot run launchctl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Is the daemon registered with launchd?
pub fn installed() -> bool {
    Path::new(MACOS_PLIST).is_file() && Path::new(MACOS_HELPER_BIN).is_file()
}

/// The `openvpn/` directory staged beside the helper, for [`install`]. Same
/// search as [`bundled_charon_dir`]; `None` when the SSL datapath is not built.
pub fn bundled_openvpn_dir(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    for candidate in [
        dir.join("../openvpn"),
        dir.join("../Resources/openvpn"),
        dir.join("openvpn"),
        dir.join("../../out/openvpn-macos"),
    ] {
        if candidate.join("openvpn").is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The `charon/` directory inside the running app bundle, for [`install`].
/// `Contents/MacOS/vpn-broker` → `Contents/Resources/charon`.
pub fn bundled_charon_dir(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    for candidate in [
        // Bundled: the helper ships at Contents/Resources/helper/vpn-broker and
        // charon beside it at Contents/Resources/charon.
        dir.join("../charon"),
        // Contents/MacOS/<exe> -> Contents/Resources/charon.
        dir.join("../Resources/charon"),
        dir.join("charon"),
        // Dev: target/release/vpn-broker -> repo/out/strongswan-macos, so the
        // helper can be installed straight from a cargo build.
        dir.join("../../out/strongswan-macos"),
    ] {
        if candidate.join("charon").is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{plist_contents, strip_quarantine};

    /// The failure this prevents cannot happen on a development machine: a
    /// locally built app is never quarantined, so the attribute is only ever
    /// present on the downloaded builds real users install.
    #[test]
    fn an_installed_file_does_not_stay_quarantined() {
        let dir = std::env::temp_dir().join("vpn-quarantine-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("staged.bin");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();

        let set = std::process::Command::new("/usr/bin/xattr")
            .args(["-w", "com.apple.quarantine", "0083;00000000;Safari;"])
            .arg(&f)
            .status()
            .expect("xattr");
        assert!(set.success());
        assert!(has_quarantine(&f), "precondition: the attribute is set");

        strip_quarantine(&f);
        assert!(!has_quarantine(&f), "quarantine should have been removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn has_quarantine(p: &std::path::Path) -> bool {
        let out = std::process::Command::new("/usr/bin/xattr")
            .arg(p)
            .output()
            .expect("xattr");
        String::from_utf8_lossy(&out.stdout).contains("com.apple.quarantine")
    }

    /// launchd silently ignores a malformed plist, which would present as "the
    /// helper installed fine but never starts". Check it parses.
    #[test]
    fn the_generated_plist_is_valid() {
        let dir = std::env::temp_dir().join("vpn-helper-plist-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.plist");
        std::fs::write(&path, plist_contents()).unwrap();
        let out = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .expect("plutil");
        assert!(
            out.status.success(),
            "plutil rejected the plist: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("/Library/PrivilegedHelperTools/"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

