//! PSK storage in the OS keychain (Windows Credential Manager, macOS Keychain,
//! Secret Service on Linux) via the `keyring` crate.
//!
//! The point is to get the pre-shared key out of the plaintext `.ini` on disk:
//! once saved here, [`connect`](crate::backend::connect) prefers the keychain
//! copy over the one parsed from the profile file. The plaintext only ever
//! lives in a short-lived [`Secret`], which redacts itself and is zeroed on
//! drop.

use keyring::Entry;
use vpn_core::Secret;

/// Namespace for our entries in the OS credential store. Matches the app's
/// bundle identifier so entries are attributable to this app.
const SERVICE: &str = "dev.jackolix.ipsecvpn";

fn entry(account: &str) -> Result<Entry, String> {
    Entry::new(SERVICE, account).map_err(|e| format!("keychain unavailable: {e}"))
}

/// Save (or overwrite) the PSK for `account` (the profile id).
pub fn store(account: &str, psk: &Secret) -> Result<(), String> {
    entry(account)?
        .set_password(psk.expose())
        .map_err(|e| format!("could not save credentials: {e}"))
}

/// Load the stored PSK for `account`, or `None` if nothing is stored.
pub fn load(account: &str) -> Result<Option<Secret>, String> {
    match entry(account)?.get_password() {
        Ok(p) => Ok(Some(Secret::new(p))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("could not read credentials: {e}")),
    }
}

/// Remove any stored PSK for `account`. Succeeds even if none was stored.
pub fn delete(account: &str) -> Result<(), String> {
    match entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("could not remove credentials: {e}")),
    }
}

/// Whether a PSK is stored for `account`. A keychain error is treated as
/// "not stored" so the UI degrades gracefully rather than erroring on load.
pub fn has(account: &str) -> bool {
    matches!(load(account), Ok(Some(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the real OS credential store: store -> load -> delete round
    // trip under a throwaway account name, cleaned up at the end.
    #[test]
    fn store_load_delete_round_trip() {
        let account = format!("__vpn_desktop_test_{}", std::process::id());
        let _ = delete(&account); // ensure a clean slate

        assert!(!has(&account));
        assert!(load(&account).unwrap().is_none());

        store(&account, &Secret::new("round-trip-secret".to_string())).unwrap();
        assert!(has(&account));
        assert_eq!(load(&account).unwrap().unwrap().expose(), "round-trip-secret");

        delete(&account).unwrap();
        assert!(!has(&account));
        // Deleting again is not an error.
        delete(&account).unwrap();
    }
}
