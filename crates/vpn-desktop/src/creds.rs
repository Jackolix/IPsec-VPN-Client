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

/// The username and password for a gateway's XAuth/EAP round.
///
/// These are the *person's* credentials, not the profile's: no profile file
/// contains them, and they are only ever collected at connect time.
pub struct UserCreds {
    pub username: String,
    pub password: Secret,
}

/// Keychain account for a profile's user-auth credentials. Suffixed so it
/// cannot collide with the PSK entry, which is keyed by the bare profile id.
fn user_account(id: &str) -> String {
    format!("{id}#userauth")
}

/// Both values live in one entry, as a small JSON object: the username is
/// part of the credential (it is what the gateway checks the password
/// against), and one entry means saving and forgetting them cannot half-fail.
///
/// [`Secret`] deliberately does not implement `Serialize`, so the JSON is
/// assembled and taken apart by hand here — that keeps every point where the
/// plaintext is copied greppable.
pub fn store_user(id: &str, creds: &UserCreds) -> Result<(), String> {
    let blob = serde_json::json!({
        "username": creds.username,
        "password": creds.password.expose(),
    })
    .to_string();
    entry(&user_account(id))?
        .set_password(&blob)
        .map_err(|e| format!("could not save credentials: {e}"))
}

pub fn load_user(id: &str) -> Result<Option<UserCreds>, String> {
    let blob = match entry(&user_account(id))?.get_password() {
        Ok(b) => b,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(format!("could not read credentials: {e}")),
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&blob).map_err(|_| "stored credentials are unreadable".to_string())?;
    let (Some(username), Some(password)) = (
        parsed.get("username").and_then(|v| v.as_str()),
        parsed.get("password").and_then(|v| v.as_str()),
    ) else {
        return Err("stored credentials are incomplete".to_string());
    };
    Ok(Some(UserCreds {
        username: username.to_string(),
        password: Secret::new(password.to_string()),
    }))
}

/// Remove saved user-auth credentials. Succeeds even if none were stored.
pub fn delete_user(id: &str) -> Result<(), String> {
    match entry(&user_account(id))?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("could not remove credentials: {e}")),
    }
}

/// Whether a username/password is stored for this profile. A keychain error
/// counts as "not stored", so the UI prompts rather than failing.
pub fn has_user(id: &str) -> bool {
    matches!(load_user(id), Ok(Some(_)))
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

    /// The user-auth entry round-trips both halves, and lives beside the PSK
    /// entry rather than overwriting it.
    #[test]
    fn user_creds_round_trip_beside_the_psk() {
        let id = format!("__vpn_desktop_user_test_{}", std::process::id());
        let _ = delete(&id);
        let _ = delete_user(&id);

        assert!(!has_user(&id));
        assert!(load_user(&id).unwrap().is_none());

        store(&id, &Secret::new("the-psk".to_string())).unwrap();
        store_user(
            &id,
            &UserCreds {
                username: "vpnuser".to_string(),
                password: Secret::new("pa55 word\"with\\quotes".to_string()),
            },
        )
        .unwrap();

        let got = load_user(&id).unwrap().unwrap();
        assert_eq!(got.username, "vpnuser");
        assert_eq!(got.password.expose(), "pa55 word\"with\\quotes");
        // The PSK entry is untouched by the user-auth one.
        assert_eq!(load(&id).unwrap().unwrap().expose(), "the-psk");

        delete_user(&id).unwrap();
        assert!(!has_user(&id));
        assert!(has(&id), "forgetting the login must not drop the PSK");

        delete_user(&id).unwrap();
        delete(&id).unwrap();
    }
}
