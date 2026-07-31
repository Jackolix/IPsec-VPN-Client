//! Importer for the profile formats a Sophos firewall hands out.
//!
//! | Format | What it is | Result |
//! |---|---|---|
//! | `.scx` | Sophos Connect profile — JSON, close to a serialised swanctl connection | a connection |
//! | `.tgb` | legacy Cyberoam/TheGreenBow client profile — ini-shaped, IKEv1 | a connection |
//! | `.pro` | provisioning pointer to a user portal | [`Format::Provisioning`], not a connection |
//!
//! All three are undocumented, so the importers follow the same policy as the
//! NCP one: anything safety-critical that cannot be mapped is a hard error —
//! failing to connect is safe, silently negotiating something else is not —
//! while anything merely unconfirmed imports and raises a warning the UI must
//! show before first connect.
//!
//! SECURITY: `.scx` and `.tgb` both carry a live pre-shared key in plaintext.
//! It goes straight into [`vpn_core::Secret`] and must never be logged,
//! written back out, or committed.

pub mod error;
pub mod pro;
pub mod proposal;
pub mod scx;
pub mod tgb;

pub use error::ImportError;
pub use pro::Provisioning;
pub use vpn_core::import::{ImportWarning, ImportedProfile};

/// Which of the three formats a file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    /// Sophos Connect profile (`.scx`).
    Connect,
    /// Legacy Cyberoam/TheGreenBow profile (`.tgb`).
    Legacy,
    /// Provisioning pointer (`.pro`) — names a user portal to sign in to.
    Provisioning,
}

/// The file extensions this crate can be handed.
pub const EXTENSIONS: [&str; 3] = ["scx", "tgb", "pro"];

/// Is this an extension we import? Case-insensitive.
pub fn handles_extension(ext: &str) -> bool {
    EXTENSIONS.iter().any(|e| ext.eq_ignore_ascii_case(e))
}

/// Work out a file's format from its contents.
///
/// Content rather than extension, because these files are routinely renamed on
/// the way to a user (mail gateways rewrite `.scx`, and both JSON formats get
/// saved as `.txt`), and because a file that claims one format while being
/// another should be treated as what it actually is.
pub fn detect(input: &str) -> Option<Format> {
    if pro::looks_like(input) {
        Some(Format::Provisioning)
    } else if scx::looks_like(input) {
        Some(Format::Connect)
    } else if tgb::looks_like(input) {
        Some(Format::Legacy)
    } else {
        None
    }
}

/// Import any Sophos *connection* profile.
///
/// A `.pro` is rejected with [`ImportError::IsProvisioning`] — it has no
/// connection in it to import; call [`pro::parse`] for those.
pub fn import_profile(input: &str) -> Result<ImportedProfile, ImportError> {
    match detect(input) {
        Some(Format::Connect) => scx::import(input),
        Some(Format::Legacy) => tgb::import(input),
        Some(Format::Provisioning) => Err(ImportError::IsProvisioning),
        None => Err(ImportError::Unrecognised),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_each_format_by_content() {
        assert_eq!(
            detect(r#"[{"gateway":"203.0.113.10","user_portal_port":4443}]"#),
            Some(Format::Provisioning)
        );
        assert_eq!(
            detect(r#"{"name":"x","gateway":"203.0.113.10"}"#),
            Some(Format::Connect)
        );
        assert_eq!(
            detect("# Written by VpnConf\n[Phase 1]\n1.2.3.4 = x-P1\n"),
            Some(Format::Legacy)
        );
        assert_eq!(detect("hello"), None);
    }

    #[test]
    fn a_provisioning_file_is_not_importable_as_a_connection() {
        let err = import_profile(r#"[{"gateway":"203.0.113.10"}]"#).unwrap_err();
        assert!(matches!(err, ImportError::IsProvisioning));
    }

    #[test]
    fn extensions_are_matched_case_insensitively() {
        assert!(handles_extension("SCX"));
        assert!(handles_extension("tgb"));
        assert!(!handles_extension("ini"));
    }
}
