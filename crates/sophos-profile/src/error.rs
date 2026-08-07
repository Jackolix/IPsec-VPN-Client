//! Failures shared by the three Sophos formats.
//!
//! SECURITY: no variant may carry a value read out of the profile's secret
//! fields. Errors are shown in the UI and written to logs, so only field
//! *names*, algorithm tokens and section names appear here.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("not valid JSON: {0}")]
    Json(String),
    #[error("not a valid Apple property list: {0}")]
    Plist(String),
    #[error(transparent)]
    Ini(#[from] vpn_core::ini::ParseError),
    #[error("input exceeds {0} bytes")]
    TooLarge(usize),
    #[error("missing required field {0}")]
    MissingField(&'static str),
    #[error("{0} is empty")]
    EmptyField(&'static str),
    #[error("{field}={value:?} is not valid: {why}")]
    BadValue {
        field: &'static str,
        value: String,
        why: &'static str,
    },
    #[error("section [{0}] referenced but not found")]
    SectionNotFound(String),
    #[error("{context}: unknown algorithm {token:?} — refusing to guess what to negotiate")]
    UnknownAlgorithm {
        context: &'static str,
        token: String,
    },
    #[error("{0} is not supported yet")]
    Unsupported(String),
    #[error("this is a provisioning file (.pro), not a connection profile — it names a user portal to sign in to, and the profile is downloaded from there")]
    IsProvisioning,
    #[error("file is not a recognisable Sophos profile (.scx, .tgb or .pro)")]
    Unrecognised,
}

impl From<serde_json::Error> for ImportError {
    /// serde_json's `Display` reports line/column and the expected type, never
    /// the offending text, so it cannot leak a secret out of the profile.
    fn from(e: serde_json::Error) -> Self {
        ImportError::Json(e.to_string())
    }
}
