//! Importer for NCP Secure Entry/Enterprise Client `.ini` VPN profiles.
//!
//! The NCP export format is proprietary and undocumented; the numeric code
//! mappings live in [`codes`] with an explicit confidence level each, and the
//! importer surfaces a warning for every value it is not sure about instead
//! of silently guessing.
//!
//! SECURITY: profile files contain a live pre-shared key in plaintext. The
//! `Secret=` value goes straight into [`vpn_core::Secret`] (redacted Debug/
//! Display) and must never be logged or committed.

pub mod codes;
pub mod import;
pub mod parser;

pub use import::{import_profile, ImportError, ImportWarning, ImportedProfile};
