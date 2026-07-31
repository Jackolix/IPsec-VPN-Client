//! What every profile importer returns, regardless of the format it read.
//!
//! Lives here rather than in one importer so the app can hold an NCP `.ini`,
//! a Sophos `.scx` and a legacy `.tgb` in the same list without caring which
//! parser produced them.

use crate::model::ConnectionConfig;

/// A non-fatal finding the UI must surface before first connect.
///
/// The importers' policy is that anything safety-critical (auth method,
/// algorithms, DH groups) that cannot be mapped is a hard error — failing to
/// connect is safe, silently negotiating the wrong thing is not — while
/// anything merely unconfirmed imports and warns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportWarning(pub String);

impl std::fmt::Display for ImportWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub struct ImportedProfile {
    pub config: ConnectionConfig,
    pub warnings: Vec<ImportWarning>,
}

/// Collects warnings while an importer walks a profile.
#[derive(Debug, Default)]
pub struct Warnings(Vec<ImportWarning>);

impl Warnings {
    pub fn new() -> Self {
        Warnings(Vec::new())
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.0.push(ImportWarning(msg.into()));
    }

    pub fn into_vec(self) -> Vec<ImportWarning> {
        self.0
    }

    pub fn as_slice(&self) -> &[ImportWarning] {
        &self.0
    }
}
