//! The ini parser this importer is built on now lives in `vpn-core`, where the
//! Sophos `.tgb` importer shares it. Re-exported here so the NCP code (and its
//! tests) keep referring to `crate::parser`.

pub use vpn_core::ini::{parse, Document, ParseError, Section, MAX_INPUT_LEN};
