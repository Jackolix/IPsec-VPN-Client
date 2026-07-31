//! Internal VPN connection config model, decoupled from any import format
//! (NCP ini, Sophos .scx/.tgb, manual entry, ...), plus generation of
//! strongSwan `swanctl.conf`.

pub mod ini;
pub mod model;
pub mod swanctl;

pub use model::*;
