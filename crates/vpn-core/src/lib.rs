//! Internal VPN connection config model, decoupled from any import format
//! (NCP ini, manual entry, ...), plus generation of strongSwan `swanctl.conf`.

pub mod model;
pub mod swanctl;

pub use model::*;
