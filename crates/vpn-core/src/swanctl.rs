//! Render a [`ConnectionConfig`] as a strongSwan `swanctl.conf`.

use crate::model::{AuthMethod, ConnectionConfig};
use std::fmt::Write;

/// Whether the rendered config contains the real PSK or a redaction marker.
/// Use `Redact` for anything shown to a user or written to logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRendering {
    Include,
    Redact,
}

/// swanctl section names: keep to a conservative charset so we never produce
/// a syntactically invalid or ambiguous config from a hostile profile name.
pub fn sanitize_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out = "conn".to_string();
    }
    out
}

/// Quote a value for swanctl.conf. strongSwan's parser understands
/// double-quoted strings with backslash escapes.
fn quote(value: &str) -> String {
    let mut s = String::with_capacity(value.len() + 2);
    s.push('"');
    for c in value.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

pub fn render(config: &ConnectionConfig, secrets: SecretRendering) -> String {
    let name = sanitize_name(&config.name);
    let mut out = String::new();

    let ike_proposal = config.ike_proposal();
    let esp_proposal = config.esp_proposal();
    let remote_ts = config
        .remote_subnets
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");

    writeln!(out, "connections {{").unwrap();
    writeln!(out, "    {name} {{").unwrap();
    writeln!(out, "        version = 2").unwrap();
    writeln!(out, "        remote_addrs = {}", config.gateway).unwrap();
    if config.request_virtual_ip {
        writeln!(out, "        vips = 0.0.0.0").unwrap();
    }
    writeln!(out, "        proposals = {ike_proposal}").unwrap();
    writeln!(out, "        local {{").unwrap();
    writeln!(out, "            auth = psk").unwrap();
    if let Some(id) = &config.local_id {
        writeln!(out, "            id = {}", quote(id)).unwrap();
    }
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        remote {{").unwrap();
    writeln!(out, "            auth = psk").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        children {{").unwrap();
    writeln!(out, "            {name} {{").unwrap();
    if !remote_ts.is_empty() {
        writeln!(out, "                remote_ts = {remote_ts}").unwrap();
    }
    writeln!(out, "                esp_proposals = {esp_proposal}").unwrap();
    if config.compression {
        writeln!(out, "                ipcomp = yes").unwrap();
    }
    writeln!(out, "                start_action = none").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    let AuthMethod::PresharedKey(psk) = &config.auth;
    let secret_value = match secrets {
        SecretRendering::Include => quote(psk.expose()),
        SecretRendering::Redact => quote("***REDACTED***"),
    };
    writeln!(out, "secrets {{").unwrap();
    writeln!(out, "    ike-{name} {{").unwrap();
    if let Some(id) = &config.local_id {
        writeln!(out, "        id = {}", quote(id)).unwrap();
    }
    writeln!(out, "        secret = {secret_value}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();

    out
}
