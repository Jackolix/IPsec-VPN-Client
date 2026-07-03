//! Parse `list-sa` events from charon into structured, serializable status,
//! and render a text summary for the CLI.

use serde::Serialize;
use vici::Message;

#[derive(Debug, Clone, Serialize)]
pub struct ChildSa {
    pub name: String,
    pub state: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub local_ts: Vec<String>,
    pub remote_ts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IkeSa {
    pub name: String,
    pub state: String,
    pub local_host: String,
    pub remote_host: String,
    pub virtual_ips: Vec<String>,
    pub children: Vec<ChildSa>,
}

fn num(section: &Message, key: &str) -> u64 {
    section
        .get_str(key)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn parse_child(name: &str, child: &Message) -> ChildSa {
    ChildSa {
        name: name.to_string(),
        state: child.get_str("state").unwrap_or_default(),
        bytes_in: num(child, "bytes-in"),
        bytes_out: num(child, "bytes-out"),
        packets_in: num(child, "packets-in"),
        packets_out: num(child, "packets-out"),
        local_ts: child.get_list("local-ts").unwrap_or_default(),
        remote_ts: child.get_list("remote-ts").unwrap_or_default(),
    }
}

fn parse_ike(name: &str, ike: &Message) -> IkeSa {
    let children = ike
        .get_section("child-sas")
        .map(|c| c.sections().map(|(n, m)| parse_child(n, m)).collect())
        .unwrap_or_default();
    IkeSa {
        name: name.to_string(),
        state: ike.get_str("state").unwrap_or_default(),
        local_host: ike.get_str("local-host").unwrap_or_default(),
        remote_host: ike.get_str("remote-host").unwrap_or_default(),
        virtual_ips: ike.get_list("local-vips").unwrap_or_default(),
        children,
    }
}

/// Flatten the `list-sa` event stream into IKE SA records.
pub fn parse_sas(events: &[Message]) -> Vec<IkeSa> {
    events
        .iter()
        .flat_map(|event| event.sections().map(|(name, ike)| parse_ike(name, ike)))
        .collect()
}

/// Human-readable summary for the CLI.
pub fn render_text(sas: &[IkeSa]) -> String {
    if sas.is_empty() {
        return "No active IKE SAs.".to_string();
    }
    let mut out = String::new();
    for ike in sas {
        out.push_str(&format!(
            "IKE_SA {}: {}  {} -> {}\n",
            ike.name, ike.state, ike.local_host, ike.remote_host
        ));
        if !ike.virtual_ips.is_empty() {
            out.push_str(&format!("  virtual IP: {}\n", ike.virtual_ips.join(", ")));
        }
        for child in &ike.children {
            out.push_str(&format!(
                "  CHILD_SA {}: {}  {} === {}  in={}B out={}B\n",
                child.name,
                child.state,
                child.local_ts.join(","),
                child.remote_ts.join(","),
                child.bytes_in,
                child.bytes_out
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_sa_event() {
        // Shape mirrors a real charon list-sa event.
        let child = Message::new()
            .str("state", "INSTALLED")
            .str("bytes-in", "0")
            .str("bytes-out", "168")
            .list("local-ts", ["10.0.0.15/32".to_string()])
            .list("remote-ts", ["10.0.0.0/24".to_string()]);
        let ike = Message::new()
            .str("state", "ESTABLISHED")
            .str("local-host", "172.17.0.2")
            .str("remote-host", "192.168.100.10")
            .list("local-vips", ["10.0.0.15".to_string()])
            .section("child-sas", Message::new().section("vRouter-TEST-1-1", child));
        let event = Message::new().section("vRouter-TEST-1", ike);

        let sas = parse_sas(&[event]);
        assert_eq!(sas.len(), 1);
        assert_eq!(sas[0].state, "ESTABLISHED");
        assert_eq!(sas[0].virtual_ips, vec!["10.0.0.15".to_string()]);
        assert_eq!(sas[0].children[0].bytes_out, 168);
        assert!(render_text(&sas).contains("CHILD_SA vRouter-TEST-1-1: INSTALLED"));
    }

    #[test]
    fn empty_is_reported() {
        assert_eq!(render_text(&[]), "No active IKE SAs.");
    }
}
