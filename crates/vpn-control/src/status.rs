//! Parse `list-sa` events from charon into structured, serializable status,
//! and render a text summary for the CLI.

use std::collections::BTreeMap;

use serde::Serialize;
use vici::Message;

#[derive(Debug, Clone, Serialize)]
pub struct ChildSa {
    pub name: String,
    /// charon's own handle for this SA. The name is not one: charon appends the
    /// unique id to the child *config* name when it reports an SA, so two
    /// generations of the same child differ only here — and `terminate` needs
    /// this rather than the name to take down one CHILD_SA without touching
    /// the others.
    pub unique_id: Option<String>,
    /// The kernel request id charon allocated for this SA's policies. Two
    /// installed children carrying *different* selectors must never share one:
    /// libipsec resolves an outbound policy by reqid, so a collision quietly
    /// sends one network's packets down the other network's SA.
    pub reqid: Option<String>,
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
    /// The IKE version charon actually negotiated, as it reports it ("1"/"2").
    /// Authoritative in a way the profile is not: the connect flow retries the
    /// other version when a gateway rejects the configured one, so a profile
    /// saying IKEv2 can be running IKEv1.
    pub version: Option<String>,
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
        unique_id: child.get_str("unique-id"),
        reqid: child.get_str("reqid"),
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
        version: ike.get_str("version"),
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

/// One CHILD_SA caught up in a reqid collision.
#[derive(Debug, Clone, Serialize)]
pub struct CollidedChild {
    pub name: String,
    pub unique_id: Option<String>,
    pub remote_ts: Vec<String>,
    pub packets_out: u64,
}

/// Installed CHILD_SAs carrying different remote networks that charon has put
/// on the same reqid.
#[derive(Debug, Clone, Serialize)]
pub struct ReqidCollision {
    pub reqid: String,
    pub children: Vec<CollidedChild>,
}

impl ReqidCollision {
    /// The children whose packets are leaving through someone else's SA.
    ///
    /// Only one SA wins a shared reqid, and it is the one still sending: the
    /// losers keep a live SA and a route in the table but stop putting packets
    /// on the wire, so the counters are the only thing that separates them.
    /// Ties (nothing has sent yet) name no victim rather than guessing.
    pub fn victims(&self) -> Vec<&CollidedChild> {
        let busiest = self
            .children
            .iter()
            .map(|c| c.packets_out)
            .max()
            .unwrap_or(0);
        self.children
            .iter()
            .filter(|c| c.packets_out < busiest)
            .collect()
    }
}

/// Find installed CHILD_SAs that share a reqid without sharing selectors.
///
/// charon keeps freed reqids in a pool and hands the next one out to any child
/// that finds no traffic-selector match (`released_reqids` in
/// `kernel_interface.c`), so a reqid released while a live SA still holds it is
/// handed to a different network. Nothing else shows it: the IKE_SA stays
/// ESTABLISHED, both children stay INSTALLED, both routes stay in the table,
/// and the losing network's packets are encrypted into the winner's SA and
/// dropped by the gateway on a selector mismatch. That network's *inbound*
/// direction keeps working, which is what makes the fault look impossible from
/// the client.
///
/// Two generations of one child during a make-before-break rekey share a reqid
/// legitimately, so only differing selector sets count.
pub fn reqid_collisions(sas: &[IkeSa]) -> Vec<ReqidCollision> {
    let mut by_reqid: BTreeMap<String, Vec<&ChildSa>> = BTreeMap::new();
    for child in sas.iter().flat_map(|sa| sa.children.iter()) {
        if child.state != "INSTALLED" {
            continue;
        }
        let Some(reqid) = child.reqid.as_ref().filter(|r| !r.is_empty()) else {
            continue;
        };
        by_reqid.entry(reqid.clone()).or_default().push(child);
    }

    by_reqid
        .into_iter()
        .filter_map(|(reqid, children)| {
            let mut selectors: Vec<Vec<String>> = children
                .iter()
                .map(|c| {
                    let mut ts = c.remote_ts.clone();
                    ts.sort();
                    ts
                })
                .collect();
            selectors.sort();
            selectors.dedup();
            if selectors.len() < 2 {
                return None;
            }
            Some(ReqidCollision {
                reqid,
                children: children
                    .into_iter()
                    .map(|c| CollidedChild {
                        name: c.name.clone(),
                        unique_id: c.unique_id.clone(),
                        remote_ts: c.remote_ts.clone(),
                        packets_out: c.packets_out,
                    })
                    .collect(),
            })
        })
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

    fn child(name: &str, reqid: &str, net: &str, packets_out: u64) -> ChildSa {
        ChildSa {
            name: name.to_string(),
            unique_id: Some("1".to_string()),
            reqid: Some(reqid.to_string()),
            state: "INSTALLED".to_string(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out,
            local_ts: vec!["172.16.17.10/32".to_string()],
            remote_ts: vec![net.to_string()],
        }
    }

    fn ike(children: Vec<ChildSa>) -> IkeSa {
        IkeSa {
            name: "ITM-Office".to_string(),
            version: Some("1".to_string()),
            state: "ESTABLISHED".to_string(),
            local_host: "192.168.178.118".to_string(),
            remote_host: "37.156.94.75".to_string(),
            virtual_ips: vec!["172.16.17.10".to_string()],
            children,
        }
    }

    /// The observed fault: one subnet's SA sits on the reqid another subnet's
    /// SA is already using, and stops sending while the other carries the
    /// traffic.
    #[test]
    fn different_selectors_on_one_reqid_collide() {
        let sas = vec![ike(vec![
            child("ITM-Office-3", "2", "10.238.96.0/24", 59),
            child("ITM-Office-1", "2", "10.100.1.220/32", 2177),
            child("ITM-Office-2", "3", "192.168.1.0/24", 9190),
        ])];

        let found = reqid_collisions(&sas);
        assert_eq!(found.len(), 1, "only reqid 2 is contended");
        assert_eq!(found[0].reqid, "2");

        // The silent one is the victim; the one carrying the packets is not.
        let victims: Vec<&str> = found[0].victims().iter().map(|c| c.name.as_str()).collect();
        assert_eq!(victims, vec!["ITM-Office-3"]);
    }

    /// A make-before-break rekey briefly leaves two generations of the same
    /// child installed, sharing a reqid and the same selectors. That is correct
    /// and must never be reported.
    #[test]
    fn rekey_generations_sharing_a_reqid_are_not_a_collision() {
        let sas = vec![ike(vec![
            child("ITM-Office-2", "3", "192.168.1.0/24", 9190),
            child("ITM-Office-2", "3", "192.168.1.0/24", 0),
        ])];
        assert!(reqid_collisions(&sas).is_empty());
    }

    /// Children that are not installed carry no policy, so they cannot be in a
    /// collision no matter what reqid they report.
    #[test]
    fn only_installed_children_count() {
        let mut rekeyed = child("ITM-Office-1", "2", "10.100.1.220/32", 0);
        rekeyed.state = "REKEYED".to_string();
        let sas = vec![ike(vec![
            child("ITM-Office-3", "2", "10.238.96.0/24", 59),
            rekeyed,
        ])];
        assert!(reqid_collisions(&sas).is_empty());
    }

    #[test]
    fn reqid_is_parsed_from_the_event() {
        let child = Message::new()
            .str("state", "INSTALLED")
            .str("reqid", "2")
            .list("remote-ts", ["10.238.96.0/24".to_string()]);
        let ike = Message::new()
            .str("state", "ESTABLISHED")
            .section("child-sas", Message::new().section("ITM-Office-3", child));
        let sas = parse_sas(&[Message::new().section("ITM-Office", ike)]);
        assert_eq!(sas[0].children[0].reqid.as_deref(), Some("2"));
    }
}
