//! Shared connection control used by both the CLI agent and the desktop app.
//!
//! Turns a [`ConnectionConfig`] into vici messages ([`bridge`]) and runs the
//! connect / status / disconnect flows against charon over a [`Transport`]
//! (Unix socket on the eventual Linux target, TCP when a Windows/macOS build
//! drives charon in a container). The PSK is pushed via `load-shared` in
//! memory; no swanctl.conf secret is written to disk.

pub mod bridge;
pub mod status;

pub use status::{ChildSa, IkeSa};

use serde::Serialize;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;
use thiserror::Error;
use vici::{Client, Message};
use vpn_core::{ConnectionConfig, IkeVersion, Secret};

const READ_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on captured handshake log lines, so a chatty charon can't grow the
/// buffer without bound (a normal `initiate` produces well under this).
const MAX_LOG_LINES: usize = 400;

/// One line of charon's log stream, captured during a connect so the caller
/// can show live handshake progress (and, on failure, the reason).
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    /// charon subsystem: `IKE`, `CFG`, `KNL`, `NET`, `ENC`, …
    pub group: String,
    /// charon log level (0 = audit/always … 4 = most verbose).
    pub level: i32,
    /// The IKE SA this line belongs to, when charon attributes it to one.
    pub ikesa: Option<String>,
    pub msg: String,
}

/// Result of a connect attempt: whether the tunnel came up, the charon error
/// message if not, and the handshake log captured either way. Only a genuine
/// transport/protocol failure (couldn't talk to charon, or `load-conn` was
/// rejected) is reported as an `Err`; a handshake that charon declines still
/// returns `Ok` so the caller can display the captured reason.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectOutcome {
    pub connected: bool,
    pub error: Option<String>,
    /// What kind of failure `error` describes, read out of the transcript. The
    /// UI needs this to say something other than charon's own wording: every
    /// failed handshake ends in "establishing CHILD_SA failed" regardless of
    /// whether the password was wrong, the gateway never answered, or the
    /// subnet has no policy — and those need different advice.
    pub kind: Option<FailureKind>,
    pub log: Vec<LogLine>,
}

impl ConnectOutcome {
    /// A tunnel that came up, carrying only its transcript.
    pub fn ok(log: Vec<LogLine>) -> Self {
        ConnectOutcome {
            connected: true,
            error: None,
            kind: None,
            log,
        }
    }

    /// A tunnel that did not come up, with the reason already classified.
    pub fn failed(kind: FailureKind, error: String, log: Vec<LogLine>) -> Self {
        ConnectOutcome {
            connected: false,
            error: Some(error),
            kind: Some(kind),
            log,
        }
    }
}

/// Why a handshake failed, as far as charon's transcript admits.
///
/// charon answers every `initiate` it could not complete with the same
/// sentence — "establishing CHILD_SA '<name>' failed" — so the message that
/// reached the user carried no information at all: a mistyped password and a
/// tunnel that broke for an unrelated reason read identically. The transcript
/// *does* distinguish them, one notify or one log line at a time, and this is
/// where that reading happens. Each variant exists because it calls for
/// different advice, and nothing is guessed: a transcript that names no cause
/// is [`FailureKind::Unknown`], not the most likely one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKind {
    /// The gateway rejected the person's login — the interactive second round
    /// (XAuth under IKEv1, EAP under IKEv2). The pre-shared key was accepted,
    /// because this round only happens after it was.
    UserCredentials,
    /// The gateway rejected our identity before any interactive round: under
    /// PSK authentication that is the key itself.
    PresharedKey,
    /// Nothing answered. Our request went out repeatedly and never drew a
    /// reply, so the gateway is unreachable rather than unhappy.
    GatewayUnreachable,
    /// No algorithm set — or no IKE version — in common with the gateway.
    NoProposal,
    /// The gateway has no policy for a network this profile asks for, so it
    /// refused the traffic selectors rather than our credentials.
    TrafficSelectors,
    /// The gateway would not hand out a virtual IP, so the tunnel has no
    /// address to source from even though authentication succeeded.
    NoVirtualIp,
    /// The gateway tore down or refused the CHILD_SA after authenticating us,
    /// for a reason it did not name.
    ChildSa,
    /// The transcript identifies nothing. charon's own message is all there is.
    Unknown,
}

impl FailureKind {
    /// A short, stable label for the log line and the CLI.
    pub fn label(self) -> &'static str {
        match self {
            FailureKind::UserCredentials => "sign-in rejected",
            FailureKind::PresharedKey => "pre-shared key rejected",
            FailureKind::GatewayUnreachable => "gateway unreachable",
            FailureKind::NoProposal => "no proposal in common",
            FailureKind::TrafficSelectors => "remote network refused",
            FailureKind::NoVirtualIp => "no virtual IP",
            FailureKind::ChildSa => "tunnel not established",
            FailureKind::Unknown => "unknown failure",
        }
    }
}

/// Read the cause of a failed handshake out of the transcript, and phrase it.
///
/// Order is by specificity, not by likelihood. The interactive round is
/// checked before the pre-shared key because a failed XAuth *also* produces an
/// `AUTHENTICATION_FAILED` notify, and the notify alone cannot tell the two
/// rounds apart. Everything below authentication is checked before the
/// retransmit test, because a gateway that answered and then refused us
/// retransmits as well — silence is only silence once nothing else matched.
///
/// `charon_error` is charon's own `errmsg`, kept as the fallback so a cause we
/// have never seen still reaches the user unaltered.
pub fn classify_failure(
    log: &[LogLine],
    charon_error: &str,
    config: &ConnectionConfig,
) -> (FailureKind, String) {
    let gateway = &config.gateway;

    // The interactive round: charon names it explicitly, and that is the only
    // evidence separating a wrong password from a wrong key.
    if log.iter().any(|l| interactive_auth_failed(&l.msg)) {
        let who = match &config.user_auth {
            Some(ua) => ua.username.clone().unwrap_or_default(),
            None => String::new(),
        };
        let whose = if who.is_empty() {
            "the username or password is wrong".to_string()
        } else {
            format!("the password for {who} is wrong, or that account is locked")
        };
        return (
            FailureKind::UserCredentials,
            format!(
                "{gateway} accepted the profile's pre-shared key and then rejected the sign-in — \
                 {whose}. Nothing else about the profile is at fault."
            ),
        );
    }

    // Rejected before any interactive round ran. Under PSK authentication —
    // the only kind this client offers — that is the key.
    if log.iter().any(|l| psk_auth_failed(&l.msg)) {
        let extra = if config.user_auth.is_some() {
            " This came before the gateway asked for your sign-in, so it is the profile's key \
             rather than your password."
        } else {
            ""
        };
        return (
            FailureKind::PresharedKey,
            format!(
                "{gateway} rejected the pre-shared key — the profile's key is not the one the \
                 gateway expects.{extra}"
            ),
        );
    }

    if log
        .iter()
        .any(|l| contains_any(&l.msg, &["NO_PROPOSAL_CHOSEN", "NO_PROP", "NO PROPOSAL"]))
    {
        return (
            FailureKind::NoProposal,
            format!(
                "{gateway} accepted none of the proposals this profile offers — neither its IKE \
                 version nor its encryption and integrity algorithms match a policy on the \
                 gateway."
            ),
        );
    }

    if log.iter().any(|l| {
        contains_any(
            &l.msg,
            &["TS_UNACCEPTABLE", "TS_UNACCEP", "NO ACCEPTABLE TRAFFIC SELECTORS"],
        )
    }) {
        let nets = config
            .remote_subnets
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return (
            FailureKind::TrafficSelectors,
            format!(
                "{gateway} authenticated us and then refused the network the tunnel asks to \
                 carry ({nets}) — the gateway has no policy covering it for this login."
            ),
        );
    }

    if log
        .iter()
        .any(|l| contains_any(&l.msg, &["INTERNAL_ADDRESS_FAILURE", "INTERNAL_ADDR"]))
    {
        return (
            FailureKind::NoVirtualIp,
            format!(
                "{gateway} authenticated us but would not assign a virtual IP — its address pool \
                 is exhausted, or this login is not entitled to one."
            ),
        );
    }

    // Only now: a gateway that answered and refused us was matched above, so
    // unanswered retransmits here really do mean nothing came back at all.
    if log.iter().any(|l| never_answered(&l.msg)) {
        return (
            FailureKind::GatewayUnreachable,
            format!(
                "{gateway} never answered. Either it is not reachable from this network, or UDP \
                 500 and 4500 are blocked on the way — the handshake drew no reply at all, so no \
                 credential was ever tested."
            ),
        );
    }

    // Authentication demonstrably succeeded and the tunnel still did not come
    // up. Worth separating from Unknown: it rules out every credential, which
    // is the question the user asks first.
    if log.iter().any(|l| ike_established(&l.msg)) {
        return (
            FailureKind::ChildSa,
            format!(
                "the IKE_SA to {gateway} came up and authenticated, but the tunnel itself was not \
                 established: {charon_error}"
            ),
        );
    }

    (FailureKind::Unknown, charon_error.to_string())
}

fn contains_any(msg: &str, needles: &[&str]) -> bool {
    let up = msg.to_ascii_uppercase();
    needles.iter().any(|n| up.contains(n))
}

/// The interactive second round failing, in the shapes charon writes it:
/// `XAuth authentication of 'user' (myself) failed`, `EAP-MSCHAPv2
/// authentication failed`, and the bare `EAP_FAILURE` payload.
fn interactive_auth_failed(msg: &str) -> bool {
    let up = msg.to_ascii_uppercase();
    (up.contains("XAUTH") && up.contains("FAIL"))
        || (up.contains("EAP") && up.contains("FAIL"))
}

/// The first round failing: a peer that rejected our identity, or one we could
/// not read. IKEv1 reports a key mismatch as a decryption failure rather than
/// a notify — a wrong PSK derives the wrong keys, so the encrypted payload is
/// simply unreadable and charon never gets as far as an authentication verdict.
fn psk_auth_failed(msg: &str) -> bool {
    let up = msg.to_ascii_uppercase();
    up.contains("AUTHENTICATION_FAILED")
        || up.contains("AUTHENTICATION FAILED")
        || up.contains("DECRYPTION FAILED")
        || up.contains("COULD NOT DECRYPT")
        || up.contains("INVALID HASH_V1")
        || up.contains("NO SHARED KEY FOUND")
        || up.contains("NO PRE-SHARED KEY")
}

/// Our request went out more than once and nothing came back.
fn never_answered(msg: &str) -> bool {
    let up = msg.to_ascii_uppercase();
    up.contains("PEER NOT RESPONDING")
        || up.contains("GIVING UP AFTER")
        || up.starts_with("RETRANSMIT")
}

/// Did the IKE_SA get far enough to prove the credentials were accepted?
fn ike_established(msg: &str) -> bool {
    let up = msg.to_ascii_uppercase();
    up.contains("IKE_SA") && up.contains("ESTABLISHED")
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error(transparent)]
    Vici(#[from] vici::Error),
    #[error("{0} was rejected by charon: {1}")]
    Rejected(&'static str, String),
    #[error("the Unix vici socket is not available on this platform; use a TCP transport")]
    NoUnixTransport,
    #[error("this profile's gateway asks for a username and password, which were not supplied")]
    MissingUserPassword,
    #[error(
        "this profile names no remote networks, so bringing it up would route all traffic through \
         the VPN — and if the gateway does not carry it, cut off internet access. Add the \
         subnet(s) you need to reach, or choose to route all traffic through the VPN on purpose"
    )]
    NoRemoteNetworks,
}

pub type Result<T> = std::result::Result<T, ControlError>;

/// How to reach charon's vici interface.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Unix domain socket path (Linux target, e.g. `/var/run/charon.vici`).
    Unix(String),
    /// `host:port` for a TCP vici socket (e.g. charon in a container exposed
    /// to a Windows/macOS host).
    Tcp(String),
}

/// One concrete stream type so the flows are generic over a single
/// `Client<ViciStream>` rather than two transport-specific clients.
enum ViciStream {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for ViciStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ViciStream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            ViciStream::Unix(s) => s.read(buf),
        }
    }
}
impl Write for ViciStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ViciStream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            ViciStream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ViciStream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            ViciStream::Unix(s) => s.flush(),
        }
    }
}

fn open(transport: &Transport) -> Result<Client<ViciStream>> {
    let stream = match transport {
        Transport::Tcp(addr) => {
            let s = std::net::TcpStream::connect(addr).map_err(vici::Error::from)?;
            let _ = s.set_read_timeout(Some(READ_TIMEOUT));
            let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
            ViciStream::Tcp(s)
        }
        Transport::Unix(path) => {
            #[cfg(unix)]
            {
                use std::os::unix::net::UnixStream;
                let s = UnixStream::connect(path).map_err(vici::Error::from)?;
                let _ = s.set_read_timeout(Some(READ_TIMEOUT));
                let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
                ViciStream::Unix(s)
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(ControlError::NoUnixTransport);
            }
        }
    };
    Ok(Client::new(stream))
}

fn check(resp: Message, ctx: &'static str) -> Result<()> {
    match resp.get_str("success").as_deref() {
        Some("yes") => Ok(()),
        _ => Err(ControlError::Rejected(
            ctx,
            resp.get_str("errmsg")
                .unwrap_or_else(|| "unknown error".to_string()),
        )),
    }
}

/// Load the connection + PSK and initiate the tunnel, capturing charon's log
/// stream during the handshake. Registering for the `log` event around
/// `initiate` turns the otherwise opaque call into a live transcript of the
/// exchange (`IKE_SA_INIT`, authentication, `CHILD_SA` install — or the reason
/// it failed), which the GUI surfaces in its charon console.
pub fn connect_logged(
    transport: &Transport,
    config: &ConnectionConfig,
    name: &str,
    user_password: Option<&Secret>,
) -> Result<ConnectOutcome> {
    // A profile whose gateway wants a second round cannot authenticate without
    // the password, and charon would fail somewhere deep in the exchange with
    // a message that doesn't say what is missing. Refuse up front instead.
    if config.user_auth.is_some() && user_password.is_none() {
        return Err(ControlError::MissingUserPassword);
    }

    // A profile with no traffic selectors would negotiate 0.0.0.0/0 and — with
    // charon's `install_routes` on — capture the machine's default route into
    // the tunnel. Against a split-tunnel gateway that does not carry internet
    // traffic (the common Sophos case), that silently kills connectivity. Never
    // do it implicitly: a full tunnel has to be an explicit 0.0.0.0/0 in the
    // profile, so an empty selector set is refused before any route is touched.
    if config.remote_subnets.is_empty() {
        return Err(ControlError::NoRemoteNetworks);
    }

    let mut client = open(transport)?;
    // Resolved once for the whole connect: the version fallback below runs a
    // second attempt, and a cold lookup costs about a second.
    let peers = peer_ids(&config.gateway);
    let primary = config.ike_version;
    let mut outcome = attempt(&mut client, config, name, primary, user_password, &peers)?;

    // The IKE version is not stated in a Sophos `.scx` (and a `.mobileconfig`
    // states it, but old gateways still disagree), so the version we import can
    // be wrong. An SFOS responder answers an IKE_SA_INIT it has no policy for —
    // version included — with NO_PROPOSAL_CHOSEN, which is a fast, unambiguous
    // "wrong version" (not an algorithm mismatch). Rather than make the user
    // edit the profile, retry once with the other version. Verified live:
    // SFOS 18.5 needs IKEv1, SFOS 21 needs IKEv2.
    if !outcome.connected && suggests_wrong_ike_version(&outcome.log) {
        let alternate = other_version(primary);
        outcome.log.push(note(
            name,
            format!(
                "the gateway did not accept IKEv{}; retrying as IKEv{}",
                primary.swanctl_value(),
                alternate.swanctl_value()
            ),
        ));
        let retry = attempt(&mut client, config, name, alternate, user_password, &peers)?;

        let mut log = outcome.log;
        log.extend(retry.log);
        if log.len() > MAX_LOG_LINES {
            log.truncate(MAX_LOG_LINES);
        }
        if retry.connected {
            return Ok(ConnectOutcome::ok(log));
        }
        // On a double failure, report whichever attempt learned something. The
        // first one is preferred — it ran at the version the user configured —
        // but "no proposal in common" is what provoked the retry in the first
        // place, so if the other version got further (a rejected password, say)
        // that is the finding worth showing.
        let (kind, error) = match (outcome.kind, retry.kind) {
            (Some(FailureKind::NoProposal), Some(other)) if other != FailureKind::NoProposal => {
                (Some(other), retry.error)
            }
            _ => (outcome.kind, outcome.error),
        };
        return Ok(ConnectOutcome {
            connected: false,
            error,
            kind,
            log,
        });
    }

    Ok(outcome)
}

/// One load-and-initiate pass at a single IKE version. Separated from
/// [`connect_logged`] so the version-fallback path can run it twice against the
/// same open client without duplicating the flow.
fn attempt(
    client: &mut Client<ViciStream>,
    config: &ConnectionConfig,
    name: &str,
    version: IkeVersion,
    user_password: Option<&Secret>,
    peers: &[String],
) -> Result<ConnectOutcome> {
    check(
        client.request("load-conn", bridge::load_conn_message_for(config, name, version))?,
        "load-conn",
    )?;
    check(
        client.request("load-shared", bridge::load_shared_message(config, name, peers))?,
        "load-shared",
    )?;
    if let Some(password) = user_password.filter(|_| config.user_auth.is_some()) {
        check(
            client.request(
                "load-shared",
                bridge::load_shared_user_auth_message_for(config, name, password, version, peers),
            )?,
            "load-shared (user auth)",
        )?;
    }

    // Under IKEv1 a profile's subnets become one CHILD_SA each (quick mode
    // negotiates a single selector pair), so there may be several to bring up.
    let children = bridge::child_names_for(config, name, version);
    let mut log: Vec<LogLine> = Vec::new();
    let mut established = 0usize;
    let mut first_error: Option<String> = None;

    for child in &children {
        let before = log.len();
        let (events, response) = client.stream_request(
            "initiate",
            "log",
            Message::new().str("child", child).str("ike", name),
        )?;
        for event in events.iter() {
            if log.len() >= MAX_LOG_LINES {
                break;
            }
            log.push(parse_log_line(event));
        }
        if response.get_str("success").as_deref() == Some("yes") {
            established += 1;
            continue;
        }

        let err = response
            .get_str("errmsg")
            .unwrap_or_else(|| "charon declined to initiate the connection".to_string());
        // Which subnet failed matters when the others came up: the tunnel
        // looks fine but part of the remote network is unreachable.
        if children.len() > 1 {
            log.push(note(name, format!("{child} did not come up: {err}")));
        }
        first_error.get_or_insert(err);

        // Credentials the gateway just rejected will be rejected again: every
        // remaining child would open its own IKE_SA and repeat the same login.
        // That cannot succeed, and it is actively harmful — a gateway that
        // locks an account after N bad attempts (Sophos does) gets N tries
        // burned per click, so a mistyped password locks the user out and the
        // profile then fails even once it is corrected. A rejected subnet is
        // different: the others are still worth trying.
        if suggests_auth_failure(&log[before..]) {
            if children.len() > 1 {
                log.push(note(
                    name,
                    "the gateway rejected these credentials — not trying the remaining \
                     networks, so a repeated attempt cannot lock the account"
                        .to_string(),
                ));
            }
            break;
        }
    }

    // One established CHILD_SA means the tunnel carries traffic, so that is
    // what "connected" means; a partial failure is reported in the log rather
    // than by throwing away a working tunnel.
    let connected = established > 0;
    if connected && established < children.len() {
        log.push(note(
            name,
            format!(
                "{established} of {} remote networks came up; the rest are not reachable over \
                 this tunnel",
                children.len()
            ),
        ));
    }
    if connected {
        return Ok(ConnectOutcome::ok(log));
    }

    // charon's own `errmsg` for a failed initiate is the same sentence
    // whatever went wrong, so read the cause out of the transcript instead and
    // keep `errmsg` only as the fallback. The verdict is appended to the
    // transcript too: the console is where a support request gets copied from,
    // and it should carry the same reading the dialog showed.
    let charon_error =
        first_error.unwrap_or_else(|| "charon declined to initiate the connection".to_string());
    let (kind, message) = classify_failure(&log, &charon_error, config);
    if log.len() < MAX_LOG_LINES {
        log.push(note(name, format!("{}: {message}", kind.label())));
    }

    Ok(ConnectOutcome::failed(kind, message, log))
}

/// The other IKE version, for the fallback retry.
fn other_version(v: IkeVersion) -> IkeVersion {
    match v {
        IkeVersion::V1 => IkeVersion::V2,
        IkeVersion::V2 => IkeVersion::V1,
    }
}

/// Does the captured handshake say the gateway rejected the IKE *version*
/// rather than something we could not fix by switching it?
///
/// `NO_PROPOSAL_CHOSEN` from a strongSwan responder (SFOS is one) at IKE_SA_INIT
/// means no connection policy matched at all — a version mismatch reads exactly
/// like this. It is deliberately the only trigger: an authentication failure or
/// an unreachable gateway must *not* provoke a pointless second attempt at the
/// other version.
fn suggests_wrong_ike_version(log: &[LogLine]) -> bool {
    log.iter().any(|line| {
        let msg = line.msg.to_ascii_uppercase();
        msg.contains("NO_PROPOSAL_CHOSEN") || msg.contains("NO_PROP")
    })
}

/// Did the peer reject who we are, rather than what we asked for? Covers both
/// authentication rounds charon reports separately: the IKE authentication
/// itself (`AUTHENTICATION_FAILED`, IKEv1 or IKEv2) and the interactive second
/// round on top of it (`XAuth authentication of '...' failed`, and the EAP
/// equivalent).
///
/// This is deliberately narrow. It gates *stopping early*, and stopping early
/// on a failure that was not about credentials would leave working subnets
/// unreachable.
fn suggests_auth_failure(log: &[LogLine]) -> bool {
    log.iter().any(|line| {
        let msg = line.msg.to_ascii_uppercase();
        msg.contains("AUTHENTICATION_FAILED")
            || msg.contains("AUTHENTICATION FAILED")
            || (msg.contains("XAUTH") && msg.contains("FAILED"))
            || (msg.contains("EAP") && msg.contains("FAILED"))
    })
}

/// Load the connection + PSK and initiate the tunnel, returning only success
/// or failure. Thin wrapper over [`connect_logged`] for the CLI, which prints
/// charon's log itself rather than collecting it.
pub fn connect(
    transport: &Transport,
    config: &ConnectionConfig,
    name: &str,
    user_password: Option<&Secret>,
) -> Result<()> {
    let outcome = connect_logged(transport, config, name, user_password)?;
    if outcome.connected {
        Ok(())
    } else {
        Err(ControlError::Rejected(
            "initiate",
            outcome.error.unwrap_or_default(),
        ))
    }
}

/// A line of our own in the handshake transcript, phrased like charon's so the
/// UI renders it the same way.
fn note(ike: &str, msg: String) -> LogLine {
    LogLine {
        group: "CFG".to_string(),
        level: 0,
        ikesa: Some(ike.to_string()),
        msg,
    }
}

fn parse_log_line(event: &Message) -> LogLine {
    LogLine {
        group: event.get_str("group").unwrap_or_default(),
        level: event
            .get_str("level")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0),
        ikesa: event.get_str("ikesa-name"),
        msg: event.get_str("msg").unwrap_or_default(),
    }
}

/// One remote network a repair pass could not bring back, and why.
#[derive(Debug, Clone, Serialize)]
pub struct RepairFailure {
    pub net: String,
    pub reason: String,
}

/// What a [`repair`] pass found, and what it did about it.
///
/// Deliberately three lists rather than a boolean. A network that came back and
/// a network that can never come back by this route both leave the tunnel in a
/// different state, and the caller has to stop retrying the second kind.
#[derive(Debug, Clone, Serialize)]
pub struct RepairOutcome {
    /// Networks whose CHILD_SA was missing (or dead) and is now installed.
    pub restored: Vec<String>,
    /// Networks we tried to bring back and could not.
    pub failed: Vec<RepairFailure>,
    /// Networks that are missing for a reason re-initiating cannot fix: the
    /// gateway narrowed the traffic selectors of a CHILD_SA that *is* up, so it
    /// simply does not carry this network. Asking again gets the same answer,
    /// so the caller must stop asking and say so.
    pub narrowed: Vec<String>,
    /// Networks that were already installed and not reported dead.
    pub healthy: Vec<String>,
    pub log: Vec<LogLine>,
}

impl RepairOutcome {
    /// Did this pass change anything? Used by the caller to decide whether the
    /// result is worth a line in the UI.
    pub fn acted(&self) -> bool {
        !self.restored.is_empty() || !self.failed.is_empty()
    }
}

/// One CHILD_SA a repair pass is about to take down, as charon must be told to
/// take it down: by unique id, never by name. The name it reports carries the
/// SA's id appended to the child *config* name, so it changes at every rekey
/// and names two generations identically for the moment they overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StaleChild {
    name: String,
    unique_id: String,
}

/// What a repair pass has decided to do about one child configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RepairAction {
    /// Nothing installed carries these networks: initiate the child.
    Initiate,
    /// Installed, but `silent` names networks nothing comes back over. The
    /// stale SAs go first: charon would otherwise keep both, and the dead one's
    /// kernel policy can still win for the same selectors.
    Replace {
        stale: Vec<StaleChild>,
        silent: Vec<String>,
    },
    /// Installed and answering — leave it alone. `narrowed` names networks the
    /// gateway would not carry, which is not something initiating again can
    /// change: it would return the same narrowing and a duplicate SA with it.
    Keep {
        healthy: Vec<String>,
        narrowed: Vec<String>,
    },
}

/// One child configuration, the networks it is meant to carry, and the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RepairStep {
    child: String,
    wanted: Vec<String>,
    action: RepairAction,
}

impl RepairStep {
    /// The line that goes in the transcript before this step runs — why it is
    /// about to do what it does. `None` for a child that needs nothing said
    /// about it, which is the healthy case and so most of them.
    fn finding(&self) -> Option<String> {
        let nets = self.wanted.join(", ");
        match &self.action {
            RepairAction::Initiate => {
                Some(format!("{nets} has no CHILD_SA at all — initiating it"))
            }
            RepairAction::Replace { silent, .. } => Some(format!(
                "{} was installed but silent — re-establishing it",
                silent.join(", ")
            )),
            RepairAction::Keep { .. } => None,
        }
    }
}

/// Decide what to do about every remote network of a live tunnel, before
/// touching charon.
///
/// Split out from [`repair`] because this is the part that can be wrong in ways
/// no compiler catches — mistake the running layout and it initiates a child
/// name that does not exist; mistake a narrowed selector for a missing SA and
/// it asks a gateway the same refused question forever — and none of it is
/// reachable through [`repair`] without a charon to talk to.
fn plan_repair(
    config: &ConnectionConfig,
    name: &str,
    negotiated: Option<IkeVersion>,
    live: &[&ChildSa],
    dead: &[String],
) -> Vec<RepairStep> {
    let version = live_version(config, negotiated, live);
    bridge::child_selectors_for(config, name, version)
        .into_iter()
        .map(|(child, nets)| {
            let wanted: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            // Match live SAs to a child config by the networks they carry, not
            // by name, for the same reason `StaleChild` exists: the reported
            // name moves with every rekey while the selectors do not.
            let installed: Vec<&&ChildSa> = live
                .iter()
                .filter(|c| {
                    c.state == "INSTALLED" && c.remote_ts.iter().any(|ts| wanted.contains(ts))
                })
                .collect();
            let silent: Vec<String> = wanted
                .iter()
                .filter(|n| dead.contains(n))
                .cloned()
                .collect();

            let action = if installed.is_empty() {
                RepairAction::Initiate
            } else if !silent.is_empty() {
                RepairAction::Replace {
                    stale: installed
                        .iter()
                        .filter_map(|c| {
                            c.unique_id.clone().map(|unique_id| StaleChild {
                                name: c.name.clone(),
                                unique_id,
                            })
                        })
                        .collect(),
                    silent,
                }
            } else {
                let carried: Vec<&String> =
                    installed.iter().flat_map(|c| c.remote_ts.iter()).collect();
                let (healthy, narrowed): (Vec<String>, Vec<String>) = wanted
                    .iter()
                    .cloned()
                    .partition(|net| carried.iter().any(|ts| *ts == net));
                RepairAction::Keep { healthy, narrowed }
            };
            RepairStep {
                child,
                wanted,
                action,
            }
        })
        .collect()
}

/// Bring back the remote networks of a live tunnel that are not carrying
/// traffic, without disturbing the ones that are.
///
/// This exists because a tunnel is not all-or-nothing. Under IKEv1 each remote
/// network is its own CHILD_SA with its own route (quick mode negotiates one
/// selector pair per SA), and they fail independently: one subnet goes dark
/// while the others carry megabytes, the IKE_SA stays ESTABLISHED, `dpd_action
/// = restart` never fires because DPD rides the IKE_SA and the gateway is
/// answering it fine. Until now the only cure was a full reconnect, which
/// tears down the networks that were working — and costs another round of
/// credentials against a gateway that locks accounts.
///
/// So: re-initiate exactly the children that are missing, and terminate and
/// re-initiate the ones `dead` names (a child whose SA is installed but whose
/// data path stopped answering — charon cannot see that, only the byte counters
/// can). Every child that is up and answering is left strictly alone.
///
/// `dead` holds remote networks in the CIDR form [`Ipv4Net`](vpn_core::Ipv4Net)
/// prints, matching what `list-sas` reports as traffic selectors. An empty
/// `dead` makes this a pure "install what is missing" pass — except for a reqid
/// collision, which this pass recognises on its own because the SA list states
/// it outright rather than leaving it to be inferred from byte counters.
pub fn repair(
    transport: &Transport,
    config: &ConnectionConfig,
    name: &str,
    dead: &[String],
) -> Result<RepairOutcome> {
    let mut client = open(transport)?;
    let (events, _) = client.stream_request("list-sas", "list-sa", Message::new())?;
    let sas = status::parse_sas(&events);

    // Every generation of the SA under this name: a make-before-break rekey
    // leaves two IKE_SAs briefly, and a child installed on either one is
    // carrying traffic.
    let live: Vec<&ChildSa> = sas
        .iter()
        .filter(|sa| sa.name == name)
        .flat_map(|sa| sa.children.iter())
        .collect();

    let mut out = RepairOutcome {
        restored: Vec::new(),
        failed: Vec::new(),
        narrowed: Vec::new(),
        healthy: Vec::new(),
        log: Vec::new(),
    };

    if !sas.iter().any(|sa| sa.name == name) {
        out.log.push(note(
            name,
            "there is no live IKE_SA under this name, so there is nothing to repair — connect \
             instead"
                .to_string(),
        ));
        return Ok(out);
    }

    // The one cause of a silent subnet that can be read straight off the SA
    // list. charon keeps freed reqids in a pool and reuses them, so a reqid
    // released while a live SA still holds it ends up on a second child: the
    // two share one policy, and the quieter one's packets leave through the
    // other's SA to be dropped by the gateway on a selector mismatch. Its route
    // and its SA both still look right, which is why nothing else here catches
    // it — and why it is worth naming in the log rather than quietly repairing.
    let mut dead: Vec<String> = dead.to_vec();
    for collision in status::reqid_collisions(&sas) {
        let names: Vec<&str> = collision.children.iter().map(|c| c.name.as_str()).collect();
        out.log.push(note(
            name,
            format!(
                "CHILD_SAs {} share reqid {} — a charon bookkeeping fault, not anything \
                 the gateway did. The quieter one's packets leave through the \
                 other's SA",
                names.join(" and "),
                collision.reqid
            ),
        ));
        for victim in collision.victims() {
            for net in &victim.remote_ts {
                if !dead.contains(net) {
                    dead.push(net.clone());
                }
            }
        }
    }

    // Decide everything first, then act. The decision is the part that can be
    // quietly wrong, so it is a pure function with tests of its own.
    for step in plan_repair(config, name, negotiated_version(&sas, name), &live, &dead) {
        if let Some(finding) = step.finding() {
            out.log.push(note(name, finding));
        }
        match step.action {
            RepairAction::Initiate => {
                reinitiate(&mut client, config, name, &step.child, &step.wanted, &mut out)?;
            }
            RepairAction::Replace { stale, .. } => {
                for c in stale {
                    out.log.push(note(
                        name,
                        format!("dropping the dead CHILD_SA {} (#{})", c.name, c.unique_id),
                    ));
                    let _ = client.request(
                        "terminate",
                        Message::new().str("child-id", c.unique_id),
                    );
                }
                reinitiate(&mut client, config, name, &step.child, &step.wanted, &mut out)?;
            }
            RepairAction::Keep { healthy, narrowed } => {
                out.healthy.extend(healthy);
                out.narrowed.extend(narrowed);
            }
        }
    }

    if !out.narrowed.is_empty() {
        out.log.push(note(
            name,
            format!(
                "{} is not carried by this tunnel: the gateway narrowed the traffic selectors it \
                 accepted, so its policy does not cover that network — asking again cannot change \
                 it",
                out.narrowed.join(", ")
            ),
        ));
    }
    Ok(out)
}

/// Initiate one child of a connection that is already up, recording the result
/// against the networks it carries.
fn reinitiate(
    client: &mut Client<ViciStream>,
    config: &ConnectionConfig,
    name: &str,
    child: &str,
    nets: &[String],
    out: &mut RepairOutcome,
) -> Result<()> {
    let before = out.log.len();
    let (events, response) = client.stream_request(
        "initiate",
        "log",
        Message::new().str("child", child).str("ike", name),
    )?;
    for event in events.iter() {
        if out.log.len() >= MAX_LOG_LINES {
            break;
        }
        out.log.push(parse_log_line(event));
    }
    if response.get_str("success").as_deref() == Some("yes") {
        out.restored.extend(nets.iter().cloned());
        out.log.push(note(name, format!("{} is up again", nets.join(", "))));
        return Ok(());
    }
    let charon_error = response
        .get_str("errmsg")
        .unwrap_or_else(|| "charon declined to initiate the child".to_string());
    // Read the same way a failed connect is: "establishing CHILD_SA failed" on
    // its own says nothing about whether to retry, reconnect, or fix the
    // gateway. Only this attempt's lines are considered — the notes above them
    // are ours, and an earlier child's failure is not this child's reason.
    let (kind, reason) = classify_failure(&out.log[before..], &charon_error, config);
    out.log.push(note(name, format!("{}: {reason}", kind.label())));
    for net in nets {
        out.failed.push(RepairFailure {
            net: net.clone(),
            reason: reason.clone(),
        });
    }
    Ok(())
}

/// The IKE version charon reports for this connection's live IKE_SA.
///
/// This is the only *stated* answer available; everything else is inference.
/// It matters because the profile is routinely wrong: a Sophos `.scx` carries
/// no IKE version at all, so the importer has to assume IKEv2, while an SFOS
/// gateway may well answer IKEv1 -- and the connect flow then retries and
/// succeeds, leaving a running tunnel whose version the profile misnames.
fn negotiated_version(sas: &[IkeSa], name: &str) -> Option<IkeVersion> {
    sas.iter()
        .filter(|sa| sa.name == name)
        .find_map(|sa| match sa.version.as_deref()?.trim() {
            "1" | "IKEv1" => Some(IkeVersion::V1),
            "2" | "IKEv2" => Some(IkeVersion::V2),
            _ => None,
        })
}

/// Is this connection running as one CHILD_SA carrying every network (IKEv2),
/// or one per network (IKEv1 quick mode)?
///
/// `negotiated` is charon's own report and outranks everything else. Without it
/// the layout is inferred from the live SAs, and only as a last resort from the
/// profile -- which can be wrong, because the connect flow retries the other
/// version when the gateway rejects the one the profile names.
///
/// Getting this wrong is not cosmetic: the child *names* follow from it, so a
/// wrong answer makes the repair pass initiate a child that does not exist and
/// report every network as unrecoverable.
fn live_version(
    config: &ConnectionConfig,
    negotiated: Option<IkeVersion>,
    live: &[&ChildSa],
) -> IkeVersion {
    if let Some(version) = negotiated {
        return version;
    }
    let installed: Vec<&&ChildSa> = live.iter().filter(|c| c.state == "INSTALLED").collect();
    // One SA carrying two of the profile's networks can only be IKEv2: quick
    // mode cannot put two selector pairs in one SA.
    let wanted: Vec<String> = config.remote_subnets.iter().map(|n| n.to_string()).collect();
    if installed
        .iter()
        .any(|c| c.remote_ts.iter().filter(|ts| wanted.contains(ts)).count() > 1)
    {
        return IkeVersion::V2;
    }
    // Several SAs, each carrying one network, is the IKEv1 split.
    if installed.len() > 1 {
        return IkeVersion::V1;
    }
    config.ike_version
}

/// List active IKE/CHILD SAs.
pub fn status(transport: &Transport) -> Result<Vec<IkeSa>> {
    let mut client = open(transport)?;
    let (events, _resp) = client.stream_request("list-sas", "list-sa", Message::new())?;
    Ok(status::parse_sas(&events))
}

/// Every identity charon may use for the far end of a connection to `gateway`.
///
/// A connection that does not pin the peer's identity gets the gateway's
/// *address* as the remote ID, so a profile that names its gateway by hostname
/// needs the resolved addresses among its secret's owners too — the hostname
/// alone would match nothing and charon would report no shared key at all.
/// Resolution is best effort: charon has to resolve the same name to reach the
/// gateway, so a failure here is a failure there, and the hostname stays in the
/// list either way.
fn peer_ids(gateway: &str) -> Vec<String> {
    let mut ids = vec![gateway.to_string()];
    if gateway.parse::<std::net::IpAddr>().is_ok() {
        return ids;
    }
    // The port is irrelevant — `to_socket_addrs` is just the resolver.
    if let Ok(addrs) = (gateway, 500u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip().to_string();
            if !ids.contains(&ip) {
                ids.push(ip);
            }
        }
    }
    ids
}

/// Terminate the named IKE SA and drop the credentials it was loaded with.
/// Rekey a live SA now, instead of waiting out the lifetime the gateway handed
/// out.
///
/// An IKE_SA rekey is make-before-break — charon establishes the replacement
/// and asks for a virtual IP on it while the SA being replaced still holds one
/// — which is the hardest thing the Windows data path does, and where it used
/// to lose the address (and with it the adapter and every route) while still
/// reporting ESTABLISHED. Gateways schedule that hours apart, so this is how it
/// gets tested in a minute rather than an afternoon.
pub fn rekey(transport: &Transport, name: &str, child: bool) -> Result<()> {
    let mut client = open(transport)?;
    let key = if child { "child" } else { "ike" };
    check(
        client.request("rekey", Message::new().str(key, name))?,
        "rekey",
    )
}

pub fn disconnect(transport: &Transport, name: &str) -> Result<()> {
    let mut client = open(transport)?;
    let terminated = check(
        client.request("terminate", Message::new().str("ike", name))?,
        "terminate",
    );

    // Everything pushed over vici outlives the SA it was pushed for: charon
    // holds loaded connections and secrets until they are unloaded or it
    // restarts. A disconnected profile's PSK left in the credential set still
    // competes for every later connection (see `bridge::secret_owners`), so
    // retire it along with the tunnel. Failures are uninteresting here — "not
    // loaded" is the state being asked for.
    for id in [format!("ike-{name}"), format!("user-{name}")] {
        let _ = client.request("unload-shared", Message::new().str("id", id));
    }
    let _ = client.request("unload-conn", Message::new().str("name", name));

    terminated
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A profile that needs a login must be refused before any connection is
    /// opened — the point of the guard is that charon never sees a half-built
    /// credential set, so this must not depend on a reachable daemon. The
    /// transport below points at a port nothing listens on: if the check ever
    /// moves after `open`, this fails with a connection error instead.
    #[test]
    fn refuses_to_connect_without_the_user_password() {
        let mut config = bridge::tests::sample();
        config.user_auth = Some(vpn_core::UserAuth {
            username: Some("vpnuser".to_string()),
            can_save: true,
            otp: false,
        });
        let transport = Transport::Tcp("127.0.0.1:1".to_string());
        let err = connect_logged(&transport, &config, "c", None).unwrap_err();
        assert!(
            matches!(err, ControlError::MissingUserPassword),
            "expected the missing-password guard, got: {err}"
        );
    }

    /// A profile with no traffic selectors must be refused before anything is
    /// opened, so it can never capture the default route into a tunnel the
    /// gateway may not carry. Same reasoning as the missing-password guard: the
    /// transport points at a dead port, so a regression that moved the check
    /// after `open` would fail with a connection error instead.
    #[test]
    fn refuses_a_profile_with_no_remote_networks() {
        let mut config = bridge::tests::sample();
        config.remote_subnets.clear();
        let transport = Transport::Tcp("127.0.0.1:1".to_string());
        let err = connect_logged(&transport, &config, "c", None).unwrap_err();
        assert!(
            matches!(err, ControlError::NoRemoteNetworks),
            "expected the no-networks guard, got: {err}"
        );
    }

    fn log_line(msg: &str) -> LogLine {
        LogLine {
            group: "IKE".to_string(),
            level: 1,
            ikesa: None,
            msg: msg.to_string(),
        }
    }

    /// The one signal that provokes the version retry, in the shape charon
    /// actually logs it — a parsed `N(NO_PROP)` notify on the IKE_SA_INIT
    /// response.
    #[test]
    fn no_proposal_chosen_triggers_the_version_fallback() {
        let log = [
            log_line("initiating IKE_SA c[1] to 203.0.113.10"),
            log_line("parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]"),
        ];
        assert!(suggests_wrong_ike_version(&log));
    }

    /// An authentication failure or an unreachable gateway must not: switching
    /// the IKE version cannot fix either, and a needless second attempt only
    /// doubles the wait and muddies the log.
    #[test]
    fn auth_failure_does_not_trigger_the_fallback() {
        let log = [
            log_line("XAuth authentication of 'user' failed"),
            log_line("received AUTHENTICATION_FAILED notify error"),
        ];
        assert!(!suggests_wrong_ike_version(&log));

        let unreachable = [log_line("retransmit 5 of request with message ID 0")];
        assert!(!suggests_wrong_ike_version(&unreachable));
    }

    /// The counterpart to the test above: what must *not* trigger the fallback
    /// is exactly what must stop the per-subnet loop, so a rejected login is
    /// tried once rather than once per remote network.
    #[test]
    fn auth_failure_stops_the_per_subnet_loop() {
        assert!(suggests_auth_failure(&[log_line(
            "XAuth authentication of 'ikoelbl' (myself) failed"
        )]));
        assert!(suggests_auth_failure(&[log_line(
            "received AUTHENTICATION_FAILED notify error"
        )]));
        assert!(suggests_auth_failure(&[log_line("EAP-MSCHAPv2 authentication failed")]));

        // A subnet the gateway has no policy for, or a peer that never answered,
        // says nothing about our credentials — the remaining subnets are still
        // worth initiating.
        assert!(!suggests_auth_failure(&[log_line(
            "no acceptable traffic selectors found"
        )]));
        assert!(!suggests_auth_failure(&[log_line(
            "retransmit 5 of request with message ID 0"
        )]));
        assert!(!suggests_auth_failure(&[log_line(
            "received NO_PROPOSAL_CHOSEN notify error"
        )]));
    }


    /// The complaint this classifier exists for: a mistyped password and a
    /// tunnel that broke for an unrelated reason both ended in charon's
    /// "establishing CHILD_SA failed", so the two were indistinguishable in
    /// the UI. Each of these transcripts must now land somewhere different.
    #[test]
    fn the_generic_child_sa_failure_is_split_by_cause() {
        let mut config = bridge::tests::sample();
        config.user_auth = Some(vpn_core::UserAuth {
            username: Some("ikoelbl".to_string()),
            can_save: true,
            otp: false,
        });
        let charon = "establishing CHILD_SA 'conn' failed";

        // A mistyped user password. charon reports the XAuth round by name,
        // and also receives an AUTHENTICATION_FAILED notify for it — so the
        // notify must not be what decides, or this would read as a bad PSK.
        let (kind, msg) = classify_failure(
            &[
                log_line("IKE_SA conn[3] established between 10.0.0.2[10.0.0.2]...203.0.113.10"),
                log_line("XAuth authentication of 'ikoelbl' (myself) failed"),
                log_line("received AUTHENTICATION_FAILED notify error"),
            ],
            charon,
            &config,
        );
        assert_eq!(kind, FailureKind::UserCredentials);
        assert!(msg.contains("ikoelbl"), "{msg}");

        // The same notify with no interactive round in the transcript is the
        // pre-shared key, and the message has to say so — it is a different
        // person's problem to fix.
        let (kind, msg) = classify_failure(
            &[
                log_line("initiating IKE_SA conn[1] to 203.0.113.10"),
                log_line("received AUTHENTICATION_FAILED notify error"),
            ],
            charon,
            &config,
        );
        assert_eq!(kind, FailureKind::PresharedKey);
        assert!(msg.contains("before the gateway asked"), "{msg}");

        // Nothing ever answered: no credential was tested at all, so neither
        // of the two above may be blamed.
        let (kind, _) = classify_failure(
            &[
                log_line("initiating IKE_SA conn[1] to 203.0.113.10"),
                log_line("retransmit 5 of request with message ID 0"),
                log_line("establishing IKE_SA failed, peer not responding"),
            ],
            charon,
            &config,
        );
        assert_eq!(kind, FailureKind::GatewayUnreachable);

        // Authenticated, then refused the network — the profile's subnets are
        // wrong (or not entitled), and no password will help.
        let (kind, msg) = classify_failure(
            &[
                log_line("IKE_SA conn[1] established"),
                log_line("received TS_UNACCEPTABLE notify, no CHILD_SA built"),
            ],
            charon,
            &config,
        );
        assert_eq!(kind, FailureKind::TrafficSelectors);
        assert!(msg.contains("10.0.0.0/24"), "{msg}");

        // Authenticated, no address handed out.
        let (kind, _) = classify_failure(
            &[
                log_line("IKE_SA conn[1] established"),
                log_line("received INTERNAL_ADDRESS_FAILURE notify, no CHILD_SA built"),
            ],
            charon,
            &config,
        );
        assert_eq!(kind, FailureKind::NoVirtualIp);

        // Algorithms or version.
        let (kind, _) = classify_failure(
            &[log_line("parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]")],
            charon,
            &config,
        );
        assert_eq!(kind, FailureKind::NoProposal);
    }

    /// A gateway that answered and then refused us retransmits too, so the
    /// retransmit test must never outrank a named cause — otherwise a rejected
    /// password reads as an unreachable gateway and the user goes looking at
    /// the firewall.
    #[test]
    fn a_named_cause_outranks_retransmits() {
        let config = bridge::tests::sample();
        let (kind, _) = classify_failure(
            &[
                log_line("retransmit 1 of request with message ID 1"),
                log_line("received AUTHENTICATION_FAILED notify error"),
            ],
            "establishing CHILD_SA 'conn' failed",
            &config,
        );
        assert_eq!(kind, FailureKind::PresharedKey);
    }

    /// A transcript that names nothing must not be dressed up as a diagnosis:
    /// charon's own words reach the user unaltered, so a cause we have never
    /// seen is never mislabelled as one we have.
    #[test]
    fn an_unrecognised_transcript_keeps_charons_wording() {
        let config = bridge::tests::sample();
        let (kind, msg) = classify_failure(
            &[log_line("something we have never seen before")],
            "establishing CHILD_SA 'conn' failed",
            &config,
        );
        assert_eq!(kind, FailureKind::Unknown);
        assert_eq!(msg, "establishing CHILD_SA 'conn' failed");
    }

    fn child(state: &str, nets: &[&str]) -> ChildSa {
        named_child(state, "conn-7", "7", nets)
    }

    /// As `child`, but naming the SA — which is what a repair plan has to get
    /// right, since `terminate` takes the unique id and nothing else.
    fn named_child(state: &str, name: &str, unique_id: &str, nets: &[&str]) -> ChildSa {
        ChildSa {
            name: name.to_string(),
            unique_id: Some(unique_id.to_string()),
            // Distinct per child, so these fixtures are not accidentally a
            // reqid collision (which `status::reqid_collisions` covers).
            reqid: Some(unique_id.to_string()),
            state: state.to_string(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            local_ts: vec!["10.9.9.5/32".to_string()],
            remote_ts: nets.iter().map(|s| s.to_string()).collect(),
        }
    }


    /// Three subnets under IKEv1, and the middle one has no SA at all.
    ///
    /// This is the report the whole repair path exists for: charon says
    /// ESTABLISHED, two networks carry megabytes, and the third was never
    /// there. The two healthy children must be left strictly alone — a plan
    /// that touches them is a plan that drops working networks, which is the
    /// full reconnect this was built to avoid.
    #[test]
    fn a_missing_child_is_the_only_one_initiated() {
        let config = split_config();
        let live = [
            named_child("INSTALLED", "c-1", "1", &["10.1.0.0/24"]),
            named_child("INSTALLED", "c-3", "3", &["10.3.0.0/24"]),
        ];
        let plan = plan_repair(&config, "c", None, &live.iter().collect::<Vec<_>>(), &[]);

        assert_eq!(plan.len(), 3, "one step per subnet under IKEv1");
        assert_eq!(plan[1].child, "c-2", "the child name follows the subnet's index");
        assert_eq!(plan[1].action, RepairAction::Initiate);
        assert!(
            plan[1].finding().unwrap().contains("no CHILD_SA at all"),
            "{:?}",
            plan[1].finding()
        );
        for healthy in [&plan[0], &plan[2]] {
            assert!(
                matches!(&healthy.action, RepairAction::Keep { narrowed, .. } if narrowed.is_empty()),
                "{:?} must be left alone",
                healthy
            );
            assert_eq!(healthy.finding(), None, "a healthy child says nothing");
        }
    }

    /// A child that is installed but silent is replaced, not duplicated.
    ///
    /// The stale SA has to be named by charon's unique id: `terminate` given
    /// the reported name would match the wrong generation after a rekey, or
    /// nothing at all. And it has to go *before* the new one is initiated —
    /// leaving it in place keeps a kernel policy that can still win for the
    /// same selectors, which is the dead path we are trying to replace.
    #[test]
    fn a_silent_child_is_terminated_by_id_then_reinitiated() {
        let config = split_config();
        let live = [
            named_child("INSTALLED", "c-1", "1", &["10.1.0.0/24"]),
            named_child("INSTALLED", "c-2-17", "17", &["10.2.0.0/24"]),
            named_child("INSTALLED", "c-3", "3", &["10.3.0.0/24"]),
        ];
        let plan = plan_repair(
            &config,
            "c",
            None,
            &live.iter().collect::<Vec<_>>(),
            &["10.2.0.0/24".to_string()],
        );

        match &plan[1].action {
            RepairAction::Replace { stale, silent } => {
                assert_eq!(silent, &["10.2.0.0/24".to_string()]);
                assert_eq!(
                    stale,
                    &[StaleChild {
                        name: "c-2-17".to_string(),
                        unique_id: "17".to_string(),
                    }],
                    "only the silent network's SA, and by id"
                );
            }
            other => panic!("expected a replacement, got {other:?}"),
        }
        // The networks that are answering are not in the blast radius.
        assert!(matches!(plan[0].action, RepairAction::Keep { .. }));
        assert!(matches!(plan[2].action, RepairAction::Keep { .. }));
    }

    /// A gateway that narrowed the selectors leaves the CHILD_SA up and
    /// carrying less than we asked for. Initiating again returns the same
    /// narrowing plus a duplicate SA, so the plan must keep the child and
    /// report the network instead — this is what stops the caller retrying a
    /// refused question forever.
    #[test]
    fn a_narrowed_selector_is_reported_not_retried() {
        let mut config = split_config();
        config.ike_version = IkeVersion::V2;
        // One child for everything (IKEv2), but the gateway accepted two of the
        // three networks.
        let live = [named_child("INSTALLED", "c-4", "4", &["10.1.0.0/24", "10.3.0.0/24"])];
        let plan = plan_repair(&config, "c", None, &live.iter().collect::<Vec<_>>(), &[]);

        assert_eq!(plan.len(), 1, "IKEv2 carries every selector in one child");
        match &plan[0].action {
            RepairAction::Keep { healthy, narrowed } => {
                assert_eq!(narrowed, &["10.2.0.0/24".to_string()]);
                assert_eq!(
                    healthy,
                    &["10.1.0.0/24".to_string(), "10.3.0.0/24".to_string()]
                );
            }
            other => panic!("expected the child to be kept, got {other:?}"),
        }
    }

    /// The same narrowed network, now also reported silent by the counters.
    /// Silence outranks narrowing: a network the gateway *is* carrying and that
    /// has stopped answering is the repairable case, and an SA that carries
    /// nothing of what we asked cannot be the one to keep.
    #[test]
    fn silence_outranks_narrowing() {
        let config = split_config();
        let live = [named_child("INSTALLED", "c-2-9", "9", &["10.2.0.0/24"])];
        let plan = plan_repair(
            &config,
            "c",
            None,
            &live.iter().collect::<Vec<_>>(),
            &["10.2.0.0/24".to_string()],
        );
        assert!(
            matches!(&plan[1].action, RepairAction::Replace { .. }),
            "{:?}",
            plan[1].action
        );
        // The other two have no SA at all, so they are initiated rather than
        // mistaken for networks the gateway refused.
        assert_eq!(plan[0].action, RepairAction::Initiate);
        assert_eq!(plan[2].action, RepairAction::Initiate);
    }

    /// A child charon reports without a unique id cannot be terminated — there
    /// is no handle to name it by. It must not silently become a plain
    /// re-initiate that stacks a second SA on top of the first: the plan drops
    /// it from `stale` and the tunnel keeps whatever it had.
    #[test]
    fn a_child_with_no_id_is_not_terminated() {
        let config = split_config();
        let mut orphan = named_child("INSTALLED", "c-2", "", &["10.2.0.0/24"]);
        orphan.unique_id = None;
        let live = [orphan];
        let plan = plan_repair(
            &config,
            "c",
            None,
            &live.iter().collect::<Vec<_>>(),
            &["10.2.0.0/24".to_string()],
        );
        match &plan[1].action {
            RepairAction::Replace { stale, .. } => assert!(stale.is_empty()),
            other => panic!("expected a replacement, got {other:?}"),
        }
    }

    /// Nothing installed and nothing reported dead: every network is initiated,
    /// which is what a repair pass does to a tunnel whose children have all
    /// gone away under a still-established IKE_SA.
    #[test]
    fn a_tunnel_with_no_children_initiates_every_network() {
        let config = split_config();
        let plan = plan_repair(&config, "c", None, &[], &[]);
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|s| s.action == RepairAction::Initiate));
        assert_eq!(
            plan.iter().map(|s| s.child.as_str()).collect::<Vec<_>>(),
            ["c-1", "c-2", "c-3"]
        );
    }

    /// A single-subnet profile keeps the plain child name — the one the
    /// disconnect path and the status output both expect.
    #[test]
    fn one_subnet_keeps_the_plain_child_name() {
        let config = bridge::tests::sample();
        let plan = plan_repair(&config, "c", None, &[], &[]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].child, "c");
    }

    /// Three subnets, IKEv1: the layout `plan_repair` has to rebuild.
    fn split_config() -> ConnectionConfig {
        let mut config = bridge::tests::sample();
        config.ike_version = IkeVersion::V1;
        config.remote_subnets = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        config
    }

    /// Which layout a repair pass has to rebuild is read off the live SAs, not
    /// the profile: the connect flow retries the other IKE version when the
    /// gateway rejects the configured one, so the profile can say IKEv2 while
    /// what is running is one CHILD_SA per subnet. Guessing wrong would
    /// initiate a child name that does not exist.
    #[test]
    fn the_running_layout_wins_over_the_profile() {
        let mut config = bridge::tests::sample();
        config.remote_subnets = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        // One SA carrying two of the profile's networks can only be IKEv2 —
        // quick mode cannot put two selector pairs in one SA.
        config.ike_version = IkeVersion::V1;
        let one = [child("INSTALLED", &["10.1.0.0/24", "10.2.0.0/24"])];
        assert_eq!(
            live_version(&config, None, &one.iter().collect::<Vec<_>>()),
            IkeVersion::V2
        );

        // Several SAs of one network each is the IKEv1 split, whatever the
        // profile claims.
        config.ike_version = IkeVersion::V2;
        let split = [
            child("INSTALLED", &["10.1.0.0/24"]),
            child("INSTALLED", &["10.2.0.0/24"]),
        ];
        assert_eq!(
            live_version(&config, None, &split.iter().collect::<Vec<_>>()),
            IkeVersion::V1
        );

        // Too little evidence — one lone child — falls back to the profile,
        // which is the best guess available. A half-installed IKEv1 tunnel is
        // exactly the case repair is called for, and the profile is right
        // about it whenever the version fallback did not fire.
        config.ike_version = IkeVersion::V1;
        let lone = [child("INSTALLED", &["10.2.0.0/24"])];
        assert_eq!(
            live_version(&config, None, &lone.iter().collect::<Vec<_>>()),
            IkeVersion::V1
        );

        // A child that is not INSTALLED proves nothing about the layout and
        // must not be counted as one of the split's SAs.
        let half = [
            child("INSTALLED", &["10.1.0.0/24"]),
            child("REKEYED", &["10.2.0.0/24"]),
        ];
        config.ike_version = IkeVersion::V2;
        assert_eq!(
            live_version(&config, None, &half.iter().collect::<Vec<_>>()),
            IkeVersion::V2
        );
    }

    fn ike(name: &str, version: Option<&str>) -> IkeSa {
        IkeSa {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            state: "ESTABLISHED".to_string(),
            local_host: "192.168.178.118".to_string(),
            remote_host: "37.156.94.75".to_string(),
            virtual_ips: vec![],
            children: vec![],
        }
    }

    /// The version charon reports outranks both the shape of the live SAs and
    /// the profile. This is the case that bit during a connect: a Sophos .scx
    /// states no IKE version so it always imports as IKEv2, the gateway
    /// answered IKEv1, and a repair pass running before enough SAs existed to
    /// infer from fell back to the profile and asked charon to initiate a child
    /// name that only exists under IKEv2.
    #[test]
    fn what_charon_negotiated_outranks_every_guess() {
        let mut config = bridge::tests::sample();
        config.ike_version = IkeVersion::V2;
        let lone = [child("INSTALLED", &["10.1.0.0/24"])];
        let live: Vec<&ChildSa> = lone.iter().collect();

        // Too little evidence: without charon's answer this falls back to the
        // profile, which is exactly the wrong guess for an .scx on IKEv1.
        assert_eq!(live_version(&config, None, &live), IkeVersion::V2);
        assert_eq!(
            live_version(&config, Some(IkeVersion::V1), &live),
            IkeVersion::V1
        );

        // It also outranks an inference that would otherwise be confident.
        let split = [
            child("INSTALLED", &["10.1.0.0/24"]),
            child("INSTALLED", &["10.2.0.0/24"]),
        ];
        let split: Vec<&ChildSa> = split.iter().collect();
        assert_eq!(live_version(&config, None, &split), IkeVersion::V1);
        assert_eq!(
            live_version(&config, Some(IkeVersion::V2), &split),
            IkeVersion::V2
        );
    }

    #[test]
    fn the_negotiated_version_comes_from_the_named_connection() {
        let sas = vec![ike("other", Some("2")), ike("ITM-Office", Some("1"))];
        assert_eq!(negotiated_version(&sas, "ITM-Office"), Some(IkeVersion::V1));
        assert_eq!(negotiated_version(&sas, "other"), Some(IkeVersion::V2));

        // No live SA under that name, a version charon did not report, and one
        // it reported in a form we do not know: all leave the caller to infer
        // rather than guessing a version out of them.
        assert_eq!(negotiated_version(&sas, "missing"), None);
        assert_eq!(negotiated_version(&[ike("x", None)], "x"), None);
        assert_eq!(negotiated_version(&[ike("x", Some("?"))], "x"), None);

        // charon has spelled it both ways across versions.
        assert_eq!(
            negotiated_version(&[ike("x", Some("IKEv1"))], "x"),
            Some(IkeVersion::V1)
        );
    }

    #[test]
    fn other_version_flips() {
        assert_eq!(other_version(IkeVersion::V1), IkeVersion::V2);
        assert_eq!(other_version(IkeVersion::V2), IkeVersion::V1);
    }
}
