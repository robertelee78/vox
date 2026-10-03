//! IPC version 9: the daemon's side of the control socket (ADR-026 §4).
//!
//! One socket serves a data root's daemon and every node attached to it (C-1). A connection opens
//! with the daemon's [`DaemonFrame::Hello`], which names the daemon's version and its attached
//! nodes (C-4). The client's first frame is an [`Opening`]:
//!
//! - [`Opening::Use`] names the node this connection acts as, **once** (C-2). The daemon answers
//!   [`DaemonFrame::Using`] or [`DaemonFrame::Refused`]; after `Using`, the connection carries the
//!   node-level [`crate::node::ipc::Request`]s and [`crate::node::ipc::Frame`]s unchanged, against
//!   that node. A request in flight when the node detaches is answered
//!   [`crate::node::ipc::Frame::NodeDetached`] (L-3).
//! - [`Opening::Daemon`] is a [`DaemonRequest`], which needs no node: list, attach, detach, end an
//!   agent session, status, metrics, subscribe to [`DaemonEvent`]s, stop.
//!
//! **There is no lock and no unlock** (ADR-026 N-2): a node takes its passphrase once, when it
//! attaches, and runs in full until it detaches. A passphrase crosses the socket only in an attach
//! (C-6), in a zeroizing buffer at each end; one taken from an environment variable is resolved by
//! the client, never by the daemon.
//!
//! Tags are 4000 and up, apart from every node-level tag, as the other additive ranges are.

use zeroize::Zeroizing;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;

// ---- names -------------------------------------------------------------------------------------

/// A node's name (ADR-026 N-1a): one path component of 1–64 bytes from `[a-z0-9._-]`, case-folded
/// to lower case, not starting with `.`, and neither `.daemon` nor `nodes`.
///
/// Held here until the layout work's `paths::NodeName` lands; this one then becomes a re-export of
/// it, so the wire never sees a name that the layout would refuse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeName(String);

impl NodeName {
    /// The longest name, in bytes.
    pub const MAX: usize = 64;

    /// Parse `s`, case-folding it, or say why it is not a node's name.
    ///
    /// # Errors
    /// If it is empty, longer than [`NodeName::MAX`], has a byte outside `[a-z0-9._-]` after
    /// folding, starts with `.`, or is a reserved name.
    pub fn parse(s: &str) -> Result<Self> {
        let folded = s.to_ascii_lowercase();
        let why = if folded.is_empty() {
            Some("is empty")
        } else if folded.len() > Self::MAX {
            Some("is longer than 64 bytes")
        } else if folded.starts_with('.') {
            Some("starts with '.'")
        } else if folded == "nodes" {
            Some("is reserved")
        } else if !folded
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            Some("may use only a-z, 0-9, '.', '_' and '-'")
        } else {
            None
        };
        match why {
            Some(why) => Err(Error::Path {
                op: "node name",
                detail: format!("{s:?} {why}"),
            }),
            None => Ok(Self(folded)),
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---- tags --------------------------------------------------------------------------------------

// Daemon → client.
const T_DAEMON_HELLO: u64 = 4000;
const T_USING: u64 = 4001;
const T_REFUSED: u64 = 4002;
/// Shared with the node-level frames: [`crate::node::ipc::Frame::NodeDetached`].
pub(crate) const T_NODE_DETACHED: u64 = 4003;
const T_NODES: u64 = 4004;
const T_ATTACHED_INFO: u64 = 4005;
const T_DAEMON_OK: u64 = 4006;
const T_DAEMON_EVENT: u64 = 4007;
const T_METRICS: u64 = 4008;
const T_DAEMON_STATUS: u64 = 4009;
const T_SESSION_ENDED: u64 = 4010;

// Client → daemon: the opening frame.
const T_USE: u64 = 4100;
const T_REQ_NODES: u64 = 4101;
const T_REQ_ATTACH: u64 = 4102;
const T_REQ_DETACH: u64 = 4103;
const T_REQ_SESSION_END: u64 = 4104;
const T_REQ_STATUS: u64 = 4105;
const T_REQ_METRICS: u64 = 4106;
const T_REQ_SUBSCRIBE: u64 = 4107;
const T_REQ_STOP: u64 = 4108;

// Events.
const T_EV_ATTACHED: u64 = 4200;
const T_EV_DETACHED: u64 = 4201;

// Refusals.
const T_REF_NOT_ATTACHED: u64 = 4300;
const T_REF_NO_SUCH_NODE: u64 = 4301;
const T_REF_WRONG_PASSPHRASE: u64 = 4302;
const T_REF_NO_IDENTITY: u64 = 4303;
const T_REF_BAD_NAME: u64 = 4304;
const T_REF_FAILED: u64 = 4305;
const T_REF_STOPPING: u64 = 4306;
const T_REF_NODE_IN_USE: u64 = 4307;

// Small enums.
const STATE_DETACHED: u64 = 0;
const STATE_ATTACHING: u64 = 1;
const STATE_ATTACHED: u64 = 2;
const STATE_DETACHING: u64 = 3;

const ATTACH_NO: u64 = 0;
const ATTACH_HOLD: u64 = 1;

const CAUSE_REQUESTED: u64 = 0;
const CAUSE_LAST_HOLDER: u64 = 1;
const CAUSE_DAEMON_STOPPING: u64 = 2;
const CAUSE_PANICKED: u64 = 3;
const CAUSE_STOPPED: u64 = 4;

// ---- types -------------------------------------------------------------------------------------

/// Where a node is in its life on the daemon (ADR-026 L-1). There is no locked state (N-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// On disk, not running.
    Detached,
    /// Being attached: its files are opening and its passphrase is being checked. A second attach
    /// waits for this one (L-2).
    Attaching,
    /// Running in full.
    Attached,
    /// Being detached: its tasks and connections are closing (L-3).
    Detaching,
}

/// One node as the daemon reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// Its name.
    pub name: NodeName,
    /// Where it is in its life.
    pub state: NodeState,
    /// Its identity's fingerprint, once known.
    pub fingerprint: Option<Digest32>,
    /// Attached implicitly, so it detaches when its last holder goes (L-3).
    pub implicit: bool,
    /// Recorded with `--keep`, so it is attached again when the daemon starts (L-4).
    pub keep: bool,
}

/// How a `Use` attaches a node that is not attached (ADR-026 L-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Never: a one-shot verb (`room`, `status`, `share`, `app`). The daemon refuses with
    /// [`Refusal::NotAttached`], which says how to attach it.
    No,
    /// Attach it implicitly if it is not attached, and hold it while this connection is open: a
    /// verb that holds a session (`serve`, `connect`, `up`, `forward`, `lan up`) or the TUI.
    Hold,
}

/// The opening `Use`: the node this connection acts as (ADR-026 C-2).
///
/// The client resolves the node itself (C-3), from its flag, the hello's attached nodes and the
/// nodes on disk, so `node` is always a name here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseNode {
    /// The node.
    pub node: NodeName,
    /// Whether, and how, to attach it if it is not attached.
    pub attach: AttachMode,
    /// The identity passphrase, for an attach this `Use` may cause; `None` for a node that needs
    /// none, or for [`AttachMode::No`]. Resolved by the client, never by the daemon (C-6).
    pub passphrase: Option<Zeroizing<String>>,
    /// Anchor specs (`--anchor`) the node is attached with, if this `Use` attaches it.
    pub anchors: Vec<String>,
}

/// Where a `--keep` node's passphrase comes from when the daemon starts (ADR-026 L-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepSource {
    /// It needs none.
    None,
    /// The first line of this file; the rest open rooms, as a piped `vox daemon`'s do.
    File(std::path::PathBuf),
}

/// A request to the daemon itself, with no `Use` (ADR-026 C-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonRequest {
    /// Every node on disk, with its state: answered [`DaemonFrame::Nodes`].
    Nodes,
    /// Attach `node` explicitly (`vox node attach`): it stays attached until `Detach` or the
    /// daemon stops. Answered [`DaemonFrame::Attached`] or [`DaemonFrame::Refused`].
    Attach {
        /// The node.
        node: NodeName,
        /// Its identity passphrase, if it has one.
        passphrase: Option<Zeroizing<String>>,
        /// Recorded in the attach file, with where its passphrase comes from (L-4); `None`
        /// attaches it for this daemon's life only.
        keep: Option<KeepSource>,
        /// Room passphrases, one per line as a piped `vox daemon` takes them.
        rooms: Vec<Zeroizing<String>>,
        /// Anchor specs it is attached with.
        anchors: Vec<String>,
    },
    /// Detach `node` (L-3). Answered [`DaemonFrame::Ok`] once it has detached.
    Detach {
        /// The node.
        node: NodeName,
    },
    /// Unregister an agent session of `node`, and detach the node if that was its last holder,
    /// in one decision (L-3). Answered [`DaemonFrame::SessionEnded`].
    SessionEnd {
        /// The node.
        node: NodeName,
        /// The harness's session id.
        session: String,
    },
    /// The daemon's own status: answered [`DaemonFrame::Status`].
    Status,
    /// The metrics, as Prometheus text: answered [`DaemonFrame::Metrics`].
    Metrics,
    /// Every later [`DaemonEvent`], as [`DaemonFrame::Event`]s, until the connection closes.
    Subscribe,
    /// Detach every node and stop the daemon. Answered [`DaemonFrame::Ok`] once it has begun.
    Stop,
}

/// A client's first frame (ADR-026 C-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// This connection acts as one node.
    Use(UseNode),
    /// This connection asks the daemon.
    Daemon(DaemonRequest),
}

/// Why a node detached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetachCause {
    /// `vox node detach`, or a `Detach` request.
    Requested,
    /// It was attached implicitly and its last holder went (L-3).
    LastHolder,
    /// The daemon is stopping.
    DaemonStopping,
    /// Its actor panicked (L-6); the panic's message.
    Panicked(String),
    /// Its actor stopped on its own.
    Stopped,
}

/// What the daemon tells a subscriber (ADR-026 C-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonEvent {
    /// `node` attached, as `fingerprint`.
    Attached {
        /// The node.
        node: NodeName,
        /// Its identity's fingerprint, if it has one yet.
        fingerprint: Option<Digest32>,
    },
    /// `node` detached.
    Detached {
        /// The node.
        node: NodeName,
        /// Why.
        cause: DetachCause,
    },
}

/// Why the daemon would not do what a `Use` or a [`DaemonRequest`] asked. Each says what to do; none
/// names another node's secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A one-shot verb's node is not attached; it must be attached first (L-2).
    NotAttached {
        /// The node.
        node: NodeName,
    },
    /// No node by that name is on disk.
    NoSuchNode {
        /// The node.
        node: NodeName,
    },
    /// The passphrase does not open the node's identity.
    WrongPassphrase {
        /// The node.
        node: NodeName,
    },
    /// The node has no identity yet.
    NoIdentity {
        /// The node.
        node: NodeName,
    },
    /// The name is not a node's name (N-1a): what was given, and why.
    BadName {
        /// What was given.
        given: String,
        /// Why it is not a name.
        why: String,
    },
    /// The node could not be attached or detached; the reason, for a person.
    Failed {
        /// The node.
        node: NodeName,
        /// Why, in plain words.
        why: String,
    },
    /// The daemon is stopping, and attaches nothing more.
    Stopping,
    /// Another process holds the node's directory: an older `vox` still running as it.
    NodeInUse {
        /// The node.
        node: NodeName,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAttached { node } => write!(
                f,
                "node {node} is not attached; attach it first: vox node attach {node}"
            ),
            Self::NoSuchNode { node } => write!(f, "there is no node {node}"),
            Self::WrongPassphrase { node } => {
                write!(f, "that passphrase does not open node {node}'s identity")
            }
            Self::NoIdentity { node } => write!(f, "node {node} has no identity yet"),
            Self::BadName { given, why } => write!(f, "{given:?} is not a node's name: {why}"),
            Self::Failed { node, why } => write!(f, "node {node}: {why}"),
            Self::Stopping => f.write_str("the daemon is stopping"),
            Self::NodeInUse { node } => write!(
                f,
                "another vox is still running as node {node}; stop it, then try again"
            ),
        }
    }
}

/// The daemon's own status (answering [`DaemonRequest::Status`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    /// The daemon's `vox` version.
    pub version: String,
    /// Its process id.
    pub pid: u32,
    /// The address its one UDP socket listens on, once bound (D-3); empty before.
    pub listen: String,
    /// Every node on disk, with its state.
    pub nodes: Vec<NodeInfo>,
    /// Node actors that panicked since it started (L-6).
    pub panics: u64,
}

/// What the daemon sends on a connection before a `Use` takes it to the node level, and in answer to
/// a [`DaemonRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonFrame {
    /// Sent once on connect, before anything else (C-4).
    Hello {
        /// The IPC protocol this daemon speaks: [`crate::node::ipc::PROTOCOL_VERSION`].
        protocol: u64,
        /// Its `vox` version.
        version: String,
        /// Its process id.
        pid: u32,
        /// The nodes attached now (C-3's second step reads these).
        attached: Vec<NodeInfo>,
    },
    /// The `Use` was taken: from here the connection acts as `node`, whose identity is `me`.
    Using {
        /// The node.
        node: NodeName,
        /// Its identity's fingerprint, or `None` if it has none yet.
        me: Option<Digest32>,
    },
    /// The `Use` or request was refused.
    Refused(Refusal),
    /// The nodes a [`DaemonRequest::Nodes`] asked for.
    Nodes(Vec<NodeInfo>),
    /// The node a [`DaemonRequest::Attach`] attached.
    Attached(NodeInfo),
    /// A daemon request succeeded and carries nothing further.
    Ok,
    /// What a [`DaemonRequest::SessionEnd`] did: whether the session was registered, and whether
    /// the node detached because it was the last holder.
    SessionEnded {
        /// The session was registered, and is not now.
        was_registered: bool,
        /// The node detached with it.
        detached: bool,
    },
    /// The daemon's status.
    Status(DaemonStatus),
    /// Prometheus text (answering [`DaemonRequest::Metrics`]).
    Metrics(String),
    /// An event, after [`DaemonRequest::Subscribe`].
    Event(DaemonEvent),
}

// ---- encoding ----------------------------------------------------------------------------------

fn malformed(what: &'static str) -> impl FnOnce(crate::cbor::CborError) -> Error {
    move |_| Error::MalformedIpc(what)
}

fn name(d: &mut Decoder<'_>, what: &'static str) -> Result<NodeName> {
    let s = d.text().map_err(malformed(what))?;
    NodeName::parse(s).map_err(|_| Error::MalformedIpc(what))
}

fn text(d: &mut Decoder<'_>, what: &'static str) -> Result<String> {
    Ok(d.text().map_err(malformed(what))?.to_owned())
}

fn flag(d: &mut Decoder<'_>, what: &'static str) -> Result<bool> {
    match d.uint().map_err(malformed(what))? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::MalformedIpc(what)),
    }
}

/// An absent fingerprint is the empty byte string, so the arity stays fixed: ADR-008's canonical
/// encoding has no optionals.
fn put_fp(e: &mut Encoder, fp: Option<&Digest32>) {
    e.bytes(fp.map_or(&[][..], |d| &d[..]));
}

fn fp(d: &mut Decoder<'_>, what: &'static str) -> Result<Option<Digest32>> {
    let b = d.bytes().map_err(malformed(what))?;
    if b.is_empty() {
        return Ok(None);
    }
    Digest32::try_from(b)
        .map(Some)
        .map_err(|_| Error::MalformedIpc(what))
}

/// An optional secret: `[]` for none, `[text]` for one. A secret is never told apart from an empty
/// one by a sentinel string.
fn put_secret(e: &mut Encoder, s: Option<&Zeroizing<String>>) {
    match s {
        None => {
            e.array(0);
        }
        Some(s) => {
            e.array(1).text(s);
        }
    }
}

fn secret(d: &mut Decoder<'_>, what: &'static str) -> Result<Option<Zeroizing<String>>> {
    match d.array().map_err(malformed(what))? {
        0 => Ok(None),
        1 => Ok(Some(Zeroizing::new(text(d, what)?))),
        _ => Err(Error::MalformedIpc(what)),
    }
}

fn put_texts(e: &mut Encoder, v: &[String]) {
    e.array(v.len());
    for s in v {
        e.text(s);
    }
}

fn texts(d: &mut Decoder<'_>, what: &'static str) -> Result<Vec<String>> {
    let n = d.array().map_err(malformed(what))?;
    let mut v = Vec::with_capacity(n.min(256));
    for _ in 0..n {
        v.push(text(d, what)?);
    }
    Ok(v)
}

fn put_state(e: &mut Encoder, s: NodeState) {
    e.uint(match s {
        NodeState::Detached => STATE_DETACHED,
        NodeState::Attaching => STATE_ATTACHING,
        NodeState::Attached => STATE_ATTACHED,
        NodeState::Detaching => STATE_DETACHING,
    });
}

fn state(d: &mut Decoder<'_>) -> Result<NodeState> {
    Ok(match d.uint().map_err(malformed("ipc node state"))? {
        STATE_DETACHED => NodeState::Detached,
        STATE_ATTACHING => NodeState::Attaching,
        STATE_ATTACHED => NodeState::Attached,
        STATE_DETACHING => NodeState::Detaching,
        _ => return Err(Error::MalformedIpc("ipc node state")),
    })
}

fn put_info(e: &mut Encoder, i: &NodeInfo) {
    e.array(5).text(i.name.as_str());
    put_state(e, i.state);
    put_fp(e, i.fingerprint.as_ref());
    e.uint(u64::from(i.implicit)).uint(u64::from(i.keep));
}

fn info(d: &mut Decoder<'_>) -> Result<NodeInfo> {
    if d.array().map_err(malformed("ipc node info"))? != 5 {
        return Err(Error::MalformedIpc("ipc node info"));
    }
    Ok(NodeInfo {
        name: name(d, "ipc node info name")?,
        state: state(d)?,
        fingerprint: fp(d, "ipc node info fingerprint")?,
        implicit: flag(d, "ipc node info implicit")?,
        keep: flag(d, "ipc node info keep")?,
    })
}

fn put_infos(e: &mut Encoder, v: &[NodeInfo]) {
    e.array(v.len());
    for i in v {
        put_info(e, i);
    }
}

fn infos(d: &mut Decoder<'_>) -> Result<Vec<NodeInfo>> {
    let n = d.array().map_err(malformed("ipc node list"))?;
    let mut v = Vec::with_capacity(n.min(256));
    for _ in 0..n {
        v.push(info(d)?);
    }
    Ok(v)
}

fn put_refusal(e: &mut Encoder, r: &Refusal) {
    match r {
        Refusal::NotAttached { node } => {
            e.array(2).uint(T_REF_NOT_ATTACHED).text(node.as_str());
        }
        Refusal::NoSuchNode { node } => {
            e.array(2).uint(T_REF_NO_SUCH_NODE).text(node.as_str());
        }
        Refusal::WrongPassphrase { node } => {
            e.array(2).uint(T_REF_WRONG_PASSPHRASE).text(node.as_str());
        }
        Refusal::NoIdentity { node } => {
            e.array(2).uint(T_REF_NO_IDENTITY).text(node.as_str());
        }
        Refusal::BadName { given, why } => {
            e.array(3).uint(T_REF_BAD_NAME).text(given).text(why);
        }
        Refusal::Failed { node, why } => {
            e.array(3).uint(T_REF_FAILED).text(node.as_str()).text(why);
        }
        Refusal::Stopping => {
            e.array(1).uint(T_REF_STOPPING);
        }
        Refusal::NodeInUse { node } => {
            e.array(2).uint(T_REF_NODE_IN_USE).text(node.as_str());
        }
    }
}

fn refusal(d: &mut Decoder<'_>) -> Result<Refusal> {
    let n = d.array().map_err(malformed("ipc refusal"))?;
    let tag = d.uint().map_err(malformed("ipc refusal tag"))?;
    let w = "ipc refusal node";
    Ok(match (tag, n) {
        (T_REF_NOT_ATTACHED, 2) => Refusal::NotAttached { node: name(d, w)? },
        (T_REF_NO_SUCH_NODE, 2) => Refusal::NoSuchNode { node: name(d, w)? },
        (T_REF_WRONG_PASSPHRASE, 2) => Refusal::WrongPassphrase { node: name(d, w)? },
        (T_REF_NO_IDENTITY, 2) => Refusal::NoIdentity { node: name(d, w)? },
        (T_REF_BAD_NAME, 3) => Refusal::BadName {
            given: text(d, "ipc refusal given")?,
            why: text(d, "ipc refusal why")?,
        },
        (T_REF_FAILED, 3) => Refusal::Failed {
            node: name(d, w)?,
            why: text(d, "ipc refusal why")?,
        },
        (T_REF_STOPPING, 1) => Refusal::Stopping,
        (T_REF_NODE_IN_USE, 2) => Refusal::NodeInUse { node: name(d, w)? },
        _ => return Err(Error::MalformedIpc("ipc refusal tag")),
    })
}

fn put_cause(e: &mut Encoder, c: &DetachCause) {
    match c {
        DetachCause::Requested => {
            e.array(1).uint(CAUSE_REQUESTED);
        }
        DetachCause::LastHolder => {
            e.array(1).uint(CAUSE_LAST_HOLDER);
        }
        DetachCause::DaemonStopping => {
            e.array(1).uint(CAUSE_DAEMON_STOPPING);
        }
        DetachCause::Panicked(m) => {
            e.array(2).uint(CAUSE_PANICKED).text(m);
        }
        DetachCause::Stopped => {
            e.array(1).uint(CAUSE_STOPPED);
        }
    }
}

fn cause(d: &mut Decoder<'_>) -> Result<DetachCause> {
    let n = d.array().map_err(malformed("ipc detach cause"))?;
    let tag = d.uint().map_err(malformed("ipc detach cause"))?;
    Ok(match (tag, n) {
        (CAUSE_REQUESTED, 1) => DetachCause::Requested,
        (CAUSE_LAST_HOLDER, 1) => DetachCause::LastHolder,
        (CAUSE_DAEMON_STOPPING, 1) => DetachCause::DaemonStopping,
        (CAUSE_PANICKED, 2) => DetachCause::Panicked(text(d, "ipc panic message")?),
        (CAUSE_STOPPED, 1) => DetachCause::Stopped,
        _ => return Err(Error::MalformedIpc("ipc detach cause")),
    })
}

impl Opening {
    /// Canonical CBOR body (unframed). In a buffer wiped when dropped: an attach carries
    /// passphrases (C-6).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::for_secrets();
        match self {
            Opening::Use(u) => {
                e.array(5).uint(T_USE).text(u.node.as_str());
                e.uint(match u.attach {
                    AttachMode::No => ATTACH_NO,
                    AttachMode::Hold => ATTACH_HOLD,
                });
                put_secret(&mut e, u.passphrase.as_ref());
                put_texts(&mut e, &u.anchors);
            }
            Opening::Daemon(r) => match r {
                DaemonRequest::Nodes => {
                    e.array(1).uint(T_REQ_NODES);
                }
                DaemonRequest::Attach {
                    node,
                    passphrase,
                    keep,
                    rooms,
                    anchors,
                } => {
                    e.array(6).uint(T_REQ_ATTACH).text(node.as_str());
                    put_secret(&mut e, passphrase.as_ref());
                    match keep {
                        None => {
                            e.array(0);
                        }
                        Some(KeepSource::None) => {
                            e.array(1).text("");
                        }
                        Some(KeepSource::File(p)) => {
                            e.array(1).text(&p.to_string_lossy());
                        }
                    }
                    e.array(rooms.len());
                    for r in rooms {
                        e.text(r);
                    }
                    put_texts(&mut e, anchors);
                }
                DaemonRequest::Detach { node } => {
                    e.array(2).uint(T_REQ_DETACH).text(node.as_str());
                }
                DaemonRequest::SessionEnd { node, session } => {
                    e.array(3)
                        .uint(T_REQ_SESSION_END)
                        .text(node.as_str())
                        .text(session);
                }
                DaemonRequest::Status => {
                    e.array(1).uint(T_REQ_STATUS);
                }
                DaemonRequest::Metrics => {
                    e.array(1).uint(T_REQ_METRICS);
                }
                DaemonRequest::Subscribe => {
                    e.array(1).uint(T_REQ_SUBSCRIBE);
                }
                DaemonRequest::Stop => {
                    e.array(1).uint(T_REQ_STOP);
                }
            },
        }
        Zeroizing::new(e.finish())
    }

    /// Parse a client's opening frame.
    ///
    /// # Errors
    /// [`Error::MalformedIpc`] for anything that is not exactly one opening.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array().map_err(malformed("ipc opening"))?;
        let tag = d.uint().map_err(malformed("ipc opening tag"))?;
        let out = match (tag, n) {
            (T_USE, 5) => {
                let node = name(&mut d, "ipc use node")?;
                let attach = match d.uint().map_err(malformed("ipc use attach"))? {
                    ATTACH_NO => AttachMode::No,
                    ATTACH_HOLD => AttachMode::Hold,
                    _ => return Err(Error::MalformedIpc("ipc use attach")),
                };
                let passphrase = secret(&mut d, "ipc use passphrase")?;
                let anchors = texts(&mut d, "ipc use anchors")?;
                Opening::Use(UseNode {
                    node,
                    attach,
                    passphrase,
                    anchors,
                })
            }
            (T_REQ_NODES, 1) => Opening::Daemon(DaemonRequest::Nodes),
            (T_REQ_ATTACH, 6) => {
                let node = name(&mut d, "ipc attach node")?;
                let passphrase = secret(&mut d, "ipc attach passphrase")?;
                let keep = match d.array().map_err(malformed("ipc attach keep"))? {
                    0 => None,
                    1 => {
                        let p = text(&mut d, "ipc attach keep")?;
                        Some(if p.is_empty() {
                            KeepSource::None
                        } else {
                            KeepSource::File(p.into())
                        })
                    }
                    _ => return Err(Error::MalformedIpc("ipc attach keep")),
                };
                let n = d.array().map_err(malformed("ipc attach rooms"))?;
                let mut rooms = Vec::with_capacity(n.min(256));
                for _ in 0..n {
                    rooms.push(Zeroizing::new(text(&mut d, "ipc attach room passphrase")?));
                }
                let anchors = texts(&mut d, "ipc attach anchors")?;
                Opening::Daemon(DaemonRequest::Attach {
                    node,
                    passphrase,
                    keep,
                    rooms,
                    anchors,
                })
            }
            (T_REQ_DETACH, 2) => Opening::Daemon(DaemonRequest::Detach {
                node: name(&mut d, "ipc detach node")?,
            }),
            (T_REQ_SESSION_END, 3) => Opening::Daemon(DaemonRequest::SessionEnd {
                node: name(&mut d, "ipc session end node")?,
                session: text(&mut d, "ipc session end session")?,
            }),
            (T_REQ_STATUS, 1) => Opening::Daemon(DaemonRequest::Status),
            (T_REQ_METRICS, 1) => Opening::Daemon(DaemonRequest::Metrics),
            (T_REQ_SUBSCRIBE, 1) => Opening::Daemon(DaemonRequest::Subscribe),
            (T_REQ_STOP, 1) => Opening::Daemon(DaemonRequest::Stop),
            _ => return Err(Error::MalformedIpc("ipc opening tag")),
        };
        d.finish().map_err(malformed("ipc opening trailing"))?;
        Ok(out)
    }
}

impl DaemonFrame {
    /// Canonical CBOR body (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            DaemonFrame::Hello {
                protocol,
                version,
                pid,
                attached,
            } => {
                e.array(5)
                    .uint(T_DAEMON_HELLO)
                    .uint(*protocol)
                    .text(version)
                    .uint(u64::from(*pid));
                put_infos(&mut e, attached);
            }
            DaemonFrame::Using { node, me } => {
                e.array(3).uint(T_USING).text(node.as_str());
                put_fp(&mut e, me.as_ref());
            }
            DaemonFrame::Refused(r) => {
                e.array(2).uint(T_REFUSED);
                put_refusal(&mut e, r);
            }
            DaemonFrame::Nodes(v) => {
                e.array(2).uint(T_NODES);
                put_infos(&mut e, v);
            }
            DaemonFrame::Attached(i) => {
                e.array(2).uint(T_ATTACHED_INFO);
                put_info(&mut e, i);
            }
            DaemonFrame::Ok => {
                e.array(1).uint(T_DAEMON_OK);
            }
            DaemonFrame::SessionEnded {
                was_registered,
                detached,
            } => {
                e.array(3)
                    .uint(T_SESSION_ENDED)
                    .uint(u64::from(*was_registered))
                    .uint(u64::from(*detached));
            }
            DaemonFrame::Status(s) => {
                e.array(6)
                    .uint(T_DAEMON_STATUS)
                    .text(&s.version)
                    .uint(u64::from(s.pid))
                    .text(&s.listen);
                put_infos(&mut e, &s.nodes);
                e.uint(s.panics);
            }
            DaemonFrame::Metrics(text) => {
                e.array(2).uint(T_METRICS).text(text);
            }
            DaemonFrame::Event(ev) => {
                e.array(2).uint(T_DAEMON_EVENT);
                match ev {
                    DaemonEvent::Attached { node, fingerprint } => {
                        e.array(3).uint(T_EV_ATTACHED).text(node.as_str());
                        put_fp(&mut e, fingerprint.as_ref());
                    }
                    DaemonEvent::Detached { node, cause } => {
                        e.array(3).uint(T_EV_DETACHED).text(node.as_str());
                        put_cause(&mut e, cause);
                    }
                }
            }
        }
        e.finish()
    }

    /// Parse one frame the daemon sent.
    ///
    /// # Errors
    /// [`Error::MalformedIpc`] for anything that is not exactly one daemon frame. A node-level
    /// `Hello` (protocol 8 and before) is malformed here: an older daemon is not this one.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array().map_err(malformed("ipc daemon frame"))?;
        let tag = d.uint().map_err(malformed("ipc daemon frame tag"))?;
        let out = match (tag, n) {
            (T_DAEMON_HELLO, 5) => {
                let protocol = d.uint().map_err(malformed("ipc daemon hello protocol"))?;
                let version = text(&mut d, "ipc daemon hello version")?;
                let pid = u32::try_from(d.uint().map_err(malformed("ipc daemon hello pid"))?)
                    .map_err(|_| Error::MalformedIpc("ipc daemon hello pid"))?;
                let attached = infos(&mut d)?;
                DaemonFrame::Hello {
                    protocol,
                    version,
                    pid,
                    attached,
                }
            }
            (T_USING, 3) => DaemonFrame::Using {
                node: name(&mut d, "ipc using node")?,
                me: fp(&mut d, "ipc using identity")?,
            },
            (T_REFUSED, 2) => DaemonFrame::Refused(refusal(&mut d)?),
            (T_NODES, 2) => DaemonFrame::Nodes(infos(&mut d)?),
            (T_ATTACHED_INFO, 2) => DaemonFrame::Attached(info(&mut d)?),
            (T_DAEMON_OK, 1) => DaemonFrame::Ok,
            (T_SESSION_ENDED, 3) => DaemonFrame::SessionEnded {
                was_registered: flag(&mut d, "ipc session ended registered")?,
                detached: flag(&mut d, "ipc session ended detached")?,
            },
            (T_DAEMON_STATUS, 6) => {
                let version = text(&mut d, "ipc daemon status version")?;
                let pid = u32::try_from(d.uint().map_err(malformed("ipc daemon status pid"))?)
                    .map_err(|_| Error::MalformedIpc("ipc daemon status pid"))?;
                let listen = text(&mut d, "ipc daemon status listen")?;
                let nodes = infos(&mut d)?;
                let panics = d.uint().map_err(malformed("ipc daemon status panics"))?;
                DaemonFrame::Status(DaemonStatus {
                    version,
                    pid,
                    listen,
                    nodes,
                    panics,
                })
            }
            (T_METRICS, 2) => DaemonFrame::Metrics(text(&mut d, "ipc metrics")?),
            (T_DAEMON_EVENT, 2) => {
                let n = d.array().map_err(malformed("ipc daemon event"))?;
                let tag = d.uint().map_err(malformed("ipc daemon event tag"))?;
                DaemonFrame::Event(match (tag, n) {
                    (T_EV_ATTACHED, 3) => DaemonEvent::Attached {
                        node: name(&mut d, "ipc event node")?,
                        fingerprint: fp(&mut d, "ipc event fingerprint")?,
                    },
                    (T_EV_DETACHED, 3) => DaemonEvent::Detached {
                        node: name(&mut d, "ipc event node")?,
                        cause: cause(&mut d)?,
                    },
                    _ => return Err(Error::MalformedIpc("ipc daemon event tag")),
                })
            }
            _ => return Err(Error::MalformedIpc("ipc daemon frame tag")),
        };
        d.finish().map_err(malformed("ipc daemon frame trailing"))?;
        Ok(out)
    }
}

// ---- client ------------------------------------------------------------------------------------

/// A connection to the daemon that has read its hello and not yet sent its opening.
#[derive(Debug)]
pub struct DaemonClient {
    /// The connection.
    pub(crate) stream: tokio::net::UnixStream,
    /// The daemon's version.
    pub version: String,
    /// The daemon's process id.
    pub pid: u32,
    /// The nodes attached when it greeted (ADR-026 C-3's second step).
    pub attached: Vec<NodeInfo>,
}

impl DaemonClient {
    /// Connect to the daemon's socket at `path`, checked as this user's own, and read its hello
    /// within [`crate::node::ipc::ANSWER_WITHIN`].
    ///
    /// # Errors
    /// [`crate::error::IpcHandshake`] if nothing is there, it is not this user's, it closes before
    /// greeting, greets with another protocol, or greets with something that is not a daemon's
    /// hello (a node of protocol 8 or before).
    pub async fn open(path: &std::path::Path) -> Result<Self> {
        use crate::error::IpcHandshake;
        use crate::node::ipc::{connect_own, read_frame, silent, ANSWER_WITHIN, PROTOCOL_VERSION};
        let (stream, hello) = tokio::time::timeout(ANSWER_WITHIN, async {
            let mut stream = connect_own(path).await?;
            let hello = read_frame(&mut stream).await?;
            Ok::<_, Error>((stream, hello))
        })
        .await
        .map_err(|_| silent())??;
        let Some(hello) = hello else {
            return Err(Error::Ipc(IpcHandshake::ClosedBeforeHello));
        };
        // An older daemon greets with a node-level hello, which is not a daemon frame: its
        // protocol is read from it so the refusal names both versions.
        if let Ok(crate::node::ipc::Frame::Hello { protocol, .. }) =
            crate::node::ipc::Frame::from_bytes(&hello)
        {
            return Err(Error::Ipc(IpcHandshake::Protocol {
                mine: PROTOCOL_VERSION,
                theirs: protocol,
            }));
        }
        match DaemonFrame::from_bytes(&hello) {
            Ok(DaemonFrame::Hello {
                protocol,
                version,
                pid,
                attached,
            }) if protocol == PROTOCOL_VERSION => Ok(Self {
                stream,
                version,
                pid,
                attached,
            }),
            Ok(DaemonFrame::Hello { protocol, .. }) => Err(Error::Ipc(IpcHandshake::Protocol {
                mine: PROTOCOL_VERSION,
                theirs: protocol,
            })),
            _ => Err(Error::Ipc(IpcHandshake::NotHello)),
        }
    }

    /// Send `request` as this connection's opening, and read the daemon's answer. After
    /// [`DaemonRequest::Subscribe`], read the events with [`DaemonClient::next`].
    ///
    /// # Errors
    /// If the connection fails or closes before an answer, or the answer is malformed.
    pub async fn request(&mut self, request: DaemonRequest) -> Result<DaemonFrame> {
        crate::node::ipc::write_frame(&mut self.stream, &Opening::Daemon(request).to_bytes())
            .await?;
        self.next()
            .await?
            .ok_or(Error::Ipc(crate::error::IpcHandshake::ClosedBeforeHello))
    }

    /// The next frame the daemon sends, or `None` once it closes the connection.
    ///
    /// # Errors
    /// If the connection fails or the frame is malformed.
    pub async fn next(&mut self) -> Result<Option<DaemonFrame>> {
        match crate::node::ipc::read_frame(&mut self.stream).await? {
            Some(b) => DaemonFrame::from_bytes(&b).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeName {
        NodeName::parse(s).unwrap()
    }

    #[test]
    fn a_node_name_is_folded_and_checked() {
        assert_eq!(n("Claude-Mac").as_str(), "claude-mac");
        assert_eq!(n("a.b_c-9").as_str(), "a.b_c-9");
        for bad in [
            "",
            ".daemon",
            ".x",
            "nodes",
            "NODES",
            "a/b",
            "a b",
            "é",
            &"x".repeat(65),
        ] {
            assert!(NodeName::parse(bad).is_err(), "{bad:?} was taken");
        }
        assert!(NodeName::parse(&"x".repeat(64)).is_ok());
    }

    fn info(name: &str, state: NodeState) -> NodeInfo {
        NodeInfo {
            name: n(name),
            state,
            fingerprint: Some([7u8; 32]),
            implicit: true,
            keep: false,
        }
    }

    #[test]
    fn every_opening_round_trips() {
        let all = [
            Opening::Use(UseNode {
                node: n("alice"),
                attach: AttachMode::Hold,
                passphrase: Some(Zeroizing::new("pw".into())),
                anchors: vec!["anchor@1.2.3.4:5".into()],
            }),
            Opening::Use(UseNode {
                node: n("alice"),
                attach: AttachMode::No,
                passphrase: None,
                anchors: vec![],
            }),
            // An empty passphrase is a passphrase, not an absent one.
            Opening::Use(UseNode {
                node: n("bob"),
                attach: AttachMode::Hold,
                passphrase: Some(Zeroizing::new(String::new())),
                anchors: vec![],
            }),
            Opening::Daemon(DaemonRequest::Nodes),
            Opening::Daemon(DaemonRequest::Attach {
                node: n("alice"),
                passphrase: Some(Zeroizing::new("pw".into())),
                keep: Some(KeepSource::File("/k/pass".into())),
                rooms: vec![Zeroizing::new("r1".into()), Zeroizing::new("r2".into())],
                anchors: vec!["a".into()],
            }),
            Opening::Daemon(DaemonRequest::Attach {
                node: n("alice"),
                passphrase: None,
                keep: Some(KeepSource::None),
                rooms: vec![],
                anchors: vec![],
            }),
            Opening::Daemon(DaemonRequest::Attach {
                node: n("alice"),
                passphrase: None,
                keep: None,
                rooms: vec![],
                anchors: vec![],
            }),
            Opening::Daemon(DaemonRequest::Detach { node: n("alice") }),
            Opening::Daemon(DaemonRequest::SessionEnd {
                node: n("alice"),
                session: "s-1".into(),
            }),
            Opening::Daemon(DaemonRequest::Status),
            Opening::Daemon(DaemonRequest::Metrics),
            Opening::Daemon(DaemonRequest::Subscribe),
            Opening::Daemon(DaemonRequest::Stop),
        ];
        for o in all {
            assert_eq!(Opening::from_bytes(&o.to_bytes()).unwrap(), o);
        }
    }

    #[test]
    fn every_daemon_frame_round_trips() {
        let refusals = [
            Refusal::NotAttached { node: n("a") },
            Refusal::NoSuchNode { node: n("a") },
            Refusal::WrongPassphrase { node: n("a") },
            Refusal::NoIdentity { node: n("a") },
            Refusal::BadName {
                given: "A/B".into(),
                why: "slash".into(),
            },
            Refusal::Failed {
                node: n("a"),
                why: "disk".into(),
            },
            Refusal::Stopping,
            Refusal::NodeInUse { node: n("a") },
        ];
        let mut all = vec![
            DaemonFrame::Hello {
                protocol: crate::node::ipc::PROTOCOL_VERSION,
                version: "0.3.0".into(),
                pid: 42,
                attached: vec![
                    info("a", NodeState::Attached),
                    info("b", NodeState::Attaching),
                ],
            },
            DaemonFrame::Using {
                node: n("a"),
                me: None,
            },
            DaemonFrame::Using {
                node: n("a"),
                me: Some([1u8; 32]),
            },
            DaemonFrame::Nodes(vec![
                info("a", NodeState::Detached),
                info("b", NodeState::Detaching),
            ]),
            DaemonFrame::Attached(info("a", NodeState::Attached)),
            DaemonFrame::Ok,
            DaemonFrame::SessionEnded {
                was_registered: true,
                detached: false,
            },
            DaemonFrame::Status(DaemonStatus {
                version: "0.3.0".into(),
                pid: 7,
                listen: "0.0.0.0:4433".into(),
                nodes: vec![info("a", NodeState::Attached)],
                panics: 1,
            }),
            DaemonFrame::Metrics("vox_up{node=\"a\"} 1\n".into()),
            DaemonFrame::Event(DaemonEvent::Attached {
                node: n("a"),
                fingerprint: None,
            }),
        ];
        for cause in [
            DetachCause::Requested,
            DetachCause::LastHolder,
            DetachCause::DaemonStopping,
            DetachCause::Panicked("boom".into()),
            DetachCause::Stopped,
        ] {
            all.push(DaemonFrame::Event(DaemonEvent::Detached {
                node: n("a"),
                cause,
            }));
        }
        all.extend(refusals.into_iter().map(DaemonFrame::Refused));
        for f in all {
            assert_eq!(DaemonFrame::from_bytes(&f.to_bytes()).unwrap(), f);
        }
    }

    /// A node-level hello, as a daemon of protocol 8 and before sent, is not a daemon frame: a
    /// client never mistakes an older daemon for this one.
    #[test]
    fn an_older_hello_is_not_a_daemon_hello() {
        let old = crate::node::ipc::Frame::Hello {
            protocol: 8,
            me: None,
        }
        .to_bytes();
        assert!(DaemonFrame::from_bytes(&old).is_err());
    }

    /// The TUI's room requests (C-7) and the detached answer round-trip at the node level.
    #[test]
    fn the_node_level_additions_round_trip() {
        use crate::node::ipc::{Frame, Request};
        for r in [
            Request::OpenRoom {
                channel_id: [3u8; 32],
                passphrase: "room pass".into(),
            },
            Request::CloseRoom {
                channel_id: [3u8; 32],
            },
        ] {
            assert_eq!(Request::from_bytes(&r.to_bytes()).unwrap(), r);
        }
        let f = Frame::NodeDetached { node: n("alice") };
        assert_eq!(Frame::from_bytes(&f.to_bytes()).unwrap(), f);
    }

    /// No name the layout refuses crosses the wire: a frame carrying one is malformed.
    #[test]
    fn a_bad_name_on_the_wire_is_malformed() {
        let mut e = Encoder::new();
        e.array(2).uint(T_REQ_DETACH).text("nodes");
        assert!(Opening::from_bytes(&e.finish()).is_err());
    }
}
