//! The TUI's [`CoreHandle`] as a **client of the account's daemon** (ADR-026 S-4, ADR-015 1.2,
//! 9.1): it holds no node of its own and no node lock.
//!
//! [`DaemonCore`] acts as one node, named once per connection with a `Use` (C-2). It **projects**
//! what the daemon says of that node into the TUI's [`ViewModel`] and maps each UI [`Command`] onto
//! a request, blocking the (synchronous, crossterm-owning) UI thread on the daemon's answer.
//! UI-local state that is not the node's business lives here: which room is on screen, and unread
//! counts (driven by the node's ordered events).
//!
//! - **What is drawn** comes from a [`NodeSnapshot`] (rooms, members, consents, shares, keyring,
//!   connected peers, this node's tunnels), asked again when an event says something changed and
//!   once a second besides; and from the room on screen, read in pages once and then extended from
//!   its newest row as events say rows arrived (`Timeline`), so a frame never costs a room's
//!   whole history.
//! - **Events** come on two connections of their own, read by tasks on the runtime: the node's
//!   (a subscribed `Use` of the same node), and the daemon's (attach and detach of every node,
//!   C-4), which the header's node list is kept from.
//! - **There is no lock** (N-2): a node takes its passphrase once, when it attaches. A node that
//!   is attached is used at once; one that is not asks for its passphrase in the masked prompt and
//!   is attached with it ([`Command::Attach`]). A node the daemon detaches says so, and asks again.
//!   An identity is made here, in the client, and then attached (C-5).
//!
//! Secrets cross once, inward: a [`SecretString`] from a masked prompt goes into the `Use` or the
//! request in a zeroizing buffer and is dropped. Every outcome maps to the closed
//! [`CommandStatus`] / [`UiError`] set where the daemon's answer names a [`Fault`]; any other
//! answer is the daemon's own sentence for a person, which carries no plaintext or key.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use vox_core::hash::Digest32;
use vox_core::node::api::{Fault, MessageRow, NodeEvent};
use vox_core::node::daemonipc::{
    AttachMode, DaemonClient, DaemonEvent, DaemonFrame, DaemonRequest, DetachCause, Refusal,
    UseNode,
};
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::{b32_decode, b32_encode};
use vox_core::node::paths::{Account, NodeName};
use vox_core::node::snapshot::{NodeSnapshot, OpenRoomSnap};
use zeroize::Zeroizing;

use crate::app::CoreHandle;
use crate::viewmodel::{
    ChannelSummary, ChannelView, Command, CommandStatus, ImageView, MemberView, MessageView,
    NoticeView, QuoteView, Reachability, SyncStatus, Trust, UiError, ViewModel,
};
use vox_agentcomms::attention::{group, RoomGroup};

/// How often the snapshot is asked again when no event has said anything changed: connections,
/// tunnels and their last moved byte change without a room event.
const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

/// What one check of a pulled image found: its announcement, and where it stands.
type ImageCheck = (Digest32, crate::viewmodel::ImageState);

/// The largest image file the TUI hashes and draws (ADR-028 F-11): a bigger one is a file, not a
/// picture to show inline.
const MAX_DRAWN_BYTES: u64 = 64 * 1024 * 1024;

/// How much of a quoted message a reply shows: its first line, to this many characters.
const QUOTE_CHARS: usize = 80;

/// How the TUI takes its node (ADR-026 L-2, S-4; the decider's ruling of 2026-10-03): it holds it
/// implicitly, so quitting or SIGHUP drops only its hold, and a node it was the last holder of
/// detaches. A node attached by hand or with `--keep` stays attached.
const HOW_THE_TUI_ATTACHES: AttachMode = AttachMode::Hold;

/// What the event tasks tell the UI thread.
enum Ev {
    /// A node event of the node this TUI acts as.
    Node(NodeEvent),
    /// Events were dropped for this client: everything is read again.
    Lagged,
    /// The node this TUI acts as detached (L-3).
    Detached,
    /// A daemon event: some node attached or detached.
    Daemon(DaemonEvent),
    /// The daemon closed its connection: it stopped.
    DaemonGone,
}

/// The node this TUI is acting as, once it is attached.
struct Conn {
    /// Requests and their answers. Holds the node while it is open (L-3, L-7).
    client: IpcClient,
    /// The node's event stream.
    events: tokio::task::JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.events.abort();
    }
}

/// How often the TUI asks whether the daemon's `.vox` proxy runs: it changes only when the
/// daemon starts or its port is taken, so not with every snapshot.
const PROXY_EVERY: Duration = Duration::from_secs(5);

/// The TUI's binding to the daemon.
pub struct DaemonCore {
    rt: tokio::runtime::Handle,
    account: Account,
    /// The node this TUI acts as: the one whose rooms are on screen.
    node: NodeName,
    /// The node's connection, once attached.
    conn: Option<Conn>,
    /// Whether the node has an identity on disk.
    has_identity: bool,
    /// Anchor specs (`--anchor`) a node this TUI attaches is attached with.
    anchors: Vec<String>,
    /// The nodes attached to the daemon now, by name (the header's list).
    attached: Vec<String>,
    /// Every node on this machine's disk, by name, read with each snapshot (ADR-028 W-1, #511).
    on_disk: Vec<String>,
    tx: mpsc::Sender<Ev>,
    rx: mpsc::Receiver<Ev>,
    /// The daemon's event task.
    daemon_events: tokio::task::JoinHandle<()>,
    snapshot: NodeSnapshot,
    /// When the snapshot was last asked for; `None` asks now.
    asked: Option<Instant>,
    /// Whether the daemon's `.vox` proxy runs, and where, as last asked: the Shared pane's
    /// `proxy configured` fact (ADR-028 S-3). `None` until asked.
    proxy: Option<Result<std::net::SocketAddr, String>>,
    /// When the proxy was last asked about.
    proxy_asked: Option<Instant>,
    /// The room on screen (drives `ViewModel::active` and unread resets).
    active: Option<Digest32>,
    /// The Session the room's timeline shows: its room, node and session id (ADR-029 CL-2).
    shown_session: Option<(Digest32, Digest32, String)>,
    /// Its lines, as last read, for a member with drive (SC-1).
    session_lines: Vec<crate::viewmodel::SessionLineView>,
    /// Its entries are to be read again on the next frame: it was just shown or driven, or the
    /// node said it has news (`NodeEvent::SessionEntry`).
    session_stale: bool,
    /// Per room, the approvals and questions waiting on this node in Sessions it may drive there
    /// (ADR-029 CL-2): what puts a room under needs you.
    waiting: BTreeMap<Digest32, usize>,
    /// The Sessions with one waiting: room, node and session id.
    waiting_sessions: BTreeSet<(Digest32, Digest32, String)>,
    /// They are to be counted again: the node said a Session has news, or one was driven.
    waiting_stale: bool,
    /// The Sessions this node may drive, room by room, when they were last counted: a Session
    /// opened, ended or given drive since is counted again.
    waiting_of: Vec<(Digest32, Vec<(Digest32, String)>)>,
    /// Unread per room off screen, at three levels (ADR-028 R-8, #484).
    unread: BTreeMap<Digest32, RoomUnread>,
    /// Rooms whose unread was counted, when the TUI first saw them open, from what the node
    /// recorded as read (`Request::Unread`): before that, only the node's events count.
    seeded: BTreeSet<Digest32>,
    /// Rooms off screen that rows have arrived in since the last frame, and how many rows: each
    /// is a notification to raise, once per room (ADR-028 R-10).
    arrived: BTreeMap<Digest32, usize>,
    /// Rooms already notified and not looked at since: a room raises one notification until it
    /// comes on screen, however many messages follow (R-10, grouped by room).
    notified: BTreeSet<Digest32>,
    /// Where this node's notifications go (`notify::command`), or `None` for the terminal; and
    /// whether they are off (`notify = off`). Read from the node's settings when the TUI opens.
    notify_to: Option<std::ffi::OsString>,
    notify_off: bool,
    /// The most recent public notice: a room link, a join, a trust grant, a detach.
    notice: Option<String>,
    /// The newest join seen in a room this node holds open (ADR-028 K-7): the room, the newcomer,
    /// and the line it put in [`Self::notice`]. Said again as the room's consent grants say more
    /// members trust it, while nothing has replaced that line.
    joined: Option<(Digest32, Digest32, String)>,
    /// The names two rooms here share, each already said once (ADR-028 R-3).
    clashes_said: std::collections::BTreeSet<String>,
    /// The room on screen's rows, as read.
    timeline: Option<Timeline>,
    /// The messages already told to the node as shown (ADR-028 RR-1).
    marked: std::collections::BTreeSet<Digest32>,
    /// Image shares whose pulled copy has been checked off this thread, and what it came to
    /// (ADR-028 F-11): only a verified, decoded one is drawn.
    images: BTreeMap<Digest32, crate::viewmodel::ImageState>,
    /// Pull records already handed to a check: a copy is hashed once.
    checked: std::collections::BTreeSet<Digest32>,
    /// Where the checks say what they found.
    image_checks: (mpsc::Sender<ImageCheck>, mpsc::Receiver<ImageCheck>),
    /// The last time the node did not take what the room on screen showed, and what the room was
    /// then: it is not asked again until the room has changed and [`MARK_RETRY`] has passed, or
    /// ever, for a room that is over.
    mark_refused: Option<MarkRefused>,
    /// This node's decision record as last read, and when (ADR-028 D-3).
    decisions: (Option<Instant>, Vec<vox_core::node::decisions::Event>),
    /// What listens on this machine, as the share flow last listed it (ADR-028 S-4).
    listening: Vec<vox_core::node::probe::Listening>,
    /// The service the share flow is about to offer, with what was said of it.
    serve_preview: Option<crate::viewmodel::ServePreview>,
    /// Why the TUI cannot go on: the daemon stopped.
    ended: Option<String>,
    /// Cancelled when the TUI is asked to stop (SIGHUP, SIGTERM): a wait on the daemon is given up
    /// then, so a stop is never held behind an answer (ADR-026 S-4).
    stop: tokio_util::sync::CancellationToken,
}

/// **A room's unread, at three levels** (ADR-028 R-8, #484), for a room off screen.
///
/// Events say only how many rows came (`pending`); the rows since `cursor` are then read and each
/// is counted as addressed to this node, new, or coordination ([`vox_agentcomms::attention::unread_level`]).
/// With no cursor yet (a room not opened this session), only the newest `pending` rows count: the
/// room's history is not unread.
#[derive(Debug, Default)]
struct RoomUnread {
    to_you: usize,
    new: usize,
    coordination: usize,
    /// The newest row counted or seen, by entry hash.
    cursor: Option<Digest32>,
    /// Rows the events announced and not yet read and counted.
    pending: usize,
}

/// The room on screen's rows, in the room's order, and what they were projected as.
///
/// **A frame costs what changed, not the room's history** (V210-120). The room is read whole once
/// when it comes on screen; after that, an event that says rows arrived reads only the rows that
/// arrived since the newest one held (`Read { since }`, a feed by arrival) and appends them. A row
/// that took its place above rows already shown (`late`), or a cursor the node no longer knows,
/// reads the room whole again. A row whose body was owed (V030-10) is replaced in place when its
/// body arrives, since it then arrives by the feed.
struct Timeline {
    channel_id: Digest32,
    rows: Vec<MessageRow>,
    /// The row that arrived last, the feed's cursor.
    cursor: Option<Digest32>,
    /// Rows have arrived since the last read.
    stale: bool,
    /// The projection, and what it was projected with.
    projected: Option<Projected>,
    /// The machine each member's newest `hello` here says it runs on (ADR-020 §4.9b), and when
    /// that hello was posted: folded as rows arrive, so a frame never reads the room for it.
    machines: std::collections::HashMap<Digest32, (u64, String)>,
}

/// Fold `row` into `machines` if it is a `hello` that says which machine it runs on, newer than
/// the one held for its author.
fn note_machine(
    machines: &mut std::collections::HashMap<Digest32, (u64, String)>,
    row: &MessageRow,
) {
    if !row.text.starts_with('{') || !row.text.contains(vox_agentcomms::envelope::HELLO) {
        return;
    }
    let Ok(e) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
        return;
    };
    if e.kind != vox_agentcomms::envelope::HELLO {
        return;
    }
    let Some(said) = crate::platform::claim(&e.data) else {
        return;
    };
    if machines
        .get(&row.author)
        .is_none_or(|(at, _)| *at <= row.created_millis)
    {
        machines.insert(row.author, (row.created_millis, said));
    }
}

/// How many of the node's decisions, newest first, the TUI's decision screen holds.
const DECISIONS_SHOWN: usize = 500;
/// The least time between two asks to record what a room showed, after the node did not take one.
const MARK_RETRY: Duration = Duration::from_secs(3);

/// A [`DaemonCore::shown`] the node did not take.
struct MarkRefused {
    channel_id: Digest32,
    at: Instant,
    /// The room as it was then: its rows and the node's detail of it.
    room: (usize, Option<OpenRoomSnap>),
    /// The room is over (ended, or left): nothing it shows is recorded again.
    over: bool,
}

/// What the node says of this node's own recent messages in the room on screen (ADR-028 R-6).
#[derive(Clone, Default, PartialEq, Eq)]
struct Own {
    /// `(entry, readers)`, from the read records the node can open.
    read_by: Vec<(Digest32, Vec<Digest32>)>,
    /// `(entry, how many other members' nodes hold it)`.
    held: Vec<(Digest32, u64)>,
    /// `(entry, members)` who pulled this node's share whole (ADR-028 F-7).
    pulled_by: Vec<(Digest32, Vec<Digest32>)>,
    /// How many other members the room has.
    others: u64,
}

struct Projected {
    /// How many images were verified when this was projected: one more projects again.
    verified: usize,
    me: Option<Digest32>,
    trusted: Vec<(Digest32, String)>,
    own: Own,
    /// The names the rows' addresses were written readable with (ADR-028 S-1a).
    names: vox_core::node::resolver::VoxResolver,
    len: usize,
    rows: std::sync::Arc<Vec<MessageView>>,
    /// Where each row is, by entry hash: in `rows`, and in the rows held. What changes with
    /// [`Own`] is projected again for its rows alone.
    at: std::collections::HashMap<Digest32, (usize, usize)>,
}

impl std::fmt::Debug for DaemonCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonCore")
            .field("node", &self.node.as_str())
            .field("attached", &self.conn.is_some())
            .finish_non_exhaustive()
    }
}

/// Said under a message this node sent that no other member's node is known to hold (ADR-028 R-6).
pub const ONLY_HERE: &str = vox_text::read::ONLY_HERE;

/// Short display form of a fingerprint (first 8 hex chars).
#[must_use]
pub fn short_id(id: &Digest32) -> String {
    let mut s = String::with_capacity(8);
    for b in &id[..4] {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Wait for `work` on `rt`, unless `stop` is cancelled first: `None` then.
fn until_stopped<F: std::future::Future>(
    rt: &tokio::runtime::Handle,
    stop: &tokio_util::sync::CancellationToken,
    work: F,
) -> Option<F::Output> {
    rt.block_on(async {
        tokio::select! {
            out = work => Some(out),
            () = stop.cancelled() => None,
        }
    })
}

/// Why a request to the daemon did not get the node's answer.
enum Lost {
    /// The node detached (L-3): it is not retried, and the TUI asks for it again.
    Detached,
    /// The daemon is gone, or the connection broke: what happened.
    Gone(String),
}

impl DaemonCore {
    /// Bind to `node` on `account`'s daemon, which must be running (see `app::run_live`). An
    /// attached node is used at once; one that is not waits for its passphrase.
    ///
    /// # Errors
    /// If the daemon does not answer, or its event stream cannot be opened.
    pub fn new(
        rt: tokio::runtime::Handle,
        account: Account,
        node: NodeName,
        anchors: Vec<String>,
        stop: tokio_util::sync::CancellationToken,
    ) -> Result<Self, crate::app::AppError> {
        let (tx, rx) = mpsc::channel();
        let socket = account.socket();
        let (attached, daemon_events) = rt.block_on(async {
            let mut daemon = DaemonClient::open(&socket).await?;
            let attached: Vec<String> = daemon
                .attached
                .iter()
                .map(|n| n.name.as_str().to_owned())
                .collect();
            match daemon.request(DaemonRequest::Subscribe).await? {
                DaemonFrame::Ok => {}
                other => {
                    return Err(crate::app::AppError::Usage(format!(
                        "the daemon would not send its events: {other:?}"
                    )))
                }
            }
            let tx = tx.clone();
            let task = tokio::spawn(async move {
                loop {
                    match daemon.next().await {
                        Ok(Some(DaemonFrame::Event(ev))) => {
                            if tx.send(Ev::Daemon(ev)).is_err() {
                                return;
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) | Err(_) => {
                            let _ = tx.send(Ev::DaemonGone);
                            return;
                        }
                    }
                }
            });
            Ok::<_, crate::app::AppError>((attached, task))
        })?;
        let (notify_to, notify_off) = account
            .node_paths(&node)
            .map(|p| (crate::notify::command(&p), crate::notify::disabled(&p)))
            .unwrap_or((None, false));
        let mut core = Self {
            has_identity: account.nodes_on_disk().contains(&node),
            anchors,
            rt,
            account,
            node,
            conn: None,
            attached,
            on_disk: Vec::new(),
            tx,
            rx,
            daemon_events,
            snapshot: NodeSnapshot::default(),
            asked: None,
            proxy: None,
            proxy_asked: None,
            active: None,
            unread: BTreeMap::new(),
            seeded: BTreeSet::new(),
            shown_session: None,
            session_lines: Vec::new(),
            session_stale: true,
            waiting: BTreeMap::new(),
            waiting_sessions: BTreeSet::new(),
            waiting_stale: true,
            waiting_of: Vec::new(),
            arrived: BTreeMap::new(),
            notified: BTreeSet::new(),
            notify_to,
            notify_off,
            notice: None,
            joined: None,
            clashes_said: std::collections::BTreeSet::new(),
            timeline: None,
            marked: std::collections::BTreeSet::new(),
            images: BTreeMap::new(),
            checked: std::collections::BTreeSet::new(),
            image_checks: mpsc::channel(),
            mark_refused: None,
            decisions: (None, Vec::new()),
            listening: Vec::new(),
            serve_preview: None,
            ended: None,
            stop,
        };
        if core.attached.iter().any(|n| n == core.node.as_str()) {
            // Attached already: it took its passphrase when it attached, and is used as it is.
            let status = core.attach(None);
            if !matches!(status, CommandStatus::Done) {
                core.notice = Some(status.message());
            }
        }
        Ok(core)
    }

    /// The node this TUI acts as.
    #[must_use]
    pub fn node(&self) -> &NodeName {
        &self.node
    }

    /// Take the node with a `Use` that holds it (L-2), attaching it with `passphrase` if it is
    /// not attached, and start its event stream.
    fn attach(&mut self, passphrase: Option<Zeroizing<String>>) -> CommandStatus {
        let socket = self.account.socket();
        let using = |passphrase| UseNode {
            node: self.node.clone(),
            attach: HOW_THE_TUI_ATTACHES,
            passphrase,
            anchors: self.anchors.clone(),
        };
        let first = using(passphrase);
        let tx = self.tx.clone();
        // The event stream does not hold the node: the request connection does, and a node is
        // let go when that one closes, however the TUI ends.
        let events_use = UseNode {
            attach: AttachMode::No,
            ..using(None)
        };
        let opened = until_stopped(&self.rt, &self.stop, async {
            let client = match IpcClient::open_node(&socket, first).await {
                Ok(Ok(c)) => c,
                Ok(Err(refusal)) => return Ok(Err(refusal)),
                Err(e) => return Err(e),
            };
            // The node's events, on a connection of their own: a subscribed connection serves no
            // more requests. The node is attached by now, so this one needs no passphrase.
            let mut events = match IpcClient::open_node(&socket, events_use).await? {
                Ok(c) => c,
                Err(refusal) => return Ok(Err(refusal)),
            };
            events.subscribe().await?;
            let task = tokio::spawn(async move {
                loop {
                    let ev = match events.next().await {
                        Ok(Some(Frame::Event(ev))) => Ev::Node(ev),
                        Ok(Some(Frame::Lagged { .. })) => Ev::Lagged,
                        Ok(Some(Frame::NodeDetached { .. })) => Ev::Detached,
                        Ok(Some(_)) => continue,
                        Ok(None) | Err(_) => Ev::DaemonGone,
                    };
                    let last = matches!(ev, Ev::Detached | Ev::DaemonGone);
                    if tx.send(ev).is_err() || last {
                        return;
                    }
                }
            });
            Ok(Ok(Conn {
                client,
                events: task,
            }))
        });
        let Some(opened) = opened else {
            return CommandStatus::Said("stopping".into());
        };
        match opened {
            Ok(Ok(conn)) => {
                // What attaching the node said (a skipped anchors line, carrying on with no
                // anchor), in the TUI's notice line: the daemon writes it only to its log (R23).
                let notes = conn.client.attach_notes().to_vec();
                self.conn = Some(conn);
                self.has_identity = true;
                self.asked = None;
                self.timeline = None;
                if notes.is_empty() {
                    return CommandStatus::Done;
                }
                let said = notes.join("; ");
                self.notice = Some(said.clone());
                // Also as the attach's own answer: the status line shows a command's answer over
                // the notice line, so a bare "done" hid what the attach said.
                CommandStatus::Said(said)
            }
            Ok(Err(refusal)) => refused(&refusal),
            Err(e) => CommandStatus::Said(format!("the daemon could not be reached: {e}")),
        }
    }

    /// Make the node's identity here, in the client (ADR-026 C-5), then attach it with the same
    /// passphrase.
    fn create_identity(
        &mut self,
        passphrase: &SecretString,
        waiting: &mut dyn FnMut(),
    ) -> CommandStatus {
        let paths = match self.account.node_paths(&self.node) {
            Ok(p) => p,
            Err(e) => return fault_status(vox_core::node::actor::fault_of(&e)),
        };
        let pass = Zeroizing::new(passphrase.expose_secret().to_owned());
        // Whether it had one when this TUI looked (at start, or at `:node`): one there now that was
        // not then was made by another vox meanwhile (V210-100).
        let had = self.has_identity;
        let (said_tx, said_rx) = mpsc::channel::<()>();
        let made = {
            let pass = pass.clone();
            self.rt.spawn_blocking(move || {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let waiting = move || {
                    let _ = said_tx.send(());
                };
                vox_core::node::profile::Profile::create_noting(
                    paths,
                    pass.as_bytes(),
                    now,
                    vox_core::atrest::sek::Argon2Profile::default(),
                    &waiting,
                )
                // Dropped here: the node directory's lock goes with it, for the daemon to take.
                .map(drop)
            })
        };
        tokio::pin!(made);
        let made = loop {
            let tick = self.rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(100), &mut made).await
            });
            if said_rx.try_recv().is_ok() {
                waiting();
            }
            if let Ok(done) = tick {
                break done;
            }
            if self.stop.is_cancelled() {
                return CommandStatus::Said("stopping".into());
            }
        };
        match made {
            Ok(Ok(())) => self.attach(Some(pass)),
            // **Another vox made it first** (V210-100): this node had no identity when the TUI
            // asked, so one that exists now was made elsewhere.
            Ok(Err(vox_core::error::Error::Profile(_))) if !had => {
                // It has one now: what is left is to attach it with its passphrase.
                self.has_identity = true;
                CommandStatus::Failed(UiError::IdentityMadeElsewhere)
            }
            Ok(Err(vox_core::error::Error::Profile(_))) => fault_status(Fault::IdentityExists),
            Ok(Err(vox_core::error::Error::ProfileBusy)) => fault_status(Fault::ProfileBusy),
            // The identity file, the store, or a directory: in the fault's own words.
            Ok(Err(e)) => fault_status(vox_core::node::actor::fault_of(&e)),
            Err(_) => CommandStatus::Failed(UiError::Internal),
        }
    }

    /// Send `request` on the node's connection.
    fn request(&mut self, request: &Request) -> Result<Frame, Lost> {
        let Some(conn) = self.conn.as_mut() else {
            return Err(Lost::Detached);
        };
        let Some(answer) = until_stopped(&self.rt, &self.stop, conn.client.request(request)) else {
            return Err(Lost::Gone("stopping".into()));
        };
        match answer {
            Ok(Frame::NodeDetached { .. }) => {
                self.detached();
                Err(Lost::Detached)
            }
            Ok(frame) => Ok(frame),
            Err(e) => {
                let why = format!("the vox daemon stopped answering: {e}");
                self.ended.get_or_insert(why.clone());
                Err(Lost::Gone(why))
            }
        }
    }

    /// Send `request`, and say how it went. A passphrase it carries is wiped once it is sent.
    fn send(&mut self, mut request: Request) -> CommandStatus {
        let answer = self.request(&request);
        wipe(&mut request);
        match answer {
            Ok(Frame::Ok | Frame::Bound { .. } | Frame::OwnRetention { .. }) => {
                self.asked = None;
                CommandStatus::Done
            }
            // **The link is the answer** (#406): set only as a notice, it sat under the "done" this
            // command's own status puts over every notice, and `:link` showed a person nothing to
            // give anyone. A room link is no secret: the passphrase travels apart.
            Ok(Frame::Link { url, .. }) => {
                // Add to room (ADR-028 W-5): the link, and that its passphrase goes another way.
                let said = format!("room link: {url} — send its passphrase another way");
                self.notice = Some(said.clone());
                CommandStatus::Said(said)
            }
            Ok(Frame::Error { reason }) => failed(&reason),
            Ok(_) => CommandStatus::Failed(UiError::Internal),
            Err(lost) => lost_status(lost),
        }
    }

    /// The node detached: forget its connection and what was drawn of it.
    fn detached(&mut self) {
        self.conn = None;
        self.active = None;
        self.timeline = None;
        self.snapshot = NodeSnapshot::default();
        self.notice = Some(format!(
            "node {} was detached — give its passphrase to attach it again",
            self.node
        ));
    }

    /// **One notification per room, naming who wrote, never what** (ADR-028 R-10): for each room
    /// off screen that rows arrived in, and that has not been notified since it was last on screen,
    /// read who wrote the rows that arrived and raise one notification. The message text is never
    /// read into it: a notification shows on a locked screen and to whoever stands near it.
    fn notify_arrivals(&mut self) {
        let arrived = std::mem::take(&mut self.arrived);
        if self.notify_off {
            return;
        }
        for (cid, n) in arrived {
            if self.notified.contains(&cid) || self.active == Some(cid) {
                continue;
            }
            let Some(conn) = self.conn.as_mut() else {
                return;
            };
            let Some(Ok(Frame::Rows { mut rows })) =
                until_stopped(&self.rt, &self.stop, conn.client.read_rows(cid, None))
            else {
                continue;
            };
            // The rows that arrived: the newest `n` by arrival, from a member other than this node.
            rows.retain(|r| !r.owed);
            rows.sort_by_key(|r| std::cmp::Reverse(r.arrival));
            let me = self.snapshot.me;
            let mut from: Vec<String> = Vec::new();
            for r in rows.iter().take(n).filter(|r| Some(r.author) != me) {
                let name = self.member_name(&r.author);
                if !from.contains(&name) {
                    from.push(name);
                }
            }
            if from.is_empty() {
                continue;
            }
            let room = self
                .snapshot
                .rooms
                .iter()
                .find(|r| r.channel_id == cid)
                .and_then(|r| r.name.clone())
                .unwrap_or_else(|| vox_core::node::link::b32_encode(&cid)[..12].to_owned());
            let note = crate::notify::Note {
                title: format!("Vox: {room}"),
                body: format!(
                    "new message{} from {}",
                    if n == 1 { "" } else { "s" },
                    from.join(", ")
                ),
            };
            crate::notify::raise_from_tui(&note, self.notify_to.as_deref());
            self.notified.insert(cid);
        }
    }

    /// Fold the events waiting into UI-local state.
    fn drain_events(&mut self) {
        self.drain_queued();
        self.notify_arrivals();
    }

    fn drain_queued(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Ev::Node(ev) => self.on_node_event(ev),
                Ev::Lagged => {
                    self.asked = None;
                    // Events were lost: a Session's news among them, maybe.
                    self.session_stale = true;
                    self.waiting_stale = true;
                    if let Some(t) = self.timeline.as_mut() {
                        t.stale = true;
                    }
                }
                Ev::Detached => {
                    if self.conn.is_some() {
                        self.detached();
                    }
                }
                Ev::Daemon(DaemonEvent::Attached { node, .. }) => {
                    if !self.attached.iter().any(|n| n == node.as_str()) {
                        self.attached.push(node.as_str().to_owned());
                        self.attached.sort();
                    }
                }
                Ev::Daemon(DaemonEvent::Detached { node, cause }) => {
                    self.attached.retain(|n| n != node.as_str());
                    if node == self.node {
                        if self.conn.is_some() {
                            self.detached();
                        }
                        if let DetachCause::Panicked(_) = cause {
                            self.notice = Some(format!(
                                "node {} stopped: its actor failed, and the daemon detached it",
                                self.node
                            ));
                        }
                    }
                }
                Ev::DaemonGone => {
                    self.ended
                        .get_or_insert_with(|| "the vox daemon stopped".to_owned());
                }
            }
        }
    }

    fn on_node_event(&mut self, ev: NodeEvent) {
        // Most events change what is drawn: ask for the snapshot again on the next frame.
        self.asked = None;
        let rows_in = |me: &mut Self, channel_id: Digest32, n: usize| {
            if me.active == Some(channel_id) {
                if let Some(t) = me.timeline.as_mut() {
                    t.stale = true;
                }
            } else if n > 0 {
                me.unread.entry(channel_id).or_default().pending += n;
                *me.arrived.entry(channel_id).or_insert(0) += n;
            }
        };
        match ev {
            NodeEvent::NewEntry { channel_id, .. } => rows_in(self, channel_id, 1),
            // A Session entry is sealed apart from the room's log: this is the one word that one
            // arrived (ADR-029 SC-1, CL-2). The Session on screen and the waiting count are read
            // again; nothing polls for them.
            NodeEvent::SessionEntry { channel_id, .. } => {
                if self
                    .shown_session
                    .as_ref()
                    .is_some_and(|(room, _, _)| *room == channel_id)
                {
                    self.session_stale = true;
                }
                self.waiting_stale = true;
            }
            NodeEvent::Shutdown => self.active = None,
            NodeEvent::ChannelClosed { channel_id } => {
                if self.active == Some(channel_id) {
                    self.active = None;
                }
            }
            // The network events, surfaced as short public notices. A link, a fingerprint prefix
            // and a count are all public facts; nothing here can carry plaintext or key material
            // (ADR-015).
            NodeEvent::InviteLink { url, .. } => {
                self.notice = Some(format!(
                    "room link: {url} — send its passphrase another way"
                ));
            }
            NodeEvent::AddressNote { note, .. }
            | NodeEvent::NodeNote { note }
            | NodeEvent::NetworkChanged { summary: note } => {
                self.notice = Some(note);
            }
            NodeEvent::AddressWithheld { reason, .. } => {
                self.notice = Some(format!("no room link: {reason}"));
            }
            // **A join this node refused, or one that did not complete, is the operator's to
            // see** (#406): a refusal is security-relevant, and the TUI is the client a person
            // watches. The reason names the joiner and the step, never a passphrase (the node
            // words it so: `answering <joiner>: join proof-of-possession failed`).
            NodeEvent::JoinFailed { reason } => {
                self.notice = Some(format!("a join did not complete — {reason}"));
            }
            NodeEvent::Joined { responder, .. } => {
                self.notice = Some(format!("joined via {}", self.member_name(&responder)));
            }
            NodeEvent::PeerJoined { channel_id, peer } => self.say_joined(channel_id, peer),
            NodeEvent::Consented { target, .. } => {
                self.notice = Some(format!("you now trust {}", self.member_name(&target)));
            }
            NodeEvent::SenderKeyReceived {
                channel_id,
                peer,
                backfilled,
            } => {
                // **Counted here, and only here.** A key arriving renders what this node already
                // held as ciphertext — messages that were unreadable a moment ago and are new to
                // whoever is looking. `Synced.rendered` below counts rows a sync renders, which is
                // a disjoint set: a backfilled row was stored by an earlier sync that could not
                // render it, so it is counted once, here.
                rows_in(self, channel_id, backfilled as usize);
                self.notice = Some(if backfilled > 0 {
                    format!(
                        "{} trusts you — {backfilled} earlier message(s) now readable",
                        self.member_name(&peer)
                    )
                } else {
                    format!("{} trusts you", self.member_name(&peer))
                });
            }
            NodeEvent::Synced {
                channel_id,
                rendered,
                ..
            } => rows_in(self, channel_id, rendered as usize),
            _ => {}
        }
    }

    /// **A newcomer, and who trusts it** (ADR-028 K-7): a member in a room this node holds open
    /// that the snapshot before did not list is said as joined. Every member's TUI says it, not
    /// only the one that answered the join. And while that line stands, it is said again as the
    /// room's consent grants name more members trusting the newcomer.
    fn note_joins(&mut self, before: &NodeSnapshot) {
        let me = self.snapshot.me;
        let mut newcomer = None;
        for room in &self.snapshot.open {
            // A room just opened lists everyone already in it: none of them just joined.
            let Some(was) = before.open.iter().find(|o| o.channel_id == room.channel_id) else {
                continue;
            };
            if let Some(m) = room
                .members
                .iter()
                .rev()
                .find(|m| Some(**m) != me && !was.members.contains(m))
            {
                newcomer = Some((room.channel_id, *m));
            }
        }
        if let Some((room, peer)) = newcomer {
            self.say_joined(room, peer);
        } else if let Some((room, peer, said)) = self.joined.clone() {
            if self.notice.as_deref() == Some(said.as_str()) {
                self.say_joined(room, peer);
            }
        }
    }

    /// Say that `peer` joined `room`, and which members this node trusts trust it (K-7): from the
    /// consent grants on the room's log, never adding it to any keyring.
    fn say_joined(&mut self, room: Digest32, peer: Digest32) {
        let trusters: Vec<String> = self
            .snapshot
            .open
            .iter()
            .find(|o| o.channel_id == room)
            .and_then(|o| o.trusted_by.iter().find(|(m, _)| *m == peer))
            .map(|(_, by)| {
                self.snapshot
                    .trusted
                    .iter()
                    .filter(|(fp, _)| by.contains(fp))
                    .map(|(fp, _)| self.member_name(fp))
                    .collect()
            })
            .unwrap_or_default();
        let who = vox_text::offer::trusted_by(&trusters);
        // Trust is offered where it matters (ADR-028 K-5), with the one action used everywhere.
        let offer = if self.snapshot.trusted.iter().any(|(t, _)| *t == peer) {
            String::new()
        } else {
            format!(" · {}", crate::ident::trust_hint(&peer))
        };
        let line = format!("{} joined. {who}{offer}", self.member_name(&peer));
        self.notice = Some(line.clone());
        self.joined = Some((room, peer, line));
    }

    /// A member as the TUI names it: its keyring petname, else its fingerprint marked as not in
    /// the keyring (`crate::ident`, #198).
    fn member_name(&self, fp: &Digest32) -> String {
        crate::ident::member_name(&self.snapshot.trusted, fp)
    }

    /// Ask for the snapshot when an event said something changed, or a second has passed.
    fn refresh(&mut self) {
        if self.conn.is_none() {
            return;
        }
        if self.asked.is_some_and(|at| at.elapsed() < SNAPSHOT_EVERY) {
            return;
        }
        self.asked = Some(Instant::now());
        self.ask_proxy();
        self.on_disk = self
            .account
            .nodes_on_disk()
            .iter()
            .map(|n| n.as_str().to_owned())
            .collect();
        let body = vox_core::node::snapshot::request_body();
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let Some(answer) = until_stopped(&self.rt, &self.stop, conn.client.exchange(&body)) else {
            return;
        };
        match answer {
            Ok(reply) => match NodeSnapshot::from_bytes(&reply) {
                Ok(Some(s)) => {
                    let before = std::mem::replace(&mut self.snapshot, s);
                    self.note_joins(&before);
                    self.check_pulls();
                }
                Ok(None) => match Frame::from_bytes(&reply) {
                    Ok(Frame::NodeDetached { .. }) => self.detached(),
                    Ok(Frame::Error { reason }) => self.notice = Some(reason),
                    _ => {}
                },
                Err(e) => self.notice = Some(format!("the daemon's answer did not read: {e}")),
            },
            Err(e) => {
                self.ended
                    .get_or_insert(format!("the vox daemon stopped answering: {e}"));
            }
        }
    }

    /// Ask the daemon whether its `.vox` proxy runs, every [`PROXY_EVERY`], on a connection of
    /// its own that attaches nothing: the Shared pane's `proxy configured` fact.
    fn ask_proxy(&mut self) {
        if self
            .proxy_asked
            .is_some_and(|at| at.elapsed() < PROXY_EVERY)
        {
            return;
        }
        self.proxy_asked = Some(Instant::now());
        let at = vox_core::node::ipc::NodeSocket {
            path: self.account.socket(),
            using: UseNode {
                node: self.node.clone(),
                attach: AttachMode::No,
                passphrase: None,
                anchors: Vec::new(),
            },
            waiting: None,
        };
        let asked = until_stopped(&self.rt, &self.stop, vox_core::node::nameipc::proxy(&at));
        if let Some(asked) = asked {
            self.proxy = Some(asked.map_err(|e| match e {
                vox_core::error::Error::AppRefused(reason) => reason,
                other => other.to_string(),
            }));
        }
    }

    /// **Count what came to each room off screen, by level** (ADR-028 R-8, #484): read the rows
    /// since its cursor and count each as addressed to this node, new, or coordination. This
    /// node's own posts are not unread.
    fn count_unread(&mut self) {
        use vox_agentcomms::attention::{unread_level, UnreadLevel};
        let me = self.snapshot.me;
        let me_fp = me.map(|m| vox_core::node::link::b32_encode(&m));
        // **What was unread before the TUI opened** (ADR-028 R-8): each room, the first time it is
        // seen open off screen, is counted from the node's own record of what its person read.
        // Without it, a message that came while the TUI was closed was never counted at all.
        let unseeded: Vec<Digest32> = self
            .snapshot
            .open
            .iter()
            .map(|o| o.channel_id)
            .filter(|cid| !self.seeded.contains(cid) && Some(*cid) != self.active)
            .collect();
        for cid in unseeded {
            let Some(conn) = self.conn.as_mut() else {
                return;
            };
            let asked = until_stopped(
                &self.rt,
                &self.stop,
                conn.client.request(&Request::Unread { channel_id: cid }),
            );
            let Some(Ok(Frame::Rows { rows })) = asked else {
                continue;
            };
            self.seeded.insert(cid);
            let u = self.unread.entry(cid).or_default();
            for r in &rows {
                match unread_level(&r.text, me_fp.as_deref()) {
                    UnreadLevel::ToYou => u.to_you += 1,
                    UnreadLevel::New => u.new += 1,
                    UnreadLevel::Coordination => u.coordination += 1,
                }
            }
            if let Some(newest) = rows.last() {
                u.cursor = Some(newest.entry_hash);
            }
        }
        let due: Vec<Digest32> = self
            .unread
            .iter()
            .filter(|(cid, u)| {
                u.pending > 0
                    && Some(**cid) != self.active
                    && self.snapshot.open.iter().any(|o| o.channel_id == **cid)
            })
            .map(|(cid, _)| *cid)
            .collect();
        for cid in due {
            let Some(cursor) = self.unread.get(&cid).map(|u| u.cursor) else {
                continue;
            };
            let Some(conn) = self.conn.as_mut() else {
                return;
            };
            let read = until_stopped(&self.rt, &self.stop, conn.client.read_rows(cid, cursor));
            let Some(u) = self.unread.get_mut(&cid) else {
                continue;
            };
            let mut rows = match read {
                Some(Ok(Frame::Rows { rows })) => rows,
                // A cursor the node no longer knows (the row expired): counted from the newest
                // `pending` rows instead, on the next frame.
                Some(Ok(_)) if cursor.is_some() => {
                    u.cursor = None;
                    continue;
                }
                _ => continue,
            };
            rows.sort_by_key(|r| r.arrival);
            if cursor.is_none() {
                // A room not seen this session: only what the events announced is unread.
                let keep = u.pending.min(rows.len());
                rows.drain(..rows.len() - keep);
            }
            for r in rows.iter().filter(|r| Some(r.author) != me) {
                match unread_level(&r.text, me_fp.as_deref()) {
                    UnreadLevel::ToYou => u.to_you += 1,
                    UnreadLevel::New => u.new += 1,
                    UnreadLevel::Coordination => u.coordination += 1,
                }
            }
            if let Some(newest) = rows
                .iter()
                .filter(|r| !r.owed)
                .map(|r| r.entry_hash)
                .next_back()
            {
                u.cursor = Some(newest);
            }
            u.pending = 0;
        }
    }

    /// **Verify what this node pulled of the room on screen's image shares** (ADR-028 F-11): each
    /// pull record new here is handed once to a thread of its own, which hashes and decodes the
    /// copy ([`crate::images::verify_and_decode`]), so a large file never holds up a frame. The
    /// daemon checked it as it pulled; this checks the file that is there now, which is what is
    /// drawn. What the checks found is taken in here too.
    fn check_pulls(&mut self) {
        while let Ok((entry, state)) = self.image_checks.1.try_recv() {
            self.images.insert(entry, state);
        }
        let Some(t) = self.timeline.as_ref() else {
            return;
        };
        let Ok(paths) = self.account.node_paths(&self.node) else {
            return;
        };
        for p in vox_core::node::pulls::recorded(&paths) {
            if p.room != t.channel_id || self.checked.contains(&p.entry) {
                continue;
            }
            let Some(row) = t.rows.iter().find(|r| r.entry_hash == p.entry) else {
                continue;
            };
            self.checked.insert(p.entry);
            let Ok(e) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
                continue;
            };
            let (Some(sha), Some(size)) = (
                e.data.get("sha256").and_then(serde_json::Value::as_str),
                e.data.get("size").and_then(serde_json::Value::as_u64),
            ) else {
                continue;
            };
            if e.data.get("image").is_none() {
                continue;
            }
            if size > MAX_DRAWN_BYTES {
                self.images.insert(
                    p.entry,
                    crate::viewmodel::ImageState::NotDrawn(crate::images::PAST_LIMITS),
                );
                continue;
            }
            let (tx, sha, entry) = (self.image_checks.0.clone(), sha.to_owned(), p.entry);
            let spawned = std::thread::Builder::new()
                .name("vox-image-check".into())
                .spawn(move || {
                    let _ = tx.send((entry, crate::images::verify_and_decode(&p.path, size, &sha)));
                });
            if spawned.is_err() {
                // Not checked now; looked at again with the next snapshot.
                self.checked.remove(&entry);
            }
        }
    }

    /// Read the room on screen: whole when it first comes on screen, or when a late row or an
    /// unknown cursor says the order changed above what is shown; else only what arrived since.
    /// Send `act` to the Session `id` of `node` in `room`, through the one sender `vox room
    /// session` uses, and say what came of it in its words (ADR-029 DR-1, DR-6, CL-1).
    fn drive(
        &mut self,
        room: Digest32,
        node: Digest32,
        id: &str,
        act: crate::viewmodel::DriveAct,
    ) -> CommandStatus {
        use crate::session_drive_ui as d;
        use crate::viewmodel::DriveAct;
        let names = SessionNames {
            trusted: &self.snapshot.trusted,
            me: self.snapshot.me,
        };
        let alias = names.alias_of(&node);
        let row = self
            .snapshot
            .open
            .iter()
            .find(|o| o.channel_id == room)
            .and_then(|o| o.sessions.iter().find(|x| x.node == node && x.id == id));
        let Some(row) = row else {
            return CommandStatus::Said(format!("no Session in this room is named {id}"));
        };
        let t = d::Target {
            room,
            node,
            session: id.to_owned(),
            label: vox_agentcomms::envelope::session_label(&alias, row.name.as_deref(), id),
            node_alias: alias.clone(),
            can_drive: row.can_drive,
        };
        let paths = match self.account.node_paths(&self.node) {
            Ok(p) => p,
            Err(e) => return CommandStatus::Said(format!("not sent to {}: {e}", t.label)),
        };
        let said = until_stopped(&self.rt, &self.stop, async {
            match &act {
                DriveAct::Say(text) => d::say(&paths, &t, text).await,
                DriveAct::Slash(text) => d::slash(&paths, &t, text).await,
                DriveAct::Interrupt => d::interrupt(&paths, &t).await,
                DriveAct::Stop => d::stop(&paths, &t).await,
                DriveAct::Approve(r) => d::approve(&paths, &t, r).await,
                DriveAct::Reject(r, why) => d::reject(&paths, &t, r, why.as_deref()).await,
                DriveAct::Answer(r, answers) => d::answer(&paths, &t, r, answers).await,
                DriveAct::File(path, note) => {
                    d::file(&paths, &t, std::path::Path::new(path), note.as_deref()).await
                }
            }
        });
        // What the Session says of it is read again at once.
        self.session_stale = true;
        self.waiting_stale = true;
        match said {
            Some(Ok(s) | Err(s)) => CommandStatus::Said(s),
            None => CommandStatus::Said(format!("not sent to {}: the TUI is stopping", t.label)),
        }
    }

    /// Count the approvals and questions waiting on this node in each open room's Sessions it may
    /// drive, by the rule that words them (`Line::waiting`, ADR-029 CL-2): again only when the
    /// node says a Session has news, or the Sessions it may drive change.
    fn count_waiting(&mut self) {
        let rooms: Vec<(Digest32, Vec<(Digest32, String)>)> = self
            .snapshot
            .open
            .iter()
            .map(|o| {
                (
                    o.channel_id,
                    o.sessions
                        .iter()
                        .filter(|x| x.open && x.can_drive)
                        .map(|x| (x.node, x.id.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        if !self.waiting_stale && rooms == self.waiting_of {
            return;
        }
        self.waiting_stale = false;
        self.waiting_of = rooms.clone();
        let mut waiting = BTreeMap::new();
        let mut sessions = BTreeSet::new();
        for (room, drivable) in rooms {
            if drivable.is_empty() {
                continue;
            }
            let Ok(Frame::SessionEntries { rows }) =
                self.request(&Request::SessionEntries { channel_id: room })
            else {
                continue;
            };
            let names = SessionNames {
                trusted: &self.snapshot.trusted,
                me: self.snapshot.me,
            };
            let mut n = 0;
            for (node, id) in &drivable {
                let mine = crate::session_cli::of_session(rows.clone(), id, node);
                let here = crate::session_cli::lines(&mine, "", &names)
                    .iter()
                    .filter(|l| l.waiting.is_some())
                    .count();
                if here > 0 {
                    sessions.insert((room, *node, id.clone()));
                }
                n += here;
            }
            waiting.insert(room, n);
        }
        self.waiting = waiting;
        self.waiting_sessions = sessions;
    }

    /// Read the shown Session's entries when they are stale, and draw them as `vox room
    /// session` does (ADR-029 SC-1, CL-1). Entries this node cannot open are not among them: a
    /// member without drive reads none (SC-2).
    fn read_session(&mut self) {
        let Some((room, node, id)) = self.shown_session.clone() else {
            return;
        };
        if Some(room) != self.active {
            return;
        }
        if !self.session_stale {
            return;
        }
        self.session_stale = false;
        let Ok(Frame::SessionEntries { rows }) =
            self.request(&Request::SessionEntries { channel_id: room })
        else {
            return;
        };
        // The Session's own entries and the drive entries naming it, in written order: as
        // `vox room session` takes them.
        let mine = crate::session_cli::of_session(rows, &id, &node);
        let me = self.snapshot.me;
        let names = SessionNames {
            trusted: &self.snapshot.trusted,
            me,
        };
        let label = self
            .snapshot
            .open
            .iter()
            .find(|o| o.channel_id == room)
            .and_then(|o| o.sessions.iter().find(|x| x.node == node && x.id == id))
            .map_or_else(
                || vox_agentcomms::envelope::session_label(&names.alias_of(&node), None, &id),
                |x| {
                    vox_agentcomms::envelope::session_label(
                        &names.alias_of(&node),
                        x.name.as_deref(),
                        &x.id,
                    )
                },
            );
        // A waiting question's questions, from its entry, for an answer (DR-1.5).
        let questions = |reference: &str| {
            mine.iter()
                .filter_map(|r| serde_json::from_str::<serde_json::Value>(&r.body).ok())
                .find(|v| v["kind"] == "question" && v["ref"] == reference)
                .map(|v| crate::session_drive_ui::questions(&v))
                .unwrap_or_default()
        };
        self.session_lines = crate::session_cli::lines(&mine, &label, &names)
            .into_iter()
            .map(|l| crate::viewmodel::SessionLineView {
                questions: if l.waiting == Some(crate::session_cli::Waiting::Question) {
                    questions(&l.reference)
                } else {
                    Vec::new()
                },
                text: l.text,
                details: l.details,
                reference: l.reference,
                waiting: l.waiting,
            })
            .collect();
    }

    fn read_timeline(&mut self) {
        let Some(cid) = self.active else {
            self.timeline = None;
            return;
        };
        if !self.snapshot.open.iter().any(|o| o.channel_id == cid) {
            return;
        }
        let fresh = !matches!(&self.timeline, Some(t) if t.channel_id == cid);
        if !fresh && !self.timeline.as_ref().is_some_and(|t| t.stale) {
            return;
        }
        let since = if fresh {
            None
        } else {
            self.timeline.as_ref().and_then(|t| t.cursor)
        };
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let Some(read) = until_stopped(&self.rt, &self.stop, conn.client.read_rows(cid, since))
        else {
            return;
        };
        let rows = match read {
            Ok(Frame::Rows { rows }) => rows,
            Ok(Frame::NodeDetached { .. }) => return self.detached(),
            // A cursor the node no longer knows (the row expired): read it whole.
            Ok(_) if since.is_some() => {
                self.timeline = None;
                return self.read_timeline();
            }
            Ok(_) => return,
            Err(e) => {
                self.ended
                    .get_or_insert(format!("the vox daemon stopped answering: {e}"));
                return;
            }
        };
        let newest = |rows: &[MessageRow]| {
            rows.iter()
                .filter(|r| !r.owed)
                .max_by_key(|r| r.arrival)
                .map(|r| r.entry_hash)
        };
        match self.timeline.as_mut() {
            Some(t) if !fresh => {
                if rows.iter().any(|r| r.late) {
                    // Above rows already shown: the order is read again.
                    self.timeline = None;
                    return self.read_timeline();
                }
                if let Some(c) = newest(&rows) {
                    t.cursor = Some(c);
                }
                for row in rows {
                    note_machine(&mut t.machines, &row);
                    // An owed row whose body has arrived takes its own place.
                    match t.rows.iter_mut().find(|r| r.entry_hash == row.entry_hash) {
                        Some(held) => {
                            *held = row;
                            t.projected = None;
                        }
                        None => t.rows.push(row),
                    }
                }
                t.stale = false;
            }
            _ => {
                let mut machines = std::collections::HashMap::new();
                for row in &rows {
                    note_machine(&mut machines, row);
                }
                self.timeline = Some(Timeline {
                    channel_id: cid,
                    cursor: newest(&rows),
                    rows,
                    stale: false,
                    projected: None,
                    machines,
                });
            }
        }
    }

    /// The room on screen's rows for the UI: only the rows added since the last frame are
    /// projected, unless who the authors are changed (a keyring rename) or a row was replaced.
    fn project_timeline(
        &mut self,
        me: Option<Digest32>,
        trusted: &[(Digest32, String)],
        own: &Own,
        names: &vox_core::node::resolver::VoxResolver,
    ) -> std::sync::Arc<Vec<MessageView>> {
        let images = &self.images;
        let Some(t) = self.timeline.as_mut() else {
            return std::sync::Arc::default();
        };
        let (held, projected) = (&t.rows, &mut t.projected);
        // **An image a message shares** (ADR-028 F-9, F-11): as announced, with this node's copy
        // once it is verified here.
        let image_of = |r: &MessageRow| {
            let e = vox_agentcomms::envelope::Envelope::parse(&r.text).ok()?;
            if e.kind != crate::room_cli::FILE {
                return None;
            }
            let image = e.data.get("image")?;
            Some(ImageView {
                name: e.data.get("name")?.as_str()?.to_owned(),
                width: image.get("width")?.as_u64()?,
                height: image.get("height")?.as_u64()?,
                state: images
                    .get(&r.entry_hash)
                    .cloned()
                    .unwrap_or(crate::viewmodel::ImageState::Unverified),
            })
        };
        let name_of = |author: &Digest32| {
            if me == Some(*author) {
                "you".to_owned()
            } else {
                crate::ident::member_name(trusted, author)
            }
        };
        // **One level** (ADR-028 R-9, #485): the entry `re` names, as this room holds it.
        let quote_of = |r: &MessageRow| {
            let re = vox_agentcomms::envelope::Envelope::parse(&r.text)
                .ok()?
                .re
                .and_then(|re| b32_decode(&re.trim().to_ascii_lowercase(), "re").ok())?;
            let text = held
                .iter()
                .find(|p| p.entry_hash == re && !p.owed)
                .map(|p| {
                    let words = crate::agent_hook::words(&p.text);
                    let first = words.lines().next().unwrap_or_default();
                    let cut: String = first.chars().take(QUOTE_CHARS).collect();
                    let more =
                        if first.chars().count() > QUOTE_CHARS || words.lines().nth(1).is_some() {
                            "…"
                        } else {
                            ""
                        };
                    format!("{}: {cut}{more}", name_of(&p.author))
                });
            Some(QuoteView {
                entry_hash: re,
                text,
            })
        };
        let readers = |r: &MessageRow| -> String {
            if me != Some(r.author) {
                return String::new();
            }
            let Some((_, who)) = own.read_by.iter().find(|(e, _)| *e == r.entry_hash) else {
                return String::new();
            };
            let mut names: Vec<String> = who
                .iter()
                .map(|fp| crate::ident::member_name(trusted, fp))
                .collect();
            names.sort();
            names.join(", ")
        };
        // Who pulled a share it sent, whole, from its daemon's own record (ADR-028 F-7).
        let pullers = |r: &MessageRow| -> String {
            if me != Some(r.author) {
                return String::new();
            }
            let Some((_, who)) = own.pulled_by.iter().find(|(e, _)| *e == r.entry_hash) else {
                return String::new();
            };
            let mut names: Vec<String> = who
                .iter()
                .map(|fp| crate::ident::member_name(trusted, fp))
                .collect();
            names.sort();
            names.join(", ")
        };
        // Where a message it sent is, while no member is known to have read it (ADR-028 R-6):
        // from what other members' nodes said they hold, never from what was sent them.
        let whereabouts = |r: &MessageRow| -> String {
            if me != Some(r.author) {
                return String::new();
            }
            match own.held.iter().find(|(e, _)| *e == r.entry_hash) {
                None => String::new(),
                Some((_, n)) => vox_text::read::whereabouts(*n, own.others),
            }
        };
        let view_of = |r: &MessageRow| MessageView {
            entry_hash: r.entry_hash,
            author: r.author,
            author_nick: if me == Some(r.author) || trusted.iter().any(|(t, _)| *t == r.author) {
                name_of(&r.author)
            } else {
                // A node not in the keyring is offered the one trust action (ADR-028 K-5).
                format!(
                    "{} (not in keyring · {})",
                    crate::ident::author_id(&r.author),
                    crate::ident::trust_hint(&r.author)
                )
            },
            // The wire names addressees by fingerprint; the timeline by this node's own names.
            addressed: if r.owed {
                String::new()
            } else {
                crate::agent_hook::addressed(&r.text, me.as_ref(), trusted)
            },
            // Milliseconds: the timeline orders by it (a whole second put a room's change made
            // just after a post above it); only a display rounds it.
            timestamp: r.created_millis,
            // As `vox room read` and the drain show it, a structured post by its words (#406), and
            // an address in it readable, in this node's names (ADR-028 S-1a).
            body: Some(if r.owed {
                vox_core::node::api::NOT_RECEIVED_YET.to_owned()
            } else {
                names.readable_in(&crate::agent_hook::words(&r.text))
            }),
            late: r.late,
            read_by: readers(r),
            pulled_by: pullers(r),
            whereabouts: whereabouts(r),
            quote: if r.owed { None } else { quote_of(r) },
            image: if r.owed { None } else { image_of(r) },
        };
        // A quote whose message arrives after its reply is projected again with it.
        let quoted_late = |p: &Projected| {
            p.rows.iter().any(|v| {
                v.quote.as_ref().is_some_and(|q| {
                    q.text.is_none() && held[p.len..].iter().any(|r| r.entry_hash == q.entry_hash)
                })
            })
        };
        match projected.as_mut() {
            Some(p)
                if p.me == me
                    && p.verified == images.len()
                    && p.trusted.as_slice() == trusted
                    && p.names == *names
                    && p.len <= held.len()
                    && !quoted_late(p) =>
            {
                if p.len < held.len() {
                    // A Session's opening and end are not the room's conversation (ADR-029 CL-2).
                    let rows = std::sync::Arc::make_mut(&mut p.rows);
                    for (i, r) in held.iter().enumerate().skip(p.len) {
                        if !crate::agent_hook::is_session_record(r) {
                            p.at.insert(r.entry_hash, (rows.len(), i));
                            rows.push(view_of(r));
                        }
                    }
                    p.len = held.len();
                }
                // **Who read, holds or pulled this node's messages changes with each one it
                // sends**, and only those messages say it (ADR-028 R-6, F-7): they are projected
                // again, not the room. Projecting the whole room again for it made each frame
                // after a send cost the room's history.
                if p.own != *own {
                    let mine = |o: &Own| -> Vec<Digest32> {
                        o.read_by
                            .iter()
                            .map(|(e, _)| *e)
                            .chain(o.held.iter().map(|(e, _)| *e))
                            .chain(o.pulled_by.iter().map(|(e, _)| *e))
                            .collect()
                    };
                    let mut again = mine(&p.own);
                    again.extend(mine(own));
                    again.sort_unstable();
                    again.dedup();
                    let rows = std::sync::Arc::make_mut(&mut p.rows);
                    for e in again {
                        if let Some(&(v, h)) = p.at.get(&e) {
                            let r = &held[h];
                            rows[v].read_by = readers(r);
                            rows[v].pulled_by = pullers(r);
                            rows[v].whereabouts = whereabouts(r);
                        }
                    }
                    p.own = own.clone();
                }
                std::sync::Arc::clone(&p.rows)
            }
            _ => {
                let mut at = std::collections::HashMap::new();
                let mut rows = Vec::new();
                for (i, r) in held.iter().enumerate() {
                    if !crate::agent_hook::is_session_record(r) {
                        at.insert(r.entry_hash, (rows.len(), i));
                        rows.push(view_of(r));
                    }
                }
                let rows = std::sync::Arc::new(rows);
                *projected = Some(Projected {
                    verified: images.len(),
                    me,
                    trusted: trusted.to_vec(),
                    own: own.clone(),
                    names: names.clone(),
                    len: held.len(),
                    rows: std::sync::Arc::clone(&rows),
                    at,
                });
                rows
            }
        }
    }

    /// **A reply, as the CLI's `--re` writes one** (ADR-028 R-9, #485): a `say` whose `re` names
    /// the entry replied to, in the thread that entry is in (or begins), spending a hop of its
    /// parent's budget (ADR-020 §9). Its parents are the room on screen's rows.
    fn reply_text(&self, channel_id: Digest32, re: &Digest32, text: &str) -> String {
        use vox_agentcomms::envelope::{reply_hops_by, Envelope};
        let held: &[MessageRow] = self
            .timeline
            .as_ref()
            .filter(|t| t.channel_id == channel_id)
            .map_or(&[], |t| t.rows.as_slice());
        let text_of = |h: &str| {
            let h = b32_decode(&h.trim().to_ascii_lowercase(), "re").ok()?;
            held.iter()
                .find(|r| r.entry_hash == h)
                .map(|r| r.text.clone())
        };
        let re_b32 = b32_encode(re);
        let mut reply = Envelope::say(text);
        reply.thread = Some(
            text_of(&re_b32)
                .and_then(|t| Envelope::parse(&t).ok())
                .and_then(|p| p.thread)
                .unwrap_or_else(|| re_b32.clone()),
        );
        reply.hops = reply_hops_by(&re_b32, text_of);
        reply.re = Some(re_b32);
        reply.to_text()
    }

    fn project(&mut self) -> ViewModel {
        let snap = self.snapshot.clone();
        let me = snap.me;
        // A room is reachable when this node holds a connection to another of its members. A
        // closed room's members are under its lock, and this node does not sync it: offline.
        let reachability = |cid: &Digest32| {
            let online = snap.open.iter().any(|d| {
                d.channel_id == *cid
                    && d.members
                        .iter()
                        .any(|m| me != Some(*m) && snap.connected_peers.binary_search(m).is_ok())
            });
            if online {
                Reachability::Online
            } else {
                Reachability::Offline
            }
        };
        // **Two rooms of one name are each shown by their room ID** (ADR-028 R-3), and why is said
        // once, when it starts.
        let names_here = || snap.rooms.iter().map(|r| r.name.as_deref());
        let clashing = crate::room_cli::clashing_names(names_here().flatten());
        for name in &clashing {
            if self.clashes_said.insert((*name).to_owned()) {
                self.notice = Some(format!(
                    "{} rooms here are called {name}, so each is shown by its room ID until one \
                     is renamed",
                    names_here().filter(|n| *n == Some(*name)).count()
                ));
            }
        }
        self.clashes_said.retain(|n| clashing.contains(n.as_str()));
        let mut channels: Vec<ChannelSummary> = snap
            .rooms
            .iter()
            .map(|c| ChannelSummary {
                open: c.open,
                channel_id: c.channel_id,
                name: match (&c.name, c.open) {
                    (Some(n), _) => vox_core::node::resolver::room_shown_here(
                        Some(n),
                        &c.channel_id,
                        names_here(),
                    ),
                    (None, true) => vox_core::node::resolver::room_shown(None, &c.channel_id),
                    (None, false) => format!("(closed {})", short_id(&c.channel_id)),
                },
                to_you: self.unread.get(&c.channel_id).map_or(0, |u| u.to_you),
                waiting: self.waiting.get(&c.channel_id).copied().unwrap_or(0),
                unread: self.unread.get(&c.channel_id).map_or(0, |u| u.new),
                coordination: self.unread.get(&c.channel_id).map_or(0, |u| u.coordination),
                // A Session waiting on this node, for a member with drive, needs the person
                // (ADR-028 W-2 as amended, ADR-029 CL-2).
                group: if self.waiting.get(&c.channel_id).is_some_and(|n| *n > 0) {
                    RoomGroup::NeedsYou
                } else {
                    self.unread
                        .get(&c.channel_id)
                        .map_or(RoomGroup::Quiet, |u| group(u.to_you, u.new, u.coordination))
                },
                reachability: reachability(&c.channel_id),
            })
            .collect();
        // Grouped as the sidebar lists them (ADR-028 W-2, #511): what needs the person first.
        channels.sort_by_key(|c| c.group);
        let mut machine_nodes: Vec<(String, bool)> = self
            .on_disk
            .iter()
            .chain(&self.attached)
            .map(|n| (n.clone(), self.attached.contains(n)))
            .collect();
        machine_nodes.sort();
        machine_nodes.dedup();
        // This node's names, for every address the views write readable (ADR-028 S-1a).
        let names = vox_core::node::resolver::VoxResolver::of_snapshot(&snap);
        let timeline = self.active.and_then(|cid| {
            let room = snap.open.iter().find(|d| d.channel_id == cid)?;
            let own = Own {
                read_by: room.read_by.clone(),
                held: room.held.clone(),
                pulled_by: room.pulled_by.clone(),
                others: room.members.iter().filter(|m| me != Some(**m)).count() as u64,
            };
            Some(self.project_timeline(me, &snap.trusted, &own, &names))
        });
        let active = self.active.and_then(|cid| {
            snap.open
                .iter()
                .find(|d| d.channel_id == cid)
                .map(|d| ChannelView {
                    channel_id: d.channel_id,
                    name: vox_core::node::resolver::room_shown_here(
                        d.name.as_deref(),
                        &d.channel_id,
                        names_here(),
                    ),
                    retention: vox_core::node::retention::describe(d.retention),
                    notices: d
                        .notices
                        .iter()
                        .map(|n| NoticeView {
                            timestamp: n.created_millis,
                            after: n.after,
                            text: format!(
                                "{} {}",
                                if me == Some(n.author) {
                                    "you".to_owned()
                                } else {
                                    crate::ident::member_name(&snap.trusted, &n.author)
                                },
                                n.what
                            ),
                        })
                        .collect(),
                    members: d
                        .members
                        .iter()
                        .map(|m| {
                            let is_me = me == Some(*m);
                            MemberView {
                                id: *m,
                                machine: self
                                    .timeline
                                    .as_ref()
                                    .filter(|t| t.channel_id == d.channel_id)
                                    .and_then(|t| t.machines.get(m))
                                    .map(|(_, said)| said.clone()),
                                capability: (!is_me && snap.trusted.iter().any(|(fp, _)| fp == m))
                                    .then(|| {
                                        if snap.drive.contains(m) {
                                            vox_core::node::trust::Capability::ReadDrive
                                        } else {
                                            vox_core::node::trust::Capability::Read
                                        }
                                    }),
                                // The members pane says "not in keyring" on the member's state
                                // line (ADR-028 L-4), so a member without a name is its
                                // fingerprint alone, which fits beside its trust glyph.
                                nickname: if is_me {
                                    "you".to_owned()
                                } else {
                                    crate::ident::alias_of(&snap.trusted, m)
                                        .unwrap_or_else(|| crate::ident::author_id(m))
                                },
                                // Off the keyring and the room's log: this node releases its key
                                // only to a member its keyring trusts (V210-148), and takes a
                                // member's key only if it trusts it.
                                trust: {
                                    let reads_you = d.consented.binary_search(m).is_ok();
                                    let trusts_you = d.consenting.binary_search(m).is_ok();
                                    if is_me {
                                        Trust::You
                                    } else if snap.trusted.iter().any(|(t, _)| t == m) {
                                        Trust::Trusted {
                                            reads_you,
                                            trusts_you,
                                        }
                                    } else {
                                        Trust::NotTrusted { reads_you }
                                    }
                                },
                            }
                        })
                        .collect(),
                    timeline: timeline.clone().unwrap_or_default(),
                    // What is shared here, in this operator's own words (V030-25): the same
                    // addresses `vox service list` prints.
                    shared: {
                        d.shares
                            .iter()
                            .map(|s| {
                                let who = if me == Some(s.host) {
                                    "you".to_owned()
                                } else {
                                    names.alias_of(&s.host)
                                };
                                // Its kind, as its sharer's node detected it (ADR-028 S-2).
                                let kind = s.kind;
                                let udp = if s.udp && kind.as_str() != "udp" {
                                    "/udp"
                                } else {
                                    ""
                                };
                                // A sharer not in the keyring cannot be reached until each
                                // trusts the other: the one trust action is offered (K-5).
                                let offer = if me != Some(s.host)
                                    && !snap.trusted.iter().any(|(t, _)| *t == s.host)
                                {
                                    format!(
                                        "  (not in keyring · {})",
                                        crate::ident::trust_hint(&s.host)
                                    )
                                } else {
                                    String::new()
                                };
                                let address = names.address_of(&d.channel_id, &s.host, &s.name);
                                let line = format!("{address} by {who}  {kind}{udp}{offer}");
                                let svc = vox_core::node::ipc::SharedService {
                                    address,
                                    canonical: vox_core::node::resolver::canonical_address(
                                        &d.channel_id,
                                        &s.host,
                                        &s.name,
                                    ),
                                    by: who,
                                    udp: s.udp,
                                    kind: kind.as_str().to_owned(),
                                    trusts_you: me == Some(s.host)
                                        || d.consenting.binary_search(&s.host).is_ok(),
                                    online: me == Some(s.host)
                                        || snap.connected_peers.binary_search(&s.host).is_ok(),
                                };
                                crate::viewmodel::SharedView {
                                    line,
                                    copy: crate::tunnel_cli::service_commands(&svc)
                                        .into_iter()
                                        .next()
                                        .map(|(_, c)| c)
                                        .unwrap_or_default(),
                                    ready: crate::tunnel_cli::service_needs(
                                        &svc,
                                        self.proxy.as_ref(),
                                    )
                                    .into_iter()
                                    .map(|(need, holds, otherwise)| {
                                        crate::tunnel_cli::service_tick(&need, holds, &otherwise)
                                    })
                                    .collect(),
                                }
                            })
                            .collect()
                    },
                    session_lines: if self
                        .shown_session
                        .as_ref()
                        .is_some_and(|(room, _, _)| *room == d.channel_id)
                    {
                        self.session_lines.clone()
                    } else {
                        Vec::new()
                    },
                    // The room's Sessions (ADR-029 CL-2), newest opening first, each labelled as
                    // `vox room sessions` labels it (SE-3).
                    sessions: d
                        .sessions
                        .iter()
                        .rev()
                        .map(|x| {
                            let node_alias =
                                crate::ident::author_for(&snap.trusted, me.as_ref(), &x.node);
                            crate::viewmodel::SessionView {
                                node: x.node,
                                id: x.id.clone(),
                                name: x.name.clone(),
                                label: vox_agentcomms::envelope::session_label(
                                    &node_alias,
                                    x.name.as_deref(),
                                    &x.id,
                                ),
                                title: vox_agentcomms::envelope::session_title(
                                    &x.harness,
                                    x.folder.as_deref(),
                                    x.name.as_deref(),
                                    &x.id,
                                ),
                                node_alias,
                                opened: x.opened_millis,
                                ended: (!x.open).then(|| x.ended_millis.unwrap_or(x.opened_millis)),
                                can_drive: x.can_drive,
                                waiting: self.waiting_sessions.contains(&(
                                    d.channel_id,
                                    x.node,
                                    x.id.clone(),
                                )),
                            }
                        })
                        .collect(),
                    // **Every member held back, each on its own line** (V210-66).
                    held_back: d
                        .equivocations
                        .iter()
                        .map(|(author, seq)| {
                            crate::ident::equivocation_notice(
                                &crate::ident::member_name(&snap.trusted, author),
                                *seq,
                            )
                        })
                        .collect(),
                    reachability: reachability(&cid),
                })
        });
        ViewModel {
            notice: self.notice.clone(),
            channels,
            active,
            sync: match snap.connected_peers.len() {
                0 => SyncStatus::Idle,
                n => SyncStatus::Connected(n),
            },
            attached: self.conn.is_some(),
            node: self.node.as_str().to_owned(),
            nodes: self.attached.clone(),
            machine_nodes,
            mlock_active: snap.mlock_active,
            keyring_open_secs: snap.keyring_open_secs,
            has_identity: self.has_identity,
            tunnels: snap.tunnels,
            closed_tunnels: snap.closed_tunnels,
            keyring: snap.trusted.clone(),
            offers: snap.offers.clone(),
            decisions: self.decisions(),
            listening: self
                .listening
                .iter()
                .map(|l| crate::viewmodel::ListeningView {
                    line: crate::tunnel_cli::listing_line(l),
                    port: l.port,
                    udp: l.udp,
                })
                .collect(),
            serve_preview: self.serve_preview.clone(),
        }
    }

    /// List what listens on this machine (ADR-028 S-4), as `vox serve` does.
    fn probe_listening(&mut self) {
        // Spawned inside the runtime: `spawn_blocking` made outside it panics.
        self.listening = self
            .rt
            .block_on(async { tokio::task::spawn_blocking(vox_core::node::probe::listening).await })
            .unwrap_or_default();
    }

    /// What offering the service on `port` in `channel_id` would do, said before it is done
    /// (ADR-028 S-4), as `vox serve` says it: the name it is offered under, the address members
    /// reach it at, who can reach it and who cannot, and each warning.
    fn preview_serve(
        &mut self,
        channel_id: Digest32,
        port: u16,
        udp: Option<bool>,
    ) -> CommandStatus {
        if self.listening.is_empty() {
            self.probe_listening();
        }
        let Some(chosen) = self
            .listening
            .iter()
            .find(|l| l.port == port && udp.is_none_or(|u| l.udp == u))
            .cloned()
        else {
            return CommandStatus::Said(format!(
                "nothing listening on port {port} can be seen from here; {}",
                crate::tunnel_cli::MAY_BE_MISSING
            ));
        };
        let local = chosen.endpoint();
        let name = self.rt.block_on(crate::tunnel_cli::suggested_name(&chosen));
        let tag = crate::tunnel_cli::tag_of(name.clone(), chosen.udp);
        let warnings = self.rt.block_on(crate::tunnel_cli::exposure_warnings(
            &[(chosen.port, tag.clone())],
            Some(local),
        ));
        let snap = &self.snapshot;
        let me = snap.me;
        let mut names = vox_core::node::resolver::VoxResolver::new();
        for o in &snap.open {
            names.add_room(o.channel_id, o.name.as_deref(), &o.members);
        }
        for (fp, petname) in &snap.trusted {
            names.name(*fp, petname);
        }
        let members: Vec<Digest32> = snap
            .open
            .iter()
            .find(|o| o.channel_id == channel_id)
            .map(|o| o.members.clone())
            .unwrap_or_default();
        let (mut can, mut cannot) = (Vec::new(), Vec::new());
        for m in members.iter().filter(|m| Some(**m) != me) {
            if snap.trusted.iter().any(|(t, _)| t == m) {
                can.push(crate::ident::member_name(&snap.trusted, m));
            } else {
                cannot.push(crate::ident::member_name(&snap.trusted, m));
            }
        }
        let address = me.map_or_else(
            || format!("{name}.<you>.<the room>.vox"),
            |me| names.address_of(&channel_id, &me, &name),
        );
        let mut lines = vec![
            format!(
                "share {}",
                crate::tunnel_cli::listing_line(&chosen).trim_end()
            ),
            format!("as {tag}: members will reach it as {address}"),
            format!(
                "who can reach it: {}",
                if can.is_empty() {
                    "nobody yet: you trust no member of this room".to_owned()
                } else {
                    can.join(", ")
                }
            ),
            format!(
                "who cannot: {}",
                if cannot.is_empty() {
                    "nobody else is in the room".to_owned()
                } else {
                    // Each named as the keyring has it, which says it is not in it.
                    cannot.join(", ")
                }
            ),
        ];
        lines.extend(warnings.into_iter().map(|w| format!("warning: {w}")));
        self.serve_preview = Some(crate::viewmodel::ServePreview {
            channel_id,
            tag,
            local,
            lines,
        });
        CommandStatus::Done
    }

    /// Offer the previewed service in its room (ADR-028 S-4), as `vox service add` does: offered
    /// until removed, across the daemon's restarts.
    fn offer_service(&mut self) -> CommandStatus {
        let Some(p) = self.serve_preview.take() else {
            return CommandStatus::Said("nothing to share: pick a service first".into());
        };
        match self.request(&Request::AddService {
            channel_id: p.channel_id,
            service_tag: p.tag.clone(),
            local: p.local.to_string(),
            persist: true,
        }) {
            Ok(Frame::Ok) => {
                self.asked = None;
                let said = format!("offering {} at {} in this room", p.tag, p.local);
                self.notice = Some(said.clone());
                CommandStatus::Said(said)
            }
            Ok(Frame::Error { reason }) => {
                CommandStatus::Said(format!("cannot offer {}: {reason}", p.tag))
            }
            Ok(other) => CommandStatus::Said(format!(
                "cannot offer {}: {}",
                p.tag,
                crate::client::unexpected(&other)
            )),
            Err(_) => CommandStatus::Failed(UiError::NotAttached),
        }
    }

    /// This node's decision record, newest first: read from its files at most once a
    /// [`SNAPSHOT_EVERY`], like the snapshot, since a frame is drawn far more often than a node
    /// decides (ADR-028 D-3).
    fn decisions(&mut self) -> Vec<vox_core::node::decisions::Event> {
        if self
            .decisions
            .0
            .is_none_or(|at| at.elapsed() >= SNAPSHOT_EVERY)
        {
            // Read by the node, which alone opens the sealed record (#563).
            let events = match self.request(&Request::Decisions {
                limit: DECISIONS_SHOWN as u64,
            }) {
                Ok(Frame::Decisions { events }) => events,
                _ => self.decisions.1.clone(),
            };
            self.decisions = (Some(Instant::now()), events);
        }
        self.decisions.1.clone()
    }
}

impl Drop for DaemonCore {
    fn drop(&mut self) {
        self.daemon_events.abort();
    }
}

/// Wipe the passphrase `request` carries, if it carries one, before it is dropped: a `String`
/// freed as it was keeps its bytes in freed memory (V210-94).
fn wipe(request: &mut Request) {
    use zeroize::Zeroize as _;
    match request {
        Request::Create { passphrase, .. }
        | Request::OpenRoom { passphrase, .. }
        | Request::Join { passphrase, .. } => passphrase.zeroize(),
        Request::Trust {
            identity_passphrase,
            ..
        } => identity_passphrase.zeroize(),
        _ => {}
    }
}

/// How a request that got no answer from the node is said.
fn lost_status(lost: Lost) -> CommandStatus {
    match lost {
        Lost::Detached => CommandStatus::Failed(UiError::NotAttached),
        Lost::Gone(why) => CommandStatus::Said(why),
    }
}

/// A daemon's refusal of a `Use`, as the TUI says it: a failed unlock in the daemon's words,
/// which carry the fault's own (the identity file that could not be written, say), on one line.
fn refused(refusal: &Refusal) -> CommandStatus {
    CommandStatus::Said(one_line(&refusal.to_string()))
}

/// A node's error answer, as the TUI says it: in the words vox-core gives the fault it names, or the
/// node's own sentence when it names none (ADR-028 E-7).
fn failed(reason: &str) -> CommandStatus {
    match Fault::from_explanation(reason) {
        Some(f) => fault_status(f),
        None => CommandStatus::Said(reason.lines().next().unwrap_or_default().to_owned()),
    }
}

/// How the TUI says fault `f`: the sentence vox-core writes for it, once, which the CLI and the app
/// show too (ADR-028 E-7), its advice after a dash on one status line. The TUI never rewords it.
fn fault_status(f: Fault) -> CommandStatus {
    CommandStatus::Said(one_line(f.explain()))
}

/// `text`'s lines as one status line: a fault's advice follows its cause after a dash.
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" — ")
}

impl CoreHandle for DaemonCore {
    fn view(&mut self) -> ViewModel {
        self.drain_events();
        self.refresh();
        // If the room on screen is no longer open (closed, left), fall back.
        if let Some(cid) = self.active {
            if self.conn.is_some() && !self.snapshot.open.iter().any(|d| d.channel_id == cid) {
                self.active = None;
            }
        }
        self.read_timeline();
        self.read_session();
        self.count_waiting();
        self.count_unread();
        self.project()
    }

    fn apply(&mut self, command: Command) -> CommandStatus {
        self.apply_noting(command, &mut || {})
    }

    fn shown(&mut self, entries: &[Digest32]) {
        let Some(cid) = self.active else {
            return;
        };
        // Each message is told to the node once; the node keeps what it has recorded.
        let new: Vec<Digest32> = entries
            .iter()
            .filter(|h| !self.marked.contains(*h))
            .copied()
            .collect();
        if new.is_empty() {
            return;
        }
        // A refusal is not asked again every frame: only once the room has changed, and
        // `MARK_RETRY` has passed, and never for a room that is over.
        let room = (
            self.timeline.as_ref().map_or(0, |t| t.rows.len()),
            self.snapshot
                .open
                .iter()
                .find(|o| o.channel_id == cid)
                .cloned(),
        );
        if let Some(r) = self.mark_refused.as_ref().filter(|r| r.channel_id == cid) {
            if r.over || r.room == room || r.at.elapsed() < MARK_RETRY {
                return;
            }
        }
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let request = Request::MarkRead {
            channel_id: cid,
            entries: new.clone(),
        };
        match until_stopped(&self.rt, &self.stop, conn.client.request(&request)) {
            Some(Ok(Frame::Ok)) => {
                self.marked.extend(new);
                self.mark_refused = None;
            }
            Some(Ok(Frame::NodeDetached { .. })) => self.detached(),
            Some(Ok(Frame::Error { reason })) => {
                let over = matches!(
                    Fault::from_explanation(&reason),
                    Some(Fault::RoomEnded | Fault::RoomLeft)
                );
                self.mark_refused = Some(MarkRefused {
                    channel_id: cid,
                    at: Instant::now(),
                    room,
                    over,
                });
            }
            Some(Ok(_)) | None => {}
            Some(Err(e)) => {
                self.ended
                    .get_or_insert(format!("the vox daemon stopped answering: {e}"));
            }
        }
    }

    fn apply_noting(&mut self, command: Command, waiting: &mut dyn FnMut()) -> CommandStatus {
        let secret = |s: &SecretString| s.expose_secret().to_owned();
        match command {
            Command::ProbeListening => {
                self.serve_preview = None;
                self.probe_listening();
                CommandStatus::Done
            }
            Command::PreviewServe {
                channel_id,
                port,
                udp,
            } => self.preview_serve(channel_id, port, udp),
            Command::OfferService => self.offer_service(),
            Command::CancelServe => {
                self.serve_preview = None;
                CommandStatus::Done
            }
            Command::CreateIdentity { passphrase } => self.create_identity(&passphrase, waiting),
            Command::Attach { passphrase } => {
                if self.conn.is_some() {
                    return CommandStatus::Done;
                }
                self.attach(Some(Zeroizing::new(passphrase.expose_secret().to_owned())))
            }
            Command::CreateChannel { name, passphrase } => self.send(Request::Create {
                name,
                passphrase: Zeroizing::new(secret(&passphrase)),
            }),
            Command::RenameRoom { channel_id, name } => {
                self.send(Request::RenameRoom { channel_id, name })
            }
            Command::AcceptOffer {
                target,
                petname,
                drive,
                identity_passphrase,
            } => match self.send(Request::Trust {
                target,
                petname: petname.clone(),
                identity_passphrase: Zeroizing::new(secret(&identity_passphrase)),
                full_history: false,
                drive,
            }) {
                CommandStatus::Done => CommandStatus::Said(format!(
                    "you now trust {petname} ({}): it may read what you write in every room you \
                     share; it is offered you back",
                    if drive { "read + drive" } else { "read" }
                )),
                other => other,
            },
            Command::DismissOffer { member } => match self.send(Request::DismissOffer { member }) {
                CommandStatus::Done => CommandStatus::Said(format!(
                    "dismissed the offer of {} on this node alone: it is not told, and stays \
                         out of your keyring",
                    crate::ident::author_id(&member)
                )),
                other => other,
            },
            Command::Trust {
                target,
                petname,
                identity_passphrase,
            } => match self.send(Request::Trust {
                target,
                petname: petname.clone(),
                identity_passphrase: Zeroizing::new(secret(&identity_passphrase)),
                full_history: false,
                drive: false,
            }) {
                CommandStatus::Done => CommandStatus::Said(format!(
                    "you now trust {petname}: it may read what you write in every room you share"
                )),
                other => other,
            },
            Command::OpenChannel {
                channel_id,
                passphrase,
            } => self.send(Request::OpenRoom {
                channel_id,
                passphrase: Zeroizing::new(secret(&passphrase)),
            }),
            Command::CloseTunnel { id } => {
                let which = vox_core::transport::quic::TunnelSelector {
                    id: Some(id),
                    ..Default::default()
                };
                // By number, so it names one tunnel and is never refused as ambiguous; and only
                // this node's (ADR-026 P-1): the daemon closes it among this node's own.
                let Some(conn) = self.conn.as_mut() else {
                    return CommandStatus::Failed(UiError::NotAttached);
                };
                match until_stopped(
                    &self.rt,
                    &self.stop,
                    vox_core::node::status::request_close_on(&mut conn.client, &which),
                )
                .unwrap_or(Err(vox_core::error::Error::MalformedIpc("stopping")))
                {
                    Ok((0, _)) => CommandStatus::Failed(UiError::NoSuchTunnel),
                    Ok(_) => {
                        self.asked = None;
                        CommandStatus::Done
                    }
                    Err(e) => CommandStatus::Said(format!("the tunnel was not closed: {e}")),
                }
            }
            Command::CloseChannel { channel_id } => {
                if self.active == Some(channel_id) {
                    self.active = None;
                }
                self.send(Request::CloseRoom { channel_id })
            }
            Command::LeaveRoom { channel_id } => {
                // Answered once another member has the leave; the room is gone then. What it did
                // is said, not "done" (ADR-028 E-5).
                let status = self.send(Request::Leave { channel_id });
                if !matches!(status, CommandStatus::Done) {
                    return status;
                }
                if self.active == Some(channel_id) {
                    self.active = None;
                }
                CommandStatus::Said(
                    "left the room: its other members see that you left; this node no longer \
                     holds it"
                        .to_owned(),
                )
            }
            Command::EndRoom { channel_id } => match self.send(Request::End { channel_id }) {
                CommandStatus::Done => CommandStatus::Said(
                    "ended the room for everyone: every member's node takes no new message in it \
                     once it has this, passes the end on, and deletes it"
                        .to_owned(),
                ),
                other => other,
            },
            Command::Drive {
                channel_id,
                session: (node, id),
                act,
            } => self.drive(channel_id, node, &id, act),
            Command::ShowSession {
                channel_id,
                session,
            } => {
                self.shown_session = session.map(|(node, id)| (channel_id, node, id));
                self.session_lines.clear();
                self.session_stale = true;
                CommandStatus::Done
            }
            Command::SelectChannel { channel_id } => {
                // The room left counts from the newest row it showed: nothing seen is unread.
                if let Some(t) = self
                    .timeline
                    .as_ref()
                    .filter(|t| Some(t.channel_id) != channel_id)
                {
                    self.unread.insert(
                        t.channel_id,
                        RoomUnread {
                            cursor: t.cursor,
                            ..RoomUnread::default()
                        },
                    );
                }
                self.active = channel_id;
                if let Some(cid) = channel_id {
                    self.unread.remove(&cid);
                    // Looked at: the next message there is news again.
                    self.notified.remove(&cid);
                }
                CommandStatus::Done
            }
            Command::ShareFile {
                channel_id,
                path,
                note,
                to,
                urgent,
            } => {
                let Ok(paths) = self.account.node_paths(&self.node) else {
                    return CommandStatus::Failed(UiError::NotAttached);
                };
                let opts = crate::share_cli::ShareOpts {
                    to: to.iter().map(vox_core::node::link::b32_encode).collect(),
                    urgent,
                    note: (!note.is_empty()).then_some(note),
                    ..crate::share_cli::ShareOpts::default()
                };
                let room = vox_core::node::link::b32_encode(&channel_id);
                let offered = until_stopped(
                    &self.rt,
                    &self.stop,
                    crate::share_cli::offer(
                        &paths,
                        &room,
                        std::path::Path::new(path.trim()),
                        &opts,
                        |_, _, _| {},
                    ),
                );
                if let Some(t) = self
                    .timeline
                    .as_mut()
                    .filter(|t| t.channel_id == channel_id)
                {
                    t.stale = true;
                }
                match offered {
                    Some(Ok(o)) => {
                        let mut said = vec![if o.row.files > 0 {
                            format!(
                                "sharing {}/ ({} files, {} bytes) as {}",
                                o.row.name, o.row.files, o.row.size, o.row.tag
                            )
                        } else {
                            format!(
                                "sharing {} ({} bytes) as {}",
                                o.row.name, o.row.size, o.row.tag
                            )
                        }];
                        if !o.to.is_empty() {
                            let names: Vec<String> = o
                                .to
                                .iter()
                                .filter_map(|fp| crate::ident::recipient(fp))
                                .map(|fp| crate::ident::member_name(&self.snapshot.trusted, &fp))
                                .collect();
                            said.push(format!("for {}", names.join(", ")));
                        }
                        said.extend(o.notes);
                        CommandStatus::Said(said.join(" · "))
                    }
                    Some(Err(e)) => CommandStatus::Said(e.to_string()),
                    None => CommandStatus::NotConnected,
                }
            }
            Command::PostAddressed {
                channel_id,
                text,
                to,
                urgent,
                re,
            } => {
                let Ok(paths) = self.account.node_paths(&self.node) else {
                    return CommandStatus::Failed(UiError::NotAttached);
                };
                let opts = crate::room_cli::PostOpts {
                    to: to.iter().map(vox_core::node::link::b32_encode).collect(),
                    urgent,
                    re: re.as_ref().map(vox_core::node::link::b32_encode),
                    ..crate::room_cli::PostOpts::default()
                };
                let room = vox_core::node::link::b32_encode(&channel_id);
                let posted = until_stopped(
                    &self.rt,
                    &self.stop,
                    crate::room_cli::post_structured(&paths, &room, &text, &opts),
                );
                if let Some(t) = self
                    .timeline
                    .as_mut()
                    .filter(|t| t.channel_id == channel_id)
                {
                    t.stale = true;
                }
                match posted {
                    Some(Ok(report)) => {
                        let said = report.said();
                        if said.is_empty() {
                            CommandStatus::Done
                        } else {
                            CommandStatus::Said(said.join(" · "))
                        }
                    }
                    Some(Err(e)) => CommandStatus::Said(e.to_string()),
                    None => CommandStatus::NotConnected,
                }
            }
            Command::Reply {
                channel_id,
                re,
                text,
            } => {
                let text = self.reply_text(channel_id, &re, &text);
                self.apply(Command::SendText { channel_id, text })
            }
            Command::SendText { channel_id, text } => {
                // A link card, fetched by this node (ADR-028 F-10).
                let status = self.send(Request::Post {
                    channel_id,
                    text,
                    card: true,
                });
                if let Some(t) = self
                    .timeline
                    .as_mut()
                    .filter(|t| t.channel_id == channel_id)
                {
                    t.stale = true;
                }
                status
            }
            Command::Join { link, passphrase } => self.send(Request::Join {
                link,
                passphrase: Zeroizing::new(secret(&passphrase)),
            }),
            Command::Invite { channel_id } => self.send(Request::Invite { channel_id }),
        }
    }

    fn startup_notice(&self) -> Option<String> {
        self.notice.clone()
    }

    fn ended(&self) -> Option<String> {
        self.ended.clone()
    }
}

/// How the TUI names a node in a Session's lines, as `vox room session` does: "you", this node's
/// name for it, or its fingerprint marked not in the keyring (ADR-029 CL-1).
struct SessionNames<'a> {
    trusted: &'a [(Digest32, String)],
    me: Option<Digest32>,
}

impl SessionNames<'_> {
    fn alias_of(&self, fp: &Digest32) -> String {
        crate::ident::author_for(self.trusted, self.me.as_ref(), fp)
    }
}

impl crate::session_cli::Names for SessionNames<'_> {
    fn alias(&self, fp: &Digest32) -> String {
        self.alias_of(fp)
    }
    fn is_me(&self, by: &str) -> bool {
        vox_core::node::link::b32_decode(by, "fingerprint").is_ok_and(|fp| self.me == Some(fp))
    }
    fn alias_b32(&self, by: &str) -> String {
        match vox_core::node::link::b32_decode(by, "fingerprint") {
            Ok(fp) => self.alias_of(&fp),
            Err(_) => by.chars().take(12).collect(),
        }
    }
}
