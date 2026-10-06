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
//!   its newest row as events say rows arrived ([`Timeline`]), so a frame never costs a room's
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
use vox_core::node::paths::{Account, NodeName};
use vox_core::node::snapshot::NodeSnapshot;
use zeroize::Zeroizing;

use crate::app::CoreHandle;
use crate::viewmodel::{
    ChannelSummary, ChannelView, Command, CommandStatus, MemberView, MessageView, Reachability,
    SyncStatus, Trust, UiError, ViewModel,
};

/// How often the snapshot is asked again when no event has said anything changed: connections,
/// tunnels and their last moved byte change without a room event.
const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

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
    tx: mpsc::Sender<Ev>,
    rx: mpsc::Receiver<Ev>,
    /// The daemon's event task.
    daemon_events: tokio::task::JoinHandle<()>,
    snapshot: NodeSnapshot,
    /// When the snapshot was last asked for; `None` asks now.
    asked: Option<Instant>,
    /// The room on screen (drives `ViewModel::active` and unread resets).
    active: Option<Digest32>,
    /// Unread counts per room (incremented by events for rooms off screen).
    unread: BTreeMap<Digest32, usize>,
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
    /// The room on screen's rows, as read.
    timeline: Option<Timeline>,
    /// Why the TUI cannot go on: the daemon stopped.
    ended: Option<String>,
    /// Cancelled when the TUI is asked to stop (SIGHUP, SIGTERM): a wait on the daemon is given up
    /// then, so a stop is never held behind an answer (ADR-026 S-4).
    stop: tokio_util::sync::CancellationToken,
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
}

struct Projected {
    me: Option<Digest32>,
    trusted: Vec<(Digest32, String)>,
    len: usize,
    rows: std::sync::Arc<Vec<MessageView>>,
}

impl std::fmt::Debug for DaemonCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonCore")
            .field("node", &self.node.as_str())
            .field("attached", &self.conn.is_some())
            .finish_non_exhaustive()
    }
}

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
            tx,
            rx,
            daemon_events,
            snapshot: NodeSnapshot::default(),
            asked: None,
            active: None,
            unread: BTreeMap::new(),
            arrived: BTreeMap::new(),
            notified: BTreeSet::new(),
            notify_to,
            notify_off,
            notice: None,
            timeline: None,
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
            Ok(Err(vox_core::error::Error::Profile(_))) => {
                CommandStatus::Failed(UiError::IdentityExists)
            }
            Ok(Err(vox_core::error::Error::ProfileBusy)) => {
                CommandStatus::Failed(UiError::ProfileBusy)
            }
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
                self.notice = Some(format!("room link: {url}"));
                CommandStatus::Said(format!("room link: {url}"))
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
                .and_then(|r| r.local_name.clone())
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
                *me.unread.entry(channel_id).or_insert(0) += n;
                *me.arrived.entry(channel_id).or_insert(0) += n;
            }
        };
        match ev {
            NodeEvent::NewEntry { channel_id, .. } => rows_in(self, channel_id, 1),
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
                self.notice = Some(format!("room link: {url}"));
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
            NodeEvent::PeerJoined { peer, .. } => {
                self.notice = Some(format!(
                    "{} joined — they read nothing until you trust them",
                    self.member_name(&peer)
                ));
            }
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
        let body = vox_core::node::snapshot::request_body();
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let Some(answer) = until_stopped(&self.rt, &self.stop, conn.client.exchange(&body)) else {
            return;
        };
        match answer {
            Ok(reply) => match NodeSnapshot::from_bytes(&reply) {
                Ok(Some(s)) => self.snapshot = s,
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

    /// Read the room on screen: whole when it first comes on screen, or when a late row or an
    /// unknown cursor says the order changed above what is shown; else only what arrived since.
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
                self.timeline = Some(Timeline {
                    channel_id: cid,
                    cursor: newest(&rows),
                    rows,
                    stale: false,
                    projected: None,
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
    ) -> std::sync::Arc<Vec<MessageView>> {
        let Some(t) = self.timeline.as_mut() else {
            return std::sync::Arc::default();
        };
        let view_of = |r: &MessageRow| MessageView {
            author: r.author,
            author_nick: if me == Some(r.author) {
                "you".to_owned()
            } else {
                crate::ident::member_name(trusted, &r.author)
            },
            // The wire names addressees by fingerprint; the timeline by this node's own names.
            addressed: if r.owed {
                String::new()
            } else {
                crate::agent_hook::addressed(&r.text, me.as_ref(), trusted)
            },
            // Displayed as a time of day, so seconds; the full precision is kept for ordering.
            timestamp: r.created_millis / 1_000,
            // As `vox room read` and the drain show it, a structured post by its words (#406).
            body: Some(if r.owed {
                vox_core::node::api::NOT_RECEIVED_YET.to_owned()
            } else {
                crate::agent_hook::words(&r.text)
            }),
            late: r.late,
        };
        match t.projected.as_mut() {
            Some(p) if p.me == me && p.trusted.as_slice() == trusted && p.len <= t.rows.len() => {
                if p.len < t.rows.len() {
                    std::sync::Arc::make_mut(&mut p.rows)
                        .extend(t.rows[p.len..].iter().map(view_of));
                    p.len = t.rows.len();
                }
                std::sync::Arc::clone(&p.rows)
            }
            _ => {
                let rows = std::sync::Arc::new(t.rows.iter().map(view_of).collect::<Vec<_>>());
                t.projected = Some(Projected {
                    me,
                    trusted: trusted.to_vec(),
                    len: t.rows.len(),
                    rows: std::sync::Arc::clone(&rows),
                });
                rows
            }
        }
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
        let channels = snap
            .rooms
            .iter()
            .map(|c| ChannelSummary {
                open: c.open,
                channel_id: c.channel_id,
                local_name: c
                    .local_name
                    .clone()
                    .unwrap_or_else(|| format!("(closed {})", short_id(&c.channel_id))),
                unread: self.unread.get(&c.channel_id).copied().unwrap_or(0),
                reachability: reachability(&c.channel_id),
            })
            .collect();
        let timeline = self
            .active
            .filter(|cid| snap.open.iter().any(|d| d.channel_id == *cid))
            .map(|_| self.project_timeline(me, &snap.trusted));
        let active = self.active.and_then(|cid| {
            snap.open
                .iter()
                .find(|d| d.channel_id == cid)
                .map(|d| ChannelView {
                    channel_id: d.channel_id,
                    local_name: d.local_name.clone(),
                    members: d
                        .members
                        .iter()
                        .map(|m| {
                            let is_me = me == Some(*m);
                            MemberView {
                                id: *m,
                                nickname: if is_me {
                                    "you".to_owned()
                                } else {
                                    crate::ident::member_name(&snap.trusted, m)
                                },
                                // Off the keyring and the room's log: this node releases its key
                                // only to a member its keyring trusts (V210-148), and takes a
                                // member's key only if it trusts it.
                                trust: {
                                    let reads_you = d.consented.binary_search(m).is_ok();
                                    if is_me {
                                        Trust::You
                                    } else if snap.trusted.iter().any(|(t, _)| t == m) {
                                        Trust::Trusted { reads_you }
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
                        let mut names = vox_core::node::resolver::VoxResolver::new();
                        for o in &snap.open {
                            names.add_room(o.channel_id, &o.local_name, &o.members);
                        }
                        for (fp, petname) in &snap.trusted {
                            names.name(*fp, petname);
                        }
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
                                format!(
                                    "{} by {who}  {kind}{udp}",
                                    names.address_of(&d.channel_id, &s.host, &s.name)
                                )
                            })
                            .collect()
                    },
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
            mlock_active: snap.mlock_active,
            keyring_open_secs: snap.keyring_open_secs,
            has_identity: self.has_identity,
            tunnels: snap.tunnels,
            closed_tunnels: snap.closed_tunnels,
        }
    }

    /// Act as `name` from now on: let go of the node acted as (which detaches it if this TUI was
    /// its last holder, L-3) and take `name`, attached already or waiting for its passphrase.
    fn use_node(&mut self, name: &str) -> CommandStatus {
        let node = match NodeName::parse(name) {
            Ok(n) => n,
            Err(e) => return CommandStatus::Said(format!("{name:?} is not a node's name: {e}")),
        };
        if node == self.node && self.conn.is_some() {
            return CommandStatus::Done;
        }
        if !self.account.nodes_on_disk().contains(&node) {
            return CommandStatus::Said(format!(
                "there is no node {node}; make one with `vox node create {node}`"
            ));
        }
        self.conn = None;
        self.node = node;
        self.has_identity = true;
        self.active = None;
        self.timeline = None;
        self.unread.clear();
        self.snapshot = NodeSnapshot::default();
        self.notice = None;
        if self.attached.iter().any(|n| n == self.node.as_str()) {
            self.attach(None)
        } else {
            CommandStatus::Done
        }
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
    match refusal {
        Refusal::WrongPassphrase { .. } => CommandStatus::Failed(UiError::WrongPassphrase),
        Refusal::NodeInUse { .. } => CommandStatus::Failed(UiError::ProfileBusy),
        Refusal::NoIdentity { .. } => CommandStatus::Failed(UiError::NoIdentity),
        other => CommandStatus::Said(one_line(&other.to_string())),
    }
}

/// A node's error answer, as the TUI says it: the fault it names, mapped onto the UI's closed set
/// — or in the fault's own words where the closed set has none that fit — or the node's own
/// sentence when it names none.
fn failed(reason: &str) -> CommandStatus {
    match Fault::from_explanation(reason) {
        Some(f) => fault_status(f),
        None => CommandStatus::Said(reason.lines().next().unwrap_or_default().to_owned()),
    }
}

/// How the TUI says fault `f`: the UI's closed set where it has the words, else the words the CLI
/// prints for `f`, on one line (R36: a refusal names its own cause).
fn fault_status(f: Fault) -> CommandStatus {
    if in_its_own_words(f) {
        CommandStatus::Said(one_line(f.explain()))
    } else {
        CommandStatus::Failed(ui_error(f))
    }
}

/// Faults the UI's closed set would say wrongly: a file that could not be written is named by
/// the fault and by nothing in the set, and "may end it" is not what an admin change or an idle
/// end is refused for, nor is "no reachable peer" a member that left the room.
const fn in_its_own_words(f: Fault) -> bool {
    matches!(
        f,
        Fault::Storage
            | Fault::IdentityFileUnwritable
            | Fault::RetentionFileUnwritable
            | Fault::NotCreator
            | Fault::NotRoomCreator
            | Fault::ResponderLeft
    )
}

/// `text`'s lines as one status line: a fault's advice follows its cause after a dash.
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" — ")
}

/// Map a node [`Fault`] onto the UI's closed error set.
#[must_use]
pub fn ui_error(f: Fault) -> UiError {
    match f {
        Fault::NoIdentity => UiError::NoIdentity,
        Fault::IdentityExists => UiError::IdentityExists,
        Fault::ProfileBusy => UiError::ProfileBusy,
        Fault::Locked => UiError::NotAttached,
        Fault::WrongPassphrase => UiError::WrongPassphrase,
        Fault::UnknownChannel | Fault::ChannelNotOpen => UiError::ChannelNotOpen,
        Fault::TooLong => UiError::TooLong,
        Fault::KeyringFull => UiError::KeyringFull,
        Fault::Storage | Fault::IdentityFileUnwritable | Fault::RetentionFileUnwritable => {
            UiError::Storage
        }
        Fault::SealedUnreadable => UiError::SealedUnreadable,
        Fault::ShuttingDown | Fault::Internal => UiError::Internal,
        // A link that will not parse is malformed input, not a network failure.
        Fault::BadLink => UiError::Malformed,
        // Nobody has published the room where we looked: a reachability problem, not bad input.
        Fault::Unreachable | Fault::BoardUnreachable | Fault::RoomNotOnBoard => {
            UiError::Unreachable
        }
        Fault::SolveTooSlow => UiError::JoinPowTooSlow,
        Fault::MembersBusy => UiError::JoinMembersBusy,
        Fault::RoomFull => UiError::JoinRoomFull,
        Fault::NotAdmittedAfterJoin => UiError::JoinNotAdmitted,
        Fault::Refused => UiError::Refused,
        Fault::NotAdmitted => UiError::NotAdmitted,
        Fault::JoinedRoomEnded => UiError::RoomEnded,
        Fault::ResponderLeft => UiError::Unreachable,
        Fault::NotConsented => UiError::NotConsented,
        Fault::NotNetworked => UiError::NotNetworked,
        Fault::AddressInUse => UiError::AddressInUse,
        Fault::AddressNotHere => UiError::AddressNotHere,
        Fault::BindFailed => UiError::BindFailed,
        Fault::AlreadyMember => UiError::AlreadyMember,
        Fault::RoomEnded => UiError::RoomEnded,
        Fault::LeaveNotHeard => UiError::LeaveNotHeard,
        Fault::LeaveUndone => UiError::LeaveUndone,
        Fault::NotCreator | Fault::NotRoomCreator => UiError::NotCreator,
        Fault::RoomNotSynced => UiError::StillJoining,
        #[allow(unreachable_patterns)]
        _ => UiError::Internal,
    }
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
        self.project()
    }

    fn apply(&mut self, command: Command) -> CommandStatus {
        self.apply_noting(command, &mut || {})
    }

    fn apply_noting(&mut self, command: Command, waiting: &mut dyn FnMut()) -> CommandStatus {
        let secret = |s: &SecretString| s.expose_secret().to_owned();
        match command {
            Command::CreateIdentity { passphrase } => self.create_identity(&passphrase, waiting),
            Command::Attach { passphrase } => {
                if self.conn.is_some() {
                    return CommandStatus::Done;
                }
                self.attach(Some(Zeroizing::new(passphrase.expose_secret().to_owned())))
            }
            Command::UseNode { name } => self.use_node(&name),
            Command::CreateChannel {
                local_name,
                passphrase,
            } => self.send(Request::Create {
                local_name,
                passphrase: Zeroizing::new(secret(&passphrase)),
            }),
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
                // Answered once another member has the leave; the room is gone then.
                let status = self.send(Request::Leave { channel_id });
                if matches!(status, CommandStatus::Done) && self.active == Some(channel_id) {
                    self.active = None;
                }
                status
            }
            Command::EndRoom { channel_id } => self.send(Request::End { channel_id }),
            Command::SelectChannel { channel_id } => {
                self.active = channel_id;
                if let Some(cid) = channel_id {
                    self.unread.remove(&cid);
                    // Looked at: the next message there is news again.
                    self.notified.remove(&cid);
                }
                CommandStatus::Done
            }
            Command::SendText { channel_id, text } => {
                let status = self.send(Request::Post { channel_id, text });
                if let Some(t) = self
                    .timeline
                    .as_mut()
                    .filter(|t| t.channel_id == channel_id)
                {
                    t.stale = true;
                }
                status
            }
            Command::Join {
                local_name,
                link,
                passphrase,
            } => self.send(Request::Join {
                link,
                local_name,
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
