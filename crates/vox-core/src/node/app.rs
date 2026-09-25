//! ADR-022 decision 7 — **the app API**: a program on one member node opens a live
//! stream, and optionally a datagram flow, to a program on another.
//!
//! This is what the decider's chat-and-calls app sits on (PRD-001 R29–R32): Vox carries
//! the bytes, encrypted and through NAT on both sides; the app decides what they mean.
//! It is a third application on the overlay beside rooms and room-bound services, and it
//! reuses their machinery rather than growing its own: a typed QUIC stream
//! ([`StreamKind::App`]), the room's author set, the node's trust keyring, and the live
//! [`Reachers`] watch that already tears tunnels down when trust is withdrawn.
//!
//! ## The exchange
//!
//! ```text
//! opener → responder   [kind 8]                                (the stream kind frame)
//! opener → responder   [1, channel_id, [label, … ≤8], flags]   (AppOpen, within 5 s)
//! responder → opener   [1, label]  |  [0, reason]              (answer)
//! ```
//!
//! Labels are libp2p-style `name/vN`, at most 64 ASCII bytes, with no registry: an
//! incompatible change is a new label. The responder takes the **first** label the opener
//! offered that a local program is listening for. `flags` bit 0 asks for a datagram flow
//! bound to the stream.
//!
//! ## The gate runs in both directions
//!
//! Each side gives the other data, so each side decides:
//!
//! - the **responder** serves only an opener that is in *its* keyring **and** a current
//!   author of the room named in `AppOpen`;
//! - the **opener's** node refuses to open at all unless the target is in *its* keyring
//!   (and an author of the room). Nothing is dialled for a refused open.
//!
//! Both read the same live set the tunnel gate reads — the node's ring joined with the
//! room's authors — so withdrawing trust on either side tears a live stream down: each
//! [`AppStream`] watches it and resets with [`APP_WITHDRAWN_CODE`] the moment its peer
//! leaves.
//!
//! ## Refusal has two tiers
//!
//! A peer that is **not trusted** gets exactly the reset a stream kind it may not open
//! gets — and, since this change, exactly what an unknown kind gets
//! ([`crate::transport::streams::refuse`]). So an untrusted peer cannot tell whether an
//! app is running, listening, or even whether the node knows the kind. A peer that **is**
//! trusted is told why: `no-listener`, `busy` or `refused`.
//!
//! ## Limits
//!
//! An app stream is opened by another program, so a peer can open many and leave them
//! waiting. Each peer gets at most [`MAX_APP_STREAMS_PER_PEER`] app streams at once and an
//! open-rate bucket of about [`OPEN_RATE_PER_SEC`] a second; its `AppOpen` must arrive
//! within [`OPEN_DEADLINE`]; an incoming stream no program accepts within
//! [`ACCEPT_DEADLINE`] is refused; and app streams are sent at [`APP_PRIORITY`], below the
//! node's own sync, join and pairwise traffic. The connection's own stream limit is set
//! explicitly ([`crate::transport::quic::MAX_CONCURRENT_BIDI_STREAMS`]).
//!
//! App streams are **live only**: nothing is queued for an absent program. Anything that
//! must survive belongs in the room's log.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use quinn::{RecvStream, SendStream};
use tokio::sync::{mpsc, oneshot};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::tunnel::Reachers;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::router::{DatagramFlow, FlowSender};
use crate::transport::streams::{open_typed, refuse, StreamKind};

/// At most this many labels in one `AppOpen`.
pub const MAX_LABELS: usize = 8;

/// A label is at most this many ASCII bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// At most this many app streams with any one peer at once, counted at the responder
/// from the moment one is admitted until it ends.
pub const MAX_APP_STREAMS_PER_PEER: usize = 16;

/// The open-rate bucket: about this many new app streams a second from any one peer...
pub const OPEN_RATE_PER_SEC: f64 = 10.0;

/// ...with at most this many at once.
pub const OPEN_BURST: f64 = 10.0;

/// The opener's `AppOpen` must arrive this soon after the stream opens.
pub const OPEN_DEADLINE: Duration = Duration::from_secs(5);

/// An incoming app stream no local program accepts in this long is refused.
pub const ACCEPT_DEADLINE: Duration = Duration::from_secs(5);

/// How long an opener waits for the answer: the responder's accept deadline, and room
/// for a slow path on top of it.
const ANSWER_DEADLINE: Duration = Duration::from_secs(15);

/// The send priority of an app stream. quinn sends higher priorities first and the
/// node's own streams run at the default 0, so app bytes never delay a sync, a join or a
/// sender key.
pub const APP_PRIORITY: i32 = -1;

/// The QUIC error code an app stream is reset with when trust is withdrawn mid-stream.
pub const APP_WITHDRAWN_CODE: u32 = 0x2207;

/// The largest `AppOpen` or answer: eight maximal labels and a room fit well inside.
const MAX_OPEN_FRAME: usize = 1024;

/// `flags` bit 0: bind a datagram flow to the stream.
const FLAG_DATAGRAMS: u64 = 1;

/// Whether `label` is a label: 1 to [`MAX_LABEL_LEN`] printable ASCII bytes, no spaces.
#[must_use]
pub fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= MAX_LABEL_LEN && label.bytes().all(|b| b.is_ascii_graphic())
}

/// The opener's request: which room's gate applies, which apps it speaks, and whether it
/// wants a datagram flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppOpen {
    /// The room whose authors, joined with the responder's keyring, decide.
    pub channel_id: Digest32,
    /// The labels the opener speaks, in preference order.
    pub labels: Vec<String>,
    /// Bit 0: a datagram flow.
    pub flags: u64,
}

impl AppOpen {
    /// Canonical CBOR: `[1, channel_id, [labels…], flags]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4).uint(1).bytes(&self.channel_id);
        e.array(self.labels.len());
        for l in &self.labels {
            e.text(l);
        }
        e.uint(self.flags);
        e.finish()
    }

    /// Strict decode: version 1, a 32-byte room, 1 to 8 valid labels, no trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bad = |_| Error::StreamRefused("app: malformed open");
        let mut d = Decoder::new(bytes);
        if d.array().map_err(bad)? != 4 || d.uint().map_err(bad)? != 1 {
            return Err(Error::StreamRefused("app: malformed open"));
        }
        let channel_id = Digest32::try_from(d.bytes().map_err(bad)?)
            .map_err(|_| Error::StreamRefused("app: malformed open"))?;
        let n = d.array().map_err(bad)?;
        if n == 0 || n > MAX_LABELS {
            return Err(Error::StreamRefused("app: malformed open"));
        }
        let mut labels = Vec::new();
        for _ in 0..n {
            let l = d.text().map_err(bad)?;
            if !valid_label(l) {
                return Err(Error::StreamRefused("app: malformed open"));
            }
            labels.push(l.to_owned());
        }
        let flags = d.uint().map_err(bad)?;
        d.finish().map_err(bad)?;
        Ok(Self {
            channel_id,
            labels,
            flags,
        })
    }
}

/// Why a **trusted** peer's app stream was refused. An untrusted one is told nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppRefusal {
    /// No program here listens for any label offered.
    NoListener,
    /// Too many app streams from this peer, or too many too fast.
    Busy,
    /// A program listens, but did not accept in time.
    Refused,
}

impl AppRefusal {
    /// The wire word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AppRefusal::NoListener => "no-listener",
            AppRefusal::Busy => "busy",
            AppRefusal::Refused => "refused",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "no-listener" => Some(AppRefusal::NoListener),
            "busy" => Some(AppRefusal::Busy),
            "refused" => Some(AppRefusal::Refused),
            _ => None,
        }
    }

    /// As the opener's error.
    fn error(self) -> Error {
        match self {
            AppRefusal::NoListener => {
                Error::StreamRefused("app: no-listener — nothing there listens for that label")
            }
            AppRefusal::Busy => {
                Error::StreamRefused("app: busy — too many app streams to that peer, or too fast")
            }
            AppRefusal::Refused => {
                Error::StreamRefused("app: refused — the program there did not accept in time")
            }
        }
    }
}

/// The responder's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppAnswer {
    /// Accepted, speaking this label.
    Accepted(String),
    /// Refused, and why.
    Refused(AppRefusal),
}

impl AppAnswer {
    /// Canonical CBOR: `[1, label]` or `[0, reason]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            AppAnswer::Accepted(label) => e.array(2).uint(1).text(label),
            AppAnswer::Refused(r) => e.array(2).uint(0).text(r.as_str()),
        };
        e.finish()
    }

    /// Strict decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bad = |_| Error::StreamRefused("app: malformed answer");
        let mut d = Decoder::new(bytes);
        if d.array().map_err(bad)? != 2 {
            return Err(Error::StreamRefused("app: malformed answer"));
        }
        let ok = d.uint().map_err(bad)?;
        let word = d.text().map_err(bad)?.to_owned();
        d.finish().map_err(bad)?;
        match ok {
            1 if valid_label(&word) => Ok(AppAnswer::Accepted(word)),
            0 => AppRefusal::parse(&word)
                .map(AppAnswer::Refused)
                .ok_or(Error::StreamRefused("app: malformed answer")),
            _ => Err(Error::StreamRefused("app: malformed answer")),
        }
    }
}

/// An incoming app stream waiting for a program to accept it with
/// [`AppHub::accept`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppIncoming {
    /// What [`AppHub::accept`] takes. Valid for [`ACCEPT_DEADLINE`].
    pub id: u64,
    /// The room the opener named.
    pub channel_id: Digest32,
    /// The opener.
    pub peer: Digest32,
    /// The label chosen.
    pub label: String,
}

/// What the app layer has done, for gates and `vox status`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AppStats {
    /// App streams that arrived from peers.
    pub inbound: u64,
    /// Refused because the opener is not in this node's keyring and the room's authors.
    pub refused_untrusted: u64,
    /// Refused as `busy`.
    pub refused_busy: u64,
    /// Refused as `no-listener`.
    pub refused_no_listener: u64,
    /// Refused because nobody accepted in time.
    pub refused_unaccepted: u64,
    /// Announced to a listening program.
    pub announced: u64,
    /// Accepted by a local program.
    pub accepted: u64,
    /// Opened by a local program and accepted by the peer.
    pub opened: u64,
    /// Opens this node refused before dialling, because the target is not in its ring.
    pub refused_locally: u64,
    /// Live app streams torn down because trust was withdrawn.
    pub withdrawn: u64,
}

#[derive(Default)]
struct Counters {
    inbound: AtomicU64,
    refused_untrusted: AtomicU64,
    refused_busy: AtomicU64,
    refused_no_listener: AtomicU64,
    refused_unaccepted: AtomicU64,
    announced: AtomicU64,
    accepted: AtomicU64,
    opened: AtomicU64,
    refused_locally: AtomicU64,
    withdrawn: AtomicU64,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// A request to the actor for a connection to `peer`, through the ADR-012 ladder.
pub struct AppDial {
    /// The room the peer is reached for (whose board has its addresses).
    pub channel_id: Digest32,
    /// Who to reach.
    pub peer: Digest32,
    /// Where the connection goes.
    pub reply: oneshot::Sender<Result<Arc<VoxConnection>>>,
}

impl std::fmt::Debug for AppDial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppDial").finish_non_exhaustive()
    }
}

struct PeerLimit {
    live: usize,
    tokens: f64,
    at: Instant,
}

type ListenKey = (Option<Digest32>, String);
type Acceptor = oneshot::Sender<AppStream>;

#[derive(Default)]
struct HubInner {
    listeners: HashMap<ListenKey, mpsc::Sender<AppIncoming>>,
    reachers: BTreeMap<Digest32, Reachers>,
    peers: HashMap<Digest32, PeerLimit>,
    pending: HashMap<u64, oneshot::Sender<Acceptor>>,
    next_id: u64,
}

/// The node's app layer: who listens for what, the live gate, the per-peer limits, and
/// the way to a connection. One per node, shared by the actor (which serves inbound app
/// streams and keeps the gate current) and every program using the API.
#[derive(Default)]
pub struct AppHub {
    inner: Mutex<HubInner>,
    dialer: Mutex<Option<mpsc::Sender<AppDial>>>,
    counters: Counters,
}

impl std::fmt::Debug for AppHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppHub").finish_non_exhaustive()
    }
}

impl AppHub {
    fn inner(&self) -> MutexGuard<'_, HubInner> {
        // Every critical section is a map operation with no `.await`, so the state is
        // consistent between them and a poisoned lock is safe to recover.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where connection requests go. Set once by the actor.
    pub(crate) fn set_dialer(&self, tx: mpsc::Sender<AppDial>) {
        *self.dialer.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);
    }

    /// The live gate for every room, as the actor recomputed it. The handles are the
    /// actor's own, so a stream holding one sees every later change.
    pub(crate) fn set_reachers(&self, reachers: &BTreeMap<Digest32, Reachers>) {
        self.inner().reachers = reachers.iter().map(|(k, v)| (*k, Arc::clone(v))).collect();
    }

    fn reachers_of(&self, channel_id: &Digest32) -> Option<Reachers> {
        self.inner().reachers.get(channel_id).map(Arc::clone)
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> AppStats {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        AppStats {
            inbound: g(&c.inbound),
            refused_untrusted: g(&c.refused_untrusted),
            refused_busy: g(&c.refused_busy),
            refused_no_listener: g(&c.refused_no_listener),
            refused_unaccepted: g(&c.refused_unaccepted),
            announced: g(&c.announced),
            accepted: g(&c.accepted),
            opened: g(&c.opened),
            refused_locally: g(&c.refused_locally),
            withdrawn: g(&c.withdrawn),
        }
    }

    /// Listen for app streams speaking `label`, in `channel_id` or (`None`) any room.
    ///
    /// Exclusive per (room, label): a second listener for the same pair is refused while
    /// the first lives. The registration ends when the [`AppListener`] is dropped.
    ///
    /// # Errors
    /// If the label is not a label, or somebody already listens for it.
    pub fn listen(
        self: &Arc<Self>,
        channel_id: Option<Digest32>,
        label: &str,
    ) -> Result<AppListener> {
        if !valid_label(label) {
            return Err(Error::StreamRefused(
                "app: a label is 1 to 64 printable ASCII bytes",
            ));
        }
        let key = (channel_id, label.to_owned());
        let (tx, rx) = mpsc::channel(64);
        let mut g = self.inner();
        if g.listeners.get(&key).is_some_and(|t| !t.is_closed()) {
            return Err(Error::StreamRefused(
                "app: something here already listens for that label",
            ));
        }
        g.listeners.insert(key.clone(), tx.clone());
        Ok(AppListener {
            key,
            tx,
            rx,
            hub: Arc::clone(self),
        })
    }

    /// Whether a program is listening for `label` in `channel_id` (or any room).
    #[must_use]
    pub fn is_listening(&self, channel_id: Option<Digest32>, label: &str) -> bool {
        self.inner()
            .listeners
            .get(&(channel_id, label.to_owned()))
            .is_some_and(|t| !t.is_closed())
    }

    /// Accept the incoming stream `id` that a listener was told about.
    ///
    /// # Errors
    /// If there is no such stream waiting — never announced, already accepted, or past
    /// [`ACCEPT_DEADLINE`].
    pub async fn accept(&self, id: u64) -> Result<AppStream> {
        let waiting = self
            .inner()
            .pending
            .remove(&id)
            .ok_or(Error::StreamRefused(
                "app: no such incoming stream is waiting",
            ))?;
        let (tx, rx) = oneshot::channel();
        waiting
            .send(tx)
            .map_err(|_| Error::StreamRefused("app: that incoming stream is gone"))?;
        rx.await
            .map_err(|_| Error::StreamRefused("app: that incoming stream is gone"))
    }

    /// Open an app stream to `peer`, speaking the first of `labels` it listens for.
    ///
    /// Refused here, before anything is dialled, unless `peer` is in this node's keyring
    /// and an author of `channel_id` — the opener's half of the two-way gate.
    ///
    /// # Errors
    /// If this node would not open it, the peer's node refused it, or it could not be
    /// reached. An untrusted refusal and an unreachable peer read the same.
    pub async fn open(
        self: &Arc<Self>,
        channel_id: Digest32,
        peer: Digest32,
        labels: Vec<String>,
        datagrams: bool,
    ) -> Result<AppStream> {
        if labels.is_empty() || labels.len() > MAX_LABELS || !labels.iter().all(|l| valid_label(l))
        {
            return Err(Error::StreamRefused(
                "app: offer 1 to 8 labels of 1 to 64 printable ASCII bytes",
            ));
        }
        let Some(reachers) = self.reachers_of(&channel_id) else {
            bump(&self.counters.refused_locally);
            return Err(Error::StreamRefused(
                "app: this node does not hold that room",
            ));
        };
        if !reachers.borrow().contains(&peer) {
            bump(&self.counters.refused_locally);
            return Err(Error::StreamRefused(
                "app: that peer is not in this node's keyring (or not in the room) — \
                 `vox trust add` it first",
            ));
        }
        let conn = self.dial(channel_id, peer).await?;
        let (mut send, mut recv) = open_typed(&conn, StreamKind::App).await?;
        let _ = send.set_priority(APP_PRIORITY);
        // Bound before the request goes out, so a datagram the responder sends the moment
        // it accepts has a flow to land on.
        let flow = if datagrams {
            Some(conn.bind_shared_flow(&send)?)
        } else {
            None
        };
        let open = AppOpen {
            channel_id,
            labels: labels.clone(),
            flags: if datagrams { FLAG_DATAGRAMS } else { 0 },
        };
        write_frame(&mut send, &open.to_bytes()).await?;
        // A reset here is the untrusted tier, or an unknown kind: deliberately the same
        // error, since the opener is not meant to learn which.
        let answer = match tokio::time::timeout(
            ANSWER_DEADLINE,
            read_frame(&mut recv, MAX_OPEN_FRAME),
        )
        .await
        {
            Ok(Ok(Some(frame))) => AppAnswer::from_bytes(&frame)?,
            _ => return Err(Error::StreamRefused("app: refused by the peer")),
        };
        let label = match answer {
            AppAnswer::Accepted(label) if labels.contains(&label) => label,
            AppAnswer::Accepted(_) => {
                return Err(Error::StreamRefused(
                    "app: the peer chose a label not offered",
                ))
            }
            AppAnswer::Refused(r) => return Err(r.error()),
        };
        bump(&self.counters.opened);
        Ok(AppStream::new(
            Arc::clone(self),
            AppInfo {
                channel_id,
                peer,
                label,
                datagrams,
            },
            send,
            recv,
            flow,
            reachers,
            None,
            conn,
        ))
    }

    async fn dial(&self, channel_id: Digest32, peer: Digest32) -> Result<Arc<VoxConnection>> {
        let tx = self
            .dialer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(Error::Unreachable("app: the node is not running"))?;
        let (reply, answer) = oneshot::channel();
        tx.send(AppDial {
            channel_id,
            peer,
            reply,
        })
        .await
        .map_err(|_| Error::Unreachable("app: the node is not running"))?;
        answer
            .await
            .map_err(|_| Error::Unreachable("app: the node is not running"))?
    }

    /// Take a place for one more app stream from `peer`, or `None` past either limit.
    fn admit(self: &Arc<Self>, peer: Digest32) -> Option<PeerSlot> {
        let now = Instant::now();
        let mut g = self.inner();
        let limit = g.peers.entry(peer).or_insert(PeerLimit {
            live: 0,
            tokens: OPEN_BURST,
            at: now,
        });
        let refill = now.duration_since(limit.at).as_secs_f64() * OPEN_RATE_PER_SEC;
        limit.tokens = (limit.tokens + refill).min(OPEN_BURST);
        limit.at = now;
        if limit.live >= MAX_APP_STREAMS_PER_PEER || limit.tokens < 1.0 {
            return None;
        }
        limit.tokens -= 1.0;
        limit.live += 1;
        Some(PeerSlot {
            hub: Arc::clone(self),
            peer,
        })
    }

    /// The listener for the first of `labels` served in `channel_id`: one bound to this
    /// room first, then one listening in any room.
    fn listener_for(
        &self,
        channel_id: &Digest32,
        labels: &[String],
    ) -> Option<(String, mpsc::Sender<AppIncoming>)> {
        let g = self.inner();
        labels.iter().find_map(|l| {
            [Some(*channel_id), None].into_iter().find_map(|room| {
                g.listeners
                    .get(&(room, l.clone()))
                    .filter(|t| !t.is_closed())
                    .map(|t| (l.clone(), t.clone()))
            })
        })
    }

    fn pend(&self) -> (u64, oneshot::Receiver<Acceptor>) {
        let (tx, rx) = oneshot::channel();
        let mut g = self.inner();
        g.next_id += 1;
        let id = g.next_id;
        g.pending.insert(id, tx);
        (id, rx)
    }
}

/// One place in a peer's app-stream limit, given back on drop.
struct PeerSlot {
    hub: Arc<AppHub>,
    peer: Digest32,
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        if let Some(l) = self.hub.inner().peers.get_mut(&self.peer) {
            l.live = l.live.saturating_sub(1);
        }
    }
}

/// A listening registration. Incoming streams arrive from [`AppListener::next`]; dropping
/// it stops listening.
pub struct AppListener {
    key: ListenKey,
    tx: mpsc::Sender<AppIncoming>,
    rx: mpsc::Receiver<AppIncoming>,
    hub: Arc<AppHub>,
}

impl std::fmt::Debug for AppListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppListener({})", self.key.1)
    }
}

impl AppListener {
    /// The next incoming stream to accept with [`AppHub::accept`].
    pub async fn next(&mut self) -> Option<AppIncoming> {
        self.rx.recv().await
    }
}

impl Drop for AppListener {
    fn drop(&mut self) {
        let mut g = self.hub.inner();
        if g.listeners
            .get(&self.key)
            .is_some_and(|t| t.same_channel(&self.tx))
        {
            g.listeners.remove(&self.key);
        }
    }
}

/// What an app stream is: whose, which room's gate admitted it, and what it speaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppInfo {
    /// The room.
    pub channel_id: Digest32,
    /// The program's node at the other end.
    pub peer: Digest32,
    /// The label both sides speak.
    pub label: String,
    /// Whether a datagram flow is bound to it.
    pub datagrams: bool,
}

struct StreamInner {
    send: tokio::sync::Mutex<SendStream>,
    recv: tokio::sync::Mutex<RecvStream>,
    flow: tokio::sync::Mutex<Option<DatagramFlow>>,
    flow_tx: Option<FlowSender>,
    reachers: Reachers,
    peer: Digest32,
    withdrawn: AtomicBool,
    hub: Arc<AppHub>,
    _slot: Option<PeerSlot>,
    /// **The connection this stream rides, held for the stream's life.** When a better
    /// path to the peer appears, the old connection is retired, and it is closed once its
    /// grace runs out *unless somebody still holds it* (`NodeNet::retire_expired`). A
    /// tunnel holds its connection for that reason; an app stream held only the QUIC
    /// stream halves, which do not count. So a call placed while the path was still
    /// relayed, or before a crossing dial was settled, was cut the moment the path
    /// improved: calls_foundation_proof's mesh saw three of twelve directions stop
    /// mid-call, their senders' flows closed under them about 16 s in.
    _carried: Arc<VoxConnection>,
}

impl StreamInner {
    /// Tear the stream down because trust was withdrawn: reset both halves with
    /// [`APP_WITHDRAWN_CODE`], so the peer learns it was a decision and not an ending,
    /// and drop the flow. Once only, whoever notices first.
    ///
    /// **Whoever notices first must be the one to do it.** Every call on the stream races
    /// the same withdrawal the guardian waits for, and a call used to return its error and
    /// leave the teardown to the guardian. When the caller then dropped the stream — which
    /// the IPC splice does the moment a call fails — the drop aborted the guardian before
    /// it ran, and the stream was *finished* rather than reset: the peer read a clean end
    /// of stream, took it for the other program hanging up, and stayed open waiting for
    /// input. Measured: 6 runs in 30 of `withdrawing_trust_tears_down_a_live_app_stream`,
    /// every one with this side cut in ~18 ms, the peer still running 5 s later, and
    /// `withdrawn: 0`. So every path that observes the withdrawal tears down before it
    /// returns, and [`AppStream`]'s drop does too if nothing has yet.
    async fn tear_down(&self) {
        if self.withdrawn.swap(true, Ordering::SeqCst) {
            return;
        }
        bump(&self.hub.counters.withdrawn);
        // Every call races the same withdrawal, so each lock below is released as soon
        // as the call holding it notices.
        let code = quinn::VarInt::from_u32(APP_WITHDRAWN_CODE);
        let _ = self.send.lock().await.reset(code);
        let _ = self.recv.lock().await.stop(code);
        self.flow.lock().await.take();
    }

    /// Resolves when `peer` stops being in the gate — trust withdrawn on this side, or
    /// the peer no longer an author of the room, or the room gone.
    async fn withdrawal(&self) {
        let mut rx = self.reachers.subscribe();
        loop {
            if !rx.borrow_and_update().contains(&self.peer) {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// A live app stream, and its datagram flow if one was asked for.
///
/// Every method takes `&self`, so one task can read while another writes (hold it in an
/// `Arc`). It ends when dropped: the stream is finished, and the flow with it.
///
/// **It is torn down when trust is withdrawn.** A guardian watches the gate this stream
/// was admitted by; the moment the peer leaves it, both halves are reset with
/// [`APP_WITHDRAWN_CODE`], the flow is dropped, and every call fails.
pub struct AppStream {
    info: AppInfo,
    inner: Arc<StreamInner>,
    guardian: tokio::task::AbortHandle,
}

impl std::fmt::Debug for AppStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppStream({})", self.info.label)
    }
}

impl Drop for AppStream {
    fn drop(&mut self) {
        self.guardian.abort();
        // Dropped after trust was withdrawn but before anything tore it down: reset now,
        // or the halves are finished on drop and the peer reads a clean ending.
        let inner = &self.inner;
        if !inner.reachers.borrow().contains(&inner.peer)
            && !inner.withdrawn.swap(true, Ordering::SeqCst)
        {
            bump(&inner.hub.counters.withdrawn);
            let code = quinn::VarInt::from_u32(APP_WITHDRAWN_CODE);
            if let Ok(mut send) = inner.send.try_lock() {
                let _ = send.reset(code);
            }
            if let Ok(mut recv) = inner.recv.try_lock() {
                let _ = recv.stop(code);
            }
        }
    }
}

fn withdrawn_error() -> Error {
    Error::TunnelRevoked("app: trust was withdrawn, so the app stream was closed")
}

impl AppStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        hub: Arc<AppHub>,
        info: AppInfo,
        send: SendStream,
        recv: RecvStream,
        flow: Option<DatagramFlow>,
        reachers: Reachers,
        slot: Option<PeerSlot>,
        carried: Arc<VoxConnection>,
    ) -> Self {
        let flow_tx = flow.as_ref().map(DatagramFlow::sender);
        let inner = Arc::new(StreamInner {
            send: tokio::sync::Mutex::new(send),
            recv: tokio::sync::Mutex::new(recv),
            flow: tokio::sync::Mutex::new(flow),
            flow_tx,
            reachers,
            peer: info.peer,
            withdrawn: AtomicBool::new(false),
            hub,
            _slot: slot,
            _carried: carried,
        });
        let guarded = Arc::clone(&inner);
        let guardian = tokio::spawn(async move {
            guarded.withdrawal().await;
            guarded.tear_down().await;
        })
        .abort_handle();
        Self {
            info,
            inner,
            guardian,
        }
    }

    /// Whose stream this is and what it speaks.
    #[must_use]
    pub fn info(&self) -> &AppInfo {
        &self.info
    }

    fn check(&self) -> Result<()> {
        if self.inner.withdrawn.load(Ordering::SeqCst) {
            Err(withdrawn_error())
        } else {
            Ok(())
        }
    }

    /// Read into `buf`: `Some(n)` bytes, or `None` at the peer's end of stream.
    /// Cancel-safe.
    ///
    /// # Errors
    /// If trust was withdrawn on either side, or the stream failed.
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        self.check()?;
        let read = {
            let mut recv = self.inner.recv.lock().await;
            tokio::select! {
                r = recv.read(buf) => Some(r),
                () = self.inner.withdrawal() => None,
            }
        };
        match read {
            Some(r) => r.map_err(|e| match e {
                quinn::ReadError::Reset(code)
                    if code.into_inner() == u64::from(APP_WITHDRAWN_CODE) =>
                {
                    Error::TunnelRevoked(
                        "app: the peer withdrew trust, so the app stream was closed",
                    )
                }
                _ => Error::MalformedTunnel("app stream read"),
            }),
            // Torn down here, not left to the guardian: see `StreamInner::tear_down`.
            None => {
                self.inner.tear_down().await;
                Err(withdrawn_error())
            }
        }
    }

    /// Write all of `data`.
    ///
    /// # Errors
    /// If trust was withdrawn, or the stream failed.
    pub async fn write_all(&self, data: &[u8]) -> Result<()> {
        self.check()?;
        let wrote = {
            let mut send = self.inner.send.lock().await;
            tokio::select! {
                r = send.write_all(data) => Some(r),
                () = self.inner.withdrawal() => None,
            }
        };
        match wrote {
            Some(r) => r.map_err(|_| Error::MalformedTunnel("app stream write")),
            None => {
                self.inner.tear_down().await;
                Err(withdrawn_error())
            }
        }
    }

    /// End this side's half of the stream.
    pub async fn finish(&self) {
        let _ = self.inner.send.lock().await.finish();
    }

    /// How long this stream's datagrams may wait to be sent before they are dropped
    /// instead ([`crate::transport::router::DEFAULT_MAX_AGE`] until set). A call keeps the
    /// default; a transfer that would rather arrive late than not at all sets it high.
    pub fn set_datagram_max_age(&self, max_age: Duration) {
        if let Some(tx) = &self.inner.flow_tx {
            tx.set_max_age(max_age);
        }
    }

    /// Send one datagram on the flow.
    ///
    /// # Errors
    /// If no flow was asked for, it has ended, or trust was withdrawn.
    pub fn send_datagram(&self, packet: &[u8]) -> Result<()> {
        self.check()?;
        self.inner
            .flow_tx
            .as_ref()
            .ok_or(Error::StreamRefused("app: no datagram flow on this stream"))?
            .send(packet)
    }

    /// The next datagram, or `None` once the flow has ended. Cancel-safe.
    pub async fn recv_datagram(&self) -> Option<Vec<u8>> {
        if self.check().is_err() {
            return None;
        }
        let got = {
            let mut flow = self.inner.flow.lock().await;
            let flow = flow.as_mut()?;
            tokio::select! {
                d = flow.recv() => Some(d),
                () = self.inner.withdrawal() => None,
            }
        };
        match got {
            Some(d) => d,
            None => {
                self.inner.tear_down().await;
                None
            }
        }
    }

    /// Resolves once trust is withdrawn and this stream has been torn down — reset on
    /// both halves, so the peer learns it was a decision.
    pub async fn withdrawn(&self) {
        self.inner.withdrawal().await;
        self.inner.tear_down().await;
    }
}

/// Answer a trusted peer with a refusal it may read, then end the stream.
async fn answer_refused(send: &mut SendStream, reason: AppRefusal) {
    let _ = write_frame(send, &AppAnswer::Refused(reason).to_bytes()).await;
    let _ = send.finish();
}

/// Serve one inbound app stream: read `AppOpen`, run the responder's gate, find a
/// listener, wait for a program to accept, and hand it the stream.
pub async fn serve_inbound(
    hub: Arc<AppHub>,
    conn: Arc<VoxConnection>,
    peer: Digest32,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    bump(&hub.counters.inbound);
    let open =
        match tokio::time::timeout(OPEN_DEADLINE, read_frame(&mut recv, MAX_OPEN_FRAME)).await {
            Ok(Ok(Some(frame))) => AppOpen::from_bytes(&frame).ok(),
            _ => None,
        };
    // The untrusted tier, and anything malformed or late: the same reset a forbidden or
    // unknown stream kind gets, and nothing else. The room is read from the request, so
    // this is also the answer for a room this node does not hold.
    let gate = open
        .as_ref()
        .and_then(|o| hub.reachers_of(&o.channel_id).map(|r| (o, r)))
        .filter(|(_, r)| r.borrow().contains(&peer));
    let Some((open, reachers)) = gate else {
        bump(&hub.counters.refused_untrusted);
        refuse(&mut send, &mut recv);
        return;
    };
    // Trusted from here: a refusal says why.
    let Some(slot) = hub.admit(peer) else {
        bump(&hub.counters.refused_busy);
        answer_refused(&mut send, AppRefusal::Busy).await;
        return;
    };
    let Some((label, listener)) = hub.listener_for(&open.channel_id, &open.labels) else {
        bump(&hub.counters.refused_no_listener);
        answer_refused(&mut send, AppRefusal::NoListener).await;
        return;
    };
    let (id, accepted) = hub.pend();
    let incoming = AppIncoming {
        id,
        channel_id: open.channel_id,
        peer,
        label: label.clone(),
    };
    if listener.try_send(incoming).is_err() {
        hub.inner().pending.remove(&id);
        bump(&hub.counters.refused_no_listener);
        answer_refused(&mut send, AppRefusal::NoListener).await;
        return;
    }
    bump(&hub.counters.announced);
    let acceptor = match tokio::time::timeout(ACCEPT_DEADLINE, accepted).await {
        Ok(Ok(acceptor)) => acceptor,
        _ => {
            hub.inner().pending.remove(&id);
            bump(&hub.counters.refused_unaccepted);
            answer_refused(&mut send, AppRefusal::Refused).await;
            return;
        }
    };
    let _ = send.set_priority(APP_PRIORITY);
    let datagrams = open.flags & FLAG_DATAGRAMS != 0;
    // Bound before the answer, so the opener's first datagram has a flow to land on.
    let flow = if datagrams {
        match conn.bind_shared_flow(&send) {
            Ok(f) => Some(f),
            Err(_) => {
                answer_refused(&mut send, AppRefusal::Refused).await;
                return;
            }
        }
    } else {
        None
    };
    if write_frame(&mut send, &AppAnswer::Accepted(label.clone()).to_bytes())
        .await
        .is_err()
    {
        return;
    }
    bump(&hub.counters.accepted);
    let stream = AppStream::new(
        Arc::clone(&hub),
        AppInfo {
            channel_id: open.channel_id,
            peer,
            label,
            datagrams,
        },
        send,
        recv,
        flow,
        reachers,
        Some(slot),
        conn,
    );
    // A program that asked and then went away drops the stream, which ends it.
    let _ = acceptor.send(stream);
}
