//! The one reader of a connection's datagrams, and the flows it routes them to
//! (ADR-022 decisions 1 and 3).
//!
//! quinn gives a connection a single datagram queue. Anything that wants datagrams —
//! a relay circuit, a UDP tunnel, an app's media — would otherwise race every other
//! consumer for it, and whichever read a datagram would have to know whose it was. So
//! each [`VoxConnection`](crate::transport::quic::VoxConnection) runs exactly one
//! [`DatagramRouter`], started with the connection, and it is the **only** caller of
//! `read_datagram`. It reads the flow ID off each datagram ([`crate::transport::datagram`])
//! and hands the datagram to that flow's bounded inbox.
//!
//! ## A flow is a stream's datagrams
//! A flow is opened by binding a bidirectional stream the two sides already share
//! ([`VoxConnection::bind_flow`](crate::transport::quic::VoxConnection::bind_flow)),
//! and it lives **exactly as long as that stream**. The binding takes ownership of the
//! stream, so nothing else can hold it open, and a watcher ends the flow the moment the
//! stream ends in either direction — the peer finishing it, resetting it, stopping it,
//! or the connection going. Unregistering is therefore not something a caller can
//! forget: dropping the [`DatagramFlow`] ends the stream, and the stream ending ends
//! the flow on both sides.
//!
//! Authorization happens once, on the stream, by the gate that stream's kind already
//! has; a datagram is accepted only for a flow whose stream got through it.
//!
//! ### The flow ID is the whole stream ID, not a quarter of it
//! ADR-022 as first written took RFC 9297's Quarter Stream ID, `stream_id / 4`. That is
//! unique in HTTP/3 only because only a client opens request streams. On a Vox
//! connection **both** ends open bidirectional streams — a relay opens its circuit
//! stream to a target that may have dialled it — and the client's stream 0 and the
//! server's stream 1 have the same quarter. The full stream ID is unique on the
//! connection, known to both ends, and costs one varint byte more only past stream 63.
//!
//! ## Loss, never stall
//! A datagram for an unknown flow, one for a flow whose inbox is full, and one that
//! cannot be parsed are all **dropped and counted** ([`DatagramStats`]). A slow consumer
//! loses its own packets and never delays another flow's, which is the property the
//! whole seam exists for: a datagram that cannot be delivered now is worth nothing
//! later.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::error::{Error, Result};
use crate::transport::datagram::{
    fragment, frame_packet, parse_body, reframe, take_varint, varint_len, Discarded, Parsed,
    Reassembled, Reassembler, Unparsable,
};

/// How many datagrams a flow's inbox holds before newer ones are dropped.
pub const FLOW_INBOX: usize = 256;

/// The largest header a whole packet can carry: an 8-byte flow ID and a 1-byte
/// context.
pub const MAX_PACKET_HEADER: usize = 9;

/// What a flow's reader receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowMode {
    /// Whole packets: fragments are reassembled before delivery. What an end uses.
    Packets,
    /// Each datagram's `context ‖ body` exactly as it arrived, fragments included and
    /// nothing reassembled. What a relay uses: it moves datagrams from one flow to
    /// another ([`DatagramFlow::forward`]) and never reads them.
    Forward,
}

/// A connection's datagram counters: what arrived, where it went, and every reason one
/// was dropped. Read with
/// [`VoxConnection::datagram_stats`](crate::transport::quic::VoxConnection::datagram_stats).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DatagramStats {
    /// Datagrams (or reassembled packets) handed to a flow's inbox.
    pub delivered: u64,
    /// Datagrams for a flow that is not registered — never opened, or already ended.
    pub unknown_flow: u64,
    /// Datagrams dropped because their flow's inbox was full.
    pub inbox_full: u64,
    /// Datagrams whose header could not be parsed.
    pub malformed: u64,
    /// Datagrams with a context this version does not define.
    pub unknown_context: u64,
    /// Partial packets dropped because not every fragment arrived in time.
    pub reassembly_expired: u64,
    /// Partial packets dropped to stay inside the reassembly bounds.
    pub reassembly_evicted: u64,
    /// Partial packets dropped because a fragment contradicted the others.
    pub reassembly_rejected: u64,
    /// Datagrams handed to QUIC to send.
    pub sent: u64,
    /// Packets that went out as fragments.
    pub fragmented: u64,
    /// Packets (or forwarded datagrams) that could not be sent: too large to fragment,
    /// too large for the path, or refused by QUIC.
    pub send_dropped: u64,
}

#[derive(Default)]
struct Counters {
    delivered: AtomicU64,
    unknown_flow: AtomicU64,
    inbox_full: AtomicU64,
    malformed: AtomicU64,
    unknown_context: AtomicU64,
    reassembly_expired: AtomicU64,
    reassembly_evicted: AtomicU64,
    reassembly_rejected: AtomicU64,
    sent: AtomicU64,
    fragmented: AtomicU64,
    send_dropped: AtomicU64,
}

fn bump(c: &AtomicU64, by: u64) {
    c.fetch_add(by, Ordering::Relaxed);
}

struct Entry {
    tx: mpsc::Sender<Vec<u8>>,
    mode: FlowMode,
}

struct Table {
    flows: HashMap<u64, Entry>,
    /// Whether the [`VoxConnection`](crate::transport::quic::VoxConnection) that owns
    /// this router is still alive. The reader runs while it is, or while any flow is:
    /// a flow outliving the connection handle must still hear its datagrams, as a
    /// stream outliving it still hears its bytes.
    owner_alive: bool,
    reader: Option<AbortHandle>,
}

/// The per-connection datagram reader and flow table.
pub struct DatagramRouter {
    conn: Connection,
    table: Mutex<Table>,
    counters: Counters,
}

impl std::fmt::Debug for DatagramRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramRouter")
            .field("flows", &self.table().flows.len())
            .finish()
    }
}

impl DatagramRouter {
    /// Start the router for `conn`: from here on it is the connection's only datagram
    /// reader. Must be called inside a tokio runtime.
    pub(crate) fn start(conn: Connection) -> Arc<Self> {
        let router = Arc::new(Self {
            conn,
            table: Mutex::new(Table {
                flows: HashMap::new(),
                owner_alive: true,
                reader: None,
            }),
            counters: Counters::default(),
        });
        let task = tokio::spawn(Arc::clone(&router).read_loop());
        router.table().reader = Some(task.abort_handle());
        router
    }

    /// The connection handle is gone. The reader stops once no flow needs it, so an
    /// unused connection is not kept open by its own reader.
    pub(crate) fn release_owner(&self) {
        let mut t = self.table();
        t.owner_alive = false;
        Self::stop_if_unused(&mut t);
    }

    fn stop_if_unused(t: &mut Table) {
        if !t.owner_alive && t.flows.is_empty() {
            if let Some(reader) = t.reader.take() {
                reader.abort();
            }
        }
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        // Every critical section is a map operation with no `.await` inside, so the
        // table is consistent between them and a poisoned lock is safe to recover.
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> DatagramStats {
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        DatagramStats {
            delivered: get(&c.delivered),
            unknown_flow: get(&c.unknown_flow),
            inbox_full: get(&c.inbox_full),
            malformed: get(&c.malformed),
            unknown_context: get(&c.unknown_context),
            reassembly_expired: get(&c.reassembly_expired),
            reassembly_evicted: get(&c.reassembly_evicted),
            reassembly_rejected: get(&c.reassembly_rejected),
            sent: get(&c.sent),
            fragmented: get(&c.fragmented),
            send_dropped: get(&c.send_dropped),
        }
    }

    /// Bind a flow to the stream `send`/`recv`, taking ownership of it.
    pub(crate) fn bind(
        self: &Arc<Self>,
        send: SendStream,
        recv: RecvStream,
        mode: FlowMode,
    ) -> Result<DatagramFlow> {
        let id = u64::from(send.id());
        let (tx, rx) = mpsc::channel(FLOW_INBOX);
        {
            let mut t = self.table();
            if t.reader.is_none() || t.flows.contains_key(&id) {
                return Err(Error::Unreachable("datagram flow: cannot bind"));
            }
            t.flows.insert(id, Entry { tx, mode });
        }
        let watcher = tokio::spawn(watch(Arc::clone(self), id, send, recv)).abort_handle();
        Ok(DatagramFlow {
            id,
            router: Arc::clone(self),
            inbox: rx,
            next_packet: AtomicU64::new(0),
            cap: None,
            watcher,
        })
    }

    fn unregister(&self, id: u64) {
        let mut t = self.table();
        t.flows.remove(&id);
        Self::stop_if_unused(&mut t);
    }

    fn is_open(&self, id: u64) -> bool {
        self.table().flows.contains_key(&id)
    }

    async fn read_loop(self: Arc<Self>) {
        let mut reassembler = Reassembler::default();
        while let Ok(raw) = self.conn.read_datagram().await {
            self.route(&raw, &mut reassembler);
        }
        // The connection is gone: every flow's inbox closes, so every reader sees the
        // end rather than waiting for a datagram that cannot come, and nothing new can
        // bind.
        let mut t = self.table();
        t.flows.clear();
        t.reader = None;
    }

    fn route(&self, raw: &[u8], reassembler: &mut Reassembler) {
        let c = &self.counters;
        let Some((id, rest)) = take_varint(raw) else {
            bump(&c.malformed, 1);
            return;
        };
        let Some((tx, mode)) = self.table().flows.get(&id).map(|e| (e.tx.clone(), e.mode)) else {
            bump(&c.unknown_flow, 1);
            return;
        };
        let packet = match mode {
            FlowMode::Forward => rest.to_vec(),
            FlowMode::Packets => match parse_body(rest) {
                Err(Unparsable::Malformed) => return bump(&c.malformed, 1),
                Err(Unparsable::UnknownContext) => return bump(&c.unknown_context, 1),
                Ok(Parsed::Packet(p)) => p.to_vec(),
                Ok(Parsed::Fragment(fragment)) => {
                    let mut discarded = Discarded::default();
                    let outcome = reassembler.accept(id, &fragment, Instant::now(), &mut discarded);
                    bump(&c.reassembly_expired, discarded.expired);
                    bump(&c.reassembly_evicted, discarded.evicted);
                    match outcome {
                        Reassembled::Complete(p) => p,
                        Reassembled::Pending => return,
                        Reassembled::Rejected => return bump(&c.reassembly_rejected, 1),
                    }
                }
            },
        };
        match tx.try_send(packet) {
            Ok(()) => bump(&c.delivered, 1),
            Err(mpsc::error::TrySendError::Full(_)) => bump(&c.inbox_full, 1),
            Err(mpsc::error::TrySendError::Closed(_)) => bump(&c.unknown_flow, 1),
        }
    }

    /// Hand one datagram to QUIC. Never waits: when QUIC's send buffer is full it
    /// discards the oldest queued datagram to make room, so a stalled path loses old
    /// packets rather than blocking the sender.
    fn transmit(&self, datagram: Vec<u8>) -> bool {
        let fits = self
            .conn
            .max_datagram_size()
            .is_some_and(|max| datagram.len() <= max);
        if fits && self.conn.send_datagram(datagram.into()).is_ok() {
            bump(&self.counters.sent, 1);
            true
        } else {
            bump(&self.counters.send_dropped, 1);
            false
        }
    }

    fn send_packet(&self, id: u64, packet_id: &AtomicU64, cap: Option<usize>, packet: &[u8]) {
        let Some(max) = self
            .conn
            .max_datagram_size()
            .map(|max| cap.map_or(max, |cap| max.min(cap)))
        else {
            bump(&self.counters.send_dropped, 1);
            return;
        };
        if varint_len(id) + 1 + packet.len() <= max {
            self.transmit(frame_packet(id, packet));
            return;
        }
        let pid = packet_id.fetch_add(1, Ordering::Relaxed);
        let Some(fragments) = fragment(id, pid, packet, max) else {
            bump(&self.counters.send_dropped, 1);
            return;
        };
        bump(&self.counters.fragmented, 1);
        for f in fragments {
            self.transmit(f);
        }
    }
}

/// End the flow when its stream ends. Owns the stream, so nothing else can keep it
/// open; returning drops it, which finishes and stops both halves and so tells the
/// peer's watcher to end the peer's side of the flow too.
async fn watch(router: Arc<DatagramRouter>, id: u64, send: SendStream, mut recv: RecvStream) {
    let mut buf = [0u8; 64];
    // A bound stream carries no more bytes: whatever the read returns — the peer
    // finishing, resetting, the connection going, or bytes the protocol has no place
    // for — ends the flow. So does the peer stopping our half.
    tokio::select! {
        _ = recv.read(&mut buf) => {}
        _ = send.stopped() => {}
    }
    router.unregister(id);
}

/// One datagram flow, bound to a stream.
///
/// Dropping it ends the stream, which ends the flow on both sides; the stream ending
/// from the other side ends it here, and [`DatagramFlow::recv`] then returns `None`.
pub struct DatagramFlow {
    id: u64,
    router: Arc<DatagramRouter>,
    inbox: mpsc::Receiver<Vec<u8>>,
    next_packet: AtomicU64,
    /// The largest datagram this flow sends, when smaller than the path's; see
    /// [`DatagramFlow::cap_datagrams`].
    cap: Option<usize>,
    watcher: AbortHandle,
}

impl std::fmt::Debug for DatagramFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DatagramFlow({})", self.id)
    }
}

impl DatagramFlow {
    /// The flow ID: the stream ID of the stream it is bound to.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Whether the flow is still open: its stream has not ended.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.router.is_open(self.id)
    }

    /// The largest packet that goes as one datagram on this flow right now; anything
    /// larger is fragmented. `None` when the connection does not carry datagrams.
    #[must_use]
    pub fn max_whole_packet(&self) -> Option<usize> {
        self.router
            .conn
            .max_datagram_size()
            .map(|n| self.cap.map_or(n, |cap| n.min(cap)))
            .map(|n| n.saturating_sub(varint_len(self.id) + 1))
    }

    /// Never send a datagram larger than `max`, fragmenting to fit, even when this
    /// connection's path would take more.
    ///
    /// For a flow whose datagrams are forwarded onto a path this end cannot see: a relay
    /// circuit's other leg. The relay forwards a datagram as it is, so it must fit the
    /// smaller of the two legs, and only a size every QUIC path is guaranteed to carry is
    /// known to.
    pub fn cap_datagrams(&mut self, max: usize) {
        self.cap = Some(max);
    }

    /// Send one packet, fragmenting it if it does not fit one datagram.
    ///
    /// Like UDP, a packet that cannot go — larger than [`MAX_PACKET`](crate::transport::datagram::MAX_PACKET),
    /// or refused by QUIC — is dropped and counted in
    /// [`DatagramStats::send_dropped`], not reported: the sender of a datagram does not
    /// learn its fate. The one error is a flow that has ended.
    ///
    /// # Errors
    /// If the flow's stream has ended.
    pub fn send(&self, packet: &[u8]) -> Result<()> {
        if !self.is_open() {
            return Err(Error::Unreachable("datagram flow closed"));
        }
        self.router
            .send_packet(self.id, &self.next_packet, self.cap, packet);
        Ok(())
    }

    /// Send `rest` — a context and body another [`FlowMode::Forward`] flow received —
    /// on this flow, unchanged. A relay's only operation on a datagram. One too large
    /// for this leg's path is dropped and counted, never split: splitting would mean
    /// reading it.
    ///
    /// # Errors
    /// If the flow's stream has ended.
    pub fn forward(&self, rest: &[u8]) -> Result<()> {
        if !self.is_open() {
            return Err(Error::Unreachable("datagram flow closed"));
        }
        self.router.transmit(reframe(self.id, rest));
        Ok(())
    }

    /// The next packet (or, for a [`FlowMode::Forward`] flow, the next datagram's
    /// `context ‖ body`). `None` once the flow has ended and its inbox is drained.
    /// Cancel-safe.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.recv().await
    }
}

impl Drop for DatagramFlow {
    fn drop(&mut self) {
        // Aborting the watcher drops the stream it owns, which finishes it: the peer's
        // watcher sees the end and ends the peer's side of the flow.
        self.watcher.abort();
        self.router.unregister(self.id);
    }
}
