//! The quinn-backed QUIC substrate (ADR-011 §"Substrate = QUIC") and the real
//! [`crate::log::sync::Transport`] implementation that M5 anti-entropy sync runs
//! over.
//!
//! ## One connection, many streams
//! A [`VoxConnection`] is one QUIC connection to one peer. Each logical flow opens
//! its own bidirectional stream ([`VoxConnection::open_stream`] /
//! [`VoxConnection::accept_stream`]): QUIC gives per-stream flow control with no
//! cross-stream head-of-line blocking, so bulk log replication on one stream never
//! stalls an interactive flow on another (ADR-011 §"Two contracts on one
//! connection"). Low-latency, loss-tolerant flows use RFC 9221 datagrams on
//! **flows** ([`VoxConnection::bind_flow`]): each flow is bound to a stream and lives
//! exactly as long as it, and the connection's one
//! [`DatagramRouter`] — started with the
//! connection, the only reader of its datagrams — hands each datagram to its flow and
//! drops and counts the rest (ADR-022). Replay is QUIC's own concern (RFC 9000 §12.3);
//! Vox adds no sequence number of its own.
//!
//! ## Authentication + the recorded session
//! Connecting and accepting both authenticate the peer via the
//! [`crate::transport::verifier`] custom verifiers (no CA): the peer's Vox identity
//! is recovered from its leaf's identity extension + composite PoP, the negotiated
//! group is confirmed to be X25519MLKEM768, and a
//! [`crate::transport::session::SessionEstablishment`] record (tag `0x0011`) is
//! produced so a downgrade is auditable end-to-end. A handshake that cannot
//! negotiate the hybrid group simply fails — there is no classical fallback.
//!
//! ## Sync over QUIC (the M5 `Transport` impl)
//! [`QuicStreamTransport`] implements the synchronous M5
//! [`Transport`](crate::log::sync::Transport) trait over
//! a reliable QUIC bi-stream by bridging to a tokio runtime
//! ([`tokio::runtime::Handle::block_on`]). Each M5 frame (an opaque byte vector) is
//! length-delimited on the stream with a 4-byte big-endian length prefix, so the
//! byte stream is re-framed into the exact messages M5 sent. A hard close maps the
//! [`WireError`] to a QUIC application close code. Two loopback peers reconcile
//! divergent logs over this transport in the tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use quinn::{Connection, Endpoint, RecvStream, Runtime, SendStream};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::transport::identity;
use crate::transport::identity_cert::build_neutral_leaf;
use crate::transport::mux::{CircuitPort, MuxSocket};
use crate::transport::provider::{neutral_client_config, neutral_server_config};
use crate::transport::router::{
    DatagramFlow, DatagramRouter, DatagramStats, FlowMode, MAX_PACKET_HEADER,
};
use crate::transport::session::SessionEstablishment;
use crate::wire::WireError;

/// The maximum length of a single length-delimited M5 frame on a reliable stream.
/// Generous enough for any [`crate::log::sync`] frame (it bounds an `ENTRY` carrying
/// a max-size entry), and a hard cap so a hostile peer cannot announce a huge frame
/// length to force an allocation (anti-abuse, mirroring the M5 codec's own caps).
pub const MAX_STREAM_FRAME: usize = crate::log::sync::MAX_ENTRY_WIRE + 4096;

/// The QUIC application close code carried when a sync stream hard-fails. quinn
/// requires a `VarInt`; the M5 [`WireError`] byte is widened into it so the peer
/// observes the exact coded reason (ADR-008 — never a silent downgrade).
pub fn close_code(err: WireError) -> quinn::VarInt {
    quinn::VarInt::from_u32(u32::from(err.code()))
}

/// **The daemon's one QUIC endpoint** (ADR-026 D-3, ADR-012 N-41): one socket, one multiplexer,
/// one neutral TLS leaf for the whole run, serving every node registered on it.
///
/// The TLS handshake authenticates only this endpoint (ADR-011 requirement 27); which node a
/// connection is to is proved afterwards by the identity exchange ([`identity`]), signed by the
/// registered node's own key. A dial runs [`identity::dial`] as the dialling node; an accepted
/// connection runs [`identity::listen`] against the registry, so a connection reaches only the
/// node it asked for, and an unknown or unregistered one gets the one refusal.
///
/// A node's view of it is a [`VoxEndpoint`] ([`SharedEndpoint::register`]).
pub struct SharedEndpoint {
    endpoint: Endpoint,
    /// The socket the endpoint runs on: the real one plus relay circuits (ADR-012 rung 4).
    mux: Arc<MuxSocket>,
    /// The client side of every dial: the neutral leaf, pre-identity limits.
    client: quinn::ClientConfig,
    /// The largest UDP payload this endpoint advertises and path-MTU discovery searches up to:
    /// [`MAX_UDP_PAYLOAD`] when the socket's receive buffer can take its bursts, else quinn's
    /// Ethernet default. See [`mtu_ceiling_for`].
    mtu_ceiling: u16,
    /// The nodes this endpoint answers for, by fingerprint.
    registry: Mutex<std::collections::HashMap<Digest32, Registered>>,
    /// The per-source rate limit on `ASK`s (ADR-011 requirement 34): one per endpoint, run
    /// before any node is looked up.
    limiter: identity::AskLimiter,
    /// Set once [`SharedEndpoint::close`] has run.
    closed: tokio::sync::watch::Sender<bool>,
    /// Each node's connections, by node, so a node gone without detaching can still have its own
    /// closed ([`SharedEndpoint::evict`]). Closed ones are dropped as new ones are added.
    by_node: Mutex<std::collections::HashMap<Digest32, Vec<Connection>>>,
    /// The socket's own drop count, `(epoch, drops)`, as the overflow sampler last read it
    /// (ADR-024 RO-1); `None` until it has, and for a socket with no such count. Each direct
    /// connection reports it to its peer ([`crate::transport::overflow`]).
    overflow: tokio::sync::watch::Receiver<Option<(u32, u32)>>,
}

/// Read the drop count of the socket under `mux` (descriptor `fd`) every
/// [`overflow::SAMPLE_EVERY`] while it receives, and publish it on `tx` when it changes (ADR-024
/// RO-1). Ends when the socket is gone, when nobody listens, or at once where the kernel keeps no
/// per-socket count. It holds the socket only while it reads it, so it never keeps the port bound.
fn sample_overflow(
    mux: std::sync::Weak<MuxSocket>,
    fd: std::os::fd::RawFd,
    epoch: u32,
    tx: tokio::sync::watch::Sender<Option<(u32, u32)>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crate::transport::overflow::SAMPLE_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut seen_batches = None;
        let mut last = None;
        loop {
            tick.tick().await;
            if tx.is_closed() {
                return;
            }
            let Some(mux) = mux.upgrade() else {
                return;
            };
            // Read only after the socket has handed something up: an idle socket costs nothing,
            // and the first tick after a stall (the process stopped, the buffer overflowing) is the
            // one that sees the drops.
            let batches = mux.received();
            if seen_batches == Some(batches) {
                continue;
            }
            seen_batches = Some(batches);
            match vox_sockdrops::recv_drops(fd) {
                Ok(Some(drops)) if last != Some(drops) => {
                    last = Some(drops);
                    tx.send_replace(Some((epoch, drops)));
                }
                Ok(Some(_)) => {}
                // No per-socket count here (macOS), or none the kernel will give: nothing to say.
                Ok(None) | Err(_) => return,
            }
        }
    });
}

/// One node on a [`SharedEndpoint`].
struct Registered {
    local: Arc<LocalNode>,
    signer: Arc<dyn RootSigner + Send + Sync>,
    /// Where the node's accepted connections go, when something routes them by node
    /// ([`SharedEndpoint::route`]).
    inbound: Option<tokio::sync::mpsc::Sender<VoxConnection>>,
}

/// **A node's view of the shared endpoint** (ADR-026 D-3): it dials as this node, its circuits
/// are this node's, and what it accepts is this node's. Dropping or closing it unregisters the
/// node — its signer leaves the exchange, so it answers nothing more — and closes the endpoint
/// itself only when the node had it to itself (a solo endpoint, [`VoxEndpoint::bind`]).
pub struct VoxEndpoint {
    shared: Arc<SharedEndpoint>,
    /// This node's own fingerprint.
    local_id: Digest32,
    /// The node this view is, with the state the process keeps per node (ADR-026 P-1).
    local: Arc<LocalNode>,
    /// The node's long-term key: it signs this node's `CLAIM`s. Taken out when the node is
    /// unregistered, so a view outliving its node's attach holds no key (ADR-026 L-3).
    signer: Mutex<Option<Arc<dyn RootSigner + Send + Sync>>>,
    /// Whether the endpoint was bound for this node alone, and so goes with it.
    solo: bool,
}

/// **One node this process hosts, and what the process keeps for it alone** (ADR-026 P-1).
///
/// A process may host several nodes, so nothing a node configures or a peer could learn from may
/// sit in a process-wide value: each tunnel, count and setting is filed under the node it is
/// for, and every reader asks by node. This is the per-node half that is not a registry entry:
/// how long the node gives a stuck tunnel, the secret its relay keys origin tags with, and the
/// per-attach `instance` its identity exchange signs (ADR-011), so a node that comes back is seen
/// as a new process of itself.
#[derive(Debug)]
pub struct LocalNode {
    id: Digest32,
    instance: [u8; 16],
    stuck_after_secs: AtomicU64,
    origin_key: [u8; 32],
}

impl LocalNode {
    /// A node with a fresh `instance` and origin key, giving stuck tunnels the default
    /// ([`crate::tunnel::session::STUCK_AFTER`]).
    ///
    /// # Errors
    /// If the OS CSPRNG is unavailable: the origin key and the instance are drawn from it, and a
    /// guessable origin key would let a target work a relayed asker's address back out.
    pub fn new(id: Digest32) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            id,
            instance: crate::identity::rng::random_array()?,
            stuck_after_secs: AtomicU64::new(crate::tunnel::session::STUCK_AFTER.as_secs()),
            origin_key: crate::identity::rng::random_array()?,
        }))
    }

    /// The node's identity fingerprint.
    #[must_use]
    pub fn id(&self) -> Digest32 {
        self.id
    }

    /// This attach of the node: new each time it is made (ADR-011).
    #[must_use]
    pub fn instance(&self) -> [u8; 16] {
        self.instance
    }

    /// Give this node's tunnels `after` before one whose bytes wait is closed as stuck
    /// (V030-11): the node's `tunnel-stuck-after` setting. At least a second.
    pub fn set_stuck_after(&self, after: std::time::Duration) {
        self.stuck_after_secs
            .store(after.as_secs().max(1), Ordering::Relaxed);
    }

    /// How long this node's tunnels' bytes may wait before the tunnel is closed as stuck.
    #[must_use]
    pub fn stuck_after(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.stuck_after_secs.load(Ordering::Relaxed))
    }

    /// The secret this node, as a relay, keys the origin tags it tells a target with
    /// (`circuitstream::origin_tags`). Never sent.
    #[must_use]
    pub fn origin_key(&self) -> &[u8; 32] {
        &self.origin_key
    }
}

/// Transport-layer admission for an *inbound* connection, evaluated **after** the
/// peer has been cryptographically authenticated (its composite identity recovered
/// and PoP verified) but before [`VoxEndpoint::accept`] returns the connection.
///
/// ## The default is open, by design (ADR-001 / ADR-005 / ADR-007)
/// Vox membership is **emergent**, not a transport-enforced roster: the swarm is
/// gated at *join* by the channel passphrase + Equihash PoW (ADR-005), and
/// *reading* is gated by per-sender consent (ADR-007). The transport's job is to
/// **authenticate and surface** the peer identity; authorization lives above it.
/// So the default ([`Admission::AcceptAnyAuthenticated`]) admits any peer that
/// proved a valid Vox identity, and the recovered identity is always available to
/// the caller via [`VoxConnection::peer_id`] for the upper-layer join/consent
/// checks.
///
/// ## Pinned / private deployments
/// A caller that *does* know who may connect (a pinned pair, or a closed
/// deployment) can supply [`Admission::Pinned`] or [`Admission::Callback`] to
/// reject an unwanted-but-authenticated identity at the transport boundary,
/// before the connection is handed up.
pub enum Admission {
    /// Admit any peer that authenticated as a valid Vox identity (open-swarm
    /// default). The identity is still recovered and surfaced to the caller.
    AcceptAnyAuthenticated,
    /// Admit only peers whose recovered identity fingerprint is in this set.
    Pinned(std::collections::HashSet<Digest32>),
    /// Admit a peer iff this predicate returns `true` for its recovered identity
    /// fingerprint. Lets a caller consult its own (dynamic) membership view.
    Callback(Box<dyn FnMut(&Digest32) -> bool + Send>),
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptAnyAuthenticated => f.write_str("Admission::AcceptAnyAuthenticated"),
            Self::Pinned(s) => f.debug_tuple("Admission::Pinned").field(&s.len()).finish(),
            Self::Callback(_) => f.write_str("Admission::Callback"),
        }
    }
}

impl Admission {
    /// Evaluate admission for a recovered, already-authenticated peer identity.
    fn admits(&mut self, peer: &Digest32) -> bool {
        match self {
            Self::AcceptAnyAuthenticated => true,
            Self::Pinned(set) => set.contains(peer),
            Self::Callback(f) => f(peer),
        }
    }
}

/// How long a connection may sit silent before QUIC closes it.
///
/// quinn's default is 30s, and Vox carries **tunnels**: an `ssh` session between keystrokes,
/// a port-forward waiting on the far end, a room with nothing being said in it. Those are
/// idle for far longer than 30s and must not be torn down for it, so the timeout is raised
/// and a keep-alive keeps the path warm underneath it.
const MAX_IDLE_MS: u32 = 60_000;

/// How long opening a stream may wait for the peer to grant one. Stream credit on a live
/// connection is immediate; the only thing this waits for is a peer that is not granting it, so
/// it is sized like a frame read (`SYNC_FRAME_TIMEOUT`, 20s) rather than a handshake.
const OPEN_STREAM_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

/// How often a silent connection sends a keep-alive.
///
/// Comfortably under half [`MAX_IDLE_MS`], so a single lost keep-alive cannot expire the
/// connection — the ratio iroh uses for the same reason (25s against a 35s idle timeout in
/// `iroh-relay`). Without this quinn sends nothing on an idle path and the connection dies
/// at the idle timeout, which for a tunnel means a person's session dropping while they
/// read.
pub(crate) const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(20);

/// The largest UDP payload a Vox endpoint accepts, and the ceiling path-MTU discovery
/// searches up to (PRD-001 R41).
///
/// quinn's default ceiling is 1452 — Ethernet's — so every path, loopback and jumbo-frame
/// links included, ran at 1452-byte packets, and a tunnel on this machine spent most of its
/// time in one `sendmsg` per packet: profiled, the sending node sat in `__sendmsg` and in
/// the connection lock that `sendmsg` is made under, with encryption at a few percent.
/// Discovery is probing, not assuming: a path that will not carry a larger packet loses the
/// probe and keeps what it had, so a 1500-byte link is exactly where it was.
///
/// **8192, not the loopback MTU (16384).** macOS refuses a UDP datagram over
/// `net.inet.udp.maxdgram` (9216 by default), and with the ceiling at 16356 connections
/// failed outright on this machine rather than falling back — measured, not reasoned. 8192
/// stays under that limit on every platform Vox builds for.
pub const MAX_UDP_PAYLOAD: u16 = 8_192;

/// The UDP socket buffers a node asks for, each way.
///
/// The OS default (768 KiB receive on macOS) overflowed during a burst, and a large packet
/// lost to overflow reads to quinn as a black hole: it drops the path MTU back to 1200 and
/// does not probe again for a minute. Measured with the larger ceiling and larger stream
/// windows (an experiment since dropped): without these buffers the MTU fell back to 1200 in
/// 3 of 3 runs (`black_holes_detected` 1–9); with them, 0 black holes in 3 of 3.
/// The OS may grant less, and Linux does so silently (`net.core.rmem_max`); that is not an
/// error, but it decides the path-MTU ceiling (`mtu_ceiling_for`).
const UDP_SOCKET_BUFFER: usize = 4 << 20;

/// The test-only variable that caps the receive buffer a socket asks for, in bytes (see
/// [`recv_buffer_asked`]).
#[cfg(feature = "test-knobs")]
pub const TEST_UDP_RCVBUF_CAP_ENV: &str = "VOX_TEST_UDP_RCVBUF_CAP";

/// The receive buffer a socket asks for: [`UDP_SOCKET_BUFFER`], or **less**, read from
/// `VOX_TEST_UDP_RCVBUF_CAP` in a build with the `test-knobs` feature. **Test-only: for proofs; no
/// shipped build reads it** (V210-105). It stands for a container on a host that keeps Linux's
/// default `net.core.rmem_max`: asked for 212992, the kernel grants 416 KiB (R41a, #218). It only
/// ever lowers the request; unset, empty or unparsable is the real one.
fn recv_buffer_asked() -> usize {
    #[cfg(feature = "test-knobs")]
    if let Some(cap) = std::env::var(TEST_UDP_RCVBUF_CAP_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        return cap.min(UDP_SOCKET_BUFFER);
    }
    UDP_SOCKET_BUFFER
}

/// Per-stream flow-control window (and half the connection's send window), sized for the
/// bandwidth-delay product of a 1 Gbit/s path at ~130 ms, or 10 Gbit/s at ~13 ms.
pub const STREAM_WINDOW: u32 = 16 << 20;

/// Flow-control credit a peer gets for the whole connection, across all its streams, **before
/// any tunnel runs on it**: what this node will buffer for one peer that sends and is not read.
///
/// quinn's default is unlimited, which is safe only while the per-stream window is small. At
/// [`STREAM_WINDOW`] a peer may open quinn's default 100 concurrent bidirectional streams, so an
/// unlimited connection window let one peer park 100 × 16 MiB = 1.6 GiB in this node's memory
/// by writing into streams nobody reads.
///
/// **Each running tunnel adds its own [`STREAM_WINDOW`] on top** ([`VoxConnection::carry_tunnel`]),
/// up to [`TUNNELS_PER_PEER`] tunnels on one connection.
/// A tunnel whose local reader stops reading keeps a full stream window unread, and the
/// connection's credit is shared: at a fixed two stream windows, two such tunnels held all of it,
/// and the room's sync, pairwise keys and board records to that peer got none — a post waited out
/// a 20 s frame timeout and failed (V210-81). With each tunnel bringing its own window, what the
/// tunnels hold can never reach this base, so everything else keeps it. Only tunnels this node
/// authorized, or opened for its own local application, are credited, so an unauthorized peer
/// still gets exactly this.
pub const CONNECTION_WINDOW: u32 = 2 * STREAM_WINDOW;

/// How many tunnels one member and this node carry between them at once, in both directions
/// together and **across every connection to that member**. A tunnel past it is refused at once,
/// saying so (decider, 2026-10-01).
///
/// Without it, every tunnel a trusted member opened added a [`STREAM_WINDOW`] to what this node
/// agreed to buffer for them, with no end: a member could hold 16 MiB of this node's memory per
/// tunnel whose far end had stopped reading. With it, a member's tunnels hold at most this many
/// stream windows (256 MiB), each credited on the connection it runs on, so the room's sync never
/// waits on them. Generous by design: past any real use, it is a bound on memory, not a quota.
///
/// Per member, not per connection: a member has two connections at once whenever a better path
/// replaces a relayed one (the old one stays open while its tunnels run), and a count per
/// connection let that member open 16 more on the new one, and told a person to close a tunnel
/// that freed nothing on the count that refused them (#272 c5).
pub const TUNNELS_PER_PEER: u32 = 16;

/// quinn's own path-MTU ceiling (`MtuDiscoveryConfig::default().upper_bound`): 1500-byte Ethernet
/// less IPv6 and UDP headers. What an endpoint falls back to when its socket cannot take the
/// bursts [`MAX_UDP_PAYLOAD`] brings.
pub const DEFAULT_UDP_PAYLOAD: u16 = 1_452;

/// The path-MTU ceiling for a socket whose receive buffer is `effective` bytes, as the OS
/// reports it after `UDP_SOCKET_BUFFER` was asked for, and why.
///
/// **The 8192 ceiling needs the buffer it was measured with.** A burst of large datagrams that
/// overflows the receive buffer loses a run of large packets and nothing small, which is exactly
/// what quinn's black-hole detector looks for: it drops the path to 1200 bytes, below the 1452 a
/// stock endpoint keeps, and does not probe again for a minute. On macOS the 768 KiB default did
/// that in 3 of 3 runs and the 4 MiB buffer in 0 of 3. Linux, though, caps `SO_RCVBUF` at
/// `net.core.rmem_max` without an error (about 208 KiB by default; only `CAP_NET_ADMIN` can
/// exceed it), so an endpoint there ran the 8192 ceiling on a tenth of the buffer, and CI's
/// loopback proof pinned the dialler at 1200.
///
/// So the larger ceiling is taken only when the buffer the OS actually granted is at least the
/// one it was measured with, read back in each OS's own units (`GRANTED_WHEN_FULL`):
/// - **Linux** reports twice what it granted (it counts its own bookkeeping): the read-back is
///   `2 × min(requested, net.core.rmem_max)`. A full grant reads as 8 MiB, and a cap at the
///   default reads as about 416 KiB. Comparing against 4 MiB there would be wrong: a host with
///   `rmem_max` between 2 and 4 MiB reads back 4–8 MiB and would take 8192 on half the buffer.
/// - **Other platforms** (macOS) report what they granted.
///
/// Anything short keeps quinn's default ceiling, which is what every other QUIC endpoint on that
/// host runs with.
#[must_use]
pub fn mtu_ceiling_for(effective: usize) -> (u16, &'static str) {
    if effective >= GRANTED_WHEN_FULL {
        (
            MAX_UDP_PAYLOAD,
            "the receive buffer takes a burst of 8192-byte datagrams",
        )
    } else {
        (
            DEFAULT_UDP_PAYLOAD,
            "the OS granted a smaller receive buffer than 8192-byte datagrams need \
             (on Linux, raise net.core.rmem_max to at least 4 MiB)",
        )
    }
}

/// What `SO_RCVBUF` reads back when the full `UDP_SOCKET_BUFFER` was granted: Linux doubles the
/// value it stores (`sock_setsockopt`: `sk_rcvbuf = 2 * min(val, rmem_max)`), other platforms do
/// not.
#[cfg(target_os = "linux")]
const GRANTED_WHEN_FULL: usize = 2 * UDP_SOCKET_BUFFER;
#[cfg(not(target_os = "linux"))]
const GRANTED_WHEN_FULL: usize = UDP_SOCKET_BUFFER;

/// How many bytes over the path-MTU ceiling a datagram this endpoint receives may run.
///
/// quinn sizes each receive buffer at the endpoint's `max_udp_payload_size`, and a datagram
/// longer than its buffer is cut by the kernel, fails decryption and is dropped without a word.
/// quinn-proto (0.11.18, and 0.11.19 and main as of 2026-10-03) fills a CONNECTION_CLOSE with
/// a long reason to the packet's size counting its error code as one byte: a peer closing with a
/// code of 2 to 8 bytes and a reason that fills the packet sends up to 7 bytes more than its
/// path MTU. At the ceiling, the close was lost, the next packet met the peer's stateless reset,
/// and the connection ended "reset by peer", its cause gone (#191: an anchor's close, code
/// 0x7e57, 8194 bytes on an 8192-byte path). Path-MTU discovery is still bounded by the ceiling
/// ([`base_transport`]), so nothing this endpoint sends grows.
const RECEIVE_HEADROOM: u16 = 64;

/// The endpoint parameters every Vox endpoint runs with: datagrams up to the path-MTU ceiling,
/// and [`RECEIVE_HEADROOM`] over it received whole.
fn endpoint_config(mtu_ceiling: u16) -> quinn::EndpointConfig {
    let mut cfg = quinn::EndpointConfig::default();
    let _ = cfg.max_udp_payload_size(mtu_ceiling.saturating_add(RECEIVE_HEADROOM));
    cfg
}

/// How many bidirectional streams a peer may have open to this node at once.
///
/// Set explicitly rather than left at quinn's default of 100 (ADR-022 decision 7). App
/// streams are opened by other programs, so a peer can hold many of them open while they
/// wait, and every one of them occupies a slot a `sync` or `join` stream would otherwise
/// take: at 100, a hundred stalled app streams were enough to stop a room's messages. The
/// per-peer app limit (`node::app::MAX_APP_STREAMS_PER_PEER`) is what keeps app streams
/// few; this is the headroom that keeps the node's own streams opening while they are.
pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 1024;

/// The transport parameters every Vox connection runs with, in both directions, once its
/// identity exchange is done; [`pre_identity_transport_config`] holds it to the exchange first.
fn base_transport(mtu_ceiling: u16) -> quinn::TransportConfig {
    let mut cfg = quinn::TransportConfig::default();
    cfg.keep_alive_interval(Some(KEEP_ALIVE));
    cfg.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS));
    // `From<VarInt>` rather than `try_from(Duration)`: the millisecond value is a compile-
    // time constant inside the varint range, so there is no error case to handle.
    cfg.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        MAX_IDLE_MS,
    ))));
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(mtu_ceiling);
    cfg.mtu_discovery_config(Some(mtu));
    // Enough flow-control credit to fill a long, fast path (PRD-001 R41). quinn's default
    // stream window is 1.25 MB, sized for 100 Mbit/s at 100 ms; at 1 Gbit/s and 20 ms RTT that
    // caps a tunnel at ~500 Mbit/s whatever the link does. Measured over a shaped 1 Gbit/s,
    // 20 ms path: 414 Mbit/s with the default, ~940 with these. The window is credit the
    // receiver grants, not memory it allocates up front.
    cfg.stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW));
    cfg.send_window(2 * u64::from(STREAM_WINDOW));
    cfg.receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW));
    // Cubic, restarted after the connection idles: a tunnel's transfer must not inherit the
    // congestion history of an older one on the same long-lived connection (PRD-001 R41).
    cfg.congestion_controller_factory(Arc::new(crate::transport::congestion::IdleRestartConfig));
    cfg
}

/// The transport parameters of a connection **before its identity exchange** (ADR-011
/// requirement 33): the normal parameters with QUIC's own limits holding the connection to the
/// exchange — at most [`identity::PRE_IDENTITY_BIDI`](crate::transport::identity::PRE_IDENTITY_BIDI)
/// client-opened bidirectional streams, no unidirectional stream, and a
/// [`identity::PRE_IDENTITY_WINDOW`](crate::transport::identity::PRE_IDENTITY_WINDOW) connection
/// window. A third stream is QUIC's STREAM_LIMIT_ERROR, not something Vox has to police.
/// [`identity::open_post_identity`](crate::transport::identity::open_post_identity) raises them
/// once the exchange is done.
#[must_use]
pub fn pre_identity_transport_config(mtu_ceiling: u16) -> Arc<quinn::TransportConfig> {
    use crate::transport::identity::{PRE_IDENTITY_BIDI, PRE_IDENTITY_UNI, PRE_IDENTITY_WINDOW};
    let mut cfg = base_transport(mtu_ceiling);
    cfg.max_concurrent_bidi_streams(quinn::VarInt::from_u32(PRE_IDENTITY_BIDI));
    cfg.max_concurrent_uni_streams(quinn::VarInt::from_u32(PRE_IDENTITY_UNI));
    cfg.receive_window(quinn::VarInt::from_u32(PRE_IDENTITY_WINDOW));
    Arc::new(cfg)
}

/// How long one inbound handshake may take before it is abandoned.
///
/// This bounds a **pre-authentication** cost: until the handshake completes there is no
/// identity to hold anybody to, so the only defence is that an unfinished attempt is cheap
/// and finite. Generous enough for a slow or relayed path — the ADR-012 ladder's rung 4 is a
/// circuit through an anchor — and short enough that abandoned attempts do not accumulate.
/// How long one inbound handshake may take before it is abandoned.
///
/// Public so a proof about handshake stalling can derive its own bound from this instead of
/// restating it: a gate that hard-codes 30 seconds keeps passing when this constant moves,
/// which is the failure mode ADR-018 §8 exists to prevent.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many ephemeral ports a dual-stack bind tries before it gives up (see [`bind_udp`]). Each
/// failed try costs at most [`DUAL_STACK_SELF_TEST`]; a collision is rare outside a machine holding
/// thousands of IPv4 ports, where one in two can collide, and 32 keeps even that from failing.
const DUAL_STACK_TRIES: usize = 32;
/// How long a dual-stack bind waits for its own IPv4 self-test datagrams (see [`bind_udp`]). The
/// datagrams are on loopback or to this machine's own address, so they are in the socket's buffer
/// as soon as they are sent; this only bounds a test whose datagram went to another program.
const DUAL_STACK_SELF_TEST: std::time::Duration = std::time::Duration::from_secs(1);

/// Bind the endpoint's UDP socket to `addr`.
///
/// **A dual-stack socket must hear its IPv4 traffic (V210-147).** On macOS a socket bound to
/// `[::]:0` with IPv6-only off is often given a port another program already holds on IPv4 —
/// measured, 529 of 3000 such binds against 3000 held `127.0.0.1` ports, 564 against `0.0.0.0` —
/// and an explicit `[::]:P` is even allowed over a `0.0.0.0:P` holder. IPv4 datagrams to that port
/// then go to the other program and this node hears none of them, saying nothing: a host dialling
/// such an anchor over IPv4 reached another program instead (V210-143). Probe-binding the IPv4
/// port cannot tell this socket's own hold on it from another program's, as both refuse the probe.
/// So the socket is tested instead: a datagram sent to `127.0.0.1:P`, and one sent to the machine's
/// routable IPv4 address on P, must each reach it — the two IPv4 addresses a node advertises
/// (`nat::reachability`), so a program holding the port on either, `0.0.0.0` included, is caught.
/// An ephemeral port that fails is bound again (the old one held meanwhile, so it is not handed
/// back); an explicit one is refused, saying why. What the test sent is drained before QUIC gets the
/// socket. **Not covered:** a program bound to another IPv4 address of this machine that no node
/// advertises; it takes only traffic no peer was told to send there.
fn bind_udp(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let bind = |at: SocketAddr| {
        std::net::UdpSocket::bind(at).map_err(|e| Error::LocalBind {
            addr: at,
            cause: crate::error::BindCause::of(&e),
            reason: e.to_string(),
        })
    };
    let mut socket = bind(addr)?;
    let dual_stack = match addr {
        SocketAddr::V6(a) if a.ip().is_unspecified() => {
            !socket2::SockRef::from(&socket).only_v6().unwrap_or(true)
        }
        _ => false,
    };
    if !dual_stack {
        return Ok(socket);
    }
    let mut misses: Vec<String> = Vec::new();
    for _ in 0..DUAL_STACK_TRIES {
        let port = socket
            .local_addr()
            .map_err(|e| Error::LocalBind {
                addr,
                cause: crate::error::BindCause::Other,
                reason: e.to_string(),
            })?
            .port();
        let missed = match hears_ipv4(&socket, port) {
            Ok(()) => return Ok(socket),
            Err(Missed::Routable(missed)) => {
                // **Said as it was observed** (V030-33's finding): only the datagram to this
                // machine's own routable address went missing. A program holding the port on
                // `0.0.0.0` takes the loopback datagram too, and that one arrived; what stops only
                // the routable one is, almost always, a firewall that filters this binary's incoming
                // traffic (macOS's application firewall leaves loopback alone), or rarely a program
                // bound to that one address. Both are named; another port would meet the same
                // firewall, so none is tried.
                return Err(Error::LocalBind {
                    addr,
                    cause: crate::error::BindCause::Other,
                    reason: format!(
                        "IPv4 traffic to this machine's own address on port {port} never reached \
                         this node, though traffic to 127.0.0.1 did ({missed}). Either this \
                         machine's firewall refuses incoming traffic to this vox (on macOS: System \
                         Settings › Network › Firewall › Options, allow {}), or another program \
                         holds port {port} on that address",
                        std::env::current_exe()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|_| "vox".to_owned())
                    ),
                });
            }
            Err(Missed::Loopback(missed)) => missed,
        };
        if addr.port() != 0 {
            return Err(Error::LocalBind {
                addr,
                cause: crate::error::BindCause::InUse,
                reason: format!(
                    "IPv4 traffic to port {port} reaches another program, which holds that port \
                     on IPv4; on it this node would hear IPv6 only ({missed})"
                ),
            });
        }
        misses.push(missed);
        // Bound before the old socket closes, so the kernel cannot hand back the same port.
        socket = bind(addr)?;
    }
    Err(Error::LocalBind {
        addr,
        cause: crate::error::BindCause::InUse,
        reason: format!(
            "{DUAL_STACK_TRIES} ports in a row were each held on IPv4 by another program, so \
             this node would hear IPv6 only on any of them (the last: {})",
            misses
                .iter()
                .rev()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ),
    })
}

/// The machine's routable IPv4 address: the one the OS would send from toward the internet (a
/// connected UDP socket's local address; nothing is sent), as `nat::reachability` finds it.
fn routable_ipv4() -> Option<std::net::Ipv4Addr> {
    let s = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // 192.0.2.0/24 is the reserved documentation prefix (RFC 5737): never routed to a real host.
    s.connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// Whether a datagram sent over IPv4 to each address a node advertises — `127.0.0.1` and the
/// routable IPv4 address — on `port` reaches `socket` (see [`bind_udp`]). Everything the test sent
/// that arrived is drained, so none of it reaches QUIC.
fn hears_ipv4(socket: &std::net::UdpSocket, port: u16) -> std::result::Result<(), Missed> {
    let started = std::time::Instant::now();
    let mut targets = vec![std::net::Ipv4Addr::LOCALHOST];
    targets.extend(routable_ipv4());
    let Ok(probe) = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)) else {
        return Ok(()); // no test is possible; never refuse a bind for that
    };
    // **A control for each address: an IPv4 socket of this test's own.** A machine can drop what
    // it sends to its own routable address (a VPN that blocks the local network does): measured
    // 2026-10-03, every datagram to the LAN address was lost, to an IPv4-only socket as much as
    // to a dual-stack one, and the node refused every port it was given as "held by another
    // program". So an address whose control datagram does not arrive tests nothing, and is left
    // out of the verdict rather than read as a collision.
    let Ok(control) = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)) else {
        return Ok(());
    };
    let Ok(control_port) = control.local_addr().map(|a| a.port()) else {
        return Ok(());
    };
    let nonce = |what: &[u8]| -> Option<Vec<u8>> {
        let mut n = [0u8; 16];
        getrandom::fill(&mut n).ok()?;
        let mut text = what.to_vec();
        text.extend_from_slice(&n);
        Some(text)
    };
    let mut owed: Vec<(std::net::Ipv4Addr, Vec<u8>)> = Vec::new();
    let mut controls: Vec<(std::net::Ipv4Addr, Vec<u8>)> = Vec::new();
    for target in targets {
        let (Some(text), Some(check)) = (
            nonce(b"vox dual-stack self-test "),
            nonce(b"vox dual-stack control "),
        ) else {
            return Ok(());
        };
        if probe.send_to(&text, (target, port)).is_err()
            || probe.send_to(&check, (target, control_port)).is_err()
        {
            return Ok(());
        }
        owed.push((target, text));
        controls.push((target, check));
    }
    let deadline = std::time::Instant::now() + DUAL_STACK_SELF_TEST;
    let mut buf = [0u8; 64];
    while !owed.is_empty() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => owed.retain(|(_, t)| buf[..n] != t[..]),
            Err(_) => break,
        }
    }
    // **What already arrived is read, whatever the clock says.** A process descheduled past the
    // deadline between sending and its first read used to give up on datagrams sitting in its own
    // buffer: measured at load ~47, a node refused all 32 ports it tried, 1.25 s apart. So the
    // buffer is drained before the verdict, and the drain also keeps every test datagram from QUIC.
    if socket.set_nonblocking(true).is_ok() {
        while let Ok((n, _)) = socket.recv_from(&mut buf) {
            owed.retain(|(_, t)| buf[..n] != t[..]);
        }
        let _ = socket.set_nonblocking(false);
    }
    let _ = socket.set_read_timeout(None);
    if owed.is_empty() {
        return Ok(());
    }
    // The controls of the addresses still owed: each had the whole wait to arrive.
    if control.set_nonblocking(true).is_ok() {
        while let Ok((n, _)) = control.recv_from(&mut buf) {
            controls.retain(|(_, t)| buf[..n] != t[..]);
        }
    }
    owed.retain(|(at, _)| !controls.iter().any(|(c, _)| c == at));
    if owed.is_empty() {
        return Ok(());
    }
    let said = format!(
        "port {port}: nothing sent to {} arrived within {} ms",
        owed.iter()
            .map(|(at, _)| at.to_string())
            .collect::<Vec<_>>()
            .join(" or "),
        started.elapsed().as_millis()
    );
    if owed.iter().any(|(at, _)| at.is_loopback()) {
        Err(Missed::Loopback(said))
    } else {
        Err(Missed::Routable(said))
    }
}

/// Which of [`hears_ipv4`]'s datagrams went missing, and what to say of it.
enum Missed {
    /// The one to `127.0.0.1`: another program holds the port on IPv4 (loopback is never
    /// firewalled).
    Loopback(String),
    /// Only the one to this machine's routable address: a firewall filtering this binary, or a
    /// program bound to that address alone.
    Routable(String),
}

impl SharedEndpoint {
    /// Bind the endpoint to `addr`: one UDP socket (dual-stack self-tested, [`bind_udp`]), the
    /// multiplexer over it, and a neutral leaf made once for this endpoint's whole life.
    ///
    /// # Errors
    /// [`Error::LocalBind`] if the address cannot be bound; a TLS setup error otherwise.
    pub fn bind(addr: SocketAddr) -> Result<Arc<Self>> {
        let socket = bind_udp(addr)?;
        let effective = {
            let sock = socket2::SockRef::from(&socket);
            let _ = sock.set_recv_buffer_size(recv_buffer_asked());
            let _ = sock.set_send_buffer_size(UDP_SOCKET_BUFFER);
            // What the OS granted, not what was asked for: see `mtu_ceiling_for`.
            sock.recv_buffer_size().unwrap_or(0)
        };
        let (mtu_ceiling, why) = mtu_ceiling_for(effective);
        if mtu_ceiling != MAX_UDP_PAYLOAD {
            // Once per process: every endpoint on the host gets the same answer.
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| {
                eprintln!(
                    "vox: UDP receive buffer {} KiB: path-MTU ceiling {mtu_ceiling} bytes, not \
                     {MAX_UDP_PAYLOAD} — {why}",
                    effective / 1024
                );
            });
        }
        let fd = std::os::fd::AsRawFd::as_raw_fd(&socket);
        let wrapped = quinn::TokioRuntime
            .wrap_udp_socket(socket)
            .map_err(|_| Error::MalformedBundle("quic endpoint bind"))?;
        Self::bind_abstract_with(wrapped, mtu_ceiling, Some(fd))
    }

    /// Bind on a caller-supplied datagram socket instead of a real UDP socket: how a simulated
    /// network with NAT devices is driven in tests (ADR-012 rungs 3 and 4).
    ///
    /// # Errors
    /// A TLS or endpoint setup error.
    pub fn bind_abstract(socket: Arc<dyn quinn::AsyncUdpSocket>) -> Result<Arc<Self>> {
        // A caller-supplied socket has no kernel buffer to overflow.
        Self::bind_abstract_with(socket, MAX_UDP_PAYLOAD, None)
    }

    /// `drops_fd` is the real socket's descriptor, for its drop count (ADR-024 RO-1); `None` for a
    /// caller-supplied socket.
    fn bind_abstract_with(
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        mtu_ceiling: u16,
        drops_fd: Option<std::os::fd::RawFd>,
    ) -> Result<Arc<Self>> {
        // Every endpoint runs on the multiplexer, so a relay circuit can be attached to a real
        // socket and a simulated one alike.
        let mux = MuxSocket::new(socket);
        let (overflow_tx, overflow) = tokio::sync::watch::channel(None);
        if let Some(fd) = drops_fd {
            // A fresh epoch per socket, so a peer never reads a restarted count as one that
            // went backwards.
            let epoch = u32::from_le_bytes(crate::identity::rng::random_array()?);
            sample_overflow(Arc::downgrade(&mux), fd, epoch, overflow_tx);
        }
        let for_endpoint: Arc<dyn quinn::AsyncUdpSocket> =
            Arc::clone(&mux) as Arc<dyn quinn::AsyncUdpSocket>;
        // One neutral leaf for every connection this endpoint makes or takes (ADR-011
        // requirement 27): it names nobody, so sharing it shows nothing a path observer could
        // not see from the address.
        let leaf = build_neutral_leaf()?;
        let quic_server =
            quinn::crypto::rustls::QuicServerConfig::try_from(neutral_server_config(&leaf)?)
                .map_err(|_| Error::MalformedBundle("quic server config"))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server.transport_config(pre_identity_transport_config(mtu_ceiling));
        let quic_client =
            quinn::crypto::rustls::QuicClientConfig::try_from(neutral_client_config(&leaf)?)
                .map_err(|_| Error::MalformedBundle("quic client config"))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic_client));
        client.transport_config(pre_identity_transport_config(mtu_ceiling));
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(mtu_ceiling),
            Some(server),
            for_endpoint,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|_| Error::MalformedBundle("quic endpoint bind"))?;
        Ok(Arc::new(Self {
            endpoint,
            mux,
            client,
            mtu_ceiling,
            registry: Mutex::new(std::collections::HashMap::new()),
            limiter: identity::AskLimiter::standard(),
            closed: tokio::sync::watch::channel(false).0,
            by_node: Mutex::new(std::collections::HashMap::new()),
            overflow,
        }))
    }

    /// **Register a node** on this endpoint, with a fresh per-attach instance (ADR-026 I-3):
    /// from now on it dials as itself and is answered for. `inbound`, when given, is where
    /// [`Self::route`] sends the connections accepted for it.
    ///
    /// # Errors
    /// [`Error::Profile`] if the node is registered already; a CSPRNG failure.
    pub fn register(
        self: &Arc<Self>,
        signer: Arc<dyn RootSigner + Send + Sync>,
        inbound: Option<tokio::sync::mpsc::Sender<VoxConnection>>,
    ) -> Result<VoxEndpoint> {
        self.register_as(signer, inbound, false)
    }

    fn register_as(
        self: &Arc<Self>,
        signer: Arc<dyn RootSigner + Send + Sync>,
        inbound: Option<tokio::sync::mpsc::Sender<VoxConnection>>,
        solo: bool,
    ) -> Result<VoxEndpoint> {
        let id = signer.fingerprint();
        let local = LocalNode::new(id)?;
        {
            let mut reg = lock(&self.registry);
            if reg.contains_key(&id) {
                return Err(Error::Profile("this node is attached already"));
            }
            reg.insert(
                id,
                Registered {
                    local: Arc::clone(&local),
                    signer: Arc::clone(&signer),
                    inbound,
                },
            );
        }
        Ok(VoxEndpoint {
            shared: Arc::clone(self),
            local_id: id,
            local,
            signer: Mutex::new(Some(signer)),
            solo,
        })
    }

    /// Take `local` off the endpoint, if it is still the registration of its node: its signer
    /// leaves the exchange, so nothing more is answered as it (ADR-011 requirement 34).
    fn unregister(&self, local: &Arc<LocalNode>) {
        let mut reg = lock(&self.registry);
        if reg
            .get(&local.id())
            .is_some_and(|r| Arc::ptr_eq(&r.local, local))
        {
            reg.remove(&local.id());
        }
    }

    /// File `conn` under the node `local`, for [`Self::evict`].
    fn track(&self, local: Digest32, conn: &Connection) {
        let mut by = lock(&self.by_node);
        let list = by.entry(local).or_default();
        list.retain(|c| c.close_reason().is_none());
        list.push(conn.clone());
    }

    /// **Evict a node** that went without detaching — its actor panicked (ADR-026 L-6): take it
    /// off the exchange, and close every connection it had, as stopping. Every other node's
    /// registration and connections are left as they are.
    pub fn evict(&self, local: &Digest32) {
        lock(&self.registry).remove(local);
        let conns = lock(&self.by_node).remove(local).unwrap_or_default();
        for c in conns {
            c.close(
                close_code(WireError::ShuttingDown),
                WireError::ShuttingDown.to_string().as_bytes(),
            );
        }
    }

    /// The fingerprints of the nodes registered now.
    #[must_use]
    pub fn registered(&self) -> Vec<Digest32> {
        lock(&self.registry).keys().copied().collect()
    }

    /// The bound local socket address.
    ///
    /// # Errors
    /// If the socket has none.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|_| Error::MalformedBundle("quic local_addr"))
    }

    /// The largest UDP payload this endpoint advertises and searches up to.
    #[must_use]
    pub fn mtu_ceiling(&self) -> u16 {
        self.mtu_ceiling
    }

    /// **Phase one of accepting:** the next inbound attempt, with no handshake. `None` when the
    /// endpoint is closed. Run [`Self::finish_incoming`] for it on a task of its own.
    pub async fn accept_incoming(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }

    /// **Phase two:** the neutral handshake (bounded by [`HANDSHAKE_TIMEOUT`]) and then the
    /// identity exchange as the listener (bounded by [`identity::EXCHANGE_TIMEOUT`]), answering
    /// for whichever registered node the dialler asks for — on a relay circuit only the node the
    /// circuit was attached for ([`MuxSocket::serves_on`]). The connection comes back filed
    /// under that node ([`VoxConnection::local_id`]); nothing above the transport sees it before
    /// `CLAIM` verified, and its session record is written only then (ADR-011 requirement 33).
    ///
    /// # Errors
    /// A failed handshake, or a refused exchange (the connection already closed with the one
    /// refusal).
    pub async fn finish_incoming(
        &self,
        incoming: quinn::Incoming,
        now_secs: u64,
    ) -> Result<VoxConnection> {
        let remote = incoming.remote_address();
        // Read before this end answers anything: see [`VoxConnection::via_circuit`].
        let via_circuit = self.mux.is_circuit(remote);
        let circuit_origin = self.mux.origin_of(remote);
        let carrier = self.mux.carrier_of(remote);
        let connecting = incoming.accept().map_err(handshake_failed)?;
        // Bounded: an unauthenticated peer must not be able to hold a task open for ever by
        // beginning a handshake and never finishing it.
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| {
                Error::Handshake(format!(
                    "the peer did not finish its handshake within {}s",
                    HANDSHAKE_TIMEOUT.as_secs()
                ))
            })?
            .map_err(handshake_failed)?;
        // A circuit's asks are limited by the relay carrying them: this end never sees the
        // asker's address.
        let source = match &carrier {
            Some((relay, _)) if via_circuit => identity::SourceKey::Circuit(*relay),
            _ => identity::SourceKey::of_addr(remote),
        };
        let answering = Answering {
            shared: self,
            remote,
        };
        let (hosted, proven) =
            identity::listen(&connection, source, None, &answering, &self.limiter)
                .await
                .map_err(|why| Error::Handshake(format!("refused the identity exchange: {why}")))?;
        // The node answered for, as it is registered now: one that went away during the exchange
        // has nothing left to take the connection.
        let local = lock(&self.registry)
            .get(&hosted.id)
            .filter(|r| r.local.instance() == hosted.instance)
            .map(|r| Arc::clone(&r.local));
        let Some(local) = local else {
            identity::refuse(&connection);
            return Err(Error::Handshake(
                "the node asked for went away during the identity exchange".to_owned(),
            ));
        };
        self.track(local.id(), &connection);
        let overflow = (!via_circuit).then(|| self.overflow.clone());
        let mut conn =
            finish_connection(connection, local, &proven, now_secs, via_circuit, overflow)?;
        conn.circuit_origin = circuit_origin.filter(|_| via_circuit);
        conn.carrier = carrier.filter(|_| via_circuit);
        Ok(conn)
    }

    /// **Hand an accepted connection to the node it is for** ([`Self::register`]'s `inbound`).
    /// A node with nowhere to put it, or a full queue, gets it closed as stopping: the node is
    /// going, or too far behind to serve it.
    pub fn route(&self, conn: VoxConnection) {
        let sink = lock(&self.registry)
            .get(&conn.local_id())
            .and_then(|r| r.inbound.clone());
        let Some(sink) = sink else {
            conn.close(WireError::ShuttingDown);
            return;
        };
        if let Err(e) = sink.try_send(conn) {
            let conn = match e {
                tokio::sync::mpsc::error::TrySendError::Full(c)
                | tokio::sync::mpsc::error::TrySendError::Closed(c) => c,
            };
            conn.close(WireError::ShuttingDown);
        }
    }

    /// Close the endpoint and every connection on it, for every node: the daemon stopping.
    pub fn close(&self) {
        // A stopping node's last word to every connection it still has (V210-93): "stopped",
        // the same as `ConnectionManager::close_all` says, never a code that reads as a fault.
        self.endpoint.close(
            close_code(WireError::ShuttingDown),
            WireError::ShuttingDown.to_string().as_bytes(),
        );
        self.closed.send_replace(true);
    }

    /// Whether the endpoint is closed, as a watch: `true` once [`Self::close`] has run.
    #[must_use]
    pub fn closed(&self) -> tokio::sync::watch::Receiver<bool> {
        self.closed.subscribe()
    }

    /// Wait until every connection of this endpoint has finished closing, which includes its
    /// CONNECTION_CLOSE having left. Callers bound it.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// How many connections the endpoint holds, in either role.
    #[must_use]
    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }
}

/// The nodes a connection from `remote` may reach: any registered node, except that a relay
/// circuit is answered only by the node it was attached for (ADR-026 P-1).
struct Answering<'a> {
    shared: &'a SharedEndpoint,
    remote: SocketAddr,
}

impl identity::Hosts for Answering<'_> {
    fn host(&self, target: &Digest32) -> Option<identity::Hosted> {
        if !self.shared.mux.serves_on(self.remote, target) {
            return None;
        }
        lock(&self.shared.registry)
            .get(target)
            .map(|r| identity::Hosted {
                id: *target,
                instance: r.local.instance(),
                signer: Arc::clone(&r.signer),
            })
    }
}

impl VoxEndpoint {
    /// Bind an endpoint of its own to `addr` for `signer`'s node (a **solo** endpoint: today's
    /// one node per process). Closing the view closes the endpoint.
    ///
    /// # Errors
    /// As [`SharedEndpoint::bind`].
    pub fn bind(signer: Arc<dyn RootSigner + Send + Sync>, addr: SocketAddr) -> Result<Self> {
        SharedEndpoint::bind(addr)?.register_as(signer, None, true)
    }

    /// [`Self::bind`] on a caller-supplied datagram socket ([`SharedEndpoint::bind_abstract`]).
    ///
    /// # Errors
    /// As [`SharedEndpoint::bind_abstract`].
    pub fn bind_abstract(
        signer: Arc<dyn RootSigner + Send + Sync>,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
    ) -> Result<Self> {
        SharedEndpoint::bind_abstract(socket)?.register_as(signer, None, true)
    }

    /// The shared endpoint this view is on.
    #[must_use]
    pub fn shared(&self) -> &Arc<SharedEndpoint> {
        &self.shared
    }

    /// Whether this view's node had the endpoint to itself.
    #[must_use]
    pub fn is_solo(&self) -> bool {
        self.solo
    }

    /// Attach a relay circuit to `peer` (ADR-012 rung 4): datagrams the endpoint
    /// sends to the port's own [`CircuitPort::addr`] come out of it, and datagrams
    /// its inlet is fed arrive from that address. Dialling that address then runs
    /// the ordinary handshake and exchange, pinned to `peer`, over whatever carries the port.
    ///
    /// # Errors
    /// If the OS CSPRNG is unavailable, since the address is drawn from it.
    pub fn attach_circuit(
        &self,
        peer: &Digest32,
        carrier: Option<crate::transport::mux::CircuitCarrier>,
    ) -> Result<CircuitPort> {
        self.shared.mux.attach(&self.local_id, peer, None, carrier)
    }

    /// Attach an **inbound** circuit from `peer`, carried by `relay`, as
    /// [`Self::attach_circuit_via`] does, recording where its far end comes from (V210-92). The
    /// connection the circuit makes carries it as [`VoxConnection::circuit_origin`].
    ///
    /// # Errors
    /// If the OS CSPRNG is unavailable, since the address is drawn from it.
    pub fn attach_inbound_circuit(
        &self,
        peer: &Digest32,
        relay: &Digest32,
        origin: crate::transport::mux::CircuitOrigin,
        carrier: Option<crate::transport::mux::CircuitCarrier>,
    ) -> Result<CircuitPort> {
        self.shared
            .mux
            .attach_via(&self.local_id, peer, relay, Some(origin), carrier)
    }

    /// [`VoxEndpoint::attach_circuit`], recording `relay` as the peer carrying it.
    ///
    /// # Errors
    /// As [`VoxEndpoint::attach_circuit`].
    pub fn attach_circuit_via(
        &self,
        peer: &Digest32,
        relay: &Digest32,
        carrier: Option<crate::transport::mux::CircuitCarrier>,
    ) -> Result<CircuitPort> {
        self.shared
            .mux
            .attach_via(&self.local_id, peer, relay, None, carrier)
    }

    /// The relay carrying this node's live circuit to `peer`, if one is recorded.
    #[must_use]
    pub fn circuit_relay_of(&self, peer: &Digest32) -> Option<Digest32> {
        self.shared.mux.circuit_relay_of(&self.local_id, peer)
    }

    /// Whether `addr` is a **live circuit** on this endpoint's socket — answered from the
    /// mux's table, which is the only authority on it.
    #[must_use]
    pub fn is_circuit(&self, addr: std::net::SocketAddr) -> bool {
        self.shared.mux.is_circuit(addr)
    }

    /// The address this node's newest live circuit to `peer` stands at, if it has one.
    #[must_use]
    pub fn circuit_addr_of(&self, peer: &Digest32) -> Option<std::net::SocketAddr> {
        self.shared.mux.circuit_addr_of(&self.local_id, peer)
    }

    /// How many relay circuits are attached for this node.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.shared.mux.circuit_count(&self.local_id)
    }

    /// The largest UDP payload this endpoint advertises and searches up to (see
    /// [`mtu_ceiling_for`]).
    #[must_use]
    pub fn mtu_ceiling(&self) -> u16 {
        self.shared.mtu_ceiling
    }

    /// The bound local socket address (useful when binding to port 0).
    ///
    /// # Errors
    /// If the socket has none.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.shared.local_addr()
    }

    /// This node's identity fingerprint.
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.local_id
    }

    /// The node this view is ([`LocalNode`]).
    #[must_use]
    pub fn local(&self) -> &Arc<LocalNode> {
        &self.local
    }

    /// Dial `addr` as this node, requiring the node that answers to prove it is
    /// `expected_peer`.
    ///
    /// The neutral TLS handshake (post-quantum group, no classical fallback), then the identity
    /// exchange as the dialler ([`identity::dial`]): this node shows who it is only once the
    /// other end has proved, on this TLS session, to be `expected_peer`. Anything else — a
    /// refusal, a `PROVE` that does not verify, silence — says "nothing at `addr` answers as
    /// `expected_peer`" and names nobody (ADR-011 38a).
    ///
    /// # Errors
    /// As above, or a handshake failure by its own cause.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected_peer: Digest32,
        now_secs: u64,
    ) -> Result<VoxConnection> {
        // Read before the first packet leaves: see [`VoxConnection::via_circuit`].
        let via_circuit = self.shared.mux.is_circuit(addr);
        let carrier = self.shared.mux.carrier_of(addr);
        // The SNI is a fixed placeholder: it carries no identity (ADR-011 requirement 27), and
        // rustls requires a syntactically valid name.
        let connecting = self
            .shared
            .endpoint
            .connect_with(self.shared.client.clone(), addr, "vox.invalid")
            .map_err(|_| Error::MalformedBundle("quic connect"))?;
        let signer = lock(&self.signer)
            .clone()
            .ok_or_else(|| Error::Handshake("this node is detached".to_owned()))?;
        let connection = connecting.await.map_err(handshake_failed)?;
        let proven = identity::dial(&connection, &*signer, self.local.instance(), expected_peer)
            .await
            .map_err(|f| f.into_error(addr, &expected_peer))?;
        self.shared.track(self.local_id, &connection);
        let mut conn = finish_connection(
            connection,
            Arc::clone(&self.local),
            &proven,
            now_secs,
            via_circuit,
            (!via_circuit).then(|| self.shared.overflow.clone()),
        )?;
        conn.carrier = carrier.filter(|_| via_circuit);
        Ok(conn)
    }

    /// Accept the next inbound connection for this node, admitting **any proven Vox
    /// identity** (the open-swarm default — see [`Admission`]). `Ok(None)` when the endpoint is
    /// closed. For a solo endpoint; on a shared one the presence accepts and routes.
    ///
    /// # Errors
    /// A failed handshake or exchange.
    pub async fn accept(&self, now_secs: u64) -> Result<Option<VoxConnection>> {
        self.accept_with_admission(now_secs, Admission::AcceptAnyAuthenticated)
            .await
    }

    /// Accept the next inbound connection, enforcing `admission` after the exchange proved who
    /// dialled. A proven but not admitted peer is closed with
    /// [`WireError::AuthenticatorInvalid`] and this returns `Err`.
    ///
    /// # Errors
    /// As [`Self::finish_incoming`].
    pub async fn accept_with_admission(
        &self,
        now_secs: u64,
        admission: Admission,
    ) -> Result<Option<VoxConnection>> {
        let Some(incoming) = self.accept_incoming().await else {
            return Ok(None);
        };
        self.finish_incoming(incoming, now_secs, admission)
            .await
            .map(Some)
    }

    /// **Phase one of accepting: wait for an inbound connection attempt and return
    /// immediately, doing no handshake.** See [`SharedEndpoint::accept_incoming`].
    ///
    /// `None` when the endpoint is closed.
    pub async fn accept_incoming(&self) -> Option<quinn::Incoming> {
        self.shared.accept_incoming().await
    }

    /// **Phase two: complete one connection's handshake, exchange and admission** as this node
    /// ([`SharedEndpoint::finish_incoming`]). A connection the exchange filed under another node
    /// of the endpoint is closed: this view accepts only its own.
    ///
    /// # Errors
    /// A failed handshake or exchange, another node's connection, or a peer not admitted.
    pub async fn finish_incoming(
        &self,
        incoming: quinn::Incoming,
        now_secs: u64,
        mut admission: Admission,
    ) -> Result<VoxConnection> {
        let conn = self.shared.finish_incoming(incoming, now_secs).await?;
        if conn.local_id() != self.local_id {
            conn.close(WireError::ShuttingDown);
            return Err(Error::Handshake(
                "a connection for another node of this endpoint".to_owned(),
            ));
        }
        // Transport-layer admission, after the exchange. A non-admitted peer is
        // closed with the coded reason and rejected.
        if !admission.admits(&conn.peer_id()) {
            conn.close(WireError::AuthenticatorInvalid);
            return Err(Error::SignatureInvalid);
        }
        Ok(conn)
    }

    /// **Take this node off the endpoint** (ADR-026 L-3, ADR-011 requirement 34): its signer
    /// leaves the exchange, so nothing more is answered as it. Its connections stay as they are;
    /// closing them is the caller's (D-5: only this node's, in their order).
    pub fn unregister(&self) {
        self.shared.unregister(&self.local);
        lock(&self.signer).take();
    }

    /// Close this node's part: unregister it, and close the endpoint itself — every connection
    /// on it — only when the node had it to itself. On a shared endpoint every other node's
    /// connections are untouched (ADR-026 D-5).
    pub fn close(&self) {
        self.unregister();
        if self.solo {
            self.shared.close();
        }
    }

    /// Wait until every connection of the endpoint has finished closing. Meaningful for a solo
    /// endpoint, after [`Self::close`]; callers bound it.
    pub async fn wait_idle(&self) {
        self.shared.wait_idle().await;
    }
}

impl Drop for VoxEndpoint {
    fn drop(&mut self) {
        // A view that goes away takes its node off the exchange with it: no signer outlives the
        // node's use of it.
        self.unregister();
    }
}

/// The most of what a peer wrote that vox prints (V210-154): a connection-close reason is the
/// peer's to fill, up to what fits in a packet.
pub const PEER_TEXT: usize = 200;

/// Text a peer wrote, as vox may print it (V210-154): through the same sanitiser as an author's
/// name in a room (V210-123), so it stays on one line and drives nothing in the terminal, and
/// capped at [`PEER_TEXT`] bytes.
#[must_use]
pub fn peer_text(s: &str) -> String {
    vox_text::shown(s.trim(), PEER_TEXT)
}

/// A connection's end as vox may print it (V210-154). quinn's own rendering of a close quotes
/// the peer's reason byte for byte, escape sequences and line breaks included; this gives the
/// same facts with the reason through [`peer_text`].
#[must_use]
pub fn closed_text(e: &quinn::ConnectionError) -> String {
    use quinn::ConnectionError as C;
    let said = |reason: &[u8]| match String::from_utf8_lossy(reason).trim() {
        "" => String::new(),
        r => format!(": {}", peer_text(r)),
    };
    match e {
        C::ConnectionClosed(c) => format!("aborted by peer: {}{}", c.error_code, said(&c.reason)),
        C::ApplicationClosed(a) => {
            format!("closed by peer: code {}{}", a.error_code, said(&a.reason))
        }
        other => peer_text(&other.to_string()),
    }
}

/// What a failed QUIC handshake is reported as: a failure of authentication as
/// [`Error::SignatureInvalid`], anything else by its own cause ([`Error::Handshake`]).
///
/// Authentication happens inside TLS, so it fails as a TLS alert: a QUIC crypto error
/// (`0x100`–`0x1ff`), raised here when the peer's certificate does not verify or names another
/// identity, or received from a peer that refused ours. Everything else — a refusal, a close, a
/// peer that never answered, this endpoint closing — is not about keys, and saying "signature
/// verification failed" for it sent the operator after the wrong thing.
///
/// A refusal is a peer that is busy (V210-86, #278): a node past its cap on handshakes refuses
/// what it cannot take in time, and its dialler is to say so and try again shortly, not report
/// a fault.
fn handshake_failed(e: quinn::ConnectionError) -> Error {
    use quinn::ConnectionError as C;
    let tls = |code: quinn::TransportErrorCode| (0x100..0x200).contains(&u64::from(code));
    // A QUIC crypto error is 0x100 plus the TLS alert.
    let alert = |code: quinn::TransportErrorCode| {
        let n = u8::try_from(u64::from(code) - 0x100).unwrap_or(u8::MAX);
        format!("TLS alert {n} ({:?})", rustls::AlertDescription::from(n))
    };
    match e {
        // This end refused the peer's TLS: not a Vox daemon's neutral leaf, or not the group.
        C::TransportError(t) if tls(t.code) => Error::HandshakeAuth(format!(
            "this node refused the peer's TLS handshake ({}): {}",
            alert(t.code),
            peer_text(&t.reason)
        )),
        // The peer refused this node's TLS, and sent only its alert.
        C::ConnectionClosed(c) if tls(c.error_code) => Error::HandshakeAuth(format!(
            "the peer refused this node's TLS handshake ({}){}",
            alert(c.error_code),
            match String::from_utf8_lossy(&c.reason).trim() {
                "" => String::new(),
                r => format!(": {}", peer_text(r)),
            }
        )),
        C::ConnectionClosed(c) if c.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED => {
            Error::Handshake("the peer is busy: it refused the connection for now".to_owned())
        }
        C::TimedOut => Error::Handshake("the peer did not answer".to_owned()),
        C::LocallyClosed => Error::Handshake("this node's endpoint is closing".to_owned()),
        other => Error::Handshake(closed_text(&other)),
    }
}

/// Confirm the negotiated group, record the session, and build the connection — once the
/// identity exchange has proved who the peer is (`proven`).
///
/// The session record is written only now (ADR-011 requirement 33), and the remote process is
/// `sha256(the peer daemon's leaf ‖ the peer node's instance)` (requirement 35, ADR-026 I-3): the
/// leaf is per daemon run and shared by its nodes, the instance per attach, so a node that
/// re-attaches — or a daemon that restarts — is a new process to its peers. The datagram router
/// starts here too, after the exchange, never before.
fn finish_connection(
    connection: Connection,
    local: Arc<LocalNode>,
    proven: &identity::Proven,
    now_secs: u64,
    via_circuit: bool,
    overflow: Option<tokio::sync::watch::Receiver<Option<(u32, u32)>>>,
) -> Result<VoxConnection> {
    let peer_id = proven.peer;
    // Confirm the handshake ran under the Vox configuration and read the key-exchange group it
    // actually negotiated; a session under any group but the post-quantum hybrid is refused.
    let group = confirm_handshake(&connection)?;
    let session = SessionEstablishment::observed(peer_id, group, now_secs)?;
    let peer_process = connection
        .peer_identity()
        .and_then(|any| {
            any.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|chain| {
            chain
                .first()
                .map(|leaf| identity::remote_process(leaf.as_ref(), &proven.instance))
        })
        .ok_or(Error::SignatureInvalid)?;
    Ok(VoxConnection {
        serial: NEXT_SERIAL.fetch_add(1, Ordering::Relaxed),
        local,
        peer_id,
        peer_process,
        session,
        via_circuit,
        circuit_origin: None,
        router: DatagramRouter::start(connection.clone(), overflow),
        connection,
        closed_here: std::sync::OnceLock::new(),
        peer_stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        carrier: None,
        tunnels: Arc::new(Mutex::new(0)),
        dropped: None,
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Confirm this handshake ran under the Vox TLS configuration, by its ALPN, and return the
/// key-exchange group it **negotiated**, read from rustls through quinn's handshake data
/// (V030-33).
///
/// It used to check only the ALPN while the session record wrote the group from a constant, so
/// the downgrade-auditability record restated the configuration rather than observing the
/// handshake. Now the record carries what rustls negotiated, and
/// [`SessionEstablishment::observed`] refuses a session under any group but X25519MLKEM768 —
/// defence in depth beneath the provider, which offers no other group
/// (`provider::assert_pq_only`), and TLS 1.3, which binds the group into the Finished MAC.
fn confirm_handshake(connection: &Connection) -> Result<u16> {
    let Some(hd) = connection.handshake_data() else {
        return Err(Error::SignatureInvalid);
    };
    let Some(hd) = hd.downcast_ref::<quinn::crypto::rustls::HandshakeData>() else {
        return Err(Error::SignatureInvalid);
    };
    match &hd.protocol {
        Some(p) if p.as_slice() == crate::transport::provider::VOX_ALPN => {
            Ok(u16::from(hd.negotiated_key_exchange_group))
        }
        _ => Err(Error::SignatureInvalid),
    }
}

/// An authenticated QUIC connection to one Vox peer.
///
/// Owns the connection's [`DatagramRouter`], started with it: every datagram the peer
/// sends is read there and handed to the flow it names, so there is no way to read a
/// datagram that bypasses the flow table (ADR-022).
pub struct VoxConnection {
    /// This connection's name in this process, never given to another (see [`Self::serial`]).
    serial: u64,
    connection: Connection,
    /// The node this end is: whose tunnels this connection's are, in a process hosting several
    /// nodes (ADR-026 P-1).
    local: Arc<LocalNode>,
    peer_id: Digest32,
    /// Which process of `peer_id` this connection is to: the digest of its per-process leaf
    /// certificate (see [`Self::peer_process`]).
    peer_process: Digest32,
    session: SessionEstablishment,
    /// Whether this connection was set up over a relay circuit (see [`Self::via_circuit`]).
    via_circuit: bool,
    /// Where an inbound circuit's far end comes from (see [`Self::circuit_origin`]).
    circuit_origin: Option<crate::transport::mux::CircuitOrigin>,
    router: Arc<DatagramRouter>,
    /// The code this end closed the connection with, if it did (see [`Self::closed_here`]).
    closed_here: std::sync::OnceLock<WireError>,
    /// Whether the peer said it is stopping (see [`Self::peer_stopped`]). Shared, so a
    /// connection over a circuit this one carries can tell (see [`Self::carrier_stopped`]).
    peer_stopped: Arc<std::sync::atomic::AtomicBool>,
    /// Who carries this connection, if it runs over a circuit (see [`Self::carrier_stopped`]).
    carrier: Option<crate::transport::mux::CircuitCarrier>,
    /// Tunnels running on this connection, each credited a stream window of its own
    /// ([`VoxConnection::carry_tunnel`]). Shared with each [`TunnelCredit`], so a credit needs no
    /// borrow of the connection.
    tunnels: Arc<Mutex<u32>>,
    /// Told when this is dropped (see [`Self::tell_when_dropped`]).
    dropped: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for VoxConnection {
    fn drop(&mut self) {
        // The router's reader holds a connection handle; without this it would keep
        // an otherwise-unused connection open for ever. Flows still bound keep it
        // reading until they end.
        self.router.release_owner();
    }
}

/// A tunnel's share of its connection's receive window, held for as long as the tunnel runs
/// (see [`CONNECTION_WINDOW`]). Dropping it gives the share back, and takes the tunnel off
/// [`live_tunnels`].
#[must_use = "the credit lasts only as long as the guard is held"]
pub struct TunnelCredit {
    tunnels: Arc<Mutex<u32>>,
    connection: Connection,
    id: u64,
    watch: TunnelWatch,
}

impl TunnelCredit {
    /// What the tunnel's splice marks and listens to: when it last moved a byte, and whether it
    /// has been asked to close (see [`TunnelWatch`]).
    #[must_use]
    pub fn watch(&self) -> TunnelWatch {
        self.watch.clone()
    }
}

impl Drop for TunnelCredit {
    fn drop(&mut self) {
        // One lock at a time, as `carry_tunnel` takes them.
        {
            let mut n = lock(&self.tunnels);
            *n = n.saturating_sub(1);
            set_tunnel_window(&self.connection, *n);
        }
        let Some(live) = lock(&LIVE).remove(&self.id) else {
            return;
        };
        // A tunnel that ended for a reason someone should see — closed by a person, closed as
        // stuck, closed at its other end — is kept on the closed list with that reason.
        if let Some(why) = lock(&self.watch.why).clone() {
            let mut closed = lock(&CLOSED);
            // Kept per node: one node's busy day must not push another's history off the list.
            if closed.iter().filter(|t| t.owner == live.owner).count() >= CLOSED_KEPT {
                if let Some(oldest) = closed.iter().position(|t| t.owner == live.owner) {
                    closed.remove(oldest);
                }
            }
            closed.push_back(ClosedTunnel {
                owner: live.owner,
                id: self.id,
                peer: live.peer,
                service: live.service,
                outbound: live.outbound,
                opened: live.opened,
                closed: unix_now_ms(),
                why,
            });
        }
    }
}

/// A running tunnel's side of its entry in the live list (V030-11): where its splice marks the
/// time it last moved a byte, and how it is asked to close and says why it ended.
#[derive(Clone, Debug)]
pub struct TunnelWatch {
    moved: Arc<AtomicU64>,
    close: Arc<tokio::sync::Notify>,
    why: Arc<Mutex<Option<String>>>,
    /// The node this end of the tunnel is (ADR-026 P-1): whose stop waits for its last bytes.
    owner: Digest32,
    /// How long its owner gives it with bytes waiting before it is closed as stuck, as the
    /// owner had it when the tunnel opened.
    stuck_after: std::time::Duration,
    /// For a tunnel this node serves, the local address of its connection to the service: how
    /// the service can ask which member a connection is (ADR-028 F-7, [`tunnel_peer_at`]).
    local: Arc<Mutex<Option<SocketAddr>>>,
}

impl TunnelWatch {
    fn new(now: u64, owner: Digest32, stuck_after: std::time::Duration) -> Self {
        Self {
            moved: Arc::new(AtomicU64::new(now)),
            close: Arc::new(tokio::sync::Notify::new()),
            why: Arc::new(Mutex::new(None)),
            owner,
            stuck_after,
            local: Arc::new(Mutex::new(None)),
        }
    }

    /// Record the local address of a served tunnel's connection to its service.
    pub fn set_local(&self, at: Option<SocketAddr>) {
        *lock(&self.local) = at;
    }

    /// The node this end of the tunnel is.
    #[must_use]
    pub fn owner(&self) -> Digest32 {
        self.owner
    }

    /// How long this tunnel's bytes may wait before it is closed as stuck: its node's setting.
    #[must_use]
    pub fn stuck_after(&self) -> std::time::Duration {
        self.stuck_after
    }

    /// Mark that the tunnel moved a byte just now.
    pub fn mark_moved(&self) {
        self.moved.store(unix_now_ms(), Ordering::Relaxed);
    }

    /// Resolves once the tunnel is asked to close ([`close_tunnels`]), with the reason.
    pub async fn close_asked(&self) -> String {
        self.close.notified().await;
        lock(&self.why).clone().unwrap_or_default()
    }

    /// Record why the tunnel ended, for [`closed_tunnels`]; the first reason stands.
    pub fn ended(&self, why: &str) {
        let mut w = lock(&self.why);
        if w.is_none() {
            *w = Some(why.to_owned());
        }
    }

    fn ask_to_close(&self, why: &str) {
        self.ended(why);
        // `notify_one` keeps a permit, so a splice that has not started listening yet still
        // hears it.
        self.close.notify_one();
    }
}

/// A tunnel that ended for a reason a person should see, as `vox status` and the TUI list it
/// (V030-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedTunnel {
    /// The node it was this end of (ADR-026 P-1).
    pub owner: Digest32,
    /// Its number while it ran ([`LiveTunnel::id`]).
    pub id: u64,
    /// The member at the other end.
    pub peer: Digest32,
    /// The service it reached.
    pub service: String,
    /// Whether this node opened it.
    pub outbound: bool,
    /// When it was opened, in Unix milliseconds.
    pub opened: u64,
    /// When it ended, in Unix milliseconds.
    pub closed: u64,
    /// Why: closed by a person here, closed at the other end, or closed as stuck.
    pub why: String,
}

/// How many ended tunnels [`closed_tunnels`] keeps for each node, newest last.
const CLOSED_KEPT: usize = 32;

/// The tunnels that ended for a reason, newest last ([`ClosedTunnel`]).
static CLOSED: Mutex<std::collections::VecDeque<ClosedTunnel>> =
    Mutex::new(std::collections::VecDeque::new());

/// The tunnels of the node `owner` that ended for a reason a person should see, oldest first.
#[must_use]
pub fn closed_tunnels(owner: &Digest32) -> Vec<ClosedTunnel> {
    lock(&CLOSED)
        .iter()
        .filter(|t| t.owner == *owner)
        .cloned()
        .collect()
}

/// Which live tunnels to close (V030-11): one by its number, or a member's — all of them, or
/// those to one service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelSelector {
    /// One tunnel, by [`LiveTunnel::id`].
    pub id: Option<u64>,
    /// The member's id as `vox status` prints it, or a prefix of it (case does not matter).
    pub member: Option<String>,
    /// Only the tunnels to this service.
    pub service: Option<String>,
}

impl TunnelSelector {
    /// Whether it names anything: a selector naming nothing closes nothing, never everything.
    #[must_use]
    pub fn names_something(&self) -> bool {
        self.id.is_some() || self.member.is_some()
    }

    fn matches(&self, id: u64, t: &Live) -> bool {
        if !self.names_something() {
            return false;
        }
        let member = self.member.as_ref().is_none_or(|m| {
            crate::node::link::b32_encode(&t.peer).starts_with(&m.to_ascii_lowercase())
        });
        self.id.is_none_or(|i| i == id)
            && member
            && self.service.as_ref().is_none_or(|s| *s == t.service)
    }
}

/// Close every live tunnel `which` names, saying `why` to whoever looks (`vox status`, the
/// TUI) and, by a reset with [`TUNNEL_CLOSED_CODE`](crate::tunnel::session::TUNNEL_CLOSED_CODE),
/// to the far end. Neither untrusts anyone nor removes a service. The tunnels it asked to close,
/// as they were.
///
/// # Errors
/// What to tell the person, closing nothing, when `which` names a member by a prefix that more
/// than one member's tunnels match: "a person closes one member's tunnels" (V030-11), and a
/// short or mistyped prefix must not close several members' at once.
pub fn close_tunnels(
    owner: &Digest32,
    which: &TunnelSelector,
    why: &str,
) -> std::result::Result<Vec<LiveTunnel>, String> {
    let live = lock(&LIVE);
    // Only the node's own: a process may host several (ADR-026 P-1), and one node closing
    // another's tunnel by its number or its member is the leak this filter exists to stop.
    let live: std::collections::BTreeMap<&u64, &Live> =
        live.iter().filter(|(_, t)| t.owner == *owner).collect();
    if let Some(prefix) = &which.member {
        let members: std::collections::BTreeSet<String> = live
            .iter()
            .filter(|(id, t)| which.matches(***id, t))
            .map(|(_, t)| crate::node::link::b32_encode(&t.peer))
            .collect();
        if members.len() > 1 {
            return Err(format!(
                "{prefix:?} matches more than one member with a live tunnel, so nothing was \
                 closed — give more of the id:\n       {}",
                members.into_iter().collect::<Vec<_>>().join("\n       ")
            ));
        }
    }
    Ok(live
        .iter()
        .filter(|(id, t)| which.matches(***id, t))
        .map(|(id, t)| {
            t.watch.ask_to_close(why);
            t.listed(**id)
        })
        .collect())
}

/// One live tunnel, as `vox status` lists it (V210-81): so a person can see which tunnels hold a
/// member's connection, and which of them is stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTunnel {
    /// Its number in this node, for closing it ([`TunnelSelector::id`]).
    pub id: u64,
    /// The member at the other end.
    pub peer: Digest32,
    /// The service it reaches: a port, or a share's tag.
    pub service: String,
    /// Whether this node opened it (to reach the member's service), rather than serving it.
    pub outbound: bool,
    /// When it was opened, in Unix milliseconds.
    pub opened: u64,
    /// When it last moved a byte either way, in Unix milliseconds; `opened` until it has.
    pub last_moved: u64,
}

/// A live tunnel's entry in [`LIVE`].
struct Live {
    /// The node this end of the tunnel is (ADR-026 P-1).
    owner: Digest32,
    peer: Digest32,
    service: String,
    outbound: bool,
    opened: u64,
    watch: TunnelWatch,
}

impl Live {
    fn listed(&self, id: u64) -> LiveTunnel {
        LiveTunnel {
            id,
            peer: self.peer,
            service: self.service.clone(),
            outbound: self.outbound,
            opened: self.opened,
            last_moved: self.watch.moved.load(Ordering::Relaxed).max(self.opened),
        }
    }
}

/// Every tunnel this process carries now, by a number of its own. A process may host several
/// nodes (ADR-026 P-1), so each entry names its node, and every reader filters by it.
static LIVE: Mutex<std::collections::BTreeMap<u64, Live>> =
    Mutex::new(std::collections::BTreeMap::new());

/// The next key in [`LIVE`].
static NEXT_TUNNEL: AtomicU64 = AtomicU64::new(0);

/// The time now in Unix seconds.
#[must_use]
pub fn unix_now() -> u64 {
    unix_now_ms() / 1_000
}

/// The time now in Unix milliseconds, as [`LiveTunnel`] states times.
#[must_use]
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The member at the other end of the tunnel `owner` serves whose connection to its service comes
/// from `from`: what a service on this machine sees as its client's address. `None` for a
/// connection no tunnel made.
#[must_use]
pub fn tunnel_peer_at(owner: &Digest32, from: SocketAddr) -> Option<Digest32> {
    lock(&LIVE)
        .values()
        .find(|t| t.owner == *owner && !t.outbound && *lock(&t.watch.local) == Some(from))
        .map(|t| t.peer)
}

/// Every tunnel the node `owner` carries now, oldest first.
#[must_use]
pub fn live_tunnels(owner: &Digest32) -> Vec<LiveTunnel> {
    lock(&LIVE)
        .iter()
        .filter(|(_, t)| t.owner == *owner)
        .map(|(id, t)| t.listed(*id))
        .collect()
}

/// What a person is told when a tunnel is refused at the cap: how many are open to this member,
/// to which services, and how to free one (decider, 2026-10-01).
fn limit_said(
    live: &std::collections::BTreeMap<u64, Live>,
    owner: &Digest32,
    peer: &Digest32,
) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for t in live
        .values()
        .filter(|t| t.owner == *owner && t.peer == *peer)
    {
        *counts.entry(t.service.clone()).or_default() += 1;
    }
    let services: Vec<String> = counts
        .iter()
        .map(|(s, n)| {
            if *n == 1 {
                s.clone()
            } else {
                format!("{s} ×{n}")
            }
        })
        .collect();
    format!(
        "{TUNNELS_PER_PEER} tunnels are already open to this member (to {})\n       \
         to free one: `vox tunnel close` it (`vox status` lists every tunnel, its number, and when \
         it last moved), close the program using it, or restart the `vox up` or `vox forward` \
         carrying it; on the host, `vox service remove` the service, or `vox trust remove` the \
         member",
        services.join(", ")
    )
}

/// Set `connection`'s receive window for `tunnels` running tunnels.
fn set_tunnel_window(connection: &Connection, tunnels: u32) {
    let window = u64::from(CONNECTION_WINDOW) + u64::from(tunnels) * u64::from(STREAM_WINDOW);
    connection.set_receive_window(quinn::VarInt::from_u64(window).unwrap_or(quinn::VarInt::MAX));
}

/// Whether `peer` already has as many live tunnels with this node as it may, on whatever
/// connections they run.
fn at_tunnel_cap(
    live: &std::collections::BTreeMap<u64, Live>,
    owner: &Digest32,
    peer: &Digest32,
) -> bool {
    live.values()
        .filter(|t| t.owner == *owner && t.peer == *peer)
        .count()
        >= TUNNELS_PER_PEER as usize
}

/// The next [`VoxConnection::serial`].
static NEXT_SERIAL: AtomicU64 = AtomicU64::new(0);

impl VoxConnection {
    /// Credit one more running tunnel with a stream window of its own on top of
    /// [`CONNECTION_WINDOW`], for as long as the returned guard is held — so a tunnel whose
    /// local reader has stopped cannot take the credit the room's other streams need.
    ///
    /// [`Error::TunnelLimit`] when the member already has [`TUNNELS_PER_PEER`] tunnels with this
    /// node, on this connection or any other: the tunnel is to be refused, not carried on memory
    /// past the member's bound.
    ///
    /// Take it only for a tunnel this node authorized or opened for its own application: the
    /// credit is memory this node agrees to hold for that peer. `service` and `outbound` are what
    /// [`live_tunnels`] lists it as.
    pub fn carry_tunnel(&self, service: &str, outbound: bool) -> Result<TunnelCredit> {
        let id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
        let opened = unix_now_ms();
        let watch = TunnelWatch::new(opened, self.local.id, self.local.stuck_after());
        {
            // Counted and taken under one lock, so two tunnels asked for at once cannot both
            // take the last place.
            let mut live = lock(&LIVE);
            if at_tunnel_cap(&live, &self.local.id, &self.peer_id) {
                return Err(Error::TunnelLimit(limit_said(
                    &live,
                    &self.local.id,
                    &self.peer_id,
                )));
            }
            live.insert(
                id,
                Live {
                    owner: self.local.id,
                    peer: self.peer_id,
                    service: service.to_owned(),
                    outbound,
                    opened,
                    watch: watch.clone(),
                },
            );
        }
        // This connection's own count only sizes its receive window: each tunnel's stream
        // window is credited where it runs.
        let mut n = lock(&self.tunnels);
        *n += 1;
        set_tunnel_window(&self.connection, *n);
        drop(n);
        Ok(TunnelCredit {
            tunnels: Arc::clone(&self.tunnels),
            connection: self.connection.clone(),
            id,
            watch,
        })
    }

    /// [`Error::TunnelLimit`] if this connection's member already has as many tunnels with this
    /// node as it may ([`TUNNELS_PER_PEER`]), so another would be refused.
    ///
    /// # Errors
    /// [`Error::TunnelLimit`], saying what it holds and how to free one.
    pub fn room_for_a_tunnel(&self) -> Result<()> {
        let live = lock(&LIVE);
        if at_tunnel_cap(&live, &self.local.id, &self.peer_id) {
            return Err(Error::TunnelLimit(limit_said(
                &live,
                &self.local.id,
                &self.peer_id,
            )));
        }
        Ok(())
    }

    /// [`Error::TunnelLimit`] as this node words it, for a refusal the **host** made at the cap
    /// (`TunnelStatus::Full`): the member's live tunnels here are the same ones it counted.
    #[must_use]
    pub fn tunnel_limit(&self) -> Error {
        Error::TunnelLimit(limit_said(&lock(&LIVE), &self.local.id, &self.peer_id))
    }

    /// **A name for this connection that no other connection in this process is ever given.**
    ///
    /// quinn's `stable_id` is not one: it is the address of the connection's state, and a
    /// connection allocated after another was freed can be given the same address. Anything
    /// that remembers connections past their lifetime — which have a stream loop, when each
    /// was last heard — keys on this instead.
    #[must_use]
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// The node this end of the connection is: whose tunnels and counts its are (ADR-026 P-1).
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.local.id
    }

    /// The node this end is ([`LocalNode`]).
    #[must_use]
    pub fn local(&self) -> &Arc<LocalNode> {
        &self.local
    }

    /// The authenticated peer identity fingerprint.
    #[must_use]
    pub fn peer_id(&self) -> Digest32 {
        self.peer_id
    }

    /// Which **process** of the peer's identity this connection is to: the digest of the
    /// peer's leaf certificate, whose key is generated per endpoint and so per process, and is
    /// bound to the identity by the identity's signature (ADR-011). Two connections to one
    /// identity with different values are to two processes of it; one profile is held by one
    /// process at a time, and an identity is one device's (V210-57).
    #[must_use]
    pub fn peer_process(&self) -> Digest32 {
        self.peer_process
    }

    /// Whether this connection was **set up over a relay circuit** (ADR-012 rung 4) — a fact
    /// about the connection, fixed when it was made, and the same at both ends: a circuit is a
    /// circuit at the dialler's socket and at the acceptor's.
    ///
    /// It is recorded rather than asked of the mux later because the mux's answer changes. The
    /// mux holds one circuit per peer, so a second circuit to the same peer detaches the first,
    /// and from then on the first connection's address is in nobody's table: asked afresh, it
    /// looked like a **direct** connection. It is the opposite — a relayed connection with no
    /// relay under it, which can send nothing — and it won the tie-break against the live
    /// circuit on "better path" at both ends (V29-15).
    ///
    /// Read from the table before this end sends its first packet. A circuit detached before
    /// then leaves nothing to carry the handshake, so a connection that completes was on a
    /// circuit exactly when this says so.
    #[must_use]
    pub fn via_circuit(&self) -> bool {
        self.via_circuit
    }

    /// **Where the far end of an inbound circuit comes from** (V210-92): the source the node
    /// recorded when it attached the circuit, from what the relay said of the asker and who the
    /// relay is. `None` on a direct connection and on one this node dialled.
    ///
    /// A circuit's address is made up per circuit and says nothing about the peer behind it, so
    /// without this every relayed join came from one place, and one stranger with many identities
    /// behind one relay tied every newcomer that relay carried.
    #[must_use]
    pub fn circuit_origin(&self) -> Option<crate::transport::mux::CircuitOrigin> {
        self.circuit_origin
    }

    /// The recorded session-establishment entry (tag `0x0011`) for this session,
    /// pinning the negotiated suite + group so a downgrade is auditable.
    #[must_use]
    pub fn session(&self) -> &SessionEstablishment {
        &self.session
    }

    /// The TLS key-exchange group this session negotiated, as rustls observed it in the
    /// handshake (X25519MLKEM768 = `0x11EC`; nothing else is accepted).
    #[must_use]
    pub fn negotiated_group(&self) -> u16 {
        self.session.negotiated_group
    }

    /// Open a fresh outbound bidirectional stream for a logical flow.
    ///
    /// **Bounded, and reported as the peer being gone.** `open_bi` waits for stream credit, and
    /// it waits indefinitely: a peer that stops granting credit — or a connection one end has
    /// retired while the other still holds it — parked the caller for good with no error, and a
    /// sync session parked there holds its room. And a connection that had closed came back as
    /// `MalformedBundle("quic open_bi")`, which nothing maps, so it reached a person as
    /// `Failed(Internal)`: a join whose stream opened on a retired connection said "internal
    /// error" rather than "unreachable". Both failures are the same fact — this peer is not there
    /// on this connection — and now say so.
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
        match tokio::time::timeout(OPEN_STREAM_PATIENCE, self.connection.open_bi()).await {
            Ok(Ok(pair)) => Ok(pair),
            Ok(Err(_)) => Err(Error::Unreachable("quic stream: the connection is closed")),
            Err(_) => Err(Error::Unreachable(
                "quic stream: the peer granted no stream in time",
            )),
        }
    }

    /// Accept the next inbound bidirectional stream the peer opened.
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
        self.connection
            .accept_bi()
            .await
            .map_err(|_| Error::Unreachable("quic stream: the connection is closed"))
    }

    /// Bind a datagram flow to the bidirectional stream `send`/`recv` (ADR-022
    /// decision 1). The flow takes the stream: from here it carries no bytes, and the
    /// flow ends when the stream does — dropped here, or finished, reset or stopped by
    /// the peer. Both ends bind the same stream, so both name the flow by its ID.
    ///
    /// Bind only a stream whose kind's gate has already admitted the peer: a flow
    /// accepts every datagram that names it.
    ///
    /// # Errors
    /// If the connection is closed, or the stream is already bound.
    pub fn bind_flow(&self, send: SendStream, recv: RecvStream) -> Result<DatagramFlow> {
        self.router.bind(send, recv, FlowMode::Packets)
    }

    /// Bind a flow that delivers each datagram's context and body as it arrived,
    /// fragments included, for a relay to [`DatagramFlow::forward`] without reading
    /// or reassembling it (ADR-022 decision 5).
    ///
    /// # Errors
    /// As [`VoxConnection::bind_flow`].
    pub fn bind_forwarding_flow(&self, send: SendStream, recv: RecvStream) -> Result<DatagramFlow> {
        self.router.bind(send, recv, FlowMode::Forward)
    }

    /// Bind a datagram flow to the stream `send` belongs to, **sharing** it: the stream
    /// keeps carrying bytes, and the caller must end the flow with the stream by holding
    /// both in one object (ADR-022 decisions 1 and 7; `node::app::AppStream` is that
    /// object). Crate-private because that discipline is not one to hand out.
    pub(crate) fn bind_shared_flow(&self, send: &SendStream) -> Result<DatagramFlow> {
        self.router
            .bind_shared(u64::from(send.id()), FlowMode::Packets)
    }

    /// This connection's datagram counters: delivered, and dropped by reason.
    #[must_use]
    pub fn datagram_stats(&self) -> DatagramStats {
        self.router.stats()
    }

    /// This connection's receiver-overflow reports, both ways, and what its controller made of
    /// the peer's (ADR-024 RO-7).
    #[must_use]
    pub fn overflow_stats(&self) -> crate::transport::overflow::OverflowStats {
        self.router.overflow_stats()
    }

    /// The largest packet any flow on this connection sends as one datagram right now
    /// (the peer's advertised datagram size less the largest flow header); larger
    /// packets are fragmented. `None` if datagrams are not enabled on the connection.
    #[must_use]
    pub fn max_datagram_payload(&self) -> Option<usize> {
        self.connection
            .max_datagram_size()
            .map(|n| n.saturating_sub(MAX_PACKET_HEADER))
    }

    /// Close the connection with an application code + reason.
    pub fn close(&self, err: WireError) {
        // **A connection already closed keeps the reason it closed with** (V210-93): closing it
        // again here made quinn report it as closed locally, so a peer that said "stopped" was
        // reported as a connection this end gave up on.
        if self.connection.close_reason().is_some() {
            return;
        }
        let _ = self.closed_here.set(err);
        self.connection
            .close(close_code(err), err.to_string().as_bytes());
    }

    /// Record that the peer said it is stopping (a [`StreamKind::Goodbye`] stream).
    ///
    /// [`StreamKind::Goodbye`]: crate::transport::streams::StreamKind::Goodbye
    pub fn mark_peer_stopped(&self) {
        self.peer_stopped.store(true, Ordering::Relaxed);
    }

    /// Whether the peer said it is stopping before this connection ended (V210-93): however it
    /// then ended — its close, or a close of this end's, or nothing at all — it ended because
    /// the peer stopped.
    #[must_use]
    pub fn peer_stopped(&self) -> bool {
        self.peer_stopped.load(Ordering::Relaxed)
    }

    /// This connection as the carrier of a circuit: the peer's identity and its stop flag, for a
    /// circuit opened through it (see [`crate::transport::mux::CircuitCarrier`]).
    #[must_use]
    pub fn as_carrier(&self) -> crate::transport::mux::CircuitCarrier {
        (self.peer_id, Arc::clone(&self.peer_stopped))
    }

    /// **The relay this connection's only path ran through, if that relay said it was stopping**
    /// (V210-93). A connection over a circuit loses its path when its relay stops, though its own
    /// peer is still running; its loss is then the relay's stop, and is said as that.
    #[must_use]
    pub fn carrier_stopped(&self) -> Option<Digest32> {
        self.carrier
            .as_ref()
            .filter(|(_, stopped)| stopped.load(Ordering::Relaxed))
            .map(|(relay, _)| *relay)
    }

    /// The code this end first closed the connection with, through [`Self::close`]: quinn reports
    /// a local close only as "locally closed", which says nothing about why (V210-93).
    #[must_use]
    pub fn closed_here(&self) -> Option<WireError> {
        self.closed_here.get().copied()
    }

    /// A receiver that resolves when this `VoxConnection` is dropped, for a task that holds a
    /// handle of the connection for its own reasons and must not keep it open on that account:
    /// a relay circuit's driver, which lingers until the connection closes (#335).
    pub(crate) fn tell_when_dropped(&mut self) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.dropped = Some(tx);
        rx
    }

    /// The underlying quinn connection, for advanced callers (M11 tunnels).
    #[must_use]
    pub fn quinn(&self) -> &Connection {
        &self.connection
    }
}

// The M5 `Transport` over a reliable QUIC bi-stream lives in its own module to
// keep this file focused on the endpoint/connection lifecycle; it is re-exported
// here so `crate::transport::quic::QuicStreamTransport` remains a stable path.
pub use crate::transport::stream_transport::QuicStreamTransport;
