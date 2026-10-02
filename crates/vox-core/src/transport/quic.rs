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
//! connection"). Low-latency, loss-tolerant flows use RFC 9221 datagrams
//! ([`VoxConnection::send_datagram`] / [`VoxConnection::recv_datagram`]); the
//! connection itself applies the [`crate::transport::datagram`] 64-bit sequence
//! framing and the DTLS-style anti-replay window (ADR-011 §"Datagram
//! anti-replay"), so a replayed, duplicate, out-of-window or unframed datagram is
//! dropped before it can reach the application — that is a property of the
//! connection, never caller discipline (2026-09-19 review).
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
use crate::transport::datagram::{parse_datagram, DatagramSender, ReplayWindow, SEQ_PREFIX_LEN};
use crate::transport::identity_cert::build_leaf_certificate;
use crate::transport::mux::{CircuitPort, MuxSocket};
use crate::transport::provider::{client_config, server_config, X25519MLKEM768_CODE_POINT};
use crate::transport::session::SessionEstablishment;
use crate::transport::verifier::{VerifiedPeer, VoxClientCertVerifier, VoxServerCertVerifier};
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

/// A Vox QUIC endpoint: it owns the local UDP socket and the authenticated TLS
/// configuration, and can both dial peers and accept inbound connections.
///
/// The endpoint holds the local identity (via its leaf certificate) and the shared
/// supported-signature-algorithms set the verifiers need.
pub struct VoxEndpoint {
    endpoint: Endpoint,
    /// The socket the endpoint runs on: the real one plus relay circuits (ADR-012
    /// rung 4). Held so circuits can be attached after binding.
    mux: Arc<MuxSocket>,
    /// The local leaf cert chain + key, re-offered on each dial for mutual auth.
    leaf_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    leaf_key: rustls_pki_types::PrivateKeyDer<'static>,
    /// The provider's signature-verification algorithms, shared with verifiers.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
    /// This endpoint's own identity fingerprint.
    local_id: Digest32,
    /// The largest UDP payload this endpoint advertises and path-MTU discovery searches up to:
    /// [`MAX_UDP_PAYLOAD`] when the socket's receive buffer can take its bursts, else quinn's
    /// Ethernet default. See [`mtu_ceiling_for`].
    mtu_ceiling: u16,
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

/// The endpoint parameters every Vox endpoint runs with.
fn endpoint_config(mtu_ceiling: u16) -> quinn::EndpointConfig {
    let mut cfg = quinn::EndpointConfig::default();
    let _ = cfg.max_udp_payload_size(mtu_ceiling);
    cfg
}

/// The transport parameters every Vox connection runs with, in both directions.
fn transport_config(mtu_ceiling: u16) -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    cfg.keep_alive_interval(Some(KEEP_ALIVE));
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

impl VoxEndpoint {
    /// Bind a Vox endpoint to `addr`, authenticating as `signer`'s identity.
    ///
    /// The endpoint can immediately [`accept`](Self::accept) inbound connections
    /// (open-swarm default: any *authenticated* Vox identity is admitted at the
    /// transport layer and surfaced for upper-layer join/consent authorization —
    /// see [`Admission`]) or [`accept_with_admission`](Self::accept_with_admission)
    /// (to enforce a pinned set / callback), and [`connect`](Self::connect) to
    /// peers (pinning the expected peer identity).
    ///
    /// Per-connection server configs are built lazily on each accept (each needs
    /// its own verifier output slot), so `bind` itself only stores the local leaf
    /// + the provider's supported-signature algorithms.
    pub fn bind<S: RootSigner>(signer: &S, addr: SocketAddr) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(addr).map_err(|e| Error::LocalBind {
            addr,
            in_use: e.kind() == std::io::ErrorKind::AddrInUse,
            reason: e.to_string(),
        })?;
        let effective = {
            let sock = socket2::SockRef::from(&socket);
            let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER);
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
        let wrapped = quinn::TokioRuntime
            .wrap_udp_socket(socket)
            .map_err(|_| Error::MalformedBundle("quic endpoint bind"))?;
        Self::bind_abstract_with(signer, wrapped, mtu_ceiling)
    }

    /// Bind on a caller-supplied datagram socket instead of a real UDP socket.
    ///
    /// Everything above the datagram — the ADR-011 handshake, the composite identity
    /// pinning, the streams — is identical; only where the bytes go changes. This is
    /// how a simulated network with NAT devices is driven in tests (ADR-012 rungs 3
    /// and 4 cannot be demonstrated without a middlebox to traverse), and it is the
    /// hook any other datagram substrate would use.
    pub fn bind_abstract<S: RootSigner>(
        signer: &S,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
    ) -> Result<Self> {
        // A caller-supplied socket has no kernel buffer to overflow.
        Self::bind_abstract_with(signer, socket, MAX_UDP_PAYLOAD)
    }

    fn bind_abstract_with<S: RootSigner>(
        signer: &S,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        mtu_ceiling: u16,
    ) -> Result<Self> {
        // Every endpoint runs on the multiplexer, so a relay circuit can be attached
        // to a real socket and a simulated one alike.
        let mux = MuxSocket::new(socket);
        let for_endpoint: Arc<dyn quinn::AsyncUdpSocket> =
            Arc::clone(&mux) as Arc<dyn quinn::AsyncUdpSocket>;
        Self::bind_with(signer, mux, mtu_ceiling, |cfg| {
            Endpoint::new_with_abstract_socket(
                endpoint_config(mtu_ceiling),
                Some(cfg),
                for_endpoint,
                Arc::new(quinn::TokioRuntime),
            )
        })
    }

    /// Attach a relay circuit to `peer` (ADR-012 rung 4): datagrams the endpoint
    /// sends to the port's own [`CircuitPort::addr`] come out of it, and datagrams
    /// its inlet is fed arrive from that address. Dialling that address then runs
    /// the ordinary handshake, pinned to `peer`, over whatever carries the port.
    ///
    /// # Errors
    /// If the OS CSPRNG is unavailable, since the address is drawn from it.
    pub fn attach_circuit(
        &self,
        peer: &Digest32,
        carrier: Option<crate::transport::mux::CircuitCarrier>,
    ) -> Result<CircuitPort> {
        self.mux.attach(peer, None, carrier)
    }

    /// Attach an **inbound** circuit from `peer`, as [`Self::attach_circuit`] does, recording
    /// where its far end comes from (V210-92). The connection the circuit makes carries it as
    /// [`VoxConnection::circuit_origin`].
    ///
    /// # Errors
    /// If the OS CSPRNG is unavailable, since the address is drawn from it.
    pub fn attach_inbound_circuit(
        &self,
        peer: &Digest32,
        origin: crate::transport::mux::CircuitOrigin,
        carrier: Option<crate::transport::mux::CircuitCarrier>,
    ) -> Result<CircuitPort> {
        self.mux.attach(peer, Some(origin), carrier)
    }

    /// Whether `addr` is a **live circuit** on this endpoint's socket — answered from the
    /// mux's table, which is the only authority on it.
    #[must_use]
    pub fn is_circuit(&self, addr: std::net::SocketAddr) -> bool {
        self.mux.is_circuit(addr)
    }

    /// The address `peer`'s newest live circuit stands at, if it has one. Circuit addresses are
    /// allocated, so this is the only way to get from a peer to its circuit.
    #[must_use]
    pub fn circuit_addr_of(&self, peer: &Digest32) -> Option<std::net::SocketAddr> {
        self.mux.circuit_addr_of(peer)
    }

    /// How many relay circuits are attached.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.mux.circuit_count()
    }

    /// The shared body of the constructors: build this node's leaf credentials and
    /// hand the resulting server config to `make` to produce the endpoint.
    fn bind_with<S: RootSigner>(
        signer: &S,
        mux: Arc<MuxSocket>,
        mtu_ceiling: u16,
        make: impl FnOnce(quinn::ServerConfig) -> std::io::Result<Endpoint>,
    ) -> Result<Self> {
        let leaf = build_leaf_certificate(signer)?;
        let leaf_chain = leaf.cert_chain();
        let leaf_key = leaf.private_key();
        let supported =
            crate::transport::provider::vox_crypto_provider().signature_verification_algorithms;

        // A minimal server config to bind the listening socket. The authenticating
        // verifier is installed per-connection in `accept` (each connection needs
        // its own [`VerifiedPeer`] slot), so this initial config's verifier output
        // is never read — it exists only so `Endpoint::server` has a crypto config.
        let bootstrap_verifier =
            VoxClientCertVerifier::any_identity(supported, VerifiedPeer::new());
        let s_cfg = server_config(
            Arc::new(bootstrap_verifier),
            leaf_chain.clone(),
            leaf.private_key(),
        )?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(s_cfg)
            .map_err(|_| Error::MalformedBundle("quic server config"))?;
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server_cfg.transport_config(transport_config(mtu_ceiling));

        let endpoint =
            make(server_cfg).map_err(|_| Error::MalformedBundle("quic endpoint bind"))?;

        Ok(Self {
            endpoint,
            mux,
            leaf_chain,
            leaf_key,
            supported,
            local_id: leaf.identity_fingerprint(),
            mtu_ceiling,
        })
    }

    /// The largest UDP payload this endpoint advertises and searches up to (see
    /// [`mtu_ceiling_for`]).
    #[must_use]
    pub fn mtu_ceiling(&self) -> u16 {
        self.mtu_ceiling
    }

    /// The bound local socket address (useful when binding to port 0).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|_| Error::MalformedBundle("quic local_addr"))
    }

    /// This endpoint's identity fingerprint.
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.local_id
    }

    /// Dial `addr`, requiring the peer to authenticate as `expected_peer`.
    ///
    /// Fails (no silent fallback) if: the peer cannot negotiate X25519MLKEM768, the
    /// peer's identity does not match `expected_peer`, or its composite PoP does not
    /// verify. On success returns an authenticated [`VoxConnection`] plus the
    /// session-establishment record.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected_peer: Digest32,
        now_secs: u64,
    ) -> Result<VoxConnection> {
        let verified = VerifiedPeer::new();
        let verifier =
            VoxServerCertVerifier::pinned(self.supported, expected_peer, verified.clone());
        let c_cfg = client_config(
            Arc::new(verifier),
            self.leaf_chain.clone(),
            self.clone_key(),
        )?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(c_cfg)
            .map_err(|_| Error::MalformedBundle("quic client config"))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_client));
        client_cfg.transport_config(transport_config(self.mtu_ceiling));

        // Read before the first packet leaves: see [`VoxConnection::via_circuit`].
        let via_circuit = self.mux.is_circuit(addr);
        let carrier = self.mux.carrier_of(addr);
        // The SNI server name is unused for authentication (we authenticate by the
        // Vox identity), but rustls requires a syntactically valid name.
        let connecting = self
            .endpoint
            .connect_with(client_cfg, addr, "vox.invalid")
            .map_err(|_| Error::MalformedBundle("quic connect"))?;
        let connection = connecting.await.map_err(handshake_failed)?;
        let mut conn = finish_connection(connection, &verified, now_secs, via_circuit)?;
        conn.carrier = carrier.filter(|_| via_circuit);
        Ok(conn)
    }

    /// Accept the next inbound connection, admitting **any authenticated Vox
    /// identity** (the open-swarm default — see [`Admission`]). Returns `Ok(None)`
    /// if the endpoint is closed.
    ///
    /// The peer is cryptographically authenticated during the handshake (composite
    /// identity recovered + PoP verified); the recovered identity is recorded and
    /// surfaced via [`VoxConnection::peer_id`] so the application can apply its
    /// join/consent authorization (ADR-005/007). To reject an
    /// authenticated-but-unwanted identity at the transport boundary (pinned /
    /// private deployments), use [`accept_with_admission`](Self::accept_with_admission).
    pub async fn accept(&self, now_secs: u64) -> Result<Option<VoxConnection>> {
        self.accept_with_admission(now_secs, Admission::AcceptAnyAuthenticated)
            .await
    }

    /// Accept the next inbound connection, enforcing `admission` **after** the peer
    /// is cryptographically authenticated. Returns `Ok(None)` if the endpoint is
    /// closed.
    ///
    /// The peer always proves a valid Vox identity first (handshake-level auth); a
    /// peer that authenticates but is **not admitted** by `admission` has its
    /// connection closed with [`WireError::AuthenticatorInvalid`] (`0x05`) and this
    /// returns `Err` — the same coded rejection the dialer uses for an identity
    /// mismatch, so an unwanted peer cannot tell "not authenticated" from "not
    /// admitted". An admitted peer's identity is surfaced via
    /// [`VoxConnection::peer_id`].
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
    /// immediately, doing no handshake.**
    ///
    /// The handshake belongs in [`VoxEndpoint::finish_incoming`], on its own task. Doing
    /// both in one call — which is what [`VoxEndpoint::accept_with_admission`] still does,
    /// for callers that want one connection — means an accept *loop* performs every
    /// handshake inline and therefore serialises on them: one peer that opens a connection
    /// and then stalls its TLS handshake blocks **every** other inbound connection, with no
    /// credential of any kind, because authentication has not happened yet. That is a
    /// pre-authentication denial of service against an always-on node, which is exactly what
    /// an anchor is.
    ///
    /// `None` when the endpoint is closed.
    pub async fn accept_incoming(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }

    /// **Phase two: complete one connection's handshake and admission.**
    ///
    /// Bounded by a 30-second handshake timeout, so a peer that opens a connection and then says
    /// nothing costs one task for that long and not for ever. Spawn this; do not await it in
    /// an accept loop.
    pub async fn finish_incoming(
        &self,
        incoming: quinn::Incoming,
        now_secs: u64,
        mut admission: Admission,
    ) -> Result<VoxConnection> {
        // Read before this end answers anything: see [`VoxConnection::via_circuit`].
        let via_circuit = self.mux.is_circuit(incoming.remote_address());
        let circuit_origin = self.mux.origin_of(incoming.remote_address());
        let carrier = self.mux.carrier_of(incoming.remote_address());
        // A fresh slot for THIS connection's verifier output. We install a
        // per-connection server config so the verifier writes into our slot.
        let verified = VerifiedPeer::new();
        let client_verifier = VoxClientCertVerifier::any_identity(self.supported, verified.clone());
        let s_cfg = server_config(
            Arc::new(client_verifier),
            self.leaf_chain.clone(),
            self.clone_key(),
        )?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(s_cfg)
            .map_err(|_| Error::MalformedBundle("quic server config (accept)"))?;
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server_cfg.transport_config(transport_config(self.mtu_ceiling));
        // Bounded: an unauthenticated peer must not be able to hold a task open for ever by
        // beginning a handshake and never finishing it.
        let connecting = incoming
            .accept_with(Arc::new(server_cfg))
            .map_err(handshake_failed)?;
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| {
                Error::Handshake(format!(
                    "the peer did not finish its handshake within {}s",
                    HANDSHAKE_TIMEOUT.as_secs()
                ))
            })?
            .map_err(handshake_failed)?;
        let mut conn = finish_connection(connection, &verified, now_secs, via_circuit)?;
        conn.circuit_origin = circuit_origin.filter(|_| via_circuit);
        conn.carrier = carrier.filter(|_| via_circuit);

        // Transport-layer admission, after authentication. A non-admitted peer is
        // closed with the coded reason and rejected — indistinguishable on the wire
        // from an authentication failure.
        if !admission.admits(&conn.peer_id()) {
            conn.close(WireError::AuthenticatorInvalid);
            return Err(Error::SignatureInvalid);
        }
        Ok(conn)
    }

    /// Gracefully close the endpoint (all connections).
    pub fn close(&self) {
        // A stopping node's last word to every connection it still has (V210-93): "stopped",
        // the same as `ConnectionManager::close_all` says, never a code that reads as a fault.
        self.endpoint.close(
            close_code(WireError::ShuttingDown),
            WireError::ShuttingDown.to_string().as_bytes(),
        );
    }

    /// Wait until every connection of this endpoint has finished closing, which includes its
    /// CONNECTION_CLOSE having left. Callers bound it.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// Clone the private key (rustls `PrivateKeyDer` is clone-by-method).
    fn clone_key(&self) -> rustls_pki_types::PrivateKeyDer<'static> {
        self.leaf_key.clone_key()
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
    match e {
        C::TransportError(t) if tls(t.code) => Error::SignatureInvalid,
        C::ConnectionClosed(c) if tls(c.error_code) => Error::SignatureInvalid,
        C::ConnectionClosed(c) if c.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED => {
            Error::Handshake("the peer is busy: it refused the connection for now".to_owned())
        }
        C::TimedOut => Error::Handshake("the peer did not answer".to_owned()),
        C::LocallyClosed => Error::Handshake("this node's endpoint is closing".to_owned()),
        other => Error::Handshake(other.to_string()),
    }
}

/// Confirm the negotiated group, record the session, and build the connection.
fn finish_connection(
    connection: Connection,
    verified: &VerifiedPeer,
    now_secs: u64,
    via_circuit: bool,
) -> Result<VoxConnection> {
    // The verifier authenticated the peer during the handshake; its fingerprint is
    // in the slot. Absence means the handshake completed without our verifier
    // running, which must not happen — treat as an auth failure.
    let peer_id = verified.fingerprint().ok_or(Error::SignatureInvalid)?;

    // Confirm the negotiated named group is the hybrid PQ group. quinn exposes the
    // negotiated group via the rustls handshake data attached to the connection.
    confirm_vox_alpn(&connection)?;

    let session = SessionEstablishment::new(peer_id, now_secs);
    // The peer's leaf certificate is generated per endpoint — per process — and bound to the
    // identity by a signature (`identity_cert`), so its digest says which *process* of the
    // identity this connection is to (V210-57).
    let peer_process = connection
        .peer_identity()
        .and_then(|any| {
            any.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|chain| chain.first().map(|leaf| crate::hash::sha256(leaf.as_ref())))
        .ok_or(Error::SignatureInvalid)?;
    Ok(VoxConnection {
        serial: NEXT_SERIAL.fetch_add(1, Ordering::Relaxed),
        connection,
        peer_id,
        peer_process,
        session,
        via_circuit,
        circuit_origin: None,
        datagram_tx: Mutex::new(DatagramSender::new()),
        datagram_rx: Mutex::new(ReplayWindow::default()),
        datagrams_dropped: AtomicU64::new(0),
        closed_here: std::sync::OnceLock::new(),
        peer_stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        carrier: None,
        tunnels: Arc::new(Mutex::new(0)),
    })
}

/// Lock a piece of per-connection datagram state. The critical sections are a
/// single counter/bitmap update with no `.await` inside, so the state is always
/// consistent between operations; a poisoned lock (another thread panicked while
/// holding it — impossible in this `deny(clippy::panic)` crate outside tests) is
/// therefore safe to recover rather than propagate.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Confirm this handshake ran under the Vox TLS configuration, by its ALPN.
///
/// **It does not observe the negotiated key-exchange group, and it is named for what
/// it checks because it used to be named for what it does not.** It was
/// `confirm_hybrid_group`, documented as confirming X25519MLKEM768 and as surfacing
/// "a clear error if a future config regression ever widened the offered groups" —
/// which it would not have done. Widening `kx_groups` leaves this function passing,
/// since the ALPN is unchanged. The defence in depth the old name promised was not
/// there, and a reader auditing the connection path had every reason to believe it
/// was.
///
/// What actually guarantees the group is upstream of here and is sound: the provider
/// offers exactly one `kx_group`, so there is no downgrade target to negotiate to;
/// `provider::assert_pq_only` enforces that at every config
/// boundary; and TLS 1.3 binds the negotiated parameters into the Finished MAC, so a
/// mismatch breaks the handshake rather than passing quietly. The group cannot be
/// checked *here* because quinn 0.11 gates rustls's
/// `negotiated_key_exchange_group` behind a test-only cfg, so the value rustls holds
/// is not reachable from the connection.
///
/// The ALPN check is still worth keeping: it confirms a Vox-configured handshake
/// completed, and a non-Vox config would not carry this protocol.
fn confirm_vox_alpn(connection: &Connection) -> Result<()> {
    let Some(hd) = connection.handshake_data() else {
        return Err(Error::SignatureInvalid);
    };
    let Some(hd) = hd.downcast_ref::<quinn::crypto::rustls::HandshakeData>() else {
        return Err(Error::SignatureInvalid);
    };
    match &hd.protocol {
        Some(p) if p.as_slice() == crate::transport::provider::VOX_ALPN => Ok(()),
        _ => Err(Error::SignatureInvalid),
    }
}

/// An authenticated QUIC connection to one Vox peer.
///
/// Owns the per-connection datagram anti-replay state (ADR-011): an outbound
/// [`DatagramSender`] sequence counter and an inbound [`ReplayWindow`] of
/// [`crate::transport::datagram::DEFAULT_WINDOW`] packets. Both are private, so
/// every datagram sent through [`VoxConnection::send_datagram`] is sequenced and
/// every datagram returned by [`VoxConnection::recv_datagram`] has passed the
/// window.
pub struct VoxConnection {
    /// This connection's name in this process, never given to another (see [`Self::serial`]).
    serial: u64,
    connection: Connection,
    peer_id: Digest32,
    /// Which process of `peer_id` this connection is to: the digest of its per-process leaf
    /// certificate (see [`Self::peer_process`]).
    peer_process: Digest32,
    session: SessionEstablishment,
    /// Whether this connection was set up over a relay circuit (see [`Self::via_circuit`]).
    via_circuit: bool,
    /// Where an inbound circuit's far end comes from (see [`Self::circuit_origin`]).
    circuit_origin: Option<crate::transport::mux::CircuitOrigin>,
    /// Outbound datagram sequence numbers (monotonic, saturating).
    datagram_tx: Mutex<DatagramSender>,
    /// Inbound sliding anti-replay window.
    datagram_rx: Mutex<ReplayWindow>,
    /// Inbound datagrams dropped as replay / out-of-window / unframed. Exposed
    /// for observability ([`VoxConnection::datagrams_dropped`]); a rising count
    /// on a live connection is a replay signal worth surfacing.
    datagrams_dropped: AtomicU64,
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
}

/// A tunnel's share of its connection's receive window, held for as long as the tunnel runs
/// (see [`CONNECTION_WINDOW`]). Dropping it gives the share back, and takes the tunnel off
/// [`live_tunnels`].
#[must_use = "the credit lasts only as long as the guard is held"]
pub struct TunnelCredit {
    tunnels: Arc<Mutex<u32>>,
    connection: Connection,
    id: u64,
    moved: Arc<AtomicU64>,
}

impl TunnelCredit {
    /// Where the tunnel's splice marks the time it last moved a byte, in Unix seconds (see
    /// [`LiveTunnel::last_moved`]).
    #[must_use]
    pub fn moved(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.moved)
    }
}

impl Drop for TunnelCredit {
    fn drop(&mut self) {
        // One lock at a time, as `carry_tunnel` takes them.
        lock(&LIVE).remove(&self.id);
        let mut n = lock(&self.tunnels);
        *n = n.saturating_sub(1);
        set_tunnel_window(&self.connection, *n);
    }
}

/// One live tunnel, as `vox status` lists it (V210-81): so a person can see which tunnels hold a
/// member's connection, and which of them is stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTunnel {
    /// The member at the other end.
    pub peer: Digest32,
    /// The service it reaches: a port, or a `vox room send` offer's tag.
    pub service: String,
    /// Whether this node opened it (to reach the member's service), rather than serving it.
    pub outbound: bool,
    /// When it was opened, in Unix seconds.
    pub opened: u64,
    /// When it last moved a byte either way, in Unix seconds; `opened` until it has.
    pub last_moved: u64,
}

/// A live tunnel's entry in [`LIVE`].
struct Live {
    peer: Digest32,
    service: String,
    outbound: bool,
    opened: u64,
    moved: Arc<AtomicU64>,
}

/// Every tunnel this process carries now, by a number of its own. A process runs one node, so
/// this is the node's list.
static LIVE: Mutex<std::collections::BTreeMap<u64, Live>> =
    Mutex::new(std::collections::BTreeMap::new());

/// The next key in [`LIVE`].
static NEXT_TUNNEL: AtomicU64 = AtomicU64::new(0);

/// The time now in Unix seconds, as [`LiveTunnel`] states times.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Every tunnel this node carries now, oldest first.
#[must_use]
pub fn live_tunnels() -> Vec<LiveTunnel> {
    lock(&LIVE)
        .values()
        .map(|t| LiveTunnel {
            peer: t.peer,
            service: t.service.clone(),
            outbound: t.outbound,
            opened: t.opened,
            last_moved: t.moved.load(Ordering::Relaxed).max(t.opened),
        })
        .collect()
}

/// What a person is told when a tunnel is refused at the cap: how many are open to this member,
/// to which services, and how to free one (decider, 2026-10-01).
fn limit_said(live: &std::collections::BTreeMap<u64, Live>, peer: &Digest32) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for t in live.values().filter(|t| t.peer == *peer) {
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
         to free one: close the program using it, or restart the `vox up` or `vox forward` \
         carrying it; on the host, `vox service remove` the service, or `vox trust remove` the \
         member\n       `vox status` lists every tunnel, and when each last moved",
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
fn at_tunnel_cap(live: &std::collections::BTreeMap<u64, Live>, peer: &Digest32) -> bool {
    live.values().filter(|t| t.peer == *peer).count() >= TUNNELS_PER_PEER as usize
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
        let opened = unix_now();
        let moved = Arc::new(AtomicU64::new(opened));
        {
            // Counted and taken under one lock, so two tunnels asked for at once cannot both
            // take the last place.
            let mut live = lock(&LIVE);
            if at_tunnel_cap(&live, &self.peer_id) {
                return Err(Error::TunnelLimit(limit_said(&live, &self.peer_id)));
            }
            live.insert(
                id,
                Live {
                    peer: self.peer_id,
                    service: service.to_owned(),
                    outbound,
                    opened,
                    moved: Arc::clone(&moved),
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
            moved,
        })
    }

    /// [`Error::TunnelLimit`] if this connection's member already has as many tunnels with this
    /// node as it may ([`TUNNELS_PER_PEER`]), so another would be refused.
    ///
    /// # Errors
    /// [`Error::TunnelLimit`], saying what it holds and how to free one.
    pub fn room_for_a_tunnel(&self) -> Result<()> {
        let live = lock(&LIVE);
        if at_tunnel_cap(&live, &self.peer_id) {
            return Err(Error::TunnelLimit(limit_said(&live, &self.peer_id)));
        }
        Ok(())
    }

    /// [`Error::TunnelLimit`] as this node words it, for a refusal the **host** made at the cap
    /// (`TunnelStatus::Full`): the member's live tunnels here are the same ones it counted.
    #[must_use]
    pub fn tunnel_limit(&self) -> Error {
        Error::TunnelLimit(limit_said(&lock(&LIVE), &self.peer_id))
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

    /// The negotiated TLS group code point recorded for this session
    /// (X25519MLKEM768 = `0x11EC`).
    #[must_use]
    pub fn negotiated_group(&self) -> u16 {
        debug_assert_eq!(self.session.negotiated_group, X25519MLKEM768_CODE_POINT);
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

    /// Send one RFC 9221 unreliable datagram carrying `payload`. The connection
    /// prepends the next 64-bit sequence number (ADR-011 datagram framing); the
    /// caller never sees or chooses sequences. Fails if the framed datagram
    /// exceeds the peer's advertised limit ([`VoxConnection::max_datagram_payload`]).
    pub fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        let frame = lock(&self.datagram_tx).frame(payload);
        self.connection
            .send_datagram(bytes::Bytes::from(frame))
            .map_err(|_| Error::MalformedBundle("quic send_datagram"))
    }

    /// Receive the next inbound datagram's **payload** that passes the
    /// anti-replay window. Datagrams that are unframed (shorter than the sequence
    /// prefix), duplicates, or below the window are dropped here — counted in
    /// [`VoxConnection::datagrams_dropped`] — and never returned, exactly as
    /// ADR-011 §"Datagram anti-replay" specifies. Only a transport-level read
    /// failure (connection closed) is an error.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>> {
        loop {
            let raw = self
                .connection
                .read_datagram()
                .await
                .map_err(|_| Error::MalformedBundle("quic read_datagram"))?;
            let Some((seq, payload)) = parse_datagram(&raw) else {
                self.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if !lock(&self.datagram_rx).accept(seq) {
                self.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            return Ok(payload.to_vec());
        }
    }

    /// Number of inbound datagrams this connection has dropped as replayed,
    /// duplicate, out-of-window, or unframed.
    #[must_use]
    pub fn datagrams_dropped(&self) -> u64 {
        self.datagrams_dropped.load(Ordering::Relaxed)
    }

    /// The maximum datagram **payload** the peer will accept right now (its
    /// advertised datagram size minus the sequence prefix), if datagrams are
    /// enabled on the connection.
    #[must_use]
    pub fn max_datagram_payload(&self) -> Option<usize> {
        self.connection
            .max_datagram_size()
            .map(|n| n.saturating_sub(SEQ_PREFIX_LEN))
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
