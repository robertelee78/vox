//! The **circuit stream** (`StreamKind::Circuit`): the relay of last resort
//! (ADR-012 rung 4).
//!
//! When neither a direct dial nor a hole punch can reach a peer — both behind
//! symmetric NAT, no IPv6 — a peer already connected to both carries the traffic.
//! What it carries is the two peers' **QUIC packets**: each end attaches a
//! [circuit](crate::transport::mux) to its endpoint, and the dial, the handshake and
//! the identity pinning are exactly those of a direct connection. The relay forwards
//! `DATAGRAM` frames it cannot read. That is what ADR-012's "ciphertext-only" relay
//! means here, and it holds by construction: there is no plaintext for the relay to
//! see, because the connection is not with the relay.
//!
//! ## Verbs
//!
//! | frame | direction | meaning |
//! |---|---|---|
//! | `OPEN <peer>` | initiator → relay | "carry a circuit to this peer" |
//! | `INCOMING <peer>` | relay → target | "a circuit from that peer" |
//! | `OPENED` | either → its counterpart | the circuit is up; `DATAGRAM` frames follow |
//! | `REFUSED <reason>` | either → its counterpart | it is not, and why |
//! | `DATAGRAM <bytes>` | end to end | one QUIC packet, opaque to the relay |
//!
//! ## Who may ask
//!
//! Both ends of a circuit must be peers the relay knows — a member, an anchor, or a
//! pending joiner, the same rule as hole-punch signaling and for the same reason
//! (`node::coordstream`). Carrying bytes costs more than carrying signaling, so a
//! relay also bounds it: at most [`MAX_RELAYED_CIRCUITS`] at once, at most
//! [`MAX_CIRCUITS_PER_ASKER`] for any one peer, and a circuit idle for
//! [`CIRCUIT_IDLE_TIMEOUT`] is closed. A relay is a last resort, not a service.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::coordstream::{accepts_relayed, relays_for};
use crate::node::net::PeerClass;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::mux::CircuitPort;
use crate::transport::quic::{VoxConnection, VoxEndpoint};
use crate::transport::streams::{open_typed, StreamKind};

/// The largest circuit frame. A QUIC packet is at most the path MTU (well under
/// 2 KiB); this leaves room for a relay stream's own MTU discovery without letting
/// the verb carry bulk.
pub const MAX_CIRCUIT_FRAME: usize = 16 * 1024;

/// How many circuits a relay will carry at once, in total.
pub const MAX_RELAYED_CIRCUITS: usize = 64;

/// How many circuits a relay will carry for any one asker at once.
pub const MAX_CIRCUITS_PER_ASKER: usize = 4;

/// A circuit with no traffic in either direction for this long is closed. QUIC keeps
/// a live connection ticking well inside it.
pub const CIRCUIT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long to wait for the opening exchange to be answered.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

const OP_OPEN: u64 = 0;
const OP_INCOMING: u64 = 1;
const OP_OPENED: u64 = 2;
const OP_REFUSED: u64 = 3;
const OP_DATAGRAM: u64 = 4;

/// Why a relay or a target would not take part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitRefusal {
    /// The relay has no live connection to the named peer.
    NotConnected,
    /// The asker, or the peer it named, is not one this node relays for.
    NotAuthorized,
    /// The relay is carrying as many circuits as it will.
    Capacity,
}

impl CircuitRefusal {
    fn code(self) -> u64 {
        match self {
            CircuitRefusal::NotConnected => 0,
            CircuitRefusal::NotAuthorized => 1,
            CircuitRefusal::Capacity => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self> {
        match code {
            0 => Ok(CircuitRefusal::NotConnected),
            1 => Ok(CircuitRefusal::NotAuthorized),
            2 => Ok(CircuitRefusal::Capacity),
            _ => Err(Error::Unreachable("circuit: unknown refusal reason")),
        }
    }
}

/// One frame on a circuit stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitFrame {
    /// "Carry a circuit to this peer."
    Open {
        /// The peer to reach.
        peer: Digest32,
    },
    /// "A circuit from that peer."
    Incoming {
        /// The peer that asked for the circuit.
        peer: Digest32,
    },
    /// The circuit is up.
    Opened,
    /// The circuit is refused.
    Refused {
        /// Why.
        reason: CircuitRefusal,
    },
    /// One QUIC packet.
    Datagram {
        /// The packet, opaque to the relay.
        payload: Vec<u8>,
    },
}

impl CircuitFrame {
    /// Canonical CBOR: a definite-length array led by the op discriminant.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            CircuitFrame::Open { peer } => {
                e.array(2).uint(OP_OPEN).bytes(peer);
            }
            CircuitFrame::Incoming { peer } => {
                e.array(2).uint(OP_INCOMING).bytes(peer);
            }
            CircuitFrame::Opened => {
                e.array(1).uint(OP_OPENED);
            }
            CircuitFrame::Refused { reason } => {
                e.array(2).uint(OP_REFUSED).uint(reason.code());
            }
            CircuitFrame::Datagram { payload } => {
                e.array(2).uint(OP_DATAGRAM).bytes(payload);
            }
        }
        e.finish()
    }

    /// Strictly decode a frame: unknown op, wrong arity, a fingerprint that is not 32
    /// bytes, or trailing bytes are all refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        let op = d.uint()?;
        let frame = match (op, arity) {
            (OP_OPEN, 2) => CircuitFrame::Open {
                peer: fingerprint(&mut d)?,
            },
            (OP_INCOMING, 2) => CircuitFrame::Incoming {
                peer: fingerprint(&mut d)?,
            },
            (OP_OPENED, 1) => CircuitFrame::Opened,
            (OP_REFUSED, 2) => CircuitFrame::Refused {
                reason: CircuitRefusal::from_code(d.uint()?)?,
            },
            (OP_DATAGRAM, 2) => CircuitFrame::Datagram {
                payload: d.bytes()?.to_vec(),
            },
            (OP_OPEN..=OP_DATAGRAM, _) => return Err(Error::Unreachable("circuit: frame arity")),
            _ => return Err(Error::Unreachable("circuit: unknown op")),
        };
        d.finish()
            .map_err(|_| Error::Unreachable("circuit: trailing bytes"))?;
        Ok(frame)
    }
}

fn fingerprint(d: &mut Decoder<'_>) -> Result<Digest32> {
    let raw = d.bytes()?;
    Digest32::try_from(raw).map_err(|_| Error::Unreachable("circuit: fingerprint length"))
}

async fn send_frame(send: &mut SendStream, frame: &CircuitFrame) -> Result<()> {
    write_frame(send, &frame.to_bytes()).await
}

/// Read the answer to an opening frame, within [`OPEN_TIMEOUT`].
async fn opening_answer(recv: &mut RecvStream) -> Result<CircuitFrame> {
    let frame = tokio::time::timeout(OPEN_TIMEOUT, read_frame(recv, MAX_CIRCUIT_FRAME))
        .await
        .map_err(|_| Error::Unreachable("circuit: peer went quiet"))??
        .ok_or(Error::Unreachable("circuit: stream closed"))?;
    CircuitFrame::from_bytes(&frame)
}

async fn refuse(send: &mut SendStream, reason: CircuitRefusal) {
    let _ = send_frame(send, &CircuitFrame::Refused { reason }).await;
    let _ = send.finish();
}

/// The relay's bookkeeping of what it is carrying, so the caps can be enforced. A
/// [`CircuitSlot`] holds one place in it and gives it back on drop.
#[derive(Debug, Default)]
pub struct CircuitLedger {
    inner: Mutex<LedgerInner>,
}

#[derive(Debug, Default)]
struct LedgerInner {
    total: usize,
    per_asker: BTreeMap<Digest32, usize>,
}

/// One relayed circuit's place in the ledger.
#[derive(Debug)]
pub struct CircuitSlot {
    asker: Digest32,
    ledger: Arc<CircuitLedger>,
}

impl CircuitLedger {
    /// Take a place for `asker`, or `None` when either cap is reached.
    #[must_use]
    pub fn take(self: &Arc<Self>, asker: Digest32) -> Option<CircuitSlot> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = g.per_asker.get(&asker).copied().unwrap_or(0);
        if g.total >= MAX_RELAYED_CIRCUITS || mine >= MAX_CIRCUITS_PER_ASKER {
            return None;
        }
        g.total += 1;
        g.per_asker.insert(asker, mine + 1);
        Some(CircuitSlot {
            asker,
            ledger: Arc::clone(self),
        })
    }

    /// How many circuits are being carried right now.
    #[must_use]
    pub fn carrying(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }
}

impl Drop for CircuitSlot {
    fn drop(&mut self) {
        let mut g = self
            .ledger
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        g.total = g.total.saturating_sub(1);
        match g.per_asker.get_mut(&self.asker) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                g.per_asker.remove(&self.asker);
            }
        }
    }
}

/// Serve one inbound circuit stream: the opening exchange runs here, and whatever it
/// establishes — a relayed circuit, or a circuit terminating at this node — then runs
/// on its own task, so the stream loop that accepted it is free at once.
///
/// `connected` resolves a fingerprint to a live connection (the relay's own peer
/// table); `endpoint` is where a circuit terminating here is attached.
pub async fn serve_circuit<F>(
    peer: Digest32,
    classify: &(dyn Fn(&Digest32) -> PeerClass + Sync),
    mut send: SendStream,
    mut recv: RecvStream,
    connected: F,
    ledger: &Arc<CircuitLedger>,
    endpoint: &Arc<VoxEndpoint>,
) -> Result<()>
where
    F: FnOnce(&Digest32) -> Option<Arc<VoxConnection>>,
{
    match opening_answer(&mut recv).await? {
        CircuitFrame::Open { peer: target } => {
            if !relays_for(classify(&peer)) || !relays_for(classify(&target)) {
                refuse(&mut send, CircuitRefusal::NotAuthorized).await;
                return Err(Error::StreamRefused(
                    "circuit: peer may not ask for a relay",
                ));
            }
            let Some(slot) = ledger.take(peer) else {
                refuse(&mut send, CircuitRefusal::Capacity).await;
                return Err(Error::Unreachable("circuit: relay at capacity"));
            };
            let Some(target_conn) = connected(&target) else {
                refuse(&mut send, CircuitRefusal::NotConnected).await;
                return Err(Error::Unreachable("circuit: target not connected"));
            };
            let (mut target_send, mut target_recv) =
                open_typed(&target_conn, StreamKind::Circuit).await?;
            send_frame(&mut target_send, &CircuitFrame::Incoming { peer }).await?;
            match opening_answer(&mut target_recv).await? {
                CircuitFrame::Opened => {}
                CircuitFrame::Refused { reason } => {
                    refuse(&mut send, reason).await;
                    return Err(Error::Unreachable("circuit: target refused"));
                }
                _ => return Err(Error::Unreachable("circuit: target did not answer")),
            }
            send_frame(&mut send, &CircuitFrame::Opened).await?;
            tokio::spawn(relay(slot, send, recv, target_send, target_recv));
            Ok(())
        }
        CircuitFrame::Incoming { peer: origin } => {
            // The same rule as a relayed punch session, anchor's vouching included:
            // a circuit is how an anchor introduces a peer nothing else can reach.
            if !accepts_relayed(classify(&peer), classify(&origin)) {
                refuse(&mut send, CircuitRefusal::NotAuthorized).await;
                return Err(Error::StreamRefused("circuit: peer may not relay to us"));
            }
            send_frame(&mut send, &CircuitFrame::Opened).await?;
            let port = endpoint.attach_circuit(&origin)?;
            tokio::spawn(terminate(port, send, recv));
            Ok(())
        }
        _ => Err(Error::Unreachable("circuit: unexpected opening frame")),
    }
}

/// Ask `relay` for a circuit to `peer` and, once it is up, dial `peer` through it.
/// The connection that comes back is pinned to `peer` and authenticated by it, the
/// same as a direct one.
pub async fn connect_through(
    relay: &VoxConnection,
    peer: Digest32,
    endpoint: &Arc<VoxEndpoint>,
    now_secs: u64,
) -> Result<VoxConnection> {
    let (mut send, mut recv) = open_typed(relay, StreamKind::Circuit).await?;
    send_frame(&mut send, &CircuitFrame::Open { peer }).await?;
    match opening_answer(&mut recv).await? {
        CircuitFrame::Opened => {}
        CircuitFrame::Refused { reason } => {
            return Err(match reason {
                CircuitRefusal::NotConnected => {
                    Error::Unreachable("circuit: relay cannot reach the peer")
                }
                CircuitRefusal::NotAuthorized => {
                    Error::Unreachable("circuit: relay will not carry for us")
                }
                CircuitRefusal::Capacity => Error::Unreachable("circuit: relay is at capacity"),
            })
        }
        _ => return Err(Error::Unreachable("circuit: relay did not open")),
    }
    let port = endpoint.attach_circuit(&peer)?;
    // Read before the port moves into the driver: the address is allocated per circuit,
    // so the port is the only thing that knows it.
    let target = port.addr();
    // The driver lives exactly as long as the attempt does, unless the attempt
    // succeeds: a failed dial — or an attempt abandoned because another rung won the
    // race (M15.1b) — aborts it on drop, which drops the port, which detaches the
    // circuit and closes the stream, which tells the relay and the far side to let go.
    let driver = DriverGuard::new(tokio::spawn(terminate(port, send, recv)));
    let conn =
        crate::nat::reachability::connect_direct(Arc::clone(endpoint), &[target], peer, now_secs)
            .await?;
    driver.keep();
    Ok(conn)
}

/// A circuit driver that is aborted when this is dropped, unless [`DriverGuard::keep`]
/// let it live on.
struct DriverGuard(Option<tokio::task::JoinHandle<()>>);

impl DriverGuard {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }

    /// The circuit is in use: the driver runs until the stream ends.
    fn keep(mut self) {
        self.0.take();
    }
}

impl Drop for DriverGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Drive a circuit that terminates at this endpoint: what the endpoint sends to the
/// circuit's address goes out as `DATAGRAM` frames, and `DATAGRAM` frames coming in
/// are handed to the endpoint as arrivals from that address. Ends when the stream
/// does, or after [`CIRCUIT_IDLE_TIMEOUT`] without traffic; the port — and with it
/// the circuit — is dropped then.
async fn terminate(mut port: CircuitPort, mut send: SendStream, mut recv: RecvStream) {
    let Some(mut outbound) = port.take_outbound() else {
        return;
    };
    let writer = tokio::spawn(async move {
        while let Some(datagram) = outbound.recv().await {
            let frame = CircuitFrame::Datagram { payload: datagram };
            if send_frame(&mut send, &frame).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });
    let inlet = port.inlet();
    loop {
        let next = tokio::time::timeout(
            CIRCUIT_IDLE_TIMEOUT,
            read_frame(&mut recv, MAX_CIRCUIT_FRAME),
        )
        .await;
        match next {
            Ok(Ok(Some(frame))) => match CircuitFrame::from_bytes(&frame) {
                Ok(CircuitFrame::Datagram { payload }) => inlet.deliver(payload),
                // Anything else on an open circuit ends it: the protocol has no other
                // frame to say here.
                _ => break,
            },
            _ => break,
        }
    }
    writer.abort();
    drop(port);
}

/// Carry `DATAGRAM` frames between the asker's stream and the target's, both ways,
/// until either side is done or the circuit idles out. The slot in the ledger is
/// given back when this returns.
async fn relay(
    slot: CircuitSlot,
    asker_send: SendStream,
    asker_recv: RecvStream,
    target_send: SendStream,
    target_recv: RecvStream,
) {
    // One task per direction: `read_frame` is not cancel-safe, so a `select!` over
    // both could abandon a half-read frame and desynchronize the stream.
    let mut up = tokio::spawn(copy_datagrams(asker_recv, target_send));
    let mut down = tokio::spawn(copy_datagrams(target_recv, asker_send));
    tokio::select! {
        _ = &mut up => {}
        _ = &mut down => {}
    }
    up.abort();
    down.abort();
    drop(slot);
}

/// Forward `DATAGRAM` frames one way, verbatim, until the stream ends, a frame that
/// is not a datagram arrives, or nothing arrives for [`CIRCUIT_IDLE_TIMEOUT`]. The
/// relay never looks inside a datagram.
async fn copy_datagrams(mut recv: RecvStream, mut send: SendStream) {
    loop {
        let next = tokio::time::timeout(
            CIRCUIT_IDLE_TIMEOUT,
            read_frame(&mut recv, MAX_CIRCUIT_FRAME),
        )
        .await;
        let Ok(Ok(Some(frame))) = next else {
            break;
        };
        if !matches!(
            CircuitFrame::from_bytes(&frame),
            Ok(CircuitFrame::Datagram { .. })
        ) {
            break;
        }
        if write_frame(&mut send, &frame).await.is_err() {
            break;
        }
    }
    let _ = send.finish();
}
