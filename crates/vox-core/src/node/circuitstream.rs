//! The **circuit stream** (`StreamKind::Circuit`): the relay of last resort
//! (ADR-012 rung 4).
//!
//! When neither a direct dial nor a hole punch can reach a peer — both behind
//! symmetric NAT, no IPv6 — a peer already connected to both carries the traffic.
//! What it carries is the two peers' **QUIC packets**: each end attaches a
//! [circuit](crate::transport::mux) to its endpoint, and the dial, the handshake and
//! the identity pinning are exactly those of a direct connection. The relay forwards
//! datagrams it cannot read. That is what ADR-012's "ciphertext-only" relay means
//! here, and it holds by construction: there is no plaintext for the relay to see,
//! because the connection is not with the relay.
//!
//! ## The packets ride datagrams, not the stream (ADR-022 decision 5)
//! The circuit stream carries only the opening exchange below. Once a circuit is up,
//! each leg's stream is bound to a [datagram flow](crate::transport::router) on that
//! leg's connection — the initiator–relay one and the relay–target one — and the QUIC
//! packets travel as datagrams on those flows. The relay moves each datagram from one
//! flow to the other without reading it, and fragments without reassembling them.
//!
//! Until ADR-022 the packets rode the stream itself as `DATAGRAM` frames. A stream is
//! reliable and ordered, so one lost outer packet held back every inner packet queued
//! behind it until it was retransmitted: the inner connection, which recovers from loss
//! on its own, saw a stall instead of a loss. Carried as datagrams, a lost outer packet
//! loses one inner packet and nothing waits for it.
//!
//! The stream still matters: each flow lives exactly as long as its leg's stream, so
//! either end, or the relay, ending its stream tears the whole circuit down.
//!
//! ## Verbs
//!
//! | frame | direction | meaning |
//! |---|---|---|
//! | `OPEN <peer>` | initiator → relay | "carry a circuit to this peer" |
//! | `INCOMING <peer>` | relay → target | "a circuit from that peer" |
//! | `OPENED` | either → its counterpart | the circuit is up; the stream is a datagram flow from here |
//! | `REFUSED <reason>` | either → its counterpart | it is not, and why |
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
use crate::transport::router::DatagramFlow;
use crate::transport::streams::{open_typed, StreamKind};

/// The largest circuit frame. Only the opening exchange rides the stream — the largest
/// frame is a verb and a 32-byte fingerprint — so anything bigger is not a circuit
/// frame.
pub const MAX_CIRCUIT_FRAME: usize = 256;

/// The largest datagram either end of a circuit sends. Larger inner packets go as
/// fragments.
///
/// Each end knows only its own leg to the relay, and the relay forwards each datagram as
/// it is — it never re-splits one, since that would mean reassembling it. So a datagram
/// sized for a leg that path-MTU discovery has grown to 1452 bytes would be dropped at
/// the relay if the other leg is still at QUIC's 1200-byte floor, and the inner handshake,
/// whose Initial packets are 1200 bytes, would never complete. Every QUIC connection
/// carries a datagram of a little over a kilobyte (1200 bytes less its packet overhead);
/// this stays under that with room for the relay's flow ID to be a few bytes longer than
/// the end's.
pub const CIRCUIT_DATAGRAM_MAX: usize = 1100;

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
            (OP_OPEN..=OP_REFUSED, _) => return Err(Error::Unreachable("circuit: frame arity")),
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
/// `carrier` is the connection the stream arrived on — the circuit's datagram flow is bound
/// to it — and whatever the circuit becomes
/// holds it — and the target's connection too, when this node relays — for as long as the
/// circuit runs: that is what marks those connections as carrying, so a retired one is
/// not closed under a live circuit. `connected` resolves a fingerprint to a live
/// connection (the relay's own peer table); `endpoint` is where a circuit terminating
/// here is attached.
pub async fn serve_circuit<F>(
    carrier: &Arc<VoxConnection>,
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
    let peer = carrier.peer_id();
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
            // Bound before the asker hears `OPENED`, so its first packet has a flow to
            // land on: nothing is sent on a circuit before that answer.
            let target_flow = target_conn.bind_forwarding_flow(target_send, target_recv)?;
            send_frame(&mut send, &CircuitFrame::Opened).await?;
            let asker_flow = carrier.bind_forwarding_flow(send, recv)?;
            let carriers = [Arc::clone(carrier), target_conn];
            tokio::spawn(relay(slot, carriers, asker_flow, target_flow));
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
            let mut flow = carrier.bind_flow(send, recv)?;
            flow.cap_datagrams(CIRCUIT_DATAGRAM_MAX);
            let port = endpoint.attach_circuit_via(&origin, &peer)?;
            tokio::spawn(terminate(port, Arc::clone(carrier), flow));
            Ok(())
        }
        _ => Err(Error::Unreachable("circuit: unexpected opening frame")),
    }
}

/// Ask `relay` for a circuit to `peer` and, once it is up, dial `peer` through it.
/// The connection that comes back is pinned to `peer` and authenticated by it, the
/// same as a direct one.
pub async fn connect_through(
    relay: &Arc<VoxConnection>,
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
    let mut flow = relay.bind_flow(send, recv)?;
    flow.cap_datagrams(CIRCUIT_DATAGRAM_MAX);
    let port = endpoint.attach_circuit_via(&peer, &relay.peer_id())?;
    // Read before the port moves into the driver: the address is allocated per circuit,
    // so the port is the only thing that knows it.
    let target = port.addr();
    // The driver lives exactly as long as the attempt does, unless the attempt
    // succeeds: a failed dial — or an attempt abandoned because another rung won the
    // race (M15.1b) — aborts it on drop, which drops the port, which detaches the
    // circuit and closes the stream, which tells the relay and the far side to let go.
    let driver = DriverGuard::new(tokio::spawn(terminate(port, Arc::clone(relay), flow)));
    let conn =
        crate::nat::reachability::connect_direct(Arc::clone(endpoint), &[target], peer, now_secs)
            .await?;
    // **The circuit ends when the connection it carries does.** Nothing else ends it: the
    // relay forwards the inner connection's packets without reading them, so it cannot see
    // a CONNECTION_CLOSE go by, and neither end's driver looks. A connection that lost a
    // race to a direct one, or was displaced by one and retired, was closed at both ends
    // while its circuit sat on the relay for `CIRCUIT_IDLE_TIMEOUT` — five minutes of a
    // relay slot, and of the relay's connections to both ends held as carrying.
    //
    // A short linger first, so the close itself crosses the circuit before it goes.
    if let Some(abort) = driver.keep() {
        let inner = conn.quinn().clone();
        tokio::spawn(async move {
            inner.closed().await;
            tokio::time::sleep(CIRCUIT_CLOSE_LINGER).await;
            abort.abort();
        });
    }
    Ok(conn)
}

/// How long a circuit outlives the connection it carried, so that connection's
/// CONNECTION_CLOSE reaches the far side through it.
const CIRCUIT_CLOSE_LINGER: Duration = Duration::from_secs(1);

/// A circuit driver that is aborted when this is dropped, unless [`DriverGuard::keep`]
/// let it live on.
struct DriverGuard(Option<tokio::task::JoinHandle<()>>);

impl DriverGuard {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }

    /// The circuit is in use: the driver runs until the stream ends, or until the
    /// returned handle aborts it.
    fn keep(mut self) -> Option<tokio::task::AbortHandle> {
        self.0.take().map(|h| h.abort_handle())
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
/// circuit's address goes out as datagrams on the circuit's flow, and datagrams
/// arriving on the flow are handed to the endpoint as arrivals from that address.
/// Ends when the flow does — its stream ended, here or anywhere along the circuit — or
/// after [`CIRCUIT_IDLE_TIMEOUT`] without traffic; the port, and with it the circuit,
/// is dropped then. `_carrier`, the connection the circuit rides, is held until then.
async fn terminate(mut port: CircuitPort, _carrier: Arc<VoxConnection>, mut flow: DatagramFlow) {
    let Some(mut outbound) = port.take_outbound() else {
        return;
    };
    let inlet = port.inlet();
    let idle = tokio::time::sleep(CIRCUIT_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        // Both receivers are channels, so a branch that loses the race loses nothing.
        tokio::select! {
            out = outbound.recv() => {
                let Some(packet) = out else { break };
                if flow.send(&packet).is_err() {
                    break;
                }
            }
            inbound = flow.recv() => {
                let Some(packet) = inbound else { break };
                inlet.deliver(packet);
            }
            () = &mut idle => break,
        }
        idle.as_mut()
            .reset(tokio::time::Instant::now() + CIRCUIT_IDLE_TIMEOUT);
    }
    drop(flow);
    drop(port);
}

/// Move datagrams between the asker's flow and the target's, both ways, until either
/// flow ends or the circuit idles out. Each datagram changes flows and nothing else:
/// the relay never reads it, and never reassembles a fragment. Returning drops both
/// flows, which ends both streams and so the circuit at both ends; the slot in the
/// ledger is given back then too, and the two connections the circuit rides are held
/// until then.
async fn relay(
    slot: CircuitSlot,
    _carriers: [Arc<VoxConnection>; 2],
    mut asker: DatagramFlow,
    mut target: DatagramFlow,
) {
    let idle = tokio::time::sleep(CIRCUIT_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            up = asker.recv() => {
                let Some(datagram) = up else { break };
                if target.forward(&datagram).is_err() {
                    break;
                }
            }
            down = target.recv() => {
                let Some(datagram) = down else { break };
                if asker.forward(&datagram).is_err() {
                    break;
                }
            }
            () = &mut idle => break,
        }
        idle.as_mut()
            .reset(tokio::time::Instant::now() + CIRCUIT_IDLE_TIMEOUT);
    }
    drop((asker, target));
    drop(slot);
}
