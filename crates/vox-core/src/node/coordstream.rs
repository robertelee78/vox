//! The **coord stream** (`StreamKind::Coord`): reflexive-address discovery and
//! hole-punch signaling (ADR-012 rung 3).
//!
//! Rung 3 needs two things the node could not do: learn the address the outside world
//! sees for it, and exchange DCUtR `Connect`/`Sync` with a peer it cannot yet reach.
//! Both ride this stream.
//!
//! ## Verbs
//!
//! | frame | direction | meaning |
//! |---|---|---|
//! | `WHOAMI` | asker → peer | "what source address do you see for me?" |
//! | `OBSERVED <multiaddr>` | peer → asker | the address the peer observes for the connection the stream is on |
//! | `RELAY <peer>` | initiator → coordinator | "carry a punch session to this peer" |
//! | `FROM <peer>` | coordinator → responder | "this relayed session is from that peer" |
//! | `RELAYING` | either → its counterpart | the session is up; `COORD` frames follow |
//! | `REFUSED <reason>` | either → its counterpart | it is not, and why |
//! | `COORD <bytes>` | end to end | one [`CoordMessage`], opaque to the coordinator |
//!
//! ## Who may ask what
//!
//! `WHOAMI` is answered for **any authenticated peer**, including one this node shares
//! no channel with. The answer is the peer's own address, which it is about to learn
//! from any other peer anyway, and this is the service a NATed client cannot do
//! without — the same openness the board's reads have (ADR-012 Implementation notes).
//! Refusing it would break exactly the client this ADR exists for.
//!
//! `RELAY`/`FROM` are **not** open. Both ends of a relayed session must be peers this
//! node knows in some way — a member, an anchor, or a **pending joiner** (a peer with a
//! live self-signed pre-join record on this node's board, which is what classified it).
//! A joiner is included deliberately: without it, a newcomer could only join a swarm
//! that has a publicly reachable member, which is the dependency this ADR exists to
//! remove — and a joiner already holds a far more expensive capability, the PoW-gated
//! join stream. An *unknown* peer, which has published nothing, gets `WHOAMI` and
//! nothing else.
//!
//! One more rule, for the joining case: a session relayed **by this node's own
//! anchor** is accepted whoever the far peer is. The anchor already applied its own
//! rule — it relays only for peers with records on its board — and it is the node the
//! user configured to introduce peers (ADR-012 §"Bootstrap": "bootstrap nodes only
//! introduce peers"). Without this, a newcomer whose pre-join record is on the
//! anchor's board could never be punched to by a member that has not seen that
//! record yet, which is every member behind a NAT.
//!
//! This is signaling for two peers, never a data path: the coordinator forwards `COORD`
//! frames and nothing else, at most [`MAX_RELAYED_FRAMES`] of them per direction within
//! [`RELAY_SESSION_TIMEOUT`], so the verb cannot be turned into a free tunnel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::nat::holepunch::{CoordMessage, Coordinator, PunchPlan, Role, Step};
use crate::nat::multiaddr::{EndpointList, Multiaddr, MAX_ENDPOINTS};
use crate::nat::reachability::connect_direct_within;
use crate::node::net::PeerClass;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{VoxConnection, VoxEndpoint};
use crate::transport::streams::{open_typed, StreamKind};

/// The largest coord frame. A `Connect` with a full endpoint list is a few hundred
/// bytes; this leaves room without letting the verb carry payloads.
pub const MAX_COORD_FRAME: usize = 4 * 1024;

/// How many `COORD` frames a coordinator will forward in one session. DCUtR needs
/// three (`Connect`, `Connect`, `Sync`); the rest is slack for a retry.
pub const MAX_RELAYED_FRAMES: usize = 8;

/// How long a relayed signaling session may live. A punch is decided in one round
/// trip; anything longer is not a punch.
pub const RELAY_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for one signaling frame from the peer.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the synchronized dial waits per target. Shorter than a plain dial's:
/// QUIC retransmits its Initial at about 1, 2 and 4 s, so a punch that has not
/// landed in six will not, and the ladder is not held up by it.
pub const PUNCH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(6);

const OP_WHOAMI: u64 = 0;
const OP_OBSERVED: u64 = 1;
const OP_RELAY: u64 = 2;
const OP_FROM: u64 = 3;
const OP_RELAYING: u64 = 4;
const OP_REFUSED: u64 = 5;
const OP_COORD: u64 = 6;

/// Why a coordinator or a responder would not take part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordRefusal {
    /// The coordinator has no live connection to the named peer.
    NotConnected,
    /// The asker (or the peer it named) is not one this node relays for.
    NotAuthorized,
    /// This node is already relaying as many sessions as it will.
    Capacity,
}

impl CoordRefusal {
    #[must_use]
    fn code(self) -> u64 {
        match self {
            CoordRefusal::NotConnected => 0,
            CoordRefusal::NotAuthorized => 1,
            CoordRefusal::Capacity => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self> {
        match code {
            0 => Ok(CoordRefusal::NotConnected),
            1 => Ok(CoordRefusal::NotAuthorized),
            2 => Ok(CoordRefusal::Capacity),
            _ => Err(Error::HolePunchFailed("coord: unknown refusal reason")),
        }
    }
}

/// One frame on a coord stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordFrame {
    /// "What source address do you see for me?"
    WhoAmI,
    /// The address the peer observes for this connection.
    Observed {
        /// The observed (reflexive) address.
        addr: Multiaddr,
    },
    /// "Carry a punch session to this peer."
    Relay {
        /// The peer to reach.
        peer: Digest32,
    },
    /// "This relayed session is from that peer."
    From {
        /// The peer that asked for the session.
        peer: Digest32,
    },
    /// The session is up; `Coord` frames follow.
    Relaying,
    /// The session is refused.
    Refused {
        /// Why.
        reason: CoordRefusal,
    },
    /// One DCUtR coordination message, opaque to the coordinator.
    Coord {
        /// The encoded [`CoordMessage`].
        payload: Vec<u8>,
    },
}

impl CoordFrame {
    /// Canonical CBOR: a definite-length array led by the op discriminant.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            CoordFrame::WhoAmI => {
                e.array(1).uint(OP_WHOAMI);
            }
            CoordFrame::Observed { addr } => {
                e.array(2).uint(OP_OBSERVED);
                addr.encode_into(&mut e);
            }
            CoordFrame::Relay { peer } => {
                e.array(2).uint(OP_RELAY).bytes(peer);
            }
            CoordFrame::From { peer } => {
                e.array(2).uint(OP_FROM).bytes(peer);
            }
            CoordFrame::Relaying => {
                e.array(1).uint(OP_RELAYING);
            }
            CoordFrame::Refused { reason } => {
                e.array(2).uint(OP_REFUSED).uint(reason.code());
            }
            CoordFrame::Coord { payload } => {
                e.array(2).uint(OP_COORD).bytes(payload);
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
            (OP_WHOAMI, 1) => CoordFrame::WhoAmI,
            (OP_OBSERVED, 2) => CoordFrame::Observed {
                addr: Multiaddr::decode_from(&mut d)?,
            },
            (OP_RELAY, 2) => CoordFrame::Relay {
                peer: fingerprint(&mut d)?,
            },
            (OP_FROM, 2) => CoordFrame::From {
                peer: fingerprint(&mut d)?,
            },
            (OP_RELAYING, 1) => CoordFrame::Relaying,
            (OP_REFUSED, 2) => CoordFrame::Refused {
                reason: CoordRefusal::from_code(d.uint()?)?,
            },
            (OP_COORD, 2) => CoordFrame::Coord {
                payload: d.bytes()?.to_vec(),
            },
            (OP_WHOAMI..=OP_COORD, _) => return Err(Error::HolePunchFailed("coord: frame arity")),
            _ => return Err(Error::HolePunchFailed("coord: unknown op")),
        };
        d.finish()
            .map_err(|_| Error::HolePunchFailed("coord: trailing bytes"))?;
        Ok(frame)
    }
}

fn fingerprint(d: &mut Decoder<'_>) -> Result<Digest32> {
    let raw = d.bytes()?;
    Digest32::try_from(raw).map_err(|_| Error::HolePunchFailed("coord: fingerprint length"))
}

/// Read one coord frame, within [`FRAME_TIMEOUT`]. A closed stream is an error here:
/// every read in this protocol expects an answer.
async fn next_frame(recv: &mut RecvStream) -> Result<CoordFrame> {
    let frame = tokio::time::timeout(FRAME_TIMEOUT, read_frame(recv, MAX_COORD_FRAME))
        .await
        .map_err(|_| Error::HolePunchFailed("coord: peer went quiet"))??
        .ok_or(Error::HolePunchFailed("coord: stream closed"))?;
    CoordFrame::from_bytes(&frame)
}

async fn send_frame(send: &mut SendStream, frame: &CoordFrame) -> Result<()> {
    write_frame(send, &frame.to_bytes()).await
}

/// Ask `conn`'s peer for the source address it sees for this connection — this node's
/// **observed address** (ADR-012 rung 3; what a STUN server answers).
///
/// The answer is not trusted on its own: it is what this node offers a peer to dial
/// during a punch, so a wrong answer costs a failed punch and nothing else. It is
/// deliberately *not* published in an address record, where a lying peer could make
/// this node advertise somebody else's address.
pub async fn ask_observed(conn: &VoxConnection) -> Result<Multiaddr> {
    let (mut send, mut recv) = open_typed(conn, StreamKind::Coord).await?;
    send_frame(&mut send, &CoordFrame::WhoAmI).await?;
    let answer = next_frame(&mut recv).await?;
    let _ = send.finish();
    match answer {
        CoordFrame::Observed { addr } => Ok(addr),
        CoordFrame::Refused { .. } => Err(Error::HolePunchFailed("coord: whoami refused")),
        _ => Err(Error::HolePunchFailed("coord: not an observed answer")),
    }
}

/// The endpoints to offer a peer for a punch: the address a coordinator observes for
/// this node first (the one a NAT will map), then whatever this node already knows it
/// is reachable at (a peer on the same LAN can use those).
#[must_use]
pub fn punch_endpoints(observed: Option<Multiaddr>, local: &EndpointList) -> EndpointList {
    let mut addrs: Vec<Multiaddr> = Vec::new();
    addrs.extend(observed);
    for a in local.addrs() {
        if !addrs.contains(a) {
            addrs.push(*a);
        }
    }
    addrs.truncate(MAX_ENDPOINTS);
    EndpointList::new(addrs).unwrap_or_default()
}

/// What an inbound coord stream turned out to be.
#[derive(Debug)]
pub enum CoordInbound {
    /// A `WHOAMI` was answered; nothing further is needed.
    Answered,
    /// A relayed punch session this node agreed to take part in as the **responder**:
    /// the DCUtR exchange is still to be run on these streams.
    Punch {
        /// The peer on the far side of the relay.
        peer: Digest32,
        /// The stream to the coordinator, carrying the session.
        send: SendStream,
        /// The same session's read half.
        recv: RecvStream,
    },
}

/// Serve one inbound coord stream.
///
/// `observed` is the source address this node sees for the connection the stream came
/// in on — the answer to `WHOAMI`. `policy` classifies both the peer and any peer it
/// names, and `connected` resolves a fingerprint to a live connection (the
/// coordinator's own peer table).
pub async fn serve_coord<F>(
    peer: Digest32,
    observed: Multiaddr,
    classify: &(dyn Fn(&Digest32) -> PeerClass + Sync),
    mut send: SendStream,
    mut recv: RecvStream,
    connected: F,
) -> Result<CoordInbound>
where
    F: FnOnce(&Digest32) -> Option<Arc<VoxConnection>>,
{
    match next_frame(&mut recv).await? {
        // Open to anyone: the answer is the asker's own address.
        CoordFrame::WhoAmI => {
            send_frame(&mut send, &CoordFrame::Observed { addr: observed }).await?;
            let _ = send.finish();
            Ok(CoordInbound::Answered)
        }
        // Relaying is work done for members and anchors only.
        CoordFrame::Relay { peer: target } => {
            // Both ends must be peers this node relays for: a member may not make it
            // open a coord stream to an identity it knows nothing about.
            if !relays_for(classify(&peer)) || !relays_for(classify(&target)) {
                refuse(&mut send, CoordRefusal::NotAuthorized).await;
                return Err(Error::StreamRefused("coord: peer may not ask for a relay"));
            }
            let Some(target_conn) = connected(&target) else {
                refuse(&mut send, CoordRefusal::NotConnected).await;
                return Err(Error::HolePunchFailed("coord: target not connected"));
            };
            relay_session(peer, send, recv, &target_conn).await?;
            Ok(CoordInbound::Answered)
        }
        // A coordinator offering a session: accept only from a member or anchor.
        CoordFrame::From { peer: origin } => {
            if !accepts_relayed(classify(&peer), classify(&origin)) {
                refuse(&mut send, CoordRefusal::NotAuthorized).await;
                return Err(Error::StreamRefused("coord: peer may not coordinate"));
            }
            send_frame(&mut send, &CoordFrame::Relaying).await?;
            Ok(CoordInbound::Punch {
                peer: origin,
                send,
                recv,
            })
        }
        _ => Err(Error::HolePunchFailed("coord: unexpected opening frame")),
    }
}

/// Whether this node will relay signaling for a peer of `class` — see the module docs
/// for why a pending joiner counts and an unknown peer does not.
#[must_use]
pub(crate) fn relays_for(class: PeerClass) -> bool {
    matches!(
        class,
        PeerClass::Member | PeerClass::Anchor | PeerClass::PendingJoiner
    )
}

/// Whether this node takes part in a session that `relay` carried here from
/// `origin`: the relay must be one this node would relay for, and the origin too —
/// unless the relay is this node's own **anchor**, which vouches for whoever it
/// introduces (see the module docs).
#[must_use]
pub(crate) fn accepts_relayed(relay: PeerClass, origin: PeerClass) -> bool {
    relays_for(relay) && (relays_for(origin) || relay == PeerClass::Anchor)
}

async fn refuse(send: &mut SendStream, reason: CoordRefusal) {
    let _ = send_frame(send, &CoordFrame::Refused { reason }).await;
    let _ = send.finish();
}

/// Pair the asker's stream with a fresh coord stream to `target` and forward `COORD`
/// frames between them until either side is done.
async fn relay_session(
    asker: Digest32,
    mut asker_send: SendStream,
    asker_recv: RecvStream,
    target: &Arc<VoxConnection>,
) -> Result<()> {
    let (mut target_send, mut target_recv) = open_typed(target, StreamKind::Coord).await?;
    send_frame(&mut target_send, &CoordFrame::From { peer: asker }).await?;
    match next_frame(&mut target_recv).await? {
        CoordFrame::Relaying => {}
        CoordFrame::Refused { reason } => {
            refuse(&mut asker_send, reason).await;
            return Err(Error::HolePunchFailed("coord: target refused the session"));
        }
        _ => return Err(Error::HolePunchFailed("coord: target did not accept")),
    }
    send_frame(&mut asker_send, &CoordFrame::Relaying).await?;
    // Two unidirectional copies, each on its own task: `read_frame` is **not**
    // cancel-safe (it reads a length prefix and then the body), so a `select!` over
    // both directions could abandon a half-read frame and desynchronize the stream.
    let mut up = tokio::spawn(copy_coord(asker_recv, target_send));
    let mut down = tokio::spawn(copy_coord(target_recv, asker_send));
    // The session ends when either direction does, and in any case at the timeout: a
    // punch is decided in one round trip, so a session that outlives that is not one.
    let _ = tokio::time::timeout(RELAY_SESSION_TIMEOUT, async {
        tokio::select! {
            _ = &mut up => {}
            _ = &mut down => {}
        }
    })
    .await;
    up.abort();
    down.abort();
    Ok(())
}

/// Forward up to [`MAX_RELAYED_FRAMES`] coordination frames one way.
///
/// Only `COORD` frames are forwarded, and the coordinator never looks inside one:
/// anything else ends the direction. This is what keeps the verb signaling rather than
/// a tunnel — the byte-forwarding rung is ADR-013's, with its own consent rules.
async fn copy_coord(mut recv: RecvStream, mut send: SendStream) {
    for _ in 0..MAX_RELAYED_FRAMES {
        let Ok(Some(frame)) = read_frame(&mut recv, MAX_COORD_FRAME).await else {
            break;
        };
        if !matches!(CoordFrame::from_bytes(&frame), Ok(CoordFrame::Coord { .. })) {
            break;
        }
        if write_frame(&mut send, &frame).await.is_err() {
            break;
        }
    }
    let _ = send.finish();
}

/// Open a punch session to `target` through `coordinator`: the `RELAY` ask and the
/// `RELAYING` acknowledgement, leaving the streams ready for
/// [`run_punch_initiator`].
pub async fn open_punch_session(
    coordinator: &VoxConnection,
    target: Digest32,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, mut recv) = open_typed(coordinator, StreamKind::Coord).await?;
    send_frame(&mut send, &CoordFrame::Relay { peer: target }).await?;
    match next_frame(&mut recv).await? {
        CoordFrame::Relaying => Ok((send, recv)),
        CoordFrame::Refused { reason } => Err(match reason {
            CoordRefusal::NotConnected => {
                Error::HolePunchFailed("coord: coordinator cannot reach the peer")
            }
            CoordRefusal::NotAuthorized => {
                Error::HolePunchFailed("coord: coordinator will not relay for us")
            }
            CoordRefusal::Capacity => Error::HolePunchFailed("coord: coordinator is at capacity"),
        }),
        _ => Err(Error::HolePunchFailed("coord: coordinator did not relay")),
    }
}

/// Run the **initiator** half of the DCUtR exchange over an established relayed
/// session, returning the plan to fire.
pub async fn run_punch_initiator(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local: EndpointList,
) -> Result<PunchPlan> {
    let mut coordinator = Coordinator::new(Role::Initiator, local);
    let opening = coordinator
        .initial_message()
        .ok_or(Error::HolePunchFailed("coord: initiator has no opening"))?;
    let started = Instant::now();
    send_coord(send, &opening).await?;
    let peer_observed = match recv_coord(recv).await? {
        CoordMessage::Connect { observed } => observed,
        CoordMessage::Sync => return Err(Error::HolePunchFailed("coord: Sync before Connect")),
    };
    let rtt = started.elapsed();
    match coordinator.on_peer_connect(&peer_observed, Some(rtt))? {
        Step::SyncThenPunch { sync, plan } => {
            send_coord(send, &sync).await?;
            Ok(plan)
        }
        Step::Send(_) | Step::Punch { .. } => {
            Err(Error::HolePunchFailed("coord: initiator out of sequence"))
        }
    }
}

/// Run the **responder** half over a session this node accepted, returning the plan to
/// fire (immediately: the initiator's own dial is timed to coincide).
pub async fn run_punch_responder(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local: EndpointList,
) -> Result<PunchPlan> {
    let mut coordinator = Coordinator::new(Role::Responder, local);
    let peer_observed = match recv_coord(recv).await? {
        CoordMessage::Connect { observed } => observed,
        CoordMessage::Sync => return Err(Error::HolePunchFailed("coord: Sync before Connect")),
    };
    match coordinator.on_peer_connect(&peer_observed, None)? {
        Step::Send(reply) => send_coord(send, &reply).await?,
        Step::SyncThenPunch { .. } | Step::Punch { .. } => {
            return Err(Error::HolePunchFailed("coord: responder out of sequence"))
        }
    }
    match recv_coord(recv).await? {
        CoordMessage::Sync => {}
        CoordMessage::Connect { .. } => {
            return Err(Error::HolePunchFailed("coord: duplicate Connect"))
        }
    }
    match coordinator.on_peer_sync(&peer_observed)? {
        Step::Punch { plan } => Ok(plan),
        Step::Send(_) | Step::SyncThenPunch { .. } => {
            Err(Error::HolePunchFailed("coord: responder out of sequence"))
        }
    }
}

async fn send_coord(send: &mut SendStream, message: &CoordMessage) -> Result<()> {
    send_frame(
        send,
        &CoordFrame::Coord {
            payload: message.to_bytes(),
        },
    )
    .await
}

async fn recv_coord(recv: &mut RecvStream) -> Result<CoordMessage> {
    match next_frame(recv).await? {
        CoordFrame::Coord { payload } => CoordMessage::from_bytes(&payload),
        CoordFrame::Refused { .. } => Err(Error::HolePunchFailed("coord: session refused")),
        _ => Err(Error::HolePunchFailed("coord: not a coordination message")),
    }
}

/// Fire a [`PunchPlan`]: wait out the synchronization delay, then dial every target at
/// once on the **same endpoint** the peer observed, requiring the expected identity.
pub async fn execute_punch(
    endpoint: Arc<VoxEndpoint>,
    plan: PunchPlan,
    expected_peer: Digest32,
    now_secs: u64,
) -> Result<VoxConnection> {
    if !plan.fire_delay.is_zero() {
        tokio::time::sleep(plan.fire_delay).await;
    }
    connect_direct_within(
        endpoint,
        &plan.targets,
        expected_peer,
        now_secs,
        PUNCH_ATTEMPT_TIMEOUT,
    )
    .await
}
