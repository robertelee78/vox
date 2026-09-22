//! The connection manager (ADR-016 §"Connections, reachability and sync"): one
//! authenticated QUIC connection per peer, and the authorization gate on what a
//! peer may open over it.
//!
//! ## One connection per peer fingerprint
//! [`ConnectionManager`] keeps at most one live [`VoxConnection`] per peer
//! fingerprint, whichever side dialed. [`ConnectionManager::connect`] reuses a live
//! connection and otherwise dials the peer's advertised endpoints through the
//! ADR-012 ladder ([`connect_direct`], Happy-Eyeballs over the record's
//! candidates); [`ConnectionManager::accept`] takes an inbound connection and files
//! it under the identity the M9 handshake authenticated. Closed connections are
//! reaped by [`ConnectionManager::prune_closed`], so a peer that comes back is
//! redialled rather than served a dead handle.
//!
//! ## Authorization is a stream-kind gate, not a transport gate
//! ADR-016's Decision says inbound connections are accepted with
//! `Admission::Callback` over the union of the channels' memberships "plus the
//! anchors and any pending pre-join identity **for the join stream only**". Taken
//! literally at the transport, that would also reject the peers ADR-012 requires a
//! rendezvous server to serve: reading the board is open to **any authenticated
//! peer that knows the channelID**, and a joiner must be able to publish its
//! pre-join record before anyone knows it. The two ADRs are reconciled by putting
//! the rule where ADR-011 says authorization belongs — *above* the transport:
//!
//! - A node that serves rendezvous accepts any authenticated identity
//!   ([`Admission::AcceptAnyAuthenticated`], ADR-011's open-swarm default); a node
//!   that does not can still be closed with [`Admission::Callback`] over
//!   [`PeerPolicy`].
//! - Every accepted stream is then classified by *who opened it* and refused if the
//!   peer's class may not open that kind ([`PeerPolicy::allows`],
//!   [`accept_authorized`]). So "pending pre-join identity, for the join stream
//!   only" is enforced exactly, and an unknown peer reaches the rendezvous service
//!   and nothing else.
//!
//! A refused stream is reset with [`WireError::AuthenticatorInvalid`] — the same
//! coded rejection an unauthenticated peer gets, so a peer cannot distinguish "not
//! a member" from "not authenticated" by probing stream kinds.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use quinn::{RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::nat::multiaddr::EndpointList;
use crate::nat::reachability::{connect_direct, direct_candidates};
use crate::time::Clock;
use crate::transport::quic::{close_code, Admission, VoxConnection, VoxEndpoint};
use crate::transport::streams::{accept_typed, StreamKind};
use crate::wire::WireError;

/// How a peer is known to this node, which decides what it may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerClass {
    /// A member of at least one channel this node holds (ADR-007 membership).
    Member,
    /// A configured anchor: it stores and forwards for us and syncs as an ordinary
    /// peer, but it is not a member of our channels.
    Anchor,
    /// An identity this node is currently expecting a join from (its pre-join
    /// record was accepted, or a link names it).
    PendingJoiner,
    /// Authenticated, but otherwise unknown to us.
    Unknown,
}

/// Who this node knows, for classifying inbound peers. Rebuilt from the node's
/// channel memberships (and its configured anchors) whenever they change, so the
/// view a stream is judged against is never stale by more than one rebuild.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    members: HashSet<Digest32>,
    anchors: HashSet<Digest32>,
    pending_joiners: HashSet<Digest32>,
}

impl PeerPolicy {
    /// An empty policy (every peer is [`PeerClass::Unknown`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the members of a channel (the union across channels is what matters).
    pub fn add_members(&mut self, members: impl IntoIterator<Item = Digest32>) {
        self.members.extend(members);
    }

    /// Add a configured anchor.
    pub fn add_anchor(&mut self, anchor: Digest32) {
        self.anchors.insert(anchor);
    }

    /// Expect a join from `joiner` (until [`PeerPolicy::forget_joiner`]).
    pub fn expect_joiner(&mut self, joiner: Digest32) {
        self.pending_joiners.insert(joiner);
    }

    /// Stop expecting a join from `joiner` (it joined, or the attempt lapsed).
    pub fn forget_joiner(&mut self, joiner: &Digest32) -> bool {
        self.pending_joiners.remove(joiner)
    }

    /// Classify a peer. Membership wins over every other class: a member that is
    /// also an anchor or a pending joiner is a member.
    #[must_use]
    pub fn classify(&self, peer: &Digest32) -> PeerClass {
        if self.members.contains(peer) {
            PeerClass::Member
        } else if self.anchors.contains(peer) {
            PeerClass::Anchor
        } else if self.pending_joiners.contains(peer) {
            PeerClass::PendingJoiner
        } else {
            PeerClass::Unknown
        }
    }

    /// How many members this policy knows.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// How many anchors this policy knows.
    #[must_use]
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// The identities this policy is currently expecting a join from.
    #[must_use]
    pub fn pending_joiners(&self) -> Vec<Digest32> {
        self.pending_joiners.iter().copied().collect()
    }

    /// Whether a peer of `class` may open a `kind` stream.
    ///
    /// - **Member**: everything. It is in the channel; the log, consent and
    ///   render gates (ADR-007/008) govern what it can actually *read*.
    /// - **Anchor**: `rendezvous` (the board), `sync` (it replicates ciphertext it
    ///   can never read) and `coord` (it relays hole-punch signalling). Never
    ///   `join` or `pairwise`: it has no channel authority.
    /// - **PendingJoiner**: `join`, `rendezvous` and `pairwise`. ADR-016's Decision
    ///   says "for the join stream only", which is one stream too few: the moment a
    ///   join completes, the newcomer must deliver its **own** sender key (ADR-007
    ///   step 2), and it cannot wait to be reclassified — the responder only admits
    ///   it as a member *after* the join's final frame, and the ADR-004 responder
    ///   cannot speak first on the new session anyway. Allowing `pairwise` costs
    ///   nothing: a sealed message from a peer we hold no session with cannot be
    ///   opened and is dropped. Never `sync` (no log authority) and never `tunnel`.
    /// - **Unknown**: `rendezvous` only, gated further by the service's own policy
    ///   (ADR-012: reads open, member-only writes refused there).
    #[must_use]
    pub fn allows(class: PeerClass, kind: StreamKind) -> bool {
        match class {
            PeerClass::Member => true,
            PeerClass::Anchor => matches!(
                kind,
                StreamKind::Rendezvous | StreamKind::Sync | StreamKind::Coord | StreamKind::Circuit
            ),
            PeerClass::PendingJoiner => matches!(
                kind,
                StreamKind::Join
                    | StreamKind::Rendezvous
                    | StreamKind::Pairwise
                    | StreamKind::Coord
                    | StreamKind::Circuit
            ),
            // An unknown peer reaches the board — and the coord stream, where the only
            // verb open to it is `WHOAMI`, whose answer is its own address (enforced in
            // `node::coordstream`). A NATed client cannot learn its reflexive address
            // any other way, and this ADR exists for that client.
            PeerClass::Unknown => matches!(kind, StreamKind::Rendezvous | StreamKind::Coord),
        }
    }

    /// The transport admission for a node that does **not** serve rendezvous: only
    /// identities this policy knows may connect at all. A node that serves
    /// rendezvous must use [`Admission::AcceptAnyAuthenticated`] instead (see the
    /// module docs).
    #[must_use]
    pub fn closed_admission(&self) -> Admission {
        let known: HashSet<Digest32> = self
            .members
            .iter()
            .chain(self.anchors.iter())
            .chain(self.pending_joiners.iter())
            .copied()
            .collect();
        Admission::Pinned(known)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How a connection reaches its peer, in preference order (ADR-012: prefer direct).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathClass {
    /// Through a relay circuit (rung 4): works anywhere, costs a third party.
    Relayed,
    /// Straight to the peer — dialled, or punched (rungs 1–3).
    Direct,
}

/// The path a connection is on.
///
/// Asked of the endpoint whose socket carries it, because a circuit's address is random:
/// only the mux's table knows which addresses are circuits, and a guess from the address
/// would be wrong in both directions — a real address can fall inside the subnet, and a
/// circuit's address looks like nothing in particular.
#[must_use]
pub fn path_class(endpoint: &VoxEndpoint, conn: &VoxConnection) -> PathClass {
    if endpoint.is_circuit(conn.quinn().remote_address()) {
        PathClass::Relayed
    } else {
        PathClass::Direct
    }
}

/// How long a connection displaced by a better one stays open before it is closed:
/// long enough for anything in flight on it — a join exchange, a sync session (whose
/// frames are bounded at 20 s) — to finish, because the peer's streams do not move.
pub const RETIRE_GRACE_SECS: u64 = 60;

/// One QUIC connection per peer fingerprint (see the module docs).
pub struct ConnectionManager {
    endpoint: Arc<VoxEndpoint>,
    conns: Mutex<HashMap<Digest32, Arc<VoxConnection>>>,
    /// Connections a better path displaced, with the time each may be closed. They
    /// keep serving what is already on them; nothing new is opened on them.
    retiring: Mutex<Vec<(Arc<VoxConnection>, u64)>>,
    retire_grace_secs: u64,
    clock: Clock,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("local_id", &crate::hash::Hex(&self.endpoint.local_id()))
            .field("connections", &lock(&self.conns).len())
            .finish_non_exhaustive()
    }
}

impl ConnectionManager {
    /// A manager over a bound endpoint.
    #[must_use]
    pub fn new(endpoint: Arc<VoxEndpoint>, clock: Clock) -> Self {
        Self::with_retire_grace(endpoint, clock, RETIRE_GRACE_SECS)
    }

    /// [`ConnectionManager::new`] with an explicit retirement grace (tests shorten it).
    #[must_use]
    pub fn with_retire_grace(endpoint: Arc<VoxEndpoint>, clock: Clock, grace_secs: u64) -> Self {
        Self {
            endpoint,
            conns: Mutex::new(HashMap::new()),
            retiring: Mutex::new(Vec::new()),
            retire_grace_secs: grace_secs,
            clock,
        }
    }

    /// This node's identity fingerprint.
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.endpoint.local_id()
    }

    /// The shared local endpoint (for the reachability ladder and for binding
    /// advertisements).
    #[must_use]
    pub fn endpoint(&self) -> &Arc<VoxEndpoint> {
        &self.endpoint
    }

    /// The live connection to `peer`, if any.
    #[must_use]
    pub fn existing(&self, peer: &Digest32) -> Option<Arc<VoxConnection>> {
        let conn = lock(&self.conns).get(peer).cloned()?;
        if is_live(&conn) {
            Some(conn)
        } else {
            lock(&self.conns).remove(peer);
            None
        }
    }

    /// The live connection to `peer`, dialling its advertised `endpoints` if there
    /// is none. Concurrent callers for the same peer may race one extra dial; the
    /// loser's connection is closed so the invariant (one per peer) holds.
    pub async fn connect(
        &self,
        peer: Digest32,
        endpoints: &EndpointList,
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.existing(&peer) {
            return Ok(conn);
        }
        let candidates = direct_candidates(endpoints);
        let conn = connect_direct(
            Arc::clone(&self.endpoint),
            &candidates,
            peer,
            (self.clock)(),
        )
        .await?;
        Ok(self.file(conn))
    }

    /// Accept the next inbound connection under `admission` and file it under the
    /// authenticated peer identity. `Ok(None)` when the endpoint is closed.
    ///
    /// **Performs the handshake inline**, so this is for a caller that wants exactly one
    /// connection. An accept *loop* must use [`Self::accept_incoming`] and
    /// [`Self::finish_incoming`] instead, or it serialises on handshakes and one stalled
    /// unauthenticated peer blocks every other inbound connection.
    pub async fn accept(&self, admission: Admission) -> Result<Option<Arc<VoxConnection>>> {
        let Some(conn) = self
            .endpoint
            .accept_with_admission((self.clock)(), admission)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(self.file(conn)))
    }

    /// Phase one for an accept loop: the next inbound attempt, with no handshake.
    /// `None` when the endpoint is closed.
    pub async fn accept_incoming(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept_incoming().await
    }

    /// Phase two: complete one attempt's handshake and admission, then file it. Spawn this.
    pub async fn finish_incoming(
        &self,
        incoming: quinn::Incoming,
        admission: Admission,
    ) -> Result<Arc<VoxConnection>> {
        let conn = self
            .endpoint
            .finish_incoming(incoming, (self.clock)(), admission)
            .await?;
        Ok(self.file(conn))
    }

    /// Take ownership of a connection this manager did not dial — one a hole punch
    /// produced (ADR-012 rung 3) — under the same one-per-peer rule.
    pub fn adopt(&self, conn: VoxConnection) -> Arc<VoxConnection> {
        self.file(conn)
    }

    /// File a connection under its peer id. One connection per peer is a
    /// **preference**, not a first-come rule (M15.1b, relay-first / upgrade-later):
    ///
    /// - a newcomer on a *better* path than the one held — direct where the held one
    ///   is relayed — **replaces** it, and the old one is retired: kept open for
    ///   [`RETIRE_GRACE_SECS`] so whatever is in flight on it finishes, closed after;
    /// - otherwise the held one is kept and the newcomer closed with a clean code (a
    ///   simultaneous dial from both sides lands here).
    ///
    /// Both ends apply the same rule, which is what lets an upgrade land without a
    /// protocol: the side that punched files the direct connection as an improvement,
    /// and the side that accepted it does too.
    fn file(&self, conn: VoxConnection) -> Arc<VoxConnection> {
        let peer = conn.peer_id();
        let mut map = lock(&self.conns);
        if let Some(existing) = map.get(&peer) {
            if is_live(existing) {
                let existing = Arc::clone(existing);
                if path_class(&self.endpoint, &conn) <= path_class(&self.endpoint, &existing) {
                    drop(map);
                    conn.close(WireError::AuthenticatorInvalid);
                    return existing;
                }
                let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
                lock(&self.retiring).push((existing, retire_at));
            }
        }
        let conn = Arc::new(conn);
        map.insert(peer, Arc::clone(&conn));
        conn
    }

    /// Close every retired connection whose grace has elapsed (or that the peer
    /// already closed). Returns how many were closed. The node's tick calls this.
    pub fn retire_expired(&self) -> usize {
        let now = (self.clock)();
        let mut retiring = lock(&self.retiring);
        let before = retiring.len();
        retiring.retain(|(conn, at)| {
            if now >= *at || !is_live(conn) {
                conn.close(WireError::AuthenticatorInvalid);
                false
            } else {
                true
            }
        });
        before - retiring.len()
    }

    /// How many displaced connections are still within their grace.
    #[must_use]
    pub fn retiring_count(&self) -> usize {
        lock(&self.retiring).len()
    }

    /// Drop every connection the peer or the network has closed. Returns how many
    /// were reaped.
    pub fn prune_closed(&self) -> usize {
        let mut map = lock(&self.conns);
        let before = map.len();
        map.retain(|_, c| is_live(c));
        before - map.len()
    }

    /// The peers with a live connection, in unspecified order.
    #[must_use]
    pub fn peers(&self) -> Vec<Digest32> {
        lock(&self.conns)
            .iter()
            .filter(|(_, c)| is_live(c))
            .map(|(p, _)| *p)
            .collect()
    }

    /// Close and forget the connection to `peer`, with the coded reason.
    pub fn close_peer(&self, peer: &Digest32, err: WireError) -> bool {
        match lock(&self.conns).remove(peer) {
            Some(conn) => {
                conn.close(err);
                true
            }
            None => false,
        }
    }

    /// Close every connection (node shutdown).
    pub fn close_all(&self) {
        for (conn, _) in lock(&self.retiring).drain(..) {
            conn.close(WireError::AuthenticatorInvalid);
        }
        for (_, conn) in lock(&self.conns).drain() {
            conn.close(WireError::AuthenticatorInvalid);
        }
    }
}

/// Whether a connection is still usable.
fn is_live(conn: &VoxConnection) -> bool {
    conn.quinn().close_reason().is_none()
}

/// Accept the next stream on `conn` and authorize it against `policy`: the peer's
/// class must be allowed to open that kind, or the stream is reset with the coded
/// rejection and [`Error::StreamRefused`] is returned (see the module docs).
pub async fn accept_authorized(
    conn: &VoxConnection,
    policy: &PeerPolicy,
) -> Result<(StreamKind, SendStream, RecvStream)> {
    let (kind, mut send, mut recv) = accept_typed(conn).await?;
    let class = policy.classify(&conn.peer_id());
    if !PeerPolicy::allows(class, kind) {
        refuse_stream(&mut send, &mut recv);
        return Err(Error::StreamRefused("peer may not open this stream kind"));
    }
    Ok((kind, send, recv))
}

/// Reset both halves of a stream with the coded rejection — the same code an
/// unauthenticated peer gets, so probing stream kinds reveals nothing.
pub fn refuse_stream(send: &mut SendStream, recv: &mut RecvStream) {
    let code = close_code(WireError::AuthenticatorInvalid);
    let _ = send.reset(code);
    let _ = recv.stop(code);
}
