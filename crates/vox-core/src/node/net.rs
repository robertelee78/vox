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

/// The path a connection is on, read off its remote address.
#[must_use]
pub fn path_class(conn: &VoxConnection) -> PathClass {
    if crate::transport::mux::is_circuit_addr(conn.quinn().remote_address()) {
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
                if path_class(&conn) <= path_class(&existing) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::nat::multiaddr::Multiaddr;
    use crate::transport::framing::write_frame;
    use crate::transport::streams::open_typed;
    use std::net::SocketAddr;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const T0: u64 = 1_700_000_000;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn endpoints_for(addr: SocketAddr) -> EndpointList {
        let SocketAddr::V4(v4) = addr else {
            unreachable!("loopback is v4 in these tests")
        };
        EndpointList::new(vec![Multiaddr::Ip4(v4)]).unwrap()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn manager(s: &SoftwareRootSigner) -> Arc<ConnectionManager> {
        let ep = Arc::new(VoxEndpoint::bind(s, loopback()).unwrap());
        Arc::new(ConnectionManager::new(ep, Arc::new(|| T0)))
    }

    #[test]
    fn peer_classes_decide_which_stream_kinds_are_allowed() {
        let member = [1u8; 32];
        let anchor = [2u8; 32];
        let joiner = [3u8; 32];
        let stranger = [4u8; 32];
        let mut p = PeerPolicy::new();
        p.add_members([member]);
        p.add_anchor(anchor);
        p.expect_joiner(joiner);

        assert_eq!(p.classify(&member), PeerClass::Member);
        assert_eq!(p.classify(&anchor), PeerClass::Anchor);
        assert_eq!(p.classify(&joiner), PeerClass::PendingJoiner);
        assert_eq!(p.classify(&stranger), PeerClass::Unknown);

        use StreamKind::{Circuit, Coord, Join, Pairwise, Rendezvous, Sync, Tunnel};
        // A member may open anything; the log/consent gates do the real work.
        for k in [Sync, Join, Pairwise, Rendezvous, Tunnel, Coord, Circuit] {
            assert!(PeerPolicy::allows(PeerClass::Member, k));
        }
        // An anchor stores, syncs, relays signalling and carries circuits — it has no
        // channel authority, so no join and no pairwise.
        for k in [Rendezvous, Sync, Coord, Circuit] {
            assert!(PeerPolicy::allows(PeerClass::Anchor, k));
        }
        for k in [Join, Pairwise, Tunnel] {
            assert!(!PeerPolicy::allows(PeerClass::Anchor, k));
        }
        // A pending joiner gets the join stream, the board it must publish its
        // pre-join record to, and `pairwise` — it has to deliver its own sender key
        // the instant the join completes, before the responder has reclassified it.
        // It also gets `coord` and `circuit`: a joiner behind NAT must learn its own
        // address, and a member that is itself behind NAT can only be reached by a
        // punch the coordinator relays or, failing that, a circuit it carries
        // (ADR-012 rungs 3–4).
        for k in [Join, Rendezvous, Pairwise, Coord, Circuit] {
            assert!(PeerPolicy::allows(PeerClass::PendingJoiner, k));
        }
        // But no log authority and no tunnels.
        for k in [Sync, Tunnel] {
            assert!(!PeerPolicy::allows(PeerClass::PendingJoiner, k));
        }
        // An unknown peer reaches the rendezvous service and the coord stream, where
        // `WHOAMI` — its own address — is the only verb open to it.
        for k in [Rendezvous, Coord] {
            assert!(PeerPolicy::allows(PeerClass::Unknown, k));
        }
        for k in [Sync, Join, Pairwise, Tunnel, Circuit] {
            assert!(!PeerPolicy::allows(PeerClass::Unknown, k));
        }

        // Membership wins over the other classes.
        let mut q = PeerPolicy::new();
        q.add_members([anchor]);
        q.add_anchor(anchor);
        q.expect_joiner(anchor);
        assert_eq!(q.classify(&anchor), PeerClass::Member);

        // A joiner is forgotten once its attempt resolves.
        assert!(p.forget_joiner(&joiner));
        assert!(!p.forget_joiner(&joiner));
        assert_eq!(p.classify(&joiner), PeerClass::Unknown);

        // The closed admission (a node that does not serve rendezvous) pins exactly
        // the identities the policy knows.
        let Admission::Pinned(known) = p.closed_admission() else {
            unreachable!("closed_admission is pinned")
        };
        assert!(known.contains(&member) && known.contains(&anchor));
        assert!(!known.contains(&stranger) && !known.contains(&joiner));
    }

    #[test]
    fn one_connection_per_peer_is_reused_and_dead_ones_are_reaped() {
        let rt = runtime();
        rt.block_on(async move {
            // Bind inside the runtime: quinn needs the reactor.
            let server = manager(&signer(10, 11));
            let client = manager(&signer(12, 13));
            let server_id = server.local_id();
            let server_eps = endpoints_for(server.endpoint().local_addr().unwrap());
            let accepting = {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    server
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap()
                })
            };

            // First connect dials; the second reuses the same connection object.
            let a = tokio::time::timeout(TIMEOUT, client.connect(server_id, &server_eps))
                .await
                .unwrap()
                .unwrap();
            let b = client.connect(server_id, &server_eps).await.unwrap();
            assert!(Arc::ptr_eq(&a, &b), "a second connect must not redial");
            assert_eq!(client.peers(), vec![server_id]);
            assert!(client.existing(&server_id).is_some());

            let server_conn = accepting.await.unwrap();
            assert_eq!(server_conn.peer_id(), client.local_id());
            assert_eq!(server.peers(), vec![client.local_id()]);

            // Closing drops it from the table, and a dead connection is never served.
            assert!(client.close_peer(&server_id, WireError::EpochMismatch));
            assert!(client.existing(&server_id).is_none());
            assert!(client.peers().is_empty());
            assert!(!client.close_peer(&server_id, WireError::EpochMismatch));

            // The server side observes the close and reaps it.
            tokio::time::timeout(TIMEOUT, async {
                while server.prune_closed() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(server.peers().is_empty());

            // A record with no direct candidates is an unreachability error, not a
            // hang (the ADR-012 ladder's other rungs are M15).
            let empty = EndpointList::new(vec![]).unwrap();
            assert!(matches!(
                client.connect([9u8; 32], &empty).await,
                Err(Error::Unreachable("no direct candidates"))
            ));
            server.close_all();
            client.close_all();
        });
    }

    #[test]
    fn an_unknown_peer_may_open_rendezvous_but_nothing_else() {
        let rt = runtime();
        rt.block_on(async move {
            let server = manager(&signer(20, 21));
            let client = manager(&signer(22, 23));
            let server_id = server.local_id();
            let server_eps = endpoints_for(server.endpoint().local_addr().unwrap());
            // The server knows nobody: the dialer is `Unknown`.
            let policy = PeerPolicy::new();
            let server_task = {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let conn = server
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    // First stream: rendezvous — allowed.
                    let first = accept_authorized(&conn, &policy).await.map(|(k, _, _)| k);
                    // Second stream: sync — refused.
                    let second = accept_authorized(&conn, &policy).await.map(|(k, _, _)| k);
                    (first, second, conn)
                })
            };

            let conn = tokio::time::timeout(TIMEOUT, client.connect(server_id, &server_eps))
                .await
                .unwrap()
                .unwrap();
            let (mut s1, _r1) = open_typed(&conn, StreamKind::Rendezvous).await.unwrap();
            write_frame(&mut s1, b"hello").await.unwrap();
            let (mut s2, mut r2) = open_typed(&conn, StreamKind::Sync).await.unwrap();
            write_frame(&mut s2, b"hello").await.unwrap();

            let (first, second, _conn) = tokio::time::timeout(TIMEOUT, server_task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.unwrap(), StreamKind::Rendezvous);
            assert!(
                matches!(second, Err(Error::StreamRefused(_))),
                "an unknown peer must not open a sync stream: {second:?}"
            );

            // The refusal reaches the peer as the same coded reset an
            // unauthenticated peer gets — no distinguishable oracle.
            let mut buf = [0u8; 4];
            let got = tokio::time::timeout(TIMEOUT, r2.read_exact(&mut buf))
                .await
                .unwrap();
            let expected = close_code(WireError::AuthenticatorInvalid);
            assert!(
                matches!(
                    got,
                    Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(c))) if c == expected
                ),
                "expected a coded reset, got {got:?}"
            );
            server.close_all();
            client.close_all();
        });
    }
}

#[cfg(test)]
mod upgrade_tests {
    //! Relay-first / upgrade-later at the manager (M15.1b). This began as the spike
    //! that showed the old first-come rule closing every upgrade on both sides, and
    //! stays as the proof of the rule that replaced it. The relayed connection is made
    //! the way rung 4 makes it — over circuits joined in-process — and the direct one
    //! over loopback.
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::transport::mux::{circuit_addr, CircuitInlet, CircuitPort};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    fn signer(seed: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap()
    }

    fn pipe(mut from: CircuitPort, to: CircuitInlet) -> CircuitPort {
        let mut rx = from.take_outbound().unwrap();
        tokio::spawn(async move {
            while let Some(d) = rx.recv().await {
                to.deliver(d);
            }
        });
        from
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_direct_path_replaces_a_relayed_one_on_both_sides_and_the_old_one_finishes() {
        let a_ep = Arc::new(VoxEndpoint::bind(&signer(1), "127.0.0.1:0".parse().unwrap()).unwrap());
        let b_ep = Arc::new(VoxEndpoint::bind(&signer(2), "127.0.0.1:0".parse().unwrap()).unwrap());
        let (a_id, b_id) = (a_ep.local_id(), b_ep.local_id());
        let b_addr = b_ep.local_addr().unwrap();
        // A clock the test advances, so the retirement grace can be crossed.
        let now = Arc::new(AtomicU64::new(1_800_000_000));
        let clock: Clock = {
            let now = Arc::clone(&now);
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let a = Arc::new(ConnectionManager::with_retire_grace(
            Arc::clone(&a_ep),
            Arc::clone(&clock),
            30,
        ));
        let b = Arc::new(ConnectionManager::with_retire_grace(
            Arc::clone(&b_ep),
            clock,
            30,
        ));

        // Circuits joined in-process: the relayed path, minus the relay.
        let a_port = a_ep.attach_circuit(&b_id);
        let b_port = b_ep.attach_circuit(&a_id);
        let (a_inlet, b_inlet) = (a_port.inlet(), b_port.inlet());
        let _a_port = pipe(a_port, b_inlet);
        let _b_port = pipe(b_port, a_inlet);

        // B accepts everything A brings, filing each through the rule.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let b = Arc::clone(&b);
            tokio::spawn(async move {
                while let Ok(Some(conn)) = b.accept(Admission::AcceptAnyAuthenticated).await {
                    let _ = tx.send(conn);
                }
            });
        }

        // 1. The relayed connection lands first, as rung 4 lands it.
        let relayed_eps = EndpointList::new(vec![circuit_addr(&b_id).into()]).unwrap();
        let a_relayed = a.connect(b_id, &relayed_eps).await.expect("relayed");
        let b_relayed = rx.recv().await.unwrap();
        assert_eq!(path_class(&a_relayed), PathClass::Relayed);
        assert_eq!(path_class(&b_relayed), PathClass::Relayed);
        // A stream on it, left in flight: what a join or a sync looks like mid-upgrade.
        let (mut in_flight_send, _in_flight_recv) = a_relayed.open_stream().await.unwrap();
        in_flight_send.write_all(b"part one, ").await.unwrap();
        let (_bs, mut br) = b_relayed.accept_stream().await.unwrap();
        let mut first = [0u8; 10];
        br.read_exact(&mut first).await.unwrap();

        // 2. A direct path becomes available: the upgrade. Both sides file it.
        let a_direct = a_ep
            .connect(b_addr, b_id, 1_800_000_000)
            .await
            .expect("direct");
        let a_primary = a.adopt(a_direct);
        let b_primary = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("B accepted the direct connection")
            .unwrap();
        assert_eq!(path_class(&a_primary), PathClass::Direct);
        assert_eq!(
            path_class(&b_primary),
            PathClass::Direct,
            "B took the better path too"
        );
        assert!(!Arc::ptr_eq(&a_primary, &a_relayed));
        assert!(!Arc::ptr_eq(&b_primary, &b_relayed));
        assert!(
            Arc::ptr_eq(&a.existing(&b_id).unwrap(), &a_primary),
            "A's primary is direct"
        );
        assert!(
            Arc::ptr_eq(&b.existing(&a_id).unwrap(), &b_primary),
            "B's primary is direct"
        );
        assert_eq!(a.retiring_count(), 1);
        assert_eq!(b.retiring_count(), 1);

        // 3. The displaced path is still serving what was in flight on it.
        in_flight_send.write_all(b"part two").await.unwrap();
        in_flight_send.finish().unwrap();
        let rest = tokio::time::timeout(Duration::from_secs(3), br.read_to_end(64))
            .await
            .expect("the retired path still carries its stream")
            .unwrap();
        assert_eq!(rest, b"part two");

        // 4. Inside the grace nothing is closed; past it, the retired path is.
        assert_eq!(a.retire_expired(), 0);
        now.fetch_add(31, Ordering::SeqCst);
        assert_eq!(a.retire_expired(), 1);
        assert_eq!(b.retire_expired(), 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(3), a_relayed.quinn().closed())
                .await
                .is_ok(),
            "the retired connection is closed after the grace"
        );
        assert_eq!(a.retiring_count(), 0);
        assert!(Arc::ptr_eq(&a.existing(&b_id).unwrap(), &a_primary));

        // 5. A *worse* newcomer never displaces: a second relayed dial is closed and the
        // direct primary kept — the rule that also settles a simultaneous dial.
        let again = a_ep
            .connect(circuit_addr(&b_id), b_id, 1_800_000_000)
            .await
            .expect("relayed again");
        let kept = a.adopt(again);
        assert!(Arc::ptr_eq(&kept, &a_primary));
        assert_eq!(a.retiring_count(), 0);
    }
}
