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
    /// - **PendingJoiner**: `join` and `rendezvous` only — exactly ADR-016's "for
    ///   the join stream only", plus the board it must publish its pre-join record
    ///   to.
    /// - **Unknown**: `rendezvous` only, gated further by the service's own policy
    ///   (ADR-012: reads open, member-only writes refused there).
    #[must_use]
    pub fn allows(class: PeerClass, kind: StreamKind) -> bool {
        match class {
            PeerClass::Member => true,
            PeerClass::Anchor => matches!(
                kind,
                StreamKind::Rendezvous | StreamKind::Sync | StreamKind::Coord
            ),
            PeerClass::PendingJoiner => {
                matches!(kind, StreamKind::Join | StreamKind::Rendezvous)
            }
            PeerClass::Unknown => matches!(kind, StreamKind::Rendezvous),
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

/// One QUIC connection per peer fingerprint (see the module docs).
pub struct ConnectionManager {
    endpoint: Arc<VoxEndpoint>,
    conns: Mutex<HashMap<Digest32, Arc<VoxConnection>>>,
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
        Self {
            endpoint,
            conns: Mutex::new(HashMap::new()),
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

    /// File a connection under its peer id, keeping the live one if a connection
    /// to that peer already exists (the newcomer is closed).
    fn file(&self, conn: VoxConnection) -> Arc<VoxConnection> {
        let peer = conn.peer_id();
        let mut map = lock(&self.conns);
        if let Some(existing) = map.get(&peer) {
            if is_live(existing) {
                let existing = Arc::clone(existing);
                drop(map);
                // A simultaneous dial from both sides: keep one, close the other
                // with a clean code rather than leaving two connections open.
                conn.close(WireError::AuthenticatorInvalid);
                return existing;
            }
        }
        let conn = Arc::new(conn);
        map.insert(peer, Arc::clone(&conn));
        conn
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
        let code = close_code(WireError::AuthenticatorInvalid);
        let _ = send.reset(code);
        let _ = recv.stop(code);
        return Err(Error::StreamRefused("peer may not open this stream kind"));
    }
    Ok((kind, send, recv))
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

        use StreamKind::{Coord, Join, Pairwise, Rendezvous, Sync, Tunnel};
        // A member may open anything; the log/consent gates do the real work.
        for k in [Sync, Join, Pairwise, Rendezvous, Tunnel, Coord] {
            assert!(PeerPolicy::allows(PeerClass::Member, k));
        }
        // An anchor stores, syncs and relays signalling — it has no channel
        // authority, so no join and no pairwise.
        for k in [Rendezvous, Sync, Coord] {
            assert!(PeerPolicy::allows(PeerClass::Anchor, k));
        }
        for k in [Join, Pairwise, Tunnel] {
            assert!(!PeerPolicy::allows(PeerClass::Anchor, k));
        }
        // ADR-016 exactly: a pending joiner gets the join stream (and the board it
        // must publish its pre-join record to) and nothing else.
        for k in [Join, Rendezvous] {
            assert!(PeerPolicy::allows(PeerClass::PendingJoiner, k));
        }
        for k in [Sync, Pairwise, Tunnel, Coord] {
            assert!(!PeerPolicy::allows(PeerClass::PendingJoiner, k));
        }
        // An unknown peer reaches the rendezvous service and nothing else.
        assert!(PeerPolicy::allows(PeerClass::Unknown, Rendezvous));
        for k in [Sync, Join, Pairwise, Tunnel, Coord] {
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
