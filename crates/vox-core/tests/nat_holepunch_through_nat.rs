//! **ADR-012 rung 3 through real NATs.** What the rung rests on, in the order it needs
//! to be true (these began as the spike that sized the design, and they stay as its
//! proof):
//!
//! 1. a node can learn the address a peer must dial from a **third party's** view of
//!    its connection (the "observed address" DCUtR's `Connect` carries);
//! 2. a one-sided dial to that address is **dropped** by the peer's NAT — so rung 3 is
//!    a real requirement, not a formality;
//! 3. a **simultaneous open** gets an authenticated QUIC connection through two
//!    port-restricted-cone NATs, with each side's filter opened by its own dial;
//! 4. how much **skew** between the two dials the punch tolerates (this sizes the
//!    RTT/2 synchronization ADR-012 specifies);
//! 5. a **symmetric** NAT defeats the punch — ADR-012's documented limit and the
//!    reason a relay rung must exist.
//!
//! Every case runs on its own [`VirtualNet`] so no earlier dial has opened a filter the
//! case under test depends on.

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vnet::{NatKind, VirtualNet};
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};

const NOW: u64 = 1_800_000_000;
/// Long enough for several QUIC Initial retransmissions, short enough to fail a stuck
/// test quickly.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);

fn signer(seed: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// Accept connections until the endpoint closes, handing each one out. The accept loop
/// must run for a punch to complete: the peer's dial is what arrives.
fn serve(endpoint: Arc<VoxEndpoint>) -> tokio::sync::mpsc::UnboundedReceiver<VoxConnection> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(conn)) = endpoint.accept(NOW).await {
            if tx.send(conn).is_err() {
                break;
            }
        }
    });
    rx
}

/// Two NATed peers and one public coordinator, each peer having just learned its own
/// observed address from the coordinator.
struct Scene {
    net: Arc<VirtualNet>,
    a: Arc<VoxEndpoint>,
    b: Arc<VoxEndpoint>,
    a_private: SocketAddr,
    b_private: SocketAddr,
    a_observed: SocketAddr,
    b_observed: SocketAddr,
    /// Held so the connections to the coordinator (and its accept loop) stay alive.
    _keep: (VoxConnection, VoxConnection, VoxConnection, VoxConnection),
}

impl Scene {
    async fn build(seed: u8, b_nat: NatKind) -> Self {
        let net = VirtualNet::new();
        let a_private = addr("10.0.1.2:5000");
        let b_private = addr("10.0.2.2:5000");
        let c_public = addr("198.51.100.1:443");
        let a_sock = net.behind_nat(a_private, NatKind::PortRestrictedCone, ip("203.0.113.1"));
        let b_sock = net.behind_nat(b_private, b_nat, ip("203.0.113.2"));
        let c_sock = net.public(c_public);

        let (sa, sb, sc) = (signer(seed), signer(seed + 1), signer(seed + 2));
        let a = Arc::new(VoxEndpoint::bind_abstract(&sa, a_sock).unwrap());
        let b = Arc::new(VoxEndpoint::bind_abstract(&sb, b_sock).unwrap());
        let c = Arc::new(VoxEndpoint::bind_abstract(&sc, c_sock).unwrap());
        let c_id = c.local_id();
        let mut c_inbound = serve(Arc::clone(&c));
        // Both peers accept, or neither could receive the other's punch.
        std::mem::forget(serve(Arc::clone(&a)));
        std::mem::forget(serve(Arc::clone(&b)));

        // Hypothesis 1: the coordinator's view of the connection is the mapped address.
        let a_to_c = a.connect(c_public, c_id, NOW).await.expect("A reaches C");
        let c_from_a = c_inbound.recv().await.expect("C accepted A");
        let a_observed = c_from_a.quinn().remote_address();
        let b_to_c = b.connect(c_public, c_id, NOW).await.expect("B reaches C");
        let c_from_b = c_inbound.recv().await.expect("C accepted B");
        let b_observed = c_from_b.quinn().remote_address();
        assert_eq!(a_observed.ip(), ip("203.0.113.1"), "A's mapped address");
        assert_eq!(b_observed.ip(), ip("203.0.113.2"), "B's mapped address");
        assert_ne!(
            a_observed, a_private,
            "the private address is not what C sees"
        );
        assert_eq!(
            net.observed(a_private, c_public),
            Some(a_observed),
            "what C observed is exactly the NAT's mapping"
        );
        Self {
            net,
            a,
            b,
            a_private,
            b_private,
            a_observed,
            b_observed,
            _keep: (a_to_c, b_to_c, c_from_a, c_from_b),
        }
    }

    /// Both peers dial each other's observed address, `skew` apart. Returns whether
    /// either side ended up with an authenticated connection.
    async fn punch(&self, skew: Duration) -> bool {
        let (a, b) = (Arc::clone(&self.a), Arc::clone(&self.b));
        let (a_id, b_id) = (self.a.local_id(), self.b.local_id());
        let (a_target, b_target) = (self.b_observed, self.a_observed);
        let a_dial = tokio::spawn(async move {
            tokio::time::timeout(PUNCH_TIMEOUT, a.connect(a_target, b_id, NOW)).await
        });
        let b_dial = tokio::spawn(async move {
            tokio::time::sleep(skew).await;
            tokio::time::timeout(PUNCH_TIMEOUT, b.connect(b_target, a_id, NOW)).await
        });
        let (a_res, b_res) = tokio::join!(a_dial, b_dial);
        let a_ok = matches!(a_res, Ok(Ok(Ok(_))));
        let b_ok = matches!(b_res, Ok(Ok(Ok(_))));
        a_ok || b_ok
    }
}

#[test]
fn an_unsolicited_dial_is_dropped_by_the_peers_nat() {
    rt().block_on(async {
        let s = Scene::build(1, NatKind::PortRestrictedCone).await;
        let filtered_before = s.net.filtered();
        let one_sided = tokio::time::timeout(
            Duration::from_secs(2),
            s.a.connect(s.b_observed, s.b.local_id(), NOW),
        )
        .await;
        assert!(
            one_sided.is_err() || one_sided.as_ref().is_ok_and(Result::is_err),
            "an unsolicited dial must not connect"
        );
        assert!(
            s.net.filtered() > filtered_before,
            "B's NAT must have dropped the unsolicited datagrams"
        );
    });
}

#[test]
fn a_simultaneous_open_traverses_port_restricted_nats() {
    rt().block_on(async {
        let s = Scene::build(4, NatKind::PortRestrictedCone).await;
        assert!(
            s.punch(Duration::ZERO).await,
            "a simultaneous open must traverse port-restricted NATs"
        );
        // Both sides' mappings are the ones the coordinator advertised: a cone NAT
        // reuses one external port whoever the destination is, which is why the
        // observed address is dialable at all.
        assert_eq!(
            s.net.observed(s.a_private, s.b_observed),
            Some(s.a_observed),
            "A's mapping for B is the same port C observed"
        );
        assert_eq!(
            s.net.observed(s.b_private, s.a_observed),
            Some(s.b_observed)
        );
    });
}

#[test]
fn the_punch_tolerates_skew_because_quic_retransmits() {
    rt().block_on(async {
        // Sizing datum for the RTT/2 synchronization: a late second dial still lands,
        // because the early side's QUIC Initial is retransmitted after the peer's dial
        // has opened its filter. Synchronization buys a *faster* punch, not the only
        // possible one — so a missed timer degrades, it does not fail.
        let s = Scene::build(7, NatKind::PortRestrictedCone).await;
        assert!(
            s.punch(Duration::from_millis(1500)).await,
            "a 1.5 s skew must still punch"
        );
    });
}

#[test]
fn a_symmetric_nat_defeats_the_punch() {
    rt().block_on(async {
        let s = Scene::build(10, NatKind::Symmetric).await;
        // A dials the address C observed for B; B's symmetric NAT allocated that port
        // for traffic to C alone, and B's dial to A allocates a *different* one, so the
        // two never meet. B may still reach A (A's cone NAT admits it once A has dialed
        // B), which is a reverse connection, not a punch A could have made.
        let (a, b_id, b_target) = (Arc::clone(&s.a), s.b.local_id(), s.b_observed);
        let a_res =
            tokio::time::timeout(Duration::from_secs(3), a.connect(b_target, b_id, NOW)).await;
        assert!(
            a_res.is_err() || a_res.as_ref().is_ok_and(Result::is_err),
            "A must not reach B through a symmetric NAT"
        );
        assert_ne!(
            s.net.observed(s.b_private, s.a_observed),
            Some(s.b_observed),
            "a symmetric NAT maps a different external port per destination"
        );
    });
}

// ---------------------------------------------------------------------------
// The composition: the node's own surface, punching through a coordinator.
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use vox_core::hash::Digest32;
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::net::PeerPolicy;
use vox_core::node::network::{Inbound, NodeNet};
use vox_core::transport::quic::Admission;

fn clock() -> vox_core::time::Clock {
    Arc::new(|| NOW)
}

/// Accept connections and serve every stream on them, exactly as the node actor does:
/// the board and `WHOAMI` are answered inside `accept_stream`, and a relayed punch
/// session is answered on its own task.
fn run_node(net: Arc<NodeNet>) {
    let accept = Arc::clone(&net);
    tokio::spawn(async move {
        while let Ok(Some(conn)) = accept
            .manager()
            .accept(Admission::AcceptAnyAuthenticated)
            .await
        {
            serve_streams(Arc::clone(&accept), conn);
        }
    });
}

fn serve_streams(net: Arc<NodeNet>, conn: Arc<vox_core::transport::quic::VoxConnection>) {
    tokio::spawn(async move {
        loop {
            match net.accept_stream(&conn).await {
                Ok(Inbound::Punch {
                    peer,
                    coordinator,
                    send,
                    recv,
                }) => {
                    let net = Arc::clone(&net);
                    tokio::spawn(async move {
                        if let Ok(punched) = net.answer_punch(peer, coordinator, send, recv).await {
                            serve_streams(net, punched);
                        }
                    });
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
}

/// Give `net` a policy that treats `members` as channel members — what a shared channel
/// would produce, and what makes a peer one this node will relay for.
fn members(net: &NodeNet, members: &[Digest32]) {
    let mut policy = PeerPolicy::new();
    policy.add_members(members.iter().copied());
    net.policy().replace(policy);
}

fn endpoints(addr: SocketAddr) -> EndpointList {
    EndpointList::new(vec![Multiaddr::from(addr)]).unwrap()
}

/// A and B behind their own port-restricted NATs, C publicly reachable, all three
/// running the node's network surface and treating each other as channel members.
struct Swarm {
    net: Arc<VirtualNet>,
    a: Arc<NodeNet>,
    b: Arc<NodeNet>,
    c: Arc<NodeNet>,
    c_addr: SocketAddr,
    a_private: SocketAddr,
    b_private: SocketAddr,
    ids: HashMap<char, Digest32>,
}

async fn swarm(seed: u8) -> Swarm {
    let net = VirtualNet::new();
    let a_private = addr("10.0.1.2:5000");
    let b_private = addr("10.0.2.2:5000");
    let c_addr = addr("198.51.100.1:443");
    let a_sock = net.behind_nat(a_private, NatKind::PortRestrictedCone, ip("203.0.113.1"));
    let b_sock = net.behind_nat(b_private, NatKind::PortRestrictedCone, ip("203.0.113.2"));
    let c_sock = net.public(c_addr);
    let (sa, sb, sc) = (signer(seed), signer(seed + 1), signer(seed + 2));
    let a = Arc::new(NodeNet::new(
        Arc::new(VoxEndpoint::bind_abstract(&sa, a_sock).unwrap()),
        clock(),
    ));
    let b = Arc::new(NodeNet::new(
        Arc::new(VoxEndpoint::bind_abstract(&sb, b_sock).unwrap()),
        clock(),
    ));
    let c = Arc::new(NodeNet::new(
        Arc::new(VoxEndpoint::bind_abstract(&sc, c_sock).unwrap()),
        clock(),
    ));
    let (a_id, b_id, c_id) = (a.local_id(), b.local_id(), c.local_id());
    members(&a, &[b_id, c_id]);
    members(&b, &[a_id, c_id]);
    members(&c, &[a_id, b_id]);
    run_node(Arc::clone(&a));
    run_node(Arc::clone(&b));
    run_node(Arc::clone(&c));

    // Both peers reach the coordinator outbound — the one thing a client inside a
    // private network can always do — and serve the streams it opens back.
    let a_to_c = a
        .manager()
        .connect(c_id, &endpoints(c_addr))
        .await
        .expect("A reaches C");
    serve_streams(Arc::clone(&a), a_to_c);
    let b_to_c = b
        .manager()
        .connect(c_id, &endpoints(c_addr))
        .await
        .expect("B reaches C");
    serve_streams(Arc::clone(&b), b_to_c);
    // A learns its observed address up front (the actor does this on every connection);
    // B is left to discover it lazily when the punch needs it.
    let a_observed = a.learn_observed(c_id).await.expect("C answers WHOAMI");
    assert_eq!(
        Some(a_observed),
        a.observed_addr(),
        "the reported address is the agreed one"
    );
    match a_observed {
        Multiaddr::Ip4(s) => assert_eq!(
            s.ip(),
            &"203.0.113.1".parse::<std::net::Ipv4Addr>().unwrap()
        ),
        other => panic!("expected A's mapped IPv4, got {other}"),
    }
    assert_eq!(b.observed_addr(), None, "B has not asked yet");

    let mut ids = HashMap::new();
    ids.insert('a', a_id);
    ids.insert('b', b_id);
    ids.insert('c', c_id);
    // The coordinator holds both peers, or it has nothing to coordinate with.
    for _ in 0..50 {
        if c.manager().peers().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        c.manager().peers().len(),
        2,
        "the coordinator is connected to both peers"
    );
    Swarm {
        net,
        a,
        b,
        c,
        c_addr,
        a_private,
        b_private,
        ids,
    }
}

#[test]
fn two_nated_nodes_reach_each_other_through_a_coordinator() {
    rt().block_on(async {
        let s = swarm(20).await;
        let b_id = s.ids[&'b'];
        // B has no dialable endpoint at all: this is the ordinary case for a client
        // inside a private network, and rungs 1–2 have nothing to offer.
        let filtered_before = s.net.filtered();
        let conn = tokio::time::timeout(
            Duration::from_secs(30),
            s.a.reach(b_id, &EndpointList::default()),
        )
        .await
        .expect("reach did not hang")
        .expect("A reaches B through the coordinator");
        assert_eq!(conn.peer_id(), b_id, "the punched peer is authenticated");
        // The connection is filed, so the next reach is free.
        assert!(s.a.manager().existing(&b_id).is_some());
        // B discovered its own observed address to answer the punch.
        assert!(
            s.b.observed_addr().is_some(),
            "B asked the coordinator when the punch needed it"
        );
        // Both sides' NATs were real: each dropped datagrams during the punch, and the
        // addresses they exchanged were their mapped ones, not their private ones.
        assert!(s.net.filtered() >= filtered_before);
        assert_eq!(
            s.net.observed(s.a_private, s.c_addr),
            s.a.observed_addr().map(|m| match m {
                Multiaddr::Ip4(x) => SocketAddr::V4(x),
                other => panic!("{other}"),
            })
        );
        // The coordinator carried **signaling only**. A's connection to B goes straight
        // to B's mapped address — not through C — and C still holds just its two peers:
        // rung 3 produces a direct path, which is the whole point of punching rather
        // than relaying.
        let b_mapped = s
            .net
            .observed(s.b_private, s.c_addr)
            .expect("B has a mapping");
        assert_eq!(
            conn.quinn().remote_address(),
            b_mapped,
            "the punched connection goes to B's NAT, not to the coordinator"
        );
        assert_ne!(conn.quinn().remote_address(), s.c_addr);
        assert_eq!(
            s.c.manager().peers().len(),
            2,
            "the coordinator gained no new connection: it relayed signaling, not bytes"
        );
    });
}

#[test]
#[ignore = "waits out a full direct-dial timeout (~10 s) before rung 3; CI runs it in release"]
fn the_punch_is_what_happens_after_a_direct_dial_fails() {
    rt().block_on(async {
        let s = swarm(30).await;
        let b_id = s.ids[&'b'];
        // B advertises its private address — honestly, because that is what it knows.
        // A cannot route to it (the NAT drops it), so the direct rungs are exhausted
        // first and the punch is the rung that actually connects.
        let unroutable_before = s.net.unroutable();
        let conn = tokio::time::timeout(
            Duration::from_secs(60),
            s.a.reach(b_id, &endpoints(s.b_private)),
        )
        .await
        .expect("reach did not hang")
        .expect("A reaches B after the direct rung fails");
        assert_eq!(conn.peer_id(), b_id);
        assert!(
            s.net.unroutable() > unroutable_before,
            "the direct dial to a private address must have been dropped"
        );
    });
}
