//! V29-15 (#50) — **a duplicate that arrives over a second relay circuit is resolved the same way at
//! both ends, and what both ends keep is live.**
//!
//! The tie-break in `ConnectionManager::file` compares each end's own path classification before
//! it compares the shared TLS-exporter key. The classification was asked of the mux *at the moment
//! of comparison*: "is this connection's remote address a live circuit right now?". The mux holds
//! one circuit per peer, so attaching a second circuit to a peer detaches the first — and from then
//! on the first connection's address is not a circuit, and the connection read as **Direct**. It
//! is not direct. It is a relayed connection whose circuit is gone: nothing it sends leaves the
//! node. Against a newcomer on the fresh circuit (Relayed) the dead one won on "better path", at
//! both ends, and both ends went on opening streams into it until `SILENCE_IS_DEATH` promoted the
//! newcomer half a minute later.
//!
//! What this stages, over the in-process NAT simulator with both peers behind **symmetric** NATs
//! (so a circuit through the anchor is the only path): A reaches B through the anchor, both ends
//! hold that relayed connection, and then a **second** relayed dial lands between the same pair —
//! from B on even trials, from A on odd ones.
//!
//! And the product path that puts a second circuit between a pair: **a peer restarts** and reaches
//! back through the anchor. The far end still holds the old process's relayed connection, heard
//! from a moment ago, and the new process's circuit (same identity) detaches the old one's. Under
//! the old rule the dead connection read as Direct and the far end kept it while the restarted
//! peer held the new one — they disagreed, and the far end's requests went nowhere until
//! `SILENCE_IS_DEATH`.
//!
//! (A simultaneous `reach` from both ends was tried as a staging and does not reach this window
//! on the simulator: across 24 runs at offsets 0–160ms it converged with the fix and without it,
//! so it is not kept as a gate.)
//!
//! What it asserts, per trial and counted:
//! - both ends keep the **same** connection (equal exporter tags, computed at each end);
//! - that connection is **live**: a request opened on it from each end gets an answer;
//! - and, for the second-circuit staging, it was classified Relayed at both ends (never
//!   "Direct" for a circuit).
//!
//! Real QUIC, real handshakes, the real `NodeNet`/`ConnectionManager` and circuit code on all
//! three nodes. `#[ignore]`d in the debug suite; run it in release.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vnet::{NatKind, VirtualNet, VirtualSocket};
use vox_core::error::Error;
use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::circuitstream::connect_through;
use vox_core::node::coordstream::ask_observed;
use vox_core::node::net::{path_class, PathClass, PeerPolicy};
use vox_core::node::network::NodeNet;
use vox_core::transport::quic::{Admission, VoxConnection, VoxEndpoint};

const NOW: u64 = 1_800_000_000;

/// Trials. Each alternates which end dials the second circuit.
const TRIALS: usize = 12;

/// How long after the second dial the two ends are compared: long enough for any close to cross,
/// and far short of `SILENCE_IS_DEATH` (30s), which is the only thing that rescued the old rule.
const SETTLE: Duration = Duration::from_millis(1500);

/// A request on the kept connection must be answered within this, or the connection is dead.
const PROBE: Duration = Duration::from_secs(5);

fn signer(seed: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xC3; 32]).unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn clock() -> vox_core::time::Clock {
    Arc::new(|| NOW)
}

fn endpoints(a: SocketAddr) -> EndpointList {
    EndpointList::new(vec![Multiaddr::from(a)]).unwrap()
}

/// Both ends derive the same bytes from the same connection's TLS exporter, so equal tags mean the
/// **same** connection.
fn tag(conn: &VoxConnection) -> [u8; 8] {
    let mut out = [0u8; 8];
    conn.quinn()
        .export_keying_material(&mut out, b"vox/test/which-connection", b"")
        .expect("exporter");
    out
}

fn hex(t: [u8; 8]) -> String {
    t.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serve every stream on `conn` as the node does: coord, circuits and punches are handled inside
/// `accept_stream`.
fn serve_streams(net: Arc<NodeNet>, conn: Arc<VoxConnection>) {
    tokio::spawn(async move { while net.accept_stream(&conn).await.is_ok() {} });
}

/// The node's accept loop: handshakes off the loop, a retired loser still served.
fn run_node(net: Arc<NodeNet>) {
    tokio::spawn(async move {
        while let Some(incoming) = net.manager().accept_incoming().await {
            let net = Arc::clone(&net);
            tokio::spawn(async move {
                if let Ok(filed) = net
                    .manager()
                    .finish_incoming(incoming, Admission::AcceptAnyAuthenticated)
                    .await
                {
                    if let Some(loser) = filed.also_serve {
                        serve_streams(Arc::clone(&net), loser);
                    }
                    serve_streams(net, filed.kept);
                }
            });
        }
    });
}

fn node(seed: u8, sock: Arc<VirtualSocket>) -> Arc<NodeNet> {
    Arc::new(NodeNet::new(
        Arc::new(VoxEndpoint::bind_abstract(&signer(seed), sock).unwrap()),
        clock(),
    ))
}

fn members(net: &NodeNet, members: &[Digest32]) {
    let mut policy = PeerPolicy::new();
    policy.add_members(members.iter().copied());
    net.policy().replace(policy);
}

/// Whether a request opened on `conn` is answered. A `WHOAMI` on a relayed connection is refused
/// — the far end will not report a circuit address — and a refusal is an answer: it crossed the
/// connection and came back. Anything else (a timeout, a stream that could not open) is death.
async fn answers(conn: &VoxConnection) -> bool {
    match tokio::time::timeout(PROBE, ask_observed(conn)).await {
        Ok(Ok(_)) | Ok(Err(Error::HolePunchFailed(_))) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

/// What both ends hold once things settle, judged the same way for every staging.
struct Outcome {
    a_kept: [u8; 8],
    b_kept: [u8; 8],
    a_class: Option<PathClass>,
    b_class: Option<PathClass>,
    a_live: bool,
    b_live: bool,
}

impl Outcome {
    fn agree(&self) -> bool {
        self.a_kept == self.b_kept && self.a_kept != [0; 8]
    }
    fn live(&self) -> bool {
        self.a_live && self.b_live
    }
    fn relayed(&self) -> bool {
        self.a_class == Some(PathClass::Relayed) && self.b_class == Some(PathClass::Relayed)
    }
}

/// Three nodes on one simulated network: A and B behind their own symmetric NATs, anchor C
/// public, each serving streams as the node does, and each peer connected to C.
struct Scene {
    net: Arc<VirtualNet>,
    seed: u8,
    b_sock: Arc<VirtualSocket>,
    c_addr: SocketAddr,
    c_id: Digest32,
    a: Arc<NodeNet>,
    b: Arc<NodeNet>,
    c: Arc<NodeNet>,
    a_to_c: Arc<VoxConnection>,
    b_to_c: Arc<VoxConnection>,
    a_id: Digest32,
    b_id: Digest32,
}

impl Scene {
    async fn build(seed: u8) -> Self {
        let net = VirtualNet::new();
        let a_private = addr("10.0.1.2:5000");
        let b_private = addr("10.0.2.2:5000");
        let c_addr = addr("198.51.100.1:443");
        let a_sock = net.behind_nat(a_private, NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(b_private, NatKind::Symmetric, ip("203.0.113.2"));
        let c_sock = net.public(c_addr);
        let (a, b, c) = (
            node(seed, a_sock),
            node(seed.wrapping_add(1), Arc::clone(&b_sock)),
            node(seed.wrapping_add(2), c_sock),
        );
        let (a_id, b_id, c_id) = (a.local_id(), b.local_id(), c.local_id());
        members(&a, &[b_id, c_id]);
        members(&b, &[a_id, c_id]);
        members(&c, &[a_id, b_id]);
        run_node(Arc::clone(&a));
        run_node(Arc::clone(&b));
        run_node(Arc::clone(&c));
        let a_to_c = a
            .manager()
            .connect(c_id, &endpoints(c_addr))
            .await
            .expect("A reaches C");
        serve_streams(Arc::clone(&a), Arc::clone(&a_to_c));
        let b_to_c = b
            .manager()
            .connect(c_id, &endpoints(c_addr))
            .await
            .expect("B reaches C");
        serve_streams(Arc::clone(&b), Arc::clone(&b_to_c));
        for _ in 0..100 {
            if c.manager().peers().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(c.manager().peers().len(), 2, "the anchor holds both");
        Self {
            net,
            seed,
            b_sock,
            c_addr,
            c_id,
            a,
            b,
            c,
            a_to_c,
            b_to_c,
            a_id,
            b_id,
        }
    }

    /// B crashes and comes back **with the same identity** on another network: the old socket is
    /// cut first, so its QUIC close never leaves the box, exactly as a crashed process's would not.
    /// A is left holding its relayed connection to the old process, which still looks live.
    async fn restart_b(&mut self) {
        self.net.sever(&self.b_sock);
        self.b.manager().endpoint().close();
        let sock =
            self.net
                .behind_nat(addr("10.0.3.2:5000"), NatKind::Symmetric, ip("203.0.113.3"));
        let b = node(self.seed.wrapping_add(1), Arc::clone(&sock));
        assert_eq!(b.local_id(), self.b_id, "the same identity came back");
        members(&b, &[self.a_id, self.c_id]);
        run_node(Arc::clone(&b));
        let b_to_c = b
            .manager()
            .connect(self.c_id, &endpoints(self.c_addr))
            .await
            .expect("the restarted B reaches C");
        serve_streams(Arc::clone(&b), Arc::clone(&b_to_c));
        self.b = b;
        self.b_to_c = b_to_c;
        self.b_sock = sock;
    }

    /// Wait out [`SETTLE`], then read what each end holds and ask each held connection a question.
    async fn judge(&self) -> Outcome {
        tokio::time::sleep(SETTLE).await;
        let a_now = self.a.manager().existing(&self.b_id);
        let b_now = self.b.manager().existing(&self.a_id);
        let a_live = match &a_now {
            Some(c) => answers(c).await,
            None => false,
        };
        let b_live = match &b_now {
            Some(c) => answers(c).await,
            None => false,
        };
        Outcome {
            a_kept: a_now.as_ref().map(|c| tag(c)).unwrap_or_default(),
            b_kept: b_now.as_ref().map(|c| tag(c)).unwrap_or_default(),
            a_class: a_now
                .as_ref()
                .map(|c| path_class(self.a.manager().endpoint(), c)),
            b_class: b_now
                .as_ref()
                .map(|c| path_class(self.b.manager().endpoint(), c)),
            a_live,
            b_live,
        }
    }

    fn close(self) {
        for n in [&self.a, &self.b, &self.c] {
            n.manager().close_all();
            n.manager().endpoint().close();
        }
    }
}

/// A holds a relayed connection to B, both ends filed it, and then a second relayed dial lands
/// between the same pair — from B when `n` is even, from A when it is odd. Returns the outcome and
/// the first and second connections' tags.
async fn second_circuit(n: usize) -> (Outcome, [u8; 8], [u8; 8]) {
    let s = Scene::build(u8::try_from(3 * n + 7).unwrap()).await;
    let first =
        s.a.reach(s.b_id, &EndpointList::default())
            .await
            .expect("A reaches B via C");
    serve_streams(Arc::clone(&s.a), Arc::clone(&first));
    assert_eq!(
        path_class(s.a.manager().endpoint(), &first),
        PathClass::Relayed,
        "trial {n}: the first connection is a circuit"
    );
    let first_tag = tag(&first);
    for _ in 0..100 {
        if s.b
            .manager()
            .existing(&s.a_id)
            .is_some_and(|c| tag(&c) == first_tag)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        s.b.manager()
            .existing(&s.a_id)
            .is_some_and(|c| tag(&c) == first_tag),
        "trial {n}: B holds the first connection"
    );
    drop(first);

    // `connect_through` and then `adopt` is exactly `NodeNet::circuit_through`, split so the
    // newcomer's own tag is read before the filing decides whether to keep it.
    let (dialer, relay, target) = if n.is_multiple_of(2) {
        (&s.b, &s.b_to_c, s.a_id)
    } else {
        (&s.a, &s.a_to_c, s.b_id)
    };
    let second = connect_through(relay, target, dialer.manager().endpoint(), NOW)
        .await
        .expect("the second circuit dial completes");
    let second_tag = tag(&second);
    let kept = dialer.manager().adopt(second).await;
    serve_streams(Arc::clone(dialer), kept);

    let out = s.judge().await;
    s.close();
    (out, first_tag, second_tag)
}

/// A reaches B through the anchor, B **restarts**, and the restarted B reaches A back through the
/// anchor. A still holds the old connection, heard from a moment ago; the new one arrives on a new
/// circuit for the same identity, which detaches the old one's. Returns the outcome and the first
/// connection's tag.
async fn restarted_peer(n: usize) -> (Outcome, [u8; 8]) {
    let mut s = Scene::build(u8::try_from(3 * n + 101).unwrap()).await;
    let none = EndpointList::default();
    let first = s.a.reach(s.b_id, &none).await.expect("A reaches B via C");
    serve_streams(Arc::clone(&s.a), Arc::clone(&first));
    let first_tag = tag(&first);
    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;
    s.restart_b().await;
    let again =
        s.b.reach(s.a_id, &none)
            .await
            .expect("the restarted B reaches A via C");
    serve_streams(Arc::clone(&s.b), again);
    let out = s.judge().await;
    s.close();
    (out, first_tag)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
#[ignore = "12 three-node relayed scenes over symmetric NATs; run in release"]
fn a_second_circuit_between_one_pair_is_decided_alike_and_the_kept_one_is_live() {
    watchdog::arm();
    rt().block_on(async {
        let (mut disagree, mut dead, mut misclassed, mut kept_second) = (0, 0, 0, 0);
        for n in 0..TRIALS {
            let (o, first, second) = second_circuit(n).await;
            let which = |t: [u8; 8]| {
                if t == first {
                    "first"
                } else if t == second {
                    "second"
                } else if t == [0; 8] {
                    "none"
                } else {
                    "other"
                }
            };
            eprintln!(
                "[test] trial {n} ({} dialled second): A keeps {} ({}, {:?}, live={}), B keeps {} \
                 ({}, {:?}, live={})",
                if n.is_multiple_of(2) { "B" } else { "A" },
                hex(o.a_kept),
                which(o.a_kept),
                o.a_class,
                o.a_live,
                hex(o.b_kept),
                which(o.b_kept),
                o.b_class,
                o.b_live,
            );
            disagree += usize::from(!o.agree());
            dead += usize::from(!o.live());
            misclassed += usize::from(!o.relayed());
            kept_second += usize::from(o.a_kept == second && o.b_kept == second);
        }
        eprintln!(
            "[test] {TRIALS} trials: {disagree} disagreed, {dead} kept a dead connection at an end, \
             {misclassed} classified the kept circuit as not Relayed; both kept the second dial \
             {kept_second} times"
        );
        assert_eq!(disagree, 0, "{disagree}/{TRIALS} trials: the ends kept different connections");
        assert_eq!(dead, 0, "{dead}/{TRIALS} trials: an end kept a connection that does not answer");
        assert_eq!(
            misclassed, 0,
            "{misclassed}/{TRIALS} trials: a relayed connection was classified as something else"
        );
    });
}

/// Restarts staged by [`restarted_peer`].
const RESTARTS: usize = 6;

#[test]
#[ignore = "6 relayed peer restarts over symmetric NATs; run in release"]
fn a_restarted_peer_reaching_back_through_the_relay_is_kept_at_both_ends() {
    watchdog::arm();
    rt().block_on(async {
        let (mut disagree, mut dead, mut kept_old) = (0, 0, 0);
        for n in 0..RESTARTS {
            let (o, first) = restarted_peer(n).await;
            eprintln!(
                "[test] restart {n}: A keeps {}{} ({:?}, live={}), restarted B keeps {} ({:?}, \
                 live={})",
                hex(o.a_kept),
                if o.a_kept == first {
                    " = the old process's"
                } else {
                    ""
                },
                o.a_class,
                o.a_live,
                hex(o.b_kept),
                o.b_class,
                o.b_live
            );
            disagree += usize::from(!o.agree());
            dead += usize::from(!o.live());
            kept_old += usize::from(o.a_kept == first);
        }
        eprintln!(
            "[test] {RESTARTS} restarts: {disagree} disagreed, {dead} kept a dead connection at an \
             end, A kept the old process's connection {kept_old} times"
        );
        assert_eq!(
            disagree, 0,
            "{disagree}/{RESTARTS}: the ends kept different connections"
        );
        assert_eq!(
            dead, 0,
            "{dead}/{RESTARTS}: an end kept a connection that does not answer"
        );
    });
}
