//! ADR-022 M22.2 (PRD-001 R27) — a relayed path loses packets; it does not stall on them.
//!
//! Two nodes behind symmetric NATs can reach each other only through a relay (ADR-012
//! rung 4). Their connection is an ordinary QUIC connection whose packets the relay
//! carries. Until ADR-022 it carried them as frames on a **reliable stream**, so one outer
//! packet lost between an end and the relay held back every inner packet queued behind it
//! until the outer connection retransmitted it — the inner connection, built to recover
//! from loss on its own, saw a stall instead. For anything live over a relay (a call, a
//! game, `mosh`) that stall is the failure: late is worse than lost.
//!
//! The scene: A and B behind symmetric NATs, C their relay, 20 ms one way on every link,
//! and every 10th datagram A sends to C lost. Over the relayed A–B connection A sends a
//! numbered datagram every 10 ms on a datagram flow, and B timestamps each arrival.
//!
//! What must hold: B sees **loss** — some of the numbered datagrams never arrive, because
//! nothing retransmits them — and **no stall**: the longest gap between two arrivals stays
//! near two send intervals (one lost datagram), below the time an outer retransmission
//! takes (one A–C round trip plus loss detection, 60 ms and up here).
//!
//! Mutation-checked against the stream carriage it replaced: with the pre-ADR-022
//! `circuitstream.rs` restored, every datagram arrives (the outer stream retransmits the
//! lost ones) and the longest gap is a retransmission's length — the signature flips.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vnet::{NatKind, VirtualNet};
use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::net::PeerPolicy;
use vox_core::node::network::{Inbound, NodeNet};
use vox_core::transport::quic::{Admission, VoxEndpoint};
use vox_core::transport::streams::{open_typed, StreamKind};

const NOW: u64 = 1_800_000_000;

/// One way, on every link. The A–C round trip is then 40 ms, and so is C–B's.
const DELAY: Duration = Duration::from_millis(20);
/// Every Nth datagram from A to the relay is lost.
const LOSS_EVERY: u64 = 10;
/// A sends one numbered datagram this often...
const INTERVAL: Duration = Duration::from_millis(10);
/// ...this many times: four seconds of traffic, several dozen outer losses...
const COUNT: u32 = 400;
/// The first datagrams after the loss begins, sent and received but not measured.
///
/// When the loss starts, both connections' congestion windows fall from their initial
/// 12 000 bytes to the 2904-byte floor within about half a second. On the step that lands
/// on the floor the outer connection briefly has more in flight than its new window, and
/// holds datagrams for up to one A–C round trip (measured: one gap of 40–45 ms, around
/// the 30th datagram, in roughly half the runs, with every datagram delayed and none
/// stalled behind a lost one). That is congestion control reacting to a new loss rate, and
/// it happens once; stream carriage stalls on *every* loss, for as long as the path is
/// lossy. So the claim is measured on the path once its loss rate is established.
const WARMUP: u32 = 100;
/// ...of this many bytes.
///
/// The rate is kept inside what the *inner* connection's congestion control allows at its
/// floor, so this measures how the relay carries packets and not how two nested congestion
/// controllers react to 10% loss. Both collapse to their minimum window (2 × 1452 bytes)
/// under this loss; at 200 datagrams a second the inner one is then the bottleneck and
/// holds datagrams back for tens of milliseconds on its own — ADR-022's "nested congestion
/// control" consequence, real but not what R27 is about. At 100 a second of 32 bytes it
/// never binds, and a gap can only be a lost datagram or a stall.
const PAYLOAD: usize = 32;
/// The longest gap between two arrivals B may see. A lost datagram costs one interval
/// (a 20 ms gap) and a little scheduling jitter on top; an outer retransmission costs at
/// least the A–C round trip (40 ms) plus loss detection. Anything past this is a stall.
const MAX_GAP: Duration = Duration::from_millis(40);

fn signer(seed: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap()
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

type Handoff = tokio::sync::mpsc::UnboundedSender<(Digest32, quinn::SendStream, quinn::RecvStream)>;

/// Accept connections and serve every stream on them as the node actor does: circuits are
/// served inside `accept_stream`, and a `sync` stream is handed up.
fn run_node(net: Arc<NodeNet>, handoff: Option<Handoff>) {
    let accept = Arc::clone(&net);
    tokio::spawn(async move {
        while let Ok(Some(conn)) = accept
            .manager()
            .accept(Admission::AcceptAnyAuthenticated)
            .await
        {
            serve_streams(Arc::clone(&accept), conn, handoff.clone());
        }
    });
}

fn serve_streams(
    net: Arc<NodeNet>,
    conn: Arc<vox_core::transport::quic::VoxConnection>,
    handoff: Option<Handoff>,
) {
    tokio::spawn(async move {
        loop {
            match net.accept_stream(&conn).await {
                Ok(Inbound::Sync {
                    peer, send, recv, ..
                }) => {
                    if let Some(h) = &handoff {
                        let _ = h.send((peer, send, recv));
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
}

fn members(net: &NodeNet, members: &[Digest32]) {
    let mut policy = PeerPolicy::new();
    policy.add_members(members.iter().copied());
    net.policy().replace(policy);
}

fn endpoints(addr: SocketAddr) -> EndpointList {
    EndpointList::new(vec![Multiaddr::from(addr)]).unwrap()
}

/// What B saw.
struct Measured {
    sent: u32,
    received: usize,
    max_gap: Duration,
    /// The longest gap while the congestion controllers settled; reported, not bounded.
    warmup_max_gap: Duration,
    /// The five longest gaps: (gap, sequence before, sequence after).
    longest: Vec<(Duration, u32, u32)>,
    /// The inner connection's congestion window and congestion events at the end.
    inner_cwnd: u64,
    inner_congestion_events: u64,
    /// Outer datagrams the path lost between A and the relay.
    lost_outer: u64,
    /// Datagrams the relay took off A's leg and put on B's.
    relay_in: u64,
    relay_out: u64,
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// A and B behind symmetric NATs, C their relay, all three running the node's network
/// surface; A has reached B, and the only path there is a circuit through C.
struct Scene {
    net: Arc<VirtualNet>,
    a: Arc<NodeNet>,
    b: Arc<NodeNet>,
    c: Arc<NodeNet>,
    a_private: SocketAddr,
    c_addr: SocketAddr,
    a_id: Digest32,
    b_id: Digest32,
    /// A's connection to B, over the circuit.
    conn: Arc<vox_core::transport::quic::VoxConnection>,
    /// The `sync` streams B's node loop handed up.
    b_inbound:
        tokio::sync::mpsc::UnboundedReceiver<(Digest32, quinn::SendStream, quinn::RecvStream)>,
}

/// Build the scene. `shape` sees the network before any host sends a packet, so a
/// path's delay or MTU is true of every connection from its first handshake.
async fn relayed(seed: u8, shape: impl FnOnce(&VirtualNet, SocketAddr)) -> Scene {
    let net = VirtualNet::new();
    let a_private = addr("10.0.1.2:5000");
    let b_private = addr("10.0.2.2:5000");
    let c_addr = addr("198.51.100.1:443");
    shape(&net, b_private);
    let a_sock = net.behind_nat(a_private, NatKind::Symmetric, ip("203.0.113.1"));
    let b_sock = net.behind_nat(b_private, NatKind::Symmetric, ip("203.0.113.2"));
    let c_sock = net.public(c_addr);
    let node = |seed: u8, sock| {
        Arc::new(NodeNet::new(
            Arc::new(VoxEndpoint::bind_abstract(&signer(seed), sock).unwrap()),
            clock(),
        ))
    };
    let (a, b, c) = (
        node(seed, a_sock),
        node(seed + 1, b_sock),
        node(seed + 2, c_sock),
    );
    let (a_id, b_id, c_id) = (a.local_id(), b.local_id(), c.local_id());
    members(&a, &[b_id, c_id]);
    members(&b, &[a_id, c_id]);
    members(&c, &[a_id, b_id]);
    let (b_handoff, b_inbound) = tokio::sync::mpsc::unbounded_channel();
    run_node(Arc::clone(&a), None);
    run_node(Arc::clone(&b), Some(b_handoff));
    run_node(Arc::clone(&c), None);
    let a_to_c = a.manager().connect(c_id, &endpoints(c_addr)).await.unwrap();
    serve_streams(Arc::clone(&a), a_to_c, None);
    let b_to_c = b.manager().connect(c_id, &endpoints(c_addr)).await.unwrap();
    serve_streams(Arc::clone(&b), b_to_c, None);
    for _ in 0..100 {
        if c.manager().peers().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(c.manager().peers().len(), 2, "the relay holds both peers");

    // Symmetric NATs on both sides: the relay is the only path.
    let conn = tokio::time::timeout(
        Duration::from_secs(60),
        a.reach(b_id, &EndpointList::default()),
    )
    .await
    .expect("reach did not hang")
    .expect("A reaches B through the relay");
    assert_eq!(
        a.manager().endpoint().circuit_addr_of(&b_id),
        Some(conn.quinn().remote_address()),
        "A's connection to B must run over a circuit, or this measures a direct path"
    );
    assert_eq!(c.relaying(), 1, "the relay carries the circuit");
    Scene {
        net,
        a,
        b,
        c,
        a_private,
        c_addr,
        a_id,
        b_id,
        conn,
        b_inbound,
    }
}

async fn measure(seed: u8) -> Measured {
    // Latency from the first packet, so every connection's RTT estimate is the path's
    // from the start. Switched on mid-connection instead, a 0.1 ms estimate meeting a
    // 40 ms path declares packets lost that are only late, and the spurious congestion
    // that follows is measured as if the relay caused it.
    let Scene {
        net,
        a: _a,
        b,
        c,
        a_private,
        c_addr,
        a_id,
        b_id,
        conn,
        mut b_inbound,
    } = relayed(seed, |net, _| net.set_delay(DELAY)).await;

    // A datagram flow on the relayed connection, bound to a stream B's node hands up.
    let (send, recv) = open_typed(&conn, StreamKind::Sync).await.unwrap();
    let (peer, bs, br) = tokio::time::timeout(Duration::from_secs(30), b_inbound.recv())
        .await
        .expect("B's loop handed the stream up")
        .expect("harness alive");
    assert_eq!(peer, a_id);
    let b_conn = b
        .manager()
        .existing(&a_id)
        .expect("B holds A's relayed connection");
    let a_flow = conn.bind_flow(send, recv).unwrap();
    let mut b_flow = b_conn.bind_flow(bs, br).unwrap();

    // Now the path turns bad: loss on A's leg to the relay.
    net.set_loss(a_private, c_addr, LOSS_EVERY);
    let lost_before = net.lost();

    let receiver = tokio::spawn(async move {
        let mut arrivals: Vec<(u32, Instant)> = Vec::new();
        // Ends when nothing has arrived for a second after the traffic.
        while let Ok(Some(d)) = tokio::time::timeout(Duration::from_secs(1), b_flow.recv()).await {
            let seq = u32::from_be_bytes(d[..4].try_into().unwrap());
            arrivals.push((seq, Instant::now()));
        }
        arrivals
    });
    let mut tick = tokio::time::interval(INTERVAL);
    for seq in 0..WARMUP + COUNT {
        tick.tick().await;
        let mut d = seq.to_be_bytes().to_vec();
        d.resize(PAYLOAD, 0xAB);
        a_flow.send(&d).unwrap();
    }
    let (warmup, arrivals): (Vec<_>, Vec<_>) = receiver
        .await
        .unwrap()
        .into_iter()
        .partition(|(seq, _)| *seq < WARMUP);
    let warmup_max_gap = warmup
        .windows(2)
        .map(|w| w[1].1.duration_since(w[0].1))
        .max()
        .unwrap_or_default();
    // Every gap between consecutive arrivals, with the sequence numbers either side, so
    // a failure shows whether the long gap spans a loss (seq jumps) or a stall (it does
    // not).
    let mut gaps: Vec<(Duration, u32, u32)> = arrivals
        .windows(2)
        .map(|w| (w[1].1.duration_since(w[0].1), w[0].0, w[1].0))
        .collect();
    gaps.sort_by(|x, y| y.0.cmp(&x.0));
    gaps.truncate(5);
    let inner = conn.quinn().stats().path;
    let relay_leg_a = c
        .manager()
        .existing(&a_id)
        .expect("C holds A")
        .datagram_stats();
    let relay_leg_b = c
        .manager()
        .existing(&b_id)
        .expect("C holds B")
        .datagram_stats();
    drop((a_flow, conn));
    Measured {
        sent: COUNT,
        received: arrivals.len(),
        max_gap: gaps.first().map_or(Duration::MAX, |g| g.0),
        warmup_max_gap,
        longest: gaps,
        inner_cwnd: inner.cwnd,
        inner_congestion_events: inner.congestion_events,
        lost_outer: net.lost() - lost_before,
        relay_in: relay_leg_a.delivered,
        relay_out: relay_leg_b.sent,
    }
}

#[test]
#[ignore = "two seconds of shaped relay traffic on top of a relayed dial; CI runs it in the release step"]
fn a_lossy_relay_leg_loses_packets_instead_of_stalling_them() {
    watchdog::arm();
    let m = rt().block_on(measure(60));
    let lost = m.sent as usize - m.received;
    eprintln!(
        "relay leg lost {} outer datagrams; B received {}/{} (lost {lost}); longest gap \
         between arrivals {:?} (bound {MAX_GAP:?}; {:?} during the warm-up); five longest (gap, seq before, seq \
         after): {:?}; inner cwnd {} after {} congestion events; the relay moved {} \
         datagrams in from A and {} out to B",
        m.lost_outer,
        m.received,
        m.sent,
        m.max_gap,
        m.warmup_max_gap,
        m.longest,
        m.inner_cwnd,
        m.inner_congestion_events,
        m.relay_in,
        m.relay_out
    );
    assert!(
        m.lost_outer > 0,
        "the relay leg lost nothing, so this measured a clean path"
    );
    assert!(
        m.max_gap < MAX_GAP,
        "B waited {:?} between two arrivals — a stall behind a retransmission, not a loss \
         ({}/{} received, {} outer datagrams lost)",
        m.max_gap,
        m.received,
        m.sent,
        m.lost_outer
    );
    assert!(
        lost > 0,
        "every datagram arrived although {} outer datagrams were lost: something \
         retransmitted them, which is stream carriage, not datagram carriage",
        m.lost_outer
    );
    assert!(
        m.received * 10 >= m.sent as usize * 8,
        "the circuit must keep flowing under loss: only {}/{} arrived",
        m.received,
        m.sent
    );
    assert!(
        m.relay_in > 0 && m.relay_out > 0,
        "the relay must have carried the circuit as datagrams: {} in, {} out",
        m.relay_in,
        m.relay_out
    );
}

/// **A circuit whose two legs carry different datagram sizes still works.**
///
/// Each end knows only its own leg to the relay, and the relay forwards a datagram as it
/// is. Here A's leg has grown to the 1452-byte QUIC maximum by path-MTU discovery while B
/// sits on a link that carries 1200 bytes, QUIC's floor. A datagram sized for A's leg
/// would be dropped on B's; since the inner handshake's Initial packets are 1200 bytes,
/// the circuit would never come up at all. The ends therefore send nothing larger than
/// `CIRCUIT_DATAGRAM_MAX`, fragmenting to fit, which every QUIC path carries.
///
/// Mutation-checked: with the ends no longer capping their datagrams, the inner handshake
/// dies at the relay and `reach` fails.
#[test]
#[ignore = "a relayed dial and a 64 KiB round trip; CI runs it in the release step"]
fn a_circuit_crosses_legs_of_different_datagram_sizes() {
    watchdog::arm();
    rt().block_on(async {
        let mut s = relayed(70, |net, b_private| net.set_host_mtu(b_private, 1200)).await;
        let c_to_a = s.c.manager().existing(&s.a_id).expect("C holds A");
        let c_to_b = s.c.manager().existing(&s.b_id).expect("C holds B");
        let (a_leg, b_leg) = (
            c_to_a.quinn().max_datagram_size().unwrap(),
            c_to_b.quinn().max_datagram_size().unwrap(),
        );
        assert!(
            a_leg > 1200 && b_leg < 1200,
            "the legs must differ across the inner Initial's size, or this proves nothing: \
             A's leg {a_leg}, B's leg {b_leg}"
        );

        let (mut send, mut recv) = open_typed(&s.conn, StreamKind::Sync).await.unwrap();
        let (_, mut bs, mut br) = tokio::time::timeout(Duration::from_secs(30), s.b_inbound.recv())
            .await
            .expect("B's loop handed the stream up")
            .expect("harness alive");
        let echo = tokio::spawn(async move {
            let got = br.read_to_end(1 << 20).await.unwrap();
            bs.write_all(&got).await.unwrap();
            bs.finish().unwrap();
        });
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(30), recv.read_to_end(1 << 20))
            .await
            .expect("echo did not hang")
            .unwrap();
        echo.await.unwrap();
        let (to_a, to_b) = (c_to_a.datagram_stats(), c_to_b.datagram_stats());
        eprintln!(
            "A's leg {a_leg} bytes, B's leg {b_leg}; 64 KiB echoed {}; relay sent {} to A \
             and {} to B, dropped {} and {} as too large; path dropped {} datagrams too big",
            echoed == payload,
            to_a.sent,
            to_b.sent,
            to_a.send_dropped,
            to_b.send_dropped,
            s.net.too_big(),
        );
        assert_eq!(
            echoed, payload,
            "64 KiB round-tripped through the relay intact"
        );
        assert_eq!(
            to_a.send_dropped + to_b.send_dropped,
            0,
            "the relay must never have to drop a datagram for its size"
        );
        drop((s.a, s.b));
    });
}
