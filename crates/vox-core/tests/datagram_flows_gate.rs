//! ADR-022 M22.1 — the datagram seam, over a real authenticated connection.
//!
//! Every datagram names a flow; one reader per connection routes it; a packet too big for
//! one datagram is fragmented and reassembled inside Vox; and whatever cannot be delivered
//! is dropped **and counted**, never delivered somewhere it does not belong and never
//! silently lost. Each case below asserts one of those, on two real `VoxEndpoint`s
//! handshaking over a [`VirtualNet`] whose path is shaped for the case.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use vnet::VirtualNet;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::datagram::{put_varint, CONTEXT_PACKET};
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use vox_core::transport::router::{DatagramFlow, DatagramStats};

const NOW: u64 = 1_800_000_000;
const WAIT: Duration = Duration::from_secs(10);

fn signer(seed: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0x66; 32]).unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// Two public hosts with one authenticated connection between them, and one flow bound
/// on a stream both ends share.
struct Pair {
    net: Arc<VirtualNet>,
    a: VoxConnection,
    b: VoxConnection,
    a_flow: DatagramFlow,
    b_flow: DatagramFlow,
    _endpoints: (Arc<VoxEndpoint>, Arc<VoxEndpoint>),
}

async fn pair(seed: u8, mtu: Option<usize>) -> Pair {
    let net = VirtualNet::new();
    // Set before the handshake, so the path is small from its first packet and QUIC's
    // path-MTU discovery learns the truth rather than a larger size it later loses.
    net.set_mtu(mtu);
    let a_addr: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let b_addr: SocketAddr = "198.51.100.2:443".parse().unwrap();
    let a_ep = Arc::new(VoxEndpoint::bind_abstract(&signer(seed), net.public(a_addr)).unwrap());
    let b_ep = Arc::new(VoxEndpoint::bind_abstract(&signer(seed + 1), net.public(b_addr)).unwrap());
    let accepting = {
        let b_ep = Arc::clone(&b_ep);
        tokio::spawn(async move { b_ep.accept(NOW).await })
    };
    let a = tokio::time::timeout(WAIT, a_ep.connect(b_addr, b_ep.local_id(), NOW))
        .await
        .expect("handshake did not hang")
        .expect("A reaches B");
    let b = accepting.await.unwrap().unwrap().expect("B accepted A");

    // The stream a flow is bound to: opened by A, seen by B once A has written to it.
    let (mut send, recv) = a.open_stream().await.unwrap();
    send.write_all(&[7]).await.unwrap();
    let (bs, mut br) = tokio::time::timeout(WAIT, b.accept_stream())
        .await
        .expect("B saw the stream")
        .unwrap();
    let mut first = [0u8; 1];
    br.read_exact(&mut first).await.unwrap();
    let a_flow = a.bind_flow(send, recv).unwrap();
    let b_flow = b.bind_flow(bs, br).unwrap();
    assert_eq!(
        a_flow.id(),
        b_flow.id(),
        "both ends must name the flow by the one stream they share"
    );
    Pair {
        net,
        a,
        b,
        a_flow,
        b_flow,
        _endpoints: (a_ep, b_ep),
    }
}

/// Wait until `f` holds for `conn`'s counters, or the deadline passes; returns the last
/// snapshot either way, so an assertion can print what it actually saw.
async fn stats_until(conn: &VoxConnection, f: impl Fn(&DatagramStats) -> bool) -> DatagramStats {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let s = conn.datagram_stats();
        if f(&s) || tokio::time::Instant::now() >= deadline {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A datagram with a flow ID and context written by hand, sent beneath the flow layer —
/// what a buggy or hostile peer could put on the wire.
fn raw(conn: &VoxConnection, flow: u64, context: u64, body: &[u8]) {
    let mut d = Vec::new();
    put_varint(&mut d, flow);
    put_varint(&mut d, context);
    d.extend_from_slice(body);
    conn.quinn().send_datagram(d.into()).unwrap();
}

/// **R26: a packet bigger than one datagram arrives whole.**
///
/// The path's MTU is 1280 bytes, so QUIC can never carry a datagram much above 1200: the
/// 1400-byte packets are the size of a WireGuard packet at MTU 1420 and the 4000-byte ones
/// are what a game or a media frame sends. Every one of them must arrive intact, in
/// fragments, and the counters must show it was fragmentation that did it.
///
/// Mutation-checked: with fragmentation disabled in the sender, every oversize packet is
/// dropped, and the sender's drop counter equals the number sent.
#[test]
fn oversize_packets_cross_a_small_path_in_fragments() {
    watchdog::arm();
    rt().block_on(async {
        let mut p = pair(10, Some(1280)).await;
        let whole = p.a_flow.max_whole_packet().expect("datagrams enabled");
        assert!(
            whole < 1400,
            "the path must be too small for a 1400-byte packet, or this proves nothing: {whole}"
        );

        const EACH: usize = 20;
        let mut sent = Vec::new();
        for size in [1400usize, 4000] {
            for i in 0..EACH {
                // Every byte depends on the packet and its position, so a fragment
                // swapped between packets, or reassembled out of order, cannot pass.
                let packet: Vec<u8> = (0..size)
                    .map(|j| (j as u8) ^ (i as u8).wrapping_mul(31) ^ (size as u8))
                    .collect();
                p.a_flow.send(&packet).unwrap();
                sent.push(packet);
                // Paced, so this measures fragmentation rather than the receive buffer.
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        let mut got = Vec::new();
        while got.len() < sent.len() {
            match tokio::time::timeout(Duration::from_secs(3), p.b_flow.recv()).await {
                Ok(Some(packet)) => got.push(packet),
                _ => break,
            }
        }
        let a_stats = p.a.datagram_stats();
        let b_stats = p.b.datagram_stats();
        eprintln!(
            "sent {} packets; received {}; sender fragmented {} and dropped {}; \
             receiver delivered {}, expired {}, evicted {}; path dropped {} too-big datagrams",
            sent.len(),
            got.len(),
            a_stats.fragmented,
            a_stats.send_dropped,
            b_stats.delivered,
            b_stats.reassembly_expired,
            b_stats.reassembly_evicted,
            p.net.too_big(),
        );
        assert_eq!(
            got.len(),
            sent.len(),
            "{} of {} oversize packets arrived; the sender dropped {} as unsendable",
            got.len(),
            sent.len(),
            a_stats.send_dropped
        );
        let intact = got.iter().filter(|g| sent.contains(g)).count();
        assert_eq!(intact, sent.len(), "every packet must arrive byte-for-byte");
        assert_eq!(
            a_stats.fragmented,
            sent.len() as u64,
            "every one of these packets is larger than a datagram, so every one must \
             have gone as fragments"
        );
        assert_eq!(a_stats.send_dropped, 0);
        assert_eq!(b_stats.reassembly_expired + b_stats.reassembly_evicted, 0);
    });
}

/// **A datagram for no flow, or for a flow that has ended, reaches nobody and is counted.**
///
/// Also: a flow ends by itself when its stream does. B dropping its end must end A's
/// without A doing anything, and A must then refuse to send on it.
///
/// Mutation-checked: with the stream watcher no longer ending the flow, A's flow stays open
/// after B's end is gone and the gate goes red.
#[test]
fn unknown_and_ended_flows_drop_and_count() {
    watchdog::arm();
    rt().block_on(async {
        let mut p = pair(20, None).await;
        let flow = p.a_flow.id();

        // A live flow delivers.
        p.a_flow.send(b"hello").unwrap();
        let hello = tokio::time::timeout(WAIT, p.b_flow.recv()).await.unwrap();
        assert_eq!(hello.as_deref(), Some(&b"hello"[..]));

        // 25 datagrams for a flow no stream was ever bound to.
        const UNKNOWN: u64 = 25;
        for i in 0..UNKNOWN {
            raw(&p.a, flow + 4 * (1000 + i), CONTEXT_PACKET, b"nobody's");
        }
        let s = stats_until(&p.b, |s| s.unknown_flow >= UNKNOWN).await;
        assert_eq!(
            s.unknown_flow, UNKNOWN,
            "every datagram for an unknown flow must be dropped and counted: {s:?}"
        );
        assert_eq!(s.delivered, 1, "and none of them delivered: {s:?}");

        // 5 on the live flow with a context this version does not define.
        for _ in 0..5 {
            raw(&p.a, flow, 7, b"future");
        }
        let s = stats_until(&p.b, |s| s.unknown_context >= 5).await;
        assert_eq!(s.unknown_context, 5, "{s:?}");
        assert_eq!(s.delivered, 1, "{s:?}");

        // B ends its side. A's flow must end with it, unprompted.
        drop(p.b_flow);
        let ended = tokio::time::timeout(Duration::from_secs(2), p.a_flow.recv()).await;
        assert!(
            matches!(ended, Ok(None)),
            "A's flow must end when the stream it is bound to ends: {ended:?}"
        );
        assert!(!p.a_flow.is_open(), "A's flow must report itself ended");
        assert!(
            p.a_flow.send(b"late").is_err(),
            "an ended flow must refuse to send"
        );

        // 25 more on the ended flow's ID, beneath the flow layer: dropped, counted.
        const ENDED: u64 = 25;
        for _ in 0..ENDED {
            raw(&p.a, flow, CONTEXT_PACKET, b"too late");
        }
        let s = stats_until(&p.b, |s| s.unknown_flow >= UNKNOWN + ENDED).await;
        eprintln!("receiver counters after the ended flow: {s:?}");
        assert_eq!(
            s.unknown_flow,
            UNKNOWN + ENDED,
            "datagrams for an ended flow must be dropped and counted: {s:?}"
        );
        assert_eq!(s.delivered, 1, "none of them delivered: {s:?}");
    });
}
