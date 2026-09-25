//! PRD-001 R41's transport settings, proved on real Vox endpoints over real loopback sockets.
//!
//! 1. **Path-MTU discovery reaches the ceiling this host can carry, and never falls below
//!    quinn's.** The 8192 ceiling needs two settings, not one: the discovery ceiling
//!    (`MtuDiscoveryConfig::upper_bound`) and the largest UDP payload this endpoint *advertises*
//!    (`EndpointConfig::max_udp_payload_size`). quinn searches only up to the smaller of our
//!    ceiling and the peer's advertised maximum, whose default is 1472, so raising one alone
//!    leaves every path at 1452 or 1472. The ceiling is taken only when the OS granted the
//!    receive buffer 8192-byte bursts need (`quic::mtu_ceiling_for`). Linux caps it silently
//!    at `net.core.rmem_max`, so there the endpoint keeps quinn's 1452. Either way the proof
//!    reads quinn's own path statistics after a bulk transfer: the path is at the endpoints'
//!    ceiling (above 1472 when that is 8192, at least 1452 otherwise), with no black hole.
//! 2. **One peer cannot park more than [`CONNECTION_WINDOW`] in this node's memory.** With a
//!    16 MiB stream window and quinn's default of 100 concurrent streams, an unlimited
//!    connection window let a peer that writes into streams nobody reads fill 1.6 GiB. Here a
//!    peer opens 100 streams and pushes 1 MiB into each (100 MiB offered) at a receiver that
//!    accepts the streams and never reads them. What crosses the wire must stay within the
//!    connection window.
//!
//! Mutations: drop `max_udp_payload_size` and (1) goes red at 1472. Take the 8192 ceiling on a
//! buffer too small for it (the pre-fix behaviour) and (1) goes red with a black hole and the
//! path at 1200. Drop the connection `receive_window` and (2) goes red with ~100 MiB received.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::{
    VoxConnection, VoxEndpoint, CONNECTION_WINDOW, DEFAULT_UDP_PAYLOAD, MAX_UDP_PAYLOAD,
};

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0x5A; 32]).unwrap()
}

/// A connected pair on loopback: (dialler's connection, acceptor's connection).
async fn pair(a: u8, b: u8) -> (VoxConnection, VoxConnection, VoxEndpoint, VoxEndpoint) {
    let dialler = VoxEndpoint::bind(&signer(a), "127.0.0.1:0".parse().unwrap()).unwrap();
    let acceptor = VoxEndpoint::bind(&signer(b), "127.0.0.1:0".parse().unwrap()).unwrap();
    let (addr, id) = (acceptor.local_addr().unwrap(), acceptor.local_id());
    let accepting = tokio::spawn(async move {
        let conn = acceptor.accept(1_000).await;
        (conn, acceptor)
    });
    let out = dialler.connect(addr, id, 1_000).await.unwrap();
    let (inn, acceptor) = accepting.await.unwrap();
    (out, inn.unwrap().unwrap(), dialler, acceptor)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_mtu_discovery_reaches_the_ceiling_on_loopback() {
    /// quinn's default advertised maximum UDP payload. Above it proves both settings took: with
    /// the ceiling raised but the advertised maximum left alone, discovery stops exactly here.
    const PEER_DEFAULT: u16 = 1472;
    let (out, inn, d, a) = pair(1, 2).await;
    let ceiling = d.mtu_ceiling().min(a.mtu_ceiling());
    // The floor the path must reach: past the peer default when the larger ceiling is in force
    // (proving both settings took), else quinn's own ceiling.
    let reached = |m: u16| {
        if ceiling == MAX_UDP_PAYLOAD {
            m > PEER_DEFAULT
        } else {
            m >= DEFAULT_UDP_PAYLOAD
        }
    };
    // Traffic, so discovery has packets to probe with.
    let reader = tokio::spawn(async move {
        let (_send, mut recv) = inn.accept_stream().await.unwrap();
        let mut n = 0usize;
        let mut buf = vec![0u8; 1 << 16];
        while let Ok(Some(k)) = recv.read(&mut buf).await {
            n += k;
        }
        (n, inn)
    });
    let (mut send, _recv) = out.open_stream().await.unwrap();
    let chunk = vec![0x42u8; 1 << 16];
    for _ in 0..(32 << 20) / chunk.len() {
        send.write_all(&chunk).await.unwrap();
    }
    send.finish().unwrap();
    let (got, inn) = reader.await.unwrap();
    assert_eq!(got, 32 << 20, "the transfer arrived whole");
    // Discovery runs alongside; give it a moment to finish its search.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut mtu = (0, 0);
    while Instant::now() < deadline {
        mtu = (
            out.quinn().stats().path.current_mtu,
            inn.quinn().stats().path.current_mtu,
        );
        if reached(mtu.0) && reached(mtu.1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let holes = (
        out.quinn().stats().path.black_holes_detected,
        inn.quinn().stats().path.black_holes_detected,
    );
    eprintln!(
        "path MTU after 32 MiB: dialler {} bytes, acceptor {} bytes (endpoint ceilings {} / {}); \
         black holes detected {} / {}",
        mtu.0,
        mtu.1,
        d.mtu_ceiling(),
        a.mtu_ceiling(),
        holes.0,
        holes.1
    );
    assert_eq!(
        holes,
        (0, 0),
        "quinn declared a black hole on loopback (path now {mtu:?}): the ceiling ({ceiling}) is \
         larger than this socket's receive buffer can take in a burst"
    );
    assert!(
        reached(mtu.0) && reached(mtu.1),
        "path-MTU discovery stopped at {mtu:?} on loopback with a ceiling of {ceiling}: \
         the ceiling was not raised on both the discovery side and the advertised maximum UDP \
         payload, or the path fell below quinn's own {DEFAULT_UDP_PAYLOAD}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_cannot_park_more_than_the_connection_window() {
    /// quinn's default concurrent bidirectional stream limit, which Vox does not change.
    const STREAMS: usize = 100;
    const PER_STREAM: usize = 1 << 20;
    let (out, inn, _d, _a) = pair(3, 4).await;
    let inn = Arc::new(inn);

    // The receiver accepts every stream and reads nothing, and keeps them open.
    let held = {
        let inn = Arc::clone(&inn);
        tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Ok(pair) = inn.accept_stream().await {
                kept.push(pair);
                if kept.len() == STREAMS {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
            drop(kept);
        })
    };
    let rx_before = inn.quinn().stats().udp_rx.bytes;

    let out = Arc::new(out);
    let mut writers = Vec::new();
    let mut opened = 0usize;
    for _ in 0..STREAMS {
        let Ok(Ok((mut send, recv))) =
            tokio::time::timeout(Duration::from_secs(5), out.open_stream()).await
        else {
            break;
        };
        opened += 1;
        writers.push(tokio::spawn(async move {
            let _recv = recv;
            let data = vec![0x17u8; PER_STREAM];
            let _ = send.write_all(&data).await;
            // Blocked on credit is the expected state; hold the stream open.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }));
    }
    // Long enough for everything the credit allows to cross, several times over.
    let mut last = 0;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now = inn.quinn().stats().udp_rx.bytes - rx_before;
        if now == last && now > 0 {
            break;
        }
        last = now;
    }
    let received = inn.quinn().stats().udp_rx.bytes - rx_before;
    let offered = (opened * PER_STREAM) as u64;
    // Headers, ACK frames and packet overhead ride on top of the stream bytes the window counts.
    let bound = u64::from(CONNECTION_WINDOW) + u64::from(CONNECTION_WINDOW) / 10;
    eprintln!(
        "{opened} streams opened, {offered} bytes offered, {received} bytes received by a reader \
         that reads nothing (connection window {CONNECTION_WINDOW}, bound with overhead {bound})"
    );
    for w in writers {
        w.abort();
    }
    held.abort();
    assert_eq!(opened, STREAMS, "every stream the limit allows was opened");
    assert!(
        received >= u64::from(CONNECTION_WINDOW) / 2,
        "only {received} bytes crossed: the peer never pushed enough to test the bound"
    );
    assert!(
        received <= bound,
        "one peer parked {received} bytes in a reader that reads nothing, beyond the connection \
         window's {CONNECTION_WINDOW} (+10% overhead)"
    );
}
