//! V030-35 D4 (#402) — **two nodes in one process keep their own tunnel state** (ADR-026 P-1).
//!
//! A process may host several nodes. The tunnel registries, the finishing count, the stuck-after
//! setting and the mux's circuit tables used to be one per process, which was right only while a
//! process was one node. Each is now filed under its node, and this gate drives two nodes, `A`
//! and `B`, side by side in one process, each on its own endpoint, against real QUIC peers on
//! loopback:
//!
//! 1. **A lists and closes only its own tunnels.** A's list holds A's tunnel and not B's; A
//!    closing by B's member prefix, or by B's tunnel number, closes nothing of B's; A closing its
//!    own by number closes it, and only A's closed list then shows it.
//! 2. **A's stuck tunnel closes by A's setting while B's lives.** A gives a stuck tunnel 2 s, B
//!    600 s. Both tunnels have bytes waiting for an application that reads nothing: A's is closed
//!    as stuck in about 2 s, B's is still live after it.
//! 3. **A's stop does not wait for B's finishing tunnel.** B's tunnel has sent its last bytes to
//!    a peer that is frozen, so it waits for an acknowledgement (up to 10 s). A waiting for its
//!    own tunnels to be acknowledged returns at once; B waiting for its own does not.
//! 4. **Two nodes hold circuits to one peer without collision, and a circuit is answered only by
//!    its own node** (Tr4). On one shared mux, A and B each attach a circuit to the same peer `X`:
//!    two addresses, each found under its own node; dropping A's leaves B's. A circuit of A's is
//!    not one B may answer on.
//!
//! In-process, not the shipped binary: today's binary runs one node per process, so two nodes in
//! one process exist only here until the daemon hosts them (ADR-026 §10 proof 4 is the
//! real-binary form, after D5/D6).
//!
//! **Which side a red is on.** A node seeing, closing, timing out or waiting on another node's
//! state is `PRODUCT:`. A premise that did not hold (B's tunnel not finishing, a peer that would
//! not connect) is `APPARATUS:` / `CANNOT MEASURE`.
//!
//! Mutants (each reverted after): remove the owner filter in `close_tunnels` → red on 1;
//! `LocalNode::stuck_after` read from one process-wide value → red on 2; one global finishing
//! counter → red on 3; `MuxSocket::serves_on` without the owner check → red on 4.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};

use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::{
    close_tunnels, closed_tunnels, live_tunnels, unix_now, TunnelSelector, VoxConnection,
    VoxEndpoint,
};
use vox_core::tunnel::session;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback")
}

fn signer() -> Arc<SoftwareRootSigner> {
    Arc::new(SoftwareRootSigner::generate().expect("APPARATUS: generate an identity"))
}

/// A peer endpoint accepting on loopback; every connection it accepts is sent to the caller.
fn host(ep: Arc<VoxEndpoint>) -> tokio::sync::mpsc::UnboundedReceiver<VoxConnection> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(conn)) = ep.accept(unix_now()).await {
            if tx.send(conn).is_err() {
                break;
            }
        }
    });
    rx
}

/// `local` dials `peer` and both ends' connections come back: (local's, peer's).
async fn connect(
    local: &VoxEndpoint,
    peer: &VoxEndpoint,
    accepted: &mut tokio::sync::mpsc::UnboundedReceiver<VoxConnection>,
) -> (VoxConnection, VoxConnection) {
    let addr = peer.local_addr().expect("APPARATUS: peer address");
    let mine = tokio::time::timeout(
        Duration::from_secs(10),
        local.connect(addr, peer.local_id(), unix_now()),
    )
    .await
    .expect("APPARATUS: the dial did not finish in 10 s")
    .expect("APPARATUS: the dial failed");
    let theirs = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
        .await
        .expect("APPARATUS: the peer accepted nothing in 10 s")
        .expect("APPARATUS: the peer's accept loop ended");
    (mine, theirs)
}

/// A loopback TCP pair: (the end the splice holds, the application's end).
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(loopback())
        .await
        .expect("APPARATUS: bind tcp");
    let addr = listener.local_addr().expect("APPARATUS: tcp address");
    let (app, spliced) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (
        spliced.expect("APPARATUS: tcp accept").0,
        app.expect("APPARATUS: tcp connect"),
    )
}

fn member_prefix(id: &Digest32) -> String {
    vox_core::node::link::b32_encode(id)
        .chars()
        .take(12)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process gate for ADR-026 P-1 (#402); run on demand"]
async fn a_node_lists_and_closes_only_its_own_tunnels() {
    watchdog::arm();
    let a = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind A");
    let b = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind B");
    let x = Arc::new(VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind X"));
    let y = Arc::new(VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind Y"));
    let (mut at_x, mut at_y) = (host(Arc::clone(&x)), host(Arc::clone(&y)));
    let (a_to_x, _x_side) = connect(&a, &x, &mut at_x).await;
    let (b_to_y, _y_side) = connect(&b, &y, &mut at_y).await;
    let (ida, idb) = (a.local_id(), b.local_id());
    assert_eq!(
        a_to_x.local_id(),
        ida,
        "APPARATUS: A's connection is not A's"
    );

    let credit_a = a_to_x
        .carry_tunnel("a-service", true)
        .expect("APPARATUS: A's tunnel");
    let credit_b = b_to_y
        .carry_tunnel("b-service", true)
        .expect("APPARATUS: B's tunnel");
    let listed_a = live_tunnels(&ida);
    let listed_b = live_tunnels(&idb);
    assert!(
        listed_a.iter().all(|t| t.service == "a-service") && listed_a.len() == 1,
        "PRODUCT: A's tunnel list is not A's alone: {listed_a:?}"
    );
    assert!(
        listed_b.iter().all(|t| t.service == "b-service") && listed_b.len() == 1,
        "PRODUCT: B's tunnel list is not B's alone: {listed_b:?}"
    );
    let b_number = listed_b[0].id;

    // A, closing by B's member's prefix and by B's tunnel number, closes nothing.
    let by_member = close_tunnels(
        &ida,
        &TunnelSelector {
            member: Some(member_prefix(&y.local_id())),
            ..Default::default()
        },
        "closed by a person on this side",
    )
    .expect("PRODUCT: A's close by B's member was refused, not empty");
    let by_number = close_tunnels(
        &ida,
        &TunnelSelector {
            id: Some(b_number),
            ..Default::default()
        },
        "closed by a person on this side",
    )
    .expect("PRODUCT: A's close by B's number was refused, not empty");
    assert!(
        by_member.is_empty() && by_number.is_empty(),
        "PRODUCT: A closed B's tunnel: by member {by_member:?}, by number {by_number:?}"
    );
    let b_asked =
        tokio::time::timeout(Duration::from_millis(300), credit_b.watch().close_asked()).await;
    assert!(
        b_asked.is_err(),
        "PRODUCT: B's tunnel was asked to close by A: {b_asked:?}"
    );

    // A's own, by number, is closed, and only A's closed list says so.
    let a_number = listed_a[0].id;
    let closed = close_tunnels(
        &ida,
        &TunnelSelector {
            id: Some(a_number),
            ..Default::default()
        },
        "closed by a person on this side",
    )
    .expect("PRODUCT: A's close of its own tunnel was refused");
    assert_eq!(closed.len(), 1, "PRODUCT: A could not close its own tunnel");
    drop(credit_a);
    assert!(
        closed_tunnels(&ida).iter().any(|t| t.id == a_number),
        "PRODUCT: A's closed list misses the tunnel A closed"
    );
    assert!(
        closed_tunnels(&idb).is_empty(),
        "PRODUCT: B's closed list shows a tunnel B never closed: {:?}",
        closed_tunnels(&idb)
    );
    assert_eq!(
        live_tunnels(&idb).len(),
        1,
        "PRODUCT: B's tunnel left B's list"
    );
    drop(credit_b);
}

/// Carry a tunnel on `conn` (the node's end) whose bytes the application never reads: `peer`
/// opens the stream and writes without end, the node splices it into a TCP connection whose far
/// end reads nothing. The splice's result arrives on the returned channel when it ends.
async fn tunnel_nobody_reads(
    conn: Arc<VoxConnection>,
    peer: Arc<VoxConnection>,
) -> (
    tokio::sync::oneshot::Receiver<Instant>,
    tokio::task::JoinHandle<()>,
    TcpStream,
) {
    let credit = conn
        .carry_tunnel("stuck-service", false)
        .expect("APPARATUS: carry the tunnel");
    let (mut send, recv) = peer.open_stream().await.expect("APPARATUS: open");
    let writer = tokio::spawn(async move {
        let chunk = vec![7u8; 64 * 1024];
        let _ = recv;
        while send.write_all(&chunk).await.is_ok() {}
    });
    let (node_send, node_recv) =
        tokio::time::timeout(Duration::from_secs(10), conn.accept_stream())
            .await
            .expect("APPARATUS: the stream did not arrive")
            .expect("APPARATUS: accept the stream");
    let (spliced, app) = tcp_pair().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let watch = credit.watch();
        let _ = session::splice_watched(node_send, node_recv, spliced, watch).await;
        let _ = done_tx.send(Instant::now());
        drop(credit);
    });
    (done_rx, writer, app)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process gate for ADR-026 P-1 (#402); run on demand"]
async fn a_stuck_tunnel_closes_by_its_own_nodes_setting() {
    watchdog::arm();
    let a = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind A");
    let b = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind B");
    // Set A's, then B's: a process-wide setting would leave both at B's 600 s.
    a.local().set_stuck_after(Duration::from_secs(2));
    b.local().set_stuck_after(Duration::from_secs(600));
    let x = Arc::new(VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind X"));
    let mut at_x = host(Arc::clone(&x));
    let (a_to_x, x_to_a) = connect(&a, &x, &mut at_x).await;
    let (b_to_x, x_to_b) = connect(&b, &x, &mut at_x).await;
    let started = Instant::now();
    let (a_done, a_writer, _a_app) = tunnel_nobody_reads(Arc::new(a_to_x), Arc::new(x_to_a)).await;
    let (mut b_done, b_writer, _b_app) =
        tunnel_nobody_reads(Arc::new(b_to_x), Arc::new(x_to_b)).await;

    let a_ended = tokio::time::timeout(Duration::from_secs(20), a_done)
        .await
        .map(|r| r.map(|at| at.duration_since(started)));
    let Ok(Ok(after)) = a_ended else {
        panic!("PRODUCT: A's stuck tunnel was not closed within 20 s, with A's setting at 2 s");
    };
    assert!(
        after >= Duration::from_secs(2),
        "PRODUCT: A's tunnel closed after {after:?}, before A's 2 s"
    );
    let a_closed = closed_tunnels(&a.local_id());
    assert!(
        a_closed.iter().any(|t| t.why.contains("stuck")),
        "PRODUCT: A's closed list does not say its tunnel was closed as stuck: {a_closed:?}"
    );
    // B's waited as long, and more: it lives, by B's own 600 s.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        b_done.try_recv().is_err(),
        "PRODUCT: B's tunnel ended with A's, though B gives a stuck tunnel 600 s"
    );
    assert_eq!(
        live_tunnels(&b.local_id()).len(),
        1,
        "PRODUCT: B's tunnel is not on B's list"
    );
    assert!(
        closed_tunnels(&b.local_id()).is_empty(),
        "PRODUCT: B's closed list holds a tunnel: {:?}",
        closed_tunnels(&b.local_id())
    );
    a_writer.abort();
    b_writer.abort();
    eprintln!("A's stuck tunnel closed after {after:?}; B's lived past it");
}

#[test]
#[ignore = "in-process gate for ADR-026 P-1 (#402); run on demand"]
fn a_nodes_stop_does_not_wait_for_another_nodes_finishing_tunnel() {
    watchdog::arm();
    // Y, B's peer, runs on a runtime of its own on its own thread, so it can be frozen: a frozen
    // peer acknowledges nothing, and B's finished tunnel waits for it.
    let (y_tx, y_rx) = std::sync::mpsc::channel::<(Arc<VoxEndpoint>, tokio::runtime::Handle)>();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let y_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("APPARATUS: Y's runtime");
        let y = rt.block_on(async {
            Arc::new(VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind Y"))
        });
        y_tx.send((Arc::clone(&y), rt.handle().clone()))
            .expect("APPARATUS: hand Y over");
        rt.block_on(async {
            while stop_rx.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        drop(y);
    });
    let (y, y_rt) = y_rx.recv().expect("APPARATUS: Y did not start");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    rt.block_on(async move {
        let a = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind A");
        let b = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind B");
        let (ida, idb) = (a.local_id(), b.local_id());
        let (acc_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let y_accept = Arc::clone(&y);
        y_rt.spawn(async move {
            while let Ok(Some(conn)) = y_accept.accept(unix_now()).await {
                let _ = acc_tx.send(conn);
            }
        });
        let (b_to_y, _y_side) = connect(&b, &y, &mut accepted).await;
        let credit = b_to_y
            .carry_tunnel("finishing-service", true)
            .expect("APPARATUS: B's tunnel");
        let (b_send, b_recv) = b_to_y.open_stream().await.expect("APPARATUS: open");

        // Freeze Y: its only thread sleeps, so it reads and acknowledges nothing.
        let (frozen_tx, frozen_rx) = std::sync::mpsc::channel();
        y_rt.spawn(async move {
            let _ = frozen_tx.send(());
            std::thread::sleep(Duration::from_secs(6));
        });
        frozen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("APPARATUS: Y did not freeze");

        // B's application writes its last bytes and ends: B's tunnel finishes and waits for Y.
        let (spliced, mut app) = tcp_pair().await;
        app.write_all(b"the last bytes")
            .await
            .expect("APPARATUS: write");
        app.shutdown().await.expect("APPARATUS: shutdown");
        tokio::spawn(async move {
            let watch = credit.watch();
            let _ = session::splice_watched(b_send, b_recv, spliced, watch).await;
            drop(credit);
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The premise: B's own wait does wait (its tunnel is finishing).
        let t = Instant::now();
        session::all_acknowledged(&idb, Duration::from_millis(600)).await;
        let b_waited = t.elapsed();
        assert!(
            b_waited >= Duration::from_millis(550),
            "CANNOT MEASURE: B's tunnel was not finishing (B's own wait returned after \
             {b_waited:?}), so A's stop has nothing of B's to wait on"
        );
        // A's stop: A has nothing finishing, and must not wait on B's.
        let t = Instant::now();
        session::all_acknowledged(&ida, session::ACK_BOUND).await;
        let a_waited = t.elapsed();
        assert!(
            a_waited < Duration::from_secs(1),
            "PRODUCT: A's stop waited {a_waited:?} for its tunnels to be acknowledged, with \
             none of its own finishing: it waited on B's"
        );
        // The whole process's wait does include B's.
        let t = Instant::now();
        session::all_acknowledged_any(Duration::from_millis(400)).await;
        assert!(
            t.elapsed() >= Duration::from_millis(350),
            "PRODUCT: the process-wide wait did not wait for B's finishing tunnel"
        );
        eprintln!("B's wait held {b_waited:?} (bound 600 ms); A's returned in {a_waited:?}");
    });
    let _ = stop_tx.send(());
    let _ = y_thread.join();
}

#[test]
#[ignore = "in-process gate for ADR-026 P-1 (#402); run on demand"]
fn two_nodes_hold_circuits_to_one_peer_and_answer_only_their_own() {
    use quinn::Runtime as _;
    use vox_core::transport::mux::MuxSocket;
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    rt.block_on(async {
        let udp = std::net::UdpSocket::bind(loopback()).expect("APPARATUS: bind udp");
        let real = udp.local_addr().expect("APPARATUS: udp address");
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(udp)
            .expect("APPARATUS: wrap udp");
        let mux = MuxSocket::new(socket);
        let (a, b, x) = ([0xA1u8; 32], [0xB2u8; 32], [0x77u8; 32]);
        let port_a = mux
            .attach(&a, &x, None, None)
            .expect("APPARATUS: A's circuit");
        let port_b = mux
            .attach(&b, &x, None, None)
            .expect("APPARATUS: B's circuit");
        assert_ne!(port_a.addr(), port_b.addr(), "APPARATUS: one address twice");
        assert_eq!(
            mux.circuit_addr_of(&a, &x),
            Some(port_a.addr()),
            "PRODUCT: A's circuit to X is not found under A (B's took its place)"
        );
        assert_eq!(
            mux.circuit_addr_of(&b, &x),
            Some(port_b.addr()),
            "PRODUCT: B's circuit to X is not found under B"
        );
        assert_eq!(
            (mux.circuit_count(&a), mux.circuit_count(&b)),
            (1, 1),
            "PRODUCT: each node does not count one circuit"
        );
        // A circuit is answered only by its own node.
        assert!(
            !mux.serves_on(port_a.addr(), &b),
            "PRODUCT: B may answer on A's circuit: an ask for B over A's circuit is not refused"
        );
        assert!(
            mux.serves_on(port_a.addr(), &a),
            "PRODUCT: A may not answer on its own circuit"
        );
        assert!(
            mux.serves_on(real, &b),
            "PRODUCT: an address that is not a circuit is refused"
        );
        // A's going leaves B's.
        drop(port_a);
        assert_eq!(
            mux.circuit_addr_of(&b, &x),
            Some(port_b.addr()),
            "PRODUCT: dropping A's circuit took B's"
        );
        assert_eq!(
            mux.circuit_addr_of(&a, &x),
            None,
            "PRODUCT: A's circuit outlived its port"
        );
        assert_eq!(
            mux.owner_of(port_b.addr()),
            Some(b),
            "PRODUCT: B's circuit's owner"
        );
        drop(port_b);
    });
}
