//! V030-35 D4 (#402) — **two nodes in one process keep their own tunnel state** (ADR-026 P-1).
//!
//! A process may host several nodes. The tunnel registries, the finishing count, the stuck-after
//! setting and the mux's circuit tables used to be one per process, which was right only while a
//! process was one node. Each is now filed under its node.
//!
//! **What a person sees is proved on the shipped binary** (#410): a node listing and closing only
//! its own tunnels, and a stuck tunnel closing by its own node's setting, are
//! `two_nodes_in_one_daemon_keep_their_own_tunnels_proof` — one daemon holding two nodes, read
//! through `vox status --json --node` and closed through `vox tunnel close --node`. This gate keeps
//! the two parts with no surface a person sees, driving two nodes, `A` and `B`, side by side in
//! one process, each on its own endpoint, against real QUIC peers on loopback:
//!
//! 1. **A's stop does not wait for B's finishing tunnel.** B's tunnel has sent its last bytes to
//!    a peer that is frozen, so it waits for an acknowledgement (up to 10 s). A waiting for its
//!    own tunnels to be acknowledged returns at once; B waiting for its own does not.
//! 2. **Two nodes hold circuits to one peer without collision, and a circuit is answered only by
//!    its own node** (Tr4). On one shared mux, A and B each attach a circuit to the same peer `X`:
//!    two addresses, each found under its own node; dropping A's leaves B's. A circuit of A's is
//!    not one B may answer on.
//!
//! **Which side a red is on.** A node waiting on another node's state, or answering on its circuit,
//! is `PRODUCT:`. A premise that did not hold (B's tunnel not finishing, a peer that would not
//! connect) is `APPARATUS:` / `CANNOT MEASURE`.
//!
//! Mutants (each reverted after): one global finishing counter → red on 1;
//! `MuxSocket::serves_on` without the owner check → red on 2.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};

use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::{unix_now_ms, VoxConnection, VoxEndpoint};
use vox_core::tunnel::session;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback")
}

fn signer() -> Arc<SoftwareRootSigner> {
    Arc::new(SoftwareRootSigner::generate().expect("APPARATUS: generate an identity"))
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
        local.connect(addr, peer.local_id(), unix_now_ms()),
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
            while let Ok(Some(conn)) = y_accept.accept(unix_now_ms()).await {
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
