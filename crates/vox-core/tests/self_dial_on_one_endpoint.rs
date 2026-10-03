//! **One quinn endpoint dials itself** (ADR-026 I-4, #400 / D2): the spike every shared-presence
//! piece rests on.
//!
//! Two nodes of one daemon reach each other by dialling the daemon's own address, through the
//! same identity exchange as any other pair (ADR-026 I-4). That needs one QUIC endpoint to be both
//! ends of a connection to itself. quinn routes an incoming packet by its destination connection
//! id: the client's random initial id goes to new-connection handling, and every later packet's id
//! names one side's own connection, so nothing should collide — but if it did, every co-hosted
//! design would need a second, loopback-only endpoint instead. So this is proved first, on the
//! exact shape the daemon will run: one endpoint over the multiplexing socket ([`MuxSocket`]),
//! the neutral daemon leaf on both sides of the handshake, IPv4 and dual-stack.
//!
//! Each case: two connections to its own address at once, data both ways on each (a stream the
//! dialling side opens and one the accepting side opens), each handshake under one second, the
//! endpoint counting two connections per self-dial; then both closed, the count back to zero, and
//! a redial that works as the first did.
//!
//! In-process, over real UDP sockets on this machine. Every wait is bounded (vox-core forbids the
//! `unsafe` the shared watchdog needs, so it is not armed here). The real-binary form (two attached nodes of
//! one `vox daemon` reach each other, through a loss and a redial) needs the daemon (D5, D7).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::Runtime as _;
use vox_core::transport::identity_cert::build_neutral_leaf;
use vox_core::transport::mux::MuxSocket;
use vox_core::transport::provider::{neutral_client_config, neutral_server_config};

/// Each handshake to the endpoint's own address must finish within this (#400).
const HANDSHAKE_BOUND: Duration = Duration::from_secs(1);

/// The endpoint under test, with its accept loop running: every connection it accepts echoes each
/// stream the dialler opens and opens one of its own carrying [`FROM_ACCEPTOR`].
fn endpoint_on(socket: std::net::UdpSocket) -> quinn::Endpoint {
    let leaf = build_neutral_leaf().expect("APPARATUS: neutral leaf");
    let server = quinn::crypto::rustls::QuicServerConfig::try_from(
        neutral_server_config(&leaf).expect("APPARATUS: server config"),
    )
    .expect("APPARATUS: quic server config");
    let client = quinn::crypto::rustls::QuicClientConfig::try_from(
        neutral_client_config(&leaf).expect("APPARATUS: client config"),
    )
    .expect("APPARATUS: quic client config");
    let wrapped = quinn::TokioRuntime
        .wrap_udp_socket(socket)
        .expect("APPARATUS: wrap socket");
    let mux = MuxSocket::new(wrapped);
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(quinn::ServerConfig::with_crypto(Arc::new(server))),
        mux,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("APPARATUS: endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client)));
    let acceptor = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = acceptor.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                // The accepting side opens a stream of its own: data the other way.
                let c2 = conn.clone();
                tokio::spawn(async move {
                    if let Ok((mut send, _recv)) = c2.open_bi().await {
                        let _ = send.write_all(FROM_ACCEPTOR).await;
                        let _ = send.finish();
                    }
                });
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(got) = recv.read_to_end(1024).await else {
                        return;
                    };
                    let mut back = b"echo:".to_vec();
                    back.extend_from_slice(&got);
                    let _ = send.write_all(&back).await;
                    let _ = send.finish();
                }
            });
        }
    });
    endpoint
}

const FROM_ACCEPTOR: &[u8] = b"from the accepting side";

/// Dial `to` from `endpoint` (its own address) and prove data moves both ways. Returns the
/// connection and how long its handshake took.
async fn dial_and_talk(endpoint: &quinn::Endpoint, to: SocketAddr, tag: &str) -> quinn::Connection {
    let started = Instant::now();
    let conn = tokio::time::timeout(
        HANDSHAKE_BOUND,
        endpoint.connect(to, "vox.invalid").expect("APPARATUS: connect"),
    )
    .await
    .unwrap_or_else(|_| {
        panic!("PRODUCT: a dial of the endpoint's own address {to} did not finish its handshake within {HANDSHAKE_BOUND:?}")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: a dial of the endpoint's own address {to} failed: {e}"));
    let took = started.elapsed();
    assert!(
        took < HANDSHAKE_BOUND,
        "PRODUCT: the handshake to {to} took {took:?}, not under {HANDSHAKE_BOUND:?}"
    );
    eprintln!("[self-dial] {tag}: handshake to {to} in {took:?}");

    // Dialler → acceptor and back, on a stream the dialling side opens.
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .expect("PRODUCT: open a stream on a self-dial");
    send.write_all(tag.as_bytes())
        .await
        .expect("PRODUCT: write on a self-dial");
    send.finish().expect("PRODUCT: finish on a self-dial");
    let back = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(1024))
        .await
        .expect("PRODUCT: no echo on a self-dial within 2 s")
        .expect("PRODUCT: the echo stream failed");
    assert_eq!(
        back,
        format!("echo:{tag}").into_bytes(),
        "PRODUCT: wrong echo on {tag}"
    );

    // Acceptor → dialler, on a stream the accepting side opens.
    let (_send, mut recv) = tokio::time::timeout(Duration::from_secs(2), conn.accept_bi())
        .await
        .expect("PRODUCT: the accepting side opened no stream within 2 s")
        .expect("PRODUCT: accepting the acceptor's stream failed");
    let got = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(1024))
        .await
        .expect("PRODUCT: the acceptor's stream said nothing within 2 s")
        .expect("PRODUCT: reading the acceptor's stream failed");
    assert_eq!(
        got, FROM_ACCEPTOR,
        "PRODUCT: wrong bytes from the accepting side on {tag}"
    );
    conn
}

/// Wait until `endpoint` counts exactly `n` connections, or fail naming what it counted.
async fn count_reaches(endpoint: &quinn::Endpoint, n: usize, why: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let open = endpoint.open_connections();
        if open == n {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: {why}: the endpoint counts {open} open connections, not {n}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn one_endpoint_dials_itself(socket: std::net::UdpSocket, targets: &[SocketAddr]) {
    let endpoint = endpoint_on(socket);
    for (round, to) in targets.iter().enumerate() {
        // Two connections at once, to the endpoint's own address.
        let (tag_a, tag_b) = (format!("r{round}-a"), format!("r{round}-b"));
        let (a, b) = tokio::join!(
            dial_and_talk(&endpoint, *to, &tag_a),
            dial_and_talk(&endpoint, *to, &tag_b),
        );
        assert_ne!(
            a.stable_id(),
            b.stable_id(),
            "PRODUCT: two dials gave one connection"
        );
        // Each self-dial is two connections in one endpoint: its dialling side and its accepting
        // side.
        count_reaches(&endpoint, 4, "two self-dials at once").await;

        // Close both; the endpoint forgets them.
        a.close(0u32.into(), b"done");
        b.close(0u32.into(), b"done");
        count_reaches(&endpoint, 0, "after both self-dials closed").await;

        // A redial works as the first dial did.
        let c = dial_and_talk(&endpoint, *to, &format!("r{round}-redial")).await;
        count_reaches(&endpoint, 2, "a redial after the close").await;
        c.close(0u32.into(), b"done");
        count_reaches(&endpoint, 0, "after the redial closed").await;
    }
    endpoint.close(0u32.into(), b"end");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over real UDP sockets; run on demand"]
async fn one_endpoint_dials_itself_over_ipv4() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind 127.0.0.1:0");
    let port = socket.local_addr().expect("APPARATUS: local addr").port();
    one_endpoint_dials_itself(socket, &[SocketAddr::from(([127, 0, 0, 1], port))]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over real UDP sockets; run on demand"]
async fn one_dual_stack_endpoint_dials_itself_over_both_families() {
    // A dual-stack socket, as a node binds `[::]:<port>` (IPv6 with IPv4-mapped addresses).
    let s = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
        .expect("APPARATUS: IPv6 socket");
    s.set_only_v6(false).expect("APPARATUS: dual-stack");
    s.bind(&SocketAddr::from(([0u16; 8], 0)).into())
        .expect("APPARATUS: bind [::]:0");
    let socket: std::net::UdpSocket = s.into();
    let port = socket.local_addr().expect("APPARATUS: local addr").port();
    one_endpoint_dials_itself(
        socket,
        &[
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
            // IPv4 on the dual-stack socket: quinn sees it as `::ffff:127.0.0.1`.
            SocketAddr::from(([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1], port)),
        ],
    )
    .await;
}
