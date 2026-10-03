//! In-process proofs of the shared presence (#403 / D5; ADR-026 D-3, D-5, I-3, I-4) over real UDP
//! on 127.0.0.1: one presence with two nodes attached, a remote node with an endpoint of its own.
//!
//! Each claim names the mutant that turns it red; a red names its side. The real-binary forms
//! (two nodes attached to one `vox daemon`) need the daemon host (D6/D7) and come with D12.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::identity::composite::SoftwareRootSigner;
use crate::transport::quic::VoxEndpoint;
use crate::wire::WireError;

fn signer() -> Arc<dyn RootSigner + Send + Sync> {
    Arc::new(SoftwareRootSigner::generate().expect("APPARATUS: keygen"))
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("addr")
}

/// The next connection a node is handed, within `wait`, if any.
async fn next_in(link: &mut NodeLink, wait: Duration) -> Option<VoxConnection> {
    tokio::time::timeout(wait, link.inbound.recv())
        .await
        .ok()
        .flatten()
}

/// One round trip on a fresh stream of `conn`: the far side echoes.
async fn round_trip(conn: &VoxConnection, tag: &[u8]) -> bool {
    let go = async {
        let (mut send, mut recv) = conn.open_stream().await.ok()?;
        send.write_all(tag).await.ok()?;
        send.finish().ok()?;
        recv.read_to_end(1024).await.ok()
    };
    matches!(tokio::time::timeout(Duration::from_secs(3), go).await, Ok(Some(b)) if b == tag)
}

/// Echo every stream opened on `conn` until it closes.
fn echo(conn: &VoxConnection) {
    let q = conn.quinn().clone();
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = q.accept_bi().await {
            tokio::spawn(async move {
                if let Ok(b) = recv.read_to_end(1024).await {
                    let _ = send.write_all(&b).await;
                    let _ = send.finish();
                }
            });
        }
    });
}

/// Each node attached to one presence is handed only the connections dialled to it, though both
/// answer at one address; a node not attached there is not answered for, and the dialler names
/// nobody. Mutant: route every connection to the first node registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn two_nodes_on_one_presence_each_get_only_their_own_connections() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let at = presence.shared().local_addr().expect("APPARATUS: addr");
    let (sa, sb) = (signer(), signer());
    let (ida, idb) = (sa.fingerprint(), sb.fingerprint());
    let mut a = presence.attach(sa).expect("PRODUCT: attach A");
    let mut b = presence.attach(sb).expect("PRODUCT: attach B");
    let c = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind C");

    for (round, (want, other)) in [(ida, idb), (idb, ida), (ida, idb)].into_iter().enumerate() {
        let dialled = c
            .connect(at, want, 0)
            .await
            .unwrap_or_else(|e| panic!("PRODUCT: C could not reach a node on the presence: {e}"));
        assert_eq!(dialled.peer_id(), want, "PRODUCT: C reached the wrong node");
        let (mine, theirs) = if want == ida {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let got = next_in(mine, Duration::from_secs(3))
            .await
            .unwrap_or_else(|| {
                panic!("PRODUCT: round {round}: the node dialled was handed nothing")
            });
        assert_eq!(
            got.local_id(),
            want,
            "PRODUCT: a connection filed under the wrong node"
        );
        assert_eq!(
            got.peer_id(),
            c.local_id(),
            "PRODUCT: the wrong dialler was proved"
        );
        assert!(
            next_in(theirs, Duration::from_millis(300)).await.is_none(),
            "PRODUCT: round {round}: a connection for {:?} was handed to {:?} too",
            crate::hash::Hex(&want),
            crate::hash::Hex(&other)
        );
    }

    // A node not attached here: refused, and the dial names no one.
    let stranger = signer().fingerprint();
    let err = c
        .connect(at, stranger, 0)
        .await
        .err()
        .expect("PRODUCT: a node not attached was answered for")
        .to_string();
    assert!(
        err.contains(&format!("nothing at {at} answers as")),
        "PRODUCT: the dial said {err:?}"
    );
    for id in [ida, idb] {
        let named = crate::node::link::b32_encode(&id);
        assert!(
            !err.contains(&named[..26]),
            "PRODUCT: the refusal named a node that is here: {err}"
        );
    }
    presence.close().await;
}

/// Two nodes of one presence reach each other by dialling its own address (ADR-026 I-4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn two_nodes_of_one_presence_reach_each_other_through_its_address() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let at = presence.shared().local_addr().expect("APPARATUS: addr");
    let (sa, sb) = (signer(), signer());
    let (ida, idb) = (sa.fingerprint(), sb.fingerprint());
    let a = presence.attach(sa).expect("PRODUCT: attach A");
    let mut b = presence.attach(sb).expect("PRODUCT: attach B");
    let started = Instant::now();
    let ab = a
        .endpoint
        .connect(at, idb, 0)
        .await
        .unwrap_or_else(|e| panic!("PRODUCT: A could not reach B on their own presence: {e}"));
    let got = next_in(&mut b, Duration::from_secs(3))
        .await
        .expect("PRODUCT: B was handed nothing for A's dial");
    assert_eq!(
        (ab.peer_id(), got.peer_id()),
        (idb, ida),
        "PRODUCT: the wrong nodes were proved"
    );
    echo(&got);
    assert!(
        round_trip(&ab, b"a to b").await,
        "PRODUCT: no bytes between two nodes of one presence"
    );
    eprintln!(
        "[presence] A reached B through the shared address in {:?}",
        started.elapsed()
    );
    presence.close().await;
}

/// **Detaching one node touches no other** (ADR-026 D-5), and **a node that comes back is a new
/// process to its peers** (I-3): with C connected to A and to B through one presence, A detaches
/// — its connections closed, its registration gone — while B's connection keeps carrying bytes and
/// the presence keeps answering; A attaches again and C reaches it at once, as a new process.
/// Mutants: the endpoint closed on a detach; a constant instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn a_detach_closes_only_that_node_and_its_return_is_a_new_process() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let at = presence.shared().local_addr().expect("APPARATUS: addr");
    let (sa, sb) = (signer(), signer());
    let (ida, idb) = (sa.fingerprint(), sb.fingerprint());
    let mut a = presence.attach(Arc::clone(&sa)).expect("PRODUCT: attach A");
    let mut b = presence.attach(sb).expect("PRODUCT: attach B");
    let c = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind C");

    let ca = c.connect(at, ida, 0).await.expect("PRODUCT: C to A");
    let a_side = next_in(&mut a, Duration::from_secs(3))
        .await
        .expect("PRODUCT: A handed nothing");
    let cb = c.connect(at, idb, 0).await.expect("PRODUCT: C to B");
    let b_side = next_in(&mut b, Duration::from_secs(3))
        .await
        .expect("PRODUCT: B handed nothing");
    echo(&b_side);
    assert!(
        round_trip(&cb, b"before").await,
        "PRODUCT: C and B exchanged nothing before the detach"
    );
    let first_process = ca.peer_process();

    // A detaches, as a node's stop does: its connections closed, then its view off the endpoint.
    a_side.close(WireError::ShuttingDown);
    a.endpoint.close();
    drop(a);
    let closed = tokio::time::timeout(Duration::from_secs(3), ca.quinn().closed()).await;
    assert!(
        closed.is_ok(),
        "PRODUCT: A's connection outlived A's detach"
    );

    // B is untouched: its connection still carries bytes, and it is still reachable afresh.
    for i in 0..5u8 {
        assert!(
            round_trip(&cb, &[b'x', i]).await,
            "PRODUCT: B's connection stopped carrying bytes after A detached (round {i})"
        );
    }
    let again = c.connect(at, idb, 0).await;
    assert!(
        again.is_ok(),
        "PRODUCT: B could not be reached after A detached: {:?}",
        again.err()
    );
    assert!(
        c.connect(at, ida, 0).await.is_err(),
        "PRODUCT: A was still answered for after it detached"
    );

    // A comes back: reached at once, as a new process.
    let a2 = presence
        .attach(sa)
        .expect("PRODUCT: A could not attach again");
    let started = Instant::now();
    let ca2 = c
        .connect(at, ida, 0)
        .await
        .unwrap_or_else(|e| panic!("PRODUCT: C could not reach A after it came back: {e}"));
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(1),
        "PRODUCT: reaching the returned A took {took:?}"
    );
    assert_ne!(
        ca2.peer_process(),
        first_process,
        "PRODUCT: A came back with the process identity it had before: its peers cannot tell it \
         restarted"
    );
    assert_ne!(
        a2.endpoint.local().instance(),
        [0u8; 16],
        "APPARATUS: instance"
    );
    eprintln!("[presence] A reattached and was reached in {took:?}");
    presence.close().await;
}

/// The gate holds handshakes and exchanges to the cap, and a connection the exchange did not
/// prove reaches no node: a dialler that never asks is closed at the exchange's 5 s bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn a_connection_that_never_asks_reaches_no_node() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let at = presence.shared().local_addr().expect("APPARATUS: addr");
    let mut a = presence.attach(signer()).expect("PRODUCT: attach A");
    // A raw neutral client: completes TLS, then says nothing.
    let leaf = crate::transport::identity_cert::build_neutral_leaf().expect("APPARATUS: leaf");
    let client = quinn::crypto::rustls::QuicClientConfig::try_from(
        crate::transport::provider::neutral_client_config(&leaf).expect("APPARATUS: cfg"),
    )
    .expect("APPARATUS: quic cfg");
    let mut raw = quinn::Endpoint::client(loopback()).expect("APPARATUS: raw endpoint");
    raw.set_default_client_config(quinn::ClientConfig::new(Arc::new(client)));
    let conn = raw
        .connect(at, "vox.invalid")
        .expect("APPARATUS: connect")
        .await
        .expect("PRODUCT: the neutral handshake failed");
    let started = Instant::now();
    let why = tokio::time::timeout(Duration::from_secs(8), conn.closed())
        .await
        .expect("PRODUCT: a connection that never asked was not closed");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(4) && took < Duration::from_secs(7),
        "PRODUCT: closed after {took:?}, not at the 5 s exchange bound ({why})"
    );
    assert!(
        next_in(&mut a, Duration::from_millis(100)).await.is_none(),
        "PRODUCT: a node was handed a connection whose exchange never ran"
    );
    presence.close().await;
}
