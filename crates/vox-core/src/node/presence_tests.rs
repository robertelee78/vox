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

/// Join two circuit ports: what each endpoint sends to its port's address arrives at the other's.
fn pump(mut a: crate::transport::mux::CircuitPort, mut b: crate::transport::mux::CircuitPort) {
    let (mut a_out, mut b_out) = (
        a.take_outbound().expect("APPARATUS: outbound"),
        b.take_outbound().expect("APPARATUS: outbound"),
    );
    let (a_in, b_in) = (a.inlet(), b.inlet());
    tokio::spawn(async move {
        let _hold = (a, b);
        loop {
            tokio::select! {
                d = a_out.recv() => match d { Some(d) => b_in.deliver(d), None => break },
                d = b_out.recv() => match d { Some(d) => a_in.deliver(d), None => break },
            }
        }
    });
}

/// **A circuit is answered only by the node it was attached for** (ADR-026 P-1, `serves_on`):
/// over A's circuit, C reaches A; an `ASK` for B, attached to the same presence, gets the one
/// refusal. Mutant: `serves_on` answering for any node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn an_ask_for_another_node_over_a_circuit_is_refused() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let (sa, sb) = (signer(), signer());
    let (ida, idb) = (sa.fingerprint(), sb.fingerprint());
    let mut a = presence.attach(sa).expect("PRODUCT: attach A");
    let mut b = presence.attach(sb).expect("PRODUCT: attach B");
    let c = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind C");
    let idc = c.local_id();

    // One circuit between C and A, as a relay carries it: A's end is A's alone.
    let at_a = a
        .endpoint
        .attach_circuit(&idc, None)
        .expect("APPARATUS: A's circuit end");
    let at_c = c
        .attach_circuit(&ida, None)
        .expect("APPARATUS: C's circuit end");
    let to_a = at_c.addr();
    pump(at_a, at_c);

    let via = c
        .connect(to_a, ida, 0)
        .await
        .unwrap_or_else(|e| panic!("PRODUCT: C could not reach A over A's circuit: {e}"));
    assert!(
        via.via_circuit(),
        "APPARATUS: the dial did not run over the circuit"
    );
    assert!(
        next_in(&mut a, Duration::from_secs(3)).await.is_some(),
        "PRODUCT: A was handed nothing for a dial over its own circuit"
    );

    let err = c
        .connect(to_a, idb, 0)
        .await
        .err()
        .expect("PRODUCT: B answered over A's circuit")
        .to_string();
    assert!(
        err.contains("answers as"),
        "PRODUCT: the refusal said {err:?}"
    );
    assert!(
        next_in(&mut b, Duration::from_millis(300)).await.is_none(),
        "PRODUCT: B was handed a connection that came over A's circuit"
    );
    presence.close().await;
}

/// **One presence, one discovery, one cache** (ADR-026 D-3, ADR-012 N-43): two nodes attaching
/// start no discovery of their own — the presence's one is what both advertise — and what a peer
/// reported to one node is the presence's observed address for both; forgetting one node's
/// reporter keeps the other's. Mutant: a discovery per attach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn one_presence_discovers_once_and_keeps_one_observed_cache() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let mut advertised = presence.advertised();
    tokio::time::timeout(
        Duration::from_secs(20),
        advertised.wait_for(Option::is_some),
    )
    .await
    .expect("PRODUCT: the presence composed no addresses within 20 s")
    .expect("APPARATUS: watch");
    let (sa, sb) = (signer(), signer());
    let (ida, idb) = (sa.fingerprint(), sb.fingerprint());
    let _a = presence.attach(sa).expect("PRODUCT: attach A");
    let _b = presence.attach(sb).expect("PRODUCT: attach B");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        presence.discoveries(),
        1,
        "PRODUCT: two attaches ran discoveries of their own: {} in all",
        presence.discoveries()
    );

    let (r1, r2) = (signer().fingerprint(), signer().fingerprint());
    let seen: crate::nat::multiaddr::Multiaddr =
        std::net::SocketAddr::from(([198, 51, 100, 7], 4242)).into();
    presence.note_observed(ida, r1, seen);
    presence.note_observed(idb, r2, seen);
    assert_eq!(
        presence.observed_addr(),
        Some(seen),
        "PRODUCT: the reports were not kept"
    );
    presence.forget_observed(&ida, &r1);
    assert_eq!(
        presence.observed_addr(),
        Some(seen),
        "PRODUCT: forgetting A's reporter forgot B's too"
    );
    presence.close().await;
}

/// **A panicked node is evicted alone** (ADR-026 L-6, D-5): its registration and every
/// connection it had close; another node's connection on the presence keeps carrying bytes.
/// Mutants: evict leaves the connections open; evict closes every node's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn an_evicted_node_loses_only_its_own_connections() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let at = presence.shared().local_addr().expect("APPARATUS: addr");
    let (sa, sb) = (signer(), signer());
    let (ida, idb) = (sa.fingerprint(), sb.fingerprint());
    let mut a = presence.attach(sa).expect("PRODUCT: attach A");
    let mut b = presence.attach(sb).expect("PRODUCT: attach B");
    let c = VoxEndpoint::bind(signer(), loopback()).expect("APPARATUS: bind C");
    let ca = c.connect(at, ida, 0).await.expect("PRODUCT: C to A");
    let _a_side = next_in(&mut a, Duration::from_secs(3))
        .await
        .expect("PRODUCT: A handed nothing");
    let cb = c.connect(at, idb, 0).await.expect("PRODUCT: C to B");
    let b_side = next_in(&mut b, Duration::from_secs(3))
        .await
        .expect("PRODUCT: B handed nothing");
    echo(&b_side);
    presence.evict(&ida);
    let closed = tokio::time::timeout(Duration::from_secs(3), ca.quinn().closed()).await;
    assert!(
        closed.is_ok(),
        "PRODUCT: the evicted node's connection was left open"
    );
    assert!(
        !presence.shared().registered().contains(&ida),
        "PRODUCT: the evicted node is still answered for"
    );
    for i in 0..3u8 {
        assert!(
            round_trip(&cb, &[b'e', i]).await,
            "PRODUCT: B's connection stopped carrying bytes when A was evicted (round {i})"
        );
    }
    presence.close().await;
}

/// **One nearby group per presence** (ADR-012 N-44): every node asking gets the same group.
/// Mutant: a group opened per node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over loopback UDP; run on demand"]
async fn every_node_on_a_presence_shares_its_one_nearby_group() {
    let presence = NetPresence::bind(loopback()).expect("APPARATUS: bind the presence");
    let Some((first, _)) = presence.nearby() else {
        panic!("CANNOT MEASURE: the nearby group cannot be opened on this machine");
    };
    let (second, _) = presence.nearby().expect("PRODUCT: the group went away");
    assert!(
        Arc::ptr_eq(&first, &second),
        "PRODUCT: a second node got a nearby group of its own"
    );
    presence.close().await;
}

/// **The relay limits of `.daemon/config` hold for the presence's one ledger** (ADR-012 N-45):
/// `relay-circuits = 3` and `relay-circuits-per-asker = 2` let one asker take 2 circuits and the
/// presence carry 3 in all; a malformed value is refused naming its key. Mutant: the ledger
/// keeping the built-in limits whatever the config says.
#[test]
#[ignore = "in-process proof; run on demand"]
fn the_relay_limits_of_the_daemon_config_hold_for_the_presences_ledger() {
    use crate::node::circuitstream::{CircuitLedger, RelayLimits};
    let limits = RelayLimits::parse(
        "# relay\nlisten = 127.0.0.1:0\nrelay-circuits = 3\nrelay-circuits-per-asker = 2\n",
    )
    .expect("PRODUCT: a valid config was refused");
    assert_eq!(
        limits,
        RelayLimits {
            total: 3,
            per_asker: 2
        },
        "PRODUCT: the limits read are not the config's"
    );
    let ledger = Arc::new(CircuitLedger::default());
    ledger.set_limits(limits);
    let (x, y, z) = (signer().fingerprint(), signer().fingerprint(), signer().fingerprint());
    let held: Vec<_> = [x, x, x, y, y, z]
        .iter()
        .map(|a| ledger.take(*a))
        .collect();
    let taken: Vec<bool> = held.iter().map(Option::is_some).collect();
    assert_eq!(
        taken,
        [true, true, false, true, false, false],
        "PRODUCT: the ledger did not hold to 2 per asker and 3 in all"
    );
    let bad = RelayLimits::parse("relay-circuits = many").expect_err("PRODUCT: a bad value was taken");
    assert!(bad.contains("relay-circuits"), "PRODUCT: the refusal did not name its key: {bad}");
}
