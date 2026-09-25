//! ADR-012 M15.1b — a relayed path that a direct one displaced is **let go** once its grace
//! is up, unless something is still carried on it.
//!
//! When a direct path appears behind a relayed one, the direct one replaces it and the relayed
//! one is retired. `ConnectionManager::retire_expired` closes a retired connection once the
//! grace has passed and nothing holds it any more — the strong count of its `Arc` is that
//! signal, because a tunnel splicing on it holds one for as long as it runs.
//!
//! The defect this guards against: each connection's stream loop held that `Arc` for the
//! connection's whole life, so the count never fell below two and **no retired connection was
//! ever closed**. A relayed pair that went direct kept its circuit on the relay for good — the
//! relay's slot, the relay's connections to both ends, and QUIC keep-alives crossing it every
//! few seconds for a path nobody used. The loop now holds a `Weak` and the quinn handle.
//!
//! The scene is `relayed_path_is_retried`'s: both members behind symmetric NATs, so the first
//! path is a circuit through the anchor; then both NATs become punchable and the pair goes
//! direct. The clock is injected, so the retry interval and the grace cost no wall clock, and
//! the only wall-clock waits are the actor's one-second tick and the circuit's close linger.
//!
//! Two properties, one test each, both on real nodes:
//! 1. an uncarried displaced relayed connection is closed within the grace plus a tick, and the
//!    anchor's relay circuit count goes to 0;
//! 2. one carrying a live tunnel stays up past the grace, the tunnel still carries bytes, and
//!    it is let go once the tunnel ends.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vnet::{NatKind, VirtualNet};
use vox_core::hash::Digest32;
use vox_core::identity::composite::RootSigner;
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::net::RETIRE_GRACE_SECS;
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);

/// The actor sweeps retired connections once per tick (`actor::TICK`).
const TICK: Duration = Duration::from_secs(1);

/// A circuit outlives the connection it carried by this much, so the close crosses it
/// (`circuitstream::CIRCUIT_CLOSE_LINGER`).
const LINGER: Duration = Duration::from_secs(1);

/// Scheduling slack: the relay has to see the circuit's stream end, one more hop of the
/// virtual network, and the anchor's view is republished on the anchor's own tick.
const SLACK: Duration = Duration::from_secs(1);

/// From the moment nothing keeps a displaced relayed connection any more (its grace is up
/// and nothing carries it) to the anchor reporting its circuit gone: the sweep's tick, the
/// circuit's linger, the anchor's own tick publishing it, and the slack.
const BOUND: Duration =
    Duration::from_secs(2 * TICK.as_secs() + LINGER.as_secs() + SLACK.as_secs());

/// How long past the bound the gate keeps watching before it calls the relay stuck, so a
/// red prints how far off it was rather than just "late".
const WATCH: Duration = Duration::from_secs(15);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}
fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

async fn node(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
    clock: vox_core::time::Clock,
) -> NodeHandle {
    let mut cfg = NodeConfig::new()
        .bind(Bind::Socket(socket))
        .anchors(anchors)
        .clock(clock);
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    let h = Node::spawn_config(paths(tmp, name), cfg).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase")
        })
        .await
        .is_done());
    h
}

async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match h.next_event().await {
                Some(e) => {
                    if let Some(v) = f(e) {
                        return v;
                    }
                }
                None => panic!("event stream ended"),
            }
        }
    })
    .await
    .expect("event did not arrive")
}

/// One echo round trip over `app`, bounded.
async fn echoes(app: &mut TcpStream, msg: &[u8]) -> bool {
    if app.write_all(msg).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; msg.len()];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && buf == msg
}

struct Scene {
    net: Arc<VirtualNet>,
    now: Arc<AtomicU64>,
    carol: NodeHandle,
    alice: NodeHandle,
    bob: NodeHandle,
    alice_fp: Digest32,
    /// Bob's local end of a forward to Alice's echo service.
    forward: SocketAddr,
    /// An application connection through that forward, over the relayed path, that has
    /// already carried one round trip.
    app: Option<TcpStream>,
}

/// Anchor Carol, Alice and Bob behind symmetric NATs, one room, Alice serving an echo, Bob
/// trusted and forwarding to it — so the only path is a circuit through Carol, and a tunnel
/// is running over it.
async fn relayed_scene(tmp: &tempfile::TempDir) -> Scene {
    let service = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service_addr = service.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = service.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let now = Arc::new(AtomicU64::new(1_800_000_000));
    let clock: vox_core::time::Clock = {
        let now = Arc::clone(&now);
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let net = VirtualNet::new();
    let c_addr = addr("198.51.100.1:443");
    let c_sock = net.public(c_addr);
    // NAT 0 is Alice's, NAT 1 is Bob's: the index `set_nat_kind` takes.
    let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
    let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

    let carol_signer =
        vox_core::node::headless::load_or_create_identity(&paths(tmp, "anchor")).unwrap();
    let carol_fp = RootSigner::public_key(&carol_signer).fingerprint();
    let carol = Node::spawn_config(
        paths(tmp, "anchor"),
        NodeConfig::new()
            .bind(Bind::Socket(c_sock))
            .headless(carol_signer)
            .clock(Arc::clone(&clock)),
    )
    .unwrap();
    let mut anchors = BootstrapSet::new();
    anchors
        .add(
            BootstrapNode::new(
                carol_fp,
                EndpointList::new(vec![Multiaddr::from(c_addr)]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

    let alice = node(tmp, "alice", a_sock, anchors.clone(), Arc::clone(&clock)).await;
    let bob = node(tmp, "bob", b_sock, anchors, Arc::clone(&clock)).await;
    let alice_fp = alice.view().identity.unwrap().fingerprint;
    let bob_fp = bob.view().identity.unwrap().fingerprint;

    let out = alice
        .apply(NodeCommand::CreateChannel {
            local_name: "room".into(),
            passphrase: secret("room passphrase"),
        })
        .await;
    assert!(out.is_done(), "alice creates the room: {out:?}");
    let cid = wait_for(&alice, |e| match e {
        NodeEvent::ChannelOpened { channel_id } => Some(channel_id),
        _ => None,
    })
    .await;
    let out = alice
        .apply(NodeCommand::AddService {
            channel_id: cid,
            service_tag: "echo".into(),
            local: service_addr,
        })
        .await;
    assert!(out.is_done(), "alice offers the echo service: {out:?}");
    assert!(alice
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(&alice, |e| match e {
        NodeEvent::InviteLink { url, .. } => Some(url),
        _ => None,
    })
    .await;
    let out = bob
        .apply(NodeCommand::JoinChannel {
            link: url,
            local_name: "room".into(),
            passphrase: secret("room passphrase"),
        })
        .await;
    assert!(out.is_done(), "bob joins through the anchor: {out:?}");
    let out = alice
        .apply(NodeCommand::Trust {
            fingerprint: bob_fp,
            petname: "bob".into(),
        })
        .await;
    assert!(out.is_done(), "alice trusts bob: {out:?}");

    // Bob's forward, retried until the relayed circuit is up and the echo answers.
    let (forward, app) = tokio::time::timeout(TIMEOUT, async {
        loop {
            let out = bob
                .apply(NodeCommand::Forward {
                    channel_id: cid,
                    host: alice_fp,
                    service_tag: "echo".into(),
                    local: addr("127.0.0.1:0"),
                })
                .await;
            assert!(out.is_done(), "{out:?}");
            let local = wait_for(&bob, |e| match e {
                NodeEvent::Forwarding { local, .. } => Some(local),
                _ => None,
            })
            .await;
            if let Ok(mut app) = TcpStream::connect(local).await {
                if echoes(&mut app, b"over the relay").await {
                    break (local, app);
                }
            }
            let _ = bob.apply(NodeCommand::StopForward { local }).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("bob's tunnel to alice's echo carried a round trip");

    assert!(
        bob.view().relayed_peers.contains(&alice_fp),
        "CANNOT MEASURE: bob reached alice other than through the relay, so there is no \
         relayed path to displace (relayed_peers {:?})",
        bob.view().relayed_peers
    );
    let relaying = carol.view().relaying;
    assert!(
        relaying >= 1,
        "CANNOT MEASURE: the anchor carries {relaying} circuits while bob is relayed"
    );
    eprintln!("relayed: bob -> alice through carol, carol relaying {relaying} circuit(s)");

    Scene {
        net,
        now,
        carol,
        alice,
        bob,
        alice_fp,
        forward,
        app: Some(app),
    }
}

/// Make a direct path possible, step one retry interval, and wait for bob to be on it.
/// The relayed connections are retired at this moment on the injected clock.
async fn go_direct(s: &Scene) {
    s.net.set_nat_kind(0, NatKind::PortRestrictedCone);
    s.net.set_nat_kind(1, NatKind::PortRestrictedCone);
    s.now.fetch_add(61, Ordering::SeqCst);
    let upgraded = tokio::time::timeout(Duration::from_secs(60), async {
        while s.bob.view().relayed_peers.contains(&s.alice_fp) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        upgraded.is_ok(),
        "CANNOT MEASURE: bob is still relayed 60 s after a direct path became possible, so \
         nothing was displaced"
    );
}

/// Watch the anchor's circuit count from now until it is 0 or `WATCH` passes; the time it
/// took and the last count seen.
async fn until_no_circuits(carol: &NodeHandle) -> (Duration, usize) {
    let t0 = Instant::now();
    loop {
        let n = carol.view().relaying;
        if n == 0 || t0.elapsed() >= WATCH {
            return (t0.elapsed(), n);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
#[ignore = "a relayed join, a tunnel and a path upgrade on real nodes; CI runs it in the release step"]
fn a_displaced_relayed_connection_is_closed_once_its_grace_is_up() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let mut s = relayed_scene(&tmp).await;
        // The tunnel ends before the path changes, so nothing is carried on the relayed
        // connection when it is displaced.
        drop(s.app.take());
        let _ = s
            .bob
            .apply(NodeCommand::StopForward { local: s.forward })
            .await;

        go_direct(&s).await;

        // Inside the grace it stays: the grace is for whatever was mid-request on it.
        tokio::time::sleep(3 * TICK).await;
        let within = s.carol.view().relaying;
        assert!(
            within >= 1,
            "the relayed connection was closed inside its grace: carol relays {within} \
             circuits {:?} after it was displaced, with the grace not yet up",
            3 * TICK
        );

        // The grace passes. Nothing is carried, so the next tick closes it, the circuit
        // ends after its linger, and the anchor carries nothing for this pair.
        s.now.fetch_add(RETIRE_GRACE_SECS + 1, Ordering::SeqCst);
        let (took, left) = until_no_circuits(&s.carol).await;
        let bound = BOUND;
        eprintln!("grace up: carol relaying {within} -> {left} after {took:?} (bound {bound:?})");
        assert_eq!(
            left, 0,
            "carol still relays {left} circuit(s) {took:?} after the grace of a displaced, \
             uncarried relayed connection ran out — the connection was never closed, so its \
             circuit holds a relay slot and both of the relay's connections for a path nobody \
             uses"
        );
        assert!(
            took <= bound,
            "the displaced relayed connection was let go {took:?} after its grace, beyond a \
             tick, the circuit linger and the anchor's tick ({bound:?})"
        );

        for h in [&s.alice, &s.bob, &s.carol] {
            let _ = h.apply(NodeCommand::Shutdown).await;
        }
    });
}

#[test]
#[ignore = "a relayed join, a tunnel and a path upgrade on real nodes; CI runs it in the release step"]
fn a_displaced_relayed_connection_carrying_a_tunnel_stays_up_until_the_tunnel_ends() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let mut s = relayed_scene(&tmp).await;

        go_direct(&s).await;

        // Well past the grace, with the tunnel still open on the relayed connection.
        s.now.fetch_add(RETIRE_GRACE_SECS + 1, Ordering::SeqCst);
        tokio::time::sleep(5 * TICK).await;
        let carried = s.carol.view().relaying;
        let alive = echoes(
            s.app.as_mut().unwrap(),
            b"still here after the path changed",
        )
        .await;
        eprintln!("grace up, tunnel open: carol relaying {carried}, tunnel echoes: {alive}");
        assert!(
            alive,
            "the tunnel on the displaced relayed connection stopped carrying bytes once the \
             grace ran out — a live session cut because a better path appeared"
        );
        assert!(
            carried >= 1,
            "carol relays {carried} circuits while a tunnel is still open on the relayed path"
        );

        // The tunnel ends; the next tick lets the connection go.
        drop(s.app.take());
        let (took, left) = until_no_circuits(&s.carol).await;
        let bound = BOUND;
        eprintln!(
            "tunnel closed: carol relaying {carried} -> {left} after {took:?} (bound {bound:?})"
        );
        assert_eq!(
            left, 0,
            "carol still relays {left} circuit(s) {took:?} after the last tunnel on a \
             displaced relayed connection ended"
        );
        assert!(
            took <= bound,
            "the relayed connection was let go {took:?} after its tunnel ended, beyond a tick, \
             the circuit linger and the anchor's tick ({bound:?})"
        );

        for h in [&s.alice, &s.bob, &s.carol] {
            let _ = h.apply(NodeCommand::Shutdown).await;
        }
    });
}
