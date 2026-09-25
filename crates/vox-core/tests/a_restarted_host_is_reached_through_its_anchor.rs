//! v0.2.9 #6 — **a host that restarts is reachable through its anchor again within one
//! `SILENCE_IS_DEATH`**, not after QUIC's 60s idle timeout.
//!
//! When a host crashes and comes back, every node that held a connection to the old process
//! keeps holding it: the old process's close never left the box, and nothing else says it is
//! gone. The anchor then has two connections filed for one identity — the dead one and the
//! restarted process's new one — and the tie-break keeps the dead one half the time. A client
//! whose connection has to be relayed asks the anchor for a circuit to the host, the anchor opens
//! it on the dead connection, and the service is unreachable for up to a minute. The client is
//! stuck the same way on its own side: its relayed connection to the old process looks live too.
//!
//! The rule under test (`node::net::SILENCE_IS_DEATH`): a connection that has received nothing
//! for 1.5 keep-alive intervals is dead, and a live one to the same peer takes over. Nothing here
//! looks at addresses, and the two restarts staged are the two an address rule gets wrong or
//! cannot tell apart:
//!
//! - **the same address and port** — the host comes back behind the same NAT on the same inner
//!   socket, so the anchor sees the new process at exactly the external address of the old one;
//! - **a different address** — the host comes back on another network (Wi-Fi to Ethernet), a
//!   new NAT with a new external IP.
//!
//! Each gate restarts the host [`RESTARTS`] times. The crash is real in the sense that matters:
//! `vnet::VirtualNet::sever` cuts the old socket before the node shuts down, so its QUIC close is
//! lost exactly as a crashed process's would be. The client — behind a symmetric NAT, so it has
//! **no** path to the host but a circuit through the anchor — leaves cleanly before each crash
//! and comes back after it, then sends bytes through its `vox up` SOCKS proxy to the host's
//! service; the gate measures how long after the crash the first echo came back, and asserts the
//! path was a circuit. The client restarts because a client that stayed up is found by the
//! restarted host dialling *it*, over the anchor's live connection to the client, and the
//! anchor's filing of the host is never consulted — the first draft of this gate passed that way
//! in 1s with the fix and without it.
//!
//! Production Argon2id; the ADR-005 PoW is reduced. `#[ignore]`d in the debug suite, run by CI's
//! release step.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vnet::{NatKind, VirtualNet};
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::vox_hostname;
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);

/// How many times each gate crashes and restarts the host. The tie-break between the dead and the
/// new connection is a coin per restart, so one restart could pass by luck with no liveness rule
/// at all; three leave that at one in eight, and the client's own stale connection (which no
/// coin rescues) makes it rarer still.
const RESTARTS: usize = 3;

/// The bound on "reachable again", from the crash: `SILENCE_IS_DEATH` (30s), plus the node's 1s
/// tick, plus a circuit being set up afresh through the ladder. Well under the 60s idle timeout
/// the old behaviour waited out, so the two cannot be confused.
const REACHABLE_AGAIN_WITHIN: Duration = Duration::from_secs(45);

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

fn config(socket: Arc<vnet::VirtualSocket>, anchors: BootstrapSet) -> NodeConfig {
    let socket: Arc<dyn quinn::AsyncUdpSocket> = socket;
    let mut cfg = NodeConfig::new()
        .bind(Bind::Socket(socket))
        .anchors(anchors);
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    cfg
}

async fn node(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
) -> NodeHandle {
    let h = Node::spawn_config(paths(tmp, name), config(socket, anchors)).unwrap();
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

/// One SOCKS5 CONNECT through `proxy` to `name:port`, then an echo of `msg`. `Err` says which
/// step failed, so a slow recovery is reported by what was refused rather than as a timeout.
async fn probe(proxy: SocketAddr, name: &str, port: u16, msg: &[u8]) -> Result<(), String> {
    let mut s = TcpStream::connect(proxy)
        .await
        .map_err(|e| format!("proxy connect: {e}"))?;
    s.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("greet: {e}"))?;
    let mut selected = [0u8; 2];
    s.read_exact(&mut selected)
        .await
        .map_err(|e| format!("method: {e}"))?;
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(u8::try_from(name.len()).unwrap());
    req.extend_from_slice(name.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)
        .await
        .map_err(|e| format!("request: {e}"))?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .map_err(|e| format!("reply: {e}"))?;
    let rest = match head[3] {
        0x01 => 6,
        0x04 => 18,
        other => return Err(format!("reply ATYP {other}")),
    };
    let mut buf = vec![0u8; rest];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| format!("reply tail: {e}"))?;
    if head[1] != 0 {
        return Err(format!("SOCKS reply code {}", head[1]));
    }
    s.write_all(msg).await.map_err(|e| format!("write: {e}"))?;
    let mut echo = vec![0u8; msg.len()];
    s.read_exact(&mut echo)
        .await
        .map_err(|e| format!("echo: {e}"))?;
    if echo != msg {
        return Err("echo differed".into());
    }
    Ok(())
}

/// Probe until an echo comes back or `within` runs out. Returns how long after `since` the first
/// echo arrived, and how many attempts failed first (with the last reason).
///
/// **A new attempt every second, and none is cut short**, which is how a person or a tool that
/// retries behaves. One request through the proxy runs the node's whole ladder, and against a
/// dead connection one attempt can take longer than any short per-attempt timeout; cutting it off
/// and starting over would measure the timeout, not the node. Overlapping attempts with a long
/// bound measure when the node could first carry an echo, to within a second.
///
/// The rate is also a check of its own. Before v0.2.8 served circuit streams on their own tasks
/// (56db6b1), an anchor handled one client's circuit requests one at a time, so requests at a dead
/// target queued, failed in a burst when it closed, and tripped the stream loop's 16-failure limit:
/// the anchor stopped reading that client for good and the host was never reached again. At this
/// rate that defect fails this gate.
async fn reach_again(
    proxy: SocketAddr,
    name: &str,
    port: u16,
    since: Instant,
    within: Duration,
) -> (Option<Duration>, usize, String) {
    let mut attempts = tokio::task::JoinSet::new();
    let (mut failed, mut last) = (0, String::new());
    let mut next = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = next.tick(), if since.elapsed() < within => {
                let name = name.to_owned();
                attempts.spawn(async move {
                    match tokio::time::timeout(
                        Duration::from_secs(30),
                        probe(proxy, &name, port, b"after the restart"),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => Err("no answer in 30s".into()),
                    }
                });
            }
            Some(done) = attempts.join_next() => match done.expect("probe task") {
                Ok(()) => {
                    let took = since.elapsed();
                    attempts.abort_all();
                    return (Some(took), failed, last);
                }
                Err(why) => {
                    failed += 1;
                    last = why;
                }
            },
            else => return (None, failed, last),
        }
    }
}

/// Start a node that has run before in this directory: open its store (waiting for a previous
/// instance in this process to let go of the lock), unlock it and open the room.
async fn restart(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: &Arc<vnet::VirtualSocket>,
    anchors: &BootstrapSet,
    cid: [u8; 32],
    room_passphrase: &str,
) -> NodeHandle {
    // The old instance shares this process, and its store lock goes a moment after its tasks
    // do: the lock is what keeps two instances off one store.
    let h = tokio::time::timeout(TIMEOUT, async {
        loop {
            match Node::spawn_config(
                paths(tmp, name),
                config(Arc::clone(socket), anchors.clone()),
            ) {
                Ok(h) => return h,
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .expect("the new instance opened its store");
    assert!(h
        .apply(NodeCommand::Unlock {
            passphrase: secret("identity passphrase")
        })
        .await
        .is_done());
    let out = h
        .apply(NodeCommand::OpenChannel {
            channel_id: cid,
            passphrase: secret(room_passphrase),
        })
        .await;
    assert!(out.is_done(), "{name} reopens the room: {out:?}");
    h
}

/// `vox up` on `h`: the SOCKS proxy that asks the node for the room's host per request.
async fn up(h: &NodeHandle, cid: [u8; 32]) -> SocketAddr {
    assert!(h
        .apply(NodeCommand::Up {
            channel_id: cid,
            bind: addr("127.0.0.1:0"),
        })
        .await
        .is_done());
    wait_for(h, |e| match e {
        NodeEvent::ProxyUp { bind, .. } => Some(bind),
        _ => None,
    })
    .await
}

/// Where the restarted host comes back.
#[derive(Clone, Copy)]
enum Comeback {
    /// The same inner socket behind the same NAT: the same external address and port.
    SameAddress,
    /// A new network: a new NAT with a new external IP.
    NewAddress,
}

fn restarts_are_recognised_by_silence(comeback: Comeback) {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // The host's service: a byte-exact echo standing in for sshd.
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

        // Both behind symmetric NATs: the only path between them is a circuit the anchor carries.
        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        let a_inner = addr("10.0.1.2:5000");
        let mut a_sock = net.behind_nat(a_inner, NatKind::Symmetric, ip("203.0.113.1"));
        let b_inner = addr("10.0.2.2:5000");
        let mut b_sock = net.behind_nat(b_inner, NatKind::Symmetric, ip("203.0.113.2"));

        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let carol_fp = vox_core::identity::composite::RootSigner::fingerprint(&carol_signer);
        let carol = Node::spawn_config(
            paths(&tmp, "anchor"),
            NodeConfig::new()
                .bind(Bind::Socket(c_sock))
                .headless(carol_signer)
                .anchor_logs(true),
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

        // ---- the host serves, the client joins, the host trusts the client ----
        let mut alice = node(&tmp, "alice", Arc::clone(&a_sock), anchors.clone()).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        let port = service_addr.port();
        let out = alice
            .apply(NodeCommand::Serve {
                local_name: "infra".into(),
                passphrase: secret("generated passphrase"),
                port,
                udp: false,
                at: Some(service_addr),
            })
            .await;
        assert!(out.is_done(), "vox serve: {out:?}");
        let cid = alice.view().channels[0].channel_id;
        assert!(alice
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        let mut bob = node(&tmp, "bob", Arc::clone(&b_sock), BootstrapSet::new()).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        assert!(bob
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "infra".into(),
                passphrase: secret("generated passphrase"),
            })
            .await
            .is_done());
        let _ = wait_for(&alice, |e| match e {
            NodeEvent::PeerJoined { channel_id, peer } if channel_id == cid && peer == bob_fp => {
                Some(())
            }
            _ => None,
        })
        .await;
        assert!(alice
            .apply(NodeCommand::Trust {
                fingerprint: bob_fp,
                petname: "bob".into(),
            })
            .await
            .is_done());

        // ---- the client's entry point: `vox up`, which asks the node for the host per request ----
        let hostname = vox_hostname(&cid);
        let mut proxy = up(&bob, cid).await;

        // Step 1: reachable at all, or the restarts prove nothing.
        let (first, failed, why) =
            reach_again(proxy, &hostname, port, Instant::now(), TIMEOUT).await;
        assert!(
            first.is_some(),
            "the service must be reachable before any restart ({failed} attempts, last: {why})"
        );
        assert!(
            bob.view().relayed_peers.contains(&alice_fp),
            "the client must reach the host through a circuit, or the anchor is not under test"
        );
        eprintln!(
            "[test] before any restart: reached through the anchor's circuit ({failed} failed \
             attempts first)"
        );

        let mut elapsed = Vec::new();
        for round in 1..=RESTARTS {
            // ---- the client goes away cleanly, so the only stale connections are the host's ----
            //
            // It comes back after the host has, and starts the conversation itself: the case a
            // `vox up` or `vox connect` started after a host restart is in. A client that stayed up
            // would be found by the restarted host dialling *it*, through the anchor's connection
            // to the client — which is live — and the anchor's filing of the host would never be
            // asked anything.
            let round_started = Instant::now();
            let _ = bob.apply(NodeCommand::Shutdown).await;
            // Its close has to leave before its socket is cut, or this is a second crash: the
            // endpoint's driver sends it just after the shutdown returns.
            tokio::time::sleep(Duration::from_secs(1)).await;
            // Its next instance gets a socket of its own at the same address. Handing it the old
            // one would put two endpoints on one inbox whenever the old instance's endpoint
            // outlives its shutdown, and the old one would read half the new one's packets.
            net.sever(&b_sock);
            b_sock = net.replug(b_inner);

            // ---- the host crashes: its socket is cut before it shuts down, so its close is lost ----
            net.sever(&a_sock);
            let _ = alice.apply(NodeCommand::Shutdown).await;
            let crashed = Instant::now();
            a_sock = match comeback {
                Comeback::SameAddress => net.replug(a_inner),
                Comeback::NewAddress => {
                    let k = u8::try_from(round).unwrap();
                    net.behind_nat(
                        SocketAddr::new(IpAddr::from([10, 0, 10 + k, 2]), 5000),
                        NatKind::Symmetric,
                        IpAddr::from([203, 0, 113, 100 + k]),
                    )
                }
            };

            // ---- and comes back: same identity, same room, same service ----
            alice = restart(
                &tmp,
                "alice",
                &a_sock,
                &anchors,
                cid,
                "generated passphrase",
            )
            .await;
            assert_eq!(
                alice.view().open_channels[0].services.len(),
                1,
                "the restarted host offers its service again"
            );

            // ---- the client returns and reaches it, which it can only do through the anchor ----
            bob = restart(
                &tmp,
                "bob",
                &b_sock,
                &BootstrapSet::new(),
                cid,
                "generated passphrase",
            )
            .await;
            proxy = up(&bob, cid).await;
            let back_up = crashed.elapsed();
            let (took, failed, why) = reach_again(
                proxy,
                &hostname,
                port,
                crashed,
                REACHABLE_AGAIN_WITHIN + Duration::from_secs(30),
            )
            .await;
            // Either end's view will do, and each is only as fresh as its last publish; with both
            // behind symmetric NATs nothing but a circuit can carry them, so this is a check that
            // the test is still staging what it says rather than a second measurement.
            let relayed = bob.view().relayed_peers.contains(&alice_fp)
                || alice.view().relayed_peers.contains(&bob_fp);
            eprintln!(
                "[test] restart {round}: reachable again {} after the crash ({failed} failed \
                 attempts first{}), relayed={relayed}; both nodes were back {:.1}s after the \
                 crash, round took {:.1}s",
                took.map_or_else(
                    || "NEVER".to_owned(),
                    |t| format!("{:.1}s", t.as_secs_f64())
                ),
                if why.is_empty() {
                    String::new()
                } else {
                    format!(", last: {why}")
                },
                back_up.as_secs_f64(),
                round_started.elapsed().as_secs_f64()
            );
            elapsed.push(took);
            if took.is_some() {
                assert!(
                    relayed,
                    "restart {round}: the path to the host must still be the anchor's circuit"
                );
            } else {
                // Unreachable: go on to the verdict, which says what the bound was.
                break;
            }
        }

        let over: Vec<String> = elapsed
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_none_or(|t| t > REACHABLE_AGAIN_WITHIN))
            .map(|(i, t)| {
                format!(
                    "restart {}: {}",
                    i + 1,
                    t.map_or_else(
                        || "never".to_owned(),
                        |t| format!("{:.1}s", t.as_secs_f64())
                    )
                )
            })
            .collect();
        eprintln!(
            "[test] {} of {} restarts reachable again within {}s",
            elapsed.len() - over.len(),
            elapsed.len(),
            REACHABLE_AGAIN_WITHIN.as_secs()
        );
        assert!(
            over.is_empty(),
            "a restarted host stayed unreachable through its anchor past {}s — the anchor (or the \
             client) kept the dead process's connection until QUIC's idle timeout: {over:?}",
            REACHABLE_AGAIN_WITHIN.as_secs()
        );

        for h in [&alice, &bob, &carol] {
            let _ = h.apply(NodeCommand::Shutdown).await;
        }
    });
}

#[test]
#[ignore = "three host crashes and restarts through a relayed circuit: ~2 min in release"]
fn a_host_restarted_on_the_same_address_is_reached_again_within_the_silence_bound() {
    restarts_are_recognised_by_silence(Comeback::SameAddress);
}

#[test]
#[ignore = "three host crashes and restarts through a relayed circuit: ~2 min in release"]
fn a_host_restarted_on_a_new_address_is_reached_again_within_the_silence_bound() {
    restarts_are_recognised_by_silence(Comeback::NewAddress);
}
