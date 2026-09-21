//! ADR-016 **M15.1 gate** — the use case the runtime exists for: *a client inside a
//! private network, with only outbound access, starts a swarm; another such client
//! joins it; the swarm carries their traffic.* Neither can reach the other, or be
//! reached, by any direct means: both sit behind **symmetric** NATs on the virtual
//! network of `support/vnet.rs`, where a direct dial is dropped and a hole punch is
//! defeated. What makes it work is the user's own always-on **anchor** (ADR-012
//! §"Bootstrap"): a **headless** node (`vox node`, M15.2a) — no vault, no passphrase,
//! no room, a file-backed identity — that serves the board, coordinates the punch
//! attempt, carries the circuit the two clients' QUIC packets ride on when that
//! fails, and comes to know the room's members only because a member vouched.
//!
//! Everything goes through the client API — `NodeCommand` in, `NodeView`/`NodeEvent`
//! out — over the nodes' real actors. Production Argon2id; the ADR-005 PoW is reduced
//! to keep the gate to seconds. `#[ignore]`d in the debug suite, run by CI's release
//! step.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vnet::{NatKind, VirtualNet};
use vox_core::identity::composite::RootSigner;
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::InviteLink;
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);

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

/// Spawn a node on a virtual socket, with these anchors, and create its identity.
async fn node(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
) -> NodeHandle {
    let mut cfg = NodeConfig::new()
        .bind(Bind::Socket(socket))
        .anchors(anchors);
    // The join's PoW, reduced: the gate is about reachability, and (200,9) is
    // exercised by the M14 gate and the release-only join test.
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    let h = Node::spawn_config(paths(tmp, name), cfg).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase")
        })
        .await
        .is_done());
    assert!(!h.view().listening.is_empty(), "{name} is listening");
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

fn sees(h: &NodeHandle, cid: [u8; 32], text: &str) -> bool {
    h.view()
        .open_channels
        .iter()
        .find(|d| d.channel_id == cid)
        .is_some_and(|d| d.timeline.iter().any(|r| r.text == text))
}

#[test]
#[ignore = "production Argon2id and a relayed join: ~10 s in release; CI runs it there"]
fn m15_two_clients_behind_symmetric_nats_form_a_swarm_through_their_anchor() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

        // ---- the anchor: `vox node`, headless — a key file, no vault, no room ----
        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let carol_fp = carol_signer.fingerprint();
        let carol = Node::spawn_config(
            paths(&tmp, "anchor"),
            NodeConfig::new()
                .bind(Bind::Socket(c_sock))
                .headless(carol_signer),
        )
        .unwrap();
        assert!(
            carol.view().identity.is_none(),
            "a headless node has no profile identity to unlock"
        );
        assert!(
            !carol.view().listening.is_empty(),
            "and is on the network from the start"
        );
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

        // ---- Alice, inside a private network, configured with her anchor ----
        let alice = node(&tmp, "alice", a_sock, anchors).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
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
        let link = InviteLink::parse(&url).expect("a well-formed link");
        assert_eq!(
            link.anchors[0].id, carol_fp,
            "the link names the anchor first: it is the reachable one"
        );
        assert!(
            link.anchors.iter().any(|a| a.id == alice_fp),
            "and Alice herself, last"
        );
        assert_eq!(link.responder, Some(alice_fp));
        assert!(!url.contains("channel passphrase"));

        // ---- Bob, inside another private network, knows nothing but the link ----
        let bob = node(&tmp, "bob", b_sock, BootstrapSet::new()).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        let join_started = std::time::Instant::now();
        let joined = tokio::time::timeout(
            TIMEOUT,
            bob.apply(NodeCommand::JoinChannel {
                link: url.clone(),
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            }),
        )
        .await
        .expect("the join did not hang");
        assert!(joined.is_done(), "Bob joins through the anchor: {joined:?}");
        // Relay-first (M15.1b): the join rides the circuit the anchor carries the
        // moment it is up, not after a direct dial and a punch have each timed out.
        // The bound is generous — production Argon2id and the PoW are inside it — but
        // well under the ~21 s the sequential ladder cost.
        assert!(
            join_started.elapsed() < Duration::from_secs(12),
            "the join took {:?}",
            join_started.elapsed()
        );
        let (joined_cid, responder) = wait_for(&bob, |e| match e {
            NodeEvent::Joined {
                channel_id,
                responder,
            } => Some((channel_id, responder)),
            _ => None,
        })
        .await;
        assert_eq!(joined_cid, cid);
        assert_eq!(
            responder, alice_fp,
            "joined through Alice, the pinned responder"
        );
        // The path between them is a circuit the anchor carries: both NATs are
        // symmetric, so nothing shorter was possible.
        assert!(
            net.filtered() > 0,
            "the NATs dropped the direct and punched attempts"
        );

        // ---- Alice sees Bob join, consents, and they talk ----
        let _ = wait_for(&alice, |e| match e {
            NodeEvent::PeerJoined { channel_id, peer } if channel_id == cid && peer == bob_fp => {
                Some(())
            }
            _ => None,
        })
        .await;
        let _ = wait_for(&alice, |e| match e {
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } if channel_id == cid && peer == bob_fp => Some(()),
            _ => None,
        })
        .await;
        let out = alice
            .apply(NodeCommand::Consent {
                channel_id: cid,
                target: bob_fp,
            })
            .await;
        assert!(out.is_done(), "Alice consents to Bob: {out:?}");
        let _ = wait_for(&bob, |e| match e {
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } if channel_id == cid && peer == alice_fp => Some(()),
            _ => None,
        })
        .await;
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "hello from inside my network".into(),
            })
            .await
            .is_done());
        assert!(bob
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "and from inside mine".into(),
            })
            .await
            .is_done());
        tokio::time::timeout(TIMEOUT, async {
            while !(sees(&alice, cid, "and from inside mine")
                && sees(&bob, cid, "hello from inside my network"))
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("automatic sync carried both messages through the swarm");

        // The anchor holds no channel and read nothing: it has no open channel at
        // all, and the only thing it ever stored is the board.
        assert!(carol.view().open_channels.is_empty());
        assert!(carol.view().channels.is_empty());
        // What it does know: the room it anchors, and — because Alice vouched for
        // Bob when she admitted him — both members. Bob's own records were refused
        // until then: an anchor learns a room's members only from a member.
        tokio::time::timeout(TIMEOUT, async {
            loop {
                let anchoring = carol.view().anchoring;
                if anchoring
                    .iter()
                    .any(|a| a.channel_id == cid && a.members >= 2)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the anchor came to know both members");
        let anchored = carol.view().anchoring;
        assert_eq!(anchored.len(), 1, "one room anchored: {anchored:?}");
        assert_eq!(anchored[0].channel_id, cid);
        assert_eq!(
            anchored[0].members, 2,
            "Alice by her genesis, Bob by Alice's vouch"
        );

        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}

/// ADR-016's M15 gate, as written: *two nodes that are never simultaneously online
/// converge through an anchor.* The anchor keeps a ciphertext copy of the room's
/// log (M15.2b); a member who was away gets what was said while it was, from the
/// anchor, with the other member gone — and can read it, because the sender key it
/// was given before survives its own restart.
#[test]
#[ignore = "production Argon2id, three node lifetimes and a relayed join: ~20 s in release; CI runs it there"]
fn m15_members_never_online_together_converge_through_the_anchor() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

        // The anchor: headless, keeping logs.
        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let carol_fp = carol_signer.fingerprint();
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

        // ---- both online once: create, join, consent ----
        let alice = node(&tmp, "alice", Arc::clone(&a_sock), anchors.clone()).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
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
        let bob = node(&tmp, "bob", Arc::clone(&b_sock), BootstrapSet::new()).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        assert!(bob
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let _ = wait_for(&bob, |e| match e {
            NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
            _ => None,
        })
        .await;
        let _ = wait_for(&alice, |e| match e {
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } if channel_id == cid && peer == bob_fp => Some(()),
            _ => None,
        })
        .await;
        assert!(alice
            .apply(NodeCommand::Consent {
                channel_id: cid,
                target: bob_fp,
            })
            .await
            .is_done());
        let _ = wait_for(&bob, |e| match e {
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } if channel_id == cid && peer == alice_fp => Some(()),
            _ => None,
        })
        .await;

        // ---- Bob leaves ----
        assert!(bob.apply(NodeCommand::Shutdown).await.is_done());

        // ---- Alice speaks into an empty room; the anchor takes it ----
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "said while you were away".into(),
            })
            .await
            .is_done());
        // Wait for the anchor to hold **everything Alice has** — not merely something.
        // Her log already had governance entries, so "at least one" would pass before
        // the content entry was ever pushed, and the anchor would be asked to serve
        // what it had never been given.
        let alice_entries = |h: &NodeHandle| -> u64 {
            h.view()
                .channels
                .iter()
                .find(|c| c.channel_id == cid)
                .map_or(0, |c| c.entries)
        };
        let anchor_holds = |h: &NodeHandle| -> u64 {
            h.view()
                .anchoring
                .iter()
                .find(|a| a.channel_id == cid)
                .and_then(|a| a.entries)
                .unwrap_or(0)
        };
        let wanted = alice_entries(&alice);
        assert!(wanted >= 3, "genesis, consent and the message: {wanted}");
        tokio::time::timeout(TIMEOUT, async {
            while anchor_holds(&carol) < wanted {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the anchor holds the whole log Alice has");
        assert!(
            carol.view().open_channels.is_empty(),
            "and reads none of it"
        );

        // ---- Alice leaves; Bob returns to a room with nobody in it ----
        assert!(alice.apply(NodeCommand::Shutdown).await.is_done());
        // Bob's earlier instance shares this process: its last session task lets go
        // of the store a moment after its connections close, and the store's lock is
        // exactly what keeps two instances from ever opening it at once.
        let bob = tokio::time::timeout(TIMEOUT, async {
            loop {
                let socket: Arc<dyn quinn::AsyncUdpSocket> =
                    Arc::clone(&b_sock) as Arc<dyn quinn::AsyncUdpSocket>;
                let mut cfg = NodeConfig::new().bind(Bind::Socket(socket));
                cfg.pow_params = Some(PowParams { n: 48, k: 5 });
                match Node::spawn_config(paths(&tmp, "bob"), cfg) {
                    Ok(h) => return h,
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            }
        })
        .await
        .expect("Bob's second instance opened its store");
        assert!(bob
            .apply(NodeCommand::Unlock {
                passphrase: secret("identity passphrase")
            })
            .await
            .is_done());
        // Bob configured no anchor: the one the link named was persisted with the room.
        assert!(bob
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        tokio::time::timeout(TIMEOUT, async {
            while !sees(&bob, cid, "said while you were away") {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("Bob converged through the anchor and read what Alice said");

        for h in [&bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}

/// ADR-013's payoff, the M16.1 gate: **a TCP service reached across the overlay** by
/// two clients that cannot reach each other at all. Alice runs a service on localhost
/// — an `ssh` daemon, in the real use; here a byte-exact echo, because `ssh` over a
/// tunnel is nothing more than TCP over a tunnel — grants Bob the capability to dial
/// it, and Bob forwards a local port to it. His application connects to his own
/// machine and its bytes come out of Alice's service, through the anchor.
///
/// What this proves that the library tests cannot: the capability travelled as a log
/// fact through ordinary sync, the host resolved it through the *named channel's*
/// evaluator, and the path was a relayed circuit — both clients are behind symmetric
/// NATs, so no punch was possible.
#[test]
#[ignore = "production Argon2id, a relayed join and a tunneled TCP round trip: ~15 s in release"]
fn m16_a_tcp_service_is_reached_across_the_overlay_between_two_nated_clients() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // A byte-exact echo service on Alice's machine, standing in for sshd.
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

        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let carol_fp = carol_signer.fingerprint();
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

        // Alice creates the room and offers her service in it.
        let alice = node(&tmp, "alice", a_sock, anchors).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "infra".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = alice.view().channels[0].channel_id;
        let out = alice
            .apply(NodeCommand::AddService {
                channel_id: cid,
                service_tag: "ssh".into(),
                local: service_addr,
            })
            .await;
        assert!(
            out.is_done(),
            "the creator holds bind: by the genesis: {out:?}"
        );
        let offered = alice.view().open_channels[0].services.clone();
        assert_eq!(offered, vec![("ssh".to_owned(), service_addr)]);

        // Bob joins through the anchor.
        assert!(alice
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        let bob = node(&tmp, "bob", b_sock, BootstrapSet::new()).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        assert!(bob
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "infra".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let _ = wait_for(&bob, |e| match e {
            NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
            _ => None,
        })
        .await;
        let _ = wait_for(&alice, |e| match e {
            NodeEvent::PeerJoined { channel_id, peer } if channel_id == cid && peer == bob_fp => {
                Some(())
            }
            _ => None,
        })
        .await;

        // Before any grant the service is dark, even to a member: Bob's forward binds
        // (that is local) but carries nothing.
        let out = bob
            .apply(NodeCommand::Forward {
                channel_id: cid,
                host: alice_fp,
                service_tag: "ssh".into(),
                local: addr("127.0.0.1:0"),
            })
            .await;
        assert!(out.is_done(), "the forward binds locally: {out:?}");
        let dark = wait_for(&bob, |e| match e {
            NodeEvent::Forwarding { local, .. } => Some(local),
            _ => None,
        })
        .await;
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut app = tokio::net::TcpStream::connect(dark).await.unwrap();
            let _ = app.write_all(b"before the grant").await;
            let mut buf = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(20), app.read(&mut buf)).await;
            assert!(
                matches!(read, Ok(Ok(0)) | Ok(Err(_))),
                "a service with no capability granted is dark: {read:?}"
            );
        }
        assert!(bob
            .apply(NodeCommand::StopForward { local: dark })
            .await
            .is_done());

        // Alice grants Bob dial:ssh — a fact on the room's log.
        let out = alice
            .apply(NodeCommand::GrantTunnel {
                channel_id: cid,
                target: bob_fp,
                service_tag: "ssh".into(),
                may_bind: false,
                expiry: 2_000_000_000,
            })
            .await;
        assert!(out.is_done(), "Alice grants Bob dial:ssh: {out:?}");

        // It reaches Bob by ordinary sync — nobody tells him.
        let forwarded = tokio::time::timeout(TIMEOUT, async {
            loop {
                let out = bob
                    .apply(NodeCommand::Forward {
                        channel_id: cid,
                        host: alice_fp,
                        service_tag: "ssh".into(),
                        local: addr("127.0.0.1:0"),
                    })
                    .await;
                assert!(out.is_done(), "{out:?}");
                let local = wait_for(&bob, |e| match e {
                    NodeEvent::Forwarding { local, .. } => Some(local),
                    _ => None,
                })
                .await;
                // Try the round trip; until the grant has synced this closes.
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                if let Ok(mut app) = tokio::net::TcpStream::connect(local).await {
                    let msg = b"ssh-over-vox, through the anchor";
                    if app.write_all(msg).await.is_ok() {
                        let mut buf = vec![0u8; msg.len()];
                        if let Ok(Ok(_)) =
                            tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut buf))
                                .await
                        {
                            assert_eq!(buf, msg, "the service echoed byte for byte");
                            break local;
                        }
                    }
                }
                let _ = bob.apply(NodeCommand::StopForward { local }).await;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .expect("the grant synced and the tunnel carried real bytes");

        // The path was a relayed circuit: both clients are behind symmetric NATs, so
        // no punch was possible, and the anchor carried the packets it cannot read.
        let conn = bob
            .view()
            .forwards
            .iter()
            .find(|f| f.local == forwarded)
            .map(|f| f.host);
        assert_eq!(conn, Some(alice_fp));
        assert!(net.filtered() > 0, "the NATs dropped the direct attempts");
        assert!(
            carol.view().open_channels.is_empty(),
            "the anchor read nothing"
        );

        // A second connection over the same forward works too: one stream each.
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut app = tokio::net::TcpStream::connect(forwarded).await.unwrap();
            app.write_all(b"second connection").await.unwrap();
            let mut buf = vec![0u8; b"second connection".len()];
            tokio::time::timeout(Duration::from_secs(20), app.read_exact(&mut buf))
                .await
                .expect("did not hang")
                .expect("echoed");
            assert_eq!(&buf, b"second connection");
        }

        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}
