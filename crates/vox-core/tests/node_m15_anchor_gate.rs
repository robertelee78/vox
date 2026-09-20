//! ADR-016 **M15.1 gate** — the use case the runtime exists for: *a client inside a
//! private network, with only outbound access, starts a swarm; another such client
//! joins it; the swarm carries their traffic.* Neither can reach the other, or be
//! reached, by any direct means: both sit behind **symmetric** NATs on the virtual
//! network of `support/vnet.rs`, where a direct dial is dropped and a hole punch is
//! defeated. What makes it work is the user's own always-on **anchor** (ADR-012
//! §"Bootstrap"): a publicly reachable node that holds no channel, serves the board,
//! coordinates the punch attempt, and — when that fails — carries the circuit the two
//! clients' QUIC packets ride on.
//!
//! Everything goes through the client API — `NodeCommand` in, `NodeView`/`NodeEvent`
//! out — over the nodes' real actors. Production Argon2id; the ADR-005 PoW is reduced
//! to keep the gate to seconds. `#[ignore]`d in the debug suite, run by CI's release
//! step.

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vnet::{NatKind, VirtualNet};
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

        // ---- the anchor: the user's always-on node, holding no channel ----
        let carol = node(&tmp, "anchor", c_sock, BootstrapSet::new()).await;
        let carol_fp = carol.view().identity.unwrap().fingerprint;
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

        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}
