//! ADR-017 **M17.2 gate** — the two-command flow, with the third step *absent*.
//!
//! The M16.1 gate proved the mechanism: a TCP service reached across the overlay
//! between two clients behind symmetric NATs, through the user's own anchor. It needed
//! six steps, and the worst of them was the sixth — Alice waiting for Bob to appear and
//! then granting him `dial:`. This gate is the same reachability with that step deleted.
//!
//! So the central assertion here is a **negative**: nowhere does this test issue
//! `GrantTunnel`, or any certificate, to anybody. Bob reaches Alice's service because
//! her room's genesis says members may (ADR-017 decision 3), and he became a member by
//! holding the passphrase and paying the proof of work.
//!
//! It also proves the two things the host needs and the service cannot give:
//! - the room's **`.vox` hostname** is derivable from the address Bob was handed, with
//!   no extra field anywhere — the same 52 characters begin both;
//! - a **`TunnelServed` event** names who reached what, because `sshd` behind a Vox
//!   tunnel only ever logs `127.0.0.1` (ADR-017 decision 6).
//!
//! Everything goes through the client API. Production Argon2id; the ADR-005 PoW is
//! reduced, because what is under test is the flow and the M14 gate already runs the
//! production solve. `#[ignore]`d in the debug suite, run by CI's release step.

#[path = "support/watchdog.rs"]
mod watchdog;

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
use vox_core::node::link::{b32_encode, channel_of_hostname, vox_hostname};
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

async fn node(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
) -> NodeHandle {
    let mut cfg = NodeConfig::new()
        .bind(Bind::Socket(socket))
        .anchors(anchors);
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

#[test]
#[ignore = "production Argon2id, a relayed join and a tunneled TCP round trip: ~15 s in release"]
fn m17_a_service_room_is_reached_with_no_grant_step() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // A byte-exact echo on Alice's machine, standing in for sshd: `ssh` over a
        // tunnel is nothing more than TCP over a tunnel.
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

        // Both clients are behind symmetric NATs, so no direct path and no punch exists:
        // the anchor carries the circuit.
        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

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

        // ---- `vox serve 22`: one command makes the room, the grant and the service ----
        let alice = node(&tmp, "alice", a_sock, anchors).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        let port = service_addr.port();
        let tag = port.to_string();
        let out = alice
            .apply(NodeCommand::Serve {
                local_name: "infra".into(),
                passphrase: secret("generated passphrase"),
                port,
                at: Some(service_addr),
            })
            .await;
        assert!(out.is_done(), "vox serve: {out:?}");
        let cid = alice.view().channels[0].channel_id;
        assert_eq!(
            alice.view().open_channels[0].services.clone(),
            vec![(tag.clone(), service_addr)],
            "the same command declared the service"
        );

        // The hostname a person types is the room id with `.vox` on it, and it round
        // trips — so a client derives it from the address it was handed.
        let hostname = vox_hostname(&cid);
        assert!(hostname.starts_with(&b32_encode(&cid)));
        assert_eq!(channel_of_hostname(&hostname).unwrap(), cid);

        // ---- `vox connect <address>`: Bob joins, and that is the whole of it ----
        assert!(alice
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        // The address carries the hostname's 52 characters, which is why no extra field
        // is needed anywhere.
        assert!(
            url.contains(&b32_encode(&cid)),
            "the address begins with the room id: {url}"
        );
        assert!(
            !url.contains("generated passphrase"),
            "the passphrase is never in the address: {url}"
        );

        let bob = node(&tmp, "bob", b_sock, BootstrapSet::new()).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        assert!(bob
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "infra".into(),
                passphrase: secret("generated passphrase"),
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

        // ---- and he reaches it, with no grant having been issued to anyone ----
        //
        // NOTE: there is deliberately no `GrantTunnel` anywhere in this test. Joining
        // was the authorization (ADR-017 decision 3).
        let out = bob
            .apply(NodeCommand::Forward {
                channel_id: cid,
                host: alice_fp,
                service_tag: tag.clone(),
                local: addr("127.0.0.1:0"),
            })
            .await;
        assert!(out.is_done(), "the forward binds: {out:?}");
        let local = wait_for(&bob, |e| match e {
            NodeEvent::Forwarding { local, .. } => Some(local),
            _ => None,
        })
        .await;

        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let msg = b"a room-bound service reached with no grant step";
            let mut app = tokio::net::TcpStream::connect(local).await.unwrap();
            app.write_all(msg).await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            tokio::time::timeout(TIMEOUT, app.read_exact(&mut buf))
                .await
                .expect("the tunnel carried the bytes")
                .expect("a full read");
            assert_eq!(buf, msg, "the service echoed byte for byte");
        }

        // The host is told who reached what. It has to be told: the echo service — like
        // `sshd` — saw a connection from `127.0.0.1` and can say nothing else.
        let (client, served_tag) = wait_for(&alice, |e| match e {
            NodeEvent::TunnelServed {
                channel_id,
                client,
                service_tag,
            } if channel_id == cid => Some((client, service_tag)),
            _ => None,
        })
        .await;
        assert_eq!(client, bob_fp, "named by identity, not by address");
        assert_eq!(served_tag, tag);

        let _ = bob.apply(NodeCommand::StopForward { local }).await;
        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}
