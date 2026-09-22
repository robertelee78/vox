//! ADR-012 M15.1b — a pair that starts out relayed keeps trying for a direct path.
//!
//! A relayed path works, so nothing forces a retry. But it spends a third party's bandwidth,
//! adds a hop of latency, and lets that third party see that two identities are talking. The
//! single attempt made at dial time happens at the worst possible moment: neither side has
//! learned the other's addresses, and whatever is blocking a direct path is at its most
//! likely. Without a retry, a pair that starts relayed stays relayed for the life of the
//! connection.
//!
//! The scenario is the one that actually happens in the field: both peers begin behind
//! symmetric NATs, where hole punching cannot work (ADR-012's documented limit), so the only
//! path is a circuit through their anchor. Then one of them moves to a network that *is*
//! punchable — a different wifi, a captive portal released, a router that stopped being
//! hostile — and from that moment a direct path is possible. Nothing tells the node so.
//!
//! What this asserts: the node discovers it anyway, within one retry interval, and stops
//! paying for the relay.
//!
//! The clock is injected, so the hour is not spent waiting for it.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vnet::{NatKind, VirtualNet};
use vox_core::identity::composite::RootSigner;
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
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

#[test]
#[ignore = "a relayed join plus a path upgrade; CI runs it in the release step"]
fn a_relayed_pair_finds_a_direct_path_once_one_becomes_possible() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // A clock the test drives, so a 60-second retry interval costs no wall clock.
        let now = Arc::new(AtomicU64::new(1_800_000_000));
        let clock: vox_core::time::Clock = {
            let now = Arc::clone(&now);
            Arc::new(move || now.load(Ordering::SeqCst))
        };

        let net = VirtualNet::new();
        let c_addr = addr("198.51.100.1:443");
        let c_sock = net.public(c_addr);
        // NAT 0 is Alice's, NAT 1 is Bob's — the order of these calls is the index
        // `set_nat_kind` takes.
        let a_sock = net.behind_nat(addr("10.0.1.2:5000"), NatKind::Symmetric, ip("203.0.113.1"));
        let b_sock = net.behind_nat(addr("10.0.2.2:5000"), NatKind::Symmetric, ip("203.0.113.2"));

        // The anchor, headless.
        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let carol_fp = RootSigner::public_key(&carol_signer).fingerprint();
        let _carol = Node::spawn_config(
            paths(&tmp, "anchor"),
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

        let alice = node(&tmp, "alice", a_sock, anchors.clone(), Arc::clone(&clock)).await;
        let bob = node(&tmp, "bob", b_sock, anchors, Arc::clone(&clock)).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;

        // One room, joined through the anchor. Both are behind symmetric NATs, so the only
        // path between them is a circuit the anchor carries.
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

        // Alice reaches Bob. Symmetric NATs both sides: this can only be a circuit.
        let relayed = tokio::time::timeout(TIMEOUT, async {
            loop {
                if alice.view().relayed_peers.contains(&bob_fp) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            relayed.is_ok(),
            "alice should reach bob over a relay to begin with — both are behind symmetric \
             NATs, so there is no other path, and if this never happens the test proves nothing"
        );

        // The world improves: both networks become punchable. Both, because a punch needs
        // an endpoint-independent mapping at *each* end — one symmetric NAT is enough to
        // defeat it (ADR-012), so flipping only one side would leave the relay the only
        // possible path and the test would assert nothing about the retry.
        net.set_nat_kind(0, NatKind::PortRestrictedCone);
        net.set_nat_kind(1, NatKind::PortRestrictedCone);

        // One retry interval passes.
        now.fetch_add(61, Ordering::SeqCst);

        let upgraded = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if !alice.view().relayed_peers.contains(&bob_fp) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            upgraded.is_ok(),
            "alice is still relayed through the anchor a full retry interval after a direct \
             path became possible — nothing retries the upgrade, so a pair that starts \
             relayed pays a third party's bandwidth and an extra hop for the life of the \
             connection"
        );

        for h in [&alice, &bob] {
            let _ = h.apply(NodeCommand::Shutdown).await;
        }
    });
}
