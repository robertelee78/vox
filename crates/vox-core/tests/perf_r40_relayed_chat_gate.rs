//! PRD-001 **R40, forced-relay path** — a chat message between two online nodes arrives in
//! **under 1 s** when the only path between them is a circuit through their anchor.
//!
//! The shipped binary has no switch that forces a relay, so this runs where a relay is the
//! only possibility: real nodes on the NAT simulator (`support/vnet.rs`), both behind
//! **symmetric** NATs, which defeat hole punching (ADR-012's documented limit). Every node
//! is a real `Node` with production Argon2id, joined and trusted through the product's own
//! commands; the relay is asserted, not assumed, before and after the samples.
//!
//! [`SAMPLES`] times, alice sends and the clock stops when bob's node renders the text,
//! polled every [`POLL`]. Printed as min / median / p95 / max; the PRD target is asserted
//! on every sample.
//!
//! The simulator delivers every datagram at once, with no loss, so this measures what the
//! node adds on a relayed path — scheduling, the extra hop's processing — and not a real
//! network's latency. A red here is the node's.
//!
//! Mutation knobs (test-side only): `VOX_PERF_THRESHOLD_MS` replaces the target;
//! `VOX_PERF_INJECT_MS` sleeps inside the timed window before the send.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vnet::{NatKind, VirtualNet};
use vox_core::identity::composite::RootSigner;
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);
const TARGET: Duration = Duration::from_millis(1000);
const SAMPLES: usize = 25;
const POLL: Duration = Duration::from_millis(5);

fn env_ms(name: &str) -> Option<Duration> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
}
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
fn uptime() -> String {
    std::process::Command::new("uptime")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// min / median / p95 / max, nearest-rank.
fn stats(label: &str, samples: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let mut s = samples.to_vec();
    s.sort();
    let at = |q: f64| s[((q * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1];
    let out = (s[0], at(0.5), at(0.95), s[s.len() - 1]);
    eprintln!(
        "{label}: n={} min={:?} median={:?} p95={:?} max={:?}",
        s.len(),
        out.0,
        out.1,
        out.2,
        out.3
    );
    out
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

fn renders(h: &NodeHandle, text: &str) -> bool {
    h.view()
        .open_channels
        .iter()
        .any(|c| c.timeline.iter().any(|r| r.text == text))
}

#[test]
#[ignore = "a relayed join on the NAT simulator with production Argon2id; CI runs it in release"]
fn r40_a_message_arrives_in_under_a_second_over_a_forced_relay() {
    watchdog::arm();
    let target = env_ms("VOX_PERF_THRESHOLD_MS").unwrap_or(TARGET);
    let inject = env_ms("VOX_PERF_INJECT_MS").unwrap_or_default();
    eprintln!("uptime at start: {}", uptime());
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

        let carol_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let carol_fp = RootSigner::public_key(&carol_signer).fingerprint();
        let _carol = Node::spawn_config(
            paths(&tmp, "anchor"),
            NodeConfig::new()
                .bind(Bind::Socket(c_sock))
                .headless(carol_signer),
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

        let alice = node(&tmp, "alice", a_sock, anchors.clone()).await;
        let bob = node(&tmp, "bob", b_sock, anchors).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        let bob_fp = bob.view().identity.unwrap().fingerprint;

        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "room".into(),
                passphrase: secret("room passphrase"),
            })
            .await
            .is_done());
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
        assert!(out.is_done(), "CANNOT MEASURE: bob's join failed: {out:?}");

        let relayed = tokio::time::timeout(TIMEOUT, async {
            while !alice.view().relayed_peers.contains(&bob_fp) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            relayed.is_ok(),
            "CANNOT MEASURE: alice never reached bob over a relay"
        );

        for (who, peer, name) in [(&alice, bob_fp, "bob"), (&bob, alice_fp, "alice")] {
            assert!(who
                .apply(NodeCommand::Trust {
                    fingerprint: peer,
                    petname: name.into(),
                })
                .await
                .is_done());
        }
        for (who, peer) in [(&alice, bob_fp), (&bob, alice_fp)] {
            wait_for(who, |e| match e {
                NodeEvent::SenderKeyReceived { peer: p, .. } if p == peer => Some(()),
                _ => None,
            })
            .await;
        }
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "warm-up".into(),
            })
            .await
            .is_done());
        let warmed = tokio::time::timeout(TIMEOUT, async {
            while !renders(&bob, "warm-up") {
                tokio::time::sleep(POLL).await;
            }
        })
        .await;
        if warmed.is_err() {
            // Say what each side can see before failing, so the red names its cause.
            for (who, h) in [("alice", &alice), ("bob", &bob)] {
                let v = h.view();
                eprintln!(
                    "[{who}] connected={} relayed={} rows={}",
                    v.connected,
                    v.relayed_peers.len(),
                    v.open_channels
                        .iter()
                        .map(|c| c.timeline.len())
                        .sum::<usize>()
                );
                while let Ok(Some(e)) =
                    tokio::time::timeout(Duration::from_millis(100), h.next_event()).await
                {
                    eprintln!("[{who} said] {e:?}");
                }
            }
            panic!("CANNOT MEASURE: the warm-up never crossed the relay in {TIMEOUT:?}");
        }

        let mut samples = Vec::new();
        for i in 0..SAMPLES {
            let text = format!("r40 relayed sample {i:02}");
            let t0 = Instant::now();
            tokio::time::sleep(inject).await;
            assert!(alice
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: text.clone(),
                })
                .await
                .is_done());
            let arrived = tokio::time::timeout(Duration::from_secs(60), async {
                while !renders(&bob, &text) {
                    tokio::time::sleep(POLL).await;
                }
            })
            .await;
            assert!(
                arrived.is_ok(),
                "sample {i} never crossed the relay in 60 s"
            );
            samples.push(t0.elapsed());
        }
        assert!(
            alice.view().relayed_peers.contains(&bob_fp),
            "the pair must still be relayed after the samples, or this measured a direct path"
        );
        eprintln!("uptime at end: {}", uptime());
        let (_, _, _, max) = stats("R40 relayed (send -> rendered on the peer)", &samples);
        let over = samples.iter().filter(|d| **d >= target).count();
        assert!(
            max < target,
            "R40 (relayed): {over} of {SAMPLES} messages took {target:?} or longer; the slowest \
             took {max:?}"
        );
        for h in [&alice, &bob] {
            let _ = h.apply(NodeCommand::Shutdown).await;
        }
    });
}
