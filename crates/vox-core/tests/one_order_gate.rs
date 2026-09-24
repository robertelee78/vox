//! ADR-023 M23.2 / PRD-001 R13 — one order on every node, on three real in-process [`Node`]s.
//!
//! The same claim as `crates/vox-tui/tests/causal_order_proof.rs` proof 1, on the nodes the
//! shipped daemon runs, networked over loopback. It exists beside the daemon proof because three
//! `vox daemon`s do not converge today for a reason below the log: the second joiner's records are
//! refused by the boards and no session with it ever runs (reproduced on the base without
//! M23.2). The order is measured the same way: [`ChannelDetail::order`] is exactly what
//! `vox room read --hashes` prints.
//!
//! Three members post at once; one is shut down while the other two keep posting; it starts again
//! on the same store and address, and all three post at once again. After convergence every node
//! holds the identical sequence (length and SHA-256 printed), and each timeline is that sequence
//! restricted to the rows the node can read, in the same relative order.
//!
//! Mutation: the order taken from arrival — red, the three sequences differ.
//!
//! [`ChannelDetail::order`]: vox_core::node::api::ChannelDetail::order

#[path = "support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use vox_core::hash::Digest32;
use vox_core::join::pow::PowParams;
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{ChannelDetail, NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(90);
/// Messages each poster writes per round.
const PER_ROUND: usize = 6;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

fn config(at: std::net::SocketAddr) -> NodeConfig {
    let mut cfg = NodeConfig::new().bind(Bind::Addr(at));
    // The join's PoW is not what this gate is about; the M14 gate exercises the real one.
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    cfg
}

/// A loopback UDP port nothing holds right now, so a node that restarts comes back on the address
/// its peers already have for it.
fn free_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
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

fn detail(h: &NodeHandle, cid: Digest32) -> ChannelDetail {
    h.view()
        .open_channels
        .into_iter()
        .find(|d| d.channel_id == cid)
        .expect("the room is open")
}

async fn post(h: &NodeHandle, cid: Digest32, text: String) {
    let out = h
        .apply(NodeCommand::SendText {
            channel_id: cid,
            text: text.clone(),
        })
        .await;
    assert!(out.is_done(), "post {text:?}: {out:?}");
}

/// Every poster writes [`PER_ROUND`] messages `"<round> <who> <i>"` at the same time.
async fn round(cid: Digest32, round: &str, posters: &[(&NodeHandle, &str)]) {
    let mut tasks = Vec::new();
    for (h, who) in posters {
        let h = (*h).clone();
        let (round, who) = (round.to_owned(), (*who).to_owned());
        tasks.push(tokio::spawn(async move {
            for i in 1..=PER_ROUND {
                post(&h, cid, format!("{round} {who} {i}")).await;
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

async fn start(tmp: &tempfile::TempDir, name: &str, at: std::net::SocketAddr) -> NodeHandle {
    // A restarted node's store is released when the old actor's last handle goes; retry until it is.
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match Node::spawn_config(paths(tmp, name), config(at)) {
                Ok(h) => return h,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .expect("the node opened its store")
}

fn digest(seq: &[Digest32]) -> String {
    vox_core::hash::sha256(&seq.concat())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
#[ignore = "three networked nodes with production Argon2id; CI runs it in release"]
fn three_nodes_one_offline_for_a_while_hold_one_order() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let carol_at = free_port();
        let alice = start(&tmp, "alice", "127.0.0.1:0".parse().unwrap()).await;
        let bob = start(&tmp, "bob", "127.0.0.1:0".parse().unwrap()).await;
        let carol = start(&tmp, "carol", carol_at).await;
        for h in [&alice, &bob, &carol] {
            assert!(h
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret("identity passphrase")
                })
                .await
                .is_done());
        }
        let fp = |h: &NodeHandle| h.view().identity.unwrap().fingerprint;
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "r".into(),
                passphrase: secret("room passphrase"),
            })
            .await
            .is_done());
        let cid = alice.view().channels[0].channel_id;
        for (who, name) in [(&bob, "bob"), (&carol, "carol")] {
            assert!(alice
                .apply(NodeCommand::Invite { channel_id: cid })
                .await
                .is_done());
            let url = wait_for(&alice, |e| match e {
                NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
                _ => None,
            })
            .await;
            assert!(
                who.apply(NodeCommand::JoinChannel {
                    link: url,
                    local_name: "r".into(),
                    passphrase: secret("room passphrase"),
                })
                .await
                .is_done(),
                "{name} joins"
            );
            wait_for(who, |e| match e {
                NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
                _ => None,
            })
            .await;
            assert!(who
                .apply(NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret("room passphrase"),
                })
                .await
                .is_done());
        }
        let all = [(&alice, "alice"), (&bob, "bob"), (&carol, "carol")];
        for (a, _) in all {
            for (b, bname) in all {
                if fp(a) != fp(b) {
                    assert!(a
                        .apply(NodeCommand::Trust {
                            fingerprint: fp(b),
                            petname: bname.into()
                        })
                        .await
                        .is_done());
                }
            }
        }

        // ---- all three at once; carol goes down; two keep going; carol back; all three --------
        round(
            cid,
            "one",
            &[(&alice, "alice"), (&bob, "bob"), (&carol, "carol")],
        )
        .await;
        assert!(carol.apply(NodeCommand::Shutdown).await.is_done());
        drop(carol);
        round(cid, "two", &[(&alice, "alice"), (&bob, "bob")]).await;
        let carol = start(&tmp, "carol", carol_at).await;
        // Unlocking binds carol's old address, which the stopped instance may not have released
        // yet; retried until it has.
        let unlock_started = Instant::now();
        loop {
            let out = carol
                .apply(NodeCommand::Unlock {
                    passphrase: secret("identity passphrase"),
                })
                .await;
            if out.is_done() {
                break;
            }
            assert!(
                unlock_started.elapsed() < TIMEOUT,
                "carol's restarted node never unlocked: {out:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(carol
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("room passphrase"),
            })
            .await
            .is_done());
        round(
            cid,
            "three",
            &[(&alice, "alice"), (&bob, "bob"), (&carol, "carol")],
        )
        .await;
        let posted = PER_ROUND * 8;

        // ---- converged: one entry set on all three (a set: the order is what is measured) -----
        let nodes = [(&alice, "alice"), (&bob, "bob"), (&carol, "carol")];
        let started = Instant::now();
        let mut stable = 0;
        let orders: Vec<Vec<Digest32>> = loop {
            let orders: Vec<Vec<Digest32>> =
                nodes.iter().map(|(h, _)| detail(h, cid).order).collect();
            let sets: Vec<BTreeSet<&Digest32>> =
                orders.iter().map(|o| o.iter().collect()).collect();
            let alice_reads = detail(&alice, cid)
                .timeline
                .iter()
                .filter(|r| {
                    ["one ", "two ", "three "]
                        .iter()
                        .any(|p| r.text.starts_with(p))
                })
                .count();
            if sets.windows(2).all(|w| w[0] == w[1]) && alice_reads == posted {
                stable += 1;
                if stable == 2 {
                    break orders;
                }
            } else {
                stable = 0;
            }
            assert!(
                started.elapsed() < Duration::from_secs(180),
                "never converged: entries held {:?}, alice reads {alice_reads} of {posted}",
                orders.iter().map(Vec::len).collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        println!("converged in {} ms", started.elapsed().as_millis());
        for ((_, who), o) in nodes.iter().zip(&orders) {
            println!("{who}: {} entries, order sha256 {}", o.len(), digest(o));
        }
        for ((_, who), o) in nodes.iter().zip(&orders).skip(1) {
            let first = o.iter().zip(&orders[0]).position(|(a, b)| a != b);
            assert!(
                *o == orders[0],
                "{who}'s order differs from alice's (first difference at {first:?}) — the room \
                 shows two orders"
            );
        }
        for (h, who) in nodes {
            let d = detail(h, cid);
            let mut last = None;
            for r in &d.timeline {
                let at = orders[0]
                    .iter()
                    .position(|x| *x == r.entry_hash)
                    .unwrap_or_else(|| panic!("{who} shows {:?}, which it does not hold", r.text));
                assert!(
                    last.is_none_or(|l| l < at),
                    "{who}'s timeline shows {:?} out of the room's order",
                    r.text
                );
                last = Some(at);
            }
            let late = d.timeline.iter().filter(|r| r.late).count();
            println!(
                "{who}: its {} readable rows are in the room's order ({late} arrived late)",
                d.timeline.len()
            );
        }
        for (h, _) in nodes {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}
