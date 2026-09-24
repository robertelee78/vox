//! ADR-021 F12 — **two members who joined a room can read each other**.
//!
//! In a room of three, alice creates and bob and carol join through alice's invite.
//! Everybody puts everybody else in their trust keyring. Creator↔joiner reads have
//! always worked; this is the case a user meets the moment a third person arrives:
//! **bob must read carol, and carol must read bob**, though neither ever met the
//! other on the join path.
//!
//! In-process nodes on loopback, no anchor. Every node waits for the whole set of
//! sender keys it is owed in ONE loop — events are consumed as they are read, so
//! waiting for one peer at a time discards the event for the next.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::time::Duration;

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, NodeView, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

async fn node(tmp: &tempfile::TempDir, name: &str) -> NodeHandle {
    let paths = Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
    let h = Node::spawn_networked(paths, "127.0.0.1:0".parse().unwrap()).unwrap();
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

fn texts(view: &NodeView, cid: [u8; 32]) -> Vec<String> {
    view.open_channels
        .iter()
        .find(|d| d.channel_id == cid)
        .map(|d| d.timeline.iter().map(|r| r.text.clone()).collect())
        .unwrap_or_default()
}

async fn reads(h: &NodeHandle, cid: [u8; 32], what: &str) -> bool {
    tokio::time::timeout(TIMEOUT, async {
        while !texts(&h.view(), cid).iter().any(|t| t == what) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok()
}

#[test]
#[ignore = "three networked nodes with production Argon2id; CI runs it in release"]
fn f12_two_members_who_joined_read_each_other() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let alice = node(&tmp, "alice").await;
        let bob = node(&tmp, "bob").await;
        let carol = node(&tmp, "carol").await;
        let fp = |h: &NodeHandle| h.view().identity.unwrap().fingerprint;
        let names = [
            (fp(&alice), "alice"),
            (fp(&bob), "bob"),
            (fp(&carol), "carol"),
        ];

        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "mission".into(),
                passphrase: secret("room passphrase"),
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
        for (who, name) in [(&bob, "bob"), (&carol, "carol")] {
            assert!(
                who.apply(NodeCommand::JoinChannel {
                    link: url.clone(),
                    local_name: "mission".into(),
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
        }
        for who in [&alice, &bob, &carol] {
            assert!(who
                .apply(NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret("room passphrase"),
                })
                .await
                .is_done());
        }
        // Everybody trusts everybody: all six edges.
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

        // Every node waits, in one loop, for the whole set of sender keys it is owed.
        let mut missing = Vec::new();
        for (a, aname) in all {
            let mut owed: BTreeSet<[u8; 32]> = [&alice, &bob, &carol]
                .iter()
                .map(|h| fp(h))
                .filter(|f| *f != fp(a))
                .collect();
            let got = tokio::time::timeout(TIMEOUT, async {
                while !owed.is_empty() {
                    match a.next_event().await {
                        Some(NodeEvent::SenderKeyReceived {
                            channel_id, peer, ..
                        }) if channel_id == cid => {
                            owed.remove(&peer);
                        }
                        Some(_) => {}
                        None => return,
                    }
                }
            })
            .await;
            if got.is_err() || !owed.is_empty() {
                let who: Vec<&str> = owed
                    .iter()
                    .map(|f| names.iter().find(|(n, _)| n == f).map_or("?", |(_, s)| *s))
                    .collect();
                missing.push(format!("{aname} never received the sender key of {who:?}"));
            }
        }

        // The property itself: each joiner reads what the other writes.
        for (who, text) in [(&bob, "from bob"), (&carol, "from carol")] {
            assert!(who
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: text.into()
                })
                .await
                .is_done());
        }
        let carol_reads_bob = reads(&carol, cid, "from bob").await;
        let bob_reads_carol = reads(&bob, cid, "from carol").await;
        let alice_reads_both =
            reads(&alice, cid, "from bob").await && reads(&alice, cid, "from carol").await;
        for (h, n) in [(&alice, "alice"), (&bob, "bob"), (&carol, "carol")] {
            let v = h.view();
            let e = v
                .channels
                .iter()
                .find(|c| c.channel_id == cid)
                .map(|c| c.entries);
            eprintln!(
                "[receipt] {n} fp={} entries={e:?} texts={:?}",
                &vox_core::node::link::b32_encode(&fp(h))[..6],
                texts(&v, cid)
            );
        }
        assert!(
            carol_reads_bob && bob_reads_carol && missing.is_empty(),
            "F12: carol reads bob = {carol_reads_bob}, bob reads carol = {bob_reads_carol} \
             (alice reads both = {alice_reads_both}); {missing:?}"
        );
    });
}
