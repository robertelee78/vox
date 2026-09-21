//! ADR-020 §3 / ADR-017 **M17.14 gate** — removing a key from the ring **changes
//! the lock**.
//!
//! The requirement, added to ADR-020 after M19.2 shipped: *"Removing a key from
//! the ring MUST change the lock."* Read access is a sender key already handed
//! over, so removal cannot take it back — it can only stop the removed party
//! reading what comes **next**. Removal therefore rotates this identity's sender
//! key and re-keys everyone still in the ring, in every room shared with the
//! removed party.
//!
//! M19.2's `Untrust` did not do this. Its own doc comment said so, and the ADR
//! quoted that comment as the defect.
//!
//! The gate as ADR-017 states it: a key trusted, used to read, then removed
//! cannot read a message published after the removal, **in every shared room**,
//! while a third identity that stays trusted reads it throughout. Hence **two**
//! rooms here, not one — a single-room gate would pass even if removal only ever
//! changed the lock in whichever room happened to come first.
//!
//! - Bob and Carol are both trusted, both read Alice, in **both** rooms.
//! - Alice untrusts Bob — one act, node-wide.
//! - **Carol keeps reading everything, in both rooms** — the rotation is invisible
//!   to her, no gap and no missing message, because she is re-keyed at the new
//!   generation's origin.
//! - **Bob reads nothing published afterwards, in either room**, while still
//!   receiving the ciphertext by ordinary sync (asserted by his entry count
//!   keeping up, so a pass cannot come from him merely being behind).
//! - **Bob keeps what he already had.** That is the honest limit — ADR-007's
//!   enforcement honesty — and asserting it stops the gate from implying a
//!   guarantee no protocol can give.
//!
//! Mutation-checked by removing the lock change from `Untrust`: Bob then keeps
//! reading, which is exactly the M19.2 behaviour this replaces.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, NodeView, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
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

fn entries(view: &NodeView, cid: [u8; 32]) -> u64 {
    view.channels
        .iter()
        .find(|c| c.channel_id == cid)
        .map_or(0, |c| c.entries)
}

async fn until(h: &NodeHandle, what: &str, mut ok: impl FnMut(&NodeView) -> bool) {
    tokio::time::timeout(TIMEOUT, async {
        while !ok(&h.view()) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// Stand up one room with Bob and Carol joined and everybody's view open.
async fn room(
    alice: &NodeHandle,
    bob: &NodeHandle,
    carol: &NodeHandle,
    name: &str,
    pass: &str,
) -> [u8; 32] {
    assert!(alice
        .apply(NodeCommand::CreateChannel {
            local_name: name.into(),
            passphrase: secret(pass),
        })
        .await
        .is_done());
    let cid = alice
        .view()
        .channels
        .iter()
        .find(|c| c.local_name.as_deref() == Some(name))
        .expect("the room just created")
        .channel_id;
    assert!(alice
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(alice, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await;

    for (who, who_name) in [(bob, "bob"), (carol, "carol")] {
        assert!(
            who.apply(NodeCommand::JoinChannel {
                link: url.clone(),
                local_name: name.into(),
                passphrase: secret(pass),
            })
            .await
            .is_done(),
            "{who_name} joins {name}"
        );
        let _ = wait_for(who, |e| match e {
            NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
            _ => None,
        })
        .await;
    }
    for who in [alice, bob, carol] {
        assert!(who
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret(pass),
            })
            .await
            .is_done());
    }
    cid
}

#[test]
#[ignore = "production Argon2id + (200,9) Equihash, two rooms; CI runs it in release"]
fn m19_removing_a_key_from_the_ring_changes_the_lock_in_every_shared_room() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let alice = node(&tmp, "alice").await;
        let bob = node(&tmp, "bob").await;
        let carol = node(&tmp, "carol").await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        let carol_fp = carol.view().identity.unwrap().fingerprint;

        // TWO rooms, both shared with Bob. One room would pass even if removal
        // only ever changed the lock in whichever room came first.
        let one = room(&alice, &bob, &carol, "team-one", "passphrase one").await;
        let two = room(&alice, &bob, &carol, "team-two", "passphrase two").await;

        // One ring, one decision, both rooms.
        for (fp, name) in [(bob_fp, "bob"), (carol_fp, "carol")] {
            assert!(alice
                .apply(NodeCommand::Trust {
                    fingerprint: fp,
                    petname: name.into(),
                })
                .await
                .is_done());
        }

        for cid in [one, two] {
            assert!(alice
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: "before removal".into(),
                })
                .await
                .is_done());
        }
        for cid in [one, two] {
            until(&bob, "bob to read before removal", |v| {
                texts(v, cid).iter().any(|t| t == "before removal")
            })
            .await;
            until(&carol, "carol to read before removal", |v| {
                texts(v, cid).iter().any(|t| t == "before removal")
            })
            .await;
        }

        // ---- the act under test: one removal, node-wide ----
        assert!(
            alice
                .apply(NodeCommand::Untrust {
                    fingerprint: bob_fp
                })
                .await
                .is_done(),
            "untrust"
        );
        assert!(
            !alice.view().trusted.iter().any(|(fp, _)| *fp == bob_fp),
            "bob is still in the ring"
        );

        for cid in [one, two] {
            for i in 0..2 {
                assert!(alice
                    .apply(NodeCommand::SendText {
                        channel_id: cid,
                        text: format!("after removal {i}"),
                    })
                    .await
                    .is_done());
            }
        }

        // Carol was re-keyed at the new generation's origin in both rooms.
        for cid in [one, two] {
            until(&carol, "carol to read past the rotation", |v| {
                texts(v, cid).iter().any(|t| t == "after removal 1")
            })
            .await;
            // Bob still receives the ciphertext, so a pass below cannot be him
            // merely being behind.
            until(&bob, "bob to receive the ciphertext", |v| {
                entries(v, cid) >= entries(&alice.view(), cid)
            })
            .await;
        }
        // Let any in-flight delivery land before judging what Bob can open.
        tokio::time::sleep(Duration::from_secs(3)).await;

        for (cid, which) in [(one, "team-one"), (two, "team-two")] {
            let bob_texts = texts(&bob.view(), cid);
            let carol_texts = texts(&carol.view(), cid);

            assert_eq!(
                carol_texts.len(),
                3,
                "carol should read everything in {which}, with no gap: {carol_texts:?}"
            );

            for i in 0..2 {
                let after = format!("after removal {i}");
                assert!(
                    !bob_texts.contains(&after),
                    "the lock did not change in {which} — bob read {after:?} after \
                     being removed from the ring: {bob_texts:?}"
                );
            }
            // The honest limit: what he already had is still his.
            assert!(
                bob_texts.iter().any(|t| t == "before removal"),
                "bob should keep the history he already held in {which} — ADR-007 \
                 enforcement honesty, and claiming otherwise would be a lie: {bob_texts:?}"
            );
        }
    });
}
