//! ADR-016 **M14 gate** — two machines chat, in one process over loopback QUIC, on
//! the production Argon2id profile (this is an integration test: `vox-core` is
//! linked without `cfg(test)`, so the reduced test profile does not exist here).
//!
//! The ADR's words: "an integration test runs two nodes in one process over loopback
//! QUIC — create, invite, join with the passphrase, consent, exchange messages both
//! ways, and a third node that joins and is *not* consented reads nothing."
//!
//! Everything here goes through the client API — `NodeCommand` in, `NodeView` and
//! `NodeEvent` out — so it exercises the same surface a client uses, not internals.
//! Real Argon2id (six derivations per node) plus a production `(200,9)` Equihash
//! solve per join make this ≈ 20 s in release and minutes unoptimized: `#[ignore]`d
//! in the debug suite, run by CI's release step with the other real-parameter gates.

use std::sync::Arc;
use std::time::Duration;

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, Outcome, Secret};
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

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

/// Spawn a networked node and create its identity.
async fn node(tmp: &tempfile::TempDir, name: &str) -> NodeHandle {
    let h = Node::spawn_networked(paths(tmp, name), "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase")
        })
        .await
        .is_done());
    assert!(
        !h.view().listening.is_empty(),
        "{name} is listening once unlocked"
    );
    h
}

/// Drain events until one matches, or fail.
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

/// Drain events until `done` is satisfied by everything seen so far. Two joins and
/// two key releases race, so the test must not depend on their order: the whole set
/// is accumulated rather than matched one event at a time.
async fn drain_until(h: &NodeHandle, mut done: impl FnMut(&[NodeEvent]) -> bool) -> Vec<NodeEvent> {
    let mut seen = Vec::new();
    tokio::time::timeout(TIMEOUT, async {
        while !done(&seen) {
            match h.next_event().await {
                Some(e) => seen.push(e),
                None => panic!("event stream ended"),
            }
        }
    })
    .await
    .expect("events did not arrive");
    seen
}

fn is_peer_joined(e: &NodeEvent, cid: [u8; 32], who: [u8; 32]) -> bool {
    match e {
        NodeEvent::PeerJoined { channel_id, peer } => *channel_id == cid && *peer == who,
        _ => false,
    }
}

fn is_key_from(e: &NodeEvent, cid: [u8; 32], who: [u8; 32]) -> bool {
    match e {
        NodeEvent::SenderKeyReceived {
            channel_id, peer, ..
        } => *channel_id == cid && *peer == who,
        _ => false,
    }
}

#[test]
#[ignore = "production Argon2id + (200,9) Equihash: ~20 s in release, minutes unoptimized; CI runs it in release"]
fn m14_two_nodes_chat_and_an_unconsented_third_reads_nothing() {
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // ---- create ----
        let alice = node(&tmp, "alice").await;
        let bob = node(&tmp, "bob").await;
        let carol = node(&tmp, "carol").await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        let carol_fp = carol.view().identity.unwrap().fingerprint;

        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = alice.view().channels[0].channel_id;
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "before anyone joined".into(),
            })
            .await
            .is_done());

        // ---- invite ----
        assert!(alice
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        assert!(url.starts_with("vox://"));
        assert!(
            !url.contains("channel passphrase"),
            "the link carries no secret: {url}"
        );

        // ---- join with the passphrase (out of band, never from the link) ----
        assert!(bob
            .apply(NodeCommand::JoinChannel {
                link: url.clone(),
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let (joined_cid, responder) = wait_for(&bob, |e| match e {
            NodeEvent::Joined {
                channel_id,
                responder,
            } => Some((channel_id, responder)),
            _ => None,
        })
        .await;
        assert_eq!(joined_cid, cid);
        assert_eq!(responder, alice_fp);
        // A wrong passphrase cannot join.
        assert_eq!(
            carol
                .apply(NodeCommand::JoinChannel {
                    link: url.clone(),
                    local_name: "team".into(),
                    passphrase: secret("wrong passphrase"),
                })
                .await,
            Outcome::Failed(Fault::Refused)
        );
        // Carol joins properly — she is in the swarm, and consented to by nobody.
        assert!(carol
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let _ = wait_for(&carol, |e| match e {
            NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
            _ => None,
        })
        .await;
        // Alice saw both joins, admitted both as log authors, and took the sender key
        // each newcomer released as part of joining (ADR-007 step 2). She needs Bob's
        // before she can answer on that session at all: the ADR-004 responder has no
        // sending chain until it has received.
        let seen = drain_until(&alice, |evs| {
            evs.iter().any(|e| is_peer_joined(e, cid, bob_fp))
                && evs.iter().any(|e| is_peer_joined(e, cid, carol_fp))
                && evs.iter().any(|e| is_key_from(e, cid, bob_fp))
        })
        .await;
        assert!(seen.iter().any(|e| is_key_from(e, cid, bob_fp)));

        // ---- consent: Alice ↔ Bob only ----
        let out = alice
            .apply(NodeCommand::Consent {
                channel_id: cid,
                target: bob_fp,
            })
            .await;
        assert!(out.is_done(), "Alice consents to Bob: {out:?}");
        // Bob takes Alice's key. He already released his own when he joined, so
        // nothing further is needed from him for Alice to read him.
        let _ = drain_until(&bob, |evs| {
            evs.iter().any(|e| is_key_from(e, cid, alice_fp))
        })
        .await;

        // ---- exchange messages both ways ----
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "hello bob".into(),
            })
            .await
            .is_done());
        assert!(bob
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "hello alice".into(),
            })
            .await
            .is_done());
        let a_sync = alice.apply(NodeCommand::Sync { channel_id: cid }).await;
        assert!(a_sync.is_done(), "Alice syncs: {a_sync:?}");
        let b_sync = bob.apply(NodeCommand::Sync { channel_id: cid }).await;
        assert!(b_sync.is_done(), "Bob syncs: {b_sync:?}");

        let texts = |h: &NodeHandle| -> Vec<String> {
            h.view()
                .open_channels
                .iter()
                .find(|d| d.channel_id == cid)
                .map(|d| d.timeline.iter().map(|r| r.text.clone()).collect())
                .unwrap_or_default()
        };
        let alice_texts = texts(&alice);
        let bob_texts = texts(&bob);
        assert!(
            alice_texts.contains(&"hello alice".to_string()),
            "Alice reads Bob: {alice_texts:?}"
        );
        assert!(
            bob_texts.contains(&"hello bob".to_string()),
            "Bob reads Alice: {bob_texts:?}"
        );
        // Forward-only history: Bob never sees what Alice wrote before consenting.
        assert!(
            !bob_texts.contains(&"before anyone joined".to_string()),
            "{bob_texts:?}"
        );

        // ---- the unconsented third reads nothing ----
        assert!(carol
            .apply(NodeCommand::Sync { channel_id: cid })
            .await
            .is_done());
        let carol_view = carol.view();
        let carol_summary = carol_view
            .channels
            .iter()
            .find(|c| c.channel_id == cid)
            .expect("Carol holds the channel");
        assert!(
            carol_summary.entries > 0,
            "Carol received the log: {} entries",
            carol_summary.entries
        );
        let carol_detail = carol_view
            .open_channels
            .iter()
            .find(|d| d.channel_id == cid)
            .expect("Carol has it open");
        assert!(
            carol_detail.timeline.is_empty(),
            "an unconsented member reads nothing: {:?}",
            carol_detail.timeline
        );

        // ---- locking takes the network down ----
        assert!(alice.apply(NodeCommand::Lock).await.is_done());
        assert!(alice.view().listening.is_empty());
        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
        drop(Arc::new(()));
    });
}
