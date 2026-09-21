//! ADR-016 **M15 gate** — a member opens a pairwise session from another member's
//! **bundle record**, having never met them on the join path.
//!
//! ADR-016 §"The rendezvous service and the member bundle record" has always said this
//! is how members reach one another: *"Every other member … opens its own session to
//! the newcomer's bundle, and delivers its SKDM when — and only when — its user
//! consents."* The runtime did not do it. Sessions were created **only** on the join
//! path, so a member admitted through somebody else was unreachable: `Consent` answered
//! `Unreachable`, and ADR-006 re-keys after a revocation silently skipped them.
//!
//! The shape here is the one that exposes it, and it is ordinary: **Carol joins Bob,
//! not Alice.** Alice and Carol therefore share no join, no CPace and no PQXDH. Alice
//! learns Carol exists the way ADR-016 says she does — from Bob's board, whose records
//! `learn_members` files onto her own — and must then be able to consent to Carol and
//! have Carol read what she writes.
//!
//! What this proves, in order: Alice opens a session from Carol's bundle record; the
//! PQXDH opening message reaches Carol over the `pairwise` stream itself
//! (`PairwiseFrame::Hello`, since there is no join stream to carry it); Carol accepts
//! it against her own prekey ring; and the SKDM that follows on the same stream opens.
//!
//! Production Argon2id and a real `(200,9)` Equihash solve per join: `#[ignore]`d in
//! the debug suite, run by CI's release step.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, NodeView, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(180);

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

/// Await a condition on a node's view, or fail with what the view actually held.
async fn until(h: &NodeHandle, what: &str, mut ok: impl FnMut(&NodeView) -> bool) {
    tokio::time::timeout(TIMEOUT, async {
        while !ok(&h.view()) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn invite(h: &NodeHandle, cid: [u8; 32]) -> String {
    assert!(h
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    wait_for(h, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await
}

async fn join(h: &NodeHandle, url: &str, cid: [u8; 32], name: &str) {
    assert!(
        h.apply(NodeCommand::JoinChannel {
            link: url.to_owned(),
            local_name: "team".into(),
            passphrase: secret("channel passphrase"),
        })
        .await
        .is_done(),
        "{name} joins"
    );
    let _ = wait_for(h, |e| match e {
        NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
        _ => None,
    })
    .await;
}

#[test]
#[ignore = "production Argon2id + two (200,9) Equihash solves: CI runs it in release"]
fn m15_a_member_reaches_one_it_never_joined_with_from_the_bundle_record() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let alice = node(&tmp, "alice").await;
        let bob = node(&tmp, "bob").await;
        let carol = node(&tmp, "carol").await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        let carol_fp = carol.view().identity.unwrap().fingerprint;

        // ---- Alice creates the room; Bob joins HER ----
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = alice.view().channels[0].channel_id;
        let from_alice = invite(&alice, cid).await;
        join(&bob, &from_alice, cid, "bob").await;

        // ---- Carol joins BOB. Alice and Carol share no join, so under the old
        // runtime Alice held no session with Carol and never could. ----
        let from_bob = invite(&bob, cid).await;
        join(&carol, &from_bob, cid, "carol").await;

        // Alice learns Carol exists the way ADR-016 says she does: from Bob's board,
        // filed onto her own by `learn_members` during sync.
        until(&alice, "Alice to learn Carol is a member", |v| {
            v.open_channels
                .iter()
                .find(|d| d.channel_id == cid)
                .is_some_and(|d| d.members.contains(&carol_fp))
        })
        .await;

        // ---- the act under test: consent to a member never met ----
        let out = alice
            .apply(NodeCommand::Consent {
                channel_id: cid,
                target: carol_fp,
            })
            .await;
        assert!(
            out.is_done(),
            "Alice consents to a member she never joined with: {out:?} \
             (before ADR-016's bundle-record sessions existed this was Unreachable)"
        );

        // ---- and it is a real session: what Alice writes, Carol reads ----
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "reached you without ever joining you".into(),
            })
            .await
            .is_done());
        until(&carol, "Carol to read Alice's message", |v| {
            texts(v, cid)
                .iter()
                .any(|t| t == "reached you without ever joining you")
        })
        .await;

        // The session Alice opened is the one Carol accepted: Carol attributes the
        // message to Alice's identity, not merely to "someone".
        let sender_is_alice = carol
            .view()
            .open_channels
            .iter()
            .find(|d| d.channel_id == cid)
            .is_some_and(|d| {
                d.timeline.iter().any(|r| {
                    r.text == "reached you without ever joining you" && r.author == alice_fp
                })
            });
        assert!(sender_is_alice, "Carol attributes the message to Alice");

        // ---- and the connection works in BOTH directions (M17.6b) ----
        //
        // The half above proves Alice can *deliver* over a connection she made from a
        // bundle record. It passed while the reverse half was broken, which is the point
        // of adding this: `reach_member` called `net.reach` directly instead of going
        // through `dial`, so the actor never adopted the connection — no receive loop, no
        // sync schedule, no upgrade behind a relayed path. A QUIC connection is
        // bidirectional, so Carol reaches *back* along the very same connection, and
        // nothing on Alice's side was reading it.
        //
        // So: Carol consents to Alice, and Alice must read what Carol writes.
        //
        // **This does NOT prove the adoption fix, and must not be cited as if it did.**
        // Mutation-checked honestly: with `reach_member` reverted to `net.reach` the
        // assertion below still passes, in 254s instead of 54s — because Carol also
        // dials Alice, whose *accept* loop adopts that connection, so the log converges
        // eventually by a slower route. What this holds is the property itself (the
        // reverse direction works), which is worth holding. The adoption fix rests on
        // the removed divergence and on that 5x timing, not on this going red.
        let out = carol
            .apply(NodeCommand::Consent {
                channel_id: cid,
                target: alice_fp,
            })
            .await;
        assert!(out.is_done(), "Carol consents to Alice: {out:?}");
        assert!(carol
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "and you can hear me too".into(),
            })
            .await
            .is_done());
        until(&alice, "Alice to read Carol's message", |v| {
            texts(v, cid).iter().any(|t| t == "and you can hear me too")
        })
        .await;
        let sender_is_carol = alice
            .view()
            .open_channels
            .iter()
            .find(|d| d.channel_id == cid)
            .is_some_and(|d| {
                d.timeline
                    .iter()
                    .any(|r| r.text == "and you can hear me too" && r.author == carol_fp)
            });
        assert!(sender_is_carol, "Alice attributes the message to Carol");

        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}
