//! ADR-007 / ADR-006 **M18.1 gate** — revocation is rotation with one member left
//! out, and it costs the members who keep consent nothing.
//!
//! Three networked nodes in one process over loopback QUIC, on the production
//! Argon2id profile. Alice consents to Bob and Carol; all three read her message.
//! Alice then revokes Bob, which rotates her sender key and re-keys Carol. From that
//! point:
//!
//! - **Carol reads everything.** She is re-keyed at the new generation's origin, so
//!   the rotation is invisible to her — no gap, no missing message.
//! - **Bob reads nothing new.** He receives the ciphertext by ordinary sync (proved
//!   by his entry count rising to match Alice's) and cannot open any of it.
//!
//! Everything goes through the client API — `NodeCommand` in, `NodeView` and
//! `NodeEvent` out — so it exercises the surface a client uses, not internals. Real
//! Argon2id (six derivations per node) plus a production `(200,9)` Equihash solve per
//! join make this slow: `#[ignore]`d in the debug suite, run by CI's release step
//! with the other real-parameter gates.

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

/// Drain events until `done` is satisfied by everything seen so far — joins and key
/// releases race, so the gate must not depend on their order.
async fn drain_until(h: &NodeHandle, mut done: impl FnMut(&[NodeEvent]) -> bool) {
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
}

fn is_peer_joined(e: &NodeEvent, cid: [u8; 32], who: [u8; 32]) -> bool {
    matches!(e, NodeEvent::PeerJoined { channel_id, peer } if *channel_id == cid && *peer == who)
}

fn is_key_from(e: &NodeEvent, cid: [u8; 32], who: [u8; 32]) -> bool {
    matches!(
        e,
        NodeEvent::SenderKeyReceived { channel_id, peer, .. }
            if *channel_id == cid && *peer == who
    )
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

#[test]
#[ignore = "production Argon2id + (200,9) Equihash: slow in release, minutes unoptimized; CI runs it in release"]
fn m18_revoking_one_member_keeps_the_others_whole() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let alice = node(&tmp, "alice").await;
        let bob = node(&tmp, "bob").await;
        let carol = node(&tmp, "carol").await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        let carol_fp = carol.view().identity.unwrap().fingerprint;

        // ---- a channel with all three in it ----
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

        for (who, name) in [(&bob, "bob"), (&carol, "carol")] {
            assert!(
                who.apply(NodeCommand::JoinChannel {
                    link: url.clone(),
                    local_name: "team".into(),
                    passphrase: secret("channel passphrase"),
                })
                .await
                .is_done(),
                "{name} joins"
            );
            let _ = wait_for(who, |e| match e {
                NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
                _ => None,
            })
            .await;
        }
        // Alice must hold both joiners' keys before she serves anything: an ADR-004
        // responder has no sending chain until it has received.
        drain_until(&alice, |evs| {
            [bob_fp, carol_fp].iter().all(|who| {
                evs.iter().any(|e| is_peer_joined(e, cid, *who))
                    && evs.iter().any(|e| is_key_from(e, cid, *who))
            })
        })
        .await;

        // ---- consent to both, then one message all three can read ----
        for (who, fp, name) in [(&bob, bob_fp, "bob"), (&carol, carol_fp, "carol")] {
            let out = alice
                .apply(NodeCommand::Consent {
                    channel_id: cid,
                    target: fp,
                })
                .await;
            assert!(out.is_done(), "Alice consents to {name}: {out:?}");
            drain_until(who, |evs| evs.iter().any(|e| is_key_from(e, cid, alice_fp))).await;
        }
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "everyone reads this".into(),
            })
            .await
            .is_done());
        // Both must actually be reading Alice before the revocation, or "Bob stopped
        // reading" would prove nothing about the revocation.
        for (who, name) in [(&bob, "bob"), (&carol, "carol")] {
            until(who, &format!("{name} to read Alice"), |v| {
                texts(v, cid).iter().any(|t| t == "everyone reads this")
            })
            .await;
        }

        // ---- revoke Bob ----
        let out = alice
            .apply(NodeCommand::Revoke {
                channel_id: cid,
                target: bob_fp,
            })
            .await;
        assert!(out.is_done(), "Alice revokes Bob: {out:?}");
        let (generation, rekeyed) = wait_for(&alice, |e| match e {
            NodeEvent::Revoked {
                channel_id,
                target,
                generation,
                rekeyed,
            } if channel_id == cid && target == bob_fp => Some((generation, rekeyed)),
            _ => None,
        })
        .await;
        assert_eq!(generation, 1, "a new sender-key generation exists");
        assert_eq!(
            rekeyed, 1,
            "the one remaining consenter was re-keyed at once"
        );

        // ---- after the revocation ----
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: "only carol reads this".into(),
            })
            .await
            .is_done());
        until(&carol, "Carol to read the post-revocation message", |v| {
            texts(v, cid).iter().any(|t| t == "only carol reads this")
        })
        .await;

        // Bob receives the bytes — his log catches up with Alice's — and opens none of
        // them. Waiting for the entry count first is what makes the negative
        // assertion mean something: he *has* the ciphertext and still reads nothing.
        let alice_entries = entries(&alice.view(), cid);
        until(&bob, "Bob's log to catch up with Alice's", |v| {
            entries(v, cid) >= alice_entries
        })
        .await;
        let bob_texts = texts(&bob.view(), cid);
        assert!(
            bob_texts.iter().any(|t| t == "everyone reads this"),
            "what Bob read before the revocation is not recalled: {bob_texts:?}"
        );
        assert!(
            !bob_texts.iter().any(|t| t == "only carol reads this"),
            "a revoked member reads nothing sent afterwards: {bob_texts:?}"
        );

        // Carol has the whole conversation, across the rotation boundary.
        let carol_texts = texts(&carol.view(), cid);
        assert!(
            carol_texts.iter().any(|t| t == "everyone reads this")
                && carol_texts.iter().any(|t| t == "only carol reads this"),
            "the rotation is invisible to whoever keeps consent: {carol_texts:?}"
        );

        for h in [&alice, &bob, &carol] {
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        }
    });
}
