//! ADR-020 §3 **M19.2 gate** — the trust keyring decides who reads, and room
//! membership does not.
//!
//! Three networked nodes over loopback QUIC, production Argon2id. All three are
//! members of one room. Alice trusts **Bob only**, and nobody ever issues a
//! `Consent` command anywhere in this test. Then:
//!
//! - **Bob reads Alice.** Auto-consent issued him the key because his fingerprint
//!   is in Alice's keyring — one act, at trust time, not per room.
//! - **Carol reads nothing.** She is a full member of the room, an admitted log
//!   author, and receives every byte Alice writes by ordinary sync (proved by her
//!   entry count matching Alice's). She cannot open any of it.
//!
//! That second assertion is the point of the design. Under the genesis "open
//! room" flag this replaced, membership *would* have been the read boundary, and
//! an identity admitted by vouching — a bundle record published by a member, for
//! someone who never held the room passphrase — would have been handed the room.
//! Keyed on the keyring, it gets nothing.
//!
//! Mutation-checked by trusting Carol too: she then reads everything, which is
//! what proves the gate is measuring the keyring rather than some accident of
//! timing.
//!
//! Everything goes through the client API — `NodeCommand` in, `NodeView` and
//! `NodeEvent` out. Real Argon2id plus a production `(200,9)` Equihash solve per
//! join make this slow: `#[ignore]`d in debug, run by CI in release.

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

/// `trust_carol` is the mutation switch: with it false this is the gate; with it
/// true, Carol must read everything, which proves the keyring is what decides.
async fn run(trust_carol: bool) -> (Vec<String>, Vec<String>, u64, u64) {
    let rt_tmp = tempfile::tempdir().unwrap();
    let alice = node(&rt_tmp, "alice").await;
    let bob = node(&rt_tmp, "bob").await;
    let carol = node(&rt_tmp, "carol").await;
    let bob_fp = bob.view().identity.unwrap().fingerprint;
    let carol_fp = carol.view().identity.unwrap().fingerprint;

    // ---- one room, all three in it ----
    assert!(alice
        .apply(NodeCommand::CreateChannel {
            local_name: "agents".into(),
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
                local_name: "agents".into(),
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
    // Alice has admitted both as log authors — membership, which is NOT read access.
    //
    // **Corrected 2026-09-21 (M17.6).** This asserted `entries(v, cid) > 0` under the
    // label "both members admitted", which is a different claim: the entry it waited for
    // was the consent grant each joiner appended when joining released its sender key
    // automatically. With that release gone there is no entry to wait for, and the check
    // could never pass — while the property it names was true all along. It now asserts
    // membership directly, which is what it says and what the rest of the gate needs.
    until(&alice, "both members admitted", |v| {
        v.open_channels
            .iter()
            .find(|c| c.channel_id == cid)
            .is_some_and(|c| c.members.contains(&bob_fp) && c.members.contains(&carol_fp))
    })
    .await;

    // ---- the only trust decision in this test ----
    assert!(
        alice
            .apply(NodeCommand::Trust {
                fingerprint: bob_fp,
                petname: "bob-agent".into(),
            })
            .await
            .is_done(),
        "alice trusts bob"
    );
    if trust_carol {
        assert!(alice
            .apply(NodeCommand::Trust {
                fingerprint: carol_fp,
                petname: "carol-agent".into(),
            })
            .await
            .is_done());
    }
    // The keyring is visible and holds exactly who was trusted.
    let trusted = alice.view().trusted;
    assert_eq!(trusted.len(), if trust_carol { 2 } else { 1 });
    assert!(trusted
        .iter()
        .any(|(fp, name)| *fp == bob_fp && name == "bob-agent"));

    for (who, name) in [(&bob, "bob"), (&carol, "carol")] {
        assert!(
            who.apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done(),
            "{name} opens"
        );
    }
    assert!(alice
        .apply(NodeCommand::OpenChannel {
            channel_id: cid,
            passphrase: secret("channel passphrase"),
        })
        .await
        .is_done());

    // ---- Alice speaks. NOBODY issues a Consent command anywhere. ----
    for i in 0..3 {
        assert!(alice
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: format!("from alice {i}"),
            })
            .await
            .is_done());
    }

    // Bob is trusted, so auto-consent reached him: he renders Alice.
    until(&bob, "bob to read alice", |v| texts(v, cid).len() >= 3).await;

    // Carol receives the ciphertext either way — she is a member and syncs.
    until(&carol, "carol to receive the ciphertext", |v| {
        entries(v, cid) >= entries(&alice.view(), cid)
    })
    .await;
    // Give any in-flight consent a chance to land before reading Carol's timeline,
    // so a pass is not an artefact of looking too early.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let bob_texts = texts(&bob.view(), cid);
    let carol_texts = texts(&carol.view(), cid);
    let carol_entries = entries(&carol.view(), cid);
    let alice_entries = entries(&alice.view(), cid);
    (bob_texts, carol_texts, carol_entries, alice_entries)
}

#[test]
#[ignore = "production Argon2id + (200,9) Equihash; CI runs it in release"]
fn m19_the_keyring_decides_who_reads_not_membership() {
    watchdog::arm();
    let rt = runtime();
    let (bob_texts, carol_texts, carol_entries, alice_entries) = rt.block_on(run(false));

    // Bob: trusted once, node-wide, with no per-room consent act anywhere.
    assert!(
        bob_texts.iter().any(|t| t == "from alice 0"),
        "bob is trusted but read nothing: {bob_texts:?}"
    );
    assert_eq!(
        bob_texts.len(),
        3,
        "bob should read all three: {bob_texts:?}"
    );

    // Carol: a full member, holding every byte, able to open none of it.
    assert!(
        carol_entries >= alice_entries,
        "carol did not receive the log ({carol_entries} < {alice_entries}), so this run \
         does not prove she was refused rather than merely behind"
    );
    assert!(
        carol_texts.is_empty(),
        "carol is NOT in the keyring and must read nothing, but rendered {carol_texts:?}"
    );
}

/// Trust must **survive a lock/unlock**, or "trust an agent once and it covers
/// every future room" is false and every restart silently trusts nobody. The
/// keyring is sealed under the identity, so this also proves the seal round-trips
/// against a real vault rather than in a codec test.
#[test]
#[ignore = "production Argon2id (several derivations); CI runs it in release"]
fn m19_trust_survives_a_lock_and_unlock() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let alice = node(&tmp, "persist").await;
        let fp = [7u8; 32];

        assert!(alice
            .apply(NodeCommand::Trust {
                fingerprint: fp,
                petname: "remembered".into(),
            })
            .await
            .is_done());
        assert_eq!(alice.view().trusted.len(), 1);

        assert!(alice.apply(NodeCommand::Lock).await.is_done());
        // Locked: the keyring is sealed under the identity, so it is not held.
        assert!(
            alice.view().trusted.is_empty(),
            "a locked node must not hold the keyring"
        );

        assert!(alice
            .apply(NodeCommand::Unlock {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        let trusted = alice.view().trusted;
        assert_eq!(
            trusted.len(),
            1,
            "the keyring did not survive lock/unlock: {trusted:?}"
        );
        assert_eq!(trusted[0].0, fp);
        assert_eq!(trusted[0].1, "remembered");

        // And untrusting persists too, or an operator's withdrawal would be undone
        // by the next restart.
        assert!(alice
            .apply(NodeCommand::Untrust { fingerprint: fp })
            .await
            .is_done());
        assert!(alice.apply(NodeCommand::Lock).await.is_done());
        assert!(alice
            .apply(NodeCommand::Unlock {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(
            alice.view().trusted.is_empty(),
            "untrust did not survive lock/unlock"
        );
    });
}

#[test]
#[ignore = "mutation check for the gate above; CI runs it in release"]
fn m19_trusting_carol_too_lets_her_read() {
    watchdog::arm();
    let rt = runtime();
    let (_bob_texts, carol_texts, _carol_entries, _alice_entries) = rt.block_on(run(true));
    assert_eq!(
        carol_texts.len(),
        3,
        "with Carol trusted the keyring must let her read, but she rendered {carol_texts:?} \
         — if this fails the gate above proves nothing about the keyring"
    );
}
