//! A room with two members must not be unjoinable because one of them is offline.
//!
//! When an invite link pins no responder, the joiner picks a member from the board and
//! joins through it. It picked **one**, and if that one was unreachable the join failed —
//! with `Unreachable`, which says nothing about the room having other members who were
//! sitting right there, online, able to serve it.
//!
//! Worse, which member it picked was **random**. `RendezvousStore::current_members`
//! returns `HashMap::values()`, so the order changed run to run and process to process. A
//! room with one offline member therefore failed joins at a rate nobody could reproduce,
//! and a retry could appear to "fix" it by landing on a different member. That is the
//! worst shape a defect can have: intermittent, unattributable, and self-healing often
//! enough to look like bad luck.
//!
//! So two things changed together, and this gate needs both. The candidate list is
//! **sorted**, so the walk is the same every time and a gate can say which member will be
//! tried first; and the join **walks** it, bounded, instead of stopping at one.
//!
//! The shape here is the ordinary one: Alice makes a room, Bob joins it, Alice goes away,
//! and Carol — who has only a link naming no particular member — must still get in
//! through Bob.
//!
//! **The member taken offline is chosen by the same rule the product sorts by**, so this
//! does not depend on which identity happened to be generated first: whichever of Alice
//! and Bob sorts lower is the one that will be tried first, and that is the one shut down.
//! Mutation: bound the walk to one candidate and this fails every time, because the only
//! candidate it will ever try is the one that is gone.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use vox_core::identity::composite::RootSigner;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::InviteLink;
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(180);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

async fn member(tmp: &tempfile::TempDir, name: &str, anchors: BootstrapSet) -> NodeHandle {
    let mut cfg = NodeConfig::new()
        .bind(Bind::Addr("127.0.0.1:0".parse().unwrap()))
        .anchors(anchors);
    // The join's PoW is not what this gate is about; the M14 gate exercises the real one.
    cfg.pow_params = Some(vox_core::join::pow::PowParams { n: 48, k: 5 });
    let h = Node::spawn_config(paths(tmp, name), cfg).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
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

/// The same link with its `r=` (pinned responder) removed.
///
/// A link minted by a node pins that node, which is the owner's choice and is left alone.
/// ADR-016 also allows a link that pins nobody, and that is the case this gate is about:
/// the joiner must choose, and choosing badly must not be fatal.
fn without_pinned_responder(url: &str) -> String {
    url.split('&')
        .filter(|p| !p.starts_with("r="))
        .collect::<Vec<_>>()
        .join("&")
}

#[test]
#[ignore = "production Argon2id and two real joins; CI runs it in release"]
fn a_room_is_still_joinable_when_the_first_member_tried_is_offline() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // ---- the anchor: headless, holds no room key, serves the board ----
        let anchor_signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let anchor_fp = anchor_signer.fingerprint();
        let anchor = Node::spawn_config(
            paths(&tmp, "anchor"),
            NodeConfig::new()
                .bind(Bind::Addr("127.0.0.1:0".parse().unwrap()))
                .headless(anchor_signer),
        )
        .unwrap();
        let anchor_addr =
            Multiaddr::parse(&anchor.view().listening[0]).expect("the anchor's own multiaddr");
        let mut anchors = BootstrapSet::new();
        anchors
            .add(
                BootstrapNode::new(anchor_fp, EndpointList::new(vec![anchor_addr]).unwrap())
                    .unwrap(),
            )
            .unwrap();

        // ---- Alice makes the room, Bob joins it: two members on the anchor's board ----
        let alice = member(&tmp, "alice", anchors.clone()).await;
        let alice_fp = alice.view().identity.unwrap().fingerprint;
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

        let bob = member(&tmp, "bob", anchors.clone()).await;
        let bob_fp = bob.view().identity.unwrap().fingerprint;
        let joined = tokio::time::timeout(
            TIMEOUT,
            bob.apply(NodeCommand::JoinChannel {
                link: url.clone(),
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            }),
        )
        .await
        .expect("bob's join did not finish");
        assert!(joined.is_done(), "bob must get in first: {joined:?}");

        // ---- the precondition, asserted rather than hoped for ----
        // Carol can only fall through to a second member if the board knows two. Waiting
        // on a sleep made this gate pass 1 run in 5: on the others the board still held
        // one member, so the walk had nothing to walk to and the gate reported the
        // fallback broken when the fallback was never reached. The anchor can say what it
        // knows, so ask it.
        let both_known = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let known = anchor
                    .view()
                    .anchoring
                    .iter()
                    .find(|a| a.channel_id == cid)
                    .map_or(0, |a| a.members);
                if known >= 2 {
                    return known;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        let known = both_known.unwrap_or_else(|_| {
            panic!(
                "the anchor never came to know both members of the room, so this gate cannot \
                 measure a fallback. It knows {:?}. A room whose members never reach their \
                 anchor's board is a separate defect from the one under test here",
                anchor
                    .view()
                    .anchoring
                    .iter()
                    .find(|a| a.channel_id == cid)
                    .map(|a| a.members)
            )
        });
        assert!(
            known >= 2,
            "the board must know both members, knows {known}"
        );

        // ---- take down whichever member the join will reach for first ----
        // The product sorts candidates by fingerprint, so this is not a guess.
        let (offline, survivor, offline_name, survivor_name) = if alice_fp <= bob_fp {
            (&alice, &bob, "alice", "bob")
        } else {
            (&bob, &alice, "bob", "alice")
        };
        assert!(offline.apply(NodeCommand::Shutdown).await.is_done());

        // **Twenty seconds, and the length is a defect, not a margin.**
        //
        // With two seconds here this gate failed four runs in five, and instrumenting it
        // showed why: in a failing run Carol's dial to the *survivor* failed too, not
        // just to the member that had been shut down. A member does not become
        // unreachable because somebody else died — unless something about the death is
        // blocking it, and something is. The node's accept loop performs the TLS
        // handshake inline, so a peer that opens a connection and never finishes it stops
        // every other inbound connection to that node; a member holding a half-finished
        // exchange with the peer that just vanished is exactly that case. The window
        // closes when the handshake times out, which is what this sleep is waiting for.
        //
        // It is written here rather than tuned away because the wait is evidence. Twenty
        // seconds passes 3 runs of 3; two seconds fails 4 of 5. A fix for the accept loop
        // is in flight on another branch, and when it lands this sleep should come down to
        // a couple of seconds — if it does not, the fix did not do what it claims, and
        // this number is the measurement that says so.
        tokio::time::sleep(Duration::from_secs(20)).await;

        // ---- Carol has a link that names nobody in particular ----
        let open_url = without_pinned_responder(&url);
        assert!(
            InviteLink::parse(&open_url)
                .expect("still a well-formed link")
                .responder
                .is_none(),
            "the link Carol uses must pin no responder, or this gate proves nothing"
        );

        let carol = member(&tmp, "carol", anchors).await;
        let out = tokio::time::timeout(
            TIMEOUT,
            carol.apply(NodeCommand::JoinChannel {
                link: open_url.clone(),
                local_name: "team".into(),
                passphrase: secret("channel passphrase"),
            }),
        )
        .await
        .expect("carol's join did not finish");

        assert!(
            out.is_done(),
            "carol could not join a room with a live member in it. {offline_name} is offline \
             and sorts first, so she must fall through to {survivor_name} — one member being \
             away is not the room being gone. Outcome: {out:?}",
        );
        let _ = wait_for(&carol, |e| match e {
            NodeEvent::Joined { channel_id, .. } if channel_id == cid => Some(()),
            _ => None,
        })
        .await;

        // Only the survivor is still up — shutting down the one already stopped fails,
        // and asserting on it turned a passing gate red in the full suite while every
        // claim above had held.
        assert!(survivor.apply(NodeCommand::Shutdown).await.is_done());
        assert!(carol.apply(NodeCommand::Shutdown).await.is_done());
        assert!(anchor.apply(NodeCommand::Shutdown).await.is_done());
    });
}
