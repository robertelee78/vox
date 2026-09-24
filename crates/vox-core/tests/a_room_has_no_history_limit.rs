//! A room with a long history must still open, and a newcomer must still catch up with all of it.
//!
//! PRD-001 R1: a room has no lifetime limit on messages; reopening it, restarting the node and a
//! cold catch-up must work at any history size. R3: the per-author rate quota is gone.
//!
//! **The defect (PRD-001 D1).** Every entry — authored here, arriving by sync, and every stored
//! entry replayed when a room is *opened* — passed `Dag::accept`, which charged it to a
//! per-author quota of 1,000 entries per rolling hour. Replay happens in one burst, so the
//! 1,001st stored entry from one author was "over quota" at open time and the room failed with
//! `stored entry failed acceptance`: a room could never be opened again once one member had
//! posted a thousand times in an hour, and restarting the node was what triggered it. The same
//! charge throttled a newcomer's catch-up, and the 1,001st local post was refused outright.
//!
//! This drives three real nodes' lifetimes:
//!
//! 1. Alice posts [`POSTS`] messages — past the old cap, and past one sync session's serve bound
//!    ([`vox_core::log::sync::MAX_SERVE_ENTRIES`]), so the catch-up below needs the continuation
//!    across sessions that the bound relies on;
//! 2. Alice's node is shut down and started again on the same store, the room is opened, and
//!    **every** post must be in its timeline;
//! 3. Bob, who has never seen the room, joins it and his log must reach Alice's entry count,
//!    with no command from anybody after the join.
//!
//! Mutation: put the 1,000/hour check back in `Dag::accept` and this fails at step 1 — the
//! 1,001st post is refused — and with the local-append path exempted it fails at step 2 on the
//! reopen, which is D1 exactly.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use vox_core::join::pow::PowParams;
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, NodeView, Secret};
use vox_core::node::paths::Paths;

/// Half again past the old 1,000/hour cap, and past one session's serve bound.
const POSTS: usize = 1_500;

const TIMEOUT: Duration = Duration::from_secs(180);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

fn config() -> NodeConfig {
    let mut cfg = NodeConfig::new().bind(Bind::Addr("127.0.0.1:0".parse().unwrap()));
    // The join's PoW is not what this gate is about; the M14 gate exercises the real one.
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    cfg
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

fn entries(view: &NodeView, cid: [u8; 32]) -> u64 {
    view.channels
        .iter()
        .find(|c| c.channel_id == cid)
        .map_or(0, |c| c.entries)
}

fn posts_by(view: &NodeView, cid: [u8; 32], author: [u8; 32]) -> usize {
    view.open_channels
        .iter()
        .find(|d| d.channel_id == cid)
        .map_or(0, |d| {
            d.timeline
                .iter()
                .filter(|r| r.author == author && r.text.starts_with("post "))
                .count()
        })
}

#[test]
#[ignore = "production Argon2id, 1,500 posts, a restart and a join: CI runs it in release"]
fn a_room_reopens_and_a_newcomer_catches_up_past_a_thousand_posts_from_one_author() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        // ---- 1. one author, many posts ----------------------------------------------------
        let alice = Node::spawn_config(paths(&tmp, "alice"), config()).unwrap();
        assert!(alice
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        let alice_fp = alice.view().identity.unwrap().fingerprint;
        assert!(alice
            .apply(NodeCommand::CreateChannel {
                local_name: "long".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = alice.view().channels[0].channel_id;

        let started = Instant::now();
        for i in 1..=POSTS {
            let out = alice
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: format!("post {i}"),
                })
                .await;
            assert!(
                out.is_done(),
                "post {i} of {POSTS} was refused ({out:?}) after {} accepted — one author may \
                 post without limit (PRD-001 R1/R3)",
                i - 1
            );
        }
        let before_restart = entries(&alice.view(), cid);
        println!(
            "alice posted {POSTS} in {:?}; her log holds {before_restart} entries",
            started.elapsed()
        );
        assert_eq!(posts_by(&alice.view(), cid, alice_fp), POSTS);

        // ---- 2. restart, reopen, read everything --------------------------------------------
        assert!(alice.apply(NodeCommand::Shutdown).await.is_done());
        drop(alice);
        // The store is released when the old actor's last handle goes; retry until it is.
        let alice = tokio::time::timeout(TIMEOUT, async {
            loop {
                match Node::spawn_config(paths(&tmp, "alice"), config()) {
                    Ok(h) => return h,
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            }
        })
        .await
        .expect("alice's second instance opened its store");
        assert!(alice
            .apply(NodeCommand::Unlock {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        let reopened = alice
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("channel passphrase"),
            })
            .await;
        assert!(
            reopened.is_done(),
            "the room with {POSTS} posts from one author did not reopen after a restart: \
             {reopened:?} — PRD-001 D1, replaying the stored log re-applied a rate limit"
        );
        let after_restart = entries(&alice.view(), cid);
        let readable = posts_by(&alice.view(), cid, alice_fp);
        println!("after restart: {after_restart} entries, {readable} posts readable");
        assert_eq!(
            after_restart, before_restart,
            "every stored entry came back"
        );
        assert_eq!(readable, POSTS, "every post reads back after the restart");

        // ---- 3. a newcomer catches up cold -------------------------------------------------
        assert!(alice
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        let bob = Node::spawn_config(paths(&tmp, "bob"), config()).unwrap();
        assert!(bob
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        let joined = bob
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "long".into(),
                passphrase: secret("channel passphrase"),
            })
            .await;
        assert!(joined.is_done(), "bob joins: {joined:?}");

        // Nothing is asked of anybody from here: the catch-up must finish on its own.
        let joined_at = Instant::now();
        let target = entries(&alice.view(), cid);
        let mut last = 0;
        let caught_up = tokio::time::timeout(TIMEOUT, async {
            loop {
                let have = entries(&bob.view(), cid);
                if have != last {
                    println!(
                        "bob holds {have} of {target} after {:?}",
                        joined_at.elapsed()
                    );
                    last = have;
                }
                if have >= target {
                    return have;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        let have = entries(&bob.view(), cid);
        assert!(
            caught_up.is_ok(),
            "bob's cold catch-up stalled at {have} of {target} entries after {:?} — a newcomer \
             must receive a history of any size (PRD-001 R1)",
            joined_at.elapsed()
        );
        println!(
            "bob caught up: {have} of {target} entries in {:?}",
            joined_at.elapsed()
        );
        assert_eq!(have, target);

        assert!(bob.apply(NodeCommand::Shutdown).await.is_done());
        assert!(alice.apply(NodeCommand::Shutdown).await.is_done());
    });
}
