//! One `WANT` must not be able to stop a room (PRD-001 R4).
//!
//! **The defect (PRD-001 D2).** A sync session holds its room's lock from start to finish, and
//! the serve phase answered the peer's `WANT` by looping `from_seq..=to_seq` — one lookup per
//! *number*, not per entry held — collecting every hit into memory. The ranges are the peer's to
//! write and nothing bounded them. So `WANT (author, 1, u64::MAX)`, which any member can send,
//! started a loop that would not finish in the life of the machine, with the room locked: no
//! message could be posted to it, no key taken, no join answered, ever. Sent as a thousand
//! duplicate ranges it also multiplied whatever *was* held a thousandfold.
//!
//! This sends exactly that, from a real member's identity over a real connection, and while the
//! victim is serving it, posts an ordinary message into the same room on the victim. Every step
//! is asserted:
//!
//! 1. the attacker is a real member of the room and the victim **answers** its session — a
//!    refused session would make the timing below measure nothing;
//! 2. the hostile `WANT` is on the wire before the post starts;
//! 3. the post completes within [`PATIENCE`] (printed);
//! 4. the attacker received each entry the victim holds exactly once — clamped to what is held,
//!    duplicates merged — and the session ended cleanly.
//!
//! Mutation: put the `from_seq..=to_seq` loop back in `entries_for_wants` and step 3 goes red —
//! the post never returns. (The victim's serving thread then spins for ever, so that run ends by
//! the watchdog; run it with `VOX_TEST_WATCHDOG_SECS` set low.)

#[path = "support/raw_sync.rs"]
mod raw_sync;
#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::Arc;
use std::time::{Duration, Instant};

use raw_sync::{Ask, Yield};
use vox_core::join::pow::PowParams;
use vox_core::log::sync::WantRange;
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, NodeView, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);
const IDENTITY: &str = "identity passphrase";
/// Posts in the room before the attack, so there is something to serve.
const POSTS: usize = 50;
/// How many copies of the absurd range the `WANT` carries.
const DUPLICATES: usize = 1_000;
/// An ordinary post must finish inside this while the attack is being served. A loopback post
/// takes milliseconds; the defect is unbounded.
const PATIENCE: Duration = Duration::from_secs(5);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

async fn node(tmp: &tempfile::TempDir, name: &str) -> NodeHandle {
    let mut cfg = NodeConfig::new().bind(Bind::Addr("127.0.0.1:0".parse().unwrap()));
    // The join's PoW is not what this gate is about; the M14 gate exercises the real one.
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    let h = Node::spawn_config(paths(tmp, name), cfg).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret(IDENTITY),
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

fn entries(view: &NodeView, cid: [u8; 32]) -> u64 {
    view.channels
        .iter()
        .find(|c| c.channel_id == cid)
        .map_or(0, |c| c.entries)
}

#[test]
#[ignore = "production Argon2id and a real join; CI runs it in release"]
fn an_absurd_want_does_not_stop_the_room_it_names() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let victim = node(&tmp, "victim").await;
        let victim_id = victim.view().identity.unwrap().fingerprint;
        assert!(victim
            .apply(NodeCommand::CreateChannel {
                local_name: "room".into(),
                passphrase: secret("room passphrase"),
            })
            .await
            .is_done());
        let cid = victim.view().channels[0].channel_id;
        for i in 1..=POSTS {
            assert!(victim
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: format!("post {i}"),
                })
                .await
                .is_done());
        }

        // A real member, whose identity the attack then uses.
        let mallory = node(&tmp, "mallory").await;
        assert!(victim
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&victim, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        let joined = mallory
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "room".into(),
                passphrase: secret("room passphrase"),
            })
            .await;
        assert!(joined.is_done(), "mallory joins: {joined:?}");
        assert!(mallory.apply(NodeCommand::Shutdown).await.is_done());
        drop(mallory);

        let held = entries(&victim.view(), cid);
        let endpoint =
            raw_sync::endpoint_as_member(&paths(&tmp, "mallory"), IDENTITY.as_bytes()).await;
        let conn = Arc::new(
            endpoint
                .connect(
                    raw_sync::dial_addr(&victim.view()),
                    victim_id,
                    raw_sync::now(),
                )
                .await
                .expect("mallory's identity connects"),
        );
        let _answered = raw_sync::answer_victim(Arc::clone(&conn));

        // The victim's own feed, a thousand times over, to the end of time; plus a feed it does
        // not hold and an inverted range, which must cost nothing.
        let mut ranges = vec![
            WantRange {
                author_id: victim_id,
                from_seq: 1,
                to_seq: u64::MAX,
            };
            DUPLICATES
        ];
        ranges.push(WantRange {
            author_id: [0xEE; 32],
            from_seq: 1,
            to_seq: u64::MAX,
        });
        ranges.push(WantRange {
            author_id: victim_id,
            from_seq: u64::MAX,
            to_seq: 1,
        });

        // ---- 1 + 2. an answered session with the hostile WANT on the wire ------------------
        let mut attack = None;
        for _ in 0..20 {
            let (tx, rx) = std::sync::mpsc::channel();
            let conn = Arc::clone(&conn);
            let ask = Ask::Ranges(ranges.clone());
            let task =
                tokio::spawn(async move { raw_sync::ask(&conn, cid, 0, ask, Some(tx)).await });
            // Either the WANT goes out, or the session ends first (refused: the victim was syncing
            // this room itself at that moment) and it is asked again.
            let sent = loop {
                if rx.try_recv().is_ok() {
                    break true;
                }
                if task.is_finished() {
                    break false;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            if sent {
                attack = Some(task);
                break;
            }
            println!(
                "session refused before the WANT ({:?}); asking again",
                task.await.unwrap()
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let attack = attack.expect(
            "steps 1-2 FAILED: the victim never answered the member's session far enough to take a \
             WANT, so the timing below would measure nothing",
        );
        println!(
            "WANT sent: {} ranges ({DUPLICATES} × (victim, 1, u64::MAX), one unheld feed, one \
             inverted) against a room holding {held} entries",
            ranges.len()
        );

        // ---- 3. the room still works ------------------------------------------------------
        let started = Instant::now();
        let posted = tokio::time::timeout(
            PATIENCE,
            victim.apply(NodeCommand::SendText {
                channel_id: cid,
                text: "posted while the WANT was being served".into(),
            }),
        )
        .await;
        let took = started.elapsed();
        println!("an ordinary post during the attack took {took:?}");
        assert!(
            posted.is_ok(),
            "an ordinary post into the room got no answer in {took:?} while one member's \
             WANT (author, 1, u64::MAX) was being served — one request stops the room \
             (PRD-001 D2/R4)"
        );
        assert!(
            posted.unwrap().is_done(),
            "the post was answered but refused"
        );

        // ---- 4. what was served: each held entry once --------------------------------------
        let y: Yield = tokio::time::timeout(TIMEOUT, attack)
            .await
            .expect("the attacker's session ended")
            .unwrap();
        println!("the attacker's session: {y:?}");
        assert!(y.hello, "the session was answered");
        let victim_feed = y
            .have
            .iter()
            .find(|(a, _)| *a == victim_id)
            .map_or(0, |(_, max)| *max);
        assert!(
            victim_feed >= POSTS as u64,
            "the victim's feed holds its posts"
        );
        assert_eq!(
            y.entries as u64, victim_feed,
            "the WANT must be served each entry of the victim's feed exactly once — \
             {DUPLICATES} duplicate ranges merged, clamped to the {victim_feed} held — got {}",
            y.entries
        );
        assert_eq!(y.ended, None, "the session ended cleanly");

        assert!(victim.apply(NodeCommand::Shutdown).await.is_done());
    });
}
