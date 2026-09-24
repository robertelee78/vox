//! A node must serve a room's log only to members of *that* room (PRD-001 R5).
//!
//! **The defect (PRD-001 D5).** Whether a peer may open a `sync` stream is decided per *peer*
//! (`node::net`'s stream-kind gate: a member of any room this node holds may), and the stream's
//! preamble then names whichever channel the peer likes. Nothing checked the two against each
//! other — `run_sync_session` received the peer's identity and discarded it — so a member of
//! room A who knew room B's channel id was handed B's whole log. A channel id is not a secret:
//! it is the room's `.vox` name. The same hole was open in the other direction: a fresh
//! connection makes the node push **every** room it holds to the peer, and the session serves
//! whatever the peer then asks for.
//!
//! Every step of the escalation is asserted, because a refusal for the wrong reason would make
//! this gate green against an open node:
//!
//! 1. the attacker is a real member of A, and connects with that member's own identity;
//! 2. **the control:** the same peer, on the same connection, asks for A and is served A's
//!    entries — so the harness can receive entries, and a zero for B means a refusal;
//! 3. it asks for B, repeatedly, and must receive nothing — no `HELLO`, no `HAVE`, no entry;
//! 4. whatever the victim pushes to it on its own must include nothing of B;
//! 5. a member of B still syncs B, in full.
//!
//! Mutation: delete the `may_sync` check in `run_sync_session` and step 3 goes red with B's
//! entries counted; delete the `allowed` check in `sync_one` and step 4 does.

#[path = "support/raw_sync.rs"]
mod raw_sync;
#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::Arc;
use std::time::Duration;

use raw_sync::{Ask, Yield};
use vox_core::join::pow::PowParams;
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, NodeView, Secret};
use vox_core::node::paths::Paths;

const TIMEOUT: Duration = Duration::from_secs(120);
const IDENTITY: &str = "identity passphrase";
/// Posts in each room, so an entry count of zero cannot be an empty room.
const POSTS: usize = 5;
/// How many times the attacker asks for B. The victim refuses an inbound session for a room it
/// is itself syncing, so one refusal could be that; five in a row, spaced out, cannot.
const ATTEMPTS: usize = 5;

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

async fn node(tmp: &tempfile::TempDir, name: &str) -> NodeHandle {
    let h = Node::spawn_config(paths(tmp, name), config()).unwrap();
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

async fn room(victim: &NodeHandle, name: &str) -> [u8; 32] {
    let before: Vec<[u8; 32]> = victim
        .view()
        .channels
        .iter()
        .map(|c| c.channel_id)
        .collect();
    assert!(victim
        .apply(NodeCommand::CreateChannel {
            local_name: name.into(),
            passphrase: secret(&format!("{name} passphrase")),
        })
        .await
        .is_done());
    let cid = victim
        .view()
        .channels
        .iter()
        .map(|c| c.channel_id)
        .find(|c| !before.contains(c))
        .unwrap();
    for i in 1..=POSTS {
        assert!(victim
            .apply(NodeCommand::SendText {
                channel_id: cid,
                text: format!("{name} post {i}"),
            })
            .await
            .is_done());
    }
    cid
}

async fn join(victim: &NodeHandle, joiner: &NodeHandle, cid: [u8; 32], name: &str) {
    assert!(victim
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(victim, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await;
    let out = joiner
        .apply(NodeCommand::JoinChannel {
            link: url,
            local_name: name.into(),
            passphrase: secret(&format!("{name} passphrase")),
        })
        .await;
    assert!(out.is_done(), "join {name}: {out:?}");
}

#[test]
#[ignore = "production Argon2id and two real joins; CI runs it in release"]
fn a_member_of_one_room_is_served_nothing_of_another() {
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
        let a = room(&victim, "alpha").await;
        let b = room(&victim, "bravo").await;

        let xavier = node(&tmp, "xavier").await; // member of A only
        let yara = node(&tmp, "yara").await; // member of B only
        join(&victim, &xavier, a, "alpha").await;
        join(&victim, &yara, b, "bravo").await;

        // ---- 5. a member of B still syncs B, in full --------------------------------------
        let b_held = entries(&victim.view(), b);
        assert!(b_held >= POSTS as u64, "the victim holds B's posts: {b_held}");
        let synced = tokio::time::timeout(TIMEOUT, async {
            while entries(&yara.view(), b) < b_held {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        println!(
            "yara (member of B) holds {} of B's {b_held} entries",
            entries(&yara.view(), b)
        );
        assert!(
            synced.is_ok(),
            "a member of B must still be served B's log: holds {} of {b_held}",
            entries(&yara.view(), b)
        );
        assert!(
            !xavier.view().channels.iter().any(|c| c.channel_id == b),
            "xavier is not a member of B"
        );

        // ---- 1. the attacker: xavier's own identity, off his own node -----------------------
        assert!(xavier.apply(NodeCommand::Shutdown).await.is_done());
        drop(xavier);
        // The victim is restarted so the attacker's connection is a *fresh* one to it. A node
        // keeps a peer's sync schedule for as long as it runs, and only a first connection
        // triggers the push of every open room (`SyncTrigger::Connected`) that step 4 is about;
        // xavier's node already had its first connection, when it joined.
        assert!(victim.apply(NodeCommand::Shutdown).await.is_done());
        drop(victim);
        let victim = tokio::time::timeout(TIMEOUT, async {
            loop {
                match Node::spawn_config(paths(&tmp, "victim"), config()) {
                    Ok(h) => return h,
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            }
        })
        .await
        .expect("the victim restarted");
        assert!(victim
            .apply(NodeCommand::Unlock {
                passphrase: secret(IDENTITY),
            })
            .await
            .is_done());
        for (cid, name) in [(a, "alpha"), (b, "bravo")] {
            assert!(victim
                .apply(NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret(&format!("{name} passphrase")),
                })
                .await
                .is_done());
        }
        let endpoint = raw_sync::endpoint_as_member(&paths(&tmp, "xavier"), IDENTITY.as_bytes()).await;
        let conn = Arc::new(
            endpoint
                .connect(raw_sync::dial_addr(&victim.view()), victim_id, raw_sync::now())
                .await
                .expect("step 1: a member of A connects"),
        );
        let pushed = raw_sync::answer_victim(Arc::clone(&conn));

        // ---- 2. the control: A is served --------------------------------------------------
        let a_held = entries(&victim.view(), a);
        let mut control = Yield::default();
        for _ in 0..20 {
            control = raw_sync::ask(&conn, a, 0, Ask::Everything, None).await;
            if control.hello {
                break;
            }
            // Refused because the victim is syncing A itself right now; it will not be for long.
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        println!("control: asked for A as its member → {control:?} (victim holds {a_held})");
        assert!(
            control.hello && control.entries as u64 == a_held,
            "step 2 FAILED, so a zero below would prove nothing: the member of A was not served \
             A's {a_held} entries — {control:?}"
        );

        // ---- 3. the attack: ask for B -------------------------------------------------------
        let mut leaked = 0usize;
        let mut answered = 0usize;
        for attempt in 1..=ATTEMPTS {
            let y = raw_sync::ask(&conn, b, 0, Ask::Everything, None).await;
            println!("attempt {attempt}: asked for B as a member of A only → {y:?}");
            leaked += y.entries;
            answered += usize::from(y.hello);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        println!("B entries served to a non-member: {leaked} over {ATTEMPTS} attempts ({answered} sessions answered)");
        assert_eq!(
            (answered, leaked),
            (0, 0),
            "a member of A was served room B — {leaked} of its entries over {answered} answered \
             sessions. A node must serve a room's log only to members of that room (PRD-001 R5)"
        );

        // ---- 4. nothing of B pushed the other way -------------------------------------------
        // The control for this direction: the victim's own push of A must have reached the
        // attacker, or a zero for B would only mean the victim never pushed anything.
        let a_pushed = tokio::time::timeout(TIMEOUT, async {
            loop {
                let got = pushed.lock().unwrap().clone();
                if got.iter().any(|(c, y)| *c == a && y.hello) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            a_pushed.is_ok(),
            "step 4's control FAILED: the victim never pushed room A to its member on a fresh \
             connection, so nothing below would be measured — {:?}",
            pushed.lock().unwrap()
        );
        // The push covers every open room in one pass; a moment for B's to land if it exists.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let pushed = pushed.lock().unwrap().clone();
        let pushed_b: usize = pushed.iter().filter(|(c, _)| *c == b).map(|(_, y)| y.entries).sum();
        let pushed_b_sessions = pushed.iter().filter(|(c, y)| *c == b && y.hello).count();
        let pushed_a: usize = pushed.iter().filter(|(c, _)| *c == a).map(|(_, y)| y.entries).sum();
        println!(
            "victim-initiated sessions: {} total; B: {pushed_b_sessions} sessions / {pushed_b} \
             entries; A: {pushed_a} entries",
            pushed.len()
        );
        assert_eq!(
            (pushed_b_sessions, pushed_b),
            (0, 0),
            "the victim opened sessions for room B to a member of A only and served it {pushed_b} \
             entries (PRD-001 R5)"
        );

        assert!(yara.apply(NodeCommand::Shutdown).await.is_done());
        assert!(victim.apply(NodeCommand::Shutdown).await.is_done());
    });
}
