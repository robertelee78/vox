//! **A room kept busy still tells its anchor about a new member** (#180).
//!
//! Sync sessions are per (room, peer), so a room whose members post steadily over a network with
//! any distance is in *some* session nearly all the time. The anchor publish, and the pass that
//! admits members a board has just learnt of, used to be deferred while the room had *any*
//! session running, and run when a session ended and the room had none left. With sessions
//! overlapping that moment need not come, so a busy room's anchor was never told of its new
//! member, and anyone reading that board saw a stale roster.
//!
//! An anchor learns a room's members **only from a member** (a joiner's own records are refused
//! until one vouches), so the anchor's member count is exactly the observable: it moves only when
//! a member's publish lands. Here Alice, Bob and Carol post every [`POST_EVERY`] over a virtual
//! network with [`ONE_WAY`] of delay each way, which keeps each of their sessions open for a few
//! round trips and their sessions overlapping. Dave joins through Alice while they post. From
//! Dave's join returning to the anchor's board counting four members must be within [`BOUND`].
//!
//! Mutation: defer the anchor publish and the new-member pass while the room has any session
//! running (the pre-fix behaviour), and the anchor is not told within the bound.
//!
//! Real node actors through the client API over the virtual network of `support/vnet.rs`, with
//! production Argon2id; the ADR-005 PoW is reduced to keep the join to seconds.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vnet::VirtualNet;
use vox_core::identity::composite::RootSigner;
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

/// Each way, between every pair: a WAN peer's distance, so a session lasts a few round trips.
const ONE_WAY: Duration = Duration::from_millis(40);
/// How often each busy member posts.
const POST_EVERY: Duration = Duration::from_millis(100);
/// How long the posting runs before Dave joins, so sessions are already overlapping.
const BUSY_BEFORE_JOIN: Duration = Duration::from_secs(3);
/// A publish round is a couple of round trips (~160 ms here); the anchor's count is read every
/// 50 ms. Far below the "not while the room stays busy" of the defect.
const BOUND: Duration = Duration::from_secs(3);
/// How long the anchor is watched after Dave joins, with the posting going on throughout.
const WATCH: Duration = Duration::from_secs(30);
/// Everything else: identities, the room, the joins.
const TIMEOUT: Duration = Duration::from_secs(120);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

async fn node(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
) -> NodeHandle {
    let mut cfg = NodeConfig::new()
        .bind(Bind::Socket(socket))
        .anchors(anchors);
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    let h = Node::spawn_config(paths(tmp, name), cfg).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase")
        })
        .await
        .is_done());
    h
}

/// The anchor's member count for `cid`, or 0 while it does not anchor the room.
fn members_on(anchor: &NodeHandle, cid: [u8; 32]) -> usize {
    anchor
        .view()
        .anchoring
        .iter()
        .find(|a| a.channel_id == cid)
        .map_or(0, |a| a.members)
}

async fn join(h: &NodeHandle, name: &str, url: &str) -> Instant {
    let out = tokio::time::timeout(
        TIMEOUT,
        h.apply(NodeCommand::JoinChannel {
            link: url.to_owned(),
            local_name: "team".into(),
            passphrase: secret("channel passphrase"),
        }),
    )
    .await
    .expect("the join did not hang");
    assert!(out.is_done(), "{name} joins: {out:?}");
    Instant::now()
}

/// Wait until the anchor counts `want` members for `cid`, up to `deadline`.
async fn anchor_counts(
    anchor: &NodeHandle,
    cid: [u8; 32],
    want: usize,
    deadline: Instant,
) -> Option<Instant> {
    loop {
        if members_on(anchor, cid) >= want {
            return Some(Instant::now());
        }
        if Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
#[ignore = "production Argon2id, four members and an anchor: ~20 s in release; CI runs it there"]
fn a_busy_room_still_reaches_its_anchor() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let net = VirtualNet::new();
        net.set_delay(ONE_WAY);
        let at = |i: u8| -> SocketAddr { format!("198.51.100.{i}:443").parse().unwrap() };

        // A headless anchor, as `vox node` runs one: a board, no room, no log.
        let signer =
            vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
        let anchor_fp = signer.fingerprint();
        let anchor = Node::spawn_config(
            paths(&tmp, "anchor"),
            NodeConfig::new()
                .bind(Bind::Socket(net.public(at(1))))
                .headless(signer),
        )
        .unwrap();
        let mut anchors = BootstrapSet::new();
        anchors
            .add(
                BootstrapNode::new(
                    anchor_fp,
                    EndpointList::new(vec![Multiaddr::from(at(1))]).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

        let alice = node(&tmp, "alice", net.public(at(2)), anchors.clone()).await;
        let bob = node(&tmp, "bob", net.public(at(3)), anchors.clone()).await;
        let carol = node(&tmp, "carol", net.public(at(4)), anchors.clone()).await;
        let dave = node(&tmp, "dave", net.public(at(5)), anchors).await;
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
        let url = tokio::time::timeout(TIMEOUT, async {
            loop {
                match alice.next_event().await {
                    Some(NodeEvent::InviteLink { channel_id, url }) if channel_id == cid => {
                        return url
                    }
                    Some(_) => {}
                    None => panic!("event stream ended"),
                }
            }
        })
        .await
        .expect("an invite link");
        join(&bob, "bob", &url).await;
        join(&carol, "carol", &url).await;
        // The anchor knows the three before anything is busy: otherwise the count below measures
        // the earlier joins, not Dave's.
        assert!(
            anchor_counts(&anchor, cid, 3, Instant::now() + TIMEOUT)
                .await
                .is_some(),
            "CANNOT MEASURE: the anchor never counted 3 members with the room idle (it counts {})",
            members_on(&anchor, cid)
        );

        // Three members post steadily until told to stop.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let posters: Vec<_> = [&alice, &bob, &carol]
            .into_iter()
            .enumerate()
            .map(|(who, h)| {
                let (h, stop) = (h.clone(), Arc::clone(&stop));
                tokio::spawn(async move {
                    let mut posted = 0usize;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let text = format!("busy-{who}-{posted}");
                        if h
                            .apply(NodeCommand::SendText {
                                channel_id: cid,
                                text,
                            })
                            .await
                            .is_done()
                        {
                            posted += 1;
                        }
                        tokio::time::sleep(POST_EVERY).await;
                    }
                    posted
                })
            })
            .collect();
        tokio::time::sleep(BUSY_BEFORE_JOIN).await;
        let before = members_on(&anchor, cid);
        let joined = join(&dave, "dave", &url).await;
        let shown = anchor_counts(&anchor, cid, 4, joined + WATCH).await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut posts = Vec::new();
        for p in posters {
            posts.push(p.await.unwrap());
        }
        let took = shown.map(|t| t.duration_since(joined));
        eprintln!(
            "posts (alice, bob, carol): {posts:?}; anchor counted {before} before the join, and \
             dave {}",
            took.map_or(
                format!("never within {WATCH:?} (it counts {})", members_on(&anchor, cid)),
                |d| format!("{d:?} after the join returned")
            )
        );
        assert_eq!(before, 3, "CANNOT MEASURE: the anchor counted {before} before Dave joined");
        assert!(
            posts.iter().all(|&n| n >= 20),
            "CANNOT MEASURE: the room was not kept busy, posts {posts:?}"
        );
        assert!(
            took.is_some_and(|d| d <= BOUND),
            "with the room kept busy the anchor counted dave {took:?} after the join, bound \
             {BOUND:?}: the members' anchor publish was deferred behind the room's sessions"
        );
        for h in [&alice, &bob, &carol, &dave, &anchor] {
            let _ = h.apply(NodeCommand::Shutdown).await;
        }
    });
}
