//! ADR-007 G-23, G-25 (#380) — **an end written by an admin whose admin was taken back meanwhile
//! does not stand**: once the members' logs reconcile, no node treats the room as ended, the end's
//! own author's included. Driven through the shipped `vox` binary: a real `vox node` anchor and real
//! `vox daemon`s, every verb a separate `vox` process.
//!
//! **Why.** An admin may end a room (G-5); only the creator names and removes admins. A removal
//! beats an addition (G-25): a revocation concurrent with or after a delegation leaves the key no
//! admin. And an authority action made during a partition is provisional until its causal
//! neighbourhood reconciles (G-23). So an admin cut off while the creator takes its admin back, who
//! ends the room before it hears of that, has written an end that its own node rightly took (it
//! held no revocation), and that must not stand once the revocation and the end meet: otherwise
//! anyone whose admin is being taken back can end the room by going offline first.
//!
//! **Staging (a real partition).** alice (the creator), bob and carol share a room through an
//! anchor. alice names carol an admin; carol's node holds that. Carol's daemon is **down**, not
//! frozen (a frozen daemon finds what was sent to it waiting in its socket when it resumes), while
//! alice takes carol's admin back; bob's node holds the revocation. Then alice's and bob's daemons
//! and the anchor (which holds the room's entries too) are frozen (SIGSTOP), and carol's daemon is
//! started again: it can reach nobody who holds the revocation. Carol's node still lists her as an
//! admin, and `vox room end` succeeds there. Then everyone is resumed (SIGCONT), and the proof
//! waits until the logs have met: alice's and bob's nodes hold carol's end entry, and carol's node
//! holds the revocation.
//!
//! **Asserted:** alice's and bob's nodes take a post in the room (an ended room takes none), list
//! it without an end, and do so still [`SETTLE`] later; and carol's node, once it holds the
//! revocation, does too — still after its wind-down ([`WIND_DOWN`]), which would have deleted a
//! room it believed ended.
//!
//! Every red names its side: `PRODUCT:` what a node did; `PRODUCT (staging):` a `vox` step of the
//! staging, including a partition that did not hold (carol's end refused, so it never wrote one)
//! or logs that never met; `APPARATUS:` a signal that could not be sent.
//!
//! **The same for a retention** (`a_retention_set_by_an_admin_revoked_meanwhile_does_not_stand`):
//! carol, cut off, sets the room's retention — a policy update, which a delegated admin may make
//! (#319) — and once the logs meet every node keeps the retention the room had.
//!
//! **Mutations that must turn it red:** the room-lifecycle fold counting an end from an issuer that
//! was an admin in the end's strict past, whatever revocation is concurrent with it — removal-wins
//! not applied to an end; and the policy fold doing the same for a policy update (the core before
//! #380's fixes).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

/// How long a step's effect may take to reach another node.
const WITHIN: Duration = Duration::from_secs(60);
/// How long the room is watched afterwards for an end taking hold late.
const SETTLE: Duration = Duration::from_secs(15);
/// An ended room is deleted at most this long after its end, once every member has it or not
/// (`actor.rs` `WIND_DOWN`, 60 s), plus room for a tick.
const WIND_DOWN: Duration = Duration::from_secs(75);

fn signal(pid: u32, sig: &str, what: &str) {
    let sent = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "APPARATUS: `kill {sig}` {what} failed");
}

/// Wait up to `within` for `done`; whether it held.
fn until(within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Whether `w`'s node lists `fp` among the room's admins.
fn lists_admin(w: &support::Worker, room: &str, fp: &str) -> bool {
    let o = w.vox(None, &["room", "admin", "list", room]);
    o.ok && o.stdout.contains(fp)
}

/// The entry hashes of the messages `w`'s node holds for the room (`vox room read --json`).
fn order(w: &support::Worker, room: &str) -> std::collections::BTreeSet<String> {
    let o = w.vox(None, &["room", "read", room, "--json"]);
    o.ndjson()
        .iter()
        .filter_map(|v| v.get("entry_hash")?.as_str().map(str::to_owned))
        .collect()
}

/// What `w`'s node says of the room now: whether it takes a post, and how it lists the room.
fn standing(w: &support::Worker, room: &str, short: &str, n: usize) -> (support::Out, String) {
    let post = w.vox(
        None,
        &["room", "post", room, &format!("{} still here {n}", w.name)],
    );
    let listed = w.vox(None, &["room", "list"]);
    let line = listed
        .stdout
        .lines()
        .find(|l| l.starts_with(short))
        .unwrap_or("(not listed)")
        .to_owned();
    (post, line)
}

/// The partition, staged (see the module docs): alice names carol an admin; carol is down while
/// alice takes it back; alice, bob and the anchor are frozen while carol, back and cut off, posts
/// and then does `act` — which her node, still listing her as an admin, must take; then everyone is
/// resumed, and this returns once the logs have met: alice and bob hold carol's post (and so what
/// she did after it), and carol's node holds the revocation. The room, and the time the logs met.
fn partitioned(
    tmp: &std::path::Path,
    what: &str,
    act: impl FnOnce(&support::Worker, &str) -> support::Out,
) -> (support::Room, Instant) {
    let rt = tokio::runtime::Runtime::new().expect("APPARATUS: no runtime");
    let mut room = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(support::room(tmp, &["alice", "bob", "carol"]))
    }))
    .unwrap_or_else(|_| panic!("PRODUCT (staging): the room could not be set up"));
    let id = room.id.clone();
    let id = id.as_str();
    let carol_fp = room.workers[2].b32();

    // alice names carol an admin; carol's node holds it.
    let o = room.workers[0].vox(None, &["room", "admin", "add", id, &carol_fp]);
    assert!(o.ok, "PRODUCT (staging): `vox room admin add` carol: {o:?}");
    assert!(
        until(WITHIN, || lists_admin(&room.workers[2], id, &carol_fp)),
        "PRODUCT (staging): carol's node never listed her as an admin"
    );

    // Carol is down while alice takes her admin back; bob's node holds the revocation.
    room.stop(2);
    let o = room.workers[0].vox(None, &["room", "admin", "remove", id, &carol_fp]);
    assert!(
        o.ok,
        "PRODUCT (staging): `vox room admin remove` carol: {o:?}"
    );
    assert!(
        until(WITHIN, || !lists_admin(&room.workers[1], id, &carol_fp)),
        "PRODUCT (staging): bob's node never held alice's revocation of carol's admin"
    );

    // Everyone who holds the revocation is frozen; carol comes back cut off from all of them.
    let alice_d = room.workers[0]
        .daemon_pid()
        .expect("APPARATUS: no pid for alice's daemon");
    let bob_d = room.workers[1]
        .daemon_pid()
        .expect("APPARATUS: no pid for bob's daemon");
    let anchor_d = room.anchor_pid();
    let frozen = [
        (alice_d, "alice's daemon"),
        (bob_d, "bob's daemon"),
        (anchor_d, "the anchor"),
    ];
    for (pid, who) in frozen {
        signal(pid, "-STOP", who);
    }
    let staged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        room.restart(2);
        let carol = &room.workers[2];
        assert!(
            lists_admin(carol, id, &carol_fp),
            "PRODUCT (staging): carol's node held the revocation though cut off: the partition did \
             not hold"
        );
        // A post first: what carol does next names everything her node holds as its causal past,
        // this post included, so a node holding that holds the post. The post is what `vox room
        // read` shows (a governance entry is not in it); seeing it on alice's and bob's nodes is
        // the sign that carol's log, and what she did, reached them.
        let before = order(carol, id);
        let o = carol.vox(None, &["room", "post", id, "carol, cut off"]);
        assert!(o.ok, "PRODUCT (staging): carol's post while cut off: {o:?}");
        let posted = order(carol, id)
            .difference(&before)
            .cloned()
            .collect::<Vec<_>>();
        let o = act(carol, id);
        assert!(
            o.ok,
            "PRODUCT (staging): carol's node, still listing her as an admin, refused to {what}, so \
             nothing was written to test: {o:?}"
        );
        posted
    }));
    for (pid, who) in frozen {
        signal(pid, "-CONT", who);
    }
    let posted = staged.unwrap_or_else(|e| std::panic::resume_unwind(e));
    println!("[proof] carol, cut off, posted {posted:?} and did: {what}");
    assert!(
        !posted.is_empty(),
        "PRODUCT (staging): carol's post added no entry to her node's log"
    );

    // The logs meet: alice and bob hold what carol did, carol holds the revocation.
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let holds = |w: &support::Worker| {
        let held = order(w, id);
        posted.iter().all(|e| held.contains(e))
    };
    let met = until(WITHIN, || {
        holds(alice) && holds(bob) && !lists_admin(carol, id, &carol_fp)
    });
    assert!(
        met,
        "PRODUCT (staging): the logs never met within {WITHIN:?}: alice holds carol's post {}, bob \
         {}, carol holds the revocation {}",
        holds(alice),
        holds(bob),
        !lists_admin(carol, id, &carol_fp)
    );
    println!("[proof] the logs met: alice and bob hold what carol did, carol holds the revocation");
    (room, Instant::now())
}

#[test]
#[ignore = "real vox daemons and an anchor, a staged partition (SIGSTOP), over a minute"]
fn an_end_by_an_admin_revoked_meanwhile_does_not_stand() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (room, met_at) = partitioned(tmp.path(), "end the room", |carol, id| {
        carol.vox(None, &["room", "end", id])
    });
    let id = room.id.as_str();
    let short: String = id.chars().take(12).collect();
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let mut red = Vec::new();
    let mut check = |when: &str, n: usize, workers: &[&support::Worker]| {
        for w in workers {
            let (post, line) = standing(w, id, &short, n);
            println!(
                "[proof] {when}: {}'s node: post ok {}, listed {line:?}",
                w.name, post.ok
            );
            if !post.ok || line.contains('[') || line == "(not listed)" {
                red.push(format!(
                    "PRODUCT: {when}: {}'s node treats the room as ended by carol, whose admin \
                     alice had taken back before carol's end met it (ADR-007 G-23, G-25): post \
                     {post:?}; listed {line:?}",
                    w.name
                ));
            }
        }
    };
    check("once the logs met", 1, &[alice, bob, carol]);
    std::thread::sleep(SETTLE);
    check(&format!("{SETTLE:?} later"), 2, &[alice, bob, carol]);
    // Carol's node winds a room it believes ended down and deletes it; one that stopped believing
    // so keeps it.
    std::thread::sleep(WIND_DOWN.saturating_sub(met_at.elapsed()));
    check("past carol's wind-down", 3, &[alice, bob, carol]);
    assert!(red.is_empty(), "{red:#?}");
}

/// The retention a node applies to the room, from `vox status --json` (seconds; `0` forever).
fn retention(w: &support::Worker, room: &str) -> Option<u64> {
    let o = w.vox(None, &["status", "--json"]);
    o.json()["rooms"]
        .as_array()?
        .iter()
        .find(|r| r["id"].as_str() == Some(room))?["retention"]
        .as_u64()
}

#[test]
#[ignore = "real vox daemons and an anchor, a staged partition (SIGSTOP), over a minute"]
fn a_retention_set_by_an_admin_revoked_meanwhile_does_not_stand() {
    // The same partition: carol, cut off, sets the room's retention (a policy update, which a
    // delegated admin may make, #319). Once the logs meet, every node keeps the room's retention as
    // it was: removal wins over a policy update concurrent with the revocation (ADR-007 G-23, G-25).
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let set_to: u64 = 7 * 24 * 3600;
    let (room, _) = partitioned(
        tmp.path(),
        "set the room's retention to a week",
        |carol, id| {
            // A retention change asks for no passphrase (ADR-028 K-11).
            carol.vox(None, &["room", "retention", id, "1w"])
        },
    );
    let id = room.id.as_str();
    let mut red = Vec::new();
    for when in ["once the logs met", "later"] {
        if when == "later" {
            std::thread::sleep(SETTLE);
        }
        for w in &room.workers {
            let r = retention(w, id);
            println!(
                "[proof] {when}: {}'s node applies retention {r:?} s",
                w.name
            );
            if r == Some(set_to) || r.is_none() {
                red.push(format!(
                    "PRODUCT: {when}: {}'s node applies carol's retention ({r:?} s), set by carol \
                     while alice was taking her admin back (ADR-007 G-23, G-25)",
                    w.name
                ));
            }
        }
    }
    assert!(red.is_empty(), "{red:#?}");
}
