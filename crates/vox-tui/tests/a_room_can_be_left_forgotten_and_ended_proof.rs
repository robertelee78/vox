//! V030-08 (#244) — **a node can leave, forget and end rooms cleanly**, driven through the shipped
//! `vox` binary as a person or an agent runs it: real `vox daemon`s in one room, and every verb a
//! separate `vox` process.
//!
//! **Why.** Agents make a room per task and tear it down when the work is done (the decider,
//! 2026-09-28). Before this, the only exit was the TUI's `:close`, which kept the room's data on
//! disk, left the other members counting the node in and syncing with it, and nobody could end a
//! room for everyone.
//!
//! **Arms**, each a claim a person would check:
//! - **Leave.** Alice runs `vox room leave`. Within [`WITHIN`] bob's and carol's rosters no longer
//!   name her; from then on, while bob and carol keep posting to each other, bob opens and admits
//!   no sync session with alice (his `vox status --json` sync row for her stays still), alice is
//!   delivered none of the new posts, and her own post is refused as from a member who left.
//! - **Forget.** Alice runs `vox room forget` on a room she is still in. It is left first (bob's
//!   roster loses her), then nothing of the room is left on her node: `vox room list` lacks it, it
//!   does not come back when her daemon restarts, and her `store.redb` no longer holds the room's
//!   id, which every one of its rows is keyed by. Before the forget it does: the control.
//! - **End.** Bob, who did not create the room, is refused `vox room end`. Alice, its creator,
//!   ends it. Within [`WITHIN`] every member's `vox room list` says it ended, every member's post
//!   is refused, and what was said before stays readable.
//! - **Idle end.** Alice makes a room with `vox room create --idle-end` [`IDLE`]. A message said
//!   before the idle time runs out keeps it going past [`IDLE`] from its creation; once nothing is
//!   said for [`IDLE`], every member sees it ended and a post is refused. The room `support::room`
//!   made without an idle end, idle for just as long, stays open: an idle end is never applied to
//!   a room whose creator did not choose one.
//!
//! **Every red names which it is.** `PRODUCT:` — `vox` did the wrong thing, and what it said is
//! quoted. `APPARATUS:` — the staging was not achieved or a precondition is unmet (a setup verb
//! failed, posting drove no session at all), so nothing about the claim was measured. The watchdog
//! (`support/watchdog.rs`) names itself when it fires.
//!
//! **Mutations that must turn it red:** a member that left still synced with (leave); the room's
//! rows not deleted (forget); a post taken after the end (end); the idle end ignored (idle end).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use support::{Out, Room, Worker};

/// How long the other members may take to act on a leave or an end: the leaver's next sync with
/// each, which it starts at once.
const WITHIN: Duration = Duration::from_secs(30);
/// The idle end the idle arm chooses.
const IDLE: Duration = Duration::from_secs(40);

/// The room `support::room` makes, or an `APPARATUS` red naming why it could not.
fn room_of(rt: &tokio::runtime::Runtime, tmp: &std::path::Path, names: &[&str]) -> Room {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(support::room(tmp, names))
    }))
    .unwrap_or_else(|e| {
        let why = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        panic!("APPARATUS: the room could not be set up, so nothing was measured: {why}")
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
}

/// `w` runs `args`; an `APPARATUS` red if a setup verb fails.
fn setup(w: &Worker, args: &[&str]) -> Out {
    let o = w.vox(None, args);
    assert!(
        o.ok,
        "APPARATUS: setup verb `vox {}` on {} failed, so nothing was measured: {o:?}",
        args.join(" "),
        w.name
    );
    o
}

/// Poll `w`'s `vox args` until `ok` holds, for up to `within`; the last output either way.
fn poll(w: &Worker, args: &[&str], within: Duration, ok: impl Fn(&Out) -> bool) -> (bool, Out) {
    let deadline = Instant::now() + within;
    loop {
        let o = w.vox(None, args);
        if ok(&o) {
            return (true, o);
        }
        if Instant::now() >= deadline {
            return (false, o);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Sessions `w` has opened and admitted with `peer` in `room`, from its `vox status --json`.
fn sessions_with(w: &Worker, room: &str, peer: &str) -> u64 {
    let o = setup(w, &["status", "--json"]);
    o.json()["sync"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|r| r["room"] == room && r["peer"] == peer)
                .map(|r| r["opened"].as_u64().unwrap_or(0) + r["admitted"].as_u64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

/// `w`'s line for `room` in `vox room list`, or `None`.
fn listed(w: &Worker, room: &str) -> Option<String> {
    let short: String = room.chars().take(12).collect();
    setup(w, &["room", "list"])
        .stdout
        .lines()
        .find(|l| l.starts_with(&short))
        .map(str::to_owned)
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_member_that_left_is_synced_with_and_delivered_to_no_more() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    let room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();

    let t = Instant::now();
    let o = alice.vox(None, &["room", "leave", id]);
    assert!(o.ok, "PRODUCT: `vox room leave` was refused: {o:?}");
    for w in [bob, carol] {
        let (gone, o) = poll(w, &["room", "roster", id], WITHIN, |o| {
            o.ok && !o.stdout.contains(&alice.b32())
        });
        assert!(
            gone,
            "PRODUCT: {WITHIN:?} after alice left, {}'s roster still names her: {o:?}",
            w.name
        );
    }
    eprintln!(
        "[proof] leave: bob and carol dropped alice from their rosters within {:.1}s",
        t.elapsed().as_secs_f64()
    );

    // Give a session that was already running when the leave arrived its time to end, then count.
    std::thread::sleep(Duration::from_secs(3));
    let with_alice = sessions_with(bob, id, &alice.b32());
    let between = sessions_with(bob, id, &carol.b32());
    for n in 0..5 {
        setup(
            bob,
            &["room", "post", id, &format!("after alice left, bob {n}")],
        );
        setup(
            carol,
            &["room", "post", id, &format!("after alice left, carol {n}")],
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    let with_alice_after = sessions_with(bob, id, &alice.b32());
    let between_after = sessions_with(bob, id, &carol.b32());
    eprintln!(
        "[proof] leave: bob's sessions with alice {with_alice} -> {with_alice_after}, with carol \
         {between} -> {between_after}, over 10 posts"
    );
    assert!(
        between_after > between,
        "APPARATUS: ten posts between bob and carol drove no sync session between them \
         ({between} -> {between_after}), so a session with alice could not have shown either"
    );
    assert_eq!(
        with_alice_after, with_alice,
        "PRODUCT: bob kept syncing with alice after she left: his sessions with her went \
         {with_alice} -> {with_alice_after} while bob and carol posted"
    );
    let read = setup(alice, &["room", "read", id]);
    assert!(
        !read.stdout.contains("after alice left"),
        "PRODUCT: alice was delivered posts made after she left the room: {}",
        read.stdout
    );
    let o = alice.vox(None, &["room", "post", id, "alice, after leaving"]);
    assert!(
        !o.ok && o.stderr.contains("left"),
        "PRODUCT: alice's post after leaving was not refused as from a member who left: {o:?}"
    );
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_forgotten_room_leaves_nothing_on_the_node() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let id = room.id.clone();
    let cid = room.cid;
    let store = room.workers[0].paths.store_file();
    let holds = |path: &std::path::Path| -> bool {
        let bytes = std::fs::read(path).unwrap_or_default();
        bytes.windows(cid.len()).any(|w| w == cid)
    };
    assert!(
        holds(&store),
        "APPARATUS: alice's store.redb does not hold the room's id before the forget, so its \
         absence afterwards would show nothing: {}",
        store.display()
    );

    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let t = Instant::now();
    let o = alice.vox(None, &["room", "forget", &id]);
    assert!(o.ok, "PRODUCT: `vox room forget` was refused: {o:?}");
    eprintln!(
        "[proof] forget: done in {:.1}s; it said: {}",
        t.elapsed().as_secs_f64(),
        o.stdout.trim()
    );
    let (gone, o2) = poll(bob, &["room", "roster", &id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&alice.b32())
    });
    assert!(
        gone,
        "PRODUCT: alice forgot the room without leaving it: {WITHIN:?} later, bob's roster still \
         names her: {o2:?}"
    );
    assert!(
        listed(alice, &id).is_none(),
        "PRODUCT: `vox room list` still names the forgotten room: {:?}",
        listed(alice, &id)
    );
    assert!(
        !holds(&store),
        "PRODUCT: alice's store.redb still holds the forgotten room's id, which keys every one \
         of its rows: {}",
        store.display()
    );

    // A daemon that restarts does not bring it back.
    let err = tmp.path().join("alice.daemon.err");
    room.workers[0].restart_daemon(&err);
    let alice = &room.workers[0];
    assert!(
        listed(alice, &id).is_none(),
        "PRODUCT: the forgotten room came back when alice's daemon restarted: {:?}",
        listed(alice, &id)
    );
    assert!(
        !holds(&store),
        "PRODUCT: after a restart, alice's store.redb holds the forgotten room's id again"
    );
    eprintln!(
        "[proof] forget: the room's id is in none of alice's store, before or after a restart"
    );
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn only_the_creator_ends_a_room_and_then_it_takes_no_new_message() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    let room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    setup(bob, &["room", "post", id, "said before the end"]);

    let o = bob.vox(None, &["room", "end", id]);
    assert!(
        !o.ok && o.stderr.contains("creator"),
        "PRODUCT: bob, who did not create the room, was not refused `vox room end` as not its \
         creator: {o:?}"
    );

    let t = Instant::now();
    let o = alice.vox(None, &["room", "end", id]);
    assert!(
        o.ok,
        "PRODUCT: the creator's `vox room end` was refused: {o:?}"
    );
    for w in [alice, bob, carol] {
        let (ended, o) = poll(w, &["room", "list"], WITHIN, |o| {
            o.stdout
                .lines()
                .any(|l| l.starts_with(&id[..12]) && l.contains("ended"))
        });
        assert!(
            ended,
            "PRODUCT: {WITHIN:?} after the creator ended the room, {}'s `vox room list` does \
             not say it ended: {o:?}",
            w.name
        );
    }
    eprintln!(
        "[proof] end: every member listed the room as ended within {:.1}s",
        t.elapsed().as_secs_f64()
    );
    for w in [alice, bob, carol] {
        let o = w.vox(None, &["room", "post", id, "said after the end"]);
        assert!(
            !o.ok && o.stderr.contains("ended"),
            "PRODUCT: {}'s post was taken after the room ended: {o:?}",
            w.name
        );
    }
    let (readable, o) = poll(carol, &["room", "read", id], WITHIN, |o| {
        o.stdout.contains("said before the end")
    });
    assert!(
        readable,
        "PRODUCT: what was said before the end is no longer readable on carol: {o:?}"
    );
    assert!(
        !o.stdout.contains("said after the end"),
        "PRODUCT: carol shows a message said after the end: {}",
        o.stdout
    );
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_chosen_idle_end_ends_a_quiet_room_and_only_that_room() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    // `support::room` makes the control: a room with no idle end, its members trusting each other.
    let room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let control = room.id.as_str();

    let before: Vec<String> = setup(alice, &["room", "list"])
        .stdout
        .lines()
        .map(str::to_owned)
        .collect();
    let idle = format!("{}", IDLE.as_secs());
    let o = alice.vox_in(
        None,
        &["room", "create", "--name", "quiet", "--idle-end", &idle],
        Some("idle room passphrase"),
    );
    assert!(
        o.ok,
        "PRODUCT: `vox room create --idle-end` was refused: {o:?}"
    );
    let made = Instant::now();
    let line = setup(alice, &["room", "list"])
        .stdout
        .lines()
        .find(|l| !before.contains(&l.to_string()))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("APPARATUS: the new room is not in alice's `vox room list`"));
    let short = line.split_whitespace().next().unwrap().to_owned();
    let link = setup(alice, &["room", "invite", &short])
        .stdout
        .trim()
        .to_owned();
    let o = bob.vox_in(
        None,
        &["room", "join", &link, "--name", "quiet"],
        Some("idle room passphrase"),
    );
    assert!(o.ok, "APPARATUS: bob could not join the idle room: {o:?}");

    // Said before the idle time runs out: the room goes on past IDLE from its creation.
    assert!(
        made.elapsed() < IDLE / 2,
        "APPARATUS: bob's join took {:?}, past half the {IDLE:?} idle end, so a message said          inside it could not be staged",
        made.elapsed()
    );
    std::thread::sleep((made + IDLE / 2).saturating_duration_since(Instant::now()));
    setup(alice, &["room", "post", &short, "still here"]);
    let said = Instant::now();
    let wait = (made + IDLE + Duration::from_secs(2)).saturating_duration_since(Instant::now());
    std::thread::sleep(wait);
    assert!(
        said.elapsed() < IDLE,
        "APPARATUS: the check of a room past its idle time since creation came {:?} after the \
         last message, past the idle time itself, so it measures nothing",
        said.elapsed()
    );
    let o = bob.vox(None, &["room", "post", &short, "bob, before the idle end"]);
    assert!(
        o.ok,
        "PRODUCT: the room ended {:?} after its creation though a message was said {:?} ago, \
         within its {IDLE:?} idle end: {o:?}",
        made.elapsed(),
        said.elapsed()
    );

    // Nothing said for IDLE: it ends, on both members.
    std::thread::sleep(IDLE + Duration::from_secs(5));
    for w in [alice, bob] {
        let (ended, o) = poll(w, &["room", "list"], WITHIN, |o| {
            o.stdout
                .lines()
                .any(|l| l.starts_with(&short) && l.contains("ended"))
        });
        assert!(
            ended,
            "PRODUCT: {}'s `vox room list` does not say the room ended after {IDLE:?} with \
             nothing said in it: {o:?}",
            w.name
        );
        let o = w.vox(None, &["room", "post", &short, "after the idle end"]);
        assert!(
            !o.ok && o.stderr.contains("ended"),
            "PRODUCT: {}'s post was taken after the room's idle end: {o:?}",
            w.name
        );
    }

    // The control: idle at least as long, never chose an idle end, still open.
    let o = alice.vox(None, &["room", "post", control, "the control room goes on"]);
    assert!(
        o.ok,
        "PRODUCT: the room made with no idle end refused a post after the same quiet time: {o:?}"
    );
    assert!(
        listed(alice, control).is_some_and(|l| !l.contains("ended")),
        "PRODUCT: the room made with no idle end is listed as ended: {:?}",
        listed(alice, control)
    );
    eprintln!(
        "[proof] idle end: the {IDLE:?} room ended after {:?} quiet; the room with none stays open",
        IDLE + Duration::from_secs(5)
    );
}
