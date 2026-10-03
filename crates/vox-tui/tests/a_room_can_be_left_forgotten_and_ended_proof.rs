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
//! - **Rejoin.** Alice leaves, then joins again through bob with the room's address and passphrase,
//!   as anyone joins (the decider, 2026-10-01). Within [`WITHIN`] bob's and carol's rosters name her
//!   again (carol learns it only from her signed return), what she posts reaches both and what bob
//!   posts reaches her, and bob has not frozen her for signing two entries at one position: her
//!   joined-again node continued her feed rather than restarting it.
//! - **Forget.** Alice runs `vox room forget` on a room she is still in. It is left first (bob's
//!   roster loses her), then nothing of the room is left on her node: `vox room list` lacks it, it
//!   does not come back when her daemon restarts, and her `store.redb` no longer holds the room's
//!   id, which every one of its rows is keyed by. Before the forget it does: the control.
//! - **End.** Bob, who did not create the room, is refused `vox room admin add`. Alice, its
//!   creator, makes bob and carol admins (`vox room admin add`) and takes carol's back (`remove`);
//!   every member's `vox room admin list` says so. Carol is then refused `vox room end`, and bob, an
//!   admin, ends the room. Afterwards carol forgets it and joins again with its address and
//!   passphrase: she is told the room has ended, not that her passphrase is probably wrong. Within [`WITHIN`] every member's `vox room list` says it ended, every member's post
//!   is refused, and what was said before stays readable.
//! - **Idle end.** Alice makes a room with `vox room create --idle-end` [`IDLE`]. A message said
//!   before the idle time runs out keeps it going past [`IDLE`] from its creation; once nothing is
//!   said for [`IDLE`], every member sees it ended and a post is refused. The room `support::room`
//!   made without an idle end, idle for just as long, stays open: an idle end is never applied to
//!   a room whose creator did not choose one.
//!
//! - **The TUI.** The same verbs typed in `vox tui` (`tests/pty/tui_room_verb.py`, a pty read
//!   through `pyte`): carol's `:leave` drops her from alice's and bob's rosters; alice's `:end`
//!   reaches bob's `vox room list`; alice's `:forget` leaves her store without the room's id.
//!
//! **Every red names which it is.** `PRODUCT:` — `vox` did the wrong thing, and what it said is
//! quoted; `PRODUCT (staging):` — a `vox` step of the staging failed (a create, join, post or list
//! a person would run). `APPARATUS:` — the apparatus's own fault or a precondition it could not
//! stage (a temporary directory, a timing window, the TUI driver), so nothing about the claim was
//! measured. The watchdog (`support/watchdog.rs`) names itself when it fires.
//!
//! **Mutations that must turn it red:** a member that left still synced with (leave); a member
//! that joined again not saying it is back (rejoin); the room's rows not deleted (forget); a post
//! taken after the end, an admin's end ignored, or a join to an ended room refused as a wrong
//! passphrase (end); the idle end ignored (idle end).

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
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

/// The room `support::room` makes, or a `PRODUCT (staging)` red naming why it could not.
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
        panic!("PRODUCT (staging): the room could not be set up: {why}")
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
}

/// `w` runs `args`, a step of the staging that the product itself performs: a failure is the
/// product failing a person, `PRODUCT (staging)`.
fn setup(w: &Worker, args: &[&str]) -> Out {
    let o = w.vox(None, args);
    assert!(
        o.ok,
        "PRODUCT (staging): `vox {}` on {} failed: {o:?}",
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
        "PRODUCT (staging): ten posts between bob and carol drove no sync session between them \
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
fn a_member_that_left_joins_again_and_is_a_member_again() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    let link = setup(bob, &["room", "invite", id]).stdout.trim().to_owned();

    let o = alice.vox(None, &["room", "leave", id]);
    assert!(o.ok, "PRODUCT: `vox room leave` was refused: {o:?}");
    let (gone, o) = poll(bob, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&alice.b32())
    });
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after alice left, bob's roster still names her: {o:?}"
    );

    let t = Instant::now();
    let o = alice.vox_in(
        None,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "mission",
        ],
        Some("channel passphrase"),
    );
    assert!(
        o.ok,
        "PRODUCT: alice, who left, was refused joining again with the room's address and \
         passphrase: {o:?}\nbob's daemon said:\n{}",
        std::fs::read_to_string(tmp.path().join("bob.daemon.err")).unwrap_or_default()
    );
    // Bob answered her join; carol learns she is back only from her signed return.
    for w in [bob, carol] {
        let (back, o) = poll(w, &["room", "roster", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&alice.b32())
        });
        assert!(
            back,
            "PRODUCT: {WITHIN:?} after alice joined again, {}'s roster does not name her: {o:?}",
            w.name
        );
    }
    eprintln!(
        "[proof] rejoin: bob's and carol's rosters named alice again {:.1}s after her join began",
        t.elapsed().as_secs_f64()
    );
    // Rooms are forward-only (ADR-006): a member reads an author from the key the author released
    // to it, so a post made before that release stays unreadable to it, as for any member who has
    // just joined (`support::room` waits the same way). Each side keeps posting fresh messages
    // until the other reads one.
    let reads = |author: &Worker, reader: &Worker, what: &str| -> (bool, Out) {
        let deadline = Instant::now() + WITHIN;
        let mut n = 0u32;
        loop {
            n += 1;
            let o = author.vox(None, &["room", "post", id, &format!("{what} {n}")]);
            assert!(o.ok, "PRODUCT: {}'s post was refused: {o:?}", author.name);
            std::thread::sleep(Duration::from_secs(1));
            let r = reader.vox(None, &["room", "read", id]);
            if r.stdout.contains(what) {
                return (true, r);
            }
            if Instant::now() >= deadline {
                return (false, r);
            }
        }
    };
    let (read, o) = reads(alice, bob, "alice is back");
    assert!(
        read,
        "PRODUCT: within {WITHIN:?}, bob read none of what alice posted after joining again: \
         {o:?}\nalice's daemon said:\n{}\nbob's daemon said:\n{}",
        std::fs::read_to_string(tmp.path().join("alice.daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(tmp.path().join("bob.daemon.err")).unwrap_or_default()
    );
    let (read, o) = reads(alice, carol, "alice is back, carol");
    assert!(
        read,
        "PRODUCT: within {WITHIN:?}, carol read none of what alice posted after joining again: \
         {o:?}"
    );
    let (read, o) = reads(bob, alice, "welcome back, alice");
    assert!(
        read,
        "PRODUCT: within {WITHIN:?}, alice, joined again, read none of what bob posted: {o:?}"
    );
    // `frozen` is null while a session holds the room; read until it is said.
    let frozen: Vec<String> = {
        let deadline = Instant::now() + WITHIN;
        loop {
            let status = setup(bob, &["status", "--json"]).json();
            let row = status["rooms"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["id"] == id)
                .cloned();
            if let Some(list) = row.as_ref().and_then(|r| r["frozen"].as_array()) {
                break list
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_owned))
                    .collect();
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): bob's `vox status --json` never said whom it froze in the room within \
                 {WITHIN:?}, so a restarted feed could not be seen: {row:?}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    assert!(
        !frozen.iter().any(|f| *f == alice.b32()),
        "PRODUCT: bob froze alice for signing two entries at one position: her node restarted \
         her feed in the room when she joined again. Frozen: {frozen:?}"
    );
    eprintln!("[proof] rejoin: alice and bob read each other again, and bob froze nobody");
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
    // Checked the moment it answers: a forget that says it is done is done.
    assert!(
        !holds(&store),
        "PRODUCT: `vox room forget` answered, and alice's store.redb still holds the room's id, which keys every one of its rows: {}",
        store.display()
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
fn an_admin_the_creator_named_ends_a_room_and_then_it_takes_no_new_message() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    setup(bob, &["room", "post", id, "said before the end"]);
    let link = setup(alice, &["room", "invite", id])
        .stdout
        .trim()
        .to_owned();

    // Only the creator names admins.
    let o = bob.vox(None, &["room", "admin", "add", id, &carol.b32()]);
    assert!(
        !o.ok && o.stderr.contains("creator"),
        "PRODUCT: bob, who did not create the room, was not refused `vox room admin add`: {o:?}"
    );
    // Alice, the creator, makes bob and carol admins, then takes carol's back.
    for (args, what) in [
        (["room", "admin", "add", id, &bob.b32()], "add bob"),
        (["room", "admin", "add", id, &carol.b32()], "add carol"),
        (
            ["room", "admin", "remove", id, &carol.b32()],
            "remove carol",
        ),
    ] {
        let o = alice.vox(None, &args);
        assert!(
            o.ok,
            "PRODUCT: the creator's `vox room admin {what}` was refused: {o:?}"
        );
    }
    for w in [bob, carol] {
        let (seen, o) = poll(w, &["room", "admin", "list", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&bob.b32()) && !o.stdout.contains(&carol.b32())
        });
        assert!(
            seen,
            "PRODUCT: {WITHIN:?} after alice made bob an admin and took carol's back, {}'s \
             `vox room admin list` does not say so: {o:?}",
            w.name
        );
    }
    // An admin whose admin was taken back may not end the room.
    let o = carol.vox(None, &["room", "end", id]);
    assert!(
        !o.ok && o.stderr.contains("creator"),
        "PRODUCT: carol, whose admin was taken back, was not refused `vox room end`: {o:?}"
    );

    let t = Instant::now();
    let o = bob.vox(None, &["room", "end", id]);
    assert!(
        o.ok,
        "PRODUCT: bob, an admin the creator named, was refused `vox room end`: {o:?}"
    );
    for w in [alice, bob, carol] {
        let (ended, o) = poll(w, &["room", "list"], WITHIN, |o| {
            o.stdout
                .lines()
                .any(|l| l.starts_with(&id[..12]) && l.contains("ended"))
        });
        assert!(
            ended,
            "PRODUCT: {WITHIN:?} after bob, an admin, ended the room, {}'s `vox room list` \
             does not say it ended: {o:?}",
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

    // Joining an ended room is refused as that, not as a wrong passphrase: carol forgets it and
    // joins again with its address and passphrase.
    setup(carol, &["room", "forget", id]);
    let o = carol.vox_in(
        None,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "mission",
        ],
        Some("channel passphrase"),
    );
    assert!(
        !o.ok && o.stderr.contains("has ended") && !o.stderr.contains("passphrase is wrong"),
        "PRODUCT: a join to the ended room was not refused as the room having ended: {o:?}"
    );
    eprintln!("[proof] end: a join to the ended room was told it ended");
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
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "quiet",
            "--idle-end",
            &idle,
        ],
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
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): the new room is not in alice's `vox room list`")
        });
    let short = line.split_whitespace().next().unwrap().to_owned();
    let link = setup(alice, &["room", "invite", &short])
        .stdout
        .trim()
        .to_owned();
    let o = bob.vox_in(
        None,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "quiet",
        ],
        Some("idle room passphrase"),
    );
    assert!(
        o.ok,
        "PRODUCT (staging): bob could not join the idle room: {o:?}"
    );

    // Said before the idle time runs out: the room goes on past IDLE from its creation.
    assert!(
        made.elapsed() < IDLE / 2,
        "APPARATUS: bob's join took {:?}, past half the {IDLE:?} idle end, so a message said inside it could not be staged",
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

/// Run `:verb` in `w`'s `vox tui` (its daemon stopped), keeping it open `hold` after; a red for a
/// refusal (`PRODUCT`) or a driver that could not get there (`APPARATUS`).
fn tui_verb(w: &Worker, verb: &str, hold: Duration) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_room_verb.py");
    let tag = format!("[{} :{verb}]", w.name);
    let hold = hold.as_secs().to_string();
    let driven = pty_driver::run(
        script,
        &[
            support::VOX,
            w.data.to_str().unwrap(),
            w.cfg.to_str().unwrap(),
            "identity passphrase",
            "channel passphrase",
            &tag,
            verb,
            &hold,
        ],
    );
    eprintln!(
        "[proof] tui: {} -> {:?} in {:.1}s: {}",
        tag,
        driven.code,
        driven.took.as_secs_f64(),
        driven.stdout.trim()
    );
    // Stopped from outside before it said anything: the driver never got to measure.
    assert!(
        driven.has_verdict(&tag),
        "APPARATUS: the TUI driver for :{verb} on {} was stopped from outside before it gave a \
         verdict (stage {:?}), so nothing was measured",
        w.name,
        driven.stage
    );
    // A crashed driver is caught by `pty_driver::checked` as APPARATUS; its own staging fault is
    // exit 2. Every other non-pass — a refusal, no answer, a TUI that exited or stopped reading
    // (`HUNG`) — is the TUI not doing what the person typed (V210-107).
    match driven.code {
        Some(0) => {}
        Some(2) => panic!(
            "APPARATUS: the TUI driver for :{verb} on {} could not stage its run: {}",
            w.name, driven.stdout
        ),
        _ => panic!(
            "PRODUCT: `vox tui` did not do :{verb} on {} (exit {:?}, stage {:?}): {}",
            w.name, driven.code, driven.stage, driven.stdout
        ),
    }
}

#[test]
#[ignore = "real daemons, an anchor and `vox tui` in a pty, production Argon2id; needs pyte"]
fn the_tui_leaves_ends_and_forgets() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let cid = room.cid;

    room.workers[2].stop_daemon();
    tui_verb(&room.workers[2], "leave", Duration::from_secs(15));
    let carol = room.workers[2].b32();
    for w in &room.workers[..2] {
        let (gone, o) = poll(w, &["room", "roster", &id], WITHIN, |o| {
            o.ok && !o.stdout.contains(&carol)
        });
        assert!(
            gone,
            "PRODUCT: after carol's :leave in the TUI, {}'s roster still names her: {o:?}",
            w.name
        );
    }

    room.workers[0].stop_daemon();
    tui_verb(&room.workers[0], "end", Duration::from_secs(15));
    let bob = &room.workers[1];
    let (ended, o) = poll(bob, &["room", "list"], WITHIN, |o| {
        o.stdout
            .lines()
            .any(|l| l.starts_with(&id[..12]) && l.contains("ended"))
    });
    assert!(
        ended,
        "PRODUCT: after alice's :end in the TUI, bob's `vox room list` does not say the room \
         ended: {o:?}"
    );

    tui_verb(&room.workers[0], "forget", Duration::from_secs(3));
    let store = room.workers[0].paths.store_file();
    let bytes = std::fs::read(&store).unwrap_or_default();
    assert!(
        !bytes.windows(cid.len()).any(|w| w == cid),
        "PRODUCT: after alice's :forget in the TUI, her store.redb still holds the room's id: {}",
        store.display()
    );
    eprintln!("[proof] tui: :leave, :end and :forget each did what the CLI verb does");
}

#[test]
#[ignore = "real daemons, an anchor and the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn an_admin_cannot_name_another_admin() {
    watchdog::arm();
    let mutant = std::env::var("VOX_MUTANT_SENDER").unwrap_or_else(|_| {
        panic!(
            "APPARATUS (harness): VOX_MUTANT_SENDER does not name the mutant sender build \
             (VOX_MUTANT_SENDER=$(scripts/build-mutant-sender.sh))"
        )
    });
    let carries = |path: &str| {
        std::fs::read(path)
            .map(|b| b.windows(17).any(|w| w == b"VOX-MUTANT-SENDER"))
            .unwrap_or(false)
    };
    assert!(
        carries(&mutant) && !carries(support::VOX),
        "APPARATUS (harness): VOX_MUTANT_SENDER={mutant} is not the mutant sender build, or the \
         shipped binary carries its marker"
    );
    let rt = runtime();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let id = id.as_str();
    {
        let (alice, bob) = (&room.workers[0], &room.workers[1]);
        setup(alice, &["room", "admin", "add", id, &bob.b32()]);
        let (named, o) = poll(bob, &["room", "admin", "list", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&bob.b32())
        });
        assert!(
            named,
            "PRODUCT (staging): bob's `vox room admin list` does not name him {WITHIN:?} after \
             alice made him an admin: {o:?}"
        );
    }
    // Bob, an admin, runs a modified client that names admins though it did not create the room —
    // the attacker, as apparatus. Its certificate for carol must verify on no node.
    let bob_err = tmp.path().join("bob.mutant.err");
    room.workers[1].restart_daemon_as(
        &mutant,
        &[("VOX_MUTANT_SENDER_MODE", "admin-unentitled")],
        &bob_err,
    );
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let o = bob.vox(None, &["room", "admin", "add", id, &carol.b32()]);
    assert!(
        o.ok,
        "APPARATUS: bob's modified client did not sign an admin certificate for carol, so the \
         room's refusal of it was not staged: {o:?}\nits daemon said:\n{}",
        std::fs::read_to_string(&bob_err).unwrap_or_default()
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        for w in [alice, carol] {
            let o = setup(w, &["room", "admin", "list", id]);
            assert!(
                !o.stdout.contains(&carol.b32()),
                "PRODUCT: {} honours the admin certificate bob, an admin but not the creator, \
                 issued carol: {}",
                w.name,
                o.stdout
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let o = carol.vox(None, &["room", "end", id]);
    assert!(
        !o.ok,
        "PRODUCT: carol, named admin only by bob, ended the room: {o:?}"
    );
    let listed = setup(alice, &["room", "list"]).stdout;
    assert!(
        !listed.contains("ended"),
        "PRODUCT: the room ended on alice after carol, named admin only by bob, tried: {listed}"
    );
    eprintln!("[proof] admin: no node honoured the admin bob's modified client named");
}
