//! V030-08 (#244) — **a node can leave a room, and an admin can end one, cleanly**, driven
//! through the shipped `vox` binary as a person or an agent runs it: real `vox daemon`s in one
//! room, and every verb a separate `vox` process.
//!
//! **Why.** Agents make a room per task and tear it down when the work is done (the decider,
//! 2026-09-28). Leaving deletes the room from the node that left, and ending it deletes it from
//! every member's node, with no `forget` step (the decider, 2026-10-03).
//!
//! **Arms**, each a claim a person would check:
//! - **Leave.** Alice runs `vox room leave`. Within [`WITHIN`] bob's and carol's rosters no longer
//!   name her; bob and carol still read each other's fresh messages while alice cannot read
//!   the room she left.
//!   A restored pre-Leave profile cannot read Bob's post-Leave content.
//! - **Nothing left.** Alice leaves a room she shares with bob. Its live room rows and SEK wrap
//!   are gone, the room is unreadable and unlisted before and after a daemon restart, and the
//!   exact previously saved sealed SEK wrap is physically absent from the rewritten store.
//!   ADR-023 RL-8.4's separate non-secret continuity checkpoint and withdrawal bookkeeping may remain.
//! - **Rejoin.** Alice leaves, then joins again through bob with the room's address and passphrase,
//!   as anyone joins. Within [`WITHIN`] bob's and carol's rosters name her again through her
//!   verified admission notice. After automatic own-history recovery her posts reach both; bob's
//!   posts reach her, and nobody reports her signing two entries at one position. Then
//!   she leaves again, joins again and leaves a third time (#564): each leave drops her from bob's
//!   and carol's rosters within [`WITHIN`], as the first did.
//! - **End.** Bob, who did not create the room, is refused `vox room admin add`. Alice, its
//!   creator, makes bob and carol admins and takes carol's back; every member's `vox room admin
//!   list` says so. Carol is then refused `vox room end`, and bob, an admin, ends the room. Within
//!   [`GONE`] the room is gone from every member's list, live room rows and SEK wraps, and so
//!   are the read cursors each member's agent session (`vox agent hook`) kept for it, with no forget.
//!   carol joins again with its address and passphrase: she is told the room has ended, not that
//!   her passphrase is probably wrong.
//! - **Idle end.** Alice makes a room with `vox room create --idle-end` [`IDLE`]. A message said
//!   before the idle time runs out keeps it going past [`IDLE`] from its creation; once nothing is
//!   said for [`IDLE`], it is gone from both members. The room `support::room` made without an
//!   idle end, idle for just as long, stays: an idle end is never applied to a room whose creator
//!   did not choose one.
//! - **The TUI.** The same verbs typed in `vox tui` (`tests/pty/tui_room_verb.py`, a pty read
//!   through `pyte`): carol's `:leave` drops her from alice's and bob's rosters and erases her
//!   room content and keys; alice's `:end` takes the room off bob's `vox room list`. Each first asks to be
//!   confirmed in words that state its effect, and then says what it did, not "done" (ADR-028
//!   E-5).
//! - **The CLI says it too** (ADR-028 E-5): `vox room leave` and `vox room end` each say, before
//!   they act, what they are to do (a line starting "vox: about to leave" or "vox: about to end"
//!   that names the room), and after, what they did.
//!
//! **Every red names which it is.** `PRODUCT:` — `vox` did the wrong thing, and what it said is
//! quoted; `PRODUCT (staging):` — a `vox` step of the staging failed (a create, join, post or list
//! a person would run). `APPARATUS:` — the apparatus's own fault or a precondition it could not
//! stage (a temporary directory, a timing window, the TUI driver), so nothing about the claim was
//! measured. The watchdog (`support/watchdog.rs`) names itself when it fires.
//!
//! **Mutations that must turn it red:** a leave that keeps the room (leave, nothing left); a
//! member that left still synced with (leave); an end that leaves the members' copies (end, idle
//! end, TUI), or their agent cursor files (end); a post taken after the end, an admin's end ignored, or a join to an ended room
//! refused as a wrong passphrase (end); the TUI's `:leave` acting with no confirmation, or saying
//! "done" in place of what it did (TUI); the CLI's before-sentence dropped (leave); a readmission
//! that outlives the departure it undid (rejoin: alice's second leave never leaves bob's roster).

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use redb::ReadableDatabase;
use std::time::{Duration, Instant};

use support::{Out, Room, Worker};

/// How long the other members may take to act on a leave or an end: the leaver's next sync with
/// each, which it starts at once.
const WITHIN: Duration = Duration::from_secs(30);
/// The idle end the idle arm chooses.
const IDLE: Duration = Duration::from_secs(40);
/// How long every member may take to delete an ended room: it passes the end on first, to each
/// member at its next sync, or for up to the node's 60 s wind-down when one cannot be reached.
const GONE: Duration = Duration::from_secs(90);

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

fn unavailable(w: &Worker, room: &str) {
    assert!(
        listed(w, room).is_none(),
        "PRODUCT: {} still lists the deleted room",
        w.name
    );
    let read = w.vox(None, &["room", "read", room]);
    assert!(
        !read.ok && read.stdout.is_empty(),
        "PRODUCT: {} still reads the deleted room: {read:?}",
        w.name
    );
}

fn erased(w: &mut Worker, room: &str, cid: &[u8; 32], checkpoint: bool) {
    unavailable(w, room);
    // Inspect only a stopped binary's committed file, as the P1 checkpoint proof does.
    w.stop_daemon_cleanly();
    {
        let path = w.paths.store_file();
        let db = redb::Database::builder()
            .open_read_only(&path)
            .unwrap_or_else(|e| panic!("APPARATUS: open {} read-only: {e}", path.display()));
        let read = db.begin_read().expect("APPARATUS: read stopped store");
        let segments = read
            .open_table(redb::TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(
                "segments",
            ))
            .expect("APPARATUS: open sealed segments");
        let rows: Vec<_> = segments
            .range((*cid, 0, 0)..=(*cid, u8::MAX, u64::MAX))
            .expect("APPARATUS: range room rows")
            .map(|row| row.expect("APPARATUS: read room row").0.value())
            .collect();
        // ADR-023 RL-8.1 / RL-8.4: retain only the separate non-secret checkpoint,
        // never message bodies, room keys, passphrases or a second room log.
        assert!(
            rows.is_empty(),
            "PRODUCT: {} kept deleted room rows: {rows:?}",
            w.name
        );
        let wraps = read
            .open_table(redb::TableDefinition::<[u8; 32], &[u8]>::new("sek_wraps"))
            .expect("APPARATUS: open SEK wraps");
        assert!(
            wraps.get(*cid).expect("APPARATUS: read SEK wrap").is_none(),
            "PRODUCT: {} kept the deleted room's SEK wrap",
            w.name
        );
        let mut binding = b"vox/own-continuity-scope/v1".to_vec();
        binding.extend_from_slice(cid);
        binding.extend_from_slice(&w.fp);
        let scope = vox_core::hash::sha256(&binding);
        let markers: Vec<_> = segments
            .range((scope, 0, 0)..=(scope, u8::MAX, u64::MAX))
            .expect("APPARATUS: range continuity rows")
            .map(|row| row.expect("APPARATUS: read continuity row").0.value())
            .collect();
        let expected = if checkpoint {
            vec![(scope, 4, 0)]
        } else {
            Vec::new()
        };
        assert_eq!(
            markers, expected,
            "PRODUCT: {} did not retain exactly the permitted public continuity checkpoint",
            w.name
        );
    }
    let log = w.data.join("erasure-restart.daemon.err");
    w.restart_daemon(&log);
    unavailable(w, room);
}

/// The files under `w`'s agent cursor directory (read cursors and held claims) filed under `room`.
fn cursors_of(w: &Worker, room: &str) -> Vec<String> {
    let prefix: String = room.chars().take(8).collect();
    let dir = w.paths.cursor_dir();
    [dir.clone(), dir.join("held")]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|f| f.starts_with(&prefix))
        .collect()
}

/// `w`'s line for `room` in `vox room list`, or `None`.
/// Whether `o` said what it was to do before it acted and what it did after (ADR-028 E-5): a line
/// "vox: about to <verb>" naming the room "mission", and after it a line starting `after`.
fn said_before_and_after(o: &Out, verb: &str, after: &str) -> bool {
    let lines: Vec<&str> = o.stdout.lines().collect();
    let before = lines
        .iter()
        .position(|l| l.starts_with(&format!("vox: about to {verb}")) && l.contains("\"mission\""));
    let done = lines.iter().position(|l| l.starts_with(after));
    matches!((before, done), (Some(b), Some(a)) if b < a)
}

fn listed(w: &Worker, room: &str) -> Option<String> {
    let short: String = room.chars().take(12).collect();
    setup(w, &["room", "list"])
        .stdout
        .lines()
        .find(|l| l.starts_with(&short))
        .map(str::to_owned)
}

/// Copy a stopped scratch profile's regular files, leaving transient sockets behind.
fn copy_profile_tree(source: &std::path::Path, dest: &std::path::Path) {
    std::fs::create_dir_all(dest).expect("APPARATUS: create profile backup directory");
    for entry in std::fs::read_dir(source).expect("APPARATUS: read profile backup source") {
        let entry = entry.expect("APPARATUS: read profile backup entry");
        let kind = entry
            .file_type()
            .expect("APPARATUS: inspect profile backup entry");
        if kind.is_dir() {
            copy_profile_tree(&entry.path(), &dest.join(entry.file_name()));
        } else if kind.is_file() {
            std::fs::copy(entry.path(), dest.join(entry.file_name()))
                .expect("APPARATUS: copy profile backup file");
        }
    }
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_member_that_left_is_synced_with_and_delivered_to_no_more() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let before = "bob before alice left";
    setup(&room.workers[1], &["room", "post", &room.id, before]);
    support::until(
        &room.workers[0],
        None,
        "alice reads bob before leave",
        &["room", "read", &room.id],
        |o| o.ok && o.stdout.contains(before),
    );
    let backup_data = tmp.path().join("alice-before-leave-data");
    let backup_cfg = tmp.path().join("alice-before-leave-config");
    room.workers[0].stop_daemon_cleanly();
    copy_profile_tree(&room.workers[0].data, &backup_data);
    copy_profile_tree(&room.workers[0].cfg, &backup_cfg);
    #[cfg(feature = "test-knobs")]
    let hold = tmp.path().join("departure-hold");
    #[cfg(feature = "test-knobs")]
    let departed_as_member = tmp.path().join("departed-as-member");
    #[cfg(feature = "test-knobs")]
    for index in [1, 2] {
        room.workers[index].restart_daemon_as(
            support::VOX,
            &[
                ("VOX_TEST_DEPARTURE_HOLD_FILE", hold.to_str().unwrap()),
                (
                    "VOX_TEST_DEPARTED_AS_MEMBER_FILE",
                    departed_as_member.to_str().unwrap(),
                ),
            ],
            &tmp.path().join(format!("departure-peer-{index}.err")),
        );
    }
    #[cfg(feature = "test-knobs")]
    room.workers[0].restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_DEPARTURE_HOLD_FILE", hold.to_str().unwrap())],
        &tmp.path().join("alice-before-leave.err"),
    );
    #[cfg(not(feature = "test-knobs"))]
    room.workers[0].restart_daemon(&tmp.path().join("alice-before-leave.err"));
    let (ready, seen) = poll(&room.workers[0], &["room", "read", &room.id], WITHIN, |o| {
        o.ok
    });
    assert!(
        ready,
        "APPARATUS: restored creator room did not finish preparing: {seen:?}"
    );
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();

    let t = Instant::now();
    // Stage a live commitment response while neither peer can apply the departure.
    #[cfg(feature = "test-knobs")]
    let o = std::thread::scope(|scope| {
        std::fs::write(&hold, b"hold").expect("APPARATUS: arm departure hold");
        let (tx, rx) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = tx.send(alice.vox(None, &["room", "leave", id]));
        });
        let deadline = Instant::now() + WITHIN;
        while !hold.with_extension("live").is_file() {
            assert!(
                Instant::now() < deadline,
                "APPARATUS: departure live discovery did not stage"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        for w in [bob, carol] {
            let roster = w.vox(None, &["room", "roster", id]);
            assert!(
                roster.ok && roster.stdout.contains(&alice.b32()),
                "APPARATUS: {} already applied Alice's departure: {roster:?}",
                w.name
            );
        }
        let early = rx.recv_timeout(Duration::from_secs(3));
        std::fs::remove_file(&hold).expect("APPARATUS: release departure hold");
        assert!(
            early.is_err(),
            "PRODUCT: Alice's leave returned before any peer applied her departure: {early:?}"
        );
        rx.recv_timeout(WITHIN)
            .expect("PRODUCT: Alice's leave did not finish after peers resumed")
    });
    #[cfg(not(feature = "test-knobs"))]
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
    #[cfg(feature = "test-knobs")]
    if std::env::var("VOX_MUTANT_FX28").as_deref() == Ok("sync-departed-peer") {
        std::fs::write(&departed_as_member, b"armed")
            .expect("APPARATUS: arm departed-member mutant after Leave");
    }

    // Let sessions already underway at the departure finish before measuring.
    std::thread::sleep(Duration::from_secs(3));
    // A restored pre-Leave profile is a real peer that still thinks it belongs to the room.
    room.workers[0].stop_daemon();
    copy_profile_tree(&backup_data, &room.workers[0].data);
    copy_profile_tree(&backup_cfg, &room.workers[0].cfg);
    room.workers[0].restart_daemon(&tmp.path().join("alice-restored.err"));
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    // ADR-018: actual recipient reads demonstrate continuing delivery, not sync counters.
    let bob_text = "bob after alice left";
    let carol_text = "carol after alice left";
    setup(bob, &["room", "post", id, bob_text]);
    setup(carol, &["room", "post", id, carol_text]);
    support::until(
        carol,
        None,
        "carol reads bob without alice",
        &["room", "read", id],
        |o| o.ok && o.stdout.contains(bob_text),
    );
    support::until(
        bob,
        None,
        "bob reads carol without alice",
        &["room", "read", id],
        |o| o.ok && o.stdout.contains(carol_text),
    );
    let (leaked, read) = poll(alice, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains(bob_text)
    });
    assert!(
        !leaked,
        "PRODUCT: restored departed Alice read Bob's post-Leave content: {read:?}"
    );
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_member_that_left_joins_again_and_is_a_member_again() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    #[allow(unused_mut)]
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    #[cfg(feature = "test-knobs")]
    let return_hold = tmp.path().join("return-presence-hold");
    #[cfg(feature = "test-knobs")]
    {
        room.workers[0].restart_daemon_as(
            support::VOX,
            &[(
                "VOX_TEST_HOLD_RETURN_PRESENCE_FILE",
                return_hold.to_str().expect("APPARATUS: return hold path"),
            )],
            &tmp.path().join("alice-return-proof.err"),
        );
        let (ready, seen) = poll(&room.workers[0], &["room", "read", &room.id], WITHIN, |o| {
            o.ok
        });
        assert!(
            ready,
            "APPARATUS: restarted Alice did not prepare: {seen:?}"
        );
    }
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    let link = setup(bob, &["room", "link", id]).stdout.trim().to_owned();

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
        &["room", "join", "--passphrase-file", "-", &link],
        Some("channel passphrase"),
    );
    assert!(
        o.ok,
        "PRODUCT: alice, who left, was refused joining again with the room's address and \
         passphrase: {o:?}\nbob's daemon said:\n{}",
        std::fs::read_to_string(tmp.path().join("bob.daemon.err")).unwrap_or_default()
    );
    // RL-8.5: Carol learns recovery standing from the verified admission notice.
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
            if !o.ok {
                // ADR-023 RL-8.5 / ADR-037 R5: a rejoin may truthfully refuse writes
                // until own-history recovery finishes, automatically and without operator action.
                assert!(o.stderr.contains("own history") && o.stderr.contains("until that is resolved"),
                    "PRODUCT: {}'s interim post did not explain pending own-history recovery: {o:?}", author.name);
                assert!(
                    Instant::now() < deadline,
                    "PRODUCT: {} never recovered automatically and accepted a post: {o:?}",
                    author.name
                );
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
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

    // **Leaving again is a leave** (#564): bob, who let alice in again, kept her readmission for
    // good, so her second departure reached him and was never applied. Leave, join again, leave:
    // each leave drops her from bob's and carol's rosters within the bound the first one had, and
    // a second readmission does not stand for the third leave either.
    let leaves = |n: u32| {
        // ADR-023 RL-8.5 / ADR-037 R5: Accepted can precede own-history recovery.
        // A third immediate Leave waits for that recovery without an operator repair.
        let (left, o) = poll(alice, &["room", "leave", id], WITHIN, |o| {
            o.ok || !o.stderr.contains("record of its own history")
        });
        assert!(
            left && o.ok,
            "PRODUCT: alice's leave {n} was refused: {o:?}"
        );
        for w in [bob, carol] {
            let (gone, o) = poll(w, &["room", "roster", id], WITHIN, |o| {
                o.ok && !o.stdout.contains(&alice.b32())
            });
            assert!(
                gone,
                "PRODUCT: {WITHIN:?} after alice's leave {n}, {}'s roster \
                 still names her: {o:?}\n{}'s daemon said:\n{}",
                w.name,
                w.name,
                std::fs::read_to_string(tmp.path().join(format!("{}.daemon.err", w.name)))
                    .unwrap_or_default()
            );
        }
    };
    let joins = |n: u32| {
        let o = alice.vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some("channel passphrase"),
        );
        assert!(o.ok, "PRODUCT: alice's join {n} was refused: {o:?}");
        let (back, o) = poll(bob, &["room", "roster", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&alice.b32())
        });
        assert!(
            back,
            "PRODUCT: {WITHIN:?} after alice's join {n}, bob's roster does not name her: {o:?}"
        );
    };
    leaves(2);
    #[cfg(feature = "test-knobs")]
    std::fs::write(&return_hold, b"hold").expect("APPARATUS: arm return Presence hold");
    joins(3);
    #[cfg(feature = "test-knobs")]
    {
        let deadline = Instant::now() + WITHIN;
        while !return_hold.with_extension("engaged").is_file() {
            assert!(
                Instant::now() < deadline,
                "APPARATUS: Alice did not reach recovery before return Presence"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // Bob already lists the verified readmission; Alice still holds her previous signed
        // departure. A new Leave must not claim it has sent a later departure yet.
        let pending = alice.vox(None, &["room", "leave", id]);
        std::fs::remove_file(&return_hold).expect("APPARATUS: release return Presence hold");
        assert!(
            !pending.ok && pending.stderr.contains("record of its own history"),
            "PRODUCT: alice's leave 3 did not report pending recovery before signing a new departure: {pending:?}"
        );
    }
    leaves(3);
    eprintln!("[proof] rejoin: alice's second and third leaves each dropped her from both rosters");
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_room_left_leaves_nothing_on_the_node() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let id = room.id.clone();
    let cid = room.cid;
    let alice_fp = room.workers[0].b32();
    room.workers[0].stop_daemon_cleanly();
    let sealed_wrap = {
        let db = redb::Database::builder()
            .open_read_only(room.workers[0].paths.store_file())
            .expect("APPARATUS: open pre-leave store");
        let read = db.begin_read().expect("APPARATUS: read pre-leave store");
        let wraps = read
            .open_table(redb::TableDefinition::<[u8; 32], &[u8]>::new("sek_wraps"))
            .expect("APPARATUS: open pre-leave SEK wraps");
        wraps
            .get(cid)
            .expect("APPARATUS: read pre-leave SEK wrap")
            .expect("APPARATUS: no pre-leave SEK wrap")
            .value()
            .to_vec()
    };
    let before = std::fs::read(room.workers[0].paths.store_file())
        .expect("APPARATUS: read pre-leave store bytes");
    assert!(
        !sealed_wrap.is_empty() && before.windows(sealed_wrap.len()).any(|b| b == sealed_wrap),
        "APPARATUS: sealed SEK wrap is not physically present before Leave"
    );
    room.workers[0].restart_daemon(&tmp.path().join("alice-before-leave.err"));
    let (ready, seen) = poll(&room.workers[0], &["room", "read", &id], WITHIN, |o| o.ok);
    assert!(
        ready,
        "APPARATUS: creator room did not finish preparing after restart: {seen:?}"
    );

    let t = Instant::now();
    let o = room.workers[0].vox(None, &["room", "leave", &id]);
    assert!(o.ok, "PRODUCT: `vox room leave` was refused: {o:?}");
    eprintln!(
        "[proof] leave: done in {:.1}s; it said: {}",
        t.elapsed().as_secs_f64(),
        o.stdout.trim()
    );
    assert!(
        said_before_and_after(&o, "leave", "vox: left "),
        "PRODUCT: `vox room leave` must say what it is to do, naming the room, before it acts, and \
         what it did after: {:?}",
        o.stdout
    );
    // ADR-023 RL-8.1 / RL-8.4 permits the checkpoint, not content, keys or passphrase.
    erased(&mut room.workers[0], &id, &cid, true);
    room.workers[0].stop_daemon_cleanly();
    let after = std::fs::read(room.workers[0].paths.store_file())
        .expect("APPARATUS: read post-leave store bytes");
    assert!(
        !after.windows(sealed_wrap.len()).any(|b| b == sealed_wrap),
        "PRODUCT: Alice's deleted sealed SEK wrap remains physically present after Leave"
    );
    room.workers[0].restart_daemon(&tmp.path().join("alice-after-physical-erasure.err"));
    let bob = &room.workers[1];
    let (gone, o2) = poll(bob, &["room", "roster", &id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&alice_fp)
    });
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after alice left, bob's roster still names her: {o2:?}"
    );

    eprintln!("[proof] leave: no live room rows or SEK wrap, including its deleted sealed bytes, or readable room after restart");
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn an_admin_the_creator_named_ends_a_room_and_then_it_takes_no_new_message() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    let link = setup(alice, &["room", "link", id]).stdout.trim().to_owned();
    let cid = room.cid;

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

    // Each member's agent session reads the room once, as Claude Code's hook does: that files a
    // read cursor under the room, which must not outlive it.
    for w in [alice, bob, carol] {
        let session = format!(r#"{{"session_id":"end-{}","cwd":"/tmp"}}"#, w.name);
        let o = w.vox_in(
            None,
            &["agent", "hook", "--node", "default", "--room", &id[..8]],
            Some(&session),
        );
        assert!(
            o.ok && !cursors_of(w, id).is_empty(),
            "PRODUCT (staging): {}'s `vox agent hook` left no read cursor for the room: {o:?}",
            w.name
        );
    }

    let t = Instant::now();
    let o = bob.vox(None, &["room", "end", id]);
    assert!(
        o.ok,
        "PRODUCT: bob, an admin the creator named, was refused `vox room end`: {o:?}"
    );
    eprintln!("[proof] end: it said: {}", o.stdout.trim());
    assert!(
        said_before_and_after(&o, "end", "vox: ended "),
        "PRODUCT: `vox room end` must say what it is to do, naming the room, before it acts, and \
         what it did after: {:?}",
        o.stdout
    );
    for w in &mut room.workers {
        let (gone, o) = poll(w, &["room", "list"], GONE, |o| {
            o.ok && !o.stdout.lines().any(|l| l.starts_with(&id[..12]))
        });
        assert!(
            gone,
            "PRODUCT: {GONE:?} after bob, an admin, ended the room, {}'s `vox room list` still \
             names it — an ended room must not need a forget: {o:?}",
            w.name
        );
        // ADR-023 RL-8.1 / RL-8.2 / RL-8.4: End erases even the continuity checkpoint.
        erased(w, id, &cid, false);
        let left = cursors_of(w, id);
        assert!(
            left.is_empty(),
            "PRODUCT: the room is off {}'s list, but the agent cursor files kept for it are still \
             on disk: {left:?}",
            w.name
        );
        let o = w.vox(None, &["room", "post", id, "said after the end"]);
        assert!(
            !o.ok,
            "PRODUCT: {}'s post was taken after the room ended: {o:?}",
            w.name
        );
    }
    let carol = &room.workers[2];
    eprintln!(
        "[proof] end: every member deleted the room within {:.1}s of the end",
        t.elapsed().as_secs_f64()
    );

    // Joining an ended room is refused as that, not as a wrong passphrase: carol joins again with
    // its address and passphrase.
    let o = carol.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some("channel passphrase"),
    );
    assert!(
        !o.ok
            && o.stderr.contains("has ended")
            && !o.stderr.contains("passphrase is wrong")
            && !o.stderr.contains("still being applied"),
        "PRODUCT: a join to the ended room was not refused as the room having ended: {o:?}"
    );
    eprintln!("[proof] end: a join to the ended room was told it ended");
}

fn end_while_away(delegated: bool) {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let link = setup(&room.workers[0], &["room", "link", &id])
        .stdout
        .trim()
        .to_owned();
    if delegated {
        let bob = room.workers[1].b32();
        setup(&room.workers[0], &["room", "admin", "add", &id, &bob]);
        let (ready, seen) = poll(
            &room.workers[1],
            &["room", "admin", "list", &id],
            WITHIN,
            |o| o.ok && o.stdout.contains(&bob),
        );
        assert!(
            ready,
            "PRODUCT (staging): bob did not receive admin authority: {seen:?}"
        );
    }
    let mut input = b"vox/own-continuity-scope/v1".to_vec();
    input.extend_from_slice(&room.cid);
    input.extend_from_slice(&room.workers[2].fp);
    let marker = vox_core::hash::sha256(&input);
    setup(&room.workers[2], &["room", "leave", &id]);
    room.workers[2].stop_daemon();
    let checkpoint = |worker: &Worker| {
        let store = vox_core::node::store::Store::open(&worker.paths.store_file()).unwrap();
        store
            .get_segment(
                &marker,
                vox_core::atrest::store::SegmentKind::KeyMaterial,
                0,
            )
            .unwrap()
            .is_some()
    };
    assert!(
        checkpoint(&room.workers[2]),
        "PRODUCT: leave lost the continuity checkpoint"
    );
    #[cfg(feature = "test-knobs")]
    let withdrawal_fault = tmp.path().join("fail-creator-withdrawal");
    #[cfg(feature = "test-knobs")]
    if delegated {
        std::fs::write(&withdrawal_fault, b"armed").expect("APPARATUS: arm withdrawal failure");
        let mutant = std::env::var("VOX_MUTANT_FX28").unwrap_or_default();
        room.workers[0].restart_daemon_as(
            support::VOX,
            &[
                (
                    "VOX_TEST_FAIL_END_WITHDRAWAL_FILE",
                    withdrawal_fault.to_str().expect("APPARATUS: fault path"),
                ),
                ("VOX_TEST_FX28_MUTANT", &mutant),
            ],
            &tmp.path().join("alice-withdrawal-fault.err"),
        );
    }
    #[cfg(feature = "test-knobs")]
    let forged_evidence = tmp.path().join("forged-end-first");
    #[cfg(feature = "test-knobs")]
    if !delegated {
        std::fs::write(&forged_evidence, b"armed").expect("APPARATUS: arm forged withdrawal");
    }
    let restart_former = |worker: &mut Worker, log: &std::path::Path| {
        #[cfg(feature = "test-knobs")]
        worker.restart_daemon_as(
            support::VOX,
            &[(
                "VOX_TEST_FORGED_END_FIRST_FILE",
                forged_evidence.to_str().expect("APPARATUS: evidence path"),
            )],
            log,
        );
        #[cfg(not(feature = "test-knobs"))]
        worker.restart_daemon(log);
    };
    restart_former(
        &mut room.workers[2],
        &tmp.path().join("carol-after-leave.err"),
    );
    let ender = if delegated { 1 } else { 0 };
    setup(&room.workers[ender], &["room", "end", &id]);
    let deadline = Instant::now() + GONE;
    loop {
        let result = room.workers[2].vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(support::ROOM_PASS),
        );
        assert!(
            !result.ok,
            "PRODUCT: ended room admitted a join: {result:?}"
        );
        room.workers[2].stop_daemon();
        let kept = checkpoint(&room.workers[2]);
        if result.stderr.contains("has ended") && !kept {
            break;
        }
        restart_former(&mut room.workers[2], &tmp.path().join("carol-wait-end.err"));
        assert!(
            Instant::now() < deadline,
            "PRODUCT: End did not authenticate and clear checkpoint: {result:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    #[cfg(feature = "test-knobs")]
    if delegated {
        assert!(
            tmp.path().join("fail-creator-withdrawal.engaged").is_file(),
            "APPARATUS: the creator's first withdrawal save did not encounter the armed fault"
        );
    }
    #[cfg(feature = "test-knobs")]
    if !delegated {
        assert!(
            tmp.path().join("forged-end-first.engaged").is_file(),
            "APPARATUS: forged withdrawal did not precede creator evidence"
        );
    }
    room.workers[2].restart_daemon(&tmp.path().join("carol-end-away-restart.err"));
    room.workers[2].stop_daemon();
    assert!(
        !checkpoint(&room.workers[2]),
        "PRODUCT: cleared checkpoint returned after restart"
    );
}

#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn creator_end_while_away_clears_the_verified_checkpoint() {
    end_while_away(false);
}

#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn delegated_end_while_away_gets_creator_endorsement() {
    end_while_away(true);
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemons and hostile stale board; run on demand in release"]
fn revoked_admin_stale_board_does_not_block_live_rejoin() {
    use vox_core::nat::withdraw::{BoardWithdraw, WithdrawScope};

    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let link = setup(&room.workers[0], &["room", "link", &id])
        .stdout
        .trim()
        .to_owned();
    let bob = room.workers[1].b32();
    setup(&room.workers[0], &["room", "admin", "add", &id, &bob]);
    let (added, seen) = poll(
        &room.workers[1],
        &["room", "admin", "list", &id],
        WITHIN,
        |o| o.ok && o.stdout.contains(&bob),
    );
    assert!(
        added,
        "PRODUCT (staging): Bob did not receive admin authority: {seen:?}"
    );
    setup(&room.workers[0], &["room", "admin", "remove", &id, &bob]);
    let (revoked, seen) = poll(
        &room.workers[1],
        &["room", "admin", "list", &id],
        WITHIN,
        |o| o.ok && !o.stdout.contains(&bob),
    );
    assert!(
        revoked,
        "PRODUCT (staging): Bob's revocation did not arrive: {seen:?}"
    );
    setup(&room.workers[2], &["room", "leave", &id]);
    room.workers[1].stop_daemon();
    let signer = {
        let mut profile = vox_core::node::profile::Profile::open(room.workers[1].paths.clone())
            .expect("APPARATUS: open stopped revoked admin profile");
        profile
            .unlock(support::ID_PASS.as_bytes())
            .expect("APPARATUS: unlock revoked admin");
        profile
            .signer_arc()
            .expect("APPARATUS: revoked admin signer")
    };
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("APPARATUS: clock")
            .as_millis(),
    )
    .expect("APPARATUS: clock range");
    let withdrawal = BoardWithdraw::build(signer.as_ref(), &room.cid, 0, WithdrawScope::Room, now)
        .expect("APPARATUS: sign stale admin withdrawal");
    room.workers[0].stop_daemon();
    let stale = tmp.path().join("stale-board");
    std::fs::write(&stale, withdrawal.to_wire()).expect("APPARATUS: stage stale board");
    room.workers[2].restart_daemon_as(
        support::VOX,
        &[(
            "VOX_TEST_STALE_BOARD_FILE",
            stale.to_str().expect("APPARATUS: stale board path"),
        )],
        &tmp.path().join("carol-stale-board.err"),
    );
    let first = room.workers[2].vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        !first.ok,
        "APPARATUS: rejoin succeeded while both live members were offline: {first:?}"
    );
    assert!(
        tmp.path().join("stale-board.engaged").is_file(),
        "APPARATUS: revoked admin's stale board response was not offered"
    );
    room.workers[2].stop_daemon();
    let mut scope = b"vox/own-continuity-scope/v1".to_vec();
    scope.extend_from_slice(&room.cid);
    scope.extend_from_slice(&room.workers[2].fp);
    let marker = vox_core::hash::sha256(&scope);
    let store = vox_core::node::store::Store::open(&room.workers[2].paths.store_file())
        .expect("APPARATUS: open former member store");
    assert!(
        store
            .get_segment(
                &marker,
                vox_core::atrest::store::SegmentKind::KeyMaterial,
                0
            )
            .expect("APPARATUS: read checkpoint")
            .is_some(),
        "PRODUCT: revoked admin's stale withdrawal erased the former member's checkpoint"
    );
    drop(store);
    room.workers[0].restart_daemon(&tmp.path().join("alice-live-board.err"));
    room.workers[1].restart_daemon(&tmp.path().join("bob-revoked.err"));
    let (ready, seen) = poll(&room.workers[0], &["room", "read", &id], WITHIN, |o| o.ok);
    assert!(
        ready,
        "APPARATUS: live creator did not reopen its room: {seen:?}"
    );
    std::fs::write(&stale, withdrawal.to_wire()).expect("APPARATUS: restage stale board");
    let _ = std::fs::remove_file(tmp.path().join("stale-board.engaged"));
    room.workers[2].restart_daemon_as(
        support::VOX,
        &[(
            "VOX_TEST_STALE_BOARD_FILE",
            stale.to_str().expect("APPARATUS: stale board path"),
        )],
        &tmp.path().join("carol-live-board.err"),
    );
    let joined = room.workers[2].vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        tmp.path().join("stale-board.engaged").is_file(),
        "APPARATUS: revoked admin's stale board response was not offered"
    );
    assert!(
        joined.ok,
        "PRODUCT: revoked admin's stale board blocked a live rejoin: {joined:?}"
    );
    let text = "live creator after stale revoked board";
    setup(&room.workers[0], &["room", "post", &id, text]);
    support::until(
        &room.workers[2],
        None,
        "returner reads live creator after stale board",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains(text),
    );
    let (posted, result) = poll(
        &room.workers[2],
        &["room", "post", &id, "return after stale board"],
        WITHIN,
        |o| o.ok || !o.stderr.contains("own history"),
    );
    assert!(
        posted && result.ok,
        "PRODUCT: returner could not post after stale board: {result:?}"
    );
    support::until(
        &room.workers[0],
        None,
        "creator reads returner after stale board",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains("return after stale board"),
    );
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn creator_withdrawals_for_another_room_or_future_do_not_erase() {
    use vox_core::nat::withdraw::{BoardWithdraw, WithdrawScope};

    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let link = setup(&room.workers[0], &["room", "link", &id])
        .stdout
        .trim()
        .to_owned();
    let mut input = b"vox/own-continuity-scope/v1".to_vec();
    input.extend_from_slice(&room.cid);
    input.extend_from_slice(&room.workers[2].fp);
    let marker = vox_core::hash::sha256(&input);
    setup(&room.workers[2], &["room", "leave", &id]);
    room.workers[2].stop_daemon();
    room.workers[0].stop_daemon();
    // The attacker uses the creator's real key to make authentic but inapplicable evidence.
    let signer = {
        let mut profile = vox_core::node::profile::Profile::open(room.workers[0].paths.clone())
            .expect("APPARATUS: open stopped creator profile");
        profile
            .unlock(support::ID_PASS.as_bytes())
            .expect("APPARATUS: unlock creator signer");
        profile.signer_arc().expect("APPARATUS: creator signer")
    };
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("APPARATUS: clock")
            .as_millis(),
    )
    .expect("APPARATUS: clock range");
    let mut other = room.cid;
    other[0] ^= 1;
    let wrong_room = BoardWithdraw::build(signer.as_ref(), &other, 0, WithdrawScope::Room, now)
        .expect("APPARATUS: sign wrong-room withdrawal");
    let future = BoardWithdraw::build(
        signer.as_ref(),
        &room.cid,
        0,
        WithdrawScope::Room,
        now + vox_core::nat::store::MAX_CLOCK_SKEW_MS + 3_600_000,
    )
    .expect("APPARATUS: sign future withdrawal");
    room.workers[0].restart_daemon(&tmp.path().join("alice-before-end.err"));
    let evidence = tmp.path().join("inapplicable-end");
    let receipt = tmp.path().join("inapplicable-end.engaged");
    std::fs::write(&evidence, wrong_room.to_wire()).expect("APPARATUS: stage wrong-room evidence");
    room.workers[2].restart_daemon_as(
        support::VOX,
        &[(
            "VOX_TEST_END_EVIDENCE_FILE",
            evidence.to_str().expect("APPARATUS: evidence path"),
        )],
        &tmp.path().join("carol-inapplicable-end.err"),
    );
    setup(&room.workers[0], &["room", "end", &id]);
    for (label, wire) in [
        ("wrong room", wrong_room.to_wire()),
        ("future", future.to_wire()),
    ] {
        std::fs::write(&evidence, wire).expect("APPARATUS: stage signed evidence");
        let _ = std::fs::remove_file(&receipt);
        let result = room.workers[2].vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(support::ROOM_PASS),
        );
        assert!(
            !result.ok && result.stderr.contains("has ended"),
            "PRODUCT: End was not reported for {label} evidence: {result:?}"
        );
        assert!(
            receipt.is_file(),
            "APPARATUS: {label} evidence did not reach verification"
        );
        room.workers[2].stop_daemon();
        let store = vox_core::node::store::Store::open(&room.workers[2].paths.store_file())
            .expect("APPARATUS: open former member store");
        assert!(
            store
                .get_segment(
                    &marker,
                    vox_core::atrest::store::SegmentKind::KeyMaterial,
                    0
                )
                .expect("APPARATUS: read checkpoint")
                .is_some(),
            "PRODUCT: {label} creator withdrawal erased the checkpoint"
        );
        drop(store);
        room.workers[2].restart_daemon_as(
            support::VOX,
            &[(
                "VOX_TEST_END_EVIDENCE_FILE",
                evidence.to_str().expect("APPARATUS: evidence path"),
            )],
            &tmp.path().join("carol-inapplicable-restart.err"),
        );
    }
}

#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn delegated_end_without_creator_keeps_former_member_checkpoint() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let bob = room.workers[1].b32();
    setup(&room.workers[0], &["room", "admin", "add", &id, &bob]);
    let (ready, seen) = poll(
        &room.workers[1],
        &["room", "admin", "list", &id],
        WITHIN,
        |o| o.ok && o.stdout.contains(&bob),
    );
    assert!(
        ready,
        "PRODUCT (staging): bob did not receive admin authority: {seen:?}"
    );
    let link = setup(&room.workers[1], &["room", "link", &id])
        .stdout
        .trim()
        .to_owned();
    let mut input = b"vox/own-continuity-scope/v1".to_vec();
    input.extend_from_slice(&room.cid);
    input.extend_from_slice(&room.workers[2].fp);
    let marker = vox_core::hash::sha256(&input);
    setup(&room.workers[2], &["room", "leave", &id]);
    room.stop(0);
    setup(&room.workers[1], &["room", "end", &id]);
    #[cfg(feature = "test-knobs")]
    if std::env::var("VOX_MUTANT_FX28").as_deref() == Ok("end-erases-without-evidence") {
        // This mutant is armed only after the first, unendorsed-End observation.
        room.workers[2].restart_daemon_as(
            support::VOX,
            &[("VOX_TEST_FX28_MUTANT", "")],
            &tmp.path().join("carol-before-forgotten-board.err"),
        );
    }
    let result = room.workers[2].vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        !result.ok && result.stderr.contains("has ended"),
        "PRODUCT: delegated End was not reported: {result:?}"
    );
    room.workers[2].stop_daemon();
    let store = vox_core::node::store::Store::open(&room.workers[2].paths.store_file()).unwrap();
    assert!(
        store
            .get_segment(
                &marker,
                vox_core::atrest::store::SegmentKind::KeyMaterial,
                0
            )
            .unwrap()
            .is_some(),
        "PRODUCT: unendorsed End erased the checkpoint"
    );
    drop(store);
    // Once every publisher is offline, restarting the RAM-only board forgets its End.
    room.stop(1);
    room.restart_anchor();
    room.workers[2].restart_daemon(&tmp.path().join("carol-forgotten-board.err"));
    let forgotten = room.workers[2].vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        !forgotten.ok
            && forgotten.stderr.contains("has nothing for room")
            && forgotten.stderr.contains("host has not published"),
        "PRODUCT: forgotten board did not truthfully report its missing room: {forgotten:?}"
    );
    room.workers[2].stop_daemon();
    let store = vox_core::node::store::Store::open(&room.workers[2].paths.store_file())
        .expect("APPARATUS: open former member store");
    assert!(
        store
            .get_segment(
                &marker,
                vox_core::atrest::store::SegmentKind::KeyMaterial,
                0
            )
            .expect("APPARATUS: read continuity checkpoint")
            .is_some(),
        "PRODUCT: forgotten board erased the former member's checkpoint"
    );
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_chosen_idle_end_ends_a_quiet_room_and_only_that_room() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
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
    let link = setup(alice, &["room", "link", &short])
        .stdout
        .trim()
        .to_owned();
    let o = bob.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
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

    // Nothing said for IDLE: it ends, and is deleted, on both members.
    std::thread::sleep(IDLE + Duration::from_secs(5));
    for w in [alice, bob] {
        let (gone, o) = poll(w, &["room", "list"], GONE, |o| {
            o.ok && !o.stdout.lines().any(|l| l.starts_with(&short))
        });
        assert!(
            gone,
            "PRODUCT: {}'s `vox room list` still names the room {GONE:?} after its {IDLE:?} \
             idle end ran out with nothing said in it: {o:?}",
            w.name
        );
        let o = w.vox(None, &["room", "post", &short, "after the idle end"]);
        assert!(
            !o.ok,
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
        "PRODUCT: the room made with no idle end is gone or listed as ended: {:?}",
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
    drive_verb(w, verb, hold, false);
}

/// Run `:verb` in `w`'s `vox tui` (its daemon stopped), a verb the TUI must refuse: the status line
/// the refusal is stated in, as the person reads it.
fn tui_refusal(w: &Worker, verb: &str) -> String {
    let stdout = drive_verb(w, verb, Duration::ZERO, true);
    stdout
        .lines()
        .find_map(|l| l.split_once("REFUSED: ").map(|(_, said)| said.to_owned()))
        .unwrap_or_default()
}

/// [`tui_verb`] and [`tui_refusal`]: the driver's stdout once it passed.
fn drive_verb(w: &Worker, verb: &str, hold: Duration, refusal: bool) -> String {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_room_verb.py");
    let tag = format!("[{} :{verb}]", w.name);
    let hold = hold.as_secs().to_string();
    let mut argv = vec![
        support::VOX,
        w.data.to_str().unwrap(),
        w.cfg.to_str().unwrap(),
        "identity passphrase",
        "channel passphrase",
        &tag,
        verb,
        &hold,
    ];
    if refusal {
        argv.push("refusal");
    }
    let driven = pty_driver::run(script, &argv);
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
    driven.stdout
}

#[test]
#[ignore = "real daemons, an anchor and `vox tui` in a pty, production Argon2id; needs pyte"]
fn the_tui_leaves_and_ends() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let cid = room.cid;

    // **A refusal is one sentence from vox-core, the same in the CLI and the TUI** (ADR-028 E-7,
    // #629): bob, who neither created the room nor was made an admin, asks to end it, first with
    // `vox room end`, then with `:end` in his TUI. Both say what failed and what to do, in the
    // words vox-core writes for the fault; the TUI words nothing of its own.
    let cli = room.workers[1].vox(None, &["room", "end", &id]);
    let cause = "only the room's creator, or an admin it delegated, may do that";
    let next = "ask the room's creator to do it, or to make you an admin";
    assert!(
        !cli.ok && cli.stderr.contains(cause) && cli.stderr.contains(next),
        "PRODUCT: bob's `vox room end` must be refused in vox-core's sentence, saying what failed \
         ({cause:?}) and what to do ({next:?}): {cli:?}"
    );
    let bob_err = tmp.path().join("bob.after-tui.err");
    room.workers[1].stop_daemon();
    let tui = tui_refusal(&room.workers[1], "end");
    room.workers[1].restart_daemon(&bob_err);
    assert!(
        tui.contains(cause) && tui.contains(next),
        "PRODUCT: bob's `:end` in the TUI must be refused in the sentence the CLI gave, from \
         vox-core ({cause:?}, then {next:?}); the TUI said: {tui:?}"
    );
    eprintln!("[proof] tui: a non-creator's :end is refused as the CLI refuses it: {tui}");

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
    // ADR-023 RL-8.1 / RL-8.4 permits public continuity, never room content or keys.
    room.workers[2].restart_daemon(&tmp.path().join("carol-after-tui-leave.err"));
    erased(&mut room.workers[2], &id, &cid, true);

    room.workers[0].stop_daemon();
    tui_verb(&room.workers[0], "end", Duration::from_secs(15));
    let bob = &room.workers[1];
    let (gone, o) = poll(bob, &["room", "list"], GONE, |o| {
        o.ok && !o.stdout.lines().any(|l| l.starts_with(&id[..12]))
    });
    assert!(
        gone,
        "PRODUCT: {GONE:?} after alice's :end in the TUI, bob's `vox room list` still names the \
         room: {o:?}"
    );
    eprintln!("[proof] tui: :leave and :end each did what the CLI verb does");
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
    let tmp = support::diagnostic_tempdir();
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
    // Restart readiness is node-wide; this retained room can still be preparing.
    let (prepared, o) = poll(
        bob,
        &["room", "admin", "add", id, &carol.b32()],
        WITHIN,
        |o| o.ok || !o.stderr.contains("preparing its saved history"),
    );
    assert!(
        prepared && o.ok,
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
