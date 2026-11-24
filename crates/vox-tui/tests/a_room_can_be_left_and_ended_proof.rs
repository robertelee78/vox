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
//! - **A readmitted member gets no body from outside its cut** (ADR-053 MP-10, #1171). Carol is
//!   removed and readmitted; bodies she never saw, some on chains she can still decrypt (one
//!   written after her removal by a member that had not heard of it), are outside her cut.
//!   Through the creator, an ordinary member and a restarted holder in turn, she shows none of
//!   them and keeps what she had read. Each boundary is proven with the other switched off: the
//!   holders' send with carol rendering everything (`a_readmitted_member_is_sent_no_body…`),
//!   carol's render with every holder sending everything (`a_readmitted_member_shows_no_body…`).
//! - **A post right after a removal.** Alice removes carol and posts while the key rotation the
//!   removal owes is held unsaved (a `test-knobs` hold). Her post waits for the rotation, exits
//!   0, and bob reads it; carol does not.
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
//! that outlives the departure it undid (rejoin: alice's second leave never leaves bob's roster);
//! boundary 1 off in one holder (`VOX_MUTANT_MP10_SEND=alice|bob|dave`: that holder sends a
//! once-removed recipient every body) and boundary 2 off in carol (`VOX_MUTANT_MP10_RENDER=1`:
//! she renders every body she is sent): the readmission-cut arm named for that boundary goes red
//! through that holder;
//! a post in a removal's rotation window refused as an internal error (post after removal,
//! `VOX_MUTANT_POST_AFTER_REMOVAL=unmapped`).

#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_node_that_left_rejoins_and_posts_at_once,
    an_unheard_departure_keeps_the_left_copy_until_a_member_returns,
    a_waiting_rejoin_does_not_hold_independently_deferred_other_room_commands,
    a_waiting_rejoin_is_answered_when_its_left_copy_is_deleted
);

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "support/room.rs"]
mod support;
#[path = "support/test_knobs.rs"]
mod test_knobs;
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
        let logs = names
            .iter()
            .map(|name| {
                let path = tmp.join(format!("{name}.daemon.err"));
                format!(
                    "{name}'s daemon:\n{}",
                    std::fs::read_to_string(path).unwrap_or_else(|error| format!(
                        "APPARATUS: daemon log unavailable: {error}"
                    ))
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        panic!("PRODUCT (staging): the room could not be set up: {why}\n{logs}")
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
}

/// Follow only the product's explicit no-change wait instruction, with a bounded, logged retry.
fn unchanged_busy_retry(w: &Worker, args: &[&str]) -> Out {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let o = w.vox(None, args);
        let said = format!("{}\n{}", o.stdout, o.stderr);
        let unchanged = said.contains(
            "a previous change to this room is still being applied; this request made no change",
        ) || said
            .contains(vox_core::node::api::Fault::GovernanceRefreshing.explain());
        if o.ok || !unchanged || Instant::now() >= deadline {
            return o;
        }
        eprintln!(
            "[staging] {}: `vox {}` made no change; retrying",
            w.name,
            args.join(" ")
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Run a successful staging step; other failures are reported as product failures.
fn setup(w: &Worker, args: &[&str]) -> Out {
    let o = unchanged_busy_retry(w, args);
    if o.ok {
        return o;
    }
    panic!(
        "PRODUCT (staging): `vox {}` on {} failed: {o:?}; daemon:\n{}\ngated daemon:\n{}",
        args.join(" "),
        w.name,
        std::fs::read_to_string(w.pass.with_file_name(format!("{}.daemon.err", w.name)))
            .unwrap_or_default(),
        std::fs::read_to_string(w.pass.with_file_name(format!("{}-gated.err", w.name)))
            .unwrap_or_default()
    );
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
        let mut binding = b"vox/own-continuity-scope/v1".to_vec();
        binding.extend_from_slice(cid);
        binding.extend_from_slice(&w.fp);
        let scope = vox_core::hash::sha256(&binding);
        let mut markers = Vec::new();
        for name in ["segments", "small_segments"] {
            let segments = match read.open_table(
                redb::TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(name),
            ) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => continue,
                Err(e) => panic!("APPARATUS: open {name}: {e}"),
            };
            let rows: Vec<_> = segments
                .range((*cid, 0, 0)..=(*cid, u8::MAX, u64::MAX))
                .unwrap_or_else(|e| panic!("APPARATUS: range room rows in {name}: {e}"))
                .map(|row| row.expect("APPARATUS: read room row").0.value())
                .collect();
            // ADR-023 RL-8.1 / RL-8.4: retain only the separate non-secret checkpoint,
            // never message bodies, room keys, passphrases or a second room log.
            assert!(
                rows.is_empty(),
                "PRODUCT: {} kept deleted room rows in {name}: {rows:?}",
                w.name
            );
            markers.extend(
                segments
                    .range((scope, 0, 0)..=(scope, u8::MAX, u64::MAX))
                    .unwrap_or_else(|e| panic!("APPARATUS: range continuity rows in {name}: {e}"))
                    .map(|row| row.expect("APPARATUS: read continuity row").0.value()),
            );
        }
        let wraps = read
            .open_table(redb::TableDefinition::<[u8; 32], &[u8]>::new("sek_wraps"))
            .expect("APPARATUS: open SEK wraps");
        assert!(
            wraps.get(*cid).expect("APPARATUS: read SEK wrap").is_none(),
            "PRODUCT: {} kept the deleted room's SEK wrap",
            w.name
        );
        // Count checkpoints across both tables, including duplicate copies.
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
    // A private directory stays private: the daemon refuses a computer management path another
    // account could read.
    std::fs::set_permissions(
        dest,
        std::fs::metadata(source)
            .expect("APPARATUS: read profile backup directory mode")
            .permissions(),
    )
    .expect("APPARATUS: keep profile backup directory mode");
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

// temp_home strips inherited product knobs. The runner selects a proof setting;
// only this exact journey deliberately passes its scoped mutation to child binaries.
fn fx62_mutant() {
    if let Ok(mutant) = std::env::var("VOX_MUTANT_FX62") {
        std::env::set_var("VOX_TEST_FX62_MUTANT", mutant);
    }
}

#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn an_admin_removes_one_member_and_the_creator_readmits_it_forward_only() {
    watchdog::arm();
    fx62_mutant();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    // An attacker can restore its identity from before joining. Keep that scratch
    // profile so the later retained-passphrase attempt is a fresh join, not a reconnect.
    let carol_prejoin_data = tmp.path().join("carol-prejoin-data");
    let carol_prejoin_cfg = tmp.path().join("carol-prejoin-cfg");
    {
        let carol = support::worker(tmp.path(), "carol");
        copy_profile_tree(&carol.data, &carol_prejoin_data);
        copy_profile_tree(&carol.cfg, &carol_prejoin_cfg);
    }
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave", "erin"]);
    let id = room.id.clone();
    let (online, offline) = room.workers.split_at_mut(3);
    let [alice, bob, carol] = online else {
        unreachable!()
    };
    let (alice, bob): (&Worker, &Worker) = (alice, bob);
    let [dave, erin] = offline else {
        unreachable!()
    };
    let id = id.as_str();
    let link = setup(alice, &["room", "link", id]).stdout.trim().to_owned();
    setup(alice, &["room", "post", id, "FX62-BEFORE"]);
    let (seen, before) = poll(carol, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("FX62-BEFORE")
    });
    assert!(
        seen,
        "APPARATUS: pre-removal message was not staged: {before:?}"
    );
    setup(carol, &["room", "post", id, "FX62-CAROL-HISTORY"]);
    let (seen, history) = poll(alice, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("FX62-CAROL-HISTORY")
    });
    assert!(
        seen,
        "APPARATUS: target's signed history was not staged: {history:?}"
    );
    let side = alice.vox_in(
        None,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "side-fx62",
        ],
        Some(support::ROOM_PASS),
    );
    assert!(
        side.ok,
        "APPARATUS: unrelated room could not be created: {side:?}"
    );
    let side_link = setup(alice, &["room", "link", "side-fx62"])
        .stdout
        .trim()
        .to_owned();
    let side_join = carol.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &side_link],
        Some(support::ROOM_PASS),
    );
    assert!(
        side_join.ok,
        "APPARATUS: unrelated room could not be joined: {side_join:?}"
    );
    let deadline = Instant::now() + WITHIN;
    loop {
        let sent = alice.vox(None, &["room", "post", "side-fx62", "FX62-OTHER-CONTROL"]);
        let read = carol.vox(None, &["room", "read", "side-fx62"]);
        if sent.ok && read.ok && read.stdout.contains("FX62-OTHER-CONTROL") {
            break;
        }
        assert!(Instant::now() < deadline, "APPARATUS: unrelated room never reached the readable control: sent={sent:?}, read={read:?}");
        std::thread::sleep(Duration::from_secs(1));
    }
    let refused = unchanged_busy_retry(carol, &["room", "remove-member", id, &bob.b32()]);
    assert!(
        !refused.ok,
        "PRODUCT [FX62 nonadmin]: non-admin removal was accepted: {refused:?}"
    );
    assert!(
        format!("{} {}", refused.stdout, refused.stderr).contains("only the room's admin"),
        "PRODUCT [FX62 refusal-reason]: non-admin refusal did not name its authority limit: {refused:?}"
    );
    let creator = unchanged_busy_retry(bob, &["room", "remove-member", id, &alice.b32()]);
    assert!(
        !creator.ok
            && format!("{} {}", creator.stdout, creator.stderr)
                .contains("creator cannot be removed"),
        "PRODUCT [FX62 creator]: creator-target removal was not truthfully refused: {creator:?}"
    );
    setup(alice, &["room", "admin", "add", id, &bob.b32()]);
    let (admin, listed) = poll(bob, &["room", "admin", "list", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&bob.b32())
    });
    assert!(
        admin,
        "APPARATUS: delegated admin did not arrive: {listed:?}"
    );
    dave.stop_daemon();
    erin.stop_daemon();
    let removed = unchanged_busy_retry(bob, &["room", "remove-member", id, &carol.b32()]);
    assert!(
        removed.ok,
        "PRODUCT: delegated admin could not remove carol: {removed:?}"
    );
    for member in [alice, bob] {
        let (gone, roster) = poll(member, &["room", "roster", id], WITHIN, |o| {
            o.ok && !o.stdout.contains(&carol.b32())
        });
        assert!(
            gone,
            "PRODUCT: {} still lists removed carol: {roster:?}",
            member.name
        );
    }
    dave.restart_daemon(&tmp.path().join("dave-restart.err"));
    let (caught, roster) = poll(dave, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&carol.b32())
    });
    assert!(
        caught,
        "PRODUCT: offline dave failed to apply removal on catch-up: {roster:?}"
    );
    eprintln!("[proof] FX62 offline-removal: dave's caught-up roster excludes carol");
    setup(alice, &["room", "post", id, "FX62-NEVER-REMOVED-HISTORY"]);
    // Rotation is forward-only: as in support::room, exchange fresh posts until
    // each remaining reader has received the sender's new-chain release.
    for (author, reader, needle) in [
        (bob, alice, "FX62-REMOVAL-BOB"),
        (alice, bob, "FX62-REMOVAL-ALICE"),
    ] {
        let deadline = Instant::now() + WITHIN;
        loop {
            setup(author, &["room", "post", id, needle]);
            let read = reader.vox(None, &["room", "read", id]);
            if read.ok && read.stdout.contains(needle) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT [FX62 remaining-posts]: remaining member did not read {needle}: {read:?}; sender status={:?}; reader status={:?}; sender daemon:\n{}\nreader daemon:\n{}",
                author.vox(None, &["status", "--json"]),
                reader.vox(None, &["status", "--json"]),
                std::fs::read_to_string(tmp.path().join(format!("{}.daemon.err", author.name))).unwrap_or_default(),
                std::fs::read_to_string(tmp.path().join(format!("{}.daemon.err", reader.name))).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let history = setup(alice, &["room", "read", id]);
    assert!(
        history.stdout.contains("FX62-CAROL-HISTORY"),
        "PRODUCT [FX62 history]: removal hid the target's readable signed history: {history:?}"
    );
    for member in [alice, bob] {
        let trust = setup(member, &["trust", "list"]);
        assert!(
            trust.stdout.contains(&carol.b32()),
            "PRODUCT [FX62 trust]: room removal changed {}'s global trust: {trust:?}",
            member.name
        );
    }
    eprintln!("[proof] FX62 remaining-posts: alice read FX62-REMOVAL-BOB; bob read FX62-REMOVAL-ALICE; target history and global trust retained");
    let deadline = Instant::now() + WITHIN;
    loop {
        let sent = alice.vox(None, &["room", "post", "side-fx62", "FX62-OTHER-ROOM"]);
        assert!(
            sent.ok,
            "PRODUCT: unrelated room stopped accepting posts: {sent:?}"
        );
        let read = carol.vox(None, &["room", "read", "side-fx62"]);
        if read.ok && read.stdout.contains("FX62-OTHER-ROOM") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: unrelated room stopped delivering after removal: {read:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    eprintln!("[proof] FX62 room-scope: removed carol read FX62-OTHER-ROOM in side-fx62");
    let removed_read = carol.vox(None, &["room", "read", id]);
    assert!(
        removed_read.ok
            && removed_read.stdout.contains("FX62-BEFORE")
            && !removed_read.stdout.contains("FX62-REMOVAL-ALICE")
            && !removed_read.stdout.contains("FX62-REMOVAL-BOB"),
        "PRODUCT: removed carol lost readable history or read a removal-period post: {removed_read:?}"
    );
    let reconnect = carol.vox(None, &["room", "join", &link]);
    let post = carol.vox(None, &["room", "post", id, "FX62-REMOVED-RECONNECT"]);
    let others = bob.vox(None, &["room", "roster", id]);
    let read = bob.vox(None, &["room", "read", id]);
    assert!(!reconnect.ok,
        "PRODUCT [FX62 reconnect]: held-room reconnect accepted the removed identity: {reconnect:?}");
    assert!(
        !others.stdout.contains(&carol.b32()) && !read.stdout.contains("FX62-REMOVED-RECONNECT"),
        "PRODUCT: held-room reconnect restored the removed node's membership or content: reconnect={reconnect:?}; post={post:?}; roster={others:?}; read={read:?}"
    );
    let readmit = unchanged_busy_retry(alice, &["room", "readmit-member", id, &carol.b32()]);
    assert!(
        readmit.ok,
        "PRODUCT: creator readmission failed: {readmit:?}"
    );
    assert!(
        format!("{} {}", readmit.stdout, readmit.stderr)
            .contains("Readmission does not restore history"),
        "PRODUCT [FX62 disclosure]: readmission omitted its history limit: {readmit:?}"
    );
    let (back, roster) = poll(bob, &["room", "roster", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&carol.b32())
    });
    assert!(back, "PRODUCT: readmitted carol did not return: {roster:?}");
    let full = setup(
        alice,
        &[
            "trust",
            "add",
            &carol.b32(),
            "--name",
            "carol",
            "--history",
            "full",
            "--identity-passphrase-file",
            alice
                .pass
                .to_str()
                .expect("APPARATUS: UTF-8 passphrase path"),
        ],
    );
    assert!(
        full.ok,
        "PRODUCT: full history grant after readmission was refused: {full:?}"
    );
    setup(alice, &["room", "post", id, "FX62-FOLD-WITNESS"]);
    erin.restart_daemon(&tmp.path().join("erin-restart.err"));
    let (synced, witness) = poll(erin, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("FX62-FOLD-WITNESS")
    });
    assert!(
        synced,
        "APPARATUS: offline erin did not catch up through the readmission witness: {witness:?}"
    );
    let (caught, roster) = poll(erin, &["room", "roster", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&carol.b32())
    });
    assert!(
        caught,
        "PRODUCT: offline erin failed to fold readmission: {roster:?}"
    );
    let offline_deadline = Instant::now() + WITHIN;
    loop {
        let post = erin.vox(None, &["room", "post", id, "FX62-OFFLINE-FORWARD"]);
        let read = carol.vox(None, &["room", "read", id]);
        if post.ok && read.ok && read.stdout.contains("FX62-OFFLINE-FORWARD") {
            break;
        }
        assert!(Instant::now() < offline_deadline,
                "PRODUCT: offline-fold sender did not deliver a fresh post after readmission: post={post:?}, read={read:?}; target status={:?}; target daemon:\n{}",
                carol.vox(None, &["status", "--json"]),
                std::fs::read_to_string(tmp.path().join("carol.daemon.err")).unwrap_or_else(|error| format!("APPARATUS: target log unavailable: {error}")));
        std::thread::sleep(Duration::from_secs(1));
    }
    let deadline = Instant::now() + WITHIN;
    let after = loop {
        let post = alice.vox(None, &["room", "post", id, "FX62-FORWARD"]);
        assert!(post.ok, "PRODUCT: post after readmission failed: {post:?}");
        let read = carol.vox(None, &["room", "read", id]);
        if read.ok && read.stdout.contains("FX62-FORWARD") {
            break read;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: readmitted carol did not read forward posts: {read:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    assert!(
        after.stdout.contains("FX62-BEFORE"),
        "PRODUCT: readmission lost already readable history: {after:?}"
    );
    let through = Instant::now() + Duration::from_secs(10);
    loop {
        let read = carol.vox(None, &["room", "read", id]);
        assert!(
            read.ok
                && !read.stdout.contains("FX62-REMOVAL-ALICE")
                && !read.stdout.contains("FX62-REMOVAL-BOB")
                && !read.stdout.contains("FX62-NEVER-REMOVED-HISTORY"),
            "PRODUCT [FX62 readmission-history]: readmission backfilled a removal-period post: {read:?}"
        );
        if Instant::now() >= through {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!("[proof] FX62 readmission-history: carol retained FX62-BEFORE and read FX62-FORWARD without removal-period history");
    let removed_again = unchanged_busy_retry(alice, &["room", "remove-member", id, &carol.b32()]);
    assert!(
        removed_again.ok,
        "PRODUCT: second removal failed: {removed_again:?}"
    );
    // An unaware partition cannot enforce a fact it has not received. Stage the
    // second removal at every online responder before exercising ordinary rejoin.
    for responder in [alice, bob, &*dave, &*erin] {
        let (gone, roster) = poll(responder, &["room", "roster", id], WITHIN, |o| {
            o.ok && !o.stdout.contains(&carol.b32())
        });
        assert!(
            gone,
            "APPARATUS: second removal did not reach {}: {roster:?}",
            responder.name
        );
    }
    // An unaware removed node cannot get a departure acknowledgement from peers
    // that correctly refuse it. Restore the pre-join attacker profile instead.
    carol.stop_daemon();
    std::fs::remove_dir_all(&carol.data).expect("APPARATUS: remove stopped attacker data");
    std::fs::remove_dir_all(&carol.cfg).expect("APPARATUS: remove stopped attacker config");
    copy_profile_tree(&carol_prejoin_data, &carol.data);
    copy_profile_tree(&carol_prejoin_cfg, &carol.cfg);
    carol.restart_daemon(&tmp.path().join("carol-old-passphrase.err"));
    let join = carol.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        !join.ok
            && format!("{} {}", join.stdout, join.stderr)
                .to_lowercase()
                .contains("remov"),
        "PRODUCT [FX62 old-passphrase]: a removed identity's old-passphrase rejoin was not truthfully refused: {join:?}"
    );
    let roster = bob.vox(None, &["room", "roster", id]);
    assert!(
        !roster.stdout.contains(&carol.b32()),
        "PRODUCT: old-passphrase rejoin restored the removed identity: {roster:?}"
    );
    eprintln!("[proof] FX-62: admin removal, non-admin refusal, remaining posts, forward-only readmission and old-passphrase exclusion");
    setup(dave, &["room", "leave", id]);
    let (left, roster) = poll(alice, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&dave.b32())
    });
    assert!(
        left,
        "APPARATUS: never-removed history control did not leave: {roster:?}"
    );
    let join = dave.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        join.ok,
        "PRODUCT [FX62 never-removed-full]: never-removed dave could not rejoin: {join:?}"
    );
    let (back, roster) = poll(alice, &["room", "roster", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&dave.b32())
    });
    assert!(
        back,
        "APPARATUS: full-history control rejoin did not reach its sender: {roster:?}"
    );
    let restart_before_post = std::env::var_os("VOX_PROOF_FX62_RESTART_REJOIN").is_some();
    if restart_before_post {
        dave.restart_daemon(&tmp.path().join("dave-rejoined-restart.err"));
        eprintln!("[proof] FX62 never-removed-full: restarted rejoined dave before its first post");
    }
    // Own-history recovery is the #1163 prerequisite, not roster propagation; use the
    // same patience as its existing recovery consumers rather than WITHIN's leave window.
    let (writable, post) = poll(
        dave,
        &["room", "post", id, "FX62-REJOIN-CONTROL"],
        support::TIMEOUT,
        |o| o.ok,
    );
    if !restart_before_post
        && !writable
        && post
            .stderr
            .contains("this node's record of its own history in this room is behind")
    {
        panic!("APPARATUS [FX62 never-removed-full]: prerequisite #1163 (returning-author continuity) is unmet; the never-removed control cannot recover after same-ID leave/rejoin: {post:?}");
    }
    assert!(writable, "PRODUCT [FX62 never-removed-full]: rejoined control never recovered its own history: {post:?}; status={:?}; daemon:\n{}",
        dave.vox(None, &["status", "--json"]),
        std::fs::read_to_string(tmp.path().join("dave-restart.err")).unwrap_or_default());
    let (ready, control) = poll(alice, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("FX62-REJOIN-CONTROL")
    });
    assert!(
        ready,
        "APPARATUS [FX62 never-removed-full]: prerequisite #1163 (returning-author continuity) is unmet; full-history control's reciprocal consent was not staged: {control:?}"
    );
    let full_control = setup(
        alice,
        &[
            "trust",
            "add",
            &dave.b32(),
            "--name",
            "dave",
            "--history",
            "full",
            "--identity-passphrase-file",
            alice
                .pass
                .to_str()
                .expect("APPARATUS: UTF-8 passphrase path"),
        ],
    );
    assert!(
        full_control.ok,
        "PRODUCT [FX62 never-removed-full]: full control grant failed: {full_control:?}"
    );
    let (seen, history) = poll(dave, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("FX62-NEVER-REMOVED-HISTORY")
    });
    assert!(
        seen,
        "PRODUCT [FX62 never-removed-full]: never-removed rejoiner lost full history: {history:?}; full grant={full_control:?}; sender status={:?}; sender daemon:\n{}\nreader daemon:\n{}",
        alice.vox(None, &["status", "--json"]),
        std::fs::read_to_string(tmp.path().join("alice.daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(tmp.path().join("dave-restart.err")).unwrap_or_default()
    );
    eprintln!(
        "[proof] FX62 never-removed-full: never-removed dave received FX62-NEVER-REMOVED-HISTORY"
    );
}

/// One control-socket request to `w`'s daemon; a socket the harness cannot reach is APPARATUS.
fn ipc(
    rt: &tokio::runtime::Runtime,
    w: &Worker,
    request: vox_core::node::ipc::Request,
) -> vox_core::node::ipc::Frame {
    rt.block_on(async {
        let mut client = support::attach::paths_client(&w.paths)
            .await
            .unwrap_or_else(|e| panic!("APPARATUS: {}'s control socket: {e}", w.name));
        client
            .request(&request)
            .await
            .unwrap_or_else(|e| panic!("APPARATUS: {}'s control socket reply: {e}", w.name))
    })
}

/// The ADR-053 MP-11 mutants in `names` the runner set, with their values. The daemons of an
/// act read them only when the act passes them (`knob_env`: temp_home strips inherited knobs),
/// and only a `vox` built to read them can: one that does not is refused here, before staging.
fn mp11_mutants(names: &[&'static str]) -> Vec<(&'static str, String)> {
    let set: Vec<(&'static str, String)> = names
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (*name, value)))
        .collect();
    if !set.is_empty() {
        test_knobs::require(&set.iter().map(|(name, _)| *name).collect::<Vec<_>>());
    }
    set
}

fn knob_env<'a>(knobs: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    knobs
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

/// What the Mac app reads for a room's sidebar row, from `w`'s node: the text of the newest row
/// of the page its `roomRead` asks for (`vox-ffi` `room_page_read`: `Request::RoomPage`, newest
/// first page; `NodeModel.swift` `readLast` previews its newest message) and the unread total of
/// `Request::UnreadSummary` (`readUnreadSummary`).
fn sidebar_of(rt: &tokio::runtime::Runtime, w: &Worker, cid: [u8; 32]) -> (Option<String>, u64) {
    use vox_core::node::ipc::{Frame, Request};
    let page = ipc(
        rt,
        w,
        Request::RoomPage {
            channel_id: cid,
            before: None,
            limit: 64,
        },
    );
    let Frame::RoomPage { rows, .. } = page else {
        panic!("PRODUCT: {}'s newest page was refused: {page:?}", w.name)
    };
    let unread = ipc(rt, w, Request::UnreadSummary { channel_id: cid });
    let Frame::UnreadSummary { summary } = unread else {
        panic!(
            "PRODUCT: {}'s unread summary was refused: {unread:?}",
            w.name
        )
    };
    (
        rows.last().map(|row| row.text.clone()),
        summary.addressed + summary.new + summary.coordination,
    )
}

/// Count what `w`'s node says to every client for `cid` as `Synced` with nothing applied: the
/// word that rows left the room or came back (ADR-053 MP-11), which a client's sidebar reads the
/// room's preview and unread again on. Subscribed before this returns.
fn display_news(w: &Worker, cid: [u8; 32]) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    let said = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let paths = w.paths.clone();
    let name = w.name.clone();
    let counter = std::sync::Arc::clone(&said);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("APPARATUS: the subscriber's runtime");
        rt.block_on(async move {
            let mut client = support::attach::paths_client(&paths)
                .await
                .unwrap_or_else(|e| panic!("APPARATUS: {name}'s control socket: {e}"));
            client
                .subscribe()
                .await
                .unwrap_or_else(|e| panic!("PRODUCT (staging): {name} refused a subscriber: {e}"));
            let _ = ready_tx.send(());
            while let Ok(Some(frame)) = client.next().await {
                if let vox_core::node::ipc::Frame::Event(vox_core::node::api::NodeEvent::Synced {
                    channel_id,
                    applied: 0,
                    rendered: 0,
                }) = frame
                {
                    if channel_id == cid {
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        });
    });
    ready_rx
        .recv_timeout(WITHIN)
        .unwrap_or_else(|_| panic!("APPARATUS: {}'s event subscription never confirmed", w.name));
    said
}

/// Green once `news` counted a word; red (`PRODUCT [MP11 news]`) when `w` reports no governance
/// work queued twice in a row and none was said: the turn that took the rows says it as it ends.
fn said_display_news(w: &Worker, news: &std::sync::atomic::AtomicU64, who: &str) {
    let mut idle = 0;
    loop {
        if news.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            return;
        }
        let status = w.vox(None, &["status", "--json"]);
        idle = if status.ok && status.json()["governance_pending"] == false {
            idle + 1
        } else {
            0
        };
        assert!(
            idle < 3,
            "PRODUCT [MP11 news]: {who} took rows away and reports no governance work queued, \
             yet said nothing a client re-reads the room's preview and unread on"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// ADR-053 MP-11 (ruling 8, "disappears"): **a message a reader already shows, whose author a
/// removal the reader applies later puts outside the removal's cut, leaves the conversation.**
///
/// Staging: alice (creator), bob and carol. Alice posts a thread root; bob posts one message and
/// one reply; alice posts again and bob, having read her, posts a tail, so a control of his own
/// that alice holds follows his two posts. Alice and carol read all of them. Bob and carol stop;
/// alice removes bob and stops. Bob and carol start again without alice, so neither has heard of
/// the removal: bob posts one message and one reply above the cut, and carol shows both. Then
/// alice starts again and carol applies the removal.
///
/// The removal's cut keeps bob's posts up to the tip alice held when she removed him (MP-6: her
/// removal names his tail), so his two posts and his tail stay; before MP-6 the cut was his last
/// control in alice's signed past and his tail was lost.
///
/// Asserted on carol, through `vox room read` and the control socket every client reads:
/// once carol's roster no longer names bob, the two posts above the cut are gone while bob's
/// three posts inside it stay; Count equals the rows the newest page holds and is what it was
/// less the two rows that left; the thread's summary counts one reply and its page lists only the
/// reply inside the cut; and all of it holds after carol's daemon restarts.
/// The verdict on a kept row is structural, not a deadline: carol's roster has dropped bob and
/// her node reports no governance work queued (`governance_pending`), twice in a row, and the
/// row is still shown.
///
/// What the Mac app's sidebar reads for the room (ADR-053 MP-11; `NodeModel.swift` `readLast`,
/// `readUnreadSummary`), asserted on what carol's node hands it: once the posts leave, carol's
/// node says `Synced` with nothing applied for the room (what makes the app read the room's
/// preview and unread again), the newest row of the page the app's `roomRead` asks for is bob's
/// tail, the newest post that stays, and carol's unread total is exactly two lower.
///
/// Main (before MP-11) is red here: the rows stay (the cached reader checks expiry, not
/// membership). Mutant `VOX_MUTANT_MP11_KEEP_ROWS` (the decision is made, the rows are left):
/// red as PRODUCT at "still shows". A `vox` that does not read the mutant's switch is refused
/// before staging (`test_knobs::require`).
#[test]
#[ignore = "three real daemons and an anchor, a removal one reader applies late; run in release"]
fn a_post_shown_before_its_authors_removal_was_applied_disappears() {
    use vox_core::node::ipc::{Frame, Request};
    watchdog::arm();
    let mutants = mp11_mutants(&["VOX_MUTANT_MP11_KEEP_ROWS"]);
    let env = knob_env(&mutants);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let cid = room.cid;
    let id = id.as_str();
    let [alice, bob, carol] = &mut room.workers[..] else {
        unreachable!()
    };
    setup(alice, &["room", "post", id, "MP11-ROOT"]);
    let Frame::RoomPage { rows, .. } = ipc(
        &rt,
        alice,
        Request::RoomPage {
            channel_id: cid,
            before: None,
            limit: 1,
        },
    ) else {
        panic!("PRODUCT (staging): alice's newest page was refused")
    };
    let root = rows
        .iter()
        .find(|row| row.text == "MP11-ROOT")
        .unwrap_or_else(|| panic!("PRODUCT (staging): alice's root is not her newest: {rows:?}"))
        .entry_hash;
    let thread = vox_core::node::link::b32_encode(&root);
    let reply = |text: &str| {
        serde_json::json!({"v":1,"type":"say","hops":8,"body":text,"thread":thread}).to_string()
    };
    setup(bob, &["room", "post", id, "MP11-BEFORE-POST"]);
    setup(bob, &["room", "post", id, &reply("MP11-BEFORE-REPLY")]);
    setup(alice, &["room", "post", id, "MP11-ALICE-AGAIN"]);
    let (seen, read) = poll(bob, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("MP11-ALICE-AGAIN")
    });
    assert!(
        seen,
        "PRODUCT (staging): bob never read alice's second post: {read:?}"
    );
    setup(bob, &["room", "post", id, "MP11-BEFORE-TAIL"]);
    for reader in [&*alice, &*carol] {
        let (seen, read) = poll(reader, &["room", "read", id], WITHIN, |o| {
            o.ok && o.stdout.contains("MP11-BEFORE-POST")
                && o.stdout.contains("MP11-BEFORE-REPLY")
                && o.stdout.contains("MP11-BEFORE-TAIL")
        });
        assert!(
            seen,
            "PRODUCT (staging): {} never read bob's posts before the removal: {read:?}",
            reader.name
        );
    }
    bob.stop_daemon();
    carol.stop_daemon();
    setup(alice, &["room", "remove-member", id, &bob.b32()]);
    let (gone, roster) = poll(alice, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&bob.b32())
    });
    assert!(gone, "PRODUCT (staging): alice still lists bob: {roster:?}");
    alice.stop_daemon();
    bob.restart_daemon(&tmp.path().join("bob-mp11.err"));
    carol.restart_daemon_as(support::VOX, &env, &tmp.path().join("carol-mp11.err"));
    setup(bob, &["room", "post", id, "MP11-ABOVE-POST"]);
    setup(bob, &["room", "post", id, &reply("MP11-ABOVE-REPLY")]);
    let (shown, read) = poll(carol, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains("MP11-ABOVE-POST") && o.stdout.contains("MP11-ABOVE-REPLY")
    });
    assert!(
        shown,
        "PRODUCT (staging): carol, not yet told of the removal, never showed bob's posts above \
         the cut: {read:?}"
    );
    let roster = setup(carol, &["room", "roster", id]);
    assert!(
        roster.stdout.contains(&bob.b32()),
        "APPARATUS: carol applied bob's removal before alice was back: {roster:?}"
    );
    let Frame::Count { n: before, .. } = ipc(
        &rt,
        carol,
        Request::Count {
            channel_id: cid,
            since: None,
        },
    ) else {
        panic!("PRODUCT: carol's Count was refused while she showed bob's posts")
    };
    let summary = |w: &Worker| match ipc(
        &rt,
        w,
        Request::ThreadSummary {
            channel_id: cid,
            root,
            after_author: None,
        },
    ) {
        Frame::ThreadSummary { reply_count, .. } => reply_count,
        other => panic!("PRODUCT: carol's thread summary was refused: {other:?}"),
    };
    let replies_before = summary(carol);
    println!("[proof] carol shows bob's posts above the cut: Count {before}, thread replies {replies_before}");
    assert_eq!(
        replies_before, 2,
        "APPARATUS: carol's thread did not hold both of bob's replies before alice returned"
    );
    let (newest_before, unread_before) = sidebar_of(&rt, carol, cid);
    assert!(
        newest_before
            .as_deref()
            .is_some_and(|text| text.contains("MP11-ABOVE-REPLY")),
        "APPARATUS: carol's newest row before alice returned is not bob's reply above the cut: \
         {newest_before:?}"
    );
    let news = display_news(carol, cid);
    alice.restart_daemon(&tmp.path().join("alice-mp11.err"));
    let mut settled_and_shown = 0;
    loop {
        let roster = carol.vox(None, &["room", "roster", id]);
        let applied = roster.ok && !roster.stdout.contains(&bob.b32());
        let status = carol.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = carol.vox(None, &["room", "read", id]);
        let kept =
            read.stdout.contains("MP11-ABOVE-POST") || read.stdout.contains("MP11-ABOVE-REPLY");
        if applied && read.ok && !kept {
            break;
        }
        settled_and_shown = if applied && idle && read.ok {
            settled_and_shown + 1
        } else {
            0
        };
        assert!(
            settled_and_shown < 2,
            "PRODUCT: carol applied bob's removal and reports no governance work queued, yet \
             still shows bob's posts above the cut: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let check = |w: &Worker, when: &str| {
        let read = setup(w, &["room", "read", id]);
        assert!(
            read.stdout.contains("MP11-BEFORE-POST")
                && read.stdout.contains("MP11-BEFORE-REPLY")
                && read.stdout.contains("MP11-BEFORE-TAIL"),
            "PRODUCT: {when}, carol lost bob's posts inside the removal's cut: {}",
            read.stdout
        );
        assert!(
            !read.stdout.contains("MP11-ABOVE"),
            "PRODUCT: {when}, carol shows bob's posts above the cut again: {}",
            read.stdout
        );
        let left = 2;
        let counted = ipc(
            &rt,
            w,
            Request::Count {
                channel_id: cid,
                since: None,
            },
        );
        let page = ipc(
            &rt,
            w,
            Request::RoomPage {
                channel_id: cid,
                before: None,
                limit: 64,
            },
        );
        let Frame::RoomPage { rows, .. } = &page else {
            panic!("PRODUCT: {when}, carol's newest page was refused: {page:?}")
        };
        assert!(
            matches!(counted, Frame::Count { n, .. } if n + left == before && n == rows.len() as u64)
                && !rows.iter().any(|row| row.text.contains("MP11-ABOVE")),
            "PRODUCT: {when}, carol's Count must be {} ({before} less the {left} rows that left) \
             and equal her newest page, which names neither post above the cut: {counted:?}, \
             {rows:?}",
            before - left
        );
        let replies = summary(w);
        let thread_page = ipc(
            &rt,
            w,
            Request::ThreadPage {
                channel_id: cid,
                root,
                before: None,
                after: None,
            },
        );
        let Frame::ThreadPage { rows, .. } = &thread_page else {
            panic!("PRODUCT: {when}, carol's thread page was refused: {thread_page:?}")
        };
        assert!(
            replies == 1 && rows.len() == 1 && rows[0].text.contains("MP11-BEFORE-REPLY"),
            "PRODUCT: {when}, carol's thread must count and list only bob's earlier reply: \
             summary {replies}, page {rows:?}"
        );
        println!(
            "[proof] {when}: carol shows bob's three earlier posts, none above the cut; Count {}, \
             thread replies {replies}",
            before - left
        );
    };
    check(carol, "once carol applied the removal");
    said_display_news(carol, &news, "carol's node, once bob's posts left");
    let (newest, unread) = sidebar_of(&rt, carol, cid);
    assert!(
        newest
            .as_deref()
            .is_some_and(|text| text.contains("MP11-BEFORE-TAIL"))
            && unread + 2 == unread_before,
        "PRODUCT [MP11 sidebar]: once bob's posts left, the app's preview read must find bob's \
         tail as the newest row and carol's unread must be {} ({unread_before} less the two that \
         left): newest {newest:?}, unread {unread}",
        unread_before.saturating_sub(2)
    );
    println!(
        "[proof] MP11 sidebar: carol's node said Synced with nothing applied; newest row \
         {newest:?}; unread {unread_before} -> {unread}"
    );
    carol.restart_daemon_as(
        support::VOX,
        &env,
        &tmp.path().join("carol-mp11-restart.err"),
    );
    let (open, read) = poll(carol, &["room", "read", id], WITHIN, |o| o.ok);
    assert!(
        open,
        "PRODUCT: carol's room did not reopen after a restart: {read:?}"
    );
    check(carol, "after carol's daemon restarted");
}

#[test]
#[ignore = "real daemons, queued sender keys and an offline sender; CI runs it in release"]
fn a_queued_key_and_history_debt_cannot_cross_room_removal() {
    watchdog::arm();
    fx62_mutant();
    let rt = runtime();
    let tmp = tempfile::tempdir().expect("APPARATUS: temporary directory");
    let mut room = room_of(&rt, tmp.path(), &["alice", "dave", "carol", "bob"]);
    let id = room.id.clone();
    let (online, offline) = room.workers.split_at_mut(3);
    let [alice, dave, carol] = online else {
        unreachable!()
    };
    let [bob] = offline else { unreachable!() };
    let id = id.as_str();
    let gate = tmp.path().join("pairwise-key.hold");
    let fold = tmp.path().join("alice-fold.hold");
    let gate_text = gate.to_str().expect("APPARATUS: UTF-8 gate path");
    let fold_text = fold.to_str().expect("APPARATUS: UTF-8 fold path");
    let change_trust = |sender: &Worker, full: bool| {
        let mut args = vec!["trust", if full { "add" } else { "remove" }];
        let target = carol.b32();
        args.push(&target);
        if full {
            args.extend(["--name", "carol", "--history", "full"]);
        }
        args.extend([
            "--identity-passphrase-file",
            sender
                .pass
                .to_str()
                .expect("APPARATUS: UTF-8 passphrase path"),
        ]);
        setup(sender, &args)
    };
    setup(alice, &["room", "admin", "add", id, &dave.b32()]);
    let (admin, listed) = poll(dave, &["room", "admin", "list", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&dave.b32())
    });
    assert!(
        admin,
        "APPARATUS: removal issuer's delegation was not staged: {listed:?}"
    );
    for sender in [&*alice, &*bob] {
        change_trust(sender, false);
        setup(
            sender,
            &[
                "room",
                "post",
                id,
                if sender.fp == alice.fp {
                    "FX62-ALICE-PRE-DEBT"
                } else {
                    "FX62-BOB-PRE-DEBT"
                },
            ],
        );
    }
    let before = setup(carol, &["room", "read", id]);
    assert!(
        !before.stdout.contains("FX62-ALICE-PRE-DEBT")
            && !before.stdout.contains("FX62-BOB-PRE-DEBT"),
        "APPARATUS: undisclosed pre-removal chains were already readable: {before:?}"
    );
    bob.stop_daemon();
    alice.restart_daemon_as(
        support::VOX,
        &[
            ("VOX_TEST_HOLD_PAIRWISE_KEY_FILE", gate_text),
            ("VOX_TEST_FOLD_HOLD_FILE", fold_text),
        ],
        &tmp.path().join("alice-gated.err"),
    );
    std::fs::write(&gate, carol.b32()).expect("APPARATUS: arm queued-key gate");
    change_trust(alice, true);
    let engaged = gate.with_extension("engaged");
    let deadline = Instant::now() + WITHIN;
    while !engaged.is_file() {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: no actual queued key reached its sender gate"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let (ready, status) = poll(alice, &["status", "--json"], WITHIN, |o| {
        o.ok && o.json()["governance_pending"] == false
    });
    assert!(
        ready,
        "APPARATUS: queued-key sender did not finish its pre-removal fold: {status:?}"
    );
    std::fs::write(&fold, b"hold").expect("APPARATUS: arm sender's governance fold hold");
    let removal = setup(dave, &["room", "remove-member", id, &carol.b32()]);
    let hash = removal
        .stdout
        .split("signed entry ")
        .nth(1)
        .and_then(|text| text.split(';').next())
        .expect("PRODUCT: removal result omitted its signed entry");
    // Exact authenticated source receipt is staging, not the egress verdict below.
    let (received, hashes) = poll(alice, &["room", "read", id, "--hashes"], WITHIN, |o| {
        o.ok && o
            .stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some(hash))
    });
    assert!(
        received,
        "APPARATUS: signed removal never reached the gated sender's hash view: {hashes:?}"
    );
    let roster = alice.vox(None, &["room", "roster", id]);
    assert!(
        roster.ok && roster.stdout.contains(&carol.b32()),
        "APPARATUS: removal was not held before the sender's fold: {roster:?}"
    );
    eprintln!("[proof] FX62 queued-key staged: a real key was queued before a durably received, unfolded removal");
    std::fs::remove_file(&gate).expect("APPARATUS: release queued-key writer");
    let through = Instant::now() + Duration::from_secs(10);
    loop {
        let read = setup(carol, &["room", "read", id]);
        assert!(
            !read.stdout.contains("FX62-ALICE-PRE-DEBT"),
            "PRODUCT [FX62 queued-key]: a pre-fold queued key reached removed carol: {read:?}"
        );
        if Instant::now() >= through {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    std::fs::remove_file(&fold).expect("APPARATUS: release sender's governance fold");
    // Releasing the marker does not poll/wake the actor. A real new governance input does.
    setup(dave, &["room", "rename", id, "fx62-fold-resumed"]);
    let (gone, roster) = poll(alice, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&carol.b32())
    });
    assert!(
        gone,
        "PRODUCT: queued-key sender failed to apply removal: {roster:?}"
    );
    setup(alice, &["room", "post", id, "FX62-ALICE-DURING-DEBT"]);
    let readmit = setup(alice, &["room", "readmit-member", id, &carol.b32()]);
    assert!(
        readmit
            .stdout
            .contains("Readmission does not restore history"),
        "PRODUCT [FX62 disclosure]: readmission omitted its history limit: {readmit:?}"
    );
    bob.restart_daemon(&tmp.path().join("bob-after-readmission.err"));
    for sender in [&*alice, &*bob] {
        let (back, roster) = poll(sender, &["room", "roster", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&carol.b32())
        });
        assert!(
            back,
            "APPARATUS: sender did not fold readmission: {roster:?}"
        );
        change_trust(sender, true);
        let tag = if sender.fp == alice.fp {
            "FX62-ALICE-FRESH"
        } else {
            "FX62-BOB-FRESH"
        };
        let deadline = Instant::now() + WITHIN;
        loop {
            setup(sender, &["room", "post", id, tag]);
            let read = setup(carol, &["room", "read", id]);
            if read.stdout.contains(tag) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT [FX62 forward]: readmitted carol received no fresh sender post: {read:?}"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let through = Instant::now() + Duration::from_secs(10);
    loop {
        let read = setup(carol, &["room", "read", id]);
        assert!(!read.stdout.contains("FX62-ALICE-PRE-DEBT")
            && !read.stdout.contains("FX62-BOB-PRE-DEBT")
            && !read.stdout.contains("FX62-ALICE-DURING-DEBT"),
            "PRODUCT [FX62 history-debt]: full grant or SEG_HISTORY backfilled undisclosed history: {read:?}");
        if Instant::now() >= through {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] FX62 queued-key: carol never read FX62-ALICE-PRE-DEBT while the removal fold was held");
    eprintln!("[proof] FX62 history-debt: both separately applied and offline-fold senders delivered fresh posts without pre-removal or removal-period debt");
}

// ---- ADR-053 MP-10: boundaries 1 and 2 of #1171, each proven alone ---------------------------
//
// A once-removed, readmitted member may newly receive (boundary 1, the provider) and newly render
// (boundary 2, the recipient) only a body whose signed causal past contains its exact readmission
// cut. Each is proven with the other one switched off, so the act's verdict rests on that boundary
// alone. Staging (both acts): alice (creator), bob (ordinary member), dave (ordinary member, the
// holder that restarts) and carol, who has read a post by each. Carol's daemon goes down. Each
// holder posts `MP10-UNSEEN-<NAME>` on the chain carol already holds; dave's daemon goes down;
// alice removes carol; alice and bob are frozen (SIGSTOP); dave comes back unaware of the removal
// (his roster still lists carol) and posts `MP10-UNAWARE-DAVE` on that chain too, after the removal
// and before the readmission. Alice and bob resume; every holder applies the removal and posts
// `MP10-GAP-<NAME>` on its rotated chain; alice readmits carol. Every one of those bodies is
// outside carol's cut, and the four on the old chains are ones she could decrypt.
// Then carol's daemon starts again, every holder running, and through each holder in turn —
// alice, then bob, then dave restarted — all run until carol reads that holder's fresh post and
// completes a sync round toward it (a live session; a holder that was frozen while carol came
// back was not reached within 60 s in two runs), then the other two are frozen and, over three more
// completed rounds toward that holder, she shows none of the seven texts and still shows the four
// `MP10-BEFORE-<NAME>` she had read. Last, every holder runs, carol's daemon restarts, and the
// same holds over three rounds toward alice. A red names the holder being watched; which holder
// can have sent the body is set by the knobs (in the mutant runs only one holder has one).
//
// Knobs (vox-core `test-knobs`, ADR-053 MP-10): `VOX_TEST_MP10_SEND_EVERY_BODY=1` switches
// boundary 1 off in the daemon that has it; `VOX_TEST_MP10_RENDER_EVERY_BODY=1` switches
// boundary 2 off.

/// A daemon's knobs for the act: boundary 1 off when `send`, boundary 2 off when `render`.
fn mp10_env(send: bool, render: bool) -> Vec<(&'static str, &'static str)> {
    let mut env = Vec::new();
    if send {
        env.push(("VOX_TEST_MP10_SEND_EVERY_BODY", "1"));
    }
    if render {
        env.push(("VOX_TEST_MP10_RENDER_EVERY_BODY", "1"));
    }
    env
}

/// Stop (`-STOP`) or resume (`-CONT`) `w`'s daemon, and check from `ps` that it took.
fn mp10_signal(w: &Worker, sig: &str) {
    let pid = w
        .daemon_pid()
        .unwrap_or_else(|| panic!("APPARATUS: {} has no daemon to {sig}", w.name));
    let sent = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status();
    assert!(
        sent.is_ok_and(|s| s.success()),
        "APPARATUS: kill {sig} {} failed",
        w.name
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let st = std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        if st.starts_with('T') == (sig == "-STOP") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: kill {sig} of {}'s daemon did not take: its state is {st:?}",
            w.name
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sync rounds `status` reports completed toward `peer`, empty ones included.
fn mp10_rounds_toward(status: &serde_json::Value, peer: &Worker) -> u64 {
    let fp = peer.b32();
    status["sync"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r["peer"]
                .as_str()
                .is_some_and(|p| fp.starts_with(p) || p.starts_with(fp.as_str()))
        })
        .map(|r| {
            ["completed", "empty", "fetched_completed", "fetched_empty"]
                .iter()
                .map(|k| r[*k].as_u64().unwrap_or(0))
                .sum::<u64>()
        })
        .sum()
}

/// `author` posts `text` again each second until `reader` reads it (a sender's rotated chain is
/// released with a fresh post); a red names `what` when it never arrives.
fn mp10_delivered(author: &Worker, reader: &Worker, id: &str, text: &str, what: &str) {
    let deadline = Instant::now() + support::TIMEOUT;
    loop {
        setup(author, &["room", "post", id, text]);
        let read = reader.vox(None, &["room", "read", id]);
        if read.ok && read.stdout.contains(text) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: {} never read {text} from {}: {read:?}; reader status={:?}",
            reader.name,
            author.name,
            reader.vox(None, &["status", "--json"]).stdout
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The phase's precondition: `holder` posts `text` again every few seconds until carol reads it
/// and her sync rounds toward `holder` have advanced since this began (a live session with it).
/// Neither within 300 s is APPARATUS NO RESULT: nothing about the boundary was measured.
fn mp10_reached(holder: &Worker, carol: &Worker, id: &str, text: &str) {
    let started = Instant::now();
    let rounds = || mp10_rounds_toward(&carol.vox(None, &["status", "--json"]).json(), holder);
    let first = rounds();
    loop {
        setup(holder, &["room", "post", id, text]);
        let read = carol.vox(None, &["room", "read", id]);
        let now = rounds();
        if read.ok && read.stdout.contains(text) && now > first {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(300),
            "APPARATUS NO RESULT (staging) [MP10 forward]: in 300 s carol did not both read {text} \
             and complete a round toward {} (rounds {first} -> {now}): {read:?}; carol status={}",
            holder.name,
            carol.vox(None, &["status", "--json"]).stdout
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// `remover` holds `text`, `author`'s post, before `author` goes and is removed: a removal keeps
/// the removed member's posts up to the last one its remover held (ADR-053 MP-6), and one it never
/// held is gone from every reader, its author included (MP-11). `author` posts `text` again every
/// few seconds, as `mp10_delivered` does (a sender's chain is released with a fresh post), until
/// `remover` shows it. Judged by `remover`'s sync rounds toward `author`: three completed after
/// the second post without it is PRODUCT (staging); fewer than three in 300 s is APPARATUS NO
/// RESULT.
fn mp10_held_by(remover: &Worker, author: &Worker, id: &str, text: &str) {
    let started = Instant::now();
    let rounds = || mp10_rounds_toward(&remover.vox(None, &["status", "--json"]).json(), author);
    let mut second: Option<u64> = None;
    let mut posts = 0u32;
    loop {
        setup(author, &["room", "post", id, text]);
        posts += 1;
        if posts == 2 {
            second = Some(rounds());
        }
        for _ in 0..3 {
            let read = remover.vox(None, &["room", "read", id]);
            if read.ok && read.stdout.contains(text) {
                return;
            }
            let now = rounds();
            if let Some(from) = second {
                assert!(
                    now < from + 3,
                    "PRODUCT (staging): {} completed {} sync rounds toward {} after the second \
                     post of {text}, and holds none of the {posts}: {read:?}",
                    remover.name,
                    now - from,
                    author.name
                );
            }
            assert!(
                started.elapsed() < Duration::from_secs(300),
                "APPARATUS NO RESULT (staging): in 300 s {} did not complete three sync rounds \
                 toward {} after the second post of {text} (rounds now {now}, from {second:?})",
                remover.name,
                author.name
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// Through `holder`, carol shows none of `gap` and every one of `before` while her sync rounds
/// toward it complete three more times. Showing any of `gap` is the RED verdict, named `red`; it
/// is given once three more rounds have completed after the first such text, naming every one
/// shown by then. Rounds that never complete within 600 s is APPARATUS NO RESULT.
fn mp10_holds(carol: &Worker, holder: &Worker, id: &str, gap: &[&str], before: &[&str], red: &str) {
    let started = Instant::now();
    let first = mp10_rounds_toward(&carol.vox(None, &["status", "--json"]).json(), holder);
    let mut shown: Vec<&str> = Vec::new();
    let mut red_at = None;
    loop {
        let read = carol.vox(None, &["room", "read", id]);
        assert!(
            read.ok,
            "PRODUCT: carol's `vox room read` failed (through {}): {read:?}",
            holder.name
        );
        for text in gap {
            if read.stdout.contains(text) && !shown.contains(text) {
                shown.push(*text);
            }
        }
        for text in before {
            assert!(
                read.stdout.contains(text),
                "PRODUCT [MP10 kept] (through {}): readmitted carol no longer shows {text}, which \
                 she had read before her removal: {}",
                holder.name,
                read.stdout
            );
        }
        let status = carol.vox(None, &["status", "--json"]).json();
        let rounds = mp10_rounds_toward(&status, holder);
        if !shown.is_empty() {
            let since = *red_at.get_or_insert(rounds);
            assert!(
                rounds < since + 3 && started.elapsed() < Duration::from_secs(600),
                "RED PRODUCT [{red}] (watching through {}): readmitted carol shows {shown:?}, written \
                 outside her readmission cut (the first at round {since} toward it, {rounds} \
                 now): {}",
                holder.name,
                read.stdout
            );
        } else if rounds >= first + 3 {
            eprintln!(
                "[proof] MP10 through {}: carol's rounds toward it {first} -> {rounds}; none of \
                 {gap:?} shown; {before:?} kept",
                holder.name
            );
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT (through {}): carol's sync rounds toward it went {first} -> \
             {rounds} in 600 s, fewer than three: status {status}",
            holder.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The staging and the verdicts both MP-10 acts share; `send[i]` and `render` are the knobs given
/// to holder `i` (alice, bob, dave) and to carol; `red` names the boundary under test.
fn mp10_readmitted_member_gets_no_gap_body(send: [bool; 3], render: bool, red: &str) {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    const CAROL: usize = 2;
    const DAVE: usize = 3;
    let holder_env = |i: usize| mp10_env(send[if i == DAVE { 2 } else { i }], false);
    // Every knob this staging sets must be read by the `vox` under test, or a default build
    // would run it unstaged and could pass without isolating its boundary.
    let knobs: Vec<&str> = mp10_env(send.contains(&true), render)
        .into_iter()
        .map(|(knob, _)| knob)
        .collect();
    test_knobs::require(&knobs);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave"]);
    let id = room.id.clone();
    let id = id.as_str();
    let err = |name: &str, what: &str| tmp.path().join(format!("{name}.{what}.err"));
    for i in [ALICE, BOB, DAVE] {
        let env = holder_env(i);
        if !env.is_empty() {
            let name = room.workers[i].name.clone();
            room.workers[i].restart_daemon_as(support::VOX, &env, &err(&name, "knobs"));
        }
    }
    let names = ["ALICE", "BOB", "CAROL", "DAVE"];
    let before: Vec<String> = names.iter().map(|n| format!("MP10-BEFORE-{n}")).collect();
    for (i, text) in before.iter().enumerate() {
        if i != CAROL {
            mp10_delivered(
                &room.workers[i],
                &room.workers[CAROL],
                id,
                text,
                "PRODUCT (staging)",
            );
        }
    }
    mp10_held_by(
        &room.workers[ALICE],
        &room.workers[CAROL],
        id,
        &before[CAROL],
    );
    let before: Vec<&str> = before.iter().map(String::as_str).collect();
    room.workers[CAROL].stop_daemon();
    // Bodies carol never saw, on the chains she holds, written before her removal.
    let unseen = ["MP10-UNSEEN-ALICE", "MP10-UNSEEN-BOB", "MP10-UNSEEN-DAVE"];
    for (i, text) in [(ALICE, unseen[0]), (BOB, unseen[1]), (DAVE, unseen[2])] {
        setup(&room.workers[i], &["room", "post", id, text]);
    }
    for i in [ALICE, BOB, DAVE] {
        for text in unseen {
            let (held, read) = poll(&room.workers[i], &["room", "read", id], WITHIN, |o| {
                o.ok && o.stdout.contains(text)
            });
            assert!(
                held,
                "PRODUCT (staging): {} never read {text}: {read:?}",
                room.workers[i].name
            );
        }
    }
    let carol_b32 = room.workers[CAROL].b32();
    room.workers[DAVE].stop_daemon();
    let removed = unchanged_busy_retry(
        &room.workers[ALICE],
        &["room", "remove-member", id, &carol_b32],
    );
    assert!(
        removed.ok,
        "PRODUCT (staging): alice could not remove carol: {removed:?}"
    );
    for i in [ALICE, BOB] {
        let (gone, roster) = poll(&room.workers[i], &["room", "roster", id], WITHIN, |o| {
            o.ok && !o.stdout.contains(&carol_b32)
        });
        assert!(
            gone,
            "PRODUCT (staging): {} still lists removed carol: {roster:?}",
            room.workers[i].name
        );
    }
    // Dave writes after the removal and before the readmission, still unaware of it: no holder
    // that knows of it runs.
    mp10_signal(&room.workers[ALICE], "-STOP");
    mp10_signal(&room.workers[BOB], "-STOP");
    let env = holder_env(DAVE);
    room.workers[DAVE].restart_daemon_as(support::VOX, &env, &err("dave", "unaware"));
    setup(
        &room.workers[DAVE],
        &["room", "post", id, "MP10-UNAWARE-DAVE"],
    );
    let roster = setup(&room.workers[DAVE], &["room", "roster", id]);
    assert!(
        roster.stdout.contains(&carol_b32),
        "APPARATUS: dave learned of carol's removal before he posted, so his post is not on the \
         chain she holds: {roster:?}"
    );
    mp10_signal(&room.workers[ALICE], "-CONT");
    mp10_signal(&room.workers[BOB], "-CONT");
    let (gone, roster) = poll(&room.workers[DAVE], &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&carol_b32)
    });
    assert!(
        gone,
        "PRODUCT (staging): dave never applied carol's removal: {roster:?}"
    );
    for i in [ALICE, BOB] {
        let (held, read) = poll(&room.workers[i], &["room", "read", id], WITHIN, |o| {
            o.ok && o.stdout.contains("MP10-UNAWARE-DAVE")
        });
        assert!(
            held,
            "PRODUCT (staging): {} never read MP10-UNAWARE-DAVE: {read:?}",
            room.workers[i].name
        );
    }
    // Bodies on the rotated chains, written during the gap.
    let gap_posts = [
        (ALICE, BOB, "MP10-GAP-ALICE"),
        (BOB, DAVE, "MP10-GAP-BOB"),
        (DAVE, ALICE, "MP10-GAP-DAVE"),
    ];
    for (author, reader, text) in gap_posts {
        mp10_delivered(
            &room.workers[author],
            &room.workers[reader],
            id,
            text,
            "PRODUCT (staging)",
        );
    }
    for (author, _, text) in gap_posts {
        for i in [ALICE, BOB, DAVE] {
            let (held, read) = poll(&room.workers[i], &["room", "read", id], WITHIN, |o| {
                o.ok && o.stdout.contains(text)
            });
            assert!(
                held,
                "PRODUCT (staging): {} never read {text} from {}: {read:?}",
                room.workers[i].name, room.workers[author].name
            );
        }
    }
    let readmit = unchanged_busy_retry(
        &room.workers[ALICE],
        &["room", "readmit-member", id, &carol_b32],
    );
    assert!(
        readmit.ok,
        "PRODUCT (staging): alice could not readmit carol: {readmit:?}"
    );
    for i in [BOB, DAVE] {
        let (back, roster) = poll(&room.workers[i], &["room", "roster", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&carol_b32)
        });
        assert!(
            back,
            "PRODUCT (staging): {} never listed readmitted carol: {roster:?}",
            room.workers[i].name
        );
    }
    let gap = [
        unseen[0],
        unseen[1],
        unseen[2],
        "MP10-UNAWARE-DAVE",
        "MP10-GAP-ALICE",
        "MP10-GAP-BOB",
        "MP10-GAP-DAVE",
    ];
    let carol_env = mp10_env(false, render);
    eprintln!("[proof] MP10 staged: carol removed, gap written, carol readmitted");
    // Carol comes back with every holder running. Then through each holder in turn: all run
    // until carol reads that holder's fresh post and completes a round toward it (dave restarts
    // first), then the other two are frozen and the act watches her rounds toward it.
    room.workers[CAROL].restart_daemon_as(support::VOX, &carol_env, &err("carol", "readmitted"));
    for (h, others) in [
        (ALICE, [BOB, DAVE]),
        (BOB, [ALICE, DAVE]),
        (DAVE, [ALICE, BOB]),
    ] {
        if h == DAVE {
            let env = holder_env(DAVE);
            room.workers[DAVE].restart_daemon_as(support::VOX, &env, &err("dave", "restarted"));
        }
        let text = format!("MP10-FORWARD-{}", names[h]);
        mp10_reached(&room.workers[h], &room.workers[CAROL], id, &text);
        for o in others {
            mp10_signal(&room.workers[o], "-STOP");
        }
        mp10_holds(
            &room.workers[CAROL],
            &room.workers[h],
            id,
            &gap,
            &before,
            red,
        );
        for o in others {
            mp10_signal(&room.workers[o], "-CONT");
        }
    }
    // Every holder at once, after carol's own restart.
    room.workers[CAROL].restart_daemon_as(support::VOX, &carol_env, &err("carol", "restarted"));
    mp10_holds(
        &room.workers[CAROL],
        &room.workers[ALICE],
        id,
        &gap,
        &before,
        red,
    );
    eprintln!("[proof] {red}: through alice, bob, restarted dave and all at once, readmitted carol shows no body from outside her cut");
}

/// Boundary 1 alone: carol renders whatever she is sent (boundary 2 off in her daemon: the
/// hostile recipient), so only the holders' sends stand between her and the gap. Mutant
/// `VOX_MUTANT_MP10_SEND=alice|bob|dave`: boundary 1 off in that holder's daemon; red through it.
#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_readmitted_member_is_sent_no_body_from_outside_its_cut() {
    watchdog::arm();
    let mutant = std::env::var("VOX_MUTANT_MP10_SEND").unwrap_or_default();
    let send = ["alice", "bob", "dave"].map(|h| mutant == h);
    mp10_readmitted_member_gets_no_gap_body(send, true, "MP10 boundary 1, provider body send");
}

/// Boundary 2 alone: every holder sends carol every body she asks for (boundary 1 off in each:
/// the hostile providers), so only her own render decision stands between her and the gap.
/// Mutant `VOX_MUTANT_MP10_RENDER=1`: boundary 2 off in carol's daemon.
#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_readmitted_member_shows_no_body_from_outside_its_cut() {
    watchdog::arm();
    let render = std::env::var("VOX_MUTANT_MP10_RENDER").is_ok_and(|v| v == "1");
    mp10_readmitted_member_gets_no_gap_body([true; 3], render, "MP10 boundary 2, recipient render");
}

/// A member who removes another and posts at once (ledger 77). The removal is applied by one save
/// and the fresh sender chain it owes by the next; the window between them is held open here
/// (`VOX_TEST_HOLD_ROOM_ROTATION_FILE`) so the post lands in it every run. The post must wait
/// out the rotation and succeed, not be refused as "an internal error".
/// Mutant: `VOX_MUTANT_POST_AFTER_REMOVAL=unmapped` (the refusal reported as an internal fault).
#[test]
#[ignore = "real daemons and a held key rotation; CI runs it in release"]
fn a_post_made_right_after_a_removal_waits_for_the_new_keys() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_HOLD_ROOM_ROTATION_FILE"]);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol"]);
    let id = room.id.clone();
    let id = id.as_str();
    let hold = tmp.path().join("rotation.hold");
    let engaged = tmp.path().join("rotation.hold.engaged");
    let met = tmp.path().join("rotation.hold.met");
    let held_log = tmp.path().join("alice-held.err");
    let daemon = || std::fs::read_to_string(&held_log).unwrap_or_default();
    // temp_home strips inherited knobs: the runner's mutant reaches alice's daemon only here.
    let mutant = std::env::var("VOX_MUTANT_POST_AFTER_REMOVAL").unwrap_or_default();
    let mut knobs = vec![(
        "VOX_TEST_HOLD_ROOM_ROTATION_FILE",
        hold.to_str().expect("APPARATUS: UTF-8 hold path"),
    )];
    if !mutant.is_empty() {
        knobs.push(("VOX_TEST_POST_AFTER_REMOVAL_MUTANT", mutant.as_str()));
    }
    room.workers[0].restart_daemon_as(support::VOX, &knobs, &held_log);
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let (ready, read) = poll(alice, &["room", "read", id], WITHIN, |o| o.ok);
    assert!(
        ready,
        "APPARATUS: alice's restarted daemon never read the room: {read:?}"
    );
    std::fs::write(&hold, id).expect("APPARATUS: arm the rotation hold");
    setup(alice, &["room", "remove-member", id, &carol.b32()]);
    let deadline = Instant::now() + WITHIN;
    while !engaged.is_file() {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: alice's removal of carol never reached its held key rotation; daemon:\n{}",
            daemon()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let roster = alice.vox(None, &["room", "roster", id]);
    assert!(
        roster.ok && !roster.stdout.contains(&carol.b32()),
        "APPARATUS: the rotation was held before alice's roster dropped carol: {roster:?}"
    );
    eprintln!("[proof] post-after-removal staged: carol's removal applied, its key rotation held");
    let text = "POST-RIGHT-AFTER-REMOVAL";
    let (answered_while_held, post) = std::thread::scope(|s| {
        let post = s.spawn(|| alice.vox(None, &["room", "post", id, text]));
        // The post is in the window once the daemon refused it there at least once.
        let deadline = Instant::now() + WITHIN;
        while !met.is_file() && !post.is_finished() {
            assert!(
                Instant::now() < deadline,
                "APPARATUS: alice's post never reached the held window; daemon:\n{}",
                daemon()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let answered_while_held = post.is_finished();
        std::fs::remove_file(&hold).expect("APPARATUS: release the rotation hold");
        (
            answered_while_held,
            post.join().expect("APPARATUS: the post's thread"),
        )
    });
    assert!(
        post.ok && !answered_while_held,
        "PRODUCT: alice's post made inside the held window (carol's removal applied, its key \
         rotation not yet saved) did not wait for the rotation and succeed (answered while the \
         rotation was still held: {answered_while_held}): {post:?}; daemon:\n{}",
        daemon()
    );
    let (seen, read) = poll(bob, &["room", "read", id], WITHIN, |o| {
        o.ok && o.stdout.contains(text)
    });
    assert!(
        seen,
        "PRODUCT: remaining bob never read alice's post made right after the removal: {read:?}"
    );
    let removed = carol.vox(None, &["room", "read", id]);
    assert!(
        !removed.stdout.contains(text),
        "PRODUCT: removed carol read alice's post made after her removal: {removed:?}"
    );
    eprintln!("[proof] post-after-removal: alice's post waited for the new keys, exited 0, bob read it and carol did not");
}

// ADR-053 MP-6. The runner selects a mutation with `VOX_MUTANT_MP6` (`uncut`: the cut ignores
// the removal's `seen` reference to its target; `absent-open`: a removal that names no tip of its
// target cuts none of its posts). temp_home strips inherited knobs, so each arm passes it to the
// daemons it starts. `knobs` are the switches the arm's daemons read: a `vox` that does not read
// every one is refused before staging (`test_knobs::require`).
fn mp6_mutant(knobs: &[&str]) -> String {
    test_knobs::require(knobs);
    std::env::var("VOX_MUTANT_MP6").unwrap_or_default()
}

/// The entry hash of the row of `read` (`<entry-hash> <author> <text>`) that says `tag`.
fn mp6_row_hash(read: &Out, tag: &str) -> String {
    read.stdout
        .lines()
        .find(|line| line.contains(tag))
        .and_then(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): the author's own read has no row {tag}: {read:?}")
        })
}

fn mp6_signed_entry(out: &Out) -> String {
    out.stdout
        .split("signed entry ")
        .nth(1)
        .and_then(|text| text.split(';').next())
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("PRODUCT: removal result omitted its signed entry: {out:?}"))
}

/// Whether `vox room read --hashes` lists `hash` (a row may print a shortened hash).
fn mp6_lists(order: &Out, hash: &str) -> bool {
    order.stdout.lines().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|held| held.starts_with(hash) || hash.starts_with(held))
    })
}

/// Post `tag` as `author` until `reader` reads it (a removal rotates keys forward-only).
fn mp6_post_until_read(author: &Worker, reader: &Worker, id: &str, tag: &str) {
    let deadline = Instant::now() + WITHIN;
    loop {
        setup(author, &["room", "post", id, tag]);
        let read = reader.vox(None, &["room", "read", id]);
        if read.ok && read.stdout.contains(tag) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {} never read {tag} from {}: {read:?}",
            reader.name,
            author.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Every one of `workers` reports no governance work pending, so no control is in flight.
fn mp6_quiet(workers: &[&Worker]) {
    for w in workers {
        let (quiet, status) = poll(w, &["status", "--json"], WITHIN, |o| {
            o.ok && o.json()["governance_pending"] == false
        });
        assert!(
            quiet,
            "APPARATUS: {} never settled its governance work: {status:?}",
            w.name
        );
    }
}

/// For ten seconds after the positive control, none of `readers` shows any of `tags`.
fn mp6_never_shown(readers: &[&Worker], id: &str, tags: &[&str], claim: &str) {
    let through = Instant::now() + Duration::from_secs(10);
    loop {
        for reader in readers {
            let read = setup(reader, &["room", "read", id]);
            let shown: Vec<_> = tags
                .iter()
                .filter(|tag| read.stdout.contains(**tag))
                .collect();
            assert!(
                shown.is_empty(),
                "PRODUCT [{claim}]: {} shows {shown:?}: {read:?}",
                reader.name
            );
        }
        if Instant::now() >= through {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Every one of `readers` shows every one of `tags`, or a `PRODUCT (staging)` red naming the
/// missing ones.
fn mp6_all_shown(readers: &[&Worker], id: &str, tags: &[&str], what: &str) {
    for reader in readers {
        let (shown, read) = poll(reader, &["room", "read", id], WITHIN, |o| {
            o.ok && tags.iter().all(|tag| o.stdout.contains(tag))
        });
        let missing: Vec<_> = tags
            .iter()
            .filter(|tag| !read.stdout.contains(**tag))
            .collect();
        assert!(
            shown,
            "PRODUCT (staging): {} never showed {what}: missing {missing:?}: {read:?}",
            reader.name
        );
    }
}

/// The verdict on what a reader keeps once it applied a removal, by its state and not by a
/// deadline. Green once `reader` shows every one of `tags`. Red (`PRODUCT [claim]`) when, twice
/// in a row, its roster no longer names `target`, it reports no governance work queued, it holds
/// every entry in `held` and shows `later` (a post made after the removal), and still does not
/// show all of `tags`. `NO RESULT` if it never reaches that state.
fn mp6_kept_once_applied(
    reader: &Worker,
    id: &str,
    target: &str,
    tags: &[&str],
    held: &[String],
    later: &str,
    claim: &str,
) {
    let give_up = Instant::now() + Duration::from_secs(120);
    let mut settled = 0;
    loop {
        let read = reader.vox(None, &["room", "read", id]);
        if read.ok && tags.iter().all(|tag| read.stdout.contains(tag)) {
            return;
        }
        let roster = reader.vox(None, &["room", "roster", id]);
        let status = reader.vox(None, &["status", "--json"]);
        let order = reader.vox(None, &["room", "read", id, "--hashes"]);
        let state = roster.ok
            && !roster.stdout.contains(target)
            && status.ok
            && status.json()["governance_pending"] == false
            && order.ok
            && held.iter().all(|hash| mp6_lists(&order, hash))
            && read.ok
            && read.stdout.contains(later);
        settled = if state { settled + 1 } else { 0 };
        let missing: Vec<_> = tags
            .iter()
            .filter(|tag| !read.stdout.contains(**tag))
            .collect();
        assert!(
            settled < 2,
            "PRODUCT [{claim}]: {} applied the removal, holds every one of the target's posts, \
             reports no governance work queued and shows the later {later}, yet does not show \
             {missing:?}: {}",
            reader.name,
            read.stdout
        );
        assert!(
            Instant::now() < give_up,
            "NO RESULT [{claim}]: {} never reached the state the verdict reads (removal applied, \
             no governance work, every post held, {later} shown): roster={roster:?} \
             status={status:?} order={order:?} read={read:?}",
            reader.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Hold `reader`'s governance fold, start it, and once it holds `removal` release the fold and
/// supply a real governance fact (`nudge` renames the room), so the fold applies the removal
/// before it decides any message it received meanwhile: one fold turn evaluates every admitted
/// control before any message's eligibility (`channel/governance.rs` `advance`).
///
/// While the reader does not hold the removal yet, `nudge` posts once every two seconds, as the
/// members of a live room do. A returning member's first history window has been seen to sit
/// unanswered while no member's head moved: in one run dave's windows of alice and carol were
/// selected and none passed for 30 s, with every connection up until the harness stopped the
/// daemons; in every run that passed, a newer head re-selected them within a second. The post
/// may be refused (it is not what this staging measures), so its result is only counted.
#[allow(clippy::too_many_arguments)]
fn mp6_apply_first(
    reader: &mut Worker,
    nudge: &Worker,
    id: &str,
    removal: &str,
    unshown: &[&str],
    hold: &std::path::Path,
    env: &[(&str, &str)],
    err: &std::path::Path,
) {
    std::fs::write(hold, b"hold").expect("APPARATUS: arm a reader's governance fold hold");
    let hold_text = hold.to_str().expect("APPARATUS: UTF-8 hold path");
    let mut env = env.to_vec();
    env.push(("VOX_TEST_FOLD_HOLD_FILE", hold_text));
    reader.restart_daemon_as(support::VOX, &env, err);
    let reader: &Worker = reader;
    let deadline = Instant::now() + WITHIN;
    let mut nudges = 0;
    loop {
        let order = reader.vox(None, &["room", "read", id, "--hashes"]);
        if order.ok && mp6_lists(&order, removal) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: {} never received the removal while its fold was held, after {nudges} \
             posts by {}: {order:?}",
            reader.name,
            nudge.name
        );
        nudges += 1;
        let posted = nudge.vox(None, &["room", "post", id, &format!("MP6-NUDGE-{nudges}")]);
        eprintln!(
            "[proof] {} does not hold the removal yet; {} posted MP6-NUDGE-{nudges}: ok={}",
            reader.name, nudge.name, posted.ok
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    let read = setup(reader, &["room", "read", id]);
    let early: Vec<_> = unshown
        .iter()
        .filter(|tag| read.stdout.contains(**tag))
        .collect();
    assert!(
        early.is_empty(),
        "APPARATUS: {} showed {early:?} before its fold could apply the removal: {read:?}",
        reader.name
    );
    std::fs::remove_file(hold).expect("APPARATUS: release a reader's governance fold");
    // Releasing the marker does not wake the actor. A real new governance input does.
    setup(
        nudge,
        &[
            "room",
            "rename",
            id,
            &format!("mp6-{}-applies", reader.name),
        ],
    );
}

/// ADR-053 MP-6 (a) with MP-11: **a removal keeps its target's posts up to the tip its remover
/// held on every reader, and a later post a reader had already shown disappears.** alice
/// (creator), bob (target), carol and dave. dave stops. alice posts a thread root; bob posts
/// three messages and a reply to it in a row, so his last control entry (the context update before
/// the first) is below all four, and alice and carol show them. With bob and carol stopped, alice
/// removes bob (her removal names his reply, the latest tip she holds) and stops. bob, who never
/// hears of it, posts once more and replies once more; carol, started again without alice, shows
/// both. alice comes back and carol applies the removal. dave comes back with his fold held,
/// receives the removal and applies it before he decides any of bob's posts: he reads the room as
/// a reader that applies the removal first does. (A newcomer that joins after the removal cannot
/// read bob at all: only bob releases bob's keys, ADR-006 §History, and a removed author's later
/// key package is outside its cut.)
///
/// Asserted:
/// - carol, which showed all six of bob's posts before applying the removal: once she applied it
///   and reports no governance work queued, the four alice had shown stay (`MP6 witnessed`) and
///   the two after them are gone (`MP11 disappears`); her Count is what it was less exactly those
///   two and equals her newest page; the thread's summary counts one reply and its page lists
///   only bob's earlier reply; the same after carol's daemon restarts;
/// - dave shows all four, the last one included (`MP6 witnessed`, a verdict by dave's state, not
///   a deadline), and his thread counts and lists that one reply; alice, the remover, still shows
///   all four; no one shows bob's posts after the removal again (`MP6 after removal`).
///
/// Mutant `uncut` (`VOX_MUTANT_MP6`, the cut of main: bob's last control entry, below all four)
/// is red at `MP6 witnessed` on carol: with MP-11 she loses the rows she showed. Mutant
/// `VOX_MUTANT_MP11_KEEP_ROWS` (the decision is made, the rows are left, as on main) is red at
/// `MP11 disappears`. Dropping the reserved slot cannot be staged red here: the picker
/// gives every other author's tip a slot while there are at most sixteen
/// (`channel/local_history.rs` `authored_context`).
#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_removal_keeps_the_posts_its_remover_held_and_no_later_one() {
    use vox_core::node::ipc::{Frame, Request};
    watchdog::arm();
    let mutant = mp6_mutant(&["VOX_TEST_MP6_MUTANT", "VOX_TEST_FOLD_HOLD_FILE"]);
    let keep_rows = mp11_mutants(&["VOX_MUTANT_MP11_KEEP_ROWS"]);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave"]);
    let id = room.id.clone();
    let cid = room.cid;
    let id = id.as_str();
    let [alice, bob, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    // Each knob a reader's daemon reads is passed to it here, never inherited.
    let mut env = vec![("VOX_TEST_MP6_MUTANT", mutant.as_str())];
    env.extend(knob_env(&keep_rows));
    alice.restart_daemon_as(support::VOX, &env, &tmp.path().join("alice-mp6.err"));
    for reader in [&*bob, &*carol, &*dave] {
        mp6_post_until_read(alice, reader, id, "MP6-READY");
    }
    mp6_quiet(&[alice, bob, carol, dave]);
    dave.stop_daemon_cleanly();
    setup(alice, &["room", "post", id, "MP6-ROOT"]);
    let Frame::RoomPage { rows, .. } = ipc(
        &rt,
        alice,
        Request::RoomPage {
            channel_id: cid,
            before: None,
            limit: 8,
        },
    ) else {
        panic!("PRODUCT (staging): alice's newest page was refused")
    };
    let root = rows
        .iter()
        .find(|row| row.text == "MP6-ROOT")
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): alice's newest page lacks her root: {rows:?}")
        })
        .entry_hash;
    let thread = vox_core::node::link::b32_encode(&root);
    let reply = |text: &str| {
        serde_json::json!({"v":1,"type":"say","hops":8,"body":text,"thread":thread}).to_string()
    };
    let tags = ["MP6-BOB-1", "MP6-BOB-2", "MP6-BOB-3", "MP6-BOB-4"];
    for tag in &tags[..3] {
        setup(bob, &["room", "post", id, *tag]);
    }
    setup(bob, &["room", "post", id, &reply(tags[3])]);
    mp6_all_shown(&[alice, carol], id, &tags, "all four of bob's posts");
    let at_remover = setup(alice, &["room", "read", id]);
    let witnessed: Vec<String> = tags
        .iter()
        .map(|tag| mp6_row_hash(&at_remover, tag))
        .collect();
    bob.stop_daemon_cleanly();
    carol.stop_daemon_cleanly();
    let removal = unchanged_busy_retry(alice, &["room", "remove-member", id, &bob.b32()]);
    assert!(
        removal.ok,
        "PRODUCT: the creator could not remove bob: {removal:?}"
    );
    let removal = mp6_signed_entry(&removal);
    alice.stop_daemon_cleanly();
    bob.restart_daemon(&tmp.path().join("bob-unaware.err"));
    let after = "MP6-BOB-AFTER-REMOVAL";
    let after_reply = "MP6-BOB-AFTER-REPLY";
    setup(bob, &["room", "post", id, after]);
    setup(bob, &["room", "post", id, &reply(after_reply)]);
    let after_hash = mp6_row_hash(&setup(bob, &["room", "read", id]), after);
    carol.restart_daemon_as(support::VOX, &env, &tmp.path().join("carol-unaware.err"));
    mp6_all_shown(
        &[carol],
        id,
        &[after, after_reply],
        "bob's two posts after his removal, before alice was back",
    );
    let roster = setup(carol, &["room", "roster", id]);
    assert!(
        roster.stdout.contains(&bob.b32()),
        "APPARATUS: carol applied bob's removal before alice was back: {roster:?}"
    );
    let count = |w: &Worker| match ipc(
        &rt,
        w,
        Request::Count {
            channel_id: cid,
            since: None,
        },
    ) {
        Frame::Count { n, .. } => n,
        other => panic!("PRODUCT: {}'s Count was refused: {other:?}", w.name),
    };
    let summary = |w: &Worker| match ipc(
        &rt,
        w,
        Request::ThreadSummary {
            channel_id: cid,
            root,
            after_author: None,
        },
    ) {
        Frame::ThreadSummary { reply_count, .. } => reply_count,
        other => panic!(
            "PRODUCT: {}'s thread summary was refused: {other:?}",
            w.name
        ),
    };
    let thread_page = |w: &Worker| match ipc(
        &rt,
        w,
        Request::ThreadPage {
            channel_id: cid,
            root,
            before: None,
            after: None,
        },
    ) {
        Frame::ThreadPage { rows, .. } => rows,
        other => panic!("PRODUCT: {}'s thread page was refused: {other:?}", w.name),
    };
    let before = count(carol);
    let replies_before = summary(carol);
    println!(
        "[proof] carol shows bob's posts after his removal: Count {before}, thread replies {replies_before}"
    );
    assert_eq!(
        replies_before, 2,
        "APPARATUS: carol's thread did not hold both of bob's replies before alice returned"
    );
    alice.restart_daemon_as(support::VOX, &env, &tmp.path().join("alice-back.err"));
    let mut settled_and_shown = 0;
    loop {
        let roster = carol.vox(None, &["room", "roster", id]);
        let applied = roster.ok && !roster.stdout.contains(&bob.b32());
        let status = carol.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = carol.vox(None, &["room", "read", id]);
        let kept = read.stdout.contains("MP6-BOB-AFTER");
        if applied && read.ok && !kept {
            break;
        }
        settled_and_shown = if applied && idle && read.ok {
            settled_and_shown + 1
        } else {
            0
        };
        assert!(
            settled_and_shown < 2,
            "PRODUCT [MP11 disappears]: carol applied bob's removal and reports no governance \
             work queued, yet still shows his posts after the tip alice held: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let check = |w: &Worker, when: &str| {
        mp6_quiet(&[w]);
        let read = setup(w, &["room", "read", id]);
        let lost: Vec<_> = tags
            .iter()
            .filter(|tag| !read.stdout.contains(**tag))
            .collect();
        assert!(
            lost.is_empty(),
            "PRODUCT [MP6 witnessed]: {when}, carol lost {lost:?}, bob's posts alice had read: {}",
            read.stdout
        );
        assert!(
            !read.stdout.contains("MP6-BOB-AFTER"),
            "PRODUCT [MP11 disappears]: {when}, carol shows bob's posts after the tip alice held: {}",
            read.stdout
        );
        let n = count(w);
        let Frame::RoomPage { rows, .. } = ipc(
            &rt,
            w,
            Request::RoomPage {
                channel_id: cid,
                before: None,
                limit: 64,
            },
        ) else {
            panic!("PRODUCT: {when}, carol's newest page was refused")
        };
        assert!(
            n + 2 == before
                && n == rows.len() as u64
                && !rows.iter().any(|row| row.text.contains("MP6-BOB-AFTER")),
            "PRODUCT [MP11 disappears]: {when}, carol's Count must be {} ({before} less the two \
             rows that left) and equal her newest page, which names neither later post: Count \
             {n}, {rows:?}",
            before - 2
        );
        let replies = summary(w);
        let rows = thread_page(w);
        assert!(
            replies == 1 && rows.len() == 1 && rows[0].text.contains(tags[3]),
            "PRODUCT [MP11 disappears]: {when}, carol's thread must count and list only bob's \
             reply alice had read: summary {replies}, page {rows:?}"
        );
        println!(
            "[proof] {when}: carol shows bob's four posts alice had read and neither later one; \
             Count {n}, thread replies {replies}"
        );
    };
    check(carol, "once carol applied the removal");
    carol.restart_daemon_as(support::VOX, &env, &tmp.path().join("carol-restart.err"));
    let (open, read) = poll(carol, &["room", "read", id], WITHIN, |o| o.ok);
    assert!(
        open,
        "PRODUCT: carol's room did not reopen after a restart: {read:?}"
    );
    check(carol, "after carol's daemon restarted");
    bob.stop_daemon_cleanly();
    let mut unshown = tags.to_vec();
    unshown.extend([after, after_reply]);
    mp6_apply_first(
        dave,
        alice,
        id,
        &removal,
        &unshown,
        &tmp.path().join("dave-fold.hold"),
        &env,
        &tmp.path().join("dave-back.err"),
    );
    let (alice, carol, dave): (&Worker, &Worker, &Worker) = (alice, carol, dave);
    let (gone, roster) = poll(dave, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&bob.b32())
    });
    assert!(
        gone,
        "PRODUCT: dave never applied bob's removal: {roster:?}"
    );
    mp6_post_until_read(alice, dave, id, "MP6-ALICE-AFTER-REMOVAL");
    mp6_kept_once_applied(
        dave,
        id,
        &bob.b32(),
        &tags,
        &witnessed,
        "MP6-ALICE-AFTER-REMOVAL",
        "MP6 witnessed",
    );
    mp6_all_shown(&[dave], id, &["MP6-ROOT"], "alice's thread root");
    let (replies, rows) = (summary(dave), thread_page(dave));
    assert!(
        replies == 1 && rows.len() == 1 && rows[0].text.contains(tags[3]),
        "PRODUCT [MP6 witnessed]: dave's thread must count and list bob's reply alice had read: \
         summary {replies}, page {rows:?}"
    );
    mp6_quiet(&[alice]);
    let at_remover = setup(alice, &["room", "read", id]);
    let lost: Vec<_> = tags
        .iter()
        .filter(|tag| !at_remover.stdout.contains(**tag))
        .collect();
    assert!(
        lost.is_empty(),
        "PRODUCT [MP6 witnessed]: alice, the remover, lost {lost:?}: {}",
        at_remover.stdout
    );
    mp6_never_shown(
        &[alice, carol, dave],
        id,
        &[after, after_reply],
        "MP6 after removal",
    );
    let order = setup(dave, &["room", "read", id, "--hashes"]);
    eprintln!(
        "[proof] MP6 (a): dave, applying bob's removal first, carol, which showed bob's later posts, and alice show all four posts alice had shown and no one shows bob's posts after it; dave holds the first of those: {}",
        mp6_lists(&order, &after_hash)
    );
}

/// ADR-053 MP-6 (b): **a removal that names no tip of its target keeps only what its signed
/// context reached: today's cut, never less.** bob, an admin alice named, runs a node built to
/// leave the target out of its `seen` (`VOX_TEST_REMOVAL_OMITS_TARGET`), so its context does not
/// join the target's own frontier either. dave stops. carol posts once, alice posts so carol's
/// next post carries a context update, and carol posts three more; alice and bob show all four.
/// alice posts again and bob reads it, so the context bob signs reaches carol's last control
/// entry through alice's tip, as an honest removal's does today. bob removes carol. dave comes
/// back with his fold held and applies the removal before he decides any of carol's posts.
///
/// Asserted on dave: carol's first post, below that control entry, stays (`MP6 omitted kept`);
/// none of the three after it is ever shown (`MP6 omitted`). Main is green (this is today's
/// cut). Mutant `absent-open` is red at `MP6 omitted`.
#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_removal_that_names_no_tip_of_its_target_keeps_only_what_its_context_reached() {
    watchdog::arm();
    let mutant = mp6_mutant(&[
        "VOX_TEST_MP6_MUTANT",
        "VOX_TEST_FOLD_HOLD_FILE",
        "VOX_TEST_REMOVAL_OMITS_TARGET",
    ]);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave"]);
    let id = room.id.clone();
    let id = id.as_str();
    let [alice, bob, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    setup(alice, &["room", "admin", "add", id, &bob.b32()]);
    let (admin, listed) = poll(bob, &["room", "admin", "list", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&bob.b32())
    });
    assert!(
        admin,
        "APPARATUS: bob's delegation was not staged: {listed:?}"
    );
    let env = [("VOX_TEST_MP6_MUTANT", mutant.as_str())];
    bob.restart_daemon_as(
        support::VOX,
        &[
            ("VOX_TEST_REMOVAL_OMITS_TARGET", "1"),
            ("VOX_TEST_MP6_MUTANT", &mutant),
        ],
        &tmp.path().join("bob-mp6.err"),
    );
    for reader in [&*bob, &*carol, &*dave] {
        mp6_post_until_read(alice, reader, id, "MP6-READY");
    }
    mp6_quiet(&[alice, bob, carol, dave]);
    dave.stop_daemon_cleanly();
    let kept = "MP6-INSIDE-CUT";
    setup(carol, &["room", "post", id, kept]);
    mp6_all_shown(&[alice, bob], id, &[kept], "carol's first post");
    mp6_post_until_read(alice, carol, id, "MP6-ALICE-BETWEEN");
    let tags = ["MP6-OMITTED-1", "MP6-OMITTED-2", "MP6-OMITTED-3"];
    for tag in tags {
        setup(carol, &["room", "post", id, tag]);
    }
    mp6_all_shown(&[alice, bob], id, &tags, "carol's three later posts");
    mp6_post_until_read(alice, bob, id, "MP6-ALICE-AFTER-CAROL");
    let at_remover = setup(bob, &["room", "read", id]);
    let held: Vec<String> = std::iter::once(kept)
        .chain(tags)
        .map(|tag| mp6_row_hash(&at_remover, tag))
        .collect();
    let removal = unchanged_busy_retry(bob, &["room", "remove-member", id, &carol.b32()]);
    assert!(
        removal.ok,
        "PRODUCT: the delegated admin could not remove carol: {removal:?}"
    );
    let removal = mp6_signed_entry(&removal);
    let mut unshown = tags.to_vec();
    unshown.push(kept);
    mp6_apply_first(
        dave,
        alice,
        id,
        &removal,
        &unshown,
        &tmp.path().join("dave-fold.hold"),
        &env,
        &tmp.path().join("dave-back.err"),
    );
    let (alice, dave): (&Worker, &Worker) = (alice, dave);
    let (gone, roster) = poll(dave, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&carol.b32())
    });
    assert!(
        gone,
        "PRODUCT: dave never applied carol's removal: {roster:?}"
    );
    mp6_post_until_read(alice, dave, id, "MP6-AFTER-OMITTING-REMOVAL");
    mp6_kept_once_applied(
        dave,
        id,
        &carol.b32(),
        &[kept],
        &held,
        "MP6-AFTER-OMITTING-REMOVAL",
        "MP6 omitted kept",
    );
    mp6_never_shown(&[dave], id, &tags, "MP6 omitted");
    eprintln!("[proof] MP6 (b): a removal naming no tip of carol keeps her post below her last control its context reached and none of the three after it");
}

/// One identifier printed in full by one command and shortened by another.
fn mp9_same_id(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && (a.starts_with(b) || b.starts_with(a))
}

/// Poll `author`'s own status until `peer` says it holds all of `author`'s own feed in `room`.
fn mp9_peer_holds_own_feed(author: &Worker, peer: &Worker, room: &str) {
    let peer_id = peer.b32();
    let (held, status) = poll(author, &["status", "--json"], WITHIN, |o| {
        o.ok && o.json()["rooms"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["id"].as_str().is_some_and(|rid| mp9_same_id(rid, room)))
            .any(|r| {
                let own = r["own_feed_through"].as_u64().unwrap_or(u64::MAX);
                r["members"].as_array().into_iter().flatten().any(|m| {
                    m["id"]
                        .as_str()
                        .is_some_and(|mid| mp9_same_id(mid, &peer_id))
                        && m["held_through"].as_u64().is_some_and(|held| held >= own)
                })
            })
    });
    assert!(
        held,
        "PRODUCT (staging): {} never said it holds {}'s whole feed: {status:?}",
        peer.name, author.name
    );
}

/// `w`'s own feed length in `room`, as its status says.
fn mp9_own_feed_through(w: &Worker, room: &str) -> u64 {
    let status = setup(w, &["status", "--json"]);
    status.json()["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"].as_str().is_some_and(|rid| mp9_same_id(rid, room)))
        .and_then(|r| r["own_feed_through"].as_u64())
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: {}'s status names no own feed in the room: {status:?}",
                w.name
            )
        })
}

/// ADR-053 MP-9 with a member that forks itself into two branches of one length: **a reader
/// holding one branch records the fork when it meets a member holding the other.** alice
/// (creator), carol (the forking member), dave. carol's last entry before the fork is a post
/// every member read, so each branch is posts alone. dave stops; carol posts branch A and alice
/// shows it; alice stops. A copy of carol's profile from before branch A then posts branch B, as
/// long as branch A, with only dave running: dave accepts and shows branch B. carol stops and
/// alice comes back: dave and alice each hold one branch of one length.
///
/// Asserted on dave: `vox status --json` lists carol's equivocation (`MP9 fork-recorded`).
/// Mutant `VOX_MUTANT_FORK=equal-rival-refused` (a head of the accepted size with another root
/// refused at staging, as before MP-9) turns it red there.
#[test]
#[ignore = "real daemons and an anchor, production Argon2id; CI runs it in release"]
fn a_target_that_forks_itself_has_its_fork_recorded_by_a_reader_holding_both_branches() {
    watchdog::arm();
    // A mutant a run names is in the `vox` under test; the daemons inherit it.
    if std::env::var_os("VOX_MUTANT_FORK").is_some() {
        test_knobs::require(&["VOX_MUTANT_FORK"]);
    }
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "carol", "dave"]);
    let id = room.id.clone();
    let id = id.as_str();
    let [alice, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    for reader in [&*carol, &*dave] {
        mp6_post_until_read(alice, reader, id, "MP9-READY");
    }
    setup(carol, &["room", "post", id, "MP9-BASE"]);
    mp6_all_shown(
        &[alice, dave],
        id,
        &["MP9-BASE"],
        "carol's last post before her fork",
    );
    mp6_quiet(&[alice, carol, dave]);
    dave.stop_daemon_cleanly();
    carol.stop_daemon_cleanly();
    let base_data = tmp.path().join("carol-base-data");
    let base_cfg = tmp.path().join("carol-base-cfg");
    copy_profile_tree(&carol.data, &base_data);
    copy_profile_tree(&carol.cfg, &base_cfg);
    carol.restart_daemon(&tmp.path().join("carol-a.err"));
    let branch_a = ["MP9-BRANCH-A-1", "MP9-BRANCH-A-2"];
    for tag in branch_a {
        setup(carol, &["room", "post", id, tag]);
    }
    mp6_all_shown(&[alice], id, &branch_a, "carol's branch A");
    let a_through = mp9_own_feed_through(carol, id);
    alice.stop_daemon_cleanly();
    carol.stop_daemon_cleanly();
    std::fs::remove_dir_all(&carol.data).expect("APPARATUS: remove carol's branch-A data");
    std::fs::remove_dir_all(&carol.cfg).expect("APPARATUS: remove carol's branch-A config");
    copy_profile_tree(&base_data, &carol.data);
    copy_profile_tree(&base_cfg, &carol.cfg);
    dave.restart_daemon(&tmp.path().join("dave-b.err"));
    carol.restart_daemon(&tmp.path().join("carol-b.err"));
    let branch_b = ["MP9-BRANCH-B-1", "MP9-BRANCH-B-2"];
    for tag in branch_b {
        setup(carol, &["room", "post", id, tag]);
    }
    let b_through = mp9_own_feed_through(carol, id);
    assert_eq!(
        a_through, b_through,
        "APPARATUS: carol's two branches are not of one length"
    );
    mp6_all_shown(&[dave], id, &branch_b, "carol's branch B");
    mp9_peer_holds_own_feed(carol, dave, id);
    carol.stop_daemon_cleanly();
    alice.restart_daemon(&tmp.path().join("alice-back.err"));
    let carol_id = carol.b32();
    let (recorded, status) = poll(dave, &["status", "--json"], Duration::from_secs(90), |o| {
        o.ok && o.json()["equivocations"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| {
                e["author"]
                    .as_str()
                    .is_some_and(|author| mp9_same_id(author, &carol_id))
            })
    });
    assert!(
        recorded,
        "PRODUCT [MP9 fork-recorded]: dave, holding carol's branch B, met alice holding her branch A of one length and never recorded her fork: {status:?}"
    );
    eprintln!("[proof] MP9: dave recorded carol's fork: {status:?}");
}

/// Count, newest page, thread summary and thread page of `w` for `cid` and `root`: what the acts
/// below compare before and after rows leave or come back.
struct Shown {
    count: u64,
    page: Vec<[u8; 32]>,
    texts: Vec<String>,
    replies: u64,
    thread: Vec<String>,
}

fn shown_of(rt: &tokio::runtime::Runtime, w: &Worker, cid: [u8; 32], root: [u8; 32]) -> Shown {
    use vox_core::node::ipc::{Frame, Request};
    let count = match ipc(
        rt,
        w,
        Request::Count {
            channel_id: cid,
            since: None,
        },
    ) {
        Frame::Count { n, .. } => n,
        other => panic!("PRODUCT: {}'s Count was refused: {other:?}", w.name),
    };
    let (page, texts) = match ipc(
        rt,
        w,
        Request::RoomPage {
            channel_id: cid,
            before: None,
            limit: 64,
        },
    ) {
        Frame::RoomPage { rows, .. } => (
            rows.iter().map(|row| row.entry_hash).collect(),
            rows.iter().map(|row| row.text.clone()).collect(),
        ),
        other => panic!("PRODUCT: {}'s newest page was refused: {other:?}", w.name),
    };
    let replies = match ipc(
        rt,
        w,
        Request::ThreadSummary {
            channel_id: cid,
            root,
            after_author: None,
        },
    ) {
        Frame::ThreadSummary { reply_count, .. } => reply_count,
        other => panic!(
            "PRODUCT: {}'s thread summary was refused: {other:?}",
            w.name
        ),
    };
    let thread = match ipc(
        rt,
        w,
        Request::ThreadPage {
            channel_id: cid,
            root,
            before: None,
            after: None,
        },
    ) {
        Frame::ThreadPage { rows, .. } => rows.iter().map(|row| row.text.clone()).collect(),
        other => panic!("PRODUCT: {}'s thread page was refused: {other:?}", w.name),
    };
    Shown {
        count,
        page,
        texts,
        replies,
        thread,
    }
}

/// The thread root `text` `w` just posted: the newest row of its newest page.
fn posted_root(rt: &tokio::runtime::Runtime, w: &Worker, cid: [u8; 32], text: &str) -> [u8; 32] {
    use vox_core::node::ipc::{Frame, Request};
    let Frame::RoomPage { rows, .. } = ipc(
        rt,
        w,
        Request::RoomPage {
            channel_id: cid,
            before: None,
            limit: 8,
        },
    ) else {
        panic!("PRODUCT (staging): {}'s newest page was refused", w.name)
    };
    rows.iter()
        .find(|row| row.text == text)
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): {} does not show {text}: {rows:?}",
                w.name
            )
        })
        .entry_hash
}

/// ADR-053 MP-6 and MP-11 at the first open by this build: **a store an older vox left showing
/// posts its own completed removal decision refuses loses them when this build first opens it,
/// with nobody writing, and keeps the posts the remover had read, including the ones the older
/// cut refused.**
///
/// Staged on the base `vox` (`VOX_PROOF_BASE_BINARY`: main, before MP-6 and MP-11), every
/// process of it: alice (creator), bob and carol. alice posts a thread root; bob posts three
/// messages and a reply to it in a row, so his last control entry (the context update before the
/// first) is below all four; alice and carol show them. bob and carol stop; alice removes bob (her
/// removal's `seen` names his reply: main gives every other author's tip a slot while there are
/// at most sixteen) and stops. bob, unaware, posts once more and replies once more; carol, started
/// without alice, shows both. alice comes back and carol applies the removal: main takes no shown
/// row away, so carol shows all six, while her completed decisions refuse the two later ones and,
/// under main's cut (bob's last control entry, below all four), the four alice had read too: what
/// `a_removal_keeps_the_posts_its_remover_held_and_no_later_one` measures red with mutant `uncut`
/// (main's cut). Every daemon stops. carol's daemon then starts from the `vox` under test, the
/// only member running: nothing new reaches her.
///
/// Asserted on carol: the two later posts leave (`MP11 upgrade`; the verdict is her state, not a
/// deadline: she reports no governance work queued twice in a row and still shows one), the four
/// alice had read stay (`MP6 upgrade`), Count is exactly two less and equals her newest page, her
/// thread counts and lists only bob's earlier reply; the same after her daemon restarts. What she
/// shows at her first answered read, while the reconcile may still be under way, is printed.
///
/// `926bba2c3` (MP-6 and MP-11 without the reconcile) is red at `MP11 upgrade`: the index main
/// sealed is settled and nothing recomputes it. Mutant `VOX_MUTANT_MP11_NO_RECONCILE` (the older
/// index is opened without the new generation) is red at the same.
#[test]
#[ignore = "real daemons and an anchor on a base vox, then the vox under test; run in release"]
fn a_store_an_older_vox_left_showing_refused_posts_loses_them_at_the_first_open() {
    watchdog::arm();
    let base = std::env::var("VOX_PROOF_BASE_BINARY").unwrap_or_else(|_| {
        panic!("APPARATUS: set VOX_PROOF_BASE_BINARY to a `vox` built before MP-6 and MP-11")
    });
    assert!(
        std::path::Path::new(&base).is_file(),
        "APPARATUS: VOX_PROOF_BASE_BINARY {base} is not a file"
    );
    let mutants = mp11_mutants(&["VOX_MUTANT_MP11_NO_RECONCILE"]);
    let env = knob_env(&mutants);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = rt.block_on(support::room_as(
        tmp.path(),
        &["alice", "bob", "carol"],
        &base,
    ));
    let id = room.id.clone();
    let cid = room.cid;
    let id = id.as_str();
    {
        let [alice, bob, carol] = &mut room.workers[..] else {
            unreachable!()
        };
        for reader in [&*bob, &*carol] {
            mp6_post_until_read(alice, reader, id, "MP11U-READY");
        }
        mp6_quiet(&[alice, bob, carol]);
    }
    let [alice, bob, carol] = &mut room.workers[..] else {
        unreachable!()
    };
    setup(alice, &["room", "post", id, "MP11U-ROOT"]);
    let root = posted_root(&rt, alice, cid, "MP11U-ROOT");
    let thread = vox_core::node::link::b32_encode(&root);
    let reply = |text: &str| {
        serde_json::json!({"v":1,"type":"say","hops":8,"body":text,"thread":thread}).to_string()
    };
    let tags = ["MP11U-BOB-1", "MP11U-BOB-2", "MP11U-BOB-3", "MP11U-BOB-4"];
    for tag in &tags[..3] {
        setup(bob, &["room", "post", id, *tag]);
    }
    setup(bob, &["room", "post", id, &reply(tags[3])]);
    mp6_all_shown(&[alice, carol], id, &tags, "all four of bob's posts");
    bob.stop_daemon_cleanly();
    carol.stop_daemon_cleanly();
    let removal = unchanged_busy_retry(alice, &["room", "remove-member", id, &bob.b32()]);
    assert!(
        removal.ok,
        "PRODUCT (staging): the creator could not remove bob on the base vox: {removal:?}"
    );
    alice.stop_daemon_cleanly();
    bob.restart_daemon(&tmp.path().join("bob-unaware.err"));
    let (after, after_reply) = ("MP11U-BOB-AFTER", "MP11U-BOB-AFTER-REPLY");
    setup(bob, &["room", "post", id, after]);
    setup(bob, &["room", "post", id, &reply(after_reply)]);
    carol.restart_daemon(&tmp.path().join("carol-unaware.err"));
    mp6_all_shown(
        &[carol],
        id,
        &[after, after_reply],
        "bob's two posts after his removal, before alice was back",
    );
    alice.restart_daemon(&tmp.path().join("alice-back.err"));
    let (applied, roster) = poll(carol, &["room", "roster", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&bob.b32())
    });
    assert!(
        applied,
        "PRODUCT (staging): carol never applied bob's removal on the base vox: {roster:?}"
    );
    mp6_quiet(&[carol]);
    let mut all = tags.to_vec();
    all.extend([after, after_reply]);
    let read = setup(carol, &["room", "read", id]);
    let missing: Vec<_> = all
        .iter()
        .filter(|tag| !read.stdout.contains(**tag))
        .collect();
    assert!(
        missing.is_empty(),
        "APPARATUS: on the base vox carol applied the removal and no longer shows {missing:?}: \
         VOX_PROOF_BASE_BINARY is not a vox before MP-11, or the staging failed: {}",
        read.stdout
    );
    let before = shown_of(&rt, carol, cid, root);
    println!(
        "[proof] on the base vox carol applied bob's removal and shows all six of his posts: \
         Count {}, thread replies {}",
        before.count, before.replies
    );
    assert_eq!(
        before.replies, 2,
        "APPARATUS: carol's thread did not hold both of bob's replies on the base vox"
    );
    let bob_b32 = room.workers[1].b32();
    for w in &mut room.workers {
        w.stop_daemon_cleanly();
    }
    let carol = &mut room.workers[2];
    carol.exe = support::VOX.to_owned();
    let opened = Instant::now();
    carol.restart_daemon_as(support::VOX, &env, &tmp.path().join("carol-upgraded.err"));
    let carol: &Worker = carol;
    let (open, first) = poll(carol, &["room", "read", id], WITHIN, |o| o.ok);
    let first_read = opened.elapsed();
    let status = carol.vox(None, &["status", "--json"]);
    println!(
        "[proof] carol's first answered read on the vox under test (open={open}): later posts \
         shown={}, the four shown={}; governance_pending={}; read: {:?}",
        first.stdout.contains("MP11U-BOB-AFTER"),
        tags.iter().all(|tag| first.stdout.contains(tag)),
        status.json()["governance_pending"],
        first
    );
    // A number for the notes, not a verdict: how long the reconcile took to show, and what
    // carol's reads and roster answered meanwhile.
    let (mut old_reads, mut refreshing, mut asked) = (0u32, 0u32, 0u32);
    let mut settled_and_shown = 0;
    loop {
        let roster = carol.vox(None, &["room", "roster", id]);
        let removed = roster.ok && !roster.stdout.contains(&bob_b32);
        let status = carol.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = carol.vox(None, &["room", "read", id]);
        asked += 1;
        refreshing += u32::from(!roster.ok && roster.stderr.contains("refreshing"));
        old_reads += u32::from(read.ok && read.stdout.contains("MP11U-BOB-AFTER"));
        if removed && read.ok && !read.stdout.contains("MP11U-BOB-AFTER") {
            println!(
                "[measure] carol's reconcile at first open: first answered read {:?} after her \
                 daemon started, reconciled rows first shown {:?} after it; of {asked} rounds, \
                 {old_reads} reads answered with the rows as they were and {refreshing} roster \
                 answers said refreshing",
                first_read,
                opened.elapsed()
            );
            break;
        }
        settled_and_shown = if removed && idle && read.ok {
            settled_and_shown + 1
        } else {
            0
        };
        assert!(
            settled_and_shown < 2,
            "PRODUCT [MP11 upgrade]: carol, opened by this vox with nobody writing, reports no \
             governance work queued and still shows bob's posts after the tip alice held: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let check = |w: &Worker, when: &str| {
        mp6_quiet(&[w]);
        let read = setup(w, &["room", "read", id]);
        let lost: Vec<_> = tags
            .iter()
            .filter(|tag| !read.stdout.contains(**tag))
            .collect();
        assert!(
            lost.is_empty(),
            "PRODUCT [MP6 upgrade]: {when}, carol lost {lost:?}, bob's posts alice had read: {}",
            read.stdout
        );
        let now = shown_of(&rt, w, cid, root);
        assert!(
            now.count + 2 == before.count
                && now.count == now.page.len() as u64
                && !now
                    .texts
                    .iter()
                    .any(|text| text.contains("MP11U-BOB-AFTER"))
                && now.replies == 1
                && now.thread.len() == 1
                && now.thread[0].contains(tags[3]),
            "PRODUCT [MP11 upgrade]: {when}, carol's Count must be {} ({} less the two later \
             posts) and equal her newest page, which names neither, and her thread must count \
             and list only bob's reply alice had read: Count {}, page {:?}, replies {}, thread \
             {:?}",
            before.count - 2,
            before.count,
            now.count,
            now.texts,
            now.replies,
            now.thread
        );
        println!(
            "[proof] {when}: carol shows the four posts alice had read and neither later one; \
             Count {} -> {}, thread replies {} -> {}",
            before.count, now.count, before.replies, now.replies
        );
    };
    check(carol, "once this vox opened carol's store");
    let carol = &mut room.workers[2];
    carol.restart_daemon_as(support::VOX, &env, &tmp.path().join("carol-restart.err"));
    let (open, read) = poll(carol, &["room", "read", id], WITHIN, |o| o.ok);
    assert!(
        open,
        "PRODUCT: carol's room did not reopen after a restart: {read:?}"
    );
    check(carol, "after carol's daemon restarted");
}

/// ADR-053 MP-11, a reversal: **a shown row a removal took away comes back, in place, when that
/// removal no longer holds.** alice (creator), bob (an admin alice named), carol (the target)
/// and dave (the reader). alice posts a thread root and carol posts once; bob shows it. bob stops;
/// carol posts once more and replies to the root; alice and dave show both. Every daemon stops.
/// bob, alone, removes carol: his removal names the post of hers he held, so her two later posts
/// are outside its cut. bob stops; alice, alone and unaware of the removal, takes bob's admin away
/// (a creator revocation concurrent with the removal). Then bob and dave run without alice: dave
/// applies the removal and carol's two later posts leave (`MP11 retract`). Then alice runs too:
/// dave receives her revocation, the creator's cutoff invalidates bob's removal
/// (`governance/authority.rs` RootCutoff), carol is a member again, and her two posts come back.
///
/// Asserted on dave: once the removal is applied, the two later posts are gone and Count is two
/// less; once carol is on his roster again, the two come back (`MP11 restore`; the verdict is his
/// state: carol listed, no governance work queued twice in a row, posts still absent), the newest
/// page lists exactly the rows it listed before the removal in the same order, Count, the
/// thread's summary and page, and the unread total are what they were before; the same after
/// dave's daemon restarts.
///
/// `926bba2c3` is red at `MP11 restore` (a retracted row is never restored, and backfill skips a
/// message with a retained cache). Mutant `VOX_MUTANT_MP11_NO_RESTORE` is red at the same.
#[test]
#[ignore = "four real daemons and an anchor, a removal and a concurrent revocation; run in release"]
fn a_post_a_removal_took_away_comes_back_when_the_removal_no_longer_holds() {
    watchdog::arm();
    let mutants = mp11_mutants(&["VOX_MUTANT_MP11_NO_RESTORE"]);
    let env = knob_env(&mutants);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave"]);
    let id = room.id.clone();
    let cid = room.cid;
    let id = id.as_str();
    let [alice, bob, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    setup(alice, &["room", "admin", "add", id, &bob.b32()]);
    let (admin, listed) = poll(bob, &["room", "admin", "list", id], WITHIN, |o| {
        o.ok && o.stdout.contains(&bob.b32())
    });
    assert!(
        admin,
        "APPARATUS: bob's delegation was not staged: {listed:?}"
    );
    dave.restart_daemon_as(support::VOX, &env, &tmp.path().join("dave-mp11r.err"));
    for reader in [&*bob, &*carol, &*dave] {
        mp6_post_until_read(alice, reader, id, "MP11R-READY");
    }
    mp6_quiet(&[alice, bob, carol, dave]);
    setup(alice, &["room", "post", id, "MP11R-ROOT"]);
    let root = posted_root(&rt, alice, cid, "MP11R-ROOT");
    let thread = vox_core::node::link::b32_encode(&root);
    let seen = "MP11R-CAROL-SEEN";
    setup(carol, &["room", "post", id, seen]);
    mp6_all_shown(
        &[bob, dave],
        id,
        &["MP11R-ROOT", seen],
        "carol's first post",
    );
    bob.stop_daemon_cleanly();
    let (later, later_reply) = ("MP11R-CAROL-LATER", "MP11R-CAROL-LATER-REPLY");
    setup(carol, &["room", "post", id, later]);
    setup(
        carol,
        &[
            "room",
            "post",
            id,
            &serde_json::json!({"v":1,"type":"say","hops":8,"body":later_reply,"thread":thread})
                .to_string(),
        ],
    );
    mp6_all_shown(
        &[alice, dave],
        id,
        &[later, later_reply],
        "carol's two later posts",
    );
    mp6_quiet(&[alice, carol, dave]);
    let before = shown_of(&rt, dave, cid, root);
    let (_, unread_before) = sidebar_of(&rt, dave, cid);
    assert!(
        before.replies == 1 && before.thread.len() == 1,
        "APPARATUS: dave's thread did not hold carol's reply: {} {:?}",
        before.replies,
        before.thread
    );
    println!(
        "[proof] dave shows carol's posts: Count {}, thread replies {}, unread {unread_before}",
        before.count, before.replies
    );
    alice.stop_daemon_cleanly();
    carol.stop_daemon_cleanly();
    dave.stop_daemon_cleanly();
    bob.restart_daemon(&tmp.path().join("bob-alone.err"));
    let removal = unchanged_busy_retry(bob, &["room", "remove-member", id, &carol.b32()]);
    assert!(
        removal.ok,
        "PRODUCT (staging): the delegated admin could not remove carol: {removal:?}"
    );
    bob.stop_daemon_cleanly();
    alice.restart_daemon(&tmp.path().join("alice-alone.err"));
    setup(alice, &["room", "admin", "remove", id, &bob.b32()]);
    let (revoked, listed) = poll(alice, &["room", "admin", "list", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&bob.b32())
    });
    assert!(
        revoked,
        "PRODUCT (staging): alice still lists bob as an admin: {listed:?}"
    );
    alice.stop_daemon_cleanly();
    bob.restart_daemon(&tmp.path().join("bob-back.err"));
    dave.restart_daemon_as(support::VOX, &env, &tmp.path().join("dave-removal.err"));
    let mut settled_and_shown = 0;
    loop {
        let roster = dave.vox(None, &["room", "roster", id]);
        let removed = roster.ok && !roster.stdout.contains(&carol.b32());
        let status = dave.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = dave.vox(None, &["room", "read", id]);
        if removed && read.ok && !read.stdout.contains("MP11R-CAROL-LATER") {
            break;
        }
        settled_and_shown = if removed && idle && read.ok {
            settled_and_shown + 1
        } else {
            0
        };
        assert!(
            settled_and_shown < 2,
            "PRODUCT [MP11 retract]: dave applied bob's removal of carol and reports no \
             governance work queued, yet still shows her posts after the one bob held: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    mp6_quiet(&[dave]);
    let retracted = shown_of(&rt, dave, cid, root);
    let read = setup(dave, &["room", "read", id]);
    assert!(
        read.stdout.contains(seen) && retracted.count + 2 == before.count && retracted.replies == 0,
        "PRODUCT [MP11 retract]: once dave applied the removal he must keep carol's post bob \
         held and show two rows fewer, no reply: Count {} (was {}), replies {}: {}",
        retracted.count,
        before.count,
        retracted.replies,
        read.stdout
    );
    println!(
        "[proof] dave applied bob's removal of carol: her two later posts left; Count {} -> {}, \
         thread replies {} -> {}",
        before.count, retracted.count, before.replies, retracted.replies
    );
    alice.restart_daemon(&tmp.path().join("alice-back.err"));
    let mut settled_and_absent = 0;
    loop {
        let roster = dave.vox(None, &["room", "roster", id]);
        let member = roster.ok && roster.stdout.contains(&carol.b32());
        let status = dave.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = dave.vox(None, &["room", "read", id]);
        if member && read.ok && read.stdout.contains(later) && read.stdout.contains(later_reply) {
            break;
        }
        settled_and_absent = if member && idle && read.ok {
            settled_and_absent + 1
        } else {
            0
        };
        assert!(
            settled_and_absent < 2,
            "PRODUCT [MP11 restore]: alice's revocation of bob reached dave and carol is on his \
             roster again, he reports no governance work queued, yet her posts the removal took \
             away are still absent: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let check = |w: &Worker, when: &str| {
        mp6_quiet(&[w]);
        let now = shown_of(&rt, w, cid, root);
        let (_, unread) = sidebar_of(&rt, w, cid);
        assert!(
            now.page == before.page
                && now.count == before.count
                && now.replies == before.replies
                && now.thread == before.thread
                && unread == unread_before,
            "PRODUCT [MP11 restore]: {when}, dave must show exactly the rows he showed before the \
             removal, in the same order, with the same Count, thread and unread: Count {} (was \
             {}), replies {} (was {}), unread {unread} (was {unread_before}), page {:?} (was \
             {:?})",
            now.count,
            before.count,
            now.replies,
            before.replies,
            now.texts,
            before.texts
        );
        println!(
            "[proof] {when}: dave shows carol's two posts again in place; Count {}, thread \
             replies {}, unread {unread}",
            now.count, now.replies
        );
    };
    check(dave, "once the removal no longer held");
    dave.restart_daemon_as(support::VOX, &env, &tmp.path().join("dave-restart.err"));
    let (open, read) = poll(dave, &["room", "read", id], WITHIN, |o| o.ok);
    assert!(
        open,
        "PRODUCT: dave's room did not reopen after a restart: {read:?}"
    );
    check(dave, "after dave's daemon restarted");
}

/// One turn of `vox agent hook` on `w` for `session` in room `id`, as Claude Code's hook runs it:
/// what it injects.
fn hook_turn(w: &Worker, id: &str, session: &str) -> String {
    // Just after a restart the hook can find the room's authorization still refreshing: it then
    // holds the news and its cursor and sends nothing, so the turn is taken again, on exactly
    // that refusal.
    const HELD: &str = "Vox could not read your rooms this turn: room pause state could not be \
                        read; news and its cursor are held: room authorization changed or is \
                        refreshing; nothing was sent";
    let input = format!(r#"{{"session_id":"{session}","cwd":"/tmp"}}"#);
    let deadline = Instant::now() + WITHIN;
    loop {
        let o = w.vox_in(
            None,
            &["agent", "hook", "--node", "default", "--room", &id[..8]],
            Some(&input),
        );
        assert!(
            o.ok,
            "PRODUCT: {}'s `vox agent hook` for session {session} failed: {o:?}",
            w.name
        );
        if o.stdout.trim() != HELD {
            return o.stdout;
        }
        assert!(
            Instant::now() < deadline,
            "NO RESULT: {}'s room authorization was still refreshing after {WITHIN:?}; each turn \
             of session {session} held its news: {o:?}",
            w.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The full entry hash of the row of `w`'s newest page whose text says `tag`.
fn row_hash(rt: &tokio::runtime::Runtime, w: &Worker, cid: [u8; 32], tag: &str) -> String {
    use vox_core::node::ipc::{Frame, Request};
    let Frame::RoomPage { rows, .. } = ipc(
        rt,
        w,
        Request::RoomPage {
            channel_id: cid,
            before: None,
            limit: 64,
        },
    ) else {
        panic!("PRODUCT (staging): {}'s newest page was refused", w.name)
    };
    let row = rows
        .iter()
        .find(|row| row.text.contains(tag))
        .unwrap_or_else(|| panic!("PRODUCT (staging): {} shows no {tag}: {rows:?}", w.name));
    vox_core::node::link::b32_encode(&row.entry_hash)
}

/// A read by one of the room's indexes, in arrival order, as the wire carries it (`ipc.rs`):
/// `Request::Thread` (tag 755) of `root`'s replies, or `Request::Structured` (tag 120) of the
/// room's `say` posts when `root` is `None`; after the message `since`, or after the position
/// `resume` (`(instance, arrival)`, a further field). Built from bytes so this act is the same
/// on a build whose requests carry no position (1b1cd3da8): that build cannot decode one, and
/// the error says so.
fn selected_request(
    cid: [u8; 32],
    root: Option<[u8; 32]>,
    since: Option<&[u8; 32]>,
    resume: Option<([u8; 16], u64)>,
) -> Result<vox_core::node::ipc::Request, String> {
    let mut e = vox_core::cbor::Encoder::new();
    let extra = usize::from(resume.is_some());
    match root {
        Some(root) => {
            e.array(4 + extra).uint(755).bytes(&cid).bytes(&root);
        }
        None => {
            e.array(5 + extra)
                .uint(120)
                .bytes(&cid)
                .array(1)
                .text("say")
                .array(0);
        }
    }
    e.bytes(since.map_or(&[][..], |h| &h[..]));
    if let Some((instance, arrival)) = resume {
        e.array(2).bytes(&instance).uint(arrival);
    }
    vox_core::node::ipc::Request::from_bytes(&e.finish()).map_err(|e| e.to_string())
}

/// `w`'s saved instance of the room and its newest arrival, as `vox room read` prints a position
/// (`@<arrival>:<instance>`).
fn arrival_head(rt: &tokio::runtime::Runtime, w: &Worker, cid: [u8; 32]) -> ([u8; 16], String) {
    use vox_core::node::ipc::{Frame, Request};
    let Frame::ArrivalHead { head } = ipc(rt, w, Request::ArrivalHead { channel_id: cid }) else {
        panic!("PRODUCT (staging): {}'s arrival head was refused", w.name)
    };
    let hex: String = head.instance.iter().map(|b| format!("{b:02x}")).collect();
    (head.instance, format!("@{}:{hex}", head.arrival))
}

/// Every row `w` holds of the room, by arrival: `(arrival, text)`.
fn arrivals_of(rt: &tokio::runtime::Runtime, w: &Worker, cid: [u8; 32]) -> Vec<(u64, String)> {
    use vox_core::node::ipc::{Frame, Request};
    let (instance, _) = arrival_head(rt, w, cid);
    let mut after = vox_core::node::api::HistoryCursor {
        instance,
        arrival: 0,
    };
    let mut all = Vec::new();
    loop {
        let page = ipc(
            rt,
            w,
            Request::ArrivalPage {
                channel_id: cid,
                after,
            },
        );
        let Frame::ArrivalPage { rows, next, .. } = page else {
            panic!(
                "PRODUCT [MP11 high water]: {}'s rows by arrival could not be read: {page:?}",
                w.name
            )
        };
        all.extend(rows.into_iter().map(|r| (r.arrival, r.text)));
        match next {
            Some(next) if next.arrival > after.arrival => after = next,
            _ => return all,
        }
    }
}

/// A running `vox room tail` of a worker: what it printed, line by line, and its stderr file.
/// Killed and reaped when dropped, by its own handle.
struct Tailing {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
    err: std::path::PathBuf,
}

impl Drop for Tailing {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Tailing {
    /// What it printed once that holds `done`, waiting at most `within`; otherwise (it exited, or
    /// printed something else) an error with everything it printed.
    fn printed(&self, within: Duration, done: impl Fn(&str) -> bool) -> Result<String, String> {
        let deadline = Instant::now() + within;
        let mut seen = String::new();
        while Instant::now() < deadline {
            match self.lines.recv_timeout(Duration::from_millis(250)) {
                Ok(line) => {
                    seen.push_str(&line);
                    if done(&seen) {
                        return Ok(seen);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Err(seen)
    }

    /// Its stderr once it has exited, waiting at most `within`; `None` while it still runs.
    fn stopped(&mut self, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return Some(std::fs::read_to_string(&self.err).unwrap_or_default());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }
}

/// `vox room tail <id> --since <since>` on `w`, with `env`, its stderr in `err`. Its stdout is
/// read line by line; with `close_once`, the read ends, and the pipe is closed, as soon as what
/// it printed holds that: the next row the tail prints then fails, and it stops.
fn tail_from(
    w: &Worker,
    id: &str,
    since: &str,
    env: &[(&str, &str)],
    err: &std::path::Path,
    close_once: Option<fn(&str) -> bool>,
) -> Tailing {
    use std::io::BufRead as _;
    let mut cmd = std::process::Command::new(support::VOX);
    cmd.args(["room", "tail", id, "--since", since])
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(
            std::fs::File::create(err).expect("APPARATUS: cannot create the tail's stderr file"),
        );
    support::strip_harness_env(&mut cmd);
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox room tail: {e}"));
    let mut out = std::io::BufReader::new(
        child
            .stdout
            .take()
            .expect("APPARATUS: the tail was spawned without a stdout pipe"),
    );
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        loop {
            let mut line = String::new();
            match out.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    seen.push_str(&line);
                    if tx.send(line).is_err() || close_once.is_some_and(|done| done(&seen)) {
                        return;
                    }
                }
            }
        }
    });
    Tailing {
        child,
        lines,
        err: err.to_owned(),
    }
}

/// The `--since` of the command a stopped `vox room tail` printed to resume with, if any.
fn resume_since(said: &str) -> Option<String> {
    let command = said.split("resume with").nth(1)?;
    command
        .split("--since ")
        .nth(1)?
        .split_whitespace()
        .next()
        .map(|token| token.trim_matches(['\'', '"', '`']).to_owned())
}

/// Every one of `others` reports bob (`bob_fp`) disconnected in room `id`: carol posts once every
/// other node has seen bob go. While their connections to him are still closing, dave was once
/// not offered her posts at all (fix3 `runs/n-first.log`).
fn mp11n_bob_gone(others: &[&Worker], bob_fp: &str, id: &str) {
    for w in others {
        let (gone_from, status) = poll(w, &["status", "--json"], WITHIN, |o| {
            o.ok && o.json()["rooms"].as_array().is_some_and(|rooms| {
                rooms.iter().filter(|r| r["id"] == id).any(|r| {
                    r["members"].as_array().is_some_and(|members| {
                        members
                            .iter()
                            .any(|m| m["id"] == bob_fp && m["connected"] == false)
                    })
                })
            })
        });
        assert!(
            gone_from,
            "APPARATUS: {} still reports bob connected after his daemon stopped: {status:?}",
            w.name
        );
    }
}

/// Stage the removal that takes carol's later posts away on dave and the revocation that brings
/// them back, as `a_post_a_removal_took_away_comes_back_when_the_removal_no_longer_holds` does:
/// bob, a delegated admin, removes carol while alice, carol and dave are stopped; alice, alone,
/// takes bob's admin away; dave, restarted with `env`, applies bob's removal first. Returns once
/// dave shows `kept` and not `gone`. Each of alice, bob, carol and dave runs on entry, bob only
/// on return.
fn mp11n_removed(
    workers: &mut [Worker],
    id: &str,
    env: &[(&str, &str)],
    tmp: &std::path::Path,
    kept: &str,
    gone: &str,
) {
    let [alice, bob, carol, dave] = workers else {
        unreachable!()
    };
    alice.stop_daemon_cleanly();
    carol.stop_daemon_cleanly();
    dave.stop_daemon_cleanly();
    bob.restart_daemon(&tmp.join("bob-alone.err"));
    let removal = unchanged_busy_retry(bob, &["room", "remove-member", id, &carol.b32()]);
    assert!(
        removal.ok,
        "PRODUCT (staging): the delegated admin could not remove carol: {removal:?}"
    );
    bob.stop_daemon_cleanly();
    alice.restart_daemon(&tmp.join("alice-alone.err"));
    setup(alice, &["room", "admin", "remove", id, &bob.b32()]);
    let (revoked, listed) = poll(alice, &["room", "admin", "list", id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&bob.b32())
    });
    assert!(
        revoked,
        "PRODUCT (staging): alice still lists bob as an admin: {listed:?}"
    );
    alice.stop_daemon_cleanly();
    bob.restart_daemon(&tmp.join("bob-back.err"));
    dave.restart_daemon_as(support::VOX, env, &tmp.join("dave-removal.err"));
    let mut settled_and_shown = 0;
    loop {
        let roster = dave.vox(None, &["room", "roster", id]);
        let removed = roster.ok && !roster.stdout.contains(&carol.b32());
        let status = dave.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = dave.vox(None, &["room", "read", id]);
        if removed && read.ok && read.stdout.contains(kept) && !read.stdout.contains(gone) {
            return;
        }
        settled_and_shown = if removed && idle && read.ok {
            settled_and_shown + 1
        } else {
            0
        };
        assert!(
            settled_and_shown < 2,
            "PRODUCT [MP11 retract]: dave applied bob's removal of carol and reports no \
             governance work queued, yet does not show exactly her post bob held: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// alice, back, brings the revocation to dave: returns once dave shows `gone` again.
fn mp11n_returned(
    alice: &mut Worker,
    carol: &Worker,
    dave: &Worker,
    id: &str,
    tmp: &std::path::Path,
    gone: &str,
) {
    alice.restart_daemon(&tmp.join("alice-back.err"));
    let mut settled_and_absent = 0;
    loop {
        let roster = dave.vox(None, &["room", "roster", id]);
        let member = roster.ok && roster.stdout.contains(&carol.b32());
        let status = dave.vox(None, &["status", "--json"]);
        let idle = status.ok && status.json()["governance_pending"] == false;
        let read = dave.vox(None, &["room", "read", id]);
        if member && read.ok && read.stdout.contains(gone) {
            return;
        }
        settled_and_absent = if member && idle && read.ok {
            settled_and_absent + 1
        } else {
            0
        };
        assert!(
            settled_and_absent < 2,
            "PRODUCT [MP11 restore]: alice's revocation of bob reached dave and carol is on his \
             roster again, he reports no governance work queued, yet her post the removal took \
             away is still absent: {}",
            read.stdout
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// ADR-053 MP-11, candidate N (review of #1393, `ruling-n.md`): **a message a removal took away
/// that comes back arrives again**, and no reader skips what arrived while it was away.
///
/// Staging as `a_post_a_removal_took_away_comes_back_when_the_removal_no_longer_holds`. alice
/// posts a thread root; carol posts once, then ten more, a reply in the thread and M. dave's
/// agent session "unseen" reads before M; "trap" is given M as the last thing it reads; a script
/// reads on, a row at a time, from carol's first post through her reply and M, and keeps M's hash
/// and the position `vox room read` prints for its next page. bob's removal of carol takes M
/// away on dave, with the ten and her reply; bob then replies H in the thread, and "unseen"
/// reads it ("trap" does not); alice's revocation brings them back. Before M goes, dave reads
/// page 1 of the thread's replies and of the room's `say` posts by their indexes, each ending at
/// carol's reply. Asserted on dave:
/// - M is in its place in `vox room read` and in its thread, before H (`MP11 in place`,
///   `MP11 thread`);
/// - page 2 of each read, from the position page 1 ended at, gives bob's reply, which arrived
///   between, and carol's again; from carol's reply's hash, it is refused (`MP11 thread page`,
///   `MP11 filtered page`);
/// - a `vox room tail` from the script's position prints H and carol's posts that came back,
///   last; its output closed, dave's next post stops it, and the command it prints resumes it
///   with that post first (`MP11 tail resume`);
/// - a post dave makes after the return is shown beside M (`MP11 allocator`: the arrival M took
///   is not given out again), and, in the same process, takes an arrival after every one of
///   carol's posts that came back, that no other row has; a reader from the script's position
///   is given H, M and the post once each (`MP11 high water`);
/// - a `vox room tail` from dave's newest position, stopped by his node before it printed
///   anything, prints that position to resume from (`MP11 tail position`);
/// - after dave's daemon restarts, before either session's next turn: M once, in place
///   (`MP11 restart`); "unseen", which never got M, is told it once (`MP11 arrives again`);
///   "trap", whose position was M, is given H and M once each, H not skipped (`MP11 cursor`),
///   and nothing of them again (`MP11 once`);
/// - a cursor file the previous build wrote (a message id) is read once and saved as a
///   position: one naming carol's first post gives H and M once each; one naming M says M came
///   back and starts again from the room's first message, bounded like any turn (`MP11 old
///   cursor`);
/// - the script's hash of M is refused in plain words, no rows (`MP11 script hash`); the
///   position it was printed gives H and M once each (`MP11 script position`);
/// - a post after the restart is given once, and M not again (`MP11 allocator`).
///
/// Each claim is asserted where it is made, so a later stop cannot hide an earlier red.
/// `de48c97ee` (M comes back at its old arrival) is red at `MP11 arrives again`; `1b1cd3da8`
/// (pages and the tail's resume continue by hash) at the page and tail claims. Mutants, each red
/// at its claim: `VOX_MUTANT_MP11_SAME_ARRIVAL` (M comes back at its old arrival) at `MP11 thread
/// page`, the first claim that needs carol's reply to arrive again (page 2 from the position
/// does not give it); `VOX_MUTANT_MP11_HASH_CURSOR` (the hook keeps a hash and the node answers
/// it by M's new arrival) at `MP11 cursor`; `VOX_MUTANT_MP11_THREAD_ARRIVAL` (thread pages by
/// arrival) at `MP11 thread`; `VOX_MUTANT_MP11_FILTERED_HASH` (a filtered or thread read from a
/// message that came back is answered from its new arrival) at `MP11 thread page`, from the
/// hash; `VOX_MUTANT_MP11_NO_HIGH_WATER` (the governance turn's allocator advance is not
/// installed) at `MP11 high water`.
#[test]
#[ignore = "four real daemons and an anchor, a removal and a concurrent revocation; run in release"]
fn a_message_that_comes_back_arrives_again_and_no_reader_skips_what_came_meanwhile() {
    watchdog::arm();
    let mutants = mp11_mutants(&[
        "VOX_MUTANT_MP11_SAME_ARRIVAL",
        "VOX_MUTANT_MP11_HASH_CURSOR",
        "VOX_MUTANT_MP11_THREAD_ARRIVAL",
        "VOX_MUTANT_MP11_NO_HIGH_WATER",
        "VOX_MUTANT_MP11_FILTERED_HASH",
    ]);
    let env = knob_env(&mutants);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave"]);
    let id = room.id.clone();
    let cid = room.cid;
    let id = id.as_str();
    {
        let [alice, bob, carol, dave] = &mut room.workers[..] else {
            unreachable!()
        };
        setup(alice, &["room", "admin", "add", id, &bob.b32()]);
        let (admin, listed) = poll(bob, &["room", "admin", "list", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&bob.b32())
        });
        assert!(
            admin,
            "APPARATUS: bob's delegation was not staged: {listed:?}"
        );
        dave.restart_daemon_as(support::VOX, &env, &tmp.path().join("dave-mp11n.err"));
        for reader in [&*bob, &*carol, &*dave] {
            mp6_post_until_read(alice, reader, id, "MP11N-READY");
        }
        mp6_quiet(&[alice, bob, carol, dave]);
    }
    let [alice, bob, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    setup(alice, &["room", "post", id, "MP11N-ROOT"]);
    let root = posted_root(&rt, alice, cid, "MP11N-ROOT");
    let thread = vox_core::node::link::b32_encode(&root);
    let reply = |body: &str| {
        serde_json::json!({"v":1,"type":"say","hops":8,"body":body,"thread":thread}).to_string()
    };
    let seen = "MP11N-CAROL-SEEN";
    setup(carol, &["room", "post", id, seen]);
    mp6_all_shown(
        &[bob, dave],
        id,
        &["MP11N-ROOT", seen],
        "carol's first post",
    );
    mp6_quiet(&[alice, bob, carol, dave]);
    let first = hook_turn(dave, id, "mp11n-unseen");
    assert!(
        first.contains(seen),
        "PRODUCT (staging): dave's session \"unseen\" was not told carol's first post: {first}"
    );
    bob.stop_daemon_cleanly();
    mp11n_bob_gone(&[alice, carol, dave], &bob.b32(), id);
    // carol posts ten more, replies in alice's thread, then posts M: an agent session is told M,
    // and is not shown replies in threads it is not in, so M is the last thing "trap" is given.
    // dave may take them in one window, and then M arrives first: nothing here depends on their
    // order. All twelve go and come back: the arrivals they come back at are more than the
    // control entries dave takes after them, so a post of his from an allocator that was not
    // advanced past them lands on one (`MP11 high water`).
    let (gone, gone_reply) = ("MP11N-CAROL-GONE", "MP11N-CAROL-REPLY");
    let extras: Vec<String> = (0..10).map(|i| format!("MP11N-CAROL-X{i}")).collect();
    for extra in &extras {
        setup(carol, &["room", "post", id, extra]);
    }
    setup(carol, &["room", "post", id, &reply(gone_reply)]);
    setup(carol, &["room", "post", id, gone]);
    let mut came_back: Vec<&str> = extras.iter().map(String::as_str).collect();
    came_back.extend([gone_reply, gone]);
    mp6_all_shown(
        &[alice, dave],
        id,
        &came_back,
        "carol's posts, her reply and M",
    );
    mp6_quiet(&[alice, carol, dave]);
    let had = hook_turn(dave, id, "mp11n-trap");
    assert!(
        had.matches(gone).count() == 1,
        "PRODUCT (staging): dave's session \"trap\" was not given M once: {had}"
    );
    let seen_hash = row_hash(&rt, dave, cid, seen);
    let gone_hash = row_hash(&rt, dave, cid, gone);
    // The script reads one row at a time from carol's first post, as each page tells it to go
    // on, until it has read her reply and M; it keeps where it was told to continue. What dave
    // took after carol's first post besides them (a late post of alice's) is read on the way.
    let (mut next_page, mut read) = (seen_hash.clone(), String::new());
    for _ in 0..64 {
        if read.contains(gone_reply) && read.contains(gone) {
            break;
        }
        let page = setup(
            dave,
            &["room", "read", id, "--since", &next_page, "--limit", "1"],
        );
        next_page = page
            .stderr
            .split("--since ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .map(|token| token.trim_matches(['\'', '"', '`']).to_owned())
            .unwrap_or_else(|| {
                panic!("PRODUCT (staging): the script's page printed no next page: {page:?}")
            });
        read.push_str(&page.stdout);
    }
    assert!(
        read.contains(gone_reply) && read.contains(gone),
        "PRODUCT (staging): reading on from carol's first post, the script never read her reply \
         and M: {read}"
    );
    println!(
        "[proof] dave's session \"trap\" was given M last; a script read on from carol's first \
         post through her reply and M, and was told to continue from {next_page}:\n{read}"
    );
    // Page 1 of two reads by the room's indexes in arrival order, before M goes: the thread's
    // replies (`Request::Thread`) and the room's `say` posts (`Request::Structured`). Each ends
    // at carol's reply, which goes and comes back while bob's reply arrives.
    let (instance, _) = arrival_head(&rt, dave, cid);
    // (which read, its thread root if any, the hash page 1 ended at, the position after it)
    type FirstPage<'a> = (&'a str, Option<[u8; 32]>, [u8; 32], u64);
    let first_pages: Vec<FirstPage<'_>> = [("thread", Some(root)), ("filtered", None)]
        .into_iter()
        .map(|(what, of)| {
            let request = selected_request(cid, of, None, None)
                .unwrap_or_else(|e| panic!("APPARATUS: a first {what} page: {e}"));
            let vox_core::node::ipc::Frame::Rows { rows } = ipc(&rt, dave, request) else {
                panic!("PRODUCT (staging): dave's first {what} page was refused")
            };
            let last = rows
                .last()
                .filter(|r| r.text.contains(gone_reply))
                .unwrap_or_else(|| {
                    panic!(
                        "PRODUCT (staging): dave's first {what} page must end at carol's \
                             reply: {rows:?}"
                    )
                });
            (what, of, last.entry_hash, last.arrival)
        })
        .collect();
    mp11n_removed(&mut room.workers, id, &env, tmp.path(), seen, gone);
    let [alice, bob, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    let (meanwhile, meanwhile_reply) = ("MP11N-BOB-MEANWHILE", "MP11N-BOB-REPLY");
    setup(bob, &["room", "post", id, &reply(meanwhile_reply)]);
    setup(bob, &["room", "post", id, meanwhile]);
    mp6_all_shown(
        &[dave],
        id,
        &[meanwhile_reply, meanwhile],
        "bob's reply and H while M was away",
    );
    mp6_quiet(&[bob, dave]);
    let away = hook_turn(dave, id, "mp11n-unseen");
    assert!(
        away.contains(meanwhile) && !away.contains(gone),
        "PRODUCT (staging): while M was away, dave's session \"unseen\" must be told H and not \
         M: {away}"
    );
    println!("[proof] while M was away, H arrived; \"unseen\" read it, \"trap\" did not");
    mp11n_returned(alice, carol, dave, id, tmp.path(), gone);
    mp6_quiet(&[alice, bob, dave]);
    let in_place = |w: &Worker, claim: &str, when: &str| {
        let read = w.vox(None, &["room", "read", id]);
        let (m, h) = (read.stdout.find(gone), read.stdout.find(meanwhile));
        assert!(
            read.ok
                && read.stdout.matches(gone).count() == 1
                && matches!((m, h), (Some(m), Some(h)) if m < h),
            "PRODUCT [{claim}]: {when}, dave's `vox room read` must show M once, in its place \
             before H: {read:?}"
        );
    };
    in_place(dave, "MP11 in place", "once M came back");
    let shown = shown_of(&rt, dave, cid, root);
    let at = |tag: &str| shown.thread.iter().position(|text| text.contains(tag));
    assert!(
        shown.replies == 2
            && matches!((at(gone_reply), at(meanwhile_reply)), (Some(m), Some(h)) if m < h),
        "PRODUCT [MP11 thread]: once carol's reply came back, dave's thread must list it in its \
         place before bob's: replies {}, thread {:?}",
        shown.replies,
        shown.thread
    );
    println!(
        "[proof] M came back in its place before H, and carol's reply before bob's in the thread"
    );
    // Page 2 of each read, after carol's reply came back with bob's arriving meanwhile: from the
    // position page 1 ended at, bob's reply and hers again (she arrived again); from the hash a
    // reader of page 1 held, refused (it would be answered from her reply's new arrival, past
    // bob's).
    for &(what, of, boundary, arrival) in &first_pages {
        let count = |rows: &[vox_core::node::api::MessageRow], tag: &str| {
            rows.iter().filter(|r| r.text.contains(tag)).count()
        };
        let request =
            selected_request(cid, of, None, Some((instance, arrival))).unwrap_or_else(|e| {
                panic!(
                    "PRODUCT [MP11 {what} page]: this vox takes no position to continue a {what} \
                     read (`Request::from_bytes`: {e}), so its page 2 can only follow a hash"
                )
            });
        match ipc(&rt, dave, request) {
            vox_core::node::ipc::Frame::Rows { rows }
                if count(&rows, meanwhile_reply) == 1 && count(&rows, gone_reply) == 1 => {}
            other => panic!(
                "PRODUCT [MP11 {what} page]: page 2 of dave's {what} read from the position page 1 \
                 ended at must give bob's reply, which arrived between, and carol's again: \
                 {other:?}"
            ),
        }
        let request = selected_request(cid, of, Some(&boundary), None)
            .unwrap_or_else(|e| panic!("APPARATUS: a {what} page from a hash: {e}"));
        match ipc(&rt, dave, request) {
            vox_core::node::ipc::Frame::Error { reason }
                if reason.ends_with(vox_core::node::ipc::CAME_BACK) =>
            {
                println!(
                    "[proof] page 2 of dave's {what} read from where page 1 ended gave bob's \
                     reply and carol's again; from her hash it was refused"
                );
            }
            vox_core::node::ipc::Frame::Rows { rows } => panic!(
                "PRODUCT [MP11 {what} page]: carol's reply ended page 1 of dave's {what} read, \
                 went and came back while bob's reply arrived; page 2 from its hash must be \
                 refused, yet was answered, giving bob's reply {} times (0: skipped): {:?}",
                count(&rows, meanwhile_reply),
                rows.iter().map(|r| &r.text).collect::<Vec<_>>()
            ),
            other => panic!(
                "PRODUCT [MP11 {what} page]: page 2 of dave's {what} read from the hash of carol's \
                 reply, which came back, must be refused in plain words: {other:?}"
            ),
        }
    }
    // A tail from the script's position prints H, bob's reply and carol's posts that came back,
    // last. Its output is closed then, so the next row it takes (dave's post below) stops it, and
    // it prints the command that resumes it.
    let closed_err = tmp.path().join("dave-tail-closed.err");
    let returned_last = |seen: &str| {
        seen.matches("MP11N-CAROL-X").count() == 10
            && [
                "MP11N-BOB-MEANWHILE",
                "MP11N-CAROL-GONE",
                "MP11N-CAROL-REPLY",
            ]
            .iter()
            .all(|tag| seen.contains(tag))
    };
    let mut closed = tail_from(dave, id, &next_page, &[], &closed_err, Some(returned_last));
    let tailed = closed.printed(WITHIN, returned_last);
    assert!(
        tailed.is_ok(),
        "PRODUCT [MP11 tail]: dave's `vox room tail --since {next_page}`, a position from before \
         carol's posts came back, did not print H and the posts of carol's that came back (they \
         must arrive again, after that position): {tailed:?}; stderr {}",
        std::fs::read_to_string(&closed_err).unwrap_or_default()
    );
    let after = "MP11N-DAVE-Q";
    setup(dave, &["room", "post", id, after]);
    // The high-water mark: dave's post, made in this process after carol's posts came back,
    // takes an arrival from the allocator they took theirs from, after all of them, that no
    // other row has; a reader continuing from before is given H, M and the post once each.
    let arrivals = arrivals_of(&rt, dave, cid);
    let at = |tag: &str| {
        arrivals
            .iter()
            .filter(|(_, text)| text.contains(tag))
            .map(|(arrival, _)| *arrival)
            .collect::<Vec<_>>()
    };
    let mut distinct: Vec<u64> = arrivals.iter().map(|(arrival, _)| *arrival).collect();
    distinct.sort_unstable();
    distinct.dedup();
    let returned: Vec<(&str, Vec<u64>)> = came_back.iter().map(|tag| (*tag, at(tag))).collect();
    let q = at(after);
    println!(
        "[proof] dave's arrivals once carol's posts came back and he posted: came back \
         {returned:?}, his post {q:?}; all {:?}",
        arrivals
            .iter()
            .map(|(arrival, text)| (*arrival, text.chars().take(24).collect::<String>()))
            .collect::<Vec<_>>()
    );
    let after_all = |q: &u64| {
        returned
            .iter()
            .all(|(_, at)| matches!(at.as_slice(), [a] if a < q))
    };
    assert!(
        matches!(q.as_slice(), [q] if after_all(q)) && distinct.len() == arrivals.len(),
        "PRODUCT [MP11 high water]: dave posted in the process carol's posts came back in; his \
         post must arrive after every one of them, at an arrival no other row has: came back \
         {returned:?}, his post {q:?}, {} arrivals for {} rows",
        distinct.len(),
        arrivals.len()
    );
    let continuing = dave.vox(None, &["room", "read", id, "--since", &next_page]);
    assert!(
        continuing.ok
            && [meanwhile, gone, after]
                .iter()
                .all(|tag| continuing.stdout.matches(tag).count() == 1),
        "PRODUCT [MP11 high water]: continuing from the script's position, dave's reader must be \
         given H, M and his post once each: {continuing:?}"
    );
    let both = dave.vox(None, &["room", "read", id]);
    assert!(
        both.ok && both.stdout.matches(gone).count() == 1 && both.stdout.contains(after),
        "PRODUCT [MP11 allocator]: dave posted after M came back; he must show M and his post: \
         {both:?}"
    );
    // The tail whose output was closed stopped at dave's post; the command it printed resumes it
    // from the last post it printed, one that came back: it prints dave's post first.
    match closed.stopped(WITHIN) {
        None => panic!(
            "APPARATUS: the tail whose output was closed did not stop when dave's post arrived"
        ),
        Some(said) => match resume_since(&said) {
            None => panic!(
                "PRODUCT [MP11 tail resume]: a tail stopped after printing a post that came back \
                 must print a command that resumes it from there: {said}"
            ),
            Some(since) => {
                let resumed = tail_from(
                    dave,
                    id,
                    &since,
                    &[],
                    &tmp.path().join("dave-tail-resumed.err"),
                    None,
                );
                match resumed.printed(WITHIN, |seen| seen.contains(after)) {
                    Ok(seen) if seen.lines().next().is_some_and(|l| l.contains(after)) => {
                        println!(
                            "[proof] the tail stopped after carol's post that came back printed \
                             `--since {since}`; that resumed with dave's post first"
                        );
                    }
                    printed => panic!(
                        "PRODUCT [MP11 tail resume]: the tail stopped after printing a post that \
                         came back said to resume with `--since {since}`; that must print \
                         dave's post, the row it stopped at, first: {printed:?}; stderr {}",
                        std::fs::read_to_string(&resumed.err).unwrap_or_default()
                    ),
                }
            }
        },
    }
    // A tail from a position that has delivered nothing when its node stops prints that
    // position. `VOX_TEST_TAIL_HOLD_MS=0` says when it has subscribed.
    test_knobs::require(&["VOX_TEST_TAIL_HOLD_MS"]);
    let (_, head) = arrival_head(&rt, dave, cid);
    let idle_err = tmp.path().join("dave-tail-idle.err");
    let mut idle = tail_from(
        dave,
        id,
        &head,
        &[("VOX_TEST_TAIL_HOLD_MS", "0")],
        &idle_err,
        None,
    );
    let deadline = Instant::now() + WITHIN;
    while !std::fs::read_to_string(&idle_err)
        .unwrap_or_default()
        .contains("tail holding")
    {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: dave's tail from {head} never said it subscribed: {}",
            std::fs::read_to_string(&idle_err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    dave.stop_daemon_cleanly();
    match idle.stopped(WITHIN) {
        None => panic!("APPARATUS: dave's tail from {head} did not stop when his node stopped"),
        Some(said) if resume_since(&said).as_deref() == Some(head.as_str()) => println!(
            "[proof] a tail from {head} that printed nothing stopped with its node and printed \
             that position to resume from"
        ),
        Some(said) => panic!(
            "PRODUCT [MP11 tail position]: a tail from {head} that printed nothing, stopped by its \
             node, must print `--since {head}` to resume from: {said}"
        ),
    }
    drop(idle);
    dave.restart_daemon_as(support::VOX, &env, &tmp.path().join("dave-restart.err"));
    let (open, reopened) = poll(dave, &["room", "read", id], WITHIN, |o| o.ok);
    assert!(
        open,
        "PRODUCT: dave's room did not reopen after a restart: {reopened:?}"
    );
    in_place(dave, "MP11 restart", "after dave's daemon restarted");
    let unseen = hook_turn(dave, id, "mp11n-unseen");
    assert!(
        unseen.matches(gone).count() == 1 && !unseen.contains(meanwhile),
        "PRODUCT [MP11 arrives again]: M came back on dave, and his session \"unseen\" never got \
         it, yet its next turn told it {} times (H {} times): {unseen}",
        unseen.matches(gone).count(),
        unseen.matches(meanwhile).count()
    );
    let trap = hook_turn(dave, id, "mp11n-trap");
    assert!(
        trap.matches(meanwhile).count() == 1 && trap.matches(gone).count() == 1,
        "PRODUCT [MP11 cursor]: dave's session \"trap\" was last given M; M went, H arrived \
         unread and M came back: its next turn must give H and M once each, yet gave H {} times \
         and M {} times: {trap}",
        trap.matches(meanwhile).count(),
        trap.matches(gone).count()
    );
    let again = hook_turn(dave, id, "mp11n-trap");
    assert!(
        !again.contains(gone) && !again.contains(meanwhile),
        "PRODUCT [MP11 once]: dave's session \"trap\" was given H or M again: {again}"
    );
    println!(
        "[proof] after dave's restart: \"unseen\" was told M once; \"trap\" was given H and M \
         once each (M a second time: it came back), then neither again"
    );
    // A cursor file the previous build wrote holds a message id. One naming carol's first post
    // (never taken away) is read once by hash and saved as a position: the turn gives what came
    // after it, H and M. One naming M, which came back, says so and starts again from the room's
    // first message, bounded like any turn.
    let room_key = vox_core::node::link::b32_encode(&cid);
    let legacy = |session: &str, hash: &str| {
        let file = dave.paths.cursor_file(&room_key, session);
        std::fs::write(&file, format!("{hash}\n"))
            .expect("APPARATUS: cannot write a previous build's cursor file");
        let out = hook_turn(dave, id, session);
        let saved = std::fs::read_to_string(&file).unwrap_or_default();
        (out, saved)
    };
    let (kept, kept_saved) = legacy("mp11n-legacy-kept", &seen_hash);
    assert!(
        kept.matches(meanwhile).count() == 1
            && kept.matches(gone).count() == 1
            && !kept.contains("harness: ready")
            && !kept.contains("was not found")
            && kept_saved.starts_with('@'),
        "PRODUCT [MP11 old cursor]: a previous build's cursor naming carol's first post must \
         give H and M once each, not the room's first messages, and be saved as a position: \
         {kept_saved:?} {kept}"
    );
    let (back, back_saved) = legacy("mp11n-legacy-back", &gone_hash);
    let said = back.find(
        "(Your read position in this room was not found — this message came back after it was \
         taken away",
    );
    let first_row = back
        .lines()
        .find(|l| l.starts_with('['))
        .and_then(|l| back.find(l));
    assert!(
        matches!((said, first_row), (Some(s), Some(r)) if s < r)
            && back.contains("so this starts again from the room's first message.)")
            && back.contains("harness: ready")
            && back.matches(meanwhile).count() == 1
            && back.matches(gone).count() == 1
            && back_saved.starts_with('@'),
        "PRODUCT [MP11 old cursor]: a previous build's cursor naming M, which came back, must say \
         so before the room's first message and start from there, H and M once each, and be \
         saved as a position: {back_saved:?} {back}"
    );
    println!(
        "[proof] previous build's cursors: carol's first post read once by hash, saved as {}; \
         M's said it came back and started again from the room's first message, saved as {}:\n{back}",
        kept_saved.lines().next().unwrap_or_default(),
        back_saved.lines().next().unwrap_or_default()
    );
    let by_hash = dave.vox(None, &["room", "read", id, "--since", &gone_hash]);
    assert!(
        !by_hash.ok
            && by_hash.stderr.contains(
                "this message came back after it was taken away; its place in arrival moved; \
                 continue from the position printed with the last page",
            )
            && !by_hash.stdout.contains(gone)
            && !by_hash.stdout.contains(meanwhile),
        "PRODUCT [MP11 script hash]: a script holding M's hash must be refused in plain words, \
         with no rows: {by_hash:?}"
    );
    let by_position = dave.vox(None, &["room", "read", id, "--since", &next_page]);
    assert!(
        by_position.ok
            && by_position.stdout.matches(meanwhile).count() == 1
            && by_position.stdout.matches(gone).count() == 1,
        "PRODUCT [MP11 script position]: continuing from the position printed with its page, a \
         script that read M must get H and M once each: {by_position:?}"
    );
    println!(
        "[proof] the script's hash of M was refused: {:?}; its printed position gave H and M",
        by_hash.stderr.trim()
    );
    let later = "MP11N-BOB-P";
    setup(bob, &["room", "post", id, later]);
    mp6_all_shown(&[dave], id, &[later], "bob's post after dave's restart");
    let next = hook_turn(dave, id, "mp11n-trap");
    assert!(
        next.matches(later).count() == 1 && !next.contains(gone) && !next.contains(meanwhile),
        "PRODUCT [MP11 allocator]: a post after dave's restart must be given once after M, and \
         M not again: {next}"
    );
    println!("[proof] a post after the restart was given once, after M; M not again");
}

/// ADR-053 MP-11, candidate N: **a message that comes back keeps its original lifetime.** dave
/// keeps messages 150 s (`retention`, his node's file). carol posts M; alice then posts C, so C
/// expires after M on dave. bob's removal takes M away on dave and alice's revocation brings it
/// back, before C expires. Asserted (`MP11 lifetime`): once dave no longer shows C, he no longer
/// shows M. The verdict is that order, not a time: if C is gone before M comes back, the act
/// cannot stage (APPARATUS). Mutant `VOX_MUTANT_MP11_FRESH_LIFETIME` (a returned row's age runs
/// from its return) is red at `MP11 lifetime`.
#[test]
#[ignore = "four real daemons and an anchor, a removal, a revocation and a short retention"]
fn a_message_that_comes_back_keeps_its_original_lifetime() {
    watchdog::arm();
    let mutants = mp11_mutants(&["VOX_MUTANT_MP11_FRESH_LIFETIME"]);
    let env = knob_env(&mutants);
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob", "carol", "dave"]);
    let id = room.id.clone();
    let id = id.as_str();
    {
        let [alice, bob, carol, dave] = &mut room.workers[..] else {
            unreachable!()
        };
        setup(alice, &["room", "admin", "add", id, &bob.b32()]);
        let (admin, listed) = poll(bob, &["room", "admin", "list", id], WITHIN, |o| {
            o.ok && o.stdout.contains(&bob.b32())
        });
        assert!(
            admin,
            "APPARATUS: bob's delegation was not staged: {listed:?}"
        );
        std::fs::write(dave.paths.retention_file(), "default 150\n")
            .expect("APPARATUS: cannot write dave's retention");
        dave.restart_daemon_as(support::VOX, &env, &tmp.path().join("dave-mp11l.err"));
        for reader in [&*bob, &*carol, &*dave] {
            mp6_post_until_read(alice, reader, id, "MP11L-READY");
        }
        mp6_quiet(&[alice, bob, carol, dave]);
        bob.stop_daemon_cleanly();
    }
    let gone = "MP11L-CAROL-M";
    let control = "MP11L-ALICE-C";
    {
        let [alice, _, carol, dave] = &mut room.workers[..] else {
            unreachable!()
        };
        setup(carol, &["room", "post", id, gone]);
        mp6_all_shown(&[alice, dave], id, &[gone], "carol's M");
        setup(alice, &["room", "post", id, control]);
        mp6_all_shown(&[dave], id, &[control], "alice's C, after M");
        mp6_quiet(&[alice, carol, dave]);
    }
    mp11n_removed(&mut room.workers, id, &env, tmp.path(), control, gone);
    let [alice, _, carol, dave] = &mut room.workers[..] else {
        unreachable!()
    };
    mp11n_returned(alice, carol, dave, id, tmp.path(), gone);
    let back = setup(dave, &["room", "read", id]);
    assert!(
        back.stdout.contains(control),
        "APPARATUS: alice's C expired on dave before M came back; the act could not stage a \
         return before M's original expiry: {back:?}"
    );
    println!("[proof] M came back on dave while C, posted after it, was still kept");
    let (expired, last) = poll(dave, &["room", "read", id], GONE + GONE, |o| {
        o.ok && !o.stdout.contains(control)
    });
    assert!(
        expired,
        "APPARATUS: alice's C never expired on dave with a 150 s retention: {last:?}"
    );
    assert!(
        !last.stdout.contains(gone),
        "PRODUCT [MP11 lifetime]: alice's C, posted after carol's M, expired on dave, yet M, \
         which came back, is still shown: it got a fresh lifetime: {last:?}"
    );
    println!("[proof] once C expired on dave, M (which came back) was gone too");
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
    // Stage a live commitment response while neither peer can apply the departure: the leave
    // answers all the same (ADR-023 RL-8.1a; the decider, 2026-11-11: "a node should be able to
    // leave a room whenever it wants"), the room is gone from alice's list and named only by
    // `vox status` as leaving, and the peers learn of it once they can apply it.
    #[cfg(feature = "test-knobs")]
    let o = {
        std::fs::write(&hold, b"hold").expect("APPARATUS: arm departure hold");
        let o = alice.vox(None, &["room", "leave", id]);
        assert!(o.ok, "PRODUCT: `vox room leave` was refused: {o:?}");
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
        let listed = alice.vox(None, &["room", "list"]);
        assert!(
            listed.ok && !listed.stdout.contains(id),
            "PRODUCT: alice left, and no member has her departure yet, but her room list still \
             names the room: {listed:?}"
        );
        let status = alice.vox(None, &["status"]);
        assert!(
            status.ok
                && status.stdout.contains("leaving ")
                && status.stdout.contains("no member has been told yet"),
            "PRODUCT: `vox status` must name the room alice left as leaving while no member has \
             her departure: {status:?}"
        );
        std::fs::remove_file(&hold).expect("APPARATUS: release departure hold");
        o
    };
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
    unavailable(&room.workers[0], &id);
    let bob = &room.workers[1];
    let (gone, o2) = poll(bob, &["room", "roster", &id], WITHIN, |o| {
        o.ok && !o.stdout.contains(&alice_fp)
    });
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after alice left, bob's roster still names her: {o2:?}"
    );
    // Receipt-driven deletion is asynchronous; absence for the person is immediate.
    // The separate offline-member arm proves deletion even without a receipt after two days.
    support::until(
        &room.workers[0],
        None,
        "the acknowledged departure's copy deleted",
        &["status", "--json"],
        |out| {
            out.ok
                && serde_json::from_str::<serde_json::Value>(&out.stdout).is_ok_and(|status| {
                    status["leaving"]
                        .as_array()
                        .is_some_and(|rooms| rooms.iter().all(|held| held["id"] != id))
                })
        },
    );
    erased(&mut room.workers[0], &id, &cid, true);
    room.workers[0].stop_daemon_cleanly();
    let after = std::fs::read(room.workers[0].paths.store_file())
        .expect("APPARATUS: read post-leave store bytes");
    assert!(
        !after.windows(sealed_wrap.len()).any(|b| b == sealed_wrap),
        "PRODUCT: Alice's deleted sealed SEK wrap remains physically present after Leave"
    );
    room.workers[0].restart_daemon(&tmp.path().join("alice-after-physical-erasure.err"));

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
    let o = unchanged_busy_retry(bob, &["room", "end", id]);
    assert!(
        o.ok,
        "PRODUCT: bob, an admin the creator named, was refused `vox room end`: {o:?}"
    );
    eprintln!("[proof] end: it said: {}", o.stdout.trim());
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

fn rejoin_ended_with_status(worker: &Worker, link: &str) -> Out {
    use std::io::Write as _;

    struct Running(Option<std::process::Child>);
    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    fn finish(running: &mut Running, deadline: Instant, what: &str) -> std::process::Output {
        loop {
            if running
                .0
                .as_mut()
                .expect("APPARATUS: owned command")
                .try_wait()
                .expect("APPARATUS: poll command")
                .is_some()
            {
                return running
                    .0
                    .take()
                    .expect("APPARATUS: completed command")
                    .wait_with_output()
                    .expect("APPARATUS: collect command");
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: {what} did not answer within its command response bound"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let command = |args: &[&str]| {
        let mut command = std::process::Command::new(&worker.exe);
        command
            .args(args)
            .env("VOX_DATA_DIR", &worker.data)
            .env("VOX_CONFIG_DIR", &worker.cfg)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        support::strip_harness_env(&mut command);
        command
    };
    let join_deadline = Instant::now() + GONE;
    let mut join = Running(Some(
        command(&["room", "join", "--passphrase-file", "-", link])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("APPARATUS: start ended-room join"),
    ));
    join.0
        .as_mut()
        .expect("APPARATUS: owned join")
        .stdin
        .take()
        .expect("APPARATUS: join passphrase input")
        .write_all(support::ROOM_PASS.as_bytes())
        .expect("APPARATUS: write join passphrase");
    let mut status = Running(Some(
        command(&["status", "--json"])
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("APPARATUS: start status beside ended-room join"),
    ));
    // Explicit command-response bounds, not an elapsed-silence verdict about background sync.
    // Owned children are killed and reaped on any panic.
    let output = finish(
        &mut status,
        Instant::now() + WITHIN,
        "vox status during ended-room join",
    );
    assert!(
        output.status.success(),
        "PRODUCT: status was refused during ended-room join: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "[proof] status answered during ended-room join: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let joined = finish(&mut join, join_deadline, "vox room join for an ended room");
    let out = Out {
        ok: joined.status.success(),
        code: joined.status.code(),
        stdout: String::from_utf8_lossy(&joined.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&joined.stderr).into_owned(),
        argv: format!("{} room join --passphrase-file - {link}", worker.exe),
    };
    eprintln!(
        "[receipt] {} -> exit {:?}\n  stdout: {}\n  stderr: {}",
        out.argv, out.code, out.stdout, out.stderr
    );
    out
}

/// `through_end`: she stays away until both members have closed the ended room, so no member
/// is left that could take her departure when she comes back and joins.
fn end_while_away(delegated: bool, through_end: bool) {
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
    if !through_end {
        restart_former(
            &mut room.workers[2],
            &tmp.path().join("carol-after-leave.err"),
        );
    }
    let ender = if delegated { 1 } else { 0 };
    setup(&room.workers[ender], &["room", "end", &id]);
    // The creator endorses only an End she holds. Wait until she holds Bob's (her room list says
    // it ended, or her armed withdrawal save met its fault) before anything reads the boards for
    // it; if Bob closed the room before she had it, the staging failed, not the product.
    #[cfg(feature = "test-knobs")]
    if delegated {
        let engaged = tmp.path().join("fail-creator-withdrawal.engaged");
        let (held, seen) = poll(&room.workers[0], &["room", "list"], GONE, |o| {
            engaged.is_file()
                || (o.ok
                    && o.stdout
                        .lines()
                        .any(|l| l.starts_with(&id[..12]) && l.contains("ended")))
        });
        assert!(
            held,
            "APPARATUS: alice never held bob's End, so the creator could not endorse it: {seen:?}"
        );
    }
    if through_end {
        for w in &room.workers[..2] {
            let (gone, o) = poll(w, &["room", "list"], GONE, |o| {
                o.ok && !o.stdout.lines().any(|l| l.starts_with(&id[..12]))
            });
            assert!(
                gone,
                "APPARATUS: {} kept the ended room listed, so carol was not away through its end: {o:?}",
                w.name
            );
        }
        restart_former(
            &mut room.workers[2],
            &tmp.path().join("carol-after-end.err"),
        );
    }
    let deadline = Instant::now() + GONE;
    loop {
        let result = rejoin_ended_with_status(&room.workers[2], &link);
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
    end_while_away(false, false);
}

#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn delegated_end_while_away_gets_creator_endorsement() {
    end_while_away(true, false);
}

/// A node that left and was away while the creator ended the room, until both members had
/// closed it, is told at its rejoin that the room has ended, and its checkpoint is cleared
/// by the creator's verified End: no member is left to take its departure.
#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn creator_end_wound_down_while_away_clears_the_verified_checkpoint() {
    end_while_away(false, true);
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

    room.workers[2].stop_daemon_cleanly();
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
    // The authenticated End must still erase Bob's public author continuity.
    erased(&mut room.workers[1], &id, &cid, false);
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

/// RG-14: ending is not a reason to refuse the person's local leave.
#[test]
#[ignore = "real daemons and an offline member; run in release"]
fn an_ended_room_can_be_left_at_once() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    room.workers[1].stop_daemon_cleanly();
    let alice = &mut room.workers[0];
    setup(alice, &["room", "end", &room.id]);
    let started = std::time::Instant::now();
    let left = alice.vox(None, &["room", "leave", &room.id]);
    assert!(
        left.ok,
        "PRODUCT: an ended room could not be left: {left:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "PRODUCT: leaving an ended room waited instead of finishing locally"
    );
    assert!(
        left.stdout.contains("had already ended")
            && left.stdout.contains("this node's copy is deleted")
            && !left.stdout.contains("withdrawal is queued"),
        "PRODUCT: ended-room leave described a departure instead of local deletion: {left:?}"
    );
    erased(alice, &room.id, &room.cid, false);
}

/// A stopped product's sealed room rows, used to check retention without opening its content.
#[cfg(feature = "test-knobs")]
fn retained_room_rows(w: &Worker, cid: &[u8; 32]) -> Vec<(u8, u64, Vec<u8>)> {
    let db = redb::Database::builder()
        .open_read_only(w.paths.store_file())
        .expect("APPARATUS: open stopped hidden-room store");
    let read = db.begin_read().expect("APPARATUS: read hidden-room store");
    let mut rows = Vec::new();
    for name in ["segments", "small_segments"] {
        let table = match read.open_table(redb::TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(
            name,
        )) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => continue,
            Err(error) => panic!("APPARATUS: open hidden-room {name}: {error}"),
        };
        rows.extend(
            table
                .range((*cid, 0, 0)..=(*cid, u8::MAX, u64::MAX))
                .expect("APPARATUS: room row range")
                .map(|row| {
                    let (key, value) = row.expect("APPARATUS: room row");
                    let (_, kind, index) = key.value();
                    (kind, index, value.value().to_vec())
                }),
        );
    }
    rows
}

/// Inspect a crash-consistent copy without restarting the daemon being measured.
#[cfg(feature = "test-knobs")]
fn live_retained_room_rows(w: &Worker, cid: &[u8; 32]) -> Vec<(u8, u64, Vec<u8>)> {
    struct Resume(u32);
    impl Drop for Resume {
        fn drop(&mut self) {
            let result = std::process::Command::new("kill")
                .args(["-CONT", &self.0.to_string()])
                .status();
            assert!(
                result.is_ok_and(|status| status.success()),
                "APPARATUS: resume the owned snapshot daemon"
            );
        }
    }
    let pid = w.daemon_pid().expect("APPARATUS: owned snapshot daemon");
    assert!(
        std::process::Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .expect("APPARATUS: suspend owned daemon")
            .success(),
        "APPARATUS: suspend owned daemon for snapshot"
    );
    let resume = Resume(pid);
    loop {
        let state = std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .expect("APPARATUS: inspect owned daemon suspension");
        assert!(state.status.success(), "APPARATUS: snapshot daemon exited");
        if String::from_utf8_lossy(&state.stdout).contains('T') {
            break;
        }
        std::thread::yield_now();
    }
    let tmp = tempfile::tempdir().expect("APPARATUS: snapshot directory");
    let path = tmp.path().join("snapshot.redb");
    std::fs::copy(w.paths.store_file(), &path).expect("APPARATUS: copy suspended store");
    drop(resume);
    // Opening the disposable copy permits redb's normal interrupted-write recovery.
    // It neither opens nor changes the running product's database.
    let db = redb::Database::create(path).expect("APPARATUS: open store snapshot");
    let read = db.begin_read().expect("APPARATUS: read store snapshot");
    let mut rows = Vec::new();
    for name in ["segments", "small_segments"] {
        let table = match read.open_table(redb::TableDefinition::<([u8; 32], u8, u64), &[u8]>::new(
            name,
        )) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => continue,
            Err(error) => panic!("APPARATUS: open snapshot {name}: {error}"),
        };
        rows.extend(
            table
                .range((*cid, 0, 0)..=(*cid, u8::MAX, u64::MAX))
                .expect("APPARATUS: snapshot room row range")
                .map(|row| {
                    let (key, value) = row.expect("APPARATUS: snapshot room row");
                    let (_, kind, index) = key.value();
                    (kind, index, value.value().to_vec())
                }),
        );
    }
    rows
}

/// The deadline is independent of the trust-change row-integrity claim.
#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemons and a two-day product clock step; run in release"]
fn a_left_rooms_hidden_copy_expires_after_two_days() {
    left_copy_lifecycle(false);
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemons, a hidden left room and a trust change; run in release"]
fn a_trust_change_preserves_a_left_rooms_hidden_copy() {
    left_copy_lifecycle(true);
}

#[cfg(feature = "test-knobs")]
fn left_copy_lifecycle(trust_only: bool) {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let bob_id = room.workers[1].b32();
    room.workers[1].stop_daemon_cleanly();
    let alice = &mut room.workers[0];
    setup(alice, &["room", "leave", &room.id]);
    unavailable(alice, &room.id);
    let hidden = setup(alice, &["status", "--json"]);
    let hidden: serde_json::Value =
        serde_json::from_str(&hidden.stdout).expect("APPARATUS: status JSON");
    assert!(
        hidden["rooms"].as_array().is_some_and(Vec::is_empty),
        "PRODUCT: left room was shown or counted as an active room: {hidden}"
    );
    alice.stop_daemon_cleanly();
    let retained = retained_room_rows(alice, &room.cid);
    assert!(
        !retained.is_empty(),
        "PRODUCT: the hidden copy was deleted at once instead of retained for two days"
    );
    alice.restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_CLOCK_STEP_MS", "86400000")],
        &tmp.path().join("alice.one-day.err"),
    );
    support::until(
        alice,
        None,
        "startup finished reopening the hidden left room",
        &["status", "--json"],
        |out| {
            out.ok
                && serde_json::from_str::<serde_json::Value>(&out.stdout).is_ok_and(|status| {
                    status["preparing"].as_array().is_some_and(Vec::is_empty)
                        && status["rooms"].as_array().is_some_and(Vec::is_empty)
                        && status["leaving"]
                            .as_array()
                            .is_some_and(|rooms| rooms.iter().any(|held| held["id"] == room.id))
                })
        },
    );
    // The acknowledged post flushes startup's derived saves before the first file snapshot.
    alice
        .vox_in(
            None,
            &[
                "room",
                "create",
                "--name",
                "still-writable",
                "--passphrase-file",
                "-",
            ],
            Some(support::ROOM_PASS),
        )
        .expect_ok("create a live room before the trust change");
    let list = setup(alice, &["room", "list"]);
    let live = list
        .stdout
        .lines()
        .find(|line| line.contains("still-writable"))
        .and_then(|line| line.split_whitespace().next())
        .expect("APPARATUS: healthy room id");
    setup(
        alice,
        &["room", "post", live, "trust did not refuse this post"],
    );
    let retained_before_trust = trust_only.then(|| live_retained_room_rows(alice, &room.cid));
    if trust_only {
        setup(
            alice,
            &[
                "trust",
                "remove",
                &bob_id,
                "--identity-passphrase-file",
                alice.pass.to_str().expect("APPARATUS: passphrase path"),
            ],
        );
        setup(
            alice,
            &[
                "trust",
                "add",
                &bob_id,
                "--name",
                "bob",
                "--identity-passphrase-file",
                alice.pass.to_str().expect("APPARATUS: passphrase path"),
            ],
        );
        support::until(
            alice,
            None,
            "trust change finished",
            &["status", "--json"],
            |out| {
                out.ok
                    && serde_json::from_str::<serde_json::Value>(&out.stdout)
                        .is_ok_and(|status| status["governance_pending"] == false)
            },
        );
    }
    if trust_only {
        assert_eq!(
            live_retained_room_rows(alice, &room.cid),
            retained_before_trust.expect("APPARATUS: trust snapshot"),
            "PRODUCT: trust rewrote the hidden room's stored rows"
        );
        unavailable(alice, &room.id);
        let healthy = setup(alice, &["room", "read", live]);
        assert!(
            healthy.stdout.contains("trust did not refuse this post"),
            "PRODUCT: trust change lost another room's post: {healthy:?}"
        );
        eprintln!("[proof] trust completed without changing the hidden copy in one daemon session");
        return;
    }
    alice.stop_daemon_cleanly();
    alice.restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_CLOCK_STEP_MS", "172801000")],
        &tmp.path().join("alice.two-days.err"),
    );
    let clock = setup(alice, &["status", "--json"]);
    let clock: serde_json::Value =
        serde_json::from_str(&clock.stdout).expect("APPARATUS: stepped status JSON");
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: system clock")
        .as_millis() as u64;
    assert!(
        clock["now_ms"]
            .as_u64()
            .is_some_and(|now| now >= wall + 172_800_000),
        "APPARATUS: product clock did not step past two days: {clock}"
    );
    // Wait for the product's purge, but let the physical copy decide the expiry verdict,
    // including on the seven-day baseline and the never-delete mutant.
    let (expired, expiry_status) = poll(alice, &["status", "--json"], WITHIN, |out| {
        out.ok
            && serde_json::from_str::<serde_json::Value>(&out.stdout).is_ok_and(|status| {
                status["leaving"]
                    .as_array()
                    .is_some_and(|rooms| rooms.iter().all(|held| held["id"] != room.id))
            })
    });
    let healthy = setup(alice, &["room", "read", live]);
    assert!(
        healthy.stdout.contains("trust did not refuse this post"),
        "PRODUCT: expiry damaged another room's acknowledged post: {healthy:?}"
    );
    erased(alice, &room.id, &room.cid, true);
    assert!(
        expired,
        "PRODUCT: hidden copy expired but status still listed it as leaving after two days: {expiry_status:?}"
    );
    eprintln!("[proof] after two days the hidden copy is gone and the healthy room reads whole");
}

/// RG-14: invalid stores are preserved; inaccessible good stores keep their identity and rooms.
/// Positive crash recovery is covered by a_daemon_reopens_its_rooms_proof.rs.
#[test]
#[ignore = "real vox opens invalid stores and a permission-denied good store; run in release"]
fn an_unreadable_store_is_left_exactly_as_it_is() {
    use std::os::unix::fs::PermissionsExt as _;

    watchdog::arm();
    let tmp = support::diagnostic_tempdir();
    let mut problems = Vec::new();
    for (name, bytes) in [
        ("garbage", vec![0xa5; 4096]),
        ("truncated", b"redb".to_vec()),
        ("empty", Vec::new()),
    ] {
        let worker = support::worker(tmp.path(), name);
        let path = worker.paths.store_file();
        std::fs::write(&path, &bytes).expect("APPARATUS: stage an invalid store header");
        let siblings = || {
            let mut names = std::fs::read_dir(path.parent().expect("APPARATUS: store parent"))
                .expect("APPARATUS: profile directory")
                .map(|entry| entry.expect("APPARATUS: profile entry").file_name())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let names = siblings();
        let modified = std::fs::metadata(&path)
            .expect("APPARATUS: store metadata")
            .modified()
            .expect("APPARATUS: store mtime");
        let out = worker.vox(None, &["id"]);
        if out.ok {
            problems.push(format!("{name}: vox accepted an invalid store: {out:?}"));
        }
        if std::fs::read(&path).expect("APPARATUS: read refused store") != bytes {
            problems.push(format!("{name}: vox changed the unreadable store's bytes"));
        }
        if std::fs::metadata(&path)
            .expect("APPARATUS: store metadata")
            .modified()
            .expect("APPARATUS: store mtime")
            != modified
        {
            problems.push(format!("{name}: vox changed the unreadable store's mtime"));
        }
        if siblings() != names {
            problems.push(format!(
                "{name}: vox made a copy beside the unreadable store"
            ));
        }
        if !out.stderr.contains("store could not be read")
            || !out
                .stderr
                .contains(path.to_str().expect("APPARATUS: store path"))
            || !out.stderr.contains("restore it from a backup")
            || !out.stderr.contains("move it aside to start a new node")
        {
            problems.push(format!(
                "{name}: refusal did not say what failed, where, and what to do: {out:?}"
            ));
        }
    }
    let rt = runtime();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let alice = &mut room.workers[0];
    let marker = "the good store still holds this room after permissions are restored";
    setup(alice, &["room", "post", &room.id, marker]);
    let before = setup(alice, &["room", "read", &room.id]);
    assert!(
        before.stdout.contains(marker),
        "APPARATUS: the good store did not hold the staged room post: {before:?}"
    );
    alice.stop_daemon_cleanly();
    let path = alice.paths.store_file();
    let bytes = std::fs::read(&path).expect("APPARATUS: snapshot the good store");
    struct RestoreMode {
        path: std::path::PathBuf,
        mode: u32,
    }
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            if let Err(error) =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode))
            {
                eprintln!(
                    "APPARATUS: could not restore permissions on {}: {error}",
                    self.path.display()
                );
            }
        }
    }
    let original_mode = std::fs::metadata(&path)
        .expect("APPARATUS: good store metadata")
        .permissions()
        .mode();
    let restore = RestoreMode {
        path: path.clone(),
        mode: original_mode,
    };
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("APPARATUS: deny access to the good scratch store");
    assert!(
        std::fs::File::open(&path)
            .err()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
        "APPARATUS: chmod did not deny read access to the good store"
    );
    let refused = alice.vox(None, &["id"]);
    drop(restore);
    assert_eq!(
        std::fs::metadata(&path)
            .expect("APPARATUS: restored store metadata")
            .permissions()
            .mode(),
        original_mode,
        "APPARATUS: the scratch store's original permissions were not restored"
    );
    if refused.ok
        || !refused
            .stderr
            .contains("check the file's permissions and the disk, then try again")
        || refused.stderr.contains("restore it from a backup")
        || refused.stderr.contains("start a new node")
        || !refused
            .stderr
            .contains(path.to_str().expect("APPARATUS: store path"))
        || !refused.stderr.contains("Permission denied")
    {
        problems.push(format!(
            "permission-denied good store did not get safe retry advice: {refused:?}"
        ));
    }
    if std::fs::read(&path).expect("APPARATUS: read the permission-refused store") != bytes {
        problems.push("vox changed the permission-denied good store's bytes".to_owned());
    }
    setup(alice, &["id"]);
    alice.restart_daemon(&tmp.path().join("permissions-restored.daemon.err"));
    support::until(
        alice,
        None,
        "the held room post after restoring permissions",
        &["room", "read", &room.id],
        |out| out.ok && out.stdout.contains(marker),
    );
    assert!(problems.is_empty(), "PRODUCT: {}", problems.join("\n"));
}

/// RG-6: no roster/readiness wait or second post command between rejoining and the first post.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real daemons and production identity work; optional, run in release"]
fn a_node_that_left_rejoins_and_posts_at_once() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let [alice, bob] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    let old = "RG6 Alice before leaving";
    alice
        .vox(None, &["room", "post", id, old])
        .expect_ok("APPARATUS: establish Alice's pre-leave history");
    let (held, seen) = poll(bob, &["room", "read", id], WITHIN, |out| {
        out.ok && out.stdout.contains(old)
    });
    assert!(
        held,
        "APPARATUS: Bob did not hold Alice's pre-leave post: {seen:?}"
    );
    let link = bob
        .vox(None, &["room", "link", id])
        .expect_ok("APPARATUS: Bob's room link")
        .stdout
        .trim()
        .to_owned();
    let started = Instant::now();
    let left = alice.vox(None, &["room", "leave", id]);
    eprintln!("[proof] leave after {:?}: {left:?}", started.elapsed());
    assert!(left.ok, "PRODUCT: once-only leave was refused: {left:?}");
    let mutant_log_offset = std::fs::metadata(tmp.path().join("alice.daemon.err"))
        .expect("APPARATUS: stat Alice's daemon log")
        .len() as usize;
    let joined_at = Instant::now();
    let joined = alice.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    eprintln!("[proof] rejoin after {:?}: {joined:?}", joined_at.elapsed());
    match std::env::var("VOX_MUTANT_FX28") {
        Ok(mutant)
            if [
                "rejoin-purge-unheard-departure",
                "rejoin-before-session-retirement",
                "rejoin-answers-before-own-history",
            ]
            .contains(&mutant.as_str()) =>
        {
            let log = std::fs::read_to_string(tmp.path().join("alice.daemon.err"))
                .expect("APPARATUS: read Alice's daemon mutant log");
            let marker = format!("[vox mutant] engaged {mutant}");
            assert!(
                log.get(mutant_log_offset..)
                    .is_some_and(|tail| tail.contains(&marker)),
                "APPARATUS: mutant did not engage during rejoin: {marker}\n{log}"
            );
            eprintln!("{marker}");
        }
        _ => {}
    }
    assert!(
        joined.ok,
        "PRODUCT: once-only rejoin was refused: {joined:?}"
    );
    let text = "RG6 first post immediately after rejoining";
    let mut command = std::process::Command::new(&alice.exe);
    command
        .args(["room", "post", id, text])
        .env("VOX_DATA_DIR", &alice.data)
        .env("VOX_CONFIG_DIR", &alice.cfg)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    support::strip_harness_env(&mut command);
    let mut child = command.spawn().expect("APPARATUS: spawn first rejoin post");
    let started = Instant::now();
    while child
        .try_wait()
        .expect("APPARATUS: inspect first post")
        .is_none()
    {
        if started.elapsed() > Duration::from_secs(35) {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("APPARATUS: reap stalled post");
            panic!(
                "PRODUCT: first rejoin post exceeded the client's thirty-second patience plus reply allowance: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child
        .wait_with_output()
        .expect("APPARATUS: reap first post");
    let posted = Out {
        ok: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        argv: format!("vox room post {id} {text:?}"),
    };
    eprintln!(
        "[proof] once-only first post after {:?}: {posted:?}",
        started.elapsed()
    );
    assert!(
        posted.ok,
        "PRODUCT: once-only first post immediately after rejoining was refused: {posted:?}"
    );
    let (read, seen) = poll(bob, &["room", "read", id], WITHIN, |out| {
        out.ok && out.stdout.contains(text)
    });
    assert!(
        read,
        "PRODUCT: Bob did not read the accepted first rejoin post: {seen:?}"
    );
    eprintln!("[proof] Bob read the once-only first rejoin post: {seen:?}");
}

/// An unheard signed departure must survive the bounded join and be deliverable later.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real daemons and an offline member; optional, run in release"]
fn an_unheard_departure_keeps_the_left_copy_until_a_member_returns() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let id = room.id.clone();
    let link = room.workers[1]
        .vox(None, &["room", "link", &id])
        .expect_ok("APPARATUS: Bob's room link")
        .stdout
        .trim()
        .to_owned();
    room.stop(1);
    let alice = &room.workers[0];
    alice
        .vox(None, &["room", "leave", &id])
        .expect_ok("APPARATUS: leave while Bob is offline");
    let started = Instant::now();
    let refused = alice.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    eprintln!(
        "[proof] offline rejoin after {:?}: {refused:?}",
        started.elapsed()
    );
    assert!(
        !refused.ok && refused.stderr.contains("no member of this room has acknowledged")
            && refused.stderr.contains("the left copy was kept")
            && refused.stderr.contains("when a member of the room is reachable"),
        "PRODUCT: offline rejoin did not explain the unheard departure and retained copy: {refused:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(30),
        "PRODUCT: offline rejoin refused before the product's 30-second board patience: {refused:?}"
    );
    room.restart(1);
    let alice = &room.workers[0];
    let bob = &room.workers[1];
    let joined = alice.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(support::ROOM_PASS),
    );
    assert!(
        joined.ok,
        "PRODUCT: rejoin after Bob returned was refused: {joined:?}"
    );
    let text = "RG6 retained departure first post";
    let posted = alice.vox(None, &["room", "post", &id, text]);
    assert!(
        posted.ok,
        "PRODUCT: immediate post after rejoin was refused: {posted:?}"
    );
    let (read, seen) = poll(bob, &["room", "read", &id], WITHIN, |out| {
        out.ok && out.stdout.contains(text)
    });
    assert!(
        read,
        "PRODUCT: Bob did not read the immediate post: {seen:?}"
    );
}

/// The hold affects only B's receiver, not the reason A's join is waiting.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "three real daemons, an offline member and a local receiver hold; optional"]
fn a_waiting_rejoin_does_not_hold_independently_deferred_other_room_commands() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Release(std::path::PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let (_anchor, spec) = support::spawn_anchor(&tmp.path().join("charlie-anchor"));
    let mut charlie = support::worker(tmp.path(), "charlie");
    support::start_daemon(&mut charlie, &spec, &tmp.path().join("charlie.daemon.err"));
    charlie
        .vox_in(
            None,
            &[
                "room",
                "create",
                "--name",
                "other",
                "--passphrase-file",
                "-",
            ],
            Some(support::ROOM_PASS),
        )
        .expect_ok("APPARATUS: Charlie creates B");
    let b_link = charlie
        .vox(None, &["room", "link", "other"])
        .expect_ok("APPARATUS: B link")
        .stdout
        .trim()
        .to_owned();
    let b = b_link
        .strip_prefix("vox://")
        .expect("APPARATUS: B link scheme")
        .split('?')
        .next()
        .expect("APPARATUS: B room id")
        .to_owned();
    room.workers[0]
        .vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &b_link],
            Some(support::ROOM_PASS),
        )
        .expect_ok("APPARATUS: Alice joins B");
    for (from, to) in [(&room.workers[0], &charlie), (&charlie, &room.workers[0])] {
        from.vox(
            None,
            &[
                "trust",
                "add",
                &to.b32(),
                "--name",
                &to.name,
                "--identity-passphrase-file",
                from.pass.to_str().expect("APPARATUS: passphrase path"),
            ],
        )
        .expect_ok("APPARATUS: trust B member");
    }
    let seed = "RG6 B already readable";
    charlie
        .vox(None, &["room", "post", &b, seed])
        .expect_ok("APPARATUS: seed B");
    let (read, seen) = poll(&room.workers[0], &["room", "read", &b], WITHIN, |out| {
        out.ok && out.stdout.contains(seed)
    });
    assert!(read, "APPARATUS: B was not readable: {seen:?}");
    let a = room.id.clone();
    let a_full = vox_core::node::link::b32_encode(&room.cid);
    let a_link = room.workers[1]
        .vox(None, &["room", "link", &a])
        .expect_ok("APPARATUS: A link")
        .stdout
        .trim()
        .to_owned();
    let hold = tmp.path().join("b-local-hold");
    let log = tmp.path().join("alice-cross-room.err");
    room.workers[0].restart_daemon_as(
        support::VOX,
        &[(
            "VOX_TEST_HOLD_ROOM_WRITE",
            hold.to_str().expect("APPARATUS: hold path"),
        )],
        &log,
    );
    let alice = &room.workers[0];
    let (read, seen) = poll(alice, &["room", "read", &b], WITHIN, |out| {
        out.ok && out.stdout.contains(seed)
    });
    assert!(
        read,
        "APPARATUS: B did not reopen after Alice's restart: {seen:?}"
    );
    alice
        .vox(
            None,
            &[
                "trust",
                "add",
                &charlie.b32(),
                "--name",
                "charlie",
                "--identity-passphrase-file",
                alice.pass.to_str().expect("APPARATUS: passphrase path"),
            ],
        )
        .expect_ok("APPARATUS: warm Alice's trust save before the held command");
    room.stop(1);
    let alice = &room.workers[0];
    alice
        .vox(None, &["room", "leave", &a])
        .expect_ok("APPARATUS: leave A with Bob offline");
    let answered = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let _release = Release(hold.clone());
        let join = scope.spawn(|| {
            let out = alice.vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", &a_link],
                Some(support::ROOM_PASS),
            );
            answered.store(true, Ordering::SeqCst);
            out
        });
        let wait_marker = |marker: &str| {
            let start = Instant::now();
            loop {
                let text = std::fs::read_to_string(&log).unwrap_or_default();
                if text.contains(marker) {
                    eprintln!("[staging] {marker}");
                    break;
                }
                assert!(
                    !join.is_finished() && start.elapsed() < WITHIN,
                    "APPARATUS: marker not reached while join waited: {marker}\n{text}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        wait_marker(&format!("vox: rejoin waiting for departure room={a_full}"));
        let b_cid = vox_core::node::link::b32_decode(&b, "room").expect("APPARATUS: B full id");
        std::fs::write(&hold, b_cid).expect("APPARATUS: arm B receiver hold");
        charlie
            .vox(None, &["room", "post", &b, "RG6 B receiver input"])
            .expect_ok("APPARATUS: trigger B receiver");
        let start = Instant::now();
        while !hold.with_extension("engaged").exists() {
            assert!(
                !join.is_finished() && start.elapsed() < WITHIN,
                "APPARATUS: B receiver did not engage while A waited"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let engaged = std::fs::read_to_string(hold.with_extension("engaged"))
            .expect("APPARATUS: receiver marker");
        assert!(
            engaged.contains("publication=false"),
            "APPARATUS: not a local receiver hold: {engaged}"
        );
        let first =
            scope.spawn(|| alice.vox(None, &["room", "post", &b, "RG6 B first pending post"]));
        // Let the first command reach B's held authored save before issuing the second.
        std::thread::sleep(Duration::from_millis(25));
        let second = scope.spawn(|| {
            let out = alice.vox(
                None,
                &["room", "post", &b, "RG6 B independently deferred post"],
            );
            (out, !answered.load(Ordering::SeqCst))
        });
        wait_marker(&format!("vox: rejoin cross-room deferred room={b} own_post=true text=\"RG6 B independently deferred post\""));
        let trust = scope.spawn(|| {
            let out = alice.vox(
                None,
                &[
                    "trust",
                    "add",
                    &charlie.b32(),
                    "--name",
                    "charlie",
                    "--identity-passphrase-file",
                    alice.pass.to_str().expect("APPARATUS: passphrase path"),
                ],
            );
            (out, !answered.load(Ordering::SeqCst))
        });
        let read = alice.vox(None, &["room", "read", &b]);
        let read_before = !answered.load(Ordering::SeqCst);
        assert!(
            !join.is_finished(),
            "APPARATUS: A answered before B was released"
        );
        std::fs::remove_file(&hold).expect("APPARATUS: release B receiver");
        let first = first.join().expect("APPARATUS: B first thread");
        let (second, second_before) = second.join().expect("APPARATUS: B second thread");
        let (trust, trust_before) = trust.join().expect("APPARATUS: trust thread");
        let a_result = join.join().expect("APPARATUS: A join thread");
        assert!(
            read.ok && read.stdout.contains(seed) && read_before,
            "PRODUCT: B read did not answer before A: {read:?}; A={a_result:?}"
        );
        assert!(first.ok && second.ok && second_before, "PRODUCT: independently deferred B post did not answer before A after B release: first={first:?}; second={second:?}; A={a_result:?}");
        assert!(
            trust.ok && trust_before,
            "PRODUCT: trust did not answer before A after B release: {trust:?}; A={a_result:?}"
        );
    });
}

/// A rejoin waiting on its unheard departure is answered when its left copy is deleted another
/// way: here by `vox room leave` of the copy, once the room's idle end has passed by the node's
/// own clock. The join is then an ordinary join and says what it found; it never tells a person
/// that a node that is running is shutting down.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real daemons, an offline member and a stepped product clock; optional"]
fn a_waiting_rejoin_is_answered_when_its_left_copy_is_deleted() {
    watchdog::arm();
    let rt = runtime();
    let tmp = support::diagnostic_tempdir();
    let mut room = room_of(&rt, tmp.path(), &["alice", "bob"]);
    let pass = "fading room passphrase";
    room.workers[0]
        .vox_in(
            None,
            &[
                "room",
                "create",
                "--passphrase-file",
                "-",
                "--name",
                "fading",
                "--idle-end",
                "90",
            ],
            Some(pass),
        )
        .expect_ok("APPARATUS: Alice creates a room with a 90-second idle end");
    let link = room.workers[0]
        .vox(None, &["room", "link", "fading"])
        .expect_ok("APPARATUS: the idle room's link")
        .stdout
        .trim()
        .to_owned();
    let id = link
        .strip_prefix("vox://")
        .and_then(|rest| rest.split('?').next())
        .map(|id| {
            vox_core::node::link::b32_encode(
                &vox_core::node::link::b32_decode(id, "room").expect("APPARATUS: room id"),
            )
        })
        .expect("APPARATUS: room id in the link");
    room.workers[1]
        .vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(pass),
        )
        .expect_ok("APPARATUS: Bob joins the idle room");
    let seed = "RG6 before Bob leaves the idle room";
    room.workers[0]
        .vox(None, &["room", "post", &id, seed])
        .expect_ok("APPARATUS: Alice posts in the idle room");
    let posted = Instant::now();
    let (read, seen) = poll(&room.workers[1], &["room", "read", &id], WITHIN, |out| {
        out.ok && out.stdout.contains(seed)
    });
    assert!(read, "APPARATUS: Bob did not read Alice's post: {seen:?}");
    // Alice offline: nobody can take Bob's departure, so his join waits on it. Stopped inside
    // the idle end, the creator never ends the room herself.
    room.stop(0);
    assert!(
        posted.elapsed() < Duration::from_secs(90),
        "APPARATUS: Alice ran past the room's idle end before she was stopped"
    );
    room.workers[1]
        .vox(None, &["room", "leave", &id])
        .expect_ok("APPARATUS: Bob leaves while Alice is offline");
    // Three minutes on by Bob's clock (inside the boards' five-minute clock window): his left copy
    // is past its idle end. The hold path is never written; set, the daemon says when a rejoin
    // is waiting on its departure.
    let hold = tmp.path().join("never-held");
    let log = tmp.path().join("bob-past-idle-end.err");
    room.workers[1].restart_daemon_as(
        support::VOX,
        &[
            ("VOX_TEST_CLOCK_STEP_MS", "180000"),
            (
                "VOX_TEST_HOLD_ROOM_WRITE",
                hold.to_str().expect("APPARATUS: hold path"),
            ),
        ],
        &log,
    );
    let bob = &room.workers[1];
    let leaving = |out: &Out| {
        out.ok
            && serde_json::from_str::<serde_json::Value>(&out.stdout).is_ok_and(|status| {
                status["preparing"].as_array().is_some_and(Vec::is_empty)
                    && status["leaving"]
                        .as_array()
                        .is_some_and(|rooms| rooms.iter().any(|held| held["id"] == id.as_str()))
            })
    };
    support::until(
        bob,
        None,
        "Bob's restart reopened his hidden left copy",
        &["status", "--json"],
        leaving,
    );
    let offset = std::fs::metadata(&log)
        .expect("APPARATUS: stat Bob's daemon log")
        .len() as usize;
    std::thread::scope(|scope| {
        let join = scope.spawn(|| {
            bob.vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", &link],
                Some(pass),
            )
        });
        let marker = format!("vox: rejoin waiting for departure room={id}");
        let start = Instant::now();
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text
                .get(offset..)
                .is_some_and(|tail| tail.contains(&marker))
            {
                eprintln!("[staging] {marker}");
                break;
            }
            assert!(
                !join.is_finished() && start.elapsed() < WITHIN,
                "APPARATUS: Bob's join did not wait on its departure: {marker}\n{text}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let left = bob.vox(None, &["room", "leave", &id]);
        eprintln!("[staging] leave of the ended left copy: {left:?}");
        assert!(
            left.ok,
            "APPARATUS: the ended left copy was not deleted by `vox room leave`: {left:?}"
        );
        let gone = bob.vox(None, &["status", "--json"]);
        assert!(
            gone.ok && !leaving(&gone),
            "APPARATUS: Bob's left copy is still held after its leave: {gone:?}"
        );
        let joined = join.join().expect("APPARATUS: join thread");
        eprintln!("[proof] the waiting join answered: {joined:?}");
        if let Ok(mutant) = std::env::var("VOX_MUTANT_FX28") {
            let text = std::fs::read_to_string(&log).expect("APPARATUS: read Bob's daemon log");
            let engaged = format!("[vox mutant] engaged {mutant}");
            assert!(
                text.get(offset..)
                    .is_some_and(|tail| tail.contains(&engaged)),
                "APPARATUS: mutant did not engage during the waiting join: {engaged}\n{text}"
            );
            eprintln!("{engaged}");
        }
        assert!(
            !joined.stderr.contains("shutting down") && !joined.stdout.contains("shutting down"),
            "PRODUCT: the waiting join was told a running node is shutting down: {joined:?}"
        );
        let running = bob.vox(None, &["status", "--json"]);
        assert!(
            running.ok,
            "PRODUCT: Bob's node did not answer after the join: {running:?}"
        );
    });
}
