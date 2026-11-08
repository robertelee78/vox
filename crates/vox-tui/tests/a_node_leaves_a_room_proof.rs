//! V210-164 — **a node can leave a room**, through the shipped binary. Run on demand; not a gate.
//!
//! There was no way to leave a room: a node held every room it ever joined, and every other
//! member listed it for good. `vox room leave` writes the node's departure into the room, waits
//! for another member to have it, and removes the room from the node.
//!
//! **Staging.** `support/room.rs`: an anchor and three `vox daemon`s — alice, bob, carol — in one
//! room, each trusting the others, each having read a post by each other.
//! With `test-knobs`, alice is offline for a post after Carol returns. Bob transiently refuses
//! the post's head to alice; after that refusal is recorded, bob reconnects and serves it.
//!
//! **Asserted.**
//! 1. carol's `vox room leave` exits 0, and afterwards carol's `vox room list` does not name the
//!    room and `vox room read` of it fails: carol no longer holds or receives it.
//! 2. alice's and bob's `vox room roster` stop naming carol, and keep naming each other.
//! 3. carol's node stops syncing it: `vox status` names no sync port of the room after bob posts.
//! 4. After recovery, carol posts, rejoins alice's roster, and both read distinct new posts.
//!    Nobody shows carol having signed two entries at one place.
//!
//! **Mutations that must turn it red (PRODUCT).** Keeping a departed member on the roster
//! fails assertion 2. Signing a replacement own prefix on rejoin prevents the two distinct
//! post-rejoin messages from being read across the real room.
//! A returner's retained Accepted may also be cancelled: its withdrawal must remove the
//! witnessed return from the other members' rosters. The `readmission-no-withdrawal-veto`
//! mutant must make that roster assertion red.
//! Persisting the transient refusal must fail the post-rejoin history read.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{until, ROOM_PASS};

#[test]
#[ignore = "an anchor and three real daemons with production Argon2id; run on demand, in release"]
fn a_node_leaves_a_room_and_the_others_see_it_gone() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = support::diagnostic_tempdir();
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let id = room.id.clone();
    let carol_fp = carol.b32();

    // Establish a nontrivial prefix on a different member before Carol erases her room.
    for n in 0..10 {
        let text = format!("carol before leave continuity {n}");
        carol
            .vox(None, &["room", "post", &id, &text])
            .expect_ok("carol's pre-leave continuity post");
        until(
            alice,
            None,
            "each pre-leave continuity post",
            &["room", "read", &id],
            |o| o.ok && o.stdout.contains(&text),
        );
    }

    // ---- 1. carol leaves ----------------------------------------------------------------------
    let left = carol.vox(None, &["room", "leave", &id]);
    println!("[proof] carol: vox room leave → {left:?}");
    assert!(
        left.ok,
        "PRODUCT: carol's `vox room leave` failed (exit {:?}): {}",
        left.code,
        left.stderr.trim()
    );
    let list = carol.vox(None, &["room", "list"]);
    assert!(
        list.ok && !list.stdout.contains(&id),
        "PRODUCT: carol still lists the room she left: {list:?}"
    );
    let read = carol.vox(None, &["room", "read", &id]);
    assert!(
        !read.ok,
        "PRODUCT: carol still reads the room she left: {read:?}"
    );

    // ---- 2. the others see her gone ----------------------------------------------------------
    for w in [alice, bob] {
        let o = until(
            w,
            None,
            "carol to leave the roster",
            &["room", "roster", &id],
            |o| o.ok && !o.stdout.contains(&carol_fp),
        );
        println!(
            "[proof] {}'s roster after carol left:\n{}",
            w.name,
            o.stdout.trim()
        );
        for other in [alice, bob] {
            assert!(
                o.stdout.contains(&other.b32()),
                "PRODUCT: {}'s roster lost {}, who did not leave: {o:?}",
                w.name,
                other.name
            );
        }
    }

    // ---- 3. carol's node no longer syncs it --------------------------------------------------
    bob.vox(None, &["room", "post", &id, "bob, after carol left"])
        .expect_ok("bob's post after carol left");
    std::thread::sleep(std::time::Duration::from_secs(5));
    let status = carol.vox(None, &["status"]);
    let short: String = id.chars().take(12).collect();
    println!(
        "[proof] carol's status after bob posted:\n{}",
        status.stdout.trim()
    );
    assert!(
        !status.stdout.contains(&format!("room {short}")),
        "PRODUCT: carol's node still syncs the room she left: {status:?}"
    );

    // The continuity marker must survive a daemon restart while the room is absent.
    room.workers[2].restart_daemon(&tmp.path().join("carol-after-leave.daemon.err"));
    let (alice, carol) = (&room.workers[0], &room.workers[2]);

    // ---- 4. joining again works --------------------------------------------------------------
    let link = alice
        .vox(None, &["room", "link", &id])
        .expect_ok("alice's `vox room link`")
        .stdout
        .trim()
        .to_owned();
    // A local same-name room must refuse the admission before Prepared; it must
    // remain usable, and removing the collision must permit the real retry.
    carol
        .vox_in(
            None,
            &[
                "room",
                "create",
                "--passphrase-file",
                "-",
                "--name",
                "mission",
            ],
            Some(ROOM_PASS),
        )
        .expect_ok("carol creates a same-name room");
    let rooms = carol.vox(None, &["room", "list"]);
    rooms.expect_ok("carol lists collision room");
    let local = rooms
        .stdout
        .split_whitespace()
        .next()
        .expect("local room id")
        .to_owned();
    assert_ne!(local, id);
    let original = "local row before the refused admission";
    carol
        .vox(None, &["room", "post", &local, original])
        .expect_ok("seed the unrelated collision room");
    let refused = carol.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(ROOM_PASS),
    );
    assert!(
        !refused.ok && refused.stderr.contains("name"),
        "PRODUCT: collision must refuse before admission: {refused:?}"
    );
    let roster = alice.vox(None, &["room", "roster", &id]);
    assert!(
        roster.ok && !roster.stdout.contains(&carol_fp),
        "PRODUCT: refused name collision admitted Carol at the creator: {roster:?}"
    );
    carol
        .vox(None, &["room", "post", &local, "collision room survives"])
        .expect_ok("local collision room remains writable");
    carol
        .vox(None, &["room", "rename", &local, "other-mission"])
        .expect_ok("rename the local collision room");
    let preserved = carol.vox(None, &["room", "read", &local]);
    assert!(
        preserved.ok && preserved.stdout.contains(original),
        "PRODUCT: refused join or collision rename lost the original local row: {preserved:?}"
    );
    carol
        .vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(ROOM_PASS),
        )
        .expect_ok("carol joining again");
    let warmup = "carol after recovering her own history";
    until(
        carol,
        None,
        "carol's post after own-history recovery",
        &["room", "post", &id, warmup],
        |o| o.ok,
    );
    until(
        alice,
        None,
        "carol back on the roster",
        &["room", "roster", &id],
        |o| o.ok && o.stdout.contains(&carol_fp),
    );
    // Establish Carol's post-rejoin consent and actual readability before Alice goes offline.
    // The separately staged post below must still reach Alice only after the refused head rearms.
    #[cfg(feature = "test-knobs")]
    until(
        alice,
        None,
        "carol's warmup before the staged refusal",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains(warmup),
    );
    #[cfg(feature = "test-knobs")]
    let (unavailable, declined, bob_fp) = {
        let unavailable = tmp.path().join("transient-head");
        let declined = tmp.path().join("transient-decline");
        let alice_fp = room.workers[0].b32();
        let bob_fp = room.workers[1].b32();
        std::fs::write(&unavailable, format!("{carol_fp} {alice_fp}"))
            .expect("APPARATUS: arm transient head response");
        room.workers[0].stop_daemon_cleanly();
        room.workers[1].restart_daemon_as(
            support::VOX,
            &[(
                "VOX_TEST_UNAVAILABLE_HEAD_FILE",
                unavailable.to_str().unwrap(),
            )],
            &tmp.path().join("bob-transient.daemon.err"),
        );
        (unavailable, declined, bob_fp)
    };
    let back = "carol's post after the transient refusal";
    room.workers[2]
        .vox(None, &["room", "post", &id, back])
        .expect_ok("carol's post after returning");
    #[cfg(feature = "test-knobs")]
    {
        until(
            &room.workers[1],
            None,
            "bob to read carol's new post",
            &["room", "read", &id],
            |o| o.ok && o.stdout.contains(back),
        );
        room.workers[2].stop_daemon_cleanly();
        let mut alice_env = vec![(
            "VOX_TEST_TRANSIENT_DECLINE_MARKER",
            declined.to_str().unwrap(),
        )];
        let mutant = std::env::var_os("HISTORY_REFUSAL_MUTANT").is_some();
        if mutant {
            alice_env.push(("VOX_TEST_DURABLE_TRANSIENT_DECLINE", "1"));
        }
        room.workers[0].restart_daemon_as(
            support::VOX,
            &alice_env,
            &tmp.path().join("alice-transient.daemon.err"),
        );
        let expected = format!(
            "{carol_fp} {bob_fp} {}",
            if mutant { "durable" } else { "connection" }
        );
        let deadline = std::time::Instant::now() + support::TIMEOUT;
        while std::fs::read_to_string(&declined).ok().as_deref() != Some(&expected) {
            assert!(
                std::time::Instant::now() < deadline,
                "APPARATUS: alice did not record bob's staged transient refusal"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::fs::remove_file(&unavailable).expect("APPARATUS: release transient response");
        room.workers[1].restart_daemon(&tmp.path().join("bob-reconnected.daemon.err"));
    }
    let alice = &room.workers[0];
    let read = until(
        alice,
        None,
        "carol's post after she joined again",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains(back),
    );
    println!("[proof] alice reads:\n{}", read.stdout.trim());
    #[cfg(feature = "test-knobs")]
    room.workers[2].restart_daemon(&tmp.path().join("carol-after-transient.daemon.err"));
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let reply = "alice after carol recovered her history";
    alice
        .vox(None, &["room", "post", &id, reply])
        .expect_ok("alice's post after carol rejoined");
    until(
        carol,
        None,
        "alice's post after carol rejoined",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains(reply),
    );

    // #1163 native regression: a member admitted after the same-ID return must
    // converge through the retained prefix, then deliver its private Session.
    let mut dave = support::worker(tmp.path(), "dave");
    support::start_daemon(&mut dave, "", &tmp.path().join("dave.daemon.err"));
    dave.vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(ROOM_PASS),
    )
    .expect_ok("dave joins after the retained-prefix return");
    for (owner, peer) in [(carol, &dave), (&dave, carol), (bob, &dave), (&dave, bob)] {
        until(
            owner,
            None,
            "late member's mutual read trust",
            &[
                "trust",
                "add",
                &peer.b32(),
                "--name",
                &peer.name,
                "--identity-passphrase-file",
                owner.pass.to_str().unwrap(),
            ],
            |o| {
                assert!(
                    o.ok || o.stderr.contains("still being applied"),
                    "PRODUCT: late member's mutual trust failed: {o:?}"
                );
                o.ok
            },
        );
    }
    let work = tmp.path().join("dave-session");
    std::fs::create_dir(&work).expect("APPARATUS: create Session work directory");
    let session = "11631163-aaaa-4bbb-8ccc-000000001163";
    let event = serde_json::json!({
        "session_id": session,
        "transcript_path": work.join("transcript.jsonl"),
        "cwd": work,
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "private Session after the retained-prefix return"
    })
    .to_string();
    dave.vox_env(
        None,
        &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
        &[
            "agent",
            "hook",
            "--node",
            support::DEFAULT_NODE,
            "--room",
            &id,
        ],
        Some(&event),
    )
    .expect_ok("late member opens a real harness Session");
    until(
        &dave,
        None,
        "dave grants the returner Drive",
        &[
            "trust",
            "drive",
            &carol_fp,
            "--identity-passphrase-file",
            dave.pass.to_str().unwrap(),
        ],
        |o| {
            assert!(
                o.ok || o.stderr.contains("still being applied"),
                "PRODUCT: late member's Drive grant failed: {o:?}"
            );
            o.ok
        },
    );
    let sessions = until(
        carol,
        None,
        "late member's private Session after same-ID recovery",
        &["room", "sessions", &id, "--json"],
        |o| {
            o.ok && o
                .ndjson()
                .iter()
                .any(|row| row["id"] == session && row["open"] == true && row["can_drive"] == true)
        },
    );
    println!(
        "[proof] recovered returner sees late member's drivable Session: {}",
        sessions.stdout.trim()
    );
    until(
        carol,
        None,
        "global trust removal after same-ID return and late admission",
        &[
            "trust",
            "remove",
            &dave.b32(),
            "--identity-passphrase-file",
            carol.pass.to_str().unwrap(),
        ],
        |o| {
            assert!(
                o.ok || o.stderr.contains("still being applied"),
                "PRODUCT: global trust removal after own-history recovery failed: {o:?}"
            );
            o.ok
        },
    );
    for w in [alice, bob, carol] {
        let o = w.vox(None, &["room", "read", &id]);
        assert!(
            !o.stdout.contains("signed two different messages"),
            "PRODUCT: {} shows carol signing two entries at one place after she joined again: \
             {o:?}",
            w.name
        );
    }
}

#[test]
#[ignore = "real daemons and anchor; run on demand in release"]
fn a_returner_reads_while_own_history_is_unavailable() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = support::diagnostic_tempdir();
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let id = room.id.clone();
    room.stop(1);
    for n in 0..10 {
        let text = format!("own prefix not held by bob {n}");
        room.workers[2]
            .vox(None, &["room", "post", &id, &text])
            .expect_ok("carol's retained prefix");
        until(
            &room.workers[0],
            None,
            "alice holds carol's prefix",
            &["room", "read", &id],
            |o| o.ok && o.stdout.contains(&text),
        );
    }
    room.workers[2]
        .vox(None, &["room", "leave", &id])
        .expect_ok("carol leaves");
    room.stop(0);
    // Simulate the admitting peer holding an authenticated entry but being unable to
    // supply its signed head; the real proposal must carry and honor kind 2.
    room.workers[1].restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_FX28_MUTANT", "join-extent-without-head")],
        &tmp.path().join("bob-kind-two.err"),
    );
    until(
        &room.workers[1],
        None,
        "bob reopens his room",
        &["room", "read", &id],
        |o| o.ok,
    );
    let bob = &room.workers[1];
    let before = bob.vox(None, &["room", "read", &id]);
    assert!(
        before.ok && !before.stdout.contains("own prefix not held by bob 9"),
        "PRODUCT (staging): bob already held the prefix: {before:?}"
    );
    let link = bob
        .vox(None, &["room", "link", &id])
        .expect_ok("bob's link")
        .stdout
        .trim()
        .to_owned();
    let carol = &room.workers[2];
    carol
        .vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &link],
            Some(ROOM_PASS),
        )
        .expect_ok("carol rejoins through bob without her latest history");
    let status = carol.vox(None, &["status"]);
    assert!(
        status.ok && status.stdout.contains("own history recovery is pending"),
        "PRODUCT: pending recovery was not reported: {status:?}"
    );
    let fenced = carol.vox(None, &["room", "post", &id, "must wait for the prefix"]);
    assert!(
        !fenced.ok && fenced.stderr.contains("own history"),
        "PRODUCT: returner wrote before recovery: {fenced:?}"
    );
    bob.vox(
        None,
        &["room", "post", &id, "bob while recovery is pending"],
    )
    .expect_ok("bob posts while alice is offline");
    until(
        carol,
        None,
        "permitted fresh read while own recovery is pending",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains("bob while recovery is pending"),
    );
    room.restart(0);
    let carol = &room.workers[2];
    until(
        carol,
        None,
        "post after authenticated recovery",
        &["room", "post", &id, "after recovered prefix"],
        |o| o.ok,
    );
    until(
        &room.workers[0],
        None,
        "alice reads post after recovery",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains("after recovered prefix"),
    );
}

#[test]
#[ignore = "real daemons, a restored checkpoint and controlled admission; run in release"]
fn signed_extent_above_a_restored_checkpoint_prevents_early_writes() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = support::diagnostic_tempdir();
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let id = room.id.clone();
    let old_link = room.workers[1]
        .vox(None, &["room", "link", &id])
        .expect_ok("bob's first link")
        .stdout
        .trim()
        .to_owned();
    room.workers[2]
        .vox(None, &["room", "leave", &id])
        .expect_ok("first leave");
    let carol_fp = room.workers[2].b32();
    until(
        &room.workers[0],
        None,
        "alice retains the original signed leave",
        &["room", "roster", &id],
        |o| o.ok && !o.stdout.contains(&carol_fp),
    );
    until(
        &room.workers[1],
        None,
        "bob retains the original signed leave",
        &["room", "roster", &id],
        |o| o.ok && !o.stdout.contains(&carol_fp),
    );
    room.workers[2].stop_daemon();
    let store = room.workers[2].paths.store_file();
    let backup = tmp.path().join("old-carol.redb");
    std::fs::copy(&store, &backup).expect("APPARATUS: save older checkpoint");
    room.stop(0);
    room.workers[2].restart_daemon(&tmp.path().join("carol-first-return.err"));
    room.workers[2]
        .vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", &old_link],
            Some(ROOM_PASS),
        )
        .expect_ok("first return through bob");
    for n in 0..10 {
        let text = format!("signed extent beyond restored checkpoint {n}");
        until(
            &room.workers[2],
            None,
            "carol writes after first recovery",
            &["room", "post", &id, &text],
            |o| o.ok,
        );
        until(
            &room.workers[1],
            None,
            "bob retains newer signed entry",
            &["room", "read", &id],
            |o| o.ok && o.stdout.contains(&text),
        );
    }
    room.workers[2]
        .vox(None, &["room", "leave", &id])
        .expect_ok("second leave");
    room.workers[2].stop_daemon();
    std::fs::copy(&backup, &store).expect("APPARATUS: restore older checkpoint");
    room.workers[1].restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_FX28_MUTANT", "join-extent-without-head")],
        &tmp.path().join("bob-extent.err"),
    );
    until(
        &room.workers[1],
        None,
        "bob reopens newer prefix",
        &["room", "read", &id],
        |o| o.ok,
    );
    let link = room.workers[1]
        .vox(None, &["room", "link", &id])
        .expect_ok("bob's extent link")
        .stdout
        .trim()
        .to_owned();
    let arm = tmp.path().join("accepted-arm");
    let engaged = tmp.path().join("accepted-engaged");
    let release = tmp.path().join("accepted-release");
    std::fs::write(&arm, b"arm").unwrap();
    let spec = format!(
        "{}\t{}\t{}",
        arm.display(),
        engaged.display(),
        release.display()
    );
    room.workers[2].restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_HOLD_DURABLE_ACCEPTED", &spec)],
        &tmp.path().join("carol-restored.err"),
    );
    let first = std::thread::scope(|scope| {
        let (donors, returning) = room.workers.split_at_mut(2);
        let join = scope.spawn(|| {
            returning[0].vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", &link],
                Some(ROOM_PASS),
            )
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while !engaged.exists() {
            if join.is_finished() {
                let result = join.join().unwrap();
                result.expect_ok("carol's admission carrying the signed extent");
                panic!("APPARATUS: successful join did not retain Accepted");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "APPARATUS: Accepted was not retained"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        donors[1].stop_daemon();
        donors[0].restart_daemon(&tmp.path().join("alice-old-prefix.err"));
        std::os::unix::net::UnixStream::connect(&release).expect("APPARATUS: release Accepted");
        join.join().unwrap()
    });
    if !first.ok {
        room.workers[2]
            .vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", &link],
                Some(ROOM_PASS),
            )
            .expect_ok("resume the retained Accepted witness");
    }
    let carol = &room.workers[2];
    until(
        &room.workers[0],
        None,
        "alice learns readmission after bob stops",
        &["room", "roster", &id],
        |o| o.ok && o.stdout.contains(&carol_fp),
    );
    until(
        carol,
        None,
        "old-prefix donor returns carol's permitted history",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains("harness: ready carol "),
    );
    std::thread::sleep(std::time::Duration::from_secs(10));
    let post = carol.vox(None, &["room", "post", &id, "must not cross signed extent"]);
    assert!(
        !post.ok && post.stderr.contains("own history"),
        "PRODUCT: wrote past an unrecovered signed extent: {post:?}"
    );
    room.workers[1].restart_daemon(&tmp.path().join("bob-new-prefix.err"));
    until(
        &room.workers[2],
        None,
        "post after the signed extent is recovered",
        &["room", "post", &id, "after signed extent recovery"],
        |o| o.ok,
    );
    until(
        &room.workers[1],
        None,
        "bob reads post after signed extent recovery",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains("after signed extent recovery"),
    );
}

#[cfg(feature = "test-knobs")]
#[test]
#[ignore = "real daemons and interrupted Accepted; run in release"]
fn cancelled_accepted_return_is_removed_from_the_roster() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    let tmp = support::diagnostic_tempdir();
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let id = room.id.clone();
    let carol_fp = room.workers[2].b32();
    room.workers[2]
        .vox(None, &["room", "leave", &id])
        .expect_ok("first leave");
    for worker in &room.workers[..2] {
        until(
            worker,
            None,
            "original departure",
            &["room", "roster", &id],
            |o| o.ok && !o.stdout.contains(&carol_fp),
        );
    }
    let mutant = std::env::var("VOX_MUTANT_FX28").unwrap_or_default();
    room.workers[1].restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_FX28_MUTANT", &mutant)],
        &tmp.path().join("bob-veto.err"),
    );
    let link = until(
        &room.workers[1],
        None,
        "bob reopens and offers a link",
        &["room", "link", &id],
        |o| o.ok,
    )
    .stdout
    .trim()
    .to_owned();
    room.workers[2].restart_daemon_as(
        support::VOX,
        &[("VOX_TEST_FAIL_RETAINED_ACCEPTED", "1")],
        &tmp.path().join("carol-accepted.err"),
    );
    let join = room.workers[2].vox_in(
        None,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(ROOM_PASS),
    );
    assert!(
        !join.ok,
        "APPARATUS: interruption did not stop Accepted: {join:?}"
    );
    until(
        &room.workers[1],
        None,
        "bob sees witnessed readmission",
        &["room", "roster", &id],
        |o| o.ok && o.stdout.contains(&carol_fp),
    );
    room.workers[2]
        .vox(None, &["room", "leave", &id])
        .expect_ok("cancel retained Accepted");
    until(
        &room.workers[1],
        None,
        "cancelled Accepted return to leave bob's roster",
        &["room", "roster", &id],
        |o| o.ok && !o.stdout.contains(&carol_fp),
    );
}
