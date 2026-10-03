//! V210-164 — **a node can leave a room**, through the shipped binary. Run on demand; not a gate.
//!
//! There was no way to leave a room: a node held every room it ever joined, and every other
//! member listed it for good. `vox room leave` writes the node's departure into the room, waits
//! for another member to have it, and removes the room from the node.
//!
//! **Staging.** `support/room.rs`: an anchor and three `vox daemon`s — alice, bob, carol — in one
//! room, each trusting the others, each having read a post by each other.
//!
//! **Asserted.**
//! 1. carol's `vox room leave` exits 0, and afterwards carol's `vox room list` does not name the
//!    room and `vox room read` of it fails: carol no longer holds or receives it.
//! 2. alice's and bob's `vox room roster` stop naming carol, and keep naming each other.
//! 3. carol's node stops syncing it: `vox status` names no sync port of the room after bob posts.
//! 4. Joining again works: carol joins, posts at once, is on alice's roster again, alice reads that
//!    post, and nobody shows carol having signed two entries at one place (a fork, which a post
//!    made before carol held her own earlier entries would be).
//!
//! **Mutations that must turn it red (PRODUCT).** `ChannelState::members` not leaving out a member
//! that left: assertion 2 fails naming carol on alice's roster. `ChannelState::catch_up_generation`
//! returning at once: assertion 4 fails, alice never reads carol's post.

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
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let id = room.id.clone();
    let carol_fp = carol.b32();

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

    // ---- 4. joining again works --------------------------------------------------------------
    let link = alice
        .vox(None, &["room", "invite", &id])
        .expect_ok("alice's `vox room invite`")
        .stdout
        .trim()
        .to_owned();
    carol
        .vox_in(
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
            Some(ROOM_PASS),
        )
        .expect_ok("carol joining again");
    let back = "carol, the moment the join returned";
    carol
        .vox(None, &["room", "post", &id, back])
        .expect_ok("carol's post right after joining again");
    until(
        alice,
        None,
        "carol back on the roster",
        &["room", "roster", &id],
        |o| o.ok && o.stdout.contains(&carol_fp),
    );
    let read = until(
        alice,
        None,
        "carol's post after she joined again",
        &["room", "read", &id],
        |o| o.ok && o.stdout.contains(back),
    );
    println!("[proof] alice reads:\n{}", read.stdout.trim());
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
