//! ADR-021 **M21.9** — **the drain says when a claim was lost**, through the shipped `vox`
//! binary and its real drain hook (`vox agent hook`).
//!
//! A lapse, a takeover or a completed handoff ends a session's ownership without any
//! message addressed to it, so a busy holder can keep working on something it no longer
//! owns. The per-turn drain is the one place every session reads without being asked, so
//! it is where the loss is said — once, with the reason:
//!
//! 1. a session whose claims did not change is told nothing;
//! 2. a claim that **lapsed** between two drains is reported, naming the resource and the
//!    lapse — and only on the first drain after it;
//! 3. a claim that lapsed and **someone else now holds**, or that lapsed and is now
//!    **reserved** for someone by a handoff, is reported with the lapse and who has it;
//! 4. a claim the session **released itself** is not news, and is not reported — in the
//!    same drain that does report a lapse, so the silence is a decision, not a dead drain.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use support::{until, Out, Worker};

/// One turn's drain for `session`, as a harness hook runs it.
fn drain(w: &Worker, r: &str, session: &str) -> String {
    let o = w.vox(
        Some(session),
        &[
            "agent",
            "hook",
            "--room",
            r,
            "--format",
            "text",
            "--session",
            session,
        ],
    );
    assert!(o.ok, "the drain hook must not fail: {o:?}");
    o.stdout
}

fn claim(w: &Worker, session: &str, r: &str, res: &str, ttl: &str) {
    let o = w.vox(Some(session), &["room", "claim", r, res, "--ttl", ttl]);
    assert!(o.ok, "{session} must win {res}: {o:?}");
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn the_drain_says_once_when_a_claim_was_lost_and_why() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // ---- (1) held and unchanged: nothing ----
    claim(alice, "s1", r, "kept", "600");
    claim(alice, "s1", r, "lapses", "2");
    let _ = drain(alice, r, "s1"); // records what s1 holds
    let quiet = drain(alice, r, "s1");
    assert!(
        !quiet.contains("no longer hold"),
        "a session whose claims did not change must be told nothing: {quiet:?}"
    );

    // ---- (2) a lapse is reported, once ----
    std::thread::sleep(Duration::from_secs(4));
    let told = drain(alice, r, "s1");
    assert!(
        told.contains("You no longer hold `lapses`") && told.contains("lapsed"),
        "a lapsed claim must be reported with its reason: {told:?}"
    );
    assert!(
        !told.contains("`kept`"),
        "a claim still held must not be reported: {told:?}"
    );
    let again = drain(alice, r, "s1");
    assert!(
        !again.contains("no longer hold"),
        "the loss must be reported once, not every turn: {again:?}"
    );

    // ---- (3) someone else now holds it ----
    claim(alice, "s1", r, "taken", "2");
    let _ = drain(alice, r, "s1");
    std::thread::sleep(Duration::from_secs(4));
    until(
        bob,
        Some("b1"),
        "bob to take the lapsed claim",
        &["room", "claim", r, "taken", "--ttl", "600"],
        |o: &Out| o.ok,
    );
    let bob_fp = bob.b32();
    until(
        alice,
        Some("s1"),
        "alice's node to see bob's claim",
        &["room", "board", r, "--json"],
        |o: &Out| {
            o.ok && support::resource(&o.json(), "taken")
                .is_some_and(|x| x["owner_session"] == "b1")
        },
    );
    let told = drain(alice, r, "s1");
    assert!(
        told.contains("You no longer hold `taken`: your claim lapsed, and it is now held by")
            && told.contains(&format!("{}/b1", &bob_fp[..26])),
        "a claim someone else now holds must name the holder: {told:?}"
    );

    // ---- (3b) lapsed, then reserved for someone by a handoff ----
    claim(alice, "s1", r, "reserved", "2");
    let _ = drain(alice, r, "s1");
    std::thread::sleep(Duration::from_secs(4));
    until(
        bob,
        Some("b1"),
        "bob to take the lapsed claim",
        &["room", "claim", r, "reserved", "--ttl", "600"],
        |o: &Out| o.ok,
    );
    let alice_fp = alice.b32();
    let o = bob.vox(
        Some("b1"),
        &[
            "room",
            "handoff",
            r,
            "reserved",
            "--to",
            &alice_fp[..16],
            "--to-session",
            "s9",
        ],
    );
    assert!(o.ok, "{o:?}");
    until(
        alice,
        Some("s1"),
        "alice's node to see the handoff",
        &["room", "board", r, "--json"],
        |o: &Out| {
            o.ok && support::resource(&o.json(), "reserved")
                .is_some_and(|x| x["state"] == "pending")
        },
    );
    let told = drain(alice, r, "s1");
    assert!(
        told.contains(
            "You no longer hold `reserved`: your claim lapsed, and it is now reserved for"
        ) && told.contains(&format!("{}/s9", &alice_fp[..26])),
        "a lapsed claim now reserved by a handoff must say so and name the recipient: {told:?}"
    );

    // ---- (4) a session's own release is not news — with a positive control ----
    claim(alice, "s1", r, "mine", "600");
    claim(alice, "s1", r, "gone", "2");
    let _ = drain(alice, r, "s1");
    let o = alice.vox(Some("s1"), &["room", "release", r, "mine"]);
    assert!(o.ok, "{o:?}");
    std::thread::sleep(Duration::from_secs(4));
    let told = drain(alice, r, "s1");
    assert!(
        told.contains("You no longer hold `gone`"),
        "the positive control: the same drain must report the lapse of `gone`: {told:?}"
    );
    assert!(
        !told.contains("`mine`"),
        "a session's own release must not be reported back to it: {told:?}"
    );
}
