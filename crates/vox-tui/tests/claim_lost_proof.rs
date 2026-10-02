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
//!
//! **Every notice is information, never an order** (V210-131, the decider: "github is the
//! authority, vox is the nagging reminder"). A room claim records nothing; the work item's
//! GitHub issue, maintained through awa, is the only record of who holds a task. So each
//! notice names the issue as the authority and never tells the agent to stop work: the
//! notice this replaced said "Stop work on it", and putting that text back turns this red.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use support::{until, Out, Worker};

/// What a lapse notice must say instead of an order: the issue decides.
const AUTHORITY: &str = "the work item's GitHub issue says who holds the task";

/// A lapse notice is information that points at the issue, never an order to stop.
fn points_at_the_issue(told: &str, what: &str) {
    assert!(
        told.contains(AUTHORITY),
        "PRODUCT: the {what} notice does not name the GitHub issue as the authority: {told:?}"
    );
    assert!(
        !told.contains("Stop work") && !told.contains("or stop"),
        "PRODUCT: the {what} notice orders the agent to stop work, though a room claim \
         records nothing: {told:?}"
    );
}

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
        !quiet.contains("room claim on"),
        "PRODUCT: a session whose claims did not change must be told nothing: {quiet:?}"
    );

    // ---- (2) a lapse is reported, once ----
    std::thread::sleep(Duration::from_secs(4));
    let told = drain(alice, r, "s1");
    assert!(
        told.contains("Your room claim on `lapses` lapsed"),
        "PRODUCT: a lapsed claim must be reported with its reason: {told:?}"
    );
    points_at_the_issue(&told, "lapse");
    assert!(
        !told.contains("`kept`"),
        "PRODUCT: a claim still held must not be reported: {told:?}"
    );
    let again = drain(alice, r, "s1");
    assert!(
        !again.contains("room claim on"),
        "PRODUCT: the loss must be reported once, not every turn: {again:?}"
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
        told.contains("Your room claim on `taken` lapsed, and ")
            && told.contains("has since claimed it in the room")
            && told.contains(&format!("{}/b1", &bob_fp[..26])),
        "PRODUCT: a claim someone else now holds must name the holder: {told:?}"
    );
    points_at_the_issue(&told, "taken-over");

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
            "Your room claim on `reserved` lapsed, and it is now reserved in the room for"
        ) && told.contains(&format!("{}/s9", &alice_fp[..26])),
        "PRODUCT: a lapsed claim now reserved by a handoff must say so and name the recipient: {told:?}"
    );
    points_at_the_issue(&told, "reserved");

    // ---- (4) a session's own release is not news — with a positive control ----
    claim(alice, "s1", r, "mine", "600");
    claim(alice, "s1", r, "gone", "2");
    let _ = drain(alice, r, "s1");
    let o = alice.vox(Some("s1"), &["room", "release", r, "mine"]);
    assert!(o.ok, "{o:?}");
    std::thread::sleep(Duration::from_secs(4));
    let told = drain(alice, r, "s1");
    assert!(
        told.contains("Your room claim on `gone` lapsed"),
        "PRODUCT: the positive control: the same drain must report the lapse of `gone`: {told:?}"
    );
    assert!(
        !told.contains("`mine`"),
        "PRODUCT: a session's own release must not be reported back to it: {told:?}"
    );
}
