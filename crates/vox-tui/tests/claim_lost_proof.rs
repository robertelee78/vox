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
//! 3. a claim **someone else now holds** is reported as such, naming the holder;
//! 4. a claim the session **released itself** is not news, and is not reported.

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
        told.contains("You no longer hold `taken`: it is now held by")
            && told.contains(&format!("{}/b1", &bob_fp[..12])),
        "a claim someone else now holds must name the holder: {told:?}"
    );

    // ---- (4) a session's own release is not news ----
    claim(alice, "s1", r, "mine", "600");
    let _ = drain(alice, r, "s1");
    let o = alice.vox(Some("s1"), &["room", "release", r, "mine"]);
    assert!(o.ok, "{o:?}");
    let told = drain(alice, r, "s1");
    assert!(
        !told.contains("`mine`"),
        "a session's own release must not be reported back to it: {told:?}"
    );
}
