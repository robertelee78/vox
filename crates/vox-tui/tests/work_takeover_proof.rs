//! PRD-001 R17 (ADR-021 §9) — **a silent holder's claim can be taken over; a holder who
//! answers keeps it**, through the shipped `vox` binary on two nodes.
//!
//! 1. The filer marks `t-silent` hard-locked with a 3 s takeover window; alice holds it;
//!    bob asks to take it over; alice says nothing; after the window **both nodes** show
//!    bob's session holding it.
//! 2. On `t-answered` (a 6 s window) alice answers with `keep` inside the window, and
//!    still holds it after the window has passed.
//! 3. An unmarked resource uses the default window (600 s): the request is pending, not
//!    transferred.
//! 4. A second takeover while one is pending is refused (exit 1).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use support::{resource, until, Out, Worker};

fn board(w: &Worker, r: &str) -> serde_json::Value {
    let o = w.vox(None, &["room", "board", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.json()
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_silent_holder_is_taken_over_and_an_answering_one_is_not() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();
    let (a_fp, b_fp) = (alice.b32(), bob.b32());

    // ---- (1) silent holder ----
    assert!(
        alice
            .vox(
                Some("a1"),
                &["room", "lock", r, "t-silent", "--takeover-secs", "3"]
            )
            .ok
    );
    assert!(alice.vox(Some("a1"), &["room", "claim", r, "t-silent"]).ok);
    until(
        bob,
        None,
        "alice's claim to reach bob",
        &["room", "board", r, "--json"],
        |o: &Out| o.ok && resource(&o.json(), "t-silent").is_some(),
    );
    let o = bob.vox(Some("b1"), &["room", "takeover", r, "t-silent"]);
    assert!(o.ok && o.stdout.contains("transfers to you"), "{o:?}");
    // ---- (4) a second request while one is pending ----
    let o = bob.vox(Some("b2"), &["room", "takeover", r, "t-silent"]);
    assert_eq!(
        o.code,
        Some(1),
        "a second pending takeover must be refused: {o:?}"
    );
    std::thread::sleep(Duration::from_secs(5));
    for w in [alice, bob] {
        let b = until(
            w,
            None,
            "the takeover to settle",
            &["room", "board", r, "--json"],
            |o: &Out| {
                o.ok && resource(&o.json(), "t-silent").is_some_and(|x| x["owner_fp"] == b_fp)
            },
        )
        .json();
        let x = resource(&b, "t-silent").unwrap();
        assert_eq!(
            x["owner_session"], "b1",
            "{}: the silent holder's claim must transfer to the requester: {b}",
            w.name
        );
    }

    // ---- (2) a holder who answers keeps it ----
    assert!(
        alice
            .vox(
                Some("a1"),
                &["room", "lock", r, "t-answered", "--takeover-secs", "6"]
            )
            .ok
    );
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "t-answered"])
            .ok
    );
    until(
        bob,
        None,
        "the second claim to reach bob",
        &["room", "board", r, "--json"],
        |o: &Out| o.ok && resource(&o.json(), "t-answered").is_some(),
    );
    assert!(
        bob.vox(Some("b1"), &["room", "takeover", r, "t-answered"])
            .ok
    );
    until(
        alice,
        None,
        "the takeover request to reach alice",
        &["room", "board", r, "--json"],
        |o: &Out| {
            o.ok && resource(&o.json(), "t-answered").is_some_and(|x| !x["takeover"].is_null())
        },
    );
    let o = alice.vox(Some("a1"), &["room", "keep", r, "t-answered"]);
    assert!(o.ok && o.stdout.contains("you keep"), "{o:?}");
    std::thread::sleep(Duration::from_secs(8));
    for w in [alice, bob] {
        let b = board(w, r);
        let x = resource(&b, "t-answered")
            .unwrap_or_else(|| panic!("{}: t-answered vanished: {b}", w.name));
        assert_eq!(
            x["owner_fp"], a_fp,
            "{}: a holder who answered must keep the claim: {b}",
            w.name
        );
        assert!(
            x["takeover"].is_null(),
            "{}: the answered request must be cleared: {b}",
            w.name
        );
    }

    // ---- (3) an unmarked resource uses the default window ----
    assert!(alice.vox(Some("a1"), &["room", "claim", r, "t-default"]).ok);
    until(
        bob,
        None,
        "the third claim to reach bob",
        &["room", "board", r, "--json"],
        |o: &Out| o.ok && resource(&o.json(), "t-default").is_some(),
    );
    assert!(
        bob.vox(Some("b1"), &["room", "takeover", r, "t-default"])
            .ok
    );
    let b = board(bob, r);
    let x = resource(&b, "t-default").unwrap();
    let left =
        x["takeover"]["deadline_millis"].as_u64().unwrap() - b["now_millis"].as_u64().unwrap();
    assert!(
        (590_000..=600_000).contains(&left),
        "default window must be 600 s, was {left} ms: {b}"
    );
    assert_eq!(x["owner_fp"], a_fp, "pending, not transferred");
}
