//! V030-14 (#320) — **a leave or an end takes its records off anchors at once**, driven through
//! the shipped `vox` binary: a real `vox node` anchor and real `vox daemon`s in one room, every
//! verb a separate `vox` process, and the anchor's board read as its operator reads it — the
//! `vox node: board — <room> <N>m/…` line it prints whenever what it holds changes.
//!
//! **Why.** A board holds no log. It kept a room's genesis for good and a member's records until
//! they lapsed — two hours for an address, seven days for a bundle — and members that still
//! mirrored them put them back. The decider (2026-10-01): "leave and end remove the member's and
//! room's records from anchors at once".
//!
//! **Asserted:**
//! - before anything, the anchor's board holds the room with its three members (the control);
//! - carol leaves: within [`WITHIN`] the board holds two, and still two [`SETTLE`] later, while
//!   alice and bob post, sync and publish — nothing put carol's records back;
//! - alice, the creator, ends the room: within [`WITHIN`] the board no longer holds it at all, and
//!   still not [`SETTLE`] later.
//!
//! Every red names which it is: `PRODUCT:` quotes what the anchor said; `APPARATUS:` is a setup
//! that did not hold (the room never reached the board), so nothing was measured.
//!
//! **Mutation that must turn it red:** a board that answers a withdraw and keeps the records.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

/// How long the anchor may take to act on a withdraw: the put the leaving or ending node makes
/// at once.
const WITHIN: Duration = Duration::from_secs(20);
/// How long the board is watched afterwards for records coming back.
const SETTLE: Duration = Duration::from_secs(15);

/// What the anchor's board holds for `room` (its short id) now: `Some(members)` from the last
/// `vox node: board — …` line it printed, `None` when that line does not name the room.
fn board_members(out: &std::path::Path, short: &str) -> Option<usize> {
    let text = std::fs::read_to_string(out).unwrap_or_default();
    let line = text
        .lines()
        .filter(|l| {
            l.starts_with("vox node: board — ")
                && !l.contains(" holding ")
                && !l.contains(" holds ")
        })
        .next_back()?;
    line.trim_start_matches("vox node: board — ")
        .split(", ")
        .find_map(|entry| {
            let (id, counts) = entry.split_once(' ')?;
            (id == short).then(|| counts.split('m').next()?.parse().ok())?
        })
}

/// Poll the board until `want` holds for `within`; the last value either way.
fn board_until(
    out: &std::path::Path,
    short: &str,
    within: Duration,
    want: impl Fn(Option<usize>) -> bool,
) -> (bool, Option<usize>) {
    let deadline = Instant::now() + within;
    loop {
        let now = board_members(out, short);
        if want(now) {
            return (true, now);
        }
        if Instant::now() >= deadline {
            return (false, now);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
#[ignore = "a real anchor and real daemons, production Argon2id; CI runs it in release"]
fn a_leave_and_an_end_take_their_records_off_the_anchor() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: no tokio runtime: {e}"));
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let room = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]))
    }))
    .unwrap_or_else(|_| panic!("APPARATUS: the room could not be set up, so nothing was measured"));
    let [alice, bob, carol] = &room.workers[..] else {
        unreachable!()
    };
    let id = room.id.as_str();
    let short: String = id.chars().take(12).collect();
    let out = tmp.path().join("anchor.out");

    let (held, n) = board_until(&out, &short, WITHIN, |n| n == Some(3));
    assert!(
        held,
        "APPARATUS: the anchor's board never held the room with its three members (last: {n:?}), \
         so a withdraw could not be seen.\nanchor:\n{}",
        std::fs::read_to_string(&out).unwrap_or_default()
    );

    let o = carol.vox(None, &["room", "leave", id]);
    assert!(o.ok, "PRODUCT: `vox room leave` was refused: {o:?}");
    let t = Instant::now();
    let (gone, n) = board_until(&out, &short, WITHIN, |n| n == Some(2));
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after carol left, the anchor's board still counts {n:?} member(s) \
         for the room, not 2.\nanchor:\n{}",
        std::fs::read_to_string(&out).unwrap_or_default()
    );
    let took = t.elapsed();
    for i in 0..3 {
        let _ = alice.vox(
            None,
            &["room", "post", id, &format!("after carol left {i}")],
        );
        let _ = bob.vox(
            None,
            &["room", "post", id, &format!("bob after carol left {i}")],
        );
    }
    let (back, n) = board_until(&out, &short, SETTLE, |n| n != Some(2));
    assert!(
        !back,
        "PRODUCT: carol's records came back on the anchor's board after her leave took them off: \
         it counts {n:?}.\nanchor:\n{}",
        std::fs::read_to_string(&out).unwrap_or_default()
    );
    eprintln!(
        "[proof] withdraw: carol's records left the anchor's board {:.1}s after her leave, and \
         stayed off {SETTLE:?}",
        took.as_secs_f64()
    );

    let o = alice.vox(None, &["room", "end", id]);
    assert!(
        o.ok,
        "PRODUCT: the creator's `vox room end` was refused: {o:?}"
    );
    let t = Instant::now();
    let (gone, n) = board_until(&out, &short, WITHIN, |n| n.is_none());
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after the room ended, the anchor's board still holds it ({n:?} \
         member(s)).\nanchor:\n{}",
        std::fs::read_to_string(&out).unwrap_or_default()
    );
    let took = t.elapsed();
    let (back, n) = board_until(&out, &short, SETTLE, |n| n.is_some());
    assert!(
        !back,
        "PRODUCT: the ended room came back on the anchor's board ({n:?} member(s)).\nanchor:\n{}",
        std::fs::read_to_string(&out).unwrap_or_default()
    );
    eprintln!(
        "[proof] withdraw: the room left the anchor's board {:.1}s after its end, and stayed off \
         {SETTLE:?}",
        took.as_secs_f64()
    );
}
