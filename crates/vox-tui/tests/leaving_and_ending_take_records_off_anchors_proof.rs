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
//! - alice, the creator, makes bob and carol admins and takes carol's back (`vox room admin`);
//!   carol's node then runs the mutant sender build in its `withdraw-unentitled` mode — the faulty
//!   peer a board must not obey — and `vox room end` makes it put a room withdraw it is not
//!   entitled to: [`SETTLE`] later the board still holds the room with all three members;
//! - carol leaves: within [`WITHIN`] the board holds two, and still two [`SETTLE`] later, while
//!   alice and bob post, sync and publish — nothing put carol's records back;
//! - bob, a current admin, ends the room: within [`WITHIN`] the board no longer holds it at all,
//!   and still not [`SETTLE`] later.
//!
//! Every red names which it is: `PRODUCT:` quotes what the anchor said; `PRODUCT (staging):` a
//! `vox` step of the staging that failed; `APPARATUS:` a setup that did not hold (the mutant sender
//! build missing, its withdraw never put), so nothing was measured.
//!
//! **Mutations that must turn it red:** a board that answers a withdraw and keeps the records; a
//! board that takes a room withdraw from any member, not only the creator and its current admins.

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
    let line = text.lines().rfind(|l| {
        l.starts_with("vox node: board — ") && !l.contains(" holding ") && !l.contains(" holds ")
    })?;
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
#[ignore = "a real anchor, real daemons and the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_leave_and_an_end_take_their_records_off_the_anchor() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: no tokio runtime: {e}"));
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
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
    let mut room = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]))
    }))
    .unwrap_or_else(|_| panic!("PRODUCT (staging): the room could not be set up"));
    let id = room.id.clone();
    let id = id.as_str();
    let short: String = id.chars().take(12).collect();
    let out = tmp.path().join("anchor.out");
    let anchor = || std::fs::read_to_string(&out).unwrap_or_default();

    let (held, n) = board_until(&out, &short, WITHIN, |n| n == Some(3));
    assert!(
        held,
        "APPARATUS: the anchor's board never held the room with its three members (last: {n:?}), \
         so a withdraw could not be seen.\nanchor:\n{}",
        anchor()
    );

    // The creator names bob and carol admins and takes carol's back; it puts each roster on the
    // boards.
    {
        let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
        for (what, member) in [("add", bob), ("add", carol), ("remove", carol)] {
            let o = alice.vox(None, &["room", "admin", what, id, &member.b32()]);
            assert!(
                o.ok,
                "PRODUCT (staging): `vox room admin {what}` {} was refused: {o:?}",
                member.name
            );
        }
    }
    // Carol, an admin no longer, runs the faulty build: it takes the room off boards anyway. Its
    // withdraw goes to the anchors it is connected to when it ends the room, so the end is asked
    // again until the faulty node says it put the withdraw to one. Not waited for on the anchor's
    // `holding` line: a node restarted on the port it kept (V210-167) puts the same address, and
    // the board prints nothing new.
    let carol_err = tmp.path().join("carol.mutant.err");
    room.workers[2].restart_daemon_as(
        &mutant,
        &[("VOX_MUTANT_SENDER_MODE", "withdraw-unentitled")],
        &carol_err,
    );
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    // **Carol's own node holds her admin's revocation before she is asked to end the room.** A
    // node decides who may end a room from the log it holds (ADR-007); until alice's revocation
    // has synced to carol, carol's node still lists her as an admin and rightly writes the end — an
    // end every node holding the revocation refuses (removal wins). Asked before the sync, this arm
    // measured the sync's timing, not the refusal: red 2 runs in 4 under load, carol's node then
    // listing three admins.
    let carol_fp = carol.b32();
    let synced = Instant::now() + WITHIN;
    loop {
        let admins = carol.vox(None, &["room", "admin", "list", id]);
        if admins.ok && !admins.stdout.contains(&carol_fp) {
            break;
        }
        assert!(
            Instant::now() < synced,
            "PRODUCT (staging): carol's node never held alice's revocation of her admin within \
             {WITHIN:?}: it lists {admins:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let deadline = Instant::now() + WITHIN;
    let put_to = loop {
        // Who carol's own node holds as the room's admins as it is asked to end it: what its
        // refusal, or not, rests on.
        let admins = carol.vox(None, &["room", "admin", "list", id]);
        let o = carol.vox(None, &["room", "end", id]);
        assert!(
            !o.ok,
            "PRODUCT: carol, whose admin was taken back, was not refused `vox room end`: {o:?}\n\
             carol's node holds as the room's admins: {admins:?}"
        );
        let said = std::fs::read_to_string(&carol_err).unwrap_or_default();
        let put_to = said
            .lines()
            .filter_map(|l| {
                l.split_once("put a room withdraw for ")?
                    .1
                    .split(" to ")
                    .nth(1)
            })
            .filter_map(|rest| rest.split(' ').next()?.parse::<usize>().ok())
            .max();
        if put_to.is_some_and(|n| n > 0) || Instant::now() >= deadline {
            break put_to;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    assert!(
        put_to.is_some_and(|n| n > 0),
        "APPARATUS: carol's faulty node did not put its room withdraw to an anchor within \
         {WITHIN:?} (anchors: {put_to:?}), so a board's refusal of it was not staged. It \
         said:\n{}",
        std::fs::read_to_string(&carol_err).unwrap_or_default()
    );
    // The faulty node says what the board answered its put: an answer is what makes the board's
    // count below a verdict on the board rather than on a put that never arrived.
    let deadline = Instant::now() + WITHIN;
    let answer = loop {
        let said = std::fs::read_to_string(&carol_err).unwrap_or_default();
        let answers: Vec<String> = said
            .lines()
            .filter_map(|l| {
                l.split_once("a board answered a withdraw: ")
                    .map(|(_, a)| a.to_owned())
            })
            .collect();
        if let Some(a) = answers.iter().find(|a| !a.starts_with("no answer")) {
            break a.clone();
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: no board answered carol's room withdraw within {WITHIN:?}, so a board's \
             refusal of it was not staged. It said:\n{said}"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let (moved, n) = board_until(&out, &short, SETTLE, |n| n != Some(3));
    assert!(
        !moved && answer.starts_with("refused"),
        "PRODUCT: the anchor took a room withdraw from carol, whose admin was taken back: it \
         answered {answer:?} and its board now counts {n:?}.\nanchor:\n{}",
        anchor()
    );
    eprintln!(
        "[proof] withdraw: the anchor refused a removed admin's room withdraw ({answer}); still 3 \
         members {SETTLE:?} later"
    );

    let o = carol.vox(None, &["room", "leave", id]);
    assert!(o.ok, "PRODUCT: `vox room leave` was refused: {o:?}");
    let t = Instant::now();
    let (gone, n) = board_until(&out, &short, WITHIN, |n| n == Some(2));
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after carol left, the anchor's board still counts {n:?} member(s) \
         for the room, not 2.\nanchor:\n{}",
        anchor()
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
        anchor()
    );
    eprintln!(
        "[proof] withdraw: carol's records left the anchor's board {:.1}s after her leave, and \
         stayed off {SETTLE:?}",
        took.as_secs_f64()
    );

    let o = bob.vox(None, &["room", "end", id]);
    assert!(
        o.ok,
        "PRODUCT: bob's `vox room end`, as a current admin, was refused: {o:?}"
    );
    let t = Instant::now();
    let (gone, n) = board_until(&out, &short, WITHIN, |n| n.is_none());
    assert!(
        gone,
        "PRODUCT: {WITHIN:?} after bob, an admin, ended the room, the anchor's board still holds it \
         ({n:?} member(s)).\nanchor:\n{}",
        anchor()
    );
    let took = t.elapsed();
    let (back, n) = board_until(&out, &short, SETTLE, |n| n.is_some());
    assert!(
        !back,
        "PRODUCT: the ended room came back on the anchor's board ({n:?} member(s)).\nanchor:\n{}",
        anchor()
    );
    eprintln!(
        "[proof] withdraw: the room left the anchor's board {:.1}s after an admin ended it, and \
         stayed off {SETTLE:?}",
        took.as_secs_f64()
    );
}
