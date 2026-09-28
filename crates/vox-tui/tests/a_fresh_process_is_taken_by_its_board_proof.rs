//! **A fresh process's address is taken by its board**, through the shipped binary.
//!
//! A board replaces a member's record only with a later `timestamp`, in whole seconds — ADR-012's
//! bound of one changed claim a second per author (`nat::store::check_replacement`). A process that
//! starts within the second its predecessor last published in signs its first record in that same
//! second, and the board refused it as stale. Every cold `vox forward` on integrate 1de7548 logged
//! `a board would not take our address … the board holds a newer record from that author`, and
//! the board went on naming the previous, dead process's address until the next publish round.
//!
//! The node now publishes its own record again just past the next second when a board refuses it
//! as stale (`NetEvent::RepublishTo`), and a refusal no republish cures is said once its short grace
//! is over (`NetEvent::StaleGraceOver`) — held, never dropped.
//!
//! **The scene.** A host serves an echo; a guest joins; then [`SAMPLES`] cold `vox forward`s run one
//! after another from the guest's profile, each a new process started as soon as the last one is
//! killed. An echo crosses each, and each is kept alive past [`WATCH`] — longer than the grace and
//! the republishes — before its transcript is read.
//!
//! **What must hold:** no forward says a board would not take its address.
//!
//! **What a green run cannot show by itself** is that the refusal happened: cured, it is never said.
//! The mutation shows it: with the republish removed, the refusal is not cured, its grace ends, and
//! the forward says it (red).
//!
//! Mutation: `NetEvent::RepublishTo` does nothing — red, `a board would not take our address`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::round_trip;

/// Cold forwards, one after another.
const SAMPLES: usize = 5;
/// How long each forward is kept alive before its transcript is read: past the node's grace for a
/// stale refusal (5 s) and its republishes (one a second, three at most).
const WATCH: Duration = Duration::from_secs(10);
/// What a node prints when a board would not take its own address.
const REFUSED: &str = "would not take our address";

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_fresh_process_is_taken_by_its_board() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join ({took:?}).\n{out}\n{err}"
    );

    let mut refused: Vec<String> = Vec::new();
    for n in 0..SAMPLES {
        // A fresh `vox forward`, started as soon as the previous one is killed by its PID.
        drop(w.fwd.take());
        let started = Instant::now();
        let at = w.forward();
        let payload = format!("sample {n}");
        let back =
            round_trip(at, payload.as_bytes(), Duration::from_secs(120)).unwrap_or_else(|e| {
                panic!(
                    "CANNOT PROVE (sample {n}): no echo through the forward ({e}).\n{}",
                    w.fwd.as_mut().unwrap().transcript()
                )
            });
        assert_eq!(
            back,
            payload.as_bytes(),
            "sample {n}: the echo came back changed"
        );
        std::thread::sleep(WATCH.saturating_sub(started.elapsed()));
        let said = w.fwd.as_mut().unwrap().transcript();
        let lines: Vec<&str> = said.lines().filter(|l| l.contains(REFUSED)).collect();
        eprintln!(
            "[proof] sample {n}: {} line(s) saying a board would not take its address",
            lines.len()
        );
        refused.extend(lines.iter().map(|l| format!("sample {n}: {l}")));
    }
    assert!(
        refused.is_empty(),
        "a fresh process's address was left refused by its board:\n{}",
        refused.join("\n")
    );
}
