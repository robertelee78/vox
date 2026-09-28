//! V210-57 (#243) — **an anchor that goes away is redialled at once, not on a 30-second tick**,
//! through the shipped binary.
//!
//! A node's anchor is its board and its relay: without it, a node reaches nobody it cannot dial
//! directly. The only redial used to run once every `ANCHOR_REDIAL_SECS` (30 s), so a node that lost
//! its anchor stayed without one for up to 30 s. CI run 36418572653 had a relayed first connection
//! take 30065 ms that way. A lost anchor is now dialled on the next tick, and only one that keeps
//! failing is backed off.
//!
//! **The scene** (`support/relay.rs`, `Split::Families`, so the only path is a circuit through the
//! anchor): the host serves an echo and the guest's `vox forward` carries it. A few seconds after
//! the forward started, the anchor is **stopped** (SIGINT, as a person stops it: it closes every
//! connection, so its peers learn at once that it is gone, which is the shape of CI's red, where the
//! anchor *closed* a connection) and brought back [`DOWN`] later **on the same port**. It is a new
//! process, so every connection to the old one is gone. The forward must carry an echo again within
//! [`BACK_WITHIN`] of the anchor's return, and say it saw the anchor go.
//!
//! **Not covered: an anchor that crashes.** A crash sends no close, so its peers learn of it only
//! when its connection falls silent (`SILENCE_IS_DEATH`). How soon a node *learns* of a loss is not
//! what #243 changed; how soon it *acts* on one is.
//!
//! **Why the bound separates the two:** the old redial ran at the node's start and then every 30 s,
//! so a forward started at `t` redialled at `t + 30`. The anchor returns at about `t + 9`, so the
//! old code comes back about 20 s later, well past [`BACK_WITHIN`].
//!
//! Mutation: the 30 s gate restored (a lost anchor waits for the next half-minute) → red.

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

/// How long after the forward starts the anchor is killed: long enough that the forward has its
/// anchor connection and its circuit, and short of the old 30 s tick.
const KILL_AFTER: Duration = Duration::from_secs(4);
/// How long the anchor stays down.
const DOWN: Duration = Duration::from_secs(3);
/// How soon after the anchor is back the forward must carry an echo again. The new code needs a
/// tick, a dial, and the host's own redial; the old code needed about 20 s more.
const BACK_WITHIN: Duration = Duration::from_secs(10);
/// What a node says when its anchor connection goes.
const GONE: &str = "the connection to this anchor is gone";

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_anchor_that_restarts_is_redialled_promptly() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let started = Instant::now();
    let at = w.forward();
    let first = round_trip(at, b"before", Duration::from_secs(30));
    assert!(
        first.as_deref().is_ok_and(|b| b == b"before"),
        "CANNOT PROVE: no echo through the forward before the anchor went: {first:?}\n{}",
        w.fwd.as_mut().unwrap().transcript()
    );
    w.expect_still_relayed();
    std::thread::sleep(KILL_AFTER.saturating_sub(started.elapsed()));

    // ---- the anchor is stopped, and comes back on the same port --------------------------------
    let anchor_dir = w.tmp.path().join("anchor");
    let killed = Instant::now();
    let _ = std::process::Command::new("kill")
        .args(["-INT", &w.anchor.proc.child.id().to_string()])
        .status();
    let stopping = Instant::now();
    while w.anchor.proc.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: the anchor did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(DOWN);
    w.anchor.restart(&anchor_dir);
    let back = Instant::now();
    eprintln!(
        "[proof] the anchor was stopped {:?} after the forward started, and is back {:?} later",
        killed.duration_since(started),
        back.duration_since(killed)
    );

    // ---- the forward carries again within BACK_WITHIN -----------------------------------------
    let mut carried = None;
    while back.elapsed() < BACK_WITHIN + Duration::from_secs(20) {
        if round_trip(at, b"after", Duration::from_secs(2)).is_ok_and(|b| b == b"after") {
            carried = Some(back.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let said = w.fwd.as_mut().unwrap().transcript();
    let saw_it_go = said.lines().any(|l| l.contains(GONE));
    eprintln!(
        "[proof] the forward carried again {carried:?} after the anchor was back (bound \
         {BACK_WITHIN:?}); it said its anchor went: {saw_it_go}"
    );
    let carried = carried.unwrap_or_else(|| {
        panic!(
            "the forward never carried again within {:?} of the anchor's return\n---- the forward \
             ----\n{said}\n---- the anchor ----\n{}",
            BACK_WITHIN + Duration::from_secs(20),
            w.anchor.proc.transcript()
        )
    });
    assert!(
        carried < BACK_WITHIN,
        "the forward carried again only {carried:?} after its anchor was back, over {BACK_WITHIN:?}: \
         a lost anchor waited for a periodic redial\n---- the forward ----\n{said}"
    );
    assert!(
        saw_it_go,
        "the forward did not say its anchor connection went ({GONE:?})\n{said}"
    );
}
