//! V210-71 (#262) — **a sync that runs past its drain budget keeps what arrived, and says so**,
//! through the shipped binary.
//!
//! A session drains the peer's entries for at most `DRAIN_BUDGET` (30 s), staging them and
//! applying up to 256 at a time. When the budget ran out, the session returned at once: every
//! staged entry was dropped, and the stop was reported as "sync mode unsupported" — a protocol
//! mismatch that did not happen. So a peer that serves slower than 256 entries in 30 s never
//! delivered anything: every session dropped what it had staged and started over.
//!
//! ## The mutant sender
//! Bob is `vox` built from this tree with vox-core's `mutant-sender` feature
//! (`scripts/build-mutant-sender.sh`, path in `VOX_MUTANT_SENDER`), started with
//! `VOX_MUTANT_SENDER_MODE=serve-slowly`: it serves what it is asked for, one frame a second, past
//! its own serve budget. No `vox` command can make a correct node serve slowly, which is why a
//! mutant peer plays it; Alice, the node under test, is the shipped binary.
//!
//! ## Staging
//! Two daemons, no anchor, each trusting the other; Alice creates a room and Bob joins it. Alice's
//! daemon is stopped (SIGSTOP by PID) while Bob posts [`POSTS`] messages, then continued, so her
//! first session with Bob asks for all of them at once.
//!
//! ## Asserted
//! 1. Within [`WITHIN`] of Alice continuing, she reads at least [`AT_LEAST`] of Bob's posts: what
//!    the first, over-budget session drained was applied.
//! 2. Her status names the stop: a sync failure reading "did not all arrive within 30s", and none
//!    reading "sync mode unsupported".
//!
//! Precondition (else `APPARATUS`: the mutant peer is the proof's own): Bob's daemon announced the
//! mutant mode.
//!
//! ## Mutation
//! Restore the early return in `frontier_session_room`'s drain (drop the staged entries, return
//! `SyncModeUnsupported`): each 30 s session applies nothing, so (1) goes red with 0 read.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{announced, failures, mutant_sender, Member};

const MODE: &str = "serve-slowly";
/// Bob's backlog: at one frame a second, more than a 30 s drain can take.
const POSTS: usize = 45;
/// From Alice continuing to the verdict: one over-budget session and change.
const WITHIN: Duration = Duration::from_secs(45);
/// A 30 s drain at one frame a second takes about 29; this leaves room for the session's start.
const AT_LEAST: usize = 20;

#[test]
#[ignore = "a real daemon against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_slow_sender_still_delivers_what_arrived() {
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(None);
    let bob_d = bob.daemon_mutant(&sender, MODE, None);
    let room = alice.create("slow");
    bob.join(&alice.invite(&room), "slow");
    bob.post(&room, "hello from bob");
    let mut reader = alice.reader();
    let cid = reader.room(&room);
    let warm = Instant::now();
    while !reader.has(cid, "hello from bob") {
        assert!(
            warm.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): alice never read bob's first post\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        announced(&bob_d, MODE),
        "APPARATUS: the mutant sender (bob's daemon) never announced the mutant mode {MODE:?}\nbob:\n{}",
        bob_d.transcript()
    );

    alice_d.signal("-STOP");
    for i in 1..=POSTS {
        bob.post(&room, &format!("backlog {i}"));
    }
    alice_d.signal("-CONT");
    let t0 = Instant::now();
    let mut read = 0;
    while t0.elapsed() < WITHIN {
        read = reader
            .texts(cid)
            .iter()
            .filter(|t| t.starts_with("backlog "))
            .count();
        std::thread::sleep(Duration::from_millis(500));
    }
    let said = failures(&alice.status());
    println!(
        "[proof] alice read {read} of bob's {POSTS} backlog posts within {WITHIN:?} of continuing; \
         her sync failures: {said:?}"
    );
    assert!(
        read >= AT_LEAST,
        "PRODUCT: alice read {read} of {POSTS} posts from a peer serving one a second (at least \
         {AT_LEAST}): a drain past its budget dropped what it staged. Her sync failures: {said:?}"
    );
    assert!(
        said.iter()
            .any(|f| f.contains("did not all arrive within 30s")),
        "PRODUCT: alice's status never named the drain budget: {said:?}"
    );
    assert!(
        !said.iter().any(|f| f.contains("sync mode unsupported")),
        "PRODUCT: alice's status still calls a slow peer a protocol mismatch: {said:?}"
    );
}
