//! ADR-025 **P1** — two members posting at the same instant never refuse each other, and each
//! reads the other's post at once. Through the shipped binaries: a real `vox node` anchor and two
//! real `vox daemon`s.
//!
//! Before ADR-025, two members that posted within a round trip each opened a session to the other
//! and each refused the other's (`SessionBusy`), then both retried after a random wait: collision
//! and backoff, a hub's CSMA/CD. ADR-025 option C (the decider, 2026-09-26) is full duplex: an
//! inbound session is admitted beside this side's own outbound one (up to three per room and
//! peer), so neither end refuses, waits on or backs off from the other for being busy.
//!
//! ## Staging
//! Alice and Bob trust each other and share one room behind an anchor. Both read each other
//! before the rounds. Then [`ROUNDS`] times, both run `vox room post` at the same instant (a
//! barrier), and each post is timed from the moment its own `vox room post` returned to the
//! moment it is readable on the **other** member's node, read over that node's control socket as
//! `vox room read` reads it.
//!
//! ## Asserted
//! 1. `busy_refused = 0` on both daemons, from the shipped `vox status --json`;
//! 2. every post readable by the other within [`BOUND`] of its `vox room post` returning (p100).
//!
//! ## Precondition (else CANNOT MEASURE)
//! At least [`MIN_TOGETHER`] rounds whose two posts returned within [`TOGETHER`] of each other,
//! which is well inside the loopback round trip plus a session, so the two ends' sessions
//! overlapped; and each daemon opened at least [`ROUNDS`] sessions to the other.
//!
//! ## Mutation
//! Restore the busy refusal at the inbound check (refuse an inbound session while this side's
//! own outbound one for the room and peer runs): (1) goes red, and the retries push (2) past the
//! bound.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, counter, failures, pct, Member};

/// Rounds of both members posting at once.
const ROUNDS: usize = 40;
/// Each post readable by the other within this of its `vox room post` returning (loopback).
const BOUND: Duration = Duration::from_millis(250);
/// Two posts that returned this close together were simultaneous for the sessions they started.
const TOGETHER: Duration = Duration::from_millis(50);
/// Rounds that must have been simultaneous for the run to measure anything.
const MIN_TOGETHER: usize = 20;
const POLL: Duration = Duration::from_millis(5);

#[test]
#[ignore = "a real anchor and two real daemons with production Argon2id; CI runs it in release"]
fn simultaneous_posts_never_collide() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(Some(&spec));
    let bob_d = bob.daemon(Some(&spec));

    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");

    let mut ra = alice.reader();
    let mut rb = bob.reader();
    let (ca, cb) = (ra.room(&room), rb.room(&room));

    // Both read each other before the rounds: keys have flowed, the pair is connected.
    let start = Instant::now();
    let mut n = 0;
    loop {
        n += 1;
        alice.post(&room, &format!("warm alice {n}"));
        bob.post(&room, &format!("warm bob {n}"));
        std::thread::sleep(Duration::from_millis(500));
        let a_reads = ra.texts(ca).iter().any(|t| t.starts_with("warm bob"));
        let b_reads = rb.texts(cb).iter().any(|t| t.starts_with("warm alice"));
        if a_reads && b_reads {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "CANNOT MEASURE: the pair never read each other before the rounds\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
    }
    std::thread::sleep(Duration::from_secs(1));
    let (a0, b0) = (alice.status(), bob.status());

    let mut lat: Vec<Duration> = Vec::new();
    let mut late: Vec<String> = Vec::new();
    let mut together = 0usize;
    for r in 0..ROUNDS {
        let (ta, tb) = (format!("p1 alice {r}"), format!("p1 bob {r}"));
        let barrier = std::sync::Barrier::new(2);
        let (a_done, b_done) = std::thread::scope(|s| {
            let a = s.spawn(|| {
                barrier.wait();
                alice.post(&room, &ta);
                Instant::now()
            });
            let b = s.spawn(|| {
                barrier.wait();
                bob.post(&room, &tb);
                Instant::now()
            });
            (a.join().unwrap(), b.join().unwrap())
        });
        let skew = if a_done > b_done {
            a_done - b_done
        } else {
            b_done - a_done
        };
        if skew <= TOGETHER {
            together += 1;
        }
        let (mut a_seen, mut b_seen): (Option<Instant>, Option<Instant>) = (None, None);
        let deadline = Instant::now() + Duration::from_secs(40);
        while (a_seen.is_none() || b_seen.is_none()) && Instant::now() < deadline {
            if b_seen.is_none() && rb.has(cb, &ta) {
                b_seen = Some(Instant::now());
            }
            if a_seen.is_none() && ra.has(ca, &tb) {
                a_seen = Some(Instant::now());
            }
            std::thread::sleep(POLL);
        }
        for (who, seen, done) in [
            ("alice->bob", b_seen, a_done),
            ("bob->alice", a_seen, b_done),
        ] {
            match seen {
                Some(t) => {
                    let d = t.saturating_duration_since(done);
                    lat.push(d);
                    if d > BOUND {
                        late.push(format!("round {r} {who}: {d:?}"));
                    }
                }
                None => late.push(format!("round {r} {who}: never within 40 s")),
            }
        }
    }
    // Let the last sessions finish and be counted.
    std::thread::sleep(Duration::from_secs(2));
    let (a1, b1) = (alice.status(), bob.status());
    let delta = |k: &str, before: &serde_json::Value, after: &serde_json::Value| {
        counter(after, k, None) - counter(before, k, None)
    };
    let busy = delta("busy_refused", &a0, &a1) + delta("busy_refused", &b0, &b1);
    // Sessions to the other member, not to the anchor.
    let (a_opened, b_opened) = (
        counter(&a1, "opened", Some(&bob.fp)) - counter(&a0, "opened", Some(&bob.fp)),
        counter(&b1, "opened", Some(&alice.fp)) - counter(&b0, "opened", Some(&alice.fp)),
    );
    let failed = delta("failed", &a0, &a1) + delta("failed", &b0, &b1);
    let max = lat.iter().copied().max().unwrap_or_default();
    let p50 = pct(&mut lat.clone(), 50.0);
    let p95 = pct(&mut lat.clone(), 95.0);
    println!(
        "[proof] P1: {ROUNDS} rounds, {together} simultaneous (posts returned within {TOGETHER:?}); \
         {} crossings, p50 {p50:?} p95 {p95:?} max {max:?}, {} over {BOUND:?}; busy_refused {busy} \
         (alice {} bob {}); opened alice {a_opened} bob {b_opened}; failed {failed}; last failures \
         alice {:?} bob {:?}",
        lat.len(),
        late.len(),
        delta("busy_refused", &a0, &a1),
        delta("busy_refused", &b0, &b1),
        failures(&a1),
        failures(&b1),
    );
    for l in late.iter().take(10) {
        println!("[late] {l}");
    }
    assert!(
        together >= MIN_TOGETHER,
        "CANNOT MEASURE: only {together} of {ROUNDS} rounds had both posts return within \
         {TOGETHER:?}"
    );
    assert!(
        a_opened >= ROUNDS as u64 && b_opened >= ROUNDS as u64,
        "CANNOT MEASURE: the daemons opened {a_opened} and {b_opened} sessions over {ROUNDS} \
         rounds; each post should open one"
    );
    assert_eq!(
        busy, 0,
        "two members posting at once refused each other {busy} time(s) (SessionBusy)"
    );
    assert!(
        late.is_empty(),
        "{} of {} crossings took longer than {BOUND:?} after `vox room post` returned: {late:?}",
        late.len(),
        ROUNDS * 2
    );
}
