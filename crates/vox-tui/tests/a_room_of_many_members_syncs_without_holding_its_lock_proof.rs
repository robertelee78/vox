//! V210-71 (#262), finding 4 — **a room of many members keeps answering its own member while it
//! syncs**, through the shipped binary. Opt-in (`--features optional-proofs`): its staging joins
//! [`MEMBERS`] identities, which takes minutes, so it is not part of every CI run.
//!
//! **The defect.** Every outbound sync session starts by fetching the room's records from the
//! peer's board and admitting any member not yet known (`admit_board_records`). It verified every
//! record's signatures, the record's and the three or four in its prekey bundle, **for every member
//! on the board, on every session, holding the room's lock**, though a record for a member already
//! admitted can change nothing. A room of N members paid N record checks per session, and every
//! post and read of that room waited behind them. Now only records for keys not yet admitted are
//! verified, and with the lock released.
//!
//! **Staging**, every node the shipped `vox`: an anchor; the host's `vox daemon`, which creates
//! the room; bob's, who joins and stays up, so the host has a member to sync with; and
//! [`MEMBERS`] more identities that each join through their own daemon, which is then stopped.
//! Their records stay on the boards, so every session between the host and bob carries them all.
//!
//! **Asserted.** With every member on the host's roster (else `APPARATUS`), the host posts
//! without pause from a thread of its own; each post is pushed to bob, and bob's node opens a
//! session with the host to take it, an outbound session that fetches the board and admits its
//! records under bob's room lock (the defect). Meanwhile bob posts [`POSTS`] times, [`GAP`]
//! apart, and **the 90th percentile of his `vox room post` stays under [`P90_BOUND`]**: what a
//! person posting in the room feels, most of the time.
//!
//! **Every red says which it is.** `PRODUCT:` is the bound broken: the node held its own member
//! up. `APPARATUS:` is a staging step not achieved, named (a member that never joined, a roster
//! short of the members staged, too few sessions to have measured anything): the product was
//! never measured, so the run says nothing about it.
//!
//! **Measured at 192 members** (release, a working machine): with the fix, p90 50.0, 37.7 and
//! 27.1 ms; with the room's lock held across re-verifying every record, p90 409, 681, 135 and
//! 121 ms. At 128 members the mutant once measured p90 76.8 ms (verifier-262c4), so the room is
//! staged larger: the mutant's hold grows with the records it re-verifies, the fix's does not.
//! **The bound, [`P90_BOUND`] = 75 ms,** sits 25 ms over the slowest fix sample (50.0 ms; at
//! 128 members the fix's slowest was 51.8 ms) and 46 ms under the weakest mutant (121 ms). A
//! 100 ms bound left the mutant 21 ms.
//! The fix's slowest posts (221–267 ms at 192) were measured with the room's lock timed in
//! bob's node, and no hold of it reached 26 ms, so they are not this defect, and under V210-08's
//! 500 ms bound. It is not staged larger still: a board takes about 256 joins per two hours
//! (#297).
//!
//! **Mutation that must turn it red.** `admit_board_records` back to its old shape: the room's lock
//! held across verifying every record on the board, admitted or not.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_room_of_many_members_syncs_without_holding_its_lock);

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, counter, Member};

/// The members staged besides the host and bob.
const MEMBERS: usize = 192;
/// How many daemons join at once while staging.
const BATCH: usize = 16;
/// Bob's posts measured: enough that a lock held across the board's records shows in the tail.
const POSTS: usize = 120;
/// The pause between them.
const GAP: Duration = Duration::from_millis(250);
/// Bob's outbound sessions while he posts, at least, for the measurement to mean anything.
const MIN_SESSIONS: u64 = 10;
/// Bob's posts' 90th percentile must stay under this: 27.1-50.0 ms with the fix at 192 members,
/// 121-681 ms without. See the module docs for the margin on each side.
const P90_BOUND: Duration = Duration::from_millis(75);

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional proof: stages a room of many members through the shipped binary"]
fn a_room_of_many_members_syncs_without_holding_its_lock() {
    // Staging [`MEMBERS`] joins takes minutes, past the default 600 s watchdog (ADR-018 §6) on a
    // loaded machine; this opt-in proof takes a budget of its own unless one is set.
    if std::env::var_os("VOX_TEST_WATCHDOG_SECS").is_none() {
        std::env::set_var("VOX_TEST_WATCHDOG_SECS", "1800");
    }
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let host = Member::new(root, "host");
    let bob = Member::new(root, "bob");
    let _host_d = host.daemon(Some(&spec));
    let _bob_d = bob.daemon(Some(&spec));
    let room = host.create("many");
    let link = host.invite(&room);
    bob.join(&link, "many");

    // ---- the members, joined through their own daemons and then stopped ---------------------
    let t_stage = Instant::now();
    let names: Vec<&'static str> = (1..=MEMBERS)
        .map(|i| &*Box::leak(format!("m{i}").into_boxed_str()))
        .collect();
    for chunk in names.chunks(BATCH) {
        std::thread::scope(|s| {
            for name in chunk {
                let (root, spec, link) = (root, &spec, &link);
                s.spawn(move || {
                    let m = Member::new(root, name);
                    let d = m.daemon(Some(spec));
                    m.join(link, "many");
                    drop(d);
                });
            }
        });
    }
    let (ok, roster, err) = host.vox(&["room", "roster", &room], None);
    assert!(ok, "APPARATUS (staging): vox room roster failed: {err}");
    let members = roster.lines().filter(|l| !l.trim().is_empty()).count();
    println!(
        "[proof] staged {MEMBERS} members in {:?}; the host's roster lists {members}",
        t_stage.elapsed()
    );
    assert!(
        members >= MEMBERS + 2,
        "APPARATUS (staging not achieved): the host's roster lists {members} members, not {} \
         (host, bob and {MEMBERS})",
        MEMBERS + 2
    );

    // ---- the host posts without pause; bob posts and is timed --------------------------------
    std::thread::sleep(Duration::from_secs(5));
    let opened_before = counter(&bob.status(), "opened", None);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut took: Vec<Duration> = Vec::with_capacity(POSTS);
    let host_posts = std::thread::scope(|s| {
        let pusher = s.spawn(|| {
            let mut n = 0usize;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                n += 1;
                host.post(&room, &format!("host post {n}"));
            }
            n
        });
        for i in 1..=POSTS {
            let t = Instant::now();
            bob.post(&room, &format!("bob post {i}"));
            took.push(t.elapsed());
            std::thread::sleep(GAP);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        pusher.join().unwrap()
    });
    let sessions = counter(&bob.status(), "opened", None).saturating_sub(opened_before);
    println!("[proof] meanwhile the host posted {host_posts} times and bob's node opened {sessions} session(s)");
    assert!(
        sessions >= MIN_SESSIONS,
        "APPARATUS (precondition unmet): bob's node opened {sessions} session(s) while it posted \
         (need {MIN_SESSIONS}): nothing ran admit_board_records, so nothing was measured"
    );
    let mut sorted = took.clone();
    sorted.sort();
    let (p50, p90, max) = (sorted[POSTS / 2], sorted[POSTS * 9 / 10], sorted[POSTS - 1]);
    println!(
        "[proof] {POSTS} bob posts in a room of {members}: p50 {p50:?}, p90 {p90:?} (bound \
         {P90_BOUND:?}), max {max:?}; all: {took:?}"
    );
    assert!(
        p90 < P90_BOUND,
        "PRODUCT: bob's posts in a room of {members} members took p90 {p90:?} (bound \
         {P90_BOUND:?}): his syncs hold the room's lock while they re-verify every member's board \
         record"
    );
}
