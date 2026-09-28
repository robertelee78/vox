//! ADR-025 **P10** — a peer that advertises entries and serves none is **paced**, not asked again
//! in a tight loop. Through real binaries: Alice runs the shipped `vox daemon`; Bob runs a
//! **mutant sender**, a deliberately misbehaving build of the same binary, because no `vox`
//! command makes a correct node advertise what it will not serve.
//!
//! ADR-025 D3: a session that leaves requested positions unfilled and made no progress raises a
//! request **and enters backoff** (D5 kind `NoProgress`, from 1 s doubling to 30 s), so a peer
//! that advertises what it never serves costs one session per backoff step. Before ADR-025 the
//! receiver could not tell: the session ended `Ok`, and once full duplex removed the busy
//! refusal that used to hide it, an honest pair retrying zero-progress sessions would loop.
//!
//! ## The mutant sender
//! Built from this tree with one change: it serves nothing for any `WANT` (its `HAVE` is true).
//! Its path is `VOX_MUTANT_SENDER`; without it the proof cannot measure and says so.
//!
//! ## Staging
//! Two daemons, no anchor. Bob (the mutant) posts; his `HAVE` now advertises an entry Alice lacks,
//! which she asks for and never gets. Her sessions to Bob are counted over [`WINDOW`].
//!
//! ## Asserted
//! 1. Alice opened at most [`MAX_SESSIONS`] sessions to Bob in [`WINDOW`];
//! 2. her port with Bob was seen in backoff of kind `no_progress`.
//!
//! Precondition (else CANNOT MEASURE): at least one of Alice's sessions with Bob ended partial.
//!
//! ## Mutation
//! Remove the no-progress backoff: Alice asks again at once each time, dozens of sessions, and (1)
//! goes red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{counter, Member};

const WINDOW: Duration = Duration::from_secs(30);
/// Backoff from 1 s doubling (1, 2, 4, 8, 16 s) allows five sessions in 30 s, plus the first.
const MAX_SESSIONS: u64 = 6;

#[test]
#[ignore = "a real daemon against a mutant sender build (VOX_MUTANT_SENDER); run by hand in release"]
fn a_peer_that_serves_nothing_is_paced() {
    watchdog::arm();
    let sender = std::env::var("VOX_MUTANT_SENDER").unwrap_or_else(|_| {
        panic!("CANNOT MEASURE: VOX_MUTANT_SENDER does not name the mutant sender build")
    });
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(None);
    let bob_d = bob.daemon_bin(&sender, None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    // Let the join's own sessions settle before counting.
    std::thread::sleep(Duration::from_secs(3));

    let before = alice.status();
    bob.post(&room, "p10 advertised, never served");
    let start = Instant::now();
    let mut saw_backoff = false;
    let mut last = before.clone();
    while start.elapsed() < WINDOW {
        last = alice.status();
        saw_backoff |= last["sync"].as_array().is_some_and(|rows| {
            rows.iter().any(|r| {
                r["peer"].as_str().is_some_and(|p| bob.fp.starts_with(p))
                    && r["backoff"]["kind"].as_str() == Some("no_progress")
            })
        });
        std::thread::sleep(Duration::from_millis(250));
    }
    let d = |k: &str| counter(&last, k, Some(&bob.fp)) - counter(&before, k, Some(&bob.fp));
    let (opened, partial, admitted) = (d("opened"), d("partial"), d("admitted"));
    println!(
        "[proof] P10: over {WINDOW:?} alice opened {opened} session(s) to bob, admitted {admitted} \
         from him; {partial} ended partial; no_progress backoff seen: {saw_backoff}"
    );
    assert!(
        partial >= 1,
        "CANNOT MEASURE: none of alice's sessions with bob ended partial\nalice:\n{}\nbob:\n{}",
        alice_d.transcript(),
        bob_d.transcript()
    );
    assert!(
        opened <= MAX_SESSIONS,
        "alice opened {opened} sessions to a peer that serves nothing in {WINDOW:?} (at most \
         {MAX_SESSIONS}): zero-progress sessions are not paced"
    );
    assert!(
        saw_backoff,
        "alice's port with bob never showed a no_progress backoff"
    );
}
