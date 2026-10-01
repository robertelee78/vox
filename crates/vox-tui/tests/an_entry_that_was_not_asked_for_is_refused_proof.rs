//! ADR-025 **P9** — an entry the receiver did not ask for is **refused, not stored**. Through
//! real binaries: Bob runs the shipped `vox daemon`; Alice runs a **mutant sender**, a
//! deliberately misbehaving build of the same binary, because no `vox` command makes a correct
//! node serve what was not asked for.
//!
//! ADR-025 D3: the receiver keeps its `WANT` as per-author intervals, and every entry that arrives
//! must fall in a requested, not yet served position. Anything else is a protocol violation: the
//! session fails, the entry is not stored, and the port backs off (`NoProgress`). Before ADR-025
//! the receiver applied whatever arrived that passed the DAG's acceptance, asked for or not
//! (security-relevant: the sender chooses what the receiver stores).
//!
//! ## The mutant sender
//! `vox` built from this tree with vox-core's `mutant-sender` feature, by
//! `scripts/build-mutant-sender.sh` (CI and the release gate run it before the proofs), and started
//! with `VOX_MUTANT_SENDER_MODE=serve-unasked`: its `HAVE` hides the newest entry of every feed (it
//! advertises `max_seq - 1`), and it serves that hidden entry on every session anyway. A correct
//! receiver never asks for it. Its path is `VOX_MUTANT_SENDER`. Without it, or if it is not a
//! mutant build, or if it never announces the mode, the proof cannot measure and says so; and the
//! shipped binary the other member runs must not carry the mutant's marker.
//!
//! ## Staging
//! Two daemons, no anchor. After the warm-up, Alice posts "p9 visible" and then "p9 hidden". The
//! first is advertised (it is now the second newest), the second never is, but is served.
//!
//! ## Asserted
//! 1. Bob reads "p9 visible" (the pair syncs; precondition, else CANNOT MEASURE);
//! 2. Bob **never** reads "p9 hidden", over [`WATCH`];
//! 3. Bob's `vox status --json` names the violation as the last failure with Alice.
//!
//! **(2) is a negative claim, so every read it rests on must have worked.** The harness's read
//! returns no rows when the control socket fails, which would read as "never stored". Once Bob has
//! read "p9 visible", every later read must still show it: a read that does not is a blind read,
//! and any blind read in the watch makes (2) CANNOT MEASURE rather than green. Reds on (2) and (3)
//! are PRODUCT and quote Bob's own transcript.
//!
//! ## Mutation
//! Remove the coverage check in the receiver (`Coverage::admit` always true): Bob stores and
//! reads "p9 hidden", and (2) goes red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{announced, counter, failures, mutant_sender, Member};

/// How long Bob is watched for the entry he did not ask for.
const WATCH: Duration = Duration::from_secs(10);
/// What the receiver says of it.
const VIOLATION: &str = "the peer served an entry that was not asked for";
/// The mutant sender's misbehaviour here.
const MODE: &str = "serve-unasked";

#[test]
#[ignore = "a real daemon against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn an_entry_that_was_not_asked_for_is_refused() {
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon_mutant(&sender, MODE, None);
    let bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut rb = bob.reader();
    let cb = rb.room(&room);

    // Warm-up: the mutant hides its newest entry, so Bob reads each warm post once the next one
    // follows it.
    let start = Instant::now();
    let mut n = 0;
    loop {
        n += 1;
        alice.post(&room, &format!("warm {n}"));
        std::thread::sleep(Duration::from_millis(500));
        if rb.texts(cb).iter().any(|t| t.starts_with("warm ")) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "CANNOT MEASURE: bob never read alice's warm-up\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
    }
    alice.post(&room, "p9 visible");
    alice.post(&room, "p9 hidden");
    let posted = Instant::now();
    let mut visible_at = None;
    let mut hidden_at = None;
    let (mut reads, mut blind) = (0usize, 0usize);
    while posted.elapsed() < WATCH {
        let texts = rb.texts(cb);
        let visible = texts.iter().any(|t| t == "p9 visible");
        if visible_at.is_some() {
            reads += 1;
            if !visible {
                blind += 1;
            }
        }
        if visible_at.is_none() && visible {
            visible_at = Some(posted.elapsed());
        }
        if hidden_at.is_none() && texts.iter().any(|t| t == "p9 hidden") {
            hidden_at = Some(posted.elapsed());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let st = bob.status();
    let failed = counter(&st, "failed", Some(&alice.fp));
    let named = st["sync"].as_array().is_some_and(|rows| {
        rows.iter().any(|r| {
            r["peer"].as_str().is_some_and(|p| alice.fp.starts_with(p))
                && r["last_failure"]
                    .as_str()
                    .is_some_and(|f| f.contains(VIOLATION))
        })
    });
    println!(
        "[proof] P9: visible read after {visible_at:?}; hidden read after {hidden_at:?}; {reads} \
         reads after it, {blind} blind; bob's sessions with alice failed {failed}; last failures \
         {:?}",
        failures(&st)
    );
    assert!(
        announced(&alice_d, MODE),
        "CANNOT MEASURE: alice's daemon never announced the mutant mode {MODE:?}\nalice:\n{}",
        alice_d.transcript()
    );
    assert!(
        visible_at.is_some(),
        "CANNOT MEASURE: bob never read \"p9 visible\" within {WATCH:?}\nbob:\n{}",
        bob_d.transcript()
    );
    assert!(
        hidden_at.is_none(),
        "PRODUCT: bob stored and read an entry he never asked for, {hidden_at:?} after it was \
         posted\nbob:\n{}",
        bob_d.transcript()
    );
    assert!(
        reads > 0 && blind == 0,
        "CANNOT MEASURE: {blind} of {reads} reads after \"p9 visible\" came back without it, so \
         \"p9 hidden\" not being read is not evidence it was refused (a failed control-socket read \
         returns no rows)\nbob:\n{}",
        bob_d.transcript()
    );
    assert!(
        named,
        "PRODUCT: bob's sessions with the mutant sender did not fail as a protocol violation \
         ({VIOLATION:?}); his last failures: {:?}\nbob:\n{}",
        failures(&st),
        bob_d.transcript()
    );
}
