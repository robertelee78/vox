//! V210-74 (#265) — **one member's bad entry, or one peer's doctored copy of a good one, never
//! stops a room**, through real binaries.
//!
//! Alice and Bob run the shipped `vox daemon`. Mallory runs the **mutant sender**, a deliberately
//! misbehaving build of the same binary (vox-core's `mutant-sender` feature, built by
//! `scripts/build-mutant-sender.sh`, named by `VOX_MUTANT_SENDER`), because no `vox` command makes a
//! correct node sign a payload that is neither kind, or serve an entry without its payload. All three
//! sit behind one real `vox node` anchor.
//!
//! ## An entry its author signed that cannot be classified ([`an_unclassifiable_entry_is_refused_and_the_room_syncs_on`])
//! Mallory runs as `author-unclassifiable`: what she posts is a signed entry whose payload is neither
//! a governance body nor a sender-key message. It used to be taken, logged, and refused only then:
//! the refusal poisoned the room's sync until a reopen, and after a restart the room did not open.
//! Asserted:
//! 1. Bob refused it (`refused` in `vox status --json` — else CANNOT MEASURE: it never reached him);
//! 2. Alice's post made after it reaches Bob;
//! 3. Bob's daemon restarts and still holds the room, with Alice's post in it;
//! 4. nothing was set aside when it reopened: the entry was refused before it was stored.
//!
//! ## A payload stripped in transit ([`a_stripped_payload_is_refused_and_the_real_entry_arrives`])
//! Mallory runs as `strip-payload`: she serves every entry without its payload. The signature
//! covers the skeleton only, so the stripped entry verifies; it used to be taken as held, filling
//! its position with nothing: never logged, never rendered, never asked for again. Staging: Bob is
//! stopped (SIGSTOP), Alice posts, Mallory gets it; Alice is stopped and Bob resumed, so Bob's only
//! copy is Mallory's. Asserted:
//! 1. Bob refused Mallory's copy (else CANNOT MEASURE: he never got it from her);
//! 2. once Alice is back, Bob reads her post;
//! 3. and still does after his daemon restarts.
//!
//! ## Mutations
//! - no refusal of an unclassifiable entry before it is held (`unclassifiable` answering `None`):
//!   arm 1 goes red at (4), the entry was stored;
//! - that, and a refusal after it is held ending the pass as an error again: red at (2), the room's
//!   sync is poisoned;
//! - no refusal of a withheld payload: arm 2 goes red at (2), Bob holds an empty copy and never asks
//!   again.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, announced, counter, mutant_sender, Member};

/// How long a post may take to reach a member before it counts as never.
const ARRIVES_WITHIN: Duration = Duration::from_secs(30);

/// Whether `m` reads `text` in `room` now (`vox room read`, which needs the room open).
fn reads(m: &Member, room: &str, text: &str) -> bool {
    let (ok, out, _) = m.vox(&["room", "read", room], None);
    ok && out.lines().any(|l| l.ends_with(text))
}

/// Wait until `m` reads `text`, up to [`ARRIVES_WITHIN`]; how long it took, or `None`.
fn arrives(m: &Member, room: &str, text: &str) -> Option<Duration> {
    let t = Instant::now();
    while t.elapsed() < ARRIVES_WITHIN {
        if reads(m, room, text) {
            return Some(t.elapsed());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

/// Wait until `m`'s status counts at least one refused entry from `from`; the count seen.
fn refused_from(m: &Member, from: &Member) -> u64 {
    let t = Instant::now();
    loop {
        let n = counter(&m.status(), "refused", Some(&from.fp));
        if n > 0 || t.elapsed() > ARRIVES_WITHIN {
            return n;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every stored entry any room of `m`'s set aside when it opened.
fn set_aside(m: &Member) -> Vec<String> {
    m.status()["set_aside"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["entries"].as_array().cloned().unwrap_or_default())
        .filter_map(|e| e.as_str().map(str::to_owned))
        .collect()
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn an_unclassifiable_entry_is_refused_and_the_room_syncs_on() {
    const MODE: &str = "author-unclassifiable";
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let mallory = Member::new(root, "mallory");
    for (a, b) in [(&alice, &bob), (&alice, &mallory), (&bob, &mallory)] {
        a.trust(b);
        b.trust(a);
    }
    let _alice_d = alice.daemon(Some(&spec));
    let bob_d = bob.daemon(Some(&spec));
    let mallory_d = mallory.daemon_mutant(&sender, MODE, Some(&spec));
    let room = alice.create("hostile");
    let link = alice.invite(&room);
    bob.join(&link, "hostile");
    mallory.join(&link, "hostile");
    let first = "alice, before mallory posts";
    alice.post(&room, first);
    assert!(
        arrives(&bob, &room, first).is_some(),
        "CANNOT MEASURE: alice's first post never reached bob, before anything hostile"
    );

    mallory.post(&room, "whatever mallory typed");
    let refused = refused_from(&bob, &mallory) + counter(&bob.status(), "refused", Some(&alice.fp));
    assert!(
        announced(&mallory_d, MODE),
        "CANNOT MEASURE: mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] unclassifiable: bob refused {refused} entr(ies); alice's next post reached him: \
         {took:?}"
    );
    assert!(
        took.is_some(),
        "alice's post made after mallory's unclassifiable entry never reached bob within \
         {ARRIVES_WITHIN:?}: the room's sync stopped\nbob's status: {}\nbob:\n{}",
        bob.status(),
        bob_d.transcript()
    );
    assert!(
        refused >= 1,
        "CANNOT MEASURE: bob never refused mallory's entry (it never reached him)\nbob's status: {}",
        bob.status()
    );

    // ---- bob restarts: the room is held again, whole, and nothing hostile was stored --------
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, after);
    let aside = set_aside(&bob);
    println!(
        "[proof] unclassifiable: after a restart bob reads it: {reopened:?}; set aside: {aside:?}"
    );
    assert!(
        reopened.is_some(),
        "after a restart bob's room is not open, or has lost alice's post\nbob's status: {}",
        bob.status()
    );
    assert!(
        aside.is_empty(),
        "mallory's unclassifiable entry was stored before it was refused: the reopen set aside \
         {aside:?}"
    );
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_stripped_payload_is_refused_and_the_real_entry_arrives() {
    const MODE: &str = "strip-payload";
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let mallory = Member::new(root, "mallory");
    for (a, b) in [(&alice, &bob), (&alice, &mallory), (&bob, &mallory)] {
        a.trust(b);
        b.trust(a);
    }
    let alice_d = alice.daemon(Some(&spec));
    let bob_d = bob.daemon(Some(&spec));
    let mallory_d = mallory.daemon_mutant(&sender, MODE, Some(&spec));
    let room = alice.create("stripped");
    let link = alice.invite(&room);
    bob.join(&link, "stripped");
    mallory.join(&link, "stripped");
    let warm = "alice, while everyone is up";
    alice.post(&room, warm);
    assert!(
        arrives(&bob, &room, warm).is_some() && arrives(&mallory, &room, warm).is_some(),
        "CANNOT MEASURE: alice's first post did not reach both, before anything was stopped"
    );

    // ---- bob's only copy of alice's post is mallory's --------------------------------------
    bob_d.signal("STOP");
    let post = "alice, while bob was away";
    alice.post(&room, post);
    let held = arrives(&mallory, &room, post);
    alice_d.signal("STOP");
    bob_d.signal("CONT");
    assert!(
        held.is_some(),
        "CANNOT MEASURE: mallory never had alice's post, so bob could not get it from her"
    );
    let refused = refused_from(&bob, &mallory);
    assert!(
        announced(&mallory_d, MODE),
        "CANNOT MEASURE: mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    assert!(
        refused >= 1,
        "CANNOT MEASURE: bob never refused a stripped entry from mallory (he never got one)\n\
         bob's status: {}",
        bob.status()
    );

    // ---- alice comes back: bob gets her post whole ------------------------------------------
    alice_d.signal("CONT");
    let took = arrives(&bob, &room, post);
    println!("[proof] stripped: bob refused {refused} entr(ies) from mallory; alice's post reached him: {took:?}");
    assert!(
        took.is_some(),
        "bob never read alice's post after refusing mallory's stripped copy: he holds an empty \
         one\nbob's status: {}",
        bob.status()
    );
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, post);
    println!("[proof] stripped: after a restart bob reads it: {reopened:?}");
    assert!(
        reopened.is_some(),
        "after a restart bob's room is not open, or has lost alice's post\nbob's status: {}",
        bob.status()
    );
}
