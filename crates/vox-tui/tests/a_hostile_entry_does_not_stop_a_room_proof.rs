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
//! ## A governance entry that does not bind to itself ([`a_misbound_governance_entry_is_refused_and_the_room_syncs_on`])
//! Mallory runs as `author-misbound`: what she posts is a real consent grant, signed, whose body
//! names an epoch 7 past the entry's own. It classifies as governance and does not bind (the
//! issue's first case: a governance body with the wrong channel or epoch). Asserted as for the
//! unclassifiable entry: Alice's next post reaches Bob, none of Bob's sessions failed with the
//! binding's reason, and after a restart the room is open with nothing set aside. Arm and mode by
//! the verifier (vox-0e-ver74).
//!
//! ## A payload stripped in transit ([`a_stripped_payload_is_refused_and_the_real_entry_arrives`])
//! Mallory runs as `strip-payload`: she serves every entry without its payload. The signature
//! covers the skeleton only, so the stripped entry verifies; it used to be taken as held, filling
//! its position with nothing: never logged, never rendered, never asked for again. Staging: Bob is
//! stopped (SIGSTOP), Alice posts, Mallory gets it; Alice and the anchor (which holds the room's
//! entries too) are stopped and Bob resumed, so Bob's only copy is Mallory's. Asserted:
//! 1. Bob reads Alice's posts, the first one included (Mallory may serve that one too);
//! 2. once Alice is back, Bob reads the post he first got from Mallory, and he refused her copy
//!    (precondition, else CANNOT MEASURE: Bob had a session with Mallory while Alice was stopped);
//! 3. and still does after his daemon restarts.
//!
//! ## A message lost before V210-73 is reported ([`a_message_lost_to_the_old_row_ids_is_reported`])
//! Before V210-73 a reopened room resumed its row ids from its log rows alone, so its first post
//! overwrote the cache row of the last message it had received, the only plaintext of it. That
//! cannot be undone (its message key was used up when it was read), so it is reported. Bob's store
//! is damaged the old way: his daemon is the mutant build as `old-row-ids` while he receives
//! Alice's posts, restarts, and posts. Then the shipped daemon opens it. Asserted: `vox status`
//! reports exactly one message lost that way, and Bob reads one post fewer (else CANNOT MEASURE:
//! nothing was lost).
//!
//! ## Mutations
//! - no refusal of an unclassifiable entry before it is held (`unclassifiable` answering `None`):
//!   arm 1 goes red at (4), the entry was stored;
//! - that, and a refusal after it is held ending the pass as an error again: red at (2), the room's
//!   sync is poisoned;
//! - no refusal of a withheld payload: arm 2 goes red at (2), Bob holds an empty copy and never asks
//!   again;
//! - no report of a lost message: arm 3 goes red;
//! - no binding check before holding (`unclassifiable` answering `None` for governance): the
//!   misbound arm goes red, the entry was stored.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, announced, counter, failures, mutant_sender, Member};

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

/// `m`'s count of refused entries, from `from` or from anyone.
fn refused(m: &Member, from: Option<&Member>) -> u64 {
    counter(&m.status(), "refused", from.map(|f| f.fp.as_str()))
}

/// Wait until `m` has refused more than `since` entries, from `from` or from anyone; how many more.
fn refused_by(m: &Member, from: Option<&Member>, since: u64) -> u64 {
    let t = Instant::now();
    loop {
        let n = refused(m, from).saturating_sub(since);
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

    let since = refused(&bob, None);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_by(&bob, None, since);
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
    // A refusal is not a failed session: before, it ended bob's session with the refusal as its
    // reason and poisoned the room's sync until a reopen, and alice's post came only when she
    // pushed it again. The reason is hard-coded here.
    let poisoned: Vec<String> = failures(&bob.status())
        .into_iter()
        .filter(|f| f.contains("neither a group message nor a governance struct"))
        .collect();
    assert!(
        poisoned.is_empty(),
        "mallory's unclassifiable entry failed bob's sync sessions: {poisoned:?}"
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
    let (anchor_d, spec) = anchor(root);
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
        arrives(&mallory, &room, warm).is_some(),
        "CANNOT MEASURE: alice's first post never reached mallory"
    );
    // Not a precondition: bob may take this one from mallory too, stripped.
    assert!(
        arrives(&bob, &room, warm).is_some(),
        "bob never read alice's first post: he holds an empty copy\nbob's status: {}",
        bob.status()
    );

    // ---- bob's only copy of alice's post is mallory's --------------------------------------
    let sessions = |m: &Member| {
        let st = bob.status();
        counter(&st, "opened", Some(&m.fp)) + counter(&st, "admitted", Some(&m.fp))
    };
    let with_mallory = sessions(&mallory);
    // Bob may have refused a stripped copy already, of the first post: only a new one counts.
    let since = refused(&bob, Some(&mallory));
    bob_d.signal("-STOP");
    let post = "alice, while bob was away";
    alice.post(&room, post);
    let held = arrives(&mallory, &room, post);
    // The anchor holds the room's entries too, and would serve bob the whole one.
    alice_d.signal("-STOP");
    anchor_d.signal("-STOP");
    bob_d.signal("-CONT");
    assert!(
        held.is_some(),
        "CANNOT MEASURE: mallory never had alice's post, so bob could not get it from her"
    );
    let refused = refused_by(&bob, Some(&mallory), since);
    let served = sessions(&mallory).saturating_sub(with_mallory);
    assert!(
        announced(&mallory_d, MODE),
        "CANNOT MEASURE: mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    assert!(
        served >= 1,
        "CANNOT MEASURE: bob had no session with mallory while alice was stopped\nbob's status: {}",
        bob.status()
    );

    // ---- alice comes back: bob gets her post whole ------------------------------------------
    alice_d.signal("-CONT");
    anchor_d.signal("-CONT");
    let took = arrives(&bob, &room, post);
    println!("[proof] stripped: bob refused {refused} entr(ies) from mallory; alice's post reached him: {took:?}");
    assert!(
        took.is_some(),
        "bob never read alice's post after mallory served it stripped: he holds an empty one\n\
         bob's status: {}",
        bob.status()
    );
    assert!(
        refused >= 1,
        "bob had {served} session(s) with mallory while alice was stopped and refused nothing"
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

#[test]
#[ignore = "real daemons with the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_message_lost_to_the_old_row_ids_is_reported() {
    const MODE: &str = "old-row-ids";
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let _alice_d = alice.daemon(Some(&spec));
    let bob_d = bob.daemon_mutant(&sender, MODE, Some(&spec));
    let room = alice.create("old");
    bob.join(&alice.invite(&room), "old");
    let hers = ["alice one", "alice two", "alice three"];
    for p in hers {
        alice.post(&room, p);
    }
    for p in hers {
        assert!(
            arrives(&bob, &room, p).is_some(),
            "CANNOT MEASURE: bob never received {p:?}"
        );
    }
    // ---- bob's store is damaged the old way: restart, post ---------------------------------
    drop(bob_d);
    let bob_d = bob.daemon_mutant(&sender, MODE, Some(&spec));
    bob.post(&room, "bob, after the restart");
    assert!(
        announced(&bob_d, MODE),
        "CANNOT MEASURE: bob's daemon never announced {MODE:?}:\n{}",
        bob_d.transcript()
    );
    drop(bob_d);

    // ---- the shipped daemon opens it --------------------------------------------------------
    let _bob_d = bob.daemon(Some(&spec));
    assert!(
        arrives(&bob, &room, "bob, after the restart").is_some(),
        "CANNOT MEASURE: the shipped daemon does not hold bob's room"
    );
    let (_, read, _) = bob.vox(&["room", "read", &room], None);
    let kept = hers
        .iter()
        .filter(|p| read.lines().any(|l| l.ends_with(**p)))
        .count();
    let lost: Vec<String> = set_aside(&bob)
        .into_iter()
        .filter(|e| e.contains("lost to the row-id collision"))
        .collect();
    println!(
        "[proof] old row ids: bob reads {kept} of alice's 3 posts; vox status reports {} lost: \
         {lost:?}",
        lost.len()
    );
    assert!(
        kept < hers.len(),
        "CANNOT MEASURE: the old row ids lost nothing (bob reads {kept} of 3)"
    );
    assert_eq!(
        lost.len(),
        hers.len() - kept,
        "bob lost {} of alice's posts to the old row ids; vox status reports {lost:?}",
        hers.len() - kept
    );
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_misbound_governance_entry_is_refused_and_the_room_syncs_on() {
    const MODE: &str = "author-misbound";
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

    let since = refused(&bob, None);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_by(&bob, None, since);
    assert!(
        announced(&mallory_d, MODE),
        "CANNOT MEASURE: mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] misbound: bob refused {refused} entr(ies); alice's next post reached him: \
         {took:?}"
    );
    assert!(
        took.is_some(),
        "alice's post made after mallory's misbound governance entry never reached bob within \
         {ARRIVES_WITHIN:?}: the room's sync stopped\nbob's status: {}\nbob:\n{}",
        bob.status(),
        bob_d.transcript()
    );
    // A refusal is not a failed session: before, it ended bob's session with the refusal as its
    // reason and poisoned the room's sync until a reopen, and alice's post came only when she
    // pushed it again. The reason is hard-coded here.
    let poisoned: Vec<String> = failures(&bob.status())
        .into_iter()
        .filter(|f| f.contains("disagrees with log entry"))
        .collect();
    assert!(
        poisoned.is_empty(),
        "mallory's misbound governance entry failed bob's sync sessions: {poisoned:?}"
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
    println!("[proof] misbound: after a restart bob reads it: {reopened:?}; set aside: {aside:?}");
    assert!(
        reopened.is_some(),
        "after a restart bob's room is not open, or has lost alice's post\nbob's status: {}",
        bob.status()
    );
    assert!(
        aside.is_empty(),
        "mallory's misbound governance entry was stored before it was refused: the reopen set aside \
         {aside:?}"
    );
}
