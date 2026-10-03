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
//! 1. Bob refused it (`refused` in `vox status --json` — else PRODUCT (staging): it never reached him);
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
//! ## A body stripped in transit is owed ([`a_stripped_body_is_owed_and_asked_for_until_it_arrives`])
//! Mallory runs as `strip-payload`: she serves every entry without its payload. The signature
//! covers the skeleton only, so the stripped entry verifies. v0.2.10 set it aside (V210-74); in
//! v0.3.0 an honest peer serves payload-less skeletons too (retention), so the decider's rule holds
//! (V030-10, 2026-10-01): the envelope is taken, and a body not received that has not expired by
//! the receiver's own reckoning is owed, shown as "not received yet" and asked for on every sync.
//! Staging: Bob is stopped (SIGSTOP), Alice posts twice, Mallory gets both; Alice and the anchor
//! (which holds the room's entries too) are stopped and Bob resumed, so Bob's only copy is Mallory's.
//! Asserted:
//! 1. Bob reads Alice's first post (Mallory may serve that one too);
//! 2. with Mallory his only source, Bob shows both posts as not received yet: the envelopes were
//!    taken and Alice's feed goes on past the first (precondition, else PRODUCT (staging): Bob had
//!    a session with Mallory while Alice was stopped);
//! 3. once Alice is back, Bob reads both, and shows nothing as not received yet;
//! 4. and still reads them after his daemon restarts.
//!
//! ## A message lost before V210-73 is reported ([`a_message_lost_to_the_old_row_ids_is_reported`])
//! Before V210-73 a reopened room resumed its row ids from its log rows alone, so its first post
//! overwrote the cache row of the last message it had received, the only plaintext of it. That
//! cannot be undone (its message key was used up when it was read), so it is reported. Bob's store
//! is damaged the old way: his daemon is the mutant build as `old-row-ids` while he receives
//! Alice's posts, restarts, and posts. Then the shipped daemon opens it. Asserted: `vox status`
//! reports exactly one message lost that way, and Bob reads one post fewer (else APPARATUS (the mutant peer):
//! nothing was lost).
//!
//! ## Mutations
//! - no refusal of an unclassifiable entry before it is held (`unclassifiable` answering `None`):
//!   arm 1 goes red at (4), the entry was stored;
//! - that, and a refusal after it is held ending the pass as an error again: red at (2), the room's
//!   sync is poisoned;
//! - v0.2.10's Withheld rule (a payload-less entry set aside): the stripped arm goes red at (2);
//! - a body not received taken as expired (never owed): the stripped arm goes red at (2), and Bob
//!   never asks again;
//! - no report of a lost message: arm 3 goes red;
//! - no binding check before holding (`unclassifiable` answering `None` for governance): the
//!   misbound arm goes red, the entry was stored.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, announced, counter, failures, mutant_sender, Member, Proc};

/// How long a post may take to reach a member before it counts as never.
const ARRIVES_WITHIN: Duration = Duration::from_secs(30);

/// Whether `m` reads `text` in `room` now (`vox room read`, which needs the room open); `Err`
/// quotes a `vox room read` that failed, so a failing read is never taken for "not yet".
fn reads(m: &Member, room: &str, text: &str) -> Result<bool, String> {
    let (ok, out, err) = m.vox(&["room", "read", room], None);
    if ok {
        Ok(out.lines().any(|l| l.ends_with(text)))
    } else {
        Err(format!("{out}{err}").trim().to_owned())
    }
}

/// Wait until `m` reads `text`, up to [`ARRIVES_WITHIN`]; how long it took, or why not: never
/// shown by reads that worked, or the last `vox room read` that failed, quoted.
fn arrives(m: &Member, room: &str, text: &str) -> Result<Duration, String> {
    let t = Instant::now();
    let mut failed = None;
    while t.elapsed() < ARRIVES_WITHIN {
        match reads(m, room, text) {
            Ok(true) => return Ok(t.elapsed()),
            Ok(false) => failed = None,
            Err(e) => failed = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(match failed {
        Some(e) => format!("not read within {ARRIVES_WITHIN:?}; `vox room read` failed: {e}"),
        None => format!("`vox room read` worked and did not show it within {ARRIVES_WITHIN:?}"),
    })
}

/// Send `sig` to `p`, and check from `ps` that it took: stopped after `-STOP`, running after
/// `-CONT`.
fn signal_took(p: &Proc, sig: &str, who: &str) {
    p.signal(sig);
    let state = |pid: u32| {
        std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    };
    let t = Instant::now();
    loop {
        let st = state(p.pid());
        if st.starts_with('T') == (sig == "-STOP") {
            return;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "APPARATUS: kill {sig} of {who}'s process did not take: its state is {st:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The entry hashes of the messages `m` shows as not received yet in `room` (V030-10), from the
/// first column of `vox room read`.
fn owed_rows(m: &Member, room: &str) -> Vec<String> {
    let (ok, out, _) = m.vox(&["room", "read", room], None);
    if !ok {
        return Vec::new();
    }
    out.lines()
        .filter(|l| l.ends_with(vox_core::node::api::NOT_RECEIVED_YET))
        .filter_map(|l| l.split(' ').next().map(str::to_owned))
        .collect()
}

/// The entry hash `m` shows `text` under in `room`, from the first column of `vox room read`.
fn hash_of(m: &Member, room: &str, text: &str) -> Option<String> {
    let (_, out, _) = m.vox(&["room", "read", room], None);
    out.lines()
        .find(|l| l.ends_with(text))
        .and_then(|l| l.split(' ').next().map(str::to_owned))
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
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
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
        arrives(&bob, &room, first).is_ok(),
        "PRODUCT (staging): alice's first post never reached bob, before anything hostile"
    );

    let since = refused(&bob, None);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_by(&bob, None, since);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    assert!(
        refused >= 1,
        "PRODUCT (staging): bob never refused mallory's entry (it never reached him)\nbob's status: {}",
        bob.status()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] unclassifiable: bob refused {refused} entr(ies); alice's next post reached him: \
         {took:?}"
    );
    if let Err(e) = &took {
        panic!(
            "PRODUCT: alice's post made after mallory's unclassifiable entry never reached bob \
             ({e}): the room's sync stopped\nbob's status: {}\nbob:\n{}",
            bob.status(),
            bob_d.transcript()
        );
    }
    // A refusal is not a failed session: before, it ended bob's session with the refusal as its
    // reason and poisoned the room's sync until a reopen, and alice's post came only when she
    // pushed it again. The reason is hard-coded here.
    let poisoned: Vec<String> = failures(&bob.status())
        .into_iter()
        .filter(|f| f.contains("neither a group message nor a governance struct"))
        .collect();
    assert!(
        poisoned.is_empty(),
        "PRODUCT: mallory's unclassifiable entry failed bob's sync sessions: {poisoned:?}"
    );

    // ---- bob restarts: the room is held again, whole, and nothing hostile was stored --------
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, after);
    let aside = set_aside(&bob);
    println!(
        "[proof] unclassifiable: after a restart bob reads it: {reopened:?}; set aside: {aside:?}"
    );
    if let Err(e) = &reopened {
        panic!(
            "PRODUCT: after a restart bob's room is not open, or has lost alice's post ({e})\n\
             bob's status: {}",
            bob.status()
        );
    }
    assert!(
        aside.is_empty(),
        "PRODUCT: mallory's unclassifiable entry was stored before it was refused: the reopen \
         set aside {aside:?}"
    );
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_stripped_body_is_owed_and_asked_for_until_it_arrives() {
    const MODE: &str = "strip-payload";
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
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
        arrives(&mallory, &room, warm).is_ok(),
        "PRODUCT (staging): alice's first post never reached mallory"
    );
    // Not a precondition: bob may take this one from mallory too, stripped.
    if let Err(e) = arrives(&bob, &room, warm) {
        panic!(
            "PRODUCT: bob never read alice's first post ({e}): he holds an empty copy\n\
             bob's status: {}",
            bob.status()
        );
    }

    // ---- bob's only copy of alice's posts is mallory's --------------------------------------
    let sessions = |m: &Member| {
        let st = bob.status();
        counter(&st, "opened", Some(&m.fp)) + counter(&st, "admitted", Some(&m.fp))
    };
    let with_mallory = sessions(&mallory);
    signal_took(&bob_d, "-STOP", "bob");
    // Two, so the second shows whether alice's feed goes on past a body bob does not have.
    let posts = [
        "alice, while bob was away",
        "alice, again while bob was away",
    ];
    for p in posts {
        alice.post(&room, p);
    }
    let held: Vec<Result<Duration, String>> =
        posts.iter().map(|p| arrives(&mallory, &room, p)).collect();
    // Which entries they are, as alice shows them: what bob must show as not received yet.
    let hashes: Vec<String> = posts
        .iter()
        .filter_map(|p| hash_of(&alice, &room, p))
        .collect();
    // The anchor holds the room's entries too, and would serve bob the whole ones.
    signal_took(&alice_d, "-STOP", "alice");
    signal_took(&anchor_d, "-STOP", "the anchor");
    signal_took(&bob_d, "-CONT", "bob");
    for (p, h) in posts.iter().zip(&held) {
        if let Err(e) = h {
            panic!(
                "PRODUCT (staging): mallory never had alice's post {p:?}, so bob could not get it \
                 from her: {e}"
            );
        }
    }
    assert_eq!(
        hashes.len(),
        posts.len(),
        "PRODUCT (staging): alice's own read does not show her posts"
    );
    // **The envelopes are taken and the bodies are owed** (V030-10): bob shows both posts as not
    // received yet, the second linked after the first, while mallory is his only source.
    let owed_posts = |m: &Member| {
        let owed = owed_rows(m, &room);
        hashes.iter().filter(|h| owed.contains(h)).count()
    };
    let t = Instant::now();
    let mut owed = 0;
    while t.elapsed() < ARRIVES_WITHIN {
        owed = owed_posts(&bob);
        if owed >= posts.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let served = sessions(&mallory).saturating_sub(with_mallory);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    assert!(
        served >= 1,
        "PRODUCT (staging): bob had no session with mallory while alice was stopped\nbob's status: {}",
        bob.status()
    );
    println!(
        "[proof] stripped: with mallory his only source, bob shows {owed} of alice's {} posts as \
         not received yet",
        posts.len()
    );
    assert!(
        owed >= posts.len(),
        "PRODUCT: bob shows {owed} of alice's {} stripped posts as not received yet: an envelope \
         without its body was set aside, or taken as expired\nbob reads: {:?}",
        posts.len(),
        bob.vox(&["room", "read", &room], None).1
    );

    // ---- alice comes back: bob asks again and gets her posts whole --------------------------
    signal_took(&alice_d, "-CONT", "alice");
    signal_took(&anchor_d, "-CONT", "the anchor");
    for p in posts {
        let took = arrives(&bob, &room, p);
        println!("[proof] stripped: {p:?} reached bob whole: {took:?}");
        if let Err(e) = &took {
            panic!(
                "PRODUCT: bob never read {p:?} once alice was back ({e}): the body he was owed was \
                 not asked for again\nbob reads: {:?}",
                bob.vox(&["room", "read", &room], None).1
            );
        }
    }
    println!(
        "[proof] stripped: bob reads:\n{}",
        bob.vox(&["room", "read", &room], None).1
    );
    let left = owed_posts(&bob);
    assert_eq!(
        left,
        0,
        "PRODUCT: bob reads alice's posts and still shows {left} of them as not received yet\n\
         bob reads: {:?}",
        bob.vox(&["room", "read", &room], None).1
    );
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, posts[1]);
    println!("[proof] stripped: after a restart bob reads it: {reopened:?}");
    if let Err(e) = &reopened {
        panic!(
            "PRODUCT: after a restart bob's room is not open, or has lost alice's post ({e})\n\
             bob's status: {}",
            bob.status()
        );
    }
}

#[test]
#[ignore = "real daemons with the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_message_lost_to_the_old_row_ids_is_reported() {
    const MODE: &str = "old-row-ids";
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
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
        if let Err(e) = arrives(&bob, &room, p) {
            panic!("PRODUCT (staging): bob never received {p:?}: {e}");
        }
    }
    // ---- bob's store is damaged the old way: restart, post ---------------------------------
    drop(bob_d);
    let bob_d = bob.daemon_mutant(&sender, MODE, Some(&spec));
    bob.post(&room, "bob, after the restart");
    assert!(
        announced(&bob_d, MODE),
        "APPARATUS (the mutant peer): bob's daemon never announced {MODE:?}:\n{}",
        bob_d.transcript()
    );
    drop(bob_d);

    // ---- the shipped daemon opens it --------------------------------------------------------
    let _bob_d = bob.daemon(Some(&spec));
    if let Err(e) = arrives(&bob, &room, "bob, after the restart") {
        panic!("PRODUCT: the shipped daemon does not hold bob's room: {e}");
    }
    let (read_ok, read, read_err) = bob.vox(&["room", "read", &room], None);
    assert!(
        read_ok,
        "PRODUCT: bob's `vox room read` failed after it had shown his post: {read}{read_err}"
    );
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
        "APPARATUS (the mutant peer): the old row ids lost nothing (bob reads {kept} of 3)"
    );
    assert_eq!(
        lost.len(),
        hers.len() - kept,
        "PRODUCT: bob lost {} of alice's posts to the old row ids; vox status reports {lost:?}",
        hers.len() - kept
    );
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_misbound_governance_entry_is_refused_and_the_room_syncs_on() {
    const MODE: &str = "author-misbound";
    watchdog::arm();
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
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
        arrives(&bob, &room, first).is_ok(),
        "PRODUCT (staging): alice's first post never reached bob, before anything hostile"
    );

    let since = refused(&bob, None);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_by(&bob, None, since);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    assert!(
        refused >= 1,
        "PRODUCT (staging): bob never refused mallory's entry (it never reached him)\nbob's status: {}",
        bob.status()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] misbound: bob refused {refused} entr(ies); alice's next post reached him: \
         {took:?}"
    );
    if let Err(e) = &took {
        panic!(
            "PRODUCT: alice's post made after mallory's misbound governance entry never reached \
             bob ({e}): the room's sync stopped\nbob's status: {}\nbob:\n{}",
            bob.status(),
            bob_d.transcript()
        );
    }
    // A refusal is not a failed session: before, it ended bob's session with the refusal as its
    // reason and poisoned the room's sync until a reopen, and alice's post came only when she
    // pushed it again. The reason is hard-coded here.
    let poisoned: Vec<String> = failures(&bob.status())
        .into_iter()
        .filter(|f| f.contains("disagrees with log entry"))
        .collect();
    assert!(
        poisoned.is_empty(),
        "PRODUCT: mallory's misbound governance entry failed bob's sync sessions: {poisoned:?}"
    );

    // ---- bob restarts: the room is held again, whole, and nothing hostile was stored --------
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, after);
    let aside = set_aside(&bob);
    println!("[proof] misbound: after a restart bob reads it: {reopened:?}; set aside: {aside:?}");
    if let Err(e) = &reopened {
        panic!(
            "PRODUCT: after a restart bob's room is not open, or has lost alice's post ({e})\n\
             bob's status: {}",
            bob.status()
        );
    }
    assert!(
        aside.is_empty(),
        "PRODUCT: mallory's misbound governance entry was stored before it was refused: the \
         reopen set aside {aside:?}"
    );
}
