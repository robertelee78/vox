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
//! 1. Bob refused it (else PRODUCT (staging): it never reached him): `refused` in `vox status
//!    --json` counts an entry refused once taken; since the typed v2 headers (6b425ba42) Bob's
//!    sparse validation refuses it before it is held, as the serving peer's fault, and a sync
//!    session's `last_failure` names it ("ordinary content carrier");
//! 2. Alice's post made after it reaches Bob;
//! 3. Bob's daemon restarts and still holds the room, with Alice's post in it;
//! 4. nothing was set aside when it reopened: the entry was refused before it was stored.
//!
//! ## A governance entry that does not bind to itself ([`a_misbound_governance_entry_is_refused_and_the_room_syncs_on`])
//! Mallory runs as `author-misbound`: what she posts is a real consent grant, signed, whose body
//! names an epoch 7 past the entry's own. It was written for the issue's first case: a governance
//! body with the wrong channel or epoch, which classifies as governance and does not bind. Since
//! the typed v2 headers (6b425ba42) the mode signs the grant as ordinary content, so Bob refuses it
//! earlier, at the typed-carrier check ("ordinary content carrier"), before any binding is read;
//! the binding of a governance-kind entry is not staged by this mode. Asserted as for the
//! unclassifiable entry: Bob refused it, Alice's next post reaches Bob, none of Bob's sessions
//! failed with the old binding reason, and after a restart the room is open with nothing set
//! aside. Arm and mode by the verifier (vox-0e-ver74).
//!
//! ## A body stripped in transit is owed ([`a_stripped_body_is_owed_and_asked_for_until_it_arrives`])
//! Mallory runs as `strip-payload`: she serves every entry without its payload (the legacy serve)
//! and answers every ordinary body asked for on the history path as not held. The signature
//! covers the skeleton only, so the stripped entry verifies. v0.2.10 set it aside (V210-74); in
//! v0.3.0 an honest peer serves payload-less skeletons too (retention), so the decider's rule holds
//! (V030-10, 2026-10-01): the envelope is taken, and a body not received that has not expired by
//! the receiver's own reckoning is owed, shown as "not received yet" and asked for on every sync.
//! Staging: Bob is stopped (SIGSTOP), Alice posts twice, Mallory gets both; Alice and the anchor
//! (which holds the room's entries too) are stopped and Bob resumed, so Bob's only copy is Mallory's.
//! Asserted:
//! 1. Bob reads Alice's first post (Mallory may serve that one too);
//! 2. with Mallory his only source, Bob shows both posts as not received yet: the envelopes were
//!    taken and Alice's feed goes on past the first (precondition: Bob completed a sync round
//!    with Mallory while Alice was stopped, else PRODUCT (staging));
//! 3. once Alice is back, Bob reads both, and shows nothing as not received yet;
//! 4. and still reads them after his daemon restarts.
//!
//! ## A member that terminated its feed and hides it ([`a_post_after_a_hidden_termination_is_never_shown`])
//! ADR-053 MP-10 (c). Mallory first runs as an ordinary member (mode `correct`) and posts; then her
//! daemon restarts as `terminate-and-withhold`: her next post is preceded by a signed
//! `Termination` of her own feed, she posts twice more past it, and she never serves the
//! termination's header (to Bob, Alice or the anchor), so the only copy is hers. Asserted on Bob
//! (shipped binary):
//! 1. while it is withheld: Bob knows Mallory's later positions (her advertised head is past both
//!    posts) and shows Alice's post written after them, and in three status answers in a row, with
//!    rounds toward Mallory completing, Bob shows neither later post and holds neither as a verified
//!    source (his verified prefix of Mallory stays below the first) — unrendered and non-citable;
//! 2. once Mallory restarts as `terminated-serves` and the termination is supplied (Bob's verified
//!    prefix of Mallory moves past what it was), Bob still shows neither later post, holds neither as
//!    a source over three answers with rounds completing, shows Alice's next post, and nothing he
//!    reports names a store error;
//! 3. the same after Bob's daemon restarts.
//!
//! Mutant `VOX_MUTANT_TERMINATION=unchecked` (given to Bob's daemon only): the validator accepts a
//! later position without the author's own termination evidence. It goes red at (2): once the
//! termination is supplied, the later entry reaches publication's last fence and Bob reports
//! `malformed at-rest artifact: sparse source follows a terminated feed` (also what v0.4.31 main
//! reports). At (1) the entry is still not shown under this mutant: a later stage also needs the
//! author's own controls (not traced to its line), so (1) stays green under this mutant.
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
//! - `VOX_MUTANT_TERMINATION=unchecked`: the hidden-termination arm goes red at (2).

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, announced, counter, failures, mutant_sender, Member, Proc};

/// How long a post may take to reach a member before it counts as never.
const ARRIVES_WITHIN: Duration = Duration::from_secs(30);

/// Bob's session failure when he refuses mallory's posted entry before holding it: its signed
/// kind is ordinary content and its body is not a group message (`governance/sparse.rs`, the
/// typed-carrier check).
const CARRIER: &str = "malformed identity bundle: ordinary content carrier";

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

/// `m`'s refusals so far, from anyone: (entries refused once taken, sessions failed).
fn refusals(m: &Member) -> (u64, u64) {
    let status = m.status();
    (
        counter(&status, "refused", None),
        counter(&status, "failed", None),
    )
}

/// Wait until `m` has refused an entry since `since` ([`refusals`]); how, or `None` within
/// [`ARRIVES_WITHIN`]. Either an entry refused once taken (`refused`), or — since the typed v2
/// headers (6b425ba42), whose sparse validation refuses an entry whose body does not fit its
/// signed kind before it is held, as the serving peer's fault — a session that failed and names
/// `why` as its last failure.
fn refused_by(m: &Member, since: (u64, u64), why: &str) -> Option<String> {
    let t = Instant::now();
    loop {
        let status = m.status();
        let refused = counter(&status, "refused", None).saturating_sub(since.0);
        if refused > 0 {
            return Some(format!("{refused} entr(ies) refused once taken"));
        }
        let failed = counter(&status, "failed", None).saturating_sub(since.1);
        let named: Vec<String> = failures(&status)
            .into_iter()
            .filter(|f| f.contains(why))
            .collect();
        if failed > 0 && !named.is_empty() {
            return Some(format!(
                "{failed} session(s) failed since, refusing it as the peer's fault: {named:?}"
            ));
        }
        if t.elapsed() > ARRIVES_WITHIN {
            return None;
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

    let since = refusals(&bob);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_by(&bob, since, CARRIER);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let Some(refused) = refused else {
        panic!(
            "PRODUCT (staging): bob never refused mallory's entry (it never reached him)\nbob's status: {}",
            bob.status()
        );
    };
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] unclassifiable: bob refused it ({refused}); alice's next post reached him: \
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
    // The refusal of an entry once taken must not fail the session that served it: before, it
    // ended bob's session with the refusal as its reason and poisoned the room's sync until a
    // reopen, and alice's post came only when she pushed it again. The reason is hard-coded here.
    // (A refusal before the entry is held, as the serving peer's fault, is what rejection looks
    // like since 6b425ba42; that the room syncs on is (2).)
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
    // Sync rounds with mallory, empty ones included: a room syncs in bounded rounds, which the
    // legacy session counters (`opened`, `admitted`) no longer count.
    let sessions = |m: &Member| rounds_toward(&bob.status(), m);
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

    let since = refusals(&bob);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_by(&bob, since, CARRIER);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let Some(refused) = refused else {
        panic!(
            "PRODUCT (staging): bob never refused mallory's entry (it never reached him)\nbob's status: {}",
            bob.status()
        );
    };
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] misbound: bob refused it ({refused}); alice's next post reached him: {took:?}"
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

/// `of`'s feed as `status` reports it in `room`: (advertised head, verified contiguous prefix).
fn feed_view(status: &serde_json::Value, room: &str, of: &Member) -> (Option<u64>, Option<u64>) {
    let same = |a: &str, b: &str| a.starts_with(b) || b.starts_with(a);
    let row = status["rooms"]
        .as_array()
        .and_then(|rooms| {
            rooms
                .iter()
                .find(|r| r["id"].as_str().is_some_and(|id| same(id, room)))
        })
        .and_then(|r| r["members"].as_array())
        .and_then(|members| {
            members
                .iter()
                .find(|m| m["id"].as_str().is_some_and(|id| same(id, &of.fp)))
        });
    row.map_or((None, None), |r| {
        (
            r["advertised_through"].as_u64(),
            r["verified_through"].as_u64(),
        )
    })
}

/// Rounds `status` reports completed toward `peer`, empty ones included: evidence it asked.
fn rounds_toward(status: &serde_json::Value, peer: &Member) -> u64 {
    ["completed", "empty", "fetched_completed", "fetched_empty"]
        .iter()
        .map(|key| counter(status, key, Some(&peer.fp)))
        .sum()
}

/// Nothing `m` reports names a store error from a terminated feed: its status and its room read.
/// A refusal of the author's entry as the peer's fault (a session's `last_failure` naming the
/// termination as a malformed bundle) is what rejection looks like, and is allowed.
fn no_store_error(m: &Member, room: &str, phase: &str) {
    let status = m.status();
    let text = status.to_string();
    let (ok, out, err) = m.vox(&["room", "read", room], None);
    for said in ["terminated feed", "malformed at-rest"] {
        assert!(
            !text.contains(said),
            "PRODUCT ({phase}): {}'s `vox status --json` reports {said:?}: {text}",
            m.name
        );
    }
    assert!(
        ok,
        "PRODUCT ({phase}): {}'s `vox room read` failed: {out}{err}",
        m.name
    );
}

/// Watch `bob` until three status answers in a row show none of `later`, `of`'s verified prefix
/// flat at a value in `floor..below`, and rounds toward `of` advancing; the prefix it held at.
/// Bob showing any of `later` is the RED verdict; neither within 600 s is APPARATUS NO RESULT.
fn holds_back(
    bob: &Member,
    room: &str,
    of: &Member,
    later: &[&str],
    (floor, below): (u64, u64),
    phase: &str,
) -> u64 {
    let started = Instant::now();
    let mut samples: Vec<(u64, u64)> = Vec::new();
    loop {
        for text in later {
            match reads(bob, room, text) {
                Ok(false) => {}
                Ok(true) => panic!(
                    "RED PRODUCT ({phase}): bob shows {text:?}, which {} wrote after \
                     terminating her feed\nbob's status: {}",
                    of.name,
                    bob.status()
                ),
                Err(e) => panic!("PRODUCT ({phase}): bob's `vox room read` failed: {e}"),
            }
        }
        let status = bob.status();
        let (_, verified) = feed_view(&status, room, of);
        match verified {
            Some(v) if (floor..below).contains(&v) => {
                samples.push((v, rounds_toward(&status, of)));
                if samples.len() > 3 {
                    samples.remove(0);
                }
            }
            _ => samples.clear(),
        }
        if samples.len() == 3
            && samples.iter().all(|s| s.0 == samples[0].0)
            && samples[2].1 > samples[0].1
        {
            println!(
                "[proof] {phase}: bob's sync rows toward {}: {}",
                of.name,
                status["sync"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|r| r["peer"]
                        .as_str()
                        .is_some_and(|p| of.fp.starts_with(p) || p.starts_with(of.fp.as_str())))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            return samples[2].0;
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT ({phase}): in 600 s bob neither showed {}'s later posts nor \
             held her verified prefix flat in {floor}..{below} with rounds completing: \
             samples {samples:?}; status: {status}",
            of.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_post_after_a_hidden_termination_is_never_shown() {
    watchdog::arm();
    let sender = mutant_sender();
    // The reader mutant goes to Bob's daemon only; Mallory is the attacker, Alice a witness.
    let mutant = std::env::var("VOX_MUTANT_TERMINATION").ok();
    let bob_env: Vec<(&str, &str)> = mutant
        .as_deref()
        .map(|m| vec![("VOX_MUTANT_TERMINATION", m)])
        .unwrap_or_default();
    // Kept: the run directory holds every daemon's log for the record.
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir").keep();
    let root = tmp.as_path();
    let (_anchor, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let mallory = Member::new(root, "mallory");
    for (a, b) in [(&alice, &bob), (&alice, &mallory), (&bob, &mallory)] {
        a.trust(b);
        b.trust(a);
    }
    let _alice_d = alice.daemon(Some(&spec));
    let mut bob_d = bob.daemon_with_anchor(Some(&spec), &bob_env);
    let mallory_d = mallory.daemon_mutant(&sender, "correct", Some(&spec));
    let room = alice.create("terminated");
    let link = alice.invite(&room);
    bob.join(&link, "terminated");
    mallory.join(&link, "terminated");
    let before = "mallory, before she terminates";
    mallory.post(&room, before);
    assert!(
        arrives(&bob, &room, before).is_ok(),
        "PRODUCT (staging): mallory's ordinary post never reached bob"
    );
    let (_, verified) = feed_view(&bob.status(), &room, &mallory);
    let base = verified.unwrap_or_else(|| {
        panic!(
            "PRODUCT (staging): bob shows mallory's post but reports no verified prefix of her \
             feed: {}",
            bob.status()
        )
    });

    // ---- 1. Mallory terminates, posts on, and withholds the termination ------------------------
    drop(mallory_d);
    let mallory_d = mallory.daemon_mutant(&sender, "terminate-and-withhold", Some(&spec));
    let later = [
        "mallory, after terminating (1)",
        "mallory, after terminating (2)",
    ];
    for text in later {
        mallory.post(&room, text);
    }
    let written = "alice, after mallory's later posts";
    alice.post(&room, written);
    if let Err(e) = arrives(&bob, &room, written) {
        panic!(
            "PRODUCT: alice's post never reached bob while mallory withholds her termination \
             ({e})\nbob's status: {}",
            bob.status()
        );
    }
    assert!(
        announced(&mallory_d, "terminate-and-withhold"),
        "APPARATUS (the mutant peer): mallory's daemon never announced its mode:\n{}",
        mallory_d.transcript()
    );
    // Bob knows her later positions: the termination and both posts lie at or below her head.
    let started = Instant::now();
    let head = loop {
        let status = bob.status();
        if let (Some(head), _) = feed_view(&status, &room, &mallory) {
            if head >= base + 3 {
                break head;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT (withheld): bob never learned mallory's head past {base} + 3: \
             {status}"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    // `head - 1` is the first later post's position or the termination's: neither may be held.
    let withheld = holds_back(&bob, &room, &mallory, &later, (base, head - 1), "withheld");
    no_store_error(&bob, &room, "withheld");
    println!(
        "[proof] hidden termination, withheld: mallory's head {head} known to bob, his verified \
         prefix of her held at {withheld} (from {base}); neither later post shown; alice's post shown"
    );

    // ---- 2. the termination is supplied ---------------------------------------------------------
    drop(mallory_d);
    let mallory_d = mallory.daemon_mutant(&sender, "terminated-serves", Some(&spec));
    let supplied = "alice, once mallory serves her termination";
    alice.post(&room, supplied);
    if let Err(e) = arrives(&bob, &room, supplied) {
        panic!(
            "PRODUCT: alice's post never reached bob once mallory's termination was served \
             ({e})\nbob's status: {}",
            bob.status()
        );
    }
    let taken = holds_back(
        &bob,
        &room,
        &mallory,
        &later,
        (withheld + 1, head - 1),
        "supplied",
    );
    no_store_error(&bob, &room, "supplied");
    assert!(
        announced(&mallory_d, "terminated-serves"),
        "APPARATUS (the mutant peer): mallory's daemon never announced its mode:\n{}",
        mallory_d.transcript()
    );
    println!(
        "[proof] hidden termination, supplied: bob took it (verified prefix {withheld} -> \
         {taken}) and holds neither later post; alice's post shown; no store error"
    );

    // ---- 3. after Bob's restart ------------------------------------------------------------------
    drop(bob_d);
    bob_d = bob.daemon_with_anchor(Some(&spec), &bob_env);
    let restarted = "alice, after bob restarts";
    alice.post(&room, restarted);
    if let Err(e) = arrives(&bob, &room, restarted) {
        panic!(
            "PRODUCT: after a restart bob does not read alice's post ({e})\nbob's status: {}\nbob:\n{}",
            bob.status(),
            bob_d.transcript()
        );
    }
    let kept = holds_back(
        &bob,
        &room,
        &mallory,
        &later,
        (taken, head - 1),
        "restarted",
    );
    no_store_error(&bob, &room, "restarted");
    println!(
        "[proof] hidden termination, after bob's restart: verified prefix {kept}; neither later \
         post shown; alice's post shown"
    );
}
