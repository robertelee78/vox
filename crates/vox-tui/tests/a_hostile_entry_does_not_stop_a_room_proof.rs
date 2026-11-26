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
//! Asserted: Alice's next post reaches Bob, and after Bob restarts he still reads it.
//!
//! ## A governance entry that does not bind to itself ([`a_misbound_governance_entry_is_refused_and_the_room_syncs_on`])
//! Mallory runs as `author-misbound`: what she posts is a real consent grant, signed with kind
//! Governance, whose body names an epoch 7 past the entry's own: the issue's first case, a
//! governance body with the wrong channel or epoch. Its signed kind and its body agree, so Bob's
//! typed check reaches the governance binding (`GovEntry::body_bound_to`, from
//! `TypedSparseBody::verify`). Asserted: Alice's next post reaches Bob, and after Bob restarts
//! he still reads it.
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
//! 2. with Mallory his only source, Bob shows both posts as not received yet;
//! 3. Bob's terminal app (his real `vox tui` in a pty, read through pyte,
//!    `tests/pty/tui_marks_read.py`) shows Alice's first post, held and unread, beside the two
//!    placeholders: his node marks the first post read (`vox room read --unread` no longer lists
//!    it) while the placeholders are shown (a placeholder is not read; his node refuses a
//!    read-mark batch naming one whole, which the act asks for over his control socket first and
//!    quotes, so a terminal app that sent one would leave the first post unread);
//! 4. once Alice is back, Bob reads both, and shows nothing as not received yet; Alice's node
//!    says her first post is read by bob;
//! 5. and still reads them after his daemon restarts.
//!
//! On the history path (rooms with authenticated history) the "not received yet" row is written
//! with the entry's effect, where its text would have been shown, once Bob's own decision says the
//! body is for him (ADR-036 H-4); before that change Bob took the envelope and showed nothing
//! (ledger 74).
//!
//! ## A body its only holder no longer keeps ([`a_body_its_only_holder_no_longer_keeps_is_shown_as_not_received_yet`])
//! The honest case of the same rule (LS-33: a node ships no body it no longer holds). All run the
//! shipped binary. The room keeps a week; Carol's node keeps a minute (`cfg/retention`, ADR-023
//! decision 2). Bob is stopped, Alice posts, Carol takes it and a minute later lets its body go;
//! Alice and the anchor are stopped and Bob resumed, so Carol, who serves the envelope and answers
//! the body as not held, is his only holder.
//!
//! Carol stops showing the post when it expires (her read hides an expired row), and her node
//! drops its body only at its retention worker's next prune; until then it still serves the text.
//! So Bob is resumed only once Carol's `vox status --json` says she no longer holds the post: her
//! `holds_through` of Alice, which had reached the post, falls below it. That is read from her
//! rendered-message index, which the prune removes the row from in the same store batch that
//! drops the body (APPARATUS when it does not, within the minute's bound). Asserted:
//! 1. Bob shows Alice's post as not received yet, in its place right after her first, without its text;
//! 2. once Alice is back, Bob reads the post and no longer shows it as not received yet.
//!
//!
//! ## Mutations
//! - v0.2.10's Withheld rule (a payload-less entry set aside): the stripped arm goes red at (2);
//! - a body not received taken as expired (never owed): the stripped arm goes red at (2), and Bob
//!   never asks again;
//! - no report of a lost message: arm 3 goes red;
//! - `VOX_MUTANT_OWED_ROW=unwritten` (Bob's daemon gets `VOX_TEST_OWED_ROW=unwritten`: no "not
//!   received yet" row is written for a body-less signed message): the stripped arm goes red at
//!   (2), and the kept-less arm at (1);
//! - `VOX_MUTANT_OWED_ROW=marked` (Bob's terminal app gets it: it submits placeholders with the
//!   rest of what it showed): the stripped arm goes red at (3);
//!
//! Every owed-row mutant, the switch and its value, is checked for in the `vox` under test first
//! (`test_knobs::require`): a `vox` that does not read it says CANNOT MEASURE.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, announced, mutant_sender, Member, Proc};

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

/// The "not received yet" mutants the runner may select with `VOX_MUTANT_OWED_ROW`, each given
/// to the reader's daemon as `VOX_TEST_OWED_ROW` (`marked` to the reader's terminal app instead):
/// `unwritten` (no row is written), `unchecked` (one for every body-less message), `undecided`
/// (rows are shown while their decision is open), `marked` (the terminal app submits placeholders
/// with its read marks), `unmoved` (hiding or showing a kept placeholder while governance
/// refreshes does not move the room's display revision).
const OWED_MUTANTS: [&str; 5] = ["unwritten", "unchecked", "undecided", "marked", "unmoved"];

/// The runner's owed-row mutant, if it selected one. A `vox` that does not read the switch
/// cannot run it: CANNOT MEASURE, never a green run of the unmutated product. Each owed-row act
/// asks this first, before any staging (a Mac staging of a default `vox` stops sooner, at its
/// private Keychain, without naming the switch).
fn owed_mutant() -> Option<&'static str> {
    let mode = std::env::var("VOX_MUTANT_OWED_ROW")
        .ok()
        .filter(|m| !m.is_empty())?;
    let mode = OWED_MUTANTS
        .into_iter()
        .find(|m| *m == mode)
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE (precondition unmet): VOX_MUTANT_OWED_ROW={mode:?} names none of \
                 this act's mutants {OWED_MUTANTS:?}"
            )
        });
    test_knobs::require(&["VOX_TEST_OWED_ROW", mode]);
    Some(mode)
}

/// The reader's daemon, given the runner's owed-row mutant ([`owed_mutant`]) as
/// `VOX_TEST_OWED_ROW`. The runner's variable reaches no other daemon.
fn reader_daemon(m: &Member, spec: &str) -> Proc {
    reader_daemon_with(m, spec, &[])
}

/// [`reader_daemon`] with `env` too.
fn reader_daemon_with(m: &Member, spec: &str, env: &[(&str, &str)]) -> Proc {
    let mut env = env.to_vec();
    if let Some(mode) = owed_mutant().filter(|mode| *mode != "marked") {
        env.push(("VOX_TEST_OWED_ROW", mode));
    }
    m.daemon_with_anchor(Some(spec), &env)
}

/// The entry hash `m` shows `text` under in `room`, from the first column of `vox room read`.
fn hash_of(m: &Member, room: &str, text: &str) -> Option<String> {
    let (_, out, _) = m.vox(&["room", "read", room], None);
    out.lines()
        .find(|l| l.ends_with(text))
        .and_then(|l| l.split(' ').next().map(str::to_owned))
}

/// Which of `texts` `m`'s node has unread in `room` (`vox room read --unread`, which marks
/// nothing); `Err` quotes a read that failed.
fn unread_of<'a>(m: &Member, room: &str, texts: &[&'a str]) -> Result<Vec<&'a str>, String> {
    let (ok, out, err) = m.vox(&["room", "read", room, "--unread"], None);
    if !ok {
        return Err(format!("`vox room read --unread` failed: {out}{err}"));
    }
    Ok(texts
        .iter()
        .copied()
        .filter(|t| out.lines().any(|l| l.ends_with(t)))
        .collect())
}

/// `m`'s real `vox tui` (`tests/pty/tui_marks_read.py`, through pyte), on its attached node: it
/// waits until the room's timeline shows `want` and a message not received yet, then stays open
/// showing both until `marked` says the node took what it showed, at most [`ARRIVES_WITHIN`],
/// and gives the screen it showed. The runner's `marked` mutant goes to the TUI only. A TUI that
/// never showed both within the driver's bound is APPARATUS NO RESULT: its node showed both
/// already, and elapsed time is no verdict on the TUI.
fn terminal_marks(
    m: &Member,
    root: &std::path::Path,
    want: &str,
    mut marked: impl FnMut() -> bool,
) -> String {
    terminal(m, root, want, Duration::from_secs(120), |_| {
        let t = Instant::now();
        while t.elapsed() < ARRIVES_WITHIN && !marked() {
            std::thread::sleep(Duration::from_millis(250));
        }
    })
}

/// [`terminal_marks`]'s terminal app, kept open at most `keep` once it showed both, while
/// `while_shown` runs with a reader of what its timeline shows now (`None` before the driver's
/// first look); the screen it showed first.
fn terminal(
    m: &Member,
    root: &std::path::Path,
    want: &str,
    keep: Duration,
    while_shown: impl FnOnce(&dyn Fn() -> Option<String>),
) -> String {
    let cues = root.join(format!("{}-tui-cues", m.name));
    std::fs::create_dir_all(&cues).expect("APPARATUS: could not make the TUI's cue directory");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_marks_read.py");
    let args: Vec<String> = vec![
        env!("CARGO_BIN_EXE_vox").to_owned(),
        m.dir.to_string_lossy().into_owned(),
        m.dir.join("cfg").to_string_lossy().into_owned(),
        cues.to_string_lossy().into_owned(),
        want.to_owned(),
        m.name.to_owned(),
        owed_mutant()
            .filter(|mode| *mode == "marked")
            .unwrap_or("-")
            .to_owned(),
        keep.as_secs().to_string(),
    ];
    // The driver's own budget grows by what `keep` adds to its default 120 s; so does its bound.
    let bound = pty_driver::BOUND + keep.saturating_sub(Duration::from_secs(120));
    let driver = std::thread::spawn(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        pty_driver::run_within(script, &args, bound)
    });
    // The driver cues `shown` once the timeline shows both, then waits for `done`.
    while !cues.join("shown").exists() && !driver.is_finished() {
        std::thread::sleep(Duration::from_millis(100));
    }
    let shown = cues.join("shown").exists();
    if shown {
        // The TUI stays open, drawing; the driver writes what its timeline shows on every look.
        let screen = || std::fs::read_to_string(cues.join("screen")).ok();
        while_shown(&screen);
    }
    std::fs::write(cues.join("done"), b"").expect("APPARATUS: could not cue the TUI driver");
    let out = driver
        .join()
        .expect("APPARATUS: the TUI driver thread panicked");
    let tag = format!("{} SHOWN:", m.name);
    match (shown, out.code) {
        _ if !out.has_verdict(m.name) => panic!(
            "APPARATUS: the TUI driver for {} ended with no verdict (exit {:?}, stage {:?}): {}",
            m.name, out.code, out.stage, out.stdout
        ),
        (true, Some(0)) => out
            .stdout
            .split_once(&tag)
            .map_or_else(|| out.stdout.clone(), |(_, s)| s.to_owned()),
        (false, Some(1)) if out.stdout.contains(" NO RESULT: ") => {
            panic!(
                "APPARATUS NO RESULT: {}'s terminal app: {}",
                m.name, out.stdout
            )
        }
        _ => panic!(
            "APPARATUS: the TUI driver for {} ended without its verdict (exit {:?}, stage {:?}): \
             {}",
            m.name, out.code, out.stage, out.stdout
        ),
    }
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

    mallory.post(&room, "whatever mallory typed");
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!("[proof] unclassifiable: alice's next post reached bob: {took:?}");
    if let Err(e) = &took {
        panic!(
            "PRODUCT: alice's post made after mallory's unclassifiable entry never reached bob \
             ({e}): the room's sync stopped\nbob's status: {}\nbob:\n{}",
            bob.status(),
            bob_d.transcript()
        );
    }

    // ---- bob restarts: the room is held again -----------------------------------------------
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, after);
    println!("[proof] unclassifiable: after a restart bob reads it: {reopened:?}");
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
fn a_stripped_body_is_owed_and_asked_for_until_it_arrives() {
    const MODE: &str = "strip-payload";
    watchdog::arm();
    owed_mutant();
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
    let bob_d = reader_daemon(&bob, &spec);
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
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
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

    // ---- bob's terminal app shows the room: what it showed is read, the placeholders aside --
    // Alice's first post is held whole and unread (`vox room read` marks nothing); her two later
    // posts are shown as not received yet beside it.
    assert_eq!(
        unread_of(&bob, &room, &[warm]),
        Ok(vec![warm]),
        "PRODUCT (staging): bob's node does not have alice's first post unread before his \
         terminal app shows it"
    );
    // What a client that names every row it shows asks for: bob's node refuses the batch whole
    // (`pending_text/read.rs`), so it marks nothing of it.
    let refused = {
        let mut reader = bob.reader();
        let id = reader.room(&room);
        let rows = reader.rows(id);
        reader.mark_read(id, rows.iter().map(|r| r.entry_hash).collect())
    };
    println!(
        "[proof] stripped: a read-mark batch of every row bob's node shows, placeholders \
         included, is answered {refused:?}"
    );
    assert!(
        matches!(refused, vox_core::node::ipc::Frame::Error { .. })
            && unread_of(&bob, &room, &[warm]) == Ok(vec![warm]),
        "CANNOT MEASURE: bob's node took a read-mark batch naming a message not received yet \
         ({refused:?}), so a terminal app that sends one is not refused"
    );
    let shown = terminal_marks(&bob, root, warm, || {
        unread_of(&bob, &room, &[warm]) == Ok(Vec::new())
    });
    println!("[proof] stripped: bob's terminal app showed:\n{shown}");
    let still = unread_of(&bob, &room, &[warm]);
    println!(
        "[proof] stripped: once bob's terminal app showed alice's first post beside {} \
         placeholders, his node has it unread: {still:?}",
        posts.len()
    );
    assert_eq!(
        still,
        Ok(Vec::new()),
        "PRODUCT: bob's terminal app showed alice's first post beside her posts not received \
         yet, and his node still has it unread {ARRIVES_WITHIN:?} later: the read marks of what \
         it showed were not taken (his node answers a batch naming a message not received yet \
         {refused:?})"
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
    // Alice, back, sees bob's read record for the post his terminal app showed him.
    let read_by = |m: &Member| -> Vec<String> {
        let (_, out, _) = m.vox(&["room", "read", &room, "--json"], None);
        out.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|row| row["text"] == warm)
            .and_then(|row| row["read_by"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    };
    let t = Instant::now();
    let mut readers = read_by(&alice);
    while t.elapsed() < ARRIVES_WITHIN && !readers.iter().any(|r| r == "bob") {
        std::thread::sleep(Duration::from_millis(250));
        readers = read_by(&alice);
    }
    println!("[proof] stripped: alice's node says her first post is read by {readers:?}");
    assert!(
        readers.iter().any(|r| r == "bob"),
        "PRODUCT: bob's terminal app showed alice's first post and his node marked it read, and \
         alice's node never says it is read by bob within {ARRIVES_WITHIN:?}: {readers:?}"
    );
    drop(bob_d);
    let _bob_d = reader_daemon(&bob, &spec);
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

/// How long a node that keeps a minute may take to let a message go: stop showing it, and drop
/// its body.
const KEPT_A_MINUTE_GOES_WITHIN: Duration = Duration::from_secs(150);

/// The latest position of `of`'s feed that `m` holds a message of, as `m`'s `vox status --json`
/// says (`holds_through`, `Channel::holds_through`): read from `m`'s rendered-message index, which
/// a retention prune removes a message from in the same store batch that drops its body
/// (`channel/pending_retention.rs`, `Step::Prune`). `m`'s read hides an expired message before
/// that; this does not.
fn holds_through(m: &Member, room: &str, of: &Member) -> Option<u64> {
    member_row(&m.status(), room, of)["holds_through"].as_u64()
}

#[test]
#[ignore = "real daemons and an anchor, a node that keeps a minute (about four minutes); CI runs it in release"]
fn a_body_its_only_holder_no_longer_keeps_is_shown_as_not_received_yet() {
    watchdog::arm();
    owed_mutant();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let (anchor_d, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let carol = Member::new(root, "carol");
    for (a, b) in [(&alice, &bob), (&alice, &carol), (&bob, &carol)] {
        a.trust(b);
        b.trust(a);
    }
    // Carol's node keeps a minute, whatever the room keeps (ADR-023 decision 2).
    std::fs::write(carol.dir.join("cfg").join("retention"), "default 60\n")
        .expect("APPARATUS: carol's node retention file");
    let alice_d = alice.daemon(Some(&spec));
    let bob_d = reader_daemon(&bob, &spec);
    let _carol_d = carol.daemon(Some(&spec));
    let room = alice.create("kept-less");
    let (ok, out, err) = alice.vox(&["room", "retention", &room, "1w"], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's vox room retention 1w: {out}{err}"
    );
    let link = alice.invite(&room);
    bob.join(&link, "kept-less");
    carol.join(&link, "kept-less");
    let warm = "alice, while everyone is up";
    alice.post(&room, warm);
    for m in [&bob, &carol] {
        if let Err(e) = arrives(m, &room, warm) {
            panic!(
                "PRODUCT (staging): {} never read alice's first post: {e}",
                m.name
            );
        }
    }

    // ---- bob is away; alice posts; carol takes it and, a minute later, lets its body go ----
    signal_took(&bob_d, "-STOP", "bob");
    let post = "alice, while bob was away";
    alice.post(&room, post);
    if let Err(e) = arrives(&carol, &room, post) {
        panic!("PRODUCT (staging): carol never read alice's post: {e}");
    }
    let hash = hash_of(&alice, &room, post)
        .unwrap_or_else(|| panic!("PRODUCT (staging): alice's own read does not show her post"));
    // The post's position in alice's feed is needed to stage Carol's retention prune.
    let post_at = holds_through(&alice, &room, &alice);
    // Carol stops showing the post when it expires; her node drops its body at its retention
    // worker's next prune, and serves the text until then. Bob is resumed only after that: once
    // her status, having said she holds alice's feed through the post, says she holds less.
    let t = Instant::now();
    let mut held = false;
    let mut hidden = None;
    let (shown_until, at_hide, gone, through) = loop {
        let through = holds_through(&carol, &room, &alice);
        held |= post_at.is_some() && through == post_at;
        if hidden.is_none() {
            match reads(&carol, &room, post) {
                Ok(false) => hidden = Some((t.elapsed(), through)),
                Ok(true) => {}
                Err(e) => panic!("PRODUCT (staging): carol's read failed: {e}"),
            }
        }
        if let Some((at, at_hide)) = hidden
            .filter(|_| held && post_at.is_some_and(|post_at| through.is_none_or(|n| n < post_at)))
        {
            break (at, at_hide, t.elapsed(), through);
        }
        if t.elapsed() >= KEPT_A_MINUTE_GOES_WITHIN {
            match hidden {
                None => panic!(
                    "PRODUCT (staging): carol's node keeps a minute and still shows alice's post \
                     after {} s",
                    t.elapsed().as_secs()
                ),
                Some((at, _)) if held => panic!(
                    "APPARATUS: carol stopped showing alice's post {} s after she read it, and {} \
                     s after, her `vox status --json` still says she holds alice's feed through \
                     it (holds_through {through:?}, the post at {post_at:?}): her node has not \
                     dropped its body, so bob cannot be resumed with carol not holding it",
                    at.as_secs(),
                    t.elapsed().as_secs()
                ),
                Some(_) => panic!(
                    "APPARATUS: carol's `vox status --json` never said she holds alice's feed \
                     through the post in {} s (holds_through {through:?}, the post at \
                     {post_at:?}), so whether her node dropped its body cannot be seen",
                    t.elapsed().as_secs()
                ),
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    println!(
        "[proof] kept less: carol stopped showing alice's post {:.1} s after she read it, her \
         status then holding alice's feed through {at_hide:?} (the post at {post_at:?}); her node \
         dropped its body {:.1} s after she read it (holds_through {through:?}): it held the text \
         {:.1} s after it no longer showed it",
        shown_until.as_secs_f64(),
        gone.as_secs_f64(),
        gone.saturating_sub(shown_until).as_secs_f64()
    );
    // Alice and the anchor hold the body; with both stopped, carol is bob's only holder.
    signal_took(&alice_d, "-STOP", "alice");
    signal_took(&anchor_d, "-STOP", "the anchor");
    signal_took(&bob_d, "-CONT", "bob");

    // ---- bob shows it in place as not received yet ------------------------------------------
    let t = Instant::now();
    let mut owed = false;
    while t.elapsed() < ARRIVES_WITHIN * 2 {
        owed = owed_rows(&bob, &room).contains(&hash);
        if owed {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let (_, shown, _) = bob.vox(&["room", "read", &room], None);
    assert!(
        owed,
        "PRODUCT: carol, bob's only holder, no longer keeps the body of alice's post, which has \
         not expired for bob (the room keeps a week), and bob does not show it as not received \
         yet\nbob reads: {shown:?}\nbob's status: {}",
        bob.status()
    );
    let lines: Vec<&str> = shown.lines().collect();
    let at_warm = lines.iter().position(|l| l.ends_with(warm));
    let at_owed = lines.iter().position(|l| l.starts_with(hash.as_str()));
    assert!(
        matches!((at_warm, at_owed), (Some(w), Some(o)) if o == w + 1),
        "PRODUCT: bob does not show alice's post as not received yet in its place, right after \
         her first: {shown:?}"
    );
    assert!(
        !shown.contains(post),
        "PRODUCT: bob shows the text of a post whose body never reached him: {shown:?}"
    );
    println!("[proof] kept less: with carol his only holder, bob shows alice's post as not received yet in its place");

    // ---- alice comes back: bob asks again and shows the text in its place --------------------
    signal_took(&alice_d, "-CONT", "alice");
    signal_took(&anchor_d, "-CONT", "the anchor");
    if let Err(e) = arrives(&bob, &room, post) {
        panic!(
            "PRODUCT: bob never read alice's post once she was back ({e}): the body he was owed \
             was not asked for again\nbob reads: {:?}",
            bob.vox(&["room", "read", &room], None).1
        );
    }
    let (_, shown, _) = bob.vox(&["room", "read", &room], None);
    assert!(
        !owed_rows(&bob, &room).contains(&hash),
        "PRODUCT: bob reads alice's post and still shows it as not received yet: {shown:?}"
    );
    println!("[proof] kept less: alice back, bob reads her post in its place:\n{shown}");
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

    mallory.post(&room, "whatever mallory typed");
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!("[proof] misbound: alice's next post reached bob: {took:?}");
    if let Err(e) = &took {
        panic!(
            "PRODUCT: alice's post made after mallory's misbound governance entry never reached \
             bob ({e}): the room's sync stopped\nbob's status: {}\nbob:\n{}",
            bob.status(),
            bob_d.transcript()
        );
    }
    // ---- bob restarts: the room is held again -----------------------------------------------
    drop(bob_d);
    let _bob_d = bob.daemon(Some(&spec));
    let reopened = arrives(&bob, &room, after);
    println!("[proof] misbound: after a restart bob reads it: {reopened:?}");
    if let Err(e) = &reopened {
        panic!(
            "PRODUCT: after a restart bob's room is not open, or has lost alice's post ({e})\n\
             bob's status: {}",
            bob.status()
        );
    }
}

/// `of`'s member row in `room` as `status` reports it; `null` when there is none.
fn member_row(status: &serde_json::Value, room: &str, of: &Member) -> serde_json::Value {
    let same = |a: &str, b: &str| a.starts_with(b) || b.starts_with(a);
    status["rooms"]
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
        })
        .cloned()
        .unwrap_or_default()
}
