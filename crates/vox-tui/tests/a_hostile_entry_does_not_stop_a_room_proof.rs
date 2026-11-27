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
//! ## What a post names as seen is a hint, never authority (ADR-053 M0)
//! Mallory runs this build of `vox` with `VOX_TEST_SEEN_HINTS` (test-knobs only): every post
//! she signs names, in `seen`, what the proof wrote into her hints file in place of her honest
//! tips. Her posts are otherwise fully valid.
//! - **A poisoned hint** ([`a_poisoned_hint_made_up_tip_is_shown_and_grants_nothing`],
//!   [`a_poisoned_hint_other_branch_is_shown_and_grants_nothing`]): her hint names dave at a
//!   made-up position and hash, or the hash dave signed on a branch nobody keeps (dave's profile
//!   copied and posted from once, every other node stopped meanwhile). Every honest member shows
//!   her posts; then alice, the creator, removes erin and the removal takes effect on every honest
//!   member, and a later control (alice makes bob an admin) does too: no control acquired the
//!   hinted coordinate.
//! - **A hint that never arrives** ([`a_hint_that_never_arrives_holds_nothing_back`]): her post
//!   names alice 1000 positions past alice's tip; bob shows it between alice's post before and
//!   alice's post after, and shows mallory's next post too: nothing waits on the hint.
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
//! - `VOX_MUTANT_SEEN_HINT=checked` (bob's daemon gets `VOX_TEST_SEEN_HINT=checked` from just
//!   before mallory's hinted post: a Content's hints are checked parents again, as before M0;
//!   bob alone and only then, because every honest post names hints too): the poisoned-hint and
//!   never-arriving-hint arms go red, bob never shows mallory's post;
//! - `VOX_MUTANT_SEEN_HINT=joined` (every honest daemon gets `VOX_TEST_SEEN_HINT=joined`: a
//!   control joins the hints of the Content tips it names into its context): the poisoned-hint
//!   arms go red at the removal.
//!
//! Every owed-row and hint mutant, the switch and its value, is checked for in the `vox` under
//! test first (`test_knobs::require`): a `vox` that does not read it says CANNOT MEASURE.

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

// ---- ADR-053 M0: what a post names as seen is a hint, never authority ----------------------

/// The hint mutants the runner may select with `VOX_MUTANT_SEEN_HINT`, each given to daemons as
/// `VOX_TEST_SEEN_HINT`: `checked` to bob's daemon only, from just before mallory's hinted post
/// (every honest post names hints too, so a reader that checks them holds the staging's posts);
/// `joined` to every honest daemon.
const HINT_MUTANTS: [&str; 2] = ["checked", "joined"];

/// The forger this act needs, and the runner's hint mutant if it selected one. A `vox` that does
/// not read the forger's file or the switch cannot run it: CANNOT MEASURE.
fn hint_mutant() -> Option<&'static str> {
    test_knobs::require(&["VOX_TEST_SEEN_HINTS"]);
    let mode = std::env::var("VOX_MUTANT_SEEN_HINT")
        .ok()
        .filter(|m| !m.is_empty())?;
    let mode = HINT_MUTANTS
        .into_iter()
        .find(|m| *m == mode)
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE (precondition unmet): VOX_MUTANT_SEEN_HINT={mode:?} names none of \
                 this act's mutants {HINT_MUTANTS:?}"
            )
        });
    test_knobs::require(&["VOX_TEST_SEEN_HINT", mode]);
    Some(mode)
}

/// An honest member's daemon behind `spec`, given the runner's `joined` mutant.
fn honest(m: &Member, spec: &str, mutant: Option<&str>) -> Proc {
    if mutant == Some("joined") {
        m.daemon_with_anchor(Some(spec), &[("VOX_TEST_SEEN_HINT", "joined")])
    } else {
        m.daemon_with_anchor(Some(spec), &[])
    }
}

/// Mallory's daemon behind `spec`: this build of `vox`, putting what `hints` names into the
/// `seen` of every post she signs while that file exists.
fn forger(m: &Member, spec: &str, hints: &std::path::Path) -> Proc {
    let hints = hints.to_str().expect("APPARATUS: UTF-8 temp path");
    m.daemon_with_anchor(Some(spec), &[("VOX_TEST_SEEN_HINTS", hints)])
}

/// Whether the forger said it signed the hints of its file into a post.
fn forged(p: &Proc) -> bool {
    p.transcript()
        .contains("VOX_TEST_SEEN_HINTS: signing seen hints")
}

/// Whether any of these daemons said it engaged the hint mutant it was given.
fn engaged(procs: &[&Proc]) -> bool {
    procs.iter().any(|p| {
        p.transcript()
            .lines()
            .any(|l| l.contains("VOX_TEST_SEEN_HINT=") && l.ends_with("engaged"))
    })
}

/// A temporary directory for an act's nodes, kept when the run sets `VOX_PROOF_KEEP_DIRS` so that
/// a red can be read.
fn act_dir() -> tempfile::TempDir {
    let mut dir = tempfile::tempdir().expect("APPARATUS: tempdir");
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        dir.disable_cleanup(true);
        eprintln!(
            "[proof] retained daemon directory: {}",
            dir.path().display()
        );
    }
    dir
}

/// Replace mallory's hints file in one step (written beside it, then renamed): her daemon reads
/// it on every post, and must never read it half-written.
fn write_hints(hints: &std::path::Path, text: &str) {
    let next = hints.with_extension("next");
    std::fs::write(&next, text).expect("APPARATUS: write mallory's hints");
    std::fs::rename(&next, hints).expect("APPARATUS: replace mallory's hints");
}

/// How long a removal or an admin change may take to reach a member.
const WITHIN: Duration = Duration::from_secs(60);

/// `m`'s rows of `room` as `vox room read --json` gives them, oldest first; none if it failed.
fn json_rows(m: &Member, room: &str) -> Vec<serde_json::Value> {
    let (ok, out, _) = m.vox(&["room", "read", room, "--json"], None);
    if !ok {
        return Vec::new();
    }
    out.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The entry hash `m` shows `text` under, from `vox room read --json`.
fn entry_of(m: &Member, room: &str, text: &str) -> Option<String> {
    json_rows(m, room)
        .iter()
        .rev()
        .find(|r| r["text"] == text)
        .and_then(|r| r["entry_hash"].as_str().map(str::to_owned))
}

/// Run `vox args` as `m`, again only while the product says a change is still being applied or
/// keys are rotating (for up to [`WITHIN`]); whether it worked, and what it said.
fn settle(m: &Member, args: &[&str]) -> (bool, String) {
    let t = Instant::now();
    loop {
        let (ok, out, err) = m.vox(args, None);
        let said = format!("{out}{err}");
        let transient = said.contains("keys are rotating")
            || said.contains("still being applied")
            || said.contains(vox_core::node::api::Fault::GovernanceRefreshing.explain());
        if ok || !transient || t.elapsed() > WITHIN {
            return (ok, said);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Poll `ok` every 250 ms for up to `within`; whether it held.
fn until(within: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    loop {
        if ok() {
            return true;
        }
        if t.elapsed() > within {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `m`'s `vox room <verb> room` output, or the failure quoted.
fn said(m: &Member, verb: &[&str], room: &str) -> String {
    let mut args = vec!["room"];
    args.extend_from_slice(verb);
    args.push(room);
    let (ok, out, err) = m.vox(&args, None);
    if ok {
        out
    } else {
        format!("FAILED: {out}{err}")
    }
}

/// A hash no node holds: 52 base32 characters of a digest of this moment.
fn made_up_hash() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    vox_core::node::link::b32_encode(&vox_core::hash::sha256(&nanos.to_be_bytes()))
}

/// A stopped member's whole profile, copied with each directory's mode (a node refuses a
/// management path that is not private): a second process of the same identity.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("APPARATUS: create a copied profile directory");
    let mode = std::fs::metadata(from)
        .expect("APPARATUS: read a profile directory's mode")
        .permissions();
    std::fs::set_permissions(to, mode).expect("APPARATUS: keep a profile directory's mode");
    for e in std::fs::read_dir(from).expect("APPARATUS: read a profile to copy") {
        let e = e.expect("APPARATUS: read a profile entry");
        let target = to.join(e.file_name());
        let kind = e.file_type().expect("APPARATUS: profile entry type");
        if kind.is_dir() {
            copy_dir(&e.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(e.path(), &target).expect("APPARATUS: copy a profile file");
        }
    }
}

/// Every member trusts every other.
fn trust_all(members: &[&Member]) {
    for (i, a) in members.iter().enumerate() {
        for b in &members[i + 1..] {
            a.trust(b);
            b.trust(a);
        }
    }
}

/// Each member posts a hello and every member reads every hello (else `PRODUCT (staging)`).
fn hellos(room: &str, members: &[&Member]) {
    for m in members {
        m.post(room, &format!("{} says hello", m.name));
    }
    for reader in members {
        for author in members {
            let text = format!("{} says hello", author.name);
            if let Err(e) = arrives(reader, room, &text) {
                panic!(
                    "PRODUCT (staging): {} never read {text:?} before anything hostile: {e}",
                    reader.name
                );
            }
        }
    }
}

#[test]
#[ignore = "real daemons, one a test-knobs `vox` that signs forged hints; run with test-knobs"]
fn a_poisoned_hint_made_up_tip_is_shown_and_grants_nothing() {
    poisoned_hint(false);
}

#[test]
#[ignore = "real daemons, one a test-knobs `vox` that signs forged hints; run with test-knobs"]
fn a_poisoned_hint_other_branch_is_shown_and_grants_nothing() {
    poisoned_hint(true);
}

fn poisoned_hint(other_branch: bool) {
    let arm = if other_branch {
        "dave's other branch"
    } else {
        "a made-up tip of dave"
    };
    watchdog::arm();
    let mutant = hint_mutant();
    let tmp = act_dir();
    let root = tmp.path();
    let (anchor_d, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let dave = Member::new(root, "dave");
    let erin = Member::new(root, "erin");
    let mallory = Member::new(root, "mallory");
    trust_all(&[&alice, &bob, &dave, &erin, &mallory]);
    let hints = root.join("mallory.hints");
    let alice_d = honest(&alice, &spec, mutant);
    let mut bob_d = honest(&bob, &spec, mutant);
    let mut dave_d = honest(&dave, &spec, mutant);
    let erin_d = honest(&erin, &spec, mutant);
    let mallory_d = forger(&mallory, &spec, &hints);
    let room = alice.create("hints");
    let link = alice.invite(&room);
    for m in [&bob, &dave, &erin, &mallory] {
        m.join(&link, "hints");
    }
    hellos(&room, &[&alice, &bob, &dave, &erin, &mallory]);

    let line = if other_branch {
        // dave signs a message on a branch nobody keeps: his profile copied, posted from once
        // while every other node is stopped, and gone before any of them runs again.
        drop(dave_d);
        let copy = Member {
            name: "dave-copy",
            dir: root.join("dave-copy"),
            pass: dave.pass.clone(),
            fp: dave.fp.clone(),
        };
        copy_dir(&dave.dir, &copy.dir);
        let others = [
            (&anchor_d, "the anchor"),
            (&alice_d, "alice"),
            (&bob_d, "bob"),
            (&erin_d, "erin"),
            (&mallory_d, "mallory"),
        ];
        for (p, who) in others {
            signal_took(p, "-STOP", who);
        }
        let copy_d = copy.daemon_with(&[("VOX_TEST_NO_NEARBY", "1")]);
        let lost = "dave, on a branch nobody keeps";
        copy.post(&room, lost);
        let other = entry_of(&copy, &room, lost)
            .unwrap_or_else(|| panic!("APPARATUS: the copy of dave does not show {lost:?}"));
        drop(copy_d);
        for (p, who) in others {
            signal_took(p, "-CONT", who);
        }
        dave_d = honest(&dave, &spec, mutant);
        let kept = "dave, on his kept branch";
        dave.post(&room, kept);
        for m in [&bob, &mallory] {
            if let Err(e) = arrives(m, &room, kept) {
                panic!("PRODUCT (staging): {} never read {kept:?}: {e}", m.name);
            }
        }
        let kept = entry_of(&bob, &room, kept).expect("APPARATUS: bob's row of dave's kept post");
        assert_ne!(
            kept, other,
            "APPARATUS: dave's two branches signed one entry"
        );
        format!("{} @{kept} {other}\n", dave.fp)
    } else {
        format!("{} +5 {}\n", dave.fp, made_up_hash())
    };
    write_hints(&hints, &line);
    if mutant == Some("checked") {
        drop(bob_d);
        bob_d = bob.daemon_with_anchor(Some(&spec), &[("VOX_TEST_SEEN_HINT", "checked")]);
    }
    let hinted = format!("mallory, naming {arm}");
    mallory.post(&room, &hinted);
    assert!(
        forged(&mallory_d),
        "APPARATUS (the forger): mallory never signed with the hints {line:?}:\n{}",
        mallory_d.transcript()
    );
    for m in [&alice, &bob, &dave, &erin] {
        if let Err(e) = arrives(m, &room, &hinted) {
            panic!(
                "PRODUCT: {} never showed mallory's post whose `seen` names {arm} ({e}): an \
                 unchecked hint held a valid message back\n{}'s status: {}\nhint mutant engaged \
                 on bob: {}",
                m.name,
                m.name,
                m.status(),
                engaged(&[&bob_d])
            );
        }
    }
    let again = "mallory again, the same hint";
    mallory.post(&room, again);
    if let Err(e) = arrives(&bob, &room, again) {
        panic!("PRODUCT: bob never showed mallory's next post ({e}): it waited on her hint");
    }

    // The creator removes erin: the removal must not inherit the hinted coordinate.
    let (removed, why) = settle(&alice, &["room", "remove-member", &room, &erin.fp]);
    assert!(
        removed,
        "PRODUCT: after mallory's hint ({arm}) alice could not remove erin: {why}\nhint mutant \
         engaged on alice: {}",
        engaged(&[&alice_d])
    );
    for m in [&alice, &bob, &dave] {
        let gone = until(WITHIN, || {
            let roster = said(m, &["roster"], &room);
            !roster.starts_with("FAILED") && !roster.contains(&erin.fp)
        });
        assert!(
            gone,
            "PRODUCT: alice's removal of erin, made after mallory's hint ({arm}), never took \
             effect on {}: its roster is {}\n{}'s status: {}\nhint mutant engaged on alice: {}",
            m.name,
            said(m, &["roster"], &room),
            m.name,
            m.status(),
            engaged(&[&alice_d])
        );
    }
    let (named, why) = settle(&alice, &["room", "admin", "add", &room, &bob.fp]);
    assert!(
        named,
        "PRODUCT: alice's later control (bob made an admin) failed: {why}"
    );
    for m in [&bob, &dave] {
        let listed = until(WITHIN, || {
            said(m, &["admin", "list"], &room).contains(&bob.fp)
        });
        assert!(
            listed,
            "PRODUCT: alice's later control never validated on {}: `vox room admin list` says {}",
            m.name,
            said(m, &["admin", "list"], &room)
        );
    }
    let after = "bob, after the removal";
    bob.post(&room, after);
    for m in [&alice, &dave] {
        if let Err(e) = arrives(m, &room, after) {
            panic!(
                "PRODUCT: the room stopped after the removal: {} ({e})",
                m.name
            );
        }
    }
    println!(
        "[proof] poisoned hint ({arm}): alice, bob, dave and erin showed mallory's post; erin's \
         removal and bob's admin took effect on every honest member; hint mutant {mutant:?} \
         engaged: {}",
        engaged(&[&alice_d, &bob_d, &dave_d, &erin_d])
    );
}

#[test]
#[ignore = "real daemons, one a test-knobs `vox` that signs forged hints; run with test-knobs"]
fn a_hint_that_never_arrives_holds_nothing_back() {
    watchdog::arm();
    let mutant = hint_mutant();
    let tmp = act_dir();
    let root = tmp.path();
    let (_anchor_d, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let mallory = Member::new(root, "mallory");
    trust_all(&[&alice, &bob, &mallory]);
    let hints = root.join("mallory.hints");
    let alice_d = honest(&alice, &spec, mutant);
    let mut bob_d = honest(&bob, &spec, mutant);
    let mallory_d = forger(&mallory, &spec, &hints);
    let room = alice.create("never");
    let link = alice.invite(&room);
    bob.join(&link, "never");
    mallory.join(&link, "never");
    hellos(&room, &[&alice, &bob, &mallory]);
    let before = "alice, before the hint";
    alice.post(&room, before);
    for m in [&bob, &mallory] {
        if let Err(e) = arrives(m, &room, before) {
            panic!("PRODUCT (staging): {} never read {before:?}: {e}", m.name);
        }
    }
    let line = format!("{} +1000 {}\n", alice.fp, made_up_hash());
    write_hints(&hints, &line);
    if mutant == Some("checked") {
        drop(bob_d);
        bob_d = bob.daemon_with_anchor(Some(&spec), &[("VOX_TEST_SEEN_HINT", "checked")]);
    }
    let hinted = "mallory, naming a post of alice that never comes";
    mallory.post(&room, hinted);
    assert!(
        forged(&mallory_d),
        "APPARATUS (the forger): mallory never signed with the hints {line:?}:\n{}",
        mallory_d.transcript()
    );
    for m in [&bob, &alice] {
        if let Err(e) = arrives(m, &room, hinted) {
            panic!(
                "PRODUCT: {} never showed mallory's post whose `seen` names an entry that never \
                 arrives ({e}): it waited on the hint\n{}'s status: {}\nhint mutant engaged on \
                 bob: {}",
                m.name,
                m.name,
                m.status(),
                engaged(&[&bob_d])
            );
        }
    }
    let after = "alice, after reading mallory";
    alice.post(&room, after);
    if let Err(e) = arrives(&bob, &room, after) {
        panic!("PRODUCT: bob never showed alice's post after the hinted one ({e})");
    }
    let next = "mallory again, the same hint";
    mallory.post(&room, next);
    if let Err(e) = arrives(&bob, &room, next) {
        panic!("PRODUCT: bob never showed mallory's next post ({e}): it waited on her hint");
    }
    let rows: Vec<String> = json_rows(&bob, &room)
        .iter()
        .filter_map(|r| r["text"].as_str().map(str::to_owned))
        .collect();
    let at = |text: &str| rows.iter().position(|t| t == text);
    let order = (at(before), at(hinted), at(after));
    assert!(
        matches!(order, (Some(b), Some(h), Some(a)) if b < h && h < a),
        "PRODUCT: bob shows the hinted post out of its place in the conversation (positions \
         before/hinted/after {order:?}): {rows:?}"
    );
    println!(
        "[proof] never-arriving hint: bob showed mallory's hinted post between alice's before \
         and after ({order:?}), and mallory's next post; hint mutant {mutant:?} engaged: {}",
        engaged(&[&alice_d, &bob_d])
    );
}
