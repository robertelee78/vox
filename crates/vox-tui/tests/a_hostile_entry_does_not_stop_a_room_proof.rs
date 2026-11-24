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
//! Mallory runs as `author-misbound`: what she posts is a real consent grant, signed with kind
//! Governance, whose body names an epoch 7 past the entry's own: the issue's first case, a
//! governance body with the wrong channel or epoch. Its signed kind and its body agree, so Bob's
//! typed check reaches the governance binding (`GovEntry::body_bound_to`, from
//! `TypedSparseBody::verify`). Asserted:
//! 1. Bob refused it at that binding, before holding it, as the serving peer's fault: a sync
//!    session's `last_failure` names "governance body epoch disagrees with log entry", and his
//!    verified prefix of Mallory never reaches the grant (RED when it does: he took it);
//! 2. Alice's next post reaches Bob;
//! 3. after a restart Bob's room is open, with Alice's post in it and nothing set aside.
//!
//! Mutant `VOX_PROOF_GOV_BINDING=unchecked` (the act hands `VOX_MUTANT_GOV_BINDING=unchecked` to
//! Bob's daemon only; a `test-knobs` build): `body_bound_to` skips its channel and epoch binding.
//! Red at (1): Bob takes the grant. Arm and mode by the verifier (vox-0e-ver74).
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
//! ## A placeholder whose decision is open ([`a_placeholder_is_not_shown_while_its_reader_cannot_decide_it`])
//! Carol's post is held stripped by Bob, and no running node holds its body. Alice removes Bob and
//! readmits him, so the post (written before his removal, never held) is outside his readmission
//! cut. Bob's governance fold is held (`VOX_TEST_FOLD_HOLD_FILE`) while he takes Alice's removal
//! and readmission: once his read says the room is still folding its control entries, no
//! placeholder is shown or counted; released and restarted, still none.
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
//! 1. Bob shows Alice's post as not received yet, in its place right after her first, without its
//!    text, and his `vox status --json` counts it as a row;
//! 2. once Alice is back, Bob reads the post, shows it no longer as not received yet, and his row
//!    count stays the same (the text took the placeholder's row).
//!
//! ## A member that terminated its feed and hides it ([`a_post_after_a_hidden_termination_is_never_shown`])
//! ADR-053 MP-10 (c). Mallory first runs as an ordinary member (mode `correct`) and posts; then her
//! daemon restarts as `terminate-and-withhold`: her next post is preceded by a signed
//! `Termination` of her own feed, she posts twice more past it, and she never serves the
//! termination's header (to Bob, Alice or the anchor), so the only copy is hers. Her later
//! positions' headers, bodies and proofs are served. Asserted on Bob (shipped binary):
//! 1. while it is withheld, Bob knows Mallory's later positions (her advertised head is past both
//!    posts) and shows Alice's post written after them; then:
//!    - non-citable, by a control's outcome rather than by Bob's contiguous verified prefix
//!      (which does not move past an unfinished predecessor, where a settled tip can): after
//!      three more completed rounds toward Mallory, Bob posts. His writer names the newest
//!      settled tip it holds of every other member in the `seen` of what it signs, with a
//!      control first when that changes his context (`local_history::authored_context`), so
//!      were either later post a settled source on Bob, that control and his post would rest
//!      on it, and Alice, from whom the termination is withheld too, could not admit them.
//!      Asserted on Alice: she shows Bob's post. RED when instead his post fails, or Alice knows
//!      his head past it and over three completed rounds toward him her verified prefix of him
//!      stays below it;
//!    - unrendered: in three status answers in a row, with rounds toward Mallory completing,
//!      Bob shows neither later post and his verified prefix of Mallory stays below the first;
//! 2. once Mallory restarts as `terminated-serves` and the termination is supplied (Bob's verified
//!    prefix of Mallory moves past what it was), Bob still shows neither later post, holds neither as
//!    a source over three answers with rounds completing, shows Alice's next post, and nothing he
//!    reports names a store error;
//! 3. the same after Bob's daemon restarts.
//!
//! Two mutants, each handed by the act to Bob's daemon only as `VOX_MUTANT_TERMINATION` (a
//! `test-knobs` build), named to the act by `VOX_PROOF_TERMINATION`:
//! - `unchecked`: the validator accepts a later position without the author's own termination
//!   evidence. Red at (2): once the termination is supplied, the later entry reaches
//!   publication's last fence and Bob reports
//!   `malformed at-rest artifact: sparse source follows a terminated feed` (also what v0.4.31
//!   main reports). (1) stays green under it: admission's preflight and the effect stage still
//!   need the author's own controls under the head, the withheld termination among them;
//! - `admitted`: a later position is admitted as a source while the termination is withheld:
//!   `unchecked`, and preflight, the effect stage and the history runtime's control closure pass
//!   over the author's own absent controls. Red at (1), non-citable: Bob holds the later post
//!   as a source, his post rests on it and Alice cannot admit it.
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
//! - no binding check of a governance body (`VOX_PROOF_GOV_BINDING=unchecked`): the misbound arm
//!   goes red at (1), Bob takes the grant;
//! - `VOX_PROOF_TERMINATION=unchecked`: the hidden-termination arm goes red at (2);
//! - `VOX_PROOF_TERMINATION=admitted`: the hidden-termination arm goes red at (1), non-citable;
//! - `VOX_MUTANT_OWED_ROW=unwritten` (Bob's daemon gets `VOX_TEST_OWED_ROW=unwritten`: no "not
//!   received yet" row is written for a body-less signed message): the stripped arm goes red at
//!   (2), and the kept-less arm at (1);
//! - `VOX_MUTANT_OWED_ROW=marked` (Bob's terminal app gets it: it submits placeholders with the
//!   rest of what it showed): the stripped arm goes red at (3);
//! - `VOX_MUTANT_OWED_ROW=undecided` (rows are shown while their decision is open): the
//!   undecided arm goes red at (3), while held.
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

use sync_pair::{anchor, announced, counter, failures, mutant_sender, Member, Proc};

/// How long a post may take to reach a member before it counts as never.
const ARRIVES_WITHIN: Duration = Duration::from_secs(30);

/// Bob's session failure when he refuses mallory's posted entry before holding it: its signed
/// kind is ordinary content and its body is not a group message (`governance/sparse.rs`, the
/// typed-carrier check).
const CARRIER: &str = "malformed identity bundle: ordinary content carrier";

/// Bob's session failure when he refuses mallory's misbound grant before holding it: its signed
/// kind is governance and its body names another epoch (`GovEntry::body_bound_to`).
const BINDING: &str = "malformed governance struct: governance body epoch disagrees with log entry";

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

/// The rows `m` reports for `room` in `vox status --json` (`entries`): every row `vox room read`
/// pages through, a message not received yet counting as its placeholder.
fn room_rows(m: &Member, room: &str) -> Option<u64> {
    m.status()["rooms"]
        .as_array()?
        .iter()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))?["entries"]
        .as_u64()
}

/// The "not received yet" mutants the runner may select with `VOX_MUTANT_OWED_ROW`, each given
/// to the reader's daemon as `VOX_TEST_OWED_ROW` (`marked` to the reader's terminal app instead):
/// `unwritten` (no row is written), `unchecked` (one for every body-less message), `undecided`
/// (rows are shown while their decision is open), `marked` (the terminal app submits placeholders
/// with its read marks).
const OWED_MUTANTS: [&str; 4] = ["unwritten", "unchecked", "undecided", "marked"];

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
    ];
    let driver = std::thread::spawn(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        pty_driver::run(script, &args)
    });
    // The driver cues `shown` once the timeline shows both, then waits for `done`.
    while !cues.join("shown").exists() && !driver.is_finished() {
        std::thread::sleep(Duration::from_millis(100));
    }
    let shown = cues.join("shown").exists();
    if shown {
        // The TUI stays open, showing both, while the caller watches what its node marked.
        let t = Instant::now();
        while t.elapsed() < ARRIVES_WITHIN && !marked() {
            std::thread::sleep(Duration::from_millis(250));
        }
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

/// Over three more completed sync rounds of `m` toward `peer`, `seen()` names nothing; else the
/// first thing it named, once three more rounds have completed after it. Rounds that never
/// complete within 600 s is APPARATUS NO RESULT.
fn none_over_rounds(
    m: &Member,
    peer: &Member,
    phase: &str,
    mut seen: impl FnMut() -> Option<String>,
) -> Option<String> {
    let first = rounds_toward(&m.status(), peer);
    let started = Instant::now();
    let mut red: Option<(String, u64)> = None;
    loop {
        let rounds = rounds_toward(&m.status(), peer);
        if red.is_none() {
            red = seen().map(|what| (what, rounds));
        }
        match &red {
            Some((what, at)) if rounds >= at + 3 => return Some(what.clone()),
            None if rounds >= first + 3 => return None,
            _ => {}
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT ({phase}): in 600 s {}'s rounds toward {} went {first} -> \
             {rounds}, fewer than three more",
            m.name,
            peer.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// What `vox room read` says before its rows while the node holds a control entry its governance
/// fold has not folded yet (`vox-tui` `room_cli.rs`, ADR-037 R3): its page is provisional.
const STILL_FOLDING: &str = "this room is still folding its control entries";

/// `m`'s `vox room read` of `room` now: the entry hashes it shows as not received yet, the rows
/// it shows, and the read itself. `Err` quotes a read that failed: never taken for "nothing
/// shown".
fn read_rows(m: &Member, room: &str) -> Result<(Vec<String>, u64, String), String> {
    let (ok, out, err) = m.vox(&["room", "read", room], None);
    if !ok {
        return Err(format!(
            "`vox room read` failed: {}",
            format!("{out}{err}").trim()
        ));
    }
    // A row is `<entry> <author> <text>`; a notice (`! …`) is not.
    let rows: Vec<&str> = out
        .lines()
        .filter(|l| {
            l.split(' ').next().is_some_and(|first| {
                first.len() >= 8 && first.chars().all(|c| c.is_ascii_alphanumeric())
            })
        })
        .collect();
    let owed = rows
        .iter()
        .filter(|l| l.ends_with(vox_core::node::api::NOT_RECEIVED_YET))
        .filter_map(|l| l.split(' ').next().map(str::to_owned))
        .collect();
    Ok((owed, rows.len() as u64, out))
}

/// Wait until `m` shows `hash` as not received yet, or 30 more of its sync rounds toward `source`
/// (the only holder of the envelope it can reach) have completed; its last read either way, for
/// the caller's verdict. Rounds that do not complete within 600 s is APPARATUS NO RESULT. (A
/// body-less entry does not advance a reader's verified prefix of its author, so no status count
/// says the envelope was taken: the row is the witness.)
fn shows_owed(
    m: &Member,
    room: &str,
    hash: &str,
    source: &Member,
) -> Result<(Vec<String>, u64, String), String> {
    let started = Instant::now();
    let from = rounds_toward(&m.status(), source);
    loop {
        let read = read_rows(m, room);
        let rounds = rounds_toward(&m.status(), source);
        if read
            .as_ref()
            .is_ok_and(|(owed, _, _)| owed.iter().any(|h| h == hash))
            || rounds >= from + 30
        {
            return read;
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT: in 600 s {}'s rounds toward {} went {from} -> {rounds}, fewer \
             than 30",
            m.name,
            source.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// After a verdict: `m`'s `vox status --json` counts exactly the rows its read shows.
fn counts_what_it_shows(m: &Member, room: &str, arm: &str) {
    let read = read_rows(m, room);
    let counted = room_rows(m, room);
    println!("[proof] {arm}: bob's status counts {counted:?} rows; his read: {read:?}");
    match read {
        Ok((_, shown, out)) => assert_eq!(
            counted,
            Some(shown),
            "PRODUCT: bob's `vox status --json` counts {counted:?} rows of the room, and his read \
             shows {shown}:\n{out}"
        ),
        Err(e) => panic!("PRODUCT: bob's read failed after the verdict: {e}"),
    }
}

/// Retry an admin verb the product answers with its explicit "made no change, still applying"
/// instruction, for up to a minute; the last answer.
fn admin(m: &Member, args: &[&str]) -> (bool, String, String) {
    let t = Instant::now();
    loop {
        let (ok, out, err) = m.vox(args, None);
        let said = format!("{out}\n{err}");
        let unchanged = said.contains(
            "a previous change to this room is still being applied; this request made no change",
        ) || said
            .contains(vox_core::node::api::Fault::GovernanceRefreshing.explain());
        if ok || !unchanged || t.elapsed() >= Duration::from_secs(60) {
            return (ok, out, err);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait until `m`'s `vox room roster` lists `who` (`listed`) or does not; a red when it never
/// does within [`ARRIVES_WITHIN`].
fn roster_lists(m: &Member, room: &str, who: &Member, listed: bool, what: &str) {
    let t = Instant::now();
    loop {
        let (ok, out, err) = m.vox(&["room", "roster", room], None);
        if ok && out.contains(&who.fp) == listed {
            return;
        }
        assert!(
            t.elapsed() < ARRIVES_WITHIN,
            "PRODUCT (staging): {}'s roster never {what} {}: {out}{err}",
            m.name,
            who.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// End `p` as a person quits it (SIGTERM), waiting for it to exit.
fn quit(mut p: Proc, who: &str) {
    p.signal("-TERM");
    let t = Instant::now();
    while !p.state().starts_with("it exited") {
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "APPARATUS: {who}'s daemon did not exit within 60 s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// ADR-036 H-4: a placeholder whose decision is open is not shown. Alice (the room's admin),
/// carol, mallory (`strip-payload`) and bob, whose daemon reads `VOX_TEST_FOLD_HOLD_FILE` (a
/// `test-knobs` build). Carol posts while bob, alice and the anchor are stopped; mallory takes
/// it; carol's daemon ends for good; bob is resumed and takes it from mallory stripped. No node
/// that runs again holds its body. Asserted on bob:
/// 1. staging (else APPARATUS NO RESULT; the stripped arm owns this claim): within 30 completed
///    rounds toward mallory, carol's post is shown as not received yet, and counted;
/// 2. with bob and mallory stopped, alice removes bob and readmits him: a body written before
///    his removal that he never held is outside his readmission cut, not for him (ADR-053
///    MP-10). Bob's fold is held, and he is resumed;
/// 3. once his own read says the room is still folding control entries it holds (alice's removal
///    and readmission of him, unfolded: his verified prefix of alice does not pass an entry his
///    held fold has not decided, so it is no witness), over three completed rounds toward alice
///    he shows no placeholder for carol's post and does not count one;
/// 4. the hold released and his daemon restarted (a released hold does not wake a held fold by
///    itself, `governance.rs`, `advance`): once he reads alice's post made after his readmission,
///    over three more rounds he still shows none, and his status counts exactly the rows his
///    read shows.
///
/// RED at (3) when a row whose decision is open is still shown
/// (`VOX_MUTANT_OWED_ROW=undecided`).
#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_placeholder_is_not_shown_while_its_reader_cannot_decide_it() {
    const MODE: &str = "strip-payload";
    watchdog::arm();
    owed_mutant();
    test_knobs::require(&["VOX_TEST_FOLD_HOLD_FILE"]);
    let sender = mutant_sender();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let (anchor_d, spec) = anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let carol = Member::new(root, "carol");
    let mallory = Member::new(root, "mallory");
    for (a, b) in [
        (&alice, &bob),
        (&alice, &carol),
        (&alice, &mallory),
        (&bob, &carol),
        (&bob, &mallory),
        (&carol, &mallory),
    ] {
        a.trust(b);
        b.trust(a);
    }
    let hold = root.join("bob-fold-hold");
    let hold_path = hold
        .to_str()
        .expect("APPARATUS: a UTF-8 hold path")
        .to_owned();
    let alice_d = alice.daemon(Some(&spec));
    let bob_d = reader_daemon_with(&bob, &spec, &[("VOX_TEST_FOLD_HOLD_FILE", &hold_path)]);
    let carol_d = carol.daemon(Some(&spec));
    let mallory_d = mallory.daemon_mutant(&sender, MODE, Some(&spec));
    let room = alice.create("undecided");
    let link = alice.invite(&room);
    bob.join(&link, "undecided");
    carol.join(&link, "undecided");
    mallory.join(&link, "undecided");
    // Each author posts first while everyone is up, so the post bob later takes only from mallory
    // is not her first: with no earlier post taken whole, his verified prefix of her stays below it.
    for (author, warm) in [
        (&alice, "alice, while everyone is up"),
        (&carol, "carol, while everyone is up"),
    ] {
        author.post(&room, warm);
        for m in [&alice, &bob, &carol, &mallory] {
            if let Err(e) = arrives(m, &room, warm) {
                panic!("PRODUCT (staging): {} never read {warm:?} ({e})", m.name);
            }
        }
    }

    // ---- (1) carol's post, whose body only she and mallory hold -------------------------------
    signal_took(&bob_d, "-STOP", "bob");
    signal_took(&alice_d, "-STOP", "alice");
    signal_took(&anchor_d, "-STOP", "the anchor");
    let posted = "carol, before bob's removal";
    carol.post(&room, posted);
    if let Err(e) = arrives(&mallory, &room, posted) {
        panic!("PRODUCT (staging): mallory never had carol's post: {e}");
    }
    let hc =
        hash_of(&carol, &room, posted).expect("PRODUCT (staging): carol's read lacks her post");
    drop(carol_d);
    signal_took(&bob_d, "-CONT", "bob");
    let seen = shows_owed(&bob, &room, &hc, &mallory);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let rows_with = room_rows(&bob, &room);
    println!("[proof] undecided: bob's read: {seen:?}; his status counts {rows_with:?} rows");
    match &seen {
        Ok((owed, _, _)) if owed.contains(&hc) && rows_with.is_some() => {}
        _ => panic!(
            "APPARATUS NO RESULT (staging): within 30 rounds toward mallory, his only source, bob \
             did not show carol's stripped post as not received yet, or his status counts no rows \
             ({rows_with:?}), so the held phase cannot be staged: {seen:?}"
        ),
    }

    // ---- (2) alice removes bob and readmits him -----------------------------------------------
    signal_took(&bob_d, "-STOP", "bob");
    signal_took(&mallory_d, "-STOP", "mallory");
    signal_took(&alice_d, "-CONT", "alice");
    signal_took(&anchor_d, "-CONT", "the anchor");
    for (verb, listed, what) in [
        ("remove-member", false, "stopped listing"),
        ("readmit-member", true, "listed again"),
    ] {
        let (ok, out, err) = admin(&alice, &["room", verb, &room, &bob.fp]);
        assert!(
            ok,
            "PRODUCT (staging): alice's `vox room {verb}` of bob failed: {out}{err}"
        );
        roster_lists(&alice, &room, &bob, listed, what);
    }
    std::fs::write(&hold, b"hold").expect("APPARATUS: could not arm bob's fold hold");
    signal_took(&bob_d, "-CONT", "bob");

    // ---- (3) held: bob holds alice's removal and readmission of him, unfolded ---------------------
    let started = Instant::now();
    loop {
        let (ok, out, err) = bob.vox(&["room", "read", &room], None);
        if ok && err.contains(STILL_FOLDING) {
            println!("[proof] undecided: held, bob's read says {STILL_FOLDING:?}:\n{out}");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT: in 600 s bob's read never said {STILL_FOLDING:?} (alice's \
             removal and readmission of him, his fold held); last read: {}\nbob's status: {}",
            format!("{out}{err}").trim(),
            bob.status()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    let mut worked = (0u32, None);
    let red = none_over_rounds(&bob, &alice, "held", || {
        let counted = room_rows(&bob, &room);
        let read = read_rows(&bob, &room);
        match &read {
            Ok(_) => worked.0 += 1,
            Err(e) => worked.1 = Some(e.clone()),
        }
        let shown = read.as_ref().is_ok_and(|(owed, _, _)| owed.contains(&hc));
        (shown || counted.is_some_and(|rows| Some(rows) >= rows_with)).then(|| {
            format!(
                "while bob's governance is held with alice's removal and readmission of him \
                 unfolded, he shows carol's post as not received yet: {shown}; his status counts \
                 {counted:?} rows (with the placeholder: {rows_with:?})\nbob's read: {read:?}"
            )
        })
    });
    println!(
        "[proof] undecided: held, over three rounds toward alice ({} reads worked, last failure \
         {:?}): {}",
        worked.0,
        worked.1,
        red.as_deref().unwrap_or("no placeholder shown or counted")
    );
    if let Some(red) = red {
        panic!("PRODUCT: a placeholder whose decision is open is shown: {red}");
    }
    assert!(
        worked.0 > 0,
        "CANNOT MEASURE: no `vox room read` of bob's worked while his fold was held: {:?}",
        worked.1
    );

    // ---- (4) released: decided, carol's post is not for bob ------------------------------------
    std::fs::remove_file(&hold).expect("APPARATUS: could not release bob's fold hold");
    quit(bob_d, "bob");
    let _bob_d = reader_daemon(&bob, &spec);
    let after = "alice, after bob's readmission";
    let started = Instant::now();
    loop {
        alice.post(&room, after);
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) && !reads(&bob, &room, after).unwrap_or(false) {
            std::thread::sleep(Duration::from_millis(250));
        }
        if reads(&bob, &room, after).unwrap_or(false) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(300),
            "APPARATUS NO RESULT: in 300 s after the hold, bob never read alice's post made after \
             his readmission\nbob's status: {}",
            bob.status()
        );
    }
    let red = none_over_rounds(&bob, &alice, "released", || match read_rows(&bob, &room) {
        Err(e) => Some(format!("bob's read failed: {e}")),
        Ok((owed, _, out)) => owed.contains(&hc).then(|| {
            format!(
                "once decided, bob shows carol's post, outside his readmission cut, as not \
                 received yet\nbob reads:\n{out}"
            )
        }),
    });
    println!(
        "[proof] undecided: released, over three rounds toward alice: {}",
        red.as_deref().unwrap_or("no placeholder shown")
    );
    if let Some(red) = red {
        panic!("PRODUCT: {red}");
    }
    counts_what_it_shows(&bob, &room, "undecided");
    drop(mallory_d);
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
    let rows_before = room_rows(&bob, &room);
    // Alice's own latest message, her first post: what she holds of her feed by her status.
    let warm_at = holds_through(&alice, &room, &alice).unwrap_or_else(|| {
        panic!(
            "PRODUCT (staging): alice's `vox status --json` names no message of her own feed she \
             holds, after posting: {}",
            alice.status()
        )
    });

    // ---- bob is away; alice posts; carol takes it and, a minute later, lets its body go ----
    signal_took(&bob_d, "-STOP", "bob");
    let post = "alice, while bob was away";
    alice.post(&room, post);
    if let Err(e) = arrives(&carol, &room, post) {
        panic!("PRODUCT (staging): carol never read alice's post: {e}");
    }
    let hash = hash_of(&alice, &room, post)
        .unwrap_or_else(|| panic!("PRODUCT (staging): alice's own read does not show her post"));
    // The post's position in alice's feed: her latest message once her status is past her first.
    let t = Instant::now();
    let post_at = loop {
        match holds_through(&alice, &room, &alice) {
            Some(n) if n > warm_at => break n,
            through if t.elapsed() >= ARRIVES_WITHIN => panic!(
                "PRODUCT (staging): alice reads her post, and her `vox status --json` still names \
                 her first as the latest message she holds of her feed after {ARRIVES_WITHIN:?} \
                 (holds_through {through:?}, her first at {warm_at})"
            ),
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    };
    // Carol stops showing the post when it expires; her node drops its body at its retention
    // worker's next prune, and serves the text until then. Bob is resumed only after that: once
    // her status, having said she holds alice's feed through the post, says she holds less.
    let t = Instant::now();
    let mut held = false;
    let mut hidden = None;
    let (shown_until, at_hide, gone, through) = loop {
        let through = holds_through(&carol, &room, &alice);
        held |= through == Some(post_at);
        if hidden.is_none() {
            match reads(&carol, &room, post) {
                Ok(false) => hidden = Some((t.elapsed(), through)),
                Ok(true) => {}
                Err(e) => panic!("PRODUCT (staging): carol's read failed: {e}"),
            }
        }
        if let Some((at, at_hide)) = hidden.filter(|_| held && through.is_none_or(|n| n < post_at))
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
                     it (holds_through {through:?}, the post at {post_at}): her node has not \
                     dropped its body, so bob cannot be resumed with carol not holding it",
                    at.as_secs(),
                    t.elapsed().as_secs()
                ),
                Some(_) => panic!(
                    "APPARATUS: carol's `vox status --json` never said she holds alice's feed \
                     through the post in {} s (holds_through {through:?}, the post at \
                     {post_at}), so whether her node dropped its body cannot be seen",
                    t.elapsed().as_secs()
                ),
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    println!(
        "[proof] kept less: carol stopped showing alice's post {:.1} s after she read it, her \
         status then holding alice's feed through {at_hide:?} (the post at {post_at}); her node \
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

    // ---- bob shows it in place as not received yet, and counts it ---------------------------
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
    let rows_owed = room_rows(&bob, &room);
    assert_eq!(
        rows_owed,
        rows_before.map(|n| n + 1),
        "PRODUCT: bob's `vox status` does not count the post not received yet as a row ({rows_before:?} before)"
    );
    println!(
        "[proof] kept less: with carol his only holder, bob shows alice's post as not received \
         yet in its place; rows {rows_before:?} -> {rows_owed:?}"
    );

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
    assert_eq!(
        room_rows(&bob, &room),
        rows_owed,
        "PRODUCT: the text took the placeholder's row, so bob's row count must not change: {shown:?}"
    );
    println!("[proof] kept less: alice back, bob reads her post in its place:\n{shown}");
}

#[test]
#[ignore = "real daemons against the mutant sender build (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_misbound_governance_entry_is_refused_and_the_room_syncs_on() {
    const MODE: &str = "author-misbound";
    watchdog::arm();
    // The reader mutant goes to Bob's daemon only; Mallory is the attacker, Alice a witness.
    let mutant = std::env::var("VOX_PROOF_GOV_BINDING").ok();
    if mutant.is_some() {
        test_knobs::require(&["VOX_MUTANT_GOV_BINDING"]);
    }
    let bob_env: Vec<(&str, &str)> = mutant
        .as_deref()
        .map(|m| vec![("VOX_MUTANT_GOV_BINDING", m)])
        .unwrap_or_default();
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
    let bob_d = bob.daemon_with_anchor(Some(&spec), &bob_env);
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

    let (head_before, _) = feed_view(&bob.status(), &room, &mallory);
    let base = head_before.unwrap_or(0);
    mallory.post(&room, "whatever mallory typed");
    // From whichever peer served it first: Mallory, or the anchor holding it for her.
    let refused = refused_at_binding(&bob, &room, &mallory, base);
    assert!(
        announced(&mallory_d, MODE),
        "APPARATUS (the mutant peer): mallory's daemon never announced {MODE:?}:\n{}",
        mallory_d.transcript()
    );
    let after = "alice, after mallory's entry";
    alice.post(&room, after);
    let took = arrives(&bob, &room, after);
    println!(
        "[proof] misbound: bob refused it at its binding ({refused}); alice's next post reached \
         him: {took:?}"
    );
    if let Err(e) = &took {
        panic!(
            "PRODUCT: alice's post made after mallory's misbound governance entry never reached \
             bob ({e}): the room's sync stopped\nbob's status: {}\nbob:\n{}",
            bob.status(),
            bob_d.transcript()
        );
    }
    // ---- bob restarts: the room is held again, whole, and nothing hostile was stored --------
    drop(bob_d);
    let _bob_d = bob.daemon_with_anchor(Some(&spec), &bob_env);
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
    let row = member_row(status, room, of);
    (
        row["advertised_through"].as_u64(),
        row["verified_through"].as_u64(),
    )
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

/// `writer` posts `text`, and `reader` must show it; how it went. `writer`'s entries name in
/// `seen` the newest settled tip it holds of every other member (a control first, when that
/// changes its context), so the post rests on whatever `writer` holds as a source. The RED
/// verdict: the post fails, or `reader` knows `writer`'s head past what she had verified before
/// it and, over three completed rounds toward `writer`, her verified prefix of him stays below
/// that head without the post shown: she cannot admit what it rests on. Neither within 600 s is
/// APPARATUS NO RESULT.
fn rests_on_nothing_later(
    writer: &Member,
    reader: &Member,
    room: &str,
    text: &str,
    phase: &str,
) -> String {
    let (_, before) = feed_view(&reader.status(), room, writer);
    let before = before.unwrap_or(0);
    let (ok, out, err) = writer.vox(&["room", "post", room, text], None);
    assert!(
        ok,
        "RED PRODUCT ({phase}): {}'s `vox room post` failed: {out}{err}",
        writer.name
    );
    let started = Instant::now();
    let mut wedged: Option<(u64, u64, u64)> = None;
    loop {
        match reads(reader, room, text) {
            Ok(true) => {
                return format!(
                    "{} shows it; her verified prefix of {} {before} -> {:?}",
                    reader.name,
                    writer.name,
                    feed_view(&reader.status(), room, writer).1
                )
            }
            Ok(false) => {}
            Err(e) => panic!(
                "PRODUCT ({phase}): {}'s `vox room read` failed: {e}",
                reader.name
            ),
        }
        let status = reader.status();
        let rounds = rounds_toward(&status, writer);
        let (head, verified) = feed_view(&status, room, writer);
        let verified = verified.unwrap_or(0);
        wedged = match (head, wedged) {
            (Some(head), Some((h, v, first))) if head == h && verified == v => Some((h, v, first)),
            (Some(head), _) if head > before && verified < head => Some((head, verified, rounds)),
            _ => None,
        };
        if let Some((head, verified, first)) = wedged {
            assert!(
                rounds < first + 3,
                "RED PRODUCT ({phase}): {} cannot admit {}'s post {text:?}: she knows his head \
                 {head}, and over rounds toward him {first} -> {rounds} her verified prefix of \
                 him stays at {verified}; what it rests on is no source she can admit\n{}'s row \
                 for him: {}",
                reader.name,
                writer.name,
                reader.name,
                member_row(&status, room, writer)
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT ({phase}): in 600 s {} neither showed {}'s post nor held his \
             verified prefix below his head over three rounds toward him: status {status}",
            reader.name,
            writer.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Rounds `status` reports completed toward `peer`, empty ones included: evidence it asked.
fn rounds_toward(status: &serde_json::Value, peer: &Member) -> u64 {
    ["completed", "empty", "fetched_completed", "fetched_empty"]
        .iter()
        .map(|key| counter(status, key, Some(&peer.fp)))
        .sum()
}

/// Wait until `m` reports `n` more completed rounds toward `peer` than now; how many it took.
/// Fewer within 600 s is APPARATUS NO RESULT.
fn rounds_after(m: &Member, peer: &Member, n: u64, phase: &str) -> u64 {
    let first = rounds_toward(&m.status(), peer);
    let started = Instant::now();
    loop {
        let now = rounds_toward(&m.status(), peer);
        if now >= first + n {
            return now - first;
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT ({phase}): in 600 s {}'s rounds toward {} went {first} -> {now}, \
             fewer than {n} more",
            m.name,
            peer.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Watch `bob` until one of his sync sessions' last failure names [`BINDING`]: he refused `of`'s
/// misbound grant before holding it, as the serving peer's fault; how. The RED verdict is the
/// other outcome: his verified prefix of `of` reaches her head past `base` (her grant) and stays
/// there over three status answers with rounds toward her completing, and no session named the
/// binding: he took it. Neither within 600 s is APPARATUS NO RESULT.
fn refused_at_binding(bob: &Member, room: &str, of: &Member, base: u64) -> String {
    let started = Instant::now();
    let mut samples: Vec<(u64, u64)> = Vec::new();
    loop {
        let status = bob.status();
        let named: Vec<String> = failures(&status)
            .into_iter()
            .filter(|f| f.contains(BINDING))
            .collect();
        if !named.is_empty() {
            return format!(
                "{} session(s) failed in all, refusing it as the peer's fault: {named:?}",
                counter(&status, "failed", None)
            );
        }
        match feed_view(&status, room, of) {
            (Some(head), Some(verified)) if head > base && verified >= head => {
                samples.push((head, rounds_toward(&status, of)));
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
            panic!(
                "RED PRODUCT: bob took {}'s misbound governance grant: his verified prefix of her \
                 reached her head {} (past {base}) over three answers with rounds toward her \
                 completing, and no session refused it at its binding\nbob's status: {status}",
                of.name, samples[2].0
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "APPARATUS NO RESULT: in 600 s bob neither refused {}'s grant at its binding nor took \
             it (samples {samples:?})\nbob's status: {status}",
            of.name
        );
        std::thread::sleep(Duration::from_secs(1));
    }
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
    // The reader mutant goes to Bob's daemon only; Mallory is the attacker, Alice a witness.
    let mutant = std::env::var("VOX_PROOF_TERMINATION").ok();
    if mutant.is_some() {
        test_knobs::require(&["VOX_MUTANT_TERMINATION"]);
    }
    let bob_env: Vec<(&str, &str)> = mutant
        .as_deref()
        .map(|m| vec![("VOX_MUTANT_TERMINATION", m)])
        .unwrap_or_default();
    let sender = mutant_sender();
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
    // Non-citable first: three more completed rounds toward mallory, so whatever bob takes of
    // her later positions while the termination is withheld he has taken before he posts.
    let asked = rounds_after(&bob, &mallory, 3, "withheld");
    println!(
        "[proof] withheld: after {asked} more rounds toward mallory, bob's row for her: {}",
        member_row(&bob.status(), &room, &mallory)
    );
    let cited = "bob, while mallory's termination is withheld";
    let took = rests_on_nothing_later(&bob, &alice, &room, cited, "withheld");
    println!(
        "[proof] hidden termination, withheld: bob's post, which names the newest tips he \
         holds, reached alice ({took}): no later post of mallory's is a source he cites"
    );
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
