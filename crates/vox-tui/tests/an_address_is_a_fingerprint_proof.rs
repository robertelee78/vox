//! PRD-001 R15 (#18) — **addressing uses fingerprints on the wire, and every node shows each
//! addressee by its own keyring's name**, through the shipped `vox` binary: an anchor and alice's,
//! bob's and carol's `vox daemon` in one room (`support/room.rs`), `vox trust rename|remove|add`,
//! `vox room post --to`, `vox room read --json`, the drain hook `vox agent hook`, and carol's
//! daemon's urgent wake.
//!
//! **Each node has its own keyring and reads no other** (the decider, 2026-10-02). A node, agent or
//! person alike, shows a member by the name its own keyring gives it, or by the fingerprint where
//! it has none. Alice names carol `mom`. Bob, an agent's node, has no name for her (`vox trust
//! remove`), until he adds his own, `cee`. Carol's session answers to the agent name `agent-c`
//! (`VOX_AGENT_NAME`).
//!
//! Nothing here is `vox` except a stand-in for Claude Code's messaging socket, which records what
//! carol's daemon writes to it: no `vox` command plays a harness session. Every `vox` child has the
//! harness variables removed (`support`), and carol's registration is read back and required to
//! name the test's own socket before anything urgent is posted.
//!
//! It asserts:
//!
//! 1. **A name is not an address.** Alice posts urgently to `agent-c` on **bob's** node: the same
//!    agent name, another fingerprint. Carol's session is not woken.
//! 2. **Each sender addresses carol by its own name, and both reach her.** Alice posts urgently
//!    `--to mom/agent-c`, and bob, once he has named her, `--to cee`. Both wake carol's session.
//! 3. **Only the fingerprint is on the wire.** Every copy of both messages carries carol's full
//!    fingerprint in `to` (with `/agent-c` for alice's), and neither `mom` nor `cee` appears in any
//!    copy.
//! 4. **Each node shows its own name, or the fingerprint.** Alice's `room read --json` names the
//!    addressee `mom`, and her drain shows `to mom/agent-c`. Bob, with no name for carol, is shown
//!    her fingerprint in both, and never `mom`.
//! 5. **A node's own new name is shown.** After bob adds carol as `cee`, his read names her `cee`
//!    and his drain shows `to cee/agent-c`, still never `mom`.
//!
//! 6. **The TUI too** (`the_tui_shows_each_node_its_own_name_for_the_addressee`, through
//!    `tests/pty/tui_addressee_names.py`): bob's own `vox tui` shows alice's message to `mom`
//!    addressed to carol's fingerprint and never to `mom`, and alice's shows it addressed to `mom`.
//!
//! **Mutation.** Each claim has a mutant in the product that turns its own assertion red:
//! - (1) a receiver matches the agent name without the fingerprint: carol is woken;
//! - (2) the sender sends what was typed instead of resolving it: no wake;
//! - (3) and (4) **names shared across nodes**: the sender sends what was typed and readers print
//!   it: `mom` on the wire and on bob's screen;
//! - (4) and (5) a reader ignores its own keyring: alice and bob are shown fingerprints;
//! - (6) the TUI shows the sender's name for the addressee instead of its own: names shared
//!   across nodes, as above, turns bob's screen red.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use support::{until, Out, Worker};

/// Base32 characters of a fingerprint a reader is shown (`ident::AUTHOR_CHARS`).
const AUTHOR_CHARS: usize = 26;

/// A stand-in Claude Code messaging socket: every connection's bytes, as they are written.
fn listen(path: &Path) -> mpsc::Receiver<String> {
    let listener = UnixListener::bind(path).expect("APPARATUS: bind the stand-in session socket");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            if tx.send(buf).is_err() {
                return;
            }
        }
    });
    rx
}

/// Everything carol's stand-in session receives within `within`, stopping early once `done`.
fn collect(
    inbox: &mpsc::Receiver<String>,
    within: Duration,
    done: impl Fn(&[String]) -> bool,
) -> Vec<String> {
    let mut got = Vec::new();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline && !done(&got) {
        if let Ok(frames) = inbox.recv_timeout(Duration::from_millis(250)) {
            eprintln!("[receipt] carol's session received: {frames}");
            got.push(frames);
        }
    }
    got
}

/// `w`'s operator runs `vox trust <args…>` against `w`'s own keyring.
fn trust(w: &Worker, args: &[&str]) {
    let mut all = vec!["trust"];
    all.extend_from_slice(args);
    all.extend([
        "--identity-passphrase-file",
        w.pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    let o = w.vox(None, &all);
    assert!(o.ok, "PRODUCT: {}'s `vox trust {args:?}` failed: {o:?}", w.name);
}

/// An urgent `ask` from `w`'s session `session`, addressed to `to` as typed.
fn post_to(w: &Worker, session: &str, r: &str, to: &str, body: &str) {
    let o = w.vox_in(
        Some(session),
        &[
            "room", "post", r, "--json", "--type", "ask", "--urgent", "--to", to, "-",
        ],
        Some(body),
    );
    assert!(o.ok, "PRODUCT: {} could not post to {to:?}: {o:?}", w.name);
}

/// `w`'s copy of the row whose text contains `marker`, as `vox room read --json` gives it.
fn row_with(w: &Worker, r: &str, marker: &str) -> Option<serde_json::Value> {
    w.vox(None, &["room", "read", r, "--json"])
        .ndjson()
        .into_iter()
        .find(|x| x["text"].as_str().is_some_and(|t| t.contains(marker)))
}

/// The line of a fresh drain, as `session` of `w`, that shows `marker`.
fn drained(w: &Worker, r: &str, session: &str, marker: &str) -> String {
    let o = w.vox(
        None,
        &["agent", "hook", "--room", r, "--format", "text", "--session", session],
    );
    assert!(o.ok, "PRODUCT: a drain hook always exits 0: {o:?}");
    o.stdout
        .lines()
        .find(|l| l.contains(marker))
        .unwrap_or_default()
        .to_owned()
}

/// Record a failed claim and carry on, so one mutant shows every case red.
fn check(failures: &mut Vec<String>, ok: bool, what: String) {
    if !ok {
        eprintln!("[red] {what}");
        failures.push(what);
    }
}

#[test]
#[ignore = "an anchor and three vox daemons with production Argon2id; CI runs it in release"]
fn each_node_addresses_by_fingerprint_and_shows_its_own_name_for_the_addressee() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let r = room.id.as_str();
    let carol_fp = carol.b32();
    let carol_id = &carol_fp[..AUTHOR_CHARS];
    let mut failures = Vec::new();

    // Alice's own name for carol; bob has none.
    trust(alice, &["rename", &carol_fp, "mom"]);
    trust(bob, &["remove", &carol_fp]);

    // ---- carol's session registers with her daemon, as a harness hook does every turn ----
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let o = carol.vox_env(
        None,
        &[
            ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
            ("VOX_AGENT_NAME", "agent-c"),
        ],
        &["agent", "hook", "--room", r],
        Some(r#"{"session_id":"session-c","hook_event_name":"UserPromptSubmit"}"#),
    );
    assert!(o.ok, "PRODUCT: `vox agent hook` must exit 0: {o:?}");
    let reg: Option<serde_json::Value> = std::fs::read(carol.paths.session_file("session-c"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    assert!(
        reg.as_ref()
            .is_some_and(|v| v["endpoint"] == sock_s.as_str() && v["name"] == "agent-c"),
        "CANNOT MEASURE: carol's session must be registered at the test's own socket, under \
         agent-c, never a real session's: {reg:?}"
    );

    // ---- (1) first, so a wrong wake cannot be confused with a right one ----
    post_to(
        alice,
        "alice-s",
        r,
        &format!("{}/agent-c", &bob.b32()[..12]),
        "NOT-FOR-CAROL",
    );
    until(
        carol,
        None,
        "alice's message to bob's agent-c to reach carol",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("NOT-FOR-CAROL"),
    );
    // Ten seconds past its arrival: five sweeps of the daemon's tick.
    let stray = collect(&inbox, Duration::from_secs(10), |_| false);
    check(
        &mut failures,
        !stray.iter().any(|f| f.contains("NOT-FOR-CAROL")),
        format!(
            "PRODUCT: (1) a message to agent-c on bob's node woke carol's agent-c: a name was \
             taken for an address: {stray:?}"
        ),
    );

    // ---- (2) alice addresses carol by her own name for her ----
    post_to(alice, "alice-s", r, "mom/agent-c", "FROM-ALICE-MARK");
    let got = collect(&inbox, Duration::from_secs(60), |g| {
        g.iter().any(|f| f.contains("FROM-ALICE-MARK"))
    });
    check(
        &mut failures,
        got.iter().any(|f| f.contains("FROM-ALICE-MARK")),
        format!("PRODUCT: (2) alice's message to `mom/agent-c` did not wake carol: {got:?}"),
    );
    until(
        bob,
        None,
        "alice's message to carol to reach bob",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("FROM-ALICE-MARK"),
    );

    // ---- (4) each node's own name, or the fingerprint ----
    let name_in = |w: &Worker, mark: &str| {
        row_with(w, r, mark).map(|x| x["addressed"].clone())
    };
    let a = name_in(alice, "FROM-ALICE-MARK");
    check(
        &mut failures,
        a == Some(serde_json::json!([{ "fp": carol_fp, "sub": "agent-c", "name": "mom" }])),
        format!("PRODUCT: (4) alice's read must name the addressee `mom`, her own name: {a:?}"),
    );
    let line = drained(alice, r, "alice-d", "FROM-ALICE-MARK");
    check(
        &mut failures,
        line.contains(" to mom/agent-c] "),
        format!("PRODUCT: (4) alice's drain must show `to mom/agent-c`: {line:?}"),
    );
    let b = name_in(bob, "FROM-ALICE-MARK");
    check(
        &mut failures,
        b == Some(serde_json::json!([{ "fp": carol_fp, "sub": "agent-c", "name": null }])),
        format!(
            "PRODUCT: (4) bob has no name for carol, so his read must give none (never alice's \
             `mom`): {b:?}"
        ),
    );
    let line = drained(bob, r, "bob-d", "FROM-ALICE-MARK");
    check(
        &mut failures,
        line.contains(&format!(" to {carol_id}/agent-c] ")) && !line.contains("mom"),
        format!(
            "PRODUCT: (4) bob's drain must show carol's fingerprint, never alice's `mom`: {line:?}"
        ),
    );

    // ---- (5) bob adds his own name for carol ----
    trust(bob, &["add", &carol_fp, "--name", "cee"]);
    let b = name_in(bob, "FROM-ALICE-MARK");
    check(
        &mut failures,
        b == Some(serde_json::json!([{ "fp": carol_fp, "sub": "agent-c", "name": "cee" }])),
        format!("PRODUCT: (5) bob's read must now name the addressee `cee`, his own name: {b:?}"),
    );
    let line = drained(bob, r, "bob-d2", "FROM-ALICE-MARK");
    check(
        &mut failures,
        line.contains(" to cee/agent-c] ") && !line.contains("mom"),
        format!("PRODUCT: (5) bob's drain must now show `to cee/agent-c`: {line:?}"),
    );

    // ---- (2) bob addresses carol by his own, different name ----
    post_to(bob, "bob-s", r, "cee", "FROM-BOB-MARK");
    let got = collect(&inbox, Duration::from_secs(60), |g| {
        g.iter().any(|f| f.contains("FROM-BOB-MARK"))
    });
    check(
        &mut failures,
        got.iter().any(|f| f.contains("FROM-BOB-MARK")),
        format!("PRODUCT: (2) bob's message to `cee` did not wake carol: {got:?}"),
    );
    until(
        alice,
        None,
        "bob's message to carol to reach alice",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("FROM-BOB-MARK"),
    );

    // ---- (3) only the fingerprint on the wire, in every copy ----
    let want = [
        ("FROM-ALICE-MARK", format!("{carol_fp}/agent-c")),
        ("FROM-BOB-MARK", carol_fp.clone()),
    ];
    for reader in [alice, bob, carol] {
        for (mark, wire) in &want {
            let row = row_with(reader, r, mark);
            let to = row.as_ref().map(|x| x["envelope"]["to"].clone());
            let text = row
                .as_ref()
                .and_then(|x| x["text"].as_str().map(str::to_owned))
                .unwrap_or_default();
            check(
                &mut failures,
                to == Some(serde_json::json!([wire])) && !text.contains("mom") && !text.contains("cee"),
                format!(
                    "PRODUCT: (3) {}'s copy of {mark} must carry exactly [{wire}] in `to`, and no \
                     node's name for carol: {row:?}",
                    reader.name
                ),
            );
        }
    }

    assert!(
        failures.is_empty(),
        "{} claim(s) red:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_shows_each_node_its_own_name_for_the_addressee() {
    // Bounded as `tui_member_names_proof` is, for the same two joins in a debug build: the driver's
    // budget is 1260 s, it is stopped from outside at 1290 s, and the watchdog is past both.
    watchdog::arm_for(Duration::from_secs(1400));
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_addressee_names.py");
    let out = pty_driver::run_within(
        script,
        &[env!("CARGO_BIN_EXE_vox"), "cargo"],
        Duration::from_secs(1290),
    );
    let said = out.stdout.clone();
    eprintln!(
        "{said}\n[proof] the driver took {:?}; its last stage: {:?}",
        out.took, out.stage
    );
    // Every red names whose it is: the driver exits 1 only on a product verdict, 2 on its own.
    match out.code {
        Some(0) => assert!(
            said.contains("cargo PASS"),
            "APPARATUS: exit 0 without a PASS line: {said}"
        ),
        Some(2) => panic!("CANNOT MEASURE: the TUI proof's apparatus failed: {said}"),
        _ if !out.has_verdict("cargo") => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver gave no verdict after {:?} at stage {:?} \
             (exit {:?}): stopped from outside at the wrapper's 1290 s bound, by its faulthandler \
             backstop, or crashed: {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
        Some(1) => panic!(
            "PRODUCT: each node's TUI must show the addressee by its own name, or the \
             fingerprint, never another node's name: {said}"
        ),
        _ => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver ended after {:?} at stage {:?} with exit \
             {:?} and no verdict this wrapper knows: {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
    }
}
