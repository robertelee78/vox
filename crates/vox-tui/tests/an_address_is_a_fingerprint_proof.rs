//! PRD-001 R15 (#18) — **addressing uses fingerprints on the wire and shows each reader its own
//! keyring names**, through the shipped `vox` binary: an anchor and alice's, bob's and carol's
//! `vox daemon` in one room (`support/room.rs`), `vox trust rename`, `vox room post --to`,
//! `vox room read --json`, the drain hook `vox agent hook`, and bob's daemon's urgent wake.
//!
//! Nothing here is `vox` except a stand-in for Claude Code's messaging socket, which records what
//! bob's daemon writes to it: no `vox` command plays a harness session. Every `vox` child has the
//! harness variables removed (`support`), and bob's registration is read back and required to
//! name the test's own socket before anything urgent is posted.
//!
//! Alice calls bob `bobby-a` and carol calls him `robert-c` (`vox trust rename`). Bob's session
//! answers to the agent name `agent-b` (`VOX_AGENT_NAME`). It asserts:
//!
//! 1. **The same addressee, however the sender names him.** Alice posts urgently to bob's
//!    session, and carol to bob's whole node, each typing a prefix of his fingerprint. Both
//!    messages wake bob's session, and both are delivered: bob's own read shows each addressed
//!    to his full fingerprint.
//! 2. **Only the fingerprint is on the wire.** The envelope each message carries names bob by
//!    his full fingerprint (and `/agent-b` for alice's), never by what was typed and never by
//!    either sender's name for him: neither `bobby-a` nor `robert-c` appears in any copy.
//! 3. **A name is not an address.** Alice posts urgently to `agent-b` on **carol's** node: the
//!    same agent name, another fingerprint. Bob's session is not woken.
//! 4. **A reader without a keyring is shown the fingerprint.** Alice's drain (a socket client,
//!    which cannot read the keyring) shows carol's message as addressed to bob's fingerprint,
//!    never to anyone's name for him.
//!
//! **Mutation.** Each claim has a mutant in the product that turns its own assertion red:
//! - the sender sends what was typed instead of resolving it: (1) no wake, (2) a prefix on
//!   the wire;
//! - a receiver matches the sub-address without the fingerprint: (3) bob is woken;
//! - the drain shows no addressees: (4).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use support::{until, Out, Worker};

/// Base32 characters of a fingerprint a socket surface shows (`ident::AUTHOR_CHARS`).
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

/// Everything bob's stand-in session receives within `within`, stopping early once `done`.
fn collect(
    inbox: &mpsc::Receiver<String>,
    within: Duration,
    done: impl Fn(&[String]) -> bool,
) -> Vec<String> {
    let mut got = Vec::new();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline && !done(&got) {
        if let Ok(frames) = inbox.recv_timeout(Duration::from_millis(250)) {
            eprintln!("[receipt] bob's session received: {frames}");
            got.push(frames);
        }
    }
    got
}

/// `w` renames the member `whom` to `name` in its own keyring, as its operator would.
fn rename(w: &Worker, whom: &Worker, name: &str) {
    let o = w.vox(
        None,
        &[
            "trust",
            "rename",
            &whom.b32(),
            name,
            "--identity-passphrase-file",
            w.pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ],
    );
    assert!(
        o.ok,
        "PRODUCT: {}'s `vox trust rename` of {} failed: {o:?}",
        w.name, whom.name
    );
}

/// An urgent `ask` from `w`'s session `session`, addressed to `to` as typed; its entry hash.
fn post_to(w: &Worker, session: &str, r: &str, to: &str, body: &str) -> String {
    let o = w.vox_in(
        Some(session),
        &[
            "room", "post", r, "--json", "--type", "ask", "--urgent", "--to", to, "-",
        ],
        Some(body),
    );
    assert!(
        o.ok,
        "PRODUCT: {} could not post to {to:?}: {o:?}",
        w.name
    );
    o.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: `vox room post --json` names the entry")
        .to_owned()
}

/// `w`'s copy of the row whose text contains `marker`, as `vox room read --json` gives it.
fn row_with(w: &Worker, r: &str, marker: &str) -> Option<serde_json::Value> {
    w.vox(None, &["room", "read", r, "--json"])
        .ndjson()
        .into_iter()
        .find(|x| x["text"].as_str().is_some_and(|t| t.contains(marker)))
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
fn an_addressee_is_its_fingerprint_on_the_wire_and_each_readers_own_name_on_screen() {
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
    let mut failures = Vec::new();

    // Two senders, two names for one member.
    rename(alice, bob, "bobby-a");
    rename(carol, bob, "robert-c");

    // ---- bob's session registers with his daemon, as a harness hook does every turn ----
    let sock = tmp.path().join("session.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let o = bob.vox_env(
        None,
        &[
            ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
            ("VOX_AGENT_NAME", "agent-b"),
        ],
        &["agent", "hook", "--room", r],
        Some(r#"{"session_id":"session-b","hook_event_name":"UserPromptSubmit"}"#),
    );
    assert!(o.ok, "PRODUCT: `vox agent hook` must exit 0: {o:?}");
    let reg: Option<serde_json::Value> = std::fs::read(bob.paths.session_file("session-b"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    assert!(
        reg.as_ref()
            .is_some_and(|v| v["endpoint"] == sock_s.as_str() && v["name"] == "agent-b"),
        "CANNOT MEASURE: bob's session must be registered at the test's own socket, under \
         agent-b, never a real session's: {reg:?}"
    );

    let bob_fp = bob.b32();
    let prefix = &bob_fp[..12];

    // ---- (3) first, so a wrong wake cannot be confused with a right one: a name is not an
    // address. Same agent name, carol's fingerprint.
    post_to(
        alice,
        "alice-s",
        r,
        &format!("{}/agent-b", &carol.b32()[..12]),
        "NOT-FOR-BOB",
    );
    until(
        bob,
        None,
        "alice's message to carol's agent-b to reach bob",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("NOT-FOR-BOB"),
    );
    // Ten seconds past its arrival: five sweeps of the daemon's tick.
    let stray = collect(&inbox, Duration::from_secs(10), |_| false);
    check(
        &mut failures,
        !stray.iter().any(|f| f.contains("NOT-FOR-BOB")),
        format!(
            "PRODUCT: (3) a message to agent-b on carol's node woke bob's agent-b: a name was \
             taken for an address: {stray:?}"
        ),
    );

    // ---- (1) two senders, two names, one addressee ----
    post_to(alice, "alice-s", r, &format!("{prefix}/agent-b"), "FROM-ALICE-MARK");
    post_to(carol, "carol-s", r, prefix, "FROM-CAROL-MARK");
    let got = collect(&inbox, Duration::from_secs(60), |g| {
        g.iter().any(|f| f.contains("FROM-ALICE-MARK"))
            && g.iter().any(|f| f.contains("FROM-CAROL-MARK"))
    });
    for (who, mark) in [("alice", "FROM-ALICE-MARK"), ("carol", "FROM-CAROL-MARK")] {
        check(
            &mut failures,
            got.iter().any(|f| f.contains(mark)),
            format!("PRODUCT: (1) {who}'s urgent message to bob did not wake his session: {got:?}"),
        );
    }
    let want = [
        ("FROM-ALICE-MARK", format!("{bob_fp}/agent-b"), Some("agent-b")),
        ("FROM-CAROL-MARK", bob_fp.clone(), None),
    ];
    for (mark, wire, sub) in &want {
        let row = row_with(bob, r, mark);
        let addressed = row.as_ref().map(|x| x["addressed"].clone());
        check(
            &mut failures,
            addressed
                == Some(serde_json::json!([{ "fp": bob_fp, "sub": sub }])),
            format!(
                "PRODUCT: (1) bob's read must show {mark} addressed to his own fingerprint \
                 ({wire}): {row:?}"
            ),
        );
    }

    // ---- (2) only the fingerprint on the wire, in every copy ----
    for reader in [alice, bob, carol] {
        for (mark, wire, _) in &want {
            let row = row_with(reader, r, mark);
            let to = row.as_ref().map(|x| x["envelope"]["to"].clone());
            check(
                &mut failures,
                to == Some(serde_json::json!([wire])),
                format!(
                    "PRODUCT: (2) {}'s copy of {mark} must carry exactly [{wire}] in `to`: \
                     {row:?}",
                    reader.name
                ),
            );
            let text = row
                .as_ref()
                .and_then(|x| x["text"].as_str().map(str::to_owned))
                .unwrap_or_default();
            check(
                &mut failures,
                !text.contains("bobby-a") && !text.contains("robert-c"),
                format!(
                    "PRODUCT: (2) a sender's own name for bob reached the wire in {}'s copy of \
                     {mark}: {text}",
                    reader.name
                ),
            );
        }
    }

    // ---- (4) a reader with no keyring is shown the fingerprint ----
    let o = alice.vox(
        None,
        &[
            "agent", "hook", "--room", r, "--format", "text", "--session", "alice-d",
        ],
    );
    let line = o
        .stdout
        .lines()
        .find(|l| l.contains("FROM-CAROL-MARK"))
        .unwrap_or_default()
        .to_owned();
    check(
        &mut failures,
        line.contains(&format!(" to {}] ", &bob_fp[..AUTHOR_CHARS]))
            && !line.contains("bobby-a")
            && !line.contains("robert-c"),
        format!(
            "PRODUCT: (4) alice's drain must show carol's message addressed to bob's \
             fingerprint, not a name: {line:?}\n{}",
            o.stdout
        ),
    );

    assert!(
        failures.is_empty(),
        "{} claim(s) red:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
