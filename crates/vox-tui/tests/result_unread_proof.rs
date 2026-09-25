//! ADR-021 **M21.10** — **a `result` warns about unread addressed messages**, through the
//! shipped `vox` binary on two nodes.
//!
//! A redirect addressed to a session can land after its last drain and before it reports
//! its result. The result still posts — it is an assertion, and refusing it would lose it —
//! but the caller is shown every message addressed to it that its drain has not delivered,
//! so it can follow up:
//!
//! 1. with an addressed message unread, the result posts **and** names that message, on
//!    stderr and in `--json`'s `unread_addressed`;
//! 2. a broadcast, and a message addressed to someone else, are not named;
//! 3. once the session's drain has delivered it, the next result warns about nothing;
//! 4. a post that is not a `result` never warns;
//! 5. a session is also addressed by its `VOX_AGENT_NAME` — the name a harness gives it —
//!    and a message to that name is named too.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{until, Out, Worker};

fn drain(w: &Worker, r: &str, session: &str) {
    let o = w.vox(
        Some(session),
        &[
            "agent",
            "hook",
            "--room",
            r,
            "--format",
            "text",
            "--session",
            session,
        ],
    );
    assert!(o.ok, "{o:?}");
}

fn post(w: &Worker, session: &str, r: &str, args: &[&str], body: &str) -> Out {
    let mut a = vec!["room", "post", r];
    a.extend_from_slice(args);
    a.push("-");
    let o = w.vox_in(Some(session), &a, Some(body));
    assert!(o.ok, "{session} must be able to post: {o:?}");
    o
}

fn result(w: &Worker, r: &str) -> Out {
    post(
        w,
        "s1",
        r,
        &[
            "--type",
            "result",
            "--work",
            "gh:acme/w#1",
            "--data",
            r#"{"evidence":[{"kind":"commit","ref":"9f3c2e1a"}]}"#,
            "--json",
        ],
        "done",
    )
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_result_names_the_addressed_messages_its_session_has_not_read() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    drain(alice, r, "s1"); // s1 is up to date

    // Bob redirects s1, and also broadcasts and writes to somebody else.
    post(
        bob,
        "b1",
        r,
        &["--type", "ask", "--to", "s1"],
        "stop: use the v2 schema",
    );
    post(bob, "b1", r, &["--type", "status"], "a note to the room");
    post(
        bob,
        "b1",
        r,
        &["--type", "ask", "--to", "s9"],
        "for someone else",
    );
    until(
        alice,
        None,
        "bob's three messages to reach alice",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("for someone else"),
    );

    // ---- (4) a post that is not a result never warns ----
    let note = post(
        alice,
        "s1",
        r,
        &["--type", "status", "--work", "gh:acme/w#1"],
        "almost",
    );
    assert!(
        !note.stderr.contains("unread"),
        "only a result warns: {note:?}"
    );

    // ---- (1) and (2) the result posts, and names exactly the addressed message ----
    let o = result(alice, r);
    let unread = o.json()["unread_addressed"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("a result must report unread_addressed: {o:?}"));
    let bodies: Vec<&str> = unread.iter().filter_map(|x| x["body"].as_str()).collect();
    assert_eq!(
        bodies,
        ["stop: use the v2 schema"],
        "exactly the message addressed to s1 must be named — not the broadcast, not the \
         one to s9: {o:?}"
    );
    assert!(
        o.stderr.contains("unread") && o.stderr.contains("stop: use the v2 schema"),
        "the caller must be told on stderr too: {o:?}"
    );

    // ---- (3) after the drain delivers it, nothing to warn about ----
    drain(alice, r, "s1");
    let o = result(alice, r);
    assert_eq!(
        o.json()["unread_addressed"],
        serde_json::json!([]),
        "a delivered message is not unread: {o:?}"
    );
    assert!(!o.stderr.contains("unread"), "{o:?}");

    // ---- (5) addressed by VOX_AGENT_NAME ----
    post(
        bob,
        "b1",
        r,
        &["--type", "ask", "--to", "alpha"],
        "alpha: please rebase first",
    );
    until(
        alice,
        None,
        "bob's message to alpha to reach alice",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("please rebase first"),
    );
    let o = alice.vox_env(
        Some("s1"),
        &[("VOX_AGENT_NAME", "alpha")],
        &[
            "room",
            "post",
            r,
            "--type",
            "result",
            "--work",
            "gh:acme/w#1",
            "--data",
            r#"{"evidence":[{"kind":"commit","ref":"9f3c2e1a"}]}"#,
            "--json",
            "-",
        ],
        Some("done again"),
    );
    assert!(o.ok, "{o:?}");
    let bodies: Vec<String> = o.json()["unread_addressed"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x["body"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        bodies,
        ["alpha: please rebase first"],
        "a message to the session's VOX_AGENT_NAME must be named: {o:?}"
    );
}
