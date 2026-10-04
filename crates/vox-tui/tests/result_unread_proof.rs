//! ADR-021 **M21.10** — **a `result` warns about unread addressed messages**, through the
//! shipped `vox` binary on two nodes.
//!
//! A redirect addressed to a session's node can land after its last drain and before it reports
//! its result. The result still posts — it is an assertion, and refusing it would lose it —
//! but the caller is shown every message addressed to it that its drain has not delivered,
//! so it can follow up:
//!
//! 1. with an addressed message unread, the result posts **and** names that message, on
//!    stderr and in `--json`'s `unread_addressed`;
//! 2. a broadcast, and a message addressed to someone else, are not named;
//! 3. once the session's drain has delivered it, the next result warns about nothing;
//! 4. a post that is not a `result` never warns;
//! 5. a message addresses a **node**, never a session (V210-161, ADR-020 6.2): another session of
//!    the same node, which has not drained it, names it too.
//!
//! This proof addressed sessions (`--to s1`, `VOX_AGENT_NAME`) until 2026-10-03; addresses name
//! nodes since V210-161, and `--to s1` is refused as naming no member.

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
            "--node",
            "default",
            "--room",
            r,
            "--format",
            "text",
            "--session",
            session,
        ],
    );
    assert!(
        o.ok,
        "PRODUCT: `vox agent hook` (the drain) failed for {session}: {o:?}"
    );
}

fn post(w: &Worker, session: &str, r: &str, args: &[&str], body: &str) -> Out {
    let mut a = vec!["room", "post", r];
    a.extend_from_slice(args);
    a.push("-");
    let o = w.vox_in(Some(session), &a, Some(body));
    assert!(o.ok, "PRODUCT: `vox room post` failed for {session}: {o:?}");
    o
}

/// The `--json` object a post printed: a post that printed anything else is the product's red.
fn json(o: &Out) -> serde_json::Value {
    serde_json::from_str(o.stdout.trim())
        .unwrap_or_else(|e| panic!("PRODUCT: `--json` printed no single JSON object ({e}): {o:?}"))
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
        .expect("APPARATUS: build the test's runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: create a tempdir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();
    let alice_fp = vox_core::node::link::b32_encode(&alice.fp);
    let bob_fp = vox_core::node::link::b32_encode(&bob.fp);

    drain(alice, r, "s1"); // s1 is up to date

    // Bob redirects s1, and also broadcasts and writes to somebody else.
    post(
        bob,
        "b1",
        r,
        &["--type", "ask", "--to", alice_fp.as_str()],
        "stop: use the v2 schema",
    );
    post(bob, "b1", r, &["--type", "status"], "a note to the room");
    post(
        bob,
        "b1",
        r,
        &["--type", "ask", "--to", bob_fp.as_str()],
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
        "PRODUCT: a status post warned about unread messages; only a result warns: {note:?}"
    );

    // ---- (1) and (2) the result posts, and names exactly the addressed message ----
    let o = result(alice, r);
    let unread = json(&o)["unread_addressed"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| {
            panic!("PRODUCT: the result's --json has no unread_addressed list: {o:?}")
        });
    let bodies: Vec<&str> = unread.iter().filter_map(|x| x["body"].as_str()).collect();
    assert_eq!(
        bodies,
        ["stop: use the v2 schema"],
        "PRODUCT: exactly the message addressed to alice's node must be named — not the \
         broadcast, not the one to bob's: {o:?}"
    );
    assert!(
        o.stderr.contains("unread") && o.stderr.contains("stop: use the v2 schema"),
        "PRODUCT: the result did not name the unread message on stderr: {o:?}"
    );

    // ---- (3) after the drain delivers it, nothing to warn about ----
    drain(alice, r, "s1");
    let o = result(alice, r);
    assert_eq!(
        json(&o)["unread_addressed"],
        serde_json::json!([]),
        "PRODUCT: a result after the drain still named a delivered message as unread: {o:?}"
    );
    assert!(
        !o.stderr.contains("unread"),
        "PRODUCT: a result after the drain still warned on stderr: {o:?}"
    );

    // ---- (5) a node is addressed, not a session: s2 of the same node names it too ----
    post(
        bob,
        "b1",
        r,
        &["--type", "ask", "--to", alice_fp.as_str()],
        "please rebase first",
    );
    until(
        alice,
        None,
        "bob's second message to alice's node to reach alice",
        &["room", "read", r],
        |o: &Out| o.stdout.contains("please rebase first"),
    );
    let o = post(
        alice,
        "s2",
        r,
        &[
            "--type",
            "result",
            "--work",
            "gh:acme/w#2",
            "--data",
            r#"{"evidence":[{"kind":"commit","ref":"9f3c2e1a"}]}"#,
            "--json",
        ],
        "done by s2",
    );
    let mut bodies: Vec<String> = json(&o)["unread_addressed"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|x| x["body"].as_str().map(str::to_owned))
        .collect();
    bodies.sort();
    assert_eq!(
        bodies,
        ["please rebase first", "stop: use the v2 schema"],
        "PRODUCT: a session that has not drained must be named every message to its node: {o:?}"
    );
}
