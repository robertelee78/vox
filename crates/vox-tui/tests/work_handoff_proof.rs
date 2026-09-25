//! ADR-021 M21.2 — **session ownership and the pending handoff**, driven through the
//! shipped `vox` binary against two real nodes and five sessions.
//!
//! What the defects were (ADR-021 F1–F3), and what this proves instead:
//!
//! - F1: a `handoff` never moved ownership — the board folded with a resolver that
//!   resolved nobody, and no proof ever ran `vox room handoff`. **Here every handoff
//!   case runs the verb and reads the result from every node.**
//! - F2: resolving a recipient by petname cannot converge, because petnames are local.
//!   **Here the two nodes name each other by petnames the other never uses** (alice
//!   knows bob as "bob-the-builder", bob knows alice as "boss"), and the folded boards
//!   must still be identical: the handoff carries a fingerprint, resolved once by the
//!   sender, so no reader resolves anything.
//! - F3: two sessions on one harness were one owner. **Here bob runs two sessions,
//!   and exactly one of them holds.**
//!
//! The cases, each asserted from every node's `board --json`:
//!
//! 1. per-session ownership, and another session's `release` having no effect;
//! 2. an untargeted handoff: pending for bob's fingerprint, completed by a bob
//!    session's `claim`, and the sender's later `release` changing nothing;
//! 3. a session-targeted handoff: the other session of the same harness can neither
//!    complete nor decline it; the named session completes it;
//! 4. a decline frees the item — it does **not** return to the sender — and a fresh
//!    claim by a third session then succeeds;
//! 5. a handoff of a claim that had **no TTL** still lapses at its own deadline.
//!
//! No assertion depends on causal order between two authors: every step waits until
//! the node that acts next has *seen* what it acts on.
//!
//! ## Why two nodes, not three — an open defect, not a limitation
//!
//! A third node was the first design, and it could not be built. Two members who both
//! **joined** (rather than created) the room never received each other's sender key,
//! although each trusted the other. Reproduction: three in-process nodes on loopback,
//! no anchor, alice creates, bob and carol join, all six `Trust` edges applied; after
//! 60 s, `bob never received the sender key of ["carol"]`. In a room of three, the two
//! who joined cannot read each other — a user meets that the moment a third person
//! arrives. It is recorded as **open defect F12 in ADR-021**, in `vox-core` key
//! distribution, not accepted as a gap; `node_m19_untrust_lock_gate` stays green only
//! because it never has one joiner read another. Every property this proof asserts is
//! a property of the fold across *nodes* and *sessions*, and two nodes with several
//! sessions each exhibit all of them.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{resource, until, Out, Worker};

/// The viewer-independent part of a board: what every node must agree on.
fn agreed(b: &serde_json::Value) -> serde_json::Value {
    let mut rs = b["resources"].as_array().cloned().unwrap_or_default();
    for r in &mut rs {
        if let Some(m) = r.as_object_mut() {
            m.remove("mine");
            m.remove("eligible");
        }
    }
    serde_json::Value::Array(rs)
}

fn board(w: &Worker, session: Option<&str>, room: &str) -> serde_json::Value {
    let o = w.vox(session, &["room", "board", room, "--json"]);
    assert!(o.ok, "board: {o:?}");
    o.json()
}

/// Wait until `w` sees `r` in the state `pred` accepts.
fn wait_state(
    w: &Worker,
    room: &str,
    what: &str,
    r: &str,
    pred: impl Fn(Option<&serde_json::Value>) -> bool,
) -> serde_json::Value {
    until(
        w,
        None,
        what,
        &["room", "board", room, "--json"],
        |o: &Out| o.ok && pred(resource(&o.json(), r)),
    )
    .json()
}

fn held_by<'a>(fp: &'a str, session: &'a str) -> impl Fn(Option<&serde_json::Value>) -> bool + 'a {
    move |r| {
        r.is_some_and(|r| {
            r["state"] == "held" && r["owner_fp"] == fp && r["owner_session"] == session
        })
    }
}

#[test]
#[ignore = "three networked nodes with production Argon2id; CI runs it in release"]
fn a_handoff_moves_ownership_by_fingerprint_and_every_node_agrees() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();
    let (a_fp, b_fp) = (alice.b32(), bob.b32());
    let b_prefix = &b_fp[..16];

    // F2's premise, made true: each node knows the other by a petname nobody else uses —
    // through the shipped binary, and read back so the premise is not assumed.
    for (w, other, name) in [(alice, &b_fp, "bob-the-builder"), (bob, &a_fp, "boss")] {
        let o = w.vox(
            None,
            &[
                "trust",
                "add",
                other,
                "--name",
                name,
                "--identity-passphrase-file",
                w.pass.to_str().unwrap(),
            ],
        );
        assert!(o.ok, "{} must be able to name its peer: {o:?}", w.name);
        let listed = w.vox(
            None,
            &[
                "trust",
                "list",
                "--identity-passphrase-file",
                w.pass.to_str().unwrap(),
            ],
        );
        assert!(
            listed.stdout.contains(name),
            "{} must now call its peer {name:?}: {listed:?}",
            w.name
        );
    }

    // ---- (1) ownership is per session ----
    let o = bob.vox(Some("b1"), &["room", "claim", r, "own-1"]);
    assert!(o.ok && o.stdout.contains("you hold own-1"), "{o:?}");
    let o = bob.vox(Some("b2"), &["room", "claim", r, "own-1"]);
    assert_eq!(
        o.code,
        Some(1),
        "a second session of the same harness must LOSE, not share: {o:?}"
    );
    assert!(
        o.stderr.contains("held by") && o.stderr.contains("/b1"),
        "{o:?}"
    );
    let o = bob.vox(Some("b2"), &["room", "release", r, "own-1"]);
    assert_eq!(
        o.code,
        Some(1),
        "another session's release must have no effect, and say so: {o:?}"
    );
    wait_state(
        alice,
        r,
        "alice to see bob/b1 hold own-1",
        "own-1",
        held_by(&b_fp, "b1"),
    );

    // ---- (2) untargeted handoff, completed by a bob session ----
    let o = alice.vox(Some("a1"), &["room", "claim", r, "h-any"]);
    assert!(o.ok, "{o:?}");
    let o = alice.vox(
        Some("a1"),
        &["room", "handoff", r, "h-any", "--to", b_prefix],
    );
    assert!(o.ok && o.stdout.contains("reserved for"), "{o:?}");
    for w in [alice, bob] {
        let b = wait_state(w, r, "the pending handoff everywhere", "h-any", |x| {
            x.is_some_and(|x| x["state"] == "pending" && x["to_fp"] == b_fp && x["from_fp"] == a_fp)
        });
        assert!(
            resource(&b, "h-any").unwrap()["owner_fp"].is_null(),
            "pending names no owner"
        );
    }
    let o = alice.vox(Some("a2"), &["room", "claim", r, "h-any"]);
    assert_eq!(
        o.code,
        Some(1),
        "a non-recipient must not take a reserved item: {o:?}"
    );
    let o = bob.vox(Some("b2"), &["room", "claim", r, "h-any"]);
    assert!(
        o.ok && o.stdout.contains("you hold h-any"),
        "the recipient's claim completes it: {o:?}"
    );
    wait_state(
        alice,
        r,
        "alice to see the handoff completed",
        "h-any",
        held_by(&b_fp, "b2"),
    );
    let o = alice.vox(Some("a1"), &["room", "release", r, "h-any"]);
    assert_eq!(
        o.code,
        Some(1),
        "the sender relinquished it; its release must change nothing: {o:?}"
    );

    // ---- (3) a session-targeted handoff ----
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "h-targeted"])
            .ok
    );
    let o = alice.vox(
        Some("a1"),
        &[
            "room",
            "handoff",
            r,
            "h-targeted",
            "--to",
            b_prefix,
            "--to-session",
            "b2",
        ],
    );
    assert!(o.ok, "{o:?}");
    wait_state(
        bob,
        r,
        "bob to see the targeted handoff",
        "h-targeted",
        |x| x.is_some_and(|x| x["state"] == "pending" && x["to_session"] == "b2"),
    );
    let o = bob.vox(Some("b1"), &["room", "claim", r, "h-targeted"]);
    assert_eq!(
        o.code,
        Some(1),
        "the other session of the recipient harness must not complete it: {o:?}"
    );
    let o = bob.vox(Some("b1"), &["room", "decline", r, "h-targeted"]);
    assert_eq!(o.code, Some(1), "…nor decline it: {o:?}");
    let o = bob.vox(Some("b2"), &["room", "claim", r, "h-targeted"]);
    assert!(o.ok && o.stdout.contains("you hold h-targeted"), "{o:?}");

    // ---- (4) a decline frees; it does not return to the sender ----
    assert!(alice.vox(Some("a1"), &["room", "claim", r, "h-decline"]).ok);
    assert!(
        alice
            .vox(
                Some("a1"),
                &["room", "handoff", r, "h-decline", "--to", b_prefix]
            )
            .ok
    );
    wait_state(
        bob,
        r,
        "bob to see the handoff to decline",
        "h-decline",
        |x| x.is_some_and(|x| x["state"] == "pending"),
    );
    let o = bob.vox(Some("b1"), &["room", "decline", r, "h-decline"]);
    assert!(o.ok && o.stdout.contains("it is free"), "{o:?}");
    let b = wait_state(alice, r, "alice to see the decline", "h-decline", |x| {
        x.is_none()
    });
    assert!(
        resource(&b, "h-decline").is_none(),
        "a declined item must be free, NOT back with the sender"
    );
    let o = alice.vox(Some("a2"), &["room", "claim", r, "h-decline"]);
    assert!(
        o.ok && o.stdout.contains("you hold h-decline"),
        "a fresh claim by a third session: {o:?}"
    );

    // ---- (5) a no-TTL claim's handoff still lapses ----
    assert!(
        alice.vox(Some("a1"), &["room", "claim", r, "h-expiry"]).ok,
        "a claim with no --ttl"
    );
    assert!(
        alice
            .vox(
                Some("a1"),
                &["room", "handoff", r, "h-expiry", "--to", b_prefix, "--ttl", "3"]
            )
            .ok
    );
    wait_state(bob, r, "bob to see the short handoff", "h-expiry", |x| {
        x.is_some_and(|x| x["state"] == "pending")
    });
    std::thread::sleep(std::time::Duration::from_secs(4));
    for w in [alice, bob] {
        let b = board(w, None, r);
        assert!(
            resource(&b, "h-expiry").is_none(),
            "{}: the handoff's own deadline must free it: {b}",
            w.name
        );
    }

    // ---- every node computed the same state ----
    // Both nodes must have seen every operation before their boards can be compared.
    let last = board(alice, None, r)["position"]["entries"].clone();
    until(
        bob,
        None,
        "bob to hold as many entries as alice",
        &["room", "board", r, "--json"],
        |o: &Out| o.ok && o.json()["position"]["entries"] == last,
    );
    let boards: Vec<serde_json::Value> = [alice, bob]
        .iter()
        .map(|w| agreed(&board(w, None, r)))
        .collect();
    assert_eq!(boards[0], boards[1], "alice and bob fold different boards");
    eprintln!(
        "[proof] identical folded boards on two nodes: {}",
        boards[0]
    );
}
