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
//! 5. a handoff of a claim that had **no TTL** still lapses at its own deadline;
//! 6. **the same rows logged in different orders fold to the same board.** Each node logs
//!    its own post when it is made and a peer's when it arrives, so two claims of one item
//!    made while the nodes cannot reach each other sit in opposite local orders: bob's
//!    daemon is down while alice claims, then alice's and the anchor's (it holds the room's
//!    entries too) are stopped (SIGSTOP) while bob's restarts and bob claims, then all
//!    resume. Each claim is posted and
//!    told it is not agreed yet, since the other member cannot be reached (V210-168). The
//!    earlier claim must hold on both nodes. Precondition (else APPARATUS, CANNOT MEASURE): `room read
//!    --json` shows the two claims in different orders on the two nodes — without that,
//!    a fold in local order and the canonical fold give the same board.
//!
//! Cases 1–5 depend on no causal order between two authors: every step waits until the
//! node that acts next has *seen* what it acts on. That is also why they cannot catch a
//! fold that follows local order — both nodes log every row in the same order — and why
//! case 6 exists.
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
    assert!(o.ok, "PRODUCT: `vox room board` failed: {o:?}");
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

/// The wall clock in milliseconds — the clock a handoff's deadline is measured against.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the system clock is before 1970")
        .as_millis() as u64
}

fn held_by<'a>(fp: &'a str, session: &'a str) -> impl Fn(Option<&serde_json::Value>) -> bool + 'a {
    move |r| {
        r.is_some_and(|r| {
            r["state"] == "held" && r["owner_fp"] == fp && r["owner_session"] == session
        })
    }
}

/// Send `sig` to `pid`, the process `what` names.
fn signal(pid: u32, sig: &str, what: &str) {
    let sent = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        sent,
        "APPARATUS: CANNOT MEASURE (6): `kill {sig}` {what} failed"
    );
}

/// The claims of `r` in a `room read --json`, in that node's local order, as
/// `(entry_hash, author, created_millis)`.
fn claims_in_local_order(o: &Out, r: &str) -> Vec<(String, String, u64)> {
    o.ndjson()
        .iter()
        .filter(|row| {
            row["envelope"]["type"] == "claim" && row["envelope"]["data"]["resource"] == r
        })
        .map(|row| {
            (
                row["entry_hash"].as_str().unwrap_or_default().to_owned(),
                row["author"].as_str().unwrap_or_default().to_owned(),
                row["created_millis"].as_u64().unwrap_or_default(),
            )
        })
        .collect()
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn a_handoff_moves_ownership_by_fingerprint_and_every_node_agrees() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: could not build the test's tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temp dir");
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let room_id = room.id.clone();
    let r = room_id.as_str();
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
                w.pass.to_str().expect("APPARATUS: a non-UTF-8 temp path"),
            ],
        );
        assert!(
            o.ok,
            "PRODUCT: {} must be able to name its peer: {o:?}",
            w.name
        );
        let listed = w.vox(
            None,
            &[
                "trust",
                "list",
                "--identity-passphrase-file",
                w.pass.to_str().expect("APPARATUS: a non-UTF-8 temp path"),
            ],
        );
        assert!(
            listed.stdout.contains(name),
            "PRODUCT: {} must now call its peer {name:?}: {listed:?}",
            w.name
        );
    }

    // ---- (1) ownership is per session ----
    let o = bob.vox(Some("b1"), &["room", "claim", r, "own-1"]);
    assert!(
        o.ok && o.stdout.contains("you hold own-1"),
        "PRODUCT: bob/b1's claim must say it holds own-1: {o:?}"
    );
    let o = bob.vox(Some("b2"), &["room", "claim", r, "own-1"]);
    assert_eq!(
        o.code,
        Some(1),
        "PRODUCT: a second session of the same harness must LOSE, not share: {o:?}"
    );
    assert!(
        o.stderr.contains("held by") && o.stderr.contains("/b1"),
        "PRODUCT: the losing session must be told bob/b1 holds it: {o:?}"
    );
    let o = bob.vox(Some("b2"), &["room", "release", r, "own-1"]);
    assert_eq!(
        o.code,
        Some(1),
        "PRODUCT: another session's release must have no effect, and say so: {o:?}"
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
    assert!(o.ok, "PRODUCT: alice/a1 could not claim h-any: {o:?}");
    let o = alice.vox(
        Some("a1"),
        &["room", "handoff", r, "h-any", "--to", b_prefix],
    );
    assert!(
        o.ok && o.stdout.contains("reserved for"),
        "PRODUCT: a handoff must say whom it reserves the item for: {o:?}"
    );
    for w in [alice, bob] {
        let b = wait_state(w, r, "the pending handoff everywhere", "h-any", |x| {
            x.is_some_and(|x| x["state"] == "pending" && x["to_fp"] == b_fp && x["from_fp"] == a_fp)
        });
        assert!(
            resource(&b, "h-any").is_some_and(|x| x["owner_fp"].is_null()),
            "PRODUCT: {}: a pending handoff must name no owner: {b}",
            w.name
        );
    }
    let o = alice.vox(Some("a2"), &["room", "claim", r, "h-any"]);
    assert_eq!(
        o.code,
        Some(1),
        "PRODUCT: a non-recipient must not take a reserved item: {o:?}"
    );
    let o = bob.vox(Some("b2"), &["room", "claim", r, "h-any"]);
    assert!(
        o.ok && o.stdout.contains("you hold h-any"),
        "PRODUCT: the recipient's claim completes it: {o:?}"
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
        "PRODUCT: the sender relinquished it; its release must change nothing: {o:?}"
    );

    // ---- (3) a session-targeted handoff ----
    let o = alice.vox(Some("a1"), &["room", "claim", r, "h-targeted"]);
    assert!(o.ok, "PRODUCT: alice/a1 could not claim h-targeted: {o:?}");
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
    assert!(o.ok, "PRODUCT: the session-targeted handoff failed: {o:?}");
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
        "PRODUCT: the other session of the recipient harness must not complete it: {o:?}"
    );
    let o = bob.vox(Some("b1"), &["room", "decline", r, "h-targeted"]);
    assert_eq!(o.code, Some(1), "PRODUCT: …nor decline it: {o:?}");
    let o = bob.vox(Some("b2"), &["room", "claim", r, "h-targeted"]);
    assert!(
        o.ok && o.stdout.contains("you hold h-targeted"),
        "PRODUCT: the named session's claim must complete the handoff: {o:?}"
    );

    // ---- (4) a decline frees; it does not return to the sender ----
    let o = alice.vox(Some("a1"), &["room", "claim", r, "h-decline"]);
    assert!(o.ok, "PRODUCT: alice/a1 could not claim h-decline: {o:?}");
    let o = alice.vox(
        Some("a1"),
        &["room", "handoff", r, "h-decline", "--to", b_prefix],
    );
    assert!(o.ok, "PRODUCT: the handoff of h-decline failed: {o:?}");
    wait_state(
        bob,
        r,
        "bob to see the handoff to decline",
        "h-decline",
        |x| x.is_some_and(|x| x["state"] == "pending"),
    );
    let o = bob.vox(Some("b1"), &["room", "decline", r, "h-decline"]);
    assert!(
        o.ok && o.stdout.contains("it is free"),
        "PRODUCT: a decline must say the item is free: {o:?}"
    );
    let b = wait_state(alice, r, "alice to see the decline", "h-decline", |x| {
        x.is_none()
    });
    assert!(
        resource(&b, "h-decline").is_none(),
        "PRODUCT: a declined item must be free, NOT back with the sender: {b}"
    );
    let o = alice.vox(Some("a2"), &["room", "claim", r, "h-decline"]);
    assert!(
        o.ok && o.stdout.contains("you hold h-decline"),
        "PRODUCT: a fresh claim by a third session must take the declined item: {o:?}"
    );

    // ---- (5) a no-TTL claim's handoff still lapses ----
    let o = alice.vox(Some("a1"), &["room", "claim", r, "h-expiry"]);
    assert!(o.ok, "PRODUCT: a claim with no --ttl failed: {o:?}");
    // The deadline is read from vox's own answer, so the lapse is checked against the
    // clock it is computed on — not against a sleep that a slow runner can outlast.
    let o = alice.vox(
        Some("a1"),
        &[
            "room", "handoff", r, "h-expiry", "--to", b_prefix, "--ttl", "3", "--json",
        ],
    );
    assert!(o.ok, "PRODUCT: the handoff with --ttl 3 failed: {o:?}");
    let state = &o.json()["state"];
    assert!(
        state["state"] == "pending",
        "PRODUCT: a handoff of a no-TTL claim must be pending on the sender's node: {o:?}"
    );
    let deadline = state["deadline_millis"]
        .as_u64()
        .unwrap_or_else(|| panic!("PRODUCT: a --ttl handoff must report its deadline: {o:?}"));
    // Bob has the handoff once he holds every entry alice does. That does not race the
    // deadline: a lapsed handoff is still an entry in his log.
    let entries = board(alice, None, r)["position"]["entries"].clone();
    until(
        bob,
        None,
        "bob to hold the handoff entry",
        &["room", "board", r, "--json"],
        |o: &Out| o.ok && o.json()["position"]["entries"] == entries,
    );
    std::thread::sleep(std::time::Duration::from_millis(
        deadline.saturating_sub(now_ms()) + 1_000,
    ));
    for w in [alice, bob] {
        let b = board(w, None, r);
        assert!(
            resource(&b, "h-expiry").is_none(),
            "PRODUCT: {}: {} ms past the handoff's own deadline it still has not freed the \
             item: {b}",
            w.name,
            now_ms() - deadline
        );
    }

    // ---- (6) the same claims, logged in opposite orders, fold to one board ----
    // Bob's daemon is **down**, not frozen, while alice claims: since a claim asks every member
    // to agree (V210-168), alice sends it to bob at once, and a frozen bob found it waiting in
    // his socket when he resumed and logged it before his own, so both orders were the same.
    let alice_d = alice
        .daemon_pid()
        .expect("APPARATUS: the harness has no pid for alice's daemon");
    let anchor_d = room.anchor_pid();
    room.stop(1);
    let alice = &room.workers[0];
    let first = alice.vox(Some("a1"), &["room", "claim", r, "h-order"]);
    // The anchor holds the room's entries too, and would serve bob alice's claim.
    signal(alice_d, "-STOP", "alice's daemon");
    signal(anchor_d, "-STOP", "the anchor");
    room.restart(1);
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let second = bob.vox(Some("b1"), &["room", "claim", r, "h-order"]);
    signal(alice_d, "-CONT", "alice's daemon");
    signal(anchor_d, "-CONT", "the anchor");
    // Bob is stopped, so alice's claim cannot be agreed: it is posted, and she is told it is not
    // sure to be hers rather than "you hold" (V210-168: a member who cannot be reached is said,
    // never answered as success). Posted is what this case needs: the fold below orders it.
    assert!(
        first.code == Some(5)
            && first.stderr.contains("h-order is not agreed yet")
            && first.stderr.contains("could not be reached")
            && first.stderr.contains("Your claim is posted"),
        "PRODUCT: alice/a1's claim of h-order, made while bob's daemon was stopped, must be posted \
         and answered \"not agreed yet\" (exit 5) naming the member it could not reach: {first:?}"
    );
    let orders: Vec<Vec<(String, String, u64)>> = [alice, bob]
        .iter()
        .map(|w| {
            let o = until(
                w,
                None,
                &format!("{} to log both claims of h-order", w.name),
                &["room", "read", r, "--json"],
                |o: &Out| o.ok && claims_in_local_order(o, "h-order").len() == 2,
            );
            claims_in_local_order(&o, "h-order")
        })
        .collect();
    let hashes = |v: &[(String, String, u64)]| v.iter().map(|c| c.0.clone()).collect::<Vec<_>>();
    eprintln!(
        "[proof] (6) local order of the h-order claims: alice {:?}, bob {:?}; bob's claim said: {}{}",
        hashes(&orders[0]),
        hashes(&orders[1]),
        second.stdout.trim(),
        second.stderr.trim()
    );
    assert!(
        hashes(&orders[0]) != hashes(&orders[1]),
        "APPARATUS: CANNOT MEASURE (6): both nodes logged the two claims of h-order in the \
         same order {:?} (bob had alice's claim before he made his), so this case cannot tell \
         a canonical fold from one in local order",
        orders[0]
    );
    let by = |author: &str| orders[0].iter().find(|c| c.1 == author).map(|c| c.2);
    assert!(
        matches!((by(&a_fp), by(&b_fp)), (Some(a), Some(b)) if a < b),
        "APPARATUS: CANNOT MEASURE (6): the two claims are not alice's then bob's, \
         stamped in that order: {:?}",
        orders[0]
    );
    let held: Vec<serde_json::Value> = [alice, bob]
        .iter()
        .map(|w| {
            resource(&board(w, None, r), "h-order")
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(
        held[0], held[1],
        "PRODUCT: alice and bob fold different boards for h-order from the same two claims, \
         logged in different orders"
    );
    assert!(
        held_by(&a_fp, "a1")(Some(&held[0])),
        "PRODUCT: the earlier claim (alice/a1) must hold h-order on every node; both say {}",
        held[0]
    );
    eprintln!(
        "[proof] (6) identical h-order on two nodes from opposite local orders: {}",
        held[0]
    );

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
    assert_eq!(
        boards[0], boards[1],
        "PRODUCT: alice and bob fold different boards"
    );
    eprintln!(
        "[proof] identical folded boards on two nodes: {}",
        boards[0]
    );
}
