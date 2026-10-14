//! ADR-020 §5 / M19.9 — **two agents splitting work**, driven as real binaries
//! against two real nodes.
//!
//! The decider's requirement is agents that "communicate **and split work loads**".
//! Communication was reachable from M19.4; splitting work was not. The whole claim
//! model has lived in `vox-agentcomms` since M19.3 — `ClaimOp`, the resolution
//! rules, the deterministic tie-break — and until M19.9 **nothing in the shipped
//! binary called any of it**. `resolve` was exercised only by its own gate, which
//! is precisely the kind of green that proves nothing about the product.
//!
//! So this drives the product. Two nodes, two identities, one room, and the `vox`
//! binary run as a separate process against each — because a claim is only useful
//! if a *different agent* is bound by it, and a single-node test cannot show that.
//!
//! **Every participant is the shipped binary** (`support/room.rs`): an anchor (`vox node`),
//! a `vox daemon` per agent, the room made with `vox room create|invite|join`, each agent
//! admitted with `vox trust add`, and the room ready only once each has rendered a post by
//! the other. Nothing in this process runs a node.
//!
//! **Mutation.** Let a claim take a resource somebody else already holds (the `Held` arm of
//! `ClaimOp::Claim` in `vox-agentcomms/src/claim.rs` answering `true`, i.e. last claim wins)
//! and this goes red at (2): bob's contested claim succeeds instead of failing.
//!
//! What it proves:
//!
//! 1. **Exactly one agent holds a contested resource.** Both claim it; the first
//!    wins; the winner is told it holds it.
//! 2. **The loser is told it lost, and fails.** Not a silent no-op — a non-zero
//!    exit and a message naming the holder. An agent that cannot tell "I got it"
//!    from "I did not" will start work someone else is already doing, which is the
//!    exact failure claims exist to prevent.
//! 3. **The board agrees from both sides**, and each agent can see which claims are
//!    its own — which is why `Frame::Hello` carries the client's fingerprint.
//! 4. **A release frees it**, and only the owner's release counts.
//! 5. **A lapsed `--ttl` frees it with nobody acting** — the property that stops a
//!    dead agent holding a resource forever.
//!
//! Real wall-clock time is used rather than a fixed test clock, because `--ttl`
//! expiry is compared against the *client's* clock and a node pinned to a fixed
//! instant would make every claim appear to be from the future.
//!
//! ## One thing this deliberately does NOT assert
//!
//! That a release leaves a resource **unowned** when another agent has already
//! posted a losing claim for it. It may not, and that is not a defect:
//! `created_secs` has one-second resolution, so a losing claim and the release that
//! follows it can carry the same timestamp, and §5's tie-break then orders them by
//! entry hash. Every node computes the *same* answer — that is what the tie-break
//! is for — but the answer is not causal within a second. The earlier claim may
//! sort after the release and acquire the resource.
//!
//! This was found by running this proof, which first asserted the causal outcome
//! and failed: bob was correctly told he had lost, and his board then showed him
//! holding it once alice released. Neither statement was wrong — "you did not get
//! it" was true when it was said — so what is asserted below is the property the
//! model actually guarantees: **after a release, the previous owner no longer
//! holds it, and a fresh claim succeeds.**

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{until, Worker};

/// `vox …` as this agent's one session, returning (ok, stdout, stderr).
fn vox(w: &Worker, args: &[&str]) -> (bool, String, String) {
    let o = w.vox(Some(&w.name), args);
    (o.ok, o.stdout, o.stderr)
}

/// The wall clock in milliseconds — the clock a `--ttl` is measured against.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the system clock is before 1970")
        .as_millis() as u64
}

/// How long `--ttl` gives the claim in (5). Bob must see it and be refused inside this,
/// on the same clock; a runner too slow for that reads CANNOT MEASURE, not PRODUCT.
const TTL_SECS: u64 = 5;

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn two_agents_split_work_and_only_one_holds_a_contested_resource() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: could not build the test's tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temp dir");
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    let alice_short: String = alice.b32().chars().take(12).collect();
    println!("[proof] room {room} ready: alice {alice_short}, bob each rendered the other");

    // ---- (1) and (2): both claim the same thing; exactly one wins ----
    let (ok, out, err) = vox(alice, &["room", "claim", &room, "port-the-codec"]);
    assert!(ok, "PRODUCT: alice's claim failed: {err}");
    assert!(
        out.contains("you hold port-the-codec"),
        "PRODUCT: a winning claim must say so: {out:?}"
    );

    // Bob must see alice's claim before his own can lose to it.
    until(
        bob,
        Some("bob"),
        "alice's claim to reach bob",
        &["room", "board", &room],
        |o| o.stdout.contains("port-the-codec"),
    );

    let (ok, out, err) = vox(bob, &["room", "claim", &room, "port-the-codec"]);
    assert!(
        !ok,
        "PRODUCT: a losing claim must fail, not succeed quietly: stdout={out:?}"
    );
    // Bob names alice by his own name for her, the one `vox trust add --name` gave (V210-162).
    assert!(
        err.contains(&format!("is held by {}/", alice.name)),
        "PRODUCT: the loser must be told who holds it, by its name for them: {err:?}"
    );

    // ---- (3) the board agrees from both sides, and each knows its own ----
    let alice_board = vox(alice, &["room", "board", &room]).1;
    assert!(
        alice_board.contains("port-the-codec") && alice_board.contains("(you)"),
        "PRODUCT: alice must see the resource as hers: {alice_board:?}"
    );
    let bob_board = vox(bob, &["room", "board", &room]).1;
    assert!(
        bob_board.contains("port-the-codec") && !bob_board.contains("(you)"),
        "PRODUCT: bob must see it held by someone who is not him: {bob_board:?}"
    );

    member_work_roundtrip(alice, bob, &room);

    // ---- (4) a release frees it, and the new claim succeeds ----
    let (ok, _, err) = vox(alice, &["room", "release", &room, "port-the-codec"]);
    assert!(ok, "PRODUCT: alice could not release: {err}");
    // What a release guarantees is that **the releaser stops holding it** — not
    // that the resource is unowned, because bob's earlier losing claim may sort
    // after the release and acquire it. See the header.
    until(
        bob,
        Some("bob"),
        "alice to stop holding the resource",
        &["room", "board", &room],
        |o| {
            !o.stdout
                .lines()
                .any(|l| l.starts_with("port-the-codec") && l.contains(&alice_short))
        },
    );
    let (ok, out, err) = vox(bob, &["room", "claim", &room, "port-the-codec"]);
    assert!(ok, "PRODUCT: bob should hold it once alice released: {err}");
    assert!(
        out.contains("you hold port-the-codec"),
        "PRODUCT: bob's claim must say he holds it: {out:?}"
    );

    // ---- (5) a lapsed ttl frees it with nobody acting ----
    // The expiry vox computed is read from its own answer, so every step below is timed
    // against the same clock the claim lapses on.
    let ttl = TTL_SECS.to_string();
    let o = alice.vox(
        Some(&alice.name),
        &[
            "room",
            "claim",
            &room,
            "flaky-test",
            "--ttl",
            &ttl,
            "--json",
        ],
    );
    assert!(o.ok, "PRODUCT: alice's ttl claim failed: {o:?}");
    let expires = o.json()["state"]["expires_millis"]
        .as_u64()
        .unwrap_or_else(|| panic!("PRODUCT: a --ttl claim must report its expiry: {o:?}"));
    // Bob must have the live claim before his own can be bound by it. Seeing it is
    // staging; if the claim lapses first, nothing about binding was tested.
    loop {
        let b = bob.vox(Some("bob"), &["room", "board", &room]);
        let seen = now_ms();
        if b.stdout.contains("flaky-test") {
            break;
        }
        assert!(
            seen < expires,
            "APPARATUS, CANNOT MEASURE: the {TTL_SECS} s ttl claim had lapsed ({} ms past its expiry) \
             before it reached bob's board, so whether a live ttl claim binds was never \
             tested; last board: {b:?}",
            seen - expires
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // While the ttl runs, it binds bob like any claim.
    let (ok, out, err) = vox(bob, &["room", "claim", &room, "flaky-test"]);
    let done = now_ms();
    if ok || !err.contains("is held by") {
        // Bob's claim started after he saw the live claim; it is a product red only if it
        // also finished before the claim lapsed.
        assert!(
            done >= expires,
            "PRODUCT: a live ttl claim did not bind bob, {} ms before it lapsed: \
             ok={ok} stdout={out:?} stderr={err:?}",
            expires - done
        );
        panic!(
            "APPARATUS, CANNOT MEASURE: bob's claim finished {} ms after the {TTL_SECS} s ttl lapsed, \
             so whether a live ttl claim binds was never tested: ok={ok} stderr={err:?}",
            done - expires
        );
    }

    // Nobody releases it. It lapses.
    let wait = expires.saturating_sub(now_ms()) + 1_000;
    std::thread::sleep(std::time::Duration::from_millis(wait));
    let (ok, out, err) = vox(bob, &["room", "claim", &room, "flaky-test"]);
    assert!(
        ok,
        "PRODUCT: a claim {} ms past its ttl still holds the resource with nobody acting: \
         stdout={out:?} stderr={err:?}",
        now_ms() - expires
    );
    assert!(
        out.contains("you hold flaky-test"),
        "PRODUCT: bob's claim must say he holds it: {out:?}"
    );
    println!(
        "[proof] contested claim: 1 winner, loser refused naming the holder; release freed it; \
         a {TTL_SECS}s ttl bound bob while live and freed itself once it lapsed"
    );
}

/// ADR-033 WD: this is also the narrow on-demand excerpt for the member-panel backend.
/// The daemon owns the fold; the native panel consumes the same Work rows through FFI.
/// Native rendering, plain non-link text and reopening are observed separately in the app.
fn member_work_roundtrip(alice: &Worker, bob: &Worker, room: &str) {
    const WORK: &str = "gwa:example/room:member-work";
    let claim = alice.vox(
        Some("alice"),
        &[
            "room", "claim", room, "--work", WORK, "--task", "#769", "--json",
        ],
    );
    claim.expect_ok("claim the member-panel work item");
    let claim_id = claim.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: claim has no hash")
        .to_owned();
    stage_work_row(
        bob,
        room,
        ReadableWorkRow {
            id: &claim_id,
            author: &alice.b32(),
            session: "alice",
            kind: "claim",
            body: &format!("claiming {WORK}"),
            re: None,
        },
    );
    let board = bob.vox(Some("bob"), &["room", "board", room, "--json"]);
    board.expect_ok("read the member work board");
    let json = board.json();
    let work = json["work"]
        .as_array()
        .expect("PRODUCT: board omitted its work rows");
    assert!(work.iter().any(|r| r["type"] == "claim" && r["member"] == alice.b32()
        && r["session"] == "alice" && r["work"] == WORK
        && r["tags"].as_array().is_some_and(|ts| ts.iter().any(|t| t == "task:#769"))),
        "PRODUCT: daemon board omitted the current member/Session claim, task or plain work reference: {board:?}");

    let ask = alice.vox(
        Some("alice"),
        &[
            "room", "post", room, "WD_ASK", "--type", "ask", "--to", "bob", "--work", WORK,
            "--json",
        ],
    );
    ask.expect_ok("address a work ask to bob");
    let ask_id = ask.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: posted ask has no hash")
        .to_owned();
    stage_work_row(
        bob,
        room,
        ReadableWorkRow {
            id: &ask_id,
            author: &alice.b32(),
            session: "alice",
            kind: "ask",
            body: "WD_ASK",
            re: None,
        },
    );
    let unread = bob.vox(Some("bob"), &["room", "board", room, "--json"]);
    unread.expect_ok("read the unanswered ask");
    assert!(
        unread.json()["work"]
            .as_array()
            .is_some_and(|rs| rs.iter().any(|r| r["type"] == "ask"
                && r["entry_hash"] == ask_id
                && r["member"] == bob.b32()
                && r["author"] == alice.b32()
                && r["from"] == "alice")),
        "PRODUCT: the addressed, unanswered ask is absent from bob's board: {unread:?}"
    );
    let unrelated = alice.vox(
        Some("alice"),
        &[
            "room",
            "post",
            room,
            "WD_SENDER_FOLLOWUP",
            "--re",
            &ask_id,
            "--json",
        ],
    );
    unrelated.expect_ok("post the asker's own follow-up");
    let still = alice.vox(Some("alice"), &["room", "board", room, "--json"]);
    still.expect_ok("read the ask after an unrelated responder");
    assert!(
        still.json()["work"]
            .as_array()
            .is_some_and(|rs| rs.iter().any(|r| r["entry_hash"] == ask_id)),
        "PRODUCT: the asker's own reply incorrectly answered bob's ask: {still:?}"
    );
    let answer = bob.vox(
        Some("bob"),
        &[
            "room",
            "post",
            room,
            "WD_ANSWER",
            "--type",
            "answer",
            "--re",
            &ask_id,
            "--json",
        ],
    );
    answer.expect_ok("bob answers the addressed ask");
    let answer_id = answer.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: answer has no hash")
        .to_owned();
    stage_work_row(
        alice,
        room,
        ReadableWorkRow {
            id: &answer_id,
            author: &bob.b32(),
            session: "bob",
            kind: "answer",
            body: "WD_ANSWER",
            re: Some(&ask_id),
        },
    );
    let answered = alice.vox(Some("alice"), &["room", "board", room, "--json"]);
    answered.expect_ok("read the answered work board");
    assert!(
        answered.json()["work"]
            .as_array()
            .is_some_and(|rs| !rs.iter().any(|r| r["entry_hash"] == ask_id)),
        "PRODUCT: bob's exact reply did not clear his addressed ask: {answered:?}"
    );

    let blocked = alice.vox(
        Some("alice"),
        &[
            "room",
            "post",
            room,
            "WD_BLOCKED",
            "--type",
            "blocked",
            "--work",
            WORK,
            "--data",
            "{\"reason\":\"waiting for the member response\"}",
            "--json",
        ],
    );
    blocked.expect_ok("publish the owner's blocked reason");
    let waiting = alice.vox(Some("alice"), &["room", "board", room, "--json"]);
    waiting.expect_ok("read the blocked work");
    assert!(
        waiting.json()["work"].as_array().is_some_and(|rs| rs
            .iter()
            .any(|r| r["type"] == "blocked" && r["work"] == WORK)),
        "PRODUCT: board omitted the owner's blocked work: {waiting:?}"
    );
    alice
        .vox(
            Some("alice"),
            &[
                "room",
                "post",
                room,
                "WD_WORKING",
                "--type",
                "working",
                "--work",
                WORK,
                "--json",
            ],
        )
        .expect_ok("publish the owner's resumed work");
    let resumed = alice.vox(Some("alice"), &["room", "board", room, "--json"]);
    resumed.expect_ok("read resumed work");
    assert!(
        resumed.json()["work"].as_array().is_some_and(|rs| !rs
            .iter()
            .any(|r| r["type"] == "blocked" && r["work"] == WORK)),
        "PRODUCT: owner's working post did not clear blocked work: {resumed:?}"
    );
    let handoff = alice.vox(
        Some("alice"),
        &[
            "room",
            "handoff",
            room,
            WORK,
            "--to",
            "bob",
            "--to-session",
            "bob",
            "--ttl",
            "600",
            "--json",
        ],
    );
    handoff.expect_ok("hand member-panel work to bob's exact Session");
    let handoff_json = handoff.json();
    let deadline = handoff_json["state"]["deadline_millis"]
        .as_u64()
        .expect("PRODUCT: handoff omitted its public deadline");
    let handoff_id = handoff_json["entry_hash"]
        .as_str()
        .expect("PRODUCT: handoff has no hash")
        .to_owned();
    stage_work_row(
        bob,
        room,
        ReadableWorkRow {
            id: &handoff_id,
            author: &alice.b32(),
            session: "alice",
            kind: "handoff",
            body: &format!("handing {WORK} to bob"),
            re: None,
        },
    );
    handoff_live(deadline);
    let pending = bob.vox(Some("bob"), &["room", "board", room, "--json"]);
    handoff_live(deadline);
    pending.expect_ok("read the pending handoff");
    assert!(pending.json()["work"].as_array().is_some_and(|rows| rows.iter().any(|r|
        r["type"] == "handoff" && r["entry_hash"] == handoff_id && r["member"] == bob.b32()
            && r["session"] == "bob" && r["author"] == alice.b32() && r["from"] == "alice"
            && r["resource"] == WORK)),
        "PRODUCT: pending handoff omitted the exact recipient or authenticated sender/Session: {pending:?}");
    handoff_live(deadline);
    let accepted = bob.vox(
        Some("bob"),
        &[
            "room", "claim", room, "--work", WORK, "--task", "#769", "--json",
        ],
    );
    handoff_live(deadline);
    accepted.expect_ok("bob accepts the exact handoff by claiming");
    let accepted_board = bob.vox(Some("bob"), &["room", "board", room, "--json"]);
    handoff_live(deadline);
    accepted_board.expect_ok("read the accepted handoff");
    let accepted_json = accepted_board.json();
    let accepted_work = accepted_json["work"]
        .as_array()
        .expect("PRODUCT: board omitted its work rows");
    assert!(accepted_work.iter().any(|r| r["type"] == "claim" && r["work"] == WORK && r["member"] == bob.b32()
        && r["session"] == "bob") && !accepted_work.iter().any(|r| r["entry_hash"] == handoff_id),
        "PRODUCT: handoff did not become bob's claim or remained pending after acceptance: {accepted_board:?}");
    bob.vox(Some("bob"), &["room", "release", room, WORK, "--json"])
        .expect_ok("release member-panel work");
    let fresh = bob.vox(Some("bob"), &["room", "board", room, "--json"]);
    fresh.expect_ok("reopen the work board after release");
    assert!(
        fresh.json()["work"]
            .as_array()
            .is_some_and(|rs| !rs.iter().any(|r| r["type"] == "claim" && r["work"] == WORK)),
        "PRODUCT: a fresh board retained the released claim: {fresh:?}"
    );
}

fn handoff_live(deadline: u64) {
    let observed = now_ms();
    assert!(
        observed < deadline,
        "APPARATUS: handoff lease expired before its non-TTL assertion; public deadline={deadline}, observed={observed}"
    );
}

/// The public row must be readable, not merely an owed hash or a parent reference.
struct ReadableWorkRow<'a> {
    id: &'a str,
    author: &'a str,
    session: &'a str,
    kind: &'a str,
    body: &'a str,
    re: Option<&'a str>,
}

fn stage_work_row(reader: &Worker, room: &str, expected: ReadableWorkRow<'_>) {
    let deadline = std::time::Instant::now() + support::TIMEOUT;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        let out = reader.vox(None, &["room", "read", room, "--json"]);
        println!("[work staging] {out:?}");
        if out.code.is_none() {
            panic!("APPARATUS: public-row staging command did not finish: {out:?}");
        }
        if !out.ok {
            let refreshing = out.code == Some(1)
                && out.stdout.is_empty()
                && matches!(
                    out.stderr.trim(),
                    "vox: room governance is refreshing; try again when it is ready"
                        | "vox: the room is refreshing saved history; retry"
                        | "vox: the room is removing expired saved history; retry"
                );
            assert!(
                refreshing,
                "PRODUCT: unexpected public staging-read refusal: {out:?}"
            );
        } else {
            for row in out.ndjson() {
                let env = &row["envelope"];
                if row["entry_hash"] == expected.id
                    && row["owed"].as_bool() == Some(false)
                    && row["author"] == expected.author
                    && env["from"] == expected.session
                    && env["type"] == expected.kind
                    && env["body"] == expected.body
                    && match expected.re {
                        Some(re) => env["re"] == re,
                        None => env["re"].is_null(),
                    }
                {
                    return;
                }
            }
        }
        last = Some(out);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("APPARATUS: exact readable {} row {} from {}/{} was not staged; no board consequence measured; last={last:?}",
        expected.kind, expected.id, expected.author, expected.session);
}
