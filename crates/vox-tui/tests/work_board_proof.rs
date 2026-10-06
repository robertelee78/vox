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
//! 6. **Each member's lane state** (ADR-028 W-3, #512), on the other's `vox room board`: bob,
//!    holding claims and posting `working`, is "working" to alice; alice posting `working` with
//!    nothing held is "ready" to bob, not working; alice's `ask` to bob makes her "needs you" to
//!    him until he answers it with `--re`. Mutation: "working" derived without a claim turns it
//!    red at alice's `working` post (she reads "working" to bob).
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

/// The lane state `vox room board` printed for the member named `name`, from its `lanes:` block.
fn lane_of(board: &str, name: &str) -> Option<String> {
    board
        .lines()
        .skip_while(|l| *l != "lanes:")
        .skip(1)
        .find_map(|l| {
            let (who, state) = l.trim_start().split_once('\t')?;
            (who == name).then(|| state.to_owned())
        })
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

    // ---- (6) each member's lane state (ADR-028 W-3) ----
    // Bob holds port-the-codec and flaky-test; he says he is working on them.
    let (ok, _, err) = vox(
        bob,
        &["room", "post", &room, "--type", "working", "porting"],
    );
    assert!(ok, "PRODUCT (staging): bob's `working` post failed: {err}");
    let seen = until(
        alice,
        Some("alice"),
        "bob's lane to read working",
        &["room", "board", &room],
        |o| lane_of(&o.stdout, &bob.name).as_deref() == Some("working"),
    );
    println!(
        "[proof] alice's board, bob holding claims and working:\n{}",
        seen.stdout
    );
    // Alice holds nothing, and posts `working` all the same: that is no claim, so she is ready.
    let (ok, _, err) = vox(
        alice,
        &["room", "post", &room, "--type", "working", "looking"],
    );
    assert!(
        ok,
        "PRODUCT (staging): alice's `working` post failed: {err}"
    );
    let (ok, asked, err) = vox(
        alice,
        &[
            "room",
            "post",
            &room,
            "--type",
            "ask",
            "--to",
            &bob.b32(),
            "--json",
            "which codec?",
        ],
    );
    assert!(ok, "PRODUCT (staging): alice's `ask` to bob failed: {err}");
    let asked: serde_json::Value = serde_json::from_str(asked.trim()).unwrap_or_else(|e| {
        panic!("PRODUCT: `vox room post --json` printed no JSON ({e}): {asked}")
    });
    let entry = asked["entry_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: `vox room post --json` named no entry: {asked}"))
        .to_owned();
    // Her `working` came before the ask on her own chain, so a board with the ask has it too.
    let seen = until(
        bob,
        Some("bob"),
        "alice's unanswered ask to make her lane \"needs you\" on bob's board",
        &["room", "board", &room],
        |o| lane_of(&o.stdout, &alice.name).as_deref() == Some("needs you"),
    );
    println!(
        "[proof] bob's board, alice's ask unanswered:\n{}",
        seen.stdout
    );
    // Bob answers it: she no longer needs him, and her `working` without a claim is no work.
    let (ok, _, err) = vox(
        bob,
        &[
            "room",
            "post",
            &room,
            "--type",
            "answer",
            "--re",
            &entry,
            "the new one",
        ],
    );
    assert!(ok, "PRODUCT (staging): bob's answer failed: {err}");
    let board = vox(bob, &["room", "board", &room]).1;
    let lane = lane_of(&board, &alice.name);
    assert_eq!(
        lane.as_deref(),
        Some("ready"),
        "PRODUCT: alice holds no claim, so her `working` post is no work, and bob answered her \
         ask: her lane on his board must read \"ready\"; it said {lane:?}:\n{board}"
    );
    println!(
        "[proof] lanes: bob working to alice; alice needs you to bob until answered, then ready"
    );
}
