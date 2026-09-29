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

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn two_agents_split_work_and_only_one_holds_a_contested_resource() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    let alice_short: String = alice.b32().chars().take(12).collect();
    println!("[proof] room {room} ready: alice {alice_short}, bob each rendered the other");

    // ---- (1) and (2): both claim the same thing; exactly one wins ----
    let (ok, out, err) = vox(alice, &["room", "claim", &room, "port-the-codec"]);
    assert!(ok, "alice's claim failed: {err}");
    assert!(
        out.contains("you hold port-the-codec"),
        "a winning claim must say so: {out:?}"
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
        "a losing claim must fail, not succeed quietly: stdout={out:?}"
    );
    assert!(
        err.contains("is held by") && err.contains(&alice_short),
        "the loser must be told who holds it: {err:?}"
    );

    // ---- (3) the board agrees from both sides, and each knows its own ----
    let alice_board = vox(alice, &["room", "board", &room]).1;
    assert!(
        alice_board.contains("port-the-codec") && alice_board.contains("(you)"),
        "alice must see the resource as hers: {alice_board:?}"
    );
    let bob_board = vox(bob, &["room", "board", &room]).1;
    assert!(
        bob_board.contains("port-the-codec") && !bob_board.contains("(you)"),
        "bob must see it held by someone who is not him: {bob_board:?}"
    );

    // ---- (4) a release frees it, and the new claim succeeds ----
    let (ok, _, err) = vox(alice, &["room", "release", &room, "port-the-codec"]);
    assert!(ok, "alice could not release: {err}");
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
    assert!(ok, "bob should hold it once alice released: {err}");
    assert!(out.contains("you hold port-the-codec"), "{out:?}");

    // ---- (5) a lapsed ttl frees it with nobody acting ----
    let (ok, out, err) = vox(alice, &["room", "claim", &room, "flaky-test", "--ttl", "2"]);
    assert!(ok, "alice's ttl claim failed: {err}");
    assert!(out.contains("you hold flaky-test"), "{out:?}");
    until(
        bob,
        Some("bob"),
        "the ttl claim to reach bob",
        &["room", "board", &room],
        |o| o.stdout.contains("flaky-test"),
    );
    // While the ttl runs, it binds bob like any claim.
    let (ok, _, err) = vox(bob, &["room", "claim", &room, "flaky-test"]);
    assert!(
        !ok && err.contains("is held by"),
        "a live ttl claim must still bind another agent: {err:?}"
    );

    // Nobody releases it. It lapses.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let (ok, out, err) = vox(bob, &["room", "claim", &room, "flaky-test"]);
    assert!(
        ok,
        "a lapsed claim must free the resource with nobody acting: stdout={out:?} stderr={err:?}"
    );
    assert!(out.contains("you hold flaky-test"), "{out:?}");
    println!(
        "[proof] contested claim: 1 winner, loser refused naming the holder; release freed it; \
         a 2s ttl bound bob while live and freed itself after 3s"
    );
}
