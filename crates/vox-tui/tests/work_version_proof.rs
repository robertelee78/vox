//! ADR-052 RG-10: coordination uses claim rules, not package versions.
//!
//! The shipped binary refuses incompatible participants by name without posting work,
//! keeps conversation usable, and recovers on participation, after bye, and on a
//! read-only session's next hook turn (#994). Explicit other rules are ignored in the
//! board; the exact v0.4.30 package-only claim remains held.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{post_raw, resource, until, Out, Worker};

const RULES: &str = vox_agentcomms::version::CLAIM_RULES;

fn another_rules_number() -> String {
    (RULES
        .parse::<u32>()
        .expect("APPARATUS: decimal claim rules")
        + 1)
    .to_string()
}

/// How a refusal names a worker's last announcement, without claiming which binary is running.
/// Matched as a phrase, never as the bare stamp: every
/// refusal also names the required rules, so matching a bare number cannot prove which
/// participant stamp caused the refusal.
fn announced(stamp: &str, is_version: bool) -> String {
    if is_version {
        format!("last announced claim rules {stamp}")
    } else {
        format!("last announced claim rules {stamp:?}")
    }
}

fn refused_naming(o: &Out, who: &Worker, what: &str) {
    assert_eq!(
        o.code,
        Some(3),
        "PRODUCT: a claim-rules refusal must exit 3: {o:?}"
    );
    // The reader names the worker by its own name for it, the one `vox trust
    // add --name` gave (V210-162), not by a fingerprint prefix.
    for needle in [
        &format!("worker {} session", who.name),
        what,
        " at ",
        &format!("required {RULES}"),
    ] {
        assert!(
            o.stderr.contains(needle),
            "PRODUCT: the refusal must name {needle:?}: {}",
            o.stderr
        );
    }
}

fn participant_is(o: &Out, who: &Worker, session: &str, version: &str) -> bool {
    o.ok && o.json()["participants"].as_array().is_some_and(|ps| {
        ps.iter()
            .any(|p| p["author"] == who.b32() && p["session"] == session && p["version"] == version)
    })
}

fn claims_by(w: &Worker, reader: &Worker, r: &str) -> usize {
    let o = reader.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "PRODUCT: `vox room read --json` failed: {o:?}");
    o.ndjson()
        .iter()
        .filter(|x| x["author"] == w.b32() && x["envelope"]["type"] == "claim")
        .count()
}

#[test]
#[ignore = "on-demand proof with two networked nodes and production Argon2id; run in release"]
fn claims_use_their_rules_and_keep_the_v0430_package_stamp() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot build the runtime: {e}"));
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: tempdir: {e}"));
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // A harness's sending session must be registered before it can post (RA-3).
    // Stage through the same public hook used by the harness, with no real wake endpoint.
    // Registration is a precondition here; this journey measures claim-rules recovery.
    for (worker, session) in [(alice, "a1"), (bob, "b1")] {
        let hook = worker.vox(
            None,
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
        let doctor = worker.vox(None, &["agent", "doctor", "--node", "default", "--json"]);
        let report: serde_json::Value = serde_json::from_str(&doctor.stdout).unwrap_or_else(|_| {
            panic!("APPARATUS: session staging report unavailable: {doctor:?}")
        });
        assert!(
            hook.ok && report["checks"].as_array().is_some_and(|checks| checks
                .iter()
                .any(|check| check["check"] == format!("session {session}"))),
            "APPARATUS: sending session {session} was not registered; hook={hook:?}; doctor={doctor:?}"
        );
    }

    // ---- (1) missing: an unstamped claim, and a fresh current worker is refused ----
    // Exactly what a release before ADR-021 wrote for `vox room claim`: no `data.claims`.
    let old_claim = serde_json::json!({
        "v": 1, "type": "claim", "from": "b-old", "body": "claiming old-work",
        "data": { "resource": "old-work" }
    })
    .to_string();
    rt.block_on(post_raw(bob, room.cid, &old_claim));
    let seen = until(
        alice,
        None,
        "the unstamped claim to reach alice",
        &["room", "read", r, "--json"],
        |o: &Out| {
            o.ok && o.ndjson().iter().any(|x| {
                x["envelope"]["type"] == "claim" && x["envelope"]["data"]["claims"].is_null()
            })
        },
    );
    let unstamped = seen
        .ndjson()
        .iter()
        .filter(|x| {
            x["author"] == bob.b32()
                && x["envelope"]["type"] == "claim"
                && x["envelope"]["data"]["claims"].is_null()
        })
        .count();
    eprintln!("[receipt] unstamped claims from bob that reached alice: {unstamped}");
    assert_eq!(
        unstamped, 1,
        "PRODUCT: exactly bob's unstamped claim must reach alice, and `vox room read --json` \
         shows {unstamped}"
    );
    eprintln!(
        "[receipt] alice's own claims before her first: {}",
        claims_by(alice, alice, r)
    );
    assert_eq!(
        claims_by(alice, alice, r),
        0,
        "PRODUCT: alice has never claimed, and `vox room read --json` shows a claim by her"
    );
    let o = alice.vox(Some("a1"), &["room", "claim", r, "new-work"]);
    refused_naming(&o, bob, "no claim-rules number");
    assert_eq!(
        claims_by(alice, alice, r),
        0,
        "PRODUCT: a refused claim must never be posted"
    );

    // ---- (3) post --work, board --json and the drain hook all refuse ----
    let o = alice.vox_in(
        Some("a1"),
        &[
            "room",
            "post",
            r,
            "--type",
            "working",
            "--work",
            "gh:IOMachines/repo-to-cve#1237",
            "-",
        ],
        Some("starting"),
    );
    refused_naming(&o, bob, "no claim-rules number");
    let b = alice
        .vox(Some("a1"), &["room", "board", r, "--json"])
        .json();
    assert_eq!(
        b["coordination"], "refused",
        "PRODUCT: board --json must say refused: {b}"
    );
    let p = b["participants"]
        .as_array()
        .and_then(|ps| ps.iter().find(|p| p["author"] == bob.b32()))
        .unwrap_or_else(|| panic!("PRODUCT: board --json has no participants row for bob: {b}"));
    assert_eq!(
        p["stamp"], "missing",
        "PRODUCT: board --json must say bob's stamp is missing: {b}"
    );
    let hook = alice.vox(
        Some("a1"),
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
            "a1",
        ],
    );
    assert!(
        hook.stdout.contains("work coordination refused")
            && hook
                .stdout
                .contains(&format!("worker {} session", bob.name)),
        "PRODUCT: the drain hook must say it plainly: {hook:?}"
    );

    // ---- (4) conversation survives ----
    let o = alice.vox(
        Some("a1"),
        &["room", "post", r, "who is still on the old vox?"],
    );
    assert!(
        o.ok,
        "PRODUCT: plain conversation was refused while coordination is: {o:?}"
    );
    // **And structured conversation**: a reply addressed to a member, urgent, is still
    // conversation — only `--work` takes part in coordination. A refusal that reached
    // every structured post stayed green while this checked only the plain form.
    let re = alice
        .vox(None, &["room", "read", r, "--json"])
        .ndjson()
        .last()
        .and_then(|x| x["entry_hash"].as_str().map(str::to_owned))
        .expect("APPARATUS: alice's own read shows no row to reply to");
    let o = alice.vox(
        Some("a1"),
        &[
            "room",
            "post",
            r,
            "--type",
            "say",
            "--to",
            "bob",
            "--urgent",
            "--re",
            &re,
            "please upgrade your vox",
        ],
    );
    assert!(
        o.ok,
        "PRODUCT: a structured non-work post (`--type say --to --urgent --re`) was refused \
         while coordination is: {o:?}"
    );

    // ---- (2) unknown, then different ----
    let other = another_rules_number();
    for (stamp, named) in [
        ("banana".to_owned(), announced("banana", false)),
        (other.clone(), announced(&other, true)),
    ] {
        let hello = serde_json::json!({
            "v": 1, "type": "hello", "from": "b-foreign", "body": "a foreign worker",
            "data": { "claims": &stamp, "op": format!("op-foreign-{}", stamp.replace('.', "-")) }
        })
        .to_string();
        rt.block_on(post_raw(bob, room.cid, &hello));
        let o = until(
            alice,
            Some("a1"),
            "alice to see the foreign stamp",
            &["room", "claim", r, "new-work"],
            |o: &Out| o.code == Some(3) && o.stderr.contains(&named),
        );
        refused_naming(&o, bob, &named);
    }

    // ---- (5) recovery: the stale worker runs the current binary ----
    let o = bob.vox(Some("b1"), &["room", "claim", r, "bob-work"]);
    assert!(
        o.ok && o.stdout.contains("you hold bob-work"),
        "PRODUCT: a current worker among current workers coordinates: {o:?}"
    );
    let o = until(
        alice,
        Some("a1"),
        "coordination to resume for alice",
        &["room", "claim", r, "new-work"],
        |o: &Out| o.ok,
    );
    assert!(
        o.stdout.contains("you hold new-work"),
        "PRODUCT: alice's claim after recovery must hold new-work: {o:?}"
    );
    let b = alice
        .vox(Some("a1"), &["room", "board", r, "--json"])
        .json();
    assert_eq!(
        b["coordination"], "ok",
        "PRODUCT: board --json must say ok once everyone is current: {b}"
    );

    // An existing session must refresh both its own and its author's latest stamp.
    // Alice's a1 is stale even though a-second most recently announced the current claim rules;
    // bob's b1 is current, but another session of his node most recently announced an old one.
    for (worker, reader, session, stamp) in [
        (alice, bob, "a1", other.as_str()),
        (alice, bob, "a-second", RULES),
        (bob, alice, "b-previous", other.as_str()),
    ] {
        let hello = serde_json::json!({
            "v": 1, "type": "hello", "from": session, "body": "a later announcement",
            "data": { "claims": stamp, "op": format!("op-later-{session}") }
        })
        .to_string();
        rt.block_on(post_raw(worker, room.cid, &hello));
        until(
            reader,
            None,
            "the peer board to show the superseding announcement",
            &["room", "board", r, "--json"],
            |o| participant_is(o, worker, session, stamp),
        );
    }
    let working = [
        "room",
        "post",
        r,
        "--type",
        "working",
        "--work",
        "gh:IOMachines/repo-to-cve#1237",
        "resuming work after an upgrade",
    ];
    let o = alice.vox(Some("a1"), &working);
    refused_naming(&o, bob, &announced(&other, true));
    // Even a refused verb announces its caller, without changing another worker's stamp.
    until(
        bob,
        None,
        "alice's existing a1 session to announce itself before refusal",
        &["room", "board", r, "--json"],
        |o| participant_is(o, alice, "a1", RULES),
    );
    let o = bob.vox(Some("b1"), &working);
    assert!(o.ok, "PRODUCT: bob's resumed work post was refused: {o:?}");
    // A working post does not count as a claim-rules announcement. Using a claim here would
    // conceal a missing hello, since the claim itself carries the current claim rules.
    until(
        alice,
        None,
        "bob's existing b1 session to replace his later foreign announcement",
        &["room", "board", r, "--json"],
        |o| participant_is(o, bob, "b1", RULES),
    );
    let o = alice.vox(Some("a1"), &["room", "claim", r, "resumed-work"]);
    assert!(
        o.ok && o.stdout.contains("you hold resumed-work"),
        "PRODUCT: current sessions must coordinate after refreshing their announcements: {o:?}"
    );

    // A bye supersedes a current hello too. Reusing b1 must make it visible again.
    let bye = serde_json::json!({
        "v": 1, "type": "bye", "from": "b1", "body": "leaving work"
    })
    .to_string();
    rt.block_on(post_raw(bob, room.cid, &bye));
    until(
        alice,
        None,
        "bob's bye to remove him from the participants",
        &["room", "board", r, "--json"],
        |o| {
            o.ok && o.json()["participants"]
                .as_array()
                .is_some_and(|ps| ps.iter().all(|p| p["author"] != bob.b32()))
        },
    );
    let o = bob.vox(Some("b1"), &working);
    assert!(o.ok, "PRODUCT: bob's return after bye was refused: {o:?}");
    until(
        alice,
        None,
        "bob's returning b1 session to announce itself after bye",
        &["room", "board", r, "--json"],
        |o| participant_is(o, bob, "b1", RULES),
    );

    // ---- (6) a session that only reads announces the vox it runs now (#994) ----
    // Bob's session b-reader announced other claim rules before an update and has only read
    // since. Found 2026-10-20: such a session kept its old stamp for a day after both Macs
    // updated, and every worker in the room was refused, including the ones that were current.
    let stale = serde_json::json!({
        "v": 1, "type": "hello", "from": "b-reader", "body": "a reader's old announcement",
        "data": { "claims": other.as_str(), "op": "op-reader-old" }
    })
    .to_string();
    rt.block_on(post_raw(bob, room.cid, &stale));
    let o = until(
        alice,
        Some("a1"),
        "alice's claim to be refused by bob's stale reader session",
        &["room", "claim", r, "reader-work"],
        |o: &Out| o.code == Some(3) && o.stderr.contains("b-reader"),
    );
    assert!(
        o.stderr.contains("let them announce on their next turn")
            && o.stderr.contains("older than a day no longer counts"),
        "PRODUCT: the refusal does not say that the stale worker re-announces on its next turn \
         and that an old announcement lapses (#994): {o:?}"
    );
    // The reader's next hook turn, which only reads: it re-announces, without a claim.
    let hook = bob.vox(
        Some("b-reader"),
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
            "b-reader",
        ],
    );
    assert!(
        hook.code == Some(0),
        "PRODUCT: the reader's hook turn failed: {hook:?}"
    );
    until(
        alice,
        None,
        "bob's reader session to announce the current claim rules from its hook turn",
        &["room", "board", r, "--json"],
        |o| participant_is(o, bob, "b-reader", RULES),
    );
    // A session that never announced stays silent: its hook turn posts no hello.
    let silent = bob.vox(
        Some("b-silent"),
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
            "b-silent",
        ],
    );
    assert!(
        silent.code == Some(0),
        "PRODUCT: a silent session's hook turn failed: {silent:?}"
    );
    // Bob's row names his latest counted session: still b-reader, so b-silent posted nothing.
    let board = alice
        .vox(Some("a1"), &["room", "board", r, "--json"])
        .json();
    let bobs = board["participants"]
        .as_array()
        .and_then(|ps| ps.iter().find(|p| p["author"] == bob.b32()))
        .unwrap_or_else(|| {
            panic!("PRODUCT: board --json has no participants row for bob: {board}")
        });
    assert!(
        bobs["session"] == "b-reader" && bobs["version"] == RULES,
        "PRODUCT: a session that never announced posted a hello from its hook turn (#994): bob's \
         latest counted session is {} at {}, not b-reader",
        bobs["session"],
        bobs["version"]
    );
    let o = alice.vox(Some("a1"), &["room", "claim", r, "reader-work"]);
    assert!(
        o.ok && o.stdout.contains("you hold reader-work"),
        "PRODUCT: coordination did not resume once the reader re-announced (#994): {o:?}"
    );

    // Explicit claim rules win; the exact v0.4.30 package-only claim is retained.
    for (item, operation, stamp) in [
        (
            "other-rules-work",
            "claim-other-rules",
            Some(other.as_str()),
        ),
        ("legacy-work", "claim-legacy-0430", None),
    ] {
        // An explicit rules stamp takes precedence over the old package-only stamp.
        let mut data = serde_json::json!({"resource": item, "op": operation, "vox": "0.4.30"});
        if let Some(stamp) = stamp {
            data["claims"] = stamp.into();
        }
        let envelope = serde_json::json!({
            "v": 1, "type": "claim", "from": "legacy-session", "body": item, "data": data
        });
        rt.block_on(post_raw(bob, room.cid, &envelope.to_string()));
        let received = until(
            alice,
            None,
            "the signed claim to reach the reader",
            &["room", "read", &room.id, "--json"],
            |out: &Out| {
                out.ok
                    && out
                        .ndjson()
                        .iter()
                        .any(|row| row["envelope"]["data"]["op"] == operation)
            },
        );
        println!("reader received {operation}: {}", received.stdout);
    }

    let board = alice.vox(None, &["room", "board", &room.id, "--json"]);
    println!("claim-rules board: {board:?}");
    assert!(
        board.ok,
        "PRODUCT: the claim-rules board was refused: {board:?}"
    );
    let board = board.json();
    assert!(
        resource(&board, "other-rules-work").is_none()
            && board["violations"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["outcome"]["other_version"] == "mismatched")),
        "PRODUCT: a claim under other claim rules must change nothing: {board}"
    );
    assert!(
        resource(&board, "legacy-work")
            .is_some_and(|row| row["state"] == "held" && row["owner_session"] == "legacy-session"),
        "PRODUCT: the v0.4.30 package-stamped claim must remain held: {board}"
    );
}

#[test]
#[ignore = "on-demand proof with two networked nodes and production Argon2id; run in release"]
fn legacy_claim_retry_survives_package_stamp_change() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: cannot build runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: cannot make scratch directory");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();
    support::register_sending_session(alice, r, "a1");

    let legacy = serde_json::json!({
        "v": 1, "type": "claim", "from": "a1", "body": "claiming",
        "data": {"resource": "legacy-retry", "op": "legacy-retry-01", "vox": "0.4.30"}
    });
    rt.block_on(post_raw(alice, room.cid, &legacy.to_string()));
    let before = until(
        bob,
        None,
        "the legacy claim to reach bob",
        &["room", "read", r, "--json"],
        |out| {
            out.ok
                && out
                    .ndjson()
                    .iter()
                    .any(|row| row["envelope"]["data"]["op"] == "legacy-retry-01")
        },
    );
    let original = before
        .ndjson()
        .iter()
        .find(|row| row["envelope"]["data"]["op"] == "legacy-retry-01")
        .and_then(|row| row["entry_hash"].as_str().map(str::to_owned))
        .expect("APPARATUS: the legacy claim has no entry hash");
    let retry = alice.vox(
        Some("a1"),
        &[
            "room",
            "claim",
            r,
            "legacy-retry",
            "--op",
            "legacy-retry-01",
            "--json",
        ],
    );
    assert!(
        retry.ok,
        "PRODUCT: retry of the v0.4.30 claim was refused: {retry:?}"
    );
    let result = retry.json();
    assert!(
        result["status"] == "already-posted" && result["entry_hash"] == original,
        "PRODUCT: retry must return the original claim without posting again: {retry:?}"
    );
    let read = alice.vox(None, &["room", "read", r, "--json"]);
    assert!(
        read.ok
            && read
                .ndjson()
                .iter()
                .filter(|row| row["envelope"]["data"]["op"] == "legacy-retry-01")
                .count()
                == 1,
        "PRODUCT: retry must leave exactly one claim: {read:?}"
    );

    // A concurrent retry may already have been posted before either lookup.
    let duplicate = serde_json::json!({
        "v": 1, "type": "claim", "from": "a1", "body": "claiming again",
        "data": {"resource": "legacy-retry", "op": "legacy-retry-01", "vox": "9.9.9", "claims": RULES}
    });
    rt.block_on(post_raw(alice, room.cid, &duplicate.to_string()));
    let board = until(
        bob,
        None,
        "the concurrent retry to reach bob",
        &["room", "read", r, "--json"],
        |out| {
            out.ok
                && out
                    .ndjson()
                    .iter()
                    .filter(|row| row["envelope"]["data"]["op"] == "legacy-retry-01")
                    .count()
                    == 2
        },
    );
    assert!(
        board
            .ndjson()
            .iter()
            .any(|row| row["op"]["id"] == "legacy-retry-01" && row["op"]["status"] == "duplicate"),
        "PRODUCT: matching retries must be marked duplicate, not conflicting: {board:?}"
    );
    let board = bob.vox(None, &["room", "board", r, "--json"]);
    assert!(
        board.ok
            && resource(&board.json(), "legacy-retry").is_some_and(|row| row["state"] == "held"),
        "PRODUCT: the matching retries must leave the claim held: {board:?}"
    );

    let foreign = serde_json::json!({
        "v": 1, "type": "claim", "from": "a1", "body": "foreign rules",
        "data": {"resource": "foreign-retry", "op": "foreign-retry-01", "vox": "0.4.30", "claims": another_rules_number()}
    });
    rt.block_on(post_raw(alice, room.cid, &foreign.to_string()));
    let read = alice.vox(None, &["room", "read", r, "--json"]);
    assert!(
        read.ok
            && read
                .ndjson()
                .iter()
                .any(|row| row["envelope"]["data"]["op"] == "foreign-retry-01"),
        "APPARATUS: foreign-rules claim not staged: {read:?}"
    );
    let refused = alice.vox(
        Some("a1"),
        &[
            "room",
            "claim",
            r,
            "foreign-retry",
            "--op",
            "foreign-retry-01",
            "--json",
        ],
    );
    assert!(
        refused.code == Some(4) && refused.stderr.contains("conflicts"),
        "PRODUCT: the same op under different claim rules must still be refused: {refused:?}"
    );
}
