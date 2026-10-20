//! ADR-021 M21.1 — **workers must run the same Vox version, enforced**, through the
//! shipped `vox` binary with the stamps other versions write.
//!
//! Mixed-version coordination is not supported: the operator upgrades every worker
//! together. What must therefore be proved is not compatibility but **refusal** — a
//! worker that would coordinate with another version announces itself, then stops
//! before posting its claim or work message, and says exactly who and what:
//!
//! 1. **missing** — a claim with no version stamp, as every release before ADR-021 wrote
//!    it. A current worker that has **never posted in the room** then has its first
//!    `claim` refused with exit 3, naming that worker, "no version", and the required
//!    version — and the claim is never posted;
//! 2. **unknown** and **different** — a stamp that is not a version (`banana`) and one
//!    that is another version (this build's patch + 1, `another_version`) are each
//!    refused and named;
//! 3. `post --work` is refused the same way, `board --json` says `refused` with the
//!    table, and the drain hook tells the session plainly;
//! 4. **plain conversation survives** a refusal, so the operator can still talk;
//! 6. **a session that only reads announces the vox it runs now** (#994): a reader session
//!    whose last stamp is another version re-announces on its next hook turn, without a
//!    claim, and coordination resumes; a session that never announced posts nothing; the
//!    refusal says that the stale worker re-announces on its next turn.
//! 5. **recovery needs nobody**: once the stale worker runs the current binary, its
//!    first participating verb announces the current version, and coordination
//!    resumes for everyone, including an existing session whose old matching hello
//!    was superseded by a different session's stamp or a `bye`.
//!
//! Every foreign stamp is written onto the control socket as exactly the envelope another
//! version writes, because this build cannot be made to *be* another version. The
//! missing stamp used to come from the real published v0.2.6, and it cannot any more,
//! either way it could be run:
//! - **its CLI against a current node** fails the handshake: the node speaks IPC protocol 7,
//!   and v0.2.6 speaks 5;
//! - **its own member node** can never deliver anything: since ADR-023 M23.2 the log entry
//!   has 12 fields where v0.2.6 writes 10, so every entry it writes is refused at decode
//!   (no compatibility, by design). Its claim would never reach alice, and the gate would
//!   measure the log format, not the version refusal.
//!
//! Every red names its side: `PRODUCT:` quotes what `vox` said, `CANNOT MEASURE:` is a
//! staging step that did not happen (a precondition), and `APPARATUS:` is the proof's own
//! fault (the runtime, its temporary directory).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{post_raw, until, Out, Worker};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A version that is valid and is **not** this build's: its patch number plus one. Hard-coded,
/// it stopped being different the day the tree was at that version: on 0.2.9 a hello stamped
/// "0.2.9" matches, coordination is rightly allowed, and the proof waited for a refusal that
/// could not come (CI 869d8f0).
fn another_version() -> String {
    let mut parts = VERSION.split('.').map(|p| {
        p.parse::<u64>()
            .expect("APPARATUS: this build's version is not numeric")
    });
    let mut next = || {
        parts
            .next()
            .unwrap_or_else(|| panic!("APPARATUS: this build's version {VERSION} is not x.y.z"))
    };
    let (major, minor, patch) = (next(), next(), next());
    format!("{major}.{minor}.{}", patch + 1)
}

/// How a refusal names a worker's last announcement, without claiming which binary is running.
/// Matched as that phrase, never as the bare stamp: every
/// refusal also says `required <this version>`, so a bare "0.2.9" matched any refusal on a 0.2.9
/// tree, and the proof passed on a stale one without testing the version at all.
fn announced(stamp: &str, is_version: bool) -> String {
    if is_version {
        format!("last announced vox {stamp}")
    } else {
        format!("last announced vox {stamp:?}")
    }
}

fn refused_naming(o: &Out, who: &Worker, what: &str) {
    assert_eq!(
        o.code,
        Some(3),
        "PRODUCT: a version refusal must exit 3: {o:?}"
    );
    // The reader names the worker by its own name for it, the one `vox trust
    // add --name` gave (V210-162), not by a fingerprint prefix.
    for needle in [
        &format!("worker {} session", who.name),
        what,
        " at ",
        &format!("required {VERSION}"),
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
fn a_worker_on_another_version_is_refused_by_name() {
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
    // Registration is a precondition here; this journey measures version recovery.
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

    // ---- (1) missing: a pre-ADR-021 claim, and a fresh current worker is refused ----
    // Exactly what a release before ADR-021 wrote for `vox room claim`: no `data.vox`.
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
            o.ok && o
                .ndjson()
                .iter()
                .any(|x| x["envelope"]["type"] == "claim" && x["envelope"]["data"]["vox"].is_null())
        },
    );
    let unstamped = seen
        .ndjson()
        .iter()
        .filter(|x| {
            x["author"] == bob.b32()
                && x["envelope"]["type"] == "claim"
                && x["envelope"]["data"]["vox"].is_null()
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
    refused_naming(&o, bob, "no version");
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
    refused_naming(&o, bob, "no version");
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
    let other = another_version();
    for (stamp, named) in [
        ("banana".to_owned(), announced("banana", false)),
        (other.clone(), announced(&other, true)),
    ] {
        let hello = serde_json::json!({
            "v": 1, "type": "hello", "from": "b-foreign", "body": "a foreign worker",
            "data": { "vox": &stamp, "op": format!("op-foreign-{}", stamp.replace('.', "-")) }
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
    // Alice's a1 is stale even though a-second most recently announced the current version;
    // bob's b1 is current, but another session of his node most recently announced an old one.
    for (worker, reader, session, stamp) in [
        (alice, bob, "a1", other.as_str()),
        (alice, bob, "a-second", VERSION),
        (bob, alice, "b-previous", other.as_str()),
    ] {
        let hello = serde_json::json!({
            "v": 1, "type": "hello", "from": session, "body": "a later announcement",
            "data": { "vox": stamp, "op": format!("op-later-{session}") }
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
        |o| participant_is(o, alice, "a1", VERSION),
    );
    let o = bob.vox(Some("b1"), &working);
    assert!(o.ok, "PRODUCT: bob's resumed work post was refused: {o:?}");
    // A working post does not count as a version announcement. Using a claim here would
    // conceal a missing hello, since the claim itself carries the current version.
    until(
        alice,
        None,
        "bob's existing b1 session to replace his later foreign announcement",
        &["room", "board", r, "--json"],
        |o| participant_is(o, bob, "b1", VERSION),
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
        |o| participant_is(o, bob, "b1", VERSION),
    );

    // ---- (6) a session that only reads announces the vox it runs now (#994) ----
    // Bob's session b-reader announced another version before an update and has only read
    // since. Found 2026-10-20: such a session kept its old stamp for a day after both Macs
    // updated, and every worker in the room was refused, including the ones that were current.
    let stale = serde_json::json!({
        "v": 1, "type": "hello", "from": "b-reader", "body": "a reader's old announcement",
        "data": { "vox": other.as_str(), "op": "op-reader-old" }
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
        o.stderr
            .contains("announces the version it runs on its next turn")
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
        "bob's reader session to announce the current version from its hook turn",
        &["room", "board", r, "--json"],
        |o| participant_is(o, bob, "b-reader", VERSION),
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
        bobs["session"] == "b-reader" && bobs["version"] == VERSION,
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
}
