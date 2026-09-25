//! ADR-021 M21.1 — **workers must run the same Vox version, enforced**, through the
//! shipped `vox` binary with the stamps other versions write.
//!
//! Mixed-version coordination is not supported: the operator upgrades every worker
//! together. What must therefore be proved is not compatibility but **refusal** — a
//! worker that would coordinate with another version stops, before it posts anything
//! that participates, and says exactly who and what:
//!
//! 1. **missing** — a claim with no version stamp, as every release before ADR-021 wrote
//!    it. A current worker that has **never posted in the room** then has its first
//!    `claim` refused with exit 3, naming that worker, "no version", and the required
//!    version — and the claim is never posted;
//! 2. **unknown** and **different** — a stamp that is not a version (`banana`) and one
//!    that is another version (`0.2.9`) are each refused and named;
//! 3. `post --work` is refused the same way, `board --json` says `refused` with the
//!    table, and the drain hook tells the session plainly;
//! 4. **plain conversation survives** a refusal, so the operator can still talk;
//! 5. **recovery needs nobody**: once the stale worker runs the current binary, its
//!    first participating verb announces the current version, and coordination
//!    resumes for everyone.
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

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{post_raw, until, Out, Worker};

const VERSION: &str = env!("CARGO_PKG_VERSION");
fn refused_naming(o: &Out, who: &Worker, what: &str) {
    assert_eq!(o.code, Some(3), "a version refusal must exit 3: {o:?}");
    for needle in [&who.b32()[..12], what, &format!("required {VERSION}")] {
        assert!(
            o.stderr.contains(needle),
            "the refusal must name {needle:?}: {}",
            o.stderr
        );
    }
}

fn claims_by(w: &Worker, reader: &Worker, r: &str) -> usize {
    let o = reader.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.ndjson()
        .iter()
        .filter(|x| x["author"] == w.b32() && x["envelope"]["type"] == "claim")
        .count()
}

#[test]
#[ignore = "two networked nodes and production Argon2id; CI runs it in release"]
fn a_worker_on_another_version_is_refused_by_name() {
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
    assert_eq!(unstamped, 1, "exactly bob's unstamped claim reached alice");
    eprintln!(
        "[receipt] alice's own claims before her first: {}",
        claims_by(alice, alice, r)
    );
    assert_eq!(
        claims_by(alice, alice, r),
        0,
        "precondition: alice has never claimed"
    );
    let o = alice.vox(Some("a1"), &["room", "claim", r, "new-work"]);
    refused_naming(&o, bob, "no version");
    assert_eq!(
        claims_by(alice, alice, r),
        0,
        "a refused claim must never be posted"
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
    assert_eq!(b["coordination"], "refused", "{b}");
    let p = b["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["author"] == bob.b32())
        .expect("bob in the table");
    assert_eq!(p["stamp"], "missing", "{b}");
    let hook = alice.vox(
        Some("a1"),
        &[
            "agent",
            "hook",
            "--room",
            r,
            "--format",
            "text",
            "--session",
            "a1",
        ],
    );
    assert!(
        hook.stdout.contains("work coordination refused") && hook.stdout.contains(&bob.b32()[..12]),
        "the drain hook must say it plainly: {hook:?}"
    );

    // ---- (4) conversation survives ----
    let o = alice.vox(
        Some("a1"),
        &["room", "post", r, "who is still on the old vox?"],
    );
    assert!(o.ok, "plain conversation must never be refused: {o:?}");

    // ---- (2) unknown, then different ----
    for (stamp, named) in [("banana", "banana"), ("0.2.9", "0.2.9")] {
        let hello = serde_json::json!({
            "v": 1, "type": "hello", "from": "b-foreign", "body": "a foreign worker",
            "data": { "vox": stamp, "op": format!("op-foreign-{}", stamp.replace('.', "-")) }
        })
        .to_string();
        rt.block_on(post_raw(bob, room.cid, &hello));
        let o = until(
            alice,
            Some("a1"),
            "alice to see the foreign stamp",
            &["room", "claim", r, "new-work"],
            |o: &Out| o.code == Some(3) && o.stderr.contains(named),
        );
        refused_naming(&o, bob, named);
    }

    // ---- (5) recovery: the stale worker runs the current binary ----
    let o = bob.vox(Some("b1"), &["room", "claim", r, "bob-work"]);
    assert!(
        o.ok && o.stdout.contains("you hold bob-work"),
        "a current worker among current workers coordinates: {o:?}"
    );
    let o = until(
        alice,
        Some("a1"),
        "coordination to resume for alice",
        &["room", "claim", r, "new-work"],
        |o: &Out| o.ok,
    );
    assert!(o.stdout.contains("you hold new-work"), "{o:?}");
    let b = alice
        .vox(Some("a1"), &["room", "board", r, "--json"])
        .json();
    assert_eq!(b["coordination"], "ok", "{b}");
}
