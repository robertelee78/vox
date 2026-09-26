//! ADR-021 **F20** — **the seeded attempt id's two exclusions**, through the shipped `vox`
//! binary.
//!
//! A holder's work-bound post that names no `--attempt` carries a seeded id: its claim's
//! acquisition, or its own latest `failed` for that work since the claim (ADR-021 §2).
//! Two `failed` entries must not seed:
//!
//! 1. **a retried `failed` seeds from its first entry, not the retry.** Two writers that
//!    both post the same `failed` under one `--op` leave two entries of one operation; the
//!    later is a duplicate. If the duplicate seeded, the next attempt's id would depend on
//!    which copy happened to land last;
//! 2. **a `failed` whose operation is void seeds nothing.** Two `failed` entries with one
//!    `--op` and different content are a conflict, and a conflicted operation has no
//!    effect anywhere (ADR-021 §6), so neither may name the next attempt.
//!
//! `vox room post --op` never posts a retry twice itself, so a genuine duplicate or
//! conflict only comes from two writers racing. They are posted here raw, through the
//! node's control socket, exactly as a second writer's post would land.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{resource, Out, Worker};
use vox_agentcomms::envelope::Envelope;

const KEY: &str = "gh:acme/vox#f20";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn rows(w: &Worker, r: &str) -> Vec<serde_json::Value> {
    let o = w.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.ndjson()
}

/// A CLI post as the holder, with no `--attempt`, so the node's seeding decides it.
fn working(w: &Worker, r: &str, body: &str) -> Out {
    let o = w.vox_in(
        Some("holder"),
        &[
            "room", "post", r, "--type", "working", "--json", "--work", KEY, "-",
        ],
        Some(body),
    );
    assert!(o.ok, "{o:?}");
    o
}

/// The seeded `data.attempt` of the entry a `post --json` reported.
fn attempt_of(w: &Worker, r: &str, posted: &Out) -> String {
    let hash = posted.json()["entry_hash"].clone();
    rows(w, r)
        .into_iter()
        .find(|x| x["entry_hash"] == hash)
        .unwrap_or_else(|| panic!("the posted entry {hash} is not in the log"))["envelope"]["data"]
        ["attempt"]
        .as_str()
        .expect("a holder's work-bound post carries a seeded attempt")
        .to_owned()
}

/// A `failed` for [`KEY`] from session `holder`, as a writer racing the CLI posts it.
fn failed_text(op: &str, reason: &str) -> String {
    let mut env = Envelope::new("failed", &format!("failed: {reason}"));
    env.from = "holder".into();
    env.data = serde_json::json!({ "op": op, "work": KEY, "reason": reason, "vox": VERSION });
    env.to_text()
}

/// The rows carrying `op`, in canonical order `(created_millis, entry_hash)`.
fn by_op(w: &Worker, r: &str, op: &str) -> Vec<serde_json::Value> {
    let mut v: Vec<serde_json::Value> = rows(w, r)
        .into_iter()
        .filter(|x| x["envelope"]["data"]["op"] == op)
        .collect();
    v.sort_by_key(|x| {
        (
            x["created_millis"].as_u64().unwrap(),
            x["entry_hash"].as_str().unwrap().to_owned(),
        )
    });
    v
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_retried_failed_seeds_from_its_first_entry_and_a_void_one_seeds_nothing() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let r = room.id.as_str();

    let claimed = alice.vox(Some("holder"), &["room", "claim", r, "--work", KEY]);
    assert!(claimed.ok, "{claimed:?}");
    let b = alice.vox(Some("holder"), &["room", "board", r, "--json"]);
    let acquisition = resource(&b.json(), KEY).expect("the claim is on the board")["acquisition"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = working(alice, r, "starting");
    assert_eq!(
        attempt_of(alice, r, &before),
        acquisition,
        "before any failure, the seed is the claim's acquisition"
    );

    // ---- (1) a retried `failed`: two entries of one operation ----
    let same = failed_text("op-f20-retried", "tests red");
    rt.block_on(support::post_raw(alice, room.cid, &same));
    std::thread::sleep(std::time::Duration::from_millis(20)); // a later created_millis
    rt.block_on(support::post_raw(alice, room.cid, &same));
    let retried = by_op(alice, r, "op-f20-retried");
    assert_eq!(retried.len(), 2, "both copies are in the log: {retried:?}");
    assert_eq!(
        retried[1]["op"]["status"], "duplicate",
        "the later copy is the duplicate: {:?}",
        retried[1]
    );
    let first = retried[0]["entry_hash"].as_str().unwrap().to_owned();
    let copy = retried[1]["entry_hash"].as_str().unwrap().to_owned();
    let after_retry = working(alice, r, "second attempt");
    let seeded = attempt_of(alice, r, &after_retry);
    eprintln!("[proof] retried failed: first {first}, copy {copy}; next attempt seeded {seeded}");
    assert_eq!(
        seeded, first,
        "a retried `failed` seeds from its FIRST entry, never the duplicate"
    );

    // ---- (2) a void `failed`: one operation, two contents ----
    rt.block_on(support::post_raw(
        alice,
        room.cid,
        &failed_text("op-f20-void", "flaky network"),
    ));
    std::thread::sleep(std::time::Duration::from_millis(20));
    rt.block_on(support::post_raw(
        alice,
        room.cid,
        &failed_text("op-f20-void", "disk full"),
    ));
    let void = by_op(alice, r, "op-f20-void");
    assert_eq!(void.len(), 2, "{void:?}");
    for x in &void {
        assert_eq!(
            x["op"]["status"], "conflict",
            "both are the conflict: {x:?}"
        );
    }
    let after_void = working(alice, r, "third post, same attempt");
    let seeded = attempt_of(alice, r, &after_void);
    eprintln!(
        "[proof] void failed: {} and {}; next attempt seeded {seeded}",
        void[0]["entry_hash"], void[1]["entry_hash"]
    );
    assert_eq!(
        seeded, first,
        "a `failed` whose operation is void seeds nothing: the id stays the last real failure's"
    );
}
