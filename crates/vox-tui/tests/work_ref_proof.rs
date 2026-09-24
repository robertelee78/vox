//! ADR-021 §3 — **a work reference has one shape, and an attempt is where a claim
//! began**, through the shipped `vox` binary.
//!
//! A tracker keys its items however it keys them; the one it is built for keys them
//! `OWNER/REPO:SOURCE:ITEM`. A reference is `<scheme>:<id>`, and the id may contain `:`,
//! so such a key rides in `data.work` byte for byte. Anything else is refused before it
//! is posted — by whichever flag carried it, because `--data '{"work":…}'` is the same
//! message as `--work` and must not be a way around the check.
//!
//! A tracker needs a named attempt to tell a retry from a continuation, and an agent
//! should not have to mint one. So a work-bound post from the session that holds the
//! claim on that item carries the claim's **acquisition** as `data.attempt`:
//!
//! 1. a skill-shaped key is accepted and carried unchanged;
//! 2. malformed references are refused (exit 1) and nothing is posted — by `--work`, by
//!    `--data`, and by `claim --work`;
//! 3. the holder's post carries the acquisition the board shows; a session that does not
//!    hold the claim gets no attempt; an explicit `--attempt` wins;
//! 4. a `failed` ends the attempt it names: the holder's next post begins a new one,
//!    named by that `failed` entry, and so on for every failure — every attempt is
//!    bounded and derivable from the log;
//! 5. release and claim again is a **new** attempt;
//! 6. retrying an `--op` after the claim was re-taken is still the same message — it
//!    keeps the attempt its first post carried, instead of turning into a conflict.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{resource, Out, Worker};

/// The key shape of the work-accountability tracker, under a scheme.
const KEY: &str = "gwa:robertelee78/vox:adr-021:m21.3";

fn rows(w: &Worker, r: &str) -> Vec<serde_json::Value> {
    let o = w.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.ndjson()
}

fn post(w: &Worker, session: &str, r: &str, extra: &[&str], body: &str) -> Out {
    post_as(w, session, r, "working", extra, body)
}

fn post_as(w: &Worker, session: &str, r: &str, kind: &str, extra: &[&str], body: &str) -> Out {
    let mut args = vec!["room", "post", r, "--type", kind, "--json"];
    args.extend_from_slice(extra);
    args.push("-");
    w.vox_in(Some(session), &args, Some(body))
}

/// The `data` of the row a `post --json` reported.
fn data_of(w: &Worker, r: &str, posted: &Out) -> serde_json::Value {
    let hash = posted.json()["entry_hash"].clone();
    rows(w, r)
        .into_iter()
        .find(|x| x["entry_hash"] == hash)
        .unwrap_or_else(|| panic!("the posted entry {hash} is not in the log"))["envelope"]["data"]
        .clone()
}

fn acquisition(w: &Worker, r: &str, key: &str) -> String {
    let b = w.vox(Some("holder"), &["room", "board", r, "--json"]);
    assert!(b.ok, "{b:?}");
    resource(&b.json(), key).unwrap_or_else(|| panic!("{key} not on the board: {b:?}"))
        ["acquisition"]
        .as_str()
        .expect("a held resource names its acquisition")
        .to_owned()
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_work_reference_has_one_shape_and_an_attempt_is_where_a_claim_began() {
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

    // ---- (1) the tracker's own key, colons and all, is carried unchanged ----
    let ok = post(alice, "other", r, &["--work", KEY], "reading the ADR");
    assert!(ok.ok, "a skill-shaped work key must be accepted: {ok:?}");
    assert_eq!(data_of(alice, r, &ok)["work"], KEY, "carried byte for byte");

    // ---- (2) anything else is refused, whichever flag carried it ----
    let before = rows(alice, r).len();
    let long = format!("gh:{}", "x".repeat(113));
    for bad in [
        "no-scheme",
        "Gh:upper-scheme",
        "gh:",
        "gh:a b",
        ":no-scheme",
        "gh:tab\there",
        long.as_str(),
    ] {
        let via_flag = post(alice, "other", r, &["--work", bad], "x");
        let data = serde_json::json!({ "work": bad }).to_string();
        let via_data = post(alice, "other", r, &["--data", &data], "x");
        let via_claim = alice.vox(Some("other"), &["room", "claim", r, "--work", bad]);
        for (how, o) in [
            ("--work", &via_flag),
            ("--data", &via_data),
            ("claim --work", &via_claim),
        ] {
            assert_eq!(
                o.code,
                Some(1),
                "{bad:?} via {how} must be refused, not posted: {o:?}"
            );
            assert!(
                o.stderr.contains("not a work reference"),
                "{bad:?} via {how} must say why: {o:?}"
            );
        }
    }
    let data_not_string = post(alice, "other", r, &["--data", r#"{"work":42}"#], "x");
    assert_eq!(data_not_string.code, Some(1), "{data_not_string:?}");
    assert_eq!(
        rows(alice, r).len(),
        before,
        "a refused reference must post nothing"
    );

    // ---- (3) the holder's post names the claim's acquisition ----
    let claimed = alice.vox(Some("holder"), &["room", "claim", r, "--work", KEY]);
    assert!(claimed.ok, "{claimed:?}");
    let first = acquisition(alice, r, KEY);
    let mine = post(
        alice,
        "holder",
        r,
        &["--work", KEY, "--op", "op-attempt-0001"],
        "porting",
    );
    assert!(mine.ok, "{mine:?}");
    assert_eq!(
        data_of(alice, r, &mine)["attempt"],
        first.as_str(),
        "the holder's work-bound post must carry its claim's acquisition as the attempt"
    );
    let theirs = post(alice, "bystander", r, &["--work", KEY], "watching");
    assert!(theirs.ok, "{theirs:?}");
    assert!(
        data_of(alice, r, &theirs).get("attempt").is_none(),
        "a session that does not hold the claim has no attempt to name"
    );
    let named = post(
        alice,
        "holder",
        r,
        &["--work", KEY, "--attempt", "a-explicit"],
        "named",
    );
    assert!(named.ok, "{named:?}");
    assert_eq!(
        data_of(alice, r, &named)["attempt"],
        "a-explicit",
        "an explicit --attempt wins"
    );

    // ---- (4) a `failed` ends the attempt it names; the retry is a new one ----
    let failed = post_as(
        alice,
        "holder",
        r,
        "failed",
        &["--work", KEY, "--data", r#"{"reason":"tests red"}"#],
        "first try failed",
    );
    assert!(failed.ok, "{failed:?}");
    assert_eq!(
        data_of(alice, r, &failed)["attempt"],
        first.as_str(),
        "a `failed` must name the attempt that failed"
    );
    let retry1 = post(alice, "holder", r, &["--work", KEY], "trying again");
    assert!(retry1.ok, "{retry1:?}");
    assert_eq!(
        data_of(alice, r, &retry1)["attempt"],
        failed.json()["entry_hash"],
        "after a `failed`, the holder's next post must begin a NEW attempt, named by that failure"
    );
    let failed2 = post_as(
        alice,
        "holder",
        r,
        "failed",
        &["--work", KEY, "--data", r#"{"reason":"still red"}"#],
        "second try failed",
    );
    assert!(failed2.ok, "{failed2:?}");
    assert_eq!(
        data_of(alice, r, &failed2)["attempt"],
        failed.json()["entry_hash"],
        "the second `failed` names the second attempt"
    );
    let retry2 = post(alice, "holder", r, &["--work", KEY], "third try");
    assert!(retry2.ok, "{retry2:?}");
    assert_eq!(
        data_of(alice, r, &retry2)["attempt"],
        failed2.json()["entry_hash"],
        "every failure begins the next attempt, not only the first"
    );

    // ---- (5) release and claim again: a new attempt ----
    let released = alice.vox(Some("holder"), &["room", "release", r, KEY]);
    assert!(released.ok, "{released:?}");
    let again = alice.vox(Some("holder"), &["room", "claim", r, "--work", KEY]);
    assert!(again.ok, "{again:?}");
    let second = acquisition(alice, r, KEY);
    assert_ne!(first, second, "a new claim must be a new acquisition");
    let next = post(alice, "holder", r, &["--work", KEY], "second go");
    assert!(next.ok, "{next:?}");
    assert_eq!(
        data_of(alice, r, &next)["attempt"],
        second.as_str(),
        "a post after re-claiming must name the NEW attempt"
    );

    // ---- (6) an --op retried after the re-claim is still the same message ----
    let retry = post(
        alice,
        "holder",
        r,
        &["--work", KEY, "--op", "op-attempt-0001"],
        "porting",
    );
    assert!(
        retry.ok,
        "a retry after the claim was re-taken must not become a conflict: {retry:?}"
    );
    assert_eq!(retry.json()["status"], "already-posted", "{retry:?}");
    assert_eq!(retry.json()["entry_hash"], mine.json()["entry_hash"]);
}
