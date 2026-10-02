//! ADR-021 §2 — **a work reference has one shape**, through the shipped `vox` binary.
//!
//! A work item is named by awa's work key, `OWNER/REPO:SOURCE:ITEM`, under a scheme. A
//! reference is `<scheme>:<id>`, and the id may contain `:`, so such a key rides in
//! `data.work` byte for byte. Anything else is refused before it is posted — by whichever
//! flag carried it, because `--data '{"work":…}'` is the same message as `--work` and must
//! not be a way around the check.
//!
//! 1. a skill-shaped key is accepted and carried unchanged, and nothing is added beside it:
//!    a work-bound post carries no attempt id, because Vox holds no task state (V030-26);
//! 2. malformed references are refused (exit 1) and nothing is posted — by `--work` and by
//!    `--data`.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{Out, Worker};

/// awa's work-key shape, under its scheme.
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

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_work_reference_has_one_shape() {
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
    let data = data_of(alice, r, &ok);
    assert_eq!(
        data["work"], KEY,
        "PRODUCT: the key must be carried byte for byte"
    );
    assert!(
        data.get("attempt").is_none(),
        "PRODUCT: a work-bound post carries an attempt id, which is task state Vox no longer \
         keeps: {data}"
    );

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
        for (how, o) in [("--work", &via_flag), ("--data", &via_data)] {
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
}
