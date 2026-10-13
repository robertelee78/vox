//! ADR-021 §2 — **a work reference has one shape, and an attempt id is seeded from the
//! log**, through the shipped `vox` binary.
//!
//! A tracker keys its items however it keys them; the one it is built for keys them
//! `OWNER/REPO:SOURCE:ITEM`. A reference is `<scheme>:<id>`, and the id may contain `:`,
//! so such a key rides in `data.work` byte for byte. Anything else is refused before it
//! is posted — by whichever flag carried it, because `--data '{"work":…}'` is the same
//! message as `--work` and must not be a way around the check.
//!
//! A tracker correlates the posts of one attempt by id, and an agent should not have to
//! mint one. So a work-bound post from the session that holds the claim on that item
//! carries a **seeded id** in `data.attempt` — the claim's acquisition, or the holder's
//! latest `failed` since it. Seeding starts nothing: an attempt becomes active only on the
//! holder's `working` (ADR-021 §3).
//! This proof covers the seeding:
//!
//! 1. a skill-shaped key is accepted and carried unchanged;
//! 2. malformed references are refused (exit 1) and nothing is posted — by `--work`, by
//!    `--data`, and by `claim --work`;
//! 3. the holder's post carries the acquisition the board shows; a session that does not
//!    hold the claim gets no id; an explicit `--attempt` wins;
//! 4. a `failed` carries the id it ends, and seeds the next one: the holder's next post
//!    carries that `failed` entry's hash, and so on for every failure — every retry's id
//!    is derivable from the log;
//! 5. release and claim again seeds a **new** id;
//! 6. retrying an `--op` after the claim was re-taken is still the same message — it
//!    keeps the attempt its first post carried, instead of turning into a conflict.
//! 7. two `failed` entries never seed (ADR-021 F20): **a retried `failed` seeds from its
//!    first entry**, not the retry, and **a `failed` whose operation is void seeds nothing**.
//!    Both need a second entry under one `(author, op)` that the CLI's own lookup would have
//!    prevented, which is what a writer racing the CLI produces. The first `failed` is
//!    `vox room post`'s; the racing copy is written onto the control socket as the bytes that
//!    writer writes, as `work_op_proof` does for the same staging. The proof checks each
//!    row's `op.status` (`duplicate`, `conflict`) and says APPARATUS if the staging did not
//!    take.

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{post_raw, resource, Out, Worker};

/// The key shape of the work-accountability tracker, under a scheme.
const KEY: &str = "gwa:robertelee78/vox:adr-021:m21.3";

fn rows(w: &Worker, r: &str) -> Vec<serde_json::Value> {
    let o = w.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "PRODUCT: `vox room read --json` failed: {o:?}");
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
        .unwrap_or_else(|| panic!("PRODUCT: the posted entry {hash} is not in the log: {posted:?}"))
        ["envelope"]["data"]
        .clone()
}

fn acquisition(w: &Worker, r: &str, key: &str) -> String {
    let b = w.vox(Some("holder"), &["room", "board", r, "--json"]);
    assert!(b.ok, "PRODUCT: `vox room board --json` failed: {b:?}");
    resource(&b.json(), key)
        .unwrap_or_else(|| panic!("PRODUCT: {key} is not on the holder's board: {b:?}"))
        ["acquisition"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: the held {key} names no acquisition: {b:?}"))
        .to_owned()
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_work_reference_has_one_shape_and_an_attempt_id_is_seeded_from_the_log() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: could not build the test's tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temp dir");
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let room_id = room.id.clone();
    let alice = &room.workers[0];
    let r = room_id.as_str();

    // ---- (1) the tracker's own key, colons and all, is carried unchanged ----
    let ok = post(alice, "other", r, &["--work", KEY], "reading the ADR");
    assert!(
        ok.ok,
        "PRODUCT: a skill-shaped work key must be accepted: {ok:?}"
    );
    let data = data_of(alice, r, &ok);
    assert_eq!(
        data["work"], KEY,
        "PRODUCT: the work key must be carried byte for byte: {data}"
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
        let via_claim = alice.vox(Some("other"), &["room", "claim", r, "--work", bad]);
        for (how, o) in [
            ("--work", &via_flag),
            ("--data", &via_data),
            ("claim --work", &via_claim),
        ] {
            assert_eq!(
                o.code,
                Some(1),
                "PRODUCT: {bad:?} via {how} must be refused, not posted: {o:?}"
            );
            assert!(
                o.stderr.contains("not a work reference"),
                "PRODUCT: {bad:?} via {how} must say why: {o:?}"
            );
        }
    }
    let data_not_string = post(alice, "other", r, &["--data", r#"{"work":42}"#], "x");
    assert_eq!(
        data_not_string.code,
        Some(1),
        "PRODUCT: a non-string `data.work` must be refused: {data_not_string:?}"
    );
    let after = rows(alice, r);
    assert_eq!(
        after.len(),
        before,
        "PRODUCT: a refused reference must post nothing, yet the log grew: {:?}",
        &after[before.min(after.len())..]
    );

    // ---- (3) the holder's post names the claim's acquisition ----
    let claimed = alice.vox(Some("holder"), &["room", "claim", r, "--work", KEY]);
    assert!(
        claimed.ok,
        "PRODUCT: the holder's claim failed: {claimed:?}"
    );
    let first = acquisition(alice, r, KEY);
    let mine = post(
        alice,
        "holder",
        r,
        &["--work", KEY, "--op", "op-attempt-0001"],
        "porting",
    );
    assert!(
        mine.ok,
        "PRODUCT: the holder's work-bound post failed: {mine:?}"
    );
    assert_eq!(
        data_of(alice, r, &mine)["attempt"],
        first.as_str(),
        "PRODUCT: the holder's work-bound post must carry its claim's acquisition as the attempt"
    );
    let theirs = post(alice, "bystander", r, &["--work", KEY], "watching");
    assert!(
        theirs.ok,
        "PRODUCT: a bystander's work-bound post failed: {theirs:?}"
    );
    let data = data_of(alice, r, &theirs);
    assert!(
        data.get("attempt").is_none(),
        "PRODUCT: a session that does not hold the claim has no attempt to name: {data}"
    );
    let named = post(
        alice,
        "holder",
        r,
        &["--work", KEY, "--attempt", "a-explicit"],
        "named",
    );
    assert!(
        named.ok,
        "PRODUCT: a post with an explicit --attempt failed: {named:?}"
    );
    assert_eq!(
        data_of(alice, r, &named)["attempt"],
        "a-explicit",
        "PRODUCT: an explicit --attempt wins"
    );

    // ---- (4) a `failed` carries the id it ends and seeds the retry's ----
    let failed = post_as(
        alice,
        "holder",
        r,
        "failed",
        &["--work", KEY, "--data", r#"{"reason":"tests red"}"#],
        "first try failed",
    );
    assert!(
        failed.ok,
        "PRODUCT: the holder's first `failed` post failed: {failed:?}"
    );
    assert_eq!(
        data_of(alice, r, &failed)["attempt"],
        first.as_str(),
        "PRODUCT: a `failed` must name the attempt that failed"
    );
    let retry1 = post(alice, "holder", r, &["--work", KEY], "trying again");
    assert!(
        retry1.ok,
        "PRODUCT: the holder's post after a `failed` failed: {retry1:?}"
    );
    assert_eq!(
        data_of(alice, r, &retry1)["attempt"],
        failed.json()["entry_hash"],
        "PRODUCT: after a `failed`, the holder's next post must carry a NEW id, seeded by that failure"
    );
    let failed2 = post_as(
        alice,
        "holder",
        r,
        "failed",
        &["--work", KEY, "--data", r#"{"reason":"still red"}"#],
        "second try failed",
    );
    assert!(
        failed2.ok,
        "PRODUCT: the holder's second `failed` post failed: {failed2:?}"
    );
    assert_eq!(
        data_of(alice, r, &failed2)["attempt"],
        failed.json()["entry_hash"],
        "PRODUCT: the second `failed` names the second attempt"
    );
    let retry2 = post(alice, "holder", r, &["--work", KEY], "third try");
    assert!(
        retry2.ok,
        "PRODUCT: the holder's third try failed: {retry2:?}"
    );
    assert_eq!(
        data_of(alice, r, &retry2)["attempt"],
        failed2.json()["entry_hash"],
        "PRODUCT: every failure seeds the next id, not only the first"
    );

    // ---- (5) release and claim again: a new id ----
    let released = alice.vox(Some("holder"), &["room", "release", r, KEY]);
    assert!(
        released.ok,
        "PRODUCT: the holder's release failed: {released:?}"
    );
    let again = alice.vox(Some("holder"), &["room", "claim", r, "--work", KEY]);
    assert!(again.ok, "PRODUCT: the holder's re-claim failed: {again:?}");
    let second = acquisition(alice, r, KEY);
    assert_ne!(
        first, second,
        "PRODUCT: a new claim must be a new acquisition"
    );
    let next = post(alice, "holder", r, &["--work", KEY], "second go");
    assert!(
        next.ok,
        "PRODUCT: the holder's post after re-claiming failed: {next:?}"
    );
    assert_eq!(
        data_of(alice, r, &next)["attempt"],
        second.as_str(),
        "PRODUCT: a post after re-claiming must carry the NEW id"
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
        "PRODUCT: a retry after the claim was re-taken must not become a conflict: {retry:?}"
    );
    assert_eq!(
        retry.json()["status"],
        "already-posted",
        "PRODUCT: the retried --op must report it was already posted: {retry:?}"
    );
    assert_eq!(
        retry.json()["entry_hash"],
        mine.json()["entry_hash"],
        "PRODUCT: the retried --op must name its first entry: first={mine:?} retry={retry:?}"
    );

    // ---- (7) a retried `failed` seeds from its first entry; a void one seeds nothing ----
    let rows_of_op = |op: &str| -> Vec<serde_json::Value> {
        let mut v: Vec<serde_json::Value> = rows(alice, r)
            .into_iter()
            .filter(|x| x["envelope"]["data"]["op"] == op)
            .collect();
        v.sort_by_key(|x| {
            (
                x["created_millis"].as_u64().unwrap_or_else(|| {
                    panic!("PRODUCT: a row of `room read --json` has no created_millis: {x}")
                }),
                x["entry_hash"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("PRODUCT: a row of `room read --json` has no entry_hash: {x}")
                    })
                    .to_owned(),
            )
        });
        v
    };
    let failed3 = post_as(
        alice,
        "holder",
        r,
        "failed",
        &["--work", KEY, "--op", "op-f20-retried"],
        "tests red",
    );
    assert!(
        failed3.ok,
        "PRODUCT: the holder's `failed` was refused: {failed3:?}"
    );
    let first_failed = failed3.json()["entry_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: `room post --json` named no entry_hash: {failed3:?}"))
        .to_owned();
    let row = rows(alice, r)
        .into_iter()
        .find(|x| x["entry_hash"] == first_failed.as_str())
        .unwrap_or_else(|| {
            panic!("PRODUCT: `room read` does not return the `failed` that `room post` accepted: {failed3:?}")
        });
    let text = row["text"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: a row of `room read --json` has no text: {row}"))
        .to_owned();
    std::thread::sleep(std::time::Duration::from_millis(20)); // the copy lands later
    rt.block_on(post_raw(alice, room.cid, &text));
    let retried = rows_of_op("op-f20-retried");
    assert!(
        retried.len() == 2 && retried[0]["entry_hash"] == first_failed.as_str(),
        "APPARATUS: the proof's raw copy of the `failed` did not land after it: {retried:?}"
    );
    assert!(
        retried[1]["op"]["status"] == "duplicate",
        "PRODUCT: `room read --json` does not mark a later copy of a `failed` under the same op \
         a duplicate: {retried:?}"
    );
    let next = post(
        alice,
        "holder",
        r,
        &["--work", KEY],
        "after the retried failure",
    );
    assert!(next.ok, "PRODUCT: {next:?}");
    let seeded = data_of(alice, r, &next)["attempt"].clone();
    eprintln!(
        "[proof] retried failed: first {first_failed}, copy {}; next post seeded {seeded}",
        retried[1]["entry_hash"]
    );
    assert!(
        seeded == first_failed.as_str(),
        "PRODUCT: a retried `failed` must seed from its FIRST entry {first_failed}, never the \
         duplicate; the next post seeded {seeded}"
    );

    let void = post_as(
        alice,
        "holder",
        r,
        "failed",
        &[
            "--work",
            KEY,
            "--op",
            "op-f20-void",
            "--data",
            r#"{"reason":"flaky network"}"#,
        ],
        "failed: flaky network",
    );
    assert!(
        void.ok,
        "PRODUCT: the holder's `failed` was refused: {void:?}"
    );
    let row = rows(alice, r)
        .into_iter()
        .find(|x| x["entry_hash"] == void.json()["entry_hash"])
        .unwrap_or_else(|| {
            panic!("PRODUCT: `room read` does not return the `failed` that `room post` accepted: {void:?}")
        });
    let text = row["text"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: a row of `room read --json` has no text: {row}"));
    let mut racing = vox_agentcomms::envelope::Envelope::parse(text).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: `room post` wrote a `failed` its own envelope parser refuses ({e}): {text}"
        )
    });
    racing.body = "failed: disk full".into();
    racing.data["reason"] = "disk full".into();
    std::thread::sleep(std::time::Duration::from_millis(20));
    rt.block_on(post_raw(alice, room.cid, &racing.to_text()));
    let voided = rows_of_op("op-f20-void");
    assert!(
        voided.len() == 2,
        "APPARATUS: the proof's raw racing `failed` did not land beside the first: {voided:?}"
    );
    assert!(
        voided.iter().all(|x| x["op"]["status"] == "conflict"),
        "PRODUCT: `room read --json` does not mark two different `failed` under one op a \
         conflict: {voided:?}"
    );
    let after_void = post(
        alice,
        "holder",
        r,
        &["--work", KEY],
        "after the void failure",
    );
    assert!(after_void.ok, "PRODUCT: {after_void:?}");
    let seeded = data_of(alice, r, &after_void)["attempt"].clone();
    eprintln!(
        "[proof] void failed: {} and {}; next post seeded {seeded}",
        voided[0]["entry_hash"], voided[1]["entry_hash"]
    );
    assert!(
        seeded == first_failed.as_str(),
        "PRODUCT: a `failed` whose operation is void must seed nothing: the id stays the last \
         real failure's, {first_failed}; the next post seeded {seeded}"
    );
    // ADR-033 TH-5 (#756): each reply gets the starting message's three opaque tags,
    // including a nested reply. An intermediate reply's extra tag is not the root's tag.
    let root = post_as(
        alice,
        "holder",
        r,
        "say",
        &[
            "--task",
            "#756",
            "--project",
            "literal-project",
            "--milestone",
            "literal-milestone",
        ],
        "TAG-ROOT",
    );
    assert!(root.ok, "PRODUCT: tagged starting post failed: {root:?}");
    let root_age = std::time::Instant::now();
    let root_hash = root.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: root hash")
        .to_owned();
    let first = post_as(
        alice,
        "holder",
        r,
        "say",
        &[
            "--re",
            &root_hash,
            "--project",
            "reply-extra",
            "--work",
            KEY,
            "--op",
            "inherited-tags",
        ],
        "TAG-FIRST",
    );
    assert!(first.ok, "PRODUCT: tagged reply failed: {first:?}");
    let first_hash = first.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: reply hash")
        .to_owned();
    let nested = post_as(
        alice,
        "other",
        r,
        "say",
        &["--re", &first_hash],
        "TAG-NESTED",
    );
    assert!(nested.ok, "PRODUCT: nested reply failed: {nested:?}");
    let inherited = serde_json::json!([
        "milestone:literal-milestone",
        "project:literal-project",
        "task:#756"
    ]);
    let read = rows(alice, r);
    let envelope = |hash: &serde_json::Value| {
        read.iter()
            .find(|row| &row["entry_hash"] == hash)
            .expect("PRODUCT: posted tagged reply absent")["envelope"]
            .clone()
    };
    let first_env = envelope(&first.json()["entry_hash"]);
    let nested_env = envelope(&nested.json()["entry_hash"]);
    assert!(
        inherited
            .as_array()
            .unwrap()
            .iter()
            .all(|tag| first_env["tags"]
                .as_array()
                .is_some_and(|tags| tags.contains(tag)))
            && first_env["tags"]
                .as_array()
                .is_some_and(|tags| tags.contains(&serde_json::json!("project:reply-extra")))
            && first_env["data"]["work"] == KEY
            && first_env["from"] == "holder"
            && first_env["re"] == root_hash,
        "PRODUCT: CLI reply must inherit all root tags and preserve explicit metadata: {first_env}"
    );
    assert!(nested_env["tags"] == inherited && nested_env["thread"] == root_hash && nested_env["re"] == first_hash,
        "PRODUCT: nested CLI reply must inherit the starting message's tags, not its parent's extra tags: {nested_env}");
    let retry = post_as(
        alice,
        "holder",
        r,
        "say",
        &[
            "--re",
            &root_hash,
            "--project",
            "reply-extra",
            "--work",
            KEY,
            "--op",
            "inherited-tags",
        ],
        "TAG-FIRST",
    );
    assert!(
        retry.ok && retry.json()["entry_hash"] == first.json()["entry_hash"],
        "PRODUCT: the same reply operation must keep its tags and identity: {retry:?}"
    );

    let raw = serde_json::json!({"v":1,"type":"say","re":first_hash,"thread":root_hash,
        "body":"RAW-TAG-REPLY","data":{"opaque":"unchanged"}})
    .to_string();
    let raw_post = alice.vox_in(None, &["room", "post", r, "-"], Some(&raw));
    assert!(
        raw_post.ok,
        "PRODUCT: pasted envelope reply refused: {raw_post:?}"
    );
    let raw_row = rows(alice, r)
        .into_iter()
        .find(|row| row["envelope"]["body"] == "RAW-TAG-REPLY")
        .expect("PRODUCT: pasted reply absent");
    assert!(
        raw_row["envelope"]["tags"] == inherited
            && raw_row["envelope"]["data"]["opaque"] == "unchanged",
        "PRODUCT: pasted reply must inherit root tags without rewriting its payload: {raw_row}"
    );

    let shared_path = tmp.path().join("thread-note.txt");
    std::fs::write(&shared_path, "A file in the tagged thread")
        .expect("APPARATUS: write shared file");
    let shared = alice.vox(
        Some("holder"),
        &[
            "share",
            r,
            shared_path.to_str().expect("APPARATUS: shared path"),
            "--re",
            &first_hash,
            "-m",
            "TAGGED-FILE-REPLY",
        ],
    );
    assert!(shared.ok, "PRODUCT: file reply refused: {shared:?}");
    let file_row = rows(alice, r)
        .into_iter()
        .find(|row| row["envelope"]["body"] == "TAGGED-FILE-REPLY")
        .expect("PRODUCT: file reply absent");
    assert!(
        file_row["envelope"]["tags"] == inherited
            && file_row["envelope"]["thread"] == root_hash
            && file_row["envelope"]["re"] == first_hash,
        "PRODUCT: a shared file reply must carry the starting tags and thread: {file_row}"
    );

    let tui_root = post_as(
        alice,
        "holder",
        r,
        "say",
        &[
            "--task",
            "#756",
            "--project",
            "literal-project",
            "--milestone",
            "literal-milestone",
        ],
        "TUI-TAG-ROOT",
    );
    assert!(
        tui_root.ok,
        "PRODUCT: TUI thread staging failed: {tui_root:?}"
    );
    let driver = tmp.path().join("reply-without-tags.py");
    std::fs::write(&driver, TUI_REPLY).expect("APPARATUS: write existing PTY apparatus caller");
    let driven = pty_driver::run(
        driver.to_str().expect("APPARATUS: driver path"),
        &[
            support::VOX,
            alice.data.to_str().expect("APPARATUS: data path"),
            alice.cfg.to_str().expect("APPARATUS: config path"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty"),
        ],
    );
    assert!(
        driven.code == Some(0)
            && driven.has_verdict("thread-tags")
            && driven
                .stdout
                .contains("thread-tags PASS: TUI posted its reply"),
        "{}: TUI reply journey: {}{}",
        if driven.code == Some(2) {
            "APPARATUS"
        } else {
            "PRODUCT"
        },
        driven.stdout,
        driven.stderr
    );
    let tui_reply = rows(alice, r)
        .into_iter()
        .find(|row| row["envelope"]["body"] == "TUI-REPLY-WITHOUT-TAGS")
        .expect("PRODUCT: TUI's posted reply is absent from room read --json");
    assert!(tui_reply["envelope"]["tags"] == inherited && tui_reply["envelope"]["thread"] == tui_root.json()["entry_hash"],
        "PRODUCT: a reply typed in the TUI with no tags must carry all three starting tags: {tui_reply}");
    eprintln!("[proof] #756 CLI and TUI replies carry starting tags: {inherited}");

    // The caller cannot manufacture the binary-owned snapshot, through flags or raw JSON.
    let spoof = post_as(
        alice,
        "holder",
        r,
        "say",
        &[
            "--re",
            &root_hash,
            "--data",
            r#"{"thread_tags":["task:forged"]}"#,
        ],
        "SPOOFED-SNAPSHOT",
    );
    assert!(
        !spoof.ok && spoof.stderr.contains("thread_tags"),
        "PRODUCT: caller-supplied inheritance must be refused: {spoof:?}"
    );
    let raw_spoof = serde_json::json!({"v":1,"type":"say","re":root_hash,
        "body":"RAW-SPOOFED-SNAPSHOT","data":{"thread_tags":[]}})
    .to_string();
    let spoof = alice.vox_in(None, &["room", "post", r, "-"], Some(&raw_spoof));
    assert!(
        !spoof.ok && spoof.stderr.contains("thread_tags"),
        "PRODUCT: a pasted inheritance snapshot must be refused: {spoof:?}"
    );

    // Reuse the existing room-verbs journey's offline-peer apparatus: the binary queues a
    // reply while its starting message is missing, then retries after that message arrives.
    room.stop(1);
    let late = post_as(
        &room.workers[0],
        "holder",
        r,
        "say",
        &["--task", "late-root"],
        "LATE-TAG-ROOT",
    );
    assert!(late.ok, "PRODUCT: late tagged root refused: {late:?}");
    let late_hash = late.json()["entry_hash"]
        .as_str()
        .expect("PRODUCT: late root hash")
        .to_owned();
    struct Frozen(u32);
    impl Drop for Frozen {
        fn drop(&mut self) {
            let _ = std::process::Command::new("kill")
                .args(["-CONT", &self.0.to_string()])
                .status();
        }
    }
    let frozen: Vec<_> = [
        room.anchor_pid(),
        room.workers[0]
            .daemon_pid()
            .expect("APPARATUS: Alice daemon"),
    ]
    .into_iter()
    .map(|pid| {
        let stopped = std::process::Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .expect("APPARATUS: pause fixture peer");
        assert!(
            stopped.success(),
            "APPARATUS: could not pause fixture peer {pid}"
        );
        Frozen(pid)
    })
    .collect();
    room.restart(1);
    let bob = &room.workers[1];
    assert!(
        !rows(bob, r)
            .iter()
            .any(|row| row["entry_hash"] == late_hash),
        "APPARATUS: offline Bob already holds the deliberately missing root"
    );
    let late_flags = [
        "--re",
        &late_hash,
        "--op",
        "late-tags-retry-756",
        "--project",
        "explicit",
    ];
    let thread_flags = [
        "--thread",
        &late_hash,
        "--op",
        "late-thread-tags-756",
        "--project",
        "explicit",
    ];
    let queued = post_as(bob, "retrying", r, "say", &late_flags, "LATE-TAG-REPLY");
    let thread_queued = post_as(
        bob,
        "retrying",
        r,
        "say",
        &thread_flags,
        "LATE-THREAD-REPLY",
    );
    assert!(
        queued.ok && thread_queued.ok,
        "PRODUCT: offline replies refused: {queued:?}; {thread_queued:?}"
    );
    let queued_row = rows(bob, r)
        .into_iter()
        .find(|row| row["entry_hash"] == queued.json()["entry_hash"])
        .expect("PRODUCT: queued reply absent");
    assert!(
        queued_row["envelope"]["data"]["thread_tags"] == serde_json::json!([]),
        "PRODUCT: an unavailable root must record empty inheritance: {queued_row}"
    );
    drop(frozen);
    support::until(
        bob,
        None,
        "late tagged root to arrive",
        &["room", "read", r, "--json"],
        |out| {
            out.ndjson()
                .iter()
                .any(|row| row["entry_hash"] == late_hash)
        },
    );
    for (flags, original) in [
        (&late_flags[..], &queued),
        (&thread_flags[..], &thread_queued),
    ] {
        let retry = post_as(
            bob,
            "retrying",
            r,
            "say",
            flags,
            "same operation after root arrival",
        );
        assert!(
            retry.ok && retry.json()["entry_hash"] == original.json()["entry_hash"],
            "PRODUCT: root arrival must not change the reply operation's inherited tags: {retry:?}"
        );
    }
    let changed = post_as(
        bob,
        "retrying",
        r,
        "say",
        &[
            "--re",
            &late_hash,
            "--op",
            "late-tags-retry-756",
            "--project",
            "changed",
        ],
        "changed tag",
    );
    assert!(
        changed.code == Some(4),
        "PRODUCT: changed explicit tags must conflict after root arrival: {changed:?}"
    );
    let removed = post_as(
        bob,
        "retrying",
        r,
        "say",
        &["--thread", &late_hash, "--op", "late-thread-tags-756"],
        "removed tag",
    );
    assert!(
        removed.code == Some(4),
        "PRODUCT: removing an explicit tag must conflict: {removed:?}"
    );

    // Keep the reply while retention removes its older root. The wait creates that age gap;
    // the product's room read, not elapsed time, is the staging verdict.
    std::thread::sleep(std::time::Duration::from_secs(17).saturating_sub(root_age.elapsed()));
    let alice = &room.workers[0];
    let retained_flags = [
        "--re",
        &root_hash,
        "--op",
        "retained-tags-756",
        "--project",
        "explicit",
    ];
    let retained = post_as(
        alice,
        "holder",
        r,
        "say",
        &retained_flags,
        "RETAINED-TAG-REPLY",
    );
    assert!(
        retained.ok,
        "PRODUCT: reply before root retention refused: {retained:?}"
    );
    let retention = alice.vox(None, &["room", "retention", r, "15"]);
    assert!(
        retention.ok,
        "PRODUCT: retention command failed: {retention:?}"
    );
    support::until(
        alice,
        None,
        "old root to expire while its reply remains",
        &["room", "read", r, "--json"],
        |out| {
            let rows = out.ndjson();
            !rows.iter().any(|row| row["entry_hash"] == root_hash)
                && rows
                    .iter()
                    .any(|row| row["entry_hash"] == retained.json()["entry_hash"])
        },
    );
    let retry = post_as(
        alice,
        "holder",
        r,
        "say",
        &retained_flags,
        "same operation after root retention",
    );
    assert!(retry.ok && retry.json()["entry_hash"] == retained.json()["entry_hash"],
        "PRODUCT: losing the root must not remove inherited tags from an identical retry: {retry:?}");
    let retained_row = rows(alice, r)
        .into_iter()
        .find(|row| row["entry_hash"] == retained.json()["entry_hash"])
        .expect("PRODUCT: retained reply absent");
    assert!(
        retained_row["envelope"]["data"]["thread_tags"] == inherited,
        "PRODUCT: recorded inherited tags must survive the root: {retained_row}"
    );
    let changed = post_as(
        alice,
        "holder",
        r,
        "say",
        &["--re", &root_hash, "--op", "retained-tags-756"],
        "removed explicit tag",
    );
    assert!(
        changed.code == Some(4),
        "PRODUCT: losing the root must not hide an explicit tag change: {changed:?}"
    );
    eprintln!("[proof] #756 inherited tags stay fixed across late root arrival and root retention; explicit changes conflict");
}

/// A bounded caller of the existing terminal apparatus, within this same real-binary journey.
const TUI_REPLY: &str = r#"
import os, re, sys, traceback
sys.dont_write_bytecode = True
vox, data, cfg, helpers = sys.argv[1:]
sys.path.insert(0, helpers)
from vox_pty import Tui, arm, disarm, pane, pyte, stage
if pyte is None:
    print('APPARATUS: pyte is unavailable'); sys.exit(2)
env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'USER') if k in os.environ}
env.update(VOX_DATA_DIR=data, VOX_CONFIG_DIR=cfg, TERM='xterm-256color', VOX_PROXY='127.0.0.1:0')
tui = None
code = 2
class Product(Exception): pass
def need(ok, why):
    if not ok: raise Product(why + '\n' + tui.text())
arm(120, 'thread-tags')
try:
    stage('open tagged thread')
    tui = Tui([vox, 'tui', '--listen', '127.0.0.1:0'], env)
    tui.pump(2)
    if 'passphrase' in tui.text().lower(): tui.key('identity passphrase\r', 2)
    tui.key('\r', 1)
    need(tui.until(lambda: 'TUI-TAG-ROOT' in tui.text(), 30), 'TUI never drew the starting message')
    for _ in range(6):
        if any(re.search(r'┌Timeline[^┐]*\[focus\]', line) for line in tui.display()): break
        tui.key('\t', .2)
    selected = lambda: next((line for line in pane(tui.display(), 'Timeline') if '▶ ' in line), '')
    tui.key('\x1b[F', .2)
    tui.key('\x1b[A', .2)
    need('TUI-TAG-ROOT' in selected(), 'Up did not select the starting message')
    stage('type untagged reply')
    tui.key('\x12', .2)
    tui.key('TUI-REPLY-WITHOUT-TAGS', .2)
    tui.key('\r', .5)
    tui.key('\x1b[F', .5)  # End: follow the posted reply
    need(tui.until(lambda: 'you: TUI-REPLY-WITHOUT-TAGS' in tui.text(), 30), 'TUI did not show its posted reply')
    print('thread-tags PASS: TUI posted its reply'); code = 0
except Product as e:
    print('thread-tags RED PRODUCT:', e); code = 1
except Exception:
    print('thread-tags APPARATUS:', traceback.format_exc()); code = 2
finally:
    if tui is not None and not tui.stop():
        print('APPARATUS: TUI could not be reaped'); code = 2
    disarm()
sys.exit(code)
"#;
