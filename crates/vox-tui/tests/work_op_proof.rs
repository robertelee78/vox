//! ADR-021 M21.4 — **a retry is one operation, and a conflict is never silent**,
//! through the shipped `vox` binary against two real nodes and a live consumer.
//!
//! A worker that posts, loses the response and posts again has made one operation. It
//! says so by reusing `--op`. The log cannot tell on its own — a retry is a new entry
//! with a new hash — so the identity is `(author, op)`, and:
//!
//! 1. **a retry with the same content** returns the first entry and posts nothing new;
//! 2. **two entries that both got past the pre-post lookup** — concurrent retries — are
//!    still **one** operation: the fold applies it once, the stream marks the second a
//!    duplicate, and a later CLI retry reports it as already posted;
//! 3. **the same op with different content** is a conflict. It voids the operation on
//!    every node — neither entry has any effect — and a consumer that already recorded
//!    the first entry is told, **in the stream**, that it is now void. The CLI refuses a
//!    conflicting reuse with exit 4 and never reports success for it;
//! 4. **two conflicting posts racing** never both report success.
//!
//! Cases 2 and 3 need two entries under one `(author, op)` that the CLI's own lookup
//! would have prevented, which is precisely what a racing retry produces. They are
//! written onto the control socket as the bytes such a retry writes.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::BufRead as _;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use support::{post_raw, resource, until, Out, Worker, HARNESS_SESSION_VARS, VOX};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn rows_with_op(w: &Worker, r: &str, op: &str) -> Vec<serde_json::Value> {
    let o = w.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.ndjson()
        .into_iter()
        .filter(|x| x["op"]["id"] == op)
        .collect()
}

/// A claim exactly as `vox room claim` writes it (the fields that make up its
/// semantic content), under `op`.
fn claim_text(session: &str, res: &str, op: &str) -> String {
    serde_json::json!({
        "v": 1, "type": "claim", "from": session, "body": "a racing retry",
        "data": { "resource": res, "op": op, "vox": VERSION }
    })
    .to_string()
}

/// A live `vox room tail --since … --json` on `w`, its lines collected as they come.
struct Consumer {
    child: std::process::Child,
    lines: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Consumer {
    fn start(w: &Worker, r: &str, since: &str) -> Self {
        let mut cmd = Command::new(VOX);
        cmd.args(["room", "tail", r, "--since", since, "--json"])
            .env("VOX_DATA_DIR", &w.data)
            .env("VOX_CONFIG_DIR", &w.cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for v in HARNESS_SESSION_VARS {
            cmd.env_remove(v);
        }
        let mut child = cmd.spawn().expect("spawn tail");
        let out = child.stdout.take().unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                eprintln!("[tail] {l}");
                sink.lock()
                    .unwrap()
                    .push(serde_json::from_str(&l).expect("NDJSON"));
            }
        });
        Self { child, lines }
    }

    fn wait(&self, what: &str, pred: impl Fn(&[serde_json::Value]) -> bool) {
        let deadline = Instant::now() + support::TIMEOUT;
        while Instant::now() < deadline {
            if pred(&self.lines.lock().unwrap()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "the consumer never saw {what}: {:?}",
            self.lines.lock().unwrap()
        );
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_retry_is_one_operation_and_a_conflict_is_explicit() {
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

    // ---- (1) the same op, the same content: one entry ----
    let args = [
        "room",
        "post",
        r,
        "--type",
        "status",
        "--work",
        "gh:acme/w#1",
        "--op",
        "op-retry-0001",
        "--json",
        "-",
    ];
    let first = alice.vox_in(Some("a1"), &args, Some("porting the codec"));
    assert!(first.ok, "{first:?}");
    let again = alice.vox_in(
        Some("a1"),
        &args,
        Some("porting the codec — reworded on retry"),
    );
    assert!(again.ok, "a retry must succeed: {again:?}");
    assert_eq!(again.json()["status"], "already-posted", "{again:?}");
    assert_eq!(
        again.json()["entry_hash"],
        first.json()["entry_hash"],
        "a retry must name the SAME entry"
    );
    assert_eq!(
        rows_with_op(alice, r, "op-retry-0001").len(),
        1,
        "a retry must not post a second entry"
    );

    // The consumer starts here, on the OTHER node, from the current end of its log.
    let cursor = until(
        bob,
        None,
        "bob to see alice's status",
        &["room", "read", r, "--json"],
        |o: &Out| o.ok && o.ndjson().iter().any(|x| x["op"]["id"] == "op-retry-0001"),
    )
    .ndjson()
    .last()
    .unwrap()["entry_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let consumer = Consumer::start(bob, r, &cursor);

    // ---- (2) two entries past the lookup: still one operation ----
    for _ in 0..2 {
        rt.block_on(post_raw(
            alice,
            room.cid,
            &claim_text("a1", "dup-res", "op-race-0002"),
        ));
    }
    let o = alice.vox(
        Some("a1"),
        &[
            "room",
            "claim",
            r,
            "dup-res",
            "--op",
            "op-race-0002",
            "--json",
        ],
    );
    assert!(
        o.ok,
        "a retry of a duplicated operation reports the holding: {o:?}"
    );
    assert_eq!(o.json()["status"], "already-posted", "{o:?}");
    let dups = rows_with_op(alice, r, "op-race-0002");
    assert_eq!(dups.len(), 2, "two racing entries are both in the log");
    let statuses: std::collections::BTreeSet<String> = dups
        .iter()
        .map(|x| x["op"]["status"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        statuses,
        ["duplicate", "ok"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        "{dups:?}"
    );
    consumer.wait("both racing entries, one marked duplicate", |ls| {
        ls.iter()
            .filter(|x| x["op"]["id"] == "op-race-0002")
            .count()
            == 2
            && ls
                .iter()
                .any(|x| x["op"]["id"] == "op-race-0002" && x["op"]["status"] == "duplicate")
    });

    // ---- (3) the same op, different content: void everywhere, and said so ----
    let o = alice.vox(
        Some("a1"),
        &["room", "claim", r, "c-one", "--op", "op-conflict-03"],
    );
    assert!(o.ok && o.stdout.contains("you hold c-one"), "{o:?}");
    consumer.wait("the first claim, as an ordinary operation", |ls| {
        ls.iter()
            .any(|x| x["op"]["id"] == "op-conflict-03" && x["op"]["status"] == "ok")
    });
    // A racing retry of the SAME op that says something else — it got past its lookup.
    rt.block_on(post_raw(
        alice,
        room.cid,
        &claim_text("a1", "c-two", "op-conflict-03"),
    ));
    consumer.wait("the earlier entry re-emitted as a conflict", |ls| {
        let c: Vec<_> = ls
            .iter()
            .filter(|x| x["op"]["id"] == "op-conflict-03" && x["op"]["status"] == "conflict")
            .collect();
        // Both entries, each reported as conflict — the first one AGAIN, after it had
        // already been delivered as ok.
        c.iter()
            .any(|x| x["envelope"]["data"]["resource"] == "c-one")
            && c.iter()
                .any(|x| x["envelope"]["data"]["resource"] == "c-two")
    });
    for w in [alice, bob] {
        let b = until(
            w,
            None,
            "the conflict to void the claim",
            &["room", "board", r, "--json"],
            |o: &Out| o.ok && resource(&o.json(), "c-one").is_none(),
        )
        .json();
        assert!(
            resource(&b, "c-two").is_none(),
            "{}: a conflicted operation had an effect: {b}",
            w.name
        );
        assert!(
            resource(&b, "dup-res").is_some(),
            "{}: the duplicated operation must still hold: {b}",
            w.name
        );
        let conflicted = b["violations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["outcome"]["conflict"].is_array())
            .count();
        assert_eq!(
            conflicted, 2,
            "{}: both conflicting entries are reported: {b}",
            w.name
        );
    }
    let o = alice.vox(
        Some("a1"),
        &["room", "claim", r, "c-one", "--op", "op-conflict-03"],
    );
    assert_eq!(
        o.code,
        Some(4),
        "reusing a conflicted op must exit 4, never 0: {o:?}"
    );

    // ---- (4) two conflicting posts racing never both succeed ----
    let spawn = |n: u32| {
        let mut cmd = Command::new(VOX);
        cmd.args([
            "room",
            "post",
            r,
            "--type",
            "status",
            "--op",
            "op-race-conflict-4",
            "--data",
            &format!("{{\"n\":{n}}}"),
            "note",
        ])
        .env("VOX_DATA_DIR", &alice.data)
        .env("VOX_CONFIG_DIR", &alice.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        for v in HARNESS_SESSION_VARS {
            cmd.env_remove(v);
        }
        cmd.env("VOX_SESSION", "a1");
        cmd.spawn().unwrap()
    };
    let (p1, p2) = (spawn(1), spawn(2));
    let (o1, o2) = (
        p1.wait_with_output().unwrap(),
        p2.wait_with_output().unwrap(),
    );
    eprintln!(
        "[receipt] racing posts: exit {:?} {:?}",
        o1.status.code(),
        o2.status.code()
    );
    assert!(
        !(o1.status.success() && o2.status.success()),
        "two conflicting posts under one op both reported success"
    );
    assert!(
        [o1.status.code(), o2.status.code()].contains(&Some(4)),
        "the loser of a conflicting race must exit 4: {:?} {:?}",
        String::from_utf8_lossy(&o1.stderr),
        String::from_utf8_lossy(&o2.stderr)
    );
    let entries = rows_with_op(alice, r, "op-race-conflict-4");
    if entries.len() == 2 {
        assert!(
            entries.iter().all(|x| x["op"]["status"] == "conflict"),
            "{entries:?}"
        );
    }
}
