//! ADR-021 M21.5 — **the adapter stream has no gaps across lag, crash and restart**,
//! and `board --json` is the fold of the rows, through the shipped `vox` binary.
//!
//! A tracker's adapter is a program that consumes a room with `vox room tail --since
//! <cursor> --json`, persists its cursor after processing each row, and resumes from
//! it. What it must be able to rely on is the one property ADR-021 §7 promises:
//! **duplicates across a restart are permitted; gaps are not.**
//!
//! What this drives, on the consumer's node (bob) while two nodes produce:
//!
//! - **1,800 messages**, 900 from bob's own node and 900 from alice's — so both the
//!   local path (`NewEntry`) and the synced path (`Synced`, which carries no row) are
//!   exercised, the second being the one `tail` used to drop entirely.
//!
//!   Not 2,000 as ADR-021 first planned: ADR-008's per-author quota admits at most
//!   1,000 entries per member per sliding hour (`log/quota.rs`), and refuses the rest —
//!   reported, wrongly, as `Failed(Internal)`, which is ADR-021 open defect F14. 900 per
//!   member stays under the quota with room for the set-up entries;
//! - a consumer that **stops reading its pipe** while all 900 of bob's own appends
//!   land — about twice what the node's 256-event buffer plus the pipe and socket
//!   buffers hold — so it is told it lagged; and the proof fails if that never
//!   happened, because an un-lagged run proves nothing about lag. Two earlier versions
//!   (a stall during a trickle, then under 450 appends) never lagged, and failed for
//!   exactly that reason;
//! - the consumer **killed three times** with SIGKILL at points inside the bursts, each
//!   time restarted from the cursor it had persisted.
//!
//! What it asserts: the union of every row the consumer emitted, after the starting
//! cursor, **equals** the room's log after that cursor — no gap — and every duplicate
//! is explained by a restart. Then, separately: `board --json` equals the ownership the
//! claim fold computes independently from the same rows.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use support::{until, Out, Worker, HARNESS_SESSION_VARS, VOX};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One run of the consumer: a `tail` process, and a reader thread that forwards its
/// lines — unless paused, when it stops reading the pipe altogether, so the pipe fills,
/// `tail` blocks writing, and the node's buffer overflows for it.
struct Run {
    child: std::process::Child,
    rx: std::sync::mpsc::Receiver<String>,
    paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

fn start(w: &Worker, r: &str, cursor: &str, stderr: &std::path::Path) -> Run {
    let mut cmd = Command::new(VOX);
    cmd.args(["room", "tail", r, "--since", cursor, "--json"])
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(stderr)
                .unwrap(),
        );
    for v in HARNESS_SESSION_VARS {
        cmd.env_remove(v);
    }
    let mut child = cmd.spawn().expect("spawn tail");
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let paused = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let p = paused.clone();
    std::thread::spawn(move || loop {
        while p.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut line = String::new();
        match lines.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if tx.send(line).is_err() {
                    return;
                }
            }
        }
    });
    Run { child, rx, paused }
}

/// Process up to `n` rows, waiting at most `idle` for each, persisting the cursor after
/// each — exactly what a tracker's adapter does. Returns how many it processed.
fn consume(
    run: &Run,
    n: usize,
    idle: Duration,
    cursor: &mut String,
    seen: &mut BTreeMap<String, u32>,
) -> usize {
    let mut got = 0;
    while got < n {
        let Ok(line) = run.rx.recv_timeout(idle) else {
            break;
        };
        let row: serde_json::Value = serde_json::from_str(line.trim()).expect("NDJSON row");
        assert_eq!(
            row["schema"], "vox.room.row/1",
            "an adapter must refuse any other schema"
        );
        let h = row["entry_hash"].as_str().unwrap().to_owned();
        *seen.entry(h.clone()).or_default() += 1;
        *cursor = h; // persisted AFTER processing
        got += 1;
    }
    got
}

fn say(i: usize) -> String {
    format!("burst message {i:05}")
}

#[test]
#[ignore = "two networked nodes, production Argon2id and a 1,800-message burst; CI runs it in release"]
fn a_consumer_that_lags_and_crashes_three_times_misses_nothing() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.clone();
    let cid = room.cid;

    // ---- the fold half: a contested claim, a completed handoff, a lapse ----
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", &r, "contested"])
            .ok
    );
    until(
        bob,
        None,
        "the claim to reach bob",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), "contested").is_some(),
    );
    assert_eq!(
        bob.vox(Some("b1"), &["room", "claim", &r, "contested"])
            .code,
        Some(1)
    );
    assert!(alice.vox(Some("a1"), &["room", "claim", &r, "passed"]).ok);
    assert!(
        alice
            .vox(
                Some("a1"),
                &["room", "handoff", &r, "passed", "--to", &bob.b32()[..16]]
            )
            .ok
    );
    until(
        bob,
        None,
        "the handoff to reach bob",
        &["room", "board", &r, "--json"],
        |o: &Out| {
            o.ok && support::resource(&o.json(), "passed").is_some_and(|x| x["state"] == "pending")
        },
    );
    assert!(bob.vox(Some("b1"), &["room", "claim", &r, "passed"]).ok);
    assert!(
        bob.vox(Some("b1"), &["room", "claim", &r, "lapsed", "--ttl", "1"])
            .ok
    );
    std::thread::sleep(Duration::from_secs(2));
    until(
        bob,
        None,
        "bob to hold everything alice posted",
        &["room", "read", &r, "--json"],
        |o: &Out| {
            o.ok && o.ndjson().len()
                == alice
                    .vox(None, &["room", "read", &r, "--json"])
                    .ndjson()
                    .len()
        },
    );
    let rows = bob.vox(None, &["room", "read", &r, "--json"]).ndjson();
    let posted: Vec<vox_agentcomms::Posted> = rows
        .iter()
        .filter_map(|x| {
            let env = vox_agentcomms::Envelope::parse(x["text"].as_str()?).ok()?;
            Some(vox_agentcomms::Posted {
                entry_hash: vox_agentcomms::claim::from_b32(x["entry_hash"].as_str()?)?,
                author: vox_agentcomms::claim::from_b32(x["author"].as_str()?)?,
                created_millis: x["created_millis"].as_u64()?,
                envelope: env,
            })
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let independent = vox_agentcomms::claim::fold(&posted, VERSION, now);
    let board = bob.vox(None, &["room", "board", &r, "--json"]).json();
    let from_board: BTreeMap<String, (String, String)> = board["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["resource"].as_str().unwrap().to_owned(),
                (
                    x["owner_fp"].as_str().unwrap_or("").to_owned(),
                    x["owner_session"].as_str().unwrap_or("").to_owned(),
                ),
            )
        })
        .collect();
    let from_fold: BTreeMap<String, (String, String)> = independent
        .resources
        .iter()
        .map(|(k, s)| match s {
            vox_agentcomms::State::Held { owner, .. } => (
                k.clone(),
                (
                    vox_agentcomms::claim::b32(&owner.author),
                    owner.session.clone(),
                ),
            ),
            vox_agentcomms::State::Pending { .. } => (k.clone(), (String::new(), String::new())),
        })
        .collect();
    assert_eq!(
        from_board, from_fold,
        "board --json is not the fold of the room's rows"
    );
    assert_eq!(
        from_board.get("contested").map(|x| x.1.as_str()),
        Some("a1")
    );
    assert_eq!(from_board.get("passed").map(|x| x.1.as_str()), Some("b1"));
    assert!(!from_board.contains_key("lapsed"));
    eprintln!("[proof] board --json == independent fold: {from_board:?}");

    // ---- the stream half ----
    let start_cursor = rows.last().unwrap()["entry_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let stderr = tmp.path().join("tail.stderr");

    // The producer, driven in phases by the proof so a burst lands exactly while the
    // consumer is not reading.
    let mut n = 0usize;
    let mut burst = |w: &Worker, count: usize| {
        let sock = w.paths.socket_file();
        let first = n;
        n += count;
        rt.block_on(async move {
            let mut c = vox_core::node::ipc::IpcClient::open(&sock).await.unwrap();
            for i in first..first + count {
                match c
                    .request(&vox_core::node::ipc::Request::Post {
                        channel_id: cid,
                        text: say(i),
                    })
                    .await
                {
                    Ok(vox_core::node::ipc::Frame::Ok) => {}
                    other => panic!("post {i}: {other:?}"),
                }
            }
        });
    };

    let mut cursor = start_cursor.clone();
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    let mut restarts = 0;
    let idle = Duration::from_secs(10);
    let kill = |run: &mut Run, restarts: &mut u32, cursor: &str, seen: &BTreeMap<String, u32>| {
        run.child.kill().unwrap(); // SIGKILL, mid-stream
        let _ = run.child.wait();
        *restarts += 1;
        eprintln!(
            "[proof] killed consumer run {restarts} at cursor {cursor} after {} distinct rows",
            seen.len()
        );
    };

    // Run 1: stall while all 900 of bob's local appends land. The pipe (~120 rows),
    // the reader's buffer, the socket buffers (~50 frames) and the node's 256-event
    // buffer together hold roughly 450 events; 900 is twice that, so the stream MUST lag.
    // (450 was tried first and never lagged — it only just filled the headroom.)
    let mut run = start(bob, &r, &cursor, &stderr);
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    burst(bob, 900);
    std::thread::sleep(Duration::from_secs(2));
    run.paused.store(false, std::sync::atomic::Ordering::SeqCst);
    consume(&run, 300, idle, &mut cursor, &mut seen);
    kill(&mut run, &mut restarts, &cursor, &seen);
    // Run 2: die in the middle of a synced burst from the other node.
    let mut run = start(bob, &r, &cursor, &stderr);
    // First drain the backlog run 1 left, so every row counted below is one that
    // arrived by sync WHILE this consumer was running.
    while consume(&run, 1000, Duration::from_secs(3), &mut cursor, &mut seen) > 0 {}
    burst(alice, 300);
    // LIVENESS, not just completeness: rows synced from another node must reach a
    // consumer while it runs. A stream that only delivered them after a restart would
    // still have no gap — the defect `tail` shipped with — so this is its own assertion.
    let live = consume(&run, 200, idle, &mut cursor, &mut seen);
    assert_eq!(
        live, 200,
        "rows synced from another node must reach a LIVE consumer, not only a restarted one"
    );
    kill(&mut run, &mut restarts, &cursor, &seen);
    // Run 3: stall under another synced burst, then die.
    let mut run = start(bob, &r, &cursor, &stderr);
    consume(&run, 50, idle, &mut cursor, &mut seen);
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    burst(alice, 300);
    std::thread::sleep(Duration::from_secs(2));
    run.paused.store(false, std::sync::atomic::Ordering::SeqCst);
    consume(&run, 250, idle, &mut cursor, &mut seen);
    kill(&mut run, &mut restarts, &cursor, &seen);
    // The rest, while nobody is listening.
    burst(alice, 300);
    assert_eq!(n, 1800);

    let all = until(
        bob,
        None,
        "bob to hold all 1,800 messages",
        &["room", "read", &r, "--json"],
        |o: &Out| {
            o.ok && o
                .ndjson()
                .iter()
                .filter(|x| {
                    x["text"]
                        .as_str()
                        .is_some_and(|t| t.starts_with("burst message"))
                })
                .count()
                == 1800
        },
    )
    .ndjson();
    let after: Vec<String> = all
        .iter()
        .map(|x| x["entry_hash"].as_str().unwrap().to_owned())
        .skip_while(|h| *h != start_cursor)
        .skip(1)
        .collect();
    assert_eq!(
        after.len(),
        1800,
        "the log after the starting cursor is the burst"
    );

    let mut run = start(bob, &r, &cursor, &stderr);
    let expected: BTreeSet<&String> = after.iter().collect();
    // Drain until every expected row has arrived, or nothing arrives for 20 s — then
    // whatever is missing is a GAP, reported by name rather than waited on for ever.
    while expected.iter().any(|h| !seen.contains_key(*h)) {
        if consume(&run, 200, Duration::from_secs(20), &mut cursor, &mut seen) == 0 {
            break;
        }
    }
    let _ = run.child.kill();
    let _ = run.child.wait();

    let missing: Vec<&&String> = expected
        .iter()
        .filter(|h| !seen.contains_key(**h))
        .collect();
    let extra: Vec<&String> = seen.keys().filter(|h| !expected.contains(h)).collect();
    let dups = seen.values().filter(|c| **c > 1).count();
    let lags = std::fs::read_to_string(&stderr)
        .unwrap_or_default()
        .matches("fell behind")
        .count();
    eprintln!(
        "[proof] expected {} rows; emitted {} distinct; missing {}; extra {}; duplicated {dups}; restarts {restarts}; lag reports {lags}",
        expected.len(),
        seen.len(),
        missing.len(),
        extra.len()
    );
    assert!(
        missing.is_empty(),
        "GAP: {} rows after the cursor were never emitted: {:?}",
        missing.len(),
        &missing[..missing.len().min(5)]
    );
    assert!(
        extra.is_empty(),
        "rows from before the starting cursor were emitted: {extra:?}"
    );
    assert!(
        lags > 0,
        "the consumer never lagged, so this run proved nothing about lag"
    );
    assert!(
        dups as u32 <= restarts * 600,
        "duplicates beyond what restarts explain: {dups}"
    );
}
