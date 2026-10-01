//! ADR-021 M21.5 — **the adapter stream has no gaps across lag, crash and restart**,
//! and a second client on the same node is never stalled or cut by the first (RP-18, RP-45),
//! through the shipped `vox` binary.
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
//!   900 per member was chosen under ADR-008's per-author quota, which PRD-001 R3 has
//!   since removed (`wire.rs` 0x06 is RESERVED); the count is kept, and the lag is
//!   forced by bytes instead (below);
//! - a consumer that is **frozen (SIGSTOP)** while all 900 of bob's own appends land,
//!   each padded to 8 KiB, so the rows past the node's 256-event queue carry about
//!   5 MiB — far more than a Unix socket buffer holds — and it is told it lagged; the
//!   proof fails if that never happened, because an un-lagged run proves nothing about
//!   lag. Three earlier versions (a stall during a trickle, then under 450 and 900
//!   short appends, the last green on macOS and red on GitHub's ubuntu runner) depended
//!   on how many *bytes* a machine's buffers hold, and failed for exactly that reason;
//! - the consumer **killed three times** with SIGKILL at points inside the bursts, each
//!   time restarted from the cursor it had persisted.
//!
//! - a **second consumer** of the same room on the same node, attached at the same time
//!   and never paused or killed, as a second tracker's adapter would be (RP-18, RP-45).
//!
//! What it asserts: the union of every row the consumer emitted, after the starting
//! cursor, **equals** the room's log after that cursor — no gap — and every duplicate
//! is explained by a restart. Then, separately: `board --json` shows what a person expects
//! of the claims made through the CLI — the contested resource held by alice's session, the
//! handed-off one by bob's, the lapsed claim gone.
//!
//! Every message is posted with `vox room post`, as a person or an agent posts.
//!
//! And of the second consumer, which shares the node with the first throughout:
//! - **a wedged client cannot stall the node** (RP-45): while the first is frozen, the
//!   second receives all 900 of bob's appends before the first is continued;
//! - **one client dying disturbs no other** (RP-18): across the first's three SIGKILLs it
//!   keeps running and ends holding every one of the 1,800 messages, with no restart.
//!
//! Every red says whose it is: `PRODUCT:` for what the node or `vox room tail` did,
//! `CANNOT MEASURE:` for staging that was not achieved.
//!
//! ## Mutations
//! - the node's subscription pumps share one lock across their socket writes: the frozen
//!   client's full socket holds it, and the second client receives nothing while it is
//!   frozen (RP-45 goes red);
//! - a client's death ends every subscription: the second client is cut off at the first
//!   SIGKILL and misses the rest (RP-18 goes red).

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

/// Whatever path leaves the proof — a red included, above all the expected one at a frozen
/// consumer — takes its `tail` with it: resumed (a stopped process outlives its parent as an
/// orphan in state T), killed and reaped, by its own handle. A child already reaped is left
/// alone, so no PID that may since have been reused is ever signalled.
impl Drop for Run {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = Command::new("kill")
                .args(["-CONT", &self.child.id().to_string()])
                .status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Send `sig` (`-STOP`, `-CONT`) to the consumer by its PID.
fn signal(run: &Run, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &run.child.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        ok,
        "CANNOT MEASURE: staging not achieved — `kill {sig} {}` failed",
        run.child.id()
    );
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
        let row: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| {
            panic!(
                "PRODUCT: `vox room tail --json` printed a line that is not JSON ({e}): {line:?}"
            )
        });
        assert_eq!(
            row["schema"], "vox.room.row/1",
            "PRODUCT: `vox room tail --json` printed a row of another schema"
        );
        let h = row["entry_hash"].as_str().unwrap().to_owned();
        *seen.entry(h.clone()).or_default() += 1;
        *cursor = h; // persisted AFTER processing
        got += 1;
    }
    got
}

/// The second consumer (RP-18, RP-45): a `tail` of the same room on the same node, never
/// paused or killed, its rows drained by a thread of its own as fast as they arrive — a
/// second tracker's adapter, attached alongside the first.
struct Steady {
    run: Run,
    rows: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Steady {
    fn start(w: &Worker, r: &str, cursor: &str, stderr: &std::path::Path) -> Self {
        let mut run = start(w, r, cursor, stderr);
        let (tx, rx) = std::sync::mpsc::channel();
        let feed = std::mem::replace(&mut run.rx, rx);
        drop(tx);
        let rows = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let into = rows.clone();
        std::thread::spawn(move || {
            while let Ok(line) = feed.recv() {
                let row: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_default();
                if let Some(h) = row["entry_hash"].as_str() {
                    into.lock().unwrap().push(h.to_owned());
                }
            }
        });
        Self { run, rows }
    }

    /// The distinct rows it has emitted so far.
    fn distinct(&self) -> BTreeSet<String> {
        self.rows.lock().unwrap().iter().cloned().collect()
    }

    /// Wait up to `secs` for it to hold at least `n` distinct rows; how many it holds.
    fn wait_for(&self, n: usize, secs: u64) -> usize {
        let end = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let have = self.distinct().len();
            if have >= n || std::time::Instant::now() >= end {
                return have;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn say(i: usize, pad: usize) -> String {
    format!("burst message {i:05}{}", " ".repeat(pad))
}

/// Padding for the burst that must make the consumer lag.
///
/// **The lag is forced, not hoped for.** The node reports `Lagged` only once its
/// 256-event queue (`EVENT_QUEUE`) is full behind a subscriber that has stopped reading,
/// and the kernel's socket buffer absorbs rows before that. The v0.2.9 release run went
/// red here on GitHub's ubuntu runner (1800/1800 delivered, 0 lag reports), and making
/// it deterministic took two things:
///
/// - the consumer must be **subscribed before it stalls** (see run 1): stalled any
///   earlier, it has no subscription for anything to fall behind, and it catches up by
///   an ordinary read afterwards. With padding alone it still lagged in only 1 run of 3;
/// - it is then **frozen** (SIGSTOP), so nothing drains the socket, and at 8 KiB a row
///   the 643 rows past the queue carry about 5 MiB where a default Unix socket buffer is
///   a few hundred KiB. A machine whose buffer held more would fail this proof loudly,
///   by the precondition below, rather than pass it.
///
/// Not larger: 32 KiB rows (29 MiB in bob's log) slowed the sync to alice enough that
/// her next burst missed the liveness window below.
const LAG_PAD: usize = 8 * 1024;

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

    // ---- the fold half: a contested claim, a completed handoff, a lapse ----
    let o = alice.vox(Some("a1"), &["room", "claim", &r, "contested"]);
    assert!(
        o.ok,
        "PRODUCT: alice's claim of a free resource was refused: {o:?}"
    );
    until(
        bob,
        None,
        "the claim to reach bob",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), "contested").is_some(),
    );
    let o = bob.vox(Some("b1"), &["room", "claim", &r, "contested"]);
    assert_eq!(
        o.code,
        Some(1),
        "PRODUCT: bob's claim of a resource alice holds did not exit 1: {o:?}"
    );
    let o = alice.vox(Some("a1"), &["room", "claim", &r, "passed"]);
    assert!(
        o.ok,
        "PRODUCT: alice's claim of a free resource was refused: {o:?}"
    );
    let o = alice.vox(
        Some("a1"),
        &["room", "handoff", &r, "passed", "--to", &bob.b32()[..16]],
    );
    assert!(o.ok, "PRODUCT: alice's handoff to bob was refused: {o:?}");
    until(
        bob,
        None,
        "the handoff to reach bob",
        &["room", "board", &r, "--json"],
        |o: &Out| {
            o.ok && support::resource(&o.json(), "passed").is_some_and(|x| x["state"] == "pending")
        },
    );
    let o = bob.vox(Some("b1"), &["room", "claim", &r, "passed"]);
    assert!(
        o.ok,
        "PRODUCT: bob could not take the resource handed to him: {o:?}"
    );
    let o = bob.vox(Some("b1"), &["room", "claim", &r, "lapsed", "--ttl", "1"]);
    assert!(
        o.ok,
        "PRODUCT: bob's claim of a free resource was refused: {o:?}"
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
    // What the board must show, as a person reads it: the contested resource held by alice's
    // session `a1`, the handed-off one by bob's session `b1`, and the lapsed claim gone. (The
    // comparison with `vox_agentcomms::claim::fold` is gone: the board is that fold, so it could
    // not fail.)
    assert_eq!(
        from_board.get("contested"),
        Some(&(alice.b32(), "a1".to_owned())),
        "PRODUCT: board --json does not show alice's session a1 holding the contested resource: \
         {board}"
    );
    assert_eq!(
        from_board.get("passed"),
        Some(&(bob.b32(), "b1".to_owned())),
        "PRODUCT: board --json does not show bob's session b1 holding the handed-off resource: \
         {board}"
    );
    assert!(
        !from_board.contains_key("lapsed"),
        "PRODUCT: board --json still shows a claim whose ttl lapsed: {board}"
    );
    eprintln!("[proof] board --json: {from_board:?}");

    // ---- the stream half ----
    let start_cursor = rows.last().unwrap()["entry_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let stderr = tmp.path().join("tail.stderr");

    // The producer, driven in phases by the proof so a burst lands exactly while the
    // consumer is not reading: `vox room post`, as a person or an agent posts.
    let mut n = 0usize;
    let mut burst = |w: &Worker, count: usize, pad: usize| {
        let first = n;
        n += count;
        for i in first..first + count {
            let o = w.vox(None, &["room", "post", &r, &say(i, pad)]);
            assert!(
                o.ok,
                "PRODUCT: `vox room post` of message {i} failed: {o:?}"
            );
        }
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

    // The second consumer (RP-18, RP-45), attached alongside the first from the same cursor
    // and left alone for the whole run.
    let steady_err = tmp.path().join("steady.stderr");
    let mut steady = Steady::start(bob, &r, &start_cursor, &steady_err);

    // Run 1: freeze the consumer while 899 of bob's 900 local appends land, each padded
    // to LAG_PAD, so the stream MUST lag whatever the machine's socket buffer (see LAG_PAD).
    let mut run = start(bob, &r, &cursor, &stderr);
    // **Subscribed first, then frozen.** `tail` subscribes before it reads its backlog,
    // so a row it emits proves it is subscribed. Frozen any earlier, it has no
    // subscription yet: nothing falls behind, and it catches up afterwards by an
    // ordinary read — which is how a run could deliver everything and never lag.
    burst(bob, 1, 0);
    assert_eq!(
        consume(&run, 1, idle, &mut cursor, &mut seen),
        1,
        "CANNOT MEASURE: staging not achieved — the consumer was not subscribed and live \
         before it was to be frozen (no row within {idle:?})"
    );
    // Both clients are attached and live before one is frozen: the staging RP-18 and RP-45
    // need.
    assert_eq!(
        steady.wait_for(1, 10),
        1,
        "CANNOT MEASURE: staging not achieved — the second consumer was not subscribed and \
         live before the first was to be frozen (no row within 10s)"
    );
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    signal(&run, "-STOP"); // frozen: it reads nothing, so only the kernel buffer absorbs
    burst(bob, 899, LAG_PAD);
    // **A wedged client cannot stall the node** (RP-45): while the first is still frozen,
    // the second receives every one of bob's 900 appends.
    let during = steady.wait_for(900, 60);
    eprintln!("[proof] while one client was frozen, the other received {during} of 900 rows");
    assert_eq!(
        during, 900,
        "PRODUCT: while one `vox room tail` was frozen, the other received only {during} of \
         bob's 900 appends within 60s — a wedged client stalled the node"
    );
    std::thread::sleep(Duration::from_secs(2));
    signal(&run, "-CONT");
    run.paused.store(false, std::sync::atomic::Ordering::SeqCst);
    consume(&run, 300, idle, &mut cursor, &mut seen);
    kill(&mut run, &mut restarts, &cursor, &seen);
    // Run 2: die in the middle of a synced burst from the other node.
    let mut run = start(bob, &r, &cursor, &stderr);
    // First drain the backlog run 1 left, so every row counted below is one that
    // arrived by sync WHILE this consumer was running.
    while consume(&run, 1000, Duration::from_secs(3), &mut cursor, &mut seen) > 0 {}
    burst(alice, 300, 0);
    // LIVENESS, not just completeness: rows synced from another node must reach a
    // consumer while it runs. A stream that only delivered them after a restart would
    // still have no gap — the defect `tail` shipped with — so this is its own assertion.
    let live = consume(&run, 200, idle, &mut cursor, &mut seen);
    assert_eq!(
        live, 200,
        "PRODUCT: rows synced from another node must reach a LIVE consumer, not only a \
         restarted one"
    );
    kill(&mut run, &mut restarts, &cursor, &seen);
    // Run 3: stall under another synced burst, then die.
    let mut run = start(bob, &r, &cursor, &stderr);
    consume(&run, 50, idle, &mut cursor, &mut seen);
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    burst(alice, 300, 0);
    std::thread::sleep(Duration::from_secs(2));
    run.paused.store(false, std::sync::atomic::Ordering::SeqCst);
    consume(&run, 250, idle, &mut cursor, &mut seen);
    kill(&mut run, &mut restarts, &cursor, &seen);
    // The rest, while nobody is listening.
    burst(alice, 300, 0);

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
        "CANNOT MEASURE: staging not achieved — the log after the starting cursor is not the \
         1,800-message burst"
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

    // **One client dying disturbs no other** (RP-18): the second consumer, attached
    // throughout, survived the first's three SIGKILLs and holds every message.
    let held = steady.wait_for(1800, 60);
    let still_running = steady.run.child.try_wait().ok().flatten().is_none();
    let steady_said = std::fs::read_to_string(&steady_err).unwrap_or_default();
    let _ = steady.run.child.kill();
    let _ = steady.run.child.wait();
    let steady_rows = steady.distinct();
    let steady_missing = expected
        .iter()
        .filter(|h| !steady_rows.contains(**h))
        .count();
    let steady_dups = steady.rows.lock().unwrap().len() - steady_rows.len();
    eprintln!(
        "[proof] second client: {held} distinct rows held; missing {steady_missing} of {}; \
         duplicated {steady_dups}; still running {still_running}; lag reports {}",
        expected.len(),
        steady_said.matches("fell behind").count()
    );
    assert!(
        still_running,
        "PRODUCT: the second `vox room tail` ended on its own while the first was killed \
         {restarts} times. It said: {steady_said}"
    );
    assert_eq!(
        steady_missing,
        0,
        "PRODUCT: the second `vox room tail`, attached throughout, never received \
         {steady_missing} of the {} messages after the first was killed {restarts} times",
        expected.len()
    );

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
        "PRODUCT: GAP: {} rows after the cursor were never emitted: {:?}",
        missing.len(),
        &missing[..missing.len().min(5)]
    );
    assert!(
        extra.is_empty(),
        "PRODUCT: rows from before the starting cursor were emitted: {extra:?}"
    );
    assert!(
        lags > 0,
        "CANNOT MEASURE: staging not achieved — the consumer never lagged, so this run proved \
         nothing about lag"
    );
    assert!(
        dups as u32 <= restarts * 600,
        "PRODUCT: duplicates beyond what restarts explain: {dups}"
    );
}
