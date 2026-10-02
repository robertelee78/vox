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
//! - then the consumer's **node** killed with SIGKILL and started again (ADR-021 F19), after
//!   alice and bob have posted alternately so bob's local order differs from canonical
//!   order (the proof says CANNOT MEASURE if it does not).
//!
//! - a **second consumer** of the same room on the same node, attached at the same time
//!   and never paused or killed, as a second tracker's adapter would be (RP-18, RP-45).
//!
//! What it asserts: the union of every row the consumer emitted, after the starting
//! cursor, **equals** the room's log after that cursor — no gap — and every duplicate
//! is explained by a restart, and while one consumer runs every row synced to it is emitted
//! **once** (V210-113).
//!
//! Every message is posted with `vox room post`, as a person or an agent posts.
//!
//! And of the second consumer, which shares the node with the first throughout:
//! - **a wedged client cannot stall the node** (RP-45): while the first is frozen, the
//!   second receives all 900 of bob's appends before the first is continued;
//! - **one client dying disturbs no other** (RP-18): across the first's three SIGKILLs it
//!   keeps running and ends holding every one of the 1,800 messages, with no restart.
//!
//! And across the node's restart (ADR-021 F19, on ADR-023's one order): a room is shown in one
//! deterministic order, and a cursor means **what arrived after it** (`--since` is
//! arrival-based, so a late row that lands *above* the cursor in the room's order is still
//! after it). Both are rebuilt from the sealed cache when the node reopens. So the proof stages
//! a cursor with a late row after it: bob's own post, which bob holds before alice's earlier
//! one reaches him. It asserts:
//! - `vox room read` shows every row in **the same order** after the restart;
//! - `tail --since` that cursor resumes with **exactly the rows that arrived after it, in the
//!   order they arrived**, the late row included.
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
use std::time::{Duration, Instant};

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
    /// The entry hashes of the rows that are the proof's own burst messages ([`say`]).
    bursts: std::sync::Arc<std::sync::Mutex<BTreeSet<String>>>,
    /// Every other row it emitted, as `hash text`, for the record: a room's own traffic (a
    /// setup row arriving late) is not one of the counted messages.
    others: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Steady {
    fn start(w: &Worker, r: &str, cursor: &str, stderr: &std::path::Path) -> Self {
        let mut run = start(w, r, cursor, stderr);
        let (tx, rx) = std::sync::mpsc::channel();
        let feed = std::mem::replace(&mut run.rx, rx);
        drop(tx);
        let rows = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let bursts = std::sync::Arc::new(std::sync::Mutex::new(BTreeSet::new()));
        let others = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (into, into_bursts, into_others) = (rows.clone(), bursts.clone(), others.clone());
        std::thread::spawn(move || {
            while let Ok(line) = feed.recv() {
                let row: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_default();
                if let Some(h) = row["entry_hash"].as_str() {
                    into.lock().unwrap().push(h.to_owned());
                    let text = row["text"].as_str().unwrap_or("");
                    if text.starts_with(BURST) {
                        into_bursts.lock().unwrap().insert(h.to_owned());
                    } else {
                        into_others.lock().unwrap().push(format!("{h} {text:.80}"));
                    }
                }
            }
        });
        Self {
            run,
            rows,
            bursts,
            others,
        }
    }

    /// The distinct rows it has emitted so far.
    fn distinct(&self) -> BTreeSet<String> {
        self.rows.lock().unwrap().iter().cloned().collect()
    }

    /// Wait up to `secs` for it to hold at least `n` of the proof's burst messages; how many
    /// it holds. Only those are counted: any other row the room carries is not a message this
    /// proof sent, and counting it once read a wedge as 901 of 900.
    fn wait_for(&self, n: usize, secs: u64) -> usize {
        let end = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let have = self.bursts.lock().unwrap().len();
            if have >= n || std::time::Instant::now() >= end {
                return have;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// What every one of the proof's own messages starts with.
const BURST: &str = "burst message ";

fn say(i: usize, pad: usize) -> String {
    format!("{BURST}{i:05}{}", " ".repeat(pad))
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
    let t0 = std::time::Instant::now();
    macro_rules! mark {
        ($n:expr) => {
            eprintln!("[phase] {:>7.1}s {}", t0.elapsed().as_secs_f64(), $n)
        };
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.clone();
    mark!("room ready");

    // **The room settled before the stream half starts**: what the room's setup posts (the
    // workers' greetings, their trust) must all be on bob's node before the starting cursor is
    // taken, or a late one arrives after it and the consumers' first row is not the one the
    // proof posted. Settled is the same count on both nodes, three reads a second apart.
    let count = |w: &Worker| w.vox(None, &["room", "read", &r, "--json"]).ndjson().len();
    let settled = Instant::now();
    let mut same = 0;
    let mut last = usize::MAX;
    while same < 3 {
        assert!(
            settled.elapsed() < Duration::from_secs(120),
            "CANNOT MEASURE: the room never settled before the stream half (bob {}, alice {})",
            count(bob),
            count(alice)
        );
        let (b, a) = (count(bob), count(alice));
        same = if b == a && b == last { same + 1 } else { 0 };
        last = b;
        std::thread::sleep(Duration::from_secs(1));
    }
    // **The starting cursor is a row bob posts now**, after the room settled: last to arrive on
    // bob's node and, posted last, last in the room's order too. `tail --since` follows arrival
    // and `read` follows the room's order, and on v0.3.0 the two differ; the last row of a read
    // can have arrived before a row it sorts after, which `tail --since` then rightly emits (a
    // late setup row did, read as "a row from before the cursor").
    let o = bob.vox(
        None,
        &["room", "post", &r, "harness: the stream starts here"],
    );
    assert!(o.ok, "PRODUCT: bob's start marker was refused: {o:?}");
    let rows = bob.vox(None, &["room", "read", &r, "--json"]).ndjson();

    // ---- the stream half ----
    let start_cursor = rows
        .iter()
        .find(|x| x["text"] == "harness: the stream starts here")
        .and_then(|x| x["entry_hash"].as_str())
        .unwrap_or_else(|| {
            panic!("PRODUCT: bob's own start marker is not in his `read --json`: {rows:?}")
        })
        .to_owned();
    assert_eq!(
        rows.last().and_then(|x| x["entry_hash"].as_str()),
        Some(start_cursor.as_str()),
        "CANNOT MEASURE: bob's start marker is not the last row of the settled room"
    );
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
    // **The red says what it saw** (the lead, on c2): no row at all, the one message, more than
    // it, or rows that were not it are four different things.
    let live = steady.wait_for(1, 10);
    let others = steady.others.lock().unwrap().clone();
    match (live, others.is_empty()) {
        // Live, and the one message arrived. Another row beside it is the room's own traffic,
        // not counted (`wait_for` counts only the proof's messages), and is printed below.
        (1, _) => {}
        (0, true) => panic!(
            "CANNOT MEASURE: staging not achieved — the second consumer emitted no row within 10s \
             of bob's first message, so it was not subscribed and live before the first was to \
             be frozen"
        ),
        (0, false) => panic!(
            "PRODUCT: the second consumer was live — it emitted {} other row(s): {others:?} — but \
             not bob's first message within 10s of its posting",
            others.len()
        ),
        (n, _) => panic!(
            "APPARATUS: the second consumer emitted {n} of the proof's messages where 1 was \
             posted, and other rows {others:?}: the staging posted more than it counts on"
        ),
    }
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    signal(&run, "-STOP"); // frozen: it reads nothing, so only the kernel buffer absorbs
    burst(bob, 899, LAG_PAD);
    mark!("run1 burst 899 posted");
    // **A wedged client cannot stall the node** (RP-45): while the first is still frozen,
    // the second receives every one of bob's 900 appends.
    let during = steady.wait_for(900, 60);
    eprintln!(
        "[proof] while one client was frozen, the other received {during} of bob's 900 messages \
         (other rows it emitted: {:?})",
        steady.others.lock().unwrap()
    );
    assert_eq!(
        during, 900,
        "PRODUCT: while one `vox room tail` was frozen, the other received only {during} of \
         bob's 900 appends within 60s — a wedged client stalled the node"
    );
    std::thread::sleep(Duration::from_secs(2));
    signal(&run, "-CONT");
    run.paused.store(false, std::sync::atomic::Ordering::SeqCst);
    consume(&run, 300, idle, &mut cursor, &mut seen);
    mark!("run1 consumed 300");
    kill(&mut run, &mut restarts, &cursor, &seen);
    // Run 2: die in the middle of a synced burst from the other node.
    let mut run = start(bob, &r, &cursor, &stderr);
    // First drain the backlog run 1 left, so every row counted below is one that
    // arrived by sync WHILE this consumer was running.
    while consume(&run, 1000, Duration::from_secs(3), &mut cursor, &mut seen) > 0 {}
    mark!("run2 backlog drained");
    burst(alice, 300, 0);
    // LIVENESS, not just completeness: rows synced from another node must reach a
    // consumer while it runs. A stream that only delivered them after a restart would
    // still have no gap — the defect `tail` shipped with — so this is its own assertion.
    let mut live_seen: BTreeMap<String, u32> = BTreeMap::new();
    let live = consume(&run, 200, idle, &mut cursor, &mut live_seen);
    mark!("run2 live 200");
    assert_eq!(
        live, 200,
        "PRODUCT: rows synced from another node must reach a LIVE consumer, not only a \
         restarted one"
    );
    // **ONCE each, within one run** (V210-113). The tail reads from where it last read rather
    // than re-reading the whole room on every `Synced`, so nothing it has emitted may come
    // again. With no restart in between, a row emitted twice in this phase, or one the
    // consumer had already processed (up to its persisted cursor, or in this run's backlog),
    // is the tail's own repeat.
    let again: Vec<(&String, &u32)> = live_seen
        .iter()
        .filter(|(h, c)| **c > 1 || seen.contains_key(*h))
        .collect();
    assert!(
        again.is_empty(),
        "PRODUCT: one running `vox room tail` emitted {} rows it had already emitted: {:?}",
        again.len(),
        &again[..again.len().min(5)]
    );
    for (h, c) in live_seen {
        *seen.entry(h).or_default() += c;
    }
    kill(&mut run, &mut restarts, &cursor, &seen);
    // Run 3: stall under another synced burst, then die.
    let mut run = start(bob, &r, &cursor, &stderr);
    consume(&run, 50, idle, &mut cursor, &mut seen);
    mark!("run3 consumed 50");
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    burst(alice, 300, 0);
    std::thread::sleep(Duration::from_secs(2));
    run.paused.store(false, std::sync::atomic::Ordering::SeqCst);
    consume(&run, 250, idle, &mut cursor, &mut seen);
    mark!("run3 consumed 250");
    kill(&mut run, &mut restarts, &cursor, &seen);
    // The rest, while nobody is listening.
    burst(alice, 300, 0);
    mark!("all bursts posted");

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
    mark!("log holds 1800");

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
    mark!("final drain done");

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

    // ---- the consumer's NODE restarts (ADR-021 F19) ----
    // The cursor only means "everything after this row" if the rows before it are still
    // before it once bob's node has restarted. bob's order is local, not canonical, and the
    // node rebuilds it from its sealed cache on reopen. So bob's local order is made to
    // differ from the canonical one, without a race: bob's daemon is stopped, alice posts
    // (her row cannot reach him), bob's `vox room post` is issued and waits on his control
    // socket, and his daemon is continued. His post is then a row created after hers and
    // taken in one step, while hers needs a sync session of several round trips, so bob holds
    // his later row before her earlier one. A node that rebuilt canonically, or in any other
    // order, is then told apart from one that kept its order.
    let bob_pid = bob.daemon_pid().unwrap_or_else(|| {
        panic!("CANNOT MEASURE: staging not achieved — bob's daemon has no pid")
    });
    let to_bob = |sig: &str| {
        let ok = Command::new("kill")
            .args([sig, &bob_pid.to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(
            ok,
            "CANNOT MEASURE: staging not achieved — `kill {sig} {bob_pid}` failed"
        );
    };
    for i in 0..20 {
        to_bob("-STOP");
        let o = alice.vox(None, &["room", "post", &r, &format!("F19 alice {i:02}")]);
        let posted = std::thread::scope(|s| {
            let bobs = s.spawn(|| bob.vox(None, &["room", "post", &r, &format!("F19 bob {i:02}")]));
            // Long enough for bob's request to be written to his control socket.
            std::thread::sleep(Duration::from_millis(200));
            to_bob("-CONT");
            bobs.join()
        });
        assert!(o.ok, "PRODUCT: alice's post {i} was refused: {o:?}");
        let o = posted.unwrap_or_else(|_| panic!("CANNOT MEASURE: bob's post {i} thread panicked"));
        assert!(o.ok, "PRODUCT: bob's post {i} was refused: {o:?}");
    }
    until(
        bob,
        None,
        "alice's last interleaved post to reach bob",
        &["room", "read", &r],
        |o: &Out| o.ok && o.stdout.contains("F19 alice 19"),
    );
    let order = |w: &Worker| -> Vec<serde_json::Value> {
        let o = w.vox(None, &["room", "read", &r, "--json"]);
        assert!(o.ok, "PRODUCT: `room read --json` failed: {o:?}");
        o.ndjson()
    };
    let hashes = |rows: &[serde_json::Value]| -> Vec<String> {
        rows.iter()
            .map(|x| {
                x["entry_hash"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("PRODUCT: a row of `room read --json` has no entry_hash: {x}")
                    })
                    .to_owned()
            })
            .collect()
    };
    let rows_with = |rows: &[serde_json::Value], text: &str| -> String {
        rows.iter()
            .find(|x| x["text"].as_str() == Some(text))
            .and_then(|x| x["entry_hash"].as_str())
            .unwrap_or_else(|| {
                panic!("PRODUCT (staging): bob's `room read --json` has no {text:?}")
            })
            .to_owned()
    };
    let held = order(bob);
    let before = hashes(&held);
    // The cursor a consumer of bob's node holds partway through the interleave: bob's own post,
    // processed when it arrived. What follows it is what arrived after it, in arrival order:
    // `room read --since` reads it so.
    let mid = rows_with(&held, "F19 bob 10");
    let since = |w: &Worker| -> Vec<String> {
        let o = w.vox(None, &["room", "read", &r, "--since", &mid, "--json"]);
        assert!(o.ok, "PRODUCT: `room read --since` failed: {o:?}");
        hashes(&o.ndjson())
    };
    let followed = since(bob);
    // The late rows: arrived after the cursor, but above it in the room's order. A node that
    // rebuilt "after the cursor" from the room's order on reopen would skip them for good.
    let place = |h: &str| before.iter().position(|x| x == h);
    let at_mid = place(&mid).expect("APPARATUS: the cursor was taken from bob's own rows");
    let late: Vec<&String> = followed
        .iter()
        .filter(|h| place(h).is_some_and(|i| i < at_mid))
        .collect();
    eprintln!(
        "[proof] before bob's node restarts: {} rows; {} arrived after the cursor (bob's post \
         10), {} of them above it in the room's order",
        before.len(),
        followed.len(),
        late.len()
    );
    assert!(
        !late.is_empty(),
        "CANNOT MEASURE (staging not achieved): no row that arrived after the cursor sits above it \
         in the room's order, so a node that read \"after the cursor\" by position could not be \
         told apart"
    );
    assert!(
        followed.len() >= 10,
        "CANNOT MEASURE (staging not achieved): only {} rows arrived after the cursor {mid}",
        followed.len()
    );

    room.restart(1); // SIGKILL by PID, then `vox daemon` with the identity passphrase alone
    let bob = &room.workers[1];

    let after = hashes(&order(bob));
    eprintln!("[proof] after bob's node restarted: {} rows", after.len());
    assert!(
        after.len() >= before.len(),
        "PRODUCT: rows lost across the restart: {} before, {} after",
        before.len(),
        after.len()
    );
    let moved: Vec<usize> = (0..before.len())
        .filter(|&i| after[i] != before[i])
        .collect();
    assert!(
        moved.is_empty(),
        "PRODUCT: {} of {} rows are at a different place in `vox room read` after the restart \
         (first at {:?}): the room's one order did not survive it",
        moved.len(),
        before.len(),
        moved.first()
    );

    // The consumer resumes from its cursor and gets exactly what arrived after it, in order.
    let mut run = start(bob, &r, &mid, &stderr);
    let mut resumed = Vec::new();
    while resumed.len() < followed.len() {
        let Ok(line) = run.rx.recv_timeout(Duration::from_secs(20)) else {
            break;
        };
        let row: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| {
            panic!("PRODUCT: `room tail` printed a line that is not JSON ({e}): {line:?}")
        });
        resumed.push(
            row["entry_hash"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("PRODUCT: a row `room tail` printed has no entry_hash: {row}")
                })
                .to_owned(),
        );
    }
    let _ = run.child.kill();
    let _ = run.child.wait();
    let late_resumed = late.iter().filter(|h| resumed.contains(h)).count();
    eprintln!(
        "[proof] after the restart: the same {} rows in the same order; tail --since the cursor \
         resumed with {} of {} rows, {late_resumed} of the {} late",
        before.len(),
        resumed.len(),
        followed.len(),
        late.len()
    );
    assert!(
        resumed == followed,
        "PRODUCT: `tail --since` a cursor held across the restart did not resume with exactly \
         the rows that arrived after it, in that order: {} of {} rows ({late_resumed} of the {} \
         late), {resumed:?} against {followed:?}",
        resumed.len(),
        followed.len(),
        late.len()
    );
}
