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
//! Every message is posted the way a person or an agent posts one: `vox room post`, the
//! shipped binary, one process per message.
//!
//! What it asserts: the union of every row the consumer emitted, after the starting
//! cursor, **equals** the room's log after that cursor — no gap — and every duplicate
//! is explained by a restart. Before that, separately: `board --json` shows what the
//! claims made it say — the contested resource held by its first claimant, the handed-off
//! one by its receiver, the lapsed one gone.
//!
//! **Which side a red is on.** What `vox` printed or failed to print is `PRODUCT:` and is
//! quoted. A run that never lagged, or a log that does not hold the burst it was given, is
//! `CANNOT MEASURE:` (the staging was not achieved). A fixture or a signal that did not take
//! is `APPARATUS:`.

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
                .expect("APPARATUS: cannot open tail's stderr file"),
        );
    for v in HARNESS_SESSION_VARS {
        cmd.env_remove(v);
    }
    let mut child = cmd.spawn().expect("APPARATUS: cannot start vox room tail");
    let mut lines = BufReader::new(
        child
            .stdout
            .take()
            .expect("APPARATUS: vox room tail has no stdout"),
    );
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

/// Send `sig` (`-STOP`, `-CONT`) to the consumer by its PID.
fn signal(run: &Run, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &run.child.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: kill {sig} {} did not take", run.child.id());
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
            "PRODUCT: `vox room tail --json` printed a row of another schema: {line:?}"
        );
        let h = row["entry_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("PRODUCT: a tail row with no entry_hash: {line:?}"))
            .to_owned();
        *seen.entry(h.clone()).or_default() += 1;
        *cursor = h; // persisted AFTER processing
        got += 1;
    }
    got
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
        .expect("APPARATUS: cannot build the runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.clone();

    // ---- the board half: a contested claim, a completed handoff, a lapse ----
    let ok = |o: Out, what: &str| assert!(o.ok, "PRODUCT: {what} failed: {o:?}");
    ok(
        alice.vox(Some("a1"), &["room", "claim", &r, "contested"]),
        "alice's claim",
    );
    until(
        bob,
        None,
        "the claim to reach bob",
        &["room", "board", &r, "--json"],
        |o: &Out| o.ok && support::resource(&o.json(), "contested").is_some(),
    );
    let lost = bob.vox(Some("b1"), &["room", "claim", &r, "contested"]);
    assert_eq!(
        lost.code,
        Some(1),
        "PRODUCT: bob's claim on what alice holds must be refused with exit 1: {lost:?}"
    );
    ok(
        alice.vox(Some("a1"), &["room", "claim", &r, "passed"]),
        "alice's second claim",
    );
    ok(
        alice.vox(
            Some("a1"),
            &["room", "handoff", &r, "passed", "--to", &bob.b32()[..16]],
        ),
        "alice's handoff",
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
    ok(
        bob.vox(Some("b1"), &["room", "claim", &r, "passed"]),
        "bob's acceptance of the handoff",
    );
    ok(
        bob.vox(Some("b1"), &["room", "claim", &r, "lapsed", "--ttl", "1"]),
        "bob's one-second claim",
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
    let board_out = bob.vox(None, &["room", "board", &r, "--json"]);
    let board = board_out.json();
    let owner = |res: &str| -> Option<(String, String)> {
        let x = support::resource(&board, res)?;
        Some((
            x["owner_fp"].as_str().unwrap_or("").to_owned(),
            x["owner_session"].as_str().unwrap_or("").to_owned(),
        ))
    };
    let contested = owner("contested");
    let passed = owner("passed");
    eprintln!(
        "[proof] board: contested {contested:?}, passed {passed:?}, lapsed {:?}",
        owner("lapsed")
    );
    assert!(
        contested.as_ref().is_some_and(|(fp, s)| s == "a1"
            && alice.b32().starts_with(fp.as_str())
            && !fp.is_empty()),
        "PRODUCT: bob's board must show `contested` held by alice's session a1: {board_out:?}"
    );
    assert!(
        passed.as_ref().is_some_and(|(fp, s)| s == "b1"
            && bob.b32().starts_with(fp.as_str())
            && !fp.is_empty()),
        "PRODUCT: bob's board must show `passed` held by bob's session b1 after the handoff: \
         {board_out:?}"
    );
    assert!(
        owner("lapsed").is_none(),
        "PRODUCT: bob's board still shows `lapsed` after its one-second claim ran out: {board_out:?}"
    );
    let rows = bob.vox(None, &["room", "read", &r, "--json"]).ndjson();

    // ---- the stream half ----
    let start_cursor = rows
        .last()
        .and_then(|x| x["entry_hash"].as_str())
        .expect(
            "CANNOT MEASURE: bob's `vox room read --json` shows no row to start the stream from",
        )
        .to_owned();
    let stderr = tmp.path().join("tail.stderr");

    // The producer, driven in phases by the proof so a burst lands exactly while the
    // consumer is not reading. Each message is one `vox room post`, as a person posts it.
    let mut n = 0usize;
    let mut burst = |w: &Worker, count: usize, pad: usize| {
        let first = n;
        n += count;
        for i in first..first + count {
            let o = w.vox_in(None, &["room", "post", &r, "-"], Some(&say(i, pad)));
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
        run.child
            .kill()
            .expect("APPARATUS: SIGKILL to the consumer did not take"); // mid-stream
        let _ = run.child.wait();
        *restarts += 1;
        eprintln!(
            "[proof] killed consumer run {restarts} at cursor {cursor} after {} distinct rows",
            seen.len()
        );
    };

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
        "PRODUCT: `vox room tail` emitted nothing for a post made while it ran, so it is not \
         live before it is frozen; it said:\n{}",
        std::fs::read_to_string(&stderr).unwrap_or_default()
    );
    run.paused.store(true, std::sync::atomic::Ordering::SeqCst);
    signal(&run, "-STOP"); // frozen: it reads nothing, so only the kernel buffer absorbs
    burst(bob, 899, LAG_PAD);
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
        live,
        200,
        "PRODUCT: rows synced from another node must reach a LIVE consumer, not only a \
         restarted one: {live} of 200 arrived; tail said:\n{}",
        std::fs::read_to_string(&stderr).unwrap_or_default()
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
        .filter_map(|x| x["entry_hash"].as_str().map(str::to_owned))
        .skip_while(|h| *h != start_cursor)
        .skip(1)
        .collect();
    assert_eq!(
        after.len(),
        1800,
        "CANNOT MEASURE: bob's log after the starting cursor is not the 1,800-message burst, so \
         the stream cannot be compared with it"
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
        "PRODUCT: GAP: {} rows after the cursor were never emitted by `vox room tail`: {:?}",
        missing.len(),
        &missing[..missing.len().min(5)]
    );
    assert!(
        extra.is_empty(),
        "PRODUCT: `vox room tail --since` emitted rows from before its cursor: {extra:?}"
    );
    assert!(
        lags > 0,
        "CANNOT MEASURE: the consumer never lagged (no \"fell behind\" from `vox room tail`), so \
         this run proved nothing about lag"
    );
    assert!(
        dups as u32 <= restarts * 600,
        "PRODUCT: `vox room tail` repeated {dups} rows, beyond what {restarts} restarts explain"
    );
}
