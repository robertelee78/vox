//! V210-08 (#179) — **`vox room post` answers promptly while another member is posting**, through
//! the shipped binary.
//!
//! Alice and Bob are real `vox daemon`s in one room, behind a real `vox node` anchor. Bob posts
//! continuously from his own `vox room post` loop. Alice then posts [`POSTS`] times with `vox room
//! post`, and each call is timed from start to exit. The bound is on the tail, not the median: the
//! defect was a median of ~15 ms with a p95 of 0.8–1.4 s and a max of 2.6–4.8 s.
//!
//! The cause was the room's lock. A sync session applying Bob's messages committed every entry on
//! its own — two durable commits apiece, about 17 ms each on macOS — while it held the room, so a
//! batch of 133 entries held it for 2.3 s and Alice's post waited behind it. The fix commits the
//! batch once (`ChannelState::absorb_arrived`, `render_content_into`).
//!
//! **The second cause was a storm on the actor** (CI ubuntu, p95 148 ms with a normal p50). A
//! member's routine republish of a record a board already held counted as news, so the board's
//! node republished its own records, which counted as news back: two members' boards woke each
//! other about a hundred times a second. And every sync that brought ordinary messages started a
//! publish round of its own. Each round signs on the actor, and a local post queues behind it on
//! a slow runner. So this also counts, through `vox status --json`, the publish rounds each node
//! started and the records it took for news during Alice's posts: two members only posting
//! change nothing to republish ([`QUIET_ROUNDS`]).
//!
//! Mutations: restore one commit per entry in `absorb_arrived`, and this goes red on the tail;
//! count a board's refresh of what it already holds as news, or start a publish round after
//! every sync that applied entries, and it goes red on the counts.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_post_answers_promptly_while_a_peer_posts);

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// Alice's timed posts.
const POSTS: usize = 100;
/// The decider's bound for V210-08 (proposed: p95 under 100 ms, max under 500 ms, on loopback).
const P95_BOUND: Duration = Duration::from_millis(100);
const MAX_BOUND: Duration = Duration::from_millis(500);
/// Bob must have this many posts in before Alice starts, so the room is busy for all of hers.
const BOB_HEAD_START: usize = 20;
const TIMEOUT: Duration = Duration::from_secs(90);
/// What the daemons said: when (against the proof's clock), who, and the line.
type Said = Arc<Mutex<Vec<(Duration, &'static str, String)>>>;

/// Publish rounds, and records passed on as board news, a node may start while two members only
/// post (#179). Measured during Alice's posts: 0 with the fix; 51–151 rounds and 137–430 news
/// before it, the two members' boards waking each other. Room for a real change of address or
/// admission, and ten times under the storm.
const QUIET_ROUNDS: u64 = 5;
/// How many of Alice's slowest posts are named, with what the daemons said around each.
const SLOWEST: usize = 10;
/// A post slower than this takes a snapshot of both nodes' sync counters after it.
const LATE: Duration = Duration::from_millis(50);

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdio handle")
        .write_all(stdin.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    let out = child.wait_with_output().expect("APPARATUS: vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A node's `vox status --json` publish counters: (rounds started, board news passed on).
fn publishing(data: &Path) -> (u64, u64) {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "PRODUCT (staging): vox status --json: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("PRODUCT: status is JSON");
    let n = |k: &str| {
        v["publish"][k]
            .as_u64()
            .unwrap_or_else(|| panic!("PRODUCT: status has no publish.{k}: {out}"))
    };
    (n("rounds"), n("board_news"))
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: a path that is not UTF-8"),
        ]),
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list`");
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real vox processes with production Argon2id; optional, run it in release"]
fn a_post_answers_promptly_while_a_peer_posts() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    let (anchor_dir, alice_dir, bob_dir) = (dir("anchor"), dir("alice"), dir("bob"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write a staging file");

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice_dir), fp(&bob_dir));
    for (d, other, name) in [(&alice_dir, &bob_fp, "bob"), (&bob_dir, &alice_fp, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {out}{err}");
    }

    let mut alice_d = daemon("alice", &alice_dir, &spec, &idpass);
    let mut bob_d = daemon("bob", &bob_dir, &spec, &idpass);
    // Everything either daemon says from here on, stamped against one clock, so a slow post can
    // be read against what the nodes were doing at that moment.
    let t0 = Instant::now();
    let said: Said = Arc::default();
    for (who, p) in [("alice", &mut alice_d), ("bob", &mut bob_d)] {
        let rx = std::mem::replace(&mut p.lines, mpsc::channel().1);
        let said = Arc::clone(&said);
        std::thread::spawn(move || {
            for line in rx {
                said.lock()
                    .expect("APPARATUS: a lock the proof holds was poisoned")
                    .push((t0.elapsed(), who, line));
            }
        });
    }

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "busy"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("busy"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT: room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link.trim(),
            "--name",
            "busy",
        ],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): bob joins: {out}{err}");

    // ---- Bob posts continuously until Alice is done -----------------------------------------
    let stop = Arc::new(AtomicBool::new(false));
    let bob_posts = Arc::new(AtomicUsize::new(0));
    let bob_thread = {
        let (stop, bob_posts, bob_dir, room) = (
            Arc::clone(&stop),
            Arc::clone(&bob_posts),
            bob_dir.clone(),
            room.clone(),
        );
        std::thread::spawn(move || {
            let mut n = 0usize;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                if vox_once(
                    &bob_dir,
                    &args(&["room", "post", &room, &format!("bob {n}")]),
                )
                .0
                {
                    bob_posts.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };
    let deadline = Instant::now() + TIMEOUT;
    while bob_posts.load(Ordering::Relaxed) < BOB_HEAD_START {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): Bob's posts failed: {BOB_HEAD_START} never went in, so the room was never busy"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // The control: Bob's posts must actually be reaching Alice, or her room is not busy with
    // arriving work and a fast post proves nothing.
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let (_, read, _) = vox_once(&alice_dir, &args(&["room", "read", &room]));
        if read.contains("bob ") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): none of Bob's posts reached Alice, so her room was not busy"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Each node's sync counters (`vox status --json`), snapshotted **only outside the timed
    // posts**: once before them, once right after any post that ran late (its time already
    // taken), and once after. The counters are cumulative, so the snapshots either side of a slow
    // post show the sessions that ran across it. Polling them throughout cost 3–7 ms of p95 here
    // (p95 36 ms off against 39–43 ms on, alternating under the timing lock), which a slower
    // runner would multiply; this costs a fast run nothing.
    let snapshot = |label: &str| {
        for (who, dir) in [("alice", &alice_dir), ("bob", &bob_dir)] {
            let (ok, out, _) = vox_once(dir, &args(&["status", "--json"]));
            if ok {
                said.lock()
                    .expect("APPARATUS: a lock the proof holds was poisoned")
                    .push((
                        t0.elapsed(),
                        who,
                        format!("sync counters ({label}) {}", out.trim()),
                    ));
            }
        }
    };
    snapshot("before the timed posts");
    let publish_before = [publishing(&alice_dir), publishing(&bob_dir)];

    // ---- Alice's posts, timed ---------------------------------------------------------------
    let mut took: Vec<Duration> = Vec::with_capacity(POSTS);
    // Each post: which, when it started (against `t0`), how long it took.
    let mut posts: Vec<(usize, Duration, Duration)> = Vec::with_capacity(POSTS);
    for i in 0..POSTS {
        let t = Instant::now();
        let (ok, _, err) = vox_once(
            &alice_dir,
            &args(&["room", "post", &room, &format!("alice {i}")]),
        );
        let dur = t.elapsed();
        took.push(dur);
        posts.push((i, t.duration_since(t0), dur));
        assert!(ok, "PRODUCT: alice's post {i} failed: {err}");
        if dur > LATE {
            snapshot(&format!("after alice {i}, {}ms", dur.as_millis()));
        }
    }
    snapshot("after the timed posts");
    let publish_after = [publishing(&alice_dir), publishing(&bob_dir)];
    stop.store(true, Ordering::Relaxed);
    bob_thread
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
    let bob_total = bob_posts.load(Ordering::Relaxed);

    // Bob's posts arrived at Alice during hers: the busy condition held for the measurement.
    let (_, read, _) = vox_once(&alice_dir, &args(&["room", "read", &room]));
    let bob_seen = read.lines().filter(|l| l.contains("bob ")).count();

    took.sort();
    let pct = |p: usize| took[(took.len() * p / 100).min(took.len() - 1)];
    let (p50, p95, max) = (
        pct(50),
        pct(95),
        *took.last().expect("APPARATUS: no samples"),
    );
    println!(
        "[proof] alice {POSTS} posts while bob posted {bob_total} ({bob_seen} seen by alice): \
         p50 {}ms, p95 {}ms, max {}ms (bounds p95 {}ms, max {}ms)",
        p50.as_millis(),
        p95.as_millis(),
        max.as_millis(),
        P95_BOUND.as_millis(),
        MAX_BOUND.as_millis()
    );
    // **The slowest posts name themselves** (a red on one CI runner, p95 148ms, did not): each
    // with when it started, and what either daemon said from a second before it until just after.
    posts.sort_by_key(|p| std::cmp::Reverse(p.2));
    let said = said
        .lock()
        .expect("APPARATUS: a lock the proof holds was poisoned")
        .clone();
    for (i, start, dur) in posts.iter().take(SLOWEST) {
        println!(
            "[slow] alice {i}: {}ms, from +{:.3}s",
            dur.as_millis(),
            start.as_secs_f64()
        );
        let (from, to) = (
            start.saturating_sub(Duration::from_secs(1)),
            *start + *dur + Duration::from_millis(500),
        );
        // What either daemon printed near it, and the counter snapshots either side of it.
        let before = said
            .iter()
            .filter(|(at, _, l)| *at < *start && l.starts_with("sync counters"))
            .rev()
            .take(2);
        let after = said
            .iter()
            .filter(|(at, _, l)| *at >= *start + *dur && l.starts_with("sync counters"))
            .take(2);
        let near = said
            .iter()
            .filter(|(at, _, l)| *at >= from && *at <= to && !l.starts_with("sync counters"));
        let mut around: Vec<_> = before.chain(near).chain(after).collect();
        around.sort_by_key(|(at, _, _)| *at);
        for (at, who, line) in around {
            println!("[slow]     +{:.3}s {who}: {line}", at.as_secs_f64());
        }
    }
    assert!(
        bob_seen >= BOB_HEAD_START,
        "PRODUCT: only {bob_seen} of Bob's {bob_total} posts reached Alice"
    );
    // **The storm itself, counted** (#179): during the timed posts, how many publish rounds each
    // node started and how many records on its board it took for news and passed on.
    let grew = |i: usize| {
        (
            publish_after[i].0.saturating_sub(publish_before[i].0),
            publish_after[i].1.saturating_sub(publish_before[i].1),
        )
    };
    let (alice_pub, bob_pub) = (grew(0), grew(1));
    println!(
        "[proof] during alice's posts: publish rounds alice {} bob {}; board news alice {} bob {}",
        alice_pub.0, bob_pub.0, alice_pub.1, bob_pub.1
    );
    for (who, (rounds, news)) in [("alice", alice_pub), ("bob", bob_pub)] {
        assert!(
            rounds <= QUIET_ROUNDS && news <= QUIET_ROUNDS,
            "PRODUCT: {who}'s node published {rounds} rounds and passed on {news} records as news while \
             two members only posted: nothing about who they are or where they are changed, so \
             there was nothing to republish (#179). Each round signs on the actor a post queues \
             behind"
        );
    }
    assert!(
        p95 <= P95_BOUND && max <= MAX_BOUND,
        "PRODUCT: `vox room post` waited on another member's traffic: p95 {}ms (bound {}ms), max {}ms \
         (bound {}ms). A post must not queue behind a sync applying a peer's messages (V210-08)",
        p95.as_millis(),
        P95_BOUND.as_millis(),
        max.as_millis(),
        MAX_BOUND.as_millis()
    );
    drop((alice_d, bob_d, anchor));
}
