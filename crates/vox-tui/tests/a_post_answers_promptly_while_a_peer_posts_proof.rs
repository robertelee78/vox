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
//! Mutation: restore one commit per entry in `absorb_arrived`, and this goes red on the tail.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
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
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

#[test]
#[ignore = "real vox processes with production Argon2id; CI runs it in release"]
fn a_post_answers_promptly_while_a_peer_posts() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, alice_dir, bob_dir) = (dir("anchor"), dir("alice"), dir("bob"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

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
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice_dir), fp(&bob_dir));
    for (d, other, name) in [(&alice_dir, &bob_fp, "bob"), (&bob_dir, &alice_fp, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(ok, "vox trust add {name}: {out}{err}");
    }

    let _alice = daemon("alice", &alice_dir, &spec, &idpass);
    let _bob = daemon("bob", &bob_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--name", "busy"],
        "room pass",
    );
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("busy"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "busy"],
        "room pass",
    );
    assert!(ok, "bob joins: {out}{err}");

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
            "CANNOT PROVE: Bob never got {BOB_HEAD_START} posts in, so the room was never busy"
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
            "CANNOT PROVE: none of Bob's posts reached Alice, so her room was not busy"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // ---- Alice's posts, timed ---------------------------------------------------------------
    let mut took: Vec<Duration> = Vec::with_capacity(POSTS);
    for i in 0..POSTS {
        let t = Instant::now();
        let (ok, _, err) = vox_once(
            &alice_dir,
            &args(&["room", "post", &room, &format!("alice {i}")]),
        );
        took.push(t.elapsed());
        assert!(ok, "alice's post {i} failed: {err}");
    }
    stop.store(true, Ordering::Relaxed);
    bob_thread.join().unwrap();
    let bob_total = bob_posts.load(Ordering::Relaxed);

    // Bob's posts arrived at Alice during hers: the busy condition held for the measurement.
    let (_, read, _) = vox_once(&alice_dir, &args(&["room", "read", &room]));
    let bob_seen = read.lines().filter(|l| l.contains("bob ")).count();

    took.sort();
    let pct = |p: usize| took[(took.len() * p / 100).min(took.len() - 1)];
    let (p50, p95, max) = (pct(50), pct(95), *took.last().unwrap());
    println!(
        "[proof] alice {POSTS} posts while bob posted {bob_total} ({bob_seen} seen by alice): \
         p50 {}ms, p95 {}ms, max {}ms (bounds p95 {}ms, max {}ms)",
        p50.as_millis(),
        p95.as_millis(),
        max.as_millis(),
        P95_BOUND.as_millis(),
        MAX_BOUND.as_millis()
    );
    assert!(
        bob_seen >= BOB_HEAD_START,
        "CANNOT PROVE: only {bob_seen} of Bob's {bob_total} posts reached Alice"
    );
    assert!(
        p95 <= P95_BOUND && max <= MAX_BOUND,
        "`vox room post` waited on another member's traffic: p95 {}ms (bound {}ms), max {}ms \
         (bound {}ms). A post must not queue behind a sync applying a peer's messages (V210-08)",
        p95.as_millis(),
        P95_BOUND.as_millis(),
        max.as_millis(),
        MAX_BOUND.as_millis()
    );
    drop(anchor);
}
