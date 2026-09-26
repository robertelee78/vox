//! V210-39 (#212) — **two nodes that each hold a backlog the other lacks both converge**, through
//! the shipped binary.
//!
//! A sync session serves its whole bounded batch before it drains what it is sent
//! (`log/sync.rs`, `frontier_session_room_inner`). One batch may approach 64 MiB, but a QUIC
//! stream's receive window is 16 MiB (`transport::quic::STREAM_WINDOW`). When both ends of one
//! session have more than a window to send, each can block writing into a window the other is
//! not yet reading. If so, both fail at the frame write timeout having applied nothing, and every
//! retry repeats it.
//!
//! The staging uses real `vox` processes only, and no daemon is restarted (a restarted daemon does
//! not reopen its rooms until V210-35). No freeze lasts as long as the 30 s silence after which a
//! connection is declared dead, so the pair's connection survives each one.
//! 1. An anchor, alice, bob and carol (`vox daemon`s, all trusting each other) share a room, and
//!    each reads the others.
//! 2. Bob is frozen (`SIGSTOP`). Alice posts [`POSTS`] rows of [`ROW`] bytes, and **carol reads
//!    all of them**. That is the precondition, readable through `vox room read`.
//! 3. Alice's daemon and the anchor are stopped. Carol is frozen and bob is continued. With nobody
//!    answering, bob posts his own [`POSTS`] rows.
//! 4. Carol is continued. Bob and carol now each hold a backlog the other lacks, past the 16 MiB
//!    stream window each way, over their one live connection.
//!
//! What this asserts: within [`CONVERGE`] of carol's return, **bob reads every one of alice's
//! rows, and carol reads every one of bob's**. If a precondition is not met, the run is CANNOT
//! MEASURE, not a pass.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// Rows per side and their size: 400 × 60,000 bytes = 24 MB, past a 16 MiB stream window, and
/// few enough to post in well under the 30 s a frozen peer may stay silent.
const POSTS: usize = 400;
const ROW: usize = 60_000;
/// How long the two backlogs may take to cross once the anchor is back. Far over the transfer
/// time on loopback, and past two 30 s intervals, so neither the tick nor luck can pass it.
const CONVERGE: Duration = Duration::from_secs(150);
const SETUP: Duration = Duration::from_secs(90);

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

fn signal(p: &VoxProc, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &p.child.id().to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "kill {sig} {}", p.name);
}

/// Stop a process by its PID with SIGTERM, so it closes its connections, and reap it.
fn stop(mut p: VoxProc) {
    signal(&p, "-TERM");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if matches!(p.child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Drop kills it by PID.
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

fn row(who: &str, i: usize) -> String {
    let head = format!("BACKLOG-{who}-{i:04} ");
    format!("{head}{}", "x".repeat(ROW - head.len()))
}

/// How many distinct rows of `who` a member's `vox room read` shows.
fn rows_read(data: &Path, room: &str, who: &str) -> usize {
    let (_, out, _) = vox_once(data, &args(&["room", "read", room]));
    let tag = format!("BACKLOG-{who}-");
    let mut seen = std::collections::BTreeSet::new();
    for l in out.lines() {
        if let Some(rest) = l.split(&tag).nth(1) {
            if let Some(n) = rest.get(..4) {
                seen.insert(n.to_owned());
            }
        }
    }
    seen.len()
}

fn post_all(data: &Path, room: &str, who: &str) {
    for i in 0..POSTS {
        let (ok, out, err) = vox_in(data, &["room", "post", room, "-"], &row(who, i));
        assert!(ok, "{who} post {i}: {out}{err}");
    }
}

#[test]
#[ignore = "real vox processes, 48 MB of history; CI runs it in release"]
fn two_backlogs_that_meet_both_cross() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, alice_dir, bob_dir, carol_dir) =
        (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

    let port = free_udp_port();
    let listen = format!("127.0.0.1:{port}");
    let mut anchor = VoxProc::spawn("anchor", &anchor_dir, &args(&["node", "--listen", &listen]));
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
    let members = [
        ("alice", &alice_dir),
        ("bob", &bob_dir),
        ("carol", &carol_dir),
    ];
    let fps: Vec<String> = members.iter().map(|(_, d)| fp(d)).collect();
    for (i, (_, d)) in members.iter().enumerate() {
        for (j, (name, _)) in members.iter().enumerate() {
            if i != j {
                let (ok, out, err) = vox_once(d, &args(&["trust", "add", &fps[j], "--name", name]));
                assert!(ok, "vox trust add {name}: {out}{err}");
            }
        }
    }
    let alice = daemon("alice", &alice_dir, &spec, &idpass);
    let bob = daemon("bob", &bob_dir, &spec, &idpass);
    let carol = daemon("carol", &carol_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--name", "big"],
        "room pass",
    );
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("big"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    for (name, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
        let (ok, out, err) = vox_in(
            d,
            &["room", "join", link.trim(), "--name", "big"],
            "room pass",
        );
        assert!(ok, "{name} joins: {out}{err}");
    }

    // Everyone reads everyone before anything large moves.
    for (name, d) in members {
        let (ok, _, err) = vox_once(
            d,
            &args(&["room", "post", &room, &format!("hello from {name}")]),
        );
        assert!(ok, "{name} posts: {err}");
    }
    let deadline = Instant::now() + SETUP;
    let mut missing: Vec<String> = Vec::new();
    'warm: loop {
        missing.clear();
        for (reader, d) in members {
            let (_, r, _) = vox_once(d, &args(&["room", "read", &room]));
            for (n, _) in members {
                if !r.contains(&format!("hello from {n}")) {
                    missing.push(format!("{reader} cannot read {n}"));
                }
            }
        }
        if missing.is_empty() {
            break 'warm;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: after {SETUP:?} the members still do not all read each other: {missing:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // ---- 2. bob frozen; alice's backlog reaches carol --------------------------------------
    signal(&bob, "-STOP");
    let frozen = Instant::now();
    let t = Instant::now();
    post_all(&alice_dir, &room, "A");
    println!(
        "[proof] alice posted {POSTS} rows of {ROW} bytes in {:.1?}",
        t.elapsed()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut carol_has = 0;
    while Instant::now() < deadline {
        carol_has = rows_read(&carol_dir, &room, "A");
        if carol_has >= POSTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    println!("[proof] carol reads {carol_has}/{POSTS} of alice's rows");
    assert!(
        carol_has >= POSTS,
        "CANNOT MEASURE: carol read only {carol_has}/{POSTS} of alice's rows, so she holds no backlog for bob"
    );

    // ---- 3. alice and the anchor stop; carol frozen; bob, alone, writes his backlog -----------
    stop(alice);
    stop(anchor);
    signal(&carol, "-STOP");
    signal(&bob, "-CONT");
    println!("[proof] bob was frozen for {:.1?}", frozen.elapsed());
    let frozen = Instant::now();
    let t = Instant::now();
    post_all(&bob_dir, &room, "B");
    println!(
        "[proof] bob posted {POSTS} rows alone in {:.1?}",
        t.elapsed()
    );
    let early = rows_read(&bob_dir, &room, "A");
    assert!(
        early < POSTS,
        "CANNOT MEASURE: bob already reads all of alice's rows ({early}) before carol returns"
    );

    // ---- 4. carol comes back: two backlogs meet ----------------------------------------------
    signal(&carol, "-CONT");
    println!("[proof] carol was frozen for {:.1?}", frozen.elapsed());
    let back = Instant::now();
    let (mut bob_has, mut carol_has_b) = (early, 0);
    while back.elapsed() < CONVERGE {
        bob_has = rows_read(&bob_dir, &room, "A");
        carol_has_b = rows_read(&carol_dir, &room, "B");
        if bob_has >= POSTS && carol_has_b >= POSTS {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    println!(
        "[proof] {:.1?} after carol returned: bob reads {bob_has}/{POSTS} of alice's rows; carol reads \
         {carol_has_b}/{POSTS} of bob's",
        back.elapsed()
    );
    let (mut bob, mut carol) = (bob, carol);
    for (who, p) in [("bob", &mut bob), ("carol", &mut carol)] {
        for l in p.transcript().lines().rev().take(6) {
            println!("[tail {who}] {l}");
        }
    }
    assert!(
        bob_has >= POSTS && carol_has_b >= POSTS,
        "two backlogs did not cross within {CONVERGE:?}: bob reads {bob_has}/{POSTS} of alice's rows, \
         carol reads {carol_has_b}/{POSTS} of bob's"
    );
}
