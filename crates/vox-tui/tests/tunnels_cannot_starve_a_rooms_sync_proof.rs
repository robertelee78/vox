//! V210-81 (#272) — **two tunnels whose far end stopped reading cannot starve the room's sync
//! between the same two nodes, in either direction**, through the shipped binary.
//!
//! Alice and Bob are real `vox daemon`s in one room, reading each other. Alice offers a large file
//! with `vox room send`. Both tunnels of each arm ride the one QUIC connection that also carries
//! the room's sync between Alice and Bob.
//!
//! - **Download arm** (the tunnels fill Bob's receive window, the dialing side's): Bob starts two
//!   `vox room get`s of the file, and each is frozen (`SIGSTOP`) as soon as its first bytes land.
//!   A frozen collector stops reading its local socket, so Bob's daemon stops reading each
//!   tunnel's QUIC stream, and each stream's receive window fills with bytes nobody reads.
//! - **Upload arm** (the tunnels fill Alice's receive window, the host's): Alice's `vox room send`
//!   is frozen, so it reads nothing its tunnels carry. This test asks Bob's daemon for a forward
//!   to the offer over Bob's control socket, exactly as `vox room get` does, opens two
//!   connections through it and writes into both until they stop taking bytes.
//!
//! The defect (sweep F-X7): the connection's receive window was two stream windows
//! (`CONNECTION_WINDOW = 2 × STREAM_WINDOW`, 32 MiB), so two backpressured tunnels could hold all
//! of it, and then the other side could send nothing on that connection: no sync frame, no
//! pairwise key. A post then waits for `SYNC_FRAME_TIMEOUT` and fails ("peer stopped taking
//! frames").
//!
//! Measured here: posts each way, timed from the post to the other side reading it on its own
//! control socket, first with no tunnel ([`POSTS`], the control) and then, in each arm, with both
//! tunnels backpressured ([`FROZEN_POSTS`]).
//! Asserted: in each arm, every post is read within [`BOUND`].
//!
//! ## Preconditions (else CANNOT MEASURE)
//! The control posts all arrived within [`BOUND`]. In the download arm, both collectors received
//! bytes before they were frozen and neither had the whole file. In each arm, **the tunnels took
//! the window**: the writing end stopped advancing (Alice's `vox room send` stopped reading the
//! file, or this test's writes stopped being taken) while more than the defect's whole connection
//! window (2 × `STREAM_WINDOW`) had been written and not read. A writer that cannot advance is
//! held by flow control, so the reading side's windows are full.
//!
//! ## Mutation
//! Restore the old windows (`CONNECTION_WINDOW = 2 * STREAM_WINDOW`, each stream allowed the
//! whole [`STREAM_WINDOW`](vox_core::transport::quic::STREAM_WINDOW)), and the frozen phase goes
//! red: Alice's posts are not read by Bob within the bound. Credit only the dialing side's tunnels
//! (no `carry_tunnel` in the host's `serve_reporting`), and the upload arm goes red: Bob's posts
//! are not read by Alice.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sync_pair::{counter, failures, pct, Member, Reader, ID_PASS, VOX};
use vox_core::transport::quic::STREAM_WINDOW;

/// Posts timed each way with no tunnel (the control).
const POSTS: usize = 10;
/// Posts timed each way with both tunnels frozen: fewer, since each may wait [`GIVE_UP`].
const FROZEN_POSTS: usize = 5;
/// How long one post may take to be read by the other member, tunnels frozen or not. Loopback
/// delivery runs in tens of milliseconds; the defect's is `SYNC_FRAME_TIMEOUT` (20 s) or never.
const BOUND: Duration = Duration::from_secs(3);
/// How long a post is waited for before it is counted as not arrived: past the 20 s a sync
/// frame is waited for, so a post that arrives only after a failed session still counts.
const GIVE_UP: Duration = Duration::from_secs(25);
/// The offered file: far more than a tunnel's window, so a frozen collector never has all of it.
const FILE_BYTES: usize = 256 << 20;
const POLL: Duration = Duration::from_millis(10);
/// What the tunnels must hold, written and not read, for the window to count as taken: the
/// defect's whole connection window.
const TAKEN: u64 = 2 * STREAM_WINDOW as u64;
/// How long the writing end may keep advancing before the arm cannot measure.
const STALL_WITHIN: Duration = Duration::from_secs(30);

/// A child process killed by its own PID however the proof ends.
struct Kid(Child);

impl Kid {
    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.0.id().to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "kill {sig} {}", self.0.id());
    }
}

impl Drop for Kid {
    fn drop(&mut self) {
        // A frozen process takes SIGKILL all the same.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_vox(m: &Member, args: &[&str], out: &Path) -> Kid {
    let child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", &m.dir)
        .env("VOX_CONFIG_DIR", m.dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", ID_PASS)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_SESSION")
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(out).unwrap()))
        .stderr(Stdio::from(
            std::fs::File::create(out.with_extension("err")).unwrap(),
        ))
        .spawn()
        .expect("spawn vox");
    Kid(child)
}

/// Bytes the collector has written into its download directory so far (its `.part` file).
fn collected(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// How far each of `pid`'s open descriptors of `name` has read, from the shipped `lsof`.
fn read_offsets(pid: u32, name: &str) -> Vec<u64> {
    let out = Command::new("lsof")
        .args([
            "-n",
            "-P",
            "-o",
            "-o",
            "0",
            "-a",
            "-p",
            &pid.to_string(),
            "-F",
            "fon",
        ])
        .output()
        .expect("lsof ran");
    let text = String::from_utf8_lossy(&out.stdout);
    let (mut offset, mut offsets) = (None, Vec::new());
    for line in text.lines() {
        if let Some(o) = line.strip_prefix('o') {
            offset = o
                .strip_prefix("0t")
                .and_then(|d| d.parse().ok())
                .or_else(|| {
                    o.strip_prefix("0x")
                        .and_then(|h| u64::from_str_radix(h, 16).ok())
                });
        } else if let Some(n) = line.strip_prefix('n') {
            if n.ends_with(name) {
                offsets.extend(offset);
            }
        } else if line.starts_with('f') {
            offset = None;
        }
    }
    offsets
}

/// Sample `now` once a second until two samples in a row are equal: the writing end has stopped
/// advancing. That sample, or `None` if it was still advancing after [`STALL_WITHIN`].
fn stalled(mut now: impl FnMut() -> Vec<u64>) -> Option<Vec<u64>> {
    let t0 = Instant::now();
    let mut last = now();
    while t0.elapsed() < STALL_WITHIN {
        std::thread::sleep(Duration::from_secs(1));
        let next = now();
        if next == last {
            return Some(next);
        }
        last = next;
    }
    None
}

/// Post `count` texts as `from` and time each until `to` reads it. `None` is a post not read
/// within [`GIVE_UP`].
fn deliveries(
    from: &Member,
    to: &mut Reader,
    to_room: vox_core::hash::Digest32,
    room: &str,
    label: &str,
    count: usize,
) -> Vec<Option<Duration>> {
    (0..count)
        .map(|i| {
            let text = format!("{label} {} {i}", from.name);
            let t0 = Instant::now();
            from.post(room, &text);
            loop {
                if to.has(to_room, &text) {
                    break Some(t0.elapsed());
                }
                if t0.elapsed() > GIVE_UP {
                    break None;
                }
                std::thread::sleep(POLL);
            }
        })
        .collect()
}

fn summary(label: &str, got: &[Option<Duration>]) -> Option<Duration> {
    let arrived: Vec<Duration> = got.iter().flatten().copied().collect();
    let mut sorted = arrived.clone();
    let max = arrived.iter().max().copied();
    eprintln!(
        "[proof] {label}: {}/{} read, p50 {:?}, max {:?}, each {:?}",
        arrived.len(),
        got.len(),
        pct(&mut sorted, 50.0),
        max,
        got
    );
    if arrived.len() < got.len() {
        None
    } else {
        max
    }
}

#[test]
#[ignore = "two real daemons with production Argon2id and two frozen 256 MiB tunnels; CI runs it in release"]
fn two_frozen_tunnels_do_not_stop_the_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(None);
    let bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut ra = alice.reader();
    let mut rb = bob.reader();
    let (ca, cb) = (ra.room(&room), rb.room(&room));

    let start = Instant::now();
    let mut n = 0;
    loop {
        n += 1;
        alice.post(&room, &format!("warm alice {n}"));
        bob.post(&room, &format!("warm bob {n}"));
        std::thread::sleep(Duration::from_millis(500));
        if ra.texts(ca).iter().any(|t| t.starts_with("warm bob"))
            && rb.texts(cb).iter().any(|t| t.starts_with("warm alice"))
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "CANNOT MEASURE: the pair never read each other\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
    }
    std::thread::sleep(Duration::from_secs(1));

    // The control: no tunnel.
    let a2b = deliveries(&alice, &mut rb, cb, &room, "control", POSTS);
    let b2a = deliveries(&bob, &mut ra, ca, &room, "control", POSTS);
    let control = [
        summary("control alice→bob", &a2b),
        summary("control bob→alice", &b2a),
    ];
    assert!(
        control.iter().all(|m| m.is_some_and(|m| m <= BOUND)),
        "CANNOT MEASURE: with no tunnel at all, a post was not read within {BOUND:?}"
    );

    // Alice offers a file far larger than a tunnel's window.
    let file = root.join("big.bin");
    {
        let mut f = std::fs::File::create(&file).unwrap();
        let chunk: Vec<u8> = (0..1 << 20).map(|i: u32| (i % 251) as u8).collect();
        for _ in 0..FILE_BYTES >> 20 {
            f.write_all(&chunk).unwrap();
        }
    }
    let send_out = root.join("send.out");
    let send = spawn_vox(
        &alice,
        &["room", "send", &room, file.to_str().unwrap()],
        &send_out,
    );
    let offered = Instant::now();
    while !rb.texts(cb).iter().any(|t| t.contains("big.bin")) {
        assert!(
            offered.elapsed() < Duration::from_secs(60),
            "CANNOT MEASURE: Bob never read Alice's offer\nsend: {}\n{}",
            std::fs::read_to_string(&send_out).unwrap_or_default(),
            std::fs::read_to_string(send_out.with_extension("err")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // Bob collects it twice, each collector frozen as soon as its first bytes land.
    let mut gets: Vec<(Kid, PathBuf)> = Vec::new();
    for g in 0..2 {
        let dir = root.join(format!("get{g}"));
        std::fs::create_dir_all(&dir).unwrap();
        let out = root.join(format!("get{g}.out"));
        let kid = spawn_vox(
            &bob,
            &[
                "room",
                "get",
                &room,
                "big.bin",
                "--out",
                dir.join("big.bin").to_str().unwrap(),
            ],
            &out,
        );
        let t0 = Instant::now();
        while collected(&dir) == 0 {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "CANNOT MEASURE: collector {g} received nothing\n{}\n{}",
                std::fs::read_to_string(&out).unwrap_or_default(),
                std::fs::read_to_string(out.with_extension("err")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        kid.signal("-STOP");
        gets.push((kid, dir));
    }
    // Let the tunnels' windows fill: both collectors' byte counts hold still.
    std::thread::sleep(Duration::from_secs(3));
    let held: Vec<u64> = gets.iter().map(|(_, d)| collected(d)).collect();
    eprintln!("[proof] frozen collectors hold {held:?} of {FILE_BYTES} bytes each");
    assert!(
        held.iter().all(|&b| b > 0 && b < FILE_BYTES as u64),
        "CANNOT MEASURE: a collector was not mid-transfer when frozen: {held:?}"
    );
    let send_pid = send.0.id();
    let offsets = stalled(|| read_offsets(send_pid, "big.bin"));
    let read: u64 = offsets.iter().flatten().sum();
    let unread = read.saturating_sub(held.iter().sum());
    eprintln!(
        "[proof] download arm: the sender stopped reading the file at {offsets:?}; {unread} bytes \
         written and not read (the window counts as taken from {TAKEN})"
    );
    assert!(
        offsets.as_ref().is_some_and(|o| o.len() == 2) && unread >= TAKEN,
        "CANNOT MEASURE: the download tunnels did not take the window: the sender's reads \
         {offsets:?}, {unread} bytes unread of the {TAKEN} needed"
    );

    let download = phase(&alice, &bob, &mut ra, &mut rb, ca, cb, &room, "download");
    for (kid, _) in &gets {
        kid.signal("-CONT");
    }
    drop(gets);

    // The upload arm: Alice's side reads nothing its tunnels carry.
    send.signal("-STOP");
    let said = std::fs::read_to_string(&send_out).unwrap_or_default();
    let tag = said
        .lines()
        .find_map(|l| l.split(" as ").nth(1))
        .map(str::trim)
        .expect("vox room send names its offer's tag")
        .to_owned();
    let host = rb
        .author_of(cb, "big.bin")
        .expect("Bob reads who offered big.bin");
    let bound = rb.forward(cb, host, &tag);
    let written: Vec<Arc<AtomicU64>> = (0..2).map(|_| Arc::default()).collect();
    let socks: Vec<TcpStream> = written
        .iter()
        .map(|count| {
            let sock = TcpStream::connect(&bound).expect("connect to Bob's forward");
            let mut w = sock.try_clone().unwrap();
            let count = Arc::clone(count);
            std::thread::spawn(move || {
                let chunk = vec![0x5a_u8; 64 * 1024];
                while let Ok(n) = w.write(&chunk) {
                    count.fetch_add(n as u64, Ordering::Relaxed);
                }
            });
            sock
        })
        .collect();
    let taken = stalled(|| written.iter().map(|c| c.load(Ordering::Relaxed)).collect());
    eprintln!(
        "[proof] upload arm: the writes stopped being taken at {taken:?} bytes (the window counts \
         as taken from {TAKEN} in all)"
    );
    assert!(
        taken
            .as_ref()
            .is_some_and(|t| t.iter().all(|&b| b > 0) && t.iter().sum::<u64>() >= TAKEN),
        "CANNOT MEASURE: the upload tunnels did not take the window: written {taken:?} of the \
         {TAKEN} needed"
    );
    let upload = phase(&alice, &bob, &mut ra, &mut rb, ca, cb, &room, "upload");
    for sock in &socks {
        let _ = sock.shutdown(Shutdown::Both);
    }
    send.signal("-CONT");

    for (arm, got) in [("download", download), ("upload", upload)] {
        assert!(
            got.iter().all(|m| m.is_some_and(|m| m <= BOUND)),
            "{arm} arm: with two tunnels backpressured, a post was not read within {BOUND:?} \
             (alice→bob {:?}, bob→alice {:?}): the tunnels took the connection's credit",
            got[0],
            got[1]
        );
    }
}

/// Posts each way with the tunnels backpressured: the slowest each way, `None` for a post not
/// read.
#[allow(clippy::too_many_arguments)]
fn phase(
    alice: &Member,
    bob: &Member,
    ra: &mut Reader,
    rb: &mut Reader,
    ca: vox_core::hash::Digest32,
    cb: vox_core::hash::Digest32,
    room: &str,
    arm: &str,
) -> [Option<Duration>; 2] {
    let a0 = alice.status();
    let b0 = bob.status();
    let a2b = deliveries(alice, rb, cb, room, arm, FROZEN_POSTS);
    let b2a = deliveries(bob, ra, ca, room, arm, FROZEN_POSTS);
    let got = [
        summary(&format!("{arm} alice→bob"), &a2b),
        summary(&format!("{arm} bob→alice"), &b2a),
    ];
    let (a1, b1) = (alice.status(), bob.status());
    eprintln!(
        "[proof] sync failures during the {arm} arm: alice {} bob {}; last: {:?} {:?}",
        counter(&a1, "failed", None) - counter(&a0, "failed", None),
        counter(&b1, "failed", None) - counter(&b0, "failed", None),
        failures(&a1),
        failures(&b1)
    );
    got
}
