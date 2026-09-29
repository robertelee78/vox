//! V210-81 (#272) — **two tunnels whose readers stopped reading cannot starve the room's sync
//! between the same two nodes**, through the shipped binary.
//!
//! Alice and Bob are real `vox daemon`s in one room, reading each other. Alice offers a large file
//! with `vox room send`; Bob starts two `vox room get`s of it, and each is frozen (`SIGSTOP`) as
//! soon as its first bytes land. A frozen collector stops reading its local socket, so Bob's
//! daemon stops reading each tunnel's QUIC stream, and each stream's receive window fills with
//! bytes nobody reads. Both tunnels ride the one QUIC connection that also carries the room's sync
//! between Alice and Bob.
//!
//! The defect (sweep F-X7): the connection's receive window was two stream windows
//! (`CONNECTION_WINDOW = 2 × STREAM_WINDOW`, 32 MiB), so two backpressured tunnels could hold all
//! of it, and then Alice could send Bob nothing on that connection: no sync frame, no pairwise
//! key. A post then waits for `SYNC_FRAME_TIMEOUT` and fails ("peer stopped taking frames").
//!
//! Measured here: posts each way, timed from the post to the other side reading it on its own
//! control socket, first with no tunnel ([`POSTS`], the control) and then with both tunnels frozen
//! ([`FROZEN_POSTS`]).
//! Asserted: with the tunnels frozen, every post is read within [`BOUND`].
//!
//! ## Preconditions (else CANNOT MEASURE)
//! Both collectors received bytes before they were frozen, neither had the whole file, and the
//! control posts all arrived within [`BOUND`].
//!
//! ## Mutation
//! Restore the old windows (`CONNECTION_WINDOW = 2 * STREAM_WINDOW`, each stream allowed the
//! whole [`STREAM_WINDOW`](vox_core::transport::quic::STREAM_WINDOW)), and the frozen phase goes
//! red: Alice's posts are not read by Bob within the bound.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sync_pair::{counter, failures, pct, Member, Reader, ID_PASS, VOX};

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
    let _send = spawn_vox(
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

    let a0 = alice.status();
    let b0 = bob.status();
    let a2b = deliveries(&alice, &mut rb, cb, &room, "frozen", FROZEN_POSTS);
    let b2a = deliveries(&bob, &mut ra, ca, &room, "frozen", FROZEN_POSTS);
    let frozen = [
        summary("frozen alice→bob", &a2b),
        summary("frozen bob→alice", &b2a),
    ];
    let (a1, b1) = (alice.status(), bob.status());
    eprintln!(
        "[proof] sync failures during the frozen phase: alice {} bob {}; last: {:?} {:?}",
        counter(&a1, "failed", None) - counter(&a0, "failed", None),
        counter(&b1, "failed", None) - counter(&b0, "failed", None),
        failures(&a1),
        failures(&b1)
    );
    for (kid, _) in &gets {
        kid.signal("-CONT");
    }
    drop(gets);

    assert!(
        frozen.iter().all(|m| m.is_some_and(|m| m <= BOUND)),
        "with two tunnels backpressured, a post was not read within {BOUND:?} (alice→bob {:?}, \
         bob→alice {:?}): the tunnels took the connection's credit",
        frozen[0],
        frozen[1]
    );
}
