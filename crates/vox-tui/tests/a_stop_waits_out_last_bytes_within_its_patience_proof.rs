//! V210-81 (#272) — **a daemon stopped while a finished tunnel's last bytes are still
//! unacknowledged stops within its patience, and does not abandon its own stop**, through the
//! shipped binary.
//!
//! A stopping node waits, up to `STOP_ACK_BOUND`, for tunnels that finished their stream to have
//! their last bytes acknowledged, and only then closes its connections (`stop_network`).
//! `vox daemon` gives its node `SHUTDOWN_PATIENCE` (5 s) to stop, then drops the node's tasks and
//! leaves, saying "the node did not stop within 5s". With the two bounds equal, a stop that
//! waited out an unacknowledged tail ran into the daemon's patience: the daemon abandoned it
//! with the connection closes still to come, and every other peer learned of the stop only by
//! its idle timeout.
//!
//! Staging, all real processes: Alice and Bob are `vox daemon`s in one room. Alice offers a
//! [`FILE_BYTES`]-byte file with `vox room send` and Bob starts `vox room get`. As soon as the
//! first bytes land, Bob's daemon is frozen (`SIGSTOP`), so nothing more Alice sends is
//! acknowledged. The file is smaller than a tunnel's window, so Alice's `vox room send` still
//! writes all of it and closes, and Alice's tunnel finishes its stream with the tail in flight.
//! Then Alice's daemon is interrupted (SIGINT), exactly as a person stops it.
//!
//! Asserted: Alice's daemon exits within the daemon's patience ([`PATIENCE`]) and never says it
//! gave up on its node's stop.
//!
//! ## Preconditions (else CANNOT MEASURE; the round is staged again, up to [`ATTEMPTS`] times)
//! Alice's `vox room send` read the whole file before the interrupt, and the collector did not
//! have it; and the stop took at least [`WAITED`], so it did wait on an unacknowledged tail
//! (a tail acknowledged before the interrupt makes the stop immediate and measures nothing).
//!
//! ## Mutation
//! `STOP_ACK_BOUND` back at 5 s, equal to the patience: the daemon exits after about 5.06 s,
//! saying "the node did not stop within 5s": red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sync_pair::{Member, ID_PASS, VOX};

/// Less than a tunnel's 16 MiB stream window, so the whole file leaves Alice's `vox room send`
/// with Bob frozen.
const FILE_BYTES: usize = 12 << 20;
/// `vox daemon`'s `SHUTDOWN_PATIENCE`.
const PATIENCE: Duration = Duration::from_secs(5);
/// What the daemon prints when it abandons its node's stop.
const GAVE_UP: &str = "did not stop within";
/// A stop that waited on an unacknowledged tail takes at least this long.
const WAITED: Duration = Duration::from_secs(2);
const ATTEMPTS: usize = 4;

struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
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

fn bytes_in(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// How far `pid`'s open descriptors of `name` have read, from the shipped `lsof`.
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

/// One staging. `None` when a precondition did not hold; else how long Alice's daemon took to
/// exit after SIGINT, and what it said.
fn attempt(root: &Path, n: usize) -> Option<(Duration, String)> {
    let alice = Member::new(&root.join(format!("a{n}")), "alice");
    let bob = Member::new(&root.join(format!("b{n}")), "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let mut alice_d = alice.daemon(None);
    let bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut rb = bob.reader();
    let cb = rb.room(&room);

    let name = "tail.bin";
    let file = root.join(format!("{n}-{name}"));
    {
        let mut f = std::fs::File::create(&file).unwrap();
        let chunk: Vec<u8> = (0..1 << 20)
            .map(|i: u32| (i.wrapping_mul(7).wrapping_add(n as u32) % 251) as u8)
            .collect();
        for _ in 0..FILE_BYTES >> 20 {
            f.write_all(&chunk).unwrap();
        }
    }
    let send_out = root.join(format!("send{n}.out"));
    let send = spawn_vox(
        &alice,
        &["room", "send", &room, file.to_str().unwrap()],
        &send_out,
    );
    let offered = format!("{n}-{name}");
    let t0 = Instant::now();
    while !rb.texts(cb).iter().any(|t| t.contains(&offered)) {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "CANNOT MEASURE: Bob never read the offer"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let dir = root.join(format!("get{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let get_out = root.join(format!("get{n}.out"));
    let _get = spawn_vox(
        &bob,
        &[
            "room",
            "get",
            &room,
            &offered,
            "--out",
            dir.join(&offered).to_str().unwrap(),
        ],
        &get_out,
    );
    let t1 = Instant::now();
    while bytes_in(&dir) == 0 {
        assert!(
            t1.elapsed() < Duration::from_secs(60),
            "CANNOT MEASURE: the collector received nothing"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // Nothing more Alice sends is acknowledged from here on.
    bob_d.signal("-STOP");
    let held = bytes_in(&dir);
    // Alice's `vox room send` writes the whole file into her daemon, and closes.
    let t2 = Instant::now();
    let read = loop {
        let read: u64 = read_offsets(send.0.id(), &offered).iter().sum();
        if read >= FILE_BYTES as u64 || t2.elapsed() > Duration::from_secs(10) {
            break read;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Let the daemon read the rest of the file and finish the tunnel's stream.
    std::thread::sleep(Duration::from_secs(1));
    if read < FILE_BYTES as u64 || held >= FILE_BYTES as u64 {
        eprintln!(
            "[proof] attempt {n}: not staged: the sender read {read} of {FILE_BYTES}, the \
             collector held {held}"
        );
        bob_d.signal("-CONT");
        return None;
    }

    let stop = Instant::now();
    alice_d.signal("-INT");
    let took = loop {
        if alice_d.child.try_wait().unwrap().is_some() {
            break stop.elapsed();
        }
        assert!(
            stop.elapsed() < Duration::from_secs(30),
            "Alice's daemon did not exit within 30 s of SIGINT:\n{}",
            alice_d.transcript()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    // The output threads read to the end of the pipes once the process is gone.
    std::thread::sleep(Duration::from_millis(200));
    let said = alice_d.transcript();
    bob_d.signal("-CONT");
    eprintln!(
        "[proof] attempt {n}: the collector held {held} of {FILE_BYTES} at the freeze; Alice's \
         daemon exited {took:?} after SIGINT"
    );
    if took < WAITED {
        eprintln!("[proof] attempt {n}: not staged: the tail was acknowledged before the stop");
        return None;
    }
    Some((took, said))
}

#[test]
#[ignore = "real daemons with production Argon2id; CI runs it in release"]
fn a_stop_waits_out_last_bytes_within_its_patience() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (took, said) = (0..ATTEMPTS)
        .find_map(|n| attempt(root, n))
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE: none of {ATTEMPTS} attempts left a finished tunnel's tail \
                 unacknowledged at the stop"
            )
        });
    let gave_up = said.lines().find(|l| l.contains(GAVE_UP));
    eprintln!("[proof] Alice's daemon exited {took:?} after SIGINT; gave up: {gave_up:?}");
    assert!(
        gave_up.is_none() && took < PATIENCE,
        "a daemon stopped with a finished tunnel's tail unacknowledged must finish its own stop \
         within its {PATIENCE:?} patience: it exited {took:?} after SIGINT and said {gave_up:?}"
    );
}
