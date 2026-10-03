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
//! - **Cap arm** (one member's tunnels past [`TUNNELS_PER_PEER`]): with the upload arm's two still
//!   held, Bob opens more connections through the same forward until his connection to Alice
//!   carries 16 tunnels, all stalled, then [`EXTRA`] more; then he runs `vox room get` of the
//!   offer. By the decider's ruling (2026-10-01), a tunnel past the cap is refused at once, saying
//!   why, so the room's sync keeps flowing and the memory a member can hold stays bounded.
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
//! Asserted: in each arm, every post is read within [`BOUND`]. In the cap arm, also: Bob's
//! `vox room get` is refused within [`REFUSED_WITHIN`], saying [`LIMIT_SAID`]; the [`EXTRA`]
//! tunnels each take less than [`ONE_WINDOW_TAKEN`]; and Alice's daemon grows by less than
//! [`GREW_PAST_CAP`] (from `ps`) between the cap and past it. The refusal names the service the
//! 16 go to and how to free one ([`FREE_ONE_SAID`]), and at the cap `vox status` (both `--json`
//! and the lines a person reads) lists the 16 on each side: out on Bob's, in on Alice's; and
//! Alice's names the offer once per tunnel, in one listing, never twice.
//!
//! ## Preconditions (else CANNOT MEASURE)
//! The control posts all arrived within [`BOUND`]. In the download arm, both collectors received
//! bytes before they were frozen and neither had the whole file. In each arm, **the tunnels took
//! the window**: the writing end stopped advancing (Alice's `vox room send` stopped reading the
//! file, or this test's writes stopped being taken) while more than the defect's whole connection
//! window (2 × `STREAM_WINDOW`) had been written and not read. A writer that cannot advance is
//! held by flow control, so the reading side's windows are full. In the cap arm, both rounds of writes
//! stopped advancing.
//!
//! ## Mutation
//! Restore the old windows (`CONNECTION_WINDOW = 2 * STREAM_WINDOW`, each stream allowed the
//! whole [`STREAM_WINDOW`](vox_core::transport::quic::STREAM_WINDOW)), and the frozen phase goes
//! red: Alice's posts are not read by Bob within the bound. Credit only the dialing side's tunnels
//! (no `carry_tunnel` in the host's `serve_reporting`), and the upload arm goes red: Bob's posts
//! are not read by Alice. Take the cap away (`at_tunnel_cap` never true), and the cap arm goes
//! red: the `vox room get` is not refused, the extra tunnels are carried, and Alice grows by
//! about a stream window per extra tunnel.

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
use vox_core::transport::quic::{STREAM_WINDOW, TUNNELS_PER_PEER};

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
/// Tunnels the cap arm opens past [`TUNNELS_PER_PEER`].
const EXTRA: usize = 8;
/// What a carried tunnel takes before it stalls, at least: half its stream window. A refused one
/// takes only what the local socket buffers before its reset arrives.
const ONE_WINDOW_TAKEN: u64 = STREAM_WINDOW as u64 / 2;
/// How much alice's daemon may grow when the [`EXTRA`] tunnels are asked for: half of what they
/// would hold if they were carried. Refused, they hold nothing.
const GREW_PAST_CAP: u64 = EXTRA as u64 * STREAM_WINDOW as u64 / 2;
/// How long a `vox room get` past the cap may take to be refused: it is refused before anything
/// is dialled anew, so this is process start and one control-socket round.
const REFUSED_WITHIN: Duration = Duration::from_secs(30);
/// What the person is told past the cap.
const LIMIT_SAID: &str = "16 tunnels are already open to this member";
/// How the refusal tells them to free one (decider, 2026-10-01).
const FREE_ONE_SAID: [&str; 5] = [
    "`vox tunnel close`",
    "close the program using it",
    "`vox forward`",
    "`vox service remove`",
    "`vox trust remove`",
];

/// A child process killed by its own PID however the proof ends.
struct Kid(Child);

impl Kid {
    /// Whether it exited successfully within `bound`; `None` if it is still running.
    fn exited_within(&mut self, bound: Duration) -> Option<bool> {
        let t0 = Instant::now();
        while t0.elapsed() < bound {
            match self.0.try_wait() {
                Ok(Some(status)) => return Some(status.success()),
                Ok(None) => std::thread::sleep(POLL),
                Err(e) => panic!("APPARATUS: wait for vox: {e}"),
            }
        }
        None
    }

    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.0.id().to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "APPARATUS: kill {sig} {} did not take", self.0.id());
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
        .stdout(Stdio::from(
            std::fs::File::create(out).expect("APPARATUS: create the stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(out.with_extension("err"))
                .expect("APPARATUS: create the stderr file"),
        ))
        .spawn()
        .expect("APPARATUS: spawn vox");
    Kid(child)
}

/// `n` connections to the forward at `bound`, each written into until it stops taking bytes,
/// with the count each has taken. A connection reset before `connect` returns took nothing: the
/// forward accepted it, and its tunnel was refused that fast.
fn writers(bound: &str, n: usize) -> (Vec<TcpStream>, Vec<Arc<AtomicU64>>) {
    let written: Vec<Arc<AtomicU64>> = (0..n).map(|_| Arc::default()).collect();
    let socks = written
        .iter()
        .filter_map(|count| {
            let sock = match TcpStream::connect(bound) {
                Ok(sock) => sock,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
                Err(e) => panic!(
                    "PRODUCT: Bob's daemon bound the forward at {bound} but it refuses a connection: {e}"
                ),
            };
            let mut w = sock
                .try_clone()
                .expect("APPARATUS: clone the forward socket");
            let count = Arc::clone(count);
            std::thread::spawn(move || {
                let chunk = vec![0x5a_u8; 64 * 1024];
                while let Ok(n) = w.write(&chunk) {
                    count.fetch_add(n as u64, Ordering::Relaxed);
                }
            });
            Some(sock)
        })
        .collect();
    (socks, written)
}

fn loads(counts: &[Arc<AtomicU64>]) -> Vec<u64> {
    counts.iter().map(|c| c.load(Ordering::Relaxed)).collect()
}

/// `pid`'s resident memory in KiB, from the shipped `ps`.
fn rss(pid: u32) -> u64 {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("APPARATUS: run ps");
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .parse()
        .unwrap_or_else(|_| panic!("APPARATUS: ps gave no resident size for {pid}: {text:?}"))
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
        .expect("APPARATUS: run lsof");
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
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
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
            "PRODUCT (staging): the pair never read each other\nalice:\n{}\nbob:\n{}",
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
        "PRODUCT (staging): with no tunnel at all, a post was not read within {BOUND:?}"
    );

    // Alice offers a file far larger than a tunnel's window.
    let file = root.join("big.bin");
    {
        let mut f = std::fs::File::create(&file).expect("APPARATUS: create the offered file");
        let chunk: Vec<u8> = (0..1 << 20).map(|i: u32| (i % 251) as u8).collect();
        for _ in 0..FILE_BYTES >> 20 {
            f.write_all(&chunk)
                .expect("APPARATUS: write the offered file");
        }
    }
    let send_out = root.join("send.out");
    let send = spawn_vox(
        &alice,
        &[
            "room",
            "send",
            &room,
            file.to_str().expect("APPARATUS: a UTF-8 path"),
        ],
        &send_out,
    );
    let offered = Instant::now();
    while !rb.texts(cb).iter().any(|t| t.contains("big.bin")) {
        assert!(
            offered.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): Bob never read Alice's offer\nsend: {}\n{}",
            std::fs::read_to_string(&send_out).unwrap_or_default(),
            std::fs::read_to_string(send_out.with_extension("err")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // Bob collects it twice, each collector frozen as soon as its first bytes land.
    let mut gets: Vec<(Kid, PathBuf)> = Vec::new();
    for g in 0..2 {
        let dir = root.join(format!("get{g}"));
        std::fs::create_dir_all(&dir).expect("APPARATUS: create the download directory");
        let out = root.join(format!("get{g}.out"));
        let kid = spawn_vox(
            &bob,
            &[
                "room",
                "get",
                &room,
                "big.bin",
                "--out",
                dir.join("big.bin")
                    .to_str()
                    .expect("APPARATUS: a UTF-8 path"),
            ],
            &out,
        );
        let t0 = Instant::now();
        while collected(&dir) == 0 {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): collector {g} received nothing\n{}\n{}",
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
        held.iter().all(|&b| b > 0),
        "PRODUCT (staging): a `vox room get` had collected nothing of big.bin when frozen: \
         {held:?}"
    );
    assert!(
        held.iter().all(|&b| b < FILE_BYTES as u64),
        "APPARATUS, CANNOT MEASURE: the proof's file was too small; a collector had all of it \
         when frozen: {held:?}"
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
        "APPARATUS, CANNOT MEASURE: the download tunnels did not take the window: the sender's reads \
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
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: `vox room send` never printed its offer's tag (\"… as <tag>\"): {said:?}"
            )
        })
        .to_owned();
    // Bob has already read the offer above, so a missing author here is the control-socket read.
    let host = rb.author_of(cb, "big.bin").unwrap_or_else(|| {
        panic!("APPARATUS: Bob's control-socket read found no row naming big.bin, already read")
    });
    let bound = rb.forward(cb, host, &tag);
    let (socks, written) = writers(&bound, 2);
    let taken = stalled(|| loads(&written));
    eprintln!(
        "[proof] upload arm: the writes stopped being taken at {taken:?} bytes (the window counts \
         as taken from {TAKEN} in all)"
    );
    assert!(
        taken
            .as_ref()
            .is_some_and(|t| t.iter().all(|&b| b > 0) && t.iter().sum::<u64>() >= TAKEN),
        "APPARATUS, CANNOT MEASURE: the upload tunnels did not take the window: written {taken:?} of the \
         {TAKEN} needed"
    );
    let upload = phase(&alice, &bob, &mut ra, &mut rb, ca, cb, &room, "upload");

    // The cap arm: Bob opens tunnels to the frozen sender until his connection to Alice carries
    // all it may, then more.
    let alice_pid = alice_d.pid();
    let cap = TUNNELS_PER_PEER as usize;
    let (more_socks, more) = writers(&bound, cap - written.len());
    let at_cap = stalled(|| loads(&written).into_iter().chain(loads(&more)).collect());
    let rss_at_cap = rss(alice_pid);
    // What each side's `vox status` lists now: Bob's 16 tunnels to the offer, Alice's 16 from him.
    let listed = |m: &Member, way: &str| -> (usize, String, String) {
        // Not `Member::status`: here the listing is the claim, so a failed one is the product's.
        let (ok, out, err) = m.vox(&["status", "--json"], None);
        assert!(ok, "PRODUCT: {}: vox status --json failed: {err}", m.name);
        let json: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| {
            panic!(
                "PRODUCT: {}: vox status --json printed what is not JSON, {out:?}: {e}",
                m.name
            )
        });
        let rows = json["tunnels"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|t| {
                        t["service"].as_str() == Some(tag.as_str())
                            && t["direction"].as_str() == Some(way)
                            && t["opened"].as_u64().is_some_and(|s| s > 0)
                            && t["last_moved"].as_u64().is_some_and(|s| s > 0)
                    })
                    .count()
            })
            .unwrap_or(0);
        let (ok, human, err) = m.vox(&["status"], None);
        assert!(ok, "PRODUCT: {}: vox status failed: {err}", m.name);
        (rows, human, out)
    };
    let (bob_rows, bob_human, _) = listed(&bob, "out");
    let (alice_rows, alice_human, alice_json) = listed(&alice, "in");
    // **Each tunnel is listed once** (V210-81, #314): Alice serves the offer and forwards nothing,
    // so every mention of its tag in her status is one of the tunnels, in one listing.
    let alice_said = alice_human
        .lines()
        .filter(|l| l.contains(tag.as_str()))
        .count();
    let alice_named = alice_json.matches(&format!("\"{tag}\"")).count();
    let human_lines = |text: &str, way: &str| {
        text.lines()
            .filter(|l| {
                l.starts_with("tunnel ")
                    && l.contains(&format!(" {way} "))
                    && l.contains(": open ")
                    && l.contains(tag.as_str())
            })
            .count()
    };
    let (bob_lines, alice_lines) = (
        human_lines(&bob_human, "to"),
        human_lines(&alice_human, "from"),
    );
    eprintln!(
        "[proof] cap arm: vox status lists {bob_rows} tunnel(s) on Bob ({bob_lines} line(s)) and \
         {alice_rows} on Alice ({alice_lines} line(s)) for {tag}; Bob's says:\n{bob_human}"
    );
    let (extra_socks, extra) = writers(&bound, EXTRA);
    let past_cap = stalled(|| loads(&extra));
    let rss_past_cap = rss(alice_pid);
    eprintln!(
        "[proof] cap arm: the first {cap} tunnels took {at_cap:?} bytes; the {EXTRA} past the cap \
         took {past_cap:?}; alice's daemon resident {rss_at_cap} KiB at the cap, {rss_past_cap} KiB \
         past it"
    );
    assert!(
        at_cap.is_some() && past_cap.is_some(),
        "APPARATUS, CANNOT MEASURE: the cap arm's writes kept advancing past {STALL_WITHIN:?}: the first \
         {cap} took {at_cap:?}, the {EXTRA} past the cap {past_cap:?}"
    );
    assert!(
        at_cap.iter().flatten().all(|&b| b >= ONE_WINDOW_TAKEN),
        "PRODUCT: Bob's connection to Alice refused a tunnel before {cap} were open (bytes \
         each took: {at_cap:?}): a tunnel that ended earlier still counts, or the cap is lower"
    );
    // The person's side: a collection asked for now is refused, saying why.
    let get_dir = root.join("get-past-cap");
    std::fs::create_dir_all(&get_dir).expect("APPARATUS: create the download directory");
    let get_out = root.join("get-past-cap.out");
    let mut get = spawn_vox(
        &bob,
        &[
            "room",
            "get",
            &room,
            "big.bin",
            "--out",
            get_dir
                .join("big.bin")
                .to_str()
                .expect("APPARATUS: a UTF-8 path"),
        ],
        &get_out,
    );
    let refused = get.exited_within(REFUSED_WITHIN);
    let get_said = std::fs::read_to_string(get_out.with_extension("err")).unwrap_or_default();
    drop(get);
    let cap_arm = phase(&alice, &bob, &mut ra, &mut rb, ca, cb, &room, "cap");
    for sock in socks.iter().chain(&more_socks).chain(&extra_socks) {
        let _ = sock.shutdown(Shutdown::Both);
    }
    send.signal("-CONT");

    eprintln!(
        "[proof] cap arm: Alice's status names {tag} on {alice_said} line(s) and {alice_named} \
         time(s) in --json"
    );
    assert!(
        alice_said == cap && alice_named == cap,
        "PRODUCT: with {cap} tunnels open to Alice's offer, her `vox status` names {tag} on \
         {alice_said} line(s) and {alice_named} time(s) in --json: a tunnel is listed more than \
         once\nAlice's vox status:\n{alice_human}"
    );
    assert!(
        [bob_rows, bob_lines, alice_rows, alice_lines]
            .iter()
            .all(|&n| n == cap),
        "PRODUCT: with {cap} tunnels open from Bob to Alice's offer, `vox status` did not list each \
         on both sides: Bob {bob_rows} in --json, {bob_lines} line(s); Alice {alice_rows} in \
         --json, {alice_lines} line(s)\nBob's vox status:\n{bob_human}\nAlice's:\n{alice_human}"
    );
    eprintln!("[proof] cap arm: Bob's `vox room get` past the cap said:\n{get_said}");
    assert!(
        refused.is_some_and(|ok| !ok)
            && get_said.contains(LIMIT_SAID)
            && FREE_ONE_SAID.iter().all(|s| get_said.contains(s))
            && get_said.contains(&format!("{tag} ×{cap}")),
        "PRODUCT: with {cap} tunnels open to Alice, Bob's `vox room get` was not refused within \
         {REFUSED_WITHIN:?} saying {LIMIT_SAID:?}, how to free one ({FREE_ONE_SAID:?}) and which \
         service they go to (\"{tag} ×{cap}\"): it exited {refused:?} (None: still running) and \
         said {get_said:?}"
    );
    assert!(
        past_cap.iter().flatten().all(|&b| b < ONE_WINDOW_TAKEN),
        "PRODUCT: tunnels past the cap of {cap} were carried: each took {past_cap:?} bytes"
    );
    let grew = rss_past_cap.saturating_sub(rss_at_cap) << 10;
    assert!(
        grew < GREW_PAST_CAP,
        "PRODUCT: alice's daemon grew by {grew} bytes when Bob opened {EXTRA} tunnels past the cap \
         ({rss_at_cap} KiB → {rss_past_cap} KiB): a member's tunnels are not bounded"
    );
    for (arm, got) in [("download", download), ("upload", upload), ("cap", cap_arm)] {
        assert!(
            got.iter().all(|m| m.is_some_and(|m| m <= BOUND)),
            "PRODUCT: {arm} arm: with two tunnels backpressured, a post was not read within {BOUND:?} \
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
