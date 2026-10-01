//! A `vox daemon` **stops when it is told to**, promptly, even when the peers it was talking
//! to have vanished — driven through the shipped binary.
//!
//! Found while auditing failure reasons (PRD-001 R36): a daemon that had joined a room through
//! an anchor printed `vox daemon: shutting down` on SIGTERM and then sat, at 0% CPU, for 59.6 s
//! when the anchor and the room's host had gone away just before. Measured with the node's own
//! stall report: it was `busy 60011ms — passing on a record that landed on our board`, i.e.
//! publishing to two boards nobody was reading, each waiting out a frame read, and `Shutdown`
//! queued behind it. A service manager's SIGTERM, a laptop lid, a `docker stop` — all of them
//! would have waited a minute, and most would have escalated to SIGKILL.
//!
//! What it asserts: with the anchor and the host killed without warning, SIGTERM stops the
//! daemon within [`STOP_WITHIN`], it says why it did not stop cleanly, **the profile is free
//! the moment it has exited** — `vox trust list`, a verb that opens the profile with its own
//! node and does not retry a busy one, run immediately, succeeds — and no process is left.
//! That third assertion is the user-visible half of "shutting a node down releases its
//! profile" (RP-46); the in-process `Shutdown`→`Done` contract is not something a shipped
//! process exposes.
//!
//! Mutations: the unbounded `node.apply(Shutdown)` this replaced turns it red at ~60 s; a
//! daemon that leaves something holding its store's lock past its own exit turns it red at
//! the `vox trust list`, which is refused with "another vox already has this profile open".
//!
//! ## And when a finished transfer's last bytes are unacknowledged (V210-81, #272)
//! [`a_stop_waits_out_last_bytes_within_its_patience`]: a stopping node waits, up to
//! `STOP_ACK_BOUND`, for tunnels that finished their stream to have their last bytes
//! acknowledged, then closes its connections. With that bound equal to the daemon's 5 s
//! patience, a stop that waited out an unacknowledged tail ran into the patience: the daemon
//! printed "the node did not stop within 5s … stopping anyway" and left with its ordered stop
//! cut short. Staging, all real processes: Alice and Bob are `vox daemon`s in one room; Alice
//! offers a [`FILE_BYTES`]-byte file (under a tunnel's window) with `vox room send`, Bob starts
//! `vox room get`, and at its first bytes Bob's daemon is frozen (SIGSTOP), so Alice's tunnel
//! finishes its stream with the tail unacknowledged; then Alice's daemon gets SIGINT.
//! Asserted: it exits within [`PATIENCE`] and never says it gave up. Preconditions (else the
//! attempt is staged again, up to [`ATTEMPTS`] times, then CANNOT MEASURE): Alice's
//! `vox room send` read the whole file (it closes the file once it has), the collector did
//! not have it, and the stop took at least [`WAITED`] (a tail acknowledged before the stop
//! makes it immediate). Mutation: `STOP_ACK_BOUND` back at 5 s — the daemon exits after about
//! 5.04 s saying "the node did not stop within 5s": red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sync_pair::{Member, ID_PASS};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
/// The daemon waits 5 s for its node before leaving anyway; this leaves room for the rest.
const STOP_WITHIN: Duration = Duration::from_secs(10);

struct Proc {
    name: &'static str,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: impl Read + Send + 'static) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    lines
}

impl Proc {
    fn spawn(name: &'static str, dir: &std::path::Path, args: &[&str], stdin: &str) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(stdin.as_bytes()).expect("write stdin");
        drop(pipe);
        let out = collect(child.stdout.take().expect("stdout"));
        let err = collect(child.stderr.take().expect("stderr"));
        Self {
            name,
            child,
            out,
            err,
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.out.lock().unwrap().clone()
    }

    fn expect_out(&self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(l) = self.stdout().into_iter().find(|l| pred(l)) {
                return l;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: never printed {what}; stdout {:#?}\nstderr:\n{}",
            self.name,
            self.stdout(),
            self.err.lock().unwrap().join("\n")
        );
    }
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin.as_bytes()).expect("write");
    drop(pipe);
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
#[ignore = "three real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn a_daemon_stops_on_sigterm_even_when_its_peers_have_vanished() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir, joiner_dir) = (dir("anchor"), dir("host"), dir("joiner"));

    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &["node", "--listen", "127.0.0.1:0"],
        "",
    );
    let spec = anchor
        .expect_out("an anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    for d in [&host_dir, &joiner_dir] {
        let (ok, said) = vox(d, &["id"], "");
        assert!(ok, "vox id: {said}");
    }
    let mut host = Proc::spawn(
        "host",
        &host_dir,
        &["serve", "9", "--anchor", &spec, "--listen", "127.0.0.1:0"],
        "",
    );
    let field = |label: &str| {
        host.expect_out(label, |l| l.starts_with(label))
            .strip_prefix(label)
            .unwrap()
            .trim()
            .to_owned()
    };
    let (address, passphrase) = (field("address"), field("passphrase"));
    let mut daemon = Proc::spawn(
        "joiner-daemon",
        &joiner_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    daemon.expect_out("its control socket", |l| l.contains("control socket"));
    let (ok, said) = vox(
        &joiner_dir,
        &["room", "join", &address, "--name", "svc"],
        &format!("{passphrase}\n"),
    );
    assert!(ok, "CANNOT MEASURE: the join failed: {said}");

    // The peers vanish without a word — no close frames, as when a machine loses power.
    let _ = anchor.child.kill();
    let _ = anchor.child.wait();
    let _ = host.child.kill();
    let _ = host.child.wait();
    std::thread::sleep(Duration::from_secs(1));

    let pid = daemon.child.id();
    let started = Instant::now();
    let sent = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sent.success(), "SIGTERM could not be sent");
    let deadline = started + Duration::from_secs(90);
    while alive(pid) && daemon.child.try_wait().ok().flatten().is_none() {
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let exited = daemon.child.try_wait().ok().flatten();
    let said = daemon.err.lock().unwrap().join("\n");
    eprintln!("[shutdown] SIGTERM -> exit in {took:?}; exit={exited:?}");
    assert!(
        exited.is_some() && took < STOP_WITHIN,
        "a daemon must stop within {STOP_WITHIN:?} of SIGTERM; it took {took:?} (exited: \
         {exited:?}). stdout {:#?}\nstderr:\n{said}",
        daemon.stdout()
    );
    assert!(
        daemon.stdout().iter().any(|l| l.contains("shutting down")),
        "it must say it is shutting down"
    );

    // The profile is free the moment the daemon has exited: a one-shot verb that opens it
    // with its own node, and does not retry a busy profile, run with nothing in between.
    let (opened, said_after) = vox(&joiner_dir, &["trust", "list"], "");
    eprintln!("[shutdown] `vox trust list` right after the exit: opened={opened}");
    assert!(
        opened,
        "the profile must be free the moment the daemon has exited; `vox trust list` said: \
         {said_after}"
    );

    // Nothing left behind: every process this test started is gone.
    let pids = [anchor.child.id(), host.child.id(), pid];
    let remaining = pids.iter().filter(|p| alive(**p)).count();
    assert_eq!(remaining, 0, "processes still running: {pids:?}");
    eprintln!("[shutdown] {remaining} processes remain");
}

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

fn spawn_member(m: &Member, args: &[&str], out: &Path) -> Kid {
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

/// How far `pid`'s open descriptors of `name` have read, from the shipped `lsof`; `None` when
/// `lsof` listed no descriptor of `pid` at all (so it saw nothing, not a closed file).
fn read_offsets(pid: u32, name: &str) -> Option<Vec<u64>> {
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
    let (mut offset, mut offsets, mut listed) = (None, Vec::new(), false);
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
            listed = true;
        }
    }
    listed.then_some(offsets)
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
        let mut f = std::fs::File::create(&file).expect("APPARATUS: create the offered file");
        let chunk: Vec<u8> = (0..1 << 20)
            .map(|i: u32| (i.wrapping_mul(7).wrapping_add(n as u32) % 251) as u8)
            .collect();
        for _ in 0..FILE_BYTES >> 20 {
            f.write_all(&chunk)
                .expect("APPARATUS: write the offered file");
        }
    }
    let send_out = root.join(format!("send{n}.out"));
    let send = spawn_member(
        &alice,
        &[
            "room",
            "send",
            &room,
            file.to_str().expect("APPARATUS: a UTF-8 path"),
        ],
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
    std::fs::create_dir_all(&dir).expect("APPARATUS: create the download directory");
    let get_out = root.join(format!("get{n}.out"));
    let _get = spawn_member(
        &bob,
        &[
            "room",
            "get",
            &room,
            &offered,
            "--out",
            dir.join(&offered)
                .to_str()
                .expect("APPARATUS: a UTF-8 path"),
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
    // `vox room send` closes the file as soon as it has read all of it; the collector already
    // holds bytes read from it, so a file no longer open was read to its end (nothing has
    // stopped the offer, and a read error is not staged here).
    let (read, open) = loop {
        let (read, open): (u64, &str) = match read_offsets(send.0.id(), &offered) {
            Some(offsets) if offsets.is_empty() => (FILE_BYTES as u64, "closed"),
            Some(offsets) => (offsets.iter().sum(), "open"),
            None => (0, "not listed"),
        };
        if read >= FILE_BYTES as u64 || t2.elapsed() > Duration::from_secs(10) {
            break (read, open);
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    eprintln!(
        "[proof] attempt {n}: the sender read {read} of {FILE_BYTES} (its file {open}); the \
         collector held {held} at the freeze"
    );
    // Let the daemon read the rest of the file and finish the tunnel's stream.
    std::thread::sleep(Duration::from_secs(1));
    if read < FILE_BYTES as u64 || held >= FILE_BYTES as u64 {
        eprintln!("[proof] attempt {n}: not staged");
        bob_d.signal("-CONT");
        return None;
    }

    let stop = Instant::now();
    alice_d.signal("-INT");
    let took = loop {
        if alice_d
            .child
            .try_wait()
            .expect("APPARATUS: poll Alice's daemon's exit")
            .is_some()
        {
            break stop.elapsed();
        }
        assert!(
            stop.elapsed() < Duration::from_secs(30),
            "PRODUCT: Alice's daemon did not exit within 30 s of SIGINT:\n{}",
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
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
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
        "PRODUCT: a daemon stopped with a finished tunnel's tail unacknowledged must finish its own stop \
         within its {PATIENCE:?} patience: it exited {took:?} after SIGINT and said {gave_up:?}"
    );
}
