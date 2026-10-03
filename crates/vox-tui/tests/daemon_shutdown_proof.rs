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
//! printed that its node did not stop within 5s and left with its ordered stop cut short. Staging, all real processes: Alice and Bob are `vox daemon`s in one room; Alice
//! offers a [`FILE_BYTES`]-byte file (under a tunnel's window) with `vox room send`, which is then
//! frozen (SIGSTOP); Bob starts `vox room get`; once Bob's `vox status` lists the tunnel, Bob's
//! daemon is frozen, and only then does the sender go on, so the whole file goes out with nothing
//! acknowledged and Alice's tunnel finishes its stream with the tail unacknowledged, every time;
//! then Alice's daemon gets SIGINT. (Freezing Bob at the collector's first bytes, as this did,
//! staged the scene on 1 attempt in 4 on a fast machine: the rest of the file had already been
//! acknowledged.)
//! Asserted: it exits within [`PATIENCE`], never says it gave up, and reports the stop as a
//! success (it says "stopped by SIGINT" and exits 0, as a service manager expects of a service it
//! stopped). The node's worst-case stop is budgeted under the patience, each wait named
//! (`STOP_WORST_CASE`: 3 s for the tail, 2 × 0.4 s for the goodbye, 0.05 s for relayed closes'
//! lead, 0.6 s for the closes to leave; 4.45 s against 5 s); this scene spends the tail's wait and,
//! with Bob frozen, the goodbye's and the flush's too. Preconditions (else the
//! attempt is staged again, up to [`ATTEMPTS`] times, then `PRODUCT (staging)`, since each is vox's doing): Alice's
//! `vox room send` read the whole file (it closes the file once it has), the collector did
//! not have it, and the stop took at least [`WAITED`] (a tail acknowledged before the stop
//! makes it immediate). Mutations: `STOP_ACK_BOUND` back at 5 s — the daemon exits after about
//! 5.04 s saying it did not finish stopping: red; the goodbye's patience past the budget (2.5 s,
//! the compile-time budget checks removed) — red the same way.
//!
//! ## And a stop that gives up says so (decider, V210-93)
//! [`a_stop_past_its_patience_says_it_did_not_finish`]: a stop the daemon abandons at its patience
//! is a failure, and a person or a service manager must be able to tell it from a stop: the daemon
//! says it did **not** finish stopping (never "stopped by SIGINT") and exits non-zero. No real
//! scene runs past the real patience (the stop is budgeted under it), so the proof shortens it with
//! the test-only `VOX_TEST_SHUTDOWN_PATIENCE_MS` (the `test-knobs` feature) to [`SHORT_PATIENCE`],
//! and stages the same unacknowledged tail, whose wait alone is longer. Staged when the stop took
//! at least that patience (else again, up to [`ATTEMPTS`] times, then `PRODUCT (staging)`). Mutation: a
//! give-up that keeps saying "stopped by SIGINT" and exiting 0 — red, PRODUCT.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

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
            sink.lock()
                .expect("APPARATUS: a lock the proof holds was poisoned")
                .push(line);
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
            .unwrap_or_else(|e| panic!("APPARATUS: spawn {name}: {e}"));
        let mut pipe = child.stdin.take().expect("APPARATUS: stdin");
        pipe.write_all(stdin.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
        drop(pipe);
        let out = collect(child.stdout.take().expect("APPARATUS: stdout"));
        let err = collect(child.stderr.take().expect("APPARATUS: stderr"));
        Self {
            name,
            child,
            out,
            err,
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.out
            .lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .clone()
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
            self.err
                .lock()
                .expect("APPARATUS: a lock the proof holds was poisoned")
                .join("\n")
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
        .expect("APPARATUS: spawn vox");
    let mut pipe = child.stdin.take().expect("APPARATUS: stdin");
    pipe.write_all(stdin.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    drop(pipe);
    let out = child.wait_with_output().expect("APPARATUS: wait");
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
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
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
        assert!(ok, "PRODUCT (staging): vox id: {said}");
    }
    let mut host = Proc::spawn(
        "host",
        &host_dir,
        &["serve", "9=9", "--anchor", &spec, "--listen", "127.0.0.1:0"],
        "",
    );
    let field = |label: &str| {
        host.expect_out(label, |l| l.starts_with(label))
            .strip_prefix(label)
            .expect("APPARATUS: a line matched by its label strips it")
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
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &address,
            "--name",
            "svc",
        ],
        &format!("{passphrase}\n"),
    );
    assert!(ok, "PRODUCT (staging): the join failed: {said}");

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
        .expect("APPARATUS: send SIGTERM");
    assert!(sent.success(), "APPARATUS: SIGTERM could not be sent");
    let deadline = started + Duration::from_secs(90);
    while alive(pid) && daemon.child.try_wait().ok().flatten().is_none() {
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let exited = daemon.child.try_wait().ok().flatten();
    let said = daemon
        .err
        .lock()
        .expect("APPARATUS: a lock the proof holds was poisoned")
        .join("\n");
    eprintln!("[shutdown] SIGTERM -> exit in {took:?}; exit={exited:?}");
    assert!(
        exited.is_some() && took < STOP_WITHIN,
        "PRODUCT: a daemon must stop within {STOP_WITHIN:?} of SIGTERM; it took {took:?} (exited: \
         {exited:?}). stdout {:#?}\nstderr:\n{said}",
        daemon.stdout()
    );
    assert!(
        daemon.stdout().iter().any(|l| l.contains("shutting down")),
        "PRODUCT: it must say it is shutting down"
    );

    // The node is free the moment the daemon has exited: `vox node attach`, which opens it in a
    // new daemon and does not retry a busy node, run with nothing in between.
    let (opened, said_after) = vox(
        &joiner_dir,
        &["node", "attach", "default", "--passphrase-file", "-"],
        &format!("{IDPASS}\n"),
    );
    eprintln!("[shutdown] `vox node attach` right after the exit: opened={opened}");
    let _ = vox(&joiner_dir, &["node", "detach", "default"], "");
    assert!(
        opened,
        "PRODUCT: the node must be free the moment the daemon has exited; `vox node attach` said: \
         {said_after}"
    );

    // Nothing left behind: every process this test started is gone.
    let pids = [anchor.child.id(), host.child.id(), pid];
    let remaining = pids.iter().filter(|p| alive(**p)).count();
    assert_eq!(remaining, 0, "PRODUCT: processes still running: {pids:?}");
    eprintln!("[shutdown] {remaining} processes remain");
}

/// Less than a tunnel's 16 MiB stream window, so the whole file leaves Alice's `vox room send`
/// with Bob frozen.
const FILE_BYTES: usize = 12 << 20;
/// `vox daemon`'s `SHUTDOWN_PATIENCE`.
const PATIENCE: Duration = Duration::from_secs(5);
/// What the daemon prints when it abandons its node's stop.
const GAVE_UP: &str = "did not finish stopping";
/// What the daemon prints when its node's stop finished.
const STOPPED: &str = "vox daemon: stopped by SIGINT";
/// The test-only knob that shortens the daemon's patience.
const PATIENCE_KNOB: &str = "VOX_TEST_SHUTDOWN_PATIENCE_MS";
/// The patience [`a_stop_past_its_patience_says_it_did_not_finish`] gives the daemon: shorter than
/// the unacknowledged tail's own wait (3 s).
const SHORT_PATIENCE: Duration = Duration::from_secs(1);
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

/// Send `sig` to `pid`, by PID.
fn signal_pid(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "APPARATUS: kill {sig} {pid} did not take");
}

/// One staging. `None` when a precondition did not hold; else how long Alice's daemon took to
/// exit after SIGINT, and what it said.
/// Stage the unacknowledged tail and stop Alice's daemon, started with `env`; staged when the stop
/// took at least `waited`.
fn attempt(
    root: &Path,
    n: usize,
    env: &[(&str, &str)],
    waited: Duration,
) -> Option<(Duration, std::process::ExitStatus, String)> {
    let alice = Member::new(&root.join(format!("a{n}")), "alice");
    let bob = Member::new(&root.join(format!("b{n}")), "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let mut alice_d = alice.daemon_with(env);
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
            "PRODUCT (staging): Bob never read the offer"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // The sender is held still until Bob's daemon is frozen: nothing it sends can be
    // acknowledged before the stop, whatever the machine's speed.
    let tag = std::fs::read_to_string(&send_out)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.split(" as ").nth(1).map(|t| t.trim().to_owned()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox room send` never named its offer's tag"));
    signal_pid(send.0.id(), "-STOP");
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
    // The tunnel is up when Bob's own `vox status` lists it (V210-81).
    let t1 = Instant::now();
    loop {
        let listed = bob.status()["tunnels"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|t| t["service"].as_str() == Some(tag.as_str()) && t["direction"] == "out")
        });
        if listed {
            break;
        }
        assert!(
            t1.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): Bob's `vox status` never listed the tunnel to {tag}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Nothing Alice sends from here on is acknowledged; then the sender goes on.
    bob_d.signal("-STOP");
    signal_pid(send.0.id(), "-CONT");
    let held = bytes_in(&dir);
    // Alice's `vox room send` writes the whole file into her daemon, and closes it: under a
    // tunnel's window, so nothing holds it back with Bob frozen. A file it still has open after
    // that was not read to its end.
    std::thread::sleep(Duration::from_secs(3));
    let (read, open): (u64, &str) = match read_offsets(send.0.id(), &offered) {
        Some(offsets) if offsets.is_empty() => (FILE_BYTES as u64, "closed"),
        Some(offsets) => (offsets.iter().sum(), "open"),
        None => (0, "not listed"),
    };
    eprintln!(
        "[proof] attempt {n}: the sender read {read} of {FILE_BYTES} (its file {open}); the \
         collector held {held} at the freeze"
    );
    if read < FILE_BYTES as u64 || held >= FILE_BYTES as u64 {
        eprintln!("[proof] attempt {n}: not staged");
        bob_d.signal("-CONT");
        return None;
    }

    let stop = Instant::now();
    alice_d.signal("-INT");
    let (took, status) = loop {
        if let Some(status) = alice_d
            .child
            .try_wait()
            .expect("APPARATUS: poll Alice's daemon's exit")
        {
            break (stop.elapsed(), status);
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
    if took < waited {
        eprintln!("[proof] attempt {n}: not staged: the tail was acknowledged before the stop");
        return None;
    }
    Some((took, status, said))
}

#[test]
#[ignore = "real daemons with production Argon2id; CI runs it in release"]
fn a_stop_waits_out_last_bytes_within_its_patience() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let (took, status, said) = (0..ATTEMPTS)
        .find_map(|n| attempt(root, n, &[], WAITED))
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): in none of {ATTEMPTS} attempts did vox leave a finished tunnel's tail \
                 unacknowledged at the stop (each attempt's own line says which step it missed)"
            )
        });
    let gave_up = said.lines().find(|l| l.contains(GAVE_UP));
    let stopped = said.lines().any(|l| l.contains(STOPPED));
    eprintln!(
        "[proof] Alice's daemon exited {took:?} after SIGINT ({status}); said it was stopped by \
         SIGINT: {stopped}; gave up: {gave_up:?}"
    );
    assert!(
        gave_up.is_none() && took < PATIENCE,
        "PRODUCT: a daemon stopped with a finished tunnel's tail unacknowledged must finish its own stop \
         within its {PATIENCE:?} patience: it exited {took:?} after SIGINT and said {gave_up:?}"
    );
    assert!(
        status.success() && stopped,
        "PRODUCT: a daemon stopped by SIGINT must report the stop as a success (\"stopped by SIGINT\", \
         exit 0): it exited {status} and said it was stopped by SIGINT: {stopped}\n{said}"
    );
}

#[test]
#[ignore = "real daemons with production Argon2id; CI runs it in release"]
fn a_stop_past_its_patience_says_it_did_not_finish() {
    watchdog::arm();
    test_knobs::require(&[PATIENCE_KNOB]);
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let ms = SHORT_PATIENCE.as_millis().to_string();
    let (took, status, said) = (0..ATTEMPTS)
        .find_map(|n| attempt(root, n, &[(PATIENCE_KNOB, ms.as_str())], SHORT_PATIENCE))
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): in none of {ATTEMPTS} attempts did vox leave a finished tunnel's tail \
                 unacknowledged long enough to outlast a {SHORT_PATIENCE:?} patience"
            )
        });
    let gave_up = said.lines().find(|l| l.contains(GAVE_UP));
    let stopped = said.lines().any(|l| l.contains(STOPPED));
    eprintln!(
        "[proof] with a {SHORT_PATIENCE:?} patience, Alice's daemon exited {took:?} after SIGINT \
         ({status}); said it was stopped by SIGINT: {stopped}; said it did not finish: {gave_up:?}"
    );
    use std::os::unix::process::ExitStatusExt;
    assert!(
        gave_up.is_some() && !stopped && status.code().is_some_and(|c| c != 0) && status.signal().is_none(),
        "PRODUCT: a daemon whose stop ran past its {SHORT_PATIENCE:?} patience must say it did not \
         finish stopping ({GAVE_UP:?}), never {STOPPED:?}, and exit non-zero: it exited {status} \
         {took:?} after SIGINT, said it did not finish: {gave_up:?}, said it was stopped: \
         {stopped}\n{said}"
    );
}
