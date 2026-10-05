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
//! the `vox trust list`, which is refused with "another vox already has this node open".
//!
//! ## And when a finished transfer's last bytes are unacknowledged (V210-81, #272)
//! [`a_stop_waits_out_last_bytes_within_its_patience`]: a stopping node waits, up to
//! `STOP_ACK_BOUND`, for tunnels that finished their stream to have their last bytes
//! acknowledged, then closes its connections. With that bound equal to the daemon's 5 s
//! patience, a stop that waited out an unacknowledged tail ran into the patience: the daemon
//! printed that its node did not stop within 5s and left with its ordered stop cut short. Staging, all real processes: Alice and Bob are `vox daemon`s in one room; Alice
//! offers a local server of the proof's own with `vox service add` that sends [`FILE_BYTES`] bytes
//! (under a tunnel's window) unasked, as `vox room send` did; Bob runs `vox forward` to it. Alice's
//! daemon is frozen (SIGSTOP); the proof connects to Bob's forward; once Bob's `vox status` lists
//! the tunnel, Bob's daemon is frozen, and only then does Alice's go on, so the whole payload goes
//! out with nothing acknowledged and Alice's tunnel finishes its stream with the tail
//! unacknowledged, every time; then Alice's daemon gets SIGINT. (A `vox share` cannot stage it:
//! it answers an HTTP request, which must cross from Bob's daemon before either can be held.)
//! Asserted: it exits within [`PATIENCE`], never says it gave up, and reports the stop as a
//! success (it says "stopped by SIGINT" and exits 0, as a service manager expects of a service it
//! stopped). The node's worst-case stop is budgeted under the patience, each wait named
//! (`STOP_WORST_CASE`: 3 s for the tail, 2 × 0.4 s for the goodbye, 0.05 s for relayed closes'
//! lead, 0.6 s for the closes to leave; 4.45 s against 5 s); this scene spends the tail's wait and,
//! with Bob frozen, the goodbye's and the flush's too. Preconditions (else the
//! attempt is staged again, up to [`ATTEMPTS`] times, then `PRODUCT (staging)`, since each is vox's doing): Alice's
//! daemon took the whole payload from the server, the collector did
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

/// Less than a tunnel's 16 MiB stream window, so the whole payload leaves Alice's daemon with Bob
/// frozen.
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

    // **What Alice serves sends unasked**, as `vox room send` did: a local server of the proof's
    // own, offered with `vox service add`, that writes the whole payload to the connection the
    // moment Alice's daemon opens it, then ends its side, as a finished transfer does. A
    // `vox share` cannot stage this: it answers an HTTP request, which must cross from Bob's daemon
    // before either daemon can be held. The tunnel, the daemons and the stop are all the product's.
    let server = std::net::TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the server");
    let local = server
        .local_addr()
        .expect("APPARATUS: the server's address");
    let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let written = Arc::clone(&written);
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = server.accept() else {
                return;
            };
            let chunk: Vec<u8> = (0..1 << 16)
                .map(|i: u32| (i.wrapping_mul(7).wrapping_add(n as u32) % 251) as u8)
                .collect();
            for _ in 0..FILE_BYTES >> 16 {
                if sock.write_all(&chunk).is_err() {
                    return;
                }
                written.fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::SeqCst);
            }
            // All of it: the stream finishes, as a transfer does, with its tail still in flight.
            let _ = sock.shutdown(std::net::Shutdown::Write);
            let _ = sock.read_to_end(&mut Vec::new());
        });
    }
    let (ok, said, err) = alice.vox(&["service", "add", &room, "tail", &local.to_string()], None);
    assert!(
        ok,
        "PRODUCT (staging): Alice's `vox service add` failed: {said}{err}"
    );
    // Bob forwards to it once the share of it has reached him.
    let t0 = Instant::now();
    while !bob
        .vox(&["service", "list", &room], None)
        .1
        .lines()
        .any(|l| l.contains("tail."))
    {
        if t0.elapsed() >= Duration::from_secs(60) {
            eprintln!("[proof] attempt {n}: not staged: Bob never listed Alice's service");
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let fwd_out = root.join(format!("fwd{n}.out"));
    let _fwd = spawn_member(
        &bob,
        &["forward", "tail.alice.pair.vox", "127.0.0.1:0"],
        &fwd_out,
    );
    let t0 = Instant::now();
    let bound = loop {
        let text = std::fs::read_to_string(&fwd_out).unwrap_or_default();
        if let Some(addr) = text
            .lines()
            .find_map(|l| l.strip_prefix("vox: forwarding "))
            .and_then(|l| l.split_whitespace().next())
        {
            break addr.to_owned();
        }
        if t0.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "[proof] attempt {n}: not staged: Bob's `vox forward` never said where it \
                 listens: {text}{}",
                std::fs::read_to_string(fwd_out.with_extension("err")).unwrap_or_default()
            );
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Alice's daemon is held still until Bob's daemon is frozen: nothing it sends can be
    // acknowledged before the stop, whatever the machine's speed.
    alice_d.signal("-STOP");
    let held = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let _collector = {
        let held = Arc::clone(&held);
        let mut sock = std::net::TcpStream::connect(&bound)
            .expect("PRODUCT (staging): connect to the forward");
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 1 << 16];
            while let Ok(got) = sock.read(&mut buf) {
                if got == 0 {
                    return;
                }
                held.fetch_add(got as u64, std::sync::atomic::Ordering::SeqCst);
            }
        })
    };
    // The tunnel is up when Bob's own `vox status` lists it (V210-81).
    let t1 = Instant::now();
    loop {
        let listed = bob.status()["tunnels"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|t| t["service"].as_str() == Some("tail") && t["direction"] == "out")
        });
        if listed {
            break;
        }
        if t1.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "[proof] attempt {n}: not staged: Bob's `vox status` did not list the tunnel to \
                 tail while Alice's daemon was held"
            );
            alice_d.signal("-CONT");
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Nothing Alice sends from here on is acknowledged; then her daemon goes on.
    bob_d.signal("-STOP");
    alice_d.signal("-CONT");
    let held = held.load(std::sync::atomic::Ordering::SeqCst);
    // Alice's daemon takes the whole payload into the tunnel: under a tunnel's window, so nothing
    // holds it back with Bob frozen.
    std::thread::sleep(Duration::from_secs(3));
    let read = written.load(std::sync::atomic::Ordering::SeqCst);
    eprintln!(
        "[proof] attempt {n}: Alice's daemon took {read} of {FILE_BYTES}; the collector held \
         {held} at the freeze"
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
