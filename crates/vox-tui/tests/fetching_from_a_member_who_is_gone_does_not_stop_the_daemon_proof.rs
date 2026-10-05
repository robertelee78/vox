//! V210-41 (#215) — **fetching from a member who is gone does not stop the daemon**, through
//! the shipped binaries.
//!
//! **The defect.** A forward dials the host once before it binds, to say why when the host
//! cannot be reached. That dial runs the whole reachability ladder, and it ran **on the actor** —
//! the one task that answers everyone. `vox room get` asks a running `vox daemon` for exactly such
//! a forward, so fetching a file from a member whose node has gone held the daemon's actor while
//! every direct rung waited out its 10 s timeout: every other request to that daemon — a `vox room
//! list`, another agent's post, a peer's sync — waited behind it. (`vox forward` itself hits the
//! same dial in its own node; seen as `busy 10000ms — opening a forward` in every relayed UDP
//! proof on the v0.3.0 line.)
//!
//! What this drives, as people would: alice and bob, real `vox daemon`s behind a real `vox node`
//! anchor, in one room. Alice shares a file (`vox share`); once bob can see the offer, alice's
//! node is killed (`SIGKILL`, so nothing tells bob), and bob waits out the 30 s the node takes to
//! recognise a silent connection as dead — so the fetch dials afresh, as it would after any real
//! absence. Then bob runs `vox room get`, and **while it dials**, bob posts to the room through
//! the same daemon — a request its actor must answer. What it asserts:
//! 1. the fetch fails (alice is gone) — the dial really ran;
//! 2. every post made during it is taken within [`ANSWER_WITHIN`];
//! 3. bob's daemon reports no stall of a second or more while opening the forward.
//!
//! **Which side a red names.** A failed or slow post is `PRODUCT:` and quotes what vox said; a
//! `vox` step of the setup that failed is `PRODUCT (staging):`. Before the fetch, bob makes the
//! same posts with no fetch running: the product's baseline, never part of the apparatus clock,
//! so one that fails or misses [`ANSWER_WITHIN`] is `PRODUCT (staging):`. The **apparatus clock**
//! is only the apparatus: the time to run `/usr/bin/true`, not vox, right after any slow post. A slow
//! post is `APPARATUS (runner stalled)` only while that clock is over [`APPARATUS_BUDGET`].
//!
//! Mutation: the dial back on the actor (the parent of this change) — (2) and (3) go red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// A long-running child, killed however the test ends, with its pipes drained.
struct Running(Child, Arc<Mutex<String>>);

impl Running {
    /// Whatever the child has said so far, for an assertion message.
    fn said(&self) -> String {
        self.1.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drain a long-lived child's pipes on threads, into a string the test can print.
///
/// **A piped stream nobody reads is a fuse, not a convenience.** The pipe buffer is
/// 64 KiB; when it fills, the child blocks on `write` and stops making progress, and
/// that looks exactly like a hang with no output to explain it. It was harmless only
/// while these children said nothing — `vox daemon` measured **0 bytes** of stderr over
/// a 40s run, which is the reporting blindness this codebase has been fixing all week.
/// Now that a node reports unreachable peers, refused publishes and stalls, the same
/// run produces kilobytes, and at ~140 B/s a 64 KiB pipe fills in about eight minutes.
/// So the bytes that were the hazard become the diagnosis instead.
fn drain(stream: Option<impl std::io::Read + Send + 'static>, into: &Arc<Mutex<String>>) {
    let Some(mut stream) = stream else { return };
    let sink = Arc::clone(into);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Ok(mut s) = sink.lock() {
                        s.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
}

/// One member: a profile and, once started, its real `vox daemon`.
struct Agent {
    data: PathBuf,
    cfg: PathBuf,
    pass: PathBuf,
    daemon: Option<Running>,
}

impl Agent {
    /// `vox` with `stdin` on its standard input.
    fn vox_with(&self, args: &[&str], stdin: &str) -> (bool, String, String) {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: spawn vox");
        child
            .stdin
            .take()
            .expect("APPARATUS: vox's stdin")
            .write_all(stdin.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
        let out = child.wait_with_output().expect("APPARATUS: wait for vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn id_pass(&self) -> &str {
        self.pass.to_str().expect("APPARATUS: a UTF-8 temp path")
    }

    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .output()
            .expect("APPARATUS: spawn vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn spawn(&self, args: &[&str]) -> Running {
        let mut child = {
            Command::new(VOX)
                .args(args)
                .env("VOX_DATA_DIR", &self.data)
                .env("VOX_CONFIG_DIR", &self.cfg)
                .env_remove("VOX_ROOM")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("APPARATUS: spawn vox")
        };
        let said = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take(), &said);
        drain(child.stderr.take(), &said);
        Running(child, said)
    }
}

/// A member as a person sets one up: `vox id`, then a real `vox daemon` on loopback, reaching
/// the anchor at `spec`.
fn agent(tmp: &tempfile::TempDir, name: &str, spec: &str) -> Agent {
    let data = tmp.path().join(name).join("data");
    let cfg = tmp.path().join(name).join("cfg");
    std::fs::create_dir_all(&cfg).expect("APPARATUS: create a staging dir");
    let pass = tmp.path().join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).expect("APPARATUS: write a staging file");
    let mut a = Agent {
        data,
        cfg,
        pass,
        daemon: None,
    };
    let (ok, _, err) = a.vox(&["id", "--identity-passphrase-file", a.id_pass()]);
    assert!(ok, "PRODUCT (staging): {name}: vox id: {err}");
    a.daemon = Some(a.spawn(&[
        "daemon",
        "--listen",
        "127.0.0.1:0",
        "--anchor",
        spec,
        "--passphrase-file",
        a.id_pass(),
    ]));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (ok, _, err) = a.vox(&["room", "list"]);
        if ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {name}'s daemon never answered `vox room list` in 60 s ({err}); \
             the daemon said: {}",
            a.daemon.as_ref().map(Running::said).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    a
}

/// A real `vox node` anchor on loopback, and the `--anchor` spec it prints.
fn anchor(tmp: &tempfile::TempDir) -> (Running, String) {
    let dir = tmp.path().join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: create a staging dir");
    let a = Agent {
        data: dir.join("data"),
        cfg: dir.join("cfg"),
        pass: PathBuf::new(),
        daemon: None,
    };
    let node = a.spawn(&["node", "--listen", "127.0.0.1:0"]);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let said = node
            .1
            .lock()
            .expect("APPARATUS: a poisoned output buffer")
            .clone();
        if let Some(spec) = said
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (node, spec.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the anchor never printed its spec in 60 s; it said: {said}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn fingerprint(a: &Agent) -> String {
    let (ok, out, err) = a.vox(&["id", "--identity-passphrase-file", a.id_pass()]);
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    out.trim().to_owned()
}

fn until(who: &Agent, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) -> String {
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = who.vox(args);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return out;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): timed out waiting for {what}; last saw {last}");
}

/// How long the daemon may take to take a post while a fetch dials.
const ANSWER_WITHIN: Duration = Duration::from_secs(2);
/// The most `/usr/bin/true` may take to run on a runner that can time an [`ANSWER_WITHIN`] bound.
const APPARATUS_BUDGET: Duration = Duration::from_secs(1);

/// The apparatus clock: how long this machine takes, now, to start a process that is **not**
/// vox (`/usr/bin/true`), spawned as vox is. A stalled runner stalls this too; a vox that is slow,
/// even only to start, does not, so it reads as the product's (the #332 trap).
fn apparatus_spawn() -> Duration {
    let t = std::time::Instant::now();
    let ok = std::process::Command::new("/usr/bin/true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn /usr/bin/true for the apparatus clock: {e}"))
        .success();
    assert!(
        ok,
        "APPARATUS: /usr/bin/true failed, so the apparatus clock cannot be read"
    );
    t.elapsed()
}

/// Red if a post missed [`ANSWER_WITHIN`]: `APPARATUS (runner stalled)` when the apparatus clock taken right
/// after it is over [`APPARATUS_BUDGET`], otherwise `side` (the product's). A post that failed
/// is the product's, whatever the clock.
fn answered_within(side: &str, what: &str, ok: bool, took: Duration, said: &str) {
    assert!(ok, "{side}: {what} failed in {took:?}: {said}");
    if took < ANSWER_WITHIN {
        return;
    }
    let apparatus = apparatus_spawn();
    assert!(
        apparatus <= APPARATUS_BUDGET,
        "APPARATUS (runner stalled): apparatus took {apparatus:?} (`/usr/bin/true`, budget \
         {APPARATUS_BUDGET:?}) right after {what} took {took:?}, so the runner, not the node, may \
         be slow"
    );
    panic!(
        "{side}: {what} took {took:?} (bound {ANSWER_WITHIN:?}; apparatus {apparatus:?}). It \
         said: {said}"
    );
}

/// The node treats a connection that has heard nothing for this long as dead
/// (`SILENCE_IS_DEATH`, 30 s), plus a margin: after it, a fetch dials afresh.
const SILENCE: Duration = Duration::from_secs(36);

#[test]
#[ignore = "two networked nodes, real child processes and a 36 s wait; CI runs it in release"]
fn fetching_from_a_member_who_is_gone_does_not_stop_the_daemon() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let source = tmp.path().join("artifact.bin");
    std::fs::write(&source, vec![7u8; 100_000]).expect("APPARATUS: write a staging file");

    let (_anchor, spec) = anchor(&tmp);
    let mut alice = agent(&tmp, "alice", &spec);
    let bob = agent(&tmp, "bob", &spec);
    let (alice_fp, bob_fp) = (fingerprint(&alice), fingerprint(&bob));
    for (who, peer, name) in [(&alice, &bob_fp, "bob"), (&bob, &alice_fp, "alice")] {
        let (ok, _, err) = who.vox(&[
            "trust",
            "add",
            peer,
            "--name",
            name,
            "--identity-passphrase-file",
            who.id_pass(),
        ]);
        assert!(ok, "PRODUCT (staging): trust {name}: {err}");
    }
    let (ok, _, err) = alice.vox_with(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "mission",
        ],
        ROOM_PASS,
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let label = alice
        .vox(&["room", "list"])
        .1
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): alice's new room in `vox room list`")
        .to_owned();
    let (ok, link, err) = alice.vox(&["room", "link", &label]);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let link = link.trim().to_owned();
    let room = link
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): an room link naming the room: {link:?}"))
        .to_owned();
    // One join, no retry: a join that fails is the product's failure, and #217's busy-host
    // refusal is fixed (V210-43), so nothing known excuses one.
    let (ok, out, err) = bob.vox_with(
        &["room", "join", "--passphrase-file", "-", &link],
        ROOM_PASS,
    );
    assert!(
        ok,
        "PRODUCT: `vox room join` failed for bob.\nstdout: {out}\nstderr: {err}"
    );

    // ---- the product's baseline: the same posts, timed the same way, with no fetch running ----
    // Taken while alice is still up, so these posts start no dial to her that could change
    // what the fetch below dials.
    let mut quiet = Duration::ZERO;
    for n in 0..3 {
        let asked = Instant::now();
        let (ok, _, err) = bob.vox(&["room", "post", &room, &format!("before {n}")]);
        let t = asked.elapsed();
        answered_within(
            "PRODUCT (staging)",
            &format!("bob's post {n}, with no fetch running,"),
            ok,
            t,
            &err,
        );
        quiet = quiet.max(t);
    }

    // ---- alice offers a file; bob sees the offer; alice's node goes, unannounced ----
    let (ok, shared, err) = alice.vox(&[
        "share",
        &room,
        source.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    assert!(
        ok,
        "PRODUCT (staging): alice's `vox share` failed: {shared}{err}"
    );
    until(
        &bob,
        "the announcement to reach bob",
        &["room", "read", &room],
        |o| o.contains("artifact.bin"),
    );
    drop(alice.daemon.take()); // SIGKILL, reaped: its QUIC close never leaves
    std::thread::sleep(SILENCE);

    // ---- bob fetches; while it dials, the same daemon is asked for its rooms ----
    let fetch = {
        let (data, cfg, room) = (bob.data.clone(), bob.cfg.clone(), room.clone());
        std::thread::spawn(move || {
            let started = Instant::now();
            let out = Command::new(VOX)
                .args(["room", "get", &room, "artifact.bin"])
                .env("VOX_DATA_DIR", &data)
                .env("VOX_CONFIG_DIR", &cfg)
                .env(
                    "HOME",
                    data.parent().expect("APPARATUS: the profile's parent dir"),
                )
                .env_remove("VOX_ROOM")
                .stdin(Stdio::null())
                .output()
                .expect("APPARATUS: spawn vox room get");
            (
                out.status.success(),
                started.elapsed(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        })
    };
    // A post, not `vox room list`: a list is answered from the view the daemon publishes, and
    // measured it answered in 3-18 ms even while the actor was held for ten seconds. A post is
    // the actor's to append, so it waits for whatever holds the actor — as another agent's post
    // would.
    let mut answers = Vec::new();
    for n in 0..3 {
        std::thread::sleep(Duration::from_millis(700));
        let asked = Instant::now();
        let (ok, _, err) = bob.vox(&["room", "post", &room, &format!("still here {n}")]);
        answers.push((asked.elapsed(), ok, err));
    }
    let (got, took, said) = fetch
        .join()
        .expect("APPARATUS: the thread running `vox room get` panicked");
    let stalls: Vec<String> = bob
        .daemon
        .as_ref()
        .expect("APPARATUS: bob's daemon handle")
        .said()
        .lines()
        .filter(|l| l.contains("busy ") && l.contains("forward"))
        .map(str::to_owned)
        .collect();
    eprintln!(
        "[proof] the fetch took {took:?} (ok={got}); `vox room post` during it answered after {:?} \
         (quiet {quiet:?}); bob's daemon reported {} forward stall(s): {stalls:?}",
        answers.iter().map(|(t, ..)| *t).collect::<Vec<_>>(),
        stalls.len()
    );
    assert!(
        !got,
        "PRODUCT (staging): the fetch from a member who is gone succeeded, so nothing was dialled: \
         {said}"
    );
    let all = answers.iter().map(|(t, ..)| *t).collect::<Vec<_>>();
    for (t, ok, err) in &answers {
        answered_within(
            "PRODUCT",
            &format!(
                "bob's daemon taking a post while a fetch dialled — the dial held its actor (#215); \
                 quiet {quiet:?}, all answers {all:?} —"
            ),
            *ok,
            *t,
            err,
        );
    }
    assert!(
        stalls.is_empty(),
        "PRODUCT: bob's daemon said it stopped answering while it opened the forward (#215): \
         {stalls:?}"
    );
}
