//! V210-76 (#267) — **locking stops a join in flight: nothing is signed with the identity after
//! the lock, and the join does not complete**, driven through the shipped `vox` binary and the
//! real `vox tui` in a pty.
//!
//! **The defect.** A join runs off the actor, on a task holding the vault signer, the prekey ring
//! and the room passphrase. That task was detached, so `:lock` (or SIGHUP) did not stop it: a node
//! the operator had just locked went on joining for as long as the join took, signing its join
//! with the identity it no longer held, and the responder admitted it.
//!
//! **Staging.** Alice runs `vox daemon` and creates a room. Bob runs `vox tui` and unlocks it,
//! which serves his control socket. Alice's daemon is stopped (SIGSTOP), so a join to her cannot
//! finish, and bob runs `vox room join` with her invite. [`IN_FLIGHT`] later bob types `:lock`;
//! once his TUI shows LOCKED, alice's daemon is resumed (SIGCONT). A join still running then
//! reaches her and completes.
//!
//! **Asserted,** with hard-coded bounds: bob's `vox room join` fails, and within [`ANSWERED`] of
//! the lock, and what it prints names the lock (not "run `vox id`", V210-94); and alice's roster, read [`SETTLE`] after she is resumed, does not name bob.
//! Preconditions, or `CANNOT MEASURE`: the join had not returned when bob locked; alice's roster
//! names alice.
//!
//! **What separates the fix from the defect is the answer time.** The lock also closes the node's
//! endpoint, so a join left running cannot reach alice over it and the roster stays clean either
//! way; the roster check guards against a join that completes regardless. A join that is not
//! stopped keeps the signer, the ring and the passphrase until its dials run out, and only then
//! answers.
//!
//! **Mutation that must turn it red:** the joiner spawned detached again (`tokio::spawn` instead of
//! `join_tasks`): measured, bob's join answered 27.6 s after the lock, in 2 of 2 runs, against
//! 0.7 s with the fix.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long the join runs, against a stopped responder, before bob locks.
const IN_FLIGHT: Duration = Duration::from_secs(3);
/// A lock that stops the join answers it at once; this is generous.
const ANSWERED: Duration = Duration::from_secs(10);
/// How long alice has, once resumed, for a join still running to reach her and complete.
const SETTLE: Duration = Duration::from_secs(40);

/// A child process, killed by its own PID when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION");
    cmd
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = command(dir, args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {pid} failed");
}

/// Wait up to `within` for `path` to exist.
fn cue(path: &Path, within: Duration) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// `vox room list` once alice's daemon answers.
fn attached(dir: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("CANNOT MEASURE: alice's daemon never answered: {last}");
}

#[test]
#[ignore = "real vox daemon and vox tui in a pty, production Argon2id; CI runs it in release"]
fn a_join_in_flight_when_the_node_locks_does_not_complete() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    let cues = tmp.path().join("cues");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    std::fs::create_dir_all(&cues).unwrap();
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    let (alice_fp, bob_fp) = (fps[0].clone(), fps[1].clone());

    // ---- alice: a daemon and a room ------------------------------------------------------
    let alice_err = std::fs::File::create(alice.join("daemon.err")).unwrap();
    let mut alice_daemon = command(&alice, &["daemon", "--listen", "127.0.0.1:0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(alice_err))
        .spawn()
        .expect("spawn alice's daemon");
    {
        let mut pipe = alice_daemon.stdin.take().expect("daemon stdin");
        pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    }
    let alice_daemon = Proc(alice_daemon);
    let alice_pid = alice_daemon.0.id();
    let before: BTreeSet<String> = attached(&alice)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "CANNOT MEASURE: vox room create: {err}");
    let room = attached(&alice)
        .split_whitespace()
        .filter(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .find(|w| !before.contains(w))
        .expect("CANNOT MEASURE: no new room id in alice's `room list`");
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "CANNOT MEASURE: vox room invite: {err}");
    let link = link.trim().to_owned();

    // ---- bob: the real TUI, unlocked -----------------------------------------------------
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_lock_on_cue.py");
    let driver = {
        let (bob, cues) = (bob.clone(), cues.clone());
        std::thread::spawn(move || {
            pty_driver::run(
                script,
                &[
                    VOX,
                    bob.to_str().unwrap(),
                    bob.join("cfg").to_str().unwrap(),
                    IDENTITY,
                    cues.to_str().unwrap(),
                    "bob",
                ],
            )
        })
    };
    assert!(
        cue(&cues.join("unlocked"), Duration::from_secs(120)),
        "CANNOT MEASURE: bob's TUI never unlocked"
    );

    // ---- a join that cannot finish yet, and a lock while it runs --------------------------
    signal(alice_pid, "-STOP");
    let mut join = command(&bob, &["room", "join", &link, "--name", "r"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox room join");
    {
        let mut pipe = join.stdin.take().expect("join stdin");
        pipe.write_all(format!("{ROOMPASS}\n").as_bytes()).unwrap();
    }
    std::thread::sleep(IN_FLIGHT);
    let early = join.try_wait().expect("poll the join");
    std::fs::write(cues.join("lock"), b"").unwrap();
    let locked = cue(&cues.join("locked"), Duration::from_secs(30));
    let locked_at = Instant::now();
    signal(alice_pid, "-CONT");
    assert!(
        early.is_none(),
        "CANNOT MEASURE: bob's join returned before he locked ({early:?}), so no join was in \
         flight"
    );
    assert!(locked, "CANNOT MEASURE: bob's TUI never showed LOCKED");

    // ---- what the join came to ------------------------------------------------------------
    let mut answered = None;
    while locked_at.elapsed() < SETTLE {
        if let Some(status) = join.try_wait().expect("poll the join") {
            answered = Some((status, locked_at.elapsed()));
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if answered.is_none() {
        let _ = join.kill();
    }
    let joined = join.wait_with_output().expect("reap the join");
    let said = String::from_utf8_lossy(&joined.stderr).into_owned();
    std::thread::sleep(SETTLE.saturating_sub(locked_at.elapsed()));
    let (ok, roster, err) = vox(&alice, &["room", "roster", &room], None);
    assert!(ok, "CANNOT MEASURE: alice's roster: {err}");
    let names = |fp: &str| roster.lines().any(|l| l.trim().starts_with(&fp[..26]));
    std::fs::write(cues.join("stop"), b"").unwrap();
    let driven = driver.join().expect("the TUI driver");
    println!(
        "[proof] bob's join answered {:?} after the lock: {}; alice's roster has {} member(s), \
         bob among them: {}; the TUI driver exited {:?} after {:?} at {:?}",
        answered.as_ref().map(|(_, t)| *t),
        said.trim(),
        roster.lines().count(),
        names(&bob_fp),
        driven.code,
        driven.took,
        driven.stage
    );
    assert!(
        driven.has_verdict("bob") && driven.code == Some(0),
        "CANNOT MEASURE: bob's TUI driver did not finish cleanly:\n{}",
        driven.stdout
    );
    assert!(
        names(&alice_fp),
        "CANNOT MEASURE: alice's roster does not name alice:\n{roster}"
    );
    assert!(
        !names(&bob_fp),
        "a join signed after the lock completed: alice admitted bob {SETTLE:?} after she was \
         resumed, though bob locked while the join ran\nbob's join said: {said}\nalice's daemon \
         said: {}",
        std::fs::read_to_string(alice.join("daemon.err")).unwrap_or_default()
    );
    let (status, took) = answered.unwrap_or_else(|| {
        panic!("bob's `vox room join` did not answer within {SETTLE:?} of the lock")
    });
    assert!(
        !status.success(),
        "bob's `vox room join` succeeded after he locked"
    );
    // **And it says why: the lock** (V210-94). It said "this profile has no unlocked identity, so
    // there is nobody to join as / run `vox id` to make one", which sent a person who had just
    // locked to make a second identity.
    assert!(
        said.contains("identity is locked") && !said.contains("vox id"),
        "bob's `vox room join` failed after the lock without naming it — the product said: {}",
        said.trim()
    );
    assert!(
        took < ANSWERED,
        "bob's `vox room join` answered only {took:?} after the lock (bound {ANSWERED:?}): the \
         join ran on after it"
    );
    drop(alice_daemon);
}
