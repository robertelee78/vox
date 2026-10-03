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
//! Preconditions, or `PRODUCT (staging)`: the join had not returned when bob locked. Alice's roster
//! names alice, or `PRODUCT (staging)`.
//!
//! **What separates the fix from the defect is the answer time.** The lock also closes the node's
//! endpoint, so a join left running cannot reach alice over it and the roster stays clean either
//! way; the roster check guards against a join that completes regardless. A join that is not
//! stopped keeps the signer, the ring and the passphrase until its dials run out, and only then
//! answers.
//!
//! **Apparatus clock.** The answer time is read on the same timeline as the runner's own stall: the
//! largest gap between two of the test's 100 ms polls of the join (a `waitpid` and a sleep, which
//! vox cannot slow). If the answer was late and that gap exceeded [`POLL_GAP_BUDGET`], the runner
//! stalled and the red is `APPARATUS (runner stalled)`; otherwise it is `PRODUCT: took X
//! (apparatus Y)`. How long the TUI took to show LOCKED is vox's own timing: printed, never the
//! clock.
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
/// The largest gap between two 100 ms polls of the join, past which the runner stalled.
const POLL_GAP_BUDGET: Duration = Duration::from_secs(2);

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
        .expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox's stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write vox's stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
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
    assert!(ok, "APPARATUS: kill {sig} {pid} failed");
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
    panic!("PRODUCT (staging): alice's daemon never answered: {last}");
}

#[test]
#[ignore = "real vox daemon and vox tui in a pty, production Argon2id; CI runs it in release"]
fn a_join_in_flight_when_the_node_locks_does_not_complete() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    let cues = tmp.path().join("cues");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile dir");
    }
    std::fs::create_dir_all(&cues).expect("APPARATUS: the cue dir");
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        fps.push(out.trim().to_owned());
    }
    let (alice_fp, bob_fp) = (fps[0].clone(), fps[1].clone());

    // ---- alice: a daemon and a room ------------------------------------------------------
    let alice_err =
        std::fs::File::create(alice.join("daemon.err")).expect("APPARATUS: the daemon's log");
    let mut alice_daemon = command(&alice, &["daemon", "--listen", "127.0.0.1:0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(alice_err))
        .spawn()
        .expect("APPARATUS: spawn alice's daemon");
    {
        let mut pipe = alice_daemon
            .stdin
            .take()
            .expect("APPARATUS: the daemon's stdin");
        pipe.write_all(format!("{IDENTITY}\n").as_bytes())
            .expect("APPARATUS: write the daemon's stdin");
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
    assert!(ok, "PRODUCT (staging): vox room create failed: {err}");
    let room = attached(&alice)
        .split_whitespace()
        .filter(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .find(|w| !before.contains(w))
        .expect("PRODUCT (staging): no new room id in alice's `room list`");
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): vox room invite failed: {err}");
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
                    bob.to_str().expect("APPARATUS: a UTF-8 path"),
                    bob.join("cfg").to_str().expect("APPARATUS: a UTF-8 path"),
                    IDENTITY,
                    cues.to_str().expect("APPARATUS: a UTF-8 path"),
                    "bob",
                ],
            )
        })
    };
    if !cue(&cues.join("unlocked"), Duration::from_secs(120)) {
        // A driver that gave up (pyte missing, no unlock screen) has already said why.
        let said = if driver.is_finished() {
            driver.join().map_or_else(
                |_| "the TUI driver thread panicked".to_owned(),
                |d| format!("the driver exited {:?} saying:\n{}", d.code, d.stdout),
            )
        } else {
            "the driver is still running".to_owned()
        };
        // The driver typed the identity passphrase and watched the status line for 60 s: a TUI
        // that never said "unlocked" is the product's. Anything else (pyte missing, a hung
        // driver) is the apparatus's.
        assert!(
            !said.contains("the TUI never unlocked"),
            "PRODUCT (staging): bob's TUI never unlocked with his identity passphrase; {said}"
        );
        panic!("PRODUCT (staging): bob's TUI driver never got as far as the unlock; {said}");
    }

    // ---- a join that cannot finish yet, and a lock while it runs --------------------------
    signal(alice_pid, "-STOP");
    let mut join = command(&bob, &["room", "join", &link, "--name", "r"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox room join");
    {
        let mut pipe = join.stdin.take().expect("APPARATUS: the join's stdin");
        pipe.write_all(format!("{ROOMPASS}\n").as_bytes())
            .expect("APPARATUS: write the join's stdin");
    }
    std::thread::sleep(IN_FLIGHT);
    let early = join.try_wait().expect("APPARATUS: poll the join");
    std::fs::write(cues.join("lock"), b"").expect("APPARATUS: write the lock cue");
    let asked = Instant::now();
    let locked = cue(&cues.join("locked"), Duration::from_secs(30));
    let locked_at = Instant::now();
    let lock_ack = locked_at - asked;
    signal(alice_pid, "-CONT");
    assert!(
        early.is_none(),
        "PRODUCT (staging): bob's join returned before he locked ({early:?}), so no join was in \
         flight"
    );
    if !locked {
        // The driver typed `:lock` and watches the screen for LOCKED for 20 s, then says what it
        // saw; give it that long to finish.
        let t = Instant::now();
        while !driver.is_finished() && t.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let said = if driver.is_finished() {
            driver.join().map_or_else(
                |_| "the TUI driver thread panicked".to_owned(),
                |d| format!("the driver exited {:?} saying:\n{}", d.code, d.stdout),
            )
        } else {
            "the driver is still running".to_owned()
        };
        // A TUI that was typed `:lock` and never showed LOCKED did not take the lock: the
        // product's (a node whose actor a join holds cannot answer it). A driver that never got
        // to `:lock`, or hung, is the apparatus's.
        assert!(
            !said.contains("the TUI never showed LOCKED after :lock"),
            "PRODUCT: bob typed `:lock` while his join was in flight, and his TUI never showed \
             LOCKED; {said}"
        );
        panic!("PRODUCT (staging): bob's TUI driver never typed `:lock` to completion; {said}");
    }

    // ---- what the join came to ------------------------------------------------------------
    let mut answered = None;
    let (mut last_poll, mut poll_gap) = (Instant::now(), Duration::ZERO);
    while locked_at.elapsed() < SETTLE {
        poll_gap = poll_gap.max(last_poll.elapsed());
        last_poll = Instant::now();
        if let Some(status) = join.try_wait().expect("APPARATUS: poll the join") {
            answered = Some((status, locked_at.elapsed()));
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if answered.is_none() {
        let _ = join.kill();
    }
    let joined = join.wait_with_output().expect("APPARATUS: reap the join");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    std::thread::sleep(SETTLE.saturating_sub(locked_at.elapsed()));
    let (ok, roster, err) = vox(&alice, &["room", "roster", &room], None);
    assert!(ok, "PRODUCT (staging): alice's roster failed: {err}");
    let names = |fp: &str| roster.lines().any(|l| l.trim().starts_with(&fp[..26]));
    std::fs::write(cues.join("stop"), b"").expect("APPARATUS: write the stop cue");
    let driven = driver
        .join()
        .expect("APPARATUS: the TUI driver thread panicked");
    println!(
        "[proof] bob's join answered {:?} after the lock: {}; alice's roster has {} member(s), \
         bob among them: {}; the TUI driver exited {:?} after {:?} at {:?}; apparatus: LOCKED \
         shown {lock_ack:?} after the lock was asked for, largest poll gap {poll_gap:?}",
        answered.as_ref().map(|(_, t)| *t),
        said.trim(),
        roster.lines().count(),
        names(&bob_fp),
        driven.code,
        driven.took,
        driven.stage
    );
    if !(driven.has_verdict("bob") && driven.code == Some(0)) {
        // A driver with no verdict, or one naming its own apparatus, failed on its own; any other
        // verdict (RED, HUNG at) is what the TUI did.
        let own = !driven.has_verdict("bob") || driven.stdout.contains("bob APPARATUS");
        let side = if own { "APPARATUS" } else { "PRODUCT" };
        panic!(
            "{side}: bob's TUI driver did not finish cleanly (exit {:?}):\n{}",
            driven.code, driven.stdout
        );
    }
    assert!(
        names(&alice_fp),
        "PRODUCT (staging): alice's roster does not name alice:\n{roster}"
    );
    assert!(
        !names(&bob_fp),
        "PRODUCT: a join signed after the lock completed: alice admitted bob {SETTLE:?} after she was \
         resumed, though bob locked while the join ran\nbob's join said: {said}\nalice's daemon \
         said: {}",
        std::fs::read_to_string(alice.join("daemon.err")).unwrap_or_default()
    );
    let stalled = poll_gap > POLL_GAP_BUDGET;
    let apparatus = format!(
        "largest poll gap {poll_gap:?}, budget {POLL_GAP_BUDGET:?}; LOCKED shown after {lock_ack:?}"
    );
    let Some((status, took)) = answered else {
        assert!(
            !stalled,
            "APPARATUS (runner stalled): the runner stalled ({apparatus}), and bob's `vox room join` did not answer \
             within {SETTLE:?} of the lock"
        );
        panic!(
            "PRODUCT: bob's `vox room join` did not answer within {SETTLE:?} of the lock \
             (apparatus: {apparatus}); it said: {}",
            said.trim()
        );
    };
    assert!(
        !status.success(),
        "PRODUCT: bob's `vox room join` succeeded ({status}) after he locked; it said: {}",
        said.trim()
    );
    // **And it says why: the lock** (V210-94). It said "this profile has no unlocked identity, so
    // there is nobody to join as / run `vox id` to make one", which sent a person who had just
    // locked to make a second identity.
    assert!(
        said.contains("identity is locked") && !said.contains("vox id"),
        "PRODUCT: bob's `vox room join` failed after the lock without naming it; it said: {}",
        said.trim()
    );
    if took >= ANSWERED {
        assert!(
            !stalled,
            "APPARATUS (runner stalled): the runner stalled ({apparatus}), and bob's join answered {took:?} after the \
             lock"
        );
        panic!(
            "PRODUCT: took {took:?} (apparatus {apparatus}): bob's `vox room join` answered only \
             after the bound {ANSWERED:?} — the join ran on after the lock; it said: {}",
            said.trim()
        );
    }
    drop(alice_daemon);
}
