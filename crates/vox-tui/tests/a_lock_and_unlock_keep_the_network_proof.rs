//! V210-80 (#271) — **a lock and an unlock back to back leave the node networked**, driven
//! through the **shipped `vox` binary** and the real `vox tui` in a pty.
//!
//! **The claim.** A lock takes the node's network down and an unlock starts a new one. The old
//! network's accept loop says it stopped (`NetEvent::Stopped`) from its own task, so that word can
//! reach the node *after* the unlock — when the node's queue is full, or the task runs late. It
//! used to be taken as "the network stopped", whichever network it came from: it wiped the new
//! one, and the node went on unlocked with no network at all — every join, dial and sync refused
//! until the next lock. The fix makes the event name its network, and only that one is let go.
//!
//! **Staging.** Alice runs a `vox daemon` holding room `r` and mints an invite. Bob's node is the
//! real `vox tui` (`tests/pty/tui_lock_unlock_join.py`): unlock, `:lock`, the passphrase again at
//! once, then — [`HOLD_SECS`] after the lock — `vox room join` through the TUI's control socket.
//! The TUI runs with the test-only `VOX_TEST_STOPPED_DELAY_MS` = [`STOPPED_DELAY_MS`], which makes
//! the old network say it stopped that late: the late event this race needs, every run, instead of
//! whenever a queue happens to be full. Unset, the knob changes nothing.
//!
//! **Asserted,** with hard-coded numbers: the join through the re-unlocked node succeeds.
//! Preconditions, or `CANNOT MEASURE`: the TUI locked, and unlocked again within
//! [`UNLOCK_BEFORE_MS`] of the lock — sooner than the old network's word arrives, which is what
//! puts that word after the new network; and the join ran after the word arrived.
//!
//! **Mutation that must turn it red:** `NetEvent::Stopped` clears `self.net` whatever network it
//! names (the old behaviour) — the join then fails, because the node it attaches to has no network.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How late the old network says it stopped (the test-only knob).
const STOPPED_DELAY_MS: u64 = 40_000;
/// The unlock must be done this soon after the lock, or the old network's word lands before the
/// new network exists and the race is not staged. Wide, because the unlock is production Argon2id:
/// about 1 s in release, and 13.6–16.0 s measured in debug on a busy machine.
const UNLOCK_BEFORE_MS: u64 = 35_000;
/// The join starts this long after the lock: past the old network's word, with room to spare.
const HOLD_SECS: u64 = 45;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with the identity passphrase on stdin, its output to files by the profile.
fn daemon(dir: &Path, tag: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn vox daemon");
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    Daemon(child)
}

/// `vox room list` once the daemon's socket answers.
fn attached(dir: &Path, tag: &str) -> String {
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
    panic!(
        "CANNOT MEASURE: {tag}'s daemon never answered: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

/// The seconds a `<tag> <what> after <s>s` line of the driver's names.
fn seconds_after(said: &str, what: &str) -> Option<f64> {
    said.lines()
        .find_map(|l| l.strip_prefix(&format!("cargo {what} after ")))
        .and_then(|s| s.trim().trim_end_matches('s').parse().ok())
}

#[test]
#[ignore = "a real vox daemon and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn a_lock_and_unlock_back_to_back_leave_the_node_networked() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        let (ok, _, err) = vox(d, &["id"], None);
        assert!(ok, "vox id: {err}");
    }

    let _alice_daemon = daemon(&alice, "alice");
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "CANNOT MEASURE: vox room create: {err}");
    let room = attached(&alice, "alice")
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("the new room's id in `room list`")
        .to_owned();
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "CANNOT MEASURE: vox room invite: {err}");

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pty/tui_lock_unlock_join.py"
    );
    let hold = HOLD_SECS.to_string();
    let delay = STOPPED_DELAY_MS.to_string();
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &bob.to_string_lossy(),
            &bob.join("cfg").to_string_lossy(),
            IDENTITY,
            ROOMPASS,
            link.trim(),
            &hold,
            &delay,
            "cargo",
        ],
    );
    let said = out.stdout.clone();
    println!(
        "[proof] the TUI driver took {:?}; its last stage: {:?}",
        out.took, out.stage
    );
    println!("[proof] tui: {}", said.trim().replace('\n', " / "));
    assert!(
        out.has_verdict("cargo") || said.contains("cargo join "),
        "CANNOT MEASURE: the TUI driver was stopped before it gave a verdict, at stage {:?} (exit \
         {:?}): {said}",
        out.stage.as_deref().unwrap_or("(before its first stage)"),
        out.code
    );
    assert!(
        out.code == Some(0),
        "CANNOT MEASURE: the TUI driver did not run its steps (exit {:?}): {said}",
        out.code
    );
    let locked = seconds_after(&said, "locked")
        .unwrap_or_else(|| panic!("CANNOT MEASURE: the driver never said the TUI locked: {said}"));
    let unlocked = seconds_after(&said, "unlocked again").unwrap_or_else(|| {
        panic!("CANNOT MEASURE: the driver never said the TUI unlocked again: {said}")
    });
    println!(
        "[proof] locked at +{locked:.2}s, unlocked again at +{unlocked:.2}s; the old network says \
         it stopped at +{:.2}s; the join starts at +{HOLD_SECS}s",
        STOPPED_DELAY_MS as f64 / 1000.0
    );
    assert!(
        unlocked * 1000.0 < UNLOCK_BEFORE_MS as f64,
        "CANNOT MEASURE: the unlock took {unlocked:.2}s after the lock, not under {:.1}s, so the \
         old network's word may have landed before the new network existed",
        UNLOCK_BEFORE_MS as f64 / 1000.0
    );
    assert!(
        said.contains("cargo join ok"),
        "OFFLINE: after a lock and an unlock back to back, a join through the unlocked node failed \
         — the old network's late \"stopped\" took the new network down: {said}"
    );
}
