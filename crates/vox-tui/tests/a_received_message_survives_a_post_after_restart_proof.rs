//! V210-73 (#264) — **a message a member received is still in the room after that member restarts,
//! posts, and restarts again**, driven through the shipped `vox` binary.
//!
//! **The defect.** A room's rows share one id counter: a post's log and cache rows take the same
//! id, and a received message's cache row takes the id after its entry's log row. A reopened room
//! resumed the counter from its log rows alone. So the first post after a restart took the id of
//! the last received message's cache row, and its own cache row silently overwrote that one. The
//! message stayed on screen until the next restart and was then gone for good.
//!
//! What this drives, as people would:
//!
//! ```text
//! vox id; vox trust add …          # alice and bob, consenting to each other
//! vox daemon                       # both, identity passphrase only
//! alice: vox room create; invite   # bob: vox room join
//! alice: vox room post ×3          # bob: vox room read, until all three have arrived
//! bob: (SIGTERM) vox daemon        # restart
//! bob: vox room post               # his first post after the restart
//! bob: (SIGTERM) vox daemon        # restart again
//! bob: vox room read               # all three of alice's posts, and his own
//! ```
//!
//! Mutation: resume the counter from the log rows alone (take the cache rows out of the reopen's
//! id scan) and Bob's last read is missing Alice's third post, the one received last.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Stop it the way a service manager does, and wait for it to leave.
    fn terminate(mut self) {
        let pid = self.0.id().to_string();
        let ok = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("run kill")
            .success();
        assert!(ok, "kill -TERM {pid} failed");
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.0.try_wait().expect("try_wait").is_none() {
            assert!(
                Instant::now() < deadline,
                "the daemon did not leave within 30s of SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
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

/// Start `vox daemon` given the identity passphrase and **nothing else**, then wait until it
/// answers.
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
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, _, err) = vox(dir, &["room", "list"], None);
        if ok {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "{tag}'s daemon never answered: {err}\nits stderr: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn read(dir: &Path, room: &str) -> String {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "vox room read: {err}");
    out
}

/// How many of `posts` appear as a line of `read`.
fn found(read: &str, posts: &[&str]) -> Vec<String> {
    posts
        .iter()
        .filter(|p| read.lines().any(|l| l.ends_with(**p)))
        .map(|p| (*p).to_owned())
        .collect()
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_received_message_survives_a_restart_a_post_and_a_restart() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "vox trust add {name}: {err}");
    }

    let _a = daemon(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "kept"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let (_, listed, _) = vox(&alice, &["room", "list"], None);
    let room: String = listed
        .split_whitespace()
        .next()
        .expect("a room id in `room list`")
        .chars()
        .take(12)
        .collect();
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
    let b = daemon(&bob, "bob-start");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", link.trim(), "--name", "kept"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");

    // ---- alice posts; bob receives all three ------------------------------------------------
    let hers = [
        "alice's first post",
        "alice's second post",
        "alice's third post",
    ];
    for p in hers {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, p], None);
        assert!(ok, "alice posts: {err}");
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = found(&read(&bob, &room), &hers);
        if got.len() == hers.len() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: bob received only {got:?} of alice's posts within 60s"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // ---- bob restarts, posts, restarts ------------------------------------------------------
    b.terminate();
    let b = daemon(&bob, "bob-second");
    let his = "bob's first post after the restart";
    let (ok, _, err) = vox(&bob, &["room", "post", &room, his], None);
    assert!(ok, "bob posts after the restart: {err}");
    b.terminate();
    let _b = daemon(&bob, "bob-third");

    let last = read(&bob, &room);
    let kept = found(&last, &hers);
    println!(
        "[proof] after restart, post, restart: bob reads {} of alice's {} posts, and his own = {}",
        kept.len(),
        hers.len(),
        !found(&last, &[his]).is_empty()
    );
    assert_eq!(
        kept.len(),
        3,
        "a message bob had received is gone after he restarted, posted and restarted: he reads \
         {kept:?}\n{last}"
    );
    assert!(
        !found(&last, &[his]).is_empty(),
        "bob's own post is gone after the restart: {last}"
    );
}
