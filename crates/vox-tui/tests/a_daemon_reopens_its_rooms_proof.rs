//! #208 (V210-35) — a restarted `vox daemon` holds every room it held before, with **no room
//! passphrase given to it**, driven through the shipped `vox` binary.
//!
//! **The defect.** A room is double-locked at rest (ADR-010): its SEK is wrapped under the room
//! passphrase *and* the identity. `vox daemon` unlocks with the identity passphrase alone, so a
//! daemon that restarted came back holding no open room, and every `vox room` verb answered
//! `room "" is not open on this node` — an agent machine running only a daemon lost every room at
//! every reboot, and the error could not even say which room. The decider's answer: the daemon
//! reopens by itself every room it held open, from the room keys kept sealed under the identity.
//!
//! What this drives, as an operator would type it:
//!
//! ```text
//! vox id; vox trust add …               # alice and bob, consenting to each other
//! vox daemon                            # unlock once and remember; no passphrase on restarts
//! vox room create / post                # alice's room, one post
//! vox room link / vox room join       # bob joins it (the join path remembers too)
//! (kill -9 both daemons) vox daemon     # a crash: both rooms must be open again
//! (kill -TERM alice) vox daemon         # a clean stop: the same
//! ```
//!
//! What it does **not** drive: a room closed on purpose staying closed. Only `vox tui` closes a
//! room, so that half is not proven here.
//!
//! Mutations: make `reopen_remembered` return at once and this goes red at alice's first read
//! after the crash; take `remember_open` out of `finish_join_channel` and it goes red at bob's.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
const POST: &str = "said before any restart";

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
            .expect("APPARATUS: run kill")
            .success();
        assert!(ok, "APPARATUS: kill -TERM {pid} did not take");
        let deadline = Instant::now() + Duration::from_secs(30);
        while self
            .0
            .try_wait()
            .expect("APPARATUS: the daemon's exit status could not be read")
            .is_none()
        {
            assert!(
                Instant::now() < deadline,
                "PRODUCT: the daemon did not leave within 30s of SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.to_vec();
    match attach::needs(dir, &verb) {
        Some(node) => {
            attach::Root::at(dir, IDENTITY).attached(&node, || vox_plain(dir, args, stdin))
        }
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(attach::persistent_args(dir, args, IDENTITY))
        .env("HOME", dir.join("home"))
        .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
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
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: vox stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS: write vox stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` without any passphrase. The first start is explicitly unlocked once;
/// every restart has only the state the product remembered, never an auto-unlock helper.
fn daemon(dir: &Path, tag: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: harness file I/O");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: harness file I/O");
    let child = Command::new(VOX)
        .args(["daemon", "--no-node", "--listen", "127.0.0.1:0"])
        .env("HOME", dir.join("home"))
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let d = Daemon(child);
    // Only the first start receives an explicit operator unlock. Restart probes below use
    // vox_plain: the staging wrapper must never unlock on behalf of the claim.
    if tag.ends_with("-start") {
        let (ok, out, err) = vox_plain(dir, &["node", "unlock", "default"], None);
        assert!(
            ok && out.contains("Ready"),
            "PRODUCT (staging): initial Unlock failed: {out}{err}"
        );
    }
    // The first start is staging; every later start is the restart this proof is about.
    let side = if tag.ends_with("-start") {
        "PRODUCT (staging): on its first start,"
    } else {
        "PRODUCT: restarted without any passphrase input,"
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, _, err) = vox_plain(dir, &["room", "list", "--node", "default"], None);
        if ok {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "{side} {tag}'s daemon never answered on its control socket: {err}\nits stderr: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `vox room read` must succeed on `room` — which it does only if the room is OPEN on the
/// daemon — and, when `want` is given, must return that post.
fn reads(dir: &Path, who: &str, when: &str, room: &str, want: Option<&str>) {
    let (ok, out, err) = vox_plain(dir, &["room", "read", room, "--node", "default"], None);
    let (_, listed, _) = vox_plain(dir, &["room", "list", "--node", "default"], None);
    // At the first start the room being open is staging; after a restart it is the claim.
    let side = if when == "start" {
        "PRODUCT (staging):"
    } else {
        "PRODUCT:"
    };
    assert!(
        ok,
        "{side} {when}: {who}'s daemon does not hold the room open (#208): {err}\n`room list`: \
         {listed:?}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{who}-{when}.err"))).unwrap_or_default()
    );
    if let Some(want) = want {
        assert!(
            out.lines().any(|l| l.ends_with(want)),
            "{side} {when}: {who} reads the room but not the post {want:?}: {out:?}"
        );
    }
}

/// The public status comes from the reopened live node, with no helper unlock.
fn free_is_ready(dir: &Path, when: &str) {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let (ok, out, err) = vox_plain(dir, &["status", "--node", "free", "--json"], None);
        let status = serde_json::from_str::<serde_json::Value>(&out).ok();
        if ok && status.as_ref().is_some_and(|s| s["status"] == "Ready") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the passphrase-free node did not become Ready {when}: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_restarted_daemon_holds_every_room_it_held_without_a_room_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("home")).expect("APPARATUS: scratch HOME");
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: harness file I/O");
    }

    // ---- two identities that consent to each other -------------------------------------
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT (staging): vox trust add {name} failed: {err}");
    }

    // ---- alice creates a room and posts; bob joins it ----------------------------------
    let a = daemon(&alice, "alice-start");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "kept"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create failed: {err}");
    let (_, listed, list_err) = vox(&alice, &["room", "list"], None);
    let room: String = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): `room list` shows no room id after `room create`: \
                 {listed:?} {list_err:?}"
            )
        })
        .chars()
        .take(12)
        .collect();
    let (ok, _, err) = vox(&alice, &["room", "post", &room, POST], None);
    assert!(ok, "PRODUCT (staging): vox room post failed: {err}");
    reads(&alice, "alice", "start", &room, Some(POST));

    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): vox room link failed: {err}");
    let b = daemon(&bob, "bob-start");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join failed: {err}");
    reads(&bob, "bob", "start", &room, None);

    // A passphrase-free node is Ready after creation and after Forget. It has no saved
    // credential to restore; startup must actually open its identity with an empty credential.
    let (ok, out, err) = vox_plain(
        &alice,
        &["node", "create", "free", "--passphrase-file", "-"],
        Some("\n"),
    );
    assert!(
        ok && out.contains("Ready"),
        "PRODUCT: no-passphrase creation was not Ready: {out}{err}"
    );
    let (ok, out, err) = vox_plain(&alice, &["node", "lock", "free"], None);
    assert!(
        ok && out.contains("is Ready after the lock request"),
        "PRODUCT: no-passphrase Lock did not stay Ready: {out}{err}"
    );

    // ---- a crash: SIGKILL both, restart both without supplying any passphrase --------
    drop(a);
    drop(b);
    let a = daemon(&alice, "alice-crash");
    let b = daemon(&bob, "bob-crash");
    free_is_ready(&alice, "after a crash");
    reads(&alice, "alice", "crash", &room, Some(POST));
    reads(&bob, "bob", "crash", &room, None);
    drop(b);

    // ---- a clean stop: SIGTERM, restart ------------------------------------------------
    a.terminate();
    let _a = daemon(&alice, "alice-term");
    free_is_ready(&alice, "after a clean daemon stop");
    reads(&alice, "alice", "term", &room, Some(POST));
    let (ok, _, err) = vox(
        &alice,
        &[
            "room",
            "post",
            &room,
            "said after the restarts",
            "--node",
            "default",
        ],
        None,
    );
    assert!(ok, "PRODUCT: the reopened room refused a post: {err}");
    reads(
        &alice,
        "alice",
        "term",
        &room,
        Some("said after the restarts"),
    );
}
