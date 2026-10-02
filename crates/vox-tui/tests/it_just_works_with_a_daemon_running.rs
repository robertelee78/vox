//! The verbs a person cannot skip must work while their daemon is running.
//!
//! redb is single-writer, so one `vox` at a time may hold a profile. Every verb outside
//! the `vox room …` family spawned its own node, so all of them failed the moment a
//! `vox daemon` held the profile — and running a daemon is the documented way to run
//! agent comms. The failure was
//!
//! ```text
//! vox: node: store open: Database already open. Cannot acquire lock.
//! ```
//!
//! which names a storage engine and no remedy.
//!
//! `vox trust add` is the sharpest case, because it is unavoidable: it is the act that
//! decides who may read you (ADR-020 §3), and until it is run nobody can read anything.
//! Setting up two agents against a live anchor is exactly where this was hit.
//!
//! The fix is not to widen the socket. ADR-020 §7 keeps keyring edits off it because an
//! agent session runs model-authored code and can reach the socket, and that reasoning
//! stands. So the request carries the **identity passphrase** and the node checks it
//! first: the operator holds it, an agent does not.
//!
//! What this proves, by running the shipped binary against a real daemon:
//!
//! 1. `vox trust add` **works while the daemon holds the profile** — the case that used
//!    to be impossible;
//! 2. `vox trust list` sees it, also over the socket;
//! 3. a **wrong identity passphrase is refused**, which is the whole reason this is safe
//!    to put on a socket an agent can reach — without it this proof would be measuring a
//!    hole rather than a fix;
//! 4. `vox trust remove` works the same way;
//! 5. a daemon started with a **bare passphrase** — no room id — opens the room anyway.
//!    That one exists because after a restart every room is closed, a closed room cannot
//!    show its name (it lives in the SEK-sealed manifest), and the unlock line matched on
//!    name: you needed the name to unlock, and unlocking is what reveals it. The id works
//!    and nothing said so, and `room list` needs a running node, so learning the id meant
//!    starting a daemon bare, listing, stopping it, and starting it again.
//!
//! **Every participant is the shipped binary.** The profile is made as a person makes one
//! — `vox id`, a `vox daemon` holding it while `vox room create` (room passphrase on stdin)
//! makes the room, that daemon stopped with SIGTERM and reaped — and the stranger to trust
//! is a second profile's `vox id`. Nothing in this process runs a node.
//!
//! **Mutation.** Skip the identity-passphrase check on `Request::Trust` in the control
//! socket (`serve_request` in `vox-core/src/node/ipc.rs`) and this goes red at claim 3: the
//! wrong passphrase's `trust add` succeeds.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "daemon passphrase";
const ROOMPASS: &str = "channel passphrase";

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `vox` with a different identity passphrase in the environment, for the claim that a
/// wrong one is refused.
fn vox_as(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    passphrase: &str,
) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env("VOX_IDENTITY_PASSPHRASE", passphrase)
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

fn vox(data: &std::path::Path, cfg: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    vox_in(data, cfg, args, None)
}

/// `vox`, with `input` piped to stdin when given (`room create` reads its passphrase there).
fn vox_in(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    input: Option<&str>,
) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        // The identity passphrase goes in the environment, not argv: a command line is
        // world-readable while the process runs, so the flag is refused (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox");
    if let Some(text) = input {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox's stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write vox's stdin");
        drop(pipe);
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Wait for the daemon's socket to answer rather than guessing at a sleep. `side` labels the red:
/// `PRODUCT (staging)` while staging, `PRODUCT` where a daemon that never answers is the claim.
fn until_attached(data: &std::path::Path, cfg: &std::path::Path, side: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (ok, out, err) = vox(data, cfg, &["room", "list"]);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!(
        "{side}: timed out waiting for the daemon's socket; last error: {last}\n  daemon stdout: \
         {:?}\n  daemon stderr: {:?}",
        std::fs::read_to_string(data.parent().unwrap_or(data).join("daemon.out"))
            .unwrap_or_default(),
        std::fs::read_to_string(data.parent().unwrap_or(data).join("daemon.err"))
            .unwrap_or_default()
    );
}

/// Start `vox daemon` with `stdin_lines` piped in.
fn daemon(data: &std::path::Path, cfg: &std::path::Path, stdin_lines: &str) -> Daemon {
    // Its output goes to files, not to /dev/null. A daemon that refuses to start says
    // why on stderr, and discarding that turns every such failure into "timed out
    // waiting for the socket" — which is what it looked like while this was being
    // written, twice.
    let log = data.parent().unwrap_or(data);
    let out = std::fs::File::create(log.join("daemon.out"))
        .expect("APPARATUS: create the daemon's stdout file");
    let err = std::fs::File::create(log.join("daemon.err"))
        .expect("APPARATUS: create the daemon's stderr file");
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    // Write, then **close** it. The daemon reads stdin to EOF, so a handle left open
    // leaves it blocked on the read and it never binds its socket — which looks exactly
    // like a daemon that failed to start.
    let mut pipe = child.stdin.take().expect("APPARATUS: the daemon's stdin");
    pipe.write_all(stdin_lines.as_bytes())
        .expect("APPARATUS: write the daemon's passphrases");
    drop(pipe);
    Daemon(child)
}

#[test]
#[ignore = "production Argon2id at setup + runs the real binary as a daemon; CI runs it in release"]
fn the_verbs_a_person_cannot_skip_work_while_a_daemon_holds_the_profile() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");

    // ---- a profile with an identity and a room, made through the binary, and nothing
    // running ----
    let room_id = make_profile(&data, &cfg);
    // Somebody to trust who is not us: a second identity, made the same way. The keyring
    // records a decision about a key, and the key's owner need not be online.
    let other = tmp.path().join("stranger");
    let (ok, stranger, err) = vox(&other.join("data"), &other.join("cfg"), &["id"]);
    assert!(ok, "PRODUCT (staging): vox id (stranger): {err}");
    let stranger = stranger.trim().to_owned();
    assert_eq!(
        stranger.len(),
        52,
        "PRODUCT (staging): `vox id` (stranger) printed no fingerprint: {stranger:?}"
    );
    println!(
        "[proof] profile made by `vox id` + `vox room create`: room {room_id}; stranger {stranger}"
    );

    // ---- claim 5: a bare passphrase opens the room without naming it ----
    // Deliberately not the room id and not the name — just the passphrase, which is all
    // an operator has in front of them after a reboot.
    let _d = daemon(&data, &cfg, &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let listed = until_attached(&data, &cfg, "PRODUCT");
    assert!(
        listed.contains("mission") && !listed.contains("[closed]"),
        "PRODUCT: a daemon given only the room passphrase must open the room it opens: `room list` \
         said {listed:?}. The id is {room_id}, and needing it here is the trap this \
         removes — a closed room cannot show its name, so there was nothing to type"
    );

    // ---- claim 1: trust add, while the daemon holds the profile ----
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &["trust", "add", &stranger, "--name", "agent-two"],
    );
    assert!(
        ok,
        "PRODUCT: `vox trust add` must work while a daemon holds the profile — it is how a person \
         decides who may read them, and there is no way to avoid running it. stdout={out:?} \
         stderr={err:?}"
    );
    assert!(
        out.contains("agent-two"),
        "PRODUCT: and it must say what it granted: {out:?}"
    );

    // ---- claim 3: a wrong passphrase is refused ----
    // This is the load-bearing one. ADR-020 §7 keeps keyring edits off this socket
    // because an agent session can reach it; the passphrase is what replaces that
    // exclusion. If it were not checked, claim 1 would be measuring a hole.
    let (ok, out, err) = vox_as(
        &data,
        &cfg,
        &["trust", "add", &stranger, "--name", "not-me"],
        "this is not the passphrase",
    );
    assert!(
        !ok,
        "PRODUCT: a wrong identity passphrase must be refused, or the control socket would let \
         anything running as this user decide who may read the operator; it succeeded: \
         stdout={out:?} stderr={err:?}"
    );
    assert!(
        err.contains("passphrase"),
        "PRODUCT: and the refusal must say why: stdout={out:?} stderr={err:?}"
    );

    // ---- claim 2: trust list, over the socket ----
    let (ok, out, err) = vox(&data, &cfg, &["trust", "list"]);
    assert!(
        ok,
        "PRODUCT: `vox trust list` against a running daemon: {err:?}"
    );
    assert!(
        out.contains("agent-two") && out.contains(&stranger),
        "PRODUCT: the keyring must show what was added: {out:?}"
    );
    assert!(
        !out.contains("not-me"),
        "PRODUCT: and must NOT contain the entry the wrong passphrase tried to add: {out:?}"
    );

    // ---- claim 4: trust remove, over the socket ----
    let (ok, _, err) = vox(&data, &cfg, &["trust", "remove", &stranger]);
    assert!(
        ok,
        "PRODUCT: `vox trust remove` against a running daemon: {err:?}"
    );
    let (ok, out, err) = vox(&data, &cfg, &["trust", "list"]);
    assert!(
        ok,
        "PRODUCT: `vox trust list` after the remove failed, so it shows nothing about the \
         entry: stdout={out:?} stderr={err:?}"
    );
    assert!(
        !out.contains("agent-two"),
        "PRODUCT: and the entry must be gone: {out:?}"
    );
    println!(
        "[proof] trust add, list, the wrong passphrase's refusal and remove all went through \
         the running daemon"
    );
}

/// Make the profile a person makes: `vox id`, a `vox daemon` holding it while `vox room
/// create` makes the room, then that daemon stopped with SIGTERM and reaped. Returns the
/// room's short id as `vox room list` prints it.
fn make_profile(data: &std::path::Path, cfg: &std::path::Path) -> String {
    let (ok, fp, err) = vox(data, cfg, &["id"]);
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    assert_eq!(
        fp.trim().len(),
        52,
        "PRODUCT (staging): `vox id` printed no fingerprint: {fp:?}"
    );
    let mut setup = daemon(data, cfg, &format!("{IDENTITY}\n"));
    until_attached(data, cfg, "PRODUCT (staging)");
    let (ok, _, err) = vox_in(
        data,
        cfg,
        &["room", "create", "--name", "mission"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let listed = until_attached(data, cfg, "PRODUCT (staging)");
    assert!(
        listed.contains("mission"),
        "PRODUCT (staging): the new room is not listed: {listed:?}"
    );
    let room = listed
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): the new room in `vox room list`")
        .to_owned();
    // Stopped as a service manager stops it, and waited for, so the proof proper starts
    // from a profile nothing holds and every room closed.
    let pid = setup.0.id();
    let stopped = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("APPARATUS: run kill");
    assert!(
        stopped.success(),
        "APPARATUS: `kill -TERM {pid}` did not take ({stopped}), so the setup daemon was not stopped"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while setup
        .0
        .try_wait()
        .expect("APPARATUS: wait for the setup daemon")
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "PRODUCT: `vox daemon` (the setup daemon, pid {pid}) was still running 30 s after SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(setup);
    let (ok, _, err) = vox(data, cfg, &["room", "list"]);
    assert!(
        !ok && err.contains("no node is running"),
        "PRODUCT (staging): the profile must be held by nothing before the proof starts: {err:?}"
    );
    room
}
