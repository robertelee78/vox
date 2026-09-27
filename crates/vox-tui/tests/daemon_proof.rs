//! ADR-020 §12 / M19.5c — `vox daemon` as a **real child process** with no terminal.
//!
//! Until this existed, agent comms could not work on an unattended host, which
//! contradicts this ADR's premise that agent sessions may be on "n-count remote
//! hosts". The TUI was the only thing serving the control socket; it needs a tty, and per
//! ADR-015 it locks the node on SIGHUP. `vox node` is an anchor — no identity
//! unlocked, no room held, nothing readable.
//!
//! What this proves, by running the shipped binary and talking to it from other
//! processes:
//!
//! 1. `vox daemon` starts from a **piped passphrase**, unlocks the profile, and
//!    reports the identity, the socket and the rooms it holds;
//! 2. a separate `vox room list` **attaches to it** and sees the room — the seam
//!    that makes several agent sessions share one node;
//! 3. `vox room post` through the daemon reaches the log;
//! 4. **SIGHUP does not stop it and does not lock it.** This is the property that
//!    distinguishes a daemon from a detached TUI, and the reason a detached TUI was
//!    not good enough: the signal a terminal sends when it goes away, and that
//!    service managers send on reload, must not disarm the node;
//! 5. a wrong passphrase **fails loudly** rather than starting an unusable daemon;
//! 6. an empty passphrase says what to do about it.
//!
//! **Every participant is the shipped binary.** The profile is made as a person makes one:
//! `vox id`, then a `vox daemon` holding it while `vox room create` (room passphrase on
//! stdin) makes the room, then that daemon is stopped with SIGTERM and reaped. Nothing in
//! this process runs a node.
//!
//! **Mutation.** Remove the daemon's SIGHUP takeover in `run_daemon` (so SIGHUP keeps its
//! default disposition, which terminates) and this goes red at claim 4: the post after the
//! signal is refused with "no node is running".

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "daemon passphrase";
const ROOMPASS: &str = "channel passphrase";

/// A daemon child, killed when the test ends however it ends, with its pipes drained.
struct Daemon(Child, Arc<Mutex<String>>);

impl Daemon {
    /// Whatever the daemon has said so far, for an assertion message.
    #[allow(dead_code)]
    fn said(&self) -> String {
        self.1.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drain a long-lived child's pipes on threads, into a string the test can print.
///
/// **A piped stream nobody reads is a fuse, not a convenience.** The pipe buffer is
/// 64 KiB; when it fills, the child blocks on `write` and stops making progress, which
/// looks exactly like a hang with no output to explain it. This was harmless only while
/// the daemon said nothing — measured at **0 bytes** of stderr over a 40s run, which is
/// precisely the reporting blindness being fixed. A daemon that now reports unreachable
/// peers, refused publishes and stalls produces kilobytes over the same run, and at
/// ~140 B/s a 64 KiB pipe fills in about eight minutes. The bytes that were the hazard
/// become the diagnosis instead.
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

fn vox(data: &std::path::Path, cfg: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    vox_in(data, cfg, args, None)
}

/// `vox`, with `input` piped to its stdin when given (`room create` reads the passphrase
/// there) and the identity passphrase in the environment, never argv (ADR-015).
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
        .expect("spawn vox");
    if let Some(text) = input {
        let mut pipe = child.stdin.take().expect("vox stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
        drop(pipe);
    }
    let out = child.wait_with_output().expect("vox ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Wait for the daemon's socket to answer, rather than guessing at a sleep.
fn until_attached(data: &std::path::Path, cfg: &std::path::Path, why: &str) -> String {
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
    panic!("timed out waiting for {why}; last error: {last}");
}

#[test]
#[ignore = "production Argon2id at setup + runs the real binary as a daemon; CI runs it in release"]
fn a_daemon_serves_agent_sessions_with_no_terminal_and_survives_sighup() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");

    // ---- a profile with an identity and a room, made through the binary, then nothing
    // running ----
    let room = make_profile(&data, &cfg);
    println!("[proof] profile made by `vox id` + `vox room create`: room {room}");

    // Nothing is running: the verbs say so rather than hanging.
    let (ok, _, err) = vox(&data, &cfg, &["room", "list"]);
    assert!(!ok, "with no node running, `room list` must fail");
    assert!(
        err.contains("no node is running"),
        "it must say what is wrong: {err:?}"
    );

    // ---- (5) and (6): the passphrase is checked before anything is served ----
    let out = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::null())
        .output()
        .expect("spawn vox");
    assert!(!out.status.success(), "an empty passphrase must not start");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("passphrase"),
        "it must say what is missing: {err:?}"
    );

    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox daemon");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"the wrong passphrase\n")
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert!(
        !out.status.success(),
        "a wrong passphrase must fail, not start an unusable daemon"
    );
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("passphrase is wrong"),
        "a wrong passphrase must be named as the reason: {said:?}"
    );

    // ---- (1) the real thing, with the passphrase piped in ----
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox daemon");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{IDENTITY}\n{} {ROOMPASS}\n", &room[..12]).as_bytes())
        .unwrap();
    // Closing stdin is what a pipe does; the daemon must not need it held open.
    drop(child.stdin.take());
    let pid = child.id();
    let said = Arc::new(Mutex::new(String::new()));
    drain(child.stdout.take(), &said);
    drain(child.stderr.take(), &said);
    let daemon = Daemon(child, said);

    // ---- (2) another process attaches to it ----
    let listed = until_attached(&data, &cfg, "the daemon to serve its control socket");
    assert!(
        listed.contains(&room[..12]),
        "an attached client must see the daemon's room: {listed:?}"
    );

    // ---- (3) and it can speak through it ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room, "from an agent session"],
    );
    assert!(ok, "posting through the daemon failed: {err}");
    let (ok, read, err) = vox(&data, &cfg, &["room", "read", &room]);
    assert!(ok, "reading through the daemon failed: {err}");
    assert!(
        read.contains("from an agent session"),
        "the post did not reach the log: {read:?}"
    );

    // ---- (4) SIGHUP must neither stop it nor lock it ----
    //
    // The TUI locks on SIGHUP because a terminal going away means the operator
    // walked off. A daemon has no terminal to lose, and a service manager sends
    // SIGHUP to ask for a reload — locking on it would make this unusable.
    // `kill(1)` rather than a libc binding: it is what an operator and a service
    // manager actually do, and it needs no new dependency.
    let signalled = Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(signalled.success(), "could not signal the daemon");
    std::thread::sleep(std::time::Duration::from_millis(500));
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room, "still here after SIGHUP"],
    );
    assert!(
        ok,
        "SIGHUP must not stop or lock a daemon — a locked node refuses this: {err}"
    );
    let (_, read, _) = vox(&data, &cfg, &["room", "read", &room]);
    assert!(
        read.contains("still here after SIGHUP"),
        "the daemon stopped serving after SIGHUP: {read:?}"
    );

    println!(
        "[proof] daemon pid {pid}: attached, posted, read back, survived SIGHUP and posted again"
    );
    drop(daemon);
}

/// Make the profile a person makes: `vox id`, a `vox daemon` holding it while `vox room
/// create` makes the room, then that daemon stopped with SIGTERM and reaped. Returns the
/// room's full id, from its invite link.
fn make_profile(data: &std::path::Path, cfg: &std::path::Path) -> String {
    let (ok, fp, err) = vox(data, cfg, &["id"]);
    assert!(ok, "vox id: {err}");
    assert_eq!(fp.trim().len(), 52, "`vox id` prints a fingerprint: {fp:?}");

    let mut setup = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the setup daemon");
    let mut pipe = setup.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let pid = setup.id();
    let setup = Daemon(setup, Arc::new(Mutex::new(String::new())));
    until_attached(data, cfg, "the setup daemon");
    let (ok, _, err) = vox_in(
        data,
        cfg,
        &["room", "create", "--name", "mission"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let listed = until_attached(data, cfg, "the setup daemon");
    let label = listed
        .split_whitespace()
        .next()
        .expect("the new room in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox(data, cfg, &["room", "invite", &label]);
    assert!(ok, "vox room invite: {err}");
    let room = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .expect("an invite link naming the room")
        .to_owned();

    // Stopped as a service manager stops it, and waited for: the proof proper starts from
    // a profile nothing holds.
    let stopped = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(stopped.success(), "could not stop the setup daemon");
    let mut setup = setup;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if setup.0.try_wait().expect("wait").is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "CANNOT MEASURE: the setup daemon (pid {pid}) did not exit within 30s of SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(setup);
    room
}
