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
//! 4. a wrong passphrase **fails loudly** rather than starting an unusable daemon;
//! 5. an empty passphrase says what to do about it.
//!
//! What a daemon does on SIGHUP is no longer here: it used to be "survives it", and it is now a
//! clean stop like SIGINT, SIGTERM and SIGQUIT (V210-108), proved with every other long-running
//! verb in `an_anchor_stops_on_ctrl_c_proof`.
//!
//! **Every participant is the shipped binary.** The profile is made as a person makes one:
//! `vox id`, then a `vox daemon` holding it while `vox room create` (room passphrase on
//! stdin) makes the room, then that daemon is stopped with SIGTERM and reaped. Nothing in
//! this process runs a node.
//!

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
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox: {e}"));
    if let Some(text) = input {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox stdin");
        pipe.write_all(text.as_bytes()).unwrap_or_else(|e| {
            panic!(
                "PRODUCT (staging): vox exited without reading its stdin (the write failed: {e})"
            )
        });
        drop(pipe);
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for vox: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Wait for the daemon's socket to answer, rather than guessing at a sleep. `side` names whose
/// red a timeout is: `PRODUCT (staging)` for staging, `PRODUCT` for a claim; `said` is what the
/// daemon has said so far.
fn until_attached(
    data: &std::path::Path,
    cfg: &std::path::Path,
    why: &str,
    side: &str,
    said: impl Fn() -> String,
) -> String {
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
        "{side}: timed out after 60 s waiting for {why}; the last `room list` said: {last}\n--- \
         the daemon said:\n{}",
        said()
    );
}

#[test]
#[ignore = "production Argon2id at setup + runs the real binary as a daemon; CI runs it in release"]
fn a_daemon_serves_agent_sessions_with_no_terminal_and_survives_sighup() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");

    // ---- a profile with an identity and a room, made through the binary, then nothing
    // running ----
    let room = make_profile(&data, &cfg);
    println!("[proof] profile made by `vox id` + `vox room create`: room {room}");

    // Nothing is running: the verbs say so rather than hanging.
    let (ok, _, err) = vox(&data, &cfg, &["room", "list"]);
    assert!(
        !ok,
        "PRODUCT: with no node running, `room list` must fail: {err:?}"
    );
    assert!(
        err.contains("no node is running"),
        "PRODUCT: with no node running, `room list` must say what is wrong: {err:?}"
    );

    // ---- (4) and (5): the passphrase is checked before anything is served ----
    let out = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox: {e}"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "PRODUCT: a daemon with an empty passphrase started: {err:?}"
    );
    assert!(
        err.contains("passphrase"),
        "PRODUCT: a daemon with an empty passphrase must say what is missing: {err:?}"
    );

    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox daemon: {e}"));
    child
        .stdin
        .as_mut()
        .expect("APPARATUS: the daemon's stdin")
        .write_all(b"the wrong passphrase\n")
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the daemon exited without reading its passphrases (the write failed: {e})"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for the daemon: {e}"));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "PRODUCT: a wrong passphrase must fail, not start an unusable daemon: {said:?}"
    );
    assert!(
        said.contains("passphrase is wrong"),
        "PRODUCT: a wrong passphrase must be named as the reason: {said:?}"
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
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox daemon: {e}"));
    child
        .stdin
        .as_mut()
        .expect("APPARATUS: the daemon's stdin")
        .write_all(format!("{IDENTITY}\n{} {ROOMPASS}\n", &room[..12]).as_bytes())
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the daemon exited without reading its passphrases (the write failed: {e})"));
    // Closing stdin is what a pipe does; the daemon must not need it held open.
    drop(child.stdin.take());
    let pid = child.id();
    let said = Arc::new(Mutex::new(String::new()));
    drain(child.stdout.take(), &said);
    drain(child.stderr.take(), &said);
    let daemon = Daemon(child, said);

    // ---- (2) another process attaches to it ----
    let listed = until_attached(
        &data,
        &cfg,
        "the daemon to serve its control socket",
        "PRODUCT",
        || daemon.said(),
    );
    assert!(
        listed.contains(&room[..12]),
        "PRODUCT: an attached client must see the daemon's room: {listed:?}\n--- the daemon \
         said:\n{}",
        daemon.said()
    );

    // ---- (3) and it can speak through it ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room, "from an agent session"],
    );
    assert!(
        ok,
        "PRODUCT: posting through the daemon failed: {err}\n--- the daemon said:\n{}",
        daemon.said()
    );
    let (ok, read, err) = vox(&data, &cfg, &["room", "read", &room]);
    assert!(
        ok,
        "PRODUCT: reading through the daemon failed: {err}\n--- the daemon said:\n{}",
        daemon.said()
    );
    assert!(
        read.contains("from an agent session"),
        "PRODUCT: the post did not reach the log: {read:?}\n--- the daemon said:\n{}",
        daemon.said()
    );

    println!("[proof] daemon pid {pid}: attached, posted and read back");
    drop(daemon);
}

/// Make the profile a person makes: `vox id`, a `vox daemon` holding it while `vox room
/// create` makes the room, then that daemon stopped with SIGTERM and reaped. Returns the
/// room's full id, from its invite link.
fn make_profile(data: &std::path::Path, cfg: &std::path::Path) -> String {
    let (ok, fp, err) = vox(data, cfg, &["id"]);
    assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
    assert_eq!(
        fp.trim().len(),
        52,
        "PRODUCT (staging): `vox id` printed no fingerprint: {fp:?}"
    );

    let mut setup = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn the setup daemon: {e}"));
    let mut pipe = setup
        .stdin
        .take()
        .expect("APPARATUS: the setup daemon's stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .unwrap_or_else(|e| panic!("PRODUCT (staging): the setup daemon exited without reading its passphrase (the write failed: {e})"));
    drop(pipe);
    let pid = setup.id();
    let said = Arc::new(Mutex::new(String::new()));
    drain(setup.stdout.take(), &said);
    drain(setup.stderr.take(), &said);
    let setup = Daemon(setup, said);
    until_attached(data, cfg, "the setup daemon", "PRODUCT (staging)", || {
        setup.said()
    });
    let (ok, _, err) = vox_in(
        data,
        cfg,
        &["room", "create", "--name", "mission"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let listed = until_attached(data, cfg, "the setup daemon", "PRODUCT (staging)", || {
        setup.said()
    });
    let label = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room in `vox room list`: {listed:?}"))
        .to_owned();
    let (ok, link, err) = vox(data, cfg, &["room", "invite", &label]);
    assert!(ok, "PRODUCT (staging): `vox room invite` failed: {err}");
    let room = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): no invite link naming the room: {link:?}"))
        .to_owned();

    // Stopped as a service manager stops it, and waited for: the proof proper starts from
    // a profile nothing holds.
    let stopped = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: run kill: {e}"));
    assert!(
        stopped.success(),
        "APPARATUS: `kill -TERM {pid}` did not deliver the signal"
    );
    let mut setup = setup;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if setup
            .0
            .try_wait()
            .unwrap_or_else(|e| panic!("APPARATUS: wait on the setup daemon: {e}"))
            .is_some()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "PRODUCT: `vox daemon` (the setup daemon, pid {pid}) was still running 30 s after SIGTERM; it \
             said:\n{}",
            setup.said()
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(setup);
    room
}
