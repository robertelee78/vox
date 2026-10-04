//! #339, #406 — **a forward into a room this node has not synced since it joined is refused, with
//! that reason, and never guessed**. Driven through the shipped `vox` binary, as a person types it:
//!
//! ```text
//! vox node create host; vox serve web=<port> --node host        (data root H)
//! vox node create guest; vox connect <address> --node guest     (data root G: joins, lets go)
//! (the host's daemon is stopped by SIGSTOP: nothing in the room can sync with the guest now)
//! vox forward nosuch.<host>.<room>.vox --node guest             (the patience shortened)
//! ```
//!
//! What a room shares is the room's log's to say (V030-25), and a room this node joined but has not
//! synced may not hold the statement yet. So the forward waits, for at most its patience, and then
//! is refused saying the room has not synced since this node joined it. It must never carry the
//! name as a TCP service on a guess: a forward of the wrong protocol fails later, where nothing
//! says why.
//!
//! The patience is shortened with the test-only `VOX_TEST_SHARE_PATIENCE_MS` (the `test-knobs`
//! feature, V210-105). The staging needs the guest's room unsynced when the forward asks: if the
//! guest's first sync with the host ran before the host was stopped, the forward is refused as
//! "shares no service", and that is `CANNOT MEASURE`, not a pass.
//!
//! **Mutation that must turn it red:** `share_refusal` answering `None` for a room not yet synced,
//! so the forward goes ahead with the name as given. With the host stopped, the guess then fails to
//! reach it, and the proof is red as `PRODUCT: a forward into a room not yet synced must be refused
//! saying so`; were the host up, it would be red as `PRODUCT: … was forwarded`.

#![cfg(unix)]

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// The forward's patience for the room's first sync, shortened.
const PATIENCE_MS: u64 = 3_000;
/// What a refused forward into an unsynced room says.
const UNSYNCED: &str = "has not synced with its members since this node joined it";

/// A child `vox`, killed by its own PID when dropped.
struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The daemon of a data root, resumed and stopped by its pid when dropped (never by a pattern).
struct Reaper(PathBuf);

impl Drop for Reaper {
    fn drop(&mut self) {
        let Some(pid) = daemon_pid(&self.0) else {
            return;
        };
        let _ = signal("CONT", pid);
        let _ = signal("TERM", pid);
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && signal("0", pid) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = signal("KILL", pid);
    }
}

fn signal(sig: &str, pid: u32) -> bool {
    Command::new("kill")
        .args([&format!("-{sig}"), &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The pid the daemon of `dir` writes in its lock.
fn daemon_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join(".daemon").join("lock"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn vox(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_NODE")
        .env_remove("VOX_PROFILE")
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .env_remove("VOX_LISTEN")
        .stdin(Stdio::null());
    cmd
}

/// Run to the end: success, stdout, stderr.
fn run(dir: &Path, args: &[&str], env: &[(&str, String)]) -> (bool, String, String) {
    let mut cmd = vox(dir, args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("APPARATUS: run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn ok(dir: &Path, side: &str, args: &[&str]) -> String {
    let (ok, out, err) = run(dir, args, &[]);
    assert!(ok, "{side} `vox {}` failed:\n{out}{err}", args.join(" "));
    out
}

/// A data root and the passphrase file of its one node.
fn root(base: &Path, name: &str) -> (PathBuf, PathBuf) {
    let dir = base.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: harness file I/O");
    let pass = dir.join("node.pass");
    std::fs::write(&pass, format!("{name}'s identity passphrase\n"))
        .expect("APPARATUS: harness file I/O");
    (dir, pass)
}

#[test]
#[ignore = "real vox daemons and production Argon2id; run on demand in release"]
fn a_forward_into_a_room_not_yet_synced_is_refused_and_never_guessed() {
    test_knobs::require(&["VOX_TEST_SHARE_PATIENCE_MS"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (h, h_pass) = root(tmp.path(), "host");
    let (g, g_pass) = root(tmp.path(), "guest");
    let (hp, gp) = (
        h_pass.to_str().expect("APPARATUS: path"),
        g_pass.to_str().expect("APPARATUS: path"),
    );
    ok(
        &h,
        "PRODUCT (staging):",
        &["node", "create", "host", "--passphrase-file", hp],
    );
    ok(
        &g,
        "PRODUCT (staging):",
        &["node", "create", "guest", "--passphrase-file", gp],
    );
    let _h_daemon = Reaper(h.clone());
    let _g_daemon = Reaper(g.clone());

    // ---- the host serves one service --------------------------------------------------------
    let web = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: a local service");
    let port = web.local_addr().expect("APPARATUS: its port").port();
    let spec = format!("web={port}");
    let mut serve = vox(
        &h,
        &[
            "serve",
            &spec,
            "--node",
            "host",
            "--listen",
            "127.0.0.1:0",
            "--identity-passphrase-file",
            hp,
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .expect("APPARATUS: spawn vox serve");
    let out = serve.stdout.take().expect("APPARATUS: serve's stdout");
    let _serve = Kid(serve);
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    let field = |label: &str| {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let l = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("PRODUCT (staging): vox serve printed no {label}"));
            if let Some(v) = l.strip_prefix(label) {
                return v.trim().to_owned();
            }
        }
    };
    let (room, address, passphrase) = (field("room"), field("address"), field("passphrase"));
    let host_fp = ok(&h, "PRODUCT (staging):", &["id", "--node", "host"])
        .trim()
        .to_owned();

    // ---- the guest joins, and lets its node go ----------------------------------------------
    let room_pass = g.join("room.pass");
    std::fs::write(&room_pass, format!("{passphrase}\n")).expect("APPARATUS: harness file I/O");
    ok(
        &g,
        "PRODUCT (staging):",
        &[
            "connect",
            &address,
            "--node",
            "guest",
            "--passphrase-file",
            room_pass.to_str().expect("APPARATUS: path"),
            "--identity-passphrase-file",
            gp,
            "--listen",
            "127.0.0.1:0",
        ],
    );

    // ---- nothing in the room can sync with the guest now ------------------------------------
    let host_daemon = daemon_pid(&h).expect("PRODUCT (staging): no daemon holds the host's lock");
    assert!(
        signal("STOP", host_daemon),
        "APPARATUS: could not SIGSTOP the host's daemon"
    );

    // ---- a forward to a name the guest's log does not carry ----------------------------------
    let name = format!("nosuch.{host_fp}.{room}.vox");
    let started = Instant::now();
    let (forwarded, out, err) = run(
        &g,
        &[
            "forward",
            &name,
            "127.0.0.1:0",
            "--node",
            "guest",
            "--identity-passphrase-file",
            gp,
            "--listen",
            "127.0.0.1:0",
        ],
        &[("VOX_TEST_SHARE_PATIENCE_MS", PATIENCE_MS.to_string())],
    );
    let took = started.elapsed();
    let _ = signal("CONT", host_daemon);
    eprintln!(
        "[proof] the forward ended after {took:?}, ok={forwarded}\n--- stdout:\n{out}\n--- stderr:\n{err}"
    );
    assert!(
        !err.contains("shares no service called"),
        "CANNOT MEASURE: the guest's room had synced before the host was stopped, so the forward \
         was refused as an absent share and never met an unsynced room:\n{err}"
    );
    assert!(
        !forwarded && !out.contains("vox: forwarding"),
        "PRODUCT: a forward into a room not synced since this node joined it was forwarded, on a \
         guess at what the name is:\n{out}{err}"
    );
    assert!(
        err.contains(UNSYNCED),
        "PRODUCT: a forward into a room not yet synced must be refused saying so ({UNSYNCED:?}):\n{err}"
    );
    assert!(
        took >= Duration::from_millis(PATIENCE_MS),
        "PRODUCT: the refusal came after {took:?}, before the {PATIENCE_MS} ms patience: it did not \
         wait for the room's first sync"
    );
}
