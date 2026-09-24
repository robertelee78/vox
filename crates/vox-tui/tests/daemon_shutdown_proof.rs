//! A `vox daemon` **stops when it is told to**, promptly, even when the peers it was talking
//! to have vanished — driven through the shipped binary.
//!
//! Found while auditing failure reasons (PRD-001 R36): a daemon that had joined a room through
//! an anchor printed `vox daemon: shutting down` on SIGTERM and then sat, at 0% CPU, for 59.6 s
//! when the anchor and the room's host had gone away just before. Measured with the node's own
//! stall report: it was `busy 60011ms — passing on a record that landed on our board`, i.e.
//! publishing to two boards nobody was reading, each waiting out a frame read, and `Shutdown`
//! queued behind it. A service manager's SIGTERM, a laptop lid, a `docker stop` — all of them
//! would have waited a minute, and most would have escalated to SIGKILL.
//!
//! What it asserts: with the anchor and the host killed without warning, SIGTERM stops the
//! daemon within [`STOP_WITHIN`], it says why it did not stop cleanly, and no process is left.
//!
//! Mutation: the unbounded `node.apply(Shutdown)` this replaced turns it red at ~60 s.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
/// The daemon waits 5 s for its node before leaving anyway; this leaves room for the rest.
const STOP_WITHIN: Duration = Duration::from_secs(10);

struct Proc {
    name: &'static str,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: impl Read + Send + 'static) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    lines
}

impl Proc {
    fn spawn(name: &'static str, dir: &std::path::Path, args: &[&str], stdin: &str) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(stdin.as_bytes()).expect("write stdin");
        drop(pipe);
        let out = collect(child.stdout.take().expect("stdout"));
        let err = collect(child.stderr.take().expect("stderr"));
        Self {
            name,
            child,
            out,
            err,
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.out.lock().unwrap().clone()
    }

    fn expect_out(&self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(l) = self.stdout().into_iter().find(|l| pred(l)) {
                return l;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: never printed {what}; stdout {:#?}\nstderr:\n{}",
            self.name,
            self.stdout(),
            self.err.lock().unwrap().join("\n")
        );
    }
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin.as_bytes()).expect("write");
    drop(pipe);
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
#[ignore = "three real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn a_daemon_stops_on_sigterm_even_when_its_peers_have_vanished() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir, joiner_dir) = (dir("anchor"), dir("host"), dir("joiner"));

    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &["node", "--listen", "127.0.0.1:0"],
        "",
    );
    let spec = anchor
        .expect_out("an anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    for d in [&host_dir, &joiner_dir] {
        let (ok, said) = vox(d, &["id"], "");
        assert!(ok, "vox id: {said}");
    }
    let mut host = Proc::spawn(
        "host",
        &host_dir,
        &["serve", "9", "--anchor", &spec, "--listen", "127.0.0.1:0"],
        "",
    );
    let field = |label: &str| {
        host.expect_out(label, |l| l.starts_with(label))
            .strip_prefix(label)
            .unwrap()
            .trim()
            .to_owned()
    };
    let (address, passphrase) = (field("address"), field("passphrase"));
    let mut daemon = Proc::spawn(
        "joiner-daemon",
        &joiner_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    daemon.expect_out("its control socket", |l| l.contains("control socket"));
    let (ok, said) = vox(
        &joiner_dir,
        &["room", "join", &address, "--name", "svc"],
        &format!("{passphrase}\n"),
    );
    assert!(ok, "CANNOT MEASURE: the join failed: {said}");

    // The peers vanish without a word — no close frames, as when a machine loses power.
    let _ = anchor.child.kill();
    let _ = anchor.child.wait();
    let _ = host.child.kill();
    let _ = host.child.wait();
    std::thread::sleep(Duration::from_secs(1));

    let pid = daemon.child.id();
    let started = Instant::now();
    let sent = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(sent.success(), "SIGTERM could not be sent");
    let deadline = started + Duration::from_secs(90);
    while alive(pid) && daemon.child.try_wait().ok().flatten().is_none() {
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let exited = daemon.child.try_wait().ok().flatten();
    let said = daemon.err.lock().unwrap().join("\n");
    eprintln!("[shutdown] SIGTERM -> exit in {took:?}; exit={exited:?}");
    assert!(
        exited.is_some() && took < STOP_WITHIN,
        "a daemon must stop within {STOP_WITHIN:?} of SIGTERM; it took {took:?} (exited: \
         {exited:?}). stdout {:#?}\nstderr:\n{said}",
        daemon.stdout()
    );
    assert!(
        daemon.stdout().iter().any(|l| l.contains("shutting down")),
        "it must say it is shutting down"
    );

    // Nothing left behind: every process this test started is gone.
    let pids = [anchor.child.id(), host.child.id(), pid];
    let remaining = pids.iter().filter(|p| alive(**p)).count();
    assert_eq!(remaining, 0, "processes still running: {pids:?}");
    eprintln!("[shutdown] {remaining} processes remain");
}
