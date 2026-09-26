//! A join the host **gave up waiting on** is not reported as a wrong passphrase, nor as nobody
//! being reachable — driven through the shipped binary (#160).
//!
//! Found reproducing #160 ("a correct passphrase is refused right after a wrong one") on the
//! v0.2.8-era binary it was seen on (4999eb0): 2 of 100 correct-passphrase joins failed with
//! "a member answered and refused the join / usually the room passphrase is wrong". Both hosts
//! logged `peer sent no frame in time`, and both joiners logged `busy 34–39 s — joining a room`.
//! The host had stopped waiting for a joiner too busy to answer, sent the one coarse refusal every
//! failure after the work gate gets, and the joiner told its person their correct passphrase was
//! probably wrong. On main the join no longer blocks the joiner's actor, but the same host timeout
//! still reached the person as a falsehood: "nobody who can answer for this room could be reached
//! ... every member the board knows is offline", about a host that had answered and was online.
//!
//! What it does: the joiner daemon is held to 0.5% of the CPU (SIGSTOP/SIGCONT) from just after
//! `vox room join` starts until the host logs that it gave up waiting; then it runs freely and
//! `room join` reports. What it asserts: the host did give up (the step the claim depends on); the
//! join failed; and what the person is told neither blames the passphrase nor claims nobody could
//! be reached, and says the exchange was cut short.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
/// How long the joiner is held to 0.5% of the CPU: long enough that its proof-of-work cannot
/// finish inside the host's patience for it (120 s at the base difficulty; a solve is at least
/// ~0.9 s of CPU, i.e. 180 s at 0.5%), bounded so a host that never gives up fails the gate.
const HELD_FOR_AT_MOST: Duration = Duration::from_secs(400);

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

#[test]
#[ignore = "three real vox processes, production Argon2id and a real PoW held past the host's patience; CI runs it in release"]
fn a_join_the_host_stopped_waiting_on_is_not_a_verdict_on_the_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir, joiner_dir) = (dir("anchor"), dir("host"), dir("joiner"));

    let anchor = Proc::spawn(
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
    let host = Proc::spawn(
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
    let daemon = Proc::spawn(
        "joiner-daemon",
        &joiner_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    daemon.expect_out("its control socket", |l| l.contains("control socket"));
    let pid = daemon.child.id().to_string();
    let signal = |sig: &str| {
        let _ = Command::new("kill").args([sig, &pid]).status();
    };

    // The correct passphrase, on its own thread: `room join` waits for the whole exchange.
    let join = {
        let (joiner_dir, address, passphrase) = (joiner_dir.clone(), address.clone(), passphrase);
        std::thread::spawn(move || {
            vox(
                &joiner_dir,
                &["room", "join", &address, "--name", "svc"],
                &format!("{passphrase}\n"),
            )
        })
    };

    // Held to 0.5% of the CPU until the host says it gave up.
    std::thread::sleep(Duration::from_millis(300));
    let gave_up = |l: &String| l.contains("peer sent no frame in time");
    let held = Instant::now();
    while !host.err.lock().unwrap().iter().any(gave_up) && held.elapsed() < HELD_FOR_AT_MOST {
        signal("-STOP");
        std::thread::sleep(Duration::from_millis(4975));
        signal("-CONT");
        std::thread::sleep(Duration::from_millis(25));
    }
    signal("-CONT");
    let host_said = host.err.lock().unwrap().join("\n");
    assert!(
        host.err.lock().unwrap().iter().any(gave_up),
        "CANNOT MEASURE: the host never gave up waiting on the held joiner within {}s; host stderr:\n{host_said}",
        HELD_FOR_AT_MOST.as_secs()
    );
    eprintln!(
        "[#160] the host gave up after the joiner was held {:.0}s: {}",
        held.elapsed().as_secs_f64(),
        host_said
            .lines()
            .find(|l| l.contains("peer sent no frame in time"))
            .unwrap_or_default()
    );

    let (ok, said) = join.join().expect("the join thread");
    eprintln!("[#160] `vox room join` with the correct passphrase said:\n{said}");
    assert!(
        !ok,
        "CANNOT MEASURE: the join succeeded although the host gave up on it:\n{said}"
    );
    assert!(
        !said.contains("passphrase is wrong"),
        "a join the host stopped waiting on was blamed on the passphrase:\n{said}"
    );
    assert!(
        !said.contains("could be reached") && !said.contains("offline"),
        "a join whose host answered was reported as nobody reachable:\n{said}"
    );
    assert!(
        said.contains("cut short") && said.contains("not a verdict"),
        "the person is to be told the exchange was cut short, and that it is no verdict on the \
         passphrase:\n{said}"
    );
}
