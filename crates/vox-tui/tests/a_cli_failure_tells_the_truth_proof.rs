//! V210-83 (#274) — **a failure names its real cause, and its exit code is the truth**, through
//! the shipped binary.
//!
//! Each claim below was a defect the v0.2.10 sweep found by reading the code; each is staged here
//! the way a person meets it.
//!
//! 1. **A join refused in the exchange says what the member said.** `vox room join` with a wrong
//!    room passphrase is refused by the member during the exchange, and the join's reasons were
//!    empty for exactly that failure (and for a failed announce): the reply carried no `said:`
//!    line, so a refusal could not be told from any other. It must now carry one naming the
//!    exchange.
//! 2. **`vox status` and an attaching verb against a suspended node end, and say so.** A node
//!    frozen with SIGSTOP still accepts on its control socket, and both waited for ever on its
//!    greeting. Each must now exit non-zero within 30 s (the product's patience is 10 s; the
//!    bound here is hard-coded) saying the node did not answer. The control: after SIGCONT the
//!    same `vox status` answers, so the node, not the proof, was what went quiet.
//! 3. **`vox room tail` exits non-zero when its node dies.** It exited 0, so a supervisor that
//!    restarts a failed tail never restarted it. The daemon is killed with SIGKILL by its PID;
//!    the tail must exit non-zero within 30 s, saying the node stopped.
//! 4. **A service removal that fails names its cause**, not a hard-coded "was not offered". The
//!    one cause a person can stage is a tag that is not offered, and its wording is asserted
//!    here; the others (a store that failed, a node with no identity) cannot be staged through
//!    any command and rest on code review, as does the governance `DenyReason` order.
//! 5. **A request whose node is suspended mid-request ends, and says so.** Only the greeting was
//!    bounded, so a node suspended after it greeted left the request waiting for ever. A second
//!    joiner's `vox room join` is sent while the host is suspended, so the join is still being
//!    worked on a second later; then the joiner's own daemon is suspended. The join must exit
//!    non-zero within 45 s (the product checks every 10 s and gives a greeting 10 s; the bound
//!    here is hard-coded) saying the node stopped answering while the request waited. If it
//!    says instead that the node never greeted, the suspension came before the request was sent:
//!    CANNOT MEASURE. The control: after SIGCONT the same daemon answers `vox status`. A node
//!    whose actor is stuck while it still greets cannot be staged through any command; that
//!    half (the ping each check sends through the actor) rests on code review.
//! 6. **A holder whose control socket cannot be bound runs on, and says why** (separate test,
//!    `a_holder_runs_without_its_control_socket`). A profile path too long for a socket puts the
//!    socket in `$TMPDIR/vox-<uid>`, and there a plain file stands where that directory should be
//!    — what another local user can plant in `/tmp`. `vox serve` must keep serving and `vox
//!    connect` must join (exit 0), each warning that the control socket is unavailable, naming
//!    the path and the cause; and the file must be left as it was, never used.
//!
//! **Staging.** An anchor (`vox node`), a host (`vox serve` of a loopback echo service), and a
//! joiner's `vox daemon`. Every participant is the shipped binary; every process is killed by its
//! own PID, and signals go to PIDs, never to patterns.
//!
//! **Mutations that must turn it red**, one per claim: (1) drop the exchange failure's
//! `why.push` in the actor's join walk — no `said:` line; (2) remove the `ANSWER_WITHIN` bound
//! from `IpcClient::open` and `status::request` — `vox status` is still running at 30 s;
//! (3) `Ok(None) => return Ok(())` back in `room_cli::tail` — the tail exits 0; (5)
//! `IpcClient::request` without `while_answering` — the join is still running at 45 s; (6)
//! `serve_control_socket(..)?`, a bind failure fatal again — `vox serve` exits 1 at once.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";

/// A long-running `vox`, killed by its own PID however the test ends.
struct Proc {
    name: &'static str,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        // A frozen process is continued first, so the kill is not left pending on it.
        signal("CONT", self.child.id());
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

fn command(dir: &std::path::Path, args: &[&str], envs: &[(&str, &str)]) -> Command {
    let mut c = Command::new(VOX);
    c.args(args)
        .envs(envs.iter().copied())
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

impl Proc {
    fn spawn(name: &'static str, dir: &std::path::Path, args: &[&str], stdin: &str) -> Self {
        Self::spawn_env(name, dir, args, stdin, &[])
    }

    fn spawn_env(
        name: &'static str,
        dir: &std::path::Path,
        args: &[&str],
        stdin: &str,
        envs: &[(&str, &str)],
    ) -> Self {
        let mut child = command(dir, args, envs)
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

    fn stderr(&self) -> String {
        self.err.lock().unwrap().join("\n")
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
            "CANNOT MEASURE: {} never printed {what}; stdout {:#?}\nstderr:\n{}",
            self.name,
            self.stdout(),
            self.stderr()
        );
    }

    /// Wait up to `within` for the process to exit; `None` if it is still running then.
    fn exit_within(&mut self, within: Duration) -> Option<(ExitStatus, Duration)> {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if let Some(s) = self.child.try_wait().expect("wait") {
                return Some((s, t0.elapsed()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

fn signal(sig: &str, pid: u32) -> bool {
    Command::new("kill")
        .args([&format!("-{sig}"), &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// One `vox` verb run to completion within `within`. Returns `None` if it had not exited by
/// then (it is killed by its PID), else (success, everything it said, how long it took).
fn vox(
    dir: &std::path::Path,
    args: &[&str],
    stdin: &str,
    within: Duration,
) -> Option<(bool, String, Duration)> {
    vox_env(dir, args, stdin, within, &[])
}

/// [`vox`], with more environment.
fn vox_env(
    dir: &std::path::Path,
    args: &[&str],
    stdin: &str,
    within: Duration,
    envs: &[(&str, &str)],
) -> Option<(bool, String, Duration)> {
    let mut p = Proc::spawn_env("verb", dir, args, stdin, envs);
    let (status, took) = p.exit_within(within)?;
    // Let the reader threads take the last lines.
    std::thread::sleep(Duration::from_millis(100));
    Some((
        status.success(),
        format!("{}\n{}", p.stdout().join("\n"), p.stderr()),
        took,
    ))
}

fn must(what: &str, r: Option<(bool, String, Duration)>) -> (bool, String, Duration) {
    r.unwrap_or_else(|| panic!("CANNOT MEASURE: `{what}` did not finish within its bound"))
}

#[test]
#[ignore = "three real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn a_cli_failure_tells_the_truth() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir, joiner_dir) = (dir("anchor"), dir("host"), dir("joiner"));
    let quick = Duration::from_secs(90);
    let bound = Duration::from_secs(30);
    let mut claims = 0usize;

    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_port = service.local_addr().unwrap().port().to_string();

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
        let (ok, said, _) = must("vox id", vox(d, &["id"], "", quick));
        assert!(ok, "CANNOT MEASURE: vox id: {said}");
    }
    let host = Proc::spawn(
        "host",
        &host_dir,
        &[
            "serve",
            &service_port,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
    );
    let field = |label: &str| {
        host.expect_out(label, |l| l.starts_with(label))
            .strip_prefix(label)
            .unwrap()
            .trim()
            .to_owned()
    };
    let (room, address, passphrase) = (field("room"), field("address"), field("passphrase"));
    let mut joiner = Proc::spawn(
        "joiner-daemon",
        &joiner_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    joiner.expect_out("its control socket", |l| l.contains("control socket"));

    // ---- (1) a join refused in the exchange says what was said ----
    let (ok, said, took) = must(
        "vox room join (wrong passphrase)",
        vox(
            &joiner_dir,
            &["room", "join", &address, "--name", "svc"],
            "not the passphrase\n",
            quick,
        ),
    );
    eprintln!(
        "[join, wrong passphrase] in {:.1}s: {}",
        took.as_secs_f64(),
        said.trim().replace('\n', " / ")
    );
    assert!(!ok, "a wrong passphrase must not join: {said}");
    assert!(
        said.contains("refused the join"),
        "CANNOT MEASURE (1): the join was not refused by a member, so the exchange was not \
         where it failed: {said}"
    );
    let said_line = said.lines().find(|l| l.trim_start().starts_with("said:"));
    assert!(
        said_line.is_some_and(|l| l.contains("exchange")),
        "(1) a join refused in the exchange must say what the member said (a `said:` line \
         naming the exchange); it said:\n{said}"
    );
    assert!(
        !said.contains("Failed("),
        "(1) an enum token reached the person:\n{said}"
    );
    claims += 1;

    let (ok, said, took) = must(
        "vox room join",
        vox(
            &joiner_dir,
            &["room", "join", &address, "--name", "svc"],
            &format!("{passphrase}\n"),
            quick,
        ),
    );
    eprintln!(
        "[join, right passphrase] ok={ok} in {:.1}s",
        took.as_secs_f64()
    );
    assert!(ok, "CANNOT MEASURE: the right passphrase must join: {said}");

    // ---- (4) removing a service that is not offered says so, and nothing else ----
    let (ok, said, _) = must(
        "vox service remove",
        vox(
            &joiner_dir,
            &["service", "remove", &room, "no-such-service"],
            "",
            quick,
        ),
    );
    eprintln!(
        "[service remove, not offered] {}",
        said.trim().replace('\n', " / ")
    );
    assert!(
        !ok,
        "(4) removing a service never offered must fail: {said}"
    );
    assert!(
        said.contains("not offered in this room") && !said.contains("Failed("),
        "(4) the failure must name its cause: {said}"
    );
    claims += 1;

    // ---- (5) a node suspended mid-request: the request ends, and says so ----
    let late_dir = dir("late");
    let (ok, said, _) = must("vox id (late)", vox(&late_dir, &["id"], "", quick));
    assert!(ok, "CANNOT MEASURE: vox id (late): {said}");
    let late = Proc::spawn(
        "late-daemon",
        &late_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    late.expect_out("its control socket", |l| l.contains("control socket"));
    let (host_pid, late_pid) = (host.child.id(), late.child.id());
    // The host is suspended, so the join waits on it and is still being worked on a second
    // after it is asked.
    assert!(
        signal("STOP", host_pid),
        "CANNOT MEASURE (5): could not SIGSTOP the host"
    );
    let mut join = Proc::spawn(
        "late join",
        &late_dir,
        &["room", "join", &address, "--name", "svc"],
        &format!("{passphrase}\n"),
    );
    std::thread::sleep(Duration::from_secs(1));
    if let Some(s) = join.child.try_wait().expect("wait") {
        signal("CONT", host_pid);
        std::thread::sleep(Duration::from_millis(100));
        panic!(
            "CANNOT MEASURE (5): the join ended ({s}) before its node could be suspended \
             mid-request: {}\n{}",
            join.stdout().join("\n"),
            join.stderr()
        );
    }
    assert!(
        signal("STOP", late_pid),
        "CANNOT MEASURE (5): could not SIGSTOP the late joiner's daemon"
    );
    let mid_bound = Duration::from_secs(45);
    let ended = join.exit_within(mid_bound);
    assert!(
        signal("CONT", late_pid) && signal("CONT", host_pid),
        "CANNOT MEASURE (5): could not SIGCONT the daemons"
    );
    let Some((status, took)) = ended else {
        panic!(
            "(5) `vox room join` against a node suspended mid-request was still running after \
             {mid_bound:?}"
        );
    };
    std::thread::sleep(Duration::from_millis(100));
    let said = format!("{}\n{}", join.stdout().join("\n"), join.stderr());
    eprintln!(
        "[room join, node suspended mid-request] exit {:?} in {:.1}s: {}",
        status.code(),
        took.as_secs_f64(),
        said.trim().replace('\n', " / ")
    );
    assert!(
        !said.contains("did not answer within"),
        "CANNOT MEASURE (5): the node was suspended before it greeted, so the request was never \
         sent: {said}"
    );
    assert!(
        !status.success(),
        "(5) a join whose node was suspended mid-request must fail: {said}"
    );
    assert!(
        said.contains("stopped answering while this request waited"),
        "(5) the join must say its node stopped answering while it waited: {said}"
    );
    let (ok, said, took) = must(
        "vox status (late, resumed)",
        vox(&late_dir, &["status"], "", bound),
    );
    eprintln!(
        "[vox status, late node resumed] ok={ok} in {:.1}s",
        took.as_secs_f64()
    );
    assert!(
        ok,
        "CANNOT MEASURE (5): the resumed node did not answer `vox status` either, so the \
         silence was not the suspension's: {said}"
    );
    drop(late);
    claims += 1;

    // ---- the tail, attached and delivering before anything is done to its node ----
    let tail = Proc::spawn("tail", &joiner_dir, &["room", "tail", &room], "");
    let mut tail = tail;
    let t0 = Instant::now();
    let mut n = 0u32;
    let delivering = loop {
        n += 1;
        let text = format!("tail-probe-{n}");
        let _ = vox(&joiner_dir, &["room", "post", &room, &text], "", quick);
        std::thread::sleep(Duration::from_millis(500));
        if tail.stdout().iter().any(|l| l.contains("tail-probe-")) {
            break true;
        }
        if t0.elapsed() > Duration::from_secs(60) {
            break false;
        }
    };
    assert!(
        delivering,
        "CANNOT MEASURE (3): the tail printed none of {n} posts in 60 s; stderr:\n{}",
        tail.stderr()
    );

    // ---- (2) a suspended node: `vox status` and an attach end, and say so ----
    let pid = joiner.child.id();
    assert!(
        signal("STOP", pid),
        "CANNOT MEASURE (2): could not SIGSTOP the daemon"
    );
    let status = vox(&joiner_dir, &["status"], "", bound);
    let list = vox(&joiner_dir, &["room", "list"], "", bound);
    assert!(
        signal("CONT", pid),
        "CANNOT MEASURE (2): could not SIGCONT the daemon"
    );
    for (verb, r) in [("vox status", status), ("vox room list", list)] {
        let Some((ok, said, took)) = r else {
            panic!("(2) `{verb}` against a suspended node was still running after {bound:?}");
        };
        eprintln!(
            "[{verb}, node suspended] ok={ok} in {:.1}s: {}",
            took.as_secs_f64(),
            said.trim().replace('\n', " / ")
        );
        assert!(
            !ok,
            "(2) `{verb}` against a suspended node must fail: {said}"
        );
        assert!(
            said.contains("did not answer"),
            "(2) `{verb}` must say the node did not answer: {said}"
        );
    }
    let (ok, said, took) = must(
        "vox status (resumed)",
        vox(&joiner_dir, &["status"], "", bound),
    );
    eprintln!(
        "[vox status, node resumed] ok={ok} in {:.1}s",
        took.as_secs_f64()
    );
    assert!(
        ok,
        "CANNOT MEASURE (2): the resumed node did not answer `vox status` either, so the \
         silence was not the suspension's: {said}"
    );
    claims += 1;

    // ---- (3) the node dies under the tail ----
    assert!(
        signal("KILL", pid),
        "CANNOT MEASURE (3): could not SIGKILL the daemon"
    );
    let _ = joiner.child.wait();
    let Some((status, took)) = tail.exit_within(bound) else {
        panic!("(3) the tail was still running {bound:?} after its node was killed");
    };
    std::thread::sleep(Duration::from_millis(100));
    let err = tail.stderr();
    eprintln!(
        "[room tail, node killed] exit {:?} in {:.1}s: {}",
        status.code(),
        took.as_secs_f64(),
        err.trim().replace('\n', " / ")
    );
    assert!(
        !status.success(),
        "(3) the tail exited 0 when its node died; a supervisor would not restart it: {err}"
    );
    assert!(
        err.contains("the node stopped"),
        "(3) the tail must say its node stopped: {err}"
    );
    claims += 1;

    eprintln!("[proof] {claims} claims held");
    assert_eq!(claims, 5);
}

/// (6) A holder whose control socket cannot be bound runs on, and says why.
#[test]
#[ignore = "real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn a_holder_runs_without_its_control_socket() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let quick = Duration::from_secs(90);
    // A profile path too long for a socket address, so the socket falls back to
    // `$TMPDIR/vox-<uid>`; and there, a plain file where that directory should be.
    let long = |n: &str| {
        let d = tmp.path().join(format!("{n}-{}", "p".repeat(120)));
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (host_dir, guest_dir) = (long("host"), long("guest"));
    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    let blocked_tmp = tmp.path().join("t");
    std::fs::create_dir_all(&blocked_tmp).unwrap();
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout).unwrap();
    let squat = blocked_tmp.join(format!("vox-{}", uid.trim()));
    std::fs::write(&squat, "not a directory\n").unwrap();
    let tmpdir = format!("{}/", blocked_tmp.display());
    let env = [("TMPDIR", tmpdir.as_str())];
    let mut held = 0usize;

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
    for d in [&host_dir, &guest_dir] {
        let (ok, said, _) = must("vox id", vox_env(d, &["id"], "", quick, &env));
        assert!(ok, "CANNOT MEASURE: vox id: {said}");
    }
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_port = service.local_addr().unwrap().port().to_string();
    let mut host = Proc::spawn_env(
        "host",
        &host_dir,
        &[
            "serve",
            &service_port,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        &env,
    );
    // Its lines, or its exit.
    let t0 = Instant::now();
    let printed = loop {
        if host.stdout().iter().any(|l| l.starts_with("passphrase")) {
            break true;
        }
        if host.child.try_wait().expect("wait").is_some() || t0.elapsed() > quick {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Still serving a moment after it printed them.
    std::thread::sleep(Duration::from_secs(2));
    let running = host.child.try_wait().expect("wait").is_none();
    let err = host.stderr();
    eprintln!(
        "[vox serve, socket blocked] printed={printed} running={running}: {}",
        err.trim().replace('\n', " / ")
    );
    assert!(
        printed && running,
        "(6) `vox serve` must keep serving when its control socket cannot be bound; \
         printed={printed} running={running}; stderr:\n{err}"
    );
    let warned = |said: &str| {
        said.contains("control socket unavailable")
            && said.contains(&squat.display().to_string())
            && said.contains("not a directory owned by you")
    };
    assert!(
        warned(&err),
        "(6) `vox serve` must say the control socket is unavailable, where and why: {err}"
    );
    held += 1;

    let field = |label: &str| {
        host.expect_out(label, |l| l.starts_with(label))
            .strip_prefix(label)
            .unwrap()
            .trim()
            .to_owned()
    };
    let (address, passphrase) = (field("address"), field("passphrase"));
    let pass_file = guest_dir.join("room-pass");
    std::fs::write(&pass_file, format!("{passphrase}\n")).unwrap();
    let (ok, said, took) = must(
        "vox connect",
        vox_env(
            &guest_dir,
            &[
                "connect",
                &address,
                "--passphrase-file",
                pass_file.to_str().unwrap(),
                "--anchor",
                &spec,
                "--listen",
                "127.0.0.1:0",
            ],
            "",
            quick,
            &env,
        ),
    );
    eprintln!(
        "[vox connect, socket blocked] ok={ok} in {:.1}s: {}",
        took.as_secs_f64(),
        said.trim().replace('\n', " / ")
    );
    assert!(
        ok && said.contains("joined."),
        "(6) `vox connect` must join when its control socket cannot be bound: {said}"
    );
    assert!(
        warned(&said),
        "(6) `vox connect` must say the control socket is unavailable, where and why: {said}"
    );
    held += 1;

    // What stood where the directory should be was never used.
    let left = std::fs::symlink_metadata(&squat).map(|m| m.file_type().is_file());
    assert!(
        matches!(left, Ok(true)) && std::fs::read_to_string(&squat).unwrap() == "not a directory\n",
        "(6) the file at {} was changed: {left:?}",
        squat.display()
    );
    drop(service);
    eprintln!("[proof] {held} holders ran without their control socket");
    assert_eq!(held, 2);
}
