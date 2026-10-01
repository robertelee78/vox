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
//! 7. **A `vox connect` stopped mid-join by SIGTERM, SIGINT, SIGHUP or SIGQUIT says why** (V210-85,
//!    #277; separate test, `a_connect_stopped_by_a_signal_says_why`): its exit status is the
//!    signal's (143, 130, 129, 131), not death by it, and it names the step it waited in and closes
//!    before it exits. A connect killed by a signal used to read as a verb that failed and said
//!    nothing.
//! 8. **A `vox connect` stopped at a passphrase prompt says why, and hands the terminal back**
//!    (V210-85; separate test, `a_connect_stopped_at_a_passphrase_prompt_says_why`).
//!
//! Each of 7 and 8 says on its own test what it stages, which reds are CANNOT MEASURE, and which
//! mutations turn it red.
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
    // A join's exchange includes the joiner's proof-of-work solve, which a debug build runs
    // ~50× slower than release, and whose nonce search is geometric: five debug runs measured the
    // exchange at 22–77 s, and one ran past 90 s. Release joins take 1–7 s. A join's bound only
    // decides CANNOT MEASURE, never a claim, so it is sized for the debug build's tail.
    let join_within = Duration::from_secs(240);
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
            join_within,
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
            join_within,
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
            // A join, so the same proof-of-work tail as the joins above.
            Duration::from_secs(240),
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

// ---- V210-85 (#277): a `vox connect` stopped by a signal says why ------------------------------

/// A stopped `vox connect` must have ended, and said so, by then — whatever it was doing.
const STOPS_WITHIN: Duration = Duration::from_secs(10);
/// How long the join is left waiting on its frozen host after it announced, before it is stopped:
/// into its wait for the host, well short of the dial's own give-up.
const LEFT_WAITING: Duration = Duration::from_secs(1);
/// How soon after the signal the anchor must count the connect gone: its close arrives at once,
/// and the anchor prints its count on its next 500 ms tick.
const CLOSED_WITHIN: Duration = Duration::from_secs(3);
/// How long a `vox connect` may take to show a passphrase prompt on its terminal.
const PROMPTS_WITHIN: Duration = Duration::from_secs(60);
/// A join's steps that wait on one member, and name it, as `vox connect` names them when stopped.
const MEMBER_STEPS: [&str; 3] = [
    "waiting for member ",
    "dialling member ",
    "the join exchange with member ",
];

/// How a stopped `vox connect` ended.
struct Ended {
    status: ExitStatus,
    took: Duration,
    stdout: String,
    stderr: String,
}

impl Ended {
    fn describe(&self) -> String {
        format!(
            "status: {} after {:.1}s\n--- stdout:\n{}\n--- stderr:\n{}",
            self.status,
            self.took.as_secs_f64(),
            self.stdout,
            self.stderr
        )
    }

    /// The step stderr says it had waited in: what follows `it had waited <n>s for `.
    fn waited(&self) -> &str {
        self.stderr
            .split("it had waited ")
            .nth(1)
            .and_then(|l| l.lines().next())
            .and_then(|l| l.split_once(" for "))
            .map(|(_, step)| step)
            .unwrap_or_default()
    }
}

/// Every stop: a status, never death by the signal, and on stderr how long it ran, that the room
/// was not joined, and what it had been waiting for. Every red here is the product's.
fn assert_says_stopped(e: &Ended, case: &str, name: &str, code: i32) {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        e.status.signal(),
        None,
        "{case}: `vox connect` died by the signal instead of ending with a reason.\n{}",
        e.describe()
    );
    assert_eq!(
        e.status.code(),
        Some(code),
        "{case}: exit status\n{}",
        e.describe()
    );
    assert!(
        !e.stderr.trim().is_empty(),
        "{case}: `vox connect` ended with status {code} and SAID NOTHING on stderr.\n{}",
        e.describe()
    );
    for want in [
        format!("stopped by {name} after "),
        "the room was not joined".to_owned(),
        "it had waited ".to_owned(),
    ] {
        assert!(
            e.stderr.contains(&want),
            "{case}: stderr does not say {want:?} — it must say how long it ran, that the room \
             was not joined, and the step it was waiting in.\n{}",
            e.describe()
        );
    }
}

/// The latest `(members, pending)` the anchor's board line gives for `room12`.
fn board_counts(anchor: &Proc, room12: &str) -> Option<(usize, usize)> {
    let tag = format!("board — {room12} ");
    anchor.stdout().iter().rev().find_map(|l| {
        let rest = l.split_once(&tag)?.1;
        let (m, rest) = rest.split_once("m/")?;
        let p = rest.split_once('p')?.0;
        Some((m.parse().ok()?, p.parse().ok()?))
    })
}

/// The latest number of peers `vox node` says it has connected.
fn peers_connected(anchor: &Proc) -> Option<usize> {
    anchor.stdout().iter().rev().find_map(|l| {
        l.strip_prefix("vox node: ")?
            .split_once(" peer(s) connected")?
            .0
            .parse()
            .ok()
    })
}

/// V210-85, claim 7 — **a `vox connect` stopped mid-join by SIGTERM, SIGINT, SIGHUP or SIGQUIT
/// says why**: exit status 143, 130, 129 or 131 (not death by the signal), and stderr says `stopped
/// by <SIGNAL> after …s`, that the room was not joined, and the join step it was waiting in, which
/// names the host. **It ends when it says so**, within [`STOPS_WITHIN`]. **And it closes before it
/// exits**: the anchor's own status line (`vox node: N peer(s) connected`, what its operator reads)
/// counts it gone within [`CLOSED_WITHIN`], not at the silence of a connection never closed.
///
/// A connect killed by the watchdog read as a verb that failed and said nothing; a person's Ctrl-C,
/// a SIGTERM from a supervisor, or a closed terminal (SIGHUP) killed it silently too.
///
/// **Staging.** An anchor and a `vox serve` host. Once the host's room is on the board, the host
/// is frozen (SIGSTOP): a join into it can then neither be answered nor get in, however late a
/// stop lands, and nothing in the product is switched for the proof. Each stop is a guest of its
/// own (a new identity), so its announce is one more pending record on the board; the stop is sent
/// [`LEFT_WAITING`] after that, while the join waits on the frozen host.
///
/// **A red names its side.** CANNOT MEASURE: a `vox id` or `kill` that failed, a room never
/// published, a join that ended on its own before the stop (its output is printed). A connect
/// that exits before it announces is the product's, quoted. Everything after the signal is the
/// product's.
///
/// **Mutations that must turn it red:** the verb runner printing nothing for an error; a signal not
/// taken (that stop dies by it); the joiner not announcing its steps (no join step named); a stop
/// that exits without closing (the anchor counts the connect past [`CLOSED_WITHIN`]).
#[test]
#[ignore = "real vox processes, production Argon2id; CI runs it in release"]
fn a_connect_stopped_by_a_signal_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir) = (dir("anchor"), dir("host"));
    let quick = Duration::from_secs(90);
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
    let (ok, said, _) = must("vox id (host)", vox(&host_dir, &["id"], "", quick));
    assert!(ok, "CANNOT MEASURE: vox id (host): {said}");
    let host_fp = said
        .split_whitespace()
        .find(|w| {
            w.len() == 52
                && w.chars()
                    .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        })
        .unwrap_or_else(|| panic!("CANNOT MEASURE: no fingerprint in `vox id`: {said}"))
        .to_owned();
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
    let room12 = room[..12].to_owned();
    let deadline = Instant::now() + Duration::from_secs(240);
    while board_counts(&anchor, &room12).is_none_or(|(m, _)| m < 1) {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: the host's room never showed on the anchor's board with its member.\n\
             ---- the anchor ----\n{}\n---- the host ----\n{}\n{}",
            anchor.stdout().join("\n"),
            host.stdout().join("\n"),
            host.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        signal("STOP", host.child.id()),
        "CANNOT MEASURE: `kill -STOP` the host failed"
    );

    let host12 = &host_fp[..12];
    let stops = [
        ("TERM", "SIGTERM", 143),
        ("INT", "SIGINT", 130),
        ("HUP", "SIGHUP", 129),
        ("QUIT", "SIGQUIT", 131),
    ];
    for (k, (sig, name, code)) in stops.iter().enumerate() {
        let case = format!("stopped by {name}");
        let guest = dir(&format!("guest-{k}"));
        let (ok, said, _) = must("vox id (guest)", vox(&guest, &["id"], "", quick));
        assert!(ok, "CANNOT MEASURE ({name}): vox id (guest): {said}");
        let file = guest.join("room-passphrase");
        std::fs::write(&file, &passphrase).unwrap();
        let pending = board_counts(&anchor, &room12).map_or(0, |(_, p)| p);
        let mut connect = Proc::spawn(
            "connect",
            &guest,
            &[
                "connect",
                &address,
                "--passphrase-file",
                file.to_str().unwrap(),
                "--anchor",
                &spec,
                "--listen",
                "127.0.0.1:0",
            ],
            "",
        );
        let t0 = Instant::now();
        // Its announce, as one more pending record on the board.
        let deadline = Instant::now() + Duration::from_secs(240);
        while board_counts(&anchor, &room12).is_none_or(|(_, p)| p <= pending) {
            if let Ok(Some(status)) = connect.child.try_wait() {
                std::thread::sleep(Duration::from_millis(100));
                panic!(
                    "{case}: `vox connect` ended ({status}) before it announced itself on the \
                     board, the room's member reachable there.\n--- stdout:\n{}\n--- stderr:\n{}",
                    connect.stdout().join("\n"),
                    connect.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE ({name}): the guest's announce never showed on the anchor's board, \
                 and its `vox connect` is still running.\n---- the connect ----\n{}\n{}\n\
                 ---- the anchor ----\n{}",
                connect.stdout().join("\n"),
                connect.stderr(),
                anchor.stdout().join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(LEFT_WAITING);
        if let Ok(Some(status)) = connect.child.try_wait() {
            std::thread::sleep(Duration::from_millis(100));
            panic!(
                "CANNOT MEASURE ({name}): the join ended on its own ({status}) before it could be \
                 stopped mid-way.\n--- stdout:\n{}\n--- stderr:\n{}",
                connect.stdout().join("\n"),
                connect.stderr()
            );
        }
        let peers = peers_connected(&anchor).unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE ({name}): the anchor never said how many peers it has.\n{}",
                anchor.stdout().join("\n")
            )
        });
        assert!(
            signal(sig, connect.child.id()),
            "CANNOT MEASURE ({name}): `kill -{sig}` failed"
        );
        let sent = Instant::now();
        let (mut exited, mut gone) = (None, None);
        while sent.elapsed() < CLOSED_WITHIN + Duration::from_secs(30) && gone.is_none() {
            if exited.is_none() {
                if let Ok(Some(s)) = connect.child.try_wait() {
                    exited = Some((s, sent.elapsed()));
                }
            }
            if peers_connected(&anchor).is_some_and(|n| n < peers) {
                gone = Some(sent.elapsed());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let (status, after) = exited
            .or_else(|| {
                connect
                    .exit_within(STOPS_WITHIN)
                    .map(|(s, _)| (s, sent.elapsed()))
            })
            .unwrap_or_else(|| {
                panic!(
                    "{case}: `vox connect` had not ended {STOPS_WITHIN:?} after the signal.\n\
                     --- stdout:\n{}\n--- stderr:\n{}",
                    connect.stdout().join("\n"),
                    connect.stderr()
                )
            });
        // Let the reader threads take the last lines.
        std::thread::sleep(Duration::from_millis(100));
        let e = Ended {
            status,
            took: t0.elapsed(),
            stdout: connect.stdout().join("\n"),
            stderr: connect.stderr(),
        };
        eprintln!("[connect] {}", e.describe().replace('\n', "\n[connect] "));
        eprintln!(
            "[proof] {name}: {status} {:.1}s after the signal, {:.1}s after the start; the \
             anchor counted it gone {gone:?} after the signal",
            after.as_secs_f64(),
            e.took.as_secs_f64()
        );
        assert!(
            after < STOPS_WITHIN,
            "{case}: `vox connect` ended only {after:?} after the signal, over {STOPS_WITHIN:?}.\n{}",
            e.describe()
        );
        assert_says_stopped(&e, &case, name, *code);
        let waited = e.waited();
        let step = MEMBER_STEPS.iter().find(|s| waited.starts_with(*s));
        assert!(
            step.is_some_and(|s| waited.starts_with(&format!("{s}{host12}"))),
            "{case}: it waited in {waited:?}, but a join past its announce into a frozen host \
             waits on that host ({host12}), in one of the join's own steps.\n{}",
            e.describe()
        );
        let gone = gone.unwrap_or_else(|| {
            panic!(
                "{case}: the anchor still counted {peers} peers {:?} after the signal — the connect \
                 did not close its connection to it.\n---- the anchor ----\n{}",
                CLOSED_WITHIN + Duration::from_secs(30),
                anchor.stdout().join("\n")
            )
        });
        assert!(
            gone < CLOSED_WITHIN,
            "{case}: the anchor counted the connect gone only {gone:?} after the signal, over \
             {CLOSED_WITHIN:?} — not a close, the silence of one never sent.\n---- the anchor \
             ----\n{}",
            anchor.stdout().join("\n")
        );
        eprintln!("[proof] {name}: said why, waited in {waited:?}");
    }
    drop(service);
    eprintln!(
        "[proof] {}/{} stops said why (SIGTERM, SIGINT, SIGHUP, SIGQUIT)",
        stops.len(),
        stops.len()
    );
}

// ---- V210-85 (#277): a `vox connect` stopped at a passphrase prompt says why ------------------

/// A `vox connect` on a terminal of its own: stdin and stdout on a pty, stderr on a pipe.
struct OnTerminal {
    child: Child,
    /// The pty's other end, kept to read the terminal's modes after the connect has ended.
    terminal: std::os::fd::OwnedFd,
    /// Everything the connect drew on its terminal, read as it arrives: a process that exits with
    /// output nobody has read cannot finish exiting on macOS.
    shown: Arc<Mutex<Vec<u8>>>,
    /// The pty's controlling side, to type on.
    keys: std::fs::File,
    stderr: std::sync::mpsc::Receiver<String>,
    t0: Instant,
}

impl OnTerminal {
    /// `vox connect` for `profile`, with no identity passphrase in its environment, and the room
    /// passphrase from `room_file` or else prompted for. Setting up the pty is the scene, not the
    /// product: a failure there is CANNOT MEASURE.
    fn start(profile: &std::path::Path, room_file: Option<&std::path::Path>) -> Self {
        use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
        let apparatus = |what: &str, e: &dyn std::fmt::Debug| -> ! {
            panic!("CANNOT MEASURE: setting up the pty: {what}: {e:?}")
        };
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)
            .unwrap_or_else(|e| apparatus("openpt", &e));
        grantpt(&controller).unwrap_or_else(|e| apparatus("grantpt", &e));
        unlockpt(&controller).unwrap_or_else(|e| apparatus("unlockpt", &e));
        let name = ptsname(&controller, Vec::new()).unwrap_or_else(|e| apparatus("ptsname", &e));
        let name = name
            .to_str()
            .unwrap_or_else(|e| apparatus("the pty's name", &e))
            .to_owned();
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&name)
                .unwrap_or_else(|e| apparatus("open the pty", &e))
        };
        let terminal: std::os::fd::OwnedFd = open().into();
        // Nothing reads this address before both prompts are answered: the stop lands first.
        let mut a = vec![
            "connect".to_owned(),
            "vox://not-read-before-the-prompts".to_owned(),
        ];
        if let Some(f) = room_file {
            a.push("--passphrase-file".to_owned());
            a.push(f.to_str().unwrap().to_owned());
        }
        let mut child = Command::new(VOX)
            .args(&a)
            .env("VOX_DATA_DIR", profile)
            .env("VOX_CONFIG_DIR", profile.join("cfg"))
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(Stdio::from(open()))
            .stdout(Stdio::from(open()))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| apparatus("spawn vox connect on the pty", &e));
        let t0 = Instant::now();
        let mut screen = std::fs::File::from(controller);
        let keys = screen
            .try_clone()
            .unwrap_or_else(|e| apparatus("the pty, to type on", &e));
        let shown = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&shown);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = screen.read(&mut buf) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let (tx, stderr) = std::sync::mpsc::channel();
        let err = child.stderr.take().expect("stderr");
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            terminal,
            shown,
            keys,
            stderr,
            t0,
        }
    }

    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.shown.lock().unwrap()).into_owned()
    }

    /// Wait until the connect shows `prompt` on its terminal. One that ends first, or never shows
    /// it, did not reach the prompt: the product's, quoted.
    fn until_prompted(&mut self, prompt: &str) {
        let deadline = Instant::now() + PROMPTS_WITHIN;
        loop {
            let shown = self.shown();
            if shown.contains(prompt) {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "`vox connect` ended ({status}) before it showed {prompt:?}. Its terminal:\n\
                     {shown}\n--- stderr:\n{}",
                    self.stderr.try_iter().collect::<Vec<_>>().join("\n")
                );
            }
            assert!(
                Instant::now() < deadline,
                "`vox connect` did not show {prompt:?} within {PROMPTS_WITHIN:?}. Its terminal:\n{shown}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Read what it says on stderr until the pipe closes, and reap it; red past [`STOPS_WITHIN`].
    fn finish(mut self) -> (Ended, rustix::termios::Termios) {
        let deadline = Instant::now() + STOPS_WITHIN;
        let mut stderr = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "`vox connect` had not ended {STOPS_WITHIN:?} after it was due to. It said:\n{}",
                stderr.join("\n")
            );
            match self.stderr.recv_timeout(left.min(Duration::from_secs(1))) {
                Ok(line) => stderr.push(line),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let status = self
            .child
            .wait()
            .unwrap_or_else(|e| panic!("CANNOT MEASURE: reaping vox connect: {e}"));
        let modes = rustix::termios::tcgetattr(&self.terminal)
            .unwrap_or_else(|e| panic!("CANNOT MEASURE: reading the terminal's modes: {e}"));
        let ended = Ended {
            status,
            took: self.t0.elapsed(),
            stdout: self.shown(),
            stderr: stderr.join("\n"),
        };
        eprintln!(
            "[connect] {}",
            ended.describe().replace('\n', "\n[connect] ")
        );
        (ended, modes)
    }
}

impl Drop for OnTerminal {
    fn drop(&mut self) {
        // By its own PID, and reaped.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The terminal a stopped prompt hands back must echo and edit lines again.
fn assert_terminal_handed_back(modes: &rustix::termios::Termios, case: &str, e: &Ended) {
    use rustix::termios::LocalModes;
    assert!(
        modes
            .local_modes
            .contains(LocalModes::ECHO | LocalModes::ICANON),
        "{case}: the terminal was left without echo or line editing (local modes {:?}) — the \
         prompt's raw mode, handed back to the shell.\n{}",
        modes.local_modes,
        e.describe()
    );
}

/// Stopped at `prompt` by `sig`: it says so, names the prompt, and hands the terminal back.
fn stopped_at_prompt(
    profile: &std::path::Path,
    room_file: Option<&std::path::Path>,
    prompt: &str,
    stop: (&str, &str, i32),
    waited_for: &str,
) {
    let (sig, name, code) = stop;
    let mut c = OnTerminal::start(profile, room_file);
    c.until_prompted(prompt);
    assert!(
        signal(sig, c.child.id()),
        "CANNOT MEASURE: `kill -{sig}` failed"
    );
    let (e, modes) = c.finish();
    let case = format!("{name} at the {prompt:?} prompt");
    assert_says_stopped(&e, &case, name, code);
    assert_eq!(
        e.waited(),
        waited_for,
        "{case}: it does not say it had waited for {waited_for:?}.\n{}",
        e.describe()
    );
    assert_terminal_handed_back(&modes, &case, &e);
    eprintln!(
        "[proof] {case}: {}, waited for {waited_for:?}, terminal handed back",
        e.status
    );
}

/// V210-85, claim 8 — **a `vox connect` stopped at a passphrase prompt says why** — the room
/// passphrase's, or the identity's — on a terminal: SIGTERM gives 143 and SIGHUP 129, each naming
/// the prompt it waited at, and the terminal is handed back with echo and line editing on, not in
/// the prompt's raw mode. Ctrl-C typed at the prompt ends with a status and `cancelled`. The prompts
/// ran before the signal handler was taken, so a stop there died on the signal and said nothing.
///
/// **A red names its side.** CANNOT MEASURE: `vox id`, the pty, or a `kill` failed. A connect that
/// never shows its prompt, or anything after the stop, is the product's, quoted.
///
/// **Mutations that must turn it red:** the prompts run before the handler is taken (it dies by
/// the signal); the terminal not handed back (still raw); a stop that waits for the runtime's
/// blocking work (a prompt still reading holds the exit past [`STOPS_WITHIN`]).
#[test]
#[ignore = "production Argon2id for the profile's identity; CI runs it in release"]
fn a_connect_stopped_at_a_passphrase_prompt_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().join("guest");
    std::fs::create_dir_all(profile.join("cfg")).unwrap();
    let (ok, said, _) = must(
        "vox id",
        vox(&profile, &["id"], "", Duration::from_secs(90)),
    );
    assert!(ok, "CANNOT MEASURE: vox id: {said}");
    let room_file = tmp.path().join("room-passphrase");
    std::fs::write(&room_file, "a room passphrase").unwrap();

    stopped_at_prompt(
        &profile,
        None,
        "room passphrase: ",
        ("TERM", "SIGTERM", 143),
        "the room passphrase",
    );
    stopped_at_prompt(
        &profile,
        Some(&room_file),
        "identity passphrase: ",
        ("HUP", "SIGHUP", 129),
        "this profile's identity passphrase",
    );

    // Ctrl-C typed at the prompt is a key on a raw terminal, not a signal: the prompt's own "no".
    let mut c = OnTerminal::start(&profile, Some(&room_file));
    c.until_prompted("identity passphrase: ");
    Write::write_all(&mut c.keys, b"\x03")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: typing Ctrl-C on the pty: {e}"));
    let (e, modes) = c.finish();
    let case = "Ctrl-C at the identity passphrase prompt";
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            e.status.signal(),
            None,
            "{case}: died by a signal.\n{}",
            e.describe()
        );
    }
    assert_eq!(
        e.status.code(),
        Some(1),
        "{case}: exit status\n{}",
        e.describe()
    );
    assert!(
        e.stderr.contains("cancelled"),
        "{case}: stderr does not say it was cancelled.\n{}",
        e.describe()
    );
    assert_terminal_handed_back(&modes, case, &e);
    eprintln!("[proof] {case}: {}, said it was cancelled", e.status);
    eprintln!("[proof] 3/3 stops at a prompt said why (SIGTERM, SIGHUP, Ctrl-C)");
}
