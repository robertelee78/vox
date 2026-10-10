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
//! 3. **`vox room tail` exits non-zero when its node dies, even part-way through a frame.** It
//!    exited 0, so a supervisor that restarts a failed tail never restarted it. The daemon is
//!    killed with SIGKILL by its PID; the tail must exit non-zero within 30 s, saying the node
//!    stopped, and never call it a "malformed control-socket message" (V210-101, #305). The kill
//!    lands mid-frame by construction: the proof stops reading the tail's output, then posts
//!    [`BIG`] messages of 60,000 characters, about 1.9 MB. The tail blocks writing them to its full
//!    stdout pipe, so it stops reading its socket, and the daemon blocks part-way through writing
//!    the next one. What lies between the daemon and the tail's printed output must hold less than
//!    that on every system CI runs: on macOS the socket buffers 8 KiB each way; on Linux a unix
//!    stream socket holds at most its sender's 208 KiB `wmem_default`, a pipe 64 KiB, and the
//!    tail one frame. Six posts (360 KB) fitted on Linux, and the tail printed all six
//!    (V210-125). After the kill the output is read again, and the tail meets a length, part of
//!    a body, then EOF. If the tail printed every one, no frame was cut: PRODUCT (staging).
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
//!    PRODUCT (staging). The control: after SIGCONT the same daemon answers `vox status`. A node
//!    whose actor is stuck while it still greets cannot be staged through any command; that
//!    half (the ping each check sends through the actor) rests on code review.
//! 7. **A request whose node is killed mid-request names the hang-up** (V210-101, #305). Staged as
//!    (5), but the joiner's daemon is killed with SIGKILL, so its connection ends rather than
//!    going quiet. The join must exit non-zero within the proof's bound, saying the node closed
//!    the connection before replying and is no longer running, and never call it a "malformed
//!    control-socket message": nothing arrived to be malformed. If it says the node closed the
//!    connection before greeting, the kill came before the request was sent: PRODUCT (staging).
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
//! 9. **A request the daemon ends without a reply is in its log** (#666; separate test,
//!    `a_request_ended_without_a_reply_is_in_the_daemons_log`): a client told "it ended this
//!    request itself; its log says why" must find a line there. A test-side client (apparatus)
//!    sends the running daemon a frame longer than it accepts; the daemon closes the connection
//!    with no reply, and its log says, in one line, that a client's request was ended without a
//!    reply, and why. Mutant: that line not written (`Dispatch::unanswered` saying nothing) —
//!    red, PRODUCT.
//!
//! Each of 7 and 8 says on its own test what it stages, which reds are APPARATUS or PRODUCT (staging), and which
//! mutations turn it red.
//!
//! **Staging.** An anchor (`vox node`), a host (`vox serve` of a loopback echo service), and a
//! joiner's `vox daemon`. Every participant is the shipped binary; every process is killed by its
//! own PID, and signals go to PIDs, never to patterns.
//!
//! **Mutations that must turn it red**, one per claim: (1) drop the exchange failure's
//! `why.push` in the actor's join walk — no `said:` line; (2) remove the `ANSWER_WITHIN` bound
//! from `IpcClient::open` and `status::request` — `vox status` is still running at 30 s;
//! (3) `Ok(None) => return Ok(())` back in `room_cli::tail` — the tail exits 0; and
//! `read_frame`'s EOF inside a body mapped back to `MalformedIpc("ipc read body")` — the tail says
//! "malformed control-socket message"; (5)
//! `IpcClient::request` without `while_answering` — the join is still running at 45 s; (6)
//! the daemon's socket refusal not echoed to its log — no path or reason said; (7)
//! `IpcClient::request`'s end-of-stream mapped back to `MalformedIpc("ipc closed before reply")` —
//! the join says "malformed control-socket message".

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A room address that parses (a room id, and one anchor with its address) and names nowhere a
/// node runs (UDP port 9 on this machine): what these verbs read only after the prompt this proof
/// is about. An address that will not parse is refused before any prompt.
const UNREACHABLE_ROOM: &str =
    "vox://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?a=ccccccccccccccccccccccccccccccccccccccccccccccccccca&b=/ip4/127.0.0.1/udp/9";

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";

/// A long-running `vox`, killed by its own PID however the test ends.
struct Proc {
    name: &'static str,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
    /// While set, nothing more of this process's stdout is read, so its pipe fills and its
    /// writes block.
    hold_out: Arc<AtomicBool>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        // A frozen process is continued first, so the kill is not left pending on it.
        signal("CONT", self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: impl Read + Send + 'static, hold: Arc<AtomicBool>) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        let mut lines = BufReader::new(stream).lines();
        loop {
            while hold.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
            let Some(Ok(line)) = lines.next() else { break };
            sink.lock()
                .expect("APPARATUS: harness step failed")
                .push(line);
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
            .unwrap_or_else(|e| panic!("APPARATUS: harness could not spawn {name}: {e}"));
        let mut pipe = child.stdin.take().expect("APPARATUS: harness: stdin");
        pipe.write_all(stdin.as_bytes())
            .expect("APPARATUS: harness: write stdin");
        drop(pipe);
        let hold_out = Arc::new(AtomicBool::new(false));
        let out = collect(
            child.stdout.take().expect("APPARATUS: harness: stdout"),
            Arc::clone(&hold_out),
        );
        let err = collect(
            child.stderr.take().expect("APPARATUS: harness: stderr"),
            Arc::new(AtomicBool::new(false)),
        );
        Self {
            name,
            child,
            out,
            err,
            hold_out,
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.out
            .lock()
            .expect("APPARATUS: harness step failed")
            .clone()
    }

    fn stderr(&self) -> String {
        self.err
            .lock()
            .expect("APPARATUS: harness step failed")
            .join("\n")
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
            "PRODUCT (staging): {} never printed {what}; stdout {:#?}\nstderr:\n{}",
            self.name,
            self.stdout(),
            self.stderr()
        );
    }

    /// Wait up to `within` for the process to exit; `None` if it is still running then.
    fn exit_within(&mut self, within: Duration) -> Option<(ExitStatus, Duration)> {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if let Some(s) = self.child.try_wait().expect("APPARATUS: harness: wait") {
                return Some((s, t0.elapsed()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

/// The pid of the daemon holding `dir`'s lock (it writes it there): what does a held verb's work,
/// so what a proof suspends to make that work wait (ADR-026 S-3: `vox serve` is only its client).
fn daemon_pid_of(dir: &std::path::Path) -> u32 {
    std::fs::read_to_string(dir.join(".daemon").join("lock"))
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT (staging): no daemon holds {}", dir.display()))
}

/// A process this proof froze with SIGSTOP, continued when this drops — however the proof ends,
/// so a red never leaves a stopped process (a daemon that is not this proof's child included).
struct Frozen(u32);

impl Drop for Frozen {
    fn drop(&mut self) {
        signal("CONT", self.0);
    }
}

/// SIGSTOP `pid`, with a guard that continues it; `None` if the signal could not be sent.
fn freeze(pid: u32) -> Option<Frozen> {
    signal("STOP", pid).then_some(Frozen(pid))
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

/// A verb that never finished within its bound is the product's: every bound here is many times
/// the verb's measured time, and the verb, not the runner, is what was waited on.
fn must(what: &str, r: Option<(bool, String, Duration)>) -> (bool, String, Duration) {
    r.unwrap_or_else(|| panic!("PRODUCT: `{what}` did not finish within its bound"))
}

#[test]
#[ignore = "three real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn a_cli_failure_tells_the_truth() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: harness step failed");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: harness step failed");
        d
    };
    let (anchor_dir, host_dir, joiner_dir) = (dir("anchor"), dir("host"), dir("joiner"));
    let quick = Duration::from_secs(90);
    // A join's exchange includes the joiner's proof-of-work solve, which a debug build runs
    // ~50× slower than release, and whose nonce search is geometric: five debug runs measured the
    // exchange at 22–77 s, and one ran past 90 s. Release joins take 1–7 s. A join past its bound is
    // the product's red, so the bound is sized for the debug build's tail.
    let join_within = Duration::from_secs(240);
    let bound = Duration::from_secs(30);
    let mut claims = 0usize;

    let service = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: harness step failed");
    let service_port = service
        .local_addr()
        .expect("APPARATUS: harness step failed")
        .port()
        .to_string();

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
        assert!(ok, "PRODUCT (staging): `vox id` failed: {said}");
    }
    let host = Proc::spawn(
        "host",
        &host_dir,
        &[
            "serve",
            &format!("{service_port}={service_port}"),
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
            .expect("APPARATUS: harness step failed")
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
            &["room", "join", "--passphrase-file", "-", &address],
            "not the passphrase\n",
            join_within,
        ),
    );
    eprintln!(
        "[join, wrong passphrase] in {:.1}s: {}",
        took.as_secs_f64(),
        said.trim().replace('\n', " / ")
    );
    assert!(!ok, "PRODUCT (1): a wrong passphrase must not join: {said}");
    assert!(
        said.contains("refused the join"),
        "PRODUCT (staging) (1): the join with a wrong passphrase was not refused by a member, so \
         the exchange was not where it failed: {said}"
    );
    let said_line = said.lines().find(|l| l.trim_start().starts_with("said:"));
    assert!(
        said_line.is_some_and(|l| l.contains("exchange")),
        "PRODUCT (1) a join refused in the exchange must say what the member said (a `said:` line \
         naming the exchange); it said:\n{said}"
    );
    assert!(
        !said.contains("Failed("),
        "PRODUCT (1) an enum token reached the person:\n{said}"
    );
    claims += 1;

    let (ok, said, took) = must(
        "vox room join",
        vox(
            &joiner_dir,
            &["room", "join", "--passphrase-file", "-", &address],
            &format!("{passphrase}\n"),
            join_within,
        ),
    );
    eprintln!(
        "[join, right passphrase] ok={ok} in {:.1}s",
        took.as_secs_f64()
    );
    assert!(
        ok,
        "PRODUCT (staging): the right passphrase did not join: {said}"
    );

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
        "PRODUCT (4) removing a service never offered must fail: {said}"
    );
    assert!(
        said.contains("not offered in this room") && !said.contains("Failed("),
        "PRODUCT (4) the failure must name its cause: {said}"
    );
    claims += 1;

    // ---- (5) a node suspended mid-request: the request ends, and says so ----
    let late_dir = dir("late");
    let (ok, said, _) = must("vox id (late)", vox(&late_dir, &["id"], "", quick));
    assert!(ok, "PRODUCT (staging): `vox id` (late) failed: {said}");
    let late = Proc::spawn(
        "late-daemon",
        &late_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    late.expect_out("its control socket", |l| l.contains("control socket"));
    let (host_pid, late_pid) = (daemon_pid_of(&host_dir), late.child.id());
    // The host is suspended, so the join waits on it and is still being worked on a second
    // after it is asked.
    let _frozen_1 =
        freeze(host_pid).unwrap_or_else(|| panic!("APPARATUS (5): could not SIGSTOP the host"));
    let mut join = Proc::spawn(
        "late join",
        &late_dir,
        &["room", "join", "--passphrase-file", "-", &address],
        &format!("{passphrase}\n"),
    );
    std::thread::sleep(Duration::from_secs(1));
    if let Some(s) = join.child.try_wait().expect("APPARATUS: harness: wait") {
        signal("CONT", host_pid);
        std::thread::sleep(Duration::from_millis(100));
        panic!(
            "PRODUCT (staging) (5): the join ended ({s}) before its node could be suspended \
             mid-request: {}\n{}",
            join.stdout().join("\n"),
            join.stderr()
        );
    }
    let _frozen_2 = freeze(late_pid)
        .unwrap_or_else(|| panic!("APPARATUS (5): could not SIGSTOP the late joiner's daemon"));
    let mid_bound = Duration::from_secs(45);
    let ended = join.exit_within(mid_bound);
    assert!(
        signal("CONT", late_pid) && signal("CONT", host_pid),
        "APPARATUS (5): could not SIGCONT the daemons"
    );
    let Some((status, took)) = ended else {
        panic!(
            "PRODUCT (5) `vox room join` against a node suspended mid-request was still running after \
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
        "PRODUCT (staging) (5): the node was suspended before it greeted, so the request was never \
         sent: {said}"
    );
    assert!(
        !status.success(),
        "PRODUCT (5) a join whose node was suspended mid-request must fail: {said}"
    );
    assert!(
        said.contains("stopped answering while this request waited"),
        "PRODUCT (5) the join must say its node stopped answering while it waited: {said}"
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
        "PRODUCT (staging) (5): the resumed node did not answer `vox status` either, so the \
         silence was not the suspension's: {said}"
    );
    drop(late);
    claims += 1;

    // ---- (7) a node killed mid-request: the request names the hang-up, never "malformed" ----
    let gone_dir = dir("gone");
    let (ok, said, _) = must("vox id (gone)", vox(&gone_dir, &["id"], "", quick));
    assert!(ok, "PRODUCT (staging) (7): `vox id` (gone) failed: {said}");
    let mut gone = Proc::spawn(
        "gone-daemon",
        &gone_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    gone.expect_out("its control socket", |l| l.contains("control socket"));
    let gone_pid = gone.child.id();
    // As in (5): the host is suspended, so the join is still being worked on when its own node
    // is killed. A kill, not a suspension: the connection ends, it does not go quiet.
    let _frozen_3 =
        freeze(host_pid).unwrap_or_else(|| panic!("APPARATUS (7): could not SIGSTOP the host"));
    let mut join = Proc::spawn(
        "gone join",
        &gone_dir,
        &["room", "join", "--passphrase-file", "-", &address],
        &format!("{passphrase}\n"),
    );
    std::thread::sleep(Duration::from_secs(1));
    if let Some(s) = join.child.try_wait().expect("APPARATUS: harness: wait") {
        signal("CONT", host_pid);
        panic!(
            "PRODUCT (staging) (7): the join ended ({s}) before its node could be killed \
             mid-request: {}\n{}",
            join.stdout().join("\n"),
            join.stderr()
        );
    }
    assert!(
        signal("KILL", gone_pid),
        "APPARATUS (7): could not SIGKILL the joiner's daemon"
    );
    let _ = gone.child.wait();
    let ended = join.exit_within(bound);
    assert!(
        signal("CONT", host_pid),
        "APPARATUS (7): could not SIGCONT the host"
    );
    let Some((status, took)) = ended else {
        panic!(
            "PRODUCT (7): `vox room join` whose node was killed mid-request was still running \
             after {bound:?}"
        );
    };
    std::thread::sleep(Duration::from_millis(100));
    let said = format!("{}\n{}", join.stdout().join("\n"), join.stderr());
    eprintln!(
        "[room join, node killed mid-request] exit {:?} in {:.1}s: {}",
        status.code(),
        took.as_secs_f64(),
        said.trim().replace('\n', " / ")
    );
    assert!(
        !said.contains("closed the connection before greeting"),
        "PRODUCT (staging) (7): the node was gone before it greeted, so no request was in flight: \
         {said}"
    );
    assert!(
        !status.success(),
        "PRODUCT (7): a join whose node was killed mid-request must fail: {said}"
    );
    assert!(
        !said.contains("malformed"),
        "PRODUCT (7): a node that hung up was called malformed, though nothing arrived to be \
         malformed: {said}"
    );
    assert!(
        said.contains("closed the connection before replying")
            && said.contains("no longer running"),
        "PRODUCT (7): the join must say its node closed the connection before replying and is no \
         longer running: {said}"
    );
    drop(gone);
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
        "PRODUCT (staging) (3): the tail printed none of {n} posts in 60 s; stderr:\n{}",
        tail.stderr()
    );

    // ---- (2) a suspended node: `vox status` and an attach end, and say so ----
    let pid = joiner.child.id();
    let _frozen_4 =
        freeze(pid).unwrap_or_else(|| panic!("APPARATUS (2): could not SIGSTOP the daemon"));
    let status = vox(&joiner_dir, &["status"], "", bound);
    let list = vox(&joiner_dir, &["room", "list"], "", bound);
    assert!(
        signal("CONT", pid),
        "APPARATUS (2): could not SIGCONT the daemon"
    );
    for (verb, r) in [("vox status", status), ("vox room list", list)] {
        let Some((ok, said, took)) = r else {
            panic!(
                "PRODUCT (2) `{verb}` against a suspended node was still running after {bound:?}"
            );
        };
        eprintln!(
            "[{verb}, node suspended] ok={ok} in {:.1}s: {}",
            took.as_secs_f64(),
            said.trim().replace('\n', " / ")
        );
        assert!(
            !ok,
            "PRODUCT (2) `{verb}` against a suspended node must fail: {said}"
        );
        assert!(
            said.contains("did not answer"),
            "PRODUCT (2) `{verb}` must say the node did not answer: {said}"
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
        "PRODUCT (staging) (2): the resumed node did not answer `vox status` either, so the \
         silence was not the suspension's: {said}"
    );
    claims += 1;

    // ---- (3) the node dies under the tail, part-way through a frame ----
    // The tail's output is no longer read, and more posts are made than everything between the
    // daemon and the tail's stdout can buffer, on macOS or Linux: the tail blocks printing, and
    // the daemon blocks inside its write of a frame.
    tail.hold_out.store(true, Ordering::SeqCst);
    let filler = "x".repeat(60_000);
    for i in 0..BIG {
        let text = format!("big-{i}-{filler}");
        let (ok, said, _) = must(
            "vox room post (big)",
            vox(&joiner_dir, &["room", "post", &room, &text], "", quick),
        );
        assert!(
            ok,
            "PRODUCT (staging) (3): a 60,000-character post was not made: {said}"
        );
    }
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        signal("KILL", pid),
        "APPARATUS (3): could not SIGKILL the daemon"
    );
    let _ = joiner.child.wait();
    tail.hold_out.store(false, Ordering::SeqCst);
    let Some((status, took)) = tail.exit_within(bound) else {
        panic!("PRODUCT (3) the tail was still running {bound:?} after its node was killed");
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
        "PRODUCT (3) the tail exited 0 when its node died; a supervisor would not restart it: {err}"
    );
    assert!(
        !err.contains("malformed"),
        "PRODUCT (3) a node that died part-way through a frame was called malformed, though what \
         arrived was only cut short: {err}"
    );
    assert!(
        err.contains("the node stopped"),
        "PRODUCT (3) the tail must say its node stopped: {err}"
    );
    let printed = tail.stdout().iter().filter(|l| l.contains("big-")).count();
    eprintln!("[room tail, node killed] printed {printed} of {BIG} big posts");
    assert!(
        printed < BIG,
        "PRODUCT (staging) (3): the tail printed all {BIG} big posts before its node died, so no \
         frame was cut part-way"
    );
    claims += 1;

    eprintln!("[proof] {claims} claims held");
    assert_eq!(
        claims, 6,
        "APPARATUS: {claims} claims were counted, not the 6 this test stages (1, 2, 3, 4, 5, 7): \
         a claim was skipped or added without its count"
    );
}

/// How many 60,000-character posts case (3) makes while the tail's output is not read: about
/// 1.9 MB, several times what a unix socket, a pipe and the tail hold together on macOS or Linux,
/// so the daemon is always part-way through a frame when it is killed.
const BIG: usize = 32;

/// (6) A daemon whose control socket cannot be bound says so, and its holder fails, saying why.
/// (Before ADR-026 the holder ran on without a socket of its own; the account socket is now the
/// only way any verb reaches a node, so there is nothing to run on.)
#[test]
#[ignore = "real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn a_holder_runs_without_its_control_socket() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: harness step failed");
    let quick = Duration::from_secs(90);
    // A profile path too long for a socket address, so the socket falls back to
    // `$TMPDIR/vox-<uid>`; and there, a plain file where that directory should be.
    let long = |n: &str| {
        let d = tmp.path().join(format!("{n}-{}", "p".repeat(120)));
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: harness step failed");
        d
    };
    let (host_dir, guest_dir) = (long("host"), long("guest"));
    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: harness step failed");
    let blocked_tmp = tmp.path().join("t");
    std::fs::create_dir_all(&blocked_tmp).expect("APPARATUS: harness step failed");
    let uid = String::from_utf8(
        Command::new("id")
            .arg("-u")
            .output()
            .expect("APPARATUS: harness step failed")
            .stdout,
    )
    .expect("APPARATUS: harness step failed");
    let squat = blocked_tmp.join(format!("vox-{}", uid.trim()));
    std::fs::write(&squat, "not a directory\n").expect("APPARATUS: harness step failed");
    let tmpdir = format!("{}/", blocked_tmp.display());
    let env = [("TMPDIR", tmpdir.as_str())];

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
        assert!(ok, "PRODUCT (staging): `vox id` failed: {said}");
    }
    let service = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: harness step failed");
    let service_port = service
        .local_addr()
        .expect("APPARATUS: harness step failed")
        .port()
        .to_string();
    let mut host = Proc::spawn_env(
        "host",
        &host_dir,
        &[
            "serve",
            &format!("{service_port}={service_port}"),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        &env,
    );
    // Since ADR-026 the account socket is how every verb reaches its node, so a daemon that cannot
    // bind it serves nobody: `vox serve` starts one, which refuses the squatted directory, and
    // `vox serve` ends within the daemon's start bound saying it did not start and where its log
    // is; that log, or what it echoes, names the socket's path and why.
    let t0 = Instant::now();
    let ended = loop {
        if let Some(status) = host.child.try_wait().expect("APPARATUS: harness: wait") {
            break Some(status);
        }
        if t0.elapsed() > quick {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let err = host.stderr();
    let log = std::fs::read_to_string(host_dir.join(".daemon").join("log")).unwrap_or_default();
    eprintln!(
        "[vox serve, socket blocked] ended={ended:?}: {} / log: {}",
        err.trim().replace('\n', " / "),
        log.trim().replace('\n', " / ")
    );
    assert!(
        ended.is_some_and(|s| !s.success()),
        "PRODUCT (6) `vox serve` whose daemon cannot bind its socket must fail within \
         {quick:?}, not serve or wait: ended={ended:?}; stderr:\n{err}"
    );
    assert!(
        (err.contains("did not start") || err.contains("stopped as it started"))
            && err.contains("log"),
        "PRODUCT (6) `vox serve` must say the daemon did not start and name its log: {err}"
    );
    let said = format!("{err}\n{log}");
    assert!(
        said.contains(&squat.display().to_string())
            && said.contains("not a directory owned by you"),
        "PRODUCT (6) the daemon must say where its control socket could not go and why: {said}"
    );
    // What stood where the directory should be was never used.
    let left = std::fs::symlink_metadata(&squat).map(|m| m.file_type().is_file());
    assert!(
        matches!(left, Ok(true))
            && std::fs::read_to_string(&squat).expect("APPARATUS: harness step failed")
                == "not a directory\n",
        "PRODUCT (6) the file at {} was changed: {left:?}",
        squat.display()
    );
    drop(service);
    drop(guest_dir);
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
        "PRODUCT: {case}: `vox connect` died by the signal instead of ending with a reason.\n{}",
        e.describe()
    );
    assert_eq!(
        e.status.code(),
        Some(code),
        "PRODUCT: {case}: exit status\n{}",
        e.describe()
    );
    assert!(
        !e.stderr.trim().is_empty(),
        "PRODUCT: {case}: `vox connect` ended with status {code} and SAID NOTHING on stderr.\n{}",
        e.describe()
    );
    for want in [
        format!("stopped by {name} after "),
        "the room was not joined".to_owned(),
        "it had waited ".to_owned(),
    ] {
        assert!(
            e.stderr.contains(&want),
            "PRODUCT: {case}: stderr does not say {want:?} — it must say how long it ran, that the room \
             was not joined, and the step it was waiting in.\n{}",
            e.describe()
        );
    }
}

/// The latest `(members, pending)` the anchor's board line gives for `room12`.
fn board_counts(anchor: &Proc, room12: &str) -> Option<(usize, usize)> {
    // `<room>: <m> member(s), <p> pending`, rooms joined by `; ` (#396).
    let tag = format!("{room12}: ");
    anchor.stdout().iter().rev().find_map(|l| {
        let rest = l.strip_prefix("vox node: board — ")?;
        let counts = rest.split("; ").find_map(|e| e.strip_prefix(&tag))?;
        let (m, p) = counts.split_once(", ")?;
        Some((
            m.split(' ').next()?.parse().ok()?,
            p.strip_suffix(" pending")?.parse().ok()?,
        ))
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
/// **A red names its side.** APPARATUS: a `kill` that failed. PRODUCT (staging): a join that ended
/// on its own before the stop (its output is printed), a `vox id` that failed, a room never
/// published. A connect that exits before it announces is the product's, quoted. Everything after
/// the signal is the product's.
///
/// **Mutations that must turn it red:** the verb runner printing nothing for an error; a signal not
/// taken (that stop dies by it); the joiner not announcing its steps (no join step named); a stop
/// that exits without closing (the anchor counts the connect past [`CLOSED_WITHIN`]).
#[test]
#[ignore = "real vox processes, production Argon2id; CI runs it in release"]
fn a_connect_stopped_by_a_signal_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile directory");
        d
    };
    let (anchor_dir, host_dir) = (dir("anchor"), dir("host"));
    let quick = Duration::from_secs(90);
    let service = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the test's service");
    let service_port = service
        .local_addr()
        .expect("APPARATUS: the service's address")
        .port()
        .to_string();

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
    assert!(ok, "PRODUCT (staging): `vox id` (host) failed: {said}");
    let host_fp = said
        .split_whitespace()
        .find(|w| {
            w.len() == 52
                && w.chars()
                    .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        })
        .unwrap_or_else(|| panic!("PRODUCT (staging): no fingerprint in `vox id`: {said}"))
        .to_owned();
    let host = Proc::spawn(
        "host",
        &host_dir,
        &[
            "serve",
            &format!("{service_port}={service_port}"),
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
            .expect("APPARATUS: a line matched by its label strips it")
            .trim()
            .to_owned()
    };
    let (room, address, passphrase) = (field("room"), field("address"), field("passphrase"));
    let room12 = room[..12].to_owned();
    let deadline = Instant::now() + Duration::from_secs(240);
    while board_counts(&anchor, &room12).is_none_or(|(m, _)| m < 1) {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the host's room never showed on the anchor's board with its member.\n\
             ---- the anchor ----\n{}\n---- the host ----\n{}\n{}",
            anchor.stdout().join("\n"),
            host.stdout().join("\n"),
            host.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let _frozen_5 = freeze(daemon_pid_of(&host_dir))
        .unwrap_or_else(|| panic!("APPARATUS: `kill -STOP` the host failed"));

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
        assert!(
            ok,
            "PRODUCT (staging) ({name}): `vox id` (guest) failed: {said}"
        );
        let file = guest.join("room-passphrase");
        std::fs::write(&file, &passphrase).expect("APPARATUS: write the room passphrase file");
        let pending = board_counts(&anchor, &room12).map_or(0, |(_, p)| p);
        let mut connect = Proc::spawn(
            "connect",
            &guest,
            &[
                "connect",
                &address,
                "--passphrase-file",
                file.to_str().expect("APPARATUS: a UTF-8 path"),
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
                    "PRODUCT: {case}: `vox connect` ended ({status}) before it announced itself on the \
                     board, the room's member reachable there.\n--- stdout:\n{}\n--- stderr:\n{}",
                    connect.stdout().join("\n"),
                    connect.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging) ({name}): the guest's announce never showed on the anchor's board, \
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
                "PRODUCT (staging) ({name}): the join ended on its own ({status}) before it could be \
                 stopped mid-way.\n--- stdout:\n{}\n--- stderr:\n{}",
                connect.stdout().join("\n"),
                connect.stderr()
            );
        }
        let peers = peers_connected(&anchor).unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging) ({name}): the anchor never said how many peers it has.\n{}",
                anchor.stdout().join("\n")
            )
        });
        assert!(
            signal(sig, connect.child.id()),
            "APPARATUS ({name}): `kill -{sig}` failed"
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
                    "PRODUCT: {case}: `vox connect` had not ended {STOPS_WITHIN:?} after the signal.\n\
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
            "PRODUCT: {case}: `vox connect` ended only {after:?} after the signal, over {STOPS_WITHIN:?}.\n{}",
            e.describe()
        );
        assert_says_stopped(&e, &case, name, *code);
        let waited = e.waited();
        let step = MEMBER_STEPS.iter().find(|s| waited.starts_with(*s));
        assert!(
            step.is_some_and(|s| waited.starts_with(&format!("{s}{host12}"))),
            "PRODUCT: {case}: it waited in {waited:?}, but a join past its announce into a frozen host \
             waits on that host ({host12}), in one of the join's own steps.\n{}",
            e.describe()
        );
        let gone = gone.unwrap_or_else(|| {
            panic!(
                "PRODUCT: {case}: the anchor still counted {peers} peers {:?} after the signal — the connect \
                 did not close its connection to it.\n---- the anchor ----\n{}",
                CLOSED_WITHIN + Duration::from_secs(30),
                anchor.stdout().join("\n")
            )
        });
        assert!(
            gone < CLOSED_WITHIN,
            "PRODUCT: {case}: the anchor counted the connect gone only {gone:?} after the signal, over \
             {CLOSED_WITHIN:?} — not a close, the silence of one never sent.\n---- the anchor \
             ----\n{}",
            anchor.stdout().join("\n")
        );
        eprintln!("[proof] {name}: said why, waited in {waited:?}");
    }
    drop(service);
    // The host's daemon was suspended for the joins to wait on; resumed, it can be stopped.
    signal("CONT", daemon_pid_of(&host_dir));
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
    /// product: a failure there is APPARATUS.
    fn start(profile: &std::path::Path, room_file: Option<&std::path::Path>) -> Self {
        use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
        let apparatus = |what: &str, e: &dyn std::fmt::Debug| -> ! {
            panic!("APPARATUS: setting up the pty: {what}: {e:?}")
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
        // Nothing dials this address before both prompts are answered: the stop lands first.
        let mut a = vec!["connect".to_owned(), UNREACHABLE_ROOM.to_owned()];
        if let Some(f) = room_file {
            a.push("--passphrase-file".to_owned());
            a.push(f.to_str().expect("APPARATUS: a UTF-8 path").to_owned());
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
                into.lock()
                    .expect("APPARATUS: a lock the proof holds was poisoned")
                    .extend_from_slice(&buf[..n]);
            }
        });
        let (tx, stderr) = std::sync::mpsc::channel();
        let err = child.stderr.take().expect("APPARATUS: the child's stderr");
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
        String::from_utf8_lossy(
            &self
                .shown
                .lock()
                .expect("APPARATUS: a lock the proof holds was poisoned"),
        )
        .into_owned()
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
                    "PRODUCT: `vox connect` ended ({status}) before it showed {prompt:?}. Its terminal:\n\
                     {shown}\n--- stderr:\n{}",
                    self.stderr.try_iter().collect::<Vec<_>>().join("\n")
                );
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: `vox connect` did not show {prompt:?} within {PROMPTS_WITHIN:?}. Its terminal:\n{shown}"
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
                "PRODUCT: `vox connect` had not ended {STOPS_WITHIN:?} after it was due to. It said:\n{}",
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
            .unwrap_or_else(|e| panic!("APPARATUS: reaping vox connect: {e}"));
        let modes = rustix::termios::tcgetattr(&self.terminal)
            .unwrap_or_else(|e| panic!("APPARATUS: reading the terminal's modes: {e}"));
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
        "PRODUCT: {case}: the terminal was left without echo or line editing (local modes {:?}) — the \
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
    assert!(signal(sig, c.child.id()), "APPARATUS: `kill -{sig}` failed");
    let (e, modes) = c.finish();
    let case = format!("{name} at the {prompt:?} prompt");
    assert_says_stopped(&e, &case, name, code);
    assert_eq!(
        e.waited(),
        waited_for,
        "PRODUCT: {case}: it does not say it had waited for {waited_for:?}.\n{}",
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
/// **A red names its side.** APPARATUS: the pty or a `kill` failed. PRODUCT (staging): `vox
/// id` failed. A connect that never shows its prompt, or anything after the stop, is the
/// product's, quoted.
///
/// **Mutations that must turn it red:** the prompts run before the handler is taken (it dies by
/// the signal); the terminal not handed back (still raw); a stop that waits for the runtime's
/// blocking work (a prompt still reading holds the exit past [`STOPS_WITHIN`]).
#[test]
#[ignore = "production Argon2id for the profile's identity; CI runs it in release"]
fn a_connect_stopped_at_a_passphrase_prompt_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let profile = tmp.path().join("guest");
    std::fs::create_dir_all(profile.join("cfg")).expect("APPARATUS: create a profile directory");
    let (ok, said, _) = must(
        "vox id",
        vox(&profile, &["id"], "", Duration::from_secs(90)),
    );
    assert!(ok, "PRODUCT (staging): `vox id` failed: {said}");
    let room_file = tmp.path().join("room-passphrase");
    std::fs::write(&room_file, "a room passphrase")
        .expect("APPARATUS: write the room passphrase file");

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
        "this node's identity passphrase",
    );

    // Ctrl-C typed at the prompt is a key on a raw terminal, not a signal: the prompt's own "no".
    let mut c = OnTerminal::start(&profile, Some(&room_file));
    c.until_prompted("identity passphrase: ");
    Write::write_all(&mut c.keys, b"\x03")
        .unwrap_or_else(|e| panic!("APPARATUS: typing Ctrl-C on the pty: {e}"));
    let (e, modes) = c.finish();
    let case = "Ctrl-C at the identity passphrase prompt";
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            e.status.signal(),
            None,
            "PRODUCT: {case}: died by a signal.\n{}",
            e.describe()
        );
    }
    assert_eq!(
        e.status.code(),
        Some(1),
        "PRODUCT: {case}: exit status\n{}",
        e.describe()
    );
    assert!(
        e.stderr.contains("cancelled"),
        "PRODUCT: {case}: stderr does not say it was cancelled.\n{}",
        e.describe()
    );
    assert_terminal_handed_back(&modes, case, &e);
    eprintln!("[proof] {case}: {}, said it was cancelled", e.status);
    eprintln!("[proof] 3/3 stops at a prompt said why (SIGTERM, SIGHUP, Ctrl-C)");
}

/// Claim 9: a request the daemon ends without a reply is said in its log.
#[test]
#[ignore = "real binary; run in release"]
fn a_request_ended_without_a_reply_is_in_the_daemons_log() {
    use std::os::unix::net::UnixStream;
    watchdog::arm();
    let tmp = tempfile::Builder::new()
        .prefix("vl")
        .tempdir_in(if std::path::Path::new("/private/tmp").is_dir() {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .expect("APPARATUS: a temp dir");
    let dir = tmp.path().join("d");
    let (ok, said, _) = must(
        "vox daemon --detach",
        vox(&dir, &["daemon", "--detach"], "", Duration::from_secs(30)),
    );
    assert!(
        ok,
        "APPARATUS (staging): vox daemon --detach failed: {said}"
    );
    let pid = daemon_pid_of(&dir);
    let log = dir.join(".daemon").join("log");
    let before = std::fs::read_to_string(&log).unwrap_or_default().len();

    // The apparatus client: the daemon's hello read, then a length past any frame it accepts.
    let mut s = UnixStream::connect(dir.join(".daemon").join("vox.sock"))
        .expect("APPARATUS: connect to the daemon's socket");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("APPARATUS: a read timeout");
    let mut len = [0u8; 4];
    s.read_exact(&mut len)
        .expect("APPARATUS: the daemon's hello length");
    let mut hello = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut hello)
        .expect("APPARATUS: the daemon's hello");
    s.write_all(&u32::MAX.to_be_bytes())
        .expect("APPARATUS: write the oversized length");
    let mut rest = Vec::new();
    let replied = s.read_to_end(&mut rest).map(|_| rest.len()).unwrap_or(0);
    assert_eq!(
        replied, 0,
        "APPARATUS (staging): the daemon replied ({replied} bytes) to the oversized frame, so \
         this is not a request ended without a reply"
    );

    let t0 = Instant::now();
    let mut line = String::new();
    while t0.elapsed() < Duration::from_secs(10) {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(l) = text[before.min(text.len())..]
            .lines()
            .find(|l| l.contains("a client's request was ended without a reply"))
        {
            line = l.to_owned();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    signal("TERM", pid);
    println!("[proof] (9) the daemon's log: {line:?}");
    assert!(
        line.starts_with("vox daemon: a client's request was ended without a reply: ")
            && line.contains("ipc frame length"),
        "PRODUCT (9): a request the daemon ended without a reply must be said in its log, with \
         why (a frame longer than it accepts); the log has no such line:\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
}
