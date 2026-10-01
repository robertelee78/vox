//! Shared set-up for the ADR-021 product proofs: an anchor and N workers, **each a real
//! `vox daemon` process** with its own identity, in one room, each trusting every other.
//!
//! Every node is the shipped binary, started as a person starts it — `vox node` for the
//! anchor, `vox daemon` for each worker — and every verb under test is the real `vox`
//! binary as a separate process, exactly as an agent's shell runs it. Nothing here runs a
//! node in this process or calls the CLI's functions (V29-17: a test counts only if it
//! drives the shipped product). The room is built with `vox room create|invite|join` and
//! `vox trust add`, and is ready when every worker has **rendered** a post by every other.
//!
//! Trust is added **after** the joins. Rooms are forward-only (ADR-006): a member reads
//! only what an author sealed after releasing its key to that member, and on this tree a
//! trust added before the join releases the key only on a later tick (F12). Adding it
//! after the join releases the key at once, and the readiness wait keeps posting until
//! each reader renders one — so a proof starts from a room where anyone reads anyone.
//!
//! **Every red here names its side** (V210-106): `PRODUCT:` quoting what `vox` said (stderr
//! included) when it refused, failed or stayed silent; `APPARATUS:` or `CANNOT MEASURE:` naming the
//! fault when it is this harness's or the machine's. A join is asked **once**: a join the product
//! turns away is a product red with its reason, never retried past.

#![allow(dead_code)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::node::paths::Paths;

pub const VOX: &str = env!("CARGO_BIN_EXE_vox");
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// How long a daemon may take to answer after it starts. It unlocks the identity first, which is
/// production Argon2id: measured 6–17s for the unoptimized build on a busy machine (V210-87), and
/// several of those at once went past the 60s this shared with everything else. Not a product
/// bound — nothing a person runs waits on it — so it is sized to never be the thing that fails.
const DAEMON_START_PATIENCE: Duration = Duration::from_secs(240);

const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// Everything a harness might have put in this process's environment that would
/// silently name a session. **This test process may itself be running inside Claude
/// Code or Codex**, and a leaked `CLAUDE_CODE_SESSION_ID` would make every worker the
/// same session — the exact defect these proofs exist to catch.
pub const HARNESS_SESSION_VARS: [&str; 10] = [
    "VOX_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "VOX_ROOM",
    "VOX_AGENT_NAME",
    // The harness's own wake endpoints. `vox agent hook` registers a session at whatever these
    // name, so a proof run from inside a real Claude or OpenCode session registered the REAL
    // session's socket in its temp profile, and an urgent test message then interrupted that
    // live session (2026-09-26: "WEDGE-TEST" reached the coordinator's session). A proof that
    // wants a wake endpoint sets its own.
    "CLAUDE_CODE_MESSAGING_SOCKET",
    "CLAUDE_CODE_MESSAGING_TOKEN",
    "OPENCODE_SERVER_URL",
    "VOX_HARNESS",
];

/// A child process killed and reaped when dropped, by its own handle — never by a name
/// pattern (a path-pattern `pkill` once missed every node and leaked hundreds).
pub struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What one `vox` invocation did.
#[derive(Debug, Clone)]
pub struct Out {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// The exact command, for the receipt.
    pub argv: String,
}

impl Out {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("PRODUCT: vox printed not one JSON object ({e}): {self:?}"))
    }
    pub fn ndjson(&self) -> Vec<serde_json::Value> {
        self.stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l).unwrap_or_else(|e| {
                    panic!("PRODUCT: vox printed a bad NDJSON line ({e}): {l}\nall of it: {self:?}")
                })
            })
            .collect()
    }

    /// Assert this invocation succeeded, or a `PRODUCT:` red naming `what` and quoting it.
    #[track_caller]
    pub fn expect_ok(&self, what: &str) -> &Self {
        assert!(
            self.ok,
            "PRODUCT: {what} failed (exit {:?}).\n$ {}\nstdout:\n{}\nstderr:\n{}",
            self.code,
            self.argv,
            self.stdout.trim(),
            self.stderr.trim()
        );
        self
    }
}

/// `p` as UTF-8, for an argument; a temp path that is not is the apparatus's fault.
fn utf8(p: &std::path::Path) -> &str {
    p.to_str()
        .unwrap_or_else(|| panic!("APPARATUS: the path {} is not UTF-8", p.display()))
}

/// A file's text for a red, or why it could not be read — never an empty string standing in for
/// a transcript that was lost.
fn read_log(p: &std::path::Path) -> String {
    std::fs::read_to_string(p)
        .unwrap_or_else(|e| format!("(APPARATUS: could not read {}: {e})", p.display()))
}

/// One worker: a `vox daemon` process, its identity, and the profile directories the
/// binary reads.
pub struct Worker {
    pub name: String,
    pub data: std::path::PathBuf,
    pub cfg: std::path::PathBuf,
    pub paths: Paths,
    pub fp: [u8; 32],
    /// The identity passphrase file the daemon was unlocked with.
    pub pass: std::path::PathBuf,
    daemon: Option<Proc>,
}

impl Worker {
    /// The pid of this worker's `vox daemon`, while it runs.
    #[allow(dead_code)] // not every proof that includes this support module measures it
    pub fn daemon_pid(&self) -> Option<u32> {
        self.daemon.as_ref().map(|p| p.0.id())
    }

    /// Run `vox …` as `session` of this worker (or with no session at all).
    pub fn vox(&self, session: Option<&str>, args: &[&str]) -> Out {
        self.vox_in(session, args, None)
    }

    /// As [`Worker::vox`], with `stdin`.
    pub fn vox_in(&self, session: Option<&str>, args: &[&str], stdin: Option<&str>) -> Out {
        self.vox_bin(VOX, session, args, stdin)
    }

    /// As [`Worker::vox_in`], with extra environment — for what a harness sets beside
    /// the session, such as `VOX_AGENT_NAME`.
    pub fn vox_env(
        &self,
        session: Option<&str>,
        env: &[(&str, &str)],
        args: &[&str],
        stdin: Option<&str>,
    ) -> Out {
        self.vox_bin_env(VOX, session, env, args, stdin)
    }

    /// Run a given `vox` binary — the one under test, or a published release — as this
    /// worker.
    pub fn vox_bin(
        &self,
        bin: &str,
        session: Option<&str>,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Out {
        self.vox_bin_env(bin, session, &[], args, stdin)
    }

    fn vox_bin_env(
        &self,
        bin: &str,
        session: Option<&str>,
        env: &[(&str, &str)],
        args: &[&str],
        stdin: Option<&str>,
    ) -> Out {
        use std::io::Write as _;
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for v in HARNESS_SESSION_VARS {
            cmd.env_remove(v);
        }
        if let Some(s) = session {
            cmd.env("VOX_SESSION", s);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {bin} {args:?}: {e}"));
        if let Some(input) = stdin {
            // A `vox` that exits without reading its stdin closes the pipe: what it said and its
            // exit status, below, are the verdict, so a refused write is reported, not fatal.
            if let Err(e) = child
                .stdin
                .take()
                .expect("APPARATUS: a piped stdin")
                .write_all(input.as_bytes())
            {
                eprintln!("[harness] {}: stdin not taken: {e}", self.name);
            }
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not wait for {bin} {args:?}: {e}"));
        let o = Out {
            ok: out.status.success(),
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            argv: format!(
                "{}VOX_DATA_DIR=<{}> {bin} {}",
                session
                    .map(|s| format!("VOX_SESSION={s} "))
                    .unwrap_or_default(),
                self.name,
                args.join(" ")
            ),
        };
        // Receipts (ADR-018 §1): the exact command, its exit status and its output.
        eprintln!(
            "[receipt] {} -> exit {:?}\n  stdout: {}\n  stderr: {}",
            o.argv,
            o.code,
            o.stdout.trim(),
            o.stderr.trim()
        );
        o
    }

    pub fn b32(&self) -> String {
        vox_core::node::link::b32_encode(&self.fp)
    }
}

/// A room shared by every worker, and the processes that serve it. Dropping it kills
/// the daemons and the anchor.
pub struct Room {
    pub workers: Vec<Worker>,
    pub id: String,
    pub cid: [u8; 32],
    _anchor: Proc,
    anchor: String,
    tmp: std::path::PathBuf,
}

impl Room {
    /// Restart worker `i`'s daemon as an operator does after a crash: killed (SIGKILL) and
    /// reaped by its own PID, then `vox daemon` again with the identity passphrase alone, which
    /// reopens every room it held (#208). Returns once this room reads on that node again.
    pub fn restart(&mut self, i: usize) {
        let w = &mut self.workers[i];
        w.daemon = None;
        let err = self.tmp.join(format!("{}.daemon.restart.err", w.name));
        start_daemon(w, &self.anchor, &err);
        let deadline = Instant::now() + TIMEOUT;
        while !w.vox(None, &["room", "read", &self.id]).ok {
            assert!(
                Instant::now() < deadline,
                "PRODUCT: {}'s restarted daemon answers but never reopened the room in {}s; its \
                 stderr:\n{}",
                w.name,
                TIMEOUT.as_secs(),
                std::fs::read_to_string(&err).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl Room {
    /// The anchor's pid, for a proof that must stop it: it holds the room's entries too, and
    /// would otherwise serve a stopped member's posts to the others.
    pub fn anchor_pid(&self) -> u32 {
        self._anchor.0.id()
    }
}

/// A file to send a child's output to, or an `APPARATUS:` red naming it.
fn log_file(p: &std::path::Path) -> Stdio {
    Stdio::from(
        std::fs::File::create(p)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", p.display())),
    )
}

fn mkdir(d: &std::path::Path) {
    std::fs::create_dir_all(d)
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
}

/// A poll loop's own clock: how many times it looked, and the longest one look took. A deadline
/// that passed after fewer than [`MIN_LOOKS`] looks did not give the product its chances — the
/// harness or the machine was too slow to ask — so it is `CANNOT MEASURE`, not a product red.
struct Looks {
    t0: Instant,
    n: u32,
    slowest: Duration,
    last: Instant,
}

/// Fewer looks than this before a deadline means the harness, not the product, ran out of time.
const MIN_LOOKS: u32 = 5;

impl Looks {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            t0: now,
            n: 0,
            slowest: Duration::ZERO,
            last: now,
        }
    }

    /// Count one look, which ended now.
    fn looked(&mut self) {
        self.n += 1;
        self.slowest = self.slowest.max(self.last.elapsed());
        self.last = Instant::now();
    }

    /// The side a deadline that passed belongs to, and what the clock saw.
    fn side(&self) -> (&'static str, String) {
        let seen = format!(
            "{} look(s) in {:?}, the slowest {:?}",
            self.n,
            self.t0.elapsed(),
            self.slowest
        );
        if self.n < MIN_LOOKS {
            ("CANNOT MEASURE: the harness was too slow to look", seen)
        } else {
            ("PRODUCT:", seen)
        }
    }
}

fn spawn_anchor(tmp: &std::path::Path) -> (Proc, String) {
    let (data, cfg) = (tmp.join("anchor/data"), tmp.join("anchor/cfg"));
    mkdir(&cfg);
    let (out, err) = (tmp.join("anchor.out"), tmp.join("anchor.err"));
    let mut anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &data)
            .env("VOX_CONFIG_DIR", &cfg)
            .stdout(log_file(&out))
            .stderr(log_file(&err))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} node: {e}")),
    );
    let mut looks = Looks::new();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(spec) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (anchor, spec.to_owned());
        }
        looks.looked();
        let exited = anchor.0.try_wait().ok().flatten();
        if exited.is_some() || Instant::now() >= deadline {
            let (side, seen) = looks.side();
            let side = if exited.is_some() { "PRODUCT:" } else { side };
            panic!(
                "{side} the anchor (`vox node`) printed no --anchor spec in {:?} ({}; {seen}).\n\
                 stdout:\n{}\nstderr:\n{}",
                looks.t0.elapsed(),
                exited.map_or_else(|| "still running".to_owned(), |s| format!("it exited: {s}")),
                read_log(&out),
                read_log(&err)
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn worker(tmp: &std::path::Path, name: &str) -> Worker {
    let data = tmp.join(name).join("data");
    let cfg = tmp.join(name).join("cfg");
    mkdir(&cfg);
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS)
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass.display()));
    let paths = Paths::resolve("default", Some(&data), Some(&cfg))
        .unwrap_or_else(|e| panic!("APPARATUS: no profile paths under {}: {e}", data.display()));
    let mut w = Worker {
        name: name.to_owned(),
        data,
        cfg,
        paths,
        fp: [0; 32],
        pass,
        daemon: None,
    };
    // `vox id` creates the identity on first use and prints its fingerprint.
    let o = w.vox(None, &["id", "--identity-passphrase-file", utf8(&w.pass)]);
    o.expect_ok(&format!("{name}'s `vox id`"));
    let fp = vox_core::node::link::b32_decode(o.stdout.trim(), "fingerprint").unwrap_or_else(|e| {
        panic!("PRODUCT: {name}'s `vox id` printed no fingerprint ({e:?}): {o:?}")
    });
    w.fp = fp;
    w
}

fn start_daemon(w: &mut Worker, anchor: &str, err: &std::path::Path) {
    let child = Command::new(VOX)
        .args([
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            anchor,
            "--passphrase-file",
        ])
        .arg(&w.pass)
        .env("VOX_DATA_DIR", &w.data)
        .env("VOX_CONFIG_DIR", &w.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file(err))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} daemon: {e}"));
    w.daemon = Some(Proc(child));
    let started = Instant::now();
    let deadline = started + DAEMON_START_PATIENCE;
    let mut looks = Looks::new();
    loop {
        let o = w.vox(None, &["room", "list"]);
        looks.looked();
        if o.ok {
            break;
        }
        let exited = w
            .daemon
            .as_mut()
            .and_then(|d| d.0.try_wait().ok().flatten());
        if exited.is_some() || Instant::now() >= deadline {
            let (side, seen) = looks.side();
            let side = if exited.is_some() { "PRODUCT:" } else { side };
            panic!(
                "{side} {}'s daemon never answered `vox room list` in {:?} \
                 ({}; {seen}). The last answer: {o:?}\nIts stderr:\n{}",
                w.name,
                started.elapsed(),
                exited.map_or_else(|| "still running".to_owned(), |s| format!("it exited: {s}")),
                read_log(err)
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "[harness] {}'s daemon answered in {:.1}s",
        w.name,
        started.elapsed().as_secs_f64()
    );
}

/// Build `names.len()` workers in one room: an anchor, a daemon per worker, the first
/// creating the room and the rest joining it, every worker trusting every other. Ready
/// when every worker has rendered a post by every other.
pub async fn room(tmp: &std::path::Path, names: &[&str]) -> Room {
    let (anchor, spec) = spawn_anchor(tmp);
    let mut workers: Vec<Worker> = names.iter().map(|n| worker(tmp, n)).collect();
    for w in &mut workers {
        let err = tmp.join(format!("{}.daemon.err", w.name));
        start_daemon(w, &spec, &err);
    }

    let first = &workers[0];
    first
        .vox_in(
            None,
            &["room", "create", "--name", "mission"],
            Some(ROOM_PASS),
        )
        .expect_ok("`vox room create`");
    let list = first.vox(None, &["room", "list"]);
    let id = list
        .expect_ok("`vox room list`")
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` does not list the new room: {list:?}"))
        .to_owned();
    let invite = first.vox(None, &["room", "invite", &id]);
    let link = invite
        .expect_ok("`vox room invite`")
        .stdout
        .trim()
        .to_owned();
    let host_err = tmp.join(format!("{}.daemon.err", workers[0].name));
    for w in &workers[1..] {
        // Asked once. A join turned away — even while the host is busy admitting another
        // joiner — is the product's to answer for, with its reason and the host's own report
        // (`a join did not complete — answering …: <reason>`); a retry would hide it.
        let t = Instant::now();
        let o = w.vox_in(
            None,
            &["room", "join", &link, "--name", "mission"],
            Some(ROOM_PASS),
        );
        assert!(
            o.ok,
            "PRODUCT: {} could not join the room: `vox room join` was refused after {:?} \
             (exit {:?}).\nstdout:\n{}\nstderr:\n{}\nthe host {}'s daemon stderr:\n{}",
            w.name,
            t.elapsed(),
            o.code,
            o.stdout.trim(),
            o.stderr.trim(),
            workers[0].name,
            read_log(&host_err)
        );
    }

    // Trust after the joins (see the module note), each worker trusting every other.
    for a in &workers {
        for b in &workers {
            if a.fp != b.fp {
                let o = a.vox(
                    None,
                    &[
                        "trust",
                        "add",
                        &b.b32(),
                        "--name",
                        &b.name,
                        "--identity-passphrase-file",
                        utf8(&a.pass),
                    ],
                );
                o.expect_ok(&format!("{}'s `vox trust add` of {}", a.name, b.name));
            }
        }
    }

    // Ready when every reader has rendered a post by every author. Forward-only means an
    // early post can stay unreadable forever, so each author keeps posting fresh ones.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut owed: Vec<(usize, usize)> = (0..workers.len())
        .flat_map(|a| {
            (0..workers.len())
                .filter(move |r| *r != a)
                .map(move |r| (a, r))
        })
        .collect();
    let mut n = 0u32;
    let mut looks = Looks::new();
    while !owed.is_empty() {
        if Instant::now() >= deadline {
            let (side, seen) = looks.side();
            let last: Vec<String> = owed
                .iter()
                .map(|(_, r)| {
                    let o = workers[*r].vox(None, &["room", "read", &id]);
                    format!(
                        "{} reads:\n{}\n{}",
                        workers[*r].name,
                        o.stdout.trim(),
                        o.stderr.trim()
                    )
                })
                .collect();
            panic!(
                "{side} the room never became readable both ways in 120s ({seen}): members who \
                 trust each other still owe (author, reader) {:?}.\n{}",
                owed.iter()
                    .map(|(a, r)| (workers[*a].name.clone(), workers[*r].name.clone()))
                    .collect::<Vec<_>>(),
                last.join("\n")
            );
        }
        n += 1;
        for (a, author) in workers.iter().enumerate() {
            if owed.iter().any(|(x, _)| *x == a) {
                let o = author.vox(
                    None,
                    &[
                        "room",
                        "post",
                        &id,
                        &format!("harness: ready {} {n}", author.name),
                    ],
                );
                o.expect_ok(&format!("{}'s `vox room post`", author.name));
            }
        }
        std::thread::sleep(Duration::from_secs(1));
        owed.retain(|(a, r)| {
            let seen = workers[*r].vox(None, &["room", "read", &id]);
            seen.expect_ok(&format!("{}'s `vox room read`", workers[*r].name));
            !seen
                .stdout
                .contains(&format!("harness: ready {} ", workers[*a].name))
        });
        looks.looked();
    }

    // `vox room list` prints a prefix; every `read --json` row names the room in full.
    let read = workers[0].vox(None, &["room", "read", &id, "--json"]);
    let rows = read.expect_ok("`vox room read --json`").ndjson();
    let full = rows
        .first()
        .and_then(|r| r["room"].as_str())
        .unwrap_or_else(|| {
            panic!("PRODUCT: a readable room's `read --json` names no room: {read:?}")
        })
        .to_owned();
    let cid = vox_core::node::link::b32_decode(&full, "room id")
        .unwrap_or_else(|e| panic!("PRODUCT: `read --json` names the room {full:?}: {e:?}"));
    Room {
        id: full,
        cid,
        workers,
        _anchor: anchor,
        anchor: spec,
        tmp: tmp.to_path_buf(),
    }
}

/// Poll a `vox` invocation until its output satisfies `ok`, or fail naming what it
/// last said. Something posted on one node reaches another through the log, so "has
/// it arrived yet" has no synchronous answer.
///
/// **One verdict names its side**: `vox` giving no answer at all (killed, no exit status) is
/// APPARATUS; a deadline that passed after fewer than [`MIN_LOOKS`] looks is CANNOT MEASURE
/// (the harness was too slow to ask); otherwise `vox` refusing (a non-zero exit) or answering
/// without what was awaited is PRODUCT, quoting the last answer.
pub fn until(
    w: &Worker,
    session: Option<&str>,
    what: &str,
    args: &[&str],
    ok: impl Fn(&Out) -> bool,
) -> Out {
    let deadline = Instant::now() + TIMEOUT;
    let mut last = None;
    let mut looks = Looks::new();
    while Instant::now() < deadline {
        let o = w.vox(session, args);
        looks.looked();
        if ok(&o) {
            return o;
        }
        last = Some(o);
        std::thread::sleep(Duration::from_millis(250));
    }
    let secs = TIMEOUT.as_secs();
    let (side, seen) = looks.side();
    match last {
        Some(o) if o.code.is_none() => panic!(
            "APPARATUS (no answer): waiting {secs}s for {what}, `{}` never exited with a \
             status ({seen}): {o:?}",
            o.argv
        ),
        // Too few looks to have given the product its chances: the harness's clock, not vox.
        Some(o) if side != "PRODUCT:" => {
            panic!("{side}: waiting {secs}s for {what} ({seen}); the last answer: {o:?}")
        }
        Some(o) if !o.ok => panic!(
            "PRODUCT: waiting {secs}s for {what}, vox refused `{}` (exit {}): {}\nlast saw \
             {o:?} ({seen})",
            o.argv,
            o.code.unwrap_or_default(),
            o.stderr.trim()
        ),
        Some(o) => panic!(
            "PRODUCT: waiting {secs}s for {what}, vox answered `{}` without it ({seen}): {o:?}",
            o.argv
        ),
        None => panic!("APPARATUS: waiting for {what}, the deadline passed before one try"),
    }
}

/// A resource's entry in a `vox.room.board/1` object, if it has one.
pub fn resource<'a>(board: &'a serde_json::Value, r: &str) -> Option<&'a serde_json::Value> {
    board["resources"]
        .as_array()?
        .iter()
        .find(|x| x["resource"] == r)
}

/// Post raw text straight onto the control socket, as a peer speaking the protocol
/// does — for writing exactly what another, older or foreign, binary would write.
pub async fn post_raw(w: &Worker, cid: [u8; 32], text: &str) {
    let mut c = vox_core::node::ipc::IpcClient::open(&w.paths.socket_file())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "CANNOT MEASURE: the harness could not open {}'s control socket: {e}",
                w.name
            )
        });
    match c
        .request(&vox_core::node::ipc::Request::Post {
            channel_id: cid,
            text: text.to_owned(),
        })
        .await
    {
        Ok(vox_core::node::ipc::Frame::Ok) => {}
        Ok(other) => panic!("PRODUCT: {}'s daemon refused a raw post: {other:?}", w.name),
        Err(e) => panic!(
            "CANNOT MEASURE: the harness's raw post to {}'s control socket failed: {e}",
            w.name
        ),
    }
}

/// Put a recording `vox` at `bin_dir/vox` for a model's shell: it runs the real binary and
/// appends to `log` a `call` line before and an `exit` line (status and stderr) after every
/// command. **It is what tells a product red from an apparatus red** in a live-model proof:
/// a command the model never ran is the apparatus, a command `vox` refused is the product,
/// and only a command `vox` accepted can be waited for. The plugin calls `VOX_BIN` directly,
/// so only the model's own commands land here.
pub fn model_shim(bin_dir: &std::path::Path, log: &std::path::Path) {
    let shim = bin_dir.join("vox");
    let _ = std::fs::remove_file(&shim);
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\n\
             printf 'call\\t%s\\n' \"$*\" >> '{log}'\n\
             err=$(mktemp \"${{TMPDIR:-/tmp}}/vox-shim.XXXXXX\")\n\
             '{vox}' \"$@\" 2>\"$err\"\n\
             rc=$?\n\
             cat \"$err\" >&2\n\
             printf 'exit\\t%s\\t%s\\t%s\\n' \"$rc\" \"$*\" \"$(tr '\\n\\t' '  ' < \"$err\")\" >> '{log}'\n\
             rm -f \"$err\"\n\
             exit $rc\n",
            log = log.display(),
            vox = VOX
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

/// One command a model's shell ran through [`model_shim`].
#[derive(Debug, Clone)]
pub struct ModelCall {
    pub args: String,
    /// `vox`'s exit status and stderr; `None` when it never returned.
    pub exit: Option<(i32, String)>,
}

/// Every command in a [`model_shim`] log, each paired with its own exit.
pub fn model_calls(log: &std::path::Path) -> Vec<ModelCall> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let mut calls: Vec<ModelCall> = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.splitn(4, '\t').collect();
        match f.as_slice() {
            ["call", args] => calls.push(ModelCall {
                args: (*args).to_owned(),
                exit: None,
            }),
            ["exit", rc, args, err] => {
                if let Some(c) = calls
                    .iter_mut()
                    .find(|c| c.exit.is_none() && c.args == *args)
                {
                    c.exit = Some((rc.parse().unwrap_or(-1), err.trim().to_owned()));
                }
            }
            _ => {}
        }
    }
    calls
}

/// Judge a model's run of one `vox` command, found in `log` by `matches`: **vox refusing it
/// is a PRODUCT red quoting the refusal**, and vox never returning is one too. Returns
/// `false` when the model never ran it — the apparatus, which the caller names.
pub fn vox_accepted(
    log: &std::path::Path,
    who: &str,
    what: &str,
    matches: impl Fn(&str) -> bool,
) -> bool {
    let calls = model_calls(log);
    let Some(c) = calls.iter().find(|c| matches(&c.args)) else {
        return false;
    };
    match &c.exit {
        Some((0, _)) => true,
        Some((rc, err)) => panic!(
            "PRODUCT: vox refused {who}'s {what} (`vox {}`), exit {rc}: {err}",
            c.args
        ),
        None => panic!(
            "PRODUCT: {who}'s {what} (`vox {}`) never returned before the model's turn ended",
            c.args
        ),
    }
}

/// [`until`] for something `vox` already accepted with exit 0, which the red says.
pub fn arrives(w: &Worker, what: &str, args: &[&str], ok: impl Fn(&Out) -> bool) -> Out {
    until(
        w,
        None,
        &format!("{what}, which vox accepted with exit 0"),
        args,
        ok,
    )
}
