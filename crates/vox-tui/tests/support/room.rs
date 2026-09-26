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

#![allow(dead_code)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::node::paths::Paths;

pub const VOX: &str = env!("CARGO_BIN_EXE_vox");
pub const TIMEOUT: Duration = Duration::from_secs(60);

const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// Everything a harness might have put in this process's environment that would
/// silently name a session. **This test process may itself be running inside Claude
/// Code or Codex**, and a leaked `CLAUDE_CODE_SESSION_ID` would make every worker the
/// same session — the exact defect these proofs exist to catch.
pub const HARNESS_SESSION_VARS: [&str; 6] = [
    "VOX_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "VOX_ROOM",
    "VOX_AGENT_NAME",
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
            .unwrap_or_else(|e| panic!("not one JSON object ({e}): {self:?}"))
    }
    pub fn ndjson(&self) -> Vec<serde_json::Value> {
        self.stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l).unwrap_or_else(|e| panic!("bad NDJSON line ({e}): {l}"))
            })
            .collect()
    }
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
        let mut child = cmd.spawn().expect("spawn vox");
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().expect("vox ran");
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
}

fn spawn_anchor(tmp: &std::path::Path) -> (Proc, String) {
    let (data, cfg) = (tmp.join("anchor/data"), tmp.join("anchor/cfg"));
    std::fs::create_dir_all(&cfg).unwrap();
    let out = tmp.join("anchor.out");
    let anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &data)
            .env("VOX_CONFIG_DIR", &cfg)
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vox node"),
    );
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(spec) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (anchor, spec.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn worker(tmp: &std::path::Path, name: &str) -> Worker {
    let data = tmp.join(name).join("data");
    let cfg = tmp.join(name).join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).unwrap();
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();
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
    let o = w.vox(
        None,
        &["id", "--identity-passphrase-file", w.pass.to_str().unwrap()],
    );
    assert!(o.ok, "{name}: vox id: {o:?}");
    let fp = vox_core::node::link::b32_decode(o.stdout.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("{name}: vox id printed no fingerprint ({e:?}): {o:?}"));
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
        .stderr(Stdio::from(std::fs::File::create(err).unwrap()))
        .spawn()
        .expect("spawn vox daemon");
    w.daemon = Some(Proc(child));
    let deadline = Instant::now() + TIMEOUT;
    while !w.vox(None, &["room", "list"]).ok {
        assert!(
            Instant::now() < deadline,
            "{}'s daemon never answered",
            w.name
        );
        std::thread::sleep(Duration::from_millis(500));
    }
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
    let o = first.vox_in(
        None,
        &["room", "create", "--name", "mission"],
        Some(ROOM_PASS),
    );
    assert!(o.ok, "room create: {o:?}");
    let id = first
        .vox(None, &["room", "list"])
        .stdout
        .split_whitespace()
        .next()
        .expect("the new room in `vox room list`")
        .to_owned();
    let link = first
        .vox(None, &["room", "invite", &id])
        .stdout
        .trim()
        .to_owned();
    for w in &workers[1..] {
        // A join can be turned away while the host is busy admitting another joiner — a
        // known, separate defect. Retry, bounded, and say so in the receipt.
        let joined = (1..=6).any(|attempt| {
            let o = w.vox_in(
                None,
                &["room", "join", &link, "--name", "mission"],
                Some(ROOM_PASS),
            );
            if !o.ok {
                eprintln!(
                    "[harness] {} join attempt {attempt} refused; retrying",
                    w.name
                );
                std::thread::sleep(Duration::from_secs(5));
            }
            o.ok
        });
        assert!(joined, "{} could not join the room", w.name);
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
                        a.pass.to_str().unwrap(),
                    ],
                );
                assert!(o.ok, "{} trusts {}: {o:?}", a.name, b.name);
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
    while !owed.is_empty() {
        assert!(
            Instant::now() < deadline,
            "the room never became readable both ways: owed (author, reader) {:?}",
            owed.iter()
                .map(|(a, r)| (workers[*a].name.clone(), workers[*r].name.clone()))
                .collect::<Vec<_>>()
        );
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
                assert!(o.ok, "{o:?}");
            }
        }
        std::thread::sleep(Duration::from_secs(1));
        owed.retain(|(a, r)| {
            let seen = workers[*r].vox(None, &["room", "read", &id]).stdout;
            !seen.contains(&format!("harness: ready {} ", workers[*a].name))
        });
    }

    // `vox room list` prints a prefix; every `read --json` row names the room in full.
    let rows = workers[0]
        .vox(None, &["room", "read", &id, "--json"])
        .ndjson();
    let full = rows
        .first()
        .and_then(|r| r["room"].as_str())
        .expect("a readable room names itself in full")
        .to_owned();
    let cid = vox_core::node::link::b32_decode(&full, "room id").expect("a room id");
    Room {
        id: full,
        cid,
        workers,
        _anchor: anchor,
    }
}

/// Poll a `vox` invocation until its output satisfies `ok`, or fail naming what it
/// last said. Something posted on one node reaches another through the log, so "has
/// it arrived yet" has no synchronous answer.
pub fn until(
    w: &Worker,
    session: Option<&str>,
    what: &str,
    args: &[&str],
    ok: impl Fn(&Out) -> bool,
) -> Out {
    let deadline = Instant::now() + TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        let o = w.vox(session, args);
        if ok(&o) {
            return o;
        }
        last = Some(o);
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; last saw {last:?}");
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
        .expect("socket");
    match c
        .request(&vox_core::node::ipc::Request::Post {
            channel_id: cid,
            text: text.to_owned(),
        })
        .await
    {
        Ok(vox_core::node::ipc::Frame::Ok) => {}
        other => panic!("raw post refused: {other:?}"),
    }
}
