//! The shared staging for ADR-025's sync proofs: real `vox daemon`s (and, where the proof wants
//! one, a real `vox node` anchor), trusted to each other, in rooms made and joined through the
//! CLI, with:
//!
//! - a **reader** on a member's own control socket, which reads a room exactly as `vox room read`
//!   does, so a proof can time when a post became readable without spawning a process per poll;
//! - the member's **sync counters**, read through the shipped `vox status --json`.
//!
//! Nothing here starts a node in-process. Included with `#[path]`, which is why not every item is
//! used by every includer.
//!
//! **Every red here names its side** (V210-106): `PRODUCT:` quoting what `vox` said when it
//! refused, failed or stayed silent; `APPARATUS:` or `CANNOT MEASURE:` naming the fault when it is
//! this harness's or the machine's. A join is asked once — a refused join is the product's red,
//! never retried past — and a read that fails is a red, never an empty room.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::ipc::{Frame, IpcClient};

pub const VOX: &str = env!("CARGO_BIN_EXE_vox");
pub const ID_PASS: &str = "an identity passphrase";
pub const ROOM_PASS: &str = "the room passphrase";

/// A child process killed by its own PID however the proof ends, its output kept.
pub struct Proc {
    pub child: Child,
    pub said: Arc<Mutex<String>>,
}

impl Proc {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Send `sig` (`-STOP`, `-CONT`) to this process, by PID. A signal that does not take is
    /// `APPARATUS:` — whatever the proof stages with it did not happen.
    pub fn signal(&self, sig: &str) {
        let pid = self.pid().to_string();
        match Command::new("kill").args([sig, &pid]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => panic!(
                "APPARATUS: `kill {sig} {pid}` did not take ({}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => panic!("APPARATUS: could not run `kill {sig} {pid}`: {e}"),
        }
    }

    pub fn transcript(&self) -> String {
        self.said
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// How the process ended, for a red: its exit status, or that it still runs.
    pub fn state(&mut self) -> String {
        match self.child.try_wait() {
            Ok(Some(status)) => format!("it exited: {status}"),
            Ok(None) => "still running".to_owned(),
            Err(e) => format!("its state is unreadable: {e}"),
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn drain(child: &mut Child) -> Arc<Mutex<String>> {
    let said = Arc::new(Mutex::new(String::new()));
    let out = child.stdout.take();
    let err = child.stderr.take();
    if let Some(out) = out {
        let sink = Arc::clone(&said);
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let mut s = sink
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.push_str(&line);
                s.push('\n');
            }
        });
    }
    if let Some(err) = err {
        let sink = Arc::clone(&said);
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let mut s = sink
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.push_str("! ");
                s.push_str(&line);
                s.push('\n');
            }
        });
    }
    said
}

/// A real `vox node` anchor on loopback, and its `--anchor` spec.
pub fn anchor(root: &Path) -> (Proc, String) {
    let dir = root.join("anchor");
    mkdir(&dir.join("cfg"));
    let mut child = Command::new(VOX)
        .args(["node", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} node: {e}"));
    let said = drain(&mut child);
    let mut p = Proc { child, said };
    let patience = Duration::from_secs(90);
    let mut looks = Looks::new();
    loop {
        let text = p.transcript();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (p, s.to_owned());
        }
        looks.looked();
        let state = p.state();
        if !state.starts_with("still") || looks.t0.elapsed() >= patience {
            let (side, seen) = looks.side();
            let side = if state.starts_with("still") {
                side
            } else {
                "PRODUCT:"
            };
            panic!(
                "{side} the anchor (`vox node`) printed no --anchor spec in {:?} ({state}; \
                 {seen}). It said:\n{}",
                looks.t0.elapsed(),
                p.transcript()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn mkdir(d: &Path) {
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

/// One person: a profile, its identity passphrase file, and its fingerprint.
pub struct Member {
    pub name: &'static str,
    pub dir: PathBuf,
    pub pass: PathBuf,
    pub fp: String,
}

impl Member {
    pub fn new(root: &Path, name: &'static str) -> Self {
        let dir = root.join(name);
        mkdir(&dir.join("cfg"));
        let pass = root.join(format!("{name}.pass"));
        std::fs::write(&pass, ID_PASS)
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass.display()));
        let mut m = Self {
            name,
            dir,
            pass,
            fp: String::new(),
        };
        let (ok, out, err) = m.vox(&["id"], None);
        assert!(
            ok && out.trim().len() == 52,
            "PRODUCT (staging): {name}'s `vox id` printed no fingerprint (exit ok: {ok}).\nstdout:\n{out}\nstderr:\n{err}"
        );
        m.fp = out.trim().to_owned();
        m
    }

    /// Run a one-shot `vox` verb as this member.
    pub fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.dir)
            .env("VOX_CONFIG_DIR", self.dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", ID_PASS)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .env_remove("VOX_SESSION")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("CODEX_THREAD_ID")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} {args:?}: {e}"));
        if let Some(s) = stdin {
            // A `vox` that exits without reading its stdin closes the pipe: its exit status and
            // what it said are the verdict, so a refused write is reported, not fatal.
            if let Err(e) = child
                .stdin
                .take()
                .expect("APPARATUS: a piped stdin")
                .write_all(s.as_bytes())
            {
                eprintln!("[harness] {}: stdin not taken: {e}", self.name);
            }
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not wait for {VOX} {args:?}: {e}"));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    pub fn trust(&self, other: &Member) {
        let (ok, out, err) = self.vox(&["trust", "add", &other.fp, "--name", other.name], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox trust add` of {} failed.\nstdout:\n{out}\nstderr:\n{err}",
            self.name, other.name
        );
    }

    /// Start this member's daemon, optionally behind `anchor`, and wait until it answers.
    pub fn daemon(&self, anchor: Option<&str>) -> Proc {
        self.daemon_bin(VOX, anchor)
    }

    /// [`Member::daemon`], running the daemon from another build of `vox` (a mutant sender that
    /// plays a faulty peer, for the proofs that need one).
    pub fn daemon_bin(&self, bin: &str, anchor: Option<&str>) -> Proc {
        self.daemon_env(bin, anchor, &[])
    }

    /// [`Member::daemon`] from the mutant sender build `bin` (see [`mutant_sender`]), misbehaving
    /// as `mode` (`serve-nothing`, `serve-unasked`). Check [`announced`] once it has synced.
    pub fn daemon_mutant(&self, bin: &str, mode: &str, anchor: Option<&str>) -> Proc {
        self.daemon_env(bin, anchor, &[("VOX_MUTANT_SENDER_MODE", mode)])
    }

    fn daemon_env(&self, bin: &str, anchor: Option<&str>, env: &[(&str, &str)]) -> Proc {
        let mut argv = vec!["daemon", "--listen", "127.0.0.1:0"];
        if let Some(a) = anchor {
            argv.extend(["--anchor", a]);
        }
        let pass = self
            .pass
            .to_str()
            .unwrap_or_else(|| panic!("APPARATUS: {} is not UTF-8", self.pass.display()))
            .to_owned();
        argv.extend(["--passphrase-file", &pass]);
        let mut child = Command::new(bin)
            .args(&argv)
            .env("VOX_DATA_DIR", &self.dir)
            .env("VOX_CONFIG_DIR", self.dir.join("cfg"))
            .env_remove("VOX_ROOM")
            .env_remove("VOX_MUTANT_SENDER_MODE")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {bin} daemon: {e}"));
        let said = drain(&mut child);
        let mut p = Proc { child, said };
        let patience = Duration::from_secs(90);
        let mut looks = Looks::new();
        loop {
            let (ok, out, err) = self.vox(&["room", "list"], None);
            looks.looked();
            if ok {
                return p;
            }
            let state = p.state();
            if !state.starts_with("still") || looks.t0.elapsed() >= patience {
                let (side, seen) = looks.side();
                let side = if state.starts_with("still") {
                    side
                } else {
                    "PRODUCT:"
                };
                panic!(
                    "{side} {}'s daemon never answered `vox room list` in {:?} ({state}; \
                     {seen}). The last answer:\n{out}{err}\nThe daemon said:\n{}",
                    self.name,
                    looks.t0.elapsed(),
                    p.transcript()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Create a room and return its id as `vox room list` prints it.
    pub fn create(&self, name: &str) -> String {
        let (ok, out, err) = self.vox(&["room", "create", "--name", name], Some(ROOM_PASS));
        assert!(
            ok,
            "PRODUCT: {}'s `vox room create` of {name} failed.\nstdout:\n{out}\nstderr:\n{err}",
            self.name
        );
        let (ok, list, err) = self.vox(&["room", "list"], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox room list` failed.\nstdout:\n{list}\nstderr:\n{err}",
            self.name
        );
        list.lines()
            .find(|l| l.split_whitespace().any(|w| w == name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("PRODUCT: `vox room list` does not list room {name}: {list}"))
            .to_owned()
    }

    pub fn invite(&self, room: &str) -> String {
        let (ok, link, err) = self.vox(&["room", "invite", room], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox room invite` failed.\nstdout:\n{link}\nstderr:\n{err}",
            self.name
        );
        link.trim().to_owned()
    }

    /// Join from `link`, **once**. A join the product turns away is its red, with its reason —
    /// a retry would pass a join that does not work the first time a person asks.
    pub fn join(&self, link: &str, name: &str) {
        let t0 = Instant::now();
        let (ok, out, err) = self.vox(&["room", "join", link, "--name", name], Some(ROOM_PASS));
        assert!(
            ok,
            "PRODUCT: {} could not join {name}: `vox room join` was refused after {:?}.\n\
             stdout:\n{out}\nstderr:\n{err}",
            self.name,
            t0.elapsed()
        );
    }

    pub fn post(&self, room: &str, text: &str) {
        let (ok, out, err) = self.vox(&["room", "post", room, text], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox room post` of {text:?} failed.\nstdout:\n{out}\nstderr:\n{err}",
            self.name
        );
    }

    /// This member's sync counters, from the shipped `vox status --json`.
    pub fn status(&self) -> serde_json::Value {
        let (ok, out, err) = self.vox(&["status", "--json"], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox status --json` failed.\nstdout:\n{out}\nstderr:\n{err}",
            self.name
        );
        serde_json::from_str(out.trim()).unwrap_or_else(|e| {
            panic!(
                "PRODUCT: {}'s `vox status --json` printed {out:?}: {e}",
                self.name
            )
        })
    }

    /// A reader on this member's control socket.
    pub fn reader(&self) -> Reader {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("APPARATUS: the reader's runtime: {e}"));
        let paths = vox_core::node::paths::Paths::resolve(
            "default",
            Some(&self.dir),
            Some(&self.dir.join("cfg")),
        )
        .unwrap_or_else(|e| {
            panic!(
                "APPARATUS: no profile paths under {}: {e}",
                self.dir.display()
            )
        });
        let client = rt
            .block_on(IpcClient::open(&paths.socket_file()))
            .unwrap_or_else(|e| {
                panic!(
                    "CANNOT MEASURE: the harness could not attach to {}'s control socket: {e}",
                    self.name
                )
            });
        Reader {
            rt,
            client,
            who: self.name,
        }
    }
}

/// What the mutant sender build says on stderr at its first session, and what no shipped binary
/// carries. Hard-coded, not read from the product: the product's copy is compiled only into the
/// mutant.
pub const MUTANT_MARKER: &str = "VOX-MUTANT-SENDER";

fn carries_marker(path: &str) -> std::io::Result<bool> {
    let bytes = std::fs::read(path)?;
    let m = MUTANT_MARKER.as_bytes();
    Ok(bytes.windows(m.len()).any(|w| w == m))
}

/// The mutant sender build that `VOX_MUTANT_SENDER` names (`scripts/build-mutant-sender.sh` builds
/// it; CI and the release gate run that before the proofs), checked before anything is measured:
/// it carries the mutant's marker, and the shipped binary the rest of the proof runs does not.
/// Else CANNOT MEASURE.
pub fn mutant_sender() -> String {
    let path = std::env::var("VOX_MUTANT_SENDER").unwrap_or_else(|_| {
        panic!(
            "CANNOT MEASURE: VOX_MUTANT_SENDER does not name the mutant sender build \
             (VOX_MUTANT_SENDER=$(scripts/build-mutant-sender.sh))"
        )
    });
    match carries_marker(&path) {
        Ok(true) => {}
        Ok(false) => panic!(
            "CANNOT MEASURE: VOX_MUTANT_SENDER={path} is not a mutant sender build (it does not \
             carry {MUTANT_MARKER})"
        ),
        Err(e) => panic!("CANNOT MEASURE: VOX_MUTANT_SENDER={path}: {e}"),
    }
    assert!(
        !carries_marker(VOX)
            .unwrap_or_else(|e| panic!("APPARATUS: could not read the shipped binary {VOX}: {e}")),
        "CANNOT MEASURE: the shipped binary {VOX} carries the mutant sender's marker {MUTANT_MARKER}, \
         so nothing here tells the shipped binary from the mutant"
    );
    path
}

/// Whether the mutant daemon `p` announced it misbehaves as `mode` (it does at its first session).
pub fn announced(p: &Proc, mode: &str) -> bool {
    p.transcript()
        .lines()
        .any(|l| l.contains(MUTANT_MARKER) && l.contains(&format!("\"{mode}\"")))
}

/// A counter summed over a member's `(room, peer)` rows, optionally for one peer only.
pub fn counter(status: &serde_json::Value, key: &str, peer: Option<&str>) -> u64 {
    status["sync"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|r| {
                    peer.is_none_or(|p| {
                        r["peer"]
                            .as_str()
                            .is_some_and(|x| p.starts_with(x) || x.starts_with(p))
                    })
                })
                .map(|r| r[key].as_u64().unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

/// The rows' last failures, for a failure message.
pub fn failures(status: &serde_json::Value) -> Vec<String> {
    status["sync"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["last_failure"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Reads a room over a member's own control socket, as `vox room read` does.
pub struct Reader {
    rt: tokio::runtime::Runtime,
    client: IpcClient,
    who: &'static str,
}

impl Reader {
    /// The node's id for the room `vox room list` names by `prefix`.
    pub fn room(&mut self, prefix: &str) -> vox_core::hash::Digest32 {
        match self.rt.block_on(self.client.rooms()) {
            Ok(Frame::Rooms { rooms }) => rooms
                .iter()
                .map(|(id, _, _)| *id)
                .find(|id| vox_core::node::link::b32_encode(id).starts_with(prefix))
                .unwrap_or_else(|| panic!("PRODUCT: room {prefix} is not on {}'s node", self.who)),
            Ok(other) => panic!(
                "PRODUCT: {}'s node answered a room list with {other:?}",
                self.who
            ),
            Err(e) => panic!(
                "CANNOT MEASURE: the harness's room list over {}'s control socket failed: {e}",
                self.who
            ),
        }
    }

    /// Every rendered text in the room now, every page of it. A read that fails is a red —
    /// **never an empty room**, which would let a proof that something was never read pass on a
    /// broken socket, and read a broken socket as slow sync.
    pub fn texts(&mut self, room: vox_core::hash::Digest32) -> Vec<String> {
        match self.rt.block_on(self.client.read_rows(room, None)) {
            Ok(Frame::Rows { rows }) => rows.into_iter().map(|r| r.text).collect(),
            Ok(other) => panic!(
                "PRODUCT: {}'s node refused to read room {}: {other:?}",
                self.who,
                vox_core::node::link::b32_encode(&room)
            ),
            Err(e) => panic!(
                "CANNOT MEASURE: the harness's control-socket read of {}'s node failed: {e}",
                self.who
            ),
        }
    }

    /// Whether `text` is readable in the room now.
    pub fn has(&mut self, room: vox_core::hash::Digest32, text: &str) -> bool {
        self.texts(room).iter().any(|t| t == text)
    }
}

/// Nearest-rank percentile of `samples` (sorted in place).
pub fn pct(samples: &mut [Duration], p: f64) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    samples.sort();
    let rank = ((p / 100.0) * samples.len() as f64).ceil() as usize;
    samples[rank.clamp(1, samples.len()) - 1]
}
