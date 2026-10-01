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

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::ipc::{Frame, IpcClient, Request};

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

    /// Send `sig` (`-STOP`, `-CONT`) to this process, by PID.
    pub fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.pid().to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "APPARATUS (harness): kill {sig} {} failed", self.pid());
    }

    pub fn transcript(&self) -> String {
        self.said.lock().unwrap().clone()
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
                let mut s = sink.lock().unwrap();
                s.push_str(&line);
                s.push('\n');
            }
        });
    }
    if let Some(err) = err {
        let sink = Arc::clone(&said);
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let mut s = sink.lock().unwrap();
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
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let mut child = Command::new(VOX)
        .args(["node", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS (harness): could not spawn vox node");
    let said = drain(&mut child);
    let p = Proc { child, said };
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let text = p.transcript();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (p, s.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS (staging): the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(100));
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
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let pass = root.join(format!("{name}.pass"));
        std::fs::write(&pass, ID_PASS).unwrap();
        let mut m = Self {
            name,
            dir,
            pass,
            fp: String::new(),
        };
        let (ok, out, err) = m.vox(&["id"], None);
        assert!(ok, "APPARATUS (staging): {name}: vox id failed: {err}");
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
            .expect("APPARATUS (harness): could not spawn vox");
        if let Some(s) = stdin {
            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        }
        let out = child
            .wait_with_output()
            .expect("APPARATUS (harness): could not wait for vox");
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
            "APPARATUS (staging): {} could not trust {}: {out}{err}",
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
        let pass = self.pass.to_str().unwrap().to_owned();
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
            .expect("APPARATUS (harness): could not spawn vox daemon");
        let said = drain(&mut child);
        let p = Proc { child, said };
        let deadline = Instant::now() + Duration::from_secs(90);
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                Instant::now() < deadline,
                "APPARATUS (staging): {}'s daemon never answered:\n{}",
                self.name,
                p.transcript()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        p
    }

    /// Create a room and return its id as `vox room list` prints it.
    pub fn create(&self, name: &str) -> String {
        let (ok, out, err) = self.vox(&["room", "create", "--name", name], Some(ROOM_PASS));
        assert!(
            ok,
            "APPARATUS (staging): {} could not create {name}: {out}{err}",
            self.name
        );
        let (ok, list, err) = self.vox(&["room", "list"], None);
        assert!(ok, "APPARATUS (staging): vox room list failed: {err}");
        list.lines()
            .find(|l| l.split_whitespace().any(|w| w == name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("APPARATUS (staging): room {name} not listed: {list}"))
            .to_owned()
    }

    pub fn invite(&self, room: &str) -> String {
        let (ok, link, err) = self.vox(&["room", "invite", room], None);
        assert!(ok, "APPARATUS (staging): vox room invite failed: {err}");
        link.trim().to_owned()
    }

    /// Join from `link`, retrying a few times: a failed join is not what these proofs measure.
    pub fn join(&self, link: &str, name: &str) {
        for attempt in 1..=6 {
            let (ok, out, err) = self.vox(&["room", "join", link, "--name", name], Some(ROOM_PASS));
            if ok {
                return;
            }
            eprintln!("[receipt] {} join attempt {attempt}: {out}{err}", self.name);
            std::thread::sleep(Duration::from_secs(3));
        }
        panic!(
            "APPARATUS (staging not achieved): {} never joined {name}",
            self.name
        );
    }

    pub fn post(&self, room: &str, text: &str) {
        let (ok, out, err) = self.vox(&["room", "post", room, text], None);
        assert!(
            ok,
            "PRODUCT: {} could not post {text:?}: {out}{err}",
            self.name
        );
    }

    /// This member's sync counters, from the shipped `vox status --json`.
    pub fn status(&self) -> serde_json::Value {
        let (ok, out, err) = self.vox(&["status", "--json"], None);
        assert!(
            ok,
            "APPARATUS (measurement): {}: vox status --json failed: {err}",
            self.name
        );
        serde_json::from_str(out.trim()).unwrap_or_else(|e| {
            panic!(
                "APPARATUS (measurement): {}: vox status --json printed {out:?}: {e}",
                self.name
            )
        })
    }

    /// A reader on this member's control socket.
    pub fn reader(&self) -> Reader {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let paths = vox_core::node::paths::Paths::resolve(
            "default",
            Some(&self.dir),
            Some(&self.dir.join("cfg")),
        )
        .unwrap();
        let client = rt
            .block_on(IpcClient::open(&paths.socket_file()))
            .expect("APPARATUS (harness): could not attach to the node");
        Reader { rt, client }
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
/// Else an `APPARATUS (harness)` red.
pub fn mutant_sender() -> String {
    let path = std::env::var("VOX_MUTANT_SENDER").unwrap_or_else(|_| {
        panic!(
            "APPARATUS (harness): VOX_MUTANT_SENDER does not name the mutant sender build \
             (VOX_MUTANT_SENDER=$(scripts/build-mutant-sender.sh))"
        )
    });
    match carries_marker(&path) {
        Ok(true) => {}
        Ok(false) => panic!(
            "APPARATUS (harness): VOX_MUTANT_SENDER={path} is not a mutant sender build (it does not \
             carry {MUTANT_MARKER})"
        ),
        Err(e) => panic!("APPARATUS (harness): VOX_MUTANT_SENDER={path}: {e}"),
    }
    assert!(
        !carries_marker(VOX).expect("APPARATUS (harness): could not read the shipped binary"),
        "APPARATUS (harness): the shipped binary {VOX} carries the mutant sender's marker {MUTANT_MARKER}"
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
}

impl Reader {
    /// The node's id for the room `vox room list` names by `prefix`.
    pub fn room(&mut self, prefix: &str) -> vox_core::hash::Digest32 {
        match self.rt.block_on(self.client.rooms()) {
            Ok(Frame::Rooms { rooms }) => rooms
                .iter()
                .map(|(id, _, _)| *id)
                .find(|id| vox_core::node::link::b32_encode(id).starts_with(prefix))
                .unwrap_or_else(|| panic!("APPARATUS (staging): room {prefix} not on this node")),
            other => panic!("APPARATUS (harness): rooms: {other:?}"),
        }
    }

    /// Every rendered text in the room now.
    pub fn texts(&mut self, room: vox_core::hash::Digest32) -> Vec<String> {
        match self.rt.block_on(self.client.request(&Request::Read {
            channel_id: room,
            since: None,
            limit: 0,
        })) {
            Ok(Frame::Rows { rows }) => rows.into_iter().map(|r| r.text).collect(),
            _ => Vec::new(),
        }
    }

    /// Whether `text` is readable in the room now.
    pub fn has(&mut self, room: vox_core::hash::Digest32, text: &str) -> bool {
        self.texts(room).iter().any(|t| t == text)
    }

    /// The author of the latest post in the room whose text contains `needle`.
    pub fn author_of(
        &mut self,
        room: vox_core::hash::Digest32,
        needle: &str,
    ) -> Option<vox_core::hash::Digest32> {
        match self.rt.block_on(self.client.request(&Request::Read {
            channel_id: room,
            since: None,
            limit: 0,
        })) {
            Ok(Frame::Rows { rows }) => rows
                .iter()
                .rev()
                .find(|r| r.text.contains(needle))
                .map(|r| r.author),
            _ => None,
        }
    }

    /// Ask this member's daemon for a local forward to `host`'s service `tag` in the room, as
    /// `vox room get` does. The bound local address.
    pub fn forward(
        &mut self,
        room: vox_core::hash::Digest32,
        host: vox_core::hash::Digest32,
        tag: &str,
    ) -> String {
        match self.rt.block_on(self.client.request(&Request::Forward {
            channel_id: room,
            host,
            service_tag: tag.to_owned(),
            local: "127.0.0.1:0".into(),
        })) {
            Ok(Frame::Bound { local }) => local,
            Ok(refused @ Frame::Error { .. }) => panic!(
                "PRODUCT: the daemon refused the forward to {tag} (as `vox room get` would): \
                 {refused:?}"
            ),
            Ok(other) => panic!("PRODUCT: unexpected reply to a forward to {tag}: {other:?}"),
            Err(e) => panic!("APPARATUS: control-socket request failed: {e}"),
        }
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
