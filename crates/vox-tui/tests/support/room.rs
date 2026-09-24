//! Shared set-up for the ADR-021 product proofs: N workers, each a real node with its
//! own identity, in one room, mutually admitted to each other's trust keyrings, each
//! serving the control socket that the shipped `vox` binary attaches to.
//!
//! Every verb under test is run as the **real `vox` binary**, as a separate process,
//! exactly as an agent's shell would run it. Nothing here calls the CLI's functions.

#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

pub const VOX: &str = env!("CARGO_BIN_EXE_vox");
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Everything a harness might have put in this process's environment that would
/// silently name a session. **This test process may itself be running inside Claude
/// Code or Codex**, and a leaked `CLAUDE_CODE_SESSION_ID` would make every worker the
/// same session — the exact defect these proofs exist to catch.
pub const HARNESS_SESSION_VARS: [&str; 5] = [
    "VOX_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "VOX_ROOM",
];

pub fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
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
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad NDJSON line ({e}): {l}")))
            .collect()
    }
}

/// One worker: a node, its identity, and the profile directories the binary reads.
pub struct Worker {
    pub name: String,
    pub data: std::path::PathBuf,
    pub cfg: std::path::PathBuf,
    pub paths: Paths,
    pub node: NodeHandle,
    pub fp: [u8; 32],
}

impl Worker {
    /// Run `vox …` as `session` of this worker (or with no session at all).
    pub fn vox(&self, session: Option<&str>, args: &[&str]) -> Out {
        self.vox_in(session, args, None)
    }

    /// As [`Worker::vox`], with `stdin`.
    pub fn vox_in(&self, session: Option<&str>, args: &[&str], stdin: Option<&str>) -> Out {
        self.vox_bin(VOX, session, args, stdin)
    }

    /// Run a given `vox` binary — the one under test, or a published release — as this
    /// worker.
    pub fn vox_bin(&self, bin: &str, session: Option<&str>, args: &[&str], stdin: Option<&str>) -> Out {
        use std::io::Write as _;
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for v in HARNESS_SESSION_VARS {
            cmd.env_remove(v);
        }
        if let Some(s) = session {
            cmd.env("VOX_SESSION", s);
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
                session.map(|s| format!("VOX_SESSION={s} ")).unwrap_or_default(),
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

/// A room shared by every worker, and the socket guards that keep it served.
pub struct Room {
    pub workers: Vec<Worker>,
    pub id: String,
    pub cid: [u8; 32],
    _socks: Vec<vox_core::node::ipc::IpcServer>,
}

async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match h.next_event().await {
                Some(e) => {
                    if let Some(v) = f(e) {
                        return v;
                    }
                }
                None => panic!("event stream ended"),
            }
        }
    })
    .await
    .expect("timed out waiting for an event")
}

async fn worker(tmp: &std::path::Path, name: &str) -> Worker {
    let data = tmp.join(name).join("data");
    let cfg = tmp.join(name).join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();
    let node = Node::spawn_networked(paths.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(node
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
        })
        .await
        .is_done());
    let fp = node.view().identity.expect("identity").fingerprint;
    Worker {
        name: name.to_owned(),
        data,
        cfg,
        paths,
        node,
        fp,
    }
}

/// Build `names.len()` workers in one room. Each trusts every other, and the room is
/// ready when every worker holds every other's sender key — so any post by anyone is
/// readable by everyone.
pub async fn room(tmp: &std::path::Path, names: &[&str]) -> Room {
    let mut workers = Vec::new();
    for n in names {
        workers.push(worker(tmp, n).await);
    }
    let first = &workers[0];
    assert!(first
        .node
        .apply(NodeCommand::CreateChannel {
            local_name: "mission".into(),
            passphrase: secret("channel passphrase"),
        })
        .await
        .is_done());
    let cid = first.node.view().channels[0].channel_id;
    assert!(first
        .node
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(&first.node, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await;
    for w in &workers[1..] {
        assert!(w
            .node
            .apply(NodeCommand::JoinChannel {
                link: url.clone(),
                local_name: "mission".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
    }
    for a in &workers {
        for b in &workers {
            if a.fp != b.fp {
                assert!(a
                    .node
                    .apply(NodeCommand::Trust {
                        fingerprint: b.fp,
                        petname: b.name.clone(),
                    })
                    .await
                    .is_done());
            }
        }
    }
    // One wait per worker for the WHOLE set of peers: events are consumed as they are
    // read, so waiting for one peer at a time would discard the event for the next.
    for a in &workers {
        let mut owed: std::collections::BTreeSet<[u8; 32]> =
            workers.iter().map(|b| b.fp).filter(|fp| *fp != a.fp).collect();
        let names: std::collections::BTreeMap<[u8; 32], String> =
            workers.iter().map(|w| (w.fp, w.name.clone())).collect();
        let waited = tokio::time::timeout(TIMEOUT, async {
            loop {
                match a.node.next_event().await {
                    Some(NodeEvent::SenderKeyReceived { channel_id, peer, .. }) if channel_id == cid => {
                        owed.remove(&peer);
                        if owed.is_empty() {
                            return;
                        }
                    }
                    Some(_) => {}
                    None => panic!("event stream ended"),
                }
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "{} never received the sender key of {:?}",
            a.name,
            owed.iter().map(|f| names[f].clone()).collect::<Vec<_>>()
        );
    }
    let socks = workers
        .iter()
        .map(|w| vox_core::node::ipc::bind(w.node.clone(), &w.paths).expect("socket"))
        .collect();
    Room {
        id: vox_core::node::link::b32_encode(&cid),
        cid,
        workers,
        _socks: socks,
    }
}

/// Poll a `vox` invocation until its output satisfies `ok`, or fail naming what it
/// last said. Something posted on one node reaches another through the log, so "has
/// it arrived yet" has no synchronous answer.
pub fn until(w: &Worker, session: Option<&str>, what: &str, args: &[&str], ok: impl Fn(&Out) -> bool) -> Out {
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
