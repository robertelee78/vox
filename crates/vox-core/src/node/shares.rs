//! File shares the daemon serves (ADR-028 F-1, F-2).
//!
//! **A share is a message.** `vox share` hands the daemon a path and the announcement it has
//! addressed — `to`, `urgent`, the note — and the daemon hashes the file, serves it over HTTP on a
//! room-bound service, and posts that announcement with the name, size and SHA-256 filled in. The
//! command returns once the file is served; no foreground process is needed.
//!
//! The daemon serves it until the announcement expires under the room's retention, the sharer
//! stops it (`vox share stop`), the sharer leaves the room, or the room ends. `--count` and
//! `--for` remain as the sharer's own earlier stop.
//!
//! Each share is recorded in `<node>/shares/<tag>.json`, so a node that restarts serves it again —
//! **after hashing it again**: a file that changed since it was announced is never served under
//! that announcement; its share is stopped instead, and the node says so.
//!
//! The bytes never enter the log (ADR-020 11.1). Reach is the keyring's, as for any room-bound
//! service: a member this node has not trusted can neither read the announcement nor open the
//! service.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};

use crate::hash::Digest32;
use crate::node::api::{Fault, NodeCommand, NodeEvent, NodeView, Outcome};
use crate::node::link::{b32_decode, b32_encode};
use crate::node::paths::Paths;

/// The envelope type a share is announced with.
pub const FILE: &str = "file";

/// How long a post into a room just joined waits for its first sync (V210-164), as
/// `vox room post` does.
const POST_PATIENCE: Duration = Duration::from_secs(30);

/// How long the daemon waits to see its own announcement come back as an entry.
const ENTRY_PATIENCE: Duration = Duration::from_secs(10);

/// How often a share's end is checked, besides every change of the node's view.
const TEND: Duration = Duration::from_secs(1);

/// What `vox share` asks the daemon to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRequest {
    /// The room.
    pub channel_id: Digest32,
    /// The file or folder, absolute.
    pub path: PathBuf,
    /// The announcement as the sharer addressed it: an envelope of type `file`, carrying `to`,
    /// `urgent` and the note. The daemon fills in what it alone knows: the name, the size, the
    /// SHA-256 and the service's tag.
    pub envelope: String,
    /// Stop after this many completed fetches; `0` for no such stop.
    pub count: u64,
    /// Stop after this many seconds; `0` for no such stop.
    pub for_secs: u64,
}

/// One share, as `vox share` and `vox share list` show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRow {
    /// The room-bound service it is served on.
    pub tag: String,
    /// The name it is announced under.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// The announcement's entry hash in base32, or empty if the daemon did not see it land.
    pub entry: String,
    /// Completed fetches since this node started serving it.
    pub fetched: u64,
}

/// What a share's record keeps, so a restarted node serves it again.
#[derive(Debug, Clone)]
struct Record {
    tag: String,
    room: Digest32,
    name: String,
    size: u64,
    sha256: String,
    /// The file served: the shared file itself, or the folder's archive in the shares directory.
    served: PathBuf,
    /// Whether `served` is this node's own archive, removed with the share.
    staged: bool,
    entry: String,
    /// When the announcement was made, seconds: the message's age runs from here.
    created: u64,
    count: u64,
    until: u64,
}

impl Record {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tag": self.tag,
            "room": b32_encode(&self.room),
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "served": self.served.to_string_lossy(),
            "staged": self.staged,
            "entry": self.entry,
            "created": self.created,
            "count": self.count,
            "until": self.until,
        })
    }

    fn from_json(v: &serde_json::Value) -> Option<Self> {
        let s = |k: &str| {
            v.get(k)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);
        Some(Self {
            tag: s("tag")?,
            room: b32_decode(&s("room")?, "share record room").ok()?,
            name: s("name")?,
            size: n("size")?,
            sha256: s("sha256")?,
            served: PathBuf::from(s("served")?),
            staged: v.get("staged").and_then(serde_json::Value::as_bool)?,
            entry: s("entry")?,
            created: n("created")?,
            count: n("count")?,
            until: n("until")?,
        })
    }

    fn row(&self, fetched: u64) -> ShareRow {
        ShareRow {
            tag: self.tag.clone(),
            name: self.name.clone(),
            size: self.size,
            sha256: self.sha256.clone(),
            entry: self.entry.clone(),
            fetched,
        }
    }
}

/// A share being served.
struct Active {
    record: Record,
    fetched: Arc<AtomicU64>,
    local: SocketAddr,
    /// Said once the share stops: every transfer still in flight is reset, never closed cleanly,
    /// so a cut-short transfer cannot read as a whole file (V210-81).
    stop: watch::Sender<bool>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Active {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.server.abort();
    }
}

/// What to do with one share, decided from the node's view.
enum Verdict {
    Keep,
    Register(SocketAddr),
    Stop(String),
}

/// The shares one node serves.
pub struct Shares {
    paths: Paths,
    /// Weak, so the shares never keep a stopped node's command queue open.
    cmd: mpsc::WeakSender<(NodeCommand, oneshot::Sender<Outcome>)>,
    view: watch::Receiver<NodeView>,
    events: broadcast::Sender<NodeEvent>,
    /// Held across each change, so a stop and the tending of the same share never interleave.
    active: Mutex<BTreeMap<String, Active>>,
}

impl std::fmt::Debug for Shares {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shares")
            .field("dir", &self.paths.shares_dir())
            .finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl Shares {
    /// Start serving `paths`' recorded shares, and tend every share for as long as the node runs:
    /// the task ends when the node's view does.
    pub(crate) fn spawn(
        paths: Paths,
        cmd: mpsc::WeakSender<(NodeCommand, oneshot::Sender<Outcome>)>,
        view: watch::Receiver<NodeView>,
        events: broadcast::Sender<NodeEvent>,
    ) -> Arc<Self> {
        let shares = Arc::new(Self {
            paths,
            cmd,
            view,
            events,
            active: Mutex::new(BTreeMap::new()),
        });
        let tending = Arc::clone(&shares);
        tokio::spawn(async move {
            tending.restore().await;
            let mut view = tending.view.clone();
            loop {
                tokio::select! {
                    changed = view.changed() => if changed.is_err() { break },
                    () = tokio::time::sleep(TEND) => {}
                }
                tending.tend().await;
            }
            // The node has stopped: so has everything it served.
            tending.active.lock().await.clear();
        });
        shares
    }

    async fn apply(&self, command: NodeCommand) -> Outcome {
        let Some(cmd) = self.cmd.upgrade() else {
            return Outcome::Failed(Fault::ShuttingDown);
        };
        let (tx, rx) = oneshot::channel();
        if cmd.send((command, tx)).await.is_err() {
            return Outcome::Failed(Fault::ShuttingDown);
        }
        rx.await.unwrap_or(Outcome::Failed(Fault::ShuttingDown))
    }

    fn say(&self, note: String) {
        let _ = self.events.send(NodeEvent::NodeNote { note });
    }

    fn record_file(&self, tag: &str) -> PathBuf {
        self.paths.shares_dir().join(format!("{tag}.json"))
    }

    /// Hash, serve, announce (F-1, F-2). Answers once the file is served and announced.
    ///
    /// # Errors
    /// A sentence for the sharer: the path cannot be read, the envelope is not a file
    /// announcement, the room cannot be written to, or the service cannot be offered.
    pub async fn start(&self, req: ShareRequest) -> Result<ShareRow, String> {
        if !req.path.is_absolute() {
            return Err(format!("{} is not an absolute path", req.path.display()));
        }
        let mut envelope: serde_json::Value = serde_json::from_str(&req.envelope)
            .map_err(|_| "the share's announcement is not an envelope".to_owned())?;
        if envelope.get("type").and_then(serde_json::Value::as_str) != Some(FILE) {
            return Err("the share's announcement is not a file announcement".into());
        }
        let meta =
            std::fs::metadata(&req.path).map_err(|e| format!("{}: {e}", req.path.display()))?;
        let base = req
            .path
            .file_name()
            .map_or_else(|| "share".to_owned(), |n| n.to_string_lossy().into_owned());
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|e| format!("no randomness for the share: {e}"))?;
        // A folder becomes one archive in this node's shares directory, which lives as long as
        // the share does.
        let (served, name, staged) = if meta.is_dir() {
            let dir = self.paths.shares_dir();
            crate::node::paths::create_private_dir(&dir).map_err(|e| e.to_string())?;
            (
                dir.join(format!("{}.tar", hex(&nonce))),
                format!("{base}.tar"),
                true,
            )
        } else {
            (req.path.clone(), base, false)
        };
        let (source, target) = (req.path.clone(), served.clone());
        let hashed = tokio::task::spawn_blocking(move || {
            if staged {
                tar_dir(&source, &target)?;
            }
            digest_file(&target)
        })
        .await
        .map_err(|e| format!("hashing the share: {e}"))?;
        let (sha256, size) = match hashed {
            Ok(h) => h,
            Err(e) => {
                if staged {
                    let _ = std::fs::remove_file(&served);
                }
                return Err(e);
            }
        };
        // The tag names the content and **this share**: two shares of the same file are two
        // services, and stopping one never withdraws the other (V210-72).
        let tag = format!("file-{}-{}", &sha256[..16], hex(&nonce));
        if let Some(obj) = envelope.as_object_mut() {
            let body_empty = obj
                .get("body")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty);
            if body_empty {
                obj.insert(
                    "body".into(),
                    format!("sharing {name} ({size} bytes)").into(),
                );
            }
            let data = obj
                .entry("data")
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            if !data.is_object() {
                *data = serde_json::Value::Object(serde_json::Map::new());
            }
            if let Some(d) = data.as_object_mut() {
                d.insert("name".into(), name.clone().into());
                d.insert("size".into(), size.into());
                d.insert("sha256".into(), sha256.clone().into());
                d.insert("tag".into(), tag.clone().into());
                d.insert("http".into(), true.into());
                d.insert("kind".into(), if staged { "folder" } else { "file" }.into());
            }
        }
        let text = envelope.to_string();

        let fail = |e: String| {
            if staged {
                let _ = std::fs::remove_file(&served);
            }
            e
        };
        let (stop, stopping) = watch::channel(false);
        let fetched = Arc::new(AtomicU64::new(0));
        let (server, local) = serve(
            served.clone(),
            name.clone(),
            size,
            Arc::clone(&fetched),
            stopping,
        )
        .await
        .map_err(fail)?;
        let active_parts = (stop, server);
        // Served before it is announced: nobody reads an announcement of a file that is not there.
        match self
            .apply(NodeCommand::AddService {
                channel_id: req.channel_id,
                service_tag: tag.clone(),
                local,
                kind: crate::governance::share::ServiceKind::Http,
                persist: false,
            })
            .await
        {
            Outcome::Done => {}
            other => {
                drop(active_parts);
                return Err(fail(format!("cannot offer {tag}: {other}")));
            }
        }
        let me = self.view.borrow().identity.as_ref().map(|i| i.fingerprint);
        let mut events = self.events.subscribe();
        let deadline = tokio::time::Instant::now() + POST_PATIENCE;
        let posted = loop {
            match self
                .apply(NodeCommand::SendText {
                    channel_id: req.channel_id,
                    text: text.clone(),
                })
                .await
            {
                Outcome::Done => break Ok(()),
                Outcome::Failed(Fault::RoomNotSynced) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                other => break Err(other.to_string()),
            }
        };
        if let Err(e) = posted {
            let _ = self
                .apply(NodeCommand::RemoveService {
                    channel_id: req.channel_id,
                    service_tag: tag.clone(),
                })
                .await;
            drop(active_parts);
            return Err(fail(format!("cannot announce the share: {e}")));
        }
        // The announcement's entry and time, from the node's own word that it landed.
        let mut entry = String::new();
        let mut created = now_secs();
        let until = tokio::time::Instant::now() + ENTRY_PATIENCE;
        while let Ok(Ok(ev)) = tokio::time::timeout_at(until, events.recv()).await {
            if let NodeEvent::NewEntry { channel_id, row } = ev {
                if channel_id == req.channel_id && Some(row.author) == me && row.text == text {
                    entry = b32_encode(&row.entry_hash);
                    created = row.created_millis / 1000;
                    break;
                }
            }
        }
        let record = Record {
            tag: tag.clone(),
            room: req.channel_id,
            name,
            size,
            sha256,
            served,
            staged,
            entry,
            created,
            count: req.count,
            until: if req.for_secs == 0 {
                0
            } else {
                now_secs().saturating_add(req.for_secs)
            },
        };
        let written =
            crate::node::paths::create_private_dir(&self.paths.shares_dir()).and_then(|()| {
                crate::node::paths::write_private_file(
                    &self.record_file(&tag),
                    record.to_json().to_string().as_bytes(),
                )
            });
        if let Err(e) = written {
            // Served and announced all the same: only a restart of this node would end it early.
            self.say(format!(
                "sharing {} without a record of it ({e}): it stops if this node restarts",
                record.name
            ));
        }
        let row = record.row(0);
        let (stop, server) = active_parts;
        self.active.lock().await.insert(
            tag,
            Active {
                record,
                fetched,
                local,
                stop,
                server,
            },
        );
        Ok(row)
    }

    /// This node's shares in `room`, in tag order.
    pub async fn list(&self, room: &Digest32) -> Vec<ShareRow> {
        self.active
            .lock()
            .await
            .values()
            .filter(|a| a.record.room == *room)
            .map(|a| a.record.row(a.fetched.load(Ordering::SeqCst)))
            .collect()
    }

    /// Stop every share in `room` whose name or tag is `selector`, or whose SHA-256 or entry
    /// starts with it. Returns those stopped.
    pub async fn stop(&self, room: &Digest32, selector: &str) -> Vec<ShareRow> {
        let mut active = self.active.lock().await;
        let tags: Vec<String> = active
            .values()
            .filter(|a| a.record.room == *room)
            .filter(|a| {
                let r = &a.record;
                r.name == selector
                    || r.tag == selector
                    || (!selector.is_empty()
                        && (r.sha256.starts_with(selector) || r.entry.starts_with(selector)))
            })
            .map(|a| a.record.tag.clone())
            .collect();
        let mut stopped = Vec::new();
        for tag in tags {
            if let Some(a) = active.remove(&tag) {
                stopped.push(a.record.row(a.fetched.load(Ordering::SeqCst)));
                self.end(a).await;
            }
        }
        stopped
    }

    /// Withdraw a share's service — which cuts what it still carries — and forget it.
    async fn end(&self, a: Active) {
        let _ = self
            .apply(NodeCommand::RemoveService {
                channel_id: a.record.room,
                service_tag: a.record.tag.clone(),
            })
            .await;
        let _ = std::fs::remove_file(self.record_file(&a.record.tag));
        if a.record.staged {
            let _ = std::fs::remove_file(&a.record.served);
        }
        drop(a);
    }

    /// Serve again what the last run recorded, each only if its bytes are still the ones announced.
    async fn restore(&self) {
        let Ok(dir) = std::fs::read_dir(self.paths.shares_dir()) else {
            return;
        };
        let files: Vec<PathBuf> = dir
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        for file in files {
            let record = std::fs::read(&file)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| Record::from_json(&v));
            let Some(record) = record else {
                let _ = std::fs::remove_file(&file);
                continue;
            };
            let served = record.served.clone();
            let now = tokio::task::spawn_blocking(move || digest_file(&served))
                .await
                .ok()
                .and_then(Result::ok);
            if now.as_ref() != Some(&(record.sha256.clone(), record.size)) {
                self.say(format!(
                    "no longer sharing {}: it changed or went since it was shared, and a share \
                     serves only the bytes it announced",
                    record.name
                ));
                let _ = std::fs::remove_file(&file);
                if record.staged {
                    let _ = std::fs::remove_file(&record.served);
                }
                continue;
            }
            let (stop, stopping) = watch::channel(false);
            let fetched = Arc::new(AtomicU64::new(0));
            let Ok((server, local)) = serve(
                record.served.clone(),
                record.name.clone(),
                record.size,
                Arc::clone(&fetched),
                stopping,
            )
            .await
            else {
                continue;
            };
            self.active.lock().await.insert(
                record.tag.clone(),
                Active {
                    record,
                    fetched,
                    local,
                    stop,
                    server,
                },
            );
        }
    }

    /// End what has ended, and offer again what a closed room dropped.
    async fn tend(&self) {
        let mut active = self.active.lock().await;
        if active.is_empty() {
            return;
        }
        let now = now_secs();
        let verdicts: Vec<(String, Verdict)> = {
            let view = self.view.borrow();
            // A locked node knows too little to end anything: it is kept for when it unlocks.
            if view.locked || view.identity.is_none() {
                return;
            }
            active
                .values()
                .map(|a| {
                    let r = &a.record;
                    let verdict = match view.channels.iter().find(|c| c.channel_id == r.room) {
                        None => Verdict::Stop("this node left the room".into()),
                        Some(c) if c.over.is_some() => {
                            Verdict::Stop(c.over.clone().unwrap_or_default())
                        }
                        Some(_) if r.count > 0 && a.fetched.load(Ordering::SeqCst) >= r.count => {
                            Verdict::Stop(format!("it was fetched {} time(s)", r.count))
                        }
                        Some(_) if r.until > 0 && now >= r.until => {
                            Verdict::Stop("its --for is up".into())
                        }
                        Some(_) => {
                            match view.open_channels.iter().find(|d| d.channel_id == r.room) {
                                Some(d)
                                    if d.retention > 0
                                        && now >= r.created.saturating_add(d.retention) =>
                                {
                                    Verdict::Stop("its message expired".into())
                                }
                                Some(d) if !d.services.iter().any(|(t, _)| *t == r.tag) => {
                                    Verdict::Register(a.local)
                                }
                                _ => Verdict::Keep,
                            }
                        }
                    };
                    (r.tag.clone(), verdict)
                })
                .collect()
        };
        for (tag, verdict) in verdicts {
            match verdict {
                Verdict::Keep => {}
                Verdict::Register(local) => {
                    let Some(room) = active.get(&tag).map(|a| a.record.room) else {
                        continue;
                    };
                    let _ = self
                        .apply(NodeCommand::AddService {
                            channel_id: room,
                            service_tag: tag,
                            local,
                            kind: crate::governance::share::ServiceKind::Http,
                            persist: false,
                        })
                        .await;
                }
                Verdict::Stop(why) => {
                    if let Some(a) = active.remove(&tag) {
                        self.say(format!("no longer sharing {}: {why}", a.record.name));
                        self.end(a).await;
                    }
                }
            }
        }
    }
}

/// Listen locally and hand the file to whoever connects, until `stopping`.
async fn serve(
    file: PathBuf,
    name: String,
    size: u64,
    fetched: Arc<AtomicU64>,
    stopping: watch::Receiver<bool>,
) -> Result<(tokio::task::JoinHandle<()>, SocketAddr), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("cannot listen locally: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("cannot read the local address: {e}"))?;
    let server = tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (file, name, fetched, stopping) = (
                file.clone(),
                name.clone(),
                Arc::clone(&fetched),
                stopping.clone(),
            );
            tokio::spawn(async move {
                if serve_one(sock, &file, &name, size, stopping).await {
                    fetched.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    Ok((server, local))
}

/// Answer one HTTP request with the file. Whatever the path, the answer is the share: there is
/// one thing here. Returns whether the receiver took every byte.
async fn serve_one(
    mut sock: tokio::net::TcpStream,
    file: &Path,
    name: &str,
    size: u64,
    mut stopping: watch::Receiver<bool>,
) -> bool {
    let whole = async {
        // Read the request head (bounded) so a client that sends one gets a well-formed
        // exchange; the path is not interpreted.
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
            match tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => head.extend_from_slice(&buf[..n]),
                _ => return Some(false),
            }
        }
        let is_head = head.starts_with(b"HEAD ");
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \
             {size}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nConnection: \
             close\r\n\r\n",
            name.replace('"', "")
        );
        if sock.write_all(reply.as_bytes()).await.is_err() {
            return None;
        }
        if is_head {
            return Some(false);
        }
        // `std::fs`: this workspace's tokio has no `fs` feature. The reads are chunked, so a large
        // file is not held in memory.
        let Ok(mut f) = std::fs::File::open(file) else {
            return None;
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut sent = 0u64;
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return None;
                    }
                    sent += n as u64;
                }
                Err(_) => return None,
            }
        }
        if sent != size {
            return None;
        }
        let _ = sock.shutdown().await;
        // **Written is not delivered.** The last write lands in this node's socket buffers, not at
        // the receiver, and counting a fetch here ended a `--count` share whose `RemoveService`
        // then cut the very session still carrying those bytes (PRD-001 R22). The far end closing
        // is what says it has everything: it reaches this socket only once the receiver has read
        // the stream's end and closed its own side. A reset instead means it did not.
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => return Some(true),
                Ok(_) => {}
                Err(_) => return Some(false),
            }
        }
    };
    let ended = tokio::select! {
        ended = whole => ended,
        _ = stopping.wait_for(|stop| *stop) => None,
    };
    match ended {
        Some(done) => done,
        // Any other ending is a reset: a clean close would say "that was all of it".
        None => {
            crate::tunnel::session::abort_after_drain(sock).await;
            false
        }
    }
}

/// Read a file and return its SHA-256 and length.
fn digest_file(path: &Path) -> Result<(String, u64), String> {
    use sha2::{Digest as _, Sha256};
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

/// Write `dir` as a ustar archive at `out`: entries in sorted order, every timestamp, owner and
/// mode fixed, so the same folder always makes the same bytes and the same hash.
fn tar_dir(dir: &Path, out: &Path) -> Result<(), String> {
    fn entries(
        root: &Path,
        dir: &Path,
        acc: &mut Vec<(String, PathBuf, bool)>,
    ) -> std::io::Result<()> {
        let mut list: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        list.sort_by_key(std::fs::DirEntry::file_name);
        for e in list {
            let path = e.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let ty = e.file_type()?;
            if ty.is_dir() {
                acc.push((format!("{rel}/"), path.clone(), true));
                entries(root, &path, acc)?;
            } else if ty.is_file() {
                acc.push((rel, path, false));
            }
            // Symlinks and devices are not carried: a share is files.
        }
        Ok(())
    }
    let io = |e: std::io::Error| format!("archiving {}: {e}", dir.display());
    let base = dir
        .file_name()
        .map_or_else(|| "share".to_owned(), |n| n.to_string_lossy().into_owned());
    let mut list = vec![(format!("{base}/"), dir.to_owned(), true)];
    let mut inner = Vec::new();
    entries(dir, dir, &mut inner).map_err(io)?;
    list.extend(
        inner
            .into_iter()
            .map(|(rel, p, d)| (format!("{base}/{rel}"), p, d)),
    );
    let mut f = std::fs::File::create(out).map_err(io)?;
    for (name, path, is_dir) in list {
        let size = if is_dir {
            0
        } else {
            std::fs::metadata(&path).map_err(io)?.len()
        };
        let mut h = [0u8; 512];
        let (prefix, leaf) = if name.len() > 100 {
            let cut = name[..name.len() - 1]
                .rfind('/')
                .filter(|i| *i <= 155 && name.len() - i - 1 <= 100)
                .ok_or_else(|| format!("{name}: path too long to archive"))?;
            (&name[..cut], &name[cut + 1..])
        } else {
            ("", name.as_str())
        };
        h[..leaf.len()].copy_from_slice(leaf.as_bytes());
        let octal = |h: &mut [u8], at: usize, len: usize, v: u64| {
            let s = format!("{v:0width$o}", width = len - 1);
            h[at..at + len - 1].copy_from_slice(s.as_bytes());
        };
        octal(&mut h, 100, 8, if is_dir { 0o755 } else { 0o644 });
        octal(&mut h, 108, 8, 0);
        octal(&mut h, 116, 8, 0);
        octal(&mut h, 124, 12, size);
        octal(&mut h, 136, 12, 0);
        h[148..156].copy_from_slice(b"        ");
        h[156] = if is_dir { b'5' } else { b'0' };
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        f.write_all(&h).map_err(io)?;
        if !is_dir {
            let mut src = std::fs::File::open(&path).map_err(io)?;
            let copied = std::io::copy(&mut src, &mut f).map_err(io)?;
            let pad = (512 - (copied % 512)) % 512;
            f.write_all(&vec![0u8; pad as usize]).map_err(io)?;
        }
    }
    f.write_all(&[0u8; 1024]).map_err(io)?;
    f.flush().map_err(io)
}
