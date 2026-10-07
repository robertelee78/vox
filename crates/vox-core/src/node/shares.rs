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
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    /// A file through a Session (ADR-029 DR-1), or `None` for a room share.
    pub session: Option<SessionShare>,
}

/// A file through a Session (ADR-029 DR-1.7, DR-1.8; #546): neither is a message of the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionShare {
    /// Out of a Session: announced as that Session's `file` entry, sealed under this node's drive
    /// key, and served to the members this node trusts with drive.
    Out {
        /// The harness's session id.
        session_id: String,
    },
    /// Into a Session on another node: announced to that node alone, on the drive request, and
    /// served to it alone.
    In {
        /// The Session's node.
        node: Digest32,
    },
}

/// Who a share is served to, besides the tunnel's own gate (this node's keyring and the room's
/// members).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Only {
    /// Any member that gate lets in: a room share, which any member may pull (ADR-028 F-3).
    Anyone,
    /// A file out of a Session: a member this node trusts with drive **when it fetches**
    /// (ADR-029 SC-2), so losing drive cuts a fetch under way.
    Drive,
    /// A file into a Session: that Session's node, alone.
    Node(Digest32),
}

impl Only {
    fn to_json(&self) -> serde_json::Value {
        match self {
            Only::Anyone => "anyone".into(),
            Only::Drive => "drive".into(),
            Only::Node(n) => b32_encode(n).into(),
        }
    }

    fn from_json(v: Option<&serde_json::Value>) -> Option<Self> {
        match v.and_then(serde_json::Value::as_str) {
            None | Some("anyone") => Some(Only::Anyone),
            Some("drive") => Some(Only::Drive),
            Some(n) => b32_decode(n, "share record node").ok().map(Only::Node),
        }
    }
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
    /// For a folder, how many files it lists (ADR-028 F-8); `0` for a file.
    pub files: u64,
}

/// What a share's record keeps, so a restarted node serves it again.
#[derive(Debug, Clone)]
struct Record {
    tag: String,
    room: Digest32,
    name: String,
    size: u64,
    sha256: String,
    /// What is served: the shared file, or the shared folder, from where it is.
    served: PathBuf,
    /// A folder's files as they were listed (ADR-028 F-8); empty for a file.
    files: Vec<crate::node::folder::Found>,
    entry: String,
    /// When the announcement was made, milliseconds: the message's age runs from here.
    created_ms: u64,
    count: u64,
    /// When its `--for` is up, milliseconds; 0 for never.
    until_ms: u64,
    /// Who it is served to.
    only: Only,
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
            "files": self
                .files
                .iter()
                .map(|f| serde_json::json!([
                    f.listed.path,
                    f.listed.size,
                    f.listed.sha256,
                    f.modified.to_string()
                ]))
                .collect::<Vec<_>>(),
            "entry": self.entry,
            "created_ms": self.created_ms,
            "count": self.count,
            "until_ms": self.until_ms,
            "only": self.only.to_json(),
        })
    }

    fn from_json(v: &serde_json::Value) -> Option<Self> {
        let s = |k: &str| {
            v.get(k)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);
        // Milliseconds; a record written before held whole seconds under the old name.
        let ms =
            |k: &str| n(&format!("{k}_ms")).or_else(|| n(k).map(|secs| secs.saturating_mul(1_000)));
        Some(Self {
            tag: s("tag")?,
            room: b32_decode(&s("room")?, "share record room").ok()?,
            name: s("name")?,
            size: n("size")?,
            sha256: s("sha256")?,
            served: PathBuf::from(s("served")?),
            files: v
                .get("files")
                .and_then(serde_json::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|e| {
                            let e = e.as_array()?;
                            Some(crate::node::folder::Found {
                                listed: crate::node::folder::Listed {
                                    path: e.first()?.as_str()?.to_owned(),
                                    size: e.get(1)?.as_u64()?,
                                    sha256: e.get(2)?.as_str()?.to_owned(),
                                },
                                modified: e.get(3)?.as_str()?.parse().ok()?,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            entry: s("entry")?,
            created_ms: ms("created")?,
            count: n("count")?,
            until_ms: ms("until")?,
            only: Only::from_json(v.get("only"))?,
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
            files: self.files.len() as u64,
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

/// Who has pulled one share whole (ADR-028 F-7): the members whose fetch of it completed, by the
/// tunnel each came through, never by what a client says.
#[derive(Debug, Clone, Default)]
struct PulledBy {
    room: Digest32,
    /// The announcement's entry, base32; empty until it is known.
    entry: String,
    who: Vec<Digest32>,
}

/// Every share's [`PulledBy`], by tag: kept past the share's end, so its card still says who
/// pulled it, and on disk, so a restart does too.
#[derive(Debug, Default)]
struct PulledBook {
    file: PathBuf,
    by_tag: BTreeMap<String, PulledBy>,
}

impl PulledBook {
    fn load(file: PathBuf) -> Self {
        let by_tag = std::fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.as_object().cloned())
            .map(|o| {
                o.into_iter()
                    .filter_map(|(tag, v)| {
                        let room = b32_decode(v.get("room")?.as_str()?, "pulled-by room").ok()?;
                        let entry = v.get("entry")?.as_str()?.to_owned();
                        let who = v
                            .get("who")?
                            .as_array()?
                            .iter()
                            .filter_map(|w| b32_decode(w.as_str()?, "pulled-by member").ok())
                            .collect();
                        Some((tag, PulledBy { room, entry, who }))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { file, by_tag }
    }

    fn save(&self) {
        let v: serde_json::Map<String, serde_json::Value> = self
            .by_tag
            .iter()
            .map(|(tag, p)| {
                (
                    tag.clone(),
                    serde_json::json!({
                        "room": b32_encode(&p.room),
                        "entry": p.entry,
                        "who": p.who.iter().map(b32_encode).collect::<Vec<_>>(),
                    }),
                )
            })
            .collect();
        if let Some(dir) = self.file.parent() {
            let _ = crate::node::paths::create_private_dir(dir);
        }
        let _ = crate::node::paths::write_private_file(
            &self.file,
            serde_json::Value::Object(v).to_string().as_bytes(),
        );
    }

    /// `member` pulled the share `tag` in `room` whole.
    fn pulled(&mut self, tag: &str, room: Digest32, member: Digest32) {
        let p = self
            .by_tag
            .entry(tag.to_owned())
            .or_insert_with(|| PulledBy {
                room,
                ..PulledBy::default()
            });
        if !p.who.contains(&member) {
            p.who.push(member);
            self.save();
        }
    }

    /// The share `tag`'s announcement is `entry`.
    fn announced(&mut self, tag: &str, room: Digest32, entry: &str) {
        let p = self
            .by_tag
            .entry(tag.to_owned())
            .or_insert_with(|| PulledBy {
                room,
                ..PulledBy::default()
            });
        if p.entry != entry {
            entry.clone_into(&mut p.entry);
            self.save();
        }
    }
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
    /// Who pulled each share whole (F-7).
    pulled: Arc<std::sync::Mutex<PulledBook>>,
}

impl std::fmt::Debug for Shares {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shares")
            .field("dir", &self.paths.shares_dir())
            .finish_non_exhaustive()
    }
}

/// The node's clock in milliseconds, a test step included, as the node's own clock has it.
fn now_ms() -> u64 {
    (crate::time::clock_with_test_skew())()
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
            pulled: Arc::new(std::sync::Mutex::new(PulledBook::load(
                // Beside the share records, not among them: `restore` reads every `*.json` there
                // as one, and removes what is not.
                paths.shares_dir().join("pulled-by").join("book.json"),
            ))),
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

    /// Who has pulled each of this node's shares in `room` whole, by announcement (ADR-028 F-7):
    /// `(entry, members)`, from this daemon's own record of completed fetches.
    #[must_use]
    pub fn pulled_by(&self, room: &Digest32) -> Vec<(Digest32, Vec<Digest32>)> {
        let book = self
            .pulled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        book.by_tag
            .values()
            .filter(|p| p.room == *room && !p.who.is_empty())
            .filter_map(|p| Some((b32_decode(&p.entry, "pulled-by entry").ok()?, p.who.clone())))
            .collect()
    }

    /// What `serve` needs to record who pulled the share `tag` in `room`, and to tell whom it
    /// may serve (`only`).
    fn witness(&self, tag: &str, room: Digest32, only: Only) -> Witness {
        Witness {
            book: Arc::clone(&self.pulled),
            tag: tag.to_owned(),
            room,
            owner: self.view.borrow().identity.as_ref().map(|i| i.fingerprint),
            events: self.events.clone(),
            said: Arc::default(),
            only,
            view: self.view.clone(),
        }
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
        // **A folder is listed, not packed** (ADR-028 F-8): every file by its path, size and
        // SHA-256, served from where it is; the share's SHA-256 is its list's.
        let folder = meta.is_dir();
        let root = req.path.clone();
        // An image's preview is made as it is hashed (ADR-028 F-9): a folder has none.
        let hashed = tokio::task::spawn_blocking(move || {
            if folder {
                crate::node::folder::walk(&root).map(|found| {
                    let list: Vec<_> = found.iter().map(|f| f.listed.clone()).collect();
                    (
                        crate::node::folder::list_sha256(&list),
                        list.iter().map(|f| f.size).sum(),
                        found,
                        None,
                    )
                })
            } else {
                crate::node::folder::digest(&root).map(|(sha, size)| {
                    (sha, size, Vec::new(), crate::node::preview::of_file(&root))
                })
            }
        })
        .await
        .map_err(|e| format!("hashing the share: {e}"))?;
        let (sha256, size, files, preview) = hashed?;
        let (served, name) = (req.path.clone(), base);
        // The tag names the content and **this share**: two shares of the same file are two
        // services, and stopping one never withdraws the other (V210-72).
        let tag = format!("file-{}-{}", &sha256[..16], hex(&nonce));
        if let Some(obj) = envelope.as_object_mut() {
            let body_empty = obj
                .get("body")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty);
            if body_empty {
                let said = if folder {
                    format!("sharing {name}/ ({} files, {size} bytes)", files.len())
                } else {
                    format!("sharing {name} ({size} bytes)")
                };
                obj.insert("body".into(), said.into());
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
                d.insert("kind".into(), if folder { "folder" } else { "file" }.into());
                // The list itself is served (F-8); the message says how many files it holds, and
                // the SHA-256 above pins it.
                if folder {
                    d.insert("files".into(), (files.len() as u64).into());
                }
                if let Some(p) = &preview {
                    d.insert("image".into(), p.json());
                }
            }
        }
        // The sharing session's name, as on every message from it (ADR-029 MD-2).
        let text = crate::node::sessions::fill_name(&self.paths, &envelope.to_string());
        let only = match &req.session {
            None => Only::Anyone,
            Some(SessionShare::Out { .. }) => Only::Drive,
            Some(SessionShare::In { node }) => Only::Node(*node),
        };
        let fail = |e: String| e;
        let (stop, stopping) = watch::channel(false);
        let fetched = Arc::new(AtomicU64::new(0));
        let what = if folder {
            let by_path: BTreeMap<_, _> = files
                .iter()
                .map(|f| (f.listed.path.clone(), f.clone()))
                .collect();
            Served::Folder {
                root: served.clone(),
                list: list_bytes(&by_path),
                files: by_path,
            }
        } else {
            Served::File {
                path: served.clone(),
                name: name.clone(),
                size,
            }
        };
        let (server, local) = serve(
            what,
            Arc::clone(&fetched),
            self.witness(&tag, req.channel_id, only.clone()),
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
        let announced = match &req.session {
            None => self.announce(req.channel_id, &text).await,
            Some(SessionShare::Out { session_id }) => {
                self.announce_in_session(req.channel_id, session_id, &envelope)
                    .await
            }
            // Into a Session: its node hears of it on the drive request, and nothing is posted.
            Some(SessionShare::In { .. }) => Ok((String::new(), now_ms())),
        };
        let (entry, created) = match announced {
            Ok(found) => found,
            Err(e) => {
                let _ = self
                    .apply(NodeCommand::RemoveService {
                        channel_id: req.channel_id,
                        service_tag: tag.clone(),
                    })
                    .await;
                drop(active_parts);
                return Err(fail(format!("cannot announce the share: {e}")));
            }
        };
        if !entry.is_empty() {
            self.pulled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .announced(&tag, req.channel_id, &entry);
        }
        let record = Record {
            tag: tag.clone(),
            room: req.channel_id,
            name,
            size,
            sha256,
            served,
            files,
            entry,
            created_ms: created,
            count: req.count,
            until_ms: if req.for_secs == 0 {
                0
            } else {
                now_ms().saturating_add(req.for_secs.saturating_mul(1_000))
            },
            only,
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

    /// Post a room share's announcement (F-1), and the entry and time it landed at, from the
    /// node's own word that it did; an empty entry if that word did not come.
    async fn announce(&self, channel_id: Digest32, text: &str) -> Result<(String, u64), String> {
        let me = self.view.borrow().identity.as_ref().map(|i| i.fingerprint);
        let mut events = self.events.subscribe();
        let deadline = tokio::time::Instant::now() + POST_PATIENCE;
        loop {
            match self
                .apply(NodeCommand::SendText {
                    channel_id,
                    text: text.to_owned(),
                })
                .await
            {
                Outcome::Done => break,
                Outcome::Failed(Fault::RoomNotSynced) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                other => return Err(other.to_string()),
            }
        }
        let mut entry = String::new();
        let mut created = now_ms();
        let until = tokio::time::Instant::now() + ENTRY_PATIENCE;
        while let Ok(Ok(ev)) = tokio::time::timeout_at(until, events.recv()).await {
            if let NodeEvent::NewEntry { channel_id: c, row } = ev {
                if c == channel_id && Some(row.author) == me && row.text == text {
                    entry = b32_encode(&row.entry_hash);
                    created = row.created_millis;
                    break;
                }
            }
        }
        Ok((entry, created))
    }

    /// Announce a file out of Session `session_id` as that Session's `file` entry (ADR-029 SC-1,
    /// #546), sealed under this node's drive key: only members it trusts with drive learn its
    /// name, size and tag. Its entry is the share's, as a room share's message is.
    async fn announce_in_session(
        &self,
        channel_id: Digest32,
        session_id: &str,
        envelope: &serde_json::Value,
    ) -> Result<(String, u64), String> {
        let data = &envelope["data"];
        let mut body = serde_json::json!({
            "v": vox_agentcomms::activity::VERSION,
            "session": session_id,
            "kind": "file",
            "dir": "out",
            "ts": now_ms(),
        });
        if let Some(obj) = body.as_object_mut() {
            for k in [
                "name", "size", "sha256", "tag", "http", "kind", "files", "image", "note",
            ] {
                if let Some(v) = data.get(k) {
                    // The data's `kind` (file or folder) is the entry's `type`: its `kind` is the
                    // activity's.
                    let key = if k == "kind" { "type" } else { k };
                    obj.insert(key.into(), v.clone());
                }
            }
        }
        let deadline = tokio::time::Instant::now() + POST_PATIENCE;
        loop {
            match self
                .apply(NodeCommand::AppendSession {
                    channel_id,
                    session_id: session_id.to_owned(),
                    body: body.to_string(),
                })
                .await
            {
                Outcome::Appended(entry) => return Ok((b32_encode(&entry), now_ms())),
                Outcome::Failed(Fault::RoomNotSynced) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                other => return Err(other.to_string()),
            }
        }
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
            // A file by its bytes; a folder by every listed file's bytes, and its times, which its
            // serving checks.
            let (served, listed) = (record.served.clone(), record.files.clone());
            let still = tokio::task::spawn_blocking(move || {
                if listed.is_empty() {
                    crate::node::folder::digest(&served).ok()
                } else {
                    listed
                        .iter()
                        .all(|f| {
                            let file = served.join(&f.listed.path);
                            std::fs::symlink_metadata(&file)
                                .is_ok_and(|m| crate::node::folder::modified_ns(&m) == f.modified)
                                && crate::node::folder::digest(&file).ok()
                                    == Some((f.listed.sha256.clone(), f.listed.size))
                        })
                        .then(|| {
                            (
                                crate::node::folder::list_sha256(
                                    &listed.iter().map(|f| f.listed.clone()).collect::<Vec<_>>(),
                                ),
                                listed.iter().map(|f| f.listed.size).sum(),
                            )
                        })
                }
            })
            .await
            .ok()
            .flatten();
            if still.as_ref() != Some(&(record.sha256.clone(), record.size)) {
                self.say(format!(
                    "no longer sharing {}: it changed or went since it was shared, and a share \
                     serves only the bytes it announced",
                    record.name
                ));
                let _ = std::fs::remove_file(&file);
                continue;
            }
            let (stop, stopping) = watch::channel(false);
            let fetched = Arc::new(AtomicU64::new(0));
            let Ok((server, local)) = serve(
                Served::of(&record),
                Arc::clone(&fetched),
                self.witness(&record.tag, record.room, record.only.clone()),
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
        let now = now_ms();
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
                        Some(_) if r.until_ms > 0 && now >= r.until_ms => {
                            Verdict::Stop("its --for is up".into())
                        }
                        Some(_) => {
                            match view.open_channels.iter().find(|d| d.channel_id == r.room) {
                                Some(d)
                                    if d.retention > 0
                                        && now
                                            >= r.created_ms.saturating_add(
                                                d.retention.saturating_mul(1_000),
                                            ) =>
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
/// Who a share's completed fetches are recorded against, and how its server tells them apart.
#[derive(Clone)]
struct Witness {
    book: Arc<std::sync::Mutex<PulledBook>>,
    tag: String,
    room: Digest32,
    /// This node, whose served tunnels say which member a connection is.
    owner: Option<Digest32>,
    /// Where the node says things to its operator.
    events: broadcast::Sender<NodeEvent>,
    /// The listed files already said to have changed, said once each.
    said: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    /// Who it may serve.
    only: Only,
    /// The node's view: its keyring's drive entries, read at each fetch.
    view: watch::Receiver<NodeView>,
}

impl Witness {
    /// The member a connection from `from` came through a tunnel for.
    fn member(&self, from: Option<SocketAddr>) -> Option<Digest32> {
        crate::transport::quic::tunnel_peer_at(&self.owner?, from?)
    }

    /// Whether `member` may fetch this share now (ADR-029 SC-2, DR-1): any member for a room
    /// share; for a Session's, one this node trusts with drive, or the Session's node.
    fn allowed(&self, member: Option<Digest32>) -> bool {
        match &self.only {
            Only::Anyone => true,
            Only::Drive => member.is_some_and(|m| self.view.borrow().drive.contains(&m)),
            Only::Node(n) => member == Some(*n),
        }
    }

    /// A listed file changed since it was listed, and was refused: said to the sharer once.
    fn changed(&self, path: &str) {
        let first = self
            .said
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_owned());
        if first {
            let _ = self.events.send(NodeEvent::NodeNote {
                note: format!("{path} changed since you shared it; share the folder again"),
            });
        }
    }

    fn pulled(&self, member: Digest32) {
        self.book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pulled(&self.tag, self.room, member);
    }
}

/// What one share serves.
enum Served {
    /// A file: whatever the request names, the answer is the file.
    File {
        path: PathBuf,
        name: String,
        size: u64,
    },
    /// A folder: its list at [`crate::node::folder::LIST_TARGET`], and each listed file at its own
    /// path, read from the folder (ADR-028 F-8).
    Folder {
        root: PathBuf,
        files: BTreeMap<String, crate::node::folder::Found>,
        /// The list, as it is served.
        list: Arc<Vec<u8>>,
    },
}

/// What a request is answered with.
enum Body {
    /// A file, read as it is sent.
    File(PathBuf),
    /// Bytes held here: a folder's list.
    Bytes(Arc<Vec<u8>>),
}

/// A folder's list as it is served: the canonical `[[path, size, sha256], …]`.
fn list_bytes(files: &BTreeMap<String, crate::node::folder::Found>) -> Arc<Vec<u8>> {
    let list: Vec<_> = files.values().map(|f| f.listed.clone()).collect();
    Arc::new(crate::node::folder::to_json(&list).to_string().into_bytes())
}

impl Served {
    fn of(record: &Record) -> Self {
        if record.files.is_empty() {
            Self::File {
                path: record.served.clone(),
                name: record.name.clone(),
                size: record.size,
            }
        } else {
            let files: BTreeMap<_, _> = record
                .files
                .iter()
                .map(|f| (f.listed.path.clone(), f.clone()))
                .collect();
            Self::Folder {
                root: record.served.clone(),
                list: list_bytes(&files),
                files,
            }
        }
    }

    /// What a request for `target` is answered with: the body, its name and size; or why not.
    fn resolve(&self, target: &str) -> Result<(Body, String, u64), Refused> {
        match self {
            Self::File { path, name, size } => Ok((Body::File(path.clone()), name.clone(), *size)),
            Self::Folder { list, .. } if target == crate::node::folder::LIST_TARGET => Ok((
                Body::Bytes(Arc::clone(list)),
                "list.json".to_owned(),
                list.len() as u64,
            )),
            Self::Folder { root, files, .. } => {
                let path = crate::node::folder::from_url_path(target).ok_or(Refused::NotListed)?;
                let f = files.get(&path).ok_or(Refused::NotListed)?;
                let file = root.join(&path);
                // **Announced content or nothing** (F-8): a file whose size or time moved since
                // it was listed is not served under the announcement.
                let same = std::fs::symlink_metadata(&file).is_ok_and(|m| {
                    m.is_file()
                        && m.len() == f.listed.size
                        && crate::node::folder::modified_ns(&m) == f.modified
                });
                if !same {
                    return Err(Refused::Changed(path));
                }
                let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
                Ok((Body::File(file), name, f.listed.size))
            }
        }
    }

    /// How many files a member must fetch whole to have pulled it.
    fn count(&self) -> usize {
        match self {
            Self::File { .. } => 1,
            Self::Folder { files, .. } => files.len(),
        }
    }
}

/// Why a request was not answered with a file.
enum Refused {
    /// It names nothing the share lists.
    NotListed,
    /// It names a listed file that changed since it was listed.
    Changed(String),
}

async fn serve(
    what: Served,
    fetched: Arc<AtomicU64>,
    witness: Witness,
    stopping: watch::Receiver<bool>,
) -> Result<(tokio::task::JoinHandle<()>, SocketAddr), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| format!("cannot listen locally: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("cannot read the local address: {e}"))?;
    let what = Arc::new(what);
    // Which of a folder's files each member has fetched whole, since it last fetched them all.
    let got: Arc<std::sync::Mutex<BTreeMap<Digest32, std::collections::BTreeSet<String>>>> =
        Arc::default();
    let server = tokio::spawn(async move {
        while let Ok((sock, from)) = listener.accept().await {
            let (what, fetched, witness, stopping, got) = (
                Arc::clone(&what),
                Arc::clone(&fetched),
                witness.clone(),
                stopping.clone(),
                Arc::clone(&got),
            );
            tokio::spawn(async move {
                // Which member this is, asked of the tunnel it came through once it has sent its
                // request: by then the tunnel has said where its connection comes from.
                let (whole, member, path) = serve_one(sock, &what, stopping, &witness, || {
                    witness.member(Some(from))
                })
                .await;
                if !whole {
                    return;
                }
                // **Pulled means the whole share reached it** (F-7): every listed file, each
                // whole. A fetch cut short is not one.
                let complete = match (&*what, member) {
                    (Served::File { .. }, _) => true,
                    (Served::Folder { .. }, None) => false,
                    (Served::Folder { .. }, Some(m)) => {
                        let mut got = got
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let set = got.entry(m).or_default();
                        // The list is not a file of the folder.
                        if !path.is_empty() {
                            set.insert(path);
                        }
                        let all = set.len() >= what.count();
                        if all {
                            got.remove(&m);
                        }
                        all
                    }
                };
                if complete {
                    fetched.fetch_add(1, Ordering::SeqCst);
                    if let Some(m) = member {
                        witness.pulled(m);
                    }
                }
            });
        }
    });
    Ok((server, local))
}

/// Answer one HTTP request: with the file, for a file share; with the listed file it names, for
/// a folder. Returns whether the receiver took every byte, who it is, as `identify` says once its
/// request has arrived, and the path it asked for.
async fn serve_one(
    mut sock: tokio::net::TcpStream,
    what: &Served,
    mut stopping: watch::Receiver<bool>,
    witness: &Witness,
    identify: impl FnOnce() -> Option<Digest32>,
) -> (bool, Option<Digest32>, String) {
    let mut member = None;
    let mut asked = String::new();
    let whole = async {
        // Read the request head (bounded).
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
            match tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => head.extend_from_slice(&buf[..n]),
                _ => return Some(false),
            }
        }
        member = identify();
        // **A Session's file goes only to whom the Session is for** (ADR-029 SC-2, DR-1): any
        // other member, though the tunnel let it in and it knows the tag, is refused.
        if !witness.allowed(member) {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Some(false);
        }
        let is_head = head.starts_with(b"HEAD ");
        let target = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .and_then(|l| l.split(' ').nth(1).map(str::to_owned))
            .unwrap_or_default();
        let (body, name, size) = match what.resolve(&target) {
            Ok(found) => found,
            Err(refused) => {
                let status = match refused {
                    Refused::NotListed => "404 Not Found",
                    Refused::Changed(path) => {
                        witness.changed(&path);
                        "409 Conflict"
                    }
                };
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
                return Some(false);
            }
        };
        asked = crate::node::folder::from_url_path(&target).unwrap_or_default();
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
        let mut f: Box<dyn std::io::Read + Send> = match body {
            Body::File(file) => match std::fs::File::open(&file) {
                Ok(f) => Box::new(f),
                Err(_) => return None,
            },
            Body::Bytes(b) => Box::new(std::io::Cursor::new(b.to_vec())),
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut sent = 0u64;
        loop {
            // Losing drive cuts a fetch under way: reset, never a clean end.
            if !witness.allowed(member) {
                return None;
            }
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
        Some(done) => (done, member, asked),
        // Any other ending is a reset: a clean close would say "that was all of it".
        None => {
            crate::tunnel::session::abort_after_drain(sock).await;
            (false, member, asked)
        }
    }
}
