//! Authenticated, session-owned OMP activity and private Drive bridge.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use vox_agentcomms::activity::{one_line, VERSION};
use vox_core::node::content::MAX_TEXT_LEN;
use vox_core::node::paths::NodeName;

use crate::codex_mirror::Steer;

const MAX_LINE: usize = 4 << 20;
const MAX_FOLLOWS: usize = 64;
const MAX_COMMANDS: usize = 32;
const MAX_COMMAND_BYTES: usize = 64 << 10;
const CALL_WITHIN: Duration = Duration::from_secs(30);
const MAX_SEMANTIC: usize = 1 << 20;
const MAX_SNAPSHOT: usize = 4 << 20;
const MAX_SEMANTIC_PARTS: u64 = 64;

struct SemanticChunk {
    cursor: u64,
    parts: u64,
    next: u64,
    bytes: Vec<u8>,
}

struct SemanticState {
    generation: Option<u64>,
    epoch: String,
    cursor: u64,
    chunk: Option<SemanticChunk>,
    snapshot: Option<Vec<Value>>,
    snapshot_bytes: usize,
    ready: bool,
    calls: BTreeMap<String, bool>,
}

impl Default for SemanticState {
    fn default() -> Self {
        Self {
            generation: None,
            epoch: String::new(),
            cursor: 1,
            chunk: None,
            snapshot: None,
            snapshot_bytes: 0,
            ready: false,
            calls: BTreeMap::new(),
        }
    }
}

fn semantic_shape_ok(root: &Value) -> bool {
    let mut stack = vec![(root, 0usize)];
    let mut seen = 0usize;
    while let Some((value, depth)) = stack.pop() {
        seen += 1;
        if seen > 16_384 || depth > 24 {
            return false;
        }
        match value {
            Value::Array(items) => {
                if stack.len().saturating_add(items.len()) > 16_384 {
                    return false;
                }
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            Value::Object(items) => {
                if stack.len().saturating_add(items.len()) > 16_384 {
                    return false;
                }
                stack.extend(items.values().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    true
}

/// Handler for an explicitly reported native session shutdown.
pub type SessionEnd = Arc<
    dyn Fn(NodeName, crate::wake::Session) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;
/// Admit activity under the exact registration captured by its follower.
pub type Activity = Arc<
    dyn Fn(
            NodeName,
            crate::wake::Session,
            Vec<String>,
        )
            -> Pin<Box<dyn Future<Output = vox_core::node::daemonipc::SessionAdmission> + Send>>
        + Send
        + Sync,
>;
/// Rename only the exact registration captured by the follower.
pub type Rename = Arc<
    dyn Fn(NodeName, crate::wake::Session, String) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;
/// Offer a verified, branch-scoped OMP image through the Session's file service.
pub type MediaOffer = Arc<
    dyn Fn(
            NodeName,
            crate::wake::Session,
            u64,
            vox_core::node::shares::media::Descriptor,
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

#[derive(Default)]
struct MediaRegistry {
    generation: Option<u64>,
    ids: std::collections::BTreeSet<String>,
    attachments: std::collections::BTreeSet<(String, String)>,
}

#[derive(Clone)]
struct Connection {
    node: NodeName,
    endpoint: String,
    token: String,
    registration: crate::wake::Session,
    commands: mpsc::Sender<Cmd>,
    media: Arc<Mutex<MediaRegistry>>,
    stop: Arc<Notify>,
    stop_reported: Arc<std::sync::atomic::AtomicBool>,
}

/// One native OMP connection per registered session.
pub struct OmpMirror {
    rename: Rename,
    session_end: SessionEnd,
    activity: Activity,
    media_offer: MediaOffer,
    conns: Mutex<BTreeMap<String, Connection>>,
    receipts: Arc<Mutex<BTreeMap<String, (String, crate::host::OmpDriveGuard)>>>,
    live: Arc<Semaphore>,
}

/// Evidence about a control which was not confirmed by the native bridge.
#[derive(Debug)]
pub(crate) enum OmpControlError {
    /// No native control was sent or the bridge explicitly refused it.
    NotSent(String),
    /// A write may have reached the bridge; delivery must not be inferred or replayed.
    Unconfirmed(String),
}

impl OmpControlError {
    pub(crate) fn message(self) -> String {
        match self {
            Self::NotSent(message) | Self::Unconfirmed(message) => message,
        }
    }
}

impl From<String> for OmpControlError {
    fn from(message: String) -> Self {
        Self::NotSent(message)
    }
}

impl From<&str> for OmpControlError {
    fn from(message: &str) -> Self {
        Self::NotSent(message.to_owned())
    }
}

enum Cmd {
    Steer {
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
        drive: Option<Box<crate::host::OmpDriveGuard>>,
        reply: oneshot::Sender<Result<String, OmpControlError>>,
    },
    Media {
        generation: u64,
        id: String,
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}

struct PendingCall {
    reply: oneshot::Sender<Result<String, OmpControlError>>,
    expires: tokio::time::Instant,
    deferred: Option<String>,
}

struct Deferred {
    text: String,
    guard: crate::host::OmpDriveGuard,
}

fn opaque_id() -> Result<String, String> {
    use std::fmt::Write as _;
    let bytes = vox_core::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
}

impl Deferred {
    fn frame(&self, id: &str) -> String {
        format!(
            "{}\n",
            json!({"type":"materialized","id":id,"ok":true,"text":self.text,
                "operator":self.guard.operator,"room":self.guard.room})
        )
    }
}

impl OmpMirror {
    /// Create followers posting through the shared Session sink.
    #[must_use]
    pub fn new(
        rename: Rename,
        session_end: SessionEnd,
        activity: Activity,
        media_offer: MediaOffer,
    ) -> Arc<Self> {
        Arc::new(Self {
            rename,
            session_end,
            activity,
            media_offer,
            conns: Mutex::new(BTreeMap::new()),
            receipts: Arc::new(Mutex::new(BTreeMap::new())),
            live: Arc::new(Semaphore::new(MAX_FOLLOWS)),
        })
    }

    fn conns(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Connection>> {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Follow this exact native session and replace a changed endpoint or token.
    pub fn watch(
        self: &Arc<Self>,
        paths: &vox_core::node::paths::Paths,
        node: &NodeName,
        registration: &crate::wake::Session,
    ) {
        let session = registration.session.as_str();
        let endpoint = registration.mirror.as_str();
        let token = registration.token.as_str();
        let mut conns = self.conns();
        let same = |conn: &Connection| {
            &conn.node == node
                && conn.registration.same(registration)
                && conn.registration.first_seen_ms == registration.first_seen_ms
                && conn.registration.mirror == registration.mirror
        };
        if conns
            .get(session)
            .is_some_and(|conn| same(conn) && !conn.commands.is_closed())
        {
            return;
        }
        let stop_reported = conns.get(session).filter(|conn| same(conn)).map_or_else(
            || Arc::new(std::sync::atomic::AtomicBool::new(false)),
            |conn| Arc::clone(&conn.stop_reported),
        );
        if let Some(old) = conns.remove(session) {
            old.stop.notify_one();
        }
        let Ok(permit) = Arc::clone(&self.live).try_acquire_owned() else {
            eprintln!("vox daemon: {node}: OMP Session {session} observation refused: {MAX_FOLLOWS} live followers already active");
            return;
        };
        let Ok(epoch) = opaque_id() else {
            eprintln!("vox daemon: {node}: cannot allocate an OMP snapshot identity");
            return;
        };
        let (tx, rx) = mpsc::channel(MAX_COMMANDS);
        let stop = Arc::new(Notify::new());
        let media_registry = Arc::new(Mutex::new(MediaRegistry::default()));
        conns.insert(
            session.to_owned(),
            Connection {
                node: node.clone(),
                endpoint: endpoint.to_owned(),
                token: token.to_owned(),
                registration: registration.clone(),
                commands: tx.clone(),
                media: Arc::clone(&media_registry),
                stop: Arc::clone(&stop),
                stop_reported: Arc::clone(&stop_reported),
            },
        );
        let follow = Follow {
            node: node.clone(),
            session: session.to_owned(),
            rename: Arc::clone(&self.rename),
            paths: paths.clone(),
            registration: registration.clone(),
            session_end: Arc::clone(&self.session_end),
            activity: Arc::clone(&self.activity),
            media_offer: Arc::clone(&self.media_offer),
            media_registry: Arc::clone(&media_registry),
            calls: BTreeMap::new(),
            deferred: BTreeMap::new(),
            receipts: Arc::clone(&self.receipts),
            semantic: SemanticState {
                epoch,
                ..SemanticState::default()
            },
            media: BTreeMap::new(),
            next_id: 1,
            failed: false,
            ended: false,
            stop_reported,
        };
        let endpoint = endpoint.to_owned();
        let token = token.to_owned();
        tokio::spawn(async move {
            let _permit = permit;
            follow.run(&endpoint, &token, rx, stop).await;
        });
    }

    /// Stop following a session that ended.
    pub fn end(&self, session: &str) {
        if let Some(conn) = self.conns().remove(session) {
            conn.stop.notify_one();
        }
    }

    pub(crate) async fn steer_guarded(
        &self,
        node: &NodeName,
        registration: &crate::wake::Session,
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
        drive: Option<crate::host::OmpDriveGuard>,
    ) -> Result<String, String> {
        self.steer_guarded_typed(node, registration, steer, guard, drive)
            .await
            .map_err(OmpControlError::message)
    }

    pub(crate) async fn steer_guarded_typed(
        &self,
        node: &NodeName,
        registration: &crate::wake::Session,
        steer: Steer,
        guard: Option<crate::host::room_pause::InterruptGuard>,
        drive: Option<crate::host::OmpDriveGuard>,
    ) -> Result<String, OmpControlError> {
        if matches!(&steer, Steer::Slash { .. }) {
            return Err(
                "OMP slash commands are unavailable through Vox; use the OMP terminal".into(),
            );
        }
        if matches!(&steer, Steer::Text(text) if text.len() > MAX_COMMAND_BYTES) {
            return Err(
                format!("OMP control exceeds {MAX_COMMAND_BYTES} bytes; nothing was sent").into(),
            );
        }
        let conn = self
            .conns()
            .get(&registration.session)
            .filter(|conn| {
                &conn.node == node
                    && conn.endpoint == registration.mirror
                    && conn.token == registration.token
            })
            .cloned()
            .ok_or_else(|| "Vox is not connected to this exact OMP session route".to_owned())?;
        let (reply, rx) = oneshot::channel();
        conn.commands
            .try_send(Cmd::Steer {
                steer,
                guard,
                drive: drive.map(Box::new),
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    "OMP's control queue is full; nothing was sent".to_owned()
                }
                mpsc::error::TrySendError::Closed(_) => {
                    "Vox's connection to this OMP session has closed; nothing was sent".to_owned()
                }
            })?;
        rx.await.unwrap_or_else(|_| Err(OmpControlError::Unconfirmed(
            "OMP's connection closed; the control outcome is unknown, do not assume it is safe to repeat".into())))
    }

    pub(crate) fn media_current(
        &self,
        node: &NodeName,
        registration: &crate::wake::Session,
        generation: u64,
        id: &str,
    ) -> bool {
        let conn = self
            .conns()
            .get(&registration.session)
            .filter(|conn| {
                &conn.node == node
                    && conn.registration.same(registration)
                    && conn.registration.first_seen_ms == registration.first_seen_ms
                    && conn.endpoint == registration.mirror
                    && conn.token == registration.token
                    && !conn.commands.is_closed()
            })
            .cloned();
        conn.is_some_and(|conn| {
            let media = conn
                .media
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            media.generation == Some(generation) && media.ids.contains(id)
        })
    }

    pub(crate) async fn media(
        &self,
        node: &NodeName,
        registration: &crate::wake::Session,
        generation: u64,
        id: String,
    ) -> Result<Vec<u8>, String> {
        let conn = self
            .conns()
            .get(&registration.session)
            .filter(|conn| {
                &conn.node == node
                    && conn.registration.same(registration)
                    && conn.registration.first_seen_ms == registration.first_seen_ms
                    && conn.endpoint == registration.mirror
                    && conn.token == registration.token
            })
            .cloned()
            .ok_or_else(|| "The exact OMP Session route is unavailable".to_owned())?;
        let (reply, rx) = oneshot::channel();
        conn.commands
            .try_send(Cmd::Media {
                generation,
                id,
                reply,
            })
            .map_err(|_| "The OMP media request queue is unavailable".to_owned())?;
        tokio::time::timeout(CALL_WITHIN, rx)
            .await
            .map_err(|_| "The OMP media request timed out".to_owned())?
            .map_err(|_| "The OMP media connection closed".to_owned())?
    }
}

type MediaWaiter = oneshot::Sender<Result<Vec<u8>, String>>;

struct Follow {
    node: NodeName,
    session: String,
    rename: Rename,
    paths: vox_core::node::paths::Paths,
    registration: crate::wake::Session,
    session_end: SessionEnd,
    activity: Activity,
    media_offer: MediaOffer,
    media_registry: Arc<Mutex<MediaRegistry>>,
    calls: BTreeMap<u64, PendingCall>,
    deferred: BTreeMap<String, Deferred>,
    receipts: Arc<Mutex<BTreeMap<String, (String, crate::host::OmpDriveGuard)>>>,
    semantic: SemanticState,
    /// One native request in flight per media id; every waiter for it receives that answer.
    media: BTreeMap<String, Vec<MediaWaiter>>,
    next_id: u64,
    failed: bool,
    stop_reported: Arc<std::sync::atomic::AtomicBool>,
    ended: bool,
}

impl Follow {
    async fn run(
        mut self,
        endpoint: &str,
        token: &str,
        mut rx: mpsc::Receiver<Cmd>,
        stop: Arc<Notify>,
    ) {
        let stream = tokio::select! {
            _ = stop.notified() => return,
            result = tokio::time::timeout(CALL_WITHIN, tokio::net::UnixStream::connect(endpoint)) => match result {
                Ok(Ok(stream)) => stream,
                _ => { self.fail("the native bridge connection could not be opened").await; return; }
            }
        };
        let (read, write) = stream.into_split();
        let mut write = Arc::new(write);
        let hello = format!(
            "{}\n{}\n",
            json!({"type":"auth", "token":token}),
            json!({"type":"subscribe", "session":self.session})
        );
        if !Self::write(&write, &hello).await {
            self.fail("the native bridge handshake failed").await;
            return;
        }
        let mut lines = BufReader::new(read);
        let mut line = Vec::new();
        let mut subscribed = false;
        let deadline = tokio::time::Instant::now() + CALL_WITHIN;
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let remaining = (MAX_LINE + 1 - line.len()) as u64;
            tokio::select! {
                biased;
                _ = stop.notified() => break,
                cmd = rx.recv(), if subscribed => match cmd {
                    None => break,
                    Some(Cmd::Steer { steer, guard, drive, reply }) => {
                        if guard.as_ref().is_some_and(|guard| !guard.allowed()) {
                            let _ = reply.send(Err("room pause, authority or Session changed; the interrupt was not sent".into()));
                            continue;
                        }
                        if let Some(call) = self.call(steer, drive.map(|guard| *guard), reply) {
                            let written = if let Some(guard) = guard {
                                tokio::select! {
                                    biased;
                                    () = guard.cancelled() => false,
                                    written = Self::write(&write, &call) => written,
                                }
                            } else { Self::write(&write, &call).await };
                            if !written {
                                self.fail("a control write failed or was cancelled; its outcome is unknown, do not assume it is safe to repeat").await;
                                break;
                            }
                        }
                    }
                    Some(Cmd::Media { generation, id, reply }) => {
                        for waiters in self.media.values_mut() {
                            waiters.retain(|reply| !reply.is_closed());
                        }
                        let admitted = {
                            let media = self.media_registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                            media.generation == Some(generation) && media.ids.contains(&id)
                        };
                        // Bounded by owed answers and waiters together: an id whose waiters left
                        // still owes the extension's one answer.
                        let pending: usize = self.media.values().map(|waiters| waiters.len().max(1)).sum();
                        let joining = self.media.get(&id).map(Vec::is_empty);
                        let needed = usize::from(joining != Some(true));
                        if !admitted || self.semantic.generation != Some(generation) || self.semantic.snapshot.is_some()
                            || id.len() > 256 || id.is_empty() || pending + needed > 8 {
                            let _ = reply.send(Err("The image is stale, unavailable or busy".into()));
                            continue;
                        }
                        if let Some(waiters) = self.media.get_mut(&id) {
                            // Same id already asked: wait for that one answer, in order.
                            waiters.push(reply);
                            continue;
                        }
                        let frame = format!("{}\n", json!({"type":"media", "id":id}));
                        self.media.insert(id, vec![reply]);
                        if !Self::write(&write, &frame).await {
                            self.fail("the OMP media request could not be written").await;
                            break;
                        }
                    }
                },
                _ = timer.tick() => {
                    if !subscribed && tokio::time::Instant::now() >= deadline {
                        self.fail("the native bridge did not confirm the session subscription").await;
                        break;
                    }
                    if self.calls.values().any(|call| call.expires <= tokio::time::Instant::now()) {
                        self.fail("OMP did not answer a control within 30 seconds; its outcome is unknown, do not assume it is safe to repeat").await;
                        break;
                    }
                },
                n = async { (&mut lines).take(remaining).read_until(b'\n', &mut line).await } => {
                    match n {
                        Ok(0) | Err(_) => { self.fail("the native bridge connection closed; pending control outcomes are unknown").await; break; }
                        Ok(_) if line.len() > MAX_LINE => { self.fail("an OMP event exceeds the 4 MiB line bound").await; break; }
                        Ok(_) if !line.ends_with(b"\n") => { self.fail("the native bridge closed with an incomplete frame").await; break; }
                        Ok(_) => {
                            match serde_json::from_slice::<Value>(&line) {
                                Ok(v) if !subscribed => {
                                    if v.get("type").and_then(Value::as_str) == Some("subscribed") && v.get("session").and_then(Value::as_str) == Some(self.session.as_str()) {
                                        subscribed = true;
                                        self.stop_reported.store(false, std::sync::atomic::Ordering::SeqCst);
                                    } else {
                                        self.fail("the native bridge did not confirm the exact session").await;
                                    }
                                }
                                Ok(v) if v.get("type").and_then(Value::as_str) == Some("materialize") => {
                                    if !self.materialize(&v, &mut write).await {
                                        self.fail("a materialization response failed; its outcome is unknown").await;
                                    }
                                }
                                Ok(v) => self.line(&v).await,
                                Err(_) => self.fail("the native bridge supplied malformed JSON").await,
                            }
                            if self.failed { break; }
                        }
                    }
                    line.clear();
                }
            }
        }
        *self
            .media_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = MediaRegistry::default();
        for (_, call) in std::mem::take(&mut self.calls) {
            let _ = call.reply.send(Err(OmpControlError::Unconfirmed(
                "the OMP connection closed; the control outcome is unknown, do not assume it is safe to repeat".into())));
        }
    }

    async fn write(write: &Arc<tokio::net::unix::OwnedWriteHalf>, line: &str) -> bool {
        let send = async {
            let mut remaining = line.as_bytes();
            while !remaining.is_empty() {
                write.writable().await?;
                match write.try_write(remaining) {
                    Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
                    Ok(n) => remaining = &remaining[n..],
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                }
            }
            Ok::<(), std::io::Error>(())
        };
        matches!(tokio::time::timeout(CALL_WITHIN, send).await, Ok(Ok(())))
    }

    fn call(
        &mut self,
        steer: Steer,
        drive: Option<crate::host::OmpDriveGuard>,
        reply: oneshot::Sender<Result<String, OmpControlError>>,
    ) -> Option<String> {
        if self.calls.len() >= MAX_COMMANDS {
            let _ = reply.send(Err(
                "OMP has 32 unanswered controls; nothing was sent".into()
            ));
            return None;
        }
        let id = self.next_id;
        let Some(next) = id.checked_add(1) else {
            let _ = reply.send(Err(
                "OMP control sequence exhausted; nothing was sent".into()
            ));
            return None;
        };
        let mut deferred = None;
        let action = match steer {
            Steer::Text(text) => {
                let Some(guard) = drive else {
                    let _ = reply.send(Err(
                        "OMP text needs current Drive authorization; nothing was sent".into(),
                    ));
                    return None;
                };
                if !guard.allowed() {
                    let _ = reply.send(Err(
                        "the driver, room or Session changed; nothing was sent".into(),
                    ));
                    return None;
                }
                self.deferred.retain(|_, item| item.guard.allowed());
                let receipt_count = {
                    let mut receipts = self
                        .receipts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    receipts.retain(|_, (_, guard)| guard.allowed());
                    receipts
                        .values()
                        .filter(|(session, _)| session == &self.session)
                        .count()
                };
                if self.deferred.len() + receipt_count >= MAX_COMMANDS {
                    let _ = reply.send(Err(
                        "OMP has 32 queued Drive messages; nothing was sent".into()
                    ));
                    return None;
                }
                let key = match opaque_id() {
                    Ok(key)
                        if !self.deferred.contains_key(&key)
                            && !self
                                .receipts
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .contains_key(&key) =>
                    {
                        key
                    }
                    _ => {
                        let _ = reply.send(Err(
                            "a unique OMP Drive capability could not be created; nothing was sent"
                                .into(),
                        ));
                        return None;
                    }
                };
                let item = Deferred { text, guard };
                if item.frame(&key).len() > MAX_COMMAND_BYTES {
                    let _ = reply.send(Err(
                        "encoded OMP Drive message exceeds 64 KiB; nothing was sent".into(),
                    ));
                    return None;
                }
                self.deferred.insert(key.clone(), item);
                deferred = Some(key.clone());
                json!({"type":"prompt", "id":key})
            }
            Steer::Interrupt => json!({"type":"abort"}),
            Steer::Stop => {
                let _ = reply.send(Err(
                    "OMP cannot end the Session through Vox; use Interrupt for the current operation"
                        .into(),
                ));
                return None;
            }
            Steer::Slash { .. } => {
                let _ = reply.send(Err("OMP slash commands are unavailable through Vox".into()));
                return None;
            }
        };
        let line = format!("{}\n", json!({"type":"call", "id":id, "action":action}));
        if line.len() > MAX_COMMAND_BYTES {
            let _ = reply.send(Err(
                "encoded OMP control exceeds 64 KiB; nothing was sent".into()
            ));
            return None;
        }
        self.next_id = next;
        self.calls.insert(
            id,
            PendingCall {
                reply,
                deferred,
                expires: tokio::time::Instant::now() + CALL_WITHIN,
            },
        );
        Some(line)
    }

    async fn materialize(
        &mut self,
        value: &Value,
        write: &mut Arc<tokio::net::unix::OwnedWriteHalf>,
    ) -> bool {
        let Some(id) = value.get("id").and_then(Value::as_str).filter(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) else {
            return false;
        };
        let Some(item) = self.deferred.remove(id) else {
            return Self::write(write, &format!("{}\n", json!({"type":"materialized","id":id,"ok":false,"error":"Drive message is unavailable or already consumed"}))).await;
        };
        let message = item.frame(id);
        let written = if let Some((handle, room, session, admission)) = item.guard.delivery.clone()
        {
            use vox_core::node::session_ingress::{DriveDelivery, DriveDeliveryResult, DriveFrame};
            struct Cancel {
                frame: Arc<DriveFrame>,
                armed: bool,
            }
            impl Drop for Cancel {
                fn drop(&mut self) {
                    if self.armed {
                        self.frame.abort();
                    }
                }
            }
            let Some(frame) = DriveFrame::new(write.clone(), message.into_bytes()).map(Arc::new)
            else {
                return false;
            };
            let mut cancel = Cancel {
                frame: frame.clone(),
                armed: true,
            };
            let lifecycle = item.guard.lifecycle.clone();
            let guard = item.guard.clone();
            let current: Arc<dyn Fn() -> Option<Box<dyn Send>> + Send + Sync> =
                Arc::new(move || {
                    if !guard.allowed() {
                        return None;
                    }
                    let native = (guard.native)()?;
                    if !guard.allowed() {
                        return None;
                    }
                    Some(native)
                });
            let send = async {
                loop {
                    if write.writable().await.is_err() {
                        return None;
                    }
                    let slot = handle.reserve_session_batch_slot().await?;
                    let _lifecycle = lifecycle.lock().await;
                    let receipt = slot.deliver_drive(
                        room,
                        session.clone(),
                        DriveDelivery {
                            admission: admission.clone(),
                            authority: item.guard.authority.clone(),
                            current: current.clone(),
                            frame: frame.clone(),
                        },
                    );
                    match receipt.await.ok()? {
                        DriveDeliveryResult::Pending => continue,
                        result => return Some(result),
                    }
                }
            };
            let result = tokio::select! {
                biased;
                () = item.guard.cancelled() => None,
                result = tokio::time::timeout(CALL_WITHIN, send) => result.ok().flatten(),
            };
            match result {
                Some(DriveDeliveryResult::Written) => {
                    cancel.armed = false;
                    true
                }
                _ if frame.cancel() => return false,
                _ => {
                    // No prefix was written; the refused frame is retired without closing
                    // the follower that carries the explicit native refusal.
                    cancel.armed = false;
                    return Self::write(
                        write,
                        &format!(
                            "{}\n",
                            json!({
                                "type":"materialized", "id":id, "ok":false,
                                "error":"the driver, room or Session changed before delivery"
                            })
                        ),
                    )
                    .await;
                }
            }
        } else {
            let lifecycle = item.guard.lifecycle.clone();
            let _lifecycle = lifecycle.lock().await;
            if !item.guard.allowed() {
                return Self::write(write, &format!("{}\n", json!({"type":"materialized","id":id,"ok":false,"error":"the driver, room or Session changed"}))).await;
            }
            use std::future::Future as _;
            use std::task::Poll;
            let mut publication = std::pin::pin!(Self::write(write, &message));
            tokio::select! {
                biased;
                () = item.guard.cancelled() => false,
                written = std::future::poll_fn(|cx| {
                    item.guard.with_publication(|| publication.as_mut().poll(cx))
                        .unwrap_or(Poll::Ready(false))
                }) => written,
            }
        };
        if written && item.guard.operator.is_some() && item.guard.operation.is_some() {
            self.receipts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id.to_owned(), (self.session.clone(), item.guard));
        }
        written
    }

    async fn line(&mut self, value: &Value) {
        match value.get("type").and_then(Value::as_str) {
            Some("event") => self.event(&value["event"]).await,
            Some("discard") => {
                if let Some(id) = value.get("id").and_then(Value::as_str).filter(|id| {
                    id.len() == 32
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }) {
                    self.deferred.remove(id);
                }
            }
            Some("result") => {
                let Some(call) = value
                    .get("id")
                    .and_then(Value::as_u64)
                    .and_then(|id| self.calls.remove(&id))
                else {
                    return;
                };
                let result = match value.get("ok").and_then(Value::as_bool) {
                    Some(true) => value
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            OmpControlError::Unconfirmed(
                                "OMP returned no control acknowledgement; outcome is unknown"
                                    .into(),
                            )
                        }),
                    Some(false)
                        if value.get("code").and_then(Value::as_str) == Some("not-queued") =>
                    {
                        Err(OmpControlError::NotSent(format!(
                            "OMP did not queue the control: {}",
                            value
                                .get("error")
                                .and_then(Value::as_str)
                                .unwrap_or("no reason given")
                        )))
                    }
                    Some(false) => Err(OmpControlError::Unconfirmed(format!(
                        "OMP reported an error; delivery is unknown: {}",
                        value
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("no reason given")
                    ))),
                    None => Err(OmpControlError::Unconfirmed(
                        "OMP returned a malformed acknowledgement; outcome is unknown".into(),
                    )),
                };
                if matches!(&result, Err(OmpControlError::NotSent(_))) {
                    if let Some(id) = call.deferred {
                        self.deferred.remove(&id);
                    }
                }
                let _ = call.reply.send(result);
            }
            _ => {
                self.fail("the native bridge supplied an unexpected frame")
                    .await
            }
        }
    }

    fn envelope(&self, kind: &str, reference: Option<&str>) -> Map<String, Value> {
        let mut entry = Map::new();
        entry.insert("v".into(), json!(VERSION));
        entry.insert("session".into(), json!(self.session));
        entry.insert("kind".into(), json!(kind));
        entry.insert(
            "ts".into(),
            json!(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
        );
        if let Some(reference) = reference {
            entry.insert("ref".into(), json!(reference));
        }
        entry
    }

    async fn post(&mut self, entry: Map<String, Value>, big: &str) {
        if self.failed {
            return;
        }
        let bodies = vox_agentcomms::activity::split(entry, big, MAX_TEXT_LEN);
        let admission = (self.activity)(self.node.clone(), self.registration.clone(), bodies).await;
        match &admission {
            vox_core::node::daemonipc::SessionAdmission::Committed { .. }
            | vox_core::node::daemonipc::SessionAdmission::Skipped => {}
            // Kept in memory only: the Session still shows it, so the follow goes on.
            vox_core::node::daemonipc::SessionAdmission::Held(why) => eprintln!(
                "vox daemon: {}: OMP Session {} activity is held in memory only: {why}",
                self.node, self.session
            ),
            vox_core::node::daemonipc::SessionAdmission::Refused(_)
            | vox_core::node::daemonipc::SessionAdmission::Unconfirmed(_) => {
                eprintln!(
                    "vox daemon: {}: OMP Session {} activity admission is incomplete: {admission:?}",
                    self.node, self.session
                );
                self.failed = true;
            }
        }
    }

    async fn fail(&mut self, why: &str) {
        if self.failed {
            return;
        }
        if self
            .stop_reported
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.failed = true;
            return;
        }
        eprintln!(
            "vox daemon: {}: OMP Session {} observation stopped: {why}",
            self.node, self.session
        );
        let mut entry = self.envelope("notice", None);
        entry.insert(
            "text".into(),
            json!(format!("OMP observation stopped: {why}")),
        );
        self.post(entry, "text").await;
        self.failed = true;
    }

    async fn semantic_frame(&mut self, event: &Value) {
        use base64::Engine as _;
        let Some(generation) = event.get("generation").and_then(Value::as_u64) else {
            self.fail("an OMP semantic frame has no generation").await;
            return;
        };
        let (Some(cursor), Some(part), Some(parts), Some(data)) = (
            event.get("cursor").and_then(Value::as_u64),
            event.get("part").and_then(Value::as_u64),
            event.get("parts").and_then(Value::as_u64),
            event.get("data").and_then(Value::as_str),
        ) else {
            self.fail("an OMP semantic frame is incomplete").await;
            return;
        };
        if self
            .semantic
            .generation
            .is_some_and(|old| old != generation)
            || cursor != self.semantic.cursor
            || parts == 0
            || parts > MAX_SEMANTIC_PARTS
            || part >= parts
            || data.len() > 48 * 1024
        {
            self.fail("OMP semantic observation has a generation or cursor gap")
                .await;
            return;
        }
        self.semantic.generation = Some(generation);
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data) else {
            self.fail("an OMP semantic frame has invalid encoding")
                .await;
            return;
        };
        if part == 0 && self.semantic.chunk.is_none() {
            self.semantic.chunk = Some(SemanticChunk {
                cursor,
                parts,
                next: 0,
                bytes: Vec::new(),
            });
        }
        let Some(chunk) = self.semantic.chunk.as_mut() else {
            self.fail("an OMP semantic record is missing its first part")
                .await;
            return;
        };
        if chunk.cursor != cursor
            || chunk.parts != parts
            || chunk.next != part
            || chunk.bytes.len().saturating_add(bytes.len()) > MAX_SEMANTIC
        {
            self.fail("an OMP semantic record has missing or oversized parts")
                .await;
            return;
        }
        chunk.bytes.extend_from_slice(&bytes);
        chunk.next += 1;
        if chunk.next != parts {
            return;
        }
        let Some(chunk) = self.semantic.chunk.take() else {
            return;
        };
        let Ok(record) = serde_json::from_slice::<Value>(&chunk.bytes) else {
            self.fail("an OMP semantic record is malformed").await;
            return;
        };
        if !semantic_shape_ok(&record) {
            self.fail("an OMP semantic record exceeds its structural bounds")
                .await;
            return;
        }
        self.semantic.cursor = match self.semantic.cursor.checked_add(1) {
            Some(next) => next,
            None => {
                self.fail("the OMP semantic cursor overflowed").await;
                return;
            }
        };
        match record.get("kind").and_then(Value::as_str) {
            Some("snapshot-begin") if self.semantic.snapshot.is_none() => {
                self.semantic.snapshot = Some(Vec::new());
                self.semantic.snapshot_bytes = 0;
                self.semantic.ready = false;
                *self
                    .media_registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = MediaRegistry::default();
            }
            Some("snapshot-end") => {
                let Some(records) = self.semantic.snapshot.take() else {
                    self.fail("an OMP snapshot ended without a beginning").await;
                    return;
                };
                let complete = record.get("complete").and_then(Value::as_bool) == Some(true);
                self.semantic.calls.clear();
                self.media_registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .generation = Some(generation);
                let mut reset = self.envelope("omp-reset", None);
                reset.insert("omp".into(), json!(true));
                reset.insert("branch".into(), json!(self.semantic.epoch));
                reset.insert("generation".into(), json!(generation));
                reset.insert("complete".into(), json!(complete));
                reset.insert("text".into(), json!(if complete {
                    "OMP current branch snapshot synchronized"
                } else {
                    "OMP current branch snapshot is incomplete; older or oversized content was omitted"
                }));
                for record in records {
                    self.semantic_record(generation, &record).await;
                    if self.failed {
                        return;
                    }
                }
                self.post(reset, "text").await;
                self.semantic.ready = true;
            }
            Some("incomplete") => {
                self.fail("the OMP semantic stream reported omitted content")
                    .await
            }
            Some("media") | Some("media-unavailable") => {
                self.semantic_record(generation, &record).await
            }
            Some(_) if self.semantic.snapshot.is_some() => {
                self.semantic.snapshot_bytes = self
                    .semantic
                    .snapshot_bytes
                    .saturating_add(chunk.bytes.len());
                if self.semantic.snapshot_bytes > MAX_SNAPSHOT
                    || self
                        .semantic
                        .snapshot
                        .as_ref()
                        .is_some_and(|records| records.len() >= 4096)
                {
                    self.fail("the current OMP branch snapshot exceeds its bound")
                        .await;
                    return;
                }
                if let Some(records) = self.semantic.snapshot.as_mut() {
                    records.push(record);
                }
            }
            Some(_) if self.semantic.ready => self.semantic_record(generation, &record).await,
            Some(_) => {
                self.fail("OMP sent a semantic update before a complete snapshot")
                    .await
            }
            None => self.fail("an OMP semantic record has no kind").await,
        }
    }

    async fn semantic_record(&mut self, generation: u64, record: &Value) {
        use base64::Engine as _;
        let kind = record
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
        if id.is_empty() || id.len() > 256 {
            self.fail("an OMP semantic record has an invalid identity")
                .await;
            return;
        }
        if kind == "media" || kind == "media-unavailable" {
            let Some(mut waiters) = self.media.remove(id) else {
                return;
            };
            let result = if kind == "media" {
                record
                    .get("data")
                    .and_then(Value::as_str)
                    .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
                    .filter(|bytes| bytes.len() <= 512 * 1024)
                    .ok_or_else(|| "The native image was malformed or oversized".to_owned())
            } else {
                Err("The native image is unavailable".to_owned())
            };
            // The single answer goes to every waiter in arrival order; the last takes it.
            if let Some(last) = waiters.pop() {
                for reply in waiters {
                    let _ = reply.send(result.clone());
                }
                let _ = last.send(result);
            }
            return;
        }
        let identity_kind = if kind == "job-remove" { "job" } else { kind };
        let reference = format!(
            "omp:{}:{generation}:{identity_kind}:{id}",
            self.semantic.epoch
        );
        match kind {
            "message" => {
                let role = record
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let Some(text) = record.get("text").and_then(Value::as_str) else {
                    return;
                };
                if !matches!(role, "user" | "assistant") {
                    return;
                }
                if self.semantic.calls.get(&reference) == Some(&true) {
                    return;
                }
                if self.semantic.calls.len() >= 4096
                    && !self.semantic.calls.contains_key(&reference)
                {
                    self.fail("the OMP message index exceeds its bound").await;
                    return;
                }
                let complete = record
                    .get("complete")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let first = self
                    .semantic
                    .calls
                    .insert(reference.clone(), complete)
                    .is_none();
                let mut entry = self.envelope(
                    if first {
                        if role == "user" {
                            "user"
                        } else {
                            "reply"
                        }
                    } else {
                        "omp-message-update"
                    },
                    Some(&reference),
                );
                entry.insert("omp".into(), json!(true));
                entry.insert("branch".into(), json!(self.semantic.epoch));
                entry.insert("generation".into(), json!(generation));
                entry.insert("complete".into(), json!(complete));
                entry.insert("text".into(), json!(text));
                self.post(entry, "text").await;
            }
            "tool" | "job" => {
                if self.semantic.calls.len() >= 4096
                    && !self.semantic.calls.contains_key(&reference)
                {
                    self.fail("the OMP running-call index exceeds its bound")
                        .await;
                    return;
                }
                if self.semantic.calls.get(&reference) == Some(&true) {
                    return;
                }
                let status = record
                    .get("status")
                    .and_then(Value::as_str)
                    .filter(|value| {
                        matches!(
                            *value,
                            "pending" | "running" | "completed" | "error" | "cancelled" | "failed"
                        )
                    })
                    .unwrap_or("unknown");
                let terminal = matches!(status, "completed" | "error" | "cancelled" | "failed");
                let name = one_line(
                    (if kind == "job" {
                        record.get("jobType")
                    } else {
                        record.get("name")
                    })
                    .and_then(Value::as_str)
                    .unwrap_or(if kind == "job" { "job" } else { "tool" }),
                );
                let intent = record
                    .get("intent")
                    .and_then(Value::as_str)
                    .or_else(|| record.get("label").and_then(Value::as_str))
                    .unwrap_or("");
                let heading = if intent.trim().is_empty() {
                    name.clone()
                } else {
                    format!("{name} · {}", one_line(intent))
                };
                let first = !self.semantic.calls.contains_key(&reference);
                self.semantic.calls.insert(reference.clone(), terminal);
                if first {
                    let mut entry = self.envelope("tool", Some(&reference));
                    entry.insert("omp".into(), json!(true));
                    entry.insert("branch".into(), json!(self.semantic.epoch));
                    if kind == "job" {
                        entry.insert("job_id".into(), json!(id));
                        entry.insert("job_type".into(), json!(name));
                        entry.insert(
                            "started".into(),
                            json!(record.get("startTime").and_then(Value::as_u64)),
                        );
                        entry.insert(
                            "ended".into(),
                            json!(record.get("endTime").and_then(Value::as_u64)),
                        );
                    }
                    entry.insert("generation".into(), json!(generation));
                    entry.insert("tool".into(), json!(name));
                    entry.insert("status".into(), json!(status));
                    if kind == "job" {
                        entry.insert(
                            "label".into(),
                            json!(one_line(
                                record.get("label").and_then(Value::as_str).unwrap_or("")
                            )),
                        );
                        entry.insert(
                            "agent_id".into(),
                            json!(one_line(
                                record.get("agentId").and_then(Value::as_str).unwrap_or("")
                            )),
                        );
                        entry.insert(
                            "owner_id".into(),
                            json!(one_line(
                                record.get("ownerId").and_then(Value::as_str).unwrap_or("")
                            )),
                        );
                    }
                    entry.insert("summary".into(), json!(heading));
                    entry.insert(
                        "input".into(),
                        json!(record
                            .get("args")
                            .and_then(Value::as_str)
                            .or_else(|| record.get("command").and_then(Value::as_str))
                            .unwrap_or("")),
                    );
                    self.post(entry, "input").await;
                }
                let mut text = String::new();
                if kind == "job" {
                    if let Some(caption) = record.get("caption").and_then(Value::as_str) {
                        text.push_str(caption);
                    }
                } else if let Some(parts) = record.get("content").and_then(Value::as_array) {
                    if parts.len() > 256 {
                        self.fail("an OMP result has too many content parts").await;
                        return;
                    }
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("text") {
                            if let Some(body) = part.get("text").and_then(Value::as_str) {
                                if !text.is_empty() {
                                    text.push('\n');
                                }
                                text.push_str(body);
                            }
                        } else if part.get("type").and_then(Value::as_str) == Some("image") {
                            self.semantic_image(generation, &reference, part).await;
                        }
                    }
                }
                if terminal || !text.is_empty() || kind == "job" {
                    let mut entry = self.envelope("tool-done", Some(&reference));
                    entry.insert("omp".into(), json!(true));
                    entry.insert("branch".into(), json!(self.semantic.epoch));
                    entry.insert("generation".into(), json!(generation));
                    entry.insert("tool".into(), json!(name));
                    entry.insert("status".into(), json!(status));
                    if kind == "job" {
                        entry.insert(
                            "ended".into(),
                            json!(record.get("endTime").and_then(Value::as_u64)),
                        );
                    }
                    entry.insert("ok".into(), json!(!matches!(status, "error" | "failed")));
                    entry.insert("interrupted".into(), json!(status == "cancelled"));
                    entry.insert("summary".into(), json!(one_line(&text)));
                    entry.insert("output".into(), json!(text));
                    self.post(entry, "output").await;
                }
                if terminal {
                    if let Some(details) = record
                        .get("details")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        let mut entry = self.envelope("omp-disclosure", Some(&reference));
                        entry.insert("omp".into(), json!(true));
                        entry.insert("branch".into(), json!(self.semantic.epoch));
                        entry.insert("text".into(), json!(details));
                        self.post(entry, "text").await;
                    }
                }
            }
            "job-remove" => {
                if self.semantic.calls.get(&reference) == Some(&false) {
                    self.semantic.calls.insert(reference.clone(), true);
                    let mut entry = self.envelope("tool-done", Some(&reference));
                    entry.insert("omp".into(), json!(true));
                    entry.insert("branch".into(), json!(self.semantic.epoch));
                    entry.insert("status".into(), json!("unavailable"));
                    entry.insert(
                        "output".into(),
                        json!("This job left the native snapshot without a final outcome."),
                    );
                    self.post(entry, "output").await;
                }
            }
            _ => {
                self.fail("an OMP semantic record has an unsupported kind")
                    .await
            }
        }
    }

    async fn semantic_image(&mut self, generation: u64, reference: &str, image: &Value) {
        let descriptor = vox_core::node::shares::media::Descriptor {
            id: image
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            mime: image
                .get("mime")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            size: image.get("size").and_then(Value::as_u64).unwrap_or(0),
            sha256: image
                .get("sha256")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        };
        if descriptor.validate().is_err() {
            let mut entry = self.envelope("omp-media", Some(reference));
            entry.insert("omp".into(), json!(true));
            entry.insert("branch".into(), json!(self.semantic.epoch));
            entry.insert(
                "unavailable".into(),
                json!("Unsupported or invalid image descriptor"),
            );
            self.post(entry, "").await;
            return;
        }
        let admission = {
            let mut registry = self
                .media_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if registry.generation != Some(generation) {
                None
            } else if registry
                .attachments
                .contains(&(reference.to_owned(), descriptor.id.clone()))
            {
                return;
            } else if registry.attachments.len() >= 512 {
                None
            } else {
                registry
                    .attachments
                    .insert((reference.to_owned(), descriptor.id.clone()));
                Some(registry.ids.insert(descriptor.id.clone()))
            }
        };
        let Some(newly_admitted) = admission else {
            let mut entry = self.envelope("omp-media", Some(reference));
            entry.insert("omp".into(), json!(true));
            entry.insert("branch".into(), json!(self.semantic.epoch));
            entry.insert(
                "unavailable".into(),
                json!("Image is stale or exceeds the attachment bound"),
            );
            self.post(entry, "").await;
            return;
        };
        let tag = (self.media_offer)(
            self.node.clone(),
            self.registration.clone(),
            generation,
            descriptor.clone(),
        )
        .await;
        if tag.is_err() && newly_admitted {
            self.media_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ids
                .remove(&descriptor.id);
        }
        let mut entry = self.envelope("omp-media", Some(reference));
        entry.insert("omp".into(), json!(true));
        entry.insert("branch".into(), json!(self.semantic.epoch));
        entry.insert("media_id".into(), json!(descriptor.id));
        entry.insert("mime".into(), json!(descriptor.mime));
        entry.insert("size".into(), json!(descriptor.size));
        entry.insert("sha256".into(), json!(descriptor.sha256));
        entry.insert("generation".into(), json!(generation));
        match tag {
            Ok(tag) => {
                entry.insert("tag".into(), json!(tag));
            }
            Err(why) => {
                entry.insert("unavailable".into(), json!(why));
            }
        }
        self.post(entry, "").await;
    }

    async fn event(&mut self, event: &Value) {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match kind {
            "semantic" => self.semantic_frame(event).await,
            "drive-accepted" => {
                let Some(id) = event.get("id").and_then(Value::as_str) else {
                    return;
                };
                let guard = {
                    let mut receipts = self
                        .receipts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if receipts
                        .get(id)
                        .is_none_or(|(session, _)| session != &self.session)
                    {
                        return;
                    }
                    receipts.remove(id).map(|(_, guard)| guard)
                };
                let Some(guard) = guard else { return };
                if !guard.allowed() {
                    return;
                }
                let (Some(operation), Some(author)) =
                    (guard.operation.as_deref(), guard.operator.as_deref())
                else {
                    return;
                };
                let Some(response) = event.get("response").and_then(Value::as_str) else {
                    return;
                };
                let mut entry = self.envelope("drive-result", None);
                entry.insert("of".into(), json!(operation));
                entry.insert("ref".into(), json!(operation));
                entry.insert("occurrence".into(), json!(author));
                entry.insert("drive_scope".into(), json!(1));
                entry.insert("by".into(), json!(author));
                entry.insert("action".into(), json!("text"));
                entry.insert("phase".into(), json!("accepted"));
                entry.insert("ok".into(), json!(true));
                entry.insert("text".into(), json!(response));
                self.post(entry, "text").await;
            }
            "user" | "reply" => {
                let Some(text) = event.get("text").and_then(Value::as_str) else {
                    self.fail("an OMP text event has no text").await;
                    return;
                };
                if text.trim().is_empty() {
                    return;
                }
                let mut entry = self.envelope(kind, None);
                entry.insert("text".into(), json!(text));
                self.post(entry, "text").await;
                self.ended = false;
            }
            "tool" | "tool-done" => {
                let Some(id) = event
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                else {
                    self.fail("an OMP tool event has no call identity").await;
                    return;
                };
                let Some(name) = event.get("name").and_then(Value::as_str) else {
                    self.fail("an OMP tool event has no name").await;
                    return;
                };
                let field = if kind == "tool" { "input" } else { "output" };
                let text = match event.get(field) {
                    Some(Value::String(text)) => text.clone(),
                    Some(value) => serde_json::to_string_pretty(value).unwrap_or_default(),
                    None => String::new(),
                };
                let mut entry = self.envelope(kind, Some(id));
                entry.insert("tool".into(), json!(name));
                entry.insert("summary".into(), json!(one_line(&text)));
                entry.insert(field.into(), json!(text));
                if kind == "tool-done" {
                    entry.insert(
                        "ok".into(),
                        json!(!event
                            .get("isError")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)),
                    );
                }
                self.post(entry, field).await;
                self.ended = false;
            }
            "state" => {
                if let Some(busy) = event.get("busy").and_then(Value::as_bool) {
                    crate::wake::record_omp_state(&self.paths, &self.registration, busy);
                } else {
                    self.fail("an OMP state event has no busy status").await;
                }
            }
            "turn-start" => {
                crate::wake::record_omp_state(&self.paths, &self.registration, true);
                self.ended = false;
            }
            "turn-end" => {
                crate::wake::record_omp_state(&self.paths, &self.registration, false);
                if !self.ended {
                    // A turn end belongs to the snapshot epoch that observed it, so a later
                    // rewind or reset hides it with the rest of that branch's activity.
                    let mut entry = self.envelope("turn-end", None);
                    entry.insert("omp".into(), json!(true));
                    entry.insert("branch".into(), json!(self.semantic.epoch));
                    self.post(entry, "").await;
                    self.ended = true;
                }
            }
            "session-end" => {
                (self.session_end)(self.node.clone(), self.registration.clone()).await;
                self.failed = true;
            }
            "transition" => {
                // The extension retired this epoch by plan. Without an open control it is
                // an expected close; an open one stays explicitly unknown.
                if self.calls.is_empty() && self.deferred.is_empty() {
                    self.failed = true;
                } else {
                    self.fail("the OMP conversation changed; pending control outcomes are unknown")
                        .await;
                }
            }
            "name" => {
                if let Some(name) = event.get("name").and_then(Value::as_str) {
                    let name = name.trim();
                    if !name.is_empty() {
                        (self.rename)(
                            self.node.clone(),
                            self.registration.clone(),
                            name.to_owned(),
                        )
                        .await;
                    }
                }
            }
            "unavailable" => {
                let why = event
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("native activity is unavailable");
                self.fail(why).await;
            }
            _ => {
                self.fail("the native bridge supplied an unknown activity event")
                    .await
            }
        }
    }
}
