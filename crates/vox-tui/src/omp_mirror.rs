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

/// Handler for an explicitly reported native session shutdown.
pub type SessionEnd = Arc<
    dyn Fn(NodeName, crate::wake::Session) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;
/// Admit activity under the exact registration captured by its follower.
pub type Activity = Arc<
    dyn Fn(NodeName, crate::wake::Session, Vec<String>) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;
/// Rename only the exact registration captured by the follower.
pub type Rename = Arc<
    dyn Fn(NodeName, crate::wake::Session, String) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
struct Connection {
    node: NodeName,
    endpoint: String,
    token: String,
    registration: crate::wake::Session,
    commands: mpsc::Sender<Cmd>,
    stop: Arc<Notify>,
}

/// One native OMP connection per registered session.
pub struct OmpMirror {
    rename: Rename,
    session_end: SessionEnd,
    activity: Activity,
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

struct Cmd {
    steer: Steer,
    guard: Option<crate::host::room_pause::InterruptGuard>,
    drive: Option<crate::host::OmpDriveGuard>,
    reply: oneshot::Sender<Result<String, OmpControlError>>,
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
    pub fn new(rename: Rename, session_end: SessionEnd, activity: Activity) -> Arc<Self> {
        Arc::new(Self {
            rename,
            session_end,
            activity,
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
        conns.retain(|_, conn| !conn.commands.is_closed());
        if let Some(conn) = conns.get(session) {
            if &conn.node == node
                && conn.registration.same(registration)
                && conn.registration.first_seen_ms == registration.first_seen_ms
                && conn.registration.mirror == registration.mirror
            {
                return;
            }
        }
        if let Some(old) = conns.remove(session) {
            old.stop.notify_one();
        }
        let Ok(permit) = Arc::clone(&self.live).try_acquire_owned() else {
            eprintln!("vox daemon: {node}: OMP Session {session} observation refused: {MAX_FOLLOWS} live followers already active");
            return;
        };
        let (tx, rx) = mpsc::channel(MAX_COMMANDS);
        let stop = Arc::new(Notify::new());
        conns.insert(
            session.to_owned(),
            Connection {
                node: node.clone(),
                endpoint: endpoint.to_owned(),
                token: token.to_owned(),
                registration: registration.clone(),
                commands: tx.clone(),
                stop: Arc::clone(&stop),
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
            calls: BTreeMap::new(),
            deferred: BTreeMap::new(),
            receipts: Arc::clone(&self.receipts),
            next_id: 1,
            failed: false,
            ended: false,
        };
        let endpoint = endpoint.to_owned();
        let token = token.to_owned();
        let session = session.to_owned();
        let owner = Arc::downgrade(self);
        tokio::spawn(async move {
            let _permit = permit;
            follow.run(&endpoint, &token, rx, stop).await;
            if let Some(owner) = owner.upgrade() {
                let mut conns = owner.conns();
                if conns
                    .get(&session)
                    .is_some_and(|conn| conn.commands.same_channel(&tx))
                {
                    conns.remove(&session);
                }
            }
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
            .try_send(Cmd {
                steer,
                guard,
                drive,
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
}

struct Follow {
    node: NodeName,
    session: String,
    rename: Rename,
    paths: vox_core::node::paths::Paths,
    registration: crate::wake::Session,
    session_end: SessionEnd,
    activity: Activity,
    calls: BTreeMap<u64, PendingCall>,
    deferred: BTreeMap<String, Deferred>,
    receipts: Arc<Mutex<BTreeMap<String, (String, crate::host::OmpDriveGuard)>>>,
    next_id: u64,
    failed: bool,
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
                    Some(Cmd { steer, guard, drive, reply }) => {
                        if guard.as_ref().is_some_and(|guard| !guard.allowed()) {
                            let _ = reply.send(Err("room pause, authority or Session changed; the interrupt was not sent".into()));
                            continue;
                        }
                        if let Some(call) = self.call(steer, drive, reply) {
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
            tokio::select! {
                biased;
                () = item.guard.cancelled() => false,
                written = Self::write(write, &message) => written,
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
        let bodies = vox_agentcomms::activity::split(entry, big, MAX_TEXT_LEN);
        (self.activity)(self.node.clone(), self.registration.clone(), bodies).await;
    }

    async fn fail(&mut self, why: &str) {
        if self.failed {
            return;
        }
        eprintln!(
            "vox daemon: {}: OMP Session {} observation stopped: {why}",
            self.node, self.session
        );
        let mut entry = self.envelope("notice", None);
        entry.insert(
            "summary".into(),
            json!(format!("OMP observation stopped: {why}")),
        );
        self.post(entry, "summary").await;
        self.failed = true;
    }

    async fn event(&mut self, event: &Value) {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match kind {
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
                    self.post(self.envelope("turn-end", None), "").await;
                    self.ended = true;
                }
            }
            "session-end" => {
                (self.session_end)(self.node.clone(), self.registration.clone()).await;
                self.failed = true;
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
