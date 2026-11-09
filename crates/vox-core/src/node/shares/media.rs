//! Ephemeral on-demand image services over the existing authenticated file tunnel.
//!
//! Neither a native path nor a URL enters this interface. The owner supplies an
//! exact-Session/branch guard and a materializer backed by its authenticated follower.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::api::{NodeCommand, Outcome};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

/// Maximum encoded image size accepted from the native follower and over the tunnel.
pub const MAX_BYTES: usize = 512 * 1024;
const MAX_SERVICES: usize = 64;
const MAX_TRANSFERS: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(30);

/// Immutable metadata from one authenticated native image part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Native attachment identifier.
    pub id: String,
    /// Declared image media type.
    pub mime: String,
    /// Expected byte count.
    pub size: u64,
    /// Expected SHA-256 digest.
    pub sha256: String,
}

/// Revalidates the authenticated requesting node against the exact room instance,
/// Session registration and current branch. Drive is also checked by the share witness.
pub type Guard = Arc<dyn Fn(Digest32) -> bool + Send + Sync>;
/// Requests precisely this descriptor from the authenticated native follower.
pub type Materialize =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>> + Send + Sync>;

static SERVICES: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_SERVICES)));
static TRANSFERS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_TRANSFERS)));
static LOCAL: LazyLock<Mutex<std::collections::BTreeMap<String, Weak<Local>>>> =
    LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));

struct Local {
    room: Digest32,
    owner: Digest32,
    descriptor: Descriptor,
    guard: Guard,
    materialize: Materialize,
    alive: std::sync::atomic::AtomicBool,
}

impl Descriptor {
    /// Reject unsupported, malformed or oversized declarations before allocation or dialing.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() != 32
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid native media id".into());
        }
        if self.size == 0 || self.size > MAX_BYTES as u64 {
            return Err("native media is empty or exceeds the 512 KiB limit".into());
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid native media SHA-256".into());
        }
        if !matches!(
            self.mime.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        ) {
            return Err("unsupported native image MIME".into());
        }
        Ok(())
    }

    /// Verify size, SHA-256 and actual image format, not just the declared MIME.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), String> {
        self.validate()?;
        if bytes.len() as u64 != self.size || super::hex(&crate::hash::sha256(bytes)) != self.sha256
        {
            return Err("native media does not match its size or SHA-256".into());
        }
        let expected = match self.mime.as_str() {
            "image/png" => image::ImageFormat::Png,
            "image/jpeg" => image::ImageFormat::Jpeg,
            "image/gif" => image::ImageFormat::Gif,
            "image/webp" => image::ImageFormat::WebP,
            _ => return Err("unsupported native image MIME".into()),
        };
        if image::guess_format(bytes).ok() != Some(expected) {
            return Err("native media does not match its MIME".into());
        }
        Ok(())
    }
}

/// The owner's sealed Session activity an offered image must be published in. A requester
/// names that record; the owner admits it only for its own matching record, under the same
/// per-recipient private Session permission that serves the record itself (#1171).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The owner's harness Session id.
    pub session: String,
    /// The native branch generation the image was offered under.
    pub generation: u64,
    /// The offered image.
    pub descriptor: Descriptor,
}

impl Binding {
    /// Whether `row` is `owner`'s own `omp-media` activity for exactly this image and `tag`.
    pub(crate) fn names(
        &self,
        row: &crate::node::drive::SessionRow,
        owner: &Digest32,
        tag: &str,
    ) -> bool {
        if row.author != *owner || row.session_id != self.session {
            return false;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&row.body) else {
            return false;
        };
        let text = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
        let number = |name: &str| value.get(name).and_then(serde_json::Value::as_u64);
        text("kind") == Some("omp-media")
            && text("tag") == Some(tag)
            && text("media_id") == Some(self.descriptor.id.as_str())
            && text("mime") == Some(self.descriptor.mime.as_str())
            && text("sha256") == Some(self.descriptor.sha256.as_str())
            && number("size") == Some(self.descriptor.size)
            && number("generation") == Some(self.generation)
    }
}

/// What one service request asks: the image, for the exact activity record it names, or
/// whether a transfer admitted under that room-removal generation is still current.
enum Asked {
    Image(Digest32),
    Current(u64),
}

fn request(asked: &Asked) -> Vec<u8> {
    let (method, target) = match asked {
        Asked::Image(entry) => ("GET", super::hex(entry)),
        Asked::Current(generation) => ("HEAD", generation.to_string()),
    };
    format!("{method} /media/{target} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn requested(head: &[u8]) -> Option<Asked> {
    let line = head.split(|&b| b == b'\r').next()?;
    let (image, rest) = if let Some(rest) = line.strip_prefix(b"GET /media/") {
        (true, rest)
    } else {
        (false, line.strip_prefix(b"HEAD /media/")?)
    };
    let (target, version) = rest.split_at(rest.iter().position(|&b| b == b' ')?);
    if !version.starts_with(b" HTTP/1.") {
        return None;
    }
    if !image {
        if target.is_empty() || target.len() > 20 || !target.iter().all(u8::is_ascii_digit) {
            return None;
        }
        return std::str::from_utf8(target)
            .ok()?
            .parse()
            .ok()
            .map(Asked::Current);
    }
    if target.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut entry = [0u8; 32];
    for (byte, pair) in entry.iter_mut().zip(target.chunks_exact(2)) {
        *byte = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(Asked::Image(entry))
}

/// The owner's room-removal generation an image response was admitted under.
const AUTHORITY: &str = "\r\nX-Vox-Authority: ";

/// A volatile share, withdrawn on drop; it is never announced as a file or restored.
pub struct MediaLease {
    room: Digest32,
    tag: String,
    cmd: tokio::sync::mpsc::WeakSender<(NodeCommand, tokio::sync::oneshot::Sender<Outcome>)>,
    stop: watch::Sender<bool>,
    server: tokio::task::JoinHandle<()>,
    _local: Arc<Local>,
    _slot: OwnedSemaphorePermit,
}

impl MediaLease {
    /// Start one Session-scoped service. The descriptor itself must be published only
    /// in its sealed Session activity, as `binding` names it. The guard must become false
    /// on every transition; each request is also admitted against its named record.
    pub async fn start(
        handle: &NodeHandle,
        room: Digest32,
        binding: Binding,
        guard: Guard,
        materialize: Materialize,
    ) -> Result<Self, String> {
        let descriptor = binding.descriptor.clone();
        descriptor.validate()?;
        let shares = handle.shares();
        let slot = SERVICES
            .clone()
            .try_acquire_owned()
            .map_err(|_| "too many active media services".to_owned())?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let tag = format!("media-{}", super::hex(&nonce));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| e.to_string())?;
        let local = listener.local_addr().map_err(|e| e.to_string())?;
        let owner = shares
            .view
            .borrow()
            .identity
            .as_ref()
            .map(|identity| identity.fingerprint)
            .ok_or("the Session node is locked")?;
        let local_source = Arc::new(Local {
            room,
            owner,
            descriptor: descriptor.clone(),
            guard: guard.clone(),
            materialize: materialize.clone(),
            alive: std::sync::atomic::AtomicBool::new(true),
        });
        let witness = shares.witness(&tag, room, super::Only::Drive);
        let admitting = (handle.clone(), tag.clone());
        let (stop, stopping) = watch::channel(false);
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, from) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let Ok(permit) = TRANSFERS.clone().try_acquire_owned() else {
                    continue;
                };
                let (witness, guard, materialize, descriptor, binding, mut stopping) = (
                    witness.clone(),
                    guard.clone(),
                    materialize.clone(),
                    descriptor.clone(),
                    binding.clone(),
                    stopping.clone(),
                );
                let (handle, tag) = admitting.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let work = async {
                        let mut head = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
                            let n = socket.read(&mut chunk).await.map_err(|e| e.to_string())?;
                            if n == 0 {
                                return Err("incomplete media request".to_owned());
                            }
                            head.extend_from_slice(&chunk[..n]);
                        }
                        let asked = requested(&head).ok_or("invalid media request")?;
                        let peer = witness
                            .member(Some(from))
                            .ok_or("unauthenticated media request")?;
                        let allowed = || witness.allowed(Some(peer)) && guard(peer);
                        // The room's removal/readmission incarnation, rechecked on every step.
                        let authority = handle
                            .view()
                            .open_channels
                            .iter()
                            .find(|channel| channel.channel_id == room)
                            .and_then(|channel| channel.removal_guard())
                            .ok_or("the media room is not open")?;
                        let fenced = || allowed() && authority.current();
                        let entry = match asked {
                            // Bytes this peer was already given under an unchanged incarnation
                            // stay current; any removal or readmission ends that transfer and
                            // a new image request is admitted under the new policy.
                            Asked::Current(generation) => {
                                if !authority.matches(generation) || !fenced() {
                                    return Err("media access withdrawn".into());
                                }
                                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.map_err(|e| e.to_string())?;
                                if !fenced() {
                                    return Err("media access withdrawn".into());
                                }
                                socket.shutdown().await.map_err(|e| e.to_string())?;
                                return Ok::<(), String>(());
                            }
                            Asked::Image(entry) => entry,
                        };
                        // Once per image request: the requester's own sealed record must be
                        // this image's, and one the existing private Session serving gives that
                        // peer. The generation is monotonic, so unchanged before and after
                        // means the decision was made under the pinned incarnation.
                        if !fenced()
                            || !handle
                                .session_media_admits(room, peer, entry, tag, binding)
                                .await
                            || !fenced()
                        {
                            return Err("media access withdrawn".into());
                        }
                        let bytes = materialize().await?;
                        if !fenced() {
                            return Err("media access withdrawn".into());
                        }
                        if descriptor.verify(&bytes).is_err() {
                            if !fenced() {
                                return Err("media access withdrawn".into());
                            }
                            socket.write_all(b"HTTP/1.1 422 Unprocessable Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.map_err(|e| e.to_string())?;
                            socket.shutdown().await.map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}{AUTHORITY}{}\r\nConnection: close\r\n\r\n",
                            bytes.len(),
                            authority.generation(),
                        );
                        socket
                            .write_all(header.as_bytes())
                            .await
                            .map_err(|e| e.to_string())?;
                        for part in bytes.chunks(16 * 1024) {
                            if !fenced() {
                                return Err("media access withdrawn".into());
                            }
                            socket.write_all(part).await.map_err(|e| e.to_string())?;
                        }
                        if !fenced() {
                            return Err("media access withdrawn".into());
                        }
                        socket.shutdown().await.map_err(|e| e.to_string())?;
                        Ok::<(), String>(())
                    };
                    let completed = tokio::select! {
                        result = tokio::time::timeout(TIMEOUT, work) => matches!(result, Ok(Ok(()))),
                        _ = stopping.wait_for(|v| *v) => false,
                    };
                    if !completed {
                        crate::tunnel::session::abort_after_drain(socket).await;
                    }
                });
            }
        });
        match shares
            .apply(NodeCommand::AddService {
                channel_id: room,
                service_tag: tag.clone(),
                local,
                kind: crate::governance::share::ServiceKind::Http,
                persist: false,
            })
            .await
        {
            Outcome::Done => {
                LOCAL
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(tag.clone(), Arc::downgrade(&local_source));
                Ok(Self {
                    room,
                    tag,
                    cmd: shares.cmd.clone(),
                    stop,
                    server,
                    _local: local_source,
                    _slot: slot,
                })
            }
            other => {
                server.abort();
                Err(other.to_string())
            }
        }
    }

    /// The opaque service tag to carry only in the sealed Session descriptor.
    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl Drop for MediaLease {
    fn drop(&mut self) {
        self._local
            .alive
            .store(false, std::sync::atomic::Ordering::SeqCst);
        LOCAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.tag);
        let _ = self.stop.send(true);
        self.server.abort();
        let (cmd, room, tag) = (self.cmd.clone(), self.room, self.tag.clone());
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Some(cmd) = cmd.upgrade() {
                    let (tx, _rx) = tokio::sync::oneshot::channel();
                    let _ = cmd
                        .send((
                            NodeCommand::RemoveService {
                                channel_id: room,
                                service_tag: tag,
                            },
                            tx,
                        ))
                        .await;
                }
            });
        }
    }
}

/// Fetch a local Session's own image without tunnelling to the same node.
/// The caller still has to authenticate the exact sealed activity first.
pub async fn fetch_local(
    room: Digest32,
    owner: Digest32,
    tag: &str,
    descriptor: &Descriptor,
) -> Result<Vec<u8>, String> {
    let source = LOCAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(tag)
        .and_then(Weak::upgrade)
        .ok_or("the media service is unavailable")?;
    if source.room != room
        || source.owner != owner
        || &source.descriptor != descriptor
        || !source.alive.load(std::sync::atomic::Ordering::SeqCst)
        || !(source.guard)(owner)
    {
        return Err("the media service is not authorized".into());
    }
    let _permit = TRANSFERS
        .clone()
        .try_acquire_owned()
        .map_err(|_| "too many media transfers".to_owned())?;
    let bytes = tokio::time::timeout(TIMEOUT, (source.materialize)())
        .await
        .map_err(|_| "media transfer timed out".to_owned())??;
    if !source.alive.load(std::sync::atomic::Ordering::SeqCst) || !(source.guard)(owner) {
        return Err("media access withdrawn".into());
    }
    descriptor.verify(&bytes)?;
    if !source.alive.load(std::sync::atomic::Ordering::SeqCst) || !(source.guard)(owner) {
        return Err("media access withdrawn".into());
    }
    Ok(bytes)
}

/// Fetch through the authenticated room tunnel, never from a URL or filesystem path.
/// `current` must revalidate the exact authorized Session activity and branch, and
/// must stay false once that authority is withdrawn. The owner admits the request against
/// the requester's own sealed activity record `entry` and answers with the room-removal
/// generation it admitted under, which [`probe`] later names.
pub async fn fetch(
    handle: &NodeHandle,
    room: Digest32,
    owner: Digest32,
    tag: &str,
    descriptor: &Descriptor,
    entry: Digest32,
    current: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Result<(Vec<u8>, u64), String> {
    descriptor.validate()?;
    let suffix = tag
        .strip_prefix("media-")
        .ok_or("invalid media service tag")?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid media service tag".into());
    }
    if !current() {
        return Err("media access withdrawn".into());
    }
    let handle = handle.clone();
    let tag = tag.to_owned();
    let descriptor = descriptor.clone();
    // A detached worker always tears down its forward even if the requesting UI
    // disappears while the transfer is in flight.
    tokio::spawn(async move {
        let _permit = TRANSFERS
            .clone()
            .try_acquire_owned()
            .map_err(|_| "too many media transfers".to_owned())?;
        if !current() {
            return Err("media access withdrawn".into());
        }
        let bound = match handle
            .apply(NodeCommand::Forward {
                channel_id: room,
                host: owner,
                service_tag: tag,
                local: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            })
            .await
        {
            Outcome::Bound(bound) => bound,
            other => return Err(other.to_string()),
        };
        let work = async {
            let mut sock = tokio::net::TcpStream::connect(bound)
                .await
                .map_err(|e| e.to_string())?;
            sock.write_all(&request(&Asked::Image(entry)))
                .await
                .map_err(|e| e.to_string())?;
            let mut header = Vec::new();
            let mut buf = [0u8; 16 * 1024];
            let mut body = Vec::with_capacity(descriptor.size as usize);
            let mut in_body = false;
            let mut authority = None;
            loop {
                if !current() {
                    return Err("media access withdrawn".to_owned());
                }
                let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                if in_body {
                    if body.len().saturating_add(n) > descriptor.size as usize {
                        return Err("media exceeds declared size".into());
                    }
                    body.extend_from_slice(&buf[..n]);
                } else {
                    header.extend_from_slice(&buf[..n]);
                    if let Some(end) = header.windows(4).position(|w| w == b"\r\n\r\n") {
                        if header.starts_with(b"HTTP/1.1 422 ") {
                            return Err("image failed verification".into());
                        }
                        if end > 8192
                            || !(header.starts_with(b"HTTP/1.1 200 ")
                                || header.starts_with(b"HTTP/1.0 200 "))
                        {
                            return Err("media service refused the request".into());
                        }
                        authority = std::str::from_utf8(&header[..end])
                            .ok()
                            .and_then(|head| head.split_once(AUTHORITY))
                            .and_then(|(_, rest)| rest.split("\r\n").next())
                            .and_then(|value| value.parse::<u64>().ok());
                        let rest = &header[end + 4..];
                        if rest.len() > descriptor.size as usize {
                            return Err("media exceeds declared size".into());
                        }
                        body.extend_from_slice(rest);
                        in_body = true;
                        header.clear();
                    } else if header.len() > 8192 {
                        return Err("invalid media response".into());
                    }
                }
            }
            let authority = authority.ok_or("media response has no admitted authority")?;
            if !in_body || !current() {
                return Err("media access withdrawn or incomplete".into());
            }
            descriptor.verify(&body)?;
            if !current() {
                return Err("media access withdrawn".into());
            }
            Ok((body, authority))
        };
        let result = tokio::time::timeout(TIMEOUT, work)
            .await
            .map_err(|_| "media transfer timed out".to_owned())
            .and_then(|r| r);
        let _ = handle
            .apply(NodeCommand::StopForward { local: bound })
            .await;
        if !current() {
            return Err("media access withdrawn".into());
        }
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Revalidate the source's current branch, the requesting peer and the room-removal
/// generation `authority` its transfer was admitted under, without transferring image bytes
/// or re-reading the record. Used before every later page of a previously verified transfer.
pub async fn probe(
    handle: &NodeHandle,
    room: Digest32,
    owner: Digest32,
    tag: &str,
    descriptor: &Descriptor,
    authority: u64,
) -> Result<(), String> {
    descriptor.validate()?;
    if handle
        .view()
        .identity
        .as_ref()
        .map(|identity| identity.fingerprint)
        == Some(owner)
    {
        let source = LOCAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tag)
            .and_then(Weak::upgrade)
            .ok_or("the media service is unavailable")?;
        return if source.room == room
            && source.owner == owner
            && source.descriptor == *descriptor
            && source.alive.load(std::sync::atomic::Ordering::SeqCst)
            && (source.guard)(owner)
        {
            Ok(())
        } else {
            Err("media access withdrawn".into())
        };
    }
    let suffix = tag
        .strip_prefix("media-")
        .ok_or("invalid media service tag")?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid media service tag".into());
    }
    let handle = handle.clone();
    let tag = tag.to_owned();
    tokio::spawn(async move {
        let _permit = TRANSFERS
            .clone()
            .try_acquire_owned()
            .map_err(|_| "too many media transfers".to_owned())?;
        let bound = match handle
            .apply(NodeCommand::Forward {
                channel_id: room,
                host: owner,
                service_tag: tag,
                local: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            })
            .await
        {
            Outcome::Bound(bound) => bound,
            other => return Err(other.to_string()),
        };
        let result = tokio::time::timeout(TIMEOUT, async {
            let mut sock = tokio::net::TcpStream::connect(bound)
                .await
                .map_err(|e| e.to_string())?;
            sock.write_all(&request(&Asked::Current(authority)))
                .await
                .map_err(|e| e.to_string())?;
            let mut reply = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                reply.extend_from_slice(&buf[..n]);
                if reply.len() > 8192 {
                    return Err("invalid media response".to_owned());
                }
            }
            if !reply.starts_with(b"HTTP/1.1 200 ") || !reply.windows(4).any(|w| w == b"\r\n\r\n") {
                return Err("media access withdrawn".into());
            }
            Ok(())
        })
        .await
        .map_err(|_| "media access check timed out".to_owned())
        .and_then(|result| result);
        let _ = handle
            .apply(NodeCommand::StopForward { local: bound })
            .await;
        result
    })
    .await
    .map_err(|e| e.to_string())?
}
