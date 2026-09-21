//! ADR-020 §7 — the node's local control socket: the seam that carries
//! [`NodeEvent`]s to **out-of-process** clients.
//!
//! Agent comms puts several agent sessions on one harness node (ADR-020 §2: one
//! node per `(host, harness)`, many sessions). M19.1a made the in-process
//! fan-out safe — emission never blocks and a lagging subscriber is told so.
//! This module carries that same stream across a process boundary, preserving
//! the same property: **no client can stall the node, and no client can disturb
//! another.**
//!
//! ## What this is not
//!
//! It is deliberately **not** a mirror of [`NodeCommand`](super::api::NodeCommand). That enum carries
//! [`Secret`](super::api::Secret) — passphrases — and reaches `CreateIdentity`,
//! `Revoke` and `PassphraseRotate`. An agent session runs model-authored code and
//! has no business issuing any of those, so the socket speaks its own narrow
//! vocabulary and this milestone carries **events only**. Requests that let a
//! client *act* arrive with the agent-comms protocol (ADR-020 §4), scoped to what
//! an app legitimately needs.
//!
//! Being honest about what that buys: the socket is `0600`, so only this uid can
//! open it — and that uid can already read `vault.cbor` in the same directory.
//! The narrow surface is therefore **accident prevention, not a security
//! boundary**, and must not be described as one. The boundary is the file mode.
//!
//! ## Wire
//!
//! Frames are length-delimited exactly as [`crate::transport::framing`] does it
//! on QUIC — a 4-byte big-endian length, then that many bytes — with a cap so a
//! client cannot announce a huge length to force an allocation. Each frame body
//! is canonical fixed-arity CBOR (ADR-008's house encoding, via
//! [`crate::cbor`]), a `[tag, ..fields]` array. No domain-separation label: these
//! frames are neither signed nor authenticated, because the file mode is what
//! authorises the peer.
//!
//! ## Lifecycle facts, measured rather than assumed (M19.1b spike)
//!
//! - `UnixListener::bind` yields a **0755** socket (the mode comes from the
//!   umask), so the explicit `chmod` to `0600` is REQUIRED, not belt-and-braces.
//! - A leftover socket file from a process that died makes `bind` fail with
//!   `AddrInUse` (errno 48), so the stale file is unlinked first — deliberately,
//!   rather than inheriting a confusing "address in use".
//! - A client that dies reads as a clean EOF and writing to it fails with
//!   `BrokenPipe`; both are isolated to that connection.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::{EventStream, EventStreamItem, NodeHandle};
use crate::node::api::{MessageRow, NodeEvent};

/// The protocol this build speaks. Bumped when a frame's shape changes in a way
/// an older client would misread; a client that sees a version it does not know
/// MUST disconnect rather than guess.
pub const PROTOCOL_VERSION: u64 = 1;

/// Largest frame accepted in either direction.
///
/// Comfortably above the largest event — `InviteLink`'s URL and a `NewEntry`'s
/// text are the only unbounded-ish fields, and message text is already capped at
/// [`crate::node::content::MAX_TEXT_LEN`] (64 KiB).
pub const MAX_FRAME: usize = 256 * 1024;

// ---- frame tags ------------------------------------------------------------
// Node → client.
const T_HELLO: u64 = 1;
const T_LAGGED: u64 = 2;
const T_NEW_ENTRY: u64 = 10;
const T_UNLOCKED: u64 = 11;
const T_LOCKED: u64 = 12;
const T_CHANNEL_OPENED: u64 = 13;
const T_CHANNEL_CLOSED: u64 = 14;
const T_PEER_JOINED: u64 = 15;
const T_SENDER_KEY: u64 = 16;
const T_FORWARDING: u64 = 17;
const T_INVITE_LINK: u64 = 18;
const T_JOINED: u64 = 19;
const T_CONSENTED: u64 = 20;
const T_REVOKED: u64 = 21;
const T_TUNNEL_SERVED: u64 = 22;
const T_PROXY_UP: u64 = 23;
const T_SYNCED: u64 = 24;
const T_SHUTDOWN: u64 = 25;
// Client → node.
const T_SUBSCRIBE: u64 = 1;

/// What a client sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Begin streaming events. Everything emitted from this point reaches this
    /// client; nothing before it does.
    Subscribe,
}

impl Request {
    /// Canonical CBOR body (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Request::Subscribe => {
                e.array(1).uint(T_SUBSCRIBE);
            }
        }
        e.finish()
    }

    /// Parse one request body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d
            .array()
            .map_err(|_| Error::MalformedBundle("ipc request"))?;
        let tag = d
            .uint()
            .map_err(|_| Error::MalformedBundle("ipc request tag"))?;
        match (tag, n) {
            (T_SUBSCRIBE, 1) => {
                d.finish()
                    .map_err(|_| Error::MalformedBundle("ipc request trailing"))?;
                Ok(Request::Subscribe)
            }
            _ => Err(Error::MalformedBundle("ipc request unknown tag")),
        }
    }
}

/// What the node sends.
///
/// Not `#[non_exhaustive]`, for the same reason as
/// [`EventStreamItem`]: a catch-all arm is
/// how a `Lagged` report comes to be silently swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Sent once on connect, before anything else.
    Hello {
        /// The [`PROTOCOL_VERSION`] this node speaks.
        protocol: u64,
    },
    /// This client fell behind and `missed` events were dropped **for it alone**.
    ///
    /// Not an error: an event is a wake, not the delivery mechanism. The client
    /// re-reads the ADR-008 log from its cursor (ADR-020 §7).
    Lagged {
        /// How many events were dropped for this client alone.
        missed: u64,
    },
    /// A node event.
    Event(NodeEvent),
}

impl Frame {
    /// Canonical CBOR body (unframed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Frame::Hello { protocol } => {
                e.array(2).uint(T_HELLO).uint(*protocol);
            }
            Frame::Lagged { missed } => {
                e.array(2).uint(T_LAGGED).uint(*missed);
            }
            Frame::Event(ev) => encode_event(&mut e, ev),
        }
        e.finish()
    }

    /// Parse one frame body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array().map_err(|_| Error::MalformedBundle("ipc frame"))?;
        let tag = d
            .uint()
            .map_err(|_| Error::MalformedBundle("ipc frame tag"))?;
        let out = decode_body(&mut d, tag, n)?;
        d.finish()
            .map_err(|_| Error::MalformedBundle("ipc frame trailing"))?;
        Ok(out)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    let b = d
        .bytes()
        .map_err(|_| Error::MalformedBundle("ipc digest"))?;
    Digest32::try_from(b).map_err(|_| Error::MalformedBundle("ipc digest length"))
}

fn addr(d: &mut Decoder<'_>) -> Result<std::net::SocketAddr> {
    d.text()
        .map_err(|_| Error::MalformedBundle("ipc addr"))?
        .parse()
        .map_err(|_| Error::MalformedBundle("ipc addr syntax"))
}

fn encode_event(e: &mut Encoder, ev: &NodeEvent) {
    match ev {
        NodeEvent::NewEntry { channel_id, row } => {
            e.array(6)
                .uint(T_NEW_ENTRY)
                .bytes(channel_id)
                .bytes(&row.entry_hash)
                .bytes(&row.author)
                .uint(row.created_secs)
                .text(&row.text);
        }
        NodeEvent::Unlocked => {
            e.array(1).uint(T_UNLOCKED);
        }
        NodeEvent::Locked => {
            e.array(1).uint(T_LOCKED);
        }
        NodeEvent::Shutdown => {
            e.array(1).uint(T_SHUTDOWN);
        }
        NodeEvent::ChannelOpened { channel_id } => {
            e.array(2).uint(T_CHANNEL_OPENED).bytes(channel_id);
        }
        NodeEvent::ChannelClosed { channel_id } => {
            e.array(2).uint(T_CHANNEL_CLOSED).bytes(channel_id);
        }
        NodeEvent::PeerJoined { channel_id, peer } => {
            e.array(3).uint(T_PEER_JOINED).bytes(channel_id).bytes(peer);
        }
        NodeEvent::SenderKeyReceived {
            channel_id,
            peer,
            backfilled,
        } => {
            e.array(4)
                .uint(T_SENDER_KEY)
                .bytes(channel_id)
                .bytes(peer)
                .uint(*backfilled);
        }
        NodeEvent::Forwarding {
            channel_id,
            host,
            service_tag,
            local,
        } => {
            e.array(5)
                .uint(T_FORWARDING)
                .bytes(channel_id)
                .bytes(host)
                .text(service_tag)
                .text(&local.to_string());
        }
        NodeEvent::InviteLink { channel_id, url } => {
            e.array(3).uint(T_INVITE_LINK).bytes(channel_id).text(url);
        }
        NodeEvent::Joined {
            channel_id,
            responder,
        } => {
            e.array(3).uint(T_JOINED).bytes(channel_id).bytes(responder);
        }
        NodeEvent::Consented { channel_id, target } => {
            e.array(3).uint(T_CONSENTED).bytes(channel_id).bytes(target);
        }
        NodeEvent::Revoked {
            channel_id,
            target,
            generation,
            rekeyed,
        } => {
            e.array(5)
                .uint(T_REVOKED)
                .bytes(channel_id)
                .bytes(target)
                .uint(*generation)
                .uint(*rekeyed);
        }
        NodeEvent::TunnelServed {
            channel_id,
            client,
            service_tag,
        } => {
            e.array(4)
                .uint(T_TUNNEL_SERVED)
                .bytes(channel_id)
                .bytes(client)
                .text(service_tag);
        }
        NodeEvent::ProxyUp {
            channel_id,
            hostname,
            bind,
        } => {
            e.array(4)
                .uint(T_PROXY_UP)
                .bytes(channel_id)
                .text(hostname)
                .text(&bind.to_string());
        }
        NodeEvent::Synced {
            channel_id,
            applied,
            rendered,
        } => {
            e.array(4)
                .uint(T_SYNCED)
                .bytes(channel_id)
                .uint(*applied)
                .uint(*rendered);
        }
    }
    // Deliberately no catch-all. `NodeEvent` is `#[non_exhaustive]`, but that
    // only obliges *other* crates; inside `vox-core` this match is exhaustive,
    // so adding a variant upstream breaks this build until it is given a codec
    // arm. A `_` here would instead drop the new event silently — the compiler
    // is a better guard than any runtime fallback.
}

fn decode_body(d: &mut Decoder<'_>, tag: u64, n: usize) -> Result<Frame> {
    let ev = match (tag, n) {
        (T_HELLO, 2) => {
            return Ok(Frame::Hello {
                protocol: d.uint().map_err(|_| Error::MalformedBundle("ipc hello"))?,
            })
        }
        (T_LAGGED, 2) => {
            return Ok(Frame::Lagged {
                missed: d.uint().map_err(|_| Error::MalformedBundle("ipc lagged"))?,
            })
        }
        (T_NEW_ENTRY, 6) => {
            let channel_id = digest(d)?;
            let entry_hash = digest(d)?;
            let author = digest(d)?;
            let created_secs = d.uint().map_err(|_| Error::MalformedBundle("ipc secs"))?;
            let text = d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc text"))?
                .to_owned();
            NodeEvent::NewEntry {
                channel_id,
                row: MessageRow {
                    entry_hash,
                    author,
                    created_secs,
                    text,
                },
            }
        }
        (T_UNLOCKED, 1) => NodeEvent::Unlocked,
        (T_LOCKED, 1) => NodeEvent::Locked,
        (T_SHUTDOWN, 1) => NodeEvent::Shutdown,
        (T_CHANNEL_OPENED, 2) => NodeEvent::ChannelOpened {
            channel_id: digest(d)?,
        },
        (T_CHANNEL_CLOSED, 2) => NodeEvent::ChannelClosed {
            channel_id: digest(d)?,
        },
        (T_PEER_JOINED, 3) => NodeEvent::PeerJoined {
            channel_id: digest(d)?,
            peer: digest(d)?,
        },
        (T_SENDER_KEY, 4) => NodeEvent::SenderKeyReceived {
            channel_id: digest(d)?,
            peer: digest(d)?,
            backfilled: d.uint().map_err(|_| Error::MalformedBundle("ipc n"))?,
        },
        (T_FORWARDING, 5) => NodeEvent::Forwarding {
            channel_id: digest(d)?,
            host: digest(d)?,
            service_tag: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc tag"))?
                .to_owned(),
            local: addr(d)?,
        },
        (T_INVITE_LINK, 3) => NodeEvent::InviteLink {
            channel_id: digest(d)?,
            url: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc url"))?
                .to_owned(),
        },
        (T_JOINED, 3) => NodeEvent::Joined {
            channel_id: digest(d)?,
            responder: digest(d)?,
        },
        (T_CONSENTED, 3) => NodeEvent::Consented {
            channel_id: digest(d)?,
            target: digest(d)?,
        },
        (T_REVOKED, 5) => NodeEvent::Revoked {
            channel_id: digest(d)?,
            target: digest(d)?,
            generation: d.uint().map_err(|_| Error::MalformedBundle("ipc gen"))?,
            rekeyed: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc rekeyed"))?,
        },
        (T_TUNNEL_SERVED, 4) => NodeEvent::TunnelServed {
            channel_id: digest(d)?,
            client: digest(d)?,
            service_tag: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc tag"))?
                .to_owned(),
        },
        (T_PROXY_UP, 4) => NodeEvent::ProxyUp {
            channel_id: digest(d)?,
            hostname: d
                .text()
                .map_err(|_| Error::MalformedBundle("ipc host"))?
                .to_owned(),
            bind: addr(d)?,
        },
        (T_SYNCED, 4) => NodeEvent::Synced {
            channel_id: digest(d)?,
            applied: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc applied"))?,
            rendered: d
                .uint()
                .map_err(|_| Error::MalformedBundle("ipc rendered"))?,
        },
        _ => return Err(Error::MalformedBundle("ipc frame unknown tag")),
    };
    Ok(Frame::Event(ev))
}

// ---- transport -------------------------------------------------------------

/// Write one length-prefixed frame, mirroring [`crate::transport::framing`].
pub async fn write_frame(s: &mut UnixStream, body: &[u8]) -> Result<()> {
    let len =
        u32::try_from(body.len()).map_err(|_| Error::SizeLimitExceeded("ipc frame length"))?;
    s.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| Error::MalformedBundle("ipc write len"))?;
    s.write_all(body)
        .await
        .map_err(|_| Error::MalformedBundle("ipc write body"))?;
    Ok(())
}

/// Read one length-prefixed frame of at most `MAX_FRAME` bytes. A clean EOF
/// exactly at a frame boundary is the peer hanging up → `Ok(None)`.
pub async fn read_frame(s: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match s.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(Error::MalformedBundle("ipc read len")),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::SizeLimitExceeded("ipc frame length"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)
        .await
        .map_err(|_| Error::MalformedBundle("ipc read body"))?;
    Ok(Some(body))
}

// ---- server ----------------------------------------------------------------

/// A bound control socket. Dropping it stops accepting and unlinks the path.
#[derive(Debug)]
pub struct IpcServer {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl IpcServer {
    /// The bound path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.task.abort();
        // Best effort: leaving the file behind only costs the next bind an
        // unlink, which `bind_at` does anyway.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the control socket at `path` and serve `handle`'s event stream to every
/// client that connects.
///
/// The stale socket file of a process that died is **unlinked first**: `bind`
/// fails with `AddrInUse` otherwise (measured), and inheriting that error would
/// report a dead predecessor as a live conflict. The socket is then chmod'd to
/// `0600` — `bind` itself yields `0755` from the umask (also measured), so this
/// is load-bearing, not decoration.
pub fn bind_at(handle: NodeHandle, path: PathBuf) -> Result<IpcServer> {
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Path {
            op: "unlink stale control socket",
            detail: format!("{}: {e}", path.display()),
        })?;
    }
    let listener = UnixListener::bind(&path).map_err(|e| Error::Path {
        op: "bind control socket",
        detail: format!("{}: {e}", path.display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            Error::Path {
                op: "chmod control socket",
                detail: format!("{}: {e}", path.display()),
            }
        })?;
    }

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // The listener is gone; nothing left to accept.
                return;
            };
            // Each client gets its own task and its own subscription, so one
            // client's pace — or death — reaches no other and never the actor.
            let stream_handle = handle.clone();
            tokio::spawn(async move {
                let _ = serve_client(stream, stream_handle).await;
            });
        }
    });

    Ok(IpcServer { path, task })
}

/// Bind the control socket at this profile's conventional path.
pub fn bind(handle: NodeHandle, paths: &crate::node::paths::Paths) -> Result<IpcServer> {
    bind_at(handle, paths.socket_file())
}

/// One client: greet, wait for `Subscribe`, then stream until either side stops.
async fn serve_client(mut stream: UnixStream, handle: NodeHandle) -> Result<()> {
    write_frame(
        &mut stream,
        &Frame::Hello {
            protocol: PROTOCOL_VERSION,
        }
        .to_bytes(),
    )
    .await?;

    // Subscribe BEFORE answering, so nothing emitted between the request and the
    // first read is missed.
    let Some(body) = read_frame(&mut stream).await? else {
        return Ok(());
    };
    match Request::from_bytes(&body)? {
        Request::Subscribe => {}
    }
    let events = handle.subscribe();
    pump(stream, events).await
}

/// Forward a subscription to a client until the client goes away or the node
/// stops. Any write failure ends **this** connection and nothing else — a client
/// that died mid-stream shows up as `BrokenPipe` here (measured).
async fn pump(mut stream: UnixStream, mut events: EventStream) -> Result<()> {
    while let Some(item) = events.next().await {
        let frame = match item {
            EventStreamItem::Event(ev) => Frame::Event(ev),
            EventStreamItem::Lagged(missed) => Frame::Lagged { missed },
        };
        if write_frame(&mut stream, &frame.to_bytes()).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

// ---- client ----------------------------------------------------------------

/// A connected client of a node's control socket.
#[derive(Debug)]
pub struct IpcClient {
    stream: UnixStream,
}

impl IpcClient {
    /// Connect, check the protocol version, and subscribe.
    pub async fn connect(path: &Path) -> Result<Self> {
        let mut stream = UnixStream::connect(path).await.map_err(|e| Error::Path {
            op: "connect control socket",
            detail: format!("{}: {e}", path.display()),
        })?;
        let Some(hello) = read_frame(&mut stream).await? else {
            return Err(Error::MalformedBundle("ipc closed before hello"));
        };
        match Frame::from_bytes(&hello)? {
            Frame::Hello { protocol } if protocol == PROTOCOL_VERSION => {}
            Frame::Hello { .. } => {
                // A version we do not know: disconnect rather than guess at the
                // shape of the frames that would follow.
                return Err(Error::MalformedBundle("ipc protocol version"));
            }
            _ => return Err(Error::MalformedBundle("ipc expected hello")),
        }
        write_frame(&mut stream, &Request::Subscribe.to_bytes()).await?;
        Ok(Self { stream })
    }

    /// The next frame, or `None` once the node has gone.
    pub async fn next(&mut self) -> Result<Option<Frame>> {
        match read_frame(&mut self.stream).await? {
            Some(body) => Ok(Some(Frame::from_bytes(&body)?)),
            None => Ok(None),
        }
    }
}
