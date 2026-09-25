//! IPC protocol 6 — the app API over the node's control socket (ADR-022 decision 7).
//!
//! The same `0600` socket as [`crate::node::ipc`], the same hello and the same
//! length-delimited canonical-CBOR frames. A connection whose **first** request is one
//! of these becomes an app connection for its whole life:
//!
//! | request | the connection becomes |
//! |---|---|
//! | `AppListen{room or any, label}` | a listener registration: one `AppIncoming{id, room, peer, label}` frame per incoming stream, until the connection closes |
//! | `AppAccept{id}` | a splice of that incoming stream |
//! | `AppOpen{room, peer, labels, datagrams}` | a splice of a new outbound stream |
//!
//! One Unix connection per app stream: accepting on a **fresh** connection is what lets a
//! program hold a listener and any number of streams at once without multiplexing them
//! itself.
//!
//! ## After the splice handshake
//!
//! The node answers `AppSplice{room, peer, label, datagrams}` (or an error frame), and
//! from then on the connection carries the stream:
//!
//! - **without datagrams**, raw bytes both ways. The client's end of input finishes the
//!   stream; the peer finishing it shuts the connection's write side.
//! - **with datagrams**, frames `u32 length ‖ u8 kind ‖ payload`, kind 0 stream bytes,
//!   1 one datagram, 2 end of stream. Datagrams and stream bytes interleave on one
//!   connection, so each must say which it is.
//!
//! The connection closes when both halves of the stream have ended, or at once when the
//! stream fails — including when trust is withdrawn on either side.
//!
//! These tags sit far from the sequential ones in [`crate::node::ipc`], as its later
//! additive tags do, so they cannot collide with a tag another branch assigns there.

use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::app::{AppIncoming, AppInfo, AppStream, MAX_LABELS};
use crate::node::ipc::{read_frame, write_frame, Frame, PROTOCOL_VERSION};

const T_APP_LISTEN: u64 = 2201;
const T_APP_ACCEPT: u64 = 2202;
const T_APP_OPEN: u64 = 2203;
const T_APP_LISTENING: u64 = 2210;
const T_APP_INCOMING: u64 = 2211;
const T_APP_SPLICE: u64 = 2212;

/// Splice frame kinds, in datagram mode.
const K_DATA: u8 = 0;
const K_DATAGRAM: u8 = 1;
const K_FIN: u8 = 2;

/// The largest splice frame: a datagram is at most 64 KiB.
const MAX_SPLICE_FRAME: usize = 70 * 1024;

/// An app request, the first frame of an app connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppRequest {
    /// Register a listener.
    Listen {
        /// The room, or `None` for any room.
        channel_id: Option<Digest32>,
        /// The label.
        label: String,
    },
    /// Accept an announced incoming stream.
    Accept {
        /// The id from `AppIncoming`.
        id: u64,
    },
    /// Open a stream.
    Open {
        /// The room whose gate applies.
        channel_id: Digest32,
        /// The target member node.
        peer: Digest32,
        /// Labels in preference order.
        labels: Vec<String>,
        /// Whether to bind a datagram flow.
        datagrams: bool,
    },
}

impl AppRequest {
    /// Canonical CBOR.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            AppRequest::Listen { channel_id, label } => {
                e.array(3)
                    .uint(T_APP_LISTEN)
                    .bytes(channel_id.as_ref().map_or(&[][..], |c| &c[..]))
                    .text(label);
            }
            AppRequest::Accept { id } => {
                e.array(2).uint(T_APP_ACCEPT).uint(*id);
            }
            AppRequest::Open {
                channel_id,
                peer,
                labels,
                datagrams,
            } => {
                e.array(5).uint(T_APP_OPEN).bytes(channel_id).bytes(peer);
                e.array(labels.len());
                for l in labels {
                    e.text(l);
                }
                e.uint(u64::from(*datagrams));
            }
        }
        e.finish()
    }

    /// `None` if `body` is not an app request at all (it is some other protocol
    /// request); otherwise the strict parse.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Result<Self>> {
        let mut d = Decoder::new(body);
        let n = d.array().ok()?;
        let tag = d.uint().ok()?;
        if !(T_APP_LISTEN..=T_APP_OPEN).contains(&tag) {
            return None;
        }
        Some(Self::parse_rest(d, tag, n))
    }

    fn parse_rest(mut d: Decoder<'_>, tag: u64, n: usize) -> Result<Self> {
        let bad = |_| Error::MalformedBundle("ipc app request");
        let digest = |d: &mut Decoder<'_>| -> Result<Digest32> {
            Digest32::try_from(d.bytes().map_err(bad)?)
                .map_err(|_| Error::MalformedBundle("ipc app request"))
        };
        let req = match (tag, n) {
            (T_APP_LISTEN, 3) => {
                let room = d.bytes().map_err(bad)?;
                let channel_id = if room.is_empty() {
                    None
                } else {
                    Some(
                        Digest32::try_from(room)
                            .map_err(|_| Error::MalformedBundle("ipc app request"))?,
                    )
                };
                let label = d.text().map_err(bad)?.to_owned();
                AppRequest::Listen { channel_id, label }
            }
            (T_APP_ACCEPT, 2) => AppRequest::Accept {
                id: d.uint().map_err(bad)?,
            },
            (T_APP_OPEN, 5) => {
                let channel_id = digest(&mut d)?;
                let peer = digest(&mut d)?;
                let count = d.array().map_err(bad)?;
                if count > MAX_LABELS {
                    return Err(Error::MalformedBundle("ipc app request"));
                }
                let mut labels = Vec::new();
                for _ in 0..count {
                    labels.push(d.text().map_err(bad)?.to_owned());
                }
                let datagrams = d.uint().map_err(bad)? != 0;
                AppRequest::Open {
                    channel_id,
                    peer,
                    labels,
                    datagrams,
                }
            }
            _ => return Err(Error::MalformedBundle("ipc app request")),
        };
        d.finish().map_err(bad)?;
        Ok(req)
    }
}

/// What the node says on an app connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppReply {
    /// The listener is registered.
    Listening,
    /// An incoming stream waits to be accepted.
    Incoming(AppIncoming),
    /// The stream is up; the splice follows.
    Splice(AppInfo),
    /// Refused, and why.
    Error(String),
}

impl AppReply {
    fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            AppReply::Listening => {
                e.array(1).uint(T_APP_LISTENING);
            }
            AppReply::Incoming(i) => {
                e.array(5)
                    .uint(T_APP_INCOMING)
                    .uint(i.id)
                    .bytes(&i.channel_id)
                    .bytes(&i.peer)
                    .text(&i.label);
            }
            AppReply::Splice(info) => {
                e.array(5)
                    .uint(T_APP_SPLICE)
                    .bytes(&info.channel_id)
                    .bytes(&info.peer)
                    .text(&info.label)
                    .uint(u64::from(info.datagrams));
            }
            AppReply::Error(reason) => {
                return Frame::Error {
                    reason: reason.clone(),
                }
                .to_bytes()
            }
        }
        e.finish()
    }

    fn from_bytes(body: &[u8]) -> Result<Self> {
        let bad = |_| Error::MalformedBundle("ipc app reply");
        let mut d = Decoder::new(body);
        let n = d.array().map_err(bad)?;
        let tag = d.uint().map_err(bad)?;
        let digest = |d: &mut Decoder<'_>| -> Result<Digest32> {
            Digest32::try_from(d.bytes().map_err(bad)?)
                .map_err(|_| Error::MalformedBundle("ipc app reply"))
        };
        let reply = match (tag, n) {
            (T_APP_LISTENING, 1) => AppReply::Listening,
            (T_APP_INCOMING, 5) => AppReply::Incoming(AppIncoming {
                id: d.uint().map_err(bad)?,
                channel_id: digest(&mut d)?,
                peer: digest(&mut d)?,
                label: d.text().map_err(bad)?.to_owned(),
            }),
            (T_APP_SPLICE, 5) => AppReply::Splice(AppInfo {
                channel_id: digest(&mut d)?,
                peer: digest(&mut d)?,
                label: d.text().map_err(bad)?.to_owned(),
                datagrams: d.uint().map_err(bad)? != 0,
            }),
            _ => {
                return match Frame::from_bytes(body)? {
                    Frame::Error { reason } => Ok(AppReply::Error(reason)),
                    _ => Err(Error::MalformedBundle("ipc app reply")),
                }
            }
        };
        d.finish().map_err(bad)?;
        Ok(reply)
    }
}

// ---- server ----------------------------------------------------------------

/// Serve one app connection whose first request was `request`. Called by the control
/// socket after its hello.
pub async fn serve(mut stream: UnixStream, handle: NodeHandle, request: AppRequest) -> Result<()> {
    let hub = Arc::clone(handle.app());
    match request {
        AppRequest::Listen { channel_id, label } => {
            let mut listener = match hub.listen(channel_id, &label) {
                Ok(l) => l,
                Err(e) => {
                    return write_frame(&mut stream, &AppReply::Error(e.to_string()).to_bytes())
                        .await
                }
            };
            write_frame(&mut stream, &AppReply::Listening.to_bytes()).await?;
            let (mut r, mut w) = stream.into_split();
            let mut probe = [0u8; 1];
            loop {
                tokio::select! {
                    // The registration lives exactly as long as this connection.
                    _ = r.read(&mut probe) => return Ok(()),
                    incoming = listener.next() => {
                        let Some(incoming) = incoming else { return Ok(()) };
                        let body = AppReply::Incoming(incoming).to_bytes();
                        write_unix(&mut w, &body).await?;
                    }
                }
            }
        }
        AppRequest::Accept { id } => match hub.accept(id).await {
            Ok(app) => splice(stream, app).await,
            Err(e) => write_frame(&mut stream, &AppReply::Error(e.to_string()).to_bytes()).await,
        },
        AppRequest::Open {
            channel_id,
            peer,
            labels,
            datagrams,
        } => match hub.open(channel_id, peer, labels, datagrams).await {
            Ok(app) => splice(stream, app).await,
            Err(e) => write_frame(&mut stream, &AppReply::Error(e.to_string()).to_bytes()).await,
        },
    }
}

async fn write_unix(w: &mut tokio::net::unix::OwnedWriteHalf, body: &[u8]) -> Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| Error::SizeLimitExceeded("ipc frame"))?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| Error::MalformedBundle("ipc write"))?;
    w.write_all(body)
        .await
        .map_err(|_| Error::MalformedBundle("ipc write"))
}

/// One splice frame, in datagram mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpliceFrame {
    /// Stream bytes.
    Data(Vec<u8>),
    /// One datagram.
    Datagram(Vec<u8>),
    /// The sender's half of the stream has ended.
    Fin,
}

/// Write one splice frame.
///
/// # Errors
/// If the write fails.
pub async fn write_splice<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    frame: &SpliceFrame,
) -> Result<()> {
    let (kind, payload): (u8, &[u8]) = match frame {
        SpliceFrame::Data(d) => (K_DATA, d),
        SpliceFrame::Datagram(d) => (K_DATAGRAM, d),
        SpliceFrame::Fin => (K_FIN, &[]),
    };
    let len = u32::try_from(payload.len() + 1).map_err(|_| Error::SizeLimitExceeded("splice"))?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(payload);
    w.write_all(&out)
        .await
        .map_err(|_| Error::MalformedBundle("splice write"))
}

/// Read one splice frame; `None` at a clean end of input. Not cancel-safe.
///
/// # Errors
/// If the frame is malformed or too large.
pub async fn read_splice<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<SpliceFrame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(Error::MalformedBundle("splice read")),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_SPLICE_FRAME {
        return Err(Error::SizeLimitExceeded("splice frame"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .await
        .map_err(|_| Error::MalformedBundle("splice read"))?;
    let payload = body.split_off(1);
    match body[0] {
        K_DATA => Ok(Some(SpliceFrame::Data(payload))),
        K_DATAGRAM => Ok(Some(SpliceFrame::Datagram(payload))),
        K_FIN => Ok(Some(SpliceFrame::Fin)),
        _ => Err(Error::MalformedBundle("splice kind")),
    }
}

/// Carry `app` over `unix` until both halves of the stream end, or it fails.
async fn splice(mut unix: UnixStream, app: AppStream) -> Result<()> {
    write_frame(&mut unix, &AppReply::Splice(app.info().clone()).to_bytes()).await?;
    let framed = app.info().datagrams;
    let app = Arc::new(app);
    let (mut ur, mut uw) = unix.into_split();

    // Client → peer, on its own task: reading a frame is not cancel-safe.
    let (up_tx, mut up_done) = tokio::sync::oneshot::channel::<Result<()>>();
    let up_app = Arc::clone(&app);
    let up = tokio::spawn(async move {
        let result: Result<()> = async {
            if framed {
                while let Some(frame) = read_splice(&mut ur).await? {
                    match frame {
                        SpliceFrame::Data(d) => up_app.write_all(&d).await?,
                        SpliceFrame::Datagram(d) => up_app.send_datagram(&d)?,
                        SpliceFrame::Fin => up_app.finish().await,
                    }
                }
            } else {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = ur
                        .read(&mut buf)
                        .await
                        .map_err(|_| Error::MalformedBundle("ipc read"))?;
                    if n == 0 {
                        break;
                    }
                    up_app.write_all(&buf[..n]).await?;
                }
            }
            up_app.finish().await;
            Ok(())
        }
        .await;
        let _ = up_tx.send(result);
    });

    // Peer → client, here.
    let mut buf = vec![0u8; 64 * 1024];
    let (mut peer_done, mut client_done, mut flow_open) = (false, false, framed);
    let outcome: Result<()> = loop {
        if peer_done && client_done {
            break Ok(());
        }
        tokio::select! {
            r = app.read(&mut buf), if !peer_done => match r {
                Ok(Some(n)) => {
                    let w = if framed {
                        write_splice(&mut uw, &SpliceFrame::Data(buf[..n].to_vec())).await
                    } else {
                        uw.write_all(&buf[..n]).await.map_err(|_| Error::MalformedBundle("ipc write"))
                    };
                    if let Err(e) = w { break Err(e) }
                }
                Ok(None) => {
                    peer_done = true;
                    let w = if framed {
                        write_splice(&mut uw, &SpliceFrame::Fin).await
                    } else {
                        uw.shutdown().await.map_err(|_| Error::MalformedBundle("ipc shutdown"))
                    };
                    if let Err(e) = w { break Err(e) }
                }
                Err(e) => break Err(e),
            },
            d = app.recv_datagram(), if flow_open => match d {
                Some(d) => {
                    if let Err(e) = write_splice(&mut uw, &SpliceFrame::Datagram(d)).await {
                        break Err(e);
                    }
                }
                None => flow_open = false,
            },
            r = &mut up_done, if !client_done => match r {
                Ok(Ok(())) => client_done = true,
                Ok(Err(e)) => break Err(e),
                Err(_) => break Err(Error::MalformedBundle("ipc splice")),
            },
            () = app.withdrawn() => break Err(Error::TunnelRevoked("app: trust was withdrawn")),
        }
    };
    up.abort();
    outcome
}

// ---- client ----------------------------------------------------------------

async fn connect(path: &Path) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(path).await.map_err(|e| Error::Path {
        op: "connect control socket",
        detail: format!("{}: {e}", path.display()),
    })?;
    let Some(hello) = read_frame(&mut stream).await? else {
        return Err(Error::MalformedBundle("ipc closed before hello"));
    };
    match Frame::from_bytes(&hello)? {
        Frame::Hello { protocol, .. } if protocol == PROTOCOL_VERSION => Ok(stream),
        Frame::Hello { .. } => Err(Error::MalformedBundle("ipc protocol version")),
        _ => Err(Error::MalformedBundle("ipc expected hello")),
    }
}

async fn ask(stream: &mut UnixStream, req: &AppRequest) -> Result<AppReply> {
    write_frame(stream, &req.to_bytes()).await?;
    let Some(body) = read_frame(stream).await? else {
        return Err(Error::MalformedBundle("ipc closed before reply"));
    };
    AppReply::from_bytes(&body)
}

/// A listener registered over the socket.
#[derive(Debug)]
pub struct IpcListener {
    stream: UnixStream,
}

impl IpcListener {
    /// The next incoming stream, or `None` once the node has gone.
    ///
    /// # Errors
    /// If the node sent something that is not an announcement.
    pub async fn next(&mut self) -> Result<Option<AppIncoming>> {
        match read_frame(&mut self.stream).await? {
            None => Ok(None),
            Some(body) => match AppReply::from_bytes(&body)? {
                AppReply::Incoming(i) => Ok(Some(i)),
                _ => Err(Error::MalformedBundle("ipc app listener")),
            },
        }
    }
}

/// What a refused app request said, kept whole for the person reading it.
fn refused(reason: String) -> Error {
    Error::AppRefused(reason)
}

/// Register a listener for `label` in `channel_id` (or any room).
///
/// # Errors
/// If the node is not running, or refuses.
pub async fn listen(path: &Path, channel_id: Option<Digest32>, label: &str) -> Result<IpcListener> {
    let mut stream = connect(path).await?;
    match ask(
        &mut stream,
        &AppRequest::Listen {
            channel_id,
            label: label.to_owned(),
        },
    )
    .await?
    {
        AppReply::Listening => Ok(IpcListener { stream }),
        AppReply::Error(r) => Err(refused(r)),
        _ => Err(Error::MalformedBundle("ipc app reply")),
    }
}

/// Accept incoming stream `id` on a fresh connection, which becomes its splice.
///
/// # Errors
/// If the node is not running, or the stream is not waiting.
pub async fn accept(path: &Path, id: u64) -> Result<(UnixStream, AppInfo)> {
    let mut stream = connect(path).await?;
    match ask(&mut stream, &AppRequest::Accept { id }).await? {
        AppReply::Splice(info) => Ok((stream, info)),
        AppReply::Error(r) => Err(refused(r)),
        _ => Err(Error::MalformedBundle("ipc app reply")),
    }
}

/// Open a stream on a fresh connection, which becomes its splice.
///
/// # Errors
/// If the node is not running, would not open it, or the peer refused.
pub async fn open(
    path: &Path,
    channel_id: Digest32,
    peer: Digest32,
    labels: Vec<String>,
    datagrams: bool,
) -> Result<(UnixStream, AppInfo)> {
    let mut stream = connect(path).await?;
    match ask(
        &mut stream,
        &AppRequest::Open {
            channel_id,
            peer,
            labels,
            datagrams,
        },
    )
    .await?
    {
        AppReply::Splice(info) => Ok((stream, info)),
        AppReply::Error(r) => Err(refused(r)),
        _ => Err(Error::MalformedBundle("ipc app reply")),
    }
}
