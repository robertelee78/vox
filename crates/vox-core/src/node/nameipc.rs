//! Local naming over the control socket (PRD-001 R20, ADR-017 decision 7).
//!
//! Two requests, additive to protocol 6 and away from the sequential tags:
//!
//! - **Resolve** `<node>.<room>.vox` against the running node's rooms and keyring, which is
//!   what lets `vox forward nas.family.vox 22` work while a daemon holds the profile.
//! - **Up**: bring the SOCKS proxy up inside the running node, across every room it
//!   holds. The connection then carries one line per refusal or cut session, and the
//!   proxy stops when the connection closes — so `vox up` stays a foreground command whose
//!   ^C stops it.

use std::net::SocketAddr;
use std::path::Path;

use tokio::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::ipc::{read_frame, write_frame, Frame, PROTOCOL_VERSION};

const T_RESOLVE: u64 = 2401;
const T_RESOLVED: u64 = 2402;
const T_UP: u64 = 2403;
const T_UP_BOUND: u64 = 2404;
const T_UP_NOTE: u64 = 2405;

/// A naming request, the first frame after hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameRequest {
    /// Resolve a `.vox` name.
    Resolve(String),
    /// Bring the proxy up at this address.
    Up(String),
}

impl NameRequest {
    /// `None` if `body` is not a naming request.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(body);
        let (Ok(2), Ok(tag)) = (d.array(), d.uint()) else {
            return None;
        };
        let text = d.text().ok()?.to_owned();
        d.finish().ok()?;
        match tag {
            T_RESOLVE => Some(Self::Resolve(text)),
            T_UP => Some(Self::Up(text)),
            _ => None,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let (tag, text) = match self {
            Self::Resolve(t) => (T_RESOLVE, t),
            Self::Up(t) => (T_UP, t),
        };
        let mut e = Encoder::new();
        e.array(2).uint(tag).text(text);
        e.finish()
    }
}

fn error(reason: String) -> Vec<u8> {
    Frame::Error { reason }.to_bytes()
}

/// Serve one naming request. Returns whether the connection may serve more requests
/// (a resolve) or is finished (an up, which lives until the client leaves).
///
/// # Errors
/// If writing to the client fails.
pub async fn serve(stream: &mut UnixStream, handle: &NodeHandle, req: NameRequest) -> Result<bool> {
    match req {
        NameRequest::Resolve(name) => {
            let body = match handle.resolve_name(&name).await {
                Ok(room) => {
                    let mut e = Encoder::new();
                    e.array(3)
                        .uint(T_RESOLVED)
                        .bytes(&room.channel_id)
                        .bytes(&room.host);
                    e.finish()
                }
                Err(why) => error(why),
            };
            write_frame(stream, &body).await?;
            Ok(true)
        }
        NameRequest::Up(bind) => {
            let Ok(bind) = bind.parse::<SocketAddr>() else {
                write_frame(stream, &error(format!("{bind:?} is not an address"))).await?;
                return Ok(false);
            };
            let (tx, mut notes) = tokio::sync::mpsc::unbounded_channel();
            let (bound, proxy) = match handle.up_all(bind, tx).await {
                Ok(up) => up,
                Err(e) => {
                    write_frame(stream, &error(e.to_string())).await?;
                    return Ok(false);
                }
            };
            let mut e = Encoder::new();
            e.array(2).uint(T_UP_BOUND).text(&bound.to_string());
            let answered = write_frame(stream, &e.finish()).await;
            // The proxy lives exactly as long as this connection.
            let mut probe = [0u8; 1];
            if answered.is_ok() {
                let (mut r, mut w) = stream.split();
                loop {
                    tokio::select! {
                        n = tokio::io::AsyncReadExt::read(&mut r, &mut probe) => {
                            if !matches!(n, Ok(k) if k > 0) {
                                break;
                            }
                        }
                        note = notes.recv() => {
                            let Some(note) = note else { break };
                            let mut e = Encoder::new();
                            e.array(2).uint(T_UP_NOTE).text(&note);
                            let body = e.finish();
                            let len = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
                            let wrote = async {
                                tokio::io::AsyncWriteExt::write_all(&mut w, &len).await?;
                                tokio::io::AsyncWriteExt::write_all(&mut w, &body).await
                            }
                            .await;
                            if wrote.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            proxy.abort();
            Ok(false)
        }
    }
}

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
        _ => Err(Error::MalformedBundle("ipc protocol version")),
    }
}

fn reason(body: &[u8]) -> Error {
    match Frame::from_bytes(body) {
        Ok(Frame::Error { reason }) => Error::AppRefused(reason),
        _ => Error::MalformedBundle("ipc naming reply"),
    }
}

/// Resolve `name` with the node at `path`: `(room, member)`.
///
/// # Errors
/// If no node answers, or the name leads nowhere — with the node's reason.
pub async fn resolve(path: &Path, name: &str) -> Result<(Digest32, Digest32)> {
    let mut stream = connect(path).await?;
    write_frame(
        &mut stream,
        &NameRequest::Resolve(name.to_owned()).to_bytes(),
    )
    .await?;
    let body = read_frame(&mut stream)
        .await?
        .ok_or(Error::MalformedBundle("ipc closed before reply"))?;
    let mut d = Decoder::new(&body);
    if let (Ok(3), Ok(T_RESOLVED)) = (d.array(), d.uint()) {
        let mut digest = || -> Result<Digest32> {
            Digest32::try_from(
                d.bytes()
                    .map_err(|_| Error::MalformedBundle("ipc naming"))?,
            )
            .map_err(|_| Error::MalformedBundle("ipc naming"))
        };
        return Ok((digest()?, digest()?));
    }
    Err(reason(&body))
}

/// A proxy running inside the node at `path`, alive while this is held.
#[derive(Debug)]
pub struct RemoteUp {
    stream: UnixStream,
    /// Where it listens.
    pub bound: SocketAddr,
}

impl RemoteUp {
    /// The next refusal or cut session, as a sentence; `None` when the node has gone.
    pub async fn next_note(&mut self) -> Option<String> {
        let body = read_frame(&mut self.stream).await.ok()??;
        let mut d = Decoder::new(&body);
        match (d.array(), d.uint()) {
            (Ok(2), Ok(T_UP_NOTE)) => d.text().ok().map(str::to_owned),
            _ => None,
        }
    }
}

/// Bring the proxy up inside the node at `path`, across every room it holds.
///
/// # Errors
/// If no node answers, or it could not bind.
pub async fn up(path: &Path, bind: SocketAddr) -> Result<RemoteUp> {
    let mut stream = connect(path).await?;
    write_frame(&mut stream, &NameRequest::Up(bind.to_string()).to_bytes()).await?;
    let body = read_frame(&mut stream)
        .await?
        .ok_or(Error::MalformedBundle("ipc closed before reply"))?;
    let mut d = Decoder::new(&body);
    if let (Ok(2), Ok(T_UP_BOUND)) = (d.array(), d.uint()) {
        let bound = d
            .text()
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or(Error::MalformedBundle("ipc up reply"))?;
        return Ok(RemoteUp { stream, bound });
    }
    Err(reason(&body))
}
