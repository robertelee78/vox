//! Local naming over the control socket (PRD-001 R20, ADR-017 decision 7).
//!
//! Two requests, additive to protocol 6 and away from the sequential tags:
//!
//! - **Resolve** `<node>.<room>.vox` against the running node's rooms and keyring, which is
//!   what lets `vox forward ssh.nas.family.vox` work while a daemon holds the profile.
//! - **Up**: where is the `.vox` proxy? The daemon runs it while any node is attached
//!   (ADR-028 S-5) and answers with its address, or the reason it is not running.

use std::net::SocketAddr;

use tokio::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::ipc::{read_frame, write_frame, Frame, NodeSocket};
use crate::node::resolver::{ServiceRoom, ShareState};

const T_RESOLVE: u64 = 2401;
const T_RESOLVED: u64 = 2402;
const T_UP: u64 = 2403;
const T_UP_BOUND: u64 = 2404;

/// A naming request, the first frame after hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameRequest {
    /// Resolve a `.vox` name.
    Resolve(String),
    /// Where is the daemon's proxy? (The text is unused, kept from when it named an address.)
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

/// The answer to [`NameRequest::Up`]: the proxy listens at `bound`. The daemon sends it
/// (ADR-028 S-5), from the proxy it runs while a node is attached.
#[must_use]
pub fn up_bound(bound: SocketAddr) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(T_UP_BOUND).text(&bound.to_string());
    e.finish()
}

fn error(reason: String) -> Vec<u8> {
    Frame::Error { reason }.to_bytes()
}

/// Serve one naming request. Returns whether the connection may serve more requests
/// (a resolve) or is finished (an up).
///
/// # Errors
/// If writing to the client fails.
pub async fn serve(stream: &mut UnixStream, handle: &NodeHandle, req: NameRequest) -> Result<bool> {
    match req {
        NameRequest::Resolve(name) => {
            let body = match handle.resolve_name(&name).await {
                Ok(room) => {
                    let mut e = Encoder::new();
                    let share = match room.share {
                        ShareState::Stated => 0,
                        ShareState::Absent => 1,
                        ShareState::NotYetKnown => 2,
                    };
                    e.array(5)
                        .uint(T_RESOLVED)
                        .bytes(&room.channel_id)
                        .bytes(&room.host)
                        .text(&room.service)
                        .uint(share);
                    e.finish()
                }
                Err(why) => error(why),
            };
            write_frame(stream, &body).await?;
            Ok(true)
        }
        // The proxy is the daemon's (ADR-028 S-5), and the daemon answers this before a node
        // sees it; a node asked directly has none to report.
        NameRequest::Up(_) => {
            write_frame(
                stream,
                &error("the .vox proxy is run by the vox daemon, which did not answer".to_owned()),
            )
            .await?;
            Ok(false)
        }
    }
}

/// A connection to the daemon acting as the node `at` names (ADR-026 C-2).
async fn connect(at: &NodeSocket) -> Result<UnixStream> {
    Ok(crate::node::ipc::open_as(at).await?.0)
}

fn reason(body: &[u8]) -> Error {
    match Frame::from_bytes(body) {
        Ok(Frame::Error { reason }) => Error::AppRefused(reason),
        _ => Error::MalformedBundle("ipc naming reply"),
    }
}

/// Resolve `name` with the node `at` names: the room, the member, the service's tag, and what
/// the room's log says of the share.
///
/// # Errors
/// If no node answers, or the name leads nowhere — with the node's reason.
pub async fn resolve(at: &NodeSocket, name: &str) -> Result<ServiceRoom> {
    let mut stream = connect(at).await?;
    write_frame(
        &mut stream,
        &NameRequest::Resolve(name.to_owned()).to_bytes(),
    )
    .await?;
    let body = read_frame(&mut stream)
        .await?
        .ok_or(Error::MalformedBundle("ipc closed before reply"))?;
    let mut d = Decoder::new(&body);
    if let (Ok(5), Ok(T_RESOLVED)) = (d.array(), d.uint()) {
        let mut digest = || -> Result<Digest32> {
            Digest32::try_from(
                d.bytes()
                    .map_err(|_| Error::MalformedBundle("ipc naming"))?,
            )
            .map_err(|_| Error::MalformedBundle("ipc naming"))
        };
        let (channel_id, host) = (digest()?, digest()?);
        let service = d
            .text()
            .map_err(|_| Error::MalformedBundle("ipc naming"))?
            .to_owned();
        let share = match d.uint() {
            Ok(0) => ShareState::Stated,
            Ok(1) => ShareState::Absent,
            Ok(2) => ShareState::NotYetKnown,
            _ => return Err(Error::MalformedBundle("ipc naming")),
        };
        return Ok(ServiceRoom {
            channel_id,
            host,
            service,
            share,
        });
    }
    Err(reason(&body))
}

/// Where the daemon's `.vox` proxy listens (ADR-028 S-5), asked as the node `at` names, which
/// must be attached: the proxy runs while any node is.
///
/// # Errors
/// If no daemon answers, or the proxy is not running, with the daemon's reason.
pub async fn proxy(at: &NodeSocket) -> Result<SocketAddr> {
    let mut stream = connect(at).await?;
    write_frame(&mut stream, &NameRequest::Up(String::new()).to_bytes()).await?;
    let body = read_frame(&mut stream)
        .await?
        .ok_or(Error::MalformedBundle("ipc closed before reply"))?;
    let mut d = Decoder::new(&body);
    if let (Ok(2), Ok(T_UP_BOUND)) = (d.array(), d.uint()) {
        return d
            .text()
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or(Error::MalformedBundle("ipc up reply"));
    }
    Err(reason(&body))
}
