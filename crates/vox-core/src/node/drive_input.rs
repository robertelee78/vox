//! ADR-029 §3 — **sending drive input** to a session's node (#544), for every client alike (the
//! CLI, the TUI, the app through the FFI): an ADR-022 app stream from this node to the session's
//! node in the Session's room, speaking [`vox_agentcomms::drive::LABEL`], one request line and one
//! answer line.
//!
//! **A Session on the driver's own node** is driven too: that node is the Session's operator
//! (ADR-029 SC-2), and no app stream runs from a node to itself. The request goes over the
//! node's own control socket instead ([`OwnDrive`]), which only this user's processes reach, and
//! the daemon hands it to the same drive handler a member's stream reaches.

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use vox_agentcomms::drive::{Answer, Request, LABEL, PATIENCE};

use crate::cbor::{Decoder, Encoder};
use crate::hash::Digest32;
use crate::node::ipc::{read_frame, write_frame, Frame, NodeSocket};

const T_DRIVE_OWN: u64 = 5440;
const T_DRIVE_OWN_ANSWER: u64 = 5441;

/// A drive request for a Session on the node the client is attached as, sent on that node's
/// control socket: `[T_DRIVE_OWN, room, request JSON]`. The daemon serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDrive {
    /// The Session's room.
    pub room: Digest32,
    /// The request, as a member's stream carries it.
    pub request: Request,
}

impl OwnDrive {
    /// `None` if `body` is not one.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(body);
        let (Ok(3), Ok(T_DRIVE_OWN)) = (d.array(), d.uint()) else {
            return None;
        };
        let room = Digest32::try_from(d.bytes().ok()?).ok()?;
        let request = serde_json::from_str(d.text().ok()?).ok()?;
        d.finish().ok()?;
        Some(Self { room, request })
    }

    /// As it goes on the node's socket; `None` if the request cannot be written.
    #[must_use]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let json = serde_json::to_string(&self.request).ok()?;
        let mut e = Encoder::new();
        e.array(3).uint(T_DRIVE_OWN).bytes(&self.room).text(&json);
        Some(e.finish())
    }
}

/// The answer an [`own_answer`] frame carries, if `body` is one.
#[must_use]
pub fn parse_own_answer(body: &[u8]) -> Option<Answer> {
    let mut d = Decoder::new(body);
    let (Ok(2), Ok(T_DRIVE_OWN_ANSWER)) = (d.array(), d.uint()) else {
        return None;
    };
    serde_json::from_str(d.text().ok()?).ok()
}

/// The daemon's answer to an [`OwnDrive`], as a frame.
#[must_use]
pub fn own_answer(answer: &Answer) -> Vec<u8> {
    let json = serde_json::to_string(answer).unwrap_or_default();
    let mut e = Encoder::new();
    e.array(2).uint(T_DRIVE_OWN_ANSWER).text(&json);
    e.finish()
}

/// Why nothing is known to have reached the session: the stream could not be opened, or the
/// session's node gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsent {
    /// The session's node could not be reached, or would not take drive input from this node
    /// (the app gate: each node must trust the other). Nothing was sent.
    Unreachable(String),
    /// The request went out and no answer came: whether it was delivered is not known.
    NoAnswer(String),
}

impl std::fmt::Display for Unsent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unsent::Unreachable(w) | Unsent::NoAnswer(w) => f.write_str(w),
        }
    }
}

/// Send `request` to the node `peer` in `room`, from the node behind `at`. The session's node's
/// answer, delivered or refused with its reason; or why no answer is known.
///
/// # Errors
/// [`Unsent`]: the stream could not be opened, or no answer came.
pub async fn send(
    at: &NodeSocket,
    room: Digest32,
    peer: Digest32,
    request: &Request,
) -> Result<Answer, Unsent> {
    if let Ok((stream, Some(me))) = crate::node::ipc::open_as(at).await {
        if me == peer {
            return send_own(stream, room, request).await;
        }
    }
    let (stream, _) = crate::node::appipc::open(at, room, peer, vec![LABEL.to_owned()], false)
        .await
        .map_err(|e| {
            Unsent::Unreachable(format!(
                "the session's node could not be reached, or would not take drive input from \
                 this node ({e}); nothing was sent"
            ))
        })?;
    let (r, mut w) = stream.into_split();
    let mut line = serde_json::to_string(request)
        .map_err(|e| Unsent::Unreachable(format!("the request could not be written: {e}")))?;
    line.push('\n');
    w.write_all(line.as_bytes()).await.map_err(|e| {
        Unsent::Unreachable(format!(
            "the request could not be sent ({e}); nothing was delivered"
        ))
    })?;
    let mut answer = String::new();
    let read = tokio::time::timeout(
        PATIENCE + std::time::Duration::from_secs(5),
        tokio::io::BufReader::new(r).read_line(&mut answer),
    )
    .await;
    match read {
        Ok(Ok(n)) if n > 0 => {}
        Ok(_) => {
            return Err(Unsent::NoAnswer(
                "the session's node closed the stream without an answer; whether it was \
                 delivered is not known"
                    .into(),
            ))
        }
        Err(_) => {
            return Err(Unsent::NoAnswer(
                "the session's node did not answer in time; whether it was delivered is not \
                 known"
                    .into(),
            ))
        }
    }
    serde_json::from_str(answer.trim()).map_err(|_| {
        Unsent::NoAnswer("the session's node answered in a form this vox does not read".into())
    })
}

/// [`send`] for a Session on the node `stream` is attached as.
async fn send_own(
    mut stream: tokio::net::UnixStream,
    room: Digest32,
    request: &Request,
) -> Result<Answer, Unsent> {
    let body = OwnDrive {
        room,
        request: request.clone(),
    }
    .to_bytes()
    .ok_or_else(|| Unsent::Unreachable("the request could not be written".into()))?;
    write_frame(&mut stream, &body).await.map_err(|e| {
        Unsent::Unreachable(format!(
            "the request could not be handed to this node ({e}); nothing was sent"
        ))
    })?;
    let read = tokio::time::timeout(
        PATIENCE + std::time::Duration::from_secs(5),
        read_frame(&mut stream),
    )
    .await;
    let body = match read {
        Ok(Ok(Some(body))) => body,
        Ok(_) => {
            return Err(Unsent::NoAnswer(
                "this node closed the request without an answer; whether it was delivered is \
                 not known"
                    .into(),
            ))
        }
        Err(_) => {
            return Err(Unsent::NoAnswer(
                "this node did not answer in time; whether it was delivered is not known".into(),
            ))
        }
    };
    if let Some(answer) = parse_own_answer(&body) {
        return Ok(answer);
    }
    // A node not run by a daemon has no drive handler: nothing was handed to the session.
    match Frame::from_bytes(&body) {
        Ok(Frame::Error { reason }) => Err(Unsent::Unreachable(format!(
            "this node would not take drive input ({reason}); nothing was sent"
        ))),
        _ => Err(Unsent::NoAnswer(
            "this node answered in a form this vox does not read".into(),
        )),
    }
}
