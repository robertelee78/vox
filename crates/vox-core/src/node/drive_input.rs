//! ADR-029 §3 — **sending drive input** to a session's node (#544), for every client alike (the
//! CLI, the TUI, the app through the FFI): an ADR-022 app stream from this node to the session's
//! node in the Session's room, speaking [`vox_agentcomms::drive::LABEL`], one request line and one
//! answer line.

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use vox_agentcomms::drive::{Answer, Request, LABEL, PATIENCE};

use crate::hash::Digest32;
use crate::node::ipc::NodeSocket;

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
