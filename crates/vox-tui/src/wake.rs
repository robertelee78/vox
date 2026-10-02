//! ADR-020 §6, second half — **interrupting** an agent session that is already
//! running, rather than waiting for its next turn.
//!
//! The queue half is the drain hook: every turn, an agent reads what it has not
//! seen. That is enough for work that can wait, and it is deliberately the default,
//! because an interrupt that fires on everything is a queue with worse manners.
//! What it cannot do is reach an agent *mid-turn*, or start a turn for an agent
//! sitting idle — which is exactly what an **addressed, urgent** message needs.
//!
//! ## How a session becomes reachable
//!
//! Not by configuration. The drain hook already runs every turn and already knows
//! the session id, so it **records what it finds in its own environment** — which
//! harness it is inside, and how that harness can be woken. "Which harness is this
//! and how do I reach it" becomes something the system observes rather than
//! something an operator maintains, and a stale registration is self-correcting
//! because the next turn rewrites it.
//!
//! ## What each harness needs, measured rather than assumed
//!
//! - **Claude Code** — a Unix socket named by `CLAUDE_CODE_MESSAGING_SOCKET`, with
//!   `CLAUDE_CODE_MESSAGING_TOKEN`. The wire is NDJSON: an `auth` frame, then a
//!   `user` message. The binary documents this form itself, and it is **verified
//!   here** — a message written this way arrived in a live session. Delivered
//!   between tool calls, and it starts a new turn when the session is idle, which
//!   is the property that makes it an interrupt rather than a queue.
//! - **OpenCode** — a plain `opencode` has **no listener** an outside process could
//!   find: the server URL its plugins are handed is a placeholder unless it was started
//!   with `--port`, and it sets no variable naming one (ADR-021 F17, measured against
//!   1.18.32). So Vox's plugin owns the channel: a Unix socket in a private directory,
//!   with a token, whose path and token it puts in the drain hook's environment
//!   (`VOX_OPENCODE_WAKE_SOCKET`, `_TOKEN`). The wire is Claude Code's shape — an
//!   `auth` frame, then a `prompt` frame naming the session — and the plugin relays it
//!   with its in-process client's `promptAsync`, which starts a turn when the session is
//!   idle and is taken at the next step boundary mid-turn. It answers one line, so a
//!   session OpenCode no longer knows is told apart from one that took the prompt.
//! - **Codex** — reachable in principle through its app-server: `turn/start` when the
//!   thread is idle, `turn/steer` with `expectedTurnId` when a turn is running (a
//!   mid-turn `turn/start` is folded into that turn — ADR-020 M19.12). But
//!   this build has no verified path to that socket from a hook's environment, so
//!   it is **named and not implemented**. A registration for it is written and
//!   waking it reports plainly that it cannot, rather than failing silently or
//!   pretending.

use std::path::Path;

use vox_agentcomms::envelope::{Envelope, DEFAULT_HOPS};
use vox_core::node::api::MessageRow;
use vox_core::node::paths::Paths;

/// How one agent session can be woken.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// The harness's own session id — the cursor key, and the wake key.
    pub session: String,
    /// `claude`, `opencode` or `codex`.
    pub harness: String,
    /// The room this session is attached to.
    pub room: String,
    /// The petname this session answers to, when it has one.
    #[serde(default)]
    pub name: String,
    /// Claude Code's messaging socket, or the Vox OpenCode plugin's wake socket.
    #[serde(default)]
    pub endpoint: String,
    /// The token that socket wants.
    #[serde(default)]
    pub token: String,
}

/// Record how this session can be woken, from what the harness put in the
/// environment.
///
/// Best effort on purpose: a session that cannot be woken should still be able to
/// read its room, so every failure here is silent and leaves the drain working.
pub fn register(paths: &Paths, session: &str, room: &str) {
    let name = std::env::var("VOX_AGENT_NAME").unwrap_or_default();
    let reg = if let (Ok(endpoint), Ok(token)) = (
        std::env::var("CLAUDE_CODE_MESSAGING_SOCKET"),
        std::env::var("CLAUDE_CODE_MESSAGING_TOKEN"),
    ) {
        Session {
            session: session.to_owned(),
            harness: "claude".into(),
            room: room.to_owned(),
            name,
            endpoint,
            token,
        }
    } else if let (Ok(endpoint), Ok(token)) = (
        std::env::var("VOX_OPENCODE_WAKE_SOCKET"),
        std::env::var("VOX_OPENCODE_WAKE_TOKEN"),
    ) {
        Session {
            session: session.to_owned(),
            harness: "opencode".into(),
            room: room.to_owned(),
            name,
            endpoint,
            token,
        }
    } else {
        Session {
            session: session.to_owned(),
            harness: std::env::var("VOX_HARNESS").unwrap_or_else(|_| "unknown".into()),
            room: room.to_owned(),
            name,
            endpoint: String::new(),
            token: String::new(),
        }
    };
    let dir = paths.session_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(body) = serde_json::to_vec(&reg) {
        let _ = vox_core::node::paths::write_private_file(&paths.session_file(session), &body);
    }
}

/// Every session that has registered a wake channel.
#[must_use]
pub fn registered(paths: &Paths) -> Vec<Session> {
    let Ok(entries) = std::fs::read_dir(paths.session_dir()) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| {
            let path = e.ok()?.path();
            let body = std::fs::read(&path).ok()?;
            serde_json::from_slice::<Session>(&body).ok()
        })
        .collect()
}

/// Drop `session`'s registration, **if it is still the one that failed**.
///
/// A registration is rewritten every turn, but nothing ever removed one: a session that
/// ended left its file behind for good, and every urgent message for its name was tried
/// against it again (V210-79). The daemon calls this once a wake finds the session is
/// gone — its socket or server no longer exists, or the server no longer knows the
/// session. A registration rewritten since (the session resumed elsewhere) is kept.
///
/// Returns whether it was removed.
pub fn forget(paths: &Paths, session: &Session) -> bool {
    let path = paths.session_file(&session.session);
    let still = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Session>(&b).ok())
        .is_some_and(|now| now == *session);
    still && std::fs::remove_file(&path).is_ok()
}

/// The hop budget `envelope` really has left, given the `rows` of its room (ADR-020 §9).
///
/// Its own `hops`, but never more than any message it replies to allows: a parent with
/// `h` hops leaves its reply `h - 1`, a grandparent `h - 2`, and so on up the `re` chain.
/// The chain is read from the log, so a sender that writes a fresh budget into a reply
/// does not reset it; and a chain longer than [`DEFAULT_HOPS`] has none left whatever
/// its members claim. A parent this room does not hold ends the walk.
#[must_use]
pub fn hops_left<'a, R>(envelope: &Envelope, rows: &'a R) -> u32
where
    R: ?Sized,
    &'a R: IntoIterator<Item = &'a MessageRow>,
{
    let mut left = envelope.hops;
    let mut re = envelope.re.clone();
    let mut depth: u32 = 0;
    while let Some(parent) = re.as_deref().and_then(|h| find(rows, h)) {
        depth += 1;
        if depth > DEFAULT_HOPS {
            return 0;
        }
        let Ok(p) = Envelope::parse(&parent.text) else {
            break;
        };
        left = left.min(p.hops.saturating_sub(depth));
        re = p.re;
    }
    left
}

/// The budget a reply to entry `re` starts with: its parent's less one (see [`hops_left`]),
/// or the default when the room does not hold that entry.
#[must_use]
pub fn reply_hops<'a, R>(re: &str, rows: &'a R) -> u32
where
    R: ?Sized,
    &'a R: IntoIterator<Item = &'a MessageRow>,
{
    let mut reply = Envelope::new(vox_agentcomms::envelope::SAY, "");
    reply.re = Some(re.to_owned());
    hops_left(&reply, rows)
}

fn find<'a, R>(rows: &'a R, re: &str) -> Option<&'a MessageRow>
where
    R: ?Sized,
    &'a R: IntoIterator<Item = &'a MessageRow>,
{
    let hash = vox_core::node::link::b32_decode(re.trim(), "re").ok()?;
    rows.into_iter().find(|r| r.entry_hash == hash)
}

/// Why a wake did not arrive.
#[derive(Debug)]
pub enum WakeError {
    /// The session is gone: nothing listens at its endpoint any more, or its server no
    /// longer knows it. Its registration can be forgotten.
    Gone(String),
    /// Anything else — including a harness with no wake path. The registration stays.
    Failed(String),
}

impl std::fmt::Display for WakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WakeError::Gone(e) | WakeError::Failed(e) => f.write_str(e),
        }
    }
}

/// Wake one session with `text`.
///
/// # Errors
/// If the harness has no implemented wake path, or delivery fails.
pub async fn wake(session: &Session, text: &str) -> Result<(), WakeError> {
    match session.harness.as_str() {
        "claude" => wake_claude(Path::new(&session.endpoint), &session.token, text).await,
        "opencode" => {
            wake_opencode(
                Path::new(&session.endpoint),
                &session.token,
                &session.session,
                text,
            )
            .await
        }
        "codex" => Err(WakeError::Failed(
            "codex sessions cannot be interrupted by this build; the message waits for the \
             session's next turn"
                .into(),
        )),
        other => Err(WakeError::Failed(format!(
            "no wake path for harness {other:?}"
        ))),
    }
}

/// Connect to a session's socket; a socket that is gone or refuses means the session ended.
async fn connect(socket: &Path) -> Result<tokio::net::UnixStream, WakeError> {
    tokio::net::UnixStream::connect(socket).await.map_err(|e| {
        let why = format!("connecting to the session socket: {e}");
        // No socket file, or nobody listening on it: the session has ended.
        match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                WakeError::Gone(why)
            }
            _ => WakeError::Failed(why),
        }
    })
}

/// Write `frames` (each one NDJSON line) and flush.
async fn send(
    stream: &mut tokio::net::UnixStream,
    frames: &[serde_json::Value],
) -> Result<(), WakeError> {
    use tokio::io::AsyncWriteExt as _;
    let payload: String = frames.iter().map(|f| format!("{f}\n")).collect();
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| WakeError::Failed(format!("writing to the session socket: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| WakeError::Failed(format!("flushing the session socket: {e}")))
}

/// NDJSON over Claude Code's messaging socket: an `auth` frame, then a user
/// message. Verified against a live session.
async fn wake_claude(socket: &Path, token: &str, text: &str) -> Result<(), WakeError> {
    let mut stream = connect(socket).await?;
    let auth = serde_json::json!({ "type": "auth", "token": token });
    let message = serde_json::json!({
        "type": "user",
        "message": { "role": "user", "content": text },
    });
    send(&mut stream, &[auth, message]).await
}

/// The Vox OpenCode plugin's wake socket: an `auth` frame, then a `prompt` frame for
/// `session`, answered with one line saying whether OpenCode took it.
async fn wake_opencode(
    socket: &Path,
    token: &str,
    session: &str,
    text: &str,
) -> Result<(), WakeError> {
    use tokio::io::AsyncBufReadExt as _;
    let mut stream = connect(socket).await?;
    let auth = serde_json::json!({ "type": "auth", "token": token });
    let prompt = serde_json::json!({ "type": "prompt", "session": session, "text": text });
    send(&mut stream, &[auth, prompt]).await?;
    let mut line = String::new();
    tokio::io::BufReader::new(stream)
        .read_line(&mut line)
        .await
        .map_err(|e| WakeError::Failed(format!("reading the plugin's answer: {e}")))?;
    let reply: serde_json::Value = serde_json::from_str(line.trim())
        .map_err(|_| WakeError::Failed(format!("the plugin answered {line:?}")))?;
    if reply["ok"] == true {
        return Ok(());
    }
    let why = format!(
        "the OpenCode plugin answered: {}",
        reply["error"].as_str().unwrap_or("nothing")
    );
    // OpenCode is up and does not know this session.
    if reply["gone"] == true {
        Err(WakeError::Gone(why))
    } else {
        Err(WakeError::Failed(why))
    }
}
