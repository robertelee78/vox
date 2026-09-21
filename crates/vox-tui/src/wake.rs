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
//! - **OpenCode** — `POST /session/:id/prompt_async` against the server URL the
//!   plugin is handed on startup. The plugin records it, because a bare `opencode`
//!   has no listener an outside process could find.
//! - **Codex** — reachable in principle through its app-server's `turn/start`, but
//!   this build has no verified path to that socket from a hook's environment, so
//!   it is **named and not implemented**. A registration for it is written and
//!   waking it reports plainly that it cannot, rather than failing silently or
//!   pretending.

use std::path::Path;

use vox_core::node::paths::Paths;

/// How one agent session can be woken.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// Claude Code's messaging socket, or OpenCode's server URL.
    #[serde(default)]
    pub endpoint: String,
    /// Claude Code's messaging token.
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
    } else if let Ok(endpoint) = std::env::var("OPENCODE_SERVER_URL") {
        Session {
            session: session.to_owned(),
            harness: "opencode".into(),
            room: room.to_owned(),
            name,
            endpoint,
            token: String::new(),
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

/// Wake one session with `text`.
///
/// # Errors
/// If the harness has no implemented wake path, or delivery fails.
pub async fn wake(session: &Session, text: &str) -> Result<(), String> {
    match session.harness.as_str() {
        "claude" => wake_claude(Path::new(&session.endpoint), &session.token, text).await,
        "opencode" => wake_opencode(&session.endpoint, &session.session, text).await,
        "codex" => Err(
            "codex sessions cannot be interrupted by this build; the message waits for the \
             session's next turn"
                .into(),
        ),
        other => Err(format!("no wake path for harness {other:?}")),
    }
}

/// NDJSON over Claude Code's messaging socket: an `auth` frame, then a user
/// message. Verified against a live session.
async fn wake_claude(socket: &Path, token: &str, text: &str) -> Result<(), String> {
    use tokio::io::AsyncWriteExt as _;
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connecting to the session socket: {e}"))?;
    let auth = serde_json::json!({ "type": "auth", "token": token });
    let message = serde_json::json!({
        "type": "user",
        "message": { "role": "user", "content": text },
    });
    let payload = format!("{auth}\n{message}\n");
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("writing to the session socket: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flushing the session socket: {e}"))?;
    Ok(())
}

/// OpenCode's `prompt_async`, which works mid-turn.
async fn wake_opencode(base: &str, session: &str, text: &str) -> Result<(), String> {
    let url = format!(
        "{}/session/{session}/prompt_async",
        base.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "parts": [{ "type": "text", "text": text }],
    });
    // The body is set directly rather than through reqwest's `json` helper, which
    // would need a feature this workspace does not enable. One CLI verb is not a
    // reason to widen a dependency.
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("posting to {url}: {e}"))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("{url} answered {}", response.status()))
    }
}
