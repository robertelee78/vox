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
//! - **Codex** — **not woken, by decision** (V210-169). Its app-server can start a turn on a
//!   thread it holds, but it keeps a session's thread loaded for a while after the user quits,
//!   so a wake sent there would start a model turn in a session nobody is in. Vox never starts
//!   a model run. A Codex session is registered so that the poster of an urgent message to it
//!   is told, in one line, that it cannot be interrupted and reads the message at its next
//!   turn ([`uninterruptible`]).

use std::path::Path;

use vox_agentcomms::envelope::{Envelope, DEFAULT_HOPS};
use vox_core::hash::Digest32;
use vox_core::node::api::MessageRow;
use vox_core::node::paths::Paths;

/// How one agent session can be woken.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// The harness's own session id — the cursor key, and the wake key.
    pub session: String,
    /// `claude`, `opencode` or `codex`.
    pub harness: String,
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
///
/// A session is woken for an urgent message addressed to its node, in any room: it hears every
/// room its node holds (V210-161, V210-163).
///
/// `codex` says the hook's input is Codex's ([`codex_input`]). It is checked first: a Codex
/// started from a Claude Code terminal inherits that terminal's messaging socket, and a Codex
/// session registered by it would have its wakes sent to the Claude session. Vox never wakes a
/// Codex session (V210-169); it is registered with no endpoint, so the poster is told so.
pub fn register(paths: &Paths, session: &str, codex: bool) {
    let reg = if codex {
        Session {
            session: session.to_owned(),
            harness: "codex".into(),
            endpoint: String::new(),
            token: String::new(),
        }
    } else if let (Ok(endpoint), Ok(token)) = (
        std::env::var("CLAUDE_CODE_MESSAGING_SOCKET"),
        std::env::var("CLAUDE_CODE_MESSAGING_TOKEN"),
    ) {
        Session {
            session: session.to_owned(),
            harness: "claude".into(),
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
            endpoint,
            token,
        }
    } else {
        Session {
            session: session.to_owned(),
            harness: std::env::var("VOX_HARNESS").unwrap_or_else(|_| "unknown".into()),
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

/// Whether a hook's input is Codex's: it names a Codex rollout (`rollout-*.jsonl`) as the
/// transcript, or carries Codex's `turn_id`. Read from the input, not the environment, which a
/// Codex started from another harness's terminal inherits.
#[must_use]
pub fn codex_input(transcript_path: &str, has_turn_id: bool) -> bool {
    has_turn_id
        || Path::new(transcript_path)
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.starts_with("rollout-") && f.ends_with(".jsonl"))
}

/// What the poster of an urgent message is told (V210-169), when it addresses this node and no
/// session of this node can be interrupted: one line, or `None`.
///
/// `to` holds the addressees' whole fingerprints, as the envelope carries them, and `me` is this
/// node's. The daemon wakes every session of an addressed node that left Vox a way to reach it;
/// a Codex session never leaves one, because Vox never interrupts it. This says nothing of other
/// nodes: a session there is woken, or not, by its own node.
#[must_use]
pub fn uninterruptible(paths: &Paths, me: &str, to: &[String]) -> Option<String> {
    if !to.iter().any(|fp| fp == me) {
        return None;
    }
    let reachable = registered(paths)
        .iter()
        .any(|s| s.harness != "codex" && !s.endpoint.is_empty());
    if reachable {
        return None;
    }
    Some(
        "no session of this node can be interrupted: Vox never interrupts a Codex session, and \
         no other session here left Vox a way to reach it. Each reads the message at its next \
         turn."
            .to_owned(),
    )
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
    let removed = still && std::fs::remove_file(&path).is_ok();
    if removed {
        let _ = std::fs::remove_file(woke_file(paths, &session.session));
    }
    removed
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

/// Where the daemon records the entries that woke `session`: a file of the same name as its
/// registration in a directory of its own beside the registrations', so the registrations'
/// directory still holds one file per session.
fn woke_file(paths: &Paths, session: &str) -> std::path::PathBuf {
    let reg = paths.session_file(session);
    let dir = paths.session_dir().with_extension("wakes");
    dir.join(reg.file_name().unwrap_or_default())
}

/// Record that entry `entry` of `room` woke `session` (V210-121), so that the session's
/// next post with no `--re` answers it rather than starting a chain of its own.
///
/// Best effort, as registration is: a wake that cannot be recorded still happened. The
/// record keeps the latest `WOKE_KEPT` wakes, private to the profile like the registration.
pub fn note_woke(paths: &Paths, session: &str, room: &str, entry: &Digest32) {
    let path = woke_file(paths, session);
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<&str> = old.lines().collect();
    let new = format!("{room} {}", vox_core::node::link::b32_encode(entry));
    lines.push(&new);
    let keep = &lines[lines.len().saturating_sub(WOKE_KEPT)..];
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = vox_core::node::paths::write_private_file(&path, (keep.join("\n") + "\n").as_bytes());
}

/// The entries of `room` recorded as having woken `session` (V210-121), oldest first.
#[must_use]
pub fn recorded_wakes(paths: &Paths, session: &str, room: &str) -> Vec<String> {
    let Ok(body) = std::fs::read_to_string(woke_file(paths, session)) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(r, _)| *r == room)
        .map(|(_, e)| e.to_owned())
        .collect()
}

/// How many wakes a session's record keeps: far more than a session leaves unanswered.
const WOKE_KEPT: usize = 64;

/// The entries of `room` that woke `session` and that it has not answered yet, oldest first
/// (V210-121): every recorded wake that `rows` still holds, less those a post of this
/// session's — signed by this node, `me`, and naming the session in `from` — replies to.
#[must_use]
pub fn open_wakes(
    paths: &Paths,
    session: &str,
    room: &str,
    rows: &[MessageRow],
    me: &Digest32,
) -> Vec<String> {
    let Ok(body) = std::fs::read_to_string(woke_file(paths, session)) else {
        return Vec::new();
    };
    let answered: std::collections::BTreeSet<String> = rows
        .iter()
        .filter(|r| r.author == *me)
        .filter_map(|r| Envelope::parse(&r.text).ok())
        .filter(|e| e.from == session)
        .filter_map(|e| e.re.map(|re| re.trim().to_ascii_lowercase()))
        .collect();
    let mut open: Vec<String> = Vec::new();
    for line in body.lines() {
        let Some((r, entry)) = line.split_once(' ') else {
            continue;
        };
        if r != room || answered.contains(entry) || open.iter().any(|o| o == entry) {
            continue;
        }
        if find(rows, entry).is_some() {
            open.push(entry.to_owned());
        }
    }
    open
}

/// Whether `session`, a session of this node (`me`), already spoke in the `re` chain
/// `envelope` answers (V210-121): a parent, grandparent and so on, signed by `me` and
/// naming `session` in `from`. Waking it again would answer it with its own conversation,
/// which is how two agents keep each other awake; the message still queues for its next turn.
#[must_use]
pub fn in_chain<'a, R>(envelope: &Envelope, rows: &'a R, me: &Digest32, session: &str) -> bool
where
    R: ?Sized,
    &'a R: IntoIterator<Item = &'a MessageRow>,
{
    let mut re = envelope.re.clone();
    let mut depth: u32 = 0;
    while let Some(parent) = re.as_deref().and_then(|h| find(rows, h)) {
        depth += 1;
        if depth > DEFAULT_HOPS {
            break;
        }
        let Ok(p) = Envelope::parse(&parent.text) else {
            break;
        };
        if parent.author == *me && p.from == session {
            return true;
        }
        re = p.re;
    }
    false
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

/// Wake one session with `text`, which carries the room entry `entry` (its full base32 hash).
///
/// # Errors
/// If the harness has no implemented wake path, or delivery fails.
pub async fn wake(session: &Session, entry: &str, text: &str) -> Result<(), WakeError> {
    match session.harness.as_str() {
        "claude" => wake_claude(Path::new(&session.endpoint), &session.token, text).await,
        "opencode" => {
            wake_opencode(
                Path::new(&session.endpoint),
                &session.token,
                &session.session,
                entry,
                text,
            )
            .await
        }
        // Never woken (V210-169): Codex keeps a quit session's thread loaded, so a turn started
        // there could run with nobody in the session.
        "codex" => Err(WakeError::Failed(
            "Vox does not interrupt Codex sessions; the message waits for the session's next turn"
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
///
/// The frame names the `entry` it carries, so the plugin can tell the session's drain that
/// this message was delivered already, and the drain does not give it to the model a second
/// time (V210-112).
async fn wake_opencode(
    socket: &Path,
    token: &str,
    session: &str,
    entry: &str,
    text: &str,
) -> Result<(), WakeError> {
    use tokio::io::AsyncBufReadExt as _;
    let mut stream = connect(socket).await?;
    let auth = serde_json::json!({ "type": "auth", "token": token });
    let prompt = serde_json::json!({
        "type": "prompt",
        "session": session,
        "entry": entry,
        "text": text,
    });
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
