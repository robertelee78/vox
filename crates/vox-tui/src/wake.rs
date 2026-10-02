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
//!
//! ## What a wake says, and when (V030-15, V030-20)
//!
//! A wake is a **notice**: how many urgent messages and replies wait, from whom, in which room,
//! and never a byte of any of them (`agent_hook::render_wake`). The messages arrive once, in the
//! drain of the turn the notice starts. The daemon counts what is owed just before it sends
//! ([`unread`], [`tend`]), keeps at most one notice outstanding, and announces an unread reply to
//! an idle session on a schedule ([`Settings`]). What it owes each session is kept in
//! [`Notices`], beside the registration, so a restart resumes it.

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
    /// What the harness last said about this session's turn (V030-20): [`BUSY`] when one began
    /// (its drain ran), [`IDLE`] when one ended (Claude Code's `Stop`).
    #[serde(default)]
    pub state: String,
    /// When the harness last said so, in Unix milliseconds.
    #[serde(default)]
    pub state_ms: u64,
}

/// A session whose turn is running: its drain ran and no end of turn has been heard since.
pub const BUSY: &str = "busy";
/// A session whose turn ended (Claude Code's `Stop`), waiting for its next prompt.
pub const IDLE: &str = "idle";

impl Session {
    /// Whether this session is waiting for a prompt at `now` (V030-20): the harness said its turn
    /// ended, or it has said nothing for `busy_idle`. The second covers what no hook reports: a
    /// Claude Code turn interrupted with Esc runs no `Stop`, and OpenCode and Codex report no end
    /// of turn to Vox at all.
    #[must_use]
    pub fn idle(&self, now: u64, busy_idle: std::time::Duration) -> bool {
        self.state == IDLE
            || now.saturating_sub(self.state_ms)
                >= u64::try_from(busy_idle.as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether `other` is this same registration: the same session at the same endpoint. What the
    /// harness says about its turns does not make it another one.
    fn same(&self, other: &Session) -> bool {
        self.session == other.session
            && self.harness == other.harness
            && self.endpoint == other.endpoint
            && self.token == other.token
    }
}

/// Now, in Unix milliseconds.
#[must_use]
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Record how this session can be woken, from what the harness put in the
/// environment, and that its turn is running: the drain runs at the start of one.
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
            state: BUSY.into(),
            state_ms: now_millis(),
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
            state: BUSY.into(),
            state_ms: now_millis(),
        }
    } else {
        Session {
            session: session.to_owned(),
            harness: std::env::var("VOX_HARNESS").unwrap_or_else(|_| "unknown".into()),
            room: room.to_owned(),
            name,
            endpoint: String::new(),
            token: String::new(),
            state: BUSY.into(),
            state_ms: now_millis(),
        }
    };
    let dir = paths.session_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(body) = serde_json::to_vec(&reg) {
        let _ =
            vox_core::node::paths::write_private_file_unique(&paths.session_file(session), &body);
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
    let still = load(paths, &session.session).is_some_and(|now| now.same(session));
    let gone = still && std::fs::remove_file(&path).is_ok();
    if gone {
        let _ = std::fs::remove_file(notices_file(paths, &session.session));
    }
    gone
}

/// `session`'s registration, if it has one.
fn load(paths: &Paths, session: &str) -> Option<Session> {
    let body = std::fs::read(paths.session_file(session)).ok()?;
    serde_json::from_slice(&body).ok()
}

/// Record that `session`'s turn ended (Claude Code's `Stop`, V030-20): it is idle now, so a reply
/// to it can be announced. A session with no registration has nothing to record.
pub fn record_idle(paths: &Paths, session: &str) {
    let Some(mut reg) = load(paths, session) else {
        return;
    };
    reg.state = IDLE.into();
    reg.state_ms = now_millis();
    if let Ok(body) = serde_json::to_vec(&reg) {
        let _ =
            vox_core::node::paths::write_private_file_unique(&paths.session_file(session), &body);
    }
}

/// Remove `session`'s registration and its notice record (Claude Code's `SessionEnd`, V030-20):
/// a session that has ended is never woken again. Its cursor stays, for a session resumed later.
pub fn end(paths: &Paths, session: &str) {
    let _ = std::fs::remove_file(paths.session_file(session));
    let _ = std::fs::remove_file(notices_file(paths, session));
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

/// Wake one session with `text`: a notice that names counts and senders, never a message
/// (V030-15).
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
    let prompt = serde_json::json!({
        "type": "prompt",
        "session": session,
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

/// Whether `harness` has a wake path at all. Codex has none (see the module header), so nothing is
/// owed to a Codex session in notices: it reads at its next turn.
#[must_use]
pub fn wakeable(harness: &str) -> bool {
    matches!(harness, "claude" | "opencode")
}

/// The kinds that are never a reply worth announcing (V030-20): acknowledgements, progress,
/// presence and its probes. They are still read at the next turn.
pub const NOT_REPLIES: [&str; 6] = ["ack", "status", "hello", "bye", "ping", "pong"];

/// The entries `session` of the node `me` posted to someone: what a reply can answer (V030-20).
/// A broadcast asked nobody in particular, so an answer to it is not owed to this session.
pub fn asked<'a>(
    rows: impl IntoIterator<Item = &'a MessageRow>,
    me: Option<vox_core::hash::Digest32>,
    session: &str,
) -> std::collections::HashSet<vox_core::hash::Digest32> {
    rows.into_iter()
        .filter(|r| me == Some(r.author))
        .filter(|r| {
            Envelope::parse(&r.text)
                .is_ok_and(|e| e.from == session && !e.from.is_empty() && !e.to.is_empty())
        })
        .map(|r| r.entry_hash)
        .collect()
}

/// Whether `envelope` answers one of the posts in `asked` (V030-20): its `re` names one, and it is
/// not one of [`NOT_REPLIES`]. The caller has already set this session's own rows aside.
#[must_use]
pub fn is_reply(
    envelope: &Envelope,
    asked: &std::collections::HashSet<vox_core::hash::Digest32>,
) -> bool {
    !NOT_REPLIES.contains(&envelope.kind.as_str())
        && envelope
            .re
            .as_deref()
            .and_then(|re| vox_core::node::link::b32_decode(re.trim(), "re").ok())
            .is_some_and(|h| asked.contains(&h))
}

/// What `session` has not been given yet that it is owed a notice for: the urgent messages
/// addressed to it that may still interrupt (hops left, ADR-020 §9), and the replies to its posts
/// (V030-20), each oldest first.
///
/// "Not given yet" is the drain's own rule: past the session's `cursor` by arrival (a cursor the
/// room no longer holds starts from the first message, as the drain does), not the session's own,
/// not a message not received yet, and not one its drain already showed ahead of the cursor.
pub fn unread<'a>(
    timeline: &'a vox_core::node::api::Timeline,
    me: Option<vox_core::hash::Digest32>,
    session: &Session,
    cursor: Option<vox_core::hash::Digest32>,
    ahead: &std::collections::BTreeSet<vox_core::hash::Digest32>,
) -> (Vec<&'a MessageRow>, Vec<&'a MessageRow>) {
    let mark = cursor.and_then(|c| {
        timeline
            .iter()
            .rev()
            .find(|r| r.entry_hash == c && !r.owed)
            .map(|r| r.arrival)
    });
    let asked = asked(timeline.iter(), me, &session.session);
    let mut rows: Vec<&MessageRow> = timeline
        .iter()
        .filter(|r| !r.owed && mark.is_none_or(|m| r.arrival > m))
        .filter(|r| !ahead.contains(&r.entry_hash))
        .collect();
    rows.sort_by_key(|r| r.arrival);
    let (mut urgent, mut replies) = (Vec::new(), Vec::new());
    for r in rows {
        let Ok(e) = Envelope::parse(&r.text) else {
            continue;
        };
        if me == Some(r.author) && !e.from.is_empty() && e.from == session.session {
            continue;
        }
        if !session.name.is_empty() && e.may_interrupt(&session.name) && hops_left(&e, timeline) > 0
        {
            urgent.push(r);
        } else if is_reply(&e, &asked) && hops_left(&e, timeline) > 0 {
            // **A reply with no hops left is announced to nobody** (ADR-020 §9): two sessions
            // answering each other's answers would otherwise wake each other for ever. It is
            // still read at the next turn.
            replies.push(r);
        }
    }
    (urgent, replies)
}

/// The timings of a session's notices, from the profile's settings file (`vox daemon` reads it
/// on every tick, so a change takes effect without a restart):
///
/// ```text
/// agent_wake_hold = 10m          # a notice is outstanding until the cursor moves, or this passes
/// agent_busy_idle = 10m          # a busy session silent this long counts as idle
/// agent_reply_nudges = 5m 20m 60m  # an unread reply is announced again after each of these
/// ```
///
/// A duration is a number of seconds, or a number with `s`, `m` or `h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// How long a notice stays outstanding while the session's cursor does not move.
    pub wake_hold: std::time::Duration,
    /// How long a session the harness last called busy may stay silent before it counts as idle.
    pub busy_idle: std::time::Duration,
    /// After the first notice of an unread reply, the waits before each further one.
    pub reply_nudges: Vec<std::time::Duration>,
}

impl Default for Settings {
    fn default() -> Self {
        let min = |m: u64| std::time::Duration::from_secs(60 * m);
        Settings {
            wake_hold: min(10),
            busy_idle: min(10),
            reply_nudges: vec![min(5), min(20), min(60)],
        }
    }
}

impl Settings {
    /// This profile's settings, and a line for each one that could not be read (which keeps its
    /// default).
    #[must_use]
    pub fn load(paths: &Paths) -> (Self, Vec<String>) {
        let mut s = Settings::default();
        let mut problems = Vec::new();
        let Ok(text) = std::fs::read_to_string(paths.config_file()) else {
            return (s, problems);
        };
        for (k, v) in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim(), v.split('#').next().unwrap_or("").trim()))
        {
            // Zero is refused everywhere: a hold or a wait of nothing would send a notice on
            // every tick, and a busy session idle at once would be told mid-turn.
            let one = |v: &str| match duration(v) {
                Some(d) if !d.is_zero() => Ok(d),
                Some(_) => Err(format!("{k} = {v}: must be more than zero")),
                None => Err(format!("{k} = {v}: not a duration (e.g. 90s, 10m, 1h)")),
            };
            let read = match k {
                "agent_wake_hold" => one(v).map(|d| s.wake_hold = d),
                "agent_busy_idle" => one(v).map(|d| s.busy_idle = d),
                "agent_reply_nudges" => v
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|w| !w.is_empty())
                    .map(one)
                    .collect::<Result<Vec<_>, _>>()
                    .and_then(|d| {
                        if d.is_empty() {
                            Err(format!("{k} = : names no waits (e.g. 5m 20m 60m)"))
                        } else {
                            s.reply_nudges = d;
                            Ok(())
                        }
                    }),
                _ => Ok(()),
            };
            if let Err(e) = read {
                problems.push(e);
            }
        }
        (s, problems)
    }
}

/// `90`, `90s`, `10m` or `1h`.
fn duration(v: &str) -> Option<std::time::Duration> {
    let (n, unit) = match v.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => v.split_at(i),
        None => (v, "s"),
    };
    let n: u64 = n.parse().ok()?;
    let secs = match unit.trim() {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    Some(std::time::Duration::from_secs(secs))
}

/// What the daemon owes one session in notices (V030-15, V030-20), kept beside its registration so
/// that a daemon restart resumes where it was.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Notices {
    /// An urgent message addressed to this session landed and has not been announced yet.
    #[serde(default)]
    pub urgent_due: bool,
    /// When the last notice was sent, in Unix milliseconds.
    #[serde(default)]
    pub sent_at: Option<u64>,
    /// The session's cursor when it was sent. The notice is outstanding until this moves or
    /// [`Settings::wake_hold`] passes.
    #[serde(default)]
    pub sent_cursor: Option<String>,
    /// The newest unread reply the series is about; a fresher one starts the series again.
    #[serde(default)]
    pub reply: Option<String>,
    /// How many notices of the series were sent.
    #[serde(default)]
    pub reply_sent: u32,
    /// When the last of them was, in Unix milliseconds.
    #[serde(default)]
    pub reply_at: u64,
    /// A notice that could not be delivered is tried again at this time (Unix milliseconds), or
    /// once the session's cursor moves: what it announced stays owed (see [`undelivered`]).
    #[serde(default)]
    pub retry_at: Option<u64>,
}

impl Notices {
    /// Whether the daemon has anything to look at for this session on its tick: an urgent notice
    /// owed, a notice to retry, or a reply series still running. A series that has sent its last
    /// notice is not looked at again until a fresh answer lands in the room.
    #[must_use]
    pub fn active(&self, s: &Settings) -> bool {
        self.urgent_due
            || self.retry_at.is_some()
            || (self.reply.is_some() && self.reply_sent as usize <= s.reply_nudges.len())
    }
}

/// A notice that `tend` sent (`before` → `after`) did not arrive: put back what it announced, so
/// it stays owed, and try again once `hold` has passed or the session's cursor moves. Nothing is
/// dropped; the hold bounds how often an endpoint that keeps failing is tried.
pub fn undelivered(paths: &Paths, session: &str, before: &Notices, after: &Notices, hold_ms: u64) {
    let mut now = notices(paths, session);
    if now == *after {
        now = before.clone();
        now.sent_at = after.sent_at;
        now.sent_cursor = after.sent_cursor.clone();
    } else {
        now.urgent_due |= before.urgent_due;
    }
    now.retry_at = Some(now_millis().saturating_add(hold_ms));
    let _ = save_notices(paths, session, &now);
}

/// The directory, under the sessions, holding what the daemon owes each one in notices.
const NOTICES_DIR: &str = "notices";

fn notices_file(paths: &Paths, session: &str) -> std::path::PathBuf {
    let reg = paths.session_file(session);
    let name = reg.file_name().map(std::ffi::OsStr::to_owned);
    paths
        .session_dir()
        .join(NOTICES_DIR)
        .join(name.unwrap_or_else(|| NOTICES_DIR.into()))
}

/// What the daemon owes `session` in notices; nothing when it has no record.
#[must_use]
pub fn notices(paths: &Paths, session: &str) -> Notices {
    std::fs::read(notices_file(paths, session))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Record what the daemon owes `session` in notices.
///
/// # Errors
/// If the record cannot be written.
pub fn save_notices(paths: &Paths, session: &str, n: &Notices) -> std::io::Result<()> {
    std::fs::create_dir_all(paths.session_dir().join(NOTICES_DIR))?;
    let body = serde_json::to_vec(n).map_err(std::io::Error::other)?;
    vox_core::node::paths::write_private_file_unique(&notices_file(paths, session), &body)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// What [`tend`] decided for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tended {
    /// Nothing is owed now.
    Quiet,
    /// An urgent message was due a notice, and the session read it first: nothing is sent.
    AlreadyRead,
    /// An urgent message is due a notice while an earlier one is still outstanding.
    Held,
    /// Send a notice now.
    Send,
}

/// Whether to send `session` a notice now, given what it has not read (V030-15, V030-20), and
/// what that changes in `n`.
///
/// - **An urgent message** gets a notice at once, whatever the session is doing, unless a notice
///   is outstanding: one was sent, the session's cursor has not moved since, and
///   [`Settings::wake_hold`] has not passed. That dedupes, it drops nothing: the message stays
///   due, the session's next read carries it, and once the cursor moves or the hold passes it is
///   counted again. Counted **now**: one read first is not announced at all.
/// - **A reply** gets a notice only while the session is idle and no notice is outstanding: one,
///   then one after each wait in [`Settings::reply_nudges`], then no more. A fresher reply starts
///   the series again; its first notice too waits for the cursor to move or the hold to pass.
///   Read, the series ends. So a session has at most one wake outstanding, of either kind.
pub fn tend(
    n: &mut Notices,
    cursor: Option<String>,
    urgent: usize,
    newest_reply: Option<String>,
    idle: bool,
    now: u64,
    s: &Settings,
) -> Tended {
    let ms = |d: std::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let outstanding = n.sent_cursor == cursor
        && n.sent_at
            .is_some_and(|t| now.saturating_sub(t) < ms(s.wake_hold));
    // A notice that did not arrive waits for its retry time, or for the cursor to move.
    if n.retry_at.is_some_and(|t| now < t) && n.sent_cursor == cursor {
        return if n.urgent_due {
            Tended::Held
        } else {
            Tended::Quiet
        };
    }
    n.retry_at = None;
    if newest_reply != n.reply {
        n.reply = newest_reply;
        n.reply_sent = 0;
        n.reply_at = 0;
    }
    let mut already = false;
    let urgent_now = if n.urgent_due && urgent == 0 {
        n.urgent_due = false;
        already = true;
        false
    } else {
        n.urgent_due && !outstanding
    };
    // **A reply's notice is a wake too** (the plan owner's ruling, 2026-10-02): it obeys the
    // one-outstanding rule, so a session has at most one wake outstanding of either kind.
    let reply_now = n.reply.is_some()
        && idle
        && !outstanding
        && match n.reply_sent {
            0 => true,
            k => s
                .reply_nudges
                .get(k as usize - 1)
                .is_some_and(|wait| now >= n.reply_at.saturating_add(ms(*wait))),
        };
    if urgent_now || reply_now {
        n.urgent_due = false;
        n.sent_at = Some(now);
        n.sent_cursor = cursor;
        // An urgent notice counts the unread replies too, so it is the series' first.
        if n.reply.is_some() && (reply_now || n.reply_sent == 0) {
            n.reply_sent += 1;
            n.reply_at = now;
        }
        return Tended::Send;
    }
    if already {
        Tended::AlreadyRead
    } else if n.urgent_due {
        Tended::Held
    } else {
        Tended::Quiet
    }
}
