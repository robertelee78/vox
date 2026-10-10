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
//!
//! ## Who is woken (V210-161, V210-163)
//!
//! An urgent message addressed to a node wakes the sessions of that node, in whichever room it
//! lands: `to` names nodes, and every session hears every room its node holds. The node the
//! message is for decides, on its own daemon, so a session on another node is woken by that
//! node's daemon once the message reaches it. Not the session that posted it, and not one that
//! already spoke in the reply chain it answers (V210-121).
//!
//! ## What a wake says, and when (V030-15, V030-20)
//!
//! A wake is a **notice**: how many urgent messages and replies wait, from whom, in which room,
//! and never a byte of any of them (`agent_hook::render_wake`). The messages arrive once, in the
//! drain of the turn the notice starts. The daemon counts what is owed just before it sends
//! ([`unread`], [`tend`]), keeps at most one notice outstanding per session, across every room,
//! and announces an unread reply to an idle session on a schedule ([`Settings`]). What it owes
//! each session is kept in [`Notices`], beside the registration, so a restart resumes it.

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
    /// What the harness last said about this session's turn (V030-20): [`BUSY`] when one began
    /// (its drain ran), [`IDLE`] when one ended (Claude Code's `Stop`).
    #[serde(default)]
    pub state: String,
    /// When the harness last said so, in Unix milliseconds.
    #[serde(default)]
    pub state_ms: u64,
    /// When this session first registered, in Unix milliseconds (V030-16). Kept as every later
    /// turn rewrites the record.
    #[serde(default)]
    pub first_seen_ms: u64,
    /// When its drain last ran, in Unix milliseconds: the last time it read its rooms.
    #[serde(default)]
    pub last_drained_ms: u64,
    /// The room this session works in (ADR-029 §6), its id in base32; `None` for none. Kept for
    /// the session's life once set (RB-4): a later registration without one never clears it, and
    /// only `vox agent room` moves it (RB-5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// The directory the session started in, as its first registration gave it (ADR-029 RB-2):
    /// what `vox agent room` offers to save in the room map. Kept, like `room`, for its life.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// The session's current name, as its harness gives it (ADR-029 MD-1); `None` when it gives
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether `name` is the one the session's person set (a Claude Code `/rename`, a Codex
    /// thread name), not one the harness made up: only such a name titles the Session (v0.4.3).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub named: bool,
    /// Claude Code's transcript for the session (its hooks' `transcript_path`), where a `/rename`
    /// writes the new name: the daemon reads it there, since no hook runs after a slash command.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transcript: String,
    /// Whether a person is at the session (ADR-029 SE-1): a headless run (`claude -p`, an SDK,
    /// `codex exec`) gets no Session.
    #[serde(default = "interactive_by_default")]
    pub interactive: bool,
    /// The tmux pane the session runs in, proven, when it runs in one (ADR-029 DR-1, DR-5): how a
    /// driver's input reaches a Claude Code session, as ctm's injector does. Refreshed by every
    /// hook. `None` outside tmux, or when the pane could not be proven ([`Session::tmux_why`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux: Option<TmuxPane>,
    /// Why the session's pane could not be proven, when it runs in tmux but could not be bound:
    /// what a driver is told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_why: Option<String>,
    /// What the hook's environment says of its pane, for the daemon to prove
    /// ([`crate::claude_injector::prove`]) before it stores the registration. Never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmux_claim: Option<TmuxClaim>,
    /// A Codex session's `CODEX_HOME`, whose app-server the daemon reads it from (ADR-029 #541).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub codex_home: String,
    /// The Vox OpenCode plugin's mirror socket, through which the daemon follows the session
    /// (ADR-029 #542). Its token is [`Self::token`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mirror: String,
}

/// What a hook's environment says of its tmux pane: claimed, not proven. The daemon proves it
/// from the process table and tmux itself, since a hook may run where neither can be read (a
/// sandbox).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TmuxClaim {
    /// `$TMUX`'s first field.
    pub socket: String,
    /// `$TMUX_PANE`.
    pub pane: String,
    /// The `tmux` the hook's `PATH` finds.
    pub bin: String,
    /// The hook's own process, waiting for the daemon's answer while it proves: its ancestry is
    /// the session's.
    pub hook_pid: u32,
}

/// Where a session's terminal is, in tmux, and the process that ties the session to it: found by
/// the session's own hook ([`crate::claude_injector::claim_here`]), proved by the daemon
/// ([`crate::claude_injector::prove`]) and checked again at every send.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TmuxPane {
    /// The tmux server's socket: the first field of `$TMUX`.
    pub socket: String,
    /// The pane: `$TMUX_PANE`, as `%<n>`.
    pub pane: String,
    /// The `tmux` the hook's `PATH` finds, so the daemon, whose environment is not the
    /// harness's, runs the same one.
    pub bin: String,
    /// The pane's own process (`#{pane_pid}`), as tmux said when the hook bound it.
    pub pane_pid: u32,
    /// The session's process: Claude Code itself, the hook's parent (after at most one `sh -c`),
    /// known by its executable, running beneath the pane through any wrapper.
    pub process: u32,
    /// When that process started, as the process table says: a reused pid is not the session.
    pub process_start: String,
    /// What that process is called, as the process table says (for the driver's words).
    pub process_name: String,
}

/// A record written before Sessions said nothing of it: it was registered by a hook a person ran.
fn interactive_by_default() -> bool {
    true
}

/// Whether the harness this hook runs inside has a person at it (ADR-029 SE-1).
///
/// **Claude Code** sets `CLAUDE_CODE_ENTRYPOINT` for its hooks: `sdk-cli` for a non-interactive
/// run (`claude -p`), `sdk-ts` / `sdk-py` for the Agent SDK, `cli` for a person at the terminal
/// (read from Claude Code 2.1.292: `set("CLAUDE_CODE_ENTRYPOINT", e ? "sdk-cli" : "cli")`).
/// Codex and OpenCode are taken as interactive until their own signals are measured.
#[must_use]
pub fn interactive_now() -> bool {
    !matches!(
        std::env::var("CLAUDE_CODE_ENTRYPOINT").as_deref(),
        Ok("sdk-cli" | "sdk-ts" | "sdk-py")
    )
}

/// How a registered session can be reached now (V030-16), as `vox agent doctor` and a pong
/// report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Its wake endpoint accepts a connection: an urgent message to its node interrupts it.
    Interrupt,
    /// It has no wake path (Codex, which Vox never interrupts, or a harness Vox does not know):
    /// it reads at its next turn.
    Turn,
    /// Its wake endpoint is gone: its harness exited or restarted, and nothing reaches it until
    /// it registers again on its next turn.
    Gone(String),
}

impl Reach {
    /// A short machine token: `interrupt`, `turn` or `gone`.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Reach::Interrupt => "interrupt",
            Reach::Turn => "turn",
            Reach::Gone(_) => "gone",
        }
    }
}

/// Whether `session` can be woken now: a connection to its endpoint, closed at once, so nothing
/// is delivered and nothing is woken.
pub async fn reach(session: &Session) -> Reach {
    if !wakeable(&session.harness) {
        return Reach::Turn;
    }
    if session.endpoint.is_empty() {
        return Reach::Gone("it registered no wake endpoint".into());
    }
    let probe = tokio::net::UnixStream::connect(&session.endpoint);
    match tokio::time::timeout(std::time::Duration::from_secs(2), probe).await {
        Ok(Ok(_)) => Reach::Interrupt,
        Ok(Err(e)) => Reach::Gone(format!("{}: {e}", session.endpoint)),
        Err(_) => Reach::Gone(format!("{}: no answer within 2 s", session.endpoint)),
    }
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

/// The `data` key of a session's `hello` saying how it can be reached (V030-17).
pub const WAKE_KEY: &str = "wake";
/// How `session` can be reached, as its `hello` says it (`data.wake`, V030-17): `interrupt` when
/// it left Vox a wake channel (Claude Code's messaging socket, or the Vox OpenCode plugin's), else
/// `turn` — it reads the room at its next turn, and nothing can start one (Codex: V210-169).
///
/// Its registration decides when it has one: a Codex started from a Claude Code terminal
/// inherits that terminal's socket, and its hook registered it as Codex from its own input. With
/// no registration (no hook ran), what the harness put in the environment.
#[must_use]
pub fn reachability(paths: &Paths, session: &str) -> &'static str {
    if let Some(reg) = load(paths, session) {
        return if reg.harness != "codex" && !reg.endpoint.is_empty() {
            "interrupt"
        } else {
            "turn"
        };
    }
    let set = |k: &str| std::env::var_os(k).is_some();
    if (set("CLAUDE_CODE_MESSAGING_SOCKET") && set("CLAUDE_CODE_MESSAGING_TOKEN"))
        || (set("VOX_OPENCODE_WAKE_SOCKET") && set("VOX_OPENCODE_WAKE_TOKEN"))
    {
        "interrupt"
    } else {
        "turn"
    }
}

/// Record how this session can be woken, from what the harness put in the
/// environment, and that its turn is running: the drain runs at the start of one.
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
    store(paths, &Session::from_env(session, codex));
}

/// Store `reg` as its session's registration (ADR-020 6.10): the daemon's half of
/// [`register`], the client's half being [`Session::from_env`]. When the session was first seen
/// is kept from its earlier record; this turn is its last drain.
pub fn store(paths: &Paths, reg: &Session) {
    let mut reg = reg.clone();
    let session = reg.session.clone();
    let session = session.as_str();
    // When the session was first seen outlives this turn's rewrite (V030-16).
    let now = now_millis();
    let earlier = load(paths, session);
    reg.first_seen_ms = earlier
        .as_ref()
        .map(|b| b.first_seen_ms)
        .filter(|&t| t != 0)
        .unwrap_or(now);
    // **A session's room is the one it started with, for its life** (ADR-029 RB-4, RB-5): a
    // session that started in no room stays in none, however it moves about later; only
    // [`store_room`] (`vox agent room`) changes it. A record from before Sessions had no room to
    // keep.
    if let Some(b) = earlier
        .as_ref()
        .filter(|b| b.room.is_some() || b.first_seen_ms != 0)
    {
        reg.room.clone_from(&b.room);
        reg.start.clone_from(&b.start);
    }
    // **A name, once given, stays until the harness gives another** (ADR-029 MD-1): a turn whose
    // harness said nothing of it (a sub-agent's event, a transcript not yet written) keeps it.
    if reg.name.is_none() {
        reg.name = earlier.and_then(|b| b.name);
    }
    reg.last_drained_ms = now;
    // **One session per pane** (ADR-029 DR-5): the newest hook in a pane claims it, and every other
    // session of this node bound there loses its binding. Case: a new session (or `/clear`) in the
    // pane of one that ended without a SessionEnd while its process lives on.
    if let Some(mine) = reg.tmux.as_ref() {
        unbind_pane(paths, session, &mine.socket, &mine.pane);
    }
    let dir = paths.session_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(body) = serde_json::to_vec(&reg) {
        let _ =
            vox_core::node::paths::write_private_file_unique(&paths.session_file(session), &body);
    }
}

/// Name `session`'s registration `name`, as its harness now calls it (ADR-029 MD-1): what an
/// adapter that hears a rename (Codex's thread name, OpenCode's session title) records. `None`
/// when the session is not registered; else the registration as it now is.
pub fn store_name(paths: &Paths, session: &str, name: &str, named: bool) -> Option<Session> {
    let mut reg = load(paths, session)?;
    reg.name = Some(name.to_owned());
    reg.named = named;
    if let Ok(body) = serde_json::to_vec(&reg) {
        let _ =
            vox_core::node::paths::write_private_file_unique(&paths.session_file(session), &body);
    }
    Some(reg)
}

/// Move `session`'s registration to `room` (ADR-029 RB-5, `vox agent room`): the one way a
/// session's room changes. `None` when the session is not registered; else the room it worked in
/// before, if any.
pub fn store_room(paths: &Paths, session: &str, room: &str) -> Option<Option<String>> {
    let mut reg = load(paths, session)?;
    let before = reg.room.replace(room.to_owned());
    if let Ok(body) = serde_json::to_vec(&reg) {
        let _ =
            vox_core::node::paths::write_private_file_unique(&paths.session_file(session), &body);
    }
    Some(before)
}

impl Session {
    /// The registration a hook builds from its harness's environment (the client's half of
    /// [`register`]; the daemon stores it with [`store`], since the daemon's environment is not
    /// the harness's).
    #[must_use]
    pub fn from_env(session: &str, codex: bool) -> Self {
        let mut s = Self::from_env_untmuxed(session, codex);
        match crate::claude_injector::claim_here() {
            Ok(claim) => s.tmux_claim = claim,
            Err(why) => s.tmux_why = Some(why),
        }
        // Claude Code sets `CLAUDE_CODE_ENTRYPOINT` for its hooks even when its messaging socket
        // is off.
        if s.harness == "unknown" && std::env::var_os("CLAUDE_CODE_ENTRYPOINT").is_some() {
            s.harness = "claude".into();
        }
        s
    }

    fn from_env_untmuxed(session: &str, codex: bool) -> Self {
        if codex {
            Session {
                session: session.to_owned(),
                harness: "codex".into(),
                endpoint: String::new(),
                token: String::new(),
                state: BUSY.into(),
                state_ms: now_millis(),
                first_seen_ms: 0,
                last_drained_ms: 0,
                room: None,
                start: None,
                name: None,
                named: false,
                transcript: String::new(),
                interactive: interactive_now(),
                tmux: None,
                tmux_why: None,
                tmux_claim: None,
                codex_home: crate::codex_mirror::codex_home_from_env(),
                mirror: String::new(),
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
                state: BUSY.into(),
                state_ms: now_millis(),
                first_seen_ms: 0,
                last_drained_ms: 0,
                room: None,
                start: None,
                name: None,
                named: false,
                transcript: String::new(),
                interactive: interactive_now(),
                tmux: None,
                tmux_why: None,
                tmux_claim: None,
                codex_home: String::new(),
                mirror: String::new(),
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
                state: BUSY.into(),
                state_ms: now_millis(),
                first_seen_ms: 0,
                last_drained_ms: 0,
                room: None,
                start: None,
                name: None,
                named: false,
                transcript: String::new(),
                interactive: interactive_now(),
                tmux: None,
                tmux_why: None,
                tmux_claim: None,
                codex_home: String::new(),
                mirror: std::env::var("VOX_OPENCODE_MIRROR_SOCKET").unwrap_or_default(),
            }
        } else {
            Session {
                session: session.to_owned(),
                harness: std::env::var("VOX_HARNESS").unwrap_or_else(|_| "unknown".into()),
                endpoint: String::new(),
                token: String::new(),
                state: BUSY.into(),
                state_ms: now_millis(),
                first_seen_ms: 0,
                last_drained_ms: 0,
                room: None,
                start: None,
                name: None,
                named: false,
                transcript: String::new(),
                interactive: interactive_now(),
                tmux: None,
                tmux_why: None,
                tmux_claim: None,
                codex_home: String::new(),
                mirror: String::new(),
            }
        }
    }
}

/// Drop the tmux binding of every session of this node but `keep` bound to `pane` on `socket`.
fn unbind_pane(paths: &Paths, keep: &str, socket: &str, pane: &str) {
    let Ok(dir) = std::fs::read_dir(paths.session_dir()) else {
        return;
    };
    for f in dir.flatten() {
        let Ok(body) = std::fs::read(f.path()) else {
            continue;
        };
        let Ok(mut other) = serde_json::from_slice::<Session>(&body) else {
            continue;
        };
        if other.session == keep
            || !other
                .tmux
                .as_ref()
                .is_some_and(|t| t.socket == socket && t.pane == pane)
        {
            continue;
        }
        other.tmux = None;
        other.tmux_why = Some(format!(
            "tmux pane {pane} now runs another session, so this one cannot be typed into until \
             its next turn"
        ));
        if let Ok(body) = serde_json::to_vec(&other) {
            let _ = vox_core::node::paths::write_private_file_unique(&f.path(), &body);
        }
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
    use vox_agentcomms::envelope::addressee;
    // The sessions of this node the message names: every one for the node, or the one session a
    // `<fingerprint>/<session id>` entry names (ADR-029 TA-3, TA-4).
    let whole = to.iter().any(|n| n == me);
    let named: Vec<&str> = to
        .iter()
        .filter_map(|n| match addressee(n) {
            (node, Some(session)) if node == me => Some(session),
            _ => None,
        })
        .collect();
    if !whole && named.is_empty() {
        return None;
    }
    let reachable = registered(paths).iter().any(|s| {
        (whole || named.contains(&s.session.as_str()))
            && s.harness != "codex"
            && !s.endpoint.is_empty()
    });
    if reachable {
        return None;
    }
    Some(if whole {
        "no session of this node can be interrupted: Vox never interrupts a Codex session, and \
         no other session here left Vox a way to reach it. Each reads the message at its next \
         turn."
            .to_owned()
    } else {
        "the session it names cannot be interrupted: Vox never interrupts a Codex session, or that \
         session left Vox no way to reach it. It reads the message at its next turn."
            .to_owned()
    })
}

/// Whether `e` may wake `session` of the node `me` (ADR-020 6.2, ADR-029 TA-3): urgent, not
/// plumbing, and addressed to the node, which reaches every session of it, or to that one session.
/// A wake is announce-only: it names counts and senders, never the message (V030-15).
#[must_use]
pub fn wakes(e: &Envelope, me: &str, session: &str) -> bool {
    e.urgent
        && !vox_agentcomms::envelope::is_plumbing(&e.kind)
        && e.is_addressed_to_session(me, session)
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
        let _ = std::fs::remove_file(woke_file(paths, &session.session));
    }
    gone
}

/// `session`'s registration, if it has one.
/// `session`'s registration as stored, if it is registered.
#[must_use]
pub fn registration(paths: &Paths, session: &str) -> Option<Session> {
    load(paths, session)
}

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

/// Remove `session`'s registration, its notice record and its record of wakes (Claude Code's
/// `SessionEnd`, V030-20): a session that has ended is never woken again. Its cursors stay, for a
/// session resumed later.
pub fn end(paths: &Paths, session: &str) {
    let _ = std::fs::remove_file(paths.session_file(session));
    let _ = std::fs::remove_file(notices_file(paths, session));
    let _ = std::fs::remove_file(woke_file(paths, session));
    let _ = std::fs::remove_file(said_detached_file(paths, session));
}

fn said_detached_file(paths: &Paths, session: &str) -> std::path::PathBuf {
    let reg = paths.session_file(session);
    let dir = paths.session_dir().with_extension("said-detached");
    dir.join(reg.file_name().unwrap_or_default())
}

/// Whether `session` is yet to be told that its node is not attached (#666): `true` the first
/// time in the session, which is recorded, and `false` after, so the hook says it once per
/// session, not every turn. A record that cannot be written says it again rather than never.
pub fn first_detached_notice(paths: &Paths, session: &str) -> bool {
    let file = said_detached_file(paths, session);
    if file.exists() {
        return false;
    }
    if let Some(dir) = file.parent() {
        let _ = vox_core::node::paths::create_private_dir(dir);
    }
    let _ = vox_core::node::paths::write_private_file_unique(&file, b"");
    true
}

/// The hop budget `envelope` really has left, given the `rows` of its room (ADR-020 §9): see
/// [`vox_agentcomms::envelope::hops_left_by`], the one rule.
#[must_use]
pub fn hops_left<'a, R>(envelope: &Envelope, rows: &'a R) -> u32
where
    R: ?Sized,
    &'a R: IntoIterator<Item = &'a MessageRow>,
{
    vox_agentcomms::envelope::hops_left_by(envelope, |h| find(rows, h).map(|r| r.text.clone()))
}

/// The budget a reply to entry `re` starts with: its parent's less one, or the default when the
/// room does not hold that entry.
#[must_use]
pub fn reply_hops<'a, R>(re: &str, rows: &'a R) -> u32
where
    R: ?Sized,
    &'a R: IntoIterator<Item = &'a MessageRow>,
{
    vox_agentcomms::envelope::reply_hops_by(re, |h| find(rows, h).map(|r| r.text.clone()))
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

/// What `session` has not been given yet in one room that it is owed a notice for: the urgent
/// messages addressed to its node `me` that may still interrupt it (hops left, ADR-020 §9; not a
/// reply chain it already spoke in, V210-121), and the replies to its posts (V030-20), each oldest
/// first.
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
    // `to` names nodes, by whole fingerprint (V210-161).
    let me_fp = me.map(|m| vox_core::node::link::b32_encode(&m));
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
        let for_me = me_fp
            .as_deref()
            .is_some_and(|fp| wakes(&e, fp, &session.session));
        if for_me
            && hops_left(&e, timeline) > 0
            && !me.is_some_and(|m| in_chain(&e, timeline, &m, &session.session))
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
    /// An urgent message addressed to this session's node landed and has not been announced yet.
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
