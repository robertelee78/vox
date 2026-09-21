//! ADR-020 §6 — `vox agent hook`: an agent session reads its room at the top of
//! every turn, without being asked.
//!
//! This is the piece that turns a CLI into agents communicating. Everything else
//! in agent comms is machinery an agent must *choose* to call; this is
//! mechanical, and that distinction is the whole design.
//!
//! ## Why a hook and not a skill
//!
//! The original plan was "the skill tells agents to drain at turn start". That
//! was the wrong mechanism and the research is unambiguous: a **skill is
//! on-demand only** and `CLAUDE.md` is context loaded once and treated as advice.
//! Neither can guarantee an action every turn. A hook can, because the harness
//! runs it whether or not the model would have thought to.
//!
//! ## What the spike measured, rather than assumed
//!
//! Against Claude Code 2.1.278, headless (`claude -p`) with a project-local hook:
//!
//! - `SessionStart` **and** `UserPromptSubmit` both fire, headless included —
//!   so this works for an agent nobody is typing at;
//! - `UserPromptSubmit` arrives with `cwd`, `hook_event_name`, `permission_mode`,
//!   `prompt`, `prompt_id`, `session_id`, `transcript_path`. **`session_id` is
//!   the cursor key**, and it is why two agent sessions on one node can be told
//!   different things;
//! - `SessionStart` arrives with `cwd`, `hook_event_name`, `session_id`,
//!   `source`, `transcript_path` — no `prompt`.
//!
//! One thing the spike could **not** confirm: that `additionalContext` reaches
//! the model. The probe injected a marker, but this machine's API key returned
//! 401 so no model ever ran. The field is documented as "added to Claude's
//! context" and the shape below matches the docs exactly, but it is unverified
//! here and the rehearsal is what will settle it.
//!
//! ## The contract
//!
//! stdin is the harness's hook JSON; stdout is the harness's injection JSON.
//! **Exit 0 whatever happens.** A hook that fails must not break the turn it is
//! attached to: an agent that cannot reach its room should carry on working, not
//! stop. Failures are reported on stderr, which the harness shows the operator
//! without feeding to the model.

use std::io::Read as _;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::tunnel_cli::resolve_prefix;

/// What the harness tells us. Only the fields we actually use — a harness may add
/// more and this must keep working when it does.
struct HookInput {
    event: String,
    session_id: String,
}

fn parse_input(raw: &str) -> HookInput {
    let v: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    HookInput {
        event: v
            .get("hook_event_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UserPromptSubmit")
            .to_owned(),
        session_id: v
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown-session")
            .to_owned(),
    }
}

/// Read this session's cursor for `room`, if it has one.
fn load_cursor(paths: &Paths, room: &str, session: &str) -> Option<Digest32> {
    let text = std::fs::read_to_string(paths.cursor_file(room, session)).ok()?;
    let t = text.trim();
    vox_core::node::link::b32_decode(t, "cursor").ok()
}

/// Record how far this session has now read.
///
/// Written **after** the messages have been emitted, so a crash between the two
/// re-delivers rather than skips. Re-reading a message is noise; missing one is a
/// silent failure, and between the two the choice is not close.
fn save_cursor(paths: &Paths, room: &str, session: &str, at: &Digest32) -> std::io::Result<()> {
    let dir = paths.cursor_dir();
    std::fs::create_dir_all(&dir)?;
    vox_core::node::paths::write_private_file(
        &paths.cursor_file(room, session),
        b32_encode(at).as_bytes(),
    )
    .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Render the messages an agent has not seen, for injection into its context.
///
/// Deliberately plain and compact. This lands in a model's context every turn, so
/// it costs tokens on every turn it is non-empty — a verbose framing here is paid
/// for over and over.
fn render(room_label: &str, rows: &[vox_core::node::api::MessageRow]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "New messages in Vox room {room_label} ({} since you last looked).\n\
         Reply with `vox room post {room_label} -` (message on stdin).\n\n",
        rows.len()
    ));
    for r in rows {
        out.push_str(&format!(
            "[{} from {}] {}\n",
            &b32_encode(&r.entry_hash)[..8],
            &b32_encode(&r.author)[..8],
            r.text.trim()
        ));
    }
    out
}

/// How a harness wants injected context on stdout.
///
/// The **only** thing that differs between harnesses. Everything above this —
/// attaching, resolving the room, the cursor, what counts as unread — is one code
/// path for all of them, which is what makes this harness-agnostic rather than
/// three implementations wearing a trench coat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Decide from the input: a `hook_event_name` field means Claude Code.
    Auto,
    /// Claude Code: `{"hookSpecificOutput":{"hookEventName":…,"additionalContext":…}}`.
    Claude,
    /// Codex, and the safe default for anything unknown: **plain stdout becomes
    /// the injected context**. Also what a person sees when running this by hand,
    /// and what the OpenCode plugin consumes before putting it in `output.parts`.
    Text,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Format::Auto),
            "claude" | "claude-code" => Ok(Format::Claude),
            "text" | "codex" | "plain" => Ok(Format::Text),
            other => Err(format!(
                "unknown format {other:?}; use auto, claude or text"
            )),
        }
    }
}

/// Emit injected context in the shape this harness reads.
fn emit(format: Format, raw_input: &str, event: &str, context: &str) {
    let chosen = match format {
        Format::Auto => {
            // Claude Code's hook input carries `hook_event_name`; Codex's plain
            // form does not. Detection rather than configuration, so an operator
            // installing this in either harness does not have to know which flag
            // to pass — and `text` is the fallback because it is the one that
            // cannot corrupt a harness that wanted the other.
            if raw_input.contains("\"hook_event_name\"") {
                Format::Claude
            } else {
                Format::Text
            }
        }
        other => other,
    };
    match chosen {
        Format::Claude => {
            let payload = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "additionalContext": context,
                }
            });
            println!("{payload}");
        }
        // Codex: "Plain text stdout becomes additionalContext for SessionStart,
        // SubagentStart and UserPromptSubmit" — and the hook must be registered
        // with `async: false`, or the output is observed and discarded.
        Format::Text | Format::Auto => print!("{context}"),
    }
}

/// Run the hook: read stdin, drain the room, emit context, advance the cursor.
///
/// Returns `Ok(())` in every case a hook should not disturb the turn. The only
/// `Err` is a usage error from the caller's own arguments, which is reported
/// before any harness is involved.
pub async fn run(
    paths: &Paths,
    room_arg: Option<&str>,
    format: Format,
    session: Option<&str>,
) -> Result<(), AppError> {
    let mut raw = String::new();
    // A harness always provides stdin; a person testing by hand may not — and
    // OpenCode's plugin cannot, so it passes `--session` instead.
    if session.is_none() {
        let _ = std::io::stdin().read_to_string(&mut raw);
    }
    let mut input = parse_input(&raw);
    if let Some(s) = session {
        input.session_id = s.to_owned();
    }

    let Some(room_arg) = room_arg
        .map(str::to_owned)
        .or_else(|| std::env::var("VOX_ROOM").ok())
    else {
        eprintln!(
            "vox agent hook: no room. Pass --room <id>, or set VOX_ROOM, in the hook's \
             environment."
        );
        return Ok(());
    };

    if let Err(e) = drain(paths, &room_arg, &input, &raw, format).await {
        // Report and carry on: a hook must never break the turn it rides on.
        eprintln!("vox agent hook: {e}");
    }
    Ok(())
}

async fn drain(
    paths: &Paths,
    room_arg: &str,
    input: &HookInput,
    raw_input: &str,
    format: Format,
) -> Result<(), AppError> {
    let sock = paths.socket_file();
    if !sock.exists() {
        return Err(AppError::Usage(
            "no node is running for this profile, so there is nothing to read".into(),
        ));
    }
    let mut client = IpcClient::open(&sock)
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;

    let rooms = match client.request(&Request::Rooms).await {
        Ok(Frame::Rooms { rooms }) => rooms,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let ids: Vec<Digest32> = rooms.iter().map(|(id, _, _)| *id).collect();
    let channel_id = resolve_prefix(room_arg, &ids)?;
    let room_key = b32_encode(&channel_id);
    let label: String = room_key.chars().take(12).collect();

    let since = load_cursor(paths, &room_key, &input.session_id);
    let rows = match client
        .request(&Request::Read {
            channel_id,
            since,
            limit: 0,
        })
        .await
    {
        Ok(Frame::Rows { rows }) => rows,
        // A cursor the node no longer holds — the room was re-opened, or the log
        // was pruned. Start from the beginning rather than failing: the agent
        // seeing a message twice is recoverable, an agent stuck forever is not.
        Ok(Frame::Error { .. }) => match client
            .request(&Request::Read {
                channel_id,
                since: None,
                limit: 0,
            })
            .await
        {
            Ok(Frame::Rows { rows }) => rows,
            Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
            Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
            Err(e) => return Err(AppError::Usage(e.to_string())),
        },
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    if rows.is_empty() {
        // Nothing new: emit nothing at all rather than "no new messages". An
        // agent's context is not the place for a heartbeat, and a quiet room
        // should cost zero tokens per turn.
        return Ok(());
    }

    emit(format, raw_input, &input.event, &render(&label, &rows));

    if let Some(last) = rows.last() {
        if let Err(e) = save_cursor(paths, &room_key, &input.session_id, &last.entry_hash) {
            // The messages are already out; failing to record that only means the
            // next turn re-delivers them.
            eprintln!("vox agent hook: could not record the cursor: {e}");
        }
    }
    Ok(())
}

/// The OpenCode plugin, shipped in the binary so `vox agent plugin opencode` can
/// print it.
///
/// OpenCode is the odd harness of the three: Claude Code and Codex both run a
/// **command** at turn start, so they need only a settings entry naming `vox agent
/// hook`. OpenCode has no such hook — it loads JavaScript plugins into its own
/// process — so the integration has to be a file. It is still a shim over the same
/// `vox agent hook`, reading `--format text`, so there is exactly one
/// implementation of what an agent has not yet read.
pub const OPENCODE_PLUGIN: &str = include_str!("../assets/opencode-plugin.js");
