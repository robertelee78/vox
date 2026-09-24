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

/// Whether `row` is this very session's own message: the same author fingerprint
/// **and** the same session.
fn is_own(row: &vox_core::node::api::MessageRow, me: Option<Digest32>, session: &str) -> bool {
    me == Some(row.author)
        && vox_agentcomms::envelope::Envelope::parse(&row.text)
            .is_ok_and(|e| !e.from.is_empty() && e.from == session)
}

/// The most messages one turn injects. Past this the rest wait for the next turn,
/// and the injection says how many.
///
/// This lands in a model's context every turn. It was unbounded — `limit: 0`, every
/// unread row — so an agent returning to a busy room, or one whose cursor was lost,
/// took the whole backlog into one prompt, and anyone in the room could make that
/// happen by posting.
pub const MAX_INJECTED_MESSAGES: usize = 50;
/// The most bytes of message text one turn injects, across every message in it.
pub const MAX_INJECTED_BYTES: usize = 16 * 1024;
/// The most bytes of any one message that are injected. The rest is a `vox room read`
/// away, and the injection says how much was cut.
pub const MAX_MESSAGE_BYTES: usize = 2 * 1024;

/// What begins every continuation line of a message. Never `[`, which is what begins
/// a row — that difference is the whole of the attribution guarantee.
const CONTINUATION: &str = "  | ";

/// Whether `c` ends a line for *somebody* reading this output.
///
/// Not just `\n`: a model, a terminal and a JSON viewer each have their own idea of
/// a line break, and a message only has to find one of them that this code did not
/// indent to start a row of its own.
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// One message, attributed so that **no author can forge another's row**.
///
/// A row is `[<entry> from <author>] <first line>`, and both fields come from the
/// log — the entry hash and the signing author's fingerprint — never from the text.
/// Every further line of the text is prefixed with [`CONTINUATION`], so nothing an
/// author writes can begin a line with `[`: a message containing a newline and a
/// fake `[… from …]` row renders as an indented line inside its true author's
/// message, not as a message from someone else. The old form printed the text raw,
/// and a two-line post was indistinguishable from two posts by two people (PRD-001
/// D9, R19).
///
/// Other control characters are replaced rather than passed through, for the same
/// reason line breaks are: whatever displays this must not be steered by the text.
fn render_row(out: &mut String, r: &vox_core::node::api::MessageRow) {
    use std::fmt::Write as _;
    let text = r.text.trim();
    let (shown, cut) = if text.len() > MAX_MESSAGE_BYTES {
        let mut end = MAX_MESSAGE_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (&text[..end], text.len() - end)
    } else {
        (text, 0)
    };
    let _ = write!(
        out,
        "[{} from {}] ",
        &b32_encode(&r.entry_hash)[..8],
        &b32_encode(&r.author)[..8],
    );
    let mut pending_break = false;
    for c in shown.chars() {
        if is_line_break(c) {
            // `\r\n` is one break, not two; any run of breaks is one continuation.
            pending_break = true;
            continue;
        }
        if pending_break {
            out.push('\n');
            out.push_str(CONTINUATION);
            pending_break = false;
        }
        if c.is_control() && c != '\t' {
            out.push('\u{fffd}');
        } else {
            out.push(c);
        }
    }
    if cut > 0 {
        let _ = write!(
            out,
            "\n{CONTINUATION}(… {cut} more bytes not shown; `vox room read` has the whole message)"
        );
    }
    out.push('\n');
}

/// Render the messages an agent has not seen, for injection into its context, and
/// say how many of them it holds.
///
/// Deliberately plain and compact. This lands in a model's context every turn, so
/// it costs tokens on every turn it is non-empty — a verbose framing here is paid
/// for over and over.
///
/// **Bounded, oldest first, and never silent about the rest.** At most
/// [`MAX_INJECTED_MESSAGES`] messages and [`MAX_INJECTED_BYTES`] of text go in; what
/// does not fit is counted in a closing line and delivered on the next turn, because
/// the cursor advances only to the last message shown. Oldest first so that nothing
/// is ever skipped: showing the newest and moving the cursor past the rest would
/// lose them without anyone having read them.
///
/// Returns the text and how many of `rows` it carries (always at least one when
/// `rows` is non-empty, so a single oversized message cannot wedge the cursor).
fn render(
    room_label: &str,
    rows: &[vox_core::node::api::MessageRow],
    notice: Option<&str>,
) -> (String, usize) {
    let mut body = String::new();
    let mut shown = 0usize;
    for r in rows.iter().take(MAX_INJECTED_MESSAGES) {
        let mut one = String::new();
        render_row(&mut one, r);
        if shown > 0 && body.len() + one.len() > MAX_INJECTED_BYTES {
            break;
        }
        body.push_str(&one);
        shown += 1;
    }
    let mut out = String::new();
    if let Some(n) = notice {
        out.push_str(n);
        out.push('\n');
    }
    out.push_str(&format!(
        "New messages in Vox room {room_label} ({} since you last looked).\n\
         Each starts with [message from author]; lines beginning \"{}\" continue it.\n\
         Reply with `vox room post {room_label} -` (message on stdin).\n\n",
        rows.len(),
        CONTINUATION.trim_end(),
    ));
    out.push_str(&body);
    let rest = rows.len() - shown;
    if rest > 0 {
        out.push_str(&format!(
            "-- {rest} more unread message(s) not shown; they follow on your next turn, or \
             read them now with `vox room read {room_label} --since {}` --\n",
            b32_encode(&rows[shown - 1].entry_hash)
        ));
    }
    (out, shown)
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
    // The same order `vox room` uses to name the session, so that what this hook
    // recognises as "my own message" is exactly what that session's verbs wrote
    // (ADR-021 §7): the flag, then `VOX_SESSION`, then what the harness sent.
    if let Some(s) = session.map(str::to_owned).or_else(|| {
        std::env::var("VOX_SESSION")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }) {
        input.session_id = s.trim().to_owned();
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

    // Record how this session can be woken, while we are here and know both the
    // session id and what the harness put in our environment (ADR-020 §6). It is a
    // side effect of the drain rather than a step an operator configures, and the
    // next turn rewrites it, so a stale entry corrects itself.
    crate::wake::register(paths, &input.session_id, &room_key);

    let since = load_cursor(paths, &room_key, &input.session_id);
    let mut notice = None;
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
        // **But say so**, in the injection itself: this used to re-read the whole
        // history silently, and on *any* error, so an agent could not tell a backlog
        // from a replay (PRD-001 D9).
        Ok(Frame::Error { reason }) if since.is_some() => {
            notice = Some(format!(
                "(Your read position in this room was not found — {reason} — so this \
                 starts again from the room's first message.)"
            ));
            match client
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
            }
        }
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    // **This session's own messages are not news to it** (ADR-021 F8) — but only when
    // BOTH the author and the session match. The author alone would drop every other
    // session on this harness; the session name alone would drop a different harness
    // that happens to use the same name. Either mistake silently loses a message
    // meant for this agent.
    let me = client.me();
    let fresh: Vec<vox_core::node::api::MessageRow> = rows
        .iter()
        .filter(|r| !is_own(r, me, &input.session_id))
        .cloned()
        .collect();

    // **Coordination refused is said plainly, every turn it holds** (ADR-021 §5): a
    // session that cannot claim work should learn why before it tries, not from an
    // exit status in the middle of a task.
    let refused = match crate::coord::snapshot(&mut client, channel_id).await {
        Ok(snap) if snap.table.refused() => Some(crate::coord::refusal(&room_key, &snap.table)),
        _ => None,
    };

    if fresh.is_empty() && refused.is_none() {
        // Nothing new: emit nothing at all rather than "no new messages". An
        // agent's context is not the place for a heartbeat, and a quiet room
        // should cost zero tokens per turn.
        if let Some(last) = rows.last() {
            let _ = save_cursor(paths, &room_key, &input.session_id, &last.entry_hash);
        }
        return Ok(());
    }

    let mut context = String::new();
    if let Some(r) = &refused {
        context.push_str(&format!(
            "{r}\nUntil then `vox room claim|renew|handoff|release|decline` and \
             `vox room post --work` exit 3.\n\n"
        ));
    }
    // Bounded (PRD-001 D9): what did not fit is delivered next turn, so the cursor
    // moves only as far as the last message shown — or past everything when all of
    // it was.
    let mut upto = rows.last();
    if !fresh.is_empty() {
        let (text, shown) = render(&label, &fresh, notice.as_deref());
        context.push_str(&text);
        if shown < fresh.len() {
            upto = fresh.get(shown.saturating_sub(1));
        }
    }
    emit(format, raw_input, &input.event, &context);

    if let Some(last) = upto {
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

/// The agent-facing skill (ADR-020 §8), shipped in the binary so `vox agent skill`
/// can print it.
///
/// A skill is **on-demand only** — it cannot guarantee an action every turn, which
/// is why the drain is a hook and not an instruction. What it carries instead is
/// the part a hook cannot: the conventions, the vocabulary, and the manners a room
/// full of agents needs to stay readable by the person in it.
pub const AGENT_SKILL: &str = include_str!("../assets/agent-skill.md");
