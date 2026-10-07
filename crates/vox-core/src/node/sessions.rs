//! Sessions (ADR-029): a room's Session per interactive harness session working in it, as its node
//! says on the room's log.
//!
//! **A Session is two records on the log**, posted by the session's node, its author key proving
//! the node and `from` claiming the session (ADR-029 MD-3): a `session` entry when the session
//! first works in the room ([`open_when_member`]), and a `session-end` entry on the harness's real
//! end ([`end`]). Both are room messages, so every member of the room reads that the Session
//! exists, its label and whether it is open (SC-3); what the session does lives elsewhere, sealed
//! to members with drive (SC-2). A Session's name is the `at.session_name` its node last gave.
//!
//! Everything here is read from the room's own log ([`fold`]), so a node that restarts, or a member
//! that joins later, knows the same Sessions.

use vox_agentcomms::envelope::{Envelope, SESSION, SESSION_END};

use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::api::{ChannelDetail, NodeCommand, Outcome};

/// One Session of a room, as its log says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// The node whose session it is: the author of its records, proven.
    pub node: Digest32,
    /// The harness's own session id, as the node claims it.
    pub id: String,
    /// The session's current name, as the node last gave it; `None` for none.
    pub name: Option<String>,
    /// The harness: `claude`, `codex` or `opencode`, as the node claims it.
    pub harness: String,
    /// Whether it is open: opened, and not ended since.
    pub open: bool,
    /// When it opened, the author's time in milliseconds.
    pub opened_millis: u64,
    /// When it ended, if it has.
    pub ended_millis: Option<u64>,
    /// The entry that opened it.
    pub opening: Digest32,
    /// The entry that ended it, if one has.
    pub ended: Option<Digest32>,
    /// Whether this node may drive it (ADR-028 K-14, ADR-029 §3): its node trusts this node with
    /// drive. `false` until the keyring says so (#525).
    pub can_drive: bool,
}

/// The Sessions a room's log holds, oldest opening first: each `session` entry opens one, and a
/// later `session-end` from the same node and session ends it. A `session` from a session already
/// open names it again and changes nothing else.
#[must_use]
pub fn fold(detail: &ChannelDetail) -> Vec<SessionRow> {
    let types = [SESSION.to_owned(), SESSION_END.to_owned()];
    let mut rows: Vec<SessionRow> = Vec::new();
    let mut positions = detail.structured.positions(&types, &[]);
    positions.sort_unstable();
    for i in positions {
        let Some(r) = detail.timeline.get(i as usize) else {
            continue;
        };
        if r.owed {
            continue;
        }
        let Ok(env) = Envelope::parse(&r.text) else {
            continue;
        };
        if env.from.trim().is_empty() {
            continue;
        }
        let at = rows
            .iter()
            .rposition(|s| s.node == r.author && s.id == env.from);
        match (env.kind.as_str(), at) {
            (SESSION, Some(k)) if rows[k].open => {
                if env.at.session_name.is_some() {
                    rows[k].name.clone_from(&env.at.session_name);
                }
            }
            (SESSION, _) => rows.push(SessionRow {
                node: r.author,
                id: env.from.clone(),
                name: env.at.session_name.clone(),
                harness: env.data["session"]["harness"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                open: true,
                opened_millis: r.created_millis,
                ended_millis: None,
                opening: r.entry_hash,
                ended: None,
                // This node reads inside it when it holds the node's drive key, or is the node
                // (ADR-029 SC-2, #543).
                can_drive: detail.drive_from.contains(&r.author),
            }),
            (SESSION_END, Some(k)) if rows[k].open => {
                rows[k].open = false;
                rows[k].ended_millis = Some(r.created_millis);
                rows[k].ended = Some(r.entry_hash);
            }
            _ => {}
        }
    }
    rows
}

/// The Sessions of the open room `room`, as `handle`'s node holds it; empty for a room not open.
#[must_use]
pub fn of_room(handle: &NodeHandle, room: &Digest32) -> Vec<SessionRow> {
    let view = handle.view();
    view.open_channels
        .iter()
        .find(|d| d.channel_id == *room)
        .map(fold)
        .unwrap_or_default()
}

/// What a session tells its node about itself, for its Session's records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    /// The harness's own session id.
    pub id: String,
    /// The harness: `claude`, `codex` or `opencode`.
    pub harness: String,
    /// Its current name, if the harness gives one.
    pub name: Option<String>,
}

/// Open `session`'s Session in `room` if it has none open there (ADR-029 SE-1): idempotent, so a
/// node that restarts or a session that resumes never opens a second. Call it once the node is a
/// member of `room`.
///
/// # Errors
/// Why the opening could not be posted.
pub async fn open_when_member(
    handle: &NodeHandle,
    room: Digest32,
    session: &Opening,
) -> Result<(), String> {
    let me = handle
        .view()
        .identity
        .as_ref()
        .map(|i| i.fingerprint)
        .ok_or_else(|| "the node is locked".to_owned())?;
    let open = of_room(handle, &room)
        .iter()
        .any(|s| s.node == me && s.id == session.id && s.open);
    if open {
        return Ok(());
    }
    let mut env = Envelope::new(SESSION, "");
    env.from.clone_from(&session.id);
    env.at.session_name.clone_from(&session.name);
    env.data = serde_json::json!({ "session": { "harness": session.harness } });
    post(handle, room, env.to_text()).await
}

/// End `session`'s Session in `room`, if it is open there (ADR-029 SE-4): on the harness's real end,
/// never on a resume.
///
/// # Errors
/// Why the end could not be posted.
pub async fn end(
    handle: &NodeHandle,
    room: Digest32,
    session: &str,
    reason: &str,
) -> Result<(), String> {
    let me = handle
        .view()
        .identity
        .as_ref()
        .map(|i| i.fingerprint)
        .ok_or_else(|| "the node is locked".to_owned())?;
    let open = of_room(handle, &room)
        .iter()
        .any(|s| s.node == me && s.id == session && s.open);
    if !open {
        return Ok(());
    }
    let mut env = Envelope::new(SESSION_END, "");
    session.clone_into(&mut env.from);
    env.data = serde_json::json!({ "reason": reason });
    post(handle, room, env.to_text()).await
}

/// Whether the harness's `reason` for a `SessionEnd` keeps the session open (ADR-029 SE-4).
#[must_use]
pub fn keeps_open(reason: &str) -> bool {
    reason.trim() == "resume"
}

async fn post(handle: &NodeHandle, room: Digest32, text: String) -> Result<(), String> {
    // A room just joined is written to once its first sync with another member has ended
    // (V210-164), usually within a second.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match handle
            .apply(NodeCommand::SendText {
                channel_id: room,
                text: text.clone(),
            })
            .await
        {
            Outcome::Done => return Ok(()),
            Outcome::Failed(crate::node::api::Fault::RoomNotSynced)
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            other => return Err(other.to_string()),
        }
    }
}

/// Write `rows` as CBOR, for the socket ([`crate::node::ipc::Frame::Sessions`]) and the snapshot
/// alike: an array of 10-element arrays. An absent name is empty text, an absent end `0` and empty
/// bytes.
pub(crate) fn put_rows(e: &mut crate::cbor::Encoder, rows: &[SessionRow]) {
    e.array(rows.len());
    for r in rows {
        e.array(10)
            .bytes(&r.node)
            .text(&r.id)
            .text(r.name.as_deref().unwrap_or_default())
            .text(&r.harness)
            .uint(u64::from(r.open))
            .uint(r.opened_millis)
            .uint(r.ended_millis.unwrap_or(0))
            .bytes(&r.opening)
            .bytes(r.ended.as_ref().map_or(&[][..], |d| &d[..]))
            .uint(u64::from(r.can_drive));
    }
}

/// Read what [`put_rows`] wrote.
///
/// # Errors
/// [`crate::error::Error::MalformedIpc`] for anything else.
pub(crate) fn read_rows(d: &mut crate::cbor::Decoder<'_>) -> crate::error::Result<Vec<SessionRow>> {
    use crate::error::Error;
    let bad = |what: &'static str| move |_| Error::MalformedIpc(what);
    let digest = |b: &[u8]| {
        Digest32::try_from(b).map_err(|_| Error::MalformedIpc("ipc session digest length"))
    };
    let n = d.array().map_err(bad("ipc sessions"))?;
    let mut rows = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        if d.array().map_err(bad("ipc session row"))? != 10 {
            return Err(Error::MalformedIpc("ipc session row arity"));
        }
        let node = digest(d.bytes().map_err(bad("ipc session node"))?)?;
        let id = d.text().map_err(bad("ipc session id"))?.to_owned();
        let name = d.text().map_err(bad("ipc session name"))?.to_owned();
        let harness = d.text().map_err(bad("ipc session harness"))?.to_owned();
        let open = d.uint().map_err(bad("ipc session open"))? != 0;
        let opened_millis = d.uint().map_err(bad("ipc session opened"))?;
        let ended_millis = d.uint().map_err(bad("ipc session ended at"))?;
        let opening = digest(d.bytes().map_err(bad("ipc session opening"))?)?;
        let ended = d.bytes().map_err(bad("ipc session ended"))?;
        let ended = if ended.is_empty() {
            None
        } else {
            Some(digest(ended)?)
        };
        let can_drive = d.uint().map_err(bad("ipc session drive"))? != 0;
        rows.push(SessionRow {
            node,
            id,
            name: (!name.is_empty()).then_some(name),
            harness,
            open,
            opened_millis,
            ended_millis: (ended_millis != 0).then_some(ended_millis),
            opening,
            ended,
            can_drive,
        });
    }
    Ok(rows)
}

/// The one Session of `rows` that `typed` names (ADR-029 TA-1, DR-5), for every client alike: its
/// whole id, a prefix of its id of at least 8 characters, or its current name when exactly one
/// Session has it. Nothing is ever guessed: no match and more than one are refused, and so is an
/// ended Session unless `ended_ok` (reading one is fine, SE-5; addressing one is not, TA-5).
/// `label` says how a refusal names a Session ([`vox_agentcomms::envelope::session_label`] with the
/// reader's alias for its node).
///
/// # Errors
/// The refusal, as a sentence.
pub fn resolve<'a>(
    rows: &'a [SessionRow],
    typed: &str,
    ended_ok: bool,
    label: impl Fn(&SessionRow) -> String,
) -> Result<&'a SessionRow, String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Err(
            "name a Session: its id, the first 8 or more characters of it, or its name".into(),
        );
    }
    let by_id: Vec<&SessionRow> = rows
        .iter()
        .filter(|s| s.id == typed || (typed.chars().count() >= 8 && s.id.starts_with(typed)))
        .collect();
    let found: Vec<&SessionRow> = if by_id.is_empty() {
        rows.iter()
            .filter(|s| s.name.as_deref() == Some(typed))
            .collect()
    } else {
        by_id
    };
    match found.as_slice() {
        // The words are the TUI's and the app's (ADR-029 CL-1).
        [] => Err(format!("no Session in this room is named {typed}")),
        [one] if !one.open && !ended_ok => Err(format!("{} has ended", label(one))),
        [one] => Ok(one),
        several => Err(format!(
            "more than one Session is named {typed}: {}",
            several
                .iter()
                .map(|s| label(s))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// `text` with its session's current name in `at.session_name` (ADR-029 MD-1, MD-2): when it is an
/// envelope from a session registered on this node (`from` names it) and carries no name yet, the
/// name that session's harness last gave, from its registration. Anything else is `text` as it is.
/// The name is the node's claim (MD-3); the model never supplies it.
#[must_use]
pub fn fill_name(paths: &crate::node::paths::Paths, text: &str) -> String {
    let Ok(mut env) = Envelope::parse(text) else {
        return text.to_owned();
    };
    if env.from.trim().is_empty() || env.at.session_name.is_some() {
        return text.to_owned();
    }
    let name = std::fs::read(paths.session_file(env.from.trim()))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["name"].as_str().map(str::to_owned))
        .filter(|n| !n.trim().is_empty());
    match name {
        Some(n) => {
            env.at.session_name = Some(n);
            env.to_text()
        }
        None => text.to_owned(),
    }
}
